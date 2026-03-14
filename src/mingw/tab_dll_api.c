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

/*
 * Minimal API runtime for Windows DLL tab plugins.
 *
 * Contains only the functions a tab DLL needs:
 *   - api_call_register: register handlers in TabInit
 *   - api_craft_tlv_pkt: craft response packets in handlers
 *   - api_calls_free: cleanup (called by parent on tab unload)
 *
 * These are extracted from api.c to avoid pulling in the heavy
 * dependency chain (sigar, tabs, child, tunnel, etc).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pwny/tlv.h>
#include <pwny/tlv_types.h>
#include <pwny/log.h>

#include <uthash/uthash.h>

typedef tlv_pkt_t *(*api_t)(void *);

typedef struct api_calls_table
{
    int tag;
    api_t handler;
    UT_hash_handle hh;
} api_calls_t;

tlv_pkt_t *api_craft_tlv_pkt(int status, tlv_pkt_t *request)
{
    int tag;
    int tab_id;
    tlv_pkt_t *c2_pkt;

    c2_pkt = tlv_pkt_create();
    tlv_pkt_add_u32(c2_pkt, TLV_TYPE_STATUS, status);

    if (request != NULL && tlv_pkt_get_u32(request, TLV_TYPE_TAG, &tag) >= 0)
    {
        tlv_pkt_add_u32(c2_pkt, TLV_TYPE_TAG, tag);
    }

    if (request != NULL && tlv_pkt_get_u32(request, TLV_TYPE_TAB_ID, &tab_id) >= 0)
    {
        tlv_pkt_add_u32(c2_pkt, TLV_TYPE_TAB_ID, tab_id);
    }

    return c2_pkt;
}

void api_call_register(api_calls_t **api_calls, int tag, api_t handler)
{
    api_calls_t *api_call;
    api_calls_t *api_call_new;

    HASH_FIND_INT(*api_calls, &tag, api_call);

    if (api_call != NULL)
    {
        return;
    }

    api_call_new = calloc(1, sizeof(*api_call_new));

    if (api_call_new == NULL)
    {
        return;
    }

    api_call_new->tag = tag;
    api_call_new->handler = handler;

    HASH_ADD_INT(*api_calls, tag, api_call_new);
    log_debug("* Registered DLL tab API call tag (%d)\n", tag);
}

void api_calls_free(api_calls_t *api_calls)
{
    api_calls_t *api_call;
    api_calls_t *api_call_tmp;

    HASH_ITER(hh, api_calls, api_call, api_call_tmp)
    {
        HASH_DEL(api_calls, api_call);
        free(api_call);
    }
}
