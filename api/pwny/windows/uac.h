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

#ifndef _UAC_H_
#define _UAC_H_

#include <windows.h>

#include <pwny/tlv.h>
#include <pwny/api.h>
#include <pwny/c2.h>
#include <pwny/tlv_types.h>
#include <pwny/log.h>

#define UAC_BASE 8

#define UAC_INFO \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       UAC_BASE, \
                       API_CALL)

#define TLV_TYPE_UAC_ELEVATED \
        TLV_TYPE_CUSTOM(TLV_TYPE_INT, UAC_BASE, API_TYPE)

#define TLV_TYPE_UAC_INTEGRITY \
        TLV_TYPE_CUSTOM(TLV_TYPE_INT, UAC_BASE, API_TYPE + 1)

#define TLV_TYPE_UAC_INTEGRITY_NAME \
        TLV_TYPE_CUSTOM(TLV_TYPE_STRING, UAC_BASE, API_TYPE)

#define INTEGRITY_UNKNOWN  0
#define INTEGRITY_LOW      1
#define INTEGRITY_MEDIUM   2
#define INTEGRITY_HIGH     3
#define INTEGRITY_SYSTEM   4

static int uac_get_integrity_level(void)
{
    HANDLE hToken;
    DWORD dwLength;
    PTOKEN_MANDATORY_LABEL pTIL;
    DWORD dwIntegrityLevel;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
    {
        return INTEGRITY_UNKNOWN;
    }

    dwLength = 0;
    GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &dwLength);

    if (dwLength == 0)
    {
        CloseHandle(hToken);
        return INTEGRITY_UNKNOWN;
    }

    pTIL = (PTOKEN_MANDATORY_LABEL)calloc(1, dwLength);
    if (pTIL == NULL)
    {
        CloseHandle(hToken);
        return INTEGRITY_UNKNOWN;
    }

    if (!GetTokenInformation(hToken, TokenIntegrityLevel, pTIL, dwLength, &dwLength))
    {
        free(pTIL);
        CloseHandle(hToken);
        return INTEGRITY_UNKNOWN;
    }

    dwIntegrityLevel = *GetSidSubAuthority(
        pTIL->Label.Sid,
        (DWORD)(UCHAR)(*GetSidSubAuthorityCount(pTIL->Label.Sid) - 1)
    );

    free(pTIL);
    CloseHandle(hToken);

    if (dwIntegrityLevel >= SECURITY_MANDATORY_SYSTEM_RID)
    {
        return INTEGRITY_SYSTEM;
    }
    else if (dwIntegrityLevel >= SECURITY_MANDATORY_HIGH_RID)
    {
        return INTEGRITY_HIGH;
    }
    else if (dwIntegrityLevel >= SECURITY_MANDATORY_MEDIUM_RID)
    {
        return INTEGRITY_MEDIUM;
    }
    else
    {
        return INTEGRITY_LOW;
    }
}

static int uac_is_elevated(void)
{
    HANDLE hToken;
    TOKEN_ELEVATION elevation;
    DWORD dwSize;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
    {
        return 0;
    }

    dwSize = sizeof(TOKEN_ELEVATION);
    if (!GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize))
    {
        CloseHandle(hToken);
        return 0;
    }

    CloseHandle(hToken);
    return elevation.TokenIsElevated ? 1 : 0;
}

static const char *uac_integrity_name(int level)
{
    switch (level)
    {
        case INTEGRITY_LOW:    return "Low";
        case INTEGRITY_MEDIUM: return "Medium";
        case INTEGRITY_HIGH:   return "High";
        case INTEGRITY_SYSTEM: return "System";
        default:               return "Unknown";
    }
}

static tlv_pkt_t *uac_info(c2_t *c2)
{
    /* Retrieve UAC elevation status and integrity level.
     *
     * :out u32(TLV_TYPE_UAC_ELEVATED): 1 if elevated, 0 otherwise
     * :out u32(TLV_TYPE_UAC_INTEGRITY): integrity level constant
     * :out string(TLV_TYPE_UAC_INTEGRITY_NAME): integrity level name
     * :out u32(TLV_TYPE_STATUS): API_CALL_SUCCESS
     */

    int elevated;
    int integrity;
    tlv_pkt_t *result;

    elevated = uac_is_elevated();
    integrity = uac_get_integrity_level();

    result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
    tlv_pkt_add_u32(result, TLV_TYPE_UAC_ELEVATED, elevated);
    tlv_pkt_add_u32(result, TLV_TYPE_UAC_INTEGRITY, integrity);
    tlv_pkt_add_string(result, TLV_TYPE_UAC_INTEGRITY_NAME, (char *)uac_integrity_name(integrity));

    return result;
}

void register_uac_api_calls(api_calls_t **api_calls)
{
    api_call_register(api_calls, UAC_INFO, uac_info);
}

#endif
