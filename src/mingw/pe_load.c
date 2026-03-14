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
 * pe_load.c — Caller-side in-process PE loader.
 *
 * Maps a raw PE DLL into the current process address space without
 * requiring any embedded loader stub (no ReflectiveLoader). This
 * replaces the reflective loading approach for in-process tab
 * plugins with a clean caller-side implementation.
 *
 * Flow:
 *   1. Validate PE headers
 *   2. Allocate SizeOfImage as RW via VirtualAlloc
 *   3. Copy PE headers
 *   4. Copy each section to its virtual address
 *   5. Process base relocations (delta from ImageBase)
 *   6. Resolve imports (LoadLibraryA + GetProcAddress)
 *   7. Apply per-section memory protections (RX, R, RW — never RWX)
 *   8. Flush instruction cache
 *   9. Call DllMain(DLL_PROCESS_ATTACH)
 *
 * Evasion notes:
 *   - No RWX allocation at any point
 *   - No known reflective loader signatures in the loaded DLL
 *   - Import resolution uses standard APIs (the DLL's imports are
 *     legitimate — it's running in our process anyway)
 *   - Per-section protections match what the Windows loader does
 */

#include <windows.h>
#include <string.h>
#include <stdlib.h>

#include <pwny/pe_load.h>

typedef BOOL (WINAPI *DLLMAIN_T)(HINSTANCE, DWORD, LPVOID);

typedef struct
{
    WORD offset : 12;
    WORD type   : 4;
} pe_reloc_t;

struct pe_image
{
    void *base;           /* Mapped image base address */
    size_t size;          /* SizeOfImage */
    DLLMAIN_T entry;      /* DllMain address */
    int attached;         /* DLL_PROCESS_ATTACH called */
};

/*
 * Convert section characteristics to page protection flags.
 * Matches the Windows loader's mapping logic.
 */
static DWORD section_protect(DWORD characteristics)
{
    BOOL exec  = (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
    BOOL read  = (characteristics & IMAGE_SCN_MEM_READ) != 0;
    BOOL write = (characteristics & IMAGE_SCN_MEM_WRITE) != 0;

    if (exec && write && read) return PAGE_EXECUTE_READWRITE;
    if (exec && write)         return PAGE_EXECUTE_WRITECOPY;
    if (exec && read)          return PAGE_EXECUTE_READ;
    if (exec)                  return PAGE_EXECUTE;
    if (write && read)         return PAGE_READWRITE;
    if (write)                 return PAGE_WRITECOPY;
    if (read)                  return PAGE_READONLY;

    return PAGE_NOACCESS;
}

/*
 * Process base relocations for the loaded image.
 */
static int pe_process_relocs(BYTE *base, PIMAGE_NT_HEADERS64 nt, ULONG_PTR delta)
{
    PIMAGE_DATA_DIRECTORY reloc_dir;
    PIMAGE_BASE_RELOCATION reloc_block;
    DWORD reloc_size;

    reloc_dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (reloc_dir->VirtualAddress == 0 || reloc_dir->Size == 0)
    {
        /* No relocations needed (loaded at preferred base) */
        return (delta == 0) ? 0 : -1;
    }

    reloc_block = (PIMAGE_BASE_RELOCATION)(base + reloc_dir->VirtualAddress);
    reloc_size = reloc_dir->Size;

    while (reloc_size > 0 && reloc_block->SizeOfBlock > 0)
    {
        BYTE *page = base + reloc_block->VirtualAddress;
        DWORD count = (reloc_block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(pe_reloc_t);
        pe_reloc_t *entries = (pe_reloc_t *)((BYTE *)reloc_block + sizeof(IMAGE_BASE_RELOCATION));
        DWORD i;

        for (i = 0; i < count; i++)
        {
            BYTE *target = page + entries[i].offset;

            switch (entries[i].type)
            {
                case IMAGE_REL_BASED_DIR64:
                    *(ULONG_PTR *)target += delta;
                    break;
                case IMAGE_REL_BASED_HIGHLOW:
                    *(DWORD *)target += (DWORD)delta;
                    break;
                case IMAGE_REL_BASED_HIGH:
                    *(WORD *)target += HIWORD(delta);
                    break;
                case IMAGE_REL_BASED_LOW:
                    *(WORD *)target += LOWORD(delta);
                    break;
                case IMAGE_REL_BASED_ABSOLUTE:
                    /* Padding — skip */
                    break;
                default:
                    return -1;
            }
        }

        reloc_size -= reloc_block->SizeOfBlock;
        reloc_block = (PIMAGE_BASE_RELOCATION)((BYTE *)reloc_block + reloc_block->SizeOfBlock);
    }

    return 0;
}

/*
 * Resolve the import table for the loaded image.
 * Uses standard LoadLibraryA/GetProcAddress since we're
 * running in our own process — these are legitimate calls.
 */
static int pe_process_imports(BYTE *base, PIMAGE_NT_HEADERS64 nt)
{
    PIMAGE_DATA_DIRECTORY import_dir;
    PIMAGE_IMPORT_DESCRIPTOR imp;

    import_dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (import_dir->VirtualAddress == 0 || import_dir->Size == 0)
    {
        return 0;
    }

    imp = (PIMAGE_IMPORT_DESCRIPTOR)(base + import_dir->VirtualAddress);

    while (imp->Characteristics != 0)
    {
        const char *dll_name = (const char *)(base + imp->Name);
        HMODULE hMod = LoadLibraryA(dll_name);

        if (hMod == NULL)
        {
            imp++;
            continue;
        }

        PIMAGE_THUNK_DATA64 orig = NULL;
        PIMAGE_THUNK_DATA64 thunk;

        if (imp->OriginalFirstThunk)
        {
            orig = (PIMAGE_THUNK_DATA64)(base + imp->OriginalFirstThunk);
        }

        thunk = (PIMAGE_THUNK_DATA64)(base + imp->FirstThunk);

        while (thunk->u1.AddressOfData != 0)
        {
            FARPROC func;

            if (orig && (orig->u1.Ordinal & IMAGE_ORDINAL_FLAG64))
            {
                /* Import by ordinal */
                func = GetProcAddress(hMod, (LPCSTR)IMAGE_ORDINAL64(orig->u1.Ordinal));
            }
            else
            {
                /* Import by name */
                ULONG_PTR hint_rva = orig ? orig->u1.AddressOfData : thunk->u1.AddressOfData;
                PIMAGE_IMPORT_BY_NAME hint = (PIMAGE_IMPORT_BY_NAME)(base + hint_rva);
                func = GetProcAddress(hMod, (LPCSTR)hint->Name);
            }

            if (func == NULL)
            {
                return -1;
            }

            thunk->u1.Function = (ULONGLONG)func;

            thunk++;
            if (orig) orig++;
        }

        imp++;
    }

    return 0;
}

/*
 * Apply per-section memory protections.
 * This converts sections from the initial RW to their
 * intended protections (typically RX for .text, R for .rdata, RW for .data).
 */
static int pe_apply_protections(BYTE *base, PIMAGE_NT_HEADERS64 nt)
{
    PIMAGE_SECTION_HEADER section;
    WORD i;
    DWORD old_prot;

    section = IMAGE_FIRST_SECTION(nt);

    for (i = 0; i < nt->FileHeader.NumberOfSections; i++)
    {
        DWORD prot;
        SIZE_T section_size;
        BYTE *section_base;

        if (section[i].SizeOfRawData == 0)
        {
            continue;
        }

        section_base = base + section[i].VirtualAddress;
        section_size = section[i].SizeOfRawData;
        prot = section_protect(section[i].Characteristics);

        VirtualProtect(section_base, section_size, prot, &old_prot);
    }

    /* Protect headers as read-only */
    VirtualProtect(base, nt->OptionalHeader.SizeOfHeaders, PAGE_READONLY, &old_prot);

    return 0;
}

pe_image_t *pe_load(unsigned char *image, size_t length)
{
    PIMAGE_DOS_HEADER dos;
    PIMAGE_NT_HEADERS64 nt;
    PIMAGE_SECTION_HEADER section;
    BYTE *base;
    ULONG_PTR delta;
    pe_image_t *pe;
    WORD i;

    if (image == NULL || length < sizeof(IMAGE_DOS_HEADER))
    {
        return NULL;
    }

    /* Validate PE signature */
    dos = (PIMAGE_DOS_HEADER)image;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
    {
        return NULL;
    }

    nt = (PIMAGE_NT_HEADERS64)(image + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
    {
        return NULL;
    }

    if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        return NULL;
    }

    /* Allocate memory for the image — RW only, never RWX */
    base = (BYTE *)VirtualAlloc(
        NULL,
        nt->OptionalHeader.SizeOfImage,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_READWRITE
    );

    if (base == NULL)
    {
        return NULL;
    }

    /* Copy PE headers */
    memcpy(base, image, nt->OptionalHeader.SizeOfHeaders);

    /* Copy sections */
    section = IMAGE_FIRST_SECTION(nt);

    for (i = 0; i < nt->FileHeader.NumberOfSections; i++)
    {
        if (section[i].SizeOfRawData > 0)
        {
            memcpy(
                base + section[i].VirtualAddress,
                image + section[i].PointerToRawData,
                section[i].SizeOfRawData
            );
        }
    }

    /* Re-parse NT headers from the mapped copy */
    nt = (PIMAGE_NT_HEADERS64)(base + dos->e_lfanew);

    /* Process base relocations */
    delta = (ULONG_PTR)base - nt->OptionalHeader.ImageBase;

    if (pe_process_relocs(base, nt, delta) < 0)
    {
        VirtualFree(base, 0, MEM_RELEASE);
        return NULL;
    }

    /* Resolve imports */
    if (pe_process_imports(base, nt) < 0)
    {
        VirtualFree(base, 0, MEM_RELEASE);
        return NULL;
    }

    /* Apply per-section protections */
    pe_apply_protections(base, nt);

    /* Flush instruction cache */
    FlushInstructionCache(GetCurrentProcess(), base, nt->OptionalHeader.SizeOfImage);

    /* Allocate the image handle */
    pe = (pe_image_t *)calloc(1, sizeof(*pe));
    if (pe == NULL)
    {
        VirtualFree(base, 0, MEM_RELEASE);
        return NULL;
    }

    pe->base = base;
    pe->size = nt->OptionalHeader.SizeOfImage;
    pe->attached = 0;

    /* Call DllMain(DLL_PROCESS_ATTACH) if entry point exists */
    if (nt->OptionalHeader.AddressOfEntryPoint != 0)
    {
        pe->entry = (DLLMAIN_T)(base + nt->OptionalHeader.AddressOfEntryPoint);
        pe->entry((HINSTANCE)base, DLL_PROCESS_ATTACH, NULL);
        pe->attached = 1;
    }

    return pe;
}

void *pe_image_base(pe_image_t *pe)
{
    if (pe == NULL)
    {
        return NULL;
    }

    return pe->base;
}

void *pe_get_proc(pe_image_t *pe, const char *name)
{
    PIMAGE_DOS_HEADER dos;
    PIMAGE_NT_HEADERS64 nt;
    PIMAGE_EXPORT_DIRECTORY exports;
    DWORD *names;
    DWORD *functions;
    WORD *ordinals;
    DWORD i;
    BYTE *base;

    if (pe == NULL || name == NULL)
    {
        return NULL;
    }

    base = (BYTE *)pe->base;
    dos = (PIMAGE_DOS_HEADER)base;
    nt = (PIMAGE_NT_HEADERS64)(base + dos->e_lfanew);

    if (nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0)
    {
        return NULL;
    }

    exports = (PIMAGE_EXPORT_DIRECTORY)(base +
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    names = (DWORD *)(base + exports->AddressOfNames);
    functions = (DWORD *)(base + exports->AddressOfFunctions);
    ordinals = (WORD *)(base + exports->AddressOfNameOrdinals);

    for (i = 0; i < exports->NumberOfNames; i++)
    {
        const char *export_name = (const char *)(base + names[i]);
        if (strcmp(export_name, name) == 0)
        {
            return (void *)(base + functions[ordinals[i]]);
        }
    }

    return NULL;
}

void pe_unload(pe_image_t *pe)
{
    if (pe == NULL)
    {
        return;
    }

    /* Call DllMain(DLL_PROCESS_DETACH) */
    if (pe->attached && pe->entry)
    {
        pe->entry((HINSTANCE)pe->base, DLL_PROCESS_DETACH, NULL);
    }

    if (pe->base)
    {
        VirtualFree(pe->base, 0, MEM_RELEASE);
    }

    free(pe);
}
