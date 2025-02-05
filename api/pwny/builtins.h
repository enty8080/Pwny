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

#ifndef _BUILTINS_H_
#define _BUILTINS_H_

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sigar.h>
#include <time.h>
#include <eio.h>

#include <mbedtls/pk.h>

#ifndef __windows__
#include <pwd.h>
#else
#include <pwny/misc.h>
#include <windows.h>
#endif

#include <pwny/api.h>
#include <pwny/c2.h>
#include <pwny/tabs.h>
#include <pwny/tlv_types.h>
#include <pwny/tlv.h>
#include <pwny/group.h>
#include <pwny/crypt.h>
#include <pwny/log.h>

#define BUILTIN_BASE 1

#define BUILTIN_QUIT \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       BUILTIN_BASE, \
                       API_CALL)
#define BUILTIN_ADD_TAB_DISK \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       BUILTIN_BASE, \
                       API_CALL + 1)
#define BUILTIN_ADD_TAB_BUFFER \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       BUILTIN_BASE, \
                       API_CALL + 2)
#define BUILTIN_DELETE_TAB \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       BUILTIN_BASE, \
                       API_CALL + 3)
#define BUILTIN_SYSINFO \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       BUILTIN_BASE, \
                       API_CALL + 4)
#define BUILTIN_TIME \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       BUILTIN_BASE, \
                       API_CALL + 5)
#define BUILTIN_WHOAMI \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       BUILTIN_BASE, \
                       API_CALL + 6)
#define BUILTIN_UUID \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       BUILTIN_BASE, \
                       API_CALL + 7)
#define BUILTIN_SECURE \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       BUILTIN_BASE, \
                       API_CALL + 8)
#define BUILTIN_UNSECURE \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       BUILTIN_BASE, \
                       API_CALL + 9)

#define TLV_TYPE_PLATFORM  TLV_TYPE_CUSTOM(TLV_TYPE_STRING, BUILTIN_BASE, API_TYPE)
#define TLV_TYPE_VERSION   TLV_TYPE_CUSTOM(TLV_TYPE_STRING, BUILTIN_BASE, API_TYPE + 1)
#define TLV_TYPE_ARCH      TLV_TYPE_CUSTOM(TLV_TYPE_STRING, BUILTIN_BASE, API_TYPE + 2)
#define TLV_TYPE_MACHINE   TLV_TYPE_CUSTOM(TLV_TYPE_STRING, BUILTIN_BASE, API_TYPE + 3)
#define TLV_TYPE_VENDOR    TLV_TYPE_CUSTOM(TLV_TYPE_STRING, BUILTIN_BASE, API_TYPE + 4)

#define TLV_TYPE_RAM_USED  TLV_TYPE_CUSTOM(TLV_TYPE_INT, BUILTIN_BASE, API_TYPE)
#define TLV_TYPE_RAM_TOTAL TLV_TYPE_CUSTOM(TLV_TYPE_INT, BUILTIN_BASE, API_TYPE + 1)
#define TLV_TYPE_FLAGS     TLV_TYPE_CUSTOM(TLV_TYPE_INT, BUILTIN_BASE, API_TYPE + 2)

#define TLV_TYPE_PUBLIC_KEY  TLV_TYPE_CUSTOM(TLV_TYPE_BYTES, BUILTIN_BASE, API_TYPE)
#define TLV_TYPE_KEY         TLV_TYPE_CUSTOM(TLV_TYPE_BYTES, BUILTIN_BASE, API_TYPE + 1)

static tlv_pkt_t *builtin_quit(c2_t *c2)
{
    /* Quit client and terminate current connection
     * if c2->tunnel->keep_alive is not set.
     *
     * :in NULL: NULL
     * :out u32(TLV_TYPE_STATUS): API_CALL_QUIT
     *
     */

    return api_craft_tlv_pkt(API_CALL_QUIT, c2->request);
}

static tlv_pkt_t *builtin_add_tab_disk(c2_t *c2)
{
    /* Load TAB (The Additional Bundle) from disk location.
     *
     * :in string(TLV_TYPE_FILENAME): location of a TAB on disk
     * :out u32(TLV_TYPE_TAB_ID): loaded TAB ID
     * :out u32(TLV_TYPE_STATUS): API_CALL_SUCCESS / API_CALL_FAIL
     *
     */

    core_t *core;
    char filename[128];
    tlv_pkt_t *result;

    core = c2->data;

    if (tlv_pkt_get_string(c2->request, TLV_TYPE_FILENAME, filename) > 0)
    {
        if (tabs_add(&core->tabs, core->t_count, filename, NULL, strlen(filename)+1, c2) == 0)
        {
            result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
            tlv_pkt_add_u32(result, TLV_TYPE_TAB_ID, core->t_count);
            core->t_count++;

            return result;
        }
    }

    return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
}

static tlv_pkt_t *builtin_add_tab_buffer(c2_t *c2)
{
    /* Load TAB (The Additional Bundle) from memory location.
     *
     * :in bytes(TLV_TYPE_TAB): buffer containing TAB executable
     * :out u32(TLV_TYPE_TAB_ID): loaded TAB ID
     * :out u32(TLV_TYPE_STATUS): API_CALL_SUCCESS / API_CALL_FAIL
     *
     */

    core_t *core;
    int tab_size;
    unsigned char *tab;
    tlv_pkt_t *result;

    core = c2->data;

    if ((tab_size = tlv_pkt_get_bytes(c2->request, TLV_TYPE_TAB, &tab)) > 0)
    {
        if (tabs_add(&core->tabs, core->t_count, NULL, tab, tab_size, c2) == 0)
        {
            result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
            tlv_pkt_add_u32(result, TLV_TYPE_TAB_ID, core->t_count);
            core->t_count++;
            free(tab);

            return result;
        }
        else
        {
            free(tab);
        }
    }

    return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
}

static tlv_pkt_t *builtin_delete_tab(c2_t *c2)
{
    /* Delete loaded TAB (The Additional Bundle).
     *
     * :in u32(TLV_TYPE_TAB_ID): loaded TAB ID
     * :out u32(TLV_TYPE_STATUS): API_CALL_SUCCESS / API_CALL_FAIL
     *
     */

    core_t *core;
    int tab_id;

    core = c2->data;
    tlv_pkt_get_u32(c2->request, TLV_TYPE_INT, &tab_id);

    if (tabs_delete(&core->tabs, tab_id) == 0)
    {
        return api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
    }

    return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
}

static tlv_pkt_t *builtin_time(c2_t *c2)
{
    /* Retrieve system local time.
     *
     * :out string(TLV_TYPE_STRING): local time in
     *                               %Y-%m-%d %H:%M:%S %Z (UTC%z) format
     * :out u32(TLV_TYPE_STATUS): API_CALL_SUCCESS / API_CALL_FAIL
     *
     */

    tlv_pkt_t *result;
    char date_time[128];

#ifndef __windows__
    struct tm local_time;
    time_t time_ctx;

    memset(date_time, '\0', 128);
    time_ctx = time(NULL);

    localtime_r(&time_ctx, &local_time);
    strftime(date_time, sizeof(date_time) - 1, "%Y-%m-%d %H:%M:%S %Z (UTC%z)", &local_time);

    result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
    tlv_pkt_add_string(result, TLV_TYPE_STRING, date_time);
#else
    TIME_ZONE_INFORMATION tzi;
    SYSTEMTIME localTime;
    DWORD tziResult;

    memset(date_time, '\0', 128);

    tziResult = GetTimeZoneInformation(&tzi);
    GetLocalTime(&localTime);

    _snprintf_s(date_time, sizeof(date_time), sizeof(date_time) - 1, "%d-%02d-%02d %02d:%02d:%02d.%d %S (UTC%s%d)",
		localTime.wYear, localTime.wMonth, localTime.wDay,
		localTime.wHour, localTime.wMinute, localTime.wSecond, localTime.wMilliseconds,
		tziResult == TIME_ZONE_ID_DAYLIGHT ? tzi.DaylightName : tzi.StandardName,
		tzi.Bias > 0 ? "-" : "+", abs(tzi.Bias / 60 * 100));

    result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
    tlv_pkt_add_string(result, TLV_TYPE_STRING, date_time);
#endif

    return result;
}

static tlv_pkt_t *builtin_sysinfo(c2_t *c2)
{
    /* Retrieve system information.
     *
     * :out string(TLV_TYPE_PLATFORM): system platform
     * :out string(TLV_TYPE_VERSION): system version
     * :out string(TLV_TYPE_ARCH): CPU architecture
     * :out string(TLV_TYPE_MACHINE): machine type
     * :out string(TLV_TYPE_VENDOR): system vendor
     *
     * :out u64(TLV_TYPE_RAM_TOTAL): total RAM space
     * :out u64(TLV_TYPE_RAM_USED): used RAM
     *
     * :out u32(TLV_TYPE_FLAGS): client flags
     * :out u32(TLV_TYPE_STATUS): API_CALL_SUCCESS / API_CALL_FAIL
     *
     */

    int status;
    tlv_pkt_t *result;
    sigar_sys_info_t sysinfo;
    sigar_mem_t memory;
    core_t *core;

    core = c2->data;

    if ((status = sigar_sys_info_get(core->sigar, &sysinfo)) != SIGAR_OK)
    {
        log_debug("* Failed to sigar sysinfo (%s)\n",
                  sigar_strerror(core->sigar, status));
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    if ((status = sigar_mem_get(core->sigar, &memory)) != SIGAR_OK)
    {
        log_debug("* Failed to sigar memory (%s)\n",
                  sigar_strerror(core->sigar, status));
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);

    tlv_pkt_add_string(result, TLV_TYPE_PLATFORM, sysinfo.name);
    tlv_pkt_add_string(result, TLV_TYPE_VERSION, sysinfo.version);
    tlv_pkt_add_string(result, TLV_TYPE_ARCH, sysinfo.arch);
    tlv_pkt_add_string(result, TLV_TYPE_MACHINE, sysinfo.machine);
    tlv_pkt_add_string(result, TLV_TYPE_VENDOR, sysinfo.vendor);

    tlv_pkt_add_u64(result, TLV_TYPE_RAM_TOTAL, memory.total);
    tlv_pkt_add_u64(result, TLV_TYPE_RAM_USED, memory.used);
    tlv_pkt_add_u32(result, TLV_TYPE_FLAGS, core->flags);

    return result;
}

#ifdef __windows__
DWORD get_user_token(LPVOID pTokenUser, DWORD dwBufferSize)
{
	DWORD dwReturnedLength;
	HANDLE hToken;

    dwReturnedLength = 0;

	if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, FALSE, &hToken))
	{
		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
		{
			log_debug("* Failed to get a valid token for thread/process\n");
			return -1;
		}
	}

	if (!GetTokenInformation(hToken, TokenUser, pTokenUser, dwBufferSize, &dwReturnedLength))
	{
		log_debug("* Failed to get token information for thread/process\n");
		return -1;
	}

	return 0;
}
#endif

static tlv_pkt_t *builtin_whoami(c2_t *c2)
{
    /* Retrieve current username.
     *
     * :out string(TLV_TYPE_STRING): current username
     * :out u32(TLV_TYPE_STATUS): API_CALL_SUCCESS / API_CALL_FAIL
     *
     */

    tlv_pkt_t *result;

#ifndef __windows__
    struct passwd *pw_entry;

    if ((pw_entry = getpwuid(geteuid())))
    {
        result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
        tlv_pkt_add_string(result, TLV_TYPE_STRING, pw_entry->pw_name);
    }
    else
    {
        result = api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }
#else
    DWORD dwResult;
	WCHAR cbUserOnly[512], cbDomainOnly[512];
	CHAR cbUsername[1024];
	BYTE tokenUserInfo[4096];
	DWORD dwUserSize = sizeof(cbUserOnly), dwDomainSize = sizeof(cbDomainOnly);
	DWORD dwSidType = 0;

    char *domainName;
    char *userName;

	memset(cbUsername, 0, sizeof(cbUsername));
	memset(cbUserOnly, 0, sizeof(cbUserOnly));
	memset(cbDomainOnly, 0, sizeof(cbDomainOnly));

	if (get_user_token(tokenUserInfo, sizeof(tokenUserInfo)) != 0)
	{
		log_debug("* Unable to get user token\n");
		return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
	}

	if (!LookupAccountSidW(NULL, ((TOKEN_USER*)tokenUserInfo)->User.Sid, cbUserOnly, &dwUserSize, cbDomainOnly, &dwDomainSize, (PSID_NAME_USE)&dwSidType))
	{
		log_debug("* Failed to lookup the account SID data\n");
		return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
	}

    result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
	domainName = wchar_to_utf8(cbDomainOnly);
	userName = wchar_to_utf8(cbUserOnly);

	_snprintf(cbUsername, 512, "%s\\%s", domainName, userName);
	free(domainName);
	free(userName);
	cbUsername[511] = '\0';

	tlv_pkt_add_string(result, TLV_TYPE_STRING, cbUsername);
#endif

    return result;
}

static tlv_pkt_t *builtin_uuid(c2_t *c2)
{
    /* Retrieve current client UUID.
     *
     * :out string(TLV_TYPE_UUID): current client UUID
     * :out u32(TLV_TYPE_STATUS): API_CALL_SUCCESS / API_CALL_FAIL
     *
     */

    core_t *core;
    tlv_pkt_t *result;

    core = c2->data;

    result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
    tlv_pkt_add_string(result, TLV_TYPE_UUID, core->uuid);

    return result;
}

static void builtin_enable_security(struct eio_req *request)
{
    int status;
    c2_t *c2;

    c2 = request->data;
    c2_enqueue_tlv(c2, c2->response);

    tlv_pkt_destroy(c2->request);
    tlv_pkt_destroy(c2->response);

    crypt_set_algo(c2->crypt, c2->crypt->next_algo);
    crypt_set_key(c2->crypt, c2->crypt->next_key, c2->crypt->next_iv);
    crypt_set_secure(c2->crypt, STAT_SECURE);

    free(c2->crypt->next_key);
    free(c2->crypt->next_iv);
}

static void builtin_disable_security(struct eio_req *request)
{
    c2_t *c2;

    c2 = request->data;
    c2_enqueue_tlv(c2, c2->response);

    tlv_pkt_destroy(c2->request);
    tlv_pkt_destroy(c2->response);

    crypt_set_secure(c2->crypt, STAT_NOT_SECURE);
    crypt_set_algo(c2->crypt, ALGO_NONE);
}

static tlv_pkt_t *builtin_unsecure(c2_t *c2)
{
    /* Disable client secure communication.
     *
     * :out u32(TLV_TYPE_STATUS): API_CALL_SUCCESS
     *
     */

    c2->response = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);

    log_debug("* Disabling security\n");

    /* Using asyncronous call so that client could send back
     * reply with old configuration before applying new one.
     *
     */

    eio_custom(builtin_disable_security, 0, NULL, c2);

    return NULL;
}

static tlv_pkt_t *builtin_secure(c2_t *c2)
{
    /* Enable client secure communication.
     *
     * :in string(TLV_TYPE_PUBLIC_KEY): RSA public key for encryption
     * :in u32(TLV_TYPE_INT): encryption algorithm
     * :out u32(TLV_TYPE_STATUS): API_CALL_SUCCESS / API_CALL_FAIL
     *
     */

    size_t length;

    int algo;
    int pkey_length;
    int key_length;

    char pkey[4096];
    unsigned char buffer[MBEDTLS_MPI_MAX_SIZE];

    if ((pkey_length = tlv_pkt_get_string(c2->request, TLV_TYPE_PUBLIC_KEY, pkey)) <= 0)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }
    pkey_length++;

    tlv_pkt_get_u32(c2->request, TLV_TYPE_INT, &algo);
    c2->crypt->next_algo = algo;

    if ((key_length = crypt_generate_key(c2->crypt, algo, &c2->crypt->next_key,
                                         &c2->crypt->next_iv)) < 0)
    {
        goto fail;
    }

    memset(buffer, '\0', MBEDTLS_MPI_MAX_SIZE);
    length = crypt_pkcs_encrypt(c2->crypt, c2->crypt->next_key, key_length, (unsigned char *)pkey,
                                pkey_length, buffer);

    if (length <= 0)
    {
        free(c2->crypt->next_key);
        free(c2->crypt->next_iv);

        goto fail;
    }

    c2->response = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
    tlv_pkt_add_bytes(c2->response, TLV_TYPE_KEY, buffer, length);

    log_debug("Symmetric key: \n");
    log_hexdump(c2->crypt->next_key, 32);

    log_debug("Symmetric key encrypted with PKCS: \n");
    log_hexdump(buffer, length);

    /* Using asyncronous call so that client could send back
     * reply with old configuration before applying new one.
     *
     */

    eio_custom(builtin_enable_security, 0, NULL, c2);
    return NULL;

fail:
    crypt_set_algo(c2->crypt, ALGO_NONE);
    return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
}

void register_builtin_api_calls(api_calls_t **api_calls)
{
    api_call_register(api_calls, BUILTIN_QUIT, builtin_quit);
    api_call_register(api_calls, BUILTIN_ADD_TAB_DISK, builtin_add_tab_disk);
    api_call_register(api_calls, BUILTIN_ADD_TAB_BUFFER, builtin_add_tab_buffer);
    api_call_register(api_calls, BUILTIN_DELETE_TAB, builtin_delete_tab);
    api_call_register(api_calls, BUILTIN_SYSINFO, builtin_sysinfo);
    api_call_register(api_calls, BUILTIN_TIME, builtin_time);
    api_call_register(api_calls, BUILTIN_WHOAMI, builtin_whoami);
    api_call_register(api_calls, BUILTIN_UUID, builtin_uuid);
    api_call_register(api_calls, BUILTIN_SECURE, builtin_secure);
    api_call_register(api_calls, BUILTIN_UNSECURE, builtin_unsecure);
}

#endif
