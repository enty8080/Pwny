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

#ifndef _SERVICES_H_
#define _SERVICES_H_

#include <windows.h>
#include <string.h>

#include <pwny/tlv.h>
#include <pwny/api.h>
#include <pwny/c2.h>
#include <pwny/tlv_types.h>
#include <pwny/misc.h>
#include <pwny/log.h>

#define SERVICES_BASE 19

#define SERVICES_LIST \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       SERVICES_BASE, \
                       API_CALL)

#define TLV_TYPE_SVC_NAME     TLV_TYPE_CUSTOM(TLV_TYPE_STRING, SERVICES_BASE, API_TYPE)
#define TLV_TYPE_SVC_DISPLAY  TLV_TYPE_CUSTOM(TLV_TYPE_STRING, SERVICES_BASE, API_TYPE + 1)
#define TLV_TYPE_SVC_STATE    TLV_TYPE_CUSTOM(TLV_TYPE_INT, SERVICES_BASE, API_TYPE)
#define TLV_TYPE_SVC_TYPE     TLV_TYPE_CUSTOM(TLV_TYPE_INT, SERVICES_BASE, API_TYPE + 1)
#define TLV_TYPE_SVC_PID      TLV_TYPE_CUSTOM(TLV_TYPE_INT, SERVICES_BASE, API_TYPE + 2)
#define TLV_TYPE_SVC_GROUP    TLV_TYPE_CUSTOM(TLV_TYPE_GROUP, SERVICES_BASE, API_TYPE)

static tlv_pkt_t *services_list(c2_t *c2)
{
    SC_HANDLE scm;
    DWORD bytes_needed;
    DWORD service_count;
    DWORD resume_handle;
    ENUM_SERVICE_STATUS_PROCESSW *services;
    DWORD buf_size;
    DWORD i;
    tlv_pkt_t *result;

    scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (scm == NULL)
    {
        log_debug("* OpenSCManager failed (%lu)\n", GetLastError());
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    bytes_needed = 0;
    service_count = 0;
    resume_handle = 0;

    EnumServicesStatusExW(
        scm, SC_ENUM_PROCESS_INFO,
        SERVICE_WIN32, SERVICE_STATE_ALL,
        NULL, 0,
        &bytes_needed, &service_count,
        &resume_handle, NULL
    );

    if (bytes_needed == 0)
    {
        CloseServiceHandle(scm);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    buf_size = bytes_needed;
    services = (ENUM_SERVICE_STATUS_PROCESSW *)malloc(buf_size);
    if (services == NULL)
    {
        CloseServiceHandle(scm);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    resume_handle = 0;
    if (!EnumServicesStatusExW(
            scm, SC_ENUM_PROCESS_INFO,
            SERVICE_WIN32, SERVICE_STATE_ALL,
            (LPBYTE)services, buf_size,
            &bytes_needed, &service_count,
            &resume_handle, NULL))
    {
        free(services);
        CloseServiceHandle(scm);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);

    for (i = 0; i < service_count; i++)
    {
        tlv_pkt_t *entry = tlv_pkt_create();
        char *name_utf8 = wchar_to_utf8(services[i].lpServiceName);
        char *display_utf8 = wchar_to_utf8(services[i].lpDisplayName);

        if (name_utf8)
        {
            tlv_pkt_add_string(entry, TLV_TYPE_SVC_NAME, name_utf8);
            free(name_utf8);
        }
        if (display_utf8)
        {
            tlv_pkt_add_string(entry, TLV_TYPE_SVC_DISPLAY, display_utf8);
            free(display_utf8);
        }

        tlv_pkt_add_u32(entry, TLV_TYPE_SVC_STATE,
                         (int32_t)services[i].ServiceStatusProcess.dwCurrentState);
        tlv_pkt_add_u32(entry, TLV_TYPE_SVC_TYPE,
                         (int32_t)services[i].ServiceStatusProcess.dwServiceType);
        tlv_pkt_add_u32(entry, TLV_TYPE_SVC_PID,
                         (int32_t)services[i].ServiceStatusProcess.dwProcessId);

        tlv_pkt_add_tlv(result, TLV_TYPE_SVC_GROUP, entry);
        tlv_pkt_destroy(entry);
    }

    free(services);
    CloseServiceHandle(scm);

    return result;
}

void register_services_api_calls(api_calls_t **api_calls)
{
    api_call_register(api_calls, SERVICES_LIST, services_list);
}

#endif
