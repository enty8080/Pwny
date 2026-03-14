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
 * pe_load.h — In-process PE loader for Windows DLL tab plugins.
 *
 * Performs caller-side manual mapping: allocate, copy sections,
 * relocate, resolve imports, apply per-section protections, call
 * DllMain. No code needed inside the DLL — eliminates the need
 * for any reflective loader stub in tab plugins.
 *
 * Key evasion properties:
 *   - No well-known ReflectiveLoader export or code in the DLL
 *   - Never allocates RWX memory (RW during mapping, then per-section RX/R/RW)
 *   - No PEB-walking hash constants (uses normal LoadLibraryA for imports)
 *   - Plugin DLLs are plain PE files with no special stub
 */

#ifndef _PE_LOAD_H_
#define _PE_LOAD_H_

#include <windows.h>

/* Opaque handle returned by pe_load */
typedef struct pe_image pe_image_t;

/*
 * Manually map a PE DLL from raw bytes into the current process.
 * Returns an opaque handle on success, NULL on failure.
 * The base address can be retrieved via pe_image_base().
 */
pe_image_t *pe_load(unsigned char *image, size_t length);

/*
 * Get the base address (HMODULE equivalent) of a loaded PE image.
 */
void *pe_image_base(pe_image_t *pe);

/*
 * Resolve an exported function by name from a loaded PE image.
 * Uses a manual PE export table walk (no GetProcAddress dependency).
 */
void *pe_get_proc(pe_image_t *pe, const char *name);

/*
 * Unload a previously loaded PE image.
 * Calls DllMain(DLL_PROCESS_DETACH), then frees mapped memory.
 */
void pe_unload(pe_image_t *pe);

#endif /* _PE_LOAD_H_ */
