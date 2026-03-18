# Code-Only Tabs (COT) — Technical Report

## Overview

Code-Only Tabs (COT) is a plugin loading mechanism that replaces the traditional
DLL-drop-and-LoadLibrary approach with **module stomping** of flat code blobs.
The goal is to eliminate every artifact that AV/EDR engines use to detect
dynamically loaded plugin code:

| Artifact                       | Legacy DLL path          | COT path             |
|--------------------------------|--------------------------|----------------------|
| File on disk                   | Temp DLL in `%TEMP%`     | **None**             |
| PE headers in memory           | Full MZ/PE at base addr  | **None**             |
| Unsigned module in VAD tree    | Yes (temp DLL)           | **No** — backed by signed system DLL |
| Import Address Table           | Present (Win32 imports)  | **None** — vtable only |
| Hooked API calls (ntdll stubs) | All go through IAT       | **Indirect** — resolved at init |
| `CreateFile` / `WriteFile`     | Yes (temp file creation)  | **None**             |

---

## Architecture

### 1. Build-Time: `pe2cot.py`

Plugins are first compiled as standard DLLs (same toolchain, same compiler
flags). A post-build step (`scripts/pe2cot.py`) then strips the DLL into a
raw code blob:

```
┌─────────────────────────────┐
│  Compiled Plugin DLL        │
│  ┌───────┐ ┌──────┐        │
│  │.text  │ │.rdata│ ...    │
│  └───────┘ └──────┘        │
│  Exports: TabInitCOT        │
└─────────────────────────────┘
              │
              ▼  pe2cot.py
┌─────────────────────────────┐
│  .cot file                  │
│  ┌──────────────────┐       │
│  │ cot_header_t     │ 24 B  │
│  │  magic: "COT\0"  │       │
│  │  version: 1      │       │
│  │  entry_offset    │       │
│  │  code_size       │       │
│  │  rw_offset       │       │
│  │  rw_size         │       │
│  ├──────────────────┤       │
│  │ flat code blob   │       │
│  │ (.text+.rdata+   │       │
│  │  .data+.bss+...) │       │
│  └──────────────────┘       │
└─────────────────────────────┘
```

**What pe2cot.py does:**

1. Parses the PE headers to enumerate sections.
2. Discards `.reloc` (relocations are useless — the code will run at an
   arbitrary address chosen at stomp time).
3. Lays out remaining sections in virtual order (`.text`, `.rdata`, `.data`,
   `.bss`, etc.) into a contiguous byte array.
4. Locates the `TabInitCOT` export via the PE export directory and records
   its offset relative to the blob start.
5. Identifies writable sections (`.data`, `.bss`, `.tls`) by checking
   `IMAGE_SCN_MEM_WRITE` (0x80000000) and records their span as `rw_offset`
   / `rw_size`.
6. Writes the 24-byte `cot_header_t` + flat blob.

**Result:** No MZ signature, no PE headers, no section table, no import
directory, no export directory — just raw machine code and data.

### 2. Transport

The `.cot` blob is stored in `pwny/tabs/<platform>/<arch>/` alongside legacy
DLL plugins. The Python session loader (`pwny/plugins.py`) reads the file and
sends it to the implant via `BUILTIN_ADD_TAB_BUFFER` — the same TLV channel
used for DLLs. No protocol changes needed.

### 3. Runtime: Module Stomping Loader (`tabs_add_cot`)

When `tabs_add()` receives a buffer, it first checks the magic bytes:

```c
if (cot_is_cot_image(image, length))
    return tabs_add_cot(tabs, id, image, length, c2);
```

If the magic is `0x00544F43` ("COT\0"), the COT loader takes over:

#### Step 1 — Load a Sacrificial Signed DLL

```c
static const char *stomp_candidates[] = {
    "dbgcore.dll",
    "dbghelp.dll",
    "wldp.dll",
    "srpapi.dll",
    NULL
};

hStomp = LoadLibraryA(stomp_candidates[i]);
```

Each candidate is a **Microsoft-signed** system DLL that ships with every
Windows installation. The loader iterates until it finds one whose
`SizeOfImage` is large enough to hold the COT blob (+ 0x1000 for the PE
header page we skip).

**Why these DLLs:**
- `dbgcore.dll` / `dbghelp.dll` — Debug support, large image (~600 KB+),
  rarely resident outside debugger contexts.
- `wldp.dll` — Windows Lockdown Policy, moderate size.
- `srpapi.dll` — Software Restriction Policies, moderate size.

All are legitimately loadable by any process. Their presence in the loaded
module list doesn't raise suspicion since many applications reference debug
or policy APIs.

#### Step 2 — VirtualProtect to RW

```c
stomp_text = (BYTE *)hStomp + 0x1000;
VirtualProtect(stomp_text, code_size, PAGE_READWRITE, &dwOld);
```

We target offset `0x1000` — the first page *after* the PE header. The PE
header page at offset `0x0` is left untouched, so the module's headers remain
valid from the OS perspective.

**Stealth note:** `VirtualProtect` on a module's own pages is common (e.g.
JIT compilers, .NET runtime, Chromium V8). The transition is strictly
`RX → RW`, never `RWX`.

#### Step 3 — Overwrite (Stomp)

```c
memcpy(stomp_text, code, code_size);
```

Plain `memcpy` into our own process memory. No `WriteProcessMemory`, no
`NtWriteVirtualMemory`, no cross-process handle. This is a **same-process,
same-thread** memory copy — the least suspicious write primitive possible.

#### Step 4 — Set Final Page Protections

```c
// Code/rodata region → RX
VirtualProtect(stomp_text, hdr->rw_offset, PAGE_EXECUTE_READ, &dwOld);

// Writable region (.data/.bss) → RW
VirtualProtect((BYTE *)stomp_text + hdr->rw_offset,
               hdr->rw_size, PAGE_READWRITE, &dwOld);
```

Memory protections follow proper **W^X discipline**:
- `.text` + `.rdata` pages → `PAGE_EXECUTE_READ` (RX)
- `.data` + `.bss` pages → `PAGE_READWRITE` (RW)

At no point do any pages have simultaneous Write + Execute. This avoids
triggering `PAGE_EXECUTE_READWRITE` heuristics that many EDRs flag.

#### Step 5 — Flush and Execute

```c
FlushInstructionCache(GetCurrentProcess(), stomp_text, code_size);

entry = (cot_init_t)((BYTE *)stomp_text + hdr->entry_offset);
entry(vt, &tab_new->api_calls, &c2->pipes);
```

Execution begins via a **direct function pointer call** in the current
thread. No `CreateThread`, no `CreateRemoteThread`, no APC injection, no
callback-based execution (e.g. `TpAllocWork`). The code simply runs as a
normal function call from the main event loop.

### 4. Plugin-Side: Vtable-Driven API Access

COT plugins have **zero imports**. Every external function is accessed through
a vtable (`tab_vtable_t`) passed at initialization:

```c
typedef struct {
    void (*api_call_register)(...);
    void (*api_pipe_register)(...);
    tlv_pkt_t *(*api_craft_tlv_pkt)(...);
    tlv_pkt_t *(*tlv_pkt_create)(void);
    void       (*tlv_pkt_destroy)(...);
    int (*tlv_pkt_add_u32)(...);
    int (*tlv_pkt_add_string)(...);
    int (*tlv_pkt_add_bytes)(...);
    int (*tlv_pkt_add_tlv)(...);
    int (*tlv_pkt_get_u32)(...);
    int (*tlv_pkt_get_string)(...);
    int (*tlv_pkt_get_bytes)(...);
    void (*log_debug)(...);
    void *(*resolve)(const char *module, const char *func);
    void *_reserved[8];
} tab_vtable_t;
```

**13 Pwny API functions** (determined by exhaustive audit of all 22 plugins)
plus a generic `resolve()` for Win32 APIs. The vtable is:
- Heap-allocated by the host (persists for the tab's lifetime).
- Populated from the host's own statically-linked symbols — no new IAT
  entries, no `GetProcAddress` calls at the host level.
- The `resolve` field is a wrapper that does
  `GetModuleHandleA → LoadLibraryA → GetProcAddress` — the plugin calls it
  once at init to cache Win32 function pointers.

Transparent macros redirect standard API names through the vtable:

```c
#define api_craft_tlv_pkt(s, r) _cot_vt->api_craft_tlv_pkt(s, r)
#define tlv_pkt_create()        _cot_vt->tlv_pkt_create()
// ... etc.
```

This means plugin source code reads identically to the DLL version — only
the header inclusion changes.

### 5. Cleanup

When a COT tab is unloaded (`tabs_delete` / `tabs_free`):

1. **Zero the stomped pages** — `VirtualProtect(RW)` → `SecureZeroMemory` →
   `VirtualProtect(RX)`. This erases any code from the sacrifice DLL's pages
   so post-mortem forensics find only zeroes.
2. **Free the vtable** — `free(tab->cot_vtable)`.
3. **Unload the sacrifice** — `FreeLibrary(tab->hStomp)`.

---

## Stealth Analysis

### What AV/EDR Engines Typically Detect

| Detection Vector               | COT Exposure | Notes |
|---------------------------------|:---:|-------|
| **File-drop scanning**          | Clean | No file touches disk. Blob arrives over encrypted C2 channel. |
| **PE header scanning in memory** | Clean | No MZ/PE anywhere in the stomped region. Headers belong to the real signed DLL. |
| **Unsigned module in VAD**      | Clean | VAD entry points to signed `dbghelp.dll` (or other candidate) on disk. OS considers pages file-backed by a trusted image. |
| **IAT/EAT hooking detection**   | Clean | COT blob has no import table. All calls go through vtable (data pointers on the heap, not in any module image). |
| **RWX page detection**          | Clean | Strict W^X: pages are RW during copy, then RX for code or RW for data. Never simultaneous. |
| **`WriteProcessMemory` hooks**  | Clean | Uses `memcpy` (same-process, same-thread). Not an API that EDR hooks. |
| **Thread creation monitoring**  | Clean | No new threads. Entry point called as a direct function invocation from the existing thread. |
| **`VirtualAlloc(RWX)` hooks**   | Clean | Never called. `VirtualProtect` is used on existing pages of a loaded module. |
| **Module load callbacks**       | Neutral | `LoadLibraryA` is called for the sacrifice DLL. This is a legitimate signed DLL load — same as if the app was using debug APIs. |
| **ETW / kernel callbacks**      | Low risk | `LdrDllNotification` fires for the sacrifice load and sees a signed Microsoft DLL. No notification for the stomp itself. |
| **Stack-based heuristics**      | Low risk | When COT code executes, the instruction pointer is inside the VAD range of a signed DLL. Return addresses on the stack trace back to `main.exe`. |
| **Code-integrity / CFG**        | Low risk | The sacrifice DLL's CFG bitmap isn't updated, but COT entry is called via function pointer from the host — not through indirect call dispatch. |
| **Memory scanning (YARA rules)** | Depends | The raw code blob has no PE signatures, no ASCII strings like "This program cannot be run in DOS mode", no MZ header. Static byte patterns in the code itself could still match custom rules. |

### Remaining Risks

1. **`VirtualProtect` on signed module pages** — Some advanced EDRs
   (CrowdStrike, SentinelOne) monitor `VirtualProtect` calls that change
   protections on pages backed by signed images. This is the strongest
   residual signal. Mitigation: the protection changes are brief
   (RX→RW→copy→RX) and use legitimate page sizes.

2. **Content mismatch between disk and memory** — If an EDR compares the
   on-disk `.text` section of `dbghelp.dll` with its in-memory contents,
   the mismatch reveals tampering. This is sometimes called "module
   integrity checking" or "unbacked executable memory detection." Not all
   EDRs do this; those that do typically only scan on alert, not continuously.

3. **Sacrifice DLL choice** — Loading `dbgcore.dll` in a process that
   otherwise never uses debug APIs could be anomalous in a behavioral model.
   The candidate list is configurable and can be tuned per-target.

4. **`FlushInstructionCache`** — Called after the stomp. This is a normal
   API but its use on a signed module's pages, combined with prior
   `VirtualProtect` calls, could form a behavioral sequence that some
   heuristic engines recognize as "module stomping."

### Why This Is Better Than the DLL Path

The legacy path (`write_temp_dll → LoadLibraryA`) triggers:
- `CreateFile` / `WriteFile` on a temp directory → **file-drop detection**.
- `LoadLibraryA` on an unsigned DLL → **unsigned module alert in VAD**.
- Full PE headers in memory → **in-memory PE scanning**.
- Populated IAT → **import table analysis reveals capabilities**.
- Temp file deletion after load → **suspicious create-load-delete pattern**.

COT eliminates **all five** of these signals.

---

## Binary Format Reference

### `cot_header_t` (24 bytes, little-endian, packed)

| Offset | Size | Field          | Description |
|--------|------|----------------|-------------|
| 0x00   | 4    | `magic`        | `0x00544F43` ("COT\0") |
| 0x04   | 4    | `version`      | `1` |
| 0x08   | 4    | `entry_offset` | Offset of `TabInitCOT` from start of code blob |
| 0x0C   | 4    | `code_size`    | Total size of flat code blob in bytes |
| 0x10   | 4    | `rw_offset`    | Offset of writable (.data/.bss) region (0 = none) |
| 0x14   | 4    | `rw_size`      | Size of writable region in bytes (0 = none) |

### Memory Layout After Stomp

```
Sacrifice DLL base (hStomp)
├── 0x0000  PE header (untouched, valid signed headers)
├── 0x1000  COT .text + .rdata      [PAGE_EXECUTE_READ]
├── ...     COT .data + .bss        [PAGE_READWRITE]
├── ...     COT trailing sections   [PAGE_EXECUTE_READ]
└── ...     Remaining sacrifice pages (untouched)
```

---

## Porting a Plugin to COT

1. **Include order** — Include real Pwny headers first, then:
   ```c
   #define COT_PLUGIN
   #include <pwny/tab_cot.h>
   ```

2. **Win32 API resolution** — Replace direct calls with function pointers
   resolved via `cot_resolve()` at init time:
   ```c
   typedef HMODULE (WINAPI *fn_LoadLibraryA)(LPCSTR);
   static fn_LoadLibraryA pLoadLibraryA;

   // In COT_ENTRY:
   pLoadLibraryA = (fn_LoadLibraryA)cot_resolve("kernel32.dll", "LoadLibraryA");
   ```

3. **Entry point** — Replace `TAB_DLL_EXPORT void TabInit(api_calls_t **)`
   with `COT_ENTRY { ... }`.

4. **CMake** — Add the plugin name to `COT_PLUGINS` list in CMakeLists.txt.

5. **C runtime** — Avoid `memcpy`, `printf`, etc. unless they're linked
   statically through `tab_dll`. Use inline helpers (`cot_memcpy`) or
   resolve from `msvcrt.dll` / `ucrtbase.dll` via `cot_resolve()`.

---

## Inspecting COT Blobs — `cotinfo.py`

`scripts/cotinfo.py` parses COT files and prints header fields, memory layout,
entropy, and optional hex dumps. No external dependencies.

### Usage

```bash
# Single file
python3 scripts/cotinfo.py pwny/tabs/windows/x64/forge

# Scan a directory (recursively finds all COT files by magic)
python3 scripts/cotinfo.py -d pwny/tabs/windows/x64/

# Include hex dump of entry point and blob header
python3 scripts/cotinfo.py --hex pwny/tabs/windows/x64/forge
```

### Sample Output — Single File

```
$ python3 scripts/cotinfo.py pwny/tabs/windows/x64/forge
[*] File:          pwny/tabs/windows/x64/forge
[*] Plugin:        forge
[*] File size:     36904 bytes (36.0 KB)
[*] Magic:         0x00544F43 ("COT\0")
[*] Version:       1
[*] Code size:     36880 bytes (36.0 KB)
[*] Entry offset:  0xD80 (stomp VA: 0x1D80)
[*] RW region:     offset 0x2000, size 28688 bytes (28.0 KB)
[*] RX region:     offset 0x0, size 8192 bytes (8.0 KB)
[*] Entropy:       1.87 / 8.00
[*] Header:        24 bytes
[*] Memory layout after stomp:
     hStomp + 0x0000  PE header (sacrifice, untouched)
     hStomp + 0x1000  .text + .rdata  [RX]  (8192 bytes)
     hStomp + 0x3000  .data + .bss    [RW]  (28688 bytes)
```

### Sample Output — Directory Scan (excerpt)

```
$ python3 scripts/cotinfo.py -d pwny/tabs/windows/x64/
[*] File:          pwny/tabs/windows/x64/bof_loader
[*] Plugin:        bof_loader
[*] File size:     36904 bytes (36.0 KB)
[*] Magic:         0x00544F43 ("COT\0")
[*] Version:       1
[*] Code size:     36880 bytes (36.0 KB)
[*] Entry offset:  0xD80 (stomp VA: 0x1D80)
[*] RW region:     offset 0x2000, size 28688 bytes (28.0 KB)
[*] RX region:     offset 0x0, size 8192 bytes (8.0 KB)
[*] Entropy:       1.91 / 8.00
[*] Header:        24 bytes
[*] Memory layout after stomp:
     hStomp + 0x0000  PE header (sacrifice, untouched)
     hStomp + 0x1000  .text + .rdata  [RX]  (8192 bytes)
     hStomp + 0x3000  .data + .bss    [RW]  (28688 bytes)

[*] File:          pwny/tabs/windows/x64/evasion
[*] Plugin:        evasion
...

[*] Analyzed 22/22 COT files.
```

### Fields Explained

| Field | Meaning |
|-------|---------|
| **Entry offset** | Offset of `TabInitCOT` within the code blob (hex). **Stomp VA** adds `0x1000` for the preserved PE header page. |
| **RW region** | Writable `.data` / `.bss` span — gets `PAGE_READWRITE` after stomp. |
| **RX region** | Read-execute `.text` + `.rdata` span — gets `PAGE_EXECUTE_READ`. |
| **Entropy** | Shannon entropy (0.0–8.0). Low values indicate sparse blobs (mostly zero `.bss`). Encrypted or packed code will be closer to 8.0. |
| **Trailing RX** | Any execute-read pages after the RW region (e.g. `.pdata`, `.xdata`). |

---

## File Inventory

| File | Role |
|------|------|
| `include/mingw/pwny/tab_cot.h` | COT binary format, vtable struct, plugin-side macros |
| `include/pwny/tabs.h` | `tabs_t` struct with COT fields (`hStomp`, `cot_code`, `cot_size`, `cot_vtable`) |
| `src/tabs.c` | COT loader (`tabs_add_cot`), vtable builder, auto-detection, cleanup |
| `scripts/pe2cot.py` | Post-build PE→COT extractor |
| `scripts/cotinfo.py` | COT blob inspector (header parsing, layout, entropy, hex dump) |
| `plugins/evasion/evasion.c` | Reference COT plugin (AMSI/ETW patching) |
| `CMakeLists.txt` | Build system with `COT_PLUGINS` list and pe2cot.py post-build step |
