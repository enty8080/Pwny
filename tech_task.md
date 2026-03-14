* Module stomping — map a legitimate DLL via LoadLibrary, then overwrite its .text section. The memory is then backed by a signed file, defeating memory scanners
* Indirect syscalls (jump into the middle of ntdll syscall stubs rather than using your own syscall instruction) — defeats syscall provenance checks
* Sleep obfuscation — encrypt the mapped image during sleep to avoid periodic memory scans catching PE headers in unbacked memory
Remove the named sections — use anonymous shared memory or a different transfer mechanism