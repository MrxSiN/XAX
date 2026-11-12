# `chains` on Windows (R4 workload for `windows-x86_64-pe`)

The OI-37 `chains` workload (`../linux_chains.py`, struct-of-arrays form) as a Windows program, authored natively:
`chains.batch` is a native batch for `../../integration/bfx/bbc.xax` (root `73b8a28b…`). It supplies five types and
four `VirtualFree` declarations as objects, defines the workload function and a wrapper with the module entry's
signature, and installs the wrapper with `replace`. The function is the Linux function's view with its host calls
changed: `mmap` to `VirtualAlloc`, `write` to msvcrt `_write`, `munmap` to `VirtualFree`, `exit_group` to
`ExitProcess`. Nothing else of `bbc.xax` stays reachable; the store is 12,936 bytes.

```text
xaxc-windows-x86_64.exe edit ..\..\integration\bfx\bbc_request.xax chains_request.batch request.xax
xaxc-windows-x86_64.exe resolve request.xax snapshot.xax
xaxc-windows-x86_64.exe build snapshot.xax chains.exe chains.provenance
```

`chains.exe` is 2,560 bytes (SHA-256 `318c36d586f62e761b89158ab73515b28e612712722a72ec3eee8d7794401211`) and writes `1048576 9437420\r\n` with exit 0 on Windows 11.

`chains.c` and `chains.rs` are the baseline arms (C and Rust by definition): the Linux twins with the same host
calls changed and the same output bytes. Built with `gcc -O2`, `gcc -O3` (MinGW-W64 16.2.0) and
`rustc -C opt-level=3 -C panic=abort -C codegen-units=1` (1.99.1), each writes the same 17 bytes.

No measurement is recorded yet: timing through a shell is dominated by process start-up noise. R4 needs a
process-timing harness (to be an XAX program) and raw samples.
