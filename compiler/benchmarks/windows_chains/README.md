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

## Harness and measurement

`xbench.batch` is the timing harness, an XAX program made the same way (a batch on `bbc.xax`; `xbench.exe` is 3,584
bytes). It supplies six kernel32 declarations as objects (`CreateProcessA`, `WaitForSingleObject`,
`QueryPerformanceCounter`, `GetExitCodeProcess`, `K32GetProcessMemoryInfo`, `CloseHandle`). It runs each program
named on its command line once per round for 34 rounds, rotating the order by one each round, and writes one line
per run to standard error: arm number, QueryPerformanceCounter ticks (100 ns), exit status, peak working set bytes,
each as 20 decimal digits.

```text
xbench.exe chains.exe c-O2.exe c-O3.exe rust.exe >NUL 2>samples.txt
```

`samples_run1.txt` to `samples_run4.txt` are four runs on Windows 11 (2026-11-12);
`../windows_chains_evidence.json` holds run 1 as samples. Result: XAX is at parity with `rustc -O3` (median ratio
1.019, 0.960, 1.028, 0.978 over the four runs) and about 0.63x `gcc`. That is not a lead, so R4 is withheld.
XAX has the smallest file (2,560 bytes against 62,598 and 126,464) and the smallest peak working set (21.8 MB
against 26.3 and 22.7).
