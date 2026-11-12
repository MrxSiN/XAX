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

`chains.exe` is 2,560 bytes (SHA-256 `90e48100e0e15a7e3e3d301868369aee2855715af18bab412bd5c9825a147889`) and writes `1048576 9437420
` with exit 0 on Windows 11.

Since 2026-11-12 the function differs from the Linux view in the lookup walk (`XAX_OPEN_ISSUES.md`, OI-58): links
are masked with 2097151 and the key and link views hold 2^21 slots, so the walk's loads are proven in bounds and
carry no check; the raw bucket head is passed in an unused parameter, which keeps the next-lookup prefetch
(ADR-211); `steps` is used in the block before the walk and `found` is read by dominance, which keeps both out of
frame slots on Win64. The inserts, the lookups and the output are the same. The first form is in git history
(`318c36d5…`).

`chains.c` and `chains.rs` are the baseline arms (C and Rust by definition): the Linux twins with the same host
calls changed and the same output bytes. `chains_soa.c` is a third: C with the XAX arm's data layout (two arrays,
32-bit slot numbers), no mask and no bounds check. It is the fastest arm, so it is in the comparison. Built with `gcc -O2`, `gcc -O3` (MinGW-W64 16.2.0) and
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

`samples_run5.txt` to `samples_run8.txt` are four runs of the six arms on Windows 11 (2026-11-12, the current
batch); `../windows_chains_soa_evidence.json` holds run 5 as samples:

```text
xbench.exe chains.exe c-O2.exe c-O3.exe rust.exe soa-O2.exe soa-O3.exe >NUL 2>samples.txt
```

Result: the XAX arm (median 122 to 132 ms) leads `rustc -O3` (0.87x to 0.92x) and is behind the C twin with its
own data layout (1.19x to 1.26x of the faster `chains_soa.c` build). That is not a lead, so R4 is withheld;
`XAX_OPEN_ISSUES.md` OI-58 has the causes. XAX has the smallest file (2,560 bytes against 62,598 and 126,464).

`samples_run1.txt` to `samples_run4.txt` are the earlier four-arm runs of the first batch
(`../windows_chains_evidence.json`): parity with `rustc -O3` (0.96x to 1.03x).
