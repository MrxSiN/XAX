# BBC driver from the production driver (staged, 2026-11-05)

BBC's driver follows XAX's production driver (`compiler/bootstrap/xax_compiler_driver_general.xax`). These two
expected-root transactions rebuild it from the production driver after ledger transaction 0003:

| Record | Applies to | Result root |
|---|---|---|
| `1_windows_host.edit` | the production driver (ledger 0003) | `1cfe26d85deca99551e6756a2e390a16dff724c55e771e229723e8f1c993587f` |
| `2_bbc_layer.edit` | that result | `1b940f78f34bad449a8cf923a5e924147e36d1fdfe6f8b5f94fb864cc153f3f8` |

1. **Windows hosting.** The entry graph's 100 Linux host calls become Windows ones. `mmap`/`munmap` become `VirtualAlloc`/`VirtualFree`. `read`, `write` and `openat` go through BBC's borrowed-view msvcrt adapters, whose returned token rebinds later uses; `arg_copy` does the same. `close` becomes `_close`, `exit_group` becomes `ExitProcess`, and the argument helpers come from `__wgetmainargs`. The target is the PE profile. The native `xaxc edit` applies it and the native and reference verifiers accept the result.
2. **BBC layer.** Lazily committed views reserve the same 17 allocation slots as before with `MEM_RESERVE`/`PAGE_NOACCESS` and commit them on touch. The three single-process `compile` step entries swap the argument helper and turn `ExitProcess` into `SetLastError`. BBC's entry, commands, compile front and vectored exception handler are unchanged, with their calls rebound to the new driver entries. The graph proof cache is not carried. The record carries 1,176 objects. With ledger 0003 the native edit parses it and stops at `DRIVER-SNAPSHOT-CAPACITY`: the 71.7 MB result exceeds the 64 MiB store limit (OI-52). It was applied with the reference engine, and the reference verifier accepts it.

**Not yet built.** The generic Python SDK cannot lower the production driver's internal calls that return several
machine values on Win64. Inlining them all exceeds 14 GB. `bbc.exe` will be built by the XAX compiler itself once the
64 MiB store limit is lifted, and `bbc.xax` is replaced only after that build passes BBC's checks.
Until then, [`../../bbc.xax`](../../bbc.xax) stays the previous store.
