# Diagnostic and test tools for the native BBC build (tooling only, never compiler logic)

None of them decides anything the compiler decides. The Python probes (`audit.py`, `probe_state.py`, `probe_order.py`,
`call_one.py`) and benchmark drivers (`bench.py`, `device_bench.py`) were deleted on 2026-11-28: nothing ran them; the
evidence records that name them keep their hashes.

- The build request is the committed `integration/bfx/bbc_request.xax` (`../README.md`); `request.py` is removed.
- `xax_bbc_check.exe <bbc.exe> <integration dir> CASES <adb> <serial> <out>`, run in an empty work directory on
  Windows: BBC's checks outside BBC, in XAX (it replaced `check.py` on 2026-11-26). See "The check tool" below.

## The check tool

For each of the 93 programs in `CASES` (pilot programs, BBC's tests, both depth-512 programs, negative loops, 60 random
programs, capacity cases) it runs `bbc.exe compile <target> <level> <out>` for android-arm64 and windows-x86_64 at
-O0 and -O1. It runs each Windows program natively and each Android program on the adb device (pushed to
`/data/local/tmp/xax-bbc`, stdin and stdout through files there). It compares the output bytes and the exact exit
status with the expectation in `CASES`, then checks the five compile error paths: their exit status, and that no new
directory entry is left. It copies `bbc.exe` and both host requests (`<integration dir>/bbc-*.xax`) into the work
directory first. `<out>` gets one line per compile (`<case> <level> <target> <compile exit> <pass>`), one per error path,
and the summary JSON line that `check.py` printed. Exit 0 when everything passes, 1 when something fails, 3 when the tool
cannot run (arguments, a file, adb).

- `CASES` is data: `XAXBBC1`, the case count, then per case its name, source, and for each input the input, the
  expected exit status and the expected output (lengths in decimal, each field ended by a newline). It was exported once
  from `check.py`'s table and interpreter, with BBC's tests at BBC `main` on 2026-11-26 (93 cases, 122 inputs).
- `check.batch` is a native batch (docs/09_AI_PROTOCOL.md §16) on `bootstrap/evolution/ledger-tool/seed.xax`. Its
  result is `xax_bbc_check.xax`, whose main has the general driver's entry, so
  `bootstrap/windows/generator/generate.sh` hosts it as `xax_bbc_check_windows.xax`. Build that with the Windows seed:
  `resolve`, then `build`.
- Main reads `CASES` and writes `<out>` through the host functions. It starts processes and handles the children's files
  through kernel32 declarations that take view pointers (`CreateProcessW` with inherited standard handles,
  `CreateFileW`, `ReadFile`, `WriteFile`, `DeleteFileW`, `CopyFileW`, `MoveFileW`, `FindFirstFileW` and the rest),
  wrapped in small helpers (`@kopen`, `@krun`, `@kfile` and others). Their work area is one committed 1 MiB view:
  ReadFile into uncommitted pages fails instead of faulting them in.
- Limits: a child's output of at most 983,039 bytes, read with one `ReadFile`, and no timeout on a child.
- Change it by a further batch on `xax_bbc_check.xax`, then regenerate the Windows store.
  `tests/test_windows_generator.py` checks both stores against the batch and the generator.

Profiling a slow native run: `gdb -p <pid> -batch -ex "info registers rip"` a few times, find the mapping in
`/proc/<pid>/maps`, subtract the mapping base and the SysV→Win64 thunk (16-byte aligned), and map the offset with
`compile_x86_64_views(reader, entry, x86_64_views_target(), backend="xax").function_offsets` of the general store
(names: build `xax_selfhost_x86_64_general.build_general_program` at commit `4a5d4b8^` for `_FN`, or match by CID).
