# Lazily committed decision tape — 2026-10-29

BBC decisions now borrow views of **2,147,246,080 bytes** (2 GiB − 232 KiB)
instead of 65,536 for the tape, input and output. Hosts reserve that address
range and commit pages only when a program touches them, so a small program
still uses a few pages while a program can move past cell 65,535 until it
reaches the new edge. The BFX wire format, decoder and Brainfuck semantics are
unchanged: moving left of cell 0 or past the last cell still fails at the first
crossing with status 1.

Input and output capacity stay at 65,536 bytes (the decision's length checks and
the hosts' read loops are unchanged). The private `bfc_call_v1` shared-library
host ([SHARED.md](SHARED.md)) is **not migrated**: its C ABI takes a caller tape
of 65,536 bytes, so decisions bound by the new `bbc` do not fit its placeholder.

## Why this extent

- Views carry their extent in the type (`heap_view<E>`), so a view cannot grow;
  the largest useful reservation is the growth mechanism.
- The x86-64 backend encodes checked bounds as signed 32-bit immediates: an
  extent of 2,147,483,648 builds, 4,294,963,200 rejects with
  `NATIVE-CHECKED-BOUND-ENCODABLE`. ARM64 builds the 4,294,963,200 probe.
- The importer emits a fixed 18-object reference set with hard-coded canonical
  indices. Among extents up to 2^31 in 4 KiB steps, 2,147,246,080 is the largest
  whose view type and `E − 1` bound constant keep the same CID-sorted positions
  in the store, the function and the graph fragment, so no index changes.

Lifting these limits is [OI-52](../../../XAX_OPEN_ISSUES.md).

## Hosts

- **Windows** (`standalone_windows.xax`, `bbc-windows-x86_64.xax`): registers the
  existing commit-on-touch vectored exception handler of `bbc.xax` (reused by
  CID), reserves the three views with `MEM_RESERVE` / `PAGE_NOACCESS`, and
  explicitly commits the first 65,536 bytes of the input and output views
  because `ReadFile`/`WriteFile` fail on reserved pages instead of faulting.
  The handler commits the touched 1 MiB slice zero-filled and resumes.
- **Android** (`standalone_arm64.xax`, `bbc-android-arm64.xax`): the existing
  anonymous private `mmap` already zero-fills pages on first touch; only the
  allocation sizes and the `munmap` length (part of its declaration name) change.
- The decision still clears `[0, 65536)` on entry. Each process host runs one
  decision on a fresh reservation, so the rest of the tape is zero. A host that
  reuses a tape across calls must provide a zero tape (for example by
  decommitting or `MADV_DONTNEED`) before binding decisions from this importer.

## Transactions

Expected-root `REPLACE_REFERENCE` records in
[transactions/dynamic_tape/](transactions/dynamic_tape/), each fully verified,
saved, and rejected as stale when replayed on its result. The native driver
(`xaxc edit`) replays records 1–3 and 6–11 to byte-identical stores; records 4–5
apply to `bbc.xax`, which exceeds the driver's file capacity
(`XAX.DRIVER.CAPACITY` / `DRIVER-FILE-CAPACITY`), so the Python reference
application and full verification establish them.

| # | Store | Change |
|---|---|---|
| 1 | `import_bfx.xax` | Emitter block 15: view type extent, `E − 1` bound constant, five CID copies, 2-byte longer type record (two byte stores become 2-byte stores, table lengths 46/45 → 48/47). In-place node changes only |
| 2, 4 | `compile_windows.xax`, `bbc.xax` | The same importer edit |
| 3, 5 | `compile_windows.xax`, `bbc.xax` | `bind` framing: the packed request root, host fragment and placeholder decision CIDs of both targets (26 words) |
| 6, 9 | Windows request and standalone host | View types and allocation sizes |
| 7, 10 | Windows request and standalone host | Handler registration, reservation flags, explicit 64 KiB I/O commits |
| 8, 11 | Android request and standalone host | View types, allocation sizes, `munmap` length |

Authoring transport: the records were produced with the existing generic
`xax_compiler` constructors and `xax_selfhost_edit.edit_record` from short
external scripts (not committed), the same method as earlier BBC transactions.
No generic SDK file and no BBC Brainfuck changed.

## Bootstrap

`bbc.exe` is rebuilt from `bbc.xax` with the generic recipes: the driver recipe
for functions present in `windows_helpers/driver.xax` and for large entry
variants absent from `compile_windows.xax`, the BBC recipe for the rest. A
rebuild of the previous `bbc.xax` with this rule compiles and runs programs
correctly but is not byte-identical to the previously tested PE, so the exact
per-function split differs from the original bootstrap. The new PE is 15,264,768
bytes. Python 3.12 was used.

## Evidence

[dynamic_tape_evidence.json](dynamic_tape_evidence.json): Windows 11 x86-64
native runs and Pixel 8 Pro device runs, 2026-10-29.
