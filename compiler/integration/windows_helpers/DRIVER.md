# Windows native driver prototype

`driver.xax` hosts the existing general compiler driver on Windows x86-64.
Hashing, decoding, CFG analysis, typing, verification, resolution and compiler
functions execute as XAX machine code. Windows imports supply allocation,
argument conversion and binary file I/O. The PE contains no Python runtime or
foreign implementation of compiler algorithms.

This is an **EXECUTED prototype with bounded coverage**. The common Python
helper loader is unchanged. It is not a complete native BBC build path or a
native self-build fixed point. [driver_execution.json](driver_execution.json)
preserves the original run. [driver_followup.json](driver_followup.json) records
the current diagnostic correction, exact rebuild and additional native checks.

The separate [CLI timing samples](driver_verification_profile.json) compare
fresh Python and native verification processes on one Windows host. They do
not measure full BBC compilation or change competitor scores.

## Executed commands

| Command | Result and boundary |
|---|---|
| `verify <store> <diagnostic>` | The original 212-case report retains 78 accepts, 130 rejects, four declines and one diagnostic mismatch. The current driver passes the separate 160-case semantic replay: 63 accepts, 97 rejects, no declines and exact full diagnostics. It also accepts BBC's v4 importer and v5 packed Mandelbrot store. This follow-up does not rerun every original case. |
| `inspect <store> <record>` | A valid semantic store produces its binary inspection record; the existing `decode_inspection` renders it. |
| `resolve <request> <snapshot>` | The Windows PE test request produces the exact reference snapshot with the driver's resolver identity. |
| `build <snapshot> <artifact> <provenance>` | The PE smoke fixture produces reference-identical executable and provenance bytes; the executable runs correctly. Windows DLL packaging explicitly declines. |
| `edit <store> <record> <output>` | The Windows host transaction and small regression transaction replay byte for byte. Reapplying the small transaction rejects its stale root. The full flag transaction declines. |

Exit 0 means success, 1 rejection with a binary diagnostic, 2 decline with
**no validity claim**, and 3 usage or I/O failure. Successful verification
writes an empty diagnostic file. Check status and discard artifacts on nonzero
exit, including any partial I/O output.

Native verification declines the corrected driver store itself. The unchanged
Python verifier and verified workspace save establish its canonical validity
before bootstrap lowering. A private canonical probe locates the original
self-store decline at the resource-callee decision's action 2. This identifies
the stage, not its underlying cause. Do not call this native self-verification.
The canonical renderer guard now gives `semantic-43-function_byte` the reference
`XAX.TYPE.EXPECTED / TYPE-BITS` diagnostic. Its 160-case replay compares every
field, including dependencies and repair neighborhood. Broader diagnostic
coverage and the four original malformed declines remain open.

## Canonical changes and resources

The source derives from `compiler/bootstrap/xax_compiler_driver_general.xax`.
That production store, builder, request store and evolution ledger are unchanged.
The initial port reuses 501 existing functions, adapts 100 host call sites and
adds six canonical adapters for arguments, paths, binary reads/writes, open and
close. The current driver contains 509 functions: the original renderer remains
as the new guard's fallback.

| Transaction | Expected root | Change |
|---|---|---|
| [windows_host.edit](windows_host.edit) | `68347cdffbc556b17dfe771a88dd308a0751376fa9feb3e9c9237978d0092122` | Windows host interfaces and PE target |
| [windows_flags.edit](windows_flags.edit) | `eec166eafff5eac891bc8174d4191767dd01b2715a2f66ffac53fb8366f3cb0e` | Capture 522 cross-block comparisons as 64-bit flags in 95 functions and bind callers to updated helpers |
| [type_kind_order.edit](type_kind_order.edit) | `59b52b732f54086588c34ba4098d54cea0d33dd1a102aeab5749b933cdc54d71` | Bind the type renderer to a canonical kind-check guard; supply only its two new semantic objects |

Final root:
`2b8136a8e052ccefd88f31b5d906dc986a070f2ca6e370668b73b17783ed3d17`.
The records were applied with the unchanged reference edit service, followed
by full canonical verification and workspace save. Native host-record replay
passes. Native replay of the larger flag record declines despite its file
fitting the 16 MiB record view. Use verified expected-root transactions for
subsequent changes.

The guard restores the verifier's kind check before bits/float body parsing
when another object kind is read as a type. It covers copied bodies beginning
with canonical forms 1 or 7. Empty bodies, other forms and ordinary TYPE or
CONSTANT objects delegate to the existing renderer. There are 110 native helper
checks across all eleven object kinds, five first bytes and two copied lengths.
No generic Python compiler source or production evolution ledger changes.

The flag convention avoids [OI-50](../../../XAX_OPEN_ISSUES.md#oi-50--x86-64-branch-fusion-loses-cross-block-comparison-values).
The generic bootstrap register allocator can fuse a comparison into its branch
while overlooking uses in later blocks. The canonical
[control](regression/flag_base.xax) reproduces wrong emitted results; its
[transaction](regression/flag.edit) produces an equivalent
[fixed graph](regression/flag_fixed.xax) passing 256 inputs. The Python emitter
is unchanged; arbitrary programs still need a general backend repair.

The PE imports only kernel32 and msvcrt. Thirty-one adapter checks cover spaces
and Unicode, binary bytes including `00`, `1A`, `FF`, 65,536-byte chunks, EOF,
invalid counts and failed handles. Five driver usage/I/O/path checks also pass.

Twenty-two inherited allocations declare **3,550,558,208 bytes** of views.
This is an allocation budget, **not measured resident RAM**. Allocation failure
traps. Source input has a 32 MiB view; edit records have a 16 MiB view. Component
limits can decline earlier. Combined UTF-8 command/file arguments, including
NUL terminators, must fit the 4,096-byte argument staging view.

## Bootstrap rebuild

Run from the repository root with 64-bit Python and `XAX_REQUIRE_NATIVE` unset.
This explicitly disclosed bootstrap uses unchanged generic Python utilities,
which may record fallback authority. It is not claimed to execute in XAX.
Lowering this large store takes substantial time.

```powershell
$env:PYTHONPATH = (Resolve-Path compiler/src).Path
@'
from pathlib import Path
import xax_compiler as X
import xax_inline as I
from xax_x86_64 import compile_native
from xax_pe import emit_pe_executable

r = X.StoreReader(Path('compiler/integration/windows_helpers/driver.xax').read_bytes(), proof_cache=X.ProofCache())
X.verify_store(r)
m = next(r.get(c) for c in r.get(r.root_cid).references if r.get(c).kind == X.Kind.MODULE)
entry = next(r.get(c) for c in m.references if r.get(c).kind == X.Kind.FUNCTION)
target = next(r.get(c) for c in m.references if r.get(c).kind == X.Kind.TARGET)
views = {}
for f in r.objects():
    if f.kind != X.Kind.FUNCTION:
        continue
    graph = X.parse_function_graph(f, r.get)
    blocks, first = I._lift(graph)
    while I._merge_blocks(blocks, first) or I._thread_jumps(blocks, first) or I._fold_pack(blocks, r.get) or I._store_truncations(blocks, r.get) or I._local_parameters(blocks, first) or I._dead_code(blocks):
        pass
    views[f.cid] = I._lower(graph, I._layout(blocks, first), first)
image = compile_native(r, entry.cid, target.cid, verified=True,
                       views=views, prefetches={cid: {} for cid in views})
output = Path('build/windows_helpers/xaxc-windows.exe')
output.parent.mkdir(parents=True, exist_ok=True)
output.write_bytes(emit_pe_executable(image))
'@ | python -B -
```

Full verification precedes `verified=True` in the same process with a fresh
local cache. Existing exact simplifiers/layout run without leaf expansion or
prefetch selection. These lowering views leave canonical source unchanged.
PE entry uses normal Win64; do not request Linux-style `process_entry=True`.

## Small native checks

These commands execute the PE directly and write generated files in ignored
`build/`. The edit output must equal `regression/flag_fixed.xax` byte for byte.
Reapplying that record to its output must return 1 for a stale root.

```powershell
$env:XAX_REQUIRE_NATIVE = '1'
& .\build\windows_helpers\xaxc-windows.exe verify compiler/integration/windows_helpers/regression/flag_fixed.xax build/windows_helpers/check.diag
& .\build\windows_helpers\xaxc-windows.exe edit compiler/integration/windows_helpers/regression/flag_base.xax compiler/integration/windows_helpers/regression/flag.edit build/windows_helpers/flag.xax
& .\build\windows_helpers\xaxc-windows.exe build compiler/integration/windows_helpers/regression/pe_smoke.xax build/windows_helpers/echo.exe build/windows_helpers/echo.provenance
```

The smoke executable copies up to 4 KiB of stdin to stdout and exits with its
byte count. External full test transports stay outside the implementation
repositories and are identified by hashes in the evidence. No full BBC pipeline,
competitor score, RAM or Android result follows from these checks. A second
independent bootstrap rebuild of the original 508-function source reproduces
its PE hash exactly. The corrected PE is 11,864,576 bytes. Its bootstrap reused
507 immutable SDK function fragments in the same process and freshly compiled
the changed entry and guard through existing APIs; this is not a cold-build
measurement or native self-build. The follow-up preserves that distinction.
