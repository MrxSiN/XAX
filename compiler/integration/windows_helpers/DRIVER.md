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
| `verify <store> <diagnostic>` | The original 212-case report retains 78 accepts, 130 rejects, four declines and one diagnostic mismatch. The current driver passes the separate 160-case semantic replay: 63 accepts, 97 rejects, no declines and exact full diagnostics. The original report's archived store inputs retain their original scope; current BFX coverage is listed below. This follow-up does not rerun every original case. |
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

The separate [resource diagnosis](resource_diagnosis.json) identifies the current
self-store's entry graph, with 2,149 blocks and 37,533 nodes, as the declined
graph; its deferred-callee token is zero. It has 112 direct calls to 37 targets.
The precise node/facts reason remains undiagnosed. The private transactions and
their distinct exit protocol are in [diagnostics](diagnostics/README.md).

Five small native controls isolate another coverage limit. A single stack
resource callee and two calls to the same callee accept. Two distinct valid
identity callees in a 1,919-byte store decline. A malformed second callee rejects
with the exact reference diagnostic. A 138-byte fixture-only expected-root
[rebinding](regression/resource_rebind_same.edit) makes the valid two-call
fixture accept while retaining both callee functions in its module. These
fixtures are `regression/resource_*.xax`; they establish a small multiple-callee
coverage gap, not its equivalence to the self-store's underlying failure.

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

## Frame bitwise extension — 2026-10-21

[driver_bits1.json](driver_bits1.json) records a canonical expected-root local
edit of the frame arithmetic predicate: verified bits1 AND/OR/XOR now use the
existing zero-extending 32-bit instructions. The closed 0/1 operand set proves
this representation exact. Width1 addition/subtraction/multiplication and
width8 operations retain their existing rejection bytes. This is extra backend
coverage; no semantic input checks are bypassed.

[frame_bits1.edit](frame_bits1.edit) expects root `2b8136a8e052ccefd88f31b5d906dc986a070f2ca6e370668b73b17783ed3d17` and produces
`fd2fe37a0128b7b8661e2be7de4fe6a44108b8eb554b5becd1fa4b99629ad7bc`. The candidate receives full verification, Workspace.save and
stale-root rejection. It changes fourteen predicate nodes in one graph; seven
function identities change transitively. Generic SDK and general driver
builder/evolution stores are unchanged.

Forty-eight native build cases pass, including Boolean truth tables, nonzero
fifth Win64 arguments, unchanged 32-bit artifacts and sixteen exact preserved
rejections. All 160 existing corrected semantic cases retain full diagnostic
bytes. Of six prepared BBC workload/target snapshots, 3 build successfully;
each success is rebuilt identically twice and executed on its target. Raw
results include any remaining declines/rejections. Snapshot preparation still
uses generic bootstrap APIs. DLL/shared-library packaging, self-store/resource
callee coverage and the full native BBC source workflow remain incomplete.
No complete-build, runtime, RAM or competitor performance score follows.

## Native pointer and byte lowering — 2026-10-21

[native_lowering_evidence.json](native_lowering_evidence.json) and
[regression/native_windows](regression/native_windows/README.md) record the
current verified source root `db44f3a8cdc955cf264aec7f4eabed549bca1bcc5bcb5d0685c6a1ee4b658e18`. Three ordered expected-root
transactions add first-class pointer frame support on Windows, byte arithmetic
masking, signed displacement validation and the existing SDK Win64 page probes.
[frame_pointers.edit](frame_pointers.edit) starts at the bitwise-phase root;
[native_pointer_lowering.edit](native_pointer_lowering.edit) then changes the
descendant helpers; [native_stack_probe.edit](native_stack_probe.edit) edits the
resulting outer frame. All new helpers are asserted reachable before final save.
Generic SDK and builder source remain unchanged by these edits.

Private helper checks pass 240 displacement, 20 stack and 24 byte-store cases.
Counted native grids cover all 256 by 256 operand pairs for six byte operations
on both inline-eligible and non-inline routes: 786,432 route executions.
Twenty-four pointer/bounds programs, three stack sizes, 48 earlier controls
and 160 exact semantic diagnostic cases pass. The former 8,192-addition frame
program now returns 16392 instead of access violation. Four byte-width controls
now accept; the other 44 earlier output expectations and six further unsupported
operation diagnostics retain exact bytes.

All six original BBC target snapshots build twice identically and execute on
Windows and Pixel 8 Pro. A separate 42-target corpus passes 38: three Windows cases
hit NATIVE-CALL-ARITY [5,4], and Android deep512 verifies but declines at build.
The public BBC command store also verifies but hits that call ABI gate.
Self-store/resource-callee coverage, DLL/shared libraries and common loader
migration remain incomplete. Initial bootstrap and snapshot preparation still
use generic Python APIs. No full Python-free BBC source workflow is claimed.

Fresh native prepared-build medians are 24.25–31.83 ms, with nine scored processes
per case; source frontend/import/binding are excluded. Separate OS counter
samples record about 3.31 GiB private commit and 11.2–13.3 MiB peak resident memory.
These boundaries do not establish a full-build or competitor win. The compiler
PE is 11,866,112 bytes, SHA256 `23d0b374b3701f011e7ad3aa7f5169085b237c2078db603aab8376591c914f1c`.
Its bootstrap uses SDK 1c211da; three private helpers also rebuild byte-identically
under upstream 2e1af7c. That compatibility check is not a new whole-driver bootstrap.

## Android interval allocation — 2026-10-21

[native_android_lowering_evidence.json](native_android_lowering_evidence.json)
records source root `68ecf527e4c18c163d1fc2bdddc76335ca2f205eff4f57766cec944a67915f4c`. One expected-root transaction replaces
the ARM64 interval pass's pessimistic block-count times value-count reservation
with three-word linked records allocated as needed inside the fixed arena.
[android_sparse_intervals.edit](android_sparse_intervals.edit) expects the
previous lowering root. [android_interval_allocator.xax](android_interval_allocator.xax)
checks capacity using subtraction before advancing the head. All three call
sites propagate exhaustion through explicit borrowed-view branches. The edge
table address is unchanged. Full verification, Workspace.save and stale-root
rejection pass; no verifier rule or bounds requirement is weakened.

The [Android fixtures](regression/android/README.md) cover zero-entry and active
depth-512 loops. All 22 prepared Android snapshots build twice with identical
artifacts and provenance and pass 47 Pixel 8 Pro process executions. All 20 prior
successful Android artifacts remain exact. There are 160 unchanged diagnostic
controls, three unchanged Windows smoke artifacts, 388 allocation boundary/random
cases and six repeated exhaustion calls. Four O0/O1 framed frontend checks
retain the single BFX format. Raw reports preserve rejected private attempts.

The native compiler PE is 11,870,208 bytes, SHA-256
`fa50e6005717a521e30123ad8e9cc637aa3fe15f28a1935cf394f0d4f2ee1125`. Generic SDK `1c211da` bootstraps it with mandatory
verification and existing same-process code-fragment APIs. Bootstrap timings
and concurrent deep-build timings are unscored. This is a native prepared-stage
coverage improvement, not a full-source speedup or competitor win.

The fixed views still declare 3,550,558,208 bytes. No dynamic arena growth or
peak-RAM improvement is claimed. Android-hosted compiler execution, the public
source-to-native command, self-store/resource-callee coverage, common loading,
shared libraries and the Windows call ABI boundary remain incomplete. Android
alias/range analysis and complete native workflow remain the next priority.
