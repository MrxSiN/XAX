# BBX verified graph import

Status: EXECUTED on a Pixel 8 Pro, Android 17/API 37, ARM64, 2026-10-18.
The BBX decision runs natively inside the XAX-built Activity. Three native
frontend rebuild generations also agree exactly. The compiler host uses
Python bootstrap helpers on Windows; this is not XAX-backend self-hosting.
Windows x86-64 PE decision execution and three native frontend generations
also passed. Linux x86-64 still has no available execution host.

`compiler/src/xax_bbx.py` is XAX construction tooling for BBX records from
the separate BBC Brainfuck frontend. It does not accept or parse raw human
Brainfuck source. BBC remains responsible for source filtering and validation;
the importer independently checks the portable record as a trust boundary.

## Record

BBX version 1 is `BBX` magic, binary version byte `01`, status byte `00`,
little-endian u16 instruction count, and exactly that many original instruction
bytes. Count is at most 3840 and bracket nesting at most 255. Error records,
old magic, unknown versions/statuses, partial/trailing records, noninstructions,
unmatched brackets and unsupported limits reject before graph construction.
The normative wire/profile contract belongs to BBC's `docs/BBX_CONTRACT.md`
and `docs/BRAINFUCK_PROFILE.md`. Saved modules use `.bbx`.

## Construction and typed call

`construct_bbx(record, input_extent=65536, output_extent=65536)` returns an
`ImportedBBX` containing a verified reader, function and Android ARM64 integer
target by default. Pass `target_object=x86_64_windows_pe_target()` to reuse the
same graph construction for Windows. The fixed view extents must be integers
from 1 through 65536; runtime
input length and output capacity may be zero and cannot exceed those extents.

The function takes an input triple, output triple, tape triple, u32 input
length and u32 output capacity. A triple is a pointer, an extent-bearing linear
heap-view proof and its memory frontier. Input is read-only and initialized;
output is writable and initialized; tape is a writable initialized
65536-byte view. All views must be live and distinct. Every exit gives the
three borrowed triples back in order. The verifier checks the graph's resource,
initialization, memory/effect and control-flow obligations; no checks are waived.

The only machine return is `(output_length << 32) | status`. Borrowed pointer
returns and proof values are erased according to XAX's existing ABI rules.
Status values: 0 success, 1 tape bounds, 2 output capacity, 3 invalid logical
lengths. Failure can retain a prefix; callers must discard it.

The graph explicitly zeroes all tape cells at every valid entry, then lowers
each instruction to checked byte operations and control-flow branches. Cell
operations use bits<8> wrapping arithmetic. Input reads after EOF store zero;
pointer movement fails before leaving 0..65535; output checks logical capacity
before writing. There is no opcode fetch loop, interpreter, callback or foreign
runtime dependency in the generated decision function.

This is an **internal typed XAX call**, not an untrusted C pointer ABI. The
Android application must establish the view allocation, initialization,
non-aliasing and lifetime obligations before calling it. Exporting the raw
function does not create those proofs for arbitrary foreign callers. Tests
export a symbol only to inspect ELF lowering and emulate code with valid
mapped buffers. The sample JNI caller below establishes those obligations.

Initial construction uses `GraphBuilder` and `program_store`, which verifies
the resulting canonical store. Constructed graphs are authoritative. Apply
subsequent graph edits through the ordinary workspace transaction interface;
the adapter is not an alternate XAX text syntax or graph mutation API.

## Android application

`compiler/src/xax_bbx_android.py` constructs both native and managed XAX graphs.
The JNI caller allocates distinct zeroed input/output/tape buffers with Bionic
calloc, writes one input byte, calls the typed core directly, validates its
packed result and output byte, and frees every buffer on returning paths.
It returns 0 permit, 1 block, or 2 error. Inputs outside 0..255 and capacities
outside 0..16 reject; a core failure or unexpected byte/count fails closed.
Allocation failure uses XAX's null-heap trap before memory access; OOM
terminates the app process rather than returning a recoverable status.

The managed graph reads Intent integer extras `flag` (default 0) and `capacity`
(default 1), invokes JNI, labels the result and shows/hides a sample row.
It compiles through XAX's JVM-to-DEX path. The platform shell only loads the
library and forwards the Activity callback; it contains no decision logic.
XAX emits the shared ELF, manifest and APK. No Java source or BF VM is shipped.

From `compiler/` with `src` on PYTHONPATH:
`python -m benchmarks.android_bbx_app module.bbx output-directory`.
This demonstration uses the existing public test signing fixture, which must
never sign a production release. Install `bbx-decision.apk`, then launch
`org.bbc.bbxdecision/.DecisionActivity` using ADB `am start -S -W -n` with
`--ei flag 0 --ei capacity 1` (permit), flag 1 (block), or capacity 0 (error).
The app performs a synchronous native call and visibly hides the row on error.

## Verification and remaining gates

`compiler/tests/test_xax_bbx.py` contains seven unittest methods, including
29 ARM64 instruction-emulator runs, malformed record/extent cases and a shared
ELF inspection. Emulated cases compare an independent eight-command oracle,
check untouched input/output canaries, seed the tape with nonzero bytes, and
exercise both bounds and all status paths. Parser limits test 3840 commands
and nesting 255; they are not large-module performance benchmarks.

Run with `compiler/src` and `compiler/tests` on PYTHONPATH:
`python -m unittest -v test_xax_bbx`. Unicorn is a test dependency already in
the project's optional test dependencies. Windows uses Python bootstrap host
helpers; this does not prove XAX-hosted compiler/self-host execution.

`test_xax_bbx_android` adds four methods with 15 ARM64 caller checks, including
three precise null-allocation traps, failed calls, invalid inputs, unexpected
output and allocation release, plus deterministic graph/APK reconstruction.
On the Pixel, 11 direct native cases and five Activity cases passed: permit,
block, block255, zero-capacity error and invalid-input error. UI hierarchies,
screenshots, process logs, device identity and artifact hashes are recorded in
BBC's `evidence/bbx_android.json`. The APK is 35,440 bytes; its XAX-built native
library is 17,432 bytes and classes.dex is 2,104 bytes.

BBC's `evidence/bbx_selfhost_android.json` records 22 checks: native BF framing,
three repeated native compiler generations with exact BBX/graph/ELF equality,
eight fixtures under both initial and final libraries, and bootstrap module
reproduction. External NDK test loaders only move files and supply buffers;
all source framing and compilation are Brainfuck, lowered by XAX. The XAX
backend still runs on Windows using Python bootstrap helpers.

## Windows execution

The same BBX module now lowers through XAX's existing Win64/PE backend. Its
frame path masks wrapping arithmetic below 32 bits and accepts proven pointer
parameters on the hosted PE profile. Narrow arithmetic falls back from the
legacy register path. Both hosted lowering paths probe large stack frames one
page at a time, following the Windows stack-growth requirement documented in
[Microsoft's x64 prolog guidance](https://learn.microsoft.com/en-us/cpp/build/prolog-and-epilog?view=msvc-170).
These fixes belong to XAX; no BBC native backend was introduced.

Use `compile_native_bound_target` with the imported reader/function/target,
then `xax_pe.emit_pe_dll` to export the trusted internal component. BBC's
`evidence/bbx_windows.json` records 22 native checks: 11 real-BBX decision and
profile cases, three exact BBX/graph/PE frontend generations and eight frontend
fixtures. The decision DLL is 8,704 bytes and compiler DLL is 701,952 bytes.
External ctypes supplies initialized buffers; no BF VM or foreign parser runs.
This proves native component execution, not a Windows GUI application.

Four Windows regression methods cover decision semantics, logical lengths,
36 narrow arithmetic cases and a 128 KiB frame in a fresh child process.
The focused pytest run passed 45 tests and 158 subtests; 12 environment-dependent
tests skipped. Android library/DEX/stores remain byte-identical after target
selection was added. XAX backend self-hosting and speed advantages are not
claimed. Linux x86-64 execution remains unverified: WSL is not installed and
the user confirmed no Linux host is available.
