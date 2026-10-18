# BBX verified graph import

Status: PROTOTYPE. Construction and ARM64 instruction simulation execute on
Windows. No Android device, Bionic/ART loader or APK action is proven here.

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
target. The fixed view extents must be integers from 1 through 65536; runtime
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
Android application must establish the view allocation, initialization,+non-aliasing and lifetime obligations before calling it. Exporting the raw
function does not create those proofs for arbitrary foreign callers. Tests
export a symbol only to inspect ELF lowering and emulate code with valid
mapped buffers. No production JNI bridge or raw-pointer wrapper is supplied.

Initial construction uses `GraphBuilder` and `program_store`, which verifies
the resulting canonical store. Constructed graphs are authoritative. Apply
subsequent graph edits through the ordinary workspace transaction interface;
the adapter is not an alternate XAX text syntax or graph mutation API.

## Verification and next step

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

Next: construct an Android caller using verified allocation/view contracts,
reuse XAX's Activity/JNI/DEX/APK path, and visibly act on BBC's permit/block
decision for two inputs and a failed call. Execute on Android before M2 is
complete. Native frontend self-hosting and Windows/Linux delivery remain
separate later acceptance gates.
