# BFX canonical decoder

`bfx.xax` is the authoritative canonical XAX semantic store, created using
`xax-construct-v1`, verified and saved by `Workspace.save`. There is no
committed Python builder or JSON source program. `decoder_cases.json` contains
static test inputs/results only. All later program changes must use verified
expected-root workspace transactions; do not regenerate this program from a
construction request or edit its binary bytes directly.

The canonical [importer](IMPORT.md) now owns graph/store emission, and the
[Android application](ANDROID.md) is maintained as canonical XAX source.
Its embedded decoder also accepts the [v2 CLEAR extension](CLEAR.md).
This standalone `bfx.xax` source remains unchanged and strict v1.
`backend_tests.xax` provides the generic arithmetic and stack-allocation
regression checks.

## Decoder ABI

The graph function accepts a borrowed read-only byte-view triple of extent
3,847, a distinct borrowed read/write byte-view triple of extent 16,380, then
`record_length:bits<32>`. A triple is pointer, initialized extent-bearing view
proof and memory frontier. Return values are a `bits<64>` result and both
borrowed triples with their updated memory frontiers. Pointers/view proofs
erase from the native return; pointers and length remain native inputs.
The caller establishes live, initialized, non-aliasing buffers and lifetimes.

Native export: `decode_bfx(record_pointer, scratch_pointer, uint32_length)`
returns `uint64`. Success is `instruction_count << 32`; error is one of:

| Low 32 bits | Meaning |
|---|---|
| 0 | Valid BFX v1 success record |
| 1 | Record length outside 7..3847, wrong magic or inconsistent count/length |
| 2 | Unsupported version |
| 3 | Compiler response is not successful |
| 4 | More than 3840 instructions or 255 nested loops |
| 5 | Noninstruction payload byte |
| 6 | Unbalanced brackets |

Checks run in that order, with instruction/nesting checks during scanning.
The length bound is checked before reading any record bytes. Logical length
still requires a valid full input view, even on rejection.

Scratch bytes 0..15359 contain a 3840-entry little-endian u32 loop-pair table;
only entries for brackets are defined on success. Each contains the matching
bracket's zero-based instruction index. Bytes 15360..16379 hold the 255-entry
u32 opening stack. Other scratch bytes are unspecified. On error, disregard
all scratch output; a rejected record may have written a partial loop table.
The input remains unchanged. No Brainfuck source filtering, optimization,
execution, graph emission, filesystem access or process API is implemented
by this function.

## Executed verification

393 native Windows x86-64 DLL cases and the same 393 native Android ARM64
cases passed on Pixel 8 Pro, Android 17/API 37. They cover all 256 possible
single payload bytes, exact and invalid lengths, invalid magic/version rejection,
compiler errors, instruction/nesting limits, random opcode streams, exact
BBC fixtures, loop pairs, input preservation and scratch canaries.

The stored snapshot selects Windows with a DLL export. The same verified
function was lowered with the existing explicitly bound Android integer
shared-library target. Windows DLL: 2048 bytes. Android ELF: 17352 bytes.
This decoder evidence proves component execution. The separate application
execution is recorded in [ANDROID.md](ANDROID.md).
The Windows compiler host uses unchanged Python bootstrap verification and
lowering utilities; `XAX_REQUIRE_NATIVE` was not set. No XAX compiler-host
self-hosting claim is made.

Evidence and tool/artifact hashes: [evidence.json](evidence.json).
The Android transport is external NDK C that copies records and result buffers
and invokes the XAX function. It supplies no BFX validation or graph emission.
The external construction request is a one-time tooling carrier, not retained
source. The canonical store is the maintained program.
