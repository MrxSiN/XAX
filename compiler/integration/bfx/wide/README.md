# Separate BFX v5 wide profile

`source.xax`, `pack.xax` and `import_bfx.xax` are authoritative canonical
semantic stores. The source and packing coordinators were initially created
with the existing generic GraphBuilder/Proc construction interface, verified
and saved through Workspace. Their subsequent changes and the importer
extension use the expected-root transactions below. No maintained Python
builder, BFX translator or foreign-language BBC backend is added.

The original adjacent v1-v4 importer and strict-v1 standalone decoder remain
byte-identical. This separate importer accepts only binary version five:

`BFX || 05 || 00 || instruction_count:u32le || payload`

Exact length is nine plus count. Payload uses exactly v4's opcode set. Count
is at most 65,536. Pair and opening-stack tables each have 65,536 u32 entries;
balanced programs can nest at most 32,768 within this instruction budget.
Status, opcode, bracket and framing validation remain defensive. Native
decoder errors retain their meanings, with a 9..65,545 logical-length guard.

## Typed interfaces

Every buffer below is a distinct live initialized borrowed view, supplied as
pointer, exact extent-bearing proof and memory frontier and returned with the
updated frontier. Raw exports erase proofs. Callers own initialization,
non-aliasing and lifetime; arbitrary pointers do not establish those facts.

| Export | Native arguments | Buffer extents |
|---|---|---|
| `compile_source` | source workspace, record, output workspace, tape workspace | 1,114,112; 65,545; 1,114,112; 1,114,112 bytes |
| `pack_bfx` | record, input workspace, output workspace, tape workspace | 65,545; 1,114,112; 1,114,112; 1,114,112 bytes |
| `import_bfx` | record, decoder workspace, output arena, hash scratch | 65,545; 524,288; 536,870,912; 2,048 bytes |

All return `(published_length << 32) | status`. Publish only the successful
prefix after successful component termination. Any error invalidates every
provisional byte. Coordinator errors are scalar results, not BFX error records.

For source coordination, write source length as u32 into record bytes 0..3
and put at most 1 MiB raw source at workspace offset 65,536. The coordinator
retains ten bytes of BBCS state and constructs complete 32,768-byte-bounded
source chunks in the workspace prefix. BF performs filtering and wide-depth
validation. Raw source is unchanged. The native coordinator checks each
packet and cumulative count before committing the v5 header.

The optional private packing coordinator accepts only a successful transparent
v5 record containing original ASCII commands from the source coordinator.
It is not an untrusted BFX validator or a general repacker for optimized v5.
The BF run packer retains a pending opcode/count across chunks, eliminates
complete 256-step identical arithmetic runs and emits arithmetic/movement
powers. Opposite moves never cancel; exact clear-loop recognition remains a
separate bounded BBC optimization. In-place publication is guarded by packed
output never overtaking consumed input.

The packing core is compiled from BBC's standard `stream_runs.bf` through
native v5, then specialized by canonical edits. Its three-pointer private ABI
fixes logical input/output extents at 65,536. The caller constructs initialized
complete count-bounded packets of at most 32,774 bytes; the BF pass reaches its
terminator before EOF and produces fewer than 65,536 bytes. This specialization
removes redundant logical-length arguments and permits ordinary direct calls
with the existing Windows register backend. Public decision length checks and
the five-argument decision ABI remain unchanged.

The importer reads u32 logical record length from decoder workspace bytes
0..3 before reusing that storage. The first 262,144 bytes hold loop pairs;
the next 262,144 hold the opening stack. Hash scratch remains aligned to four
bytes; byte workspaces require alignment one. Main serialization offsets are
expanded eightfold; the graph arena has 64 MiB, metadata starts at 384 MiB
and the block map at 392 MiB. Generated decisions retain the original
65,536-cell tape, full reset, checked moves, EOF and I/O failure semantics.

These are fixed capacity specializations. Runtime-sized views, paging, file
spooling and dynamic arena growth are not implemented. A 512-MiB arena extent
does not assert that many resident bytes or a memory advantage.

## Transaction replay

All files under `transactions/` are canonical seed snapshots or `.edit` data,
not alternate textual source. Each edit is verified and rejects a stale replay.

| Starting store | Ordered edits | Result |
|---|---|---|
| `../import_bfx.xax` | `wide_decoder`, `wide_regions`, `wide_importer` | `import_bfx.xax` |
| `transactions/source_seed.xax` | `coordinator_four_args` | `source.xax` |
| `transactions/chunk_seed.xax` | `chunk_large_views` | Borrowed-view specialization embedded in source coordinator |
| `transactions/runs_seed.xax` | `runs_large_views` | Initial packing-core view specialization |
| `transactions/packed_runs_seed.xax` | `packed_runs_large_views`, `runs_fixed_core` | Private three-pointer optimized BF core |
| `transactions/pack_seed.xax` | `pack_fixed_packet` | `pack.xax` |

Edit names denote the corresponding `.edit` file in `transactions/`.
Source seeds preserve the initial canonical construction states for replay;
they are not additional public interfaces. `source_seed` records a discarded
six-argument ABI prototype. Derived generic inlining views must not be saved
as canonical source: attempted proof-erasing cleanup was rejected by full
verification. The final source remains fully verified before native lowering.

## Executed evidence and scope

[Profile evidence](evidence.json) records 398 source cases per target, 414
decoder cases per target, exact old-store parity, five 65,536-instruction
native import stress cases and fourteen complete-program buffer regressions.
The stress cases check store integrity and cross-target bytes, not full SSA
verification/lowering of every maximum-size graph. Mandelbrot's 11,451
instructions compile through both transparent and packed stores on Android
ARM64 and Windows x86-64, producing the exact 6,240-byte expected output.
Packing leaves 5,172 instructions. The packed Android executable is 123,440
bytes; an explicit Windows derived-function closure yields 135,168 bytes.

[Run-packer evidence](runs_evidence.json) includes 1,796 calls per target,
independent BF interpreter checks, native complete-buffer regressions and
the fixed-packet specialization comparison. [Bootstrap evidence](bootstrap_evidence.json)
records three native own-source cycles through filtering, packing, import,
canonical interface edits, full verification and both native backends, with
identical DLL/ELF hashes and exact transaction replay.
[Final audit](final_audit.json) confirms all fourteen regression stores are
also reproduced by the maintained private fixed-packet coordinator.

Android results execute on Pixel 8 Pro/API37; Windows results execute natively
on x86-64. Unchanged generic Windows-hosted Python SDK verification, editing,
binding, lowering and packaging remain bootstrap dependencies. Executed file
hashes and normalized pinned Git source identities are recorded separately.
Windows source coordination uses the existing explicit inlining configuration;
the private fixed packing core uses direct calls. A standalone Windows view
may prune an unused original function only after generic inlining leaves no
direct calls, while preserving full verification of the canonical input.

These results establish bounded wide-profile compilation and component
bootstrap replay. They do not complete the native XAX compiler driver, promote
replacement levels or establish compiler/runtime/RAM superiority over any
competitor. Interrupted exploratory builds and rejected interfaces are kept
separate from completed correctness results.
