# Versioned BFX monotone movement powers

The current importer accepts strict versions one through four. V4 retains
CLEAR and arithmetic powers, adding right moves `15..21` by `2^(opcode-14)`
and left moves `22..28` by `2^(opcode-21)` (decimal byte values). Original eight
ASCII commands remain unchanged; other payload bytes reject. Unknown versions
reject. Successful framing remains `BFX || version || 00 || count:u16le || ops`,
exactly `7 + count` bytes, at most 3,840 operations and nesting 255.
Earlier versions retain their strict byte sets and exact accepted store bytes.
The separate `bfx.xax` validator remains strict v1.

BBC's standard Brainfuck producer combines only adjacent identical unit moves.
This importer lowers the declared operation; it performs no source recognition.
A monotone run is safe exactly when its endpoint is in bounds. It changes no
cell, input, output or conditional state between intermediate positions. On
first crossing the original stops at the last valid boundary, so the new
failure edge clips its abstract cursor to 0 or 65,535 and retains all prior
effects/status/count. Opposite moves never cancel; zero-entry loops bypass
both movement and bounds checking.

The generated decision block uses three nodes: supported bits32 rotate-right
of existing global one to produce K, add/subtract the current cursor, and a
comparison. Right failure is endpoint > 65,535; left failure is old cursor < K.
Right arithmetic cannot overflow bits32 under the cursor invariant. A wrapped
left endpoint stays on the failure path and never reaches memory/continuation.
The condition is used in the same block. Full tape reset, pre-reset invalid
length guards, checked memory operations, native ABI and caller extents stay.
No generic compiler implementation or emitted constant-pool entry is added.

The verified expected-root records are [decoder](moves_decoder.edit) and
[importer](moves_importer.edit). They start at root
`a8f97518c9c8744d7048df7e8c80107a3558be9f34e2feb52ca7bd19230ce1f7` and end at
`e244a6ae42bbefeea65ca6b7fbcad2edb5880dedac8bfc46bc44b5481fa65be7`.
Entry is `9f3906f863e625e515c899cedb50d1fe5ad5ae04ad4595300276dd1fa46e2b9e`;
source SHA-256 is `9709c11d09af8bc2fb6ea0a1efe387d00ba79a02d7923b379c58987d0b6ed49e`.
Full canonical verification and stale replay rejection precede `Workspace.save`.
The published source matches the privately executed candidate byte for byte.

[Execution evidence](movement_optimization_evidence.json) records 432 native
BF packing properties, 72 independent binary-output interpreter cases, 1,164
exact Android/Windows record comparisons and every payload byte in each version.
There are 42 decision modules, 2,398 vectors per arm/target and 9,592 complete
input/output/tape/guard calls. Both directions and all powers pass nearby
bounds, five alignments, dirty tape, EOF, output failure ordering, zero-entry
and trap-reaching loops, and invalid 32-bit logical lengths/capacities.

Frontend, clear, arithmetic and movement BF components each reach three
identical native generations on Android and Windows, with twelve exact
frontend fixtures per generation. Android-native import stores match Windows.
Execution uses Pixel 8 Pro/API37 and Windows x86-64. Unchanged generic Python
verification/lowering on Windows and the maintained explicit importer graph-view
configuration remain disclosed dependencies. This is component self-compilation,
not a complete native compiler host. Separate BBC measurements own performance,
resources and competitor conclusions; no sweep is established here.

The [capacity supplement](movement_capacity_evidence.json) verifies three
3,840-operation records: all right-128, all left-128 and depth-255 nesting
with movement powers. Native Android/Windows stores agree exactly and all
verify canonically; caller buffer guards remain intact.
