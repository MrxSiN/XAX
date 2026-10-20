# Versioned BFX arithmetic powers

The importer accepts versions one through four; [v4 movement](MOVEMENT.md)
is a separate extension. This document specifies v3. V1 stays strict ASCII;
v2 adds CLEAR byte zero. V3 adds fourteen one-byte modular arithmetic
operations. Every successful record is `BFX || version || 00 || count:u16le ||
operations`, exactly `7 + count` bytes. Limits remain 3,840 operations, nesting
255 and 3,847 bytes. Unknown versions and unassigned bytes reject.

| V3 byte | Declared effect on current byte |
|---|---|
| `00` | CLEAR |
| `01`..`07` | Add `2^opcode`, modulo 256 |
| `08`..`0E` | Subtract `2^(opcode - 7)`, modulo 256 |
| Original eight ASCII bytes | Unchanged |
| Any other byte | Reject |

Neither input/output nor cursor changes for the new operations. V1/v2 continue
to reject bytes one through fourteen. The standalone `bfx.xax` validator is
unchanged and remains strict v1. The importer contains the extended decoder.
BBC recognizes source runs in a separate standard Brainfuck pass; this
consumer only validates and lowers declared operations.

## Source and lowering

The required parent is the v2 importer root
`3aad8ec0071769c38b67f8fb8f3e21ef02936007f7c8a8ae3e79cdde31528b58`.
Apply [powers_decoder.edit](powers_decoder.edit), then
[powers_importer.edit](powers_importer.edit), then
[powers_windows_rotate.edit](powers_windows_rotate.edit). Each expected-root
record rejects stale replay. Full canonical verification precedes the final
`Workspace.save`. The final root is
`a8f97518c9c8744d7048df7e8c80107a3558be9f34e2feb52ca7bd19230ce1f7`,
source SHA-256
`36650003407916ed5be1282f3b79dfdb0d518b23b1fd36bd48b253a51adfb97d`,
entry
`0d497a40dd4464f1a7270e5ba1b7f8b301776da50d8948ab5e06eabe5d305d09`.

A power operation emits five nodes: checked byte load; rotate the existing
global 32-bit constant one right by `32 - exponent`; truncate to eight bits;
add/subtract with wrap; checked byte store. Since the exponent is one through
seven, the constant is exactly 2..128 and truncation preserves it. The
initial byte-width rotate verified but the Windows bootstrap backend declined
it. The third transaction repairs that limitation using supported operations;
no generic backend implementation changes.

There are no new generated-decision constant-pool entries. Old unit arithmetic and CLEAR retain their
three-node serialization and exact store bytes. Length guards, full logical
65,536-byte tape reset, every movement check, EOF and first-failure behavior
remain. The four-pointer importer ABI and its caller views are unchanged.

The current fixed storage proof still applies: one main block per operation
and existing I/O blocks, at most 11,529 blocks. The five-node arithmetic
sequence fits the existing conservative 512 bytes per operation plus fixed
overhead bound. The original 64 MiB compiler work/output view is retained;
its extent is not measured resident RAM.

## Executed scope

[power_optimization_evidence.json](power_optimization_evidence.json) records:

- 432 native BF packing properties and 72 independent C-interpreter cases,
  including both signs, every power boundary, count carries, nested/negative
  cases and maximum count. The producer has 3,639 instructions in 5,259 raw
  bytes; its observed peak cell is 61,469. No input record expands.
- Every payload byte for versions one, two and three, plus unknown versions.
  The 908 Android record results match Windows exactly, with full input and
  buffer guards. Accepted stores verify canonically; v1/v2 stores remain exact.
- Fourteen powers in 42 decision modules, 5,530 vectors per arm/target and
  22,120 full-buffer calls. Both native targets match the original eight-command
  interpreter on every byte value, dirty tape, EOF, five alignments, both
  bounds, output-failure ordering and invalid 32-bit lengths/capacities.
- Three identical native generations of BBC's frontend, clear helper and
  power helper on Windows and Android. Each frontend generation passes twelve
  exact fixtures. Native Android import produces exact Windows store bytes;
  own-source v1/v2/v3 records and target artifacts reach fixed points.

Android components execute on Pixel 8 Pro/API 37. Unchanged generic Python
tools on Windows still verify and lower; large importer lowering uses the
maintained explicit graph-view/prefetch configuration. This is component
self-compilation, not a complete native compiler-host fixed point. Separate
BBC measurements own build latency, resources and competitor conclusions.
