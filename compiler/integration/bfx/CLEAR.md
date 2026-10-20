# Versioned BFX CLEAR lowering

`import_bfx.xax` accepts BFX v1 and v2. V1 remains exact: only the original
eight ASCII instructions are legal and accepted records produce identical
decision stores. V2 additionally accepts byte zero as CLEAR. All other payload
bytes reject, brackets still pair by operation index and versions other than
one/two reject. Existing lengths, status ordering, 3,840 operations and nesting
255 remain. Maximum record size is still 3,847 bytes.

The standalone `bfx.xax` decoder is unchanged and remains strict v1. Only the
importer's embedded validator is extended. A producer needing the standalone
v2 validator can use the importer's validation boundary; do not reinterpret
the old decoder's version rejection as v2 support.

BBC owns source recognition in its separate standard Brainfuck optimizer.
It folds exact `[-]` and `[+]` and removes complete same-direction arithmetic
wraps before import. This consumer recognizes no source idiom, performs no
new raw-source parsing and supplies no termination proof on a producer's
behalf. A v2 CLEAR is a declared operation just as `+` is in v1.

## Graph changes and equivalence

[importer_decoder_clear.edit](importer_decoder_clear.edit) replaces the
embedded decoder graph, then [importer_clear.edit](importer_clear.edit)
extends importer arithmetic dispatch and operand serialization.

| State | Canonical root |
|---|---|
| Required parent | `6af38cf7dce17eaeb4929a5e3cde770f04996db84026d5c9acb6743a07f4e63e` |
| After decoder edit | `264048fdf0a38195d81026d495e30a3b6a26b7dd92346747801279af6a0194ee` |
| After importer edit | `3aad8ec0071769c38b67f8fb8f3e21ef02936007f7c8a8ae3e79cdde31528b58` |

The parent source SHA-256 is
`b4069061eec825d34f1c6a4172ecae4aff3e588c67054e27810d4ed3ced41c03`.
The result entry is
`25008388f90f71e1d5034a5a4a0fda7ca37c6b7cf7fda10647cfa26f4d77f0a6`.
Both records reject stale replay. The unchanged generic reference applier,
full canonical verifier and `Workspace.save` establish maintained source;
no direct binary patch or regenerated textual program is used.

CLEAR uses the existing checked current-cell load, subtracts that byte from
itself and stores zero with the existing checked store. The graph operation
set and global constant table remain unchanged. Serialized operand selectors
choose the local loaded-byte reference for CLEAR; ordinary plus/minus retain
their old constant-one reference and exact bytes. Memory frontiers and all
borrowed views remain explicit. The complete 65,536-byte tape reset, invalid
length guard, intermediate movement traps, EOF and I/O failure ordering stay
unchanged. The public native four-pointer importer ABI is unchanged.

## Executed scope

[clear_optimization_evidence.json](clear_optimization_evidence.json) records:

- 393 legacy record cases and every v2 payload byte, with unknown-version
  checks. The 652 Android importer results match Windows stores/statuses;
  accepted stores pass full canonical verification. Version-two eligibility
  is the intentional extension; v1 acceptance/bytes stay unchanged.
- Twenty decision modules, 1,512 full-buffer vectors per arm/target and
  6,048 native calls in total. Independent interpreter comparisons include
  all 256 clear entry bytes, dirty tape, five pointer alignments, EOF,
  invalid lengths, output capacity, tape bounds and failure ordering. Full
  input/output/tape and allocation guards agree.
- Three identical native frontend and optimizer generations on Android ARM64
  and Windows x86-64. Frontend output remains v1, with twelve exact fixtures
  each generation; its optimized module/store/artifact also reproduces.
- 359 native BF optimizer properties and 71 independent C-interpreter cases,
  including count boundaries and maximum operation count. The independent
  Windows interpreter uses binary stdout; it is an external test oracle.
- All 96 standalone artifacts build, and all 48 Windows and 48 Android
  artifact executions pass exact output/status checks on the sixteen-source
  corpus. This is correctness evidence, not a timing superiority claim.

Pixel 8 Pro executes Android native components and static syscall programs.
Unchanged Windows-hosted generic Python tools still verify, bind and lower
canonical stores. The standalone hosts retain their pinned build settings,
including the generic derived inlining view required by the Windows backend.
This is not a native whole-compiler fixed point or a completed competitor
sweep. Complete-pipeline, file-size and runtime measurements belong to BBC's
separate evidence report.
