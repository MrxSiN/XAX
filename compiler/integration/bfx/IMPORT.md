# BFX import and native interfaces

Use only the [BFX specification](https://github.com/MrxSiN/BBC/blob/main/docs/02_BFX_CONTRACT.md). Select the canonical source's
entry function and use the existing generic verifier, target lowering and
packaging APIs. `bfx.xax` is a portable FUNCTION closure, replacing its former
BUILD/package wrapper. The decoder's FUNCTION CID is shared exactly with the
importer, rather than a separately maintained implementation.

| Export | Machine arguments after borrowed resources lower to pointers |
|---|---|
| `decode_bfx` | record 65,546 bytes read-only; scratch 524,288 writable; logical length u32 |
| `import_bfx` | record 65,546 read-only; scratch 524,288; output arena 536,870,912; hash scratch 2,048 |
| `compile_source` | source/work 1,114,112; record 65,546; output work 1,114,112; tape work 1,114,112 |
| `pack_bfx` | record 65,546; input/output/tape work 1,114,112 each |

All views are distinct, initialized and live under typed caller ownership.
Raw native pointers alone do not prove these properties. Before import, write
logical record length into scratch u32 at offset zero. Before source compilation,
copy raw source to source/work offset 65,536 and write source length into record
u32 at offset zero. Source limit is 1 MiB; instruction limit is 65,536.

Decoder returns `(count << 32) | validation_status`. Other components return
`(written_bytes << 32) | status`; discard all provisional output on failure.
Decoder/importer reject untrusted records. Packing requires complete previously
validated successful BFX and preserves opaque instructions, including CLEAR;
its header checks do not replace exact-length/opcode/bracket validation.
Private BBCS and BBCR packets are not importable BFX modules.

Native decision exports borrow three 65,536-byte views plus logical input/output
u32 values, reset the full tape on valid calls, and return `(output_bytes << 32)
| status`. See BBC's execution profile for statuses and first-crossing semantics.
The importer still avoids the general ARM64 large-composite return defect by
using checked scratch outputs and small results.

## Build configuration

Fully verify every source store and emitted decision before lowering. Generic
SDK files are not edited by this migration. Initial builds used snapshot
`3dcb358e48b0f9a45b8cb72767c1aa600e55cd78`; unrelated upstream additions
from `943884a` are preserved, with all eight component images rebuilding exactly.
Android uses the existing shared integer target. Windows uses the existing PE
target and explicit generic source-coordinator callee inlining; its five-argument
BF decision call otherwise meets a backend decline. No new Python compiler logic
or alternate native backend is introduced. Explicit lowering views do not edit
the authoritative graph. Full verification and workspace saves gate graph edits.

Current native tests cover Android ARM64 and Windows x86-64. Linux execution and
native compiler-host completion remain unproven. Existing standalone hosts and
the Android app embed decisions, not record decoders; previous packaging evidence
retains its original identity and does not claim new application execution.
