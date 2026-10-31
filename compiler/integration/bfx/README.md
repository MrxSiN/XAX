# BBC and BFX integration

BBC's [BFX specification](https://github.com/MrxSiN/BBC/blob/main/docs/02_BFX_CONTRACT.md) is the single wire authority. All producer
routes and optimization levels use that format. One canonical decoder accepts
only the new magic and identifier; old records reject without fallback.

| Canonical source | Responsibility |
|---|---|
| `bfx.xax` | Portable FUNCTION dependency closure of the shared strict decoder |
| `import_bfx.xax` | Same decoder, then checked canonical decision-store import |
| `compile.xax` | Single public typed source-to-BFX interface, O0/O1 |
| `compile_windows.xax` | Native Windows `compile`, `bind`, emit-bfx, check and info process host |
| `bbc.xax` | Single-process `bbc.exe`: BBC commands plus the native XAX driver |
| `bbc-android-arm64.xax`, `bbc-windows-x86_64.xax` | Host build requests `bbc compile` binds a decision into |
| `source.xax` | BF chunk filtering/validation and final BFX publication |
| `pack.xax` | Historical: BF streaming run packing for BFX id `01`; no longer reached by `compile_bfx` |
| `android_bfx.xax` | Bounded decision demo, JNI/lifecycle/UI packaging |
| `standalone_arm64.xax` | Direct native decision process host on Android |
| `standalone_windows.xax` | Direct native decision Windows process host |

[DYNAMIC_TAPE.md](DYNAMIC_TAPE.md) describes the lazily committed 2 GiB decision tape
(2026-10-29) and its transactions.

[PACKED_LENGTHS.md](PACKED_LENGTHS.md) (2026-10-31): decisions take their input length and
output capacity as one `bits<64>` argument, so they have four machine arguments and take
the x86-64 register path; the hosts and `bind` framing changed with them.

[BFX_V2.md](BFX_V2.md) describes BFX id `02` (2026-10-29): no count field, an END byte,
offset ADD/MUL/CHECK/MOVE instructions emitted by BBC's `fold.bf`, and the importer,
decoder and `compile_bfx` transactions that implement them. Where older sections of this
directory describe id `01`, its u32 count, power opcodes or the packer, they are historical.

[COMPILE.md](COMPILE.md) specifies the unified public interface and exact generic
bootstrap recipe. `bbc compile` builds Android ARM64 and Windows x86-64
executables from Brainfuck source with the native XAX driver and no Python at
runtime, in one process (`bbc.xax`), committing the driver's large views only as
they are touched and checking each graph once per process; see its native,
single-process, lazily committed views and graph proof cache sections for scope
and evidence.

[IMPORT.md](IMPORT.md) specifies typed buffer/build contracts and
[TRANSACTIONS.md](TRANSACTIONS.md) records exact-root migration/replay boundaries.
`canonical_bfx_evidence.json` records current execution. Old JSON execution
reports remain immutable, with their original source hashes and format meanings.
The old `wide/*.xax` entrypoints and obsolete legacy edit records are retired;
Git commit `6c9ed73474307d4b3f6130dd09a16431b0f8046d` preserves them for history.
Migration replay edits old graphs as data; it is not a production legacy decoder.

All implementation remains canonical XAX semantic graphs. Generic SDK Python
under `compiler/src` is unchanged. Windows-hosted generic verification/lowering
and helper-loader fallback are disclosed; native component execution is separate
from a native compiler host. No performance or application milestone is promoted.
