# BBC and BFX integration

BBC's [BFX specification](https://github.com/MrxSiN/BBC/blob/main/docs/02_BFX_CONTRACT.md) is the single wire authority. All producer
routes and optimization levels use that format. One canonical decoder accepts
only the new magic and identifier; old records reject without fallback.

| Canonical source | Responsibility |
|---|---|
| `bfx.xax` | Portable FUNCTION dependency closure of the shared strict decoder |
| `import_bfx.xax` | Same decoder, then checked canonical decision-store import |
| `compile.xax` | Single public typed source-to-BFX interface, O0/O1 |
| `compile_windows.xax` | Native Windows emit-bfx, check and info process host |
| `source.xax` | BF chunk filtering/validation and final BFX publication |
| `pack.xax` | BF streaming run packing of validated BFX, including opaque encoded opcodes |
| `android_bfx.xax` | Bounded decision demo, JNI/lifecycle/UI packaging |
| `standalone_arm64.xax` | Direct native decision process host on Android |
| `standalone_windows.xax` | Direct native decision Windows process host |

[COMPILE.md](COMPILE.md) specifies the unified public interface and exact generic
bootstrap recipe. Native emit/check/info commands need no Python at runtime;
full native target builds remain incomplete.

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
