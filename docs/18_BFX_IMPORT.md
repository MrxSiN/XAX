# BFX integration

BBC's portable handoff is BFX, extension .bfx. The single
[wire specification](https://github.com/MrxSiN/BBC/blob/main/docs/02_BFX_CONTRACT.md)
defines framing, opcodes and rejection rules for every optimization level,
source size and target. No legacy decoder or format fallback remains in the
maintained compilation path.

- [Canonical sources and evidence](../compiler/integration/bfx/README.md)
- [Typed import/build interfaces](../compiler/integration/bfx/IMPORT.md)
- [Expected-root migration transactions](../compiler/integration/bfx/TRANSACTIONS.md)
- [Standalone Android host](../compiler/integration/bfx/STANDALONE.md)
- [Standalone Windows host](../compiler/integration/bfx/WINDOWS_STANDALONE.md)

The shared decoder function is present by identical CID in its portable closure
and importer. Source/chunk coordination and streaming packing use that same
format. Historical JSON reports retain original bytes and meanings. Native
component execution remains distinct from native compiler-host completion;
unchanged generic Python SDK verification/lowering and Windows loader fallback
remain disclosed. No competitive, application or replacement level is promoted.
