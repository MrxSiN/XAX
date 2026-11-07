# XAX bootstrap artifacts

## M11 bootstrap artifacts

`m11_compiler_subset.xax` is the authoritative XAX semantic program for the declared M11 compiler/tooling subset. It implements one deterministic compiler component: folding either `add.wrap` or `mul.wrap` over `bits<32>` according to a `bits<1>` selector.

`m11_bootstrap_bundle.xax` is the fixed hermetic build snapshot that binds that program module to the WebAssembly bootstrap target, package entry, build profile, trust policy, and resolver identity.

`generate_m11.py` and `xax_bootstrap.m11_definition()` are transitional Python seed material. They exist only to reproduce and validate the committed canonical artifacts byte-for-byte. They are not XAX source and do not define XAX meaning.

M11 claims B0/B1 only. It does not claim recursive self-compilation, semantic generation equivalence, a fixed point, toolchain closure, or bootstrap independence.

### Seed boundary and dependencies

The approved M11 seed path is the existing Python bootstrap implementation identified by `BOOTSTRAP_COMPILER_IDENTITY_V1`, using the fixed `WASM_LOWERING_IDENTITY_V1` lowering. Reconstructing the historical M11 seed path requires Python 3.11+; the repository now carries an exact in-tree suite-1 BLAKE3 implementation, so no external `blake3` wheel is required; executing the resulting bootstrap artifact requires Node.js/WebAssembly support. These are transitional M11 dependencies, not XAX language semantics.

The seed still owns canonical-store decoding/verification, package/build resolution, and WebAssembly lowering/emission. M11 migrates only the declared arithmetic-folding compiler component into authoritative XAX semantic state. Removal of the remaining Python implementation dependency belongs to later bootstrap milestones.

## M14 semantic-image closure artifacts (retired bootstrap, W3)

W3 (ADR-362) retired the M14 Python bootstrap: the Python zipapp seed (`m14_seed_runtime.pyz`) and the OI-26 minimization candidates, `generate_m14.py`, `m14_selfhost_evidence.json`, and the Python code that executed the wrapper's recursive generations. The bootstrap seed is the pinned native compiler, `seed/xaxc-linux-x86_64` (ADR-286), which rebuilds the production compiler with no Python. B levels are derived by `xax_selfhost.bootstrap_status` from the executed records alone:

<!-- xax-status:bootstrap -->Bootstrap status (derived by `xax_selfhost.bootstrap_status` from `compiler/benchmarks/full_selfhost_evidence.json` and `compiler/benchmarks/python_free_seed_evidence.json`): whole production compiler: B0, B1, B2, B3, B4, B5, B6 established (derived from the Linux x86-64 production compiler, whose executed record covers every target and artifact `build` makes (S15g, ADR-358)); Linux x86-64 production compiler (`benchmarks/full_selfhost_evidence.json`): B0, B1, B2, B3, B4, B5, B6 hold, none do not; its seed requires Python: no; S-step component fixed points are not B milestones (`XAX_SPEC.md` §16.5). Bootstrap seed: native-elf `compiler/bootstrap/seed/xaxc-linux-x86_64`, 31,543,498 bytes, requires Python: no.<!-- /xax-status:bootstrap -->

`m14_selfhost_compiler.xax` stays as a frozen corpus program (a ledger baseline in `evolution/LEDGER`): the `xax-semantic-image-v1` META wrapper, program root `097da62f7ba9832620f5d202297fc522783ed5b4c9e68f8da6b77515b185164d`. Its history (B2-B4 for the wrapper, the 46,255-byte seed, the OI-26 study) is in git and in the dated sections of `XAX_STATE.md` and `XAX_CONFORMANCE.md`.

### OI-27 release-only diversity checker

`oi27_independent_checker.go` is a release-only independent implementation for the bounded M11/M14 trust check. It uses Go 1.23 with no external packages and independently implements suite-1 BLAKE3-256, canonical store/index/CID verification, the accepted M11 arithmetic and M14 semantic-image verification subset, and canonical store re-emission. It is deliberately not a second production compiler: it has no general META evaluator, package resolver, or native/WebAssembly/accelerator backend.

For trust-sensitive releases the Go checker independently verifies the frozen M14 store under its pinned root and re-emits byte-identical canonical bytes (until W3, the primary OI-26 Python seed first reconstructed that root). This check supplements recursive self-build evidence; it does not prove that the pinned authoritative compiler graph or the XAX specification is benign. Exact measurements and controlled fault injections are in `../benchmarks/oi27_bootstrap_diversity_evidence.json`.

## Self-hosted compiler stores (S ladder)

Each store is canonical XAX semantic state for one compiler component on the production path (`XAX_IMPLEMENTATION_ROADMAP.md`, S ladder). Since W2 (ADR-361) every store here except `xax_blake3_compress.xax` (a corpus program `xax_native_blake3` still builds) is frozen: the committed file is the component's source, and it changes only by transactions of the production compiler's own `edit` command recorded in `evolution/LEDGER` (`python -m xax_selfhost_evolution apply`). The Python builders that once made these stores are deleted. The module named next to each store loads it, runs its native image and holds the Python reference it is compared against; it is not XAX source. `tests/test_store_regeneration.py` checks on every host that each store is its ledger chain's end and replays every transaction (store + transaction = next store, byte for byte). The native image of a store runs only on Linux x86-64; `xax_native.AUTHORITY` records which implementation ran.

| Store | Component | Module |
|---|---|---|
| `xax_blake3_compress.xax` | BLAKE3 compression (S0) | `reference/xax_native_blake3.py` |
| `xax_blake3_hash.xax` | Whole BLAKE3-256 hash over lent views (S2) | `src/xax_selfhost_blake3.py` |
| `xax_riscv64_encoder.xax` | RISC-V instruction encoder and `li` planner (S1) | `src/xax_selfhost_riscv64.py` |
| `xax_store_decoder.xax` | Store container and object envelopes (S3, S3b) | `src/xax_selfhost_store.py` |
| `xax_graph_decoder.xax` | Graph-body syntax (S3c) | `src/xax_selfhost_graph.py` |
| `xax_cfg_analysis.xax` | Control flow and SSA dominance (S3d, S3e) | `src/xax_selfhost_cfg.py` |
| `xax_op_typing.xax` | Operation, constant, and terminator typing (S4) | `src/xax_selfhost_typing.py` |
| `xax_riscv64_backend.xax` | RISC-V code generation from store bytes (S5) | `src/xax_selfhost_riscv64_backend.py` |
| `xax_store_verifier.xax` | The store verifier: facts, linearity, objects (S6) | `src/xax_selfhost_verify.py` |
| `xax_x86_64_backend.xax` | x86-64 views-profile code generation; lowers every helper above for the host (S7a) | `src/xax_selfhost_x86_64_backend.py` |
