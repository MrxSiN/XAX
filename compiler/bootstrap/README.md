# XAX bootstrap artifacts

## M11 bootstrap artifacts

`m11_compiler_subset.xax` is the authoritative XAX semantic program for the declared M11 compiler/tooling subset. It implements one deterministic compiler component: folding either `add.wrap` or `mul.wrap` over `bits<32>` according to a `bits<1>` selector.

`m11_bootstrap_bundle.xax` is the fixed hermetic build snapshot that binds that program module to the WebAssembly bootstrap target, package entry, build profile, trust policy, and resolver identity.

`generate_m11.py` and `xax_bootstrap.m11_definition()` are transitional Python seed material. They exist only to reproduce and validate the committed canonical artifacts byte-for-byte. They are not XAX source and do not define XAX meaning.

M11 claims B0/B1 only. It does not claim recursive self-compilation, semantic generation equivalence, a fixed point, toolchain closure, or bootstrap independence.

### Seed boundary and dependencies

The approved M11 seed path is the existing Python bootstrap implementation identified by `BOOTSTRAP_COMPILER_IDENTITY_V1`, using the fixed `WASM_LOWERING_IDENTITY_V1` lowering. Reconstructing the historical M11 seed path requires Python 3.11+; the repository now carries an exact in-tree suite-1 BLAKE3 implementation, so no external `blake3` wheel is required; executing the resulting bootstrap artifact requires Node.js/WebAssembly support. These are transitional M11 dependencies, not XAX language semantics.

The seed still owns canonical-store decoding/verification, package/build resolution, and WebAssembly lowering/emission. M11 migrates only the declared arithmetic-folding compiler component into authoritative XAX semantic state. Removal of the remaining Python implementation dependency belongs to later bootstrap milestones.

## M14 semantic-image closure artifacts

### Seed immutability and rotation (ADR-177)

`generate_m14.py` regenerates the compiler store and its evidence. It reads `m14_seed_runtime.pyz`, stops if its SHA-256 and size are not the pinned `SEED_SHA256`/`SEED_SIZE`, and never writes it (`tests/test_audit_remediation.py` runs it on a copy and checks). `pack_seed` reproduces the committed seed from its own entries and their recorded zip metadata; the committed seed keeps the wall-clock zip timestamps it was first packed with. The only writer is `python bootstrap/generate_m14.py rotate-seed`, which packs the current seed sources with fixed metadata (1980-01-01, mode 0644, no host file system) and prints the new digest. A rotation is a reviewed change: review the new seed contents, then pin the printed digest and size; the tests fail until then. The seed is a Python zipapp: bootstrapping requires Python.

`m14_selfhost_compiler.xax` is the authoritative compiler program for the declared `xax-semantic-image-v1` closure target. Its entry graph wraps a function into a canonical program, invokes verifier-facing and canonical-image encoding functions, and performs finalization/build orchestration in XAX. Verification and canonical-store formation terminate in explicit trusted META substrate operations.

<!-- xax-status:bootstrap -->Bootstrap status (generated from `compiler/bootstrap/m14_selfhost_evidence.json`, derived by `xax_selfhost.bootstrap_status`): whole production compiler: none of B0-B6 is established (no canonical XAX store implements the whole compiler; S7b and later steps are open); M14 semantic-image META wrapper: B2, B3, B4 hold, B5, B6 do not (host-executed META_CANONICAL_STORE, META_MATERIALIZE_PROGRAM, META_VERIFY_SEMANTICS). S-step component fixed points are not B milestones (`XAX_SPEC.md` §16.5). Bootstrap seed: python-zipapp, 46,255 bytes, requires Python: yes.<!-- /xax-status:bootstrap -->

`m14_selfhost_evidence.json` records the executed generations and the B status derived by `xax_selfhost.bootstrap_status` (ADR-177): B2–B4 for this META wrapper; B5/B6 are not held because verification, encoding, and materialization are host-executed META primitives. *(It recorded B2–B6 until ADR-177.)* Compiler root is `097da62f7ba9832620f5d202297fc522783ed5b4c9e68f8da6b77515b185164d`; entry function is `4300342f92f9ba32bcefbb45af4aad117a3bbf3699bd66266b25cefdc874b6fc`; generations 0/1/2 are byte-identical with BLAKE3-256 `6340c903f5da3e8aaf4d8ae886694a0d858687fc5c5520662a018518693f4788`; and 4/4 fixed-policy function vectors match.

`m14_seed_runtime.pyz` is the approved immutable seed artifact for ordinary semantic-image release reconstruction. It is 46,255 bytes with SHA-256 `4e0c64d6f360359cc263c39817ec8cbe4cc3069edf20823755755c4d2707fe52`. Validation executes it from a temporary working directory with repository `PYTHONPATH` removed and requires byte-identical compiler reconstruction. The archive internally contains Python modules and requires a Python interpreter. B6 therefore means that the declared ordinary release path does not require importing or editing repository Python implementation sources; it does not mean the seed contains no Python, eliminate the interpreter, or provide diverse-double-compilation trust.

The withdrawn M14 B5/B6 claim explicitly excluded the legacy x86-64, AArch64, WebAssembly, and accelerator lowerers. Those remain removable bootstrap/reference implementations until separately closed.

### OI-26 seed minimization

`oi26_seed_reachability.json` records the machine-readable M11/M14 seed feature closure. `m14_seed_entry_pruned.pyz`, `m14_seed_reachable.pyz`, and `m14_seed_specialized.pyz` are deterministic minimization candidates derived from the frozen historical M14 seed. OI-26 selects `m14_seed_reachable.pyz` as the minimum practical measured subset: it preserves the existing generic verifier/evaluator/serializer after static reachability pruning and avoids the new seed-specific semantic evaluator required by the smaller specialized candidate. See `oi26_seed_minimization_report.md` and `../benchmarks/oi26_seed_minimization_evidence.json`.

### OI-27 release-only diversity checker

`oi27_independent_checker.go` is a release-only independent implementation for the bounded M11/M14 trust check. It uses Go 1.23 with no external packages and independently implements suite-1 BLAKE3-256, canonical store/index/CID verification, the accepted M11 arithmetic and M14 semantic-image verification subset, and canonical store re-emission. It is deliberately not a second production compiler: it has no general META evaluator, package resolver, or native/WebAssembly/accelerator backend.

For trust-sensitive `xax-semantic-image-v1` releases, the primary OI-26 seed reconstructs the pinned authoritative root and the Go checker must independently verify that exact root and re-emit byte-identical canonical bytes. This check supplements recursive self-build evidence; it does not prove that the pinned authoritative compiler graph or the XAX specification is benign. Exact measurements and controlled fault injections are in `../benchmarks/oi27_bootstrap_diversity_evidence.json`.

## Self-hosted compiler stores (S ladder)

Each store is canonical XAX semantic state for one compiler component on the production path (`XAX_IMPLEMENTATION_ROADMAP.md`, S ladder). The Python module next to each one builds the graph, checks the committed bytes, and loads the native leaf; it is seed material, not XAX source. In practice the builder is where a component is still edited, which is why `tests/test_store_regeneration.py` checks, on every host and twice per process, that each committed store is exactly what its builder makes (ADR-177). The native image of a store runs only on Linux x86-64; `xax_native.AUTHORITY` records which implementation ran.

| Store | Component | Builder |
|---|---|---|
| `xax_blake3_compress.xax` | BLAKE3 compression (S0) | `src/xax_native_blake3.py` |
| `xax_blake3_hash.xax` | Whole BLAKE3-256 hash over lent views (S2) | `src/xax_selfhost_blake3.py` |
| `xax_riscv64_encoder.xax` | RISC-V instruction encoder and `li` planner (S1) | `src/xax_selfhost_riscv64.py` |
| `xax_store_decoder.xax` | Store container and object envelopes (S3, S3b) | `src/xax_selfhost_store.py` |
| `xax_graph_decoder.xax` | Graph-body syntax (S3c) | `src/xax_selfhost_graph.py` |
| `xax_cfg_analysis.xax` | Control flow and SSA dominance (S3d, S3e) | `src/xax_selfhost_cfg.py` |
| `xax_op_typing.xax` | Operation, constant, and terminator typing (S4) | `src/xax_selfhost_typing.py` |
| `xax_riscv64_backend.xax` | RISC-V code generation from store bytes (S5) | `src/xax_selfhost_riscv64_backend.py` |
| `xax_store_verifier.xax` | The store verifier: facts, linearity, objects (S6) | `src/xax_selfhost_verify.py` |
| `xax_x86_64_backend.xax` | x86-64 views-profile code generation; lowers every helper above for the host (S7a) | `src/xax_selfhost_x86_64_backend.py` |
