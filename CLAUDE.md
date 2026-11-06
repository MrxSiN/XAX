# XAX AI Instructions

XAX has no canonical human-written source syntax. Do not invent or emit textual XAX programs as authoritative source.

For XAX programming tasks:

1. Read `docs/09_AI_PROTOCOL.md` and follow its normative requirements.
2. Treat the canonical semantic graph and current workspace state as authoritative.
3. Query only the smallest semantic neighborhood required for the task.
4. Use short workspace-local handles instead of persistent identities when available.
5. Emit only the minimum exact semantic mutation and do not repeat facts uniquely reconstructible from shared workspace or protocol state.
6. Do not regenerate unchanged program state or the canonical `.xax` artifact for a local edit.
7. Use structured diagnostics and the supplied repair neighborhood for rejected mutations; do not request unrelated context.
8. Verify required invariants and commit only through the XAX transaction/workspace interface.

If the XAX workspace/compiler interface is available, use it instead of producing a source-like textual substitute. The native one is `xaxc edit <store> <input> <output>` (views, batches and rejection text; `docs/09_AI_PROTOCOL.md` §16). Human-readable protocol examples and diagnostic notation are tooling views, not XAX source.

For repository maintenance (compiler, evidence, documentation):

- Layout (ADR-363): `compiler/src/` holds the native compiler's Python-side runners and tooling (`xax_native`, the frozen programs' `xax_selfhost_*` runners, the ledger and seed tools, status derivation); `compiler/reference/` holds the Python reference compiler (`xax_compiler`, backends, workspace, `xaxc`) that tests compare the native compiler against. Put new Python compiler code in `reference/`, never in `src/`. Run Python from `compiler` with `PYTHONPATH=src:reference:.` (pytest needs no `PYTHONPATH`: `pyproject.toml` sets it); `setup.py` packages both directories.
- `XAX_REPLACEMENT_MATRIX.json` is the source of current replacement levels and of the README Targets table (each row's `name` and `summary`). After changing it, run `python -m xax_status_docs --write` from `compiler/src` to regenerate every `<!-- xax-status:levels -->` and `<!-- xax-status:targets -->` block; `tests/test_status_docs.py` fails while a block is stale.
- B levels are derived, never written by hand: `xax_selfhost.bootstrap_status` computes them from the executed records (`compiler/benchmarks/full_selfhost_evidence.json`, `compiler/benchmarks/python_free_seed_evidence.json`) into every `<!-- xax-status:bootstrap -->` block (`python -m xax_status_docs --write` from `compiler/src`). An S-step self-compilation result is a component fixed point, not B1-B4 (ADR-177). The M14 Python bootstrap is retired (ADR-362): add no Python seed, and do not regenerate M14 evidence; `m14_selfhost_compiler.xax` is a frozen corpus store.
- The self-hosting stores in `compiler/bootstrap/` are frozen (ADR-361): the committed store is the source and no Python builder exists. Change one only by a ledger transaction: `python -m xax_selfhost_evolution apply <record> <store>...` runs `xaxc edit <store> <record> <out>` then `verify` and appends the ledger line (`compiler/bootstrap/evolution/LEDGER`); `tests/test_store_regeneration.py` fails on every host while a store is not its ledger chain's end or a transaction does not make its recorded store.
- The Linux x86-64 compiler seed (`compiler/bootstrap/seed/xaxc-linux-x86_64`, ADR-286) is pinned in `xax_selfhost_seed`. Replace it only with `python -m xax_selfhost_seed rotate-seed` followed by a reviewed update of `SEED_SHA256`/`SEED_SIZE`; after a driver-store change run `python -m xax_selfhost_seed write-request`.
- Native evolution (ADR-367): after the N0 bootstrap, compiler logic is authored only as canonical XAX graphs through native XAX transactions; Python or other languages may test or serve as references but must not generate or implement production compiler logic. N0 is complete (ADR-372): write a change as native batch text from `xaxc edit <store> <selector> <view>` (`define`, `replace`, docs/09 §16), one batch per store, and record it with `sh compiler/bootstrap/evolution/evolve.sh apply <batch> <store>` (the seed's `xaxc edit` and `verify`; `evolve.sh replay` and `check` re-run and check the ledger). Keep the driver's main within the general backend's limits: at most four machine parameters per function and four machine inputs per call, and nothing that inlines into main (it is 632 values below `VCAP`).
- Change the production compiler by a transaction on both `xax_compiler_driver_general.xax` and `seed/xax_compiler_request.xax` (the request store must stay `compiler_request` of the driver store), then rebuild with `bootstrap/seed/selfbuild.sh` and rotate the seed. A transaction that changes a function of the edit engine, the semantic index or Ed25519 also fails the pin of their kept generators until those helper tests follow. A `bits<1>` comparison result may be used in a later block (ADR-376 fixed the general backend's branch fusion that ADR-304 worked around with 64-bit flags).
- BBC's driver follows the production driver: `integration/bfx/bbc.xax` is the current `xax_compiler_driver_general.xax` plus only the Windows hosting layer (process entry, file I/O, lazily committed views). After any production driver change (ledger transaction or seed rotation), rebuild BBC's driver from it, rebuild `bbc.exe`, and rerun BBC's checks; never maintain or patch a separate driver copy.
- Evidence that claims XAX-hosted execution must run with `XAX_REQUIRE_NATIVE=1` and record `xax_native.AUTHORITY`; never record a native result from a host that fell back to Python.
- `MEASURED` performance needs raw per-arm samples (`wall_seconds_samples`); the matrix validator recomputes R4 from them: XAX median <= 0.9999x the fastest non-XAX median, with a significant advantage (ADR-207). R5 is autonomous maintenance (record a cycle with `benchmarks.bench_r5_maintenance`, ADR-209); R6 is a proven 100% XAX-developed application (create programs with `xax_construct.construct`, then change them only by workspace transactions; see `benchmarks.bench_r6_xb64`, ADR-210).
- Dated sections in `XAX_STATE.md`, `XAX_HANDOFF.md`, `XAX_BENCHMARKS.md`, and `XAX_DECISIONS.md` are historical records; record a new result in a new section and point the superseded one at it instead of rewriting it.
- Local mutation batches use `xax_local_protocol.LocalMutationSession` bound to the queried generation; never rebuild a stale session implicitly. Host-applied final requests use the ordinary snapshot session and exact compound carriers; return local diagnostics on rejection and never refresh before reporting staleness.

Git workflow:

- Do not add AI attribution to commits or pull requests: no `Co-Authored-By` trailers naming an AI assistant, no session links, no "Generated with" footers.
- Commit and push to `main` as soon as each task is finished and its tests pass; do not hold finished work until a larger set is complete.
