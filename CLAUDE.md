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

If the XAX workspace/compiler interface is available, use it instead of producing a source-like textual substitute. Human-readable protocol examples and diagnostic notation are tooling views, not XAX source.

For repository maintenance (compiler, evidence, documentation):

- `XAX_REPLACEMENT_MATRIX.json` is the source of current replacement levels and of the README Targets table (each row's `name` and `summary`). After changing it, run `python -m xax_status_docs --write` from `compiler/src` to regenerate every `<!-- xax-status:levels -->` and `<!-- xax-status:targets -->` block; `tests/test_status_docs.py` fails while a block is stale.
- B levels are derived, never written by hand: `xax_selfhost.bootstrap_status` feeds `compiler/bootstrap/m14_selfhost_evidence.json` (regenerate with `python bootstrap/generate_m14.py` from `compiler`) and every `<!-- xax-status:bootstrap -->` block. An S-step self-compilation result is a component fixed point, not B1-B4 (ADR-177).
- After changing a self-hosting builder or anything it reads, rewrite its store with the module's `write_*` function; `tests/test_store_regeneration.py` fails on every host while a committed store differs from its builder.
- The Linux x86-64 compiler seed (`compiler/bootstrap/seed/xaxc-linux-x86_64`, ADR-286) is pinned in `xax_selfhost_seed`. Replace it only with `python -m xax_selfhost_seed rotate-seed` followed by a reviewed update of `SEED_SHA256`/`SEED_SIZE`; after a driver-store change run `python -m xax_selfhost_seed write-request`.
- The general driver's committed store (and the compiler request store derived from it) is its builder's baseline with the evolution ledger applied (`compiler/bootstrap/evolution/`, ADR-305). Change the production compiler by adding a ledger transaction applied with its own `edit` command (`xaxc edit <store> <record> <out>` on the driver store and the request store, then `verify`), not by editing a builder; rebuild with `bootstrap/seed/selfbuild.sh`. A deliberate builder change moves the baseline: run `python -m xax_selfhost_evolution rebase` and review the rewritten records. Do not use a `bits<1>` comparison result in a later block of a driver or helper function; keep it as a 64-bit flag (the self-built compiler's general backend does not carry it, ADR-304).
- The M14 seed is pinned. Never replace `m14_seed_runtime.pyz` except with `python bootstrap/generate_m14.py rotate-seed` followed by a reviewed update of `SEED_SHA256`/`SEED_SIZE`.
- Evidence that claims XAX-hosted execution must run with `XAX_REQUIRE_NATIVE=1` and record `xax_native.AUTHORITY`; never record a native result from a host that fell back to Python.
- `MEASURED` performance needs raw per-arm samples (`wall_seconds_samples`); the matrix validator recomputes R4 from them: XAX median <= 0.9999x the fastest non-XAX median, with a significant advantage (ADR-207). R5 is autonomous maintenance (record a cycle with `benchmarks.bench_r5_maintenance`, ADR-209); R6 is a proven 100% XAX-developed application (create programs with `xax_construct.construct`, then change them only by workspace transactions; see `benchmarks.bench_r6_xb64`, ADR-210).
- Dated sections in `XAX_STATE.md`, `XAX_HANDOFF.md`, `XAX_BENCHMARKS.md`, and `XAX_DECISIONS.md` are historical records; record a new result in a new section and point the superseded one at it instead of rewriting it.
- Local mutation batches use `xax_local_protocol.LocalMutationSession` bound to the queried generation; never rebuild a stale session implicitly. Host-applied final requests use the ordinary snapshot session and exact compound carriers; return local diagnostics on rejection and never refresh before reporting staleness.

Git workflow:

- Do not add AI attribution to commits or pull requests: no `Co-Authored-By` trailers naming an AI assistant, no session links, no "Generated with" footers.
- Commit and push to `main` as soon as each task is finished and its tests pass; do not hold finished work until a larger set is complete.
