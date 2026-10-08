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
9. Minimize total model-visible tokens per successful semantic change, but never trade away exact semantics, determinism, freshness checks, conflict detection, or verification success.

If the XAX workspace/compiler interface is available, use it instead of producing a source-like textual substitute. Human-readable protocol examples and diagnostic notation are tooling views, not XAX source.

For repository maintenance (compiler, evidence, documentation):

- `XAX_REPLACEMENT_MATRIX.json` is the source of current replacement levels and of the README Targets table (each row's `name` and `summary`). After changing it, run `python -m xax_status_docs --write` from `compiler/src` to regenerate every `<!-- xax-status:levels -->` and `<!-- xax-status:targets -->` block; `tests/test_status_docs.py` fails while a block is stale.
- B levels are derived, never written by hand: `xax_selfhost.bootstrap_status` feeds `compiler/bootstrap/m14_selfhost_evidence.json` (regenerate with `python bootstrap/generate_m14.py` from `compiler`) and every `<!-- xax-status:bootstrap -->` block. An S-step self-compilation result is a component fixed point, not B1-B4 (ADR-177).
- After changing a self-hosting builder or anything it reads, rewrite its store with the module's `write_*` function; `tests/test_store_regeneration.py` fails on every host while a committed store differs from its builder.
- The M14 seed is pinned. Never replace `m14_seed_runtime.pyz` except with `python bootstrap/generate_m14.py rotate-seed` followed by a reviewed update of `SEED_SHA256`/`SEED_SIZE`.
- Evidence that claims XAX-hosted execution must run with `XAX_REQUIRE_NATIVE=1` and record `xax_native.AUTHORITY`; never record a native result from a host that fell back to Python.
- `MEASURED` performance needs raw per-arm samples (`wall_seconds_samples`); the matrix validator recomputes R4 from them.
- Dated sections in `XAX_STATE.md`, `XAX_HANDOFF.md`, `XAX_BENCHMARKS.md`, and `XAX_DECISIONS.md` are historical records; record a new result in a new section and point the superseded one at it instead of rewriting it.
- Local mutation batches use `xax_local_protocol.LocalMutationSession` bound to the queried generation; never rebuild a stale session implicitly. JVM R5 trials use separate fresh artifacts, at least three trials per Java/Kotlin/XAX cell, every failed-attempt cost, and the 0.50 lowest-textual-median gate. A numeric gate alone does not establish task equivalence or promote the matrix. Preserve exact CSV bytes under `.gitattributes` because evidence digests include line endings.

- Host-applied final requests use the ordinary snapshot session and exact compound carriers; return local diagnostics on rejection and never refresh before reporting staleness. Response-v9 (0.498423x; ADR-194) is historical: ADR-195's review rejected it as R5 evidence for context asymmetry. The current `benchmarks.run_jvm_r5_response` profile is same-prefill response-v12 (ADR-196): all context is inline, no arm uses tools, XAX gets no out-of-band edit target, the client is minimal (`gpt-6-luna`, low), and the gate subtracts a calibrated per-request client floor. R5 needs at most 0.55x (0.50 is the target); v12 measured 0.995x, and ADR-197's multi-file corpus (`benchmarks.run_jvm_r5_multifile`, four textual workflows including IDE excerpts) measured 1.68x, so R5 is unmet. Multi-file profile v6 (ADR-201) gives XAX the shared edit grammar (ADR-200) as base instructions; it is unmeasured, and its gate counts the grammar in every request. Sources, client flags and common instruction hashes must stay pinned. Keep prior interrupted/exploratory profiles separate and retain every current-profile failed response/attempt cost.
