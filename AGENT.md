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

- `XAX_REPLACEMENT_MATRIX.json` is the source of current replacement levels. After changing it, run `python -m xax_status_docs --write` from `compiler/src` to regenerate every `<!-- xax-status:levels -->` block; `tests/test_status_docs.py` fails while a block is stale.
- Dated sections in `XAX_STATE.md`, `XAX_HANDOFF.md`, `XAX_BENCHMARKS.md`, and `XAX_DECISIONS.md` are historical records; record a new result in a new section and point the superseded one at it instead of rewriting it.
