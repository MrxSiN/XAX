# XAX continuation

One task is left from the ledger 0023 work (2026-11-08). Paste the prompt below into a new session.
Delete this file once the task is done.

## Prompt

> Re-record XAX's full self-hosting evidence for the ledger 0023 seed, then regenerate the status blocks.
>
> Context: ledger 0023 rotated the Linux x86-64 seed to SHA-256
> `a35fd59fc9effe08f58f6d1db0d2e951abbd56a065dc0dca729c9bc6f5ec793b` (31,903,131 bytes, pinned in
> `compiler/src/xax_selfhost_seed.py`). `compiler/benchmarks/python_free_seed_evidence.json` is already
> re-recorded for it; `compiler/benchmarks/full_selfhost_evidence.json` is not, so the derived B levels
> do not yet hold for the current seed.
>
> 1. Make sure `/tmp` has at least 12 GB free. Remove stale `/tmp/xax-full-selfhost-*`, `/tmp/xax-seed-*`
>    and `/tmp/xax-driver-*` directories by explicit path (no glob `rm -rf *`).
> 2. From `compiler`, run the benchmark detached, because it takes over two hours and a foreground
>    timeout kills it:
>    `nohup sh -c 'XAX_REQUIRE_NATIVE=1 PYTHONPATH=src:reference:tests:.:.. python3 benchmarks/bench_full_selfhost.py --write > fs.log 2>&1; echo "rc=$?" >> fs.log' &`
>    Wait for `rc=0` in the log; do not record a result from a run that fell back to Python.
> 3. From `compiler/src`, run `PYTHONPATH=.:../reference:.. python3 -m xax_status_docs --write` and check that
>    it reports B0 to B6 holding with seed size 31,903,131. Run `pytest tests/test_status_docs.py`.
> 4. Commit `full_selfhost_evidence.json` and the regenerated status blocks as the repository's git identity
>    (no AI attribution), add a new dated section to `XAX_STATE.md` rather than editing old ones, push,
>    open a pull request with a plain-English title, and merge it. Then delete this file.
