

## ADR-319 — The driver's store files and snapshots hold 64 MiB; the seed rotated to carry it

| Field | Record |
|---|---|
| Decision | The general driver reads store files of up to 64 MiB (`xax_selfhost_store.DATA_EXTENT`, was 32 MiB) and the S9 writer takes a 64 MiB batch and writes up to 64 MiB (`xax_selfhost_writer.IN_EXTENT`, `OUT_LIMIT`; its buffer `BUF_EXTENT` 128 MiB). The store decoder, the writer and both drivers were regenerated (the native decoder and writer bypassed while their own stores were made: `XAX_STORE_PYTHON_DECODER=1`, `XAX_STORE_PYTHON_WRITER=1`); the evolution ledger was rebased. The seed was rotated deliberately (ADR-287's procedure): the old seed resolved and built the new request, the new compiler rebuilt itself to the same bytes, and `rotate-seed` pinned it. |
| Rationale | The compiler with the next targets in its closure (S15e.3b, S15e.7) is a 33.4 MB store: past the 32 MiB views, so `resolve` rejected its own request with `DRIVER-SNAPSHOT-CAPACITY`. As in S15b.0 and S15e.2a, the capacity lands alone, while the old seed can still build it. |
| Evidence | EXECUTED on Linux x86-64. The old seed resolved and built the new request; that compiler (14,372,181 bytes) rebuilt itself to the same bytes. The rotated seed (`66a3f91d…`, 14,372,181 bytes) passes `selfbuild.sh`, `tests/test_python_free_seed.py` and `tests/test_store_regeneration.py`. |
| Limits | None beyond the views' size: a larger compiler needs another such step. |
