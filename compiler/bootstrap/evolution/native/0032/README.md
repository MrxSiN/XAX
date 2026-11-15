# Ledger 0032: the DEX writer's output buffer for large modules (ADR-403)

Applied with `../../evolve.sh apply` to four stores, one batch each, written from `xaxc edit <store> <selector>` views
and accepted by `xaxc verify`. Each batch sets one constant: `N3331` (64, the output words per input word of the
writer frontend's buffer) becomes 16.

| Batch | Store | Function |
|---|---|---|
| `0032-dex-writer-output-cap-dex-writer.batch` | `xax_dex_writer.xax` | F28 (`f6b7f601…`) |
| `0032-dex-writer-output-cap-android.batch` | `xax_android.xax` | F446 (`ec5f4709…`, the writer as the Android program's layer) |
| `0032-dex-writer-output-cap.batch` | the driver | F966 (`ec5f4709…`) |
| `0032-dex-writer-output-cap-request.batch` | the request | F966 (`ec5f4709…`) |

This change was first written as a ledger 0030 on top of ledger 0029 (pull request 53), at the same time as the
host-ABI ledgers 0030 and 0031. Those landed first, so it is replayed here on their stores. The writer and Android
program batches are unchanged, because ledgers 0030 and 0031 do not touch those stores. In the driver and the request,
the function and the node are the same; only the root line and the function's handle (F962 before 0030 and 0031,
F966 after) are new.

**Finding the site.** The Android program declined at site 1580, layer 3. Site codes are constants stored at
`G_WHY` (word `CO_AT + 8` = 264241160); without the deleted builder, the site is found natively by scanning the
program store for the constant 1580 and viewing the one function that holds it (`xax_android.xax` F230): the check
after its first layer, which is the DEX writer (layer 1 is the JVM program, layer 2 the class translation). The
writer's own `_ok` checks record no site; the failing one was `G_OUT`'s `alloc` (`64 * 1,559,494 + 65536` words
against the 80M-word arena).

**Windows hosting files.** The new request has root `ad816a6d…`. Its handles are numbered in CID order, so the edit
moves most of them. `../../windows/hosting.batch` is rewritten from the handle lists of the requests before and after:
the root line, plus each handle whose function kept its CID mapped to that CID's new handle. The four functions whose CID
changed (the writer and its callers) are matched by their views with handles ignored: main F473 → F426, F504 → F227,
F620 → F1026, F966 → F1009. Nothing but handles and the root line changes.

**Checks.** `tests/test_xax_selfhost_dex_writer.py::test_large_code_dex`; the PPE module built natively on Windows
equals its reference APK (ADR-403).
