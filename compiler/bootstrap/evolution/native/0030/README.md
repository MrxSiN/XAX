# Ledger 0030: the DEX writer's output buffer for large modules (ADR-401)

Applied with `../../evolve.sh apply` to four stores, one batch each, written from `xaxc edit <store> <selector>` views
and accepted by `xaxc verify`. Each batch sets one constant: `N3331` (64, the output words per input word of the
writer frontend's buffer) becomes 16.

| Batch | Store | Function |
|---|---|---|
| `0030-dex-writer-output-cap-dex-writer.batch` | `xax_dex_writer.xax` | F28 (`f6b7f601…`) |
| `0030-dex-writer-output-cap-android.batch` | `xax_android.xax` | F446 (`ec5f4709…`, the writer as the Android program's layer) |
| `0030-dex-writer-output-cap.batch` | the driver | F962 (`ec5f4709…`) |
| `0030-dex-writer-output-cap-request.batch` | the request | F962 (`ec5f4709…`) |

**Finding the site.** The Android program declined at site 1580, layer 3. Site codes are constants stored at
`G_WHY` (word `CO_AT + 8` = 264241160); without the deleted builder, the site is found natively by scanning the
program store for the constant 1580 and viewing the one function that holds it (`xax_android.xax` F230): the check
after its first layer, which is the DEX writer (layer 1 is the JVM program, layer 2 the class translation). The
writer's own `_ok` checks record no site; the failing one was `G_OUT`'s `alloc` (`64 * 1,559,494 + 65536` words
against the 80M-word arena).

**Checks.** `tests/test_xax_selfhost_dex_writer.py::test_large_code_dex`; the PPE module built natively on Windows
equals its reference APK (ADR-401).
