# `xbench` maintenance cycle on Windows (R5 record for `windows-x86_64-pe`)

`xbench` is the timing harness of `../windows_chains` (an XAX program authored as a native batch). This directory
holds one maintenance cycle on it, run only through the native workspace of the Windows seed
(`docs/09_AI_PROTOCOL.md` section 16) on Windows 11; `../r5_windows_xbench_maintenance_evidence.json` is the record.

Request: run 50 rounds per arm instead of 34.

```text
xaxc-windows-x86_64.exe edit xbench-gen0.xax <empty file> list.txt      the function list
xaxc-windows-x86_64.exe edit xbench-gen0.xax <file holding F1> f1.txt   the harness function: N23 constant 34
xaxc-windows-x86_64.exe edit xbench-gen0.xax rounds50.batch gen1.xax    the edit: const N23 50
xaxc-windows-x86_64.exe verify gen1.xax diag
```

`gen1.xax` is `xbench-gen1.xax` byte for byte. The executable comes from the same edit on the build request
(`rounds50_request.batch` on the request that `../windows_chains/xbench_request.batch` makes), then `resolve` and
`build`.

- `xbench-gen0.xax`: `../windows_chains/xbench.batch` applied to `../../integration/bfx/bbc.xax` (root `eb64f934…`).
- `xbench-gen1.xax`: generation 0 with the edit (root `3b945072…`).

The harness that made the committed chains samples is generation 0. Generation 1 is not yet the committed
`xbench.batch`; adopt it with the next measurement.

The record also says what this application lacks to count as XAX-only (R6): tests written in XAX.
