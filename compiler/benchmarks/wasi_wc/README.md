# `wc` for WASI, authored natively and built by the production compiler

A stream counter for `wasm32-wasi-v1`: it reads standard input to the end and writes one line of five zero-padded
10-digit fields: lines (byte 10), words (maximal runs of bytes above 32), bytes, and `s1`, `s2` (8-bit wrap-around
sums, `s1 += byte`, `s2 += s1`). Before reading it calls `args_sizes_get`, `args_get`, `clock_time_get` and
`random_get` and exits 20 to 27 if one fails (more than 4 arguments: 21). A failing `fd_read` exits 15.

`wc.batch` is a native batch (docs/09 section 16) on `starter_request.xax`: it supplies the WASI types and eight
`wasm32-import` declarations as `object` lines, defines `DIGIT`, `REM`, `EMIT`, `WIDEN8`, `PROBE`, `WCRUN` and
`ENTRY`, and installs `ENTRY` with `replace F0`. The `object` lines (types and foreign declarations) and
`starter_request.xax` (one trivial entry, package, `wasm32-wasi-v1` target, default profile) were produced once with
the Python reference constructors, because no native interface creates a request store from nothing and `replace`
cannot change a request's target. The Windows seed cannot make this store itself; every function body is native.

```text
..\..\bootstrap\windows\xaxc-windows-x86_64.exe edit starter_request.xax wc.batch request.xax
..\..\bootstrap\windows\xaxc-windows-x86_64.exe verify request.xax request.diag
..\..\bootstrap\windows\xaxc-windows-x86_64.exe resolve request.xax snapshot.xax
..\..\bootstrap\windows\xaxc-windows-x86_64.exe build snapshot.xax wc.wasm wc.provenance
```

Run it with any WASI preview1 host that gives it standard input on descriptor 0 (the evidence used `node:wasi`).

`wc.wasm` is 3,626 bytes, SHA-256 `990f7aae6f1ff4168eeeb5d985124ba43991c8e0dba92d6b433d47ebfd8c76ba`; rebuilding gives
the same bytes, and the Python reference backend (`xax_wasm.compile_wasm_bound_target`) gives the same bytes from the
same verified store. `../wasi_wc_evidence.json` records the runs under Node.js WASI and the oracles (an independent
JavaScript statement of the contract, and GNU `wc` on the inputs where its definition of a word agrees).

Platform rules this program works around (found by the verifier, not assumed): the wasm32-wasi profile has no
widening, xor, and/or or division, so digits are produced by repeated subtraction and the checksum is 8-bit;
`pointer.cast` between element types is declined by the native verifier, so each buffer is allocated with the type
it is read with; a checked load needs the whole view initialized by plain stores (host writes are not tracked), so
the 32-byte read buffer is zeroed with 32 byte stores; a wasm function has at most one machine result.
