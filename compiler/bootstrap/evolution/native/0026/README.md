# Ledger 0026: PE images commit their whole stack reserve (ADR-396, OI-56)

Applied with `../../evolve.sh apply` to three stores: `0026-pe-commit-stack-reserve-x86-64.batch`
(`xax_x86_64_general.xax`), `0026-pe-commit-stack-reserve.batch` (the driver) and `-request`.

The function is the PE writer, CID `afdd041f…` before (F155 of the x86-64 program, F690 of the driver). Its optional
header writes four constants in a row: stack reserve 1048576 (N7798), stack commit 4096 (N7906), heap reserve
1048576 (N8014), heap commit 4096 (N8122). The batch is one edit, `const N7906 1048576`, under each store's own
root and handle.

Why the header and not page probes: the backend takes a frame with one `sub rsp, N` in three emitters (F17, F26
and F145 of the x86-64 program). Probes would add a loop to each and have to match the reference's bytes; the header
is one value and covers every frame up to the reserve.

Check: `selfbuild.sh` reaches its fixed point on the new request store (`7988e0d0…`), and the `bbc.exe` built from
the new stores runs on Windows 11 with its header as built (`XAX_STATE.md`, 2026-11-12).
