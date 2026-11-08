# Prototype, not applied: the constant fold for the AArch64 backends (2026-11-08)

`mka64.sh <store> <batch>` splices `a64fold.src` (ledger 0022's fold loop with this program's types, the width from
`G2_WBITS`, no erased marks) into the AArch64 view builder (CID `df9251f8…` in the driver, `e875046b…` in
`xax_aarch64_general.xax`) right after `value_facts` succeeds. Folded nodes still compute their value; their uses
read the constant. The edit and `xaxc verify` accept it on the AArch64 program and on BBC's driver.

Not applied: on BBC's Android executables under qemu-aarch64 (median of 5) it measured no gain — mandelbrot 7,628 →
7,790 ms, factor 175 → 181 ms, life 96 → 99 ms (noise) — and 1–2% smaller files. The AArch64 allocator already keeps
the importer's pool values in registers (it has more of them, and hoists costly constants). Emulated timings are not
device timings; a Pixel run could change this (BLOCKED).
