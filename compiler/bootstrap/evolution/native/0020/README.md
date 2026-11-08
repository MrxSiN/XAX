# Ledger 0020: AArch64 `_aliases` and `_intervals` scale with nesting depth (ADR-384)

Applied to four stores with `../../evolve.sh apply`: `0020-aarch64-alias-lists.batch` (the driver), `-request`,
`-aarch64` (`xax_aarch64_general.xax`) and `-android` (`xax_android.xax`), each from that store's own views.

BBC's `deep512active` (512 nested loops, 2,058 blocks and 37,041 values in its view) took the native AArch64
program about 2,100 s (Python-hosted) and then declined.
- **Time:** `_aliases` (CID `adc7c672…`, F104 of the AArch64 program, F679 of the driver and request, F324 of the
  Android program) gives a block parameter an alias when every incoming argument gives one value, in rounds to a fixed
  point. Each round scanned every edge argument of the function for every parameter. `aliases.awk` splices in
  `lists.src` (through `blocks.awk`): before the rounds, each parameter's incoming arguments are listed once, in the
  order that scan met them (start offsets S and the arguments A, two passes over the edges). A round then reads
  `A[S[v] .. S[v + 1])` for parameter v. The aliases found are the same, in the same order. Sampling put all 40
  samples in this function; with the lists the program reaches its decline in 6 s.
- **Decline:** `_intervals` (CID `0952bb79…`) allocated its range pool as (blocks × values + 4 × blocks) × 3 words,
  228.7 M words here, past the arena. `pool_bound.src` (`@pool_bound`) bounds the ranges exactly enough: a block
  touches only values live into it, its parameters and the values its nodes define (anything it reads or leaves live
  is one of those), so at most |live-in| + parameters + nodes per block, the value count once for hoisted values,
  and one range per edge argument. The pool takes min(that bound, blocks × values) ranges, so it is never larger than
  before. `intervals.awk` calls it at the top of B0.

Files: `mkbatch.sh <store> <batch>` (lists the store, views both functions, applies the edits, numbers the result);
`ws64.awk` (`../0016/ws.awk` with this program's word and memory types), `blocks.awk` (the block macros of
`lists.src`), `blockrenum.awk` (blocks numbered in order), then `../0015/renumber.awk`.
