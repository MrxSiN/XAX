# BBC's importer: bounds branch before each offset access (2026-11-08)

BBC's importer (`@L_51b36b76` in `../layer_functions.batch`, the emitter that writes a decision's graph from a BFX
record) wrote each ADD (`01 d k`) and MUL (`02 d k`) as one block: the address, its bounds test, an `and` mask that
sends a failing access to cell 0, the access, then a branch on the test. It now writes two blocks:

- the handler block (the block the instruction table names): the address and its bounds test, then a branch to the
  status-1 block or to the access block, passing the address as a tenth parameter (the same shape as CHECK);
- the access block (the next block id): the load(s), the arithmetic and the store, then a branch to the next
  instruction's block.

A failing instruction now touches no cell before it returns status 1 (it touched cell 0 before; the tape is not
observable after a failure either way). The pre-pass gives ADD and MUL two block ids (`split.awk`, B12), so the block
count, the instruction table and every other block keep their meaning; O0 records (no offset instructions) are
unchanged.

Files: `add.tok` and `mul.tok` are the two handlers' varint streams (graph-body encoding, `xax_compiler`'s
`_graph_syntax_bootstrap`: parameters, nodes, terminator; `P5155`/`P5184` the handler block, `N9500001`/`N9500002` the
access block, `N13762`/`N14158` the next block); `chain.awk` turns a stream into the emitter's chained writes
(`@L_fb0c995c`); `split.awk` replaces the old chains and adds the pre-pass count. The result was spliced into
`../layer_functions.batch` (numbered with `bootstrap/evolution/native/0015/renumber.awk`); `../rebuild.sh` then gives
`bbc.xax` root `d6eb910e…`, identical to the store the checks ran on.

Effect on x86-64 (bbc.exe after ledger 0022, Wine, median of 7): mandelbrot 1,198 → 1,092 ms, factor 63 → 60 ms,
life 50 → 46 ms; an ADD is 8 instructions instead of 15. Evidence: `../../../../importer_split_evidence.json`.
