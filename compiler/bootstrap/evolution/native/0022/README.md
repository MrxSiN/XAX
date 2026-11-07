# Ledger 0022: pure integer nodes over constants fold in the x86-64 register lowering (ADR-388)

`mkbatch.sh <store> <batch>` (with `BASICS_CID=c0dd2cdb…`, the x86-64 general backend's `basics`: F766 in the driver
and the request, F176 in the x86-64 general program) lists the store, views `basics`, splices in `fold.src` and
numbers the result. The same function is in all three stores, so the three batches differ only in their first two
lines.

- `basics` (the register lowering's first analysis of a function) clears its per-value tables, then runs its
  analyses from B78. `splice.awk` puts the fold loop (`fold.src`, through `../0020/ws64.awk`) on the one edge into
  B78.
- The loop visits every value of the view in id order. A value whose producer has one result, is `add.wrap`,
  `sub.wrap`, `mul.wrap`, `int.truncate` or `int.zero.extend`, has a machine width of 8, 16, 32 or 64 bits
  (`T_RW`), and whose operands are all constants (`G2_CONST`) becomes a constant: `G2_CONST` = 1, `G2_CVAL` = the
  result masked to its width, and `T_ERASED` = 1. An operand is defined before its user in id order, so chains fold
  in one pass; a value the pass meets first stays a value (exact, only less folded).
- The rest of the lowering already treats those tables by value: an erased value's node emits nothing and its uses
  are not counted; a constant is an immediate, is rematerialized at each use, takes no register and no spill slot,
  and is a read-modify-write addend (`add [m], c`).

Why: BBC's importer builds its offsets and factors in block 0 as an `add.wrap` chain from constant 1 (so a decision
needs no new constant objects). The chain's values were live across the whole decision, so they were spilled and
reloaded at every use. On BBC's mandelbrot decision the fold takes run time from 1,361 to 1,150 ms (median of 7,
Wine on the Linux host) and the executable from 136,704 to 113,664 bytes; the output is unchanged.

The AArch64 backends do not use `basics` and are unchanged.
