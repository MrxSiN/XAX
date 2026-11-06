# Ledger 0017: next-iteration prefetch within a block budget (ADR-380)

`prefetch.awk` puts a guard in front of the general backend's `prefetch` (the view's next-iteration prefetch
selection). It is F295 in the driver and the request and F65 in the x86-64 general program, and its view is the same
in all three apart from handles.
- The guard reads the view's block count (`GLOBALS + G_BCOUNT`, word 29360176).
- Above `LIMIT` (4096) blocks it returns 1 and selects nothing.
- Otherwise the old body runs. Its entry block is B2, every block number shifts by two, and `../0015/renumber.awk`
  numbers nodes and parameters.

Why: `prefetch` calls `cycle` for every block that ends in a branch. Each `cycle` makes a forward walk and then a
backward fixed point over every block, so the cost grows roughly as the cube of the block count. In BBC's F811
(1,782 inlined calls) one function took more than 35 minutes in the native program. With the guard, F811's closure
takes 4 minutes. Prefetch marks only add prefetches, so skipping them changes speed, never results.
