# Ledger 0025: copies for an edge that leaves a loop stay in its stub (ADR-394)

Applied with `../../evolve.sh apply` to four stores, each from its own view (`mkbatch.sh <store> <batch>`):
`0025-loop-exit-copies.batch` (the driver), `-request`, `-aarch64` (`xax_aarch64_general.xax`) and `-android`
(`xax_android.xax`). The function is the same in all four: `_conditional` of the AArch64 register lowering, CID
`8037b966…` before (F70 of the AArch64 program).

**What was measured.** BBC's mandelbrot at -O1 for Android ARM64, on a Pixel 8 Pro (Cortex-X3 core): 1,599 of the
executable's 15,962 instructions were the same `str x1, [sp, #0xb8]`, one before every tape bounds check, inside
every loop:

```text
add  w13, w20, w3
str  x1, [sp, #0xb8]     the off-tape block's parameter lives in a frame slot
cmp  w13, w0
b.hi off_tape
ldrb w19, [x2, x13]
```

`_conditional` runs the taken edge's copies before the test whenever nothing the test or the other path reads lives
where they write, so the branch can go straight to its block. That is right for a loop's back edge. For an edge that
leaves the loop it puts the copy on every pass of the loop, and here the copy is a store. Replacing those stores with
`nop` in the executable (an experiment, not a build) took 6.3% off the run's cycles.

**The change.** The early copies get one more condition: the taken target's loop depth is not below this block's
(`A_DEPTH`, word 36 of the lowering's globals, the table `_loop_depths` fills and the layout already reads).
`exit_copies.awk` adds four word loads and the comparison to the block that decides (B33 of the view: "the taken edge
has copies and its target is not the following block") and threads the loads' memory into the block's two edges. An
edge that fails the test keeps its copies and gets the out-of-line stub every conditional edge with copies already
gets (`X_STUBS`); nothing else in the function changes. `../0015/renumber.awk` numbers the nodes.

The Python reference (`reference/xax_aarch64_regalloc.py`, `_conditional`) has the same condition, so the two still
agree in bytes.

**Result** (Pixel 8 Pro, `taskset 100`, `simpleperf stat`, user mode, three runs each, identical counts of
instructions): mandelbrot -O1 11,992,173,786 → 10,568,247,514 instructions and 2,858 M → 2,649 M cycles (0.927x);
factor -O1 587.2 M → 525.3 M instructions, 153.0 M → 139.2 M cycles (0.910x); factor -O0 3,430 M → 2,869 M
instructions, 762 M → 756 M cycles. Every output equals the expected bytes. The executables grow 8% to 12%
(mandelbrot 67,944 → 74,572 bytes): a stub is the copy and a branch where the early copy was one instruction.

Ceiling: every such edge has its own stub, although most of a function's off-tape edges make the same copy to the
same block. Sharing a stub between edges with equal copies and target would give the size back, if size matters.

Not changed: copies for edges that stay at the same or a deeper loop depth, the false edge's copies, the frame path,
x86-64.
