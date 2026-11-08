# Rejected: fewer block parameters in BBC's importer (2026-11-08)

Step 1 of the hanoi -O0 plan. Every block of a decision has nine parameters: the pointer, the input and output
positions, and three (view, memory token) pairs. The three views (type T1) are only passed on and returned; no node
reads them. Dropping them from every block but block 0, and returning block 0's views directly, would take hanoi's
-O0 decision from about 620,000 to about 458,000 values.

Tools (not applied): `chains.awk` lists each emitter block's write chain; `parse.awk` walks a chain through the
graph-body grammar from the start state in `progs.txt` and emits patch actions (header 9 → 6 types, edge arguments
3/5/7 dropped, returns pointed at block 0's views, token indices 4/6/8 → 3/4/5); `patchview.awk` applies them to the
emitter's view (a set is a fresh constant, a drop rewires the chain).

The emitter edit and `xaxc verify` of `bbc.xax` accept it, but every decision it emits is rejected by `verify` and
`resolve`: `XAX.MEMORY.HEAP_VIEW` `HEAP-VIEW-RETURN-WHOLE` ("live base pointer, view, and matching effect"). A
returned heap view must arrive with its own effect chain, so the views travel with their tokens through every
block. Without this, hanoi -O0 needs `VCAP` of 2^20 (ADR-390).
