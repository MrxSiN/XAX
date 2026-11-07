# Ledger 0019: leaf-call inlining within a value budget (ADR-383)

`budget.awk` puts a guard in front of the general backend's `candidate` (CID `ac26e229…`, the inliner's test of
whether one `call.direct` of a small leaf function is inlined into the lowering view). It is F667 in the driver and
the request and F144 in the x86-64 general program, and its view is the same in all three apart from callee handles.
- The guard reads the view's value count (`GLOBALS + G_VCOUNT`, word 29360173).
- Above `BUDGET` (2^17) values it gives 0: the call is not inlined and stays a call.
- Otherwise the old body runs. Its entry block is B2, every block number shifts by two, and `../0015/renumber.awk`
  numbers nodes and parameters.

`mkbatch.sh <store> <batch>` lists the store, views `candidate`, applies the guard and writes the batch.

Why: a view holds at most `VCAP` = 2^18 values. BBC's compile front (`51b36b76…`, F163 of the older `bbc.xax`)
calls one 47-line leaf 2,434 times; inlining every call passed `VCAP` and the build declined (`G_VCOUNT` = 262,144).
Each splice adds at most one leaf's values (256 nodes at most), so the budget leaves half the view for them and for
the passes after inlining. Inlining only removes calls, so leaving some in place changes speed, never results.
With the guard, BBC's whole program (1,058 functions, 35.95 MB of code) is emitted.
