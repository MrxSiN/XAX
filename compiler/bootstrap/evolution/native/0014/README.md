# Ledger 0014: heap views on the frame path on every x86-64 target (ADR-377)

The batch for each store is that store's native view of `frame_function` (F815 in the driver and the request, F195
in the x86-64 general program, from `xaxc edit <store> F<n> <view>`), with one edit. It is the compare that sets
`F_DYN`, N343: `int.compare N341 N342 -> T6 [1]` (`G_WINDOWS == 0`) becomes `[6]` (`G_WINDOWS >= 0`, unsigned),
so `F_DYN` is 1 on every target. Each view keeps its own callee handles, so the batches differ only in their
handles and roots.
