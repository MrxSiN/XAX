# Ledger 0009: N0's completion change, written as native batch text (ADR-372)

The records `../../0009-decoder-reads-bounded-by-store.batch` (the general driver) and `…-request.batch` (the
request store; only the `R` line differs) are the whole change. `evolve.sh apply` ran them through the seed's
`xaxc edit` and `xaxc verify`. They were written from the native views (`xaxc edit <store> <selector> <view>`) of the
ledger-0008 driver's decoder (F77) and main (F85):

- `read_limit.view`: the new function `@read_limit`, written by hand.
- `decode2.awk`: the decoder's view, with these changes:
  - P6 becomes the read limit and P7 (the mode) becomes `bits<32>`, as do the constants compared with it;
  - three opening nodes: the limit through `@read_limit`, 32, and the length (the limit less 32), which replaces P6
    wherever P6 was used;
  - the 166 data byte reads become growable loads bounded by that limit;
  - node handles are renumbered.
- `main2.awk`: main's view. Each decoder call is preceded by `32` and `length + 32`, and passes that sum and its mode
  constant typed `bits<32>`. Node handles are renumbered, because the assembler takes handles in order.

The batch is `R <root>`, `F77`, `define @read_limit … end`, `define @decode2 … end`, `define @main2 … end`, and
`replace F85 @main2`. The awk scripts only splice and renumber view text; no generator made the change.
