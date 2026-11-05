# Ledger 0009: N0's completion change, written as native batch text (ADR-372)

The records `../../0009-decoder-reads-bounded-by-store.batch` (the general driver) and `…-request.batch` (the
request store; only the `R` line differs) are the whole change; `evolve.sh apply` ran them through the seed's
`xaxc edit` and `xaxc verify`.  They were written from the native views of the decoder (F77) and the driver's main
(F85) of the ledger-0008 driver (`xaxc edit <store> <selector> <view>`):

- `read_limit.view`: the new function `@read_limit`, by hand;
- `decode2.awk`: the decoder's view with a ninth parameter (P8, the limit; later parameters renumbered) and its 166
  data byte reads as `growable.load.bits.le … P8 …`;
- `main2.awk`: main's view with a `@read_limit` call before each of the ten decoder calls, which become
  `@decode2` calls with that limit; node handles renumbered (the assembler takes handles in order).

The batch is `R <root>`, `F77`, `define @read_limit … end`, `define @decode2 … end`, `define @main2 … end`,
`replace F85 @main2`.  These awk scripts only renumber and splice view text; no generator made the change.
