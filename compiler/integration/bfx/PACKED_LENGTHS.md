# Packed decision lengths — 2026-10-31

An emitted BBC decision used to take five machine arguments: the three borrowed
views (input, output, tape) plus the input length and the output capacity as two
`bits<32>` values. The x86-64 register-resident lowering (`_eligible`, ADR-095)
accepts at most four machine parameters, so every decision fell back to the frame
path, which keeps every value in memory.

The decision now takes the two lengths as one `bits<64>` argument,
`input | capacity << 32`. With four machine parameters every decision checked so
far is eligible for the register path on Windows x86-64.

## Decision interface

| | Before | After |
|---|---|---|
| Parameters | 3 × (view, resource, effect), `bits<32>` input, `bits<32>` capacity | 3 × (view, resource, effect), `bits<64>` lengths |
| Machine parameters | 5 | 4 |
| Returns | unchanged: `bits<64>` `(output_bytes << 32) \| status`, the views given back | unchanged |

Block 0 unpacks first: `n0 = trunc32(p9)` (input), `n1 = rotr64(p9, 32)`,
`n2 = trunc32(n1)` (capacity). Every former use of the two parameters reads `n0` or
`n2`; the checks, statuses and Brainfuck semantics are unchanged. The FUNCTION no
longer references `bits<32>` (the graph still does), so it has six references.

## Importer emitter (`import_bfx.xax`)

One `REPLACE_REFERENCE` of the emitter function's graph fragment:

- **Block 0 stream** (emitter block 6): parameter count 11 → 10, the last parameter
  type `bits<64>`; three unpack nodes before the length checks; the checks and their
  `or` move to nodes 13–15.
- **Node count and pool**: block 0 has `15 + M` nodes (was `12 + M`); the pool loop,
  its operand offsets and the handlers' pool references move by 3.
- **Status dispatch** (emitter block 167): the two error-status branches read the
  length checks at nodes 13/14, and block 0's terminator reads node 15.
- **I/O limits**: the decision's I/O length operands read block-0 nodes instead of
  parameters.
- **FUNCTION references** (emitter blocks 15, 46–63, 126): the fragment's CID rank
  no longer counts `bits<32>`; the six type CIDs shift one slot so `bits<32>` is not
  copied; the reference count is 6.
- **FUNCTION signature** (emitter blocks 63–123): 10 parameters, the tenth has the
  rank of `bits<64>`; type ranks above `bits<32>` drop by one.

## Hosts

`standalone_windows.xax`, `standalone_arm64.xax`, `bbc-windows-x86_64.xax` and
`bbc-android-arm64.xax`: the placeholder decision gets the same signature and unpack
nodes, and the single call site passes `zext64(input length) | 65536 << 32`
(three new nodes before the call). Input and output capacity stay 65,536 bytes.

`compile_windows.xax` and `bbc.xax`: the importer is rebound by reference, and the
`bind` framing's 26 identity words (request root, host fragment and placeholder of
both targets) are replaced at equal length, as in the dynamic-tape migration.

## Results (Windows 11 x86-64, native, 2026-10-31)

[packed_lengths_evidence.json](packed_lengths_evidence.json) has the identities and
checks; BBC's `evidence/packed_lengths_benchmark_2026-10-31.json` has the raw timing samples.

- **Correctness.** The new `bbc.exe` against the previous one: 85 programs × O0/O1,
  170 cases, identical output bytes and exit status (21 slow edge-walking cases were
  rerun to completion; both exit 1 at the tape edge, the new code 5–8× sooner).
- **Run time, O1 (median of 15).** Mandelbrot 7,661 → 1,080 ms, factor 467 → 84 ms,
  life 62 → 23 ms, bottles 15.5 → 13.5 ms. Small programs are at the process floor.
- **Executable size.** Mandelbrot 1.05 MB → 137 KB, factor 352 → 47 KB, small programs
  about 43 → 8.6 KB.
- **Build cost went up** for large programs: mandelbrot O1 566 → 1,303 ms and
  91 → 142 MiB peak working set, factor O1 149 → 208 ms. Register allocation is the
  added work. Small builds are unchanged (43 → 40 ms).
- **Android.** Two packed programs (`,[.,]` and factor O1) ran correctly on a Pixel 8
  Pro. The device then went offline, so the Android campaign was not run. Android
  mandelbrot still declines at build, as before.
- **Mandelbrot O0** still declines: native `verify` declines its decision store
  ([OI-51](../../../XAX_OPEN_ISSUES.md)).

## Transactions

Expected-root records in [transactions/packed/](transactions/packed/). Each was
fully verified with the reference verifier and rejected as stale on its result.
The native driver (`xaxc edit`, PE SHA-256 `110a76a2…`) replays records 1–3 and 6–9
to byte-identical stores, verifies each result and rejects each replay as stale;
records 4–5 apply to `bbc.xax`, which exceeds the driver's file capacity, so the
reference application and full verification establish them.

| # | Store | Change |
|---|---|---|
| 1 | `import_bfx.xax` | Emitter: packed lengths, six FUNCTION references |
| 2, 4 | `compile_windows.xax`, `bbc.xax` | The new importer, by reference |
| 3, 5 | `compile_windows.xax`, `bbc.xax` | `bind` framing identities of the new requests |
| 6, 7 | Windows and Android requests | Placeholder signature, packed call |
| 8, 9 | Windows and Android standalone hosts | Placeholder signature, packed call |

Authoring transport: short external Python scripts using the generic `xax_compiler`
constructors and `xax_selfhost_edit.edit_record` (not committed), as for the earlier
BBC transactions. No generic SDK file and no BBC Brainfuck changed.
