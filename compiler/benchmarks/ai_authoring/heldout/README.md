# Held-out fixture stores (corpus `v1`)

The starting stores of the held-out tasks H1-H5 in [`../README.md`](../README.md#held-out-tasks), committed on
2026-11-28 before any measured run. A change to a store, a name or a key makes corpus `v2`.

## Stores

Each store was made natively: its `.batch` is a `define` and `replace` batch (`docs/09_AI_PROTOCOL.md` §16) on
`compiler/bootstrap/evolution/ledger-tool/seed.xax`, applied with `xaxc edit` and accepted by `xaxc verify` (Windows
seed, release 0045). Views are 64 KiB byte views: `ptr<bits8>`, its `heap_view`, and a memory-effect token, the
seed's own types.

| Task | Store | Root | Start |
|---|---|---|---|
| H1 | `h1.xax` | `d17067a2…` | `copy(dst, dst view, dst token, src, src view, src token, n: bits64)` returns its views and tokens unchanged |
| H2 | `h2.xax` | `9e3feb7c…` | `mark(p, view, token, flag: bits64)` returns its view and token unchanged |
| H3, H4 | `calc.xax` | `8fa2a94e…` | the functions below |
| H5 | `calc.xax` with `h5.batch` | | `h5.rejection` is `xaxc verify`'s record for the store `h5.batch` makes |

Function names are not in the graph (ADR-428 would add them), so the task text's names map to handles here. These
belong to the task statement and are given to the agent with it.

| `calc.xax` handle | Name | What it is meant to do |
|---|---|---|
| F0 | `scale` | `x * 3` |
| F1 | `calc` | the entry: `op` 0 calls `sum_below(x)`, 1 calls `crc_mix(x, y)`, anything else `scale(x)` |
| F2 | `crc_step` | one bit of the reflected CRC-32 step (polynomial `0xEDB88320`) |
| F3 | `crc_byte` | eight `crc_step` calls over a byte |
| F4 | `crc_mix` | `crc_byte` of `x` and then of `y`, from `0xFFFFFFFF` |
| F5 | `bound` | the loop bound `sum_below` uses |
| F6 | `sum_below` | the sum of `i` for `i < n` |

## Checks

- H1, H2, H3, H5: the harness builds the agent's store and runs the entry against the reference executor on the
  inputs of the task table (H1: n = 0, 1, 7, 4,096 over source bytes `i mod 251`; H2: flag 0 and 1; H3 and H5:
  `calc` with op 0, 1 and 2 on x, y in {0, 1, 7, 255, 4,096}).
- H3's "no caller's CID changes" is read as: no other function's graph changes except for its reference to the
  changed function. A caller's CID always changes when a callee's does, since the store is content-addressed.
- H5: the repair is in `keys/H5.key` (hidden, as below).
- Solvability (EXECUTED, Windows 11, scratch, not committed): a scratch H1 loop with checked loads and stores is
  accepted by `xaxc verify`.

## Answer keys

`keys/` holds the answer keys for B9 and H4 and the H5 repair. Like the task table's "Reference" column, it is
hidden from the measured agent: the harness removes `keys/` from the run's checkout.

- `keys/B9.key`: over the release/0043 driver (`a9c43b8`), the x86-64 backend entry F86 (ADR-423 amendment 5)
  reaches 237 functions, and 11 of them hold the constant 29,360,298. Computed read-only with the reference
  `StoreReader`; the handles were checked against `xaxc edit`'s listing of that store.
- `keys/H4.key`: changing `crc_step`'s signature makes `crc_byte` be redefined, and changes the CIDs of `crc_step`,
  `crc_byte`, `crc_mix` and `calc`.
