# The ledger check as an XAX program

`xax_ledger.xax` is a Linux x86-64 process, an XAX build request store. `xax_ledger <bootstrap directory>` reads
`<bootstrap>/evolution/LEDGER`, follows every frozen store's chain from its `baseline` line through the transaction
lines that name it, reads the store and compares its git blob id (SHA-1 of `blob <size>\0` and the bytes) with the
chain's end. Exit status 0 when every store is its chain's end; 1 after writing to standard error the path of each
store that is not, whose chain is broken (a transaction that does not start at the chain's end) or that cannot be
read; 3 when the ledger cannot be read. It replaces the Python `xax_selfhost_evolution.check` (removed) and the
shell loop `evolve.sh check` had; `evolve.sh check [<bootstrap>]` builds it with the pinned seed and runs it.

Limits: the ledger at most 1 MiB, a store at most 256 MiB, a path at most 64 KiB; the comparison is with the
lower-case hexadecimal blob ids the ledger writes.

How it was made, without a Python generator of its logic:

- `seed.xax`: a one-function program from one `xax-construct-v1` carrier (ADR-210), which only supplies the
  entry's signature, the Linux declarations it calls and the three heap-view types.
- `check.batch`: the native batch (docs/09_AI_PROTOCOL.md section 16) that defines the seven functions (SHA-1,
  the field and line scanners, two comparisons, the entry) and replaces the seed's entry.
  `xaxc edit seed.xax check.batch xax_ledger.xax` makes the committed store byte for byte; `xaxc verify` accepts it.

Change it by a further batch on `xax_ledger.xax` (`xaxc edit` lists and shows its functions), then `xaxc verify`.

Checked on Linux x86-64 (WSL 2, the seed `7988e0d0…`): on the committed tree it exits 0; on a copy it reports a
store with one byte appended, a transaction whose before blob is altered, a missing store (status 1, each with its
path) and a missing ledger (status 3). Its SHA-1 equals `sha1sum` on the empty file, a 62 MB store and two small
files.
