# The evolution ledger's logic as an XAX program

The directory is `ledger-tool/` so it can coexist with the `../LEDGER` file on
case-insensitive Windows filesystems. This naming change leaves canonical store
and batch bytes unchanged; `evolve.sh` and the copy-based test use the new path.

`xax_ledger.xax` is an XAX build request store with the general driver's entry (since 2026-11-25, `driver.batch`):
`main` takes and returns the file system, the process and 22 memory tokens, and reaches files only through the
driver's host functions. So `../../windows/generator/generate.sh` hosts it, and `xax_ledger_windows.xax` is its output;
`evolve.sh` builds that one with the pinned Windows seed under Git for Windows' `sh`. It holds the ledger's logic;
`evolve.sh` keeps only the loops that run `xaxc` and `git`. Every command writes its text to an output file, its last
argument (`evolve.sh`'s `ledger` function prints it back, to standard error for `check`):

```text
xax_ledger check <bootstrap> <out>          exit 0 when every frozen store is its ledger chain's end; 1 after writing
                                            the path of each store that is not, whose chain is broken (a transaction
                                            that does not start at the chain's end) or that cannot be read;
                                            3 when the ledger cannot be read
xax_ledger head <bootstrap> <store> <out>   the store's chain end, 40 hexadecimal digits and a newline; exit 1 when the
                                            store has no baseline or its chain is broken
xax_ledger transactions <bootstrap> <out>   the ledger's transaction lines (every line that is not a comment, a baseline
                                            or empty), as they are
xax_ledger blob <file> <out>                the file's git blob id (SHA-1 of "blob <size>\0" and the bytes) and a
                                            newline; exit 3 when the file cannot be read
xax_ledger after <bootstrap> <prefix> <out> the transaction lines after an earlier LEDGER: exit 1 unless the file
                                            <prefix> is a byte prefix of the ledger that is empty or ends with a
                                            newline; 3 when either cannot be read
```

It replaced the Python `xax_selfhost_evolution` module (removed) and, in `evolve.sh`, the shell check loop, the awk chain lookup,
the awk transaction filter and `git hash-object`/`sha1sum` for blob ids.

Limits: the ledger under 1 MiB, a file under 256 MiB, an argument under 4 KiB; a wrong argument count exits 3.

How it was made, without a Python generator of its logic:

- `seed.xax`: a one-function program from one `xax-construct-v1` carrier (ADR-210), which only supplies the
  entry's signature, the Linux declarations it calls and the three heap-view types.
- `check.batch` (native batch, docs/09_AI_PROTOCOL.md section 16) on `seed.xax`: SHA-1, the field and line scanners,
  two comparisons and the `check` entry.
- `commands.batch` on that result: `blobsum`, `hexput`, `fieldeq`, `copy23` and the entry with the four commands.
  Its result is the committed `xax_ledger.xax`; `xaxc verify` accepts it.

Change it by a further batch on `xax_ledger.xax` (`xaxc edit` lists and shows its functions), then `xaxc verify`.

Checked on Linux x86-64 (WSL 2, the seed `7988e0d0…`): `check` exits 0 on the committed tree and reports a store with
one byte appended, a transaction whose before blob is altered, a missing store (status 1, each with its path) and a
missing ledger (status 3); `head` gives the awk lookup's chain end for three stores and exits 1 for an unknown one;
`transactions` gives the awk filter's 125 lines byte for byte; `blob` equals `git hash-object` on the empty file, a
16 KB and a 62 MB store, and exits 3 for a missing file.

## Derived lines (RFC step 6, 2026-11-15)

`derived.batch` on the previous `xax_ledger.xax` (`main` only) teaches the program a third line kind:
`derived <store> <final blob> <tool root>`.

- From that line on, the store is a tool's output, not a chain. The chain scan stops there, and the line's
  `<final blob>` must equal the chain end; otherwise the chain is broken.
- `check` then no longer compares that store with its committed file. `evolve.sh check` compares the committed file
  with the tool's output instead.
- `head` exits 1 for it, so `evolve.sh apply` refuses a transaction on it.
- `transactions` does not list `derived` lines, so the store's historical transactions still replay.
- Every old line is read as before.

The `<tool root>` (the tool store's root CID) is not read by the program.

Checked on Linux x86-64 (WSL 2, the pinned seed), EXECUTED. On the committed tree the new program's `check`,
`transactions` (142 lines) and `head` equal the old program's. With `derived seed/xax_compiler_request.xax 3b123e3d…`
appended:
- `check` exits 0, `transactions` is unchanged, and `head` of the request exits 1;
- with a byte appended to the request, `check` still exits 0, while a byte appended to the driver fails it;
- a derived line whose final blob is not the chain end fails `check`.

## Driver-shaped main (2026-11-25)

`driver.batch` on the previous `xax_ledger.xax` replaces `main` (F5) and keeps every helper. It supplies the driver's
`xax-host-v1` declarations (and a free declaration for the 1 MiB view type, the driver's 8 MiB one with that type
swapped in), copies the driver's five host functions, and reads every file in 64 KiB chunks. EXECUTED in WSL 2 with
the release 0042 seed: `blob` (empty, 16 KiB, the 63 MB driver, a missing file), `transactions` (31,674 bytes),
`head` (three stores and an unknown one), and `check` (the committed tree, a damaged copy, a missing ledger) give the
previous program's standard output and error byte for byte, with the same exit statuses. On Windows 11 the Windows
build (39,936 bytes) gives the Linux build's `transactions`, `head` and `blob` output, `evolve.sh check` passes in 2 s,
and `evolve.sh replay xax_jvm_general.xax` replays 7 of 7 transactions (54 s). `evolve.sh` still refuses a driver
transaction and skips the request derivation there: `../request-tool` is a Linux x86-64 program.

## The `after` command (ADR-433, 2026-11-28)

`after.batch` on the previous `xax_ledger.xax` replaces `main` (F13) and keeps every helper. A first byte `a` is
command 3 (five arguments). After reading the ledger, the program reads `<prefix>` into the 256 MiB view as a new read
phase, compares it with the ledger's first bytes, checks that it ends at a line end, and then runs the `transactions`
scan from the prefix's end. `evolve.sh replay --from <blob>` uses it for a checkpointed replay.

Checked on Linux x86-64 (WSL 2, the release 0045 seed), EXECUTED:
- `transactions`, `check`, `head` and `blob` give the previous program's output byte for byte.
- `after` exits 0 and gives the ledger's last two lines for the ledger minus those lines, the `transactions` output for
  an empty prefix, and nothing for the whole ledger.
- It exits 1 for a prefix with a byte changed or added, one cut inside a line, and a file longer than the ledger; 3 for
  a missing prefix or four arguments.

The Windows build (`xax_ledger_windows.xax`, from `generate.sh`) gives the same `after` and `transactions` output on
Windows 11.
