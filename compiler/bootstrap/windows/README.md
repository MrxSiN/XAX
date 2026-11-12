# Native Windows seed — the production compiler, self-built on Windows

`xaxc-windows-x86_64.exe` is the production compiler (`xax_compiler_driver_general.xax` after ledger 0026) with the
Windows hosting layer: 31,959,040 bytes, SHA-256
`e2f68c00a8dee67490929b173469e383853564254ed80b3a7a5e8188d8c50122`. Exact identities are in `seed.json`.

It replaces the alias-index seed of 2026-10 (`aa72234d…`, in git history), which took only `XAXEDIT1` records and
declined its own source.

## What it is made from

The store is BBC's driver (`../../integration/bfx/bbc.xax`: the production driver plus the Windows process entry,
file adapters and lazily committed views) with one native batch applied, `xaxc_entry.batch`. The batch defines a
four-node entry and installs it with `replace`: it registers the view-commit handler and calls the driver's
command-line entry. BBC's own front is no longer reachable, so the edit engine drops it: the result is the
production driver and the hosting layer only (62,530,358 bytes, SHA-256 `c35072b4…`).
`xaxc_entry_request.batch` is the same batch for `bbc_request.xax` and gives the build request (SHA-256
`ceb7d893…`).

## Rebuilding it on Windows

```text
xaxc-windows-x86_64.exe edit ..\..\integration\bfx\bbc_request.xax xaxc_entry_request.batch request.xax
xaxc-windows-x86_64.exe verify request.xax request.diag
xaxc-windows-x86_64.exe resolve request.xax snapshot.xax
xaxc-windows-x86_64.exe build snapshot.xax xaxc.exe xaxc.provenance
```

`xaxc.exe` must have the SHA-256 above. That is the check for this directory: the seed builds itself byte for byte.
On Windows 11 it takes about 5 minutes. No Python, WSL or Wine takes part.

The two batches name handles of the `bbc.xax` they were written for (root `73b8a28b…`). After `bbc.xax` changes,
write them again from `xaxc edit bbc.xax <selector>`: the root line, the entry's handle (twice), the handler
(`function.address`) and the command-line entry (`call.direct`) as the entry's own view shows them.

## Evidence (2026-11-12, Windows 11 build 26300)

`../../benchmarks/windows_selfhost_evidence.json` records the runs:

- the Linux-hosted compiler (self-built from ledger 0026, `7988e0d0…`) built `xaxc.exe` from the request; that
  file then built itself on Windows to the same bytes (generation 1 equals generation 2);
- its `edit` applies a native batch and its result equals the Linux compiler's, byte for byte; `verify` accepts it;
- it resolves and builds the Linux compiler's request (`../seed/xax_compiler_request.xax`) to the bytes the Linux
  self-build makes (`7988e0d0…`);
- it builds the BLAKE3 host (`../../integration/windows_helpers/hash_request.xax`), which gives the official digest
  of `abc`.

## Contract

```text
xaxc-windows-x86_64.exe verify <store> <diagnostic>
xaxc-windows-x86_64.exe inspect <store> <inspection-record>
xaxc-windows-x86_64.exe edit <store> <input> <output>
xaxc-windows-x86_64.exe resolve <request-store> <snapshot-store>
xaxc-windows-x86_64.exe build <snapshot-store> <artifact> <provenance>
```

The commands and exit statuses are the production compiler's (`docs/09_AI_PROTOCOL.md` §16): `edit` takes a
selector, a native batch, a rejection record or an `XAXEDIT1` record. Exit 0 is success, 1 a rejection with a
diagnostic, 2 a decline, 3 a usage or I/O failure. Run `verify` on a candidate before accepting it.

## Limits

- The Linux seed in `../seed` is still the ledger 0023 build; this seed is ahead of it until that one is rotated.
- All runs here had standard input and output redirected. One earlier run of a program this compiler built, started
  with the console's own handles, did not return and is not explained (`XAX_STATE.md`, 2026-11-12).
- The store and request are not committed: they are one `edit` away from `bbc.xax` and `bbc_request.xax`.
