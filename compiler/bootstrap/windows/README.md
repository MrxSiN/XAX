# Current Windows seed — 2026-11-13

Ledger 0028 adds native rebuilding of unsigned resolved snapshots after edits. The current seed is 31973888 bytes, SHA-256 `9779c7938b092b6a1b64bd97ff4950a0e5858f43e0f95040e5ea0d33c2319cd0`. Its exact source and build identities are in [seed.json](seed.json). Native Windows generation 1 equals generation 2; see [the new fixed-point record](../../benchmarks/windows_selfhost_20261113_evidence.json) and [mutation acceptance](../../benchmarks/snapshot_mutation_20261113_evidence.json). The Linux seed is also rotated to ledger 0028 and has two identical native generations.

The entry batches now bind BBC roots `c5814b38579d1f78b3ab23f6c10e2df6942e9ecc3a306e767aa911304909a154` and `4104d62baccfb59cb42d2035c354ae923847017422db7c90eaa7aff4c3d37217`; current handles are recorded in the checked native entry batches. Apply the same rebuilding commands below using the current seed. Run native verification on every edited candidate before accepting it. Signed-package changes, recursion-group users, signature/provenance rewriting and broader backend/security readiness are outside this increment.

The following description records the prior ledger-0027 seed; its hashes and observations are historical.

# Native Windows seed â€” the production compiler, self-built on Windows

`xaxc-windows-x86_64.exe` is the production compiler (`xax_compiler_driver_general.xax` after ledger 0027) with the
Windows hosting layer: 31,964,672 bytes, SHA-256
`91ce2a7146bc1057bfd85e6c739173bc8c9a3a7d46e2898779bae53522e7e871`. Exact identities are in `seed.json`.

It replaces the alias-index seed of 2026-10 (`aa72234dâ€¦`, in git history), which took only `XAXEDIT1` records and
declined its own source.

## What it is made from

The store is BBC's driver (`../../integration/bfx/bbc.xax`: the production driver plus the Windows process entry,
file adapters and lazily committed views) with one native batch applied, `xaxc_entry.batch`. The batch defines a
four-node entry and installs it with `replace`: it registers the view-commit handler and calls the driver's
command-line entry. BBC's own front is no longer reachable, so the edit engine drops it: the result is the
production driver and the hosting layer only (62,542,672 bytes, SHA-256 `82543ac7â€¦`).
`xaxc_entry_request.batch` is the same batch for `bbc_request.xax` and gives the build request (SHA-256
`1b528828â€¦`).

## Rebuilding it on Windows

```text
xaxc-windows-x86_64.exe edit ..\..\integration\bfx\bbc_request.xax xaxc_entry_request.batch request.xax
xaxc-windows-x86_64.exe verify request.xax request.diag
xaxc-windows-x86_64.exe resolve request.xax snapshot.xax
xaxc-windows-x86_64.exe build snapshot.xax xaxc.exe xaxc.provenance
```

`xaxc.exe` must have the SHA-256 above. That is the check for this directory: the seed builds itself byte for byte.
On Windows 11 it takes about 5 minutes. No Python, WSL or Wine takes part.

The two batches name handles of the `bbc.xax` they were written for (root `937d05c3â€¦`). After `bbc.xax` changes,
write them again from `xaxc edit bbc.xax <selector>`: the root line, the entry's handle (twice), the handler
(`function.address`) and the command-line entry (`call.direct`) as the entry's own view shows them.

## Ledger 0027 (2026-11-13)

Cut after ledger 0027 (edge-copy staging, `XAX_OPEN_ISSUES.md` OI-59) from the rebuilt `bbc.xax`. The ledger 0026
seed (`e2f68c00â€¦`, in git history) built generation 1 from the request; generation 1 built generation 2 and generation
2 built generation 3 on Windows 11. Generations 2 and 3 are byte-identical and are this file: a change to code
generation needs the extra generation, since generation 1 is still the old compiler's output. The entry batches name
the new store's handles: entry `F598`, handler `F988`, command-line entry `F125`.

## Evidence (2026-11-12, Windows 11 build 26300, ledger 0026 seed)

`../../benchmarks/windows_selfhost_evidence.json` records the runs:

- the Linux-hosted compiler (self-built from ledger 0026, `7988e0d0â€¦`) built `xaxc.exe` from the request; that
  file then built itself on Windows to the same bytes (generation 1 equals generation 2);
- its `edit` applies a native batch and its result equals the Linux compiler's, byte for byte; `verify` accepts it;
- it resolves and builds the Linux compiler's request (`../seed/xax_compiler_request.xax`) to the bytes the Linux
  self-build makes (`7988e0d0â€¦`);
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

The commands and exit statuses are the production compiler's (`docs/09_AI_PROTOCOL.md` Â§16): `edit` takes a
selector, a native batch, a rejection record or an `XAXEDIT1` record. Exit 0 is success, 1 a rejection with a
diagnostic, 2 a decline, 3 a usage or I/O failure. Run `verify` on a candidate before accepting it.

## Limits

- The Linux seed in `../seed` is the ledger 0027 build (rotated 2026-11-13, with this seed).
- All runs here had standard input and output redirected. One earlier run of a program this compiler built, started
  with the console's own handles, did not return and is not explained (`XAX_STATE.md`, 2026-11-12).
- The store and request are not committed: they are one `edit` away from `bbc.xax` and `bbc_request.xax`.
