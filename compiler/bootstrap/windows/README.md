# Current Windows seed — the release record, 2026-11-18

`xaxc-windows-x86_64.exe` is pinned only by `../RELEASES` (`sh ../seed/rotate.sh state`, `pin x86_64-windows-pe-v1`).
Its confirmation, with the generated request it rebuilt itself from, is the release's
`../evidence/confirm/<n>-x86_64-windows-pe-v1.txt`. `seed.json` is retired (ADR-410); the sections below are
historical, and their links to it name the file as it was in git history.

# Current Windows seed — ledger 0035 (release 0033), 2026-11-16

`xaxc-windows-x86_64.exe`: 31,602,176 bytes, SHA-256 `ae43e32f21ccd2d7e333ebf30a114d329ca5b5912c388ae167c24d12d2e9f665`.
It is built from `generator/generate.sh`'s request (`67f7cfa4…`) for the ledger 0035 shared request. The new Linux
fixed point (`36e2b756…`) cross-built it in WSL 2 (210 s). On Windows 11 it rebuilt itself byte for byte (197 s), and
that generation rebuilt the next one identically (195 s); no Python, WSL or Wine took part. Identities are in
`seed.json` (retired by ADR-410; see git before `01276a8`). The sections below are historical.

# The Windows request is generated — 2026-11-15

`hosting.batch` and `pe_target.edit` are no longer written by hand; they are deleted. `generator/generate.sh`
makes the Windows seed's build request from the shared request ([generator/README.md](generator/README.md)):

```text
sh generator/generate.sh ../seed/xax_compiler_request.xax request.xax
xaxc resolve request.xax snapshot.xax
xaxc build snapshot.xax xaxc.exe xaxc.provenance
```

At ledger 0032 it reproduces the deleted files' results, EXECUTED in WSL 2 with the pinned Linux seed:

- the hosting batch, byte for byte (`afa009b9…`);
- the hosted store (`ff9dfa42…`);
- the PE record, byte for byte (`d13fb5b9…`);
- the request (`5bf65de6…`);
- its build, which is the pinned seed `e88877d1…`.

`seed.json` (retired by ADR-410; see git before `01276a8`) keeps the deleted files' names and hashes as the record of how the pinned seed was built. The
generator needs Linux x86-64, as the ledger and request tools do. The sections below are historical; where they say
to rewrite the hosting files, run the generator instead.

# Current Windows seed — ledger 0032, 2026-11-15

Ledger 0032 lets the DEX writer size its output for large modules (ADR-403). The seed is built as the ledger 0031
section below describes. Only the hosting files changed: they are rewritten for the new request root `ad816a6d…`.
`hosting.batch` has the new root line and the handles that moved. Main is F426 (F473 before), and the four functions
whose CIDs changed are matched by their views (`../evolution/native/0032/README.md`). `pe_target.edit` binds the new
hosted root `7262bc4f…` and the new module object `14fbaca8…`; its supplied object and target reference are unchanged.
On Windows 11, the ledger 0031 seed built generation 1 in 7 minutes, and generation 1 built generation 2. Both are
byte-identical: 31,993,856 bytes, SHA-256 `e88877d10690e171b73d9de8b94cb579820672e980b97f0bb11a88e460a7a77f`. The
Linux ledger 0032 seed cross-builds the same bytes from the same `request.xax` (WSL 2). Identities are in
`seed.json` (retired by ADR-410; see git before `01276a8`). The section below describes the ledger 0031 seed and how to build it; its seed identity is
historical.

# Current Windows seed — one request for both hosts, ledger 0031, 2026-11-14

The Windows seed is now built from the **same request store as the Linux seed** (`../seed/xax_compiler_request.xax`)
and a small Windows hosting step. BBC's store is no longer part of it (ADR-402). `xaxc-windows-x86_64.exe`: 31,993,856
bytes, SHA-256 `b9a1ba463001559caa26efc68a275cf8694be7cecb419a29dd361b40735225eb`; identities in `seed.json` (retired by ADR-410; see git before `01276a8`),
the runs in [windows_selfhost_20261114_evidence.json](../../benchmarks/windows_selfhost_20261114_evidence.json).

## Building it on Windows

```text
xaxc-windows-x86_64.exe edit ..\seed\xax_compiler_request.xax hosting.batch hosted.xax
xaxc-windows-x86_64.exe verify hosted.xax hosted.diag
xaxc-windows-x86_64.exe edit hosted.xax pe_target.edit request.xax
xaxc-windows-x86_64.exe verify request.xax request.diag
xaxc-windows-x86_64.exe resolve request.xax snapshot.xax
xaxc-windows-x86_64.exe build snapshot.xax xaxc.exe xaxc.provenance
```

`xaxc.exe` must equal the seed byte for byte. On Windows 11 the build takes about 11 minutes; no Python, WSL or Wine
takes part. The Linux seed cross-builds the same bytes from `request.xax` (`resolve`, `build`).

## What the hosting step is

Main is shared: after ledgers 0030 and 0031 its memory calls are `xax-host-v1` and its file and exit calls are host
functions (`host_open`, `host_read`, `host_write`, `host_close`, `host_exit`). `hosting.batch` is a native batch on the
request:
- the Windows declarations and types the layer needs (`define`'s `object` form): msvcrt `_wopen`, `_read`, `_write`,
  `_close`, `__wgetmainargs`, `memcpy`; kernel32 `ExitProcess`, `AddVectoredExceptionHandler`, `VirtualAlloc`,
  `VirtualFree`, `VirtualQuery`, `RtlMoveMemory`, `GetLastError`, `SetLastError`, `MultiByteToWideChar`,
  `WideCharToMultiByte`;
- the Windows bodies of the host functions (`@w_open`, `@w_read`, `@w_write`, `@w_close`, `@w_exit`), the argument
  adapters (`@w_argc`, `@w_argcopy`) and the view-commit handler (`@w_handler`), from BBC's views of them (their CIDs
  are unchanged since BBC's port);
- `@w_main`: main's view with its host function calls made calls of the Windows bodies and its three startup reads
  (`argc`, `arg_copy`, which only a Linux process entry may make) made calls of the argument adapters;
- `@XAXC`, the process entry: it registers the handler, commits and releases one page (it holds the `VirtualFree`
  declaration, through which `xax-host-v1` `free` is imported, ADR-400), calls `@w_main` and returns its results.
  `replace` makes it the module's entry.

`pe_target.edit` is an `XAXEDIT1` record (two `REPLACE_REFERENCE` operations, one supplied object): the module's and
the build request's target become `x86_64-windows-pe-v1` with the growable accesses.

**Handles.** Both files bind the request's root. After a production ledger transaction write them again from `xaxc
edit <request> <selector>`: the root line, main's handle, and the five host functions' handles in `@w_main`.

The sections below describe earlier seeds and are historical.

# Current Windows seed — ledger 0029, 2026-11-14

Ledger 0029 adds the portable host memory ABI `xax-host-v1` (ADR-400). The seed is cut from `bbc_request.xax`
rebuilt with `rebuild.sh` from the 0029 driver batch, with `xaxc_entry_request.batch` written for its root
`93a7fc42…` (entry `F547`, view-commit handler `F1005`, command-line entry `F1002`; `bbc.xax`, root `9e01697c…`, has
the same handles). On Windows 11 the ledger 0028 seed built generation 1, which built generation 2, which built
generation 3: all three are byte-identical, 31,993,856 bytes, SHA-256
`4308ea905aad7f8c8e42299953a2e7e1480eb75e4b0949f44cf1878378bd7c72` (the driver does not call the new ABI yet, so
its code is unchanged and generation 1 is already the fixed point). Identities are in `seed.json` (retired by ADR-410; see git before `01276a8`). The
section below describes the ledger 0028 seed and is historical.

# Current Windows seed — 2026-11-13

Ledger 0028 adds native rebuilding of unsigned resolved snapshots after edits. The current seed is 31973888 bytes, SHA-256 `9779c7938b092b6a1b64bd97ff4950a0e5858f43e0f95040e5ea0d33c2319cd0`. Its exact source and build identities are in `seed.json` (retired by ADR-410; see git before `01276a8`). Native Windows generation 1 equals generation 2; see [the new fixed-point record](../../benchmarks/windows_selfhost_20261113_evidence.json) and [mutation acceptance](../../benchmarks/snapshot_mutation_20261113_evidence.json). The Linux seed is also rotated to ledger 0028 and has two identical native generations.

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
