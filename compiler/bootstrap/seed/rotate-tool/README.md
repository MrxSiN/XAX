# The release state as an XAX program

RFC `docs/proposals/build-bootstrap-rotation-rfc.md` §3, §8 and §9, phase 6. `xax_rotate.xax` is a Linux x86-64
process, an XAX build request store. `../rotate.sh` builds it with the pinned seed and runs it.

```text
xax_rotate state <bootstrap>             the release state, one line each: ledger <head record>, validated <n|none>,
                                         candidate <n|none>, any blocked line, pending <target> per unconfirmed host,
                                         then profile <development|candidate|released> or unmet <blocked|confirm>;
                                         exit 1 with an unmet line
xax_rotate tests <bootstrap>             the tests POLICY selects: for development, the rest of every `test` line
                                         whose store a transaction since the last validated release changed (or *);
                                         `all` for a candidate; nothing when released or blocked
xax_rotate pin <bootstrap> <target>      <sha256>:<size> of that host's seed in the last validated release; exit 1
                                         when there is none
xax_rotate id <file>                     <sha256>:<size> of the file
xax_rotate valid <levels>                exit 0 when an `xax_evidence levels` output is B0-B6 1, rotated 1, python 0
```

It reads `<bootstrap>/RELEASES`, `<bootstrap>/evolution/LEDGER` and `<bootstrap>/POLICY` into one view (at 0,
256 KiB and 768 KiB).

- The ledger head is the record of the last transaction line (not a comment, `baseline` or `derived` line).
- The validated release is the last `validated` line, and its candidate the last `candidate` line before it. A
  newer candidate is the last `candidate` line after it, and a `blocked` line after it blocks.
- A candidate counts only while its `ledger=` is the head; otherwise the profile is development, so a transaction
  after a candidate needs a new one.
- A host is confirmed when a `confirmed <n> <target> <sha256>` line after the candidate names the candidate's hash
  for that target.

Limits: RELEASES under 256 KiB, LEDGER under 512 KiB, POLICY under 240 KiB; a key word is matched by its first
eight bytes (`validate`, `candidat`, `confirme`, `blocked `, `host `, `test `). A missing file reads as empty.

How it was made, without a generator of its logic:

- `rotate.batch` is a native batch (docs/09_AI_PROTOCOL.md §16) on `../../evolution/ledger-tool/seed.xax`. Its result
  is `xax_rotate.xax`, and `xaxc verify` accepts it.
- It copies the ledger tool's `@fend`, `@nextline` and `@memeq`, and the evidence program's SHA-256 (`@s256` and its
  parts), `@put`, `@putw`, `@copyc`, `@fld` and `@upto` (`../../evidence/README.md`).
- Change it by a further batch on `xax_rotate.xax`, then `xaxc verify`.

## `rotate.sh`

`../rotate.sh` keeps only the loops that run `xaxc`, the tools and the repository's scripts:

- `build <n>`: derive the request (`request.sh`, which must equal the committed one), rebuild from the pinned seed
  to the first fixed point (at most three generations), cross-build the Windows seed with the fixed-point compiler
  from `generate.sh`'s request, install both seeds and append the `candidate` line. `build --dry` compares the
  rebuilt seeds with the pins instead and writes nothing.
- `confirm <target>`: the candidate seed of that host rebuilds itself, and its rebuild rebuilds it again; both must
  be the seed byte for byte. It writes `../../evidence/confirm/<n>-<target>.txt` and appends the `confirmed` line.
  The Windows seed runs natively, through WSL interop with `wslpath -w` paths when run in WSL; when it cannot run,
  the confirmation is NOT RUN and the script exits 1.
- `gate`: `state` must have no unmet line, `evolve.sh check` must pass, and the selected tests must pass.
- `validate <record>`: with a fully confirmed candidate, the V2 record's levels must all hold
  (`xax_evidence levels`, then `valid`); it appends `validated <n> evidence=<record sha256>`.

Until `rotate.sh` has made one release, `SEED_SHA256` (`src/xax_selfhost_seed.py`) and `../../windows/seed.json` stay
and must equal the pins (`tests/test_rotate_tool.py`); they are retired by the first release `rotate.sh` makes.

Checked on Linux x86-64 (WSL 2, the pinned seed `36e2b756…`), EXECUTED, 2026-11-16, at ledger 0035:

- `rotate.sh build --dry` rebuilt both pinned seeds byte for byte in 9 min 42 s: generation 1 equals the seed, and
  the cross-built Windows seed is `ae43e32f…` (31,602,176 bytes).
- On a scratch copy with a test candidate naming the current pins, `confirm x86_64-windows-pe-v1` ran the Windows
  seed as a Windows process through WSL interop. It rebuilt itself from the generated request (`67f7cfa4…`) and
  rebuilt itself again, both byte for byte, in 9 min 35 s. `confirm x86_64-linux-elf-exec-v1` did the same in
  6 min 17 s. `state` then moved from `unmet confirm` to `profile candidate`. A first attempt, before `rotate.sh`
  made an executable copy, showed the NOT RUN path: exit 1 and no `confirmed` line.
- `rotate.sh gate` on the committed tree: profile released, `evolve.sh check` passes, and no tests are selected.
