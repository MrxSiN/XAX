# The full self-hosting evidence, V2, as an XAX program

RFC `docs/proposals/build-bootstrap-rotation-rfc.md` §4, phase 3. `sh run.sh <out> [quick]` runs the production
compiler's generations and its frozen corpus, and writes the record `<out>/record`. Every file it hashed stays under
`<out>`, so an independent checker can hash it again.

## The frozen corpus (policy files)

- `CORPUS` is the corpus of the V1 runner (`bench_full_selfhost.corpus()`, 198 cases) plus B6's structural probe, one
  line per case: `<kind> <command> <expect> <n inputs> <input>... <n outputs> <n files> <file>... <name>`.
  - A path is under `compiler/bootstrap/`. The committed stores and `tests/fixtures/declared_rejections` are read by
    path; the 132 inputs the reference and the test helpers generate are in `corpus/`, each named by its SHA-256.
    `=zero:<n>` is n zero bytes.
  - `<expect>` is `-` (none), `image:<SHA-256 of each output>`, `rejected:<code>:<rule>`, or
    `diag:<code>:<rule>:<SHA-256 of the record>`: the bootstrap verifier's exact diagnostic, as the rejection record
    the pinned seed wrote, which the reference decoded to that diagnostic.
  - The probe (`edit: a structural probe (B6)`) applies the V1 probe transaction to the status program, a frozen
    store, instead of to the committed driver. Its expectation is the reference engine's store, which the reference
    verifier accepts.
- `SNAPSHOTS` holds `<request SHA-256> <snapshot SHA-256>`: the reference resolver's snapshot of a compiler request
  (B2). A request with no line has no reference, and B2 does not hold for it.

They change only through the reference oracle's command, in a commit that changes nothing else (RFC §9). The export
of 2026-11-16 ran on `main` `95647a0` in WSL (Python 3.12.3), from `compiler/`:

```text
PYTHONHASHSEED=0 PYTHONPATH=src:reference:tests:.:.. python3 export_corpus.py <dir>
```

with the scratch script recorded in the PR that added these files. Two exports agreed except the three libxposed
module cases, whose branding archive carries a timestamp; freezing removes that difference.

## The program

`xax_evidence.xax` is an XAX build request store with the general driver's entry (since 2026-11-25, `driver.batch`), so
`../windows/generator/generate.sh` hosts it (`xax_evidence_windows.xax`, which the Windows seed builds where the
status and release scripts run on Windows). Every command writes its text to an output file, its last argument
(`run.sh`'s `ev` prints it back); `plan`'s zero file is still `<dir>/zero`:

```text
xax_evidence sha <file> <out>            the file's SHA-256 in hexadecimal and a newline; "-" when it cannot be read
xax_evidence elf <file> <out>            1 when the ELF file has a PT_INTERP program header, else 0; "-" when unreadable
xax_evidence diag <file> <out>           "<code> <rule>" from xaxc's text rendering of a rejection record (the values
                                         of its `code` and `rule` lines, "-" for a missing one); "- -" when unreadable
xax_evidence plan <corpus> <dir> <out>   one line per case: "<index> <command> <arguments>", with outputs
                                         <dir>/<index>.<k>; it writes <dir>/zero when a case needs zero bytes;
                                         exit 3 when the corpus cannot be read
xax_evidence levels <record> <corpus> <snapshots> <seed> <out>
                                         the B levels of a V2 record (below), one "<name> 0|1" line each: B0 to B6,
                                         rotated, python; <seed> is the pinned seed file, whose SHA-256 is compared
                                         with the record's; exit 3 when the record cannot be read
```

Limits: a hashed file under 256 MiB, a corpus or rendered record under 1 MiB, a path under 4 KiB; `plan` output under
64 MiB and a zero input under 128 MiB. For `levels`: a record under 512 KiB, a corpus under 448 KiB and snapshots
under 64 KiB, at most 3 generations, 4 contexts and 256 cases. A record outside these limits is not one the runner
writes, and its levels are undefined.

How it was made, without a generator of its logic:

- `evidence.batch` is a native batch (docs/09_AI_PROTOCOL.md §16) on `../evolution/ledger-tool/seed.xax`, the ledger
  tool's one-function seed. Its result is `xax_evidence.xax`, and `xaxc verify` accepts it.
- It uses the ledger tool's types and declarations (`ptr<bits8>` views) and copies its `@fend` and `@nextline`.
- SHA-256 (FIPS 180-4) is `@s256`: `@mb` gives the padded message's bytes, `@s256w` the message schedule and
  `@s256r` the 64 rounds; the digest is at scratch bytes 2048–2079 as `@hex64` prints it.
- Output text goes through a cursor word in memory (`@put`, `@putd`), as in the Windows generator.
- `levels` reads the record, the corpus and the snapshots into one view (at 0, 512 KiB and 960 KiB, through
  `address.offset`). `@parse` and `@pline` keep the record's facts in scratch cells (`@gc`, `@sc`) and an outcome
  table, `@cindex` indexes the corpus, and `@gens`, `@cases` (with `@exact1` and `@agree`) and `@levels` derive the
  levels.
- Change it by a further batch on `xax_evidence.xax` (`xaxc edit` lists and shows its functions), then `xaxc verify`.
- `driver.batch` (2026-11-25) replaces `main` (F35) with the general driver's entry and host functions and keeps every
  call. EXECUTED in WSL 2 with the release 0042 seed: `sha`, `elf`, `diag` (including unreadable files), `plan` (its
  199 lines and its 68,157,440-byte zero file) and `levels` (the 0042 record, with the pinned and another seed) equal
  the previous program's output and exit status byte for byte. On Windows 11 the Windows build (48,128 bytes) gives the
  same `sha` and `levels` (B0-B6 1 for release 0042).

## The record

`run.sh` writes one fact per line. Exit statuses are the processes' own (0 image, 1 rejected, 2 declined, 3 failed).

```text
xax-full-selfhost-evidence-v2
ledger <LEDGER blob>
corpus <SHA-256 of CORPUS>
seed <SHA-256> <interpreter 0|1>
request <SHA-256 of seed/xax_compiler_request.xax>
generation <n> <producer SHA-256> <resolve status> <snapshot SHA-256> <build status> <artifact SHA-256> <provenance SHA-256> <interpreter|->
fixedpoint <n|none>                      the first n with C(n) = C(n-1); at most three generations run
empty <k> <resolve status> <build status> <artifact SHA-256>       the seed with an empty environment, twice
context <C<n>> <compiler SHA-256>        one per distinct compiler: the seed and each generation before the fixed point
outcome <context> <case> <status> <output 0> <output 1> <code> <rule>
repeat <context>-r <case> ...            the first ten cases again (the flakiness probe)
replay <status> <evolve.sh replay's last line>    C1 replays the ledger; "replay not-run" with quick
end
```

A missing output or field is `-`. A record without `end` is unfinished.

## The levels of a V2 record

`levels` computes every level from the record, the corpus's expectations and the snapshot list; nothing is read
from the record as a claim. With E = the record has `end`, and C1 = generation 1's artifact:

- **B2**: E, at least one generation, and every generation resolved and built (status 0), was produced by the seed
  (generation 1) or by the previous generation's artifact, and wrote the reference snapshot of the record's request.
- **B0**: E, generation 1 resolved and built, and either generation 2 resolved or C1 is the seed (fixed point 1).
- **B1**: B2, and C1's context reproduces every `diag` expectation (status 1 and the expected record digest).
- **B3**: B2; the contexts agree (each has every case, all contexts' outcomes are equal, and every repeat equals
  its context's outcome); C1's context meets every `image` and `rejected` expectation (the probe's is B6's); no `diag` case is rejected
  with a diagnostic other than the bootstrap's and other than `XAX.DRIVER.VERIFY`; the corpus has positive and
  negative cases.
- **B4**: B2 and a fixed point F (the first generation whose artifact is its producer), with every later generation
  equal to it. A fixed point that is not the seed still counts during development; `rotated` says whether it is.
- **B5**: B2, and no executable (the seed and every generation) has an ELF interpreter.
- **B6**: B5, the replay exited 0 with `replayed N of N` for N ≥ 1, and C1's context meets the probe's expectation.
- **python** (the seed requires Python): not (the record's seed is the pinned seed file, has no interpreter, and
  both empty-environment runs resolved and built the last generation's artifact).

The reference evaluator `compiler/reference/xax_selfhost.py` computes the same levels from a V2 record and the V1
record. Since ADR-433 (3) the V1 record (`bench_full_selfhost`) holds only the pinned seed's corpus outcomes against the
live reference, so the evaluator reads the generations, the fixed point, the contexts, the replay and the probe from
the V2 record. `tests/test_evidence_v2.py` writes V2 records from the committed V1 record and the latest validated
release's generation, fixed point and replay lines, mutates facts of either, and requires `levels` to give the
reference's levels on each.

Checked on Linux x86-64 (WSL 2, the pinned seed `36e2b756…`), EXECUTED, 2026-11-16:

- `sha` equals `sha256sum` on empty, 3-, 55- and 56-byte inputs, the 31,549,147-byte seed and the 62 MB driver
  (0.34 s); `elf` gives 0 for the seed and 1 for `/bin/ls`; `plan` on `CORPUS` equals an awk reading of it byte for
  byte, and its zero file is 68,157,440 zero bytes.
- `sh run.sh <out> quick` on `main` `95647a0` plus this directory took 10 min 50 s: generation 1 equals the seed
  (fixed point 1), its snapshot is the reference's, both empty-environment rebuilds give the seed, and the 198 cases,
  the probe and the ten repeats ran. `levels` gives B0–B5 1, B6 0 (the replay was not run), rotated 1, python 0.
