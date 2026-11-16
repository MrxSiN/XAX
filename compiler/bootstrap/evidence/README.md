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

`xax_evidence.xax` is a Linux x86-64 process, an XAX build request store:

```text
xax_evidence sha <file>                  the file's SHA-256 in hexadecimal and a newline; "-" when it cannot be read
xax_evidence elf <file>                  1 when the ELF file has a PT_INTERP program header, else 0; "-" when unreadable
xax_evidence diag <file>                 "<code> <rule>" from xaxc's text rendering of a rejection record (the values
                                         of its `code` and `rule` lines, "-" for a missing one); "- -" when unreadable
xax_evidence plan <corpus> <dir>         one line per case: "<index> <command> <arguments>", with outputs
                                         <dir>/<index>.<k>; it writes <dir>/zero when a case needs zero bytes;
                                         exit 3 when the corpus cannot be read
```

Limits: a hashed file under 256 MiB, a corpus or rendered record under 1 MiB, a path under 4 KiB; `plan` output under
64 MiB and a zero input under 128 MiB.

How it was made, without a generator of its logic:

- `evidence.batch` is a native batch (docs/09_AI_PROTOCOL.md §16) on `../evolution/ledger-tool/seed.xax`, the ledger
  tool's one-function seed. Its result is `xax_evidence.xax`, and `xaxc verify` accepts it.
- It uses the ledger tool's types and declarations (`ptr<bits8>` views) and copies its `@fend` and `@nextline`.
- SHA-256 (FIPS 180-4) is `@s256`: `@mb` gives the padded message's bytes, `@s256w` the message schedule and
  `@s256r` the 64 rounds; the digest is at scratch bytes 2048–2079 as `@hex64` prints it.
- Output text goes through a cursor word in memory (`@put`, `@putd`), as in the Windows generator.
- Change it by a further batch on `xax_evidence.xax` (`xaxc edit` lists and shows its functions), then `xaxc verify`.

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
