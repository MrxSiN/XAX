# AI authoring baseline corpus (ADR-427)

This corpus measures what it costs an AI agent to change an XAX program before and after the authoring features of
ADR-424, ADR-425 and ADR-428. ADR-427 owns the method; this file owns the tasks, their starting states, their checks and
the run rules. It was frozen on 2026-11-25, before any measured run. A change to a task, its start or its check makes
a new corpus version (`v2`), never an edit of `v1`.

Corpus version: `v1`.

## Contents

- [Tasks](#tasks)
- [Held-out tasks](#held-out-tasks)
- [Rejection cases](#rejection-cases)
- [Arms](#arms)
- [Run rules](#run-rules)
- [Recorded fields](#recorded-fields)
- [Status](#status)

## Tasks

Each task starts from a clean checkout of the given commit. A ledger start means `evolve.sh replay` of the chain up to
the named ledger line. The task text given to the agent is the "Task" column and nothing else. The reference solution
is the named commit or ledger record. The agent never sees it: its workspace is cut from the start commit.

| ID | Task | Start | Check (pass = all of it) | Reference |
|---|---|---|---|---|
| B1 | Make the status tool build and run on Windows with the Windows seed, giving the same documents as on Linux. | commit `954790b` | `compiler/tests/test_status_docs.py` passes on Windows and Linux | PR #179 |
| B2 | Make the ledger tool run on Windows. | commit `b1f9983` | `tests/test_xax_selfhost_evolution.py` passes on Windows | `c732866` |
| B3 | Make the request tool run on Windows. | commit `c732866` | `evolve.sh check` passes on Windows | `fdafb1f` |
| B4 | Make the release (rotate) tool run on Windows. | commit `fdafb1f` | `tests/test_rotate_tool.py` passes on Windows | `342fa63` (rotate part) |
| B5 | Make the evidence tool run on Windows. | commit `fdafb1f` | `tests/test_evidence_v2.py` passes on Windows | `342fa63` (evidence part) |
| B6 | Signed compares of `bits<8>` and `bits<16>` operands in registers give wrong results on x86-64; fix the general backend. | ledger line 145's start (driver blob `2189c5cb…`) | `tests/test_x86_64_narrow_signed_compare.py` passes | ledger `0024-sign-correct-register-compares*` |
| B7 | The legacy Wasm32 profile emits an invalid module for a `bits<64>` checked offset; make it reject the case. | ledger start of `0042-legacy-wasm-offset-bits` (driver blob `fb10f5e7…`) | `tests/test_xax_oi52_r2.py` passes | that ledger record |
| B8 | Add the xax-host-v1 file functions to the driver. | ledger line 169's start (driver blob `d51c9519…`) | `tests/test_xax_host_abi.py` passes | ledger `0031-host-functions*` |
| B9 | In the driver store, which functions does the x86-64 backend entry reach, and which of them hold the capacity word's address 29360298? | release/0043 driver | the answer equals the key computed over `StoreReader` at the start commit | none (a query) |
| B10 | `xaxc edit` accepts a snapshot with a missing reference; make it reject with a diagnostic. | ledger line 256's start on `release/0043` (driver blob `052e34a3…`) | `tests/test_xax_selfhost_verify_exact.py` passes | ledger `0043-snapshot-missing-reference` |

## Held-out tasks

No solution to these exists in the repository. They run on the fixture stores in `heldout/`, whose roots are recorded
here when the stores are committed, before any measured run. Each check runs the built program and compares it with the
reference executor on fixed inputs.

| ID | Task | Check |
|---|---|---|
| H1 | Add a loop that copies `n` bytes from one view to another, threading the memory token through the loop. | equal output for n = 0, 1, 7, 4,096 |
| H2 | Add a branch that writes to a view on one side only; both sides must return the token. | equal output on both branches |
| H3 | Change one function's arithmetic (an off-by-one in a bound) without touching its callers. | equal output; no caller's CID changes |
| H4 | Which functions would change if function `crc_step` changed its signature? | the answer equals the key |
| H5 | Repair a batch from its rejection record alone (the record and batch are given). | the repaired batch verifies; equal output |

## Rejection cases

These are feature tests for ADR-425 and ADR-426, not measured tasks. They are listed so the measured runs and the
feature tests use the same cases: a token read after it is consumed; a variable undefined on one path; a derived
pointer passed to a call; a branch argument of the wrong type; a function over a target capacity limit.

## Arms

Each arm records the compiler commit it ran on, so compiler changes (release 0044, ADR-429's extractions) are not
counted as authoring gains.

1. Explicit batches (the baseline, today's interface).
2. The baseline plus names (ADR-428).
3. The baseline plus queries (ADR-424).
4. The baseline plus variables (ADR-425).
5. All of them.
6. All of them through XAX-MCP.

Models: the Claude model and client used for XAX development (required). Where available: a smaller coding model, a
GPT coding model, and a model from another family. Each model keeps one configuration across all arms.

## Run rules

- Every run is a fresh session with no earlier conversation, in its own checkout of the start commit.
- The task text is the table's text. The agent may read the repository, as any agent would. It may not read the
  reference commit, this file's "Reference" column, or other runs' results.
- At least three runs per task, arm and model. A failed or abandoned run is recorded, never dropped or rerun in its
  place.
- The check is run by the person or harness, not by the measured agent; the agent cannot change it.
- A run ends when the agent says it is done, or after 4 hours or 2 million input tokens, whichever comes first.

## Recorded fields

One line per run in `results-v1.csv`:

```text
task,arm,model,client,client_version,reasoning,compiler_commit,run,started,wall_seconds,build_seconds,verify_seconds,
input_tokens,output_tokens,cached_tokens,gross_tokens,overhead_tokens,adjusted_tokens,billable,tool_calls,
attempts,rejected_by_class,repair_rounds,batch_lines,completed,correct,cost
```

A field a client does not report is written as `unavailable`, never estimated. `overhead_tokens` follows OI-46's
method, and `adjusted_tokens` is `gross_tokens - overhead_tokens`. Both are reported, never the adjusted one alone.

## Status

| Item | Status |
|---|---|
| Tasks and checks | frozen (`v1`, 2026-11-25) |
| Held-out fixture stores | committed 2026-11-28 ([`heldout/`](heldout/README.md): roots `d17067a2…` H1, `9e3feb7c…` H2, `8fa2a94e…` H3-H5) |
| B9 and H4 answer keys | committed 2026-11-28 (`heldout/keys/`, hidden from measured runs) |
| Measured runs | NOT RUN |
