# Tiny C vs XAX Codex benchmark

This exploratory benchmark asks one question: can the same Codex Desktop model complete small program edits in XAX with fewer model tokens or turns than in C?

It has five paired tasks:

| ID | Semantic edit |
|---|---|
| `task-01` | Change one shared constant used twice |
| `task-02` | Change an arithmetic operation |
| `task-03` | Rewire one operand to another producer |
| `task-04` | Delete an unused constant |
| `task-05` | Move a pure constant before another |

The C arm edits a tiny C file. The XAX arm edits one transaction against a compact view produced by the real `xax_workspace.Workspace`; its checker commits that transaction through the core XAX verifier. Each pair starts from the same one-function, unsigned 32-bit program and has the same exact prompt and target structure.

## Run a pair

Use the same Codex Desktop product, model, reasoning setting, and token-counting rule for both arms. Start a fresh chat for every arm. From `compiler/`, with `PYTHONPATH=src` if the package is not installed:

```text
$env:PYTHONPATH='src'
python -m benchmarks.ai_native prepare task-01 C
python -m benchmarks.ai_native prepare task-01 XAX
```

For the C trial:

1. Open `benchmarks/ai_native/runs/task-01-c` as the Codex workspace.
2. Start a fresh chat and paste only the prompt in `TASK.md`.
3. Let Codex edit `program.c`. Questions, corrections, and retries remain in that chat and count as turns and tokens.
4. Check it from `compiler/`:

```text
python -m benchmarks.ai_native check task-01 C benchmarks/ai_native/runs/task-01-c
```

For XAX, repeat with a fresh chat and `runs/task-01-xax`. The pasted prompt points Codex at one task-local interface:

```text
python xax.py inspect
python xax.py mutate set-constant N0 7
python xax.py test
```

`inspect` returns only the function's local semantic neighborhood with `P0`/`N0` handles. `mutate` also accepts `set-op`, `replace-operand`, `delete`, and `move`; it writes the verifier transaction without exposing repository internals. `verify` checks any candidate without committing, while `test` also requires the exact task target. Failures are compact JSON arrays containing only code, entity, expected, actual, and repair handles.

The external checker remains available from `compiler/`:

```text
python -m benchmarks.ai_native check task-01 XAX benchmarks/ai_native/runs/task-01-xax
```

Both checkers print only `PASS` or `FAIL` plus a short reason. The C checker requires the requested structure while ignoring formatting and comments. The XAX checker requires a verifier-accepted transaction whose canonical root is the exact target root.

## Record and summarize

Codex Desktop may not show token counts in the UI, but it records exact session usage locally. After checking a trial, import the newest session whose working directory is that trial workspace. Count every model response, including questions and failed attempts.

```text
python -m benchmarks.ai_native record-session task-01 C PASS benchmarks/ai_native/runs/task-01-c --turns 1
python -m benchmarks.ai_native record-session task-01 XAX PASS benchmarks/ai_native/runs/task-01-xax --turns 1
python -m benchmarks.ai_native summary
```

`record-session` reads the final `total_token_usage` event from `%USERPROFILE%\.codex\sessions`; it does not estimate or retokenize text. The manual `record` command remains available for clients that expose counts elsewhere.

Results append to the single human-readable `results.csv`. Duplicate task/arm/trial rows are rejected so a failed attempt cannot be silently replaced. Run the other four pairs the same way. A simple alternating arm order (`C, XAX, XAX, C, ...`) is enough if order effects are a concern.

The summary reports every task plus passes, total tokens, median tokens per recorded task, and turns for C and XAX. With five tasks, inspect the raw rows; no significance test is implied.

## Qualifying fixed-setting run (2026-10-06)

`jvm-r5-results.csv` is the first run with explicit fixed model/reasoning metadata and balanced arm order. Ten fresh Codex CLI 0.160.0 sessions used `gpt-5.6-luna` with low reasoning. All five C and five XAX cells passed in one turn with no repair. C used 325,282 total tokens; XAX used 264,535 (0.813×, 18.675% fewer). `jvm-r5-evidence.json` records the aggregate, session IDs, CSV digest, protocol, and limits. The evidence is bounded to these five local edits; no significance or untested-task-class claim is made.

## Direct semantic workflow (2026-10-06)

`XAX-DIRECT` supplies the already-bounded local semantic view in the task and accepts one atomic `python xax.py apply CMD` operation. `apply` accepts either split arguments or one quoted command payload, then writes, verifies, commits, and exact-target-checks the transaction. The paired C arm now has a task-local `python c.py` exact-target checker.

`jvm-r5-optimized-results.csv` records the controlled fixed-profile comparison. All ten cells passed in one turn with no repair. C used 197,252 total tokens; XAX-DIRECT used 98,432 (0.4990×, **50.098% fewer**). `jvm-r5-optimized-evidence.json` records the client profile, workflow distinction, session IDs, CSV digest, aggregate, and limits. This is five-edit workflow evidence, not complete JVM R5 evidence.

## Second confirmation run

Run the same tasks from `runs-2/` in the opposite arm order—XAX first, then C—and save them separately:

```text
python -m benchmarks.ai_native record-session task-01 XAX PASS benchmarks/ai_native/runs-2/task-01-xax --turns 1 --results benchmarks/ai_native/results-run-2.csv
python -m benchmarks.ai_native record-session task-01 C PASS benchmarks/ai_native/runs-2/task-01-c --turns 1 --results benchmarks/ai_native/results-run-2.csv
python -m benchmarks.ai_native summary --results benchmarks/ai_native/results-run-2.csv
```

## OI-01 transport candidates

Six versioned (`X1`) fallback transport candidates cross two handle namespaces with three packet framings. None is canonical; all decode to the same workspace `Transaction` and are non-source tooling.

| Handles | Example view line | Framing | Example packet |
|---|---|---|---|
| `typed` (current) | `N1 add.wrap P0 N0` | `line` | `X1 R0.0` / `set-constant N0 7` |
| `unified` | `2 add.wrap 0 1` | `pipe` | `X1\|R0.0;C\|1\|7` |
| | | `json` | `["X1","R0.0",["C","N0",7]]` |

Offline tokenizer/byte accounting over the five reference edits (requires `tiktoken`; no model is called):

```text
python -m benchmarks.ai_native transport
```

This rewrites `transport-oi01.json` with every raw view, packet, byte count, and `cl100k_base`/`o200k_base` token count. Model trials for a candidate use the same runbook with an arm such as `XAX-UNIFIED-PIPE`: `prepare task-01 XAX-UNIFIED-PIPE`, have Codex edit `packet.txt`, then `check`/`record-session` with that arm into a separate `--results` CSV.

### OI-01 closure corpus extension

The benchmark corpus additionally contains only the six families missing from the earlier five-edit run:

| ID | Family | Exact benchmark condition |
|---|---|---|
| `task-06` | program creation | insert a new semantic constant into a minimal function scaffold and connect its transaction-local result |
| `task-07` | control-flow edit | replace one branch-edge argument with an exact disconnect/connect pair |
| `task-08` | type repair | start from a candidate that fails `u8`/`u16` operand verification, then repair to the requested `u8` value |
| `task-09` | resource/effect repair | start from an incomplete resource swap that violates linear resource use, then repair it without changing the effect chain |
| `task-10` | stale-root recovery | start from `R0.0` after an unrelated committed update advances the workspace to `R0.1`, then refresh and retry successfully |
| `task-11` | optimization | delete one dead semantic node under an exact target-root checker |

All six still use the same `X1` typed/unified × line/pipe/json arms. `insert-constant`, `disconnect-edge`, and `connect-edge` decode directly to existing workspace mutations; canonical serialization is unchanged. The creation task uses `@ID` only for the existing transaction-local insertion result and does not create a persistent handle namespace.

Generate the deterministic corpus/checker sidecar without a tokenizer or model:

```text
python -m benchmarks.ai_native corpus
```

`corpus-oi01.json` contains the exact local view, prefilled packet, target packet, semantic-entity count, byte counts, and exact target root for all 66 task/arm cells (11 tasks × 6 arms). The type/resource/stale prefilled candidates are expected to fail before repair; every target packet must commit to its exact target root.

For model evidence, use a fresh model session for every trial and a unique workspace directory. Run at least three trials per tested cell, keep model and reasoning settings fixed, and balance or randomize arm order. Repeated rows are keyed by `task_id`, `arm`, and `trial`:

```text
python -m benchmarks.ai_native record-session task-08 XAX-UNIFIED-LINE PASS <workspace> --trial 1 --model <exact-model> --reasoning <fixed-setting> --turns 2 --results benchmarks/ai_native/results-oi01.csv
python -m benchmarks.ai_native oi01-summary --results benchmarks/ai_native/results-oi01.csv
```

For transport arms, `record-session` records exact client input/output/total token usage plus failed `verify`/`test` attempts, packet-repair count from `trace.jsonl`, turns, view bytes, final packet bytes, semantic entities exposed, and the exact final root. It does not retokenize model traffic. The summary groups by task family and arm so completion/reliability can be considered before token and byte cost.

This corpus/tooling extension contains no new OpenAI/Codex model run. Do not use offline tokenizer counts as a substitute for model usage.

### Claude Code trial run (2026-10-01)

`runs-claude/` holds all 30 candidate trials (5 tasks × 6 arms), each with its final `packet.txt` and an objective `trace.jsonl` of every `xax.py` invocation, exit code, and packet at that moment. `results-claude.csv` is the flat record. Each trial was one fresh Claude Code `general-purpose` subagent (`claude-opus-5-5`) given exactly this preamble followed by the quoted `TASK.md` prompt:

```text
You are one trial in a controlled benchmark. Work only in the directory <trial>. Run commands only as `python xax.py ...` from that directory, and change only `packet.txt` there. Do not read, search, or list any other file or directory.

<TASK.md prompt>

When `python xax.py test` prints PASS, reply with only PASS. If you cannot reach PASS, reply with only FAIL.
```

`total_tokens` is the harness-reported `subagent_tokens` for that trial (Claude tokenizer; an input/output split was not exposed). `failed_checks` counts non-zero `verify`/`test` exits in the trace. The task-02 unified/pipe trial ran alone as a probe before the parallel batch.

### Observed OI-01 result

All 30 trials reached `PASS`. The five-task harness-reported token totals were 278,750 (`typed`/`line`), 280,478 (`typed`/`pipe`), 280,648 (`typed`/`json`), 278,301 (`unified`/`line`), 281,968 (`unified`/`pipe`, including the standalone probe), and 280,587 (`unified`/`json`). These differences are about 1.3% and are not treated as a token-efficiency ranking because each trial carried roughly 55.6k tokens of fixed harness context.

Reliability separated the framings more clearly: `line` produced 0 failed `verify`/`test` checks across 10 trials, `pipe` produced 2 across 10 trials, and `json` produced 14 across 10 trials. Nine of the ten JSON trials had at least one failed check, usually because the model emitted the required flat packet as separate or nested arrays. By handle namespace, typed arms had 9 failed checks and unified arms had 7; all were attributable to framing rather than handle confusion.

Offline tokenizer accounting still favors unified handles and `pipe`: unified views save 15 tokens over typed views across the original five tasks under both `cl100k_base` and `o200k_base`, and unified/pipe has the smallest combined view+packet total at 237 tokens under either encoding. The model trial does **not** select a canonical transport. The missing task families now have deterministic corpus/checker coverage, but no new model run is attached to that extension. `line` remains the observed reliability leader on the earlier Claude run, flat-array JSON is disfavored there, typed versus unified handles is unresolved, and OI-01 remains open pending repeated OpenAI/Codex-family trials, a smaller second-family confirmation if available, and tokenizer-native integration.

### JVM snapshot-bound follow-up (2026-10-07, ADR-186)

Direct mutation batches now use the normal `xax_local_protocol.LocalMutationSession` adapter. Quote the entire batch as one shell argument. No benchmark task identity or expected target is available to that adapter.

After non-token checks, from `compiler/` with `src` and `.` on `PYTHONPATH`, run:

```powershell
py -3.13 -m benchmarks.run_jvm_r5_ai --repetitions 3
```

The default output is `jvm-r5-bound-results.csv`, its `.evidence.json` summary, and fresh workspaces under `runs-jvm-r5-bound/`. Every attempt retains `model-events.jsonl` and its SHA-256; all completed-turn input/output tokens, including cached input, count. Retry costs accumulate within a task/arm/trial cell. The default sequential runner stops on a pre-inference client failure. Reinvocation resumes successful cells without repeating them and creates a fresh attempt for failures.

`--summarize-only` recomputes the gate without inference. No historical CSV is edited. A complete three-trial numeric gate is still subject to task-equivalence review; the inherited XAX creation scaffold currently prevents an unconditional R5 claim.

The exploratory `jvm-r5-local-*` profile remains archived with its exact source snapshot and every model attempt. The bound profile supplies role-to-handle facts already available as names in textual source, explains pre-batch handles and `@ID`, and strengthens creation probes to nine inputs. Filtered `--tasks`/`--arms` runs are preflights only; summaries still require the entire corpus. A `--stop-file` stops safely between cells.

### Current JVM host-applied response comparison (ADR-187–192)

After non-token checks, use `py -3.13 -m benchmarks.run_jvm_r5_response --repetitions 3`
from `compiler/`, with `src;.;..` on `PYTHONPATH` and Java/Kotlin tools available.
Default artifacts are `jvm-r5-response-v9-results.csv`, its `.evidence.json`,
and `runs-jvm-r5-response-v9/`. `--summarize-only` performs no inference.
`--tasks` and `--arms` are preflight filters; they never relax the full gate.

All arms return final requests which the host applies and checks. Java/Kotlin
read their named program and return an ordinary context patch. XAX returns a
snapshot-bound mutation batch, or an ordinary construction request when empty.
Creation starts empty in every arm. The conditional task executes both branches;
stale conflicts are real and require repair; the large fixture contains 160
actual helpers and its target/assertion functions. Abstract resource effects
are verified against their exact target, with no JVM execution claim.

Each attempt streams event files, records start/result markers and preserves
every response, diagnostic and token cost. Sources are copied and hashed in
`manifest.json`; resume refuses source/profile drift. Shared CLI flags disable
unrelated plugin/skill injection, and the common instruction context is saved
and hashed for every response. Unknown costs, unrecorded attempts or differing
instruction contexts block the gate. Create `runs-jvm-r5-response-v9/STOP` to
stop after the active cell; remove that file to resume. Never interrupt a model
and silently discard its usage.

The bound profile was interrupted before one final usage record. The first
response preflight had unequal injected skill catalogs. Response-v2 preserved
a failed operand-edit cell that motivated normal typed-field prefix elision
and collision-safe function projection. All these profiles remain historical
evidence, not rows to mix into the current source/client comparison. Numeric
success is scoped to this synthetic corpus and still requires review.

Response-v3's 11/15 XAX preflight motivated exact normal edge/type/signature
setters and dead-closure pruning. Response-v4 retained 137 attempts and 134/135
successes at a partial 0.501623 ratio; one Kotlin cell remained blocked by an
overly strict literal-conversion check. Its independent audit preserves the
raw costs and source hashes. Response-v5 accepts that spelling only after equal
compiled JVM instructions and behavioral checks, and rejects overload changes.
It measures normal compact aliases/help in a fresh profile. Graph context is
host-projected; textual edits inspect the named file, an explicit review limit.

Independently audit the current artifacts without inference:

```powershell
python -m benchmarks.audit_jvm_r5_response benchmarks/ai_native/jvm-r5-response-v9-results.csv benchmarks/ai_native/runs-jvm-r5-response-v9 --output benchmarks/ai_native/jvm-r5-response-v9-audit.json
```

Use `--archived` only to audit an older frozen snapshot after intentional live
source changes; its report still records the live drift. Current-run audits
check both live and copied sources.

### Transferred-host continuation (ADR-190)

The current runner defaults to response-v6. Response-v5 remains incomplete at
60/135 successful cells, partial ratio 0.5003204395, with an interrupted Java
creation turn whose final usage was not transferred. Its interruption record
and continuation audit preserve that blocker. No old row is imported.

Response-v6 declares uniform node result types once per function and pins
Python/JDK/Kotlin checker versions before model requests. Missing or broken
tools and version changes reject before inference. Use the pinned CLI on PATH
and JAVA_HOME, Java/javac/javap/kotlinc on PATH; run from compiler/ with
`PYTHONPATH=src;.;..`. All comparisons retain failed-response/attempt costs.
Audit jvm-r5-response-v6-results.csv against runs-jvm-r5-response-v6/ before
reporting a numeric gate. Numeric success still requires corpus review.

### Bound-field comparison (ADR-191)

Current defaults are response-v7. Ordinary clients may call session.bind(verb,
node) before inference and commit_bound(response) with only the remaining fields.
Kinds/targets are caller-selected, never replacement values. The adapter knows
no task identity or expected result; stale roots and alias drift reject.

Response-v6 is preserved as complete negative evidence: 142 attempts, all
135 cells successful, ratio 0.5002551375, and zero independent audit errors.
Response-v7 runs all Java/Kotlin/XAX cells fresh; no old row is imported. Its
manifest explicitly records the bound-target versus named-file context limit.

### Immutable scalar comparison (ADR-192)

Current defaults are response-v8. A binding cannot change kind or target while
a response is outstanding. Bound constant/arithmetic queries expose only the
selected node's old value/operation and width; operand, move and edge queries
keep their selected candidates. Ordinary exact commit and stale checks remain.
Response-v7 stopped between cells after 11 successes, with complete accounting
and a clean audit, before this guard and view change. No earlier row is imported.

## Matching bound commands and ordinary repair (2026-10-07, ADR-193)

Response-v8 stopped between cells at 71/135 successes in 74 attempts. All costs are known and its independent audit has zero errors. Field-only responses caused unnecessary format repairs. Response-v9 accepts ordinary commands only when kind and target match the immutable binding, uses ordinary movement batches, and switches rejected bound requests to ordinary full-batch repair. It starts all 135 cells fresh. Validation: 146 tests and 167 subtests passed.

## Response-v9 completed numeric gate (2026-10-07, ADR-194)

*Superseded as R5 evidence by ADR-195 (2026-10-07): the corpus review found the comparison context-asymmetric; see the response-v10 section below.*

135/135 successful cells in 142 attempts; all seven failures and cached input costs count. Medians: Java 21,564, Kotlin 21,566, XAX 10,748. Ratio **0.4984232980894083** meets the median 0.50 gate. Aggregate ratio is 0.747651; the 50.1577% reduction refers to the median only. Independent `jvm-r5-response-v9-audit.json` reports zero errors and no live-source drift. The agent context-command review found only named Java/Kotlin program reads. No runner remains active. Keep the frozen artifacts; the next task is corpus/context equivalence review before R5 promotion. JVM remains R4/PROTOTYPE.

## Response-v10 same-prefill pilot (2026-10-07, ADR-195)

*Superseded by ADR-196 (2026-10-07): option (a) measured; see the response-v12 section below.*

Response-v9 is not R5 evidence. In every textual edit cell the model read its file through a tool call, a second client request with about 10,000 tokens of fixed client context. XAX got its view inline, along with an out-of-band mutation kind and target. On creation, where nobody reads a file, XAX was 1.007× Java. Response-v9 rows, traces and audits are retained unchanged.

Response-v10 is same-prefill: every arm gets inline context and one request with no tools, and XAX is unbound. Textual checks admit equal compiled JVM instructions that differ from the initial program. The status distinguishes `TARGET_MET` (≤ 0.50), `ACCEPTED_WITHIN_TOLERANCE` (≤ 0.55, owner-approved) and `NOT_R5`. The pilot (jvm-01 and jvm-15, one trial, CSV SHA-256 f4839408a24567cd66a20a8014375fd334a9522d2322a90bb0f0a7f051f66c23) gives Java 10,753/10,723, Kotlin 10,738/10,747 and XAX 21,965 (one repair)/10,834. Even with one-line instructions the client still uses about 6,900 input tokens per request, so a fair ratio stays near 0.93× or above.

The full 135-cell v10 run has not been executed. Resolve OI-46's measurement design first. Validation: 29 JVM R5 tests pass on Windows with Temurin 17 and Kotlin 2.1.0. JVM stays R4.

## Response-v12 minimal-client run (2026-10-07, ADR-196)

*Superseded by ADR-197 (2026-10-08): option (b) measured; see the multi-file section below.*

The run uses option (a) of OI-46. Every arm goes through the pinned Codex client with all configurable optional tools, skills and instruction blocks removed, one-line base instructions, and `gpt-6-luna` at low reasoning. The fixed per-request floor was calibrated at 3,501 input tokens, identical in three samples. The gate subtracts it once per request from every arm, and failed attempts still count.

Two adapter defects were fixed first, and each fix started a new profile. Edit forms are now listed one per line as labelled placeholders. Cross-function views now alias callee parameters instead of leaking `F2.B0.P0`. v10 (stopped) and v11 (stopped, 113/135 cells) are retained unchanged.

Response-v12 had 151 attempts and 123/135 successful cells after one refill pass. 28 attempts failed: XAX 16, Kotlin 10 and Java 2. Medians including failed costs were Java 3,710, Kotlin 3,702 and XAX 3,701. The raw ratio is 0.99973 and the floor-adjusted ratio is **0.99502**. Aggregate recorded tokens were Java 200,712, Kotlin 283,035 and XAX 322,843. The independent audit has zero errors and no source drift. CSV SHA-256: c39f72bedb1e7162938ab1d642669be7c0fe9846fd4bad4c794c332c94cc6bac.

R5 is unmet, with a target of 0.50 and acceptance at 0.55. On single-function edits the XAX view plus edit list costs about the same as the inline program plus a patch, and the model repairs XAX more often. 12 cells never passed: XAX jvm-07, jvm-09, jvm-14 and jvm-15, and Kotlin jvm-12 and jvm-14, where "u16" invites `UShort`. JVM stays R4. Validation: 47 JVM R5/local-protocol tests pass.

## Multi-file corpus v5 (2026-10-08, ADR-197)

`benchmarks.run_jvm_r5_multifile` compares XAX with four textual workflows on generated five-class projects. The textual workflows are Java and Kotlin, each with whole files or an IDE-style excerpt of the same call hierarchy. There are three families: a cross-file API change, a large-class operation change with its dependent assertion, and a transitive constant change. XAX gets the target and its transitive callers from the workspace `callers` query. Client, model (`gpt-6-luna`, low) and the calibrated 3,501-token floor are as in ADR-196.

Profile v5 had 48 attempts and 42/45 cells after one refill pass. Floor-adjusted medians:

| Arm | Median |
|---|---|
| Kotlin excerpt | 286 |
| Java excerpt | 306 |
| XAX | 481 |
| Kotlin files | 1,315 |
| Java files | 1,391 |

XAX is **1.68×** the lowest textual median (raw 1.05×) and 0.35× the whole-file workflows. XAX had 6 failed attempts and the textual arms none. Every XAX mf-02 attempt changed the operation but not the assertion constant. CSV SHA-256: 9414ad6a56deac5ef95939b6de419e0bdb033be60c535142360dd04a39f8c0aa. Profiles v1–v4 were stopped for protocol defects and are retained.

Normal-protocol work from this corpus:
- A workspace fix: an edited function no longer calls a stale, rebuilt callee.
- Exact `type OLD NEW` and `type F OLD NEW` retypes.
- Removal of edits the batch already implies.
- Kind-specific node diagnostics.

R5 is unmet and JVM stays R4. The remaining gap is the per-request edit-form help, which the textual arms don't pay because the model knows Java and Kotlin, and lower model reliability on XAX.
