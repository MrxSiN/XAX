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
