# OI-31 Codex Desktop evidence status — 2026-10-02

The repository already contains two ten-row result files labeled with Codex Desktop session IDs:

- `results.csv` (primary historical run)
- `results-run-2.csv` (historical confirmation run)

Both files are preserved unchanged. All ten workspaces in `runs/` and all ten workspaces in `runs-2/` still pass the official checker.

## Historical primary rows

| Arm | Passes | Total tokens | Median tokens/task | Total turns |
|---|---:|---:|---:|---:|
| C | 5/5 | 1,363,522 | 261,725 | 6 |
| XAX | 5/5 | 1,698,890 | 327,918 | 7 |

On these rows XAX used 335,368 more total tokens, or 24.60% more than C. This is a descriptive result only; five pairs do not support a significance claim.

## Historical confirmation rows

| Arm | Passes | Total tokens | Median tokens/task | Total turns |
|---|---:|---:|---:|---:|
| C | 5/5 | 1,320,698 | 262,319 | 5 |
| XAX | 5/5 | 1,632,943 | 333,673 | 5 |

On these rows XAX used 312,245 more total tokens, or 23.64% more than C.

## Why OI-31 is not closed from these rows

The OI-31 contract requires one fixed Codex Desktop model and reasoning setting, fresh sessions, and balanced/alternating arm order. The historical CSV schema does not record model or reasoning setting. The referenced local Codex session logs are not present in this environment, so those settings cannot be recovered or independently checked. The row/session order is C then XAX for every pair, so the files also do not demonstrate the required balanced/alternating arm order.

This execution environment has no Codex Desktop control surface, no `codex` executable, and no local `%USERPROFILE%/.codex/sessions` equivalent containing the referenced session IDs. Therefore a qualifying fresh ten-cell rerun cannot be performed here. No API, alternate model, offline tokenizer, or reconstructed token count is substituted.

## Integrity/check evidence

- `results.csv` SHA-256: `a2836d67509f8c3a7e6f4e831badf3b10ad1f7532fa324ffafcfac364e56892c`
- `results-run-2.csv` SHA-256: `b7efe0f405cc786faf22ff63deccbc32b8e88c76ed3d09a7f81e13189d0245ab`
- `python -m benchmarks.ai_native summary --results benchmarks/ai_native/results.csv` reports the primary totals above.
- All 20 stored primary/confirmation workspaces pass the official checker as stored.
- `python -m pytest -q tests/test_ai_native_benchmark.py`: 16 passed, 1 skipped (`tiktoken` unavailable).

A future qualifying run should write explicit model/reasoning metadata (or retain auditable Desktop session logs that establish it), use the required balanced/alternating order, and preserve failures rather than replacing rows.
