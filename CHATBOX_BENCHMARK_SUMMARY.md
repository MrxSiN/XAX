# ChatGPT Continuous-Session XAX Benchmark Results

Interpretation: **Task-attributable observable token proxy for sequential benchmark tasks executed in one continuous ChatGPT session.**

Provider-reported input/output/total token telemetry was unavailable. `tiktoken` was not installed in the execution environment, so the recorded proxy uses the session's deterministic UTF-8 byte fallback; exact UTF-8 byte counts are retained in the CSV. These values are not OpenAI billing/model token counts.

## Completion

- Recorded trials: **76**
- Successful trials: **76/76**
- Transport cells: **66/66 passed**
- Failed checker/test attempts: **3**
- Repairs: **3**
- Total recorded task-local proxy units: **107,423**

The public benchmark CLI accepts numbered tasks through `task-11`; probing `task-12` returned `unknown task: task-12`.

## Aggregate by arm

| Arm | Trials | Successful | Proxy total | Median / trial | Failed checks | Repairs |
|---|---:|---:|---:|---:|---:|---:|
| C | 5 | 5 | 14,384 | 2,846 | 0 | 0 |
| XAX | 5 | 5 | 8,148 | 1,700 | 0 | 0 |
| XAX-TYPED-LINE | 11 | 11 | 16,661 | 1,292 | 3 | 3 |
| XAX-TYPED-PIPE | 11 | 11 | 13,292 | 1,123 | 0 | 0 |
| XAX-TYPED-JSON | 11 | 11 | 13,720 | 1,204 | 0 | 0 |
| XAX-UNIFIED-LINE | 11 | 11 | 14,530 | 1,235 | 0 | 0 |
| XAX-UNIFIED-PIPE | 11 | 11 | 12,956 | 1,137 | 0 | 0 |
| XAX-UNIFIED-JSON | 11 | 11 | 13,732 | 1,217 | 0 | 0 |

## Transport coverage

| Task | T-LINE | T-PIPE | T-JSON | U-LINE | U-PIPE | U-JSON |
|---|---|---|---|---|---|---|
| task-01 | PASS | PASS | PASS | PASS | PASS | PASS |
| task-02 | PASS | PASS | PASS | PASS | PASS | PASS |
| task-03 | PASS | PASS | PASS | PASS | PASS | PASS |
| task-04 | PASS | PASS | PASS | PASS | PASS | PASS |
| task-05 | PASS | PASS | PASS | PASS | PASS | PASS |
| task-06 | PASS | PASS | PASS | PASS | PASS | PASS |
| task-07 | PASS | PASS | PASS | PASS | PASS | PASS |
| task-08 | PASS | PASS | PASS | PASS | PASS | PASS |
| task-09 | PASS | PASS | PASS | PASS | PASS | PASS |
| task-10 | PASS | PASS | PASS | PASS | PASS | PASS |
| task-11 | PASS | PASS | PASS | PASS | PASS | PASS |

## Trials requiring repair

| Trial | Task | Arm | Checks | Failed | Repairs | Proxy total |
|---:|---|---|---:|---:|---:|---:|
| 41 | task-06 | XAX-TYPED-LINE | 2 | 1 | 1 | 1,464 |
| 47 | task-07 | XAX-TYPED-LINE | 3 | 2 | 2 | 1,613 |

## Scientific limitation

This is a continuous-chat experiment. It does **not** reproduce a fresh-session benchmark and cannot remove context/learning carryover between sequential tasks. `carry_in_proxy_tokens` is retained per trial as metadata and is not added to the task-local proxy total.
