# ChatGPT Continuous-Session XAX Benchmark Summary

Interpretation: **Task-attributable observable token proxy for sequential benchmark tasks executed in one continuous ChatGPT session.**

Provider-reported token telemetry was unavailable for all trials. Recorded proxy counts used the benchmark session's deterministic UTF-8-byte fallback because `tiktoken` was unavailable; these values are not exact OpenAI billing/model token usage. Exact byte counts are preserved in `chatbox-results.csv`.

Percentage difference below is `(C - XAX) / XAX * 100`; positive means C used more recorded task-local proxy units.

## Matched core tasks — TASK-LOCAL PROXY

| Task | C proxy | XAX proxy | Abs. diff | C vs XAX | C/XAX | Checks C/XAX | Repairs C/XAX | Result |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| task-01 | 945 | 1,764 | 819 | -46.4% | 0.54 | 1/1 | 0/0 | PASS/PASS |
| task-02 | 3,692 | 1,700 | 1,992 | +117.2% | 2.17 | 1/1 | 0/0 | PASS/PASS |
| task-03 | 1,087 | 695 | 392 | +56.4% | 1.56 | 1/1 | 0/0 | PASS/PASS |
| task-04 | 2,846 | 2,481 | 365 | +14.7% | 1.15 | 1/1 | 0/0 | PASS/PASS |
| task-05 | 5,814 | 1,508 | 4,306 | +285.5% | 3.86 | 1/1 | 0/0 | PASS/PASS |

## Aggregate — TASK-LOCAL PROXY

| Arm | Total proxy | Median/task | Successful | Checks | Failed checks | Repairs |
|---|---:|---:|---:|---:|---:|---:|
| C | 14,384 | 2,846 | 5/5 | 5 | 0 | 0 |
| XAX | 8,148 | 1,700 | 5/5 | 5 | 0 | 0 |

Across the five matched successful tasks, C recorded 14,384 proxy units and XAX recorded 8,148. Aggregate C/XAX ratio: 1.77; C was 76.5% higher than XAX by this recorded proxy.

## PROVIDER-REPORTED

Provider input tokens: unavailable. Provider output tokens: unavailable. Provider total tokens: unavailable.

This experiment does not reproduce a fresh-session benchmark and cannot eliminate learning or context carryover between sequential tasks.
