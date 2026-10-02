# XAX Benchmark Specification

This document defines benchmark methodology, result templates, and current result status. Raw observations are stored separately. No result is fabricated.

## 1. Purpose

The benchmark suite has two co-equal families:

1. generated-program/compiler quality; and
2. AI effort per successful semantic change.

XAX does not satisfy its founding objectives merely by winning one family while failing the other.

Every result MUST identify exact benchmark-suite version, compiler/toolchain revision, semantic root, target/platform package, build policy, model/tokenizer where applicable, and measurement environment.

## 2. Benchmark case schema

Every case has a machine-readable logical record equivalent to:

```text
BenchmarkCase {
  case_id
  case_version
  family                 # runtime | ai-efficiency
  semantic_contract
  inputs
  target_set
  build_policies
  baselines
  metrics
  oracle
  measurement_protocol
  exclusions
  environment
  artifacts
  notes                  # non-normative
}
```

Changing semantic requirements, inputs, baseline flags, target configuration, or metric procedure creates a new case version.

Measured/profile data remains non-semantic.

## 3. Global validity and fairness rules

1. Correct semantics precede performance measurement.
2. Invalid programs receive no invented performance value.
3. Direct comparisons require meaning-equivalent workloads.
4. Cases/results are version/content identified.
5. Per-case outcomes remain available behind aggregates.
6. Failures, timeouts, unsupported cases, verifier rejection, and regressions remain visible.
7. Repair turns count toward AI-efficiency cost.
8. Compilation effort is reported when optimization effort differs.
9. Claims do not generalize beyond measured targets, workloads, objectives, models, or tokenizers.
10. Fewer bytes/characters do not imply better AI efficiency.
11. A transformation receives performance credit only if verifier/oracle requirements pass.
12. Benchmark corpus, target set, build policies, baselines, and primary metrics are fixed before comparative execution for a published suite run.
13. Exploratory results are labeled and separated from preregistered results.
14. XAX-specific tuning is not permitted unless equivalent permitted tuning is available to baselines.
15. Semantic weakening is valid only when every compared implementation receives the same relaxed contract.
16. Simulated benchmark outcomes are forbidden; missing capability is reported unavailable.

## 4. Runtime/compiler benchmark family

### 4.1 Metrics

Where meaningful, collect:

| Metric | Rule |
|---|---|
| execution time | wall-clock and/or cycles under declared protocol |
| throughput | completed work per declared time unit |
| tail latency | declared high percentile for latency-sensitive cases |
| code size | emitted text plus separately reported required static data |
| peak program memory | maximum benchmark-attributable memory |
| dynamic allocations | count and bytes, when allocation exists |
| startup cost | entry-to-ready or entry-to-completion as declared |
| interrupt latency | hardware event to declared handler milestone |
| compile time | end-to-end and stage-attributed when available |
| compiler peak memory | maximum compiler memory attributable to build |
| target-cost estimate | selected target model prediction |
| measured target cost | empirical counterpart where observable |

Use `not_applicable`, not fabricated zero, for inapplicable metrics.

### 4.2 Build-policy separation

Published suites SHOULD distinguish at least:

- fast-development;
- normal optimized;
- size-oriented where applicable;
- high-effort search/optimization where enabled.

Compile-time/memory cost of expensive modes remains visible.

### 4.3 C/Rust baseline rules

When used, C/Rust baselines MUST:

- implement the same semantic contract/algorithm unless the case explicitly studies algorithm choice;
- name exact compiler versions and flags;
- receive normal whole-program/LTO facilities where customary and permitted;
- not be intentionally degraded;
- report linked/runtime library components affecting startup, memory, size, or allocation;
- identify unavoidable semantic/runtime differences.

A case need not include C/Rust when fair expression would change the semantic contract.

### 4.4 Assembly baseline rules

Assembly comparisons are limited to kernels with a credible expert, vendor, published, or otherwise independently reviewable implementation.

If the assembly baseline relies on alignment, vector width, target features, relaxed semantics, restricted inputs, or other assumptions, XAX receives the same assumptions.

No result supports a universal “faster than assembly” claim.

### 4.5 Runtime case classes

The initial suite SHOULD include, as implementation milestones permit:

- exact integer arithmetic kernels;
- branch/control kernels;
- stack/address/load/store kernels;
- no-allocation/bare-metal startup cases;
- resource/effect-heavy cases;
- atomic/synchronization kernels;
- interrupt/real-time cases on capable hardware;
- specialization/generic-erasure cases;
- interprocedural optimization cases;
- code-size-sensitive firmware-style cases;
- ABI/foreign-boundary cases;
- package/build incrementality cases;
- selected credible assembly kernels;
- accelerator/GPU kernels when target path exists;
- compiler self-build stages after self-hosting milestones.

## 5. Target-cost-model validation

For candidate variants, preserve both predicted and measured values.

Evaluate:

1. **ordering accuracy** — whether lower predicted cost generally corresponds to lower measured cost;
2. **magnitude error** — normalized predicted-versus-measured difference after the declared unit mapping.

Candidate sets MUST contain materially different legal implementations; testing only the final chosen implementation is insufficient.

Objectives that cannot be credibly measured on a target are marked unvalidated.

## 6. AI-efficiency benchmark family

### 6.1 Required representation arms

The first decisive family compares identical semantic tasks using:

1. C-like text;
2. conventional SSA text;
3. compact graph packets;
4. tokenizer-native XAX transactions.

Later replacement-scale studies (§15) additionally include, where relevant: Rust-like source, a verbose structured protocol, the compact fallback protocol, and a binary/tool-call protocol. An encoding is never called optimal without these measurements; a form with fewer tokens but more repair turns loses on tokens per successful change.

The tokenizer-native arm is valid only when the evaluated model/tokenizer actually supports the dedicated vocabulary/integration. Otherwise it is `unavailable`.

### 6.2 Required task classes

The initial corpus MUST include:

- creation of small valid programs;
- one-literal edits;
- operation substitutions;
- control-flow edits;
- type-changing edits;
- repair after verifier-detectable type error;
- resource/effect repair once supported;
- targeted local optimization;
- stale-root recovery once workspace transactions exist;
- constant local edit with increasing unrelated repository/project size;
- cross-function refactor and API (interface) change;
- local change inside a large repository/application.

Each task defines the desired semantic end state independently of representation.

### 6.3 AI metrics

For every attempted task record:

| Metric | Definition |
|---|---|
| input tokens | all task-attributable model input tokens |
| output tokens | all task-attributable generated tokens |
| total tokens | input + output across initial and repair turns |
| tokens/success | total tokens divided by successful semantic changes |
| local context | bytes, tokens, and semantic entity count supplied |
| invalid generation rate | initial outputs unable to produce a valid candidate/form |
| repair iterations | additional attempts after initial failure |
| semantic entities transmitted | distinct semantic objects exchanged |
| transaction size | bytes and tokens of attempted/committed mutation payload |
| commit conflict rate | stale/conflicted expected-base rejection fraction |
| context growth | context change as unrelated project size increases |
| task success rate | fraction passing verifier and behavioral oracle within attempt budget |
| bytes transmitted | request/response payload bytes |
| irrelevant context | retrieved entities/tokens not needed by the final mutation |
| verifier failures | rejected candidates by diagnostic code |
| stale transaction failures | expected-root/read-set rejections |
| latency | wall time from task start to committed success |
| final semantic correctness | behavioral oracle result of the committed root |

Token accounting uses the exact evaluated tokenizer.

### 6.4 Fairness across representations

All arms receive:

- the same semantic task and behavioral oracle;
- the same attempt budget;
- equivalent diagnostic information to the extent their representation supports it;
- the same model, sampling policy, context limit, tokenizer, and tool-access policy unless the experiment explicitly varies one of these.

Representation-specific protocol instructions may explain mechanics but may not leak the solution to only one arm.

If an arm must regenerate a larger unit because it lacks local mutation, that cost remains part of the result.

## 7. Context-scaling experiment

Hold the requested local semantic edit and its dependency neighborhood constant while increasing unrelated project content.

Measure task-attributable context and semantic entities, not total repository bytes.

A successful local-query architecture should have context growth dominated by the semantic dependency neighborhood rather than unrelated repository size.

A harness that serializes the entire repository into each request invalidates this experiment.

## 8. Serialization/compiler-service microbenchmarks

Before runtime code generation exists, valid benchmark categories include:

- canonical store bytes by object kind;
- encode/decode throughput;
- CID/hash throughput;
- sorted-reference-table construction;
- random object lookup;
- malformed-object rejection throughput;
- full versus local graph-fragment rewrite size;
- verifier throughput by rule family;
- local invalidation frontier size;
- derived-fact cache hit/recompute cost;
- deterministic diagnostic construction;
- transaction apply/verify/commit cost.

## 9. Current measured results

## 9. Reproducibility protocol

A published benchmark run records at least:

```text
ResultEnvironment {
  suite_root/version
  case_id/version
  compiler/toolchain root
  semantic program root
  target/platform/ABI roots
  build policy/profile root
  package snapshot root
  machine/firmware identifiers
  OS/runtime identifiers if present
  measurement-tool identity
  model/tokenizer/sampling identity for AI cases
  warmup/reset/run-count protocol
  input seeds/digests
  timestamp as non-semantic observation
}
```

Timing measurements SHOULD report raw per-run observations or sufficient summary distribution data to audit aggregation.

Outlier handling, warm-up, CPU/device frequency controls, affinity, power state, background-load policy, and timer source MUST be declared when relevant.

## 10. Anti-cherry-picking rules

A published summary MUST NOT:

- report only favorable targets/cases;
- remove slow cases after observation;
- hide unsupported or failed cases;
- compare different semantic contracts without labeling the difference;
- grant target-specific assumptions to only one side;
- compare high-effort XAX optimization against low-effort baseline builds while hiding build effort;
- use a faster algorithm on only one side and call it a compiler comparison;
- merge materially different hardware environments into one score;
- publish only final successful AI outputs while excluding failed/repair attempts;
- approximate tokenizer-native results using ordinary text and label them tokenizer-native.

## 11. Result templates

### 11.1 Runtime case result

```text
RuntimeResult {
  case_id
  case_version
  target/configuration
  build_policy
  semantic_oracle_status
  execution_time_samples
  throughput_samples?
  tail_latency?
  code_size
  peak_memory
  allocations?
  startup_cost?
  interrupt_latency?
  compile_time
  compiler_peak_memory
  predicted_target_cost?
  measured_target_cost?
  output_artifact_root
  notes
}
```

### 11.2 AI case result

```text
AIResult {
  case_id
  case_version
  representation_arm
  model
  tokenizer
  task_success
  verifier_status
  oracle_status
  input_tokens
  output_tokens
  total_tokens
  repair_iterations
  local_context_bytes
  local_context_tokens
  semantic_entities_transmitted
  transaction_bytes
  transaction_tokens
  conflict_count
  elapsed_tool_time?
  final_root_or_artifact
  notes
}
```

### 11.3 Aggregate summary

```text
Aggregate {
  suite_version
  preregistration_identity
  included_cases
  failed_cases
  unsupported_cases
  primary_metrics
  per_case_result_references
  aggregation_method
  confidence/dispersion_method
  exclusions_with_predeclared_reason
}
```

The aggregate never replaces per-case data.

## 12. Milestone gating

A benchmark becomes valid only after the implementation capability it measures exists. The staged gates are defined in `XAX_IMPLEMENTATION_ROADMAP.md`.

Examples:

- before direct native backend: no native runtime-performance claims;
- before transactional workspace: no XAX local-transaction AI claim;
- before actual tokenizer integration: tokenizer-native arm unavailable;
- before calibrated target model: magnitude accuracy unvalidated;
- before self-hosting subset: no self-build benchmarks;
- before GPU/accelerator path: accelerator performance unavailable.

## 13. Falsification conditions

The architecture must be reconsidered if reproducible fair measurements establish any of the following after reasonable implementation maturity:

1. semantic graph transactions do not materially reduce tokens per successful change versus source/SSA regeneration after repair cost;
2. local-edit context grows approximately with unrelated repository size;
3. a second substantially different native target requires changes to fundamental program semantics;
4. calibrated target cost models cannot usefully rank candidate implementations;
5. generated code remains materially worse across a preregistered fair corpus for selected objectives despite reasonable optimizer maturity/effort;
6. programs with no semantic runtime requirement still acquire allocator/scheduler/libc/GC/reference-counting/etc. dependencies;
7. local edits routinely rewrite/retransmit unrelated program regions because identity/objectization is too coarse;
8. exact verification becomes too globally coupled for practical incremental checking;
9. aggressive optimization cannot be paired with adequate correctness validation;
10. self-hosting closure requires a permanently maintained second compiler/backend/target/build/package language.

A falsified claim is recorded as falsified. Benchmark definitions must not be changed after results merely to preserve a preferred conclusion.

## 14. Current result status

No comparative runtime or model-driven AI-efficiency benchmark has been run.

Section 9 records one exploratory static representation-token comparison using two actual tokenizers. C-like text wins that case. It contains no model invocation or success evidence and supports no general AI-efficiency conclusion.

`compiler/benchmarks/m6_workspace_smoke.json` records one exploratory deterministic M6 accounting check: 4 entities exposed in 534 response bytes, 4 read handles, 101 transaction bytes, 6 new objects, and 2 reused objects for three verified mutations committed through one graph rebuild. It contains no timing data and supports no performance conclusion.

`compiler/benchmarks/m6_artifact_mapping_smoke.json` records deterministic non-timing artifact-query accounting reproduced by `bench_artifact_mapping.py`. The unchanged x86-64 stack artifact is 43 bytes. The v2 record includes semantic-root handle, target CID, explicit compiler/lowering identities, artifact SHA-256 digest, and compact provenance-binding identity. Seven artifact/mapping queries expose 9 local entities in **2,499** bootstrap response bytes: artifact 564 bytes, function mapping 282, unavailable stack-allocation mapping 223, store mapping 285, and two one-entity reverse-mapping pages 290/297. The exact store span is `[12,21)` and the stack-allocation node is explicitly unavailable because it emits no independently attributable bytes. The increase from the prior v1 accounting is retained evidence of attribution overhead, not a regression selected away. This is accounting/conformance evidence only and supports no runtime or AI-efficiency performance conclusion.

`compiler/benchmarks/m6_artifact_mapping_cross_target.json` extends the same non-timing seven-query v2 accounting shape to all currently emitted artifact formats using `bench_artifact_mapping_cross_target.py`. Each target exposed 9 entities. Total bootstrap response bytes are x86-64 **2,499**, AArch64 **2,502**, and WebAssembly **2,495**. Exact function/store ranges remain x86-64 `[0,43)` / `[12,21)`, AArch64 `[0,44)` / `[12,20)`, and WebAssembly body `[39,78)` / `[56,63)`. Stack allocation remains unavailable on all three because it emits no independently attributable bytes. These response-byte counts include dependency-attribution identities and are not token counts, timings, code-quality results, or evidence that one target is more AI-efficient.


`compiler/benchmarks/m6_response_budget_smoke.json` records deterministic non-timing response-byte-budget accounting reproduced by `bench_response_budget.py`. For the three-node workspace query, the unbounded one-page response is **424 bytes**. An exact **178-byte** budget forces three positive-progress pages of **171 / 171 / 178 bytes**, exposing one entity per page with continuations `1 / 2 / none`; total returned bytes increase to **520** because pagination metadata and repeated framing are retained rather than hidden. This is transport accounting only. It is not a model-token measurement and makes no AI-efficiency or timing claim.


### M6 relation-transaction accounting smoke

`compiler/benchmarks/m6_relation_transaction_smoke.json` is reproduced by `bench_relation_transaction.py`. It is a deterministic **non-timing** accounting/conformance record for the first operand/use relation mutation. The one-mutation `ReplaceUse` transaction uses a generation-scoped root alias and encodes to **24 bootstrap transaction bytes**. In the harness fixture it changes `add(p0,p1)` to `add(p1,p1)`, changing the direct function result for `(2,3)` from **5 to 6**, rebuilds/verifies **6** affected objects, reuses **1** reachable object, and retains one direct caller relationship to the rebuilt callee. These values are implementation/accounting evidence only; they are not tokenizer, model-efficiency, compile-time, or runtime-performance results.

### M6 node-deletion accounting smoke

`compiler/benchmarks/m6_delete_node_smoke.json` is reproduced by `bench_delete_node.py`. It is a deterministic **non-timing** accounting/conformance record for the first containment-preconditioned node deletion. The one-mutation `DeleteNode` transaction uses a generation-scoped root alias and encodes to **17 bootstrap transaction bytes**. In the harness fixture it deletes one unused constant from a two-node callee, deterministically renumbers the surviving arithmetic node and return reference, preserves the callee result for `(2,3)` at **5**, rebuilds/verifies **6** affected objects, reuses **2** reachable objects, and retains one direct caller relationship to the rebuilt callee. These values are implementation/accounting evidence only; they are not tokenizer, model-efficiency, compile-time, or runtime-performance results.

### M6 proof-dependency accounting smoke

`compiler/benchmarks/m6_proof_dependency_smoke.json` is reproduced by `bench_proof_dependency.py`. It is a deterministic **non-timing** accounting/conformance record for verifier-status proof reads. The `proof` query returns local dependency handle `P0.0` without exposing a persistent semantic CID and accounts **299 bootstrap response bytes**. A one-mutation transaction guarded by that dependency uses **22 bootstrap transaction bytes**, changes the fixed fixture result from **5 to 6**, rebuilds/verifies **4** affected objects, and reuses **4** reachable objects. Reusing the same proof handle after its semantic subject changes rejects as `XAX.WORKSPACE.PROOF_CONFLICT` / `WORKSPACE-PROOF-DEPENDENCY`. These values are byte-accounting/conformance evidence only; they are not tokenizer, model-efficiency, formal-proof, compile-time, or runtime-performance results.

### M6 pure-node insertion accounting smoke

`compiler/benchmarks/m6_insert_node_smoke.json` is reproduced by `bench_insert_node.py`. It is a deterministic **non-timing** accounting/conformance record for the first exact-position pure-node insertion plus same-transaction consumption of the new result. The two context queries expose **4 entities in 576 bootstrap response bytes**. The generation-root transaction contains `InsertPureNode` plus `ReplaceUse`, uses transaction-local result `I4.R0`, and encodes to **43 bootstrap transaction bytes**. In the fixed fixture it changes 3 nodes to 4 and the function result from **5 to 12**, rebuilds/verifies **5** affected objects, and reuses **4** reachable objects. These values are implementation/accounting evidence only; they are not tokenizer, model-efficiency, compile-time, or runtime-performance results.

### M6 control-edge argument accounting smoke

`compiler/benchmarks/m6_edge_argument_smoke.json` is reproduced by `bench_edge_argument.py`. It is a deterministic **non-timing** accounting/conformance record for the first exact-position block-terminator edge-argument reconnect. The bootstrap context query exposes **2 node entities in 301 response bytes**. The generation-root transaction contains one `DisconnectEdgeArgument` and one `ConnectEdgeArgument`, changes edge argument 0 from source parameter 0 to source parameter 1, and encodes to **39 bootstrap transaction bytes**. In the fixed one-caller fixture the callee result for `(2,3,300)` changes from **2 to 3**, rebuilds/verifies **6** affected objects, reuses **4** reachable objects, and retains one direct caller relationship. These values are implementation/accounting evidence only; they are not tokenizer, model-efficiency, compile-time, or runtime-performance results.

### M6 candidate-only verify/rollback accounting smoke

`compiler/benchmarks/m6_candidate_verify_smoke.json` is reproduced by `bench_candidate_verify.py`. It is a deterministic **non-timing** accounting/conformance record for private candidate verification, explicit rollback, and a subsequent ordinary commit from the unchanged base. The bootstrap context query exposes **3 node entities in 424 response bytes**. Candidate verification of one generation-root `SetOperation` transaction uses **26 bootstrap transaction bytes**, touches/verifies **4** objects, reuses **4** reachable objects, returns local candidate handle `C0.0`, and leaves canonical root/generation unchanged. Rollback also leaves root/generation unchanged. The same ordinary transaction then commits successfully and changes the fixed result **5→6**. Candidate verification/verified-object accounting is maintained separately from ordinary commit accounting. These values are implementation/accounting evidence only; they are not tokenizer, model-efficiency, compile-time, or runtime-performance results.

### M6 narrow specialization accounting smoke

`compiler/benchmarks/m6_specialize_smoke.json` is reproduced by `bench_specialize.py`. It is a deterministic **non-timing** accounting/conformance record for one exact-constant `SpecializeFunction` request. Three bootstrap queries expose **4 entities in 479 response bytes**. The generation-root transaction specializes parameter 0 of a two-parameter `bits<8>` wrapping-add function to constant 5 and encodes **15 bootstrap transaction bytes**. The published one-parameter clone returns **8** for input 3, while the original source and direct caller remain unchanged. Construction adds/verifies **5** objects and reuses **5** reachable objects. These values are implementation/accounting and semantic-execution evidence only; they are not tokenizer, model-efficiency, general META, compile-time-performance, or runtime-performance results.

### M6 same-block pure-node move accounting smoke

`compiler/benchmarks/m6_move_node_smoke.json` is reproduced by `bench_move_node.py`. It is a deterministic **non-timing** accounting/conformance record for the first exact-source/exact-anchor same-block pure-node move. The bootstrap context query exposes **3 node entities in 424 response bytes**. The generation-root `MovePureNode` transaction moves the second constant immediately before the first, encodes to **28 bootstrap transaction bytes**, remaps the arithmetic operands by original producer identity, preserves the callee result at **5**, rebuilds/verifies **6** affected objects, reuses **4** reachable objects, and retains one direct caller relationship. These values are implementation/accounting evidence only; they are not tokenizer, model-efficiency, compile-time, or runtime-performance results.

### M7 resource/effect proof-erasure check

`compiler/benchmarks/bench_m7_resource_effect.py` is a deterministic non-timing comparison between a bits-only baseline and the same observable computation surrounded by a verified generic resource/effect lifecycle. Each backend emits byte-identical artifacts for the pair:

| Target | Baseline bytes | Lifecycle bytes | SHA-256 |
|---|---:|---:|---|
| x86-64 | 25 | 25 | `6d9e24dc5ddc2dbe5c55f3e8e932e162a6f1ed3033fd4eaedfaf730100ba2fc0` |
| AArch64 | 28 | 28 | `fb5970c1e6ab2c3be407a4a0a7ef6003051549e163cc76811138a552d3ca68db` |
| WebAssembly | 59 | 59 | `40997b5662863f0ba9253c23bf4e915b1e32c0a2878f0e4635d00063532bfc88` |

This proves zero emitted-byte overhead for this fixed proof-only lifecycle fixture. It is not a runtime-performance, compile-time-performance, tokenizer, model-efficiency, or general generated-code-quality result.

The M7 clean deterministic wheel was built twice with `SOURCE_DATE_EPOCH=946684800` and matched byte-for-byte: `xax_compiler-0.1.0-py3-none-any.whl`, **66,118 bytes**, SHA-256 `578486a736f73d82db13dbcc82bbe21a9ba13ee68ae12a58bf5693c71534d9ba`. This is packaging/reproducibility evidence only. An earlier dirty/non-normalized ad hoc wheel comparison was discarded and is not evidence.

### M8 atomic artifact/execution smoke

`compiler/benchmarks/m8_atomic_smoke.json` is reproduced by `bench_m8_atomic.py`. It is a deterministic **non-timing** artifact/execution record for one verified x86-64 stack-resident atomic sequence containing release store, wrapping acq-rel RMW, strong seq-cst/acquire compare-exchange, seq-cst fence, and seq-cst load. The raw load image is **108 bytes**, SHA-256 `3766932e195970e563376f48093c6ccf479aa838d08845b70571a8903266d938`; reference and isolated native execution both return **8** for inputs `(5,3,11)`. The selected target CID is `24e312c773b777ac4dd892b39a9477f1758ff8bf05d7708bfb8282120a9ded56`, and the record declares no runtime assists. This is direct-emission/conformance evidence only; it is not synchronization-cost, latency, throughput, cross-target, tokenizer, or model-efficiency evidence.

The M8 `SOURCE_DATE_EPOCH=946684800` wheel reproducibility test passed. The final wheel is **75,365 bytes**, SHA-256 `7f812534ddd002efbaa29510071f5bcf0886e70da67debfcca5d7ceb40a82db4`. This is packaging/reproducibility evidence only.

### M9 compile-time construction/cache smoke

`compiler/benchmarks/m9_comptime_smoke.json` is reproduced by `bench_m9_comptime.py`. It is a deterministic **non-timing** META construction/cache/artifact record. One ordinary XAX compile-time function inspects a `bits<32>` type, constant 5, and the x86-64 target package; reads declared input 7; computes 44; and constructs a verified constant-return function. Evaluation uses **8 semantic steps**, creates three canonical objects, and a repeated identical request is a cache hit. The generated function CID is `03dfe6520ab043dd40d391d8834a41ce4314481ce6d7cc8dd8bf15ea560b5adc`. Explicit materialization emits a **35-byte** x86-64 image with SHA-256 `6fba4d01d380cba2d2dc500f6ac96b6cdee1df35e810e587ee517be248bf754e`; reference and isolated native execution both return **44**. This record is not a compile-time-duration, runtime-performance, tokenizer, model-efficiency, cache-hit-rate, or general generated-code-quality result.

The M9 `SOURCE_DATE_EPOCH=946684800` wheel built twice and matched byte-for-byte: **79,608 bytes**, SHA-256 `407922eb7017f5a0bb841fa7b69e915654afd0bf14c19d4e0b7e8f4143ac5a67`. This is packaging/reproducibility evidence only.

### M10 deterministic package/build smoke

`compiler/benchmarks/m10_package_build_smoke.json` is reproduced by `bench_m10_package_build.py`. It creates one canonical package, hermetic profile, trust policy, typed build request, complete snapshot, verified cache entry, and direct artifact for each of x86-64 and WebAssembly. Repeating each build produces byte-identical `BuildResult` data, and target-specific requests produce distinct cache keys.

| Target | Snapshot root | Build key | Artifact bytes | Artifact BLAKE3-256 |
|---|---|---|---:|---|
| x86-64 | `0441036881fb4ca91a8f3acf52d0bcb8b076e1a92592039da0a11a6668767349` | `cf3528c16cc24b16c341568282b11871ad49079b5034722ef88bf8e8158dd3be` | 35 | `4c6bd5edce503f68519033d7d58cc43c5a2bd8fe0636cc625855ee63f6b3b889` |
| WebAssembly | `0c7823663324f58e25e73e477356407f4e004720d245d23d5517bb674082c117` | `92b705a924300f62ac1897f0a855486054f94d6e1e509a4a6fe9ee707a7be590` | 62 | `1cc566ee4cc39286fd638b71a81e5e148637cf7cfe827a3bdd630b90f826f022` |

Both cache reads revalidated artifact digest and provenance closure. This is deterministic identity/artifact/cache evidence, not resolver performance, runtime performance, build-time performance, sandbox portability, supply-chain security, tokenizer, or AI-efficiency evidence.

The final M10 `SOURCE_DATE_EPOCH=946684800` wheel built twice and matched byte-for-byte: **89,076 bytes**, SHA-256 `05d55cc76e28d3e677465c37afe06af5820a41b112a3e2a8dbab5dfd653cb482`. This is packaging/reproducibility evidence only.

### M11 B0/B1 bootstrap evidence

`compiler/bootstrap/m11_bootstrap_evidence.json` is reproduced by `compiler/benchmarks/bench_m11_bootstrap.py`. It is deterministic **non-timing** bootstrap/conformance evidence for the first XAX-hosted compiler component.

The authoritative compiler program store is **820 bytes** with program root `e73735dff5be8c569a94fa434abf73015330d59fc13c4e4bf8e81aad87e2b92e`. The fixed hermetic WebAssembly bootstrap snapshot is **1,566 bytes** with root `ad0af6c240790d0e9845c2776fa8f4431fd7bf149997348995a323a1a262ad0e`. The seed uses compiler identity `13dbd0cf3458d70b1e2f817928fa7248dabd7c6dade5ca52624ace6d6c296c78` and WebAssembly lowering identity `546ca644b02be7c240931ee7ed46e236ac02b10047506044e82eed530836821b`, producing provenance root `2b951daac225cb560c650332e97299346f786fbd3f3a34c08e60676c7534f6aa`.

The resulting import-free WebAssembly artifact is **144 bytes** with BLAKE3-256 digest `3f9f35e6fe8c8ec00e0490fa3e9f9b613255f6ab930c8d8ab2b9d18a221be09a`. Repeating the build produces identical `BuildResult` data. Six conformance vectors compare the Python seed/reference execution against the seed-built XAX-hosted artifact, including wrapping-add and wrapping-multiply cases; all **6/6 match**.

This establishes implementation-local B0/B1 evidence for the declared arithmetic-folding compiler component only. It is **not** a self-build timing benchmark, recursive self-hosting result, B2/B3/B4 fixed-point result, toolchain-closure claim, bootstrap-independence claim, tokenizer result, or runtime-performance result.

The M11 `SOURCE_DATE_EPOCH=946684800` wheel built twice and matched byte-for-byte: **92,769 bytes**, SHA-256 `7be816707f5e4270d4cfd94be3591461410b76ecc5dfe3a1f57fa8630f450d97`. This is packaging/reproducibility evidence only.

### M12 optimizer/validated-search evidence

`compiler/benchmarks/m12_optimizer_evidence.json` is reproduced by `compiler/benchmarks/bench_m12_optimizer.py`. It is deterministic **non-timing** optimizer/cost/validation evidence for the declared M12 slice. The canonical optimization-policy root is `924e070eceab1b9abba8c1cbb67fb2365fa7cc9f21362537f4b228bcdbd90dba`; its fixed evidence budget uses 4 local-pass iterations, 96 search steps, 64 candidate attempts, 262,144 bytes search memory, 256 polynomial terms, cold/hot inline limits 2/8, and hot-call threshold 10.

For the fixed pure `bits<32>` wrapping-arithmetic fixture equivalent to `x * 2`, bounded search examines 64 candidates per target. Exactly **4** candidates pass exact polynomial equivalence and **60** are rejected by validation; 64 deterministic steps are consumed and peak deterministic search accounting is **6,560 bytes**. The selected semantic function CID is `949339b59e4a8283ca0b269155c0f7db1573663e44bcf5cde1cd182a11ae9a7b` on both targets.

| Target | Before function extent | After function extent | Change |
|---|---:|---:|---:|
| x86-64 | 59 bytes | 43 bytes | -16 bytes (-27.1%) |
| WebAssembly | 36 bytes | 32 bytes | -4 bytes (-11.1%) |

The x86-64 target root is `24e312c773b777ac4dd892b39a9477f1758ff8bf05d7708bfb8282120a9ded56`; the WebAssembly target root is `946143a04b0b1ba8ed7312af6c85f70cbb4f71644fb20f7aea3be8ed06da41ed`. The cost classification is **lowering-derived estimate**: the oracle measures exact emitted function extent for code-size selection. It is not measured runtime latency, throughput, energy, or a calibrated predictive model.

The same evidence record includes profile-guided inlining: a tooling-only hot call-weight profile changes profitability/output relative to the cold case, all before/after/reference vectors match, and the profile identity bytes do not occur in the canonical store. This demonstrates non-semantic profile separation for the declared fixture only.

The evidence JSON was generated twice and compared byte-for-byte; SHA-256 is `046d6996ec1619a6e3150b728cd3256fea02bda7d570fb862d433f620f89dfff`. This is not broad optimizer-quality, compile-time-duration, runtime-performance, solver-generality, tokenizer, or AI-efficiency evidence.

The M12 `SOURCE_DATE_EPOCH=946684800` wheel built twice and matched byte-for-byte: **102,449 bytes**, SHA-256 `e21d519dff45f9972f4a094a2998cef26d6971c7fbdbd10d77041298875591ab`. This is packaging/reproducibility evidence only.


### M13 accelerator deployment/conformance evidence

`compiler/benchmarks/m13_accelerator_evidence.json` is reproduced by `bench_m13_accelerator.py`. It is deterministic **non-timing** target/deployment/conformance evidence for one prototype non-CPU SIMT packet target. The program root is `6e088c0ff84c0723a9c3b7f527bf2bd98b886f8e5846f0200f5b1ee2ecf7db5c`; target root is `202e9d0db81107e8380f27ef1f233327c34fe8a1f56431d38814ec4ee6feee04`.

The target package declares 32-lane execution, device/workgroup scopes, and three explicit memory spaces (host staging, device global, workgroup). Its six target-operation contracts encode explicit allocate, host→device transfer, launch, synchronize, device→host transfer, and release steps. The emitted deployment packet is **122 bytes**, BLAKE3-256 `b4ba34f70945722503a3927b8a44ca308055a0786873aa5e98f69356d5da4f5b`, SHA-256 `4e3c8522d322a3c0edceb93df393813c5f7017ca82c2427e94dbf258447ec79f`, and declares no runtime dependency. Repeated compilation is byte-identical.

Six wrapping-add vectors, including 32-bit wraparound, all match the expected result. Two negative fixtures prove deterministic rejection of unsupported execution scope (`TARGET-OPERATION-SCOPE-SUPPORTED`) and memory-space pairing (`TARGET-OPERATION-MEMORY-SPACES`). Evidence JSON SHA-256 is `58e12d090e82c330e554728638b4070c9514a73d5861fad56afdea3aa463ce9a`.

This is not physical-GPU execution, runtime latency/throughput/energy, compiler-performance, tokenizer, AI-efficiency, multi-vendor scope portability, or cost-model evidence.

The M13 `SOURCE_DATE_EPOCH=946684800` wheel built twice and matched byte-for-byte: **109,836 bytes**, SHA-256 `b2180788ecfb0cc697f43613f6cd553f2b26ebd1f486739b8327319988db85e7`. This is packaging/reproducibility evidence only.


## M14 recursive self-hosting/closure evidence — non-performance

`compiler/bootstrap/m14_selfhost_evidence.json` is deterministic **bootstrap/conformance evidence**, not a performance benchmark. It records executed B2–B6 only for `xax-semantic-image-v1`.

The authoritative compiler image is **2,020 bytes**, program root `097da62f7ba9832620f5d202297fc522783ed5b4c9e68f8da6b77515b185164d`, entry function `4300342f92f9ba32bcefbb45af4aad117a3bbf3699bd66266b25cefdc874b6fc`, and SHA-256 `05eb15404836e9f77b2f2931489859c43c0f75dcb00c891504e9ddcdd427cd07`. Generation 0, generation 1, and generation 2 are byte-identical with BLAKE3-256 `6340c903f5da3e8aaf4d8ae886694a0d858687fc5c5520662a018518693f4788`. Four independent function-CID generation vectors match **4/4**.

The immutable seed runtime is **46,255 bytes**, SHA-256 `4e0c64d6f360359cc263c39817ec8cbe4cc3069edf20823755755c4d2707fe52`, BLAKE3-256 `eb8157fd2a00fcca5666ea574b7641b4adcb43382f5fbb60f8addead5f04b7b6`. It reconstructs the compiler byte-identically with repository `PYTHONPATH` removed. The seed internally contains Python modules and requires a Python interpreter; this is an immutable-seed B6 boundary, not an implementation-language-elimination or diverse-trust claim. Evidence JSON is **3,240 bytes**, SHA-256 `36c2a9a57aea432250ff7a1595e19535ed1d37f2aa7588cd4edd1f01710c6dfa`.

The compiler image, seed runtime, and evidence JSON were generated twice after the final evidence-label correction and matched byte-for-byte. No self-build wall time, native code speed, throughput, latency, memory footprint, tokenizer/model efficiency, or diverse-double-compilation result is inferred from these numbers. Legacy x86-64, AArch64, WebAssembly, and accelerator lowerers are explicitly outside the B5/B6 closure target.

The final M14 `SOURCE_DATE_EPOCH=946684800` wheel built twice and matched byte-for-byte: **117,715 bytes**, SHA-256 `fa4add6e966ca09fe5df6c02043e91d333f0726ec92f681a03bf7251e4a4a34e`. This is packaging/reproducibility evidence only.
## Tiny AI-native C vs XAX experiment

`compiler/benchmarks/ai_native/` now contains a five-task, manually run Codex Desktop comparison with exactly two arms: C and the real XAX workspace transaction interface. It records pass/fail, available model tokens, turns, optional elapsed time, and no inferential statistics. The sole runbook is `compiler/benchmarks/ai_native/README.md`.

For OI-01 the same benchmark also compares six versioned `X1` fallback-transport candidates: typed (`P0`/`N0`) versus unified dense-integer handles, each with `line`, `pipe`, and `json` packet framing. `python -m benchmarks.ai_native transport` records offline `cl100k_base`/`o200k_base` token and byte counts in `transport-oi01.json`. Unified handles save 15 view tokens across the five tasks under both encodings, and unified/pipe has the smallest combined view+packet total at 237 tokens under either encoding. A 30-trial Claude Code run (`claude-opus-5-5` subagents, 5 tasks × 6 arms, n=1) completed 30/30. Five-task harness-token totals were 278,750 typed/line, 280,478 typed/pipe, 280,648 typed/json, 278,301 unified/line, 281,968 unified/pipe, and 280,587 unified/json; the roughly 1.3% spread is below run-to-run noise because each trial includes roughly 55.6k fixed harness-context tokens. Reliability separated the framings: failed `verify`/`test` checks were `line` 0, `pipe` 2, and `json` 14; nine of ten JSON trials had at least one failed check. Typed versus unified handles had 9 versus 7 failed checks, all attributable to framing. Raw packets and per-invocation traces are in `runs-claude/`; rows are in `results-claude.csv`. These results disfavor the tested flat-array JSON framing and make line framing the observed reliability leader on this corpus, but they do not select a canonical transport or close OI-01.


## Android libxposed API-102 structural evidence — non-runtime

The Android/libxposed structural evidence suite records deterministic generated DEX/APK shape and MUST NOT be interpreted as runtime framework validation. Current bounded evidence includes direct service wrappers, capability-gated remote preferences/files, deoptimization, retained manual unhook, and stable-ID guarded hot reload with host-owned target-ClassLoader saved-state transfer. `android_libxposed_hot_reload_evidence.json` currently records a **34,347-byte** deterministic APK and **2,920-byte** generated module DEX. Initial install contains API-102 `HookBuilder.setId("xax.primary")` and stores the package-ready ClassLoader. `onHotReloading` is **11 code units** with a missing-loader rejection branch plus one `setSavedInstanceState`; `onHotReloaded` is **51 code units**, restores that loader, then uses explicit saved-state, empty-transfer, and ID-mismatch guards before one `HookHandle.replaceHook`. The Hooker/interceptor DEX is byte-identical to the retained non-hot-reload baseline. All runtime fields in that evidence remain `UNEXECUTED`.

## Compiler-latency fast paths — 2026-10-02 (timed, host-local)

Host: Windows 11 x86-64, CPython 3.12.10, bytecode cache enabled. "Before" = the pre-change tree with only the `AARCH64_GENERAL_OPERATIONS` import-order fix applied. Medians of 5–7 runs; the global graph-parse memo is cleared before every sample (cold). Reproduce the scaling rows with `python -m benchmarks.bench_compile_scaling 10 100 1000`.

| Measurement | Before | After |
|---|---:|---:|
| verify, n=1000 straight-line nodes | 104.7 ms | 43.8 ms |
| x86-64 compile (verify+lower), n=1000 | 214.0 ms | 64.0 ms |
| AArch64 compile (verify+lower), n=1000 | 227.8 ms | 62.0 ms |
| x86-64 compile, n=10 | 7.5 ms | 2.8 ms |
| canonical store write, n=1000 | 31.7 ms | 9.5 ms |
| M14 recursive self-build (B2–B4 evidence path) | 264.4 ms | 80.1 ms |
| workspace one-node commit, 170,031-byte store | 2,164 ms | 15.9 ms |
| workspace open (full verification), same store | 1,884 ms | 552 ms |
| traced peak allocation, x86-64 compile n=1000 | 1,052 KiB | 1,028 KiB |
| `import xax_compiler` (cumulative) | 89.8 ms | 91.2 ms (noise) |
| full unittest discovery | 90.6 s | 45.0 s |

Generated x86-64/AArch64 code is byte-identical before/after; M14 compiler root, generation digests, equivalence vectors, and fixed point are unchanged. Mechanisms: `StoreReader.get` decodes and CID-checks each record once; `_parse_graph` is memoized by graph CID with dependency-resolve replay (falling back to an uncached parse on any replay failure so diagnostics stay exact); `Cursor.uleb` checks minimality without re-encoding; BLAKE3 compression uses inlined local-word rounds (official vectors pass); objects created or decoded by the compiler carry a non-copyable CID-checked flag; and `StoreReader.from_objects` validates contents eagerly but emits canonical bytes and the container digest only when `.data` is read. Remaining measured bottleneck: pure-Python BLAKE3 is ~40% of cold verification.

## 15. Universal-replacement benchmarks

Replacement levels R4/R5 (`XAX_SPEC.md` §21.2) are earned only through this section.

**Workloads.** The U1 workloads (`XAX_IMPLEMENTATION_ROADMAP.md`): hosted native application, bare-metal program, WebAssembly/WASI or browser application, Android application, accelerator workload; later, representative per-domain workloads (server, database, compiler, game loop, HPC kernel, AI runtime operator) as the matrix grows. Workload definitions are fixed before XAX results are seen and are not tuned to favor XAX.

**Baselines.** The platform's established toolchains at stated versions and settings: optimized C/C++ (Clang/GCC/MSVC), Rust, platform-native compilers (Kotlin/Java for Android/JVM, C# for CLR, Swift for Apple), Emscripten/wasi-sdk or Rust for WebAssembly, vendor GPU toolchains, and hand-written assembly where a credible implementation exists (§4.4). "Faster than assembly" is never claimed universally; the objective is minimum selected target cost subject to exact semantics.

**Record per result.** Exact hardware; OS/build; compiler/toolchain versions and flags; optimization/build policy; workload and input; warmup; repetitions; median, p95/p99 where meaningful, and dispersion (MAD/IQR); binary size; peak memory; execution time; startup where relevant; generated instruction/code properties when useful; platform-required runtime and generated adapters. Unavailable baselines are recorded as unavailable with the reason; they are never estimated.

**AI token trials.** For the same workloads, run the §6 task classes with real models and record §6.3 metrics. Per the current work order, token trials run only after the replacement upgrade lands, using the smallest corpus that exercises each task class once (n=1 per cell first, extended only when differences exceed run-to-run noise).

**Current status.** `compiler/benchmarks/windows_pe_hosted_evidence.json` is EXECUTED evidence for the hosted Windows PE fixture (current fixture: 2,560-byte executable, 1,269 code bytes after the PE register path (2,181 before), eight kernel32 imports, heap-array round trip and function-pointer dispatch table; 20/20 runs; process wall time includes CreateProcess and pipe overhead). `compiler/benchmarks/wasi_command_evidence.json` is EXECUTED evidence for the WASI command module (635 bytes, stdout via `fd_write`, Node v26.7.0, 10/10 runs). It is not an R4 result: no C/Rust baseline toolchain exists on the measuring host and the code is from the spill-every-value frame lowering. `compiler/benchmarks/windows_c_reference/hosted.c` is the fixed semantic twin for the baseline run. `compiler/benchmarks/x86_register_path_evidence.json` is MEASURED intra-XAX evidence: the register path runs `sum_to(200,000,000)` 8.02x faster than the frame path (92.1 vs 738.7 ms median, 7 runs); it is not a cross-toolchain claim.

### 15.1 U1.3 Linux `filestat` (MEASURED, 2026-10-02)

This is the first cross-toolchain comparison. Source: `compiler/benchmarks/linux_filestat.py` (XAX graph and harness), `compiler/benchmarks/linux_filestat_c/filestat.c` (fixed semantic twin, linked with `-lz`), and `compiler/benchmarks/linux_filestat_c/runner.c` (fork/exec/`wait4` timer). Evidence: `compiler/benchmarks/u1_linux_filestat_evidence.json`.

The workload opens `input.dat`, reads it in 64 KiB chunks into an anonymous `mmap` buffer, and counts bytes, lines, and words. It also computes FNV-1a 64, keeps a 256-entry histogram in a second mapping, and folds each chunk into `libz.so.1` `crc32`. It then writes six decimal fields and exits explicitly. Host: Intel Xeon @ 2.10 GHz, 4 logical CPUs, Linux 6.18.44 x86-64, gcc 13.3.0, clang 18.1.3, zlib 1.3. Input: 32 MiB deterministic text (`shake_256` + 77-symbol alphabet). 3 warmup runs and 31 repetitions per arm; `CLOCK_MONOTONIC` around fork/exec/`wait4`; peak RSS from `ru_maxrss`. All arms produce identical output, and each matches an independent Python reference contract on a 200,003-byte input.

| Arm | Median wall (s) | Stdev (s) | vs gcc -O2 | vs best baseline | Peak RSS (KiB) | File / stripped bytes |
|---|---:|---:|---:|---:|---:|---:|
| clang 18 -O2 (dynamic glibc + libz) | 0.0694 | 0.0090 | 0.64 | 1.00 | 1,860 | 16,352 / 14,576 |
| gcc 13 -O2 (dynamic glibc + libz) | 0.1079 | 0.0136 | 1.00 | 1.55 | 1,792 | 16,256 / 14,472 |
| gcc 13 -O3 | 0.1004 | 0.0069 | 0.93 | 1.45 | 1,800 | 16,256 / 14,472 |
| gcc 13 -O2 -static (+ libz.a) | 0.1040 | 0.0133 | 0.96 | 1.50 | 716 | 798,120 / 718,872 |
| XAX `x86_64-linux-elf-dynexec-v1` | 0.1133 | 0.0242 | 1.05 | 1.63 | 1,184 | 3,560 / 3,560 |

Seven independent 31-repetition runs on this shared host gave XAX/`gcc -O2` 0.95–1.14 and XAX/`clang -O2` 1.41–1.82; the committed JSON is the last written run. **R4 is not met**: `clang -O2` is fastest, and peak memory exceeds the static baseline because the explicitly requested loader maps `libz` and the libc it requires. Binary size is the smallest of all arms. Before the Linux register allocator (ADR-089), the frame path measured 5.9× `gcc -O2` with a 23,472-byte artifact. The remaining gap is attributed to per-block allocation: loop-invariant pointers reload from home slots each iteration, one edge-induced spill, and no unrolling (OI-38).

### 15.2 OI-37 `chains`: arena + index versus pointer links (MEASURED, 2026-10-02)

Source: `compiler/benchmarks/linux_chains.py`; C twins `linux_filestat_c/chains.c` (pointer links) and `chains_index.c` (diagnostic: XAX's index representation, optionally with XAX-equivalent bounds checks). Evidence: `compiler/benchmarks/oi37_chains_evidence.json`. Same host and method as §15.1 (3 warmup runs, 31 repetitions). Every arm prints `1048576 9437420`, and each matches an independent reference on smaller tables in the test suite.

| Arm | Median wall (s) | Stdev (s) | vs gcc -O2 | Peak RSS (KiB) | File bytes |
|---|---:|---:|---:|---:|---:|
| gcc 13 -O2 (pointer links) | 0.2813 | 0.0605 | 1.00 | 18,272 | 16,096 |
| gcc 13 -O3 | 0.2781 | 0.0796 | 0.99 | 18,272 | 16,096 |
| clang 18 -O2 | 0.3509 | 0.2060 | 1.25 | 18,272 | 16,160 |
| gcc 13 -O2 -static | 0.2678 | 0.0459 | 0.95 | 17,420 | 785,304 |
| diagnostic: gcc -O2, index links | 0.4062 | 0.1110 | 1.42 | 18,272 | 16,104 |
| diagnostic: gcc -O2, index links + checks | 0.5450 | 0.1239 | 1.90 | 18,272 | 16,136 |
| XAX `x86_64-linux-elf-exec-v1` (index links, checked) | 0.9815 | 0.0691 | 3.49 | 16,896 | 1,598 |

Across two runs, the attribution (median ratios within one run) was: index vs pointer 1.44–1.47×, checked vs unchecked index 1.34–1.41×, and XAX vs checked-index C 1.73–1.80×. In total XAX ran 3.49–3.58× `gcc -O2`. Decision: ADR-090. The diagnostic arms are not baselines and are excluded from "best baseline" ratios; their file sizes are unstripped.

### 15.3 After ADR-091 (OI-38 step 1): `filestat` and `chains` re-measured (MEASURED, 2026-10-02)

Same host, method, and sources as §15.1–15.2; one 31-repetition run each. Outputs are unchanged and validated as before.

`filestat` (`u1_linux_filestat_evidence.json`):

| Arm | Median wall (s) | Stdev (s) | vs gcc -O2 | vs best baseline | Peak RSS (KiB) | File bytes |
|---|---:|---:|---:|---:|---:|---:|
| gcc 13 -O2 | 0.1013 | 0.0119 | 1.00 | 1.57 | 1,792 | 16,256 |
| gcc 13 -O3 | 0.1005 | 0.0045 | 0.99 | 1.56 | 1,792 | 16,256 |
| clang 18 -O2 | 0.0643 | 0.0075 | 0.64 | 1.00 | 1,792 | 16,352 |
| gcc 13 -O2 -static | 0.0974 | 0.0061 | 0.96 | 1.51 | 716 | 798,120 |
| XAX `x86_64-linux-elf-exec-v1` | 0.0948 | 0.0088 | 0.94 | 1.47 | 1,184 | 3,400 |

`chains` (`oi37_chains_evidence.json`):

| Arm | Median wall (s) | Stdev (s) | vs gcc -O2 | vs best baseline | Peak RSS (KiB) | File bytes |
|---|---:|---:|---:|---:|---:|---:|
| gcc 13 -O2 | 0.2418 | 0.0288 | 1.00 | 1.04 | 18,272 | 16,096 |
| gcc 13 -O3 | 0.2328 | 0.0364 | 0.96 | 1.00 | 18,272 | 16,096 |
| clang 18 -O2 | 0.2967 | 0.0848 | 1.23 | 1.27 | 18,272 | 16,160 |
| gcc 13 -O2 -static | 0.2513 | 0.0394 | 1.04 | 1.08 | 17,420 | 785,304 |
| diagnostic: index links | 0.3563 | 0.0554 | 1.39 | — | 18,272 | 16,104 |
| diagnostic: index links + checks | 0.4336 | 0.0484 | 1.69 | — | 18,272 | 16,136 |
| XAX (index links, checked) | 0.4609 | 0.0579 | 1.91 | 1.98 | 16,896 | 1,352 |

The `chains` attribution in this run is index vs pointer 1.47×, checks 1.22×, and XAX vs checked-index C 1.06×. Code generation is no longer the dominant factor (it was 1.73–1.80×, §15.2). **R4 is still not met**: `clang -O2` is 1.47× faster on `filestat`, and pointer-linked C is 1.91× faster on `chains`.

### 15.4 `chains` with `pointer_rebase` links (ADR-092; MEASURED, 2026-10-02)

Same host and method as §15.1–15.3, one 31-repetition run (this host's stdev is 13–25% of the median). Every arm prints `1048576 9437420`. Diagnostic arms are not baselines.

| Arm | Median wall (s) | Stdev (s) | vs gcc -O2 | Peak RSS (KiB) | File bytes |
|---|---:|---:|---:|---:|---:|
| gcc 13 -O2 (pointer links) | 0.2697 | 0.0349 | 1.00 | 18,272 | 16,096 |
| gcc 13 -O3 | 0.2718 | 0.0693 | 1.01 | 18,272 | 16,096 |
| clang 18 -O2 | 0.3322 | 0.1354 | 1.23 | 18,272 | 16,160 |
| gcc 13 -O2 -static | 0.2948 | 0.0939 | 1.09 | 17,420 | 785,304 |
| diagnostic: pointer links + rebase-equivalent check | 0.4106 | 0.0689 | 1.47 | 18,272 | 16,128 |
| diagnostic: index links | 0.3811 | 0.0739 | 1.37 | 18,272 | 16,104 |
| diagnostic: index links + checks | 0.5615 | 0.1141 | 2.02 | 18,272 | 16,136 |
| XAX, pointer links (`pointer_rebase`) | 0.4411 | 0.0681 | 1.64 | 16,896 | 1,336 |
| XAX, index links (checked) | 0.5382 | 0.0724 | 2.00 | 16,896 | 1,352 |

Attribution in this run: index vs pointer links (C) 1.41×; checks on pointer links (C) 1.52×; checks on index links (C) 1.47×. XAX pointer vs checked-pointer C 1.07×; XAX index vs checked-index C 0.96×. `filestat` in the same session: XAX 0.96× `gcc -O2`, 1.37× `clang -O2`. **R4 is not met.** The remaining `chains` gap is the per-link check, which only check-free reloads (OI-37 typed storage) remove.

### 15.5 `chains` with record links (ADR-097, OI-41; MEASURED, 2026-10-02)

Same host and method as §15.1–15.4; one 31-repetition run. Every arm prints `1048576 9437420`. Diagnostic arms are not baselines.

| Arm | Median wall (s) | Stdev (s) | vs gcc -O2 | Peak RSS (KiB) | File bytes |
|---|---:|---:|---:|---:|---:|
| gcc 13 -O2 (pointer links) | 0.2326 | 0.0486 | 1.00 | 18,272 | 16,096 |
| gcc 13 -O3 | 0.2414 | 0.0565 | 1.04 | 18,272 | 16,096 |
| clang 18 -O2 | 0.2748 | 0.0538 | 1.18 | 18,272 | 16,160 |
| gcc 13 -O2 -static | 0.2431 | 0.0462 | 1.04 | 17,420 | 785,304 |
| diagnostic: pointers + rebase-equivalent check | 0.3668 | 0.0624 | 1.41 | 18,272 | 16,128 |
| diagnostic: index links | 0.3150 | 0.0500 | 1.21 | 18,272 | 16,104 |
| diagnostic: index links + checks | 0.4017 | 0.0597 | 1.54 | 18,272 | 16,136 |
| XAX, record links (`link_follow`, ADR-097) | 0.2479 | 0.0425 | 1.07 | 16,896 | 1,408 |
| XAX, `pointer_rebase` links | 0.3700 | 0.0645 | 1.59 | 16,896 | 1,472 |
| XAX, index links (checked) | 0.3953 | 0.0243 | 1.70 | 16,896 | 1,496 |

Record links run at 1.066× `gcc -O2` with real pointers. That meets the OI-41 criterion (≤ 1.1×), at the edge of this host's noise (A/B probes measured 1.04–1.12×). Verifier: 3.6 ms for links against 3.5 ms for index links. `filestat` in this session: 0.95× `gcc -O2`, 1.38× `clang -O2`.

### 15.6 Windows PE hosted fixture: XAX vs MinGW-w64 C, under Wine (MEASURED-UNDER-WINE, 2026-10-02)

| Arm | File bytes | Executable bytes | Median process wall (ms) |
|---|---:|---:|---:|
| XAX `x86_64-windows-pe-v1` | 2,048 | 757 | 2564.19 |
| C, `x86_64-w64-mingw32-gcc (GCC) 13-win32` `-O2`, no CRT | 2,560 | 416 | 2549.87 |

21 runs each, interleaved, under wine-9.0 (Ubuntu 9.0~repack-4build3). Both print `XAX\n` and exit 1339 (59 mod 256). Wall time is Wine start-up. The C code is smaller because gcc folds work XAX performs at run time. Source: `bench_windows_pe_c_wine.py`.
