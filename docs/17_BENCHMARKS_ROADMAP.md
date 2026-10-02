# XAX Stage 17 — Benchmark Specification and Staged Implementation Roadmap

## 1. Purpose and scope

This document defines how XAX is to be measured and in what order the first complete implementation is to be constructed.

The benchmark specification has two co-equal purposes:

1. measure the quality of generated programs and the cost of compiling them; and
2. measure whether XAX actually reduces AI effort per successful semantic change.

Neither family is subordinate to the other. XAX fails its founding objective if it produces strong machine code but requires excessive model context, regeneration, or repair. It likewise fails if AI mutation is compact but generated programs are materially inferior for the selected runtime objective.

This stage defines measurement contracts, benchmark case schemas, anti-cherry-picking rules, baseline requirements, result-validity rules, and milestone gates. It does not define benchmark results and does not presume that XAX will outperform any baseline.

The benchmark suite MUST evolve only by versioned additions or corrections. Historical results MUST remain attributable to the exact benchmark-suite version, compiler revision, target package, build policy, model, tokenizer, and measurement environment that produced them.

---

## 2. Normative definitions

**Benchmark case**  
A versioned workload with fixed observable semantics, inputs, measurement procedure, permitted transformations, target set, and comparison baselines.

**Benchmark corpus**  
A versioned collection of benchmark cases selected before comparative execution.

**Runtime benchmark**  
A benchmark whose primary outputs concern generated code, execution behavior, executable properties, or compiler resource cost.

**AI-efficiency benchmark**  
A benchmark whose primary outputs concern model tokens, semantic context, transaction size, generation validity, repair effort, or project-size scaling.

**Baseline**  
An independently specified comparison implementation or representation. Baselines MAY include optimized C, optimized Rust, conventional SSA text, hand-written assembly, or another declared representation.

**Build policy**  
A canonical set of compiler objectives and allowed compilation effort. Results produced under different build policies MUST NOT be merged as if equivalent.

**Successful semantic change**  
A requested program mutation that commits transactionally, passes the required verifier obligations, and satisfies the benchmark case's behavioral oracle.

**Repair iteration**  
A model-visible generation attempt after the initial mutation attempt that exists because the prior attempt failed verification, failed the behavioral oracle, or could not commit.

**Local context**  
All semantic entities, diagnostics, protocol material, and other benchmark-accounted information supplied to the model for a task, excluding fixed system infrastructure explicitly declared outside the experiment.

**Semantic entities transmitted**  
The count of distinct program-semantic objects exposed to or emitted by the AI interaction, counted according to the benchmark protocol rather than byte encoding.

**Transaction size**  
The encoded size of the mutation request submitted to the XAX workspace, reported in bytes and model tokens where applicable.

**Target-cost estimate**  
A cost predicted from target-package cost data for a candidate or generated program before empirical runtime measurement.

**Valid result**  
A measurement produced under the case's declared procedure with all required metadata and without violating exclusion, baseline, warm-up, instrumentation, or fairness rules.

---

## 3. Canonical benchmark case model

Every benchmark case MUST have a machine-readable logical record equivalent to the following schema:

| Field | Requirement |
|---|---|
| `case_id` | Stable logical identity |
| `case_version` | Monotonic version of the case definition |
| `family` | `runtime` or `ai-efficiency` |
| `semantic_contract` | Observable behavior that all compared forms MUST preserve |
| `inputs` | Fixed, generated-by-seed, or externally versioned inputs |
| `target_set` | Targets on which the case is valid |
| `build_policies` | Exact optimization/cost policies to measure |
| `baselines` | Required comparison implementations or representations |
| `metrics` | Metrics collected for this case |
| `oracle` | Method for determining semantic correctness |
| `measurement_protocol` | Runs, warm-up, reset, timing, and aggregation rules |
| `exclusions` | Predeclared reasons a run may be invalid |
| `environment` | Required hardware/software metadata |
| `artifacts` | Hashes or identities of source, graph, binary, target, and toolchain objects |
| `notes` | Non-normative observations only |

A result MUST identify the exact case version. Changing inputs, semantic requirements, baseline flags, target configuration, or metric procedure creates a new case version.

Benchmark records MUST separate measured data from program semantics. Profile information MUST NOT silently mutate the semantic identity of the workload.

---

## 4. Runtime and compiler benchmark family

### 4.1 Required metrics

Where meaningful for a case, XAX runtime/compiler benchmarking MUST collect:

| Metric | Measurement rule |
|---|---|
| Execution time | Wall-clock or cycle-based duration under a declared protocol |
| Throughput | Completed work per declared time unit |
| Tail latency | At minimum the declared high-percentile latency for latency-sensitive cases |
| Code size | Relevant emitted text plus separately reported required static data |
| Peak memory use | Maximum benchmark-attributable memory consumption |
| Dynamic allocations | Count and total bytes, when allocation exists |
| Startup cost | Entry-to-ready or entry-to-completion cost for startup-sensitive cases |
| Interrupt latency | Hardware event to required handler milestone for real-time cases |
| Compile time | End-to-end and, when available, stage-attributed compilation time |
| Compiler peak memory | Maximum compiler memory attributable to the build |
| Target-cost estimate | Predicted target cost using the selected target cost function |
| Measured target cost | Empirical counterpart to the predicted objective where observable |

A benchmark MUST report `not_applicable` rather than inventing a zero for a metric that the workload does not exercise.

### 4.2 Build-policy separation

At minimum, results SHOULD distinguish:

- fast-development compilation;
- normal optimized compilation;
- size-oriented compilation where relevant;
- high-effort search/optimization compilation where enabled.

Compilation effort MUST be included in the result. A high-effort optimizer result MUST NOT be compared against a baseline's low-effort build while hiding the difference.

### 4.3 Optimized C and Rust comparisons

A case comparing XAX with C or Rust MUST:

1. use semantically equivalent algorithms and externally observable behavior;
2. document the compiler version and exact optimization/link flags;
3. permit normal whole-program and link-time optimization when the compared environment normally supports it;
4. prohibit intentionally degraded baseline code;
5. report required runtime or library components when they affect startup, size, allocation, or memory;
6. distinguish language/runtime overhead from algorithmic differences where practicable.

The benchmark suite MUST NOT require C or Rust when the case cannot be expressed fairly without changing the semantic contract.

### 4.4 Hand-written assembly comparisons

Assembly comparisons are valid only for selected kernels where a credible expert implementation, published reference, vendor implementation, or otherwise independently reviewable sequence exists.

XAX MUST NOT claim universal superiority over assembly. Assembly results define specific comparison points for a declared machine, workload, and objective.

If assembly uses target-specific assumptions, alignment, vector width, unavailable instructions, relaxed semantics, or restricted inputs, XAX MUST receive the same permitted assumptions before the comparison is considered fair.

### 4.5 Target-cost estimate accuracy

For cases with a target cost model, the suite MUST preserve both predicted and measured values.

Accuracy MUST be evaluated in at least two ways:

- **ordering accuracy:** whether lower predicted cost generally corresponds to lower measured cost among candidate variants;
- **magnitude error:** the normalized difference between predicted and measured cost after applying the declared unit mapping.

The cost model is not validated merely because it predicts the final chosen program well. Candidate sets used for validation MUST contain materially different legal implementations so that ranking quality is testable.

If an objective such as energy or deterministic latency cannot be measured credibly on a target, the benchmark MUST mark that objective unvalidated for that target.

### 4.6 Runtime anti-cherry-picking rules

Before comparative execution, the benchmark corpus, target set, build policies, baselines, and primary metrics MUST be fixed for the suite version.

All valid cases in the declared corpus MUST be reported. Failures, regressions, timeouts, unsupported cases, and verifier rejections MUST appear in aggregate results.

A result summary MUST NOT:

- publish only favorable targets;
- remove slow cases after seeing results;
- tune XAX per case while denying equivalent permitted tuning to baselines;
- compare different semantic contracts;
- use a faster algorithm only on one side without identifying it as an algorithm comparison;
- hide compile-time or memory costs of expensive optimization modes;
- combine results from materially different hardware as though they were one measurement.

Exploratory experiments MAY be reported, but MUST be labeled exploratory and kept separate from preregistered suite results.

---

## 5. AI-efficiency benchmark family

### 5.1 Required representations

The first decisive AI benchmark family MUST compare the same semantic tasks using:

1. C-like text;
2. conventional SSA text;
3. compact graph packets;
4. tokenizer-native XAX transactions.

The tokenizer-native arm is valid only when the benchmark model/tokenizer actually supports the declared dedicated vocabulary or equivalent integration. Until then it MUST be marked unavailable, not approximated with invented results.

### 5.2 Required task classes

The initial corpus MUST include at least:

- creation of small valid programs;
- single-literal edits;
- operation substitutions;
- control-flow edits;
- type-changing edits;
- repair after a verifier-detectable type error;
- local optimization tasks;
- edits in projects whose unrelated size increases while the edited semantic neighborhood remains fixed.

Each task MUST define the requested semantic end state independently of representation.

### 5.3 Required metrics

For every attempted task, record:

| Metric | Definition |
|---|---|
| Input tokens | Total model input tokens attributable to the task |
| Output tokens | Total generated model tokens attributable to the task |
| Total tokens | Input plus output across initial and repair turns |
| Successful-change tokens | Total tokens divided by successful semantic changes |
| Local-context size | Bytes, tokens, and semantic entity count supplied |
| Invalid generation rate | Fraction of initial outputs that cannot produce a valid candidate transaction/form |
| Repair iterations | Additional model attempts required before success or terminal failure |
| Semantic entities transmitted | Distinct semantic objects exchanged |
| Transaction size | Bytes and tokens of committed or attempted mutation payloads |
| Commit conflict rate | Fraction rejected because the expected base state is stale or conflicted |
| Context growth | Change in required task context as unrelated project size increases |
| Task success rate | Fraction satisfying verifier and behavioral oracle within the declared attempt limit |

Token accounting MUST use the exact tokenizer used by the evaluated model.

### 5.4 Context-scaling experiment

To test repository-size independence, a benchmark MUST hold the requested local edit constant while increasing unrelated project content.

The primary observation is the growth of task-attributable context, not total repository bytes.

A successful local-query architecture SHOULD exhibit context growth governed mainly by the semantic dependency neighborhood rather than by total repository size. Any benchmark harness that serializes the full project into every model request invalidates this measurement.

### 5.5 Fairness across representations

Every representation arm MUST receive the same semantic task, behavioral oracle, attempt budget, and access to equivalent diagnostic information to the extent that its representation can express it.

Representation-specific instructions MAY describe syntax or protocol mechanics, but MUST NOT leak the desired solution to only one arm.

If one representation requires regeneration of a larger unit because it lacks local mutation, that cost is part of the result and MUST NOT be normalized away.

Model, sampling policy, context limit, tokenizer, and tool-access policy MUST be identical across arms unless the experiment explicitly studies one of those variables.

---

## 6. Global benchmark invariants

The following are normative:

1. Correct semantics precede performance measurement.
2. Invalid programs do not receive fabricated performance values.
3. Meaning-equivalent workloads are required for direct performance claims.
4. Benchmark cases and results are content/version identified.
5. Every published aggregate retains access to per-case outcomes.
6. Failed and unsupported cases remain visible.
7. Measured profile data is not canonical program semantics.
8. AI-efficiency results account for repair turns, not only the final successful output.
9. Runtime results account for compilation effort when optimization effort differs.
10. No benchmark result may be generalized beyond its measured targets, workloads, objectives, models, or tokenizers.
11. A representation that emits fewer bytes but causes more model tokens or more repair attempts is not presumed superior.
12. A compiler transformation is credited only when the resulting program passes the case oracle and verifier requirements.

---

## 7. Invalid or rejected alternatives

**Source-character count as the primary AI metric** is rejected because XAX optimizes model effort, not human-visible brevity.

**Single-number “performance” scores** are rejected as the normative result because latency, throughput, size, memory, startup, compilation cost, and deterministic behavior represent different objectives.

**Best-case-only publication** is rejected because it permits target and workload cherry-picking.

**Comparing against unoptimized baseline builds** is rejected unless the specific benchmark is explicitly about unoptimized development builds.

**Treating tokenizer-native XAX as ordinary compact text** is rejected. Dedicated vocabulary claims require actual tokenizer/model integration and measurement.

**Using the entire repository as model context** is rejected as the default benchmark procedure because it defeats the local semantic workspace architecture being tested.

**Synthetic assembly strawmen** are rejected. Assembly comparisons require credible, target-relevant implementations.

**Benchmark-specific semantic weakening** is rejected unless every compared implementation is granted the identical relaxed contract.

**Simulated benchmark outcomes** are forbidden. Missing implementation capability produces an unavailable benchmark, not an estimated result.

---

## 8. Interfaces and subsystem dependencies

Stage 17 depends on stable contracts from the surrounding XAX architecture:

- the semantic graph and operation model define what constitutes equivalent program meaning;
- the type, memory, ownership, effect, atomic, and control-flow systems define verification obligations;
- canonical serialization and Merkle identity define benchmark artifact identity and reproducibility;
- the AI workspace protocol defines local queries, mutations, diagnostics, transactions, and token accounting boundaries;
- target packages define legal machine operations, ABI constraints, lowering behavior, and cost models;
- compiler and optimizer stages expose compile-time attribution and candidate selection;
- package/build semantics identify dependency and build-policy state;
- self-hosting milestones determine when XAX can measure its own toolchain without an external permanent language layer.

A benchmark harness MAY exist outside the trusted core, but benchmark inputs, policies, results, and artifact identities SHOULD be representable as XAX semantic data once the required facilities exist.

---

## 9. Staged implementation roadmap

A milestone is complete only when all exit criteria are met. “Benchmark becomes valid” means the implementation is mature enough for that benchmark to produce meaningful measurements; it does not imply any favorable result.

| Milestone | Required capability | Exit criteria | Benchmarks that become valid |
|---|---|---|---|
| 1 | Minimal semantic store and verifier | Canonical objects can be created, identified, loaded, verified, rejected deterministically, and round-tripped without semantic change | Store size, verifier throughput, serialization cost, malformed-object rejection; no runtime performance claims |
| 2 | Arithmetic, functions, branches | Typed constants, integer arithmetic, functions, calls, block parameters, branches, and returns verify and execute through an initial reference path | Small-program correctness; representation creation/edit tasks; basic compile-time accounting |
| 3 | Stack memory | Explicit stack storage, address calculation, load/store, alignment, bounds/provenance obligations, and stack layout verify correctly | Stack footprint, load/store kernels, no-allocation tests, memory-safety diagnostic tasks |
| 4 | First direct native backend | One target package lowers the milestone-3 subset to directly emitted native object/executable bytes without a required permanent external backend | Native execution time, code size, startup, compile time, first C/Rust comparisons on supported subset |
| 5 | Second architecturally different backend | The same semantic subset compiles through a second materially different target package without changing fundamental XAX semantics | Cross-target portability, target-description adequacy, target-cost comparison on both targets |
| 6 | Transactional AI workspace | Query, local handles, mutation, verification, stale-base rejection, structured diagnostics, and commit operate transactionally | C-like vs SSA vs graph-packet AI benchmarks; local-edit token cost; repair turns; context-growth tests |
| 7 | Resources and effects | Linear resource states, explicit release/transfer, effect domains, and associated verifier obligations are implemented | Resource-lifetime tasks, effect-reordering tests, hidden-operation checks, AI repair of resource/effect violations |
| 8 | Atomics and real-time profiles | Atomic ordering, fences, target capability checks, interrupt-relevant semantics, and bounded real-time profile restrictions exist | Atomic kernels, synchronization cost, interrupt latency, deterministic-latency cases on capable hardware |
| 9 | Compile-time specialization | Deterministic bounded compile-time XAX execution can construct/specialize semantic values and erase unused abstraction | Specialization compile cost, generated-code impact, generic/specialization AI tasks |
| 10 | Package and build semantics | Content-addressed package graphs, dependency identity, reproducible build configuration, and supply-chain checks are usable | Reproducible-build tests, dependency/build incrementality, package-context AI tasks |
| 11 | Self-hosting subset | A declared subset of compiler/tooling functionality is implemented in XAX and can rebuild that subset through the supported bootstrap path | Bootstrap size/time, subset self-build reproducibility, comparison of hosted vs bootstrap behavior |
| 12 | Optimizer expansion | Interprocedural optimization plus at least one higher-effort search/equality or superoptimization path operates with translation/equivalence validation where required | Optimization-quality corpus, compile-time/performance tradeoffs, target-cost-estimate accuracy, assembly kernel comparisons |
| 13 | GPU/accelerator path | A non-CPU accelerator target/package path expresses memory spaces, target operations, lowering, and executable deployment without changing fundamental semantics | Accelerator throughput/latency, host-device memory effects, target-model portability, GPU-kernel code quality |
| 14 | Self-hosting completion | The intended compiler services, optimizer, target definitions, linker/package/build tooling required by the architecture can be maintained in XAX, with no permanent second implementation language required by normal operation | Full self-build, whole-toolchain reproducibility, complete compile-time/resource accounting, end-to-end AI-native maintenance benchmarks |

Progression is monotonic in semantic obligation, not necessarily in implementation code size. A later milestone MUST NOT invalidate the semantics or benchmark identities of earlier valid cases without a versioned architectural change.

---

## 10. Open issues requiring implementation evidence

### 10.1 Tokenizer-native vocabulary

The exact dedicated token inventory cannot be fixed normatively before measurement with candidate models and tokenizers. The architecture fixes the objective—minimum model tokens per successful semantic mutation—but the vocabulary itself remains benchmark-selected.

### 10.2 Target-cost magnitude calibration

Target packages can define structural cost models before hardware measurement, but the stable mapping from predicted cost units to measured cycles, latency, energy, or other physical units requires empirical calibration per target and environment. Ordering accuracy can still be tested before absolute calibration is trusted.

No other benchmark rule in this stage is intentionally left open.

---

## 11. Falsification criteria

This design MUST be reconsidered if reproducible future measurements establish any of the following:

1. **AI transaction failure:** compact graph transactions and, when actually available, tokenizer-native transactions do not materially reduce total tokens per successful semantic change versus source or SSA regeneration after repair costs are included.
2. **Context-scaling failure:** local XAX editing requires context that grows approximately with total unrelated project size rather than the dependency neighborhood.
3. **Portability failure:** adding a second architecturally different native target requires changes to fundamental XAX program semantics instead of target/platform packages.
4. **Cost-model failure:** target cost estimates fail to rank materially different candidate implementations well enough to guide optimization, even after target-specific calibration.
5. **Code-quality failure:** across a preregistered fair corpus, generated native code remains materially worse than optimized C/Rust or credible assembly references for the selected objectives despite reasonable optimizer maturity and compilation effort.
6. **Zero-runtime failure:** workloads that semantically require no allocator, scheduler, libc, GC, reference counting, or other runtime nevertheless acquire such dependencies from the language/toolchain.
7. **Transaction-locality failure:** small semantic edits routinely rewrite or retransmit unrelated program regions because content identity or workspace transactions are too coarse.
8. **Verification-cost failure:** exact semantic verification becomes so globally coupled that routine local edits cannot be checked incrementally at practical cost.
9. **Optimization-trust failure:** aggressive optimization cannot be paired with sufficient translation validation, equivalence checking, or other correctness evidence for the transformations that require it.
10. **Self-hosting continuity failure:** completing self-hosting requires a permanently maintained second language, target DSL, build DSL, or package DSL that becomes architecturally authoritative.

A falsified claim MUST be recorded as such. Benchmark definitions MUST not be changed after results merely to preserve a preferred architectural conclusion.

The governing rule is empirical: XAX's semantic-first design is justified only if measured compiler behavior, generated code, and AI interaction costs support it.

## 12. Universal replacement benchmarks (2026-10-02)

Replacement-level performance claims (R4) follow `XAX_BENCHMARKS.md` §15 and `docs/18_UNIVERSAL_REPLACEMENT.md` §15. The first recorded comparison is U1 Linux `filestat` against `gcc -O2` and `gcc -O2 -static` (MEASURED; XAX 6.2× slower, smaller artifact than static glibc, lower peak RSS). AI-efficiency claims (R5) require real model trials; offline tokenizer counts never establish R5.

