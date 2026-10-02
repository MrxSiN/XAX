# XAX Optimizer, Lowering, Code Generation, and Cost Model

## 1. Purpose and scope

This document defines the canonical XAX performance pipeline from a verified semantic graph to a target artifact.

It covers:

- specialization and normalization;
- local, global, and interprocedural optimization;
- constant folding, dead-code elimination, CSE/GVN, SROA, escape analysis, devirtualization, vectorization, and loop transforms;
- equality saturation where justified;
- profile-guided optimization with profiles kept non-semantic;
- bounded superoptimization and instruction search;
- correctness by verified rules, proof, equivalence checking, or translation validation;
- target lowering, legalization, and instruction selection;
- scheduling and register allocation;
- code layout, encoding, relocation, and emission;
- optimization policy and compile-time budgets;
- cost objectives and a machine-cost API.

The authoritative input is the verified XAX semantic graph. The output is a target artifact whose observable behavior is equivalent under the selected target, ABI, platform, capability, and build-policy constraints.

Human source structure is not preserved because it is not authoritative XAX meaning. Optimization MUST preserve semantics, not human formatting, naming, or statement shape.

Optimization and lowering MUST NOT invent hidden allocation, synchronization, syscalls, initialization, ownership transfer, exception edges, scheduler interaction, or other runtime behavior not permitted by the input program and selected environment.

---

## 2. Normative definitions

| Term | Definition |
|---|---|
| **normalization** | Deterministic rewriting into constrained semantic forms that reduce equivalent graph shapes. |
| **specialization** | Refinement using compile-time-known values, types, targets, capabilities, or policies. |
| **optimization** | A semantics-preserving transformation intended to improve declared cost objectives. |
| **legalization** | Conversion of valid XAX semantics into forms representable by the selected target. |
| **lowering** | Replacement of abstract operations with more target-specific semantic or machine operations. |
| **instruction selection** | Choice of target machine operations implementing lowered semantics. |
| **schedule** | Legal machine-operation ordering under dependency and target constraints. |
| **register allocation** | Assignment of machine values to registers or legal compiler-managed storage. |
| **cost objective** | Metric or metric set that compilation is requested to minimize or constrain. |
| **cost estimate** | Predicted cost derived from a model without executing the final artifact. |
| **measurement** | Empirical result obtained by executing or externally observing generated code. |
| **translation validation** | Post-transformation verification that output preserves input semantics. |
| **equivalence checking** | Proof or bounded proof that two regions have equivalent observable behavior. |
| **superoptimization** | Bounded search for a lower-cost equivalent implementation. |
| **profile data** | Non-semantic execution observations used for profitability decisions. |
| **build policy** | Semantic configuration of objectives, budgets, determinism, and optimization permissions. |

Normative keywords **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** express stage requirements.

---

## 3. Canonical performance pipeline

Conceptually:

```text
verified semantic graph
    -> specialize
    -> normalize
    -> optimize
    -> target-lower
    -> legalize/select
    -> schedule
    -> register-allocate
    -> machine-optimize
    -> layout
    -> encode/relocate
    -> emit
```

An implementation MAY interleave or iterate stages. The semantic contracts remain normative even when concrete pass boundaries differ.

Every target-dependent assumption MUST originate from the selected target package, platform/ABI package, explicit profile evidence, or build policy. Host-machine accidents are not legal compiler facts.

### 3.1 Specialization

Specialization may use:

- compile-time values and types;
- constant arguments;
- known function identities;
- proven resource states;
- target and capability facts;
- ABI/platform facts;
- deterministic compile-time computation.

It MAY inline calls, clone functions, resolve proven indirect calls, simplify aggregates, specialize layouts, eliminate generic abstraction, and select target-capability-specific implementations.

It MUST NOT convert an uncertain runtime fact into a compile-time assumption.

Build policy MUST be able to bound specialization by compile time, graph growth, clone count, and code-size growth.

### 3.2 Normalization

Normalization SHOULD cover:

- constant canonicalization;
- equivalent comparison forms;
- branch and block canonicalization;
- aggregate construction/extraction simplification;
- address-expression normalization;
- conversion normalization;
- redundant block-parameter removal;
- reconstructible effect-edge simplification.

Normalization MUST preserve exact arithmetic behavior, floating-point rules, trapping behavior, memory provenance, effects, resource state, and target-visible semantics.

---

## 4. Target-independent optimization

The optimizer operates on semantic facts rather than textual patterns.

A production optimizer SHOULD support, when legal:

| Family | Required condition |
|---|---|
| constant folding | required inputs and operation semantics are known |
| dead-code elimination | values and effects are provably unobservable |
| CSE / GVN | operations are semantically equivalent and effect ordering permits reuse |
| SROA | decomposition preserves visible layout, provenance, and alias behavior |
| escape analysis | relevant escape boundaries are represented and proven |
| devirtualization | callee identity is proven or guarded by explicit semantics |
| load/store forwarding | provenance, alias, volatility, and ordering rules permit |
| CFG simplification | observable control behavior is preserved |
| loop transforms | dependencies, traps, effects, and resource lifetime remain legal |
| vectorization | scalar semantics are preserved under the active arithmetic/FP contract |
| interprocedural propagation | external contracts and call-graph assumptions remain valid |

No pass is required when its preconditions cannot be established.

### 4.1 Deadness

A node is dead only if removal cannot change:

- returned values;
- visible memory;
- I/O;
- atomics or fences;
- traps;
- resource acquisition/release;
- target-visible state;
- device or privileged effects;
- deterministic-latency constraints explicitly selected by policy.

An effectful operation is not dead merely because its result is unused.

### 4.2 CSE and GVN

Semantic equivalence may depend on:

- opcode and operands;
- type;
- overflow mode;
- floating-point mode;
- provenance and alias facts;
- effect domain;
- attributes;
- target mode;
- proof assumptions.

Operations with different trapping, rounding, ordering, provenance, or capability behavior MUST NOT be merged.

### 4.3 Escape analysis and SROA

Escape analysis MAY prove storage or aggregates local to a region, function, thread, device, or other semantic boundary.

SROA or allocation elimination MAY replace such storage with values when address identity, lifetime, placement, provenance, and externally visible memory behavior remain unchanged.

### 4.4 Loop and vector optimization

Permitted transforms include canonicalization, peeling, unrolling, interchange, fusion, fission, unswitching, invariant-code motion, induction rewriting, strength reduction, and vectorization.

Legality is determined by data dependencies, explicit effects, alias/provenance facts, traps, atomics, and resource lifetime.

Profile data MAY affect profitability but never legality.

### 4.5 Interprocedural optimization

Closed-world or whole-program compilation MAY perform global constant propagation, global DCE, aggressive inlining, function merging, clone specialization, devirtualization, calling-convention specialization, internal ABI rewriting, and global layout optimization.

Externally visible ABI, symbol, relocation, and platform contracts MUST remain intact unless the compilation world proves they may change.

---

## 5. Equality saturation

Equality saturation MAY be applied where many rewrite orders compete and the semantics admit a tractable equational model.

It is not a universal optimizer representation.

Its rewrite system MUST encode exact operation semantics. Identities valid only for wrapping arithmetic cannot be applied to checked arithmetic. Floating-point rewrites must respect the selected FP contract. Effects, memory, resources, traps, and opaque target operations must either be modeled safely or excluded.

Build policy MUST bound equality saturation by one or more of:

- node count;
- rewrite count;
- memory budget;
- compile-time budget;
- extraction iterations.

If search fails or yields no improvement, the original legal graph remains available.

---

## 6. Profile-guided optimization

Profile data is non-semantic.

It MAY contain:

- block and edge frequencies;
- branch probabilities;
- call-target frequencies;
- value distributions;
- allocation frequency;
- cache or hardware-counter observations;
- latency samples.

Profiles MAY influence inlining, cloning, layout, unrolling, vectorization, instruction selection, register-allocation priorities, and superoptimization candidate selection.

Profiles MUST NOT legalize an otherwise invalid transformation.

Profile records SHOULD identify program version, target, build policy, workload, collection method, measurement environment, and statistical metadata. Stale or mismatched profiles MAY be rejected or down-weighted.

---

## 7. Correctness of transformations

Every transformation MUST have an explicit correctness mechanism.

Permitted mechanisms are:

1. a small verifier-checked canonical rule;
2. a mechanically checked proof;
3. equivalence checking;
4. translation validation;
5. conservative pattern legality with verified preconditions;
6. target-package semantic expansion validated against its contract.

High-risk and search-generated transformations SHOULD prefer equivalence checking or translation validation so the optimizer itself need not be trusted.

A failed proof or validation MUST reject the candidate transformation. It MUST NOT weaken semantics to make the transformation pass.

---

## 8. Target lowering, legalization, and instruction selection

The target package supplies:

- legal machine value types;
- register classes and constraints;
- instruction semantics and encodings;
- memory spaces and addressing forms;
- atomic capabilities;
- calling conventions;
- relocations;
- scheduling resources;
- legalizations;
- cost information.

### 8.1 Legalization

Unsupported operations MAY be lowered by:

- splitting or widening values;
- scalarizing vectors;
- expanding into legal operation sequences;
- rewriting addressing modes;
- lowering atomics to legal target sequences;
- calling explicitly available helper routines.

Legalization MUST NOT silently introduce a runtime dependency absent from the selected environment.

For bare-metal builds, helper routines exist only if selected through program, target, platform, or package semantics.

### 8.2 Instruction selection

Instruction selection MAY use pattern matching, dynamic programming, target-provided rules, equality saturation, or bounded search.

Selected instructions MUST satisfy target-defined restrictions including:

- operand classes;
- immediate ranges;
- implicit/fixed operands;
- tied operands;
- memory forms;
- alignment;
- flags;
- privilege;
- encoding availability;
- control-flow behavior.

Multi-instruction selection SHOULD be permitted where independently selected instructions produce worse cost.

---

## 9. Scheduling and register allocation

### 9.1 Scheduling

Scheduling MUST honor:

- data dependencies;
- effect dependencies;
- control dependencies;
- memory ordering;
- atomics/fences;
- fixed machine-resource hazards;
- target issue/bundle restrictions;
- correctness-relevant latency constraints.

Profitability MAY consider latency, throughput, critical path, register pressure, code size, energy, and deterministic latency.

Targets MAY expose multiple microarchitecture scheduling models for the same ISA.

### 9.2 Register allocation

Allocation MUST support:

- register classes;
- subregister relations;
- fixed and reserved registers;
- register tuples;
- call-clobbered/preserved sets;
- tied operands;
- target-specific allocation constraints.

Spilling is a compiler machine transformation, not a language allocation. Spill slots MUST obey target stack, alignment, address-space, and ABI rules.

The allocator MUST NOT assume spill memory exists. If the selected target forbids spilling and no legal assignment exists, compilation fails unless another legal target strategy is available.

---

## 10. Machine optimization and bounded superoptimization

After selection and allocation, target-specific optimization MAY perform:

- peephole rewriting;
- redundant-move elimination;
- branch shortening;
- addressing-mode folding;
- flag reuse;
- post-allocation scheduling;
- machine-level CSE where legal;
- spill/reload optimization;
- target-specific instruction substitution.

Bounded superoptimization MAY search selected high-value regions using instruction sequences, algebraic rewrites, addressing forms, constant synthesis, or register-use variants.

Candidate regions SHOULD be chosen using semantic size, profile hotness, bottleneck evidence, and expected value.

Search MUST be bounded by build policy.

Every accepted search result MUST pass equivalence checking, translation validation, or an equally strong verifier-approved mechanism. Timeout or proof failure falls back to known-correct code.

Superoptimization is optional and never required for semantic correctness.

---

## 11. Layout, encoding, relocation, and emission

Code layout controls placement of functions, blocks, hot/cold regions, literals, jump tables, and padding.

It MAY optimize for fallthrough, branch range, cache locality, size, page locality, and deterministic address structure, while obeying ABI and relocation constraints.

The target package defines instruction/data encodings. The encoder MUST reject machine operations that cannot be represented.

Relocations remain explicit target-defined records until resolution and MUST preserve symbol identity, relocation kind, addend semantics, width, range, address-space rules, and position dependence.

Relaxation MAY replace a valid encoding with a smaller or faster legal encoding once placement is known.

Final emission MAY produce a raw image, object file, executable, firmware image, or another target-defined binary container.

No external assembler or linker is architecturally required. External tools MAY be used during bootstrap but are not part of the final required architecture.

---

## 12. Optimization policy and compile-time budget

Optimization policy is semantic build configuration, not program meaning.

A policy SHOULD define:

```text
objectives
objective weights or priority
compile-time budget
optimizer memory budget
code-growth budget
whole-program scope
profile policy
search budget
proof/validation level
determinism requirement
diagnostic/debug preservation policy
```

Conceptual policy classes may include minimum-compile, balanced, size, speed, deterministic-latency, and exhaustive modes. These names have no normative meaning unless mapped to explicit settings.

An implementation MUST expose the actual selected policy as machine-readable data.

Expensive optimization MUST be interruptible at policy boundaries while retaining a correct fallback result.

---

## 13. Cost objectives and machine-cost API

A target SHOULD provide models where possible for:

- latency;
- throughput;
- binary size;
- working memory;
- energy;
- deterministic latency.

A cost may be scalar, vector-valued, constrained, weighted, or lexicographically ordered.

Examples:

```text
minimize latency
subject to code_size <= S
```

```text
lexicographically minimize:
    deterministic_latency
    code_size
```

Unknown cost MUST be representable as unknown.

The compiler SHALL expose a machine-readable query conceptually equivalent to:

```text
cost(entity, target, policy, evidence) -> CostReport
```

A `CostReport` SHOULD contain:

```text
entity identity
target identity
policy identity
metric values and units
estimate or measured classification
model identity/version
confidence or uncertainty if available
profile identity if used
benchmark identity if measured
assumptions
```

Estimated and measured values MUST remain distinguishable.

A measurement MUST identify enough workload and environment information to prevent it from being represented as a universal property.

Target packages MUST NOT claim universal real-world performance from analytical estimates alone.

---

## 14. Invariants

1. **Semantic preservation:** every accepted transformation preserves observable behavior under declared assumptions.
2. **No hidden runtime behavior:** optimization and lowering do not introduce undeclared allocation, synchronization, syscalls, initialization, exception edges, scheduler interactions, or ownership transfers.
3. **Explicit target facts:** target-dependent decisions derive from selected target/platform/ABI packages and policy.
4. **Profile non-semanticity:** profiles affect profitability only.
5. **Fallback correctness:** failed search, proof, validation, or cost estimation leaves a known-correct compilation path.
6. **Machine-readable policy:** objectives and budgets are explicit semantic configuration.
7. **Bare-metal viability:** no stage requires an OS, libc, allocator, scheduler, external assembler, or external linker.
8. **No assembly supremacy claim:** XAX may beat particular assembly implementations but cannot guarantee superiority over every possible implementation.
9. **Cost honesty:** estimates and measurements remain distinguishable.
10. **Bounded expensive search:** equality saturation and superoptimization cannot require unbounded resources.
11. **Deterministic mode:** identical semantic inputs, target data, profiles, compiler version, and deterministic policy MUST permit reproducible output.
12. **Verifier authority:** transformations whose obligations cannot be discharged are rejected.

---

## 15. Rejected alternatives

| Alternative | Reason rejected |
|---|---|
| Preserve human source structure | Human source is not authoritative semantics and would constrain optimization without semantic value. |
| Permanent LLVM dependency | Violates direct target definition and direct native emission goals. |
| Hardcode ISAs in the language core | Prevents clean unknown-hardware support and duplicates target-package responsibility. |
| Treat profiles as semantic | Makes meaning depend on empirical history and damages reproducibility. |
| Assume undefined overflow or relaxed FP | Conflicts with exact XAX operation semantics. |
| Universal equality saturation | Poor fit for many effectful regions and can impose excessive cost. |
| Unbounded superoptimization | Makes compile-time resource use uncontrolled. |
| Trust search-generated rewrites | Enlarges the trusted base and risks silent miscompilation. |
| Textual optimizer directives | Introduces a second human-oriented configuration language. |
| Implicit helper runtimes | Invalid for minimal and bare-metal environments unless explicitly selected. |
| Fixed conventional O-level meanings | Objectives and budgets must be explicit, target-aware semantic configuration. |
| Universal “faster than assembly” promise | Not logically supportable and not falsifiable as a universal claim. |

---

## 16. Interfaces with other XAX subsystems

### Semantic graph and verifier

This stage consumes verified types, operations, effects, resources, memory facts, control flow, and proof obligations. Optimizers may strengthen facts but cannot weaken verifier-established obligations.

### Compile-time execution

Compile-time XAX computation supplies specialization results, which re-enter the verified semantic pipeline.

### Memory, ownership, and effects

Alias analysis, SROA, code motion, deadness, and memory optimization depend on explicit provenance, permission, resource, and effect information.

### Target, ABI, and platform packages

Target packages provide machine semantics, encodings, legalizations, register constraints, scheduling data, and cost information. ABI/platform packages provide calling conventions, external contracts, object/executable rules, and relocation policy.

### Semantic database and incrementality

A local semantic change SHOULD invalidate only analyses, optimized regions, machine fragments, and cost records dependent on changed facts.

Cache keys MUST include every semantic dependency that can affect generated output, including target, policy, profile identity, and relevant compiler-model identity.

### Serialization and workspace

Optimized or lowered artifacts MAY be content-addressed.

The AI workspace MAY query cost, optimization decisions, proof status, hot regions, selected instruction sequences, register pressure, code size, and failed legality reasons. Machine data is preferred over mandatory prose.

---

## 17. Open issues requiring implementation evidence

### 17.1 Universal machine-level representation

It remains open whether all targets should share one machine-level graph or target packages should define more specialized machine forms. The choice depends on verifier complexity, target extensibility, optimizer quality, and implementation volume.

### 17.2 Global optimizer organization

The architecture does not yet choose a conventional pass pipeline, demand-driven rewriting, equality-saturation hybrid, or another organization. Compile time, incrementality, implementation complexity, and generated-code quality must decide.

### 17.3 Cost-model calibration

The interface is fixed, but statistical models for latency, throughput, energy, and deterministic latency require real target measurements.

### 17.4 Proof granularity

The appropriate split among trusted rewrite rules, proof objects, solver-backed equivalence, and translation validation must be established by trusted-core size and compile-time evidence.

---

## 18. Falsification criteria

This design must be revised if implementation or benchmarking shows any of the following:

1. Equivalent programs consistently produce materially worse machine code because the semantic graph lacks optimization-relevant facts.
2. Substantially different architectures require target-specific compiler hardcoding beyond generic algorithms, showing the target model is insufficient.
3. Equivalence checking or translation validation is too expensive to protect high-risk transformations under realistic expensive-build budgets.
4. Equality saturation yields no material wins while consuming substantially more memory or compile time than simpler rewriting.
5. Bounded superoptimization rarely improves high-value regions or costs more than its runtime savings justify.
6. Target cost models rank candidate implementations poorly relative to measured results.
7. Profile mismatch routinely causes severe regressions, showing profile confidence or policy controls are inadequate.
8. Small semantic edits routinely trigger broad recompilation despite narrow dependency changes.
9. Minimal bare-metal output still requires hidden runtime machinery.
10. Deterministic builds with identical semantic inputs, target data, profiles, compiler version, and policy are not reproducible.
11. Expensive optimization cannot be stopped at budget boundaries while retaining a correct fallback.
12. Known hand-written assembly consistently dominates well-modeled hot regions despite sufficient search and optimization budget, indicating deficiencies in selection, scheduling, allocation, search, or cost modeling.

The stage succeeds only if optimization quality, correctness, target extensibility, and compile-time cost remain independently measurable while preserving the core rule: **meaning is source**.
