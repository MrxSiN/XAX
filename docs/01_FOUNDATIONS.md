# XAX Stage 01 — Foundations, Normative Vocabulary, and Invariants

## 1. Purpose and scope

This document defines the normative foundation that every later XAX specification, implementation, target package, library, tool, and protocol MUST preserve unless a later architecture revision explicitly replaces a rule stated here.

XAX is an AI-native programming language architecture whose authoritative programs are canonical semantic structures rather than human-oriented source text. The governing principle is:

> **Meaning is source.**

The canonical program is the semantic program representation itself. Human-readable notation, diagnostics, visualizations, dumps, interchange views, and debugging forms are projections of that representation; none becomes authoritative merely because a human can read or edit it.

This stage fixes the meaning of the architecture’s top-level goals, non-goals, vocabulary, requirement priorities, feasibility boundaries, and cross-stage invariants. It intentionally does **not** define the detailed semantic graph, type system, binary encoding, optimizer, target instruction model, compiler implementation, or AI transaction protocol. Later stages own those details, subject to the constraints in this document.

The foundation prevents later subsystems from reintroducing conventional source-language assumptions, separates requirements from implementation choices, makes ambitious goals measurable, and preserves applicability from bare metal through large applications.

---

## 2. Normative language and statement classes

### 2.1 Normative keywords

The keywords **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** are normative when written in uppercase.

| Keyword | Meaning |
|---|---|
| **MUST** | Required for conformance. A violation is an architectural incompatibility unless an explicit future revision changes the requirement. |
| **MUST NOT** | Prohibited for conformance. |
| **SHOULD** | Strong default. Deviation is permitted only when a concrete reason is documented and the higher-priority requirements remain satisfied. |
| **SHOULD NOT** | Strong prohibition. Deviation requires documented justification. |
| **MAY** | Optional behavior or implementation freedom. |

Lowercase uses such as “must” or “may” in explanatory prose are non-normative unless the sentence is explicitly marked normative.

### 2.2 Statement classes

Every specification statement belongs conceptually to one of these classes:

| Class | Role |
|---|---|
| **Invariant** | Cross-stage architectural rule that later specifications MUST preserve. |
| **Requirement** | Behavior or property required of a conforming component. |
| **Recommendation** | Preferred design choice that can be overridden with justification. |
| **Permission** | Explicitly allowed behavior that is not required. |
| **Definition** | Fixed meaning of a term used by the specification. |
| **Objective** | Measurable direction for optimization or evaluation, not an unconditional guarantee. |
| **Non-goal / anti-goal** | Property XAX intentionally does not optimize for or architecture it intentionally rejects. |
| **Open issue** | Decision deferred because evidence from implementation or benchmarking is required. |

A later document MUST NOT convert an objective into a claimed guarantee without evidence. It MUST NOT weaken an invariant merely by choosing a different implementation technique.

---

## 3. Foundational model

### 3.1 XAX

**XAX** is a canonical semantic programming system designed primarily for machine generation, querying, modification, verification, optimization, specialization, lowering, and compilation.

A conforming XAX program is authoritatively represented as typed semantic structure exposing behavior required to determine meaning, subject only to explicit target-defined semantics.

XAX is not defined as a human-written textual language. Human-oriented notation MAY support inspection, debugging, or diagnostics, but MUST NOT become canonical source through convenience.

### 3.2 AI-native

**AI-native** means the architecture is optimized for machine reasoning and semantic mutation rather than human typing conventions.

An AI-native XAX workflow SHOULD minimize:

- total model tokens per successful semantic change;
- context required to understand a local task;
- invalid mutations;
- repair iterations;
- redundant retransmission of unchanged semantics;
- ambiguity in generated program meaning.

AI-native does **not** require a particular model, tokenizer, transport, or autonomous agent. Machine clients are first-class; human textual authoring is not required.

### 3.3 One language

**One language** means XAX MUST NOT depend on a second permanently maintained programming language or domain-specific language for essential semantic domains such as target descriptions, build configuration, package semantics, compile-time computation, or generated program construction.

Temporary bootstrap languages, imported ABI descriptions, human-facing query syntaxes, diagnostics, protocol encodings, and external object/executable formats are allowed. They become prohibited additional languages only if they evolve into authoritative program-semantic sources that XAX itself cannot express.

### 3.4 No human involvement

**No human involvement** is an architectural capability claim, not a prohibition on humans.

A conforming mature toolchain MUST be capable, after bootstrap, of allowing machine agents to construct, inspect, verify, benchmark, mutate, compare, and commit XAX programs without requiring human source-code authoring, naming, formatting, code review, target-backend authoring, or build-file authoring as a mandatory representational step.

Humans MAY specify goals, constraints, policies, hardware requirements, and acceptance criteria; human approval MAY also be imposed by policy. None becomes a semantic requirement of the language.

### 3.5 Bare metal

**Bare metal** means a valid deployment MAY consist only of:

- a XAX program graph; and
- a target package sufficient to emit code for the hardware.

XAX MUST NOT require libc, an operating system, a garbage collector, an allocator, a scheduler, a threading runtime, an exception runtime, reference counting, startup libraries, or other ambient software unless the program or target explicitly requires them.

For suitable hardware, direct execution from a reset or entry address into generated instructions MUST be representable.

### 3.6 Universal target

**Universal target** means fundamental XAX semantics are not defined around a fixed list of current processors, operating systems, object formats, or instruction sets.

Hardware- and platform-specific knowledge SHOULD reside in target or platform packages. A new target SHOULD be supportable by supplying semantic descriptions, constraints, lowering rules, encoding rules, ABI information, and related target data without changing the fundamental language merely because an instruction set is new.

Target-package data models MAY evolve, but the separation between target knowledge and language fundamentals MUST remain.

### 3.7 Zero hidden runtime cost

**Zero hidden runtime cost** means runtime behavior MUST NOT appear merely as an implicit consequence of using a language abstraction when that behavior is absent from the authoritative semantics.

In particular, XAX MUST NOT silently introduce:

- allocation;
- deallocation;
- reference counting;
- garbage collection;
- locking or synchronization;
- syscalls;
- scheduler interaction;
- ownership transfer;
- initialization;
- exception edges;
- I/O;
- capability acquisition or release.

An abstraction satisfies this principle only if it is erased before runtime or its runtime semantics are explicit. This does not mean every abstraction is free; it means runtime cost is semantically requested and analyzable.

### 3.8 “Better than assembly”

“Better than assembly” is not a universal semantic guarantee.

XAX MUST NOT claim that generated code is always faster, smaller, or otherwise superior to every possible hand-written assembly program. Assembly can express the instructions available to a machine, so universal dominance is not logically defensible.

The valid objective is cost-directed and measurable:

> For a selected target, workload, semantic contract, and cost function, XAX SHOULD search for generated machine code whose measured or modeled cost is no worse than the best known conforming implementation.

Cost functions MAY include latency, throughput, code size, energy, memory, deterministic latency, or weighted combinations. A superiority claim MUST identify its comparison, target, workload, cost function, and measurement procedure.

---

## 4. Requirement priority

When two design goals conflict, the following priority order governs unless an explicit architecture revision states otherwise:

| Priority | Requirement |
|---:|---|
| 1 | Exact semantics |
| 2 | Minimum AI token expenditure |
| 3 | Minimum probability of AI generation error |
| 4 | Native machine performance |
| 5 | Minimal memory/code footprint |
| 6 | Universal hardware targeting |
| 7 | Determinism |
| 8 | Incremental/local modification |
| 9 | Compiler simplicity |
| 10 | Human usability |

The ordering is normative. A lower-priority property MUST NOT be improved by violating a higher-priority requirement. Human readability, human writability, human-friendly naming, and formatting have zero normative weight; they MAY be useful tooling properties but are not language-design constraints.

---

## 5. Normative definitions

### 5.1 XAX source

**XAX source** is the authoritative canonical semantic program state from which meaning is determined.

Human-readable dumps, pretty-printers, diagrams, debugging views, natural-language explanations, generated pseudo-code, or disassembly are not XAX source unless a future architecture revision explicitly changes the canonical-source model.

### 5.2 Representation

A **representation** is any encoding, view, projection, transport form, cache form, or persisted form of XAX semantics.

A representation MAY be textual or binary. Two forms claiming the same canonical program MUST resolve to the same semantics or be rejected as inconsistent.

### 5.3 Tooling protocol

A **tooling protocol** is a machine-facing interface for querying, constructing, mutating, verifying, testing, benchmarking, comparing, or committing XAX state.

Protocol handles, opcodes, transaction packets, or tokenizer-native tokens MAY differ from persistent serialization if semantic identity and verification are preserved.

### 5.4 Target package

A **target package** is XAX semantic data and computation that describes machine- or platform-specific capabilities and constraints needed for lowering and emission.

Target packages MAY describe machine types, memory spaces, instructions, encodings, registers, calling conventions, formats, atomics, scheduling constraints, costs, legalizations, lowering, and ABI rules. Such knowledge SHOULD NOT be hardcoded into fundamental semantics when it can reside in a target package.

### 5.5 Library

A **library** is reusable XAX semantic content providing abstractions, algorithms, data structures, protocols, frameworks, or runtime services. It is optional unless explicitly depended upon.

### 5.6 Runtime

A **runtime** is executable support code or persistent runtime state beyond direct lowering of explicit operations. XAX has no mandatory general runtime; any runtime dependencies and effects MUST be visible.

### 5.7 Environment

An **environment** is external execution context not defined entirely by the XAX program, such as hardware, firmware, kernels, operating systems, hosts, networks, filesystems, or external processes. Interaction MUST use explicit semantic contracts.

### 5.8 Implementation artifact

An **implementation artifact** is a non-authoritative item used to build or operate XAX, such as bootstrap source, generated tables, test harnesses, profiler data, or host build scripts. It MUST NOT silently become program meaning.

---

## 6. Core architectural invariants

The following invariants constrain all later stages.

### 6.1 Semantic authority

1. The authoritative program MUST be canonical semantic structure, not human-oriented source text.
2. Meaning MUST be derivable from explicit semantics plus explicitly referenced target/environment contracts.
3. There MUST be no unspecified evaluation order where order can affect observable behavior.
4. Semantic transformations MUST preserve observable program meaning.

### 6.2 Explicit behavior

5. External effects MUST be explicit.
6. Resource ownership and transfer MUST be explicit.
7. Storage creation MUST be semantically visible.
8. Hidden allocation, synchronization, syscalls, initialization, reference counting, scheduler interaction, and exception edges are prohibited.
9. Recoverable failure SHOULD be represented as ordinary semantics rather than mandatory implicit language exceptions.
10. Unsafe or obligation-waiving behavior MUST be machine-visible rather than hidden only behind human lexical markers.

### 6.3 Runtime minimality

11. XAX MUST have no mandatory garbage collector, allocator, scheduler, exception runtime, reference-counting runtime, libc, or operating system.
12. Programs that do not require a facility MUST be compilable without linking that facility.
13. Abstractions SHOULD erase when they have no required runtime meaning.

### 6.4 Target separation

14. Fundamental semantics MUST NOT assume x86, Arm, RISC-V, GPUs, a particular OS, or any equivalent fixed target family.
15. Platform-specific knowledge SHOULD reside in target/platform packages.
16. New machine operations MUST have enough semantic contract information to preserve verification and optimization correctness even when their detailed internal behavior is opaque.

### 6.5 AI locality and transactionality

17. AI workflows SHOULD request the smallest semantic neighborhood sufficient for a task.
18. Local edits SHOULD avoid retransmitting unrelated program state.
19. Mutations MUST be machine-verifiable before becoming authoritative.
20. Multi-entity mutation SHOULD be transactional so stale or partially valid edits cannot silently corrupt program state.
21. Diagnostics SHOULD be machine-structured; natural-language explanation is optional presentation.

### 6.6 Language unity

22. Compile-time construction, target description, build semantics, and package semantics MUST remain expressible within XAX’s semantic system rather than requiring permanently separate DSLs.
23. Bootstrap implementation choices MUST NOT redefine the language architecture.
24. Debug and interchange notations MUST NOT become a second normative source language by accident.

### 6.7 Performance and evidence

25. Optimization MUST preserve observable semantics.
26. Performance claims MUST be falsifiable by future testing.
27. Universal superiority over all hand-written assembly MUST NOT be claimed.
28. Token efficiency MUST be evaluated using successful semantic work, not merely serialized byte or character count.
29. Measured profile data MUST remain distinct from program semantics unless explicitly imported as a semantic assumption or policy.

---

## 7. Hard anti-goals

XAX intentionally rejects the following as architectural goals:

| Rejected alternative | Reason |
|---|---|
| A conventional human-first source language as the canonical program | Reintroduces parsing, textual regeneration, formatting churn, naming dependence, and token cost unrelated to semantics. |
| A mandatory parser-generated AST as source authority | The canonical representation is already semantic; a source-language AST would be an unnecessary authoritative layer. |
| Human readability as a language constraint | It conflicts with machine compactness and exactness and has lower priority than every core design objective. |
| Mandatory GC, allocator, scheduler, async runtime, exceptions, or libc | Prevents minimal bare-metal deployment and creates hidden or unavoidable runtime costs. |
| Implicit RAII-style destruction as fundamental semantics | Resource release must be explicit and machine-visible. |
| Implicit exception edges | Calls and control flow must not gain hidden behavior. |
| A permanently separate macro/template/preprocessor language | Compile-time semantics must be expressible using XAX itself. |
| Fixed built-in backends for a closed set of architectures | Violates the universal-target objective and makes future hardware a language change. |
| A second target-description, package, build, or configuration DSL | Violates the one-language principle. |
| Whole-project regeneration for routine AI edits | Wastes tokens and increases generation-error probability. |
| Claims that compact text is automatically token-optimal | Tokenizer behavior and repair rates must be measured empirically. |
| Claims of unconditional superiority to assembly | Not logically defensible and not falsifiable without a defined workload and cost function. |
| Optimization that depends on preserving human source shape | Human source preservation has no normative weight. |

Convenience tooling MAY resemble rejected forms but MUST NOT become authoritative semantics or a mandatory dependency.

---

## 8. Feasibility boundaries

The semantic model MUST support verification, optimization, target lowering, local mutation, and direct native code generation while keeping runtime dependencies explicit and target knowledge separable.

### 8.1 What the architecture does not guarantee

The architecture does not guarantee:

- that every optimization problem is decidable;
- that globally optimal machine code can always be found;
- that every target semantic can be modeled mathematically in full detail;
- that tokenizer-native protocols will outperform all alternatives without benchmarking;
- that content-addressed storage alone eliminates merge conflicts;
- that AI agents never generate invalid programs;
- that verification can prove all desirable properties statically;
- that one target package format will remain sufficient forever;
- that compilation will always be fast.

Where proof is impossible or too expensive, later stages MAY use bounded analysis, conservative rejection, explicit checks, target opacity, or translation validation if observable semantics and explicit-cost rules remain intact.

---

## 9. Interfaces with later XAX subsystems

This stage constrains but does not fully design the following subsystems.

### 9.1 Semantic graph and operation model

The representation MUST be typed, explicit about relationships required for meaning, and suitable for local mutation. Detailed node, block, edge, identifier, and canonicalization rules are deferred.

### 9.2 Type, value, constant, and layout system

Types and layouts MUST support exact semantics, verification, target lowering, and explicit memory behavior; the complete algebra and layout algorithm are deferred.

### 9.3 Memory and resource semantics

Storage creation, ownership, transfer, access obligations, and release MUST be explicit. Detailed pointer, lifetime, allocation, and resource-state rules are deferred.

### 9.4 Effects, control flow, calls, and errors

Observable ordering and effects MUST be explicit enough to prevent hidden behavior. Calls MUST NOT silently add exception edges; detailed domains, control, ABI, and error rules are deferred.

### 9.5 Concurrency, atomics, interrupts, and real-time profiles

XAX MUST expose exact concurrency semantics without assuming one scheduler or framework. Concurrency libraries remain optional; detailed ordering, interrupts, scheduling, and real-time rules are deferred.

### 9.6 Compile-time execution and metaprogramming

Compile-time computation MUST use XAX semantics rather than a second macro/template language. Its execution and specialization details are deferred.

### 9.7 Persistence and AI protocol

Persistence and AI protocols MAY use different encodings but MUST preserve canonical semantics. Token efficiency is empirical; local handles MUST NOT weaken identity or transaction safety.

### 9.8 Compiler and optimizer

The compiler MUST verify required assumptions and preserve observable behavior. It SHOULD support direct native emission without a permanent external backend.

### 9.9 Target/platform packages

Target packages MUST isolate machine-specific facts while exposing enough semantics and constraints for safe lowering, optimization, encoding, and ABI compliance.

### 9.10 Package and build system

Packages, dependency identity, and build configuration MUST remain semantic XAX concepts rather than requiring external authoritative JSON, YAML, TOML, or another package/build language.

---

## 10. Compact glossary and notation

| Term | Meaning |
|---|---|
| **canonical** | The unique authoritative semantic form or equivalence rule designated by the specification. |
| **semantic graph** | The canonical structured program representation; exact structure is defined in a later stage. |
| **observable semantics** | Behavior visible according to the program, target, environment, and declared effect contracts. |
| **effect** | Semantically relevant interaction or ordering domain beyond pure value computation. |
| **resource** | A value whose acquisition, transfer, state, or release requires controlled semantics. |
| **target** | Machine/platform description used for legalization, lowering, scheduling, encoding, ABI handling, and related target behavior. |
| **lowering** | Semantics-preserving translation from target-independent or higher-level semantic operations toward target operations. |
| **specialization** | Compile-time reduction of general semantics using known values, types, targets, or policies. |
| **transaction** | A mutation set checked against an expected program state and committed atomically only if valid. |
| **hidden cost** | Runtime behavior not explicitly represented by authoritative semantics. |
| **AI token expenditure** | Model-context and generated-token cost attributable to accomplishing a semantic task, including repair. |
| **conforming** | Satisfying the applicable MUST/MUST NOT requirements of the specification. |

Notation conventions:

- `X -> Y` denotes conceptual flow, not textual syntax.
- `cost(P, T, C)` denotes a conceptual cost evaluation for program `P`, target `T`, and cost function `C`; it is not defined here as a concrete API.
- Code-font terms are illustrative identifiers unless a later stage declares them canonical symbols.
- Human-readable examples are explanatory projections and MUST NOT be interpreted as normative XAX source syntax.

---

## 11. Open issues

Only questions requiring implementation evidence remain open at this stage.

### 11.1 Token-native protocol threshold

The architecture prefers tokenizer-native semantic transactions if they materially reduce total AI tokens per successful semantic change. The exact protocol, token vocabulary, and break-even threshold cannot be fixed without model/tokenizer benchmarks.

**Required evidence:** controlled comparison against at least conventional source text, SSA-like text, and compact graph transactions across creation, local edits, control-flow edits, error repair, and optimization tasks.

### 11.2 Canonical representation granularity

The foundation requires canonical semantic authority and local mutation, but the ideal granularity of persistent content-addressed objects is not fixed here.

**Required evidence:** implementation measurements of deduplication, mutation locality, verification cost, storage overhead, cache behavior, and merge/conflict behavior.

No other foundation-level decision is intentionally left open.

---

## 12. Falsification criteria

The Stage 01 architecture should be revised if later evidence demonstrates any of the following under representative workloads and honest comparisons:

1. **Semantic ambiguity:** two conforming implementations can assign materially different observable meaning to the same canonical XAX program without an explicit target/environment distinction.
2. **Hidden mandatory runtime:** ordinary valid programs cannot avoid an allocator, GC, scheduler, exception runtime, reference counting, libc, OS service, or equivalent facility even when their semantics do not request it.
3. **Target leakage:** supporting substantially different hardware repeatedly requires changes to fundamental language semantics rather than target/platform packages.
4. **Non-local mutation failure:** small semantic edits inherently require retransmitting or rebuilding unrelated program state at a scale comparable to whole-source regeneration.
5. **AI inefficiency:** after protocol optimization, semantic transactions fail to materially improve total tokens per successful mutation or generation reliability compared with simpler source-based approaches.
6. **Verification incompatibility:** the canonical representation cannot support machine verification of the explicit obligations required for memory, resources, effects, or control semantics.
7. **Optimization obstruction:** canonical semantic choices prevent optimizations available to conventional compiler IRs without providing compensating correctness or AI-efficiency advantages.
8. **Bare-metal failure:** minimal programs cannot be lowered directly to native code for suitable hardware without importing unrelated runtime facilities.
9. **Language fragmentation:** practical use requires permanently maintaining independent macro, target-description, build, package, or configuration languages because XAX cannot express those domains adequately.
10. **Performance-objective failure:** on representative targets, cost-directed compilation consistently cannot approach established optimized compiler or expert assembly baselines because the semantic model withholds essential information or imposes unavoidable overhead.
11. **Token metric mismatch:** minimizing model tokens per successful semantic change proves to be a poor predictor of total autonomous-development cost, reliability, or throughput; if so, the priority metric MUST be revised to the empirically superior measure.
12. **Canonicalization cost failure:** maintaining canonical semantic identity imposes storage, verification, or mutation costs large enough to outweigh its locality, deduplication, and correctness benefits.

A single implementation failure does not falsify the architecture unless it follows from a required Stage 01 invariant or definition rather than an avoidable implementation choice.

---

## 13. Foundation summary

Every later XAX stage MUST preserve the following compact rule set:

- **Meaning is source.**
- Canonical programs are machine-oriented typed semantic structures.
- Exact semantics outrank every other design objective.
- AI efficiency is measured by successful semantic work, not textual brevity alone.
- Human readability, writability, naming, and formatting are non-normative.
- Runtime behavior is explicit or erased; hidden runtime work is prohibited.
- No GC, allocator, scheduler, exception runtime, reference counting, libc, or OS is mandatory.
- Bare-metal direct native deployment is a first-class requirement.
- Target-specific knowledge belongs in target/platform packages.
- XAX remains one semantic language across runtime code, compile-time computation, targets, packages, and builds.
- AI edits are local, machine-verifiable, and preferably transactional.
- Optimization may be aggressive but MUST preserve observable semantics.
- Performance superiority is a measurable objective, never an unconditional claim over all assembly.
- Architectural claims remain subject to falsification by later compiler implementation and benchmarking.
