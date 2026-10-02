# XAX Stage 15 — Bootstrapping, Self-Hosting, Autonomous Development, and Repository Continuity

## 1. Purpose and scope

This stage defines how XAX becomes a self-sustaining implementation ecosystem without acquiring a permanently maintained second implementation language, build DSL, package DSL, linker DSL, assembler DSL, or repository-control language.

The bootstrap is transitional. Its purpose is to reach a state in which the compiler, verifier-facing compiler services, target definitions, object/executable emission, linker functionality, package/build logic, repository transformations, and autonomous-development operations are represented as XAX semantic programs and data.

This stage specifies the trusted seed, migration to an XAX-hosted compiler, self-hosting and closure milestones, target/backend and native emission ownership, bootstrap trust validation, autonomous development, semantic multi-agent merging, canonical repository continuation state, coupled specification/conformance updates, and the criterion for eliminating any independently maintained second implementation language.

This stage does not implement any bootstrap component and does not claim that any milestone has already been achieved.

---

## 2. Normative language

The terms **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** are normative.

### 2.1 Bootstrap seed

A **bootstrap seed** is a temporary implementation capable of producing the first sufficiently complete XAX-hosted toolchain from canonical XAX artifacts.

The seed is not part of the permanent language architecture.

A seed MAY be written in a pre-existing implementation language, assembled from an earlier executable, or produced by another trusted toolchain. Once XAX closure is achieved, the seed MUST be removable from ordinary development, build, release, and target-enablement paths.

### 2.2 XAX-hosted compiler

An **XAX-hosted compiler** is a compiler whose authoritative implementation is represented as XAX semantic program artifacts.

Its executable form MAY be produced by another compiler instance, but its maintained source of truth is XAX semantic state.

### 2.3 Self-hosting

XAX is **self-hosting** when an XAX-hosted compiler can compile the authoritative XAX-hosted compiler implementation into another operational compiler instance for at least one supported bootstrap target.

Self-hosting alone does not imply full toolchain closure or bootstrap independence.

### 2.4 Toolchain closure

**Toolchain closure** is reached when every component required for normal XAX development and release is either:

1. a canonical XAX semantic artifact;
2. canonical non-program semantic data interpreted by XAX programs; or
3. a minimal externally supplied execution substrate explicitly declared by the target environment.

A separately maintained compiler, assembler, linker, build system, package manager, target-description DSL, or repository mutation language violates toolchain closure.

### 2.5 Bootstrap independence

**Bootstrap independence** is reached when a clean release of XAX can be reproduced from retained XAX artifacts and an approved bootstrap binary or equivalent immutable seed artifact without requiring maintenance of the original seed implementation language.

The archived seed MAY remain necessary as a historical trust anchor or first-machine artifact. Its implementation source MUST NOT remain necessary for ordinary evolution of XAX.

### 2.6 Repository root

A **repository root** is a content-addressed root object naming the exact semantic and documentary state of a XAX repository revision.

A root MUST identify all state required to reproduce the revision's declared build and verification meaning.

### 2.7 Continuation state

**Continuation state** is the minimal canonical repository state a new AI session needs to determine what exists, what is authoritative, what is verified, what remains unresolved, and what mutation may safely occur next.

Conversation transcripts are not continuation state.

---

## 3. Bootstrap trust boundary

The permanent trusted foundation SHOULD remain consistent with the XAX trusted-core objective: canonical semantic definitions, graph verification, canonical serialization, minimal target-independent lowering machinery, and enough target encoding capability to construct executable output.

The bootstrap trust boundary is therefore divided into two categories.

| Category | Status | Rule |
|---|---|---|
| semantic definitions | permanent trusted meaning | MUST have canonical versioned identity |
| graph verifier | permanent trusted enforcement | MUST reject malformed or invalid semantic graphs |
| canonical serializer | permanent trusted identity mechanism | MUST produce deterministic canonical encodings |
| minimal lowering/encoding path | permanent or reducible core | MUST be sufficient to reach native output |
| bootstrap seed executable | transitional trust anchor | MAY be retained, MUST NOT define language meaning |
| seed implementation source | disposable bootstrap material | MUST NOT remain normative after closure |
| host compiler/runtime used to build seed | external historical dependency | MUST NOT remain required after bootstrap independence |

The bootstrap seed MUST NOT be permitted to silently redefine XAX semantics. The meaning of accepted XAX artifacts is determined by canonical semantic definitions and verifier rules, not by undocumented seed behavior.

Where the seed and the canonical semantics disagree, the seed is defective.

---

## 4. Minimal bootstrap artifact

A minimal bootstrap distribution SHOULD contain:

```text
BootstrapBundle {
  semantic_spec_root
  verifier_rules_root
  serializer_rules_root
  compiler_program_root
  bootstrap_target_root
  seed_executable
  build_policy_root
  conformance_root
  provenance_record
}
```

Every field MUST name exact content-addressed state or an immutable executable artifact. Together the bundle MUST identify the semantics, verification and serialization rules, authoritative XAX compiler graph, bootstrap target, seed, deterministic build policy, conformance evidence, and seed provenance required for reconstruction.

The bundle MUST NOT require textual source code as the authoritative XAX program representation. Any omitted external prerequisite is part of the bootstrap trust boundary and MUST be declared.

---

## 5. Seed compiler strategy

The seed SHOULD implement the smallest semantic subset capable of compiling the first XAX-hosted compiler. It is a bridge, not the reference implementation.

The seed MUST:

- consume canonical XAX artifacts, or an explicitly bounded representation mapping losslessly to them;
- verify all graph properties required by its accepted subset;
- emit target-native output for at least one bootstrap target;
- reject unsupported semantics explicitly;
- preserve canonical identity rules for persistent objects;
- operate under a fixed reproducible build policy;
- identify rejected semantic entities in machine-readable diagnostics.

Correct verification and sufficient lowering take precedence over optimizer sophistication.

The seed MUST NOT make XAX depend semantically on undocumented host behavior, host-language layouts absent from the target package, a host package manager, a permanent external assembler/linker, or a second target-description language. Any temporary host dependency MUST be recorded in provenance and eliminated before toolchain closure.

---

## 6. Self-hosting milestones

Self-hosting is reached through explicit milestones. A later milestone MUST NOT be claimed solely because an earlier one succeeds.

| ID | Milestone | Required evidence |
|---|---|---|
| B0 | seed viability | seed accepts the required compiler subset and emits a runnable compiler |
| B1 | first XAX compiler | authoritative compiler implementation is XAX semantic state |
| B2 | recursive compilation | XAX compiler can compile its own authoritative program graph |
| B3 | semantic self-equivalence | compiler generations accept/reject required inputs equivalently under fixed policy |
| B4 | deterministic fixed point | repeated self-compilation reaches the required canonical output fixed point |
| B5 | toolchain closure | assembler/linker/object writing/target/build/package paths are XAX-hosted |
| B6 | bootstrap independence | no independently maintained second implementation language is required |

### 6.1 Fixed-point rule

Under a deterministic bootstrap build policy, let:

```text
C0 = approved seed executable
C1 = build(C0, compiler_program_root)
C2 = build(C1, compiler_program_root)
C3 = build(C2, compiler_program_root)
```

A bootstrap policy MAY require binary identity between selected generations when the target and build policy make that meaningful.

When exact binary identity is not a valid requirement because of declared metadata, signatures, addresses, or intentionally variable sections, the comparison MUST instead use a canonical projection that removes only explicitly non-semantic variability.

The projection MUST be versioned and auditable. It MUST NOT be defined ad hoc merely to make a failing comparison pass.

---

## 7. Compiler and backend migration into XAX

After B1, new compiler functionality SHOULD be implemented in XAX unless doing so would block the transition itself.

Migration SHOULD proceed from the most architecturally central and deterministic functions outward:

1. graph verification services;
2. canonical serialization and semantic database operations;
3. target-independent normalization and lowering;
4. target package interpretation;
5. instruction selection and legalization;
6. scheduling and register allocation;
7. relocation and object emission;
8. linker and executable emission;
9. package/build/repository operations;
10. optional high-cost optimization and search.

A bootstrap-only host implementation MAY temporarily coexist with an XAX implementation during validation. Once the XAX path is accepted, the host implementation MUST either be deleted from the maintained build path or retained only as non-authoritative historical/bootstrap material.

---

## 8. Targets, assembler functionality, and linking

Target-specific knowledge belongs in target packages rather than fundamental XAX semantics. A target package MUST describe the machine facts needed by code generation, including instruction semantics and encodings, register constraints, memory spaces, relocations, calling conventions, object/executable formats, legalizations, and scheduling or cost data where available.

Instruction encoding SHOULD be performed by XAX-hosted compiler functionality using target-package data. Textual assembly MAY exist for diagnostics or interoperability but MUST NOT become authoritative.

For a target claimed to have toolchain closure, XAX-hosted linking MUST cover identity resolution, required layout, relocation, import/export handling, elimination of unreachable objects when legal, and object/executable or load-image construction. External assemblers and linkers MAY be interoperability tools but MUST NOT be mandatory for a fully self-hosted target.

---

## 9. Bootstrap trust verification

Self-hosting can reproduce a malicious or defective compiler, so recursive compilation alone is insufficient trust evidence.

For trust-sensitive releases or transitions, XAX SHOULD support diverse double compilation or a comparably strong procedure:

```text
A1 = build(seed_A, compiler_program_root)
B1 = build(seed_B, compiler_program_root)

A2 = build(A1, compiler_program_root)
B2 = build(B1, compiler_program_root)

compare(canonical_projection(A2),
        canonical_projection(B2))
```

`seed_A` and `seed_B` SHOULD have sufficiently different provenance that a shared hidden trigger is materially less likely. Diversity MAY come from different historical implementations, architectures, compilers, operating environments, or independently produced bootstrap binaries.

Bootstrap validation SHOULD also use conformance vectors, verifier consistency checks, canonical serialization vectors, deterministic self-builds, cross-target compilation, and exact provenance. Every trust check MUST name the roots, policy, target, and comparison projection used. Such checks reduce specific bootstrap risks; they do not prove compiler correctness.

---

## 10. Autonomous AI development workflow

The repository interface MUST allow an AI session to continue development without reading a historical conversation transcript.

A normal autonomous development cycle is:

```text
load repository root
→ inspect continuation state
→ query smallest required semantic neighborhood
→ construct proposed mutation transaction
→ verify
→ run declared conformance checks
→ optionally benchmark under an explicit policy
→ compare evidence
→ commit new repository root
→ update continuation state
```

AI-generated mutation MUST remain transactional.

A transaction MUST identify its expected base root. If the base root is stale, the mutation MUST be rejected or rebased through an explicit semantic merge procedure.

The AI SHOULD request only the semantic entities and evidence needed for the task. Repository scale MUST NOT force full-repository context transmission.

---

## 11. Multi-agent repository merge model

Repository collaboration operates over semantic identities, not lines of text.

A proposed change is modeled as:

```text
RepoTxn {
  base_root
  read_set
  mutation_set
  created_objects
  deleted_bindings
  expected_invariants
  evidence_updates
}
```

Two transactions are **structurally independent** when their mutations do not alter the same semantic entity, binding, invariant, decision, or derived canonical root.

Independent transactions MAY be merged automatically if the repository can prove that their combined result satisfies all affected invariants.

### 11.1 Mandatory conflict cases

A semantic conflict MUST be raised when concurrent transactions:

- replace the same function or graph entity incompatibly;
- alter the same package binding to different identities;
- change a semantic definition and dependent conformance evidence inconsistently;
- change target semantics in incompatible ways;
- change an architectural decision and its status differently;
- invalidate another transaction's proof assumptions;
- modify repository policy governing the other transaction.

A conflict MUST identify affected semantic entities and violated expectations. It SHOULD NOT be reported as a textual diff when a semantic relationship is available.

### 11.2 Merge functions

A repository MAY define canonical merge functions for specific commutative structures, such as adding disjoint conformance vectors or adding independent package objects.

A merge function MUST itself have versioned semantics.

Absence of a defined merge rule means conflicting writes are rejected rather than guessed.

---

## 12. Canonical repository state

A repository revision SHOULD expose canonical roots:

```text
RepositoryRoot {
  spec_root
  decision_root
  program_root
  target_roots
  package_root
  conformance_root
  build_policy_root
  bootstrap_root
  status_root
  handoff_root
}
```

These roots identify, respectively, normative specification state; accepted/superseded/rejected/open decisions; compiler and toolchain programs; exact target packages; package state; conformance and reproducibility evidence; build policy; approved seeds and provenance; implementation maturity; and compact continuation state.

The repository model is content-addressed. A filesystem layout MAY be synthesized for convenience but is not authoritative.

---

## 13. Concise handoff format

The handoff MUST be small enough to load at the start of an AI session and precise enough to prevent dependence on chat history.

A conceptual schema is:

```text
Handoff {
  repository_root
  spec_revision
  active_milestone
  last_verified_root
  verified_targets[]
  active_work_items[]
  blocked_items[]
  open_decisions[]
  known_failures[]
  required_next_checks[]
  risk_flags[]
}
```

Each item SHOULD use stable semantic identities and compact status codes rather than prose where machine-readable relationships suffice.

The handoff MUST NOT duplicate large semantic graphs. It references them.

A new AI session MUST be able to obtain all additional details through repository queries derived from these identities.

---

## 14. Coupled update rules

Specification, decisions, repository status, and conformance evidence are separate objects but MUST remain mutually consistent.

A commit that changes normative semantics MUST also:

1. update or supersede the relevant decision objects;
2. update conformance vectors affected by the semantic change;
3. invalidate prior evidence that depended on the changed semantics;
4. update status claims whose basis changed;
5. update handoff state when active work or risks change.

A compiler implementation change that does not change language semantics MUST NOT silently edit normative specification objects.

A target-package change that alters observable target behavior MUST update target conformance evidence.

A milestone status MUST NOT advance unless its required evidence is present at the committed repository root.

Repository policy SHOULD permit these related mutations to occur in one atomic transaction.

---

## 15. Elimination of the second implementation language

XAX reaches the point where no independently maintained second implementation language remains when all of the following are true:

- the authoritative compiler implementation is XAX;
- the compiler can build itself;
- canonical serializer and verifier-facing compiler services are XAX-hosted except for any deliberately minimal trusted substrate;
- at least one complete native target can be emitted without an external assembler or linker;
- target definitions are XAX semantic packages;
- package and build logic required for the self-build are XAX programs/data;
- repository mutation and continuity operations required for normal development are expressible through the XAX semantic interface;
- release builds do not require rebuilding or modifying the historical seed source;
- adding or maintaining a fully supported target does not require a second backend language;
- archived seed executables and their provenance are sufficient for bootstrap recovery under the declared trust policy.

At this point, a host-language seed implementation MAY still exist in archival history, but it is no longer part of the live implementation dependency graph.

If ordinary XAX evolution requires editing that seed implementation, bootstrap independence has not been achieved.

---

## 16. Invariants

The following invariants apply to this stage.

| ID | Invariant |
|---|---|
| BS-1 | XAX language meaning is not defined by the seed implementation. |
| BS-2 | The seed is transitional and cannot become a permanent second compiler architecture. |
| BS-3 | Self-hosting claims require explicit reproducible milestone evidence. |
| BS-4 | Recursive self-build alone is not a sufficient trust argument. |
| BS-5 | Target knowledge remains in target/platform packages rather than fundamental semantics. |
| BS-6 | No permanent assembler, linker, package, build, or target-description DSL is introduced. |
| BS-7 | Repository mutations are content-addressed and transactional. |
| BS-8 | Multi-agent conflicts are detected at semantic entities and invariants. |
| BS-9 | A new AI session can continue from canonical repository state without conversation history. |
| BS-10 | Specification, decisions, conformance evidence, and status claims cannot drift silently. |
| BS-11 | Bootstrap artifacts and trust checks name exact roots and policies. |
| BS-12 | No hidden runtime, allocator, scheduler, GC, exception mechanism, or host dependency is introduced by self-hosting. |
| BS-13 | Human-readable repository views are non-authoritative projections. |
| BS-14 | No claim of bootstrap closure or performance is accepted without falsifiable evidence. |

---

## 17. Rejected alternatives

The following alternatives are rejected:

| Alternative | Reason |
|---|---|
| permanent host-language compiler | leaves XAX dependent on a second maintained language ecosystem |
| permanent LLVM dependency | violates the requirement for direct native target capability in the final architecture |
| mandatory external assembler/linker | prevents toolchain closure for a target |
| text-source repository authority | contradicts semantic graphs as the authoritative program |
| conversation-history continuity | cannot provide canonical, scalable autonomous continuation |
| line-oriented primary merge model | discards semantic identity and invariant information already available |
| self-build equality as proof of trust | a compromised compiler can reproduce its own compromise |
| hidden manual release state | prevents reproducible autonomous reconstruction from canonical objects |

Transition tools MAY temporarily use some of these mechanisms, but they MUST NOT become permanent architectural dependencies.

---

## 18. Interfaces and dependencies

This stage depends on and constrains other XAX subsystems.

| Subsystem | Required interface |
|---|---|
| semantic graph | authoritative compiler/toolchain program representation |
| canonical serialization | deterministic identities for repository and bootstrap artifacts |
| semantic database | local query, mutation, dependency, and invalidation support |
| verifier | proof obligations for compiler/toolchain artifacts and mutations |
| transaction protocol | stale-root detection, atomic commits, semantic conflicts |
| target model | machine descriptions, encodings, relocations, formats, ABI rules |
| compiler pipeline | lowering through encoding without requiring an external backend |
| package/build model | content-addressed dependencies and XAX-defined build computation |
| diagnostics | machine-readable failure and repair neighborhoods |
| conformance system | milestone evidence, semantic vectors, reproducibility checks |
| security/supply chain model | artifact provenance, root authorization, bootstrap trust policy |

Stage 15 does not replace those subsystem specifications. It defines the closure conditions connecting them.

---

## 19. Open issues requiring implementation evidence

Only the following issues remain intentionally unfixed.

### OI-15-1: Fixed-point comparison level

It remains to be measured whether reproducible self-builds can require full binary identity on initial targets or whether a canonical projection is necessary for unavoidable non-semantic output variation.

The default preference is full identity.

### OI-15-2: Minimum practical seed subset

The exact smallest semantic subset that can compile the first useful XAX-hosted compiler cannot be fixed without implementing the initial compiler architecture.

The seed subset MUST remain smaller than the permanent language surface it bootstraps where practical.

### OI-15-3: Diversity threshold for bootstrap trust

The minimum acceptable independence between two bootstrap seeds is a policy and evidence question. Implementation experience must determine which combinations of architecture, provenance, historical compiler, and environment give useful diversity without creating an ongoing second implementation obligation.

These issues do not alter the requirement for eventual XAX-hosted closure.

---

## 20. Falsification criteria

The design in this stage must be reconsidered if later implementation evidence establishes any of the following.

1. **Unbounded seed growth:** the seed repeatedly requires most of the production compiler, making the transitional boundary impractical.
2. **No attainable self-build fixed point:** deterministic self-compilation cannot reach a stable canonical result under a well-defined target/build policy for reasons intrinsic to the architecture.
3. **External-tool dependence cannot be eliminated:** a fully supported target cannot be emitted without a permanent external assembler, linker, backend, or format tool.
4. **Target packages are insufficient:** materially new targets routinely require changing fundamental XAX semantics rather than adding semantic target/platform packages.
5. **Repository continuation is too large:** a new AI session cannot resume normal development without loading repository-scale history or unbounded conversational context.
6. **Semantic merging is not advantageous:** entity-level transactions and conflict detection fail to reduce ambiguity or invalid merges relative to textual repository methods.
7. **Bootstrap validation lacks discriminating power:** diverse compilation or alternative trust checks cannot detect intentionally or accidentally divergent compiler behavior under controlled experiments.
8. **Closure requires a maintained second DSL:** build, package, target, linker, or repository operations prove impractical to express as XAX semantic programs/data and demand a permanent separate language.
9. **Canonical state drifts in practice:** the repository model cannot reliably keep specification, decisions, conformance evidence, and status claims synchronized transactionally.
10. **Bootstrap recovery is not reproducible:** retained canonical roots, seed artifact, provenance, and policy are insufficient to reconstruct a verified self-hosted compiler generation.
11. **Autonomous mutation cannot remain local:** routine compiler changes require transmitting or regenerating large unrelated portions of the repository, contradicting the semantic-neighborhood model.
12. **Trusted-core growth becomes uncontrolled:** self-hosting forces large, semantically privileged components outside XAX that cannot be reduced or verified through the stated architecture.

Passing these tests does not prove correctness. Failing one requires reconsidering this stage, its implementation strategy, or an upstream assumption.
