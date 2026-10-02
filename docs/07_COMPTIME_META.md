# XAX Compile-Time Execution, Specialization, Generics, and Metaprogramming

## 1. Purpose and scope

This document defines the normative compile-time execution model for XAX.

XAX does not introduce a macro language, template language, preprocessor, generics DSL, build-script language, or target-description language. Compile-time computation is ordinary XAX computation executed by the compiler under a distinct, explicit evaluation stage. The purpose of this model is to make abstraction, specialization, semantic construction, target generation, and eventual self-hosting possible without creating a second programming system.

It covers stage separation, compile-time values and types, specialization, semantic introspection and construction, verification, deterministic bounded execution, declared inputs, caching, and target-package use.

This document does not define optimizer algorithms, target instruction semantics, package resolution policy, binary serialization details, or an implementation of the compile-time evaluator. It defines the semantic contract those subsystems must obey.

---

## 2. Normative terminology

The key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** are normative.

| Term | Definition |
|---|---|
| **runtime stage** | Evaluation whose resulting operations or values exist in the executable program or its explicitly requested runtime state. |
| **compile-time stage** | Evaluation performed by the XAX toolchain before final runtime graph emission for the affected artifact. |
| **compile-time function** | An ordinary XAX function selected for execution by the compile-time evaluator. It is not written in a separate language. |
| **compile-time value** | A value available to compile-time execution. It may represent ordinary data, a type, a constant, a semantic object, a target object, or an explicit capability. |
| **semantic value** | A compile-time value denoting or describing XAX semantic structure rather than only runtime bits. |
| **semantic object** | A typed XAX object such as a type, constant, function identity, block, operation, graph fragment, module, target object, or other canonical semantic entity. |
| **specialization** | Construction of a more specific semantic graph from a function or graph plus compile-time-known arguments or semantic facts. |
| **generic abstraction** | An XAX computation whose specialization depends on compile-time values such as types, constants, target properties, or semantic objects. |
| **materialization** | Explicit conversion of a compile-time result into runtime semantic structure or runtime data. |
| **introspection** | Read-only semantic inspection through compiler-provided meta operations. |
| **construction** | Creation of new candidate semantic objects through compiler-provided meta operations. |
| **compile-time input** | Any external fact that may affect compile-time evaluation and is therefore explicitly declared and included in dependency tracking. |
| **evaluation budget** | Explicit limits on compile-time recursion, steps, memory, generated objects, graph growth, or related resources. |
| **specialization key** | Canonical identity of a specialization request, derived from the callee, compile-time arguments, declared dependencies, and semantic environment. |

A compile-time stage is an execution context, not a textual region or second language.

---

## 3. Stage model

### 3.1 Two semantic stages

Every evaluated XAX operation belongs to one of two relevant stages:

1. **compile time**, where XAX computes semantic results before runtime graph finalization; or
2. **runtime**, where the resulting program executes on the target environment.

The stage is explicit in the compiler's evaluation request and dependency graph. It MUST NOT be inferred from naming conventions, source formatting, or hidden compiler heuristics that can change observable meaning.

An ordinary function MAY be executed at compile time, runtime, or both, provided its operations are legal in the selected stage.

### 3.2 No implicit stage crossing

A compile-time value does not become a runtime value merely because it contains ordinary data.

A runtime value does not become available to compile-time execution unless it is proven compile-time-known and explicitly supplied to the evaluation.

Crossing from compile time to runtime requires explicit semantic materialization. Typical materializations include:

- emitting a constant;
- selecting a concrete type;
- constructing a concrete function or graph fragment;
- selecting a target operation or lowering rule;
- emitting explicit runtime data derived from a compile-time value.

Materialization MUST NOT introduce hidden runtime allocation, initialization, synchronization, or other effects.

### 3.3 Stage legality

An operation is legal during compile-time execution only when:

- its semantic behavior is defined for compile time;
- every required operand is available;
- every required capability is explicitly supplied;
- every observable input is declared;
- execution can be accounted against the active evaluation budget.

A runtime-only operation requested during compile-time execution is a stage error unless the operation is being represented as semantic data rather than executed.

For example, compile-time code may construct a graph containing a runtime filesystem operation. It may not silently perform that filesystem operation on the compiler host.

---

## 4. Compile-time values and types

### 4.1 Ordinary values

Bits, tuples, sums, vectors, constants, and other ordinary XAX values MAY be compile-time values when their complete semantic value is known to the evaluator.

Their compile-time representation is not required to match their eventual target ABI representation.

### 4.2 Types as values

XAX types MUST be available as compile-time semantic values.

A compile-time function MAY:

- accept one or more types;
- inspect permitted type properties;
- construct derived types;
- compare canonical type identity;
- return types;
- use types to specialize functions or data layout.

This does not create a separate meta-type language. Type manipulation is ordinary compile-time XAX computation over semantic type values.

A type value MUST have canonical semantic identity suitable for equality, dependency tracking, content addressing, and memoization.

### 4.3 Semantic references

Compile-time execution MAY hold references to semantic objects. Such references MUST distinguish at least:

- immutable canonical objects;
- local candidate objects under construction;
- scoped handles into an introspection view.

Persistent object identity MAY be content-addressed while local workspace references MAY use compact transient handles. A transient handle MUST NOT become persistent program identity.

### 4.4 Capability values

Access to compiler services that can observe or construct semantic state MUST be represented by explicit capabilities or equivalent explicit semantic inputs.

Capabilities MAY authorize operations such as:

- inspect a function body;
- inspect a type;
- query a target package;
- construct a candidate graph fragment;
- request verification;
- intern a canonical constant or type.

A capability MUST NOT imply access to undeclared compiler-host state.

---

## 5. Compile-time execution request

A compile-time evaluation request is conceptually:

| Field | Meaning |
|---|---|
| `callee` | Persistent identity of the XAX function to execute. |
| `arguments` | Canonical compile-time arguments. |
| `semantic_inputs` | Explicit semantic objects made available to evaluation. |
| `capabilities` | Explicit compiler services permitted for this evaluation. |
| `target_inputs` | Target identities or target semantic objects, when required. |
| `policy` | Determinism, sandbox, and evaluation-budget policy. |
| `evaluator_semantics` | Identity/version of the compile-time execution semantics. |

The request MUST be dependency-complete: every external fact capable of changing a successful result MUST appear directly or transitively in its dependency closure.

The compiler MUST reject or isolate any undeclared environmental dependency that could affect the semantic result.

---

## 6. Environmental isolation

### 6.1 Default isolation

Compile-time execution has no ambient authority.

Unless explicitly declared and semantically modeled, compile-time XAX MUST NOT depend on:

- host wall-clock time;
- host randomness;
- process identifiers;
- user identity;
- environment variables;
- current working directory;
- arbitrary host filesystem contents;
- network state;
- host locale;
- host thread scheduling;
- mutable global compiler state;
- undeclared package cache state;
- nondeterministic address values.

The default compile-time environment is deterministic with respect to declared inputs.

### 6.2 Explicit external inputs

A build system MAY supply external data, but it MUST become an explicit compile-time input with stable identity.

Examples include an embedded asset, a generated schema, a selected package lock graph, or a measured profile artifact.

The dependency is on declared content or canonical identity, not an implicit pathname or host lookup.

### 6.3 Effects

The ordinary XAX effect model remains applicable.

Compile-time execution MUST NOT reinterpret an effectful operation as pure merely because it runs before runtime. If an effect is permitted at compile time, its authority and input/output dependency MUST be explicit.

Compiler-internal introspection and construction actions MUST be represented through the meta-operation model or an equivalent explicit compiler capability interface. They MUST NOT masquerade as runtime effects.

---

## 7. Generic programming by specialization

### 7.1 No separate generics system

XAX has no independent generic type checker or template instantiation language.

A generic abstraction is an ordinary XAX computation that accepts compile-time values and produces a specialized semantic result.

Common specialization parameters include:

- types;
- integer constants;
- shapes or vector widths;
- effect-domain facts;
- pointer properties;
- resource kinds;
- target capabilities;
- calling-convention objects;
- semantic predicates.

### 7.2 Specialization result

A specialization MUST produce ordinary verified XAX semantics.

After specialization, no generic mechanism is required at runtime unless the program explicitly constructs runtime dispatch or runtime type representation.

Unused compile-time machinery MUST disappear from the runtime artifact.

### 7.3 Monomorphization is not mandatory policy

Specialization frequently produces a concrete function for a concrete argument set, but the language does not normatively require one implementation strategy.

The compiler MAY:

- reuse an existing equivalent specialization;
- fold specialization into a caller;
- preserve a shared runtime implementation when semantics permit;
- merge equivalent specialized graphs;
- eliminate the specialized function entirely.

The requirement is semantic equivalence, not a prescribed duplication strategy.

### 7.4 Specialization identity

Equivalent specialization requests SHOULD converge on equivalent canonical semantic objects.

A specialization key MUST include every semantic dependency capable of changing the result. At minimum this includes the callee identity, compile-time arguments, declared semantic inputs, applicable target inputs, and evaluator semantics.

Resource ceilings that can only terminate evaluation without changing a successful result SHOULD NOT be treated as semantic arguments. A budget-exhaustion result MUST NOT poison reuse under a later, larger budget.

---

## 8. Semantic introspection

Compile-time XAX MAY inspect semantic objects through a bounded, typed introspection interface.

Permitted introspection SHOULD expose semantic facts rather than storage-layout accidents of the compiler implementation.

Examples of inspectable facts include:

- operation family and exact operation semantics;
- operand and result types;
- block parameters;
- explicit control-flow successors;
- effect domains and dependencies;
- declared capabilities;
- constant values;
- pointer semantic properties;
- target operation contracts;
- canonical object identities.

Introspection MUST NOT expose unstable compiler memory addresses or other accidental host representation as program meaning.

Introspection of an immutable canonical object is read-only.

A compile-time function MUST NOT mutate an already committed semantic object in place.

---

## 9. Semantic construction

### 9.1 Candidate construction

Compile-time XAX MAY construct:

- constants;
- types;
- operations;
- blocks;
- functions;
- graph fragments;
- module fragments;
- target semantic objects where authorized.

Construction occurs in a candidate workspace or equivalent transactional context.

Candidate entities MAY use local handles before canonicalization.

### 9.2 Explicit structure

Generated semantics are subject to the same rules as non-generated semantics.

Metaprogramming MUST NOT introduce:

- implicit control-flow edges;
- implicit exception edges;
- implicit ownership transfer;
- implicit effects;
- hidden initialization;
- hidden temporaries with observable behavior;
- hidden allocations;
- hidden synchronization.

### 9.3 Verification barrier

A generated graph fragment is not valid XAX merely because compile-time execution produced it.

Before a generated fragment can become part of the authoritative program, the compiler MUST verify all applicable invariants, including:

- type correctness;
- SSA and block-parameter correctness;
- control-flow well-formedness;
- effect dependency correctness;
- ownership/resource obligations;
- memory proof obligations;
- target-operation constraints;
- capability restrictions;
- stage restrictions.

Verification failure rejects the generated candidate. Invalid generated semantics MUST NOT be partially committed.

---

## 10. Determinism and bounded execution

### 10.1 Deterministic semantics

Given the same:

- callee identity;
- compile-time arguments;
- declared semantic inputs;
- target inputs;
- relevant policy inputs;
- evaluator semantics;

successful compile-time evaluation MUST produce the same semantic result.

Canonicalization MAY change local handles or storage placement but MUST preserve canonical semantic identity.

### 10.2 Evaluation budgets

Every compile-time evaluation MUST execute under explicit finite limits.

An implementation MUST be able to bound at least:

| Budget dimension | Required purpose |
|---|---|
| evaluation steps or fuel | Prevent unbounded computation. |
| recursion depth | Bound recursive evaluator state. |
| compile-time memory | Bound evaluator storage. |
| semantic objects created | Bound candidate-object explosion. |
| graph nodes emitted | Bound generated-program growth. |

Implementations MAY add limits for wall-clock execution, diagnostics, interned objects, or other resources, provided such limits do not alter successful program semantics.

Exhausting a limit produces a deterministic compile-time failure for that evaluation attempt. It MUST NOT yield a partially accepted semantic result.

### 10.3 Recursion

Compile-time recursion is permitted.

There is no special template-recursion mechanism. Recursive compile-time functions obey ordinary call semantics plus the compile-time recursion and fuel limits.

A recursive specialization that exceeds active limits is rejected.

---

## 11. Memoization and content addressing

### 11.1 Pure-result reuse

A deterministic compile-time computation whose complete dependency closure is known MAY be memoized.

Memoization keys SHOULD be content-derived where practical.

A cached result is reusable only when all semantic dependencies still match.

### 11.2 Object interning

Immutable semantic results such as types, constants, and verified graph fragments SHOULD be internable by canonical identity.

Constructing an object semantically identical to an existing immutable object MAY reuse that canonical object.

### 11.3 Cache correctness

Cache lookup is never allowed to weaken semantic validation.

A cached graph MAY skip reconstruction only when it corresponds to previously verified semantics under the same relevant rules.

Changes to verifier semantics, evaluator semantics, target semantic inputs, or other meaning-affecting dependencies MUST invalidate incompatible cached results.

---

## 12. Target-package compile-time use

A target package is XAX semantic data and XAX computation. It does not require a second target-description DSL.

Compile-time XAX MAY use target packages to:

- inspect supported machine value types;
- inspect address spaces;
- inspect instruction semantic contracts;
- select legalizations;
- derive calling-convention decisions;
- generate target-specific graph fragments;
- construct encoding or lowering tables;
- specialize algorithms to target capabilities.

Target-package compile-time execution is subject to the same deterministic, bounded, sandboxed model as all other compile-time execution.

A target package MUST NOT gain implicit access to compiler-host native APIs merely because it describes the active machine.

A target operation that would perform device I/O at runtime may be inspected or emitted at compile time; it MUST NOT thereby execute device I/O on the compiler host.

This separation supports cross-compilation, reproducibility, sandboxing, and future hardware.

---

## 13. Invariants

The following are mandatory:

1. **One language:** compile-time programming is XAX executing XAX.
2. **Meaning remains source:** generated semantics become authoritative only as verified semantic objects, never as textual expansion.
3. **No ambient authority:** compile-time code receives only explicit inputs and capabilities.
4. **No hidden stage crossing:** compile-time results enter runtime semantics only through explicit materialization.
5. **No hidden effects:** compile-time execution does not erase or invent effect semantics.
6. **No unverified generation:** generated graph fragments are verified before commit.
7. **No in-place mutation of committed immutable objects:** modifications create candidate or replacement semantic objects.
8. **Deterministic successful evaluation:** identical semantic inputs produce identical semantic results.
9. **Finite execution:** every evaluation runs under explicit finite budgets.
10. **Dependency-complete caching:** cache reuse is valid only when all meaning-affecting dependencies match.
11. **No permanent generic runtime tax:** compile-time-only abstraction disappears unless runtime representation is explicitly requested.
12. **Target symmetry:** target packages obey the same compile-time execution rules as other XAX packages.
13. **Transactional failure:** evaluation or verification failure cannot partially mutate the authoritative program.

---

## 14. Rejected alternatives

| Alternative | Status | Reason |
|---|---|---|
| Textual macros | Rejected | Reintroduce text as a semantic transformation layer and create token-heavy, syntax-dependent expansion. |
| Preprocessor directives | Rejected | Create a second evaluation system outside XAX semantics. |
| Template language | Rejected | Duplicates functions, values, control flow, recursion, and specialization in a second language. |
| Build-script language | Rejected as fundamental mechanism | Build-time algorithms can be XAX compile-time computation over explicit semantic inputs. |
| Target-description DSL | Rejected as permanent architecture | Target semantics belong in XAX target packages. |
| Host-language compiler plugins | Rejected as semantic requirement | They undermine portability, sandboxing, content addressing, self-hosting, and deterministic dependency tracking. |
| Unbounded compile-time execution | Rejected | An autonomous compiler must be able to guarantee termination of each evaluation attempt. |
| Ambient filesystem/network access | Rejected by default | Makes builds non-reproducible and hides semantic dependencies. |
| AST text generation and reparsing | Rejected | XAX has no normative human source syntax and semantic construction should operate directly on graph objects. |
| Unverified generated graphs | Rejected | Metaprogramming cannot bypass type, effect, resource, memory, or target invariants. |
| Implicit runtime reflection metadata | Rejected | Runtime metadata has cost and must be explicitly requested. |
| Compiler-memory-address reflection | Rejected | Host representation is not XAX meaning and is not stable semantic identity. |

---

## 15. Interfaces with other XAX subsystems

| Subsystem | Required interface |
|---|---|
| **Type system** | Canonical type values, type construction, type identity, and permitted semantic inspection. |
| **Constant/value system** | Canonical compile-time constants and materialization into runtime semantics. |
| **Core semantic graph** | Typed introspection, candidate construction, local handles, canonicalization, and graph-fragment identity. |
| **Control flow and calls** | Ordinary call/return/branch semantics usable by the compile-time evaluator. |
| **Effects** | Explicit effect domains and stage-legal capability checks. |
| **Memory and resources** | Compile-time evaluator resources remain implementation resources; generated runtime memory/resource operations retain ordinary proof obligations. |
| **Verifier** | Mandatory validation barrier for generated semantic objects. |
| **Content-addressed store** | Stable identity and reuse of immutable semantic inputs and results. |
| **Transactions** | Candidate generation and all-or-nothing commit behavior. |
| **Target packages** | Semantic target values, target introspection, legalizations, and target-specific compile-time computation. |
| **Package/build system** | Explicit dependency identities and declared build-time inputs. |
| **Optimizer** | May consume specialized verified graphs; MUST NOT rely on textual macro artifacts. |
| **Diagnostics** | Machine-readable stage, budget, capability, dependency, and verification failures. |

---

## 16. Open issues

Only issues requiring implementation evidence remain open.

### 17.1 Budget units

The architecture requires bounded evaluation, but the exact portable definition of "fuel" is not fixed.

A raw interpreter-instruction count may be simple but implementation-dependent. A semantic-operation cost model may be more stable but more complex.

The chosen unit must be deterministic enough for diagnostics and policy while not becoming an unnecessary permanent constraint on evaluator implementation.

### 17.2 Granularity of introspection capabilities

It is not yet fixed whether introspection authority should be coarse-grained per semantic object class or fine-grained per operation family/property.

This should be decided using evidence from self-hosting, target generation, verifier complexity, and least-authority enforcement.

### 17.3 Canonical specialization boundaries

The semantic model permits specialization, reuse, inlining, and equivalence merging. The best canonical granularity for persistent specialization objects requires implementation data on cache reuse, graph size, optimization opportunity, and AI transaction locality.

These issues do not justify a second metaprogramming language or weakening any invariant above.

---

## 17. Falsification criteria

This design should be revised if implementation evidence demonstrates one or more of the following:

1. **Compile-time XAX cannot express required self-hosting transformations** without repeatedly depending on privileged host-language plugins.
2. **Target packages cannot describe or generate required target semantics** within the bounded compile-time model without introducing a separate target DSL.
3. **Explicit dependency tracking is insufficient for reproducible memoization**, causing semantically stale compile-time results despite correct content identities.
4. **Semantic introspection cannot remain stable across compiler implementations** without exposing host representation details as program meaning.
5. **Mandatory verification of generated fragments creates prohibitive repeated cost** and no sound content-addressed validation strategy can remove that cost.
6. **Specialization causes unavoidable graph or code explosion** for common generic workloads and equivalence reuse cannot control it.
7. **Bounded execution prevents practical generic, target-generation, or self-hosting tasks** under any defensible resource policy.
8. **The absence of a separate macro/template language materially increases AI token cost or semantic error rate** compared with a competing semantic mechanism under controlled measurements.
9. **Content-addressed compile-time memoization provides negligible reuse** while imposing substantial semantic or storage complexity.
10. **Declared-input isolation cannot support necessary real build workflows** without routinely falling back to undeclared ambient host state.
11. **The same compile-time semantics cannot be implemented consistently across substantially different host platforms**, undermining reproducibility.
12. **Generated semantic construction remains more error-prone for AI agents than an alternative representation** after accounting for verification failures, repair turns, transmitted semantic entities, and total tokens per successful semantic change.

Failure of an implementation to optimize a valid instance is not by itself a failure of this semantic model. The design is falsified when the stated invariants prevent XAX from expressing, specializing, verifying, caching, or targeting required programs with acceptable measurable cost, or when a simpler semantic-first model demonstrably performs better.
