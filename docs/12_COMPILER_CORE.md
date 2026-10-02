# 12. Compiler Core, Verifier, Incrementality, and Semantic Database

## 12.1 Purpose and scope

This stage defines the XAX compiler core: the smallest persistent and deterministic machinery that accepts canonical XAX semantic objects, verifies them, stores them, answers semantic queries, invalidates dependent facts after local change, and exposes verified inputs to later optimization and target-lowering stages.

The compiler core is not a human-source frontend. The authoritative program is the canonical semantic graph. The core therefore begins at canonical semantic ingestion rather than lexing, parsing, textual name resolution, or AST construction.

This stage specifies:

- the persistent semantic database;
- canonical ingestion and deserialization;
- structural and semantic verification;
- proof obligations and proof-result storage;
- dependency tracking and invalidation;
- local verification;
- query execution;
- content-addressed caches;
- incremental compilation;
- deterministic diagnostics;
- parallel compiler services;
- trust boundaries;
- compiler determinism modes;
- cache-key inputs;
- semantic transaction integration;
- the boundary to optimization and direct object/executable generation;
- corruption and crash recovery;
- the implementation trajectory toward self-hosted XAX.

Detailed optimization algorithms, instruction selection, scheduling, register allocation, encoding algorithms, and target-specific machine optimization are outside this stage.

## 12.2 Normative language and definitions

The key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** are normative.

| Term | Definition |
|---|---|
| semantic object | Canonically serializable XAX object such as a module, function, type, constant, target object, graph fragment, proof artifact, or configuration object. |
| persistent identity | Cryptographic content identity of an immutable canonical semantic object. |
| local handle | Session- or query-local compact identifier that refers to a persistent object without exposing its full hash. |
| semantic database | Persistent content-addressed store plus indexes, dependency records, derived facts, validation state, and query services. |
| root | Persistent identity that selects a complete program/module graph and its declared compilation inputs. |
| fact | Derived semantic result such as type equality, dominance, effect reachability, ownership state, target legality, or proof satisfaction. |
| proof obligation | Precisely identified condition that MUST hold for a semantic operation or transformation to be valid. |
| evidence | Canonical or reproducibly derived data that discharges a proof obligation. |
| dependency | Directed relation from a derived fact or compilation artifact to every semantic input whose change can invalidate it. |
| transaction | Mutation set applied against an expected base root and committed only after required verification succeeds. |
| trusted core | Minimal implementation whose defect can cause invalid canonical semantics to be accepted as valid without an independent checker detecting it. |
| validated transformation | Transformation whose output is not trusted merely because the transformation executed; its result is rechecked or translation-validated. |
| deterministic diagnostic | Machine-readable diagnostic whose identity and payload are reproducible from the same semantic inputs, configuration, and target. |
| compiler configuration | Canonical semantic object describing compilation policies that affect semantics, validation, optimization eligibility, determinism, or emitted output. |

The compiler core MUST treat semantic meaning as primary. Human-readable renderings are views only and MUST NOT become authoritative program state.

## 12.3 Architectural decomposition

The compiler core consists of the following logical services:

| Service | Responsibility | Authoritative output |
|---|---|---|
| canonical reader | Decode canonical XAX objects and reject malformed encodings | immutable semantic objects |
| object store | Persist and retrieve content-addressed objects | object-by-identity mapping |
| root manager | Resolve module/program roots and compilation input roots | validated root descriptors |
| structural verifier | Check graph shape, object references, block form, arity, canonical invariants | structural validity facts |
| semantic verifier | Check typing, effects, ownership, memory obligations, control rules, capabilities, and target-independent semantic rules | semantic validity facts |
| proof engine | Create, query, combine, or reject evidence for explicit proof obligations | proof facts/evidence records |
| dependency engine | Record exact or conservative dependencies of derived facts | invalidation graph |
| query engine | Answer bounded semantic queries over verified or explicitly unverified state | query results with dependencies |
| cache manager | Store derived facts and compilation products under complete cache keys | reusable validated entries |
| transaction service | Apply local mutations, verify affected neighborhoods, and commit new roots atomically | new persistent roots |
| diagnostic service | Emit deterministic machine diagnostics and repair neighborhoods | canonical diagnostic records |
| compilation coordinator | Schedule independent compiler work while preserving reproducibility requirements | verified stage inputs/outputs |

## 12.4 Persistent semantic database

### 12.4.1 Object model

The semantic database MUST be content-addressed at immutable-object boundaries.

A minimal persistent record is:

```text
ObjectRecord {
    kind
    schema_version
    canonical_payload
    content_identity
}
```

`content_identity` MUST be derived from the canonical bytes of the semantic identity domain. Storage metadata such as file offsets, compression format, timestamps, access counters, or replication state MUST NOT influence semantic identity.

Large semantic entities MAY be split into independently addressable objects when doing so preserves canonical meaning and materially improves locality. Function bodies, immutable type objects, constants, target descriptions, and reusable graph fragments SHOULD be independently addressable.

### 12.4.2 Derived state

Derived facts MUST be stored separately from authoritative semantic objects.

A derived-fact record conceptually contains:

```text
DerivedFact {
    fact_kind
    subject_identity
    input_fingerprint
    result
    dependencies[]
    verifier_or_algorithm_version
    configuration_identity
    target_identity?
}
```

A derived result MUST NOT be treated as valid unless its complete dependency set is still valid for the requested root and configuration.

Derived indexes MAY use non-content-addressed internal structures for performance, provided they are reconstructible from authoritative objects and do not become semantic authority.

## 12.5 Canonical ingestion and deserialization

Canonical ingestion has three phases:

1. **framing validation** — lengths, canonical integers, deterministic field order, object boundaries, and schema identifiers;
2. **identity validation** — recompute persistent identity and reject identity/payload mismatch;
3. **semantic admission** — store the immutable object, then verify it at the required level before allowing it to participate in a verified root.

Canonical decoding MUST reject non-canonical encodings, duplicate or misordered normative fields, invalid local references, impossible kind/schema combinations, unresolved mandatory references, identity mismatches, and out-of-bounds length or integer encodings.

A well-formed byte sequence is not necessarily a valid XAX program. Deserialization MUST NOT imply semantic verification.

Unknown object kinds or schema versions MUST be rejected unless the active version policy explicitly provides a deterministic compatibility rule.

## 12.6 Verification model

Verification is layered so that inexpensive failures are rejected before expensive reasoning.

### 12.6.1 Structural verification

Structural verification MUST establish valid scoped references, operation arity/result shape, branch/block-parameter compatibility, valid terminators and successors, legal SSA uses, internally consistent function parameters/returns, unique graph-local identifiers, and syntactically complete resource/effect edges.

Structural verification MUST be deterministic.

### 12.6.2 Semantic verification

Semantic verification MUST establish applicable type compatibility, operation-specific arithmetic/conversion semantics, effect legality, resource linearity/state transitions, call compatibility, capability availability, memory obligations, atomic-ordering legality, compile-time/runtime boundary legality, opaque-operation restrictions, and absence of hidden control or exception edges.

Target-dependent legality is not guessed by the core. Where legality depends on a target package, the verifier MUST invoke the target semantic interface and include the target identity in the derived-fact dependency set.

### 12.6.3 Proof obligations

Operations MAY introduce explicit proof obligations. Each obligation MUST have a stable rule identity and a subject.

Representative memory obligations include:

- valid provenance;
- sufficient object extent or bounds;
- required alignment;
- required access permission;
- permitted alias relation where relevant.

Representative resource obligations include:

- resource is in the required state;
- resource has exactly one live owner when linear;
- release or transfer occurs only from a permitted state;
- no required resource disappears at function exit.

An obligation has one of these states:

| State | Meaning |
|---|---|
| proven | static evidence satisfies the obligation |
| runtime-enforced | semantics explicitly include a runtime check or operation satisfying it |
| waived | an explicit raw/unsafe semantic operation waives the obligation under defined rules |
| unsatisfied | no valid evidence, runtime enforcement, or permitted waiver exists |

`unsatisfied` MUST reject the verified program state.

Proof evidence MUST itself be dependency-tracked. A proof derived from bounds, dominance, type, target, or ownership facts becomes invalid when any of those premises changes.

## 12.7 Dependency graph and invalidation

Every reusable derived fact MUST identify the semantic inputs on which it depends. Dependency precision is a performance property; soundness is mandatory.

The invalidation rule is:

> A cached fact MAY survive a change only when the compiler can prove that none of the fact's semantic dependencies changed.

Dependencies SHOULD be recorded at the smallest economical identity granularity. For example, changing one operation in a function SHOULD NOT invalidate unrelated functions merely because they share a module root.

The dependency engine MUST support direct object dependencies, transitive derived-fact dependencies, configuration/target/compiler-version dependencies, package/interface dependencies, and negative dependencies where absence is semantically relevant.

Conservative invalidation is permitted. Unsound under-invalidation is not.

## 12.8 Local verification and incremental compilation

A semantic transaction supplies an expected base root and a mutation set. The compiler MUST determine an affected verification frontier rather than automatically re-verifying the entire program.

The frontier begins with changed or newly introduced semantic objects and expands through dependency edges until all invalidated required facts are recomputed.

Local verification MUST be equivalent in acceptance behavior to verification from a cold database over the resulting root. Incrementality may change work performed, not program meaning.

A commit proceeds conceptually:

```text
receive transaction
→ validate expected base root
→ construct candidate immutable objects
→ structurally verify affected objects
→ invalidate dependent facts
→ semantically verify required frontier
→ validate root-level invariants
→ atomically publish new root
```

If any required check fails, the transaction MUST NOT partially publish semantic state.

Incremental compilation follows the same rule. Later-stage products such as optimized functions or machine fragments may be reused only when their complete semantic and configuration keys remain valid.

## 12.9 Query engine

The query engine is the normal machine interface to compiler knowledge. It MUST support bounded retrieval of the smallest semantic neighborhood sufficient for an AI or compiler service to act.

Queries MAY cover entity lookup, uses/definitions, control-flow neighbors, type/layout facts, effects, resource state, proof obligations/evidence, invalidation causes, target legality, later-stage cost inputs, diagnostics, and repair neighborhoods.

Every query result SHOULD return or internally retain its dependency fingerprint so repeated queries can be reused safely.

The query engine MUST distinguish:

- authoritative semantic objects;
- verified derived facts;
- provisional/unverified transaction state;
- unavailable facts;
- facts invalid under the current target/configuration.

Queries MUST NOT silently convert uncertainty into validity.

## 12.10 Content-addressed caches and cache keys

Cache entries MUST be keyed by every input capable of changing the result.

A compilation cache key conceptually includes:

```text
CacheKey {
    semantic_subject_identity
    compiler_semantic_version
    algorithm_or_pass_version
    configuration_identity
    target_package_identity
    platform_or_abi_identity?
    relevant_dependency_identities[]
    determinism_mode
}
```

Measured profile data, when used, MUST be included by identity and MUST remain separate from program semantics.

Host-machine identity MUST NOT enter a cache key unless host properties are deliberately allowed to influence the result. In reproducible modes, accidental host dependence is a compiler defect.

Cache corruption MUST degrade to recomputation or explicit failure, never silent semantic acceptance.

### 12.10.1 OI-05 measured proof-cache policy

The bootstrap OI-05 experiment keeps successful object-verification facts outside the canonical store in an optional non-semantic sidecar. A reusable entry is keyed by the verifier identity, exact subject CID, and exact direct-reference CID tuple. Subject, dependency, or verifier changes are cache misses; local workspace commits replace verified frontier entries and prune subjects no longer present. The sidecar has independent canonical framing/integrity and may be discarded without changing any semantic CID, root, diagnostic meaning, or generated artifact.

The 2026-10-01 96-function benchmark found strong in-process reuse and smaller but positive restart/build reuse, at a sidecar size of roughly 0.8x the canonical store and measurable local-update maintenance. Therefore proof-cache persistence is optional policy rather than canonical state or a mandatory build requirement. Facts whose meaning depends on additional target/configuration/profile/compiler inputs MUST extend the key with those identities before reuse.

### 12.10.2 OI-06 measured memory-proof surface

The bounded OI-06 verifier keeps precise local provenance/alias class as a derived allocation/storage identity rather than a serialized pointer field. Two independent allocations therefore require no extra graph bytes for alias identity, and offset-derived views preserve the same class. Checked scalar load/store add only a bounded dynamic-offset proof path to the existing memory verifier; raw load reuses the same provenance/permission/effect facts and requires an explicit unsafe-effect waiver. In the committed 31-sample fixtures, verifier medians remain in the same low-millisecond range as their ordinary comparators; these timings are implementation evidence, not semantic thresholds. No general borrow checker, ownership inference engine, or hidden runtime metadata is introduced.

## 12.11 Deterministic diagnostics

Diagnostics are machine data. A diagnostic MUST have a stable structure such as:

```text
Diagnostic {
    code
    rule
    entity
    expected
    actual
    dependencies[]
    repair_neighborhood[]
}
```

Given the same semantic root, target, compiler semantic version, and configuration, required diagnostics MUST be reproducible in identity and meaning.

Parallel execution MUST NOT make diagnostic ordering semantically significant. When a stable ordered stream is requested, diagnostics MUST be sorted by deterministic keys independent of thread scheduling.

Natural-language explanations MAY be synthesized as a view. They are not canonical diagnostics.

## 12.12 Parallel compiler services

The core SHOULD parallelize independent compiler work.

Parallel execution MUST preserve immutable objects, atomic root publication, race-free derived-fact publication, deterministic duplicate-work resolution, and rejection of results whose dependencies changed during computation.

A worker MAY compute from a snapshot root while a newer root is committed. Its result may be published only if the result's key and dependencies still match the root for which it is being installed.

Redundant computation is acceptable. Nondeterministic meaning is not.

## 12.13 Trusted core and validated transformations

The trusted core SHOULD remain smaller than the full compiler.

At minimum, trust is concentrated in:

- canonical semantic definitions;
- canonical decoding/identity checking;
- graph and semantic verification rules;
- proof-obligation acceptance logic;
- canonical serialization required for identity;
- minimal target-independent lowering machinery needed to reach validated target interfaces;
- target encoder bootstrap until independently checkable replacements exist.

Optimization and other complex transformations SHOULD be treated as untrusted or partially trusted whenever practical. Their outputs MUST pass ordinary structural and semantic verification. Transformations that can alter observable behavior SHOULD additionally support translation validation or equivalence checking where the selected build policy requires it.

A pass succeeding is not evidence that its output is correct.

## 12.14 Compiler determinism modes

The compiler MUST expose explicit determinism policy rather than relying on ambient implementation behavior.

At least these conceptual modes are required:

| Mode | Requirement |
|---|---|
| semantic-deterministic | identical valid inputs produce semantically equivalent outputs; internal scheduling may differ |
| artifact-reproducible | identical declared inputs produce byte-identical declared output artifacts |
| search-variable | bounded optimization/search may explore alternatives nondeterministically, but any accepted result MUST preserve semantics and the variability policy MUST be explicit |

Artifact-reproducible builds MUST exclude undeclared entropy such as time, process identifiers, random seeds, filesystem iteration order, thread race order, or unconfigured host-specific tuning.

## 12.15 Semantic transaction integration

Transactions are integrated directly with the semantic database.

A transaction MUST identify:

- expected base root;
- mutation operations or newly constructed objects;
- referenced local/persistent entities;
- requested verification policy;
- optional expected facts used for conflict detection.

The transaction service MUST reject a stale base root unless the transaction protocol explicitly supports a verified rebase operation.

Conflict detection SHOULD operate on affected semantic entities and dependencies rather than textual regions.

A successful commit produces a new persistent root. Existing immutable objects remain valid and reusable.

## 12.16 Interfaces to optimizer and target backend

The optimizer receives only verified semantic state plus explicitly identified profile/configuration inputs. It MAY produce candidate semantic graphs, but those outputs MUST return through verifier interfaces before becoming accepted compiler state.

The compiler core exposes to the optimizer:

- verified function/module graphs;
- type/effect/resource/proof facts;
- dependency fingerprints;
- target-independent legality queries;
- target semantic-query handles;
- configuration and cost-object identities.

The target backend interface receives verified target-lowered semantics and target package data. Target packages define machine value types, instruction semantics, encodings, memory spaces, calling conventions, relocations, object/executable formats, atomics, legalizations, and ABI rules.

This stage ends at the boundary where verified target-lowered or machine-semantic objects are handed to direct object/executable generation. XAX does not require LLVM or another external backend in the final architecture.

## 12.17 Crash and corruption recovery

Authoritative immutable objects MUST be written before any root that references them becomes visible.

Root publication MUST be atomic with respect to crash recovery. After restart, the database MUST expose either the prior valid root or the fully committed new root, never a partially published root.

Rebuildable indexes, caches, and derived facts MAY be discarded after corruption or version mismatch.

The system MUST detect, rather than silently tolerate:

- object hash mismatch;
- truncated canonical objects;
- missing referenced objects;
- incompatible schema versions;
- corrupted root records;
- derived facts whose key or dependency metadata is inconsistent.

Where authoritative objects remain intact, recovery SHOULD rebuild derived state instead of requiring repository reconstruction.

## 12.18 Implementation-language trajectory

The initial compiler core MAY use a bootstrap language, but that language MUST NOT become a second normative language or DSL. The trajectory is to bootstrap the reader/database/verifier/minimal lowering/one encoder, move compiler services and target/build/package logic into XAX, reduce the external bootstrap to the smallest practical trusted substrate, and support rebuilding the XAX-hosted compiler from prior verified artifacts.

Self-hosting is complete only when XAX can represent the compiler's own required semantics without reintroducing hidden runtime dependencies forbidden by the architecture.

## 12.19 Core invariants

The compiler core MUST preserve all of the following:

1. **Meaning is source.** Textual views never outrank canonical semantic objects.
2. **Verification precedes trust.** Deserialization, transformation success, or cache presence never implies validity.
3. **Immutability under identity.** A persistent identity never changes meaning.
4. **Atomic roots.** No partial semantic transaction becomes visible.
5. **Sound invalidation.** Reuse is forbidden when a relevant dependency may have changed.
6. **Locality without semantic drift.** Incremental verification must accept and reject exactly as cold verification would.
7. **Explicit target dependence.** Target-sensitive facts depend on target identities.
8. **Explicit configuration dependence.** Policy-sensitive facts depend on canonical configuration identities.
9. **Machine diagnostics.** Diagnostic meaning is structured and deterministic.
10. **No hidden runtime semantics.** The compiler core does not invent allocation, synchronization, exception, initialization, ownership, syscall, or scheduler behavior absent from the semantic graph.
11. **No permanent second DSL.** Compiler configuration, target descriptions, build logic, and package logic remain XAX semantic data/programs.
12. **Direct native boundary.** The final architecture can emit target object/executable bytes without requiring an external backend.

## 12.20 Rejected alternatives

| Alternative | Rejection reason |
|---|---|
| textual source database as authority | contradicts semantic-first architecture and makes parser/text identity part of meaning |
| mutable compiler IR nodes with stable IDs | risks identity/meaning divergence and weakens content addressing |
| whole-program re-verification after every local edit | correct but violates the locality objective and makes repository size drive edit cost |
| cache keys based only on function hash | unsound when target, compiler semantics, configuration, ABI, profile, or dependent interfaces affect results |
| diagnostics as free-form English | non-canonical, token-expensive, difficult to compare, and poor for automated repair |
| trusting optimizer passes | makes complex transformation code part of the semantic trusted base unnecessarily |
| storing proof success without premises | permits stale proofs after local mutation |
| target legality embedded permanently in compiler code | violates universal target-package architecture |
| relying on filesystem timestamps for validity | not semantic identity and not reproducible |
| silent recovery from corrupt semantic objects | can change or accept program meaning without proof |
| requiring byte-identical output in every compilation mode | unnecessarily constrains search-oriented optimization; reproducibility is a selectable policy |

## 12.21 Interfaces and dependencies with other XAX subsystems

The compiler core depends on canonical definitions established by the semantic graph, type/value/layout, memory/resource, effect/control, concurrency, compile-time execution, serialization/identity, workspace transaction, universal target, and ABI/platform stages.

It provides the stable verified substrate for:

- optimizer passes;
- specialization services;
- target lowering;
- machine scheduling and register allocation;
- object/executable emission;
- package/build services;
- AI semantic queries and repairs;
- testing and benchmarking infrastructure.

No downstream subsystem may bypass the core verifier when publishing a new authoritative semantic root.

## 12.22 Open issues requiring implementation evidence

Only the following remain intentionally open:

1. **Object granularity.** Function/block/fragment/fact boundaries require measurement of lookup cost, hash churn, storage, and edit locality.
2. **Dependency representation.** Exact reverse edges, compressed sets, fingerprints, and recomputation strategies require benchmarking.
3. **Proof persistence.** Persist-versus-recompute thresholds require implementation data.
4. **Cross-process parallelism.** Distribution thresholds require workload measurements.
5. **Hash selection and migration.** Security, speed, hardware support, and migration policy require implementation evidence.

These issues MAY change representation or performance strategy but MUST NOT weaken these invariants.

## 12.23 Falsification criteria

This design MUST be reconsidered if implementation evidence shows any of the following:

- local semantic edits routinely require verification work proportional to total repository size despite unchanged unrelated identities;
- dependency tracking consumes more time or storage than cold recomputation for representative workloads without producing meaningful latency or token savings;
- cache correctness requires hidden host state that cannot be represented in canonical keys;
- canonical object granularity causes excessive hash churn such that small edits rewrite large unaffected semantic regions;
- deterministic diagnostics materially increase compiler cost without improving automated repair reliability;
- the trusted verifier becomes so complex that independent checking is less practical than trusting transformation passes directly;
- translation validation or re-verification costs exceed their safety value for most optimization classes and no narrower validation boundary is viable;
- self-hosting requires a permanent external target/build/configuration language;
- artifact-reproducible mode cannot produce byte-identical outputs from identical declared inputs because relevant inputs cannot be captured;
- corruption recovery cannot distinguish authoritative-object damage from rebuildable cache/index damage;
- incremental compilation produces acceptance, rejection, diagnostics, or emitted semantics different from cold compilation for the same root and declared inputs;
- the semantic database fails to make AI edits substantially more local and machine-verifiable than regeneration of equivalent source-oriented representations.

The decisive correctness condition is not that incrementality is fast. It is that every incremental result is semantically equivalent to the result obtained from the same canonical root by a clean compiler state, with all declared target and configuration inputs held equal.
