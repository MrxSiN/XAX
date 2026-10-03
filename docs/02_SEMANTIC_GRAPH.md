# XAX Canonical Semantic Graph and Core Operation Model

## 1. Purpose and scope

This document specifies the canonical semantic program model of XAX.

XAX programs are persistent, typed semantic graphs. The graph is the authoritative program representation; human-readable notation is diagnostic only. The model supports exact verification, local transactional mutation, aggressive optimization, compact AI interaction, target-independent reasoning, and direct native lowering.

This stage defines semantic entities; module/function/block/value/node structure; block-parameter SSA; data, control, effect, resource, and target-dependency edges; operation signatures; entry/exit, calls, recursion, loops, traps, and unreachable code; constants and pure operations; structural validity; operation identity/version hooks; the minimal initial kernel; and the boundary between canonical semantics and diagnostic notation.

Binary serialization, detailed type layouts, ownership policy, complete effect-domain taxonomy, target encoding, optimizer algorithms, and AI transport packets are specified elsewhere.

---

## 2. Normative definitions

The terms **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** are normative.

| Term | Definition |
|---|---|
| semantic graph | Authoritative typed graph representing a XAX program. |
| entity | Semantically addressable immutable object or graph-local object. |
| module | Container referencing functions, types, constants, target requirements, imports, and exports. |
| function | Callable graph with an interface, entry block, blocks, effect interface, and capabilities. |
| recursion group | Content-addressed group of mutually recursive functions with local member references. |
| block | Control-flow region with parameters, nodes, and exactly one terminator. |
| node | Application of an operation definition to explicit operands, effects, resources, attributes, and target dependencies. |
| value | Immutable SSA result from a block parameter or node result. |
| operation definition | Canonical contract for an operation's types, effects, control, resources, proofs, attributes, and target constraints. |
| effect edge | Dependency carrying an `effect<D>` frontier for domain `D`. |
| resource edge | Linear SSA dependency carrying a resource value. |
| target-dependency edge | Explicit reference to target/package semantics required by an entity. |
| diagnostic notation | Non-authoritative visualization of canonical semantics. |

### 2.1 Identity classes

| Class | Lifetime | Purpose |
|---|---|---|
| persistent identity | Across sessions | Content-addressed immutable objects and published references. |
| graph-local identity | Inside one immutable graph | Blocks, nodes, parameters, results. |
| workspace handle | One query/mutation session | Compact AI-facing handles such as `F3`, `B2`, `N7`. |

Workspace handles MUST NOT be semantic identity. Graph-local identities MAY be renumbered if all references are updated and meaning is preserved. Persistent identities SHOULD be cryptographic content identities and SHOULD normally be hidden from AI context.

---

## 3. Canonical containment model

Conceptually:

```text
ProgramRoot
  -> Module*
       -> Type*
       -> Constant*
       -> RecursionGroup*
            -> Function+
                 -> Block+
                      -> BlockParameter*
                      -> Node*
                      -> Terminator
       -> TargetRequirement*
       -> Import*
       -> Export*
```

This is explanatory pseudostructure, not source syntax.

### 3.1 Module

A module references its imports, exports, functions, types, constants, required target/platform semantics, and any module-wide capabilities. File paths, textual symbol names, source line order, formatting, and human names MUST NOT determine meaning. Human names MAY exist as removable metadata.

### 3.2 Function

A function conceptually contains:

```text
Function {
    interface
    effect_interface
    declared_capabilities
    entry_block
    blocks
    semantic_attributes
}
```

`interface` defines data/resource inputs and outputs. `effect_interface` defines externally visible effect domains. `declared_capabilities` defines explicit authority requirements.

A function MUST NOT implicitly capture values. External semantic dependencies enter through explicit inputs, immutable entity references, capabilities, or target/package references.

### 3.3 Recursion groups

Naive content hashing cannot represent cyclic function hashes. Mutually recursive functions therefore reside in an immutable **recursion group** that:

- assigns deterministic group-local member indices;
- permits members to reference one another by local index;
- is content-addressed as one immutable object;
- exposes a persistent function identity as group identity plus member index.

Non-recursive functions MUST use the standalone acyclic `function` encoding; a group MUST hold exactly one recursive strongly connected component in canonical member order (`XAX_SPEC.md` §3.3). Recursion otherwise has ordinary call semantics and introduces no mandatory runtime, scheduler, allocation, or stack policy. The member identity is callable from outside the group through a group member function (`XAX_SPEC.md` §3.3, ADR-125).

---

## 4. Block-parameter SSA

XAX uses block-parameter SSA.

1. Every SSA value is immutable and defined once.
2. Node results are identified by `(producer, result_index)`.
3. Block parameters are identified by `(block, parameter_index)`.
4. Ordinary uses satisfy dominance; block parameters receive values from predecessor terminators.
5. Mutable variables and phi nodes are not core primitives.
6. Loop-carried and branch-specific values pass through block parameters.
7. Serialization order never defines evaluation order.

Block parameters are preferred to phi nodes because incoming values are attached directly to control transfers and the same mechanism carries data, resources, and effect frontiers.

A block is:

```text
Block {
    parameters { data* resource* effect* }
    nodes*
    terminator
}
```

Each block MUST have exactly one terminator. Every successor edge MUST supply exactly one argument for each successor parameter, matching class and type.

The entry block has no internal predecessor. Its data/resource parameters correspond to function inputs; its effect parameters correspond to the function effect interface.

### 4.1 Loops

A loop is an ordinary control-flow cycle. Loop-carried data, resources, and effect frontiers are header block parameters supplied by the back edge. No loop implicitly retains mutable state.

---

## 5. Edge classes

All semantic dependencies use one of these classes.

| Edge | Carries | Key obligation |
|---|---|---|
| data | ordinary SSA value | type, dominance, producer existence |
| control | successor block | terminator legality, successor arguments |
| effect | `effect<D>` frontier | domain match, valid frontier progression |
| resource | linear resource value | state match, no illegal copy/drop |
| target dependency | target/package reference | contract availability and compatibility |

### 5.1 Data

Pure operations may be reordered when data dependencies and exact semantics allow. Node storage order has no semantic sequencing effect.

### 5.2 Effects

For each domain `D`, an effectful operation consumes and produces an `effect<D>` frontier. Effect frontiers are semantic dependencies and normally consume no runtime storage.

They MUST NOT be duplicated to bypass ordering in one domain. Distinct domains MAY progress independently. Frontiers pass through block parameters at joins and loops and are consumed by function exits.

A function exposing `D` has an entry and exit frontier for `D`. Multi-domain operations consume/produce each required frontier unless their operation contract defines a more precise relation.

Effect-domain granularity may later be refined by memory/effect specifications without changing this graph model.

### 5.3 Resources

Linear resources are SSA values with additional use constraints. Resource transitions consume the prior state and produce the next state. Transfers across branches/loops use block arguments.

The verifier MUST reject illegal duplication, incompatible transitions, or disappearance where the resource contract requires release or transfer. Resource edges remain semantically distinguishable from duplicable data edges.

### 5.4 Target dependencies

Core target-independent operations do not gain target edges merely because lowering is target-specific. A target operation or target-constrained semantic operation MUST explicitly reference the package contract that gives it meaning. Target meaning MUST NOT be inferred from the compiler host, file name, symbol name, or opcode spelling.

---

## 6. Operation and node schema

Every node references an operation definition equivalent to:

```text
OperationDefinition {
    op_identity
    semantic_version
    family
    type_parameters
    data_inputs
    data_outputs
    effect_contract
    resource_contract
    control_contract
    attribute_schema
    proof_obligations
    target_contract
}
```

`semantic_version` changes when old and new interpretations could differ in meaning or validity. `attribute_schema` defines typed canonical attributes; unknown fields cannot silently affect semantics. `proof_obligations` describe facts such as provenance, bounds, alignment, permissions, or arithmetic preconditions.

A node is conceptually:

```text
Node {
    operation_ref
    type_arguments
    data_operands
    resource_operands
    effect_inputs
    attributes
    target_dependencies
    data_results
    resource_results
    effect_outputs
}
```

Result counts/types MUST be derivable from the operation contract, type arguments, operands, and canonical attributes.

A node MUST NOT contain hidden operands, allocations, control edges, ownership transfers, synchronization, syscalls, exception edges, or target assumptions.

### 6.1 Families

| Family | Role |
|---|---|
| value | constants and pure computation |
| aggregate | tuple/sum construction and extraction |
| control | call, branch, conditional branch, return, trap |
| memory | allocation, addressing, load, store, copy |
| resource | acquire, transfer, release, state transition |
| atomic | atomic operations and fences |
| target | machine/platform-defined primitive |
| meta | compile-time semantic construction/inspection |

Families classify contracts; they do not require a large fixed opcode set.

---

## 7. Control semantics

### 7.1 Terminators and branches

Every block has one explicit terminator. The initial core requires unconditional branch, conditional branch, return, and trap. There is no fallthrough.

A branch edge contains a successor block and the complete data/resource/effect argument bundle required by that block.

### 7.2 Entry and exit

The entry block is unique, has no internal predecessor, receives explicit function inputs, and receives one effect parameter per function effect domain. Target ABI-only hidden machine parameters are introduced during lowering unless they have canonical semantic meaning.

A `return` MUST provide the declared outputs, final effect frontiers, and satisfy all resource transfer/release obligations. A `trap` ends the dynamic path and has no successor. There is no implicit exception edge.

### 7.3 Calls

A call references or consumes a callable semantic entity with a known contract containing:

- input/output data and resource types;
- effect domains consumed/produced;
- capabilities;
- control properties needed for verification/optimization;
- target/package requirements when applicable.

A call cannot silently add an exception edge, allocation, synchronization event, scheduler interaction, or syscall. Direct recursion uses recursion-group member references. Indirect calls require a complete callable contract; its exact value/type representation is finalized by the type-system stage.

### 7.4 Unreachable code

A function MAY contain unreachable blocks or dead pure nodes, but all stored entities MUST still be structurally valid and type-correct. Unreachable effectful operations do not execute because no control path enters their block.

Optimization MAY delete unreachable/dead entities; XAX has no source-preservation requirement.

A node cannot semantically occur "after" a terminator because node order is non-semantic. Operations that must precede termination must be connected by data, effect, resource, or control dependencies.

---

## 8. Constants and pure operations

Constants are immutable semantic objects identified by exact type and value encoding.

Pure operations have no effect dependencies, hidden control transfer, or nondeterminism. They may be reordered or common-subexpression eliminated when dependencies permit.

Arithmetic semantics are explicit. Wrapping, checked, and saturating addition are distinct semantic operations or exact operation modes. Signed/unsigned interpretation belongs to the operation contract where applicable rather than being assumed from stored bits.

---

## 9. Structural validity

A valid function satisfies all applicable rules.

### 9.1 Entity and type integrity

- Every reference resolves locally or through a valid import.
- Every operation reference resolves to an exact known contract.
- Workspace handles are not serialized as semantic identity.
- Operand/result types satisfy operation signatures.
- Branch arguments match block parameters.
- Returns match function outputs.
- Callable operands satisfy their callable contracts.

### 9.2 SSA and control integrity

- Every value has one definition.
- Ordinary uses satisfy dominance.
- Every predecessor supplies each block parameter.
- There is exactly one entry block and one terminator per block.
- Successor references and argument bundles are valid.
- No implicit fallthrough or exception successor exists.

### 9.3 Effect and resource integrity

- Every effect edge has a domain and required frontiers are present.
- Frontiers are not illegally duplicated.
- Branches, loops, and returns propagate required effect frontiers.
- Linear resources are not illegally copied or dropped.
- Resource state transitions are valid.
- Every function exit satisfies resource obligations.

### 9.4 Target integrity

- Target operations resolve to explicit target/package contracts.
- Target-independent operations do not vary with compiler host.
- Required target capabilities are verifiable before lowering.

Other stages may add proof obligations without changing these structural classes.

---

## 10. Operation identity and semantic versioning

Diagnostic operation names are not identity.

Each operation definition MUST have stable semantic identity. Compact numeric keys, content identities, or interned references MAY encode it.

A semantic-version change is required for incompatible changes to operand/result interpretation, arithmetic behavior, effects, resource transitions, control behavior, proof obligations, target-visible semantics, or optimization legality. Purely diagnostic renaming does not require a new version.

A verifier MUST reject operation versions it cannot interpret exactly. It MUST NOT guess a nearby version. Target-defined operations follow the same rule through target-package identities.

---

## 11. Minimal initial semantic kernel

The first prototype SHOULD implement only enough semantics for the architecture's initial programs.

| Capability | Minimum support |
|---|---|
| integers | exact `bits<32>` / `bits<64>` constants |
| arithmetic | small exact integer set with explicit overflow behavior |
| functions | interfaces, entry, return |
| calls | direct call with explicit effects |
| control | unconditional/conditional branch, trap |
| stack memory | explicit stack storage creation |
| addressing | address derivation required for stack access |
| memory | load/store with explicit memory effects |
| native lowering | target/package references sufficient for direct machine emission |

Aggregates, broader resource semantics, atomics, additional memory forms, target primitives, and meta operations may be added later.

A new core primitive SHOULD be added only when testing or semantic necessity shows that existing operations plus specialization cannot express it exactly/efficiently; a library form would hide required effects/control/resources; repeated expansion materially harms verification, optimization, token efficiency, or lowering; or a common target-independent contract is necessary.

Human familiarity, syntax convenience, or elegance is not sufficient.

---

## 12. Canonical semantics vs diagnostic notation

A diagnostic view may show:

```text
F3
  B0(%0:b64, %1:b64):
    N0 = add.wrap %0, %1
    ret N0
```

This is not XAX source. Human-readable dumps, symbolic names, indentation, comments, pretty-printed types, and AI-facing compact text are non-normative.

Editing diagnostic text changes nothing unless a tool converts it into a semantic transaction that verifies and commits.

The canonical graph MUST remain fully defined if all optional diagnostic text is removed.

---

## 13. Core invariants

1. Meaning is the graph, not text.
2. Values are immutable.
3. Control, effects, resources, and target dependence are explicit.
4. No evaluation order is implied by storage order.
5. No hidden runtime is introduced by the graph model.
6. Calls expose their semantic contracts.
7. Loops are control-flow cycles with block parameters.
8. Recursion preserves persistent content addressing through recursion groups.
9. Workspace handles are not semantic identity.
10. Semantically meaningful attributes are typed and declared.
11. Unknown operation semantics are rejected rather than guessed.
12. Diagnostic readability has no normative weight.

---

## 14. Rejected alternatives

| Alternative | Why rejected |
|---|---|
| parser AST or conventional source as authority | Reintroduces a human-text layer and source regeneration. |
| mutable variables | Adds implicit state and weakens explicit dataflow. |
| phi nodes | Block parameters unify merge handling for data, resources, and effects. |
| instruction-list ordering | Creates hidden sequencing. |
| one global effect token | Needlessly serializes independent domains. |
| implicit effects or destructors | Hides observable ordering/resource transitions. |
| implicit exception edges | Hides control behavior at calls. |
| global hashes exposed to AI | Increases token cost; local handles suffice. |
| host target assumptions | Makes meaning depend on compiler host. |
| permanent target DSL | Creates a second language. |
| full sea-of-nodes initially | Adds control/verification complexity without demonstrated need. |
| human source locations as identity | Human source structure has no normative weight. |

---

## 15. Subsystem interfaces

**Types/values/layout.** Must provide canonical type identities, equality, parameterized types, constants, callable contracts, and target-aware layout without making layout implicit.

**Memory/ownership/resources.** Adds provenance, bounds, permissions, storage classes, alias facts, memory proof obligations, and linear state transitions over these edge classes.

**Effects/control/errors.** May refine effect domains, call summaries, capabilities, traps, and sum-valued recoverable errors while preserving explicit control/effects.

**Concurrency/atomics.** Uses operation contracts, effect edges, and target capabilities; schedulers remain libraries.

**Compile-time execution.** Manipulates semantic graph/value objects through XAX semantics rather than a second macro language.

**Serialization/transactions.** Defines deterministic ordering, interning, hashes, local-reference encoding, compact workspace handles, stale-base detection, verification, and immutable commit.

**Targets/lowering.** Target packages define machine operations, ABIs, legalizations, and capabilities. Lowering consumes explicit target dependencies and cannot change core target-independent meaning.

**Verifier/optimizer.** The verifier enforces structural and operation-specific obligations. The optimizer may rewrite any region when data, effect, resource, control, capability, and target semantics are preserved.

---

## 16. Open issues

### 16.1 Effect-domain granularity

The graph requires explicit effect frontiers, but optimal memory/effect partitioning is not yet fixed. A single broad domain may over-serialize; very fine domains may inflate graph/token cost. Later stages and prototype measurements must determine safe granularity.

### 16.2 Encoding trivial recursion groups

Resolved by OI-03 (2026-10-01): non-recursive functions use the standalone `function` encoding; one-member groups are reserved for self-recursive functions and carry no dedicated compact form. Groups hold exactly one recursive SCC in canonical member order.

### 16.3 Indirect callable contracts — resolved by OI-09

The bounded callable contract is a separately content-addressed `call_contract` semantic object referenced by first-class callable values. The contract identity is independent of implementation-function CIDs. Exact sealed dispatch sets remain optional optimization facts for devirtualization and MUST NOT replace the bounded contract merely because a current target set is known. Repeating the complete contract in each callable value is not semantic authority. Indirect calls remain invalid unless the verifier resolves the complete bounded contract; no unspecified-effects fallback exists.

---

## 17. Falsification criteria

This design must be revised if implementation or benchmarking shows that:

1. block-parameter SSA plus explicit dependencies costs materially more AI tokens per successful semantic mutation than an equally exact alternative;
2. explicit effect frontiers cause unacceptable graph growth or lost optimization that domain refinement cannot recover;
3. local edits routinely require broad renumbering/retransmission;
4. recursion-group identity creates material update amplification versus an immutable Merkle-compatible alternative;
5. verification repeatedly requires whole-program reconstruction rather than small changed neighborhoods;
6. important target primitives require hidden compiler semantics or ad hoc host knowledge;
7. operation versioning allows one persistent program to have multiple conforming interpretations;
8. resource transitions require a second incompatible graph mechanism;
9. the minimal kernel grows mainly for human syntax expectations rather than semantic or measured needs;
10. a tested alternative graph model gives materially better AI-edit locality or optimization without unacceptable verification complexity;
11. direct native lowering on two substantially different architectures requires architecture-specific assumptions in fundamental XAX semantics.

Such evidence invalidates the design choice; compatibility or aesthetic preference is not sufficient reason to preserve it.
