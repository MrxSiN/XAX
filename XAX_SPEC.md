# XAX Specification

**Status:** merged v0.1 normative architecture  
**Source set:** founding architecture plus Stages 01–17  
**Authority:** this document is the canonical merged documentation specification; it does not replace the canonical semantic program representation defined here.

## 1. Normative language and precedence

The keywords **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** are normative when uppercase.

When requirements conflict, implementations and future revisions MUST resolve them in this order:

1. semantic correctness and exact meaning;
2. deterministic machine interpretation of meaning;
3. AI tokens per successful semantic change, including generation reliability and repair cost;
4. runtime performance/latency, then memory footprint, then binary footprint;
5. compilation (generated-code) quality;
6. universal hardware/platform portability and target extensibility;
7. deterministic/reproducible builds and tooling behavior;
8. locality and incremental operation;
9. compiler/toolchain simplicity;
10. human convenience.

(Refined by ADR-078; ranks 1–2 together are the mission's "semantic correctness".)

Human readability, writability, naming style, formatting, and textual source preservation have no normative weight.

Document precedence: this specification is normative; `docs/NN_*.md` stage documents are detailed normative text subordinate to it on conflict; `XAX_CONFORMANCE.md` and `XAX_BENCHMARKS.md` define test and measurement obligations; `XAX_DECISIONS.md` records adopted rationale; `XAX_AI_Native_Programming_Language_Architecture.md` states founding principles and architecture intent and never overrides this specification; `XAX_STATE.md`, `XAX_HANDOFF.md`, and `XAX_REPLACEMENT_MATRIX.json` record evidence, never requirements.

A later implementation choice MUST NOT silently weaken a higher-ranked requirement. Performance, token-efficiency, portability, and self-hosting claims are objectives until supported by the evidence required in `XAX_BENCHMARKS.md` or `XAX_CONFORMANCE.md`.

## 2. Foundational invariants

| ID | Requirement |
|---|---|
| FND-001 | **Meaning is source.** The authoritative XAX program is its canonical semantic state. |
| FND-002 | Human-readable dumps, diagrams, pseudocode, diagnostic notation, disassembly, and protocol fallback text are projections, never authoritative XAX source. |
| FND-003 | XAX MUST NOT require a permanent second language or DSL for targets, ABI descriptions, builds, packages, macros, templates, or metaprogramming. |
| FND-004 | XAX MUST NOT require a runtime, GC, allocator, scheduler, reference-counting runtime, exception runtime, libc, OS, dynamic loader, or startup library unless explicitly required by the program or selected target/platform contract. |
| FND-005 | No allocation, deallocation, synchronization, syscall, initialization, ownership transfer, exception edge, scheduler interaction, I/O, or capability acquisition/release may be introduced invisibly. |
| FND-006 | Core semantics MUST NOT hardcode contemporary CPU, accelerator, OS, object-format, or ABI assumptions. |
| FND-007 | AI interaction SHOULD be local, query-driven, machine-first, and transactional; whole-repository context is not a requirement. |
| FND-008 | XAX MUST NOT claim universal superiority over all assembly. Code-quality claims MUST identify target, workload, semantic contract, objective, baseline, and measurement method. |
| FND-009 | A bare-metal deployment consisting only of a program graph and sufficient target package is valid. |
| FND-010 | Every abstraction either erases before runtime or has explicitly requested runtime semantics. |

## 3. Canonical semantic program model

### 3.1 Entities and containment

A XAX program is a persistent, typed, directed semantic graph using block-parameter SSA plus explicit data, control, effect, resource, and target-dependency relations.

Conceptually:

```text
ProgramRoot
  -> Module*
       -> Type*
       -> Constant*
       -> Function* / RecursionGroup*
            -> Function+
                 -> Block+
                      -> BlockParameter*
                      -> Node*
                      -> Terminator
       -> TargetRequirement*
       -> Import*
       -> Export*
```

The notation is explanatory only.

A module owns or references functions, types, constants, imports, exports, required target/platform semantics, and module capabilities. File paths, symbol spelling, source-line order, formatting, and human names MUST NOT determine meaning.

A function has:

```text
Function {
  interface
  call_contract
  declared_capabilities
  entry_block
  blocks
  semantic_attributes
}
```

External dependencies enter through explicit values, resources, capabilities, immutable entity references, or target/platform references. There are no implicit captures.

### 3.2 Identity classes

XAX distinguishes:

- **persistent identity:** immutable content identity across sessions;
- **graph-local identity:** block/node/parameter/result identity inside one immutable graph carrier;
- **workspace handle:** compact session-local reference used by query/mutation tooling;
- **logical lineage identity:** optional non-semantic continuity identity mapping successive immutable revisions.

Workspace handles and lineage identities MUST NOT replace content integrity.

### 3.3 Recursive functions

Content-addressed objects MUST remain acyclic at the CID level. Therefore:

- a non-recursive function MUST be serialized as a standalone `function` object;
- a recursive strongly connected component, including a self-recursive singleton, MUST be serialized in a `recursion_group` carrier;
- a `recursion_group` MUST contain exactly one recursive strongly connected component of its group-local call graph: every member reaches every member through `call.group_member` edges, and a singleton member calls itself. A group violating this rejects (`GRAPH-RECURSION-SCC`);
- members of a recursion group use deterministic group-local indices for internal recursive references;
- member order is canonical (`GRAPH-RECURSION-ORDER`). Each member has an erased key: its graph-fragment reference table and body with every group-local member index removed, plus its parameter and return type CIDs. For each start member, the candidate order is breadth-first discovery from that member following group calls in block/node order; its descriptor is, per position, the member's erased key and its callee indices renumbered to candidate positions. The canonical order is the candidate with the lexicographically smallest descriptor; candidates with equal descriptors encode byte-identical groups. A group not in canonical order rejects;
- a persistent member identity is `(recursion_group CID, member_index)`.
- that identity is callable as a **group member function** (ADR-125): a `function` object whose single reference is the `recursion_group` and whose body is the canonical ULEB `member_index` (no parameter or return lists; its interface is the member's). `call.direct` and `function_address` accept it like any function, which is how code outside a group calls into it; a member index outside the group rejects (`GRAPH-RECURSION-MEMBER`). `call.group_member` remains legal only inside group members (`GRAPH-GROUP-CALL-CONTEXT`). A `function` over a `graph_fragment` keeps its encoding and identity. A group call obeys the whole-heap-view borrowing contract of a direct call; any other memory-carrying operand or result of a group call (stack pointer, stack owner, bare memory frontier) rejects (`GROUP-CALL-MEMORY-VIEWS-ONLY`). Backends lower `call.group_member k` inside member function *m* as a direct call of member function *k* of the same group, so a target that supports `call.direct` supports recursion; a backend whose frame storage is not reentrant MUST reject recursive functions that use it rather than share it between activations (wasm32: `WASM-REENTRANT-FRAME`).

This rule resolves recursion without cyclic hash computation and does not add runtime semantics.

### 3.4 Block-parameter SSA

1. Every SSA value is immutable and defined once.
2. Node results are identified by producer and result index.
3. Block parameters are identified by block and parameter index.
4. Ordinary uses obey dominance; predecessor terminators supply successor block parameters.
5. Loops carry data, resource state, and effect frontiers through block parameters.
6. Every block has exactly one terminator.
7. Serialization or construction order never defines execution order.
8. XAX has no core mutable-variable or phi-node primitive.

A block is conceptually:

```text
Block {
  parameters { data* resource* effect* }
  nodes*
  terminator
}
```

Each successor edge MUST supply exactly one argument for every destination parameter with matching class and type.

### 3.5 Edge classes

| Edge | Meaning | Principal verifier obligation |
|---|---|---|
| data | ordinary SSA value | type, producer, dominance |
| control | successor and argument bundle | terminator and block-parameter compatibility |
| effect | effect frontier | domain/instance ordering correctness |
| resource | linear/affine semantic state | no illegal duplication, disappearance, or transition |
| target dependency | target/platform semantic reference | contract availability and exact configuration compatibility |

### 3.6 Operations and nodes

An operation definition is equivalent to:

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

A node is equivalent to:

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

A node MUST NOT contain hidden operands, effects, allocations, ownership transfers, synchronization, syscalls, exception edges, target assumptions, or observable temporaries.

Operation families are `value`, `aggregate`, `control`, `memory`, `resource`, `atomic`, `target`, and `meta`.

### 3.7 Control

Core terminators are:

```text
br target(args...)
cbr bits<1>, true(args...), false(args...)
switch key, cases..., default
ret values...
trap payload...
unreachable
```

There is no fallthrough and no truthiness coercion. `switch` has no fallthrough and requires unique cases plus either a default or proof of exhaustiveness.

`trap` is explicit fatal control. It performs no implicit unwinding or cleanup. Its portable payload core is a 16-bit unsigned reason: the empty payload is reason 0 (`unspecified`) with no target detail; a non-empty payload begins with the canonical ULEB encoding of a reason in `0..65535`, followed by target/platform-specific bytes, with the zero encoding permitted only when such suffix bytes are present. Prototype portable reason 1 denotes `explicit`; reason 2 denotes `integer-divide-by-zero` (ADR-084); additional portable meanings require an explicit specification decision. Target-specific suffix bytes are semantic data but do not acquire portable meaning or implicit cleanup/unwind behavior. `unreachable` is a verifier assertion and MUST be proven unreachable unless a separately defined raw/target construct supplies different semantics.

Core `call` has no hidden exceptional successor.

## 4. Types, values, constants, and layout

### 4.1 Core type families

The canonical core families are:

```text
bits<N>
float<F>
vec<N,T>
tuple<T...>
sum<T...>
ptr<space,T,permission,alignment>
resource<K,state>
fn<input...,output...>
effect<D>
opaque<K>
opaque-id<I>
```

Types are immutable and internable by canonical identity. `opaque-id<I>` is an
identity-qualified ABI/platform carrier type. It has no core runtime behavior,
does not manufacture provenance or ownership, and is valid only through explicit
ABI/platform contracts that define its representation and lifetime.

### 4.2 Exact scalar semantics

`bits<N>` is an exact N-bit value domain for arbitrary positive `N`. Stored bits have no global signedness. Signedness is an operation property where required.

Integer arithmetic MUST identify exact behavior, including overflow semantics. Representative families include wrapping, checked, saturating, signed, and unsigned interpretations where applicable. Pure bit operations likewise have width-exact semantics. `bit.xor`, `bit.and`, and `bit.or` return the N-bit exclusive-or, conjunction, and disjunction of two `bits<N>` values; `rotate.right k` rotates one `bits<N>` value right by the explicit amount `0 <= k < N` without changing width. `udiv` and `urem` return the unsigned quotient and remainder of two `bits<N>` values; a zero divisor executes an explicit trap with portable reason 2 and never yields a value. `int.truncate` maps `bits<M>` to `bits<N>` for `N < M` by keeping the low N bits; `int.zero_extend` maps `bits<M>` to `bits<N>` for `N > M`; identity width changes are invalid nodes. Constant shifts and sign extension are not kernel operations: they are the exact compositions `mul.wrap 2^k`, `udiv 2^k`, and `(zext(x) xor 2^(M-1)) - 2^(M-1)`, which lowering MAY select as single instructions (ADR-084, OI-39).

There are no implicit integer promotions or implicit value conversions.

`float<F>` identifies an exact floating format/semantic contract sufficient to determine supported values, exceptional values, rounding behavior, and other required observable semantics. Ambient host floating-point state MUST NOT silently affect canonical semantics.

### 4.3 Aggregates and sums

`vec<N,T>`, `tuple<T...>`, and `sum<T...>` are semantic value types independent of target ABI layout. Sum variants and aggregate fields are exact semantic structure; physical placement is a separate target/context query unless an explicit-layout type is selected.

### 4.4 Pointer and function types

`ptr<space,T,permission,alignment>` identifies semantic address space, addressed element type, static permission, and guaranteed minimum alignment. Provenance, object identity, extent, lifetime, alias class, and initialization are memory facts rather than hidden pointer payload requirements. For precise object-backed storage, provenance/alias class is derived from the storage identity; a redundant serialized local alias ID is not required.

A pointer type does not imply nullability. Null exists only when its address-space contract explicitly defines it.

`fn<input...,output...>` identifies exact value-level input/output types. Calling convention, effects, capabilities, resource transfer, and unwind/control behavior are carried by an explicit **CallContract** where required:

```text
CallContract {
  input_types
  output_types
  effect_summary
  resource_contract
  capability_requirements
  control_summary
}
```

Every indirect callable MUST have a bounded CallContract before an indirect call is valid. The bare function type alone is insufficient for an effectful or capability-bearing indirect call.

**OI-09 representation decision.** A CallContract is a separately content-addressed semantic object and callable values reference that contract identity. The contract is implementation-independent: changing a function body or function CID without changing its bounded interface/effect/control contract does not change the CallContract CID. Exact sealed dispatch sets MAY be attached as additional optimization facts for devirtualization, but target membership is not the sole contract authority because implementation-CID churn would otherwise churn package-facing callable contracts. Repeating the full contract inside every callable value is not the semantic representation; a future serializer MAY compress a low-reuse reference by deterministic inlining only if reconstruction yields the identical referenced CallContract identity.

Prototype schema v1 stores exact input/output type references plus return/trap bounds in kind 11. Effect-domain bounds and resource/capability-bearing value requirements are reconstructed from the exact typed interface in the current prototype. There is no unknown/unbounded effect form. General indirect-call operations remain a later implementation step and MUST reference a verified bounded contract when introduced.

### 4.5 Effect and capability separation

`effect<D>` denotes a semantic effect frontier for ordering in domain or refined domain instance `D`. It normally has no runtime representation.

Authority/capability values are not represented by `effect<D>` merely because both are compile-time-visible. Capabilities are explicit semantic authority objects/resources defined by their owning subsystem. This separation prevents effect ordering from being confused with permission to perform an operation.

### 4.6 Constants, zero, poison, and undefined values

Constants are typed canonical objects.

XAX has no canonical poison or `undef`. Undefined optimizer-internal states MAY exist only as non-source implementation artifacts and MUST NOT escape into canonical program semantics.

There is no universal zero/default value for every type. A zero/default construction is valid only where the type contract defines it.

### 4.7 Semantic type versus physical layout

Ordinary semantic types MUST NOT embed target ABI layout assumptions. Layout is queried under an explicit layout context, normally including target/platform/ABI identities.

Where physical representation is itself part of program meaning, XAX uses an interned explicit-layout type:

```text
ExplicitLayoutType {
  logical_type
  storage_extent
  alignment
  members_or_slices
  representation_constraints
  byte_or_bit_order
  target_scope
}
```

Conversion between logical and explicit-layout forms is explicit.

### 4.8 Reinterpretation and proof facts

The compiler MUST distinguish type equality, semantic-domain equivalence, representation compatibility, and safe reinterpretability.

Safe reinterpretation requires proof of extent, alignment, destination-valid bit patterns, and preservation of pointer/resource/effect/function contracts. Raw reinterpretation may waive only explicitly named obligations.

Ranges, known bits, nonzero facts, alignment, active variants, and similar refinements are verifier/optimizer proof facts in v0.1, not general runtime-distinct refinement types.

## 5. Memory, pointers, ownership, and resources

### 5.1 Storage objects

Storage creation is always semantically visible. A storage object has an identity and enough canonical semantics to determine class, address space, extent/layout requirements, lifetime policy, placement, ownership, and required effects.

Supported conceptual storage classes include `static`, `stack`, `region`, `arena`, `target-memory`, and `raw`. A heap is not fundamental; heap allocation is an explicit allocator operation supplied by a program/environment package.

Dynamic lifetime end is explicit. Scope exit does not imply destruction or release.

### 5.2 Pointer facts and addressing

Ordinary pointer-derived access is governed by proof of:

- live provenance;
- sufficient extent/bounds;
- required alignment;
- access permission;
- compatible access size/layout;
- legal alias relation;
- required initialization state.

Address construction uses semantic operations such as field/index/offset/narrow. A derived pointer cannot gain authority outside the source object's proven extent.

If an obligation cannot be proven, the graph MUST use an explicit checked operation, establish stronger evidence, or use an explicit raw waiver. Hidden bounds checks are forbidden.

### 5.3 Load, store, copy, and move

Ordinary `load` and `store` are non-atomic and non-volatile unless their operation contract says otherwise.

Copy operations distinguish overlap semantics. Ordinary copying cannot duplicate linear ownership. `move` transfers initialized contents and contained linear resources and renders the source unavailable for ordinary read until reinitialized.

### 5.4 Aliasing

Aliasing is provenance/relation based, not type-name based.

- distinct simultaneously live storage object identities do not alias unless an explicit raw/target mapping says otherwise;
- views of one object may alias only where extents overlap;
- numeric address reuse does not merge provenance;
- casts do not silently strengthen no-alias guarantees.

Alias facts may include exclusive, shared-read, may-alias class, or unknown/conservative relations.

### 5.5 Volatile, MMIO, and DMA

Volatile access is observable but is not atomic and does not create synchronization.

MMIO/device memory is governed by target-defined address-space/device contracts describing legal access widths, alignment, side effects, speculation restrictions, ordering hooks, and other relevant behavior.

DMA buffers, mappings, ownership transitions, cache maintenance, and synchronization are explicit resources/operations when required by the target/platform contract. DMA buffer resource kinds that use the shared cross-target vocabulary distinguish `host-unmapped`, `host-mapped`, `host-dirty`, `device-owned`, `device-pending`, and `host-stale`. `device-pending` means device work has not yet passed the required explicit synchronization point; `host-dirty` and `host-stale` mean required non-coherent cache maintenance has not yet occurred. A coherent package may omit the dirty/stale states and maintenance operations when its target contract proves they are unnecessary, but it may not silently omit ownership, mapping, or synchronization transitions that remain semantically required. These states use the existing compact `resource<K,state>` encoding; no DMA-specific core object kind is required.

### 5.6 Raw operations

Unsafety is operation-local. A raw operation MUST enumerate waived obligations, such as provenance, bounds, alignment, permission, aliasing, initialization, or lifetime.

A waiver never removes unrelated typing, SSA, effect, resource, capability, or control obligations. Missing proof never silently becomes unchecked behavior.

`pointer_address` (ADR-081) converts a pointer to `bits<N>`, N equal to the selected target's pointer width. It carries a mandatory provenance-exposure waiver attribute, requires live storage when the pointer has a local fact, and produces an integer with no provenance. Only `pointer_rebase` converts such an integer back into a dereferenceable pointer, and only inside a live view that already carries the provenance.

`pointer_rebase` (operation 73, ADR-092) takes a view pointer with a local storage fact, a `bits<32|64>` address (the backend requires the target pointer width), and an extent attribute E. The result type MUST be in the view's address space, with the same element, no added permission, and alignment A no greater than the view's. The result carries the view's storage, lifetime, and alias class, and extent E (1 <= E <= view extent). At run time, let d be the address minus the view address, modulo 2^N. If d > view extent - E or d is not a multiple of A, the program traps; no value is produced. The verifier models the unknown position as a *window* (view extent - E, accumulated across nested rebases). A load through a windowed pointer proves initialization only when the whole window plus the access is initialized. A store through it records no new initialized interval. Atomics, heap-call contracts, and view-base requirements reject windowed pointers. The reference executor rejects the operation, because addresses are target facts. Lowering on x86-64 Linux is `sub`, `ror log2(A)`, `cmp`, then a cold trap branch; on wasm32 it is `i32.sub`, `i32.rotr`, `i32.gt_u`, then `unreachable`. A target whose storage could start at address 0 MUST reserve it, because programs may use 0 as a null link (wasm32 reserves bytes 0–15; ADR-093). Foreign code that dereferences an exposed address MUST receive that storage's memory effect so lifetime ordering stays explicit.

Pointer-typed memory elements (ADR-082) hold one target pointer word (access size 4 or 8; the backend requires its pointer width). Only provenance-free pointers — function addresses and foreign/external pointers without a local storage fact — may be stored; a reloaded pointer carries no facts. Storing a pointer with local storage provenance is rejected (`MEMORY-POINTER-STORE-LOCAL-PROVENANCE`) until container/referent lifetime coupling exists (OI-37). Pointer-linked data over XAX-owned storage uses arena + index representations.

`link` (type form 11, ADR-097) is an 8-byte scalar whose only constant is null. A view whose element is a tuple of whole-byte bits, float, or link fields is a record array: its extent is a whole number of records, `address_offset` moves by whole records or lands exactly on a field (and then has the field's extent), and checked dynamic-offset accesses cannot reach it. `link_make` (operation 74) turns a record-start pointer into a link. `link_follow` (75) takes the storage's whole record view and a link, and yields a one-record pointer after a null test. Each storage's link fields point into one fixed target: itself, or the record view named by an optional fourth `heap_view` operand. A store into a link field accepts only null or a link into that target. Foreign calls may not receive a link-bearing storage's memory effect except to deallocate it. Atomics may not write link fields. A target must outlive the storages that target it. Links compare only with `eq`/`ne`. `link_target` (76, ADR-101) in an entry block declares that one borrowed view parameter's links point into another borrowed view parameter. Each direct call site must pass a matching pair. Without it, borrowed views link into themselves. Under these rules every loaded link is null or a record start of a known live storage, so following it needs no range check.

### 5.7 Resources

A canonical resource has type `resource<K,state>`.

Resource acquisition, transfer, state transition, split/join where supported, release, and permitted affine discard are explicit graph operations.

A linear resource MUST reach exactly one allowed terminal transfer/release on every terminating path unless transferred out. An affine resource may be discarded only by an explicit kind-approved operation. No implicit RAII destructor exists.

## 6. Effects, calls, and errors

### 6.1 Effect partial order

Effects form an explicit partial order. A pure operation has no effect frontier. An effectful operation consumes and produces frontiers for every domain instance it orders.

Standard domains include `memory`, `io`, `syscall`, `device`, `filesystem`, `network`, `time`, `random`, `privileged`, `unsafe`, and `atomic` where concurrency semantics require it.

Domains are not automatically hierarchical. Domain refinement is allowed only with proof of independence. Unrelated domains MAY progress independently. For memory, filesystem, network, and device effects, the canonical granularity rule is the narrowest verifier-proven semantic domain instance; when independence is not proven, operations MUST share a conservative instance rather than inventing a finer partition. XAX does not impose a deeper universal object/file/socket/device partition taxonomy.

Persistent encoding MAY compress or reconstruct effect edges only when reconstruction is deterministic and produces exactly the same semantic dependency relation. OI-08 evidence prefers domain-grouped semantic topological runs with explicit operation handles and explicit predecessor deltas at roots/forks/joins over repeated full frontiers. Any such run order is itself semantic effect-order data; ordinary node, record, CID, file, construction, or traversal order MUST NOT be used to infer an effect dependency. Canonical store v1 is unchanged by that benchmark-only selection.

### 6.2 Effect summaries

Every callable with observable behavior MUST expose a verified upper-bound effect/control contract. A conceptual summary includes observed/modified domains, return behavior, trap behavior, and any explicit foreign-exception contract.

Stored and derived summaries MUST agree. Recursive summary inference MUST reach a deterministic conservative fixed point.

A direct call consumes and produces the frontiers required by the callee contract and has no hidden cleanup or exception edge.

A direct call that transfers a linear resource MUST consume exactly one live incoming resource value and every associated ordered effect frontier, then produce exactly the declared successor resource/effect values. The caller MUST NOT reuse pre-call values, and the callee MUST explicitly return, release, or otherwise legally terminate every incoming linear resource on every return path. An initial bootstrap subset MAY support only the exact single-block pass-through contract `(resource<stack-storage,live>, effect<memory>) -> (resource<stack-storage,live>, effect<memory>)`; that restriction is an implementation limit, not a second calling language or implicit ABI.

### 6.3 Recoverable errors and foreign exceptions

Recoverable errors are ordinary values, normally sums such as `sum<ok:T,err:E>`, and are handled by ordinary control flow.

Foreign unwinding is not core exception semantics. A foreign ABI that may unwind requires an explicit interoperability operation/adapter with visible exceptional control. Such an adapter converts, contains, traps, or explicitly rethrows under the same foreign ABI contract.

## 7. Concurrency, atomics, interrupts, and real-time profiles

### 7.1 Atomic operations and orders

Portable atomic families are:

```text
atomic.load
atomic.store
atomic.rmw
atomic.cmpxchg
atomic.fence
```

Portable orders are `relaxed`, `acquire`, `release`, `acq_rel`, and `seq_cst`; `consume` is not a portable order.

Valid order constraints include:

- load: relaxed/acquire/seq_cst;
- store: relaxed/release/seq_cst;
- RMW: all five;
- compare-exchange failure: relaxed/acquire/seq_cst, never release-like, never stronger than the success read-side guarantee;
- fence: acquire/release/acq_rel/seq_cst; relaxed fence is invalid.

Atomic arithmetic retains the exact arithmetic contract of the selected update operation.

### 7.2 Target atomic capability

Atomic legality is target-dependent and must query exact address space, width, alignment, family, order, and scope. Target support may be `native`, `bounded_sequence`, `runtime_assist`, or `unsupported`, with progress/retry/alignment properties.

A compiler MUST NOT silently insert a lock, scheduler call, allocator use, syscall, or helper runtime. Runtime assistance is legal only when declared by the target/platform and explicitly permitted by the selected build/profile policy.

### 7.3 Data races and synchronization libraries

Non-atomic conflicting shared accesses must be ordered so no data race exists. If proof is unavailable, use atomics, explicit synchronization, stronger ownership/separation evidence, or an explicit raw/target operation with defined concurrent semantics.

Data races do not grant arbitrary compiler freedom.

Threads, tasks, actors, fibers, coroutines, futures, event loops, mutexes, channels, and similar mechanisms are optional semantic libraries unless a target requires a primitive. Their blocking, progress, scheduler, ownership, and synchronization behavior MUST remain explicit.

### 7.4 Interrupts and target traps

Interrupt/fault/target-trap handlers are ordinary functions referenced by target/platform entry contracts stating ABI, privilege, priority, nesting, reentrancy, allowed effects, stack/storage contract, saved state, and resume/termination behavior.

Asynchronous entry does not imply a scheduler, heap, libc, exception runtime, or thread runtime.

### 7.5 SIMD/GPU boundary

`vec<N,T>` is a value type and does not create execution agents. GPU/accelerator execution topology, scopes, barriers, memory spaces, launches, and host-device synchronization belong to target/platform semantics and explicit libraries.

### 7.6 Real-time profiles

A real-time profile is a rejection policy applied after specialization and again after lowering. It may forbid blocking, unbounded retry, allocation, dynamic initialization, runtime assistance, scheduler/kernel interaction, unknown external calls, unbounded stack/recursion/interrupt masking, or unknown progress.

Unknown is not safe under a strict profile.

Timing information is classified as semantic proof, target/platform guarantee, or cost estimate. Only the first two, plus explicit bounded environment assumptions, may support hard guarantees. Cost estimates MUST NOT be relabeled as guarantees.

## 8. Compile-time execution, specialization, and metaprogramming

### 8.1 One semantic language

XAX metaprogramming is XAX executing XAX. There is no macro language, template language, or preprocessor.

Compile-time and runtime are semantic stages. Stage crossing is explicit; a compile-time value becomes runtime program semantics only through explicit materialization/construction.

Types, constants, canonical semantic references, and explicitly provided capability values may be compile-time values.

### 8.2 Isolation and authority

Compile-time execution has no ambient filesystem, network, clock, randomness, process state, host API, or device authority. Such inputs/effects require explicit capabilities and, in reproducible mode, explicit declared inputs.

Target packages are inspected/executed as XAX semantic data/computation; compiling for a device never grants compiler-host device access.

### 8.3 Generic programming

Generic programming is ordinary XAX computation plus specialization. No distinct generics type system is required.

Specialization may erase abstraction, clone or reuse semantic objects, and choose target-specific alternatives under explicit facts. Monomorphization is a policy, not a language mandate.

### 8.4 Semantic introspection and construction

Compile-time XAX may inspect canonical types, constants, operation contracts, graph structure, capabilities, target contracts, pointer facts, and identities according to granted introspection authority.

It may construct candidate constants, types, operations, blocks, functions, graph/module fragments, and authorized target objects directly as semantic structures. It MUST NOT generate text and reparse it as a required semantic path.

Generated candidate semantics MUST pass the same verifier as non-generated semantics before commit.

### 8.5 Determinism, boundedness, caching

Successful compile-time evaluation under the same complete semantic inputs and policy MUST produce the same semantic result.

Every evaluation has finite budgets for evaluation work, recursion depth, memory, semantic-object creation, and generated graph growth. Exhaustion is a deterministic failed attempt and cannot yield a partial accepted result.

Memoization is permitted only when the complete meaning-affecting dependency closure matches. Immutable verified results SHOULD be internable by canonical identity.

## 9. Canonical serialization, identity, and versioning

### 9.1 Store invariants

A canonical `.xax` store is deterministic, content-addressed, corruption-detecting, and locally readable. Immutable CID-addressed objects are never changed in place. A changed hashed semantic fact changes its object CID and propagates through semantic ancestors; unchanged objects retain their CIDs.

Non-semantic metadata never changes semantic CIDs or root identity.

### 9.2 Container v1

A v0.1 canonical store has ordered regions:

1. container header;
2. semantic object records;
3. optional non-semantic records;
4. canonical index and integrity trailer.

Header fields, in canonical order:

```text
magic                    = 58 41 58 00   # XAX\0
container_major          = minimal ULEB128, value 1
container_minor          = minimal ULEB128
hash_suite               = minimal ULEB128 enum
root_cid                 = digest for selected suite
semantic_object_count    = minimal ULEB128
nonsemantic_record_count = minimal ULEB128
feature_flags            = minimal ULEB128 bitset
```

For v0.1, **hash suite 1 is BLAKE3-256 and CIDs are 32 bytes**. Readers MUST reject unsupported major versions, mandatory feature bits, or hash suites. Future hash migration is versioned; a reader MUST never substitute a different hash algorithm under suite ID 1.

### 9.3 Primitive encoding

- unsigned integers: minimal ULEB128;
- signed schema integers: ZigZag then minimal ULEB128;
- booleans: `00` false, `01` true;
- lengths/counts: minimal ULEB128;
- byte strings: length plus raw bytes;
- lists: count then canonical elements;
- unordered semantic sets: schema-defined canonical order.

Overlong, ambiguous, unknown-forbidden, out-of-bounds, or otherwise noncanonical encodings MUST be rejected rather than normalized as canonical input.

### 9.4 Semantic object envelope and CID

Each semantic record is:

```text
record_length
cid
kind_id
schema_version
reference_table
body_length
semantic_body
```

CID input is:

```text
"XAX-SEM-1" || kind_id || schema_version || reference_table || body_length || semantic_body
```

The stored CID, outer length, file offset, container version, index, non-semantic metadata, and integrity trailer are excluded. Decoders MUST recompute and verify every CID.

### 9.5 Core object kinds

| ID | Kind |
|---:|---|
| 1 | program_root |
| 2 | module |
| 3 | function |
| 4 | type |
| 5 | constant |
| 6 | target |
| 7 | graph_fragment |
| 8 | recursion_group |
| 9 | package |
| 10 | build |
| 11 | call_contract |

Kind 8 resolves the recursive-function carrier required by the semantic graph model. Kinds 9 and 10 are the package/build semantic carriers. Kind 11 is the reusable bounded CallContract selected by OI-09. Other kinds require a versioned registry/schema.

### 9.6 References and interning

Each object has one canonical direct-reference table: collect referenced external CIDs, deduplicate, sort by unsigned lexicographic bytes, assign dense indices, and encode the sorted list. Body references use minimal ULEB128 indices.

Local entities inside one semantic body use schema-defined canonical definition order.

Duplicate semantic records for one CID are forbidden.

### 9.7 CID, lineage, Merkle DAG, and mutation

CID is authoritative immutable content identity. Optional 128-bit lineage/workspace LIDs may map a logical editable entity across revisions but are non-semantic and excluded from semantic hashes.

The semantic root heads a Merkle DAG. Mutation is copy-on-write: replace the lowest changed semantic object, canonicalize/hash it, rebuild only ancestors whose child CID changed, and retain every unchanged object.

Graph-fragment boundaries are identity-relevant objectization choices but not observable runtime behavior. For v0.1, canonical byte equality across implementations is required only for the same object graph/schema/objectization. A future canonical-normalization policy may further constrain fragmentation after evidence is available.

### 9.8 Non-semantic metadata, record order, index, and integrity

Debug names, source-origin descriptions, comments, UI layout, profiling observations, timestamps, local handles, and diagnostic caches are non-semantic unless another specification explicitly promotes them. They are stored outside semantic envelopes and may refer to CIDs/LIDs. Changing or removing them MUST NOT change semantic CIDs or the semantic root.

Semantic records in a canonical store are sorted by CID in ascending unsigned lexicographic byte order. Non-semantic records follow them and use their tooling-schema ordering. Record order is independent of graph traversal and construction history.

The canonical index has one entry per semantic record:

```text
cid || file_offset || record_length
```

Entries are CID-sorted; offsets and lengths use minimal ULEB128. The index is non-semantic but participates in canonical container bytes and whole-store integrity. A random-access reader SHOULD be able to locate and validate one object without deserializing unrelated objects.

The store ends with:

```text
index_length   # minimal ULEB128
index_bytes
store_digest   # 32 bytes
trailer_magic  # 58 41 58 45 = XAXE
```

For container v1, `store_digest` is BLAKE3-256 over every byte from the start of the file through the final byte of `index_bytes`, excluding the digest and trailer magic. A bounded reader MAY validate an individual record without the whole-store digest; it MUST validate the digest before claiming whole-store integrity.

### 9.9 Version evolution, compatibility, and corruption

Container version, object schema version, and hash suite are independent version dimensions. A major container version may break framing. A minor version of the same major MUST preserve record location and deterministic rejection of unsupported mandatory features. Semantic reinterpretation or canonical object-encoding changes require a new object schema version. Hash-suite migration is an explicit store-wide identity migration; CIDs from different suites are never silently interchangeable.

A newer implementation SHOULD read older supported versions when their exact semantics remain implemented. A writer MAY emit an older schema only when meaning is preserved exactly. An older reader MAY preserve newer framed records opaquely, but MUST reject verification/optimization/compilation/mutation when any reachable kind, schema, required feature, or hash suite is unsupported. Unknown reachable semantic fields are never silently ignored.

Canonical schema migration decodes under the exact old schema, constructs the corresponding new semantic object, serializes under the new schema, recomputes changed CIDs, rebuilds affected Merkle ancestors, and produces a new root. It is never in-place reinterpretation.

Readers MUST fail deterministically on invalid header/trailer magic, unsupported required versions/features/schemas/hash suites, non-minimal integers, invalid booleans/enums, length/count overflow, record-boundary violations, missing/trailing semantic-body bytes, noncanonical/duplicate reference tables, invalid local indices, duplicate record CIDs, CID mismatch, illegal CID cycles, missing reachable objects, noncanonical semantic-record order, inconsistent index, or store-digest mismatch when full validation is requested. They MUST NOT heuristically repair corrupted semantics. Separate recovery tooling may copy intact objects into a new store but cannot represent guessed meaning as the original artifact.

## 10. AI workspace, queries, transactions, and diagnostics

### 10.1 Workspace model

A workspace binds a canonical base root, optional target/platform/configuration identities, verifier/compiler versions, local handle tables, derived facts, and transaction state.

The default retrieval principle is: return the smallest semantic neighborhood that completely answers the query under the declared mode.

Queries SHOULD support bounded expansion by relation kind, direction, depth, entity count, region, effect domain, dominance, ownership, target dependency, diagnostic dependency, and token budget. Truncated results MUST identify truncation and continuation.

A compiler-service implementation MAY additionally enforce an exact serialized **response-byte budget** as a transport/tooling control. A byte budget is not a model-token budget and MUST NOT be reported as one. For paginated queries, if the caller-requested page exceeds the byte budget, the service MAY return the largest deterministic positive-progress prefix whose exact serialized response fits and MUST return continuation for the next unreturned entity. If no positive-progress page can fit, or if a non-paginated response cannot fit, the query MUST fail deterministically without publishing local handles or accounting response bytes for data that was not returned. Omitting the byte budget MUST preserve the unbudgeted query result.

### 10.2 Core query families

Required families include `entity`, `expand`, `users`, `operands`, `callers`, `callees`, `type`, `effects`, `layout`, `cost`, `invalidate`, `map_semantic`, `map_artifact`, `root`, `diff`, `proof`, and `neighborhood`.

Query results MUST distinguish authoritative facts, derived facts, estimates, unknown/unavailable facts, and stale facts. Target-dependent results MUST identify the target package/configuration.

Artifact mappings are derived compiler facts, never canonical program semantics. Exact byte mappings MUST be attributable to the exact semantic root, target/configuration, compiler/lowering identity, and emitted artifact. Output-affecting compiler and lowering implementations MUST have explicit versioned identities; those identities MUST NOT be reverse-derived from diagnostic text or disassembly. A reusable mapping binding records the semantic root, target/configuration identity, compiler identity, lowering identity, emitted-artifact identity/digest, and retained exact ranges. If any recorded dependency changes, the binding is stale and mapping queries MUST reject or return stale rather than reuse it. Byte ranges use half-open intervals `[start,end)`. An implementation MUST NOT infer an exact semantic range merely from instruction adjacency or disassembly when emission provenance is unavailable. A semantic entity that emits no independently attributable byte range, or an artifact range whose contributors cannot be established exactly, MUST be reported as unavailable/unknown rather than assigned a guessed mapping. Workspace-local artifact/mapping handles are generation-scoped and become stale when their dependency scope changes. The `map_semantic` / `map_artifact` query contract is target-independent: backend-specific provenance carriers and artifact container layouts are tooling details, not alternate semantic interfaces or source forms.

A `proof` query reports verifier-status evidence, not a canonical proof certificate. When a proof result is exposed as a transaction read dependency, the workspace MUST bind a local proof-dependency identity to the exact semantic subject observed, the root at which it was observed, the verifier identity/version, and the freshness rule required by that result. The binding MUST NOT become semantic source or require persistent CIDs in ordinary AI context. A proof dependency MAY remain reusable across an unrelated commit only when the implementation can establish that the exact semantic subject and verifier identity required by the reported fact are unchanged. Root-scoped proof dependencies become stale on any root change. Once a proof dependency is invalidated by a dependency-changing commit, later restoration of equal-looking state MUST NOT silently revive that old local dependency handle.

### 10.3 Transactions

Every canonical mutation occurs in a transaction:

```text
Transaction {
  expected_root
  optional_read_set
  mutations
  requested_checks
  commit_policy
}
```

Commit sequence:

```text
open expected root
-> apply mutations to private candidate state
-> validate local preconditions/read set
-> verify required invariants
-> derive immutable replacement objects
-> compute candidate root
-> atomically compare expected root
-> publish candidate root
```

Stale-base or failed verification MUST leave the canonical root unchanged.

A workspace-local handle MAY abbreviate `expected_root` in a transaction only when the handle resolves unambiguously to a particular workspace root and freshness scope. Such a handle is non-semantic tooling. The final atomic comparison MUST validate the handle's freshness scope in addition to the resolved root identity; matching root bytes after an intervening change do not make a stale generation-scoped handle current again.

Mutation vocabulary includes `insert`, `delete`, `replace`, `connect`, `disconnect`, `set`, `move`, `specialize`, `verify`, `commit`, and `rollback`.

A relation replacement MUST identify the exact relation being changed and carry a local precondition for the old relation. For an operand/use replacement, the mutation identifies the containing operation and operand position plus the expected old value reference and replacement value reference. If the old relation does not match, commit MUST reject with a relation conflict before publication. The candidate graph MUST then pass the ordinary type, dominance, control, effect/resource, and structural verifier obligations before publication. A bootstrap API MAY represent this as a typed host-language structure such as `ReplaceUse`; that structure is tooling only and is not XAX source or a permanent mutation DSL.

A node deletion MUST carry an exact local containment precondition for the entity being removed. For graph nodes this includes the expected containing block and node position or an equivalent exact containment identity. A deletion MUST reject before publication if the target is no longer at that containment relation. It MUST also reject if any semantic use that survives the transaction still refers to a produced value of the deleted node. After deletion, any deterministic local-position renumbering required by the graph representation is tooling/canonicalization work and MUST preserve all surviving value relations. The resulting candidate graph MUST pass the ordinary verifier before publication. A bootstrap implementation MAY initially restrict deletion to a verifier-safe pure-node subset; such a typed host-language carrier (for example `DeleteNode`) is tooling only and is not XAX source or a permanent mutation DSL.

A graph-node insertion MUST carry an exact semantic container/position precondition. If a bootstrap implementation uses an existing node as an insert-before anchor, the request MUST also state the expected containing block and anchor position; drift rejects atomically as a containment/position conflict. Surviving references to pre-existing nodes MUST be deterministically remapped when local node numbering shifts. An inserted result needed by another mutation in the same transaction MAY be named only by a transaction-local temporary identity until commit; that temporary identity MUST NOT become a persistent semantic identity or workspace-global source notation. The candidate graph MUST pass the ordinary verifier before publication. A bootstrap implementation MAY initially restrict insertion to verifier-safe pure constants and wrapping arithmetic and MAY require an existing anchor; typed host-language carriers used for that bootstrap are tooling only.

A graph-node `move` MUST carry exact old containment and exact destination-anchor preconditions. A same-block move changes only containment/order: semantic uses continue to refer to the same producer identities and any local node-position representation MUST be deterministically remapped. Source or destination drift rejects before publication. A move MUST NOT silently rewire data flow, control flow, effects, ownership, or resources. The completed candidate MUST pass the ordinary type, SSA-dominance, control, effect/resource, and structural verifier obligations before publication. A bootstrap implementation MAY initially restrict move to one verifier-safe pure constant/wrapping-arithmetic node moved immediately before an existing anchor in the same block; a typed host-language carrier such as `MovePureNode` is tooling only and is not XAX source or a permanent mutation DSL.

A workspace `specialize` request MUST identify an exact source function and explicit compile-time arguments, including exact parameter positions and types. Construction remains private candidate state until commit and MUST pass the ordinary semantic verifier before publication. Existing source functions and callers remain unchanged unless separate explicit mutations rewire them. A bootstrap implementation MAY initially clone only a verified standalone, straight-line, single-block function containing constants and pure wrapping arithmetic by materializing exact constant arguments and removing those parameters from the clone interface. A typed host-language carrier such as `SpecializeFunction` is tooling only; this restricted semantic clone is not textual substitution, a macro/template language, a general compile-time evaluator, or a META conformance claim.

A control-edge argument `disconnect` MUST identify the exact containing block, terminator edge position, argument position, and expected old value relation. Containment/edge drift and old-relation drift MUST reject before publication. A corresponding `connect` identifies the same exact relation position and a graph-local or transaction-local replacement value. A transaction MAY carry disconnect+connect together so no verifier-invalid intermediate graph is ever published. The completed private candidate MUST pass the ordinary branch-arity/type, SSA-dominance, control-flow, and structural verifier obligations before publication. Bootstrap host-language carriers used to represent this operation are tooling only and MUST NOT become a textual graph-edit language or authoritative source form.

A candidate-only `verify` service MAY construct and retain private candidate state without publishing it. Verification MUST apply the same transaction root/read/local-precondition checks, mutation construction path, and ordinary semantic verifier obligations required before commit. A successful candidate-only verification MAY return a short workspace-local candidate handle, but MUST NOT expose candidate semantic CIDs, transaction-local inserted-result identities, or otherwise make the private candidate authoritative source. The canonical root and workspace generation MUST remain unchanged. Candidate handles are tooling-only and scoped to the verified base generation/verifier context; a successful canonical commit invalidates outstanding private candidates rather than silently rebasing them. `rollback`/discard removes the named private candidate and its transaction-local state without changing the canonical root or generation. Failed verification and failed/repeated rollback MUST likewise leave canonical state unchanged. Stale root, ordinary read, proof-dependency, and artifact-dependency assumptions MUST reject candidate verification rather than being refreshed merely because a private candidate was requested. Candidate verification MUST revalidate dependencies before returning a reusable candidate handle so raw-root ABA cannot revive an invalidated local dependency.



Read sets MAY contain proof-dependency handles returned by `proof`. Commit MUST validate those dependencies distinctly from ordinary entity-handle freshness. If a recorded proof dependency is no longer valid, commit MUST reject atomically with a proof-dependency conflict before publication. Proof dependencies MUST be revalidated at final publication, not only when candidate construction begins, so root-byte ABA cannot revive an invalidated local proof dependency. A transaction may rely on a currently valid proof dependency while changing its subject; that dependency is then stale for later transactions unless the workspace obtains a new verified dependency.

Semantic rebase is permitted only after revalidating targets, attributes/relations, read-set assumptions, handles, and local preconditions. Blind replay is forbidden.

### 10.4 Conflict classes

At minimum the system distinguishes root/identity, attribute, relation, delete/use, containment, proof-dependency, and artifact-dependency conflicts. Disjoint transactions SHOULD merge only when dependency analysis proves compatibility.

### 10.5 Machine-first diagnostics

Diagnostics are structured data:

```text
Diagnostic {
  code
  entity
  rule
  expected
  actual
  dependencies
  repair_neighborhood
  severity
  phase
}
```

The core fields through `repair_neighborhood` are required. Under fixed inputs, the core repair neighborhood MUST be deterministic. Natural-language explanation is optional presentation.

### 10.6 Token protocol

The optimization target is minimum **model tokens per successful semantic mutation**, including repair turns. Dedicated tokenizer vocabulary is permitted but not assumed. A fallback transport MUST be versioned, deterministic, unambiguous, whitespace-independent, and explicitly non-source.

Workspace accounting SHOULD track model input/output tokens, semantic entities, query/mutation counts, rejected transactions, repair rounds, committed changes, protocol bytes, artifact bytes, verifier work, and target-cost query work.

## 11. Universal target model

### 11.1 Target package

A target package is an immutable content-addressed XAX module graph describing a machine family or exact target configuration. Exact revision identity is authoritative; names are metadata.

Conceptually:

```text
TargetPackage {
  logical_identity
  revision_identity
  compatibility_metadata
  capabilities
  machine_value_types
  memory_spaces
  register_units
  physical_registers
  register_classes
  instruction_definitions
  target_operations
  legalization_rules
  selection_rules
  scheduling_model
  calling_conventions
  relocation_kinds
  image_object_profiles
  platform_profiles
}
```

A target configuration fixes exact target revision, selected capabilities, ABI/platform profile, object/image profile, legality-changing parameters, and any permitted emulation/runtime assistance.

### 11.2 Capabilities and memory spaces

Capabilities are structured machine-verifiable facts. Absence means not proven available.

Every memory space states identity, address representation/width, address unit, endianness where applicable, alignment/access-width rules, device/volatility semantics, coherence, atomic support, visibility/scope, and pointer-conversion legality.

Same numeric address width does not make two spaces equivalent.

### 11.3 Registers and instructions

Target register modeling MUST support irregular, overlapping, banked, aliased, fixed-purpose, paired, tied, and partially addressable registers using explicit register units/classes and constraints.

An instruction definition states operands/results, constraints, implicit uses/defs, semantic contract, deterministic encoding, control behavior, effects, trap behavior, and optional cost metadata.

Semantic behavior and cost metadata are separate.

### 11.4 Opaque operations

An opaque target operation is permitted only when it still declares input/output types, resources, effects, memory spaces/access classes, ordering, control/trap/blocking/synchronization behavior, privilege/state requirements, alias/visibility constraints, and optimization restrictions sufficient for sound compilation.

Opacity is never permission for hidden effects.

### 11.5 Legalization, selection, scheduling, formats

Target packages supply semantics-preserving legalizations, instruction-selection constraints/rules, scheduling resources/costs, calling conventions, relocation kinds, object/executable/image formats, and accelerator execution facts.

Failure to realize a required semantic operation is an explicit unsupported-target failure, not license to weaken semantics.

## 12. ABI, foreign interoperability, platform capabilities, and standard environment

### 12.1 ABI boundary

Core XAX calls are semantic calls. Register placement, stack rules, symbol conventions, unwind tables, loader behavior, syscall numbering, TLS, startup conventions, red zones, and similar facts belong to target/ABI/platform packages.

ABI descriptions are XAX semantic objects and deterministic compile-time XAX computation.

### 12.2 ABI model

An ABI defines deterministic parameter/result classification, register/stack conventions, preserved state, aggregate and variadic rules, tail-call constraints, unwind policy, symbol conventions, data representation, and object constraints.

Foreign variadic calls use ABI-defined typed argument packs; there is no untyped core ellipsis.

### 12.3 Foreign import/export contracts

A foreign boundary MUST identify symbol/service identity, ABI, foreign-visible representation, XAX-visible type, parameter/result mapping, effects, ownership/lifetime, alias/provenance guarantees, unwind behavior, and resolution/binding mode.

A boundary MUST explicitly preserve, adapt, weaken, or mark unknown each required property. It cannot fabricate provenance, bounds, alignment, no-alias, ownership, lifetime, thread-safety, determinism, or resource-release guarantees.

Adapters may perform representation conversion, ownership transfer, bounds reconstruction, error conversion, callback bridging, unwind containment, and other explicit work, but may not allocate, copy, lock, call a syscall, initialize, or acquire resources invisibly.

### 12.4 Platform capabilities

Platform facilities are explicit semantic capabilities. Examples include filesystem, network, process, threads, clocks, entropy, display, audio, GPU, dynamic loading, virtual memory, environment data, identity/security context, IPC, and devices.

Mandatory capability requirements are resolved at compile/build validation for a statically selected environment. The toolchain MUST NOT silently add an OS, libc, allocator, scheduler, dynamic loader, emulator, or runtime probe.

Optional/dynamic capabilities require an explicit compile-time alternative or runtime acquisition/query operation with its own effects/resources.

### 12.5 Freestanding-first environment and dynamic linking

The standard environment is layered semantic packages, not one mandatory runtime. Freestanding use is first-class.

Dynamic linking is optional and requires an explicit dynamic-loader capability plus explicit program/dependency request. Foreign import does not imply dynamic linking.

Unsupported ABI/platform facts produce structured validation failures, never silent semantic weakening.

## 13. Compiler core, verifier, incrementality, and semantic database

### 13.1 Services

The compiler core includes canonical reading, content-addressed object storage, root management, structural verification, semantic verification, proof handling, dependency/invalidation tracking, bounded query service, cache management, transaction service, deterministic diagnostics, and compilation coordination.

Derived facts are separate from authoritative semantic objects and are valid only under their complete dependency/configuration/target/compiler-version closure.

### 13.2 Verification layers

Verification is layered:

1. framing/canonical decoding;
2. identity verification;
3. structural graph verification;
4. semantic verification;
5. proof-obligation discharge;
6. target/platform legality where required;
7. selected profile checks.

Deserialization is not semantic verification.

Proof obligations may be `proven`, `runtime-enforced` by explicit semantics, `waived` by a permitted explicit raw operation, or `unsatisfied`. `unsatisfied` rejects the candidate/root.

### 13.3 Dependencies and invalidation

Every reusable derived fact or artifact MUST be keyed by all meaning/output-affecting dependencies. A cached fact survives change only when the compiler proves its dependencies unchanged.

Conservative over-invalidation is permitted; unsound under-invalidation is not.

Local transactions SHOULD verify and recompile an affected dependency frontier rather than the whole repository.

### 13.4 Determinism and parallelism

Parallel compiler work is permitted only when deterministic modes preserve deterministic semantic results and required artifact bytes. Scheduling accidents, map iteration order, host pointers, wall-clock time, and similar ambient data MUST NOT become semantic inputs.

### 13.5 Trusted core

The trusted core SHOULD remain minimal: canonical semantic definitions, canonical decoding/serialization, verifier, and minimal target-independent lowering/encoding needed to establish executable output. High-risk optimizer/search transformations SHOULD be independently checked or translation-validated so they need not join the trusted core.

## 14. Optimization, lowering, code generation, and cost model

### 14.1 Pipeline

The canonical performance pipeline is:

```text
verify
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

Implementations may interleave stages but MUST preserve their semantic contracts.

### 14.2 Optimization legality

Optimizations may include constant folding, DCE, CSE/GVN, SROA, escape analysis, devirtualization, load/store forwarding, CFG and loop transforms, vectorization, interprocedural optimization, equality saturation, profile-guided profitability, and bounded superoptimization.

Legality always follows exact semantics: arithmetic/FP mode, traps, effects, provenance/aliasing, resources, atomics, target contracts, and selected real-time/profile constraints.

Profile data affects profitability, never semantic legality, and remains non-semantic.

### 14.3 Correctness mechanisms

Every transformation uses at least one explicit correctness mechanism: verifier-checked rewrite, mechanically checked proof, equivalence checking, translation validation, conservative legality with verified premises, or validated target semantic expansion.

A failed check rejects the candidate transformation.

### 14.4 Lowering and machine code

Legalization may split/widen/scalarize values, expand operations, rewrite addressing, lower atomics, or invoke explicitly available helpers. It MUST NOT create an undeclared runtime dependency.

Scheduling and register allocation obey target constraints and semantic dependencies. Spilling is a compiler machine transformation, not a language allocation; if no legal spill storage exists, compilation fails rather than assuming one.

Object/executable emission is direct from target package semantics; LLVM, an external assembler, or external linker may be transitional/interoperability tools but are not permanent architectural requirements.

### 14.5 Cost model

Target packages MAY expose objective-specific cost data/functions for latency, throughput, code size, energy, memory pressure, deterministic latency, or weighted objectives. Cost estimates are optimization evidence, not core semantic truth.

Expensive search modes are explicit build policies with visible compile-time/memory budgets.

## 15. Packages, builds, security, reproducibility, and supply chain

### 15.1 Package identity and resolution

A package is a content-addressed XAX module graph plus canonical package metadata. Exact package root is authoritative. Logical package identity and human version labels support continuity but do not establish integrity.

Dependencies are semantic requirements over exact roots or logical identities plus exact semantic constraints. Given the same root request, candidate set, trust policy, target/profile/configuration, and resolver identity, resolution MUST select the same immutable package roots or fail identically.

There is no implicit `latest` selector.

### 15.2 Snapshots

A content-addressed `Snapshot` fixes the resolved dependency closure and relevant build inputs, including target roots, profile, features, external artifact digests, trust policy, and resolver identity. It is the canonical lock mechanism.

### 15.3 Builds

Build descriptions and build-time algorithms are XAX semantic data/programs. A build request identifies package root, build entry, target, profile, features, configuration, requested artifacts, and capability policy.

Output-affecting configuration is typed semantic input and changes build identity.

### 15.4 Reproducible input closure and modes

For each artifact, the build system MUST be able to identify the complete allowed input closure. Reproducible mode rejects undeclared observable inputs.

Execution modes include:

- `hermetic-reproducible`;
- `hermetic-nondeterministic` with explicitly granted nondeterministic capabilities;
- `ambient` development/integration mode with explicit host effects and no reproducibility claim.

Hermetic mode SHOULD be the release default.

### 15.5 Capability security

Build effects such as external reads, artifact writes, network access, clocks, randomness, signing, tool invocation, or publication require explicit narrow capabilities. Dependency code does not inherit unrestricted user authority merely because it is selected.

### 15.6 Integrity, signatures, provenance, trust

Content hashes prove immutable content relative to an expected identity; they do not prove producer identity or trust. Signatures, provenance, and trust policy are separate mechanisms.

Caches and fetched content MUST be validated against expected roots/digests and active trust/provenance policy before use.

A fully resolved build can run without network access when its declared closure is locally available.

## 16. Bootstrapping, self-hosting, and repository continuity

### 16.1 Bootstrap roles

A bootstrap seed is temporary. It may use a pre-existing language or historical executable but MUST NOT define XAX semantics or remain a permanently maintained implementation dependency after closure.

An XAX-hosted compiler has authoritative implementation as XAX semantic artifacts.

Self-hosting, toolchain closure, and bootstrap independence are distinct claims.

### 16.2 Bootstrap milestones

| ID | Claim | Required evidence class |
|---|---|---|
| B0 | seed viability | seed accepts required subset and emits runnable compiler |
| B1 | first XAX compiler | authoritative compiler implementation is XAX semantic state |
| B2 | recursive compilation | XAX compiler compiles its own authoritative graph |
| B3 | semantic self-equivalence | generations agree on required accept/reject semantics under fixed policy |
| B4 | deterministic fixed point | repeated self-build reaches required binary identity or versioned canonical projection |
| B5 | toolchain closure | required assembler/linker/object/target/build/package paths are XAX-hosted |
| B6 | bootstrap independence | no maintained second implementation language is needed for ordinary evolution |

No milestone may be claimed without committed evidence naming exact roots, targets, policies, and comparison method.

### 16.5 Compiler migration steps

The bootstrap compiler moves into XAX one component at a time. Steps `S1`, `S2`, ... are tracked in the roadmap. A component counts as migrated only when all of these hold:

1. its authoritative logic is a committed canonical XAX store that regenerates byte-identically and verifies on load;
2. the production compiler path executes that logic as code lowered by an XAX backend, not by the reference executor;
3. any remaining bootstrap implementation is only a fallback and reference, and is differentially checked against the XAX component on committed vectors; and
4. its outputs on the production path are byte-identical to the bootstrap reference's.

A migration step is not a B-milestone. B1–B6 still require the whole compiler (§16.2).

### 16.3 Trust

Recursive self-compilation alone is not proof of trust. Trust-sensitive releases SHOULD support diverse double compilation or comparably strong checks using independently sourced seeds and a fixed, auditable canonical projection when byte identity is not meaningful.

### 16.4 Repository continuity

Repository collaboration is semantic and transactional. A repository root SHOULD identify specification, decisions, program, targets, packages, conformance evidence, build policy, bootstrap state, status, and handoff state.

A new AI session MUST be able to continue from canonical repository/continuation state without relying on conversation history. Multi-agent conflicts are detected at semantic entities, bindings, decisions, invariants, and proof dependencies, not source lines.

Normative semantic changes MUST update affected decision records, conformance vectors/evidence validity, status claims, and handoff state consistently.

## 17. Conformance model reference

Implementations claim one or more levels:

| Level | Capability |
|---|---|
| C0 | Canonical Store |
| C1 | Semantic Verifier |
| C2 | Semantic Executor |
| C3 | Native Compiler for named targets |
| C4 | Transactional Workspace |

C1–C4 claims include `CORE` and may additionally claim `MEMORY`, `RESOURCE`, `CONCURRENT`, `META`, `TARGET`, `PLATFORM`, and `WORKSPACE` profiles as defined in `XAX_CONFORMANCE.md`.

Conformance is established by positive and negative vectors. Silently accepting an invalid semantic artifact is non-conforming even if valid programs compile.

## 18. Benchmark and evidence reference

Performance, AI efficiency, cost-model quality, context scaling, self-hosting maturity, and similar empirical claims MUST use the definitions and fairness rules in `XAX_BENCHMARKS.md`.

The first decisive AI comparison is C-like text versus conventional SSA text versus compact graph packets versus an actual tokenizer-native XAX transaction interface when such model/tokenizer integration exists. Unavailable arms are reported as unavailable, never simulated.

## 19. Open implementation choices

Unresolved evidence-dependent choices are listed only in `XAX_OPEN_ISSUES.md`. Those choices MAY alter representation, granularity, heuristics, or performance policy, but MUST NOT weaken the normative invariants in this specification.

## 20. Versioning and change rule

A change that can alter accepted program meaning, canonical identity, verifier validity, target behavior, transaction semantics, ABI behavior, or build reproducibility requires a versioned specification/schema/contract change and corresponding conformance updates.

No implementation behavior, benchmark result, common practice, or human-facing syntax silently changes XAX semantics.

## 21. Universal replacement

### 21.1 Definition

XAX is a candidate replacement for authoring software otherwise written in C, C++, Rust, assembly, Java, Kotlin, C#, Swift, Objective-C, JavaScript, TypeScript, Python, Go, PHP, Ruby, Dart, Solidity, Fortran, COBOL, CUDA-style languages, shell languages, and comparable languages. Replacement means sufficiency for the **software those languages build**, not reproduction of their features.

A platform/workload class is **replacement-capable** when an AI can perform

```text
intent -> construct XAX semantics -> verify -> optimize -> build -> deployable artifact
```

without any human-authored program in another programming language.

| ID | Requirement |
|---|---|
| UR-001 | Compiler-generated adapters (DEX entry shims, host bindings, loader stubs, import tables) are permitted only when deterministically generated from XAX semantic/platform contracts and recorded in build provenance. They are never authored source. |
| UR-002 | A platform-required runtime (ART, a WebAssembly engine, CLR, JVM, a GPU driver) is permitted only when the selected platform itself requires it and its observable behavior is represented by explicit platform/ABI contracts. XAX MUST NOT add a runtime of its own. |
| UR-003 | Replacement claims are scoped to `(platform package, workload class, R-level)` and MUST be backed by the evidence in §21.3. Architecture goals are not implementation facts. |
| UR-004 | A program pays only for semantics it requests. No domain (managed, web, GPU, real-time, scripting-style) may impose runtime, code, data, or verification cost on programs that do not use it. |

### 21.2 Replacement conformance levels

Levels are cumulative; a level is held only when every lower level is held.

| Level | Name | Required evidence |
|---|---|---|
| R0 | Semantic expressibility | The workload is represented exactly in verified XAX (STRUCTURAL or stronger). |
| R1 | Executable lowering | XAX directly produces a valid executable representation that EXECUTED on the target (a harness, emulator, or device must be named). Emulated execution counts for correctness only, never as performance evidence; an emulator-only row lists "not hardware" as a blocker (ADR-114, OI-44). |
| R2 | Platform interoperability | Required ABI, system APIs, libraries, callbacks, dynamic loading, resources, and platform lifecycle EXECUTED. |
| R3 | Practical application | A nontrivial real application/workload EXECUTED successfully. |
| R4 | Performance competitiveness | Runtime, memory, and binary size MEASURED against the platform's established toolchains under `XAX_BENCHMARKS.md`. |
| R5 | AI efficiency | Total tokens per successful change and repair rate MEASURED against textual-source workflows on real model trials. |
| R6 | Autonomous maintenance | Query, modify, verify, benchmark, rebuild, and commit of the application EXECUTED through semantic transactions without whole-source regeneration. |

A negative R4/R5 measurement is valid evidence and MUST be reported; the level is held only when the measured result is competitive.

### 21.3 Evidence labels

Every implemented claim in state, matrix, handoff, or benchmark documents carries exactly one label:

| Label | Meaning |
|---|---|
| PROVEN | machine-checked proof or exhaustive verification of the stated property |
| EXECUTED | the artifact ran and produced the checked result; host/harness/device named |
| MEASURED | quantitative result recorded under benchmark rules, with raw data |
| STRUCTURAL | verified or inspected artifact structure; not executed |
| PROTOTYPE | bounded implementation exists; scope is narrower than the claim's name suggests |
| UNIMPLEMENTED | absent |

A stronger label requires stronger evidence. Host-unavailable executions remain unavailable, never passed.

### 21.4 Universal Replacement Matrix

`XAX_REPLACEMENT_MATRIX.json` is the machine-maintained per-platform evidence record. Its levels are derived from cited evidence by `compiler/src/xax_replacement.py` and checked by `compiler/tests/test_replacement_matrix.py`; a claimed level above the derived level, an uncited label, or a missing evidence path is rejected. Because a MEASURED label only says that a comparison exists, R4 additionally requires the row's `competitive` verdict `[true, evidence...]`; a row with `[false, ...]` or no verdict derives at most R3 (ADR-126). An emulator-only row cannot cite performance evidence (§21.2). The matrix records evidence; it never defines requirements.

### 21.5 Kernel admission rule

Universal replacement is achieved by layering, not by kernel growth:

```text
tiny XAX kernel -> compile-time construction -> zero-cost semantic libraries
-> platform packages -> ABI packages -> target packages -> artifact
```

The kernel remains approximately: values, exact arithmetic, aggregates, control, calls, memory, resources, effects, atomics, target operations, and compile-time/meta operations. A kernel addition MUST be recorded as an ADR demonstrating that the semantics cannot be expressed exactly, with equal-or-better generated cost, verification precision, and AI tokens per change, using existing primitives plus libraries/packages. Language-specific concepts (class, object, trait, interface, async, future, string, dictionary, exception, GC object) are not kernel concepts unless that demonstration exists.

### 21.6 Lowering of conventional programming models

These are library or compile-time patterns over existing semantics. None is mandatory, and none adds cost to programs that do not use it.

| Model | XAX realization |
|---|---|
| closures | function + explicit environment aggregate (+ explicit storage when escaping) |
| objects | storage + functions; layout is explicit |
| interfaces/traits | compile-time specialization; dynamic dispatch = explicit table + `call_indirect` under a referenced CallContract |
| generics | compile-time specialization (§8.3) |
| async/coroutines | explicit state machine; scheduler/event loop only as an explicitly linked capability |
| exceptions | sums + explicit control; foreign unwinding only through an explicit ABI adapter (§6.3) |
| GC | optional collector package with explicit roots, barriers, and allocation effects |
| reference counting | explicit library operations on linear resources |
| reflection | compile-time introspection; runtime metadata only when explicitly retained |
| dynamic typing | tagged sums/boxed representations supplied by libraries |
| strings, collections | explicit representations + semantic libraries |
| actors/tasks | libraries over atomics, resources, and platform thread capabilities |
| GPU kernels | target/platform packages over `target_op`, memory spaces, and scopes |

### 21.7 Platform classes

Without changing kernel semantics, the target/platform/ABI package architecture MUST be able to describe: CPU ISAs (x86-64, AArch64, RISC-V, future ISAs) including registers, calling conventions, relocations, object/executable formats, TLS, atomics, vectors, unwind data, and static/dynamic linking; operating systems (Linux, Windows, macOS, BSD/Unix, Android, Apple mobile OSes, RTOS, bare metal); the web (WebAssembly, WASI, browser host APIs/DOM/WebGPU through compiler-generated bindings, never handwritten JavaScript); managed runtimes (JVM, DEX/ART, CLI/CLR) as targets, never as kernel semantics; accelerators (SIMT/SIMD, memory spaces, synchronization scopes, barriers, launches, host/device ownership); embedded systems (no runtime, deterministic startup, exact sections, interrupts, MMIO, DMA, volatile access, fixed budgets, optional bounded-stack analysis); and legacy/specialized targets (mainframes, DSPs, consoles, custom accelerators) whenever target/ABI information is available. Target packages MUST be able to express irregular registers, predication, vector-length-dependent execution, SIMT, capabilities, tagged memory, multiple memory spaces, non-coherent memory, asynchronous devices, special calling conventions, target atomics, unusual traps, and security features without an imaginary universal CPU.

### 21.8 Executable and object formats

Executable/object containers (raw images, ELF, PE/COFF, Mach-O, WebAssembly, DEX/APK, classfile/JAR, CLI assemblies, GPU binaries) are target/platform package responsibilities. A container MUST add no code beyond what explicit platform contracts require; container metadata (import tables, relocations, headers) is derived deterministically from semantic identity. Process start/exit, loader behavior, and platform lifecycle are explicit platform contracts: when a platform does not end a process on entry return, the program performs the explicit exit operation; the container supplies no hidden exit path.

### 21.9 Foreign ecosystem import

Interoperability is mandatory. Deterministic importers SHOULD convert external metadata (C headers/API descriptions, POSIX, Win32, Objective-C runtime metadata, JVM/DEX metadata, .NET metadata, Web IDL, syscall tables, GPU API descriptions, shared/static library symbol tables) into XAX platform/ABI packages of typed foreign declarations. Importers are build-time XAX or bootstrap tooling; their output is canonical semantic state, never wrapper source. No universal ABI is assumed; C++ and similar ABIs require explicit ABI packages. Foreign exceptions, ownership, aliasing, lifetime, callbacks, thread requirements, dynamic loading, and calling conventions remain verifier-visible (§12). Each foreign ABI is owned by exactly one backend, which rejects declarations of any other ABI. The C header importer (ADR-127) MUST be deterministic over its declared inputs (header digests, clang version, names, soname, ABI, overrides), MUST refuse rather than approximate any type outside its LP64 subset (by-value aggregates, arrays, `long double`, variadics), MUST give every import a memory frontier unless an explicit override states `pure`, and MUST map pointers to non-scalar C types to opaque identity handles.

### 21.9a Linux x86-64 hosted profiles

`linux-x86_64-syscall-v1` declarations encode the syscall number and an explicit register template (`nr` or `nr:arg,...`, with `$k` machine-operand references each used exactly once and unsigned 64-bit literals). Arguments use `rdi, rsi, rdx, r10, r8, r9`, the result is the exact 64-bit `rax`, and allocator-contract failures `-4095..-1` project to null (ADR-085). `sysv-x86_64-c` declarations import a C symbol from a shared library named by soname. They lower only on `x86_64-linux-elf-dynexec-v1`, which explicitly requests `/lib64/ld-linux-x86-64.so.2`, derives `DT_NEEDED` only from declared sonames, and is bounded to register-passed psABI scalars: at most six INTEGER-class and eight SSE-class (f32/f64) arguments and one scalar result (ADR-087, ADR-102). A code address that foreign code may call has type `ptr<opaque_identity<"code-entry:" + abi>>` for an `abi` in `FOREIGN_ENTRY_ABIS` (currently `sysv-x86_64-c`); `FUNCTION_ADDRESS` with that result type MUST name a function with no proof parameters or results, and the backend MUST lower it to a compiler-generated adapter rather than the internal entry (ADR-102). Such an address is not a `ptr<opaque<function>>`, so it cannot be called with `CALL_INDIRECT`. A lend entry (`sysv-x86_64-c-lend`, ADR-115) is the one exception to purity. Its type names one view's pointer and token types. The callee MUST take scalars followed by exactly that read-only, initialized view triple, and MUST return one integer followed by the same triple. An operand of that type MUST only be passed to a `sysv-x86_64-c` call that lends a whole, live, initialized view of that extent, passes its memory effect, and returns a memory effect (`LEND-ENTRY-VIEW-LENT`). `android-aapcs64-c` entries follow the same purity rule. On AArch64 they are the function's own address, and their parameters MUST be 64-bit integers or pointers (ADR-107). On both Linux profiles `e_entry` is the XAX entry function; the program exits explicitly with `exit_group`, the entry is lowered for Linux's aligned no-return-address entry, and returning traps (ADR-086, §21.8).

`linux-x86_64-startup-v1` (ADR-094) reads the initial process stack inline, with no code before the entry function. It is owned by the Linux profiles and allowed only in the process entry function (`LINUX-STARTUP-PROCESS-ENTRY`). The declarations have library `linux` and these names: `argc() -> bits<64>`, `arg_length(i)`, `arg_copy(i, ptr<bytes,rw>, memory) -> (bits<64>, memory)`, `envc`, `env_length`, `env_copy`, and `auxv_value(type) -> bits<64>`. An index at or past `argc`/`envc` traps. `*_length` excludes the terminating NUL. `*_copy` copies at most the destination view's static extent and returns the bytes copied, so a result below `*_length` reports truncation. `auxv_value` returns 0 when the type is absent.

### 21.9b Browser pages

`wasm32-browser-v1` (ADR-103) uses the WASI command container (`_start` and `memory` exports; proof-only entry). Browser APIs are `wasm32-import` declarations of a platform package. Each has exactly one fixed host meaning, and host state is ordered by an `effect<io>` token supplied to `_start`. The host page MUST be generated from the imported declarations alone: an import outside the package rejects, and unused bindings emit nothing. Event handlers are foreign entries of ABI `wasm32-browser-event` (ADR-104): their parameters MUST be non-memory effects returned unchanged, with no machine values, and the host supplies that authority on each call. On wasm32 the address is the export number of `entry_<k>`.

### 21.9c JVM class files

`jvm-classfile-v1` (ADR-112) is target architecture 5 with the exact machine tuple (profile 1, ABI 6, format 1, 64, 64). It emits one class file of major version ≥ 61 (strict IEEE 754) in a byte-deterministic JAR. Its operation set is the scalar general subset: integer arithmetic and completion operations, compares, rotates, float arithmetic, compares and conversions, direct and foreign calls, and the erased resource/effect operations. Any other operation MUST reject (`JVM-OP-TARGET-SUPPORTED`).

Bits up to 32 lower to `int` and up to 64 to `long`, kept zero-extended. Every observable result MUST equal the reference executor's, including traps. A trap MUST terminate the program abruptly and MUST NOT be catchable by XAX code.

Foreign members use the ABIs `jvm-invokestatic`, `jvm-invokevirtual`, and `jvm-getstatic`. The declaration's library is the class's internal name and its name is `member(descriptor)` or `field:descriptor`. Each descriptor component MUST match the declared machine type: Z/B/C/S/I/J ↔ `bits` 1/8/16/16/32/64, F/D ↔ f32/f64, and an object or array descriptor ↔ `ptr<opaque-identity "jvm-ref:" + descriptor>`. For `jvm-invokevirtual` the receiver comes first. A Java exception escaping a foreign member terminates the program like a trap.

`JVM_EXECUTABLE_JAR` requires a proof-only entry. Its `Main-Class` is the generated `main(String[])` that calls the entry and returns (JVM exit status 0); any other status MUST be an explicit `java/lang/System.exit` call.

### 21.9d RISC-V RV64 raw images

`riscv64-baremetal-raw-v1` (ADR-113) is target architecture 6 with the exact machine tuple (profile 1, ABI 7 LP64, format 1 raw, 64, 64). It needs only RV64I plus M. Functions follow the LP64 integer calling convention (a0–a7, a0, ra; s0–s11 preserved). A zero divisor MUST trap even though `divu`/`remu` do not. The image MUST be position-independent, with the entry at offset 0, and contain no loader, relocation, data section, or runtime.

### 21.9e Linux AArch64 hosted profiles

`aarch64-linux-elf-exec-v1` and `aarch64-linux-elf-dynexec-v1` (ADR-123) are architecture 3 with ABI 5 and formats 6 (static) and 7 (explicit loader), profile 1. `linux-aarch64-syscall-v1` declarations use the §21.9a template identity with asm-generic syscall numbers; arguments go in `x0..x5` and the number in `x8`, and allocator-contract failures project to null. `aapcs64-linux-c` declarations import a C symbol by soname and MUST reject on format 6. Format 7 MUST request exactly `/lib/ld-linux-aarch64.so.1` with `DT_NEEDED` derived only from declared sonames and bind-now `R_AARCH64_GLOB_DAT` slots. The only container code is the compiler-generated `e_entry` stub (`bl entry; brk`, so returning traps), one thunk per referenced syscall declaration, and one `adrp`/`ldr`/`br` thunk per C import. The AArch64 backend MUST reject a foreign ABI owned by another AArch64 platform (`AARCH64-FOREIGN-ABI`).

### 21.9f SPIR-V compute for Vulkan

`spirv-vulkan-compute-v1` (ADR-124) is target architecture 7 with the exact machine tuple (profile 1, ABI 8, format 1, 32, 32); the artifact is a SPIR-V 1.3 module with one `GLCompute` entry `main` and a fixed workgroup of 64. A kernel is an ordinary function under the `spirv-compute-v1` entry contract: parameters `(bits<32> invocation, (ptr<bits<32>>, heap_view<E>, memory)...)` and results equal to the view triples, in order. Triple *i* is storage-buffer binding *i* of descriptor set 0 (read-only pointers are `NonWritable`); binding *k* (one past the last triple) is the status word; push constant 0 is the launch count. Invocations whose `GlobalInvocationId.x` is at or past the launch count MUST have no effect. A trap MUST end its invocation before the trapping access and raise the status word with `atomicMax` to `0x10000 | portable reason` (explicit traps and zero divisors) or `0x20000` (a failed checked access). Pointers MUST resolve to one static binding and 4-aligned byte offset. Every store, and every load from a binding the kernel stores to, MUST address exactly `invocation * 4` (`SPIRV-KERNEL-OWN-ELEMENT`); this is the profile's data-race rule, so no unchecked concurrency assumption exists. A launch MUST supply buffers of exactly each view's extent and a count below 2^30.

### 21.9g Board packages

A board package (ADR-128) is target profile 5: the profile-2 concurrency section followed by profile-4 target-operation contracts. Device registers, system registers, and board instructions are `target` operations of the package, each consuming and returning the board's device effect; a backend MUST reject a board operation when compiling for any other target. An image names a reset entry and one handler per declared event. Both MUST have proof-only interfaces, and each handler MUST satisfy its event's contract (effect domains, stack bound). The generated startup MUST only set the declared stack, install the vector table, and call the reset entry. Every exception without a handler, every trap, and a returning reset entry MUST end in the board's declared fault path (for `aarch64-qemu-virt-v1`: `!` on the UART, then PSCI `SYSTEM_OFF`).

### 21.10 Standard semantic libraries

The standard ecosystem is a set of independently linked semantic packages (allocators, arenas, text, slices, arrays, maps, sets, numerics, big integers, filesystem, sockets, HTTP, TLS integration, threads, synchronization, event loops, serialization, compression, cryptography interfaces, graphics, audio, database interfaces, SIMD, tensors, GPU compute). There is no mandatory runtime: unused packages contribute zero code and data, and every package's runtime semantics are explicit effects, resources, and capabilities.

### 21.11 Observability

Semantic-to-machine maps, crash/stack mapping where platforms permit, disassembly maps, profiling, debugger integration, coverage, and instrumentation/sanitizer builds are derived, non-authoritative views (§9.8, ADR-030). Instrumented builds are distinct build policies; their artifacts never become source and never alter release semantics.

---

# Android arm64-v8a hosted target note (2026-10-01)

The prototype includes `android-arm64-v8a-shared-v3` as an ordinary target/ABI
package. This does not add Android, JNI, libxposed, or ELF operations to the XAX
semantic kernel. Generic function-address, bounded indirect-call, and explicit
foreign-call operations are used with target/package contracts.

Android C-ABI exports and foreign imports are content-addressed target/build
carriers with exact names, ABI identities, function/type identities, and (for
imports) exact library identity. Exported symbols are explicit; no XAX function
is exported merely because it exists.

Opaque borrowed pointers are valid ABI carriers but do not fabricate
provenance. Local stack provenance exists only for verified local storage and
must continue through any opaque/indirect call using explicit owner/effect
facts. There is no unknown-effects foreign-call mode.

The Android emitter is a bounded direct ELF64 ET_DYN emitter. It preserves the
existing register-resident AArch64 lowering and introduces no XAX runtime,
startup runtime, implicit allocation, cleanup, exception, TLS, or scheduler
semantics.


The v3 Android package exposes the Android public JNI 1.6 invocation and native
function tables only through ordinary fixed-offset `target-op` contracts.
`JNIEnv*`, `JavaVM*`, method/field IDs, and JNI reference classes use
identity-qualified opaque ABI carrier types; they do not add Java/JNI concepts
to the core type vocabulary. JNI call signatures remain bounded `CallContract`
objects. Acquired local/global/weak-global JNI references additionally carry an
explicit linear ownership proof value; release calls consume that proof. A
borrowed JNI reference has no release proof and therefore cannot be silently
treated as owned. A JNI reference, class handle, method ID, or field ID MAY carry
an explicit class-loader domain in its semantic identity. When such a domain is
known, local/global/weak reference lifetime transitions MUST preserve it, and a
call/member contract requiring a different loader domain MUST reject rather than
coerce identities. Loader identity is proof state and does not by itself imply a
runtime class lookup or cache.

A JNI call whose contract may establish a Java exception MUST make that fact
verifier-visible. In the current bounded profile, an explicit linear exception
state has at least `clean` and `maybe-pending` states. Ordinary JNI operations
whose safe precondition is `clean` MUST NOT consume `maybe-pending`; an explicitly
selected exception-policy operation MAY restore `clean` when its JNI semantics
justify that transition. The current profile supports explicit `ExceptionClear`
as that recovery operation. This does not establish conditional refinement to a
definite pending/clean branch or successful thread-attachment state; those
require separate explicit semantics before they may be claimed. The bounded
mixed-argument path MAY distinguish nullable from proven-non-null JNI reference
carrier identity, but this identity alone MUST NOT be described as a runtime null
check or branch refinement.

## Android direct artifact and SDK-package note (2026-10-01)

Android managed/platform support remains ordinary platform/package semantics rather
than additions to the fundamental XAX kernel.  For the current bounded Android
profile, the compiler MAY directly emit DEX, binary Android XML, ZIP/APK layout,
and APK Signature Scheme v2 bytes from verified semantic build data.  These are
target/build representations and MUST NOT become authoritative program source.

The current Activity bridge profile synthesizes a managed override only when the
Android lifecycle contract requires it. `Activity.onCreate(Bundle)` first invokes
the superclass implementation, then performs exactly one direct call to a private
native XAX callback, then returns. The generated class performs one static
`System.loadLibrary` call for the selected native library.

For an interface callback whose platform contract does not require a superclass
implementation, the same DEX bridge machinery MAY emit a public interface method
that performs exactly one direct invocation of a private native XAX callback and
returns. The class MUST encode its implemented interface(s) in the DEX interface
type list. Such a bridge MUST NOT synthesize a superclass callback, reflection,
dynamic member lookup, per-callback object/array allocation, Java/Kotlin source,
D8/R8, or a generic runtime. Adapter object construction and registration remain
explicit platform behavior and are not implied by bridge emission.

Android resource and component declarations in the current bounded profile are
also ordinary content-addressed platform/build carriers. A resource carrier MAY
describe a canonical application string table whose deterministic IDs are resolved
into generated DEX before publication; applications with no semantic resources MUST
NOT gain a resource table or runtime resource parser. A manifest-declared broadcast
receiver MAY be derived from a semantic component carrier. Its generated DEX class
subclasses `android.content.BroadcastReceiver` and its `onReceive(Context,Intent)`
method MAY forward directly to one private native XAX callback without a superclass
call. The matching JNI export and manifest component declaration MUST both exist
before the APK is published. Component delivery and resource loading remain runtime
claims and MUST NOT be inferred from structural artifact validation alone.

The bounded component profile MAY also synthesize an optional `Application` whose
`onCreate()` invokes the superclass implementation before one private native XAX
callback, and an optional concrete unbound `Service` whose `onCreate()` and
`onDestroy()` preserve superclass behavior before one native callback each while
`onBind(Intent)` returns null entirely in managed DEX.  These components MUST be
absent when no corresponding semantic carrier is reachable.  This service profile
does not imply Binder-object result support.

Modern libxposed support is likewise an ordinary Android platform package.  The
bounded API-102 managed profile uses a content-addressed module-entry carrier, hook
adapter carrier, and hook-installation carrier plus current `META-INF/xposed/*`
metadata.  The generated Java entry subclasses `io.github.libxposed.api.XposedModule`;
framework attachment is external platform behavior.  A hook installation MUST name
its target class/method, generated Hooker class, parameter types, exception policy,
failure policy, and lifetime policy explicitly.  The current bounded profiles accept
either a zero-argument method or exactly one `java.lang.String` parameter,
`PROTECTIVE` exception mode, `propagate` installation failure, and either `process`
or `retained-manual-unhook` lifetime.  `onPackageReady` resolves the target through
the supplied package ClassLoader, obtains the exact `Executable`, invokes `hook`,
selects the exception mode, creates exactly one Hooker object, and installs it.
Resolving the one-String profile MAY allocate one `Class[1]` during installation;
this allocation MUST remain visible in generated-code evidence.  The `process`
profile MUST discard the returned HookHandle and remain field-free.  The
`retained-manual-unhook` profile MUST store exactly one HookHandle in the generated
module and MUST expose an idempotent `xaxUnhook()` operation that returns immediately
when no handle is retained, otherwise invokes `HookHandle.unhook()`, clears the
stored field, and returns.  Retained-handle support MUST NOT change the generated
Hooker/interceptor bytes.

Deoptimization is a separate content-addressed libxposed policy and MUST NOT be
inferred merely because a hook exists.  The current bounded profile accepts one
explicit `best-effort` deoptimization request for the exact executable already
resolved by the companion hook installation.  Lowering MUST reuse that resolved
`Method`, invoke API-102 `deoptimize(Executable)` exactly once before `hook`, and
MUST NOT add allocation or deoptimization work to the Hooker hot path.  Because
the current policy explicitly ignores libxposed's boolean success result, that
choice is semantic data rather than an implicit compiler fallback.  Other result
policies and caller-deoptimization sets are outside this bounded profile.

Framework/module services are likewise opt-in semantic platform data.  The
bounded direct module-service carrier MAY request `getFrameworkName`,
`getFrameworkVersion`, `getRemotePreferences(String)`, `listRemoteFiles`, and
`openRemoteFile(String)`.  Each selected direct service lowers to one generated
module method containing exactly one direct `invoke-virtual` of the API-102
wrapper followed by object-result forwarding.  No cache, reflection layer,
hidden retry, or exception translation is permitted.  Unselected services MUST
add no DEX methods or runtime machinery.

Remote-resource use is a separate canonical policy rather than an implicit
property of those direct wrappers.  The current bounded remote-preferences and
remote-files carriers MUST test
`(getFrameworkProperties() & PROP_CAP_REMOTE) != 0` before acquisition.  Under
the explicit `nullable-on-unsupported` policy, an absent capability MUST return
null without invoking the remote operation; once the capability is present,
framework failure MUST propagate and MUST NOT be translated into null, retried,
or silently cached.  The bounded remote-preferences profile MAY expose only
`SharedPreferences` reads for boolean, int, long, float, String, and `contains`;
each selected typed read lowers directly to the corresponding interface method.
No `Editor`, write, apply, or commit path is part of this profile.  The bounded
remote-files profile MAY expose only remote listing and remote-file open.  Both
acquisition profiles and all typed read helpers MUST remain allocation-free in
emitted DEX unless a later explicit semantic carrier requests an allocation.

Hot reload is also a separate canonical libxposed policy.  The current bounded
profile is `single-retained-hook-id-guarded-atomic-replace` with `propagate`
framework-failure policy, stable hook ID `xax.primary` by default, explicit
`skip-replacement` old-handle mismatch policy, `package-ready-class-loader`
saved-state policy, and `reject-reload` policy when package-ready state was never
captured.  It is legal only for an API-102 module with exactly one generated Java
entry and exactly one generated hook whose lifetime is `retained-manual-unhook`.
Selecting the policy MUST emit `autoHotReload=true` in module metadata, MUST
configure the initial HookBuilder with `setId(<stable-id>)` before interception,
and MUST retain the target/app `ClassLoader` obtained from `PackageReadyParam` in
a generated field.  The generated `onHotReloading(HotReloadingParam)` MUST reject
the reload if that field is null; otherwise it MUST pass only that host-owned
`ClassLoader` through `setSavedInstanceState(...)` and accept the transition.  It
MUST NOT serialize a module-defined object, module lambda, HookHandle, or hidden
resource container.  The generated `onHotReloaded(HotReloadedParam)` MUST restore
that saved target `ClassLoader`, obtain the old hook-handle list, return without
replacement if saved state or the list is absent, fetch the sole old handle,
compare `HookHandle.getId()` with the declared stable ID, return without
replacement on mismatch, and only then allocate one replacement Hooker and invoke
`HookHandle.replaceHook(...)` exactly once.  The returned handle MUST replace the
existing retained-handle field.  It MUST NOT implement replacement as `unhook`
followed by a new installation, because that would create an observable unhooked
interval.  Framework/API exceptions still propagate.  Multi-hook matching,
lifecycle replay, listener/thread cleanup, and arbitrary external-resource
migration remain outside this bounded profile.

The corresponding bounded Hooker hot path MAY be a pure pass-through interceptor:
exactly one `Chain.proceed()` followed by returning its result.  Such a hot path MUST
contain no target lookup, reflection, Hooker allocation, Java/Kotlin source, or
generic runtime.  Installation-time reflection and allocation MUST remain visible in
the generated artifact/evidence and MUST NOT be described as hot-path work.  Managed
hook installation/interception is a runtime claim and requires execution under a
compatible current libxposed implementation; structural DEX/APK evidence alone does
not establish that claim.

Hook mutation policy is a separate content-addressed semantic carrier and MUST NOT
silently change Hooker identity.  The bounded result policy currently accepts only a
zero-argument target returning `java.lang.String`; it calls `Chain.proceed()` exactly
once, captures the original result, and returns one declared constant replacement
String without emitted hot-path allocation.  The bounded argument policy currently
accepts only argument index 0 of an exact `(java.lang.String) -> java.lang.String`
target.  Because current API 102 exposes replacement through
`Chain.proceed(Object[])` rather than an in-place argument setter, generated DEX MUST
make the required one-element `Object[]` allocation and replacement store explicit.
This profile therefore MUST NOT be described as zero-allocation.  Reusable/shared
argument arrays MUST NOT be introduced without a separate concurrency/lifetime proof.
A separate bounded combined mutation policy MAY compose these two effects only for the
exact `(java.lang.String) -> java.lang.String` profile: replace argument 0, invoke
`Chain.proceed(Object[])` exactly once, capture its original result, then return one
declared constant replacement String.  The combined policy MUST preserve the same
explicit one-element `Object[]` allocation; result replacement MUST NOT introduce an
additional emitted hot-path allocation.  Separate result-only and argument-only carrier
identities MUST retain their existing meaning and byte shape.

APK signing authority is an explicit external build capability.  Private key
material MUST NOT be encoded into program semantics, content-addressed public
objects, diagnostics, or evidence.  The current direct v2 profile uses a
certificate-bound RSA key capability and deterministic RSA PKCS#1 v1.5 with
SHA-256; changing signature algorithm/profile is build policy, not program
meaning.  Packaging/alignment MUST complete before v2 signing because subsequent
APK-byte modification invalidates the v2 content digest.

Android SDK metadata import is likewise a platform-library operation.  A direct
class/JAR importer produces canonical content-addressed target carriers for class
and member identity, exact JVM descriptors, access flags, selected annotations,
and Android API availability metadata.  JAR entry order MUST NOT affect the
result.  Multi-release JARs MUST reject unless an explicit version-selection
policy is supplied.  Imported `since`/removal metadata MUST be checked against
the compile SDK and the exact reachable runtime API interval.  A runtime API
branch may narrow that interval explicitly; no silent availability fallback is
permitted.

Typed JNI member IDs bind owner, name, descriptor, and staticness.  Descriptor-
driven method invocation selects an exact `Call*MethodA` JNI entry and an explicit
fixed-size `jvalue[]` argument pack rather than a C varargs path.
Descriptor-driven field access selects the exact get/set entry. Object-returning
calls produce owned local-reference semantics. The bounded AArch64 stack-pack
profile supports homogeneous integer JNI parameters `Z/B/C/S/I/J`; each 8-byte
`jvalue` union slot MUST be fully initialized, and subword values MUST use exact
byte/halfword stores rather than wider over-stores. The bounded mixed profile MAY
combine `jlong` with strong JNI references only when each reference has an exact
semantic descriptor, optional imported superclass/interface proof for subtyping,
and any required defining-loader identity. Converting such a reference to the
`jvalue.l` machine word MUST be an explicit target ABI operation, not an unchecked
core pointer cast. Owned local/global references MUST thread their linear owner
proof through that projection and through the JNI call. Weak-global references,
mixed narrow integers, or unproved subtype/loader combinations MUST reject.
Until exact float carriers and AAPCS64 floating-point lowering exist,
`float`/`double` JNI member paths MUST reject rather
than be approximated. Pending-exception state is verifier-visible in the bounded
profile above, but the implementation MUST NOT describe that as complete Java
exception handling until conditional `ExceptionCheck`/`ExceptionOccurred` control
refinement and corresponding runtime evidence exist.
