# XAX Stage 04 — Memory, Pointer, Ownership, and Resource Semantics

## 1. Purpose and scope

This document defines the canonical XAX memory and resource model. It specifies storage objects, pointer semantics, lifetime and ownership representation, aliasing, ordinary and device memory operations, raw access, and linear or affine resources.

Memory behavior is represented directly in the semantic graph. Storage creation, ownership transfer, release, device access, and waived safety obligations are explicit semantic facts.

This stage defines memory/resource correctness, not concurrent ordering. Atomics, fences, inter-thread ordering, interrupts, and real-time constraints belong to the concurrency stage. Target packages define platform address spaces, device constraints, placement, DMA facilities, and lowering details.

Normative goals are:

- no mandatory heap, garbage collector, reference counting, allocator, runtime, or operating system;
- no hidden allocation, ownership transfer, release, destructor, synchronization, or device access;
- precise proof obligations for ordinary memory operations;
- enough provenance, bounds, alignment, permission, and alias information for aggressive optimization;
- machine-visible raw operations when obligations are intentionally waived;
- deterministic resource lifetime through explicit state transitions;
- zero runtime cost for metadata and checks that the verifier/compiler proves statically.

## 2. Normative definitions

| Term | Normative meaning |
|---|---|
| **storage object** | A semantically identified region of storage with a class, size/extent, alignment, address space, lifetime, and placement contract. |
| **storage class** | The mechanism and lifetime discipline by which a storage object exists: `static`, `stack`, `region`, `arena`, `allocator<K>`, `target-memory<K>`, or `raw`. |
| **object identity** | The provenance identity that distinguishes one live storage object from another even if their numeric addresses are equal at different times. |
| **provenance** | Evidence that a pointer designates storage derived from a particular object or explicitly declared raw/target mapping. |
| **extent** | The byte or element range of an object or pointer view that may be addressed under its current proof state. |
| **pointer** | A typed semantic address capability containing an address space plus statically known or runtime-represented provenance, extent, alignment, permission, and alias information. |
| **permission** | The operations permitted through a pointer, such as read, write, or read-write. Permission is semantic authority, not merely an optimizer hint. |
| **alias class** | A verified relation describing which live pointer views may designate overlapping storage. It is not inferred from source-level type names. |
| **lifetime** | The interval in the semantic graph during which a storage object or resource state is valid. |
| **owner capability** | A linear resource value whose possession authorizes lifetime-ending or state-changing operations on a storage object or resource. |
| **linear resource** | A `resource<K,state>` value that must have exactly one valid continuation at every transfer and must terminate through an allowed final transition. |
| **affine resource** | A resource that may be explicitly discarded when its kind permits it, but may not be duplicated. Discard is still an explicit semantic operation. |
| **raw operation** | An operation that explicitly waives one or more normal proof obligations and therefore carries the waiver and resulting target/runtime behavior in the graph. |
| **device access** | A memory-like operation whose observable semantics are defined partly by a target/platform device contract and therefore cannot be treated as an ordinary load or store. |
| **release** | An explicit terminal or state-changing operation that consumes an owner/resource value. No destructor is implied by scope exit. |

A numeric address alone is not a complete XAX pointer. Equal machine addresses can have different provenance, permissions, bounds, or lifetime validity. Statically known pointer metadata need not occupy runtime storage.

## 3. Canonical memory model

### 3.1 Storage object schema

Conceptually, each storage object has the following semantic record:

```text
StorageObject {
    identity
    class
    address_space
    extent
    alignment
    placement
    lifetime
    access_semantics
}
```

`identity` is semantic provenance, not a required runtime field. `extent` may be static or represented by a value/proof relation. `placement` is explicit only when constrained.

`access_semantics` is one of:

```text
ordinary
volatile
device<K>
raw
```

`volatile` and `device<K>` affect observability of accesses. They do not imply atomicity or inter-thread synchronization.

### 3.2 Storage classes

| Class | Required semantics |
|---|---|
| `static` | Exists for the program or target-defined image lifetime. Creation and placement are present in module semantics. No dynamic allocator is required. |
| `stack` | Storage belongs to an explicit frame/lifetime region. Creation is visible. Lifetime end is represented semantically and may lower to no instruction. |
| `region` | Allocations are subordinate to a region owner capability. Ending the region invalidates all subordinate pointers at once. |
| `arena` | Like a region but permits an implementation-defined allocation policy within a bounded or extensible arena resource. Individual members need not be individually releasable. |
| `allocator<K>` | Storage is obtained from an explicit allocator resource or capability of kind `K`. There is no universal XAX heap. Allocation and release contracts belong to that allocator. |
| `target-memory<K>` | Storage belongs to a target-defined memory space such as device-local, scratchpad, shared GPU, persistent, or other platform memory. |
| `raw` | Storage existence or mapping is asserted through an explicit raw contract rather than proved through ordinary object creation. Required waivers are carried by the creating/mapping operation. |

A program using no `allocator<K>` storage requires no allocator code.

### 3.3 Storage creation and end-of-life

Dynamic-lifetime storage creation produces at least:

```text
(pointer-view, owner-capability)
```

The pointer view grants access according to its pointer contract. The owner capability controls lifetime-ending operations. The owner capability is normally linear.

Static storage needs no runtime owner. Region/arena members may inherit lifetime from the parent owner rather than producing individual release owners.

End-of-life is explicit:

```text
storage.end(owner)
allocator.release(owner, allocator)
region.end(region_owner)
arena.end(arena_owner)
```

These operations may lower to zero instructions when they only change compiler knowledge. Scope exit and function return do not release resources implicitly; each live linear resource must be transferred, released, or enter another allowed terminal transition.

## 4. Pointer semantics

The canonical pointer type remains:

```text
ptr<space, T, permission, alignment>
```

The semantic value associated with a pointer additionally carries or proves:

```text
provenance/object identity
current offset or addressed subobject
remaining extent/bounds
alignment evidence
permission evidence
alias class
lifetime validity
```

Encoding may use type parameters, metadata, proof edges, or canonical attributes; the semantic meaning is fixed here.

### 4.1 Address calculation

Ordinary address calculation preserves provenance while updating extent and alignment facts.

Conceptually:

```text
addr.field(base, field) -> ptr
addr.index(base, index, element_layout) -> ptr
addr.offset(base, byte_offset) -> ptr
ptr.narrow(base, subextent) -> ptr
```

A derived pointer cannot acquire authority outside the source object's proven extent. If range cannot be proved, the graph must use:

- an explicit checked form whose failure is an ordinary value or explicit trap;
- a narrower runtime-proven view produced by a prior check;
- a raw operation carrying the waived obligation.

Arbitrary integer arithmetic is not ordinary pointer arithmetic.

### 4.2 Permission changes

Permissions may strengthen only when an explicit proof or owner capability authorizes it. Read-write may narrow to read-only at zero runtime cost; recovering write permission requires retained authority and no conflicting live alias.

Pointer casts do not erase provenance, extend lifetime, enlarge bounds, or manufacture permission. Operations unable to preserve those facts must be raw or target-defined.

## 5. Load, store, copy, and move

### 5.1 Ordinary load

An ordinary `load` requires proof of:

```text
live provenance
sufficient extent
required alignment
read permission
compatible access size/layout
valid alias relation
```

It produces the value plus the memory-effect continuation and implies neither volatility, atomicity, nor device interaction.

### 5.2 Ordinary store

An ordinary `store` requires destination validity, write permission, and applicable initialization/resource obligations. Embedded linear resources are transferred, never duplicated.

### 5.2.1 Checked scalar access and raw waiver surface

When a scalar byte offset is not statically proved in range, the bounded OI-06 kernel admits explicit checked load/store forms whose failure is a trap. Their pointer provenance and permission remain ordinary proof obligations; the dynamic bounds condition is checked at runtime. Statically proved accesses remain ordinary `load`/`store` and do not carry a checked wrapper. This keeps higher-level indexing/slicing in libraries while preserving the semantic failure edge at the kernel operation that actually requires it.

The bounded raw-load form is distinct. It requires a live pointer, the required read permission, the memory-effect frontier, and an explicit `effect<unsafe>` continuation plus a nonzero waiver mask. The current measured form can waive alignment and/or initialization; it does **not** waive provenance, permission, lifetime, access size, or bounds. Raw waivers are proof-visible and erase from emitted code when the target access itself needs no additional instruction.

### 5.3 Copy

`copy` preserves the source and requires a duplicable representation. Overlap is explicit:

```text
copy.disjoint(dst, src, extent)
copy.overlap(dst, src, extent)
```

`copy.disjoint` permits non-overlap optimization. `copy.overlap` has traversal-independent results. Byte copying cannot duplicate linear ownership unless the resource kind explicitly defines that behavior.

### 5.4 Move

`move` transfers initialized contents and any contained linear ownership, making the source unavailable for ordinary reads until reinitialized. It may lower to zero machine copies when optimized away.

## 6. Lifetime and initialization

Lifetime validity and initialization are separate facts.

A pointer may remain numerically representable after lifetime end but cannot be ordinarily accessed. Live storage may still be uninitialized; typed loads require compatible initialized state.

The graph verifier tracks enough state to reject:

- use after `storage.end` or parent region/arena end;
- double release;
- release through a non-owner view;
- read of uninitialized typed storage;
- duplication of linear contents by ordinary copy;
- transfer from a value already consumed by move or resource transfer.

Initialization state may be proof-only and erased.

## 7. Aliasing model

XAX aliasing is provenance- and relation-based.

Default rules:

1. Distinct simultaneously live storage object identities do not alias.
2. Views derived from the same object may alias only where their extents overlap.
3. Type identity alone never proves non-aliasing.
4. Reusing the same numeric address for a later object does not merge the two objects' provenance.
5. A cast preserves alias relationships unless an explicit verified restriction operation establishes a narrower relation.
6. Raw or target mappings that cannot provide precise provenance must use an explicit conservative alias class.

Alias classes may represent relations such as:

```text
exclusive<object, extent>
shared-read<object, extent>
may-alias<class-id>
unknown
```

For precise object-backed storage, the compact encoding is the storage-object/provenance identity itself: the verifier derives the local alias class from that identity and does not serialize a redundant class number on each pointer view. The OI-06 two-allocation measurement found zero added graph bytes/token-native atoms for this derived form versus two bytes/two atoms for explicit local class IDs. `exclusive` proves no conflicting live view over its extent; `shared-read` permits readers but no writer; `may-alias` distinguishes conservative alias sets; `unknown` is conservative. An explicit compact class ID is reserved for raw/target mappings where exact object identity is unavailable. Creating/ending an alias restriction is semantic and may be zero-cost; no lexical borrow syntax is fundamental.

## 8. Placement, volatile access, MMIO, and DMA

### 8.1 Placement

Fixed placement is explicit and may name an image section, segment, bank, fixed address, or target location key. The target package validates and lowers it; names do not imply placement.

### 8.2 Volatile

A volatile access is observable; the optimizer may not remove, invent, merge, or replace it when that changes the declared access trace. Volatile is not atomic, does not create happens-before, and does not substitute for fences.

### 8.3 MMIO and device memory

MMIO uses a target-defined address space or `device<K>` contract, not ordinary RAM semantics.

A device contract may specify:

```text
legal access widths
required alignment
read/write availability
read or write side effects
read-to-clear / write-one-to-clear behavior
forbidden speculative access
required access granularity
target-defined ordering hooks
```

MMIO carries a device effect and may only be transformed according to the target contract.

### 8.4 DMA

DMA storage and mappings are explicit resources. OI-07 target-package evidence supports the following smallest shared DMA-buffer state vocabulary on ordinary `resource<K,state>` values:

```text
host-unmapped   mapped to neither active host DMA view nor device ownership
host-mapped     host-owned mapped view; coherent or cache-maintained
host-dirty      host-owned mapped view requiring clean before device ownership
device-owned    device-owned and eligible for transfer/synchronized host return
device-pending  device work is outstanding and explicit synchronization is required
host-stale      host ownership returned but invalidate is required before host read
```

The prototype encodes these states as compact integers 1–6 under one experimental DMA resource kind. The semantic names and transition meaning are the standard; a future store-local/interner encoding may compress the numbers without changing meaning. No separate DMA object kind is introduced.

The shared legal transition envelope demonstrated by the two packages is:

```text
host-unmapped -> host-mapped
host-mapped   -> host-dirty | device-owned | host-unmapped
host-dirty    -> host-mapped                 // explicit cache clean
device-owned  -> device-pending              // device work begins
device-pending-> device-owned                // explicit synchronization
device-owned  -> host-mapped                 // coherent host reacquire
device-owned  -> host-stale                  // non-coherent host reacquire
host-stale    -> host-mapped                 // explicit cache invalidate
```

A non-coherent split-memory target uses all six states and explicit clean/invalidate operations. A coherent shared-memory target keeps host writes and host reacquire in `host-mapped` and therefore does not invent redundant cache-maintenance nodes. Both still make mapping, device ownership, device work, synchronization, host reacquire, unmapping, and release explicit. A target package may further restrict transitions; it may not silently bypass a required maintenance or synchronization state. Pinning or IOMMU-specific state remains target/platform-specific unless future cross-target evidence establishes another common semantic state. Their ordering/fence semantics belong to the concurrency stage.

## 9. Raw and unsafe access

Unsafety is attached to the operation that waives a proof obligation.

A raw operation records a waiver set such as:

```text
provenance
bounds
alignment
permission
alias
initialization
lifetime
```

A waiver does not erase other semantics. The operation still states:

- the target/address-space operation being requested;
- its value types and byte width;
- its effects;
- which obligations are waived;
- the behavior policy for an unmet condition where relevant.

Behavior policy is explicit checked failure, explicit trap, or target-defined unchecked behavior. Missing proof never silently becomes unchecked behavior. Raw access cannot waive structural validity, SSA consistency, declared effects, or resource accounting.

## 10. Resource model

The canonical resource type is:

```text
resource<K, state>
```

`K` identifies the resource kind. `state` is part of the verifier-visible state machine.

Examples include storage ownership, handles, sockets, locks, DMA channels, GPU buffers, interrupt registrations, capabilities, mappings, and transactions.

### 10.1 Acquisition

Acquisition is explicit:

```text
resource.acquire<K>(...) -> resource<K, state0>
```

Failure is an ordinary result value, not a hidden exception or runtime action.

### 10.2 Transfer

Transfer consumes the old SSA resource value and produces the continuation owned by the destination context:

```text
resource.transfer(r) -> r'
```

It may lower to zero instructions while remaining queryable and preventing silent duplication.

### 10.3 State transitions

Resource-kind contracts define legal transitions:

```text
resource.transition<K>(resource<K, S>, op) -> resource<K, S2>
```

The verifier rejects operations that are not legal from the current state.

### 10.4 Split and join

Split and join are not universally available. A resource kind may declare them only when it defines a sound algebra for partitioning authority.

For example, a buffer owner may permit splitting into disjoint byte ranges:

```text
split(owner[0..N], k) -> (owner[0..k], owner[k..N])
join(owner[A], owner[B]) -> owner[A union B]
```

Join requires compatible non-overlapping pieces. Non-partitionable resources do not expose split.

### 10.5 Release and discard

Release is explicit and consumes the resource:

```text
resource.release(resource<K, releasable>)
```

A linear resource reaches an allowed terminal transition exactly once on each terminating path unless transferred out. An affine resource may be explicitly discarded only when its kind permits:

```text
resource.discard(resource<K, S>)
```

Discard remains an explicit graph node; lexical scope does not consume resources.

## 11. Static proof and zero-runtime-cost rules

Ordinary memory operations require provenance, bounds, lifetime, alignment, permission, initialization, and alias proofs.

If all obligations are proven statically:

```text
runtime metadata cost = 0
runtime check cost = 0
```

Pointer bounds, provenance IDs, owner capabilities, alias classes, and resource states may exist only in compiler semantics. If proof fails, the graph must use an explicit checked operation, stronger evidence, restructured ownership, or raw waiver. Hidden bounds checks are forbidden.

## 12. Core invariants

1. Every ordinary memory access has valid live provenance or is rejected.
2. Every ordinary access has sufficient bounds and alignment or is rejected.
3. Write access requires explicit write permission.
4. Pointer casts never silently create lifetime, provenance, bounds, or permission.
5. Distinct live object identities are non-aliasing unless a raw/target mapping explicitly states otherwise.
6. Type names alone do not establish strict-aliasing assumptions.
7. Storage creation is semantically visible.
8. Lifetime end is semantically visible for dynamic-lifetime storage.
9. No scope exit performs an implicit destructor or release.
10. Linear resources cannot be duplicated or silently discarded.
11. Affine resources can only be discarded through an explicit kind-approved operation.
12. Split/join exists only for resource kinds with a declared partition algebra.
13. Volatile and device access are not equivalent to ordinary memory access.
14. Volatile does not imply atomicity or synchronization.
15. Raw operations identify exactly which proof obligations are waived.
16. Statically proven checks and metadata need not consume runtime space or instructions.
17. A target package may refine placement/device legality but may not silently weaken these invariants.
18. Optimization may erase or fuse operations only when observable semantics and resource state are preserved.

## 13. Rejected alternatives

| Alternative | Rejection reason |
|---|---|
| Mandatory garbage collection | Violates bare-metal and zero-runtime requirements; hides release policy and runtime cost. |
| Mandatory reference counting | Introduces hidden increments/decrements, memory traffic, synchronization risk, and runtime ownership semantics. |
| Implicit RAII/destructors | Makes scope exit perform hidden resource actions and obscures graph-level lifetime. |
| Universal built-in heap | Contradicts explicit allocator choice and programs that require no allocator. |
| C-style pointer model | Numeric-address-centric rules, type-based alias ambiguity, and implicit undefined-behavior assumptions are too imprecise for machine verification. |
| Mandatory fat pointers | Forces runtime representation cost even when bounds/provenance are statically known. |
| Type-based strict aliasing | Couples optimization legality to source-like type conventions rather than verified object relations. |
| Lexical borrow syntax as fundamental semantics | Human syntax is non-normative; graph lifetime and alias relations are the actual semantic facts. |
| Volatile as synchronization | Conflates device observability with concurrency ordering and would make optimization and verification ambiguous. |
| Raw pointer as unrestricted escape | Would hide which guarantees were abandoned and prevent local reasoning. |
| Implicit resource cleanup on error paths | Reintroduces hidden control/resource edges; cleanup must be explicit or generated as explicit graph nodes before verification. |

## 14. Interfaces with other XAX subsystems

### Type, constant, and layout system

This stage depends on exact object size, alignment, aggregate field offsets, representation compatibility, and pointer/address-space types. Layout determines the byte obligations of load/store/copy/move but does not itself grant provenance or permission.

### Effect and control-flow system

Loads, stores, device accesses, acquisition, release, and allocator operations expose effect dependencies. Resource values and owner capabilities flow through ordinary SSA edges and block parameters. Error results are ordinary values; resource cleanup paths must therefore be explicit in control flow.

### Concurrency and atomics

This stage supplies object identity, address spaces, device operations, and resource states used by concurrent semantics. Atomic ordering, fences, data-race rules, interrupt visibility, and scheduler interactions are not defined here.

### Compile-time execution

Compile-time code may construct storage/resource schemas, prove layout and bounds relations, specialize allocator/resource kinds, and erase proof-only metadata. It may not bypass the same semantic verifier obligations when constructing runtime graphs.

### Target packages

Targets define address-space inventory, legal pointer representations, fixed placement mechanisms, device/MMIO contracts, DMA facilities, ABI pointer lowering, and target-memory resource kinds. Fundamental provenance, ownership, and explicit-waiver rules remain target-independent.

### Optimizer

The optimizer may use object identity, precise extents, alias classes, permissions, initialization state, and resource state to eliminate redundant loads/stores, prove non-aliasing, scalarize aggregates, remove checks, coalesce moves, and erase zero-runtime ownership operations. It must preserve volatile/device traces and resource transitions according to their contracts.

### Serialization and AI mutation

Persistent XAX storage should intern repeated pointer/resource schemas and avoid retransmitting proof facts that can be reconstructed unambiguously. AI mutation should normally edit the smallest affected storage, pointer, or resource fact and re-run local verification rather than regenerate surrounding functions.

### Diagnostics

A failed memory/resource proof should identify the entity, violated rule, required evidence, actual evidence, dependency chain, and repair neighborhood. Natural-language borrow-style explanations are optional human views, not the canonical diagnostic.

## 15. Open issues requiring implementation evidence

The following representation choices remain open because their best form depends on verifier complexity, target coverage, and token-efficiency measurements rather than missing semantics:

1. **Alias-class encoding.** The semantic relations above are fixed, but whether canonical storage uses explicit class objects, interval capabilities, compact relation tables, or reconstructed proof edges should be benchmarked.
2. **Provenance compression.** Persistent object identity is required, but the best local-handle and serialization strategy for very large graphs requires measurement.
3. **Checked-access kernel surface.** The rule that unproved ordinary access must become checked or raw is fixed. Which checked variants deserve kernel operations versus library specialization should be decided from code-size and target-lowering evidence.
4. **DMA state vocabulary.** Closed by OI-07: the shared six-state vocabulary in §8.4 is sufficient for the measured coherent and non-coherent target packages; additional pinning/IOMMU/device-specific states remain target-defined until separate evidence justifies standardization.

These are representation or vocabulary questions. They do not weaken the invariants of this stage.

## 16. Falsification criteria

Revise this design if implementation or benchmark evidence shows:

- precise provenance and alias facts cannot be represented compactly enough for local AI queries and mutations;
- the verifier must conservatively collapse most real programs to `unknown` aliasing, eliminating the expected optimization value;
- correct ordinary systems code routinely requires raw waivers because the ownership/provenance model cannot express common patterns;
- static pointer/resource metadata causes unavoidable runtime fat-pointer or bookkeeping overhead on targets where the facts should be erasable;
- region, arena, allocator, target-memory, or raw classes cannot express at least two substantially different architectures without adding hidden platform semantics;
- MMIO or DMA correctness requires ad hoc compiler knowledge that cannot be supplied through target/platform packages and explicit effects;
- explicit resource transitions cause graph/token growth large enough to outweigh their reduction in AI repair errors, after compact serialization and local-handle protocols are implemented;
- deterministic cleanup cannot be expressed without introducing implicit destructor or exception behavior;
- optimization using the defined alias/provenance rules produces worse code than a less precise model because the proof machinery blocks common transformations rather than enabling them;
- translation validation or targeted compiler tests find a transformation considered legal by these rules that changes observable memory, device, or resource behavior.

Failures require evidence-based semantic or representation changes, not hidden runtime behavior or human-oriented source conventions.
