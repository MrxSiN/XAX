# XAX Stage 03 — Type, Value, Constant, and Layout System

## 1. Purpose and scope

This document defines the canonical XAX model for types, SSA values, constants, and physical layout.

The design preserves the founding rule that **meaning is source**. Types are semantic objects in the canonical graph, not parser artifacts or human-facing declarations. Value interpretation must be exact enough for verification, optimization, specialization, and direct native lowering without introducing hidden conversions, target assumptions, or runtime machinery.

This stage defines:

- the core type families;
- typed SSA value rules;
- constant identity and encoding;
- integer and floating-point value semantics;
- aggregate, pointer, function, resource, effect, opaque, and target-facing types;
- the separation between semantic type identity and target storage layout;
- compile-time size/alignment/layout queries;
- explicit physical-representation types for ABI and device interfaces;
- representation equivalence and reinterpretation rules;
- proof metadata that has zero runtime cost;
- verifier obligations owned by this stage.

This stage does **not** fully define pointer provenance, object lifetime, allocation, loads/stores, ownership transfer, resource release, effect ordering, calls, or target lowering. Those systems consume the definitions here but specify their own behavioral rules.

---

## 2. Normative definitions

| Term | Normative meaning |
|---|---|
| **type** | An immutable, interned semantic descriptor defining the admissible values and operations of a value class. |
| **type identity** | Equality of canonical type descriptors after canonicalization; normally represented persistently by content identity and locally by compact handles. |
| **value** | A typed semantic result produced by a parameter, constant, operation, block parameter, or other graph entity. |
| **SSA value** | A value with one definition and no mutation. State changes are represented by new values and explicit effects, not by changing a value. |
| **constant** | An immutable typed semantic value whose complete meaning is available at compile time and is independent of runtime execution. |
| **semantic width** | The number of logical bits or lanes defined by a semantic type. It is not necessarily a target storage size. |
| **layout** | A target/context-specific physical representation: storage size, alignment, field placement, discriminant placement, stride, and related ABI/device properties. |
| **representation** | The physical bit/storage form selected for a semantic value in a given layout context. |
| **explicit-layout type** | A distinct interned type whose physical representation contract is part of its semantic identity because external interoperability requires exact layout. |
| **proof fact** | Compile-time evidence about a value, such as a range, alignment, non-null property, known bits, or representation condition. Unless explicitly promoted to a type, a proof fact does not change runtime representation or base type identity. |
| **valid bit pattern** | A physical representation admitted by a type under a particular representation contract. |
| **reinterpretation** | Construction of a value of one type from the representation of another without a semantic numeric/structural conversion. |

Normative keywords **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** have their ordinary specification meanings.

---

## 3. Canonical type model

### 3.1 Core families

The canonical semantic type families are:

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
```

Derived compile-time construction MAY create explicit-layout type objects as defined in §8 without adding hidden runtime behavior.

All type parameters that participate in semantic meaning MUST participate in canonical identity.

### 3.2 General well-formedness

A type descriptor MUST be finite, deterministic, canonically serializable, and independent of human spelling.

The verifier MUST reject nonpositive bit widths or vector lane counts, malformed/unresolved references, illegal recursive descriptors, undefined semantic parameters, and contradictory explicit-layout constraints.

There are no implicit aliases. Structurally identical canonical structural descriptors intern to one type. Nominal identity exists only where a constructor explicitly includes a nominal key such as `K`.

### 3.3 Type interning and persistent identity

Canonical type descriptors are immutable and interned. Persistent identity SHOULD be content-derived from canonical serialization; local workspaces SHOULD use small handles.

Structural types with identical canonical descriptors are identical after interning. For `opaque<K>` and `resource<K,state>`, nominal keys remain part of identity even when representations match.

Type identity MUST NOT depend on names, formatting, irrelevant declaration order, local handles, or target layout unless layout is explicitly part of the type.

---

## 4. Values and exact scalar semantics

### 4.1 Typed values

Every runtime-capable semantic value MUST have exactly one canonical type.

Operations MUST consume and produce exact declared types. XAX has no implicit:

- integer promotion;
- sign conversion;
- truncation;
- extension;
- float widening or narrowing;
- pointer/integer conversion;
- vector splat;
- tuple destructuring;
- sum injection;
- ABI coercion.

Each such transformation, when valid, is an explicit semantic operation.

### 4.2 `bits<N>`

`bits<N>` is an exact `N`-bit pattern type.

Its value set is:

```text
{0, 1, ..., 2^N - 1}
```

as bit patterns. The stored type itself does not declare signedness.

Signed or unsigned interpretation belongs to operations where interpretation matters. Examples include conceptually distinct operations such as:

```text
udiv
sdiv
icmp.ult
icmp.slt
lshr
ashr
zext
sext
```

Arithmetic overflow behavior MUST also be explicit at the operation:

```text
add.wrap
add.checked
add.saturate
```

Therefore `bits<32>` can be consumed by both signed and unsigned operations without changing the underlying value type.

Arbitrary widths are normative. Implementations MAY impose explicit compilation-resource limits, but MUST report them rather than silently changing width.

Implemented kernel integer operations (2026-10-02, ADR-084): `add.wrap`, `sub.wrap`, `mul.wrap`, `bit.and`, `bit.or`, `bit.xor`, `rotate.right k`, `udiv`, `urem` (zero divisor → trap, portable reason 2), `int.truncate`, `int.zero_extend`, and `int.compare` (unsigned and signed predicates). The interpretations named above that are not in this list — `lshr`, `ashr`, `sext`, signed division — are, for now, exact compositions or future admissions under the kernel admission rule (`XAX_SPEC.md` §21.5, OI-39). They are not implicit behaviors of any existing operation.

### 4.3 Integer constants

A `bits<N>` constant is canonically identified by:

```text
(type = bits<N>, bit_pattern)
```

The bit pattern MUST contain exactly `N` semantic bits.

Negative human-number notation has no special canonical status. For example, the all-ones `bits<8>` pattern is the same stored constant whether a diagnostic chooses to display it as `255`, `0xff`, or signed `-1`.

Constant construction that starts from a mathematical integer MUST specify whether out-of-range input is rejected, wrapped, saturated, or otherwise transformed. The canonical constant itself contains only the resulting exact bit pattern.

### 4.4 `float<F>`

`float<F>` denotes values under an explicit semantic format descriptor `F`. The descriptor MUST determine the semantic value space and encoding rules, including applicable radix, precision, exponent range, zeros, infinities, NaNs/payloads, subnormals, and semantic encoding width. XAX does not assume IEEE binary formats.

Constants preserve every distinction made observable by `F`, including signed zero and NaN distinctions. Compilers MUST NOT silently canonicalize NaNs, flush subnormals, alter rounding, or contract operations.

Floating operations whose result varies by rounding, exception, contraction, denormal, or trap policy MUST carry that policy explicitly or depend on an explicit environment object defined by the effects stage. If a target lacks direct support, lowering MUST emulate, use another verified implementation, or reject the target/policy combination.

---

## 5. Aggregate and vector types

### 5.1 `vec<N,T>`

`vec<N,T>` is an exact ordered vector of `N` lanes of type `T`. Lane count is semantic; native register width is not.

A target MAY lower a semantic vector to one or more registers, scalar operations, target instructions, or other legal sequences. Vector operations MUST state lane-wise, horizontal, permutation, masking, overflow, and floating semantics explicitly.

### 5.2 `tuple<T...>`

`tuple<T...>` is an ordered product type.

Tuple semantics define element count, order, and element types. They do **not** define:

- byte offsets;
- padding;
- ABI register assignment;
- storage alignment;
- endianness;
- field packing.

An empty tuple MAY represent the unit product with one semantic value. Whether it occupies storage in a particular context is a layout question.

### 5.3 `sum<T...>`

`sum<T...>` is a tagged semantic union with exactly one active alternative.

Its semantics define the alternative set and active variant, but no default discriminant width or payload layout.

Construction MUST identify the selected alternative. Extraction of a payload MUST be dominated by, conditioned on, or otherwise proven from evidence of the active variant.

A sum has no implicit “zero variant.” Any default variant is an explicit higher-level convention, not a core rule.

---

## 6. Pointer, function, resource, effect, and opaque types

### 6.1 Pointers

The pointer type family is:

```text
ptr<space,T,permission,alignment>
```

where:

- `space` identifies a semantic address space;
- `T` identifies the addressed semantic element type;
- `permission` expresses the static access authority relevant to later memory rules;
- `alignment` expresses a guaranteed minimum alignment when such a guarantee is part of the pointer contract.

Pointer provenance, object identity, extent, alias class, lifetime, pointer arithmetic, dereference obligations, and raw-memory waivers are defined by the memory stage. For precise object-backed pointers, OI-06 derives provenance/alias class from storage identity rather than adding another pointer-type parameter or redundant serialized class ID.

A pointer type MUST NOT imply the existence of a null value. Nullability is valid only when the address-space/pointer contract explicitly defines a null representation and semantics.

### 6.2 Function types

A function type identifies exact ordered input and output types:

```text
fn<input...,output...>
```

No implicit argument or result coercion exists.

Calling convention, unwind compatibility, capability declarations, and effect summaries are not silently inferred from this type family. Later call/effect and target/ABI stages may attach or wrap additional contract data when those properties are semantically relevant.

A function value has no generic zero/null value unless an explicitly defined callable-reference representation provides one.

### 6.3 Resources

`resource<K,state>` denotes a semantic resource kind `K` in a declared state.

Resource values may represent entities such as file handles, locks, GPU buffers, transactions, capabilities, or device channels, but this stage defines only type identity.

`K` and `state` participate in canonical identity. State transitions require explicit operations defined by the resource-owning subsystem. Bitwise copying or reinterpretation MUST NOT duplicate a linear resource.

### 6.4 Effects

`effect<D>` denotes a semantic effect-domain dependency or capability object for domain `D`.

Effect values are graph-semantic values and SHOULD erase before runtime when they exist only to encode ordering/proof. Runtime representation is permitted only when explicitly required by a concrete environment contract.

The ordering and consumption rules for effect values are defined by the effects stage.

### 6.5 Opaque and target-defined types

`opaque<K>` is a nominal semantic type owned by identity `K`. Target packages MAY define target-specific types through opaque or target-owned descriptors, but MUST provide enough contracts for verification and lowering. Target assumptions MUST NOT leak into fundamental XAX semantics.

---

## 7. Constants, zero values, traps, poison, and undefined values

### 7.1 Constant model

Constants are immutable interned semantic objects. A constant descriptor MUST include its exact type and enough information to reconstruct its value without runtime execution. Aggregate constants compose recursively; repeated large constants SHOULD be content-interned and locally referenced by compact handles.

### 7.2 Zero values

XAX has no universal zero-initialization rule.

A type is **zero-constructible** only when its semantics explicitly define such a value.

Core cases:

| Type | Generic zero? |
|---|---|
| `bits<N>` | Yes: all semantic bits zero. |
| `float<F>` | Only the format-defined positive zero when `F` has one; negative zero remains distinct. |
| `vec<N,T>` | Only if `T` is zero-constructible, by lane-wise construction. |
| `tuple<T...>` | Only if every element is zero-constructible, by element-wise construction. |
| `sum<T...>` | No generic zero. |
| pointer | No generic zero/null unless the pointer contract explicitly defines one. |
| function | No generic zero. |
| resource | No generic zero. |
| effect | No generic zero. |
| opaque | Only if `K` explicitly defines one. |

Memory initialization policy MUST therefore use explicit construction, not a language-wide assumption that all-zero bytes produce a valid value.

### 7.3 No canonical poison or `undef`

The canonical graph has no poison value or implicit `undef`. Arbitrary/nondeterministic values require an explicit semantic operation defining their constraints.

Compiler-internal IR MAY use poison-like analysis states, but they MUST NOT be committed or alter observable meaning.

Uninitialized storage is a memory-state property, not a value; invalid loads are handled by memory verification or explicit raw semantics, not by producing `undef`.

### 7.4 Traps

A trap is an explicit control/effect operation, not a value.

Checked arithmetic, conversion, or representation operations MAY produce an ordinary result encoding success/failure or branch to an explicit trap according to their operation contract. No type implicitly traps merely because one physical bit pattern is unusual.

---

## 8. Semantic type versus physical layout

### 8.1 Separation rule

Except for explicit-layout types, semantic type identity MUST be independent of target layout.

For example, these facts are semantic:

```text
bits<24> has 24 logical bits
tuple<bits<8>,bits<32>> has two ordered elements
vec<3,float<F32>> has three lanes
```

These facts are layout-dependent:

```text
bits<24> occupies 3 or 4 addressable bytes
tuple element 1 begins at byte offset 4
vec<3,float<F32>> has 16-byte ABI size
sum<T,U> uses an 8-bit or 32-bit discriminant
```

A target/platform package and layout context decide the latter.

This separation is mandatory so new targets do not change the core semantic type system.

### 8.2 Layout context

A layout query is conceptually:

```text
layout_query(type, target, context) -> layout-result | unsupported
```

`context` MUST distinguish uses whose physical rules differ, including memory, stack, ABI arguments/results, device buffers, packed external records, register classes, and object-file data.

Results MAY contain storage extent, ABI/preferred alignment, stride, field/lane offsets, discriminant/payload placement, representation constraints, and byte/bit-order mapping as applicable.

### 8.3 Compile-time layout queries

Size, alignment, offsets, and related properties are compile-time queries once target and layout context are fixed.

A query MUST return an exact deterministic answer, return an explicitly accepted symbolic compile-time constraint, or report unsupported/not-yet-decidable. It MUST NOT guess.

No runtime `sizeof` machinery is required. Types without runtime representation SHOULD report `no-runtime-representation` rather than an invented size zero unless the context explicitly defines zero-sized placement.

### 8.4 Explicit-layout types

External ABIs, device registers, packet formats, shared-memory interfaces, and hardware descriptors sometimes require physical layout to be part of meaning.

For those cases, compile-time metaprogramming MAY construct an **explicit-layout type** with canonical descriptor conceptually equivalent to:

```text
ExplicitLayoutType {
    logical_type
    storage_extent
    alignment
    members / slices
    representation_constraints
    byte_or_bit_order
    target_scope
}
```

This is a distinct interned type. Its layout contract participates in type identity.

An explicit-layout type MUST state whether it is:

- target-independent by construction, such as a fixed bit-level wire format;
- scoped to a target family;
- scoped to one exact target/platform ABI.

An explicit-layout type MUST NOT silently alter the semantics of its `logical_type`. Conversion between logical and explicit-layout forms requires explicit pack/unpack or representation operations.

This mechanism is not a second target DSL. The descriptor is ordinary canonical XAX semantic data and may be constructed and inspected by XAX compile-time programs.

---

## 9. Representation equivalence and reinterpretation

### 9.1 Distinct relations

The compiler MUST distinguish at least these relations:

```text
same_type(A,B)
same_semantic_value_domain(A,B)
representation_compatible(A,B,target,context)
safe_reinterpretable(A,B,target,context)
```

They are not interchangeable.

Two nominal opaque types may be representation-compatible but not the same type.

Two integer bit types of equal width may have identical representation while conversions still remain explicit because operation-level interpretation differs.

### 9.2 Safe reinterpretation

Safe representation-preserving reinterpretation requires proof of equal extent, sufficient alignment, destination-valid bit patterns, and preservation of resource linearity, pointer authority/provenance, effect dependencies, function contracts, and padding rules. Any unproven obligation causes rejection.

### 9.3 Raw reinterpretation

A later memory/unsafe subsystem MAY define explicit raw reinterpretation operations that waive selected proof obligations.

Such waiver MUST be machine-visible in the semantic graph. A raw operation does not retroactively make the conversion safe and does not grant optimizers permission to assume the waived invariant.

Pointer, resource, effect, and function values SHOULD be excluded from generic raw bit reinterpretation unless their defining subsystem supplies a precise operation.

---

## 10. Refinements and zero-runtime-cost proof metadata

XAX v0.1 keeps general ranges and refinements as verifier/optimizer proof facts rather than distinct runtime types. Examples include ranges, nonzero facts, known bits, alignment, and active sum variants.

Proof facts MUST derive from canonical semantics, validated assumptions, or proof-producing operations; MUST NOT alter runtime representation; and MUST be invalidated when premises cease to hold. They MAY be recomputed or persisted as cache/proof objects.

A refinement SHOULD become a distinct semantic type only when programs must observe it, an API requires nominal capability, or implementation evidence shows proof-only representation is inadequate.

---

## 11. Verifier rules

The Stage 03 verifier MUST enforce:

1. type-constructor and parameter well-formedness;
2. exact operand/result typing and absence of implicit conversions;
3. canonical, type-valid constants;
4. exact tuple, sum, and vector structure;
5. preservation of opaque/resource nominal identity;
6. absence of accidental target-layout assumptions in ordinary semantic types;
7. deterministic target/context-qualified layout queries;
8. internal consistency of explicit-layout descriptors;
9. complete proof for safe reinterpretation;
10. sound proof metadata;
11. absence of canonical poison/`undef`;
12. zero/null/default construction only where defined by the type contract.

Diagnostics SHOULD identify machine-readable rule IDs, involved entities, proof obligations, and the smallest repair neighborhood.

---

## 12. Invalid or rejected alternatives

| Rejected alternative | Reason |
|---|---|
| Put signedness in every integer type (`i32`, `u32`) | Duplicates representation identity and forces unnecessary conversions. XAX places signed/unsigned interpretation on operations where it matters. |
| Fixed-width integers only | Prevents exact modeling of packed fields, unusual hardware widths, cryptographic arithmetic, and target semantics. |
| Implicit integer promotions | Introduce hidden semantic changes and target/language folklore. |
| One universal float type | Cannot express exact formats, NaN behavior, or nonstandard hardware semantics. |
| Ambient floating-point mode | Creates hidden dependencies and invalidates local reasoning unless modeled explicitly. |
| Canonical poison/`undef` | Makes exact meaning dependent on optimizer rules and permits hidden nondeterminism. |
| Universal zero initialization | Invalid for sums, resources, pointers without null, opaque capabilities, and many external representations. |
| Target layout embedded in ordinary tuple/vector types | Makes one semantic program target-specific and obstructs universal lowering. |
| C-like “struct layout by default” | Elevates one ABI tradition into core semantics and introduces padding assumptions unrelated to meaning. |
| Representation compatibility implies type equality | Breaks nominal resources, opaque capabilities, ABI distinctions, and safety proofs. |
| General refinement types in v0.1 | Increase type-identity and AI-token complexity before evidence shows they are required. Proof metadata provides most optimization value at lower semantic cost. |
| Implicit pointer/integer or pointer/pointer reinterpretation | Can fabricate provenance, permissions, or address-space meaning. |
| Hidden runtime type descriptors | Violates the no-hidden-runtime rule; runtime reflection must be explicitly requested. |

---

## 13. Interfaces with other XAX subsystems

- **Semantic graph/serialization:** stores references to interned types and constants while preserving canonical identity and permitting compact local handles.
- **Memory/ownership:** consumes pointer types, address spaces, permissions, alignments, layouts, and representation rules; it owns provenance, extent, lifetime, aliasing, initialization, loads/stores, ownership, and raw waivers.
- **Effects/calls/errors:** owns effect ordering, extended call contracts, trapping control flow, recoverable error values, and explicit environment state required by operations.
- **Compile-time execution:** may construct types, inspect canonical identity, query layout, build explicit-layout types, and specialize by type properties.
- **Target packages:** define machine value forms, address spaces, ABI/storage layouts, native floats/vectors, alignment, target types, and legalization without redefining core type meaning.
- **Optimizer:** may use type, layout, and proof facts and change representation only when observable semantics are preserved.

---

## 14. Open issues requiring implementation evidence

Only the following issues remain intentionally open for v0.1 implementation evidence:

1. **Canonical float format catalog.** The semantic requirements for `F` are fixed, but the initial set of pre-interned common formats versus fully structural format descriptors should be selected by serializer/token and compiler-complexity measurements.
2. **Proof-fact persistence policy.** The semantics of proof metadata are fixed, but which facts should be serialized, cached, or recomputed should be decided from incremental verification cost and artifact-size measurements.
3. **Compact type vocabulary.** Canonical identity is fixed, but which high-frequency types receive dedicated transport/token IDs should be chosen empirically from AI token and mutation benchmarks.

These issues affect encoding and implementation efficiency, not program meaning.

---

## 15. Falsification criteria

This design must be revised if later compiler implementation or benchmarking demonstrates any of the following:

1. Separating semantic type from target layout causes pervasive semantic ambiguity that cannot be resolved by explicit target/context queries.
2. The explicit-layout mechanism cannot represent required ABI, device, wire, packed-bit, or shared-memory contracts without introducing a second permanent layout language.
3. Arbitrary-width `bits<N>` causes unacceptable verifier or optimizer complexity even when uncommon widths are legalized late and common widths are fast-pathed.
4. Operation-level signedness creates materially more AI-generation errors or semantic mutations than type-level signedness after controlling for tokenizer and protocol design.
5. Exact float-format semantics make ordinary floating optimization impractical without a smaller equivalent semantic contract.
6. Excluding poison/`undef` from canonical semantics prevents competitive optimization even when compiler-internal transient analysis states are permitted.
7. Proof-only refinements fail to provide enough information for verification or optimization and a distinct refinement-type identity demonstrably reduces total complexity.
8. Structural type interning produces excessive persistent identity, incremental-update, or AI-context costs compared with an alternative that preserves exact semantics.
9. Layout queries cannot be made deterministic for supported targets without embedding hidden platform state.
10. Safe-reinterpretation obligations are either too weak to prevent invalid representation use or so expensive that a simpler exact rule yields better verified compilation without loss of required expressiveness.

A failed criterion requires changing the smallest affected rule. It does not justify weakening the founding invariants of exact semantics, explicit behavior, machine-verifiable mutation, or target-independent core meaning.
