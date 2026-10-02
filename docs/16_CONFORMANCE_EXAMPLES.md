# XAX Conformance Model and Normative Reference Examples

## 1. Purpose and scope

This document defines how an implementation demonstrates conformance to XAX. Conformance is determined from canonical semantic artifacts, verifier behavior, declared target/platform contracts, deterministic processing rules, and observable semantics. Human-readable diagnostic or pseudostructural notation is never XAX source and is not a conformance surface.

A conformance suite derived from this document MUST test positive and negative cases. Successful compilation alone does not establish conformance; silently accepting an invalid graph is non-conforming.

Conformance does not require a garbage collector, allocator, scheduler, exception runtime, reference counting runtime, libc, operating system, textual source parser, or permanent external backend. No profile may introduce those facilities implicitly.

Normative terms **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** express requirement strength.

## 2. Normative definitions

| Term | Definition |
|---|---|
| semantic artifact | A typed XAX semantic object graph whose meaning is carried by semantic structure rather than human text. |
| canonical artifact | A semantic artifact encoded by the versioned canonical serialization rules with exactly one permitted byte representation for the represented object. |
| semantic root | The persistent identity of the root object from which the tested program/module graph is reachable. |
| implementation | A separately developed XAX component or toolchain claiming one or more conformance levels. |
| verifier | The component that checks structural, typing, effect, memory, resource, control, capability, and profile obligations before an artifact is accepted for the requested operation. |
| target package | XAX semantic data describing machine/platform value types, operations, encodings, ABI rules, memory spaces, legalizations, costs, and other target-specific contracts. |
| platform package | Target-associated semantic data describing environment boundaries such as syscalls, executable entry requirements, or hosted facilities. |
| observable semantics | Values, control outcomes, external effects, atomic behavior, traps, resource-visible actions, and target/platform observations permitted by the artifact and its declared environment. |
| target-defined behavior | Behavior intentionally selected by a target/platform semantic contract. It is not unconstrained behavior. |
| invalid artifact | An artifact that violates any mandatory rule applicable to its declared version, profile, target, or capabilities. |
| diagnostic rule identifier | A stable machine identifier naming a violated normative rule. Human wording is not part of the identifier. |
| deterministic build profile | A build mode in which all semantically relevant inputs are fixed and repeated processing by the same implementation must produce identical committed semantic results and emitted artifact bytes where emission is part of the profile. |
| reference notation | Human-readable diagnostic notation used only to describe examples in this document. It MUST NOT be accepted as proof of support for a human textual XAX language. |

## 3. Conformance levels

Conformance is layered. A claim MUST name the XAX specification version, conformance-suite version, supported level, profiles, and target-package identities used by target-dependent tests.

| Level | Name | Required obligations |
|---|---|---|
| C0 | Canonical Store | Parse/read supported canonical objects, reject malformed or noncanonical encodings, emit canonical bytes, preserve persistent identities, and round-trip supported objects without semantic or identity change. |
| C1 | Semantic Verifier | All C0 obligations plus deterministic accept/reject decisions and enforcement of all semantic rules for the claimed profiles. |
| C2 | Semantic Executor | All C1 obligations plus execution or interpretation sufficient to demonstrate the observable semantics of all claimed target-independent operations and compile-time operations. |
| C3 | Native Compiler | All C1 obligations plus target lowering and direct production of target object/executable bytes for each claimed target package. C2 is not required if equivalent semantic behavior is demonstrated through compiled execution. |
| C4 | Transactional Workspace | All C1 obligations plus query/mutation transactions, stale-base detection, atomic commit/reject behavior, and deterministic post-commit semantic roots for deterministic transactions. |

Levels are capabilities, not maturity rankings. A native compiler claiming C3 MUST identify each target package for which C3 is tested; an unscoped “supports XAX” claim is insufficient.

No level permits a textual AST to become authoritative. An implementation MAY expose text dumps, visualizations, or debugging forms, but canonical semantics and conformance decisions MUST derive from semantic objects.

## 4. Conformance profiles

Profiles identify semantic families supported by an implementation. `CORE` is mandatory for every C1, C2, C3, or C4 claim.

| Profile | Required semantic families |
|---|---|
| CORE | `bits<N>` values, constants, exact integer operations used by the suite, tuples/sums needed by core control, functions, calls, block parameters, branches, returns, traps, stack storage, address calculation, load/store, and explicit effect dependencies. |
| MEMORY | Pointer provenance, extent/bounds, alignment, permissions, alias-relevant obligations, additional storage classes, raw waivers, and memory effects. |
| RESOURCE | Linear resource acquisition, transfer, use, state transition, and explicit release. |
| CONCURRENT | Atomics, fences, exact memory orderings, atomic capability checks, and target legalization/rejection. |
| META | Deterministic bounded compile-time XAX execution, semantic construction/inspection, and specialization. |
| TARGET | Target primitives, target semantic contracts, calling conventions, legalizations, encodings, relocation/object/executable rules needed by the claimed C3 target. |
| PLATFORM | Platform/environment capabilities such as syscalls or hosted boundaries, with explicit effects and ABI contracts. |
| WORKSPACE | Query handles, transactional mutation, base-root validation, verification before commit, and conflict/staleness handling. |

A profile claim is all-or-nothing for the suite version named by the claim. Implementations MAY expose additional experimental operations, but those operations MUST be outside the conformance claim unless standardized by the named version.

## 5. Canonical serialization conformance

For every supported semantic object, canonical serialization MUST satisfy all of the following:

- one represented object has one canonical byte encoding for a given serialization version;
- integer representation, field ordering, length encoding, reference representation, interning, and identity derivation MUST follow the versioned serialization specification;
- semantically irrelevant serializer choices MUST NOT change bytes;
- malformed, ambiguous, duplicate-forbidden, out-of-order, overlong, or otherwise noncanonical encodings MUST be rejected rather than silently normalized when supplied as canonical input;
- deserialize-then-serialize of canonical input MUST reproduce identical bytes;
- serialization MUST preserve the identities of unchanged immutable objects;
- editing one reachable object MUST NOT require unrelated immutable objects to receive new content identities;
- local compact handles are session/workspace conveniences and MUST NOT replace persistent identities in the canonical store.

The suite MUST contain byte fixtures, identity fixtures, malformed encodings, boundary-length objects, repeated/interned objects, and Merkle-DAG locality cases. Exact hash algorithms or encoding constants are governed by the canonical serialization version and are not redefined here.

## 6. Semantic verifier conformance

For a fixed artifact, profile set, target/platform package set, and verifier version, the verifier verdict MUST be deterministic.

The verifier MUST reject at least:

- type-incompatible operands or results;
- control edges whose argument lists do not match destination block parameters;
- calls whose inputs, outputs, capabilities, or effects violate the callee contract;
- memory accesses lacking required provenance, bounds/extent, alignment, or permission evidence unless a semantically explicit raw waiver applies;
- implicit or duplicated ownership of a linear resource, invalid resource state transitions, and unconsumed resources where the contract requires release or transfer;
- effectful operations whose dependency/capability obligations are absent;
- unsupported atomic widths/orderings or illegal atomic combinations when the target cannot legalize them;
- target primitives whose operand/result/effect constraints are not satisfied;
- compile-time actions that exceed mandatory determinism, sandbox, or boundedness rules of the META profile;
- a transaction whose expected base root is stale;
- any artifact requiring an undeclared target/platform capability.

Rejection MUST occur before a rejected artifact is committed or treated as valid input to later semantic stages. A raw waiver changes an obligation only where its defining rule explicitly permits that waiver; it MUST NOT erase unrelated effects, ownership, or capability requirements.

## 7. Type, memory, effect, resource, and concurrency invariants

1. SSA values do not change after definition.
2. Block parameters, not hidden mutable variables, carry loop and control-flow values.
3. Evaluation order is determined by data, control, and effect dependencies; no additional order may be invented as language semantics.
4. Signedness is an operation property where the operation requires it; a `bits<N>` value does not acquire global signedness.
5. Storage creation is semantically visible.
6. Loads, stores, copies, and atomics require the memory facts mandated by their operation contracts.
7. Hidden allocation, release, ownership transfer, lock acquisition, syscall, initialization, scheduler interaction, or exception edge is forbidden.
8. Linear resources MUST NOT silently duplicate or disappear.
9. External effects MUST be represented in their applicable domains.
10. Independent effect domains MUST NOT be serialized merely to emulate a conventional single global effect chain.
11. Atomic order is exact. An implementation MUST NOT strengthen or weaken observable atomic semantics in a way that changes permitted program behavior.
12. Recoverable errors are explicit values/branches; fatal semantics are explicit traps. A call MUST NOT secretly add an exception edge.
13. Target-dependent operations are legal only through declared target/platform semantic contracts.
14. Target-defined behavior MUST remain within the choices enumerated or constrained by that contract.

## 8. Deterministic-result requirements

Canonical serialization, verifier verdicts, content identities, transaction conflict decisions, and successful deterministic transaction roots MUST be reproducible from identical normative inputs.

Compile-time execution under META MUST be deterministic for conformance cases. Any access to time, randomness, filesystem state, network state, or host process state is forbidden unless represented as an explicit declared input/effect permitted by a profile; such an input then becomes part of the conformance test vector.

Optimizers MAY choose different valid transformations. Independent C3 compilers are therefore not required to emit byte-identical machine code. They MUST preserve the same observable semantics and conform to the same ABI/target contracts.

Within a deterministic build profile, the same implementation version, semantic root, target/platform roots, build policy, compiler configuration, profile set, and explicit external inputs MUST reproduce identical emitted bytes. If an implementation deliberately offers a nondeterministic optimization/search mode, that mode cannot be used for a deterministic-build conformance claim.

## 9. Diagnostic conformance

Diagnostics are machine data. For a normative rejection test, the suite MUST be able to identify the violated rule without parsing English.

The following are normative where the corresponding subsystem specification defines them:

- diagnostic rule identifier;
- primary rejected entity identity or local test handle;
- expected/actual structured values required by the rule;
- dependency entities necessary to establish the violation.

The following are non-normative unless a later specification explicitly promotes them: English wording, punctuation, prose explanation, color, display ordering among independent diagnostics, source-like excerpts, and human remediation advice.

An implementation MAY report multiple violations. A conformance test MUST pass if the required rule identifier is present and its structured payload is correct, even if additional valid diagnostics are also emitted. The suite SHOULD avoid depending on which of several causally equivalent errors is reported first.

## 10. Cross-implementation semantic equivalence

Two implementations are semantically equivalent for a test when, given the same canonical semantic inputs and declared environment, they produce observations permitted by the same XAX semantics.

For pure computation, equivalent results MUST match exactly according to the operation contract. For traps, both executions MUST reach the required trap condition. For external effects, the ordered and unordered relationships required by effect dependencies MUST be preserved. For resources, externally visible acquisition/use/release behavior and state transitions MUST satisfy the same contract. For atomics, all observed outcomes MUST lie within the exact allowed memory-order semantics. For target-defined operations, comparison is made against the target package contract, not an unstated host behavior.

Different register allocation, instruction selection, block layout, inlining decisions, object-internal ordering permitted by the target format, or optimization strategies do not by themselves violate semantic equivalence.

## 11. Normative reference examples

The notation below is **diagnostic pseudostructural notation only**. It is not XAX source. Names such as `N0`, `B1`, and `R0` stand for local handles to semantic entities.

### 11.1 Arithmetic

```text
N0 = const bits<32> 0xffffffff
N1 = const bits<32> 1
N2 = add.wrap bits<32> N0 N1
ret N2
```

Required result: `bits<32>(0)`. Replacing `add.wrap` with an operation whose overflow semantics are unspecified is not conforming; overflow behavior belongs to the operation.

### 11.2 Branch

```text
B0(c: bits<1>, x: bits<32>, y: bits<32>)
  cbr c -> B1(x), B2(y)
B1(v: bits<32>) -> B3(v)
B2(v: bits<32>) -> B3(v)
B3(r: bits<32>) -> ret r
```

Both branch argument lists MUST match destination block parameters exactly. Passing a `bits<64>` value to `B3(bits<32>)` is rejected.

### 11.3 Loop

```text
B0 -> B1(i=0, acc=0)
B1(i: bits<32>, acc: bits<32>)
  done = eq i limit
  cbr done -> B3(acc), B2(i, acc)
B2(i, acc)
  i2 = add.wrap i, 1
  acc2 = add.wrap acc, i
  br B1(i2, acc2)
B3(result) -> ret result
```

The loop-carried state is explicit through block parameters. An implementation MUST NOT infer hidden mutable locals as part of XAX semantics.

### 11.4 Function call

```text
Fadd(a: bits<32>, b: bits<32>) -> bits<32>
  r = add.wrap a, b
  ret r

Fmain()
  x = call Fadd(4, 5)
  ret x
```

Required result: `9`. A call with a mismatched argument type, result arity, or undeclared required capability is rejected.

### 11.5 Stack memory

```text
P0 = stack.alloc object bytes=4 align=4
P1 = ptr.view P0 as bits<32> permission=rw align=4
store P1, 7
V0 = load P1
stack.end P0
ret V0
```

Required result: `7`. A load after the storage lifetime ends, a misaligned view lacking permission for unaligned access, or a write through a read-only pointer is rejected unless an explicitly defined raw operation changes the applicable obligation.

### 11.6 Resource flow

```text
R0 = acquire resource<File,Open>
R1 = resource.use R0
R2 = resource.release R1
ret
```

The resource flows linearly. Using both `R0` and `R1` as if both owned the same live resource, or returning while a required live resource is neither transferred nor released, is rejected.

### 11.7 Checked error

```text
C0 = add.checked bits<32> a, b
match C0
  ok(v)       -> B_ok(v)
  overflow(e) -> B_err(e)
```

Overflow is an explicit recoverable result and control decision. A conforming implementation MUST NOT replace this with a hidden exception edge.

### 11.8 Atomic operation

```text
A0 = atomic.load P ordering=acquire
A1 = add.wrap A0, 1
A2 = atomic.store P, A1 ordering=release
```

`P` MUST satisfy the atomic operation’s type, address-space, alignment, and target capability rules. If the target package cannot implement or legalize the requested atomic semantics, verification/lowering MUST reject the program rather than silently weaken the ordering.

### 11.9 Syscall boundary

```text
S0 = platform.op syscall.write
     args=(handle, buffer, length)
     effects=(memory.read, syscall, io)
     capability=platform.write
S1 = branch_on_result S0
```

The exact ABI and result contract are platform-defined semantic data. The syscall, memory access, and external effects are explicit. A compiler MUST NOT introduce an equivalent hidden syscall for an operation that lacks this boundary.

### 11.10 Target primitive

```text
T0 = target.op crypto.rotate_mix
     inputs=(x, k)
     outputs=(y)
     effects=()
     contract=TargetPackageObject#P
```

The primitive is valid only if the selected target package supplies the referenced operation contract and all constraints are satisfied. Its human name is illustrative; identity and semantics come from target semantic data.

### 11.11 Compile-time specialization

```text
CT0 = meta.call specialize_width(width=32)
CT1 = meta.result function<bits<32> -> bits<32>>
F0  = instantiate CT1
```

With the same compile-time semantic inputs and META execution limits, the constructed semantic result and its canonical identity MUST be deterministic. Unmodeled host randomness or clock access is non-conforming.

### 11.12 Transactional edit

```text
base_root = H0
mutation  = set-op(F3.N0, mul.wrap)
verify
commit
```

If the workspace still has base `H0` and the mutation verifies, commit MUST be atomic and produce the deterministic new root for the resulting semantic graph. If the base has changed to `H1`, the transaction MUST be rejected as stale; partial mutation is forbidden.

## 12. Invalid or rejected alternatives

| Alternative | Reason for rejection |
|---|---|
| Define conformance by parsing a human textual language | Text is not authoritative XAX source. |
| Accept multiple byte encodings for the same “canonical” object | Breaks stable identities, caching, Merkle locality, and deterministic exchange. |
| Treat successful code generation as proof of validity | Invalid graphs could be silently compiled; verification is independently normative. |
| Require byte-identical optimized machine code across independent compilers | Over-constrains optimization and target implementation without improving semantic correctness. |
| Permit implicit resource destruction or exception propagation | Introduces hidden semantics forbidden by the architecture. |
| Make English diagnostic text normative | Wastes machine interface stability on presentation and impedes structured diagnostics. |
| Allow host behavior to fill gaps in target primitives | Makes semantics depend on accidental implementation environment rather than target contracts. |
| Declare unsupported atomics “best effort” | Can silently change concurrency semantics. |
| Treat target-defined as undefined | Target-defined behavior is constrained by explicit semantic data; undefined behavior has no such contract. |
| Use a second permanent DSL for conformance, targets, or builds | Contradicts the requirement that these concepts be represented as XAX semantic data. |

## 13. Interfaces and dependencies

This conformance model depends on other XAX subsystems for the detailed rule tables it tests:

- the canonical semantic graph and core operation model define entity structure and operation contracts;
- the type/value/layout model defines type equality, layout obligations, and constant semantics;
- memory/pointer/ownership/resource rules define provenance, lifetime, permissions, linearity, and raw waivers;
- effects/control/call/error rules define dependency, branching, call, trap, and recoverable-error semantics;
- concurrency rules define atomic operations, orderings, fences, interrupts, and real-time restrictions;
- compile-time execution rules define META determinism, bounding, sandboxing, and specialization;
- canonical serialization/versioning rules define byte encoding, identity, Merkle structure, and compatibility;
- workspace/query/transaction rules define local handles, mutation preconditions, diagnostics, and commit;
- target and ABI/platform specifications define machine primitives, legalizations, calling conventions, executable interfaces, and environment capabilities;
- compiler/optimizer/lowering rules define preservation obligations and translation validation requirements where used.

This document does not override those subsystem rules. The conformance suite MUST bind each test to the exact versioned rule it exercises.

## 14. Edge cases and undefined or target-defined behavior

XAX conformance SHOULD minimize undefined behavior. When an operation cannot provide portable semantics, preference order is:

1. define exact target-independent semantics;
2. define checked failure or explicit trap;
3. define a constrained target/platform-dependent contract;
4. expose a deliberate raw operation with explicit waived obligations and remaining effects;
5. leave behavior undefined only when none of the above can accurately represent the machine capability.

Unspecified evaluation order is not available as a fallback: dependencies determine semantic ordering. Integer overflow MUST follow the selected operation (`wrap`, `checked`, `saturate`, or another explicitly standardized form). ABI details, register use, executable entry rules, syscall numbers, and target instruction behavior may be target/platform-defined only through versioned semantic packages.

A conformance test involving target-defined behavior MUST include the target/platform package identity and MUST test the contract’s allowed set rather than one host’s incidental outcome.

## 15. Open issues

Only issues requiring implementation evidence remain open:

1. **Diagnostic payload minimums.** Rule identifiers are normative, but the smallest dependency/repair-neighborhood payload that remains stable and useful should be fixed after verifier prototypes expose real failure graphs.
2. **Cross-implementation atomic litmus corpus size.** The semantic requirement is exact, but the minimum practical corpus needed to detect incorrect orderings depends on target support and executable test methodology.
3. **Deterministic optimizer boundary.** Same-implementation byte reproducibility is required for deterministic builds, but the exact set of build-policy inputs that must be hashed into a reproducibility manifest should be finalized with package/build implementation evidence.

These issues do not permit semantic ambiguity in accepted programs.

## 16. Falsification criteria

The conformance design is wrong or incomplete if later implementation evidence demonstrates any of the following:

- two conforming serializers produce different canonical bytes or persistent identities for the same versioned semantic object;
- a canonical serializer cannot reject ambiguous/noncanonical encodings without losing required forward compatibility;
- two conforming verifiers, given identical normative inputs and profiles, disagree on whether an artifact is valid because the specification leaves a required rule ambiguous;
- a valid program’s observable behavior differs across conforming implementations for reasons not permitted by an explicit target/platform contract;
- invalid ownership, memory, effect, control, or atomic behavior can pass the required negative suite while still satisfying the written rules;
- deterministic META execution yields different semantic results from identical explicit inputs;
- deterministic transactions can partially commit, commit on a stale base, or produce different semantic roots from identical starting state and mutations;
- diagnostic rule identifiers prove too unstable to support machine repair without coupling conformance to English text;
- the profile system allows an implementation to claim a profile while omitting operations necessary to exercise that profile meaningfully;
- target-defined behavior repeatedly requires compiler-private knowledge that cannot be represented in target/platform semantic packages;
- deterministic build requirements make legitimate optimization impossible without improving reproducibility or semantic confidence;
- the conformance suite cannot distinguish an implementation that merely compiles examples from one that correctly rejects malformed or semantically invalid artifacts.

Any such result requires revising the applicable semantic rule, profile boundary, test oracle, or deterministic-input definition before expanding the conformance claim.
