# XAX Stage 05 — Effects, Control Flow, Calls, and Error Semantics

## 1. Purpose and scope

This document defines the canonical XAX semantics for effect ordering, ordinary control flow, function calls, recoverable errors, fatal traps, and foreign exception interoperability.

The design preserves the founding XAX model: the authoritative program is a typed semantic graph; control, data, effects, ownership, and target-dependent behavior are explicit; pure computation carries no artificial sequencing; and no call may silently introduce allocation, synchronization, system calls, unwinding, cleanup, or exception control flow.

This stage specifies:

- effect domains, domain instances, effect dependencies, and effect summaries;
- ordering and independence rules for memory, I/O, syscall, device, filesystem, network, time, randomness, privileged, unsafe, and reserved atomic effects;
- ordinary control terminators and their block-parameter SSA behavior;
- direct and indirect call obligations;
- recoverable errors as ordinary values;
- fatal traps and verifier-only unreachable control;
- foreign exception ABI adapters without adding exceptions to core XAX;
- rules for inferring or compressing effect information;
- verifier obligations and optimization freedoms.

Thread creation, scheduling, atomic ordering, interrupts, and real-time concurrency semantics are outside this stage. The `atomic` effect domain is reserved here only so later concurrency semantics can compose with this model.

---

## 2. Normative definitions

The key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** are normative.

| Term | Definition |
|---|---|
| **pure operation** | An operation whose semantics depend only on explicit value operands and which has no effect dependency or externally observable action. |
| **effect domain** | A semantic category whose operations may require observable ordering relative to other operations in the same domain or a declared interacting domain. |
| **domain instance** | A domain refined by a verifier-proven partition key, such as a memory object, device, or external resource identity. |
| **effect token** | A semantic dependency value representing the current ordered state of one effect domain instance along a control path. It normally has no runtime representation. |
| **effect edge** | A graph dependency from one effect-producing operation to a later operation, represented directly or reconstructed canonically through effect tokens. |
| **effect footprint** | The set of domain instances an operation observes, modifies, synchronizes with, or otherwise orders. |
| **effect summary** | A conservative contract describing the externally visible effects and control outcomes of a function or callable value. |
| **effect refinement** | A proven replacement of a coarse effect domain with one or more narrower domain instances without changing observable behavior. |
| **control terminator** | The final operation of a block. It selects zero or more successor blocks or terminates the function path. |
| **recoverable error** | An ordinary typed value, normally represented by a sum, that the program may inspect and handle using ordinary control flow. |
| **trap** | An explicit non-returning fatal control operation. A trap performs no implicit unwinding or cleanup. |
| **unreachable** | A verifier assertion that a control point has no valid dynamic execution. It is not a recoverable or fatal runtime mechanism. |
| **foreign exception** | Exceptional control behavior required by an external ABI or platform contract. It is represented only through an explicit interoperability operation or adapter. |

Effect tokens are semantic ordering objects, not user-visible runtime state. Lowering MUST erase them unless a target operation requires corresponding runtime synchronization.

---

## 3. Effect model

### 3.1 Core rule

XAX effects form a **partial order**. A pure operation has no effect-token operands or results. An effectful operation conceptually consumes the current token for every domain instance it orders and produces successor tokens:

```text
(v..., eD1', eD2') = op(v..., eD1, eD2)
```

The canonical graph may encode equivalent dependency edges directly.

Operations without data, control, resource, or interacting-effect dependencies are unordered. Textual, serialized, construction, and node-ID order MUST NOT imply execution order.

### 3.2 Standard domains

| Domain | Meaning |
|---|---|
| `memory` | Observable reads or writes through XAX storage. |
| `io` | Generic external I/O not more precisely classified at the current abstraction level. |
| `syscall` | Interaction with an OS or supervisor-call ABI. |
| `device` | Target-defined device interaction. |
| `filesystem` | Filesystem-visible state and file operations. |
| `network` | Network-visible state and communication. |
| `time` | Clocks, timers, or target-defined time sources. |
| `random` | Nondeterministic or entropy-producing sources. |
| `privileged` | Operations requiring elevated authority or execution mode. |
| `unsafe` | Explicit waiver or weakening of a proof obligation; normally static rather than runtime. |
| `atomic` | Reserved for Stage 06 synchronization semantics. |

Domains are not automatically hierarchical. `io` MUST NOT silently subsume filesystem, network, device, or syscall effects.

Lowering may refine a high-level effect such as `filesystem` into `syscall` or `device` operations, but MUST preserve the original observable ordering. Redundant implementation-layer domains need not coexist on the original operation.

### 3.3 Domain instances and partitioning

A domain MAY be partitioned when independence is proven, conceptually:

```text
effect<memory:Object17>
effect<device:UART0>
```

The existing `effect<D>` form is sufficient because `D` may identify a refined domain instance.

Partitioning MUST be evidence-based. Proven-disjoint memory objects or independent devices may use separate instances. If independence cannot be proven, operations MUST share a conservative instance. Alias guesses, profile likelihood, naming, construction order, and optimizer convenience are insufficient evidence.

OI-08 measurements select the same rule for the common memory/filesystem/network/device classes: use the narrowest verifier-proven semantic instance already representable by `effect<domain,instance>` and no finer universal taxonomy. A conservative shared instance is the mandatory fallback. On the bounded two-instance fixtures this small type/graph cost materially increased unordered scheduling freedom; the policy is therefore proof-directed rather than a fixed “one token per whole domain” or “one token per operation” rule.

### 3.4 Multi-domain operations and control flow

An operation touching several domains consumes and produces every required token. This orders it against those domains without serializing unrelated ones.

Effect tokens follow control paths as semantic SSA dependencies. At a block merge, the current token may be a block parameter supplied by each predecessor. A token MAY be forwarded to mutually exclusive branch successors, but MUST NOT be forked into concurrently executable operations in the same non-partitioned domain unless Stage 06 semantics explicitly permit it.

Effect tokens are compiler-semantic objects, not mandatory ABI arguments. Calls expose their behavior through effect summaries.

## 4. Effect summaries and calls

### 4.1 Function effect summary

Every callable semantic object MUST have a verified effect contract sufficient to determine what a call may observe or modify.

A summary conceptually contains:

```text
effects:
  read/observe: {D...}
  modify/order: {D...}
control:
  returns: yes|no
  may_trap: yes|no
foreign_exception: none|explicit-contract
```

The exact binary encoding is not fixed by this stage.

A summary is an **upper bound**. A function may execute fewer effects on a particular path, but it MUST NOT perform an effect outside its verified summary.

A pure function has an empty effect set and no hidden effect token behavior.

### 4.2 Direct calls

A direct `call`:

1. evaluates only through explicit data and effect dependencies;
2. consumes the tokens required by the callee summary;
3. produces successor tokens for the domains the callee may order;
4. returns only the declared ordinary result values;
5. has no hidden exceptional successor;
6. performs no implicit caller or callee cleanup.

The verifier MUST reject a direct call whose callee body exceeds its stored or derived summary.

### 4.3 Indirect calls

An indirect call MUST have a verified call contract before it can be accepted.

The contract may originate from function-type metadata, a callable capability, a sealed dispatch set, target/platform metadata, or another canonical mechanism defined by the type/callable subsystem.

If an exact summary is unavailable, the graph MAY use an explicit conservative bound covering all domains permitted for that callable. An unbounded call with unspecified effects is invalid.

A deliberately opaque foreign call MAY use a visible "all permitted domains" contract. This is legal but intentionally destroys optimization freedom across the call.

### 4.4 Recursion and summary inference

Effect summaries MAY be inferred from function bodies.

For recursive strongly connected call components, inference MUST compute a conservative fixed point. Inference is valid only if it is deterministic and produces the same semantic contract as explicit storage.

Public interfaces, separately distributed modules, dynamic dispatch boundaries, and foreign callable objects MAY store summaries explicitly so verification does not require unavailable bodies.

Stored summaries and inferred summaries MUST never disagree. A mismatch is a verification failure, not an optimizer hint.

---

## 5. Ordinary control flow

### 5.1 Block rule

Every reachable block MUST end in exactly one terminator. Block parameters are the merge mechanism; there is no implicit phi placement or serialization-order fallthrough.

Successor arguments MUST satisfy the destination block's parameter types, resource obligations, and effect-token obligations.

### 5.2 Terminators

| Terminator | Semantics |
|---|---|
| `br target(args...)` | Unconditional transfer. |
| `cbr cond, true(...), false(...)` | Selects one successor from an explicit `bits<1>` condition. |
| `switch key, cases..., default` | Exact finite dispatch to one successor. |
| `ret values...` | Returns the declared ordinary results. |
| `trap payload...` | Explicit non-returning fatal control. |
| `unreachable` | Verifier assertion that the block has no valid dynamic execution. |

`cbr` performs no truthiness conversion. Only the selected edge executes.

`switch` cases MUST be unique. A default is required unless exhaustiveness is proven. Discriminants may be bit patterns, sum-variant identities, or another canonically finite form. Stored bits do not imply signedness, and switch has no fallthrough. Match-equivalent behavior is expressed using sum inspection plus branches or switch; no separate matching runtime is required.

`ret` MUST match the function result contract. It performs no implicit destructors, deferred actions, reference-count updates, releases, or cleanup.

### 5.3 Trap

`trap` is fatal control, not an exception. It has no normal successor and performs no implicit unwinding or cleanup. The portable payload core is one unsigned 16-bit reason code. The empty payload canonically means reason 0 (`unspecified`) with no target detail; otherwise the payload begins with a canonical ULEB reason in `0..65535`, followed by opaque target/platform bytes, with a zero prefix permitted only when at least one suffix byte follows. Prototype portable reasons are 1 (`explicit`). The suffix remains part of semantic identity and diagnostics but has no portable interpretation.

A native lowering MUST preserve the portable reason in its defined target-path observable trap convention when one is provided. The current x86-64 Windows path places it in `rax` before `ud2`; the current AAPCS64 path places it in `x0` and also encodes the same 16-bit reason in `brk #imm16`. Target-specific suffix bytes may be consumed by a platform-specific trap mechanism, but the portable compiler paths do not invent an ABI for them. Trap lowering may otherwise use a machine trap, abort ABI, reset, supervisor transfer, or another target-defined fatal mechanism, whose externally visible effects remain target/platform data.

Resource obligations on trapping paths belong to the resource model; `trap` itself supplies no invisible release.

### 5.4 Unreachable

`unreachable` is not a substitute for `trap`. The verifier MUST prove that no valid execution reaches it. If an explicit raw/unsafe waiver is permitted, that waiver MUST be present in the graph and reflected in `unsafe` effect/capability information.

Optimizers MAY use verified unreachability as a proof fact, but MUST NOT invent it from likelihood or undefined assumptions.

## 6. Evaluation-order guarantees

XAX has no unspecified evaluation order because evaluation order is not derived from source syntax.

The only semantic ordering constraints are those induced by:

1. data dependencies;
2. control dependencies;
3. resource/ownership dependencies;
4. effect dependencies;
5. target operation constraints.

If operation `B` depends on a value or effect token produced by `A`, `A` precedes `B` on that dynamic path.

If two operations have no ordering dependency, XAX deliberately leaves them unordered. The optimizer MAY reorder, overlap, fuse, eliminate, vectorize, or otherwise transform them if all observable semantics remain equal.

Node identifiers, serialization order, diagnostic display order, AI transaction order, and construction timestamps MUST NOT create execution order.

---

## 7. Recoverable error semantics

Recoverable errors are ordinary values.

A conventional result is representable as:

```text
sum<ok:T, err:E>
```

A callee returning an error variant has returned normally. No exceptional control edge exists.

Handling is ordinary graph control:

```text
r = call f(...)
tag = variant(r)
switch tag:
  ok  -> B_ok(extract_ok(r))
  err -> B_err(extract_err(r))
```

This notation is diagnostic only.

No error-specific runtime is mandatory. No stack unwinder, personality routine, landing pad, exception table, heap allocation, or thread-local exception object exists unless an explicit library, target, or foreign ABI requires it.

An error value may contain arbitrary typed data, including resource values, provided ownership rules remain valid.

The optimizer MAY specialize away error variants when proof shows only one variant can occur.

---

## 8. Foreign exception interoperability

Core XAX `call` never throws.

A foreign ABI that can unwind MUST be represented by an explicit target/platform interoperability operation whose contract exposes exceptional behavior.

Conceptually:

```text
foreign.invoke contract, callee, args...
  normal      -> B_ok(results...)
  exceptional -> B_foreign_exception(payload...)
```

`foreign.invoke` is not a new universal XAX exception mechanism. It is a target/platform-defined operation with explicit control behavior and effect information.

An adapter SHOULD convert a foreign exception at the boundary into one of:

- an ordinary XAX sum/error value;
- an explicit fatal `trap`;
- an explicit foreign rethrow operation when continuing within the same foreign ABI is required.

A normal XAX function called after conversion sees ordinary values and ordinary control flow.

Foreign unwinding MUST NOT cross an ordinary XAX call frame unless that frame is explicitly represented as participating in the foreign ABI contract. Any required cleanup on an exceptional foreign edge MUST be explicit in the adapter graph or guaranteed by the foreign ABI package.

This isolates platform exception machinery from core XAX semantics.

---

## 9. Effect inference, storage, and compression

### 9.1 Intrinsic operation effects

Every primitive or target operation definition MUST declare its intrinsic effect footprint and control behavior.

The compiler MUST NOT infer purity merely because an operation "looks mathematical" or because a previous implementation happened not to perform side effects.

### 9.2 Derived function effects

A function summary may be derived from:

- intrinsic operation footprints;
- called-function summaries;
- explicit foreign/target contracts;
- explicit unsafe waivers;
- control reachability.

Dead operations proven unreachable do not contribute to the executable effect summary after canonical normalization.

### 9.3 Safe compression

The persistent `.xax` representation MAY omit effect edges or summary fields when they can be reconstructed **uniquely and deterministically** from canonical semantics.

Compression is safe only when reconstruction does not depend on:

- optimizer heuristics;
- target cost models;
- profile data;
- unstable alias analysis;
- non-canonical traversal order;
- unavailable external code;
- implementation-specific defaults.

If two legal reconstructions would yield different ordering freedoms, the information MUST be stored explicitly.

OI-08 benchmark evidence prefers a domain-grouped persistent form when an effect-edge section is objectized: explicit operation handles are grouped per domain instance in a semantic topological run; the common immediate predecessor may be represented by a compact “previous member” code; roots, forks, joins, and other non-run frontiers carry explicit predecessor deltas. The run order is semantic data in that section and MUST NOT be inferred from ordinary graph/store serialization order. An implementation MUST reconstruct and compare the exact frontier/partial order before treating such compressed data as verified semantics. Canonical store v1 remains unchanged by the benchmark carrier.

The serializer may compress redundant facts. It may not compress semantic choices.

### 9.4 Unsafe effect information

An `unsafe` waiver is semantically significant even if it produces no runtime instruction.

Unsafe proof waivers MUST remain machine-visible after serialization/reconstruction and MUST NOT be erased merely because generated machine code is unchanged.

---

## 10. Verifier obligations

The verifier MUST reject a graph that violates any of the following:

1. an effectful primitive lacks the required incoming effect state;
2. two same-domain effects are illegally forked without partition or concurrency semantics;
3. a domain partition lacks proof of independence;
4. a call performs effects outside its declared or inferred summary;
5. an indirect call lacks a bounded effect contract;
6. a block has zero or multiple terminators;
7. a successor edge fails to satisfy block parameters;
8. switch cases overlap or are incomplete without a default/proof of exhaustiveness;
9. return values do not match the function result contract;
10. a normal `call` is modeled as having a hidden exception edge;
11. `unreachable` lacks proof or an allowed explicit unsafe waiver;
12. foreign exceptional control is not represented explicitly at the interoperability boundary;
13. stored and inferred effect summaries conflict;
14. compressed effect information cannot be reconstructed uniquely;
15. an operation's required privilege or unsafe capability is absent.

Verification SHOULD produce machine-readable diagnostics naming the violated rule, entity, expected effect/control contract, actual contract, and repair neighborhood.

---

## 11. Optimization freedoms

Subject to semantic equivalence, the optimizer MAY:

- reorder operations from independent effect domains;
- reorder or combine operations within a domain when the operation definitions prove the transformation preserves observations;
- partition a coarse effect domain after proving independence;
- merge partitions conservatively;
- eliminate effect-free dead computation;
- eliminate effectful operations only when their semantics prove the effect unobservable or redundant;
- inline calls and refine their effect summaries;
- specialize indirect dispatch into smaller verified call sets;
- fold branches and switches;
- remove unreachable blocks after proof;
- convert recoverable-error branches into direct values when variants are statically known;
- lower high-level effect domains into target/platform effects;
- erase all effect tokens that have no runtime meaning.

The optimizer MUST NOT:

- reorder operations merely because serialization order differs;
- speculate externally visible effects across control without proof;
- assume a call is pure from naming, linkage, or historical behavior;
- treat recoverable errors as impossible without proof;
- transform `trap` into `unreachable`;
- introduce hidden cleanup or exceptional control;
- erase unsafe audit information from the canonical semantic record before the relevant verification/audit boundary.

---

## 12. Invariants

1. **Meaning, not serialization order, determines execution order.**
2. **Pure computation has no effect dependency.**
3. **Effect ordering is domain-specific and therefore a partial order.**
4. **Independent domains do not serialize one another unless a declared operation links them.**
5. **Every externally observable effect is represented by an operation contract and effect footprint.**
6. **Every call has a bounded effect contract.**
7. **Core `call` has no hidden exceptional successor.**
8. **Recoverable errors are ordinary values.**
9. **Fatal behavior is explicit `trap`, not implicit exception propagation.**
10. **`unreachable` is a proof assertion, not a runtime error mechanism.**
11. **No return, trap, branch, or call performs implicit resource cleanup.**
12. **Foreign exception semantics remain explicit at foreign ABI boundaries.**
13. **Effect compression may remove redundancy but never semantic choice.**
14. **Unsafe waivers are machine-visible semantic facts.**
15. **Optimization may exploit missing dependencies only when their absence is semantically justified.**

---

## 13. Rejected alternatives

| Alternative | Rejection reason |
|---|---|
| One global effect token | Correct but unnecessarily serializes independent filesystem, device, memory, network, and other effects, reducing optimization freedom. |
| Implicit left-to-right evaluation | XAX has no normative source-text order; such a rule would create hidden sequencing and waste semantic freedom. |
| Implicit switch fallthrough | Creates control behavior not visible in successor edges. |
| Core language exceptions | Introduce hidden exceptional edges, cleanup rules, runtime metadata, and unwinding semantics that are unnecessary for recoverable errors. |
| Mandatory `try`/`catch` representation | Duplicates ordinary sum values and control flow. Foreign ABIs can be isolated in adapters. |
| Hidden "may throw" calls | Violates explicit control-flow and effect invariants. |
| Error flags or thread-local last-error state as language semantics | Couples independent operations through hidden mutable state and target conventions. Libraries may model such ABIs explicitly. |
| Treating all external actions as `io` | Prevents useful independence and makes effect summaries too coarse. |
| Optimizer-inferred purity without a semantic contract | Makes correctness depend on implementation guesses rather than program meaning. |
| Unrestricted `unreachable` as undefined behavior | Would turn missing proof into unconstrained semantics. XAX requires proof or an explicit unsafe waiver. |
| Mandatory storage of every effect edge | Wastes persistent bytes and AI tokens when edges are uniquely reconstructible. |
| Erasing unsafe markers because they emit no instructions | Loses audit and proof-waiver semantics. |

---

## 14. Interfaces and dependencies

| Subsystem | Dependency |
|---|---|
| Canonical graph | Supplies block-parameter SSA, explicit operands, terminators, and verification; effect dependencies are graph edges, not a second control representation. |
| Types/values | Supplies `bits<1>`, sums, callable contracts, effect values, and exact result typing. |
| Memory/resources | Memory effects order observations but do not replace provenance, bounds, permission, alias, ownership, transfer, or lifetime proofs. |
| Stage 06 concurrency | Owns atomic ordering, fences, threads/tasks/interrupts, and legal concurrent token behavior; this stage only reserves `atomic`. |
| Compile-time execution | Uses the same effects; policy may reject or sandbox external/nondeterministic domains to preserve deterministic builds. |
| Target/platform packages | Define syscall ABIs, devices, privilege, trap lowering, foreign exceptions, and target-specific cross-domain constraints. |
| Verifier/optimizer | Verification establishes legal dependencies and contracts; optimization exploits only proven freedoms. |
| AI workspace | SHOULD expose compact effect summaries and local dependencies. Footprint edits MUST re-verify affected summaries and callers, not unrelated program text. |

---

## 15. Open issues requiring implementation evidence

### 15.1 OI-08 resolved choices

OI-08 is closed by the committed effect-edge benchmark. Memory/filesystem/network/device partitioning is proof-directed at semantic domain-instance granularity, with one conservative instance when independence is unproven. For a future persistent edge section, domain-grouped semantic runs plus explicit predecessor deltas at roots/forks/joins are preferred over repeated explicit frontiers. The benchmark carrier is not canonical store v1, and ordinary serialization order never supplies effect semantics.

### 15.2 Effect-summary encoding for indirect calls — resolved by OI-09

Indirect calls require a bounded contract. The semantic placement is a separately content-addressed referenced `call_contract` object. In the committed OI-09 call-heavy benchmark, this placement has lower ideal token cost and lower verifier cost than embedding on both measured reuse profiles, while preserving one implementation-independent contract identity for package interfaces. A sparse-callable profile shows a byte-size crossover where direct embedding is smaller; that is retained as potential serialization-compression evidence, not as a reason to duplicate semantic authority.

A sealed dispatch set MAY additionally enumerate exact targets and thereby enable devirtualization. It remains an optimization/refinement fact: changing an implementation CID without changing its contract changes affected sealed-set identities but not the referenced CallContract identity. An indirect call never derives permission for unspecified effects from the absence of a dispatch set.

### 15.3 Trap payload portability — resolved by OI-10

The minimum portable core is one canonical unsigned 16-bit reason plus an optional opaque target/platform suffix. This is intentionally smaller than a structured exception object: reason 0 is unspecified and reason 1 is explicit fatal control in the current prototype. Additional portable meanings require an explicit specification decision; target/platform detail remains opaque unless a target package defines it.

The OI-10 evidence maps the same reason through x86-64 Windows (`rax` + `ud2`) and AAPCS64 (`x0` + `brk #imm16`) while diagnostics expose `{reason,target_data,payload}`. Changing only target-specific bytes changes semantic identity but not either portable native trap sequence; changing the portable reason changes both native sequences. This closes the portability split without adding exceptions, cleanup, unwinding, or a target-independent runtime ABI.

These issues concern representation efficiency or portability. They do not reopen the core semantic rules above.

---

## 16. Falsification criteria

Implementation evidence must force revision if any of the following occurs:

1. **Effect metadata costs more than it enables.** If graph size, AI tokens, verification time, or compile time rise materially without compensating optimization, partitioning or encoding must change.
2. **Real platforms require pervasive undeclared cross-domain ordering.** This would show the domain model is too weak or fragmented.
3. **Canonical reconstruction is unstable.** If compliant implementations reconstruct different effect dependencies or summaries from one artifact, compression is under-specified.
4. **Summary inference is impractical.** If recursive or indirect-call fixed points dominate compilation or become excessively conservative, summary storage/callable contracts must change.
5. **Foreign exception isolation fails.** If major ABIs cannot keep exceptional control explicit at adapters, the boundary model is incomplete.
6. **Recoverable values impose unavoidable material cost.** If representative error workloads remain consistently larger or slower than an explicit exception-aware design after equivalent optimization, the error model must be re-evaluated.
7. **Effect partitioning permits miscompilation.** Any unsound independence proof invalidates the relevant verifier rule or partition mechanism.
8. **A required execution order cannot be represented by data, control, resource, effect, or target constraints.** The ordering model is then incomplete.
9. **Verified `unreachable` is unusably restrictive.** If proof plus explicit unsafe waiver cannot support necessary low-level code, that boundary must change.
10. **AI mutation efficiency regresses.** If explicit effect/control representation causes more tokens, invalid transactions, or repair turns than a less redundant semantic protocol, the protocol encoding must be redesigned without weakening semantic explicitness.

The stage succeeds only if prototypes show that explicit effects and control remain exact, compact, locally editable, verifier-friendly, and exploitable by optimization.
