# XAX Stage 06 — Concurrency, Atomics, Interrupts, and Real-Time Profiles

## 1. Purpose and scope

This document defines the low-level concurrency and deterministic-latency semantics of XAX.

The stage makes shared-memory interaction, synchronization, asynchronous machine entry, and latency-relevant behavior explicit enough for verification, optimization, target lowering, and AI mutation without assuming a mandatory runtime.

It defines atomics, fences, compare/exchange, target capability checks, the shared-memory race rule, synchronization effects, interrupt/trap contracts, the SIMD/GPU boundary, real-time rejection profiles, latency queries, and the distinction between proof-backed guarantees and cost estimates.

This stage does **not** define a scheduler, thread library, operating-system API, GPU runtime, allocator, garbage collector, exception runtime, or universal worst-case-execution-time algorithm.

The governing architectural rule remains: meaning is source. Concurrency behavior that can affect correctness or latency MUST therefore be represented by semantic operations, dependencies, capabilities, target contracts, or explicit environment assumptions. It MUST NOT arise from invisible runtime behavior.

---

## 2. Normative definitions

The key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** are normative.

### 2.1 Execution agent

An **execution agent** is an independently progressing locus of execution that may overlap with another agent.

Examples include an operating-system thread, hardware thread/core, interrupt handler relative to interrupted execution, or a GPU execution unit when its target package gives it shared-memory semantics. A library task is an execution agent only when its implementation permits concurrent execution.

The kernel does not require a universal agent representation. Agent identities and topologies MAY be supplied by a platform or target package.

### 2.2 Memory event

A **memory event** is an operation that reads, writes, or synchronizes through memory.

A memory event carries the applicable address space, provenance, extent, alignment, atomic status, ordering, synchronization scope, effects, and target capability requirements.

### 2.3 Conflicting accesses

Two memory accesses **conflict** when their accessed storage extents overlap and at least one access writes a bit observed by the other.

### 2.4 Happens-before

**Happens-before** is the transitive closure of:

1. intra-agent semantic sequencing required by the XAX graph;
2. synchronization edges established by release/acquire operations, fences, joins, or target/platform operations whose contracts explicitly define such edges;
3. other explicit dependency edges whose contracts state that they establish happens-before.

Graph adjacency alone does not imply execution ordering unless the involved data, effect, control, or synchronization dependency requires it.

### 2.5 Modification order

Each atomic memory location has a **modification order**: a total order over atomic writes and successful atomic read-modify-write updates to that location.

Modification order is semantic. A target lowering MUST preserve it.

### 2.6 Data race

A **data race** exists when two conflicting accesses can occur in different execution agents, are not ordered by happens-before, and at least one access is non-atomic.

A normal XAX program MUST NOT contain a data race.

XAX does not convert a data race into an implicit license for arbitrary compiler behavior. If a program intentionally requires racy target behavior, it MUST use an explicit raw/target concurrent-memory operation whose semantic contract defines the allowed observations. Waiving a proof obligation does not invent semantics.

### 2.7 Blocking

An operation **may block** when its completion can depend on an event not bounded solely by the executing agent's finite instruction progress under the stated environment contract.

Examples include waiting for a lock owner, scheduler wakeup, filesystem completion, network completion, unbounded device response, or an operating-system service.

### 2.8 Bounded operation

An operation is **bounded** under an environment contract when a finite upper bound can be proven for the relevant resource or latency property. A numerical target cost estimate is not by itself a proof of boundedness.

### 2.9 Real-time profile

A **real-time profile** is a semantic build policy containing admissibility predicates over source semantics, target lowering, and declared environment assumptions.

A profile can reject a program even when the program is otherwise semantically valid.

Profiles constrain compilation; they do not create hidden runtime behavior.

---

## 3. Atomic operation model

### 3.1 Canonical atomic families

The target-independent semantic model contains the following atomic families:

```text
atomic.load
atomic.store
atomic.rmw
atomic.cmpxchg
atomic.fence
```

Each operation explicitly carries the fields required by its family.

Conceptual schemas:

```text
atomic.load(
    ptr,
    value_type,
    order,
    scope,
    alignment
) -> value

atomic.store(
    ptr,
    value,
    order,
    scope,
    alignment
)

atomic.rmw(
    ptr,
    update_kind,
    operand,
    order,
    scope,
    alignment
) -> old_value

atomic.cmpxchg(
    ptr,
    expected,
    desired,
    success_order,
    failure_order,
    scope,
    alignment,
    strength
) -> tuple<old_value, success>

atomic.fence(
    order,
    scope
)
```

`update_kind` identifies exact update semantics. Examples include exchange, bitwise operations, and arithmetic with explicit overflow behavior such as wrapping addition. The atomic operation does not silently change the arithmetic semantics of the update.

`strength` for compare/exchange is:

```text
strong
weak
```

A weak compare/exchange MAY fail spuriously according to its semantic contract. A strong compare/exchange MUST NOT fail spuriously.

### 3.2 Memory orders

The portable order set is:

| Order | Atomicity | Acquire effect | Release effect | Global sequential order |
|---|---:|---:|---:|---:|
| `relaxed` | yes | no | no | no |
| `acquire` | yes | yes | no | no |
| `release` | yes | no | yes | no |
| `acq_rel` | yes | yes | yes | no |
| `seq_cst` | yes | yes where applicable | yes where applicable | yes |

Rules:

1. `relaxed` guarantees atomic access and participation in modification order, but creates no inter-agent synchronization edge by itself.
2. A release-like write synchronizes with an acquire-like read that reads from that write or from its release sequence.
3. A **release sequence** is a release-like write followed in modification order by zero or more atomic read-modify-write updates to the same location.
4. `acq_rel` combines acquire and release behavior where the operation both reads and writes.
5. All `seq_cst` operations participate in one total sequentially-consistent order consistent with required happens-before and per-location modification order constraints.
6. An implementation MAY use stronger machine ordering than requested only when observable XAX semantics and selected cost/policy constraints are preserved.
7. An optimizer MUST NOT weaken an order unless it proves the weakened operation preserves all observable behavior.

`consume` is not a portable XAX memory order. Dependency-based target primitives MAY exist as target operations, but portable semantics do not depend on historically unstable consume-style rules.

### 3.3 Valid order combinations

`atomic.load` permits:

```text
relaxed
acquire
seq_cst
```

`atomic.store` permits:

```text
relaxed
release
seq_cst
```

`atomic.rmw` permits all five portable orders.

For `atomic.cmpxchg`:

- `success_order` MAY be any portable order valid for a read-modify-write operation;
- `failure_order` MAY be `relaxed`, `acquire`, or `seq_cst`;
- failure ordering MUST NOT contain release semantics;
- failure ordering MUST NOT be stronger than the read-side guarantees of the success ordering.

Invalid order combinations are verifier errors, not target-lowering accidents.

### 3.4 Fences

A fence has no storage value result. It constrains memory-event ordering according to its order and scope.

`atomic.fence` permits:

```text
acquire
release
acq_rel
seq_cst
```

A relaxed fence is invalid because it would add no portable synchronization semantics.

A fence MUST NOT be treated as a universal compiler barrier beyond the effects implied by its contract. Independent non-conflicting effects remain optimizable when proof permits.

### 3.5 Atomic widths, alignment, and address spaces

The semantic type system permits arbitrary bit widths, but a target does not necessarily support every type as an atomic object.

Before lowering an atomic event, the compiler queries a target capability equivalent to:

```text
atomic_capability(
    address_space,
    width,
    alignment,
    operation_family,
    order,
    scope
)
```

The result describes at least:

```text
support:
    native
    bounded_sequence
    runtime_assist
    unsupported

lock_free:
    always
    conditional
    no

retry_behavior:
    none
    statically_bounded
    potentially_unbounded

required_alignment
supported_orders
supported_scopes
latency_properties
```

A lowering MUST NOT silently insert a lock, allocator use, scheduler call, system call, or runtime helper.

If a target requires runtime assistance, the resulting semantic/lowering dependency MUST be exposed before final profile verification. A program or build policy MAY reject that assistance.

Misaligned atomic access is invalid unless the target package explicitly supplies semantics for that alignment.

### 3.6 Atomic effect precision

Atomic operations participate in memory and synchronization reasoning, but they do not create one mandatory global `atomic` serial chain.

Effect dependencies SHOULD be as precise as the verifier can establish from:

- provenance;
- alias class;
- accessed extent;
- address space;
- synchronization scope;
- order;
- target memory model.

This precision permits unrelated atomic activity to remain independent.

---

## 4. Shared-memory race and synchronization rules

### 4.1 Non-atomic shared memory

Non-atomic memory may be shared only when conflicting accesses are ordered so that no data race exists.

The verifier MAY establish this using static ownership, provenance, agent topology, synchronization edges, region separation, or supplied proof facts.

When proof is unavailable, one of the following is required:

- use atomic operations;
- add explicit synchronization;
- provide a stronger verified ownership/separation fact;
- use an explicit raw/target operation with target-defined concurrent semantics.

There is no implicit "benign race" category.

### 4.2 Synchronization primitives above atomics

Mutexes, reader/writer locks, semaphores, condition variables, channels, barriers, once-initialization cells, queues, and similar abstractions are semantic libraries unless a target requires a primitive operation.

Their contracts MUST expose the behavior relevant to optimization and profiles, including as applicable:

- acquire/release edges;
- may-block status;
- progress class;
- fairness assumptions;
- possible spinning;
- retry bounds;
- scheduler or kernel interaction;
- priority effects;
- resource ownership transfer.

A library implementation may erase to atomics and ordinary control flow after specialization.

### 4.3 Progress properties

Concurrency operations and lowered sequences MAY expose `wait_free`, `lock_free`, `obstruction_free`, `blocking`, or `unknown` progress. This is a queryable property, not a promise inferred from an API name. A strict profile MAY reject unacceptable or unknown progress.

---

## 5. Threads, tasks, fibers, coroutines, actors, and schedulers

XAX has no mandatory thread or asynchronous runtime.

The following are libraries or semantic abstractions:

- threads;
- tasks;
- fibers;
- coroutines;
- actors;
- futures;
- executors;
- event loops;
- work-stealing pools;
- scheduler policies.

A platform package may supply operations such as creating an operating-system thread or submitting work to a device. Such operations are ordinary explicit calls or target/platform operations with declared effects and capabilities.

A program that uses none of these mechanisms links none of their machinery.

Coroutine specialization MAY lower to explicit state/control flow, but any storage, allocation, synchronization, or scheduling it requires MUST remain visible. Spawn/join abstractions MUST explicitly state their synchronization semantics.

---

## 6. Interrupt, fault, and target-trap handlers

### 6.1 Handler entry contracts

Interrupt, fault, and target-trap handlers are functions referenced by target/platform entry descriptors.

A conceptual entry descriptor contains:

```text
handler_entry {
    event_kind
    entry_abi
    privilege
    priority
    nesting_policy
    reentrancy_policy
    saved_machine_state
    allowed_effects
    stack_or_storage_contract
    return_or_resume_contract
}
```

These fields belong to the target/platform semantic package when hardware-specific.

A handler does not acquire a scheduler, heap, libc, exception runtime, or thread runtime merely because it is asynchronous.

### 6.2 Reentrancy

A handler contract MUST state whether the handler may:

- interrupt itself;
- be interrupted by higher-priority handlers;
- run concurrently on multiple agents;
- re-enter functions also reachable from ordinary execution.

Shared state accessed by handlers follows the same atomic and data-race rules as other concurrent state.

Disabling interrupts is not a universal language-level mutex. It has target-defined scope and effects and MUST be modeled as such.

### 6.3 Handler restrictions

Profiles or target contracts MAY reject from a handler:

- blocking operations;
- unbounded allocation;
- runtime-assisted atomics;
- non-reentrant library calls;
- scheduler interaction;
- kernel calls;
- floating-point or vector state usage requiring undeclared save/restore;
- excessive stack usage;
- priority inversion risks;
- unbounded interrupt masking.

A synchronous target fault or trap handler is not a XAX language exception. Its control behavior is defined by the target entry and resume/terminate contract.

---

## 7. SIMD and GPU parallelism boundary

`vec<N,T>` expresses vector values; it does not itself create concurrent execution agents.

SIMD instructions that operate on vector values are ordinary pure or memory operations unless a target contract states additional effects.

GPU and accelerator models may introduce lanes, waves/warps, workgroups, grids, specialized memory spaces, barriers, scoped atomics, and device synchronization. These belong in target/platform semantic packages and libraries rather than in a mandatory host runtime.

Portable atomic semantics apply only where a target can map their address-space and synchronization-scope contract correctly. Target-specific scopes form a declared scope relation or lattice. A verifier MUST reject an atomic or fence whose requested scope cannot be represented by the selected target.

Device launch, command submission, queue synchronization, or host/device transfer is effectful and MUST be explicit.

---

## 8. Real-time profile model

### 8.1 Profiles are rejection policies

A real-time profile is a set of predicates applied after specialization and again after target lowering when lowering can introduce latency-relevant machinery.

A conceptual profile is:

```text
realtime_profile {
    forbid_blocking
    forbid_unbounded_retry
    forbid_dynamic_allocation
    forbid_dynamic_initialization
    forbid_runtime_assist
    forbid_scheduler_interaction
    forbid_kernel_interaction
    forbid_unknown_external_calls
    require_bounded_stack
    require_bounded_recursion
    require_bounded_interrupt_mask
    require_known_progress
    accepted_effect_domains
    accepted_environment_assumptions
}
```

Profiles MAY add target-specific constraints.

A strict profile MUST reject a property that is required by policy but remains `unknown`. Unknown is not equivalent to safe.

### 8.2 Queryable latency-relevant properties

The compiler workspace MUST be able to query, at function, region, or operation granularity where meaningful:

| Property | Example result |
|---|---|
| `may_block` | `false` |
| `allocation` | `none`, `bounded(128)`, `unbounded`, `unknown` |
| `stack_upper_bound` | `384 bytes`, `unknown` |
| `recursion_bound` | `0`, `12`, `unknown` |
| `retry_bound` | `0`, `64`, `unbounded`, `unknown` |
| `progress` | `wait_free`, `lock_free`, `blocking`, `unknown` |
| `runtime_assist` | set of helper dependencies |
| `scheduler_interaction` | `none` or explicit operations |
| `kernel_interaction` | `none` or explicit operations |
| `dynamic_initialization` | `none` or explicit initializers |
| `interrupt_mask_bound` | target time/cycle bound or `unknown` |
| `external_latency` | declared environment dependency |
| `target_timing_bound` | proven bound or `unknown` |
| `target_cost_estimate` | model estimate with confidence/conditions |

These properties SHOULD be derived from the specialized graph and actual selected lowering, not only from high-level declarations.

### 8.3 Deterministic-latency admissibility

A deterministic-latency profile can require all execution paths relevant to its scope to have bounded:

- instruction/control-flow iterations;
- recursion;
- allocation behavior;
- synchronization retry;
- stack usage;
- interrupt-disabled duration;
- target helper calls;
- external service latency under explicit environment assumptions.

The profile MAY permit external interaction only when the environment contract supplies the required bound.

A profile does not guarantee a deadline from source simplicity. Cache, memory, bus, device, preemption, and platform timing effects require target/environment guarantees or accepted assumptions before they can support a hard bound.

---

## 9. Guarantees versus estimates

XAX distinguishes three classes of timing information:

| Class | Meaning | May support hard guarantee? |
|---|---|---:|
| semantic proof | proven from graph plus explicit assumptions | yes |
| target/platform contract | guaranteed by selected target/environment under stated conditions | yes |
| target cost estimate | predictive latency/throughput/energy model | no |

A cost model may estimate that an operation takes a number of cycles. That estimate is optimization data unless the target contract separately guarantees a bound.

The compiler MUST NOT relabel an estimate as a guarantee.

A hard real-time claim is valid only when every component required by the claim is either proven, guaranteed by a target/platform contract, or bounded by an explicit environment assumption accepted by the profile.

---

## 10. Invariants

1. No scheduler is mandatory.
2. No atomic operation silently introduces a lock or runtime helper.
3. Atomic ordering is explicit on every portable atomic operation.
4. Atomic width, alignment, address space, and scope are checked against target capabilities.
5. Non-atomic data races are invalid unless replaced by an explicit raw/target operation with defined concurrent semantics.
6. Data races never create implicit arbitrary compiler freedom.
7. Synchronization effects are explicit and SHOULD be represented with sufficient precision to avoid unnecessary global serialization.
8. Threads, tasks, fibers, coroutines, actors, futures, and event loops are optional libraries or semantic abstractions.
9. Interrupt and trap entry behavior is target/platform data, not hidden compiler convention.
10. Reentrancy and nesting assumptions affecting correctness are explicit.
11. SIMD value semantics do not imply a scheduler or agent model.
12. GPU/device scopes and execution topology are target capabilities.
13. Real-time profiles reject forbidden or unknown latency properties; they do not insert corrective runtimes.
14. Profile validation occurs after transformations that can materially change latency-relevant properties.
15. Target cost estimates are never hard guarantees.
16. Bare-metal programs can use atomics and interrupts without linking an operating-system or asynchronous runtime.

---

## 11. Rejected alternatives

### 11.1 Mandatory async runtime

Rejected because programs must not acquire scheduler or allocator machinery they did not request.

### 11.2 Language-defined thread object model

Rejected as fundamental semantics because operating systems, bare-metal targets, GPUs, and future machines expose different agents. Shared-memory ordering belongs in the kernel; agent creation belongs in platform semantics or libraries.

### 11.3 Sequential consistency for all atomics

Rejected because it destroys expressiveness and can impose unnecessary cost on weakly ordered machines. XAX instead records the required order exactly.

### 11.4 `volatile` as synchronization

Rejected. Device visibility, compiler observability, and inter-agent synchronization are different semantics. MMIO belongs to target memory/effect contracts; inter-agent synchronization uses atomics, fences, or explicit primitives.

### 11.5 Silent lock-based emulation of unsupported atomics

Rejected because it introduces hidden synchronization, possible blocking, storage, priority effects, and nondeterministic latency.

### 11.6 Undefined behavior from ordinary data races

Rejected as an implicit semantic hole. Intentional racy machine behavior must be selected explicitly through operations whose allowed outcomes are defined.

### 11.7 Global atomic effect token

Rejected as the default representation because unrelated atomic locations and scopes need not serialize. Dependencies should follow aliasing and synchronization requirements.

### 11.8 Real-time as an optimization hint

Rejected. A real-time profile is an admissibility policy. If required bounds or exclusions cannot be established, compilation under that profile fails.

### 11.9 WCET inferred from generic cost estimates

Rejected. Expected or modeled cost is not a proof of worst-case latency.

---

## 12. Interfaces with other XAX subsystems

### 12.1 Type and layout system

Atomic operations depend on exact value width, alignment, address space, and pointer provenance. Layout decisions can therefore change atomic legality and must be visible before final verification.

### 12.2 Memory and ownership

Ownership/separation proofs can establish that non-atomic accesses cannot race. Transfer of a linear resource between agents must be represented by explicit ownership transfer and synchronization where required.

### 12.3 Effects

Atomic, memory, device, syscall, time, network, and privileged effects interact with concurrency and real-time profiles. Effects are not merely documentation; they participate in dependency and admissibility analysis.

### 12.4 Calls and errors

A call cannot secretly add blocking, synchronization, exception edges, runtime assistance, or scheduler interaction. Such properties are part of the callee contract or discovered specialization/lowering summary.

### 12.5 Compile-time specialization

Concurrency abstractions may specialize away. Profile analysis SHOULD operate on specialized graphs so erased abstractions do not falsely count as runtime cost.

### 12.6 Target packages

Target packages define atomic capabilities, memory spaces, synchronization scopes, machine fences, interrupt entry rules, lowering sequences, timing contracts, and relevant cost information.

### 12.7 Optimizer

Optimizations MUST preserve the atomic memory model and handler contracts. They MAY remove or weaken synchronization only with proof that observable behavior is unchanged. They MUST update latency-relevant summaries after transformations.

### 12.8 AI semantic workspace

The workspace SHOULD support compact queries for atomic capability, race neighborhoods, synchronization predecessors, handler reentrancy, latency properties, and profile violations. Diagnostics SHOULD identify the violating entity, required and observed properties, dependencies, and repair neighborhood.

---

## 13. Open issues requiring implementation evidence

### 13.1 Portable synthesis threshold for non-native atomics

The capability model permits bounded inline sequences and runtime assistance, but the default policy for when the compiler should synthesize a non-native atomic versus require an explicit library/target operation should be fixed only after code-size, correctness, and target-diversity evidence exists.

### 13.2 Timing-proof representation granularity

The architecture requires a strict separation between guarantees and estimates, but the most compact persistent representation for path bounds, microarchitectural assumptions, and derived timing proofs should be selected after at least two substantially different target models are implemented.

### 13.3 GPU synchronization-scope normalization

Target-defined scope relations are required. Whether a small portable canonical subset can cover major GPU and accelerator models without semantic loss should be decided from actual target-package experiments rather than assumed in advance.

---

## 14. Falsification criteria

This design must be reconsidered if later implementation or measurement demonstrates any of the following:

1. The five portable memory orders cannot be lowered correctly across selected weak-memory CPU targets without requiring frequent target-specific fundamental semantic escape hatches.
2. The target capability schema cannot describe important CPU, GPU, accelerator, or device atomic behavior without proliferating incompatible core operations.
3. Precise atomic effects provide no meaningful optimization benefit relative to a global atomic chain while materially increasing verification or AI mutation cost.
4. The explicit data-race rule forces most practical low-level shared-memory code into raw target operations because normal proofs cannot be represented compactly enough.
5. Post-lowering profile verification repeatedly fails to detect hidden blocking, runtime assistance, retry loops, kernel interaction, or other latency hazards introduced by the backend.
6. Static latency-property queries cannot be maintained incrementally after ordinary graph mutations and optimization.
7. The distinction between target guarantees and estimates proves too weak to prevent unsound hard-real-time conclusions.
8. Interrupt and reentrancy contracts cannot represent at least two substantially different bare-metal interrupt architectures without changing fundamental XAX semantics.
9. GPU synchronization scopes require core-language assumptions tied to one vendor or execution topology.
10. Real-time profile checking produces so many unavoidable `unknown` results that strict profiles are unusable even for intentionally bounded bare-metal programs.
11. Supporting ordinary atomics requires a mandatory runtime on targets where native hardware support should be sufficient.
12. Generated machine code under a profile violates a property that the compiler reported as proven. Such a failure is a verifier, lowering-contract, or proof-model defect and invalidates the affected guarantee until corrected.

The stage is successful only if concurrency remains exact and low-level, higher-level scheduling remains optional, target diversity does not leak into mandatory language runtime semantics, and latency-sensitive builds can mechanically reject behavior that their declared policy does not permit.
