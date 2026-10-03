# XAX Target Model

## 1. Purpose and scope

This document defines the canonical XAX model for describing machines and code-emission constraints without adding architecture-specific rules to fundamental XAX semantics.

A target is a content-addressed XAX semantic package containing the facts required to verify target-dependent operations, legalize graphs, select and schedule instructions, allocate registers, encode bytes, relocate references, and emit raw images, objects, or executables. It may describe CPUs, microcontrollers, DSPs, GPUs, accelerators, virtual machines, heterogeneous systems, or future hardware.

The core language MUST NOT privilege any ISA, operating system, ABI, object format, accelerator model, or vendor convention. New hardware SHOULD require new target/platform packages rather than changes to the semantic kernel.

“Universal targeting” means the model can describe target-relevant facts and compilation either finds a semantics-preserving lowering or fails explicitly. It does not mean every program runs on every target.

## 2. Normative definitions

The terms **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** are normative.

| Term | Definition |
|---|---|
| **Target package** | A content-addressed XAX module graph describing one machine family or a precisely delimited target configuration. |
| **Target revision** | The exact immutable content identity of a target package. |
| **Logical target identity** | A stable package identity used to express lineage across compatible or successive revisions. It is not a substitute for exact content identity. |
| **Target configuration** | A target revision plus selected capabilities, ABI/platform profile, object or image profile, and compilation policy inputs. |
| **Capability** | A machine-verifiable fact asserting that a target can realize a defined semantic requirement under stated constraints. |
| **Machine value type** | A target-defined value representation that can participate in machine operations, registers, memory, or instruction encodings. |
| **Physical register** | A named target storage location with explicit overlap and allocation relationships. |
| **Register unit** | The smallest target-described allocation-conflict unit used to model overlapping registers and subregisters. |
| **Register class** | A target-defined set or predicate over legal physical registers for an operand or result. |
| **Target operation** | A target-dependent semantic operation whose contract is supplied by the target package. |
| **Instruction definition** | A target object describing operands, results, constraints, semantics, encoding, and optional scheduling metadata for one encodable machine operation. |
| **Semantic contract** | The target-supplied description of observable behavior required for verification and semantics-preserving transformation. |
| **Legalization** | A semantics-preserving replacement that converts unsupported semantic structures into structures legal for the selected target configuration. |
| **Instruction selection** | The process of choosing target operations or instruction definitions that realize an already-defined semantic contract. |
| **Opaque target operation** | A target operation for which complete mathematical semantics are unavailable or intentionally undisclosed, but whose effects, control behavior, memory behavior, constraints, and optimization barriers are explicitly described. |
| **Platform profile** | A target-associated semantic package describing ABI, calling convention, image/object format, runtime-entry conventions, or other environment-specific facts. |
| **Cost metadata** | Non-semantic target data used to estimate latency, throughput, code size, energy, pressure, or other optimization objectives. |

Exact target revision identity is authoritative. Human-readable architecture names and version strings MAY exist as metadata, but MUST NOT determine semantic identity.

## 3. Target package model

A target package is an immutable XAX semantic graph. Conceptually it contains:

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

This notation is diagnostic only. The canonical representation is the XAX semantic graph.

### 3.1 Identity, revisions, and configuration

`revision_identity` MUST derive from canonical content identity; any semantic change creates a new revision. `logical_identity` MAY connect revisions in one lineage, but compatibility MUST be explicit rather than inferred from names.

Before target-dependent verification or final lowering, a build MUST resolve an exact configuration identifying the target revision, optional capabilities, required ABI/platform profile, image/object profile, legality-changing target parameters, and any policy permitting emulation or runtime support.

Configurations that differ in legality, ABI behavior, encoding, memory semantics, or observable execution are distinct.

### 3.2 Capabilities

Capabilities are semantic facts, not marketing feature strings. A capability MUST have a stable semantic identity and enough structure to answer legality queries.

Examples include:

```text
atomic.rmw(width=64, space=global, order=acq_rel)
vector(width=256, element=bits<32>)
predication(lanes=32, mask=target_predicate)
memory.space(shared, address_bits=32)
trap.precise
interrupt.entry(profile=P7)
```

A capability MAY be conditional on other target facts. Capability predicates MUST be machine-evaluable XAX semantics rather than free-form text.

The absence of a capability means “not proven available”. Compilation MUST NOT assume unlisted capabilities.

## 4. Machine value types

A target package MUST describe every machine value type required by its instruction definitions and calling conventions.

A machine value type MAY state bit/storage width, lanes, floating-point format, predicate representation, storage legality, legal alignments, register classes, conversions, and opaque target identity. Signedness SHOULD remain an operation property unless the physical representation distinguishes it.

Machine types do not replace XAX core types; they describe lowered representations. A core value may map to different machine types by context, but lowering MUST NOT silently change rounding, saturation, truncation, lane order, exceptional-value behavior, or other semantics.

## 5. Memory-space model

Every addressable memory space used by a target MUST be explicit.

A memory-space description MUST be able to state:

| Property | Required meaning |
|---|---|
| identity | Stable semantic identity of the address space. |
| address width | Number of address bits or target-defined address representation. |
| address unit | Smallest addressable unit. |
| endianness | Byte or unit ordering where applicable. |
| alignment rules | Legal and preferred alignment constraints. |
| access widths | Legal load/store widths and composition rules. |
| volatility/device behavior | Whether accesses have externally observable device semantics. |
| coherence domain | Which agents observe coherent memory and under what rules. |
| atomic support | Supported widths, orderings, scopes, and operation families. |
| visibility/scope | Agent, core, subgroup, device, system, or target-defined visibility relationships. |
| pointer compatibility | Legal conversions or explicit prohibition between spaces. |

Different memory spaces MUST NOT be merged merely because they use the same numeric address width.

Cross-space conversion MUST be an explicit operation or proven identity conversion. Heterogeneous targets MAY define global, local, shared, private, device, host, constant, descriptor, scratch, or other spaces without requiring changes to XAX core semantics.

Endianness is a property of relevant memory and encoding behavior, not a global assumption of the XAX language.

## 6. Register model

Targets MUST be able to describe irregular, overlapping, banked, aliased, fixed-purpose, and partially addressable register files.

Each physical register references one or more register units. Two physical registers conflict for allocation when their unit sets overlap unless the target package explicitly supplies a narrower coexistence rule.

A physical register MAY describe units, bit/lane coverage, subregister relations, encodable number, supported machine types, reserved or privileged status, ABI save/restore class, and implicit uses/clobbers.

Register classes MUST be semantic sets or predicates, not strings. Instruction constraints MAY require fixed, paired, disjoint, tied, early-clobber, consecutive, banked, aligned, or other target-defined register relations. The allocator MUST determine conflicts from target data without hardcoded register knowledge.

## 7. Instruction definitions and encodings

An instruction definition MUST identify:

```text
Instruction {
  semantic_identity
  operands
  results
  operand_constraints
  result_constraints
  implicit_uses
  implicit_defs
  semantic_contract
  encoding
  control_behavior
  effects
  trap_behavior
  optional_cost_metadata
}
```

Operands and results MUST specify machine value and allocation constraints. Immediates MUST define legal ranges, transformations, relocation eligibility, and encoding restrictions.

Encoding MUST be deterministic for a fixed instruction, encoding variant, and layout/relocation context, and the encoding logic itself is XAX semantics. Fixed fields, transformed operands, variable-length forms, prefixes, bundles, and packets are permitted. Layout-dependent bits MUST produce defined relocations or fixups rather than guessed addresses.

Encoding aliases MAY exist, but semantic identity MUST remain unambiguous.

## 8. Instruction semantic contracts

The semantic contract is the authority for what an instruction or target operation means.

Where practical, contracts SHOULD use ordinary XAX semantic computation over values, memory, effects, and control, and MAY call target-defined semantic functions. They can describe computation, memory access, ordering, atomicity, control transfer, traps, privilege, resources, and target-visible state. Semantic behavior MUST remain separate from cost metadata.

### 8.1 Opaque operations

Some future or proprietary operations may not have a useful complete mathematical model. Such operations MAY be opaque, but opacity does not permit unspecified effects.

An opaque target operation MUST declare at least:

- input and output types;
- consumed and produced resources, if any;
- effect domains;
- memory spaces and access classes it may touch;
- ordering relationships;
- whether it may trap, branch, block, synchronize, or terminate;
- privilege or execution-state requirements;
- aliasing and visibility constraints required for soundness;
- the narrowest optimization barrier that preserves correctness.

The compiler MUST treat unmodeled behavior conservatively. A target package SHOULD prefer narrow barriers over a global “unknown side effects” barrier when the machine contract permits it.

If the available contract is insufficient to preserve observable semantics, the operation is not legal for verified compilation.

## 9. Atomics, vectors, predication, privilege, traps, and interrupts

These facilities are target-described capabilities, not fixed architecture assumptions.

### 9.1 Atomics

Atomic capabilities MUST identify operation family, width, memory space, ordering modes, synchronization scope, alignment requirements, and failure semantics where applicable.

If a core atomic requirement is unsupported, legalization MAY use a semantics-preserving alternative only when the selected build policy permits any required runtime, lock, trap, or privileged mechanism. Otherwise compilation MUST fail.

### 9.2 Vectors and predication

Vector descriptions MUST distinguish representation from operation semantics. Targets MAY support fixed-width vectors, scalable vectors, lane groups, subgroups, warps, wavefront-like execution, or other target-defined execution structures.

Predicated operations MUST define inactive-lane behavior, mask representation, side-effect suppression rules, and fault behavior. “Masked off” MUST NOT implicitly mean “no observable effect” unless the contract states it.

### 9.3 Privilege, traps, and interrupts

Privilege-sensitive operations MUST carry explicit privilege requirements and effects.

Trap descriptions MUST define whether the trap is precise, resumable, synchronous, asynchronous, target-defined, or fatal with respect to the current profile.

Interrupt entry and return behavior belong to target/platform profiles. An interrupt handler profile MAY define register state, stack behavior, preserved resources, masking state, vector identity, and return protocol. Core XAX does not assume that interrupts, exceptions, or an operating system exist.

## 10. Legalization and lowering

Legalization rules are XAX semantic objects and XAX computations. There is no separate rewrite DSL.

Conceptually:

```text
LegalizationRule {
  source_predicate
  target_capability_predicate
  replacement_constructor
  semantic_relation
  applicability_constraints
  phase_constraints
}
```

A legalization rule MUST preserve observable source semantics. It MAY split values, synthesize control flow, expand vectors, call explicitly selected runtime/library facilities, or substitute equivalent target primitives.

It MUST NOT introduce hidden allocation, synchronization, syscalls, scheduler interaction, ownership transfer, or exception behavior. Required runtime behavior must already be permitted and remain explicit.

The package MUST expose a legality predicate sufficient to decide when lowering is complete and SHOULD support a well-founded measure or phase discipline so cycles can be detected.

## 11. Instruction selection constraints

Instruction selection MUST be constrained by semantic equivalence and target legality before cost.

Selection rules MAY account for:

- machine value types;
- constant ranges;
- addressing forms;
- immediate encodability;
- register classes;
- fixed, tied, or early-clobber registers;
- memory-space identity;
- alignment;
- predication;
- atomic scope/order;
- control-flow placement;
- neighboring target operations;
- bundling or packet constraints.

Constraint predicates MUST be semantic data, not embedded parser strings.

A target MAY expose multiple instruction sequences for the same semantic requirement. The compiler may choose among them using selected cost objectives, but cost MUST NOT justify semantic weakening.

## 12. Scheduling and cost metadata

Scheduling metadata is advisory non-semantic information.

A target package MAY describe latency, throughput, issue width, execution resources, occupancy, hazards, bundling, serialization, branch/memory penalties, code size, energy, and register-pressure contribution.

Costs may be unknown or profile-dependent; missing data MUST NOT mean zero. Dynamic measurements are compilation inputs, not program meaning, unless intentionally published as a new immutable model revision. A compiler MAY ignore cost metadata, but MUST NOT ignore correctness hazards.

## 13. Calling conventions and ABI profiles

Calling conventions are target/platform semantic objects. They MUST be able to define argument/result assignment, register preservation, stack/frame rules, alignment, aggregate and variadic behavior, required hidden ABI state, selected unwind/foreign-exception interoperability, entry/exit state, and call-clobbered resources.

No calling convention is fundamental XAX semantics. Foreign interoperability behavior belongs to the selected profile and MUST remain explicit at the boundary.

## 14. Relocations, object formats, and executable formats

Object and executable knowledge is supplied through target/platform packages.

A relocation kind MUST define its symbolic relation, field placement, bit interpretation, addend behavior, range/alignment constraints, overflow behavior, and resolution stage.

Image/object profiles MAY define sections, segments, symbols, alignment, fixups, metadata, entry points, checksums, signing hooks, and loader-facing structures. These are XAX semantic definitions, not a second linker/object DSL. Bare-metal targets MAY emit raw images and omit relocation or loader machinery when unnecessary.

## 15. GPU, accelerator, and heterogeneous-machine support

The target model MUST not assume a single scalar CPU.

A heterogeneous package MAY describe multiple engines and memory domains. It MUST make explicit engine eligibility, legal value/register types, accessible spaces, synchronization and coherence, transfers/mappings, launch requirements, and resources such as queues, descriptors, DMA channels, or accelerator handles.

Execution topology MAY be modeled where semantics or legality require it. Host-to-accelerator launch need not be fundamental; target operations, resources, or libraries may express it. Allocation, queueing, synchronization, mapping, and transfer remain visible.

For DMA buffers, packages SHOULD reuse the common resource-state vocabulary `host-unmapped`, `host-mapped`, `host-dirty`, `device-owned`, `device-pending`, and `host-stale` when those meanings apply. The states remain ordinary `resource<K,state>` values. `device-pending` prevents host reacquire until an explicit synchronizing operation returns the resource to `device-owned`; `host-dirty` and `host-stale` make non-coherent clean/invalidate requirements explicit. Coherent shared-memory packages MAY omit dirty/stale states and cache-maintenance operations when the package contract establishes coherence. Address spaces, pinning/IOMMU details, legal state transitions, scopes, and lowering remain package data rather than a universal device framework.

## 16. Universal-portability criterion and failure behavior

A program is **portable to a target configuration** when, after allowed specialization, every surviving semantic requirement has:

1. a legal representation on that target;
2. a semantics-preserving lowering path;
3. satisfiable memory, register, atomic, privilege, and control constraints;
4. any required calling convention and emission support;
5. no unresolved target operation whose contract is insufficient for verification.

Portability is therefore proven per program and target configuration, not declared by architecture family name.

Compilation MUST fail explicitly when a required capability is absent and no permitted semantics-preserving legalization exists.

A failure diagnostic SHOULD identify:

```text
required_semantics
failing_entity
target_configuration
missing_capability
attempted_legalization_set
blocking_constraints
repair_neighborhood
```

The compiler MUST NOT silently substitute weaker atomic ordering, different floating-point behavior, reduced address width, host emulation, hidden runtime calls, or other changed semantics.

Optional emulation is legal only when its observable behavior matches the source requirement and any introduced runtime/resource behavior is explicitly permitted by the program and build policy.

## 17. Invariants

The following invariants are normative:

1. Core XAX semantics contain no hardcoded ISA, operating system, ABI, object format, or accelerator family.
2. Exact target revision identity is content-based and immutable.
3. Target-dependent behavior is represented by target semantic objects or target operations with explicit contracts.
4. No target rule may introduce hidden runtime behavior.
5. Machine legality and semantic correctness precede cost optimization.
6. Register overlap and allocation constraints are target data, not compiler hardcoding.
7. Address spaces are explicit and are never merged solely because their numeric representation matches.
8. Encodings and relocations are deterministic under a fixed target configuration and layout context.
9. Incomplete target semantics require conservative explicit barriers; unspecified effects are not permitted.
10. Cost metadata is non-semantic.
11. Unsupported capabilities cause explicit failure unless an explicitly permitted equivalent legalization exists.
12. New hardware SHOULD be describable by new target/platform packages without changing the fundamental XAX language.
13. Target packages, legalizers, encoders, and format logic use XAX semantics rather than a permanently maintained second DSL.
14. A target package may be minimal. It need only describe features required by the programs and emission modes it claims to support.

## 18. Rejected alternatives

| Alternative | Rejection |
|---|---|
| Hardcode major ISAs in the compiler core | Violates universal targeting and makes future hardware require compiler-language changes. |
| Maintain a separate target-description DSL | Creates a second language, parser, semantics, tooling path, and long-term maintenance burden. |
| Use human-readable constraint strings | Makes legality parser-dependent, weakly typed, and difficult for machine verification. |
| Treat unknown instructions as arbitrary side effects | Preserves too little information for optimization and may still be unsound if control, memory, or privilege behavior is omitted. |
| Require complete mathematical semantics for every instruction | Excludes proprietary, stateful, analog-adjacent, or otherwise difficult hardware operations that can still be compiled soundly with explicit conservative contracts. |
| Model all memory as one flat address space | Fails for accelerators, devices, Harvard-like machines, capability memories, and heterogeneous coherence. |
| Encode signedness into every integer machine value type | Reintroduces interpretation that is more precisely attached to operations. |
| Make one universal ABI part of XAX | Prevents accurate interoperability and bare-metal targets and would embed platform policy into core semantics. |
| Implicitly emulate missing features | Can add allocations, locks, calls, traps, or changed timing and therefore violates explicit-semantics rules. |
| Make scheduler cost data semantic | Would make program meaning depend on microarchitectural estimates and measured performance. |
| Promise every program is portable | Confuses target describability with capability availability and would require silent semantic degradation. |

## 19. Interfaces and dependencies

### 19.1 Canonical semantic graph

Target packages are ordinary semantic objects referenced by content identity. Target operations, legalizations, instruction definitions, and encoding objects therefore participate in canonical identity and versioning like other immutable XAX objects.

### 19.2 Type and value system

Core XAX types describe program semantics. Machine value types describe legal lowered representations. The lowering boundary must preserve exact value behavior or expose the operation that changes it.

### 19.3 Memory and pointer semantics

Pointer provenance, bounds, permissions, alignment, address space, and alias information constrain target lowering. A target may refine these facts but may not silently discard proof obligations needed for correctness.

### 19.4 Effects and resources

Target operations use the same explicit effect and resource principles as the rest of XAX. Device state, DMA channels, queues, privileged handles, or execution resources that require lifetime control may be represented as resources.

### 19.5 Concurrency and atomics

Target atomic capabilities determine which source atomic contracts are directly legal. Unsupported contracts require explicit legalization or failure.

### 19.6 Compile-time execution and metaprogramming

Target package construction, capability queries, legalization selection, encoding generation, and format construction may use compile-time XAX execution. This does not create a macro or target DSL.

### 19.7 Compiler pipeline

The target model participates in verification, specialization, optimization, target lowering, scheduling, register allocation, machine optimization, encoding, and emission. Earlier stages may query target facts where legality or specialization requires them, but target policy must not alter source meaning.

### 19.8 AI workspace and diagnostics

The semantic workspace should expose compact local handles for target entities and machine-readable capability/legality queries. AI agents should request only the relevant target neighborhood rather than ingesting an entire target package.

## 20. Open issues requiring implementation evidence

Only the following issues remain intentionally open:

1. **Granularity of semantic instruction models.** Some targets may be best modeled per instruction, while others may benefit from shared semantic primitives plus encoding variants. The choice should be measured against verifier complexity, target-package size, optimization quality, and AI token cost.
2. **Cost-model representation.** Static tables, symbolic models, profile-conditioned functions, or combinations may differ materially in accuracy and compilation cost. The semantic/non-semantic boundary is fixed; the most effective representation is not.
3. **Legalization search discipline.** Rule ranking, bounded search, equality saturation, staged rewriting, or hybrid approaches may be appropriate. The required properties are semantic preservation, explicit failure, and detectable nontermination/cycles.
4. **Opaque-contract minimums by hardware class.** The general minimum contract is defined above, but practical compiler validation may show that some device classes require additional mandatory fields to avoid excessive global barriers.
5. **Scheduling-resource detail.** Micro-operation-level models may improve code quality but increase package size and maintenance cost. The necessary granularity must be determined experimentally.

These are implementation-design questions, not permission to weaken the invariants of this document.

## 21. Falsification criteria

This design should be revised if implementation or benchmarking demonstrates any of the following:

1. Supporting a substantially new machine class repeatedly requires adding architecture-specific concepts to fundamental XAX semantics rather than target/platform packages.
2. Common register files, overlapping subregisters, bank constraints, or accelerator register structures cannot be represented without compiler hardcoding.
3. Target instruction semantics cannot express enough behavior for sound optimization while opaque contracts remain so conservative that useful optimization collapses.
4. The legalization model cannot reliably detect unsupported semantics, cycles, or incomplete lowering.
5. Deterministic instruction encoding or relocation emission requires an external target language because XAX semantic computation is impractically large, slow, or ambiguous.
6. Target package size or query cost makes local AI target interaction materially worse than architecture-specific compiler interfaces.
7. Capability-based portability checks produce frequent unsound acceptance or excessive false rejection on real targets.
8. Heterogeneous memory, synchronization, execution topology, or transfer semantics require a fixed GPU/accelerator model in core XAX.
9. Separating semantic contracts from cost metadata prevents the compiler from expressing correctness-critical scheduling hazards; such hazards would need to be reclassified as semantic constraints rather than cost data.
10. Cost metadata is too inaccurate or expensive to improve instruction selection and scheduling compared with simpler machine models.
11. A future instruction with only partial semantics cannot be compiled soundly without either modifying core XAX or granting an unbounded “unknown behavior” escape hatch.
12. Exact target revisioning and configuration identity are insufficient to reproduce legality and encoding decisions across compiler sessions.

Passing these tests does not establish that the design is optimal. It establishes only that the target model remains consistent with XAX’s central requirement: machine-specific knowledge can evolve independently while program meaning remains explicit, verifiable, and target-agnostic at the fundamental language level.

---

## 22. Android arm64-v8a shared-library target (2026-10-01)

The prototype now contains one hosted Android target package:

```
android-arm64-v8a-shared-v3
architecture = AArch64
ABI          = Android AAPCS64 C
image        = ELF64 ET_DYN
page align   = 0x4000
```

This target reuses the existing register-resident AArch64 lowerer. It does not
fork instruction selection or register allocation. Android-specific behavior is
restricted to the target/package ABI contracts and ELF emission layer.

The target adds only bounded operations needed by the current ABI/platform
fixtures: fixed-offset borrowed-table loads, function-address formation, bounded
indirect calls, and explicitly declared foreign calls. The v3 package includes
the Android public JNI 1.6 `JNIInvokeInterface` slots 3..7 and
`JNINativeInterface` callable slots 4..232 as fixed-offset function-pointer
loads. Their signatures are not encoded as architecture opcodes; they remain
explicit bounded `CallContract` objects in the JNI platform package.

Borrowed opaque pointers, identity-qualified ABI pointers, and function pointers
are ordinary machine-pointer carriers; they do not create local-stack provenance
or ownership. Acquired JNI local/global/weak-global references use separate
linear owner proof values, erased at the machine ABI, which typed JNI contracts
thread until explicit release. For bounded mixed `jvalue[]` construction, the
package additionally defines explicit strong-reference-to-64-bit ABI projection
operations. Borrowed last-use projection may erase to zero instructions; local
and global forms thread the matching linear owner proof unchanged. This target
operation is not a general core pointer cast. A local `STACK_ALLOC` pointer that
crosses an indirect call still must carry its exact owner/effect proof through
the bounded CallContract.

Local XAX calls are resolved to direct `BL` branches. Local function addresses
use PC-relative address formation. Referenced foreign functions use a local
AArch64 GOT thunk and one dynamic `R_AARCH64_GLOB_DAT` relocation per imported
symbol; no PLT is emitted by the bounded prototype. If a module has no foreign
imports it has no dynamic relocations or `DT_NEEDED` entries.

The emitter is intentionally not a general ELF linker. Unsupported reach,
relocation, or ABI cases fail explicitly rather than introducing a runtime
helper or silently changing semantics.

## 23. Architectures 5 and 6: the JVM and RISC-V (2026-10-03)

The target decoder knows six architectures: 1 x86-64, 2 wasm32, 3 AArch64, 4 the SIMT accelerator packet, 5 the JVM (ADR-112), and 6 RISC-V RV64 (ADR-113). Architectures 5 and 6 carry no register lists, because their convention is fixed by the identity (as for wasm32). Each accepts exactly one machine tuple. Adding them required no new operation, type form, or terminator. A package states its operation set, and every backend rejects operations outside it, so the JVM and RISC-V can each start with a subset and grow independently.

