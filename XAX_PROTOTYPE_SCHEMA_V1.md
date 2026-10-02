# XAX Prototype Object Schema Revision 1

Status: implementation fixture schema for Roadmap M1. This document fixes the bytes tested by the bootstrap compiler. It does not close evidence-dependent objectization issues or extend the normative language specification.

## 1. Common encoding

All integers are minimal ULEB128. A `ref` is a minimal ULEB128 index into the enclosing object's CID-sorted, duplicate-free direct-reference table. A `bytes` field is `length || raw_bytes`. Lists are `count || elements`.

Every object uses schema version 1 and the envelope defined by `XAX_SPEC.md` §9.4. CID input encodes `kind_id`, `schema_version`, `reference_table`, and `body_length` exactly as their canonical bytes.

Container index `file_offset` points to the record-length prefix. Index `record_length` repeats the envelope payload length, excluding its own ULEB128 prefix.

Prototype non-semantic records are opaque tooling records:

```text
record_length
tooling_schema_id
payload_length
payload
```

They are sorted and deduplicated by complete canonical record bytes. They do not affect semantic CIDs or root identity, but they do affect container bytes and the whole-store digest.

## 2. Object bodies

### Kind 1: `program_root`

```text
module_count
module_ref[module_count]
```

References are modules only. Body refs MUST be `0..reference_count-1`; module order is CID order and has no source-order meaning.

### Kind 2: `module`

```text
member_count
member_ref[member_count]
```

Members may be types, constants, standalone functions, targets, recursion groups, or call contracts. Body refs MUST be `0..reference_count-1`; member order is CID order.

### Kind 3: `function`

```text
graph_ref
parameter_count
parameter_type_ref[parameter_count]
return_count
return_type_ref[return_count]
```

`graph_ref` names one kind-7 graph fragment. Type refs name kind-4 objects. Entry block parameters and every return terminator MUST match the interface exactly. A standalone function graph MUST NOT contain a group-local call.

### Kind 4: `type`

Prototype revision 1 supports these initial forms:

```text
form = 1
bit_width
```

`bit_width` MUST be positive. Form 1 means `bits<N>`.

```text
form = 2
address_space = 1
element_type_ref
permission
alignment
```

Form 2 means `ptr<address-space,T,permission,alignment>`. Address-space 1 is stack/local memory; other positive spaces are target/platform-defined and do not acquire local provenance merely from their type. The element MAY be a scalar value type, another pointer type, or an opaque ABI carrier (`opaque<K>` / form-6 identity-qualified opaque type). Portable bounded memory load/store currently support whole-byte integer and binary32/binary64 scalar elements; opaque-element pointers are foreign/platform carriers and gain no local provenance merely from their type. Permission IDs are 1 = read, 2 = write, and 3 = read-write. Alignment MUST be a positive power of two.

```text
form = 3
domain
[instance when nonzero]
```

Form 3 means `effect<domain,instance>`. Domain IDs are 1 memory, 2 I/O, 3 syscall, 4 device, 5 filesystem, 6 network, 7 time, 8 random, 9 privileged, 10 unsafe, and 11 atomic. The omitted instance is zero, preserving the original `effect<memory>` bytes. Effects are ordering frontiers, not authority capabilities.

```text
form = 4
resource_kind
state
[flags || instance || transition_count || transition_state[...] for the general form]
```

Form 4 represents `resource<kind,state,flags,instance>`. Flag bits are 1 affine, 2 partitionable, 4 releasable, and 8 acquirable; zero is strictly linear. Transition states are sorted, duplicate-free, positive, and distinct from the current state. The short two-field encoding remains exactly the initial releasable `resource<stack-storage,live>` owner capability. Resources are distinct from pointer views and effect frontiers.

```text
form = 5
opaque_kind
```

Form 5 represents compile-time/tooling semantic handles `opaque<K>`. Opaque-kind IDs are 1 type, 2 constant, 3 function, 4 target, 5 graph, 6 generic semantic object, and 7 byte sequence. Values of form-5 opaque types are compile-time evaluator values and do not introduce a human source language or mandatory runtime representation. `opaque<object>` can carry any verified semantic object; `opaque<bytes>` carries deterministic byte output such as a canonical semantic image.

```text
form = 6
identity_bytes
```

Form 6 represents an identity-qualified opaque ABI/platform carrier. The identity byte string MUST be non-empty and is part of canonical type identity. Form 6 has no references and defines no implicit layout, ownership, provenance, allocation, or runtime behavior. A platform/ABI contract must supply those facts.

```text
form = 7
float_format
```

Form 7 is a scalar IEEE floating-point value. Format IDs are 1 = binary32 and 2 = binary64.

```text
form = 8
element_count
element_type_ref[element_count]
```

Form 8 is a positional product/tuple. Struct field names are tooling metadata and do not alter product type identity.

```text
form = 9
element_type_ref
element_count
```

Form 9 is a fixed-size homogeneous array.

```text
form = 10
variant_count
variant_type_ref[variant_count]
```

Form 10 is a tagged sum. Variant order is semantic and the count MUST be positive. Forms 1–10 are canonical type objects.

### Kind 5: `constant`

```text
type_ref
value_bytes
```

The type MUST be `bits<N>` or a form-7 float. Integer value bytes are little-endian, exactly `ceil(N/8)` bytes, with unused high bits zero. Float value bytes use canonical IEEE binary32/binary64 bits; NaNs use the canonical quiet-NaN representation.

### Kind 6: `target`

```text
identity_bytes
```

Identity MUST be nonempty. An identity-only object remains the M1 serialization carrier and cannot drive native compilation.

The current x86-64 native profile appends:

```text
profile_version = 2
architecture = 1                 # x86-64
abi = 1                          # Windows x64
image_format = 1                 # raw callable load image
word_bits = 64
pointer_bits = 64
stack_alignment = 16
shadow_space = 32
argument_register_count = 4
argument_registers = [RCX, RDX, R8, R9]
result_register = RAX
scratch_register_count = 2
scratch_registers = [R10, R11]
supported_operation_count
supported_operation_id[...]
supported_terminator_count
supported_terminator_id[...]
atomic_width_count = 2
atomic_widths = [32, 64]
atomic_scope_count = 1
atomic_scopes = [system]
atomic_family_count = 5
atomic_families = [load, store, rmw, cmpxchg, fence]
handler_entry_count = 1
handler_entry[0] = {
    event_kind,
    entry_abi,
    privilege,
    priority,
    nesting_policy,
    reentrancy_policy,
    saved_machine_state,
    allowed_effect_domain_count,
    allowed_effect_domains,
    stack_bound,
    return_contract
}
```

Register IDs are x86-64 encoding numbers. Operation, terminator, atomic capability, allowed-effect, and handler-event lists MUST be sorted and duplicate-free. The current M8 target CID is:

```text
24e312c773b777ac4dd892b39a9477f1758ff8bf05d7708bfb8282120a9ded56
```

This is the minimum exact package for the bootstrap raw-image/atomic backend. Instruction encoding and numeric handler-policy vocabularies remain removable Python bootstrap code; the profile does not claim a complete target-package schema or close OI-11, OI-12, or OI-16.

The second executable profile uses the same common prefix and replaces the x86-specific ABI fields with:

```text
profile_version = 1
architecture = 2                 # WebAssembly core
abi = 2                          # direct core-function ABI
image_format = 2                 # WebAssembly core module
word_bits = 64                   # maximum scalar width
pointer_bits = 32                # linear-memory address width
supported_operation_count
supported_operation_id[...]
supported_terminator_count
supported_terminator_id[...]
```

It has no register, shadow-space, or native stack-alignment fields. Its target CID is:

```text
946143a04b0b1ba8ed7312af6c85f70cbb4f71644fb20f7aea3be8ed06da41ed
```

The emitted module has no imports. Node/V8 is an execution harness, not XAX source or an emitted runtime dependency. This profile provides a materially different stack-machine/linear-memory portability check, but is not evidence for a second physical CPU-native backend.

The physical second-ISA profile uses:

```text
profile_version = 1
architecture = 3                 # AArch64
abi = 3                          # AAPCS64 register subset
image_format = 1                 # raw callable load image
word_bits = 64
pointer_bits = 64
stack_alignment = 16
shadow_space = 0
argument_register_count = 8
argument_registers = [X0..X7]
result_register = X0
scratch_register_count = 2
scratch_registers = [X9, X10]
supported_operation_count
supported_operation_id[...]
supported_terminator_count
supported_terminator_id[...]
```

Its target CID is:

```text
0af5a0c8db7996951be281cf7ab22a7ee158287c43f195c9518f782f5832e355
```

The raw load image contains only callable AArch64 code. QEMU machine setup and semihosted result extraction belong to the invocation harness and are not part of the emitted image.

The M13 non-CPU accelerator profile uses the same common target prefix and no CPU register fields:

```text
profile_version = 3
architecture = 4                 # prototype non-CPU accelerator
abi = 4                          # explicit packet/deployment ABI
image_format = 3                 # XAXA deployment packet
word_bits = 32
pointer_bits = 64
supported_operation_count
supported_operation_id[...]
supported_terminator_count
supported_terminator_id[...]
accelerator_lane_width
accelerator_max_groups
execution_scope_count
execution_scope[...]
memory_space_count
memory_space[...]
target_operation_count
target_operation[...]

memory_space =
    identity || address_bits || address_unit_bits || minimum_alignment
    access_width_count || access_width[...]
    visibility_scope_count || visibility_scope[...]
    host_visible_bool || device_visible_bool

target_operation =
    operation_id || semantic_code || encoding_opcode
    operand_constraint_count || value_constraint[...]
    result_constraint_count || value_constraint[...]
    supported_scope_count || supported_scope[...]
    source_space || destination_space
    synchronizes_bool || may_block_bool
    runtime_dependency_bytes

value_constraint = constraint_kind || primary || secondary
```

Constraint kind 1 is `bits<N>` (`primary=N`, `secondary=0`), kind 2 is `resource<K,state>` (`primary=K`, `secondary=state`), and kind 3 is `effect<D,instance>` (`primary=D`, `secondary=instance`). Scope IDs are system=1, device=2, and workgroup=3. Lists are canonical sorted sets where the verifier requires set semantics. Memory-space identities and target-operation IDs are positive and unique. A runtime dependency is either empty or exactly one 32-byte identity; the M13 target declares none.

The fixed M13 target is `simt32-packet-accelerator-v1`, target CID:

```text
202e9d0db81107e8380f27ef1f233327c34fe8a1f56431d38814ec4ee6feee04
```

It declares lane width 32, maximum group count 65535, device/workgroup execution scopes, host/global/workgroup memory spaces, and six target operations for allocation, host→device transfer, launch, synchronization, device→host transfer, and release. Packet opcode and accelerator semantic-code meanings remain target-package facts; the fundamental graph operation only references their generic contract.

### Kind 7: `graph_fragment`

```text
block_count
entry_block
block[block_count]
```

`block_count` MUST be positive and `entry_block < block_count`.

```text
block =
  parameter_count
  parameter_type_ref[parameter_count]
  node_count
  node[node_count]
  terminator

node =
  operation
  [member_index when operation = 4]
  [entity_ref when operation = 5, 6, or 30]
  operand_count
  value_ref[operand_count]
  result_count
  result_type_ref[result_count]
  [attribute_count || attribute[attribute_count] when operation is 7..11, 20..30 as defined below]
```

Value refs are:

```text
block_parameter = 0 || block_index || parameter_index
node_result     = 1 || block_index || node_index || result_index
```

Supported operation IDs:

| ID | Operation | Contract |
|---:|---|---|
| 1 | `add.wrap` | two equal `bits<N>` inputs, one same-type result |
| 2 | `sub.wrap` | two equal `bits<N>` inputs, one same-type result |
| 3 | `mul.wrap` | two equal `bits<N>` inputs, one same-type result |
| 4 | recursion-group member call | exact selected member interface |
| 5 | direct standalone-function call | exact referenced function interface |
| 6 | constant | zero inputs, one result matching referenced constant type |
| 7 | stack allocation | zero inputs; pointer, stack-owner, and memory-effect results; extent/alignment attributes |
| 8 | address offset | pointer input and pointer result; constant byte-offset attribute |
| 9 | little-endian bits store | pointer, value, and memory-effect inputs; successor memory-effect result; size/alignment attributes |
| 10 | little-endian bits load | pointer and memory-effect inputs; bits value and successor memory-effect results; size/alignment attributes |
| 11 | stack lifetime end | stack-owner and memory-effect inputs; no results |
| 12 | resource acquire | effect input; acquirable resource and matching successor effect results |
| 13 | resource transfer | resource and effect inputs; same resource type and matching successor effect results |
| 14 | resource transition | resource and effect inputs; declared successor-state resource and matching successor effect results |
| 15 | resource release | releasable resource and effect inputs; matching successor effect result |
| 16 | resource discard | affine resource and effect inputs; matching successor effect result |
| 17 | resource split | partitionable resource and effect inputs; two same-type pieces and matching successor effect results |
| 18 | resource join | two sibling pieces and effect inputs; joined same-type resource and matching successor effect results |
| 19 | effect step | one or more distinct effect-domain-instance inputs and matching successor results |
| 20 | atomic load | explicit order/scope/alignment; pointer + atomic effect to loaded value + successor effect |
| 21 | atomic store | explicit order/scope/alignment; pointer + value + atomic effect to successor effect |
| 22 | atomic RMW | explicit update/order/scope/alignment; pointer + value + atomic effect to old value + successor effect |
| 23 | atomic compare-exchange | explicit success/failure order, scope, strength, alignment; returns old value, success bit, successor effect |
| 24 | atomic fence | explicit order/scope; atomic effect to successor effect |
| 25 | META type bit width | typed compile-time type reference to bit-width result |
| 26 | META constant value | typed compile-time constant reference to ordinary bit result |
| 27 | META target supports | typed compile-time target reference plus operation attribute to `bits<1>` support result |
| 28 | META declared input | declared-input index attribute to one result |
| 29 | META materialize constant function | typed compile-time type plus ordinary value to opaque function result |
| 30 | target operation | exact target-package entity plus `(operation_id, scope, source_space, destination_space)` attributes; operands/results must match the package-declared contract |
| 31 | META function graph | `opaque<function>` to `opaque<graph>` under function-inspection authority |
| 32 | META graph block count | `opaque<graph>` to ordinary integer count |
| 33 | META graph node count | `opaque<graph>` plus block index to ordinary integer count |
| 34 | META graph node operation | `opaque<graph>` plus block/node indices to ordinary operation ID |
| 35 | META canonical store | `opaque<object>` to `opaque<bytes>` containing the deterministic reachable canonical store |
| 36 | META verify semantics | `opaque<object>` to `bits<1>` after ordinary verifier acceptance |
| 37 | META materialize program | `opaque<function>` to `opaque<object>` program root using canonical module/root construction |
| 38 | checked little-endian load | local pointer + dynamic byte offset + memory effect to scalar value + successor effect |
| 39 | checked little-endian store | local pointer + dynamic byte offset + scalar value + memory effect to successor effect |
| 40 | raw little-endian load | external/raw pointer to scalar value under explicit unsafe semantics |
| 41 | function address | standalone function reference to a typed function-pointer carrier |
| 42 | foreign call | exact foreign symbol/call contract; effects and resources remain explicit operands/results |
| 43 | indirect call | function pointer plus arguments under an exact call contract |
| 44 | float add | two equal form-7 floats to the same float type |
| 45 | float subtract | two equal form-7 floats to the same float type |
| 46 | float multiply | two equal form-7 floats to the same float type |
| 47 | float divide | two equal form-7 floats to the same float type |
| 48 | float compare | equal float inputs to `bits<1>`; one comparison-kind attribute |
| 49 | unsigned integer to float | `bits<N>` input to form-7 float |
| 50 | float to unsigned integer | form-7 float to `bits<N>` with trapping truncation for invalid/out-of-range input |
| 51 | aggregate make | exact tuple/array element operands to one aggregate result |
| 52 | aggregate get | aggregate input to selected element; one constant index attribute |
| 53 | sum make | selected variant value to one sum; one variant-index attribute |
| 54 | sum tag | sum input to an integer tag |
| 55 | sum get | sum input to selected variant value; wrong tag traps |
| 56 | pointer cast | same-space/same-element pointer identity conversion with no permission/alignment authority gain |
| 57 | integer compare | equal `bits<N>` inputs to `bits<1>`; one signed/unsigned comparison-kind attribute |
| 58 | float convert | binary32/binary64 input to binary32/binary64 result |

Operation 4 is valid only for a graph referenced as a kind-8 member. `member_index` addresses the enclosing recursion group's deterministic member list.
Operation 5 references a kind-3 standalone function. Operation 6 references a kind-5 constant. Without changing operation-5 encoding, the M7 bootstrap verifier recognizes one owner/effect pass-through interface plus three pointer-bearing resource-call interface families driven by a verifier-internal derived descriptor. `(ptr<stack,T,P,A>, T, resource<stack-storage,live>, effect<memory>) -> (resource<stack-storage,live>, effect<memory>)` accepts 1–8 same-pointer `store.bits.le` accesses; `(ptr<stack,T,P,A>, resource<stack-storage,live>, effect<memory>) -> (T, resource<stack-storage,live>, effect<memory>)` accepts 1–8 same-pointer `load.bits.le` accesses; and `(ptr<stack,T,P,A>, T, resource<stack-storage,live>, effect<memory>) -> (T, resource<stack-storage,live>, effect<memory>)` accepts 2–8 same-pointer store/load accesses when the first access is a store and the final access is a load whose value is returned. Load-only calls require the caller to prove the exact accessed range initialized before transfer; store-bearing calls establish initialization internally and return a successor frontier carrying that proof. The descriptor is authoritative for caller/callee bootstrap validation but remains tooling/implementation state only and is not serialized XAX source. The 8-access limit is not part of canonical XAX semantics. These are implementation-local CallContract slices, not a second source language or a claim that function types implicitly carry general resource/effect contracts.

Operations 38–43 extend the existing memory/call substrate with checked dynamic offsets, raw loads, function values, foreign calls, and indirect calls. Operations 44–58 add scalar floats, compact products/sums, comparisons, permission-narrowing pointer casts, and float-format conversion without introducing a runtime.

Operations 7–11 form the M3 straight-line stack-memory subset. Allocation identity is the allocating node. Address derivation preserves identity and can only reduce permission, extent, or alignment. Load/store require proved provenance, live lifetime, sufficient extent, matching size, alignment, permission, and initialization. Memory effects are linear per allocation. `stack lifetime end` consumes the separate owner and current effect. All proof facts erase in the reference execution path; no hidden check, heap, allocator, or runtime is introduced.

Operations 12–19 form the M7 general resource/effect subset. Exact linear consumption is checked through block parameters, branches, conditional branches, returns, and traps. Split pieces may rejoin only when they are the two siblings produced by the same split. Effect steps reject repeated domain instances, so independent domains remain independently ordered. Direct-call summaries are derived from verified function interfaces and terminators. Resource/effect values and proof-only calls erase from x86-64, AArch64, and WebAssembly ABIs and emitted bytes.

Operations 20–24 are the M8 atomic subset. Their attributes encode exact portable order/scope/alignment and family-specific update/compare-exchange fields. The verifier checks order legality, pointer permission/provenance/alignment, atomic effect linearity, and selected-target capability before lowering.

Operations 25–29 are the M9 compile-time META subset. They operate on typed opaque semantic references and explicit attributes/inputs under evaluator capabilities and deterministic budgets; they do not create a macro/template language.

Operations 31–37 are the M14 compile-time self-hosting substrate. Operations 31–34 inspect canonical function/graph structure under explicit `inspect-function` authority. Operation 35 emits the deterministic reachable canonical store for a semantic root under serialization authority. Operation 36 runs the ordinary semantic verifier under verifier authority. Operation 37 constructs the canonical module/program-root wrapper for a function under semantic-construction authority. These remain compile-time semantics; they add no mandatory runtime support and do not make diagnostic notation authoritative source.

Operation 30 is the generic target-operation hook added for M13. It references a kind-6 target object and carries exactly four attributes: package-defined operation ID, execution scope, source memory-space ID, and destination memory-space ID. The core verifier resolves the referenced target-operation contract and checks exact operand/result constraints, supported scope/space pair, legal resource-state transition, and effect continuation. Accelerator-specific semantic codes and packet opcodes are not fundamental XAX operations.

Terminators are:

```text
br   = 1 || target_block || argument_count || value_ref[argument_count]
cbr  = 2 || condition || true_edge || false_edge
ret  = 3 || value_count || value_ref[value_count]
trap = 4 || payload_bytes

edge = target_block || argument_count || value_ref[argument_count]
```

`cbr` condition MUST be `bits<1>`. Edge argument classes/types and function returns MUST match exactly. Same-block node uses must refer backward; cross-block uses must satisfy dominance.

### Kind 8: `recursion_group`

```text
member_count
member[member_count]

member =
  graph_ref
  parameter_count
  parameter_type_ref[parameter_count]
  return_count
  return_type_ref[return_count]
```

`member_count` MUST be positive. Members use zero-based group-local identity. Their graph entry/return contracts MUST match the encoded interfaces. Operation 4 member indices MUST be in range and call operands/results MUST match the selected interface.

Member graphs remain separate kind-7 objects in this prototype. Their group-local call indices are interpreted only through the owning kind-8 closure. This is an M1 objectization choice, not closure of OI-02 or OI-03.

### Kind 9: `package`

```text
logical_identity_bytes
module_count || module_ref[module_count]
dependency_count || dependency[dependency_count]
build_entry_count || (name_bytes || function_ref)[build_entry_count]
feature_count || (name_bytes || type_ref)[feature_count]
configuration_count || (name_bytes || type_ref)[configuration_count]
capability_count || (capability_kind || scope_bytes)[capability_count]

dependency = 1 || exact_package_ref
           | 2 || logical_identity_bytes
```

Modules, dependencies, named schemas, and capabilities are sorted and duplicate-free. Exact dependency references name kind-9 objects. Logical requirements reject unless the supplied candidate set contains exactly one matching immutable package. Build entries name standalone functions. Feature/configuration values in a build request must be constants of the declared types.

### Kind 10: `build`

Kind 10 uses a leading form tag:

```text
1 profile =
    mode || optimization || verification
    grant_count || (logical_identity_bytes || capability_kind || scope_bytes)[grant_count]

2 request =
    package_ref || build_entry_bytes || target_ref || profile_ref
    feature_count || (name_bytes || constant_ref)[feature_count]
    configuration_count || (name_bytes || constant_ref)[configuration_count]
    artifact_count || artifact_kind[artifact_count]

3 snapshot =
    request_ref || resolver_identity_bytes || trust_policy_ref
    package_count || package_ref[package_count]
    signature_count || signature_ref[signature_count]
    external_digest_count || blake3_256[external_digest_count]

4 trust_policy =
    require_package_signatures_bool || require_provenance_signature_bool
    algorithm_count || algorithm_identity_bytes[algorithm_count]
    signer_count || signer_identity_bytes[signer_count]

5 provenance =
    snapshot_ref || request_ref || target_ref || profile_ref
    artifact_blake3_256 || compiler_identity_256 || lowering_identity_256
    producer_identity_bytes

6 signature =
    signed_object_ref || algorithm_identity_bytes || signer_identity_bytes || signature_bytes

7 optimization_policy =
    objective_id
    pass_iterations || search_steps || search_candidates || search_memory_bytes
    polynomial_terms || inline_cold_nodes || inline_hot_nodes || hot_call_threshold
    deterministic_bool
```

Mode IDs are 1 hermetic-reproducible, 2 hermetic-nondeterministic, and 3 ambient. Capability IDs are 1 read-object, 2 read-external, 3 write-artifact, 4 network, 5 clock, 6 random, 7 sign, 8 invoke-tool, and 9 publish. Artifact kind 1 is a direct native/load-image or WebAssembly module selected by the explicit target package. Artifact kind 2 is an accelerator deployment artifact selected by an accelerator target package. Optimization objective ID 1 is code size. M12 optimization-policy integer fields are deterministic compiler-work/memory bounds; they do not encode wall-clock deadlines. Observed profile data is deliberately absent from form 7 and remains non-semantic tooling input. Collections are canonical sorted sets. Snapshot verification requires the exact transitive package closure; build identity includes snapshot, request, compiler, and lowering identities.

### Kind 11: `call_contract`

```text
input_count || input_type_ref[input_count]
output_count || output_type_ref[output_count]
may_return_bool
may_trap_bool
```

Input/output references name kind-4 exact types in call order. The reference table is the usual CID-sorted deduplicated table; repeated signature types reuse one local reference. `may_return_bool` and `may_trap_bool` are canonical `0`/`1` bytes. In prototype revision 1 the bounded effect set is reconstructed from exact `effect<domain,instance>` input/output types, while resource/capability-bearing values remain explicit exact resource/interface types. There is no unknown-effects sentinel or omitted-contract meaning. A direct function may be checked against a kind-11 contract only when its exact interface matches, its derived effects are a subset of the contract bound, and its return/trap behavior is within the encoded control bound.

Kind 11 is the OI-09-selected reusable contract identity. It does not add an indirect-call opcode by itself. Exact sealed dispatch sets remain optional optimizer/tooling facts rather than the sole contract authority.

## 3. Fixture revision 1

Compiler fixture files:

- `tests/fixtures/c0_all_kinds.xax.hex` — 1,229 canonical bytes encoded as whitespace-tolerant hexadecimal.
- `tests/fixtures/c0_all_kinds.json` — expected root CID and every object CID/kind.

Root CID:

```text
7046fcc2c7fc26bd66d282872faa7ec6381588b7a2ab8712b3e806bba90044aa
```

The fixture covers all eight M1 core kind IDs, standalone arithmetic, and a self-recursive group-local call. Later additive kind IDs do not alter its accepted bytes or identities. The test suite verifies byte identity, CID identity, structural validity, and indexed lookup.

## 4. Deliberate M1 limits

- Non-semantic payload interpretation remains tooling-specific; only canonical opaque framing is fixed here.
- No direct external call, switch, arbitrary type family, raw waiver, alias-restriction operation, or target lowering.
- M3 pointer/owner/effect memory facts remain restricted to the documented stack-memory subset. M7 general resource/effect values support verified cross-block linear flow.
- ULEB decoding is bounded to ten bytes in the bootstrap implementation.
- Graph fragmentation normalization remains open under OI-02.

## 5. M2 execution fixture

- `tests/fixtures/m2_direct_call.xax.hex` — 967 canonical bytes.
- `tests/fixtures/m2_direct_call.json` — root CID, entry function CID, arguments, and expected result.

The fixture calls a standalone `bits<8>` wrapping-add function with `250` and `10`; the required result is `4`. The reference executor also supports bounded recursion-group member execution. Executor fuel is a harness bound, not program semantics.

## 6. M3 stack-memory vector

The test suite constructs a 1,030-byte canonical store for a `bits<32>` stack allocate/store/load/end function. Stable identities are:

```text
root     41d276b7d29615423856fe617314ff2952075eceb4c0103e73fa89d63ad53c66
function a73f64f3d1540cf8527a2a7f21fa87455b0a82f3937b4d96b0a1f4976b99313b
```

The vector round-trips byte-identically and returns its stored input through the bounded reference executor. Negative vectors cover provenance, bounds, alignment, permission, initialization, effect linearity, owner/effect separation, explicit lifetime end, use after lifetime, and unsupported operation IDs.

## 7. M4 x86-64 Windows load-image vectors

The direct backend emits deterministic callable machine-code images without LLVM, an assembler, a linker, libc, or a XAX runtime. The Windows allocation/protection API belongs only to the invocation harness.

| Vector | Bytes | Entry | SHA-256 | Executed result |
|---|---:|---:|---|---|
| conditional branch + direct call | 238 | 48 | `8148798f74978748a6cf9b2111b49e60e897f81e61acca1aa1ba47e56e96ca75` | `(1,7,9) -> 16`; `(0,7,9) -> 4294967294` |
| stack allocate/store/load/end | 43 | 0 | `4f0aad0b3c17fddd89aa23d36339c6523f73d7fcf46da9468f5362ecec78a035` | `2864434397 -> 2864434397` |

`tests/fixtures/m4_x86_64.disasm` stores GNU objdump inspection. Tests execute images in isolated child processes and reject unsupported arithmetic widths explicitly.

## 8. M5 WebAssembly core-module vectors

The direct backend emits deterministic WebAssembly binary modules without a text format or external compiler. The semantic inputs are the same branch/direct-call and stack-memory programs used by M4.

| Vector | Bytes | SHA-256 | Executed result |
|---|---:|---|---|
| conditional branch + direct call | 185 | `39fde1ae42dbebe790b3b1820eb19e31c7cf548b508687cc7d263147618332f8` | `(1,7,9) -> 16`; `(0,7,9) -> 4294967294` |
| stack allocate/store/load/end | 78 | `0191ce4817c61cc96256f82c665dccca06f11d774925f57c25bdeb6a6137693e` | `2864434397 -> 2864434397` |

`tests/fixtures/m5_wasm32.hex` stores the exact modules. Node 24.19.0 validates and executes them with no imports. The bootstrap uses static linear-memory offsets and rejects direct-call cycles; reentrant stack lowering remains future work.

## 9. M5 AArch64 bare-metal load-image vectors

The backend directly encodes AArch64 instructions and AAPCS64 calls. QEMU 11.0.1 executes the raw code on a `virt`/`cortex-a72` machine; a generated harness initializes the stack, supplies arguments, and extracts the result through semihosting. Capstone 5.0.9 independently inspects the emitted bytes.

| Vector | Bytes | Entry | SHA-256 | Executed result |
|---|---:|---:|---|---|
| conditional branch + direct call | 212 | 48 | `0c12963d31a12bd555f1134b32f00046635fd0308c861415b9c2c112a78c6e4a` | `(1,7,9) -> 16`; `(0,7,9) -> 4294967294` |
| stack allocate/store/load/end | 44 | 0 | `698dfec16abf2adfe7a199a6d0ce01001abf1c04e7f742dea02951d4447ea28d` | `2864434397 -> 2864434397` |

`tests/fixtures/m5_aarch64.disasm` stores the Capstone inspection. The compiled image has no imports, allocator, libc, OS, assembler, linker, LLVM, semihosting call, or XAX runtime.
