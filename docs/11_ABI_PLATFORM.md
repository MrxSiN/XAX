# XAX Documentation Stage 11: ABI, Foreign Interoperability, Platform Capabilities, and Standard Environment

## 1. Purpose and scope

This document defines the boundary between core XAX semantics, binary application binary interfaces (ABIs), platform facilities, foreign ecosystems, and optional hosted environments.

XAX remains freestanding-first. A valid XAX program requires a program graph and a target package; it does not inherently require an operating system, libc, allocator, scheduler, dynamic loader, exception runtime, reflection system, or other hosted facility. Any such facility exists only when explicitly required by program semantics and supplied by the selected target/platform environment.

This stage specifies:

- first-class ABI descriptions;
- calling and data-transfer conventions at binary boundaries;
- syscall, kernel, firmware, and device ABIs;
- import/export of representable foreign binary interfaces;
- explicit adapters for semantic mismatches;
- explicit loss of XAX guarantees at foreign boundaries;
- platform capabilities and compile-time requirement checking;
- freestanding and hosted environment layering;
- optional dynamic linking;
- exact failure behavior for unsupported requirements.

---

## 2. Normative definitions

| Term | Definition |
|---|---|
| **core XAX** | The target-independent semantic system whose program meaning is represented directly by typed semantic graphs. Core XAX does not imply any operating system, runtime, allocator, loader, scheduler, exception mechanism, or standard library. |
| **target package** | A semantic package describing machine-level properties required for lowering and code generation, including machine types, registers, instructions, encodings, memory spaces, relocations, executable formats, calling-convention primitives, and related target constraints. |
| **ABI** | A first-class semantic description of externally observable binary conventions: argument and result placement, preserved machine state, stack rules, layout constraints, symbol conventions, variadic conventions, unwind requirements, and other boundary rules. |
| **ABI instance** | An ABI description specialized for a concrete target/platform combination and all parameters needed to make its rules exact. |
| **platform** | A semantic description of facilities exposed above or beside the raw target, such as syscalls, filesystems, networking, processes, threads, clocks, displays, accelerators, device interfaces, loaders, and security domains. |
| **platform capability** | A typed, versioned semantic contract stating that a platform can provide a particular externally observable facility. |
| **environment** | The selected combination of target package, platform package, capability set, and optional hosted packages under which a program is built. |
| **freestanding environment** | An environment that assumes no hosted facilities beyond those explicitly declared by the target and program. |
| **hosted package** | An ordinary XAX package that provides higher-level facilities by depending on explicit platform capabilities. |
| **foreign entity** | A function, object, symbol, service, or callable interface whose defining semantics are outside canonical XAX. |
| **foreign boundary** | A semantic boundary across which XAX guarantees may differ from or be weaker than guarantees inside verified XAX code. |
| **semantic adapter** | Explicit XAX semantics that convert between XAX representations/contracts and foreign representations/contracts. |
| **capability requirement** | A declarative condition that must be satisfied by the selected environment before the dependent program or package is valid for that environment. |
| **dynamic capability** | A capability whose availability or usable instance is intentionally resolved at runtime rather than proven present at build time. |
| **dynamic linking** | Runtime or load-time resolution of external binary symbols through a platform-supported loader facility. It is never implied by importing a foreign symbol. |

---

## 3. Architectural boundary

### 3.1 Core XAX owns meaning, not platform convention

Core XAX defines program semantics independently of platform ABI conventions. A call inside canonical XAX is a semantic call. It does not inherently mean "place value in register R0", "reserve 32 bytes of shadow space", "emit a PLT entry", or "invoke a system call".

C ABI rules, syscall numbering, red zones, loader behavior, visibility, name mangling, unwind tables, TLS conventions, startup rules, libc behavior, and device calling conventions are non-core and belong in target, ABI, platform, or hosted packages.

### 3.2 No second ABI or platform language

ABI and platform descriptions are XAX semantic objects and XAX compile-time computations. XAX does not introduce a permanently maintained ABI DSL, target DSL, syscall DSL, or build-language syntax.

Diagnostic or human-readable renderings may exist, but they are not authoritative program representations.

---

## 4. First-class ABI model

An ABI description MUST be complete enough that every exported or imported binary boundary has deterministic classification and compatibility rules.

Conceptually:

```text
abi {
    identity
    target_constraints
    data_representation
    call_conventions[]
    symbol_conventions
    unwind_models[]
    object_constraints
}
```

A call convention conceptually contains:

```text
call_convention {
    input_classification
    output_classification
    register_roles
    stack_rules
    preserved_state
    variadic_rules
    aggregate_rules
    tail_call_constraints
    unwind_policy
}
```

### 4.1 Parameter and return classification

Every ABI call convention MUST deterministically classify each parameter and result into one or more ABI locations or transfer mechanisms.

Possible outcomes include:

- machine registers;
- register pairs or register groups;
- stack slots;
- indirect-by-address transfer;
- hidden structure-return pointers;
- split aggregate transfer;
- target-defined special locations.

Classification MAY depend on semantic type, ABI-visible layout, size/alignment, aggregate composition, register availability, variadic status, target features, and ABI revision.

If classification is algorithmic, the algorithm MUST be deterministic compile-time XAX computation in the ABI package.

A boundary must prove semantic/ABI representation compatibility or use an explicit adapter.

### 4.2 Register and stack conventions

An ABI instance MUST define, where applicable:

- argument register classes and ordering;
- return register classes and ordering;
- caller-preserved and callee-preserved state;
- special-purpose registers;
- stack growth convention when externally observable;
- call-site stack alignment;
- entry stack alignment;
- stack argument ordering and slot alignment;
- mandatory shadow/home space;
- red-zone existence, size, and invalidation conditions;
- frame-pointer obligations, if any;
- return-address representation where ABI-visible.

A red zone is an ABI fact, not a generic XAX stack feature.

### 4.3 Variadic calls

Variadic behavior is ABI-specific and MUST NOT be modeled as an untyped, implicit core-language ellipsis.

A foreign variadic call requires an ABI-defined variadic argument pack whose construction applies all required promotions, register-save behavior, classification differences, alignment rules, and metadata.

Each actual variadic argument remains semantically typed in XAX before boundary conversion.

If the selected ABI cannot deterministically represent a requested variadic argument sequence, the call is rejected.

### 4.4 Unwind metadata

Core XAX has no mandatory exception mechanism and no implicit exception edge.

An ABI MAY define unwind metadata or foreign unwinding requirements. Such requirements are active only for boundaries that explicitly select them.

A foreign call that may unwind across XAX frames MUST have an explicit semantic representation of that control behavior compatible with the control/effect model. Otherwise one of the following must be true:

1. the foreign declaration guarantees no unwind across the boundary;
2. an explicit adapter contains the foreign unwind and converts it to ordinary XAX control/results;
3. an explicit adapter terminates or traps on unwind;
4. the import is rejected.

Unwind-table emission is therefore a consequence of selected ABI semantics, never an implicit language runtime feature.

---

## 5. Foreign import and export

### 5.1 Foreign import contract

A foreign import MUST identify at least:

- foreign symbol or service identity;
- ABI instance;
- foreign-visible type representation;
- XAX-visible semantic type;
- parameter and result mapping;
- effect contract;
- ownership/lifetime contract where resources or memory cross the boundary;
- aliasing/provenance guarantees that remain valid;
- unwind behavior;
- symbol-resolution mode.

### 5.2 Foreign export contract

A foreign export MUST identify:

- exported symbol identity;
- selected ABI instance;
- exported binary signature;
- semantic XAX entry point;
- adapter rules, if binary and semantic signatures differ;
- preserved-state obligations;
- unwind policy;
- visibility/binding policy if relevant to the object or executable format.

Exporting a XAX function does not weaken its internal semantics. Any required weakening or conversion occurs at the explicit boundary adapter.

### 5.3 Explicit loss of guarantees

Foreign code is not assumed to satisfy XAX invariants merely because it is callable.

The boundary MUST state which guarantees are preserved, converted, weakened, or unknown.

| XAX property | Foreign-boundary rule |
|---|---|
| pointer provenance | Preserved only if the foreign contract supplies sufficient provenance semantics; otherwise the returned/reference value carries a weaker foreign/raw provenance contract. |
| bounds | Preserved only when the boundary proves or supplies an extent. An address alone does not fabricate bounds. |
| alignment | Must be proven from the foreign ABI/contract or represented as a weaker alignment guarantee. |
| aliasing | Must follow the foreign contract. XAX MUST NOT infer no-alias properties that the foreign side does not guarantee. |
| ownership | Transfer, borrow, shared access, and release responsibility must be explicit. Ownership cannot silently change at the boundary. |
| lifetime | Foreign lifetime guarantees must be stated or treated conservatively. |
| effects | The call must declare all externally observable effects required for sound ordering and verification. |
| unwind | Must be explicitly absent, represented, contained, or rejected. |
| thread safety | Never assumed from symbol type alone. |
| determinism | Never assumed unless part of the foreign semantic contract. |
| resource release | Must use explicit XAX or foreign release semantics; no destructor is inferred. |

A boundary that cannot express a required loss of guarantee is invalid.

### 5.4 Semantic adapters

Adapters are explicit semantic objects or functions. They may perform:

- layout conversion;
- integer width/sign interpretation conversion;
- string or slice representation conversion;
- handle wrapping;
- ownership transfer;
- bounds reconstruction from separately supplied lengths;
- error-code to sum-value conversion;
- callback trampoline construction;
- unwind containment;
- calling-convention bridging.

There is no privileged "FFI magic" that can allocate, copy, lock, translate errors, or acquire resources invisibly.

### 5.5 C and other ecosystems

C-family ABIs are ordinary ABI packages, not foundational XAX rules.

Other ecosystems are importable only when their binary and behavioral contracts, including required runtime participation, can be represented explicitly. Otherwise the interface is rejected.

---

## 6. Syscall, kernel, firmware, and device ABIs

System-call and device interfaces are foreign binary contracts.

A platform package MAY define:

- syscall numbers or selectors;
- register placement;
- memory-buffer conventions;
- privilege transitions;
- error-result conventions;
- blocking behavior;
- memory effects;
- capability checks;
- device command formats;
- kernel object handles;
- interrupt or callback entry ABIs.

Core XAX assigns no universal meaning to syscall numbers, interrupt vectors, firmware tables, device register maps, or kernel handles.

A syscall-like operation that can block, mutate memory, access files, use networking, read time, or perform privileged work must expose the corresponding semantic effects and capability requirements.

Bare-metal targets may instead expose device or firmware interfaces directly, with no operating-system layer.

---

## 7. Platform capability model

A platform capability is a semantic contract, not merely a Boolean feature name.

Conceptually:

```text
capability {
    identity
    version
    operations
    type_contracts
    effects
    resource_contracts
    availability
    constraints
}
```

Typical capabilities include:

- filesystem;
- network;
- process;
- threads;
- clocks;
- entropy/randomness;
- display/windowing;
- audio;
- GPU/accelerator;
- dynamic loading;
- virtual memory;
- environment variables;
- user identity/security context;
- interprocess communication;
- device classes.

### 7.1 Capability requirements

A package or program MAY declare requirements such as:

```text
requires capability filesystem >= V
requires capability monotonic_clock
requires capability gpu with feature X
```

The notation above is diagnostic only.

A requirement may constrain identity, compatible version, operations, semantic features, statically known limits, and required platform properties. Satisfaction is semantic and deterministic.

### 7.2 Compile-time checking

For statically selected environments, all mandatory capability requirements MUST be resolved before the program is considered valid for that environment.

The toolchain MUST NOT silently:

- substitute a different capability with weaker semantics;
- add an operating system;
- add libc;
- add an allocator;
- add a scheduler;
- add a dynamic loader;
- emulate unsupported facilities;
- convert a required capability into a runtime probe.

Fallbacks are legal only when the program or package explicitly encodes them.

### 7.3 Optional and dynamic capabilities

A program that intentionally supports environments where a facility may or may not exist must model that choice explicitly.

Two valid patterns are:

1. compile-time alternatives selected by environment capability satisfaction;
2. a runtime dynamic-capability acquisition/query whose result is an ordinary XAX value representing success or absence.

A dynamic capability therefore requires a platform facility capable of performing that query. Its presence is not universal.

Runtime capability acquisition MUST expose effects and resource ownership when applicable.

---

## 8. Freestanding-first standard environment

XAX has no mandatory monolithic standard runtime.

The standard environment is a family of semantic packages layered by dependency.

A useful conceptual layering is:

| Layer | Meaning |
|---|---|
| **core semantic packages** | Pure or target-independent facilities requiring no hosted platform capability. |
| **target facilities** | Target-specific operations and representations supplied by the target package. |
| **platform capability interfaces** | Typed contracts for external facilities. |
| **hosted service packages** | Files, sockets, threads, clocks, processes, loaders, displays, GPUs, and similar APIs implemented against capabilities. |
| **policy/convenience packages** | Higher-level APIs that may select allocators, schedulers, buffering, executors, text conventions, or other policies explicitly. |

No package gains authority to introduce hidden behavior. Unused allocators, schedulers, libc layers, and operating-system facilities remain absent.

---

## 9. Dynamic linking

Dynamic linking is optional.

A program uses dynamic linking only when:

1. the selected platform exposes a dynamic-loader capability;
2. the program or a dependency explicitly requests dynamic symbol resolution;
3. the requested ABI and object/executable formats support it.

A foreign import does not imply dynamic linking. It may instead be resolved statically, provided by firmware, fixed at an address, supplied by a kernel/service table, or bound by another explicit mechanism.

Dynamic lookup failure is explicit. Loader policies such as lazy binding, interposition, and version lookup must not silently change effects, identity, or determinism assumptions.

If dynamic loading is unavailable and no explicit alternative is encoded, the environment is rejected.

---

## 10. Exact unsupported-platform behavior

An environment mismatch is not an invitation to guess.

Validation MUST produce machine-readable failure identifying the unsatisfied semantic fact.

Required failure classes include at least:

| Failure | Meaning |
|---|---|
| `abi.unsupported` | The requested ABI is not valid for the selected target/platform instance. |
| `abi.unclassifiable_type` | A boundary type cannot be classified by the selected ABI. |
| `abi.varargs_unrepresentable` | Requested variadic arguments cannot be represented exactly. |
| `abi.unwind_unrepresentable` | Required unwind behavior cannot be represented or contained. |
| `foreign.representation_mismatch` | XAX and foreign representations are incompatible and no explicit adapter is supplied. |
| `foreign.contract_incomplete` | Effects, ownership, provenance, lifetime, unwind, or another required boundary fact is missing. |
| `platform.missing_capability` | A mandatory capability is absent. |
| `platform.capability_version_mismatch` | A capability exists but does not satisfy the required semantic version/feature contract. |
| `platform.unsupported_operation` | The capability exists but lacks a required operation or semantic guarantee. |
| `platform.dynamic_loader_unavailable` | Dynamic linking was explicitly required but is unsupported. |
| `environment.unsatisfied_requirement` | A higher-level environment constraint cannot be satisfied. |

Diagnostics SHOULD identify the requiring entity, selected environment, required capability/ABI, known alternatives, and nearest repair neighborhood.

The toolchain MUST NOT continue by weakening semantics unless that weakening is explicitly encoded as an alternative program path.

---

### 10.1 Portable trap reason and target detail

Core `trap` carries a 16-bit portable reason plus optional opaque target/platform detail. The portable reason is not an exception class and does not imply unwinding, cleanup, allocation, or a runtime. Current native bootstrap mappings make the reason observable without standardizing the suffix: x86-64 Windows writes the reason to `rax` and executes `ud2`; AAPCS64 writes it to `x0` and executes `brk` with the same 16-bit immediate. A debugger, supervisor, crash collector, or firmware handler may inspect that target-specific machine state. The opaque suffix remains available to semantic diagnostics and may be mapped only by an explicit target/platform contract.

## 11. Invariants

1. Core XAX remains independent of C, POSIX, Windows, ELF, PE, Mach-O, WASI, libc, or any other specific hosted ecosystem.
2. ABI behavior is explicit and first-class.
3. Platform facilities are explicit capabilities, not assumed ambient services.
4. Foreign effects cannot be hidden behind a pure-looking call.
5. Foreign ownership transfer cannot be implicit.
6. Bounds, provenance, aliasing, lifetime, and alignment guarantees cannot be fabricated at a foreign boundary.
7. A foreign call cannot secretly introduce an exception/unwind edge.
8. Varargs are ABI-defined typed boundary construction, not untyped core semantics.
9. Hosted packages cannot force unrelated runtimes into a program.
10. Dynamic linking is never mandatory.
11. Absence of a required capability is a validation failure unless the program explicitly models an alternative.
12. No adapter may introduce hidden allocation, synchronization, syscall, initialization, or resource transfer.
13. ABI/platform descriptions use XAX semantic data and compile-time XAX computation rather than a second permanent language.
14. Freestanding deployment remains a first-class valid environment.

---

## 12. Rejected alternatives

### 12.1 Make the C ABI the universal XAX ABI

Rejected. C ABIs vary by target and platform, cannot express all XAX types or guarantees, and would make a historical foreign convention foundational.

### 12.2 Require libc as the platform abstraction

Rejected. libc is unavailable or undesirable for firmware, kernels, accelerators, constrained systems, and many direct platform interfaces. It would also violate freestanding-first semantics.

### 12.4 Treat every foreign pointer as a normal proven XAX pointer

Rejected. A raw address does not establish provenance, bounds, alignment, ownership, lifetime, or alias properties.

### 12.5 Give foreign calls implicit "may do anything" semantics

Rejected as the default. Overly broad effects destroy optimization and verification information. Foreign effects must be declared precisely enough for soundness; conservative broad effects are permitted only when that is the actual known contract.

### 12.6 Require dynamic linking for foreign imports

Rejected. Static, firmware, fixed-address, kernel-table, device-table, and other binding mechanisms are valid.

### 12.7 Define one mandatory standard runtime

Rejected. It would contradict the requirements that unused facilities disappear and that bare-metal programs require no allocator, scheduler, libc, or OS.

---

## 13. Interfaces with other XAX subsystems

| Subsystem | Dependency/interface |
|---|---|
| Foundations | Uses canonical semantic identity, explicitness rules, and machine-verifiable invariants. |
| Core semantic graph | Represents ABI selections, foreign declarations, adapters, capability requirements, and explicit control/effect relationships. |
| Type/value/layout system | Supplies semantic types and layout facts used to prove or adapt foreign binary representations. |
| Memory/pointer/resource model | Governs provenance, bounds, permissions, ownership, lifetimes, handles, and explicit resource release across boundaries. |
| Effects/control/calls | Represents foreign effects, explicit failure, trap behavior, call control behavior, and any modeled unwind path. |
| Concurrency/atomics | Supplies thread, atomic, and synchronization semantics; platform thread APIs do not redefine the core memory model. |
| Compile-time execution | Specializes ABI classification and capability-dependent alternatives without requiring a separate ABI language. |
| Canonical serialization | Provides stable identities for ABI, platform, capability, and adapter semantic objects. |
| AI workspace/protocol | Allows local query and mutation of foreign contracts and capability requirements through semantic entities rather than source text. |
| Universal target model | Supplies machine properties, object formats, relocations, instruction constraints, and target-level ABI primitives on which ABI instances depend. |
| Package system | Distributes content-addressed ABI, platform, and hosted-library packages and records exact dependencies. |

---

## 14. Open issues

Only issues requiring implementation or ecosystem evidence remain open.

### 14.1 Capability granularity

The correct granularity for widely used capabilities such as filesystem, networking, GPU, and process control may require prototype experience. Capabilities that are too coarse reduce portability; capabilities that are too fine increase graph and package overhead.

The invariant is fixed: capability boundaries must preserve exact semantics and permit deterministic requirement checking.

### 14.2 Foreign contract inference

Future tooling may infer candidate foreign effect, ownership, or representation contracts from machine-readable external metadata. Such inference cannot become authoritative unless verified against the imported interface contract.

### 14.3 ABI classification representation

Some ABIs may be best represented as declarative tables; others may require deterministic compile-time classifiers. The canonical system may support both forms as ordinary semantic data/computation, provided there is no second language and behavior remains deterministic.

---

## 15. Falsification criteria

This design should be reconsidered if later implementation evidence shows one or more of the following:

1. Real ABIs cannot be represented without adding target- or ecosystem-specific semantics to the XAX core.
2. ABI classification expressed as XAX semantic data/compile-time computation is materially less reliable or substantially more complex than a separate representation, without compensating benefits.
3. Explicit boundary adapters impose unavoidable runtime overhead compared with equivalent hand-written foreign interfaces even after specialization and optimization.
4. Capability decomposition causes prohibitive package or semantic-graph overhead for ordinary programs.
5. Compile-time capability checking cannot express common portable fallback structures without excessive duplication.
6. The foreign guarantee-loss model is too weak to represent major C, C++, system-call, kernel, GPU, or device interfaces soundly.
7. Required unwind interoperation cannot be represented without introducing hidden exception semantics into ordinary XAX calls.
8. Freestanding-first layering prevents hosted programs from achieving competitive binary size, startup cost, or native performance because optional services cannot be erased or specialized effectively.
9. Dynamic and static linking policies cannot coexist cleanly without ambiguous symbol identity or observable-semantic differences that the model fails to expose.
10. Real platform APIs routinely require implicit process-global state that cannot be made explicit enough for verification and optimization without unreasonable semantic overhead.

Any such failure must be demonstrated with concrete ABI/platform cases or measured compiler/tooling evidence. Convenience alone is insufficient reason to move hosted assumptions into core XAX.

---

## 16. Android arm64-v8a / modern libxposed bounded ABI slice (2026-10-01)

The implemented Android ABI profile is `android-aapcs64-c` over the existing
AAPCS64 register contract (`x0..x7` arguments, `x0` result, 16-byte stack
alignment). Effects/resources/proofs remain semantic values and erase from the
machine calling sequence; integer and pointer carriers use the normal AAPCS64
registers.

### 16.1 Explicit exports and imports

An Android export is a content-addressed build/target declaration containing:

```
ABI        = android-aapcs64-c
visibility = default
name       = exact unmangled byte string
function   = exact function CID
```

Only these declarations become externally visible `.dynsym` definitions.
Internal reachable functions remain local. An export is also an emission
reachability root, so a callback referenced by an exported function can remain
internal without being removed.

Foreign functions use a separate bounded declaration carrying exact ABI,
library, symbol name, input types, and output types. No library is inferred from
a symbol name. Only referenced foreign declarations become undefined dynamic
symbols and `DT_NEEDED` dependencies.

### 16.2 libxposed native ABI

For the currently verified native-hook ABI on AArch64, the borrowed
`NativeAPIEntries*` layout used by the target package is:

```
offset 0   uint32_t version
offset 8   HookFunType hook_func
offset 16  UnhookFunType unhook_func
```

The padding between `version` and the first pointer is ordinary AAPCS64 struct
layout. The compiler does not copy or wrap this object. Loads lower directly
from the borrowed pointer. `hook_func`/`unhook_func` are bounded opaque function
pointers and calls lower directly to `BLR` after ordinary ABI argument setup.

The sample module exports exactly `native_init` and returns an internal
`NativeOnModuleLoaded` function address. No registration table, adapter object,
allocator, or runtime dispatcher is emitted.

### 16.3 JNI bounded ABI slice

JNI is represented as borrowed opaque pointers and fixed table loads. The
current fixture proves the `JNI_OnLoad(JavaVM*, void*)` path needed to obtain
`JNIEnv*` through `JavaVM->functions->GetEnv` and invokes that function pointer
with `BLR`. A local output slot for `JNIEnv*` remains explicit XAX stack memory,
including exact owner/effect proof across the indirect call. There is no JNI
wrapper runtime or generic dispatcher.

`JNI_OnLoad` exists only when explicitly exported. Modules without it have no
JNI-specific code or startup work.

### 16.4 Android shared-object startup surface

The direct ELF emitter produces two 16-KiB-aligned `PT_LOAD` segments plus the
minimal dynamic metadata required by the specific module. It emits no implicit
`.init_array`, `.fini_array`, TLS segment, exception/unwind runtime, C++ runtime,
allocator initialization, or default libc/libdl dependency.

The modern packaging fixture places native module metadata under
`META-INF/xposed/` and packages the already-generated `arm64-v8a` `.so`; Gradle
is not part of XAX native code generation.


### 16.5 libxposed API-102 remote-capability ABI surface

Remote framework resources are target/platform calls, not XAX kernel operations.  The
bounded managed ABI profile materializes `PROP_CAP_REMOTE` as the API-102 property bit
`1L << 1`.  A generated remote acquisition helper first calls
`XposedModule.getFrameworkProperties()`, masks that bit, and branches before any remote
call.  The unsupported branch returns null.  The supported branch directly invokes the
selected API method and lets framework exceptions escape under the semantic `propagate`
policy.

The current remote-preferences ABI imports `android.content.SharedPreferences` only when
reachable and emits direct `invoke-interface` reads for boolean, int, long, float,
String, and contains.  No `SharedPreferences.Editor` ABI surface is emitted.  The current
remote-files ABI imports only the `String[]` listing and `ParcelFileDescriptor` result
contracts needed by list/open.  Neither profile adds a cache, retry layer, service
manager, or allocation in generated helpers.

### 16.6 libxposed API-102 bounded hot-reload ABI surface

The first hot-reload ABI is deliberately single-entry/single-hook.  Build closure requires
one API-102 Java module entry and one retained generated HookHandle.  Metadata sets
`autoHotReload=true`; the generated entry therefore exposes API-102
`onHotReloading(HotReloadingParam)` and `onHotReloaded(HotReloadedParam)` methods.

`onHotReloading` returns true without calling ordinary package/module lifecycle callbacks.
`onHotReloaded` consumes `HotReloadedParam.getOldHookHandles()`, takes the sole handle
allowed by the build invariant, casts it to `HookHandle`, constructs one replacement
Hooker, invokes `HookHandle.replaceHook(Hooker)`, and stores the returned handle in the
existing retained field.  No native ABI changes are introduced.  There is no
unhook/install window, no generated target-member lookup in the reload callback, and no
implicit state/resource migration.  Multiple-hook matching and saved-instance-state are
not ABI commitments of this bounded profile.

## 17. Windows x86-64 hosted PE slice (2026-10-02)

Target `x86_64-windows-pe-v1` adds the `win64-c` foreign ABI to the general x86-64 operation set. It is a platform/ABI package choice; no Windows concept enters the kernel.

### 17.1 Imports

A `call_foreign` declaration names `(abi, library, symbol, typed interface)`. The x86-64 backend lowers it to `call qword [rip+disp32]`; the PE container allocates one import-address-table slot per distinct `(library, symbol)` and the Windows loader binds it. Effect and resource arguments are proof values and erase. Pointer-sized platform words (`HANDLE`, `LPOVERLAPPED`) are typed `b64`; caller buffers are borrowed address-space-1 pointers whose lifetime the verifier checks at the call. Allocator/deallocator contracts (HeapAlloc/HeapFree) carry the same linear heap-owner rules as the POSIX package.

### 17.2 Ownership of foreign ABIs

Each foreign ABI string is owned by one backend and profile: x86-64 accepts `win64-c` on the PE profile and `linux-x86_64-syscall-v1`/`sysv-x86_64-c` on the Linux profiles (§19), AArch64 accepts only `android-aapcs64-c`, and wasm32 accepts only `wasm32-import`. Declarations for another ABI reject (`XAX.FOREIGN.ABI`) rather than being reinterpreted. Raw load images cannot bind imports and reject import-bearing images (`XAX.NATIVE.IMPORTS`).

### 17.3 Process lifecycle

The PE entry point is the XAX entry function itself: it takes no machine parameters and returns only integers (`XAX.PE.ENTRY`). The container emits no startup or exit code. Because a process whose loader worker threads are alive does not end when the entry returns, termination is the program's explicit `ExitProcess` call. TLS callbacks, exception/unwind tables, exports, and resources are absent until explicit contracts require them (OI-33).

### 17.4 Heap views

`heap_view` lowers to a null test plus `ud2` on failure, then stores the base. Static heap accesses fold the view offset into `[base+disp]`; checked accesses compare the dynamic offset against `extent - size` and trap with `ud2` before `[base+index+disp]`. `VirtualAlloc` is declared with a zero-filled, 4096-aligned allocator contract (committed pages are zero-filled by the platform), so checked loads over the whole view are initialization-proven; `VirtualFree(view, 0, MEM_RELEASE)` consumes the view.

## 18. wasm32 WASI slice (2026-10-02)

Target `wasm32-wasi-v1` adds `call_foreign` under the `wasm32-import` ABI: a declaration's `library` is the wasm import module and its `name` the field. Value types follow the wasm32 general profile (pointers are i32 linear-memory addresses). The module exports `_start` and `memory`; the entry takes and returns no machine values; termination is the program's explicit `proc_exit`. The WASI host is a platform-required runtime (UR-002); no JavaScript glue is generated or required. Bounded package: `xax_platform.wasi_preview1_api` (`args_sizes_get`, `fd_write`, `proc_exit`). `fd_write` iovec buffer words are exposed addresses (`pointer_address`, ADR-081); its declaration takes the buffer storage's memory effect as a second memory input/output so the buffer cannot end before the call. APIs that need provenance-carrying pointers reloaded from memory wait on OI-37.

## 19. Linux x86-64 hosted slice (2026-10-02)

Targets `x86_64-linux-elf-exec-v1` (static) and `x86_64-linux-elf-dynexec-v1` (explicit dynamic loader) keep XAX-internal calls on the general x86-64 register convention. Their external boundaries are the process entry, syscalls, and declared C imports. No Linux concept enters the kernel (ADR-084–ADR-089).

### 19.1 `linux-x86_64-syscall-v1`

A declaration has library `linux` and a canonical register-template name:

```text
name = nr                      -- machine operands passed in order
name = nr ":" arg ("," arg)*   -- arg = "$k" (k-th machine operand) | unsigned 64-bit decimal literal
```

Each machine operand is used exactly once, with at most six arguments, placed in `rdi, rsi, rdx, r10, r8, r9`; `eax` carries the number, and the result is the exact 64-bit `rax`. Proof values erase. With an allocator contract, the kernel's error range `-4095..-1` projects to the contract's nullable (zero) pointer, and `heap_view` then traps on null. Fixed literals (`PROT_READ|PROT_WRITE`, `MAP_PRIVATE|MAP_ANONYMOUS`, `fd = -1`) live in the template, so "anonymous private mappings are zero-filled" is part of the `mmap_anonymous` declaration identity rather than an assumption about caller arguments. Syscalls that read or write program memory take the reached storage's memory effect. Bounded package: `xax_linux.linux_api()` (`read`, `write`, `openat`, `close`, `mmap_anonymous`, `munmap_view`, `exit_group`). Platform pointers are address-space-2 (heap/external) pointers.

### 19.2 `sysv-x86_64-c`

A declaration imports a C symbol from the shared library named by its soname (`library`). It lowers only on the explicit-loader profile; on the static profile it rejects (`SYSV-C-REQUIRES-DYNAMIC-PROFILE`). The artifact's `PT_INTERP` is exactly `/lib64/ld-linux-x86-64.so.2`; `DT_NEEDED` lists exactly the declared sonames (no default libc); each import gets one bind-now `R_X86_64_GLOB_DAT` GOT slot and is called through the shared `call_import` path. Signatures are limited to the psABI INTEGER class: at most six integer or pointer arguments in `rdi, rsi, rdx, rcx, r8, r9` and at most one integer or pointer result (`SYSV-C-INTEGER-CLASS`). ELF symbol lookup is global, so one symbol name cannot be imported from two libraries (`XAX.LINUX.IMPORT`); the declared library is a load dependency, not a direct binding. Callbacks, floats, aggregates, stack arguments, variadics, and symbol versioning are OI-40.

### 19.3 Process lifecycle

As on Windows (§17.3), the container emits no code: `e_entry` is the XAX entry function, which takes no machine parameters, returns at most one integer (`XAX.LINUX.ENTRY`), and ends the process with an explicit `exit_group`. Linux starts a process with RSP 16-byte aligned and no return address, so the entry function is lowered as a process entry. Its frame uses that alignment, it saves no callee-saved registers, and its `ret` lowers to `ud2`, so returning traps instead of exiting or jumping to an unknown address. argv/env/auxv, TLS, signals, and unwind data are absent until explicit contracts require them (OI-33).

