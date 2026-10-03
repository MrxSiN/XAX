# XAX — AI-Native Programming Language Architecture v0.4

**v0.3 scope.** v0.1 framed XAX as a compiler-architecture prototype (sections 1–34, preserved below). v0.2 extended the same principles to a universal-replacement architecture (sections 35–47). v0.3 records the first two architectures added without any kernel change, a managed JVM target and a RISC-V ISA target (§37, §39, §41). v0.4 records a second AArch64 platform (Linux), a real GPU representation (SPIR-V for Vulkan), callable recursion, the first R3 application, deterministic C header import, board packages with interrupts, and static linking of existing C objects (§37, §39, §40, §43, §47; ADR-123–ADR-129). The only change to semantic-object encoding is the callable form of the recursion-group member identity the specification already defined. This document states principles and intent; `XAX_SPEC.md` is normative and wins on conflict; implementation status lives in `XAX_STATE.md` and `XAX_REPLACEMENT_MATRIX.json`.

## Founding definition

XAX is not a textual language designed for humans.

XAX is a **canonical semantic program representation designed to be generated, queried, modified, verified, optimized, and compiled by machines**.

The fundamental pipeline is:

AI intent  
→ semantic graph  
→ verification  
→ optimization/search  
→ target lowering  
→ machine code

There is no mandatory human-readable programming syntax between AI and compiler.

The authoritative XAX program is the semantic graph itself.

---

# 1. Design priorities

In descending order:

| Priority | Requirement |
|---|---|
| 1 | Semantic correctness (deterministic meaning is part of correctness) |
| 2 | Minimum AI tokens per successful semantic change |
| 3 | AI generation reliability |
| 4 | Runtime performance |
| 5 | Memory footprint |
| 6 | Binary footprint |
| 7 | Compilation quality |
| 8 | Hardware/platform portability |
| 9 | Deterministic behavior of builds and tooling |
| 10 | Compiler/toolchain simplicity |
| 11 | Human usability |

Incremental/local modification serves priority 2. Reconciliation with `XAX_SPEC.md` §1 is ADR-078.

Human readability has zero normative weight.

Human writability has zero normative weight.

Human-friendly naming has zero normative weight.

Formatting has zero normative weight.

---

# 2. What XAX is

A XAX program is a persistent, typed, directed semantic graph.

The basic semantic object is:

    node = operation(
        type,
        operands,
        effects,
        attributes
    )

Functions are graphs containing blocks.

Blocks contain dependency-connected nodes.

Control flow is explicit.

Data flow is explicit.

External effects are explicit.

Resource ownership is explicit.

Target-dependent operations are explicit.

There is no parser-generated AST because there is no human source syntax to parse.

The persistent graph is already close to the representation the optimizer needs.

---

# 3. Semantic structure

The core representation is **block-parameter SSA plus explicit dependency/effect edges**.

This is deliberately less complicated than a full sea-of-nodes architecture while retaining nearly all information needed for optimization.

A function consists conceptually of:

    Function
      Parameters
      Blocks
        Block parameters
        Operations
        Terminator
      Return types
      Declared capabilities

SSA values never change.

Loops use block parameters rather than mutable variables.

There are no implicit captures.

There are no implicit temporaries.

There are no implicit destructors.

There are no implicit exceptions.

There is no unspecified evaluation order.

---

# 4. Tiny semantic kernel

The language kernel should remain extremely small.

| Family | Meaning |
|---|---|
| value | constants and pure computation |
| aggregate | tuples, sums, extraction, construction |
| control | call, branch, conditional branch, return, trap |
| memory | allocation, address calculation, load, store, copy |
| resource | acquisition, transfer, release |
| atomic | atomic memory operations and fences |
| target | machine/platform-defined primitive |
| meta | compile-time semantic construction and inspection |

The exact-arithmetic family currently contains wrapping add/sub/mul, `bit.and`, `bit.or`, `bit.xor`, `rotate.right k`, `udiv`/`urem` (explicit portable trap on a zero divisor), `int.truncate`, `int.zero_extend`, integer comparison, and IEEE float operations. Shifts and sign extension are exact compositions of these (ADR-084); target lowering selects single instructions for them when profitable.

Arithmetic operations are parameterized by exact semantics.

For example, overflow is not determined by vague language rules.

The operation itself states the behavior:

    add.wrap
    add.checked
    add.saturate

Likewise:

    sdiv
    udiv

instead of attaching unnecessary signedness semantics to every stored bit pattern.

---

# 5. Types

The primitive type system is intentionally small.

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

`bits<N>` supports arbitrary bit width.

Signed and unsigned interpretation belongs primarily to operations rather than the underlying bits.

Pointers carry enough semantic information for optimization and verification.

A pointer may include:

    address space
    object/provenance
    extent
    alignment
    read/write permission
    alias class

These properties may be statically proven and therefore consume zero runtime space.

---

# 6. Memory

There is no mandatory heap.

There is no mandatory garbage collector.

There is no mandatory reference counting.

Storage creation is always semantically visible.

Storage classes include:

    static
    stack
    region
    arena
    target-memory
    raw

Heap allocation is simply an allocator operation supplied by an environment or library.

If a program performs no allocation, no allocator exists in the resulting executable.

If a program needs 48 bytes of stack, the compiler should know that directly.

---

# 7. Resource model

Memory ownership is only one instance of resource ownership.

XAX uses linear resource values for things requiring controlled lifetime.

Examples include file handles, sockets, locks, DMA channels, GPU buffers, interrupt registrations, capabilities and transactions.

A linear resource cannot silently disappear or silently duplicate.

There is no implicit RAII destructor.

Release is semantically explicit.

The compiler can prove that a release operation is redundant or can be fused, but program semantics never rely on an invisible destructor.

---

# 8. Effects

Pure operations have no effect dependency.

Effectful operations describe their domains.

Examples:

    memory
    io
    atomic
    device
    syscall
    time
    random
    network
    filesystem
    privileged

Internally, effect dependencies form graph edges.

The persistent serialization is permitted to compress edges that can be reconstructed unambiguously.

Thus XAX obtains explicit semantics without paying repeated token cost for redundant information.

Independent effect domains allow optimization.

A filesystem operation does not automatically serialize unrelated GPU memory operations.

---

# 9. Safety

XAX does not have a global "safe language versus unsafe language" split.

Instead every operation has precise proof obligations.

For example, a memory access may require evidence for:

    valid provenance
    sufficient bounds
    alignment
    required permission

When the compiler proves the conditions statically, no runtime check exists.

A raw operation can deliberately waive an obligation.

That waiver becomes part of the semantic graph and effect information.

Unsafe behavior is therefore machine-visible rather than hidden behind a lexical `unsafe` block.

---

# 10. Errors

There are no mandatory language exceptions.

Recoverable errors are ordinary values, usually sums.

Fatal behavior uses explicit trap operations.

A call cannot secretly introduce an exception edge.

A target or library may implement exception-compatible ABIs when interoperability requires them, but they are not fundamental XAX semantics.

---

# 11. Concurrency

The kernel contains the primitives necessary to express concurrency rather than one mandatory concurrency framework.

Atomics specify ordering exactly.

Scheduling, threads, tasks, actors, futures, coroutines and event loops can be implemented in XAX libraries.

No scheduler is automatically linked.

A bare-metal interrupt handler does not acquire an asynchronous runtime merely because the language supports asynchronous software elsewhere.

---

# 12. Compile-time execution

There is no macro language.

There is no template language.

There is no preprocessor.

XAX executes XAX at compile time.

Compile-time functions can accept semantic values and produce semantic values.

Types themselves may be compile-time values.

Generic programming therefore becomes specialization of ordinary XAX computation.

Compile-time execution may be required to be deterministic, bounded and sandboxed.

After specialization, unused compile-time machinery disappears.

---

# 13. No conventional source code

The canonical `.xax` artifact is a compact binary semantic store.

It contains content-addressed objects such as:

    module
    function
    type
    constant
    target
    graph fragment

Encoding uses canonical integer representation, length-prefixing and deterministic field ordering.

Repeated objects are interned.

Local references use tiny integers.

Large persistent identities use hashes but are normally hidden from AI context.

A human-readable dump may exist for debugging the compiler.

It is not XAX source.

Editing that dump does not modify the program.

---

# 14. AI-native representation

AI should almost never regenerate a `.xax` artifact.

The compiler exposes a semantic workspace.

The model receives small local handles such as:

    0
    1
    2
    3

rather than 256-bit hashes.

A model request might conceptually see:

    F3
    N0 add.wrap b64 0 1
    N1 ret N0

This is diagnostic notation only.

It is not the XAX language.

If the requested change is "multiply instead of add", the AI transaction can effectively contain:

    set-op N0 mul.wrap

Only the changed semantic fact is transmitted.

---

# 15. Token-native AI protocol

For maximum efficiency, the eventual model and XAX protocol should be co-designed.

Common operations receive dedicated model vocabulary tokens.

Frequent concepts such as:

    ADD
    LOAD
    CALL
    RET
    B32
    B64

should ideally each consume one model token.

Small local references should also use compact vocabulary representations.

The objective is therefore not merely "short text".

The objective is:

    minimum model tokens / semantic mutation

With model/tokenizer integration, a simple semantic edit could require only a few tokens.

With an existing unmodified tokenizer, a compact fallback transport is used and empirically selected by benchmark.

No serialization alphabet is declared optimal without measuring actual tokenizer behavior.

---

# 16. Content addressing

Immutable XAX objects are content-addressed.

A module references functions by persistent identity.

A function references immutable type and constant objects.

A local edit creates a new function version without rewriting unrelated objects.

Programs form a Merkle DAG.

Therefore changing one operation in a million-function project need not retransmit or rewrite the million functions.

---

# 17. Transactions

AI mutation is transactional.

Conceptually:

    base root
    mutation set
    verify
    commit

The compiler rejects the entire transaction if the expected base root is stale.

Partial program mutation cannot occur.

Semantic conflicts between multiple AI agents are detected at affected graph entities rather than by comparing lines of text.

---

# 18. Machine diagnostics

The normal diagnostic format is data.

Conceptually:

    code
    entity
    rule
    expected
    actual
    dependencies
    repair-neighborhood

No explanatory English is required.

Instead of:

    "Cannot borrow x as mutable because..."

the AI receives exact semantic relationships responsible for the violation.

Natural language can be synthesized only when a human requests it.

---

# 19. Universal target model

XAX does not hardcode x86, ARM, RISC-V, GPUs or operating systems into its fundamental language.

A target is an ordinary XAX semantic package describing:

    machine value types
    registers
    register classes
    instructions
    instruction semantics
    encodings
    memory spaces
    calling conventions
    relocations
    object format
    executable format
    atomic capabilities
    scheduling constraints
    latency/throughput data
    lowering rules
    legalizations
    ABI rules

Because these descriptions are XAX semantic objects manipulated by XAX programs, no second target-description DSL is required.

---

# 20. Unknown future hardware

The compiler does not need to understand every future instruction in advance.

A target operation supplies a semantic contract.

The contract states its input/output types, effects, control behavior, memory behavior and optimization restrictions.

Where mathematical semantics can be expressed, the target package supplies them.

Where the operation is inherently opaque, its effects and constraints still allow safe compilation.

Thus XAX can target a new machine without altering fundamental XAX semantics.

---

# 21. Compilation

The native compiler pipeline is:

    verify
    specialize
    normalize
    optimize
    target-lower
    schedule
    register-allocate
    machine-optimize
    encode
    emit

The compiler directly emits target object/executable bytes.

LLVM is not required.

An external backend may temporarily assist bootstrapping, but it cannot become part of the final architecture.

---

# 22. Optimization

Because human source preservation is irrelevant, optimization is allowed to be extremely aggressive.

XAX may combine:

    conventional optimization
    interprocedural specialization
    whole-program optimization
    equality saturation
    profile-guided optimization
    instruction search
    bounded superoptimization

Each transformation must preserve observable semantics.

For expensive optimization modes, candidate replacements can be verified by equivalence checking or translation validation.

The optimizer may spend minutes or hours on a binary intended to run billions of times if the selected build policy allows it.

---

# 23. "Better than assembly"

XAX cannot promise to be universally faster than assembly.

Assembly ultimately specifies instructions available to the machine.

The meaningful objective is instead:

    generated machine code <= best known cost

for the chosen cost function and target constraints.

The compiler is free to search instruction sequences that a human assembly programmer would be unlikely to discover manually.

Therefore XAX may outperform particular hand-written assembly implementations.

It cannot logically guarantee superiority over every possible assembly implementation.

---

# 24. Cost-directed compilation

Every target package exposes a cost model when possible.

The compiler can optimize for different objectives:

    latency
    throughput
    binary size
    energy
    memory
    deterministic latency

The AI can ask:

    cost(F3,target=T0)

and receive machine data rather than guessing from source.

Measured profile data is kept separate from program semantics.

---

# 25. Bare metal

A minimal valid XAX program requires:

    program graph
    target package

Nothing else.

No runtime.

No libc.

No allocator.

No scheduler.

No startup library unless demanded by the target.

For suitable hardware:

    reset address
    -> generated instructions
    -> hardware

is a valid XAX deployment.

---

# 26. Operating systems and applications

The same language represents:

    firmware
    kernels
    drivers
    allocators
    compilers
    databases
    applications
    web servers
    GPU kernels
    AI runtimes

"High-level" functionality is provided by semantic libraries rather than by adding a second language.

Abstraction disappears during specialization when it has no runtime meaning.

---

# 27. Package system

A package is a content-addressed XAX module graph.

Dependency identity uses cryptographic hashes plus logical package identities where upgrade continuity is needed.

There is no JSON, YAML, TOML or external package language required.

Build configuration is XAX semantic data.

Build-time algorithms are XAX programs.

---

# 28. Autonomous development

The architecture assumes AI is the normal software engineer.

The toolchain therefore exposes machine operations for:

    query
    construct
    mutate
    verify
    test
    benchmark
    compare
    commit

A new AI session does not need to read thousands of source files.

It requests the smallest semantic neighborhood necessary to perform the task.

Repository size and model context size therefore become largely independent.

---

# 29. "No human involvement"

For XAX this means:

Human source-code authoring is not required.

Human naming is not required.

Human formatting is not required.

Human code review is not required for compilation.

Human-written target backends are not architecturally required.

Human-written build configuration is not required.

After bootstrap, an AI can construct XAX using the compiler's semantic interface, verify it, benchmark it and commit it.

Humans may still specify desired behavior, hardware requirements or policy.

They are users of the system, not a required stage of program representation.

---

# 30. Trusted core

To keep XAX small, the trusted foundation should contain only:

    canonical semantic definitions
    graph verifier
    canonical serializer
    minimal target-independent lowering machinery
    target encoder bootstrap

Almost everything else should eventually be implemented in XAX itself.

This includes the optimizer, compiler services, target definitions, linker functionality, package tooling and build system.

---

# 31. Performance rule

XAX contains no feature merely because it is elegant.

Every abstraction must satisfy one of two conditions:

    erased before runtime

or:

    explicitly requested runtime semantics

There are no hidden allocations.

There are no hidden locks.

There is no hidden reference counting.

There are no hidden syscalls.

There is no hidden initialization.

There are no hidden scheduler interactions.

---

# 32. Token-efficiency rule

The metric is not source characters.

The primary metric is:

    total AI tokens required
    /
    successful semantic change

Secondary metrics include context tokens, generated tokens, repair iterations, invalid transactions and semantic entities transmitted.

A representation that uses fewer bytes but causes more model mistakes loses.

A representation that is slightly larger but reduces repair turns may win.

This must be experimentally measured.

---

# 33. First prototype

*Status: achieved — M1–M5 (see `XAX_STATE.md`).*

XAX should not begin by implementing a giant language specification.

Version 0 needs only enough semantics to compile:

    b32/b64 constants
    integer arithmetic
    functions
    calls
    branches
    stack memory
    load/store
    return

The first implementation target should emit machine code directly for one architecture.

Then implement the same program on a second substantially different architecture using only a target package.

Only after this succeeds should ownership, SIMD, atomics, GPUs and high-level libraries be expanded.

---

# 34. First decisive experiment

*Status: open — historical C-vs-XAX rows are negative for XAX on tokens and not qualifying (OI-31); the tokenizer-native arm remains unavailable (OI-01).*

The first benchmark should compare four representations of the same small programs:

    C-like text
    conventional SSA text
    compact graph packets
    tokenizer-native XAX transactions

Measure creation, one-literal edits, control-flow edits, type-error repair and optimization tasks.

Record:

    input tokens
    output tokens
    invalid generation rate
    repair turns
    graph bytes
    compilation time
    generated machine code

If tokenizer-native semantic transactions do not substantially outperform source regeneration, this architecture must be reconsidered.

---

# 35. Universal replacement

The long-term objective is that one canonical AI-native semantic language removes the practical need to author software in C, C++, Rust, assembly, Java, Kotlin, C#, Swift, Objective-C, JavaScript, TypeScript, Python, Go, PHP, Ruby, Dart, Solidity, Fortran, COBOL, CUDA-style languages, shell languages, and their peers.

This does not mean reproducing their features. It means XAX is sufficient to build what they build:

    firmware, bootloaders, kernels, hypervisors, drivers
    embedded and real-time systems
    desktop, mobile, web, and browser/Wasm applications
    servers, distributed systems, databases, compilers
    game engines and games
    GPU kernels, scientific/HPC software, AI runtimes
    cloud infrastructure
    JVM/.NET/managed-platform applications
    scripting-style applications
    smart contracts and legacy/mainframe workloads where target specifications permit

A platform is **replacement-capable** when an AI can go

    intent -> XAX semantics -> verify -> optimize -> build -> deployable artifact

with no human-authored program in any other language. Compiler-generated adapters are permitted. Platform-required runtimes (ART, a JVM, the CLR, a WebAssembly engine, a GPU driver) are permitted only when the platform itself requires them and their behavior is represented by explicit platform/ABI contracts. Examples:

    browser   XAX -> WebAssembly + generated platform bindings -> browser
    Android   XAX -> native machine code and/or DEX -> Android
    JVM       XAX -> JVM-compatible artifact -> JVM
    .NET      XAX -> CLI-compatible artifact -> CLR
    Apple     XAX -> Mach-O + Apple ABI/framework contracts -> platform
    GPU       XAX -> target-specific GPU representation/binary -> device

The normative definition is `XAX_SPEC.md` §21.

---

# 36. Replacement conformance levels

Replacement is claimed per platform and workload, at cumulative evidence-gated levels:

| Level | Meaning |
|---|---|
| R0 | semantic expressibility: the workload is represented exactly in XAX |
| R1 | executable lowering: XAX directly produces an executable representation that ran |
| R2 | platform interoperability: ABI, system APIs, libraries, callbacks, dynamic loading, resources, lifecycle work |
| R3 | practical application: a nontrivial real workload ran |
| R4 | performance competitiveness: runtime, memory, binary size measured competitive with established toolchains |
| R5 | AI efficiency: tokens per successful change and repair rate measured better than textual-source workflows |
| R6 | autonomous maintenance: query, modify, verify, benchmark, rebuild, commit through semantic transactions |

Every implementation claim carries one label: PROVEN, EXECUTED, MEASURED, STRUCTURAL, PROTOTYPE, or UNIMPLEMENTED. No platform or language is "replaced" until the required evidence exists.

---

# 37. Kernel, libraries, and packages

Universality comes from layering, never from growing the kernel:

    tiny universal XAX kernel
        -> compile-time semantic construction
        -> zero-cost semantic libraries
        -> platform packages
        -> ABI packages
        -> target packages
        -> generated machine/platform artifact

The kernel stays approximately: values, exact arithmetic, aggregates, control, calls, memory, resources, effects, atomics, target operations, and compile-time/meta operations.

Before anything enters the kernel it must be shown that existing primitives cannot express it exactly and efficiently. Concepts such as class, object, trait, interface, async, future, string, dictionary, exception, and garbage-collected object are not kernel concepts. Duplicate mechanisms, speculative generality, extra layers, and per-domain DSLs are rejected. There is one semantic language.

Evidence for the layering (ADR-112, ADR-113): two architectures with nothing in common, a typed stack-machine VM (the JVM) and a load/store RISC ISA (RV64IM), were added with zero kernel changes. Neither needed a new operation, type form, terminator, or verifier rule for programs. Each added only a target architecture number with its machine tuple, a backend module, and (for the JVM) three foreign ABI names. Both run the same differential corpus against the same reference executor.

---

# 38. Zero-cost high-level abstraction policy

Target: **zero unavoidable language overhead**. Runtime cost may come only from semantics the program requests or from unavoidable requirements of the selected hardware/platform ABI.

Never mandatory: garbage collector, allocator, reference counting, object runtime, exception runtime, scheduler, async runtime, reflection runtime, libc, VM, JIT, initialization framework, dynamic loader, statically provable bounds checks, statically provable ownership bookkeeping, and any hidden synchronization, allocation, cleanup, syscall, stack object, or heap object.

Common programming models lower into existing semantics:

    closures            -> function + explicit environment
    objects             -> storage + functions
    interfaces/traits   -> specialization, or explicit dispatch table + call_indirect
    generics            -> compile-time specialization
    async/coroutines    -> explicit state machine (+ scheduler capability when needed)
    exceptions          -> sums/control, or explicit foreign-unwind adapter
    GC                  -> optional collector package with explicit roots
    reference counting  -> explicit library operations
    reflection          -> compile-time introspection; retained metadata only when requested
    dynamic typing      -> tagged/boxed representations from libraries
    strings/collections -> explicit representations + libraries
    actors/tasks        -> libraries
    GPU kernels         -> target/platform packages

A program that does not use a model pays nothing for it. Safety follows `prove -> erase check`; when proof fails the policy is explicit (reject, checked operation, explicit trap, or raw waiver), and undefined behavior is never silently turned into optimizer permission.


Recursion follows the same rule (ADR-125). A recursive strongly connected component is one content-addressed recursion group, and its member identity `(group, index)` is callable like any function. Backends see a group-local call as an ordinary direct call, so recursion costs exactly a call on every target and adds no runtime. A backend that cannot make frame storage reentrant, which today is wasm32 for stack allocations and aggregates, rejects the program rather than sharing frames.

---

# 39. Executable and object formats

Containers are target/platform package responsibilities: raw load images, ELF, PE/COFF, Mach-O, WebAssembly modules, DEX/APK, classfiles/JARs, CLI assemblies, GPU binaries.

A container adds no code beyond explicit platform contracts. Import tables, relocations, headers, and section layout are derived deterministically from semantic identity. Process start and exit, loaders, TLS, and unwind data are explicit platform contracts, not container conveniences.

Current containers: raw load images (x86-64, AArch64, RISC-V RV64), PE32+, ELF64 `ET_EXEC` and Android `ET_DYN`, WebAssembly modules, generated browser pages, DEX/APK, and JVM class files in a stored JAR (ADR-112). The JAR is byte-deterministic (fixed entry order and timestamps, no compression). Its `Main-Class` is a compiler-generated `main(String[])` that calls the proof-only XAX entry; this is the platform's required entry, recorded in the matrix row's `runtime_requirement`.

First hosted evidence: XAX emits a PE32+ executable directly, with kernel32 imports bound through the loader-filled import table and process exit as an explicit `ExitProcess` call. The container contains zero bytes of startup code. Linux follows the same rule (ADR-086): `e_entry` is the XAX entry function, the program calls `exit_group` explicitly, and the entry is lowered for Linux's aligned, no-return-address start, so returning traps. A static profile emits only one load segment. An explicit-loader profile adds `PT_INTERP` and `DT_NEEDED` derived from declared C imports, with bind-now GOT slots (ADR-087). Linux AArch64 reuses the same rules on the shared AAPCS64 lowerer (ADR-123): the container adds only an 8-byte `e_entry` stub that traps if the entry returns, one thunk per declared syscall, and one GOT thunk per declared C import. The unchanged `filestat` graph runs there with glibc and `libz.so.1` (under qemu-aarch64). GPU kernels are SPIR-V 1.3 modules (ADR-124). Native hosted platforms need: complete calling conventions, relocations, TLS, atomics, vectors, unwind data when required, and static/dynamic linking when requested.

---

# 40. Foreign ecosystem import

A universal replacement cannot require rewriting the world. Interop is mandatory for: C ABI and headers, POSIX, Win32, Objective-C runtime/framework APIs, JVM metadata, .NET metadata, Android SDK/DEX/JNI, browser/Web APIs, system calls, GPU APIs, and existing shared/static libraries.

Deterministic importers convert external metadata into XAX platform/ABI packages of typed foreign declarations. No human writes wrapper source. There is no universal ABI: C++ and other complex ABIs are explicit ABI packages. Foreign exceptions, ownership, aliasing, lifetime, callbacks, thread requirements, dynamic loading, and calling conventions stay visible to verification. Each foreign ABI is owned by one backend, which rejects the others.

Current ABIs: `android-aapcs64-c`, `win64-c`, `wasm32-import`, `linux-x86_64-syscall-v1`, `sysv-x86_64-c`, and the JVM member ABIs `jvm-invokestatic`, `jvm-invokevirtual`, and `jvm-getstatic` (ADR-112). A JVM declaration's identity carries the class's internal name and the exact member descriptor, and the compiler rejects a descriptor that disagrees with the declared XAX types. JVM object references are `ptr<opaque-identity "jvm-ref:<descriptor>">`: handles that no XAX memory operation accepts. Syscall declarations carry an explicit register template in their identity, so a property such as "anonymous mappings are zero-filled" is part of the declaration rather than an assumption about caller arguments (ADR-085). `sysv-x86_64-c` calls real shared libraries (EXECUTED and MEASURED: `libz.so.1` `crc32`) and covers register-passed INTEGER and SSE scalars. C can call back into pure XAX functions: the calling convention is part of the code-address type, and the compiler generates the adapter (ADR-102, EXECUTED with libc `tsearch`). A callback may also read memory the C call was lent: a lend entry's type names the view, and the call that receives it must lend that view for exactly its own duration (ADR-115, EXECUTED with glibc `qsort_r` sorting an XAX array). Aggregates and variadics remain OI-40. Linux AArch64 adds `linux-aarch64-syscall-v1` (the same template identity) and `aapcs64-linux-c` (ADR-123).

---

# 41. Hosted managed targets

JVM, Android DEX/ART, and .NET CLI/CLR are targets and platforms. Java, Kotlin, and C# semantics are not reproduced in the kernel. Where a managed runtime is required, XAX emits its artifact format directly (as already done for DEX) or emits native code plus a compiler-generated managed bridge; any GC or object-model interaction is an explicit platform contract.

JVM evidence (ADR-112, EXECUTED on HotSpot 21). `jvm-classfile-v1` lowers verified XAX directly to class-file bytecode, with no Java source, `javac`, or bytecode library. Bits up to 64 become `int`/`long`, f32/f64 become strict `float`/`double`, functions become static methods, and blocks become labelled code with uniform StackMapTable frames. The HotSpot verifier accepts every emitted class. A trap is `athrow` of `java.lang.Error`; integer division by zero is the JVM's own `ArithmeticException`. A Java exception escaping a foreign call terminates the program like a trap, so XAX code never observes it. On a Collatz kernel the result runs at 1.04× the kernel time of the `javac`-compiled Java twin on the same JVM, with a class file 1.51× larger. Adding the JVM changed no kernel semantics: it needed one target architecture number, three foreign ABI names, and one backend module.

---

# 42. Web and browser target model

The web target is WebAssembly plus platform contracts: WASI for system interfaces, browser host APIs (DOM, fetch, WebGPU, events) through declarations imported from Web IDL-class metadata. XAX never requires handwritten JavaScript. If a host requires glue, the compiler generates it deterministically from explicit platform semantics and records it in provenance.

First evidence (ADR-103, EXECUTED in headless Chromium): target `wasm32-browser-v1` and the `xax-web-v1` binding package. The page is one generated HTML file containing the module plus host functions for exactly the bindings the module imports. An XAX program reads its URL, computes, renders into the DOM, and handles clicks through an XAX event entry (ADR-104, which reuses the ADR-102 code-entry type). A Web IDL importer is OI-32.

---

# 43. Production GPU and accelerator path

Target packages model SIMT/SIMD execution, memory spaces, synchronization scopes, barriers, kernels, launches, shared/workgroup memory, host/device ownership, and device resources. The same core semantics map to SPIR-V/Vulkan, CUDA-compatible targets, Metal, DXIL, and future accelerators. Launch, transfer, and synchronization are explicit effects/resources; there is no XAX device runtime. The synthetic M13 target proves the package mechanism; production requires physical-device execution and vendor-baseline measurements.

Bare metal (ADR-128, ADR-129): a board package lists the board's registers and instructions (UART, interrupt controller, timer, `wfi`, power-off) as typed target operations on a device effect, together with interrupt handler contracts. The image adds only a reset stub, a fault path, and a vector table that calls contract-checked XAX handlers. Existing freestanding C objects are linked in by an exact relocation subset, and each foreign declaration names the object that defines its symbol.

First real representation (ADR-124): SPIR-V for Vulkan. A kernel is an ordinary XAX function; the target-owned entry contract maps its first parameter to the global invocation index and its borrowed view triples to storage-buffer bindings. Nothing was added to the kernel. Concurrency is not assumed safe: the target checks that every store, and every load of a stored-to buffer, touches only the invocation's own element. Any control-flow graph lowers to one structured dispatch loop, and traps become a status word raised with `atomicMax`. Kernels run on Mesa llvmpipe with buffers and traps equal to the reference executor. On that CPU device the dispatch loop costs 6.9× an equivalent glslang kernel, so structured lowering of reducible graphs and a physical-GPU run are the next steps (OI-34).

Embedded and bare-metal targets require: no runtime, deterministic startup, exact sections/layout, interrupts, MMIO, DMA, volatile operations, custom layout semantics, fixed memory budgets, optional zero allocation, and bounded stack analysis where requested. Legacy and specialized targets (mainframes, legacy ISAs, DSPs, consoles, custom accelerators) are added as target packages whenever target/ABI information exists, never hardcoded.

---

# 44. Standard semantic library strategy

A minimal modular ecosystem, not a runtime: allocators, arenas, text, slices, arrays, maps, sets, numerics, big integers, filesystem, sockets, HTTP, TLS integration, threads, synchronization, event loops, serialization, compression, cryptography interfaces, graphics, audio, databases, SIMD, tensors, GPU compute.

Programs link only what they semantically require. Unused packages contribute zero runtime code and data. Every package's runtime behavior is explicit effects, resources, and capabilities.

---

# 45. Compiler optimization trajectory

Universal replacement needs far stronger optimization than a prototype backend. The path is incremental: constant propagation/folding, dead-code elimination, CFG simplification, inlining, specialization, devirtualization, escape analysis, scalar replacement, load/store forwarding, alias-aware optimization, GVN/CSE, LICM, loop simplification/unrolling/vectorization, SLP, strength reduction, bounds-check elimination, interprocedural and whole-program optimization, PGO, code layout, instruction selection, peephole, scheduling, register allocation, and bounded superoptimization where justified.

Every transformation preserves exact observable semantics; high-risk and search transformations use translation validation or equivalence checking. Profile data stays non-semantic unless promoted into build identity. Parallel compilation never alters semantics. Optimizer machinery migrates into XAX where practical. LLVM is never a permanent architectural dependency.

Current state (MEASURED). New targets reuse the same lowering ideas. The JVM backend fuses each compare with its branch, strength-reduces power-of-two division, and gives block-local values scratch locals (ADR-112). The RISC-V backend runs a linear scan over block-liveness hulls into the eleven callee-saved registers, which cut its Collatz instruction count from 15.9× to 3.72× `clang -O2` (ADR-113). Two register-resident x86-64 allocators exist: PE (ADR-083) and Linux (ADR-089; ADR-091 adds pinned loop values, fall-through layout and cold trap stubs, bringing `chains` from 3.49× to 1.91× `gcc -O2`). Convergence is OI-38. On the Linux `filestat` workload the frame path measured 5.9× `gcc -O2`; the Linux allocator measures 0.95–1.14× `gcc -O2` and 1.41–1.82× `clang -O2` across seven runs, validated against the reference executor on a random-program corpus. Cross-block allocation, LICM, and loop transformations come next.

---

# 46. Practical debugging and observability

Current derived views: semantic byte ranges for every native, wasm, JVM, and RISC-V artifact through the workspace `artifact`/`map_semantic` queries. For the JVM, a `LineNumberTable` numbers each XAX node, so a platform stack trace names the exact semantic node (ADR-112, EXECUTED: an `ArithmeticException` trace maps back to its `UDIV` node).

Production use requires observability through derived, non-authoritative views: semantic-to-machine maps, crash location mapping, stack traces where platforms permit, disassembly maps, profiling, debugger integration, coverage, sanitizer/instrumentation builds, and deterministic diagnostics. Instrumented builds are separate build policies. None of these views becomes source.

---

# 47. Replacement evidence matrix and benchmarks

`XAX_REPLACEMENT_MATRIX.json` tracks each platform: semantic expressibility, code generation, ABI, artifact format, platform APIs, FFI, concurrency, atomics, SIMD, dynamic linking, debugging, optimization maturity, runtime requirement, real execution, performance/memory/code-size/AI-token evidence, blockers, and replacement level. Levels are derived from cited evidence by a validator; unchecked boxes never become claims.

Replacement benchmarks compare XAX against the platform's established toolchains (optimized C/C++, Rust, platform-native compilers, WebAssembly toolchains, GPU toolchains, hand-written assembly where credible), recording hardware, OS, toolchain versions, settings, workload, warmup, repetitions, variance, binary size, peak memory, and time. Benchmark definitions are never tuned to favor XAX. AI benchmarks measure total successful-task tokens and repair counts on real models; repository size should have as little relationship as possible to task context size.

The goal is not "faster than assembly"; it is:

    minimize selected target cost
    subject to exact semantics

Snapshot (2026-10-03, after ADR-129): R3: linux-aarch64, linux-x86_64; R2: aarch64-baremetal, android-arm64, browser-web, jvm; R1: gpu-spirv-cuda-metal-dxil, riscv64, wasm32-core, wasm32-wasi, windows-x86_64-pe; R0: accelerator-simt-packet; no row yet: dotnet-clr, macos-ios-apple, rtos-embedded-mcu. Linux x86-64 reached R3 with `jsonmin`, a validating JSON minifier that recurses through a recursion group; it measures 1.20× gcc -O2 after bit-test selection (ADR-131), so the row is not R4, and the matrix now requires an explicit `competitive` verdict before R4 can derive. Emulator and software-device execution (QEMU, Unicorn, llvmpipe) count as EXECUTED for correctness, never as performance evidence, and each such row lists "not hardware" as a blocker (ADR-114).

The first replacement milestone (U1) is a hosted native application, a bare-metal program, a WebAssembly/WASI or browser application, an Android application, and an accelerator workload, all from XAX semantics, measured against established implementations.

---

# 48. Core invariant

The fundamental XAX rule is:

    meaning is source

not:

    text describes source

Everything else follows from this.

XAX therefore becomes less like C, Rust or assembly and more like a direct communication protocol between an AI reasoning system and a verified optimizing compiler.

The human sees whatever visualization is useful.

The AI sees whatever semantic neighborhood is useful.

The processor sees machine instructions.

None of those representations is forced to resemble the others.

The same semantic system must scale from tiny bare-metal firmware to operating systems, native, web, and mobile applications, servers and databases, games, and GPU/HPC/AI workloads, without imposing the costs of one domain on another:

    The AI should communicate meaning,
    the compiler should own representation,
    and the hardware should receive only what execution requires.
