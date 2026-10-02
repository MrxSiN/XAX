# XAX — AI-Native Programming Language Architecture v0.1

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
| 1 | Exact semantics |
| 2 | Minimum AI token expenditure |
| 3 | Minimum probability of AI generation error |
| 4 | Native machine performance |
| 5 | Minimal memory/code footprint |
| 6 | Universal hardware targeting |
| 7 | Determinism |
| 8 | Incremental/local modification |
| 9 | Compiler simplicity |
| 10 | Human usability |

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

# 35. Core invariant

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
