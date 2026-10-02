# 18 — Universal Replacement

**Status:** normative (v0.2).  
**Authority:** this document refines `XAX_SPEC.md` §21. On conflict, `XAX_SPEC.md` §1 precedence governs and this document is corrected.  
**Machine state:** `docs/universal_replacement_matrix.json`, validated by `compiler/src/xax_replacement.py` and `compiler/tests/test_xax_replacement_matrix.py`.

## 1. Objective

XAX aims to remove the *practical need* to author software in C, C++, Rust, assembly, Java, Kotlin, C#, Swift, Objective-C, JavaScript, TypeScript, Python, Go, PHP, Ruby, Dart, Solidity, Fortran, COBOL, CUDA-style languages, shell languages, and comparable languages.

This is **not** reproduction of those languages' features. It is sufficiency for the *software* they are used to build: firmware, bootloaders, kernels, hypervisors, drivers, embedded and real-time systems, desktop/mobile/web/browser applications, servers, distributed systems, databases, compilers, game engines, GPU kernels, scientific/HPC code, AI runtimes, cloud infrastructure, managed-platform applications, scripting-style tools, smart contracts where the target permits, and legacy/mainframe workloads where target specifications permit.

The invariant is unchanged: **meaning is source** (`FND-001`). Universal replacement never introduces a human textual language, a second meta language, or a mandatory runtime.

## 2. Definition (UR-001)

A target platform or workload class is **replacement-capable** when an AI can perform

```text
intent -> construct XAX semantics -> verify -> optimize -> build -> deployable artifact
```

without any human-authored program in another programming language.

| ID | Requirement |
|---|---|
| UR-001 | A replacement claim names one target/platform *and* one workload class. "XAX replaces C" without both is not a claim. |
| UR-002 | Compiler-generated adapters are permitted only when deterministic, derived from explicit XAX platform/ABI contracts, and attributable in artifact provenance. |
| UR-003 | A platform-required runtime (ART, CLR, JVM, a browser engine, a GPU driver) is permitted only because the platform itself requires it, and only through an explicit platform/ABI contract. XAX never adds its own mandatory runtime. |
| UR-004 | A replacement claim carries the highest level from §3 whose evidence obligations are all met, and no higher. |
| UR-005 | Claims are recorded in the replacement matrix with evidence labels from §4; prose elsewhere may cite but never exceed the matrix. |

Examples of the required shape (each is a target/platform description, not a claim):

```text
Browser:  XAX -> WebAssembly + generated platform bindings -> browser
Android:  XAX -> native machine code and/or DEX -> ART
JVM:      XAX -> class files -> JVM
.NET:     XAX -> CLI assembly -> CLR
Apple:    XAX -> Mach-O + Apple ABI/framework contracts -> platform
GPU:      XAX -> target GPU representation/binary -> device
Linux:    XAX -> ELF64 executable + syscall contract -> kernel
```

## 3. Replacement conformance levels

Levels are cumulative. A level is reached only when every lower level is reached for the same target and workload class.

| Level | Name | Evidence obligation |
|---|---|---|
| **R0** | Semantic expressibility | A representative workload exists as verified canonical XAX semantics, and its observable behavior is exactly specified (reference execution or independent reference contract). |
| **R1** | Executable lowering | XAX directly produces a valid deployable artifact in the target's native format, and that artifact **executed** on the target (hardware, OS, or the platform's own engine). An emulator counts only when recorded as such. |
| **R2** | Platform interoperability | Required ABI, system APIs, foreign libraries, callbacks, dynamic loading, resources, and platform lifecycle work **in execution** for the declared workload class. Missing classes are listed as blockers. |
| **R3** | Practical application capability | A nontrivial real application or workload (not a fixture) executes successfully with real I/O, data structures, and error paths. |
| **R4** | Performance competitiveness | Runtime, peak memory, and binary size are **measured** against the platform's established optimized toolchain under `XAX_BENCHMARKS.md` §15, and are within the declared competitiveness bound (default: median runtime ≤ 1.10× the best baseline, peak memory and binary size ≤ the best baseline, or a stated bound justified in the claim). |
| **R5** | AI efficiency | Real model trials show total tokens per successful semantic change and repair counts beat or materially improve on the textual-source workflow for the same tasks (`XAX_BENCHMARKS.md` §6). |
| **R6** | Autonomous maintenance | An AI queries, modifies, verifies, benchmarks, rebuilds, and commits the R3 application through semantic transactions without whole-source regeneration, with recorded runs. |

No platform or language is described as "replaced" until the matrix records R3 or higher for that platform and workload class. R4–R6 are reported separately and never inferred from R3.

## 4. Evidence labels

Every implemented claim in normative and state documents carries exactly one label. A stronger label requires stronger evidence; missing evidence downgrades the label.

| Label | Meaning |
|---|---|
| **PROVEN** | Established by a machine-checked proof or exhaustive validation over the stated domain. |
| **EXECUTED** | The artifact ran on the stated target (host, device, engine, or recorded emulator) and observable results matched the specification. |
| **MEASURED** | EXECUTED, plus quantitative results recorded under the benchmark policy (hardware, OS, toolchains, settings, repetitions, variance). |
| **STRUCTURAL** | The artifact is produced and validated structurally (format checks, decoders, verifiers) but has not executed on the target. |
| **PROTOTYPE** | Partial or synthetic implementation exercising the architecture without a real target (e.g. a synthetic deployment packet). |
| **UNIMPLEMENTED** | No implementation. Architectural intent only. |

Architecture goals are not implementation facts. A host-unavailable test is UNIMPLEMENTED for that host's claim, never "passed".

## 5. Layer hierarchy and kernel admission

```text
tiny universal XAX kernel
    -> compile-time semantic construction (META)
    -> zero-cost semantic libraries
    -> platform packages
    -> ABI packages
    -> target packages
    -> generated machine/platform artifact
```

| ID | Rule |
|---|---|
| UR-010 | The kernel is limited to: values, exact arithmetic, aggregates, control, calls, memory, resources, effects, atomics, target operations, and compile-time/meta operations. |
| UR-011 | **Kernel admission rule.** A new kernel operation or type family requires an ADR showing that it cannot be expressed exactly *and* efficiently (no avoidable runtime, size, or token cost after ordinary lowering) using existing primitives, and that it duplicates no existing mechanism. |
| UR-012 | Language-specific concepts (class, object, trait, interface, async, future, string, dictionary, exception, garbage-collected object, …) are not kernel concepts unless UR-011 is met. |
| UR-013 | A library or platform facility a program does not use contributes zero code, data, initialization, and metadata to its artifact. |
| UR-014 | There is one semantic language. Platform, ABI, and target packages are XAX semantic data; no DSL is introduced for them. |

The 2026-10-02 integer completion (`bit.and`, `bit.or`, `udiv`, `urem`, `int.truncate`, `int.zero_extend`) was admitted under UR-011 (ADR-077). Shifts and sign extension were **not** admitted: they are exact compositions of existing operations (`shl k` = `mul.wrap 2^k`, `lshr k` = `udiv 2^k`, `sext` = `(zext(x) ^ m) - m`), and their cost is a strength-reduction/instruction-selection question (OI-34).

## 6. Zero-cost high-level abstraction policy

An abstraction is acceptable only when it is **erased before runtime** or its runtime semantics were **explicitly requested** (`FND-010`). The canonical lowerings below are the required design; each row's status is the implementation label today.

| Programming model | Lowering into kernel semantics | Runtime cost appears only when | Status |
|---|---|---|---|
| Closures | function + explicit environment aggregate/pointer | environment escapes to storage the program allocated | PROTOTYPE (function pointers + aggregates executed; no closure library) |
| Objects | storage + functions over it | the program allocates the storage | EXECUTED (aggregates, pointers, calls) |
| Interfaces/traits | compile-time specialization, or an explicit dispatch table + `call_indirect` | dynamic dispatch is requested | EXECUTED (bounded `call_indirect` on x86-64/AArch64) |
| Generics | compile-time specialization (META) | never (erased) | PROTOTYPE (M9 bounded construction) |
| async/coroutines | explicit state machine (sum + block parameters) + a scheduler capability when needed | a scheduler package is linked by request | UNIMPLEMENTED |
| Exceptions | sums + control; foreign unwinding only through an explicit unwind adapter | a foreign ABI requires unwinding | EXECUTED (errors as sums); foreign unwind UNIMPLEMENTED |
| Garbage collection | optional allocator/collector package with explicit roots and effects | the program links the collector | UNIMPLEMENTED |
| Reference counting | explicit library operations on explicit counts | the program calls them | UNIMPLEMENTED (library) |
| Reflection | compile-time introspection; retained runtime metadata only when requested | metadata is requested | PROTOTYPE (M14 graph introspection) |
| Dynamic typing | tagged values (sums) / boxed library representations | the library is used | PROTOTYPE (sums executed; no library) |
| Strings | byte-slice representation + explicit library operations | operations are called | PROTOTYPE (UTF-8 slice type; library code is Python tooling, not XAX semantics) |
| Collections | semantic libraries over explicit storage | used | PROTOTYPE (U1 histogram over explicit `mmap` storage) |
| Actors/tasks | libraries over atomics, resources, and platform thread capabilities | used | UNIMPLEMENTED |
| GPU kernels | target/platform packages behind generic `target` operations | a device is targeted | PROTOTYPE (M13 synthetic SIMT packet) |

## 7. Universal platform architecture

Core semantics hardcode no ISA, OS, object format, or ABI (`FND-006`). Every class below is reached through target, ABI, and platform packages.

| Class | Required package content | Current status |
|---|---|---|
| CPU (x86-64, AArch64, RISC-V, future ISAs) | instruction semantics, registers, calling conventions, relocations, object/executable formats, TLS, atomics, vectors, unwind data when required | x86-64 EXECUTED (Linux static/dynamic ELF, Windows raw image); AArch64 EXECUTED (Android device, QEMU bare metal); RISC-V UNIMPLEMENTED |
| Operating systems (Linux, Windows, macOS, BSD, Android, Apple mobile, bare metal, RTOS) | process-entry contract, syscall or system-API ABI, loader/format contract | Linux x86-64 static and dynamic EXECUTED; Android EXECUTED (Activity); bare metal EXECUTED (raw image, QEMU); others UNIMPLEMENTED |
| Web (Wasm, WASI, browser host, DOM/Web APIs, WebGPU) | core module + generated, deterministic host bindings from platform contracts; no handwritten JavaScript | core Wasm EXECUTED (Node harness, no imports); WASI/browser bindings UNIMPLEMENTED |
| Managed (JVM, Android DEX/ART, .NET CLI/CLR) | managed runtime is a *target*; XAX emits its artifact format; Java/C#/Kotlin semantics never enter the kernel | DEX EXECUTED on ART (bounded Activity); JVM/CLI UNIMPLEMENTED |
| GPU/accelerators (SPIR-V/Vulkan, CUDA-compatible, Metal, DXIL) | execution topology, scopes, memory spaces, barriers, launches, host/device ownership | synthetic SIMT PROTOTYPE; no real device |
| Embedded/bare metal | no runtime, deterministic startup, exact sections/layout, interrupts, MMIO, DMA, volatile, fixed budgets, optional zero allocation, bounded stack | raw images EXECUTED (QEMU); DMA vocabulary EXECUTED in harness (OI-07); sections/linker layout UNIMPLEMENTED |
| Legacy/specialized (mainframes, DSPs, consoles, custom accelerators) | additional target packages when target/ABI information is available | UNIMPLEMENTED; never hardcoded |

Target packages must remain able to express unusual registers, irregular instruction sets, predication, vector-length-dependent execution, SIMT, capabilities, tagged memory, multiple memory spaces, asynchronous devices, non-coherent memory, target-specific atomics, unusual traps, and architecture security features (`XAX_SPEC.md` §11). Future hardware is added by packages, never by kernel redesign.

## 8. Foreign ecosystem import and interoperability

A universal replacement cannot require rewriting the world.

| ID | Rule |
|---|---|
| UR-020 | Every foreign call names an ABI from the verifier's foreign-ABI registry (`FOREIGN_CALL_ABIS`). An unknown ABI is rejected (`XAX.FOREIGN.ABI`). |
| UR-021 | A foreign declaration's identity carries everything the lowering needs: symbol or service identity, ABI, typed inputs/outputs, ownership/allocation contracts, and any fixed arguments. Lowering may not consult unstated tables. |
| UR-022 | Deterministic importers should convert external metadata (C headers/API descriptions, POSIX, Win32, Objective-C runtime metadata, JVM class files, .NET metadata, Android SDK/DEX/JNI, Web IDL, syscall tables, GPU API descriptions, shared/static library symbol tables) into XAX semantic packages. Importers are tools; their output is ordinary canonical XAX. |
| UR-023 | C++ and other complex foreign ABIs are handled by explicit ABI packages; no universal ABI is assumed. |
| UR-024 | Foreign exceptions, ownership, aliasing, lifetime, callbacks, thread requirements, dynamic loading, and calling conventions remain visible to verification. |

Implemented today: `android-aapcs64-c` foreign calls (EXECUTED on device for JNI), Android SDK/JAR API-version import (STRUCTURAL), JNI 1.6 table package (STRUCTURAL/EXECUTED for the Activity fixture), `linux-x86_64-syscall-v1` (EXECUTED), and `sysv-x86_64-c` (EXECUTED; §8.3). Generic C-header/Win32/ObjC/JVM/.NET importers are UNIMPLEMENTED (OI-35).

### 8.1 `linux-x86_64-syscall-v1`

A syscall declaration is an ordinary foreign function carrier with `abi = "linux-x86_64-syscall-v1"`, `library = "linux"`, and a canonical **register template** name:

```text
name = nr                      -- machine operands passed in order
name = nr ":" arg ("," arg)*   -- arg = "$k" (k-th machine operand) | unsigned 64-bit decimal literal
```

Each machine operand is used exactly once. Arguments go to `rdi, rsi, rdx, r10, r8, r9`; `rax` carries the number and the exact 64-bit result. Proof values (effects, resources) are erased. For a declaration with an allocator contract, the kernel's error range `-4095..-1` is projected to the contract's nullable (zero) pointer, and `heap.view` then traps explicitly on null. Fixed literals (e.g. `PROT_READ|PROT_WRITE`, `MAP_PRIVATE|MAP_ANONYMOUS`, `fd = -1`) live in the template, so properties such as "anonymous mappings are zero-filled" are part of the declaration identity rather than an assumption about caller arguments.

### 8.2 Linux process-entry contract

For `x86_64-linux-elf-exec-v1`, the entry function has only erased proof parameters (initial effect frontiers) and returns one `bits<8>` or `bits<32>` status plus proof values. The only compiler-generated code is the documented 9-instruction adapter: reserve the x64 home area, call the entry, and pass its status to `exit_group`. There is no libc, dynamic loader, `_init`, TLS setup, or allocator. `argv`/`envp`/auxv access is not yet part of the contract (OI-36).

### 8.3 `sysv-x86_64-c`

`sysv-x86_64-c` declarations import a C function by symbol from a shared library named by its soname (`library`). They lower only on `x86_64-linux-elf-dynexec-v1`, which explicitly requests the system loader `/lib64/ld-linux-x86-64.so.2`; on the static profile they reject (`SYSV-C-REQUIRES-DYNAMIC-PROFILE`). `DT_NEEDED` entries are exactly the declared libraries. Every import gets one bind-now `R_X86_64_GLOB_DAT` GOT slot and is called with `call [rip+slot]`. Arguments use the psABI INTEGER class only — at most six integer or pointer arguments in `rdi, rsi, rdx, rcx, r8, r9` and at most one integer or pointer result in `rax`. Floats, aggregates, stack arguments, variadics, and callbacks reject (`SYSV-C-INTEGER-CLASS`). ELF lookup is global, so one symbol name cannot be declared from two libraries in one artifact (`XAX.LINUX.IMPORT`); the declared library is enforced as a load dependency, not as a direct binding.

## 9. Hosted managed targets and the web

Managed runtimes (JVM, ART, CLR) and browsers are *targets*. XAX emits their artifact formats directly (class files, DEX, CLI assemblies, Wasm modules) together with generated, deterministic bridge code described by platform contracts (ADR-062 is the precedent: the smallest direct DEX-to-XAX adapter). XAX never requires handwritten Java, Kotlin, C#, or JavaScript glue; when glue is unavoidable it is compiler-generated, attributable, and represented by explicit platform semantics.

## 10. Production GPU/accelerator path

The M13 synthetic SIMT target established the package shape: topology, scopes, memory spaces, and typed target-operation contracts behind one generic `target` operation. The production path adds real target packages (SPIR-V/Vulkan first, because it is vendor-neutral and self-describing) with real device execution evidence. No GPU claim above PROTOTYPE exists until a kernel executes on physical hardware with measured results (OI-39).

## 11. Standard semantic library strategy

The standard ecosystem is a set of small, optional, content-addressed XAX semantic packages, never a mandatory runtime. Candidate packages: allocators and arenas, slices/arrays, strings/text, maps/sets, numeric algorithms, big integers, filesystem, sockets, HTTP, TLS integration, threads, synchronization, event loops, serialization, compression, cryptography interfaces, graphics, audio, database interfaces, SIMD, tensors, GPU compute.

Rules: programs link only what they semantically require (UR-013); every package states its effects, resources, and allocation behavior; a package that hides allocation, locking, syscalls, or initialization is non-conforming. Python modules under `compiler/src` that model library behavior (e.g. `xax_strings.py`) are tooling and do not count as XAX libraries (OI-40).

## 12. Executable and object formats

Artifact infrastructure is shared across targets:

| Format | Status |
|---|---|
| ELF64 ET_EXEC (Linux x86-64, static) | EXECUTED (U1) |
| ELF64 ET_EXEC with `PT_INTERP`, `DT_NEEDED`, bind-now GOT (Linux x86-64 dynexec) | EXECUTED/MEASURED (U1) |
| ELF64 ET_DYN (Android arm64 shared object) | EXECUTED (device) |
| DEX 039 / APK v2 signing | EXECUTED (device, bounded Activity) |
| Wasm core module | EXECUTED (Node harness) |
| Raw load images (x86-64 Windows, AArch64 bare metal) | EXECUTED (historical host/QEMU evidence) |
| PE/COFF, Mach-O, relocatable objects (ET_REL/COFF/Mach-O object), static archives, PIE/ET_DYN executables | UNIMPLEMENTED |

## 13. Practical debugging and observability

Production use requires derived, non-authoritative views: semantic-to-machine mapping, crash-location mapping, stack traces where the platform permits, disassembly mapping, profiling, debugger integration (DWARF/PDB/CodeView generated from retained ranges), coverage, sanitizer/instrumentation builds, and deterministic diagnostics. These views are never authoritative source. Implemented today: exact `ArtifactSemanticRange` retention per node and target-neutral workspace mapping (EXECUTED for raw images; the U1 ELF emitter re-bases ranges to file offsets, STRUCTURAL). Debug-format emission is UNIMPLEMENTED (OI-41).

## 14. Replacement evidence matrix

`docs/universal_replacement_matrix.json` is the only authoritative record of replacement status. For each target it records: semantic expressibility, code generation, ABI, artifact format, platform APIs, FFI, concurrency, atomics, SIMD, dynamic linking, debugging, optimization maturity, runtime requirement, real execution status, performance evidence, memory evidence, code-size evidence, AI-token evidence, known blockers, and replacement conformance level. Each capability carries a §4 label, evidence paths, and a note. The validator rejects:

* unknown labels or missing capabilities;
* EXECUTED/MEASURED/PROVEN entries without an existing evidence path;
* a replacement level whose §3 obligations are not met by the recorded labels;
* a runtime requirement that names a XAX-added runtime.

Unchecked boxes are never marketing claims.

## 15. Universal replacement benchmarks

Every replacement-level performance claim follows `XAX_BENCHMARKS.md` §15: exact hardware, OS, toolchain versions, optimization settings, workload, warmup, repetitions, variance, binary size, peak memory, execution time, and code properties where useful, against appropriate optimized baselines. Benchmark definitions are never tuned to favor XAX. "Faster than assembly" is never claimed universally; the objective is *minimize the selected target cost subject to exact semantics* (`FND-008`).

## 16. First universal-replacement milestone (UR-M1)

UR-M1 proves the transition from "compiler architecture prototype" to "practical general-purpose replacement". All five items originate from XAX semantics:

| Item | Requirement | Status (2026-10-02) |
|---|---|---|
| U1 | Native hosted CPU application with real allocation, filesystem I/O, an external/dynamic library call, nontrivial control flow, and data structures, with no hidden language runtime; measured against an optimized baseline | **Capabilities EXECUTED and MEASURED; level R2.** Linux x86-64 `filestat`: allocation (`mmap`), filesystem I/O, a 41-block control flow, a histogram, and a dynamic `libz.so.1` `crc32` call through an explicitly requested loader, with no XAX runtime. 5.9× slower than `gcc -O2`; 23,472 B vs 718,872 B static; 1,204 KiB vs 716 KiB peak RSS. R3 needs an application rather than a benchmark utility. |
| U2 | Bare-metal program with deterministic startup and exact layout | Partial: raw AArch64 images EXECUTED in QEMU (historical); startup/section layout UNIMPLEMENTED. |
| U3 | WebAssembly/browser or WASI application | Partial: core modules EXECUTED in Node; WASI/browser bindings UNIMPLEMENTED (OI-37). |
| U4 | Android application | Partial: bounded Activity EXECUTED on Pixel 8 Pro; nontrivial application UNIMPLEMENTED. |
| U5 | Accelerator/GPU workload | PROTOTYPE only (OI-39). |

UR-M1 closes only when all five items reach R3 for their declared workload classes and U1 additionally records R4 measurements (competitive or not).
