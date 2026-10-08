# XAX Implementation Roadmap

This roadmap orders implementation work. A milestone is complete only when every exit criterion is supported by committed conformance/evidence artifacts. “Benchmark valid” means measurable, not favorable.

## 1. Sequencing rules

1. Semantic correctness precedes optimization.
2. Canonical storage/identity precedes distributed editing and self-hosting claims.
3. The first backend MUST emit native bytes directly; a temporary external backend may help bootstrap development but cannot define the final architecture.
4. A second materially different target is required before claiming universal target-package adequacy.
5. Runtime/profile dependencies introduced by lowering must be exposed before profile validation.
6. Self-hosting status follows B0–B6 evidence and is not inferred from implementation language alone.
7. Later milestones MUST NOT silently change the semantics of earlier accepted vectors; semantic changes require versioning.
8. Post-M14 milestones (U-series) are defined by replacement-matrix evidence: a step is complete only when its matrix row changes under the validator.

## M1 — Minimal canonical semantic store and verifier

**Entry criteria**

- merged v0.1 specification and canonical serialization rules accepted;
- v0.1 hash suite fixed to BLAKE3-256 suite 1;
- minimal object schemas selected for the prototype.

**Required capability**

- canonical container v1 reader/writer;
- CIDs and direct-reference tables;
- `program_root`, `module`, `function`, `type`, `constant`, `graph_fragment`, `recursion_group` carrier support needed by fixtures;
- content-addressed object store;
- structural verifier and deterministic machine diagnostics;
- deterministic rejection of malformed/noncanonical inputs.

**Exit criteria**

- canonical objects can be created, identified, loaded, verified/rejected deterministically, and round-tripped without byte/identity change;
- malformed encoding and CID mismatch fixtures are rejected;
- local lookup does not require full-store deserialization;
- no text form is used as authoritative program state.

**Dependencies**: none beyond merged specification and cryptographic/hash implementation.

**Benchmarks now valid**: store size, encode/decode/hash throughput, lookup, malformed-object rejection, verifier throughput. No native runtime claims.

## M2 — Arithmetic, functions, calls, branches

**Entry criteria**: M1 complete.

**Required capability**

- `bits<N>` common prototype widths plus arbitrary-width semantic path;
- canonical constants;
- exact integer arithmetic needed by initial suite;
- functions, entry block, block parameters, direct calls, branches/switch as needed, return, trap;
- data/effect edges sufficient for the subset;
- simple executor or equivalent reference path for semantic oracles.

**Exit criteria**

- valid arithmetic/control fixtures execute with required results;
- invalid types, arities, SSA uses, branch arguments, and call contracts reject deterministically;
- no implicit promotions, fallthrough, exceptional call edge, or serialization-order semantics.

**Dependencies**: M1; initial CORE operation definitions.

**Benchmarks now valid**: small-program correctness, representation creation/edit tasks, basic compile-time/verifier accounting.

## M3 — Stack memory and proof obligations

**Entry criteria**: M2 complete.

**Required capability**

- explicit stack storage creation/lifetime;
- pointer/address derivation;
- load/store;
- provenance, extent, alignment, permission, initialization obligations;
- memory effects;
- explicit checked/raw path for unproved access where included in prototype.

**Exit criteria**

- stack/address/load/store vectors pass;
- use-after-lifetime, out-of-bounds, misalignment, permission, initialization, and invalid raw-waiver cases reject;
- statically proven obligations add no mandatory runtime metadata/check.

**Dependencies**: M1–M2; pointer/layout subset.

**Benchmarks now valid**: stack footprint, memory kernels through reference path, no-allocation cases, memory-safety diagnostic tasks.

## M4 — First direct native backend

**Entry criteria**: M3 complete and one target package sufficient for the subset exists.

**Required capability**

- machine value/address mapping;
- target lowering/legalization for M3 subset;
- instruction selection;
- basic scheduling/register allocation;
- direct deterministic encoding, relocation/layout, and object/executable or load-image emission;
- minimal ABI/entry support required by test programs.

**Exit criteria**

- milestone-3 programs execute as native code on the first target;
- output bytes are produced without a required permanent external backend/assembler/linker path;
- target assumptions originate from the exact target package;
- unsupported operations fail explicitly.

**Dependencies**: M1–M3; target-model/ABI subset.

**Benchmarks now valid**: native execution time, code size, startup, compile time/memory, first fair C/Rust comparisons for supported cases.

## M5 — Second architecturally different native backend

**Entry criteria**: M4 complete.

**Required capability**: implement the same semantic subset using a second materially different target package without modifying fundamental XAX semantics.

**Exit criteria**

- same canonical program subset lowers and executes on both targets;
- target-specific differences reside in target/platform/ABI packages;
- memory/register/encoding/legalization differences do not force core semantic changes;
- cross-target conformance vectors pass.

**Dependencies**: M4; second target package.

**Benchmarks now valid**: cross-target portability, target-package adequacy, target-cost ranking comparisons on both targets.

## M6 — Transactional AI workspace

**Entry criteria**: M1–M5 provide stable semantic/query identities and verifier services.

**Required capability**

- bounded semantic queries and local handles;
- transactions with expected root/read sets/local preconditions;
- mutation operations;
- affected-frontier verification;
- stale-root rejection and atomic commit;
- semantic conflicts/rebase;
- structured deterministic diagnostics/repair neighborhoods;
- token/context accounting.

**Exit criteria**

- local edits commit without retransmitting/rebuilding unrelated objects;
- failed/stale transactions leave root unchanged;
- deterministic queries/diagnostics pass C4 vectors;
- independent semantic edits can be detected as nonconflicting where dependencies permit.

**Dependencies**: M1–M5; semantic database dependency tracking.

**Benchmarks now valid**: C-like vs SSA vs graph-packet AI tasks, local-edit tokens, repair turns, context-scaling, conflict/rebase workloads. Tokenizer-native arm remains unavailable until actual integration exists.

## M7 — Resources and richer effects

**Entry criteria**: M6 complete; memory/control verifier stable.

**Required capability**

- `resource<K,state>` linear/affine rules;
- explicit acquire/transfer/transition/release/discard;
- split/join contract mechanism;
- effect domains/instances, summaries, calls, partitioning;
- resource/effect diagnostics and incremental invalidation.

**Exit criteria**

- lifecycle/effect vectors pass;
- duplication/disappearance/invalid state transitions reject;
- calls cannot exceed effect/resource/capability contract;
- independent proven effect domains may reorder; unproven independence remains conservative.

**Dependencies**: M3, M6.

**Benchmarks now valid**: resource-lifetime tasks, effect-reordering tests, hidden-operation checks, AI repair of resource/effect violations.

## M8 — Atomics, interrupts, and real-time profiles

**Entry criteria**: M7 complete; target atomic capability interface implemented on at least one capable target.

**Required capability**

- portable atomic families/orders/scopes;
- target atomic capability/legalization interface;
- fences and synchronization semantics;
- race validation sufficient for suite;
- interrupt/target-handler entry contracts;
- real-time rejection profiles and latency-relevant queries.

**Exit criteria**

- atomic order legality and litmus subset pass;
- unsupported atomics reject or expose explicitly permitted assistance;
- no hidden lock/runtime helper;
- strict profiles reject forbidden/unknown properties after lowering;
- interrupt constraints are target-driven and explicit.

**Dependencies**: M5, M7.

**Benchmarks now valid**: atomic kernels, synchronization cost, interrupt latency, deterministic-latency cases on capable targets.

## M9 — Compile-time XAX specialization/metaprogramming

**Entry criteria**: M7 verifier and transaction model stable; target query interface available.

**Required capability**

- deterministic bounded compile-time evaluator;
- explicit capability/environment isolation;
- types/constants/semantic references as compile-time values;
- semantic introspection and candidate construction;
- specialization, memoization, verifier barrier;
- target-package compile-time computation.

**Exit criteria**

- same inputs/policy produce same semantic result;
- budget exhaustion is deterministic and non-committing;
- ambient host effects are unavailable without capability;
- generated invalid graphs cannot commit;
- compile-time-only abstractions erase when no runtime representation is requested.

**Dependencies**: M6–M7; target query services.

**Benchmarks now valid**: specialization compile cost, generated-code impact, generic/specialization AI tasks, compile-time cache behavior.

## M10 — Package, build, security, and reproducibility semantics

**Entry criteria**: M9 provides build-time XAX execution; semantic database/snapshots stable.

**Required capability**

- package roots/logical identities;
- deterministic resolver;
- content-addressed snapshots;
- typed build requests/profiles/features/config;
- declared build input closure;
- hermetic/reproducible mode;
- build capabilities/sandbox boundary;
- cache integrity, provenance/signature/trust hooks.

**Exit criteria**

- identical declared resolver inputs produce identical roots/failure;
- clean offline build succeeds from complete local snapshot closure;
- undeclared host/network/time/random inputs reject in reproducible mode;
- fetched/cached objects verify against identities;
- package/build semantics require no external manifest/build DSL.

**Dependencies**: M1, M6, M9.

**Benchmarks now valid**: reproducible build tests, resolver/build incrementality, package-context AI tasks, cache/provenance overhead.

## M11 — XAX self-hosting subset

**Entry criteria**: M10 complete; seed strategy and bootstrap target fixed.

**Required capability**

- canonical XAX implementation of a declared compiler/tooling subset;
- seed capable of building it;
- provenance/build policy roots;
- self-build comparison/evidence infrastructure.

**Exit criteria**

- B0 and B1 achieved for declared subset;
- subset can be rebuilt through approved bootstrap path;
- behavior is compared against seed path using conformance vectors;
- seed limitations/dependencies are explicit.

**Dependencies**: M4, M9, M10.

**Benchmarks now valid**: bootstrap size/time, subset self-build reproducibility, hosted versus seed behavior.

## M12 — Optimizer expansion and validated search

**Entry criteria**: M11 plus stable target/compiler services.

**Required capability**

- interprocedural optimization;
- target-aware cost-directed optimization;
- at least one bounded higher-effort equality/search/superoptimization path;
- translation/equivalence validation for selected high-risk/search transformations;
- profile-guided profitability path with non-semantic profile separation.

**Exit criteria**

- optimizer suite demonstrates semantic preservation under verifier/oracles;
- failed candidate validation cannot alter accepted output;
- compile-time/memory budgets are explicit;
- target cost predictions and candidate selection are recorded for calibration.

**Dependencies**: M5, M7–M11.

**Benchmarks now valid**: optimization-quality corpus, compile-time/performance tradeoffs, target-cost ranking/magnitude validation, credible assembly kernel comparisons.

## M13 — GPU/accelerator path

**Entry criteria**: M8/M12 infrastructure can express target scopes, memory spaces, effects, and target operations.

**Required capability**

- non-CPU accelerator target package;
- execution topology/scopes;
- accelerator memory spaces;
- target operations/legalizations/encodings or deployment artifact path;
- explicit host-device launch/transfer/synchronization semantics.

**Exit criteria**

- accelerator programs compile/deploy without changing fundamental XAX semantics;
- unsupported scope/memory behavior rejects deterministically;
- host/device effects/resources are explicit;
- target-specific runtime dependencies, if any, are selected explicitly.

**Dependencies**: M5, M8, M12.

**Benchmarks now valid**: accelerator throughput/latency, host-device effects, target-model portability, GPU/accelerator code quality.

## M14 — Self-hosting completion and toolchain closure

**Entry criteria**: M11–M13 mature enough to migrate the remaining live toolchain.

**Required capability**

- authoritative compiler services in XAX;
- serializer/semantic database/verifier-facing services XAX-hosted except deliberate minimal trusted substrate;
- target interpretation/codegen, object writing, linking, package/build/repository operations XAX-hosted;
- normal target maintenance does not require a second backend language;
- release build can start from approved immutable seed artifact without maintaining seed-source language.

**Exit criteria**

- B2–B6 evidence satisfied for claimed closure target(s);
- compiler recursively compiles its authoritative graph;
- semantic self-equivalence and deterministic fixed point/projection pass;
- no required live second compiler/assembler/linker/build/package/target DSL remains;
- full self-build and release reconstruction are reproducible under declared policy;
- canonical continuation state permits a new AI session to resume without conversation history.

**Dependencies**: all prior milestones.

**Benchmarks now valid**: full self-build, whole-toolchain reproducibility, end-to-end compiler resource accounting, AI-native maintenance/context scaling.

**Status (ADR-177)**: complete only for the `xax-semantic-image-v1` META wrapper at B2–B4. These exit criteria are not met for the compiler as a whole: the verifier, lowering, object writing, linking, and package/build services are live Python, so B5/B6 are not held.

## U1 — Universal-replacement proof set (after M14)

M1–M14 establish a compiler-architecture prototype. U1 is the first milestone measured in replacement terms (`XAX_SPEC.md` §21): every result is a row update in `XAX_REPLACEMENT_MATRIX.json`, and levels are derived, never asserted.

**Entry criteria**: M14 complete; replacement matrix and validator present.

<!-- xax-status:levels -->Replacement levels (generated from `XAX_REPLACEMENT_MATRIX.json`): R6: linux-x86_64; R5: jvm; R3: android-arm64, linux-aarch64; R2: aarch64-baremetal, browser-web, windows-x86_64-pe; R1: gpu-spirv-cuda-metal-dxil, riscv64, wasm32-core, wasm32-wasi; R0: accelerator-simt-packet; no level yet: bsd-unix, dotnet-clr, macos-ios-apple, rtos-embedded-mcu.<!-- /xax-status:levels -->

**Progress (2026-10-03)**: workload 1 holds R4 on Linux x86-64 (ADR-147/148: `filestat`, `chains`, and `jsonmin` within 1.05× of the fastest of gcc, clang, and rustc, `XAX_BENCHMARKS.md` §15.14) and its R3 application is `jsonmin` (ADR-126; allocation, stdin/stdout I/O, recursion over borrowed memory, nontrivial control flow; the dynamic library call is `filestat`'s `libz` `crc32` on the same row), and Linux AArch64 runs the same graph (emulated). Workload 3 is at R2 (browser) and workload 5 at R1 (SPIR-V on llvmpipe, ADR-124). Workload 2 holds R2 on QEMU `virt` (ADR-128/129: MMIO, GIC timer interrupt, statically linked C). Workload 4 is unchanged (R2; the device run is queued).

**Progress (2026-10-04; historical — current status is U1.4b below)**: workload 4 held R3 then: the stateful counter app passed its UI oracle (restore, increments, persistence across process death, file contents) on an Android 12L x86_64 emulator, with the arm64 library run through ARM translation (ADR-155). Its sizes are measured against a Java + NDK twin (ADR-153/154); start-up and memory still need arm64 hardware.

**Progress (2026-10-05)**: workload 4 now holds R4 on physical arm64 hardware (ADR-172). The committed counter app passed its persistence oracle on Pixel 8 Pro; against its Java + NDK twin, XAX cold start is 1.016× the fastest arm, with lower median PSS and smaller APK/native-library size.

**Progress (2026-10-05)**: the Windows x86-64 row holds R2. Current PE bytes execute on Windows 11, and a second artifact exercises a loader-bound `CreateThread` call into a pure XAX `win64-c` entry, then waits, reads the callback result, and closes its linearly tracked handle (ADR-170).

**Progress (2026-10-08)**: ADR-207 redefines R4 as leadership (≤ 0.9999× the fastest non-XAX median, significant), R5 as autonomous maintenance, and R6 as a proven XAX-only application. The JVM keeps R4 (`jsonmin` 0.835× `javac`); Android drops to R3 (1.007×). The next milestone is U2 below.

**Required workloads** (all originate from verified XAX semantics; no human-authored program in another language):

1. **Hosted native application** on a mainstream OS performing real allocation, filesystem or network I/O, at least one dynamic/external library call, nontrivial control flow, and a data structure, with no hidden language runtime.
2. **Bare-metal program** on a named board or emulator with deterministic startup, explicit sections/layout, MMIO, and an interrupt handler.
3. **WebAssembly application** using WASI or browser host APIs through compiler-generated bindings.
4. **Android application** beyond the minimal Activity (state, I/O, lifecycle).
5. **Accelerator workload** executed on physical GPU/accelerator hardware.

**Exit criteria**

- each workload holds at least R2 in the matrix for its platform row; at least two hold R3;
- each workload has a measured comparison (time, peak memory, binary size) against an established toolchain baseline under `XAX_BENCHMARKS.md` §15, reported whether favorable or not;
- every platform-required runtime and generated adapter is listed in the row's `runtime_requirement` and build provenance;
- negative tests reject the corresponding verifier/ABI misuse (wrong foreign ABI, missing exit/lifecycle contract, undeclared imports).

**Ordered implementation sequence** (ADR-077; reorder only on matrix evidence):

| Step | Work | Unblocks | Status |
|---|---|---|---|
| U1.1 | Direct PE32+ container, `win64-c` foreign ABI and callback entries, IAT import binding, explicit process exit, linear thread-handle lifecycle | workload 1 (Windows), R2 interop | EXECUTED on Windows 11 (`windows_pe_hosted_evidence.json`, ADR-170) |
| U1.2a | x86-64 `heap_view` lowering: non-null trap, folded static/checked dynamic heap loads/stores | workload 1 data structures | EXECUTED (heap array in `windows_pe_hosted_evidence.json`) |
| U1.2b | register-allocating frame lowering (replaces spill-every-value) | R4 on every x86-64 row | PROTOTYPE on PE (ADR-083: compares, foreign calls, heap views, cross-block homes; `sum_to` 8.02x faster, fixture code −42%). MEASURED on Linux (ADR-089: separate allocator with immediates, cmp+jcc fusion, strength reduction; `filestat` 5.9x → 0.95–1.14x `gcc -O2`, 1.41–1.82x `clang -O2`; differential corpus of 120 random programs). Stack/float/aggregate functions still use the frame path; allocator convergence is OI-38. |
| U1.2c | pointer values in memory (OI-37) | iovecs, linked structures, vtables | PROTOTYPE (address exposure ADR-081 EXECUTED via WASI `fd_write`; provenance-free pointer elements ADR-082 EXECUTED as a dispatch table; local-provenance pointer reloads PROTOTYPE on Linux x86-64 via `pointer_rebase` (ADR-092; checked, 1.64× `gcc -O2` on `chains`) and EXECUTED on wasm32 (ADR-093); OI-37 CLOSED (ADR-096); check-free reloads MEASURED via record links on Linux x86-64 (ADR-097, 1.066× `gcc -O2`; OI-41 CLOSED); arena+index measured 1.44–1.47× slower than pointer links in C, plus 1.34–1.41× for checks — justified, sequenced after OI-38 per ADR-090) |
| U1.3 | ELF64 executable container + SysV foreign ABI (x86-64, AArch64 Linux) | Linux rows; reuses Android ELF writer | **x86-64 EXECUTED/MEASURED**: static and explicit-loader ELF64 `ET_EXEC` (ADR-086/087), `linux-x86_64-syscall-v1` (ADR-085), `sysv-x86_64-c` imports of register-passed INTEGER and SSE scalars (`libz.so.1` `crc32`; libm `ldexp`/`pow`/`sqrtf`), pure C-to-XAX callbacks through generated adapters (libc `tsearch`/`tfind`, ADR-102), explicit `exit_group`; Linux row at R2 then, now R4 (U1.8). **AArch64 EXECUTED under qemu-aarch64** (ADR-123): static and explicit-loader ELF64, `linux-aarch64-syscall-v1`, `aapcs64-linux-c` imports (glibc `strlen`, `libz.so.1` `crc32`), the unchanged `filestat` graph; linux-aarch64 row R2 then (emulated; frame path 6.6× gcc), now R3 with `jsonmin` (ADR-126). Remaining SysV breadth is OI-40, effectful callbacks OI-42, and TLS/unwind OI-33. |
| U1.4 | wasm32 imports + WASI and generated browser bindings | workload 3 | WASI EXECUTED (`wasi_command_evidence.json`); browser EXECUTED in headless Chromium (ADR-103/104, `browser_fib_evidence.json`: generated page, URL in, DOM out, XAX click entries; browser row R2). |
| U1.4a | Android workload evidence without a device | workload 4 | EXECUTED under Android's `linker64`/bionic via qemu-user (ADR-106, 31 runs, including C→XAX thread callbacks, ADR-107); every APK passes ART's verifier (ADR-108); libxposed modules EXECUTED on ART with a stand-in framework (ADR-109); packed ELF container (ADR-105); size MEASURED against a Java + NDK twin (packed APK 0.79×). Device run of the packed APK, and start-up/memory, UNEXECUTED. |
| U1.4b | Android app with state, I/O, lifecycle (workload 4) | Android R4 | `xax.counter` (ADR-111): XAX owns state, file I/O, and descriptor lifetime. ART-verified; persistence EXECUTED under bionic and on Pixel 8 Pro arm64 hardware (ADR-172). Current (ADR-198, §15.29): XAX cold-start median is 1.007× the fastest of a Java + NDK twin and a pure Java twin (four rotated passes, equal `speed` compilation, per-pass 1.00–1.06×), median PSS equal within 0.11%, APK 0.703× the NDK twin; Android row R4 then, R3 since ADR-207 (1.007× is above the 0.9999× leadership target). libxposed modules execute under Vector v2.2 on the same device (ADR-197). Descriptor ownership and durable writes (`fdatasync`) remain verifier-visible (ADR-153). |
| U1.5 | Deterministic foreign metadata importer (OI-32) | every platform API package | C headers EXECUTED (ADR-127: clang AST → declarations, byte-identical to hand-built ones, imported stdio program runs; 855 of 1,084 functions in four headers import); Android classfiles PROTOTYPE |
| U1.6 | Bare-metal board package: vector table, sections, MMIO, interrupt entry | workload 2 | EXECUTED on QEMU `virt` (ADR-128): board profile, GICv2 and timer interrupt through a contract-checked XAX handler, UART MMIO, PSCI power-off, 5,420-byte image. Static linking of freestanding C objects EXECUTED (ADR-129: XAX calls a linked C CRC and a C allocator); aarch64-baremetal row R2 (emulated). Hardware is OI-44. |
| U1.7 | Real GPU target package and device execution (OI-34) | workload 5 | SPIR-V/Vulkan package EXECUTED on Mesa llvmpipe (ADR-124; GPU row R1; matches the reference executor, traps included). Next: structured lowering of reducible CFGs (6.9× glslang today), floats and workgroup memory, an XAX host program driving Vulkan (R2), and a physical-GPU run with a throughput baseline (closes OI-34). |
| U1.8 | Baseline toolchains on measuring hosts; first R4 measurements | R4 on all rows | **Linux MEASURED** against gcc -O2/-O3/-static and clang -O2 (`XAX_BENCHMARKS.md` §15.1; R4 not met then), then against gcc, clang, and rustc under the multi-language rule (§15.0, §15.14; R4 met, ADR-147/148). **JVM MEASURED** against `javac` on the same HotSpot (§15.8: 1.04× kernel time, 1.51× class bytes), then against `javac` and `kotlinc` under the JVM runtime rule (§15.0a, §15.17: `jsonmin` fastest, Collatz 0.93×; R4 met, ADR-157; §15.18: class 0.99× kotlinc's, 1.5× javac's, ADR-158). **RISC-V MEASURED-EMULATED** against `clang -O2` (§15.9: 3.72× instructions). Windows under Wine only (§15.6). |
| U1.9 | Managed target by direct emission: JVM class files (OI-35) | JVM row; the managed-platform strategy question | EXECUTED (ADR-112): HotSpot runs XAX class files from `java -jar`, with typed JDK member calls, an explicit `System.exit`, and stack traces mapped to nodes; JVM row R2 then. ADR-156: linear memory (`jvm-classfile-memory-v1`) and `jsonmin` on HotSpot (1.18× the `javac` twin's process time); JVM row R3. ADR-157: slot coloring, Top frames, folding, compare fusion, and shared access members; `jsonmin` fastest of XAX, `javac`, and `kotlinc` (class 2.29× javac's); JVM row R4. ADR-158: expression trees, short-circuit branches, one name per value, dead-code elimination, frames only at targets, tail merging, and two-address `iinc`; `jsonmin`'s class 8,539 → 5,575 bytes (0.99× kotlinc, 1.5× javac). ADR-159/160: `jvm-classfile-general-v1` adds aggregates, sums, stack allocations, indirect calls, links, raw loads, and atomics. ADR-161: JVM→XAX callbacks as functional-interface objects, and interface method calls. ADR-162: object/array construction, string constants, casts. ADR-163: instance fields and `instanceof`; ADR-164: multi-dimensional arrays; ADR-165: native code plus a generated JNI bridge, measured against direct emission; OI-35 closed for the JVM. ADR-166: class-file importer from JDK modules; OI-32 closed. ADR-167: static field writes. ADR-175: the controlled direct semantic workflow uses 0.4990× C-like text's aggregate tokens (10/10 pass), but JVM stays R4 until the remaining §6.2 task classes run. |
| U1.10 | Third ISA through a target package only: RISC-V RV64 | riscv64 row; U1.6 on RISC-V boards | EXECUTED under Unicorn (ADR-113): raw RV64IM image with LP64 calls and a liveness-hull register allocator; riscv64 row R1. Next: compare/branch fusion, F/D floats and memory, a Linux `ET_EXEC` profile (reusing `xax_elf`), and a hardware or QEMU-system run (OI-44). |
| U1.11 | Standard semantic libraries, first families (OI-36) | every workload | EXECUTED (ADR-130): `xax.text` and `xax.collections.hashset_u64` as canonical packages; the `uniqcount` application runs on Linux x86-64 and AArch64; per-export bytes, compile cost, and offline tokens MEASURED. OI-36 CLOSED. |

**Dependencies**: M4/M5 backends, M7 resources/effects, M10 build/provenance, M13 accelerator scopes.

**Benchmarks now valid**: replacement-workload runtime/memory/size comparisons (§15 of `XAX_BENCHMARKS.md`). AI token trials are deferred to the future AI-efficiency milestone (ADR-207).

## U2 — Performance leadership, autonomous maintenance, XAX-only application (after U1)

Priority order (ADR-207): R4, then R5, then R6. The AI-token milestone is not scheduled here.

**Exit criteria**

1. **R4 on hardware rows.** Linux x86-64 and Android arm64 each hold R4: XAX median ≤ 0.9999× the fastest non-XAX arm (C/C++ plus Rust or another non-C language; Java + NDK and Kotlin on Android), significant over interleaved raw samples, rerun after every performance-relevant backend change. Memory and binary size are reported for every arm.
2. **R5 on one row.** An agent queries, modifies, verifies, benchmarks, rebuilds, and commits an R4 application through `LocalMutationSession` transactions with no whole-source regeneration; the run is recorded as EXECUTED `autonomous_maintenance` evidence.
3. **R6 on one row.** One complete deployable application (logic, tests, build definitions all XAX) is built reproducibly, deployed, functionally tested on its target, and taken through one XAX-only maintenance/release cycle; the record cites provenance, graph history, and test results as EXECUTED `xax_only_application`.

**Ordered sequence**

| Step | Work | Unblocks | Status |
|---|---|---|---|
| U2.1 | Re-run Linux `filestat`, `chains`, and `jsonmin` with raw samples (the harness records them since ADR-207) | Linux R4 verdict | MEASURED (ADR-208, §15.30): `filestat` 0.882x and `jsonmin` 0.968x clang lead; `chains` 0.984x rustc is within noise |
| U2.2 | Profile the gaps and optimize: allocator convergence for float/aggregate functions (OI-38), loop unrolling, LICM | Linux and Android R4 | In progress: predicate tables (ADR-208); next-iteration prefetch and edge sinking (ADR-211) made `chains` lead; single-edge parameters and 1 MiB reads (ADR-212): Linux derives R4 (§15.33). Next: a wider `jsonmin` margin |
| U2.3 | Android cold-start re-run with a Kotlin arm and more passes | Android R4 verdict | Open |
| U2.4 | Maintenance harness: scripted semantic-transaction cycle with verification, benchmark, rebuild, and commit recorded | R5 | EXECUTED for the JVM (ADR-209) and Linux x86-64 (ADR-213): one cycle of `jsonmin` each |
| U2.5 | XAX-only application with XAX test and build definitions | R6 | EXECUTED for `xb64` on Linux x86-64 (ADR-210); the row derives R6 (ADR-213) |

## S — Compiler migration ladder (after M14; runs alongside U1)

Steps S3–S7a are migrated for acceptance only: their XAX components decline invalid input to the bootstrap, which decides the rejection (`XAX_SPEC.md` §16.5 condition 5, ADR-180). Migration is reported with the SH0–SH8 labels of ADR-180; current: SH1. M14's semantic-image META wrapper reached B2–B4 for the small `xax-semantic-image-v1` target (its B5/B6 claim was withdrawn in ADR-177). The working compiler (verification, lowering, encoding, emission) is still Python. The S ladder moves it into XAX component by component under the rule in `XAX_SPEC.md` §16.5. Each step must be on the production path with byte-identical output, and the bootstrap code stays only as a checked fallback. A step's self-compilation result is a *component fixed point*, not a B milestone (ADR-177 renamed the earlier "B1–B4" labels below).

<!-- xax-status:bootstrap -->Bootstrap status (generated from `compiler/bootstrap/m14_selfhost_evidence.json`, derived by `xax_selfhost.bootstrap_status`): whole production compiler: none of B0-B6 is established (no canonical XAX store implements the whole compiler; S8 and later steps are open (ADR-180)); M14 semantic-image META wrapper: B2, B3, B4 hold, B5, B6 do not (host-executed META_CANONICAL_STORE, META_MATERIALIZE_PROGRAM, META_VERIFY_SEMANTICS). S-step component fixed points are not B milestones (`XAX_SPEC.md` §16.5). Bootstrap seed: python-zipapp, 46,255 bytes, requires Python: yes.<!-- /xax-status:bootstrap -->

| Step | Component | Needs | Status |
|---|---|---|---|
| S0 | BLAKE3 compression (CID hashing leaf) | scalar leaf | EXECUTED (native XAX leaf, 2026-10-02) |
| S1 | RISC-V instruction encoder + `li` planner | scalar leaf, loops | EXECUTED (ADR-116): production default on Linux x86-64; self-compilation fixed point; runs on x86-64, RISC-V, and the JVM |
| S2 | The whole BLAKE3 hash (chunking, padding, chaining-value tree) over lent views, so every CID comes from XAX | borrowed heap views across the leaf boundary | EXECUTED (ADR-117): production default on Linux x86-64; 11.6× faster object hashing than the driver it replaces |
| S3 | Store container decoder: header, record envelopes and CID order, non-semantic records, index, trailer, root presence | S2 buffers | EXECUTED (ADR-118): production `StoreReader` path on Linux x86-64; bootstrap parser only for diagnostics and deferrals |
| S3b | Object envelopes: kind, schema version, sorted reference table, exact body bounds, per record | S3 | EXECUTED (ADR-119): `StoreReader.get` builds objects from the XAX parse; CIDs checked with the S2 hash |
| S3c | Graph-body syntax: blocks, nodes, entity and attribute presence per operation, values, terminators, exact end, reference bounds | S3b | EXECUTED (ADR-120): `_parse_graph` walks the XAX decoder's stream; resolution, type checks, and trap payloads stay in body order |
| S3d | Control-flow analysis: branch-target check, dominator sets, depth-first reverse postorder | S3c | EXECUTED (ADR-121): `_parse_graph` uses the XAX results; the bootstrap computes them only on reject/defer |
| S3e | Value-definition and SSA-dominance checks for every use | S3d | EXECUTED (ADR-122): when XAX proves every use valid, `value_type` is a plain lookup; otherwise the bootstrap checks run |
| S4 | Operation typing rules (arity and operand/result types per operation family) | S3e | EXECUTED for the scalar families (ADR-132): integer, compare, rotate, float, and conversion nodes are typed by XAX on the production path; 2,419/2,419 covered nodes of four real stores proven |
| S4b | Aggregate and sum typing (`aggregate.make/get`, `sum.make/tag/get`) | S4 | EXECUTED (ADR-133): tuple, array, and sum types of scalars decoded and checked by XAX |
| S4c | Resource/effect and meta typing (`effect.step`, `resource.*`, `meta.*`) with effect, resource, and opaque type decoding | S4b | EXECUTED (ADR-134): every node check that reads only types is now XAX |
| S4d.1 | Constant typing (object decoding and canonical values) and terminator typing (conditions, edge arguments) | S4c | EXECUTED (ADR-135): 927 constants and 427 terminators in the corpus proven by XAX |
| S4d.2a | Direct-call contracts and memory-free graphs: XAX proves a graph has no tracked memory and Python runs no fact passes for it | S4d.1 | EXECUTED (ADR-136): 5 of 20 corpus graphs skip the fact system |
| S4d.2b | The memory-fact passes as an XAX engine (accept or decline), modelling stack storage | S4d.2a | EXECUTED (ADR-137): identical outcomes and extents on 300 random stack programs; the engine accepts every valid one |
| S4d.2c | Heap views (borrowed and allocated), checked accesses, foreign calls, view-passing direct and group calls and returns, pointer address and rebase windows | S4d.2b | EXECUTED (ADR-138): every corpus graph (20/20) verified by the XAX engine with identical extents |
| S4d.2d | Links and records, atomics, raw loads, stack resource contracts, lend entries, indirect calls, function addresses, target operations: the engine accepts every graph the bootstrap accepts (S4 complete) | S4d.2c | EXECUTED (ADR-139): S4 complete. Across the whole suite, every graph the bootstrap accepts is decided by XAX, except the helper programs' own seed graphs |
| S5a | RISC-V code generation (liveness, linear scan, frame, lowering, `li`, jump fixups) as an XAX program on the production path | S2–S4 | EXECUTED (ADR-140): byte-identical images; 2.3× faster on a 300-value loop |
| S5b | The backend's input from the XAX store and graph decoders instead of the Python marshal: store bytes to image bytes | S5a | EXECUTED (ADR-141): S5 complete. Closure, interfaces, widths, constants, and order are decided by XAX; 6.4× faster than the bootstrap generator on a 300-value loop |
| S6a | Resource and effect linearity (`_verify_linear_flow`) decided by XAX | S4 | EXECUTED (ADR-142): 6,518 suite graphs proven, none unsound |
| S6b.1 | Type and constant objects decided by XAX | S6a | EXECUTED (ADR-143): no Python type or constant decoding when verifying the corpus stores |
| S6b.2 | Function, call-contract, and module/root objects, and store rootedness, decided by XAX | S6b.1 | EXECUTED (ADR-144): 17/17 ordinary corpus functions and every list and store check proven |
| S6b.3 | Recursion groups, group member functions, and targets decided by XAX | S6b.2 | EXECUTED (ADR-146): every corpus function, group, list, contract, and target proven; only build/package objects left |
| S6b.4 | Build and package objects, accelerator/platform/board targets, and the per-graph glue (reference resolution, trap payloads) decided by XAX | S6b.3 | EXECUTED (ADR-149): every object kind and every per-graph check has an XAX decision path; declines and rejections keep the bootstrap's diagnostics |
| S6c | Every committed store (the verifier's own included) decided by XAX; a component fixed point for the store verifier on RV64 | S6b.4, component fixed point (RISC-V backend) | EXECUTED (ADR-150): no object of any helper store is left to Python; gen1 compiles every views-expressible helper program like the bootstrap; the verifier's RISC-V image verifies every committed store, its own included, with the native verdicts; gen2 reproduces the verifier image |
| Component fixed point (RISC-V backend) | The XAX RISC-V backend compiles its own store for a RISC-V views profile; the image, emulated, compiles it again | S5 | EXECUTED (ADR-145): gen1 = bootstrap reference, gen2 = gen1 on a corpus, gen3 == gen2 byte for byte |
| S6 | The full verifier, then component fixed points for the compiler components on at least one target | S4–S5 | EXECUTED for RV64 (ADR-150, ADR-151): S6a–S6c; component fixed points for the RISC-V backend (ADR-145) and the store verifier (ADR-150); BLAKE3 through both RISC-V generators with aggregates and stack arguments (ADR-151). The x86-64 backend and a component fixed point on a second target followed in S7a; the driver's lowering structures and exact rejection diagnostics are S7b |
| S6d | Aggregates (`aggregate.make/get`) and stack arguments in the views profile, so BLAKE3 closes on RV64 | S6c | EXECUTED (ADR-151): both generators byte-identical; the emulated BLAKE3 image gives production digests; gen2 reproduces it |
| S7a | The x86-64 backend that lowers the helpers, as an XAX program (x86-64 views profile); a component fixed point on a second target, natively | S6d | EXECUTED (ADR-152): byte-identical to its bootstrap reference on every helper, itself included; native fixed point in about a second; every production helper except its own image is lowered by it (1.08–1.32× the optimizing backend's run time) |
| S7b | The driver's lowering structures (the object table, image assembly) and the exact rejection diagnostics produced by XAX | S7a, EI | EXECUTED (ADR-179, ADR-181, ADR-182) for the views profiles on Linux x86-64: legality, exact diagnostics, the object table, and the image record are XAX decisions; RISC-V range rejections still come from the bootstrap emitter |
| S7b.1 | Target legality of the x86-64 views lowering decided by the XAX program, which writes the exact diagnostic record | S7a | EXECUTED (ADR-179): every x86-64 views rejection rule is decided in XAX, in the bootstrap's order, with an identical `Diagnostic` |
| S7b.2 | The object table (store objects and graph streams) and the image record (order, offsets, ranges) decided by XAX | S7b.1, S3, S3c | EXECUTED (ADR-181): references, target placement, and the entry are resolved by CID in XAX; the image record (function CIDs and code ranges) comes from the program |
| S7b.3 | The same legality pass and record for the RISC-V views family | S7b.1 | EXECUTED (ADR-182): both families decide their rejections in XAX; the entry-interface check is deferred to keep the bootstrap's order |
| S8 | Verifier totality: the store decoder, graph decoder, typing/facts, and store verifier reject with the bootstrap's exact diagnostics (`XAX_SPEC.md` §16.5 condition 5) | S7b.1 record | In progress: S8a and S8b EXECUTED; S8c.1–S8c.15 EXECUTED, rest of S8c open |
| S8a | Store-container rejections (header, records, non-semantic records, index, digest, trailer, root) decided by XAX with exact diagnostics | S3, S7b.1 record | EXECUTED (ADR-183): every container rule, in the bootstrap's order, digest comparison included |
| S8b | Object-envelope rejections (`decode_object`) and graph-body rejections (S3c decoder) | S8a | EXECUTED (ADR-184, ADR-185) |
| S8b.1 | Object-envelope rejections and the CID comparison decided by XAX on `get` | S8a | EXECUTED (ADR-184) |
| S8b.2 | Graph-body rejections (the S3c graph decoder writes the exact diagnostic) | S8b.1 | EXECUTED (ADR-185): every graph syntax rule decided by XAX; resolution before it in body order keeps precedence |
| S8c | Typing, facts, and store-verifier rejections | S8b | In progress |
| S8c.1 | Integer-family typing rejections decided by the XAX typing program with exact diagnostics | S8b | EXECUTED (ADR-214) |
| S8c.2 | Float and integer-compare typing rejections | S8c.1 | EXECUTED (ADR-215) |
| S8c.3 | Aggregate and sum typing rejections | S8c.2 | EXECUTED (ADR-216) |
| S8c.4 | Meta-operation typing rejections | S8c.3 | EXECUTED (ADR-217) |
| S8c.5 | Resource/effect typing rejections (separate rejection pass) | S8c.4 | EXECUTED (ADR-218) |
| S8c.6 | Constant and direct-call target rejections | S8c.5 | EXECUTED (ADR-219) |
| S8c.7 | Direct-call contract rejections (graph-fragment callees) | S8c.6 | EXECUTED (ADR-220) |
| S8c.8 | Stack-memory fact rejections decided by the XAX facts engine | S8c.7 | EXECUTED (ADR-221) |
| S8c.9 | Checked-access and access-type rejections decided by the facts engine | S8c.8 | EXECUTED (ADR-226) |
| S8c.10 | Rebase-window rejections decided by the facts engine | S8c.9 | EXECUTED (ADR-227) |
| S8c.11 | Returned-view rejections decided by the facts engine | S8c.10 | EXECUTED (ADR-228) |
| S8c.12 | Heap-view construction rejections decided by the facts engine | S8c.11 | EXECUTED (ADR-229) |
| S8c.13 | Foreign-call memory rejections decided by the facts engine | S8c.12 | EXECUTED (ADR-230) |
| S8c.14 | View-passing direct and group-member call rejections decided by the facts engine | S8c.13 | EXECUTED (ADR-232) |
| S8c.15 | Indirect-call stack-proof rejections decided by the facts engine | S8c.14 | EXECUTED (ADR-233) |
| S9 | Canonical store writing (object encoding, CID, container) in XAX | S2, S3 | UNIMPLEMENTED |
| S10 | The driver as an XAX program in a native Linux x86-64 process: explicit platform file I/O, target-package interpretation, verify → lower → assemble → write | S7b, S8, S9 | UNIMPLEMENTED |
| S11 | ELF64 executable container for views images, so the S10 driver is a standalone executable | S10 | UNIMPLEMENTED |
| S12 | General x86-64 program lowering (the optimizing backend's decisions) for ordinary programs | S10 | UNIMPLEMENTED |
| S13 | Build/package/provenance and the minimal command surface (`verify`, `build`, `inspect`) | S9, S10 | UNIMPLEMENTED |
| S14 | Full-compiler generations C1 → C2 → C3 on Linux x86-64 with positive/negative equivalence and identity records (full-compiler B2–B4) | S10–S13 | UNIMPLEMENTED |
| S15 | Compiler evolution by semantic transactions (B6/SH7), other targets through target packages, a Python-free seed (SH8) | S14 | UNIMPLEMENTED |

## EI — Evidence and canonical-state integrity (ADR-177; before S7b)

Not an R level and not a B milestone: a gate that restores a reproducible, derived-evidence baseline after the independent audit. Exit: every committed store regenerates byte-identically on every host (repeated builds included); B levels come only from `xax_selfhost.bootstrap_status`; the seed is pinned and only `rotate-seed` writes it; component authority is recorded and `XAX_REQUIRE_NATIVE=1` forbids silent fallback; native image cache entries are authenticated; the wheel carries every module and store; matrix levels are recomputed from evidence by validator v2; hosted artifacts carry build provenance; host-unavailable tests skip with an `UNAVAILABLE` reason. Status: **EXECUTED on Windows 11 x86-64** (`audit_remediation_evidence.json`); the native-host items are UNVERIFIED until run on Linux x86-64 (OI-45). The OI-45 self-hosting re-runs EXECUTED on Linux x86-64 on 2026-10-07 (`XAX_STATE.md`).

## 2. Bootstrap mapping

| Bootstrap evidence | Earliest roadmap point | Meaning |
|---|---|---|
| B0 seed viability | M11 | seed produces runnable XAX-hosted subset |
| B1 first XAX compiler | M11 | authoritative subset implementation is XAX semantic state |
| B2 recursive compilation | M14 | XAX compiler compiles itself |
| B3 semantic self-equivalence | M14 | generations agree under fixed policy |
| B4 deterministic fixed point | M14 | byte identity or predeclared canonical projection stabilizes |
| B5 toolchain closure | M14 | required live toolchain paths are XAX-hosted |
| B6 bootstrap independence | M14 | maintained second implementation language no longer required |

## 3. Milestone evidence rule

For every completed milestone, repository evidence SHOULD include:

```text
MilestoneEvidence {
  milestone_id
  spec_revision
  implementation_root
  target_roots[]
  package_snapshot_root
  build_policy_root
  conformance_suite_revision
  conformance_evidence_roots[]
  benchmark_suite_revision?
  benchmark_result_roots[]?
  known_failures[]
  open_issue_impacts[]
}
```

Milestone status cannot advance when required evidence is absent or invalidated by a semantic/target/toolchain change.

## JVM token optimization follow-up (2026-10-07, ADR-186)

The next dependency after ADR-176 is the normal snapshot-bound local mutation interface, now implemented in `compiler/src/xax_local_protocol.py`. Direct edit arms share it; task definitions, textual competitors, and exact semantic target checks are retained. The runner supports three fresh trials per cell, rotated arm order, exact event accounting, and resumable failures with retained costs. JVM stays R4 until the complete repeated comparison meets the 0.50 lowest-textual-median gate and task equivalence is established. No backend runtime-speed improvement is claimed by this change.

## JVM host-response and compound-edit follow-up (2026-10-07, ADR-187/188)

The current response corpus removes the inherited creation scaffold, supplies
real helpers in every large-application arm, and exercises a real stale
conflict before a fresh retry. Normal setters reconstruct exact old edge,
type and signature fields; dead-chain pruning preserves surviving users.
These implementation steps are complete. The pinned repeated model comparison,
independent raw-usage audit and corpus review determine the remaining token
gate and promotion work. The large application is synthetic, and the abstract
resource task is verifier checked rather than executed on the JVM.

## Android platform capability contracts (2026-10-08, ADR-202 to ADR-204)

Done (STRUCTURAL): exact JNI floats and typed-record argument packs, platform declarations for the managed-class APK, POSIX async/ownership contracts, NDK window/codec/AAudio contracts, and the SDK capability table enforced at build time (`docs/ANDROID_PLATFORM_CAPABILITIES.md`). Next: device execution of each new contract on the authorized device, then OI-47 (path-exact ownership for media buffers, NULL windows and JNI-held SDK objects).
