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

## U1 — Universal-replacement proof set (after M14)

M1–M14 establish a compiler-architecture prototype. U1 is the first milestone measured in replacement terms (`XAX_SPEC.md` §21): every result is a row update in `XAX_REPLACEMENT_MATRIX.json`, and levels are derived, never asserted.

**Entry criteria**: M14 complete; replacement matrix and validator present.

<!-- xax-status:levels -->Replacement levels (generated from `XAX_REPLACEMENT_MATRIX.json`): R4: jvm, linux-x86_64; R3: android-arm64, linux-aarch64; R2: aarch64-baremetal, browser-web; R1: gpu-spirv-cuda-metal-dxil, riscv64, wasm32-core, wasm32-wasi, windows-x86_64-pe; R0: accelerator-simt-packet; no level yet: bsd-unix, dotnet-clr, macos-ios-apple, rtos-embedded-mcu.<!-- /xax-status:levels -->

**Progress (2026-10-03)**: workload 1 holds R4 on Linux x86-64 (ADR-147/148: `filestat`, `chains`, and `jsonmin` within 1.05× of the fastest of gcc, clang, and rustc, `XAX_BENCHMARKS.md` §15.14) and its R3 application is `jsonmin` (ADR-126; allocation, stdin/stdout I/O, recursion over borrowed memory, nontrivial control flow; the dynamic library call is `filestat`'s `libz` `crc32` on the same row), and Linux AArch64 runs the same graph (emulated). Workload 3 is at R2 (browser) and workload 5 at R1 (SPIR-V on llvmpipe, ADR-124). Workload 2 holds R2 on QEMU `virt` (ADR-128/129: MMIO, GIC timer interrupt, statically linked C). Workload 4 is unchanged (R2; the device run is queued).

**Progress (2026-10-04)**: workload 4 holds R3: the stateful counter app passed its UI oracle (restore, increments, persistence across process death, file contents) on an Android 12L x86_64 emulator, with the arm64 library run through ARM translation (ADR-155). Its sizes are measured against a Java + NDK twin (ADR-153/154); start-up and memory still need arm64 hardware.

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
| U1.1 | Direct PE32+ container, `win64-c` foreign ABI, IAT import binding, explicit process exit | workload 1 (Windows), R1 hosted | EXECUTED (`windows_pe_hosted_evidence.json`) |
| U1.2a | x86-64 `heap_view` lowering: non-null trap, folded static/checked dynamic heap loads/stores | workload 1 data structures | EXECUTED (heap array in `windows_pe_hosted_evidence.json`) |
| U1.2b | register-allocating frame lowering (replaces spill-every-value) | R4 on every x86-64 row | PROTOTYPE on PE (ADR-083: compares, foreign calls, heap views, cross-block homes; `sum_to` 8.02x faster, fixture code −42%). MEASURED on Linux (ADR-089: separate allocator with immediates, cmp+jcc fusion, strength reduction; `filestat` 5.9x → 0.95–1.14x `gcc -O2`, 1.41–1.82x `clang -O2`; differential corpus of 120 random programs). Stack/float/aggregate functions still use the frame path; allocator convergence is OI-38. |
| U1.2c | pointer values in memory (OI-37) | iovecs, linked structures, vtables | PROTOTYPE (address exposure ADR-081 EXECUTED via WASI `fd_write`; provenance-free pointer elements ADR-082 EXECUTED as a dispatch table; local-provenance pointer reloads PROTOTYPE on Linux x86-64 via `pointer_rebase` (ADR-092; checked, 1.64× `gcc -O2` on `chains`) and EXECUTED on wasm32 (ADR-093); OI-37 CLOSED (ADR-096); check-free reloads MEASURED via record links on Linux x86-64 (ADR-097, 1.066× `gcc -O2`; OI-41 CLOSED); arena+index measured 1.44–1.47× slower than pointer links in C, plus 1.34–1.41× for checks — justified, sequenced after OI-38 per ADR-090) |
| U1.3 | ELF64 executable container + SysV foreign ABI (x86-64, AArch64 Linux) | Linux rows; reuses Android ELF writer | **x86-64 EXECUTED/MEASURED**: static and explicit-loader ELF64 `ET_EXEC` (ADR-086/087), `linux-x86_64-syscall-v1` (ADR-085), `sysv-x86_64-c` imports of register-passed INTEGER and SSE scalars (`libz.so.1` `crc32`; libm `ldexp`/`pow`/`sqrtf`), pure C-to-XAX callbacks through generated adapters (libc `tsearch`/`tfind`, ADR-102), explicit `exit_group`; Linux row at R2 then, now R4 (U1.8). **AArch64 EXECUTED under qemu-aarch64** (ADR-123): static and explicit-loader ELF64, `linux-aarch64-syscall-v1`, `aapcs64-linux-c` imports (glibc `strlen`, `libz.so.1` `crc32`), the unchanged `filestat` graph; linux-aarch64 row R2 then (emulated; frame path 6.6× gcc), now R3 with `jsonmin` (ADR-126). Remaining SysV breadth is OI-40, effectful callbacks OI-42, and TLS/unwind OI-33. |
| U1.4 | wasm32 imports + WASI and generated browser bindings | workload 3 | WASI EXECUTED (`wasi_command_evidence.json`); browser EXECUTED in headless Chromium (ADR-103/104, `browser_fib_evidence.json`: generated page, URL in, DOM out, XAX click entries; browser row R2). |
| U1.4a | Android workload evidence without a device | workload 4 | EXECUTED under Android's `linker64`/bionic via qemu-user (ADR-106, 31 runs, including C→XAX thread callbacks, ADR-107); every APK passes ART's verifier (ADR-108); libxposed modules EXECUTED on ART with a stand-in framework (ADR-109); packed ELF container (ADR-105); size MEASURED against a Java + NDK twin (packed APK 0.79×). Device run of the packed APK, and start-up/memory, UNEXECUTED. |
| U1.4b | Android app with state, I/O, lifecycle (workload 4) | Android R3 | `xax.counter` (ADR-111): XAX owns the state, file I/O, and descriptor lifetime. ART-verified; native persistence EXECUTED under bionic; UI oracle EXECUTED on an Android 12L x86_64 emulator through ARM translation (ADR-155; Android row R3), not yet on arm64 hardware (`validate_counter_apk.sh`). ADR-153: descriptor ownership verified as a linear resource, durable writes (`fdatasync`), and a Java + NDK twin (sizes MEASURED: APK 0.706× after ADR-154 put heap access on the AArch64 register path; start-up and memory need hardware, `bench_android_counter_twin.py --device`). |
| U1.5 | Deterministic foreign metadata importer (OI-32) | every platform API package | C headers EXECUTED (ADR-127: clang AST → declarations, byte-identical to hand-built ones, imported stdio program runs; 855 of 1,084 functions in four headers import); Android classfiles PROTOTYPE |
| U1.6 | Bare-metal board package: vector table, sections, MMIO, interrupt entry | workload 2 | EXECUTED on QEMU `virt` (ADR-128): board profile, GICv2 and timer interrupt through a contract-checked XAX handler, UART MMIO, PSCI power-off, 5,420-byte image. Static linking of freestanding C objects EXECUTED (ADR-129: XAX calls a linked C CRC and a C allocator); aarch64-baremetal row R2 (emulated). Hardware is OI-44. |
| U1.7 | Real GPU target package and device execution (OI-34) | workload 5 | SPIR-V/Vulkan package EXECUTED on Mesa llvmpipe (ADR-124; GPU row R1; matches the reference executor, traps included). Next: structured lowering of reducible CFGs (6.9× glslang today), floats and workgroup memory, an XAX host program driving Vulkan (R2), and a physical-GPU run with a throughput baseline (closes OI-34). |
| U1.8 | Baseline toolchains on measuring hosts; first R4 measurements | R4 on all rows | **Linux MEASURED** against gcc -O2/-O3/-static and clang -O2 (`XAX_BENCHMARKS.md` §15.1; R4 not met then), then against gcc, clang, and rustc under the multi-language rule (§15.0, §15.14; R4 met, ADR-147/148). **JVM MEASURED** against `javac` on the same HotSpot (§15.8: 1.04× kernel time, 1.51× class bytes), then against `javac` and `kotlinc` under the JVM runtime rule (§15.0a, §15.17: `jsonmin` fastest, Collatz 0.93×; R4 met, ADR-157; §15.18: class 0.99× kotlinc's, 1.5× javac's, ADR-158). **RISC-V MEASURED-EMULATED** against `clang -O2` (§15.9: 3.72× instructions). Windows under Wine only (§15.6). |
| U1.9 | Managed target by direct emission: JVM class files (OI-35) | JVM row; the managed-platform strategy question | EXECUTED (ADR-112): HotSpot runs XAX class files from `java -jar`, with typed JDK member calls, an explicit `System.exit`, and stack traces mapped to nodes; JVM row R2 then. ADR-156: linear memory (`jvm-classfile-memory-v1`) and `jsonmin` on HotSpot (1.18× the `javac` twin's process time); JVM row R3. ADR-157: slot coloring, Top frames, folding, compare fusion, and shared access members; `jsonmin` fastest of XAX, `javac`, and `kotlinc` (class 2.29× javac's); JVM row R4. ADR-158: expression trees, short-circuit branches, one name per value, dead-code elimination, frames only at targets, tail merging, and two-address `iinc`; `jsonmin`'s class 8,539 → 5,575 bytes (0.99× kotlinc, 1.5× javac). ADR-159/160: `jvm-classfile-general-v1` adds aggregates, sums, stack allocations, indirect calls, links, raw loads, and atomics. ADR-161: JVM→XAX callbacks as functional-interface objects, and interface method calls. ADR-162: object/array construction, string constants, casts. ADR-163: instance fields and `instanceof`. ADR-164: multi-dimensional arrays. ADR-165: native code plus a generated JNI bridge, measured against direct emission; OI-35 closed for the JVM. Next: a classfile metadata importer (OI-32). |
| U1.10 | Third ISA through a target package only: RISC-V RV64 | riscv64 row; U1.6 on RISC-V boards | EXECUTED under Unicorn (ADR-113): raw RV64IM image with LP64 calls and a liveness-hull register allocator; riscv64 row R1. Next: compare/branch fusion, F/D floats and memory, a Linux `ET_EXEC` profile (reusing `xax_elf`), and a hardware or QEMU-system run (OI-44). |
| U1.11 | Standard semantic libraries, first families (OI-36) | every workload | EXECUTED (ADR-130): `xax.text` and `xax.collections.hashset_u64` as canonical packages; the `uniqcount` application runs on Linux x86-64 and AArch64; per-export bytes, compile cost, and offline tokens MEASURED. OI-36 CLOSED. |

**Dependencies**: M4/M5 backends, M7 resources/effects, M10 build/provenance, M13 accelerator scopes.

**Benchmarks now valid**: replacement-workload runtime/memory/size comparisons (§15 of `XAX_BENCHMARKS.md`); AI token trials on the same workloads once U1 applications exist (R5).

## S — Compiler migration ladder (after M14; runs alongside U1)

M14 closed B2–B6 only for the small `xax-semantic-image-v1` target. The working compiler (verification, lowering, encoding, emission) is still Python. The S ladder moves it into XAX component by component under the rule in `XAX_SPEC.md` §16.5. Each step must be on the production path with byte-identical output, and the bootstrap code stays only as a checked fallback.

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
| S6c | Every committed store (the verifier's own included) decided by XAX; B1–B4 for the store verifier on RV64 | S6b.4, B1–B4 (RISC-V backend) | EXECUTED (ADR-150): no object of any helper store is left to Python; gen1 compiles every views-expressible helper program like the bootstrap; the verifier's RISC-V image verifies every committed store, its own included, with the native verdicts; gen2 reproduces the verifier image |
| B1–B4 (RISC-V backend) | The XAX RISC-V backend compiles its own store for a RISC-V views profile; the image, emulated, compiles it again | S5 | EXECUTED (ADR-145): gen1 = bootstrap reference, gen2 = gen1 on a corpus, gen3 == gen2 byte for byte |
| S6 | The full verifier, then B1–B4 for the real compiler on at least one target | S4–S5 | EXECUTED for RV64 (ADR-150, ADR-151): S6a–S6c; B1–B4 for the RISC-V backend (ADR-145) and the store verifier (ADR-150); BLAKE3 through both RISC-V generators with aggregates and stack arguments (ADR-151). The x86-64 backend and B1–B4 on a second target followed in S7a; the driver's lowering structures and exact rejection diagnostics are S7b |
| S6d | Aggregates (`aggregate.make/get`) and stack arguments in the views profile, so BLAKE3 closes on RV64 | S6c | EXECUTED (ADR-151): both generators byte-identical; the emulated BLAKE3 image gives production digests; gen2 reproduces it |
| S7a | The x86-64 backend that lowers the helpers, as an XAX program (x86-64 views profile); B1–B4 on a second target, natively | S6d | EXECUTED (ADR-152): byte-identical to its bootstrap reference on every helper, itself included; native fixed point in about a second; every production helper is lowered by it (1.08–1.32× the optimizing backend's run time) |
| S7b | The driver's lowering structures (the object table, image assembly) and the exact rejection diagnostics produced by XAX | S7a | Open |

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
