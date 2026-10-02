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
| U1.3 | ELF64 executable container + SysV foreign ABI (x86-64, AArch64 Linux) | Linux rows; reuses Android ELF writer | **x86-64 EXECUTED/MEASURED**: static and explicit-loader ELF64 `ET_EXEC` (ADR-086/087), `linux-x86_64-syscall-v1` (ADR-085), `sysv-x86_64-c` imports of register-passed INTEGER and SSE scalars (`libz.so.1` `crc32`; libm `ldexp`/`pow`/`sqrtf`), pure C-to-XAX callbacks through generated adapters (libc `tsearch`/`tfind`, ADR-102), explicit `exit_group`; Linux row at R2. AArch64 Linux UNIMPLEMENTED; remaining SysV breadth is OI-40, effectful callbacks OI-42, and TLS/unwind OI-33. |
| U1.4 | wasm32 imports + WASI and generated browser bindings | workload 3 | WASI EXECUTED (`wasi_command_evidence.json`); browser EXECUTED in headless Chromium (ADR-103/104, `browser_fib_evidence.json`: generated page, URL in, DOM out, XAX click entries; browser row R2). |
| U1.4a | Android workload evidence without a device | workload 4 | EXECUTED under Android's `linker64`/bionic via qemu-user (ADR-106, 29 runs); packed ELF container (ADR-105); size MEASURED against a Java + NDK twin (packed APK 0.79×). Device run of the packed APK, and start-up/memory, UNEXECUTED. |
| U1.5 | Deterministic foreign metadata importer (OI-32) | every platform API package | PROTOTYPE (Android classfiles) |
| U1.6 | Bare-metal board package: vector table, sections, MMIO, interrupt entry | workload 2 | PROTOTYPE (AArch64 raw image) |
| U1.7 | Real GPU target package and device execution (OI-34) | workload 5 | UNIMPLEMENTED |
| U1.8 | Baseline toolchains on measuring hosts; first R4 measurements | R4 on all rows | **Linux MEASURED** against gcc -O2/-O3/-static and clang -O2 (`XAX_BENCHMARKS.md` §15.1; R4 not met). Windows/other hosts UNIMPLEMENTED. |

**Dependencies**: M4/M5 backends, M7 resources/effects, M10 build/provenance, M13 accelerator scopes.

**Benchmarks now valid**: replacement-workload runtime/memory/size comparisons (§15 of `XAX_BENCHMARKS.md`); AI token trials on the same workloads once U1 applications exist (R5).

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
