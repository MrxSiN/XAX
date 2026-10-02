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

## Phase U — Universal replacement (after M14)

Phase U converts the M1–M14 prototype into a practical general-purpose replacement, as defined in `docs/18_UNIVERSAL_REPLACEMENT.md`. Sequencing rule: prefer work that unlocks many targets at once (shared lowering, foreign ABIs, artifact infrastructure) before per-platform breadth. Do not redo completed work, and never claim a replacement level the matrix does not compute.

| Milestone | Capability | Unlocks | Status (2026-10-02) |
|---|---|---|---|
| **U1** | Linux x86-64 hosted native proof: exact integer completion, syscall ABI, first-class pointers, static ELF64 executable, real allocation/I/O/data-structure workload measured against `gcc -O2` | Linux R1; shared ELF/x86 infrastructure | **Capabilities EXECUTED/MEASURED; matrix R2.** Remaining: argv/env (OI-36); R3 needs an application rather than a benchmark utility. |
| **U2** | General-path register allocation + translation-validated machine optimizations (OI-32) | R4 on every CPU target; shared by x86-64/AArch64 | UNIMPLEMENTED; current gap 5.9× vs `gcc -O2` |
| **U3** | C-ABI foreign calls and dynamic ELF imports with an explicit loader capability (OI-33) | libraries on Linux and Android; R2 | **EXECUTED/MEASURED for INTEGER-class imports on Linux x86-64** (`libz.so.1` `crc32`); callbacks, floats, aggregates, variadics, and Android device `dlopen` validation remain |
| **U4** | Bare-metal startup/reset, sections, memory-map layout, and vector tables; RISC-V target-package proof | embedded R1–R3; third ISA family | UNIMPLEMENTED |
| **U5** | Wasm imports, WASI package, generated browser bindings (OI-37) | WASI and browser R1–R3 | UNIMPLEMENTED |
| **U6** | Nontrivial Android application beyond the bounded Activity | Android R3 | UNIMPLEMENTED |
| **U7** | SPIR-V compute kernel executed on a physical device (OI-39) | GPU R1 | UNIMPLEMENTED |
| **U8** | Foreign-metadata importers (C headers first) and first XAX standard semantic packages (OI-35, OI-40) | ecosystem reuse without human wrapper code | UNIMPLEMENTED |
| **U9** | Debug information and observability (OI-41) | production debugging | UNIMPLEMENTED |

**UR-M1 (first universal-replacement milestone)** closes when U1's workload, a U4 bare-metal program, a U5 Wasm/WASI or browser application, a U6 Android application, and a U7 GPU workload each reach R3 for their declared workload classes, and U1 records R4 measurements (competitive or not). The native workload must also perform a real external/dynamic library call.

**U1 exit evidence (current):** `compiler/tests/test_xax_linux.py`, `compiler/benchmarks/u1_linux_filestat_evidence.json`, ADR-077–ADR-080, `XAX_CONFORMANCE.md` §24.

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
