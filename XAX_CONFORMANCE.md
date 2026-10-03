# XAX Conformance Requirements

This document consolidates conformance requirements and test categories. It contains **no test results**.

## 1. Claim format

Every conformance claim MUST name:

- XAX specification revision;
- conformance-suite revision;
- claimed level(s);
- claimed profile(s);
- exact target/platform package identities for target-dependent claims;
- deterministic build/profile identity where deterministic output is claimed.

An unscoped claim such as “supports XAX” is insufficient.

## 2. Conformance levels

| Level | Name | Required obligations |
|---|---|---|
| C0 | Canonical Store | Read supported canonical objects; reject malformed/noncanonical data; recompute CIDs; emit canonical bytes; preserve immutable identity; round-trip canonical fixtures byte-identically. |
| C1 | Semantic Verifier | C0 plus deterministic accept/reject behavior and enforcement of all semantic rules for claimed profiles. |
| C2 | Semantic Executor | C1 plus execution/interpreting capability sufficient to demonstrate observable semantics of claimed target-independent and META operations. |
| C3 | Native Compiler | C1 plus lowering and direct object/executable/image emission for each named target package. C2 is optional if compiled execution demonstrates semantics. |
| C4 | Transactional Workspace | C1 plus bounded semantic queries, transactions, stale-root detection, verification-before-commit, atomic commit/reject, semantic conflicts, and deterministic roots for deterministic transactions. |

Levels are capability dimensions, not maturity grades.

## 3. Conformance profiles

`CORE` is mandatory for C1–C4.

| Profile | Required families |
|---|---|
| CORE | `bits<N>`, constants, exact integer operations used by suite, tuples/sums needed by control, functions, calls, block parameters, branches/switch/return/trap, stack storage, addressing, load/store, explicit effects. |
| MEMORY | Provenance, extent/bounds, alignment, permissions, alias obligations, additional storage classes, raw waivers, memory effects, initialization/lifetime. |
| RESOURCE | Linear/affine resource acquisition, transfer, state transition, split/join where declared, release/discard. |
| CONCURRENT | Atomics, fences, memory orders, scopes, target capability/legalization/rejection, race/synchronization rules. |
| META | Deterministic bounded compile-time execution, semantic inspection/construction, specialization, capability isolation. |
| TARGET | Target operations/contracts, machine types, memory spaces, registers, legalizations, encodings, relocations, object/executable rules, scheduling constraints required by claimed target. |
| PLATFORM | ABI/foreign/platform capability contracts, syscalls/hosted boundaries, explicit effects/resources/unwind. |
| WORKSPACE | Query handles, bounded neighborhood retrieval, transactional mutation, base-root/read-set checks, structured diagnostics, conflict handling. |

Experimental extensions are outside a claim unless standardized by the named suite/spec revision.

## 4. Canonical serialization tests

### 4.1 Positive vectors

The suite MUST include canonical fixtures for:

- v0.1 header with `XAX\0`, container major 1, hash suite 1/BLAKE3-256;
- minimum/maximum practical ULEB128 boundary values;
- ZigZag signed schema fields where used;
- booleans, byte strings, ordered collections, canonical unordered sets;
- semantic object envelopes and CID recomputation using `XAX-SEM-1` domain separation;
- sorted direct-reference tables with deduplication;
- local-reference numbering;
- repeated/interned objects;
- `program_root`, `module`, `function`, `type`, `constant`, `target`, `graph_fragment`, and `recursion_group` fixtures;
- identity-qualified opaque ABI types with deterministic identity separation and opaque-pointer carrier validation;
- Merkle roots with shared children;
- optional non-semantic records whose modification does not change semantic root;
- canonical index/integrity trailer as defined by active serialization schema;
- deserialize→serialize byte identity.

### 4.2 Negative vectors

Readers MUST reject:

- bad magic;
- unsupported major version or required feature bit;
- unknown/unsupported hash suite;
- overlong/redundant/unterminated ULEB128;
- invalid boolean or forbidden enum value;
- length/count overflow or record overrun;
- out-of-order or duplicate-forbidden canonical fields;
- noncanonical set/reference-table ordering;
- duplicate semantic record for one CID;
- stored CID mismatch;
- unknown reachable kind/schema without an explicit compatibility rule;
- invalid local reference;
- unresolved required external reference in a standalone store;
- malformed recursion-group member reference;
- corrupted/truncated index or integrity data;
- ambiguous or heuristic-repair-dependent input.

## 5. Structural graph verification tests

The verifier MUST accept valid vectors and reject at least:

- undefined or multiply defined graph-local values;
- illegal SSA use/dominance;
- block without exactly one terminator;
- successor argument count/class/type mismatch;
- branch to nonexistent block;
- invalid entry-block contract;
- return arity/type/resource/effect mismatch;
- malformed node arity/results relative to operation contract;
- unknown semantic attribute where schema forbids it;
- illegal target dependency reference;
- cyclic content-addressed object references outside schema-defined local recursion indirection.

## 6. Type/value/layout tests

Required categories:

- arbitrary-width `bits<N>` constants and operations;
- operation-level signed/unsigned distinctions;
- wrap/checked/saturating arithmetic differences;
- rejection of implicit conversion/promotion;
- exact vector/tuple/sum construction and extraction;
- sum variant and exhaustiveness rules;
- pointer type nullability absence unless contract-defined;
- function signature versus explicit CallContract behavior;
- `resource<K,state>`, `effect<D>`, and nominal `opaque<K>` identity;
- rejection of canonical poison/`undef`;
- no universal zero for types without defined zero;
- target-qualified layout queries;
- explicit-layout type consistency;
- safe reinterpretation proof requirements;
- raw reinterpretation waiver visibility;
- proof-fact dependency invalidation.

## 7. Memory and resource tests

The suite MUST include positive/negative vectors for:

- explicit stack/static/region/arena/target/raw storage creation;
- lifetime end and use-after-end rejection;
- provenance-preserving address derivation;
- bounds/extent and alignment proofs;
- read/write permission checks;
- initialization before typed load;
- alias relation establishment/invalidation;
- ordinary load/store versus volatile/device semantics;
- disjoint versus overlap copy;
- move semantics and source invalidation;
- no duplication of embedded linear resources;
- raw waiver sets that waive only named obligations;
- resource acquire/transfer/transition/release;
- legal and illegal split/join;
- affine discard only where resource kind permits it;
- terminal-path resource accounting;
- MMIO speculative-access restrictions;
- DMA ownership/mapping transition checks where target profile supports them.

## 8. Effects, calls, errors, and control tests

Required categories:

- pure operation with no effect frontier;
- same-domain ordering;
- proven independent domain instances;
- conservative shared domain when independence is unproven;
- effect frontiers through branch/merge/loop parameters;
- multi-domain operation ordering;
- exact direct-call effect/resource/capability contract;
- indirect call rejection without bounded CallContract;
- recursive effect-summary fixed point;
- stored/derived summary mismatch rejection;
- recoverable error as ordinary sum/control;
- no hidden exceptional edge on core call;
- trap versus unreachable distinction;
- foreign unwind explicit normal/exceptional control;
- no implicit cleanup on return/trap/foreign edge.

Current implementation-local M7/C6 evidence includes the earlier bounded single-pointer stack-memory direct-call contracts plus a general resource/effect operation layer. Operations cover acquire, transfer, declared state transition, release, affine discard, partitionable two-piece split/sibling join, and effect steps over distinct domain instances. Exact linear consumption is checked through same-block uses, block parameters, branches, conditional branches, returns, and traps. Reference execution covers the lifecycle, transitions, split/join, and independent effect domains. Negative coverage includes duplicate/reuse, dropped linear values, invalid transition, illegal discard/release, non-sibling join, non-partitionable split, and effect-domain forks. Verified direct-function interfaces/terminators yield derived domain-instance/return/trap summaries exposed through the workspace. x86-64, AArch64, and WebAssembly erase resource/effect values from ABI slots, edge copies, calls, returns, and emitted bytes; the deterministic comparison is byte-identical for baseline versus lifecycle programs. The full 2026-09-30 regression passed 189/189, including 47 memory tests and 8 general resource/effect tests. No indirect-call operation is accepted, and no persistent or recursive fixed-point summary representation is claimed.

## 9. Concurrency and real-time tests

### 9.1 Atomic semantics

Tests MUST cover:

- load orders: relaxed/acquire/seq_cst;
- store orders: relaxed/release/seq_cst;
- RMW all portable orders;
- compare-exchange success/failure order legality;
- strong versus weak spurious failure behavior;
- fence legality and no relaxed fence;
- modification order/release-sequence behavior;
- seq_cst total-order obligations;
- exact arithmetic semantics inside atomic RMW;
- target width/alignment/address-space/scope capability checks;
- rejection or explicit runtime-assist dependency for unsupported native operations;
- no hidden lock/helper/scheduler/syscall lowering.

### 9.2 Race/synchronization and profiles

Tests MUST include:

- ordered non-atomic sharing;
- unproven conflicting non-atomic access rejection;
- `volatile` not creating synchronization;
- explicit lock/channel library contracts where suite fixtures provide them;
- interrupt reentrancy/nesting/allowed-effect constraints;
- GPU/accelerator scope rejection where target cannot represent requested scope;
- strict real-time profile rejection of unknown blocking/retry/stack/recursion/runtime-assist/etc.;
- distinction between target timing guarantee and cost estimate.

Current implementation-local M8 evidence covers all five portable atomic families, legal load/store/RMW/fence orders, compare-exchange success/failure-order legality, explicit strong/weak behavior, wrapping RMW arithmetic, modification order, release sequences, seq-cst ordering, and target width/alignment/address-space/scope checks. Conflicting unordered non-atomic abstract memory events reject while ordered or wholly atomic conflicts pass. Failed compare-exchange derives read synchronization and seq-cst participation from its failure order. The x86-64 revision-2 target package declares native system-scope 32/64-bit atomic capability and one explicit handler entry; direct lowering emits no helper call, lock object, scheduler, syscall, allocator, or runtime dependency. WebAssembly and unsupported scopes/alignment/widths reject. Strict real-time profiles inspect specialized/selected-target properties and reject unknown target support, loops/recursion, runtime assistance, progress, timing guarantees, effect domains, and interrupt-mask bounds when required. Workspace queries expose atomic capability, handler policy, and latency-relevant facts without relabeling unavailable cost estimates as guarantees. `xax-atomic-litmus-v1` is the OI-29 minimum conformance corpus: 9 greedily retained cases from an 11-case source corpus cover the portable order/family surface, release sequence, SC order, race rejection, and x86-64/AArch64/WebAssembly target-capability boundaries while detecting all seven declared injected fault classes. Unsupported target cases MUST remain explicit, and target packages MUST add vectors for target-only synchronization claims. The corpus is sufficient only for that declared fault model; physical concurrent execution is supplementary. External thread/lock/channel fixtures and exhaustive physical-device weak-memory execution remain unavailable and are not claimed.

## 10. Compile-time/META tests

Tests MUST cover:

- compile-time type/constant/semantic-reference inputs;
- explicit stage materialization;
- no ambient filesystem/network/clock/random/device authority;
- explicit capability-granted external input in a non-reproducible/declared mode;
- deterministic repeated evaluation under same complete inputs;
- fuel/recursion/memory/object/node budget exhaustion;
- no partial result on exhaustion;
- semantic introspection authorization;
- semantic object construction;
- verification barrier rejecting invalid generated graph;
- specialization identity/reuse;
- cache invalidation on evaluator/verifier/target/input change;
- target-package inspection without executing target device I/O on host.

Current implementation-local M9 evidence covers typed type/constant/function/target compile-time references, explicit capabilities, declared reproducible and non-reproducible bit inputs, deterministic repeat evaluation, content-derived memoization, evaluator/verifier/target/input invalidation, ordinary calls/control/recursion, all five mandatory budget dimensions, non-caching failure, runtime-operation stage rejection, target-package inspection, candidate constant/function/graph construction, whole-store verifier-gated materialization, and reference/x86-64 execution of the erased generated function. The final 2026-09-30 regression passed 206/206, including 6 `CompileTimeTests`; the deterministic M9 record reproduced a cache hit and reference/native result 44. Construction beyond constant-return functions, persistent cache storage, external conformance vectors, and representative specialization workloads remain unavailable and are not claimed.

## 11. Target and ABI/platform tests

### 11.1 Target profile

For each claimed C3 target, suites MUST test:

- exact target revision/configuration identity;
- machine type mapping without semantic drift;
- memory spaces and explicit cross-space conversions;
- overlapping register/unit conflicts;
- fixed/tied/paired/reserved register constraints;
- instruction semantic contracts and deterministic encoding;
- immediate/relocation constraints;
- opaque operation minimum contract;
- legalization success and explicit unsupported failure;
- scheduling hazards/bundle restrictions;
- object/executable/image emission and relocation;
- bare-metal image where target profile declares it.

### 11.2 ABI/platform

Tests MUST cover, where claimed:

- deterministic parameter/result classification;
- preserved/clobbered registers and stack alignment;
- red-zone/shadow-space/aggregate rules where applicable;
- typed variadic argument-pack construction;
- foreign representation compatibility and explicit adapters;
- identity-qualified opaque ABI carriers remain distinct and do not fabricate provenance/ownership;
- verifier-visible foreign reference lifetime acquisition/release where the platform contract declares ownership;
- provenance/bounds/ownership/effect/unwind loss at boundary;
- explicit unwind containment/conversion;
- syscall/device ABI contracts;
- missing platform capability rejection;
- optional/dynamic capability acquisition;
- dynamic-linking availability only when explicitly selected;
- freestanding program with no mandatory hosted runtime.

## 12. Compiler/incrementality tests

The compiler-core suite SHOULD test:

- deterministic structural then semantic verification;
- proof states: proven/runtime-enforced/waived/unsatisfied;
- dependency-complete cache keys;
- invalidation after type/effect/target/configuration change;
- unchanged-fact reuse after unrelated local edit;
- affected-frontier verification versus whole-program correctness oracle;
- negative dependency invalidation;
- parallel deterministic build reproducibility;
- crash/corruption recovery without accepting invalid authoritative state;
- optimizer candidate rejection when translation/equivalence validation fails.

## 13. Workspace C4 tests

Required vectors include:

- deterministic local handles for a fixed workspace/query mode;
- minimal neighborhood query plus bounded expansion;
- explicit truncation and continuation;
- when response-byte budgets are supported: exact-boundary success, deterministic one-byte-under failure or bounded positive-progress truncation, no publication of unreturned local handles, exact accounting of returned response bytes only, stable diagnostics, and unchanged behavior when no byte budget is supplied; byte-budget evidence MUST NOT be labeled model-token-budget conformance;
- authoritative/derived/estimate/unknown/stale result classification;
- generation-scoped local artifact identities for artifact-mapping queries;
- deterministic bounded `map_semantic` semantic-to-artifact ranges and `map_artifact` artifact-range contributors for supported emitted artifacts;
- exact half-open artifact ranges derived from retained compiler provenance, with erased/non-attributable semantics classified unavailable rather than guessed;
- artifact bindings record semantic root, target/configuration, explicit versioned compiler/lowering identities, emitted-artifact identity/digest, and retained exact ranges; identical dependencies produce stable binding identity while any output/dependency-affecting change invalidates reuse;
- the same artifact-mapping query/result semantics across materially different supported artifact formats/targets; target-specific layout must not require a second mapping language;
- artifact/mapping handles reject after their dependency generation or recorded compiler/lowering/target/artifact dependency changes and participate in read-set validation when exposed as read dependencies;
- transaction with expected root;
- generation-scoped expected-root aliases, when supported, remain stale across ABA restoration of identical root bytes;
- successful atomic commit;
- failed verification with unchanged root;
- stale-root rejection;
- entity/attribute/relation/delete-use/containment/proof conflict diagnostics;
- proof queries that expose a compact local proof-dependency read handle without persistent semantic CIDs, bind it to exact subject/root/verifier freshness internally, accept it while current, reject a dependency-changing commit with a stable proof-dependency conflict distinct from generic read conflict, preserve it across an unrelated commit only when its exact subject/verifier dependencies remain unchanged, invalidate root-scoped proof reads on root change, reject raw-root ABA restoration when a proof dependency changed during candidate construction, and account response/transaction bytes deterministically;
- for operand/use replacement support: successful exact-relation replacement, wrong-old-relation rejection with unchanged root, verifier rejection of a type/dominance-incompatible replacement, stale-root/read-set rejection, deterministic transaction accounting, and dependency-frontier propagation to direct callers;
- for node-deletion support: successful deletion of an unused verifier-safe node, deterministic local-position remapping, delete/use rejection for ordinary operands and terminator/control-edge arguments, wrong-containment rejection with unchanged root, stale-root/read-set rejection, deterministic transaction accounting/root, and dependency-frontier propagation to direct callers;
- for graph-node insertion support: successful verifier-safe insertion at an exact preconditioned position, deterministic remapping of later node and terminator references, transaction-local inserted-result use without persistent identity exposure, wrong-position rejection with unchanged root, ordinary verifier rejection of invalid type/dominance, stale-root/read-set rejection, deterministic transaction/response accounting, dependency-frontier propagation to direct callers, and reuse of unrelated reachable objects;
- for same-block graph-node move support: successful verifier-safe pure-node move under exact source and destination-anchor containment preconditions, deterministic producer-identity remapping of all surviving node-result/terminator references, unchanged semantics when the reorder is dependency-compatible, source/destination/self-anchor conflict rejection with unchanged root, ordinary verifier rejection of SSA-dominance-invalid reorder, stale-root/read-set rejection, deterministic root/transaction accounting, dependency-frontier propagation to direct callers, and reuse of unrelated reachable objects;
- for block-edge argument connect/disconnect support: successful same-transaction disconnect+connect at exact containing-block/edge/argument positions, exact old-value precondition checking, deterministic result independent of request ordering, transaction-local replacement-value consumption, wrong edge/argument/old-value rejection with unchanged root, disconnect-only rejection when the completed graph is verifier-invalid, ordinary verifier rejection of branch-argument type or SSA-dominance violations, stale-root/read-set rejection, deterministic transaction accounting/root, dependency-frontier propagation to direct callers, and reuse of unrelated reachable objects;
- for candidate-only verify/rollback support: successful private candidate verification with unchanged canonical root/generation, verifier-invalid candidate rejection with unchanged root, generation-scoped tooling-only candidate handle with no candidate CID or transaction-local semantic identity exposure, explicit rollback/discard with unchanged root, automatic invalidation of outstanding candidates on canonical commit, stale root/ordinary read/proof/artifact dependency rejection including raw-root ABA proof invalidation, deterministic candidate verification accounting separate from commit accounting, transaction-local inserted-result resolution inside private verification, and a subsequent ordinary commit from the unchanged base succeeding when its assumptions remain current;
- for workspace specialization support: exact source-function and parameter/type/value preconditions, candidate-only verification without clone identity leakage, deterministic clone/root identity, source and existing caller preservation, stale-root/read-set rejection, ordinary verifier rejection of unsupported calls/control/effects, retained-generation rebase only when source/type dependencies remain unchanged, and explicit non-claim of general META conformance;
- read-set/local-precondition failure;
- semantic rebase success only when assumptions remain compatible;
- rebase conflict when assumptions changed;
- deterministic structured diagnostic core and repair neighborhood;
- no whole-function/module dump unless explicitly requested/required by query.

## 14. Package/build/reproducibility tests

The suite SHOULD include:

- exact package-root integrity;
- deterministic resolution from identical candidate set/policy/configuration;
- ambiguity/conflict rejection;
- exact-root dependency and logical-identity constraint cases;
- snapshot completeness;
- offline rebuild from a locally complete snapshot closure;
- undeclared host input rejection in reproducible mode;
- explicit network/clock/random/sign/tool capabilities;
- dependency capability isolation;
- cache digest/root verification;
- provenance/trust-policy enforcement where claimed;
- cross-target cache separation;
- same-input repeated output-byte identity for deterministic profile, except where active spec explicitly uses a versioned canonical projection.

## 15. Bootstrap/self-hosting conformance evidence

Bootstrap claims are evidence labels, not base language conformance levels. Evidence bundles MUST identify exact compiler/spec/target/build-policy roots.

| Bootstrap label | Required evidence |
|---|---|
| B0 | Seed builds runnable first compiler for declared subset. |
| B1 | Authoritative compiler program is canonical XAX semantic state. |
| B2 | XAX compiler compiles its own authoritative program. |
| B3 | Fixed-policy generations have required semantic accept/reject equivalence. |
| B4 | Repeated self-build reaches required byte identity or predeclared canonical projection. |
| B5 | Required target encoding/link/object/package/build paths are XAX-hosted for claimed closure target. |
| B6 | Ordinary development/release/target maintenance does not require editing a second implementation language. |

Diverse double compilation or comparable trust evidence SHOULD be attached for trust-sensitive releases; it is not equivalent to a proof of compiler correctness.


### 15.1 Current M11 bootstrap evidence

The 2026-09-30 M11 implementation claims **B0** and **B1 only** for the declared arithmetic-folding compiler component. The authoritative program root is `e73735dff5be8c569a94fa434abf73015330d59fc13c4e4bf8e81aad87e2b92e`; the fixed hermetic bootstrap snapshot root is `ad0af6c240790d0e9845c2776fa8f4431fd7bf149997348995a323a1a262ad0e`; the package root is `c65da02999393448b39895a6085e64c65837eeded76bf9faecce1a56b18767b1`; the request root is `b44f86473bcb8cd1e49e242b5a14a798cb783582fff4fa5924d9df3bb13d950d`; and the fixed WebAssembly target root is `946143a04b0b1ba8ed7312af6c85f70cbb4f71644fb20f7aea3be8ed06da41ed`.

The seed build uses compiler identity `13dbd0cf3458d70b1e2f817928fa7248dabd7c6dade5ca52624ace6d6c296c78`, WebAssembly lowering identity `546ca644b02be7c240931ee7ed46e236ac02b10047506044e82eed530836821b`, and produces provenance root `2b951daac225cb560c650332e97299346f786fbd3f3a34c08e60676c7534f6aa`. The emitted 144-byte artifact has BLAKE3-256 digest `3f9f35e6fe8c8ec00e0490fa3e9f9b613255f6ab930c8d8ab2b9d18a221be09a`. Six implementation-local conformance vectors executed through both the Python seed/reference path and the seed-built XAX-hosted WebAssembly artifact and matched exactly.

B2, B3, B4, B5, and B6 are **not claimed**. No recursive compilation, generation equivalence, self-build fixed point, toolchain closure, bootstrap independence, or diverse-double-compilation trust claim follows from M11.

### 15.2 Current M14 closure evidence

The 2026-09-30 M14 implementation claims **B2–B6 only for the declared `xax-semantic-image-v1` closure target**. It does not extend those labels to the legacy x86-64, AArch64, WebAssembly, or accelerator lowerers.

The authoritative compiler image has program root `097da62f7ba9832620f5d202297fc522783ed5b4c9e68f8da6b77515b185164d` and entry function `4300342f92f9ba32bcefbb45af4aad117a3bbf3699bd66266b25cefdc874b6fc`. The XAX build graph materializes the input function as a canonical program root, invokes an XAX verifier-facing function, invokes an XAX canonical-image encoder function, and invokes an XAX finalization/link function. The verifier-facing and canonical-store operations terminate in deliberate trusted META substrate primitives; no legacy target-specific lowerer or package/build dispatcher is on this declared closure path.

B2 was executed by having generation 0 compile its own authoritative entry graph into generation 1 and loading/verifying that result as the next compiler. B3 uses four function-CID vectors compiled independently through generations 0 and 1; all **4/4** generated canonical-image digests match. B4 uses exact byte identity: generations 0, 1, and 2 all have root `097da62f7ba9832620f5d202297fc522783ed5b4c9e68f8da6b77515b185164d` and canonical-store BLAKE3-256 `6340c903f5da3e8aaf4d8ae886694a0d858687fc5c5520662a018518693f4788`.

B5 is target-scoped to the semantic-image path described above. For that path, semantic materialization, verifier invocation, encoding invocation, finalization, and build orchestration are represented by the authoritative XAX graph; canonical verification and store formation remain part of the minimal trusted substrate. This evidence does **not** permit describing the current native/WebAssembly/accelerator Python lowerers as XAX-hosted.

B6 is claimed at the approved immutable-seed boundary. `m14_seed_runtime.pyz` is a committed 46,255-byte seed artifact, SHA-256 `4e0c64d6f360359cc263c39817ec8cbe4cc3069edf20823755755c4d2707fe52`, that reconstructs the authoritative compiler byte-identically with repository `PYTHONPATH` removed and a temporary working directory. The archive internally contains Python modules and requires a Python interpreter; the claim is therefore **not** that Python execution has disappeared. The evidence is that ordinary release reconstruction for this closure target need not import or edit repository Python implementation sources. Replacing or independently trusting the seed is a separate bootstrap-trust question under OI-27.

The committed evidence record is `compiler/bootstrap/m14_selfhost_evidence.json`. Artifact generation was repeated and produced byte-identical compiler image, seed archive, and evidence JSON. Diverse double compilation has not been executed and no compiler-correctness proof is claimed.

### 15.3 OI-27 release-only diversity evidence

OI-27 adds a release-only Go checker rather than a second production compiler. For the bounded M11/M14 subset it independently implements suite-1 BLAKE3-256, canonical store/index/CID validation, semantic verification, and canonical store re-emission. On 2026-10-02 the selected 32,017-byte OI-26 seed and CPython 3.13.5 reconstructed the M14 semantic image through two generations at root `097da62f7ba9832620f5d202297fc522783ed5b4c9e68f8da6b77515b185164d`; the Go 1.23.2 checker independently verified that root and re-emitted the same 2,020 bytes under raw-byte comparison. Four controlled faults—pinned-root semantic divergence, runtime/output corruption, object-CID/hash corruption under a repaired outer digest, and a primary-verifier omission—were detected by the independent path. This is diversity evidence against those declared classes, not a proof that the pinned compiler graph, specification, test vectors, hardware, or release authorization are correct. The exact tool/seed identities and residual dependencies are recorded in `compiler/benchmarks/oi27_bootstrap_diversity_evidence.json`.
## 16. Deterministic diagnostics

Every negative semantic test SHOULD identify:

```text
code
entity
rule
expected
actual
dependencies
repair_neighborhood
```

The same candidate graph, verifier version, target/configuration, and rule set MUST yield the same core diagnostic identity/payload where determinism is claimed. Human wording may vary and is non-normative.

## 17. Cross-implementation equivalence

For common supported profiles:

1. identical canonical fixture objects MUST serialize identically under the same serialization version/objectization;
2. verifiers MUST agree on validity for normative vectors;
3. executors/compiled programs MUST agree on observable semantics for defined behavior;
4. target-defined behavior comparisons require the same exact target/platform contract;
5. different optimizer/code-generation choices are permitted when observable semantics and deterministic-profile obligations are preserved;
6. unsupported features MUST be reported as unsupported, not silently approximated.

## 18. Normative reference-example categories

The conformance suite MUST include at least one valid and one invalid or boundary-focused case, where meaningful, for:

1. exact arithmetic;
2. conditional branch;
3. loop with block parameters;
4. direct function call and CallContract;
5. stack memory/address/load/store;
6. linear resource flow;
7. checked recoverable error value;
8. atomic operation/order/scope;
9. syscall/platform boundary;
10. target primitive/opaque contract;
11. compile-time specialization;
12. transactional semantic edit.

Human-readable example notation is explanatory only; canonical fixtures are the conformance authority.

## 19. Optimizer and validated-search conformance

An implementation claiming the M12 optimizer slice MUST demonstrate:

1. every accepted transformed function passes the ordinary semantic verifier;
2. optimization legality is independent of non-semantic profile observations;
3. profile-guided decisions preserve observable semantics on the declared vectors and do not serialize profile observations into canonical program identity;
4. higher-effort/search-generated candidates are bounded by explicit deterministic compiler-work and memory budgets;
5. every search-generated candidate selected for acceptance passes an explicit equivalence/translation-validation mechanism appropriate to the claimed subset;
6. a candidate that fails validation cannot replace the last known-correct accepted function;
7. target cost reports identify the exact target, objective, unit, model identity/classification, and assumptions used for selection;
8. deterministic mode reproduces selected semantic identity/store bytes for the same input, policy, target, and tool identities.

### 19.1 Current M12 implementation-local evidence

The 2026-09-30 M12 prototype uses canonical optimization-policy root `924e070eceab1b9abba8c1cbb67fb2365fa7cc9f21362537f4b228bcdbd90dba`. Its search validator is exact polynomial equivalence over `Z/(2^N)` for the restricted pure wrapping-arithmetic subset, followed by ordinary graph verification. The fixed search fixture examines 64 candidates per target: 4 pass equivalence and 60 fail validation; rejected candidates do not alter accepted output. Deterministic selection chooses function CID `949339b59e4a8283ca0b269155c0f7db1573663e44bcf5cde1cd182a11ae9a7b` for both tested targets.

The lowering-derived code-size oracle records exact emitted function extents of 59→43 bytes for x86-64 target root `24e312c773b777ac4dd892b39a9477f1758ff8bf05d7708bfb8282120a9ded56` and 36→32 bytes for WebAssembly target root `946143a04b0b1ba8ed7312af6c85f70cbb4f71644fb20f7aea3be8ed06da41ed`. Profile-guided hot/cold inlining produces different profitability output while the profile bytes remain absent from canonical store bytes; execution vectors agree before/after.

This evidence is implementation-local and code-size-specific. It does not establish runtime speedup, calibrated target cost prediction, general optimization completeness, general solver equivalence, or closure of OI-17–OI-19.

## 20. No-results rule

This file defines obligations and test categories only. Conformance status, pass rates, benchmark measurements, and performance claims MUST be recorded in separate evidence artifacts tied to exact revisions.

## 20. M13 accelerator target/deployment obligations

An implementation claiming the M13 accelerator slice MUST demonstrate:

1. at least one non-CPU accelerator target package declares execution topology/scopes, memory spaces, and target-operation contracts without requiring a second source language;
2. target operation nodes name the exact target package and all target-dependent scope/space facts needed for verification;
3. host/device transfers, synchronization, effects, and resource ownership are explicit in the semantic graph rather than inferred by the backend;
4. unsupported requested execution scope or memory-space behavior rejects deterministically;
5. emitted/deployment artifacts identify the exact target and reproduce under identical semantic/build/tool inputs;
6. any target runtime dependency is explicit and selected by policy; absence of a dependency is recorded rather than inferred;
7. package/build provenance and semantic-to-artifact mapping remain target-neutral interfaces rather than target-specific side channels;
8. hardware/runtime performance is claimed only from actual physical execution measurements, not packet size or a host conformance harness.

### 20.1 Current M13 implementation-local evidence

The 2026-09-30 prototype target root is `202e9d0db81107e8380f27ef1f233327c34fe8a1f56431d38814ec4ee6feee04`. It declares 32-lane execution, device/workgroup execution scopes, explicit host/global/workgroup memory spaces, and six target-operation contracts. The tested graph threads one device effect and one linear buffer resource through explicit allocate → H→D → launch → synchronize → D→H → free operations. The target declares no runtime dependency.

The fixed program root is `6e088c0ff84c0723a9c3b7f527bf2bd98b886f8e5846f0200f5b1ee2ecf7db5c`. Repeated compilation emits the same 122-byte deployment packet; all six execution vectors match the wrapping-add contract. Unsupported launch scope and invalid H→D source memory space reject with `TARGET-OPERATION-SCOPE-SUPPORTED` and `TARGET-OPERATION-MEMORY-SPACES`. Package/build provenance and workspace semantic mapping use the existing target-neutral artifact interfaces.

This evidence establishes the declared prototype path only. No physical GPU was executed, so no accelerator latency/throughput/energy or vendor-portability claim is made. OI-16 remains open; OI-13 scope-normalization closure evidence is recorded below.

### 20.2 OI-13 synchronization-scope normalization evidence

The 2026-10-02 OI-13 experiment preserves the original M13 target root and deployment evidence byte-for-byte and adds a second package-driven accelerator model, `coherent-grid-accelerator-v1`, target root `0ffdb5e9fece2ccf25d51b7b48246ae8deb04cc9652471f786aa9f6eb91db7bf`. The second package has coherent host+device-visible unified memory plus workgroup-local memory and supports system/device/workgroup scopes. Its existing six-operation deployment contract verifies and lowers through the ordinary accelerator path without runtime dependencies.

The measured portable synchronization-scope subset is exactly `workgroup < device`. Portable-to-target mapping returns the same scope meaning on both target packages and rejects absence; target-to-portable mapping round-trips those two scopes exactly and reports coherent-grid `system` as nonportable rather than approximating it. Conformance vectors cover atomic and barrier ordering, both portable scopes, workgroup global/local cross-space synchronization, rejection of device scope over local-only memory, coherent-grid target-only system scope, and SIMT rejection of that system scope. These are semantic and target-package conformance vectors only; no physical accelerator execution or performance claim follows.

## 21. AI-native C-vs-XAX experiment obligations

The exploratory suite MUST use the same Codex Desktop model/reasoning setting, the same semantic goal, equivalent starting states and checks, fresh chats, and the same token-counting rule for C and XAX. Every question, failed edit, retry, turn, and associated token count remains in the recorded result. The task prompt must not include expected answers. Report all five paired rows and simple totals without inferential claims. The complete operator procedure is `compiler/benchmarks/ai_native/README.md`.

## 22. Android direct-artifact/platform-package obligations

An implementation claiming the current direct Android prototype slice MUST
demonstrate, for the exact declared profile:

1. generated DEX is deterministic and internally validates its header checksum,
   signature, ID/table bounds, class definition, and method/code layout;
2. lifecycle bridges preserve platform-required superclass behavior before the
   XAX callback and contain no unrequested reflection or allocation machinery;
3. binary manifest semantics are deterministic and exact for declared package,
   SDK profile, components, and intent filters;
4. APK entries have deterministic ordering/timestamps/compression policy and the
   declared data alignment, including native-library alignment;
5. signing consumes a package-declared/profile-granted `SIGN` capability whose
   scope is the public signer identity; private key material is accepted only via
   an explicit ephemeral build effect, MUST NOT appear in canonical semantic store,
   provenance, or build-key identity, and repeated deterministic signing is
   byte-identical for identical inputs/capability;
6. v2 signed-content verification rejects mutation of signed APK regions;
7. JNI method/field IDs are identity-qualified by owner/signature/staticness and
   descriptor-driven plans choose an exact JNI table entry rather than a generic
   varargs wrapper;
8. when a JNI loader domain is known, local/global/weak reference transitions
   preserve that domain, qualified member/reference identities do not alias a
   different loader domain, and a mismatched call operand rejects;
9. owned JNI references cannot be silently dropped or used after their ownership
   proof is consumed in the supported verifier subset;
10. a JNI call that may establish a Java exception transitions explicit verifier
    state from `clean` to `maybe-pending`; ordinary safe JNI operations reject
    that state until an explicitly selected supported policy (currently
    `ExceptionClear`) restores `clean`. This obligation does not claim conditional
    pending/clean branch refinement;
11. direct SDK/JAR import is canonical under archive entry reordering and imported
    target carriers verify through the ordinary canonical store verifier;
12. API availability checks reject a member outside the selected compile/runtime
    interval unless an explicit runtime guard proves the reachable interval;
13. a generated interface callback bridge records the implemented DEX interface.
    The pure forwarding profile contains one direct private native callback plus
    return. The bounded UI click profile may additionally perform an exact managed
    state mutation before that callback, but MUST emit no reflection or click-time
    allocation machinery and MUST still perform exactly one native transition;
14. Android component/UI behavior claimed to originate from XAX MUST be derived
    from a content-addressed semantic platform/build carrier rather than compiler-only
    configuration. Identical carrier identity MUST lower byte-identically; a local
    click-text-only edit MUST NOT change the unrelated Activity DEX in the current
    bounded profile;
15. homogeneous `Z/B/C/S/I/J` stack `jvalue[]` packs fully initialize every
    8-byte union slot and subword AArch64 stores use their exact byte width;
16. the bounded mixed pack accepts only `jlong` plus strong JNI references whose
    descriptor/subtype and required loader identity are proven; reference-to-word
    conversion is an explicit target ABI operation, owned local/global references
    thread their owner proof, and weak-global or unproved combinations reject;
17. nullable and proven-non-null mixed-pack reference identities are distinct, but
    this does not claim runtime null checking or conditional null refinement;
18. unsupported float/double JNI ABI lowering rejects rather than approximates;
19. host structural evidence MUST remain labeled structural. Installability, ART
    verification, lifecycle/callback execution, JNI behavior, and Android/Xposed
    behavior require execution on the corresponding real runtime before those
    claims may be made.
20. current modern-libxposed Java metadata MUST name exactly the generated
    `XposedModule` entry; hook adapter/installation carriers MUST reject unless the
    matching managed entry and module metadata are present;
21. the bounded API-102 hook-install profile MUST make target class/method, Hooker
    identity, parameter types, `PROTECTIVE` exception mode, `propagate` failure policy,
    and `process` lifetime part of canonical semantic identity. It accepts only zero
    parameters or exactly one `java.lang.String` parameter in the current profile;
22. `onPackageReady` hook installation MUST use the supplied package-ready ClassLoader,
    perform target/member resolution only in that lifecycle path, set the declared
    exception mode, allocate exactly one generated Hooker, and then perform the existing
    native package-ready callback. The one-String profile MAY additionally allocate one
    `Class[1]` at installation and MUST expose that allocation in evidence;
23. a pure pass-through generated Hooker MUST invoke `Chain.proceed()` exactly once,
    return that result, and contain no argument lookup, reflection, target/member
    resolution, or emitted allocation in the interceptor body;
24. the bounded result-replacement policy MUST remain a separate canonical carrier for
    an exact zero-argument String-returning target, invoke `Chain.proceed()` exactly once,
    capture the original result, return the declared replacement String, and emit no
    hot-path allocation;
25. the bounded argument-replacement policy MUST remain a separate canonical carrier for
    argument 0 of an exact `(String)->String` target, read argument 0, allocate exactly
    one `Object[1]`, store the declared replacement, and invoke `Chain.proceed(Object[])`
    exactly once. It MUST NOT claim zero XAX-attributable allocation;
26. the bounded combined mutation policy MUST remain a distinct canonical carrier for the
    same exact `(String)->String` target, perform the argument replacement above, invoke
    `proceed(Object[])` exactly once, capture the original result, and then return the
    declared replacement result with no additional emitted allocation;
27. hook-installation lifetime MUST be canonical. The `process` profile MUST remain
    field-free and MUST NOT claim explicit unhook. The `retained-manual-unhook` profile
    MUST store exactly one returned HookHandle, expose one `xaxUnhook()` method, return
    without framework work when the stored handle is null, otherwise invoke
    `HookHandle.unhook()` exactly once and clear the field before returning. Enabling
    retained lifetime MUST NOT change Hooker/interceptor bytes. All managed-hook runtime
    behavior, including actual unhook/idempotence, remains unproven until executed on a
    compatible libxposed runtime.
28. libxposed deoptimization MUST be an explicit canonical carrier and MUST NOT be
    inferred from hook installation. The current bounded profile MUST target the exact
    same executable as its companion hook-installation carrier, use explicit
    `best-effort` result policy, invoke `deoptimize(Executable)` exactly once after
    resolution and before `hook`, add no allocation, and leave Hooker/interceptor bytes
    unchanged. The boolean deoptimization result MUST NOT be silently upgraded to a
    success claim; real deoptimization remains unproven until runtime execution.
29. selected libxposed module services MUST be canonical and reachability-driven. The
    current bounded service set is framework name/version, remote preferences, remote
    file listing, and remote file open. Each selected generated helper MUST contain one
    wrapper `invoke-virtual`, one object result move, one object return, and no emitted
    allocation. Remote failures MUST use explicit `propagate` policy; the compiler MUST
    NOT hide capability checks, retries, caching, or exception translation. Unselected
    services MUST contribute no helper method.
30. remote-preferences and remote-files acquisition MUST use separate canonical
    carriers with explicit `nullable-on-unsupported` capability policy and MUST test
    `PROP_CAP_REMOTE` before invoking a remote operation. Capability absence MUST return
    null without the remote invocation; after capability presence, framework failure MUST
    propagate. The bounded preference surface is read-only boolean/int/long/float/String/
    contains through direct `SharedPreferences` interface calls and MUST emit no Editor or
    write path. The bounded files surface is list/open only. Selected gates/reads MUST
    contain no emitted allocation unless a later carrier explicitly changes the policy.
31. hot reload MUST be a separate canonical API-102 carrier. The current bounded
    `single-retained-hook-id-guarded-atomic-replace` profile MUST require exactly one Java
    entry and exactly one `retained-manual-unhook` generated hook, MUST emit
    `autoHotReload=true`, MUST set one declared stable hook ID on the initial HookBuilder,
    and MUST capture the target/app `ClassLoader` supplied by `PackageReadyParam`.
    `onHotReloading` MUST reject reload when that host-owned loader was never captured;
    otherwise it MUST pass only that loader through `setSavedInstanceState(...)` and MUST
    NOT persist module-defined objects, lambdas, HookHandles, or hidden resource state.
    `onHotReloaded` MUST restore the saved loader, check for an empty old-handle list,
    compare the old handle's `getId()` result with the declared ID, skip replacement on
    absent/mismatched transfer state under the explicit policy, and otherwise perform
    exactly one `HookHandle.replaceHook(...)` before storing the returned handle. It MUST
    NOT unhook/reinstall. Multi-hook identity, lifecycle replay, and external-resource
    cleanup/migration MUST reject or remain outside the profile rather than being inferred.
    Runtime saved-state transfer, ID transfer, mismatch behavior, and replacement atomicity
    remain unproven until compatible framework execution.

## 23. Universal-replacement obligations

Replacement claims (`XAX_SPEC.md` §21) are separate from C0–C4: C-levels certify an implementation; R-levels certify a `(platform package, workload class)` pair.

1. **Claim form.** An R-level claim MUST name the platform row of `XAX_REPLACEMENT_MATRIX.json`, the workload, the target/platform/ABI package identities, and the evidence artifacts. The claimed level MUST equal the level derived by `compiler/src/xax_replacement.py`; `compiler/tests/test_replacement_matrix.py` MUST pass.
2. **Labels.** Each matrix field is `UNIMPLEMENTED`, `NOT_APPLICABLE`, or one of PROVEN/EXECUTED/MEASURED/STRUCTURAL/PROTOTYPE with at least one existing evidence path. Bare labels and missing paths are non-conforming.
3. **No hidden runtime.** For R1+ the row's `runtime_requirement` MUST list every platform-required runtime and compiler-generated adapter; an emitted artifact containing any XAX-owned runtime, startup code, or exit path not derived from an explicit contract is non-conforming.
4. **Foreign ABI ownership.** A backend MUST reject foreign declarations whose ABI it does not own (`XAX.FOREIGN.ABI`); a container that cannot bind imports MUST reject images that contain them (`XAX.NATIVE.IMPORTS`).
5. **Hosted lifecycle.** Process/application start and exit MUST be explicit platform contracts. For `x86_64-windows-pe-v1`, the entry MUST take no machine parameters and return only integer values (`XAX.PE.ENTRY`), and process termination is the program's explicit `ExitProcess` call.
6. **Negative vectors.** Each new platform row at R1+ MUST add negative tests for its ABI/container rules. Current vectors: `compiler/tests/test_xax_pe.py` (wrong-ABI foreign call, raw-image foreign call, parameterized PE entry, raw execution of an import-bearing image) and `compiler/tests/test_replacement_matrix.py` (overclaim, bare label, missing evidence).
7. **Heap views and frontiers (U1.2a).** `x86_64-windows-pe-v1` MUST trap (not assume) on a null allocator result before producing a heap view, and MUST range-check dynamic heap offsets at runtime: `compiler/tests/test_xax_pe.py::test_out_of_bounds_heap_store_traps` requires `STATUS_ILLEGAL_INSTRUCTION` for an index one past the view. Pointer-free memory-effect calls MUST consume the input effect linearly (ADR-079).
8. **WASI (U1.4).** `wasm32-wasi-v1` MUST import only declared `wasm32-import` functions, export `_start` and `memory`, reject entries with machine parameters/results (`XAX.WASM.WASI_ENTRY`), reject other foreign ABIs (`XAX.FOREIGN.ABI`), and the core wasm profile MUST reject foreign calls. Vectors: `compiler/tests/test_xax_wasi.py`.
8a. **Browser pages (ADR-103).** `wasm32-browser-v1` MUST export `_start` and `memory` and MUST reject entries with machine parameters or results. A generated page MUST contain host functions only for bindings the module imports, and MUST reject any import that is not an `xax-web-v1` package declaration (`WEB-IMPORT-DECLARED`). Page generation MUST be deterministic. A `wasm32-browser-event` entry MUST reject machine values, resources, memory effects, and parameters not returned unchanged (`GRAPH-FUNCTION-ADDRESS-FOREIGN-ENTRY`). Wasm MUST reject any other code address (`WASM-FUNCTION-ADDRESS-EVENT-ENTRY`), and x86-64 MUST reject browser entries (ADR-104). The wasm backend MUST reject integer-completion operations on targets that do not list them (`WASM-OP-TARGET-SUPPORTED`). Vectors: `compiler/tests/test_xax_web.py` (headless Chromium: queries `30`, `90`, empty, and `7x9` render `n fib(n)` and two clicks advance it, e.g. `30 832040` → `31 1346269` → `32 2178309`).
9. **Address exposure (ADR-081).** `pointer_address` MUST carry waiver attribute 1, MUST reject exposure of ended storage, MUST produce a provenance-free integer of the target pointer width (backends reject other widths), and MUST NOT be executable by the reference executor. Vectors: `compiler/tests/test_xax_wasi.py::test_address_exposure_requires_waiver_and_live_storage`.
10. **Pointer elements (ADR-082).** Pointer-typed memory accesses MUST use the target pointer width (`NATIVE-POINTER-ELEMENT-WIDTH`); storing a pointer with local storage provenance MUST reject (`MEMORY-POINTER-STORE-LOCAL-PROVENANCE`); reloaded pointers MUST carry no storage facts. Vectors: `compiler/tests/test_xax_pe.py::test_local_pointer_store_rejects_until_oi37` and the executed dispatch table in the PE fixture.
11. **Linux x86-64 (U1.3; ADR-085–ADR-088).** `x86_64-linux-elf-exec-v1` MUST emit a static ELF64 `ET_EXEC` with no `PT_INTERP`, `PT_DYNAMIC`, relocations, or container code; `e_entry` MUST be the XAX entry function. The entry MUST take no machine parameters and return at most one integer (`XAX.LINUX.ENTRY`). It MUST be lowered for Linux's aligned, no-return-address entry and MUST trap if it returns; process exit is the program's explicit `exit_group`. Non-Linux targets reject (`XAX.LINUX.TARGET`). `linux-x86_64-syscall-v1` templates MUST be canonical, use every machine operand exactly once, and take at most six arguments (`XAX.FOREIGN.SYSCALL`). Allocator-contract failures MUST project to null, and `heap_view` of null MUST trap. A zero `udiv`/`urem` divisor that is not a nonzero constant MUST trap with portable reason 2. `x86_64-linux-elf-dynexec-v1` MUST additionally emit `PT_PHDR`, `PT_INTERP` naming exactly `/lib64/ld-linux-x86-64.so.2`, and `PT_DYNAMIC`, with `DT_NEEDED` equal to the declared `sysv-x86_64-c` sonames (no default libc) and bind-now GOT relocations only. It MUST reject `sysv-x86_64-c` on the static profile (`SYSV-C-REQUIRES-DYNAMIC-PROFILE`), signatures outside register-passed INTEGER/SSE scalars (`SYSV-C-SCALAR-CLASS`), an implicit loader (`XAX.LINUX.DYNAMIC_REQUIRED`), and one symbol imported from two libraries (`XAX.LINUX.IMPORT`). Vectors: `compiler/tests/test_xax_linux.py`; register-allocation validation: `compiler/tests/test_xax_regalloc_differential.py`.
12. **Pointer rebase (ADR-092).** `pointer_rebase` MUST trap, never produce a value, when the address is outside [view, view + view extent - extent] or misaligned relative to the view. The result MUST NOT gain element, permission, alignment, address space, or extent over its view. Loads through a windowed pointer MUST prove initialization of the whole window, and windowed stores MUST NOT add initialized intervals. Vectors: `compiler/tests/test_xax_pointer_rebase.py` (x86-64) and `compiler/tests/test_xax_wasm_rebase.py` (wasm32: list walk exits 42; out-of-range, misaligned, below-view, and wrapped links trap), with in-range execution and SIGILL traps for out-of-range, misaligned, and wrapped addresses, plus `MEMORY-REBASE-*`, `MEMORY-LIFETIME-LIVE`, and `MEMORY-INITIALIZED` rejections.
12b. **Android containers and evidence (ADR-105, ADR-106).** An Android target MUST name image format 4 or 5, and any other format MUST reject (`TARGET-AARCH64-PROFILE`). A format-5 library MUST have `p_offset ≡ p_vaddr (mod 16 KiB)` for both `PT_LOAD` segments, MUST place RW at an address no lower than the 16 KiB-rounded end of RX, and MUST relocate every RW address (GOT, `.dynamic`, `.data`, `.bss`, import thunks) by the same constant. Format-4 output MUST stay byte-identical. Every committed APK MUST pass `apksigner` (when signed), `zipalign -c -P 16`, `aapt2 dump badging`, `dexdump`, and D8 re-dexing. The JNI slot tables MUST equal the NDK `jni.h` declaration order. Vectors: `test_xax_android_packed.py`, `test_xax_android_official_tools.py`, `test_xax_android_bionic.py` (29 runs under Android's `linker64` and bionic via `qemu-aarch64`).
12d. **ART verification (ADR-108).** Every committed APK MUST verify under ART `dex2oat --compiler-filter=verify` with every class `Verified`. libxposed modules are verified with the libxposed API they target as parent class loader. An ill-typed control MUST NOT be `Verified`. Vectors: `test_xax_android_art_verify.py`, `bench_android_art_verify.py`.
12e. **libxposed modules on ART (ADR-109).** Every generated libxposed module with managed code MUST, on ART with a stand-in API-102 framework, produce exactly its declared observation: hook target, exception mode, framework and builder call order, the number of `proceed` calls and their arguments, the returned value, unhook through a retained handle, and capability-gated service behaviour. Vectors: `test_xax_android_art_execute.py` (the combined module live, plus a patched-literal control).
12f. **AArch64 register path (ADR-110).** A general-target function MUST take the register path only when all its values are 32/64-bit integers, pointers, or compare results, all its operations are in the register-path subset, and its calls have at most eight machine arguments. Every value used across blocks MUST be written to its home at its definition before any other block reads it. v3 output MUST stay byte-identical. Vectors: `test_xax_aarch64_regalloc_differential.py` (288 results under bionic).
12g. **Stateful Android app (ADR-111).** The counter's native functions MUST restore the count from the state file, increment and persist it on click, and close the descriptor they receive. Assembled DEX instructions MUST reject unknown mnemonics, more than five invoke registers, and malformed operands. Existing DEX output MUST stay byte-identical. Vectors: `test_xax_android_counter.py`.
12c. **Android C entries (ADR-107).** An `android-aapcs64-c` entry MUST be pure and MUST reject narrow parameters, more than eight parameters, or a non-integer result (`AARCH64-ENTRY-SIGNATURE`). AArch64 MUST reject other entry ABIs (`AARCH64-FOREIGN-ENTRY-TARGET`), and x86-64 MUST reject this one. The lowered address MUST be the function's own entry. Vectors: `test_xax_android_c_entry.py`; execution: four concurrent bionic threads with XAX start routines (`bench_android_bionic.py`).
12a. **Foreign entries (ADR-102).** `FUNCTION_ADDRESS` with a `code-entry:<abi>` result type MUST reject an ABI outside `FOREIGN_ENTRY_ABIS` and a target function with proof parameters or results (`GRAPH-FUNCTION-ADDRESS-FOREIGN-ENTRY`). Passing an internal `ptr<opaque<function>>` where a declaration names a foreign entry type MUST reject (`FOREIGN-CALL-CONTRACT`), as MUST `CALL_INDIRECT` through a foreign entry address (`INDIRECT-CALL-TARGET-TYPE`). The x86-64 SysV adapter MUST zero-extend narrow arguments, keep RSP 16-byte aligned at the internal call, and reject more than four parameters or non-integer classes (`SYSV-ENTRY-SIGNATURE`) and non-Linux profiles (`SYSV-ENTRY-TARGET`); AArch64 MUST reject foreign entries. Vectors: `compiler/tests/test_xax_c_interop.py` (libc `tsearch`/`tfind` with an XAX comparator exits 31; a constant comparator exits 78; libm SSE-class calls exit 68).
13. **Linux startup reads (ADR-094).** `linux-x86_64-startup-v1` declarations MUST be rejected outside the process entry function (`LINUX-STARTUP-PROCESS-ENTRY`) and on non-Linux targets (ABI ownership). Out-of-range `argv`/`envp` indexes MUST trap. Copies MUST NOT write past the destination view's static extent and MUST return the bytes copied. Vectors: `compiler/tests/test_xax_linux_startup.py`.
14. **Record links (ADR-097).** A store into a link field MUST accept only null or a link into that storage's link target. `address_offset` on record pointers MUST land on whole records or exact fields. Foreign calls MUST NOT receive a link-bearing storage's memory effect except to deallocate it. A link target MUST NOT end before the storages that target it. `link_follow` MUST trap on null unless a dominating test proved the link nonzero. A view passed to a direct call MUST link into its own storage, or into the storage of the view its callee's `link_target` declaration names (ADR-101; `MEMORY-LINK-CALL-TARGET`). Vectors: `compiler/tests/test_xax_links.py` (x86-64 Linux), `test_xax_wasm_links.py` (wasm32), `test_xax_pe_links.py` (PE under Wine).
15. **JVM class files (ADR-112).** `jvm-classfile-v1` MUST reject operations outside its profile (`JVM-OP-TARGET-SUPPORTED`) and any machine tuple other than (1, 6, 1, 64, 64) (`TARGET-JVM-CLASSFILE`). A foreign declaration MUST use a JVM ABI (`XAX.FOREIGN.ABI`), and its descriptor MUST agree with its declared types (`JVM-FOREIGN-DESCRIPTOR-TYPE`, `JVM-FOREIGN-ARITY`). An executable JAR's entry MUST be proof-only (`JVM-PROCESS-ENTRY-CONTRACT`). Emitted classes MUST load under HotSpot's split verifier, and every result, including traps, MUST equal the reference executor's. The JAR MUST be byte-deterministic. Vectors: `compiler/tests/test_xax_jvm.py` (differential corpus, float grid, `java -jar` run exiting 7 with expected stdout, trap-to-node mapping, package build).
16. **RISC-V raw images (ADR-113).** `riscv64-baremetal-raw-v1` MUST reject operations outside its integer profile, more than eight machine arguments (`RISCV64-REGISTER-ARGUMENTS`), and any machine tuple other than (1, 7, 1, 64, 64) (`TARGET-RISCV64-RAW`). A zero `udiv`/`urem` divisor MUST trap. Every emitted word MUST decode as RV64IM. The entry MUST be at offset 0 and the image position-independent. Vectors: `compiler/tests/test_xax_riscv64.py` (Unicorn; `llvm-mc` decode).
17. **Evidence hosts (ADR-114).** An emulator or harness adapter MUST execute exactly the image bytes the target receives. A row whose execution is emulator-only MUST list "not hardware" among its blockers and MUST NOT cite the emulator for `performance`.
18. **Lend entries (ADR-115).** A `sysv-x86_64-c-lend` callee MUST match the admissibility shape (`GRAPH-FUNCTION-ADDRESS-FOREIGN-ENTRY`). Passing such an entry to a call that does not lend a whole live initialized view of the entry's extent with its memory effect MUST reject (`LEND-ENTRY-VIEW-LENT`). Vectors: `compiler/tests/test_xax_lend_entry.py` (glibc `qsort_r` exits 117; `atexit`, no-lend, write-through, writable-view, wrong-extent, and pointer-result rejections).

