# XAX Compiler State

## Current milestone

M1 — minimal canonical semantic store and structural verifier: **complete for prototype schema revision 1**.

M2 — arithmetic, functions, calls, and branches: **complete for the prototype operation set**.

M3 — stack memory, pointer facts, and explicit lifetime: **complete for the straight-line prototype subset**.

M4 — first direct native backend: **complete for the declared x86-64 Windows raw-load-image subset**.

M5 — second architecturally different native backend: **complete for the declared AArch64 bare-metal load-image subset**.

M6 — transactional AI workspace: **complete for the declared prototype workspace capability**. The bounded query/mutation/specialization surface, dependency-aware verification, target-neutral artifact mappings, retained multi-generation diff/rebase, and durable canonical workspace save/load all have executable evidence. General recursion-group editing, changed-entity semantic merge, and multi-process coordination remain later capability growth rather than missing prototype exit criteria.

M7 — effects and resources: **complete for the declared prototype operation set**. Generic acquire/transfer/transition/release/discard, partitionable split/join, multiple domain-instance effects, cross-block linear flow, derived direct-call summaries, reference execution, and proof-value ABI erasure are implemented and validated. Indirect calls are not an accepted operation in this schema; recursive general summaries and persistent summary objects remain future extensions.

M8 — atomics, interrupts, and real-time profiles: **complete for the declared prototype slice**. All five portable atomic families and orders, target capability rejection, x86-64 lowering, race/litmus validation, target-driven handler contracts, latency-property queries, and strict post-lowering rejection profiles have executable evidence. OI-11 now adds one explicit bounded-inline x86-64 case plus legalization policy selection; cross-target implemented atomics, real runtime-assisted atomics, persistent timing proofs, and a normative external litmus corpus remain future work.

M9 — compile-time XAX specialization/metaprogramming: **complete for the declared prototype slice**. Ordinary verified XAX graphs execute under a deterministic bounded compile-time stage with explicit semantic inputs/capabilities, typed type/constant/function/target references, target inspection, candidate function construction, dependency-complete memoization, verifier-gated materialization, and compile-time abstraction erasure. Broader semantic construction and richer introspection remain future extensions.

M10 — package/build/security/reproducibility semantics: **complete for the declared prototype slice**. Canonical package/profile/request/snapshot/trust/provenance/signature objects, exact/logical deterministic resolution, typed feature/configuration bindings, exact offline closure, package-local capability grants, reproducible-mode rejection, verified cache entries, signature hooks, and direct x86-64/WebAssembly builds have executable evidence. Compatibility constraint algebra, persistent/remote caches, action-level provenance, and OS sandbox adapters remain future extensions.

M11 — XAX self-hosting subset: **complete for the declared B0/B1 prototype slice**. The authoritative arithmetic-folding compiler component is committed as canonical XAX semantic state, the fixed hermetic WebAssembly bootstrap snapshot rebuilds it through the ordinary package/build path, exact tool/policy/provenance roots are recorded, and six seed-versus-hosted conformance vectors execute equivalently. M11 itself claims B0/B1 only; later M14 evidence supplies B2–B6 for a separate, explicitly scoped semantic-image closure target.

M12 — optimizer expansion and validated search: **complete for the declared prototype slice**. Deterministic local simplification/CFG passes, conservative pure direct-call inlining, non-semantic profile-guided profitability, a canonical optimization-policy build object with explicit deterministic work/memory budgets, lowering-derived target code-size selection, and bounded wrapping-arithmetic search with exact modular-polynomial equivalence validation are implemented. Search candidates that fail validation cannot become accepted output. Broader optimizer organization, calibrated runtime cost models, loop/vector/SROA optimization, and richer proof mechanisms remain open under OI-17–OI-19.

M13 — accelerator target path: **complete for the declared prototype slice**. A canonical non-CPU SIMT packet target package declares execution topology/scopes, host/global/workgroup memory spaces, and six typed target-operation contracts. Generic `target` nodes carry the exact package plus operation/scope/space attributes; host/device buffer ownership and the device effect are explicit and linear. The direct accelerator backend emits a deterministic deployment packet, build/provenance/workspace mapping use the existing target-neutral interfaces, and unsupported scope/memory-space requests reject deterministically. This is deployment-format/conformance evidence only; it is not physical-GPU throughput/latency evidence and does not close OI-13 or OI-16.

M14 — full self-hosting transition: **complete for the declared `xax-semantic-image-v1` closure target**. The authoritative XAX compiler graph materializes a program root, invokes an XAX-hosted verifier-facing service, emits the reachable canonical store through the trusted serialization substrate, and performs XAX-hosted finalization/build orchestration. Executed recursive generations establish B2, four generation-equivalence vectors establish B3, generation 0/1/2 reach exact byte identity for B4, the declared semantic-image service path establishes target-scoped B5, and reconstruction through the committed immutable seed runtime with repository Python sources removed from the import path establishes the declared B6 seed boundary. This B5/B6 claim explicitly excludes the legacy x86-64, AArch64, WebAssembly, and accelerator lowerers.

Post-roadmap AI-native experiment: **a five-task manual C-vs-XAX Codex Desktop benchmark is ready; historical, non-qualifying Codex Desktop rows exist and are negative for XAX (1.25× C's tokens; see OI-31)**. The OI-01 transport-candidate arms have one 30-trial Claude Code run (30/30 completed; details below and in `XAX_OPEN_ISSUES.md`). It has no API transport, frozen corpus, preregistration, or significance machinery. See `compiler/benchmarks/ai_native/README.md`.


Repository: repository root. Compiler: `compiler/`.

U1 — universal-replacement proof set: **in progress**. Step status is in `XAX_IMPLEMENTATION_ROADMAP.md` U1; the dated sections below are the history of each step.

<!-- xax-status:levels -->Replacement levels (generated from `XAX_REPLACEMENT_MATRIX.json`): R4: linux-x86_64; R3: android-arm64, linux-aarch64; R2: aarch64-baremetal, browser-web, jvm; R1: gpu-spirv-cuda-metal-dxil, riscv64, wasm32-core, wasm32-wasi, windows-x86_64-pe; R0: accelerator-simt-packet; no level yet: bsd-unix, dotnet-clr, macos-ios-apple, rtos-embedded-mcu.<!-- /xax-status:levels -->

S — compiler migration ladder: **S0–S5 EXECUTED** on the production path (native XAX leaves on Linux x86-64) and **S6 EXECUTED** with B1–B4 for the RISC-V backend and the store verifier on RV64 under emulation (ADR-116–ADR-151). BLAKE3 also closes on RV64 (ADR-151). **S7a EXECUTED** (ADR-152): the x86-64 views backend is an XAX program with B1–B4 natively on x86-64, and it lowers every native helper. Open (S7b): the driver's lowering structures and the exact rejection diagnostics, which still run in Python.

Dated sections below are historical records: a figure in them (a ratio, a level, a test count) is current only if no later section supersedes it.

## Implemented

- Python 3.11+ bootstrap library and `xaxc` diagnostic CLI.
- M14 compile-time function/graph introspection plus generic semantic-object/byte opaque values, verifier-gated program materialization, canonical-store emission, and semantic verification under explicit META capabilities. Executed bootstrap labels are recorded separately from mere capability presence.
- Container major 1 header/trailer with `XAX\0`/`XAXE` magic.
- Minimal ULEB128, ZigZag, boolean, byte-string, list/count encoding checks.
- Hash suite 1 using BLAKE3-256 and `XAX-SEM-1` semantic domain separation.
- Semantic envelopes, sorted/deduplicated direct-reference tables, CID checks, CID-sorted records, canonical index, and whole-store digest.
- Indexed object lookup without decoding unrelated semantic bodies.
- Prototype schema revision 1 for all core kind IDs, documented in `XAX_PROTOTYPE_SCHEMA_V1.md`.
- Stored 1,229-byte all-kinds fixture plus expected root/object CID manifest.
- Canonical opaque non-semantic record framing that preserves semantic root identity.
- `bits<N>` types and canonical bit constants.
- Prototype `add.wrap`, `sub.wrap`, `mul.wrap`, constant, direct-call, and recursion-group member-call contracts.
- Functions, blocks, block parameters, `br`, `cbr`, `ret`, and `trap` structural verification.
- Recursion groups with verified local call contracts, restricted to exactly one recursive SCC in canonical member order.
- Operation arity/type, direct-call contract, branch argument, return contract, local-reference, SSA dominance, reachability, CID-cycle, and direct-reference verification.
- Deterministic machine diagnostics with stable rule/code fields.
- Bounded semantic executor for constants, wrapping arithmetic, direct calls, recursion-group member calls, branches, returns, and explicit traps.
- Stored executable direct-call fixture with exact root/entry CIDs, inputs, and expected output.
- `ptr<stack,bits<N>,permission,alignment>`, `effect<memory>`, and distinct `resource<stack-storage,live>` prototype types.
- General `effect<domain,instance>` types for memory, I/O, syscall, device, filesystem, network, time, random, privileged, unsafe, and atomic domains; general resource kind/state/instance types with affine, partitionable, releasable, acquirable, and declared-transition flags.
- Generic acquire, transfer, state transition, release, affine discard, sibling-checked split/join, and multi-domain effect-step operations with exact cross-block linear consumption through edges, returns, and traps.
- Derived direct-function effect summaries report domain instances plus return/trap behavior; workspace `effects` queries expose these summaries without making them canonical source objects.
- OI-08 closes effect partition granularity for memory/filesystem/network/device: use the narrowest verifier-proven `effect<domain,instance>` partition, with instance 0 as the conservative fallback when independence is unproven. The four 8-event pair fixtures gain 16 unordered pairs and halve the effect critical path (8 -> 4) for +4 graph-body bytes/+2 ideal token atoms; the 36-event mixed fixture gains 162 unordered pairs and shortens 13 -> 6 for +16 bytes/+8 atoms.
- OI-08's benchmark-only persistent comparator reconstructs the exact same partial order from domain-grouped semantic runs plus explicit fork/join predecessor deltas. Refined pair sections shrink 48 -> 36 B and 44 -> 32 ideal token atoms; the mixed section shrinks 230 -> 162 B and 226 -> 158 atoms; the branch/merge fixture preserves two roots and a two-predecessor join at 22 -> 20 B. Canonical store v1 is unchanged.
- Resource/effect proof values erase from x86-64, AArch64, and WebAssembly ABIs, edge copies, calls, returns, and emitted bytes; proof-only direct calls emit no runtime call.
- General language target profiles now carry native `f32`/`f64`, tuple/array/sum construction and extraction, signed/unsigned integer↔float conversion, pointer values, and recursive C-layout aggregate lowering. `abi_layout` lays out tuples, arrays, and tagged sums. x86-64 Win64 lowers ABI-sized aggregates directly, larger/non-power-of-two aggregates through 16-byte-aligned caller copies, and arguments beyond the first four through the standard stack/home area; AArch64 AAPCS64 classifies scalar FP, homogeneous FP aggregates, one/two-register composites, stack arguments, indirect large arguments, and `x8` indirect aggregate returns; wasm32 uses native float locals and deterministic linear-memory C-layout aggregate values. Legacy wasm32 profiles route through the retained v1 lowering so their module bytes and evidence hashes remain unchanged; the other legacy target profiles retain their original narrower contracts and hashes.
- Foreign allocator contracts can now make an explicitly sized `HEAP_VIEW` from allocator-returned storage. `HEAP_VIEW` consumes the allocator pointer, linear owner, and allocator memory-effect continuation, then produces an extent-bearing pointer/view/effect triple. The verifier tracks foreign-allocation provenance, exact extent, alignment, permission, initialization frontier, and linear owner/effect state; direct core load/store is permitted only through that proof. POSIX/Android `malloc` declares its allocator contract and `free_heap_view(...)` creates a matching typed deallocator declaration so the extent-bearing view owner is consumed explicitly rather than weakened to raw foreign memory.
- Library-level UTF-8/string support in `src/xax_strings.py` provides strict UTF-8 validation, byte-boundary searching/counting, deterministic scalar formatting, and allocator-backed owned strings with explicit clone/concat/append/format/free operations. It introduces no core string type, finalizer, hidden allocator, or implicit lifetime.
- Android/AArch64 platform runtime evidence now has an executable v4 shared-object probe plus `integration/android/validate_platform_contracts.sh`. On a compatible arm64 Android device/emulator it validates XAX-lowered file open/write/read/close, pthread create/join, and loopback socket connect/send/recv/close. This repository snapshot does not claim device execution unless `android_platform_runtime_probe_evidence.json` contains `runtime.executed=true`; the current development host has no `adb`/AArch64 Android runtime.
- Explicit stack allocation, constant address offset, little-endian bits load/store, and stack lifetime end operations.
- Verifier facts for allocation-node provenance, allocation-derived precise alias class, remaining extent, alignment, permission, initialization intervals, linear per-allocation memory effects, owner consumption, and live lifetime.
- Direct calls may consume one live stack owner/memory-effect pair and return the same symbolic provenance exactly once. A verifier-internal `_ResourceCallContract` descriptor is authoritative for caller recognition, entry proof seeding, supported callee access shape, and owner/effect result positions; it is derived tooling state and is not serialized XAX source or a permanent DSL. The bootstrap supports owner/effect pass-through; 1–8 same-pointer stores for `(ptr<stack,T,P,A>, T, owner, effect) -> (owner, effect)`; 1–8 same-pointer loads for `(ptr<stack,T,P,A>, owner, effect) -> (T, owner, effect)`; and 2–8 same-pointer mixed store/load accesses for `(ptr<stack,T,P,A>, T, owner, effect) -> (T, owner, effect)` when the final access is a load returned as the ordinary value. The verifier derives the mixed-call precondition from the verified callee access order: load-first mixed sequences require exact-range incoming initialization, while store-first mixed sequences do not; any store establishes initialization for the successor frontier. Mixed sequences require read+write authority. The 8-access bound is a bootstrap verifier capability limit, not canonical language semantics. Drop, duplicate/reuse, effect fork, unsupported body shape/order, insufficient extent/alignment/permission, uninitialized range, wrong returned value, and mismatched provenance reject deterministically.
- OI-09 adds kind-11 reusable `call_contract` objects as the semantic placement for bounded indirect-call contracts. Prototype v1 stores exact input/output type references plus `may_return`/`may_trap`; effect bounds and explicit resource/capability-bearing values are reconstructed from those exact types. `derive_call_contract` creates the implementation-independent contract from a verified direct function, and `verify_function_call_contract` rejects signature/effect/control overflow. The indirect-call opcode/verifier contract and x86-64/AArch64 bounded runtime dispatch are implemented; wasm32 indirect-call lowering and an unknown-effects contract remain absent.
- OI-10 fixes the portable trap payload core as a canonical u16 reason plus optional opaque target/platform bytes. Empty payload is reason 0 with no target detail; non-empty payload begins with canonical u16 ULEB plus target detail, with zero allowed only when suffix bytes follow. `XaxTrap` and CLI diagnostics expose reason/target-data separately while retaining exact payload bytes. x86-64 Windows maps the portable reason through `rax` before `ud2`; AAPCS64 maps it through `x0` and `brk #imm16`. Trap remains non-returning with no implicit cleanup or unwind.
- Bounded reference execution for the straight-line stack-memory subset; verifier facts add no runtime metadata to emitted semantics.
- Stable 1,030-byte M3 vector identities for allocate/store/load/end, with negative tests for bounds, alignment, permission, initialization, effect forks, owner/effect separation, lifetime leaks, and use after lifetime.
- Canonical x86-64 Windows target package with machine width, ABI registers, stack alignment/shadow space, raw load-image profile, and supported operation/terminator sets.
- Direct deterministic x86-64 instruction encoding, rel32 call/branch fixups, stack-slot register allocation, Windows x64 entry/call ABI, and raw callable load-image emission in `src/xax_x86_64.py`.
- Native isolated execution for wrapping 32/64-bit arithmetic, constants up to 64 bits, direct calls, block-parameter branches, conditional branches, returns/traps, and the straight-line M3 stack subset.
- Canonical atomic load/store/RMW/compare-exchange/fence operations with explicit portable order, scope, alignment, compare-exchange strength/failure order, and wrapping-update semantics. Verification rejects invalid order pairs, permissions, initialization, bounds, alignment, types, and scopes.
- Target atomic capability queries classify exact address-space/width/alignment/family/order/scope requests as native, bounded sequence, runtime assist, or unsupported and expose lock-free, retry, required-alignment, supported-order/scope, and latency facts. The implemented target set currently produces native, one bounded x86-64 case, or unsupported; no target currently declares a real runtime assist. Unsupported operations reject; no lock, helper, scheduler, syscall, allocator, or runtime is inserted.
- x86-64 lowering emits aligned 32/64-bit loads/stores, `xchg`, locked `xadd`/`cmpxchg`, and fences. The existing system-scope 32/64-bit seq-cst load path is explicitly classified as a bounded inline load+`mfence` sequence; acquire loads remain native. Strong lowering is valid for weak compare-exchange; no spurious failure is introduced by this backend.
- Implementation-local race/litmus validation covers per-agent order, explicit happens-before, conflicting non-atomic access rejection, modification order, release sequences, seq-cst order, and explicit weak compare-exchange spurious-failure witnesses.
- Target profile revision 2 carries atomic widths/scopes/families and explicit interrupt-handler entry contracts. Handler validation enforces proof-only ABI, allowed effect domains, strict real-time policy, and stack bound.
- Workspace atomic capability, real-time, and handler-entry queries expose target-qualified facts. Real-time analysis derives stack/control/recursion/retry/progress/effect/assist facts and strict profiles reject forbidden or unknown target support, progress, bounds, runtime assistance, effects, timing guarantees, or interrupt-mask bounds when requested.
- Type form 5 carries typed opaque compile-time references to types, constants, functions, and targets. Meta operations 25–29 inspect bit widths/constants/target operation support, read indexed declared inputs, and construct verified constant-return functions.
- `CompileTimeEvaluator` executes ordinary arithmetic, constants, calls, recursion-group calls, branches, traps, and meta operations with explicit step, call-depth, memory, semantic-object, and emitted-node budgets. Runtime-only memory/effect/resource/atomic operations reject at the compile-time stage; no filesystem, network, clock, random, process, environment, or device API exists in the evaluator.
- Compile-time cache keys include callable/member identity, semantic arguments, ordered declared inputs, capabilities, reproducibility policy, and evaluator/verifier identities while excluding terminating-only budget ceilings. Only successful verified results cache; budget/stage/capability failures publish nothing.
- `materialize_compile_time` creates a private replacement module/root, retains only its reachable closure, and runs the ordinary whole-store verifier before returning it. Generated constant functions contain no meta operations and execute through reference and isolated x86-64 paths.
- Kind 9 encodes canonical package identity, modules, exact/logical dependency requirements, build entries, typed feature/configuration schemas, and declared build capabilities. Kind 10 tagged forms encode profiles, build requests, snapshots, trust policies, provenance, and signatures.
- The M10 resolver consumes an explicit candidate set, selects exact roots directly, accepts a logical identity only with exactly one candidate, and produces a content-addressed exact transitive snapshot closure. Discovery order is non-semantic; missing/ambiguous requirements reject deterministically.
- Hermetic build validation requires exact external BLAKE3 inputs, isolates capability grants by package logical identity, rejects live network/clock/random observations in reproducible mode, and exposes no ambient host API in the implemented pure direct-emission action.
- Build keys bind snapshot/request/compiler/lowering identities; requests and snapshots transitively bind target, profile, typed feature/configuration values, trust, packages, signatures, and external inputs. Cache reads revalidate artifact digest, provenance closure, and optional provenance signatures.
- Stored objdump inspection and stable native-image hashes: 238-byte branch/call image and 43-byte stack-memory image.
- Canonical WebAssembly target package with direct core-module ABI, 32-bit linear-memory addresses, 32/64-bit scalar storage, and the same supported operation/terminator sets.
- Direct deterministic WebAssembly binary encoding in `src/xax_wasm.py`; no WAT, external compiler, imports, libc, allocator, or XAX runtime.
- Dispatcher-based CFG lowering, direct calls, subword masking, static one-page stack-storage lowering for acyclic calls, and Node-isolated execution.
- Stable WebAssembly hashes: 185-byte branch/call module and 78-byte stack-memory module; both M4 semantic vectors execute with identical results on both targets.
- Canonical AArch64 bare-metal target package with AAPCS64 argument/result registers, 16-byte stack alignment, no shadow space, and raw callable load-image profile.
- Direct deterministic AArch64 encoding in `src/xax_aarch64.py`: stack frames, link-register preservation, branches, calls, wrapping 32/64-bit arithmetic, and M3 stack memory.
- QEMU 11.0.1 executes the same branch/call and stack-memory programs on a `virt`/`cortex-a72` machine; Capstone 5.0.9 disassembly is stored. The invocation wrapper alone uses semihosting.
- Stable AArch64 hashes: 212-byte branch/call image and 44-byte stack-memory image; results match x86-64, WebAssembly, and reference execution.
- `xaxc verify`, `xaxc inspect`, and `xaxc run` entrypoints.
- Bounded per-function node queries with generation-scoped local handles, deterministic pagination, authoritative operation/literal facts, and exposed-entity accounting.
- Deterministic bounded direct-`users` queries backed by a per-root reverse-reference index and generation-scoped object handles.
- Deterministic bounded `callers`/`callees` queries for standalone functions return only generation-scoped `F*` handles, support continuation, update entity accounting, and make exposed function handles valid read-set members.
- Bounded `operands` queries accept exposed node handles and return only graph-local value handles plus authoritative local type handles. Results paginate deterministically, update entity accounting, join transaction read sets, and reject stale node/value/type handles after commit.
- `type` queries accept exposed `T*` handles and return authoritative local facts for bits, pointers, general domain-instance effects, and general kind/state/flag/transition resources. Nested pointer element types remain local handles; no persistent CID is exposed. Type reads update entity accounting, join transaction read sets, and reject stale handles after commit.
- `effects` queries accept exposed node handles or function-bound node handles, report pure nodes explicitly, return authoritative frontier input/output values for stack and general effect/resource operations, and expose derived function domain-instance/return/trap summaries. Nested value/type handles join transaction read sets; query accounting and stale rejection are deterministic.
- One-hop `neighborhood` queries accept exposed node handles and return deterministic operand/result handles with explicit effect-input/effect-output relations. A caller-supplied entity limit, continuation, query accounting, read-set bindings, and stale-handle rejection are enforced without exposing persistent CIDs.
- Bounded `expand` queries accept exposed value handles, an explicit `producer` or `users` direction, positive depth, entity limit, and continuation. Deterministic breadth-first traversal alternates node/value handles, labels producer/user/operand/result relations, deduplicates revisited entities, updates read-set bindings/accounting, rejects stale handles, and exposes no persistent CIDs.
- Bounded `invalidate` queries accept exposed function or object handles and traverse the existing reverse-reference index transitively. Deterministic dependent object handles paginate under an entity limit, join read sets, reject stale handles, and expose no persistent CIDs.
- Bounded retained-generation `diff` queries compare any retained verified reader with the current root. Removed and added object kinds are returned in deterministic CID order through opaque `D*` handles with continuation; unavailable bases reject, and persistent CIDs are not exposed.
- Bounded `repair_neighborhood` queries paginate the deterministic local handles already attached to rejected-transaction diagnostics. Stale-root and read conflicts include the root/read handle plus mutation targets; attribute conflicts identify the target. No additional persistent CID is exposed.
- Every implemented workspace query records exact response bytes using a compact sorted-key JSON bootstrap projection. The API accepts an optional exact serialized response-byte budget: paginated queries shrink to the largest positive-progress prefix that fits and return continuation; non-paginated or too-small pages fail deterministically with `XAX.WORKSPACE.RESPONSE_BUDGET`. Only returned handles are published and only returned response bytes are charged. This framing is removable tooling, not authoritative XAX source or a model-token-budget claim; without a byte budget the two-page three-node vector remains 472 bytes.
- The `root` query atomically returns `R0`, the explicit canonical root identity, and workspace generation. Target, platform, and configuration contexts are individually classified unavailable until bound; the fixed response is 249 bootstrap bytes before and after a commit.
- A workspace may bind one separately verified native target package. Target-qualified `layout` queries return derived byte size/alignment for standard `bits<8|16|32|64>` and pointer forms, classify absent targets/unsupported forms unavailable, reject stale type handles, and identify the target CID. x86-64 and wasm32 pointer layouts differ as 8 and 4 bytes.
- Target-qualified `cost` queries report operation identity and package-declared support authoritatively. Numeric instruction cost, latency, and code bytes remain explicitly unavailable because current target packages encode no cost model; missing targets and stale node handles are handled deterministically.
- `proof` queries accept `R0` or exposed current-generation entity handles and report verified-under-current-root status plus bootstrap verifier identity authoritatively. Formal proof artifacts remain explicitly unavailable; stale handles reject and no persistent entity CID is exposed.
- Artifact provenance uses the shared tooling-only `ArtifactSemanticRange` / `MappableArtifact` interface across x86-64 raw load images, AArch64 raw load images, and WebAssembly modules. `ArtifactProvenanceBinding` records the exact semantic root, target/configuration CID, opaque explicit compiler/lowering V1 identities, SHA-256 emitted-artifact digest, and retained ranges; a compact SHA-256 binding identity commits to the binary dependency record. Same inputs reproduce the identity; root-only, target, or lowering changes alter it, while same-generation compiler/lowering mismatches stale mapping/read-set reuse. Each backend retains exact half-open function spans and node spans only where a node directly emits attributable bytes; emitted bytes are unchanged. Workspace `artifact`, `map_semantic`, and `map_artifact` use one target-neutral query contract, generation-local `A<generation>.<function-index>` handles, bounded pagination, read-set participation, and dependency staleness. On the common 32-bit stack vector: x86-64 maps function/store/load to `[0,43)` / `[12,21)` / `[21,30)`; AArch64 to `[0,44)` / `[12,20)` / `[20,28)`; WebAssembly to body `[39,78)` / `[56,63)` / `[63,70)`. Stack allocation/lifetime semantics and WebAssembly container bytes without exact semantic contributors remain unavailable rather than guessed.
- `entity` queries inspect already-exposed function, object, node, value, type, and artifact handles through one generation-checked entrypoint. Results contain only minimal authoritative/derived kind/fact views and local cross-references; persistent semantic CIDs are not exposed.
- Atomic expected-root transactions for canonical handle-ordered batches of wrapping-operation substitutions, constant-literal edits, typed operand/use replacement, and the first typed pure-node deletion across standalone functions, with explicit local-handle read sets, per-mutation attribute/relation/containment preconditions, duplicate-target rejection, private candidate verification, stale/read-conflict rejection, generation invalidation, and protocol-byte accounting.
- `ReplaceUse` changes exactly one node operand relation using an explicit operand index, expected old `ValueRef`, and replacement `ValueRef`. Wrong-old relations reject as `XAX.WORKSPACE.RELATION_CONFLICT`; type/dominance incompatibilities flow through the ordinary graph verifier before publication. The Python carrier is bootstrap tooling only, not XAX source.
- `DeleteNode` removes exactly one current pure constant/wrapping-arithmetic node using an explicit expected block/node containment precondition. Wrong containment rejects as `XAX.WORKSPACE.CONTAINMENT_CONFLICT`; any ordinary operand, terminator value, or control-edge argument use rejects as `XAX.WORKSPACE.DELETE_USE_CONFLICT`. Surviving node-result references are deterministically renumbered and the rebuilt candidate passes the ordinary verifier before publication. The Python carrier is bootstrap tooling only, not XAX source.
- `InsertPureNode` inserts one pure constant or wrapping-arithmetic node immediately before an existing current node under exact expected block/index preconditions. Surviving old node references are deterministically shifted. `TransactionValueRef` gives another mutation in the same transaction a nonpersistent integer-scoped reference to the inserted result; it is resolved only while constructing the private candidate and is never published as a semantic/workspace identity. Wrong position rejects as `XAX.WORKSPACE.CONTAINMENT_CONFLICT`, and type/dominance legality remains the ordinary graph verifier's responsibility.
- `DisconnectEdgeArgument` / `ConnectEdgeArgument` edit one block-terminator edge argument in private candidate state. The disconnect carries exact expected block, edge index, argument index, and old graph-local `ValueRef`; the connect carries the same position plus a graph-local or `TransactionValueRef` replacement. Wrong block/edge position rejects as `XAX.WORKSPACE.CONTAINMENT_CONFLICT`; wrong argument index/old value rejects as `XAX.WORKSPACE.RELATION_CONFLICT`; branch arity/type and dominance remain ordinary verifier obligations. A matching pair may share one node anchor in the same transaction; request ordering does not affect the candidate root.
- Copy-on-write mutation retains unchanged semantic objects while rebuilding the changed constant when needed plus graph/function/module/root ancestors. Deterministic candidate roots and structured conflict diagnostics are tested.
- Mutation input order does not affect candidate root or transaction size. Every batch precondition is checked before rebuilding; empty, duplicate, cyclic-topology, or partially invalid batches reject without publication.
- Disjoint functions and standalone caller/callee pairs may be edited in one transaction. Edited functions rebuild in call-dependency order, preserving caller-local edits while substituting edited callees; shared callers/modules/root rebuild once. Direct caller/callee output roots remain identical under reversed mutation order.
- Transaction results return every changed function CID in deterministic old-CID order; the compatibility `changed_entity` view is available only for single-function transactions.
- Changed function CIDs propagate through complete acyclic `call.direct` caller chains via the reverse-reference index; every affected graph/function/module/root is rebuilt once per final dependency state. Only newly created/rebuilt reachable objects are then verified; unchanged objects retain the verification established when the workspace root was opened. Unsupported recursion-group caller topology rejects without publication.
- Transaction results and workspace accounting record exact frontier objects examined by the verifier. A full-store verifier remains the regression oracle, and candidate-verification failure rejects atomically without changing the root.
- Explicit retained-generation rebase translates previously exposed node/object/function/value/type handles only when their persistent function/object identities remain reachable and unchanged after independent commits. Mutation preconditions are rechecked against the current root; changed targets, changed read-set entities, and dependency-rebuilt functions reject with deterministic rebase-conflict diagnostics.
- Transactions may use a workspace-local `R0.<generation>` expected-root alias instead of retransmitting the 32-byte root. Byte-root transactions remain supported. Alias freshness is checked before candidate work and again at the final atomic compare, so an ABA sequence that restores identical root bytes still rejects the stale generation.

- `SpecializeFunction` clones one current standalone straight-line single-block function containing only constants and wrapping arithmetic under explicit `(parameter index, expected type, constant value)` arguments. Specialized parameters become constant nodes and disappear from the clone interface. The clone remains private during candidate verification, is published alongside the unchanged source, does not rewire callers, has deterministic content identity/accounting, participates in stale-root/read-set and retained-generation rebase checks, and uses the ordinary verifier. This is workspace semantic construction only, not general compile-time XAX/META.


- M12 optimizer service in `compiler/src/xax_optimizer.py` implements deterministic constant folding, wrapping identities, block-local exact CSE, pure-node DCE, constant-branch CFG simplification, and conservative pure single-block direct-call inlining. Effect/resource/atomic regions are preserved conservatively and excluded from current search/inlining.
- Canonical kind-10 build form 7 is an `optimization_policy` carrying code-size objective ID plus explicit pass/search/candidate/memory/polynomial/inlining budgets and a deterministic flag. Profile observations remain tooling-only and are not serialized into canonical program/build semantics.
- Target-aware code-size selection lowers each verified candidate through the existing target backend and measures its exact emitted function extent. The current cost report is explicitly a lowering-derived estimate, not latency/throughput/energy calibration.
- The first bounded higher-effort path enumerates pure one-block `add.wrap`/`sub.wrap`/`mul.wrap` expressions and validates candidates by the ordinary verifier plus exact polynomial equivalence over `Z/(2^N)` under a declared polynomial-term budget. Invalid/non-equivalent candidates are rejected without altering accepted output.

- Generic operation 30 `target` references an exact target package and carries target-defined operation ID, execution scope, source memory space, and destination memory space. The core verifier checks declared signatures, exact supported scopes/spaces, legal resource-state transitions, and exact effect continuation without knowing accelerator opcodes.
- Canonical target profile 3 / architecture 4 `simt32-packet-accelerator-v1` declares 32-lane execution, device/workgroup scopes, host/global/workgroup memory spaces, and six target-defined contracts for allocation, H→D transfer, launch, synchronization, D→H transfer, and release. No target runtime dependency is declared in this revision.
- `compiler/src/xax_accelerator.py` emits the deterministic `XAXA\x01` deployment packet directly. The fixed M13 path uses an explicit device effect and a linear buffer resource through all six operations; the deterministic harness executes the target-defined wrapping-add launch for conformance only.
- Accelerator deployment is artifact kind 2 and uses the ordinary package/build snapshot and provenance path plus a versioned lowering identity. Workspace artifact/mapping queries consume the same target-neutral `MappableArtifact` ranges used by CPU/WebAssembly targets.

## Supported targets

- x86-64 Windows, raw callable load-image profile revision 2 with native system-scope 32/64-bit atomics and one explicit handler entry, target CID `24e312c773b777ac4dd892b39a9477f1758ff8bf05d7708bfb8282120a9ded56`. Invocation uses an isolated Windows host harness.
- WebAssembly core module, target CID `946143a04b0b1ba8ed7312af6c85f70cbb4f71644fb20f7aea3be8ed06da41ed`. Invocation uses Node/V8 only as a test harness; emitted modules have no imports.
- AArch64 bare-metal raw callable load image, target CID `0af5a0c8db7996951be281cf7ab22a7ee158287c43f195c9518f782f5832e355`. Invocation uses QEMU/semihosting only as a test harness; emitted code contains neither.
- Prototype SIMT packet accelerator, profile 3 / architecture 4, target CID `202e9d0db81107e8380f27ef1f233327c34fe8a1f56431d38814ec4ee6feee04`. It emits a deterministic deployment packet with no declared runtime dependency; `run_accelerator_deployment` is a conformance harness, not an emitted runtime or physical-GPU claim.

- x86-64 Windows hosted PE32+ executable, target `x86_64-windows-pe-v1` (CID `9c6224e5e314c60a1bbfd2dc54b28ccac19b570d5113ba2c70bb7686fbf67d1c`): v5 operations plus `call_foreign`, `heap_view`, and `pointer_address` under the `win64-c` ABI, bound through a loader-filled import table by `xax_pe.emit_pe_executable`. Runs as an ordinary Windows process; no harness.

- x86-64 Linux `x86_64-linux-elf-exec-v1` (static) and `x86_64-linux-elf-dynexec-v1` (explicit `ld.so`, declared `DT_NEEDED` only): direct ELF64 `ET_EXEC`, EXECUTED natively on Linux x86-64. `e_entry` is the XAX entry; the program exits explicitly with `exit_group`.

- JVM `jvm-classfile-v1` (architecture 5, ADR-112): one class file (major 61) in a stored deterministic JAR, EXECUTED on OpenJDK 21 HotSpot with `java -jar`. Foreign members are typed `jvm-invokestatic`/`jvm-invokevirtual`/`jvm-getstatic` declarations; `xax_jvm.java_base_api()` covers `System.out`, `println`, `print(char)`, `flush`, `System.exit`, `Math.sqrt`, `System.nanoTime`, and `Long.bitCount`.

- RISC-V `riscv64-baremetal-raw-v1` (architecture 6, ADR-113): a raw position-independent RV64IM image with the LP64 integer convention, EXECUTED under the Unicorn RV64 emulator (test harness only).

All emitted forms have no mandatory XAX runtime, allocator, libc, assembler, linker, or LLVM dependency. The M13 accelerator package declares an empty runtime-dependency set.

## Build and test commands

```text
cd compiler
PYTHONPATH=src:. python -m py_compile src/*.py tests/*.py benchmarks/*.py benchmarks/ai_native/*.py bootstrap/*.py
PYTHONPATH=src python -m unittest tests.test_xax_selfhost -v
PYTHONPATH=src:. python -m unittest tests.test_ai_native_benchmark -v
PYTHONPATH=src:. python -m benchmarks.ai_native prepare task-01 C
PYTHONPATH=src:. python -m benchmarks.ai_native prepare task-01 XAX
PYTHONPATH=src python bootstrap/generate_m14.py
PYTHONPATH=src python -m unittest discover -s tests -v
SOURCE_DATE_EPOCH=946684800 python -m pip wheel . --no-deps --no-build-isolation --wheel-dir dist
```

Since ADR-114 the raw Win64 images also execute on Linux x86-64 hosts (a harness call thunk), and AArch64 raw images run in Unicorn when `qemu-system-aarch64` is absent (`pip install unicorn`). The RISC-V tests need Unicorn, and the JVM tests need `java` and `javac`. M14's `xax-semantic-image-v1` closure tests themselves are host-portable under the approved Python seed execution environment.

## Executed test state

- 2026-09-30 Linux x86-64 / Python 3.13.5 final M14 repository contains **239 test methods**.
- Basic Python syntax/import compilation passed for `compiler/src`, `compiler/tests`, `compiler/benchmarks`, and `compiler/bootstrap`.
- M14 narrow gate on the final repository state: **7/7 passed**. This includes graph introspection/capability checks, executed B2–B5 recursive evidence, committed compiler/evidence integrity, and repository-source-independent reconstruction through the committed seed runtime.
- The broad unfiltered regression was executed before the final two artifact-integrity assertions were added: **237 tests**, with exactly the same **8 environment-only execution errors** as M13 (6 Windows x86-64 native execution cases and 2 AArch64/QEMU cases). No M14 or hash regression appeared.
- Final applicable regression on the exact final code/test state, excluding only those same 8 host-bound cases: **231/231 passed** in **13.371 seconds**. The current total is 239 tests: 231 executed applicable passes plus 8 unavailable host-bound cases.
- Executed M14 recursive evidence: closure target `xax-semantic-image-v1`; compiler function `4300342f92f9ba32bcefbb45af4aad117a3bbf3699bd66266b25cefdc874b6fc`; compiler root `097da62f7ba9832620f5d202297fc522783ed5b4c9e68f8da6b77515b185164d`; generation 0/1/2 canonical-store BLAKE3-256 `6340c903f5da3e8aaf4d8ae886694a0d858687fc5c5520662a018518693f4788`; all three roots are identical; all **4/4** fixed-policy function vectors match.
- The committed compiler image is **2,020 bytes**, SHA-256 `05eb15404836e9f77b2f2931489859c43c0f75dcb00c891504e9ddcdd427cd07`. The immutable seed runtime is **46,255 bytes**, SHA-256 `4e0c64d6f360359cc263c39817ec8cbe4cc3069edf20823755755c4d2707fe52`, BLAKE3-256 `eb8157fd2a00fcca5666ea574b7641b4adcb43382f5fbb60f8addead5f04b7b6`. The evidence JSON is **3,240 bytes**, SHA-256 `36c2a9a57aea432250ff7a1595e19535ed1d37f2aa7588cd4edd1f01710c6dfa`.
- The M14 artifact generator was run twice after the final evidence-wording correction; compiler image, seed archive, and evidence JSON hashes were byte-identical across both runs.
- Deterministic wheel reproducibility passed twice with `SOURCE_DATE_EPOCH=946684800`: `xax_compiler-0.1.0-py3-none-any.whl`, **117,715 bytes**, SHA-256 `fa4add6e966ca09fe5df6c02043e91d333f0726ec92f681a03bf7251e4a4a34e`. The build used setuptools 82.0.1.
- Tiny AI-native benchmark validation on 2026-09-30: focused tests pass **7/7** and the full compiler suite passes **246/246**.
- OI-02 granularity harness on 2026-10-01 (Windows x86-64, Python 3.12.10): focused tests passed **4/4** and the full compiler suite **257/257** in 36.8 seconds; after `call_indirect`, focused **6/6** and full suite **276/276** in 45.1 seconds. The completed fourth `block` candidate now passes the focused OI-02 suite **7/7** in the current repository; no new full-suite pass is claimed for this later edit.
- OI-03 recursion-carrier harness and verifier enforcement on 2026-10-01 (Windows x86-64): focused tests passed **10/10**; the historical concurrent full-suite run saw one OI-02 evidence mismatch while `call_indirect` was being added. That OI-02 evidence mismatch is no longer present; the current OI-02 focused reproduction test passes.
- OI-04 type-vocabulary harness on 2026-10-01 (Windows x86-64, Python 3.12.10): pre-dictionary focused tests passed **7/7** and the full compiler suite passed **271/271** in 39.2 seconds. For the later store-wide CID-dictionary edit, all **9/9** focused tests that do not require `tiktoken` pass natively on the current host; the complete OI-04 suite is **10/10** when the unchanged committed tiktoken counts are replayed through a local test shim. A new broad-suite run was attempted but exceeded this host's execution window, so no new full-suite pass is claimed.
- OI-07 DMA-vocabulary harness on 2026-10-01: focused tests pass **7/7**. The non-coherent split-memory and coherent shared-memory target packages both verify, compile deterministically, and execute **4/4** fixed DMA vectors; omitting non-coherent cache clean or either target's synchronization rejects by resource/target type state. Portable core/workspace/build/optimizer/bootstrap/selfhost plus OI-05/OI-06/OI-07 regression passed **265 tests with 1 existing skip** after excluding exactly the same 8 host-bound execution cases. In addition, all six non-evidence OI-02 tests, all nine non-tokenizer OI-03 tests, and all nine non-tokenizer OI-04 tests passed. The OI-02 committed-evidence replay exceeded this host's execution window; the OI-03/OI-04 committed-evidence replays are blocked here by absent `tiktoken`. No semantics or tests were weakened to hide those environment/tooling limits.
- OI-08 effect partition/edge-encoding harness on 2026-10-01: focused tests pass **8/8**. Syntax compilation passed for all compiler source, benchmark, and test modules. The broad core/workspace/build/optimizer/bootstrap/selfhost/accelerator plus OI-05/OI-06/OI-07/OI-08 run produced **260 passes** and exactly the same **8 host-bound execution failures** (6 Windows x86-64, 2 AArch64/QEMU); rerunning with only those eight collected node IDs deselected produced **260/260 passed**. The portable non-evidence OI-02/OI-03/OI-04 subset added **24/24 passed**, and the AI-native test module added **13 passed / 1 existing skip**. No semantic test was weakened or skipped to make OI-08 pass.

## Known gaps

- Workspace specialization is deliberately restricted to one explicit-constant clone of a standalone straight-line single-block constants/wrapping-arithmetic function. It does not evaluate calls, control flow, effects/resources, target queries, types as values, or arbitrary compile-time XAX; it does not automatically rewire callers or implement specialization caching policy.
- No external normative fixture corpus exists yet; current vectors are implementation-local.
- Switch and checked/saturating arithmetic remain unimplemented. General target profiles now implement sum values; x86-64 and AArch64 general profiles also lower bounded indirect calls. wasm32 indirect-call lowering, recursion-group ABI, and native multi-result ABI remain outside this completion.
- Stack-memory proof flow remains deliberately limited to one transferred pointer/range and its fixed direct-call contracts. Multiple pointer alias classes, checked/raw access forms, and a second memory model remain absent. General resources/effects have cross-block flow and derived direct-call summaries, but no persistent summary objects or recursive summary fixed point.
- Legacy `x86_64-windows-load-image-v2` and `aarch64-baremetal-load-image-v1` keep their original bounded scalar ABIs for compatibility. The general profiles (`x86_64-windows-load-image-v5`, `aarch64-baremetal-load-image-v2`, `wasm32-core-module-v2`, and Android arm64 shared v4) add pointer/float/product/sum values and target ABI aggregate classification. Native general functions still expose at most one machine return; recursion-group ABI and native multi-result ABI remain absent. x86 remains a raw load image; bare-metal AArch64 remains a raw load image; Android uses the separate ET_DYN emitter.
- Target instruction semantics/encodings still reside in removable Python bootstrap code. M12 can derive exact emitted function byte extents through target lowering, but target packages still do not encode calibrated latency/throughput/energy cost models.
- WebAssembly stack storage uses deterministic static linear-memory offsets and rejects direct-call cycles. Reentrant/recursive stack lowering is absent.
- Store parser loads container bytes into memory, though it decodes object bodies lazily.
- Prototype ULEB decoder limits values to ten encoded bytes.
- M6 queries inspect roots/entities, nodes/operands/results/effects/types, users/callers/callees, bounded neighborhoods/expansion/invalidation, retained-generation diffs, and target-neutral semantic/artifact mappings. Compatible unchanged entities can rebase from any retained generation; changed entities reject rather than guess. `Workspace.save/load` durably round-trips canonical store bytes atomically. Artifact indexes, candidate state, and retained history remain process-local; recursion-group edits, changed-entity merge, workspace-integrated general META transactions, and multi-process commit coordination remain unsupported.
- M9 construction currently emits only constant-return functions; it does not yet expose arbitrary type/block/operation/module/target constructors, persistent on-disk compile-time caches, scoped introspection views, or general workspace transaction integration. Its memory accounting is a deterministic evaluator-frame bound, not measured host process memory. OI-14 and OI-15 remain open.
- M10 logical requirements deliberately support only the deterministic exactly-one-candidate rule; version/compatibility algebra, coexisting logical versions, registry discovery, persistent/remote caches, arbitrary build-time XAX action graphs, publication, real signing implementations, OS sandbox adapters, and action-level provenance remain unavailable. Signature algorithms are explicit caller-supplied verification hooks. OI-23, OI-24, and OI-30 remain open.
- M11 remains historical B0/B1 evidence for its arithmetic-folding component. M14 later establishes B2–B6 only for `xax-semantic-image-v1`; the legacy x86-64, AArch64, WebAssembly, and accelerator lowering/emission paths remain Python bootstrap/reference implementations and are outside that closure claim. Diverse-double-compilation trust evidence remains unavailable under OI-27.
- M12 search is restricted to pure one-block same-width wrapping integer polynomial expressions with one or two parameters and constants 0/1/2. The exact polynomial validator is intentionally independent of target lowering but is not a general solver/proof object. Interprocedural optimization only inlines verified pure single-block direct calls. Profile data currently contains call weights only. OI-17, OI-18, and OI-19 remain open.
- M6 mutation handles batches across disjoint functions and standalone call-dependency DAGs. Recursion-group callers and other unsupported parent kinds reject. Frontier verification currently relies on the restricted mutation vocabulary preserving the verified old DAG; generalized insert/connect/disconnect mutations will require explicit candidate reachability/cycle frontier checks.
- Runtime ABI layout now covers byte-sized bit/float/pointer values plus recursive tuples, arrays, and tagged sums under the general target profiles. Arbitrary non-byte-sized runtime fields, user-declared packed/over-aligned/explicit-offset layouts, platform/configuration-dependent record definitions, and package-defined custom alignment rules remain unavailable.
- Current target packages still carry no calibrated numeric cost model. M12 adds a tooling-side lowering-derived exact function-size oracle for candidate selection, while workspace `cost` and target packages do not yet claim instruction latency, throughput, energy, or predictive magnitude calibration. OI-17 remains open.
- `proof` reports successful verifier status retained by the workspace, not a portable proof object, proof certificate, or independently checkable derivation. Each successful proof query also publishes an ephemeral `P<n>.<generation>` read-dependency handle backed privately by the exact semantic subject, observed root, and explicit verifier identity. Subject proof reads may survive unrelated commits only when the same content-addressed subject/verifier dependency remains valid; root proofs invalidate on any root change; changed proof reads reject distinctly as `XAX.WORKSPACE.PROOF_CONFLICT`.
- OI-05 adds an optional non-semantic proof-cache sidecar for successful object-verification facts. Keys contain verifier identity, exact subject CID, and exact direct-reference CID tuple; cache bytes are canonical/integrity-checked but never enter the semantic store/root. `StoreReader` may carry the cache, `Workspace.load/save` may persist it separately, and local commits replace/prune only affected proof entries. Missing/stale entries recompute and corrupt sidecars reject explicitly. On the committed 96-function evidence workload, the cache is 33,639 B versus a 42,155 B program store; a one-function edit invalidates/writes 5 entries while reusing 286 objects. OI-05 is closed; the sidecar remains optional because its storage/maintenance cost is material.
- M8/OI-11 atomic lowering exists only for aligned system-scope 32/64-bit x86-64 stack storage; seq-cst load is the sole bounded-inline case and the remaining implemented x86-64 cases are native. AArch64/WebAssembly atomics, shared pointer parameters, runtime-assist packages, additional bounded-inline cases, GPU scopes, external thread/lock/channel fixtures, and target cost/timing guarantees remain unavailable rather than guessed.
- Handler policy fields are explicit target data, but only the current x86-64 entry contract is implemented; a second interrupt architecture and persistent timing/interrupt-mask proof representation remain absent. The litmus/race corpus is implementation-local and does not close OI-12 or OI-29. OI-11 remains open for its own measured latency and multi-architecture implementation evidence.

- M13 proves one synthetic non-CPU deployment target and target-package contract path only. It does not execute on physical GPU hardware, normalize multiple vendor scope lattices, lower general kernels, prove coherence/barrier semantics across devices, or calibrate accelerator cost/performance. OI-13 and OI-16 remain open.

## Latest benchmark status

- **OI-05 proof-cache persistence (2026-10-01):** `compiler/benchmarks/oi05_proof_cache_evidence.json` records seven raw samples per arm over a deterministic 96-function workload. Median verifier-only cold/warm is 92.65/42.46 ms; restart-inclusive load+verify 135.98/124.27 ms; compiler-only cold/warm 127.55/79.36 ms; restart-inclusive load+compile 171.70/162.73 ms; build-only cold/warm 218.56/171.81 ms; restart-inclusive load+build 319.64/253.19 ms. A local edit verifies 5 objects, reuses 286, invalidates/writes 5 cache entries, and reduces the following compile from 127.61 to 81.68 ms while adding about 2.5% commit-time maintenance in this run. Program/build cache sizes are 33,639/34,123 B (79.8%/79.5% of their stores). Artifact/provenance identity is unchanged. These are host timing observations, not normative thresholds.

- **AI-native C vs XAX experiment (not yet run):** five paired structural edits, manual Codex Desktop operation, native XAX transaction verification, flat CSV results, and raw descriptive totals only. The historical M6 one-edit tokenizer result below remains a separate microbenchmark.

- 2026-09-29 narrow specialization smoke (`compiler/benchmarks/m6_specialize_smoke.json`): 479 bootstrap query bytes, 4 exposed entities, 15 transaction bytes, 5 touched/verified objects, 5 reused objects, stable specialized CID `28e05c5b4a7dceca1ab59e4e7522d072ab1fc1c20dc2decb7a2e372f1bac0942`, and result 8 while source/caller behavior remained unchanged. This is deterministic non-timing accounting and semantic-execution evidence only; no tokenizer/model/META/performance claim.
The separate deterministic M6 accounting smoke measurement exposed 4 entities in 534 bootstrap response bytes, validated a 4-handle read set, encoded a 101-byte three-mutation transaction, created 6 objects, and reused 2 objects; raw data is `compiler/benchmarks/m6_workspace_smoke.json`. No timing or runtime-performance conclusion is claimed.

The first relation-mutation accounting smoke (`compiler/benchmarks/m6_relation_transaction_smoke.json`, reproduced by `bench_relation_transaction.py`) records one generation-root `ReplaceUse` transaction at **24 bootstrap bytes**. In its one-caller fixture it changes the direct callee result for `(2,3)` from 5 to 6, rebuilds/verifies 6 affected objects, and reuses 1 reachable object. This is non-timing accounting/conformance evidence, not a token or performance result.

The first deletion accounting smoke (`compiler/benchmarks/m6_delete_node_smoke.json`, reproduced by `bench_delete_node.py`) records one generation-root `DeleteNode` transaction at **17 bootstrap bytes**. In its one-caller fixture it removes an unused constant node (2 nodes → 1), preserves the direct callee result for `(2,3)` at 5, rebuilds/verifies 6 affected objects, reuses 2 reachable objects, and retains one direct caller relationship. This is non-timing accounting/conformance evidence, not a token or performance result.


The first insertion accounting smoke (`compiler/benchmarks/m6_insert_node_smoke.json`, reproduced by `bench_insert_node.py`) records **576 bootstrap query bytes** for the node/type context and a **43-byte** generation-root two-mutation transaction that inserts a constant before a stable anchor and replaces a later operand with transaction-local result `I4.R0`. The fixed fixture changes from 3 to 4 nodes and result 5→12, rebuilds/verifies 5 affected objects, and reuses 4 reachable objects. This is non-timing accounting/conformance evidence, not a tokenizer, model-efficiency, compile-time, or runtime-performance result.

The first control-edge argument accounting smoke (`compiler/benchmarks/m6_edge_argument_smoke.json`, reproduced by `bench_edge_argument.py`) records **301 bootstrap query bytes** for two node handles and a **39-byte** generation-root disconnect+connect transaction. In its one-caller fixture it changes edge argument 0 from source parameter 0 to source parameter 1 and changes the callee result for `(2,3,300)` from 2 to 3, rebuilds/verifies 6 affected objects, reuses 4 reachable objects, and retains one direct caller relationship. This is non-timing accounting/conformance evidence, not a tokenizer, model-efficiency, compile-time, or runtime-performance result.

The candidate-only verification accounting smoke (`compiler/benchmarks/m6_candidate_verify_smoke.json`, reproduced by `bench_candidate_verify.py`) records **424 bootstrap query bytes** for three node handles and a **26-byte** generation-root candidate transaction. Candidate verify touches/verifies 4 objects, reuses 4 reachable objects, returns `C0.0`, and leaves canonical root/generation unchanged; explicit rollback also leaves canonical root/generation unchanged. The same ordinary transaction then commits successfully and changes result 5→6. Candidate verification accounting is separate from ordinary commit accounting. This is non-timing accounting/conformance evidence, not a tokenizer, model-efficiency, compile-time, or runtime-performance result.

The same-block pure-node move accounting smoke (`compiler/benchmarks/m6_move_node_smoke.json`, reproduced by `bench_move_node.py`) records **424 bootstrap query bytes** for three node handles and a **28-byte** generation-root `MovePureNode` transaction. It moves constant 3 immediately before constant 2, remaps the arithmetic operands by original producer identity, preserves the callee result at 5, rebuilds/verifies 6 affected objects, reuses 4 reachable objects, and retains one direct caller relationship. This is non-timing accounting/conformance evidence, not a tokenizer, model-efficiency, compile-time, or runtime-performance result.

The proof-dependency accounting smoke (`compiler/benchmarks/m6_proof_dependency_smoke.json`, reproduced by `bench_proof_dependency.py`) records a **299-byte** bootstrap `proof` response exposing local dependency `P0.0` without a persistent semantic CID. A one-mutation transaction guarded by that proof dependency is **22 bootstrap bytes**, changes the fixture result from 5 to 6, rebuilds/verifies 4 affected objects, reuses 4 reachable objects, and then rejects reuse of the invalidated proof as `XAX.WORKSPACE.PROOF_CONFLICT` / `WORKSPACE-PROOF-DEPENDENCY`. This is non-timing accounting/conformance evidence, not a formal-proof, token, or performance result.


The response-budget accounting smoke uses the same three-node query to show the bound/cost tradeoff explicitly: the unbounded one-page response is 424 bootstrap JSON bytes; with an exact 178-byte budget the deterministic positive-progress pages are 171/171/178 bytes (one entity each, continuations 1/2/none), totaling 520 returned bytes. Raw data/reproducer: `compiler/benchmarks/m6_response_budget_smoke.json` and `compiler/benchmarks/bench_response_budget.py`. This is transport accounting only and is not a token or timing result.

The deterministic x86 artifact-mapping accounting smoke emitted the unchanged 43-byte stack image and issued 7 artifact/mapping queries exposing 9 local entities in **2,499** bootstrap response bytes after explicit dependency attribution was added. The artifact response is 564 bytes; function mapping 282; unavailable stack-allocation mapping 223; store mapping 285; and the two one-entity reverse-mapping pages 290/297 bytes. Raw data and reproducer are `compiler/benchmarks/m6_artifact_mapping_smoke.json` and `compiler/benchmarks/bench_artifact_mapping.py`. This increase versus the earlier 1,713-byte record is preserved as attribution overhead, not hidden. A second cross-target accounting smoke runs the identical seven-query shape for all three emitted formats: x86-64 2,499 response bytes, AArch64 2,502, and WebAssembly 2,495, each exposing 9 entities and preserving the target-specific exact ranges listed above. Raw data/reproducer: `compiler/benchmarks/m6_artifact_mapping_cross_target.json` and `compiler/benchmarks/bench_artifact_mapping_cross_target.py`. This comparison is accounting/conformance evidence only; it is not a runtime or AI-efficiency benchmark.

The 2026-09-30 M7 proof-erasure check compares a bits-only baseline with an otherwise equivalent resource/effect lifecycle for each backend. Emitted bytes are identical: x86-64 **25/25** (`6d9e24dc5ddc2dbe5c55f3e8e932e162a6f1ed3033fd4eaedfaf730100ba2fc0`), AArch64 **28/28** (`fb5970c1e6ab2c3be407a4a0a7ef6003051549e163cc76811138a552d3ca68db`), and WebAssembly **59/59** (`40997b5662863f0ba9253c23bf4e915b1e32c0a2878f0e4635d00063532bfc88`). This is deterministic erasure evidence, not a performance result.

The 2026-09-30 M8 deterministic atomic smoke (`compiler/benchmarks/m8_atomic_smoke.json`, reproduced by `bench_m8_atomic.py`) emits a **108-byte** x86-64 image with SHA-256 `3766932e195970e563376f48093c6ccf479aa838d08845b70571a8903266d938`. Reference and isolated native execution both return **8** for `(5,3,11)`; the record declares zero runtime assists. This is artifact/execution evidence only, not a synchronization-cost, latency, throughput, or cross-target performance result.

The final M8 reproducible-wheel check with `SOURCE_DATE_EPOCH=946684800` passed; the produced `xax_compiler-0.1.0-py3-none-any.whl` is **75,365 bytes**, SHA-256 `7f812534ddd002efbaa29510071f5bcf0886e70da67debfcca5d7ceb40a82db4`. An earlier ad hoc dirty/non-normalized wheel comparison remains discarded as invalid evidence.

The 2026-09-30 M9 deterministic compile-time smoke (`compiler/benchmarks/m9_comptime_smoke.json`, reproduced by `bench_m9_comptime.py`) performs **8 evaluator steps**, confirms a memoized cache hit, constructs three canonical objects, materializes function CID `03dfe6520ab043dd40d391d8834a41ce4314481ce6d7cc8dd8bf15ea560b5adc`, and emits a **35-byte** x86-64 image with SHA-256 `6fba4d01d380cba2d2dc500f6ac96b6cdee1df35e810e587ee517be248bf754e`. Reference and isolated native execution both return **44**; target inspection reports `add.wrap` supported. This is deterministic construction/cache/artifact evidence, not compile-time or runtime performance evidence.

The final M9 reproducible wheel built twice with `SOURCE_DATE_EPOCH=946684800` and matched byte-for-byte: **79,608 bytes**, SHA-256 `407922eb7017f5a0bb841fa7b69e915654afd0bf14c19d4e0b7e8f4143ac5a67`.

The 2026-09-30 M10 deterministic package/build smoke (`compiler/benchmarks/m10_package_build_smoke.json`, reproduced by `bench_m10_package_build.py`) creates canonical package/request/snapshot/provenance objects and verified cache entries for x86-64 and WebAssembly. Repeated builds are byte-identical; cross-target cache keys differ. The x86-64 snapshot/build/artifact are `0441036881fb4ca91a8f3acf52d0bcb8b076e1a92592039da0a11a6668767349` / `cf3528c16cc24b16c341568282b11871ad49079b5034722ef88bf8e8158dd3be` / **35 bytes**. WebAssembly uses `0c7823663324f58e25e73e477356407f4e004720d245d23d5517bb674082c117` / `92b705a924300f62ac1897f0a855486054f94d6e1e509a4a6fe9ee707a7be590` / **62 bytes**. This is deterministic identity/artifact/cache evidence, not performance or sandbox-portability evidence.

The final M10 reproducible wheel built twice with `SOURCE_DATE_EPOCH=946684800` and matched byte-for-byte: **89,076 bytes**, SHA-256 `05d55cc76e28d3e677465c37afe06af5820a41b112a3e2a8dbab5dfd653cb482`.

The 2026-09-30 M11 deterministic bootstrap evidence (`compiler/bootstrap/m11_bootstrap_evidence.json`, reproduced by `compiler/benchmarks/bench_m11_bootstrap.py`) records an **820-byte** authoritative XAX program store, **1,566-byte** fixed hermetic WebAssembly snapshot, **144-byte** seed-built artifact with BLAKE3-256 `3f9f35e6fe8c8ec00e0490fa3e9f9b613255f6ab930c8d8ab2b9d18a221be09a`, repeated build identity, exact provenance/tool roots, and **6/6** matching seed-versus-hosted conformance vectors. This is B0/B1 artifact/conformance evidence only, not recursive self-hosting, fixed-point, bootstrap-minimality, timing, runtime-performance, or AI-efficiency evidence.

The final M11 reproducible wheel built twice with `SOURCE_DATE_EPOCH=946684800` and matched byte-for-byte: **92,769 bytes**, SHA-256 `7be816707f5e4270d4cfd94be3591461410b76ecc5dfe3a1f57fa8630f450d97`.


The 2026-09-30 M12 deterministic optimizer evidence (`compiler/benchmarks/m12_optimizer_evidence.json`, reproduced by `compiler/benchmarks/bench_m12_optimizer.py`) records policy root `924e070eceab1b9abba8c1cbb67fb2365fa7cc9f21362537f4b228bcdbd90dba`. On the fixed pure wrapping-arithmetic fixture, target-aware validated search changes exact emitted function extent from **59→43 bytes** for x86-64 and **36→32 bytes** for WebAssembly. Per target, 64 candidates were examined, 4 passed exact equivalence, 60 failed validation, 64 deterministic search steps were consumed, and peak deterministic search accounting was 6,560 bytes. Hot/cold profile data changes inlining profitability without appearing in canonical store bytes. This is code-size/validation/determinism evidence only, not runtime latency/throughput/energy, broad optimization quality, or calibrated cost-model evidence.

The final M12 reproducible wheel built twice with `SOURCE_DATE_EPOCH=946684800` and matched byte-for-byte: **102,449 bytes**, SHA-256 `e21d519dff45f9972f4a094a2998cef26d6971c7fbdbd10d77041298875591ab`.


The 2026-09-30 M13 deterministic accelerator evidence (`compiler/benchmarks/m13_accelerator_evidence.json`, reproduced by `compiler/benchmarks/bench_m13_accelerator.py`) records target root `202e9d0db81107e8380f27ef1f233327c34fe8a1f56431d38814ec4ee6feee04`, program root `6e088c0ff84c0723a9c3b7f527bf2bd98b886f8e5846f0200f5b1ee2ecf7db5c`, and a deterministic **122-byte** deployment packet. The packet contains six explicit target operations (allocate, H→D, launch, synchronize, D→H, free), no runtime dependencies, and exact semantic ranges. All **6/6** wrapping-add conformance vectors match; unsupported execution scope and memory-space pair reject under the expected verifier rules. Evidence JSON SHA-256 is `58e12d090e82c330e554728638b4070c9514a73d5861fad56afdea3aa463ce9a`. This is artifact/semantic/conformance evidence, not physical-accelerator performance evidence.

The final M13 reproducible wheel built twice with `SOURCE_DATE_EPOCH=946684800` and matched byte-for-byte: **109,836 bytes**, SHA-256 `b2180788ecfb0cc697f43613f6cd553f2b26ebd1f486739b8327319988db85e7`.

The 2026-09-30 M14 bootstrap evidence (`compiler/bootstrap/m14_selfhost_evidence.json`) records executed B2–B6 for the declared `xax-semantic-image-v1` closure target. The authoritative compiler image is 2,020 bytes; compiler root `097da62f7ba9832620f5d202297fc522783ed5b4c9e68f8da6b77515b185164d`; entry function `4300342f92f9ba32bcefbb45af4aad117a3bbf3699bd66266b25cefdc874b6fc`. Generation 0, 1, and 2 are byte-identical with BLAKE3-256 `6340c903f5da3e8aaf4d8ae886694a0d858687fc5c5520662a018518693f4788`; four independently compiled function vectors match. The committed immutable seed runtime reconstructs that compiler with repository Python sources removed from the import path and is itself deterministic at 46,255 bytes / SHA-256 `4e0c64d6f360359cc263c39817ec8cbe4cc3069edf20823755755c4d2707fe52`. This is self-hosting/closure/reproducibility evidence, not native-target performance, compiler-speed, tokenizer, or diverse-trust evidence. B5/B6 do not apply to the legacy native/WebAssembly/accelerator lowerers.

The final M14 reproducible wheel built twice with `SOURCE_DATE_EPOCH=946684800` and matched byte-for-byte: **117,715 bytes**, SHA-256 `fa4add6e966ca09fe5df6c02043e91d333f0726ec92f681a03bf7251e4a4a34e`.

## M6/M7/M8/M9/M10/M11/M12/M13/M14 exit audit

- M6 exit is satisfied for the declared prototype: atomic local transactions, exact preconditions/conflicts, dependency-aware affected-frontier verification, bounded queries, candidate verify/rollback, narrow specialization, retained multi-generation diff/rebase for unchanged entities, and durable canonical store save/load have executable coverage.
- M7 exit is satisfied for the declared operation set: generic lifecycle/state transitions, affine/linear handling, split/join, domain-instance effect ordering and independence, cross-block flow, derived direct-call summaries, reference execution, deterministic diagnostics, and native/WebAssembly proof erasure have executable coverage.
- M8 exit is satisfied for the declared prototype slice: portable atomic operation/order verification, exact target capability rejection, x86-64 lowering without runtime help, race/litmus checks, explicit target handler contracts, workspace latency queries, and strict post-lowering profile rejection have executable coverage.
- M9 exit is satisfied for the declared prototype slice: identical explicit inputs/policy yield identical canonical results; all five mandatory budgets reject deterministically without commit; ambient authority is absent; declared non-reproducible input is explicit; invalid generated semantics fail the ordinary verifier barrier; memoization invalidates on semantic/tool identities; generated compile-time-only abstractions erase from the emitted function.
- M10 exit is satisfied for the declared prototype slice: identical resolver inputs reproduce roots/failure; complete local snapshots build offline; undeclared/mismatched external inputs and live network/clock/random effects reject in reproducible mode; cache/fetched content verifies exact identity; trust/provenance hooks are separate; no external manifest/build DSL exists.
- M11 exit is satisfied for the declared B0/B1 slice: the authoritative compiler component is canonical XAX semantic state; the fixed hermetic snapshot rebuilds it through the approved seed; exact program/package/request/target/profile/tool/provenance roots are recorded; and six seed-versus-hosted behavior vectors match. B2–B6 remain explicitly unclaimed.
- Final M11 validation on 2026-09-30: syntax/import checks passed; all **6/6 M11 checks** executed successfully across the gate; the final applicable regression passed **211/211** after excluding exactly 8 unavailable host-bound execution cases (6 Windows x86-64, 2 AArch64/QEMU); the M11 deterministic bootstrap record passed; and the wheel reproduced byte-for-byte at **92,769 bytes**, SHA-256 `7be816707f5e4270d4cfd94be3591461410b76ecc5dfe3a1f57fa8630f450d97`.
- M12 exit is satisfied for the declared optimizer slice: deterministic local/interprocedural transforms execute behind ordinary verification, explicit deterministic work/memory budgets constrain search, exact modular-polynomial validation rejects non-equivalent candidates before acceptance, target lowering supplies code-size ranking on two targets, and profile data affects profitability only.
- Final M12 validation on 2026-09-30: syntax compilation passed; M12 narrow tests passed **6/6** after one grouped optimizer fix; the final applicable regression passed **217/217** after excluding exactly the same 8 unavailable host-bound cases; deterministic optimizer evidence reproduced; and the wheel reproduced byte-for-byte at **102,449 bytes**, SHA-256 `e21d519dff45f9972f4a094a2998cef26d6971c7fbdbd10d77041298875591ab`.
- M13 exit is satisfied for the declared accelerator slice: one non-CPU target package carries topology/scopes/memory spaces/operation contracts; deployment encoding/build/provenance/workspace mapping use existing target abstractions; host/device transfer, synchronization, effect, and linear buffer ownership are explicit; unsupported scope/space behavior rejects deterministically; and the target declares no runtime dependency.
- Final M13 validation on 2026-09-30: syntax compilation passed; M13 narrow tests passed **7/7** after correcting two test-only rule assertions; the final applicable regression passed **224/224** after excluding exactly the same 8 unavailable host-bound cases; deterministic accelerator evidence passed **6/6** execution vectors plus both negative cases; and the wheel reproduced byte-for-byte at **109,836 bytes**, SHA-256 `b2180788ecfb0cc697f43613f6cd553f2b26ebd1f486739b8327319988db85e7`.
- M14 exit is satisfied for the declared `xax-semantic-image-v1` closure target: B2 recursive compilation executed; B3 fixed-policy equivalence passed **4/4** vectors; B4 reached exact byte identity across generations 0/1/2; B5 is satisfied by the XAX-hosted semantic-image materialize→verify→encode→finalize/build path with verifier/serializer retained as deliberate trusted META substrate; and B6 is satisfied at the declared immutable-seed boundary by reconstructing the release compiler without repository Python sources on the import path. The claim does **not** extend to legacy x86-64, AArch64, WebAssembly, or accelerator target maintenance.
- Final M14 validation on 2026-09-30: syntax compilation passed; M14 narrow tests passed **7/7**; the broad pre-artifact-finalization suite had **237 tests** with the same 8 host-only errors; the exact final applicable regression passed **231/231** out of 239 current tests after excluding those same 8 unavailable cases; M14 artifacts regenerated deterministically twice; and the wheel reproduced byte-for-byte at **117,715 bytes**, SHA-256 `fa4add6e966ca09fe5df6c02043e91d333f0726ec92f681a03bf7251e4a4a34e`.

## Bootstrap dependencies

- Python 3.13.5 — execution environment for the committed immutable M14 seed runtime and the removable bootstrap/reference implementation. The declared B6 claim does not assert elimination of the interpreter; it asserts that ordinary `xax-semantic-image-v1` release reconstruction need not import or edit repository Python implementation sources.
- In-tree `compiler/src/blake3.py` — dependency-free suite-1 BLAKE3 implementation. The external platform-specific `blake3` wheel dependency has been removed from `pyproject.toml`.
- `setuptools` 82.0.1 — wheel build only.
- Node 24.19.0 — WebAssembly validation/execution harness only; outside the M14 semantic-image closure claim.
- MSYS2 QEMU 11.0.1 plus its runtime package dependencies — AArch64 execution harness only; outside the M14 semantic-image closure claim.
- Capstone 5.0.9 — transitive QEMU-package dependency used only to inspect AArch64 bytes.

## Current blockers

- **OI-31 / exploratory AI-native evaluation:** run the five C/XAX pairs manually in Codex Desktop under one fixed model setting and record the displayed token counts and all turns.
- No M6–M14 implementation/validation blocker remains for the declared prototype/closure scopes.
- External conformance fixtures still do not exist; current evidence remains implementation-local.
- M14 B5/B6 closure is deliberately target-scoped to `xax-semantic-image-v1`. Extending closure to the legacy x86-64, AArch64, WebAssembly, or accelerator paths remains future hardening and must earn separate B5/B6 evidence rather than inheriting the semantic-image claim.
- OI-27 remains open: the immutable seed boundary is bootstrap independence evidence for the declared release path, not diverse-double-compilation or compiler-correctness proof.
- Calibrated target cost models, broader optimizer/search organization, stronger transformation proof systems, indirect calls, recursive general effect-summary fixed points, broader META construction, richer package constraints/actions, cross-target atomics, durable timing proofs, a normative atomic litmus corpus, changed-entity semantic merge, and multi-process workspace coordination remain explicit future extensions, not silently claimed behavior.

## Prototype choices pending evidence

- Index `record_length` currently repeats the semantic envelope payload length; `file_offset` points at the record-length prefix.
- Graph fragments own block/node-local numbering. Their reference tables contain external type/entity CIDs used by the body.
- Recursion-member call indices are interpreted through the owning kind-8 closure.
- OI-03 recursion-carrier harness (2026-10-01): `bench_oi03_recursion.py` shows a one-member group costs one byte over a direct `function`, a compact singleton form would save only that byte, and a mutual SCC group is 14.4% smaller in store bytes than per-member objects while an edit changes every member identity in its SCC only. OI-03 is closed: non-recursive functions must use `function`; self- and mutually recursive SCCs keep `recursion_group`. The verifier rejects groups that are not exactly one recursive SCC (`GRAPH-RECURSION-SCC`) or not in canonical member order (`GRAPH-RECURSION-ORDER`); `canonical_recursion_order` gives producers that order.
- OI-04 type-vocabulary harness (2026-10-01): `bench_oi04_type_vocabulary.py` now measures both the catalog-alias container and a catalog-free store-wide CID-reference dictionary. The dictionary indexes exactly the CIDs referenced by at least two semantic objects, carries those full CIDs once per store, leaves singleton references explicit, re-derives every object CID, and expands byte-identically to the canonical store. On the 26,703 B integer corpus it saves 4,174 B (15.6%), versus 4,991 B (18.7%) for `bits5` and 5,623 B (21.1%) for `common`; it beats `bits5` on the OI-03 reference-heavy stores, showing that most raw byte gain is generic reference compression while a fixed type vocabulary retains a smaller incremental advantage. Float catalog entries still matter only for synthetic float-typed stores. OI-04 remains open for model mutation reliability and real floating-point workloads. Neither comparator changes the canonical store format.
- OI-06 closes the bounded alias/provenance choice for ordinary object-backed memory: precise local alias class is derived from allocation/storage identity and consumes no extra semantic field. Measurement-only checked load/store and raw-load candidates preserve provenance/permission, make trap/waiver behavior explicit, and lower on OI-06 x86-64 frame-relative and WebAssembly linear-memory target packages without changing the canonical M4/M5 target CIDs.
- Memory effects are ordering frontiers; the separate stack-owner resource authorizes lifetime end, preserving ADR-010.
- M4 uses a spill-every-value stack allocator and raw callable image to minimize trusted code. Improve only after measurement; no performance claim follows from native execution alone.
- M5 validated the same semantic graphs on x86-64, WebAssembly, and AArch64. It removed x86 ABI/register/shadow-space assumptions from the shared target decoder, but does not close OI-16 without measured package/cost/verifier evidence.
- M8 plus OI-11 use native x86-64 atomics, one bounded inline seq-cst-load sequence, and hard rejection on unsupported targets. They do not yet establish a portable non-native synthesis threshold across multiple implemented architectures or measured atomic latency/cost, so OI-11 remains open; persistent timing-proof format and sufficient normative litmus evidence remain open under OI-12 and OI-29.
- M9 counts deterministic semantic evaluator steps, active frame storage, constructed objects, and emitted nodes. These prototype units satisfy boundedness but do not select portable long-term fuel/memory accounting or final introspection authority granularity; OI-14 remains open. Constant-function objectization and canonical reuse provide first general META evidence, but no representative generic corpus establishes the best specialization boundary; OI-15 remains open.
- M10 uses exact roots or exactly-one logical candidate, closure-level provenance, in-memory verified cache entries, and pure direct-backend build actions. These choices prove the milestone base case but do not select version constraint algebra, provenance granularity, persistent cache format, general build-action semantics, or portable sandbox enforcement; OI-23, OI-24, and OI-30 remain open.
- M12 uses a small deterministic pass pipeline, pure direct-call inlining, lowering-derived code-size selection, and exact polynomial validation for bounded wrapping-arithmetic search. These choices establish the milestone base case but do not select a permanent optimizer/machine-IR organization, calibrated multi-objective target cost model, or general transformation-proof granularity; OI-17, OI-18, and OI-19 remain open.
- M13 uses one generic target-operation node family and one synthetic SIMT packet target with three memory spaces and six operation contracts. This demonstrates package-driven accelerator semantics without selecting a universal GPU scope lattice or permanent per-instruction/shared-primitive target organization; OI-13 and OI-16 remain open.
- M6 ordinary semantic handles are generation-scoped and invalidated after commit. Proof-dependency handles record an origin generation but may remain valid across unrelated commits only while their exact content-addressed subject and verifier identity are preserved; invalidated proof handles do not revive. The reverse-reference index is rebuilt per root. The prototype transaction accounting is canonical for its same-function mutation subset; it does not select the permanent fallback protocol, close OI-01/OI-02/OI-21/OI-28, or claim C4 conformance.
- M6 caller propagation follows the verified CID DAG and preserves unrelated objects. Recursion-group rebuilding remains deliberately unsupported until member/objectization mutation semantics are explicit.
- M6 multi-function propagation topologically rebuilds edited standalone functions and their affected users, preserving local caller edits plus callee replacements. Recursion-group rewriting remains deliberately unsupported until member/objectization mutation semantics are explicit.
- M6 artifact provenance is retained at emission time through the shared tooling-only `ArtifactSemanticRange` carrier for x86-64, AArch64, WebAssembly, and the M13 accelerator deployment packet. `ArtifactProvenanceBinding` adds explicit root/target/compiler/lowering/artifact/range attribution using opaque V1 toolchain identities that are deliberately not derived from human text or disassembly. Backend container layout remains private to the backend while workspace mapping semantics are target-neutral. Zero-code/non-local semantics and un-attributed container bytes remain unavailable rather than being assigned neighboring bytes. Durable persisted mapping indexes remain future work.
- OI-01 transport harness (2026-10-01): `python -m benchmarks.ai_native transport` compares typed (`P0`/`N0`) versus unified dense-integer handles across `line`, `pipe`, and `json` `X1` framings on the five reference edits; all six candidates decode to one identical transaction and reach the target root. Offline `tiktoken` 0.14.0 totals (view+packet, five tasks) range from 262/257 (`typed`/`line`) and 279/274 (`typed`/`json`) down to 237/237 (`unified`/`pipe`) for `cl100k_base`/`o200k_base`; unified handles save 15 view tokens under both encodings. A 30-trial Claude Code (`claude-opus-5-5` subagent) run completed 30/30. Harness-token totals differed by about 1.3% peak-to-peak across arms and are below run-to-run noise; `line` framing had 0 failed checks, `pipe` 2, and `json` 14, with nine of ten JSON trials requiring at least one repair. The tested flat-array JSON framing is disfavored; line is the observed reliability leader on this corpus; typed versus unified handles remains unresolved. No candidate is canonical; OI-01 remains open (n=1, one model family, five task families missing).
- M6 tokenizer measurement found that a generation-scoped `R0.0` output candidate saves tokens versus the full-root candidates and current graph packet but still loses total tokens to C-like text in the single measured case. The expected-root alias is now implemented in the bootstrap transaction API; the measured colon/line text framings are still non-authoritative tooling candidates and do not select a permanent fallback protocol.
- Python remains removable bootstrap/reference code and the execution format of the immutable M14 seed artifact; it is not XAX semantics. The M14 B6 claim is scoped to ordinary semantic-image release reconstruction, not to elimination of all Python-based legacy target tooling.
- OI-02 granularity harness (2026-10-01): `bench_oi02_granularity.py` now measures four arms: canonical function grain, tooling-only module packing, `call_indirect`, and block grain (graph skeleton + content-addressed per-block units). Block reassembly must reproduce canonical graph/function CIDs exactly; the reassembled entry is verified and executed. In `star-8x16-b4`, block grain reduces the leaf-edit rewrite from 6,628 B to 5,668 B and same-module conflict bytes from 924 B to 846 B, but grows the store from 74,938 B/396 objects to 88,617 B/537 and query bytes from 324 to 710. In `chain-8x16-b4`, direct-call CID propagation dominates and block grain is worse (394 objects/56,635 B rewritten versus function grain 266/50,581 B). `call_indirect` remains the strongest locality arm (8x16 chain leaf edit 5 objects/1,774 B) but still has a 259-object conservative verification frontier without interface-only summaries. The canonical format is unchanged; OI-02 remains open (synthetic corpus, byte-only AI context, block+indirection not combined, no interface-only callee-summary contract).
- OI-06 memory-surface harness (2026-10-01): `bench_oi06_memory_surface.py` measures two independent allocation-derived alias classes, checked dynamic scalar load/store, and explicit raw load. Derived local alias identity costs 0 extra graph bytes/token-native atoms versus +2/+2 for redundant explicit IDs in the two-allocation comparator. Checked load/store cost +3 graph-body bytes and +1 semantic token atom each, with +24 x86-64 code bytes / +12 WebAssembly module bytes for the required runtime bounds branch. Raw initialized load costs +6 graph-body bytes / +3 atoms but 0 emitted bytes on both targets. The WebAssembly checked-load fixture executes correctly at offsets 0 and 4. OI-06 is closed for this bounded scalar/object-backed design; conservative raw/target mappings use explicit class IDs only when precise object identity is unavailable.
- OI-07 DMA-state harness (2026-10-01): the shared `resource<K,state>` vocabulary is `host_unmapped`, `host_mapped`, `host_dirty`, `device_owned`, `device_pending`, and `host_stale`. A split host/device non-coherent target uses all six plus explicit clean/invalidate; a coherent shared-memory target uses the same vocabulary subset and omits cache maintenance while retaining explicit mapping, ownership, device work, synchronization, and release. Deterministic packets are 163 B and 148 B respectively and both execute 4/4 vectors. `device_pending` makes synchronization verifier-visible; missing clean/sync transitions reject. OI-07 is closed without adding a device framework or changing the existing M13 target identity.
- OI-08 effect-edge harness (2026-10-01): six representative workloads compare conservative versus proven domain-instance partitioning and explicit-frontier versus domain-grouped reconstruction. Reconstruction verifies the exact footprint/frontier relation before measurement, is deterministic under input-map ordering, rejects changed/corrupt frontiers, and includes a real XAX branch/merge fixture so compression is not limited to total chains. The selected policy is proof-directed instance granularity plus domain-grouped semantic runs with explicit non-run predecessor deltas; the carrier remains benchmark-only and store v1/CIDs are unchanged.
- OI-09 CallContract harness (2026-10-01): five direct-contract families, 15 exact dispatch sets, and two 960-call profiles compare callable-embedded, referenced-contract, and sealed-set placement. Reuse-heavy bytes/atoms are 9,962/1,801 embedded, 9,737/1,231 referenced, and 11,651/1,341 sealed; sparse-callable bytes/atoms are 2,087/1,066, 2,387/1,021, and 4,301/1,131 respectively. Referenced verification is fastest in both measured profiles; sealed sets expose exact target sets and one-third singleton-devirtualizable calls but an implementation-only function-CID replacement churns 3 set identities and 192 affected call references while the referenced CallContract CID remains unchanged. Kind 11 is therefore the bounded semantic contract identity; sealed sets remain optional optimization facts and embedding remains only a possible future low-reuse serialization compression. OI-09 is closed as a representation decision; general indirect-call operations are still unimplemented.
- OI-10 trap-payload harness (2026-10-01): focused tests pass 9/9, including committed-evidence reproduction. Reason `0x1234` maps on x86-64 Windows to `rax` plus `ud2` and on AAPCS64 to `x0` plus `brk #0x1234`; target-specific suffix changes semantic identity but not the portable native sequence. Diagnostic JSON preserves raw payload while exposing reason and suffix. The portable u16-reason/opaque-suffix split closes OI-10 without exception, unwind, cleanup, or runtime semantics. The unchanged core run produced 112 passes plus exactly the same 8 host-bound execution failures; deselecting only those eight yielded 112/112 portable passes. Remaining portable compiler/OI modules added 190 passes with 1 existing skip, and the non-evidence OI-02/OI-03/OI-04 subset added 24/24 passes.
- OI-11 atomic-legalization harness (2026-10-01): focused tests pass **6/6**, including committed-evidence reproduction. x86-64 acquire load remains `native`; system-scope 32-bit seq-cst load is explicitly `bounded_sequence` and emits a deterministic 12-byte node range versus 9 bytes for acquire, with the exact +3-byte delta being `mfence`. The bounded case remains `lock_free=always`, `retry=none`, and real-time analysis reports `wait_free`, retry bound 0, and no runtime assist. Build policy permits bounded inline by default to preserve existing lowering and rejects it deterministically when disabled; runtime assistance is rejected by default and can only be selected when both target capability and policy say `runtime_assist`, but no current target implements such an assist. AArch64 bare-metal and wasm32 remain hard-rejection endpoints for this request. The evidence records no latency bound because current target packages provide none and this host cannot execute the Windows artifact; no second architecture implements a bounded/assisted path, so **OI-11 remains OPEN**. Portable regression after the change: **258 passed / 8 documented host-bound cases deselected** across `test_xax_*`, **52 passed** across OI-05..OI-11, and **24/24 passed** for the non-evidence OI-02/OI-03/OI-04 subset; syntax compilation passed.
- These choices do not close OI-02, OI-04, OI-05, OI-11, OI-12, OI-13, OI-14, OI-15, OI-16, OI-17, OI-18, OI-19, OI-21, OI-22, OI-23, OI-24, OI-28, OI-29, or OI-30.


## Android arm64-v8a shared-library target — 2026-10-01

A bounded `android-arm64-v8a-shared-v3` target now reuses the register-resident
AArch64 backend and directly emits ELF64 little-endian `ET_DYN` / `EM_AARCH64`
shared objects. The emitter supports explicit exports, explicit foreign imports,
local PC-relative calls/function addresses, read-only/initialized/zero-filled
static data, a minimal dynamic symbol/string/hash table, Android-compatible RELA
for referenced imports, and 0x4000-aligned load segments.

Deterministic structural/codegen evidence is committed at
`compiler/benchmarks/android_arm64_evidence.json` and reproduced by
`bench_android_arm64.py`. The measured fixtures include simple add, minimal
`native_init`, libxposed table access/function-pointer call, `JNI_OnLoad`, and
one explicit Bionic import. The minimal no-import module has 2 `PT_LOAD`
segments, 1 export, 0 imports, 0 dynamic relocations, 0 `DT_NEEDED`, 0
constructors, and 0 TLS entries. Its `native_init` hot path is two AArch64
instructions (`ADR x0,<callback>; RET`) with no stack frame. A trivial exported
add remains exactly `ADD w0,w0,w1; RET`.

The modern libxposed fixture is at
`compiler/integration/android/libxposed_fixture`; it packages the generated
`.so` from `jniLibs/arm64-v8a` and uses `META-INF/xposed/native_init.list`,
`module.prop`, and `scope.list`. A device/emulator validation script is included.

Android loader execution is **not claimed on this host**: no Android `adb`
device/emulator or Android NDK is installed here. `readelf`/`llvm-objdump`
structural validation is available and used. The NDK C reference sources are
committed only as future benchmark oracles; no C/C++ stage participates in XAX
production code generation.


### JNI platform package phase 1 — 2026-10-01

Android JNI remains outside the XAX kernel. The generic type system now has an
identity-qualified opaque ABI carrier used for distinct `JavaVM*`, `JNIEnv*`,
JNI table, ID, and reference-class identities. `android-arm64-v8a-shared-v3`
exposes all JNI 1.6 VM invocation slots 3..7 and native interface slots 4..232
as fixed-offset target operations, with exact call signatures represented by
bounded `CallContract` objects. Acquired local/global/weak-global JNI references
carry explicit linear ownership proofs; a verifier test rejects dropping an
owned global reference. No wrapper library, hidden reference cleanup, dynamic
lookup helper, allocation, or runtime dependency was added.

Deterministic evidence is committed at
`compiler/benchmarks/android_jni_platform_evidence.json`. On this host, direct
`JNIEnv->GetVersion` emits 36 bytes / 9 AArch64 instructions and the typed
`NewGlobalRef`→`DeleteGlobalRef` round trip emits 72 bytes / 18 instructions;
both ELF fixtures have zero imports, `DT_NEEDED`, and relocations. This is
structural/codegen evidence only. JNI calls that may raise now thread an explicit
linear exception-state proof from `clean` to `maybe-pending`; ordinary safe JNI
calls cannot consume `maybe-pending`, and the supported explicit `ExceptionClear`
policy restores `clean`. JNI reference/class/member identities may carry an
explicit loader domain, and local/global/weak lifetime transitions preserve it;
loader-mismatched call operands reject. Nullable and non-null reference argument
identities are now distinct in the bounded mixed-pack path. Android arm64 target
operations 11..13 expose a verifier-visible `jobject` -> 64-bit `jvalue.l` ABI
projection; local/global forms thread the linear owner proof and the borrowed
last-use form emits zero instructions. Actual Android JNI execution, conditional
exception refinement (`pending` versus `clean`), runtime null-check/refinement and
explicit null construction, successful thread-attachment state, runtime
loader-relative resolution/caching, and floating-point AAPCS64 JNI calls remain
unvalidated/unimplemented.

### Direct managed Android artifacts, signing, and SDK import — 2026-10-01

The Android prototype now directly emits deterministic DEX 039 managed classes,
binary `AndroidManifest.xml`, an aligned deterministic APK ZIP container, and an
APK Signature Scheme v2 block without Java/Kotlin source, D8/R8, AAPT2, Gradle,
external linker, or `apksigner` in the production path. The first UI-bearing
Activity is now derived from a content-addressed Android target/platform semantic
carrier (CID `2f5d4c1e16498da946dbfd64c815782b831c28af6311907add0bcc598b2fc7bb`)
rather than only compiler configuration. The carrier declares the Activity and
listener class identities plus initial/click text; it adds no Android operation to
the XAX kernel and has no runtime representation by itself.

The generated `XaxActivity.onCreate(Bundle)` is 28 DEX code units: it calls
`super.onCreate`, constructs one `Button`, sets initial text `XAX`, constructs and
registers the generated listener, installs the button with `setContentView`, calls
one private native `xaxOnCreate` callback, and returns. The primary DEX is 1,236
bytes. The generated `XaxOnClickListener.onClick(View)` is 11 code units: it
narrows the clicked view to `TextView`, loads the constant `Clicked`, calls
`setText`, invokes one private native `xaxOnClick` callback, and returns. It emits
no click-time allocation or reflection machinery; the secondary DEX is 764 bytes.
The combined 17,352-byte XAX AArch64 shared object exports both canonical JNI
symbols and has zero imports, `DT_NEEDED`, or relocations. A click-text-only
semantic edit changes the semantic carrier CID and secondary listener DEX while
leaving the primary Activity DEX byte-identical.

The directly emitted signed fixture APK is 35,413 bytes and contains the 1,132-byte
binary manifest, 1,236-byte `classes.dex`, 764-byte `classes2.dex`, and aligned
17,352-byte `lib/arm64-v8a/libxaxapp.so`. The fixture has `minSdk=28`; ART on
API 21+ natively supports secondary DEX files, so no multidex support runtime is
introduced. Repeated generation/signing is byte-identical; committed evidence is
`compiler/benchmarks/android_managed_bridge_evidence.json` and
`compiler/benchmarks/android_apk_evidence.json`.

Both `ANDROID_UNSIGNED_APK` and `ANDROID_SIGNED_APK` are now ordinary M10
requested artifact kinds. The signed request requires a package-declared/profile-
granted `SIGN` capability whose 32-byte scope is the signer certificate SHA-256.
Only that public identity participates in canonical package/profile/request/snapshot
state; RSA private material is transported solely in the ephemeral `BuildEffect`
value, is absent from the canonical store and provenance, and is never placed in
the build key. Repeated signed builds are byte-identical. The committed signer is
test-only fixture material. The direct verifier confirms certificate/public-key
match, PKCS#1-v1.5 SHA-256 signature, and v2 chunked content digest; tamper tests
cover both signed content and signed-data mutation. Independent Android `apksig`
or package-manager verification has not run because no Android SDK/device/runtime
is installed and binary retrieval is unavailable in this host environment.
Therefore installability and UI execution are **not claimed**.

`xax_android_sdk.py` directly parses Java class files, ordinary JARs, and
AOSP-style API-version XML into canonical content-addressed target carriers.
Archive entry order does not change semantic object CIDs. Imported API
`since`/removal metadata is verifier-checked against `compileSdk` and the exact
reachable runtime API interval; an explicit runtime guard can narrow that interval.
`xax_jni.py` derives typed method/field IDs and exact JNI `Call*MethodA`/field
access plans from JVM descriptors, including explicit `jvalue[]` byte counts and
owned local-reference results for object returns. Homogeneous integer argument
packs cover `Z/B/C/S/I/J`: every 8-byte JNI union slot is fully initialized, and
AArch64 uses exact byte/halfword/word/dword stores. The bounded mixed path supports
`jlong` plus strong JNI references. Reference arguments require exact descriptor
compatibility or imported superclass/interface evidence and may require an exact
defining-loader domain; weak globals and mixed narrow integers still reject.
Float/double JNI plans still hard-reject until exact float carriers and AAPCS64 FP
lowering exist. Committed deterministic SDK/JNI evidence is
`compiler/benchmarks/android_sdk_import_evidence.json` and
`compiler/benchmarks/android_jni_platform_evidence.json`.

No Android runtime/device evidence has been fabricated. Package installation, ART
DEX verification/class initialization, `System.loadLibrary`, Activity launch,
actual rendering/click delivery, conditional pending-exception refinement, general
mixed-narrow/reference/float JNI argument-pack lowering, explicit null
construction/refinement, runtime loader-relative resolution/caching, and modern
managed libxposed execution remain open. A bounded cached
`View.setVisibility(I)V` hot-path probe emits 84 bytes / 21 AArch64 instructions;
`View.setClickable(Z)V` emits 108 bytes / 27 instructions; and
`View.postDelayed(Runnable,long)` emits 88 bytes / 22 instructions. All have no
helper/import/relocation and are structural codegen evidence, not Android latency
evidence.

### Android resources, components, and modern libxposed managed-hook structure — 2026-10-01

The generic Android APK builder now accepts an optional content-addressed string-resource carrier and emits deterministic `resources.arsc` only when reachable. Resource-backed UI semantics resolve exact resource IDs into DEX; the bounded resource-backed fixture is 34,742 bytes and keeps `XAX`/`Clicked` literals out of the managed classes. Resource-free APKs remain byte-unchanged and acquire no resource runtime machinery. Android runtime `AssetManager` acceptance remains UNEXECUTED.

Optional semantic component carriers now cover one manifest-declared `BroadcastReceiver`, one concrete unbound `Service`, and one `Application`. The receiver's `onReceive(Context,Intent)` is four DEX code units and performs one direct native callback. The service DEX is 1,052 bytes; `onCreate`/`onDestroy` preserve superclass lifecycle then call XAX, while `onBind(Intent)` is a two-code-unit null return and does not imply Binder support. `Application.onCreate` likewise preserves the superclass call before one XAX callback. Absent component carriers produce no component class/manifest entry.

Current modern libxposed API-102 structural support now covers explicit zero-argument and one-`String` hook installation. Canonical installation identity includes target class/method, Hooker identity, parameter types, `PROTECTIVE` exception mode, `propagate` failure policy, and an explicit lifetime policy. `onPackageReady` resolves through `PackageReadyParam.getClassLoader`; the one-String profile constructs one `Class[1]` only during installation. Both profiles allocate exactly one Hooker at install time. `process` lifetime remains field-free and discards the returned HookHandle. A distinct `retained-manual-unhook` lifetime stores one HookHandle in the generated module and adds an 11-code-unit `xaxUnhook()` method that null-checks, calls `HookHandle.unhook()`, clears the field, and returns. `android_libxposed_unhook_evidence.json` records a 2,016-byte retained module DEX versus 1,896 bytes for the process profile; the Hooker DEX remains byte-identical.

Four deterministic hot-path profiles are now separated by canonical policy: pass-through; zero-argument constant result replacement; one-String argument replacement; and one-String combined argument-then-result replacement. Pass-through and result-only emitted Hookers contain zero hot-path allocations. API-102 argument mutation requires `Chain.proceed(Object[])`, so argument-only and combined profiles explicitly emit one `Object[1]` allocation and one array store per interception; no zero-allocation claim is made. `android_libxposed_combined_evidence.json` records the most complete structural Fixture-E shape: a 34,347-byte module APK, 1,952-byte install DEX with a 51-code-unit `onPackageReady`, and an 852-byte Hooker DEX whose 20-code-unit interceptor reads arg0, allocates/stores one replacement array, calls `proceed(Object[])` exactly once, captures the original result, and returns constant `HookedResult` without any additional object allocation. The paired controlled target is `hookTarget(String):String`, a one-code-unit direct return of its incoming argument. Repeated outputs are byte-identical and the native 17,352-byte ELF remains import/`DT_NEEDED`/relocation free.

Explicit API-102 deoptimization and module-service semantics are now implemented structurally. Deoptimization is a separate canonical carrier with `best-effort` result policy; it must match the companion hook target and adds exactly one `deoptimize(Executable)` invocation between `getDeclaredMethod` and `hook`, reusing the resolved `Method`. `android_libxposed_deopt_evidence.json` records a 1,956-byte module DEX with a 43-code-unit `onPackageReady`; the extra operation emits no allocation and the 5-code-unit Hooker remains deoptimization-free. A separate module-service carrier can reachably expose framework name/version, remote preferences, remote file listing, and remote file open. `android_libxposed_services_evidence.json` records a 1,664-byte module DEX where each selected helper is exactly five code units (`invoke-virtual`, `move-result-object`, `return-object`) with zero emitted allocation; remote failures use explicit `propagate` policy with no hidden cache/retry/exception translation.

Remote-resource capability policy is now explicit rather than delegated to exceptions. A `libxposed-remote-preferences-v1` carrier checks `PROP_CAP_REMOTE` before `getRemotePreferences`, returns null only on capability absence, propagates supported-path framework failures, and exposes a bounded read-only `SharedPreferences` surface: boolean, int, long, float, String, and `contains`. `android_libxposed_remote_preferences_evidence.json` records a deterministic 34,289-byte APK, 2,144-byte managed DEX, one 16-code-unit acquisition gate, and six 5-code-unit typed read helpers, all with zero emitted allocation and no Editor/write surface. A separate `libxposed-remote-files-v1` carrier applies the same capability/failure policy to list/open. `android_libxposed_remote_files_evidence.json` records a deterministic 34,289-byte APK and 1,428-byte managed DEX; each file helper is 16 code units with one capability mask/branch, two direct virtual calls, one null fallback, and zero allocation.

Bounded API-102 hot reload is also implemented structurally. `libxposed-hot-reload-v1` accepts only `single-retained-hook-id-guarded-atomic-replace` with `propagate` framework-failure policy, stable ID `xax.primary`, explicit `skip-replacement` transfer-mismatch policy, `package-ready-class-loader` saved-state policy, and `reject-reload` when package-ready state was never captured. Build closure requires exactly one Java entry, exact min/target API 102, and exactly one `retained-manual-unhook` generated hook. Metadata adds `autoHotReload=true`; initial package-ready installation calls `HookBuilder.setId("xax.primary")` and stores the target/app ClassLoader. The generated 11-code-unit `onHotReloading` rejects a missing loader or saves only that host-owned ClassLoader through `setSavedInstanceState`. The 51-code-unit `onHotReloaded` restores the loader, rejects absent/empty transfer state, verifies `HookHandle.getId()` with `String.equals`, skips mismatched state, then creates one replacement Hooker, calls atomic `HookHandle.replaceHook(...)`, and stores the returned handle; it emits no unhook/install gap, target-member reflection, array allocation, module-defined saved object, or hidden serialization runtime. `android_libxposed_hot_reload_evidence.json` records a deterministic 34,347-byte APK and 2,920-byte managed DEX; the Hooker remains byte-identical to the retained baseline.

This does **not** establish working managed hooking on Android. Module discovery, framework attachment, package-ready delivery, class-loader resolution, hook installation, interception, argument/result mutation, original invocation, exception-mode behavior, retained-handle behavior, actual unhook/idempotence, ART deoptimization result, remote capability/value behavior, preference/file operations, hot-reload callback delivery, saved target-ClassLoader transfer, stable-ID transfer/mismatch behavior, atomic replacement, ART allocation counts, and process survival remain UNEXECUTED because no compatible Android/libxposed runtime is available on this host. Broader method signatures/boxing, remote-file-descriptor consumption, preference writes/listeners, multi-hook stable-identity reload, package/process/resource/listener/thread migration, and measured runtime latency remain unimplemented or unproven.

## Native XAX compiler leaf — BLAKE3 compression (2026-10-02)

The first performance-critical compiler leaf now executes as ordinary XAX semantics. `compiler/bootstrap/xax_blake3_compress.xax` is the committed canonical implementation; `compiler/src/xax_native_blake3.py` can regenerate the full seven-round BLAKE3 compression function as one verified graph with 28 `bits<32>` inputs and one 16-word tuple result. The graph uses ordinary `add.wrap`, new width-exact `bit.xor` and `rotate.right`, aggregate construction, and the existing x86-64 general target; there is no handwritten BLAKE3 lowering or target intrinsic. The graph CID is `f1744e682b2f99c542100f0e987dced9a87f40dfa4b8f173596fb24b78faa216`, function CID `3d3a391c22e1baf03a0a037e33ce7689df0aaceea0f5e65e1bbdf0677a2bf564`, and the normal x86-64 backend emits 19,744 bytes with 806 semantic machine-code ranges.

`compiler/src/blake3.py` retains its dependency-free Python compressor as the immutable bootstrap/fallback path. After `xax_compiler` is available on a compatible x86-64 host, the first compression lazily loads/verifies/lowers the committed XAX graph; recursive hashing during accelerator initialization is forced through the Python leaf. Subsequent compiler BLAKE3 compression calls use the XAX-generated native leaf. The Linux host boundary uses a 279-byte SysV-to-Win64 argument trampoline only because the repository x86-64 target ABI is Win64; the trampoline contains no hash logic.

Executed evidence is in `compiler/benchmarks/xax_native_blake3_evidence.json`, reproduced by `bench_xax_native_blake3.py`. The native graph matched the Python compressor on the committed vector and full public BLAKE3 digests. On the evidence host (`x86_64` Linux, Python 3.13.5), median 5,000-call leaf timing improved by **5.18x** and two 1 MiB whole-hash iterations improved by **4.77x** after warm-up. These are host measurements, not a cross-platform performance guarantee. The existing official BLAKE3 vector tests remain authoritative for digest compatibility.

## U1.1 hosted Windows PE32+ executable — 2026-10-02

- Path: verified XAX -> existing x86-64 frame lowering -> `xax_pe.py` PE32+ container -> Windows loader. No CRT, linker, assembler, LLVM, startup stub, or base-relocation table (code is position independent; image is ASLR/NX compatible).
- `call_foreign` lowers to `call [rip+disp32]`; each distinct `(library, symbol)` gets one IAT slot. Foreign ABI ownership is now explicit: verifier accepts `android-aapcs64-c` and `win64-c`; x86-64 rejects non-`win64-c`, AArch64 rejects non-`android-aapcs64-c`; raw load images reject import-bearing images (`XAX.NATIVE.IMPORTS`). `x86_64-windows-load-image-v5` CID unchanged.
- Escaping stack pointers are materialized by one `lea` only at foreign/direct call argument sites; 1/2-byte stack loads/stores now lower (previously rejected). Existing 4/8-byte encodings unchanged.
- Bounded platform package `xax_platform.win32_kernel32_api`: GetStdHandle, WriteFile, GetProcessHeap, HeapAlloc (verified heap-owner allocator contract), HeapFree (deallocator contract), ExitProcess.
- Returning from a PE entry left the process alive (observed hang; loader worker threads), so termination is an explicit `ExitProcess` call; the container adds no exit path (ADR-076).
- EXECUTED at U1.1 (evidence file since regenerated by U1.2a below): 2,048-byte PE (SHA-256 `4c0bffdf87a5042eccb3737f7e0891e6ebb563e41a5fa75c2d7bc15efd6c7c46`), 918 code bytes, six kernel32 imports; fixture writes `XAX\n` from stack storage, allocates/frees 64 heap bytes, runs a looping `sum_to(10)` direct call, exits 57; 20/20 runs on Windows 11 10.0.26200 AMD64 (AMD Family 25 Model 80). Process wall median 19.3 ms (includes CreateProcess/pipe; not a code-quality claim).
- Not claimed: R2 (no exported callbacks, threads, files, sockets), R4 (no C baseline toolchain on host; code is spill-every-value), heap memory access on x86-64 (HEAP_VIEW not lowered), unwind/PDB/TLS.
- Tests: `tests/test_xax_pe.py` 5/5 (execution test runs only on Windows x86-64), `tests/test_replacement_matrix.py` 3/3. Full suite: 577 tests; the 31 failures/errors are identical by name to the pre-change baseline (missing `pytest`/tokenizer modules, stale pinned evidence/code hashes, host-bound cases); 0 new.

## U1.2a heap views on x86-64 and U1.4 WASI — 2026-10-02

- x86-64 frame lowering now lowers `heap_view` (null test + `ud2`), static heap loads/stores with folded offsets, and checked dynamic heap loads/stores (`[base+index+disp32]` after an unsigned bound check + `ud2`). Heap `address_offset`/`pointer_cast` results are materialized so calls/returns/branches see them. Atomics on heap views reject explicitly. `x86_64-windows-pe-v1` adds `heap_view`; its CID changed to `f9385ae2…`.
- Verifier (ADR-079): pointer-free memory-effect call interfaces are pure ordering frontiers; previously any effect-bearing direct call needed a stack contract.
- `win32_kernel32_api` adds `VirtualAlloc` (zero-filled, 4096-aligned allocator contract) and `virtual_free_view`.
- EXECUTED (Windows 11 x86-64): the PE fixture now also calls `squares_sum`, which fills a 16 x b32 heap array with i*i in one loop and sums it in another through checked heap accesses, then frees it. Exit 1298 = 55 + 1 + 1 + 1240 + 1. Evidence: 3,072-byte PE, 1,997 code bytes, 8 kernel32 imports, 20/20 runs (`windows_pe_hosted_evidence.json`, SHA-256 `ab3d7a86…`). Out-of-bounds variant (17 elements) traps with `STATUS_ILLEGAL_INSTRUCTION` (test).
- WASI (ADR-080): `wasm32-wasi-v1` + `wasm32-import` ABI + `xax_platform.wasi_preview1_api`; `run_wasi_isolated` runs modules under Node `node:wasi`. EXECUTED: 451-byte module; host writes argc/argv size into XAX stack storage via `args_sizes_get`; XAX reads them, runs `sum_to(10)`, and calls `proc_exit(97)`; 10/10 runs on Node v26.7.0 (`wasi_command_evidence.json`).
- U1.2b prototype: `x86_64-windows-pe-v1` frame functions get a chunk-exact store→load forwarding peephole (reload deleted, or `mov dst, src`; never at a branch target; labels/branches/calls/semantic ranges shifted). Legacy load-image targets keep pinned bytes. PE fixture code 1,997 → 1,873 bytes (−6.2%); evidence regenerated (3,072-byte PE, SHA-256 `87e1edaa…`), still exit 1298 on 20/20 runs.
- Regression after all U1 changes: 584 tests; the 31 failures/errors are identical by name to the pre-change baseline; 0 new.
- Not done: real register allocation for frame functions (U1.2b); pointer values in memory (OI-37) — blocks `fd_write` iovecs and linked structures; browser bindings.

## OI-37 first slice: `pointer_address` — 2026-10-02

- New memory operation `pointer_address` (id 66, ADR-081): pointer -> `bits<pointer width>`, mandatory exposure waiver, live-storage check, provenance-free result; lowered on x86-64 (`lea`/load) and wasm32 (no-op); reference executor rejects. Added to `x86_64-windows-pe-v1` (CID now `9c6224e5…`; PE bytes unchanged) and `wasm32-wasi-v1`.
- `wasi_preview1_api.fd_write` declared with iovec/nwritten memory effect plus buffer memory effect.
- EXECUTED: WASI fixture now prints `XAX\n` to stdout through `fd_write` and exits 97; 635-byte module; 10/10 runs on Node v26.7.0 (`wasi_command_evidence.json`, SHA-256 `88df1893…`).
- Still open (OI-37): provenance-carrying pointer stores/reloads (linked structures, vtables).

## OI-37 second slice: provenance-free pointer elements — 2026-10-02

- ADR-082: memory elements may be pointer types; only provenance-free pointers (function addresses, external pointers) may be stored; reloads carry no facts. x86-64 checks pointer-element accesses against the 64-bit pointer width. Reference executor rejects pointer elements explicitly.
- EXECUTED (Windows 11 x86-64): PE fixture adds `dispatch()` — a two-entry function-pointer table in stack memory, reloaded by checked loads and called via `call_indirect` (41). Exit 1339; 3,584-byte PE, 2,181 code bytes, SHA-256 `87fd6168…`, 20/20 runs.
- Negative: storing the table's own stack address rejects (`MEMORY-POINTER-STORE-LOCAL-PROVENANCE`).

## U1.2b register path for hosted x86-64 — 2026-10-02

- ADR-083: on `x86_64-windows-pe-v1` the register-resident allocator now also lowers compares, foreign calls (with shadow space), function addresses, heap views, heap pointer arithmetic, static/checked heap loads/stores, and cross-block SSA uses (frame homes). Stack-storage/float/aggregate/indirect-call functions remain on the frame path with the forwarding peephole. Legacy targets unchanged.
- MEASURED (`x86_register_path_evidence.json`): `sum_to(200,000,000)` frame path 433 B / 738.7 ms median vs register path 89 B / 92.1 ms (8.02x), 7 runs.
- EXECUTED: PE fixture code 1,269 bytes (was 2,181), PE 2,560 bytes (SHA-256 `a5e01731…`), exit 1339, 20/20 runs; OOB heap store still traps.

## Android without a device (ADR-105, ADR-106) — 2026-10-02

- Host tooling (not in the repository): `qemu-user-static` 8.2.2, NDK r28c, build-tools 34 and 36.1, platform 35, and the official Android 14 arm64 system image. `linker64` and bionic were extracted from it into a qemu root (paths in `bench_android_bionic.py`).
- EXECUTED under Android's `linker64` and bionic, via `qemu-aarch64` (`android_bionic_qemu_evidence.json`, 29/29). That covers the platform-contract probe (file, pthread, socket through 10 bionic imports; first execution ever), libxposed `native_init`, nine JNI fixtures checked slot by slot against recording stubs generated from the NDK `jni.h`, `JNI_OnLoad`/`GetEnv`, a bionic `getpid` import, and both callbacks from the device-validated APK. Every case runs in both ELF containers.
- XAX's 229 native and 5 invoke JNI slot names equal the `jni.h` order exactly.
- STRUCTURAL: all 20 committed APKs pass `apksigner`, `zipalign -c -P 16`, `aapt2`, `dexdump`, D8 re-dex, and `llvm-readelf` (`android_official_tools_evidence.json`). A first run reported 12 false `apksigner` failures; the cause was the benchmark's signed-APK detector, not the APKs (libxposed fixtures carry unsigned `META-INF/xposed/` metadata).
- ADR-105: the packed container (format 5) cuts the Activity library from 17,352 to 1,496 bytes and the APK from 35,413 to 19,557 bytes. The format-4 APK is byte-identical.
- MEASURED against a Java + NDK twin (`XAX_BENCHMARKS.md` §15.7): format 4 is 1.43× the twin's APK; packed is 0.79× the APK and 0.39× the native library. DEX is 1.17× (one DEX per class). With equal 16 KiB alignment, the first comparison (2.83×) was unfair to XAX, because the twin had only 4 KiB alignment.
- ADR-107: C code on Android calls pure XAX functions with no adapter (the address is the function itself). bionic `pthread_create` ran four concurrent XAX start routines (looping `fib`), all joined correctly in both containers. The suite is now 31/31. The worker is lowered by the AArch64 frame path, so code quality is poor.
- ADR-108: ART's own verifier (`dex2oat64 --compiler-filter=verify` plus `oatdump`, from the system image, under qemu) reports all 20 committed APKs and 62 classes `Verified`. That includes every libxposed module, checked against libxposed API 102.0.0 as parent class loader. An ill-typed listener control is `NotReady`. `integration/android/make_android_root.py` rebuilds the environment from SHA-256-pinned archives. A fresh rebuild into a second prefix (77 s, from cached archives) reproduced identical ART class statuses (20/20 plus the control) and the bionic suite (31/31, identical library hashes).
- ADR-109: all 12 libxposed module profiles EXECUTED on ART (`dalvikvm64` from the system image) with a stand-in framework. Each matches its declared behaviour: argument/result/combined replacement, deopt before hook, stable hook ID, unhook through the retained handle, capability-gated remote preferences/files, and service pass-through with `propagate`. ART's nativeloader loads each module's XAX library and JNI dispatches into it. A patched-literal control is observed. Hooks on `Activity` methods use a simulated receiver.
- ADR-110: the AArch64 register path now covers general (v4 and bare-metal general) functions with integer, pointer, and compare values, including loops: `cmp`/`cset` compares, plus value homes for cross-block uses. The differential corpus (48 programs, 288 results under bionic) matches the reference executor, and two mutation checks prove it can fail. v3 bytes are unchanged; the packed probe is 3,016 → 2,760 B and the thread library 1,936 → 1,664 B.
- ADR-111: stateful app `xax.counter` (`benchmarks/android_counter_app.py`). XAX native code owns the count, the file reads and writes, and descriptor closing; DEX only opens the descriptor and shows the number. ART verifies both classes. Under bionic the APK's library restores, increments, and persists across a simulated restart (0,1,2,3 → 3 → 4; 8-byte file; descriptors closed). The DEX emitter gained generic assembled methods, and existing DEX is byte-identical. The official-tools and ART evidence now cover 21 APKs (64 classes, all `Verified`). Device run pending: `integration/android/validate_counter_apk.sh`.
- Regression: 717 tests. The failure set equals the baseline except for environment effects of installing `tiktoken` (OI-03 now passes; OI-12/OI-13 evidence replays fail whenever `tiktoken` is present, as already recorded below).

## Post-upgrade token test (lowest cost) — 2026-10-02

- Offline, with no model tokens: after installing `tiktoken` 0.14.0, the AI-native harness and the OI-03/OI-04 tokenizer replays pass 44/44.
- Model: one `task-01` pair (change a shared constant) run as fresh `haiku` subagents. C used 38,278 tokens and 4 tool calls; XAX used 39,997 tokens and 7 tool calls (1.04× C). Both passed the external checkers on the first attempt with no repairs. This is n=1 with fixed agent-harness overhead dominating, so it is not OI-31 evidence. It agrees with the earlier `task-02` smoke check (1.04×): on tiny edits, the XAX protocol's extra inspect/test round trips cost about as much as the C edit saves.

## Browser pages with generated host bindings (ADR-103, U1.4) — 2026-10-02

- Target `wasm32-browser-v1`, platform package `compiler/src/xax_web.py` (`xax-web-v1`: `query_copy`, `set_body_text`; host state ordered by `effect<io>`). `emit_browser_page` generates one deterministic HTML page containing the module plus host functions for the imported bindings only. Imports outside the package reject.
- The wasm backend lowers `bit.and`/`bit.or`/`bit.xor`/`udiv`/`urem`/`int.truncate`/`int.zero_extend`, but only on targets that list them. Existing wasm targets and their evidence are byte-identical.
- EXECUTED in headless Chromium 141 through Playwright (`compiler/benchmarks/browser_fib.py`, `browser_fib_evidence.json`). The XAX program reads the URL query, parses `n`, computes `fib(n)` modulo 2^64, formats it, and renders it into the DOM. Four queries pass with no page errors. Module 1,270 B, page 2,343 B. Vectors: `compiler/tests/test_xax_web.py` (7 tests).
- Event entries (ADR-104, closes OI-43): `code-entry:wasm32-browser-event` addresses lower to exported `entry_<k>`; `body_on_click` and `body_text_copy` bindings. The interactive page (`n fib(n)`, advanced by XAX on each click) passes 4 queries × 2 clicks in Chromium. Module 3,700 B, page 5,843 B.
- Matrix: `browser-web` NONE → R2 (bounded bindings executed, including events). R3 needs a nontrivial application.

## C callbacks and SSE-class SysV arguments (ADR-102, OI-40) — 2026-10-02

- A code address's calling convention is now part of its type. `FUNCTION_ADDRESS` returns `ptr<opaque<function>>` (internal) or `ptr<opaque_identity<"code-entry:sysv-x86_64-c">>` (`linux_api().c_callback`). The verifier requires foreign-entry targets to be pure and rejects both convention mismatches. No new operation, object kind, or type form.
- x86-64 emits one 20-byte SysV-to-internal adapter per C-entry function after all functions. `sysv-x86_64-c` imports pass f32/f64 in `xmm0`–`xmm7` and return them in `xmm0`.
- EXECUTED (`compiler/benchmarks/linux_c_interop.py`, `linux_c_interop_evidence.json`): libc `tsearch`/`tfind` with an XAX comparator exits 31 (a constant comparator, as a control, exits 78); libm `ldexp`/`pow`/`sqrtf` exits 68. Artifacts are 1,640 and 1,536 bytes and deterministic. Vectors: `compiler/tests/test_xax_c_interop.py` (12 tests).
- Bug fixed: the Linux register allocator silently dropped SysV C arguments past the sixth. It now defers to the frame path, which rejects (`SYSV-C-SCALAR-CLASS`).
- Open: effectful callbacks such as a `qsort` comparator that reads elements (OI-42); aggregates, stack arguments, and variadics (OI-40).

## U1.3 Linux x86-64 executables and the Linux register path — 2026-10-02

- Kernel integer completion (ADR-084): `bit.and` 67, `bit.or` 68, `udiv` 69, `urem` 70, `int.truncate` 71, `int.zero_extend` 72, with verifier rules, reference semantics, and x86-64 lowering. Portable trap reason 2 is `integer-divide-by-zero`. Only the Linux target packages advertise these operations.
- Foreign ABIs: `linux-x86_64-syscall-v1` (ADR-085, register templates in declaration identity) and `sysv-x86_64-c` (ADR-087, INTEGER class only), both added to the single `FOREIGN_ABIS` registry. Typed declarations live in `xax_linux.py` (`read`, `write`, `openat`, `close`, `mmap_anonymous`, `munmap_view`, `exit_group`, and `c_function` for C imports).
- Containers (ADR-086/087): `xax_linux.py` emits static or explicit-loader ELF64 `ET_EXEC` with no container code. Generic ELF packing is in `xax_elf.py`, shared with the Android emitter (Android bytes unchanged). Linux imports use the shared `call_import`/`NativeImage.imports` path.
- Process entry: the entry function is lowered for Linux's aligned, no-return-address start (`compile_native(..., process_entry=True)`); its `ret` lowers to `ud2`, and exit is the program's explicit `exit_group` (ADR-076 rule).
- Frame path (ADR-088): on Linux profiles only, escaping frame pointers are materialized and value pointers use base-register access, alongside main's heap-view lowering. `pointer_extent_from_graph` is shared with AArch64.
- Register path (ADR-089): `xax_x86_64_regalloc.py`, separate from the PE allocator (ADR-083); convergence is OI-38. Differential corpus: `compiler/tests/test_xax_regalloc_differential.py` (120 seeded programs executed natively versus the reference executor).
- Workload: `compiler/benchmarks/linux_filestat.py`. MEASURED (`u1_linux_filestat_evidence.json`, `XAX_BENCHMARKS.md` §15.1): 0.95–1.14× `gcc -O2` and 1.41–1.82× `clang -O2` over seven runs; 3,560-byte artifact; 1,184 KiB peak RSS (loader + libz + libc). R4 is not met.
- Construction tooling: `xax_graph_builder.py` (block/node builder and reachable-closure store writer); it is not a source language.
- Token test after the upgrade (lowest cost). Offline: with `tiktoken` installed, the OI-01 transport counts and the OI-03/OI-04 replays reproduce, and the AI-native tests pass 17/17. The OI-12 and OI-13 committed evidence records `tiktoken` as unavailable, so those replays fail whenever it is present (environment-dependent; predates this work). Model: one `task-02` pair with `haiku` subagents — C 35,151 tokens, XAX 36,492 tokens (1.04×), both pass; this is not OI-31 evidence.
- Regression on Linux x86-64 (Python 3.11.15, pytest, `tiktoken` installed): the merged tree has exactly main's 17 environment/evidence failures — host-bound Windows/QEMU cases, the stale stack-memory hash pin, the OI-25/OI-26 replays, the OI-12/OI-13 `tiktoken` replays, and the wheel build — with 781 tests passing.

## OI-37 measurement: arena + index versus pointer links — 2026-10-02

- Workload `compiler/benchmarks/linux_chains.py` (chained hash table, 2^20 nodes, 2^16 buckets) in XAX with arena indices and checked access. Its C twin uses pointer links, and diagnostic C twins use index links with and without checks. Shared tooling: `benchmarks/linux_graph_kit.py` and `benchmarks/linux_harness.py` (filestat ported with a byte-identical artifact).
- MEASURED (`oi37_chains_evidence.json`, two runs): XAX 3.49–3.58× `gcc -O2`, 1,598 B, 16,896 KiB RSS. Attribution: representation 1.44–1.47×, checks 1.34–1.41×, XAX code generation 1.73–1.80×. Decision ADR-090: OI-37 pointer provenance is justified but follows OI-38.
- Tests: `compiler/tests/test_xax_chains.py` (small-table correctness against an independent reference, plus artifact identity).

## OI-38 step 1: Linux allocator (ADR-091) — 2026-10-02

- `xax_x86_64_regalloc.py`: cross-block values used in loops are pinned to `rbx/rbp/r12–r15`; fall-through branch layout with out-of-line edge stubs; shared cold trap stubs; power-of-two `udiv`/`urem` as shift/mask; 16-byte loop-header alignment.
- MEASURED (one run each): `chains` 1.91× `gcc -O2` (was 3.49×), and 1.06× equivalent checked-index C (was 1.80×). `filestat` 0.94× `gcc -O2`, 1.47× `clang -O2`.
- Differential corpus: 120 + 40 programs (the 40 call while values are pinned). Evidence JSONs regenerated.

## OI-37 step: `pointer_rebase` (ADR-092) — 2026-10-02

- Operation 73 in the kernel. Verifier windows, executor and frame-path rejection, Linux allocator lowering (`sub; ror; cmp; ja` to a cold trap). Spec §5.6, conformance §23 item 12.
- `chains` builds `links="pointer"`, and C gains a `-DCHECKED` diagnostic. MEASURED: pointer links 1.64× `gcc -O2` (1.07× checked-pointer C); index links 2.00×. The Linux allocator also keeps a layout-next successor inline when both edges copy.
- Tests: `compiler/tests/test_xax_pointer_rebase.py` (executed traps, verifier rejections), and `test_xax_chains.py` covers both link kinds.

## OI-37 step: `pointer_rebase` on wasm32 (ADR-093) — 2026-10-02

- `wasm32-wasi-v1` lowers operation 73 (`i32.sub; i32.rotr; i32.gt_u; unreachable`). The wasm static layout reserves address 0–15, so 0 is never a storage address.
- EXECUTED: a WASI linked-list walk exits 42, and four corrupted-link vectors trap (`test_xax_wasm_rebase.py`). Full suite: 790 passed, plus the 17 pre-existing failures.

## Linux argv/env/auxv (ADR-094) — 2026-10-02

- New foreign ABI `linux-x86_64-startup-v1`: `argc`, `arg_length`, `arg_copy`, `envc`, `env_length`, `env_copy`, `auxv_value`, lowered inline in the process entry (`xax_linux.linux_startup_api()`). `run_linux_executable` accepts `arguments` and `env`.
- EXECUTED: an echo-style tool, envc, `AT_PAGESZ`, truncation reporting, and traps (`test_xax_linux_startup.py`). Full suite: 796 passed, plus the 17 pre-existing failures.

## OI-38: PE on the converged allocator (ADR-095) — 2026-10-02

- `x86_64-windows-pe-v1` uses `xax_x86_64_regalloc.py` first. It adds Win64 calls (including stack arguments), `function_address`, `call_indirect`, and stack storage, with per-profile foreign ABI ownership. It also fixes the constant-return epilogue bug.
- PE fixture: 6/6 functions converged; code 700 B (was 1,269); EXECUTED-UNDER-WINE 9.0 (`windows_pe_wine_evidence.json`; `WineExecutionTests` runs when wine64 is installed).

## OI-37 closed (ADR-096) — 2026-10-02

- Closure evidence: iovecs (ADR-081); pointer-linked traversal on x86-64 (heap) and wasm32 (stack storage, the stated deviation); forged/expired vectors on both targets; verifier cost and offline edit tokens (`oi37_closure_evidence.json`).
- Check-free reloads move to OI-41 (typed mixed storage, deferred).

## OI-41 closed: record links (ADR-097) — 2026-10-02

- Kernel: type `link` (form 11), operations `link_make` (74) and `link_follow` (75), record views over tuple elements, and an optional `heap_view` link-target operand. Verifier rules: 21 (`oi41_links_evidence.json`).
- Allocator (shared by Linux and PE): null-test elision, displacement folding, loop rotation with aligned targets, edge hints, and range-proven rebase elision.
- MEASURED: `chains` record links 1.066× `gcc -O2`. Tests: `test_xax_links.py` (9 rejection vectors, null-only constants, a walk, and a null-follow trap). Full suite: 801+ passed, plus the 17 pre-existing failures.

## Record links on wasm32 and PE (ADR-098) — 2026-10-02

- wasm32: 8-byte link fields holding zero-extended `i32` addresses; `link_follow` as `i32.eqz`/`unreachable`. PE: operations 73–75 admitted and lowered by the converged allocator.
- EXECUTED: `test_xax_wasm_links.py` (walk exits 42, null traps) and `test_xax_pe_links.py` (exit 42 under Wine 9.0). Full suite: 807 passed, plus the 17 pre-existing failures.

## Links across calls and padding (ADR-099) — 2026-10-02

- Borrowed record views link into themselves (callers may pass only such views). Windowed record loads ignore uninitialized padding.
- EXECUTED: a callee walk (exit 42); a cross-target table cannot be passed; padded wasm32 stack records walk to 42; an unwritten field still rejects.

## PE row: first C comparison (ADR-100) — 2026-10-02

- `hosted.c` is now an exact twin of the fixture (exit 1339). MinGW-w64 no-CRT build; `CTwinTests` checks parity under Wine.
- MEASURED-UNDER-WINE: file 2,048 B (XAX) against 2,560 B (C); code 757 B against 416 B (gcc folds `sum_to` and the dispatch table); wall time equal, start-up bound.

## Cross-call link targets (ADR-101) — 2026-10-02

- `link_target` (op 76) lets a callee borrow a table and the arena its links point into. Every call site checks the pair. It lowers to no code.
- x86-64 elides returned borrowed views when a function has more than one machine return. Executed: callee walks cross-storage links, exit 42. Three rejection vectors.
- Linux target profiles now list op 76. That changes the `chains` and `filestat` program roots; the executables are byte-identical. Evidence JSONs are updated.

## JVM and RISC-V targets; evidence hosts (ADR-112–ADR-114) — 2026-10-03

- JVM (ADR-112): `xax_jvm.py`. EXECUTED: integer differential corpus (widths 8/13/32/47/64), float/conversion grid, `java -jar` run (stdout through `System.out`, exit 7 via `System.exit`), a trap stack trace mapped to its node, package build (`JVM_EXECUTABLE_JAR`/`JVM_LIBRARY_JAR`), and workspace mapping (`test_xax_jvm.py`, 18 tests and 78 subtests). MEASURED: Collatz 1.04× `javac` kernel time, 1.51× class bytes, 1.01× peak RSS (`XAX_BENCHMARKS.md` §15.8). JVM row: R2.
- RISC-V (ADR-113): `xax_riscv64.py`, with liveness-hull linear scan into s1–s11. EXECUTED under Unicorn: the same differential corpus, a register-pressure loop, traps; every word decodes under `llvm-mc` (`test_xax_riscv64.py`, 9 tests and 383 subtests). MEASURED (emulated): Collatz 3.72× `clang -O2` instructions, 3.23× bytes (§15.9). riscv64 row: R1.
- Evidence hosts (ADR-114): the six Windows-only x86-64 tests and both QEMU-only AArch64 tests now execute on Linux. One stale code hash was re-pinned after execution.
- Repairs: OI-25's projection benchmark wrote zip entries in filesystem order (Python 3.11 `zipapp` uses an unsorted `rglob`), so its replay failed on some hosts; it now writes them in declared order. OI-26's replay compared the generating interpreter's version, a host observation. The wheel listed neither `xax_web` nor `xax_android_counter`.
- Regression on this host (Linux x86-64, Python 3.11.15, OpenJDK 21.0.11, clang 18.1.3, unicorn 2.1.0): **903 passed, 19 skipped, 2 failed**. The two failures are environment-bound: `tiktoken` is not installed, and the wheel build requires Python ≥ 3.12. Before this pass: 862 passed, 16 failed.

## Lend entries: `qsort_r` with an XAX comparator (ADR-115, OI-42 closed) — 2026-10-03

- `sysv-x86_64-c-lend` entries read a view lent by the C call that receives them. EXECUTED: glibc `qsort_r` sorts a 16-element XAX heap array; exit 117 (`linux_qsort_evidence.json`). Seven rejection vectors (`test_xax_lend_entry.py`, 9 tests).

## Post-upgrade token test (lowest cost) — 2026-10-03

- Offline, with no model tokens (tiktoken 0.14.0, `o200k_base`): the AI-native harness and the OI-03/OI-04 tokenizer replays pass 44/44. With a tokenizer installed, the OI-12/OI-13 suites now check real counts, and OI-12's committed evidence records them (9 and 7 tokens per timing query/response).
- Model: one `task-01` pair (change a shared constant), each arm a fresh `haiku` subagent given the identical task prompt. C used 37,576 tokens and 3 tool calls; XAX used 40,021 tokens and 10 tool calls (1.065× C). Both pass the external checkers on the first attempt with no repairs. n=1, dominated by fixed agent-harness overhead, so this is neither R5 nor OI-31 evidence. It matches the earlier results (1.04×, 1.04×): on one-constant edits, the XAX protocol's inspect/mutate/test round trips cost slightly more than the C edit saves. The ADR-112–115 changes did not touch the workspace protocol, so this is a regression check, not a new measurement of it.

## Self-hosting step S1: XAX-authored RISC-V encoder on the production path (ADR-116) — 2026-10-03

- `xax_selfhost_riscv64.py` builds `encode(kind, a1..a6)`, covering all RV64 formats plus the `li` planner, as one XAX function. Its committed store is `bootstrap/xax_riscv64_encoder.xax` (10,129 bytes). On Linux x86-64 the RISC-V backend encodes through it by default, natively, with the Python encoders as reference and fallback.
- EXECUTED: the native leaf agrees with Python on 12,072/12,072 cases. The encoder also runs on RISC-V (emulated, 300/300) and on the JVM. Corpus images are byte-identical with either encoder, and the encoder compiling itself is a fixed point (`test_xax_selfhost_riscv64.py`, `selfhost_s1_evidence.json`).
- Cost: about 2.0 µs per native call against 0.18 µs in Python; a RISC-V compile takes 2.30 ms against 2.15 ms. The compiler is still mostly Python; see the S ladder in the roadmap.

## Self-hosting step S2: every CID from an XAX-authored hash (ADR-117) — 2026-10-03

- `xax_selfhost_blake3.py` implements the whole BLAKE3-256 hash as one XAX function over lent input and scratch views (store `bootstrap/xax_blake3_hash.xax`, 34,025 bytes; native leaf 44,387 bytes). `blake3.blake3()` uses it by default on Linux x86-64, so the compiler's content identities come from XAX code.
- EXECUTED: official vectors, boundary and random lengths up to 1 MiB, and 3,000/3,000 agreement with the Python driver. MEASURED: 11.6× faster object hashing (49 ms against 568 ms for 3,000 objects).

## Self-hosting step S3: the store container decoder is XAX (ADR-118) — 2026-10-03

- `xax_selfhost_store.py` (store `bootstrap/xax_store_decoder.xax`) decides container acceptance and builds the record index. `StoreReader` uses it by default on Linux x86-64, checking digests with the S2 XAX hash, and runs the bootstrap parser only to produce diagnostics or for deferred cases. EXECUTED: identical accept/reject and index over 2,000 mutations (6,000 in development), and identical diagnostics on rejection. MEASURED: 0.70 ms against 1.17 ms per read of a 34 KB store.
- With S0–S3 on the production path, an object's identity (hash) and the container that holds it are both computed by XAX code.
- S3b (ADR-119): the XAX decoder also parses every object envelope; `StoreReader.get` builds objects from it and checks CIDs with the S2 hash. Objects or their exact diagnostics are identical to the bootstrap decoder's on committed stores and 600 mutations. Read plus decode of a 34 KB store: 1.90 ms against 3.48 ms.
- S3c (ADR-120): graph-body syntax is decoded by XAX (`xax_selfhost_graph.py`, store `bootstrap/xax_graph_decoder.xax`); `_parse_graph` walks its stream. Parses and diagnostics are identical on real graphs and 1,500 mutations. Full suite: 936 passed, 1 host-bound failure.
- S3d (ADR-121): branch targets, dominators, and block order are computed by XAX (`xax_selfhost_cfg.py`, store `bootstrap/xax_cfg_analysis.xax`), identical to the bootstrap on 400 random CFGs. Full suite: 941 passed, 1 host-bound failure.
- S3e (ADR-122): every value use's definition and dominance is checked by XAX; `value_type` is a plain lookup when XAX proves them all. Full suite: 942 passed, 1 host-bound failure.

## Linux AArch64 executables (ADR-123) — 2026-10-03

- New platform row `linux-aarch64` at R2 (emulator-only): static and explicit-loader ELF64 executables from the shared AAPCS64 lowerer, `linux-aarch64-syscall-v1` thunks, `aapcs64-linux-c` imports, and the unchanged `filestat` graph executed under qemu-aarch64 with glibc and `libz.so.1`. 14,024 bytes vs 67,496 for gcc -O2; 6.6× gcc's emulated time (frame path).
- AArch64 frame path: integer completion operations; liveness-shared value slots on the Linux identities (filestat frame 4,848 → 240 bytes).
- Fixed a miscompile: a duplicate `_cset` made frame-path integer and float compares crash or pick the wrong condition. Regression test executes every compare kind.
- Matrix validator now enforces conformance §23.17 (no performance evidence on emulator-only rows). `requires-python` lowered to 3.11, where the full suite passes.
- Full suite: 809 tests pass, 17 skipped (host-bound), on Python 3.11 with qemu-user, pytest, tiktoken, and unicorn installed.

## SPIR-V compute kernels on Vulkan (ADR-124) — 2026-10-03

- GPU row NONE → R1. `xax_spirv.py` lowers ordinary XAX functions (the `spirv-compute-v1` entry contract) to SPIR-V 1.3 compute modules; they pass `spirv-val` and run on Mesa llvmpipe with buffers and trap status equal to the reference executor. Concurrency safety is a checked rule (`SPIRV-KERNEL-OWN-ELEMENT`). Collatz: 6.9× glslang's time on llvmpipe, 1.81× module bytes (dispatch-loop lowering).
- `GraphBuilder` blocks gained `trap()`; the reference executor accepts reference-backed heap-space pointer arguments.

## Recursion is callable (ADR-125) — 2026-10-03

- Group member functions make `(group, member)` callable; recursion now compiles and runs on the reference executor, wasm32, RISC-V, the JVM, AArch64 bare metal, and Linux x86-64/AArch64 executables (factorial, even/odd, and recursion over a borrowed view). Previously no compiled program could recurse.
- AArch64 now elides borrowed-view returns (ADR-101), so view-passing functions compile there.
- Full suite: 833 passed, 17 skipped.

## First R3 application: `jsonmin` (ADR-126) — 2026-10-03

- Linux x86-64 R2 → R3 and Linux AArch64 R2 → R3 (emulated). `jsonmin` validates and minifies JSON from stdin; it matches its reference contract and Python's parser on generated and mutated inputs. Against C twins it now takes 1.56× gcc -O2 and 1.67× clang -O2 time (from 2.11× before program and compiler changes) with the smallest RSS and binary, so it is not R4.
- The matrix validator now gates R4 on an explicit `competitive` verdict.
- Fixed: narrow-width register binary operations on the Linux x86-64 allocator; extents of pointers that calls give back.
- Full suite: 840 passed, 17 skipped.

## C header import (ADR-127) — 2026-10-03

- `xax_c_import` turns C prototypes (clang JSON AST) into canonical foreign declarations. It is byte-identical to the hand-built `crc32`, libm, and `strlen` declarations, and an XAX program using imported glibc stdio executes. Coverage: 855 of 1,084 functions across zlib.h, string.h, stdio.h, and math.h; the rest are refused with reasons (variadics, by-value types).

## Bare-metal board on QEMU virt (ADR-128) — 2026-10-03

- Board profile 5 and `aarch64-qemu-virt-v1`: a bare-metal XAX program prints over UART MMIO, takes three GICv2 virtual-timer interrupts through a contract-checked XAX handler, and powers off via PSCI (5,420-byte image, exact output). U1.6 is executed (emulated); the row stays R1 because bare metal cannot link foreign objects yet.
- The semihosting AArch64 harness now passes `-net none`: with `qemu-system-aarch64` installed but no EFI ROMs, its default NIC failed to start (3 tests errored in the commit that added the board; fixed in the next commit). Full suite: 853 passed, 17 skipped.

## Static linking into bare-metal images (ADR-129) — 2026-10-03

- `xax_elf_link` links freestanding AArch64 ELF objects (exact relocation subset) into board images. XAX calls C through `aapcs64-c` declarations imported from the header, including a C-side allocator under an explicit contract. The aarch64-baremetal row R1 → R2 (emulated). Matrix: `NOT_APPLICABLE` needs a justification and satisfies only `dynamic_linking`.

## Standard semantic libraries (ADR-130) — 2026-10-03

- `xax_stdlib`: the `xax.text` and `xax.collections.hashset_u64` package families (canonical `PACKAGE` objects, function-granular, instantiated per extent or capacity, target independent). `uniqcount` uses them and is EXECUTED on Linux x86-64 and AArch64. OI-36 CLOSED.

## Small-set membership selection (ADR-131) — 2026-10-03

- The Linux x86-64 register allocator lowers `x == c1 || x == c2 || …` branches to one `bt`. `jsonmin` went from 1.56× to 1.20× gcc -O2, and from 1.67× to 1.31× clang -O2. Linux stays at R3 (not competitive).

## Post-upgrade token test (lowest cost) — 2026-10-03, after ADR-123–131

- Offline only, with zero model tokens (tiktoken 0.14.0): the AI-native harness and the OI-03/OI-04/OI-12/OI-13 tokenizer replays pass 67/67 against the changed verifier. New offline token evidence comes from OI-36 (`oi36_stdlib_evidence.json`): using the standard packages takes a 268-token interface view plus a 1,360-token application mutation, against 3,256 tokens with the library bodies inline.
- No model pair was run. `xax_workspace`, the AI-native harness, and `docs/09_AI_PROTOCOL.md` are unchanged since the last pair (`task-01`, `haiku`, XAX 1.065× C), so a new pair would only repeat that regression check. The next paid trial should measure something new: a library-using edit, such as adding a call to `hashset_u64.contains`.

## Self-hosting step S4: scalar operation typing is XAX (ADR-132) — 2026-10-03

- `xax_selfhost_typing.py` (store `bootstrap/xax_op_typing.xax`) types the integer, compare, rotate, float, and conversion nodes, decoding type objects itself. It is the default verifier path on Linux x86-64. The bootstrap checks only the nodes it does not prove, so diagnostics are unchanged. EXECUTED: on 600 random nodes, the proven set is exactly the bootstrap-accepted set. MEASURED: all 2,419 covered nodes in four real stores are proven, with verify time roughly unchanged. Full suite: 868 tests, 17 skipped.

## Self-hosting step S4b: aggregate and sum typing is XAX (ADR-133) — 2026-10-03

- The XAX typing function now also decodes tuple, array, and sum types (of scalar elements) and checks `aggregate.make/get` and `sum.make/tag/get`. On 1,000 random nodes it agrees with the bootstrap: every proven node is accepted, and every accepted node is proven except those with nested aggregates. 2,444/2,444 covered corpus nodes are proven. Full suite: 868 tests, 17 skipped. Next is S4c: call, constant, memory, and resource nodes together with the fact tracking.

## Self-hosting step S4c: resource, effect, and meta typing is XAX (ADR-134) — 2026-10-03

- The XAX typing function now decodes effect, resource, and opaque types and checks `effect.step`, `resource.*`, and `meta.*` nodes. Every node check that reads only types is now XAX. For 2,000 random nodes, outcomes and exact diagnostics are identical with the path on and off. 2,447/2,447 covered corpus nodes are proven. Full suite: 868 tests, 17 skipped. Next is S4d: call, constant, memory, atomic, and target typing, which needs the pointer/owner/effect fact tracking.

## Self-hosting step S4d.1: constants and terminators typed by XAX (ADR-135) — 2026-10-03

- The XAX typing function now validates constant objects and values, and terminator condition and edge types. Outcomes are identical with the path on and off on random nodes and 150 random branching graphs. 3,374/3,374 covered corpus nodes and 427/427 terminators are proven. Full suite: 870 tests, 17 skipped. Remaining in Python: call contracts and the pointer/owner/effect fact system (S4d.2).

## Self-hosting step S4d.2a: memory-free graphs skip the fact system (ADR-136) — 2026-10-03

- XAX now checks `call.direct` contracts and reports whether a graph is memory-free. When it is, and every node and terminator is proven, the verifier runs no memory-fact passes. Outcomes are identical with the path on and off on random nodes, calls, and branching graphs. 5 of 20 corpus graphs take the skip path. Full suite: 870 tests, 17 skipped. Next is S4d.2b: stack-storage facts in XAX.

## Self-hosting step S4d.2b: memory-fact engine in XAX, stack storage (ADR-137) — 2026-10-03

- `xax_selfhost_facts.py` runs the bootstrap's memory-fact passes as XAX (same facts, merge, and fixpoint), accept or decline. It models stack storage now; on acceptance the verifier skips its Python passes and takes the pointer extents from XAX. Identical outcomes and extents on 300 random stack programs; full suite 872 tests, 17 skipped. Next: heap views (S4d.2c), then links, atomics, and the rest (S4d.2d).

## Self-hosting step S4d.2c: the facts engine models heap views and calls (ADR-138) — 2026-10-03

- Borrowed and allocated views, checked accesses, rebase windows, foreign calls (carrier decoded in XAX), view-passing direct and group calls, and view returns are modelled. All 20 corpus graphs are verified by the XAX engine with identical pointer extents, and `verify_store` is 20–30% faster on the view-heavy stores. Full suite: 872 tests, 17 skipped. Remaining for S4d.2d: links and records, atomics, raw loads, stack resource contracts, lend entries, indirect calls, function addresses, and target operations.

## Self-hosting step S4d.2d: S4 complete (ADR-139) — 2026-10-03

- The XAX facts engine now decides atomics, raw loads, stack resource contracts, function addresses, indirect calls, lend entries, and target operations, the last through a target-package decoder in XAX (`xax_selfhost_target.py`). It also decides records and links: layouts, field addresses, padding-aware windows, the link operations, link stores and loads, link targets, dependents, and declarations.
- Across the whole suite, every graph the bootstrap accepts is now decided by XAX. Python only produces diagnostics on a decline or a rejection. The exceptions are the helper programs' own seed graphs, parsed while those programs are built or loaded.
- Larger views let the engine handle the biggest self-hosting graphs (98K values, 1,594 blocks).
- `verify_store` is 10–25% faster with the XAX path on the measured stores. Full suite: 875 tests, 17 skipped. Next: S5, the RISC-V backend in XAX.

## Self-hosting step S5a: RISC-V code generation in XAX (ADR-140) — 2026-10-03

- `compile_riscv64` now generates code with an XAX program (`xax_selfhost_riscv64_backend.py`): liveness, linear scan, frame layout, lowering, the `li` planner, and jump fixups. Images are byte-identical to the bootstrap's, which stays as the fallback and the source of diagnostics.
- Compiling is 2.3× faster on a 300-value loop. Full suite: 881 tests, 17 skipped. Next: S5b, which feeds the program from the XAX decoders instead of the Python marshal.

## Self-hosting step S5b: S5 complete, store objects to RISC-V image in XAX (ADR-141) — 2026-10-03

- The XAX backend program now reads the store's objects and the XAX graph decoder's streams itself. It decides the target's operation sets, function interfaces, value widths, constants, the call closure (skipping erased proof callees), and the function order. Python only copies objects and assembles the image object.
- Images are byte-identical to the bootstrap's. `compile_riscv64` is 6.4× faster on a 300-value loop. Full suite: 882 tests, 17 skipped. Next: S6.

## Self-hosting step S6a: linear flow in XAX (ADR-142) — 2026-10-03

- The facts engine proves resource and effect linearity (`_verify_linear_flow`), and the verifier skips the Python pass when it does. 6,518 suite graphs are proven, none of them wrongly. Full suite: 883 tests, 17 skipped. Next: S6b, object-level verification.

## Self-hosting step S6b.1: types and constants decided by XAX (ADR-143) — 2026-10-03

- `verify_store` asks the typing program for a verdict on every type and constant, and skips the Python decoders for each one proven. On 600 random and mutated objects, XAX proved every valid one and no invalid one. Full suite: 884 tests, 17 skipped. Next: S6b.2 (functions, groups, contracts, reference lists, build objects, targets).

## Self-hosting step S6b.2: functions, lists, contracts, and rootedness decided by XAX (ADR-144) — 2026-10-03

- A native XAX store verifier decides ordinary functions (interface and graph contract), module and root reference lists, call contracts, and store rootedness and acyclicity. Every ordinary corpus function is proven. Full suite: 885 tests, 17 skipped.
- The E DSL now binds a value already held by another variable as a fresh copy. This avoids an x86-64 register-resident lowering issue (aliased variables across control flow) whose root cause is open.

## B1–B4 for the XAX RISC-V backend: a self-compilation fixed point (ADR-145) — 2026-10-03

- A RISC-V views profile (checked heap-view loads and stores, 64-bit pointers, borrowed-view returns elided, `auipc`/`jalr` far jumps) lets the XAX RISC-V backend compile its own store. The XAX backend's image is identical to the bootstrap generator's (1,959,876 bytes).
- That image, run in the RV64 emulator, compiles a corpus exactly as the native backend does. Compiling the backend store with it reproduces it byte for byte (gen3 == gen2, at most 22 billion emulated instructions).

## Self-hosting step S6b.3: recursion groups, group member functions, and targets decided by XAX (ADR-146) — 2026-10-03

- The store verifier decides recursion groups, with the bootstrap's full member key for the canonical order. It also decides group member functions, and identity carriers plus general and concurrency targets. Every corpus function (including jsonmin's group member), group, list, contract, and target is proven. Full suite: 890 tests, 18 skipped. Next: S6b.4 (build and package objects, the remaining target profiles, and the per-graph glue).

## Multi-language performance rule; x86-64 within 1.05× of the fastest (ADR-147, ADR-148) — 2026-10-03

- Performance requirements were updated: each CPU/native runtime comparison now includes C/C++ and Rust, and XAX must be within 1.05× of the fastest valid implementation. The first run measured XAX at 1.57× (`filestat`), 1.18× (`chains`), and 1.21× (`jsonmin`) the fastest: unmet.
- After ADR-148 (range-proven checks, a lowering view with leaf inlining and layout, call-aware allocation), the interleaved re-run measures 1.017×, 1.000× (XAX fastest), and 1.029×: MEASURED, primary target met on all three. Linux x86-64 row: R4 for that scope. Full suite: 1,059 passed, 4 skipped. Next: S6b.4.

## Self-hosting step S6b.4: packages, build objects, all target profiles, and per-graph glue decided by XAX (ADR-149) — 2026-10-03

- The store verifier decides packages; profiles, trust policies, signatures, and optimization policies; then requests, snapshots, and provenance in later passes (closures, grants, signature coverage); platform, accelerator, and board targets; and every streamed graph's type references, reference use, and trap payloads. Randomized and mutated stores agree with the bootstrap exactly, and no verdict holds for an object the bootstrap rejects. Full suite: 1,064 passed, 4 skipped. Next: the remaining S6 work (the bootstrap's graph checks that are not yet XAX passes, then B1–B4 for the real compiler on one target).

## Self-hosting step S6c: all committed stores decided by XAX; B1–B4 for the store verifier on RV64 (ADR-150) — 2026-10-04

- The graph decoder and the verifier windows now hold the largest helper stores, so every object of all 12 committed stores, the verifier's own included, is decided by XAX. The XAX RISC-V backend reclaims each function's arena and compiles the verifier and the typing program like the bootstrap. The verifier's RISC-V image verifies every committed store with the native verdicts (B2/B3). The backend's RISC-V image recompiles the verifier byte for byte (B4). The backend's own fixed point was re-run and still holds. S6 is EXECUTED for RV64. Next: aggregates in the RISC-V views profile (BLAKE3), and moving the Python driver's lowering structures and the x86-64 backend into XAX.

## Documentation sync (2026-10-04)

- Replacement levels in `README.md`, this file, `XAX_HANDOFF.md`, the roadmap, and the architecture document are now generated from `XAX_REPLACEMENT_MATRIX.json` by `compiler/src/xax_status_docs.py`; `tests/test_status_docs.py` fails while any copy is stale. Stale current-status text was corrected (README: "no platform is above R2", the 1.4–1.8× `clang` figure, and Python 3.12; the architecture snapshot after ADR-129; roadmap U1.8). Superseded benchmark sections (§15.1, §15.12) now point at §15.14.
- Markdown structure: one H1 per document (architecture, specification, bootstrap README), fence languages in `docs/10_TARGET_MODEL.md` and `docs/11_ABI_PLATFORM.md`, and a store table in `compiler/bootstrap/README.md`.
- `compiler/pyproject.toml` gains a `test` extra (`pytest`, `pytest-xdist`, `unicorn`, `tiktoken`).
- Full suite on Linux x86-64 (Python 3.11.15, the `XAX_HANDOFF.md` environment, Android root from `make_android_root.py`): **1,070 passed, 5 skipped** (two Windows-host PE runs, the physical arm64 device, and the two opt-in `XAX_FIXED_POINT=1` emulation runs).

## S6d: aggregates and stack arguments in the RISC-V views profile (2026-10-04, ADR-151)

- Both RISC-V generators lower `aggregate.make`/`aggregate.get` for tuples and arrays of up to 255 scalar fields, LP64 indirect results (a hidden result-area address in a0, field k at offset 8k), and stack arguments past a7. Frames without such calls are unchanged, so every earlier image is byte-identical. The shared, instruction-set-neutral analysis moved to `compiler/src/xax_views_lowering.py`.
- BLAKE3 (`xax_blake3_hash.xax`) compiles through both generators to one 18,844-byte RV64 image. Emulated, it matches the official vectors and the reference across chunk and tree boundaries, and gives the production digest of every committed store under 1 MiB. gen2 (the backend's own RISC-V image) compiles the BLAKE3 store to gen1's image (a default test, 3 s).
- Evidence regenerated: `selfhost_closure_evidence.json` (B1 now includes BLAKE3; B4 verifier image unchanged, 4,559,444 bytes) and `selfhost_fixed_point_evidence.json` (backend store 902,679 bytes; gen2 = reference = gen3, 2,810,964 bytes).

## S7a: the x86-64 backend as XAX; B1–B4 natively on x86-64 (2026-10-04, ADR-152)

- `x86_64_views_target()` (`x86_64-linux-views-v1`) and its bootstrap reference `compiler/src/xax_x86_64_views.py` (Win64 registers, stack arguments above the shadow area, aggregate results through a hidden area, `ud2` traps). It matches the reference executor on 320 random calls and executes aggregates of 3–255 fields.
- The XAX backends now share `compiler/src/xax_selfhost_views_backend.py` (front end, liveness, linear scan, edge copies, driver, native runner); the RISC-V store is byte-identical after the split. `compiler/src/xax_selfhost_x86_64_backend.py` adds the x86-64 hooks and lowering (store `compiler/bootstrap/xax_x86_64_backend.xax`, 974,862 bytes).
- B1 on all nine helper programs, itself included; the native verifier image agrees with the bootstrap verifier on all 13 committed stores; gen2 reproduces itself natively in 0.95 s (`benchmarks/selfhost_x86_64_evidence.json`).
- Production: every native helper is lowered by the XAX x86-64 backend (`host_image`); the optimizing `compile_native` lowers no XAX helper. MEASURED cost: 1.08–1.32× the optimizing images' run time; warm self-hosting suites 1.14×, cold 0.67×.
- `blake3.py` now retries the native hasher when a module on its path is still importing (it previously gave up for the process). Full suite: **1,087 passed, 5 skipped** (the same host-bound five).


## Documentation sync: generated Targets table and R0–R6 summary (2026-10-04)

- `README.md` explains the replacement levels R0–R6 and the evidence labels, and its Targets table is now generated from `XAX_REPLACEMENT_MATRIX.json` (a new `<!-- xax-status:targets -->` block in `compiler/src/xax_status_docs.py`). Every matrix row carries a `name` and `summary`; the validator rejects a row without them. Platforms that have not started stay visible at level `NONE` (shown as "—"): Apple, .NET, RTOS/MCU, and a new `bsd-unix` row.
- Roadmap: the U1 progress paragraph and levels block had drifted into M1 and are back under U1; the U1.3 row no longer states the Linux rows' old R2 levels as current.
- README test command fixed (`PYTHONPATH=src:.:..`; `compiler.benchmarks` imports need the repository root) and the complete Ubuntu host environment written out.
- Full suite on Linux x86-64 (Python 3.11.15, that environment): **1,089 passed, 5 skipped** (two Windows-host PE runs, the physical arm64 device, and the two opt-in `XAX_FIXED_POINT=1` runs). A statically linked `busybox` fails the three OI-24 sandbox tests; the dynamic build is required.

## Android counter: verified descriptor ownership, durable writes, Java + NDK twin (2026-10-04, ADR-153)

- `xax_platform.posix_descriptor_api()`: a linear `descriptor` resource consumed only by the owning `close`, plus `fdatasync`. The counter's JNI callbacks take the token with the descriptor, so a leak (`XAX.RESOURCE.DROP`) or double close (`XAX.RESOURCE.DUPLICATE`) is rejected; a click syncs its write before closing. The rebuilt APK passes Google's tools and ART's verifier and runs the same sequence under bionic (`android_counter_evidence.json`).
- `bench_android_counter_twin.py` and `benchmarks/android_counter_twin/`: a same-behavior Java + NDK twin. Sizes MEASURED: APK 0.715×, native library 0.561×, DEX 1.188× (`android_counter_twin_evidence.json`). `--device` measures cold start and PSS; it counts as evidence only on arm64 hardware.
- `validate_counter_apk.sh` polls the UI with a timeout; `android_counter_app.py --device` records the target and whether it is hardware.
- Android row: still R2. The device run of the stateful app is still outstanding. *(Superseded: R3 on an emulator, see the ADR-155 section below.)*
- Full suite: **1,094 passed, 5 skipped** (the same host-bound five).

## AArch64 register path: heap views and heap loads/stores (2026-10-04, ADR-154)

- General AArch64 functions with null-checked heap views and full-width heap loads/stores now stay on the register path. A 40-program heap corpus matches its mirror under bionic (160 results); the ADR-110 corpus is unchanged.
- The counter's callbacks shrink from 224/324 to 128/168 bytes (clang twin 96/132); APK 20,393 bytes, 0.706× the Java + NDK twin. No other committed artifact changes.
- Full suite: **1,096 passed, 5 skipped** (the counter APK pin was the only failure before regenerating it).
- Emulator: the API 30 x86_64 image runs arm64 code through ARM translation, but without KVM an arm64 app misses Android 11's fixed 10-second process-attach deadline, so the counter did not launch there (`compiler/integration/android/README.md`). The device run is still outstanding. *(Superseded: it passed on API 32, see the ADR-155 section below.)*

## Android R3: the counter app on an x86_64 emulator with ARM translation (2026-10-04, ADR-155)

- The committed counter APK passed `validate_counter_apk.sh` on an Android 12L (API 32) `google_apis` x86_64 emulator, its arm64 library run through `libndk_translation`: 0 → 1 → 2 → 3, restore 3 after `force-stop`, 4, state file 4 (`android_counter_evidence.json` `device`, `hardware: false`).
- Android row: `practical_application` EXECUTED, level R3. Correctness evidence only; arm64 hardware is still wanted, and start-up and memory against the twin need it.
- Full suite: **1,096 passed, 5 skipped**.
- The host has no KVM: the run needed `ro.hw_timeout_multiplier=20` (Android 12+), a JDWP connection on `system_server`, and hidden error dialogs (`compiler/integration/android/README.md`). The oracle now reads the state file correctly on non-debuggable builds and can retry a lost tap.

## Android twin harness checked on the emulator (2026-10-04, ADR-153)

- `bench_android_counter_twin.py --device` ran end to end on the API 32 emulator (`XAX_TWIN_RUNS=4`, `XAX_TWIN_WARMUP=1`): both apps installed, launched, and passed the click check, and every launch was tracked. Recorded with `hardware: false`; the timings and PSS there are not evidence. The run found and fixed four harness problems (dumpsys's 10 s limit, untracked launches, install races, lost taps).
- Size comparison recorded in `XAX_BENCHMARKS.md` §15.15.
- Platform contracts: `validate_platform_contracts.sh` (the `XAX_ANDROID_RUNTIME=1` test) passed on the same emulator: the XAX library's own `open/write/read/close`, `pthread_create/join`, and loopback socket calls printed `XAX_PLATFORM_RUNTIME_OK file=1 thread=1 socket=1` under the Android 12L kernel, arm64 code translated (`android_platform_runtime_probe_evidence.json`, `hardware: false`). The Android oracle scripts were not executable in git, so that test could not have passed anywhere before; they are now.
