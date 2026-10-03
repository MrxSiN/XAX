# XAX Architectural Decisions

This file records merged v0.1 decisions. Each decision is normative unless superseded by a versioned architectural revision. Evidence-dependent choices remain in `XAX_OPEN_ISSUES.md`.

## ADR-001 — The language is XAX

| Field | Record |
|---|---|
| Decision | The language and architecture are named **XAX**. “XAX Zero” is not a language name or conformance label. |
| Rationale | One canonical identity avoids specification and package lineage ambiguity. |
| Alternatives rejected | Parallel “XAX”/“XAX Zero” naming; stage-specific language names. |
| Runtime cost expectation | None. |
| AI/token expectation | Reduces naming ambiguity and repair/query overhead. |
| Falsification condition | Only an explicit future branding/versioning decision may replace the name; implementation evidence cannot silently create a second language identity. |

## ADR-002 — Meaning is source

| Field | Record |
|---|---|
| Decision | Canonical semantic state is authoritative XAX source. Human-readable forms are non-authoritative projections. |
| Rationale | Eliminates parsing/source-preservation constraints, makes exact semantics machine-addressable, and enables local semantic mutation. |
| Alternatives rejected | Human textual syntax as authoritative source; editable debug dump; AST reconstructed from text. |
| Runtime cost expectation | None; representation is compile/tooling state. |
| AI/token expectation | Expected to reduce regeneration and ambiguity by transmitting semantic neighborhoods instead of source files. |
| Falsification condition | Reconsider if semantic-first editing consistently costs more tokens/repairs than a textual authoritative representation across controlled benchmarks without delivering compensating correctness/locality benefits. |

## ADR-003 — Reconciliation precedence

| Field | Record |
|---|---|
| Decision | Conflicts are resolved by: semantic correctness → deterministic machine interpretation → AI token/reasoning efficiency → runtime performance/footprint → universal extensibility → locality/incrementality → implementation simplicity → human convenience. |
| Rationale | The merge prompt explicitly requires this ordering and it resolves the earlier tension between the founding priority table and later deterministic serialization/conformance requirements. |
| Alternatives rejected | Retaining every earlier priority order independently; letting implementation convenience decide contradictions. |
| Runtime cost expectation | May reject faster but semantically or deterministically weaker designs. |
| AI/token expectation | Deterministic interpretation may consume some encoding bytes but should lower ambiguity/repair cost. |
| Falsification condition | Only a future architecture revision may change the ordering after evidence demonstrates a superior priority model without weakening exact semantics. |

## ADR-004 — One semantic language

| Field | Record |
|---|---|
| Decision | Targets, ABI descriptions, build/package logic, compile-time computation, and metaprogramming use XAX semantic data and XAX computation; no permanent second DSL is required. |
| Rationale | Avoids duplicated semantics and enables self-hosting/toolchain closure. |
| Alternatives rejected | Permanent macro/template language; target DSL; build DSL; package-manifest language as semantic authority. |
| Runtime cost expectation | None inherently; compile-time implementations may specialize away abstractions. |
| AI/token expectation | One semantic vocabulary reduces cross-language translation/context. |
| Falsification condition | Reconsider only if an essential domain cannot be expressed adequately in XAX without materially greater total complexity than a second language and the same guarantees cannot be preserved. |

## ADR-005 — Block-parameter SSA with explicit dependency classes

| Field | Record |
|---|---|
| Decision | Core functions use block-parameter SSA with explicit data, control, effect, resource, and target-dependency relations. |
| Rationale | Preserves optimizer-relevant information with less structural complexity than a universal sea-of-nodes model. |
| Alternatives rejected | Mutable-variable core; implicit phi reconstruction; serialization-order execution; full sea-of-nodes as mandatory representation. |
| Runtime cost expectation | SSA/dependency objects are compile-time semantics and normally erase. |
| AI/token expectation | Local graph relations should reduce implicit reasoning and repair ambiguity. |
| Falsification condition | Reconsider if representative compiler implementation shows this model materially blocks optimization, target modeling, or local AI edits compared with a demonstrably simpler/effective graph model. |

## ADR-006 — Recursive SCC carrier

| Field | Record |
|---|---|
| Decision | Non-recursive functions must be standalone content-addressed `function` objects; recursive SCCs, including self-recursive singletons, use a content-addressed `recursion_group` holding exactly one SCC in canonical member order (OI-03, 2026-10-01). Serialization kind ID 8 is reserved for `recursion_group`. |
| Rationale | Resolves Stage 02 recursive identity requirements with Stage 08 acyclic CID computation. |
| Alternatives rejected | Cyclic hashes; name-based recursive identity; forcing every function into a recursion group. |
| Runtime cost expectation | None; serialization/identity structure only. |
| AI/token expectation | Local group indices are compact; unrelated non-recursive functions avoid group overhead. |
| Falsification condition | Reconsider encoding if a different acyclic scheme measurably improves canonical size/locality without weakening persistent identity or deterministic recursion semantics. |

## ADR-007 — Exact bit types; signedness belongs to operations

| Field | Record |
|---|---|
| Decision | `bits<N>` is the general integer bit domain. Signed/unsigned interpretation is attached to operations where relevant. |
| Rationale | Avoids duplicate representation identity and supports arbitrary widths/hardware fields. |
| Alternatives rejected | Separate `iN`/`uN` as fundamental stored-value types; fixed common widths only; implicit promotions. |
| Runtime cost expectation | None; type semantics only. |
| AI/token expectation | Fewer conversion/type variants, but requires operation-level signedness precision. |
| Falsification condition | Reconsider if controlled AI-generation benchmarks show materially higher error/repair rates than a type-signedness design after protocol/tokenizer optimization. |

## ADR-008 — Semantic types are separate from target layout

| Field | Record |
|---|---|
| Decision | Ordinary types do not contain target ABI layout. Layout is target/context qualified; physical representation that is itself semantic uses explicit-layout types. |
| Rationale | Preserves target-independent program meaning and cross-target reuse. |
| Alternatives rejected | C-like layout by default; host-layout assumptions; representation compatibility implying type equality. |
| Runtime cost expectation | Static layout queries normally have zero runtime cost. Explicit packing/unpacking costs only when semantically requested. |
| AI/token expectation | Prevents repeated target assumptions in ordinary semantic graphs; explicit layout contracts increase local precision. |
| Falsification condition | Reconsider if target/ABI programming becomes pervasively ambiguous or unimplementable without embedding layout into ordinary semantic type identity. |

## ADR-009 — Function value type is not the full call contract

| Field | Record |
|---|---|
| Decision | `fn<input...,output...>` identifies value-level signature; effect/resource/capability/control behavior is carried by an explicit `CallContract` for callable references. Indirect calls require a bounded contract. |
| Rationale | Reconciles minimal Stage 03 function types with Stage 05's requirement that indirect effects cannot be unspecified. |
| Alternatives rejected | Unbounded “may do anything” indirect calls by default; making every function type encode all ABI/platform facts. |
| Runtime cost expectation | Contract data is compile-time/verification metadata and normally erases. |
| AI/token expectation | Slightly larger callable metadata but fewer hidden effects and invalid indirect calls. |
| Falsification condition | Reconsider representation placement if a different contract carrier materially lowers graph/token cost while preserving complete bounded call semantics. |

## ADR-010 — Effect frontiers are not authority capabilities

| Field | Record |
|---|---|
| Decision | `effect<D>` values represent ordering frontiers. Authority to perform operations is represented separately as explicit capability/resource semantics. |
| Rationale | Stage 03 wording could conflate effect dependencies and capabilities; later stages require both ordering and authority checks. |
| Alternatives rejected | Treating possession of an effect token as authority; implicit ambient capabilities. |
| Runtime cost expectation | Effect frontiers normally erase; capability runtime representation exists only if explicitly required. |
| AI/token expectation | Clear separation reduces semantic ambiguity at call/build/platform boundaries. |
| Falsification condition | None expected at semantic level; representation may change if equivalent separation is preserved more compactly. |

## ADR-011 — Explicit proof obligations, checked behavior, and raw waivers

| Field | Record |
|---|---|
| Decision | Ordinary memory/unsafe-sensitive operations require proof. Failure to prove requires an explicit checked semantic operation, stronger evidence, or an operation-local raw waiver naming waived obligations. |
| Rationale | Provides machine-visible safety without a global safe/unsafe language split or hidden checks. |
| Alternatives rejected | Lexical `unsafe` authority as the primary semantic unit; silent unchecked behavior; hidden bounds checks. |
| Runtime cost expectation | Proven obligations cost zero at runtime; checked operations pay only explicitly requested checks. |
| AI/token expectation | Structured obligations/waivers support precise diagnostics and repair. |
| Falsification condition | Reconsider kernel checked-operation vocabulary if it becomes impractically large or inefficient, but retain explicitness of proof/check/waiver choice. |

## ADR-012 — Linear resources with explicit release

| Field | Record |
|---|---|
| Decision | Resource state is represented by `resource<K,state>` values; acquisition, transfer, state transition, split/join where permitted, release, and discard are explicit. No implicit RAII destructor exists. |
| Rationale | Generalizes ownership beyond memory and keeps all lifecycle behavior visible. |
| Alternatives rejected | Scope-driven destruction as language semantics; silent drop; unrestricted resource copying. |
| Runtime cost expectation | Pure ownership/state transitions may erase; actual release/acquire costs are explicit. |
| AI/token expectation | More explicit nodes but lower ambiguity and machine-checkable lifecycle repair. |
| Falsification condition | Reconsider encoding if explicit state transitions impose disproportionate token/graph overhead and an equally exact machine-visible alternative performs better. |

## ADR-013 — Effects form a partial order and may be canonically compressed

| Field | Record |
|---|---|
| Decision | Observable ordering is represented by explicit effect-domain dependencies. Persistent storage may compress/reconstruct chains only when the exact same dependency relation is deterministically recoverable. |
| Rationale | Preserves semantics while allowing token/storage optimization. |
| Alternatives rejected | Serialization order as execution order; one global effect chain; heuristic reconstruction. |
| Runtime cost expectation | Effect frontiers are compile-time semantics; runtime ordering exists only when the operation itself requires it. |
| AI/token expectation | Partitioning enables smaller relevant neighborhoods; compression may reduce transport cost. |
| Falsification condition | Choose a different canonical partition/edge encoding if measurements show better token/verification tradeoffs without loss of exact ordering. |

## ADR-014 — Errors are values; exceptions are boundary semantics

| Field | Record |
|---|---|
| Decision | Recoverable errors are ordinary typed values. Core calls do not throw. Foreign unwinding is represented only through explicit ABI/platform interoperability control. |
| Rationale | Avoids hidden control edges and mandatory exception runtime. |
| Alternatives rejected | Mandatory language exceptions; implicit stack unwinding across ordinary XAX frames. |
| Runtime cost expectation | No exception machinery unless explicitly selected. Sum/error paths optimize away when proven unreachable. |
| AI/token expectation | Explicit control/result structure is locally queryable and deterministic. |
| Falsification condition | Reconsider ergonomics/encoding, not hidden-edge prohibition, if value-based error graphs impose excessive graph/token cost. |

## ADR-015 — Exact atomics; data races are not optimizer permission

| Field | Record |
|---|---|
| Decision | Atomics carry explicit order/scope and target legality. Non-atomic data races are invalid unless an explicit raw/target concurrent semantic operation defines behavior. |
| Rationale | Avoids C/C++-style undefined-race compiler freedom and preserves exact concurrency semantics. |
| Alternatives rejected | Sequential consistency for all atomics; `volatile` synchronization; silent lock emulation; arbitrary UB from data races. |
| Runtime cost expectation | Exactly the selected atomic/synchronization semantics; no hidden runtime helper. |
| AI/token expectation | Explicit order/scope increases mutation fields but avoids implicit memory-model inference. |
| Falsification condition | Reconsider portable order/scope vocabulary if real target packages cannot map it without systematic semantic loss. |

## ADR-016 — Real-time profiles reject unknowns rather than insert runtimes

| Field | Record |
|---|---|
| Decision | Real-time policies are post-specialization/post-lowering rejection predicates over blocking, bounds, progress, allocation, runtime assistance, scheduler/kernel interaction, and timing evidence. |
| Rationale | A profile must constrain actual selected lowering, not source-level intent. |
| Alternatives rejected | Real-time as optimizer hint; inferring WCET from generic cost estimates; silently replacing forbidden operations. |
| Runtime cost expectation | Profiles add no runtime mechanism; they reject nonconforming builds. |
| AI/token expectation | Queryable boundedness facts provide direct machine evidence. |
| Falsification condition | Reconsider proof representation if profile verification is too costly, but not the guarantee/estimate separation. |

## ADR-017 — Compile-time execution is bounded, deterministic XAX

| Field | Record |
|---|---|
| Decision | Compile-time computation uses XAX semantics, explicit capabilities/inputs, deterministic successful evaluation, finite budgets, and a verifier barrier before generated semantics commit. |
| Rationale | Replaces macros/templates/build plugins with one sandboxable semantic mechanism. |
| Alternatives rejected | Text macros; preprocessor; unbounded compile-time execution; ambient host filesystem/network access; text generation and reparsing. |
| Runtime cost expectation | Compile-time-only machinery erases unless runtime representation is requested. |
| AI/token expectation | One language and direct semantic construction avoid syntax-generation/reparse overhead. |
| Falsification condition | Reconsider budget units/introspection granularity if implementation evidence shows better bounded deterministic alternatives. |

**Prototype evidence (2026-09-30).** M9 executes ordinary verified XAX arithmetic/control/calls/recursion plus typed meta operations under explicit capabilities and step/depth/memory/object/node ceilings. Identical semantic inputs reproduce canonical constructed object identities; successful results memoize by evaluator/verifier/target/input identity, while exhausted or invalid attempts do not cache or commit. Materialization passes through the ordinary whole-store verifier, and the generated constant function contains no meta operations. This validates the decision for the declared slice but does not settle fuel units, authority granularity, or specialization object boundaries.

## ADR-018 — Canonical `.xax` v0.1 uses BLAKE3-256 suite 1

| Field | Record |
|---|---|
| Decision | Container major 1 uses hash suite ID 1 = BLAKE3-256 with 32-byte CIDs. Future hash agility is versioned; suite ID 1 never changes meaning. |
| Rationale | Stage 08 fixes an initial canonical format while Stages 12/14 leave migration/agility open. This decision removes the conflict by fixing v0.1 and deferring only future evolution. |
| Alternatives rejected | Leaving the v0.1 hash unspecified; implementation-selected hash algorithms under one suite ID; hash substitution on read. |
| Runtime cost expectation | Build/store hashing cost only; no program runtime requirement. |
| AI/token expectation | Full hashes are normally hidden behind local handles, so CID width should not dominate AI context. |
| Falsification condition | Security/performance evidence may justify a new hash suite/version and migration procedure, never silent reassignment of suite 1. |

## ADR-019 — Canonical encoding is strict; heuristic repair is forbidden

| Field | Record |
|---|---|
| Decision | Noncanonical, corrupt, ambiguous, overlong, hash-mismatched, or unsupported canonical input is rejected rather than normalized/guessed. |
| Rationale | Deterministic identity requires one encoding and deterministic failure. |
| Alternatives rejected | Permissive readers that silently normalize canonical input; damage guessing. |
| Runtime cost expectation | Tooling validation cost only. |
| AI/token expectation | Deterministic failures enable exact machine diagnostics and repair. |
| Falsification condition | None for canonical input; separate noncanonical import tools may exist outside the canonical format. |

## ADR-020 — Fragmentation is an identity/objectization choice, not runtime meaning

| Field | Record |
|---|---|
| Decision | Graph-fragment boundaries may affect Merkle object identities but not observable program semantics. Conformance byte equality is for the same schema/objectization; canonical normalization of fragmentation remains evidence-dependent. |
| Rationale | Reconciles local-mutation granularity experiments with the one-encoding-per-object rule. |
| Alternatives rejected | Claiming all observationally equivalent graphs must have one root today; making fragment boundaries observable runtime semantics. |
| Runtime cost expectation | None. Object granularity affects compiler/storage performance. |
| AI/token expectation | Smaller fragments may improve edit locality but increase object/hash overhead. |
| Falsification condition | Fix a stricter canonical fragmentation policy if cross-tool identity interoperability or performance requires it. |

## ADR-021 — AI mutation is transactional and stale-root checked

| Field | Record |
|---|---|
| Decision | Every canonical mutation uses an expected base root, private candidate state, explicit verification, and atomic commit/reject. Semantic rebase is validated, never blind replay. Workspace-local generation aliases may abbreviate the expected root only as non-semantic tooling; final atomic comparison validates both the resolved root and alias freshness scope. |
| Rationale | Prevents partial mutation and detects concurrent-agent conflicts at semantic entities/dependencies. |
| Alternatives rejected | Whole-artifact regeneration as default; line-based diff/merge; last-writer-wins; blind replay. |
| Runtime cost expectation | Development/tooling only. |
| AI/token expectation | Small semantic mutation sets and local diagnostics should reduce retransmission and repair. |
| Falsification condition | Reconsider transaction/rebase granularity if controlled multi-agent workloads show whole-root serialization is simpler and not materially worse; atomicity/stale detection remain required. |

## ADR-022 — Target knowledge is package semantics, not compiler hardcoding

| Field | Record |
|---|---|
| Decision | Machine value types, memory spaces, registers, instructions, semantic contracts, encodings, legalizations, ABI primitives, relocations, formats, scheduling, and costs live in target/platform semantic packages. |
| Rationale | Supports unknown future hardware without changing core language meaning. |
| Alternatives rejected | Fixed built-in CPU list; permanent backend language; host-machine assumptions. |
| Runtime cost expectation | None inherent; selected target operations define actual cost. |
| AI/token expectation | Target facts are queryable local semantic data instead of hidden compiler lore. |
| Falsification condition | Reconsider package schema if a second materially different target requires fundamental language changes rather than target-package extensions. |

## ADR-023 — ABI/platform contracts are explicit and freestanding-first

| Field | Record |
|---|---|
| Decision | ABI classification, foreign contracts, syscalls, platform services, and dynamic loading are explicit target/platform semantics. No C/POSIX/libc/OS ABI is foundational. |
| Rationale | Preserves bare-metal validity and avoids fabricated foreign guarantees. |
| Alternatives rejected | Universal C ABI; mandatory libc; implicit dynamic linking; pure-looking foreign calls with hidden effects. |
| Runtime cost expectation | Only explicitly selected adapters/platform facilities are emitted. |
| AI/token expectation | Structured foreign contracts reduce implicit ecosystem assumptions. |
| Falsification condition | Reconsider ABI representation form if real ABIs cannot be expressed deterministically without a second DSL. |

## ADR-024 — Verifier authority and optimizer distrust are separated

| Field | Record |
|---|---|
| Decision | Canonical semantics and verifier form the trusted validity boundary. High-risk/search-generated optimizer transformations should be independently checked or translation-validated. |
| Rationale | Enables aggressive optimization without making the entire optimizer trusted. |
| Alternatives rejected | Trust every optimizer pass because it ran; treat validation failure as permission to weaken semantics. |
| Runtime cost expectation | Compile-time verification overhead, selectable by build policy where safe; no runtime tax. |
| AI/token expectation | Machine-readable proof/validation failures support local optimizer repair. |
| Falsification condition | Adjust proof granularity if checking cost is excessive, while retaining an explicit correctness mechanism for every transformation. |

## ADR-025 — Profile data and cost models are non-semantic

| Field | Record |
|---|---|
| Decision | Measured profiles and target cost estimates may guide profitability but cannot legalize transformations or alter canonical program meaning. |
| Rationale | Keeps empirical data/environment changes from silently changing semantics. |
| Alternatives rejected | Treating profile likelihood or cost estimate as semantic truth. |
| Runtime cost expectation | Can improve generated code; profiling instrumentation is explicit when used. |
| AI/token expectation | Cost queries provide machine data instead of source-based guessing. |
| Falsification condition | Recalibrate/replace cost models if ranking accuracy is poor; semantic boundary remains. |

## ADR-026 — Packages/builds are content-addressed XAX semantics

| Field | Record |
|---|---|
| Decision | Package roots, snapshots, build descriptions, resolver inputs, feature/configuration values, build capabilities, and provenance are semantic XAX objects; exact roots govern integrity. |
| Rationale | Enables deterministic resolution, reproducibility, sandboxing, and no second manifest/build language. |
| Alternatives rejected | Authoritative TOML/YAML/JSON manifests; implicit latest resolution; undeclared host/network input. |
| Runtime cost expectation | Build-system only; does not force runtime dependencies into produced programs. |
| AI/token expectation | Exact roots and typed config reduce ambiguous package/build edits. |
| Falsification condition | Restrict resolver/metadata expressiveness if measured complexity/token cost is excessive; content identity and explicit-input rules remain. |

## ADR-027 — Self-hosting claims are evidence-gated

| Field | Record |
|---|---|
| Decision | XAX distinguishes seed viability, first XAX compiler, recursive compilation, semantic self-equivalence, deterministic fixed point, toolchain closure, and bootstrap independence (B0–B6). |
| Rationale | “Self-hosting” alone does not establish reproducibility, closure, or trust. |
| Alternatives rejected | Declaring closure after one self-build; treating seed implementation as permanent architecture; external assembler/linker as mandatory final path. |
| Runtime cost expectation | None to user programs; bootstrap/build cost is measured separately. |
| AI/token expectation | Canonical repository/handoff state permits continuation without chat-history context. |
| Falsification condition | Milestone evidence may refine comparison projections or seed subset, but claims cannot be weakened to preserve status. |

## ADR-028 — Conformance is layered and negative tests are mandatory

| Field | Record |
|---|---|
| Decision | Conformance levels C0–C4 and named semantic profiles define claim scope; suites test both accepted and rejected artifacts. |
| Rationale | Compilation success alone cannot detect unsound verifier acceptance or noncanonical storage. |
| Alternatives rejected | Unscoped “supports XAX” claims; positive-only tests; target-independent claims for target-specific compilers. |
| Runtime cost expectation | Test-time only. |
| AI/token expectation | Stable rule IDs and profiles make failures machine-actionable. |
| Falsification condition | Levels/profiles may be versioned if implementation evidence shows a better decomposition, but exact claim scope and negative testing remain required. |

## ADR-029 — Benchmark claims must be preregistered, fair, and fully attributed

| Field | Record |
|---|---|
| Decision | Runtime and AI-efficiency benchmark cases fix semantic contract, inputs, target set, build policies, baselines, metrics, oracle, procedure, exclusions, environment, and artifact identities before comparative execution. |
| Rationale | Prevents cherry-picking and converts founding objectives into falsifiable evidence. |
| Alternatives rejected | Simulated results; best-case-only publication; unoptimized strawman baselines; source-character count as AI metric; universal assembly-superiority claims. |
| Runtime cost expectation | None in deployed programs; measurement overhead is explicit. |
| AI/token expectation | Counts actual model tokens, repair turns, context, semantic entities, transaction size, and success. |
| Falsification condition | Architecture claims must be revised when preregistered measurements falsify them; benchmark definitions must not be changed post hoc to protect conclusions. |

## ADR-030 — Artifact mappings require retained emission provenance

| Field | Record |
|---|---|
| Decision | `map_semantic` / `map_artifact` expose derived, target-qualified artifact provenance only when the compiler retained exact emission attribution. Artifact byte ranges are half-open `[start,end)` and workspace artifact handles are generation-scoped. Erased or non-locally contributing semantics are reported unavailable rather than guessed from disassembly or adjacency. |
| Rationale | A reverse-engineered source map can silently misattribute prologues, edge copies, padding, fused instructions, or erased semantics. Emission-time provenance keeps artifact queries machine-verifiable without making mappings part of canonical source meaning. |
| Alternatives rejected | Treating disassembly heuristics as authoritative; assigning zero-code operations to nearby instructions; persistent artifact handles independent of root/target/compiler dependencies. |
| Runtime cost expectation | None in emitted programs. Provenance is compiler/workspace metadata and may be omitted when mapping queries are not requested. |
| AI/token expectation | Local byte ranges and contributor handles allow focused artifact inspection without exposing whole binaries or persistent semantic CIDs. |
| Falsification condition | The concrete provenance representation may change if a smaller target-neutral form provides equal exactness and lower compile/query cost; exactness and unavailable classification remain required. |

## ADR-031 — Artifact provenance uses one target-neutral compiler-service interface

| Field | Record |
|---|---|
| Decision | Backends that can retain exact emission provenance expose the same non-semantic artifact interface: emitted artifact bytes, entry byte offset, target identity, and exact half-open `ArtifactSemanticRange` records for functions and directly attributable nodes. Workspace `artifact`, `map_semantic`, and `map_artifact` behavior is target-independent. |
| Rationale | x86-64 raw images, AArch64 raw images, and WebAssembly modules have materially different container/instruction layouts, but provenance consumers need one bounded query contract. Keeping the carrier target-neutral prevents backend structure from becoming a second source or query language. |
| Alternatives rejected | Keeping x86-specific `NativeSemanticRange`; reconstructing AArch64/WebAssembly ranges from disassembly/decoding after emission; target-specific workspace mapping APIs. |
| Runtime cost expectation | None in emitted programs. Provenance exists only in compiler-service memory/tooling and can be omitted when mapping queries are not requested by a production pipeline. |
| AI/token expectation | One stable mapping schema avoids target-specific prompt/context variants; actual token benefit remains unmeasured. |
| Falsification condition | Refine the interface if another artifact class cannot represent exact attributable ranges without semantic loss; do not weaken the no-guessing rule or make mapping metadata canonical XAX source. |


## ADR-032 — Artifact mappings use explicit dependency bindings

| Field | Record |
|---|---|
| Decision | Each reusable artifact-mapping record is tooling-only derived state bound to the canonical semantic root, target/configuration CID, explicit versioned compiler identity, explicit versioned lowering identity, emitted-artifact digest, and retained exact semantic ranges. A compact binding identity commits to that dependency tuple. Any dependency mismatch makes the mapping stale. |
| Rationale | Generation alone is insufficient attribution: identical bytes can arise from different roots/toolchains, and a compiler/lowering change can invalidate exact source attribution even when the artifact remains byte-identical. Explicit dependency binding makes reuse auditable without making provenance canonical XAX source. |
| Alternatives rejected | Key mappings only by artifact bytes; key only by workspace generation; derive toolchain identity from human version strings, source text, or disassembly; silently reuse mappings after a lowering change. |
| Runtime cost expectation | None in emitted programs. Hashing/comparison occurs only in compiler/workspace tooling. |
| AI/token expectation | A compact artifact binding ID lets mapping responses remain locally attributable without retransmitting every dependency on every page; token impact remains unmeasured. |
| Falsification condition | The concrete digest/record encoding may change if a smaller equally exact form is measured, but dependency completeness, explicit toolchain versioning, and stale-on-mismatch behavior remain required. |


## ADR-033 — Bootstrap query budgets use exact response bytes without token claims

| Field | Record |
|---|---|
| Decision | The bootstrap workspace accepts an optional per-query exact serialized response-byte budget. Paginated queries return the largest deterministic positive-progress prefix that fits and a continuation; if no positive-progress page fits, or a non-paginated response exceeds the budget, the query fails with `XAX.WORKSPACE.RESPONSE_BUDGET`. Only handles actually returned are published, and only returned response bytes are charged to query accounting. |
| Rationale | Entity-count bounds alone do not cap transport size because different semantic entities serialize to different byte sizes. An exact byte cap provides deterministic bounded service behavior now without pretending bytes predict model tokens. |
| Alternatives rejected | Treat entity count as a byte/token bound; silently expose handles from a larger internally computed page; return zero-entity continuations that make no progress; call byte counts token counts without tokenizer validation. |
| Runtime cost expectation | None in emitted programs. Budget fitting is compiler-service/tooling work only. |
| AI/token expectation | Prevents unexpectedly large bootstrap responses. No model-token efficiency claim follows until the proxy is measured against actual tokenizer/model behavior. |
| Falsification condition | Replace or augment the byte budget when model-token measurements show a better deterministic budgeting boundary; preserve positive progress, no hidden handle publication, and exact accounting of returned data. |


## ADR-034 — Operand/use replacement is preconditioned semantic relation mutation

| Field | Record |
|---|---|
| Decision | The first bootstrap relation mutation is a typed `ReplaceUse` request against one operand of a standalone-function node. It records the target node, operand index, expected old graph-local value reference, and replacement value reference. The old relation must match exactly before rebuild; mismatch is a stable relation conflict. The rebuilt candidate is then checked by the normal verifier before atomic publication. The Python carrier is tooling only and is not XAX source or a permanent transaction DSL. |
| Rationale | This adds executable relation-level conflict detection without broadening immediately into insert/delete/connect machinery or bypassing the existing verifier. Explicit old-relation preconditions detect concurrent semantic rewiring below whole-root granularity. |
| Alternatives rejected | Rebuild the whole function without a relation precondition; infer the changed operand from text; silently accept stale relation coordinates; special-case type checking inside the workspace instead of using the verifier. |
| Runtime cost expectation | None in emitted programs. The mutation exists only in compiler/workspace tooling. |
| AI/token expectation | A local target plus one operand index and two compact value references should be substantially smaller than function regeneration, but tokenizer/model efficiency is unmeasured. The measured bootstrap transaction is 24 bytes and is not a token claim. |
| Falsification condition | Replace the concrete bootstrap carrier if measured protocol/error rates favor another typed local form; exact relation preconditions, verifier-before-publication, atomicity, and machine conflict diagnostics remain required. |

## ADR-035 — Node deletion is containment-preconditioned and use-safe

| Field | Record |
|---|---|
| Decision | The first bootstrap deletion mutation is a typed `DeleteNode` request for one node in a standalone function. It records the target local node handle plus expected block/node containment coordinates. The current bootstrap permits only constants and wrapping arithmetic nodes. Commit rejects a containment mismatch as `XAX.WORKSPACE.CONTAINMENT_CONFLICT` and rejects any current operand, terminator value, or control-edge argument use of a produced value as `XAX.WORKSPACE.DELETE_USE_CONFLICT`. Surviving references to later nodes in the deleted block are renumbered deterministically, then the rebuilt candidate passes the ordinary verifier before atomic publication. The Python carrier is tooling only and is not XAX source or a permanent transaction DSL. |
| Rationale | This closes executable delete/use and containment conflict coverage with the smallest inspectable mutation. Exact containment prevents deleting a different node after local structural drift; explicit use rejection prevents dangling semantic relations; verifier reuse avoids a second semantic checker. |
| Alternatives rejected | Delete by textual position without a precondition; silently drop or redirect uses; reconstruct uses from disassembly/debug text; allow effectful/resource-bearing deletion before the effect/resource mutation contract is mature; bypass normal verification after renumbering. |
| Runtime cost expectation | None in emitted programs. Deletion and renumbering are compiler/workspace tooling only. |
| AI/token expectation | The measured bootstrap transaction is 17 bytes for the fixed smoke fixture. This is byte accounting only; no tokenizer/model-efficiency claim follows. |
| Falsification condition | Broaden or replace the concrete bootstrap carrier when insert/connect/disconnect and effect/resource semantics require a richer typed transaction form; exact containment/use preconditions, verifier-before-publication, atomicity, and stable conflict classes remain required. |

## ADR-036 — Proof query results use explicit local dependency bindings

| Field | Record |
|---|---|
| Decision | A bootstrap `proof` query may expose an ephemeral `P<n>.<generation>` read-dependency handle. Its private binding records the exact semantic subject, observed root, explicit verifier identity/version, origin generation, and subject-local coordinates needed to identify the verified fact. It is verifier-status evidence only, not a proof certificate or canonical XAX object. Subject-scoped dependencies may survive unrelated commits only while the exact content-addressed subject and verifier identity are preserved; root-scoped dependencies invalidate on any root change. Once invalidated by a dependency-changing commit, the old local handle is not revived by later state restoration; proof reads are therefore revalidated at final atomic publication as well as before candidate construction. |
| Rationale | A boolean `verified` result without dependency identity cannot participate safely in transactional read sets. Content-addressed subject preservation allows useful local reuse without making every unrelated root edit invalidate verifier evidence, while explicit invalidation prevents stale proof assumptions from collapsing into generic handle conflicts. |
| Alternatives rejected | Treat every proof result as a formal certificate; expose persistent CIDs to the AI merely to name proof state; invalidate every subject proof on any root change; silently accept stale proof reads as ordinary handles; revive old proof handles after ABA-like restoration. |
| Runtime cost expectation | None in emitted programs. Bindings and validation are workspace/compiler-service metadata only. |
| AI/token expectation | Compact proof handles avoid retransmitting roots/CIDs when a transaction depends on verifier status. The measured bootstrap response is 299 bytes and the guarded one-mutation transaction is 22 bytes; these are byte-accounting figures, not token claims. |
| Falsification condition | Replace the concrete handle/binding representation if verifier-dependency experiments require finer dependency graphs or a smaller measured protocol, while retaining exact dependency tracking, distinct proof-conflict diagnostics, and no fabricated proof certificates. |

## ADR-037 — Bootstrap insertion uses exact anchors and transaction-local results

| Field | Record |
|---|---|
| Decision | The first M6 insertion slice is a typed tooling-only `InsertPureNode` request that inserts immediately before an existing node identified by a current workspace handle plus exact expected block/node coordinates. It is restricted to pure constants and wrapping arithmetic. Result types use workspace-local type handles. New results referenced by later mutations in the same transaction use integer-scoped `TransactionValueRef` identities that are resolved only inside candidate construction and are never published as persistent identities. |
| Rationale | Exact anchors make containment drift machine-detectable; local result identities permit atomic construction/use without exposing a CID before the candidate exists; ordinary graph verification remains the semantic authority for type, dominance, and structural legality. |
| Alternatives rejected | Textual insertion scripts; persistent provisional CIDs; silently inferring a changed insertion position; bypassing the graph verifier; broad effect/resource insertion before ownership/effect mutation semantics exist. |
| Runtime cost expectation | None. Insertion and local-result resolution are compiler-service operations only. |
| AI/token expectation | Short local handles and integer transaction-local results avoid transmitting persistent identities; token efficiency remains unclaimed until measured with real tokenizers/model tasks. |
| Falsification condition | Replace the anchor/local-ID carrier if measured mutation cost or conflict behavior is inferior to another typed semantic protocol, while preserving exact position preconditions, nonpersistent temporary identities, deterministic remapping, and verifier-before-publication. |

## ADR-038 — Control-edge argument reconnects are exact relation mutations

| Field | Record |
|---|---|
| Decision | The first bootstrap `disconnect`/`connect` slice edits one block-terminator edge argument in a standalone function using typed tooling-only `DisconnectEdgeArgument` and `ConnectEdgeArgument` carriers. The disconnect records an exact containing block, edge index, argument index, and expected old graph-local `ValueRef`; the connect records the same exact position and a graph-local or transaction-local replacement value. A matching pair may target the same local anchor in one transaction. Only the completed private candidate is verified and published. |
| Rationale | Edge rewiring needs finer conflict detection than whole-root identity while avoiding publication of verifier-invalid intermediate control-flow state. Exact positional and old-relation preconditions make drift deterministic; reuse of the ordinary graph verifier keeps branch arity/type and SSA dominance in the trusted semantic checker rather than duplicating those rules in workspace code. |
| Alternatives rejected | Textual CFG-edit scripts; disconnect followed by publication before reconnect; silently infer an edge after position drift; accept last-writer-wins edge replacement without an old relation; add a second branch/dominance checker in workspace tooling. |
| Runtime cost expectation | None. Edge mutation carriers and candidate rewiring exist only in compiler/workspace tooling. |
| AI/token expectation | The fixed non-timing smoke uses 301 bootstrap query bytes and a 39-byte two-mutation disconnect+connect transaction. These are byte-accounting figures only; no tokenizer/model-efficiency claim follows. |
| Falsification condition | Replace the concrete anchor/position carrier if measured conflict or protocol results favor another typed relation form, while preserving exact old-relation preconditions, atomic private candidate construction, transaction-local value support, ordinary verifier authority, and no textual source syntax. |

## ADR-039 — Candidate-only verify/rollback keeps private semantic state non-authoritative

| Field | Record |
|---|---|
| Decision | The bootstrap workspace exposes candidate-only `verify(Transaction)` and `rollback(C...)` services. `verify` reuses the same typed mutation carriers, private `_candidate` construction path, exact root/read/local preconditions, and ordinary object verifier used by commit, but does not publish the candidate root. A successful verify returns only a generation-scoped tooling handle `C<n>.<generation>` plus counts/accounting; candidate semantic CIDs and transaction-local inserted-result identities are not exposed. `rollback` discards the named private candidate without changing canonical root/generation. Dependencies are revalidated before a successful candidate handle is returned so raw-root ABA cannot revive invalidated proof/read assumptions. Any successful canonical commit invalidates all outstanding candidate handles rather than rebasing them implicitly. |
| Rationale | Verification-before-publication is useful to AI tooling only if it cannot accidentally become a second source representation or refresh stale assumptions. Reusing the commit candidate/verifier path minimizes semantic drift, while explicit discard bounds private state lifetime. |
| Alternatives rejected | Expose candidate root/changed-object CIDs as an editable source surface; implement a second preview verifier; let candidate verification refresh stale read/proof/artifact dependencies; retain candidate handles across canonical commits; encode candidate edits as textual scripts. |
| Runtime cost expectation | None in emitted programs. Candidate state and handles are compiler/workspace service metadata only. |
| AI/token expectation | The fixed non-timing smoke uses 424 bootstrap query bytes and a 26-byte candidate transaction. These are byte-accounting figures only; no tokenizer/model-efficiency claim follows. |
| Falsification condition | Replace the concrete handle/lifecycle if measured workflows show unnecessary state or protocol cost, while retaining private non-authoritative candidate state, exact dependency validation, ordinary verifier reuse, explicit discard, and no candidate CID leakage. |

## ADR-040 — Same-block pure-node move remaps producer identities, not numeric positions

| Field | Record |
|---|---|
| Decision | The first workspace `move` mutation is a tooling-only typed `MovePureNode` restricted to one pure constant/wrapping-arithmetic node in a standalone function block. It carries exact source containment and an exact existing destination insert-before anchor. Moving changes node order only; every surviving graph-local `ValueRef` is deterministically remapped by the identity of its original producer. Cross-function/cross-block moves, self-anchors, multiple moves in one function, and move+insert/delete structural combinations are rejected in this slice. The ordinary graph verifier remains authoritative for type/SSA-dominance/structural legality after remapping. |
| Rationale | Numeric node indices are representation-local. Preserving indices through a reorder would silently rewire uses and violate “meaning is source.” Exact source/anchor preconditions detect local containment drift while the ordinary verifier avoids duplicating SSA legality in workspace code. |
| Alternatives rejected | Treating move as delete+insert with newly exposed semantic identity; keeping old numeric `ValueRef`s after reorder; silently repairing dominance; broad cross-block/effect/resource move semantics in the first slice. |
| Runtime cost expectation | None. This is compiler/workspace mutation logic only. |
| AI/token expectation | Exact local source/anchor handles bound the edit and avoid function regeneration; token benefit is unmeasured. |
| Falsification condition | Broaden or replace the carrier if real move workloads require more general structure with lower verifier/context cost, but producer-identity preservation, exact local preconditions, tooling-only status, and verification-before-publication remain required. |

## ADR-041 — First workspace specialization is a verified semantic clone, not META evaluation

| Field | Record |
|---|---|
| Decision | The first workspace `specialize` slice is the tooling-only `SpecializeFunction` request. It accepts one exact current standalone-function handle plus explicit constant arguments carrying parameter index, expected type handle, and value. The bootstrap supports only verified straight-line single-block functions containing constants and wrapping arithmetic. It materializes constants, removes specialized parameters from the clone interface, verifies every new object through the ordinary verifier, and publishes the clone alongside the unchanged source. Existing callers are not silently rewired. Candidate-only verification exposes no clone CID before commit. |
| Rationale | This closes the workspace mutation-vocabulary gap using semantics already expressible by the current core. It exercises exact dependency/precondition handling, deterministic identity, private candidate construction, and verifier authority without importing the future general compile-time evaluator. |
| Alternatives rejected | Textual substitution; a host-language template/macro system; interpreting arbitrary XAX at compile time in M6; silently replacing the source or its callers; exposing private candidate identities before commit. |
| Runtime cost expectation | None unless the published clone is explicitly called later. The specialization operation itself is compiler/workspace service work. |
| AI/token expectation | The 2026-09-29 non-timing smoke used 479 bootstrap query bytes and a 15-byte transaction. These are transport/accounting figures only, not tokenizer or model-efficiency evidence. |
| Falsification condition | Replace or broaden this carrier when real specialization workloads require control flow, effects/resources, calls, types/targets, evaluation budgets, or canonical reuse policy. The no-second-language rule, explicit inputs, private construction, ordinary verification, and no implicit caller rewiring remain fixed. |

## ADR-042 — First resource-bearing call is exact pass-through

| Field | Record |
|---|---|
| Decision | The first M7/C6 direct-call slice accepts only one non-recursive single-block contract: `(resource<stack-storage,live>, effect<memory>) -> (resource<stack-storage,live>, effect<memory>)`. Verification consumes incoming owner/effect facts once, assigns the same symbolic provenance to call results, requires explicit return transfer in the callee, and preserves the rule that locally allocated stack storage cannot escape. |
| Rationale | This reuses the M3 linear-fact verifier and reference runtime wrappers, proving call transfer without a generalized resource framework, ABI lowering, or runtime machinery. |
| Alternatives rejected | Hidden call ordering; copied owner/effect tokens; implicit cleanup; a general effect/resource framework before one executable slice; backend ABI support before semantic verification. |
| Runtime cost expectation | None. Reference execution passes the same owner/effect wrapper objects through the callee; native/WebAssembly backends remain bits-only and reject this ABI shape. |
| AI/token expectation | Unmeasured. The change adds no textual source or protocol language. |
| Falsification condition | Broaden when the next vertical slice needs pointer/data operands, multiple resources/effect domains, or cross-block transfer; preserve exact linear consumption, provenance, and no hidden runtime behavior. |

## ADR-043 — First pointer/data resource call is an exact one-store contract

| Field | Record |
|---|---|
| Decision | Extend the M7/C6 bootstrap direct-call slice with exactly one non-recursive single-block store contract: `(ptr<stack,T,P,A>, T, resource<stack-storage,live>, effect<memory>) -> (resource<stack-storage,live>, effect<memory>)`. The callee body contains exactly one `store.bits.le`. Its entry pointer is symbolically tied to the same storage provenance as the owner/effect pair, with one-element minimum extent and the pointer type's guaranteed alignment/permission. At the call site, the verifier requires a live local pointer fact with sufficient remaining extent, write permission, and the same storage provenance as the consumed owner/effect pair. The successor effect conservatively preserves prior initialization and adds the stored byte range. |
| Rationale | This is the smallest executable pointer/data-bearing call that proves interprocedural provenance, extent, permission, alignment, initialization, and linear effect/resource transfer without introducing a new source language, serialized CallContract object, runtime metadata, or backend ABI. |
| Alternatives rejected | Guessing provenance or extent from numeric addresses; treating pointer type alone as hidden provenance/extent; hidden runtime bounds metadata; general effect-summary inference before one vertical slice; backend ABI lowering before semantic/reference proof; allowing arbitrary callee bodies under the narrow bootstrap contract. |
| Runtime cost expectation | None beyond the explicit store itself. Proof facts erase. Reference execution reuses the existing runtime pointer/storage/owner/effect wrappers and adds no allocator, metadata object, scheduler, exception path, or helper runtime. |
| AI/token expectation | Unmeasured. The slice adds no textual XAX language and no new transaction/protocol syntax. |
| Falsification condition | Replace this implementation-local structural contract when a canonical CallContract representation is introduced or when load/multi-access evidence requires a different compact form. Exact provenance, proof obligations, linear consumption, and no hidden runtime behavior remain mandatory. |

## ADR-044 — First pointer/data load resource call is an exact one-load contract

| Field | Record |
|---|---|
| Decision | Extend the M7/C6 bootstrap direct-call slice with exactly one non-recursive single-block load contract: `(ptr<stack,T,P,A>, resource<stack-storage,live>, effect<memory>) -> (T, resource<stack-storage,live>, effect<memory>)`. The callee body contains exactly one `load.bits.le`. At the call site, the verifier requires a live local pointer fact with sufficient remaining one-element extent, read permission, the same storage provenance as the consumed owner/effect pair, and proof that the exact requested byte range is initialized. The callee verifier treats that one-element view as initialized only as the derived precondition of this exact contract. The returned owner/effect preserve the same storage provenance and initialization frontier. |
| Rationale | This is the smallest read-side counterpart to ADR-043. It proves interprocedural initialization preconditions, read authority, exact-range checking, linear owner/effect transfer, and post-call continuation without introducing a serialized CallContract object, runtime metadata, or backend ABI. |
| Alternatives rejected | Reading uninitialized memory and relying on runtime contents; treating any initialized interval in the storage as sufficient; hidden runtime initialization metadata/checks; allowing arbitrary multi-access callees in the same slice; backend ABI lowering before semantic/reference proof. |
| Runtime cost expectation | None beyond the explicit load itself. Initialization/provenance facts erase. Reference execution reuses the existing runtime pointer/storage/owner/effect wrappers and adds no allocator, metadata object, scheduler, exception path, or helper runtime. |
| AI/token expectation | Unmeasured. The slice adds no textual XAX language and no new transaction/protocol syntax. |
| Falsification condition | Replace this implementation-local structural contract when a canonical/derived general CallContract mechanism is introduced or when multi-access evidence requires a different compact form. Exact provenance, initialized-range proof, linear consumption, and no hidden runtime behavior remain mandatory. |

## ADR-045 — First multi-access resource call is a fixed store→load sequence with a verifier-internal derived descriptor

| Field | Record |
|---|---|
| Decision | Extend M7/C6 with one exact non-recursive single-block contract `(ptr<stack,T,P,A>, T, resource<stack-storage,live>, effect<memory>) -> (T, resource<stack-storage,live>, effect<memory>)` whose body is exactly `store.bits.le` followed by `load.bits.le`, with the load consuming the store successor effect and the function returning the loaded value, owner, and load successor effect. Factor caller-side recognition of the fixed pass/store/load/store→load interfaces through a small verifier-internal `_ResourceCallContract` descriptor that records only operand/result positions, required permission, whether incoming initialization is required, and whether the call initializes the accessed range. The descriptor is derived implementation state: it is not serialized, not XAX source, and not a target/build/package DSL. |
| Rationale | This is the smallest multi-access call that proves effect sequencing across more than one operation and initialization created inside the callee. The descriptor removes repeated caller-side shape booleans without prematurely introducing a canonical general CallContract representation. |
| Alternatives rejected | Add another unrelated boolean branch for every call shape; serialize a general CallContract before evidence exists; infer effects from runtime addresses; allow load-before-store or effect forks; return the input merely because it has the same type as the loaded value; add runtime initialization metadata/checks. |
| Runtime cost expectation | None beyond the explicit store and load. Provenance/initialization/linearity facts and the derived descriptor erase completely; reference execution reuses the existing runtime wrappers. |
| AI/token expectation | Unmeasured. No new textual source or transaction language was added. |
| Falsification condition | Replace the fixed descriptor/contracts when measured multi-access/cross-block workloads justify a canonical or more general derived effect/resource summary. Preserve exact sequencing, verifier-before-execution, linear transfer, and zero hidden runtime behavior. |

## ADR-046 — Derived resource-call descriptor drives caller and callee fixed-contract checks

| Field | Record |
|---|---|
| Decision | Make the verifier-internal `_ResourceCallContract` candidate set the single source for the M7 fixed resource-call interface facts, entry proof seeding, callee body-shape selection, and owner/effect return positions. Preserve the previously accepted pass-through behavior, including pure work in the single block, while keeping store/load resource callees restricted to their supported access shapes. The descriptor remains derived Python verifier state and is never serialized. |
| Rationale | Caller recognition and callee entry validation had duplicated shape logic. Centralizing both through one derived descriptor reduces verifier drift without adding canonical objects, a second language, or runtime metadata. |
| Alternatives rejected | Keep parallel interface/body boolean trees; serialize a general `CallContract` before broader evidence exists; tighten pass-through bodies during a cleanup-only change. |
| Runtime cost expectation | None. The descriptor exists only while verifying and erases completely. |
| AI/token expectation | Unmeasured. Canonical encoding and workspace transport are unchanged. |
| Falsification condition | Replace or extend the derived descriptor when resource summaries need facts that cannot be expressed compactly without duplication. Any replacement must retain one verifier authority, deterministic diagnostics, and zero hidden runtime semantics. |

## ADR-047 — Bounded single-pointer resource-call access sequences extend the fixed interfaces

| Field | Record |
|---|---|
| Decision | Extend the three pointer-bearing M7 direct-call interfaces from fixed one/two-access bodies to verifier-bounded single-block sequences of at most **8** accesses to the same entry pointer. `(ptr,T,owner,effect)->(owner,effect)` accepts 1–8 stores; `(ptr,owner,effect)->(T,owner,effect)` accepts 1–8 loads; `(ptr,T,owner,effect)->(T,owner,effect)` accepts 2–8 store/load accesses with the first access a store and the final access a load, and returns that final loaded value. The existing derived descriptor supplies caller permission/initialization/successor facts. The limit is a bootstrap verifier capability limit, not a canonical XAX language limit. |
| Rationale | This is the smallest variable-length interprocedural memory slice that exercises repeated effect-frontier transfer and initialization propagation while preserving the existing interface-derived caller summaries. It avoids prematurely deriving arbitrary summaries from callee bodies or introducing stored general `CallContract` objects. |
| Alternatives rejected | Unbounded scanning in the bootstrap verifier; arbitrary load-first mixed sequences requiring new caller-summary inference in the same change; multiple pointers/ranges; cross-block flow; canonical summary encoding; backend ABI lowering. |
| Runtime cost expectation | None beyond the explicitly represented loads/stores. The sequence bound and verifier descriptor add no runtime checks or metadata. |
| AI/token expectation | Unmeasured. No textual XAX syntax, transaction syntax, or canonical encoding was added. |
| Falsification condition | Replace the fixed 8-access bootstrap bound and interface-derived sequence classes when measured workloads justify bounded derived summaries for more general orderings, ranges, or pointers. Preserve exact effect sequencing, permission/initialization proof, and no hidden runtime behavior. |

## ADR-048 — Bounded mixed-call initialization preconditions are derived from the verified callee body

| Field | Record |
|---|---|
| Decision | For the existing single-pointer `(ptr<stack,T,P,A>, T, owner, effect) -> (T, owner, effect)` bootstrap interface, the verifier derives a bounded access summary from the verified single-block callee body. A mixed sequence may begin with load or store but must contain both access kinds, remain within the 8-access bootstrap bound, end in a load, and return that final loaded value. A load-first sequence requires exact-range incoming initialization at the caller; a store-first sequence does not. Any store establishes initialization in the successor memory frontier. The summary is verifier-internal derived state and is not serialized XAX semantics. |
| Rationale | Initialization is a memory fact, not an interface-level guess. Deriving the precondition from the actual verified access order admits a valid load-first case without creating a stored summary language or weakening caller proof obligations. |
| Alternatives rejected | Permanently require first-store mixed bodies; treat all mixed calls as requiring initialization; treat all mixed calls as initializing without inspecting order; serialize a new general effect-summary format before cross-block/multi-domain evidence exists. |
| Runtime cost expectation | None. The summary is verifier work only and erases completely; reference execution is unchanged. |
| AI/token expectation | No token-efficiency claim. The change avoids adding canonical summary objects or a textual contract DSL. |
| Falsification condition | Replace the derived bounded form when multi-range, cross-block, recursive, or multi-domain calls require a more general summary representation, while preserving exact caller preconditions and verifier authority. |

## ADR-049 — General resource/effect operations use canonical types and verifier-enforced linear flow

| Field | Record |
|---|---|
| Decision | Extend type forms 3 and 4 compatibly with effect domain instances and resource flags/instances/declared state transitions. Add canonical operations for acquire, transfer, transition, release, affine discard, two-piece split/sibling join, and multi-domain effect steps. Verify exact consumption through nodes, block edges, returns, and traps; reject implicit drop, duplication, forks, invalid transitions, and unrelated joins. |
| Rationale | The existing canonical graph/type machinery already carries every required dependency. Extending it directly is smaller and safer than a textual lifecycle DSL, hidden runtime manager, or parallel verifier framework. |
| Alternatives rejected | Host-language resource metadata; implicit cleanup; reference counting; textual contracts; same-block-only verification; arbitrary joins without split lineage. |
| Runtime cost expectation | Proof flow itself costs nothing at runtime. Reference execution uses removable wrapper objects only to test observable lifecycle semantics. |
| AI/token expectation | Unmeasured; no separate source or protocol language was added. |
| Falsification condition | Generalize the two-piece contract or persistent encoding only when real workloads require fractional/heterogeneous partitions, while preserving explicit state, exact linearity, and verifier authority. |

## ADR-050 — Resource/effect proof values erase from executable ABIs

| Field | Record |
|---|---|
| Decision | Treat resource/effect values as proof-only in the three direct backends: allocate no machine/WebAssembly slots, copy no edge values, pass/return no ABI values, emit no lifecycle/effect instructions, and remove verified proof-only direct calls entirely. Ordinary bit-valued computation remains unchanged. |
| Rationale | These values establish legality and ordering; representing them at runtime would create cost and hidden machinery without observable semantics. One shared proof-type predicate keeps erasure consistent. |
| Alternatives rejected | Zero-sized runtime placeholders; hidden token integers; runtime lifecycle helpers; backend-specific proof conventions. |
| Runtime cost expectation | Zero bytes and zero instructions for proof-only behavior. The deterministic baseline/lifecycle comparisons are byte-identical on x86-64, AArch64, and WebAssembly. |
| AI/token expectation | Unmeasured. Backend code reuses existing ABI/slot paths with one proof-type exclusion. |
| Falsification condition | Introduce runtime representation only for an operation whose specified observable behavior requires it; never for verifier bookkeeping alone. |

## ADR-051 — Workspace durability stores canonical bytes; history remains bounded tooling state

| Field | Record |
|---|---|
| Decision | Retain verified generation snapshots in memory for multi-generation diff/rebase of unchanged entities. Persist a workspace by atomically replacing a file with the reader's canonical store bytes; load it through the ordinary store verifier. Do not invent a separate workspace database or serialize ephemeral handles, candidates, indexes, or history. |
| Rationale | Canonical bytes already contain authoritative state. Standard temporary-file plus `fsync`/replace supplies the required single-file durability with no new format or dependency. |
| Alternatives rejected | SQLite/object database for the prototype; serializing local handles; checkpointing candidate state; rewriting canonical store semantics into a workspace format. |
| Runtime cost expectation | Workspace-service I/O only; no emitted-program cost. |
| AI/token expectation | Unmeasured. Reloaded workspaces deterministically regenerate local handles from canonical content. |
| Falsification condition | Add a durable history/index layer only when measured multi-process or large-project workflows require it; canonical store bytes and verification-on-load remain authoritative. |

## ADR-052 — First atomic target path is native-or-reject with post-lowering profile validation

| Field | Record |
|---|---|
| Decision | Add canonical load/store/RMW/compare-exchange/fence operations with explicit order, scope, alignment, update semantics, and compare-exchange strength/failure order. Target profile revision 2 declares atomic widths/scopes/families and handler entries. The first backend lowers supported aligned system-scope 32/64-bit x86-64 atomics directly; every unsupported request rejects. Real-time properties are derived against the selected target and validated after lowering. No bounded sequence, lock, runtime helper, scheduler, syscall, or allocator is synthesized. |
| Rationale | Native-or-reject is the smallest exact M8 slice. It proves semantic verification, target qualification, direct code emission, handler contracts, and strict latency-policy rejection without choosing an unevidenced non-native synthesis policy. |
| Alternatives rejected | Sequential consistency for all operations; silent lock/helper lowering; treating unsupported target requests as generic memory; pre-lowering-only real-time validation; hard-coding handler convention outside the target package. |
| Runtime cost expectation | Exactly the selected x86-64 instructions and fences. Profile and handler checks are compile-time only; no runtime support is emitted. |
| AI/token expectation | Unmeasured. Workspace queries return compact target-qualified capability, handler, and latency facts; no token-efficiency claim follows. |
| Falsification condition | Broaden support only with evidence for another target or bounded/runtime-assisted policy. Preserve explicit capability, no hidden help, exact atomic semantics, and post-lowering policy validation. |

## ADR-053 — First package/build slice uses exact semantic closure and an ambiguity-rejecting resolver

| Field | Record |
|---|---|
| Decision | Add canonical kind-9 package objects and tagged kind-10 profile/request/snapshot/trust/provenance/signature objects. Exact-root dependencies resolve directly; a logical identity resolves only when exactly one candidate matches. Snapshots contain the exact transitive package closure, declared external digests, trust policy, resolver identity, and accepted package signatures. Build/cache identities include the snapshot, request, compiler, lowering, target/profile/configuration transitively. |
| Rationale | This is the smallest M10 model that proves deterministic resolution, typed configuration, offline closure, capability isolation, cache integrity, and trust hooks without a manifest DSL, registry grammar, solver, sandbox framework, or new dependency. |
| Alternatives rejected | Implicit latest selection; textual manifests/lockfiles; host-directory discovery; accepting the lowest version label; ambient dependency privileges; unsigned cache trust; embedding package management in target backends. |
| Runtime cost expectation | Build-system only. Emitted program bytes are produced by the existing direct backends and gain no package runtime. |
| AI/token expectation | Unmeasured. Canonical package/build roots make changes exact, but no token-efficiency claim follows from the M10 smoke. |
| Falsification condition | Add compatibility constraints, action-level provenance, persistent caches, or platform sandbox adapters only when representative package graphs require them. Preserve exact roots, deterministic failure, declared closure, and explicit authority. |

## ADR-054 — First XAX-hosted compiler subset is a canonical arithmetic folder on a fixed WebAssembly bootstrap target

| Field | Record |
|---|---|
| Decision | M11/B0–B1 uses one deliberately small compiler/tooling component as the first authoritative XAX-hosted program: `(bits<1> selector, bits<32> lhs, bits<32> rhs) -> bits<32>`, where selector 0 performs `add.wrap` and selector 1 performs `mul.wrap`. The authoritative implementation is the committed canonical `compiler/bootstrap/m11_compiler_subset.xax` program root. `m11_bootstrap_bundle.xax` binds the same module/function identities to a hermetic WebAssembly build snapshot. Python constructors are transitional seed material only and must reproduce the committed artifacts byte-for-byte; they are not XAX source. |
| Rationale | This is the smallest compiler-relevant deterministic component that exercises canonical XAX authority, fixed build policy, seed lowering, runnable hosted behavior, and seed-versus-hosted conformance comparison without prematurely claiming recursive self-hosting. WebAssembly is the M11 bootstrap execution target because the emitted artifact is directly runnable in the available validation environment and already uses the ordinary target/package/build path. |
| Alternatives rejected | Treating the Python constructor as authoritative source; inventing a textual XAX compiler language; claiming B2 from a seed-built hosted component; choosing a host-only target that cannot execute in the milestone validation environment; migrating a much larger compiler service before the B0/B1 evidence path is proven. |
| Runtime cost expectation | No XAX runtime is added. The hosted component is a 144-byte import-free WebAssembly artifact for the fixed M11 snapshot. |
| AI/token expectation | Unmeasured. M11 records canonical artifact/build identities and conformance behavior only; it makes no token-efficiency claim. |
| Falsification condition | Broaden or replace the hosted subset when later self-hosting work requires more expressive compiler services. The authoritative-program rule, exact roots/policies/provenance, ordinary verifier/build path, and separation of B0/B1 from B2–B6 remain fixed. |

## ADR-055 — M12 uses bounded wrapping-polynomial validation and lowering-derived code-size selection

| Field | Record |
|---|---|
| Decision | M12 keeps low-risk local/CFG/direct-call transforms deterministic and verifier-gated, represents optimizer budgets as canonical kind-10 build form 7 `optimization_policy`, keeps observed profile call weights tooling-only, and admits the first higher-effort search only for pure one-block same-width wrapping integer arithmetic. Search candidates are validated by ordinary graph verification plus exact polynomial equivalence over `Z/(2^N)` under an explicit polynomial-term bound. Target-aware profitability for this slice uses exact emitted function extent from the existing target lowering as a code-size oracle. Any failed verifier/equivalence check rejects the candidate and preserves the last known-correct accepted function. |
| Rationale | The design gives M12 an independently checkable semantic-preservation path and deterministic compile-work/memory limits without adding an SMT solver, e-graph framework, runtime, or new semantic language. Measuring actual lowering output makes code-size selection target-aware while keeping the limitation explicit: it predicts bytes, not runtime behavior. Profile separation preserves the spec rule that measurements influence profitability rather than legality or program meaning. |
| Alternatives rejected | Trusting search-generated rewrites; accepting randomized or wall-clock-only search cutoffs; serializing profile observations into canonical program identity; treating optimization levels as opaque external strings; unbounded equality saturation; inferring latency/throughput wins from emitted byte count; making target-specific rewrite legality part of core semantics. |
| Runtime cost expectation | Zero runtime support is introduced. M12 changes compiler work and selected machine code only. Search is opt-in/bounded by explicit deterministic work/candidate/memory/term budgets. |
| AI/token expectation | Unmeasured. The policy is machine-readable and compact, but M12 records no tokenizer/model-efficiency claim. |
| Falsification condition | Broaden or replace the polynomial validator/search organization when representative workloads require control flow, memory/effects, vector operations, richer algebra, or proof reuse. Replace the lowering-derived size oracle with calibrated target cost models when measured ranking/magnitude evidence supports them. Preserve explicit legality validation, failure fallback, deterministic budgeting where requested, and non-semantic profile separation. |


## ADR-056 — M13 accelerator semantics remain target-package contracts behind one generic target operation

| Field | Record |
|---|---|
| Decision | Add one generic canonical graph operation, `target` (operation 30), whose node references an exact target package and carries a package-defined operation ID, execution scope, source memory space, and destination memory space. Target profile 3 / architecture 4 supplies execution topology, memory-space contracts, typed operand/result constraints, supported scopes, packet opcode/semantic code, synchronization/blocking flags, and optional runtime-dependency identity. The first package is `simt32-packet-accelerator-v1`; its six contracts explicitly model buffer acquisition, H→D transfer, launch, synchronization, D→H transfer, and release. |
| Rationale | The base language already requires target-dependent operations to be explicit. One generic contract hook proves a non-CPU deployment path while keeping GPU-specific opcode/topology/memory facts out of fundamental semantics and avoiding a second CUDA/OpenCL-like source language. Existing resource/effect linearity and package/build/provenance machinery can enforce host/device ownership and ordering without hidden runtime behavior. |
| Alternatives rejected | Hard-code GPU launch/barrier/copy operations into the semantic kernel; introduce a textual kernel/deployment DSL; infer synchronization or transfer from address spaces; silently attach a vendor runtime; encode accelerator packets directly in the core verifier; claim physical GPU support from a host-only simulation. |
| Runtime cost expectation | No mandatory XAX runtime is added. The prototype target declares no runtime dependency; emitted output is a 122-byte deterministic deployment packet. The Python executor is a conformance harness only. |
| AI/token expectation | Unmeasured. The target package centralizes repeated accelerator facts, but M13 records no tokenizer/model-efficiency claim. |
| Falsification condition | Generalize the contract/profile when materially different accelerator targets cannot express their scopes, coherence, memory spaces, synchronization, launch, or runtime-assist requirements without semantic loss. Preserve explicit effects/resources, exact target identity, deterministic rejection, and absence of hidden runtime behavior. |


## ADR-057 — M14 graph introspection is necessary but not self-hosting evidence

| Field | Record |
|---|---|
| Decision | Add capability-gated compile-time inspection of function graph structure (`opaque<graph>`, function→graph, block count, node count, node opcode) as an M14 prerequisite, while keeping B2–B6 false until recursive generation and closure evidence actually execute. |
| Rationale | A XAX-hosted compiler cannot compile its own authoritative graph if graph structure must first be projected by maintained host-language code. Introspection removes that dependency class without pretending that inspection alone performs serialization, verification, code generation, linking, or package/build work. |
| Alternatives rejected | Treating Python graph projection as evidence of recursive self-compilation; relabeling M11 behavior equivalence as B2; claiming B5/B6 from canonical data definitions while live implementations remain Python. |
| Runtime cost expectation | None in user programs; these operations are compile-time META only and require explicit authority. |
| AI/token expectation | Direct semantic inspection should reduce host-side projection state and make future compiler-generation transactions local to canonical entities. |
| Falsification condition | Replace the introspection surface if a smaller capability can support executed B2–B5 evidence; bootstrap labels still require the evidence classes defined by the spec. |


## ADR-058 — M14 closure is target-scoped to the canonical semantic image and immutable seed boundary

| Field | Record |
|---|---|
| Decision | Claim B2–B6 for `xax-semantic-image-v1` only after executed recursive evidence. The authoritative XAX entry graph materializes a program root, invokes verifier-facing and canonical-image encoder functions, then an XAX finalization/build function. Canonical graph verification and canonical store formation remain deliberate trusted META substrate. B4 uses exact byte identity. B6 uses the committed immutable `m14_seed_runtime.pyz` as the approved seed boundary; ordinary semantic-image release reconstruction must succeed without repository Python sources on the import path. Legacy x86-64, AArch64, WebAssembly, and accelerator lowerers are explicitly outside this B5/B6 claim. |
| Rationale | The semantic-image target is canonical by construction, so it can establish recursive compiler generation and an exact fixed point without inventing a textual compiler language or relabeling legacy Python backend code as hosted. Keeping verifier/serializer primitives in the minimal trusted substrate matches the architecture's trusted-core rule. A fixed immutable seed artifact separates ordinary release reconstruction from maintained seed-source implementation while keeping the remaining trust boundary explicit. |
| Alternatives rejected | Advancing B2–B6 from graph-introspection capability alone; calling M11 behavioral equivalence recursive self-hosting; claiming closure for all existing backends because their data is canonical; hiding the serializer/verifier boundary; calling the seed “source-free” when it internally contains Python modules; treating immutable-seed bootstrap independence as diverse-double-compilation evidence. |
| Runtime cost expectation | None for user programs. M14 additions are compile-time/bootstrap services; the semantic-image output is canonical store bytes. |
| AI/token expectation | Unmeasured. Local graph inspection and canonical semantic-image generation reduce dependence on host projections, but no tokenizer/model-efficiency result is claimed. |
| Falsification condition | Withdraw or narrow B5/B6 if the declared semantic-image release path requires a live legacy target/package dispatcher, repository Python implementation imports, or edits to a second implementation language for ordinary releases. A future native/accelerator closure target must earn separate B5/B6 evidence. Seed diversity and correctness trust remain separate under OI-27. |

## ADR-059 — The first AI-native experiment is a tiny manual C-vs-XAX comparison

| Field | Record |
|---|---|
| Decision | Compare C and the implemented XAX workspace on five equivalent structural edits, run manually in fresh Codex Desktop chats. Record pass/fail, available model tokens, turns, optional elapsed time, and every retry. Report raw per-task and aggregate values only. |
| Rationale | This is the smallest experiment that can expose whether XAX's structural transaction interface helps Codex while keeping token spend and operator effort low. |
| Alternatives rejected | API/provider automation, extra representation arms, large frozen corpora, tokenizer reconstruction, desktop automation, preregistration machinery, bootstrap/significance tests, and hiding failed attempts. |
| Runtime cost expectation | Benchmark tooling only; no program-runtime claim. |
| AI/token expectation | Unknown. The experiment may show no XAX advantage. |
| Falsification condition | If XAX uses at least as many tokens/turns or completes fewer tasks, this narrow experiment provides no evidence that XAX beats C. |


## ADR-060 — JNI stays a platform package; identity-qualified ABI carriers and linear reference owners expose its exact boundary

| Field | Record |
|---|---|
| Decision | Add one generic identity-qualified opaque ABI type form and use it to model Android JNI carrier identities. Android arm64 target v2 exposes the JNI 1.6 `JNIInvokeInterface` and `JNINativeInterface` as fixed-offset `target-op` contracts; function signatures are bounded `CallContract` objects. JNI references acquired by XAX produce explicit linear local/global/weak-global owner proof values that release calls consume. No JNI-specific core operation is added. |
| Rationale | JNI pointer identities and reference classes are semantically distinct even though AAPCS64 represents them as machine pointers. Encoding that distinction as target-independent ABI carrier identity lets the verifier reject signature/lifetime mistakes without introducing Android/Java into the kernel. The existing target-op plus indirect-call path already emits the minimum direct table load and `BLR`. |
| Alternatives rejected | A giant JNI opcode family in the core; C/JNI wrapper source; a mandatory Android runtime; untyped `void*` for every JNI handle; hidden automatic local/global-reference cleanup; runtime reflection/lookup wrappers; treating a borrowed reference as owned. |
| Runtime cost expectation | Carrier and ownership proof types erase from the executable ABI. The measured `GetVersion` probe adds no imports/relocations/runtime and emits 36 bytes of AArch64 entry code; the measured `NewGlobalRef`→`DeleteGlobalRef` path emits 72 bytes. |
| AI/token expectation | Not yet measured. Central slot metadata and typed contract constructors avoid regenerating table offsets/signatures, but no Android AI-token advantage is claimed yet. |
| Falsification condition | Revise the carrier/lifetime model if real Android execution or broader JNI contracts show that exact JNI ownership, nullability, exception, thread, or class-loader semantics cannot be represented without hidden state. Pending-exception refinement, nullability, and attach-thread state remain explicitly unclaimed. |

## ADR-061 — JNI loader domains and pending exceptions are explicit proof state, not hidden runtime state

| Field | Record |
|---|---|
| Decision | Extend the JNI platform-package model without adding core JNI operations. An optional loader domain participates in JNI reference/class/member-ID semantic identity and is preserved through local/global/weak reference lifetime transitions; a loader-mismatched call operand rejects. Calls that may establish a Java exception thread a linear proof state from `clean` to `maybe-pending`; ordinary safe JNI calls require `clean`, and the bounded first recovery policy is an explicit `ExceptionClear` transition back to `clean`. |
| Rationale | Class-loader identity changes Java member meaning, and a pending exception changes which JNI operations are legal. Both therefore need verifier-visible identity/state. They are still platform facts and can erase when statically known; hiding them in a global cache, thread-local runtime, or helper would violate XAX's explicit-effect/runtime rules. |
| Alternatives rejected | Unqualified global JNI member caches; silently treating equal JVM descriptors from different loaders as identical; automatic exception checks/clears after every JNI call; hidden TLS exception bookkeeping; Android/JNI-specific kernel operations. |
| Runtime cost expectation | Loader-domain proof identity itself emits zero instructions. Exception handling emits only the explicitly selected JNI operation. The current cached `View.setVisibility(I)V` probe with explicit `ExceptionClear` is 84 bytes / 21 AArch64 instructions and has zero imports, `DT_NEEDED`, relocations, or helper runtime. |
| AI/token expectation | Unmeasured. Loader-qualified semantic handles avoid repeatedly restating class-loader provenance, but no token-efficiency claim is made. |
| Falsification condition | Revise the proof-state model if real Android execution shows that loader identity, reference lifetime, or JNI exception legality cannot be represented exactly this way. Conditional pending/clean refinement, nullability, successful attach state, and runtime loader-relative lookup/cache lifecycle remain separate unclaimed work. |

## ADR-062 — Managed interface callbacks lower to the smallest direct DEX-to-XAX adapter

| Field | Record |
|---|---|
| Decision | Extend the direct DEX bridge emitter to encode canonical implemented-interface type lists and a no-super forwarding mode. For a supported interface callback such as `View.OnClickListener.onClick(View)`, generate one public interface method whose body directly invokes one private native XAX callback and returns. Lifecycle overrides retain their separate required superclass call. Adapter construction/registration remains explicit platform behavior. |
| Rationale | ART-visible callback classes are required platform representation, not a reason to add Java/Kotlin source, reflection, or a generic callback runtime. Separating lifecycle-super behavior from interface forwarding produces the minimum bridge while preserving exact Android method contracts. |
| Alternatives rejected | Java/Kotlin source generation; D8/R8 as production dependency; reflection-based generic listeners; heap-allocating closure runtime; calling a nonexistent/irrelevant superclass interface implementation; routing every callback through a generic dispatcher. |
| Runtime cost expectation | The current `View.OnClickListener` bridge method is exactly four DEX code units (`invoke-direct` to the private native callback plus `return-void`), one managed/native transition, and emits no per-callback allocation or reflection operation. Its DEX is 796 bytes; the matching 17,352-byte AArch64 ELF has one callback export and zero imports, `DT_NEEDED`, or relocations. These are structural measurements, not Android runtime latency/allocation measurements. |
| AI/token expectation | Unmeasured. The bridge is derived from semantic callback intent and avoids requiring the model to author an interface class or JNI symbol glue. |
| Falsification condition | Replace or specialize this adapter if real ART/Android execution demonstrates a required extra transition, lifetime operation, exception edge, or platform call. Do not claim zero framework allocations until measured on Android; the current claim is only zero allocation machinery emitted by XAX in the callback body. |

## ADR-063 — JNI `jvalue` packing widens only where exact stores are already provable

| Field | Record |
|---|---|
| Decision | Extend the bounded stack `jvalue[]` lowering from homogeneous `jint`/`jlong` to homogeneous integer JNI shapes `Z/B/C/S/I/J`. Every 8-byte union slot is explicitly initialized. AArch64 semantic memory stores use exact 8/16/32/64-bit encodings; subword slot padding is zeroed with same-width stores. Mixed/reference packs and float/double packs continue to reject. |
| Rationale | Narrow integer JNI arguments need no new cast, object-compatibility rule, runtime packer, or kernel operation: their exact bit widths and AArch64 store encodings are already known. Reference and mixed packs do require additional exact type-compatibility/retyping semantics, so accepting them now would hide assumptions. |
| Alternatives rejected | Wider 32-bit over-stores for byte/short arguments; leaving union padding uninitialized; a generic C-style varargs helper; unchecked pointer/reference bitcasts; treating Java reference subtype compatibility as raw pointer equality. |
| Runtime cost expectation | The cached `View.setClickable(Z)V` structural probe emits 108 bytes / 27 AArch64 instructions. Its `jvalue` construction is one `STRB` argument store plus seven explicit `STRB` zero-padding stores; the complete probe has zero imports, `DT_NEEDED`, relocations, or helper runtime. This is not an Android latency claim. |
| AI/token expectation | Unmeasured. Descriptor-driven packing removes the need for the model to construct JNI union layout manually. |
| Falsification condition | Replace the repeated subword zero stores only with an exactly equivalent, measured smaller/faster sequence that preserves explicit initialization and type legality. Do not admit mixed/reference or float/double packs until their exact semantic and ABI obligations are implemented and tested. |

## ADR-064 — Mixed JNI reference packs use an explicit target ABI projection, not a core pointer cast

| Field | Record |
|---|---|
| Decision | Supersede ADR-063's blanket mixed/reference rejection only for a bounded arm64 case: `jvalue[]` packs may combine `jlong` with strong borrowed/local/global JNI references. A reference slot is lowered by an explicit `android-arm64-v8a-shared-v3` target operation from the identity-qualified JNI handle to the 64-bit `jvalue.l` ABI word. Local/global forms consume and return the matching linear reference-owner proof; borrowed form has no owner token. Weak-global references, mixed narrow integers, and float/double remain rejected. |
| Rationale | Current AOSP JNI defines `jvalue.l` as `jobject`, and Android arm64 represents JNI object references as opaque pointer-shaped handles. Making that representation conversion target-declared keeps Android/JNI out of the kernel and avoids an unchecked general pointer-to-integer cast. Threading owned-reference proof through projection and call keeps lifetime legality verifier-visible. Exact descriptor matching or imported superclass/interface evidence plus any required defining-loader identity gates pack construction. |
| Alternatives rejected | Generic pointer bitcasts in the XAX kernel; C/JNI pack helpers; hidden runtime packers; treating every pointer as a JNI object reference; accepting weak globals without liveness/null refinement; assuming Java subtype compatibility from raw pointer equality; silently widening mixed byte/short/int slots. |
| Runtime cost expectation | The structural `View.postDelayed(Runnable,long)` probe emits 88 bytes / 22 AArch64 instructions. Its borrowed `Runnable` reference projection is last-use and emits zero instructions; the 16-byte pack is two 64-bit stores. The resulting 17,352-byte ELF has zero imports, `DT_NEEDED`, relocations, or helper runtime. This is codegen evidence, not Android latency evidence. |
| AI/token expectation | Unmeasured. Descriptor/loader-qualified argument specs and imported hierarchy evidence remove manual JNI union and subtype boilerplate, but no token advantage is claimed until benchmarked. |
| Falsification condition | Revise this bounded path if Android runtime execution shows the handle representation, subtype/loader assumptions, owner threading, or nullable carrier model is incomplete. Runtime null construction/refinement, weak-reference liveness, mixed narrow integers, float/double, and cross-loader subtype resolution remain explicitly unclaimed. |

## ADR-065 — First Android UI behavior is a semantic platform carrier lowered directly to bounded managed DEX

| Field | Record |
|---|---|
| Decision | Represent the first Activity UI behavior as a content-addressed identity-only Android target/platform carrier containing the generated Activity class identity, listener class identity, initial button text, and click-state text. Lower that semantic carrier directly to two deterministic DEX classes: an Activity that constructs/registers a `Button` + listener and a listener that performs the bounded visible `setText` mutation before one native XAX callback. Keep this outside the fundamental XAX kernel. |
| Rationale | The mission requires lifecycle/UI behavior to originate from XAX semantic objects, not merely compiler configuration or handwritten managed source. An existing identity-only target carrier provides semantic identity without adding a new object kind, DSL, Android kernel opcode, runtime registry, reflection layer, or source language. |
| Alternatives rejected | Hard-coded benchmark-only UI configuration; Java/Kotlin source templates; reflection/generic listener runtimes; JNI construction of the managed listener when DEX can construct it directly; a new Android-specific kernel operation or semantic object kind. |
| Runtime/code-size evidence | Structural evidence only: Activity `onCreate` is 28 DEX code units and its DEX is 1,236 bytes; click `onClick` is 11 code units, emits zero click-time allocation/reflection machinery, and its DEX is 764 bytes. One 17,352-byte ELF exports both JNI callbacks with zero imports/`DT_NEEDED`/relocations. The signed APK is 35,413 bytes. Runtime latency/allocation inside Android framework code is unmeasured. |
| Incrementality evidence | Changing only semantic click text from `Clicked` to `Done` changes the semantic carrier CID and listener DEX hash while the Activity DEX remains byte-identical. |
| Falsification condition | Revise the lowering if real ART/Android execution shows verifier, lifecycle, class-loading, allocation, or callback behavior not represented by the structural model. Do not claim installability, rendering, click delivery, or framework allocation counts until executed on Android. |



## ADR-066 — Android signed APK publication is an explicit M10 build capability

| Field | Record |
|---|---|
| Decision | Add `ANDROID_SIGNED_APK` as an ordinary requested artifact beside `ANDROID_UNSIGNED_APK`. A signed request must declare and receive a package-local `SIGN` capability whose scope is exactly the SHA-256 identity of the signing certificate. The corresponding `BuildEffect.value` carries a bounded private RSA capability transport only for that build invocation. The compiler validates the transport, validates the public signer identity, signs the directly emitted unsigned APK with deterministic APK Signature Scheme v2 RSA PKCS#1 v1.5 + SHA-256, and emits ordinary build provenance. |
| Rationale | APK signing is a build authority, not program meaning. Public signer identity affects the selected artifact and therefore belongs in explicit build policy; private key material must remain secret, non-semantic, and non-content-addressed. Reusing M10 capability/effect isolation avoids Android-specific secret storage or an external `apksigner` production dependency. |
| Alternatives rejected | Serializing a private key into package/profile semantics; reading a key implicitly from disk/environment; postprocessing the artifact outside the build request; permanent `apksigner` dependency; including private effect bytes in provenance/cache keys/diagnostics. |
| Runtime/build evidence | The generic signed request reproduces the existing signed fixture byte-for-byte: 35,413 bytes, SHA-256 `048b3130a6e0996abb9640fdc730114ca5734aa321253e5689cc6aa436b46ae5`. Repeated builds are identical. Focused tests prove missing capability rejection, signer-identity mismatch rejection, valid v2 signature/content digest/certificate match, and absence of private transport bytes from canonical store and provenance. Android package-manager verification remains unexecuted. |
| Falsification condition | Revise this boundary if an Android signature scheme required by a selected target cannot be implemented without secret-dependent semantic identity or if deterministic signing cannot preserve the declared reproducible-build contract. Additional signature schemes require their own explicit build-policy/evidence extension. |

## ADR-067 — First managed libxposed hook is an explicit install carrier plus a lookup-free pass-through Hooker

| Field | Record |
|---|---|
| Decision | Represent the first installed modern libxposed hook with two content-addressed Android platform carriers: one Hooker adapter and one installation declaration. The installation identity includes target class/method, Hooker class, zero-argument parameter list, `PROTECTIVE` exception mode, `propagate` failure policy, and explicit `process` lifetime. Generated `onPackageReady` resolves the target through `PackageReadyParam.getClassLoader()`, obtains the zero-argument `Method`, calls `hook`, selects `PROTECTIVE`, allocates one Hooker, installs it, then performs the native XAX lifecycle callback. The generated Hooker hot path calls `Chain.proceed()` exactly once and returns the result. |
| Rationale | This is the smallest current-API managed hook that proves semantic target/install identity, current metadata, target-class-loader use, exception policy, generated Hooker ABI, and separation of one-time resolution from the hot path. It adds no Xposed concepts to the kernel and does not require Java/Kotlin source, reflection in the interceptor, or a generic runtime. |
| Alternatives rejected | Treating a packaged Hooker as proof that a hook is installed; hidden reflective lookup per invocation; implicit exception mode; an unbounded generic reflection dispatcher; pretending an unretained HookHandle supports unhook; depending on legacy `XposedHelpers` or `assets/xposed_init`. |
| Structural evidence | `android_libxposed_hook_evidence.json` reproduces a 34,347-byte APK. The generated module DEX is 1,896 bytes; `onPackageReady` is 40 code units / 20 decoded instructions with one Hooker `new-instance`. The Hooker DEX is 672 bytes; `intercept` is 5 code units / 3 decoded instructions (`invoke-interface proceed`, `move-result-object`, `return-object`) with zero emitted hot-path allocations and no reflection strings. The shared 17,352-byte ELF keeps zero imports/`DT_NEEDED`/relocations. These are structural measurements only. |
| Limitation/falsification | Runtime module discovery, package-ready delivery, class-loader resolution, hook installation, interception, and original invocation are UNEXECUTED. The current profile supports only zero-argument pass-through and process lifetime; argument/result modification and explicit unhook require separate semantics/evidence. Revise the ABI/profile if current compatible libxposed runtime execution disproves any descriptor, ownership, or lifecycle assumption. |

## ADR-068 — API-102 hook mutation policies stay canonical and expose argument-array cost

| Field | Record |
|---|---|
| Decision | Keep pass-through, result-only, argument-only, and combined argument-then-result behavior as distinct content-addressed libxposed platform-policy carriers. The bounded result-only profile is exact zero-argument `String` return and emits no hot allocation. The bounded argument-only and combined profiles are exact `(String)->String`, argument index 0, and use API-102 `Chain.proceed(Object[])`; generated DEX explicitly allocates/stores one `Object[1]` per interception. The combined profile calls `proceed(Object[])` exactly once, captures the original result, then returns one constant replacement `String` without another allocation. |
| Rationale | Current API-102 exposes modified arguments through a replacement array rather than an in-place setter. Making that array explicit preserves XAX's no-hidden-allocation rule while the separate carrier identities prevent measured zero-allocation result/pass-through profiles from silently changing semantics. The combined profile supplies the controlled structural shape required to inspect/modify an argument, proceed once, inspect the result, and replace it. |
| Alternatives rejected | Claiming zero allocation for argument mutation; hiding `Object[]` creation in a helper/runtime; sharing one mutable argument array across invocations without concurrency/lifetime proof; silently composing independent policy carriers whose original semantic contracts differ; per-interception reflection/member lookup. |
| Structural evidence | `android_libxposed_combined_evidence.json` reproduces a 34,347-byte module APK. Install DEX is 1,952 bytes with a 51-code-unit `onPackageReady`, one install-time `Class[1]`, and one Hooker allocation. Hooker DEX is 852 bytes; `intercept` is 20 code units, reads arg0, performs one `Object[1]` allocation + store, invokes `proceed(Object[])` once, captures the original result, and returns `HookedResult`. Paired target `hookTarget(String):String` is one code unit. Runtime behavior and ART allocation counts are UNEXECUTED. |
| Falsification condition | Replace this lowering only if current libxposed runtime/API evidence provides a safe lower-allocation mutation mechanism or execution disproves the descriptor/chain assumptions. Any reusable-array optimization requires explicit reentrancy, concurrency, ownership, and lifetime proof before it can replace the one-array profile. |


## ADR-069 — Retained libxposed HookHandle lifetime is explicit and isolated from the hot Hooker

| Field | Record |
|---|---|
| Decision | Add `retained-manual-unhook` as a distinct canonical hook-installation lifetime beside the existing `process` lifetime. The process profile remains field-free and discards the returned HookHandle. The retained profile stores exactly one returned `HookHandle` in a private generated-module field and emits public `xaxUnhook()`: load the field; return if null; call `HookHandle.unhook()` once; clear the field; return. |
| Rationale | Unhook is lifecycle semantics and must not be inferred from a transient installation result. Keeping lifetime in the installation carrier makes retention explicit while keeping the interceptor hot path byte-identical. Clearing the field after unhook makes repeated generated `xaxUnhook()` calls perform no further framework work; framework-level idempotence remains a runtime property to validate. |
| Alternatives rejected | Pretending the process-lifetime profile supports unhook; retaining HookHandle in a hidden runtime/global map; adding lookup or lifetime checks to every interception; implicit finalizer/cleanup; changing Hooker identity merely because installation lifetime changes. |
| Structural evidence | `android_libxposed_unhook_evidence.json` reproduces a retained-profile APK and records a 2,016-byte generated module DEX with one instance field, one HookHandle store in `onPackageReady`, and an 11-code-unit `xaxUnhook()` opcode shape `iget-object / if-eqz / invoke-interface / const-null / iput-object / return`. The process profile remains 1,896 bytes, zero instance fields, and has no `xaxUnhook`; Hooker DEX SHA-256 is identical across both lifetime policies. Runtime unhook is UNEXECUTED. |
| Limitation/falsification | Real framework retention, unhook behavior, repeated-call idempotence, and process survival are not established until executed under a compatible current libxposed runtime. Revise if runtime behavior requires a different ownership/lifetime contract. |

## ADR-070 — libxposed deoptimization is explicit best-effort policy, not an implicit hook side effect

| Field | Record |
|---|---|
| Decision | Add a distinct content-addressed libxposed deoptimization carrier. The current bounded profile names the same zero-argument or one-`String` executable as a companion hook installation and has explicit `best-effort` result policy. Lowering reuses the already-resolved `Method`, calls API-102 `deoptimize(Executable)` exactly once before `hook(Executable)`, ignores the returned boolean exactly because the carrier says `best-effort`, and emits no deoptimization work in the Hooker hot path. |
| Rationale | Deoptimization affects ART execution and can hurt performance, so it must never appear merely because hooking is enabled. A separate policy keeps cost and semantics visible, avoids duplicate member resolution, and makes the currently ignored success boolean an explicit policy choice instead of an accidental compiler behavior. |
| Alternatives rejected | Automatically deoptimizing every hook; resolving the same `Method` twice; hidden retry/fallback after a false result; pretending a false result is success; inserting deoptimization in every interception; a generic Java helper/runtime. |
| Structural evidence | `android_libxposed_deopt_evidence.json` reproduces a 34,347-byte APK. The generated module DEX is 1,956 bytes; `onPackageReady` is 43 code units and has invoke order `loadClass`, `getDeclaredMethod`, `deoptimize`, `hook`. The deoptimization adds one 3-code-unit invoke and zero allocations. The Hooker remains a 5-code-unit pass-through with zero emitted allocation and contains no `deoptimize` string. Runtime ART deoptimization success remains UNEXECUTED. |
| Limitation/falsification | The bounded profile does not yet express separate caller sets or require-success/fallback semantics. Real API-102 execution must validate the boolean behavior and performance consequences before broader policy is added. |

## ADR-071 — libxposed framework/remote services are opt-in generated wrappers with propagating failures

| Field | Record |
|---|---|
| Decision | Add a distinct module-service carrier selecting only the libxposed services required by the semantic program. The current bounded set is framework name, framework version, remote preferences, remote file listing, and remote file open. Each selected service becomes one generated `XposedModule` helper containing one direct wrapper `invoke-virtual`, one object result move, and one object return. Remote failures use explicit `propagate` policy. |
| Rationale | Module preferences/files are external framework capabilities, not XAX kernel semantics and not justification for a generic Android runtime. Reachability-selected direct wrappers expose the current API with fixed cost while preserving framework exception behavior and avoiding hidden caching, retries, reflection, or service-manager layers. |
| Alternatives rejected | Bundling a general libxposed service runtime; eagerly generating every service; hiding `UnsupportedOperationException` or file-open failures; implicit caching; Java/Kotlin helper source; making SharedPreferences or ParcelFileDescriptor core XAX types. |
| Structural evidence | `android_libxposed_services_evidence.json` reproduces a 34,289-byte APK and a 1,664-byte generated module DEX. All five selected helpers are exactly 5 code units, each with one `invoke-virtual`, one `move-result-object`, one `return-object`, and zero emitted allocation opcodes. The DEX contains only the selected service surface and the required `SharedPreferences`/`ParcelFileDescriptor` target types. Runtime values and remote capability behavior remain UNEXECUTED. |
| Limitation/falsification | The direct wrapper carrier still does not expose framework properties/version code as a first-class result and does not consume ParcelFileDescriptor contents. Capability-gated remote-resource acquisition and bounded typed SharedPreferences reads are separate carriers under ADR-072; runtime service behavior remains unproven until compatible framework execution. |


## ADR-072 — libxposed remote resources are capability-gated; SharedPreferences remains a bounded read-only target contract

| Field | Record |
|---|---|
| Decision | Add separate content-addressed remote-preferences and remote-files carriers. Both use explicit `nullable-on-unsupported` capability policy and `propagate` supported-path failure policy. Generated acquisition helpers call `getFrameworkProperties()`, test `PROP_CAP_REMOTE = 1L << 1`, return null without a remote call when unsupported, and otherwise invoke the selected remote operation. The preferences carrier exposes only boolean/int/long/float/String/contains reads through direct `SharedPreferences` interface calls; it emits no `Editor`, write, apply, or commit path. The files carrier exposes only list/open. |
| Rationale | The upstream capability bit is semantically observable: calling a remote service without it is not equivalent to an unavailable value, and translating a supported-path failure into null would hide failure. Separate carriers keep capability policy, type surface, and reachability explicit without turning Android preferences/files into XAX kernel semantics or a generic service runtime. |
| Alternatives rejected | Calling remote services unconditionally and catching failure; hidden retry/fallback; eagerly creating a preference abstraction with writes; synthesizing Java/Kotlin helpers; implicit caching; interpreting null as every possible framework failure; always generating both preferences and file support. |
| Structural evidence | `android_libxposed_remote_preferences_evidence.json` reproduces a 34,289-byte APK and a 2,144-byte managed DEX. Its acquisition gate is 16 code units and each of six selected typed reads is 5 code units with zero emitted allocation; no Editor/write surface is present. `android_libxposed_remote_files_evidence.json` reproduces a 34,289-byte APK and a 1,428-byte managed DEX; both list/open gates are 16 code units, contain one capability mask/branch, two direct virtual calls, one null unsupported fallback, and zero allocation. Runtime capability values and remote operations remain UNEXECUTED. |
| Limitation/falsification | The current profile is intentionally read-only for preferences and returns nullable remote handles/files only at the acquisition boundary. ParcelFileDescriptor consumption, listeners, writes, and richer preference values require separate typed semantics. Real API-102 execution must confirm the capability bit, null unsupported behavior, and supported-path exceptions. |

## ADR-073 — API-102 hot reload uses stable hook identity plus atomic `replaceHook`, never an unhook/install gap

| Field | Record |
|---|---|
| Decision | Use a distinct `single-retained-hook-id-guarded-atomic-replace` carrier with `propagate` framework-failure policy, a canonical stable hook ID, explicit `skip-replacement` handle-mismatch policy, `package-ready-class-loader` saved-state policy, and `reject-reload` missing-state policy. It is legal only when min/target libxposed API are exactly 102, metadata contains exactly one Java entry, and the module owns exactly one generated `retained-manual-unhook` hook. Metadata adds `autoHotReload=true`. Initial installation calls `HookBuilder.setId(...)` and stores the `PackageReadyParam` target/app ClassLoader. `onHotReloading` returns false if that loader was never captured; otherwise it saves only the host-owned ClassLoader with `setSavedInstanceState`. `onHotReloaded` restores that loader, obtains `getOldHookHandles()`, returns if saved state or the list is absent, checks the sole old handle's `getId()` against the declared ID, returns on mismatch, otherwise creates one replacement generated Hooker, calls `HookHandle.replaceHook(...)` exactly once, and stores the returned handle into the existing retained field. |
| Rationale | API-102 exposes saved-state transfer, stable hook IDs, and atomic replacement. Preserving only the host-owned target ClassLoader gives the new generation the minimum lifecycle state needed for later bounded re-resolution without retaining module-generation objects. Stable ID validation prevents positional old-handle assumptions from replacing an unrelated hook, while `replaceHook` avoids an unhook/install gap. Missing package-ready state is rejected before the old generation exits; empty or mismatched new-generation transfer state becomes an explicit no-op; actual API/framework failures remain visible. |
| Alternatives rejected | `unhook()` followed by normal installation; silently replaying `onPackageReady`; rebuilding target reflection state without a preserved target loader; unconditionally replacing list index zero; saving module-defined state containers or HookHandles; inventing hidden retries; generic serialization; a generic reload runtime; process-global hook maps. |
| Structural evidence | `android_libxposed_hot_reload_evidence.json` reproduces a 34,347-byte APK. Managed DEX is 2,920 bytes. Initial package-ready installation includes `setId("xax.primary")` and stores the target ClassLoader. `onHotReloading` is 11 code units with one null-state rejection branch and one `setSavedInstanceState` call. `onHotReloaded` is 51 code units and restores the saved ClassLoader before one old-list emptiness guard, one `HookHandle.getId`, one `String.equals`, one ID-mismatch guard, one Hooker allocation, one `replaceHook`, and one store of the returned handle, with no new-array and no target-member reflection. Metadata is `minApiVersion=102`, `targetApiVersion=102`, `staticScope=true`, `autoHotReload=true`. Hooker bytes remain identical to the retained non-hot-reload baseline. Runtime saved-state transfer/reload/ID-transfer/atomicity remains UNEXECUTED. |
| Limitation/falsification | The profile still supports only one generated hook. It transfers only the host-owned target/app ClassLoader; package/process identity, listeners, threads, resources, and arbitrary external state are not migrated. Generalize to multiple hooks only with explicit unique IDs and deterministic matching. Revise the saved-state or transfer/mismatch policy if compatible runtime execution shows that framework validation, old-handle identity, or lifecycle differs from the API-102 contract. |

## ADR-074 — Universal replacement is reached by layering, not kernel growth

| Field | Record |
|---|---|
| Decision | XAX targets replacement of conventional languages by sufficiency for the software they build. The kernel stays approximately values, exact arithmetic, aggregates, control, calls, memory, resources, effects, atomics, target operations, and compile-time/meta. Every conventional model (closures, objects, traits, generics, async, exceptions, GC, RC, reflection, dynamic typing, strings, collections, actors, GPU kernels) is realized by compile-time construction, zero-cost libraries, or platform/ABI/target packages (`XAX_SPEC.md` §21.5–§21.6). A kernel addition requires an ADR showing the semantics cannot be expressed exactly at equal-or-better generated cost, verification precision, and AI tokens per change. |
| Rationale | Every kernel concept multiplies verifier, optimizer, target, and AI-protocol surface for every program. Libraries and packages are paid for only by programs that use them (FND-004/FND-010), so layering is the only route that scales from firmware to managed applications without imposing one domain's cost on another. |
| Alternatives rejected | Adding classes/async/exceptions/strings/GC objects to the kernel; one DSL per domain; a mandatory standard runtime; importing a host language's object model. |
| Runtime cost expectation | Zero for unused abstractions; requested abstractions cost exactly their explicit lowering. |
| AI/token expectation | Smaller kernel vocabulary and fewer verifier rules per edit; library-level concepts are queried only when used. |
| Falsification condition | A workload whose exact semantics or competitive generated code is measurably unattainable through layering. Then a kernel addition is admitted by ADR with that evidence. |

## ADR-075 — Replacement claims use cumulative R0–R6 levels derived from cited evidence

| Field | Record |
|---|---|
| Decision | Replacement capability is claimed per `(platform package, workload class)` at cumulative levels R0 semantic expressibility, R1 executable lowering, R2 platform interoperability, R3 practical application, R4 performance competitiveness, R5 AI efficiency, R6 autonomous maintenance. Each implemented claim carries one evidence label: PROVEN, EXECUTED, MEASURED, STRUCTURAL, PROTOTYPE, UNIMPLEMENTED. `XAX_REPLACEMENT_MATRIX.json` stores the per-platform record; `compiler/src/xax_replacement.py` derives levels from cited evidence and the test suite rejects overclaims, uncited labels, and missing evidence paths. |
| Rationale | Prose status tables drifted toward capability language. A derived level makes "supports platform X" impossible to state without the evidence that justifies it, and keeps the matrix cheap for an AI to update (one row, one field). |
| Alternatives rejected | Checkbox matrices in Markdown; maturity grades without evidence links; per-language rather than per-platform rows. |
| Runtime cost expectation | None (tooling only). |
| AI/token expectation | One compact JSON row per platform; validator diagnostics name the exact field. |
| Falsification condition | If levels cannot be meaningfully ordered for some platform class (e.g. R4 required before R2), split the workload class rather than weaken cumulativity. |

## ADR-076 — Hosted Windows uses a direct PE32+ container with explicit imports and explicit process exit

| Field | Record |
|---|---|
| Decision | Add target `x86_64-windows-pe-v1` (v5 operations plus `call_foreign`) and the `win64-c` foreign ABI. Foreign calls lower to `call [rip+disp32]`; the PE emitter (`xax_pe.py`) binds each to one loader-filled IAT slot, emits no startup stub, CRT, base relocations, or linker, and sets the entry point to the XAX entry function. Process exit is an explicit `ExitProcess` foreign call. Each foreign ABI is owned by exactly one backend: x86-64 rejects non-`win64-c` declarations and AArch64 rejects non-`android-aapcs64-c`; raw load images reject foreign imports. `x86_64-windows-load-image-v5` stays byte-identical. Stack pointers passed to foreign calls are materialized with one `lea` only at the escaping call site. |
| Rationale | PE/import infrastructure is the smallest high-leverage step from "harness-loaded raw image" to a deployable hosted artifact with dynamic library calls, and it is executable on the current host. Returning from a PE entry does not terminate a process whose loader worker threads remain alive (observed: hang), so an implicit exit would be a hidden lifecycle operation; the explicit call keeps it visible. |
| Alternatives rejected | Emitting a container-owned exit stub; linking via an external linker; CRT startup; treating `android-aapcs64-c` declarations as ABI-neutral; materializing every stack address eagerly. |
| Runtime cost expectation | Zero container code; one indirect call per foreign call (platform-required import binding). |
| Executed evidence | At U1.1 (since regenerated for U1.2a, see `XAX_STATE.md`) `compiler/benchmarks/windows_pe_hosted_evidence.json` recorded: 2,048-byte PE, 918 code bytes, six kernel32 imports, stdout `XAX\n`, exit 57, 20/20 runs on Windows 11 x86-64. Code is from the existing spill-every-value frame lowering; no code-quality claim. |
| Falsification condition | Revise if a PE feature required by a real application (TLS callbacks, SEH/unwind tables, exports, resources) cannot be derived from explicit contracts without a container-owned runtime. |

## ADR-077 — Next milestone is U1, a five-domain replacement proof, ordered by shared infrastructure

| Field | Record |
|---|---|
| Decision | After M14 the roadmap continues with U1 (`XAX_IMPLEMENTATION_ROADMAP.md`): a hosted native application, a bare-metal program, a WebAssembly/WASI or browser application, an Android application, and an accelerator workload, all from XAX semantics, each recorded in the replacement matrix. Work is ordered by how many matrix rows it unblocks: (1) executable containers + import binding (PE done; ELF executable next), (2) register-allocating frame lowering and foreign-heap memory access on x86-64, (3) wasm imports/WASI, (4) a generic metadata importer producing foreign-declaration packages, (5) a real GPU target package with physical execution. |
| Rationale | Containers, ABI binding, and memory access are shared by every hosted platform; a stronger optimizer is shared by every target. Domain-specific features without these unblock one row at most. |
| Alternatives rejected | Starting with JVM/.NET/Apple containers before generic import/ABI machinery; custom GPU runtime before a real device target; broad optimizer search before register allocation. |
| Falsification condition | Reorder when matrix evidence shows a later item unblocks more rows or a dependency was misjudged. |

## ADR-078 — Priority order refined for universal replacement

| Field | Record |
|---|---|
| Decision | Adopt the universal-replacement mission order: semantic correctness → AI tokens per successful change → AI generation reliability → runtime performance → memory footprint → binary footprint → compilation quality → portability → deterministic behavior → toolchain simplicity → human usability. Deterministic *interpretation of meaning* remains inseparable from semantic correctness (ADR-003 rank 2 stays directly below it); the mission's "deterministic behavior" rank refers to reproducible builds and tooling. `XAX_SPEC.md` §1 and the architecture §1 table state the merged order. |
| Rationale | The mission separates footprint and compilation-quality ranks that ADR-003 grouped, and places build reproducibility below portability. Keeping semantic determinism at the top avoids weakening exact meaning, which every other rank depends on. |
| Alternatives rejected | Moving semantic determinism to rank 9 (would allow nondeterministic meaning for performance); leaving the two orders unreconciled. |
| Runtime cost expectation | None directly. |
| AI/token expectation | None directly. |
| Falsification condition | A conflict case where this order selects a design that the mission order (read literally) would reject and evidence favors the literal reading. |

## ADR-079 — Pointer-free memory-effect interfaces are pure ordering frontiers

| Field | Record |
|---|---|
| Decision | A direct call whose callee interface carries `effect<memory>` values but no pointer and no stack owner is accepted without a fixed stack resource-call contract. The caller's input memory effect is consumed linearly; the returned effect carries no storage facts. Interfaces that include pointers or stack owners keep the existing bounded contracts. |
| Rationale | Without a pointer, the callee cannot reach caller storage under the provenance model, so the effect is only an ordering token. The previous rule rejected every effect-bearing call, which made a function that allocates and frees its own heap data uncallable. |
| Alternatives rejected | Adding a new kernel call-contract kind; erasing memory effects from calls (would hide ordering); inferring facts through the call. |
| Runtime cost expectation | None (proof values erase). |
| Evidence | `tests/test_xax_pe.py`: `squares_sum(mem)` (VirtualAlloc, heap view, two loops of checked heap accesses, VirtualFree) is called from the PE entry and executes; a forked effect into two such calls rejects (`RESOURCE-LINEAR-CONTINUATION`/`MEMORY-EFFECT-LINEAR`). |
| Falsification condition | A pointer-free path through which a callee can observe or mutate caller storage (e.g. a future global/static storage model) would require extending the rule. |

## ADR-080 — WASI is a wasm32 target package with explicit module imports and an explicit `proc_exit`

| Field | Record |
|---|---|
| Decision | Add `wasm32-wasi-v1` (general wasm32 operations plus `call_foreign`) and the `wasm32-import` foreign ABI, whose declaration `library`/`name` are the wasm import module/field. Imports occupy the first function indices in deterministic `(module, field)` order; the module exports `_start` (entry must have no machine parameters or results) and `memory`. Exit is the program's explicit `proc_exit` call. `wasm32-core-module-v2` bytes are unchanged. Target operation lists are canonicalized by sorting at construction. |
| Rationale | WASI is the smallest standardized system interface for wasm and runs on this host (Node `node:wasi`), so it gives EXECUTED host-interop evidence without JavaScript glue. |
| Alternatives rejected | Generated JS glue for WASI; a XAX-owned `_start` wrapper calling `proc_exit` implicitly; reusing the `entry` export name. |
| Evidence | `compiler/benchmarks/wasi_command_evidence.json`: 451-byte module, imports `args_sizes_get` and `proc_exit`; the host writes argc/argv-size into XAX stack storage and XAX reads them back; exit 97 on 10/10 runs (Node v26.7.0). |
| Falsification condition | Revise if WASI preview2/component-model hosts require a container shape that cannot be derived from explicit imports. |

## ADR-081 — `pointer_address`: explicit, one-way provenance exposure

| Field | Record |
|---|---|
| Decision | Add memory-family operation `pointer_address` (id 66): one pointer operand, one `bits<32|64>` result, one attribute that MUST be 1 (provenance exposed). If the pointer carries a local storage fact the storage must be live. The result is a plain integer: there is no verified integer-to-pointer operation, so exposure never manufactures provenance. Backends require N to equal the target pointer width (x86-64: 64, wasm32: 32). The reference executor rejects it (addresses are target facts). Foreign declarations that read through exposed addresses take the reached storage's memory effect as an additional input/output so lifetime ordering is verifier-visible (`wasi_preview1_api.fd_write`). |
| Kernel admission (`XAX_SPEC.md` §21.5) | Not expressible with existing primitives: `pointer_cast` keeps pointer types and elements, memory elements are byte-addressable scalars only, and no other operation yields an address value. Without it, any platform API whose arguments are structs containing addresses (WASI iovecs, Win32/POSIX struct-of-pointer APIs, MMIO descriptor rings, DMA descriptors) is inexpressible. Cost: zero bytes on x86-64 stack values (`lea`), zero instructions on wasm32 (pointer already an i32). |
| Alternatives rejected | Pointer-typed memory elements now (requires provenance-carrying reloads, typed mixed storage, and lifetime coupling — the open half of OI-37); a raw integer-to-pointer operation (would create unverified provenance); implicit exposure on foreign calls (hidden). |
| Evidence | `compiler/tests/test_xax_wasi.py`: a WASI module writes `XAX\n` to stdout through `fd_write` with an iovec holding an exposed message address; exit 97 on 10/10 runs under Node v26.7.0 (`wasi_command_evidence.json`, 635-byte module). Negative vectors: missing waiver (`MEMORY-ADDRESS-EXPOSE-WAIVER`), exposure after storage end (`MEMORY-LIFETIME-LIVE`). |
| Falsification condition | If verified provenance-carrying pointer stores (OI-37) subsume every use, `pointer_address` remains only for genuinely address-valued interfaces (MMIO/DMA/ABI structs). |

## ADR-082 — Provenance-free pointers may live in memory; local-provenance pointers may not (yet)

| Field | Record |
|---|---|
| Decision | Memory elements may be pointer types. An access of a pointer element has size 4 or 8 in the verifier and must equal the target pointer width in the backend (`NATIVE-POINTER-ELEMENT-WIDTH`). Stores (plain and checked) accept only values without a local storage fact; storing a stack/heap-view pointer rejects with `MEMORY-POINTER-STORE-LOCAL-PROVENANCE`. Reloaded pointers carry no facts, so they can be passed to foreign calls or used by `call_indirect` under a bounded CallContract, but never dereferenced through verified memory operations. The reference executor rejects pointer elements (`EXEC-MEMORY-SCALAR`). |
| Rationale | Function addresses and external pointers cannot dangle relative to XAX-owned storage, so no lifetime coupling is required and the change adds no proof state. It makes dispatch tables (the §21.6 lowering of interfaces/traits) expressible without a kernel object model. Linked structures over XAX storage use arena + index, which is already verifiable and position-independent. |
| Alternatives rejected | Allowing any pointer store and dropping facts (dangling local pointers would escape lifetime checks); a full provenance-carrying store model now (needs typed mixed storage and container/referent lifetime coupling — remaining OI-37 work); a vtable kernel concept. |
| Runtime cost expectation | One machine word per stored pointer; table dispatch costs one load + one indirect call. |
| Evidence | `compiler/tests/test_xax_pe.py::_dispatch_table`: two function addresses stored into stack memory, reloaded by checked dynamic-offset loads, and called with `call_indirect`; `add1(10) + times3(10) = 41` contributes to the PE exit code 1339 (20/20 runs, `windows_pe_hosted_evidence.json`). Negative: storing the table's own stack address rejects. |
| Falsification condition | A workload needing pointer-linked XAX-owned storage whose arena/index form is measurably worse in code size, speed, or AI tokens per edit; that would justify the coupled-provenance design. |

## ADR-083 — Hosted x86-64 extends the register-resident allocator instead of rewriting frame lowering

| Field | Record |
|---|---|
| Decision | For `x86_64-windows-pe-v1` only, the existing per-block register-resident allocator (next-use spilling, parallel edge moves) additionally lowers `int_compare` (32/64-bit, `setcc` into any register), `call_foreign` (IAT call with Win64 shadow space), `function_address`, `heap_view` (null trap), heap `address_offset`/`pointer_cast`/`pointer_address`, and static/checked heap loads/stores (`[base]`, `[base+index]` after an unsigned bound check). Values used outside their defining block get one frame home written at definition (dominance orders the write first). Functions with stack storage, floats, aggregates, or indirect calls stay on the frame path (with the store→load forwarding peephole). Legacy load-image profiles keep their pinned bytes. |
| Rationale | The register-resident allocator already existed and was verified on arithmetic/branches/calls; widening its operation set was the shortest path to register-allocated hot loops without regenerating evidence for every legacy target. |
| Alternatives rejected | Rewriting the frame lowering as a global allocator in one step (large risk, invalidates pinned evidence); keeping the peephole only. |
| Measured | `compiler/benchmarks/x86_register_path_evidence.json`: the same verified `sum_to` graph, 200,000,000 iterations, 7 runs, Windows 11 AMD Family 25: frame path 433 code bytes, median 738.7 ms; register path 89 code bytes, median 92.1 ms (8.02x). Hosted PE fixture code 2,181 → 1,269 bytes (−42%), PE 3,584 → 2,560 bytes, still exit 1339 on 20/20 runs. Intra-XAX comparison only; no external C/Rust baseline. |
| Falsification condition | Replace with a global allocator when stack-storage/float/aggregate-heavy functions dominate measured hosted workloads. |

## ADR-084 — Exact integer completion admits six operations and rejects shifts and sign extension

| Field | Record |
|---|---|
| Decision | Add `bit.and` (67), `bit.or` (68), `udiv` (69), `urem` (70), `int.truncate` (71), and `int.zero_extend` (72). Binary operations take two `bits<N>` operands and return `bits<N>`; width operations require strict narrowing or widening. A zero divisor executes a trap with new portable reason 2 (`integer-divide-by-zero`); lowering omits the check when the divisor is a nonzero constant. Do not add shift or sign-extension operations. |
| Kernel admission (`XAX_SPEC.md` §21.5) | AND, OR, and division have no exact composition at equal cost from add/sub/mul/xor/rotate: bitwise composition needs per-bit loops, and division needs a loop. Width changes had no expression except a store/load round trip through memory. Shifts by constants are exactly `mul.wrap 2^k` and `udiv 2^k`, and sign extension is `(zext(x) xor m) - m`, so admitting them would duplicate existing mechanisms; single-instruction selection is a lowering concern (OI-39). |
| Alternatives rejected | Signed division/remainder (deferred until a workload needs them); variable shifts with hardware-specific masking; returning an unspecified value for a zero divisor. |
| Evidence | Verifier, reference executor, and x86-64 lowering EXECUTED (`compiler/tests/test_xax_linux.py`, `test_xax_regalloc_differential.py`). Only the Linux target packages advertise the operations; every other target identity and committed artifact is unchanged. |
| Falsification condition | Admit `shl`/`lshr`/`ashr`/`int.sign_extend` if measured token cost or repair rate for the compositions is materially worse, or if lowering cannot select them reliably (OI-39). |

## ADR-085 — Linux syscalls are `linux-x86_64-syscall-v1` declarations carrying an explicit register template

| Field | Record |
|---|---|
| Decision | Add the foreign ABI `linux-x86_64-syscall-v1`, owned by the x86-64 backend on Linux profiles only (ADR-076 ownership rule). A declaration has library `linux` and a canonical name `nr` or `nr:arg,...`, where each `arg` is `$k` (the k-th machine operand, each used exactly once) or an unsigned 64-bit literal. Arguments go in `rdi, rsi, rdx, r10, r8, r9`; the result is the exact 64-bit `rax`. With an allocator contract, `-4095..-1` projects to the nullable zero pointer, and `heap_view` traps on null. |
| Rationale | Syscalls are the smallest hosted boundary: no libc, loader, or runtime. Fixed arguments in the declaration identity make contracts such as "anonymous private mapping, zero-filled" sound without trusting caller operands, and leave lowering with no unstated tables. |
| Alternatives rejected | A syscall kernel operation (OS concept in the kernel); a name-to-number table in the backend; libc wrappers as a mandatory runtime. |
| Evidence | EXECUTED (`compiler/tests/test_xax_linux.py`); negative vectors cover non-canonical templates, duplicate or missing operands, more than six arguments, and unknown ABIs. |

## ADR-086 — Linux x86-64 executables are direct ELF64 `ET_EXEC` whose entry point is the XAX entry function

| Field | Record |
|---|---|
| Decision | Add target `x86_64-linux-elf-exec-v1` (architecture 1, ABI 5, image format 5). The emitter (`xax_linux.py`) writes one R+X `PT_LOAD` at `0x400000` and a `PT_GNU_STACK` R+W marker, with no section table, interpreter, dynamic section, relocations, or added code. `e_entry` is the XAX entry function. As on Windows (ADR-076), the program ends the process with an explicit `exit_group` declaration. Linux enters `e_entry` with RSP 16-byte aligned and no return address, so the entry function is lowered as a *process entry*: its frame is laid out for that alignment, it saves no callee-saved registers, and its `ret` lowers to `ud2`. A program that returns instead of exiting therefore traps deterministically, never jumping to a garbage address and never exiting implicitly. |
| Rationale | Linux execution was runnable on the development host and exercises allocation, I/O, control flow, and data structures end to end. Applying ADR-076's no-container-code rule keeps lifecycle uniform across PE and ELF. The alignment difference is an ABI fact of the entry function, not container code. |
| Alternatives rejected | A generated entry adapter that calls `exit_group` after the entry returns (an implicit exit; superseded during the merge with ADR-076); linking with libc or an external linker. |
| Evidence | EXECUTED and MEASURED on Linux 6.18 x86-64 (`u1_linux_filestat_evidence.json`); `test_returning_entry_traps_instead_of_exiting` checks the trap. |
| Falsification condition | argv/env/auxv access (OI-33), TLS, or signals requiring container-owned startup code would force a revision. |

## ADR-087 — Shared-library calls require the explicit-loader profile and are bounded to the INTEGER-class SysV C ABI

| Field | Record |
|---|---|
| Decision | Add the foreign ABI `sysv-x86_64-c` (library = soname, name = symbol) and target `x86_64-linux-elf-dynexec-v1` (image format 6). Only this profile lowers C imports; the static profile rejects them rather than adding a loader silently. The ELF gains `PT_PHDR`, `PT_INTERP` (`/lib64/ld-linux-x86-64.so.2`, fixed by the profile identity), and `PT_DYNAMIC`, with `DT_NEEDED` exactly for the declared sonames, `.dynsym`/`.dynstr`/SysV hash/RELA in the R+X segment, and the dynamic table plus GOT in a congruently mapped R+W segment, under `DF_BIND_NOW`/`DF_1_NOW` with one `R_X86_64_GLOB_DAT` per import. Calls use main's `call_import` path (`call [rip+slot]`) with at most six INTEGER-class arguments and one INTEGER-class result. Generic ELF byte packing lives in `xax_elf.py`, shared with the Android emitter. |
| Rationale | `XAX_SPEC.md` §12.5 requires an explicit dynamic-loader capability and an explicit dependency request; a separate profile puts both in target identity, and deriving `DT_NEEDED` from declarations keeps every dependency program-visible. Bind-now avoids lazy-binding trampolines. |
| Alternatives rejected | Implicit `PT_INTERP` when imports appear; lazy PLT binding; a libffi-style generic call path; libc as a default dependency. |
| Evidence | EXECUTED: `libz.so.1` `crc32` called from XAX (`test_external_library_call_executes`). MEASURED: `u1_linux_filestat_evidence.json` (per-chunk `crc32`). Android ELF bytes are unchanged after the `xax_elf.py` extraction. |
| Limitation | ELF symbol lookup is global, so the declared library is a load dependency, not a direct binding; duplicate symbol names across libraries reject. No callbacks, floats, aggregates, stack arguments, variadics, or symbol versioning (OI-40). |

## ADR-088 — Linux frame lowering treats every pointer as a machine value

| Field | Record |
|---|---|
| Decision | On Linux profiles the frame (spill) path, in addition to main's heap-view handling (U1.2a), materializes frame pointers that escape into calls, edges, returns, or stores once at their definition. It also addresses pointers that are neither frame-resident nor heap-view-derived (parameters, call results, block parameters) through a base register, with exact 1/2/4/8-byte and `[base+index]` checked access. Legacy and PE profiles are unaffected. |
| Rationale | Hosted programs pass addresses to the platform and between functions; pointers that arrive as values otherwise had no lowering. Gating by profile keeps every committed artifact identical. |

## ADR-089 — Linux uses a separate register-resident allocator module; convergence with ADR-083 is tracked

| Field | Record |
|---|---|
| Decision | `xax_x86_64_regalloc.py` lowers Linux-profile functions first. It allocates per block over 14 registers (callee-saved pushed only when used), uses dominance-crossing home slots, and rematerializes constants with exact imm32 folding (64-bit operands only below 2^31). It fuses a compare consumed only by its block's branch into `cmp`+`jcc`, reuses an identical in-block bounds check, applies power-of-two strength reduction (`shl`/`shr`/`and`), and spills everything across calls. Ineligible functions fall back to the frame path. ADR-083 extends the legacy allocator for the PE profile instead; the two are deliberately kept separate during this merge and converge under OI-38. |
| Rationale | The two allocators were developed in parallel. Merging them in place would regenerate committed PE evidence without new measurements. The Linux module is self-contained and validated independently. |
| Evidence | MEASURED (`u1_linux_filestat_evidence.json`): `filestat` went from 5.9× to 0.95–1.14× `gcc -O2` (1.41–1.82× `clang -O2`, the fastest baseline) across seven 31-repetition runs, with a 3,560-byte artifact. Validation: `test_xax_regalloc_differential.py` runs 120 seeded random programs (DAGs and counted loops, all integer operations, compares, width changes, boundary and power-of-two constants) natively and compares every 64-bit result with the reference executor; 1,320 matched across eleven seeds during development. |
| Falsification condition | Merge into one allocator when either profile's design is measured strictly better on both workloads (OI-38). |

## ADR-090 — Arena + index links are measurably slower; OI-37 pointer provenance is justified but sequenced after OI-38

| Field | Record |
|---|---|
| Decision | The ADR-082 falsification condition ("a workload needing pointer-linked XAX-owned storage whose arena/index form is measurably worse in code size, speed, or AI tokens per edit") is met for **speed** on a chained hash table. The coupled-provenance pointer design (OI-37 remainder) is therefore justified. It is sequenced **after** OI-38, because code generation is the larger measured factor and benefits every workload. Arena + index remains the verified representation until then. |
| Evidence | `compiler/benchmarks/oi37_chains_evidence.json` (`linux_chains.py`, two 31-repetition runs on Linux 6.18 x86-64): 2^20 inserts into 2^16 buckets, then 2^20 successful lookups (9,437,420 node visits). The XAX artifact (1,598 B) runs 3.49–3.58× `gcc -O2` (pointer links) and 3.67–3.79× the fastest baseline. Same-run diagnostic C twins attribute the gap: index links instead of pointers 1.44–1.47×, bounds checks equivalent to XAX's checked access 1.34–1.41×, and XAX code generation over the equivalent checked-index C 1.73–1.80×. Peak RSS: XAX 16,896 KiB vs 18,272 KiB `gcc -O2`. |
| Rationale | Comparing C to C isolates the representation cost from XAX's backend, so the OI-37 question is answered independently of current code quality. |
| Consequences | OI-38 (allocator convergence, cross-block allocation, LICM) is next. OI-37 then needs node-typed provenance whose extent and lifetime make both the index scaling and the per-access bounds check unnecessary. Removing only the scaling would leave the 1.34–1.41× check cost. |

## ADR-091 — Linux allocator: pinned cross-block values, fall-through layout, cold trap stubs (OI-38 step 1)

| Field | Record |
|---|---|
| Decision | `xax_x86_64_regalloc.py` gains five deterministic, local changes. (1) A cross-block value used in a block on a CFG cycle is *pinned*: it owns one of `rbx, rbp, r12–r15` from its definition to the end of the function, ranked by cycle-weighted use count. Edges write pinned block parameters directly, and calls do not spill pinned values. (2) A conditional branch falls through to the next block when that edge needs no copies; otherwise its copies move to an out-of-line stub. Jumps to the next block are omitted. (3) Bounds, null-view, and zero-divisor checks branch to shared out-of-line trap stubs, so a passing check is a not-taken branch. (4) `udiv`/`urem` by any power of two become `shr`/`and` (64-bit masks through `r11`). (5) Loop headers (targets of backward edges) are padded to 16 bytes with recommended NOPs. Allocator convergence with ADR-083 remains open. |
| Invariant | A pinned register must survive every Linux call kind. SysV C callees preserve `rbx, rbp, r12–r15`, and syscalls clobber only `rax, rcx, r11`. XAX callees either never name these registers (frame and legacy paths use only the target's volatile registers plus `rdi/rsi` for call arguments) or save them (this allocator). The differential corpus adds 40 programs whose loops call earlier programs while values are pinned. |
| Evidence | MEASURED, one 31-repetition run each on the §15 host. `chains`: XAX 0.461 s = 1.91× `gcc -O2`, down from 3.49×. XAX vs equivalent checked-index C is 1.06×, down from 1.80×, so the remaining gap is representation (1.47×) and checks (1.22×), i.e. OI-37. `filestat`: 0.94× `gcc -O2`, 1.47× `clang -O2`. Artifacts: 1,352 B and 3,400 B. Ablation on `chains` (7-repetition probes): pinning, layout, and shift strength reduction gave about 0.98 → 0.70 s. Cold trap stubs gave 0.70 → 0.46–0.54 s; alignment alone was within noise. |
| Rationale | Every bounds check that jumped over its own `ud2` put an always-taken branch on the hot path. That cost more than any register traffic. |
| Consequences | OI-37 coupled provenance is now the larger lever on pointer-chasing code. OI-38 remains open for allocator convergence with the PE profile, cross-block allocation of values not on cycles, and redundant-check elimination by range facts (for example `node + 8` after a checked 16-aligned `node`). |

## ADR-092 — `pointer_rebase`: verified reload of an exposed address inside a live view

| Field | Record |
|---|---|
| Decision | Add memory-family operation `pointer_rebase` (id 73). Operands: a view pointer with a local storage fact, and a `bits<32|64>` address (backend: the target pointer width). Attribute: node extent E. The result keeps the view's address space and element, never gains permission, and has alignment no greater than the view's. It carries the view's storage, lifetime, and alias class, with extent E. At run time the address must lie in [view, view + extent(view) − E] and be aligned to the result alignment relative to the view, or the program traps. The verifier records the unknown position as a window. Windowed loads must find the whole window initialized; windowed stores add no initialized interval. Atomics, heap-call contracts, and view-base rules reject windowed pointers. Storing a link needs no new operation: it is `pointer_address` (explicit exposure, ADR-081) followed by an ordinary integer store. The reference executor and x86-64 frame lowering reject the operation explicitly. The Linux register allocator lowers it to `mov; sub; ror log2(A); cmp; ja cold-trap`. |
| Kernel admission (`XAX_SPEC.md` §5.6, §21.5) | Not expressible with existing primitives. Checked loads take only a dynamic *offset* and re-check every access; no operation narrows a view to a dynamically positioned sub-view. Without it, a linked structure pays index scaling on the critical path plus a check per field access. Provenance is not manufactured: the result can only name storage the view already proves live. Typed storage is not required, because a forged or stale address traps instead of escaping the view. |
| Alternatives rejected | Typed mixed storage with check-free reloads (a typed-memory model, larger kernel: still open under OI-37); raw integer-to-pointer (unverified provenance); dropping the alignment test (would weaken the verifier's alignment fact). |
| Evidence | MEASURED (`oi37_chains_evidence.json`, one 31-repetition run; host stdev 13–25%). Pointer-linked `chains` runs at 1.64× `gcc -O2` and 1.07× C carrying the same check. Index links run at 2.00×, so pointer links are 1.22× faster. In C, the check costs 1.52× on pointers and the index representation 1.41×. The remaining gap to unchecked C is the check, not code generation. Probe runs placed the pointer arm at 0.38–0.45 s, against 0.38–0.41 s for checked-pointer C. Executed vectors (`test_xax_pointer_rebase.py`): in-range offsets 0/8/48 exit 41; offsets 56, 64, 4, 2^64−8, and 2^40 trap with SIGILL. Verifier rejections: `MEMORY-REBASE-EXTENT`, `-ALIGNMENT`, `-NO-AUTHORITY-GAIN`, `-ADDRESS-WIDTH`, `MEMORY-LIFETIME-LIVE`, and `MEMORY-INITIALIZED` for both windowed loads and windowed stores. |
| Consequences | ADR-081's statement that no verified operation turns an exposed address back into a pointer is narrowed: only `pointer_rebase`, only inside a live view. OI-37 stays open. Remaining: check-free reloads (typed storage proving every stored link valid), a second target with a different pointer width (wasm32), and AI tokens per edit. |

## ADR-093 — `pointer_rebase` on wasm32; wasm storage never starts at address 0

| Field | Record |
|---|---|
| Decision | `wasm32-wasi-v1` admits operation 73. Lowering: `local.get address; local.get view; i32.sub; i32.const log2(A); i32.rotr; i32.const span>>log2(A); i32.gt_u; if unreachable end`. That is the same single unsigned compare as x86-64, at the 32-bit pointer width. The wasm static layout now reserves bytes 0–15 (`_NULL_GUARD_BYTES`), so no storage address equals 0 and 0 can terminate links. Before this, the first stack allocation lived at address 0, where its exposed address was indistinguishable from a null link. |
| Evidence | EXECUTED (`compiler/tests/test_xax_wasm_rebase.py`, Node v22.22.0 `node:wasi`). A WASI command builds a three-node list in stack storage with exposed-address links and walks it through `pointer_rebase`, exiting 42 (5 + 7 + 30). First links that are out of range (+24), misaligned (+4), below the view (−8), or wrapped (+2^31) trap with `unreachable`. With x86-64 Linux (ADR-092) this gives one representation executing on 64- and 32-bit pointer targets. No existing test pins wasm module bytes. `wasi_command_evidence.json` is regenerated (new target identity and layout). |
| Consequences | OI-37 closure still needs check-free reloads and the AI tokens-per-edit measurement. Measuring verifier cost is folded into that token pass. |

## ADR-094 — Linux argv/env/auxv through an inline startup ABI, not a kernel extension

| Field | Record |
|---|---|
| Decision | Add foreign ABI `linux-x86_64-startup-v1`, owned by the Linux x86-64 profiles, with seven declarations (`argc`, `arg_length`, `arg_copy`, `envc`, `env_length`, `env_copy`, `auxv_value`). The Linux register allocator lowers them inline, reading the initial stack the kernel built at `rsp + frame size` in the process entry function. They are rejected anywhere else, and the frame path rejects them through ABI ownership. Copies land in program-owned views under the memory effect, are clamped to the destination's static extent, and return the bytes copied. Indexes outside `argv`/`envp` trap. |
| Kernel admission | None needed: these are foreign declarations, the same mechanism as `linux-x86_64-syscall-v1` and WASI `args_get`. The kernel and verifier are unchanged. |
| Alternatives rejected | An entry parameter exposing the initial stack as a view (needs dynamic-extent views: kernel growth). Reading `/proc/self/cmdline` and `environ` (depends on procfs; not equivalent to argv in chroots or containers). Container startup code that copies argv (violates ADR-076, no container code). |
| Evidence | EXECUTED (`compiler/tests/test_xax_linux_startup.py`, 6 tests). An `echo`-style process prints `alpha`, the empty string, `two words`, and a 5,000-byte argument clamped to its 4,096-byte view, then exits with argc 5. `arg_length` reports 300 for a 300-byte argument. Environment entries print exactly, and envc is returned. `auxv_value(AT_PAGESZ)` is 4096 and an absent type returns 0. Out-of-range argument and environment indexes trap with SIGILL. A startup read in a called function rejects with `LINUX-STARTUP-PROCESS-ENTRY`. Full suite: 796 passed, plus the 17 pre-existing failures. |
| Consequences | The Linux process-entry contract now covers command-line tools. TLS and unwind/debug data remain open under OI-33. Existing syscalls still trust caller-supplied lengths against view extents; the startup copies do not. |

## ADR-095 — One register allocator for the hosted x86-64 profiles (OI-38 convergence)

| Field | Record |
|---|---|
| Decision | `x86_64-windows-pe-v1` uses `xax_x86_64_regalloc.py` first, like the Linux profiles. The allocator gains: Win64 `call_import` with arguments past the fourth stored above the shadow space; `function_address` (`lea reg, [rip+fn]`); `call_indirect` (`call rax`); and stack storage, laid out in the frame with pointers rematerialized by `lea` like constants. Foreign ABIs are owned per profile (PE: `win64-c`; Linux: syscall, SysV C, startup), and any other ABI rejects with `XAX.FOREIGN.ABI`. The legacy allocator (ADR-083) and frame lowering remain only as fallbacks for functions this allocator cannot lower (floats, aggregates, alignment over 16) and for the byte-stable raw load-image profiles. |
| Bug fixed | A function returning a constant that was not in a register loaded `[rsp + constant]` instead of the constant. Only process-entry exits had hit it, where it was harmless. `HandcraftedLoweringTests` now covers constant returns, stack storage, function addresses, and indirect calls on Linux. |
| Evidence | All six functions of the PE hosted fixture now take this allocator, versus 0 of 6 before ADR-095 (ADR-083 handled them). Code is 700 bytes, down from 1,269, and the PE is 2,048 bytes, down from 2,560. EXECUTED-UNDER-WINE (`windows_pe_wine_evidence.json`, Wine 9.0, 20 runs): stdout `XAX\n`, exit 1339 mod 256 = 59. Wine is not Windows, and `windows_pe_hosted_evidence.json` remains the Windows-host record for its own (older) bytes. The Linux differential corpus (160 programs) and every Linux test are unchanged. `chains` evidence was regenerated for the 2-byte exit-path change. |
| Consequences | OI-38 is narrowed to: floats and aggregates in the allocator (then deleting the hosted use of the legacy path), range-based check elimination, and LICM. Re-executing on a real Windows host is still needed to refresh the Windows-host record. |

## ADR-096 — Close OI-37 on `pointer_rebase`; open OI-41 for check-free reloads

| Field | Record |
|---|---|
| Decision | OI-37 is closed. Its closure criteria are met by `pointer_address` (ADR-081), provenance-free pointer elements (ADR-082), and `pointer_rebase` on x86-64 Linux and wasm32 (ADR-092/093), with the negative vectors listed in the issue, measured verifier cost, and offline edit-token cost (`oi37_closure_evidence.json`, `bench_oi37_closure.py`). Removing the per-link check is a separate performance question that needs kernel growth (typed mixed storage), so it is tracked as OI-41. |
| Stated deviation | The wasm32 traversal uses stack storage because that profile has no heap allocator; the representation and the checks are the same as on x86-64. |
| Evidence | Verifier: 47.9 µs per rebase+load against 46.8 µs per checked load; `chains` verifies in 2.7 ms (pointer) and 2.6 ms (index). Edit: 4 rewritten objects, 4,458 bytes, 4,198 o200k hex tokens; an 11-operation delta of 87 o200k tokens. Performance (`oi37_chains_evidence.json`, one 31-repetition run): pointer links 1.58× `gcc -O2` and 1.05× checked-pointer C. |
| Consequences | PE does not yet lower `pointer_rebase` (its target operation set omits 73). |

## ADR-097 — Record links: verified link fields make pointer reloads check-free (closes OI-41)

| Field | Record |
|---|---|
| Decision | **Type `link`** (form 11): an 8-byte scalar on every target, whose only constant is null. **Record views**: a view whose element is a tuple of whole-byte bits, float, or link fields is a record array; its extent must be a whole number of records. `address_offset` from a record pointer either moves by whole records or lands exactly on a field, and a field pointer's extent is that field. **`link_make`** (74) turns a record-start pointer into a link. **`link_follow`** (75) takes the storage's whole record view and a link, and yields a record pointer (one record extent, window over all records) after only a null test, which the backend elides when every edge into the block tested the link against null. **Link targets**: a storage's link fields point into itself, or into the record view named by an optional fourth `heap_view` operand, fixed at creation. A borrowed view's target is unknown, so it can neither store nor follow links. **Integrity rules**: a store into a link field takes only null or a link into that field's target; foreign calls may not receive a link-bearing storage's memory effect except to deallocate it; atomics may not write link fields; checked dynamic-offset accesses cannot reach record elements; a link target must outlive the storages that target it; links compare only for (in)equality. These rules make every loaded link null or a record start of a known live storage, which is why the follow needs no range check. The reference executor and frame lowering reject the operations explicitly. |
| Kernel admission (§21.5) | `pointer_rebase` must re-check because storage bytes are untyped: any integer store can forge an address. Typing link fields is the minimal change that removes the check. Growth: one type form, two operations, one optional `heap_view` operand, and 21 verifier rules. The verifier module grew +227/−33 lines against `cb0b53c`. |
| Backend work (OI-38) | The Linux/PE allocator gained, used by every workload: elision of null tests already proven by incoming edges; constant `address_offset` folded into load/store displacement; loop rotation by duplicating test-only headers; alignment of rotated branch targets; edge-register hints with base-register reuse for dying load bases; and value-range elision of provably in-range `pointer_rebase` checks. |
| Workload shape | The `chains` link variant mirrors the C control flow: `found++` in its own block, and `cur->next` loaded only when the key differs. Loading `next` before the compare cost about 10% (it issues a miss that is never used, at every successful node). |
| Evidence | MEASURED (`oi37_chains_evidence.json`, one 31-repetition run): record links run at **1.066× `gcc -O2`** with real pointers (0.248 s against 0.233 s), 1,408 B. In earlier same-session A/B probes on user CPU time, the ratio was 1.04–1.12×; host noise is 13–20% stdev. `pointer_rebase` links run at 1.59× and index links at 1.70×. Verifier (`oi41_links_evidence.json`): `chains` verifies in 3.6 ms (links), 4.0 ms (rebase), and 3.5 ms (index). Negative vectors (`test_xax_links.py`): bits into a link field, wrong field offset, sub-record stride, checked dynamic store into records, a link from the wrong storage, an untargeted table, a follow through a non-root view, the target ending first, and a foreign call with the arena's effect all reject with their own rules. Non-null link constants reject. A null follow traps (SIGILL). |
| Limits | x86-64 Linux only (wasm32 and PE do not admit operations 74/75 yet). Re-linking a followed record needs a power-of-two record stride. Views passed to callees lose their link target. |

## ADR-098 — Record links and `pointer_rebase` on wasm32 and Windows PE

| Field | Record |
|---|---|
| Decision | `wasm32-wasi-v1` admits operations 74/75. Link values are `i32` addresses in locals; link fields stay 8 bytes in memory (`i64.store` of the zero-extended address; `i64.load` + `i32.wrap_i64`), so record layouts match x86-64. `link_follow` lowers to `i32.eqz; if unreachable end`. `x86_64-windows-pe-v1` admits operations 73–75; the converged allocator (ADR-095) lowers them exactly as on Linux. |
| Evidence | EXECUTED. wasm32 (`test_xax_wasm_links.py`, Node v22.22.0 `node:wasi`): three stack-storage records walked through `link_follow` exit 42; a loaded null link traps with `unreachable`. PE (`test_xax_pe_links.py`, Wine 9.0): the same list exits 42 through `ExitProcess`. Wine is not Windows. WASI and Wine evidence were regenerated for the new target identities (PE fixture bytes unchanged). |
| Limit found | Records with padding need zero-filled storage: a load through a followed record must find every byte of the window initialized, and padding is never written. Stack-storage tests therefore use an explicit padding field. Views passed to callees still lose their link target (open). |

## ADR-099 — Link targets across direct calls; padding-aware record initialization

| Field | Record |
|---|---|
| Decision | (1) A callee assumes each borrowed link-bearing record view links into itself, and so does a view a call returns. A caller may pass only views whose link target is their own storage (`MEMORY-LINK-CALL-TARGET`). A table that targets another storage stays in the function that created it. This keeps callees verifiable on their own, with no caller-specific summaries. (2) A load through a windowed record pointer (a followed or rebased record) accepts initialization gaps that lie entirely in record padding. Fields never read padding, so stack-storage records need not write it. A gap as long as a record always contains field bytes and still rejects. |
| Evidence | EXECUTED. `test_xax_links.py`: a callee borrows the arena view, walks the list from record 0's link, and writes the sum back; the caller exits with 42. Passing the arena-targeting table to a callee rejects. `test_xax_wasm_links.py`: records `(bits<32>, link)` with 4 unwritten padding bytes walk to 42 under `node:wasi`, and leaving one key unwritten still rejects with `MEMORY-INITIALIZED`. Full suite: 810 passed, plus the 17 pre-existing failures. |
| Limits | Cross-storage targets do not cross calls. Native calls return at most one machine value, so a borrowed view's results travel through the view. |

## ADR-100 — First C comparison on the Windows PE row (MinGW-w64, under Wine)

| Field | Record |
|---|---|
| Decision | `windows_c_reference/hosted.c` is updated to an exact twin of the current hosted fixture (WriteFile, heap alloc/free, `sum_to(10)`, the VirtualAlloc squares sum, and function-pointer dispatch; exit 1339). It is built without a CRT by MinGW-w64 (`x86_64-w64-mingw32-gcc (GCC) 13-win32`, `-O2 -nostdlib -ffreestanding -fno-asynchronous-unwind-tables -e start -s ... -lkernel32`), and both binaries are compared under Wine. `CTwinTests` checks behavioural parity whenever MinGW and Wine are installed. |
| Evidence | MEASURED-UNDER-WINE (`windows_pe_c_wine_evidence.json`, 21 runs, wine-9.0 (Ubuntu 9.0~repack-4build3)): file bytes XAX 2,048 against C 2,560; executable bytes XAX 757 (code image) against C 416 (`.text`). Process wall time is 2564.19 ms against 2549.87 ms, dominated by Wine start-up. gcc inlines and constant-folds `sum_to(10)` and the dispatch table and vectorizes the squares loops; XAX executes all of these at run time, which accounts for its larger code. |
| Consequences | The PE row has a C baseline on this host for the first time. R4 needs a Windows host and a workload where run time is not start-up bound. XAX has no interprocedural constant folding or inlining of small callees; that is a code-size gap, tracked under OI-38. |

## ADR-101 — Declared cross-storage link targets across direct calls

| Field | Record |
|---|---|
| Decision | (1) `link_target` (operation 76, no results) in a function's entry block names two borrowed view parameters: the links in the first view's storage point into the second's. The callee verifies follows and stores against that target. Every direct call site checks that the passed table's link target is the passed target view's storage (`MEMORY-LINK-CALL-TARGET`). Operands that are not entry parameters, or not link-bearing record views, reject (`MEMORY-LINK-TARGET-DECLARATION`). The caller's facts are restored on the returned views. A storage released by a call still may not have live dependents. A new link-bearing view a function returns must target itself (`MEMORY-LINK-RETURN-TARGET`). It lowers to no code. (2) When a function has more than one machine return, x86-64 elides each returned borrowed view (the pointer that comes back unchanged from the matching parameter). The caller keeps its own register for that value, so callees can give back several borrowed views. |
| Evidence | EXECUTED (x86-64 Linux). `test_xax_links.py::test_declared_callee_walks_cross_storage_links`: the caller builds an arena and a table that targets it, and a callee borrows both. The callee walks the table's links into the arena and writes the sum into an arena record. The caller exits with 42. `test_declared_cross_storage_targets`: passing a different arena rejects (`MEMORY-LINK-CALL-TARGET`); a callee with no declaration rejects at its follow (`MEMORY-LINK-FOLLOW-PROVENANCE`); declaring a non-view operand rejects (`MEMORY-LINK-TARGET-DECLARATION`). Executables of existing programs are byte-identical. Program roots change only because target profiles now list operation 76. Full suite: 811 passed, plus the 17 pre-existing failures. |
| Limits | The declaration is per function, not per call. A function that receives tables with different targets needs one declaration per pair. Return elision is x86-64 only. wasm32 and PE accept `link_target`, but no cross-call program has been executed on either. |

## ADR-102 — C-callable XAX code addresses and SSE-class SysV arguments (OI-40)

| Field | Record |
|---|---|
| Decision | (1) The calling convention of a code address is part of its **type**. `FUNCTION_ADDRESS` keeps returning `ptr<opaque<function>>` for the internal convention; it may instead return `ptr<opaque_identity<"code-entry:" + abi>>` for an `abi` in `FOREIGN_ENTRY_ABIS` (currently only `sysv-x86_64-c`). A foreign declaration that takes a callback names that exact type, so passing an internal address to C, or calling a C-entry address with `CALL_INDIRECT` (which requires `opaque<function>`), is a type error (`FOREIGN-CALL-CONTRACT`, `INDIRECT-CALL-TARGET-TYPE`). (2) A foreign entry target must have no proof parameters or results (`GRAPH-FUNCTION-ADDRESS-FOREIGN-ENTRY`): a C caller cannot supply effect or resource tokens, so an effectful entry would hide its effects. (3) The x86-64 backend lowers such an address to a compiler-generated adapter placed after the functions: `sub rsp,40`, explicit zero-extending moves from SysV argument registers into the internal convention, `call`, `add rsp,40`, `ret` (20 bytes for two 64-bit arguments). It accepts at most four integer/pointer parameters of 8/16/32/64 bits and at most one integer/pointer result (`SYSV-ENTRY-SIGNATURE`), only on the Linux profiles (`SYSV-ENTRY-TARGET`); AArch64 rejects foreign entries (`AARCH64-FOREIGN-ENTRY-UNSUPPORTED`). (4) `sysv-x86_64-c` imports now lower SSE-class scalars: up to eight f32/f64 arguments in xmm0–xmm7, independent of up to six INTEGER-class arguments, and an f32/f64 result in xmm0 (frame path; the register allocator defers SSE values to it). Anything else rejects (`SYSV-C-SCALAR-CLASS`). |
| Alternatives rejected | A new operation or object kind for callbacks: the existing `FUNCTION_ADDRESS` plus an identity-qualified opaque type expresses it exactly. A node attribute naming the ABI: it would leave both addresses with the same type, so the mismatch would be found only by the backend, or not at all. Generating adapters for every function: unused entries must cost nothing. |
| Evidence | EXECUTED on Linux x86-64 (`linux_c_interop_evidence.json`, `test_xax_c_interop.py`). libc `tsearch`/`tfind` call an XAX comparator through the adapter. Inserting 7, 3, 9, 3, 12 and probing 1..12 exits 31. A control comparator that always answers "equal" exits 78, which shows the callback's result is used. `ldexp(3.0, 3)`, `pow(24.0, 2.0)`, and `sqrtf(16.0f)` from `libm.so.6` exit 68. Artifacts: 1,640 and 1,536 bytes, deterministic. Negative vectors cover an effectful entry, both convention mismatches, a five-parameter entry, a non-Linux profile, and seven INTEGER-class arguments. That last vector exposed a pre-existing bug: the register allocator silently dropped arguments past the sixth, and now defers to the frame path, which rejects. |
| Growth | No operation, object kind, or type form. One verifier rule, one target-independent registry (`FOREIGN_ENTRY_ABIS`), about 120 backend lines including docstrings. |
| Limits | Callbacks are pure. A comparator that must read the elements C passes (for example, `qsort`) needs the foreign caller's borrow to reach the callback as proofs (OI-42). No stack arguments, aggregates, variadics, or foreign entries on PE, AArch64, or wasm32. The adapter is not listed in the semantic-range map. |

## ADR-103 — Browser pages with compiler-generated host bindings (`wasm32-browser-v1`)

| Field | Record |
|---|---|
| Decision | (1) Target `wasm32-browser-v1` is the wasm32 general profile with `call_foreign`, `pointer_address`, and the integer-completion operations (ADR-084). It shares the WASI command container: it exports `_start` and `memory`, and the entry takes and returns proof values only. (2) Browser APIs are typed `wasm32-import` declarations in the platform package `xax_web` (import module `xax-web-v1`). Each declaration has exactly one fixed host meaning in that package. Host page state is ordered by one `effect<io>` token, which the host supplies to `_start`. (3) `emit_browser_page` generates one self-contained HTML page: the module in base64, plus host functions for exactly the bindings the module imports. Unused bindings emit nothing. An import outside the package rejects (`WEB-IMPORT-DECLARED`), because the page would otherwise need a hand-written host. The page adds no runtime, allocator, or event loop; `_start` runs once after instantiation. (4) The wasm backend now lowers `bit.and`/`bit.or`/`bit.xor`/`udiv`/`urem`/`int.truncate`/`int.zero_extend`, but only on targets that list them. Existing wasm targets and their evidence are unchanged. A zero divisor traps in the wasm engine. |
| Alternatives rejected | A hand-written JavaScript runtime or loader: XAX must not require hand-written host code. Emscripten-style generic glue: it brings a runtime the program did not ask for. A new kernel concept for the DOM: declarations plus an effect token express it exactly. |
| Evidence | EXECUTED in headless Chromium 141.0.7390.37 through Playwright (`browser_fib_evidence.json`, `test_xax_web.py`). The XAX program zero-fills a stack buffer, copies the URL query into it, parses decimal digits, computes `fib(n)` modulo 2^64 in a loop, formats it with `udiv`/`urem` and checked stores, and sets the body text. Queries `30`, `90`, empty, and `7x9` render `832040`, `2880067194370816120`, `0`, and `13`, with no page errors. Module 1,270 bytes, page 2,343 bytes, both deterministic. Negative vectors: an undeclared binding, and integer-completion operations on a target that does not list them. |
| Limits | Two bindings (`query_copy`, `set_body_text`). No event handlers or other host-invoked entries (OI-43), no Web IDL importer (OI-32), and no Emscripten or Rust comparison (R4). The matrix row is R1: `platform_apis` stays PROTOTYPE until events and a broader API set are executed. |

## ADR-104 — Browser event entries (closes OI-43)

| Field | Record |
|---|---|
| Decision | Candidate (a) of OI-43, reusing ADR-102. `FOREIGN_ENTRY_ABIS` gains `wasm32-browser-event`. A `FUNCTION_ADDRESS` of type `ptr<opaque_identity<"code-entry:wasm32-browser-event">>` must name a function whose parameters are non-memory effects returned unchanged, with no machine values or resources (`GRAPH-FUNCTION-ADDRESS-FOREIGN-ENTRY`). The host supplies that declared authority on each call, as it does for `_start`. Memory effects are excluded because they name storage the host cannot vouch for. On wasm32 such an address lowers to `i32.const k`, and the module exports the function as `entry_<k>` (numbered in function-CID order). Wasm rejects every other code address (`WASM-FUNCTION-ADDRESS-EVENT-ENTRY`), and x86-64 rejects every foreign entry it does not own (`SYSV-ENTRY-TARGET`). `xax-web-v1` gains `body_text_copy` and `body_on_click(entry, effect<io>)`. The generated host registers `exports["entry_" + k]` as the click listener. |
| Ordering argument | The browser runs each listener to completion after the current task, and no `xax-web-v1` binding dispatches events synchronously. Entries therefore never overlap, and the page effect is used by one entry at a time in host event order. A future binding that dispatches synchronously (for example, `element.click()`) must not be added without revisiting this argument. |
| Evidence | EXECUTED in headless Chromium 141 (`browser_fib_evidence.json` v2, `test_xax_web.py`). `_start` registers the XAX `on_click` entry and renders `"n fib(n)"` from the URL. Each click reads the body text, increments `n`, and re-renders it. For queries `30`, `90`, empty, and `7x9`, the load text and two clicks match the reference (for example `30 832040` → `31 1346269` → `32 2178309`), with no page errors. Module 3,700 B, page 5,843 B. Negative vectors: an entry with a machine parameter, an entry claiming a memory effect, an internal address on wasm, and a browser entry on x86-64. |
| Growth | No operation, object kind, or type form. One ABI name, one admissibility rule, and one wasm lowering case. |
| Limits | One event kind (click on the body). There is no element addressing, event payload, removal, timers, or fetch. State between events lives in the DOM, because XAX has no static storage yet. A Web IDL importer remains OI-32. |

## ADR-105 — Packed Android ELF container (format 5)

| Field | Record |
|---|---|
| Decision | Android targets gain an explicit container choice, image format 5 (`android_arm64_shared_target(packed=True)`, likewise for the general target). Format 4 maps every segment at its file offset, so the RW segment starts at the next 16 KiB file boundary. Format 5 places the RW segment directly after RX in the file (8-byte aligned) and maps it at the next 16 KiB page plus its offset modulo 16 KiB. That satisfies `p_offset ≡ p_vaddr (mod p_align)` with `p_align` still 16 KiB, which is what standard linkers do. Every RW address (GOT, `.data`, `.bss`, `.dynamic`, the import thunks' ADRP/LDR targets) moves by one constant. Format 4 output is byte-identical, so the APK validated on the Pixel 8 Pro keeps its bytes and identity. The format is part of the target object, so the two containers have distinct target CIDs and build identities. |
| Alternatives rejected | Switching format 4 in place would change the device-validated artifact's bytes. A packaging flag outside the target would let two builds of the same request differ. |
| Evidence | MEASURED and EXECUTED. The platform probe shrinks from 17,496 to 3,016 bytes, and the Activity library from 17,352 to 1,496 bytes. Android 14's own `linker64` and bionic, under `qemu-aarch64`, load, relocate, and run every packed library in the bionic suite (29/29 runs, ADR-106). The packed Activity APK (19,557 bytes) passes `apksigner`, `zipalign -c -P 16`, `aapt2`, `dexdump`, and D8. Size against a Java + NDK twin: 0.79× the APK and 0.39× the native library (`android_ndk_twin_evidence.json`). Tests: `test_xax_android_packed.py`, including a rejected unknown format (`TARGET-AARCH64-PROFILE`). |
| Limits | Not yet executed on a device or under ART. As with a default lld layout, the RX mapping of the last file page also covers the RW bytes (no `-z separate-code`). Format 4 remains the default until a device run of the packed APK is recorded. |

## ADR-106 — Android evidence without a device: Android's own linker and libc, and Google's tools

| Field | Record |
|---|---|
| Decision | Two evidence sources are added, both reproducible on any Linux x86-64 host and neither replacing device runs. (1) `bench_android_bionic.py` runs AArch64 Android libraries with `qemu-aarch64` user mode over a root holding `linker64` and bionic (`libc`, `libdl`, `libm`), extracted from the official Android 14 arm64 system image (`super` LP metadata → `system` ext4 → runtime APEX). Loaders are built with NDK r28c. JNI exports run against a `JNIEnv`/`JavaVM` whose slots are recording stubs generated from the NDK's `jni.h`, and their calls are checked by official slot name, arguments, and `jvalue` contents. (2) `bench_android_official_tools.py` checks every committed APK with build-tools 36.1 (`apksigner`, `zipalign -c -P 16`, `aapt2`, `dexdump`, D8 re-dex) and NDK `llvm-readelf`. The labels stay honest: bionic runs are EXECUTED for the native ABI, linker, libc, and JNI-table contracts, but not for ART, Java code, or the device kernel; the tool checks are STRUCTURAL. |
| Evidence | Bionic suite: 29/29 in both containers. That covers file, pthread, and socket contracts through 10 bionic imports (previously never executed), the libxposed `native_init` entry, nine JNI fixtures (slot sequence, arguments, and `jvalue` payloads), `JNI_OnLoad` through `JavaVM.GetEnv`, a bionic `getpid` import, and the two callbacks from the device-validated APK. XAX's 229 native and 5 invoke JNI slot names equal the `jni.h` declaration order. Official tools: 20/20 committed APKs pass, including 16 KiB `.so` alignment. |
| Consequences | The Android row gains measured code size. Start-up time, memory, ART verification, and libxposed behaviour still need a device. |

## ADR-107 — Android C code calls XAX functions (`android-aapcs64-c` entries)

| Field | Record |
|---|---|
| Decision | `FOREIGN_ENTRY_ABIS` gains `android-aapcs64-c`, with the ADR-102 rule that the target must be pure. On AArch64 Android targets, such a `FUNCTION_ADDRESS` is the function's own address, with no adapter. XAX AArch64 code allocates only x0–x7 and x9, never x18 (the Android platform register) or x19–x28, and keeps SP 16-byte aligned, so it already meets AAPCS64's callee obligations. AAPCS64 leaves the upper bits of narrow arguments unspecified, so entry parameters must be 64-bit integers or pointers, with at most eight parameters and one integer or pointer result (`AARCH64-ENTRY-SIGNATURE`). Other entry ABIs reject on AArch64 (`AARCH64-FOREIGN-ENTRY-TARGET`), and x86-64 rejects this one. `xax_platform.android_c_entry_api()` adds a typed `pthread_create` whose start routine has the entry type. The existing declaration (a C-supplied function pointer) is unchanged, and passing an XAX entry to it is a type error. |
| Evidence | EXECUTED under Android 14's `linker64` and bionic via `qemu-aarch64` (ADR-106). `xax_spawn_fib` starts bionic threads whose start routine is the XAX `worker` (a looping `fib`). The oracle spawns four at once (n = 10, 50, 90, 93), joins them with `pthread_join`, and gets 4/4 correct results in both ELF containers. The disassembly shows `adr x16, <worker>`, so no adapter code exists. Negative vectors: a narrow parameter, an effectful entry, a SysV entry on Android, an Android entry on x86-64, and an XAX entry passed where C supplies the pointer (`test_xax_android_c_entry.py`). |
| Limits | Pure entries only: a callback that touches memory or effects is OI-42. The looping worker is lowered by the AArch64 frame path, which spills every value. AArch64 optimization stays PROTOTYPE. |

## ADR-108 — ART's own verifier for every XAX APK

| Field | Record |
|---|---|
| Decision | `bench_android_art_verify.py` runs Android 14's `dex2oat64 --compiler-filter=verify` over every committed APK, against the device's 12-jar boot classpath (read from the system image's `boot.oat` header) and its precompiled arm64 boot image. Class statuses are read back with `oatdump`. Both tools come from the official system image and run under `qemu-aarch64`. libxposed modules are verified with the libxposed API 102.0.0 (Maven Central, SHA-256 pinned, dexed with D8) as parent class loader, which is how the framework supplies it. `integration/android/make_android_root.py` rebuilds the whole host environment from SHA-256-pinned Google and Maven archives (GPT → LP `super` → ext4 `system` → APEX/CAPEX payloads). |
| Evidence | EXECUTED (verification only). All 20 committed APKs, 62 classes, are `Verified`: the Activity (both containers), Service, Receiver, hook targets, and every libxposed module, including hook installation, argument/result mutation, unhook, deoptimization, hot reload, remote preferences/files, and services. Without the libxposed API, module classes are `NotReady` or `VerifiedNeedsAccessChecks`, which shows the API context is required and is not silently assumed. Negative control: the listener with its `check-cast View→TextView` replaced by `nop`s is `NotReady`. `test_xax_android_art_verify.py` replays the evidence by APK hash and re-runs the packed Activity and the control when the root is present. |
| Limits | Verification is not execution. No class is initialized, no Activity runs, and libxposed hooks are not installed. Those still need a device with an Xposed framework. |

## ADR-109 — XAX libxposed modules executed on ART

| Field | Record |
|---|---|
| Decision | `bench_android_art_execute.py` runs each unmodified module APK on Android 14's own `dalvikvm64` (from the system image, under `qemu-aarch64`). A harness (`integration/android/art_libxposed_harness`, built with `javac` and D8 against libxposed API 102.0.0) plays the framework. It attaches to the generated `XaxModule` and calls `onModuleLoaded`, which loads the module's XAX native library through ART's nativeloader and calls into it over JNI. It then calls `onPackageReady`, which installs the hook, runs the installed `Hooker` around the real target method, and drives any generated service wrappers with `PROP_CAP_REMOTE` off and then on. Each module's observed behaviour is compared exactly with the behaviour its profile declares. ART needs a namespace configuration that a device generates at boot; `make_android_root.py` writes a minimal one in which every namespace resolves through `default`. |
| Evidence | EXECUTED, 12/12 module profiles (`android_art_execute_evidence.json`). Argument replacement, result replacement, and combined replacement (including the signed runtime module) each proceed exactly once with the declared arguments and return the declared value. `deoptimize` runs before `hook`. Hot reload sets the stable ID `xax.primary`. The retained-handle profiles unhook through `xaxUnhook()`. Service wrappers pass through framework name and version, and the `propagate` policy rethrows `FileNotFoundException`. The capability-gated remote preferences and files return `null` without calling the service when the capability is absent, and with it make exact typed reads (boolean/int/long/float/String/contains). Control: the combined module with its replacement literal patched returns the patched value. A rebuilt root reproduces 12/12. |
| Limits | The framework is a recording stand-in, not LSPosed, so no other process is hooked. Hooks on `android.app.Activity` methods run with a simulated receiver (`receiver=simulated`): a bare `dalvikvm` has no framework JNI, so an `Activity` cannot be constructed and the original call returns no value. Hot-reload callbacks are not delivered. No Activity UI runs. |

## ADR-110 — AArch64 register path for general targets: compares and value homes

| Field | Record |
|---|---|
| Decision | (1) The register-resident AArch64 path lowers `INT_COMPARE` as `cmp` plus `cset` on 32- or 64-bit operands, with all ten predicates. (2) A value used outside its defining block (legal by dominance) gets one frame "home". It is written once at its definition: block parameters at block entry, node results right after the node. Other blocks reload it on demand, as on x86-64 (ADR-089). Homes are never rewritten, because SSA values are immutable. (3) On general targets (Android v4 and bare-metal general), a function uses the register path when every value is a 32/64-bit integer, a pointer, or a compare result; every operation is in a subset the path already lowers (add/sub/mul, constants, compares, direct/foreign/indirect calls, code addresses); and every call has at most eight machine arguments. Any other function keeps the uniform frame path, so floats, aggregates, memory, heap views, and narrow integers are unchanged. v3 output is byte-identical, because v3 has no compare operation and could not express cross-block uses before. |
| Evidence | EXECUTED. A differential corpus (`test_xax_aarch64_regalloc_differential.py`) has 48 seeded programs in a 64-bit and a 32-bit family. Each has arithmetic, a counted loop whose body uses entry values by dominance and may call earlier programs, and a diamond on a random predicate. All are compiled into one v4 Android library and called with edge and random arguments under Android's `linker64` and bionic. All 288 results equal the reference executor's. Mutation checks confirm that the corpus fails when the `cset` condition is mis-encoded and when home stores are dropped. The `fib` thread worker's loop now runs in registers, and the bionic suite still passes 31/31. Packed libraries shrink: probe 3,016 → 2,760 bytes, thread library 1,936 → 1,664 bytes. The bare-metal general `add` fixture drops from 52 to 8 bytes (OI-20 evidence regenerated from its committed raw samples). |
| Limits | Homes are reloaded on every use: loop-carried constants such as a loop bound cost one load per iteration (x86-64 later added pinning, ADR-091). Bare-metal output is validated only through the Android corpus, because no `qemu-system-aarch64` is available here. No device timing. |

## ADR-111 — A stateful Android app: persistent counter with XAX-owned state, I/O, and lifecycle

| Field | Record |
|---|---|
| Decision | (1) New carrier `counter_activity_semantics` (`xax_android_counter.py`) names the package, the Activity and listener classes, and one private state file. It adds no kernel concept. (2) The behaviour is two ordinary XAX functions exported as JNI methods. `onCreate` restores the count; `onClick` increments it and persists it. Each one `malloc`s an 8-byte cell, zero-fills it explicitly (the heap view is declared uninitialized), `pread64`s the state file, does its arithmetic, `pwrite64`s (on click), `close`s the descriptor, and `free`s the cell, all through typed bionic declarations. (3) The managed side only obtains the platform capability and displays the result. It runs `ParcelFileDescriptor.open(new File(getFilesDir(), name), READ_WRITE|CREATE).detachFd()`, hands the descriptor to XAX (which then owns and closes it), and sets `Long.toString(count)` as the button text. (4) The DEX emitter gains a generic extension point, `DexAssembledMethod`: instructions with symbolic string, type, and method references, from which the emitter derives every pool entry. New managed shapes need no emitter edits, and all existing DEX output is byte-identical. |
| Evidence | `android_counter_activity.apk` (20,561 bytes: activity DEX 1,656, listener DEX 1,280, packed native library 2,496). STRUCTURAL: Google's tools pass. EXECUTED: ART's verifier reports both classes `Verified`. EXECUTED: under Android's `linker64` and bionic, the APK's own library goes restore → 0, three clicks → 1, 2, 3, restore after a "restart" → 3, click → 4. The file is exactly 8 bytes holding 4, and every descriptor was closed by XAX (`android_counter_evidence.json`, `test_xax_android_counter.py`). The device oracle `validate_counter_apk.sh` checks the same sequence through the real UI, including persistence across `force-stop`; it has not been run. |
| Limits | Descriptor ownership is by construction, not verified: the descriptor is a plain integer, not a resource type. A partial write could leave a torn file, because the value is written with one 8-byte `pwrite64` and no atomic rename. The managed UI path did not run off-device: `app_process64` needs the full device boot classpath and system services. No device run yet. |

## ADR-112 — The JVM is a target: direct class-file emission

| Field | Record |
|---|---|
| Decision | (1) A new architecture, 5 (`jvm-classfile-v1`, machine tuple profile 1 / ABI 6 / format 1 / 64 / 64), lowers verified XAX straight to one class file (major version 61, so floating point is strict IEEE 754), packaged as a stored, byte-deterministic JAR. No Java source, `javac`, ASM, or XAX runtime class is involved. (2) Representation: `bits<N≤32>` is `int` and `bits<N≤64>` is `long`, both kept zero-extended; f32/f64 are `float`/`double`. Every function is a `public static` method. Block parameters and values used outside their block are method-wide locals, typed in one uniform StackMapTable frame, while block-local values reuse a per-block scratch region that frames leave as Top. A compare whose only use is its block's branch fuses into `lcmp`/`fcmp` + `if<cond>`, and division by a constant power of two becomes a shift or mask. (3) Traps: a `TRAP` terminator or failed float-to-int range check is `athrow` of a `java.lang.Error` (an allocation on the trap path only); a zero divisor is the JVM's `ArithmeticException`. (4) Foreign members use three ABIs, `jvm-invokestatic`, `jvm-invokevirtual` (receiver first), and `jvm-getstatic`. Library is the class's internal name; name is `member(descriptor)` or `field:descriptor`. The descriptor must agree with the declared XAX types (`JVM-FOREIGN-DESCRIPTOR-TYPE`, `JVM-FOREIGN-ARITY`); B/C/S arguments are narrowed and B/S results masked, explicitly. A JVM reference is `ptr<opaque-identity "jvm-ref:<descriptor>">`, which no XAX memory operation accepts. A Java exception escaping a foreign call terminates the program like a trap. (5) Process entry: `JVM_EXECUTABLE_JAR` requires a proof-only entry (`JVM-PROCESS-ENTRY-CONTRACT`). Its `Main-Class` is a generated `main(String[])` that calls it and returns, which ends the JVM with status 0; any other status is an explicit `System.exit` call. `JVM_LIBRARY_JAR` has no `Main-Class`. (6) Debugging: `LineNumberTable` line *k* is the method's *k*-th XAX node, so platform stack traces name semantic nodes; workspace `artifact`/`map_semantic` work on the JAR. |
| Rationale | OI-35 asked whether managed targets should get direct bytecode or native code plus a bridge. The JVM's portable artifact *is* bytecode: a native-plus-JNI design would make the JAR platform-specific and add a bridge to every call. Bytecode is a typed stack machine close to the wasm backend's model, and HotSpot's JIT supplies register allocation. Uniform frames keep frame computation trivial without giving up the split verifier. |
| Evidence | EXECUTED on OpenJDK 21.0.11 HotSpot (`test_xax_jvm.py`, 18 tests and 78 subtests). An integer differential corpus (widths 8/13/32/47/64; straight-line DAGs, loops whose back edge rebinds their own parameters, calls) and a float/conversion grid (signed zeros, NaN, infinities, exact trap boundaries, u64↔float) match the reference executor. `java -jar` runs a program that prints through `System.out`, calls `Math.sqrt` and `Long.bitCount`, and exits with status 7 via `System.exit`. A trap's stack trace maps back to its `UDIV` node. Package build and workspace mapping produce the same JAR. Negative vectors: a SysV foreign call, a descriptor/type mismatch, an arity mismatch, a process entry with machine values, a memory operation, and a wrong machine tuple. MEASURED (`jvm_twin_evidence.json`, seven fresh JVMs each): on the Collatz total-steps kernel (n = 10⁶, after warmup) XAX takes 1.04× the kernel time of the `javac` twin, with peak RSS 1.01× and a class file 1.51× larger (1,147 vs 760 bytes). |
| Limits | Scalar subset only: no linear memory, aggregates, sums, recursion groups, or indirect calls on this target, and no object, array, or string construction (references only arrive as foreign results). No JVM-to-XAX callbacks. The class-size gap comes from block parameters that are not coalesced. Unsigned 64-bit compares cost a sign flip. JVM row: R2. |

## ADR-113 — RISC-V RV64IM target: raw position-independent image

| Field | Record |
|---|---|
| Decision | (1) A new architecture, 6 (`riscv64-baremetal-raw-v1`: profile 1 / ABI 7 LP64 / format 1 raw / 64 / 64), uses only the RV64I base ISA plus M. It follows the LP64 integer calling convention: arguments in a0–a7, one result in a0, return address in ra; the identity fixes the convention, so the profile carries no register lists. (2) The integer subset is `bits<N≤64>` arithmetic, bitwise operations, unsigned division, rotates, width changes, compares, direct calls, and all four terminators. (3) RISC-V `divu`/`remu` return a value on a zero divisor, so the lowering emits the explicit test that turns it into the XAX trap. A trap is `unimp`. (4) Allocation is a linear scan over interval hulls from block-level liveness into s1–s11, which the prologue saves; values that do not fit spill to frame slots. Edge copies go through frame temporaries only when a destination is also a source. (5) Every transfer is `jal` or a branch over `jal`, so the image is position-independent and branch range never limits function size. The entry is laid out first. There is no loader, relocation, data section, or runtime. |
| Rationale | RISC-V is the open ISA most future embedded and accelerator hosts build on. A raw image with the standard calling convention is the smallest artifact that proves the target-package path for a third, unrelated machine model, and it is what a bare-metal board package (U1.6) or a Linux container would wrap. |
| Evidence | EXECUTED under the Unicorn 2.1 RV64 emulator (`test_xax_riscv64.py`, 9 tests and 383 subtests). The JVM differential corpus at eight programs per width matches the reference executor. So do a 24-value register-pressure loop whose back edge rotates every carried value (spills plus overlapping copies), large-constant materialization, and the explicit zero-divisor and `TRAP` paths. `llvm-mc --disassemble` (LLVM 18) independently decodes every emitted word with no diagnostics. Build and workspace produce the same image. MEASURED (`riscv64_twin_evidence.json`, emulated instruction counts, not hardware time): Collatz n = 300 runs at 3.72× the instructions of `clang -O2 -march=rv64im` with 3.23× its code bytes, down from 15.9× and 8.85× before register allocation. On `sum_to`, clang computes a closed form (14 instructions) where XAX runs the loop. |
| Limits | Emulator only, with no hardware and no Linux or RTOS container. Integer subset only: no F/D floats, memory, aggregates, atomics, V vectors, or indirect calls. No compare/branch fusion or copy coalescing yet. riscv64 row: R1. |

## ADR-114 — Execution hosts for evidence: harness adapters and emulators

| Field | Record |
|---|---|
| Decision | (1) The x86-64 raw-image test harness (`run_native`) runs on Linux x86-64 hosts through a 131-byte SysV→Win64 call thunk. Slots 0–3 go to RCX/RDX/R8/R9 *and* XMM0–3, since Win64 assigns argument registers by position; aggregates follow the Win64 size rule; a large aggregate result uses a hidden pointer. (2) When no `qemu-system-aarch64` is installed, the AArch64 harness runs the raw image in Unicorn's ARM64 CPU, calling the entry directly. (3) The RISC-V harness is Unicorn. In all three cases the image bytes are exactly those the target receives, and the adapter or emulator is a host tool, never part of an artifact. (4) Policy: emulated execution satisfies `code_generation` and `real_execution` (execution correctness); it is never hardware performance evidence. Emulated instruction counts are reported as such, and a row whose execution is emulator-only lists "not hardware" as a blocker. |
| Evidence | The six Windows-only x86-64 tests (branch/call, stack memory, atomic RMW/CAS, compile-time materialization) and both QEMU-only AArch64 tests now execute on this Linux host. The stack-memory test's stale code hash was re-pinned only after the current 43-byte code executed correctly. |
| Limits | The thunk covers the raw-image call ABI only; PE executables still need Windows or Wine. Unicorn has no semihosting or devices, so MMIO and interrupt programs still need QEMU or a board. |

## ADR-115 — Lend entries: C callbacks that read memory the C call was lent (OI-42)

| Field | Record |
|---|---|
| Decision | (1) A new foreign entry ABI, `sysv-x86_64-c-lend`. Its code-address type is `lend_entry_pointer_type(view_pointer, view)`, whose opaque identity embeds the CIDs of the view's pointer type and token type. (2) Admissibility at `FUNCTION_ADDRESS` (`GRAPH-FUNCTION-ADDRESS-FOREIGN-ENTRY`): the callee takes C scalars, then exactly that view triple `(ptr<space 2> READ, heap_view<N> initialized, memory)` as its last parameters. It returns one integer followed by the same triple. The callee is then verified like any function that borrows a view (ADR-099/101): it must return the triple whole and in order; it cannot store through a READ pointer; and it reaches elements only through `pointer_rebase`, which traps on out-of-view or misaligned addresses (ADR-092). The C caller passes the view back as its context argument, which is the declaration's foreign contract (`qsort_r`'s `arg`). (3) The call-site rule, `LEND-ENTRY-VIEW-LENT`: an operand of a lend-entry type may only go to a `sysv-x86_64-c` call that also passes a whole, live, initialized view of exactly that extent, with that storage's memory effect as an operand and a memory effect among the results. The borrow therefore lives exactly as long as the call. A declaration that keeps the entry (`atexit`) lends no view and rejects. (4) Proof parameters stay erased: the x86-64 SysV adapter maps machine values only, and the borrowed view pointer is elided from the results (ADR-101), so the adapter keeps the ADR-102 shape. |
| Rationale | This is OI-42 candidate (a). Every proof the callback uses comes from the one foreign call in progress, and nothing is ambient or synthesized at run time. Candidate (b) (an opaque context plus raw access under an `unsafe` waiver) would have dropped bounds and lifetime checking. The type carries the view's types, so a mismatch is a type error at the call, not a runtime check. |
| Evidence | EXECUTED on Linux x86-64 with glibc 2.39 (`linux_qsort_evidence.json`, `test_xax_lend_entry.py`). `qsort_r` sorts a 16-element XAX heap array with an XAX comparator that loads both elements through the lent view; the exit status 117 equals the checksum of the ascending order. A descending comparator yields the descending checksum, so the callback's results really decide the order. Negative vectors: the entry passed to `atexit` (kept past the call), a call that lends no view, a store through the lent view (`MEMORY-WRITE-PERMISSION`), a writable lent view, a view of another extent, a callback returning a pointer into the view, and the pure entry type on a proof-taking callee. |
| Limits | One lent view per entry, read-only, x86-64 Linux only. That the C side passes the context back unchanged is the declaration's stated contract, not something verified (as for every foreign declaration). Writable lends (`qsort` mutating through the comparator), several views, and AArch64/Android lend entries are not implemented. |
