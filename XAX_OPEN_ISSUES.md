# XAX Open Issues

This register lists the issues that require implementation, target, ecosystem, or benchmark evidence before they can be closed, together with the closed issues whose resolution and evidence it keeps. Each record gives the current status first, then the question, constraints, evidence, decision, and closure criteria. Superseded status updates and chronological progress notes stay available in each record's collapsed **Historical Record**.

## Scope and Governing Constraints

> [!IMPORTANT]
> Only issues requiring implementation, target, ecosystem, or benchmark evidence are listed here. None permits weakening `XAX_SPEC.md` invariants.

- Specification precedence is defined in [`XAX_SPEC.md` §1](XAX_SPEC.md#1-normative-language-and-precedence). This register records evidence and adopted resolutions; it is not normative.
- Dated sections are historical records. A new result is recorded as a new entry and the superseded entry is kept, not rewritten.
- Evidence labels follow the repository rule: `EXECUTED`, `MEASURED`, `NOT RUN`, and `BLOCKED`. Emulator, Wine, or qemu runs are not device runs, and a successful compilation or a passing test is not by itself execution evidence.

## Status Definitions

| Status | Meaning in this register |
| --- | --- |
| `OPEN` | The closure criteria of the record are not all met. Partial progress is stated in the record, for example "partially addressed". |
| `CLOSED` | The record states that its resolution is decided and its closing evidence is recorded. A scope limit, where one exists, is stated next to the status (for example OI-35 closes for the JVM only). |
| `MOVED` | The record's work is tracked by an issue in another first-party repository, linked in its status line; XAX keeps only what that line names. |

- The date in a status line is the date the original record gives for that status. Statuses that the original gives in other words (for example `FIXED IN THE STORES`, `OPEN (partially addressed)`) are kept verbatim inside the Historical Record of the issue that used them.
- Where an original record has no status line, the status shown is the one its own text states (for example "remains open" or "is closed"), and the record says so.
- Where an earlier dated paragraph says closed and a later dated status line says open (OI-15, OI-18, OI-19 until 2026-11-25), the later status line supersedes it; the record notes the superseded claim.
- Closure-criteria checkboxes are ticked only where the original text states that the criterion is met.
- OI-01, OI-31, and OI-46 were removed from this register by commit `7af8108` (2026-10-30) and are restored from the version before it; the ADRs and evidence files they cite that were deleted at the same time are in git history.

## Issue Index

| Issue ID | Title | Status |
| --- | --- | --- |
| [OI-01](#oi-01--ai-token-vocabulary-fallback-framing-and-handle-namespace) | AI token vocabulary, fallback framing, and handle namespace | MOVED |
| [OI-02](#oi-02--canonical-object-and-graph-fragment-granularity) | Canonical object and graph-fragment granularity | CLOSED |
| [OI-03](#oi-03--recursion-group-compact-encoding) | Recursion-group compact encoding | CLOSED |
| [OI-04](#oi-04--float-format-catalog-and-compact-type-vocabulary) | Float format catalog and compact type vocabulary | OPEN |
| [OI-05](#oi-05--proof-fact-persistence) | Proof-fact persistence | CLOSED |
| [OI-06](#oi-06--aliasprovenance-representation-and-checked-access-kernel-surface) | Alias/provenance representation and checked-access kernel surface | CLOSED |
| [OI-07](#oi-07--dma-resource-state-vocabulary) | DMA resource-state vocabulary | CLOSED |
| [OI-08](#oi-08--effect-partition-granularity-and-persistent-edge-encoding) | Effect partition granularity and persistent edge encoding | CLOSED |
| [OI-09](#oi-09--indirect-callcontract-representation) | Indirect CallContract representation | CLOSED |
| [OI-10](#oi-10--portable-trap-payload-core) | Portable trap payload core | CLOSED |
| [OI-11](#oi-11--non-native-atomic-synthesis-policy) | Non-native atomic synthesis policy | CLOSED |
| [OI-12](#oi-12--timing-proof-representation) | Timing-proof representation | CLOSED |
| [OI-13](#oi-13--gpuaccelerator-synchronization-scope-normalization) | GPU/accelerator synchronization-scope normalization | CLOSED |
| [OI-14](#oi-14--compile-time-fuel-units-and-introspection-authority-granularity) | Compile-time fuel units and introspection authority granularity | OPEN |
| [OI-15](#oi-15--specialization-object-boundaries) | Specialization object boundaries | CLOSED |
| [OI-16](#oi-16--target-semanticinstruction-granularity-and-opaque-contract-minimums) | Target semantic/instruction granularity and opaque-contract minimums | OPEN |
| [OI-17](#oi-17--target-cost-model-representation-and-calibration) | Target cost-model representation and calibration | OPEN |
| [OI-18](#oi-18--legalizationoptimizer-organization-and-machine-level-ir) | Legalization/optimizer organization and machine-level IR | CLOSED |
| [OI-19](#oi-19--transformation-proof-granularity) | Transformation-proof granularity | CLOSED |
| [OI-20](#oi-20--abiplatform-capability-and-classification-representation) | ABI/platform capability and classification representation | OPEN |
| [OI-21](#oi-21--semantic-database-dependency-representation-and-cross-process-parallelism) | Semantic-database dependency representation and cross-process parallelism | CLOSED |
| [OI-22](#oi-22--hash-agility-and-migration) | Hash agility and migration | CLOSED |
| [OI-23](#oi-23--package-resolver-expressiveness-and-complexity-bounds) | Package resolver expressiveness and complexity bounds | CLOSED |
| [OI-24](#oi-24--provenance-granularity-and-sandbox-portability) | Provenance granularity and sandbox portability | CLOSED |
| [OI-25](#oi-25--bootstrap-fixed-point-comparison-level) | Bootstrap fixed-point comparison level | CLOSED |
| [OI-26](#oi-26--minimum-practical-bootstrap-seed-subset) | Minimum practical bootstrap seed subset | CLOSED |
| [OI-27](#oi-27--bootstrap-trust-diversity-threshold) | Bootstrap trust diversity threshold | CLOSED |
| [OI-28](#oi-28--diagnostic-payload-and-repair-neighborhood-minimum) | Diagnostic payload and repair-neighborhood minimum | MOVED |
| [OI-29](#oi-29--atomic-litmus-conformance-corpus-size) | Atomic litmus conformance corpus size | CLOSED |
| [OI-30](#oi-30--deterministic-build-manifest-boundary--closed) | Deterministic-build manifest boundary | CLOSED |
| [OI-31](#oi-31--run-the-tiny-c-vs-xax-experiment-in-codex-desktop) | Run the tiny C-vs-XAX experiment in Codex Desktop | CLOSED |
| [OI-32](#oi-32--foreign-metadata-importer-scope-and-representation) | Foreign metadata importer scope and representation | CLOSED |
| [OI-33](#oi-33--hosted-process-lifecycle-unwind-and-tls-contracts) | Hosted process lifecycle, unwind, and TLS contracts | OPEN |
| [OI-34](#oi-34--first-production-gpu-target) | First production GPU target | OPEN |
| [OI-35](#oi-35--managed-platform-emission-strategy-jvm-clr) | Managed-platform emission strategy (JVM, CLR) | CLOSED (for the JVM) |
| [OI-36](#oi-36--standard-semantic-library-granularity) | Standard semantic library granularity | CLOSED |
| [OI-37](#oi-37--pointer-values-stored-in-memory) | Pointer values stored in memory | CLOSED |
| [OI-38](#oi-38--x86-64-register-allocation-convergence-and-remaining-code-quality-gap) | x86-64 register allocation: convergence and remaining code-quality gap | OPEN |
| [OI-39](#oi-39--shift-and-sign-extension-selection-versus-kernel-operations) | Shift and sign-extension selection versus kernel operations | OPEN |
| [OI-40](#oi-40--breadth-of-the-sysv-c-abi-on-linux) | Breadth of the SysV C ABI on Linux | OPEN |
| [OI-41](#oi-41--check-free-pointer-reloads-typed-mixed-storage) | Check-free pointer reloads (typed mixed storage) | CLOSED |
| [OI-42](#oi-42--effectful-foreign-entries-callbacks-that-touch-memory-or-effects) | Effectful foreign entries (callbacks that touch memory or effects) | CLOSED |
| [OI-43](#oi-43--browser-event-entries-host-invoked-xax-entry-points) | Browser event entries (host-invoked XAX entry points) | CLOSED |
| [OI-44](#oi-44--hardware-versus-emulated-execution-as-replacement-evidence) | Hardware versus emulated execution as replacement evidence | OPEN |
| [OI-45](#oi-45--re-executing-native-evidence-after-a-canonical-change) | Re-executing native evidence after a canonical change | CLOSED |
| [OI-46](#oi-46--fixed-client-overhead-in-r5-token-measurement) | Fixed client overhead in R5 token measurement | MOVED |
| [OI-47](#oi-47--path-exact-ownership-for-android-platform-objects) | Path-exact ownership for Android platform objects | OPEN |
| [OI-48](#oi-48--windows-host-process-capabilities-for-vramboost-dx12) | Windows host-process capabilities for VRAMBoost DX12 | OPEN |
| [OI-49](#oi-49--android-arm64-large-composite-return-copy) | Android ARM64 large composite return copy | CLOSED |
| [OI-50](#oi-50--x86-64-branch-fusion-loses-cross-block-comparison-values) | x86-64 branch fusion loses cross-block comparison values | CLOSED |
| [OI-51](#oi-51--windows-native-driver-coverage-and-diagnostic-parity) | Windows native driver coverage and diagnostic parity | OPEN |
| [OI-52](#oi-52--64-bit-checked-offsets-and-growable-views-roadmap) | 64-bit checked offsets and growable views (roadmap) | OPEN |
| [OI-53](#oi-53--xaxc-verify-rejects-byte-view-widening) | `xaxc verify` rejects byte-view widening | CLOSED |
| [OI-54](#oi-54--function-views-past-218-values-bbcs-hanoi--o0) | Function views past 2^18 values (BBC's hanoi -O0) | OPEN |
| [OI-55](#oi-55--native-x86-64-signed-compares-below-32-bits) | Native x86-64 signed compares below 32 bits | CLOSED |
| [OI-56](#oi-56--pe-images-take-large-frames-without-a-stack-probe) | PE images take large frames without a stack probe | CLOSED |
| [OI-57](#oi-57--the-references-s12c2-analysis-audit-disagrees-with-the-native-basics-since-ledger-0022) | The reference's S12c.2 analysis audit disagrees with the native `basics` since ledger 0022 | CLOSED |
| [OI-58](#oi-58--windows-x86-64-code-generation-on-the-chains-walk-r4-blocker-for-windows-x86_64-pe) | Windows x86-64 code generation on the `chains` walk (R4 blocker for `windows-x86_64-pe`) | OPEN |
| [OI-59](#oi-59--edge-copies-overwrite-a-frame-word-another-copy-of-the-same-edge-still-reads) | Edge copies overwrite a frame word another copy of the same edge still reads | CLOSED |
| [OI-60](#oi-60--host-portability-gaps-left-after-the-2026-11-13-audit) | Host-portability gaps left after the 2026-11-13 audit | CLOSED |
| [OI-61](#oi-61--the-jvm-program-does-not-check-a-catching-calls-throwable-output-type) | The JVM program does not check a catching call's throwable output type | CLOSED |
| [OI-62](#oi-62--the-legacy-wasm32-profile-emits-an-invalid-module-for-a-bits64-checked-offset) | The legacy Wasm32 profile emits an invalid module for a `bits<64>` checked offset | CLOSED |
| [OI-63](#oi-63--canonical-index-acceleration-for-large-stores) | Canonical index acceleration for large stores | OPEN |
| [OI-64](#oi-64--semantic-rebase-granularity-for-concurrent-agents) | Semantic rebase granularity for concurrent agents | OPEN |
| [OI-65](#oi-65--scheduling-resource-detail-in-target-packages) | Scheduling-resource detail in target packages | OPEN |

## OI-01 — AI token vocabulary, fallback framing, and handle namespace

**Status:** MOVED (2026-11-28) to [MrxSiN/XAX-MCP#5](https://github.com/MrxSiN/XAX-MCP/issues/5): the measurement and its client side are XAX-MCP's (it owns transport, tool schemas and the client surface). A protocol change its results call for comes back here as an ADR. The earlier status line follows.

**Status:** OPEN (2026-11-25): a measurement design is proposed below for the owner; nothing is run. The original record has no status line; its last entry, "Remaining after this extension", leaves it open. It was removed from this register by commit `7af8108` (2026-10-30) and restored on 2026-11-24 from the version before that commit.

### Summary

Which dedicated model tokens, fallback packet encoding, and local-handle namespace minimize total model tokens per successful semantic change without increasing invalid mutations or repair rounds?

### Fixed Constraints

- Transport is versioned, deterministic, unambiguous, non-source, and measured with the actual tokenizer/model. Full persistent hashes need not appear in normal AI context.

### Measurement design (proposed, 2026-11-25)

Not run. A design for the closure criterion, for the owner to approve or change:

- Arms: (a) typed handles (`F`, `N`, `P`, `T`), (b) one unified handle namespace, each with two fallback framings
  (the current line form and a length-prefixed packet). Four arms, one native workspace (`xaxc edit`), one pinned
  model and tokenizer, identical instructions and tool surface.
- Tasks: 30 fixed tasks, 5 per family: program creation, literal/op/control edits, type/resource/effect repair,
  stale-root recovery, optimization. Each has a verified target root, so success is exact.
- Per attempt: input and output tokens from the API (retries included), protocol bytes, semantic entities touched,
  invalid mutations, repair turns, completion within 6 turns.
- Trials: 3 per task and arm, task order randomized per trial; report medians and the per-task spread, and a paired
  comparison per task.
- Decision rule: the arm with the lowest median tokens per completed task wins, provided its invalid-mutation rate
  and repair turns are not higher than the current arm's; tokenizer-native vocabulary is a separate, later arm (it
  needs model integration).
- Needs the owner: ADR-207 defers AI-efficiency work, so nothing here runs until the owner approves the design and
  the model budget. No agent runs these trials on its own initiative.

### Closure Criteria

- [ ] Controlled comparison of typed versus unified handles and multiple fallback framings across program creation, literal/op/control edits, type/resource/effect repair, stale-root recovery, and optimization tasks. Record tokens, error rates, repair turns, semantic entities, protocol bytes, and completion rates. Tokenizer-native vocabulary requires actual tokenizer/model integration.

### References

- The benchmark evidence it cites under `compiler/benchmarks/ai_native/` was removed from the tree by `227a976` (2026-10-30) and is in git history.

<details>
<summary>Historical Record</summary>

**Earlier evidence.** One fixed 2026-09-29 static edit case measured generation-scoped `R0.0` against full-root text with `cl100k_base` and `o200k_base`; the alias reduced candidate output tokens from 60/61 to 28/28 and bootstrap transaction accounting from 77 to 47 bytes. The alias is implemented with ABA-safe generation freshness checks. The workspace now also has an exact serialized response-byte cap with deterministic positive-progress pagination, but the measured 178-byte cap increased the three-node query total from 424 to 520 bytes across pages; this is transport accounting, not tokenizer evidence. This evidence predates the 2026-10-01 model trial below and does not by itself select a transport.

**Transport-candidate evidence (2026-10-01).** `compiler/benchmarks/ai_native` now compares two handle namespaces (current typed `P0`/`N0`; unified dense integers with kind out-of-band, `P0`→`0`, `Nk`→`k+1`) across three versioned `X1` fallback framings (`line` long verbs, `pipe` short verbs with `|`/`;`, compact `json`). Strict decoders reject unknown versions/verbs/fields, cross-namespace handles, non-canonical integers, and JSON type confusion; all six candidates decode to one identical workspace transaction and reach the target root for all five reference edits. Raw views/packets and counts are in `transport-oi01.json` (offline `tiktoken` 0.14.0). Five-task view+packet totals, `cl100k_base`/`o200k_base`: typed line 191+71/186+71, typed pipe 191+68/186+73, typed json 191+88/186+88, unified line 176+71/171+71, unified pipe 176+61/171+66, unified json 176+81/171+81; view+packet bytes 484/434/500/438/388/440. Unified handles save 15 view tokens under both encodings; `json` costs the most packet tokens. Each candidate is also runnable as a model-trial arm (`XAX-<TYPED|UNIFIED>-<LINE|PIPE|JSON>`).

**Model-trial evidence (2026-10-01).** All 30 candidate trials (5 tasks × 6 arms, n=1 per cell) ran as fresh Claude Code `general-purpose` subagents on `claude-opus-5-5`; raw packets, per-invocation traces, and rows are in `runs-claude/` and `results-claude.csv`. Completion was 30/30. Harness-reported subagent tokens per arm (five tasks): typed line 278,750, typed pipe 280,478, typed json 280,648, unified line 278,301, unified pipe 281,968 (includes the standalone probe run), unified json 280,587; ~55.6k per trial is fixed harness context, so arm differences (about 1.3% peak-to-peak) are within run-to-run noise. Failed `verify`/`test` checks: line 0 (0/10 trials), pipe 2 (2/10; both submitted the unedited header-only packet), json 14 (9/10 trials; the model wrote the header and mutations as separate or nested arrays instead of one flat array). By handle namespace: typed 9, unified 7 failed checks, all attributable to framing. On this corpus and model, `line` framing is the only zero-repair candidate, `json` as specified is error-prone, and typed versus unified handles shows no measurable token or reliability difference.

**Remaining to close.** (1) Repeated trials (n>1) and a second model family; the measured token differences are below noise and the OpenAI/Codex arm has not run. (2) Task families absent from the corpus: program creation, control-flow edits, type/resource/effect repair, stale-root recovery (only the rejection path is tested), and optimization. (3) Tokenizer-native vocabulary requires real tokenizer/model integration and remains unavailable.

**Corpus/checker extension evidence (2026-10-02).** `compiler/benchmarks/ai_native` now adds exactly the six missing families without adding a seventh transport: program construction from a minimal semantic scaffold via the existing insertion mutation, branch-edge argument replacement via existing disconnect/connect mutations, verifier-driven `u8`/`u16` type repair, linear resource/effect repair, stale-root refresh/retry that advances from `R0.0` to `R0.1` before the requested edit, and one dead-node optimization request. All 11 tasks run through the same typed/unified × line/pipe/json `X1` arms. `corpus-oi01.json` contains 66 deterministic task/arm rows with the minimum local view, prefilled packet, exact target packet, semantic-entity count, byte counts, and exact final target root; every target packet decodes to the same transaction across framings/namespaces and reaches that root. The type/resource/stale prefilled candidates reject for the intended semantic reason and then pass after the exact repair. Trial recording now supports repeated `trial` rows and records client token usage, turns, failed checks, repairs, view/packet bytes, semantic entities, and final root; `oi01-summary` groups results by family and arm.

**Remaining after this extension.** No new OpenAI/Codex-family model trial was available in the implementation environment, so there is still no n>=3 model evidence on the expanded corpus and no second-family confirmation. No fallback framing or typed-vs-unified default is selected by this change. Tokenizer-native vocabulary still requires actual tokenizer/model vocabulary integration and remains the dedicated-vocabulary blocker; offline tokenizer counts are not substituted for model usage. OI-01 remains open.

</details>

## OI-02 — Canonical object and graph-fragment granularity

**Status:** CLOSED (2026-10-02)

### Summary

What objectization policy best balances edit locality, CID churn, deduplication, index/hash overhead, cache reuse, verification locality, and merge conflict size?

### Fixed Constraints

- Each chosen object has one canonical encoding.
- Unchanged objects retain CIDs.
- Fragment boundaries do not alter runtime semantics.

### Evidence and Measurements

`compiler/benchmarks/bench_oi02_granularity.py` compares:

- the canonical function grain;
- the existing measurement-only `call_indirect` and block candidates;
- module packing;
- one combined **stable-interface+block** candidate.

The combined arm reuses the existing canonical kind-11 `CallContract` as the separately content-addressed immutable interface/control summary. A measurement-only stable declaration references that summary, and a module binding references a separately objectized block-skeleton body. The summary therefore has no independently mutable duplicate signature/effect/resource/control copy. Reassembly derives the expected summary from the exact block body and type interface, rejects stale summary/body pairs, recursively resolves stable declarations, and must reproduce the exact canonical graph/function CIDs before verification or execution. Existing function/call-indirect/block deterministic bytes and CIDs remain unchanged.

The corpus includes `service-6x8-b4`, a generated six-module, eight-function-per-module, four-block service-like DAG with both intra-module and inter-module calls, in addition to the chain/star stress fixtures.

- Deterministic evidence: `compiler/benchmarks/oi02_granularity_evidence.json`.
- Raw fixed-count timing observations (5 samples/cell): `compiler/benchmarks/oi02_granularity_timing.json`.
- Focused tests include corruption and stale-summary negatives and pass 12/12.

#### Service corpus (`service-6x8-b4`)

| Measurement | Function grain | Stable-interface+block |
| --- | ---: | ---: |
| Store size | 28,713 B / 154 objects | 44,304 B / 290 objects |
| Read function `(0,0)` | 324 B | 821 B |
| First-leaf body edit preserving the exact `CallContract`: rewritten | 104 objects / 19,237 B | 6 objects / 1,255 B |
| First-leaf body edit: verification frontier | 104 objects | 5 objects |
| Shallower sibling edit: rewritten | 30 objects / 6,061 B | 6 objects / 1,255 B |
| Shallower sibling edit: verification frontier | 30 | 5 |
| Already-local entry edit: rewritten | 5 objects / 976 B | 6 objects / 1,255 B |
| Already-local entry edit: verification frontier | 5 objects | 5 objects |
| Same-module merge overlap | 28 objects / 5,745 B | 1 object / 567 B |

For an already-local entry edit, function grain is the smaller rewrite.

#### Synthetic stress fixtures

| Fixture | Edit | Function grain | Stable-interface+block |
| --- | --- | ---: | ---: |
| `chain-8x16-b4` | deep leaf edit | 266 objects / 50,581 B, frontier 266 | 6 objects / 1,849 B, frontier 5 |
| `star-8x16-b4` | leaf edit | 35 objects / 6,628 B, frontier 35 | 6 objects / 1,849 B, frontier 5 |

#### Persistent overhead of the stable candidate

- Stores are 36.1% to 61.2% larger than function grain on the measured four-block workloads.
- Function query bytes are 2.53x larger (821 B versus 324 B).
- Python-bootstrap encode/decode/query timings are correspondingly slower.
- `call_indirect` retains similarly small rewrite sets but does not provide the same proof reuse, because body-dependent verification still follows rebound callees.

### Decision

Canonical **function grain remains the store-v1 default**. No finer candidate dominates it.

- Stable-interface+block fragmentation is bounded to derived/tooling use for body-only edits whose exact immutable `CallContract` summary CID is unchanged and whose measured/predicted function-grain dependency frontier would otherwise propagate through callers.
- An implementation should select it only when the local cost estimate shows lower rewrite bytes **and** a smaller verification frontier than function grain.
- For already-local edits, interface-changing edits, single-block bodies without demonstrated reuse, or query/store-size-sensitive paths, keep function grain.

This policy preserves one semantic identity: fragmented units are reassembled and checked against the canonical function/graph CIDs, and store v1 is unchanged.

### References

- `compiler/benchmarks/bench_oi02_granularity.py`
- `compiler/benchmarks/oi02_granularity_evidence.json`
- `compiler/benchmarks/oi02_granularity_timing.json`

## OI-03 — Recursion-group compact encoding

**Status:** CLOSED (2026-10-01)

### Summary

Should non-recursive functions always use the direct `function` carrier, and what compact representation should trivial or singleton recursive groups use?

### Fixed Constraints

- Recursive CID computation remains acyclic.
- Recursive member identity is deterministic.

### Evidence and Measurements

`compiler/benchmarks/bench_oi03_recursion.py` measures eight identical `x * k + c` bodies in three workloads with two carriers each. Deterministic results are in `oi03_recursion_evidence.json`, reproduced by `tests/test_oi03_recursion.py`. Legal arms are whole-store verified and every entity executes to its reference value. Measurement-only arms (including the one-member group around a non-recursive function, which the verifier now rejects) are never verified.

| Workload / carrier | Carrier objects | Carrier bytes | Store bytes |
| --- | ---: | ---: | ---: |
| none / direct `function` | 8 | 856 | 4,682 |
| none / singleton `recursion_group` | 8 | 864 | 4,690 |
| self / `recursion_group` (current) | 8 | 1,128 | 5,911 |
| self / compact singleton (count omitted; measurement-only) | 8 | 1,120 | 5,903 |
| mutual rings 2+2+4 / `recursion_group` (canonical order) | 3 | 613 | 5,050 |
| mutual / one `function` per member (illegal CID-cycle comparator) | 8 | 1,120 | 5,902 |

### Decision

1. Non-recursive functions always use the direct `function` carrier. A one-member group costs exactly one body byte (the member count) and a `#0` handle suffix, yields a second CID for the same semantics, and cannot be a `call.direct` target (`XAX.STRUCT.CALL_TARGET`), so it has no benefit.
2. Self-recursive singletons keep the existing `recursion_group` carrier. The only possible compaction is the one-byte member count (8 B / 0.14% of store). No dedicated singleton encoding or new kind is warranted.
3. Mutually recursive SCCs keep `recursion_group`. Sharing one reference table makes the group 45% smaller in carrier bytes and 14.4% smaller in store bytes than per-member objects. The cost is that an edit to one member changes the identities of all SCC members (2 or 4 here) but no member outside the SCC, while rewritten bytes stay at or below per-member (753–829 B versus 879 B). CID computation remains acyclic and member identity remains `(group CID, member_index)`.

#### Enforcement (2026-10-01)

- `XAX_SPEC.md` §3.3 now says MUST.
- The verifier rejects a group that is not exactly one recursive SCC (`XAX.STRUCT.RECURSION_SCC` / `GRAPH-RECURSION-SCC`, which covers non-recursive singletons and groups of separate SCCs).
- The verifier rejects a group not in canonical member order (`XAX.CANON.RECURSION_ORDER` / `GRAPH-RECURSION-ORDER`).
- The canonical order is the breadth-first order from the start member that gives the smallest per-member descriptor (erased key, renumbered callees). This is O(k²) in SCC size, and `canonical_recursion_order` exposes it to producers.
- `tests/test_oi03_recursion.py` checks that all four rotations of a 4-member ring canonicalize to one group CID and that 3 of the 4 raw rotations are rejected.

### Closure Criteria

- [x] Serializer and storage measurements over workloads with no recursion, self-recursion, and mutually recursive SCCs.

### References

- `compiler/benchmarks/bench_oi03_recursion.py`
- `oi03_recursion_evidence.json`
- `tests/test_oi03_recursion.py`
- `XAX_SPEC.md` §3.3

## OI-04 — Float format catalog and compact type vocabulary

**Status:** OPEN (the original record has no status line; it states "Still open")

### Summary

Which floating formats and high-frequency type forms receive dedicated pre-interned/transport IDs rather than structural descriptors?

### Fixed Constraints

- Exact float semantics and canonical type identity are preserved.

### Current Findings

- The representative storage evidence favors generic CID compression over every fixed catalog tested, so no fixed transport/pre-interned vocabulary is justified by storage alone.
- No catalog or CID-dictionary container is canonical.
- Canonical type identity remains structural.
- Store v1 is unchanged.

### Evidence and Measurements

#### Prototype evidence (2026-10-01)

`compiler/benchmarks/bench_oi04_type_vocabulary.py` compares the canonical structural encoding against two measurement-only compression families.

- The catalog-alias arms write references to catalog types as small indices instead of 32-byte CIDs, omit those catalog type objects, and add a 32-byte catalog digest to the header.
- The new `cid_dictionary` comparator is catalog-free: every CID referenced by at least two semantic objects is entered once in a deterministic store-wide dictionary carried by the container. References use small dictionary indices while one-use CIDs remain explicit.
- Both decoders rebuild each object's exact structural reference set, re-derive every CID, and rebuild byte-identical canonical store bytes. The dictionary decoder additionally requires the dictionary to equal the exact repeated-reference set, validates record/index/digest integrity, and rejects unknown indices, dual explicit/index encoding, and wrong expansions.
- Deterministic results are in `oi04_type_vocabulary_evidence.json`.

Catalogs:

- `bits5` = `bits<1,8,16,32,64>`.
- `+float2` = binary32/binary64.
- `+float4` adds binary16/bfloat16.
- `common` adds memory effect, stack owner, and the seven opaque kinds.

Floats use a measurement-only descriptor (form 6: radix, precision, emax, emin, encoding width, flags for signed zero/infinities/subnormals/NaN model). The verifier rejects it (`XAX.TYPE.FORM`), no float operation or execution semantics exist, and binary32-FTZ and E4M3FN stay structural in every catalog.

| Measurement | Result |
| --- | --- |
| Integer corpus (5 committed stores, 5 task stores, 2 OI-03 workloads, 2 verified+executed reverse kernels; 26,703 B) | `bits5` −4,991 B (−18.7%); `common` −5,623 B (−21.1%); float entries change nothing |
| Per store | −6.1% (M14, opaque-heavy) to −29.1% under `bits5`; M14 −37.4% under `common` |
| Float reverse kernels (IEEE mix / with FTZ+E4M3FN; unverified) | `bits5` +1.8%/+1.7% (digest + 1 B/object, no hits); `float2` −15.5%/−11.5%; `float4` −24.6%/−11.5% |
| Descriptor size | `bits<N>` body 2 B, envelope 39 B; float body 7–9 B, envelope 44–46 B |
| Store-wide CID dictionary comparator | Integer corpus −4,174 B (−15.6%); 34 dictionary entries cover 175 repeated references. It beats `bits5` on reference-heavy OI-03 stores but trails it on the integer corpus overall. |
| Codec complexity | Catalog alias 57 source lines; CID dictionary 97 source lines (encode + decode + container); no verifier change |

Findings of the prototype:

1. Most byte savings are generic CID-reference compression rather than compact type descriptors. The store-wide dictionary shrinks the same 26,703 B integer corpus by 15.6%, versus 18.7% for `bits5` and 21.1% for `common`. Thus `bits5` has an 817 B / 3.1 percentage-point advantage over a carried generic dictionary, while `common` has a 1,449 B / 5.5-point advantage. That incremental gain comes from the externally fixed vocabulary and omitted catalog objects, not a smaller structural type identity.
2. The generic dictionary wins where non-type references dominate: OI-03 mutual recursion is −1,333 B versus −1,119 B for `bits5`, and OI-03 non-recursive is −942 B versus −820 B.
3. A catalog must be a transport/store alias that expands to the structural descriptor. A canonical pre-interned body form is a second CID for the same type (test `test_catalog_body_form_would_split_identity`), violating canonical identity.
4. Catalogs with no hits cost the 32-byte digest plus one byte per object; the store-wide dictionary instead pays 32 bytes for each repeated CID it chooses to index.

#### Extended evidence (2026-10-02)

The benchmark now uses the compiler's exact canonical binary32/binary64 type objects and adds a representative generated numeric corpus.

- `numeric_service_verified` is 6,231 B / 45 objects. It uses binary32/binary64 in function signatures, CallContracts, pointer permission/address-space forms, vector-shaped arrays, and real stack load/store graphs, and it passes the current verifier.
- `numeric_abi_extended` is 11,762 B / 86 objects. It adds actual function/CallContract uses of exact measurement-only binary16/bfloat16 descriptors plus `vec<N,T>` descriptors, which remain unsupported by production semantics and therefore are not presented as verified language features.

| Arm (across both stores, 17,993 canonical bytes) | Change |
| --- | ---: |
| `bits5` | +197 B |
| `bits5_float2` | −1,250 B |
| `bits5_float4` | −1,720 B |
| `common` | −2,270 B |
| Carried generic repeated-CID dictionary | −2,901 B |

- The fixed catalog does not beat generic compression on representative storage.
- The zero-hit float control is 1,629 B canonical and every fixed catalog is +45 B while the dictionary is −170 B. Zero-hit entries are reported explicitly and the catalog still pays its 32-byte digest/container overhead.
- The extended corpus hits binary16/bfloat16 5 references each and binary32/binary64 12/10.
- Catalog codec complexity is 88 source lines versus 97 for the generic dictionary.
- The catalog decoder now validates the catalog digest, whole-container digest, record order, and exact index table instead of ignoring trailer/index corruption.

#### Mutation cells

Eight deterministic mutation cells cover bit width, binary32->binary64, binary16->bfloat16, vector lane count, pointer permission, pointer address space, vector creation, and one invalid-pointer repair. Structural-diagnostic and compact-alias arms have the same exact target CIDs and strict packet checkers.

### Closure Criteria

- [ ] Serializer size, compiler complexity, and mutation reliability across representative numeric/target workloads. Partial: serializer size and codec complexity are measured (tables above), and eight deterministic mutation cells exist.
- [ ] Mutation-reliability evidence on real floating-point workloads (the additional closure gate named in the original).

### References

- `compiler/benchmarks/bench_oi04_type_vocabulary.py`
- `oi04_type_vocabulary_evidence.json`
- Test `test_catalog_body_form_would_split_identity`

## OI-05 — Proof-fact persistence

**Status:** CLOSED (2026-10-01)

### Summary

Which derived facts should be serialized/persisted, cached separately, or recomputed?

### Fixed Constraints

- Derived facts are never semantic authority.
- Derived facts are invalidated with all meaning-affecting dependencies.

### Current Findings

Successful object-verification facts are a separate non-semantic `xax-proof-cache-v1` sidecar candidate, never semantic store records or semantic authority.

- Each entry is keyed by exact verifier identity, subject CID, and the subject's exact sorted direct-reference CID tuple.
- Only successful verification is cached.
- Whole-store digest/CID decoding and rooted/acyclic closure checks remain active.
- Stale subject/dependency/verifier keys miss deterministically.
- Cache framing is canonical binary with its own BLAKE3 integrity digest; malformed/corrupt sidecars fail explicitly.
- `Workspace.load/save` can opt into a separate cache path. Successful local commits replace only the verified new frontier entries while pruning subjects no longer present.
- Deleting the sidecar leaves canonical store bytes, root identity, diagnostics, and compilation semantics unchanged.

### Evidence and Measurements

Deterministic raw evidence is committed in `compiler/benchmarks/oi05_proof_cache_evidence.json` and reproduced by `bench_oi05_proof_cache.py`. The focused correctness suite is `tests/test_oi05_proof_cache.py`.

The fixed workload contains 96 constant-return functions, 291 program objects / 42,155 store bytes, and a 296-object package-build snapshot / 42,935 store bytes. Seven raw timing samples are retained for every timing arm. Timings are medians on this host.

| Measurement | Cold / no cache | Warm / with cache | Change |
| --- | ---: | ---: | ---: |
| Verifier only | 92.65 ms | 42.46 ms | −54.2% |
| Load + verify, including store/cache decoding across a restart | 135.98 ms | 124.27 ms | −8.6% |
| Compiler only | 127.55 ms | 79.36 ms | −37.8% |
| Load + compile, restart-inclusive | 171.70 ms | 162.73 ms | −5.2% |
| Build only | 218.56 ms | 171.81 ms | −21.4% |
| Load + build, restart-inclusive | 319.64 ms | 253.19 ms | −20.8% |

Generated artifact bytes/digests and provenance are identical in every cached/uncached arm.

| Cache size | Cache bytes | Store bytes | Ratio |
| --- | ---: | ---: | ---: |
| Program proof cache | 33,639 B | 42,155 B | 79.8% |
| Build-snapshot cache | 34,123 B | 42,935 B | 79.5% |

One-function literal edit:

- Verifies/touches 5 objects and reuses 286.
- Cache maintenance invalidates exactly 5 old entries, writes exactly 5 new entries, accounts 102 direct dependency CIDs, and keeps the cache at 291 entries / 33,639 B.
- The immediately following compile is 81.68 ms versus 127.61 ms without cache (−36.0%).
- The local commit itself is 397.86 ms with cache maintenance versus 388.34 ms without (+2.5%), so persistence is not free.

### Decision

- Proof facts MUST NOT be serialized into canonical semantic objects or treated as source.
- Successful verifier facts MAY be retained in a separate exact-key cache.
- In-memory reuse is the default economical reuse path. Persistent sidecars are optional policy for workloads where repeated verification/build startup amortizes roughly 0.8x-store cache size and maintenance.
- Missing/stale cache entries recompute. Corrupt sidecars may be discarded/recomputed or explicitly rejected.
- Any future proof-fact class with dependencies broader than `(verifier, subject CID, direct-reference CIDs)` must extend its cache key before reuse.
- Host timing magnitudes are evidence for this prototype policy, not normative performance thresholds.

### Closure Criteria

- [x] Incremental verification/compile time, artifact/cache size, dependency maintenance cost, and cold/warm build measurements.

### References

- `compiler/benchmarks/oi05_proof_cache_evidence.json`
- `bench_oi05_proof_cache.py`
- `tests/test_oi05_proof_cache.py`

## OI-06 — Alias/provenance representation and checked-access kernel surface

**Status:** CLOSED (2026-10-01)

**Related ADRs:** ADR-231

### Summary

What compact encoding should represent alias classes/provenance, and which checked memory operations deserve kernel status versus library specialization?

### Fixed Constraints

- Ordinary accesses require proof.
- Checked and raw behavior are explicit.
- Provenance/permission cannot be fabricated.

### Current Findings

- The bounded memory-proof prototype carries an explicit verifier-only alias-class fact derived from exact allocation-node provenance. Two simultaneously live allocations therefore form two precise independent provenance/alias classes without serializing any additional class identifier. `addr.offset` preserves that class. Cross-class pointer/effect use rejects deterministically.
- A comparator in `compiler/benchmarks/bench_oi06_memory_surface.py` shows that serializing local class IDs would add 2 graph bytes / 2 semantic atoms to the two-allocation fixture, while the allocation-derived representation adds zero.
- Explicit small class IDs remain reserved for conservative `may-alias` raw/target mappings where no precise storage-object identity is available. They are not emitted redundantly for ordinary object-backed pointers.
- The same experiment adds measurement-only checked scalar load/store candidates with a dynamic `bits<32>` byte offset and explicit trap-on-failed-bounds behavior, plus a raw-load candidate.
  - Ordinary and checked accesses still require live provenance and permission.
  - Checked loads additionally require the entire candidate view initialized in this bounded prototype. Checked stores do not fabricate initialization for an unknown dynamic offset.
  - Raw load never fabricates provenance/permission or waives bounds. It requires `effect<unsafe>` and a nonzero explicit waiver mask, and can currently waive alignment and/or initialization only.
- Canonical x86-64 and WebAssembly target package CIDs are unchanged. Separate OI-06 target packages advertise these measured candidates.

### Evidence and Measurements

Deterministic evidence is committed in `compiler/benchmarks/oi06_memory_surface_evidence.json` and reproduced by `compiler/tests/test_oi06_memory_surface.py`. `semantic_atoms` counts operation, value, type and attribute handles.

| Candidate versus ordinary form | Graph-body bytes | Store bytes | Semantic atoms |
| --- | ---: | ---: | ---: |
| Checked load versus ordinary load | +3 | +4 | +1 |
| Checked store versus ordinary store | +3 | +3 | +1 |
| Raw initialized load versus ordinary initialized load | +6 | +7 | +3 |

Raw initialized load costs more because the waiver and `effect<unsafe>` continuation remain explicit.

Median cold verifier measurements over 31 samples:

| Pair | Ordinary | Candidate | Change |
| --- | ---: | ---: | ---: |
| Ordinary load versus checked load | 3.19 ms | 3.12 ms | −2.1% |
| Ordinary store versus checked store | 2.65 ms | 2.87 ms | +8.1% |
| Ordinary initialized load versus raw load | 3.27 ms | 3.32 ms | +1.7% |

The small/noisy deltas show that the added proof paths did not introduce a different verifier-complexity regime. These host timings are evidence, not normative thresholds.

Lowering preserves the semantic distinction on two materially different memory models:

| Target package | Lowering | Checked load/store cost versus ordinary static fixture |
| --- | --- | --- |
| OI-06 x86-64 | software unsigned bounds branch plus indexed frame-relative access | each adds 24 code bytes |
| OI-06 WebAssembly | explicit allocation-view bounds branch plus 32-bit linear-memory access | each adds 12 module bytes |

- The checked-load WebAssembly fixture executes offsets 0 and 4 and returns the two initialized words respectively.
- Raw load adds **0** emitted bytes on both targets relative to initialized ordinary load, because its waiver/unsafe facts erase after verification.

### Decision

- Precise object-backed provenance is represented by storage-object/allocation identity and verifier-derived range/permission/alias facts. No second serialized local alias-class ID is carried.
- Conservative mappings MAY carry an explicit compact class ID only when exact object identity is unavailable.
- Dynamic scalar checked load/store deserve kernel status because their failure behavior is semantic, compact (+1 semantic atom in these fixtures), and lowers directly on both frame-relative native memory and WebAssembly linear memory.
- Statically proven accesses remain ordinary load/store and need no checked wrapper. Higher-level slicing/indexing libraries should specialize to those ordinary forms when they can discharge the proof.
- Raw access remains a distinct explicit waiver form with an unsafe effect. The bounded prototype intentionally does not provide a general provenance-forging cast, borrow checker, ownership language, or bounds-waiving raw pointer primitive.

#### Note (2026-10-08, ADR-231)

Checked access gained byte-view widening. On a `bits<8>` view a checked load/store may move 1, 2, 4, or 8 bytes as one `bits<8*size>` integer, with every proof obligation unchanged (`docs/04_MEMORY_RESOURCES.md` §5.2.1). Other element types keep the element-size rule. RISC-V rejects widened byte-view access; SPIR-V kernels take word views only.

### Closure Criteria

- [x] Verifier complexity, graph size, lowering/code-size quality, and target coverage on at least two materially different memory models.

### References

- `compiler/benchmarks/bench_oi06_memory_surface.py`
- `compiler/benchmarks/oi06_memory_surface_evidence.json`
- `compiler/tests/test_oi06_memory_surface.py`
- `docs/04_MEMORY_RESOURCES.md` §5.2.1

## OI-07 — DMA resource-state vocabulary

**Status:** CLOSED (2026-10-01)

### Summary

Which common DMA ownership/mapping/cache states should be standardized across targets?

### Fixed Constraints

- DMA ownership, mapping, cache maintenance, and synchronization are explicit when required.

### Current Findings

The bounded OI-07 experiment standardizes six semantic DMA-buffer states on the existing `resource<K,state>` mechanism:

1. `host_unmapped`
2. `host_mapped`
3. `host_dirty`
4. `device_owned`
5. `device_pending`
6. `host_stale`

- The prototype encodes them as the compact state integers 1–6 under one experimental DMA resource kind. No new object kind, borrow/ownership language, device framework, or hidden runtime was added.
- `device_pending` is deliberately distinct from transferable `device_owned`, so a device write must pass through an explicit synchronizing operation before host ownership can be reacquired.
- `host_dirty` and `host_stale` similarly make required non-coherent clean/invalidate steps verifier-visible.
- Required operations are enforced by semantic state, not harness convention. Omitting cache clean from the non-coherent flow makes `host_dirty` fail the target contract expecting `host_mapped`. Omitting synchronize on either target makes `device_pending` fail the host-acquire contract expecting `device_owned`. All three negative cases reject deterministically with `TARGET-OPERATION-TYPE`.
- The pre-existing M13 accelerator target CID remains unchanged.

### Evidence and Measurements

Deterministic evidence is committed in `compiler/benchmarks/oi07_dma_evidence.json` and reproduced by `bench_oi07_dma.py`. Focused tests are in `tests/test_oi07_dma.py`.

| Package | Memory model | Flow | Packet carrier | Fixed vectors |
| --- | --- | --- | ---: | --- |
| `oi07-noncoherent-split-dma-v1` | separate host-only and device-only memory spaces | acquire → map → host write → cache clean → device acquire → device write → synchronize → host acquire → cache invalidate → host read → unmap → release (uses all six states) | 163 B | 4/4, identical wrapping-add results |
| `oi07-coherent-shared-dma-v1` | one host/device-visible coherent space | acquire → map → host write → device acquire → device write → synchronize → host acquire → host read → unmap → release | 148 B | 4/4, identical wrapping-add results |

The coherent package uses the same shared vocabulary but legitimately omits the dirty/stale cache states and clean/invalidate operations. Both target packages verify and compile deterministically to the existing packet carrier.

### Decision

The cross-target DMA-buffer vocabulary is the six states above.

- A package need only use states that its memory/coherence model requires. Coherent targets may keep host writes/returns in `host_mapped`, while non-coherent targets use `host_dirty`/`host_stale` around explicit maintenance.
- Mapping/unmapping, ownership transfer, cache maintenance, device work, synchronization, and release remain explicit operations/effect transitions.
- Target/platform packages still define address spaces, legal transitions, scope, cache-operation necessity, and lowering. The shared vocabulary does not imply a universal DMA API or runtime.

### Closure Criteria

- [x] At least two substantially different target/platform packages with working DMA flows showing a stable shared vocabulary.

### References

- `compiler/benchmarks/oi07_dma_evidence.json`
- `bench_oi07_dma.py`
- `tests/test_oi07_dma.py`

## OI-08 — Effect partition granularity and persistent edge encoding

**Status:** CLOSED (2026-10-01)

### Summary

How finely should memory/filesystem/network/device effects be partitioned, and should persistent stores encode explicit frontiers, compressed chains, or deterministic reconstruction?

### Fixed Constraints

- The exact effect partial order is preserved.
- Unproven independence is conservative.
- Serialization order is never semantics.

### Evidence and Measurements

`compiler/benchmarks/bench_oi08_effect_edges.py` adds a benchmark-only comparison over the existing `effect<domain,instance>` model. It does not change the canonical graph/store schema.

The corpus contains:

- paired independent instances for each of `memory`, `filesystem`, `network`, and `device`;
- a 36-event four-domain workload with multi-domain steps;
- a filesystem branch/merge case with two unordered roots and one two-predecessor join.

Every XAX fixture is verified through the existing verifier before measurement. The candidate encodings are then checked against the exact authoritative footprint/frontier relation; both must reconstruct an identical transitive partial order before size or timing results are accepted.

#### Partition granularity

The evidence selects **verifier-proven semantic instance** as the granularity rule rather than a fixed finer subdomain vocabulary.

| Workload | Additional unordered effectful-operation pairs exposed | Effect critical path | Cost of refinement |
| --- | ---: | --- | --- |
| Each 8-event two-instance domain workload | 16 | 8 events → 4 | +4 canonical graph-body bytes, +2 semantic graph atoms |
| 36-event mixed workload | 162 | 13 → 6 | +16 graph-body bytes, +8 graph atoms |

- Median whole-store verification rises from roughly 2.8–3.2 ms coarse to 3.5–3.7 ms refined on the 8-event cases, and from 7.99 ms to 10.50 ms on the mixed fixture on this host. These timings are observations, not thresholds.
- When independence is not proven, instance `0` remains the conservative shared frontier.

#### Persistent encoding comparators

1. An **explicit frontier** section repeats domain-instance handles and predecessor handles per event.
2. **Domain-grouped deterministic reconstruction** carries explicit operation handles, groups them by domain instance in a semantic topological run, uses a compact "previous member" code for the common single-chain predecessor, and stores explicit backward predecessor deltas at roots/forks/joins. That run order is itself effect-semantic data; ordinary XAX node, record, CID, file, construction, or traversal order is never consulted.

| Case | Explicit frontier | Reconstruction | Change (bytes / atoms) |
| --- | ---: | ---: | --- |
| Each refined 8-event pair | 48 B / 44 scalar-handle atoms | 36 B / 32 atoms | −25.0% / −27.3% |
| 36-event mixed workload | 230 B / 226 atoms | 162 B / 158 atoms | −29.6% / −30.1% |
| Branch/merge case | 22 B / 18 atoms | 20 B / 16 atoms | preserves two roots and the exact two-predecessor join |

- Median candidate verification is also lower in these fixtures (mixed: 451.9 us explicit versus 349.2 us reconstructed).
- Mixed reconstruction alone costs 254.7 us; the small branch case reconstructs in 34.1 us.
- Raw timing samples and deterministic size/order results are committed in `compiler/benchmarks/oi08_effect_edges_evidence.json`. Focused reproduction/rejection tests are in `compiler/tests/test_oi08_effect_edges.py`.

### Decision

- Memory/filesystem/network/device effects use the narrowest **proven** domain instance already expressible as `effect<domain,instance>`. XAX does not standardize a deeper universal file/socket/device/memory partition taxonomy.
- Unproven independence uses one conservative instance.
- For a future persistent effect-edge section, domain-grouped semantic runs with explicit fork/join predecessor deltas are preferred over repeating full explicit frontiers, because they preserve the identical partial order while reducing bytes and did not increase verifier cost on the measured corpus.
- The explicit frontier remains a valid verifier/internal normal form and fallback.
- OI-08 does **not** make either benchmark carrier part of canonical store v1. Adopting the selected compression in a future schema still requires the ordinary schema-version process, but the representation choice itself is resolved.

### Closure Criteria

- [x] Optimization freedom, graph size, verifier time, and reconstruction cost on representative programs.

### References

- `compiler/benchmarks/bench_oi08_effect_edges.py`
- `compiler/benchmarks/oi08_effect_edges_evidence.json`
- `compiler/tests/test_oi08_effect_edges.py`

## OI-09 — Indirect CallContract representation

**Status:** CLOSED (2026-10-01)

### Summary

Should indirect-call effects/resources/capabilities/control be embedded with callable values, referenced through contract objects, or represented through sealed dispatch sets?

### Fixed Constraints

- Every indirect call has a bounded verified contract.
- Unbounded unspecified effects are invalid.

### Evidence and Measurements

`compiler/benchmarks/bench_oi09_call_contracts.py` builds:

- five verified direct-call contract families (pure value, filesystem effect, network effect, device effect plus an explicit resource-typed authority value, and non-returning trap control);
- 15 exact dispatch sets;
- two 960-indirect-call placement profiles.

The comparator uses the same exact direct-function interface/effect/control facts for all three arms:

1. contract fields embedded in every callable carrier;
2. separately content-addressed referenced CallContract objects;
3. sealed exact-target sets carrying the bounded union contract.

Every candidate is rejected unless every callable resolves a finite bound and every admitted target stays within it; there is no unknown-effects arm. Raw deterministic corpus identities, placement sizes, reuse/devirtualization facts, package-edit churn, and host timing observations are committed in `compiler/benchmarks/oi09_call_contract_evidence.json`.

#### Placement profiles

The **reuse-heavy** profile has 120 callable values and 960 calls. The **sparse-callable** profile keeps the same 960 calls but uses only 15 callable values (three per contract); it records the crossover instead of hiding it.

| Profile | Metric | Embedded | Referenced | Sealed |
| --- | --- | ---: | ---: | ---: |
| Reuse-heavy | Metadata bytes | 9,962 | 9,737 | 11,651 |
| Reuse-heavy | Ideal semantic atoms | 1,801 | 1,231 | 1,341 |
| Reuse-heavy | Median placement verification (approx., this host) | 2.51 ms | 0.60 ms | 0.77 ms |
| Sparse-callable | Metadata bytes | 2,087 | 2,387 | 4,301 |
| Sparse-callable | Ideal semantic atoms | 1,066 | 1,021 | 1,131 |
| Sparse-callable | Median placement verification (approx.) | 0.36 ms | 0.29 ms | not stated |

- Reuse-heavy: referenced contracts save 2.3% bytes and 31.6% atoms versus embedding while verifying about 76% faster. Each of the five referenced contract objects is reused by 24 callable values.
- Sparse-callable: embedding is smaller (2,087 B) than referencing (2,387 B), while referenced contracts still use fewer semantic atoms and verify faster. Sealed sets remain largest (4,301 B / 1,131 atoms) and slowest of the two reusable-object candidates in this profile. Direct embedding can therefore be a useful future serialization compression for low-reuse contracts, but it is not the best semantic authority placement.

#### Sealed sets

- Sealed sets uniquely expose exact-target optimization information: all sealed callables have exact sets and one third of calls are singleton-devirtualizable in both profiles.
- The cost is interface coupling. Replacing one implementation with a new function CID while preserving the exact same derived CallContract changes **3 sealed-set identities** and forces **192 indirect-call references** through affected callable carriers to rebind (24 carriers in the reuse-heavy profile; 3 in the sparse profile).
- The separately referenced CallContract CID is unchanged. Embedded contract bytes are likewise unchanged but have no independent reusable identity.

#### Tests

Focused OI-09 tests cover deterministic identity, exact direct-function bounding, noncanonical-control rejection, rejection of an effectful function under an empty contract, all three placement comparators, sealed cross-contract target rejection, the measured byte crossover, and committed-evidence reproduction.

### Decision

- The semantic representation is a separately content-addressed **referenced CallContract object**. Callable values reference that bounded contract identity.
- Exact sealed dispatch sets are optional additional optimization facts for devirtualization. They do not replace the contract and cannot create an unspecified-effects escape hatch.
- Full contract embedding is not semantic authority, though a later persistent serializer may deterministically compress low-reuse references if it reconstructs the identical contract identity.
- Prototype kind 11 implements the smallest winning reusable object: exact input/output type references plus return/trap bounds. Current effect bounds and resource/capability-bearing value requirements are reconstructed from the exact typed interface.
- The compiler still has no general indirect-call opcode, so this closes the **representation** issue without claiming indirect-call execution/lowering support.

### Closure Criteria

- [x] Call-heavy workloads measuring object size, verifier cost, devirtualization, reuse, and package-interface stability.

This closure covers the representation only. Indirect-call execution/lowering support is not claimed (the compiler has no general indirect-call opcode).

### References

- `compiler/benchmarks/bench_oi09_call_contracts.py`
- `compiler/benchmarks/oi09_call_contract_evidence.json`

## OI-10 — Portable trap payload core

**Status:** CLOSED (2026-10-01)

### Summary

What minimum machine-readable trap payload is portable, versus target/platform-specific reason data?

### Fixed Constraints

- Trap is explicit non-returning control with no implicit cleanup/unwind.

### Decision

The portable core is a canonical unsigned 16-bit reason code.

- An empty payload means reason 0 (`unspecified`) with no target detail.
- A non-empty payload begins with canonical ULEB `0..65535` followed by opaque target/platform bytes. A zero prefix is valid only when suffix bytes are present.
- Prototype portable reason meaning 1 is `explicit`. Additional portable meanings require an explicit specification decision.
- The verifier rejects noncanonical/oversized reason prefixes.
- Diagnostics expose the exact payload split as `reason`, `target_data`, and raw `payload`.

### Evidence and Measurements

The committed OI-10 evidence maps reason `0x1234` through two materially different native targets without adding runtime or unwind semantics.

| Target | Emitted sequence | Size |
| --- | --- | ---: |
| x86-64 Windows | the existing frame prefix followed by `mov rax,0x1234; ud2` | 19 function bytes total in this bootstrap path |
| AAPCS64 | `movz x0,#0x1234; brk #0x1234` | 8 bytes |

- Changing only the target-specific suffix changes graph identity but leaves both native sequences unchanged.
- Changing the portable reason changes native code.
- Focused tests cover canonical encoding, deterministic malformed-payload rejection, interpreter/diagnostic projection, both native mappings, suffix-vs-core identity behavior, and deterministic semantic identity.

### Closure Criteria

- [x] Two materially different native targets plus diagnostic/ABI use cases demonstrating a common minimal payload.

## OI-11 — Non-native atomic synthesis policy

**Status:** CLOSED (2026-10-02)

### Summary

When should unsupported atomics become bounded inline sequences, explicitly permitted runtime assistance, or hard rejection?

### Fixed Constraints

- No hidden lock/helper/scheduler/syscall.
- Target capability and build/profile policy are explicit.

### Decision

Exact target capability remains authoritative.

| Strategy | Selected only when |
| --- | --- |
| `native` | an exact supported address-space/width/alignment/family/order/scope request |
| `bounded_sequence` | the target/backend has a finite declared inline sequence, finite retry behavior, an exact maximum sequence instruction count, and `permit_bounded_inline=true`; otherwise the request rejects |
| `runtime_assist` | explicit policy permission plus an explicit helper identity and backend-declared helper contract; no current target implements one, so absent/undeclared assistance rejects rather than synthesizing a helper |

Unsupported capability and post-lowering real-time-profile violations reject deterministically.

### Evidence and Measurements

The committed cross-target evidence retains the x86-64 32-bit system-scope seq-cst load as a 2-instruction atomic sequence (load+`mfence`) and adds AArch64 as a materially different second architecture.

| Target | Order | Lowering | Emitted atomic node | Versus native acquire |
| --- | --- | --- | ---: | ---: |
| x86-64 (32-bit, system scope) | seq-cst | 2-instruction sequence: load + `mfence` | 12 bytes (versus 9 bytes for native acquire) | +3 bytes |
| AArch64 concurrency target (naturally aligned 32/64-bit, system scope) | acquire | native `LDAR` | 8 bytes | — |
| AArch64 (same) | seq-cst | finite 3-instruction sequence `DMB ISH; LDAR; DMB ISH`, with one deterministic address-materialization instruction in the emitted node | 16 bytes | +8 bytes |

- Both paths are `lock_free=always`, `retry=none`, `wait_free`, have no runtime helper, and preserve the canonical graph CID when bounded-inline policy rejects.
- Unsupported AArch64 width, alignment, scope, invalid load order, disabled bounded-inline policy, and strict unknown-timing profile all have deterministic rejection evidence.
- wasm32 remains a hard-rejection comparator.

#### Observed host latency

Observed executable-host latency is recorded separately from guaranteed timing metadata. On Linux x86-64 (`6.18.44`, Debian GCC 14.2.0), 31 warm-run batches of 500,000 calls measured the emitted XAX functions as follows.

| Path | Median | p10 | p90 |
| --- | ---: | ---: | ---: |
| Native acquire | 1.994138 ns/call | 1.965538 ns | 2.331232 ns |
| Seq-cst bounded path | 18.83312 ns/call | 17.94376 ns | 24.11178 ns |

> [!WARNING]
> These are cost observations, not cycle/deadline guarantees. No AArch64 hardware or `qemu-system-aarch64` was available on this host. The existing AArch64 execution harness is retained, and hardware latency/timing remains explicitly unknown rather than inferred.

### Closure Criteria

- [x] Correctness, code size, latency, lock-free/progress behavior, and target diversity across multiple architectures.

## OI-12 — Timing-proof representation

**Status:** CLOSED (2026-10-02)

### Summary

What persistent representation best captures path bounds, microarchitectural assumptions, interrupt-mask limits, and derived timing proofs?

### Fixed Constraints

- Guarantees remain distinct from cost estimates.
- Strict profiles reject unknown required properties.

### Decision

A measurement-only non-semantic timing-proof sidecar carries one dependency-exact representation for two materially different models:

- `fixed-inorder`: fixed per-operation upper bounds, zero interrupt contribution.
- `bounded-memory-interrupt`: base operation bounds plus an explicit bounded memory contribution and bounded interrupt-count/service/mask assumptions.

The carrier:

- is keyed by exact subject semantic CID, target CID, a deterministic `RealtimeProfile` identity, timing-model identity/version, exact reachable function/graph CIDs, and only the timing assumptions relevant to that subject;
- stores path/control, recursion/retry/progress, relevant operation timing bounds, applicable memory/interrupt assumptions, the resulting cycle upper bound, and a dependency fingerprint.

Unknown required memory or interrupt assumptions reject. Deletion of the sidecar leaves the canonical root and execution unchanged. Cost estimates remain a separate non-proof field and do not invalidate proofs.

### Evidence and Measurements

On the committed 2,051-byte three-function branch/call/memory fixture:

| Model | Caller proof | Cycle bound | Three-function proof set |
| --- | ---: | ---: | ---: |
| `fixed-inorder` | 351 bytes | 15 cycles | 911 bytes |
| `bounded-memory-interrupt` | 363 bytes | 42 cycles | 946 bytes |

Exact incremental invalidation:

| Change | Invalidated entries |
| --- | --- |
| Unrelated-function edit | 1/3 entries (caller + leaf reused) |
| Callee-body edit | exactly caller + callee (2/3) |
| Memory-bound change | exactly the two memory-dependent proofs |
| `sub` timing-assumption change | only the caller |
| Target or profile change | all 3 |
| Change of the separate cost estimate | 0 |

- The compact local-handle timing query is 10 request bytes and 14 response bytes.
- The committed 31-sample host-tooling timings are observations, not target timing guarantees: proof construction/deep checking are approximately low-single-digit milliseconds, while decoded warm-key queries are approximately 0.1 ms on this host.
- No canonical store, XAX semantic object, target timing guarantee, or cost-model semantics were changed.

### Closure Criteria

- [x] At least two materially different timing models, measuring proof size, incremental invalidation, verifier cost, and query cost.

## OI-13 — GPU/accelerator synchronization-scope normalization

**Status:** CLOSED (2026-10-02; the original record has no status line and states "OI-13 is closed for scope normalization")

### Summary

Can a small portable scope lattice cover major GPU/accelerator models without semantic loss?

### Fixed Constraints

- Target-specific scopes remain legal.
- An unsupported requested scope is rejected.

### Decision

The OI-13 measurement harness adds a second package-driven accelerator model without changing canonical synchronization semantics.

- `coherent-grid-accelerator-v1` has one coherent host+device-visible unified space plus workgroup-local memory and explicitly supports system/device/workgroup scopes.
- The existing SIMT package retains its split host/global/workgroup topology and exact target CID.
- The smallest exact common portable lattice is `workgroup < device`. Both directions round-trip exactly on both packages; no strengthening or weakening fallback exists.
- `system` remains an explicit target-only scope on the coherent package, and reverse mapping reports it nonportable. The existing SIMT package rejects it.

### Evidence and Measurements

- Portable atomic-load/store and barrier conformance vectors cover workgroup and device scopes, workgroup global/local cross-space synchronization, rejection of device scope when workgroup-local memory participates, and the coherent-only system-scope escape.
- Both target packages verify and compile through the existing deterministic accelerator deployment path and execute the existing wrapping-add conformance kernel. No runtime dependency is introduced.
- The original M13 evidence JSON remains byte-identical.

> [!WARNING]
> The evidence is semantic/target-package conformance only. No physical accelerator was executed, so it makes no device latency, throughput, coherence-implementation, or vendor-conformance claim.

### Closure Criteria

- [x] Working target packages for multiple different accelerator memory models and portable atomic/barrier conformance vectors (closed for scope normalization).

<details>
<summary>Historical Record</summary>

#### 2026-09-30 (prototype evidence)

M13 adds one non-CPU target package with explicit device/workgroup execution scopes, host/global/workgroup memory spaces, and deterministic rejection of an unsupported system-scope launch. This demonstrates the required reject path for one model but provides neither a second accelerator memory model nor portable cross-vendor atomic/barrier vectors, so OI-13 remains open.

</details>

## OI-14 — Compile-time fuel units and introspection authority granularity

**Status:** OPEN (2026-11-25): ADR-421 proposes adopting the function-interface/body authority split; this stays open until the owner accepts it. The original record has no status line; it states "OI-14 remains open until that split is adopted".

### Summary

What deterministic budget metric and introspection-capability granularity best balance portability, least authority, evaluator freedom, and diagnostics?

### Fixed Constraints

- Every evaluation is finite, sandboxed, deterministic under declared inputs/policy, and cannot partially commit.

### Current Findings (2026-10-02)

Three bounded META workloads cover compiler-like body inspection plus semantic generation, target/interface inspection plus target-specialized generation, and ordinary nested generic construction.

| Measurement | Workload 1 (compiler-like) | Workload 2 (target/interface) | Workload 3 (nested generic) |
| --- | ---: | ---: | ---: |
| Semantic steps | 13 | 9 | 9 |
| Maximum call depth | 1 | 1 | 2 |
| Peak evaluator frame storage | 288 bytes | 256 bytes | 304 bytes |
| Constructed objects | 3 | 3 | 3 |
| Emitted graph nodes | 1 | 1 | 1 |

- Repeated fresh evaluations and three independent process runs reproduce the same counters, result CIDs, budget-failure rules, and deterministic evidence hash.
- Exact below/at/above tests cover steps, call depth, active frame bytes, object count, and emitted graph-node count. Every below-limit failure leaves the evaluator cache empty and the program root unchanged.

### Decision

#### Budget policy (selected)

**One deterministic semantic-step limit per evaluation/workload plus hard structural caps for call depth, active evaluator frame bytes, constructed objects, and emitted graph nodes.**

- The existing evaluator already enforces this shape, so no weighted or host-dependent fuel formula is introduced.
- On the measured corpus this reduces workload-calibrated values from 15 independent vector limits to 3 step limits plus 4 shared hard caps.
- Host `perf_counter_ns`/`tracemalloc` observations are retained only as non-semantic analysis data. The three-workload evaluator-frame/host-peak relationship is strongly negative on this host. This limited observation supports keeping host memory out of semantic fuel rather than treating it as a portable proxy.

#### Authority split (least-authority candidate)

Authority is split only once, where the workloads demonstrate a least-authority benefit.

- `inspect_function_interface` authorizes two arity queries.
- Existing `inspect_function` remains required for graph/body access.
- The target-adapter workload therefore reads exact function interface facts without body authority; the compiler-like workload explicitly requests both.
- This costs one extra compact capability byte only when both authorities are required and adds no runtime dependency.
- No per-query capability family is introduced.

The deterministic fuel subquestion is resolved by this evidence. The function-interface/body split is the least-authority candidate with measured byte overhead.

### Closure Criteria

- [ ] Self-hosting, target-generation, and metaprogramming workloads measuring stability of limits, failure reproducibility, capability overhead, and implementation complexity. Partial: three bounded META workloads are measured.
  - [x] The deterministic fuel subquestion is resolved by the three-workload evidence.
  - [ ] The function-interface/body authority split is adopted ("OI-14 remains open until that split is adopted").

<details>
<summary>Historical Record</summary>

#### 2026-09-30 (prototype evidence)

M9 uses deterministic counts for evaluated blocks/nodes, active frame storage, constructed semantic objects, emitted graph nodes, and active call depth. Tests exhaust every dimension, including recursive group calls, and confirm no cache entry or program-root change. Five explicit capabilities separately authorize type, constant, target, declared-input, and construction operations. This proves a workable bounded slice but lacks workload evidence for portable fuel calibration, host-memory correlation, or finer body-introspection authority, so OI-14 remains open.

</details>

## OI-15 — Specialization object boundaries

**Status:** CLOSED (2026-11-25). The missing compile-time criterion is measured (see "Compile time (2026-11-25)"); the 2026-10-02 decision stands.

> [!NOTE]
> Superseded claim: the 2026-10-02 closure evidence paragraph ends with "OI-15 is closed." The later status line above (2026-11-15, the audit that added status lines) supersedes it, because that paragraph does not meet every item of the closure criteria. The paragraph is kept as the historical record.

### Summary

What canonical granularity best supports specialization identity/reuse versus graph growth and invalidation?

### Fixed Constraints

- Specialization is semantic XAX computation, not textual substitution.
- Generated graphs are verified.

### Evidence and Measurements

#### Closure evidence (2026-10-02)

OI-15 measures eight semantic specialization requests over five generic functions: one repeated request, partially shared nested-call specializations, a three-block conditional specialization, and a specialization reachable only through a branch that becomes dead under ordinary optimization.

- Seven unique requests produce seven unique verified function CIDs and seven unique specialized graph CIDs. The repeated request reuses the exact function CID.
- All eight materialized results execute identically to their unspecialized references.
- Store v1 already content-addresses the graph fragment beneath each function shell, so a second graph/body specialization-cache boundary produced **zero additional body-cache reuse** and no canonical-store reduction. All candidates materialize the same **5,381-byte / 33-object** semantic store with **22 new / 11 reused** objects.

A one-input change rewrites the same **5 semantic objects / 815 bytes** for all boundaries. The derived cache cost differs:

| Boundary | Derived cache cost |
| --- | --- |
| Whole-function identity | 100 bytes / one lookup |
| Graph + shell | 200 bytes / two lookups |
| Module aggregate | 486 bytes for one module aggregate rewrite |

- Across the corpus, optimizer/code-size processing reduces seven unique specialized functions from **232 to 137 x86-64 emitted function bytes**.
- A specialization reachable only from a constant-dead branch is absent from the post-optimization runtime closure (**19 to 15 objects**).
- Cache keys include source semantic CID, exact specialized parameter/type/value inputs, specializer identity, evaluator identity/version, and verifier identity. Corrupt or stale records reject deterministically.

#### Compile time (2026-11-25)

`bench_oi15_specialization_boundaries.py` re-run, MEASURED on WSL 2 on the Ryzen 9 5900HS, CPython 3.12.3, the Python reference (11 samples per metric, raw samples in
`compiler/benchmarks/oi15_specialization_timing_20261125.json`; the evidence file reproduced unchanged):

| Step | Median | p10–p90 |
| --- | ---: | ---: |
| Specializing the eight requests (shared by every boundary) | 1.390 ms | 1.313–1.708 ms |
| Cache record, whole-function identity | 0.044 ms | 0.042–0.070 ms |
| Cache record, graph + shell | 0.064 ms | 0.063–0.087 ms |
| Cache record, module aggregate | 0.014 ms | 0.013–0.017 ms |
| Code-size query (x86-64 emission of the seven functions) | 9.464 ms | 8.627–10.982 ms |

The boundaries differ only in their cache record, at most 0.05 ms per run against 1.39 ms of specialization; compile
time does not change the decision below.

### Decision

- The mechanical default is **whole specialized-function identity/cache entries**, while retaining the existing independently interned canonical graph fragment beneath the function.
- A separate fragment-level specialization identity is not selected because it duplicates cache/index/query work without measured reuse.
- Module aggregation is not selected because one local input change rewrites the aggregate.
- This closes OI-15 for current store-v1 function semantics. Future function-shell semantics that introduce independently varying canonical metadata would require new evidence rather than changing this default implicitly.
- The original paragraph ends: **OI-15 is closed.** (See the warning above.)

### Closure Criteria

- [x] Cache reuse.
- [x] Graph size.
- [x] Compile time (2026-11-25, MEASURED; see "Compile time (2026-11-25)").
- [x] Optimization opportunity.
- [x] Transaction locality.

<details>
<summary>Historical Record</summary>

#### 2026-09-29 (prototype evidence)

M6 constructs one deterministic specialization object for a verified straight-line single-block pure function under explicit constant arguments. The clone is content-addressed, verified before publication, added beside the unchanged source, and leaves callers untouched. The smoke produced one stable clone CID with 5 new verified objects and 5 reused objects. No cache-reuse, graph-growth corpus, compile-time, profitability, or general META evidence exists, so OI-15 remains open.

#### 2026-09-30 (prototype evidence)

M9 adds general compile-time evaluation and a content-derived request key. Its constructor creates a canonical constant, one-node graph, and constant-return function; repeated requests reuse the verified cached result, and explicit materialization adds the function without retaining compile-time operations in its runtime closure. The smoke records three created CIDs and one stable generated function CID. One construction shape and one cache-hit case do not establish optimal graph/function/module boundaries across generic workloads, so OI-15 remains open.

</details>

## OI-16 — Target semantic/instruction granularity and opaque-contract minimums

**Status:** OPEN (the original record has no status line; it states "OI-16 remains open")

### Summary

Should target semantics be modeled primarily per instruction or through shared primitives plus encoding variants, and do some hardware classes require stronger minimum opaque contracts?

### Fixed Constraints

- Effects/control/memory/optimization restrictions are never unspecified.

### Current Findings

A measurement-only OI-16 harness compares complete per-instruction contracts with shared semantic primitives plus target encoding variants for wrapping integer `add/sub` at 32/64 bits on the existing x86-64, AArch64, and WebAssembly backends.

- Both forms normalize to identical type/effect/control/memory contracts and produce byte-identical target artifacts for every target/width. WebAssembly execution also matches the semantic reference.
- Existing generated code is unchanged, with identical per-node ranges in both arms.

| Measurement (three compact experimental packages) | Per-instruction | Shared primitives |
| --- | ---: | ---: |
| Package bytes | 324 | 279 |
| Compact model-description bytes | 450 | 354 |
| Logical records | 12 | 18 |
| Decoder/encoder implementation | 41 lines | 57 lines |
| Cost of adding another width | 34 bytes/target | 14 bytes/target |

| Target | Emitted bytes for the 32/64-bit two-op function |
| --- | --- |
| x86-64 | 8/10 |
| AArch64 | 12/12 |
| WebAssembly | 75/77 |

#### Opaque-contract minimum

- The opaque-contract negatives establish an explicit minimum of input/output types, effects, control behavior, memory behavior, legality, and optimization restrictions. Missing fields reject rather than implying purity.
- Synchronizing accelerator operations additionally require explicit supported scope, source/destination space, and visibility. The complete fixture permits only a narrow device-space barrier rather than a global unknown-side-effect barrier.
- These schemas remain benchmark-only and store/target serialization is unchanged.

### Closure Criteria

- [ ] Multiple CPU/accelerator target packages measuring package size, verifier complexity, code quality, and optimization barriers. Partial: the 2026-10-02 benchmark-only harness measures package size, code bytes, and the opaque minimum on three targets; the original does not state this criterion as met.
- [ ] Canonical target-package integration of shared primitives and the selected opaque minimum (the remaining gap named in the original).

<details>
<summary>Historical Record</summary>

#### 2026-09-29 (prototype evidence)

M4 uses one compact x86-64 Windows raw-load-image package carrying machine width, ABI registers, stack rules, supported operations, and supported terminators. M5 adds both a register-free WebAssembly stack-machine package and an AArch64/AAPCS64 bare-metal package. Direct deterministic encoders execute the same control/call/memory vectors on Windows x86-64, Node/V8 WebAssembly, and QEMU AArch64 without core semantic changes. This exposed and removed x86-only target decoding, ABI, register, shadow-space, and arithmetic-width assumptions. It does not close this issue: instruction semantics/encodings remain bootstrap code, no cost model exists, and target-package size/verifier/code-quality evidence is not yet measured.

#### 2026-09-30 (prototype evidence)

M13 adds generic target-operation contracts plus a non-CPU SIMT packet target whose topology, three memory spaces, typed target operations, scopes, synchronization/blocking flags, and packet opcodes reside in the target package. The core verifier interprets only the generic contract shape. This broadens the hardware class evidence but remains one synthetic accelerator model with Python bootstrap emission and no package-size/verifier-cost/code-quality comparison, so OI-16 remains open.

</details>

## OI-17 — Target cost-model representation and calibration

**Status:** OPEN (the original record has no status line; it states "OI-17 remains open")

> [!IMPORTANT]
> Exact blocker: repetition on at least one materially different real microarchitecture/objective set before selecting a default model family and unknown-hardware fallback.

### Summary

What combination of static tables, symbolic functions, profile-conditioned models, and measured calibration best ranks candidate code and predicts magnitude?

### Fixed Constraints

- Costs remain non-semantic estimates unless separately guaranteed.
- Ordering and magnitude are evaluated independently.

### Evidence and Measurements (2026-10-02)

A benchmark-only OI-17 harness separates five verified calibration functions from eight held-out verified candidates in four semantic-equivalence families:

- arithmetic `x*2`;
- lazy/eager conditional control;
- direct/local-stack-roundtrip identity;
- dependency-chain/independent `4*x`.

Method:

- The emitted Win64 code is executed directly on one pinned Intel Xeon Platinum 8370C host through the existing explicit `ms_abi` path, with 21 raw samples after warmup for both dependent-call latency and four-way independent-call throughput. Code size remains exact from lowering.
- Three non-semantic model families are compared: a fixed per-operation table, a small critical-path/resource composition model, and coefficients calibrated only from the separate calibration functions and keyed by exact target CID + microarchitecture + model version + raw calibration identity.

Results on the held-out candidates:

| Model | Latency pairwise ranking | Latency mean normalized absolute magnitude error | Throughput pairwise ranking | Throughput mean normalized absolute magnitude error |
| --- | ---: | ---: | ---: | ---: |
| Static (fixed per-operation table) | 50% | 24.12% | 25% | 33.23% |
| Symbolic (critical-path/resource) | 50% | 23.23% | 25% | 27.53% |
| Calibrated | 50% | 17.84% | 25% | 7.59% |

- Measured calibration improves magnitude substantially on this host without improving candidate ordering. Ordering and magnitude remain separate quality dimensions.
- A bounded calibrated-latency choice over the two memory-identity candidates selects the measured-faster direct candidate, and the selected semantic store is re-verified before emission.
- Calibration is sidecar/build-policy state and does not alter semantic CIDs.
- Only one real microarchitecture was available, so the portable acquisition harness and raw samples are committed but cross-microarchitecture evidence is missing.

### Closure Criteria

- [ ] Candidate-set ranking accuracy and normalized magnitude error on measured hardware, across multiple objectives and microarchitectures. Partial: measured on one real microarchitecture (Intel Xeon Platinum 8370C) only.
- [ ] Repetition on at least one materially different real microarchitecture/objective set, then selection of a default model family and unknown-hardware fallback (the exact blocker).

<details>
<summary>Historical Record</summary>

#### 2026-09-30 (prototype evidence)

M12 introduces a lowering-derived code-size oracle that measures the exact emitted function extent of each verified candidate on x86-64 and WebAssembly. On the fixed `x * 2` search fixture it ranks the validated replacement at 43 versus 59 bytes on x86-64 and 32 versus 36 bytes on WebAssembly. This proves target-aware size selection for one narrow objective; it provides no measured-hardware ranking accuracy, latency/throughput/energy objective, microarchitecture calibration, or magnitude-error study. OI-17 remains open.

</details>

## OI-18 — Legalization/optimizer organization and machine-level IR

**Status:** CLOSED (2026-11-25). Verifier complexity is recorded (see "Verifier complexity (2026-11-25)"); the 2026-10-02 decision stands.

> [!NOTE]
> Superseded claim: the 2026-10-02 closure evidence paragraph ends with "OI-18 is closed." The later status line above (2026-11-15, the audit that added status lines) supersedes it, because that paragraph does not meet every item of the closure criteria. The paragraph is kept as the historical record.

### Summary

Should implementations use one universal machine graph or target-specialized machine forms; conventional passes, demand-driven rewriting, equality saturation hybrids, or other bounded search organizations?

### Fixed Constraints

- Transformations preserve semantics.
- Termination/failure is detectable.
- Target assumptions come from packages.

### Evidence and Measurements

#### Closure evidence (2026-10-02)

OI-18 compares the current staged semantic optimizer/direct lowering with one benchmark-only alternate organization: demand-driven target-package legality/selection cached per immutable block, with no persistent machine IR.

- The five-workload corpus covers straight-line arithmetic, branch/merge, stack memory, direct calls, and a real system-scope seq-cst atomic legalization on both x86-64 and AArch64.
- Both organizations produce the exact same optimized function CID and byte-identical emitted artifacts for all ten target/workload cells. Semantic execution vectors also match.
- The alternate adds **51 benchmark-only selector lines** and **60 deterministic legality/selection work units** over the ten cold cells. It adds no production or target-specific lines, no target-duplication reduction, and no code-size/optimization improvement.
- Cold median wall time is higher in 9/10 cells and equal-output peak memory is generally higher. The sole memory decrease occurs on one noisy branch cell and does not correspond to less compiler work.
- After a one-block branch edit, the alternate correctly reuses **2/3** cached block selections on both targets, but the existing backend must still re-lower the function:

| Target | Median incremental wall time: demand vs staged | Retained-cache-aware peak memory: demand vs staged |
| --- | ---: | ---: |
| x86-64 | 23.837 ms vs 21.948 ms | 45,050 vs 25,972 bytes |
| AArch64 | 24.014 ms vs 21.218 ms | 42,468 vs 24,707 bytes |

- The explicit unsupported WebAssembly atomic case rejects deterministically both in the selector and unchanged backend.
- Existing optimizer search remains bounded by deterministic fuel and ordinary candidate validation.

#### Verifier complexity (2026-11-25)

`bench_oi18_optimizer_organization.py --measure` re-run, EXECUTED on WSL 2 on the Ryzen 9 5900HS, CPython 3.12.3, the Python reference (deterministic counts in
`compiler/benchmarks/oi18_optimizer_organization_evidence_20261125.json`, its `verifier` record; timing samples
beside it):

- The selected organization needs no verifier of its own: no machine IR exists, so the ordinary semantic verifier and
  the optimizer's candidate validation are the whole correctness surface. Over the ten cold cells they check 21 store
  objects and 8 optimizer events, and validate 192 search candidates, rejecting 186.
- The alternate adds 60 legality/selection checks on top of that, for byte-identical output.

### Decision

The simpler organization remains the mechanical default: **staged semantic optimization followed by direct target-specialized lowering, with no universal persistent machine IR and no additional demand-selection layer**.

- Target assumptions continue to come from target packages.
- Future evidence may justify a target-specialized derived form only when it materially reduces total compile cost or improves generated code.
- The original paragraph ends: **OI-18 is closed.** (See the warning above.)

### Closure Criteria

- [x] Compiler implementation volume.
- [x] Compile time/memory.
- [x] Incrementality.
- [x] Verifier complexity (2026-11-25; see "Verifier complexity (2026-11-25)").
- [x] Target extensibility.
- [x] Generated-code quality across at least two architectures.

<details>
<summary>Historical Record</summary>

#### 2026-09-30 (prototype evidence)

M12 uses a deliberately small staged organization: deterministic local/CFG rewrites, conservative pure direct-call inlining, then optional bounded enumerative search. The fixed search consumes 64 deterministic steps and 6,560 bytes of deterministic search accounting per target and selects against both x86-64 and WebAssembly lowering without adding a universal machine IR or e-graph. This is not representative compile-time/memory, large-program incrementality, optimizer implementation-volume, or broad code-quality evidence. OI-18 remains open.

</details>

## OI-19 — Transformation-proof granularity

**Status:** CLOSED (2026-11-25). Validation memory and throughput are measured (see "Validation memory and throughput (2026-11-25)"); the 2026-10-02 policy stands.

> [!NOTE]
> Superseded claim: the 2026-10-02 closure evidence paragraph ends with "OI-19 is closed." The later status line above (2026-11-15, the audit that added status lines) supersedes it, because that paragraph does not meet every item of the closure criteria. The paragraph is kept as the historical record.

### Summary

What split among trusted rewrite rules, proof objects, solver-backed equivalence, and translation validation yields the best trusted-core/compile-cost balance?

### Fixed Constraints

- Every transformation has an explicit correctness mechanism.
- Failed validation rejects the candidate.

### Evidence and Measurements

#### Closure evidence (2026-10-02)

OI-19 compares:

- the ordinary verifier;
- one compact benchmark-only rule-witness format with an independent checker;
- the existing exact wrapping-polynomial validator;
- an exhaustive finite-domain oracle used only for testing.

The corpus contains six accepted transforms across local wrapping rewrites (including overflow and explicit-effect preservation), constant-CFG simplification, pure single-block inlining, and search-generated arithmetic. Seven deterministic fault injections cover a wrong folded constant, a wrong overflow assumption, wrong CFG edge, wrong inline dependency, dropped arithmetic dependency, dropped explicit effect, and malformed dominance.

| Mechanism | Faults caught | False rejection | Validation time on this host |
| --- | --- | --- | --- |
| Ordinary verifier | **1/7** (dominance); correctly accepts every well-formed but semantically wrong candidate | not stated | approximately **0.97–1.13 ms** (verifier-only) |
| Witness checker (+ verifier) | **7/7** | **0/6** | approximately **2.13–2.88 ms** for the measured conventional rules |
| Finite-domain oracle (testing only) | **6/6** applicable pure faults | **0/5** | **5.56–292.53 ms** |
| Exact polynomial validator (search-specific) | not stated | not stated | **1.757 ms**; needs no proof object |

- Correct witnesses are **107–139 bytes** and bind exact subject, candidate, and dependency identities.
- The benchmark witness codec/checker is **223 lines** versus **276 lines** for the existing local/CFG/inline generator logic, but it covers only the measured subset. Adding it without removing those trusted generators would expand the correctness-critical implementation.

#### Validation memory and throughput (2026-11-25)

`bench_oi19_transform_proofs.py --measure` re-run, MEASURED on WSL 2 on the Ryzen 9 5900HS, CPython 3.12.3, the Python reference (21 samples per case and mechanism; raw elapsed
time and `tracemalloc` peak bytes in `compiler/benchmarks/oi19_transform_proof_timing_20261125.json`):

| Mechanism | Cases | Median validation time | Median peak memory | Throughput |
| --- | ---: | ---: | ---: | ---: |
| Ordinary verifier | 6 | 0.398–0.483 ms | 3,568–4,568 bytes | about 2,250 per second |
| Witness checker (+ verifier) | 6 | 0.766–1.028 ms | 5,858–7,987 bytes | about 1,065 per second |
| Exact polynomial validator | 1 | 0.771 ms | 8,032 bytes | about 1,300 per second |
| Finite-domain oracle (testing only) | 5 | 2.819–121.552 ms | 8,900–88,532 bytes | about 31 per second |

Throughput is validated transforms per second: the number of cases over the sum of their median validation times
(candidate generation is not timed). The policy's mechanisms (verifier, witness, polynomial) stay under 8 KB and
above 1,000 transforms per second; only the testing oracle is costly.

### Decision

The mechanical policy:

1. Ordinary verification is always required for graph/type/effect/dominance validity but is not semantic equivalence evidence.
2. Current conservative local/CFG/inlining rewrites remain trusted-rule-premise + verifier, because the witness prototype does not yet replace a complete rule family. A family moves to untrusted generation + witness only when one independent checker covers the complete family, catches its fault corpus, and is smaller than the trusted rule code it replaces.
3. Bounded search-generated wrapping arithmetic continues to require exact polynomial translation validation + verifier.
4. Future untrusted effect/resource transforms require a checker that covers the observable effect/resource relation or are rejected.
5. No general solver dependency is justified.

Failed checks retain the prior accepted function CID, and proof artifacts never enter canonical program identity. The original paragraph ends: **OI-19 is closed.** (See the warning above.)

### Closure Criteria

- [x] Trusted code size.
- [x] Validation latency.
- [x] Validation memory (2026-11-25, MEASURED).
- [x] Bug detection.
- [x] Optimization throughput (2026-11-25, MEASURED as validated transforms per second).

<details>
<summary>Historical Record</summary>

#### 2026-09-30 (prototype evidence)

M12 uses conservative trusted rewrite preconditions plus the ordinary verifier for low-risk transforms, and a distinct exact polynomial normal-form validator over `Z/(2^N)` plus the verifier for bounded pure wrapping-arithmetic search. In the fixed search, 60 non-equivalent candidates are rejected and 4 equivalent candidates pass per target; failed candidates cannot replace accepted output. The milestone itself also exposed and fixed an SSA-coordinate remapping defect in the low-risk pass pipeline. There is no portable proof object, solver-backed general equivalence, validation latency study, trusted-code-size measurement, or optimization-throughput study. OI-19 remains open.

</details>

## OI-20 — ABI/platform capability and classification representation

**Status:** OPEN (2026-11-25): ADR-422 proposes a canonical ABI/capability representation; this stays open until the owner accepts it and the remaining ABI measurements are made. The original record has no status line; it states "OI-20 remains open; no canonical ABI/capability representation is selected yet".

### Summary

What granularity should platform capabilities use, how should ABI classification be represented, and how much foreign-contract inference is useful?

### Fixed Constraints

- ABI/capability satisfaction is deterministic.
- Inferred foreign contracts are not authoritative until verified.

### Evidence and Measurements

#### Additional prototype evidence (2026-10-02)

OI-20 has one benchmark-only data-driven ABI-classification carrier covering Windows x86-64, AAPCS64 bare metal, and Android AAPCS64, without changing production lowering or canonical identity.

| Carrier | Compact size | Unchanged-backend artifact |
| --- | ---: | --- |
| Windows x86-64 | 65 bytes | add: 5 bytes |
| AAPCS64 bare metal | 67 bytes | add: 52 bytes |
| Android AAPCS64 | 77 bytes | `getpid` Android/Bionic shared-object fixture: 17,424 bytes, one `libc.so` relocation/import |

- Android reuses all 15 measured AAPCS64 classification fields.
- The candidate physical plan matches the existing AArch64 classifier on the mixed scalar/HFA/aggregate corpus and matches every measured Win64 direct-vs-by-reference aggregate decision.
- Unchanged backends emit byte-identical artifacts for these fixtures.
- The candidate classifier/codec is 71/73 benchmark lines versus 109 existing backend classification-helper lines, with zero production lines changed.

Capability granularity:

- A parameterized capability family costs 40 bytes across the three measured Bionic/JNI requirements versus 21 bytes for coarse families, but removes 245 unrelated authorized members (13 POSIX declarations, 4 JNI invocation slots, 228 JNI native-table slots).
- Unsupported JNI invocation slot 8 rejects deterministically.
- The machine query is 41 bytes and a parameterized capability mutation is 5 bytes.

Foreign-contract inference is tooling-only. The suggestion binds the exact verified declaration CID, ABI-carrier CID, and signature digest, remains non-authoritative, and becomes authoritative only after exact rematerialization/verification. A digest mismatch rejects.

### Closure Criteria

- [ ] Several real ABIs/platforms measuring reuse, graph/package size, verifier complexity, mutation cost, and unsupported-boundary diagnostics. Partial: three ABIs are measured at benchmark level; the original does not state this criterion as met.
- [ ] A canonical ABI/capability representation is selected (not selected yet).

## OI-21 — Semantic-database dependency representation and cross-process parallelism

**Status:** CLOSED (2026-10-02; status line added 2026-11-15). The closure evidence below meets every item of "Closure Criteria".

### Summary

What reverse-dependency representation, fingerprints, and distribution thresholds best support incremental compiler services?

### Fixed Constraints

- Under-invalidation is forbidden.
- All reusable facts include complete relevant dependencies.

### Evidence and Measurements

#### Dependency snapshot (`XDI1`)

A benchmark-only versioned derived dependency snapshot (`XDI1`) is keyed by exact semantic root CID, verifier identity, and compiler identity.

- Each object record carries one dependency fingerprint plus exact direct-dependency and reverse-user local ordinals.
- The snapshot is non-semantic, atomic-replace, read-only shareable across processes, and disposable.
- Digest/root/verifier/compiler mismatch rejects. Missing/corrupt snapshots rebuild. Logically inconsistent reverse edges reject even with a recomputed file digest. A full recomputation path proves snapshot equality.
- Incremental update reuses retained immutable-CID records and reads only newly introduced objects. It reproduced the full rebuilt index byte-for-byte after both graph-local body and interface edits on four projects: 128-function shallow fan-out, 128-function deep chain, 128-function mixed modules, and a generated 72-function/6-module multi-block service DAG.
- Exact invalidation matched the complete removed-object set in every case, with no under-invalidation.

| Measurement (297–523-object projects, measured Linux x86-64 host) | Result |
| --- | ---: |
| Snapshot size | 21,878-38,865 bytes (43.9-45.3% of canonical store bytes) |
| Median cold index build | 28.5-104.4 ms |
| Warm load | 2.82-12.77 ms |
| Reverse-frontier query | 0.043-0.085 ms |
| Post-verified-commit index update | 0.78-3.43 ms |

#### Cross-process compilation

Cross-process compilation of four independent verified functions compared 1/2/4 workers, with process startup and payload serialization charged. A 20%-benefit gate was predeclared.

- 16-node tasks remain serial.
- 256 nodes/task is the first measured distribution threshold. With 4 workers, median cold falls from 48.46 to 32.61 ms and median warm from 38.76 to 19.69 ms.
- 2,048- and 4,096-node tasks also benefit.
- Three independent cold launches and three warm batches per cell produced schedule-independent artifact digests.
- An invalid entry produced the same structured diagnostic across worker counts.
- Two workers concurrently read the same immutable index snapshot without mutation.

### Decision

OI-21 is closed with the mechanical bootstrap policy:

1. Authoritative semantics never depend on the index.
2. Use XDI1-style disposable exact snapshots.
3. Update only from a validated prior snapshot plus immutable CID additions/removals, and retain a full recomputation check path.
4. Reject/rebuild stale or corrupt snapshots.
5. On this measured 5-logical-CPU host, keep compile tasks serial below 256 verified graph nodes/task. Distribute only when host-local calibration shows at least 20% benefit for both cold and warm batches.
6. Unknown/unmeasured hosts fall back to serial.

### Closure Criteria

- [x] Large-project cold/warm/incremental workloads measuring index size, update cost, invalidation precision, parallel speedup, and deterministic reproducibility.

<details>
<summary>Historical Record</summary>

#### 2026-09-29 (prototype evidence: artifact provenance)

M6 records exact emission provenance through one target-neutral `ArtifactSemanticRange` carrier for x86-64 raw load images, AArch64 raw load images, and WebAssembly modules.

- A tooling-only `ArtifactProvenanceBinding` commits to semantic root, target/configuration CID, explicit opaque versioned compiler/lowering identities, SHA-256 artifact digest, and retained ranges.
- Identical inputs reproduce the binding identity. A root-only change changes binding identity while preserving identical artifact bytes/digest. Target/lowering changes change identity. Same-generation compiler/lowering mismatches reject mapping/read-set reuse.
- Generation-scoped `A*` handles map function spans and directly emitted node spans in both directions with bounded continuation. Erased stack allocation/lifetime nodes and WebAssembly container bytes without exact semantic attribution are unavailable rather than guessed.
- The common seven-query accounting shape now exposes 9 entities in 2,499 / 2,502 / 2,495 bootstrap response bytes for x86-64 / AArch64 / WebAssembly respectively, because attribution identities are included.

This remains implementation-local evidence: durable persisted artifact dependency indexing, large-project index behavior, and query-latency/index-size measurements are absent, so OI-21 remains open.

#### 2026-09-29 (additional prototype evidence: candidate bindings)

Candidate-only verification stores private `C<n>.<generation>` bindings only in workspace memory, validates current ordinary/proof/artifact read dependencies, exposes no candidate semantic CIDs, and discards candidates explicitly on rollback or automatically on canonical commit. This demonstrates one bounded private-state lifecycle but does not answer durable multi-process candidate storage, crash recovery, or large-project dependency-index design; OI-21 remains open.

#### 2026-09-30 (additional prototype evidence: generations and persistence)

The workspace retains multiple verified generations for deterministic diff/rebase of unchanged identities and can atomically save/load the authoritative canonical store bytes. Reload uses the ordinary store verifier and regenerates local handles; ephemeral candidates, artifact indexes, and generation history are deliberately not serialized. This supplies single-file crash-safe canonical-state evidence, but not durable dependency indexes, multi-process coordination, or large-project measurements; OI-21 remains open.

</details>

## OI-22 — Hash agility and migration

**Status:** CLOSED (2026-10-02; status line added 2026-11-15). The closure evidence below meets every item of "Closure Criteria".

### Summary

How should a future hash suite be introduced and migrated without ambiguous identities or unnecessary graph churn?

### Fixed Constraints

- v0.1 suite 1 remains BLAKE3-256 permanently.
- Algorithm transitions are explicit/versioned.

### Evidence and Measurements

A benchmark-only dual-suite prototype leaves every suite-1 canonical byte/CID unchanged. It uses SHA-256 only as a readily available 256-bit migration-test suite, not as a hash recommendation.

- Persistent identities in dual-suite tooling are `(suite_id,digest)`. Suite is never inferred from digest bytes.
- `XHA2/v1` secondary addressing hashes each immutable suite-1 canonical semantic envelope under suite 2 and maps the typed secondary address back to its exact suite-1 CID.
- `XHF2/v1` is the comparison full-readdress carrier. All experimental object identities and 654 child references use suite 2, while source CIDs are retained only as migration provenance/rollback mapping.

Fixture: a package-rooted generated service with 6 modules, 72 functions, 297 objects, and a 49,881-byte suite-1 store.

| Measurement | `XHA2` (secondary address) | `XHF2` (full readdress) |
| --- | ---: | ---: |
| Carrier size | 19,145 bytes | 48,413 bytes |
| Semantic envelopes/identities rewritten | 0 | all 297 |
| Direct reuse of a populated 297-entry verifier proof cache | 297/297 (lookup returns the unchanged suite-1 object) | 0/297 raw-key reuse; requires an explicit equivalence/migration map |
| Median migration time (11 host samples) | 11.584 ms | 11.619 ms |
| Median lookup cost | 1.162 us/object (suite-1 direct: 0.094 us/object) | 1.242 us/object |

- Both resolve dependencies and reproduce the exact decoded canonical semantics/root mapping.
- On the repository's current Python implementations over the 31,941-byte semantic-input sample, BLAKE3 suite-1 hashing measured 4.824 MiB/s and the SHA-256 test implementation 605.328 MiB/s. This is implementation-specific performance evidence and not an algorithm-selection claim.
- Unknown/wrong suite declarations, stale source fingerprints, file corruption, rehashed inner-record corruption, missing references, and forced simulated same-suite digest collisions reject deterministically.
- Atomic-replace interruption leaves the authoritative suite-1 repository unchanged. Restart reproduces the same migration artifact. Rollback deletes the migration artifact and restores the suite-1-only view.

### Decision

OI-22 is closed with the migration rule:

1. Suite 1 remains permanent and never reinterpreted.
2. Introduce any future suite only under a new explicit suite ID/version.
3. Prefer a validated secondary-address index over immutable suite-1 objects, so ordinary migration causes no Merkle churn or direct derived-cache loss.
4. Define cross-suite equivalence only by equality of decoded canonical semantics, never raw digest equality.
5. Reject unknown or ambiguous suite identities and any same-suite digest collision between unequal semantics.
6. Use full store-wide re-addressing only when retiring suite-1 storage is explicitly required. Then rewrite every persistent child identity under the new suite and rekey/translate derived caches explicitly.

### Closure Criteria

- [x] Security/performance analysis.
- [x] A prototype dual-suite migration demonstrating deterministic identity comparison, dependency resolution, cache behavior, and repository upgrade.

## OI-23 — Package resolver expressiveness and complexity bounds

**Status:** CLOSED (2026-10-02; status line added 2026-11-15). The closure evidence below meets every item of "Closure Criteria".

### Summary

How expressive should compatibility constraints be before resolution cost and mutation complexity become pathological?

### Fixed Constraints

- Resolution is deterministic.
- Exact roots remain authoritative.

### Evidence and Measurements

A benchmark-only `XRV1` catalog keyed by exact package CID adds only three compatibility forms:

1. exact root;
2. exact numeric version `(major,minor,patch)`;
3. conjunctive inclusive-lower/exclusive-upper range `[lo,hi)`.

Canonical package objects and M10 store/build semantics are unchanged.

Resolver behavior:

- Resolution fixes at most one root per logical identity and chooses the highest compatible version in deterministic version/CID order.
- Two roots at the same chosen version reject as `XAX.RESOLVE.AMBIGUOUS`.
- Resolution backtracks deterministically when a higher candidate's transitive constraints fail.
- It rejects on explicit state/requirement-visit/candidate-check budgets rather than depending on discovery order or time.
- Simultaneous incompatible major lines use distinct logical identities. OR, arbitrary predicates, scripts, and implicit `latest` are excluded.

Measurements:

- Realistic linear, diamond, explicit-major-line, and generated-service fixtures resolve with 0 backtracks. The 33-candidate generated service selects 13 exact roots in 335 deterministic work units.
- Adversarial ladders on the measured Linux x86-64 host:

| Ladder | Work units | Median time | Deterministic backtracks |
| --- | ---: | ---: | ---: |
| 33 candidates / depth 8 / version 4 | 212 | 1.215 ms | 3 |
| 257 candidates / depth 32 / version 8 | 4,744 | 10.591 ms | 7 |

- Catalog overhead ranges from 286 B for the 5-candidate dual-major fixture to 18,665 B for the 257-candidate adversarial case.
- Exact-root repair resolves deliberately ambiguous same-version candidates. Unsatisfiable ranges and budget exhaustion produce deterministic compact diagnostics.
- Four mutation/checker tasks cover adding/changing a constraint and repairing unsatisfied/ambiguous resolution. Compact views are 79–226 B and mutation packets 50–71 B with exact target snapshots.

### Decision

OI-23 is closed with the first-resolver contract:

- Exact roots remain authoritative.
- Logical compatibility is exact version or conjunctive bounded half-open interval only.
- Select the highest compatible exact package root under deterministic bounded backtracking.
- Allow one root per logical identity, requiring distinct logical identities for deliberate coexisting major lines.
- Reject equal-version duplicate roots as ambiguous unless an exact root is requested.
- Reject unsatisfied/budget-exhausted resolution deterministically.
- Do not add OR/disjunction, arbitrary predicates, scripts, SAT-style features, or implicit latest until a measured workload requires them.

### Closure Criteria

- [x] Adversarial and realistic dependency graphs measuring worst-case/typical resolver work and transaction/query complexity.

<details>
<summary>Historical Record</summary>

#### 2026-09-30 (prototype evidence)

M10 implements deterministic exact-root selection and the smallest logical constraint: exactly one candidate with the requested logical identity. Zero candidates reject as missing; multiple candidates reject as ambiguous; discovery order does not affect the snapshot root. This proves a deterministic base case but includes no compatibility/version algebra, coexisting-version policy, adversarial graph study, resolver timing, or AI mutation measurement, so OI-23 remains open.

</details>

## OI-24 — Provenance granularity and sandbox portability

**Status:** CLOSED (2026-10-02; status line added 2026-11-15). The closure evidence below meets every item of "Closure Criteria".

### Summary

Should provenance normally capture only snapshot/toolchain closure or an action-level build DAG, and how should semantic capabilities be enforced across hosted/bare-metal build environments?

### Fixed Constraints

- Declared build input/effect boundaries are authoritative.
- Requested isolation failure is a build failure.

### Evidence and Measurements

A benchmark-only derived `XAD1`/`XAS1` action carrier records action kind/implementation identity, exact input digests/CIDs, declared build capabilities, output digests, and dependency action IDs, without entering canonical semantic identity.

On the measured M10 fixture:

| Measurement | Value |
| --- | ---: |
| Closure-only snapshot+provenance metadata | 458 B |
| Optional three-record action set (additional) | 661 B |
| Combined | 1,119 B |
| Compact action query | 96 B |
| Closure root/provenance query | 159 B |

- Repeating the same build hits the existing closure cache.
- Changing one declared external digest changes the closure build key and misses that cache even though emitted bytes are unchanged. The action records precisely invalidate `verify-external` and `emit-provenance` while reusing the unchanged `lower-entry` identity (1/3 action records reused).
- Action records improve step attribution and expose a reusable lowering unit, but not enough on this small build to justify their 144% metadata increase over closure metadata as a mandatory form.

Enforcement experiments:

- A Linux hosted adapter validates XAX semantic capabilities before launch, maps the declared `READ_EXTERNAL` input into a read-only chroot, clears ambient environment, and uses user/mount/network namespaces. On Linux 6.18.44 it allows the declared file while denying writes to that read-only input, `/etc/hostname`, ambient `HOME`, and outbound network.
- Because this bootstrap has no semantic environment-fact carrier, environment is denied rather than implicitly inherited.
- Forced namespace/sandbox unavailability fails as `XAX.SANDBOX.UNAVAILABLE`.
- The existing pure/no-host-API build path remains the portable second enforcement model and reproduced byte-identically for x86-64 and wasm32.

### Decision

OI-24 is closed with closure-level provenance as the default.

- Action-DAG records remain optional derived evidence for explicit audit/debugging or future action caches where measured reuse pays their metadata/index cost.
- Semantic capability validation always precedes hosted execution.
- Host sandbox permissions are a conservative projection of those grants plus explicit environment facts, never additional authority.
- If requested host isolation cannot be enforced, the build fails rather than running unsandboxed.

### Closure Criteria

- [x] Reproducibility, cache utility, metadata size, audit value, and enforcement experiments on multiple host/platform models.

<details>
<summary>Historical Record</summary>

#### 2026-09-30 (prototype evidence)

M10 records closure-level provenance over snapshot, request, target, profile, artifact digest, compiler, lowering, and optional producer identities. Package-local capability declarations plus profile grants reject undeclared/cross-package effects; live network/clock/random observations reject in hermetic-reproducible mode. The implemented build action is pure and exposes no ambient host API. Signature verification remains an explicit caller-supplied algorithm hook. No OS-level sandbox adapter, action-level DAG, multi-platform enforcement experiment, or metadata-cost study exists, so OI-24 remains open.

</details>

## OI-25 — Bootstrap fixed-point comparison level

**Status:** CLOSED (2026-10-02)

### Summary

Can supported deterministic self-builds require full byte identity, or do some targets need a canonical projection for declared non-semantic variability?

### Fixed Constraints

- Projection is versioned/auditable and removes only predeclared non-semantic variability.

### Evidence and Measurements

The committed `m14_seed_runtime.pyz` supplies a real bootstrap-artifact variability case without inventing randomness. `zipapp.create_archive` records source-file DOS modification time/date in each local and central ZIP entry, and the existing generator used `shutil.copy2`, so source metadata can change raw seed bytes while embedded code and reconstruction behavior remain identical.

`compiler/benchmarks/bench_oi25_bootstrap_projection.py` builds B2/B3/B4-style seed generations from the exact committed seed payloads with 2024/2025/2026 metadata.

- All three are 46,255 B, have distinct raw SHA-256 values, execute successfully, and reconstruct the exact committed semantic-image compiler.
- Every B2→B3 and B3→B4 differing byte is attributed to one of the eight declared ZIP DOS timestamp fields.
- The strict target/profile-specific `xax-m14-seed-pyz-projection-v1` rejects unknown entry layouts and corrupt payloads, normalizes only those declared timestamp fields, and maps all three generations to projected digest `e66994a87dea4f6de05d33ba18ed2d1505c51cc441ecc1fa3098464d718fd625`.
- A semantic mutation of the embedded `__main__.py` output write changes the projected digest and runtime output, so the projection does not hide executable content.

The experiment also shows projection is unnecessary for the supported emitter.

| Approach | Result |
| --- | --- |
| Normalizing staged seed mtimes before `zipapp` | byte-for-byte the same archive as the projection (SHA-256 `b60eec6cd64ae480e1e9a8cf7adf3c5d2cf32f526c9f574c96b3d192ff43bf7b`), with a 5-line generator change |
| Strict projection checker | 68 benchmark lines |

On the measured Linux x86-64/Python 3.13.5 host: 31 projection samples had median 1.634 ms; 11 variable-emitter samples had median 6.847 ms and 11 deterministic-emitter samples 6.713 ms. Timing is host-observed and non-semantic.

### Decision

Policy:

- Require full byte identity whenever non-semantic variability is under emitter control; normalize it at emission.
- A versioned target/profile-specific projection is permitted only for a predeclared non-semantic class that cannot be eliminated, and must reject unknown layouts.
- `xax-semantic-image-v1` remains raw-byte identity.
- Legacy timestamp-varied M14 seed archives may be compared through the measured projection for audit/migration only. Newly generated seeds normalize timestamps and require raw byte identity.

### Closure Criteria

- [x] B2–B4 self-build experiments on initial targets with exact artifact-difference attribution.

### References

- `compiler/benchmarks/bench_oi25_bootstrap_projection.py`

<details>
<summary>Historical Record</summary>

#### 2026-09-30 (M14 evidence)

The declared `xax-semantic-image-v1` self-build reaches full byte identity: generations 0, 1, and 2 share root `097da62f7ba9832620f5d202297fc522783ed5b4c9e68f8da6b77515b185164d` and canonical-store BLAKE3-256 `6340c903f5da3e8aaf4d8ae886694a0d858687fc5c5520662a018518693f4788`. Four generation-equivalence vectors also match. This closes OI-25 for the semantic-image closure target by selecting full byte identity when the target is canonical by construction. The general question remains open for future targets that contain explicitly permitted non-semantic variability; any projection must still be predeclared and versioned.

</details>

## OI-26 — Minimum practical bootstrap seed subset

**Status:** CLOSED (2026-10-02)

### Summary

What is the smallest seed semantic/compiler subset that can build the first useful XAX-hosted compiler?

### Fixed Constraints

- The seed is transitional, verifies its accepted subset, emits native output, and does not define language meaning.

### Evidence and Measurements

`compiler/benchmarks/bench_oi26_seed_minimization.py` traces the exact M11/M14 accepted semantic surface and deterministically derives three smaller archives from the frozen 46,255-byte M14 seed snapshot.

The accepted union:

- five object kinds: `TYPE`, `GRAPH_FRAGMENT`, `FUNCTION`, `MODULE`, `PROGRAM_ROOT`;
- six operations: `ADD_WRAP`, `MUL_WRAP`, `CALL_DIRECT`, `META_MATERIALIZE_PROGRAM`, `META_VERIFY_SEMANTICS`, `META_CANONICAL_STORE`;
- `RETURN` and `CONDITIONAL_BRANCH`.

Every accepted store still passes the existing verifier. Excluded BUILD/PACKAGE/TARGET snapshots and `SUB_WRAP` reject explicitly, and corrupt stores publish no output.

| Seed | Size | Compiler-source lines | Note |
| --- | ---: | ---: | --- |
| Frozen M14 baseline | 46,255 B | 4,330 | — |
| Entry-pruned candidate | 42,324 B | not stated | removes unused self-host/evidence machinery |
| Static top-level reachability-pruned (`m14_seed_reachable.pyz`) | 32,017 B | 3,050 | adds no seed-specific evaluator; **selected** |
| Further-reduced candidate | 27,392 B | not stated | requires a new 30-line seed-specific semantic evaluator; rejected as the practical default because the extra 4,625-byte reduction increases trusted special-case logic |

- All three candidates reconstruct two successive M14 generations byte-identically and reproduce all six M11 arithmetic vectors.
- Detailed reachability is in `compiler/bootstrap/oi26_seed_reachability.json`. Reproducible measurements are in `compiler/benchmarks/oi26_seed_minimization_evidence.json` and `oi26_seed_minimization_timing.json`.

### Decision

The selected **minimum practical seed subset is `m14_seed_reachable.pyz`**: retain the existing generic verifier/evaluator/serializer after static reachability pruning, plus the bundled pure-Python BLAKE3 implementation.

- Python remains an explicit external interpreter dependency and is not counted as seed bytes.
- This is the smallest among measured viable candidates, not a mathematical minimum.

### Closure Criteria

- [x] Implement B0/B1 and record supported semantics, seed size/complexity, required external dependencies, and transition cost.

### References

- `compiler/benchmarks/bench_oi26_seed_minimization.py`
- `compiler/bootstrap/oi26_seed_reachability.json`
- `compiler/benchmarks/oi26_seed_minimization_evidence.json`
- `oi26_seed_minimization_timing.json`

<details>
<summary>Historical Record</summary>

#### 2026-09-30 (prototype evidence: M11 and M14)

M11 achieves B0/B1 for one declared arithmetic-folding compiler component whose authoritative implementation is canonical XAX semantic state.

- The committed program store is 820 bytes, the fixed hermetic WebAssembly bootstrap snapshot is 1,566 bytes, and the seed emits a 144-byte import-free artifact.
- Six seed-versus-hosted vectors match, including 32-bit wrapping cases.
- Exact program/snapshot/package/request/target/profile/provenance/tool identities are recorded in `compiler/bootstrap/m11_bootstrap_evidence.json`.

M14 subsequently adds a 46,255-byte committed immutable seed runtime for the semantic-image closure target and removes the external `blake3` package dependency. That seed reconstructs the 2,020-byte authoritative M14 compiler without repository Python sources on the import path, but it still requires a Python interpreter and bundles the trusted evaluator/verifier/serializer implementation. No minimization study has established that this seed is smallest or close to smallest, so OI-26 remains open.

</details>

## OI-27 — Bootstrap trust diversity threshold

**Status:** CLOSED (2026-10-02)

### Summary

What independence between bootstrap seeds provides useful diverse-double-compilation evidence without creating a permanent second implementation obligation?

### Fixed Constraints

- Trust claims identify exact seeds, provenance, targets, policies, roots, and projections.

### Evidence and Measurements

`compiler/bootstrap/oi27_independent_checker.go` is a release-only Go implementation with no external packages and no dependency on the Python compiler modules. It independently implements suite-1 BLAKE3-256, canonical store/index/CID validation, bounded M11/M14 semantic verification, and canonical store re-emission.

- The selected OI-26 seed (`m14_seed_reachable.pyz`, SHA-256 `992e66fd2b99c529a79efa93f42c0da39824489abbdda8131c6c52c3712076e2`) reconstructed B2/B3 byte-identically at authoritative root `097da62f7ba9832620f5d202297fc522783ed5b4c9e68f8da6b77515b185164d`.
- The independent checker accepted that exact root and re-emitted the same 2,020 bytes.
- Controlled faults demonstrated detection of:
  - a structurally valid but wrong pinned root;
  - output corruption;
  - an inner object-CID/hash error with a repaired outer digest;
  - a canonical-but-semantically-invalid arithmetic graph representing a primary verifier omission.

### Decision

The minimum maintained diversity threshold is **one release-only independent verifier + canonical serializer/hash checker**, not a permanent second compiler.

> [!IMPORTANT]
> Exact trust claims MUST name the seed hash, checker source/binary identity, Python and Go toolchain identities, authoritative root, closure target/policy identities, and comparison rule. `xax-semantic-image-v1` uses raw byte identity.

- A full independent META evaluator/target toolchain is deliberately excluded until a threat experiment shows additional value worth its maintenance cost.
- Residual common modes include the normative specification/test vectors, pinned-root authorization, host kernel/hardware, and BLAKE3 specification.

### Closure Criteria

- [x] Release-process experiments comparing feasible diversity sources and threat models.

### References

- `compiler/bootstrap/oi27_independent_checker.go`
- `compiler/benchmarks/oi27_bootstrap_diversity_evidence.json`
- `compiler/bootstrap/oi27_trust_diversity_report.md` (release procedure)

<details>
<summary>Historical Record</summary>

#### 2026-09-30 (M14 evidence)

The committed immutable seed establishes the declared B6 ordinary-release boundary for `xax-semantic-image-v1`, but it is not an independent implementation and therefore provides no diverse-double-compilation assurance. OI-27 remains open.

</details>

## OI-28 — Diagnostic payload and repair-neighborhood minimum

**Status:** MOVED (2026-11-28) to [MrxSiN/XAX-MCP#6](https://github.com/MrxSiN/XAX-MCP/issues/6): the measurement and its client side are XAX-MCP's (it owns transport, tool schemas and the client surface). A protocol change its results call for comes back here as an ADR. The earlier status line follows.

**Status:** OPEN (2026-11-25): a measurement design for the repeated repair trials is proposed below; nothing is run. The original record has no status line; it states "OI-28 remains open pending repeated controlled repair trials".

### Summary

What minimum stable dependency/repair payload is useful, and is strict minimality worth its verifier cost?

### Fixed Constraints

- Rule identity and core diagnostic fields are stable/deterministic under fixed inputs.

### Current Findings (2026-10-02)

`compiler/benchmarks/bench_oi28_diagnostic_payload.py` fixes a nine-case repair corpus covering stale operand relation, containment drift, delete-used node, proof dependency, insertion position, edge argument, move dominance, type mismatch, and resource/effect failure. It compares only two non-source payload policies:

- `minimal` carries the stable core diagnostic plus directly implicated repair handles.
- `near` adds deterministic one-hop producer/user/type/effect facts under an 8-entity/1024-byte page cap that preserves the core and makes positive pagination progress.

| Measurement across the corpus | `minimal` | `near` |
| --- | ---: | ---: |
| Deterministic payload total | 2,314 bytes | 6,936 bytes |
| Construction median-by-cell (measured host) | 1.949 microseconds | 398.216 microseconds |

- Every case has an exact known repair target root. Payload staleness is generation-bound. The resource case exercises pagination. `oi28_repair_tasks.json` holds the repair tasks.
- Repair turns and repair success remain unmeasured, and byte savings alone cannot select strict minimality.

### Measurement design (proposed, 2026-11-25)

Not run. For the two unmeasured items (repair success, repair turns) and the repeated trials:

- Corpus: the nine `oi28_repair_tasks.json` cases plus real verifier failures: the `fixtures/declared_rejections`
  stores (36) and a sample of 30 `test_xax_selfhost_verify_exact` rejections, each with a known repaired root.
- Arms: `minimal` and `near` payloads, the same native workspace, model, instructions and turn limit (4).
- Per attempt: success (the committed root equals a verified repair), repair turns, tokens, payload bytes, the
  payload's construction time.
- Trials: 3 per case and arm, order randomized; paired per case.
- Decision rule: `near` is adopted only if it raises repair success or lowers median turns on the real failures by
  more than the trial spread; otherwise `minimal` stays the default and strict minimality is not pursued further.
- Needs the owner: ADR-207 defers AI-efficiency work, so nothing here runs until the owner approves the design and
  the model budget. No agent runs these trials on its own initiative.

### Closure Criteria

- [ ] Real verifier failure graphs measuring diagnostic bytes, computation cost, repair success, and repair turns for minimal versus deterministic near-minimal neighborhoods. Partial: diagnostic bytes and computation cost are measured; repair success and repair turns are not.
- [ ] Repeated controlled repair trials (what the original names as pending).

### References

- `compiler/benchmarks/bench_oi28_diagnostic_payload.py`
- `oi28_repair_tasks.json`

<details>
<summary>Historical Record</summary>

Each entry below ends with the original statement that OI-28 remains open.

#### 2026-09-29 (`ReplaceUse` slice)

The M6 `ReplaceUse` slice adds an exact old-operand relation precondition. A mismatch deterministically reports `XAX.WORKSPACE.RELATION_CONFLICT` / `WORKSPACE-OPERAND-PRECONDITION` with the target local node handle and exact old/actual graph-local value-reference tuples. An incompatible replacement is rejected separately by the ordinary graph verifier before publication. This demonstrates stable relation-level diagnostics but does not measure repair success, payload minimality, or repair turns, so OI-28 remains open.

#### 2026-09-29 (`DeleteNode` slice)

The typed `DeleteNode` slice deterministically distinguishes `XAX.WORKSPACE.DELETE_USE_CONFLICT` / `WORKSPACE-DELETE-NODE-UNUSED` from `XAX.WORKSPACE.CONTAINMENT_CONFLICT` / `WORKSPACE-NODE-CONTAINMENT`, leaves the root unchanged on either failure, and uses the normal verifier after successful local renumbering. This expands conflict-class evidence but still does not measure repair success, diagnostic minimality, or repair turns; OI-28 remains open.

#### 2026-09-29 (proof read dependencies)

Proof read dependencies reject separately as `XAX.WORKSPACE.PROOF_CONFLICT` / `WORKSPACE-PROOF-DEPENDENCY` when the bound semantic subject, root freshness rule, or verifier identity no longer holds. This closes the implementation-local distinction between proof conflict and generic read conflict, but still provides no repair-success, payload-minimality, token, or repair-turn measurement; OI-28 remains open.

#### 2026-09-29 (typed insertion slice)

The first typed insertion slice rejects anchor/block/index drift as `XAX.WORKSPACE.CONTAINMENT_CONFLICT` / `WORKSPACE-INSERT-POSITION`, preserves the root on failure, resolves integer-scoped transaction-local inserted results only inside candidate construction, and delegates invalid type/dominance to the ordinary graph verifier. This adds insertion-position diagnostic evidence but still does not measure repair success, payload minimality, or repair turns; OI-28 remains open.

#### 2026-09-29 (typed control-edge argument slice)

The first typed control-edge argument slice distinguishes:

- edge-containment drift (`XAX.WORKSPACE.CONTAINMENT_CONFLICT` / `WORKSPACE-TERMINATOR-EDGE`);
- argument-position drift (`XAX.WORKSPACE.RELATION_CONFLICT` / `WORKSPACE-EDGE-ARGUMENT-INDEX`);
- wrong-old-value drift (`XAX.WORKSPACE.RELATION_CONFLICT` / `WORKSPACE-EDGE-ARGUMENT-PRECONDITION`).

Disconnect-only candidates that violate target block parameters are rejected by the ordinary verifier, and same-transaction reconnect can consume a transaction-local inserted result. This expands machine-repair conflict evidence but still does not measure repair success, minimality, or repair turns; OI-28 remains open.

#### 2026-09-29 (`MovePureNode` slice)

The first typed `MovePureNode` slice distinguishes stale source containment (`XAX.WORKSPACE.CONTAINMENT_CONFLICT` / `WORKSPACE-MOVE-SOURCE`), stale destination-anchor containment (`WORKSPACE-MOVE-DESTINATION`), and self-anchor relation conflict (`XAX.WORKSPACE.RELATION_CONFLICT` / `WORKSPACE-MOVE-SELF-ANCHOR`). A dependency-incompatible reorder is rejected by the ordinary `GRAPH-SSA-DOMINANCE` verifier with unchanged root. This expands deterministic containment/repair evidence but does not measure repair success, diagnostic minimality, or repair turns; OI-28 remains open.

#### 2026-09-30 (resource/effect verification)

General resource/effect verification distinguishes duplicate/drop, domain fork, invalid transition, illegal discard/release, non-partitionable split, and non-sibling join with stable resource/effect diagnostic families and exact expected/actual facts. These tests expand semantic repair evidence but still do not measure payload minimality, repair success, or turns; OI-28 remains open.

</details>

## OI-29 — Atomic litmus conformance corpus size

**Status:** CLOSED (2026-10-02; the original marks the resolution evidence "CLOSED")

### Summary

What portable/target-aware litmus corpus is sufficient to detect incorrect atomic-order implementations without excessive conformance cost?

### Fixed Constraints

- Exact atomic semantics are fixed.
- Unsupported tests are reported, not silently skipped.

### Evidence and Measurements

`compiler/benchmarks/bench_oi29_atomic_litmus.py` defines versioned corpus `xax-atomic-litmus-v1`.

- The full 11-case fault-oriented corpus covers relaxed/acquire/release/acq_rel/seq_cst, load/store/RMW/CAS success+failure/fence, release sequences, SC order, race rejection, and x86-64/AArch64/WebAssembly capability negatives.
- Greedy coverage reduction retains 9 cases while preserving every required semantic category and all seven injected faults: order downgrade, omitted fence, swapped CAS failure order, broken release sequence, ignored SC total order, narrowed scope, and acceptance of unsupported width/alignment.
- Every injected fault is detected. Unsupported target cases are explicit results with reasons.
- The experiment found and fixed one M8 validator bug: failed compare-exchange now derives acquire/seq-cst behavior from `failure_order`, not `success_order`.
- x86-64 and AArch64 seq-cst load lowerings are checked against exact emitted-node bytes/fence counts. AArch64 RMW and WebAssembly atomics remain explicitly unsupported.

### Decision

- The corpus is sufficient only for this declared fault model.
- Target packages MUST add vectors for target-only scope/family/legalization claims and every unsupported capability boundary they expose.
- Extending the fault model precedes extending the minimum corpus.
- Physical concurrent execution is supplementary, not a substitute for deterministic abstract/package conformance.

### Closure Criteria

- [x] Cross-implementation/target fault-injection studies showing detection coverage and execution cost.

<details>
<summary>Historical Record</summary>

#### 2026-09-30 (prototype evidence)

M8 includes an implementation-local abstract event validator for modification order, release sequences, seq-cst order, compare-exchange outcomes, happens-before, and data-race rejection, plus direct x86-64 execution tests. No external corpus, cross-implementation study, target diversity, fault injection, or execution-cost measurement exists, so OI-29 remains open.

</details>

## OI-30 — Deterministic-build manifest boundary — CLOSED

**Status:** CLOSED (decision recorded 2026-10-02)

### Decision

Same-implementation reproducibility identity is the existing build key over `(snapshot_root, request_root, compiler_identity, lowering_identity)`.

- The request transitively binds package/build-entry semantic program, target, profile, feature/configuration values, and requested artifacts.
- The snapshot binds resolver/trust/package closure plus every declared external input digest.
- Benign ambient cwd/path, environment ordering/variables, locale/timezone/source-date environment, and process scheduling/worker count are outside the identity and measured byte/key-stable, because reproducible builds cannot observe them.
- Output-affecting host SDK/tool/signing material must instead be declared by digest in the snapshot external closure.
- Signing material was the one missing current dependency. Hermetic reproducible SIGN effects now require the BLAKE3 digest of their ephemeral transport in the snapshot external closure. Private bytes remain absent from semantic/provenance objects.
- The signing algorithm is currently fixed by `ANDROID_SIGNED_APK_LOWERING_IDENTITY_V1`.
- Unknown/undeclared clock/random/network observations reject.
- No whole-host-environment digest is added.

### Evidence and Measurements

`bench_oi30_build_manifest.py` perturbs scheduling, cwd/environment/locale/timezone/source-date, canonical input ordering, compiler/lowering identities, target/profile/configuration, build-program semantics, external SDK digest, and Android signing material.

- Irrelevant ambient changes preserve artifact bytes and build key.
- Declared policy/toolchain/input changes alter the transitive build identity, while semantic/output changes also alter bytes.
- The signed Android fixture demonstrates that two explicit signing transports under the same certificate identity produce different bytes and, after the fix, different snapshot/build keys.
- Focused tests cover missing/extra/mismatched external closure and nondeterministic effect rejection.

### References

- `bench_oi30_build_manifest.py`

## OI-31 — Run the tiny C-vs-XAX experiment in Codex Desktop

**Status:** CLOSED (2026-10-06, ADR-174). It was removed from this register by commit `7af8108` (2026-10-30) and restored on 2026-11-24 from the version before that commit; its text below is unchanged.

### Summary

Resolution is one manual pass through all ten task/arm workspaces using the same Codex Desktop model and reasoning setting. Record every turn, failure, retry, and available token count in the flat results CSV. The complete procedure is `compiler/benchmarks/ai_native/README.md`; no API, tokenizer, transport automation, or statistical gate is required.

### References

- `ADR-174`, `ADR-175` were deleted from `XAX_DECISIONS.md` by `7af8108` (2026-10-30); their text is in git history at `7af8108^`.
- The benchmark evidence it cites under `compiler/benchmarks/ai_native/` was removed from the tree by `227a976` (2026-10-30) and is in git history.

<details>
<summary>Historical Record</summary>

**Status:** OPEN — historical Codex Desktop rows exist, but they do not establish the fixed model/reasoning setting or the required balanced arm order.

**Evidence audit (2026-10-02).** The repository already contains ten primary rows in `compiler/benchmarks/ai_native/results.csv` and ten confirmation rows in `results-run-2.csv`, each labeled with a Codex Desktop session ID. All ten stored primary workspaces still pass their official checkers. The primary rows are C 5/5, 1,363,522 total tokens, median 261,725, 6 turns versus XAX 5/5, 1,698,890 total tokens, median 327,918, 7 turns; the confirmation rows are C 5/5, 1,320,698 tokens, median 262,319, 5 turns versus XAX 5/5, 1,632,943 tokens, median 333,673, 5 turns. Thus the historical measurements are negative for XAX on token usage, but they are not qualifying OI-31 closure evidence: the CSV schema does not record model/reasoning settings, the referenced Desktop session logs are absent here, and recorded row/session order is C then XAX for every pair rather than a balanced/alternating arm order. This environment also exposes no Codex Desktop/session store with which to perform or authenticate a fresh qualifying rerun. `OI31_RESULT_NOTE.md` records the raw-file hashes and checker audit. Do not replace these historical rows or infer the missing settings.

**Post-upgrade smoke check (2026-10-02).** This was the lowest-token run possible: one pair (`task-02`, operation change) with fresh Claude Code `haiku` subagents in parallel. Both arms passed the official checker. C used 35,151 tokens and 3 tool calls; XAX used 36,492 tokens and 8 tool calls, i.e. XAX cost 1.04× C (`results-claude-haiku-u.csv`). One pair under a different product and model is not OI-31 evidence. Offline, with `tiktoken` installed, the committed OI-01 transport counts reproduce exactly (unified/pipe 237/237; typed/line 262/257).

**Remaining to close.** Run one fresh ten-cell Codex Desktop pass under one explicitly recorded fixed model/reasoning setting and balanced/alternating arm order, preserving every failure/retry and importing exact session usage. A negative XAX result still closes the experiment.

**Status: CLOSED (2026-10-06, ADR-174).** The status above is the historical record. A fresh ten-cell run used fixed `gpt-5.6-luna` low reasoning, one session per cell, and balanced alternating order. All cells passed in one turn with no repair. C-like text used 325,282 total tokens; XAX used 264,535 (0.813×, 18.675% fewer). Evidence is `compiler/benchmarks/ai_native/jvm-r5-evidence.json` and `jvm-r5-results.csv`. The run used the Codex CLI bundled with the desktop installation rather than manual UI chats; exact session usage and session IDs are retained, which satisfies the issue's fixed-model, fresh-session, balanced-order, failure-preservation, and exact-accounting intent. Broader §6.2 task classes and repeated trials are outside this closure.

**Optimized follow-up (2026-10-06, ADR-175).** Under one controlled client profile for both arms, the task-local C workflow used 197,252 tokens and XAX-DIRECT used 98,432 across the same five edits (0.4990×; 50.098% fewer), with 10/10 passes and no repair. Evidence is `jvm-r5-optimized-evidence.json` and `jvm-r5-optimized-results.csv`. This supersedes the current bounded efficiency figure without changing the issue's closed status or completing the broader R5 corpus.

</details>

## OI-32 — Foreign metadata importer scope and representation

**Status:** CLOSED (2026-10-05, ADR-166). The earlier OPEN status is kept in the Historical Record below.

**Related ADRs:** ADR-127, ADR-166

**Related Issues:** [OI-30](#oi-30--deterministic-build-manifest-boundary--closed)

### Summary

Which external interface sources should deterministic importers read first (C headers, curated API descriptions, Win32 metadata, JVM/DEX classfiles, .NET metadata, Web IDL, syscall tables), and what is the smallest typed-declaration package format that keeps ownership, nullability, callbacks, threading, and error conventions verifier-visible?

### Fixed Constraints

- Importer output is canonical XAX semantic state (foreign declarations, types, effects, resources), never wrapper source.
- Unknown ownership/aliasing/lifetime facts import as explicit conservative contracts, not optimistic ones.
- Importers are deterministic over a declared input digest (OI-30 rules).

### Decision

- Read class files and C headers first.
- The package format is the canonical foreign declarations themselves.
- Unknown facts import conservatively:
  - every member is ordered by an effect token;
  - references are nullable;
  - callbacks are opt-in entry types, which must be pure, so no thread crosses effects;
  - Java exceptions and C errors keep their existing rules.
- Purity and effects are curated facts the caller states explicitly.

### Evidence and Measurements

Two unrelated ecosystems produce packages that executed programs consume: the C header importer (ADR-127) and the JVM class-file importer (`xax_jvm_import`), whose program runs on HotSpot. MEASURED in `oi32_import_evidence.json` and `c_import_evidence.json`:

- `java.base` imports 14,973 of 15,806 public and protected members in 1.79 s, as 3.7 MB of declarations.
- Declaration error rate against hand-built declarations is 0/30 (JVM) and 0/5 (C).

> [!NOTE]
> Not covered by this closure: Win32, .NET metadata, and Web IDL.

### Closure Criteria

- [x] One importer over two unrelated ecosystems (e.g. the existing Android classfile importer plus a Win32/C header source) producing packages consumed by executed programs, with measured package size, import latency, and declaration error rate. Closed with the C header importer and the JVM class-file importer as the two ecosystems (see Evidence and Measurements).

### References

- `oi32_import_evidence.json`
- `c_import_evidence.json`
- `xax_c_import`, `xax_jvm_import`

<details>
<summary>Historical Record</summary>

#### Earlier status: OPEN (partially addressed, ADR-127)

Hand-built bounded packages exist (`xax_platform.posix_android_api`, `xax_platform.win32_kernel32_api`); the Android SDK classfile importer is structural only. The C header importer (`xax_c_import`) is the second ecosystem: it reproduces hand-built declarations byte for byte, an imported stdio program executes, and coverage, latency, and package size are measured (`c_import_evidence.json`). Still missing for closure: an executed program over the classfile importer's output and a declaration error rate measured against curated metadata.

The original CLOSED status states that this record is the historical record and the CLOSED status supersedes it.

</details>

## OI-33 — Hosted process lifecycle, unwind, and TLS contracts

**Status:** OPEN

**Related ADRs:** ADR-076, ADR-086, ADR-094

### Summary

How are per-OS process entry/exit, thread-local storage, unwind tables (SEH/`.pdata`, DWARF CFI), and foreign-exception crossing represented so that hosted containers emit only what explicit contracts require?

### Fixed Constraints

- No container-owned startup/exit code (ADR-076).
- Unwind data is emitted only when a contract requires it (foreign unwinding through XAX frames, platform debuggers/profilers) and never implies exception semantics inside XAX.

### Current Findings

- Explicit `ExitProcess` (PE) and explicit `exit_group` (Linux ELF, ADR-086) are implemented and executed.
- Linux enters `e_entry` aligned with no return address. The entry function is lowered for that and traps if it returns.
- Linux argv/env/auxv are available through the inline `linux-x86_64-startup-v1` ABI (ADR-094, executed).
- Still missing on Linux: TLS and unwind/debug data.

### Closure Criteria

Executed PE and ELF programs that:

- [ ] cross a foreign exception boundary under an explicit adapter;
- [ ] use TLS;
- [ ] produce symbolized stack traces;

with measured size cost of the emitted metadata versus none.

## OI-34 — First production GPU target

**Status:** OPEN

**Related ADRs:** ADR-124

**Related Issues:** [OI-13](#oi-13--gpuaccelerator-synchronization-scope-normalization)

### Summary

Which real accelerator representation (SPIR-V/Vulkan compute, PTX/CUDA-compatible, Metal, DXIL) should be the first production target package, given available hardware and the M13 synthetic scope model?

### Fixed Constraints

- No XAX device runtime.
- Launch/transfer/synchronization are explicit effects/resources.
- Vendor scope lattices normalize through OI-13 without kernel changes.

### Current Findings

- SPIR-V for Vulkan is the selected first representation (ADR-124). `spirv-vulkan-compute-v1` kernels execute on Mesa llvmpipe and match the reference executor (GPU row R1).
- The llvmpipe comparison (6.9× glslang for Collatz) is software-device evidence only.

#### Check (2026-11-15): still OPEN

`compiler/benchmarks/vulkan_gpu_evidence.json` EXECUTED a kernel on physical GPUs (RTX 3060 Laptop GPU, AMD Radeon iGPU) and compared it with an independent CPU computation, which meets the first two criteria. It records no throughput and no vendor-toolchain baseline on that hardware, so the third criterion is not met.

> [!WARNING]
> Evidence limitation: there is no throughput measurement and no vendor-toolchain baseline on physical hardware yet.

### Closure Criteria

- [x] One kernel executed on physical hardware through the selected representation (EXECUTED, `vulkan_gpu_evidence.json`).
- [x] Validated against a CPU oracle.
- [ ] Measured throughput versus a vendor-toolchain baseline. Closes with: the same kernel timed on the RTX 3060 against a glslang (or vendor) build of it, with raw samples.

### References

- `compiler/benchmarks/vulkan_gpu_evidence.json`

<details>
<summary>Historical Record</summary>

#### Earlier status: OPEN (partially addressed, ADR-124)

SPIR-V for Vulkan is the selected first representation: `spirv-vulkan-compute-v1` kernels execute on Mesa llvmpipe and match the reference executor (GPU row R1). Still missing for closure: execution on a physical GPU and a measured throughput comparison against a vendor or glslang baseline there (the llvmpipe comparison, 6.9× glslang for Collatz, is software-device evidence only).

The 2026-11-15 check above supersedes the "execution on a physical GPU" part of this entry.

</details>

## OI-35 — Managed-platform emission strategy (JVM, CLR)

**Status:** CLOSED for the JVM (2026-10-05, ADR-165). CLR is not covered: it has neither arm because there is no CLI/IL container.

**Related ADRs:** ADR-112, ADR-156, ADR-157, ADR-158, ADR-161, ADR-162, ADR-163, ADR-164, ADR-165, ADR-167

### Summary

For JVM and .NET, should XAX emit bytecode/IL directly (as for DEX), emit native code plus a generated managed bridge, or choose per workload?

### Fixed Constraints

- Managed runtimes are targets, never kernel semantics.
- Any GC/object interaction is explicit platform contract.
- Generated bridges follow UR-001.

### Decision

Choose per workload, with direct emission as the default.

### Evidence and Measurements

The native-code-plus-generated-bridge arm (`xax_jvm_bridge`) runs `jsonmin` on HotSpot as an x86-64 JNI library. Compared with direct emission:

| Measurement | Bridge arm versus direct emission |
| --- | ---: |
| Start-up and process time | 0.68× |
| Peak RSS | 0.64× |
| Artifact bytes | 2.86× |
| Generated adapters | 0.81× (372 vs 462 bytes) |

- The bridge is faster and smaller in memory than direct emission, but larger to ship.
- It runs on one host architecture only, and has no Java objects, callbacks, or mapped traps.
- Evidence: `jvm_strategies_evidence.json`, `XAX_BENCHMARKS.md` §15.19.
- `multianewarray` is now done (ADR-164). `putstatic` remained, untestable against `java.base`, and is done too (ADR-167, against a class on the class path).

> [!NOTE]
> Not covered: CLR, which has neither arm because there is no CLI/IL container.

### Closure Criteria

- [x] One executed application per strategy on one managed platform (the JVM) with measured startup, steady-state time, memory, artifact size, and generated-adapter size.
- [ ] The same for CLR (not covered; no CLI/IL container).

### References

- `jvm_strategies_evidence.json`
- `XAX_BENCHMARKS.md` §15.0a, §15.17, §15.18, §15.19

<details>
<summary>Historical Record</summary>

#### Earlier status: OPEN (partially addressed, ADR-112, ADR-156, ADR-157, ADR-158)

Direct emission is EXECUTED on two managed platforms. DEX runs on Android (minimal and stateful Activities). On the JVM, direct emission is now competitive under the JVM runtime rule (ADR-157, `XAX_BENCHMARKS.md` §15.0a/§15.17).

- `jsonmin` over linear memory is the fastest of XAX, `javac`, and `kotlinc` builds, with the lowest peak RSS and a class 0.99× kotlinc's and 1.5× javac's (ADR-158, §15.18).
- The Collatz kernel runs at 0.91× `javac` with a 0.95× class.
- The closing criterion was still unmet: there is no native-code-plus-generated-bridge arm on the JVM to compare against, and no CLI/IL container.
- Direct-emission gaps on the JVM: `multianewarray` and `putstatic` (construction, arrays, object-taking callbacks, instance fields, and `instanceof`: ADR-161/162/163).

The original CLOSED status states that this entry is the historical record and the CLOSED status supersedes it.

</details>

## OI-36 — Standard semantic library granularity

**Status:** CLOSED (2026-10-03, ADR-130)

**Related ADRs:** ADR-130

### Summary

What package granularity and versioning for the standard semantic libraries (§21.10) minimizes linked footprint and the size of a change while keeping cross-package specialization possible?

### Fixed Constraints

- No mandatory runtime.
- Unused packages contribute zero bytes.
- All runtime behavior is explicit.

### Decision

- The package is a canonical `PACKAGE` object.
- The linking unit is the function. An application references exports by CID, and canonical stores hold only the reachable closure, so unused exports and packages contribute zero bytes.
- Specialization is static instantiation: each extent or capacity is its own package with its own CIDs.

### Evidence and Measurements

`uniqcount` uses the `xax.text` and `xax.collections.hashset_u64` families and is EXECUTED on Linux x86-64 natively and on Linux AArch64 under qemu-aarch64, matching the reference.

MEASURED (`oi36_stdlib_evidence.json`):

| Measurement | Value |
| --- | ---: |
| Code per used export (x86-64) | 130 to 326 bytes |
| Store bytes per instance | 2,112 to 4,077 |
| Compile cost: build | 11 ms |
| Compile cost: verify | 1.6 ms |
| Compile cost: lower | 60 ms |

> [!NOTE]
> Not covered: versioning policy beyond the identity, and in-graph type parameters.

### Closure Criteria

- [x] At least two library families (slices/text and allocators/collections) used by an executed application, with measured code/data contribution per used feature, and compile cost.

### References

- `oi36_stdlib_evidence.json`

## OI-37 — Pointer values stored in memory

**Status:** CLOSED (2026-10-02, ADR-096)

**Related ADRs:** ADR-081, ADR-082, ADR-090, ADR-092, ADR-093, ADR-096

**Related Issues:** [OI-38](#oi-38--x86-64-register-allocation-convergence-and-remaining-code-quality-gap), [OI-41](#oi-41--check-free-pointer-reloads-typed-mixed-storage)

### Summary

How should pointer-typed values be stored to and loaded from memory (provenance, extent, permission, alias class, target pointer width) so that iovecs, linked structures, vtables, and object graphs are expressible without raw waivers?

### Fixed Constraints

- Provenance is never manufactured: a loaded pointer carries at most the facts the verifier can re-establish. Unknown provenance stays explicit (checked/raw policy).
- Pointer width/layout comes from the target ABI, not the kernel.
- No hidden runtime metadata.

### Evidence and Measurements

Closure evidence, criterion by criterion:

- *WASI `fd_write` iovecs:* address-valued interface structs via `pointer_address` (ADR-081), executed under `node:wasi`.
- *A linked list with verified traversal on two pointer widths:* x86-64 Linux, 64-bit, heap views (`chains` with `pointer_rebase`, 2^20 nodes, ADR-092); wasm32, 32-bit (`test_xax_wasm_rebase.py`, ADR-093). Deviation stated: the wasm32 list lives in stack storage, because the wasm32 profile has no heap allocator; the representation and the checks are identical.
- *Negative vectors:* forged, misaligned, below-view, and wrapped addresses trap on both targets. Expired provenance (rebase after unmap or `stack_end`) rejects with `MEMORY-LIFETIME-LIVE` on both targets, and authority, extent, alignment, width, and initialization violations reject on x86-64.
- *Verifier cost* (`oi37_closure_evidence.json`): `verify_store` costs 47.9 µs per additional rebase+load against 46.8 µs per checked load (straight-line, K = 1–256). Pointer-linked `chains` verifies in 2.7 ms, index-linked in 2.6 ms.

> [!NOTE]
> Check-free reloads, which remove the per-link check (1.5× in C on `chains`), are not part of the closure criteria and move to OI-41.

### Closure Criteria

- [x] One representation that admits WASI `fd_write` iovecs and a heap linked list with verified traversal on two targets of different pointer widths.
- [x] Negative vectors for forged/expired provenance.
- [x] Measured verifier cost.

### References

- `oi37_closure_evidence.json`
- `test_xax_wasm_rebase.py`

<details>
<summary>Historical Record</summary>

#### History: OPEN (partially addressed)

ADR-081 adds one-way provenance exposure (`pointer_address`), which unblocks address-valued interface structs (WASI `fd_write` iovecs, executed). ADR-082 admits provenance-free pointers (function addresses, external pointers) as memory elements, unblocking function-pointer/dispatch tables (EXECUTED on Windows PE). Still open: storing pointers *with* local provenance and reloading them as dereferenceable pointers (pointer-linked lists/trees over XAX storage), which needs typed mixed storage and lifetime coupling between the container and the referenced storage; arena + index is the current verified alternative. Memory elements remain whole-byte bits/float scalars (`MEMORY-BYTE-ADDRESSABLE-VALUE`).

#### Progress (2026-10-02, ADR-092)

`pointer_rebase` (op 73) reloads an exposed address as a pointer inside a live view, with one range+alignment check, so field reads need no further checks. Pointer-linked `chains` measures 1.64× `gcc -O2` and 1.07× C with the same check; index links measure 2.00×. wasm32 (32-bit pointers) executes the same representation with trap vectors (ADR-093). Remaining for closure: check-free reloads (typed storage), with verifier cost.

#### Measured justification (2026-10-02, ADR-090)

On a 2^20-node chained hash table (`oi37_chains_evidence.json`), arena + index links cost 1.44–1.47× versus pointer links in C, and the bounds checks equivalent to XAX's checked access cost a further 1.34–1.41×. The ADR-082 falsification condition is met for speed. A design that closes this must carry node extent with the provenance, so the per-access check disappears along with the index scaling. Sequenced after OI-38, whose measured share (1.73–1.80×) is larger.

</details>

## OI-38 — x86-64 register allocation: convergence and remaining code-quality gap

**Status:** OPEN (partially addressed; ADR-131 bit-test selection; ADR-148 brings all three Linux workloads within 1.05× of the fastest of gcc, clang, and rustc)

**Related ADRs:** ADR-083, ADR-089, ADR-090, ADR-091, ADR-095, ADR-131, ADR-147, ADR-148, ADR-170

### Summary

Which single allocator design serves both profiles? The candidates are global allocation across blocks (loop-invariant pointers currently reload from home slots every iteration), edge-copy hints, LICM, and unrolling. The design must stay deterministic and differentially validatable against the reference executor.

### Current Findings

Two register-resident allocators exist: ADR-083 extends the legacy allocator for the PE profile, and ADR-089 is a separate module for the Linux profiles.

- On Linux `filestat` the frame path measured 5.9× `gcc -O2`. The Linux allocator measures 0.95–1.14× `gcc -O2` but 1.41–1.82× `clang -O2`, the fastest baseline (`u1_linux_filestat_evidence.json`, seven runs).
- On the pointer-chasing `chains` workload (ADR-090), XAX code generation is 1.73–1.80× slower than equivalent checked-index C. The walk loop spans three blocks, so per-block allocation round-trips loop state through edges and home slots.

#### Latest progress (ADR-147/148, 2026-10-03)

Range-proven check elimination, a lowering view (leaf inlining, layout, folding), loop pass-through slots, hoisted wide constants, and call-surviving callee-saved registers. Against the fastest of gcc, clang, and rustc (interleaved harness):

| Workload | Result |
| --- | --- |
| `filestat` | 1.017× |
| `chains` (struct-of-arrays arm) | the fastest |
| `jsonmin` | 1.029× |

The ADR-147 primary target is met on all three. The PE fixture reran on Windows in ADR-170.

Remaining:

- floats and aggregates on this path;
- a global (cross-block) allocator to remove the remaining shuffles and home reloads;
- translation validation of the lowering view.

### Closure Criteria

- [ ] One allocator used by PE and Linux profiles.
- [ ] The U1 Linux workload and the PE fixture both re-measured (no regression).
- [ ] The differential corpus green on both.
- [ ] The gap to the fastest baseline reported.

<details>
<summary>Historical Record</summary>

#### Progress (ADR-091, 2026-10-02)

The Linux allocator pins cross-block values used in loops to callee-saved registers, falls through on branches, and moves trap paths out of line. `chains` went from 1.80× to 1.06× the equivalent checked-index C, and from 3.49× to 1.91× `gcc -O2`. `filestat` measures 0.94× `gcc -O2` and 1.47× `clang -O2`. Remaining: convergence with the PE allocator, range-based redundant-check elimination, and LICM.

#### Progress (ADR-095)

PE now uses the Linux allocator first, with Win64 calls, stack storage, function addresses, and indirect calls. All six PE fixture functions take it (700 vs 1,269 code bytes), executed under Wine. This historical step's Windows-host rerun is complete in ADR-170.

</details>

## OI-39 — Shift and sign-extension selection versus kernel operations

**Status:** OPEN

**Related ADRs:** ADR-084

### Summary

ADR-084 rejected shift and sign-extension kernel operations as exact compositions. The Linux allocator already selects `shl`/`shr`/`and` for constant powers of two.

### Decision

Shift and sign-extension kernel operations remain rejected as exact compositions (ADR-084).

#### Falsification condition

Admit `shl`/`lshr`/`ashr`/`int.sign_extend` under §21.5 if lowering cannot select them reliably on another target.

## OI-40 — Breadth of the SysV C ABI on Linux

**Status:** OPEN (partially addressed, ADR-102)

**Related ADRs:** ADR-102, ADR-115

**Related Issues:** [OI-42](#oi-42--effectful-foreign-entries-callbacks-that-touch-memory-or-effects)

### Current Findings

`sysv-x86_64-c` lowers register-passed scalars: up to six INTEGER-class and eight SSE-class (f32/f64) arguments, and one scalar result.

- Pure C-to-XAX callbacks run through a compiler-generated adapter, typed by a `code-entry:sysv-x86_64-c` code-address type.
- Executed: libc `tsearch`/`tfind` with an XAX comparator, and libm `ldexp`/`pow`/`sqrtf` (`linux_c_interop_evidence.json`).
- The original closure program, `qsort` with an XAX comparator, now runs as `qsort_r` with a lend entry (ADR-115, OI-42 closed).

### Closure Criteria

The original record states no separate closing evidence. It lists the following as still missing:

- [ ] Callbacks that read memory the C caller passes (OI-42; now closed, see its record).
- [ ] Aggregates by value and by memory.
- [ ] Stack arguments.
- [ ] Variadics through typed argument packs.
- [ ] Symbol versioning.
- [ ] Direct binding.

### References

- `linux_c_interop_evidence.json`

## OI-41 — Check-free pointer reloads (typed mixed storage)

**Status:** CLOSED (2026-10-02, ADR-097)

**Related ADRs:** ADR-094, ADR-095, ADR-097, ADR-101

**Related Issues:** [OI-37](#oi-37--pointer-values-stored-in-memory)

### Summary

Can stored links be reloaded as dereferenceable pointers without a per-link range check, by proving that every value stored in a link field is null or a valid record address in the same storage?

### Fixed Constraints

- No manufactured provenance.
- No hidden runtime metadata.
- The kernel grows only under the §21.5 admission rule.
- The likely shape is a record-layout view type, a link scalar type, make-link and follow-link operations (null test only), and rules that keep foreign code from writing link fields.

### Decision

Record views with typed `link` fields, `link_make`/`link_follow`, and per-storage link targets make reloads check-free (null test only, elided under a dominating null test).

### Evidence and Measurements

- `chains` runs at 1.066× unchecked pointer `gcc -O2` (`oi37_chains_evidence.json`), within the 1.1× criterion.
- Forged-link vectors reject (`test_xax_links.py`).
- Growth: 1 type form, 2 operations, 1 optional `heap_view` operand, 21 rules, +227/−33 verifier lines.
- Verify time is 3.6 ms against 3.5 ms for index links (`oi41_links_evidence.json`).

#### Follow-up (ADR-101)

Cross-storage targets now cross direct calls through a per-function `link_target` declaration. Growth: 1 operation and 2 rules.

### Closure Criteria

- [x] `chains` (or an equivalent pointer-chasing workload) within 1.1× of unchecked pointer C on the same host, verified.
- [x] Negative vectors for forged link fields.
- [x] Measured kernel and verifier growth.

### References

- `oi37_chains_evidence.json`
- `oi41_links_evidence.json`
- `test_xax_links.py`

<details>
<summary>Historical Record</summary>

#### History

Measured motivation: the `pointer_rebase` check costs 1.51× in C on `chains`, and XAX pointer links ran at 1.58× `gcc -O2`. The user first deferred this in favour of ADR-094/095, then asked for it.

</details>

## OI-42 — Effectful foreign entries (callbacks that touch memory or effects)

**Status:** CLOSED (2026-10-03, ADR-115)

**Related ADRs:** ADR-092, ADR-102, ADR-115

**Related Issues:** [OI-40](#oi-40--breadth-of-the-sysv-c-abi-on-linux)

### Summary

How does an XAX function called by foreign code receive the effect and resource proofs it needs, when the foreign caller cannot pass proof values? Example: a `qsort` comparator reads the two array elements whose addresses `qsort` passes, and those elements live in an XAX heap view that the caller lent to `qsort`.

### Fixed Constraints

- No ambient authority and no hidden effects (ADR-102 rejects proof parameters on foreign entries for this reason).
- The proofs a callback uses must come from the foreign declaration that receives it, because only that call is in progress when the callback runs.
- Whatever the adapter synthesizes must be erased at run time.
- Bounds stay checked or proven, since the foreign caller chooses the addresses.

### Alternatives Considered

| Candidate | Description |
| --- | --- |
| (a) | The foreign declaration states, per callback parameter, which of its own borrowed inputs the callback may use. The adapter then supplies the matching erased tokens, and pointer arguments are refined into that view with a checked rebase (as `pointer_rebase`, ADR-092). |
| (b) | Callbacks receive only an opaque context integer and reach memory through explicit raw operations with an `unsafe` effect waiver. |

### Decision

Candidate (a) was implemented as lend entries (`sysv-x86_64-c-lend`).

### Evidence and Measurements

Glibc `qsort_r` sorts an XAX-owned 16-element heap array with an XAX comparator that reads elements through the lent view (EXECUTED, exit 117; the descending comparator yields the descending checksum).

Negative vectors:

- the entry kept past the call via `atexit` (`LEND-ENTRY-VIEW-LENT`);
- a call lending no view;
- a write through the lent view (`MEMORY-WRITE-PERMISSION`);
- a writable lent view;
- a view of another extent;
- a callback returning a pointer into the view (`GRAPH-FUNCTION-ADDRESS-FOREIGN-ENTRY`).

### Closure Criteria

- [x] An executed `qsort` (or `bsearch`) program whose XAX comparator reads elements of an XAX-owned array.
- [x] Negative vectors for using the borrow after the foreign call returns, for writing through a read-only lent view, and for a callback stored past the call (for example, registered with `atexit`).

### References

- `test_xax_lend_entry.py`
- `linux_qsort_evidence.json`

## OI-43 — Browser event entries (host-invoked XAX entry points)

**Status:** CLOSED (2026-10-02, ADR-104)

**Related ADRs:** ADR-102, ADR-103, ADR-104

**Related Issues:** [OI-32](#oi-32--foreign-metadata-importer-scope-and-representation)

### Summary

How does a browser page deliver events (click, input, timers, fetch completion) to XAX without hand-written JavaScript and without hidden effects?

### Fixed Constraints

- The host page stays compiler-generated (ADR-103).
- An event entry receives its authority (the page `effect<io>` token and any other proofs) from the host, as `_start` does.
- JavaScript runs handlers to completion one at a time, so the host's event order is the effect order.
- Unused event kinds emit no host code.

### Alternatives Considered

| Candidate | Description |
| --- | --- |
| (a) | Reuse ADR-102: a code-address type `code-entry:wasm32-browser-event` whose functions take and return proof values only. `FUNCTION_ADDRESS` lowers to a table index, and a binding such as `listen_click(element, entry)` registers it. |
| (b) | Named exports declared by a content-addressed carrier, as Android does for JNI exports. In that case registration is fixed at build time rather than performed by program semantics. |

### Decision

Candidate (a) was implemented.

### Evidence and Measurements

- In headless Chromium 141, the XAX `on_click` entry re-renders `"n fib(n)"` on each click for four queries with no page errors (`browser_fib_evidence.json`).
- Negative vectors cover a machine parameter, a claimed memory effect, an internal address on wasm, a browser entry on x86-64, and an undeclared binding (`WEB-IMPORT-DECLARED`).
- Remaining breadth (more event kinds, element addressing, timers, fetch) is ordinary binding-package growth under OI-32.

### Closure Criteria

- [x] An executed page whose XAX click handler updates the DOM on each click.
- [x] Negative vectors for a handler that has machine parameters and for an undeclared event kind.

### References

- `browser_fib_evidence.json`

## OI-44 — Hardware versus emulated execution as replacement evidence

**Status:** OPEN

**Related ADRs:** ADR-114, ADR-155, ADR-198, ADR-254

### Summary

ADR-114 lets emulated execution (QEMU, Unicorn) satisfy `code_generation` and `real_execution`, which is enough for R1. Should R1 for an ISA row (RISC-V, AArch64 bare metal) instead require one hardware run, as R3 effectively does for applications?

### Fixed Constraints

- Emulators never supply performance evidence, and emulator-only rows list "not hardware" as a blocker.
- Image bytes must equal what the hardware would receive.

### Current Findings

- The riscv64 and aarch64-baremetal rows are emulator-only.
- 2026-10-10, ADR-254: the Linux AArch64 static profile now runs on hardware, a Pixel 8 Pro's kernel through `adb`, and its runtime tests pass there as they do under qemu: the first hardware ISA run, no discrepancy. One more ISA row is needed; dynamic Linux AArch64 images still run only under qemu.
- The Android row's application, first run only on an x86_64 emulator through ARM binary translation (ADR-155), has run on Pixel 8 Pro hardware since ADR-198.
- The matrix validator now rejects `performance` evidence on any row whose blockers say "not hardware" (conformance §22.17).

### Closure Criteria

- [ ] One case where an emulator and hardware disagree on an XAX image (which would show that emulation is insufficient), or
- [ ] a documented hardware run on two ISA rows with no discrepancy against the emulator corpus. Partial: one ISA row has run on hardware (Linux AArch64 static profile, ADR-254); one more is needed.

## OI-45 — Re-executing native evidence after a canonical change

**Status:** CLOSED (2026-10-08, ADR-208)

**Related ADRs:** ADR-177, ADR-198, ADR-207, ADR-208

### Summary

ADR-177 regenerated `xax_op_typing.xax` on a host that cannot run native XAX images, and withdrew R4 for Linux x86-64 and Android because their runtime evidence cannot be recomputed. What re-execution restores them, and how is staleness caught before it recurs?

### Fixed Constraints

- Evidence names the committed store it describes (`store_sha256`). An entry whose store changed carries `native_rerun_required` and null executed fields, never a carried-over verdict.
- Native evidence generators run with `XAX_REQUIRE_NATIVE=1`.
- R4 is derived only from raw per-arm samples under §15.0/§15.0a.

### Evidence and Measurements

The original status record, in chronological order:

1. **OPEN (2026-10-06, ADR-177).**
2. **Self-hosting half EXECUTED (2026-10-07).** On Linux x86-64 (Python 3.13.16) `bench_selfhost_closure.py --write` and `bench_selfhost_x86_64.py --write` re-ran under `XAX_REQUIRE_NATIVE=1` against the committed stores, with no `native_rerun_required` entry left.
   - The typing store's gen1 image equals the bootstrap reference (4,728,348 RV64 code bytes), its emulated verdict equals the native one (95 objects proven), and every component reports `actual_authority: xax`.
   - The native self-hosting tests pass there: 97 passed, and the opt-in fixed-point tests (`XAX_FIXED_POINT=1`) pass too: 7 tests, 31 subtests, 31 minutes.
   - The R4 half (Linux raw-sample re-runs, the Android second baseline) was still open.
3. **Android R4 half closed (2026-10-07, ADR-198).** The counter was re-measured on Pixel 8 Pro against a Java + NDK twin and a pure Java twin, in four rotated passes with equal AOT compilation. XAX is 1.007× the fastest median, with per-pass ratios 1.00/1.053/1.06/1.00 (§15.29). Still open at that point: the Linux `filestat`, `chains` and `jsonmin` R4 re-measurements.
4. **Closed (2026-10-08, ADR-208).** All three re-ran with 31 raw `wall_seconds_samples` per arm (`XAX_BENCHMARKS.md` §15.30); the validator recomputes their verdicts. The Android re-measurement stands (now below R4 under ADR-207).

### Closure Criteria

- [x] On Linux x86-64: `bench_selfhost_closure.py --write` and `bench_selfhost_x86_64.py --write` re-executed against the current stores (no `native_rerun_required` left), and the native self-hosting tests passing there.
- [x] For R4: the Linux `filestat`, `chains`, and `jsonmin` comparisons re-run with `wall_seconds_samples` per arm.
- [x] The Android counter compared against a Kotlin or Java baseline as well as the Java + NDK twin, with the pass effect reported.

### References

- `XAX_BENCHMARKS.md` §15.29, §15.30
- `bench_selfhost_closure.py`, `bench_selfhost_x86_64.py`

## OI-46 — Fixed client overhead in R5 token measurement

**Status:** MOVED (2026-11-28) to [MrxSiN/XAX-MCP#7](https://github.com/MrxSiN/XAX-MCP/issues/7): the measurement and its client side are XAX-MCP's (it owns transport, tool schemas and the client surface). A protocol change its results call for comes back here as an ADR. The earlier status line follows.

**Status:** OPEN (2026-11-25): a measurement design is proposed below for the owner's approval; nothing is run. Opened 2026-10-07 (ADR-195); deferred and unscheduled since 2026-10-08 (ADR-207). It was removed from this register by commit `7af8108` (2026-10-30) and restored on 2026-11-24 from the version before that commit.

### Summary

In the same-prefill JVM comparison (ADR-195), every arm makes one request through the pinned Codex client. That client adds about 10,000 input tokens per request with its default instructions, and about 6,900 even with one-line base instructions. This floor is common to all arms and dominates edits that cost a few hundred task tokens, so a 0.50–0.55× ratio cannot be reached. Which measurement keeps "same model, same tools, equivalent context" and still measures the language and protocol?

### Fixed Constraints

- All arms use the same client, model, instructions and tool surface, and every token the model receives or emits is counted, including retries. No benchmark-only XAX shortcut, no weakened textual workflow, and no removal of a lower-token competitor are allowed. Historical profiles are never re-scored.

### Alternatives Considered

(a) A minimal client or direct API with identical, minimal instructions and no tool schemas for every arm. (b) A corpus whose textual context is legitimately larger: real multi-file repositories where a named-symbol excerpt is not available as cheaply as the XAX neighborhood. (c) Record R5 as unreachable for single-edit tasks under agent clients with a fixed overhead.

### Measurement design (proposed, 2026-11-25)

Not run. A design that combines alternatives (a) and (b), for the owner's approval (the closure criterion asks for
an owner-approved design):

- Client: a direct API caller with one fixed, minimal instruction block and no tool schemas, the same for every arm,
  so the fixed overhead is a few hundred tokens and is reported separately.
- Corpus: v10's single-edit tasks plus tasks on real multi-file repositories (alternative (b)), where the textual
  arm's context is what a competent agent would actually read.
- Counting: every token in and out, retries included; the fixed overhead reported per request; R5 ratios computed
  with and without it.
- Trials: three complete trials (the criterion's v10 successor), then an independent audit of the raw transcripts.
- If (a) and (b) still cannot reach the R5 ratio for single edits, record (c): R5 is unreachable for single-edit
  tasks under a fixed client overhead, and report multi-file tasks only.
- Needs the owner: ADR-207 defers AI-efficiency work, so nothing here runs until the owner approves the design and
  the model budget. No agent runs these trials on its own initiative.

### Closure Criteria

- [ ] An owner-approved measurement design, then a complete three-trial v10 or successor run under it, independently audited.

### References

- [`ADR-200`](XAX_DECISIONS.md), [`ADR-207`](XAX_DECISIONS.md).
- `ADR-195`, `ADR-196` were deleted from `XAX_DECISIONS.md` by `7af8108` (2026-10-30); their text is in git history at `7af8108^`.
- "Option (b) measured (ADR-197)" below names the decision now numbered [`ADR-420`](XAX_DECISIONS.md) (renumbered 2026-11-24 from a duplicate ADR-197); `7af8108` removed its benchmark results from that record.

<details>
<summary>Historical Record</summary>

*Deferred (2026-10-08, ADR-207):* token efficiency is no longer R5; this issue belongs to the future AI-efficiency milestone and stays open but unscheduled.

**Status.** OPEN (2026-10-07, ADR-195). *Option (a) measured (ADR-196):* the minimal Codex client still has a fixed floor of 3,501 input tokens per request. Floor-adjusted medians were XAX 200 and Kotlin 201 (0.995×), so removing client overhead does not make the gate reachable on this corpus. Closing this issue needs option (b), a corpus with legitimately larger textual context, or an owner decision to record R5 as unreachable for single small edits. *Option (b) measured (ADR-197):* on a multi-file corpus XAX is 0.35× whole-file textual workflows but 1.68× an IDE-style excerpt of the same call hierarchy, which the rules require as a valid lower-token competitor. The remaining gap is the fixed edit-form help in every request and lower model reliability on XAX. *Shared grammar (ADR-200):* the edit-form help can now be sent once as shared context (`edit_grammar`, `instructions(shared=ID)`). This has not been measured. Its effect depends on multi-request sessions or prompt caching, and on how the owner accounts the shared block.

</details>

## OI-47 — Path-exact ownership for Android platform objects

**Status:** OPEN (2026-10-08, ADR-204)

**Related ADRs:** ADR-204

### Summary

ADR-204 gives NDK objects linear tokens, but three gaps remain:

1. `AMediaCodec_getInputBuffer` returns a platform buffer whose capacity is written at run time, so it is not a bounds-proven view.
2. `ANativeWindow_fromSurface` can return NULL and releasing NULL is undefined, so the token should exist only on the non-null path.
3. JNI references to SDK objects (`BluetoothSocket`, `MediaCodec`, `AudioRecord`) are checked for release only by reachability, not per path.

How are these made exact without new kernel concepts?

### Fixed Constraints

- No hidden runtime checks, no kernel object model, no wrapper library.
- Existing linear-resource and heap-view rules are reused where possible.

### Alternatives Considered

| Option | Description |
| --- | --- |
| (a) | A sum-typed result (`SUM_MAKE`) whose non-null variant carries the token. |
| (b) | A `HEAP_VIEW`-style foreign view contract whose extent comes from the written size cell, checked once. |
| (c) | Capability-specific owner tokens on JNI local/global references produced by acquiring members and consumed by their release members. |

### Closure Criteria

- [ ] Verifier tests for each option.
- [ ] A device run of a decode loop (configure, queue, dequeue, release).
- [ ] An RFCOMM connect/close with no leaks under StrictMode.

## OI-48 — Windows host-process capabilities for VRAMBoost DX12

**Status:** OPEN (2026-10-13)

**Related ADRs:** ADR-259, ADR-260

### Summary

VRAMBoost DX12 (`D:\GitHub\VRAMBoost`) is an XAX-only DirectX 12 memory tool that loads as a DLL inside game processes. ADR-259 (PE DLL exports) unblocked its first module. Its register `D:\GitHub\VRAMBoost\XAX_CAPABILITY_REQUESTS.md` records the remaining requests with failing examples and acceptance tests.

### Current Findings

| Request | Description | Status |
| --- | --- | --- |
| CR-002 | Typed `win64-c` imports | **Resolved by ADR-260** (2026-10-13): EXECUTED against DXGI and D3D12 |
| CR-003 | COM methods on `com:<Interface>` declarations | **Resolved by ADR-260** (2026-10-13): EXECUTED against DXGI and D3D12 |
| CR-011 | Calling a bare code address (`GetProcAddress` result) under a declared signature, needed for a `version.dll` pass-through proxy | remaining |
| CR-005 | Module state that persists across export calls | remaining |
| CR-006 | Checked views over caller-supplied `(address, length)` buffers at a DLL boundary | remaining |
| CR-007 | A non-trapping failure policy for code inside a host process (`ud2` would kill the game) | remaining |
| CR-008 | Threads, timers and file I/O through the construct carrier | remaining |

### Closure Criteria

- [ ] Each open request closes only with the acceptance test named in the register, EXECUTED on Windows.

## OI-49 — Android ARM64 large composite return copy

**Status:** CLOSED (2026-11-24)

**Related ADRs:** ADR-254

### Summary

The generic ARM64 frame path's return of a composite larger than 16 bytes loads its destination into the same temporary used by the memory-copy data load. Pixel 8 Pro execution of a 64-byte BLAKE3 result faults: the emitted sequence loads the destination into x16, overwrites x16 with source data, then stores through that data value. The affected code is `_compile_general_function`'s indirect-result return copy in `compiler/src/xax_aarch64.py`. The backend is unchanged.

### Decision

Ledger 0035 (`0035-aarch64-copy-data-register{,-aarch64,-android}.batch`) shipped in release 0033's seeds and is on `main`.

- The copy function of the AArch64 frame path (`xax_aarch64_general.xax`, `xax_android.xax`, the driver) and the reference `_copy_memory` move the data through x17 when x16 holds the destination or source address: the return copy through the result pointer, and the entry copy of a composite argument passed on the stack (the same fault).

### Evidence and Measurements

The closing run is the 2026-11-16 Pixel 8 Pro run (`adb`): 18 programs returning 24-, 32- and 64-byte composites from leaf and non-leaf makers.

| Backend | Programs right |
| --- | ---: |
| `main`'s backend before ledger 0035 | 0 of 18 (SIGSEGV) |
| After ledger 0035 | 18 of 18, three repeats identical (EXECUTED, `XAX_STATE.md` 2026-11-16) |

> [!WARNING]
> Evidence limitation: those were static AArch64 images (Linux AArch64 executables) on the device's kernel (ADR-254). A build of the same programs as an Android shared library stays NOT RUN (no harness exists for it). The copy function it would use is the same one ledger 0035 changed in `xax_android.xax`.

The BFX importer uses checked scratch outputs and at most 16-byte mixing results, with native Android and Windows regression evidence in [android_import_evidence.json](compiler/integration/bfx/android_import_evidence.json). This enables that program; it does not repair the general backend operation.

### Closure Criteria

- [x] A canonical XAX backend change with distinct live copy-address/data registers (ledger 0035), exercised on a Pixel 8 Pro for leaf and non-leaf calls and for multiple composite sizes above 16 bytes, with repeatable native results (18 of 18, three repeats identical). Android shared-library build: NOT RUN (see the warning above).

No new Python implementation is needed or authorized by this issue.

### References

- `0035-aarch64-copy-data-register{,-aarch64,-android}.batch`
- `compiler/src/xax_aarch64.py`
- [android_import_evidence.json](compiler/integration/bfx/android_import_evidence.json)
- `XAX_STATE.md` 2026-11-16

<details>
<summary>Historical Record</summary>

#### 2026-11-16: FIXED IN THE STORES (ledger 0035 on `release/0033`); closes when the release's seed ships it

The copy function of the AArch64 frame path (`xax_aarch64_general.xax`, `xax_android.xax`, the driver) and the reference `_copy_memory` move the data through x17 when x16 holds the destination or source address: the return copy through the result pointer, and the entry copy of a composite argument passed on the stack (the same fault). On a Pixel 8 Pro (`adb`), 18 programs returning 24-, 32- and 64-byte composites from leaf and non-leaf makers: 0 of 18 right with `main`'s backend (SIGSEGV), 18 of 18 right after ledger 0035, three repeats identical (EXECUTED, `XAX_STATE.md` 2026-11-16). Static Linux AArch64 executables on the device's kernel; the Android-target build of the same programs was NOT RUN. The earlier status follows.

#### 2026-10-19: OPEN

The report is shown in full as the Summary above, together with this closing requirement of the time.

Evidence that closed it, as stated then: a canonical XAX backend change with distinct live copy-address/data registers, exercised on Android for leaf and non-leaf calls, multiple composite sizes above 16 bytes, output guards and repeatable native results. No new Python implementation is needed or authorized by this issue.

</details>

## OI-50 — x86-64 branch fusion loses cross-block comparison values

**Status:** CLOSED (2026-11-15; opened 2026-10-20) by ADR-376 (ledger 0013, 2026-11-06)

**Related ADRs:** ADR-376

### Summary

Compare/branch fusion in the hosted register allocator (`compiler/src/xax_x86_64_regalloc.py`) counts consumers only in the defining block and its outgoing arguments. A comparison may also dominate uses in later blocks. Fusing it without materializing its result leaves those uses reading a value the emitter did not define. Windows execution through verified raw lowering views reproduces this with a canonical three-block function.

### Decision

The production compiler's x86-64 general backend, a canonical XAX program, fuses a compare into its branch only when the branch is its only use anywhere in the function (every block, terminators included), so a compare read in later blocks is materialized.

### Evidence and Measurements

`tests/test_native_branch_fusion.py` (`SeedBranchFusionTests`) builds two functions with the host's pinned native compiler (`build`, Windows or Linux x86-64): a compare read by its branch, both arms and the join, and a branch-only compare. It runs each on taken, not-taken and equal inputs against `xax_compiler.execute`.

EXECUTED 2026-11-15:

| Host | Result |
| --- | --- |
| Windows seed | passes all six |
| Linux x86-64 (WSL 2), pre-0013 seed | returns 1 for the taken case, where the reference gives 51 |
| Linux x86-64 (WSL 2), ledger 0013 and current seeds | return 51 |

The pre-0013 and current seeds build byte-identical branch-only executables.

> [!WARNING]
> Known limitation: the Python reference emitter (`compiler/reference/xax_x86_64_regalloc.py`) keeps the defect: through `xax_x86_64.compile_native` the reused case returns garbage. It is not the production path and is not repaired (language rule).

### Closure Criteria

- [x] A canonical XAX backend repair accounting for all comparison uses, with native positive/negative branches, reuse in multiple later blocks, and unchanged branch-only comparisons. Do not substitute a new Python compiler implementation.

### References

- `tests/test_native_branch_fusion.py`
- [canonical control and fixed fixture](compiler/integration/windows_helpers/DRIVER.md)
- [execution report](compiler/integration/windows_helpers/driver_execution.json)

<details>
<summary>Historical Record</summary>

#### Original report (opened 2026-10-20)

The report summarized above as Summary is kept in the Summary section. The remainder of the original report:

The [canonical control and fixed fixture](compiler/integration/windows_helpers/DRIVER.md) and [execution report](compiler/integration/windows_helpers/driver_execution.json) record the reproduction. Capturing the comparison as a 64-bit flag before the branch makes the equivalent fixed graph pass 256 native inputs. The Windows driver follows that convention for 522 results in 95 functions through an exact transaction. The Python emitter remains unchanged; arbitrary programs still need a general repair. No Linux execution is claimed by this report.

</details>

## OI-51 — Windows native driver coverage and diagnostic parity

**Status:** OPEN (2026-11-25). Scope moved to the Windows seed; it accepts the self-store and re-ran the verify-exact corpora with no decline. The large flag record is refused by the edit engine's 16 MiB capacity.

**Related Issues:** [OI-52](#oi-52--64-bit-checked-offsets-and-growable-views-roadmap)

### Current Findings

#### Windows seed run (2026-11-25)

Scope decision: the criteria are judged on the Windows seed, the production driver built as a PE image (ADR-397,
ADR-402); the prototype below is superseded and is not developed further. Runs, all EXECUTED on Windows 11 with the
release 0042 Windows seed (`4d361a39…`) as a native Windows process:

| Criterion | Run | Result |
| --- | --- | --- |
| Accept the corrected self-store | `xaxc verify compiler/integration/windows_helpers/driver.xax` | exit 0 (13 s) |
| Replay the large flag transaction | the prototype's base (driver at `dc25d2b`, root `68347cdf…`), then `windows_host.edit`, then `windows_flags.edit` | the host record gives the flag record's expected root `eec166ea…` (14 s); the flag record is refused: `DRIVER-EDIT-CAPACITY`, expected 16,777,216, actual larger |
| Re-run the corpus | `test_xax_selfhost_verify_exact`'s seven corpora with the Windows seed as the driver (through WSL interop) | 938 exact diagnostics, 377 accepts, 0 declines, 0 driver records (114 s) |

- The original 212-case inputs were generated by an SDK harness outside the repository and are not kept; the
  verify-exact corpora (object sites, types and constants, graphs, uses, memory facts, resource callees, the 36
  declared rejections) cover every object kind, and no case declined, so no decline is read as a validity claim.
- Left open: the flag record (15.9 MB) exceeds a fixed 16 MiB region of the edit engine. Lifting it is edit-engine
  work in the production driver (the same kind of limit OI-54 step 1 raised for bodies), not a Windows matter.

#### Check (2026-11-15): still OPEN

The production compiler now runs natively on Windows (the Windows seed, ADR-397, ADR-402), but no run of it, or of the prototype, has accepted the corrected self-store, replayed the large flag transaction byte for byte, or re-run the 212-case corpus. Those are this issue's closing criteria. Whether they should move from the prototype to the Windows seed is a scope decision for this issue; until one of them runs, it stays open.

#### Windows driver prototype (2026-10-20)

The [Windows driver prototype](compiler/integration/windows_helpers/DRIVER.md) on its 212-case corpus:

| Outcome | Cases |
| --- | ---: |
| Accepts reference-valid stores | 78 |
| Rejects reference-invalid stores | 130 |
| Explicitly declines (malformed) | 4 |

- The original run's rejected case, `semantic-43-function_byte`, produces `XAX.CANON.TRAILING_BYTES / TYPE-BODY` where the reference produces `XAX.TYPE.EXPECTED / TYPE-BITS`. The current canonical [kind-order transaction](compiler/integration/windows_helpers/type_kind_order.edit) corrects that mismatch.
- A separate 160-case native replay now has 63 accepts, 97 rejects and exact full diagnostic equality, including dependencies and repair neighborhood. Its 110 helper checks cover every object kind. The complete original 212-case corpus has not been replayed in this follow-up.
- All 508 original graph bodies decode natively. Audited CFG input/output and object-table sizes fit their current views.
- Windows DLL packaging and migration of the common Python helper loader remain outside the implemented native route.

#### Self-store and large flag edit

The corrected self-store and large flag edit still decline.

- A private canonical probe locates the original self-store's decline at resource-callee action 2. The current self-store probe identifies its entry graph (2,149 blocks, 37,533 nodes; defer token zero). The underlying node/facts reason is still being diagnosed.
- Separate tiny resource-call controls accept one/same callee, decline two distinct valid callees and reject a malformed second callee exactly. [Resource evidence](compiler/integration/windows_helpers/resource_diagnosis.json) and [private records](compiler/integration/windows_helpers/diagnostics/README.md) preserve that distinct coverage gap without assuming it is the self-store's cause.

#### BBC O0 decisions (2026-10-31)

With packed decision lengths ([PACKED_LENGTHS.md](compiler/integration/bfx/PACKED_LENGTHS.md)) factor's O0 decision builds and runs on Windows.

- Mandelbrot's O0 decision (a 1,389,518-byte decision store) still declines, and the decline is in native `verify` of the decision store alone (exit 2), before resolution or lowering. The reference verifier accepts the same store.
- The facts checker bump-allocates its tables from one fixed arena and declines on exhaustion (`xax_selfhost_facts.alloc`), which fits edges that no single count explains; this is not yet confirmed with the decline-site probe.

> [!WARNING]
> No B-level or replacement matrix promotion follows from the current prototype.

### Closure Criteria

- [x] Canonical graph changes preserving rejection and diagnostic ordering, accepting the corrected self-store (2026-11-25, Windows seed).
- [ ] Replaying the large transaction byte for byte.
- [x] Re-running the corpus without treating declines as validity claims or removing the diagnostic mismatch (2026-11-25, Windows seed, the verify-exact corpora).

### References

- [Windows driver prototype](compiler/integration/windows_helpers/DRIVER.md)
- [kind-order transaction](compiler/integration/windows_helpers/type_kind_order.edit)
- [resource evidence](compiler/integration/windows_helpers/resource_diagnosis.json)
- [private records](compiler/integration/windows_helpers/diagnostics/README.md)
- [PACKED_LENGTHS.md](compiler/integration/bfx/PACKED_LENGTHS.md)

## OI-52 — 64-bit checked offsets and growable views (roadmap)

**Status:** OPEN (2026-10-29). R1 and R2 are done; R3 and R4 remain.

**Related ADRs:** ADR-231, ADR-373, ADR-374, ADR-412

**Related Issues:** [OI-62](#oi-62--the-legacy-wasm32-profile-emits-an-invalid-module-for-a-bits64-checked-offset), [OI-54](#oi-54--function-views-past-218-values-bbcs-hanoi--o0)

### Summary

BBC's decision tape is now a lazily committed view of 2,147,246,080 bytes instead of 65,536 ([dynamic tape](compiler/integration/bfx/DYNAMIC_TAPE.md)). That size is set by three present XAX limits, measured with the native driver on 2026-10-29.

### Current Findings

1. **Static extents.** `heap_view<E>` carries its extent in the type, so a view cannot grow at run time. Hosts reserve the largest extent and commit pages on first touch (Android `mmap` does this natively; Windows needs a reservation plus a commit-on-touch handler, as `bbc.xax` already uses for its driver views).
2. **32-bit checked offsets.** Checked loads and stores take a `bits<32>` byte offset (`docs/04_MEMORY_RESOURCES.md`, ADR-231), so no checked view exceeds 4 GiB.
3. **x86-64 bound encoding.** The x86-64 backend encodes `extent - size` as a signed 32-bit immediate. An extent of 2,147,483,648 builds; 4,294,963,200 rejects with `XAX.NATIVE.MEMORY` / `NATIVE-CHECKED-BOUND-ENCODABLE`. The same 4,294,963,200-byte view builds for Android ARM64.

### Roadmap

| Item | Description | Status |
| --- | --- | --- |
| R1 | x86-64 encoding | DONE 2026-11-05 (ADR-373, ADR-374; ledgers 0010, 0011) |
| R2 | 64-bit checked offsets | DONE 2026-11-19 (ADR-412, ledger 0038, release 0038) |
| R3 | Growable views | open |
| R4 | BBC follow-through | open |

#### R1: x86-64 encoding (DONE 2026-11-05)

ADR-373, ADR-374; ledgers 0010, 0011. Done for the native general backend's register and frame paths; the PE legacy path and the division span check still reject.

- When `extent - size` is not a sign-extended imm32, materialize the bound in a register (`mov r64, imm64`) and compare 64-bit. This alone lifts x86-64 to the 4 GiB offset limit.
- Test: the 2^31 and 4 GiB−4 KiB probes above, plus first-crossing traps at both edges.

#### R2: 64-bit checked offsets (DONE 2026-11-19)

ADR-412, ledger 0038, release 0038.

- The verifier accepts a `bits<64>` offset. The x86-64 frame path loads the index whole. AArch64, RISC-V, the JVM and general Wasm32 already compared 64 bits. SPIR-V rejects (`SPIRV-VALUE`). The legacy Wasm32 profile is OI-62.
- EXECUTED: the release's Windows seed builds a 5 GiB view probe that answers at its last byte and past 2^32 and traps at the edge and at 2^64 - 1, natively on Windows 11 (10 of 10, both x86-64 paths); Linux AArch64 under qemu (14 of 14).
- The Android ARM64 device run, first BLOCKED (no adb device), ran later on 2026-11-19 on a Pixel 8 Pro (`XAX_AARCH64_ADB=1`): an 8 GiB view answers 42 at its last byte and past 2^32 and traps (`brk`, SIGTRAP) at the edge and near 2^64, 14 of 14 built in-process and 14 of 14 built by the release's Linux seed `15b6c6d9…`.
- R2's evidence is complete; OI-52 stays open for R3 and R4.
- The original item: allow `bits<64>` offsets on byte views with the unchanged rule `offset + size <= extent`, evaluated without overflow. Requires an ADR, verifier and both native backends; `bits<32>` stays valid.

#### R3: growable views

A view whose extent is a run-time value bounded by a static reservation, with a verified grow operation, so hosts need neither a fixed reservation nor a fault handler. Requires an ADR and a resource-state rule for growth.

#### R4: BBC follow-through

Once R1–R2 land, BBC widens the tape and the movement bounds, and moves the decision's position and I/O lengths to 64 bits through a versioned BFX/decision ABI change.

### Closure Criteria

- [ ] Native builds and device runs on Windows x86-64 and Android ARM64 of a program that moves past 4 GiB of tape and then fails exactly at the new edge, with the importer and hosts unchanged except for the extent.
  - [x] R1 done.
  - [x] R2 done.
  - [ ] R3 (growable views).
  - [ ] R4 (BBC follow-through).

### References

- [dynamic tape](compiler/integration/bfx/DYNAMIC_TAPE.md)
- `docs/04_MEMORY_RESOURCES.md`

## OI-53 — `xaxc verify` rejects byte-view widening

**Status:** CLOSED (2026-11-06, ADR-376, ledger 0013)

**Related ADRs:** ADR-231, ADR-376

**Related Issues:** [OI-50](#oi-50--x86-64-branch-fusion-loses-cross-block-comparison-values)

### Summary

The general backend fused a compare into its branch although a later block read it, so the self-built compiler miscompiled its own facts program.

Before the fix, the production compiler's `verify` answered `MEMORY-CHECKED-STORE-TYPE` for an 8-byte `bits<64>` checked store through a `ptr<bits8>` heap view (byte-view widening, ADR-231).

- `verify_store` accepts it, both with the native typing program and with the reference alone.
- The driver holds the typing store's 88 functions as the same objects, so the difference is in the tables the driver builds for them.
- BBC's committed driver (`integration/bfx/bbc.xax`) fails native `verify` this way.

### Evidence and Measurements

- `tests/test_native_verify_byte_view.py` is no longer an expected failure: the ledger 0013 fix (`fc7ebcd`) lifted the marker, and the test's docstring records OI-53 as closed.

<details>
<summary>Historical Record</summary>

#### Before the fix

- Reproduction: `tests/test_native_verify_byte_view.py` (expected failure).
- The original record's last sentence reads: "Fix natively (a driver transaction), then lift the expected failure."

</details>

## OI-54 — Function views past 2^18 values (BBC's hanoi -O0)

**Status:** OPEN (2026-11-28). Step 2 part 2 for Windows x86-64: the 8 GiB workspace (release 0044) and the x86-64 arena above it with a value capacity of 2^20 (release 0045, ADR-423 amendment 6); hanoi -O0 for Windows x86-64 builds and matches with that release's `bbc.exe`. The capacity is still a fixed value, not sized per function. Step 3 (AArch64 liveness) stays open. Step 1 done (release 0039, ADR-413); step 2 part 1 in release 0042 (ADR-419).

**Related ADRs:** ADR-386, ADR-387, ADR-390, ADR-391, ADR-413, ADR-419

**Related Issues:** [OI-52](#oi-52--64-bit-checked-offsets-and-growable-views-roadmap)

### Summary

One function view holds at most 2^18 values. Since ledger 0023 (ADR-391) that capacity is a workspace word (globals slot 170) that the backend prologues set, not a constant in 18 functions; its value is still 262,144. BBC's hanoi at -O0 is one decision of about 620,000 values (7.25 MB, 54,000 blocks) and declines.

### Current Findings

#### Workspace census (2026-11-24)

A census of the workspace (gdb at the first `munmap`, nonzero bytes per 2^20-word bucket of the 2 GiB view; words in Mi = 2^20) found what lies above the arena's end (Mi200 = 209,715,200).

| Situation | Occupied | Free |
| --- | --- | --- |
| Full self-build by the part-1 compiler (`8d7745ab…`, 2:52, 2.87 GB peak) | image buffer Mi200–Mi216; image record Mi232–Mi239; top word page | Mi217–Mi231 and Mi240–Mi254, about 15 Mi words each |
| During hanoi -O0 (declining, capacity 917,504) | Mi200–Mi217, Mi236–Mi238 and Mi247–Mi255 hold data | not stated |

- The per-value tables at hanoi's size are about 86 words × 650,000 values = 56M words, and 112M with a ×2 capacity margin.
- Neither fits one free span, nor both together (31M words), so a region of their own inside the fixed 2 GiB workspace is not enough.
- Part 2 needs one of: tables packed to 32-bit lanes (about 43 words per value, then also moving the image record), a second workspace view (a host ABI change), or growable views (OI-52 R3). Decided 2026-11-25: growable views (ADR-423).

#### Release 0043 check (2026-11-25)

With the release 0043 `bbc.exe` (`4521cc64…`) on Windows 11, EXECUTED: hanoi -O1 for Windows x86-64 builds (33 s, 359,424 bytes, byte-identical to 0042's) and runs (19,090 bytes of output, equal to the independent interpreter's); -O0 for both targets and -O1 for Android ARM64 decline (exit 5), as with 0042.

#### Release 0045 arena (2026-11-28)

Ledger `0045-x86-64-arena-above-2gib` (ADR-423 amendment 6) puts the x86-64 entry's arena at [2^28, 2^30 − 2^27) words with a capacity of 2^20; the other pipelines' arenas stay. EXECUTED on Windows 11 with a `bbc.exe` built from BBC's driver with the same batch: hanoi -O0 for Windows x86-64 builds (318 s) and its output equals the expected 19,090 bytes. Not yet run: Android ARM64 -O0 (step 3).

#### Remaining steps

In the order a build meets them (ADR-386, ADR-387, ADR-390):

1. The semantic index's graph-stream region (3 M words at word 20 M, below regions at 23 M and 24 M), the edit engine's 4 MiB body limit, and the graph decoder's 4 MiB body view (prepared as ledger 0021). **Step 1 done (2026-11-20, release 0039, ADR-413)**, see the Historical Record.
2. Room for the per-value tables: about 118 words per value of capacity in the x86-64 arena (80 M words, words 120 M–200 M), so the capacity and the arena boundary must follow the program rather than fixed regions. **Step 2 part 1 is in release 0042; part 2 moves to release 0043.**
3. An AArch64 liveness that is not one bit per value per block (hanoi's would be about 4 GB). **Open.**

The decision's nine block parameters cannot shrink: the memory facts need each heap view to travel with its effect (`HEAP-VIEW-RETURN-WHOLE`, ADR-390).

#### Unlocated decline (2026-11-20)

A 4.5 MB chain of 21,000 blocks of 37 values declines after the facts engine; not located.

### Closure Criteria

- [ ] BBC's hanoi -O0 builds for Windows x86-64 and Android ARM64 and matches the interpreter, with no fixed per-view capacity left in the driver.

<details>
<summary>Historical Record</summary>

#### 2026-11-23: step 2 part 1 on `release/0042` (ledger 0042, ADR-419)

- The x86-64 container buffer is sized from the image (I_LEN + 1 MiB, at most 48 MiB + 64 KiB) and its 273 checks read the allocated size, which frees about 49M of the arena's 84M words for ordinary builds.
- Measured: the first value-capacity limit is the x86-64 prologue's capacity word (262,144; F355). With part 1 and a capacity of 917,504, hanoi -O0 reaches the backend and declines during the views with 6M arena words left after the tables.
- The rest of step 2 is a layout change: the per-value tables need a region of their own (or the workspace must grow, OI-52), and the capacity can then follow the program (a count of each function's lifted values in `views_prologue`).

#### 2026-11-20: step 1 done (release 0039, ADR-413)

BBC's hanoi -O0 decision (one 7.25 MB graph fragment) now verifies, resolves and takes a native edit. The front end's limits were measured rather than taken from the list below, and four were lifted, each with a test just past its old value (`tests/test_xax_oi54_limits.py`):

- the CFG program's output view (128 MiB to 1 GiB; it was the first limit for every O0 function past 22,238 instructions);
- the semantic index's block section (1M to 3M words, moved to 29M–32M);
- the graph decoder's body buffers (4 to 8 MiB);
- the edit engine's body region (4M to 8M + 64K words; a larger body had been silently overwritten by the preimages).

The index's node stream (step 1's first item) was never binding for hanoi. Still open at that date: steps 2 and 3; and a 4.5 MB chain of 21,000 blocks of 37 values that declines after the facts engine, not located.

#### 2026-11-08: OPEN (record)

The Summary above and the steps listed under "Remaining steps" are from this record. Its list read "What it still needs, in the order a build meets them (ADR-386, ADR-387, ADR-390)".

</details>

## OI-55 — Native x86-64 signed compares below 32 bits

**Status:** CLOSED (2026-11-15). The Linux half closed with ADR-393.

**Related ADRs:** ADR-392, ADR-393, ADR-397

### Summary

The native x86-64 general backend compares zero-extended `bits<N>` values, N < 32, with a 32-bit `cmp`, so `int.compare` with `slt`, `sle`, `sgt` or `sge` ignores the operand's sign bit. A verified program then computes a wrong flag with no diagnostic. The Python reference backend had the same defect and is fixed (ADR-392).

### Decision

Ledger 0024 sign-corrects both lowerings. The Linux seed is rotated to `fb31b03b…`. BBC's driver follows the fixed production driver. The Windows seed is cut from the fixed driver (ADR-397) and builds `native/0024/narrow_signed_compare.xax` to the Linux seed's bytes.

### Evidence and Measurements

| Host | Result |
| --- | --- |
| Linux (ADR-393) | 240 of 240 probe programs equal the reference executor (128 of 240 differ with the seed before, which confirms the expectation) |
| Windows 11 (EXECUTED 2026-11-15, `XAX_STATE.md`) | all 3,840 equal the reference executor |

The Windows run: `tests/test_x86_64_narrow_signed_compare.py::SeedNarrowCompareTests` builds the file's cases (6 widths × 10 predicates × 64 operand pairs) as PE programs with the pinned Windows seed `e88877d1…` and runs them on Windows 11.

- The seed inlines the callees and keeps one operand of each compare as an immediate.
- The other operand is a register or stack value, sign-corrected at run time (`shl $24` then `cmp`/`setl` at width 8), which is the ledger 0024 lowering.

### Closure Criteria

- [x] A ledger transaction that sign-corrects these compares on `xax_compiler_driver_general.xax` and `seed/xax_compiler_request.xax` (ledger 0024).
- [x] The rebuilt and rotated Linux seed, BBC's driver rebuilt from it, and a Windows seed cut from it.
- [x] `tests/test_x86_64_narrow_signed_compare.py`'s cases executed through the native compiler on Linux and Windows, equal to the reference executor.

Do not substitute a Python implementation.

### References

- `tests/test_x86_64_narrow_signed_compare.py`
- [independent audit, finding 1](docs/audits/2026-11-11-independent-audit.md)

<details>
<summary>Historical Record</summary>

#### 2026-11-12: OPEN for Windows PE cases only; closed on Linux by ADR-393

Ledger 0024 sign-corrects both lowerings, the Linux seed is rotated to `fb31b03b…`, and with it 240 of 240 probe programs equal the reference executor (128 of 240 differ with the seed before, which confirms the expectation below). BBC's driver follows the fixed production driver. The Windows seed is cut from the fixed driver (ADR-397) and builds `native/0024/narrow_signed_compare.xax` to the Linux seed's bytes. Still missing: the cases as PE programs, built by that seed and run on Windows. The record of 2026-11-11 follows unchanged.

#### 2026-11-11: OPEN (reproduction)

Reproduced on the Windows seed `compiler/bootstrap/windows/xaxc-windows-x86_64.exe` (SHA-256 `aa72234d…ab79`), the compiler XAX-MCP pins: a PE program that truncates two stdin words to `bits<8>`, compares them and exits with the zero-extended flag returns 0 for `0xF1 slt 0x03`; the reference executor gives 1. 40 of 441 single-operation probes fail, all signed predicates at widths 8 and 16 ([audit](docs/audits/2026-11-11-independent-audit.md), finding 1). The Linux production compiler (ledger 0023) was not run: the audit host has no Linux. It was accepted on byte equality with the bootstrap, so it is expected to fail the same probes.

No committed store is affected: the frozen compiler stores, the production driver and the MCP programs hold no signed compare below 32 bits.

Closing evidence as stated then: a ledger transaction on `xax_compiler_driver_general.xax` and `seed/xax_compiler_request.xax` that sign-corrects these compares (or sends the function to a corrected path), the rebuilt and rotated Linux seed, BBC's driver rebuilt from it, and a Windows seed cut from it; then `tests/test_x86_64_narrow_signed_compare.py`'s cases executed through the native compiler on Linux and Windows, equal to the reference executor. Do not substitute a Python implementation.

</details>

## OI-56 — PE images take large frames without a stack probe

**Status:** CLOSED (2026-11-24)

**Related ADRs:** ADR-396, ADR-397

**Related Issues:** [OI-58](#oi-58--windows-x86-64-code-generation-on-the-chains-walk-r4-blocker-for-windows-x86_64-pe), [OI-60](#oi-60--host-portability-gaps-left-after-the-2026-11-13-audit)

### Summary

The native x86-64 general backend allocates a PE function's frame with one `sub rsp, N`. Windows commits a thread's stack one guard page at a time, so a frame larger than a page that is first written below the guard page faults. The Python reference probes each page for the PE profile (`xax_x86_64._reserve_stack`); the native backend does not, and the PE header commits only 4 KiB of the 1 MiB reserve.

### Decision

Ledger 0026 is in both seeds since 2026-11-12 and on `main`.

### Evidence and Measurements

Every release since has rebuilt `bbc.exe` from the fixed driver and run BBC's `check.py` with the Windows files executed natively on Windows 11 (release 0041: 372 of 372, `XAX_HANDOFF.md` 2026-11-23), which is this issue's closing evidence.

> [!WARNING]
> Evidence limitation: the DLL note (a DLL runs on its host's thread stack) was answered by ledger 0034's per-page PE probes (release 0033). A DLL frame over 4 KiB run on Windows 11 is still NOT RUN and is tracked with OI-58 and OI-60.

### Closure Criteria

- [x] A native transaction that makes PE frames safe (page probes in the frame and register prologues as the reference emits them, or a header that commits the reserve), the Windows seed and `bbc.exe` rebuilt, and BBC's checks run on Windows itself, not under Wine.

### References

- `XAX_HANDOFF.md` 2026-11-23
- `XAX_STATE.md` 2026-11-12

<details>
<summary>Historical Record</summary>

#### 2026-11-12: FIXED IN THE STORES AND IN THE WINDOWS SEED (ledger 0026, ADR-396, ADR-397); the Linux seed is rotated to it (`7988e0d0…`, 2026-11-12)

The Windows seed is rebuilt from the fixed driver and builds itself on Windows 11 (`compiler/benchmarks/windows_selfhost_evidence.json`). Earlier status: PE images now commit their whole stack reserve, and the unpatched `bbc.exe` built from the new stores runs on Windows 11 (`XAX_STATE.md`, 2026-11-12). Still open for closing: the Linux seed rotation (pending review together with ledgers 0024 and 0025). The record of the defect follows.

#### Record of the defect

Reproduced on Windows 11 (build 26300) with the `bbc.exe` the seed `a35fd59f…` builds from the committed `integration/bfx/bbc.xax` (36,319,232 bytes, SHA-256 `445b2fb2…`): every invocation, `bbc.exe compile windows-x86_64 hello.exe < hello.bf` included, ends with exception `0xC0000005` at image offset `0x15e1817`, the first store after `sub rsp, 0x13038` (gdb: `mov [rsp+0x20], rcx`). Wine commits the whole stack, so the Wine campaigns pass. With `SizeOfStackCommit` set to `SizeOfStackReserve` in a copy's header the same file compiles and its outputs run on Windows 11 and on a Pixel 8 Pro; the 2026-11-11 device measurements use such a copy.

</details>

## OI-57 — The reference's S12c.2 analysis audit disagrees with the native `basics` since ledger 0022

**Status:** CLOSED (2026-11-15)

**Related ADRs:** ADR-388

### Summary

`tests/test_xax_selfhost_general_view.py` failed on Linux x86-64 with `XAX_REQUIRE_NATIVE=1`: `test_jsonmin`, `test_random_programs` (trials 2, 17 and 39), `test_register_resident_analyses` and one subtest of `test_executables_assembled_in_xax`.

- The messages are "S12c.2 analyses disagree" in `erased` and `uses` (for some functions also `pinned`, `allocatable` and `hoisted`) and one "S12d emission disagrees" (272 against 270 bytes).
- The native `basics` folds constants since ledger 0022 and the Python reference's analysis audit does not, so the two sides describe different graphs.

### Decision

The reference register lowering (`compiler/reference/xax_x86_64_regalloc.py`) now does both halves of ADR-388, as the native `basics` and emit do.

- It folds single-result wrap add/sub/mul, truncate and zero extend of width 8/16/32/64 over constants, in value order, into erased constants.
- It also saves the register of every hoisted constant.

So the audit and the native analyses describe the same graph. The emission difference (272 against 270 bytes) was the missing save of `r15`, which held a hoisted constant.

### Evidence and Measurements

`tests/test_xax_selfhost_general_view.py` passes under `XAX_REQUIRE_NATIVE=1` on Linux x86-64 (WSL 2, seed `0cd26742…`): 17 passed, 119 subtests (EXECUTED, `XAX_STATE.md` 2026-11-15).

### Closure Criteria

- [x] The audit and the native analyses compared on the same graph (the reference folding as `basics` does, or the comparison made after folding on both sides), and the file passing under `XAX_REQUIRE_NATIVE=1`; or the audit replaced by a native check under the repository's language rule.

### References

- `tests/test_xax_selfhost_general_view.py`
- `compiler/reference/xax_x86_64_regalloc.py`

<details>
<summary>Historical Record</summary>

#### 2026-11-12: OPEN

The failure description is shown as the Summary above.

Seen at commit `6bcaf77` with the seed `a35fd59f…` (2026-11-11) and again with the seed `fb31b03b…` (2026-11-12); it is not caused by ledger 0024 or the seed rotation. Not established: whether every failing case is this one cause (the emission difference was not traced). The later closure traced the emission difference to the missing save of `r15`.

</details>

## OI-58 — Windows x86-64 code generation on the `chains` walk (R4 blocker for `windows-x86_64-pe`)

**Status:** OPEN (2026-11-12); a fix of item 1 was tried and dropped (2026-11-13, OI-59)

**Related Issues:** [OI-37](#oi-37--pointer-values-stored-in-memory), [OI-59](#oi-59--edge-copies-overwrite-a-frame-word-another-copy-of-the-same-edge-still-reads)

**Related ADRs:** ADR-211, ADR-396

### Summary

On Windows 11 (Ryzen 9 5900HS) the XAX arm of `compiler/benchmarks/windows_chains` is behind a C twin with the same data layout (`chains_soa.c`, `gcc -O2`). The numbers are in `compiler/benchmarks/windows_chains_soa_evidence.json`.

### Current Findings

Found while looking for the cause, all measured with `xbench.exe` on that host:

1. **Frame slots that the inner loop reads and writes.** `_loop_parameter_slots` (`compiler/reference/xax_x86_64_regalloc.py`, and its native twin) gives a frame slot to a loop parameter that its block only forwards, when some block of the class is under register pressure. It asks for a loop made only of member blocks, and the outer lookup loop is one. It does not ask whether a non-member block on a deeper cycle uses the value: the walk's visit block increments `steps`, so every step loads and stores the slot. Win64 meets this where SysV does not, because the pressure limit is the length of the allocatable tuple: argument registers, one scratch, the result register and `CALLEE_SAVED`. That is 14 registers on Win64. On SysV `rsi` and `rdi` are in it twice (as argument registers and in `CALLEE_SAVED`), so the limit is 16 for the same 14 registers and the same loop is not counted as under pressure. The committed batch avoids it in the program: the block before the walk uses `steps` (`bit.or` with itself), and `found` is read by dominance instead of passed along.
2. **The prefetch pass matches one shape only.** `xax_prefetch.prefetch_next_iteration` (ADR-211) needs the raw bucket load among the arguments of the edge into the walk and the walk's first block on the cycle. A masked head (the mask proves the walk's loads in bounds, so they carry no check) or a walk entered at the visit block gets no prefetch. The committed batch passes the raw head in an unused parameter to keep it.
3. **Loop layout.** The backend closes the walk on the link test (`visit; advance; test; jne`), gcc on the key compare (`advance; test; je exit; visit; jne`). In one C program, gcc's own loop ran in 102 to 104 ms and the backend's order in 117 to 120 ms. A back edge that needs copies goes through an out-of-line stub: 123 to 133 ms against 108 to 110 ms inline, in the same test.
4. **Placement matters more than any of these.** The same instructions at another address differ by up to 25%: moving only the out-of-line stubs by 2 to 12 bytes (dead padding, loop bytes unchanged) took a C-hosted copy of the loop from 107-111 ms to 122-141 ms, and removing the stub from the hot path did not help (134 ms). The fast placements are not understood. A comparison on this workload therefore needs more than one build of each arm before a few percent can be called a lead.

> [!WARNING]
> **Correction (2026-11-13).** Item 1's explanation of why Win64 meets the slot rule and SysV does not is wrong. Every x86-64 target, Linux included, uses the same internal register set (`xax_compiler._x86_64_windows_target`: arguments rcx, rdx, r8, r9; the decoder rejects any other, `TARGET-WINDOWS-X64-REGISTERS`), so `allocatable` is the same 14 distinct registers on both ABIs and rsi and rdi are not counted twice on SysV. The frame slot in the Windows walk is real (seen in the code); why the Linux build of the same program avoids it is not established.

A related divergence, recorded so it is not lost: for PE frames over 4 KiB the reference still emits per-page stack probes (`xax_x86_64.py`, `_reserve_stack`), while the native backend relies on the committed 1 MiB reserve (ADR-396). A DLL export runs on its host's thread stack, which that header does not cover.

#### Static comparison with the 0043 seed (2026-11-26)

No timing; Windows 11, `llvm-objdump` of `chains.exe` beside `gcc -O2 chains_soa.c`.

- The 0043 Windows seed (`f95af786…`) builds the committed batch to the measured binary byte for byte (`90e48100…`),
  so `windows_chains_soa_evidence.json` still describes current code generation (EXECUTED).
- Item 1 is fixed by ledger 0033: without the `bit.or` workaround the walk has no frame slot and each lookup runs
  3 fewer instructions (EXECUTED: built, output `1048576 9437420`, disassembled; not measured).
- Per lookup the XAX code runs about 20 more instructions than gcc and 2 more taken branches:
  - `found` is a positional block parameter of the outer header (`r8`) and is pinned to `r14` in the body, so
    every lookup copies it in and out. The found exit (every lookup succeeds) leaves through an out-of-line stub:
    the mispredicted `je` goes to another cache line, then `jmp` to the header.
  - The outer header is not rotated (the test is at the top and the latch is a `jmp`): stubs and rotated copies
    never duplicate a header.
  - The mask puts an `and` on the dependent link chain; the Linux form uses a predicted compare instead.
  - The prefetch computes the next key a second time.
- These account for perhaps 10 to 20 cycles of the about 100 cycles per lookup that the 24% gap means. The hops are
  L3-latency bound in both arms, and the XAX arm has the prefetch that brought a C twin to 93-103 ms. The disassembly
  does not explain the gap; item 4 (placement) stays the leading hypothesis. Settling it needs measurement.

#### Re-measured with the 0043 seed (2026-11-26)

XAX_BENCHMARKS.md 15.41. The XAX arm is 1.12x to 1.17x the C twin over four runs. The batch without the `bit.or`
workaround, which has fewer instructions and no frame slot, is slower (1.17x, 1.22x). Loop alignment moves gcc's
build by under 7%. Item 4 now has XAX-built evidence: the XAX code is placement-sensitive in a way gcc's is not. An
instruction-count fix alone (sub-batches A and B) may not show up until the cause of that sensitivity is known.

#### Where the walk loses, by diagnostic (2026-11-27)

This is a C program hosting XAX's exact lookup instructions (inline assembly) beside gcc's. The two alternate in
one process, so each pair gives a ratio and machine drift cancels out. The sweep covers 8 placements and 48 pairs.
It is a diagnostic, not evidence. The values are median ratios, XAX's copy over gcc's lookup phase:

| XAX variant | Ratio |
| --- | ---: |
| as built | 1.25 |
| no mask on the link | 1.07 |
| bounds compare instead of the mask (the Linux form) | 1.20 |
| gcc's walk order (close on the key compare, found exit inline) | 1.13 |
| gcc's order, no mask | 0.99 to 1.01 |
| gcc's order, no mask, no prefetch | 1.10 |
| gcc's order, no mask, prefetch 2, 3, 4 nodes deep into the next lookup | 0.96, 0.90, 0.87 to 0.89 |
| the same at depth 4, key load masked (off the chain) | 0.915 |

Any extra operation on a hop costs about 15 to 20%, a predicted branch included. The 2026-11-26 estimate of 2%
for the mask was wrong. Placement moves the as-built copy by about 10%.

Program-side form (`compiler/benchmarks/windows_chains/chains_v4_request.batch`). Links hold byte offsets
(slot × 4). Keys are read at `cur × 2` from a 2^34-byte view and links at `cur × 1` from a 2^33-byte view, both
reserved with `PAGE_NOACCESS` and committed on touch by the hosting layer's handler (ADR-400). Every 32-bit link
is then in bounds: no mask and no check, and the ADR-211 prefetch still matches. Measured (XAX_BENCHMARKS.md
15.42): 1.13x and 1.18x the fastest arm, against 1.14x and 1.22x for the committed batch. That is not a lead.

What the lead needs (compiler, release 0045):
- (a) the ADR-211 prefetch followed 3 or 4 links into the next lookup's chain. The added loads are in bounds by
  the view widths above.
- (b) a walk layout that closes on the key compare and keeps the found exit inline (the rotation rule).
- (c) `mul.wrap(x, 1)` emitted as `shl r, 0` on the link chain (a missing peephole).

Found on the way (native, 0043 seed). A batch that supplies a heap-view type equal to one the store already holds
(instances 2^25, 2^30, 2^31 in `bbc_request.xax`), or one of instance 2^35, makes `resolve` and `verify` decline
with no record, or reject with `XAX.CANON.TRUNCATED`. The reference verifier accepts the same store.

#### Measurements with workarounds

With items 1 and 2 worked around in the program, the XAX arm went from about 134-155 ms to about 121-136 ms (two runs).

| Arm | Time |
| --- | ---: |
| XAX, before workarounds | about 134-155 ms |
| XAX, with items 1 and 2 worked around | about 121-136 ms |
| rustc | 134-142 ms |
| C twin | 105-112 ms |
| C twin with the same prefetch written by hand | 93-103 ms |

#### Not established

- Why some placements are fast.
- Whether the Linux row's `chains` result (OI-37) has the same sensitivity.
- Whether a deeper prefetch (the next lookup's second and third node; 8 to 15% in a C prototype) holds on other processors.

### Closure Criteria

- [ ] Native transactions (with the reference following) for the slot rule at least.
- [ ] The workload batch without its two workarounds.
- [ ] A recorded comparison in which the XAX arm leads every arm including `chains_soa.c`, repeated over more than one placement of each arm.

### References

- `compiler/benchmarks/windows_chains`
- `compiler/benchmarks/windows_chains_soa_evidence.json`
- `chains_soa.c`

## OI-59 — Edge copies overwrite a frame word another copy of the same edge still reads

**Status:** CLOSED (2026-11-24)

**Related ADRs:** ADR-398

**Related Issues:** [OI-57](#oi-57--the-references-s12c2-analysis-audit-disagrees-with-the-native-basics-since-ledger-0022), [OI-58](#oi-58--windows-x86-64-code-generation-on-the-chains-walk-r4-blocker-for-windows-x86_64-pe)

### Summary

Both x86-64 register-path emitters, `copy_edge` in `compiler/reference/xax_x86_64_regalloc.py` and the native general backend's (in `bootstrap/xax_x86_64_general.xax` and the driver), copy an edge's arguments in two phases: first every argument whose destination is a frame word (a loop-parameter slot or an edge spill slot), then the register destinations, register sources in parallel and memory sources afterwards. Nothing orders a frame store against a later read of the same word.

Edge spill slots (`edge_spill_base + (index - allocatable) * 8`) are shared by every block's parameters past the allocatable registers. So when the source block keeps such a parameter in slot k and the target block's parameter k gets another argument, the first phase overwrites the word before a later move reads it.

### Decision

Ledger 0027 is in both seeds and BBC's driver since 2026-11-13 and on `main`.

### Evidence and Measurements

The native compiler returns the executor's result on the whole family (`XAX_STATE.md` 2026-11-13, ledger 0027 correctness, EXECUTED), which completes "Closure Criteria". OI-58 item 1 can be retried.

### Closure Criteria

- [x] The same staging as a native transaction on the x86-64 backend, driver and request stores, both seeds and BBC rebuilt, and the native compiler equal to the executor on the same family.

The original adds that OI-58 item 1 can now be retried; that follow-up is tracked in OI-58.

### References

- `compiler/reference/xax_x86_64_regalloc.py`
- `bootstrap/xax_x86_64_general.xax`
- `XAX_STATE.md` 2026-11-13

<details>
<summary>Historical Record</summary>

#### 2026-11-13: FIXED (reference b137b66, native ledger 0027 (ADR-398), both seeds and BBC rebuilt)

Found from nested loops that carry many values: with 8 or fewer allocatable registers (a caller that pins several loop counters, or inlined copies), 1 to 9 of 40 random programs of that shape return wrong results. The smallest traced case is a five-block function (two loops, 10 parameters per loop block, 8 registers): on the edge into the exit block the copy stores the ninth argument into `[rsp+0x20]` and then loads the eighth from `[rsp+0x20]`.

Earlier text of this issue (2026-11-13, first version) is corrected here: its "reference" results came from `compile_linux_executable` in its default mode, which runs the native general backend. The fault is in both. The committed production compiler builds those programs wrong too; the one case it built correctly differs only by its own slot decisions. Ledger 0027 (not committed) made the fault reach the compiler's own Ed25519 code.

#### 2026-11-13: reference fix

Before the first phase, every source in a frame word that the edge also writes (to another value) is copied to a free dynamic spill slot and read from there; the slot is returned after the edge. The frame already counts dynamic spill slots and `rsp` does not move. With it the reference returns the executor's result for every program of the family (0 of 40 for each of seven shapes, before 1 to 9). The x86-64 general-backend comparison tests are unchanged (the 7 failures of `test_xax_selfhost_general_view.py` are OI-57's, with and without the fix).

#### Closing evidence as stated at that time

The same staging as a native transaction on the x86-64 backend, driver and request stores, both seeds and BBC rebuilt, and the native compiler equal to the executor on the same family; then OI-58 item 1 can be retried.

</details>

## OI-60 — Host-portability gaps left after the 2026-11-13 audit

**Status:** CLOSED (2026-11-25). The ledger, request, release, evidence, hosting and status tools run on the Windows seed, `selfbuild.sh` rebuilds the Windows seed from itself there, and tests run Windows-seed commands against the pin. The remaining findings below are not closure criteria.

**Related Issues:** [OI-58](#oi-58--windows-x86-64-code-generation-on-the-chains-walk-r4-blocker-for-windows-x86_64-pe)

### Summary

A read-only audit of the tracked repository for Linux-host assumptions found the compiler itself host-neutral: one XAX program on both hosts; the x86-64 allocator and emitter are shared, with five small ABI guards; ELF and PE writers are separate modules; `sys.platform` only picks the test harness.

- The checkout collision of `bootstrap/evolution/LEDGER` with the ledger program's directory is fixed (the directory is now `ledger-tool/`, 43054ce).
- `*.sh`, `*.batch` and `LEDGER` keep LF on every host.

### Current Findings

Left open, each needing either a native tool or new test glue that the language rule does not allow in Python:

- `rotate.sh build`, `confirm` and `evidence/run.sh` still run on Linux x86-64 (they drive the Linux seed's generations; the
  Windows confirm runs the Windows seed through WSL interop).
- No test exercises the Windows seed (`compiler/bootstrap/windows`), and the seed tools pin the Linux seed only.
- About 130 test modules gate on Linux x86-64 although several only call seed commands.
- `benchmarks/linux_harness.py` reads `/proc/cpuinfo` without a fallback (the other three benchmark readers have one).
- The reference emits per-page stack probes for PE frames over 4 KiB, the native backend does not (OI-58 note).

### Closure Criteria

- [x] A native ledger tool and seed check that run on the Windows seed (2026-11-25).
- [x] One test that runs a Windows-seed command against its pin (2026-11-25: `test_status_docs.py` on Windows).

<details>
<summary>Historical Record</summary>

#### 2026-11-25: CLOSED — the seed check on the Windows seed

The release tool (`seed/rotate-tool`), the evidence tool and the Windows generator's hosting tool got the same
driver-shaped `main` (`driver.batch` each; every output byte for byte the previous tool's). `generate.sh` now runs on
Windows with the Windows seed (the compiler's Windows request byte for byte, `0ee68b3c…`, 296 s), so `selfbuild.sh` does
there: EXECUTED on Windows 11, the Windows seed rebuilt itself twice and `xaxc1.exe`, `xaxc2.exe` and the pinned seed are
all `4d361a39…` (720 s). `rotate.sh state` and `status.sh` (bootstrap block included) run there too; on Windows
`test_status_docs.py` 6 passed, `test_rotate_tool.py`, `test_xax_selfhost_evolution.py` and `test_status_docs.py` 10
passed. Both closure criteria are met.

#### 2026-11-25: the ledger tool runs on the Windows seed

`ledger-tool/xax_ledger.xax` has the driver's entry (`driver.batch`) and `generate.sh` hosts it
(`xax_ledger_windows.xax`; the hosting tool's entry lookup was fixed for it, `entry.batch`). Every command gives the
previous tool's output byte for byte (14 cases, WSL 2). On Windows 11 with the Windows seed, EXECUTED:
`evolve.sh check` passes (2 s), `evolve.sh replay xax_jvm_general.xax` replays 7 of 7, and three tests in
`test_xax_selfhost_evolution.py` pass. The same day the request tool followed (`request-tool/driver.batch`,
`xax_request_windows.xax`): on Windows it writes the committed compiler request byte for byte, so `evolve.sh check`
derives and compares it there too (4 s), and four Windows tests pass. `evolve.sh apply` was not run on Windows. The first
closure criterion still needs a seed check there.

#### 2026-11-25: the status tool runs on the Windows seed

The status tool's main is driver-shaped, so `windows/generator/generate.sh` hosts it (`xax_status_windows.xax`). On
Windows 11, `test_status_docs.py` checks the Windows seed against the `RELEASES` pin and runs the levels, targets and
rewrite cases with it (EXECUTED: 4 passed; the repository and bootstrap cases stay Linux-only). On Linux the file and
`test_windows_generator.py` pass (9 passed, 1 skipped).

#### 2026-11-25: the two developer paths removed

`bootstrap/evolution/native/0023/all.sh` finds the seed beside its own directory (or `XAXC`), and BBC's
`tools/check.py` requires `--bbc <BBC checkout>` instead of defaulting to a developer's home directory. The
2026-11-13 list had also named "benchmark harnesses" for `/proc/cpuinfo`; only `linux_harness.py` lacks a fallback.

</details>

## OI-61 — The JVM program does not check a catching call's throwable output type

**Status:** CLOSED (2026-11-24)

**Related ADRs:** ADR-406, ADR-409

### Summary

ADR-406 (2) makes a catching JVM declaration's last output `jvm-ref:Ljava/lang/Throwable;`. The XAX JVM program (`jk_member`, F38 of `xax_jvm_general.xax` and its copies in `xax_android.xax` and the driver) takes one off the output count for a catching ABI (ledger 0036 d) but does not compare that output's type text.

A declaration with another reference type there lowers to a class whose handler stores a `Throwable` into a local of that type, and the JVM or ART rejects the class at load (`VerifyError`). No program runs with a wrong value.

### Decision

Release 0037 (ledger 0037 `jvm-throwable`, PR #104) is on `main`: the three stores reject such a declaration and the rejection test passes.

### Evidence and Measurements

The rejection test fails 6 of 6 on the stores before the fix (`XAX_STATE.md` 2026-11-18, EXECUTED).

### Closure Criteria

- [x] A transaction on the three stores that rejects such a declaration with `JVM-FOREIGN-ARITY` (or a new diagnostic), and a test that builds one and gets the rejection.

### References

- `XAX_STATE.md` 2026-11-18

<details>
<summary>Historical Record</summary>

#### 2026-11-18: FIXED on `release/0037` (PR #104, ledger 0037 `jvm-throwable`); closes when release 0037 reaches `main`

Fixing it is one more transaction on F38 (about 45,600 view lines) in three stores, outside the DEX change of ADR-409, so it was left for the C-cap step of release 0036.

</details>

## OI-62 — The legacy Wasm32 profile emits an invalid module for a `bits<64>` checked offset

**Status:** CLOSED (2026-11-24). Release 0042 (ledger 0042 `legacy-wasm-offset-bits`, PR #158) is on `main` (#171), with its seeds rotated and validated.

**Related ADRs:** ADR-412

**Related Issues:** [OI-52](#oi-52--64-bit-checked-offsets-and-growable-views-roadmap)

### Summary

Since OI-52 R2 (ADR-412) a checked offset may be `bits<64>`. The general Wasm32 profile lowers it (`i64.gt_u`, then `i32.wrap_i64`), but the legacy profile that `oi06_wasm32_target` and other targets without the general operations select (`xax_wasm_legacy.py`; in the driver, the per-node lowering F784 as of `release/0038` after #126) pushes the `i64` local and compares it with `i32.const` and `i32.gt_u`.

Wasm validation rejects the module (`i32.gt_u[0] expected type i32, found local.get of type i64`), so no program runs with a wrong value, but the compiler should reject the program instead of emitting the module.

### Resolution

`0042-legacy-wasm-offset-bits` routes the legacy lowering's offset `local.get` (F786 by sorted CID in the 0041 driver) through a new `@g225`. It reads the offset's width the way the general profile does (the value's type, then the type's body) and rejects a width above 32 with `XAX.WASM.CHECKED_OFFSET` / `WASM-CHECKED-OFFSET-BITS` (expected 32, actual the width), written as F225 writes its own records. The reference (`xax_wasm_legacy.py`) rejects the same way at the same point. A `bits<32>` offset keeps its module bytes.

### Closure Criteria

- [x] A transaction on the driver that rejects such a program for the legacy profile with `WASM-CHECKED-OFFSET-BITS` (ledger 0042, PR #158).
- [x] The same rejection in the reference.
- [x] A test that builds one and gets it: `test_xax_oi52_r2.WasmTests.test_legacy_profile_rejects` compares the reference's diagnostic with the production compiler's `build`. It fails with the 0041 seed and passes with the 0042 seed (EXECUTED 2026-11-24, WSL 2).

<details>
<summary>Historical Record</summary>

#### 2026-11-23: FIXED on `release/0042` (ledger 0042); closes when release 0042's seed is rotated

The fix as recorded on the release branch; see Resolution above.

#### 2026-11-19: OPEN (planned fix)

The legacy lowering decodes each type's width inline from its body. The native fix copies the general profile's width lookup (F112's blocks before its `i64.gt_u` choice) into F784's checked-access case and rejects when the offset's width is not 32, with a `WASM-CHECKED-OFFSET-BITS` diagnostic in the Wasm renderer (F589). The Python legacy reference rejects the same way.

</details>

## OI-63 — Canonical index acceleration for large stores

**Status:** OPEN (2026-11-24)

### Summary

The mandatory sorted CID index is sufficient for deterministic lookup. An additional canonical acceleration structure should be added only if large-store measurements show a material benefit greater than its byte and implementation cost. Any such structure remains non-semantic.

Recorded on 2026-11-24 from [`docs/08_SERIALIZATION_IDENTITY.md`](docs/08_SERIALIZATION_IDENTITY.md#222-index-acceleration) §22.2, an open question of that stage that no register record tracked.

### Fixed Constraints

- The sorted CID index stays mandatory and sufficient for deterministic lookup.
- Any acceleration structure is non-semantic: it never changes a CID or the meaning of a store.

### Closure Criteria

- [ ] Large-store lookup measurements that compare the sorted index with a candidate acceleration structure, with the candidate's byte and implementation cost, `MEASURED`.
- [ ] A decision: adopt the structure (as a versioned container feature) or record that the sorted index stays sufficient.

### References

- [`docs/08_SERIALIZATION_IDENTITY.md`](docs/08_SERIALIZATION_IDENTITY.md#222-index-acceleration) §22.2.

## OI-64 — Semantic rebase granularity for concurrent agents

**Status:** OPEN (2026-11-28), linked to [MrxSiN/XAX-MCP#8](https://github.com/MrxSiN/XAX-MCP/issues/8), where the measurement runs. The decision on the default rebase granularity stays here as an ADR; this record closes with that ADR. The earlier status line follows.

**Status:** OPEN (2026-11-25): a measurement design is proposed below; nothing is run. Recorded 2026-11-24.

### Summary

The correct balance between whole-root compare-and-swap, entity-level preconditions, and explicit read-set validation requires implementation experience with concurrent AI agents.

Recorded on 2026-11-24 from [`docs/09_AI_PROTOCOL.md`](docs/09_AI_PROTOCOL.md#134-semantic-rebase-granularity) §13.4, an open question of that stage that no register record tracked.

### Fixed Constraints

- Commits stay atomic against `expected_root`; no rebase may publish a verifier-invalid or partially applied candidate ([`docs/09_AI_PROTOCOL.md`](docs/09_AI_PROTOCOL.md) §5).

### Measurement design (proposed, 2026-11-25)

Not run:

- Policies: whole-root compare-and-swap (today's `expected_root`), entity-level preconditions (each mutation's old
  fields, as the workspace already checks), and read-set validation (the entities a batch read must be unchanged).
- Load: 2, 4 and 8 concurrent agents on one store, each with an independent task stream from the OI-01 task set;
  conflicts arise naturally from shared callees and types.
- Per policy: commit conflicts, retries, repair turns after a conflict, wasted tokens, and whether any committed root
  fails `verify` (must be zero for every policy).
- Trials: 3 per policy and agent count.
- Decision rule (ADR): the finest policy whose wasted-work saving is larger than the trial spread and that never
  publishes an invalid root; otherwise whole-root compare-and-swap stays.
- Needs the owner: ADR-207 defers AI-efficiency work, so nothing here runs until the owner approves the design and
  the model budget. No agent runs these trials on its own initiative.

### Closure Criteria

- [ ] Measurements of conflict, retry and repair rates for concurrent agents under whole-root compare-and-swap, entity-level preconditions and read-set validation, `MEASURED`.
- [ ] A decision on the default granularity, recorded as an ADR.

### References

- [`docs/09_AI_PROTOCOL.md`](docs/09_AI_PROTOCOL.md#134-semantic-rebase-granularity) §13.4.

## OI-65 — Scheduling-resource detail in target packages

**Status:** OPEN (2026-11-24)

### Summary

Micro-operation-level models may improve code quality but increase package size and maintenance cost. The necessary granularity must be determined experimentally.

Recorded on 2026-11-24 from [`docs/10_TARGET_MODEL.md`](docs/10_TARGET_MODEL.md#20-open-issues-requiring-implementation-evidence) item 5 of §20, an open question of that stage that no register record tracked.

### Fixed Constraints

- Scheduling data is target-package data; it does not change program meaning.

### Closure Criteria

- [ ] Code-quality and package-size measurements of at least two scheduling-model granularities on one target, `MEASURED`.
- [ ] A decision on the granularity target packages use, recorded as an ADR.

### References

- [`docs/10_TARGET_MODEL.md`](docs/10_TARGET_MODEL.md#20-open-issues-requiring-implementation-evidence) item 5 of §20.
