# XAX AI Workspace, Query, Transaction, Diagnostic, and Token Protocol

## 1. Purpose and scope

This document specifies the AI-facing interaction model for XAX. It defines how an AI reasoning system observes, queries, modifies, verifies, and commits changes to an authoritative XAX semantic program without regenerating the canonical `.xax` artifact or depending on human-oriented source text.

The protocol minimizes **model tokens per successful semantic change** while preserving exact semantics, local modification, conflict detection, and machine diagnostics. The workspace is a bounded transactional view over the canonical semantic graph.

This stage defines:

- semantic workspaces and minimal-context retrieval;
- local short handles and persistent identities;
- semantic queries;
- transactional graph mutation;
- concurrent-agent conflict detection;
- machine-first diagnostics and deterministic repair locality;
- token-native protocol objectives;
- provisional fallback wire forms for current tokenizers;
- token/context accounting;
- interfaces to serialization, verification, target, optimization, artifact, and package subsystems.

This stage does **not** define a programming language, source syntax, optimizer or lowering implementation, or final wire encoding. Textual notation here is non-authoritative tooling. The canonical semantic graph remains authoritative.

---

## 2. Normative language

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**, **SHOULD NOT**, and **MAY** are normative.

### 2.1 Core definitions

| Term | Normative definition |
|---|---|
| **persistent identity** | Content-derived or otherwise canonical identity used in the persistent XAX object graph. Normally represented by a cryptographic hash or compact canonical reference to one. |
| **workspace** | An ephemeral AI-facing view over one base program root, selected entities, derived facts, local handles, and zero or more uncommitted transactions. |
| **workspace root** | The persistent program root against which workspace facts and transaction preconditions are interpreted. |
| **local handle** | A short workspace-scoped identifier for an entity or derived object. A local handle has no persistent meaning outside its workspace binding. |
| **entity** | A semantic object addressable by the workspace, including modules, functions, blocks, operations, values, types, constants, resources, targets, artifacts, packages, and graph fragments. |
| **use** | A semantic dependency from one entity to another, including operand use, control transfer, effect dependency, type reference, resource dependency, metadata reference, or other explicitly typed relation. |
| **query** | A read-only request for semantic or derived information. Queries MUST NOT mutate the canonical program. |
| **mutation** | A requested semantic change expressed against entities, relations, or attributes. |
| **transaction** | An ordered or dependency-constrained set of mutations with an expected base root and atomic verification/commit semantics. |
| **diagnostic** | Structured machine data describing a violated rule, failed precondition, invalid graph state, or rejected transaction. |
| **repair neighborhood** | The smallest deterministic semantic neighborhood sufficient to explain and potentially repair a diagnostic under the verifier's dependency model. |
| **token-native form** | A protocol representation designed jointly with a model vocabulary so frequent semantic operations and references can consume minimal model tokens. |
| **fallback transport** | A compact non-authoritative transport used when the model tokenizer cannot provide dedicated XAX tokens. |
| **artifact mapping** | A relation between semantic entities and emitted or derived artifacts such as object sections, machine-code ranges, relocations, debug views, test observations, or profile records. |

### 2.2 Separation of identities

A workspace MUST distinguish:

1. persistent identity;
2. workspace-local handle;
3. transaction-local temporary handle.

Persistent identities are suitable for storage, deduplication, Merkle-DAG references, synchronization, and stale-root detection. They are usually inefficient for AI context.

Workspace-local handles MUST be short, dense, and scoped to a workspace generation. A workspace MAY bind:

```text
F0 -> persistent function identity
B0 -> block within F0
N0 -> operation within B0
T0 -> type
V0 -> SSA value
```

A transaction MAY introduce temporary handles before persistent identities exist:

```text
+n0 = add.wrap ...
+n1 = ...
```

Temporary handles MUST become invalid after rollback or failed commit unless explicitly rebound by a later transaction.

Local handles MUST NOT be interpreted as canonical serialization fields.

---

## 3. Semantic workspace model

### 3.1 Workspace state

A workspace is conceptually:

```text
Workspace {
    id
    base_root
    generation
    bindings
    selected_entities
    cached_facts
    active_transactions
    accounting
}
```

`base_root` identifies the exact canonical program state. `generation` changes when handle bindings are invalidated or rebound; incompatible-generation handles MUST be rejected. `bindings` map handles to entities or derived objects. `cached_facts` MAY contain verifier-derived type, effect, layout, ownership, use, cost, or invalidation information and are invalid when their dependencies are stale.

### 3.2 Minimal-context principle

The workspace MUST support task-local retrieval rather than whole-program presentation.

The default retrieval rule is:

> return the smallest semantic neighborhood that completely answers the query under the declared query mode.

A query SHOULD return identifiers and compact facts before full entity bodies. Expansion is explicit. For example, `callers F3` may return only `[F8@N2, F12@N7, F91@N1]`, after which the AI expands selected call sites.

A workspace SHOULD support bounded expansion by:

- edge kind;
- direction;
- depth;
- entity count;
- semantic region;
- effect domain;
- dominance region;
- ownership/resource dependency;
- target dependency;
- diagnostic dependency;
- estimated token budget.

If a complete answer exceeds the budget, the response MUST indicate truncation and provide a continuation mechanism without pretending completeness.

### 3.3 Deterministic views

For the same program root, query parameters, target facts, and verifier version, query results that claim determinism MUST have deterministic ordering and deterministic identity.

Presentation compression MAY vary only when it does not change semantic interpretation.

---

## 4. Query interface

Queries are read-only. They MAY request authoritative facts, verifier-derived facts, optimizer-derived estimates, target-derived facts, or artifact mappings. Every derived result MUST be attributable to a dependency set or versioned subsystem.

### 4.1 Core query families

| Query | Required result |
|---|---|
| `entity(x)` | Kind, persistent identity, local handle, owning region, and compact semantic summary. |
| `expand(x, fields)` | Requested semantic fields of `x`. |
| `users(x, kinds?)` | Semantic uses of `x`, classified by relation kind. |
| `operands(x)` | Direct semantic operands/dependencies of `x`. |
| `callers(f)` | Call sites that may invoke `f` under the requested resolution mode. |
| `callees(f)` | Direct or resolved callees reachable from `f` under the requested mode. |
| `type(x)` | Exact type and relevant type dependencies. |
| `effects(x)` | Effect domains, effect edges, capabilities, and waived obligations attributable to `x`. |
| `layout(t, target)` | Target-dependent size, alignment, field placement, ABI classification, and unresolved layout conditions. |
| `cost(x, target, objective)` | Target cost estimate plus cost-model identity and assumptions. |
| `invalidate(change)` | Derived facts and semantic objects that would become stale if the hypothetical change occurred. |
| `map_semantic(x, artifact)` | Artifact ranges/records attributable to semantic entity `x`. |
| `map_artifact(a, offset/range)` | Semantic entities contributing to an artifact location. |
| `root()` | Current workspace base root and canonical identity metadata. |
| `diff(a, b, scope)` | Semantic differences between roots or entities, not line differences. |
| `proof(x, rule)` | Proof status, obligations, evidence references, and dependencies for a verifier rule. |
| `neighborhood(x, selector)` | Bounded semantic neighborhood selected by typed relations. |

### 4.2 Query result requirements

A query result MUST distinguish authoritative facts, derived facts, estimates, unavailable or unknown facts, and stale facts. Target-cost estimates MUST NOT be presented as measured performance unless explicitly backed by measured profile data. Target-dependent queries MUST identify their target package. `users` results MUST preserve relation kinds.

Artifact mapping results are derived facts keyed by the exact root, target/configuration, compiler/lowering identity, and artifact identity. A mapping binding SHOULD expose a compact artifact identity that commits to those dependencies plus the artifact digest and retained exact ranges; artifact inspection MAY expose the individual dependency identities needed to audit that binding. Compiler/lowering identities are explicit versioned tooling identities and MUST NOT be inferred from human-readable diagnostic text or disassembly. Any dependency mismatch makes the binding stale. Byte intervals are half-open `[start,end)`. Exact mappings SHOULD be recorded while emitting/lowering the artifact; tooling MUST NOT reverse-infer authoritative provenance from nearby instructions when that provenance was not retained. Semantic entities that erase or influence code non-locally MAY have no exact contiguous range and MUST then be classified unavailable/unknown. `map_artifact` returns all exactly known contributors within the declared bounds, using generation-local semantic handles. Artifact and mapping handles are workspace-local, generation-scoped tooling and participate in read-set/staleness rules when exposed as read dependencies. The query/result contract is target-neutral: raw machine-code images and structured containers such as WebAssembly modules use the same mapping semantics, while target-specific byte layout remains derived backend data.

`proof` results are verifier-status evidence, not canonical proof artifacts. If a workspace makes a reported proof fact reusable as a transaction read dependency, it SHOULD expose a compact local proof-dependency handle while privately retaining the exact semantic subject, observed root, verifier identity/version, and required freshness scope. The handle MUST NOT be a persistent semantic identity. Subject-scoped proof dependencies may survive unrelated commits only when the exact content-addressed subject and verifier identity remain unchanged; root-scoped dependencies invalidate on any root change. A dependency-changing commit permanently invalidates that local proof handle even if later edits restore equivalent root bytes.

### 4.3 Invalidation queries

`invalidate(change)` is advisory and read-only. It reports dependencies that would become stale under a hypothetical mutation.

Conceptually:

```text
invalidate set N3.op = mul.wrap
=> {
    semantic: [N3],
    verify: [N3, B1, F2],
    cost: [F2],
    artifacts: [A7],
    callers: []
}
```

Dependency classes MUST be machine-readable.

---

## 5. Transaction model

### 5.1 Atomic structure

Every mutation of the canonical program MUST occur within a transaction.

A transaction contains:

```text
Transaction {
    expected_root
    optional_read_set
    mutations
    requested_checks
    commit_policy
}
```

`expected_root` is REQUIRED for canonical commit.

A workspace MAY use a compact generation-scoped local root handle as a transport abbreviation for `expected_root`. The handle is not semantic identity. Its generation/freshness scope MUST be checked again at the final atomic comparison, so an intervening change followed by restoration of identical root bytes does not revive a stale handle.

The canonical commit sequence is:

```text
open(base_root)
-> apply mutations to private candidate state
-> validate mutation preconditions
-> verify required invariants
-> derive new persistent objects
-> compute candidate root
-> atomically compare expected_root
-> commit candidate root
```

If the expected root is stale, canonical commit MUST fail without partially applying mutations.

### 5.2 Mutation operations

The semantic mutation vocabulary MUST include the following operations. Exact binary opcodes remain implementation-defined.

| Operation | Semantics |
|---|---|
| `insert` | Create a new entity in a specified semantic container or relation position. |
| `delete` | Remove an entity if all required uses, ownership obligations, control obligations, and container invariants remain valid or are changed in the same transaction. |
| `replace` | Replace one entity or value with another under explicitly checked compatibility rules. |
| `connect` | Create a typed semantic relation or edge. |
| `disconnect` | Remove a typed semantic relation or edge. |
| `set` | Change a mutable semantic attribute of an entity in candidate state. |
| `move` | Change containment or permitted ordering without silently changing dependencies. |
| `specialize` | Request semantic specialization under explicit compile-time arguments or conditions, producing candidate specialized entities. |
| `verify` | Run requested verifier scopes/checks against candidate state without committing. |
| `commit` | Atomically publish candidate state if all required preconditions and verification rules succeed. |
| `rollback` | Discard the uncommitted candidate state and all transaction-local handles. |

Candidate-only `verify` is a workspace service boundary, not an alternate source representation. The bootstrap service may return a generation-scoped local handle such as `C0.0` only after the private candidate passes the same root/read/local-precondition checks and ordinary verifier used before commit. The response exposes verification/accounting facts, not candidate CIDs. Canonical root/generation remain unchanged, and transaction-local inserted-result identities remain private to candidate construction. `rollback(C...)` discards that private state only; repeated/unknown rollback is a structured candidate-handle failure. Any successful canonical commit invalidates outstanding candidate handles instead of rebasing them implicitly. Candidate verification MUST reject stale ordinary/proof/artifact dependencies and MUST NOT refresh them.

`move` MUST NOT imply data-flow, control-flow, ownership, or effect rewiring unless those relations are explicitly included in the transaction or are defined as deterministic consequences of the moved container relation.

For graph nodes, a bootstrap `move` may use an exact source block/node precondition plus an existing destination node as an insert-before anchor with exact block/node coordinates. Source or anchor drift is a containment conflict. Surviving graph-local value references are remapped by producer identity when node numbering changes; they are not left pointing at the old numeric position. Same-block pure-node move legality after remapping is decided by the ordinary verifier, so a reorder that places a use before its producer is rejected as SSA dominance failure with no publication. Self-anchor and unsupported cross-function/cross-block moves reject before publication. Typed carriers such as `MovePureNode` are tooling data only.

`replace` MUST specify what relation class is replaced when ambiguity exists. Replacing a value use is not the same operation as replacing an operation entity. A value-use replacement carries the containing operation, operand position, expected old value reference, and replacement value reference; mismatch of the old relation is a relation conflict, while an incompatible replacement is rejected by ordinary semantic verification. Bootstrap host-language structures used to carry this request are tooling only, not an authoritative mutation syntax.

`delete` MUST carry an exact containment precondition for the entity being removed. A graph-node deletion rejects as a containment conflict if the expected block/node relation no longer matches, and rejects as a delete/use conflict if a surviving operand, terminator value, or control-edge argument still references a produced value. Any node-index renumbering caused by deletion is a deterministic representation update, not an implicit semantic rewiring. The candidate is verified before publication. Bootstrap carriers such as a typed `DeleteNode` structure are tooling only.

`insert` MUST identify an exact semantic container/relation position and carry enough local precondition data to detect position drift before publication. A bootstrap graph insertion may use an existing node handle as an insert-before anchor plus expected block/node coordinates. Node-index changes caused by insertion are deterministic representation remapping, not hidden rewiring. When a later mutation in the same transaction consumes the new result before persistent identity exists, it uses a transaction-local temporary handle/reference; that temporary identity is discarded at commit/rollback and never becomes XAX source. The candidate is verified normally after all transaction-local references are resolved. Bootstrap carriers such as typed `InsertPureNode` / `TransactionValueRef` structures are tooling only.

For a block-terminator edge argument, `disconnect` identifies the containing block, edge index, argument index, and exact expected old value relation. `connect` identifies the same relation position plus the new graph-local or transaction-local value. Drift in the containing block/edge position is a containment conflict; argument-index or expected-old-value drift is a relation conflict. A disconnect that would leave the completed candidate invalid does not publish. A same-transaction disconnect+connect is applied only to private candidate state, after which the ordinary graph verifier decides branch-argument type/arity and SSA-dominance legality. Bootstrap carriers such as `DisconnectEdgeArgument` / `ConnectEdgeArgument` are typed tooling data, not XAX source or a permanent edit DSL.

`specialize` MUST not be a textual macro substitution. It is semantic construction and compile-time evaluation using XAX semantics.

The M6 bootstrap MAY expose a narrower tooling-only specialization request before the general compile-time evaluator exists: clone one already verified standalone straight-line pure function under explicit constant parameter arguments, verify the clone through the ordinary semantic verifier, and publish it without changing the source or callers. This is implementation evidence for the workspace transaction boundary, not META conformance or a second specialization language.

### 5.3 Mutation preconditions

Mutations MAY carry local preconditions such as:

```text
set N0.op = mul.wrap
if N0.op == add.wrap
if type(N0.result) == T4
```

Local preconditions reduce accidental edits and enable conflict detection below whole-root granularity. If a transaction declares a semantic read set, commit MUST fail when any read-set dependency changes incompatibly.

Proof-dependency reads are validated separately from ordinary entity handles. A stale proof read MUST produce a proof-dependency conflict rather than a generic missing/stale-handle conflict. Proof reads MUST be rechecked at final atomic publication so an intervening dependency change followed by root-byte restoration cannot revive an invalidated local proof handle. A currently valid proof dependency may be consumed by a transaction that changes its subject; after publication, that old dependency is no longer reusable unless its required subject/verifier dependencies were provably preserved.


### 5.4 Verification policy

A transaction MUST NOT commit a candidate graph that violates canonical XAX invariants.

A transaction MAY request stronger checks than the minimum commit rules, including whole-function, ownership/resource, effect, target-legality, compile-time determinism, equivalence, cost-regression, or artifact-regeneration checks. Failed verification produces diagnostics and leaves the canonical root unchanged.

---

## 6. Concurrent AI agents and conflict detection

Concurrent agents MUST NOT resolve conflicts by line-based merge because no normative source lines exist.

Conflict detection operates on semantic entities, relations, attributes, and dependency assumptions.

### 6.1 Conflict classes

At minimum, the transaction system MUST distinguish:

| Conflict | Example |
|---|---|
| identity/root conflict | transaction expected root `R1`, canonical root is `R2` |
| attribute conflict | two agents change `N0.op` incompatibly |
| relation conflict | one agent disconnects an edge another assumes |
| delete/use conflict | one agent deletes an entity another newly references |
| containment conflict | incompatible moves of the same entity |
| proof dependency conflict | a proof relied on a fact changed by another commit |
| artifact dependency conflict | a requested artifact mapping is stale after semantic change |

Changes to disjoint entities SHOULD be mergeable when dependency analysis proves they do not invalidate each other's assumptions.

### 6.2 Semantic rebase

After a stale-root failure, tooling MAY offer semantic rebase. Rebase is not blind replay.

For each mutation, rebase MUST confirm that the target still exists, relevant attributes/relations and read-set assumptions remain compatible, handles can be rebound deterministically, and local preconditions still hold. Otherwise it MUST return a structured conflict diagnostic.

---

## 7. Machine-first diagnostics

Diagnostics are structured program data. Natural-language explanation is optional presentation generated for humans and is not required by the AI protocol.

### 7.1 Diagnostic schema

Every verifier or transaction diagnostic SHOULD use the following core shape:

```text
Diagnostic {
    code
    entity
    rule
    expected
    actual
    dependencies
    repair_neighborhood
    severity
    phase
}
```

`code`, `entity`, `rule`, `expected`, `actual`, `dependencies`, and `repair_neighborhood` are required. Optional fields MAY include candidate repairs, proof traces, target identity, transaction operation index, or artifact mapping.

### 7.2 Deterministic repair locality

For the same candidate graph, verifier version, target package, and rule configuration, the core repair neighborhood MUST be deterministic.

Repair neighborhoods SHOULD follow typed dependency relations and include only what is needed to establish the rule, expose conflicting requirements, identify valid repair boundaries, and support bounded expansion. Diagnostics MUST NOT dump whole functions or modules merely because a failure occurs within them.

### 7.3 Example

Diagnostic notation is provisional:

```text
D17 {
  code: E_TYPE_OPERAND
  entity: N4
  rule: add.same_width
  expected: bits<64>
  actual: bits<32>
  dependencies: [N4.arg1=V8, type(V8)=T2]
  repair: [N4, V8, T2, users(V8)]
}
```

This notation is a tooling view, not XAX source.

---

## 8. Token-native protocol

### 8.1 Objective

The primary protocol metric is:

```text
total model tokens consumed
---------------------------
successful semantic change
```

The accounting boundary SHOULD include all model-visible protocol traffic required to complete a change:

- query input;
- query output;
- mutation request;
- diagnostics;
- repair queries;
- repaired mutation;
- verification response;
- commit response.

A shorter packet that causes more invalid transactions can be worse than a slightly larger packet that completes in one pass.

### 8.2 Minimal-token execution policy

An AI-facing XAX implementation MUST minimize total model-visible tokens per successful semantic change subject first to exact semantics and successful verification. It MUST NOT require the model to reproduce any semantic fact that is uniquely reconstructible from the current workspace state, declared query or transaction mode, or previously bound protocol state.

The AI-facing protocol SHOULD:

- treat workspace state and semantic query results as authoritative;
- request only the smallest semantic neighborhood required to determine an exact valid change;
- emit only information that is not uniquely derivable from shared state;
- express the smallest exact mutation set that satisfies the requested semantic change;
- omit unchanged semantics, repeated context, redundant framing, natural-language explanation, formatting, and success text unless explicitly required;
- avoid exploratory queries when the required mutation is already determined exactly;
- after rejection, consume only the diagnostic and repair neighborhood needed to produce the correcting mutation;
- prefer a slightly larger one-pass representation over a smaller representation that measurably increases invalid generations or repair turns.

Workspace roots, generations, targets, handle bindings, types, proofs, transaction defaults, and other protocol facts MAY be bound out of band and omitted from model-visible traffic when they are unambiguous and freshness requirements remain enforceable. Such omission MUST NOT weaken stale-root detection, transaction preconditions, verification, conflict detection, or canonical commit semantics.

When a query mode, transaction mode, or constrained decoder uniquely determines a field, that field SHOULD be omitted from model-visible traffic. When the mutation kind and target entity are uniquely bound, the model MAY emit only the remaining semantic value or values required to distinguish the intended mutation.

This policy optimizes semantic information transfer rather than textual brevity. Any elision that introduces ambiguity, changes semantics, prevents deterministic decoding, or increases total tokens per successful semantic change loses to the more explicit representation.

### 8.3 Dedicated vocabulary

A future model/XAX integration SHOULD assign dedicated vocabulary entries to frequent operations, mutation/query verbs, type forms, small widths, effect domains, diagnostic fields, handles, and transaction delimiters. Optimization targets frequent semantic mutations, not bytes alone.

### 8.4 Fallback transport

Current tokenizers require a compact fallback transport. No textual alphabet is normatively preferred without measurement.

A candidate fallback may look like:

```text
q users N3 kind=value
m set N7 op mul.wrap
v txn
c
```

or a denser framed representation:

```text
Q|U|N3|V
M|S|N7|op|mul.wrap
V
C
```

These shapes are **provisional until benchmarked**.

Fallback transport MUST be unambiguous, deterministically framed, versioned, and independent of whitespace; it MUST preserve semantic field boundaries, distinguish handles/literals/persistent identities, reject unknown mandatory elements, and remain non-source tooling.

### 8.5 Empirical selection rules

Candidate transports MUST be selected by measurement with the actual intended model/tokenizer family.

Evaluation SHOULD measure input/output tokens, completion rate, invalid packet and transaction rates, repair turns, semantic entities transmitted, protocol overhead, and packet bytes. Tests SHOULD cover creation, literal/operation/control-flow edits, type and ownership/effect repair, targeted optimization, and stale-root recovery.

A transport loses if its token savings are outweighed by significantly higher semantic error or repair rates.

---

## 9. Context and accounting

Every workspace SHOULD maintain machine-readable accounting:

```text
Accounting {
    model_input_tokens
    model_output_tokens
    semantic_entities_in
    semantic_entities_out
    query_count
    mutation_count
    rejected_transactions
    repair_rounds
    committed_changes
}
```

Accounting data is operational telemetry, not program semantics.

For benchmarkability, tooling SHOULD separately record model tokens, protocol bytes, artifact bytes, semantic and diagnostic entities, verifier work, and target-cost query work. Token efficiency MUST NOT be inferred from characters or bytes alone.

Workspace servers SHOULD support response budgets expressed in model tokens or in a proxy that is validated against model-token measurements. The current bootstrap workspace also supports an exact serialized response-byte budget as a separate transport control. This byte budget is explicitly not a model-token budget: paginated queries deterministically shrink to the largest positive-progress prefix that fits and return continuation; non-paginated responses or pages too small to make progress fail with `XAX.WORKSPACE.RESPONSE_BUDGET`. Budget failure publishes no new local handles and charges no unreturned query-response bytes.

---

## 10. Interfaces with other XAX subsystems

### 10.1 Canonical semantic graph

The workspace operates on the canonical graph and does not redefine operation, SSA, control, effect, or ownership semantics.

### 10.2 Canonical serialization and Merkle DAG

Persistent identities, expected roots, object reuse, and commit results depend on canonical serialization and content addressing. Short handles MUST resolve to canonical identities at commit.

### 10.3 Types, values, constants, and layout

Type and layout queries depend on the canonical type/value model. Target-sensitive layout MUST identify the target package used.

### 10.4 Memory, ownership, resources, effects, and errors

Mutation verification depends on explicit provenance, ownership, resource, effect, and error/control semantics. Violations MUST be exposed as structured dependencies.

### 10.5 Compile-time execution and specialization

`specialize` invokes the compile-time semantic machinery. The workspace is only the control surface; it is not a separate macro or template language.

### 10.6 Target packages and cost models

`layout`, target-legality, and `cost` queries depend on versioned target packages. Cost queries are estimates unless explicitly backed by measured profile data.

### 10.7 Compiler, optimizer, and artifacts

Optimization and lowering MAY expose queryable derived facts, but these do not replace canonical semantics. Artifact mapping connects canonical semantic entities to generated outputs without making emitted code authoritative source.

### 10.8 Packages and build configuration

Workspace queries MAY traverse package/module identities and build-semantic objects. Package/build data remains XAX semantic data, not an external JSON/YAML/TOML protocol language.

---

## 11. Invariants

The AI protocol MUST preserve all of the following:

1. **Meaning is source.** Tooling notation is never authoritative XAX source.
2. **No mandatory whole-program context.** Local tasks are serviced by bounded semantic retrieval.
3. **No hash burden on normal AI context.** Persistent identities may be hidden behind workspace-local handles.
4. **No hidden mutation.** Every canonical change occurs in a transaction.
5. **No partial commit.** A failed transaction leaves the canonical root unchanged.
6. **Stale-root detection is mandatory.** A transaction cannot silently commit against an unexpected base.
7. **Semantic conflicts are first-class.** Conflict detection is entity/relation/dependency based, not line based.
8. **Diagnostics are data.** Natural-language explanation is optional.
9. **Repair locality is deterministic under fixed inputs.**
10. **Derived facts identify dependencies or subsystem versions.**
11. **Target-dependent facts identify the relevant target package.**
12. **Token efficiency is measured empirically.**
13. **Fallback notation is tooling, not a second maintained language.**
14. **No protocol feature may introduce hidden allocation, synchronization, ownership transfer, exception edges, or runtime behavior into program semantics.**

---

## 12. Rejected alternatives

| Alternative | Rejection reason |
|---|---|
| Regenerate entire `.xax` artifacts for each edit | Defeats locality, retransmits unchanged semantics, increases token use, and weakens conflict isolation. |
| Present persistent cryptographic hashes directly for every reference | Wastes model context and increases generation error without adding semantic value for local tasks. |
| Make a human-readable dump editable source | Creates a second programming language, reintroduces parsing/source-preservation obligations, and violates meaning-is-source. |
| Line-based diff and merge | Lines are non-normative and do not capture semantic dependencies or graph conflicts. |
| Unconditional last-writer-wins mutation | Can silently invalidate proof assumptions, ownership relations, control edges, or concurrent work. |
| English-first compiler diagnostics | Consumes tokens, loses machine precision, and makes deterministic repair-neighborhood extraction harder. |
| Automatically transmit whole functions after every diagnostic | Violates minimal-context retrieval and can scale model context with repository size. |
| Declare one compact text syntax permanently optimal | Tokenizer behavior is model-dependent and must be benchmarked. |
| Treat byte size as the primary protocol metric | Small byte streams may tokenize poorly or increase repair turns. |
| Encode target costs as semantic truth | Costs are model- and target-dependent estimates or measurements, not core program meaning. |

---

## 13. Open issues

Only implementation evidence can settle the following:

### 13.1 Handle namespace shape

It is not yet fixed whether handles should use typed namespaces such as `F3`, `N7`, `T2`, or a single dense integer namespace with out-of-band kind information. Tokenization efficiency and error rate must decide.

Prototype evidence (non-normative, 2026-10-01): on the five-task bootstrap corpus, unified dense integers saved 15 offline view tokens over typed `P0`/`N0` handles. In 30 Claude Code (`claude-opus-5-5`) trials the two namespaces showed no measurable difference in model tokens or failed checks (typed 9, unified 7, all caused by framing). This does not settle the question; see OI-01.

### 13.2 Fallback framing

Textual separators, binary framing, compact CBOR-like structures, or tokenizer-informed alphabets remain candidates. The final fallback transport requires measurement on target model families.

Prototype evidence (non-normative, 2026-10-01): three versioned `X1` framings were measured on the same corpus. Offline, `pipe` used the fewest tokens and `json` the most. In 30 Claude Code trials all completed, but failed `verify`/`test` checks were `line` 0, `pipe` 2, and `json` 14; nine of ten JSON trials required at least one repair because the flat single-array packet was repeatedly written as separate or nested arrays. Model-token differences were below run-to-run noise. On this corpus, line framing is the observed reliability leader and the tested flat-array JSON framing is disfavored, but one model family with n=1 per cell does not select the transport; see OI-01.

### 13.3 Repair-neighborhood minimization cost

The verifier must determine whether computing a strictly minimal repair neighborhood is worth its cost. A deterministic near-minimal neighborhood may be preferable if it reduces verifier cost without increasing repair turns.

### 13.4 Semantic rebase granularity

The correct balance between whole-root compare-and-swap, entity-level preconditions, and explicit read-set validation requires implementation experience with concurrent AI agents.

No other unresolved issue in this stage justifies weakening the invariants above.

---

## 14. Falsification criteria

This design should be reconsidered if implementation and benchmarking show any of the following:

1. Minimal semantic queries repeatedly require near-whole-program expansion for ordinary local edits, making repository size strongly correlate with model context size.
2. Short local handles produce materially more reference mistakes than persistent identifiers after accounting for token cost.
3. Transactional semantic edits require more model tokens or more repair rounds than regenerating a compact source-like representation for representative workloads.
4. Structured diagnostics plus repair neighborhoods do not reduce repair turns relative to concise natural-language diagnostics.
5. Deterministic repair neighborhoods are consistently too large or too expensive to compute to justify their protocol value.
6. Entity/relation-level conflict detection fails to permit useful concurrent AI work beyond what whole-root serialization already provides.
7. Semantic rebase causes unacceptable silent misapplication risk even with explicit preconditions and read sets.
8. Token-native vocabulary fails to produce substantial token or reliability improvements over the best measured fallback transport.
9. The best fallback transport is so syntax-dependent that it effectively requires maintaining a second programming language and parser ecosystem.
10. Context/token accounting cannot reliably predict or explain successful semantic-change cost across supported model families.
11. Query and mutation protocol overhead dominates compiler/verifier work for small edits to the point that direct artifact regeneration is measurably superior.
12. Artifact/source mapping cannot remain deterministic enough to support targeted diagnostics, optimization feedback, and emitted-code inspection.

The architecture remains valid only if the workspace enables precise local reasoning, transactions prevent partial or stale mutation, diagnostics support machine repair, and measured protocol cost materially benefits from semantic locality.

## 15. Snapshot-bound local mutation adapter (ADR-186)

When every node in a projected function has the same single result type, the
view declares `node results=(TYPE)` once for that function and omits repeated
node result annotations. Function signatures and block parameter types remain
explicit. Mixed result types, zero-result nodes and multiple results retain
their exact per-node result lists. This is a lossless tooling view; canonical
types, transaction preconditions and verification are unchanged.

`session.bind(verb, node)` MAY bind a caller-selected mutation kind and exposed
node before requesting model output. It returns help for the remaining fields;
`session.commit_bound(response)` accepts those fields or an ordinary full command
whose kind and resolved target exactly match the binding, and expands them
through the ordinary exact transaction parser. Supported bindings are constant
and operation setters, operand replacement, movement, and edge-argument
replacement. No replacement value, operand, destination, or edge index is
selected by the binding adapter. Mutations with no remaining fields are not
offered as model requests in this mode.

Binding MUST retain the queried snapshot and target identity. A full command
with a different kind or target MUST reject. Extra commands,
wrong field counts, unexposed targets, and alias changes MUST reject. Stale
generations, including identical restored roots, MUST reject through ordinary
commit. A client may explicitly bind a fresh session only after reporting the
conflict and returning fresh context. The adapter has no benchmark task identity
or expected target; this is the out-of-band field elision allowed by §8.2.

An established binding MUST NOT be retargeted or change mutation kind while
awaiting a response. Repeating the identical binding is permitted; a different
binding requires a new session. `view(bound=True)` MAY expose only the selected
node's old value/operation and integer width for bound constant/arithmetic
setters: all operands, uses and other nodes remain immutable under that bound
request. Operand, movement and edge requests retain their full selected view
because the model must choose among exposed values or destinations. Every view
continues to read the captured snapshot, never a newer canonical root.

After reporting a rejected bound request, clients MAY query a fresh local
session and request the established full-batch carrier for repair. Token
measurements MUST include the rejected response. If field-only movement
requests cause more repairs, clients SHOULD retain the ordinary movement batch
rather than requiring redundant format repair. No parser may guess a different
mutation kind, target or replacement value to make a response pass.

`compiler/src/xax_local_protocol.py` supplies `LocalMutationSession` for ordinary
workspaces. A session MUST be constructed from the same queried generation as
the supplied model view. It retains that snapshot and expands omitted old
operation, constant, operand, and containment preconditions from it. Submission
MUST NOT refresh the snapshot implicitly. Commit uses the existing transaction
verifier and final generation check, including rejection after an intervening
change restores identical root bytes.

The semicolon-separated command batch is a fallback transport, never semantic
source. Aliases abbreviate exposed handles only. `N` used as a value means
result zero; other results require an exposed value handle. `@I` denotes an
existing transaction-local insertion result. Cross-function value references,
unexposed handles, malformed batches, and incomplete bounded function queries
MUST reject. Multiple mutations publish together or do not publish.

`LocalMutationSession.for_function(workspace, function_cid, limit=64)` binds a
selected function's nodes and parameters with dense local aliases; it rejects
truncation. `session.commit(command)` submits the batch without a separate
candidate verification round trip. External behavioral checks remain required
when a task needs more than semantic verification. Neither the session nor its
aliases constitute a canonical program or a benchmark-specific operation.

Optional intent roles (for example, a caller's names for two values) MAY bind
to exposed handles through ordinary session aliases. A model view that uses
such roles in its intent MUST supply those bindings explicitly rather than
expecting the model to infer them from numeric values. All handles in a batch
refer to the pre-batch snapshot; insertion does not change their meaning.
`BATCH_HELP` exposes this rule and `@ID` insertion-result addressing to clients.

A client MAY treat the model's final response as a mutation request and call
the bound session's `commit` itself. Successful host verification requires no
additional model acknowledgement. On failure the client MUST retain the failed
request and usage, return the diagnostic and required repair neighborhood, and
obtain a new request. A stale snapshot MUST be rejected before any refresh;
refreshing is a separate query bound to a new session. This interaction is
ordinary tooling, available independently of benchmark tasks.

`session.view()` projects exposed functions from the captured snapshot,
including parameter/result types, nodes, operands, attributes, and control
edges. It rejects an incomplete node projection. Request-local result aliases
such as `N0.R1` abbreviate exposed results, including effect values.

For empty-program construction, `construct_program(request, limit=64)` decodes
a bounded construction-tool request into one verified straight-line integer
function and its canonical store. `parameters` and `returns` contain bit
widths; `nodes` contain ordinary operation/result-type/operand constructor
arguments; `return` contains result references. Parameter aliases `P0...` and
prior node-result aliases `@0...` are request-local and are erased before
semantic identity. This is a transport adapter over `GraphBuilder`, not an
alternative source language or a task-aware function template. Unknown values,
invalid types, malformed requests and verifier failures MUST reject before a
canonical store is returned.

General construction uses the `xax-construct-v1` carrier (`xax_construct.construct`,
ADR-210): one request carries type aliases, multi-block functions (block
parameters, nodes with attributes and platform or function entities, `ret`/`br`/
`cbr` ends), and a package with named build entries. It returns a verified build
snapshot store. Value names (`p0`, `n3.r1`, `B0.n1`) are request-local and erased.
The request is a transport record: once the store exists it is authoritative, and
every later change is a workspace transaction on it, never a re-sent request.

The carrier also names the `linux-x86_64-startup-v1` reads as `linux.startup.<name>`
entities (`argc`, `arg_length`, `arg_copy`, `envc`, `env_length`, `env_copy`,
`auxv_value`; ADR-222). They are valid only in the process entry function, so a
build of a program that reads them elsewhere rejects (`LINUX-STARTUP-PROCESS-ENTRY`).
Integrations depend on the carrier through `xax-host-contract-v1` (`xax_contract`,
ADR-224), not on the distribution version.

An atomic batch MAY delete an entire dead dependency chain of supported pure
nodes. Uses inside that same deletion set do not survive publication. Any use
in a surviving node, terminator or control edge MUST still reject deletion;
each deleted operation remains subject to the ordinary purity checks.

`session.instructions()` advertises transport carriers from the exposed node
operations, types and control edges. It contains no task identity or expected
edit. Clients SHOULD send this applicable schema instead of retransmitting
unrelated mutation forms for every local request.

The edit grammar is also available as shared context (ADR-200).
`edit_grammar(compact=...)` is the complete carrier grammar. It is a pure
function of the protocol version, with no snapshot, task, generation or handle,
and `edit_grammar_id(compact=...)` is its content identity. A client SHOULD
send the grammar once per conversation or session as shared context (system
instructions, a cached prefix or a tool description) and then call
`session.instructions(shared=ID)`, which returns no per-request help. An ID
that does not match the session's current grammar MUST reject; the session
never silently falls back or mixes grammars. Holding the shared grammar changes
no acceptance rule: every carrier still checks exposure, the snapshot
generation, exact old fields and verification, and a form that does not apply
to the shown handles rejects with the ordinary diagnostic. Every form that
`instructions()` advertises for a neighborhood is covered by the shared grammar.

An exposed node alias `N0...` MAY omit its `N` prefix when the carrier field
expects a node or node-result value. Resolution is through the session's
existing `N` alias, never through a new global index; parameter aliases retain
`P`. Type and function fields MAY likewise omit `T` or `F` when the corresponding
alias or exposed handle is already bound. Field kinds make this resolution
unambiguous; it never constructs a type or selects an unexposed function.
This shorthand preserves the
same generation, exposure and function-ownership checks.

`view(functions=(...))` selects an already exposed function subset; an
unexposed function or ambiguous projected function alias MUST reject.
`diagnostic_view` returns the actual verifier code, rule, expected/actual facts
and repair neighborhood using exposed local identities where available.

Normal setters MAY reconstruct unique old fields from the captured snapshot:
`set-edge ANCHOR EDGE_INDEX ARG_INDEX VALUE` expands to the exact matching
disconnect/connect pair; the projection supplies a source-block anchor and
zero-based indices. `set-type NODE NEW_TYPE` requires one result; its indexed
variant requires an explicit result index. `set-signature FUNCTION PARAM_TYPES
RETURN_TYPES` derives the old interface. The ordinary carriers still check all
old attributes and the final generation. `edge0`, `arg0`, and `R0` MAY abbreviate
the corresponding integer-index fields; they never select unexposed state.

`prune-dead NODE` requires an unused supported pure root and computes its dead
pure dependency closure within the exposed function neighborhood. Dependencies
with any surviving use or effect MUST remain. Expansion uses ordinary exact
deletions; missing exposure, malformed requests, stale generations or verifier
rejection MUST publish nothing. This is deterministic construction of existing
mutations, not a task-aware optimization template.

Resource and effect types in a projection MUST identify their forms and
contracts sufficiently to distinguish resource values from effect values;
opaque type labels alone are inadequate for a resource-flow repair.

Ordinary sessions accept compact verb aliases: `const` = `set-constant`,
`op` = `set-op`, `operand` = `replace-operand`, `edge` = `set-edge`,
`type` = `set-type`, `sig` = `set-signature`, and `prune` = `prune-dead`.
Arguments and all exact snapshot preconditions are identical. These are
tool-transport aliases, erased before transaction verification; they introduce
no new semantic operation. `instructions()` advertises the compact forms by
default; `instructions(compact=False)` advertises the accepted long forms.
Applicable help SHOULD state result-index notation for multi-result nodes
and omit redundant optional spelling rules. A rejected pending request is
not applied to the projected snapshot.


## Platform carrier replacement v1 (2026-10-07)

Workspace exposes bind_object(cid, byte_budget=...) and ReplaceTarget(handle,
expected_old_cid, new_identity_only_target). Transactions require RootRef and
current generation handles; old CIDs are exact preconditions. Canonical
constructors rebuild supported acyclic MODULE/PACKAGE/REQUEST/SNAPSHOT ancestors.
The new frontier passes ordinary verification, and affected Android APK requests
lower privately before final generation/root/read comparison. Verify/rollback
publish nothing. Machine targets, duplicate handles, stale rebase and rebuilding
signature/provenance objects reject. Renew signatures/evidence separately.
Capabilities, policy, resolver identity and external digests are preserved.
This tooling contract adds no kernel opcode or textual program authority.
Platform-specific checking outside an affected Android request is not promised.
See compiler/integration/android/CARRIER_TRANSACTIONS.md and
compiler/tests/test_xax_workspace_targets.py.
