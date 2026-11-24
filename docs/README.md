# XAX documentation index

The documents in this directory are the detailed normative text of XAX. Precedence is set by
[`XAX_SPEC.md` §1](../XAX_SPEC.md#1-normative-language-and-precedence): the specification is normative and these
stage documents are subordinate to it on conflict; an implementation conforms to both
([`16_CONFORMANCE_EXAMPLES.md`](16_CONFORMANCE_EXAMPLES.md)). Each document opens with its purpose and scope.

Agents: start at [`AGENTS.md`](../AGENTS.md), then use [Task routes](#task-routes) to read only what a task needs.
Read a large document by section (its Contents list, or `grep -n '^## ' <file>`), not whole.

## Repository documents

| Class | Documents | Authority |
|---|---|---|
| NORMATIVE | [`XAX_SPEC.md`](../XAX_SPEC.md), `docs/01`–`18` (tables below) | Language meaning; spec wins on conflict |
| NORMATIVE (obligations) | [`XAX_CONFORMANCE.md`](../XAX_CONFORMANCE.md), [`XAX_BENCHMARKS.md`](../XAX_BENCHMARKS.md) Part I | What a claim must show |
| INSTRUCTION | [`AGENTS.md`](../AGENTS.md), [`compiler/AGENTS.md`](../compiler/AGENTS.md) (`CLAUDE.md` files import them) | How agents work here |
| DECISION | [`XAX_DECISIONS.md`](../XAX_DECISIONS.md) | Adopted rationale; an ADR is superseded only by a later ADR |
| CURRENT_STATE (generated) | `<!-- xax-status:... -->` blocks; sources [`XAX_REPLACEMENT_MATRIX.json`](../XAX_REPLACEMENT_MATRIX.json), `compiler/bootstrap/RELEASES`, `compiler/bootstrap/evidence/records/` | Replacement and bootstrap levels; never hand-edited |
| CURRENT_STATE | [`XAX_OPEN_ISSUES.md`](../XAX_OPEN_ISSUES.md) (each OI's newest status line), the last section of [`XAX_HANDOFF.md`](../XAX_HANDOFF.md) | Open work and where it stands |
| EVIDENCE / HISTORICAL | Dated sections of [`XAX_STATE.md`](../XAX_STATE.md), `XAX_HANDOFF.md`, `XAX_BENCHMARKS.md` Part II; `compiler/**/*_evidence.json` | What ran, when; never rewritten |
| ROADMAP | [`XAX_IMPLEMENTATION_ROADMAP.md`](../XAX_IMPLEMENTATION_ROADMAP.md), [`17_BENCHMARKS_ROADMAP.md`](17_BENCHMARKS_ROADMAP.md) | Planned order; not evidence |
| PROPOSAL | [`proposals/`](proposals/) | Not normative until adopted by an ADR |
| REFERENCE | [`XAX_AI_Native_Programming_Language_Architecture.md`](../XAX_AI_Native_Programming_Language_Architecture.md) (founding intent, never overrides the spec), [`XAX_PROTOTYPE_SCHEMA_V1.md`](../XAX_PROTOTYPE_SCHEMA_V1.md) (M1 fixture bytes), component READMEs under `compiler/` | Background and component detail |
| AUDIT | [`audits/`](audits/) | Dated, non-normative |

## Task routes

"Read" is mandatory for the task; "If needed" only when the task reaches it. Every route also applies
[`AGENTS.md`](../AGENTS.md), and every route that changes `compiler/` applies [`compiler/AGENTS.md`](../compiler/AGENTS.md).

| Task | Read | If needed | Code and data | Verify |
|---|---|---|---|---|
| Understand XAX | `XAX_SPEC.md` §1–3; [`01`](01_FOUNDATIONS.md); [`02`](02_SEMANTIC_GRAPH.md) | Architecture document §1–4 | — | — |
| Create or change an XAX program | [`09`](09_AI_PROTOCOL.md) §3, §5, §8, §11, §16 | [`03`](03_TYPES_VALUES_LAYOUT.md)–[`05`](05_EFFECTS_CONTROL_ERRORS.md) for the operations touched | `xaxc edit`/`verify`/`build` (the pinned seed) | `xaxc verify`; run the built program |
| Semantic graph or canonical identity | [`02`](02_SEMANTIC_GRAPH.md); [`08`](08_SERIALIZATION_IDENTITY.md) | `XAX_PROTOTYPE_SCHEMA_V1.md` (fixture bytes only) | `compiler/bootstrap/xax_store_*.xax`, `xax_graph_decoder.xax` | `tests/test_store_regeneration.py`; the store's own tests |
| Workspace queries and transactions | [`09`](09_AI_PROTOCOL.md) §4–8, §15, §16 | §6 (concurrent agents) | `xaxc edit`; `compiler/reference/xax_local_protocol.py` | rejection text and repair neighborhood per §7 |
| Types, memory, effects, concurrency, compile time | the matching stage: [`03`](03_TYPES_VALUES_LAYOUT.md), [`04`](04_MEMORY_RESOURCES.md), [`05`](05_EFFECTS_CONTROL_ERRORS.md), [`06`](06_CONCURRENCY_REALTIME.md), [`07`](07_COMPTIME_META.md) | ADRs that name the rule | `xax_op_typing.xax`, `xax_store_verifier.xax` (in the driver) | verifier positive and negative cases; `XAX_CONFORMANCE.md` Part II |
| Compiler change (any pass) | `compiler/AGENTS.md` (all); [`12`](12_COMPILER_CORE.md) | [`13`](13_OPTIMIZER_CODEGEN.md); the component's README under `compiler/` | `compiler/bootstrap/xax_compiler_driver_general.xax`; `evolution/LEDGER`, `evolve.sh` | C1 (and C2 for x86-64 code generation); corpus differential; the reference executor |
| Optimization or lowering | [`13`](13_OPTIMIZER_CODEGEN.md); `compiler/AGENTS.md` | `XAX_BENCHMARKS.md` Part I for speed claims | the backend store (`xax_x86_64_general.xax`, `xax_aarch64_general.xax`, …) and the driver | the reference executor's result, not only bytes; ADR-207 for speed |
| Target backend | [`10`](10_TARGET_MODEL.md); [`13`](13_OPTIMIZER_CODEGEN.md) | [`11`](11_ABI_PLATFORM.md) | the backend store; `compiler/reference/xax_<target>.py` (oracle) | run on the target (emulator runs are labelled as such) |
| ABI and platform integration | [`11`](11_ABI_PLATFORM.md) | `compiler/integration/android/README.md`; [`XAX_OPEN_ISSUES.md`](../XAX_OPEN_ISSUES.md) OI-33, OI-42, OI-47 | target packages; integration stores | a device or host run of the ABI's cases |
| Bootstrap and self-hosting | [`15`](15_BOOTSTRAP_SELFHOST.md); `compiler/AGENTS.md` "Seeds, releases and bootstrap levels" | `compiler/bootstrap/README.md`; `evidence/README.md` | `compiler/bootstrap/seed/`, `evidence/` | `selfbuild.sh` fixed point; B levels only from the release record |
| Compiler evolution and release | `compiler/AGENTS.md` (all); [`proposals/build-bootstrap-rotation-rfc.md`](proposals/build-bootstrap-rotation-rfc.md) §3, §8, §13.7 | the last "Release … on `main`" section of `XAX_HANDOFF.md` (the recipe as run) | `rotate.sh build/confirm/validate`, `evidence/run.sh`, `RELEASES` | `evolve.sh check` and `replay`; `rotate.sh validate`; full suite |
| Benchmarks and replacement levels | [`XAX_BENCHMARKS.md`](../XAX_BENCHMARKS.md) Part I; `compiler/AGENTS.md` "Evidence" | [`17`](17_BENCHMARKS_ROADMAP.md); ADR-207, ADR-209, ADR-210 | `compiler/benchmarks/`; `XAX_REPLACEMENT_MATRIX.json` | raw `wall_seconds_samples`; `tests/test_status_docs.py` after `status-tool/status.sh write` |
| Conformance testing | [`XAX_CONFORMANCE.md`](../XAX_CONFORMANCE.md) Part I–II; [`16`](16_CONFORMANCE_EXAMPLES.md) | Part III (obligations) | `compiler/tests/` | the named tests, EXECUTED with `XAX_REQUIRE_NATIVE=1` where native |
| BBC and BFX | [`18`](18_BFX_IMPORT.md); `compiler/integration/bfx/README.md` | `bfx/COMPILE.md`, `DYNAMIC_TAPE.md`, `SHARED.md` | `integration/bfx/bbc.xax` (follows the driver), BBC's repository | BBC's `check.py` with the release's `bbc.exe` |
| XAX-MCP boundary | Ecosystem rules in `AGENTS.md`; `compiler/integration/mcp/README.md` | `compiler/integration/construct/README.md` | XAX-MCP's repository (transport, schemas, sandbox) | the pin XAX-MCP records |
| Open issues and design questions | [`XAX_OPEN_ISSUES.md`](../XAX_OPEN_ISSUES.md) (Contents, then the one OI) | the ADRs it cites | — | the OI's "Closure Criteria" |
| Find a decision | `grep -n '^## ADR-<n>' XAX_DECISIONS.md`, then that section | later ADRs or amendments naming it (`grep -n 'ADR-<n>'`) | — | — |
| Continue interrupted work | the top and the last `## ` section of [`XAX_HANDOFF.md`](../XAX_HANDOFF.md) | the OIs and issues it names | — | its "Next" items, against `git log` |
| Documentation maintenance | this index; `AGENTS.md` "Documents and status"; [`DOCUMENTATION_STYLE.md`](DOCUMENTATION_STYLE.md) | `compiler/bootstrap/status-tool/README.md` (generated blocks) | — | `tests/test_status_docs.py`; links resolve |

## Reading order

New readers should start with the foundations, the semantic graph and the AI protocol, then read the stage that
matches their task:

1. [`01_FOUNDATIONS.md`](01_FOUNDATIONS.md) — the vocabulary and the invariants every later document preserves.
2. [`02_SEMANTIC_GRAPH.md`](02_SEMANTIC_GRAPH.md) — programs as persistent, typed semantic graphs.
3. [`09_AI_PROTOCOL.md`](09_AI_PROTOCOL.md) — how an AI queries, edits, verifies and commits a program. Agents must
   read this one before editing a program ([`AGENTS.md`](../AGENTS.md)).

## Language semantics

| Document | Defines |
|---|---|
| [`01_FOUNDATIONS.md`](01_FOUNDATIONS.md) | Normative vocabulary, invariants, the rule that meaning is source |
| [`02_SEMANTIC_GRAPH.md`](02_SEMANTIC_GRAPH.md) | The canonical semantic graph and the core operation model |
| [`03_TYPES_VALUES_LAYOUT.md`](03_TYPES_VALUES_LAYOUT.md) | Types, SSA values, constants and physical layout |
| [`04_MEMORY_RESOURCES.md`](04_MEMORY_RESOURCES.md) | Storage, pointers, ownership, aliasing, device memory and linear resources |
| [`05_EFFECTS_CONTROL_ERRORS.md`](05_EFFECTS_CONTROL_ERRORS.md) | Effect ordering, control flow, calls, recoverable errors and traps |
| [`06_CONCURRENCY_REALTIME.md`](06_CONCURRENCY_REALTIME.md) | Atomics, synchronization, interrupts and real-time profiles |
| [`07_COMPTIME_META.md`](07_COMPTIME_META.md) | Compile-time execution, specialization and generics |

## Representation and interaction

| Document | Defines |
|---|---|
| [`08_SERIALIZATION_IDENTITY.md`](08_SERIALIZATION_IDENTITY.md) | The canonical `.xax` store: content-addressed objects in a Merkle DAG |
| [`09_AI_PROTOCOL.md`](09_AI_PROTOCOL.md) | The AI workspace: queries, transactions and diagnostics |

## Targets and platforms

| Document | Defines |
|---|---|
| [`10_TARGET_MODEL.md`](10_TARGET_MODEL.md) | Target packages: the machine facts code generation needs |
| [`11_ABI_PLATFORM.md`](11_ABI_PLATFORM.md) | ABIs, foreign interoperability, platform capabilities and hosted environments |
| [`18_BFX_IMPORT.md`](18_BFX_IMPORT.md) | The BFX module import used by the BBC integration |

## Compiler, build and bootstrap

| Document | Defines |
|---|---|
| [`12_COMPILER_CORE.md`](12_COMPILER_CORE.md) | Ingestion, verification, the semantic database and incrementality |
| [`13_OPTIMIZER_CODEGEN.md`](13_OPTIMIZER_CODEGEN.md) | Optimization, lowering, code generation and the cost model |
| [`14_PACKAGE_BUILD_SECURITY.md`](14_PACKAGE_BUILD_SECURITY.md) | Packages, dependency resolution, builds, reproducibility and trust |
| [`15_BOOTSTRAP_SELFHOST.md`](15_BOOTSTRAP_SELFHOST.md) | Bootstrapping, self-hosting (B0-B6) and autonomous development |

## Conformance and measurement

| Document | Defines |
|---|---|
| [`16_CONFORMANCE_EXAMPLES.md`](16_CONFORMANCE_EXAMPLES.md) | How an implementation demonstrates conformance; reference examples |
| [`17_BENCHMARKS_ROADMAP.md`](17_BENCHMARKS_ROADMAP.md) | The benchmark specification and the staged implementation roadmap |

## Documentation style

[`DOCUMENTATION_STYLE.md`](DOCUMENTATION_STYLE.md) sets Markdown formatting and reusable templates; it governs form only.

## Audits

[`audits/`](audits/) holds dated, non-normative audit records.

## Proposals

[`proposals/`](proposals/) holds design proposals that are not yet normative.
