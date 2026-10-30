# XAX normative documentation

The documents in this directory define XAX. They are normative: the specification
([`XAX_SPEC.md`](../XAX_SPEC.md)) summarizes them, and an implementation conforms to them
([`16_CONFORMANCE_EXAMPLES.md`](16_CONFORMANCE_EXAMPLES.md)). Each one opens with its purpose and scope.

## Reading order

New readers should start with the foundations, the semantic graph and the AI protocol, then read the stage that
matches their task:

1. [`01_FOUNDATIONS.md`](01_FOUNDATIONS.md) — the vocabulary and the invariants every later document preserves.
2. [`02_SEMANTIC_GRAPH.md`](02_SEMANTIC_GRAPH.md) — programs as persistent, typed semantic graphs.
3. [`09_AI_PROTOCOL.md`](09_AI_PROTOCOL.md) — how an AI queries, edits, verifies and commits a program. Agents must
   read this one first ([`CLAUDE.md`](../CLAUDE.md)).

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
| [`09_AI_PROTOCOL.md`](09_AI_PROTOCOL.md) | The AI workspace: queries, transactions, diagnostics and token cost |

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

## Proposals

[`proposals/`](proposals/) holds design proposals that are not yet normative.
