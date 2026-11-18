# Design: the native reference executor (ADR-405)

Date: 2026-11-16. Status: design; slice 1 is the next implementation step. Base: `main` `1cef687`.

ADR-405 makes the correctness oracle a native XAX program. This note fixes its interface, its independence rules,
its data model and the order in which it replaces the Python executor's comparison tests, starting with x86-64
register lowering.

## 1. What it is

`xax_oracle` is a Linux x86-64 XAX process: an interpreter of canonical graph semantics. It reads a canonical store
and runs one function on given arguments:

```text
xax_oracle run <store> <function CID, 64 hex digits> <argument>...
```

- Arguments and results are unsigned decimal integers, one per `bits<N>` parameter or result.
- Exit 0: the results, one decimal per line.
- Exit 1: the function trapped. It prints `trap <payload hex>`, the terminator's payload or the reason an operation
  traps (division by zero), encoded as `xax_compiler.trap_payload` encodes it.
- Exit 2: declined. The function, or one it calls, uses an operation, type or form outside the slices implemented
  so far. It prints `decline <operation number>`.
- Exit 3: a usage or I/O failure, a malformed store (bounds, an unknown kind, a missing CID), or fuel exhausted
  (`fuel`; the default is 100,000 steps, like `execute`, but the units may differ, so fuel exhaustion is reported and never compared).

## 2. Independence

ADR-405 requires the oracle to share no code with the backends, lowerings or optimizers it checks, and never to be
generated from the compiler's stores:

- It is written as native batches on `compiler/bootstrap/evolution/ledger-tool/seed.xax`, like the other tools.
  It copies only tool helpers (`@fend`, `@nextline`, `@memeq`, and the store-record walk of
  `request-tool/request.batch`), none of the compiler's functions.
- It decodes the canonical bytes itself (`docs/08_SERIALIZATION_IDENTITY.md` §4–§7, §14; the graph body of
  `_graph_syntax_bootstrap`). It does not read `xaxc edit` views, whose printer shares the compiler's decoder: a
  decoder bug would then be invisible to both.
- It interprets: no code generation, no register allocation, no optimization. Each operation's meaning is written
  once from the spec (`docs/02_SEMANTIC_GRAPH.md`, `docs/03_TYPES_VALUES_LAYOUT.md`), not from a backend.
- It does not verify. The harness runs `xaxc verify` first, as `execute` runs `verify_store`. A store that does
  not verify is not given to the oracle. Verification decides admissibility, the oracle decides meaning, and the
  two stay separate concerns.
- It is built with the pinned seed. A miscompile of the oracle by the seed would have to agree with a miscompile
  of the program under test to stay hidden, which is the same residual risk the Python executor carries under
  CPython. The first slice is therefore accepted only after it agrees with the Python executor (§5).

## 3. Data model

- **Store:** read into one view (at most 192 MiB). Walk the header and the records once and keep, per record, its
  CID offset, kind, reference table and body. Objects are found by CID with a binary search over the sorted
  records, because records are in CID order (§14.1).
- **Types:** `bits<N>` (kind 4, body `uleb(1) uleb(N)`) for N from 1 to 64. Any other type declines.
- **Constants:** kind 5, body `uleb(0) uleb(len) bytes`, little-endian, with one reference, the type.
- **Functions:** kind 3, body `ref(graph) uleb(n) ref(type)×n uleb(m) ref(type)×m`. A group member function (graph
  reference to kind 8) declines in slice 1.
- **Graphs:** kind 7, body `uleb(blocks) uleb(entry)`, then per block `uleb(params) ref(type)...`,
  `uleb(nodes)` nodes, and a terminator.
  - A node is `uleb(op)`, `ref(entity)` for the entity operations, `uleb(k)` values, `uleb(r)` result types, and
    `uleb(a)` attributes for the attribute operations.
  - A value is `0 block index` (a parameter) or `1 block index result` (a node result).
  - The terminators are 1 (branch: an edge), 2 (conditional branch: a value and two edges), 3 (return: values) and
    4 (trap: a byte string).
- **Execution:** one decoded graph per call frame.
  - A slot table gives every block parameter and node result a 64-bit slot.
  - Frames live on an explicit stack in memory (no host recursion, which XAX tools cannot express yet).
  - Each block entry and node costs one unit of fuel.

## 4. Slices

| Slice | Covers | Replaces the Python executor in |
|---|---|---|
| 1 (done 2026-11-16) | `constant`, `add.wrap`, `sub.wrap`, `mul.wrap`, `bit.xor`, `bit.and`, `bit.or`, `udiv`, `urem` (trap on zero), `rotate.right`, `int.compare` (all ten predicates), `int.truncate`, `int.zero.extend`, `call.direct`; `br`, `cbr`, `ret`, `trap`; `bits<1..64>` | `test_xax_regalloc_differential` (x86-64 register lowering), then `test_x86_64_narrow_signed_compare`, `test_native_branch_fusion` |
| 2 (done 2026-11-16) | recursion groups (`call.group.member`) | `test_xax_recursion` |
| 3 (done 2026-11-18) | stack allocation, address offsets, plain and checked loads and stores (`memory-check` traps) | `test_xax_byte_view_widening`; `test_xax_x86_64_views` needs only slices 1 and 4, and `test_xax_pointer_rebase` runs executables (target addresses and `mmap`), so neither compares with `execute` here |
| 4 | aggregates, sums, floats | `test_xax_general_language` |
| — | foreign calls, target operations, meta operations | declined for good: a host or target is not graph semantics |

## 5. Acceptance of each slice (ADR-405 (4))

1. Both oracles run the area's existing corpus: the same stores and arguments, `execute` against `xax_oracle run`.
   All results, traps and declines are recorded. Declines are allowed only for programs outside the slice.
2. Once they agree on every case, that run is committed as an EXECUTED record (`compiler/benchmarks/oracle_<area>.json`,
   with the binary SHA-256s and case counts).
3. Only then does the area's comparison test call the native oracle instead of `execute`. A second test keeps
   checking that both oracles agree, until the Python module has no other importer (ADR-405 (2)).

## 6. Effort and limits

Slice 1 is one native program of about 2,000 to 3,000 view lines: the store walk, the decoders, the slot table, the
interpreter loop and the CLI. It is one PR. It runs on Linux x86-64 only, like the other tools, and it trusts the
pinned seed that builds it (§2). It adds no Python to `reference/`; the agreement test is a test comparing with the
reference, which AGENTS.md permits.
