# The native reference executor (ADR-405)

`xax_oracle.xax` is a Linux x86-64 process, an XAX build request store: an interpreter of canonical graph semantics,
independent of the compiler (design: `docs/proposals/native-oracle.md`). `sh oracle.sh <arguments>` builds it with
the pinned seed and runs it.

```text
xax_oracle run <store> <function CID> <argument>...
```

- Arguments and results are unsigned decimals, one per `bits<N>` parameter or result.
- Exit 0 prints the results, one per line.
- Exit 1 prints `trap <payload hex>`: the trap terminator's payload, or `02` for a division by zero.
- Exit 2 prints `decline <operation>`. An operation outside slice 1, or `decline 0` for a type that is not
  `bits<1..64>`, a group member function or a callee that is not a function.
- Exit 3 prints `fuel` (100,000 block entries and nodes) or `error`.

The store is not verified here; run `xaxc verify` on it first, as `execute` verifies first.

**Slice 1** covers:

- `constant`, `add.wrap`, `sub.wrap`, `mul.wrap`, `bit.xor`, `bit.and`, `bit.or`, `udiv`, `urem`, `rotate.right`,
  `int.compare` (all ten predicates), `int.truncate`, `int.zero.extend` and `call.direct`;
- the terminators `br`, `cbr`, `ret` and `trap`.

How it works:

- The store is read into one view. Objects are found by CID through a walk of the records.
- A call builds a frame in two passes over its graph's body: the first counts nodes and slots; the second lays out
  the block table (parameter slots, first node, node count, terminator position), the node table (position,
  result slot, operation) and the slots (value, mask).
- Frames are on an explicit stack with caller, destination and resume fields, because tools cannot recurse.
- An edge copies its values through a buffer, so that parallel block arguments are correct.
- A binary operation computes every candidate result and keeps the one its operation selects; division by zero
  traps.
- A signed comparison flips the operand's sign bit; a rotation uses the result's mask.

It shares no code with the compiler. It copies no compiler function, decodes the canonical bytes itself and reads
no `xaxc edit` view.

How it was made: `oracle.batch` is a native batch (docs/09_AI_PROTOCOL.md §16) on
`../evolution/ledger-tool/seed.xax`, written by hand without a generator of its logic. Its result is `xax_oracle.xax`,
and `xaxc verify` accepts it. Change it by a further batch on `xax_oracle.xax`, then `xaxc verify`.

Limits:

- a store under 256 MiB;
- frames under 896 KiB in all;
- at most 512 values on one edge, call or return;
- a 32-byte CID argument in hexadecimal.

**Checked (EXECUTED, WSL 2, the pinned seed `36e2b756…`, 2026-11-16):**

- On the whole x86-64 register-lowering corpus (160 programs of `test_xax_regalloc_differential`), the native and
  Python executors give the same results (`../../benchmarks/oracle_x86_64_regalloc_evidence.json`).
- They also agree on division by zero, an explicit trap with a payload, signed comparisons on `bits<8>`, a
  32-bit rotation, two results and fuel exhaustion.
- A float operation and a float parameter decline.
- So `test_xax_regalloc_differential` compares the native code with this oracle (ADR-405 (4)), and
  `tests/test_native_oracle.py` keeps checking that both oracles agree.
