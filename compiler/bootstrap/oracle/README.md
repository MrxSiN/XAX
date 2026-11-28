# The native reference executor (ADR-405)

`xax_oracle.xax` is an XAX build request store: an interpreter of canonical graph semantics, independent of the
compiler (design: `docs/proposals/native-oracle.md`). Its main has the general driver's entry and reaches files only
through the driver's host functions, so it runs as a Linux x86-64 process and, hosted by
`../windows/generator/generate.sh`, as a Windows x86-64 one (`xax_oracle_windows.xax`). `sh oracle.sh <arguments>`
builds the host's store with that host's pinned seed and runs it.

```text
xax_oracle run <store> <function CID> <argument>...
```

- Arguments and results are unsigned decimals, one per `bits<N>` parameter or result.
- Exit 0 prints the results, one per line.
- Exit 1 prints `trap <payload hex>`: the trap terminator's payload, or `02` for a division by zero.
- Exit 2 prints `decline <operation>`. An operation outside the slices, or `decline 0` for a type that is not
  `bits<1..64>` or a callee that is not a function.
- Exit 3 prints `fuel` (100,000 block entries and nodes) or `error`.

The store is not verified here; run `xaxc verify` on it first, as `execute` verifies first.

**Slice 1** covers:

- `constant`, `add.wrap`, `sub.wrap`, `mul.wrap`, `bit.xor`, `bit.and`, `bit.or`, `udiv`, `urem`, `rotate.right`,
  `int.compare` (all ten predicates), `int.truncate`, `int.zero.extend` and `call.direct`;
- the terminators `br`, `cbr`, `ret` and `trap`.

**Slice 2** adds recursion groups. A group member function's graph is its group's member, and `call.group.member`
calls a member of the caller's own group: each frame records its group.

**Slice 3** adds stack memory: `stack.alloc`, `address.offset`, `store.bits.le`, `load.bits.le`, `stack.end`,
`checked.load.bits.le` and `checked.store.bits.le`, with pointer, effect and resource types as values. A checked access
past its allocation, or misaligned within it, traps with the payload `memory-check` (exit 1, `trap 6d656d6f72792d636865636b`),
as `execute` does. The bound `offset + size <= extent` is evaluated without a 64-bit wrap, so a `bits<64>` offset near
2^64 traps (ADR-412 (4)). Pointers into the target's address space (`pointer.address`, `pointer.rebase`), heap views and growable
accesses stay declined.

**Slice 4** (aggregates and sums so far; floats follow) adds `aggregate.make`, `aggregate.get`, `sum.make`, `sum.tag`
and `sum.get`, with tuple, array and sum types as values. An aggregate or sum value is the frame view's address of its
words in an arena from byte 983,040 to 1,040,384, whose cursor is control slot 1000: an aggregate is its operands'
words, a sum its tag and its value. The arena is never freed, so a value outlives the frame that made it; past
57,344 bytes a call declines (`decline 0`). The wrong variant traps with the payload `sum-variant`, written to the
store view's last 32 bytes (after the 32-byte function CID). An aggregate or sum entry parameter or result is outside
the command line and is not checked: give the oracle bits entries.

How it works:

- The store is read into one view. Objects are found by CID through a walk of the records.
- A call builds a frame in two passes over its graph's body: the first counts nodes and slots; the second lays out
  the block table (parameter slots, first node, node count, terminator position), the node table (position,
  result slot, operation) and the slots (value, mask).
- Frames are on an explicit stack with caller, destination and resume fields, because tools cannot recurse.
- A stack allocation takes zeroed words from the top of the same frame stack, after its extent word, and is released
  when its frame returns. A pointer is the allocation's data address times 2^32 plus its offset, so a checked access
  finds the allocation's extent and its own offset from the pointer alone.
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
- frames and stack allocations under 896 KiB in all (more exits 3, `error`);
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
- Slice 1 also covers two more corpora. Narrow and signed `int.compare` (3,840 cases of
  `test_x86_64_narrow_signed_compare`) and compares reused after their branch (6 cases of
  `test_native_branch_fusion`) agree in both executors (`../../benchmarks/oracle_x86_64_compare_evidence.json`).
  Both tests now take their expected values from `oracle_execute`: the native oracle on Linux x86-64 and, since
  2026-11-28, on Windows x86-64 (see "The Windows build" below); the Python executor elsewhere.
- Slice 2: recursion groups agree in both executors (10 cases of `test_xax_recursion`, among them mutual recursion
  200 calls deep; `../../benchmarks/oracle_recursion_evidence.json`), and the register-lowering corpus still agrees
  160 of 160. `test_xax_recursion`'s execution check uses `oracle_execute`. Frames take about 0.5 KiB each, so about
  1,800 calls fit; the Python executor stops at its host recursion limit sooner.
- Slice 3: on the stack-memory corpus of `test_xax_byte_view_widening` (sizes 1, 2, 4 and 8, loads and stores, offsets
  0 to 33, 646 cases) both executors give the same results and traps (`../../benchmarks/oracle_memory_evidence.json`).
  The earlier areas still agree. That test's execution check now takes its expected values from the native oracle on
  Linux x86-64, and `tests/test_native_oracle.py` keeps checking that both oracles agree.

## The Windows build (2026-11-28)

`driver.batch` gives `@main` the general driver's entry (the file system, the process and 22 memory tokens), as the
request tool's `driver.batch` did for that tool. The rest of the program is unchanged.

- Views come from the driver's `xax-host-v1` declarations: a committed 64 KiB view A (reads, the current argument's
  text), a committed 64 KiB argument stash S, a committed 4 KiB view Q, the committed 1 MiB frame view and a reserved
  256 MiB store view.
- `argc` is read once and one `arg_copy` site copies every argument, from the last down to 2, into Q and then into S
  (offset and length at `16k`, text from 16 KiB on). Argument 2, the store path, is still in Q, the view
  `host_open` takes. Each later use of an argument copies it from S into A, where the unchanged code reads it.
- The store is read with `host_read` in 64 KiB pieces through A, because Windows `ReadFile` into a reserved page
  fails. The output goes from the frame view through A in 64 KiB pieces to `host_write` on standard output.
- New limits: 4 to 1,024 arguments, each under 4 KiB, at most 48 KiB of argument text in all. Anything else exits 3
  with `error`. On Windows the host layer's `_write` writes text mode, so each output line ends with CR LF.
- `xax_oracle.xax` is `oracle.batch`, `driver.batch`, then slice 4's `slice4-types.batch` (`@tmask`: tuple, array
  and sum types get a mask) and `slice4-aggregates.batch` (`@snode` knows operations 51-55, `@opx` sends them to the new
  `@op4`) on `../evolution/ledger-tool/seed.xax`
  (`tests/test_native_oracle.py`), and `xax_oracle_windows.xax` is `generate.sh`'s output for it
  (`tests/test_windows_generator.py`). Change the program by a further batch on `xax_oracle.xax`, then regenerate the
  Windows store.

**Checked (EXECUTED, 2026-11-28):** `tests/test_native_oracle.py` on Windows 11 with the Windows store built by the
pinned Windows seed: 8 passed (the Linux-only store check skipped), 4,111 subtests. Both oracles agree on the
register-lowering (160), narrow-compare (3,840), branch-fusion (6), recursion (10), stack-memory (60) and trap (7)
corpora (`../../benchmarks/oracle_windows_evidence.json`). The same file on Linux x86-64 (WSL 2, the pinned Linux
seed, `XAX_REQUIRE_NATIVE=1`): 9 passed, 4,111 subtests. Both seeds make the same two stores byte for byte. The tests
that take their expected values from `oracle_execute` (narrow compare, recursion, branch fusion, sign-extend
composition, byte-view widening) pass on Windows with the native oracle (23 passed, 3,875 subtests). They take
148 s instead of 42 s, because each case starts a process.

**Slice 4, aggregates and sums (EXECUTED, 2026-11-28):** both oracles agree on 10 cases on Windows 11 and on Linux
x86-64 (WSL 2): test_xax_general_language's tuple/array and sum programs at three inputs each, the sum-variant trap, a
tag with a 64-bit value, nested aggregates and an aggregate returned by a callee
(`../../benchmarks/oracle_aggregates_evidence.json`). The earlier corpora still agree (4,121 subtests on each host), and
test_xax_general_language's two checks now take their values from `oracle_execute`.
