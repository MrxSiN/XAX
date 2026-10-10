"""Differential validation of the Linux AArch64 register allocator (ADR-168).

Seeded random programs over bits<8/16/32/33/64> use every operation the
allocator lowers. Each program has:
- straight-line arithmetic, logic, division, rotation, truncation, and compares;
- a counted loop carrying up to 14 values (enough to force frame slots) that
  may call an earlier program, so values cross calls;
- a diamond on a random predicate.

Each program is compiled for ``aarch64-linux-elf-exec-v1``, run in Unicorn
with its arguments in x0-x7, and must return the reference executor's result.
Targeted programs check the trap paths, the flag-free membership test, the
``bic`` form, and register pressure across calls. This is translation
validation by execution over a fixed corpus, not a proof.
"""

from __future__ import annotations

import random
import unittest

from xax_aarch64 import _run_aarch64_unicorn, _unicorn_available, compile_aarch64_bound_target
from xax_aarch64_regalloc import compile_linux_function
from xax_compiler import (
    IntCompare,
    Operation,
    aarch64_linux_exec_target,
    bits_type,
    decode_native_target,
    execute,
    store_resolver,
)
from xax_graph_builder import GraphBuilder, program_store

SEED, PER_WIDTH = 20261005, 10
WIDTHS = (8, 16, 32, 33, 64)
B1 = bits_type(1)
BINARY = (Operation.ADD_WRAP, Operation.SUB_WRAP, Operation.MUL_WRAP, Operation.BIT_AND, Operation.BIT_OR, Operation.BIT_XOR)


def _edges(width: int) -> tuple[int, ...]:
    top = (1 << width) - 1
    return tuple(sorted({value & top for value in (0, 1, 2, 3, 7, 8, 63, 64, 255, 4095, 4096, top, top >> 1, (top >> 1) + 1, 0x9E3779B97F4A7C15, 0xF0F0F0F0F0F0F0F0)}))


def _program(rng: random.Random, width: int, callees: list):
    """``f(a, b, c) -> bits<width>`` with a loop of up to 14 carried values and a diamond."""
    kind = bits_type(width)
    narrow = bits_type(max(1, width // 2))
    graph = GraphBuilder()
    entry = graph.block(kind, kind, kind)
    carried = rng.randrange(2, 15)
    loop = graph.block(kind, *([kind] * carried))
    body = graph.block(kind, *([kind] * carried))
    after = graph.block(*([kind] * carried))
    then, otherwise, join = graph.block(kind), graph.block(kind), graph.block(kind)

    def constant(block):
        return block.const(kind, rng.choice(_edges(width)) if rng.random() < 0.6 else rng.getrandbits(width))

    def step(block, pool):
        pick = lambda: rng.choice(pool) if rng.random() < 0.75 else constant(block)  # noqa: E731
        choice = rng.random()
        if choice < 0.55:
            return block.op1(rng.choice(BINARY), (pick(), pick()), kind)
        if choice < 0.65:
            divisor = block.op1(Operation.BIT_OR, (pick(), block.const(kind, 1)), kind)
            if rng.random() < 0.3:
                divisor = block.const(kind, rng.choice((1, 2, 8, 10, 1 << (width - 1))) & ((1 << width) - 1))
            return block.op1(rng.choice((Operation.UDIV, Operation.UREM)), (pick(), divisor), kind)
        if choice < 0.72:
            return block.op1(Operation.ROTATE_RIGHT, (pick(),), kind, attributes=(rng.randrange(0, width),))
        if choice < 0.82 and width > 1:
            low = block.op1(Operation.INT_TRUNCATE, (pick(),), narrow)
            return block.op1(Operation.INT_ZERO_EXTEND, (low,), kind)
        test = block.op1(Operation.INT_COMPARE, (pick(), pick()), B1, attributes=(rng.choice(tuple(IntCompare)),))
        return block.op1(Operation.INT_ZERO_EXTEND, (test,), kind)

    pool = list(entry.params)
    for _ in range(rng.randrange(2, 8)):
        pool.append(step(entry, pool))
    initial = [rng.choice(pool) for _ in range(carried)]
    entry.br(loop, entry.const(kind, 0), *initial)

    counter, *values = loop.params
    limit = loop.const(kind, rng.randrange(0, 5))
    loop.cbr(loop.op1(Operation.INT_COMPARE, (counter, limit), B1, attributes=(IntCompare.ULT,)), body, (counter, *values), after, tuple(values))

    counter, *values = body.params
    inner = [counter, *values, *rng.sample(pool, min(3, len(pool)))]  # entry values used by dominance
    for _ in range(rng.randrange(1, 6)):
        inner.append(step(body, inner))
    if callees and rng.random() < 0.6:
        inner.append(body.op1(Operation.CALL_DIRECT, tuple(rng.choice(inner) for _ in range(3)), kind, entity=rng.choice(callees)))
    following = [rng.choice(inner[-4:] + values) for _ in range(carried)]
    body.br(loop, body.op1(Operation.ADD_WRAP, (counter, body.const(kind, 1)), kind), *following)

    total = after.params[0]
    for value in after.params[1:]:
        total = after.op1(Operation.BIT_XOR, (after.op1(Operation.MUL_WRAP, (total, after.const(kind, 31)), kind), value), kind)
    test = after.op1(Operation.INT_COMPARE, (total, rng.choice(pool)), B1, attributes=(rng.choice(tuple(IntCompare)),))
    after.cbr(test, then, (total,), otherwise, (total,))
    then.br(join, then.op1(Operation.ADD_WRAP, (then.params[0], rng.choice(pool)), kind))
    otherwise.br(join, otherwise.op1(Operation.SUB_WRAP, (otherwise.params[0], constant(otherwise)), kind))
    join.ret(join.params[0])
    return graph, graph.function((kind, kind, kind), (kind,))


def corpus():
    rng = random.Random(SEED)
    target = aarch64_linux_exec_target()
    programs = []
    for width in WIDTHS:
        family, objects = [], []
        for _ in range(PER_WIDTH):
            graph, function = _program(rng, width, family)
            family.append(function)
            objects.extend(graph.objects.values())
            programs.append((width, function, tuple(objects)))
    return target, programs


def _run(reader, function, target, arguments):
    image = compile_aarch64_bound_target(reader, function.cid, target)
    return _run_aarch64_unicorn(image, arguments)


def _allocated(reader, function, target) -> bool:
    resolve = store_resolver(reader)
    return compile_linux_function(function, resolve, decode_native_target(target)) is not None


@unittest.skipUnless(_unicorn_available(), "requires unicorn")
class LinuxAArch64AllocatorDifferentialTests(unittest.TestCase):
    def test_random_programs_match_the_reference_executor(self):
        target, programs = corpus()
        rng = random.Random(SEED + 1)
        for width, function, objects in programs:
            reader = program_store(function, target, (B1, *objects))
            self.assertTrue(_allocated(reader, function, target), width)
            for _ in range(4):
                arguments = tuple(rng.choice(_edges(width)) if rng.random() < 0.5 else rng.getrandbits(width) for _ in range(3))
                expected = execute(reader, function.cid, arguments)
                self.assertEqual(_run(reader, function, target, arguments), (expected[0],), (width, arguments))

    def test_values_live_across_calls_survive_register_pressure(self):
        """30 values live across a call: callee-saved registers run out, so some live in frame slots."""
        b64 = bits_type(64)
        callee_graph = GraphBuilder()
        block = callee_graph.block(b64)
        block.ret(block.op1(Operation.MUL_WRAP, (block.params[0], block.const(b64, 3)), b64))
        callee = callee_graph.function((b64,), (b64,))
        graph = GraphBuilder()
        block = graph.block(b64, b64)
        a, b = block.params
        values = [block.op1(Operation.ADD_WRAP, (block.op1(Operation.MUL_WRAP, (a, block.const(b64, index * 2 + 3)), b64), b), b64) for index in range(30)]
        called = block.op1(Operation.CALL_DIRECT, (values[0],), b64, entity=callee)
        total = called
        for value in values:
            total = block.op1(Operation.BIT_XOR, (block.op1(Operation.MUL_WRAP, (total, block.const(b64, 1099511628211)), b64), value), b64)
        block.ret(total)
        function = graph.function((b64, b64), (b64,))
        target = aarch64_linux_exec_target()
        reader = program_store(function, target, (*callee_graph.objects.values(), callee, *graph.objects.values()))
        self.assertTrue(_allocated(reader, function, target))
        for arguments in ((0, 0), (1, 2), (0x9E3779B97F4A7C15, (1 << 64) - 1)):
            self.assertEqual(_run(reader, function, target, arguments), execute(reader, function.cid, arguments))

    def test_membership_bic_and_checked_accesses(self):
        """``x`` in {9, 10, 13, 32} (bit test), ``(t ^ 1) & u`` (bic), and a checked table access."""
        b64, b8 = bits_type(64), bits_type(8)
        graph = GraphBuilder()
        block = graph.block(b64, b64)
        x, flag = block.params
        tests = [block.op1(Operation.INT_ZERO_EXTEND, (block.op1(Operation.INT_COMPARE, (x, block.const(b64, value)), B1, attributes=(IntCompare.EQ,)),), b64) for value in (32, 10, 9, 13)]
        member = block.op1(Operation.BIT_OR, (block.op1(Operation.BIT_OR, (tests[0], tests[1]), b64), block.op1(Operation.BIT_OR, (tests[2], tests[3]), b64)), b64)
        bit = block.op1(Operation.INT_ZERO_EXTEND, (block.op1(Operation.INT_COMPARE, (flag, block.const(b64, 0)), B1, attributes=(IntCompare.NE,)),), b64)
        cleared = block.op1(Operation.BIT_AND, (block.op1(Operation.BIT_XOR, (member, block.const(b64, 1)), b64), bit), b64)
        far = [block.op1(Operation.INT_ZERO_EXTEND, (block.op1(Operation.INT_COMPARE, (x, block.const(b64, value)), B1, attributes=(IntCompare.EQ,)),), b64) for value in (100, 120, 140)]
        far_member = block.op1(Operation.BIT_OR, (block.op1(Operation.BIT_OR, (far[0], far[1]), b64), far[2]), b64)
        block.ret(block.op1(Operation.ADD_WRAP, (block.op1(Operation.ADD_WRAP, (member, block.op1(Operation.MUL_WRAP, (cleared, block.const(b64, 2)), b64)), b64), block.op1(Operation.MUL_WRAP, (far_member, block.const(b64, 4)), b64)), b64))
        function = graph.function((b64, b64), (b64,))
        target = aarch64_linux_exec_target()
        reader = program_store(function, target, (B1, b8, *graph.objects.values()))
        self.assertTrue(_allocated(reader, function, target))
        for value in (*range(0, 150), 255, 1 << 40, (1 << 64) - 1, (1 << 64) - 9):
            for flag_value in (0, 5):
                self.assertEqual(_run(reader, function, target, (value, flag_value)), execute(reader, function.cid, (value, flag_value)), value)

    def test_a_zero_constant_is_never_read_as_the_stack_pointer(self):
        """Register 31 is SP in add/sub/compare immediate forms: ``0 + 4096`` and ``0 < 5`` must not read SP."""
        b64 = bits_type(64)
        graph = GraphBuilder()
        block = graph.block(b64)
        (x,) = block.params
        total = block.op1(Operation.ADD_WRAP, (block.const(b64, 0), block.const(b64, 4096)), b64)
        less = block.op1(Operation.INT_ZERO_EXTEND, (block.op1(Operation.INT_COMPARE, (block.const(b64, 0), block.const(b64, 5)), B1, attributes=(IntCompare.ULT,)),), b64)
        block.ret(block.op1(Operation.ADD_WRAP, (block.op1(Operation.ADD_WRAP, (total, less), b64), x), b64))
        function = graph.function((b64,), (b64,))
        target = aarch64_linux_exec_target()
        reader = program_store(function, target, (B1, *graph.objects.values()))
        self.assertEqual(_run(reader, function, target, (7,)), (4096 + 1 + 7,))

    def test_division_by_zero_traps(self):
        import unicorn

        b32 = bits_type(32)
        graph = GraphBuilder()
        block = graph.block(b32, b32)
        a, b = block.params
        block.ret(block.op1(Operation.UREM, (a, b), b32))
        function = graph.function((b32, b32), (b32,))
        target = aarch64_linux_exec_target()
        reader = program_store(function, target, tuple(graph.objects.values()))
        self.assertEqual(_run(reader, function, target, (17, 5)), (2,))
        with self.assertRaises(unicorn.UcError):
            _run(reader, function, target, (17, 0))

    def test_byte_predicates_read_a_table(self):
        """ADR-254 (ADR-208 on AArch64): a byte-bounded predicate, as a value and as a branch, is one table load."""
        b64 = bits_type(64)
        graph = GraphBuilder()
        entry = graph.block(b64)
        yes, no = graph.block(), graph.block()
        (x,) = entry.params
        byte = entry.op1(Operation.BIT_AND, (x, entry.const(b64, 0xFF)), b64)

        def equal(value):
            return entry.op1(Operation.INT_COMPARE, (byte, entry.const(b64, value)), B1, attributes=(IntCompare.EQ,))

        member = entry.op1(Operation.INT_ZERO_EXTEND, (entry.op1(Operation.BIT_OR, (entry.op1(Operation.BIT_OR, (equal(32), equal(10)), B1), entry.op1(Operation.BIT_OR, (equal(9), equal(13)), B1)), B1),), b64)
        control = entry.op1(Operation.INT_COMPARE, (byte, entry.const(b64, 32)), B1, attributes=(IntCompare.ULT,))
        stop = entry.op1(Operation.BIT_OR, (entry.op1(Operation.BIT_OR, (equal(34), equal(92)), B1), control), B1)
        entry.cbr(stop, yes, (), no, ())
        yes.ret(yes.op1(Operation.ADD_WRAP, (member, yes.const(b64, 100)), b64))
        no.ret(no.op1(Operation.ADD_WRAP, (member, no.const(b64, 200)), b64))
        function = graph.function((b64,), (b64,))
        target = aarch64_linux_exec_target()
        reader = program_store(function, target, (B1, *graph.objects.values()))
        code = compile_linux_function(function, store_resolver(reader), decode_native_target(target))[0]
        self.assertIn(bytes(int(value in (32, 10, 9, 13)) for value in range(256)), code)
        self.assertIn(bytes(int(value in (34, 92) or value < 32) for value in range(256)), code)
        for value in (*range(256), 256 + 32, 1 << 40 | 92, (1 << 64) - 1):
            self.assertEqual(_run(reader, function, target, (value,)), execute(reader, function.cid, (value,)), value)


if __name__ == "__main__":
    unittest.main()
