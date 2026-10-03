"""S5a (ADR-140): the XAX RISC-V backend program produces the bootstrap's images byte for byte.

Random integer programs with calls (five widths), 64-bit constant edge cases
for the ``li`` planner, register pressure that spills through loop
parameters, frames past the 12-bit offset range, traps, and erased proof
calls compile to identical ``Riscv64Image`` values (code, offsets, semantic
ranges) with ``backend="xax"`` (which fails if the XAX program declines) and
``backend="python"``; rejected programs raise the same diagnostic either way.
"""

from __future__ import annotations

import platform
import random
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))  # sibling suites' program builders

from xax_compiler import IntCompare, Operation, XaxError, bits_type, riscv64_baremetal_target
from xax_graph_builder import GraphBuilder, program_store
from xax_riscv64 import compile_riscv64_bound_target

LINUX_X86_64 = sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")
B1, B8, B64 = bits_type(1), bits_type(8), bits_type(64)


def _both(entry, objects):
    target = riscv64_baremetal_target()
    reader = program_store(entry, target, objects)
    return (compile_riscv64_bound_target(reader, entry.cid, target, backend="python"),
            compile_riscv64_bound_target(reader, entry.cid, target, backend="xax"))


def _pressure(count: int, rounds: int = 5):
    """``count`` 64-bit values live around a loop whose back edge rotates them (overlapping copies)."""
    graph = GraphBuilder()
    entry_block = graph.block(B64, B64)
    a, b = entry_block.params
    values = [entry_block.op1(Operation.ADD_WRAP, (entry_block.op1(Operation.MUL_WRAP, (a, entry_block.const(B64, k + 3)), B64), b), B64) for k in range(count)]
    loop = graph.block(B8, *(B64,) * count)
    exit_block = graph.block(*(B64,) * count)
    entry_block.br(loop, entry_block.const(B8, 0), *values)
    counter, *carried = loop.params
    rotated = [loop.op1(Operation.BIT_XOR, (carried[(k + 1) % count], carried[k]), B64) for k in range(count)]
    following = loop.op1(Operation.ADD_WRAP, (counter, loop.const(B8, 1)), B8)
    condition = loop.op1(Operation.INT_COMPARE, (following, loop.const(B8, rounds)), B1, attributes=(IntCompare.ULT,))
    loop.cbr(condition, loop, (following, *rotated[1:], rotated[0]), exit_block, tuple(carried))
    total = exit_block.params[0]
    for value in exit_block.params[1:]:
        total = exit_block.op1(Operation.ADD_WRAP, (exit_block.op1(Operation.MUL_WRAP, (total, exit_block.const(B64, 31)), B64), value), B64)
    exit_block.ret(total)
    return graph.function((B64, B64), (B64,)), tuple(graph.objects.values())


@unittest.skipUnless(LINUX_X86_64, "requires a Linux x86-64 host")
class SelfhostRiscv64BackendTests(unittest.TestCase):
    def assertSameImage(self, entry, objects):
        python, xax = _both(entry, objects)
        self.assertEqual(xax, python)

    def test_random_programs_are_byte_identical(self):
        from test_xax_jvm import _random_function

        rng = random.Random(140)
        for width in (8, 13, 32, 47, 64):
            callees, callee_objects = [], []
            for index in range(12):
                entry, graph = _random_function(rng, width, tuple(callees))
                with self.subTest(width=width, program=index):
                    self.assertSameImage(entry, (*graph.objects.values(), *callees, *callee_objects))
                callees.append(entry)
                callee_objects.extend(graph.objects.values())

    def test_constant_planner_edges(self):
        rng = random.Random(7)
        values = [0, 1, 2047, 2048, (1 << 64) - 2048, (1 << 64) - 2049, 0x7FFFF7FF, 0x7FFFF800, 0x80000000, 0xFFFFFFFF, (1 << 64) - (1 << 31),
                  (1 << 64) - (1 << 31) - 1, 0x7FFFFFFFFFFFFFFF, 0x8000000000000000, 0xFFFFFFFFFFFFFFFF, 0x9E3779B97F4A7C15, 1 << 40, 0x0FFF_F000_0000_0FFF,
                  *(rng.getrandbits(64) for _ in range(40)), *(rng.getrandbits(rng.randrange(1, 64)) << rng.randrange(0, 20) & ((1 << 64) - 1) for _ in range(40))]
        for value in values:
            graph = GraphBuilder()
            block = graph.block()
            block.ret(block.const(B64, value))
            entry = graph.function((), (B64,))
            with self.subTest(value=hex(value)):
                self.assertSameImage(entry, tuple(graph.objects.values()))

    def test_spills_and_frames_past_the_immediate_range(self):
        for count in (12, 24, 300):  # 300 spilled values put slots past 2047 bytes
            with self.subTest(count=count):
                self.assertSameImage(*_pressure(count))

    def test_traps_and_division(self):
        b32 = bits_type(32)
        graph = GraphBuilder()
        entry_block = graph.block(b32, b32)
        x, y = entry_block.params
        trap_block, divide_block = graph.block(), graph.block(b32, b32)
        zero = entry_block.op1(Operation.INT_COMPARE, (x, entry_block.const(b32, 0)), B1, attributes=(IntCompare.EQ,))
        entry_block.cbr(zero, trap_block, (), divide_block, (x, y))
        trap_block.trap()
        p, q = divide_block.params
        divide_block.ret(divide_block.op1(Operation.UREM, (divide_block.op1(Operation.UDIV, (p, q), b32), divide_block.const(b32, 7)), b32))
        entry = graph.function((b32, b32), (b32,))
        self.assertSameImage(entry, tuple(graph.objects.values()))

    def test_closure_skips_erased_proof_callees_and_unreachable_functions(self):
        from xax_compiler import EffectDomain, effect_type

        io = effect_type(EffectDomain.IO)
        callee_graph = GraphBuilder()
        callee_block = callee_graph.block(io)
        callee_block.ret(*callee_block.params)
        erased = callee_graph.function((io,), (io,))
        unused_graph = GraphBuilder()
        unused_block = unused_graph.block(B64)
        unused_block.ret(unused_block.op1(Operation.ADD_WRAP, (unused_block.params[0], unused_block.const(B64, 1)), B64))
        unused = unused_graph.function((B64,), (B64,))
        graph = GraphBuilder()
        block = graph.block(B64, io)
        value, effect = block.params
        (effect,) = block.op(Operation.CALL_DIRECT, (effect,), (io,), entity=erased)
        block.ret(block.op1(Operation.MUL_WRAP, (value, block.const(B64, 3)), B64), effect)
        entry = graph.function((B64, io), (B64, io))
        objects = (*graph.objects.values(), *callee_graph.objects.values(), *unused_graph.objects.values(), erased, unused)
        python, xax = _both(entry, objects)
        self.assertEqual(xax, python)
        self.assertEqual([cid for cid, _offset in xax.function_offsets], [entry.cid])

    def test_rejections_keep_the_bootstrap_diagnostic(self):
        graph = GraphBuilder()
        block = graph.block(*(B64,) * 9)
        total = block.params[0]
        for value in block.params[1:]:
            total = block.op1(Operation.ADD_WRAP, (total, value), B64)
        block.ret(total)
        entry = graph.function((B64,) * 9, (B64,))
        target = riscv64_baremetal_target()
        reader = program_store(entry, target, tuple(graph.objects.values()))
        rules = []
        for backend in ("python", "auto"):
            with self.assertRaises(XaxError) as raised:
                compile_riscv64_bound_target(reader, entry.cid, target, backend=backend)
            rules.append(raised.exception.diagnostic.rule)
        self.assertEqual(rules[0], rules[1])
        self.assertEqual(rules[0], "RISCV64-REGISTER-ARGUMENTS")

    def test_committed_store_is_the_built_program(self):
        from xax_selfhost_riscv64_backend import STORE_PATH, build_backend_program

        reader, _function = build_backend_program()
        self.assertEqual(STORE_PATH.read_bytes(), reader.data)


if __name__ == "__main__":
    unittest.main()
