"""S15e.5a-b (ADR-327, ADR-328): JVM JARs built by the XAX JVM program equal the bootstrap's.

``xax_selfhost_jvm.jvm_jar(..., frontend="xax")`` runs the XAX program and fails where it declines;
``frontend="python"`` is ``compile_jvm_bound_target``.  Differential, by bytes, over seeded integer programs of
``test_xax_jvm._random_function`` (widths 8/13/32/47/64, a counted loop rebinding its own parameters, direct calls),
executable JARs with a proof-only entry, the float operations and conversions over every width pair (the trapping
truncations included), and the rejections the program decides (``JVM-ENTRY-FUNCTION``, ``JVM-PROCESS-ENTRY-CONTRACT``).
"""

from __future__ import annotations

import platform
import random
import sys
import unittest
from pathlib import Path

from xax_compiler import FloatCompare, FloatFormat, Operation, XaxError, bits_type, float_type, jvm_classfile_target
from xax_graph_builder import GraphBuilder, program_store
from xax_selfhost_jvm import jvm_jar

sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_xax_jvm import _binary_float, _random_function, _unary  # noqa: E402

LINUX_X86_64 = sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")


def _outcome(reader, cid, target, frontend, process_entry):
    try:
        return "jar", jvm_jar(reader, cid, target, process_entry=process_entry, frontend=frontend)
    except XaxError as error:
        return "rejected", error.diagnostic


def _random_case(seed: int):
    rng = random.Random(seed)
    width = rng.choice((8, 13, 32, 47, 64))
    objects: list = []
    callees: tuple = ()
    if rng.random() < 0.4:
        callee, graph = _random_function(rng, width)
        callees = (callee,)
        objects += [callee, *graph.objects.values()]
    entry, graph = _random_function(rng, width, callees)
    return entry, [*graph.objects.values(), *objects], rng.random() < 0.3


def _proof_entry(width: int):
    """An executable JAR's entry: no machine values, a call of an integer function."""
    bw = bits_type(width)
    inner = GraphBuilder()
    block = inner.block(bw)
    block.ret(block.op1(Operation.ADD_WRAP, (block.params[0], block.const(bw, 3)), bw))
    callee = inner.function((bw,), (bw,))
    graph = GraphBuilder()
    block = graph.block()
    block.op1(Operation.CALL_DIRECT, (block.const(bw, 4),), bw, entity=callee)
    block.ret()
    entry = graph.function((), ())
    return entry, [*graph.objects.values(), callee, *inner.objects.values()]


@unittest.skipUnless(LINUX_X86_64, "the XAX JVM program runs natively on Linux x86-64")
class SelfhostJvmTests(unittest.TestCase):
    def _agree(self, entry, objects, process_entry):
        target = jvm_classfile_target()
        reader = program_store(entry, target, objects)
        expected = _outcome(reader, entry.cid, target, "python", process_entry)
        self.assertEqual(_outcome(reader, entry.cid, target, "xax", process_entry), expected)
        return expected

    def test_random_integer_programs(self):
        kinds = set()
        for seed in range(80):
            with self.subTest(seed=seed):
                entry, objects, process_entry = _random_case(seed)
                kinds.add(self._agree(entry, objects, process_entry)[0])
        self.assertEqual(kinds, {"jar", "rejected"})

    def test_process_entry_rejection_is_the_bootstraps(self):
        entry, objects, _ = _random_case(3)
        kind, diagnostic = self._agree(entry, objects, True)
        self.assertEqual((kind, diagnostic.rule), ("rejected", "JVM-PROCESS-ENTRY-CONTRACT"))

    def test_executable_jars(self):
        for width in (8, 32, 47, 64):
            with self.subTest(width=width):
                entry, objects = _proof_entry(width)
                self.assertEqual(self._agree(entry, objects, True)[0], "jar")

    def test_float_operations(self):
        for width in (32, 64):
            for operation in (Operation.FLOAT_ADD, Operation.FLOAT_SUB, Operation.FLOAT_MUL, Operation.FLOAT_DIV, *FloatCompare):
                with self.subTest(width=width, operation=operation.name):
                    entry, graph = _binary_float(operation, width)
                    self.assertEqual(self._agree(entry, tuple(graph.objects.values()), False)[0], "jar")

    def test_float_conversions(self):
        floats = {32: float_type(FloatFormat.BINARY32), 64: float_type(FloatFormat.BINARY64)}
        for fwidth, ftype in floats.items():
            for iwidth in (1, 2, 8, 13, 24, 25, 32, 47, 53, 54, 64):
                itype = bits_type(iwidth)
                for operation, source, result in ((Operation.UINT_TO_FLOAT, itype, ftype), (Operation.SINT_TO_FLOAT, itype, ftype),
                                                  (Operation.FLOAT_TO_UINT_TRUNC, ftype, itype), (Operation.FLOAT_TO_SINT_TRUNC, ftype, itype)):
                    with self.subTest(operation=operation.name, i=iwidth, f=fwidth):
                        entry, graph = _unary(operation, source, result)
                        self.assertEqual(self._agree(entry, tuple(graph.objects.values()), False)[0], "jar")
            other = floats[96 - fwidth]
            with self.subTest(operation="FLOAT_CONVERT", f=fwidth):
                entry, graph = _unary(Operation.FLOAT_CONVERT, ftype, other)
                self.assertEqual(self._agree(entry, tuple(graph.objects.values()), False)[0], "jar")

    def test_entry_must_be_a_function(self):
        target = jvm_classfile_target()
        entry, objects, _ = _random_case(1)
        b8 = bits_type(8)
        reader = program_store(entry, target, (*objects, b8))
        expected = _outcome(reader, b8.cid, target, "python", False)
        self.assertEqual(expected[0], "rejected")
        self.assertEqual(_outcome(reader, b8.cid, target, "xax", False), expected)


if __name__ == "__main__":
    unittest.main()
