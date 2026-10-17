"""S15e.2 (ADR-315, ADR-316): Linux AArch64 executables built by the XAX AArch64 program equal the bootstrap's.

``xax_linux_aarch64.compile_linux_aarch64_executable(..., frontend="xax")`` runs the XAX program (its front end, the
register allocator over the lowering view, the frame path over the function's own graph, the image and the ELF
container) and fails where it declines; ``frontend="python"`` is the bootstrap.  Differential, by bytes:

* seeded frame-path programs over floats, conversions, products, sums, aggregate and homogeneous-float arguments
  passed in registers, register pairs, by reference and on the stack;
* the register allocator's differential corpus, each function called from a process entry;
* rejections the program decides: a C import on the static profile (``AARCH64-FOREIGN-ABI``), a frame of 4096 bytes
  or more (``AARCH64-FRAME-SIZE``).

The driver's ``build`` of these targets is ``test_xax_selfhost_general_build``'s.
"""

from __future__ import annotations

import platform
import random
import sys
import unittest
from pathlib import Path

from xax_compiler import (
    Cursor, FloatCompare, FloatFormat, Operation, XaxError, aarch64_linux_exec_target, array_type, bits_type, decode_bits_width,
    float_constant, float_type, sum_type, tuple_type, verify_store,
)
from xax_graph_builder import GraphBuilder, program_store
from xax_linux_aarch64 import compile_linux_aarch64_executable, linux_aarch64_api

sys.path.insert(0, str(Path(__file__).resolve().parent))

LINUX_X86_64 = sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")
B1, B32, B64 = bits_type(1), bits_type(32), bits_type(64)
F32, F64 = float_type(FloatFormat.BINARY32), float_type(FloatFormat.BINARY64)
FLOATS = (0.0, -0.0, 1.0, -1.0, 0.5, 2.25, 3.0e9, -7.75, 65536.0, 1e-3, 255.0)


def _components(kind):
    """A product's component types (an array's element repeated); ``KNOWN`` resolves references."""
    cursor = Cursor(kind.body, "type")
    form = cursor.uleb()
    if form == 8:
        return tuple(KNOWN[kind.references[cursor.uleb()]] for _ in range(cursor.uleb()))
    element = KNOWN[kind.references[cursor.uleb()]]
    return (element,) * cursor.uleb()


PRODUCTS = (tuple_type((F32, F32)), tuple_type((F64, F64, F64)), tuple_type((B32, F32)), tuple_type((B64, B64)), tuple_type((B64, B64, B64)),
            array_type(B32, 4), tuple_type((F32, F32, F32, F32)))
KNOWN = {kind.cid: kind for kind in (B1, B32, B64, F32, F64, *PRODUCTS)}


def _float(block, kind, value):
    return block.op1(Operation.CONSTANT, (), kind, entity=float_constant(kind, value))


def _to_bits(rng, block, value, kind, width):
    """A float as ``bits<width>``: a compare extended, or a truncation (which may trap)."""
    if rng.random() < 0.5:
        test = block.op1(Operation.FLOAT_COMPARE, (value, _float(block, kind, rng.choice(FLOATS))), B1, attributes=(rng.choice(tuple(FloatCompare)),))
        return block.op1(Operation.INT_ZERO_EXTEND, (test,), bits_type(width))
    return block.op1(rng.choice((Operation.FLOAT_TO_UINT_TRUNC, Operation.FLOAT_TO_SINT_TRUNC)), (value,), bits_type(width))


def _float_ops(rng, block, pool, kind, count):
    for _ in range(count):
        pick = lambda: rng.choice(pool) if pool and rng.random() < 0.8 else _float(block, kind, rng.choice(FLOATS))  # noqa: E731
        choice = rng.random()
        if choice < 0.6:
            operation = rng.choice((Operation.FLOAT_ADD, Operation.FLOAT_SUB, Operation.FLOAT_MUL, Operation.FLOAT_DIV))
            pool.append(block.op1(operation, (pick(), pick()), kind))
        elif choice < 0.75:
            there = block.op1(Operation.FLOAT_CONVERT, (pick(),), F64 if kind is F32 else F32)
            pool.append(block.op1(Operation.FLOAT_CONVERT, (there,), kind))
        else:
            width = rng.choice((8, 16, 32, 64))
            source = block.const(bits_type(width), rng.getrandbits(width))
            pool.append(block.op1(rng.choice((Operation.UINT_TO_FLOAT, Operation.SINT_TO_FLOAT)), (source,), kind))


def frame_function(rng: random.Random):
    """``f(parameters) -> bits<32>`` over floats, products and a sum, so the bootstrap takes the frame path."""
    kinds = (F32, F64, B32, B64, *PRODUCTS)
    parameters = [rng.choice(kinds) for _ in range(rng.randrange(1, 11))]
    graph = GraphBuilder()
    entry = graph.block(*parameters)
    floats, doubles, integers = [], [], []
    for value, kind in zip(entry.params, parameters):
        components = ((value, kind),) if kind in (F32, F64, B32, B64) else tuple(
            (entry.op1(Operation.AGGREGATE_GET, (value,), component, attributes=(index,)), component) for index, component in enumerate(_components(kind)))
        for item, component in components:
            (floats if component is F32 else doubles if component is F64 else integers).append((item, component))
    floats, doubles = [item for item, _ in floats], [item for item, _ in doubles]
    _float_ops(rng, entry, floats, F32, rng.randrange(1, 6))
    _float_ops(rng, entry, doubles, F64, rng.randrange(1, 6))
    # A sum made in one variant, its tag branched on, read back.
    choice = sum_type((B32, F64))
    variant = rng.randrange(2)
    payload = rng.choice(doubles) if variant else entry.op1(Operation.INT_TRUNCATE, (_to_bits(rng, entry, rng.choice(floats), F32, 64),), B32)
    made = entry.op1(Operation.SUM_MAKE, (payload,), choice, attributes=(variant,))
    integral, floating, join = graph.block(choice, B32), graph.block(choice, B32), graph.block(B32)
    seed = _to_bits(rng, entry, rng.choice(doubles), F64, 32)
    entry.cbr(entry.op1(Operation.SUM_TAG, (made,), B1), floating, (made, seed), integral, (made, seed))
    got = integral.op1(Operation.SUM_GET, (integral.params[0],), B32, attributes=(0,))
    integral.br(join, integral.op1(Operation.ADD_WRAP, (got, integral.params[1]), B32))
    got = floating.op1(Operation.SUM_GET, (floating.params[0],), F64, attributes=(1,))
    floating.br(join, floating.op1(Operation.BIT_XOR, (_to_bits(rng, floating, got, F64, 32), floating.params[1]), B32))
    pair = tuple_type((B32, F32))
    product = join.op1(Operation.AGGREGATE_MAKE, (join.params[0], rng.choice(floats)), pair)
    total = join.op1(Operation.ADD_WRAP, (join.op1(Operation.AGGREGATE_GET, (product,), B32, attributes=(0,)),
                                          _to_bits(rng, join, join.op1(Operation.AGGREGATE_GET, (product,), F32, attributes=(1,)), F32, 32)), B32)
    for value, kind in integers[:4]:
        narrowed = value if kind is B32 else join.op1(Operation.INT_TRUNCATE, (value,), B32)
        total = join.op1(rng.choice((Operation.ADD_WRAP, Operation.BIT_XOR, Operation.MUL_WRAP)), (total, narrowed), B32)
    join.ret(total)
    return graph.function(tuple(parameters), (B32,)), parameters, (*graph.objects.values(), *KNOWN.values(), choice, pair)


def process_calling(function, argument_types, result_type, objects, rng: random.Random):
    """A process entry calling ``function`` with constants (products made from constants) and exiting with the low
    byte of its ``bits`` result."""
    api = linux_aarch64_api()
    graph = GraphBuilder()
    block = graph.block(api.process_effect, api.filesystem_effect)
    process, fs = block.params

    def constant(kind):
        if kind in (F32, F64):
            return _float(block, kind, rng.choice(FLOATS))
        if kind.body[0] == 1:
            return block.const(kind, rng.getrandbits(decode_bits_width(kind)))
        return block.op1(Operation.AGGREGATE_MAKE, tuple(constant(component) for component in _components(kind)), kind)

    result = block.op1(Operation.CALL_DIRECT, tuple(constant(kind) for kind in argument_types), result_type, entity=function)
    width = decode_bits_width(result_type)
    if width != 32:
        result = block.op1(Operation.INT_TRUNCATE if width > 32 else Operation.INT_ZERO_EXTEND, (result,), B32)
    status = block.op1(Operation.BIT_AND, (result, block.const(B32, 0xFF)), B32)
    process = block.op1(Operation.CALL_FOREIGN, (status, process), api.process_effect, entity=api.exit_group)
    block.ret(status, process, fs)
    entry = graph.function((api.process_effect, api.filesystem_effect), (B32, api.process_effect, api.filesystem_effect))
    target = aarch64_linux_exec_target()
    return program_store(entry, target, (*objects, *api.types, *graph.objects.values(), B1, B32)), entry, target


def frame_programs(count: int, seed: int):
    rng = random.Random(seed)
    for _ in range(count):
        function, parameters, objects = frame_function(rng)
        yield process_calling(function, parameters, B32, objects, rng)


def register_programs():
    """The register allocator's differential corpus (``test_xax_aarch64_linux_regalloc``), byte-wide results."""
    import test_xax_aarch64_linux_regalloc as corpus

    rng = random.Random(7)
    _target, programs = corpus.corpus()
    for width, function, objects in programs:
        if width in (8, 16, 32, 64):
            kind = bits_type(width)
            yield process_calling(function, (kind, kind, kind), kind, objects, rng)


def _outcome(reader, entry, target, frontend):
    try:
        return "image", compile_linux_aarch64_executable(reader, entry.cid, target.cid, frontend=frontend).data
    except XaxError as error:
        return "rejected", error.diagnostic


@unittest.skipUnless(LINUX_X86_64, "UNAVAILABLE: the XAX AArch64 program runs on Linux x86-64 only")
class XaxAarch64ProgramTests(unittest.TestCase):
    def assertSame(self, reader, entry, target):
        verify_store(reader)
        expected = _outcome(reader, entry, target, "python")
        self.assertEqual(_outcome(reader, entry, target, "xax"), expected)
        return expected

    def test_frame_path_programs(self):
        for index, (reader, entry, target) in enumerate(frame_programs(60, 20261017)):
            with self.subTest(index):
                self.assertEqual(self.assertSame(reader, entry, target)[0], "image")

    def test_register_path_programs(self):
        for index, (reader, entry, target) in enumerate(register_programs()):
            with self.subTest(index):
                self.assertEqual(self.assertSame(reader, entry, target)[0], "image")

    def test_the_frame_size_rejection(self):
        """600 float values live at once need more frame than the AArch64 immediate allows: ``AARCH64-FRAME-SIZE``."""
        rng = random.Random(1)
        graph = GraphBuilder()
        block = graph.block(F64)
        values = [_float(block, F64, float(k)) for k in range(600)]
        total = block.params[0]
        for value in values:
            total = block.op1(Operation.FLOAT_ADD, (total, value), F64)
        test = block.op1(Operation.FLOAT_COMPARE, (total, _float(block, F64, 1.0)), B1, attributes=(FloatCompare.LT,))
        block.ret(block.op1(Operation.INT_ZERO_EXTEND, (test,), B32))
        function = graph.function((F64,), (B32,))
        reader, entry, target = process_calling(function, (F64,), B32, tuple(graph.objects.values()), rng)
        kind, diagnostic = self.assertSame(reader, entry, target)
        self.assertEqual((kind, diagnostic.rule), ("rejected", "AARCH64-FRAME-SIZE"))

    def test_the_foreign_abi_rejection(self):
        """A C import on the static profile is the bootstrap's ``AARCH64-FOREIGN-ABI``, on both paths."""
        from test_xax_linux_aarch64 import _status_program
        from xax_compiler import aarch64_linux_exec_target as exec_target
        from xax_linux_aarch64 import c_function

        strlen = c_function(b"libc.so.6", b"strlen", (B64,), (B64,))
        for floating in (False, True):
            with self.subTest(floating=floating):
                def compute(block, floating=floating):
                    length = block.op1(Operation.CALL_FOREIGN, (block.const(B64, 0),), B64, entity=strlen)
                    if floating:
                        length = block.op1(Operation.FLOAT_TO_UINT_TRUNC, (block.op1(Operation.UINT_TO_FLOAT, (length,), F64),), B64)
                    return block.op1(Operation.INT_TRUNCATE, (length,), B32)

                reader, entry, target, _value = _status_program(compute)
                self.assertEqual(target.cid, exec_target().cid)
                kind, diagnostic = self.assertSame(reader, entry, target)
                self.assertEqual((kind, diagnostic.rule), ("rejected", "AARCH64-FOREIGN-ABI"))


if __name__ == "__main__":
    unittest.main()
