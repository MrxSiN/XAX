"""JVM linear memory (``jvm-classfile-memory-v1``, ADR-156).

Seeded programs allocate a block from the generated ``xax/jvm/Memory`` package,
store and load every access width (1, 2, 4, 8 bytes; integers and floats) at
random offsets, plain and checked, and return a 64-bit digest; a byte-level
mirror computes the expected digest.  Trap and profile cases check that checked
accesses, rebases, and null blocks trap, and that the v1 profile rejects memory.
"""

from __future__ import annotations

import random
import shutil
import struct
import unittest

from xax_compiler import (
    FloatFormat, IntCompare, Operation, XaxError, bits_type, float_type, heap_view_type, jvm_classfile_memory_target,
    jvm_classfile_target, pointer_type, Permission,
)
from xax_graph_builder import program_store
from xax_jvm import compile_jvm_bound_target, jvm_memory_api, run_jvm_calls
from xax_structured import B8, B32, B64, Proc

API = jvm_memory_api()
MEM = API.memory_effect
EXTENT = 64
VIEW = heap_view_type(EXTENT)
F32, F64 = float_type(FloatFormat.BINARY32), float_type(FloatFormat.BINARY64)
WIDTHS = {1: bits_type(8), 2: bits_type(16), 4: B32, 8: B64}
SEED, COUNT = 20261005, 24


def _program(rng: random.Random):
    """``f(a, b) -> b64`` over one block of one element type, and the mirror's expected result.

    Accesses must match the pointer's element size (``MEMORY-ACCESS-SIZE``), so
    each program picks one width; float programs store ``u16`` values converted
    exactly to f32/f64 and convert loads back, so the float load/store paths are
    covered without depending on rounding.
    """
    size = rng.choice((1, 2, 4, 8))
    floating = size in (4, 8) and rng.random() < 0.4
    kind = (F32 if size == 4 else F64) if floating else WIDTHS[size]
    element_pointer = pointer_type(kind, Permission.READ_WRITE, size, space=2)
    proc = Proc((("a", B64), ("b", B64), ("m", MEM)))
    raw, owner, effect = proc.op(Operation.CALL_FOREIGN, (proc.const(EXTENT, B64), proc.drop("m")), (API.bytes_rw, API.heap_owner, MEM), entity=API.mmap_anonymous)
    pointer, view, memory = proc.op(Operation.HEAP_VIEW, (raw, owner, effect), (element_pointer, VIEW, MEM), attributes=(EXTENT, size))
    steps = []
    digest = proc.const(0, B64)
    for _ in range(rng.randrange(4, 12)):
        offset = size * rng.randrange(0, EXTENT // size)
        checked = rng.random() < 0.5
        source = rng.choice(("a", "b"))
        if checked:
            def at():
                return proc.const(offset)
        else:
            def at():
                return proc.op1(Operation.ADDRESS_OFFSET, (pointer,), element_pointer, attributes=(offset,)) if offset else pointer
        if rng.random() < 0.5:
            if floating:
                small = proc.op1(Operation.INT_TRUNCATE, (proc[source],), bits_type(16))
                value = proc.op1(Operation.UINT_TO_FLOAT, (small,), kind)
            else:
                value = proc[source] if size == 8 else proc.op1(Operation.INT_TRUNCATE, (proc[source],), kind)
            if checked:
                memory = proc.op1(Operation.CHECKED_STORE_BITS_LE, (pointer, at(), value, memory), MEM, attributes=(size, 1))
            else:
                memory = proc.op1(Operation.STORE_BITS_LE, (at(), value, memory), MEM, attributes=(size, size))
            steps.append(("store", offset, source))
        else:
            if checked:
                loaded, memory = proc.op(Operation.CHECKED_LOAD_BITS_LE, (pointer, at(), memory), (kind, MEM), attributes=(size, 1))
            else:
                loaded, memory = proc.op(Operation.LOAD_BITS_LE, (at(), memory), (kind, MEM), attributes=(size, size))
            if floating:
                loaded = proc.op1(Operation.FLOAT_TO_UINT_TRUNC, (loaded,), B32)
            wide = loaded if size == 8 and not floating else proc.op1(Operation.INT_ZERO_EXTEND, (loaded,), B64)
            rotated = proc.op1(Operation.ROTATE_RIGHT, (digest,), B64, attributes=(7,))
            digest = proc.op1(Operation.BIT_XOR, (rotated, wide), B64)
            steps.append(("load", offset))
    _status, memory = proc.op(Operation.CALL_FOREIGN, (pointer, view, memory), (B64, MEM), entity=API.munmap_view(element_pointer, EXTENT))
    proc.ret(digest, memory)
    function = proc.function((B64, MEM))

    def expected(a: int, b: int) -> int:
        cells, value = {}, 0
        for step in steps:
            if step[0] == "store":
                source = a if step[2] == "a" else b
                cells[step[1]] = source & 0xFFFF if floating else source & ((1 << (8 * size)) - 1)
            else:
                loaded = cells.get(step[1], 0)
                value = (((value >> 7) | (value << 57)) & ((1 << 64) - 1)) ^ loaded
        return value

    return (*proc.graph.objects.values(), element_pointer, bits_type(16)), function, expected


def _image(functions_objects, function, target=None):
    target = target or jvm_classfile_memory_target()
    reader = program_store(function, target, (*API.types, *functions_objects, B8, B32, B64, F32, F64, VIEW))
    return compile_jvm_bound_target(reader, function.cid, target)


@unittest.skipUnless(shutil.which("java") and shutil.which("javac"), "requires a JDK")
class JvmMemoryTests(unittest.TestCase):
    def test_widths_and_floats_match_the_byte_mirror(self):
        rng = random.Random(SEED)
        for index in range(COUNT):
            objects, function, expected = _program(rng)
            image = _image(objects, function)
            calls = [(rng.getrandbits(64), rng.getrandbits(64)) for _ in range(3)] + [(0, (1 << 64) - 1)]
            with self.subTest(program=index):
                self.assertEqual(run_jvm_calls(image, calls, result_width=64), tuple(expected(a, b) for a, b in calls))

    def test_checked_access_outside_the_view_traps(self):
        words = pointer_type(B32, Permission.READ_WRITE, 4, space=2)
        proc = Proc((("i", B32), ("m", MEM)))
        raw, owner, effect = proc.op(Operation.CALL_FOREIGN, (proc.const(EXTENT, B64), proc.drop("m")), (API.bytes_rw, API.heap_owner, MEM), entity=API.mmap_anonymous)
        pointer, view, memory = proc.op(Operation.HEAP_VIEW, (raw, owner, effect), (words, VIEW, MEM), attributes=(EXTENT, 4))
        loaded, memory = proc.op(Operation.CHECKED_LOAD_BITS_LE, (pointer, proc["i"], memory), (B32, MEM), attributes=(4, 1))
        _status, memory = proc.op(Operation.CALL_FOREIGN, (pointer, view, memory), (B64, MEM), entity=API.munmap_view(words, EXTENT))
        proc.ret(loaded, memory)
        function = proc.function((B32, MEM))
        image = _image((*proc.graph.objects.values(), words), function)
        results = run_jvm_calls(image, [(0,), (EXTENT - 4,), (EXTENT - 3,), ((1 << 32) - 1,)], result_width=32)
        self.assertEqual(results[:2], (0, 0))
        self.assertEqual(results[2:], ("trap java.lang.Error",) * 2)

    def test_rebase_outside_the_view_traps(self):
        proc = Proc((("d", B64), ("m", MEM)))
        raw, owner, effect = proc.op(Operation.CALL_FOREIGN, (proc.const(EXTENT, B64), proc.drop("m")), (API.bytes_rw, API.heap_owner, MEM), entity=API.mmap_anonymous)
        pointer, view, memory = proc.op(Operation.HEAP_VIEW, (raw, owner, effect), (API.bytes_rw, VIEW, MEM), attributes=(EXTENT, 1))
        base = proc.op1(Operation.POINTER_ADDRESS, (pointer,), B64, attributes=(1,))
        window = proc.op1(Operation.POINTER_REBASE, (pointer, proc.bin(Operation.ADD_WRAP, base, proc["d"], B64)), API.bytes_rw, attributes=(8,))
        memory = proc.op1(Operation.CHECKED_STORE_BITS_LE, (window, proc.const(7), proc.const(0x5A, B8), memory), MEM, attributes=(1, 1))
        loaded, memory = proc.op(Operation.CHECKED_LOAD_BITS_LE, (pointer, proc.const(EXTENT - 1), memory), (B8, MEM), attributes=(1, 1))
        _status, memory = proc.op(Operation.CALL_FOREIGN, (pointer, view, memory), (B64, MEM), entity=API.munmap_view(API.bytes_rw, EXTENT))
        proc.ret(loaded, memory)
        function = proc.function((B8, MEM))
        image = _image(proc.graph.objects.values(), function)
        results = run_jvm_calls(image, [(EXTENT - 8,), (0,), (EXTENT - 7,), ((1 << 64) - 1,)], result_width=8)
        self.assertEqual(results, (0x5A, 0, "trap java.lang.Error", "trap java.lang.Error"))

    def test_an_oversized_request_is_a_null_block_and_its_view_traps(self):
        def program(size: int):
            proc = Proc((("m", MEM),))
            raw, owner, effect = proc.op(Operation.CALL_FOREIGN, (proc.const(size, B64), proc.drop("m")), (API.bytes_rw, API.heap_owner, MEM), entity=API.mmap_anonymous)
            pointer, view, memory = proc.op(Operation.HEAP_VIEW, (raw, owner, effect), (API.bytes_rw, VIEW, MEM), attributes=(EXTENT, 1))
            address = proc.op1(Operation.POINTER_ADDRESS, (pointer,), B64, attributes=(1,))
            _status, memory = proc.op(Operation.CALL_FOREIGN, (pointer, view, memory), (B64, MEM), entity=API.munmap_view(API.bytes_rw, EXTENT))
            proc.ret(proc.cmp(IntCompare.NE, address, 0, B64), memory)
            return proc.graph.objects.values(), proc.function((bits_type(1), MEM))

        self.assertEqual(run_jvm_calls(_image(*program(EXTENT)), [()], result_width=1), (1,))
        self.assertEqual(run_jvm_calls(_image(*program(1 << 31)), [()], result_width=1), ("trap java.lang.Error",))


class JvmMemoryProfileTests(unittest.TestCase):
    def test_the_v1_profile_rejects_memory(self):
        objects, function, _expected = _program(random.Random(SEED))
        with self.assertRaises(XaxError) as caught:
            _image(objects, function, jvm_classfile_target())
        self.assertEqual(caught.exception.diagnostic.rule, "JVM-OP-TARGET-SUPPORTED")

    def test_unknown_memory_members_reject(self):
        from xax_jvm import MEMORY_CLASS, jvm_static

        bogus = jvm_static(MEMORY_CLASS, b"peek(I)J", (pointer_type(B8, Permission.READ, 1, space=2), MEM), (B64, MEM))
        proc = Proc((("p", pointer_type(B8, Permission.READ, 1, space=2)), ("m", MEM)))
        value, memory = proc.op(Operation.CALL_FOREIGN, (proc["p"], proc["m"]), (B64, MEM), entity=bogus)
        proc.ret(value, memory)
        function = proc.function((B64, MEM))
        with self.assertRaises(XaxError) as caught:
            _image(proc.graph.objects.values(), function)
        self.assertEqual(caught.exception.diagnostic.rule, "JVM-MEMORY-MEMBER")


if __name__ == "__main__":
    unittest.main()
