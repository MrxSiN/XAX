"""JVM class-file backend (ADR-112): XAX semantics -> class file + JAR -> HotSpot.

Differential corpora compare every JVM result with the reference executor:
seeded random integer programs over widths 8/13/32/47/64 (straight-line DAGs,
a counted loop whose back edge rebinds its own block parameters, and calls),
and a float/conversion grid with signed zeros, NaN, infinities, and the
exact trap boundaries.  This is translation validation by execution over a
fixed corpus, not a proof.
"""

from __future__ import annotations

import hashlib
import math
import os
import random
import re
import shutil
import struct
import unittest

from xax_compiler import (
    FloatCompare,
    FloatFormat,
    IntCompare,
    Operation,
    Permission,
    SYSV_X86_64_C_ABI,
    XaxError,
    XaxTrap,
    bits_type,
    execute,
    float_constant,
    float_type,
    foreign_function_symbol,
    jvm_classfile_target,
    pointer_type,
    stack_owner_type,
    memory_effect_type,
    decode_native_target,
)
from xax_compiler import JVM_ABI, JVM_ARCHITECTURE, Kind, SemanticObject, uleb
from xax_graph_builder import GraphBuilder, program_store
from xax_jvm import (
    compile_jvm_bound_target,
    java_base_api,
    jvm_static,
    jvm_virtual,
    run_jvm_calls,
    run_jvm_jar,
)

JAVA = shutil.which("java") is not None and shutil.which("javac") is not None
B1 = bits_type(1)
F32, F64 = float_type(FloatFormat.BINARY32), float_type(FloatFormat.BINARY64)
BINARY = (Operation.ADD_WRAP, Operation.SUB_WRAP, Operation.MUL_WRAP, Operation.BIT_XOR, Operation.BIT_AND, Operation.BIT_OR, Operation.UDIV, Operation.UREM)


def _interesting(width: int) -> tuple[int, ...]:
    mask = (1 << width) - 1
    values = {0, 1, 2, 3, 7, mask, mask >> 1, (mask >> 1) + 1, 0x9E3779B97F4A7C15 & mask, 10 & mask}
    return tuple(sorted(values))


def _random_function(rng: random.Random, width: int, callees: tuple = ()):
    bw = bits_type(width)
    graph = GraphBuilder()
    entry = graph.block(bw, bw, bw)
    pool = list(entry.params)

    def value(block, values):
        if values and rng.random() < 0.8:
            return rng.choice(values)
        return block.const(bw, rng.choice(_interesting(width)) if rng.random() < 0.6 else rng.getrandbits(width))

    def step(block, values):
        choice = rng.random()
        if choice < 0.55:
            operation = rng.choice(BINARY)
            left, right = value(block, values), value(block, values)
            if operation in (Operation.UDIV, Operation.UREM):
                right = block.op1(Operation.BIT_OR, (right, block.const(bw, 1 << rng.randrange(width))), bw)
            return block.op1(operation, (left, right), bw)
        if choice < 0.72:
            flag = block.op1(Operation.INT_COMPARE, (value(block, values), value(block, values)), B1, attributes=(rng.choice(tuple(IntCompare)),))
            return block.op1(Operation.INT_ZERO_EXTEND, (flag,), bw)
        if choice < 0.85:
            return block.op1(Operation.ROTATE_RIGHT, (value(block, values),), bw, attributes=(rng.randrange(width),))
        narrow = bits_type(rng.randrange(2, width)) if width > 2 else bw
        truncated = block.op1(Operation.INT_TRUNCATE, (value(block, values),), narrow)
        return block.op1(Operation.INT_ZERO_EXTEND, (truncated,), bw)

    for _ in range(rng.randrange(3, 16)):
        pool.append(step(entry, pool))
    b8 = bits_type(8)
    loop = graph.block(b8, bw, bw)
    exit_block = graph.block(bw, bw)
    entry.br(loop, entry.const(b8, 0), pool[-1], pool[-2])
    counter, a, b = loop.params
    local = [a, b, *rng.sample(pool, min(3, len(pool)))]
    for _ in range(rng.randrange(2, 10)):
        local.append(step(loop, local))
    if callees:
        callee = rng.choice(callees)
        local.append(loop.op1(Operation.CALL_DIRECT, tuple(value(loop, local) for _ in range(3)), bw, entity=callee))
    following = loop.op1(Operation.ADD_WRAP, (counter, loop.const(b8, 1)), b8)
    condition = loop.op1(Operation.INT_COMPARE, (following, loop.const(b8, rng.randrange(1, 5))), B1, attributes=(IntCompare.ULT,))
    # The back edge passes (b, a) into (a, b): a parallel copy through the loop's own parameters.
    loop.cbr(condition, loop, (following, b if rng.random() < 0.5 else local[-1], a if rng.random() < 0.5 else local[-2]), exit_block, (local[-1], local[-3]))
    x, y = exit_block.params
    exit_block.ret(exit_block.op1(rng.choice(BINARY[:6]), (x, y), bw))
    return graph.function((bw, bw, bw), (bw,)), graph


def _compile(entry, objects, *, process_entry=False):
    target = jvm_classfile_target()
    reader = program_store(entry, target, objects)
    return reader, compile_jvm_bound_target(reader, entry.cid, target, process_entry=process_entry)


def _float_bits(value: float, width: int) -> int:
    return struct.unpack("<I", struct.pack("<f", value))[0] if width == 32 else struct.unpack("<Q", struct.pack("<d", value))[0]


def _same_float(left, right, width: int) -> bool:
    if isinstance(left, str) or isinstance(right, str):
        return left == right
    if math.isnan(left) or math.isnan(right):
        return math.isnan(left) and math.isnan(right)
    return _float_bits(left, width) == _float_bits(right, width)


def _reference(reader, cid, arguments):
    try:
        return execute(reader, cid, arguments)[0]
    except XaxTrap:
        return "trap"


@unittest.skipUnless(JAVA, "requires java and javac")
class JvmIntegerDifferentialTests(unittest.TestCase):
    SEED = 20261003
    PER_WIDTH = 6

    def test_random_programs_match_reference_executor(self):
        rng = random.Random(self.SEED)
        for width in (8, 13, 32, 47, 64):
            callees = []
            for index in range(self.PER_WIDTH):
                entry, graph = _random_function(rng, width, tuple(callees))
                objects = (*graph.objects.values(), *callees)
                callee_objects = [item for c in callees for item in _CALLEE_OBJECTS[c.cid]]
                reader, image = _compile(entry, (*objects, *callee_objects))
                _CALLEE_OBJECTS[entry.cid] = (*objects, *callee_objects)
                calls = [tuple(rng.choice(_interesting(width)) if rng.random() < 0.5 else rng.getrandbits(width) for _ in range(3)) for _ in range(6)]
                expected = tuple(_reference(reader, entry.cid, call) for call in calls)
                actual = run_jvm_calls(image, calls, result_width=width)
                with self.subTest(width=width, program=index):
                    self.assertEqual(actual, expected)
                callees.append(entry)

    def test_power_of_two_division_matches_reference(self):
        for width in (13, 32, 64):
            bw = bits_type(width)
            graph = GraphBuilder()
            block = graph.block(bw)
            (a,) = block.params
            quotient = block.op1(Operation.UDIV, (a, block.const(bw, 8)), bw)
            remainder = block.op1(Operation.UREM, (a, block.const(bw, 1 << (width - 1))), bw)
            block.ret(block.op1(Operation.ADD_WRAP, (quotient, remainder), bw))
            entry = graph.function((bw,), (bw,))
            reader, image = _compile(entry, tuple(graph.objects.values()))
            calls = [(value,) for value in _interesting(width)]
            with self.subTest(width=width):
                self.assertEqual(run_jvm_calls(image, calls, result_width=width), tuple(_reference(reader, entry.cid, call) for call in calls))

    def test_deep_long_expression_trees_get_their_stack(self):
        """ADR-257: single-use nodes are evaluated in place (ADR-157), so a balanced tree of 64-bit values holds one
        long per level on the operand stack; max_stack must cover it (the old fixed bound of 8 did not)."""
        b64 = bits_type(64)
        graph = GraphBuilder()
        block = graph.block(b64, b64, b64, b64)
        operations = (Operation.ADD_WRAP, Operation.MUL_WRAP, Operation.BIT_XOR, Operation.SUB_WRAP, Operation.BIT_OR)

        def tree(depth: int, at: int):
            if depth == 0:
                return block.params[at % 4]
            left, right = tree(depth - 1, 2 * at), tree(depth - 1, 2 * at + 1)
            return block.op1(operations[(depth + at) % len(operations)], (left, right), b64)

        block.ret(tree(6, 0))
        entry = graph.function((b64, b64, b64, b64), (b64,))
        reader, image = _compile(entry, tuple(graph.objects.values()))
        calls = [(1, 2, 3, 4), (0, (1 << 64) - 1, 1 << 63, 12345), tuple(random.Random(7).getrandbits(64) for _ in range(4))]
        self.assertEqual(run_jvm_calls(image, calls, result_width=64), tuple(_reference(reader, entry.cid, call) for call in calls))

    def test_subtraction_of_a_value_left_on_the_stack(self):
        # ADR-157: a value read once right after its definition stays on the operand
        # stack; only commutative operations may read it first.
        for width in (32, 64):
            bw = bits_type(width)
            graph = GraphBuilder()
            block = graph.block(bw, bw)
            a, b = block.params
            tripled = block.op1(Operation.MUL_WRAP, (b, block.const(bw, 3)), bw)
            difference = block.op1(Operation.SUB_WRAP, (a, tripled), bw)
            shifted = block.op1(Operation.ADD_WRAP, (b, block.const(bw, 5)), bw)
            block.ret(block.op1(Operation.SUB_WRAP, (difference, shifted), bw))
            entry = graph.function((bw, bw), (bw,))
            reader, image = _compile(entry, tuple(graph.objects.values()))
            calls = [(x, y) for x in _interesting(width) for y in (0, 1, 7, (1 << width) - 1)]
            with self.subTest(width=width):
                self.assertEqual(run_jvm_calls(image, calls, result_width=width), tuple(_reference(reader, entry.cid, call) for call in calls))

    def test_short_circuit_branches_match_reference(self):
        # ADR-157: a branch on an OR/AND tree of compares jumps per compare (javac's || and &&).
        from xax_structured import Proc

        b32 = bits_type(32)
        proc = Proc((("a", b32), ("b", b32), ("c", b32)))
        either = proc.any_of(proc.cmp(IntCompare.EQ, proc["a"], 1), proc.all_of(proc.cmp(IntCompare.ULT, proc["b"], 10), proc.cmp(IntCompare.NE, proc["c"], 0)))
        both = proc.all_of(proc.cmp(IntCompare.UGT, proc["a"], 100), proc.any_of(proc.cmp(IntCompare.EQ, proc["b"], 3), proc.cmp(IntCompare.EQ, proc["c"], 4)))
        proc.if_(either, lambda p: p.ret(p.const(7)))
        proc.if_(both, lambda p: p.ret(p.const(8)))
        proc.ret(proc.const(9))
        entry = proc.function((b32,))
        reader, image = _compile(entry, tuple(proc.graph.objects.values()))
        calls = [(a, b, c) for a in (0, 1, 101, (1 << 32) - 1) for b in (0, 3, 9, 10, (1 << 32) - 1) for c in (0, 4, 5)]
        self.assertEqual(run_jvm_calls(image, calls, result_width=32), tuple(_reference(reader, entry.cid, call) for call in calls))

    def test_rotate_shift_forms_match_reference(self):
        # ADR-157: a rotation of a zero-extended value no wider than the amount is a left
        # shift (and a 32-bit source then needs only i2l); a rotation read only through a
        # narrow enough truncation is a right shift.  Near misses keep the intrinsic.
        b8, b16, b32, b64 = bits_type(8), bits_type(16), bits_type(32), bits_type(64)
        graph = GraphBuilder()
        block = graph.block(b32, b32, b64)
        a, b, c = block.params

        def rotate(value, kind, amount):
            return block.op1(Operation.ROTATE_RIGHT, (value,), kind, attributes=(amount,))

        def zext(value, kind):
            return block.op1(Operation.INT_ZERO_EXTEND, (value,), kind)

        def trunc(value, kind):
            return block.op1(Operation.INT_TRUNCATE, (value,), kind)

        terms = [
            block.op1(Operation.BIT_OR, (rotate(zext(a, b64), b64, 32), zext(b, b64)), b64),  # pack
            zext(trunc(rotate(c, b64, 32), b32), b64),  # unpack the high half
            zext(trunc(rotate(c, b64, 40), b8), b64),
            rotate(zext(trunc(a, b16), b64), b64, 20),
            rotate(zext(a, b64), b64, 31),  # source wider than the amount
            zext(trunc(rotate(c, b64, 33), b32), b64),  # truncation wider than what a shift keeps
            zext(rotate(zext(trunc(b, b8), b32), b32, 12), b64),
            zext(trunc(rotate(trunc(c, b32), b32, 8), b16), b64),
        ]
        result = terms[0]
        for index, term in enumerate(terms[1:], 1):
            result = block.op1(Operation.BIT_XOR, (rotate(result, b64, index), term), b64)
        block.ret(result)
        entry = graph.function((b32, b32, b64), (b64,))
        reader, image = _compile(entry, tuple(graph.objects.values()))
        rng = random.Random(self.SEED)
        calls = [(x, y, z) for x in _interesting(32) for y in (0, (1 << 32) - 1) for z in (0, (1 << 64) - 1)]
        calls += [(rng.getrandbits(32), rng.getrandbits(32), rng.getrandbits(64)) for _ in range(16)]
        self.assertEqual(run_jvm_calls(image, calls, result_width=64), tuple(_reference(reader, entry.cid, call) for call in calls))


_CALLEE_OBJECTS: dict[bytes, tuple] = {}


def _binary_float(operation, width):
    ftype = F32 if width == 32 else F64
    graph = GraphBuilder()
    block = graph.block(ftype, ftype)
    a, b = block.params
    if operation in (Operation.FLOAT_ADD, Operation.FLOAT_SUB, Operation.FLOAT_MUL, Operation.FLOAT_DIV):
        block.ret(block.op1(operation, (a, b), ftype))
        return graph.function((ftype, ftype), (ftype,)), graph
    flag = block.op1(Operation.FLOAT_COMPARE, (a, b), B1, attributes=(operation,))
    block.ret(flag)
    return graph.function((ftype, ftype), (B1,)), graph


def _unary(operation, source, result):
    graph = GraphBuilder()
    block = graph.block(source)
    block.ret(block.op1(operation, block.params, result))
    return graph.function((source,), (result,)), graph


FLOATS = (0.0, -0.0, 1.5, -2.25, 0.1, 3.0, -1.0, 1e300, -1e300, 5e-324, math.inf, -math.inf, math.nan, 2.0 ** 63, 2.0 ** 64, 2.0 ** 31, -(2.0 ** 31), -(2.0 ** 31) - 1, 4294967295.5, 255.9, -0.5, 2.0 ** 63 - 1024)


@unittest.skipUnless(JAVA, "requires java and javac")
class JvmFloatDifferentialTests(unittest.TestCase):
    def _check(self, entry, graph, calls, width, *, float_result: bool):
        reader, image = _compile(entry, tuple(graph.objects.values()))
        expected = tuple(_reference(reader, entry.cid, call) for call in calls)
        actual = run_jvm_calls(image, calls, result_width=width)
        for call, left, right in zip(calls, actual, expected):
            if right == "trap":
                self.assertTrue(isinstance(left, str) and left.startswith("trap"), (call, left))
            elif float_result:
                self.assertTrue(_same_float(left, right, width), (call, left, right))
            else:
                self.assertEqual(left, right, call)

    def test_arithmetic_and_compares(self):
        for width in (32, 64):
            values = [v for v in FLOATS if width == 64 or not math.isfinite(v) or abs(v) < 3e38]
            if width == 32:
                values = [struct.unpack("<f", struct.pack("<f", v))[0] for v in values]
            calls = [(a, b) for a in values for b in values]
            for operation in (Operation.FLOAT_ADD, Operation.FLOAT_SUB, Operation.FLOAT_MUL, Operation.FLOAT_DIV):
                with self.subTest(width=width, operation=operation.name):
                    self._check(*_binary_float(operation, width), calls, width, float_result=True)
            for compare in FloatCompare:
                with self.subTest(width=width, compare=compare.name):
                    self._check(*_binary_float(compare, width), calls, 1, float_result=False)

    def test_conversions(self):
        integer_values = {8: (0, 1, 127, 128, 255), 32: (0, 1, (1 << 31) - 1, 1 << 31, (1 << 32) - 1, 16777217), 64: (0, 1, (1 << 53) + 1, (1 << 63) - 1, 1 << 63, (1 << 64) - 1, (1 << 63) + (1 << 40) + 1, 0x8000000000000401)}
        for fwidth, ftype in ((32, F32), (64, F64)):
            for iwidth, values in integer_values.items():
                itype = bits_type(iwidth)
                for operation in (Operation.UINT_TO_FLOAT, Operation.SINT_TO_FLOAT):
                    with self.subTest(op=operation.name, i=iwidth, f=fwidth):
                        self._check(*_unary(operation, itype, ftype), [(v,) for v in values], fwidth, float_result=True)
                floats = [v for v in FLOATS if fwidth == 64 or not math.isfinite(v) or abs(v) < 3e38]
                for operation in (Operation.FLOAT_TO_UINT_TRUNC, Operation.FLOAT_TO_SINT_TRUNC):
                    with self.subTest(op=operation.name, i=iwidth, f=fwidth):
                        self._check(*_unary(operation, ftype, itype), [(v,) for v in floats], iwidth, float_result=False)
        with self.subTest(op="FLOAT_CONVERT"):
            self._check(*_unary(Operation.FLOAT_CONVERT, F64, F32), [(v,) for v in FLOATS], 32, float_result=True)
            self._check(*_unary(Operation.FLOAT_CONVERT, F32, F64), [(v,) for v in (0.0, -0.0, 1.5, math.inf, math.nan, 0.1)], 64, float_result=True)

    def test_float_constants_keep_exact_bits(self):
        graph = GraphBuilder()
        block = graph.block()
        value = block.op1(Operation.CONSTANT, (), F64, entity=float_constant(F64, -0.0))
        block.ret(value)
        entry = graph.function((), (F64,))
        _reader, image = _compile(entry, tuple(graph.objects.values()))
        (result,) = run_jvm_calls(image, [()])
        self.assertEqual(_float_bits(result, 64), 1 << 63)


def _hello_program(status: int, *, divide_by_zero: bool = False):
    """Print 42 and sum_to(10) with System.out, then exit with ``status`` (or trap first)."""
    api = java_base_api()
    graph = GraphBuilder()
    block = graph.block(api.io_effect, api.process_effect)
    io, process = block.params
    stream, io = block.op(Operation.CALL_FOREIGN, (io,), (api.print_stream, api.io_effect), entity=api.system_out)
    io = block.op1(Operation.CALL_FOREIGN, (stream, block.const(api.b64, 42), io), api.io_effect, entity=api.println_long)
    total = block.const(api.b64, 0)
    for value in range(1, 11):
        total = block.op1(Operation.ADD_WRAP, (total, block.const(api.b64, value)), api.b64)
    if divide_by_zero:
        total = block.op1(Operation.UDIV, (total, block.const(api.b64, 0)), api.b64)
    io = block.op1(Operation.CALL_FOREIGN, (stream, total, io), api.io_effect, entity=api.println_long)
    root = block.op1(Operation.CALL_FOREIGN, (block.op1(Operation.CONSTANT, (), api.f64, entity=float_constant(api.f64, 2.0)),), api.f64, entity=api.sqrt)
    io = block.op1(Operation.CALL_FOREIGN, (stream, root, io), api.io_effect, entity=api.println_double)
    bits = block.op1(Operation.CALL_FOREIGN, (block.const(api.b64, 0xFF00),), api.b32, entity=api.bit_count)
    io = block.op1(Operation.CALL_FOREIGN, (stream, block.op1(Operation.INT_ZERO_EXTEND, (bits,), api.b64), io), api.io_effect, entity=api.println_long)
    io = block.op1(Operation.CALL_FOREIGN, (stream, block.const(api.b16, ord("Z")), io), api.io_effect, entity=api.print_char)
    io = block.op1(Operation.CALL_FOREIGN, (stream, io), api.io_effect, entity=api.flush)
    process = block.op1(Operation.CALL_FOREIGN, (block.const(api.b32, status), process), api.process_effect, entity=api.exit)
    block.ret(io, process)
    entry = graph.function((api.io_effect, api.process_effect), (api.io_effect, api.process_effect))
    return entry, (*api.types, *graph.objects.values())


@unittest.skipUnless(JAVA, "requires java and javac")
class JvmPlatformTests(unittest.TestCase):
    def test_jar_runs_under_java_launcher_with_platform_calls(self):
        entry, objects = _hello_program(7)
        _reader, image = _compile(entry, objects, process_entry=True)
        completed = run_jvm_jar(image)
        self.assertEqual(completed.returncode, 7, completed.stderr)
        self.assertEqual(completed.stdout, os.linesep.encode().join((b"42", b"55", b"1.4142135623730951", b"8", b"Z")))
        self.assertEqual(completed.stderr, b"")

    def test_artifact_is_deterministic(self):
        entry, objects = _hello_program(0)
        first = _compile(entry, objects, process_entry=True)[1]
        second = _compile(entry, objects, process_entry=True)[1]
        self.assertEqual(first.jar, second.jar)
        self.assertEqual(hashlib.sha256(first.jar).hexdigest(), hashlib.sha256(second.jar).hexdigest())
        self.assertIn(b"Main-Class: " + first.class_name.replace("/", ".").encode(), first.jar)

    def test_trap_stack_trace_names_the_semantic_node(self):
        entry, objects = _hello_program(0, divide_by_zero=True)
        _reader, image = _compile(entry, objects, process_entry=True)
        completed = run_jvm_jar(image)
        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(completed.stdout, b"42" + os.linesep.encode())  # the program stops at the trap
        stderr = completed.stderr.decode()
        self.assertIn("java.lang.ArithmeticException", stderr)
        line = int(re.search(r"\.entry\(XAX:(\d+)\)", stderr).group(1))
        (function_cid, block, node) = next((cid, b, n) for method, number, cid, b, n in image.line_map if method == "entry" and number == line)
        self.assertEqual((function_cid, block), (entry.cid, 0))
        from xax_compiler import _decode_function_interface, _parse_graph
        from xax_compiler import store_resolver as resolver_of
        reader = _reader
        resolve = resolver_of(reader)
        graph = _parse_graph(_decode_function_interface(entry, resolve)[0], resolve)
        self.assertEqual(graph.blocks[0].nodes[node].operation, Operation.UDIV)

    def test_workspace_maps_semantic_nodes_into_the_jar(self):
        from xax_workspace import Workspace

        entry, objects = _hello_program(0)
        reader, _image = _compile(entry, objects)
        workspace = Workspace(reader, jvm_classfile_target())
        artifact = workspace.artifact(entry.cid)
        self.assertEqual((artifact.classification, artifact.format), ("derived", "jvm-classfile-v1"))
        mapping = workspace.map_semantic(artifact.entry_handle, artifact.handle, 8)
        self.assertTrue(any(item.end > item.start for item in mapping.ranges))

    def test_semantic_ranges_point_into_the_jar(self):
        entry, objects = _hello_program(0)
        _reader, image = _compile(entry, objects, process_entry=True)
        whole = [item for item in image.semantic_ranges if item.block_index is None]
        self.assertEqual(len(whole), 1)
        start = image.jar.index(image.class_bytes)
        self.assertTrue(start <= whole[0].start < whole[0].end <= start + len(image.class_bytes))


@unittest.skipUnless(JAVA, "requires java and javac")
class JvmBuildTests(unittest.TestCase):
    def test_package_build_emits_executable_jar_with_provenance(self):
        from xax_build import ArtifactKind, build, build_profile, build_request, package, resolve_packages, snapshot_store, trust_policy

        entry, objects = _hello_program(3)
        reader, direct = _compile(entry, objects, process_entry=True)
        module = next(item for item in reader.objects() if item.kind == Kind.MODULE)
        target = jvm_classfile_target()
        app = package(b"jvm-hello", (module,), build_entries=((b"main", entry),))
        profile, policy = build_profile(), trust_policy()
        results = {}
        for kind in (ArtifactKind.JVM_EXECUTABLE_JAR, ArtifactKind.JVM_LIBRARY_JAR, ArtifactKind.NATIVE_IMAGE):
            request = build_request(app, b"main", target, profile, requested_artifacts=(kind,))
            candidates = (*tuple(reader.objects()), app, profile, policy, request)
            snapshot = snapshot_store(resolve_packages(request, candidates, policy, b"jvm-resolver-v1"), candidates)
            if kind == ArtifactKind.NATIVE_IMAGE:
                with self.assertRaises(XaxError) as raised:
                    build(snapshot, request.cid)
                self.assertEqual(raised.exception.diagnostic.rule, "BUILD-ARTIFACT-SUPPORTED")
                continue
            results[kind] = build(snapshot, request.cid)
        self.assertEqual(results[ArtifactKind.JVM_EXECUTABLE_JAR].artifact, direct.jar)
        self.assertNotIn(b"Main-Class", results[ArtifactKind.JVM_LIBRARY_JAR].artifact)
        self.assertTrue(results[ArtifactKind.JVM_EXECUTABLE_JAR].provenance.references)


@unittest.skipUnless(JAVA, "requires java and javac")
class JvmTrapTests(unittest.TestCase):
    def test_explicit_trap_and_division_by_zero(self):
        b32 = bits_type(32)
        graph = GraphBuilder()
        entry_block = graph.block(b32, b32)
        a, b = entry_block.params
        trap_block = graph.block()
        done = graph.block(b32)
        is_seven = entry_block.op1(Operation.INT_COMPARE, (a, entry_block.const(b32, 7)), B1, attributes=(IntCompare.EQ,))
        entry_block.cbr(is_seven, trap_block, (), done, (entry_block.op1(Operation.UDIV, (a, b), b32),))
        from xax_compiler import Terminator, TerminatorKind
        trap_block.terminator = Terminator(TerminatorKind.TRAP)
        done.ret(done.params[0])
        entry = graph.function((b32, b32), (b32,))
        reader, image = _compile(entry, tuple(graph.objects.values()))
        results = run_jvm_calls(image, [(9, 2), (9, 0), (7, 1), ((1 << 32) - 1, 3)], result_width=32)
        self.assertEqual(results, (4, "trap java.lang.ArithmeticException", "trap java.lang.Error", 0x55555555))
        self.assertEqual(execute(reader, entry.cid, (9, 2)), (4,))


class JvmNegativeTests(unittest.TestCase):
    def test_foreign_abi_from_another_platform_rejects(self):
        b32 = bits_type(32)
        foreign = foreign_function_symbol(b"libm.so.6", b"abs", (b32,), (b32,), abi=SYSV_X86_64_C_ABI)
        graph = GraphBuilder()
        block = graph.block(b32)
        block.ret(block.op1(Operation.CALL_FOREIGN, block.params, b32, entity=foreign))
        entry = graph.function((b32,), (b32,))
        with self.assertRaises(XaxError) as raised:
            _compile(entry, tuple(graph.objects.values()))
        self.assertEqual(raised.exception.diagnostic.code, "XAX.FOREIGN.ABI")

    def test_descriptor_type_mismatch_rejects(self):
        api = java_base_api()
        wrong = jvm_virtual(b"java/io/PrintStream", b"println(J)V", (api.print_stream, api.b32, api.io_effect), (api.io_effect,))
        graph = GraphBuilder()
        block = graph.block(api.io_effect)
        stream, io = block.op(Operation.CALL_FOREIGN, block.params, (api.print_stream, api.io_effect), entity=api.system_out)
        io = block.op1(Operation.CALL_FOREIGN, (stream, block.const(api.b32, 1), io), api.io_effect, entity=wrong)
        block.ret(io)
        entry = graph.function((api.io_effect,), (api.io_effect,))
        with self.assertRaises(XaxError) as raised:
            _compile(entry, (*api.types, *graph.objects.values()))
        self.assertEqual(raised.exception.diagnostic.rule, "JVM-FOREIGN-DESCRIPTOR-TYPE")

    def test_static_arity_mismatch_rejects(self):
        b64 = bits_type(64)
        wrong = jvm_static(b"java/lang/Long", b"bitCount(J)I", (b64, b64), (bits_type(32),))
        graph = GraphBuilder()
        block = graph.block(b64)
        block.ret(block.op1(Operation.CALL_FOREIGN, (block.params[0], block.params[0]), bits_type(32), entity=wrong))
        entry = graph.function((b64,), (bits_type(32),))
        with self.assertRaises(XaxError) as raised:
            _compile(entry, tuple(graph.objects.values()))
        self.assertEqual(raised.exception.diagnostic.rule, "JVM-FOREIGN-ARITY")

    def test_process_entry_with_machine_values_rejects(self):
        b32 = bits_type(32)
        graph = GraphBuilder()
        block = graph.block(b32)
        block.ret(block.params[0])
        entry = graph.function((b32,), (b32,))
        with self.assertRaises(XaxError) as raised:
            _compile(entry, tuple(graph.objects.values()), process_entry=True)
        self.assertEqual(raised.exception.diagnostic.rule, "JVM-PROCESS-ENTRY-CONTRACT")

    def test_memory_operations_are_not_in_the_profile(self):
        b32 = bits_type(32)
        pointer = pointer_type(b32, Permission.READ_WRITE, 4)
        graph = GraphBuilder()
        block = graph.block()
        _p, owner, memory = block.op(Operation.STACK_ALLOC, (), (pointer, stack_owner_type(), memory_effect_type()), attributes=(4, 4))
        block.op(Operation.STACK_END, (owner, memory), ())
        block.ret()
        entry = graph.function((), ())
        with self.assertRaises(XaxError) as raised:
            _compile(entry, (b32, *graph.objects.values()))
        self.assertEqual(raised.exception.diagnostic.code, "XAX.JVM.UNSUPPORTED_OPERATION")

    def test_target_machine_tuple_is_exact(self):
        identity = b"jvm-classfile-v1"
        body = bytearray(uleb(len(identity)) + identity)
        for value in (1, JVM_ARCHITECTURE, JVM_ABI, 1, 64, 32):
            body.extend(uleb(value))
        body.extend(uleb(1) + bytes((1,)) + uleb(1) + bytes((3,)))
        with self.assertRaises(XaxError) as raised:
            decode_native_target(SemanticObject.create(Kind.TARGET, bytes(body)))
        self.assertEqual(raised.exception.diagnostic.rule, "TARGET-JVM-CLASSFILE")


if __name__ == "__main__":
    unittest.main()
