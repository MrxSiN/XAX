"""S15e.5a-e (ADR-327-ADR-331): JVM JARs built by the XAX JVM program equal the bootstrap's.

``xax_selfhost_jvm.jvm_jar(..., frontend="xax")`` runs the XAX program and fails where it declines;
``frontend="python"`` is ``compile_jvm_bound_target``.  Differential, by bytes, over seeded integer programs of
``test_xax_jvm._random_function`` (widths 8/13/32/47/64, a counted loop rebinding its own parameters, direct calls),
executable JARs with a proof-only entry, the float operations and conversions over every width pair (the trapping
truncations included), platform calls over references (static, virtual, interface, static fields; narrow parameters
and results), the object kinds (``new``, arrays, ``ldc``, instance and static fields, casts), and the rejections the
program decides, callbacks on the general profile (the JDK stream pipeline, a comparator over objects, the program over
imported declarations; ``JVM-ENTRY-SIGNATURE``) (``JVM-ENTRY-FUNCTION``, ``JVM-PROCESS-ENTRY-CONTRACT``, and
``_foreign_member``'s and ``_object_member``'s: the ABI, the member and descriptor texts, the arity, each descriptor's
type, the array and ``multianewarray`` descriptors, ``ldc`` strings, cast inputs).
"""

from __future__ import annotations

import platform
import random
import sys
import unittest
import unittest.mock
from pathlib import Path

from xax_compiler import (
    JVM_ARRAYLENGTH_ABI, JVM_ARRAYLOAD_ABI, JVM_ARRAYSTORE_ABI, JVM_CHECKCAST_ABI, JVM_GETFIELD_ABI, JVM_INSTANCEOF_ABI, JVM_LDC_ABI,
    JVM_MULTIANEWARRAY_ABI, JVM_NEW_ABI, JVM_NEWARRAY_ABI, JVM_PUTFIELD_ABI, JVM_PUTSTATIC_ABI, SYSV_X86_64_C_ABI, FloatCompare, FloatFormat, Operation, XaxError, bits_type, float_type, foreign_function_symbol, jvm_classfile_target,
)
from xax_compiler import opaque_identity_type
from xax_jvm import REFERENCE_PREFIX, java_base_api, jvm_interface, jvm_reference_type, jvm_static, jvm_static_field, jvm_virtual
from xax_graph_builder import GraphBuilder, program_store
from xax_selfhost_jvm import jvm_jar

sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_xax_jvm import _binary_float, _hello_program, _random_function, _unary  # noqa: E402

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

    def test_platform_programs(self):
        for status, divide in ((7, False), (0, True)):
            with self.subTest(status=status, divide=divide):
                entry, objects = _hello_program(status, divide_by_zero=divide)
                for process_entry in (False, True):
                    self.assertEqual(self._agree(entry, objects, process_entry)[0], "jar")

    def _call_one(self, carrier, inputs, outputs, extra=()):
        """``entry(inputs...) -> outputs``: one call of ``carrier``."""
        graph = GraphBuilder()
        block = graph.block(*inputs)
        results = block.op(Operation.CALL_FOREIGN, block.params, tuple(outputs), entity=carrier)
        block.ret(*results)
        entry = graph.function(tuple(inputs), tuple(outputs))
        return self._agree(entry, (*graph.objects.values(), *extra), False)

    def test_platform_members(self):
        b8, b16, b32, b64, f64 = bits_type(8), bits_type(16), bits_type(32), bits_type(64), float_type(FloatFormat.BINARY64)
        string = jvm_reference_type(b"Ljava/lang/String;")
        sequence = jvm_reference_type(b"Ljava/lang/CharSequence;")
        stream = jvm_reference_type(b"Ljava/io/PrintStream;")
        elements = tuple(opaque_identity_type(REFERENCE_PREFIX + text) for text in (b"Ljava/lang/String;", b"Ljava/lang/CharSequence;",
                                                                                 b"Ljava/io/PrintStream;"))
        cases = {
            "narrow S": (jvm_static(b"java/lang/Short", b"reverseBytes(S)S", (b16,), (b16,)), (b16,), (b16,), "jar"),
            "narrow B": (jvm_static(b"java/lang/Byte", b"toUnsignedInt(B)I", (b8,), (b32,)), (b8,), (b32,), "jar"),
            "char": (jvm_static(b"java/lang/Character", b"toUpperCase(C)C", (b16,), (b16,)), (b16,), (b16,), "jar"),
            "boolean": (jvm_static(b"java/lang/Boolean", b"logicalXor(ZZ)Z", (bits_type(1), bits_type(1)), (bits_type(1),)),
                        (bits_type(1), bits_type(1)), (bits_type(1),), "jar"),
            "double": (jvm_static(b"java/lang/Math", b"fma(DDD)D", (f64, f64, f64), (f64,)), (f64, f64, f64), (f64,), "jar"),
            "virtual": (jvm_virtual(b"java/lang/String", b"length()I", (string,), (b32,)), (string,), (b32,), "jar"),
            "interface": (jvm_interface(b"java/lang/CharSequence", b"charAt(I)C", (sequence, b32), (b16,)), (sequence, b32), (b16,), "jar"),
            "field": (jvm_static_field(b"java/lang/System", b"err:Ljava/io/PrintStream;", (), (stream,)), (), (stream,), "jar"),
            "no colon": (jvm_static_field(b"java/lang/System", b"err", (), (stream,)), (), (stream,), "rejected"),
            "no paren": (jvm_static(b"java/lang/Math", b"abs", (b32,), (b32,)), (b32,), (b32,), "rejected"),
            "no close": (jvm_static(b"java/lang/Math", b"abs(I", (b32,), (b32,)), (b32,), (b32,), "rejected"),
            "bad letter": (jvm_static(b"java/lang/Math", b"abs(Q)I", (b32,), (b32,)), (b32,), (b32,), "rejected"),
            "open class": (jvm_static(b"java/lang/Math", b"abs(Ljava/lang/String)I", (b32,), (b32,)), (b32,), (b32,), "rejected"),
            "arity": (jvm_static(b"java/lang/Math", b"abs(II)I", (b32,), (b32,)), (b32,), (b32,), "rejected"),
            "no name": (jvm_static(b"java/lang/Math", b"(I)I", (b32,), (b32,)), (b32,), (b32,), "rejected"),
            "width": (jvm_static(b"java/lang/Math", b"abs(J)J", (b32,), (b32,)), (b32,), (b32,), "rejected"),
            "receiver": (jvm_virtual(b"java/lang/Object", b"hashCode()I", (string,), (b32,)), (string,), (b32,), "rejected"),
            "abi": (foreign_function_symbol(b"libm.so.6", b"abs", (b32,), (b32,), abi=SYSV_X86_64_C_ABI), (b32,), (b32,), "rejected"),
        }
        for name, (carrier, inputs, outputs, expected) in cases.items():
            with self.subTest(case=name):
                self.assertEqual(self._call_one(carrier, inputs, outputs, (*inputs, *outputs, *elements))[0], expected)
        api = java_base_api()
        self.assertEqual(self._call_one(api.system_out, (api.io_effect,), (api.print_stream, api.io_effect), api.types)[0], "jar")

    def test_object_members(self):
        b1, b8, b16, b32, b64 = (bits_type(width) for width in (1, 8, 16, 32, 64))
        texts = (b"Ljava/lang/String;", b"Ljava/lang/StringBuilder;", b"Ljava/lang/Short;", b"[I", b"[Ljava/lang/String;", b"[[I", b"[B",
                 b"Ljava/awt/Point;", b"Ljava/lang/Object;")
        string, builder, short, ints, strings, grid, bytes_, point, anything = (jvm_reference_type(text) for text in texts)
        elements = tuple(opaque_identity_type(REFERENCE_PREFIX + text) for text in texts)

        def member(abi, library, text, inputs, outputs):
            return foreign_function_symbol(library, text, inputs, outputs, abi=abi), inputs, outputs

        cases = {
            "new": (member(JVM_NEW_ABI, b"java/lang/StringBuilder", b"<init>(I)V", (b32,), (builder,)), "jar"),
            "new narrow": (member(JVM_NEW_ABI, b"java/lang/Short", b"<init>(S)V", (b16,), (short,)), "jar"),
            "new no V": (member(JVM_NEW_ABI, b"java/lang/StringBuilder", b"<init>(I)", (b32,), (builder,)), "rejected"),
            "new name": (member(JVM_NEW_ABI, b"java/lang/StringBuilder", b"make(I)V", (b32,), (builder,)), "rejected"),
            "newarray": (member(JVM_NEWARRAY_ABI, b"I", b"x", (b32,), (ints,)), "jar"),
            "anewarray": (member(JVM_NEWARRAY_ABI, b"Ljava/lang/String;", b"x", (b32,), (strings,)), "jar"),
            "array of arrays": (member(JVM_NEWARRAY_ABI, b"[I", b"x", (b32,), (grid,)), "jar"),
            "multianewarray": (member(JVM_MULTIANEWARRAY_ABI, b"[[I", b"x", (b32, b32), (grid,)), "jar"),
            "multi rank": (member(JVM_MULTIANEWARRAY_ABI, b"[I", b"x", (b32,), (ints,)), "rejected"),
            "baload": (member(JVM_ARRAYLOAD_ABI, b"[B", b"x", (bytes_, b32), (b8,)), "jar"),
            "iaload": (member(JVM_ARRAYLOAD_ABI, b"[I", b"x", (ints, b32), (b32,)), "jar"),
            "aaload": (member(JVM_ARRAYLOAD_ABI, b"[Ljava/lang/String;", b"x", (strings, b32), (string,)), "jar"),
            "not an array": (member(JVM_ARRAYLOAD_ABI, b"I", b"x", (ints, b32), (b32,)), "rejected"),
            "iastore": (member(JVM_ARRAYSTORE_ABI, b"[I", b"x", (ints, b32, b32), ()), "jar"),
            "arraylength": (member(JVM_ARRAYLENGTH_ABI, b"[I", b"x", (ints,), (b32,)), "jar"),
            "ldc": (member(JVM_LDC_ABI, b"java/lang/String", b"hello, world", (), (string,)), "jar"),
            "ldc class": (member(JVM_LDC_ABI, b"java/lang/Object", b"hello", (), (string,)), "rejected"),
            "ldc control": (member(JVM_LDC_ABI, b"java/lang/String", b"a\x01", (), (string,)), "rejected"),
            "getfield": (member(JVM_GETFIELD_ABI, b"java/awt/Point", b"x:I", (point,), (b32,)), "jar"),
            "putfield": (member(JVM_PUTFIELD_ABI, b"java/awt/Point", b"y:I", (point, b32), ()), "jar"),
            "putstatic": (member(JVM_PUTSTATIC_ABI, b"xax/Holder", b"v:J", (b64,), ()), "jar"),
            "field colon": (member(JVM_GETFIELD_ABI, b"java/awt/Point", b"x", (point,), (b32,)), "rejected"),
            "checkcast": (member(JVM_CHECKCAST_ABI, b"java/lang/String", b"x", (anything,), (string,)), "jar"),
            "checkcast array": (member(JVM_CHECKCAST_ABI, b"[I", b"x", (anything,), (ints,)), "jar"),
            "instanceof": (member(JVM_INSTANCEOF_ABI, b"java/lang/String", b"x", (anything,), (b1,)), "jar"),
            "cast an int": (member(JVM_CHECKCAST_ABI, b"java/lang/String", b"x", (b32,), (string,)), "rejected"),
            "cast arity": (member(JVM_CHECKCAST_ABI, b"java/lang/String", b"x", (anything, anything), (string,)), "rejected"),
        }
        for name, ((carrier, inputs, outputs), expected) in cases.items():
            with self.subTest(case=name):
                self.assertEqual(self._call_one(carrier, inputs, outputs, (*inputs, *outputs, *elements))[0], expected)

    def test_callback_programs(self):
        import importlib

        import test_xax_jvm_callbacks
        import xax_jvm

        cases = (("test_xax_jvm_callbacks", "_program", {}), ("test_xax_jvm_objects", "_comparator_program", {}),
                 ("test_xax_jvm_import", "_program", {}))
        for module_name, builder, arguments in cases:
            module = importlib.import_module(module_name)
            seen = []

            def compiled(reader, cid, target, *, process_entry=False, seen=seen):
                expected = _outcome(reader, cid, target, "python", process_entry)
                self.assertEqual(_outcome(reader, cid, target, "xax", process_entry), expected)
                seen.append(expected[0])
                return xax_jvm.compile_jvm_bound_target(reader, cid, target, process_entry=process_entry)

            with self.subTest(module=module_name), unittest.mock.patch.object(module, "compile_jvm_bound_target", compiled):
                getattr(module, builder)(**arguments)
                self.assertEqual(seen, ["jar"])
        with self.subTest(case="JVM-ENTRY-SIGNATURE"):
            seen = []

            def rejected(reader, cid, target, *, process_entry=False):
                expected = _outcome(reader, cid, target, "python", process_entry)
                self.assertEqual(_outcome(reader, cid, target, "xax", process_entry), expected)
                seen.append(expected)
                return xax_jvm.compile_jvm_bound_target(reader, cid, target, process_entry=process_entry)

            with unittest.mock.patch.object(test_xax_jvm_callbacks, "compile_jvm_bound_target", rejected):
                test_xax_jvm_callbacks.JvmCallbackRejectionTests("test_the_interface_method_must_match_the_function").test_the_interface_method_must_match_the_function()
            self.assertEqual([(kind, diagnostic.rule) for kind, diagnostic in seen], [("rejected", "JVM-ENTRY-SIGNATURE")])

    def test_memory_programs(self):
        """S15e.5g: the memory profile (``test_xax_jvm_memory``'s programs: every access width, checked and plain, floats,
        traps, rebases, null blocks, string runs and repeated loads, ``JVM-MEMORY-MEMBER``) through both front ends."""
        import test_xax_jvm_memory as memory
        import xax_jvm

        seen = []

        def compiled(reader, cid, target, *, process_entry=False):
            expected = _outcome(reader, cid, target, "python", process_entry)
            self.assertEqual(_outcome(reader, cid, target, "xax", process_entry), expected)
            seen.append(expected[0] if expected[0] == "jar" else expected[1].rule)
            if expected[0] == "rejected":
                raise XaxError(expected[1])
            return xax_jvm.compile_jvm_bound_target(reader, cid, target, process_entry=process_entry)

        rng = random.Random(memory.SEED)
        with unittest.mock.patch.object(memory, "compile_jvm_bound_target", compiled):
            for index in range(memory.COUNT):
                objects, function, _expected = memory._program(rng)
                with self.subTest(program=index):
                    memory._image(objects, function)
            for name in ("test_checked_access_outside_the_view_traps", "test_rebase_outside_the_view_traps",
                         "test_an_oversized_request_is_a_null_block_and_its_view_traps", "test_constant_byte_runs_and_repeated_loads"):
                with self.subTest(case=name), unittest.mock.patch.object(memory, "run_jvm_calls", lambda *a, **k: None):
                    try:
                        getattr(memory.JvmMemoryTests(name), name)()
                    except (AssertionError, TypeError):
                        pass  # the run itself is test_xax_jvm_memory's
            memory.JvmMemoryProfileTests("test_unknown_memory_members_reject").test_unknown_memory_members_reject()
        self.assertEqual(seen.count("jar"), memory.COUNT + 4, seen)  # the null-block case stops at its first run
        self.assertEqual(seen[-1], "JVM-MEMORY-MEMBER")

    def _both(self, reader, cid, target, process_entry=False):
        expected = _outcome(reader, cid, target, "python", process_entry)
        self.assertEqual(_outcome(reader, cid, target, "xax", process_entry), expected)
        return expected[0] if expected[0] == "jar" else expected[1].rule

    def test_general_programs(self):
        """S15e.5h: the general profile (``test_xax_jvm_general``'s programs: aggregates, sums, indirect calls through a
        passed pointer, stack frames and the shadow stack in a recursion group, atomics, links, raw loads) and the memory
        profile's JVM-OP-TARGET-SUPPORTED rejections."""
        import test_xax_jvm_general as general
        from xax_compiler import jvm_classfile_general_target, jvm_classfile_memory_target

        programs = (general._aggregate_program(), general._sum_program(), general._wrong_variant_program(), general._indirect_program(),
                    general._recursive_stack_program(), general._atomic_program(32), general._atomic_program(64), general._link_program(),
                    general._link_program(null_follow=True), general._raw_load_program())
        for index, (function, objects) in enumerate(programs):
            with self.subTest(program=index):
                target = jvm_classfile_general_target()
                self.assertEqual(self._both(program_store(function, target, objects), function.cid, target), "jar")
        for index, (function, objects) in enumerate(programs[:2] + programs[3:4]):
            with self.subTest(rejected=index):
                target = jvm_classfile_memory_target()
                self.assertEqual(self._both(program_store(function, target, objects), function.cid, target), "JVM-OP-TARGET-SUPPORTED")

    def test_threaded_process_entries(self):
        """S15e.5i: a process entry on the memory and general profiles runs on the threaded launcher."""
        import test_xax_jvm_general as general
        from xax_compiler import jvm_classfile_general_target

        member_function, objects = general._recursive_stack_program()
        member = next(item for item in objects if getattr(item, "kind", None) is not None and item.cid != member_function.cid and item.kind.name == "FUNCTION")
        graph = GraphBuilder()
        block = graph.block()
        block.op1(Operation.CALL_DIRECT, (block.const(bits_type(32), 9),), objects[0], entity=member)
        block.ret()
        entry = graph.function((), ())
        target = jvm_classfile_general_target()
        self.assertEqual(self._both(program_store(entry, target, (*objects, *graph.objects.values())), entry.cid, target, True), "jar")

    def test_shadow_stack_rejection(self):
        import test_xax_jvm_callbacks as callbacks
        import xax_jvm

        seen = []

        def compiled(reader, cid, target, *, process_entry=False):
            seen.append(self._both(reader, cid, target, process_entry))
            return xax_jvm.compile_jvm_bound_target(reader, cid, target, process_entry=process_entry)

        with unittest.mock.patch.object(callbacks, "compile_jvm_bound_target", compiled):
            with self.assertRaises(XaxError):
                callbacks._program(stack_in_square=True)
        self.assertEqual(seen, ["JVM-ENTRY-SHADOW-STACK"])

    def test_jsonmin_application(self):
        """The JVM row's application (``benchmarks.jsonmin``): memory, platform streams, the threaded launcher."""
        sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
        from benchmarks.jsonmin import build_jsonmin

        program = build_jsonmin("jvm")
        self.assertEqual(self._both(program.reader, program.entry.cid, program.target, True), "jar")

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
