"""S12a (ADR-268): the general x86-64 backend's front end decided by an XAX program.

For ``x86_64-linux-elf-exec-v1`` (and the dynamic-loader profile) the XAX program decides the target check, the
process-entry contract, and the function closure with its ABI, layout, operation, terminator, and foreign-entry
rejections, and the image's function order.  ``closure_with_xax(required=True)`` fails rather than fall back, so an
equal outcome -- the same functions in the same order, or a ``Diagnostic`` equal in every field and in repr -- proves
the XAX program decided it; ``linux_closure`` is the bootstrap reference.  Every rule is exercised by a store the
verifier accepts.  The suites that build Linux programs also run with ``XAX_GENERAL_FRONTEND_DIFF=1`` (both front ends
decide every compile and must agree); see ADR-268.
"""

from __future__ import annotations

import platform
import sys
import unittest
from pathlib import Path

from xax_compiler import (
    IntCompare,
    Kind,
    Operation,
    OpaqueKind,
    SemanticObject,
    XaxError,
    _x86_64_windows_target,
    X86_64_LINUX_OPERATIONS,
    bits_type,
    float_type,
    foreign_entry_pointer_type,
    jvm_interface_entry_type,
    link_type,
    opaque_identity_type,
    opaque_type,
    sum_type,
    array_type,
    tuple_type,
    x86_64_linux_dynamic_exec_target,
    x86_64_linux_exec_target,
    x86_64_windows_target,
)
from xax_graph_builder import GraphBuilder, program_store
from xax_linux import compile_linux_executable, linux_api, linux_closure

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

LINUX_X86_64 = sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")
B1, B8, B32, B64, B128 = bits_type(1), bits_type(8), bits_type(32), bits_type(64), bits_type(128)
F64 = float_type(2)
LINUX_ABI, EXEC_FORMAT = 5, 5


def _linux_target(operations=X86_64_LINUX_OPERATIONS, terminators=(1, 2, 3, 4), abi=LINUX_ABI, image_format=EXEC_FORMAT) -> SemanticObject:
    """The Linux executable profile's machine fields with chosen operation and terminator lists."""
    target = _x86_64_windows_target(b"x86_64-linux-elf-exec-v1", tuple(sorted(set(operations))), machine=(2, 1, abi, image_format, 64, 64, 16, 32))
    if terminators == (1, 2, 3, 4):
        return target
    old = b"\x04\x01\x02\x03\x04\x02"  # terminator list, then the atomic widths' count
    assert target.body.count(old) == 1
    return SemanticObject.create(Kind.TARGET, target.body.replace(old, bytes((len(terminators), *terminators, 2)), 1))


def _function(parameters, returns, body):
    graph = GraphBuilder()
    body(graph, graph.block(*parameters))
    return graph.function(parameters, returns), tuple(graph.objects.values())


def _process(callees=(), arguments=None):
    """A process entry that calls each callee (with ``arguments(block)``), then exits with status 0."""
    api = linux_api()
    graph = GraphBuilder()
    block = graph.block(api.process_effect, api.filesystem_effect)
    process, fs = block.params
    for callee, (inputs, results) in callees:
        block.op(Operation.CALL_DIRECT, tuple(item(block) for item in inputs), results, entity=callee)
    status = block.const(B32, 0)
    process = block.op1(Operation.CALL_FOREIGN, (status, process), api.process_effect, entity=api.exit_group)
    block.ret(status, process, fs)
    parameters = (api.process_effect, api.filesystem_effect)
    return graph.function(parameters, (B32, *parameters)), (*graph.objects.values(), *api.types)


def _store(entry_objects, target, *extra):
    entry, objects = entry_objects
    return program_store(entry, target, (*objects, *extra)), entry


def _constant(type_, value):
    return lambda block: block.const(type_, value)


def _call(callee, parameters, results):
    return callee, (tuple(_constant(item, 0) for item in parameters), results)


def _outcome(decide):
    try:
        return [function.cid for function in decide()]
    except XaxError as error:
        return error.diagnostic


@unittest.skipUnless(LINUX_X86_64, "UNAVAILABLE: native XAX helper images run on Linux x86-64 only")
class GeneralFrontendTests(unittest.TestCase):
    def assertSame(self, reader, entry_cid, target, *, rule=None, exact_repr=True):
        from xax_selfhost_x86_64_general import closure_with_xax

        xax = _outcome(lambda: closure_with_xax(reader, entry_cid, target, required=True))
        reference = _outcome(lambda: linux_closure(reader, entry_cid, target))
        self.assertEqual(xax, reference)
        if exact_repr:
            self.assertEqual(repr(xax), repr(reference))
        if rule is None:
            self.assertIsInstance(reference, list)
        else:
            self.assertNotIsInstance(reference, list, "the reference accepted the store")
            self.assertEqual(reference.rule, rule)
        return reference

    # -- acceptance and order ------------------------------------------------------------------------------

    def test_order_is_the_closure_by_cid(self):
        callees = []
        objects = []
        for k in range(6):
            callee, items = _function((B64,), (B64,), lambda g, b, k=k: b.ret(b.op1(Operation.ADD_WRAP, (b.params[0], b.const(B64, k)), B64)))
            callees.append(_call(callee, (B64,), (B64,)))
            objects.extend(items)
        entry = _process(callees)
        for target in (x86_64_linux_exec_target(), x86_64_linux_dynamic_exec_target()):
            reader, function = _store(entry, target, *objects)
            order = self.assertSame(reader, function.cid, target)
            self.assertEqual(len(order), 7)
            self.assertEqual(order, sorted(order))

    def test_erased_proof_functions_are_not_in_the_closure(self):
        api = linux_api()
        erased, items = _function((api.filesystem_effect,), (api.filesystem_effect,), lambda g, b: b.ret(b.params[0]))
        api_entry = GraphBuilder()
        block = api_entry.block(api.process_effect, api.filesystem_effect)
        process, fs = block.params
        fs = block.op1(Operation.CALL_DIRECT, (fs,), api.filesystem_effect, entity=erased)
        status = block.const(B32, 3)
        process = block.op1(Operation.CALL_FOREIGN, (status, process), api.process_effect, entity=api.exit_group)
        block.ret(status, process, fs)
        entry = api_entry.function((api.process_effect, api.filesystem_effect), (B32, api.process_effect, api.filesystem_effect))
        target = x86_64_linux_exec_target()
        reader = program_store(entry, target, (*items, *api_entry.objects.values(), *api.types))
        self.assertEqual(len(self.assertSame(reader, entry.cid, target)), 1)

    def test_jsonmin_recursion_group_members(self):
        """jsonmin's parser is a recursion group: its member functions, stored or not, are in the closure."""
        from benchmarks.jsonmin import build_jsonmin

        program = build_jsonmin()
        order = self.assertSame(program.reader, program.entry.cid, program.target)
        stored = {obj.cid for obj in program.reader.objects()}
        self.assertTrue(any(cid not in stored for cid in order), "no unstored group member function was reached")

    def test_production_bytes_unchanged(self):
        from benchmarks.jsonmin import build_jsonmin

        program = build_jsonmin()
        xax = compile_linux_executable(program.reader, program.entry.cid, program.target.cid, frontend="xax")
        python = compile_linux_executable(program.reader, program.entry.cid, program.target.cid, frontend="python")
        self.assertEqual(xax.data, python.data)

    # -- the target and the process entry ------------------------------------------------------------------

    def test_target_abi(self):
        target = x86_64_windows_target()
        reader, entry = _store(_function((B32,), (B32,), lambda g, b: b.ret(b.params[0])), target)
        self.assertSame(reader, entry.cid, target, rule="LINUX-ELF-EXEC-TARGET")

    def test_other_architectures(self):
        """Targets of other architectures (with and without register fields) are decoded like the bootstrap's.  The
        check names only the ABI and the image format, so the AArch64 Linux profile passes it and the entry decides."""
        from xax_compiler import aarch64_linux_exec_target, riscv64_views_target

        cases = ((aarch64_linux_exec_target(), "LINUX-PROCESS-ENTRY-CONTRACT"), (riscv64_views_target(), "LINUX-ELF-EXEC-TARGET"))
        for target, rule in cases:
            with self.subTest(rule):
                reader, entry = _store(_function((B32,), (B32,), lambda g, b: b.ret(b.params[0])), target)
                self.assertSame(reader, entry.cid, target, rule=rule)

    def test_entry_not_a_function(self):
        target = x86_64_linux_exec_target()
        reader, _entry = _store(_process(), target)
        self.assertEqual(self.assertSame(reader, B32.cid, target, rule="LINUX-ENTRY-FUNCTION").actual, "TYPE")

    def test_entry_contract(self):
        target = x86_64_linux_exec_target()
        cases = {
            "machine parameter": _function((B32,), (B32,), lambda g, b: b.ret(b.params[0])),
            "two results": _function((), (B32, B32), lambda g, b: b.ret(b.const(B32, 1), b.const(B32, 2))),
            "float result": _function((), (F64,), lambda g, b: b.ret(b.op1(Operation.UINT_TO_FLOAT, (b.const(B64, 1),), F64))),
        }
        for name, entry in cases.items():
            with self.subTest(name):
                reader, function = _store(entry, target, B64)
                self.assertSame(reader, function.cid, target, rule="LINUX-PROCESS-ENTRY-CONTRACT")

    # -- the closure ---------------------------------------------------------------------------------------

    def test_abi_arity(self):
        target = x86_64_linux_exec_target()
        pair, items = _function((B32,), (B32, B32), lambda g, b: b.ret(b.params[0], b.params[0]))
        reader, entry = _store(_process([_call(pair, (B32,), (B32, B32))]), target, *items)
        self.assertSame(reader, entry.cid, target, rule="NATIVE-ABI-ARITY")

    def test_abi_arity_register_profile(self):
        """Without float, aggregate, or sum operations a function has only the four argument registers."""
        operations = [op for op in X86_64_LINUX_OPERATIONS if op not in (Operation.FLOAT_ADD, Operation.AGGREGATE_MAKE, Operation.SUM_MAKE)]
        target = _linux_target(operations)
        five, items = _function((B64,) * 5, (B64,), lambda g, b: b.ret(b.params[0]))
        reader, entry = _store(_process([_call(five, (B64,) * 5, (B64,))]), target, *items)
        diagnostic = self.assertSame(reader, entry.cid, target, rule="NATIVE-ABI-ARITY")
        self.assertEqual(diagnostic.expected, [4, 1])

    def test_hidden_result_counts_as_an_argument(self):
        """A hidden aggregate result (12 bytes: by reference) takes one of the four argument registers."""
        operations = [op for op in X86_64_LINUX_OPERATIONS if op not in (Operation.FLOAT_ADD, Operation.AGGREGATE_MAKE, Operation.SUM_MAKE)]
        target = _linux_target(operations)
        triple = tuple_type((B32, B32, B32))

        def body(g, b):
            _first, rest = g.block(), g.block()
            b.cbr(b.op1(Operation.INT_COMPARE, (b.params[0], b.const(B64, 0)), B1, attributes=(IntCompare.EQ,)), _first, (), rest, ())
            _first.trap()
            rest.trap()

        callee, items = _function((B64,) * 4, (triple,), body)
        reader, entry = _store(_process([_call(callee, (B64,) * 4, (triple,))]), target, *items)
        diagnostic = self.assertSame(reader, entry.cid, target, rule="NATIVE-ABI-ARITY")
        self.assertEqual(diagnostic.actual, [5, 1])

    def test_abi_value(self):
        target = x86_64_linux_exec_target()
        values = {"bits<128>": B128, "link": link_type(), "opaque": opaque_type(OpaqueKind.OBJECT)}
        for name, value in values.items():
            with self.subTest(name):
                callee, items = _function((value,), (B32,), lambda g, b: b.ret(b.const(B32, 1)))
                inputs = (lambda block: block.op1(Operation.INT_ZERO_EXTEND, (block.const(B64, 0),), B128),) if value is B128 else None
                if inputs is None:
                    # A value of this type cannot be made here; the callee is reached through its address instead.
                    reader, entry = _store(_address_of(callee), target, *items)
                else:
                    reader, entry = _store(_process([(callee, (inputs, (B32,)))]), target, *items)
                self.assertSame(reader, entry.cid, target, rule="NATIVE-ABI-VALUE")

    def test_abi_layout_component(self):
        """An aggregate component without an ABI layout (an opaque type) is rejected where the bootstrap's layout
        recursion reaches it, before the value check."""
        target = x86_64_linux_exec_target()
        opaque = opaque_type(OpaqueKind.OBJECT)
        inner = tuple_type((B8, opaque))
        array = array_type(inner, 2)
        bad = tuple_type((B32, array))
        callee, items = _function((bad,), (B32,), lambda g, b: b.ret(b.const(B32, 1)))
        reader, entry = _store(_address_of(callee), target, *items, opaque, inner, array, B8)
        diagnostic = self.assertSame(reader, entry.cid, target, rule="ABI-LAYOUT-VALUE-TYPE")
        self.assertEqual(diagnostic.entity, opaque_type(OpaqueKind.OBJECT).cid.hex())

    def test_aggregate_layouts_accepted(self):
        target = x86_64_linux_exec_target()
        pair = tuple_type((B32, B64))
        components = (B8, B32, B64, pair, link_type(), F64)
        shapes = (tuple_type((B8, B64, B32)), array_type(B32, 3), sum_type((B8, pair)), tuple_type(()), array_type(B64, 0),
                  tuple_type((link_type(), F64)), array_type(pair, 3))
        for shape in shapes:
            with self.subTest(shape.cid.hex()[:8]):
                callee, items = _function((shape,), (B32,), lambda g, b: b.ret(b.const(B32, 1)))
                reader, entry = _store(_address_of(callee), target, *items, *components)
                self.assertSame(reader, entry.cid, target)

    def test_unsupported_operation(self):
        target = _linux_target([op for op in X86_64_LINUX_OPERATIONS if op != Operation.UDIV])
        callee, items = _function((B64,), (B64,), lambda g, b: b.ret(b.op1(Operation.UDIV, (b.params[0], b.const(B64, 3)), B64)))
        reader, entry = _store(_process([_call(callee, (B64,), (B64,))]), target, *items)
        self.assertSame(reader, entry.cid, target, rule="NATIVE-OP-TARGET-SUPPORTED")

    def test_unsupported_terminator(self):
        target = _linux_target(terminators=(1, 2, 3))

        def body(g, b):
            trap, rest = g.block(), g.block()
            b.cbr(b.op1(Operation.INT_COMPARE, (b.params[0], b.const(B64, 0)), B1, attributes=(IntCompare.EQ,)), trap, (), rest, ())
            trap.trap()
            rest.ret(rest.const(B64, 7))

        callee, items = _function((B64,), (B64,), body)
        reader, entry = _store(_process([_call(callee, (B64,), (B64,))]), target, *items)
        self.assertSame(reader, entry.cid, target, rule="NATIVE-TERMINATOR-TARGET-SUPPORTED")

    def test_depth_first_order(self):
        """Callees that fail differently: the first one the depth-first walk reaches is reported, whatever its CID; a
        callee's callees come before its caller's later nodes and its terminators."""
        target = _linux_target([op for op in X86_64_LINUX_OPERATIONS if op not in (Operation.UDIV, Operation.UREM)])
        udiv, a = _function((B64,), (B64,), lambda g, b: b.ret(b.op1(Operation.UDIV, (b.params[0], b.const(B64, 3)), B64)))
        urem, c = _function((B64,), (B64,), lambda g, b: b.ret(b.op1(Operation.UREM, (b.params[0], b.const(B64, 3)), B64)))
        pair, d = _function((B32,), (B32, B32), lambda g, b: b.ret(b.params[0], b.params[0]))
        middle, e = _function((B64,), (B64,), lambda g, b: b.ret(b.op1(Operation.CALL_DIRECT, (b.op1(Operation.CALL_DIRECT, (b.params[0],), B64, entity=urem),), B64, entity=udiv)))
        seen = set()
        for order in ((middle, udiv, pair), (udiv, middle), (pair, middle), (urem, udiv)):
            calls = [_call(item, (B32,), (B32, B32)) if item is pair else _call(item, (B64,), (B64,)) for item in order]
            reader, entry = _store(_process(calls), target, *a, *c, *d, *e)
            rule = "NATIVE-ABI-ARITY" if order[0] is pair else "NATIVE-OP-TARGET-SUPPORTED"
            diagnostic = self.assertSame(reader, entry.cid, target, rule=rule)
            seen.add((diagnostic.rule, diagnostic.entity, repr(diagnostic.actual)))
        self.assertEqual(len(seen), 3)  # urem first and middle first both stop in urem's graph

    def test_foreign_entry_abis(self):
        target = x86_64_linux_exec_target()
        callee, items = _function((B64,), (B64,), lambda g, b: b.ret(b.params[0]))
        cases = {"WIN64-ENTRY-TARGET": foreign_entry_pointer_type(b"win64-c"),
                 "SYSV-ENTRY-TARGET": jvm_interface_entry_type(b"java/util/function/LongUnaryOperator", b"applyAsLong(J)J")}
        for rule, pointer in cases.items():
            with self.subTest(rule):
                try:
                    reader, entry = _store(_address_of(callee, pointer), target, *items)
                except XaxError as error:
                    self.skipTest(f"the verifier rejects this code address on Linux: {error.diagnostic.rule}")
                self.assertSame(reader, entry.cid, target, rule=rule)

    def test_sysv_entry_accepted(self):
        target = x86_64_linux_exec_target()
        callee, items = _function((B64,), (B64,), lambda g, b: b.ret(b.params[0]))
        reader, entry = _store(_address_of(callee, foreign_entry_pointer_type(b"sysv-x86_64-c")), target, *items)
        self.assertSame(reader, entry.cid, target)


def _address_of(callee, pointer=None):
    """A process entry that takes ``callee``'s code address (as a plain function pointer unless ``pointer``)."""
    from xax_compiler import function_pointer_type

    api = linux_api()
    graph = GraphBuilder()
    block = graph.block(api.process_effect, api.filesystem_effect)
    process, fs = block.params
    pointer = pointer or function_pointer_type()
    block.op1(Operation.FUNCTION_ADDRESS, (), pointer, entity=callee)
    status = block.const(B32, 0)
    process = block.op1(Operation.CALL_FOREIGN, (status, process), api.process_effect, entity=api.exit_group)
    block.ret(status, process, fs)
    parameters = (api.process_effect, api.filesystem_effect)
    return graph.function(parameters, (B32, *parameters)), (*graph.objects.values(), *api.types, *_ELEMENTS)


# The code-address types' elements (``program_store`` writes only objects it is given).
_ELEMENTS = (
    opaque_type(OpaqueKind.FUNCTION),
    opaque_identity_type(b"code-entry:win64-c"),
    opaque_identity_type(b"code-entry:sysv-x86_64-c"),
    opaque_identity_type(b"code-entry:jvm-interface:java/util/function/LongUnaryOperator.applyAsLong(J)J"),
)


if __name__ == "__main__":
    unittest.main()
