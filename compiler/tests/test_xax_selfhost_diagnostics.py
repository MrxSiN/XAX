"""S7b (ADR-179): the XAX x86-64 backend program decides target legality and writes the exact diagnostic.

Every rejection rule of the x86-64 views lowering is exercised by a program that
the store verifier accepts and the lowering rejects.  ``backend="xax"`` fails
rather than fall back, so an equal ``Diagnostic`` (all fields, reprs included)
proves the XAX program decided the rejection; ``backend="python"`` is the
bootstrap reference.  The record codec is checked on its own as well.
"""

from __future__ import annotations

import platform
import sys
import unittest

from xax_compiler import (
    Diagnostic,
    IntCompare,
    Kind,
    Operation,
    Permission,
    SemanticObject,
    TerminatorKind,
    XaxError,
    bits_type,
    float_type,
    heap_view_type,
    memory_effect_type,
    pointer_type,
    stack_owner_type,
    tuple_type,
    uleb,
    views_operations,
    x86_64_views_target,
)
from xax_graph_builder import GraphBuilder, program_store
from xax_x86_64_views import compile_x86_64_views

LINUX_X86_64 = sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")
B1, B32, B64, B128 = bits_type(1), bits_type(32), bits_type(64), bits_type(128)
F64 = float_type(2)
AGGREGATE = tuple_type((B32, B32))


def _target(operations=None, terminators=(1, 2, 3, 4)) -> SemanticObject:
    """The views target, or a variant with the same identity whose operation and terminator lists differ."""
    base = x86_64_views_target()
    if operations is None and terminators == (1, 2, 3, 4):
        return base
    operations = views_operations() if operations is None else tuple(sorted(operations))
    old = uleb(len(views_operations())) + bytes(views_operations()) + uleb(4) + bytes((1, 2, 3, 4))
    new = uleb(len(operations)) + bytes(operations) + uleb(len(terminators)) + bytes(terminators)
    return SemanticObject.create(Kind.TARGET, base.body.replace(old, new, 1))


def _function(parameters, returns, body):
    graph = GraphBuilder()
    body(graph, graph.block(*parameters))
    return graph.function(parameters, returns), tuple(graph.objects.values())


def _identity_add():
    return _function((B64,), (B64,), lambda g, b: b.ret(b.op1(Operation.ADD_WRAP, (b.params[0], b.const(B64, 1)), B64)))


def _float_round_trip():
    return _function((B64,), (B64,), lambda g, b: b.ret(b.op1(Operation.FLOAT_TO_UINT_TRUNC, (b.op1(Operation.UINT_TO_FLOAT, (b.params[0],), F64),), B64)))


def _two_results():
    return _function((B32,), (B32, B32), lambda g, b: b.ret(b.params[0], b.params[0]))


def _calls(callees, parameter=B64):
    """``entry(x)`` threading ``x`` through each callee in turn."""
    def body(g, b):
        value = b.params[0]
        for callee in callees:
            value = b.op1(Operation.CALL_DIRECT, (value,), parameter, entity=callee)
        b.ret(value)
    return _function((parameter,), (parameter,), body)


def case_unsupported_operation():
    entry, objects = _float_round_trip()
    return entry, (*objects, F64, B64), None


def case_closure_order():
    """Two callees with an unsupported operation: the bootstrap's depth-first order picks which one is reported."""
    (first, a), (second, b) = _float_round_trip(), _function((B64,), (B64,), lambda g, b: b.ret(b.op1(
        Operation.FLOAT_TO_UINT_TRUNC, (b.op1(Operation.UINT_TO_FLOAT, (b.op1(Operation.ADD_WRAP, (b.params[0], b.params[0]), B64),), F64),), B64)))
    entry, objects = _calls((first, second))
    return entry, (*objects, *a, *b, F64, B64), None


def case_unsupported_terminator():
    def body(g, b):
        trap, rest = g.block(), g.block()
        b.cbr(b.op1(Operation.INT_COMPARE, (b.params[0], b.const(B64, 0)), B1, attributes=(IntCompare.EQ,)), trap, (), rest, ())
        trap.trap()
        rest.ret(rest.const(B64, 7))
    entry, objects = _function((B64,), (B64,), body)
    return entry, (*objects, B64, B1), _target(terminators=(1, 2, 3))


def case_value_bits_parameter():
    entry, objects = _function((B128,), (B32,), lambda g, b: b.ret(b.const(B32, 1)))
    return entry, (*objects, B128, B32), None


def case_value_bits_result():
    def body(g, b):
        wide = b.op1(Operation.INT_ZERO_EXTEND, (b.params[0],), B128)
        b.ret(b.op1(Operation.INT_TRUNCATE, (b.op1(Operation.ADD_WRAP, (wide, wide), B128),), B32))
    entry, objects = _function((B32,), (B32,), body)
    return entry, (*objects, B128, B32), None


def case_entry_returns_aggregate():
    entry, objects = _function((B32,), (AGGREGATE,), lambda g, b: b.ret(b.op1(Operation.AGGREGATE_MAKE, (b.params[0], b.params[0]), AGGREGATE)))
    return entry, (*objects, AGGREGATE, B32), None


def case_aggregate_result():
    callee, inner = _function((B32,), (AGGREGATE, B32), lambda g, b: b.ret(b.op1(Operation.AGGREGATE_MAKE, (b.params[0], b.params[0]), AGGREGATE), b.params[0]))
    entry, objects = _function((B32,), (B32,), lambda g, b: b.ret(b.op(Operation.CALL_DIRECT, (b.params[0],), (AGGREGATE, B32), entity=callee)[1]))
    return entry, (*objects, *inner, AGGREGATE, B32), None


def case_aggregate_block_parameter():
    def body(g, b):
        tail = g.block(AGGREGATE)
        b.br(tail, b.op1(Operation.AGGREGATE_MAKE, (b.params[0], b.params[0]), AGGREGATE))
        tail.ret(tail.op1(Operation.AGGREGATE_GET, (tail.params[0],), B32, attributes=(0,)))
    entry, objects = _function((B32,), (B32,), body)
    return entry, (*objects, AGGREGATE), None


def case_aggregate_call_argument():
    callee, inner = _function((AGGREGATE,), (B32,), lambda g, b: b.ret(b.op1(Operation.AGGREGATE_GET, (b.params[0],), B32, attributes=(1,))))
    entry, objects = _function((B32,), (B32,), lambda g, b: b.ret(b.op1(
        Operation.CALL_DIRECT, (b.op1(Operation.AGGREGATE_MAKE, (b.params[0], b.params[0]), AGGREGATE),), B32, entity=callee)))
    return entry, (*objects, *inner, AGGREGATE, B32), None


def case_returned_call_aggregate():
    callee, inner = _function((B32,), (AGGREGATE,), lambda g, b: b.ret(b.op1(Operation.AGGREGATE_MAKE, (b.params[0], b.params[0]), AGGREGATE)))
    entry, objects = _function((B32,), (AGGREGATE,), lambda g, b: b.ret(b.op1(Operation.CALL_DIRECT, (b.params[0],), AGGREGATE, entity=callee)))
    return entry, (*objects, *inner, AGGREGATE, B32), None


def case_single_result_return():
    entry, objects = _two_results()
    return entry, (*objects, B32), None


def case_single_result_call():
    callee, inner = _two_results()
    entry, objects = _function((B32,), (B32,), lambda g, b: b.ret(b.op(Operation.CALL_DIRECT, (b.params[0],), (B32, B32), entity=callee)[0]))
    return entry, (*objects, *inner, B32), None


def case_phase_order():
    """The entry's lowering check (a two-result call) precedes a callee's width check: functions are checked one at
    a time, entry first."""
    wide, inner_wide = _function((B32,), (B32,), lambda g, b: b.ret(b.op1(Operation.INT_TRUNCATE, (b.op1(Operation.INT_ZERO_EXTEND, (b.params[0],), B128),), B32)))
    two, inner_two = _two_results()

    def body(g, b):
        first = b.op(Operation.CALL_DIRECT, (b.params[0],), (B32, B32), entity=two)
        b.ret(b.op1(Operation.CALL_DIRECT, (first[0],), B32, entity=wide))
    entry, objects = _function((B32,), (B32,), body)
    return entry, (*objects, *inner_wide, *inner_two, B128, B32), None


def case_operation_not_lowered():
    pointer = pointer_type(B32, Permission.READ_WRITE, 4)

    def body(g, b):
        _pointer, owner, memory = b.op(Operation.STACK_ALLOC, (), (pointer, stack_owner_type(), memory_effect_type()), attributes=(4, 4))
        b.op(Operation.STACK_END, (owner, memory), ())
        b.ret(b.params[0])
    entry, objects = _function((B32,), (B32,), body)
    target = _target({*views_operations(), int(Operation.STACK_ALLOC), int(Operation.STACK_END)})
    return entry, (*objects, pointer, stack_owner_type(), memory_effect_type(), B32), target


REJECTIONS = {
    name[len("case_"):]: make for name, make in sorted(globals().items()) if name.startswith("case_")
}
EXPECTED_RULES = {
    "unsupported_operation": "OP-TARGET-SUPPORTED", "closure_order": "OP-TARGET-SUPPORTED",
    "unsupported_terminator": "TERMINATOR-TARGET-SUPPORTED", "value_bits_parameter": "VALUE-BITS", "value_bits_result": "VALUE-BITS",
    "entry_returns_aggregate": "VALUE-BITS", "aggregate_result": "AGGREGATE-RESULT", "aggregate_block_parameter": "AGGREGATE-VALUE",
    "aggregate_call_argument": "AGGREGATE-USE", "returned_call_aggregate": "AGGREGATE-USE", "single_result_return": "SINGLE-RESULT",
    "single_result_call": "SINGLE-RESULT", "phase_order": "SINGLE-RESULT", "operation_not_lowered": "OP-LOWERED",
}


def _outcome(reader, entry, target, backend):
    try:
        return "image", compile_x86_64_views(reader, entry.cid, target, backend=backend)
    except XaxError as error:
        return "rejected", error.diagnostic


@unittest.skipUnless(LINUX_X86_64, "requires a Linux x86-64 host")
class XaxRejectionDiagnosticTests(unittest.TestCase):
    def test_every_rule_is_decided_by_the_xax_program(self):
        self.assertEqual(set(REJECTIONS), set(EXPECTED_RULES))
        for name, make in REJECTIONS.items():
            entry, objects, target = make()
            target = target or _target()
            reader = program_store(entry, target, objects)
            with self.subTest(case=name):
                reference = _outcome(reader, entry, target, "python")
                hosted = _outcome(reader, entry, target, "xax")
                self.assertEqual(reference[0], "rejected")
                self.assertEqual(reference[1].rule, f"X86_64_VIEWS-{EXPECTED_RULES[name]}")
                self.assertEqual(hosted, reference)
                self.assertEqual(repr(hosted[1]), repr(reference[1]))

    def test_accepted_programs_still_lower_byte_identically(self):
        entry, objects = _identity_add()
        reader = program_store(entry, _target(), (*objects, B64))
        self.assertEqual(_outcome(reader, entry, _target(), "xax"), _outcome(reader, entry, _target(), "python"))

    def test_a_production_rejection_records_xax_authority(self):
        import xax_native

        entry, objects, _target_object = case_single_result_return()
        reader = program_store(entry, _target(), objects)
        with self.assertRaises(XaxError):
            compile_x86_64_views(reader, entry.cid, _target(), backend="auto")
        self.assertEqual(xax_native.AUTHORITY["x86-64-views-backend"]["actual_authority"], "xax")


class DiagnosticRecordTests(unittest.TestCase):
    """The host side renders words and decides nothing: a record round-trips exactly."""

    def test_record_round_trips(self):
        import xax_selfhost_diagnostics as D

        def words_for(*values):
            out = []
            for value in values:
                if value is None:
                    out.append(D.T_NONE)
                elif isinstance(value, TerminatorKind):
                    out += [D.T_TERMINATOR, int(value)]
                elif isinstance(value, int):
                    out += [D.T_INT, value]
                elif isinstance(value, bytes):
                    out += [D.T_CID, *(int.from_bytes(value[k:k + 8], "big") for k in range(0, 32, 8))]
                elif isinstance(value, list):
                    out += [D.T_LIST, len(value), *words_for(*value)]
                else:
                    data = value.encode()
                    out += [D.T_STR, len(data), *(int.from_bytes(data[k:k + 8], "little") for k in range(0, len(data), 8))]
            return out

        entity = bytes(range(32))
        record = words_for("XAX.X86_64_VIEWS.ABI", entity, "X86_64_VIEWS-CHECKED-ACCESS", [1, None, TerminatorKind.TRAP], "eight bytes")
        memory = {0: D.REJECT, D.DIAG_AT: D.DIAG_AT + 1 + len(record)}
        memory.update({D.DIAG_AT + 1 + k: word for k, word in enumerate(record)})
        read = lambda start, count: [memory.get(start + k, 0) for k in range(count)]  # noqa: E731
        self.assertEqual(D.decode_diagnostic(read), Diagnostic("XAX.X86_64_VIEWS.ABI", entity.hex(), "X86_64_VIEWS-CHECKED-ACCESS",
                                                             [1, None, TerminatorKind.TRAP], "eight bytes"))
        memory[0] = 1
        self.assertIsNone(D.decode_diagnostic(read))


if __name__ == "__main__":
    unittest.main()
