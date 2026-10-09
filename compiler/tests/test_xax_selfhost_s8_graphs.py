"""S8 (ADR-248): graph-level rejections the XAX programs decide with the bootstrap's exact diagnostics.

Each case is a small function that breaks one rule; the outcome with the XAX programs equals the bootstrap's
alone, and the diagnostic was raised from an XAX rejection record (``_xax_fail``).
"""

from __future__ import annotations

import platform
import sys
import unittest

from xax_compiler import FloatCompare, IntCompare, Kind, Operation, SemanticObject, ValueRef, bits_type, float_type
from xax_graph_builder import GraphBuilder

LINUX_X86_64 = sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")
B1, B8, B32, B64 = (bits_type(width) for width in (1, 8, 32, 64))
F32, F64 = float_type(1), float_type(2)
TRAILING = SemanticObject.create(Kind.TYPE, b"\x01\x20\x00")  # bits<32> with a trailing byte
LINK = SemanticObject.create(Kind.TYPE, b"\x0b")
# S8 (ADR-248): ``(parameter, operation, operand count, result, attribute)``: one node decoding a type of another form.
CROSS = {
    "add_float_result": (B32, Operation.ADD_WRAP, 2, F32, None, "TYPE-BITS"),
    "truncate_float_source": (F32, Operation.INT_TRUNCATE, 1, B8, None, "TYPE-BITS"),
    "fadd_bits_result": (B32, Operation.FLOAT_ADD, 2, B32, None, "TYPE-FLOAT-FORMAT"),
    "fcompare_bits_operands": (B32, Operation.FLOAT_COMPARE, 2, B1, FloatCompare(1), "TYPE-FLOAT-FORMAT"),
    "icompare_float_operand": (F64, Operation.INT_COMPARE, 2, B1, IntCompare.EQ, "TYPE-BITS"),
    "uint_to_float_bits_result": (B32, Operation.UINT_TO_FLOAT, 1, B64, None, "TYPE-FLOAT-FORMAT"),
    "convert_bits_source": (B32, Operation.FLOAT_CONVERT, 1, F64, None, "TYPE-FLOAT-FORMAT"),
    "add_trailing_result": (B32, Operation.ADD_WRAP, 2, TRAILING, None, "TYPE-BODY"),
    "add_link_result": (B32, Operation.ADD_WRAP, 2, LINK, None, "SER-ULEB-TERMINATED"),
}


def _cross(variant: str):
    parameter, operation, count, result, attribute, _rule = CROSS[variant]
    graph = GraphBuilder()
    graph.track(B1, B8, B32, B64, F32, F64, result)
    block = graph.block(parameter)
    (x,) = block.params
    attributes = () if attribute is None else (int(attribute),)
    block.ret(block.op1(operation, (x,) * count, result, attributes=attributes))
    return graph.function((parameter,), (result,)), tuple(graph.objects.values())


def _decided(function, objects):
    """``(native outcome, bootstrap outcome, decided by XAX)``."""
    import xax_compiler
    from test_xax_selfhost_facts import _outcome
    from xax_selfhost_typing import NativeTyping

    raised = []
    original = xax_compiler._xax_fail

    def recording(*arguments):
        raised.append(arguments[2])
        return original(*arguments)

    xax_compiler._xax_fail = recording
    try:
        native = _outcome(NativeTyping(), function, objects)
    finally:
        xax_compiler._xax_fail = original
    return native, _outcome(None, function, objects), raised


def _branching(variant: str):
    """``(x: b32) -> b32``: branch on a compare; ``variant`` breaks the condition or an edge's argument types."""
    graph = GraphBuilder()
    graph.track(B1, B8, B32, B64)
    entry = graph.block(B32)
    then, other = graph.block(B32), graph.block(B32)
    (x,) = entry.params
    condition = entry.op1(Operation.INT_COMPARE, (x, entry.const(B32, 0)), B1, attributes=(IntCompare.EQ,))
    if variant == "condition_width":
        condition = entry.op1(Operation.INT_TRUNCATE, (x,), B8)
    argument = entry.op1(Operation.INT_ZERO_EXTEND, (x,), B64) if variant == "edge_arguments" else x
    entry.cbr(condition, then, (argument,), other, (x,))
    then.ret(*then.params)
    other.ret(*other.params)
    return graph.function((B32,), (B32,)), tuple(graph.objects.values())


@unittest.skipUnless(LINUX_X86_64, "requires a Linux x86-64 host")
class TerminatorRejectionTests(unittest.TestCase):
    def test_terminators_are_decided_by_xax(self):
        cases = {"condition_width": "GRAPH-CBR-CONDITION", "edge_arguments": "GRAPH-BLOCK-PARAMETERS"}
        for variant, rule in cases.items():
            with self.subTest(variant=variant):
                native, bootstrap, raised = _decided(*_branching(variant))
                self.assertEqual(native, bootstrap)
                self.assertEqual(bootstrap[:1] + bootstrap[2:3], ("reject", rule))
                self.assertIn(rule, raised)



USES = {"block": "GRAPH-VALUE-DEFINED", "parameter": "GRAPH-VALUE-DEFINED", "result": "GRAPH-VALUE-DEFINED", "later": "GRAPH-SSA-DOMINANCE",
        "dominance": "GRAPH-SSA-DOMINANCE", "target": "GRAPH-BRANCH-TARGET"}


def _use(variant: str):
    """``(x: b32) -> b32``: two branches joining; ``variant`` makes one use invalid (or a branch target)."""
    from xax_compiler import Terminator

    graph = GraphBuilder()
    graph.track(B1, B32)
    entry = graph.block(B32)
    then, other = graph.block(), graph.block()
    (x,) = entry.params
    condition = entry.op1(Operation.INT_COMPARE, (x, entry.const(B32, 0)), B1, attributes=(IntCompare.EQ,))
    entry.cbr(condition, then, (), other, ())
    late = then.op1(Operation.ADD_WRAP, (x, x), B32)
    bad = {"block": ValueRef.parameter(9, 0), "parameter": ValueRef.parameter(0, 3), "result": ValueRef.node_result(1, 0, 2),
           "later": ValueRef.node_result(1, 1, 0), "dominance": late}.get(variant)
    then.ret(then.op1(Operation.ADD_WRAP, (x, bad if variant != "target" else late), B32))
    other.ret(x if variant != "dominance" else bad)
    if variant == "target":
        other.terminator = Terminator.branch(7, ())
    return graph.function((B32,), (B32,)), tuple(graph.objects.values())


@unittest.skipUnless(LINUX_X86_64, "requires a Linux x86-64 host")
class UseRejectionTests(unittest.TestCase):
    def test_invalid_uses_are_decided_by_xax(self):
        for variant, rule in USES.items():
            with self.subTest(variant=variant):
                native, bootstrap, raised = _decided(*_use(variant))
                self.assertEqual(native, bootstrap)
                self.assertEqual(bootstrap[:1] + bootstrap[2:3], ("reject", rule))
                self.assertIn(rule, raised)


@unittest.skipUnless(LINUX_X86_64, "requires a Linux x86-64 host")
class CrossFormRejectionTests(unittest.TestCase):
    def test_wrong_form_types_are_decided_by_xax(self):
        for variant, row in CROSS.items():
            rule = row[-1]
            with self.subTest(variant=variant):
                native, bootstrap, raised = _decided(*_cross(variant))
                self.assertEqual(native, bootstrap)
                self.assertEqual(bootstrap[:1] + bootstrap[2:3], ("reject", rule))
                self.assertIn(rule, raised)


if __name__ == "__main__":
    unittest.main()
