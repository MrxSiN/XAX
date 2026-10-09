"""S8 (ADR-248): graph-level rejections the XAX programs decide with the bootstrap's exact diagnostics.

Each case is a small function that breaks one rule; the outcome with the XAX programs equals the bootstrap's
alone, and the diagnostic was raised from an XAX rejection record (``_xax_fail``).
"""

from __future__ import annotations

import platform
import sys
import unittest

from xax_compiler import IntCompare, Operation, bits_type
from xax_graph_builder import GraphBuilder

LINUX_X86_64 = sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")
B1, B8, B32, B64 = (bits_type(width) for width in (1, 8, 32, 64))


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


if __name__ == "__main__":
    unittest.main()
