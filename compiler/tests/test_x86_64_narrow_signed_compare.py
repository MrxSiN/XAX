"""The x86-64 lowering of ``int.compare`` against the reference executor at every operand width.

The frame path used to compare zero-extended ``bits<8>``/``bits<16>`` slots as 32-bit values, so the four signed
predicates ignored the narrow sign bit (docs/audits/2026-11-11-independent-audit.md, finding 1).  The oracle here is
``execute``, not another backend's bytes.
"""

from __future__ import annotations

import platform
import sys
import unittest

from xax_compiler import IntCompare, Operation, bits_type, execute, x86_64_windows_pe_target
from xax_graph_builder import GraphBuilder, program_store
from xax_x86_64 import compile_native, run_native

X86_64_HOST = platform.machine().lower() in ("amd64", "x86_64") and (sys.platform == "win32" or sys.platform.startswith("linux"))
B1, B64 = bits_type(1), bits_type(64)


def _compare_program(width: int, kind: IntCompare):
    """fn(bits64, bits64) -> bits64: zero-extend(compare(truncate(x), truncate(y))), so the operands are run-time values."""
    graph = GraphBuilder()
    block = graph.block(B64, B64)
    narrow = bits_type(width)
    left, right = block.params if width == 64 else (block.op1(Operation.INT_TRUNCATE, (value,), narrow) for value in block.params)
    flag = block.op1(Operation.INT_COMPARE, (left, right), B1, attributes=(kind,))
    block.ret(block.op1(Operation.INT_ZERO_EXTEND, (flag,), B64))
    entry = graph.function((B64, B64), (B64,))
    target = x86_64_windows_pe_target()
    return program_store(entry, target, tuple(graph.objects.values())), entry, target


@unittest.skipUnless(X86_64_HOST, "requires an x86-64 Windows or Linux host")
class NarrowCompareTests(unittest.TestCase):
    def test_every_predicate_matches_the_executor_at_every_width(self):
        for width in (5, 8, 16, 24, 32, 64):
            top = 1 << (width - 1)
            # Both signs, the extremes, and dirt above the operand width that truncation must discard.
            values = (0, 1, 3, top - 1, top, top + 1, (1 << width) - 1, 0xF1 | (0xABCD << width) & ((1 << 64) - 1))
            for kind in IntCompare:
                reader, entry, target = _compare_program(width, kind)
                image = compile_native(reader, entry.cid, target.cid)
                for left in values:
                    for right in values:
                        with self.subTest(width=width, kind=kind.name, left=hex(left), right=hex(right)):
                            self.assertEqual(run_native(image, (left, right)), execute(reader, entry.cid, (left, right)))


if __name__ == "__main__":
    unittest.main()
