"""S15f.4 (ADR-325): bare-metal AArch64 load images built by the XAX AArch64 program equal the bootstrap's.

``xax_selfhost_aarch64_general.aarch64_raw_image(..., frontend="xax")`` runs the XAX program (its front end, the frame
path with one slot per value on the general profile, the legacy register path on the v1 and atomic profiles and for
register-path eligible functions, and the bundle) and fails where it declines; ``frontend="python"`` is
``compile_aarch64_bound_target``.  Differential, by bytes, over ``aarch64_raw_corpus``, and the encoders' rejections
the program decides (``AARCH64-FRAME-SIZE``, ``AARCH64-STACK-ADDRESS-OFFSET``, ``AARCH64-SP-OFFSET``,
``AARCH64-ARITHMETIC-BITS``).
"""

from __future__ import annotations

import os
import platform
import random
import sys
import unittest
from pathlib import Path

from xax_compiler import (
    Operation, Permission, XaxError, aarch64_baremetal_target, bits_type, memory_effect_type, pointer_type, stack_owner_type, verify_store,
)
from xax_graph_builder import GraphBuilder, program_store
from xax_selfhost_aarch64_general import aarch64_raw_image

sys.path.insert(0, str(Path(__file__).resolve().parent))

LINUX_X86_64 = sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")
B32 = bits_type(32)


def _outcome(reader, entry, target, frontend):
    try:
        return "image", aarch64_raw_image(reader, entry.cid, target, frontend=frontend)
    except XaxError as error:
        return "rejected", error.diagnostic


def _stack_program(extent: int, offset: int, alignment: int, call: bool):
    """A ``bits<32>`` store through a stack object at ``offset``; with ``call`` the pointer is passed to a function."""
    objects: list = []
    owner_type, memory_type = stack_owner_type(), memory_effect_type()
    pointer = pointer_type(B32, Permission.READ_WRITE, alignment)
    callee = None
    if call:
        inner = GraphBuilder()
        block = inner.block(pointer)
        block.ret(block.const(B32, 7))
        callee = inner.function((pointer,), (B32,))
        objects += list(inner.objects.values())
    graph = GraphBuilder()
    block = graph.block()
    base, owner, memory = block.op(Operation.STACK_ALLOC, (), (pointer, owner_type, memory_type), attributes=(extent, alignment))
    at = block.op1(Operation.ADDRESS_OFFSET, (base,), pointer, attributes=(offset,)) if offset else base
    memory = block.op1(Operation.STORE_BITS_LE, (at, block.const(B32, 5), memory), memory_type, attributes=(4, alignment))
    value = block.op1(Operation.CALL_DIRECT, (at,), B32, entity=callee) if call else block.const(B32, 1)
    block.op(Operation.STACK_END, (owner, memory), ())
    block.ret(value)
    function = graph.function((), (B32,))
    objects += [owner_type, memory_type, pointer, B32, *graph.objects.values()]
    target = aarch64_baremetal_target()
    return program_store(function, target, tuple(objects)), function, target


@unittest.skipUnless(LINUX_X86_64, "UNAVAILABLE: the XAX AArch64 program runs on Linux x86-64 only")
class XaxAarch64RawImageTests(unittest.TestCase):
    def assertSame(self, reader, entry, target):
        verify_store(reader)
        expected = _outcome(reader, entry, target, "python")
        self.assertEqual(_outcome(reader, entry, target, "xax"), expected)
        return expected

    def test_corpus(self):
        from aarch64_raw_corpus import aarch64_raw_case

        rng = random.Random(325)
        seen = set()
        for kind in ("legacy", "eligible", "general", "random"):
            for trial in range(int(os.environ.get("XAX_RAW_TRIALS", "15"))):
                reader, entry, target, name = aarch64_raw_case(rng, kind)
                with self.subTest(kind=kind, trial=trial, case=name):
                    outcome = self.assertSame(reader, entry, target)
                    seen.add(outcome[0] if outcome[0] == "image" else outcome[1].rule)
        self.assertIn("image", seen)
        self.assertIn("AARCH64-ARITHMETIC-BITS", seen)

    def test_encoder_rejections(self):
        cases = {
            "AARCH64-FRAME-SIZE": (5000, 0, 4, False),
            "AARCH64-STACK-ADDRESS-OFFSET": (8192, 5000, 4, True),
            "AARCH64-SP-OFFSET": (64, 2, 1, False),
        }
        for rule, arguments in cases.items():
            with self.subTest(rule):
                kind, diagnostic = self.assertSame(*_stack_program(*arguments))
                self.assertEqual((kind, diagnostic.rule), ("rejected", rule))
        self.assertEqual(self.assertSame(*_stack_program(4000, 0, 4, True))[0], "image")


if __name__ == "__main__":
    unittest.main()
