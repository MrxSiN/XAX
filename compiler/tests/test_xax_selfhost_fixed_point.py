"""B1-B4 (ADR-145): the XAX RISC-V backend compiles itself, and the compiled backend reproduces itself.

B1/B2: the backend program's store, compiled for the RISC-V views profile, is
the same image (code, offsets, semantic ranges) with ``backend="xax"`` (gen1,
the backend run natively) and ``backend="python"`` (the bootstrap reference):
that image is gen2.  B3: gen2, run in the RV64 emulator, compiles a corpus of
random programs to exactly the images gen1 produces.  B4: gen2 compiling the
backend store itself gives gen3 == gen2, the self-hosting fixed point; it runs
about 25 billion emulated instructions, so it is opt-in (``XAX_FIXED_POINT=1``)
and its result is recorded by ``benchmarks/riscv64_fixed_point.py``.
"""

from __future__ import annotations

import os
import platform
import random
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))  # sibling suites' program builders

LINUX_X86_64 = sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")

try:
    import unicorn  # noqa: F401

    HAVE_UNICORN = True
except ImportError:
    HAVE_UNICORN = False


def _emulated(image, reader, entry, target):
    """``image`` (a compiled backend) run in the emulator on ``entry``'s object table: the image it produces."""
    import xax_riscv64 as R
    from xax_selfhost_riscv64_backend import collect_output
    from xax_selfhost_typing import IN_WORDS, OUT_WORDS

    words = R._object_table(reader, entry, target)
    status, output = R.run_riscv64_views(image, words, 8 * IN_WORDS, 8 * OUT_WORDS, collect_output, instruction_limit=1 << 40)
    if status == "trap" or output is None:
        return status
    return R.image_from_backend_output(reader, target, output)


@unittest.skipUnless(LINUX_X86_64, "requires a Linux x86-64 host")
class SelfhostFixedPointTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from xax_compiler import riscv64_views_target
        from xax_riscv64 import compile_riscv64_bound_target
        from xax_selfhost_riscv64_backend import load_backend_program

        cls.reader, cls.entry = load_backend_program()
        cls.views = riscv64_views_target()
        cls.gen2 = compile_riscv64_bound_target(cls.reader, cls.entry.cid, cls.views, backend="xax")

    def test_b1_gen1_compiles_the_backend_like_the_bootstrap(self):
        from xax_riscv64 import compile_riscv64_bound_target

        python = compile_riscv64_bound_target(self.reader, self.entry.cid, self.views, backend="python")
        self.assertEqual(self.gen2, python)
        self.assertEqual(len(self.gen2.function_offsets), 17)  # every backend function is in the closure

    @unittest.skipUnless(HAVE_UNICORN, "requires the unicorn emulator")
    def test_b3_gen2_agrees_with_gen1_on_a_corpus(self):
        from test_xax_jvm import _random_function
        from xax_compiler import riscv64_baremetal_target
        from xax_graph_builder import program_store
        from xax_riscv64 import compile_riscv64_bound_target

        target = riscv64_baremetal_target()
        rng = random.Random(145)
        for width in (8, 32, 64):
            callees, callee_objects = [], []
            for index in range(4):
                entry, graph = _random_function(rng, width, tuple(callees))
                objects = (*graph.objects.values(), *callees, *callee_objects)
                reader = program_store(entry, target, objects)
                with self.subTest(width=width, program=index):
                    gen1 = compile_riscv64_bound_target(reader, entry.cid, target, backend="xax")
                    self.assertEqual(_emulated(self.gen2, reader, entry, target), gen1)
                callees.append(entry)
                callee_objects.extend(graph.objects.values())

    @unittest.skipUnless(HAVE_UNICORN and os.environ.get("XAX_FIXED_POINT") == "1", "opt-in: XAX_FIXED_POINT=1 (minutes of emulation)")
    def test_b4_gen3_is_gen2(self):
        self.assertEqual(_emulated(self.gen2, self.reader, self.entry, self.views), self.gen2)


if __name__ == "__main__":
    unittest.main()
