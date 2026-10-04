"""S6c (ADR-150): B1-B4 for the XAX store verifier on RV64.

B1: gen1 (the XAX RISC-V backend run natively) compiles the store verifier
program, and the small helper programs, to the bootstrap generator's images.
B2/B3: the verifier's RISC-V image, run in the Unicorn RV64 emulator, gives the
native verifier's verdicts on committed stores and on stores with mutated
object bodies (so declines agree too).  B4: gen2 (the backend's RISC-V image)
compiling the verifier store reproduces the image; it emulates tens of billions
of instructions, so it is opt-in (``XAX_FIXED_POINT=1``) and recorded by
``benchmarks/bench_selfhost_closure.py``.
"""

from __future__ import annotations

import dataclasses
import os
import platform
import random
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "benchmarks"))

LINUX_X86_64 = sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")
BOOTSTRAP = Path(__file__).resolve().parents[1] / "bootstrap"

try:
    import unicorn  # noqa: F401

    HAVE_UNICORN = True
except ImportError:
    HAVE_UNICORN = False


@unittest.skipUnless(LINUX_X86_64, "requires a Linux x86-64 host")
class VerifierClosureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from xax_compiler import riscv64_views_target
        from xax_riscv64 import compile_riscv64_bound_target
        from xax_selfhost_verify import load_verifier_program

        cls.target = riscv64_views_target()
        cls.reader, cls.entry = load_verifier_program()
        cls.image = compile_riscv64_bound_target(cls.reader, cls.entry.cid, cls.target, backend="xax")

    def test_b1_gen1_compiles_the_helpers_like_the_bootstrap(self):
        import importlib

        from xax_riscv64 import compile_riscv64_bound_target

        self.assertEqual(self.image, compile_riscv64_bound_target(self.reader, self.entry.cid, self.target, backend="python"))
        for module, loader in (("xax_selfhost_cfg", "load_cfg_program"), ("xax_selfhost_graph", "load_graph_decoder_program"),
                               ("xax_selfhost_store", "load_decoder_program")):
            with self.subTest(program=module):
                reader, entry = getattr(importlib.import_module(module), loader)()
                self.assertEqual(compile_riscv64_bound_target(reader, entry.cid, self.target, backend="xax"),
                                 compile_riscv64_bound_target(reader, entry.cid, self.target, backend="python"))

    @unittest.skipUnless(HAVE_UNICORN, "requires the unicorn emulator")
    def test_b3_emulated_verifier_agrees_with_the_native_one(self):
        import xax_compiler as X
        from bench_selfhost_closure import same_verdicts, verifier_input
        from xax_riscv64 import run_riscv64_views
        from xax_selfhost_typing import IN_WORDS, OUT_WORDS
        from xax_selfhost_verify import collect_verdicts, native_store_verifier

        native = native_store_verifier()
        rng = random.Random(150)
        cases = []
        for name in ("m11_bootstrap_bundle.xax", "m14_selfhost_compiler.xax", "xax_cfg_analysis.xax"):
            reader = X.StoreReader((BOOTSTRAP / name).read_bytes())
            listed = list(reader.objects())
            cases.append((name, *verifier_input(reader)))
            # Mutated bodies: one byte of one object changed (its CID is kept: only the verdicts are compared,
            # and both runs see the same table, built as the production path builds it).
            for trial in range(4):
                position = rng.choice([k for k, obj in enumerate(listed) if obj.body])
                body = bytearray(listed[position].body)
                body[rng.randrange(len(body))] ^= rng.randrange(1, 256)
                mutated = [*listed[:position], dataclasses.replace(listed[position], body=bytes(body)), *listed[position + 1:]]
                made = verifier_input(reader, mutated)
                if made is not None:
                    cases.append((f"{name}#{trial}", *made))
        declined = 0
        for name, words, listed, groups in cases:
            with self.subTest(store=name):
                expected = native.verify(words, len(listed), groups)
                status, emulated = run_riscv64_views(self.image, words, 8 * IN_WORDS, 8 * OUT_WORDS,
                                                     lambda read: collect_verdicts(read, len(listed), groups), instruction_limit=1 << 36)
                self.assertNotEqual(status, "trap")
                if expected is None:
                    self.assertIsNone(emulated)
                    continue
                self.assertTrue(same_verdicts(emulated, expected, listed))
                declined += int(not expected[0] or 0 in expected[1])
        self.assertGreater(declined, 0)  # some mutation is declined somewhere, and the image agrees on it

    @unittest.skipUnless(HAVE_UNICORN and os.environ.get("XAX_FIXED_POINT") == "1", "opt-in: XAX_FIXED_POINT=1 (minutes of emulation)")
    def test_b4_gen2_reproduces_the_verifier_image(self):
        import xax_riscv64 as R
        from xax_selfhost_riscv64_backend import collect_output, load_backend_program
        from xax_selfhost_typing import IN_WORDS, OUT_WORDS

        backend_reader, backend_entry = load_backend_program()
        gen2 = R.compile_riscv64_bound_target(backend_reader, backend_entry.cid, self.target, backend="xax")
        words = R._object_table(self.reader, self.entry, self.target)
        status, output = R.run_riscv64_views(gen2, words, 8 * IN_WORDS, 8 * OUT_WORDS, collect_output, instruction_limit=1 << 40)
        self.assertEqual(R.image_from_backend_output(self.reader, self.target, output), self.image)


if __name__ == "__main__":
    unittest.main()
