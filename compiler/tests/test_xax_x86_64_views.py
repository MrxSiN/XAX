"""x86-64 views-profile generator (ADR-152): XAX semantics -> raw x86-64 code, executed natively.

The integer differential corpus is the JVM/RISC-V one (widths 8/13/32/47/64, loops
with parallel block-argument copies, calls); every result must match the reference
executor, traps included (a trap is ``ud2``, run in a forked child).  ``llvm-mc``
independently decodes the code when it is installed.
"""

from __future__ import annotations

import platform
import random
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_xax_jvm import _interesting, _random_function, _reference  # noqa: E402
from test_xax_riscv64 import MASK32, aggregate_program  # noqa: E402
from xax_compiler import Operation, XaxError, bits_type, tuple_type, x86_64_views_target  # noqa: E402
from xax_graph_builder import GraphBuilder, program_store  # noqa: E402
from xax_x86_64_views import compile_x86_64_views, run_x86_64_views  # noqa: E402

LINUX_X86_64 = sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")
LLVM_MC = shutil.which("llvm-mc")
B32, B64 = bits_type(32), bits_type(64)


def _compile(entry, objects, backend="python"):
    target = x86_64_views_target()
    reader = program_store(entry, target, objects)
    return reader, compile_x86_64_views(reader, entry.cid, target, backend=backend)


def _decode(code: bytes) -> tuple[str, str]:
    text = " ".join(f"0x{byte:02x}" for byte in code)
    completed = subprocess.run([LLVM_MC, "--disassemble", "-triple=x86_64"], input=text, capture_output=True, text=True, check=False)
    return completed.stdout, completed.stderr


@unittest.skipUnless(LINUX_X86_64, "requires a Linux x86-64 host")
class X86ViewsDifferentialTests(unittest.TestCase):
    def test_random_programs_match_reference_executor(self):
        rng = random.Random(20261004)
        images = []
        for width in (8, 13, 32, 47, 64):
            callees, callee_objects = [], []
            for index in range(8):
                entry, graph = _random_function(rng, width, tuple(callees))
                reader, image = _compile(entry, (*graph.objects.values(), *callees, *callee_objects))
                images.append(image)
                for _ in range(8):
                    call = tuple(rng.choice(_interesting(width)) if rng.random() < 0.5 else rng.getrandbits(width) for _ in range(3))
                    with self.subTest(width=width, program=index, call=call):
                        self.assertEqual(run_x86_64_views(image, call), _reference(reader, entry.cid, call))
                callees.append(entry)
                callee_objects.extend(graph.objects.values())
        if LLVM_MC:
            for image in images[::7]:
                text, diagnostics = _decode(image.code)
                self.assertEqual(diagnostics, "")
                self.assertNotIn("(bad)", text)

    def test_stack_arguments_and_aggregate_results_execute(self):
        for form, fields in (("tuple", 12), ("array", 16), ("tuple", 3), ("tuple", 255)):
            entry, objects, reference = aggregate_program(form, fields)
            _reader, image = _compile(entry, objects)
            for a, b in ((0, 0), (1, 2), (MASK32, 0x12345678), (0xDEADBEEF, 7)):
                with self.subTest(form=form, fields=fields, a=a, b=b):
                    self.assertEqual(run_x86_64_views(image, [a, b]), reference(a, b))

    def test_aggregate_block_parameters_reject(self):
        aggregate = tuple_type((B32, B32))
        graph = GraphBuilder()
        block = graph.block(B32)
        tail = graph.block(aggregate)
        block.br(tail, block.op1(Operation.AGGREGATE_MAKE, (block.params[0], block.params[0]), aggregate))
        tail.ret(tail.op1(Operation.AGGREGATE_GET, (tail.params[0],), B32, attributes=(1,)))
        entry = graph.function((B32,), (B32,))
        with self.assertRaises(XaxError) as raised:
            _compile(entry, (*graph.objects.values(), aggregate))
        self.assertEqual(raised.exception.diagnostic.rule, "X86_64_VIEWS-AGGREGATE-VALUE")

    def test_blake3_hash_matches_the_production_digest(self):
        import ctypes

        import blake3
        from xax_selfhost_blake3 import DIGEST_OFFSET, INPUT_EXTENT, SCRATCH_EXTENT, load_hash_program
        from xax_x86_64_views import NativeViewsImage

        reader, function = load_hash_program()
        image = NativeViewsImage(compile_x86_64_views(reader, function.cid, x86_64_views_target()))
        data, scratch = (ctypes.c_uint8 * INPUT_EXTENT)(), (ctypes.c_uint8 * SCRATCH_EXTENT)()
        for message in (b"", b"abc", bytes(range(256)) * 41):
            ctypes.memmove(data, message, len(message))
            image(ctypes.addressof(data), ctypes.addressof(scratch), len(message))
            self.assertEqual(bytes(scratch[DIGEST_OFFSET:DIGEST_OFFSET + 32]), blake3._Blake3(message).digest())


if __name__ == "__main__":
    unittest.main()
