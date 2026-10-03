"""Self-hosting step S1 (ADR-116): the RISC-V encoder is XAX semantics on the production path.

* The committed canonical store regenerates byte-identically and verifies.
* The reference executor, the natively lowered leaf, the RISC-V-lowered
  encoder (in the emulator), and the JVM-lowered encoder (on HotSpot) agree
  with the bootstrap Python encoders.
* Every RISC-V image in a program corpus is byte-identical whichever encoder
  built it, including the encoder compiling its own graph (a fixed point).
"""

from __future__ import annotations

import platform
import random
import shutil
import sys
import unittest

from xax_compiler import execute, jvm_classfile_target, riscv64_baremetal_target
from xax_graph_builder import program_store
import xax_riscv64 as rv
from xax_riscv64 import PythonEncoder, compile_riscv64_bound_target, run_riscv64
from xax_selfhost_riscv64 import STORE_PATH, build_encoder_program, load_encoder_program, native_encoder
from test_xax_jvm import _random_function

NATIVE = sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")
try:
    import unicorn  # noqa: F401

    EMULATOR = True
except ImportError:
    EMULATOR = False
JAVA = shutil.which("java") is not None and shutil.which("javac") is not None
MASK64 = (1 << 64) - 1
LI_VALUES = (0, 5, -1, 2047, -2048, 2048, 0x12345, -0x12345, 0x7FFFF800, 0x80000000, -(1 << 31), 0x9E3779B97F4A7C15, 1 << 63, MASK64, 0x123456789, 0xFFF0000000000001, (1 << 63) - 1, (1 << 63) - 2048, (1 << 63) - 2049, (1 << 63) + 2047, -(1 << 31) - 1)


def _cases(rng: random.Random, count: int):
    """(arguments, expected word list) pairs covering every format and li."""
    cases = []
    for _ in range(count):
        f7, rs2, rs1, f3, rd, op = rng.getrandbits(7), rng.getrandbits(5), rng.getrandbits(5), rng.getrandbits(3), rng.getrandbits(5), rng.getrandbits(7)
        imm, offset, jump = rng.randrange(-2048, 2048), rng.randrange(-4096, 4096) & ~1, rng.randrange(-(1 << 20), 1 << 20) & ~1
        upper = rng.getrandbits(20)
        cases += [
            ((0, f7, rs2, rs1, f3, rd, op), rv._r(f7, rs2, rs1, f3, rd, op)),
            ((1, imm, rs1, f3, rd, op), rv._i(imm, rs1, f3, rd, op)),
            ((2, imm, rs2, rs1, f3, op), rv._s(imm, rs2, rs1, f3, op)),
            ((3, offset, rs2, rs1, f3), rv._b(offset, rs2, rs1, f3)),
            ((4, jump, rd), rv._j(jump, rd)),
            ((5, upper, rd, 0x37), (upper << 12) | (rd << 7) | 0x37),
        ]
    for value in LI_VALUES:
        words = PythonEncoder.li(10, value)
        for index in range(len(words) + 1):
            cases.append(((6, 10, value & MASK64, index), words[index] if index < len(words) else 0))
    return [((*arguments, *(0,) * (7 - len(arguments))), expected) for arguments, expected in cases]


class EncoderStoreTests(unittest.TestCase):
    def test_committed_store_regenerates_and_verifies(self):
        reader, encode = build_encoder_program()
        self.assertEqual(reader.data, STORE_PATH.read_bytes())
        loaded, loaded_encode = load_encoder_program()
        self.assertEqual(loaded_encode.cid, encode.cid)

    def test_reference_executor_agrees_with_python(self):
        reader, encode = load_encoder_program()
        for arguments, expected in _cases(random.Random(1), 40):
            with self.subTest(arguments=arguments):
                masked = tuple(value & MASK64 for value in arguments)
                self.assertEqual(execute(reader, encode.cid, masked, fuel=10**6), (expected,))


@unittest.skipUnless(NATIVE, "the native leaf runs on Linux x86-64")
class NativeEncoderTests(unittest.TestCase):
    def test_native_leaf_agrees_with_python(self):
        native = native_encoder()
        self.assertIsNotNone(native)
        for arguments, expected in _cases(random.Random(2), 3000):
            self.assertEqual(native(*arguments), expected, arguments)

    def test_backend_uses_the_xax_encoder_by_default(self):
        self.assertEqual(rv.select_encoder().identity, "xax-native")
        self.assertEqual(rv.select_encoder("python").identity, "python-bootstrap")

    def test_images_are_byte_identical_with_either_encoder(self):
        target = riscv64_baremetal_target()
        rng = random.Random(20261003)
        for width in (8, 32, 64):
            for index in range(6):
                entry, graph = _random_function(rng, width)
                reader = program_store(entry, target, tuple(graph.objects.values()))
                with self.subTest(width=width, program=index):
                    xax = compile_riscv64_bound_target(reader, entry.cid, target, encoder="xax")
                    python = compile_riscv64_bound_target(reader, entry.cid, target, encoder="python")
                    self.assertEqual(xax.code, python.code)

    def test_encoder_compiles_itself_to_the_same_image(self):
        """Fixed point: the RISC-V lowering of the encoder's own graph, encoded by itself."""
        reader, encode = load_encoder_program()
        target = riscv64_baremetal_target()
        self_built = compile_riscv64_bound_target(reader, encode.cid, target, encoder="xax")
        bootstrap = compile_riscv64_bound_target(reader, encode.cid, target, encoder="python")
        self.assertEqual(self_built.code, bootstrap.code)


@unittest.skipUnless(EMULATOR, "requires the unicorn RV64 emulator")
class CrossTargetEncoderTests(unittest.TestCase):
    def test_encoder_lowered_to_riscv64_agrees(self):
        reader, encode = load_encoder_program()
        image = compile_riscv64_bound_target(reader, encode.cid, riscv64_baremetal_target())
        for arguments, expected in _cases(random.Random(3), 60):
            self.assertEqual(run_riscv64(image, tuple(value & MASK64 for value in arguments)), expected, arguments)

    @unittest.skipUnless(JAVA, "requires java and javac")
    def test_encoder_lowered_to_the_jvm_agrees(self):
        from xax_jvm import compile_jvm_bound_target, run_jvm_calls

        reader, encode = load_encoder_program()
        image = compile_jvm_bound_target(reader, encode.cid, jvm_classfile_target())
        cases = _cases(random.Random(4), 200)
        results = run_jvm_calls(image, [tuple(value & MASK64 for value in arguments) for arguments, _ in cases], result_width=64)
        self.assertEqual(results, tuple(expected for _, expected in cases))


if __name__ == "__main__":
    unittest.main()
