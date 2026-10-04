"""S7a (ADR-152): the XAX x86-64 backend program, and B1-B4 natively on x86-64.

The program reproduces the bootstrap generator (``xax_x86_64_views``) byte for
byte or declines.  B1: gen1 (the program, lowered by the bootstrap reference)
compiles every XAX helper program, itself included, to the bootstrap's images.
B2/B3: those images run natively on the production path; gen2 (its own image)
compiles other programs exactly as gen1 does.  B4: gen2 compiling the backend
store reproduces gen2 -- natively, in about a second.
"""

from __future__ import annotations

import importlib
import platform
import random
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from xax_compiler import Operation, XaxError, bits_type, tuple_type, x86_64_views_target  # noqa: E402
from xax_graph_builder import GraphBuilder, program_store  # noqa: E402
from xax_x86_64_views import compile_x86_64_views  # noqa: E402

LINUX_X86_64 = sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")
HELPERS = (
    ("xax_selfhost_cfg", "load_cfg_program"), ("xax_selfhost_graph", "load_graph_decoder_program"),
    ("xax_selfhost_riscv64", "load_encoder_program"), ("xax_selfhost_store", "load_decoder_program"),
    ("xax_selfhost_typing", "load_typing_program"), ("xax_selfhost_verify", "load_verifier_program"),
    ("xax_selfhost_blake3", "load_hash_program"), ("xax_selfhost_riscv64_backend", "load_backend_program"),
    ("xax_selfhost_x86_64_backend", "load_backend_program"),
)


class X86BackendStoreTests(unittest.TestCase):
    def test_committed_store_is_the_built_program(self):
        from xax_selfhost_x86_64_backend import STORE_PATH, build_backend_program

        reader, _function = build_backend_program()
        self.assertEqual(STORE_PATH.read_bytes(), reader.data)


@unittest.skipUnless(LINUX_X86_64, "requires a Linux x86-64 host")
class X86BackendTests(unittest.TestCase):
    target = x86_64_views_target()

    def assertSameImage(self, entry, objects):
        reader = program_store(entry, self.target, objects)
        self.assertEqual(compile_x86_64_views(reader, entry.cid, self.target, backend="xax"),
                         compile_x86_64_views(reader, entry.cid, self.target, backend="python"))

    def test_random_programs_are_byte_identical(self):
        from test_xax_jvm import _random_function

        rng = random.Random(152)
        for width in (8, 13, 32, 47, 64):
            callees, callee_objects = [], []
            for index in range(4):
                entry, graph = _random_function(rng, width, tuple(callees))
                with self.subTest(width=width, program=index):
                    self.assertSameImage(entry, (*graph.objects.values(), *callees, *callee_objects))
                callees.append(entry)
                callee_objects.extend(graph.objects.values())

    def test_stack_arguments_and_aggregate_results_are_byte_identical(self):
        from test_xax_riscv64 import aggregate_program

        for form, fields in (("tuple", 12), ("array", 16), ("tuple", 255)):
            with self.subTest(form=form, fields=fields):
                entry, objects, _reference = aggregate_program(form, fields)
                self.assertSameImage(entry, objects)

    def test_rejections_keep_the_bootstrap_diagnostic(self):
        b32 = bits_type(32)
        aggregate = tuple_type((b32, b32))
        graph = GraphBuilder()
        block = graph.block(b32)
        tail = graph.block(aggregate)
        block.br(tail, block.op1(Operation.AGGREGATE_MAKE, (block.params[0], block.params[0]), aggregate))
        tail.ret(tail.op1(Operation.AGGREGATE_GET, (tail.params[0],), b32, attributes=(0,)))
        entry = graph.function((b32,), (b32,))
        reader = program_store(entry, self.target, (*graph.objects.values(), aggregate))
        rules = []
        for backend in ("python", "auto"):
            with self.assertRaises(XaxError) as raised:
                compile_x86_64_views(reader, entry.cid, self.target, backend=backend)
            rules.append(raised.exception.diagnostic.rule)
        self.assertEqual(rules, ["X86_64_VIEWS-AGGREGATE-VALUE"] * 2)

    def test_b1_gen1_compiles_every_helper_like_the_bootstrap(self):
        for module, loader in HELPERS:
            with self.subTest(program=module):
                reader, entry = getattr(importlib.import_module(module), loader)()
                self.assertEqual(compile_x86_64_views(reader, entry.cid, self.target, backend="xax"),
                                 compile_x86_64_views(reader, entry.cid, self.target, backend="python"))

    def test_production_helpers_are_its_images(self):
        """B2: the native helpers the compiler runs are the images this backend makes."""
        from xax_selfhost_verify import _native_image, load_verifier_program

        reader, entry = load_verifier_program()
        image = compile_x86_64_views(reader, entry.cid, self.target, backend="xax")
        self.assertEqual(_native_image(), (image.code, image.entry_offset))

    def test_b3_b4_gen2_compiles_like_gen1_and_reproduces_itself(self):
        from test_xax_jvm import _random_function
        from xax_riscv64 import _object_table
        from xax_selfhost_views_backend import _NativeRunner
        from xax_selfhost_x86_64_backend import collect_output, image_from_backend_output, load_backend_program

        reader, entry = load_backend_program()
        gen2 = compile_x86_64_views(reader, entry.cid, self.target, backend="xax")
        runner = _NativeRunner(gen2.code, gen2.entry_offset)

        def gen2_compile(store, function):
            return image_from_backend_output(store, self.target, runner.run(_object_table(store, function, self.target), collect_output))

        self.assertEqual(gen2_compile(reader, entry), gen2)  # B4: the native fixed point
        rng = random.Random(4)
        for index in range(6):
            program, graph = _random_function(rng, 32)
            store = program_store(program, self.target, tuple(graph.objects.values()))
            with self.subTest(program=index):
                self.assertEqual(gen2_compile(store, program), compile_x86_64_views(store, program.cid, self.target, backend="xax"))


if __name__ == "__main__":
    unittest.main()
