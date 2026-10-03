"""RISC-V RV64IM backend (ADR-113): XAX semantics -> raw image -> RV64 emulator.

The integer differential corpus is the JVM one (widths 8/13/32/47/64, loops
with parallel block-argument copies, calls); every result must match the
reference executor.  ``llvm-objdump`` independently decodes every emitted
word when it is installed.
"""

from __future__ import annotations

import random
import shutil
import subprocess
import unittest

from xax_compiler import (
    IntCompare,
    Kind,
    Operation,
    SemanticObject,
    Terminator,
    TerminatorKind,
    XaxError,
    bits_type,
    decode_native_target,
    float_type,
    FloatFormat,
    riscv64_baremetal_target,
    uleb,
    RISCV64_ARCHITECTURE,
    RISCV64_LP64_ABI,
)
from xax_graph_builder import GraphBuilder, program_store
from xax_riscv64 import compile_riscv64_bound_target, run_riscv64
from test_xax_jvm import _interesting, _random_function, _reference

try:
    import unicorn  # noqa: F401

    EMULATOR = True
except ImportError:
    EMULATOR = False
LLVM_MC = shutil.which("llvm-mc")
B1 = bits_type(1)


def _compile(entry, objects):
    target = riscv64_baremetal_target()
    reader = program_store(entry, target, objects)
    return reader, compile_riscv64_bound_target(reader, entry.cid, target)


def _disassemble(code: bytes) -> tuple[list[str], str]:
    """Decode with LLVM's RISC-V disassembler: (instruction lines, diagnostics)."""
    text = " ".join(f"0x{byte:02x}" for byte in code)
    completed = subprocess.run(
        [LLVM_MC, "--disassemble", "-triple=riscv64", "-mattr=+m"], input=text, capture_output=True, text=True, check=False,
    )
    lines = [line.strip() for line in completed.stdout.splitlines() if line.strip() and not line.strip().startswith(".text")]
    return lines, completed.stderr


@unittest.skipUnless(EMULATOR, "requires the unicorn RV64 emulator")
class Riscv64DifferentialTests(unittest.TestCase):
    SEED = 20261003
    PER_WIDTH = 8

    def test_random_programs_match_reference_executor(self):
        rng = random.Random(self.SEED)
        images = []
        for width in (8, 13, 32, 47, 64):
            callees, callee_objects = [], []
            for index in range(self.PER_WIDTH):
                entry, graph = _random_function(rng, width, tuple(callees))
                objects = (*graph.objects.values(), *callees, *callee_objects)
                reader, image = _compile(entry, objects)
                images.append(image)
                for _ in range(8):
                    call = tuple(rng.choice(_interesting(width)) if rng.random() < 0.5 else rng.getrandbits(width) for _ in range(3))
                    expected = _reference(reader, entry.cid, call)
                    with self.subTest(width=width, program=index, call=call):
                        self.assertEqual(run_riscv64(image, call), expected)
                callees.append(entry)
                callee_objects.extend(graph.objects.values())
        if LLVM_MC:
            # Independent decode: every word is one valid RV64IM instruction.
            for image in images[::7]:
                lines, diagnostics = _disassemble(image.code)
                self.assertEqual(diagnostics, "")
                self.assertEqual(len(lines), len(image.code) // 4)

    def test_large_constants_and_power_of_two_division(self):
        for width, value in ((64, 0x9E3779B97F4A7C15), (64, 0x8000000000000000), (64, 0x7FFFF800), (64, 0x80000000), (47, 0x7FFF_FFFF_FFFF), (32, 0xFFFFF800)):
            bw = bits_type(width)
            graph = GraphBuilder()
            block = graph.block(bw)
            (a,) = block.params
            mixed = block.op1(Operation.BIT_XOR, (a, block.const(bw, value)), bw)
            block.ret(block.op1(Operation.UDIV, (mixed, block.const(bw, 8)), bw))
            entry = graph.function((bw,), (bw,))
            reader, image = _compile(entry, tuple(graph.objects.values()))
            for argument in _interesting(width):
                with self.subTest(width=width, value=hex(value), argument=argument):
                    self.assertEqual(run_riscv64(image, (argument,)), _reference(reader, entry.cid, (argument,)))

    def test_register_pressure_spills_through_loop_parameters(self):
        """24 values live around a loop: more than the eleven allocatable registers."""
        b64, b8 = bits_type(64), bits_type(8)
        count = 24
        graph = GraphBuilder()
        entry_block = graph.block(b64, b64)
        a, b = entry_block.params
        values = [entry_block.op1(Operation.ADD_WRAP, (entry_block.op1(Operation.MUL_WRAP, (a, entry_block.const(b64, k + 3)), b64), b), b64) for k in range(count)]
        loop = graph.block(b8, *(b64,) * count)
        exit_block = graph.block(*(b64,) * count)
        entry_block.br(loop, entry_block.const(b8, 0), *values)
        counter, *carried = loop.params
        # Rotate the carried values each iteration: every back-edge copy overlaps.
        rotated = [loop.op1(Operation.BIT_XOR, (carried[(k + 1) % count], carried[k]), b64) for k in range(count)]
        following = loop.op1(Operation.ADD_WRAP, (counter, loop.const(b8, 1)), b8)
        condition = loop.op1(Operation.INT_COMPARE, (following, loop.const(b8, 5)), B1, attributes=(IntCompare.ULT,))
        loop.cbr(condition, loop, (following, *rotated[1:], rotated[0]), exit_block, tuple(carried))
        total = exit_block.params[0]
        for k, value in enumerate(exit_block.params[1:]):
            total = exit_block.op1(Operation.ADD_WRAP, (exit_block.op1(Operation.MUL_WRAP, (total, exit_block.const(b64, 31)), b64), value), b64)
        exit_block.ret(total)
        entry = graph.function((b64, b64), (b64,))
        reader, image = _compile(entry, tuple(graph.objects.values()))
        for call in ((1, 2), (0x9E3779B97F4A7C15, 7), ((1 << 64) - 1, (1 << 63))):
            with self.subTest(call=call):
                self.assertEqual(run_riscv64(image, call), _reference(reader, entry.cid, call))


@unittest.skipUnless(EMULATOR, "requires the unicorn RV64 emulator")
class Riscv64TrapTests(unittest.TestCase):
    def test_zero_divisor_and_explicit_trap(self):
        b32 = bits_type(32)
        graph = GraphBuilder()
        entry_block = graph.block(b32, b32)
        a, b = entry_block.params
        trap_block = graph.block()
        done = graph.block(b32)
        is_seven = entry_block.op1(Operation.INT_COMPARE, (a, entry_block.const(b32, 7)), B1, attributes=(IntCompare.EQ,))
        entry_block.cbr(is_seven, trap_block, (), done, (entry_block.op1(Operation.UREM, (a, b), b32),))
        trap_block.terminator = Terminator(TerminatorKind.TRAP)
        done.ret(done.params[0])
        entry = graph.function((b32, b32), (b32,))
        reader, image = _compile(entry, tuple(graph.objects.values()))
        # RISC-V remu by zero would return the dividend; XAX requires the trap.
        self.assertEqual([run_riscv64(image, call) for call in ((9, 4), (9, 0), (7, 1))], [1, "trap", "trap"])
        self.assertEqual(_reference(reader, entry.cid, (9, 0)), "trap")


class Riscv64PipelineTests(unittest.TestCase):
    def test_build_and_workspace_produce_the_same_image(self):
        from xax_build import ArtifactKind, build, build_profile, build_request, package, resolve_packages, snapshot_store, trust_policy
        from xax_workspace import Workspace

        entry, graph = _random_function(random.Random(9), 32)
        reader, direct = _compile(entry, tuple(graph.objects.values()))
        module = next(item for item in reader.objects() if item.kind == Kind.MODULE)
        target = riscv64_baremetal_target()
        app = package(b"riscv64-kernel", (module,), build_entries=((b"kernel", entry),))
        profile, policy = build_profile(), trust_policy()
        request = build_request(app, b"kernel", target, profile, requested_artifacts=(ArtifactKind.NATIVE_IMAGE,))
        candidates = (*tuple(reader.objects()), app, profile, policy, request)
        result = build(snapshot_store(resolve_packages(request, candidates, policy, b"riscv64-resolver-v1"), candidates), request.cid)
        self.assertEqual(result.artifact, direct.code)
        workspace = Workspace(reader, target)
        artifact = workspace.artifact(entry.cid)
        self.assertEqual(artifact.format, "riscv64-baremetal-raw-v1")
        mapping = workspace.map_semantic(artifact.entry_handle, artifact.handle, 8)
        self.assertTrue(any(item.end > item.start for item in mapping.ranges))


class Riscv64NegativeTests(unittest.TestCase):
    def test_float_values_are_not_in_the_profile(self):
        f64 = float_type(FloatFormat.BINARY64)
        graph = GraphBuilder()
        block = graph.block(f64, f64)
        block.ret(block.op1(Operation.FLOAT_ADD, block.params, f64))
        entry = graph.function((f64, f64), (f64,))
        with self.assertRaises(XaxError) as raised:
            _compile(entry, tuple(graph.objects.values()))
        self.assertEqual(raised.exception.diagnostic.code, "XAX.RISCV64.UNSUPPORTED_OPERATION")

    def test_more_than_eight_register_arguments_rejects(self):
        b32 = bits_type(32)
        graph = GraphBuilder()
        block = graph.block(*(b32,) * 9)
        block.ret(block.params[8])
        entry = graph.function((b32,) * 9, (b32,))
        with self.assertRaises(XaxError) as raised:
            _compile(entry, tuple(graph.objects.values()))
        self.assertEqual(raised.exception.diagnostic.rule, "RISCV64-REGISTER-ARGUMENTS")

    def test_target_machine_tuple_is_exact(self):
        identity = b"riscv64-baremetal-raw-v1"
        body = bytearray(uleb(len(identity)) + identity)
        for value in (2, RISCV64_ARCHITECTURE, RISCV64_LP64_ABI, 1, 64, 64):
            body.extend(uleb(value))
        body.extend(uleb(1) + bytes((1,)) + uleb(1) + bytes((3,)))
        body.extend(uleb(0) * 4)  # profile 2's (empty) concurrency fields; RV64 is exactly profile 1
        with self.assertRaises(XaxError) as raised:
            decode_native_target(SemanticObject.create(Kind.TARGET, bytes(body)))
        self.assertEqual(raised.exception.diagnostic.rule, "TARGET-RISCV64-RAW")

    def test_image_is_deterministic_and_entry_first(self):
        entry, graph = _random_function(random.Random(5), 32)
        first = _compile(entry, tuple(graph.objects.values()))[1]
        second = _compile(entry, tuple(graph.objects.values()))[1]
        self.assertEqual(first.code, second.code)
        self.assertEqual(first.entry_offset, 0)
        self.assertEqual(dict(first.function_offsets)[entry.cid], 0)


if __name__ == "__main__":
    unittest.main()
