"""ADR-124: SPIR-V compute kernels from ordinary XAX functions, executed through Vulkan."""

from __future__ import annotations

import random
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from xax_compiler import (
    IntCompare,
    Operation,
    XaxError,
    bits_type,
    decode_native_target,
    float_type,
    FloatFormat,
    float_constant,
    spirv_vulkan_compute_target,
    target,
)
from xax_graph_builder import GraphBuilder, program_store
from xax_spirv import STATUS_BOUNDS, STATUS_TRAP, compile_spirv_kernel, reference_dispatch, run_spirv_kernel, vulkan_device

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from benchmarks.spirv_kernels import B1, B32, MEM, binding, collatz_kernel, mix_kernel, trap_kernel, words  # noqa: E402

SPIRV_VAL = shutil.which("spirv-val")
DEVICE = vulkan_device()


def _store_kernel(offset_builder, *, read_written: bool = False):
    """``data[f(i)] = i`` with a caller-chosen byte offset ``f``; used for race-rule vectors."""
    triple = binding(64)
    graph = GraphBuilder()
    block = graph.block(B32, *triple)
    invocation, pointer, view, memory = block.params
    offset = offset_builder(block, invocation)
    if read_written:
        _value, memory = block.op(Operation.CHECKED_LOAD_BITS_LE, (pointer, block.const(B32, 0), memory), (B32, MEM), attributes=(4, 1))
    memory = block.op1(Operation.CHECKED_STORE_BITS_LE, (pointer, offset, invocation, memory), MEM, attributes=(4, 1))
    block.ret(pointer, view, memory)
    kernel = graph.function((B32, *triple), triple)
    spirv = spirv_vulkan_compute_target()
    return program_store(kernel, spirv, tuple(graph.objects.values())), kernel, spirv


def _rule(callable_) -> str:
    with unittest.TestCase().assertRaises(XaxError) as caught:
        callable_()
    return caught.exception.diagnostic.rule


class SpirvTargetTests(unittest.TestCase):
    def test_target_package_decodes(self):
        description = decode_native_target(spirv_vulkan_compute_target())
        self.assertEqual((description.architecture, description.abi, description.image_format), (7, 8, 1))
        self.assertNotIn(Operation.CALL_FOREIGN, description.supported_operations)

    def test_module_is_deterministic_and_valid(self):
        reader, kernel, spirv = collatz_kernel(64)
        first = compile_spirv_kernel(reader, kernel.cid, spirv.cid)
        self.assertEqual(first.module, compile_spirv_kernel(reader, kernel.cid, spirv.cid).module)
        self.assertEqual(first.module[:4], struct.pack("<I", 0x07230203))
        self.assertEqual([item.extent for item in first.bindings], [256])

    @unittest.skipUnless(SPIRV_VAL, "requires spirv-val")
    def test_every_corpus_module_passes_spirv_val(self):
        for builder in (lambda: collatz_kernel(64), lambda: mix_kernel(64), lambda: mix_kernel(16, divide=False, extra_offset=32), lambda: trap_kernel(16)):
            reader, kernel, spirv = builder()
            module = compile_spirv_kernel(reader, kernel.cid, spirv.cid).module
            with tempfile.NamedTemporaryFile(suffix=".spv") as handle:
                handle.write(module)
                handle.flush()
                completed = subprocess.run([SPIRV_VAL, "--target-env", "vulkan1.1", handle.name], capture_output=True, text=True)
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)


class SpirvRejectionTests(unittest.TestCase):
    def test_other_targets_reject(self):
        reader, kernel, _spirv = collatz_kernel(16)
        from xax_compiler import x86_64_linux_exec_target

        other = x86_64_linux_exec_target()
        store = program_store(kernel, other, tuple(reader.objects()))
        self.assertEqual(_rule(lambda: compile_spirv_kernel(store, kernel.cid, other.cid)), "SPIRV-TARGET")

    def test_entry_contract(self):
        triple = binding(16)
        graph = GraphBuilder()
        graph.track(B32)  # the pointer element type
        block = graph.block(*triple)
        block.ret(*block.params)
        kernel = graph.function(triple, triple)
        spirv = spirv_vulkan_compute_target()
        reader = program_store(kernel, spirv, tuple(graph.objects.values()))
        self.assertEqual(_rule(lambda: compile_spirv_kernel(reader, kernel.cid, spirv.cid)), "SPIRV-KERNEL-ENTRY-CONTRACT")

    def test_unsupported_operation_rejects(self):
        f32 = float_type(FloatFormat.BINARY32)
        triple = binding(16)
        graph = GraphBuilder()
        block = graph.block(B32, *triple)
        constant = block.op1(Operation.CONSTANT, (), f32, entity=float_constant(f32, 1.5))
        block.op1(Operation.FLOAT_ADD, (constant, constant), f32)
        block.ret(*block.params[1:])
        kernel = graph.function((B32, *triple), triple)
        probe = target(b"spirv-probe")
        reader = program_store(kernel, probe, tuple(graph.objects.values()))
        spirv = spirv_vulkan_compute_target()
        store = program_store(kernel, spirv, tuple(reader.objects()))
        self.assertEqual(_rule(lambda: compile_spirv_kernel(store, kernel.cid, spirv.cid)), "SPIRV-OP-TARGET-SUPPORTED")

    def test_races_reject(self):
        own = lambda block, invocation: block.op1(Operation.MUL_WRAP, (invocation, block.const(B32, 4)), B32)
        reader, kernel, spirv = _store_kernel(own)
        compile_spirv_kernel(reader, kernel.cid, spirv.cid)  # the own-element store is accepted
        vectors = {
            "fixed offset": lambda block, invocation: block.const(B32, 0),
            "stride 8": lambda block, invocation: block.op1(Operation.MUL_WRAP, (invocation, block.const(B32, 8)), B32),
            "shifted": lambda block, invocation: block.op1(Operation.ADD_WRAP, (own(block, invocation), block.const(B32, 4)), B32),
        }
        for name, offset in vectors.items():
            with self.subTest(name):
                reader, kernel, spirv = _store_kernel(offset)
                self.assertEqual(_rule(lambda: compile_spirv_kernel(reader, kernel.cid, spirv.cid)), "SPIRV-KERNEL-OWN-ELEMENT")
        with self.subTest("read another element of a written binding"):
            reader, kernel, spirv = _store_kernel(own, read_written=True)
            self.assertEqual(_rule(lambda: compile_spirv_kernel(reader, kernel.cid, spirv.cid)), "SPIRV-KERNEL-OWN-ELEMENT")


@unittest.skipUnless(DEVICE, "requires a Vulkan device (e.g. Mesa llvmpipe) and the vulkan Python bindings")
class SpirvExecutionTests(unittest.TestCase):
    def _differential(self, built, buffers, count):
        reader, kernel, spirv = built
        compiled = compile_spirv_kernel(reader, kernel.cid, spirv.cid)
        launch = run_spirv_kernel(compiled, buffers, count)
        self.assertEqual((launch.buffers, launch.status), reference_dispatch(reader, kernel.cid, buffers, count))
        return launch

    def test_collatz_matches_reference(self):
        rng = random.Random(1)
        values = [rng.randrange(1, 50_000) for _ in range(200)]
        launch = self._differential(collatz_kernel(200), [words(values)], 200)
        self.assertEqual(launch.status, 0)

    def test_partial_launch_leaves_the_tail_untouched(self):
        values = list(range(1, 129))
        launch = self._differential(collatz_kernel(128), [words(values)], 70)  # not a multiple of the workgroup size
        self.assertEqual(struct.unpack("<128I", launch.buffers[0])[70:], tuple(values[70:]))

    def test_mixed_integer_operations_match_reference(self):
        rng = random.Random(2)
        for seed in range(3):
            source = [rng.choice((0, 1, 2, 0x80, 0xFF, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF, rng.getrandbits(32))) for _ in range(64)]
            source = [value or 1 for value in source]  # no divide-by-zero in this vector
            with self.subTest(seed=seed):
                launch = self._differential(mix_kernel(64), [words(source), bytes(256)], 64)
                self.assertEqual(launch.status, 0)

    def test_divide_by_zero_traps_only_its_invocation(self):
        values = [13 if index in (3, 50) else index + 20 for index in range(64)]
        launch = self._differential(trap_kernel(64), [words(values)], 64)
        self.assertEqual(launch.status, STATUS_TRAP | 2)
        out = struct.unpack("<64I", launch.buffers[0])
        self.assertEqual((out[3], out[50]), (13, 13))  # trapped invocations stored nothing
        self.assertEqual(out[4], 1_000_000 // (24 - 13))

    def test_out_of_bounds_read_traps(self):
        launch = self._differential(mix_kernel(16, divide=False, extra_offset=32), [words(list(range(1, 17))), bytes(64)], 16)
        self.assertEqual(launch.status, STATUS_BOUNDS)


if __name__ == "__main__":
    unittest.main()
