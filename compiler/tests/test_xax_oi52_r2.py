"""OI-52 R2 (ADR-412): checked accesses with a ``bits<64>`` byte offset.

A callee maps a lazily reserved heap view past 4 GiB and stores and loads one byte through checked accesses at a
``bits<64>`` run-time offset.  The bound is still ``offset + size <= extent``, evaluated without a wrap: the last byte
answers 42, and the first byte past the extent and offsets near 2^64 trap.  ``bits<32>`` offsets keep their meaning.
"""

from __future__ import annotations

import platform
import unittest

from xax_compiler import Operation, Permission, XaxError, bits_type, heap_view_type, pointer_type, verify_store, x86_64_linux_exec_target
from xax_graph_builder import GraphBuilder, program_store
from xax_linux import compile_linux_executable, linux_api, run_linux_executable

B8, B32, B64 = bits_type(8), bits_type(32), bits_type(64)
GIB = 1 << 30
EXTENT = 8 * GIB
CASES = ((EXTENT, EXTENT - 1, 42), (EXTENT, EXTENT, None), (EXTENT, (1 << 32) + 7, 42), (EXTENT, (1 << 64) - 1, None),
         (EXTENT, (1 << 64) - EXTENT, None), (4096, 4095, 42), (4096, 4096, None))


def program(extent: int, offset: int, extra: int = 0, offset_type=B64, api=None):
    """``program`` of ``test_xax_oi52_r1`` with the offset (and ``extra`` machine parameters) of ``offset_type``, for
    ``api`` (Linux x86-64 by default)."""
    api = api or linux_api()
    mem = api.memory_effect
    view_type = heap_view_type(extent)
    bytes_view = pointer_type(B8, Permission.READ_WRITE, 16, space=2)
    graph = GraphBuilder()
    graph.track(*api.types, B8, B32, B64, offset_type, bytes_view, view_type)
    block = graph.block(offset_type, *(offset_type,) * extra, mem)
    at, memory = block.params[0], block.params[-1]
    raw, owner, memory = block.op(Operation.CALL_FOREIGN, (block.const(B64, extent), memory), (api.bytes_rw, api.heap_owner, mem),
                                  entity=api.mmap_anonymous)
    view, token, memory = block.op(Operation.HEAP_VIEW, (raw, owner, memory), (bytes_view, view_type, mem), attributes=(extent, 16))
    memory = block.op1(Operation.CHECKED_STORE_BITS_LE, (view, at, block.const(B8, 42), memory), mem, attributes=(1, 1))
    value, memory = block.op(Operation.CHECKED_LOAD_BITS_LE, (view, at, memory), (B8, mem), attributes=(1, 1))
    memory = block.op(Operation.CALL_FOREIGN, (view, token, memory), (B64, mem), entity=api.munmap_view(bytes_view, extent))[1]
    block.ret(value, memory)
    callee = graph.function((offset_type, *(offset_type,) * extra, mem), (B8, mem))
    objects = tuple(graph.objects.values())
    graph = GraphBuilder()
    block = graph.block(api.process_effect, api.filesystem_effect, mem)
    process, fs, memory = block.params
    arguments = (block.const(offset_type, offset), *(block.const(offset_type, k) for k in range(extra)), memory)
    value, memory = block.op(Operation.CALL_DIRECT, arguments, (B8, mem), entity=callee)
    status = block.op1(Operation.INT_ZERO_EXTEND, (value,), B32)
    process = block.op1(Operation.CALL_FOREIGN, (status, process), api.process_effect, entity=api.exit_group)
    block.ret(status, process, fs, memory)
    entry = graph.function((api.process_effect, api.filesystem_effect, mem), (B32, api.process_effect, api.filesystem_effect, mem))
    return entry, (*objects, *graph.objects.values(), *api.types)


class VerifierTests(unittest.TestCase):
    def test_a_64_bit_offset_verifies(self):
        entry, objects = program(EXTENT, 0)
        verify_store(program_store(entry, x86_64_linux_exec_target(), objects))

    def test_other_widths_reject(self):
        for width in (8, 16):
            with self.subTest(width=width):
                with self.assertRaises(XaxError) as raised:
                    entry, objects = program(4096, 0, offset_type=bits_type(width))
                    program_store(entry, x86_64_linux_exec_target(), objects)
                diagnostic = raised.exception.diagnostic
                self.assertEqual((diagnostic.rule, diagnostic.expected, diagnostic.actual), ("MEMORY-CHECKED-OFFSET-BITS", [32, 64], width))


@unittest.skipUnless(platform.system() == "Linux" and platform.machine() in ("x86_64", "AMD64"), "requires Linux x86-64")
class X86_64Tests(unittest.TestCase):
    def run_cases(self, extra=0, frontends=("xax",)):
        target = x86_64_linux_exec_target()
        for frontend in frontends:
            for extent, offset, expected in CASES:
                with self.subTest(frontend=frontend, extent=extent, offset=offset):
                    entry, objects = program(extent, offset, extra)
                    reader = program_store(entry, target, objects)
                    completed = run_linux_executable(compile_linux_executable(reader, entry.cid, target.cid, frontend=frontend).data)
                    if expected is None:
                        self.assertLess(completed.returncode, 0)  # the checked access's trap
                    else:
                        self.assertEqual(completed.returncode, expected)

    def test_register_path(self):
        self.run_cases()

    def test_frame_path(self):
        """A callee of five machine parameters is lowered on the frame path."""
        self.run_cases(extra=4)


class AArch64Tests(unittest.TestCase):
    """The AArch64 general backend under Linux (qemu-aarch64 or an adb device), heap views past 4 GiB."""

    def run_cases(self, extra=0):
        from xax_compiler import aarch64_linux_exec_target
        from xax_linux_aarch64 import aarch64_runner, compile_linux_aarch64_executable, linux_aarch64_api, run_linux_aarch64_executable

        if aarch64_runner() is None:
            self.skipTest("requires qemu-aarch64 or an AArch64 device")
        target = aarch64_linux_exec_target()
        for extent, offset, expected in CASES:
            with self.subTest(extent=extent, offset=offset):
                entry, objects = program(extent, offset, extra, api=linux_aarch64_api())
                data = compile_linux_aarch64_executable(program_store(entry, target, objects), entry.cid, target.cid, frontend="xax").data
                completed = run_linux_aarch64_executable(data)
                if expected is None:
                    self.assertNotIn(completed.returncode, (0, 42))  # the checked access's trap
                else:
                    self.assertEqual(completed.returncode, expected)

    def test_register_path(self):
        self.run_cases()

    def test_five_parameters(self):
        self.run_cases(extra=4)


SMALL = 64  # the 32-bit-index targets' views
NEAR = (0, 1, SMALL - 1, SMALL, 1 << 31, (1 << 32) - 1, 1 << 32, (1 << 32) + 1, (1 << 64) - SMALL, (1 << 64) - 1)
DATA = bytes(((k * 37) + 11) & 255 for k in range(SMALL))


def _expected(offset):
    return DATA[offset] if offset < SMALL else None


class RiscvTests(unittest.TestCase):
    """RV64 compares the whole register (``bgeu``), so the views profile lowers a ``bits<64>`` offset as it is; the XAX
    backend program and the reference make the same image (ADR-412, amended)."""

    def test_views_profile(self):
        try:
            import unicorn  # noqa: F401
        except ImportError:
            self.skipTest("requires unicorn")
        from xax_compiler import memory_effect_type, riscv64_views_target
        from xax_riscv64 import compile_riscv64_bound_target, run_riscv64_views

        mem, target = memory_effect_type(), riscv64_views_target()
        view_in, view_out = heap_view_type(SMALL, initialized=True), heap_view_type(2 * SMALL, initialized=True)
        pointer = pointer_type(B8, Permission.READ_WRITE, 1, space=2)
        words = [int.from_bytes(DATA[k:k + 8], "little") for k in range(0, SMALL, 8)]
        graph = GraphBuilder()
        graph.track(view_in, view_out, pointer, B8, B64, mem)
        block = graph.block(pointer, view_in, mem, pointer, view_out, mem, B64)
        p, tin, memory, q, tout, mout, offset = block.params
        value, memory = block.op(Operation.CHECKED_LOAD_BITS_LE, (p, offset, memory), (B8, mem), attributes=(1, 1))
        block.ret(value, p, tin, memory, q, tout, mout)
        function = graph.function((pointer, view_in, mem, pointer, view_out, mem, B64), (B8, pointer, view_in, mem, pointer, view_out, mem))
        reader = program_store(function, target, tuple(graph.objects.values()))
        image = compile_riscv64_bound_target(reader, function.cid, target, backend="xax")
        self.assertEqual(image, compile_riscv64_bound_target(reader, function.cid, target, backend="python"))
        for offset in NEAR:
            with self.subTest(offset=offset):
                status, _ = run_riscv64_views(image, words, SMALL, 2 * SMALL, lambda read: None, extra_arguments=(offset,))
                expected = _expected(offset)
                self.assertEqual(status if expected is None else status & 255, "trap" if expected is None else expected)


class JvmTests(unittest.TestCase):
    """The JVM backend compares the ``long`` offset unsigned against ``extent - size`` before it narrows it."""

    def test_memory_target(self):
        import shutil

        if not (shutil.which("java") and shutil.which("javac")):
            self.skipTest("requires a JDK")
        from xax_compiler import jvm_classfile_memory_target
        from xax_jvm import compile_jvm_bound_target, jvm_memory_api, run_jvm_calls
        from xax_structured import Proc

        api = jvm_memory_api()
        view = heap_view_type(SMALL)
        proc = Proc((("i", B64), ("m", api.memory_effect)))
        raw, owner, effect = proc.op(Operation.CALL_FOREIGN, (proc.const(SMALL, B64), proc.drop("m")), (api.bytes_rw, api.heap_owner, api.memory_effect),
                                     entity=api.mmap_anonymous)
        p, token, memory = proc.op(Operation.HEAP_VIEW, (raw, owner, effect), (api.bytes_rw, view, api.memory_effect), attributes=(SMALL, 1))
        for k in range(SMALL):
            memory = proc.op1(Operation.CHECKED_STORE_BITS_LE, (p, proc.const(k), proc.const(DATA[k], B8), memory), api.memory_effect, attributes=(1, 1))
        out, memory = proc.op(Operation.CHECKED_LOAD_BITS_LE, (p, proc["i"], memory), (B8, api.memory_effect), attributes=(1, 1))
        _status, memory = proc.op(Operation.CALL_FOREIGN, (p, token, memory), (B64, api.memory_effect), entity=api.munmap_view(api.bytes_rw, SMALL))
        proc.ret(out, memory)
        function = proc.function((B8, api.memory_effect))
        target = jvm_classfile_memory_target()
        reader = program_store(function, target, (*api.types, *proc.graph.objects.values(), B8, B32, B64, view))
        image = compile_jvm_bound_target(reader, function.cid, target)
        expected = tuple("trap java.lang.Error" if _expected(offset) is None else _expected(offset) for offset in NEAR)
        self.assertEqual(run_jvm_calls(image, [(offset,) for offset in NEAR], result_width=8), expected)


class WasmTests(unittest.TestCase):
    """The general Wasm32 profile compares a ``bits<64>`` offset with ``i64.gt_u`` and then wraps it (the reference and
    the XAX backend program make the same module).  The legacy ``oi06`` profile does not: OI-62."""

    def test_general_profile(self):
        import shutil
        import sys
        from pathlib import Path

        if not shutil.which("node"):
            self.skipTest("requires node")
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        from test_xax_byte_view_widening import BYTES, EXTENT as STACK, _stack_callee
        from xax_compiler import wasm32_general_target
        from xax_wasm import compile_wasm_bound_target, run_wasm_isolated

        target = wasm32_general_target()
        function, objects = _stack_callee(1, offset_type=B64)
        image = compile_wasm_bound_target(program_store(function, target, objects), function.cid, target)
        for offset in (0, STACK - 1, STACK, 1 << 32, (1 << 32) + 1, (1 << 64) - STACK, (1 << 64) - 1):
            with self.subTest(offset=offset):
                if offset >= STACK:
                    with self.assertRaises(Exception):
                        run_wasm_isolated(image, (offset,))
                else:
                    self.assertEqual(run_wasm_isolated(image, (offset,))[0] & 255, BYTES[offset])


if __name__ == "__main__":
    unittest.main()
