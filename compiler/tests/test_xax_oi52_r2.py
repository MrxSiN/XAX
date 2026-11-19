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


if __name__ == "__main__":
    unittest.main()
