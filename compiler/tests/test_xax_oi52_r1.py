"""OI-52 R1 (ledgers 0010, 0011): x86-64 checked accesses whose bound ``extent - size`` is past ``imm32``.

A callee maps a heap view of up to 4 GiB - 4 KiB, reserved lazily, and stores and loads one byte through checked
accesses at a run-time offset.  The bound is materialized (``movabs r11, bound; cmp index, r11``) instead of rejected
(NATIVE-CHECKED-BOUND-ENCODABLE), on the register path (ledger 0010; the reference too) and on the frame path (ledger
0011: a callee of five machine parameters).  The last byte answers and the first byte past the extent traps.
"""

from __future__ import annotations

import platform
import unittest

from xax_compiler import Operation, Permission, bits_type, heap_view_type, pointer_type, x86_64_linux_exec_target
from xax_graph_builder import GraphBuilder, program_store
from xax_linux import compile_linux_executable, linux_api, run_linux_executable

B8, B32, B64 = bits_type(8), bits_type(32), bits_type(64)
CASES = (((1 << 31), (1 << 31) - 1, 42), ((1 << 31), 1 << 31, None), ((1 << 32) - 4096, (1 << 32) - 4097, 42),
         ((1 << 32) - 4096, (1 << 32) - 4096, None), (4096, 4095, 42), (4096, 4096, None))


def program(extent: int, offset: int, extra: int = 0):
    api = linux_api()
    mem = api.memory_effect
    view_type = heap_view_type(extent)
    bytes_view = pointer_type(B8, Permission.READ_WRITE, 16, space=2)
    graph = GraphBuilder()
    graph.track(*api.types, B8, B32, B64, bytes_view, view_type)
    block = graph.block(B32, *(B32,) * extra, mem)
    at, memory = block.params[0], block.params[-1]
    raw, owner, memory = block.op(Operation.CALL_FOREIGN, (block.const(B64, extent), memory), (api.bytes_rw, api.heap_owner, mem),
                                  entity=api.mmap_anonymous)
    view, token, memory = block.op(Operation.HEAP_VIEW, (raw, owner, memory), (bytes_view, view_type, mem), attributes=(extent, 16))
    memory = block.op1(Operation.CHECKED_STORE_BITS_LE, (view, at, block.const(B8, 42), memory), mem, attributes=(1, 1))
    value, memory = block.op(Operation.CHECKED_LOAD_BITS_LE, (view, at, memory), (B8, mem), attributes=(1, 1))
    memory = block.op(Operation.CALL_FOREIGN, (view, token, memory), (B64, mem), entity=api.munmap_view(bytes_view, extent))[1]
    block.ret(value, memory)
    callee = graph.function((B32, *(B32,) * extra, mem), (B8, mem))
    objects = tuple(graph.objects.values())
    graph = GraphBuilder()
    block = graph.block(api.process_effect, api.filesystem_effect, mem)
    process, fs, memory = block.params
    arguments = (block.const(B32, offset), *(block.const(B32, k) for k in range(extra)), memory)
    value, memory = block.op(Operation.CALL_DIRECT, arguments, (B8, mem), entity=callee)
    status = block.op1(Operation.INT_ZERO_EXTEND, (value,), B32)
    process = block.op1(Operation.CALL_FOREIGN, (status, process), api.process_effect, entity=api.exit_group)
    block.ret(status, process, fs, memory)
    entry = graph.function((api.process_effect, api.filesystem_effect, mem), (B32, api.process_effect, api.filesystem_effect, mem))
    return entry, (*objects, *graph.objects.values(), *api.types)


@unittest.skipUnless(platform.system() == "Linux" and platform.machine() in ("x86_64", "AMD64"), "requires Linux x86-64")
class BoundEncodingTests(unittest.TestCase):
    def test_bounds_past_imm32(self):
        target = x86_64_linux_exec_target()
        for frontend in ("xax", "python"):
            for extent, offset, expected in CASES:
                with self.subTest(frontend=frontend, extent=extent, offset=offset):
                    entry, objects = program(extent, offset)
                    reader = program_store(entry, target, objects)
                    completed = run_linux_executable(compile_linux_executable(reader, entry.cid, target.cid, frontend=frontend).data)
                    if expected is None:
                        self.assertLess(completed.returncode, 0)  # the checked access's trap (ud2)
                    else:
                        self.assertEqual(completed.returncode, expected)

    def test_frame_path_bounds_past_imm32(self):
        """A callee of five machine parameters is lowered on the frame path (ledger 0011)."""
        target = x86_64_linux_exec_target()
        for extent, offset, expected in CASES:
            with self.subTest(extent=extent, offset=offset):
                entry, objects = program(extent, offset, extra=4)
                reader = program_store(entry, target, objects)
                completed = run_linux_executable(compile_linux_executable(reader, entry.cid, target.cid, frontend="xax").data)
                if expected is None:
                    self.assertLess(completed.returncode, 0)
                else:
                    self.assertEqual(completed.returncode, expected)


if __name__ == "__main__":
    unittest.main()
