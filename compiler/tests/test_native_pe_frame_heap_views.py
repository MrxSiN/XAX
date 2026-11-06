"""ADR-377 (ledger 0014): heap views on the general x86-64 frame path of a Windows PE executable.

The helper takes six machine parameters (``x``, a heap-view pointer and four ``bits<32>``) and has more than 256 nodes,
so it is neither inlined nor register resident: the frame path lowers it.  It stores ``x * k + a`` at ``(x + k) * 8``
for 100 values of ``k`` through the view, loads them back, and leaves ``b + c + d`` plus their sum in the view.  Before
ledger 0014 the frame path kept pointers first-class only on Linux, so the XAX general program declined the
executable (BBC's driver, which passes its views to such helpers, could not be built natively).  Under wine the
program exits with the sum's low byte, or traps (``ud2``: 0xC000001D) when an offset passes the view's extent.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from xax_compiler import (
    Kind, Operation, Permission, StoreReader, bits_type, heap_view_type, object_with_refs, pointer_type, verify_store,
    write_store, x86_64_windows_pe_target,
)
from xax_graph_builder import GraphBuilder
from xax_platform import win32_kernel32_api

B8, B32, B64 = bits_type(8), bits_type(32), bits_type(64)
EXTENT = 1 << 20
K = 100
ARGUMENTS_AT, RESULT_AT = 8 * 2000, 8 * 3000
ILLEGAL_INSTRUCTION = 0xC000001D & 0xFF
# (x, a, b, c, d); the last passes the extent: (131000 + 99) * 8 > 1 MiB
CASES = ((3, 5, 7, 11, 13), (1000, 1, 2, 3, 4), (130000, 9, 9, 9, 9), (131000, 1, 1, 1, 1))


def expected(x, a, b, c, d):
    if (x + K - 1) * 8 + 8 > EXTENT:
        return ILLEGAL_INSTRUCTION
    return (sum(x * k + a for k in range(K)) + b + c + d) & 255


def program(x0, a0, b0, c0, d0):
    api = win32_kernel32_api()
    view_type = heap_view_type(EXTENT)
    pointer = pointer_type(B8, Permission.READ_WRITE, 8, space=2)
    mem = api.memory_effect
    graph = GraphBuilder()
    graph.track(*api.types, B8, B32, B64, pointer, view_type)
    h = graph.block(B64, pointer, view_type, mem, B32, B32, B32, B32)
    x, p, v, m, a, b, c, d = h.params

    def offset(k):
        at = h.op1(Operation.MUL_WRAP, (h.op1(Operation.ADD_WRAP, (x, h.const(B64, k)), B64), h.const(B64, 8)), B64)
        return h.op1(Operation.INT_TRUNCATE, (at,), B32)

    def wide(value):
        return h.op1(Operation.INT_ZERO_EXTEND, (value,), B64)

    for k in range(K):
        value = h.op1(Operation.ADD_WRAP, (h.op1(Operation.MUL_WRAP, (x, h.const(B64, k)), B64), wide(a)), B64)
        m = h.op1(Operation.CHECKED_STORE_BITS_LE, (p, offset(k), value, m), mem, attributes=(8, 1))
    total = h.op1(Operation.ADD_WRAP, (wide(b), h.op1(Operation.ADD_WRAP, (wide(c), wide(d)), B64)), B64)
    for k in range(K):
        got, m = h.op(Operation.CHECKED_LOAD_BITS_LE, (p, offset(k), m), (B64, mem), attributes=(8, 1))
        total = h.op1(Operation.ADD_WRAP, (total, got), B64)
    m = h.op1(Operation.CHECKED_STORE_BITS_LE, (p, h.const(B32, RESULT_AT), total, m), mem, attributes=(8, 1))
    h.ret(p, v, m)
    helper = graph.function((B64, pointer, view_type, mem, B32, B32, B32, B32), (pointer, view_type, mem))
    objects = list(graph.objects.values())

    graph = GraphBuilder()
    graph.track(*api.types, B8, B32, B64, pointer, view_type)
    block = graph.block(api.process_effect, api.filesystem_effect, mem)
    process, fs, memory = block.params
    raw, owner, memory = block.op(Operation.CALL_FOREIGN, (block.const(B64, 0), block.const(B64, EXTENT), block.const(B32, 0x3000),
                                                           block.const(B32, 4), memory), (api.heap_ptr_rw, api.heap_resource, mem), entity=api.virtual_alloc)
    view, token, memory = block.op(Operation.HEAP_VIEW, (raw, owner, memory), (pointer, view_type, mem), attributes=(EXTENT, 8))
    # The arguments go through the heap, so the helper sees no constants.
    for k, value in enumerate((x0, a0, b0, c0, d0)):
        memory = block.op1(Operation.CHECKED_STORE_BITS_LE, (view, block.const(B32, ARGUMENTS_AT + 8 * k), block.const(B64, value), memory), mem,
                           attributes=(8, 1))
    arguments = []
    for k, width in enumerate((B64, B32, B32, B32, B32)):
        got, memory = block.op(Operation.CHECKED_LOAD_BITS_LE, (view, block.const(B32, ARGUMENTS_AT + 8 * k), memory), (width, mem),
                               attributes=(8 if width is B64 else 4, 1))
        arguments.append(got)
    view, token, memory = block.op(Operation.CALL_DIRECT, (arguments[0], view, token, memory, *arguments[1:]), (pointer, view_type, mem), entity=helper)
    total, memory = block.op(Operation.CHECKED_LOAD_BITS_LE, (view, block.const(B32, RESULT_AT), memory), (B64, mem), attributes=(8, 1))
    free = api.virtual_free_view(view_type, pointer)
    memory = block.op(Operation.CALL_FOREIGN, (view, block.const(B64, 0), block.const(B32, 0x8000), token, memory), (B32, mem), entity=free)[1]
    status = block.op1(Operation.INT_TRUNCATE, (block.op1(Operation.BIT_AND, (total, block.const(B64, 255)), B64),), B32)
    process = block.op1(Operation.CALL_FOREIGN, (status, process), api.process_effect, entity=api.exit_process)
    block.ret(status, process, fs, memory)
    entry = graph.function((api.process_effect, api.filesystem_effect, mem), (B32, api.process_effect, api.filesystem_effect, mem))
    target = x86_64_windows_pe_target()
    module = object_with_refs(Kind.MODULE, [entry, target])
    root = object_with_refs(Kind.PROGRAM_ROOT, [module])
    by_cid = {o.cid: o for o in (*api.types, *api.symbols, free, *objects, helper, *graph.objects.values(), entry, target, module, root)}
    kept, pending = {}, [root.cid]
    while pending:
        cid = pending.pop()
        if cid not in kept:
            kept[cid] = by_cid[cid]
            pending.extend(kept[cid].references)
    return StoreReader(write_store(root.cid, list(kept.values()))), entry, target


class PeFrameHeapViewTests(unittest.TestCase):
    def test_frame_path_heap_view_helper_under_wine(self):
        from xax_pe import compile_pe_executable
        from xax_selfhost_x86_64_general import native_general

        if native_general() is None:
            self.skipTest("the XAX general program cannot run here")
        wine = shutil.which("wine")
        if wine is None:
            self.skipTest("requires wine")
        with tempfile.TemporaryDirectory() as work:
            for case in CASES:
                with self.subTest(case=case):
                    reader, entry, target = program(*case)
                    verify_store(reader)
                    path = Path(work) / "frame.exe"
                    path.write_bytes(compile_pe_executable(reader, entry.cid, target, frontend="xax"))
                    run = subprocess.run([wine, str(path)], capture_output=True, timeout=300, env={**os.environ, "WINEDEBUG": "-all"})
                    self.assertEqual(run.returncode, expected(*case))


if __name__ == "__main__":
    unittest.main()
