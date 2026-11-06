"""ADR-379 (ledger 0016): borrowed views given back to a frame-path caller.

``callee`` (more than 256 nodes, so not inlined) takes ``(ptr, view, memory, x)``, stores ``x`` at word 0 of the
view and returns ``(x + 1 + pad, ptr, view, memory)``: one machine value and a borrowed view (ADR-101).  ``caller``
takes six machine parameters, so the frame path lowers it.  It calls ``callee`` and then stores ``y`` at word 1 and
loads word 0 through the *returned* pointer, and leaves ``a + y + word 0`` at word 2.  Before ledger 0016 the frame
path counted the borrowed pointer as a second machine result and rejected the call (``NATIVE-CALL-ARITY``).  Run on
Linux x86-64, and as a PE executable under wine when wine is present.
"""

from __future__ import annotations

import os
import platform
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

B32, B64, B8 = bits_type(32), bits_type(64), bits_type(8)
EXTENT = 1 << 16
PAD = 300  # add.wrap nodes that keep the callee above the inliner's 256 nodes


def expected(x, a):
    y = (x + 1 + sum(range(PAD))) & ((1 << 64) - 1)
    return (a + y + x) & 255


def program(x0, a0):
    api = win32_kernel32_api()
    view_type = heap_view_type(EXTENT)
    pointer = pointer_type(B8, Permission.READ_WRITE, 8, space=2)
    mem = api.memory_effect

    graph = GraphBuilder()
    graph.track(*api.types, B8, B32, B64, pointer, view_type)
    c = graph.block(pointer, view_type, mem, B64)
    p, v, m, x = c.params
    m = c.op1(Operation.CHECKED_STORE_BITS_LE, (p, c.const(B32, 0), x, m), mem, attributes=(8, 1))
    y = c.op1(Operation.ADD_WRAP, (x, c.const(B64, 1)), B64)
    for k in range(PAD):
        y = c.op1(Operation.ADD_WRAP, (y, c.const(B64, k)), B64)
    c.ret(y, p, v, m)
    callee = graph.function((pointer, view_type, mem, B64), (B64, pointer, view_type, mem))
    objects = list(graph.objects.values())

    graph = GraphBuilder()
    graph.track(*api.types, B8, B32, B64, pointer, view_type)
    h = graph.block(B64, pointer, view_type, mem, B32, B32, B32, B32)
    x, p, v, m, a, b, cc, d = h.params
    y, p2, v2, m = h.op(Operation.CALL_DIRECT, (p, v, m, x), (B64, pointer, view_type, mem), entity=callee)
    m = h.op1(Operation.CHECKED_STORE_BITS_LE, (p2, h.const(B32, 8), y, m), mem, attributes=(8, 1))
    w0, m = h.op(Operation.CHECKED_LOAD_BITS_LE, (p2, h.const(B32, 0), m), (B64, mem), attributes=(8, 1))
    unused = h.op1(Operation.ADD_WRAP, (h.op1(Operation.INT_ZERO_EXTEND, (b,), B64),
                                        h.op1(Operation.ADD_WRAP, (h.op1(Operation.INT_ZERO_EXTEND, (cc,), B64), h.op1(Operation.INT_ZERO_EXTEND, (d,), B64)), B64)), B64)
    total = h.op1(Operation.ADD_WRAP, (h.op1(Operation.ADD_WRAP, (h.op1(Operation.INT_ZERO_EXTEND, (a,), B64), y), B64), w0), B64)
    total = h.op1(Operation.ADD_WRAP, (total, h.op1(Operation.MUL_WRAP, (unused, h.const(B64, 0)), B64)), B64)
    m = h.op1(Operation.CHECKED_STORE_BITS_LE, (p2, h.const(B32, 16), total, m), mem, attributes=(8, 1))
    h.ret(p2, v2, m)
    caller = graph.function((B64, pointer, view_type, mem, B32, B32, B32, B32), (pointer, view_type, mem))
    objects += graph.objects.values()

    graph = GraphBuilder()
    graph.track(*api.types, B8, B32, B64, pointer, view_type)
    block = graph.block(api.process_effect, api.filesystem_effect, mem)
    process, fs, memory = block.params
    raw, owner, memory = block.op(Operation.CALL_FOREIGN, (block.const(B64, 0), block.const(B64, EXTENT), block.const(B32, 0x3000),
                                                           block.const(B32, 4), memory), (api.heap_ptr_rw, api.heap_resource, mem), entity=api.virtual_alloc)
    view, token, memory = block.op(Operation.HEAP_VIEW, (raw, owner, memory), (pointer, view_type, mem), attributes=(EXTENT, 8))
    for k, value in enumerate((x0, a0)):  # through the heap, so the callee sees no constants
        memory = block.op1(Operation.CHECKED_STORE_BITS_LE, (view, block.const(B32, 64 + 8 * k), block.const(B64, value), memory), mem, attributes=(8, 1))
    xs, memory = block.op(Operation.CHECKED_LOAD_BITS_LE, (view, block.const(B32, 64), memory), (B64, mem), attributes=(8, 1))
    as_, memory = block.op(Operation.CHECKED_LOAD_BITS_LE, (view, block.const(B32, 72), memory), (B32, mem), attributes=(4, 1))
    zero = block.const(B32, 0)
    view, token, memory = block.op(Operation.CALL_DIRECT, (xs, view, token, memory, as_, zero, zero, zero), (pointer, view_type, mem), entity=caller)
    total, memory = block.op(Operation.CHECKED_LOAD_BITS_LE, (view, block.const(B32, 16), memory), (B64, mem), attributes=(8, 1))
    free = api.virtual_free_view(view_type, pointer)
    memory = block.op(Operation.CALL_FOREIGN, (view, block.const(B64, 0), block.const(B32, 0x8000), token, memory), (B32, mem), entity=free)[1]
    status = block.op1(Operation.INT_TRUNCATE, (block.op1(Operation.BIT_AND, (total, block.const(B64, 255)), B64),), B32)
    process = block.op1(Operation.CALL_FOREIGN, (status, process), api.process_effect, entity=api.exit_process)
    block.ret(status, process, fs, memory)
    entry = graph.function((api.process_effect, api.filesystem_effect, mem), (B32, api.process_effect, api.filesystem_effect, mem))
    target = x86_64_windows_pe_target()
    module = object_with_refs(Kind.MODULE, [entry, target])
    root = object_with_refs(Kind.PROGRAM_ROOT, [module])
    by_cid = {o.cid: o for o in (*api.types, *api.symbols, free, *objects, callee, caller, *graph.objects.values(), entry, target, module, root)}
    kept, pending = {}, [root.cid]
    while pending:
        cid = pending.pop()
        if cid not in kept:
            kept[cid] = by_cid[cid]
            pending.extend(kept[cid].references)
    return StoreReader(write_store(root.cid, list(kept.values()))), entry, target


class FrameBorrowedReturnTests(unittest.TestCase):
    def test_frame_caller_uses_the_returned_pointer(self):
        from xax_pe import compile_pe_executable
        from xax_selfhost_x86_64_general import native_general

        if native_general() is None:
            self.skipTest("the XAX general program cannot run here")
        wine = shutil.which("wine")
        with tempfile.TemporaryDirectory() as work:
            for x0, a0 in ((5, 7), (1000, 3)):
                with self.subTest(x=x0, a=a0):
                    reader, entry, target = program(x0, a0)
                    verify_store(reader)
                    data = compile_pe_executable(reader, entry.cid, target, frontend="xax")
                    if wine is None:
                        continue
                    path = Path(work) / "borrowed.exe"
                    path.write_bytes(data)
                    run = subprocess.run([wine, str(path)], capture_output=True, timeout=300, env={**os.environ, "WINEDEBUG": "-all"})
                    self.assertEqual(run.returncode, expected(x0, a0))


if __name__ == "__main__":
    unittest.main()
