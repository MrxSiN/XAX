"""OI-53: the production compiler's ``xaxc verify`` rejects byte-view widening (ADR-231) that the reference and the
native typing program (as ``verify_store`` runs it) accept.

A Linux program maps a heap view of ``ptr<bits8>`` and stores a ``bits<64>`` with an 8-byte checked store.  The seed's
``verify`` answers MEMORY-CHECKED-STORE-TYPE (it is what BBC's committed driver fails on); ``verify_store`` accepts.
The functions are the same objects in both (the driver holds the typing store's 88 functions), so the difference is in
the tables the driver builds for them.  Expected to fail until a native transaction fixes the driver.
"""

from __future__ import annotations

import platform
import tempfile
import unittest
from pathlib import Path

import xax_compiler as X
import xax_selfhost_evolution as EV
from xax_compiler import Operation, Permission, bits_type, heap_view_type, pointer_type, x86_64_linux_exec_target
from xax_graph_builder import GraphBuilder, program_store
from xax_linux import linux_api

B8, B32, B64 = bits_type(8), bits_type(32), bits_type(64)


def widened_store():
    api = linux_api(); mem = api.memory_effect; extent = 65536
    view_type = heap_view_type(extent); bytes_view = pointer_type(B8, Permission.READ_WRITE, 1, space=2)
    graph = GraphBuilder(); graph.track(*api.types, B8, B32, B64, bytes_view, view_type)
    block = graph.block(api.process_effect, api.filesystem_effect, mem)
    process, fs, memory = block.params
    raw, owner, memory = block.op(Operation.CALL_FOREIGN, (block.const(B64, extent), memory), (api.bytes_rw, api.heap_owner, mem),
                                  entity=api.mmap_anonymous)
    view, token, memory = block.op(Operation.HEAP_VIEW, (raw, owner, memory), (bytes_view, view_type, mem), attributes=(extent, 1))
    memory = block.op1(Operation.CHECKED_STORE_BITS_LE, (view, block.const(B32, 8), block.const(B64, 42), memory), mem, attributes=(8, 1))
    value, memory = block.op(Operation.CHECKED_LOAD_BITS_LE, (view, block.const(B32, 8), memory), (B8, mem), attributes=(1, 1))
    status = block.op1(Operation.INT_ZERO_EXTEND, (value,), B32)
    memory = block.op(Operation.CALL_FOREIGN, (view, token, memory), (B64, mem), entity=api.munmap_view(bytes_view, extent))[1]
    process = block.op1(Operation.CALL_FOREIGN, (status, process), api.process_effect, entity=api.exit_group)
    block.ret(status, process, fs, memory)
    function = graph.function((api.process_effect, api.filesystem_effect, mem), (B32, api.process_effect, api.filesystem_effect, mem))
    return program_store(function, x86_64_linux_exec_target(), tuple(graph.objects.values()))


class ByteViewWideningTests(unittest.TestCase):
    def test_verify_store_accepts(self):
        X.verify_store(widened_store())

    @unittest.skipUnless(platform.system() == "Linux" and platform.machine() in ("x86_64", "AMD64"), "the seed runs on Linux x86-64")
    @unittest.expectedFailure  # OI-53
    def test_production_verify_accepts(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Path(directory) / "s.xax"
            store.write_bytes(widened_store().data)
            self.assertEqual(EV.run_compiler(EV.SEED_COMPILER, "verify", store, Path(directory) / "report"), 0)


if __name__ == "__main__":
    unittest.main()
