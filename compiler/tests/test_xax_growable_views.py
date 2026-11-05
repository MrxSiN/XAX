"""Growable views (ADR-368, N0.3): ``extent<V>``, ``extent.make``/``extent.grow`` and the growable checked accesses.

A Linux program maps a heap view, makes its extent, grows it, and stores and loads through it; each forged variant
rejects with its rule.  Verification here is the reference (bootstrap) passes; the XAX typing and facts programs and the
native backends follow in later steps of N0.3.
"""

from __future__ import annotations

import unittest

import xax_compiler
from xax_compiler import (
    Operation, Permission, XaxError, bits_type, extent_type, heap_view_type, pointer_type, verify_store,
)
from xax_graph_builder import GraphBuilder, program_store
from xax_linux import linux_api

B8, B32, B64 = bits_type(8), bits_type(32), bits_type(64)
RESERVATION = 1 << 20
BYTES = pointer_type(B8, Permission.READ_WRITE, 16, space=2)


def program(mutation: str | None = None):
    """A Linux entry whose exit status is a byte stored and loaded back through a grown extent."""
    api = linux_api()
    mem = api.memory_effect
    view_type = heap_view_type(RESERVATION)
    extent = extent_type(view_type)
    graph = GraphBuilder()
    graph.track(*api.types, B8, B32, B64, BYTES, view_type, extent)
    block = graph.block(api.process_effect, api.filesystem_effect, mem)
    process, fs, memory = block.params
    raw, owner, memory = block.op(Operation.CALL_FOREIGN, (block.const(B64, RESERVATION), memory), (api.bytes_rw, api.heap_owner, mem),
                                  entity=api.mmap_anonymous)
    view, token, memory = block.op(Operation.HEAP_VIEW, (raw, owner, memory), (BYTES, view_type, mem), attributes=(RESERVATION, 16))
    wrong = extent_type(heap_view_type(64))
    graph.track(heap_view_type(64), wrong)
    token, limit = block.op(Operation.EXTENT_MAKE, (token,), (view_type, extent if mutation != "wrong-extent-type" else wrong))
    limit = block.op1(Operation.EXTENT_GROW, (limit, block.const(B32 if mutation == "narrow-grow" else B64, 4096)), extent)
    if mutation == "bound-not-extent":
        limit = block.const(B64, 4096)
    at = view if mutation != "offset-pointer" else block.op1(Operation.ADDRESS_OFFSET, (view,), BYTES, attributes=(16,))
    memory = block.op1(Operation.GROWABLE_STORE_BITS_LE, (at, block.const(B32, 100), limit, block.const(B8, 42), memory), mem, attributes=(1, 1))
    value, memory = block.op(Operation.GROWABLE_LOAD_BITS_LE, (at, block.const(B32, 100), limit, memory), (B8, mem), attributes=(1, 1))
    status = block.op1(Operation.INT_ZERO_EXTEND, (value,), B32)
    memory = block.op(Operation.CALL_FOREIGN, (view, token, memory), (B64, mem), entity=api.munmap_view(BYTES, RESERVATION))[1]
    process = block.op1(Operation.CALL_FOREIGN, (status, process), api.process_effect, entity=api.exit_group)
    block.ret(status, process, fs, memory)
    function = graph.function((api.process_effect, api.filesystem_effect, mem), (B32, api.process_effect, api.filesystem_effect, mem))
    return function, tuple(graph.objects.values())


class GrowableViewTests(unittest.TestCase):
    def verify(self, mutation=None):
        """The reference passes alone (the XAX graph decoder and typing program do not know these yet)."""
        saved = (xax_compiler._NATIVE_TYPING, xax_compiler._TYPING_ATTEMPTED, xax_compiler._NATIVE_GRAPH_DECODER, xax_compiler._GRAPH_DECODER_ATTEMPTED)
        xax_compiler._NATIVE_TYPING, xax_compiler._TYPING_ATTEMPTED = None, True
        xax_compiler._NATIVE_GRAPH_DECODER, xax_compiler._GRAPH_DECODER_ATTEMPTED = None, True
        xax_compiler._PARSED_GRAPHS.clear()
        try:
            function, objects = program(mutation)
            for item in objects:
                xax_compiler._XAX_REJECTED_OBJECTS.pop(item.cid, None)
            verify_store(program_store(function, xax_compiler.x86_64_linux_exec_target(), objects))
        finally:
            (xax_compiler._NATIVE_TYPING, xax_compiler._TYPING_ATTEMPTED, xax_compiler._NATIVE_GRAPH_DECODER,
             xax_compiler._GRAPH_DECODER_ATTEMPTED) = saved
            xax_compiler._PARSED_GRAPHS.clear()

    def test_valid_program_verifies(self):
        self.verify()

    def test_forged_extents_reject(self):
        for mutation, rule in (("wrong-extent-type", "MEMORY-EXTENT-TYPE"), ("offset-pointer", "MEMORY-GROWABLE-WHOLE-VIEW"),
                               ("narrow-grow", "MEMORY-EXTENT-GROW-TYPES"), ("bound-not-extent", "MEMORY-GROWABLE-EXTENT")):
            with self.subTest(mutation), self.assertRaises(XaxError) as raised:
                self.verify(mutation)
            self.assertEqual(raised.exception.diagnostic.rule, rule)


if __name__ == "__main__":
    unittest.main()
