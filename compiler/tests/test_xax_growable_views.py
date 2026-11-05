"""Growable views (ADR-369, N0.3): checked accesses bounded by a runtime ``bits<64>`` limit as well as the extent.

A Linux program maps a heap view reserved at its largest extent, grows a limit with ordinary arithmetic, and stores and
loads through ``growable.store/load.bits.le``; forged variants reject with their rules.  Verification here is the
reference (bootstrap) passes; the XAX graph decoder, typing and facts programs and the native backends learn the
operations in the next N0.3 steps.
"""

from __future__ import annotations

import unittest

import xax_compiler
from xax_compiler import Operation, Permission, XaxError, bits_type, heap_view_type, pointer_type, verify_store
from xax_graph_builder import GraphBuilder, program_store
from xax_linux import linux_api

B8, B32, B64 = bits_type(8), bits_type(32), bits_type(64)
RESERVATION = 1 << 20
BYTES = pointer_type(B8, Permission.READ_WRITE, 16, space=2)


def program(mutation: str | None = None):
    """A Linux entry whose exit status is a byte stored and loaded back below a grown limit."""
    api = linux_api()
    mem = api.memory_effect
    view_type = heap_view_type(RESERVATION)
    graph = GraphBuilder()
    graph.track(*api.types, B8, B32, B64, BYTES, view_type)
    block = graph.block(api.process_effect, api.filesystem_effect, mem)
    process, fs, memory = block.params
    raw, owner, memory = block.op(Operation.CALL_FOREIGN, (block.const(B64, RESERVATION), memory), (api.bytes_rw, api.heap_owner, mem),
                                  entity=api.mmap_anonymous)
    view, token, memory = block.op(Operation.HEAP_VIEW, (raw, owner, memory), (BYTES, view_type, mem), attributes=(RESERVATION, 16))
    # the limit grows by ordinary arithmetic: 0, then one 4 KiB page
    limit = block.op1(Operation.ADD_WRAP, (block.const(B64, 0), block.const(B64, 4096)), B64)
    if mutation == "narrow-limit":
        limit = block.const(B32, 4096)
    stored = block.const(B32, 42) if mutation == "wide-store" else block.const(B8, 42)  # a 1-byte access storing a bits<32> value
    memory = block.op1(Operation.GROWABLE_STORE_BITS_LE, (view, block.const(B32, 100), limit, stored, memory), mem, attributes=(1, 1))
    value, memory = block.op(Operation.GROWABLE_LOAD_BITS_LE, (view, block.const(B32, 100), limit, memory), (B8, mem), attributes=(1, 1))
    status = block.op1(Operation.INT_ZERO_EXTEND, (value,), B32)
    memory = block.op(Operation.CALL_FOREIGN, (view, token, memory), (B64, mem), entity=api.munmap_view(BYTES, RESERVATION))[1]
    process = block.op1(Operation.CALL_FOREIGN, (status, process), api.process_effect, entity=api.exit_group)
    block.ret(status, process, fs, memory)
    function = graph.function((api.process_effect, api.filesystem_effect, mem), (B32, api.process_effect, api.filesystem_effect, mem))
    return function, tuple(graph.objects.values())


class GrowableViewTests(unittest.TestCase):
    def verify(self, mutation=None):
        """The reference passes alone (the XAX graph decoder and typing program do not know these operations yet)."""
        saved = (xax_compiler._NATIVE_TYPING, xax_compiler._TYPING_ATTEMPTED, xax_compiler._NATIVE_GRAPH_DECODER, xax_compiler._GRAPH_DECODER_ATTEMPTED)
        xax_compiler._NATIVE_TYPING, xax_compiler._TYPING_ATTEMPTED = None, True
        xax_compiler._NATIVE_GRAPH_DECODER, xax_compiler._GRAPH_DECODER_ATTEMPTED = None, True
        xax_compiler._PARSED_GRAPHS.clear()
        try:
            function, objects = program(mutation)
            verify_store(program_store(function, xax_compiler.x86_64_linux_exec_target(), objects))
        finally:
            (xax_compiler._NATIVE_TYPING, xax_compiler._TYPING_ATTEMPTED, xax_compiler._NATIVE_GRAPH_DECODER,
             xax_compiler._GRAPH_DECODER_ATTEMPTED) = saved
            xax_compiler._PARSED_GRAPHS.clear()

    def test_valid_program_verifies(self):
        self.verify()

    def test_forged_accesses_reject(self):
        for mutation, rule in (("narrow-limit", "MEMORY-GROWABLE-LIMIT-BITS"), ("wide-store", "MEMORY-CHECKED-STORE-TYPE")):
            with self.subTest(mutation):
                with self.assertRaises(XaxError) as raised:
                    self.verify(mutation)
                self.assertEqual(raised.exception.diagnostic.rule, rule)


if __name__ == "__main__":
    unittest.main()
