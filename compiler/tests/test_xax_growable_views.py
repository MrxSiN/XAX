"""Growable views (ADR-369, N0.3): checked accesses bounded by a runtime ``bits<64>`` limit as well as the extent.

A Linux program maps a heap view reserved at its largest extent, grows a limit with ordinary arithmetic, and stores and
loads through ``growable.store/load.bits.le``; forged variants reject with their rules, in the reference passes and in
the XAX graph decoder, typing and facts programs (ledger 0006).  The native x86-64 and AArch64 general backends lower
the accesses: past the limit or the extent they trap.
"""

from __future__ import annotations

import unittest

import xax_compiler
from xax_compiler import (
    Operation, Permission, XaxError, aarch64_linux_exec_target, bits_type, heap_view_type, memory_effect_type, pointer_type,
    stack_owner_type, verify_store, x86_64_linux_exec_target,
)
from xax_graph_builder import GraphBuilder, program_store
from xax_linux import linux_api

B8, B32, B64 = bits_type(8), bits_type(32), bits_type(64)
MEM, OWNER = memory_effect_type(), stack_owner_type()
RESERVATION = 1 << 20
BYTES = pointer_type(B8, Permission.READ_WRITE, 16, space=2)
EXTENT = 32


def program(mutation: str | None = None, limit: int = 4096, api=None):
    """A Linux entry whose exit status is a byte stored and loaded back below a grown limit."""
    api = api or linux_api()
    mem = api.memory_effect
    view_type = heap_view_type(RESERVATION)
    graph = GraphBuilder()
    graph.track(*api.types, B8, B32, B64, BYTES, view_type)
    block = graph.block(api.process_effect, api.filesystem_effect, mem)
    process, fs, memory = block.params
    raw, owner, memory = block.op(Operation.CALL_FOREIGN, (block.const(B64, RESERVATION), memory), (api.bytes_rw, api.heap_owner, mem),
                                  entity=api.mmap_anonymous)
    view, token, memory = block.op(Operation.HEAP_VIEW, (raw, owner, memory), (BYTES, view_type, mem), attributes=(RESERVATION, 16))
    # the limit grows by ordinary arithmetic: 0, then ``limit`` bytes
    grown = block.op1(Operation.ADD_WRAP, (block.const(B64, 0), block.const(B64, limit)), B64)
    if mutation == "narrow-limit":
        grown = block.const(B32, limit)
    stored = block.const(B32, 42) if mutation == "wide-store" else block.const(B8, 42)  # a 1-byte access storing a bits<32> value
    memory = block.op1(Operation.GROWABLE_STORE_BITS_LE, (view, block.const(B32, 100), grown, stored, memory), mem, attributes=(1, 1))
    value, memory = block.op(Operation.GROWABLE_LOAD_BITS_LE, (view, block.const(B32, 100), grown, memory), (B8, mem), attributes=(1, 1))
    status = block.op1(Operation.INT_ZERO_EXTEND, (value,), B32)
    memory = block.op(Operation.CALL_FOREIGN, (view, token, memory), (B64, mem), entity=api.munmap_view(BYTES, RESERVATION))[1]
    process = block.op1(Operation.CALL_FOREIGN, (status, process), api.process_effect, entity=api.exit_group)
    block.ret(status, process, fs, memory)
    function = graph.function((api.process_effect, api.filesystem_effect, mem), (B32, api.process_effect, api.filesystem_effect, mem))
    return function, tuple(graph.objects.values())


def callee_program(api, offset: int, limit: int):
    """An entry calling ``(offset: bits<32>, limit: bits<64>) -> bits<8>``: a 32-byte stack view, zeroed, then a growable
    store of 42 and a growable load at ``offset``: dynamic offset and limit, the backends' register paths."""
    graph = GraphBuilder()
    pointer = pointer_type(B8, Permission.READ_WRITE, 1)
    graph.track(pointer, OWNER, MEM, B8, B32, B64)
    block = graph.block(B32, B64)
    at_offset, at_limit = block.params
    p, owner, memory = block.op(Operation.STACK_ALLOC, (), (pointer, OWNER, MEM), attributes=(EXTENT, 1))
    for k in range(EXTENT):
        at = p if k == 0 else block.op1(Operation.ADDRESS_OFFSET, (p,), pointer, attributes=(k,))
        memory = block.op1(Operation.STORE_BITS_LE, (at, block.const(B8, 0), memory), MEM, attributes=(1, 1))
    memory = block.op1(Operation.GROWABLE_STORE_BITS_LE, (p, at_offset, at_limit, block.const(B8, 42), memory), MEM, attributes=(1, 1))
    out, memory = block.op(Operation.GROWABLE_LOAD_BITS_LE, (p, at_offset, at_limit, memory), (B8, MEM), attributes=(1, 1))
    block.op(Operation.STACK_END, (owner, memory), ())
    block.ret(out)
    callee = graph.function((B32, B64), (B8,))
    objects = tuple(graph.objects.values())
    graph = GraphBuilder()
    block = graph.block(api.process_effect, api.filesystem_effect)
    process, fs = block.params
    result = block.op1(Operation.CALL_DIRECT, (block.const(B32, offset), block.const(B64, limit)), B8, entity=callee)
    status = block.op1(Operation.INT_ZERO_EXTEND, (result,), B32)
    process = block.op1(Operation.CALL_FOREIGN, (status, process), api.process_effect, entity=api.exit_group)
    block.ret(status, process, fs)
    entry = graph.function((api.process_effect, api.filesystem_effect), (B32, api.process_effect, api.filesystem_effect))
    return entry, (*objects, *graph.objects.values(), *api.types)


# (offset, limit, exit status or None for a trap); the extent is 32 bytes
CALLEE_CASES = ((5, 6, 42), (5, 64, 42), (31, 32, 42), (31, 64, 42), (5, 5, None), (32, 64, None))
ENTRY_CASES = ((4096, 42), (101, 42), (100, None), (0, None))


class GrowableViewTests(unittest.TestCase):
    def verify(self, mutation=None, native=False):
        """The reference passes alone, or with the XAX graph decoder and typing program (``native``)."""
        saved = (xax_compiler._NATIVE_TYPING, xax_compiler._TYPING_ATTEMPTED, xax_compiler._NATIVE_GRAPH_DECODER, xax_compiler._GRAPH_DECODER_ATTEMPTED)
        if not native:
            xax_compiler._NATIVE_TYPING, xax_compiler._TYPING_ATTEMPTED = None, True
            xax_compiler._NATIVE_GRAPH_DECODER, xax_compiler._GRAPH_DECODER_ATTEMPTED = None, True
        xax_compiler._PARSED_GRAPHS.clear()
        try:
            function, objects = program(mutation)
            verify_store(program_store(function, x86_64_linux_exec_target(), objects))
        finally:
            (xax_compiler._NATIVE_TYPING, xax_compiler._TYPING_ATTEMPTED, xax_compiler._NATIVE_GRAPH_DECODER,
             xax_compiler._GRAPH_DECODER_ATTEMPTED) = saved
            xax_compiler._PARSED_GRAPHS.clear()

    def test_valid_program_verifies(self):
        for native in (False, True):
            with self.subTest(native=native):
                self.verify(native=native)

    def test_forged_accesses_reject(self):
        for native in (False, True):
            for mutation, rule in (("narrow-limit", "MEMORY-GROWABLE-LIMIT-BITS"), ("wide-store", "MEMORY-CHECKED-STORE-TYPE")):
                with self.subTest(mutation, native=native):
                    with self.assertRaises(XaxError) as raised:
                        self.verify(mutation, native)
                    self.assertEqual(raised.exception.diagnostic.rule, rule)

    def check(self, completed, expected):
        if expected is None:
            self.assertLess(completed.returncode, 0)  # a trap: SIGILL (ud2) on x86-64, SIGTRAP (brk) on AArch64
        else:
            self.assertEqual(completed.returncode, expected)

    def test_linux_x86_64_native(self):
        import platform

        from xax_linux import compile_linux_executable, run_linux_executable

        if platform.system() != "Linux" or platform.machine() not in ("x86_64", "AMD64"):
            self.skipTest("requires Linux x86-64")
        target = x86_64_linux_exec_target()
        for limit, expected in ENTRY_CASES:
            with self.subTest("entry", limit=limit):
                function, objects = program(limit=limit)
                reader = program_store(function, target, objects)
                self.check(run_linux_executable(compile_linux_executable(reader, function.cid, target.cid, frontend="xax").data), expected)
        for offset, limit, expected in CALLEE_CASES:
            with self.subTest("callee", offset=offset, limit=limit):
                entry, objects = callee_program(linux_api(), offset, limit)
                reader = program_store(entry, target, objects)
                self.check(run_linux_executable(compile_linux_executable(reader, entry.cid, target.cid, frontend="xax").data), expected)

    def test_linux_aarch64_native(self):
        from xax_linux_aarch64 import aarch64_runner, compile_linux_aarch64_executable, linux_aarch64_api, run_linux_aarch64_executable

        if aarch64_runner() is None:
            self.skipTest("requires an AArch64 Linux host or qemu-aarch64")
        target = aarch64_linux_exec_target()
        for limit, expected in ENTRY_CASES:
            with self.subTest("entry", limit=limit):
                function, objects = program(limit=limit, api=linux_aarch64_api())
                reader = program_store(function, target, objects)
                data = compile_linux_aarch64_executable(reader, function.cid, target.cid, frontend="xax").data
                self.check(run_linux_aarch64_executable(data), expected)
        for offset, limit, expected in CALLEE_CASES:
            with self.subTest("callee", offset=offset, limit=limit):
                entry, objects = callee_program(linux_aarch64_api(), offset, limit)
                reader = program_store(entry, target, objects)
                data = compile_linux_aarch64_executable(reader, entry.cid, target.cid, frontend="xax").data
                self.check(run_linux_aarch64_executable(data), expected)


if __name__ == "__main__":
    unittest.main()
