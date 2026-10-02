"""``pointer_rebase`` (operation 73, ADR-092): verified reloads of exposed addresses.

A Linux process maps a zeroed 64-byte view, exposes its address, rebases
``address + offset`` into a 16-byte node, stores 41 at node + 8, reloads it, and
exits with it.  In-range offsets execute; out-of-range and misaligned
addresses trap at run time; the verifier rejects authority gain, extents and
alignments the view cannot supply, dead views, and initialization claims a
windowed pointer cannot prove.
"""

from __future__ import annotations

import platform
import signal
import sys
import unittest

from xax_compiler import (
    Operation,
    Permission,
    XaxError,
    bits_type,
    heap_view_type,
    memory_effect_type,
    pointer_type,
    stack_owner_type,
    verify_store,
    x86_64_linux_exec_target,
)
from xax_graph_builder import GraphBuilder, program_store
from xax_linux import compile_linux_executable, linux_api, run_linux_executable

LINUX_X86_64 = sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")
B16, B32, B64 = bits_type(16), bits_type(32), bits_type(64)
WORDS = pointer_type(B64, Permission.READ_WRITE, 8, space=2)
VIEW_BYTES = 64


def heap_program(offset: int = 0, *, node_bytes: int = 16, node_type=WORDS, view_type=WORDS, address_type=B64, unmap_first: bool = False):
    api = linux_api()
    mem = api.memory_effect
    graph = GraphBuilder()
    graph.track(*api.types, WORDS, view_type, node_type, address_type)
    block = graph.block(api.process_effect, api.filesystem_effect, mem)
    process, fs, memory = block.params
    raw, owner, memory = block.op(Operation.CALL_FOREIGN, (block.const(B64, VIEW_BYTES), memory), (api.bytes_rw, api.heap_owner, mem), entity=api.mmap_anonymous)
    view, token, memory = block.op(Operation.HEAP_VIEW, (raw, owner, memory), (view_type, heap_view_type(VIEW_BYTES), mem), attributes=(VIEW_BYTES, 8))
    address = block.op1(Operation.POINTER_ADDRESS, (view,), B64, attributes=(1,))
    if address_type != B64:
        address = block.op1(Operation.INT_TRUNCATE, (address,), address_type)
    target = address if address_type != B64 else block.op1(Operation.ADD_WRAP, (address, block.const(B64, offset)), B64)
    if unmap_first:
        _r, memory = block.op(Operation.CALL_FOREIGN, (view, token, memory), (B64, mem), entity=api.munmap_view(view_type, VIEW_BYTES))
    node = block.op1(Operation.POINTER_REBASE, (view, target), node_type, attributes=(node_bytes,))
    field = block.op1(Operation.ADDRESS_OFFSET, (node,), node_type, attributes=(8,))
    memory = block.op1(Operation.STORE_BITS_LE, (field, block.const(B64, 41), memory), mem, attributes=(8, 8))
    value, memory = block.op(Operation.LOAD_BITS_LE, (field, memory), (B64, mem), attributes=(8, 8))
    if not unmap_first:
        _r, memory = block.op(Operation.CALL_FOREIGN, (view, token, memory), (B64, mem), entity=api.munmap_view(view_type, VIEW_BYTES))
    status = block.op1(Operation.INT_TRUNCATE, (value,), B32)
    process = block.op1(Operation.CALL_FOREIGN, (status, process), api.process_effect, entity=api.exit_group)
    block.ret(status, process, fs, memory)
    function = graph.function((api.process_effect, api.filesystem_effect, mem), (B32, api.process_effect, api.filesystem_effect, mem))
    return function, x86_64_linux_exec_target(), tuple(graph.objects.values())


def stack_program(*, store_through_node: bool):
    """Uninitialized stack storage: a windowed load or store cannot prove initialization."""
    pointer = pointer_type(B64, Permission.READ_WRITE, 8, space=1)
    mem = memory_effect_type()
    graph = GraphBuilder()
    graph.track(pointer, stack_owner_type(), mem)
    block = graph.block(mem)
    (memory,) = block.params
    view, owner, memory = block.op(Operation.STACK_ALLOC, (), (pointer, stack_owner_type(), mem), attributes=(VIEW_BYTES, 8))
    address = block.op1(Operation.POINTER_ADDRESS, (view,), B64, attributes=(1,))
    node = block.op1(Operation.POINTER_REBASE, (view, address), pointer, attributes=(16,))
    if store_through_node:
        memory = block.op1(Operation.STORE_BITS_LE, (node, block.const(B64, 1), memory), mem, attributes=(8, 8))
    value, memory = block.op(Operation.LOAD_BITS_LE, (node, memory), (B64, mem), attributes=(8, 8))
    memory = block.op1(Operation.STACK_END, (owner, memory), mem)
    block.ret(value, memory)
    function = graph.function((mem,), (B64, mem))
    return function, x86_64_linux_exec_target(), tuple(graph.objects.values())


class PointerRebaseVerifierTests(unittest.TestCase):
    def assertRule(self, program, rule: str) -> None:
        with self.assertRaises(XaxError) as raised:
            program_store(*program)  # verifies the store
        self.assertEqual(raised.exception.diagnostic.rule, rule)

    def test_in_range_program_verifies(self):
        verify_store(program_store(*heap_program(48)))

    def test_rejections(self):
        cases = {
            "MEMORY-REBASE-EXTENT": dict(node_bytes=VIEW_BYTES + 8),
            "MEMORY-REBASE-ALIGNMENT": dict(node_type=pointer_type(B64, Permission.READ_WRITE, 16, space=2)),
            "MEMORY-REBASE-NO-AUTHORITY-GAIN": dict(view_type=pointer_type(B64, Permission.READ, 8, space=2)),
            "MEMORY-REBASE-ADDRESS-WIDTH": dict(address_type=B16),
            "MEMORY-LIFETIME-LIVE": dict(unmap_first=True),
        }
        for rule, options in cases.items():
            with self.subTest(rule=rule):
                self.assertRule(heap_program(**options), rule)

    def test_windowed_access_cannot_prove_initialization(self):
        for store_through_node in (False, True):
            with self.subTest(store_through_node=store_through_node):
                self.assertRule(stack_program(store_through_node=store_through_node), "MEMORY-INITIALIZED")


@unittest.skipUnless(LINUX_X86_64, "requires a Linux x86-64 host")
class PointerRebaseExecutionTests(unittest.TestCase):
    def run_offset(self, offset: int):
        function, target, objects = heap_program(offset)
        return run_linux_executable(compile_linux_executable(program_store(function, target, objects), function.cid, target.cid).data)

    def test_valid_offsets_execute(self):
        for offset in (0, 8, 48):
            with self.subTest(offset=offset):
                completed = self.run_offset(offset)
                self.assertEqual(completed.returncode, 41, completed.stderr)

    def test_forged_and_misaligned_addresses_trap(self):
        for offset in (56, 64, 4, (1 << 64) - 8, 1 << 40):
            with self.subTest(offset=offset):
                self.assertEqual(self.run_offset(offset).returncode, -signal.SIGILL)


if __name__ == "__main__":
    unittest.main()
