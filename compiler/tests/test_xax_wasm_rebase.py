"""``pointer_rebase`` on wasm32 (ADR-092): the 32-bit pointer-width target.

A WASI command builds a three-node linked list in stack storage (8-byte
nodes: ``key: u32, next: u32``, links are exposed addresses, 0 ends), walks it
through ``pointer_rebase`` links summing keys 5 + 7 + 30, and exits with 42.
Corrupting the first link (out of range, misaligned, or wrapped) traps.
"""

from __future__ import annotations

import shutil
import unittest

from xax_compiler import IntCompare, Operation, XaxError, bits_type, stack_owner_type, wasm32_wasi_target
from xax_graph_builder import GraphBuilder, program_store
from xax_platform import wasi_preview1_api
from xax_wasm import compile_wasm_bound_target, run_wasi_isolated

NODE_BYTES, NODES = 8, 3
KEYS = (5, 7, 30)


def linked_list_program(first_link_offset: int = 0, *, expired: bool = False):
    api = wasi_preview1_api()
    b1, b32, words, mem = bits_type(1), api.b32, api.u32_ptr_rw, api.memory_effect
    owner = stack_owner_type()
    graph = GraphBuilder()
    graph.track(*api.types, owner, b1)
    entry = graph.block(api.process_effect)
    (process,) = entry.params
    view, token, memory = entry.op(Operation.STACK_ALLOC, (), (words, owner, mem), attributes=(NODE_BYTES * NODES, 8))
    base = entry.op1(Operation.POINTER_ADDRESS, (view,), b32, attributes=(1,))
    for index, key in enumerate(KEYS):
        node = view if index == 0 else entry.op1(Operation.ADDRESS_OFFSET, (view,), words, attributes=(index * NODE_BYTES,))
        link = entry.op1(Operation.ADDRESS_OFFSET, (node,), words, attributes=(4,))
        following = entry.op1(Operation.ADD_WRAP, (base, entry.const(b32, (index + 1) * NODE_BYTES)), b32) if index + 1 < NODES else entry.const(b32, 0)
        memory = entry.op1(Operation.STORE_BITS_LE, (node, entry.const(b32, key), memory), mem, attributes=(4, 4))
        memory = entry.op1(Operation.STORE_BITS_LE, (link, following, memory), mem, attributes=(4, 4))
    first = entry.op1(Operation.ADD_WRAP, (base, entry.const(b32, first_link_offset)), b32)

    walk = graph.block(api.process_effect, b32, b32, owner, mem)
    step = graph.block(api.process_effect, b32, b32, owner, mem)
    done = graph.block(api.process_effect, b32, owner, mem)
    entry.br(walk, process, first, entry.const(b32, 0), token, memory)
    process, cursor, total, token, memory = walk.params
    walk.cbr(walk.op1(Operation.INT_COMPARE, (cursor, walk.const(b32, 0)), b1, attributes=(IntCompare.NE,)), step, (process, cursor, total, token, memory), done, (process, total, token, memory))
    process, cursor, total, token, memory = step.params
    if expired:  # end the storage, then rebase into it: expired provenance
        step.op(Operation.STACK_END, (token, memory), ())
    node = step.op1(Operation.POINTER_REBASE, (view, cursor), words, attributes=(NODE_BYTES,))
    key, memory = step.op(Operation.LOAD_BITS_LE, (node, memory), (b32, mem), attributes=(4, 4))
    following, memory = step.op(Operation.LOAD_BITS_LE, (step.op1(Operation.ADDRESS_OFFSET, (node,), words, attributes=(4,)), memory), (b32, mem), attributes=(4, 4))
    step.br(walk, process, following, step.op1(Operation.ADD_WRAP, (total, key), b32), token, memory)
    process, total, token, memory = done.params
    done.op(Operation.STACK_END, (token, memory), ())
    process = done.op1(Operation.CALL_FOREIGN, (total, process), api.process_effect, entity=api.proc_exit)
    done.ret(process)
    function = graph.function((api.process_effect,), (api.process_effect,))
    target = wasm32_wasi_target()
    reader = program_store(function, target, (*graph.objects.values(), *api.symbols))
    return compile_wasm_bound_target(reader, function.cid, target)


class WasmPointerRebaseVerifierTests(unittest.TestCase):
    def test_expired_view_rejects(self):
        with self.assertRaises(XaxError) as raised:
            linked_list_program(expired=True)
        self.assertEqual(raised.exception.diagnostic.rule, "MEMORY-LIFETIME-LIVE")


@unittest.skipUnless(shutil.which("node"), "requires Node's node:wasi host")
class WasmPointerRebaseTests(unittest.TestCase):
    def test_linked_list_walk_executes(self):
        self.assertEqual(run_wasi_isolated(linked_list_program())[0], sum(KEYS))

    def test_corrupted_links_trap(self):
        for offset in (NODE_BYTES * NODES, 4, -NODE_BYTES, 1 << 31):
            with self.subTest(offset=offset):
                with self.assertRaisesRegex(RuntimeError, "unreachable"):
                    run_wasi_isolated(linked_list_program(offset & 0xFFFFFFFF))


if __name__ == "__main__":
    unittest.main()
