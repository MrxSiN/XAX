"""Record links on wasm32 (ADR-097): 8-byte link fields holding 32-bit addresses.

A WASI command builds three records ``(key: bits<32>, pad: bits<32>, next:
link)`` in stack storage.  The padding is an explicit field: stack storage is
not zero-filled, and loads through a followed record need every record byte
initialized.  It links them, and walks the list with ``link_follow``, exiting with 5 + 7 + 30 = 42.
Following a null link traps.
"""

from __future__ import annotations

import shutil
import unittest

from xax_compiler import IntCompare, Operation, Permission, bits_type, link_type, null_link, pointer_type, stack_owner_type, tuple_type, wasm32_wasi_target
from xax_graph_builder import GraphBuilder, program_store
from xax_platform import wasi_preview1_api
from xax_wasm import compile_wasm_bound_target, run_wasi_isolated

KEYS = (5, 7, 30)
B1, B32, B64 = bits_type(1), bits_type(32), bits_type(64)
LINK = link_type()
RECORD = tuple_type((B32, B32, LINK))
RECORDS = pointer_type(RECORD, Permission.READ_WRITE, 16)
KEY = pointer_type(B32, Permission.READ_WRITE, 4)
NEXT = pointer_type(LINK, Permission.READ_WRITE, 8)


def program(*, null_follow: bool = False):
    api = wasi_preview1_api()
    mem, owner = api.memory_effect, stack_owner_type()
    graph = GraphBuilder()
    graph.track(*api.types, owner, B1, B64, LINK, RECORD, RECORDS, KEY, NEXT)
    entry = graph.block(api.process_effect)
    (process,) = entry.params
    view, token, memory = entry.op(Operation.STACK_ALLOC, (), (RECORDS, owner, mem), attributes=(16 * len(KEYS), 16))
    records = [view if index == 0 else entry.op1(Operation.ADDRESS_OFFSET, (view,), RECORDS, attributes=(16 * index,)) for index in range(len(KEYS))]
    null = entry.op1(Operation.CONSTANT, (), LINK, entity=null_link())
    for index, (record, key) in enumerate(zip(records, KEYS)):
        following = entry.op1(Operation.LINK_MAKE, (records[index + 1],), LINK) if index + 1 < len(KEYS) else null
        memory = entry.op1(Operation.STORE_BITS_LE, (entry.op1(Operation.ADDRESS_OFFSET, (record,), KEY, attributes=(0,)), entry.const(B32, key), memory), mem, attributes=(4, 4))
        memory = entry.op1(Operation.STORE_BITS_LE, (entry.op1(Operation.ADDRESS_OFFSET, (record,), KEY, attributes=(4,)), entry.const(B32, 0), memory), mem, attributes=(4, 4))
        memory = entry.op1(Operation.STORE_BITS_LE, (entry.op1(Operation.ADDRESS_OFFSET, (record,), NEXT, attributes=(8,)), following, memory), mem, attributes=(8, 8))
    first = null if null_follow else entry.op1(Operation.LINK_MAKE, (view,), LINK)
    if null_follow:  # the head is a loaded null link: verified, traps at run time
        first, memory = entry.op(Operation.LOAD_BITS_LE, (entry.op1(Operation.ADDRESS_OFFSET, (records[-1],), NEXT, attributes=(8,)), memory), (LINK, mem), attributes=(8, 8))
        entry.op1(Operation.LINK_FOLLOW, (view, first), RECORDS)
    walk = graph.block(api.process_effect, LINK, B32, owner, mem)
    step = graph.block(api.process_effect, LINK, B32, owner, mem)
    done = graph.block(api.process_effect, B32, owner, mem)
    entry.br(walk, process, first, entry.const(B32, 0), token, memory)
    process, cursor, total, token, memory = walk.params
    test = walk.op1(Operation.INT_COMPARE, (cursor, walk.op1(Operation.CONSTANT, (), LINK, entity=null_link())), B1, attributes=(IntCompare.NE,))
    walk.cbr(test, step, (process, cursor, total, token, memory), done, (process, total, token, memory))
    process, cursor, total, token, memory = step.params
    node = step.op1(Operation.LINK_FOLLOW, (view, cursor), RECORDS)
    key, memory = step.op(Operation.LOAD_BITS_LE, (step.op1(Operation.ADDRESS_OFFSET, (node,), KEY, attributes=(0,)), memory), (B32, mem), attributes=(4, 4))
    following, memory = step.op(Operation.LOAD_BITS_LE, (step.op1(Operation.ADDRESS_OFFSET, (node,), NEXT, attributes=(8,)), memory), (LINK, mem), attributes=(8, 8))
    step.br(walk, process, following, step.op1(Operation.ADD_WRAP, (total, key), B32), token, memory)
    process, total, token, memory = done.params
    done.op(Operation.STACK_END, (token, memory), ())
    done.ret(done.op1(Operation.CALL_FOREIGN, (total, process), api.process_effect, entity=api.proc_exit))
    function = graph.function((api.process_effect,), (api.process_effect,))
    target = wasm32_wasi_target()
    return compile_wasm_bound_target(program_store(function, target, (*graph.objects.values(), *api.symbols)), function.cid, target)


@unittest.skipUnless(shutil.which("node"), "requires Node's node:wasi host")
class WasmLinkTests(unittest.TestCase):
    def test_linked_records_walk(self):
        self.assertEqual(run_wasi_isolated(program())[0], sum(KEYS))

    def test_null_follow_traps(self):
        with self.assertRaisesRegex(RuntimeError, "unreachable"):
            run_wasi_isolated(program(null_follow=True))


if __name__ == "__main__":
    unittest.main()
