"""Record links on Windows PE (ADR-097), executed under Wine.

The entry builds three records ``(key: bits<32>, pad: bits<32>, next: link)``
in stack storage, links them, walks the list with ``link_follow`` (lowered by
the converged allocator, ADR-095), and calls ``ExitProcess(5 + 7 + 30)``.
Wine reimplements the Windows API on Linux; it is not Windows.
"""

from __future__ import annotations

import tempfile
import unittest

from benchmarks.bench_windows_pe_wine import run_under_wine, wine_executable
from xax_compiler import IntCompare, Operation, Permission, bits_type, link_type, null_link, pointer_type, stack_owner_type, tuple_type, x86_64_windows_pe_target
from xax_graph_builder import GraphBuilder, program_store
from xax_pe import emit_pe_executable
from xax_platform import win32_kernel32_api
from xax_x86_64 import compile_native_bound_target

KEYS = (5, 7, 30)
B1, B32 = bits_type(1), bits_type(32)
LINK = link_type()
RECORD = tuple_type((B32, B32, LINK))
RECORDS = pointer_type(RECORD, Permission.READ_WRITE, 16)
KEY = pointer_type(B32, Permission.READ_WRITE, 4)
NEXT = pointer_type(LINK, Permission.READ_WRITE, 8)


def linked_list_pe() -> bytes:
    api = win32_kernel32_api()
    mem, owner = api.memory_effect, stack_owner_type()
    graph = GraphBuilder()
    graph.track(api.b32, api.process_effect, mem, owner, B1, LINK, RECORD, RECORDS, KEY, NEXT)
    entry = graph.block(api.process_effect)
    (process,) = entry.params
    view, token, memory = entry.op(Operation.STACK_ALLOC, (), (RECORDS, owner, mem), attributes=(16 * len(KEYS), 16))
    records = [view if index == 0 else entry.op1(Operation.ADDRESS_OFFSET, (view,), RECORDS, attributes=(16 * index,)) for index in range(len(KEYS))]
    null = entry.op1(Operation.CONSTANT, (), LINK, entity=null_link())
    for index, (record, key) in enumerate(zip(records, KEYS)):
        following = entry.op1(Operation.LINK_MAKE, (records[index + 1],), LINK) if index + 1 < len(KEYS) else null
        for offset, value in ((0, key), (4, 0)):
            memory = entry.op1(Operation.STORE_BITS_LE, (entry.op1(Operation.ADDRESS_OFFSET, (record,), KEY, attributes=(offset,)), entry.const(B32, value), memory), mem, attributes=(4, 4))
        memory = entry.op1(Operation.STORE_BITS_LE, (entry.op1(Operation.ADDRESS_OFFSET, (record,), NEXT, attributes=(8,)), following, memory), mem, attributes=(8, 8))
    walk = graph.block(api.process_effect, LINK, B32, owner, mem)
    step = graph.block(api.process_effect, LINK, B32, owner, mem)
    done = graph.block(api.process_effect, B32, owner, mem)
    entry.br(walk, process, entry.op1(Operation.LINK_MAKE, (view,), LINK), entry.const(B32, 0), token, memory)
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
    process = done.op1(Operation.CALL_FOREIGN, (total, process), api.process_effect, entity=api.exit_process)
    done.ret(total, process)
    function = graph.function((api.process_effect,), (B32, api.process_effect))
    target = x86_64_windows_pe_target()
    reader = program_store(function, target, (*graph.objects.values(), api.exit_process))
    return emit_pe_executable(compile_native_bound_target(reader, function.cid, target))


class PeLinkTests(unittest.TestCase):
    def test_linked_records_walk_under_wine(self):
        pe = linked_list_pe()
        wine = wine_executable()
        if wine is None:
            self.skipTest("wine64 is not installed")
        with tempfile.TemporaryDirectory() as prefix:
            self.assertEqual(run_under_wine(pe, wine, prefix).returncode, sum(KEYS))


if __name__ == "__main__":
    unittest.main()
