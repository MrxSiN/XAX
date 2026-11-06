"""ADR-376 (ledger 0013): a compare that drives its block's branch and is read again in a later block.

The callee computes ``c = x < y``, branches on it, and in the join block returns ``10 * zext(c) + marker``.  Before
ledger 0013 the x86-64 general backend fused the compare into the branch without materializing it, so the join block
read a stale register (x < y returned 1, not 11).  The AArch64 backend lowers it correctly too.
"""

from __future__ import annotations

import platform
import unittest

from xax_compiler import IntCompare, Operation, aarch64_linux_exec_target, bits_type, x86_64_linux_exec_target
from xax_graph_builder import GraphBuilder, program_store

B1, B32 = bits_type(1), bits_type(32)
CASES = ((1, 2, 11), (3, 2, 2))


def program(api, a, b):
    graph = GraphBuilder()
    graph.track(*api.types, B1, B32)
    callee = graph.block(B32, B32)
    x, y = callee.params
    flag = callee.op1(Operation.INT_COMPARE, (x, y), B1, attributes=(int(IntCompare.ULT),))
    true, false, join = graph.block(), graph.block(), graph.block(B32)
    callee.cbr(flag, true, (), false, ())
    true.br(join, true.const(B32, 1))
    false.br(join, false.const(B32, 2))
    widened = join.op1(Operation.INT_ZERO_EXTEND, (flag,), B32)
    tens = join.op1(Operation.MUL_WRAP, (widened, join.const(B32, 10)), B32)
    join.ret(join.op1(Operation.ADD_WRAP, (tens, join.params[0]), B32))
    function = graph.function((B32, B32), (B32,))
    objects = tuple(graph.objects.values())
    graph = GraphBuilder()
    block = graph.block(api.process_effect, api.filesystem_effect)
    process, fs = block.params
    value = block.op1(Operation.CALL_DIRECT, (block.const(B32, a), block.const(B32, b)), B32, entity=function)
    process = block.op1(Operation.CALL_FOREIGN, (value, process), api.process_effect, entity=api.exit_group)
    block.ret(value, process, fs)
    entry = graph.function((api.process_effect, api.filesystem_effect), (B32, api.process_effect, api.filesystem_effect))
    return entry, (*objects, *graph.objects.values(), *api.types)


class BranchFusionTests(unittest.TestCase):
    @unittest.skipUnless(platform.system() == "Linux" and platform.machine() in ("x86_64", "AMD64"), "requires Linux x86-64")
    def test_x86_64(self):
        from xax_linux import compile_linux_executable, linux_api, run_linux_executable

        target = x86_64_linux_exec_target()
        for a, b, expected in CASES:
            with self.subTest(a=a, b=b):
                entry, objects = program(linux_api(), a, b)
                data = compile_linux_executable(program_store(entry, target, objects), entry.cid, target.cid, frontend="xax").data
                self.assertEqual(run_linux_executable(data).returncode, expected)

    def test_aarch64(self):
        from xax_linux_aarch64 import aarch64_runner, compile_linux_aarch64_executable, linux_aarch64_api, run_linux_aarch64_executable

        if aarch64_runner() is None:
            self.skipTest("requires an AArch64 Linux host or qemu-aarch64")
        target = aarch64_linux_exec_target()
        for a, b, expected in CASES:
            with self.subTest(a=a, b=b):
                entry, objects = program(linux_aarch64_api(), a, b)
                data = compile_linux_aarch64_executable(program_store(entry, target, objects), entry.cid, target.cid, frontend="xax").data
                self.assertEqual(run_linux_aarch64_executable(data).returncode, expected)


if __name__ == "__main__":
    unittest.main()
