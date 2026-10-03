"""Small-set membership branches become one bit test on the Linux x86-64 register allocator."""

from __future__ import annotations

import platform
import sys
import unittest

from xax_compiler import IntCompare, Operation, x86_64_linux_exec_target
from xax_graph_builder import program_store
from xax_structured import B32, Proc

LINUX_X86_64 = sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")
BT = b"\x0f\xa3"


def _program(members: tuple[int, ...]):
    """Exit status: the sum, modulo 256, of every x in [0, 300) that is in ``members``."""
    from xax_linux import linux_api

    api = linux_api()
    proc = Proc((("process", api.process_effect), ("fs", api.filesystem_effect), ("m", api.memory_effect)))
    proc.let("x", B32, proc.const(0))
    proc.let("total", B32, proc.const(0))

    def step(p: Proc):
        hit = p.any_of(*(p.cmp(IntCompare.EQ, p["x"], value) for value in members))
        p.if_(hit, lambda q: q.__setitem__("total", q.bin(Operation.ADD_WRAP, q["total"], q["x"])))
        p["x"] = p.bin(Operation.ADD_WRAP, p["x"], 1)

    proc.while_(lambda p: p.cmp(IntCompare.ULT, p["x"], 300), step)
    status = proc.bin(Operation.BIT_AND, proc["total"], 0xFF)
    process = proc.op1(Operation.CALL_FOREIGN, (status, proc["process"]), api.process_effect, entity=api.exit_group)
    proc.ret(status, process, proc["fs"], proc["m"])
    entry = proc.function((B32, api.process_effect, api.filesystem_effect, api.memory_effect))
    target = x86_64_linux_exec_target()
    return program_store(entry, target, (*api.types, *proc.graph.objects.values())), entry, target


@unittest.skipUnless(LINUX_X86_64, "requires a Linux x86-64 host")
class MemberBitTestTests(unittest.TestCase):
    def _run(self, members):
        from xax_linux import compile_linux_executable, run_linux_executable

        reader, entry, target = _program(members)
        executable = compile_linux_executable(reader, entry.cid, target.cid)
        completed = run_linux_executable(executable.data)
        self.assertEqual(completed.returncode, sum(set(members)) & 0xFF, members)
        return executable.data

    def test_fused_sets_execute_exactly(self):
        for members in ((0x20, 0x09, 0x0A, 0x0D), (0, 1, 62), (200, 230, 262, 210), (5, 5, 6)):
            self.assertIn(BT, self._run(members), members)

    def test_wide_or_small_sets_keep_compares(self):
        for members in ((0x22, 0x5C, 0x74), (1, 64), (7, 70, 133)):
            self.assertNotIn(BT, self._run(members), members)


if __name__ == "__main__":
    unittest.main()
