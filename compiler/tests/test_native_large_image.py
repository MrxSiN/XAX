"""Ledger 0018 (ADR-381): the native general backend assembles an image larger than 32 MiB.

Before ledger 0018 the general program kept the image one byte per workspace word in a 32M-word buffer
(``IMAGE_CAP`` = 2^25 bytes) and declined any larger image.  It now packs the buffer eight bytes to a word and
assembles up to 48 MiB.  The program here has about 36 MiB of code: 1,700 functions, each a chain of 1,000
multiply/xor steps over a 64-bit value (constants from a 16-entry pool; the first step xors in the function's index, so every
function is a distinct object, and none is small enough to inline), called in sequence by the process entry, which exits with the
result's low byte.  It is built with ``frontend="xax"`` (the native program must assemble it, no fallback), the code
must exceed 32 MiB, and the executable must exit with the status computed here.  Slow: about 25 minutes.
"""

from __future__ import annotations

import platform
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_xax_linux import _exit_entry  # noqa: E402
from xax_compiler import Operation, bits_type, x86_64_linux_exec_target  # noqa: E402
from xax_graph_builder import GraphBuilder, program_store  # noqa: E402
from xax_linux import ASSEMBLY_COUNTS, compile_linux_executable, linux_api, run_linux_executable  # noqa: E402

LINUX_X86_64 = sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")
B64 = bits_type(64)
MASK = (1 << 64) - 1
POOL = [(0x9E3779B97F4A7C15 * (k + 1) | 1) & MASK for k in range(16)]
FLIP = 0xFFFF0000FFFF0000
FUNCTIONS, STEPS = 1700, 1000


def _factors(index: int, step: int) -> tuple[int, int]:
    """The step's multiplier and mask; step 0 xors the function's own index in, so no two functions are equal."""
    return POOL[(step + index) % 16], POOL[(3 * step + 7 * index + 5) % 16] ^ (FLIP if step else index)


def _chain(index: int) -> tuple[GraphBuilder, object]:
    graph = GraphBuilder()
    block = graph.block(B64)
    x = block.params[0]
    for step in range(STEPS):
        multiplier, mask = _factors(index, step)
        x = block.op1(Operation.MUL_WRAP, (x, block.const(B64, multiplier)), B64)
        x = block.op1(Operation.BIT_XOR, (x, block.const(B64, mask)), B64)
    block.ret(x)
    return graph, graph.function((B64,), (B64,))


def large_program():
    api = linux_api()
    graphs, functions = zip(*(_chain(index) for index in range(FUNCTIONS)))
    graph = GraphBuilder()
    block = graph.block(api.process_effect, api.filesystem_effect)
    x = block.const(B64, 7)
    for function in functions:
        x = block.op1(Operation.CALL_DIRECT, (x,), B64, entity=function)
    low = block.op1(Operation.BIT_AND, (x, block.const(B64, 0xFF)), B64)
    status = block.op1(Operation.INT_TRUNCATE, (low,), bits_type(32))
    entry = _exit_entry(api, graph, block, status)
    target = x86_64_linux_exec_target()
    objects = [obj for chain in graphs for obj in chain.objects.values()]
    return program_store(entry, target, (*objects, *graph.objects.values(), *api.types)), entry, target


def expected_status() -> int:
    x = 7
    for index in range(FUNCTIONS):
        for step in range(STEPS):
            multiplier, mask = _factors(index, step)
            x = ((x * multiplier) & MASK) ^ mask
    return x & 0xFF


class LargeImageTests(unittest.TestCase):
    @unittest.skipUnless(LINUX_X86_64, "requires a Linux x86-64 host")
    def test_an_image_larger_than_32_mib_is_assembled_natively(self):
        reader, entry, target = large_program()
        ASSEMBLY_COUNTS.clear()
        executable = compile_linux_executable(reader, entry.cid, target.cid, frontend="xax")
        self.assertEqual(ASSEMBLY_COUNTS, {"xax": 1})  # the XAX program assembled the image and wrote the ELF
        self.assertGreater(len(executable.image.code), 1 << 25)
        completed = run_linux_executable(executable.data)
        self.assertEqual(completed.returncode, expected_status())


if __name__ == "__main__":
    unittest.main()
