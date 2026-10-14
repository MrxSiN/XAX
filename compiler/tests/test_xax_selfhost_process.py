"""S11 (ADR-267): Linux process entries in the x86-64 views profile, lowered by the XAX backend program.

``x86_64-linux-views-exec-v1`` makes the entry function the process entry: no machine parameters, a frame aligned
for an entry RSP that points at ``argc``, ``argc``/``arg_copy`` startup reads, ``ud2`` for a return, and a static
ELF64 container (``views_executable``).  The XAX backend must produce the bootstrap generator's bytes and decide
every rejection with its exact diagnostic; the executables run as real processes.
"""

from __future__ import annotations

import os
import platform
import subprocess
import sys
import tempfile
import unittest

from xax_compiler import (
    LINUX_X86_64_STARTUP_ABI,
    Operation,
    XaxError,
    foreign_function_symbol,
    heap_view_type,
    x86_64_linux_exec_target,
    x86_64_views_exec_target,
    x86_64_views_syscall_target,
)
from xax_graph_builder import GraphBuilder, program_store
from xax_linux import _LIBRARY, linux_api, linux_startup_api
from xax_x86_64_views import compile_x86_64_views, views_executable

LINUX_X86_64 = sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")
API = linux_api()
STARTUP = linux_startup_api(API)
B32, B64, FS, MEM, PROCESS = API.b32, API.b64, API.filesystem_effect, API.memory_effect, API.process_effect
EXTENT = 64


def echo_program(*, parameter: bool = False, read_in_callee: bool = False, startup_read=STARTUP.argc):
    """``main``: ``argc``, ``arg_copy(1)`` into an owned 64-byte view, ``write`` it to stdout, ``exit_group(argc + n)``.

    ``parameter`` gives the entry a machine parameter; ``read_in_callee`` moves the ``argc`` read into a callee;
    ``startup_read`` is the declaration read as ``argc``."""
    view = heap_view_type(EXTENT)
    objects = []
    if read_in_callee:
        callee_graph = GraphBuilder()
        callee_block = callee_graph.block(B64)
        callee_block.ret(callee_block.op1(Operation.CALL_FOREIGN, (), B64, entity=startup_read))
        callee = callee_graph.function((B64,), (B64,))
        objects += callee_graph.objects.values()
    graph = GraphBuilder()
    inputs = (FS, MEM, PROCESS, *((B64,) if parameter else ()))
    block = graph.block(*inputs)
    fs, memory, process = block.params[:3]
    argc = (block.op1(Operation.CALL_DIRECT, (block.const(B64, 0),), B64, entity=callee) if read_in_callee
            else block.op1(Operation.CALL_FOREIGN, (), B64, entity=startup_read))
    raw, owner, memory = block.op(Operation.CALL_FOREIGN, (block.const(B64, 4096), memory), (API.bytes_rw, API.heap_owner, MEM), entity=API.mmap_anonymous)
    pointer, token, memory = block.op(Operation.HEAP_VIEW, (raw, owner, memory), (API.bytes_rw, view, MEM), attributes=(EXTENT, 4096))
    count, memory = block.op(Operation.CALL_FOREIGN, (block.const(B64, 1), pointer, memory), (B64, MEM), entity=STARTUP.arg_copy)
    narrowed = block.op1(Operation.POINTER_CAST, (pointer,), API.bytes_read)
    _written, fs, memory = block.op(Operation.CALL_FOREIGN, (block.const(B32, 1), narrowed, count, fs, memory), (B64, FS, MEM), entity=API.write)
    _status, memory = block.op(Operation.CALL_FOREIGN, (pointer, token, memory), (B64, MEM), entity=API.munmap_view(API.bytes_rw, EXTENT))
    total = block.op1(Operation.INT_TRUNCATE, (block.op1(Operation.ADD_WRAP, (argc, count), B64),), B32)
    process = block.op1(Operation.CALL_FOREIGN, (total, process), PROCESS, entity=API.exit_group)
    block.ret(fs, memory, process)
    entry = graph.function(inputs, (FS, MEM, PROCESS))
    reader = program_store(entry, x86_64_linux_exec_target(), (*graph.objects.values(), *objects, *API.types, *STARTUP.symbols, startup_read))
    return reader, entry


@unittest.skipUnless(LINUX_X86_64, "UNAVAILABLE: the XAX backend program and the executables run on Linux x86-64 only")
class ProcessEntryTests(unittest.TestCase):
    def assertSameOutcome(self, reader, entry, target=None):
        """Both generators agree: the same image, or the same exact rejection diagnostic."""
        target = target or x86_64_views_exec_target()
        outcomes = []
        for backend in ("python", "xax"):
            try:
                outcomes.append(compile_x86_64_views(reader, entry.cid, target, backend=backend))
            except XaxError as error:
                outcomes.append(error.diagnostic)
        self.assertEqual(outcomes[0], outcomes[1])
        return outcomes[0]

    def test_an_echo_process(self):
        image = self.assertSameOutcome(*echo_program())
        self.assertEqual(type(image).__name__, "X86ViewsImage", image)
        path = os.path.join(tempfile.mkdtemp(), "echo")
        with open(path, "wb") as handle:
            handle.write(views_executable(image))
        os.chmod(path, 0o755)
        long = "a" * 100
        for arguments, status, output in ((["hello"], 7, b"hello"), ([""], 2, b""), (["hi", "x"], 5, b"hi"), ([long], 66, long[:EXTENT].encode())):
            with self.subTest(arguments=arguments):
                result = subprocess.run([path, *arguments], capture_output=True, check=False)
                self.assertEqual((result.returncode, result.stdout), (status, output))
        self.assertEqual(subprocess.run([path], capture_output=True, check=False).returncode, -4)  # argv[1] missing: ud2, SIGILL

    def test_the_container(self):
        reader, entry = echo_program()
        image = compile_x86_64_views(reader, entry.cid, x86_64_views_exec_target())
        data = views_executable(image)
        self.assertEqual(data[:4], b"\x7fELF")
        self.assertEqual(int.from_bytes(data[24:32], "little"), 0x400000 + 176)  # e_entry: the entry function
        self.assertEqual(data[176:], image.code)  # the container adds no code

    def test_rejections_are_the_bootstraps(self):
        envc = foreign_function_symbol(_LIBRARY, b"envc", (), (B64,), abi=LINUX_X86_64_STARTUP_ABI)
        cases = (
            (echo_program(), x86_64_views_syscall_target(), "X86_64_VIEWS-STARTUP"),  # not a process entry
            (echo_program(parameter=True), None, "X86_64_VIEWS-PROCESS-ENTRY"),
            (echo_program(read_in_callee=True), None, "X86_64_VIEWS-STARTUP"),
            (echo_program(startup_read=envc), None, "X86_64_VIEWS-SYSCALL"),  # a read the views profile does not lower
        )
        for (reader, entry), target, rule in cases:
            with self.subTest(rule=rule):
                diagnostic = self.assertSameOutcome(reader, entry, target)
                self.assertEqual(type(diagnostic).__name__, "Diagnostic", diagnostic)
                self.assertEqual(diagnostic.rule, rule)


if __name__ == "__main__":
    unittest.main()
