"""Linux process startup reads (``linux-x86_64-startup-v1``, ADR-094).

An ``echo``-style process copies each argument (or environment entry) into a
zero-filled heap view and writes it with a newline; the exit status reports
``argc``/``envc``/an ``auxv`` value.  Out-of-range indexes trap, and startup
reads outside the process entry function are rejected.
"""

from __future__ import annotations

import platform
import signal
import sys
import unittest
from pathlib import Path

from xax_compiler import IntCompare, Operation, XaxError, heap_view_type, x86_64_linux_exec_target
from xax_graph_builder import GraphBuilder, program_store
from xax_linux import compile_linux_executable, linux_api, linux_startup_api, run_linux_executable

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from benchmarks.linux_graph_kit import Flow, Kit  # noqa: E402

LINUX_X86_64 = sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")
BUFFER = 4096
AT_PAGESZ = 6


def lines_program(source: str = "arg", first: int = 1, status: str = "count", extra_index: int | None = None):
    """Write items ``first..count-1`` of argv/envp, one per line; exit with ``status``.

    ``status`` is ``"count"`` (argc or envc), ``"length"`` (item 1's full length), or ``"pagesize"`` (auxv AT_PAGESZ >> 8,
    plus auxv of an absent type, which must be 0).  ``extra_index`` reads one
    item past the loop to exercise the out-of-range trap.
    """
    api, startup, kit = linux_api(), linux_startup_api(), Kit()
    b32, b64, mem = kit.b32, kit.b64, api.memory_effect
    count_symbol, length_symbol, copy_symbol = (startup.argc, startup.arg_length, startup.arg_copy) if source == "arg" else (startup.envc, startup.env_length, startup.env_copy)
    graph = GraphBuilder()
    graph.track(*api.types, kit.b1)
    flow = Flow(graph, ("proc", "fs", "token", "mem"), {"proc": api.process_effect, "fs": api.filesystem_effect, "token": heap_view_type(BUFFER), "mem": mem})
    entry = graph.block(api.process_effect, api.filesystem_effect, mem)
    process, fs, memory = entry.params
    raw, owner, memory = entry.op(Operation.CALL_FOREIGN, (kit.const(entry, BUFFER), memory), (api.bytes_rw, api.heap_owner, mem), entity=api.mmap_anonymous)
    view, token, memory = entry.op(Operation.HEAP_VIEW, (raw, owner, memory), (api.bytes_rw, heap_view_type(BUFFER), mem), attributes=(BUFFER, 1))
    count = entry.op1(Operation.CALL_FOREIGN, (), b64, entity=count_symbol)
    loop, loop_state = flow.block(("i", b64))
    body, body_state = flow.block(("i", b64))
    finish, finish_state = flow.block()
    entry.br(loop, *flow.args(loop, {"proc": process, "fs": fs, "token": token, "mem": memory, "i": kit.const(entry, first)}))
    loop.cbr(kit.compare(loop, IntCompare.ULT, loop_state["i"], count), body, flow.args(body, loop_state), finish, flow.args(finish, loop_state))
    b, s = body, body_state
    copied, memory = b.op(Operation.CALL_FOREIGN, (s["i"], view, s["mem"]), (b64, mem), entity=copy_symbol)
    text = b.op1(Operation.POINTER_CAST, (view,), api.bytes_read)
    _w, fs, memory = b.op(Operation.CALL_FOREIGN, (kit.const(b, 1, b32), text, copied, s["fs"], memory), (b64, api.filesystem_effect, mem), entity=api.write)
    memory = b.op1(Operation.STORE_BITS_LE, (view, kit.const(b, 10, kit.b8), memory), mem, attributes=(1, 1))
    _w, fs, memory = b.op(Operation.CALL_FOREIGN, (kit.const(b, 1, b32), text, kit.const(b, 1), fs, memory), (b64, api.filesystem_effect, mem), entity=api.write)
    b.br(loop, *flow.args(loop, {**s, "fs": fs, "mem": memory, "i": kit.binary(b, Operation.ADD_WRAP, s["i"], kit.const(b, 1))}))
    f, fstate = finish, finish_state
    if status == "pagesize":
        page = f.op1(Operation.CALL_FOREIGN, (kit.const(f, AT_PAGESZ),), b64, entity=startup.auxv_value)
        absent = f.op1(Operation.CALL_FOREIGN, (kit.const(f, 1000),), b64, entity=startup.auxv_value)
        value = kit.binary(f, Operation.ADD_WRAP, kit.binary(f, Operation.UDIV, page, kit.const(f, 256)), absent)
    elif status == "length":
        value = f.op1(Operation.CALL_FOREIGN, (kit.const(f, 1),), b64, entity=length_symbol)
    else:
        value = f.op1(Operation.CALL_FOREIGN, (), b64, entity=count_symbol)
    if extra_index is not None:
        value = kit.binary(f, Operation.ADD_WRAP, value, f.op1(Operation.CALL_FOREIGN, (kit.const(f, extra_index),), b64, entity=length_symbol))
    _r, memory = f.op(Operation.CALL_FOREIGN, (view, fstate["token"], fstate["mem"]), (b64, mem), entity=api.munmap_view(api.bytes_rw, BUFFER))
    status_value = f.op1(Operation.INT_TRUNCATE, (value,), b32)
    process = f.op1(Operation.CALL_FOREIGN, (status_value, fstate["proc"]), api.process_effect, entity=api.exit_group)
    f.ret(status_value, process, fstate["fs"], memory)
    function = graph.function((api.process_effect, api.filesystem_effect, mem), (b32, api.process_effect, api.filesystem_effect, mem))
    target = x86_64_linux_exec_target()
    reader = program_store(function, target, (*graph.objects.values(), *startup.symbols))
    return compile_linux_executable(reader, function.cid, target.cid)


@unittest.skipUnless(LINUX_X86_64, "requires a Linux x86-64 host")
class LinuxStartupTests(unittest.TestCase):
    def test_arguments_echo_and_argc(self):
        arguments = ("alpha", "", "two words", "x" * 5000)  # the last is clamped to the 4096-byte view
        completed = run_linux_executable(lines_program().data, arguments=arguments)
        self.assertEqual(completed.returncode, len(arguments) + 1)
        self.assertEqual(completed.stdout, b"".join(item.encode()[:BUFFER] + b"\n" for item in arguments))

    def test_length_reports_untruncated_size(self):
        completed = run_linux_executable(lines_program(status="length").data, arguments=("y" * 300,))
        self.assertEqual(completed.returncode, 300 % 256)
        self.assertEqual(completed.stdout, b"y" * 300 + b"\n")

    def test_environment_lines_and_envc(self):
        environment = {"XAX_A": "1", "XAX_LONGER": "twenty-two"}
        completed = run_linux_executable(lines_program("env", first=0).data, env=environment)
        self.assertEqual(completed.returncode, len(environment))
        self.assertEqual(sorted(completed.stdout.decode().splitlines()), sorted(f"{key}={value}" for key, value in environment.items()))

    def test_auxv_page_size_and_absent_type(self):
        completed = run_linux_executable(lines_program(status="pagesize").data)
        self.assertEqual(completed.returncode, 4096 // 256)

    def test_out_of_range_indexes_trap(self):
        for source, index in (("arg", 3), ("env", 1)):
            with self.subTest(source=source):
                program = lines_program(source, extra_index=index)
                completed = run_linux_executable(program.data, arguments=("a",), env={"ONLY": "1"})
                self.assertEqual(completed.returncode, -signal.SIGILL)

    def test_startup_reads_belong_to_the_process_entry(self):
        api, startup, kit = linux_api(), linux_startup_api(), Kit()
        helper_graph = GraphBuilder()
        block = helper_graph.block()
        block.ret(block.op1(Operation.CALL_FOREIGN, (), kit.b64, entity=startup.argc))
        helper = helper_graph.function((), (kit.b64,))
        graph = GraphBuilder()
        graph.track(*api.types)
        entry = graph.block(api.process_effect)
        (process,) = entry.params
        status = entry.op1(Operation.INT_TRUNCATE, (entry.op1(Operation.CALL_DIRECT, (), kit.b64, entity=helper),), kit.b32)
        process = entry.op1(Operation.CALL_FOREIGN, (status, process), api.process_effect, entity=api.exit_group)
        entry.ret(status, process)
        function = graph.function((api.process_effect,), (kit.b32, api.process_effect))
        target = x86_64_linux_exec_target()
        reader = program_store(function, target, (*graph.objects.values(), *helper_graph.objects.values(), helper, *startup.symbols))
        with self.assertRaises(XaxError) as raised:
            compile_linux_executable(reader, function.cid, target.cid)
        self.assertEqual(raised.exception.diagnostic.rule, "LINUX-STARTUP-PROCESS-ENTRY")


if __name__ == "__main__":
    unittest.main()
