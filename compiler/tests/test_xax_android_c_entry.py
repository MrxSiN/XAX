"""ADR-107: Android C code calls XAX functions (android-aapcs64-c entries)."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

from xax_compiler import (
    Operation,
    SYSV_X86_64_C_ABI,
    XaxError,
    android_arm64_shared_general_target,
    bits_type,
    foreign_entry_code_type,
    foreign_entry_pointer_type,
    x86_64_linux_dynamic_exec_target,
)
from xax_graph_builder import GraphBuilder, program_store
from xax_android import AndroidExport, compile_android_shared
from xax_platform import android_c_entry_api, posix_android_api

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from benchmarks import android_thread_entry  # noqa: E402

B32, B64 = bits_type(32), bits_type(64)


def _address_of(parameters, results, address_type, target=None, extra_types=()):
    callee_graph = GraphBuilder()
    block = callee_graph.block(*parameters)
    block.ret(*block.params[: len(results)])
    callee = callee_graph.function(parameters, results)
    graph = GraphBuilder()
    entry = graph.block()
    entry.op1(Operation.FUNCTION_ADDRESS, (), address_type, entity=callee)
    entry.ret(entry.const(B64, 0))
    function = graph.function((), (B64,))
    target = target or android_arm64_shared_general_target(packed=True)
    reader = program_store(function, target, (*extra_types, *callee_graph.objects.values(), *graph.objects.values()))
    return reader, function, target


class AndroidCEntryTests(unittest.TestCase):
    def setUp(self):
        self.api = posix_android_api()
        self.entries = android_c_entry_api(self.api)

    def _compile(self, reader, function, target):
        return compile_android_shared(reader, (AndroidExport(b"probe", function.cid),), target_object=target)

    def test_entry_address_is_the_function_itself(self):
        reader, _target, spawn, worker = android_thread_entry.program()
        shared = compile_android_shared(reader, (AndroidExport(b"xax_spawn_fib", spawn.cid),), target_object=android_arm64_shared_general_target(packed=True))
        offsets = dict(shared.function_offsets)
        self.assertIn(worker.cid, offsets)  # compiled once, at its own offset; no adapter function exists
        self.assertEqual(len(offsets), 2)

    def test_narrow_parameter_rejects(self):
        reader, function, target = _address_of((B32,), (B32,), self.entries.c_entry, extra_types=self.entries.types)
        with self.assertRaises(XaxError) as caught:
            self._compile(reader, function, target)
        self.assertEqual(caught.exception.diagnostic.rule, "AARCH64-ENTRY-SIGNATURE")

    def test_effectful_entry_rejects(self):
        with self.assertRaises(XaxError) as caught:
            _address_of((B64, self.api.memory_effect), (B64, self.api.memory_effect), self.entries.c_entry, extra_types=self.entries.types)
        self.assertEqual(caught.exception.diagnostic.rule, "GRAPH-FUNCTION-ADDRESS-FOREIGN-ENTRY")

    def test_sysv_entry_rejects_on_android(self):
        sysv = foreign_entry_pointer_type(SYSV_X86_64_C_ABI)
        reader, function, target = _address_of((B64,), (B64,), sysv, extra_types=(sysv, foreign_entry_code_type(SYSV_X86_64_C_ABI)))
        with self.assertRaises(XaxError) as caught:
            self._compile(reader, function, target)
        self.assertEqual(caught.exception.diagnostic.rule, "AARCH64-FOREIGN-ENTRY-TARGET")

    def test_android_entry_rejects_on_x86_64(self):
        from xax_x86_64 import compile_native_bound_target

        reader, function, _target = _address_of((B64,), (B64,), self.entries.c_entry, target=x86_64_linux_dynamic_exec_target(), extra_types=self.entries.types)
        with self.assertRaises(XaxError) as caught:
            compile_native_bound_target(reader, function.cid, x86_64_linux_dynamic_exec_target())
        self.assertEqual(caught.exception.diagnostic.rule, "SYSV-ENTRY-TARGET")

    def test_entry_cannot_be_passed_as_a_foreign_supplied_function_pointer(self):
        api = self.api
        worker_graph = GraphBuilder()
        worker = android_thread_entry.worker(worker_graph)
        graph = GraphBuilder()
        block = graph.block(api.byte_ptr_rw, api.byte_ptr_read, api.byte_ptr_rw, api.thread_effect, api.memory_effect)
        slot, attr, argument, thread, memory = block.params
        start = block.op1(Operation.FUNCTION_ADDRESS, (), self.entries.c_entry, entity=worker)
        status, thread, memory = block.op(Operation.CALL_FOREIGN, (slot, attr, start, argument, thread, memory), (B32, api.thread_effect, api.memory_effect), entity=api.pthread_create)
        block.ret(status, thread, memory)
        function = graph.function(block.parameter_types, (B32, api.thread_effect, api.memory_effect))
        with self.assertRaises(XaxError) as caught:
            program_store(function, android_arm64_shared_general_target(), (*api.types, *self.entries.types, *worker_graph.objects.values(), *graph.objects.values()))
        self.assertEqual(caught.exception.diagnostic.rule, "FOREIGN-CALL-CONTRACT")


if __name__ == "__main__":
    unittest.main()
