"""OI-40 / ADR-102: C callbacks into XAX and SSE-class SysV C arguments."""

from __future__ import annotations

import hashlib
import json
import platform
import sys
import unittest
from pathlib import Path

from xax_compiler import (
    OpaqueKind,
    Operation,
    XaxError,
    bits_type,
    call_contract,
    function_pointer_type,
    opaque_type,
    x86_64_linux_dynamic_exec_target,
    x86_64_windows_general_target,
)
from xax_graph_builder import GraphBuilder, program_store
from xax_linux import c_function, compile_linux_executable, linux_api, run_linux_executable
from xax_x86_64 import _sysv_entry_adapter, _zero_extending_move, compile_native_bound_target
from xax_compiler import decode_native_target

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from benchmarks.linux_c_interop import (  # noqa: E402
    CALLBACK_STATUS, EVIDENCE, FLOAT_STATUS, callback_program, compile_programs, float_program,
)

LINUX_X86_64 = sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")
B8, B16, B32, B64 = bits_type(8), bits_type(16), bits_type(32), bits_type(64)


def _pure(parameters, result=B32):
    graph = GraphBuilder()
    block = graph.block(*parameters)
    block.ret(block.const(result, 0))
    return graph, graph.function(parameters, (result,))


def _address_program(callee_graph, callee, result_type, target=None, extra=()):
    """``entry() -> bits<32>`` that takes ``callee``'s address as ``result_type`` and returns 0."""
    graph = GraphBuilder()
    block = graph.block()
    block.op1(Operation.FUNCTION_ADDRESS, (), result_type, entity=callee)
    block.ret(block.const(B32, 0))
    entry = graph.function((), (B32,))
    target = target or x86_64_linux_dynamic_exec_target()
    return program_store(entry, target, (*extra, *callee_graph.objects.values(), *graph.objects.values())), entry, target


class ForeignEntryVerifierTests(unittest.TestCase):
    def test_entry_with_proof_parameters_rejects(self):
        """C cannot supply effect tokens, so an effectful entry would hide its effects."""
        api = linux_api()
        graph = GraphBuilder()
        block = graph.block(B64, api.memory_effect)
        block.ret(block.const(B32, 0), block.params[1])
        callee = graph.function((B64, api.memory_effect), (B32, api.memory_effect))
        with self.assertRaises(XaxError) as caught:
            _address_program(graph, callee, api.c_callback, extra=api.types)
        self.assertEqual(caught.exception.diagnostic.rule, "GRAPH-FUNCTION-ADDRESS-FOREIGN-ENTRY")

    def test_c_entry_cannot_be_called_with_the_internal_convention(self):
        api = linux_api()
        callee_graph, callee = _pure((B64, B64))
        graph = GraphBuilder()
        block = graph.block()
        pointer = block.op1(Operation.FUNCTION_ADDRESS, (), api.c_callback, entity=callee)
        contract = call_contract((B64, B64), (B32,), may_return=True, may_trap=False)
        block.ret(block.op1(Operation.CALL_INDIRECT, (pointer, block.const(B64, 1), block.const(B64, 2)), B32, entity=contract))
        entry = graph.function((), (B32,))
        with self.assertRaises(XaxError) as caught:
            program_store(entry, x86_64_linux_dynamic_exec_target(), (*api.types, *callee_graph.objects.values(), *graph.objects.values()))
        self.assertEqual(caught.exception.diagnostic.rule, "INDIRECT-CALL-TARGET-TYPE")

    def test_internal_address_cannot_be_passed_as_a_c_callback(self):
        api = linux_api()
        tsearch = c_function(b"libc.so.6", b"tsearch", (B64, B64, api.c_callback, api.memory_effect), (B64, api.memory_effect))
        callee_graph, callee = _pure((B64, B64))
        graph = GraphBuilder()
        block = graph.block(api.memory_effect)
        internal = block.op1(Operation.FUNCTION_ADDRESS, (), function_pointer_type(), entity=callee)
        _node, memory = block.op(Operation.CALL_FOREIGN, (block.const(B64, 1), block.const(B64, 0), internal, block.params[0]), (B64, api.memory_effect), entity=tsearch)
        block.ret(memory)
        entry = graph.function((api.memory_effect,), (api.memory_effect,))
        with self.assertRaises(XaxError) as caught:
            program_store(entry, x86_64_linux_dynamic_exec_target(), (*api.types, opaque_type(OpaqueKind.FUNCTION), *callee_graph.objects.values(), *graph.objects.values()))
        self.assertEqual(caught.exception.diagnostic.rule, "FOREIGN-CALL-CONTRACT")


class ForeignEntryBackendTests(unittest.TestCase):
    def test_adapter_is_exact(self):
        api = linux_api()
        callee_graph, callee = _pure((B64, B64))
        reader, _entry, target = _address_program(callee_graph, callee, api.c_callback, extra=api.types)
        description = decode_native_target(target)
        code, call = _sysv_entry_adapter(callee, reader_resolve(reader), description)
        # sub rsp, 40; mov rdx, rsi; mov rcx, rdi; call rel32; add rsp, 40; ret
        self.assertEqual(code, bytes.fromhex("4883ec28488bd6488bcfe8000000004883c428c3"))
        self.assertEqual(call, 11)

    def test_narrow_arguments_are_zero_extended(self):
        self.assertEqual(_zero_extending_move(1, 7, 32), bytes.fromhex("8bcf"))  # mov ecx, edi
        self.assertEqual(_zero_extending_move(2, 6, 16), bytes.fromhex("0fb7d6"))  # movzx edx, si
        self.assertEqual(_zero_extending_move(8, 2, 8), bytes.fromhex("440fb6c2"))  # movzx r8d, dl
        self.assertEqual(_zero_extending_move(9, 1, 64), bytes.fromhex("4c8bc9"))  # mov r9, rcx

    def test_entry_signature_outside_the_adapter_rejects(self):
        api = linux_api()
        callee_graph, callee = _pure((B64,) * 5)
        reader, entry, target = _address_program(callee_graph, callee, api.c_callback, extra=api.types)
        with self.assertRaises(XaxError) as caught:
            compile_linux_executable(reader, entry.cid, target.cid)
        self.assertEqual(caught.exception.diagnostic.rule, "SYSV-ENTRY-SIGNATURE")

    def test_entry_on_a_non_sysv_profile_rejects(self):
        api = linux_api()
        callee_graph, callee = _pure((B64, B64))
        reader, entry, _target = _address_program(callee_graph, callee, api.c_callback, extra=api.types)
        with self.assertRaises(XaxError) as caught:
            compile_native_bound_target(reader, entry.cid, x86_64_windows_general_target())
        self.assertEqual(caught.exception.diagnostic.rule, "SYSV-ENTRY-TARGET")

    def test_artifacts_are_deterministic(self):
        first, second = compile_programs(), compile_programs()
        for name in first:
            self.assertEqual(first[name].data, second[name].data)

    def test_committed_evidence_matches_the_compiled_artifacts(self):
        committed = json.loads(EVIDENCE.read_text(encoding="utf-8"))
        for name, executable in compile_programs().items():
            row = committed["programs"][name]
            self.assertEqual(row["artifact_sha256"], hashlib.sha256(executable.data).hexdigest())
            self.assertTrue(row["passed"])


def reader_resolve(reader):
    from xax_compiler import store_resolver

    return store_resolver(reader)


@unittest.skipUnless(LINUX_X86_64, "requires a Linux x86-64 host to execute ELF64 artifacts")
class ForeignEntryExecutionTests(unittest.TestCase):
    def test_libc_calls_back_into_xax(self):
        reader, entry, target, _compare = callback_program()
        completed = run_linux_executable(compile_linux_executable(reader, entry.cid, target.cid).data)
        self.assertEqual(completed.returncode, CALLBACK_STATUS)

    def test_callback_result_is_consulted(self):
        """Control: a comparator that always answers 'equal' keeps one node, so every probe finds it."""
        import benchmarks.linux_c_interop as workload

        original = workload.comparator

        def constant(graph):
            block = graph.block(B64, B64)
            block.ret(block.const(B32, 0))
            return graph.function((B64, B64), (B32,))

        workload.comparator = constant
        try:
            reader, entry, target, _compare = workload.callback_program()
        finally:
            workload.comparator = original
        completed = run_linux_executable(compile_linux_executable(reader, entry.cid, target.cid).data)
        self.assertEqual(completed.returncode, sum(workload.PROBED))

    def test_sse_class_arguments_and_results(self):
        reader, entry, target = float_program()
        completed = run_linux_executable(compile_linux_executable(reader, entry.cid, target.cid).data)
        self.assertEqual(completed.returncode, FLOAT_STATUS)


if __name__ == "__main__":
    unittest.main()
