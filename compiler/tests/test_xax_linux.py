"""U1.3: exact integer completion, Linux syscall and SysV C ABIs, and direct ELF64 executables."""

from __future__ import annotations

import hashlib
import json
import platform
import struct
import sys
import tempfile
import unittest
from pathlib import Path

from xax_compiler import (
    IntCompare,
    Operation,
    TrapReason,
    XaxError,
    XaxTrap,
    bits_type,
    execute,
    foreign_function_symbol,
    heap_view_type,
    x86_64_linux_dynamic_exec_target,
    x86_64_linux_exec_target,
    x86_64_windows_general_target,
)
from xax_compiler import FloatFormat, float_type
from xax_graph_builder import GraphBuilder, program_store
from xax_linux import DYNAMIC_INTERPRETER, c_function, compile_linux_executable, linux_api, run_linux_executable
from xax_x86_64 import compile_native, decode_syscall_name, encode_syscall_name

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from benchmarks.linux_filestat import EVIDENCE, compile_filestat, reference_filestat  # noqa: E402

LINUX_X86_64 = sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")
B32, B64 = bits_type(32), bits_type(64)


def _binary_program(operation: Operation, width: int = 32):
    """``f(a, b) = op(a, b)`` over bits<width>."""
    type_ = bits_type(width)
    graph = GraphBuilder()
    block = graph.block(type_, type_)
    block.ret(block.op1(operation, block.params, type_))
    entry = graph.function((type_, type_), (type_,))
    target = x86_64_linux_exec_target()
    return program_store(entry, target, tuple(graph.objects.values())), entry, target


def _exit_entry(api, graph: GraphBuilder, block, status, *, explicit_exit: bool = True):
    """Finish a Linux process entry: explicit ``exit_group(status)`` (ADR-076), then the unreachable return."""
    process, fs = block.params[:2]
    if explicit_exit:
        process = block.op1(Operation.CALL_FOREIGN, (status, process), api.process_effect, entity=api.exit_group)
    rest = block.params[2:]
    block.ret(status, process, fs, *rest)
    parameters = (api.process_effect, api.filesystem_effect, *(api.memory_effect for _ in rest))
    return graph.function(parameters, (B32, *parameters))


def _status_program(compute, target=None, *, explicit_exit: bool = True):
    """Linux entry exiting with ``value() & 0xff``; ``value`` is a pure callee the executor can run."""
    api = linux_api()
    pure = GraphBuilder()
    body = pure.block()
    body.ret(compute(body))
    value = pure.function((), (B32,))
    graph = GraphBuilder()
    block = graph.block(api.process_effect, api.filesystem_effect)
    computed = block.op1(Operation.CALL_DIRECT, (), B32, entity=value)
    status = block.op1(Operation.BIT_AND, (computed, block.const(B32, 0xFF)), B32)
    entry = _exit_entry(api, graph, block, status, explicit_exit=explicit_exit)
    target = target or x86_64_linux_exec_target()
    return program_store(entry, target, (*pure.objects.values(), *graph.objects.values(), *api.types)), entry, target, value


class ExactIntegerOperationTests(unittest.TestCase):
    def test_reference_semantics(self):
        cases = {
            Operation.BIT_AND: (0xF0F0_1234, 0x0FF0_FFFF, 0x00F0_1234),
            Operation.BIT_OR: (0xF000_0000, 0x0000_000F, 0xF000_000F),
            Operation.UDIV: (0xFFFF_FFFF, 10, 429_496_729),
            Operation.UREM: (0xFFFF_FFFF, 10, 5),
        }
        for operation, (left, right, expected) in cases.items():
            with self.subTest(operation=operation.name):
                reader, entry, _target = _binary_program(operation)
                self.assertEqual(execute(reader, entry.cid, (left, right)), (expected,))

    def test_division_by_zero_is_an_explicit_portable_trap(self):
        for operation in (Operation.UDIV, Operation.UREM):
            reader, entry, _target = _binary_program(operation, 64)
            with self.assertRaises(XaxTrap) as caught:
                execute(reader, entry.cid, (7, 0))
            self.assertEqual(caught.exception.reason, TrapReason.INTEGER_DIVIDE_BY_ZERO)

    def test_width_changes_are_exact(self):
        graph = GraphBuilder()
        block = graph.block(B64)
        narrow = block.op1(Operation.INT_TRUNCATE, block.params, bits_type(8))
        block.ret(block.op1(Operation.INT_ZERO_EXTEND, (narrow,), B32))
        entry = graph.function((B64,), (B32,))
        reader = program_store(entry, x86_64_linux_exec_target(), tuple(graph.objects.values()))
        self.assertEqual(execute(reader, entry.cid, (0x1234_5678_9ABC_DEF1,)), (0xF1,))

    def test_width_direction_is_verified(self):
        for operation, source, result in ((Operation.INT_TRUNCATE, B32, B64), (Operation.INT_ZERO_EXTEND, B64, B32), (Operation.INT_TRUNCATE, B32, B32)):
            with self.subTest(operation=operation.name, source=source.cid.hex()[:8], result=result.cid.hex()[:8]):
                graph = GraphBuilder()
                block = graph.block(source)
                block.ret(block.op1(operation, block.params, result))
                entry = graph.function((source,), (result,))
                with self.assertRaises(XaxError) as caught:
                    program_store(entry, x86_64_linux_exec_target(), tuple(graph.objects.values()))
                self.assertEqual(caught.exception.diagnostic.code, "XAX.INT.WIDTH")

    def test_binary_operand_types_must_match(self):
        graph = GraphBuilder()
        block = graph.block(B32, B64)
        block.ret(block.op1(Operation.UDIV, block.params, B32))
        entry = graph.function((B32, B64), (B32,))
        with self.assertRaises(XaxError) as caught:
            program_store(entry, x86_64_linux_exec_target(), tuple(graph.objects.values()))
        self.assertEqual(caught.exception.diagnostic.code, "XAX.STRUCT.OP_TYPE")

    def test_legacy_targets_do_not_advertise_new_operations(self):
        reader, entry, _target = _binary_program(Operation.BIT_AND)
        legacy = x86_64_windows_general_target()
        from xax_x86_64 import compile_native_bound_target

        with self.assertRaises(XaxError) as caught:
            compile_native_bound_target(reader, entry.cid, legacy)
        self.assertEqual(caught.exception.diagnostic.code, "XAX.NATIVE.UNSUPPORTED_OPERATION")


class SyscallTemplateTests(unittest.TestCase):
    def test_round_trip_and_default_order(self):
        name = encode_syscall_name(9, (0, "$0", 3, 34, (1 << 64) - 1, 0))
        self.assertEqual(name, b"9:0,$0,3,34,18446744073709551615,0")
        self.assertEqual(decode_syscall_name(name, 1)[0], 9)
        self.assertEqual(decode_syscall_name(b"1", 3), (1, ("$0", "$1", "$2")))

    def test_non_canonical_or_incomplete_templates_reject(self):
        for name, machine_inputs in ((b"01", 0), (b"9:$1", 1), (b"9:$0,$0", 1), (b"9:$0", 2), (b"x", 0), (b"1:1,2,3,4,5,6,7", 0)):
            with self.subTest(name=name):
                with self.assertRaises(XaxError) as caught:
                    decode_syscall_name(name, machine_inputs)
                self.assertEqual(caught.exception.diagnostic.code, "XAX.FOREIGN.SYSCALL")

    def test_unknown_foreign_abi_is_rejected_by_the_verifier(self):
        api = linux_api()
        unknown = foreign_function_symbol(b"linux", b"39", (api.filesystem_effect,), (B64, api.filesystem_effect), abi=b"linux-x86_64-guess")
        graph = GraphBuilder()
        block = graph.block(api.filesystem_effect)
        pid, fs = block.op(Operation.CALL_FOREIGN, block.params, (B64, api.filesystem_effect), entity=unknown)
        block.ret(block.op1(Operation.INT_TRUNCATE, (pid,), B32), fs)
        entry = graph.function((api.filesystem_effect,), (B32, api.filesystem_effect))
        with self.assertRaises(XaxError) as caught:
            program_store(entry, x86_64_linux_exec_target(), tuple(graph.objects.values()))
        self.assertEqual(caught.exception.diagnostic.code, "XAX.FOREIGN.ABI")


class ProcessEntryTests(unittest.TestCase):
    def test_entry_with_machine_parameters_rejects(self):
        reader, entry, target = _binary_program(Operation.BIT_OR)
        with self.assertRaises(XaxError) as caught:
            compile_linux_executable(reader, entry.cid, target.cid)
        self.assertEqual(caught.exception.diagnostic.code, "XAX.LINUX.ENTRY")

    def test_non_linux_target_rejects(self):
        reader, entry, legacy, _value = _status_program(lambda block: block.const(B32, 7), x86_64_windows_general_target())
        with self.assertRaises(XaxError) as caught:
            compile_linux_executable(reader, entry.cid, legacy.cid)
        self.assertEqual(caught.exception.diagnostic.code, "XAX.LINUX.TARGET")

    def test_elf_structure_is_static_and_minimal(self):
        reader, entry, target, _value = _status_program(lambda block: block.const(B32, 7))
        executable = compile_linux_executable(reader, entry.cid, target.cid)
        data = executable.data
        self.assertEqual(data[:4], b"\x7fELF")
        e_type, machine = struct.unpack_from("<HH", data, 16)
        entry_address, phoff, shoff = struct.unpack_from("<QQQ", data, 24)
        phnum = struct.unpack_from("<H", data, 56)[0]
        self.assertEqual((e_type, machine, shoff, phnum), (2, 62, 0, 2))
        types = [struct.unpack_from("<II", data, phoff + 56 * index) for index in range(phnum)]
        self.assertEqual(types, [(1, 5), (0x6474E551, 6)])  # R+X load, non-executable stack; no PT_INTERP/PT_DYNAMIC
        self.assertEqual(entry_address, 0x400000 + executable.entry_offset)  # e_entry is the XAX entry itself
        self.assertEqual(data, compile_linux_executable(reader, entry.cid, target.cid).data)


def _crc_program(target, data: bytes = b"hello", declaration=None):
    """mmap a page, store ``data``, return ``libz crc32(0, data) & 0xff``."""
    api = linux_api()
    declaration = declaration or c_function(b"libz.so.1", b"crc32", (B64, api.bytes_read, B32, api.memory_effect), (B64, api.memory_effect))
    graph = GraphBuilder()
    block = graph.block(api.process_effect, api.filesystem_effect, api.memory_effect)
    process, fs, memory = block.params
    raw, owner, memory = block.op(Operation.CALL_FOREIGN, (block.const(B64, 4096), memory), (api.bytes_rw, api.heap_owner, api.memory_effect), entity=api.mmap_anonymous)
    pointer, view, memory = block.op(Operation.HEAP_VIEW, (raw, owner, memory), (api.bytes_rw, heap_view_type(4096), api.memory_effect), attributes=(4096, 1))
    for offset, byte in enumerate(data):
        address = pointer if offset == 0 else block.op1(Operation.ADDRESS_OFFSET, (pointer,), api.bytes_rw, attributes=(offset,))
        memory = block.op1(Operation.STORE_BITS_LE, (address, block.const(api.b8, byte), memory), api.memory_effect, attributes=(1, 1))
    readable = block.op1(Operation.POINTER_CAST, (pointer,), api.bytes_read)
    crc, memory = block.op(Operation.CALL_FOREIGN, (block.const(B64, 0), readable, block.const(B32, len(data)), memory), (B64, api.memory_effect), entity=declaration)
    _result, memory = block.op(Operation.CALL_FOREIGN, (pointer, view, memory), (B64, api.memory_effect), entity=api.munmap_view(api.bytes_rw, 4096))
    status = block.op1(Operation.BIT_AND, (block.op1(Operation.INT_TRUNCATE, (crc,), B32), block.const(B32, 0xFF)), B32)
    process = block.op1(Operation.CALL_FOREIGN, (status, process), api.process_effect, entity=api.exit_group)
    block.ret(status, process, fs, memory)
    entry = graph.function((api.process_effect, api.filesystem_effect, api.memory_effect), (B32, api.process_effect, api.filesystem_effect, api.memory_effect))
    return program_store(entry, target, (*api.types, *graph.objects.values())), entry, target


class DynamicLinkingTests(unittest.TestCase):
    def test_dynamic_executable_declares_only_requested_loader_and_libraries(self):
        reader, entry, target = _crc_program(x86_64_linux_dynamic_exec_target())
        executable = compile_linux_executable(reader, entry.cid, target.cid)
        data = executable.data
        self.assertEqual(executable.needed, (b"libz.so.1",))
        phoff, phnum = struct.unpack_from("<Q", data, 32)[0], struct.unpack_from("<H", data, 56)[0]
        headers = [struct.unpack_from("<IIQQQQQQ", data, phoff + 56 * index) for index in range(phnum)]
        self.assertEqual([item[0] for item in headers], [6, 3, 1, 1, 2, 0x6474E551])
        interp = headers[1]
        self.assertEqual(data[interp[2]:interp[2] + interp[5]], DYNAMIC_INTERPRETER + b"\x00")
        self.assertNotIn(b"libc.so", data)  # no libc dependency of XAX's own
        self.assertEqual(data, compile_linux_executable(reader, entry.cid, target.cid).data)

    def test_static_profile_rejects_c_imports(self):
        reader, entry, target = _crc_program(x86_64_linux_exec_target())
        with self.assertRaises(XaxError) as caught:
            compile_linux_executable(reader, entry.cid, target.cid)
        self.assertEqual(caught.exception.diagnostic.code, "XAX.NATIVE.FOREIGN_ABI")

    def test_emitter_rejects_implicit_loader_and_ambiguous_imports(self):
        from xax_linux import emit_linux_elf_executable
        from xax_x86_64 import NativeImage

        def image(*imports):
            return NativeImage(bytes(16), 0, (), (32,), bytes(32), (), imports=imports)

        with self.assertRaises(XaxError) as caught:
            emit_linux_elf_executable(image((2, b"libz.so.1", b"crc32")))
        self.assertEqual(caught.exception.diagnostic.code, "XAX.LINUX.DYNAMIC_REQUIRED")
        with self.assertRaises(XaxError) as caught:
            emit_linux_elf_executable(image((2, b"libz.so.1", b"crc32"), (8, b"libother.so", b"crc32")), dynamic_loader=True)
        self.assertEqual(caught.exception.diagnostic.code, "XAX.LINUX.IMPORT")

    def test_non_integer_c_signature_rejects(self):
        api = linux_api()
        f64 = float_type(FloatFormat.BINARY64)
        declaration = c_function(b"libm.so.6", b"sqrt", (f64,), (f64,))
        graph = GraphBuilder()
        block = graph.block(api.filesystem_effect)
        value = block.op1(Operation.CALL_FOREIGN, (block.op1(Operation.UINT_TO_FLOAT, (block.const(B32, 4),), f64),), f64, entity=declaration)
        block.ret(block.op1(Operation.FLOAT_TO_UINT_TRUNC, (value,), B32), block.params[0])
        entry = graph.function((api.filesystem_effect,), (B32, api.filesystem_effect))
        target = x86_64_linux_dynamic_exec_target()
        reader = program_store(entry, target, tuple(graph.objects.values()))
        with self.assertRaises(XaxError) as caught:
            compile_linux_executable(reader, entry.cid, target.cid)
        self.assertEqual(caught.exception.diagnostic.rule, "SYSV-C-INTEGER-CLASS")


@unittest.skipUnless(LINUX_X86_64, "requires a Linux x86-64 host to execute ELF64 artifacts")
class LinuxExecutionTests(unittest.TestCase):
    def test_integer_operations_execute_natively(self):
        cases = (
            (lambda b: b.op1(Operation.UDIV, (b.const(B32, 1000), b.const(B32, 7)), B32), 142),
            (lambda b: b.op1(Operation.UREM, (b.const(B32, 1000), b.const(B32, 7)), B32), 6),
            (lambda b: b.op1(Operation.BIT_OR, (b.const(B32, 0x40), b.const(B32, 0x05)), B32), 0x45),
            (lambda b: b.op1(Operation.INT_TRUNCATE, (b.op1(Operation.UDIV, (b.const(B64, 1 << 40), b.const(B64, 1 << 33)), B64),), B32), 128),
            (lambda b: b.op1(Operation.INT_TRUNCATE, (b.op1(Operation.INT_ZERO_EXTEND, (b.const(bits_type(8), 0xC3),), B64),), B32), 0xC3),
        )
        for compute, expected in cases:
            with self.subTest(expected=expected):
                reader, entry, target, value = _status_program(compute)
                self.assertEqual(execute(reader, value.cid, ())[0], expected)
                completed = run_linux_executable(compile_linux_executable(reader, entry.cid, target.cid).data)
                self.assertEqual(completed.returncode, expected)

    def test_dynamic_division_by_zero_traps(self):
        def compute(block):
            zero = block.op1(Operation.SUB_WRAP, (block.const(B32, 5), block.const(B32, 5)), B32)
            return block.op1(Operation.UDIV, (block.const(B32, 9), zero), B32)

        reader, entry, target, _value = _status_program(compute)
        completed = run_linux_executable(compile_linux_executable(reader, entry.cid, target.cid).data)
        self.assertEqual(completed.returncode, -4)  # SIGILL from the explicit ud2 trap

    def test_returning_entry_traps_instead_of_exiting(self):
        reader, entry, target, _value = _status_program(lambda block: block.const(B32, 5), explicit_exit=False)
        completed = run_linux_executable(compile_linux_executable(reader, entry.cid, target.cid).data)
        self.assertEqual(completed.returncode, -4)  # no hidden exit path

    def test_failed_mapping_never_becomes_a_proven_heap_view(self):
        api = linux_api()
        graph = GraphBuilder()
        block = graph.block(api.process_effect, api.filesystem_effect, api.memory_effect)
        process, fs, memory = block.params
        size = (1 << 62)
        raw, owner, memory = block.op(Operation.CALL_FOREIGN, (block.const(B64, size), memory), (api.bytes_rw, api.heap_owner, api.memory_effect), entity=api.mmap_anonymous)
        pointer, view, memory = block.op(Operation.HEAP_VIEW, (raw, owner, memory), (api.bytes_rw, heap_view_type(4096), api.memory_effect), attributes=(4096, 1))
        _result, memory = block.op(Operation.CALL_FOREIGN, (pointer, view, memory), (B64, api.memory_effect), entity=api.munmap_view(api.bytes_rw, 4096))
        zero = block.const(B32, 0)
        process = block.op1(Operation.CALL_FOREIGN, (zero, process), api.process_effect, entity=api.exit_group)
        block.ret(zero, process, fs, memory)
        entry = graph.function((api.process_effect, api.filesystem_effect, api.memory_effect), (B32, api.process_effect, api.filesystem_effect, api.memory_effect))
        target = x86_64_linux_exec_target()
        reader = program_store(entry, target, (*api.types, *graph.objects.values()))
        completed = run_linux_executable(compile_linux_executable(reader, entry.cid, target.cid).data)
        self.assertEqual(completed.returncode, -4)

    def test_external_library_call_executes(self):
        import zlib

        reader, entry, target = _crc_program(x86_64_linux_dynamic_exec_target())
        completed = run_linux_executable(compile_linux_executable(reader, entry.cid, target.cid).data)
        self.assertEqual(completed.returncode, zlib.crc32(b"hello") & 0xFF)

    def test_filestat_matches_reference_contract(self):
        _program, executable = compile_filestat()
        corpora = (b"", b"x", b"hello world\n  foo\tbar\r\nzzz", bytes(range(256)) * 300, b"a\n" * 70_000)
        with tempfile.TemporaryDirectory() as directory:
            for data in corpora:
                with self.subTest(size=len(data)):
                    Path(directory, "input.dat").write_bytes(data)
                    completed = run_linux_executable(executable.data, cwd=directory)
                    self.assertEqual((completed.returncode, completed.stdout), (0, reference_filestat(data)))
            Path(directory, "input.dat").unlink()
            completed = run_linux_executable(executable.data, cwd=directory)
            self.assertEqual((completed.returncode, completed.stdout), (2, b""))


class FilestatEvidenceTests(unittest.TestCase):
    def test_committed_artifact_identity_reproduces(self):
        program, executable = compile_filestat()
        evidence = json.loads(EVIDENCE.read_text())
        self.assertEqual(evidence["xax"]["artifact_sha256"], hashlib.sha256(executable.data).hexdigest())
        self.assertEqual(evidence["xax"]["program_root"], program.reader.root_cid.hex())
        self.assertEqual(evidence["xax"]["runtime_dependencies"], [])
        self.assertEqual(evidence["evidence_label"], "MEASURED")


if __name__ == "__main__":
    unittest.main()
