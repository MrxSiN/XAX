"""ADR-123: Linux AArch64 executables from the shared AAPCS64 lowerer."""

from __future__ import annotations

import os
import struct
import sys
import tempfile
import unittest
import zlib
from pathlib import Path

from xax_compiler import (
    FloatCompare,
    FloatFormat,
    IntCompare,
    Operation,
    XaxError,
    aarch64_linux_exec_target,
    android_arm64_shared_general_target,
    bits_type,
    float_constant,
    decode_native_target,
    execute,
    float_type,
    foreign_function_symbol,
    heap_view_type,
)
from xax_graph_builder import GraphBuilder, program_store
from xax_linux_aarch64 import (
    DYNAMIC_INTERPRETER,
    SYSROOT,
    aarch64_runner,
    c_function,
    compile_linux_aarch64_executable,
    linux_aarch64_api,
    run_linux_aarch64_executable,
    syscall_thunk,
)
from xax_x86_64 import encode_syscall_name

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from benchmarks.linux_filestat import benchmark_input, build_filestat_program, reference_filestat  # noqa: E402

B1, B8, B32, B64 = bits_type(1), bits_type(8), bits_type(32), bits_type(64)
F64 = float_type(FloatFormat.BINARY64)
RUNNER = aarch64_runner() is not None
SYSROOT_LIBC = os.path.exists(os.path.join(SYSROOT, "lib", "libc.so.6")) or not aarch64_runner()
SYSROOT_LIBZ = os.path.exists(os.path.join(SYSROOT, "lib", "libz.so.1"))
SIGTRAP = -5
FRAME_BYTES = 240  # filestat entry frame with liveness-shared slots (ADR-123)


def _status_program(compute, *, dynamic: bool = False, explicit_exit: bool = True):
    """Process entry exiting with ``value() & 0xff``; ``value`` is a pure callee the reference executor runs."""
    api = linux_aarch64_api()
    pure = GraphBuilder()
    body = pure.block()
    body.ret(compute(body))
    value = pure.function((), (B32,))
    graph = GraphBuilder()
    block = graph.block(api.process_effect, api.filesystem_effect)
    process, fs = block.params
    status = block.op1(Operation.BIT_AND, (block.op1(Operation.CALL_DIRECT, (), B32, entity=value), block.const(B32, 0xFF)), B32)
    if explicit_exit:
        process = block.op1(Operation.CALL_FOREIGN, (status, process), api.process_effect, entity=api.exit_group)
    block.ret(status, process, fs)
    entry = graph.function((api.process_effect, api.filesystem_effect), (B32, api.process_effect, api.filesystem_effect))
    target = aarch64_linux_exec_target(dynamic=dynamic)
    reader = program_store(entry, target, (*pure.objects.values(), *graph.objects.values(), *api.types))
    return reader, entry, target, value


def _write_program(message: bytes, *, extra=None, dynamic: bool = False):
    """mmap a page, store ``message``, write it to stdout, munmap, exit with ``extra(...)`` or 0."""
    api = linux_aarch64_api()
    graph = GraphBuilder()
    block = graph.block(api.process_effect, api.filesystem_effect, api.memory_effect)
    process, fs, memory = block.params
    raw, owner, memory = block.op(Operation.CALL_FOREIGN, (block.const(B64, 4096), memory), (api.bytes_rw, api.heap_owner, api.memory_effect), entity=api.mmap_anonymous)
    pointer, view, memory = block.op(Operation.HEAP_VIEW, (raw, owner, memory), (api.bytes_rw, heap_view_type(4096), api.memory_effect), attributes=(4096, 1))
    for offset, byte in enumerate(message):
        at = pointer if offset == 0 else block.op1(Operation.ADDRESS_OFFSET, (pointer,), api.bytes_rw, attributes=(offset,))
        memory = block.op1(Operation.STORE_BITS_LE, (at, block.const(B8, byte), memory), api.memory_effect, attributes=(1, 1))
    readable = block.op1(Operation.POINTER_CAST, (pointer,), api.bytes_read)
    _count, fs, memory = block.op(Operation.CALL_FOREIGN, (block.const(B32, 1), readable, block.const(B64, len(message)), fs, memory), (B64, api.filesystem_effect, api.memory_effect), entity=api.write)
    status, memory = extra(api, block, readable, memory) if extra else (block.const(B32, 0), memory)
    _result, memory = block.op(Operation.CALL_FOREIGN, (pointer, view, memory), (B64, api.memory_effect), entity=api.munmap_view(api.bytes_rw, 4096))
    process = block.op1(Operation.CALL_FOREIGN, (status, process), api.process_effect, entity=api.exit_group)
    block.ret(status, process, fs, memory)
    parameters = (api.process_effect, api.filesystem_effect, api.memory_effect)
    entry = graph.function(parameters, (B32, *parameters))
    target = aarch64_linux_exec_target(dynamic=dynamic)
    return program_store(entry, target, (*api.types, *graph.objects.values())), entry, target


def _strlen(api, block, readable, memory):
    strlen = c_function(b"libc.so.6", b"strlen", (api.bytes_read, api.memory_effect), (B64, api.memory_effect))
    length, memory = block.op(Operation.CALL_FOREIGN, (readable, memory), (B64, api.memory_effect), entity=strlen)
    return block.op1(Operation.INT_TRUNCATE, (length,), B32), memory


class LinuxAarch64ProfileTests(unittest.TestCase):
    def test_targets_decode_with_linux_abi_and_formats(self):
        static, dynamic = (decode_native_target(aarch64_linux_exec_target(dynamic=flag)) for flag in (False, True))
        self.assertEqual((static.architecture, static.abi, static.image_format), (3, 5, 6))
        self.assertEqual((dynamic.architecture, dynamic.abi, dynamic.image_format), (3, 5, 7))
        for operation in (Operation.UDIV, Operation.UREM, Operation.ROTATE_RIGHT, Operation.CALL_FOREIGN, Operation.HEAP_VIEW):
            self.assertIn(operation, static.supported_operations)

    def test_static_elf_is_minimal(self):
        reader, entry, target = _write_program(b"hi\n")
        data = compile_linux_aarch64_executable(reader, entry.cid, target.cid).data
        self.assertEqual(data[:4], b"\x7fELF")
        e_type, machine = struct.unpack_from("<HH", data, 16)
        phnum = struct.unpack_from("<H", data, 56)[0]
        self.assertEqual((e_type, machine, phnum), (2, 183, 2))
        self.assertNotIn(DYNAMIC_INTERPRETER, data)
        self.assertEqual(data, compile_linux_aarch64_executable(reader, entry.cid, target.cid).data)

    def test_dynamic_elf_requests_only_declared_libraries(self):
        reader, entry, target = _write_program(b"hello", extra=_strlen, dynamic=True)
        executable = compile_linux_aarch64_executable(reader, entry.cid, target.cid)
        self.assertEqual(executable.needed, (b"libc.so.6",))
        self.assertIn(DYNAMIC_INTERPRETER, executable.data)

    def test_static_profile_rejects_c_imports(self):
        reader, entry, target = _write_program(b"hello", extra=_strlen)
        with self.assertRaises(XaxError) as caught:
            compile_linux_aarch64_executable(reader, entry.cid, target.cid)
        self.assertEqual(caught.exception.diagnostic.rule, "AARCH64-FOREIGN-ABI")

    def test_foreign_conventions_are_owned_by_one_platform(self):
        api = linux_aarch64_api()
        android_call = foreign_function_symbol(b"libc.so", b"getpid", (), (B32,))

        def call(entity):
            def compute(block):
                return block.op1(Operation.CALL_FOREIGN, (), B32, entity=entity)
            return compute

        reader, entry, target, _value = _status_program(call(android_call), dynamic=True)
        with self.assertRaises(XaxError) as caught:
            compile_linux_aarch64_executable(reader, entry.cid, target.cid)
        self.assertEqual(caught.exception.diagnostic.rule, "AARCH64-FOREIGN-ABI")
        # A Linux syscall declaration on the Android profile also rejects.
        from xax_android import compile_android_shared  # noqa: F401  (import proves the module stays importable)
        from xax_aarch64 import compile_aarch64_bundle_bound_target

        graph = GraphBuilder()
        block = graph.block(api.process_effect)
        process = block.op1(Operation.CALL_FOREIGN, (block.const(B32, 0), block.params[0]), api.process_effect, entity=api.exit_group)
        block.ret(process)
        entry = graph.function((api.process_effect,), (api.process_effect,))
        android = android_arm64_shared_general_target()
        reader = program_store(entry, android, (*graph.objects.values(), *api.types))
        with self.assertRaises(XaxError) as caught:
            compile_aarch64_bundle_bound_target(reader, (entry.cid,), android)
        self.assertEqual(caught.exception.diagnostic.rule, "AARCH64-FOREIGN-ABI")

    def test_entry_with_machine_parameters_rejects(self):
        graph = GraphBuilder()
        block = graph.block(B32)
        block.ret(block.params[0])
        entry = graph.function((B32,), (B32,))
        target = aarch64_linux_exec_target()
        reader = program_store(entry, target, tuple(graph.objects.values()))
        with self.assertRaises(XaxError) as caught:
            compile_linux_aarch64_executable(reader, entry.cid, target.cid)
        self.assertEqual(caught.exception.diagnostic.rule, "LINUX-PROCESS-ENTRY-CONTRACT")

    def test_syscall_thunk_places_template_operands_and_literals(self):
        name = encode_syscall_name(222, (0, "$0", 3, 0x22, (1 << 64) - 1, 0))
        words = [int.from_bytes(chunk, "little") for chunk in (lambda b: [b[i:i + 4] for i in range(0, len(b), 4)])(syscall_thunk(name, True))]
        self.assertEqual(words[0], 0xAA0003E9)  # mov x9, x0 (stage operand 0)
        self.assertIn(0xD4000001, words)  # svc #0
        self.assertEqual(words[-3:], [0xB13FFC1F, 0x9A8023E0, 0xD65F03C0])  # error range -> null, ret

    def test_frame_slots_are_shared_by_liveness(self):
        program = build_filestat_program("aarch64")
        executable = compile_linux_aarch64_executable(program.reader, program.entry.cid, program.target.cid)
        bundle = executable.bundle
        prologue = int.from_bytes(bundle.code[dict(bundle.function_offsets)[program.entry.cid]:][:4], "little")
        self.assertEqual(prologue & 0xFFC003FF, 0xD10003FF)  # sub sp, sp, #frame
        # One slot per SSA value needed 4,848 bytes, past the 4 KiB frame limit.
        self.assertLessEqual((prologue >> 10) & 0xFFF, FRAME_BYTES)
        self.assertEqual(executable.data, compile_linux_aarch64_executable(program.reader, program.entry.cid, program.target.cid).data)


@unittest.skipUnless(RUNNER, "requires an AArch64 Linux host or qemu-aarch64")
class LinuxAarch64ExecutionTests(unittest.TestCase):
    def _run_status(self, compute, **kwargs):
        reader, entry, target, value = _status_program(compute, **kwargs)
        completed = run_linux_aarch64_executable(compile_linux_aarch64_executable(reader, entry.cid, target.cid).data)
        return completed.returncode, reader, value

    def test_integer_completion_matches_reference(self):
        cases = (
            lambda b: b.op1(Operation.UDIV, (b.const(B32, 1000), b.const(B32, 7)), B32),
            lambda b: b.op1(Operation.UREM, (b.const(B32, 1000), b.const(B32, 7)), B32),
            lambda b: b.op1(Operation.BIT_XOR, (b.const(B32, 0x40), b.const(B32, 0x05)), B32),
            lambda b: b.op1(Operation.BIT_AND, (b.const(B32, 0xF7), b.const(B32, 0x3C)), B32),
            lambda b: b.op1(Operation.BIT_OR, (b.const(B32, 0x40), b.const(B32, 0x05)), B32),
            lambda b: b.op1(Operation.ROTATE_RIGHT, (b.const(B32, 0x81),), B32, attributes=(1,)),
            lambda b: b.op1(Operation.INT_ZERO_EXTEND, (b.op1(Operation.ROTATE_RIGHT, (b.const(bits_type(12), 0x0F3),), bits_type(12), attributes=(4,)),), B32),
            lambda b: b.op1(Operation.INT_TRUNCATE, (b.op1(Operation.UREM, (b.const(B64, (1 << 40) + 77), b.const(B64, 1 << 33)), B64),), B32),
        )
        for index, compute in enumerate(cases):
            with self.subTest(case=index):
                status, reader, value = self._run_status(compute)
                self.assertEqual(status, execute(reader, value.cid, ())[0] & 0xFF)

    def test_every_compare_kind_on_the_frame_path(self):
        # INT_ZERO_EXTEND keeps these functions off the register path, so the
        # frame path's own condition encoding is what executes.
        for kind in IntCompare:
            for left, right in ((3, 5), (5, 5), (0xFFFFFFFE, 1)):
                def compute(block, kind=kind, left=left, right=right):
                    flag = block.op1(Operation.INT_COMPARE, (block.const(B32, left), block.const(B32, right)), B1, attributes=(kind,))
                    return block.op1(Operation.INT_ZERO_EXTEND, (flag,), B32)
                with self.subTest(kind=kind.name, left=left, right=right):
                    status, reader, value = self._run_status(compute)
                    self.assertEqual(status, execute(reader, value.cid, ())[0])
        for kind in FloatCompare:
            for left, right in ((1.5, 2.5), (2.5, 2.5), (3.0, -1.0)):
                def compute(block, kind=kind, left=left, right=right):
                    a = block.op1(Operation.CONSTANT, (), F64, entity=float_constant(F64, left))
                    c = block.op1(Operation.CONSTANT, (), F64, entity=float_constant(F64, right))
                    flag = block.op1(Operation.FLOAT_COMPARE, (a, c), B1, attributes=(kind,))
                    return block.op1(Operation.INT_ZERO_EXTEND, (flag,), B32)
                with self.subTest(kind=kind.name, left=left, right=right):
                    status, reader, value = self._run_status(compute)
                    self.assertEqual(status, execute(reader, value.cid, ())[0])

    def test_division_by_zero_traps(self):
        def compute(block):
            zero = block.op1(Operation.SUB_WRAP, (block.const(B32, 5), block.const(B32, 5)), B32)
            return block.op1(Operation.UDIV, (block.const(B32, 9), zero), B32)
        self.assertEqual(self._run_status(compute)[0], SIGTRAP)

    def test_returning_entry_traps_instead_of_exiting(self):
        self.assertEqual(self._run_status(lambda block: block.const(B32, 5), explicit_exit=False)[0], SIGTRAP)

    def test_failed_mapping_never_becomes_a_proven_heap_view(self):
        api = linux_aarch64_api()
        graph = GraphBuilder()
        block = graph.block(api.process_effect, api.filesystem_effect, api.memory_effect)
        process, fs, memory = block.params
        raw, owner, memory = block.op(Operation.CALL_FOREIGN, (block.const(B64, 1 << 62), memory), (api.bytes_rw, api.heap_owner, api.memory_effect), entity=api.mmap_anonymous)
        pointer, view, memory = block.op(Operation.HEAP_VIEW, (raw, owner, memory), (api.bytes_rw, heap_view_type(4096), api.memory_effect), attributes=(4096, 1))
        _result, memory = block.op(Operation.CALL_FOREIGN, (pointer, view, memory), (B64, api.memory_effect), entity=api.munmap_view(api.bytes_rw, 4096))
        zero = block.const(B32, 0)
        process = block.op1(Operation.CALL_FOREIGN, (zero, process), api.process_effect, entity=api.exit_group)
        block.ret(zero, process, fs, memory)
        parameters = (api.process_effect, api.filesystem_effect, api.memory_effect)
        entry = graph.function(parameters, (B32, *parameters))
        target = aarch64_linux_exec_target()
        reader = program_store(entry, target, (*api.types, *graph.objects.values()))
        completed = run_linux_aarch64_executable(compile_linux_aarch64_executable(reader, entry.cid, target.cid).data)
        self.assertEqual(completed.returncode, SIGTRAP)

    def test_static_write_executes(self):
        reader, entry, target = _write_program(b"hello from xax\n")
        completed = run_linux_aarch64_executable(compile_linux_aarch64_executable(reader, entry.cid, target.cid).data)
        self.assertEqual((completed.returncode, completed.stdout), (0, b"hello from xax\n"))

    @unittest.skipUnless(SYSROOT_LIBC, "requires the AArch64 glibc sysroot")
    def test_dynamic_libc_call_executes(self):
        reader, entry, target = _write_program(b"hello", extra=_strlen, dynamic=True)
        completed = run_linux_aarch64_executable(compile_linux_aarch64_executable(reader, entry.cid, target.cid).data)
        self.assertEqual((completed.returncode, completed.stdout), (5, b"hello"))

    @unittest.skipUnless(SYSROOT_LIBZ, "requires libz.so.1 in the AArch64 sysroot")
    def test_filestat_matches_reference_contract(self):
        program = build_filestat_program("aarch64")
        executable = compile_linux_aarch64_executable(program.reader, program.entry.cid, program.target.cid)
        self.assertEqual(executable.needed, (b"libz.so.1",))
        data = benchmark_input(100_003)
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, "input.dat").write_bytes(data)
            completed = run_linux_aarch64_executable(executable.data, cwd=directory)
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(completed.stdout, reference_filestat(data))
        self.assertIn(str(zlib.crc32(data)).encode(), completed.stdout)


if __name__ == "__main__":
    unittest.main()
