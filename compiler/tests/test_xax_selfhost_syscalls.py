"""S10a (ADR-264): Linux syscalls in the x86-64 views profile, lowered by the XAX backend program.

``x86_64-linux-views-v2`` adds ``call.foreign`` of a ``linux-x86_64-syscall-v1`` declaration (no heap contract) to the
views operations.  The XAX x86-64 backend program decodes the declaration and its register template itself and must
produce the bootstrap generator's bytes; it decides every ``X86_64_VIEWS-SYSCALL`` rejection with the bootstrap's exact
diagnostic.  Natively, an XAX views image opens, reads, writes, and closes files with its own syscalls.
"""

from __future__ import annotations

import ctypes
import os
import platform
import random
import sys
import tempfile
import unittest

from xax_compiler import (
    LINUX_X86_64_SYSCALL_ABI,
    Operation,
    XaxError,
    foreign_function_symbol,
    heap_view_type,
    x86_64_linux_exec_target,
    x86_64_views_syscall_target,
    x86_64_views_target,
)
from xax_graph_builder import GraphBuilder, program_store
from xax_linux import _LIBRARY, linux_api
from xax_x86_64 import encode_syscall_name
from xax_x86_64_views import NativeViewsImage, compile_x86_64_views

LINUX_X86_64 = sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")
API = linux_api()
B32, B64, FS, MEM = API.b32, API.b64, API.filesystem_effect, API.memory_effect
PATH_VIEW, BUFFER_VIEW = heap_view_type(256), heap_view_type(4096)


def syscall(name: bytes, inputs, outputs, abi: bytes = LINUX_X86_64_SYSCALL_ABI, **contracts):
    return foreign_function_symbol(_LIBRARY, name, inputs, outputs, abi=abi, **contracts)


# ``write`` from a read-write view (the profile has no permission narrowing yet).
WRITE_RW = syscall(encode_syscall_name(1), (B32, API.bytes_rw, B64, FS, MEM), (B64, FS, MEM))


def copy_program():
    """``copy(path, buffer, out) -> written``: openat, read, write, close."""
    graph = GraphBuilder()
    inputs = (API.bytes_read, PATH_VIEW, MEM, API.bytes_rw, BUFFER_VIEW, MEM, FS, B64)
    block = graph.block(*inputs)
    path, path_view, path_memory, buffer, buffer_view, buffer_memory, fs, out = block.params
    at_fdcwd, zero = block.const(B32, 0xFFFFFF9C), block.const(B32, 0)
    fd, fs, path_memory = block.op(Operation.CALL_FOREIGN, (at_fdcwd, path, zero, zero, fs, path_memory), (B64, FS, MEM), entity=API.openat)
    fd32 = block.op1(Operation.INT_TRUNCATE, (fd,), B32)
    count, fs, buffer_memory = block.op(Operation.CALL_FOREIGN, (fd32, buffer, block.const(B64, 4096), fs, buffer_memory), (B64, FS, MEM), entity=API.read)
    out32 = block.op1(Operation.INT_TRUNCATE, (out,), B32)
    written, fs, buffer_memory = block.op(Operation.CALL_FOREIGN, (out32, buffer, count, fs, buffer_memory), (B64, FS, MEM), entity=WRITE_RW)
    _closed, fs = block.op(Operation.CALL_FOREIGN, (fd32, fs), (B64, FS), entity=API.close)
    block.ret(path, path_view, path_memory, buffer, buffer_view, buffer_memory, fs, written)
    entry = graph.function(inputs, (*inputs[:7], B64))
    return program_store(entry, x86_64_linux_exec_target(), (*graph.objects.values(), *API.types)), entry


def pressure_program(rng: random.Random, declaration, machine_inputs: int, results: int = 1):
    """Many live values around one syscall (so operands sit in rsi, rdi, other callee-saved registers, and frame
    slots), then a sum of everything; ``machine_inputs`` bits<64> operands chosen among the live values."""
    graph = GraphBuilder()
    block = graph.block(B64, B64, FS)
    a, b, fs = block.params
    live = [a, b]
    for index in range(rng.randrange(6, 24)):
        x, y = rng.choice(live), rng.choice(live)
        live.append(block.op1(rng.choice((Operation.ADD_WRAP, Operation.MUL_WRAP, Operation.BIT_XOR)), (x, block.const(B64, index * 7919 + 3) if rng.random() < 0.3 else y), B64))
    operands = [rng.choice(live) for _ in range(machine_inputs)]
    outs = block.op(Operation.CALL_FOREIGN, (*operands, fs), (*(B64,) * results, FS), entity=declaration)
    total = outs[0] if results else block.const(B64, 0)
    for value in live:
        total = block.op1(Operation.ADD_WRAP, (total, value), B64)
    block.ret(total, outs[-1])
    entry = graph.function((B64, B64, FS), (B64, FS))
    return program_store(entry, x86_64_linux_exec_target(), (*graph.objects.values(), *API.types)), entry


def _outcome(reader, entry, target, backend):
    try:
        return compile_x86_64_views(reader, entry.cid, target, backend=backend)
    except XaxError as error:
        return error.diagnostic


@unittest.skipUnless(LINUX_X86_64, "UNAVAILABLE: the XAX backend program runs on Linux x86-64 only")
class SyscallLoweringTests(unittest.TestCase):
    target = x86_64_views_syscall_target()

    def assertSameOutcome(self, reader, entry, target=None):
        target = target or self.target
        expected = _outcome(reader, entry, target, "python")
        self.assertEqual(_outcome(reader, entry, target, "xax"), expected)
        return expected

    def test_copy_program_is_byte_identical_and_copies_a_file(self):
        reader, entry = copy_program()
        image = self.assertSameOutcome(reader, entry)
        directory = tempfile.mkdtemp()
        source = os.path.join(directory, "in.txt")
        with open(source, "wb") as handle:
            handle.write(b"hello from XAX syscalls\n")
        target = os.path.join(directory, "out.txt")
        out = os.open(target, os.O_WRONLY | os.O_CREAT, 0o600)
        path = ctypes.create_string_buffer(source.encode() + b"\0", 256)
        buffer = ctypes.create_string_buffer(4096)
        try:
            written = NativeViewsImage(image)(ctypes.addressof(path), ctypes.addressof(buffer), out)
        finally:
            os.close(out)
        self.assertEqual(written, 24)
        with open(target, "rb") as handle:
            self.assertEqual(handle.read(), b"hello from XAX syscalls\n")

    def test_templates_under_register_pressure(self):
        rng = random.Random(264)
        templates = [
            (39, None, 0), (1, None, 3), (1, ("$2", "$0", "$1"), 3), (9, (0, "$0", 3, 0x22, (1 << 64) - 1, 0), 1),
            (60, ("$1", "$0", 5, "$3", "$2", "$4"), 5), (2147483647, ("$0",), 1), (0, (1 << 32, "$1", "$0", (1 << 64) - (1 << 31)), 2),
        ]
        for number, arguments, inputs in templates:
            declaration = syscall(encode_syscall_name(number, arguments), (*(B64,) * inputs, FS), (B64, FS))
            for trial in range(6):
                with self.subTest(number=number, arguments=arguments, trial=trial):
                    self.assertEqual(type(self.assertSameOutcome(*pressure_program(rng, declaration, inputs))).__name__, "X86ViewsImage")
        # "$00" names operand 0 (``str.isdigit``): accepted by the bootstrap template decoder too.
        declaration = syscall(b"1:$00,$1", (B64, B64, FS), (B64, FS))
        self.assertEqual(type(self.assertSameOutcome(*pressure_program(rng, declaration, 2))).__name__, "X86ViewsImage")

    def test_every_rejection_is_the_bootstrap_diagnostic(self):
        rng = random.Random(4)
        cases = {
            "another ABI": (syscall(b"1", (B64, FS), (B64, FS), abi=b"sysv-x86_64-c"), 1, 1),
            "two machine results": (syscall(b"1", (B64, FS), (B64, B64, FS)), 1, 2),
            "a leading zero": (syscall(b"01", (B64, FS), (B64, FS)), 1, 1),
            "a number past 2^31": (syscall(b"2147483648", (B64, FS), (B64, FS)), 1, 1),
            "a repeated operand": (syscall(b"1:$0,$0", (B64, B64, FS), (B64, FS)), 2, 1),
            "an operand never named": (syscall(b"1:$0,5", (B64, B64, FS), (B64, FS)), 2, 1),
            "an operand out of range": (syscall(b"1:$0,$2", (B64, B64, FS), (B64, FS)), 2, 1),
            "an empty item": (syscall(b"1:$0,", (B64, FS), (B64, FS)), 1, 1),
            "an empty template": (syscall(b"1:", (FS,), (B64, FS)), 0, 1),
            "a bare dollar": (syscall(b"1:$", (B64, FS), (B64, FS)), 1, 1),
            "a signed literal": (syscall(b"1:+5,$0", (B64, FS), (B64, FS)), 1, 1),
            "a literal past 2^64": (syscall(b"1:18446744073709551616,$0", (B64, FS), (B64, FS)), 1, 1),
            "a literal with a leading zero": (syscall(b"1:05,$0", (B64, FS), (B64, FS)), 1, 1),
            "seven arguments": (syscall(b"1:$0,0,0,0,0,0,0", (B64, FS), (B64, FS)), 1, 1),
            "seven operands": (syscall(b"1", (*(B64,) * 7, FS), (B64, FS)), 7, 1),
            "a trailing character": (syscall(b"1:$0x", (B64, FS), (B64, FS)), 1, 1),
            "a second colon": (syscall(b"1:$0:2", (B64, FS), (B64, FS)), 1, 1),
            "a non-digit number": (syscall(b"x1", (B64, FS), (B64, FS)), 1, 1),
        }
        rules = set()
        for name, (declaration, inputs, results) in cases.items():
            with self.subTest(case=name):
                diagnostic = self.assertSameOutcome(*pressure_program(rng, declaration, inputs, results))
                self.assertEqual(type(diagnostic).__name__, "Diagnostic", name)
                rules.add(diagnostic.rule)
        self.assertEqual(rules, {"X86_64_VIEWS-SYSCALL"})

    def test_a_heap_contract_is_rejected(self):
        """``mmap`` with its allocator contract: the views profile has no heap ownership yet (S10b)."""
        graph = GraphBuilder()
        block = graph.block(B64, MEM)
        size, memory = block.params
        pointer, owner, memory = block.op(Operation.CALL_FOREIGN, (size, memory), (API.bytes_rw, API.heap_owner, MEM), entity=API.mmap_anonymous)
        block.ret(pointer, owner, memory)
        entry = graph.function((B64, MEM), (API.bytes_rw, API.heap_owner, MEM))
        reader = program_store(entry, x86_64_linux_exec_target(), (*graph.objects.values(), *API.types))
        self.assertEqual(self.assertSameOutcome(reader, entry).rule, "X86_64_VIEWS-SYSCALL")

    def test_the_v1_profile_rejects_syscalls(self):
        reader, entry = copy_program()
        diagnostic = self.assertSameOutcome(reader, entry, x86_64_views_target())
        self.assertEqual(diagnostic.rule, "X86_64_VIEWS-OP-TARGET-SUPPORTED")


if __name__ == "__main__":
    unittest.main()
