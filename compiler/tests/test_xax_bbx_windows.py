"""The same BBX graph under the PE loader and Win64 ABI, with native buffers."""
import ctypes
import platform
import sys
import tempfile
import unittest
from pathlib import Path

from xax_bbx import construct_bbx
from xax_compiler import Operation, Permission, bits_type, memory_effect_type, pointer_type, stack_owner_type, x86_64_windows_pe_target
from xax_graph_builder import GraphBuilder, program_store
from xax_pe import emit_pe_dll
from xax_x86_64 import compile_native_bound_target, run_native, run_native_isolated
from test_xax_bbx import record, reference

WINDOWS = sys.platform == "win32" and platform.machine().lower() in ("amd64", "x86_64")


def windows_bbx(record):
    imported = construct_bbx(record, input_extent=16, output_extent=16, target_object=x86_64_windows_pe_target())
    image = compile_native_bound_target(imported.reader, imported.function.cid, imported.target)
    return imported, emit_pe_dll(image, b"bbx.dll", ((b"run_decision", imported.function.cid),))


def run_dll(dll, data, capacity, length=None):
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory, "bbx.dll")
        path.write_bytes(dll)
        library = ctypes.WinDLL(str(path))
        try:
            function = library.run_decision
            function.argtypes = (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32)
            function.restype = ctypes.c_uint64
            inp = ctypes.create_string_buffer(data + b"\xa5" * (16 - len(data)))
            output = ctypes.create_string_buffer(b"\xa5" * 16)
            tape = ctypes.create_string_buffer(b"\xa5" * 65536)
            packed = function(inp, output, tape, len(data) if length is None else length, capacity)
            status, count = packed & 0xffffffff, packed >> 32
            assert count <= min(capacity, 16)
            assert output.raw[count:16] == b"\xa5" * (16 - count)
            assert inp.raw[:16] == data + b"\xa5" * (16 - len(data))
            return status, output.raw[:count], tape.raw[:65536]
        finally:
            ctypes.windll.kernel32.FreeLibrary(ctypes.c_void_p(library._handle))


@unittest.skipUnless(WINDOWS, "requires native Windows x86-64")
class WindowsBBXTests(unittest.TestCase):
    def test_native_pe_semantics(self):
        decision = b",>+<[[-]>[-]<]>.[-]"
        for code, data, capacity in ((b"", b"", 16), (b"-.+.,.,.", b"\0", 16),
            (b"++[>++[>+<-]<-]>>.", b"", 16), (b"<", b"", 16), (b"+[>+]", b"", 16),
            (b",.,.,.", b"\0\xff", 16), (b"..", b"", 1), (decision, b"\0", 16),
            (decision, b"\1", 16), (decision, b"\xff", 16), (decision, b"", 16), (decision, b"\0", 0)):
            with self.subTest(code=code, data=data, capacity=capacity):
                imported, dll = windows_bbx(record(code))
                actual = run_dll(dll, data, capacity)
                self.assertEqual(actual[:2], reference(code, data, capacity))
                if not code:
                    self.assertEqual(actual[2], bytes(65536))

    def test_invalid_logical_lengths_do_not_touch_tape(self):
        _, dll = windows_bbx(record(b"."))
        for length, capacity in ((17, 16), (0, 17), (0xffffffff, 16), (0, 0xffffffff)):
            with self.subTest(length=length, capacity=capacity):
                status, output, tape = run_dll(dll, b"", capacity, length)
                self.assertEqual((status, output), (3, b""))
                self.assertEqual(tape, b"\xa5" * 65536)

    def test_narrow_arithmetic_wraps_on_frame_fallback(self):
        for width in (1, 2, 7, 8, 16, 31):
            typ = bits_type(width)
            maximum = (1 << width) - 1
            for operation, left, right, expected in (
                (Operation.ADD_WRAP, maximum, 1, 0), (Operation.SUB_WRAP, 0, 1, maximum),
                (Operation.MUL_WRAP, maximum, maximum, 1), (Operation.BIT_OR, 0, maximum, maximum),
                (Operation.BIT_AND, maximum, 0, 0), (Operation.BIT_XOR, maximum, maximum, 0)):
                with self.subTest(width=width, operation=operation):
                    graph = GraphBuilder()
                    block = graph.block(typ, typ)
                    result = block.op1(operation, block.params, typ)
                    block.ret(result)
                    function = graph.function((typ, typ), (typ,))
                    target = x86_64_windows_pe_target()
                    reader = program_store(function, target, tuple(graph.objects.values()))
                    image = compile_native_bound_target(reader, function.cid, target)
                    self.assertEqual(run_native(image, (left, right)), (expected,))

    def test_large_frame_probes_windows_guard_pages(self):
        b32, owner, memory = bits_type(32), stack_owner_type(), memory_effect_type()
        pointer = pointer_type(b32, Permission.READ_WRITE, 4, space=1)
        graph = GraphBuilder()
        block = graph.block()
        ptr, token, effect = block.op(Operation.STACK_ALLOC, (), (pointer, owner, memory), attributes=(131072, 16))
        effect = block.op1(Operation.STORE_BITS_LE, (ptr, block.const(b32, 42), effect), memory, attributes=(4, 4))
        value, effect = block.op(Operation.LOAD_BITS_LE, (ptr, effect), (b32, memory), attributes=(4, 4))
        block.op(Operation.STACK_END, (token, effect), ())
        block.ret(value)
        function = graph.function((), (b32,))
        target = x86_64_windows_pe_target()
        reader = program_store(function, target, tuple(graph.objects.values()))
        image = compile_native_bound_target(reader, function.cid, target)
        # A fresh process has not already committed pages for a previous large call.
        self.assertEqual(run_native_isolated(image, ()), (42,))


if __name__ == "__main__":
    unittest.main()
