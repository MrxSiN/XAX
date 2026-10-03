"""ADR-127: deterministic C header import (OI-32) reproduces hand-built declarations and runs."""

from __future__ import annotations

import platform
import shutil
import sys
import unittest
from pathlib import Path

from xax_compiler import (
    AAPCS64_LINUX_C_ABI,
    FloatFormat,
    Operation,
    XaxError,
    bits_type,
    float_type,
    heap_view_type,
    x86_64_linux_dynamic_exec_target,
)
from xax_graph_builder import GraphBuilder, program_store

CLANG = shutil.which("clang")
LINUX_X86_64 = sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")
B8, B32, B64 = bits_type(8), bits_type(32), bits_type(64)
F32, F64 = float_type(FloatFormat.BINARY32), float_type(FloatFormat.BINARY64)
ZLIB = Path("/usr/include/zlib.h")
POSIX = ["-D_GNU_SOURCE"]


@unittest.skipUnless(CLANG and ZLIB.exists(), "requires clang and the zlib/libc development headers")
class CHeaderImportTests(unittest.TestCase):
    def test_imports_reproduce_hand_built_declarations(self):
        from xax_c_import import import_c_functions
        from xax_linux import c_function, linux_api

        api = linux_api()
        zlib = import_c_functions([ZLIB], b"libz.so.1", ["crc32"])
        # The declaration filestat (U1.3) uses, byte for byte: same CID, same program, same artifact.
        self.assertEqual(zlib["crc32"].cid, c_function(b"libz.so.1", b"crc32", (B64, api.bytes_read, B32, api.memory_effect), (B64, api.memory_effect)).cid)
        math = import_c_functions(["/usr/include/math.h"], b"libm.so.6", ["ldexp", "pow", "sqrtf"], overrides={"ldexp": "pure", "pow": "pure", "sqrtf": "pure"})
        for name, inputs, outputs in (("ldexp", (F64, B32), (F64,)), ("pow", (F64, F64), (F64,)), ("sqrtf", (F32,), (F32,))):
            self.assertEqual(math[name].cid, c_function(b"libm.so.6", name.encode(), inputs, outputs).cid, name)
        aarch64 = import_c_functions(["/usr/include/string.h"], b"libc.so.6", ["strlen"], abi=AAPCS64_LINUX_C_ABI)
        from xax_linux_aarch64 import c_function as aarch64_c_function, linux_aarch64_api

        a64 = linux_aarch64_api()
        self.assertEqual(aarch64["strlen"].cid, aarch64_c_function(b"libc.so.6", b"strlen", (a64.bytes_read, a64.memory_effect), (B64, a64.memory_effect)).cid)

    def test_refusals_are_explicit_and_import_is_deterministic(self):
        from xax_c_import import ImportRefused, import_c_functions

        headers = ["/usr/include/stdio.h", "/usr/include/stdlib.h", "/usr/include/search.h"]
        names = ["fdopen", "fputs", "fclose", "printf", "div", "qsort", "tsearch", "getenv"]
        first = import_c_functions(headers, b"libc.so.6", names, flags=POSIX)
        second = import_c_functions(headers, b"libc.so.6", names, flags=POSIX)
        self.assertEqual(first.report, second.report)
        self.assertEqual(first.report["refused"], {
            "printf": "variadic (typed argument packs: OI-40)",
            "div": "by-value type 'struct div_t' (structs, unions, arrays, long double: OI-40)",
        })
        self.assertEqual(sorted(first.report["imported"]), ["fclose", "fdopen", "fputs", "getenv", "qsort", "tsearch"])
        with self.assertRaises(ImportRefused):
            import_c_functions(headers, b"libc.so.6", ["no_such_function"], flags=POSIX)
        callbacks = import_c_functions(headers, b"libc.so.6", ["qsort"], abi=AAPCS64_LINUX_C_ABI, flags=POSIX)
        self.assertIn("ADR-102", callbacks.report["refused"]["qsort"])
        with self.assertRaises(ValueError):
            import_c_functions(headers, b"libc.so.6", ["fclose"], overrides={"fclose": "nothrow"}, flags=POSIX)

    def _stdio_program(self, *, dereference_handle: bool = False):
        from xax_c_import import import_c_functions
        from xax_linux import linux_api

        api = linux_api()
        stdio = import_c_functions(["/usr/include/stdio.h"], b"libc.so.6", ["fdopen", "fputs", "fclose"], flags=POSIX)
        graph = GraphBuilder()
        block = graph.block(api.process_effect, api.filesystem_effect, api.memory_effect)
        process, fs, memory = block.params
        raw, owner, memory = block.op(Operation.CALL_FOREIGN, (block.const(B64, 4096), memory), (api.bytes_rw, api.heap_owner, api.memory_effect), entity=api.mmap_anonymous)
        pointer, view, memory = block.op(Operation.HEAP_VIEW, (raw, owner, memory), (api.bytes_rw, heap_view_type(4096), api.memory_effect), attributes=(4096, 1))
        for offset, data in ((0, b"w\0"), (16, b"hello from imported stdio\n\0")):
            for index, byte in enumerate(data):
                at = pointer if offset + index == 0 else block.op1(Operation.ADDRESS_OFFSET, (pointer,), api.bytes_rw, attributes=(offset + index,))
                memory = block.op1(Operation.STORE_BITS_LE, (at, block.const(B8, byte), memory), api.memory_effect, attributes=(1, 1))
        mode = block.op1(Operation.POINTER_CAST, (pointer,), api.bytes_read)
        message = block.op1(Operation.POINTER_CAST, (block.op1(Operation.ADDRESS_OFFSET, (pointer,), api.bytes_rw, attributes=(16,)),), api.bytes_read)
        fdopen, fputs, fclose = (stdio.function(name) for name in ("fdopen", "fputs", "fclose"))
        handle, memory = block.op(Operation.CALL_FOREIGN, (block.const(B32, 1), mode, memory), fdopen.outputs, entity=fdopen.declaration)
        if dereference_handle:  # FILE * is an opaque handle: no XAX memory operation accepts it
            _byte, memory = block.op(Operation.LOAD_BITS_LE, (handle, memory), (B8, api.memory_effect), attributes=(1, 1))
        _result, memory = block.op(Operation.CALL_FOREIGN, (message, handle, memory), fputs.outputs, entity=fputs.declaration)
        _result, memory = block.op(Operation.CALL_FOREIGN, (handle, memory), fclose.outputs, entity=fclose.declaration)
        _result, memory = block.op(Operation.CALL_FOREIGN, (pointer, view, memory), (B64, api.memory_effect), entity=api.munmap_view(api.bytes_rw, 4096))
        zero = block.const(B32, 0)
        process = block.op1(Operation.CALL_FOREIGN, (zero, process), api.process_effect, entity=api.exit_group)
        block.ret(zero, process, fs, memory)
        parameters = (api.process_effect, api.filesystem_effect, api.memory_effect)
        entry = graph.function(parameters, (B32, *parameters))
        target = x86_64_linux_dynamic_exec_target()
        return program_store(entry, target, (*api.types, *graph.objects.values(), *stdio.objects)), entry, target

    def test_opaque_handles_reject_memory_operations(self):
        with self.assertRaises(XaxError):
            self._stdio_program(dereference_handle=True)

    @unittest.skipUnless(LINUX_X86_64, "requires a Linux x86-64 host with glibc")
    def test_imported_stdio_executes(self):
        from xax_linux import compile_linux_executable, run_linux_executable

        reader, entry, target = self._stdio_program()
        executable = compile_linux_executable(reader, entry.cid, target.cid)
        self.assertEqual(executable.needed, (b"libc.so.6",))
        completed = run_linux_executable(executable.data)
        self.assertEqual((completed.returncode, completed.stdout), (0, b"hello from imported stdio\n"))


if __name__ == "__main__":
    unittest.main()
