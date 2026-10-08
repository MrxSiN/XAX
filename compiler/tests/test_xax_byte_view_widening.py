"""Byte-view widening (ADR-231): a checked access on a ``bits<8>`` view reads or writes 1, 2, 4, or 8 bytes as one
little-endian ``bits<8*size>`` integer.

Verification (bootstrap and the XAX facts engine, exact diagnostics), the reference executor, and every backend
with an executor in this repository: x86-64 Linux (native), AArch64 (Unicorn), JVM, and wasm run the same values;
RISC-V and SPIR-V reject with their documented diagnostics.
"""

from __future__ import annotations

import contextlib
import platform
import random
import shutil
import signal
import sys
import unittest
from pathlib import Path

from xax_compiler import (
    CHECKED_BYTE_VIEW_WIDTHS, FloatFormat, Operation, Permission, XaxError, XaxTrap, bits_type, execute, float_type, heap_view_type, link_type,
    memory_effect_type, pointer_type, resource_type, x86_64_linux_exec_target,
)
from xax_graph_builder import GraphBuilder, program_store

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

LINUX_X86_64 = sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")
B8, B16, B32, B64 = (bits_type(width) for width in (8, 16, 32, 64))
F32 = float_type(FloatFormat.BINARY32)
MEM, OWNER = memory_effect_type(), resource_type(1, 1)
EXTENT = 32
BYTES = bytes(((k * 37 + 11) & 255) for k in range(EXTENT))
VALUE = 0x8877665544332211


def _mask(size: int) -> int:
    return (1 << 8 * size) - 1


@contextlib.contextmanager
def _engine(native):
    """The XAX typing/facts image (``native``) or the bootstrap passes only (None) for the next verifications."""
    import xax_compiler

    saved = (xax_compiler._NATIVE_TYPING, xax_compiler._TYPING_ATTEMPTED)
    xax_compiler._NATIVE_TYPING, xax_compiler._TYPING_ATTEMPTED = native, True
    xax_compiler._PARSED_GRAPHS.clear()
    try:
        yield
    finally:
        xax_compiler._NATIVE_TYPING, xax_compiler._TYPING_ATTEMPTED = saved
        xax_compiler._PARSED_GRAPHS.clear()


def _stack_callee(size: int, *, store: bool = False, element=B8, value_type=None, alignment: int = 1, initialized: int = EXTENT,
                  offset=None):
    """``(offset: bits<32>[, k: bits<32>]) -> T``: a 32-byte stack view of ``element``, its first ``initialized`` bytes
    written by ordinary stores, then one checked access of ``size`` bytes at ``offset``.  A load returns the value; a
    store returns the byte at ``offset + k`` read back with a 1-byte checked load."""
    graph = GraphBuilder()
    pointer = pointer_type(element, Permission.READ_WRITE, 1)
    value_type = value_type or bits_type(8 * size)
    graph.track(pointer, OWNER, MEM, B8, B32, value_type, element)
    block = graph.block(B32, B32) if store else graph.block(B32)
    index = block.params[0] if offset is None else block.const(B32, offset)
    p, owner, memory = block.op(Operation.STACK_ALLOC, (), (pointer, OWNER, MEM), attributes=(EXTENT, 1))
    if element == B8:  # other elements are rejected before initialization matters
        for k in range(initialized):
            at = p if k == 0 else block.op1(Operation.ADDRESS_OFFSET, (p,), pointer, attributes=(k,))
            memory = block.op1(Operation.STORE_BITS_LE, (at, block.const(B8, BYTES[k]), memory), MEM, attributes=(1, 1))
    if store:
        width = int.from_bytes(value_type.body[1:2], "little")  # a bits<N> value type, N < 128
        stored = block.const(value_type, VALUE & ((1 << width) - 1))
        memory = block.op1(Operation.CHECKED_STORE_BITS_LE, (p, index, stored, memory), MEM, attributes=(size, alignment))
        at = block.op1(Operation.ADD_WRAP, (index, block.params[1]), B32)
        out, memory = block.op(Operation.CHECKED_LOAD_BITS_LE, (p, at, memory), (B8, MEM), attributes=(1, 1))
    else:
        out, memory = block.op(Operation.CHECKED_LOAD_BITS_LE, (p, index, memory), (value_type, MEM), attributes=(size, alignment))
    block.op(Operation.STACK_END, (owner, memory), ())
    block.ret(out)
    function = graph.function((B32, B32) if store else (B32,), (B8 if store else value_type,))
    return function, tuple(graph.objects.values())


def _expected(size: int, offset: int, *, store: bool = False, k: int = 0):
    if offset + size > EXTENT:
        return None  # traps
    if store:
        data = bytearray(BYTES)
        data[offset:offset + size] = (VALUE & _mask(size)).to_bytes(size, "little")
        return data[offset + k]
    return int.from_bytes(BYTES[offset:offset + size], "little")


def _verdict(function, objects, target=None, native=False):
    """None (verified) or ``(code, rule, expected, actual)``."""
    from xax_selfhost_typing import NativeTyping, native_typing_usable

    image = NativeTyping() if native and native_typing_usable() else None
    with _engine(image):
        try:
            program_store(function, target or x86_64_linux_exec_target(), objects)
        except XaxError as error:
            d = error.diagnostic
            return d.code, d.rule, d.expected, d.actual
    return None


class ByteViewVerifierTests(unittest.TestCase):
    def test_wide_accesses_on_a_byte_view_verify(self):
        for size in CHECKED_BYTE_VIEW_WIDTHS:
            for store in (False, True):
                for offset in (0, 1, EXTENT - size):
                    function, objects = _stack_callee(size, store=store, offset=offset)
                    self.assertIsNone(_verdict(function, objects), (size, store, offset))

    def test_rejections_keep_their_codes_and_rules(self):
        cases = [
            (dict(size=3), ("XAX.MEMORY.ACCESS_SIZE", "MEMORY-ACCESS-SIZE", [1, 2, 4, 8], 3)),
            (dict(size=16, value_type=B64), ("XAX.MEMORY.ACCESS_SIZE", "MEMORY-ACCESS-SIZE", [1, 2, 4, 8], 16)),
            (dict(size=8, value_type=B32), ("XAX.MEMORY.VALUE_TYPE", "MEMORY-CHECKED-LOAD-TYPE", B64.cid.hex(), B32.cid.hex())),
            (dict(size=2, store=True, value_type=B32), ("XAX.MEMORY.VALUE_TYPE", "MEMORY-CHECKED-STORE-TYPE", B16.cid.hex(), B32.cid.hex())),
            (dict(size=4, element=B16, value_type=B32), ("XAX.MEMORY.ACCESS_SIZE", "MEMORY-ACCESS-SIZE", 2, 4)),
            (dict(size=8, element=F32, value_type=B64), ("XAX.MEMORY.ACCESS_SIZE", "MEMORY-ACCESS-SIZE", 4, 8)),
            (dict(size=2, element=pointer_type(B8, Permission.READ, 1), value_type=B16), ("XAX.MEMORY.ACCESS_SIZE", "MEMORY-POINTER-ELEMENT-SIZE", [4, 8], 2)),
            (dict(size=8, alignment=8), ("XAX.MEMORY.CHECKED_ALIGNMENT", "MEMORY-CHECKED-ALIGNMENT-BOOTSTRAP", 1, 8)),
            (dict(size=4, initialized=EXTENT - 1), ("XAX.MEMORY.UNINITIALIZED", "MEMORY-CHECKED-LOAD-INITIALIZED-VIEW", [0, EXTENT], ((0, EXTENT - 1),))),
        ]
        for keywords, expected in cases:
            function, objects = _stack_callee(offset=0, **keywords)
            for native in (False, True):
                with self.subTest(case=keywords, native=native):
                    self.assertEqual(_verdict(function, objects, native=native), expected)

    def test_link_element_keeps_its_size(self):
        # A link field of a record (links live only in records): a 4-byte checked access is still a size error.
        from xax_compiler import tuple_type

        record = tuple_type((link_type(), B32))
        graph = GraphBuilder()
        whole = pointer_type(record, Permission.READ_WRITE, 8)
        field = pointer_type(link_type(), Permission.READ_WRITE, 8)
        graph.track(whole, field, record, OWNER, MEM, B32, link_type())
        block = graph.block(B32)
        p, owner, memory = block.op(Operation.STACK_ALLOC, (), (whole, OWNER, MEM), attributes=(32, 8))
        link = block.op1(Operation.ADDRESS_OFFSET, (p,), field, attributes=(0,))
        out, memory = block.op(Operation.CHECKED_LOAD_BITS_LE, (link, block.params[0], memory), (B32, MEM), attributes=(4, 1))
        block.op(Operation.STACK_END, (owner, memory), ())
        block.ret(out)
        function = graph.function((B32,), (B32,))
        for native in (False, True):
            self.assertEqual(_verdict(function, tuple(graph.objects.values()), native=native), ("XAX.MEMORY.ACCESS_SIZE", "MEMORY-ACCESS-SIZE", 8, 4))

    def test_size_zero_is_rejected(self):
        # Built directly: the helper derives the value type from the size.
        graph = GraphBuilder()
        pointer = pointer_type(B8, Permission.READ_WRITE, 1)
        graph.track(pointer, OWNER, MEM, B8, B32)
        block = graph.block(B32)
        p, owner, memory = block.op(Operation.STACK_ALLOC, (), (pointer, OWNER, MEM), attributes=(EXTENT, 1))
        out, memory = block.op(Operation.CHECKED_LOAD_BITS_LE, (p, block.params[0], memory), (B8, MEM), attributes=(0, 1))
        block.op(Operation.STACK_END, (owner, memory), ())
        block.ret(out)
        function = graph.function((B32,), (B8,))
        for native in (False, True):
            self.assertEqual(_verdict(function, tuple(graph.objects.values()), native=native)[:2], ("XAX.MEMORY.ACCESS_SIZE", "MEMORY-ACCESS-SIZE"))


class ByteViewExecutionTests(unittest.TestCase):
    def test_reference_executor(self):
        for size in CHECKED_BYTE_VIEW_WIDTHS:
            for store in (False, True):
                function, objects = _stack_callee(size, store=store)
                reader = program_store(function, x86_64_linux_exec_target(), objects)
                for offset in (0, 1, 3, EXTENT - size, EXTENT - size + 1):
                    for k in range(size) if store else (0,):
                        arguments = (offset, k) if store else (offset,)
                        expected = _expected(size, offset, store=store, k=k)
                        if expected is None:
                            with self.assertRaises(XaxTrap):
                                execute(reader, function.cid, arguments)
                        else:
                            self.assertEqual(execute(reader, function.cid, arguments), (expected,), (size, store, arguments))

    @unittest.skipUnless(LINUX_X86_64, "requires a Linux x86-64 host")
    def test_linux_x86_64_matches_the_reference_executor(self):
        from xax_linux import compile_linux_executable, linux_api, run_linux_executable

        rng = random.Random(231)
        for size in CHECKED_BYTE_VIEW_WIDTHS:
            for store in (False, True):
                callee, objects = _stack_callee(size, store=store)
                offsets = sorted({0, 1, EXTENT - size, EXTENT - size + 1, rng.randrange(0, EXTENT - size + 1)})
                for offset in offsets:
                    k = rng.randrange(size) if store else 0
                    api = linux_api()
                    graph = GraphBuilder()
                    block = graph.block(api.process_effect, api.filesystem_effect)
                    process, fs = block.params
                    arguments = (block.const(B32, offset), block.const(B32, k)) if store else (block.const(B32, offset),)
                    result = block.op1(Operation.CALL_DIRECT, arguments, B8 if store else bits_type(8 * size), entity=callee)
                    low = result if store or size == 4 else block.op1(Operation.INT_TRUNCATE if size == 8 else Operation.INT_ZERO_EXTEND, (result,), B32)
                    if store:
                        low = block.op1(Operation.INT_ZERO_EXTEND, (result,), B32)
                    status = block.op1(Operation.BIT_AND, (low, block.const(B32, 0xFF)), B32)
                    process = block.op1(Operation.CALL_FOREIGN, (status, process), api.process_effect, entity=api.exit_group)
                    block.ret(status, process, fs)
                    entry = graph.function((api.process_effect, api.filesystem_effect), (B32, api.process_effect, api.filesystem_effect))
                    target = x86_64_linux_exec_target()
                    reader = program_store(entry, target, (*objects, *graph.objects.values(), *api.types))
                    completed = run_linux_executable(compile_linux_executable(reader, entry.cid, target.cid).data)
                    expected = _expected(size, offset, store=store, k=k)
                    with self.subTest(size=size, store=store, offset=offset):
                        self.assertEqual(completed.returncode, -signal.SIGILL if expected is None else expected & 0xFF)

    def test_aarch64_under_unicorn(self):
        try:
            import unicorn
        except ImportError:
            self.skipTest("requires unicorn")
        from benchmarks.android_elf_emulator import run_export
        from xax_android import AndroidExport, compile_android_shared
        from xax_compiler import android_arm64_shared_general_target

        target = android_arm64_shared_general_target()
        for size in CHECKED_BYTE_VIEW_WIDTHS:
            for store in (False, True):
                function, objects = _stack_callee(size, store=store)
                reader = program_store(function, target, objects)
                elf = compile_android_shared(reader, (AndroidExport(b"probe", function.cid),), target_object=target).data
                for offset in (0, 1, 3, EXTENT - size, EXTENT - size + 1):
                    for k in range(size) if store else (0,):
                        expected = _expected(size, offset, store=store, k=k)
                        try:
                            got, _trace = run_export(elf, b"probe", (offset, k) if store else (offset,), {})
                            got &= _mask(1 if store else size)
                        except unicorn.UcError:
                            got = None  # brk: the checked-access trap
                        self.assertEqual(got, expected, (size, store, offset, k))

    @unittest.skipUnless(shutil.which("node"), "requires node")
    def test_wasm(self):
        from xax_compiler import oi06_wasm32_target
        from xax_wasm import compile_wasm_bound_target, run_wasm_isolated

        target = oi06_wasm32_target()
        for size in CHECKED_BYTE_VIEW_WIDTHS:
            for store in (False, True):
                function, objects = _stack_callee(size, store=store)
                image = compile_wasm_bound_target(program_store(function, target, objects), function.cid, target)
                for offset in (0, 1, EXTENT - size, EXTENT - size + 1):
                    k = size - 1 if store else 0
                    expected = _expected(size, offset, store=store, k=k)
                    arguments = (offset, k) if store else (offset,)
                    if expected is None:
                        with self.assertRaises(Exception):
                            run_wasm_isolated(image, arguments)
                    else:
                        self.assertEqual(run_wasm_isolated(image, arguments)[0] & _mask(1 if store else size), expected, (size, store, offset))

    @unittest.skipUnless(shutil.which("java") and shutil.which("javac"), "requires a JDK")
    def test_jvm(self):
        from xax_compiler import jvm_classfile_memory_target
        from xax_jvm import compile_jvm_bound_target, jvm_memory_api, run_jvm_calls
        from xax_structured import Proc

        api = jvm_memory_api()
        memory_effect, view = api.memory_effect, heap_view_type(EXTENT)
        for size in CHECKED_BYTE_VIEW_WIDTHS:
            for store in (False, True):
                wide = bits_type(8 * size)
                proc = Proc((("i", B32), ("k", B32), ("m", memory_effect)) if store else (("i", B32), ("m", memory_effect)))
                raw, owner, effect = proc.op(Operation.CALL_FOREIGN, (proc.const(EXTENT, B64), proc.drop("m")), (api.bytes_rw, api.heap_owner, memory_effect), entity=api.mmap_anonymous)
                p, token, memory = proc.op(Operation.HEAP_VIEW, (raw, owner, effect), (api.bytes_rw, view, memory_effect), attributes=(EXTENT, 1))
                for k in range(EXTENT):
                    memory = proc.op1(Operation.CHECKED_STORE_BITS_LE, (p, proc.const(k), proc.const(BYTES[k], B8), memory), memory_effect, attributes=(1, 1))
                if store:
                    memory = proc.op1(Operation.CHECKED_STORE_BITS_LE, (p, proc["i"], proc.const(VALUE & _mask(size), wide), memory), memory_effect, attributes=(size, 1))
                    out, memory = proc.op(Operation.CHECKED_LOAD_BITS_LE, (p, proc.bin(Operation.ADD_WRAP, proc["i"], proc["k"], B32), memory), (B8, memory_effect), attributes=(1, 1))
                else:
                    out, memory = proc.op(Operation.CHECKED_LOAD_BITS_LE, (p, proc["i"], memory), (wide, memory_effect), attributes=(size, 1))
                _status, memory = proc.op(Operation.CALL_FOREIGN, (p, token, memory), (B64, memory_effect), entity=api.munmap_view(api.bytes_rw, EXTENT))
                proc.ret(out, memory)
                function = proc.function((B8 if store else wide, memory_effect))
                target = jvm_classfile_memory_target()
                reader = program_store(function, target, (*api.types, *proc.graph.objects.values(), B8, B32, B64, wide, view))
                image = compile_jvm_bound_target(reader, function.cid, target)
                calls, expected = [], []
                for offset in (0, 1, 3, EXTENT - size, EXTENT - size + 1):
                    for k in range(size) if store else (0,):
                        calls.append((offset, k) if store else (offset,))
                        value = _expected(size, offset, store=store, k=k)
                        expected.append("trap java.lang.Error" if value is None else value)
                self.assertEqual(run_jvm_calls(image, calls, result_width=8 if store else 8 * size), tuple(expected), (size, store))


def _views_program(size, target, *, element=B8, store=False):
    view = heap_view_type(64, initialized=True)
    pointer = pointer_type(element, Permission.READ_WRITE, 1, space=2)
    wide = bits_type(8 * size)
    graph = GraphBuilder()
    graph.track(view, pointer, wide, B8, B32, MEM)
    block = graph.block(B32, pointer, view, MEM)
    offset, p, token, memory = block.params
    if store:
        memory = block.op1(Operation.CHECKED_STORE_BITS_LE, (p, offset, block.const(wide, 5), memory), MEM, attributes=(size, 1))
        result = block.const(wide, 0)
    else:
        result, memory = block.op(Operation.CHECKED_LOAD_BITS_LE, (p, offset, memory), (wide, MEM), attributes=(size, 1))
    block.ret(result, p, token, memory)
    function = graph.function((B32, pointer, view, MEM), (wide, pointer, view, MEM))
    return program_store(function, target, tuple(graph.objects.values())), function


@unittest.skipUnless(LINUX_X86_64, "the XAX backend programs run natively on Linux x86-64")
class ViewsBackendTests(unittest.TestCase):
    """The views profile: x86-64 lowers widened accesses; RISC-V rejects them (a possibly misaligned ``lh/lw/ld``).
    The XAX backend programs decide exactly what the bootstrap generators decide."""

    def _compiled(self, compile_):
        try:
            return "ok", compile_().code
        except XaxError as error:
            d = error.diagnostic
            return d.code, d.rule, d.expected, d.actual

    def test_riscv64_rejects_and_x86_64_lowers(self):
        from xax_compiler import riscv64_views_target, x86_64_views_target
        from xax_riscv64 import compile_riscv64_bound_target
        from xax_selfhost_views_backend import BYTE_VIEW_WIDTH_EXPECTED
        from xax_x86_64_views import compile_x86_64_views

        for size in CHECKED_BYTE_VIEW_WIDTHS:
            for store in (False, True):
                for element in (B8, bits_type(8 * size)):
                    reader, function = _views_program(size, riscv64_views_target(), element=element, store=store)
                    riscv = [self._compiled(lambda b=b: compile_riscv64_bound_target(reader, function.cid, riscv64_views_target(), backend=b))
                             for b in ("python", "xax")]
                    reader, function = _views_program(size, x86_64_views_target(), element=element, store=store)
                    x86 = [self._compiled(lambda b=b: compile_x86_64_views(reader, function.cid, x86_64_views_target(), backend=b))
                           for b in ("python", "xax")]
                    with self.subTest(size=size, store=store, byte_view=element == B8):
                        self.assertEqual(riscv[0], riscv[1])
                        self.assertEqual(x86[0], x86[1])
                        self.assertEqual(x86[0][0], "ok")
                        if element == B8 and size > 1:
                            self.assertEqual(riscv[0], ("XAX.RISCV64.UNSUPPORTED_OPERATION", "RISCV64-CHECKED-BYTE-VIEW-WIDTH", BYTE_VIEW_WIDTH_EXPECTED, size))
                        else:
                            self.assertEqual(riscv[0][0], "ok")


class SpirvTests(unittest.TestCase):
    def test_kernels_take_word_views_only(self):
        from xax_compiler import spirv_vulkan_compute_target
        from xax_spirv import compile_spirv_kernel

        target = spirv_vulkan_compute_target()
        triple = (pointer_type(B8, Permission.READ_WRITE, 1, space=2), heap_view_type(64), MEM)
        graph = GraphBuilder()
        graph.track(B8, B32, *triple)
        block = graph.block(B32, *triple)
        invocation, p, token, memory = block.params
        memory = block.op1(Operation.CHECKED_STORE_BITS_LE, (p, block.const(B32, 0), invocation, memory), MEM, attributes=(4, 1))
        block.ret(p, token, memory)
        kernel = graph.function((B32, *triple), triple)
        reader = program_store(kernel, target, tuple(graph.objects.values()))
        with self.assertRaises(XaxError) as caught:
            compile_spirv_kernel(reader, kernel.cid, target.cid)
        self.assertEqual(caught.exception.diagnostic.rule, "SPIRV-KERNEL-ENTRY-CONTRACT")


@unittest.skipUnless(LINUX_X86_64, "requires a Linux x86-64 host")
class FactsEngineTests(unittest.TestCase):
    """The S8c-style differential: random byte-view programs and mutations verify or reject identically with and
    without the XAX facts engine, and the engine decides them (accepts, or rejects with the record) itself."""

    def test_random_byte_view_programs(self):
        import xax_selfhost_typing as typing_module

        native = typing_module.NativeTyping()
        accepted, decided = [], []
        facts, rejection = typing_module.NativeTyping.facts, typing_module.NativeTyping.memory_rejection

        def counting(self_, values):
            result = facts(self_, values)
            accepted.append(result[0])
            return result

        def deciding(self_, *arguments):
            result = rejection(self_, *arguments)
            decided.append(result is not None)
            return result

        typing_module.NativeTyping.facts, typing_module.NativeTyping.memory_rejection = counting, deciding
        rng = random.Random(20261008)
        engine_accepted = engine_rejected = rejections = 0
        try:
            for _ in range(120):
                size = rng.choice((1, 2, 4, 8))
                mutation = rng.choice((None, None, None, "size", "type", "alignment", "uninitialized"))
                keywords = dict(size=size, store=rng.random() < 0.4, offset=rng.randrange(0, EXTENT - size + 1))
                if mutation == "size":
                    keywords.update(size=rng.choice((3, 5, 16)), value_type=bits_type(8 * size))
                elif mutation == "type":
                    keywords.update(value_type=rng.choice([t for t in (B8, B16, B32, B64) if t != bits_type(8 * size)]))
                elif mutation == "alignment":
                    keywords.update(alignment=rng.choice((2, 4, 8)))
                elif mutation == "uninitialized":
                    keywords.update(initialized=rng.randrange(0, EXTENT), store=False)
                function, objects = _stack_callee(**keywords)
                baseline = _verdict(function, objects, native=False)
                accepted.clear()
                decided.clear()
                with _engine(native):
                    try:
                        program_store(function, x86_64_linux_exec_target(), objects)
                        outcome = None
                    except XaxError as error:
                        d = error.diagnostic
                        outcome = d.code, d.rule, d.expected, d.actual
                self.assertEqual(outcome, baseline, keywords)
                rejections += baseline is not None
                engine_accepted += baseline is None and any(accepted)
                engine_rejected += baseline is not None and any(decided)
        finally:
            typing_module.NativeTyping.facts, typing_module.NativeTyping.memory_rejection = facts, rejection
        self.assertGreater(engine_accepted, 20)
        self.assertEqual(engine_rejected, rejections)  # every rejection decided by the engine, none left to the bootstrap


class HostContractTests(unittest.TestCase):
    def test_contract_advertises_byte_view_widths(self):
        import xax_contract

        self.assertGreaterEqual(xax_contract.HOST_CONTRACT_MINOR, 2)
        self.assertEqual(xax_contract.FORMATS["checked_byte_view_widths"], [1, 2, 4, 8])


if __name__ == "__main__":
    unittest.main()
