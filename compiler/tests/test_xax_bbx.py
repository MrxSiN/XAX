"""BBX record rejection, verified construction and AArch64 instruction simulation.

Unicorn is an instruction emulator, not Android/Bionic/ART or an app test.
The mapped buffers satisfy the importer's borrowed-view caller preconditions.
"""
import random
import unittest
from importlib.util import find_spec

from xax_bbx import construct_bbx, decode_bbx
from xax_aarch64 import compile_aarch64_bundle_bound_target
from xax_android import AndroidExport, compile_android_shared, inspect_android_elf
from xax_compiler import verify_store


def record(code):
    return b"BBX\x01\0" + len(code).to_bytes(2, "little") + code


def reference(code, data=b"", capacity=16):
    tape = bytearray(65536)
    pairs, stack = {}, []
    for n, c in enumerate(code):
        if c == 91:
            stack.append(n)
        elif c == 93:
            a = stack.pop()
            pairs[a], pairs[n] = n, a
    p = pc = ip = 0
    out = bytearray()
    while pc < len(code):
        c = code[pc]
        if c in (62, 60):
            p += 1 if c == 62 else -1
            if not 0 <= p < 65536:
                return 1, bytes(out)
        elif c in (43, 45):
            tape[p] = (tape[p] + (1 if c == 43 else -1)) & 255
        elif c == 44:
            tape[p] = data[ip] if ip < len(data) else 0
            if ip < len(data):
                ip += 1
        elif c == 46:
            if len(out) == capacity:
                return 2, bytes(out)
            out.append(tape[p])
        elif c == 91 and tape[p] == 0 or c == 93 and tape[p] != 0:
            pc = pairs[pc]
        pc += 1
    return 0, bytes(out)


def emulate(imported, data=b"", capacity=16, *, length=None):
    from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM
    from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X30, UC_ARM64_REG_SP, UC_ARM64_REG_PC
    bundle = compile_aarch64_bundle_bound_target(imported.reader, (imported.function.cid,), imported.target)
    assert not bundle.foreign_calls
    cpu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    code, stop, stack, inp, out, tape = 0x100000, 0x300000, 0x400000, 0x600000, 0x700000, 0x800000
    cpu.mem_map(code, (len(bundle.code) + 4095) & ~4095)
    cpu.mem_write(code, bundle.code)
    cpu.mem_map(stop, 4096)
    cpu.mem_map(stack, 1 << 20)
    for address in (inp, out, tape):
        cpu.mem_map(address, 65536)
        cpu.mem_write(address, b"\xa5" * 65536)
    if data:
        cpu.mem_write(inp, data)
    for index, value in enumerate((inp, out, tape, len(data) if length is None else length, capacity)):
        cpu.reg_write(UC_ARM64_REG_X0 + index, value)
    cpu.reg_write(UC_ARM64_REG_X30, stop)
    cpu.reg_write(UC_ARM64_REG_SP, stack + (1 << 20) - 16)
    cpu.emu_start(code + dict(bundle.function_offsets)[imported.function.cid], stop, count=50_000_000, timeout=10_000_000)
    if cpu.reg_read(UC_ARM64_REG_PC) != stop:
        raise TimeoutError("BBX generated code did not return within emulator test budget")
    result = cpu.reg_read(UC_ARM64_REG_X0)
    status, count = result & 0xFFFFFFFF, result >> 32
    assert count <= capacity
    output = bytes(cpu.mem_read(out, count))
    assert bytes(cpu.mem_read(out + count, 65536 - count)) == b"\xa5" * (65536 - count)
    assert bytes(cpu.mem_read(inp, 65536)) == data + b"\xa5" * (65536 - len(data))
    return status, output, bytes(cpu.mem_read(tape, 65536)), len(bundle.code)


class BBXTests(unittest.TestCase):
    def test_record_rejections(self):
        bad = [b"", b"BBX", b"BBX\0\0\0\0", b"BBX\x02\0\0\0", b"BFI1\0\0\0",
               b"BBX\x01\x01", b"BBX\x01\x02", b"BBX\x01\x03", b"BBX\x01\x04\0\0",
               record(b"+")[:-1], record(b"") + b"+", record(b"x"), record(b"["), record(b"]"),
               record(b"]["), record(b"[" * 256 + b"]" * 256), record(b"+" * 3841), bytearray(record(b""))]
        for data in bad:
            with self.subTest(data=repr(data)[:60]), self.assertRaises(ValueError):
                construct_bbx(data)

    def test_record_limits(self):
        self.assertEqual(len(decode_bbx(record(b"+" * 3840))[0]), 3840)
        self.assertEqual(len(decode_bbx(record(b"[" * 255 + b"]" * 255))[1]), 510)

    def test_invalid_view_extents(self):
        for extent in (0, -1, 65537, True, 1.0):
            for name in ("input_extent", "output_extent"):
                with self.subTest(extent=extent, name=name), self.assertRaises(ValueError):
                    construct_bbx(record(b""), **{name: extent})

    @unittest.skipUnless(find_spec("unicorn"), "requires the optional Unicorn test dependency")
    def test_semantics_emulated(self):
        decision = b",>+<[[-]>[-]<]>.[-]"
        cases = [(b"", b"", 16), (b"><+-.,[]", b"\0", 16), (b"-.+.,.,.", b"\0", 16),
                 (b"++[>++[>+<-]<-]>>.", b"", 16), (b",.,.,.", b"\0\xff", 16),
                 (b"[<]", b"", 16), (b"+<", b"", 16), (b"+[>+]", b"", 16),
                 (b"..", b"", 1), (b".", b"", 0), (b"-[-].", b"", 16),
                 (decision, b"\0", 16), (decision, b"\x01", 16), (decision, b"\xff", 16)]
        rng = random.Random(20261018)
        for _ in range(10):
            code = b"+" * rng.randrange(1, 30) + b"[>+<-]>" + b"+-" * rng.randrange(8) + b"."
            cases.append((code, b"", 16))
        for code, data, capacity in cases:
            with self.subTest(code=code, data=data, capacity=capacity):
                imported = construct_bbx(record(code), input_extent=16, output_extent=16)
                actual = emulate(imported, data, capacity)
                self.assertEqual(actual[:2], reference(code, data, capacity))

    @unittest.skipUnless(find_spec("unicorn"), "requires the optional Unicorn test dependency")
    def test_invalid_lengths_do_not_touch_buffers(self):
        imported = construct_bbx(record(b",."), input_extent=16, output_extent=16)
        for length, capacity in ((17, 16), (0, 17), (0xFFFFFFFF, 16), (0, 0xFFFFFFFF)):
            with self.subTest(length=length, capacity=capacity):
                status, output, tape, _ = emulate(imported, capacity=capacity, length=length)
                self.assertEqual((status, output), (3, b""))
                self.assertEqual(tape, b"\xa5" * 65536)

    @unittest.skipUnless(find_spec("unicorn"), "requires the optional Unicorn test dependency")
    def test_tape_is_reset_fully(self):
        imported = construct_bbx(record(b""), input_extent=16, output_extent=16)
        self.assertEqual(emulate(imported)[2], b"\0" * 65536)

    def test_android_library_lowering(self):
        imported = construct_bbx(record(b",>+<[[-]>[-]<]>.[-]"), input_extent=16, output_extent=16)
        verify_store(imported.reader)
        library = compile_android_shared(imported.reader, (AndroidExport(b"bbx_decision_internal", imported.function.cid),), target_object=imported.target)
        inspect_android_elf(library.data)
        self.assertTrue(library.data.startswith(b"\x7fELF"))


if __name__ == "__main__":
    unittest.main()
