"""JNI caller validation, allocation failures and packaging (not device evidence)."""
import io
import unittest
import zipfile
from importlib.util import find_spec

from xax_bbx_android import JNI_SYMBOL, build_bbx_app, native_decision
from xax_aarch64 import compile_aarch64_bundle_bound_target
from test_xax_bbx import record

DECISION = b",>+<[[-]>[-]<]>.[-]"


def emulate_jni(module, flag, capacity, *, fail_allocation=None):
    from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
    from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X30, UC_ARM64_REG_SP, UC_ARM64_REG_PC

    reader, function, target = native_decision(module)
    bundle = compile_aarch64_bundle_bound_target(reader, (function.cid,), target)
    cpu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    code, stop, stack = 0x100000, 0x300000, 0x400000
    cpu.mem_map(code, (len(bundle.code) + 4095) & ~4095)
    cpu.mem_write(code, bundle.code)
    cpu.mem_map(stop, 4096)
    cpu.mem_map(stack, 1 << 20)
    sites = {code + offset: symbol for offset, library, symbol in bundle.foreign_calls if library == b"libc.so"}
    assert len(sites) == len(bundle.foreign_calls)
    allocations, freed = [], []

    def foreign(uc, address, size, data):
        if address not in sites:
            return
        if sites[address] == b"calloc":
            extent = uc.reg_read(UC_ARM64_REG_X0) * uc.reg_read(UC_ARM64_REG_X0 + 1)
            pointer = 0 if len(allocations) == fail_allocation else 0x600000 + 0x20000 * len(allocations)
            allocations.append(pointer)
            if pointer:
                uc.mem_map(pointer, (extent + 4095) & ~4095)
                uc.mem_write(pointer, b"\0" * extent)
            uc.reg_write(UC_ARM64_REG_X0, pointer)
        elif sites[address] == b"free":
            freed.append(uc.reg_read(UC_ARM64_REG_X0))
        else:
            raise AssertionError(sites[address])
        uc.reg_write(UC_ARM64_REG_PC, address + 4)

    cpu.hook_add(UC_HOOK_CODE, foreign)
    for index, value in enumerate((0, 0, flag & 0xffffffff, capacity & 0xffffffff)):
        cpu.reg_write(UC_ARM64_REG_X0 + index, value)
    cpu.reg_write(UC_ARM64_REG_X30, stop)
    cpu.reg_write(UC_ARM64_REG_SP, stack + (1 << 20) - 16)
    if fail_allocation is not None:
        from unicorn import UcError, UC_ERR_EXCEPTION
        try:
            cpu.emu_start(code + dict(bundle.function_offsets)[function.cid], stop, count=50_000_000, timeout=10_000_000)
        except UcError as error:
            assert error.errno == UC_ERR_EXCEPTION
            instruction = int.from_bytes(cpu.mem_read(cpu.reg_read(UC_ARM64_REG_PC), 4), "little")
            assert instruction == 0xd4200060  # XAX BRK_NULL_HEAP (3)
            assert len(allocations) == fail_allocation + 1 and allocations[-1] == 0
            assert not freed
            return "null-allocation-trap", len(allocations)
        raise AssertionError("null heap allocation did not trap")
    cpu.emu_start(code + dict(bundle.function_offsets)[function.cid], stop, count=50_000_000, timeout=10_000_000)
    assert cpu.reg_read(UC_ARM64_REG_PC) == stop
    assert allocations == freed, (allocations, freed)
    return cpu.reg_read(UC_ARM64_REG_X0), len(allocations)


class AndroidBBXTests(unittest.TestCase):
    @unittest.skipUnless(find_spec("unicorn"), "requires optional Unicorn dependency")
    def test_caller_results_and_rejections(self):
        for flag, capacity, expected, allocated in ((0, 1, 0, 3), (1, 1, 1, 3), (255, 16, 1, 3),
            (0, 0, 2, 3), (-1, 1, 2, 0), (256, 1, 2, 0), (0, -1, 2, 0), (0, 17, 2, 0)):
            with self.subTest(flag=flag, capacity=capacity):
                self.assertEqual(emulate_jni(record(DECISION), flag, capacity), (expected, allocated))

    @unittest.skipUnless(find_spec("unicorn"), "requires optional Unicorn dependency")
    def test_calloc_failure_traps_before_dereference(self):
        for failure in range(3):
            with self.subTest(failure=failure):
                self.assertEqual(emulate_jni(record(DECISION), 0, 1, fail_allocation=failure), ("null-allocation-trap", failure + 1))

    @unittest.skipUnless(find_spec("unicorn"), "requires optional Unicorn dependency")
    def test_core_error_and_unexpected_output_fail_closed(self):
        for code in (b"", b"<", b"++.", b".."):
            with self.subTest(code=code):
                self.assertEqual(emulate_jni(record(code), 0, 16), (2, 3))

    def test_deterministic_complete_apk(self):
        app = build_bbx_app(record(DECISION))
        rebuilt = build_bbx_app(record(DECISION))
        self.assertEqual((app.library, app.dex, app.unsigned_apk), (rebuilt.library, rebuilt.dex, rebuilt.unsigned_apk))
        self.assertEqual(app.native_reader.root_cid, rebuilt.native_reader.root_cid)
        self.assertEqual(app.managed_reader.root_cid, rebuilt.managed_reader.root_cid)
        with zipfile.ZipFile(io.BytesIO(app.unsigned_apk)) as archive:
            self.assertEqual(set(archive.namelist()), {"AndroidManifest.xml", "classes.dex", "lib/arm64-v8a/libbbxdecision.so"})
        self.assertIn(JNI_SYMBOL, app.library)
        self.assertTrue(app.dex.startswith(b"dex\n"))


if __name__ == "__main__":
    unittest.main()
