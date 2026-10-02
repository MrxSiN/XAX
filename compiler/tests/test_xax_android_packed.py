"""ADR-105: the packed Android ELF container (format 5)."""

from __future__ import annotations

import hashlib
import json
import struct
import sys
import unittest
from pathlib import Path

from xax_compiler import XaxError, _android_arm64_shared_target, android_arm64_shared_general_target, decode_native_target

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from benchmarks import bench_android_apk, bench_android_ndk_twin, bench_android_platform_runtime  # noqa: E402

PAGE = 0x4000
PT_LOAD = 1


def _loads(elf: bytes) -> list[tuple[int, int, int, int, int, int]]:
    """``(flags, offset, vaddr, filesz, memsz, align)`` of each PT_LOAD."""
    phoff, = struct.unpack_from("<Q", elf, 32)
    phnum, = struct.unpack_from("<H", elf, 56)
    headers = [struct.unpack_from("<IIQQQQQQ", elf, phoff + 56 * index) for index in range(phnum)]
    return [(flags, offset, vaddr, filesz, memsz, align) for kind, flags, offset, vaddr, _paddr, filesz, memsz, align in headers if kind == PT_LOAD]


class PackedContainerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.identity_mapped = bench_android_platform_runtime.build_probe()
        cls.packed = bench_android_platform_runtime.build_probe(packed=True)

    def test_segments_are_congruent_page_aligned_and_disjoint(self):
        (rx_flags, rx_offset, rx_vaddr, rx_filesz, _rx_memsz, rx_align), (_rw_flags, rw_offset, rw_vaddr, _rw_filesz, _rw_memsz, rw_align) = _loads(self.packed)
        self.assertEqual((rx_offset, rx_vaddr, rx_align, rw_align), (0, 0, PAGE, PAGE))
        self.assertEqual(rw_offset % PAGE, rw_vaddr % PAGE)  # the ELF requirement
        self.assertLess(rw_offset, PAGE)  # no file padding to the next page
        self.assertGreaterEqual(rw_vaddr, -(-(rx_vaddr + rx_filesz) // PAGE) * PAGE)  # RW starts on a fresh page in memory
        self.assertEqual(rw_offset, -(-rx_filesz // 8) * 8)

    def test_packed_library_is_smaller_and_identity_mapped_one_is_unchanged(self):
        self.assertLess(len(self.packed), len(self.identity_mapped) // 4)
        committed = json.loads(bench_android_platform_runtime.EVIDENCE.read_text(encoding="utf-8"))
        self.assertEqual(hashlib.sha256(self.identity_mapped).hexdigest(), committed["artifact_sha256"])

    def test_device_validated_apk_is_unchanged(self):
        self.assertEqual(bench_android_apk.build_fixture()[-1], bench_android_apk.ARTIFACT_PATH.read_bytes())

    def test_packed_apk_is_deterministic_and_committed(self):
        self.assertEqual(bench_android_apk.build_fixture(packed=True)[-1], bench_android_apk.PACKED_ARTIFACT_PATH.read_bytes())

    def test_packed_target_is_a_distinct_explicit_format(self):
        packed, plain = android_arm64_shared_general_target(packed=True), android_arm64_shared_general_target()
        self.assertNotEqual(packed.cid, plain.cid)
        self.assertEqual((decode_native_target(packed).image_format, decode_native_target(plain).image_format), (5, 4))

    def test_unknown_container_format_rejects(self):
        with self.assertRaises(XaxError) as caught:
            decode_native_target(_android_arm64_shared_target(b"android-arm64-v8a-shared-v4", (1, 2, 3), 6))
        self.assertEqual(caught.exception.diagnostic.rule, "TARGET-AARCH64-PROFILE")

    def test_committed_size_comparison_matches_the_committed_apks(self):
        committed = json.loads(bench_android_ndk_twin.EVIDENCE.read_text(encoding="utf-8"))
        self.assertTrue(committed["behavior_match"])
        for key, path in (("xax", bench_android_ndk_twin.XAX_APK), ("xax_packed", bench_android_ndk_twin.XAX_PACKED_APK)):
            self.assertEqual(committed[key]["apk_sha256"], hashlib.sha256(path.read_bytes()).hexdigest())
        self.assertLess(committed["xax_packed"]["apk_bytes"], committed["java_ndk"]["apk_bytes"])


if __name__ == "__main__":
    unittest.main()
