from __future__ import annotations

import io
import unittest
import zipfile

from xax_apk import ApkEntry, build_apk, build_unsigned_apk, inspect_apk
from xax_dex import activity_bridge_spec, emit_dex039_bridge


class ApkTests(unittest.TestCase):
    def test_direct_zip_is_deterministic_and_canonical_under_input_order(self) -> None:
        first = build_apk((ApkEntry("z", b"z"), ApkEntry("a", b"a")))
        second = build_apk((ApkEntry("a", b"a"), ApkEntry("z", b"z")))
        self.assertEqual(first, second)
        with zipfile.ZipFile(io.BytesIO(first), "r") as archive:
            self.assertEqual(archive.namelist(), ["a", "z"])
            self.assertEqual(archive.read("a"), b"a")

    def test_unsigned_android_container_aligns_native_library_to_16k(self) -> None:
        dex = emit_dex039_bridge(activity_bridge_spec())
        apk = build_unsigned_apk(b"binary-manifest-fixture", dex, native_libraries={"libxaxapp.so": b"ELF" * 100})
        view = inspect_apk(apk)
        by_name = {item.name: item for item in view.entries}
        self.assertEqual(by_name["AndroidManifest.xml"].data_offset % 4, 0)
        self.assertEqual(by_name["classes.dex"].data_offset % 4, 0)
        self.assertEqual(by_name["lib/arm64-v8a/libxaxapp.so"].data_offset % (16 * 1024), 0)
        with zipfile.ZipFile(io.BytesIO(apk), "r") as archive:
            self.assertEqual(archive.read("classes.dex"), dex)

    def test_entry_validation_rejects_escape_and_duplicates(self) -> None:
        with self.assertRaises(ValueError):
            ApkEntry("../bad", b"")
        with self.assertRaises(ValueError):
            build_apk((ApkEntry("a", b"1"), ApkEntry("a", b"2")))

    def test_builder_rejects_implicit_missing_core_artifacts(self) -> None:
        with self.assertRaises(ValueError):
            build_unsigned_apk(b"", b"dex")
        with self.assertRaises(ValueError):
            build_unsigned_apk(b"manifest", b"")


if __name__ == "__main__":
    unittest.main()
