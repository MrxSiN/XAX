"""ADR-262 module record v1/v2 identity and the v2 static branding archive."""
from __future__ import annotations

import struct
import sys
import unittest
import zipfile
from io import BytesIO
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from xax_android_libxposed_jvm import (  # noqa: E402
    PREFIX, PREFIX_V2, LibxposedJvmModule, branding_entries, decode_libxposed_jvm_module, libxposed_jvm_module_semantics)
from xax_compiler import Cursor  # noqa: E402


def _manifest(version_code: int = 1, copies: int = 1) -> bytes:
    """A minimal binary manifest: resource map, then one root element holding ``copies`` versionCode attributes."""
    resources = struct.pack("<HHI", 0x0180, 8, 12) + struct.pack("<I", 0x0101021B)
    attributes = b"".join(struct.pack("<IIIHBBI", 0xFFFFFFFF, 0, 0xFFFFFFFF, 8, 0, 0x10, version_code) for _ in range(copies))
    element = struct.pack("<HHIII", 0x0102, 16, 36 + len(attributes), 1, 0xFFFFFFFF)
    element += struct.pack("<IIHHHHHH", 0xFFFFFFFF, 0, 20, 20, copies, 0, 0, 0) + attributes
    body = resources + element
    return struct.pack("<HHI", 0x0003, 8, 8 + len(body)) + body


def _archive(entries: dict[str, bytes]) -> bytes:
    out = BytesIO()
    with zipfile.ZipFile(out, "w") as archive:
        for name, data in entries.items():
            archive.writestr(name, data)
    return out.getvalue()


MODULE = dict(package="org.example.module", module_class="org.example.Module", scopes=("com.example",), version_code=7)


class ModuleRecord(unittest.TestCase):
    def test_unbranded_keeps_v1_and_branded_round_trips_as_v2(self) -> None:
        plain = libxposed_jvm_module_semantics(LibxposedJvmModule(**MODULE))
        self.assertTrue(Cursor(plain.body, "plain").byte_string().startswith(PREFIX))
        branded = LibxposedJvmModule(**MODULE, branding=bytes(range(32)))
        carrier = libxposed_jvm_module_semantics(branded)
        self.assertTrue(Cursor(carrier.body, "branded").byte_string().startswith(PREFIX_V2))
        self.assertEqual(decode_libxposed_jvm_module(carrier), branded)
        self.assertIn(bytes(range(32)), branded.inputs)


class Branding(unittest.TestCase):
    def test_version_code_replaced_and_resources_kept(self) -> None:
        entries = branding_entries(_archive({"AndroidManifest.xml": _manifest(), "res/a.xml": b"a", "resources.arsc": b"r"}), 127)
        self.assertEqual(entries["AndroidManifest.xml"], _manifest(127))
        self.assertEqual((entries["res/a.xml"], entries["resources.arsc"]), (b"a", b"r"))

    def test_rejections(self) -> None:
        for entries in ({"AndroidManifest.xml": _manifest(), "classes.dex": b""},
                        {"res/a.xml": b""},
                        {"AndroidManifest.xml": _manifest(copies=2)},
                        {"AndroidManifest.xml": _manifest()[:-4]}):
            with self.subTest(sorted(entries)), self.assertRaises(ValueError):
                branding_entries(_archive(entries), 2)


if __name__ == "__main__":
    unittest.main()
