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


class ModuleBuild(unittest.TestCase):
    def test_construct_export_and_build_unsigned_module(self) -> None:
        from xax_android_libxposed_jvm import build_module
        from xax_construct import construct, export_carrier

        parameters = ["jvm:Lio/github/libxposed/api/XposedInterface;",
                      "jvm:Lio/github/libxposed/api/XposedModuleInterface$PackageReadyParam;"]
        request = {"format": "xax-construct-v1", "platform": "android-libxposed",
                   "functions": [{"name": "main", "params": parameters, "returns": [],
                                  "blocks": [{"params": parameters, "nodes": [], "end": ["ret", []]}]}],
                   "package": {"name": "module", "entries": {"app": "main"}, "release": "app",
                               "android": {**MODULE, "natives": [["Lorg/example/Policy;", "check", "(I)I"]]}}}
        reader = construct(request).reader
        self.assertEqual(construct(export_carrier(reader)).reader.canonical_bytes(), reader.canonical_bytes())
        result = build_module(reader, {})
        with zipfile.ZipFile(BytesIO(result.artifact)) as apk:
            self.assertTrue({"AndroidManifest.xml", "classes.dex", "classes2.dex", "classes3.dex"} <= set(apk.namelist()))
            self.assertEqual(apk.read("META-INF/xposed/java_init.list"), b"org.example.Module\n")


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
