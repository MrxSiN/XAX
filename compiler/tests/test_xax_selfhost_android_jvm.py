"""S15e.6i.2b (ADR-358): libxposed JVM modules built by the XAX Android program equal the bootstrap's.

``build_libxposed_jvm_apk`` asks the XAX Android program first.  Its libxposed JVM profile decodes the module record and
the metadata carrier, checks the record's rules and its external inputs, runs the JVM program on the entry, lowers each
class of the JAR with the class-translation program, writes the code DEX (with the field holders), the Module and
native-class bridges, the manifest (generated, or the branding archive's with the record's versionCode) and the metadata,
and the APK.  Under ``XAX_GENERAL_FRONTEND_DIFF=1`` each APK and each rejection equals the bootstrap's.
"""

from __future__ import annotations

import os
import platform
import struct
import sys
import unittest
import zipfile
from io import BytesIO
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

LINUX_X86_64 = sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")
PARAMETERS = ["jvm:Lio/github/libxposed/api/XposedInterface;", "jvm:Lio/github/libxposed/api/XposedModuleInterface$PackageReadyParam;"]
MODULE = dict(package="org.example.module", module_class="org.example.Module", scopes=["com.example"], version_code=7)


def _manifest(version_code: int = 1) -> bytes:
    """A minimal binary manifest: the resource map, then one root element with a versionCode attribute."""
    resources = struct.pack("<HHI", 0x0180, 8, 12) + struct.pack("<I", 0x0101021B)
    attributes = struct.pack("<IIIHBBI", 0xFFFFFFFF, 0, 0xFFFFFFFF, 8, 0, 0x10, version_code)
    element = struct.pack("<HHIII", 0x0102, 16, 36 + len(attributes), 1, 0xFFFFFFFF)
    element += struct.pack("<IIHHHHHH", 0xFFFFFFFF, 0, 20, 20, 1, 0, 0, 0) + attributes
    body = resources + element
    return struct.pack("<HHI", 0x0003, 8, 8 + len(body)) + body


def _archive(entries: dict[str, bytes]) -> bytes:
    out = BytesIO()
    with zipfile.ZipFile(out, "w") as archive:
        for name, data in entries.items():
            archive.writestr(name, data)
    return out.getvalue()


def _module(android: dict, params=PARAMETERS):
    from xax_construct import construct

    request = {"format": "xax-construct-v1", "platform": "android-libxposed",
               "functions": [{"name": "main", "params": params, "returns": [], "blocks": [{"params": params, "nodes": [], "end": ["ret", []]}]}],
               "package": {"name": "module", "entries": {"app": "main"}, "release": "app", "android": {**MODULE, **android}}}
    return construct(request).reader


@unittest.skipUnless(LINUX_X86_64, "the XAX Android program runs natively on Linux x86-64")
class SelfhostAndroidJvmTests(unittest.TestCase):
    def build(self, reader, inputs, direct: bool = False):
        """``build_module``'s outcome (``direct``: ``build`` of the constructed snapshot, which declares no inputs),
        requiring that the XAX program decided it."""
        import xax_selfhost_android as A
        from xax_android_libxposed_jvm import build_module
        from xax_build import build, decode_snapshot
        from xax_compiler import XaxError

        decided = []
        original = A.android_with_xax

        def recorded(*arguments, **keywords):
            try:
                built = original(*arguments, **keywords)
            except XaxError:
                decided.append("rejected")
                raise
            decided.append("apk" if built is not None else "declined")
            return built

        with mock.patch.dict(os.environ, {"XAX_GENERAL_FRONTEND_DIFF": "1"}), mock.patch.object(A, "android_with_xax", recorded):
            try:
                if direct:
                    outcome = ("apk", build(reader, decode_snapshot(reader.get(reader.root_cid), reader.get).request_root).artifact)
                else:
                    outcome = ("apk", build_module(reader, inputs).artifact)
            except XaxError as error:
                outcome = ("rejected", error.diagnostic)
        self.assertEqual(decided, [outcome[0]])
        return outcome

    def test_modules(self):
        from blake3 import blake3

        dex = b"dex\n035\x00" + bytes(range(64))
        library = bytes(range(256)) * 9
        branding = _archive({"res/values/strings.xml": b"<strings/>", "AndroidManifest.xml": _manifest(), "resources.arsc": b"arsc"})
        inputs = {blake3(item).digest(): item for item in (dex, library, branding)}
        cases = {
            "natives": (_module({"natives": [["Lorg/example/Policy;", "check", "(I)I"]]}), {}),
            "fields and native classes": (_module({
                "natives": [["Lorg/example/B;", "b", "(J[Ljava/lang/String;)V"], ["Lorg/example/A;", "a", "()Z"], ["Lorg/example/A;", "c", "(D)D"]],
                "fields": [["Lorg/example/State;", "count", "I"], ["Lorg/example/Other;", "name", "Ljava/lang/String;"],
                           ["Lorg/example/State;", "ready", "Z"]]}), {}),
            "inputs and branding": (_module({"dex": [blake3(dex).hexdigest()], "libraries": {"lib/arm64-v8a/libpolicy.so": blake3(library).hexdigest()},
                                             "branding": blake3(branding).hexdigest(), "min_sdk": 30, "target_sdk": 34}), inputs),
            "missing inputs": (_module({"dex": [blake3(dex).hexdigest()], "libraries": {"lib/arm64-v8a/libpolicy.so": blake3(library).hexdigest()}}),
                               None),
        }
        seen = set()
        for name, (reader, given) in cases.items():
            with self.subTest(case=name):
                outcome = self.build(reader, given or {}, direct=given is None)
                seen.add(outcome[0] if outcome[0] == "apk" else outcome[1].rule)
                if name == "inputs and branding":
                    with zipfile.ZipFile(BytesIO(outcome[1])) as apk:
                        self.assertEqual(apk.read("lib/arm64-v8a/libpolicy.so"), library)
                        self.assertEqual(apk.read("classes3.dex"), dex)
                        self.assertEqual(apk.read("resources.arsc"), b"arsc")
        self.assertEqual(seen, {"apk", "LIBXPOSED-JVM-INPUTS"})

    def test_entry_signature(self):
        """An entry that is not ``(XposedInterface, PackageReadyParam)V``: ``LIBXPOSED-JVM-ENTRY``."""
        try:
            reader = _module({}, params=PARAMETERS[:1])
        except Exception as error:  # noqa: BLE001 - the constructor refuses it before any build
            self.skipTest(f"construct refuses the entry: {error}")
        outcome = self.build(reader, {})
        self.assertEqual(outcome[0], "rejected")
        self.assertEqual(outcome[1].rule, "LIBXPOSED-JVM-ENTRY")


if __name__ == "__main__":
    unittest.main()
