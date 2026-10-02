"""ADR-109: XAX-generated libxposed modules executed on ART with a stand-in framework."""

from __future__ import annotations

import hashlib
import io
import json
import sys
import tempfile
import unittest
import zipfile
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from benchmarks import bench_android_art_execute as art  # noqa: E402


def _with_replaced_result(apk: Path, destination: Path) -> None:
    """Copy ``apk`` with the Hooker's "HookedResult" literal changed to "HookedResulX" (DEX checksum fixed)."""
    with zipfile.ZipFile(apk) as source, zipfile.ZipFile(destination, "w", zipfile.ZIP_STORED) as out:
        for item in source.infolist():
            data = source.read(item.filename)
            if item.filename.endswith(".dex") and b"HookedResult" in data:
                dex = bytearray(data.replace(b"HookedResult", b"HookedResulX"))
                dex[8:12] = zlib.adler32(bytes(dex[12:])).to_bytes(4, "little")
                data = bytes(dex)
            out.writestr(item, data)


class ArtExecuteEvidenceTests(unittest.TestCase):
    def test_evidence_matches_the_declared_behaviour_and_current_apks(self):
        committed = json.loads(art.EVIDENCE.read_text(encoding="utf-8"))
        self.assertEqual(sorted(committed["runs"]), sorted(art.EXPECTED))
        for name, run in committed["runs"].items():
            self.assertEqual(run["sha256"], hashlib.sha256((art.HERE / name).read_bytes()).hexdigest())
            self.assertEqual((run["expected"], run["observed"], run["passed"]), (art.EXPECTED[name], art.EXPECTED[name], True))

    def test_every_libxposed_module_with_managed_code_is_covered(self):
        modules = {
            path.name for path in art.HERE.glob("android_libxposed_*.apk")
            if any(name.startswith("META-INF/xposed/") for name in zipfile.ZipFile(path).namelist())
            and any(b"Lxax/generated/XaxModule;" in zipfile.ZipFile(path).read(name) for name in zipfile.ZipFile(path).namelist() if name.endswith(".dex"))
        }
        self.assertEqual(modules, set(art.EXPECTED))


@unittest.skipUnless(art.available(), "requires qemu-aarch64 and the Android root from make_android_root.py")
class ArtExecuteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        cls.harness = art.build_harness(Path(cls.directory.name))

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def _observed(self, apk: Path) -> str | None:
        completed = art.run_module(apk, self.harness)
        return next((line.removeprefix("XAX_LIBXPOSED_ART ") for line in completed.stdout.splitlines() if line.startswith("XAX_LIBXPOSED_ART ")), None)

    def test_combined_module_runs_as_declared(self):
        name = "android_libxposed_combined_fixture.apk"
        self.assertEqual(self._observed(art.HERE / name), art.EXPECTED[name])

    def test_harness_observes_a_changed_hooker(self):
        """Control: the same module with a different replacement literal must not match its declaration."""
        changed = Path(self.directory.name) / "changed.apk"
        _with_replaced_result(art.HERE / "android_libxposed_combined_fixture.apk", changed)
        observed = self._observed(changed)
        self.assertIsNotNone(observed)
        self.assertTrue(observed.endswith("result=HookedResulX"), observed)


if __name__ == "__main__":
    unittest.main()
