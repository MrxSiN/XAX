"""ADR-108: ART's own verifier accepts every committed XAX APK and rejects an ill-typed control."""

from __future__ import annotations

import hashlib
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from benchmarks import bench_android_art_verify as art  # noqa: E402


class ArtVerifyEvidenceTests(unittest.TestCase):
    def test_evidence_covers_every_committed_apk_at_its_current_bytes(self):
        committed = json.loads(art.EVIDENCE.read_text(encoding="utf-8"))
        apks = sorted(art.HERE.glob("*.apk"))
        self.assertEqual(sorted(committed["apks"]), [path.name for path in apks])
        for path in apks:
            row = committed["apks"][path.name]
            self.assertEqual(row["sha256"], hashlib.sha256(path.read_bytes()).hexdigest())
            self.assertTrue(row["passed"] and set(row["classes"].values()) == {"Verified"}, path.name)
        self.assertTrue(committed["negative_control"]["rejected"])

    def test_control_patch_changes_exactly_one_instruction(self):
        import zipfile

        original = zipfile.ZipFile(art.HERE / "android_minimal_activity.apk").read("classes2.dex")
        patched = art._ill_typed_listener()
        differing = [index for index, (left, right) in enumerate(zip(original, patched)) if left != right]
        self.assertEqual(len(original), len(patched))
        position = original.index(bytes.fromhex("1f020200"))  # check-cast v2, TextView
        self.assertTrue(all(8 <= index < 12 or position <= index < position + 4 for index in differing))  # checksum + one instruction
        self.assertEqual(patched[position:position + 4], bytes(4))  # nop; nop


@unittest.skipUnless(art.available(), "requires qemu-aarch64 and the Android root from make_android_root.py")
class ArtVerifyExecutionTests(unittest.TestCase):
    def test_packed_activity_verifies_and_control_rejects(self):
        import shutil

        art.WORK.mkdir(parents=True, exist_ok=True)
        apk = art.WORK / "android_minimal_activity_packed.apk"
        shutil.copy(art.HERE / apk.name, apk)
        self.assertEqual(set(art.verify(apk).values()), {"Verified"})
        control = art.WORK / "ill_typed_listener.dex"
        control.write_bytes(art._ill_typed_listener())
        self.assertNotIn("Verified", set(art.verify(control).values()))


if __name__ == "__main__":
    unittest.main()
