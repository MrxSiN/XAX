"""Committed APKs validated by Google's build tools (format only; no ART)."""

from __future__ import annotations

import hashlib
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from benchmarks import bench_android_official_tools as official  # noqa: E402


class OfficialToolsEvidenceTests(unittest.TestCase):
    def test_evidence_covers_every_committed_apk_at_its_current_bytes(self):
        committed = json.loads(official.EVIDENCE.read_text(encoding="utf-8"))
        apks = sorted(official.HERE.glob("*.apk"))
        self.assertEqual(sorted(committed["apks"]), [path.name for path in apks])
        for path in apks:
            row = committed["apks"][path.name]
            self.assertEqual(row["sha256"], hashlib.sha256(path.read_bytes()).hexdigest())
            self.assertTrue(row["passed"], path.name)
            self.assertIn("zipalign_16k", row["checks"])

    @unittest.skipUnless((official.BUILD_TOOLS / "apksigner").exists(), "requires Android build-tools")
    def test_packed_activity_passes_the_official_tools(self):
        row = official.validate_apk(official.HERE / "android_minimal_activity_packed.apk")
        self.assertTrue(row["passed"], row["checks"])


if __name__ == "__main__":
    unittest.main()
