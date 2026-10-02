from __future__ import annotations

import hashlib
import json
from pathlib import Path
import unittest

from benchmarks.bench_android_apk import ARTIFACT_PATH, EVIDENCE_PATH, build_fixture, collect_evidence
from xax_apk_signing import inspect_apk_v2


class AndroidApkEvidenceTests(unittest.TestCase):
    def test_committed_signed_apk_and_evidence_reproduce(self) -> None:
        _manifest_semantics, _manifest, _dex, _listener_dex, _elf, _unsigned, signed = build_fixture()
        self.assertEqual(ARTIFACT_PATH.read_bytes(), signed)
        self.assertEqual(json.loads(EVIDENCE_PATH.read_text(encoding="utf-8")), collect_evidence())
        evidence = collect_evidence()
        self.assertEqual(hashlib.sha256(signed).hexdigest(), evidence["signed_apk"]["sha256"])
        self.assertTrue(evidence["signed_apk"]["signature_valid"])
        self.assertTrue(evidence["signed_apk"]["content_digest_valid"])
        self.assertEqual(evidence["runtime_validation"]["activity_launch"], "UNEXECUTED")
        self.assertEqual(evidence["runtime_validation"]["validation_harness"], "compiler/integration/android/validate_activity_apk.sh")
        self.assertEqual(evidence["dex"]["multidex_runtime_dependency"], 0)
        self.assertEqual(evidence["dex"]["managed_activity_create_allocations_emitted"], 2)
        self.assertEqual(evidence["dex"]["native_transitions_per_click_callback"], 1)
        self.assertIn("classes2.dex", evidence["unsigned_apk"]["entry_order"])

    def test_committed_apk_v2_signature_verifies(self) -> None:
        view = inspect_apk_v2(ARTIFACT_PATH.read_bytes())
        self.assertTrue(view.signature_valid)
        self.assertTrue(view.content_digest_valid)
        self.assertTrue(view.certificate_key_matches)


if __name__ == "__main__":
    unittest.main()
