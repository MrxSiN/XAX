from __future__ import annotations

import json
import unittest

from benchmarks.bench_android_service import APK_PATH, EVIDENCE_PATH, collect_evidence, service_apk_fixture


class AndroidServiceEvidenceTests(unittest.TestCase):
    def test_committed_service_evidence_matches_reproduction(self) -> None:
        expected = json.loads(EVIDENCE_PATH.read_text(encoding="utf-8"))
        self.assertEqual(collect_evidence(), expected)
        *_unused, result = service_apk_fixture()
        self.assertEqual(APK_PATH.read_bytes(), result.artifact)
        self.assertEqual(expected["dex"]["on_create_code_units"], 7)
        self.assertEqual(expected["dex"]["on_destroy_code_units"], 7)
        self.assertEqual(expected["dex"]["on_bind_code_units"], 2)
        self.assertEqual(expected["dex"]["on_bind_native_transitions"], 0)
        self.assertEqual(expected["runtime_validation"]["service_instantiation"], "UNEXECUTED")


if __name__ == "__main__":
    unittest.main()
