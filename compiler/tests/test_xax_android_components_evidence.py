from __future__ import annotations

import json
import unittest

from benchmarks.bench_android_components import APK_PATH, EVIDENCE_PATH, collect_evidence, receiver_apk_fixture


class AndroidComponentsEvidenceTests(unittest.TestCase):
    def test_committed_receiver_evidence_matches_reproduction(self) -> None:
        expected = json.loads(EVIDENCE_PATH.read_text(encoding="utf-8"))
        self.assertEqual(collect_evidence(), expected)
        *_unused, result = receiver_apk_fixture()
        self.assertEqual(APK_PATH.read_bytes(), result.artifact)
        self.assertEqual(expected["dex"]["on_receive_code_units"], 4)
        self.assertEqual(expected["dex"]["allocations_emitted_in_on_receive"], 0)
        self.assertEqual(expected["runtime_validation"]["broadcast_delivery"], "UNEXECUTED")


if __name__ == "__main__":
    unittest.main()
