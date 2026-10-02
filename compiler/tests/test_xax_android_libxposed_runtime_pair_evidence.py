from __future__ import annotations

import json
import unittest
from pathlib import Path

from benchmarks.bench_android_libxposed_runtime_pair import collect_evidence

EVIDENCE = Path(__file__).parents[1] / "benchmarks" / "android_libxposed_runtime_pair_evidence.json"


class AndroidLibxposedRuntimePairEvidenceTests(unittest.TestCase):
    def test_committed_runtime_pair_replays_exactly(self):
        self.assertEqual(collect_evidence(), json.loads(EVIDENCE.read_text(encoding="utf-8")))

    def test_signed_pair_is_only_validation_input_not_runtime_proof(self):
        evidence = collect_evidence()
        self.assertTrue(evidence["target"]["v2_signature_valid"])
        self.assertTrue(evidence["module"]["v2_signature_valid"])
        self.assertEqual(evidence["runtime_validation"]["install"], "UNEXECUTED")
        self.assertEqual(evidence["runtime_validation"]["module_enabled_and_scoped"], "EXTERNAL_PRECONDITION")


if __name__ == "__main__":
    unittest.main()
