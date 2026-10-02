from __future__ import annotations

import json
import unittest
from pathlib import Path

from benchmarks.bench_android_libxposed_combined import collect_evidence

EVIDENCE = Path(__file__).parents[1] / "benchmarks" / "android_libxposed_combined_evidence.json"


class AndroidLibxposedCombinedEvidenceTests(unittest.TestCase):
    def test_committed_evidence_replays_exactly(self):
        committed = json.loads(EVIDENCE.read_text(encoding="utf-8"))
        self.assertEqual(collect_evidence(), committed)

    def test_combined_hot_path_is_one_proceed_one_array_and_post_result_replacement(self):
        evidence = collect_evidence()
        hot = evidence["hot_hooker_dex"]
        self.assertEqual(hot["argument_reads"], 1)
        self.assertEqual(hot["chain_proceed_calls"], 1)
        self.assertEqual(hot["object_array_allocations_per_intercept_emitted"], 1)
        self.assertEqual(hot["object_allocations_per_intercept_emitted"], 0)
        self.assertEqual(hot["argument_array_stores"], 1)
        self.assertTrue(hot["argument_replacement_literal_present"])
        self.assertTrue(hot["result_replacement_literal_present"])
        self.assertTrue(hot["original_result_captured_before_replacement"])
        self.assertEqual(evidence["allocation_policy"]["zero_allocation_claim"], False)
        self.assertEqual(evidence["runtime_validation"]["interception"], "UNEXECUTED")
        self.assertEqual(evidence["runtime_validation"]["result_replacement"], "UNEXECUTED")


if __name__ == "__main__":
    unittest.main()
