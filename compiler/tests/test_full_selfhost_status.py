"""S14b (ADR-285): the Linux x86-64 production compiler's B levels are derived from the committed record, never read.

``benchmarks/full_selfhost_evidence.json`` (``bench_full_selfhost.py``) records raw facts: digests, producers, the
bootstrap references, every generation's outcome on the corpus, and the recorded gaps.  ``xax_selfhost.
linux_x86_64_status`` computes B0-B6 from them.  The record must describe the committed compiler store, and changing
a fact must change the level that depends on it.
"""

from __future__ import annotations

import copy
import hashlib
import json
import unittest

from xax_selfhost import FULL_SELFHOST_EVIDENCE, linux_x86_64_status


class FullSelfhostStatusTests(unittest.TestCase):
    def setUp(self):
        self.evidence = json.loads(FULL_SELFHOST_EVIDENCE.read_text(encoding="utf-8"))

    def levels(self, evidence):
        status = linux_x86_64_status(evidence)
        return {level for level in (f"B{n}" for n in range(7)) if status[level]}

    def test_the_record_describes_the_committed_compiler(self):
        from xax_selfhost_driver import GENERAL_STORE_PATH

        self.assertEqual(self.evidence["compiler"]["store_sha256"], hashlib.sha256(GENERAL_STORE_PATH.read_bytes()).hexdigest())
        self.assertEqual(self.evidence["label"], "EXECUTED")

    def test_the_committed_levels(self):
        self.assertEqual(self.levels(self.evidence), {"B0", "B2", "B3", "B4"})
        self.assertFalse(any(key.startswith("B") and key[1:].isdigit() for key in self.evidence))  # no level is recorded

    def test_each_level_follows_its_facts(self):
        broken = copy.deepcopy(self.evidence)
        broken["generations"][2]["artifact_sha256"] = "0" * 64
        self.assertNotIn("B4", self.levels(broken))
        chain = copy.deepcopy(self.evidence)
        chain["generations"][1]["producer_sha256"] = "0" * 64
        self.assertFalse(self.levels(chain) & {"B2", "B3", "B4"})
        disagree = copy.deepcopy(self.evidence)
        disagree["corpus"][0]["outcomes"]["C3"] = ["declined", None]
        self.assertNotIn("B3", self.levels(disagree))
        reference = copy.deepcopy(self.evidence)
        reference["references"]["bootstrap_compile_sha256"] = "0" * 64
        self.assertNotIn("B4", self.levels(reference))
        closed = copy.deepcopy(self.evidence)
        closed["rejection_exactness_gaps"], closed["required_paths_outside_xax"] = [], []
        rejecting = [row for row in closed["corpus"] if row.get("bootstrap_diagnostic")]
        for row in rejecting:
            for generation in row["outcomes"]:
                row["outcomes"][generation] = ["rejected", *row["bootstrap_diagnostic"]]
        self.assertEqual(self.levels(closed) & {"B1", "B5", "B6"}, {"B1", "B5"})
        # S15b (ADR-288): a verification rejection that is not the bootstrap's keeps B1; another diagnostic is a
        # disagreement (B3); a decline or the driver's own record is no claim.
        self.assertTrue(rejecting)
        index = closed["corpus"].index(rejecting[0])
        declined = copy.deepcopy(closed)
        declined["corpus"][index]["outcomes"] = {generation: ["declined", None] for generation in declined["corpus"][index]["outcomes"]}
        self.assertEqual(self.levels(declined) & {"B1", "B3"}, {"B3"})
        wrong = copy.deepcopy(closed)
        wrong["corpus"][index]["outcomes"] = {generation: ["rejected", "XAX.OTHER", "OTHER", "0" * 64] for generation in wrong["corpus"][index]["outcomes"]}
        self.assertFalse(self.levels(wrong) & {"B1", "B3"})


if __name__ == "__main__":
    unittest.main()
