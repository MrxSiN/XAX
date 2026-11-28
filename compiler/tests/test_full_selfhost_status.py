"""S14b (ADR-285), ADR-433 (3): the Linux x86-64 production compiler's B levels are derived from records, never read.

``benchmarks/full_selfhost_evidence.json`` (``bench_full_selfhost.py``) records the pinned seed's outcome on every
corpus case beside the reference's, the reference resolver's snapshot and the recorded gaps; the latest validated
release's V2 record (``bootstrap/evidence/records``) holds the generations, the fixed point, the contexts, the replay and
the structural probe.  ``xax_selfhost.linux_x86_64_status`` computes B0-B6 from both.  The V1 record must describe the
committed compiler store, and changing a fact must change the level that depends on it.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
import unittest

from xax_selfhost import FULL_SELFHOST_EVIDENCE, linux_x86_64_status, released_record


def _swap(record: str, pattern: str, replacement: str) -> str:
    """``record`` with the one line matching ``pattern`` (a regular expression, from a line start) replaced."""
    changed, count = re.subn(rf"(?m)^{pattern}.*$", replacement, record)
    assert count == 1, (pattern, count)
    return changed


class FullSelfhostStatusTests(unittest.TestCase):
    def setUp(self):
        self.evidence = json.loads(FULL_SELFHOST_EVIDENCE.read_text(encoding="utf-8"))
        self.record = released_record()

    def levels(self, evidence=None, record=None):
        status = linux_x86_64_status(self.evidence if evidence is None else evidence, None, self.record if record is None else record)
        return {level for level in (f"B{n}" for n in range(7)) if status[level]}

    def test_the_record_describes_the_committed_compiler(self):
        from xax_selfhost_driver import GENERAL_STORE_PATH

        self.assertEqual(self.evidence["compiler"]["store_sha256"], hashlib.sha256(GENERAL_STORE_PATH.read_bytes()).hexdigest())
        self.assertEqual(self.evidence["label"], "EXECUTED")
        self.assertEqual({tuple(row["outcomes"]) for row in self.evidence["corpus"]}, {("C0",)})  # ADR-433 (3): C0 only

    def test_the_committed_levels(self):
        # S15c.5 (ADR-309): B5; S15d.4b (ADR-314): B6; S15b.3e (ADR-318): B1
        self.assertEqual(self.levels(), {"B0", "B1", "B2", "B3", "B4", "B5", "B6"})
        self.assertFalse(any(key.startswith("B") and key[1:].isdigit() for key in self.evidence))  # no level is recorded

    def test_each_level_follows_the_v2_record(self):
        first = re.search(r"(?m)^generation 1 (.*)$", self.record).group(1).split()
        artifact = _swap(self.record, "generation 1 ", "generation 1 " + " ".join([*first[:4], "cd" * 32, *first[5:]]))
        self.assertFalse(self.levels(record=artifact) & {"B0", "B4"})
        producer = _swap(self.record, "generation 1 ", "generation 1 " + " ".join(["0" * 64, *first[1:]]))
        self.assertFalse(self.levels(record=producer) & {"B2", "B3", "B4"})
        snapshot = _swap(self.record, "generation 1 ", "generation 1 " + " ".join([*first[:2], "-", *first[3:]]))
        self.assertNotIn("B2", self.levels(record=snapshot))
        unbuilt = _swap(self.record, "generation 1 ", "generation 1 " + " ".join([*first[:3], "3", *first[4:]]))
        self.assertFalse(self.levels(record=unbuilt))
        interpreter = _swap(self.record, "generation 1 ", "generation 1 " + " ".join([*first[:6], "1"]))
        self.assertEqual(self.levels(record=interpreter) & {"B4", "B5", "B6"}, {"B4"})
        repeat = re.search(r"(?m)^repeat (\S+) 0 .*$", self.record).group(1)
        flaky = _swap(self.record, f"repeat {repeat} 0 ", f"repeat {repeat} 0 3 - - - -")
        self.assertNotIn("B3", self.levels(record=flaky))
        self.assertFalse(self.levels(record=self.record.replace("\nend\n", "\n")))
        for replay in ("replay 1 replayed 256 of 256", "replay 0 replayed 255 of 256", "replay not-run"):
            self.assertEqual(self.levels(record=_swap(self.record, "replay ", replay)) & {"B5", "B6"}, {"B5"}, replay)
        context = re.search(r"(?m)^context (\S+) ", self.record).group(1)
        probe = max(int(line.split()[2]) for line in self.record.splitlines() if line.startswith(f"outcome {context} "))
        unprobed = _swap(self.record, f"outcome {context} {probe} ", f"outcome {context} {probe} 0 {'ef' * 32} - - -")
        self.assertEqual(self.levels(record=unprobed) & {"B5", "B6"}, {"B5"})

    def test_each_level_follows_the_v1_record(self):
        rows = self.evidence["corpus"]
        image = next(i for i, row in enumerate(rows) if row["reference"] and row["reference"][0] == "image")
        differs = copy.deepcopy(self.evidence)
        differs["corpus"][image]["outcomes"]["C0"] = ["declined", None]
        self.assertNotIn("B3", self.levels(differs))
        seedless = copy.deepcopy(self.evidence)
        seedless["seed"]["sha256"] = "0" * 64
        self.assertFalse(self.levels(seedless) & {"B2", "B3", "B4"})
        reference = copy.deepcopy(self.evidence)
        reference["references"]["python_resolver_snapshot_sha256"] = "0" * 64
        self.assertNotIn("B2", self.levels(reference))
        gaps = copy.deepcopy(self.evidence)
        gaps["rejection_exactness_gaps"], gaps["required_paths_outside_xax"], gaps["ordinary_evolution"] = ["a gap"], ["a path"], "stated"
        self.assertEqual(self.levels(gaps) & {"B1", "B5", "B6"}, set())
        interpreter = copy.deepcopy(self.evidence)
        interpreter["executables_have_interpreter"]["C0"] = True
        self.assertFalse(self.levels(interpreter) & {"B5", "B6"})
        # S15b (ADR-288): a verification rejection that is not the bootstrap's keeps B1; another diagnostic is a
        # disagreement (B3); a decline or the driver's own record is no claim.
        rejecting = [i for i, row in enumerate(rows) if row.get("bootstrap_diagnostic")]
        self.assertTrue(rejecting)
        declined = copy.deepcopy(self.evidence)
        declined["corpus"][rejecting[0]]["outcomes"]["C0"] = ["declined", None]
        self.assertEqual(self.levels(declined) & {"B1", "B3"}, {"B3"})
        wrong = copy.deepcopy(self.evidence)
        wrong["corpus"][rejecting[0]]["outcomes"]["C0"] = ["rejected", "XAX.OTHER", "OTHER", "0" * 64]
        self.assertFalse(self.levels(wrong) & {"B1", "B3"})


if __name__ == "__main__":
    unittest.main()
