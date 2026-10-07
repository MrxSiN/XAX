import csv
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from benchmarks import run_jvm_r5_ai as runner


class JvmR5RunnerTests(unittest.TestCase):
    def test_usage_counts_every_model_turn_and_cached_input(self):
        usage = runner.aggregate_usage([
            {"type": "turn.completed", "usage": {"input_tokens": 100, "cached_input_tokens": 80, "output_tokens": 10}},
            {"type": "turn.completed", "usage": {"input_tokens": 200, "cached_input_tokens": 170, "output_tokens": 20}},
        ])
        self.assertEqual(usage, {"input_tokens": 300, "cached_input_tokens": 250, "output_tokens": 30})

    def test_three_trials_per_cell_rotate_all_arms(self):
        cells = runner.schedule()
        self.assertEqual(len(cells), 135)
        self.assertEqual(len(set(cells)), 135)
        self.assertEqual({trial for _, _, trial in cells}, {1, 2, 3})
        self.assertNotEqual(cells[:3], cells[45:48])

    def _summary(self, *, xax=40, repetitions=3, missing=False, failures=False):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "results.csv")
            rows = []
            for task, arm, trial in runner.schedule(repetitions):
                row = dict.fromkeys(runner.FIELDS, "")
                row.update(task_id=task, arm=arm, trial=trial, model=runner.MODEL, reasoning=runner.REASONING,
                           client="fixed", total_tokens=xax if arm == "XAX" else 100 if arm == "JAVA" else 90,
                           **{"pass": "TRUE"})
                if failures and arm == "XAX":
                    rows.append(row | {"pass": "FALSE", "total_tokens": 100})
                rows.append(row)
            if missing:
                rows.pop()
            with path.open("w", newline="", encoding="utf-8") as file:
                writer = csv.DictWriter(file, fieldnames=runner.FIELDS)
                writer.writeheader()
                writer.writerows(rows)
            with patch.object(runner, "RESULTS", path):
                return runner.summarize(repetitions)

    def test_lowest_textual_median_controls_gate(self):
        evidence = self._summary(xax=46)
        self.assertFalse(evidence["meets_token_gate"])
        self.assertAlmostEqual(evidence["partial_xax_ratio_vs_lowest_textual_median"], 46 / 90)
        self.assertTrue(self._summary(xax=45)["meets_token_gate"])

    def test_missing_or_single_trials_never_satisfy_gate(self):
        self.assertFalse(self._summary(missing=True)["meets_token_gate"])
        self.assertFalse(self._summary(repetitions=1)["meets_token_gate"])

    def test_failed_attempts_count_toward_success_cost(self):
        evidence = self._summary(failures=True)
        self.assertEqual(evidence["successful_task_medians_including_retries"]["XAX"], 140)
        self.assertFalse(evidence["meets_token_gate"])


if __name__ == "__main__":
    unittest.main()
