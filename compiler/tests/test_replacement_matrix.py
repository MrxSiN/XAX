"""The replacement matrix may never claim a level its evidence does not support."""
import copy
import unittest
from pathlib import Path

from xax_replacement import derived_level, load, validate

ROOT = Path(__file__).resolve().parents[2]
MATRIX = load(ROOT / "XAX_REPLACEMENT_MATRIX.json")


class ReplacementMatrixTests(unittest.TestCase):
    def test_repository_matrix_is_evidence_consistent(self):
        self.assertEqual(validate(MATRIX, ROOT), [])

    def test_overclaim_missing_evidence_and_bare_labels_reject(self):
        bad = copy.deepcopy(MATRIX)
        row = next(r for r in bad["platforms"] if r["id"] == "windows-x86_64-pe")
        row["level"] = "R4"
        row["fields"]["simd"] = "EXECUTED"
        row["fields"]["memory"] = ["MEASURED", "no/such/file.json"]
        errors = validate(bad, ROOT)
        self.assertIn("windows-x86_64-pe: claimed R4 but evidence supports R1", errors)
        self.assertIn("windows-x86_64-pe.simd: bare label EXECUTED needs evidence", errors)
        self.assertIn("windows-x86_64-pe.memory: missing evidence no/such/file.json", errors)

    def test_rows_need_a_name_and_summary_for_generated_tables(self):
        bad = copy.deepcopy(MATRIX)
        row = next(r for r in bad["platforms"] if r["id"] == "dotnet-clr")
        del row["name"]
        row["summary"] = " "
        errors = validate(bad, ROOT)
        self.assertIn("dotnet-clr: missing name", errors)
        self.assertIn("dotnet-clr: missing summary", errors)

    def test_emulator_only_rows_cannot_cite_performance(self):
        bad = copy.deepcopy(MATRIX)
        row = next(r for r in bad["platforms"] if r["id"] == "linux-aarch64")
        self.assertTrue(any("not hardware" in blocker for blocker in row["blockers"]))
        row["fields"]["performance"] = ["MEASURED", "compiler/benchmarks/linux_aarch64_filestat_evidence.json"]
        self.assertIn("linux-aarch64.performance: emulator-only row cannot claim performance evidence", validate(bad, ROOT))

    def test_linux_application_is_the_cited_r3_evidence(self):
        row = next(r for r in MATRIX["platforms"] if r["id"] == "linux-x86_64")
        practical = row["fields"]["practical_application"]
        self.assertEqual(practical[0], "EXECUTED")
        # The benchmark-scale filestat utility alone is not the application.
        self.assertIn("compiler/benchmarks/jsonmin_evidence.json", practical)
        self.assertEqual(derived_level(row), "R4")

    def test_not_applicable_needs_a_justification_and_only_covers_dynamic_linking(self):
        bad = copy.deepcopy(MATRIX)
        row = next(r for r in bad["platforms"] if r["id"] == "aarch64-baremetal")
        self.assertEqual(derived_level(row), "R2")
        del row["not_applicable"]
        self.assertIn("aarch64-baremetal.dynamic_linking: NOT_APPLICABLE needs a justification in not_applicable", validate(bad, ROOT))
        self.assertEqual(derived_level(row), "R1")
        row["not_applicable"] = {"ffi": "no foreign code", "dynamic_linking": "no loader"}
        row["fields"]["ffi"] = "NOT_APPLICABLE"
        self.assertEqual(derived_level(row), "R1")

    def test_measured_but_uncompetitive_rows_stop_at_r3(self):
        row = copy.deepcopy(next(r for r in MATRIX["platforms"] if r["id"] == "linux-x86_64"))
        self.assertTrue(all(row["fields"][field][0] == "MEASURED" for field in ("performance", "memory", "code_size")))
        self.assertEqual(derived_level(row), "R4")
        row["competitive"] = [False, "compiler/benchmarks/jsonmin_evidence.json"]
        self.assertEqual(derived_level(row), "R3")
        bad = copy.deepcopy(MATRIX)
        target = next(r for r in bad["platforms"] if r["id"] == "linux-x86_64")
        target["competitive"] = [False, "compiler/benchmarks/jsonmin_evidence.json"]
        self.assertIn("linux-x86_64: claimed R4 but evidence supports R3", validate(bad, ROOT))
        target["competitive"] = [True]
        self.assertIn("linux-x86_64.competitive: expected [bool, evidence...]", validate(bad, ROOT))

    def test_competitive_runtime_evidence_follows_the_multi_language_rule(self):
        import json
        import tempfile

        from xax_replacement import _runtime_rule_errors

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cases = {
                "c_only.json": {"results": {"xax": {"performance_class": "meets-primary-target"}, "gcc-O2": {}}},
                "slow.json": {"results": {"xax": {"performance_class": "competitive-below-primary-target"}, "gcc-O2": {}, "rustc-O3": {}}},
                "good.json": {"results": {"xax": {"performance_class": "meets-primary-target"}, "gcc-O2": {}, "rustc-O3": {}}},
                "javac_only.json": {"results": {"xax": {"performance_class": "meets-primary-target"}, "javac": {}}},
                "jvm.json": {"results": {"xax": {"performance_class": "meets-primary-target"}, "javac": {}, "kotlinc": {}}},
            }
            for name, body in cases.items():
                (root / name).write_text(json.dumps(body))
            self.assertEqual(_runtime_rule_errors("r", ["c_only.json"], root), ["r.competitive: c_only.json has no implementation outside C/C++"])
            self.assertEqual(_runtime_rule_errors("r", ["slow.json"], root), ["r.competitive: slow.json has no XAX arm within 1.05x of the fastest"])
            self.assertEqual(_runtime_rule_errors("r", ["good.json"], root), [])
            # §15.0a: a JVM comparison needs javac and kotlinc, not a C/C++ or Rust arm.
            self.assertEqual(_runtime_rule_errors("r", ["javac_only.json"], root), ["r.competitive: javac_only.json has no JVM baseline besides javac"])
            self.assertEqual(_runtime_rule_errors("r", ["jvm.json"], root), [])
        self.assertEqual(validate(MATRIX, ROOT), [])

    def test_levels_are_cumulative(self):
        row = {"fields": {"semantic_expressibility": ["STRUCTURAL", "x"], "ai_tokens": ["MEASURED", "x"]}}
        self.assertEqual(derived_level(row), "R0")  # R5 evidence cannot skip R1-R4


if __name__ == "__main__":
    unittest.main()
