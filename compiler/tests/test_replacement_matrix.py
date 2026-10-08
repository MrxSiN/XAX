"""The replacement matrix may never claim a level its evidence does not support."""
import copy
import csv
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from xax_replacement import derived_level, load, recompute_runtime_verdict, validate

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
        self.assertIn("windows-x86_64-pe: claimed R4 but evidence supports R2", errors)
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
        # ADR-177: the R4 comparisons kept no raw samples, so the row stops at R3.
        self.assertEqual(derived_level(row), "R3")

    def test_summary_only_performance_cannot_be_measured_or_competitive(self):
        bad = copy.deepcopy(MATRIX)
        row = next(r for r in bad["platforms"] if r["id"] == "linux-x86_64")
        summary_only = "compiler/benchmarks/oi41_links_evidence.json"  # median/min/stdev only (pre-ADR-177)
        row["fields"]["performance"] = ["MEASURED", summary_only]
        row["competitive"] = [True, summary_only]
        row["level"] = "R4"
        errors = validate(bad, ROOT)
        self.assertIn("linux-x86_64.performance: MEASURED performance needs 5+ raw samples to recompute from", errors)
        self.assertTrue(any(e.startswith("linux-x86_64.competitive: verdict True but recomputation") for e in errors), errors)
        self.assertIn("linux-x86_64: claimed R4 but evidence supports R3", errors)

    def test_android_runtime_r4_needs_c_and_non_c_hardware_baselines(self):
        row = next(r for r in MATRIX["platforms"] if r["id"] == "android-arm64")
        evidence = json.loads((ROOT / "compiler/benchmarks/android_counter_twin_evidence.json").read_text())
        platform = json.loads((ROOT / "compiler/benchmarks/android_platform_runtime_probe_evidence.json").read_text())
        # ADR-207: 1.007x the fastest non-XAX arm is above the 0.9999x R4 target.
        self.assertEqual(derived_level(row), "R3")
        self.assertIn("1.007273x the fastest non-XAX arm", recompute_runtime_verdict(row["competitive"][1:])[0])
        self.assertEqual(set(evidence["results"]), {"xax", "clang_ndk_java", "java_d8"})
        self.assertEqual(len(evidence["device"]["xax_pass_ratios_vs_fastest"]), evidence["device"]["passes"])
        without_java = {**evidence, "results": {k: v for k, v in evidence["results"].items() if k != "java_d8"}}
        with tempfile.TemporaryDirectory() as directory:  # a single C-family baseline stops at R3 again
            (Path(directory) / "one.json").write_text(json.dumps(without_java))
            self.assertTrue(recompute_runtime_verdict(["one.json"], Path(directory)))
        self.assertTrue(evidence["device"]["hardware"])
        self.assertTrue(platform["runtime"]["hardware"])
        self.assertTrue(platform["runtime"]["arm64_native"])
        self.assertTrue(platform["runtime"]["executed"])

    def test_documents_sources_and_images_alone_never_prove_execution(self):
        bad = copy.deepcopy(MATRIX)
        row = next(r for r in bad["platforms"] if r["id"] == "aarch64-baremetal")
        row["fields"]["real_execution"] = ["EXECUTED", "XAX_STATE.md", "compiler/src/xax_board.py", "compiler/integration/android/activity_after_click.png"]
        errors = validate(bad, ROOT)
        self.assertIn("aarch64-baremetal.real_execution: EXECUTED cites only supporting files (documents, sources, scripts, images)", errors)
        self.assertEqual(derived_level(row), "R0")
        row["fields"]["code_size"] = ["MEASURED", "compiler/tests/test_xax_board.py"]
        self.assertIn("aarch64-baremetal.code_size: MEASURED needs a recorded .json/.csv result", validate(bad, ROOT))

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

    def test_competitive_verdict_must_equal_recomputation(self):
        bad = copy.deepcopy(MATRIX)
        target = next(r for r in bad["platforms"] if r["id"] == "jvm")
        self.assertEqual(derived_level(target), "R4")
        target["competitive"] = [False, "compiler/benchmarks/jvm_jsonmin_evidence.json"]
        self.assertTrue(any(e.startswith("jvm.competitive: verdict False but recomputation") for e in validate(bad, ROOT)))
        target["competitive"] = [True]
        self.assertIn("jvm.competitive: expected [bool, evidence...]", validate(bad, ROOT))

    def test_runtime_verdict_is_recomputed_from_raw_samples(self):
        import tempfile

        from xax_replacement import recompute_runtime_verdict

        faster, fast, slow = [0.8] * 5, [1.0] * 5, [1.2] * 5
        host = {"cpu": "x"}
        arm = lambda samples, **extra: {"wall_seconds_samples": samples, **extra}  # noqa: E731
        cases = {
            "c_only.json": {"host": host, "results": {"xax": arm(fast), "gcc-O2": arm(fast), "clang-O2": arm(fast)}},
            "slow.json": {"host": host, "results": {"xax": arm(slow, performance_class="meets-primary-target"), "gcc-O2": arm(fast), "rustc-O3": arm(fast)}},
            "tie.json": {"host": host, "results": {"xax": arm(fast), "gcc-O2": arm(fast), "rustc-O3": arm(slow)}},
            "good.json": {"host": host, "results": {"xax": arm(faster, time_ratio_vs_fastest_competitor=0.8), "gcc-O2": arm(fast), "rustc-O3": arm(slow)}},
            "lying.json": {"host": host, "results": {"xax": arm(faster, time_ratio_vs_fastest=0.8), "gcc-O2": arm(fast), "rustc-O3": arm(fast)}},
            "lying_competitor.json": {"host": host, "results": {"xax": arm(faster, time_ratio_vs_fastest_competitor=0.5), "gcc-O2": arm(fast), "rustc-O3": arm(fast)}},
            "few.json": {"host": host, "results": {"xax": arm([1.0]), "gcc-O2": arm(fast), "rustc-O3": arm(fast)}},
            "nohost.json": {"results": {"xax": arm(fast), "gcc-O2": arm(fast), "rustc-O3": arm(fast)}},
            "javac_only.json": {"host": host, "results": {"xax": arm(fast), "javac": arm(fast), "javac-O": arm(fast)}},
            "jvm.json": {"host": host, "results": {"xax": arm(faster), "javac": arm(fast), "kotlinc": arm(slow)}},
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, body in cases.items():
                (root / name).write_text(json.dumps(body))
            check = lambda name: recompute_runtime_verdict([name], root)  # noqa: E731
            self.assertEqual(check("c_only.json"), ["c_only.json: baselines do not meet the 15.0/15.0a policy"])
            # performance_class is never trusted: the samples say 1.2x.
            self.assertEqual(check("slow.json"), ["slow.json: XAX median is 1.200000x the fastest non-XAX arm (gcc-O2); R4 needs <= 0.9999x"])
            # ADR-207: equal to the fastest competitor is not leadership.
            self.assertEqual(check("tie.json"), ["tie.json: XAX median is 1.000000x the fastest non-XAX arm (gcc-O2); R4 needs <= 0.9999x"])
            self.assertEqual(check("good.json"), [])
            self.assertEqual(check("lying.json"), ["lying.json: xax publishes ratio 0.8, raw samples give 1.000000"])
            self.assertEqual(check("lying_competitor.json"), ["lying_competitor.json: xax publishes competitor ratio 0.5, raw samples give 0.800000"])
            self.assertEqual(check("few.json"), ["few.json: an arm lacks 5+ raw wall_seconds_samples"])
            self.assertEqual(check("nohost.json"), ["nohost.json: no host/hardware identity"])
            self.assertEqual(check("javac_only.json"), ["javac_only.json: baselines do not meet the 15.0/15.0a policy"])
            self.assertEqual(check("jvm.json"), [])
            self.assertEqual(recompute_runtime_verdict(["good.json"], root, emulated=True), ["emulated execution is never performance evidence"])
        self.assertEqual(validate(MATRIX, ROOT), [])

    def test_r4_margin_is_exact_and_noise_is_not_leadership(self):
        """ADR-207: 0.9999x is compared unrounded, and a margin inside the noise withholds R4."""
        host = {"cpu": "x"}
        base = [1.0, 1.01, 0.99, 1.02, 0.98, 1.0, 1.01, 0.99]
        cases = {
            # 0.99995x: within 0.0001 of parity, so above the target even though it rounds to 1.000.
            "margin.json": {"xax": [v * 0.99995 for v in base], "gcc-O2": base, "rustc-O3": [v * 1.2 for v in base]},
            # 0.99x median but samples overlap the competitor's spread: not significant.
            "noisy.json": {"xax": [0.70, 1.30, 0.99, 0.60, 1.40, 0.99, 1.2, 0.8], "gcc-O2": base, "rustc-O3": [v * 1.2 for v in base]},
            # 0.9x with tight samples: significant leadership.
            "lead.json": {"xax": [v * 0.9 for v in base], "gcc-O2": base, "rustc-O3": [v * 1.2 for v in base]},
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, arms in cases.items():
                (root / name).write_text(json.dumps({"host": host, "results": {a: {"wall_seconds_samples": v} for a, v in arms.items()}}))
            self.assertIn("R4 needs <= 0.9999x", recompute_runtime_verdict(["margin.json"], root)[0])
            self.assertIn("within noise", recompute_runtime_verdict(["noisy.json"], root)[0])
            self.assertEqual(recompute_runtime_verdict(["lead.json"], root), [])

    def test_levels_are_cumulative(self):
        row = {"fields": {"semantic_expressibility": ["STRUCTURAL", "x"], "autonomous_maintenance": ["EXECUTED", "x"]}}
        self.assertEqual(derived_level(row), "R0")  # R5 evidence cannot skip R1-R4

    def test_r5_is_maintenance_r6_is_xax_only_application_and_tokens_gate_nothing(self):
        """ADR-207: AI-token evidence is historical; R5 needs executed maintenance, R6 an executed XAX-only application."""
        row = copy.deepcopy(next(r for r in MATRIX["platforms"] if r["id"] == "jvm"))
        self.assertEqual(derived_level(row), "R4")
        row["fields"]["ai_tokens"] = ["MEASURED", "compiler/benchmarks/ai_native/jvm-r5-optimized-evidence.json"]
        self.assertEqual(derived_level(row), "R4")
        row["fields"]["autonomous_maintenance"] = ["EXECUTED", "compiler/benchmarks/m6_workspace_smoke.json"]
        self.assertEqual(derived_level(row), "R5")
        row["fields"]["xax_only_application"] = ["STRUCTURAL", "compiler/benchmarks/m6_workspace_smoke.json"]
        self.assertEqual(derived_level(row), "R5")
        row["fields"]["xax_only_application"] = ["EXECUTED", "XAX_STATE.md"]
        self.assertEqual(derived_level(row), "R5")  # a document alone never shows execution
        row["fields"]["xax_only_application"] = ["EXECUTED", "compiler/benchmarks/m6_workspace_smoke.json"]
        self.assertEqual(derived_level(row), "R6")

    def test_jvm_r5_candidate_evidence_is_consistent(self):
        row = next(r for r in MATRIX["platforms"] if r["id"] == "jvm")
        evidence_path = ROOT / "compiler/benchmarks/ai_native/jvm-r5-optimized-evidence.json"
        results_path = ROOT / "compiler/benchmarks/ai_native/jvm-r5-optimized-results.csv"
        evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
        with results_path.open(newline="", encoding="utf-8") as file:
            rows = list(csv.DictReader(file))
        self.assertEqual(derived_level(row), "R4")  # historical AI-token evidence (ADR-207) gates no level
        self.assertEqual(row["fields"]["ai_tokens"][0], "PROTOTYPE")
        self.assertEqual(len(rows), 10)
        self.assertEqual({r["model"] for r in rows}, {"gpt-5.6-luna"})
        self.assertEqual({r["reasoning"] for r in rows}, {"low"})
        self.assertTrue(all(r["pass"] == "TRUE" and r["turns"] == "1" for r in rows))
        totals = {arm: sum(int(r["total_tokens"]) for r in rows if r["arm"] == arm) for arm in ("C", "XAX-DIRECT")}
        self.assertEqual(totals, {"C": 197252, "XAX-DIRECT": 98432})
        self.assertEqual(evidence["results"]["c"]["total_tokens"], totals["C"])
        self.assertEqual(evidence["results"]["xax"]["total_tokens"], totals["XAX-DIRECT"])
        self.assertTrue(evidence["results"]["meets_50_percent_reduction_gate"])
        self.assertLessEqual(evidence["results"]["xax_over_c_total_tokens"], 0.5)
        self.assertEqual(hashlib.sha256(results_path.read_bytes()).hexdigest(), evidence["source"]["sha256"])


if __name__ == "__main__":
    unittest.main()
