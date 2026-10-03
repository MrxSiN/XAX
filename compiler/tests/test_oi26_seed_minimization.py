from __future__ import annotations

import io
import json
from pathlib import Path
import unittest
import zipfile

from benchmarks.bench_oi26_seed_minimization import (
    ALLOWED_KIND_NAMES,
    ALLOWED_OPERATION_NAMES,
    BASELINE_SEED,
    EVIDENCE,
    FIXED_TIME,
    M11_PROGRAM,
    M11_VECTORS,
    M14_PROGRAM,
    REACHABILITY,
    TIMING,
    VARIANT_PATHS,
    _reachability_report,
    build_variants,
    validate_candidate,
)


class OI26SeedMinimizationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.variants, cls.meta = build_variants()
        cls.baseline = BASELINE_SEED.read_bytes()
        cls.validations = {name: validate_candidate(data) for name, data in cls.variants.items()}

    def test_variants_are_deterministic_and_smaller(self):
        again, _ = build_variants()
        self.assertEqual(self.variants, again)
        for name, data in self.variants.items():
            self.assertLess(len(data), len(self.baseline), name)
            with zipfile.ZipFile(io.BytesIO(data), "r") as archive:
                self.assertEqual(tuple(info.filename for info in archive.infolist()), ("__main__.py", "blake3.py", "xax_compiler.py"))
                self.assertTrue(all(info.date_time == FIXED_TIME for info in archive.infolist()))

    def test_reachable_candidate_keeps_generic_evaluator(self):
        data = self.variants["reachable_pruned"]
        with zipfile.ZipFile(io.BytesIO(data), "r") as archive:
            source = archive.read("xax_compiler.py")
        self.assertIn(b"class CompileTimeEvaluator", source)
        self.assertEqual(self.meta["reachable_pruned"]["seed_specific_evaluator_lines"], 0)
        self.assertGreater(self.meta["specialized_subset"]["seed_specific_evaluator_lines"], 0)

    def test_every_candidate_rebuilds_two_generations_and_m11_vectors(self):
        for name, data in self.variants.items():
            with self.subTest(candidate=name):
                result = self.validations[name]
                self.assertTrue(result["m14_first_rebuild"])
                self.assertTrue(result["m14_second_rebuild"])
                self.assertTrue(result["m11_all_match"])
                self.assertEqual(len(result["m11_vectors"]), len(M11_VECTORS))

    def test_excluded_object_kind_and_operation_reject(self):
        for name, data in self.variants.items():
            with self.subTest(candidate=name):
                result = self.validations[name]
                self.assertTrue(result["unsupported_build_bundle_rejected"])
                self.assertIn("UNSUPPORTED_KIND", result["unsupported_build_bundle_diagnostic"])
                self.assertTrue(result["unsupported_operation_rejected"])
                self.assertIn("UNSUPPORTED_OP", result["unsupported_operation_diagnostic"])

    def test_corrupt_input_never_publishes_output(self):
        for name, result in self.validations.items():
            with self.subTest(candidate=name):
                self.assertTrue(result["corrupt_store_rejected"])
                self.assertEqual(result["corrupt_output_bytes"], 0)

    def test_machine_reachability_report_is_narrow(self):
        reachability = _reachability_report(self.meta)
        self.assertEqual(reachability["format"], "xax-oi26-seed-reachability-v1")
        self.assertEqual(tuple(reachability["semantic_features"]["accepted_object_kinds"]), ALLOWED_KIND_NAMES)
        self.assertEqual(tuple(reachability["semantic_features"]["accepted_operations"]), ALLOWED_OPERATION_NAMES)
        self.assertEqual(reachability["static_reachable_seed_compiler"]["selected_candidate"], "reachable_pruned")

    def test_committed_candidates_match_generation(self):
        if not all(path.exists() for path in VARIANT_PATHS.values()):
            self.skipTest("OI-26 generated seed candidates not written yet")
        for name, path in VARIANT_PATHS.items():
            with self.subTest(candidate=name):
                self.assertEqual(path.read_bytes(), self.variants[name])

    def test_committed_evidence_replays(self):
        if not (EVIDENCE.exists() and TIMING.exists() and REACHABILITY.exists()):
            self.skipTest("OI-26 evidence not written yet")
        evidence = json.loads(EVIDENCE.read_text())
        committed_timing = json.loads(TIMING.read_text())
        committed_reachability = json.loads(REACHABILITY.read_text())
        self.assertEqual(evidence["selection"]["candidate"], "reachable_pruned")
        self.assertEqual(evidence["host_observations_nonsemantic"], committed_timing["host"])
        replayed = _reachability_report(self.meta)
        # The interpreter version is a host observation of the generating run, not seed content.
        for report in (committed_reachability, replayed):
            report["implementation_dependencies"]["external_runtime"].pop("python")
        self.assertEqual(committed_reachability, replayed)
        by_name = {item["name"]: item for item in evidence["candidates"]}
        for name, data in self.variants.items():
            self.assertEqual(by_name[name]["seed_bytes"], len(data))
            self.assertEqual(by_name[name]["sha256"], __import__("hashlib").sha256(data).hexdigest())

    def test_selected_seed_is_repository_source_independent(self):
        result = self.validations["reachable_pruned"]
        self.assertTrue(result["m14_first_rebuild"])
        self.assertTrue(result["m14_second_rebuild"])

    def test_baseline_remains_immutable(self):
        self.assertEqual(len(self.baseline), 46255)
        self.assertEqual(
            __import__("hashlib").sha256(self.baseline).hexdigest(),
            "4e0c64d6f360359cc263c39817ec8cbe4cc3069edf20823755755c4d2707fe52",
        )


if __name__ == "__main__":
    unittest.main()
