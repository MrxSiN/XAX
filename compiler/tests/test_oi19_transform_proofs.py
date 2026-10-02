from __future__ import annotations

import json
import unittest
from pathlib import Path

from benchmarks import bench_oi19_transform_proofs as bench


HERE = Path(__file__).resolve().parent
EVIDENCE = HERE.parent / "benchmarks" / "oi19_transform_proof_evidence.json"
RAW = HERE.parent / "benchmarks" / "oi19_transform_proof_timing.json"


class OI19TransformProofTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases, cls.faults = bench.build_corpus()

    def test_correct_transforms_verify_and_witness_without_false_rejection(self):
        for case in self.cases:
            self.assertTrue(bench._verifier_accepts(case.candidate_reader), case.name)
            self.assertTrue(bench.check_witness(case.source_reader, case.candidate_reader, case.witness), case.name)
            if case.pure:
                self.assertTrue(
                    bench.exact_finite_translation_validation(case.source_reader, case.source, case.candidate_reader, case.candidate),
                    case.name,
                )

    def test_all_injected_faults_are_detected_by_witness(self):
        self.assertEqual(len(self.faults), 7)
        for fault in self.faults:
            self.assertFalse(bench._witness_accepts(fault), fault.name)

    def test_ordinary_verifier_catches_dominance_but_not_semantic_faults(self):
        by_name = {fault.name: fault for fault in self.faults}
        self.assertFalse(bench._verifier_accepts(by_name["dominance_error"].candidate_reader))
        for name in (
            "dropped_effect",
            "wrong_constant",
            "overflow_assumption",
            "wrong_cfg_edge",
            "wrong_inline_argument",
            "dropped_dependency",
        ):
            self.assertTrue(bench._verifier_accepts(by_name[name].candidate_reader), name)

    def test_finite_oracle_detects_every_applicable_pure_fault(self):
        applicable = 0
        for fault in self.faults:
            result = bench._translation_accepts(fault)
            if result is not None:
                applicable += 1
                self.assertFalse(result, fault.name)
        self.assertEqual(applicable, 6)

    def test_polynomial_validator_accepts_search_candidate_and_rejects_dependency_drop(self):
        search = next(case for case in self.cases if case.transform_class == "search")
        ok, _ = bench._poly_expected(search.source_reader, search.source, search.candidate_reader, search.candidate)
        self.assertTrue(ok)
        fault = next(item for item in self.faults if item.name == "dropped_dependency")
        ok, _ = bench._poly_expected(fault.source_reader, fault.source, fault.candidate_reader, fault.candidate)
        self.assertFalse(ok)

    def test_witness_binds_exact_subject_candidate_and_dependencies(self):
        for case in self.cases:
            rule, block, node, subject, candidate, dependencies = bench.decode_witness(case.witness)
            self.assertEqual(subject, case.source.cid)
            self.assertEqual(candidate, case.candidate.cid)
            self.assertIn(rule, bench.RULE_NAMES)
            self.assertGreaterEqual(len(dependencies), 1)
            self.assertGreaterEqual(block, 0)
            self.assertGreaterEqual(node, 0)

    def test_stale_candidate_identity_and_corruption_reject(self):
        case = next(item for item in self.cases if item.name == "local_const_fold")
        damaged = bytearray(case.witness)
        damaged[42] ^= 1
        with self.assertRaises(KeyError):
            bench.check_witness(case.source_reader, case.candidate_reader, bytes(damaged))
        with self.assertRaises(ValueError):
            bench.decode_witness(case.witness + b"\x00")
        bad_version = bytearray(case.witness)
        bad_version[4] += 1
        with self.assertRaises(ValueError):
            bench.decode_witness(bytes(bad_version))

    def test_failed_validation_keeps_last_accepted_output(self):
        # Acceptance is deliberately transactional: a rejected candidate never
        # replaces the known-good function identity.
        for fault in self.faults:
            accepted = fault.source.cid
            if bench._witness_accepts(fault):
                accepted = fault.candidate.cid
            self.assertEqual(accepted, fault.source.cid, fault.name)

    def test_proof_sidecar_is_nonsemantic(self):
        for case in self.cases:
            before = case.candidate.cid
            _ = case.witness
            del _
            self.assertEqual(case.candidate.cid, before)
            self.assertNotIn(case.witness, case.candidate_reader.data)

    def test_implementation_accounting_rejects_solver_complexity(self):
        sizes = bench.implementation_sizes()
        self.assertEqual(sizes["solver_dependency_lines"], 0)
        self.assertLess(sizes["benchmark_witness_codec_checker_lines"], sizes["existing_trusted_local_cfg_inline_generator_lines"])
        self.assertLess(sizes["existing_exact_polynomial_validator_lines"], sizes["benchmark_witness_codec_checker_lines"])

    def test_committed_evidence_replays_from_raw_samples(self):
        raw = json.loads(RAW.read_text())
        expected = json.loads(EVIDENCE.read_text())
        self.assertEqual(bench.evidence_from_raw(raw), expected)
        self.assertEqual(expected["fault_detection"]["witness"], 7)
        self.assertEqual(expected["fault_detection"]["verifier"], 1)
        self.assertEqual(expected["false_rejection"], {"finite_translation": 0, "verifier": 0, "witness": 0})


if __name__ == "__main__":
    unittest.main()
