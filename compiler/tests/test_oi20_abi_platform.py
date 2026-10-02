from __future__ import annotations

import json
import unittest
from pathlib import Path

from benchmarks import bench_oi20_abi_platform as bench

HERE = Path(__file__).resolve().parent
EVIDENCE = HERE.parent / "benchmarks" / "oi20_abi_platform_evidence.json"
RAW = HERE.parent / "benchmarks" / "oi20_abi_platform_timing.json"


class OI20AbiPlatformTests(unittest.TestCase):
    def test_abi_carriers_round_trip_and_are_exact(self):
        for make in (bench.win64_carrier, bench.aapcs64_carrier, bench._android_carrier):
            carrier = make()
            encoded = bench.encode_abi(carrier)
            self.assertEqual(bench.decode_abi(encoded), carrier)
            self.assertEqual(bench.carrier_cid(carrier), bench.hashlib.sha256(encoded).digest())

    def test_abi_carrier_corruption_version_and_unknown_mode_reject(self):
        encoded = bytearray(bench.encode_abi(bench.win64_carrier()))
        encoded[-1] ^= 1
        with self.assertRaisesRegex(ValueError, "digest"):
            bench.decode_abi(bytes(encoded))
        encoded = bytearray(bench.encode_abi(bench.win64_carrier()))
        encoded[4] += 1
        with self.assertRaisesRegex(ValueError, "magic/version"):
            bench.decode_abi(bytes(encoded))
        carrier = bench.win64_carrier()
        bad = bench.AbiCarrier(
            carrier.identity, carrier.pointer_bytes, carrier.stack_alignment, carrier.shadow_space, 99,
            carrier.gpr_args, carrier.fpr_args, carrier.gpr_result, carrier.fpr_result,
            carrier.indirect_result_register, carrier.scratch_registers, carrier.direct_aggregate_sizes,
            carrier.split_aggregate_max, carrier.hfa_max_members, carrier.hfa_member_sizes,
            carrier.stack_slot_alignment,
        )
        with self.assertRaisesRegex(ValueError, "classifier mode"):
            bench.decode_abi(bench.encode_abi(bad))

    def test_candidate_matches_existing_backend_classification(self):
        conformance = bench._backend_conformance()
        self.assertTrue(conformance["aapcs64_physical_plan_match"])
        self.assertTrue(conformance["win64_by_reference_match"])

    def test_unclassifiable_signature_rejects_deterministically(self):
        result = bench._diagnostics()
        self.assertTrue(result["unclassifiable_signature_rejected"])
        self.assertEqual(result["diagnostic"], "abi.unclassifiable_type: unsupported type form")

    def test_existing_boundary_emission_is_byte_identical(self):
        rows = bench._compile_equivalence()
        self.assertEqual({row["boundary"] for row in rows}, {"windows_x86_64", "aapcs64_baremetal", "android_aapcs64_bionic"})
        self.assertTrue(all(row["identical"] for row in rows))
        android = next(row for row in rows if row["boundary"] == "android_aapcs64_bionic")
        self.assertEqual(android["imports"], ["getpid"])
        self.assertEqual(android["needed"], ["libc.so"])

    def test_parameterized_capabilities_remove_authority_overgrant(self):
        rows, unsupported = bench._capability_experiment()
        self.assertEqual(len(rows), 3)
        self.assertTrue(all(row["parameterized_authority_overgrant_members"] == 0 for row in rows))
        self.assertTrue(all(row["coarse_authority_overgrant_members"] > 0 for row in rows))
        self.assertTrue(all(row["requested_satisfied_coarse"] and row["requested_satisfied_parameterized"] for row in rows))
        self.assertTrue(all(row["unrelated_same_family_satisfied_coarse"] for row in rows))
        self.assertTrue(all(not row["unrelated_same_family_satisfied_parameterized"] for row in rows))
        self.assertTrue(unsupported["rejected"])
        self.assertEqual(unsupported["diagnostic"], "platform.unsupported_operation")

    def test_foreign_contract_inference_is_suggestion_until_verified_materialization(self):
        evidence = bench._foreign_inference_evidence()
        self.assertFalse(evidence["suggestion_authoritative"])
        self.assertTrue(evidence["materialized_authoritative"])
        self.assertTrue(evidence["mismatch_rejected"])

    def test_aapcs64_android_reuse_all_classification_fields(self):
        metrics = bench._package_metrics()
        self.assertEqual(
            metrics["aapcs64_android_reused_classification_fields"],
            metrics["aapcs64_android_classification_fields"],
        )
        self.assertEqual(metrics["candidate_objects"], 3)

    def test_model_token_cost_is_not_fabricated(self):
        evidence = bench.collect_deterministic_evidence()
        self.assertIsNone(evidence["model_tokens"])
        self.assertIsNone(evidence["ai_payload"]["tokenizer_model_tokens"])
        self.assertGreater(evidence["ai_payload"]["classification_query_bytes"], 0)

    def test_committed_evidence_replays_from_raw_samples(self):
        raw = json.loads(RAW.read_text())
        expected = json.loads(EVIDENCE.read_text())
        actual = bench.evidence_from_raw(bench.collect_deterministic_evidence(), raw)
        self.assertEqual(actual, expected)


if __name__ == "__main__":
    unittest.main()
