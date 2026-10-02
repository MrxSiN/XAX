from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from benchmarks import bench_oi12_timing_proof as bench
from xax_compiler import RealtimeProfile, aarch64_baremetal_general_target, execute


class OI12TimingProofTests(unittest.TestCase):
    def setUp(self):
        self.fixture = bench.program_fixture()
        self.profile = RealtimeProfile(require_bounded_interrupt_mask=True)

    def proof(self, model=bench.BOUNDED_MEMORY_INTERRUPT):
        return bench.build_timing_proof(
            self.fixture.reader,
            self.fixture.functions["caller"].cid,
            self.fixture.target,
            self.profile,
            model,
        )

    def test_both_models_share_one_carrier_and_fail_closed(self):
        fixed = self.proof(bench.FIXED_IN_ORDER)
        bounded = self.proof(bench.BOUNDED_MEMORY_INTERRUPT)
        self.assertEqual(fixed.path_control_bound, bounded.path_control_bound)
        self.assertNotEqual(fixed.guarantee_cycles, bounded.guarantee_cycles)
        for proof in (fixed, bounded):
            decoded = bench.TimingProof.from_bytes(proof.canonical_bytes())
            self.assertEqual(decoded, proof)
            self.assertEqual(
                bench.check_timing_proof(
                    decoded,
                    self.fixture.reader,
                    self.fixture.functions["caller"].cid,
                    self.fixture.target,
                    self.profile,
                    bench.FIXED_IN_ORDER if proof is fixed else bench.BOUNDED_MEMORY_INTERRUPT,
                    deep=True,
                ),
                proof.guarantee_cycles,
            )

    def test_unknown_required_memory_assumption_rejects(self):
        model = bench.TimingModel(
            "unknown-memory",
            1,
            bench.BOUNDED_MEMORY_INTERRUPT.operation_cycles,
            None,
            0,
            0,
            0,
            True,
            False,
        )
        with self.assertRaisesRegex(bench.TimingProofError, "unknown-memory-bound"):
            bench.build_timing_proof(self.fixture.reader, self.fixture.functions["caller"].cid, self.fixture.target, self.profile, model)

    def test_unknown_required_interrupt_assumption_rejects(self):
        model = bench.TimingModel(
            "unknown-interrupt",
            1,
            bench.BOUNDED_MEMORY_INTERRUPT.operation_cycles,
            6,
            None,
            None,
            None,
            True,
            True,
        )
        with self.assertRaisesRegex(bench.TimingProofError, "unknown-interrupt-bound"):
            bench.build_timing_proof(self.fixture.reader, self.fixture.functions["caller"].cid, self.fixture.target, self.profile, model)

    def test_corrupt_proof_rejects(self):
        encoded = bytearray(self.proof().canonical_bytes())
        encoded[len(encoded) // 2] ^= 1
        with self.assertRaisesRegex(bench.TimingProofError, "proof-digest"):
            bench.TimingProof.from_bytes(bytes(encoded))

    def test_noncanonical_integer_rejects(self):
        encoded = self.proof().canonical_bytes()
        # Version 1 immediately follows the four-byte magic.  Replace canonical
        # 0x01 with the noncanonical two-byte ULEB 0x81 0x00.
        malformed = encoded[:4] + b"\x81\x00" + encoded[5:]
        with self.assertRaisesRegex(bench.TimingProofError, "proof-version:noncanonical"):
            bench.TimingProof.from_bytes(malformed)

    def test_stale_subject_target_profile_and_assumption_reject(self):
        proof = self.proof()
        changed_leaf = bench.program_fixture(leaf_extra=True)
        with self.assertRaisesRegex(bench.TimingProofError, "stale-subject"):
            bench.check_timing_proof(
                proof,
                changed_leaf.reader,
                changed_leaf.functions["caller"].cid,
                changed_leaf.target,
                self.profile,
                bench.BOUNDED_MEMORY_INTERRUPT,
            )
        changed_target = aarch64_baremetal_general_target()
        with self.assertRaisesRegex(bench.TimingProofError, "stale-target"):
            bench.check_timing_proof(proof, self.fixture.reader, self.fixture.functions["caller"].cid, changed_target, self.profile, bench.BOUNDED_MEMORY_INTERRUPT)
        changed_profile = RealtimeProfile(require_bounded_interrupt_mask=False)
        with self.assertRaisesRegex(bench.TimingProofError, "stale-profile"):
            bench.check_timing_proof(proof, self.fixture.reader, self.fixture.functions["caller"].cid, self.fixture.target, changed_profile, bench.BOUNDED_MEMORY_INTERRUPT)
        changed_model = bench.TimingModel(
            bench.BOUNDED_MEMORY_INTERRUPT.identity,
            bench.BOUNDED_MEMORY_INTERRUPT.version,
            bench.BOUNDED_MEMORY_INTERRUPT.operation_cycles,
            7,
            bench.BOUNDED_MEMORY_INTERRUPT.max_interrupts,
            bench.BOUNDED_MEMORY_INTERRUPT.interrupt_service_cycles,
            bench.BOUNDED_MEMORY_INTERRUPT.interrupt_mask_bound_cycles,
            True,
            True,
        )
        with self.assertRaisesRegex(bench.TimingProofError, "stale-assumption"):
            bench.check_timing_proof(proof, self.fixture.reader, self.fixture.functions["caller"].cid, self.fixture.target, self.profile, changed_model)

    def test_invalidation_frontier_is_dependency_exact(self):
        evidence = bench.collect_evidence()["invalidation"]
        self.assertEqual(evidence["unrelated_function_edit"], {"reused_roles": ["caller", "leaf"], "reused": 2, "invalidated": 1})
        self.assertEqual(evidence["callee_body_edit"], {"reused_roles": ["unrelated"], "reused": 1, "invalidated": 2})
        self.assertEqual(evidence["target_change"]["invalidated"], 3)
        self.assertEqual(evidence["profile_change"]["invalidated"], 3)
        self.assertEqual(evidence["memory_assumption_change"], {"reused_roles": ["unrelated"], "reused": 1, "invalidated": 2})
        self.assertEqual(evidence["sub_operation_assumption_change"], {"reused_roles": ["leaf", "unrelated"], "reused": 2, "invalidated": 1})
        self.assertEqual(evidence["cost_estimate_only_change"]["invalidated"], 0)

    def test_unrelated_edit_reuses_caller_proof(self):
        proof = self.proof()
        changed = bench.program_fixture(unrelated_variant=True)
        self.assertEqual(changed.functions["caller"].cid, self.fixture.functions["caller"].cid)
        self.assertEqual(
            bench.check_timing_proof(proof, changed.reader, changed.functions["caller"].cid, changed.target, self.profile, bench.BOUNDED_MEMORY_INTERRUPT),
            proof.guarantee_cycles,
        )

    def test_sidecar_deletion_does_not_change_semantics(self):
        proof_bytes = self.proof().canonical_bytes()
        before_root = self.fixture.reader.root_cid
        before_true = execute(self.fixture.reader, self.fixture.functions["caller"].cid, (1, 9))
        before_false = execute(self.fixture.reader, self.fixture.functions["caller"].cid, (0, 9))
        with tempfile.TemporaryDirectory() as directory:
            sidecar = Path(directory) / "timing.proof"
            sidecar.write_bytes(proof_bytes)
            sidecar.unlink()
            self.assertFalse(sidecar.exists())
        self.assertEqual(self.fixture.reader.root_cid, before_root)
        self.assertEqual(execute(self.fixture.reader, self.fixture.functions["caller"].cid, (1, 9)), before_true)
        self.assertEqual(execute(self.fixture.reader, self.fixture.functions["caller"].cid, (0, 9)), before_false)

    def test_query_payload_is_compact_and_tokens_are_not_fabricated(self):
        proof = self.proof()
        request = bench.timing_query_payload()
        response = bench.timing_query_response(proof.guarantee_cycles)
        self.assertLessEqual(len(request), 16)
        self.assertLessEqual(len(response), 24)
        tokens = bench.tokenizer_counts((request, response))
        if not tokens["available"]:
            self.assertIsNone(tokens["tokens"])

    def test_committed_deterministic_evidence(self):
        path = Path(__file__).resolve().parents[1] / "benchmarks" / "oi12_timing_proof_evidence.json"
        self.assertEqual(json.loads(path.read_text()), bench.collect_evidence())

    def test_timing_sample_shape(self):
        timing = bench.collect_timing(self.fixture, self.profile, (bench.FIXED_IN_ORDER,))
        self.assertEqual(timing["repetitions"], bench.TIMING_REPETITIONS)
        for metric in timing["models"][bench.FIXED_IN_ORDER.identity].values():
            self.assertEqual(len(metric["raw_ns"]), bench.TIMING_REPETITIONS)
            self.assertLessEqual(metric["min_ns"], metric["median_ns"])
            self.assertLessEqual(metric["median_ns"], metric["max_ns"])


if __name__ == "__main__":
    unittest.main()
