from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

from benchmarks.bench_oi14_comptime_policy import (
    EVIDENCE_PATH,
    HOST_PATH,
    boundary_evidence,
    compiler_like_workload,
    deterministic_evidence,
    generic_metaprogram_workload,
    target_adapter_workload,
    workloads,
)
from xax_compiler import CompileTimeEvaluator, MetaCapability, XaxError


class OI14CompileTimePolicyTests(unittest.TestCase):
    def test_three_workloads_are_deterministic_and_bounded(self):
        expected = {
            "compiler-like-body-generation": (13, 1, 288, 3, 1),
            "target-adapter-interface-generation": (9, 1, 256, 3, 1),
            "ordinary-generic-construction": (9, 2, 304, 3, 1),
        }
        for workload in workloads():
            runs = [workload.evaluate(evaluator=CompileTimeEvaluator()) for _ in range(4)]
            counters = {
                (item.steps, item.max_call_depth, item.peak_memory_bytes, len(item.created_objects), item.graph_nodes)
                for item in runs
            }
            self.assertEqual(counters, {expected[workload.identity]})
            self.assertEqual(len({tuple(obj.cid for obj in item.created_objects) for item in runs}), 1)
            self.assertEqual(len({item.values for item in runs}), 1)

    def test_interface_authority_does_not_grant_body_access(self):
        workload = target_adapter_workload()
        result = workload.evaluate()
        self.assertEqual(result.values[1:], (1, 1))
        self.assertIn(MetaCapability.INSPECT_FUNCTION_INTERFACE, workload.capabilities)
        self.assertNotIn(MetaCapability.INSPECT_FUNCTION, workload.capabilities)

    def test_body_workload_requires_both_interface_and_body_authority(self):
        workload = compiler_like_workload()
        only_body = tuple(cap for cap in workload.capabilities if cap != MetaCapability.INSPECT_FUNCTION_INTERFACE)
        only_interface = tuple(cap for cap in workload.capabilities if cap != MetaCapability.INSPECT_FUNCTION)
        with self.assertRaises(XaxError) as missing_interface:
            CompileTimeEvaluator().evaluate(
                workload.reader, workload.entry.cid, workload.arguments, capabilities=only_body, inputs=workload.inputs
            )
        self.assertEqual(missing_interface.exception.diagnostic.rule, "META-CAPABILITY-DECLARED")
        self.assertEqual(missing_interface.exception.diagnostic.expected, "inspect_function_interface")
        with self.assertRaises(XaxError) as missing_body:
            CompileTimeEvaluator().evaluate(
                workload.reader, workload.entry.cid, workload.arguments, capabilities=only_interface, inputs=workload.inputs
            )
        self.assertEqual(missing_body.exception.diagnostic.rule, "META-CAPABILITY-DECLARED")
        self.assertEqual(missing_body.exception.diagnostic.expected, "inspect_function")

    def test_boundary_below_at_above_every_budget_dimension(self):
        evidence = boundary_evidence(generic_metaprogram_workload())
        expected_rules = {
            "steps": "META-STEP-BUDGET",
            "call_depth": "META-CALL-DEPTH",
            "memory_bytes": "META-MEMORY-BUDGET",
            "semantic_objects": "META-OBJECT-BUDGET",
            "graph_nodes": "META-GRAPH-NODE-BUDGET",
        }
        for field, rule in expected_rules.items():
            row = evidence[field]
            self.assertEqual(row["below"] + 1, row["at"])
            self.assertEqual(row["at"] + 1, row["above"])
            self.assertEqual(row["failure"]["code"], "XAX.META.BUDGET")
            self.assertEqual(row["failure"]["rule"], rule)
            self.assertEqual(row["failure"]["actual"], row["at"])
            self.assertTrue(row["root_unchanged"])

    def test_simpler_step_plus_hard_caps_covers_all_workloads(self):
        evidence = deterministic_evidence()
        model = evidence["budget_models"]["semantic_steps_plus_hard_caps"]
        self.assertEqual(model["host_dependent_terms"], 0)
        self.assertEqual(model["calibration_values"], 7)
        self.assertEqual(evidence["budget_models"]["current_vector"]["workload_specific_calibration_values"], 15)
        caps = model["global_hard_caps"]
        for row in evidence["workloads"]:
            self.assertLessEqual(row["max_call_depth"], caps["call_depth"])
            self.assertLessEqual(row["peak_frame_bytes"], caps["memory_bytes"])
            self.assertLessEqual(row["constructed_objects"], caps["semantic_objects"])
            self.assertLessEqual(row["emitted_graph_nodes"], caps["graph_nodes"])
            self.assertEqual(model["workload_specific_step_limits"][row["identity"]], row["steps"])

    def test_cache_hit_preserves_deterministic_counter_record(self):
        workload = generic_metaprogram_workload()
        evaluator = CompileTimeEvaluator()
        first = workload.evaluate(evaluator=evaluator)
        second = workload.evaluate(evaluator=evaluator)
        self.assertTrue(second.cache_hit)
        self.assertEqual(
            (first.steps, first.evaluated_blocks, first.evaluated_nodes, first.peak_memory_bytes, first.graph_nodes, first.max_call_depth),
            (second.steps, second.evaluated_blocks, second.evaluated_nodes, second.peak_memory_bytes, second.graph_nodes, second.max_call_depth),
        )

    def test_deterministic_projection_reproduces_across_processes(self):
        root = Path(__file__).resolve().parents[1]
        command = [sys.executable, "-m", "benchmarks.bench_oi14_comptime_policy", "--deterministic-hash"]
        env = dict(__import__("os").environ)
        env["PYTHONPATH"] = "src:."
        hashes = [subprocess.check_output(command, cwd=root, env=env, text=True).strip() for _ in range(3)]
        self.assertEqual(len(set(hashes)), 1)
        self.assertEqual(hashes[0], deterministic_evidence()["deterministic_projection_sha256"])

    def test_committed_evidence_matches_deterministic_projection(self):
        committed = json.loads(EVIDENCE_PATH.read_text())
        current = deterministic_evidence()
        self.assertEqual(committed, current)
        self.assertTrue(committed["host_observations"]["excluded_from_budget_and_reproducibility_hash"])
        host = json.loads(HOST_PATH.read_text())
        self.assertFalse(host["semantic"])
        self.assertFalse(host["fuel_input"])
        self.assertGreaterEqual(host["samples_per_workload"], 7)
        self.assertEqual(len(host["workloads"]), 3)

    def test_capability_packet_cost_is_small_and_token_count_unclaimed(self):
        evidence = deterministic_evidence()["capability_policy"]
        self.assertEqual(evidence["split_packet_bytes"]["compiler-like-body-generation"], 4)
        self.assertEqual(evidence["coarse_packet_bytes_conceptual"]["compiler-like-body-generation"], 3)
        self.assertEqual(evidence["split_packet_bytes"]["target-adapter-interface-generation"], 5)
        self.assertIsNone(evidence["token_counts"])


if __name__ == "__main__":
    unittest.main()
