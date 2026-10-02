import json
import unittest
from pathlib import Path

from compiler.benchmarks.bench_oi08_effect_edges import (
    EffectEncodingError,
    EffectOrder,
    branch_fixture,
    branch_order,
    collect_evidence,
    decode_explicit_frontier,
    decode_reconstructed,
    encode_explicit_frontier,
    encode_reconstructed,
    linear_fixture,
    mixed_order,
    pair_order,
    verify_candidate,
)
from xax_compiler import EffectDomain, verify_store


class OI08EffectEdgeTests(unittest.TestCase):
    def test_refined_domain_instances_verify_and_keep_independent_frontiers(self):
        for domain in (EffectDomain.MEMORY, EffectDomain.FILESYSTEM, EffectDomain.NETWORK, EffectDomain.DEVICE):
            with self.subTest(domain=domain.name):
                order = pair_order(domain)
                reader, _, _ = linear_fixture(order)
                verify_store(reader)
                self.assertEqual(len(order.keys()), 2)
                self.assertGreater(len(order.coarsen().direct_edges()), len(order.direct_edges()))

    def test_mixed_four_domain_fixture_verifies(self):
        order = mixed_order()
        reader, _, _ = linear_fixture(order)
        verify_store(reader)
        self.assertEqual(len(order.keys()), 8)
        self.assertEqual({key[0] for key in order.keys()}, {
            int(EffectDomain.MEMORY), int(EffectDomain.FILESYSTEM),
            int(EffectDomain.NETWORK), int(EffectDomain.DEVICE),
        })

    def test_explicit_and_reconstructed_encodings_preserve_exact_partial_order(self):
        for order in (pair_order(EffectDomain.MEMORY), mixed_order(), branch_order()):
            with self.subTest(events=len(order.events)):
                explicit, _ = encode_explicit_frontier(order)
                reconstructed, _ = encode_reconstructed(order)
                self.assertEqual(decode_explicit_frontier(explicit), order)
                self.assertEqual(decode_reconstructed(reconstructed), order)
                self.assertEqual(verify_candidate(explicit, order), order)
                self.assertEqual(verify_candidate(reconstructed, order), order)

    def test_reconstruction_handles_branch_merge_without_serialization_order_semantics(self):
        order = branch_order()
        # Numeric event-table order is 3,17,29, while the two roots are unordered
        # and 29 depends on both. No event-table/record order can supply that fact.
        self.assertEqual(order.events, (3, 17, 29))
        reader, _, _ = branch_fixture()
        verify_store(reader)
        encoded, _ = encode_reconstructed(order)
        self.assertEqual(decode_reconstructed(encoded), order)
        predecessor = order.predecessor_map()
        key = order.keys()[0]
        self.assertEqual(predecessor[(3, key)], ())
        self.assertEqual(predecessor[(17, key)], ())
        self.assertEqual(predecessor[(29, key)], (3, 17))

    def test_encoding_is_deterministic_under_input_mapping_order(self):
        original = mixed_order()
        footprints = dict(reversed(original.footprints))
        predecessors = {
            (event, key): preds
            for event, key, preds in reversed(original.predecessors)
        }
        rebuilt = EffectOrder.create(reversed(original.events), footprints, predecessors)
        self.assertEqual(rebuilt, original)
        self.assertEqual(encode_explicit_frontier(rebuilt), encode_explicit_frontier(original))
        self.assertEqual(encode_reconstructed(rebuilt), encode_reconstructed(original))

    def test_corruption_or_changed_frontier_is_rejected(self):
        order = mixed_order()
        encoded, _ = encode_reconstructed(order)
        corrupt = bytearray(encoded)
        corrupt[-1] ^= 1
        with self.assertRaises(EffectEncodingError):
            verify_candidate(bytes(corrupt), order)

        key = order.keys()[0]
        footprints = order.footprint_map()
        predecessors = order.predecessor_map()
        event = next(event for event in order.events if key in footprints[event] and predecessors[(event, key)])
        predecessors[(event, key)] = ()
        changed = EffectOrder.create(order.events, footprints, predecessors)
        with self.assertRaises(EffectEncodingError):
            verify_candidate(encoded, changed)

    def test_candidate_sections_are_nonsemantic_and_do_not_change_store_identity(self):
        order = mixed_order()
        reader, _, _ = linear_fixture(order)
        before_root = reader.root_cid
        before_store = reader.canonical_bytes()
        encode_explicit_frontier(order)
        encode_reconstructed(order)
        self.assertEqual(reader.root_cid, before_root)
        self.assertEqual(reader.canonical_bytes(), before_store)

    def test_committed_evidence_reproduces_deterministic_fields(self):
        committed = json.loads((Path(__file__).parents[1] / "benchmarks" / "oi08_effect_edges_evidence.json").read_text())
        actual = collect_evidence()
        self.assertEqual(actual["schema"], committed["schema"])
        self.assertEqual(actual["token_metric"], committed["token_metric"])
        self.assertEqual(actual["partition_summary"], committed["partition_summary"])
        self.assertEqual(actual["encoding_summary"], committed["encoding_summary"])
        self.assertEqual(actual["claims"], committed["claims"])
        deterministic_graph = ("root_cid", "graph_cid", "graph_body_bytes", "graph_envelope_bytes", "store_bytes", "token_atoms")
        for workload, row in committed["workloads"].items():
            for variant in row:
                self.assertEqual(actual["workloads"][workload][variant]["partial_order"], row[variant]["partial_order"])
                self.assertEqual(
                    {key: actual["workloads"][workload][variant]["graph"][key] for key in deterministic_graph},
                    {key: row[variant]["graph"][key] for key in deterministic_graph},
                )


if __name__ == "__main__":
    unittest.main()
