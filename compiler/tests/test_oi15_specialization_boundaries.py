from __future__ import annotations

import json
import unittest
from pathlib import Path

from benchmarks.bench_oi15_specialization_boundaries import (
    SpecArg,
    SpecRequest,
    _record,
    build_corpus,
    decode_module_cache,
    decode_record,
    fragment_cache_records,
    function_request_key,
    materialized_store,
    module_cache_record,
    requests,
    run_deterministic,
    shell_request_key,
    specialize,
    validate_results,
    whole_cache_records,
)
from xax_compiler import Block, Kind, Node, Operation, Terminator, ValueRef, function, graph_fragment


class OI15SpecializationBoundaryTests(unittest.TestCase):
    def test_corpus_specializations_verify_and_match_reference_execution(self):
        corpus = build_corpus()
        results = tuple(specialize(corpus, request) for request in requests(corpus))
        measured = validate_results(corpus, results)
        self.assertEqual(measured, {"executions_compared": 8, "unique_specialized_functions": 7})
        self.assertEqual(results[0].function.cid, results[1].function.cid)
        self.assertEqual(len({result.graph.cid for result in results}), 7)

    def test_multi_block_and_nested_specializations_are_present(self):
        corpus = build_corpus()
        results = {result.request.name: result for result in (specialize(corpus, request) for request in requests(corpus))}
        self.assertNotEqual(results["nested-7x2"].function.cid, results["nested-7x3"].function.cid)
        self.assertNotEqual(results["nested-7x2"].graph.cid, results["nested-7x3"].graph.cid)
        self.assertEqual(len(results["choose-true-bias7"].remaining_parameters), 1)

    def test_cache_boundaries_account_exactly(self):
        evidence = run_deterministic()
        whole = evidence["arms"]["whole_function"]
        fragment = evidence["arms"]["shared_fragment_shell"]
        module = evidence["arms"]["module_aggregate"]
        self.assertEqual((whole["cache_objects"], whole["cache_bytes"]), (7, 700))
        self.assertEqual((fragment["cache_objects"], fragment["cache_bytes"]), (14, 1400))
        self.assertEqual((module["cache_objects"], module["cache_bytes"]), (1, 486))
        self.assertEqual(fragment["extra_body_reuse_beyond_whole_function"], 0)
        self.assertEqual(whole["canonical_store_bytes"], fragment["canonical_store_bytes"])
        self.assertEqual(whole["canonical_store_bytes"], module["canonical_store_bytes"])
        self.assertEqual(whole["canonical_store_objects"], 33)

    def test_one_input_change_invalidation_is_local_for_function_and_fragment(self):
        evidence = run_deterministic()
        whole = evidence["arms"]["whole_function"]
        fragment = evidence["arms"]["shared_fragment_shell"]
        module = evidence["arms"]["module_aggregate"]
        self.assertEqual(whole["one_input_change_store_added_objects"], 5)
        self.assertEqual(whole["one_input_change_store_removed_objects"], 5)
        self.assertEqual(whole["one_input_change_store_rewrite_bytes"], 815)
        self.assertEqual(whole["one_input_change_cache_bytes"], 100)
        self.assertEqual(fragment["one_input_change_cache_bytes"], 200)
        self.assertEqual(module["one_input_change_cache_bytes"], 486)

    def test_whole_record_rejects_corrupt_and_stale_keys(self):
        corpus = build_corpus()
        result = specialize(corpus, requests(corpus)[0])
        record = _record(b"SPF1", result.request_key, result.function.cid)
        self.assertEqual(decode_record(record, b"SPF1", result.request_key), result.function.cid)
        corrupt = bytearray(record)
        corrupt[40] ^= 1
        with self.assertRaisesRegex(ValueError, "corrupt"):
            decode_record(bytes(corrupt), b"SPF1", result.request_key)
        stale = bytes([result.request_key[0] ^ 1]) + result.request_key[1:]
        with self.assertRaisesRegex(ValueError, "stale"):
            decode_record(record, b"SPF1", stale)
        with self.assertRaisesRegex(ValueError, "wrong"):
            decode_record(record, b"SPG1", result.request_key)

    def test_fragment_records_reassemble_exact_function_identity(self):
        corpus = build_corpus()
        result = specialize(corpus, requests(corpus)[4])
        records = fragment_cache_records((result,))
        graph_cid = decode_record(records[0], b"SPG1", result.body_key)
        function_cid = decode_record(records[1], b"SPS1", result.shell_key)
        self.assertEqual(graph_cid, result.graph.cid)
        self.assertEqual(function_cid, result.function.cid)
        self.assertEqual(shell_request_key(result.graph.cid, result.remaining_parameters, (corpus.b32,)), result.shell_key)

    def test_module_aggregate_rejects_corruption_and_staleness(self):
        corpus = build_corpus()
        results = tuple(specialize(corpus, request) for request in requests(corpus))
        record = module_cache_record(results)
        expected = {result.request_key: result.function.cid for result in results}
        decode_module_cache(record, expected)
        corrupt = bytearray(record)
        corrupt[-1] ^= 1
        with self.assertRaisesRegex(ValueError, "corrupt"):
            decode_module_cache(bytes(corrupt), expected)
        stale = dict(expected)
        key = next(iter(stale))
        stale[key] = bytes(32)
        with self.assertRaisesRegex(ValueError, "stale"):
            decode_module_cache(record, stale)

    def test_cache_key_includes_source_identity_and_specialization_input(self):
        corpus = build_corpus()
        req = requests(corpus)[0]
        original = function_request_key(req.source_cid, req.args)
        changed_value = function_request_key(req.source_cid, (SpecArg(1, corpus.b32.cid, 8),))
        source = corpus.functions["add_bias"]
        changed_graph = graph_fragment((Block(
            (corpus.b32, corpus.b32),
            (Node(Operation.SUB_WRAP, (ValueRef.parameter(0, 0), ValueRef.parameter(0, 1)), (corpus.b32,)),),
            Terminator.return_((ValueRef.node_result(0, 0),)),
        ),))
        changed_source = function(changed_graph, (corpus.b32, corpus.b32), (corpus.b32,))
        changed_source_key = function_request_key(changed_source.cid, req.args)
        self.assertNotEqual(original, changed_value)
        self.assertNotEqual(original, changed_source_key)
        self.assertNotEqual(source.cid, changed_source.cid)

    def test_dead_specialization_is_absent_after_optimization(self):
        evidence = run_deterministic()
        dead = evidence["dead_specialization"]
        self.assertTrue(dead["present_before_optimization"])
        self.assertFalse(dead["present_after_optimization"])
        self.assertLess(dead["post_objects"], dead["pre_objects"])

    def test_downstream_optimization_reduces_total_code_size(self):
        evidence = run_deterministic()
        opt = evidence["optimization"]
        self.assertEqual(opt["before_code_bytes"], 232)
        self.assertEqual(opt["after_code_bytes"], 137)
        self.assertLess(opt["after_code_bytes"], opt["before_code_bytes"])

    def test_evidence_file_matches_regeneration(self):
        path = Path(__file__).parents[1] / "benchmarks" / "oi15_specialization_boundaries_evidence.json"
        recorded = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(recorded, run_deterministic())


if __name__ == "__main__":
    unittest.main()
