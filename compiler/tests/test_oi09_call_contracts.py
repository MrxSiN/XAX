import json
import unittest
from pathlib import Path

from compiler.benchmarks.bench_oi09_call_contracts import (
    ContractPlacementError,
    build_corpus,
    build_embedded_candidate,
    build_referenced_candidate,
    build_sealed_candidate,
    collect_evidence,
    verify_candidate,
)
from xax_compiler import (
    Block,
    EffectDomain,
    Kind,
    Node,
    Operation,
    SemanticObject,
    StoreReader,
    Terminator,
    ValueRef,
    XaxError,
    call_contract,
    derive_call_contract,
    effect_type,
    function,
    graph_fragment,
    object_with_refs,
    semantic_cid,
    verify_function_call_contract,
    verify_store,
    write_store,
)


class OI09CallContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.corpus = build_corpus()

    def test_derived_contract_is_bounded_and_matches_direct_summary(self):
        for contract, functions in zip(self.corpus.contracts, self.corpus.functions_by_contract):
            for function_cid in functions:
                verified = verify_function_call_contract(self.corpus.reader, function_cid, contract.cid)
                self.assertEqual(contract.cid, derive_call_contract(self.corpus.reader, function_cid).cid)
                self.assertEqual(verified.inputs, next(s.inputs for c, s in zip(self.corpus.contracts, self.corpus.contract_summaries) if c.cid == contract.cid))

    def test_contract_identity_is_deterministic_and_separate_from_function_identity(self):
        contract = self.corpus.contracts[0]
        summary = self.corpus.contract_summaries[0]
        objects = {obj.cid: obj for obj in self.corpus.objects}
        rebuilt = call_contract(
            tuple(objects[cid] for cid in summary.inputs),
            tuple(objects[cid] for cid in summary.outputs),
            may_return=summary.may_return,
            may_trap=summary.may_trap,
        )
        self.assertEqual(rebuilt.cid, contract.cid)
        self.assertEqual(self.corpus.mutated_contract_cid, contract.cid)
        self.assertNotEqual(self.corpus.mutated_function_old, self.corpus.mutated_function_new)

    def test_call_contract_store_rejects_noncanonical_control_flag(self):
        contract = self.corpus.contracts[0]
        bad_body = contract.body[:-1] + b"\x02"
        bad = SemanticObject.create(Kind.CALL_CONTRACT, bad_body, contract.references)
        module = object_with_refs(Kind.MODULE, [bad])
        root = object_with_refs(Kind.PROGRAM_ROOT, [module])
        referenced = {obj.cid: obj for obj in self.corpus.objects}
        objects = [*(referenced[cid] for cid in bad.references), bad, module, root]
        reader = StoreReader(write_store(root.cid, objects))
        with self.assertRaises(XaxError) as caught:
            verify_store(reader)
        self.assertEqual(caught.exception.diagnostic.rule, "SER-BOOL-CANONICAL")

    def test_effectful_function_cannot_be_bounded_by_empty_unknown_contract(self):
        effect = effect_type(EffectDomain.FILESYSTEM)
        graph = graph_fragment(
            [Block((effect,), (Node(Operation.EFFECT_STEP, (ValueRef.parameter(0, 0),), (effect,)),), Terminator.return_((ValueRef.node_result(0, 0),)))]
        )
        fn = function(graph, (effect,), (effect,))
        empty = call_contract((), (), may_return=True, may_trap=False)
        module = object_with_refs(Kind.MODULE, [fn, empty])
        root = object_with_refs(Kind.PROGRAM_ROOT, [module])
        reader = StoreReader(write_store(root.cid, [effect, graph, fn, empty, module, root]))
        verify_store(reader)
        with self.assertRaises(XaxError) as caught:
            verify_function_call_contract(reader, fn.cid, empty.cid)
        self.assertEqual(caught.exception.diagnostic.rule, "CALL-CONTRACT-BOUNDS-FUNCTION")

    def test_all_three_candidate_placements_verify_exact_bounded_contracts(self):
        candidates = (
            build_embedded_candidate(self.corpus),
            build_referenced_candidate(self.corpus),
            build_sealed_candidate(self.corpus),
        )
        for candidate in candidates:
            with self.subTest(candidate=candidate.name):
                verify_candidate(self.corpus, candidate)

    def test_sealed_dispatch_rejects_target_from_another_contract(self):
        sealed = build_sealed_candidate(self.corpus)
        first = sealed.metadata_objects[0]
        # Replace one target reference with a function from a different contract
        # while preserving a canonical candidate object; the embedded bound must reject it.
        foreign = self.corpus.functions_by_contract[1][0]
        refs = list(first.references)
        target_ref_positions = [i for i, cid in enumerate(refs) if cid in self.corpus.functions_by_contract[0]]
        self.assertTrue(target_ref_positions)
        refs[target_ref_positions[0]] = foreign
        from compiler.benchmarks.bench_oi09_call_contracts import CandidateObject, Candidate
        bad_set = CandidateObject.create(first.tag, first.body, refs)
        metadata = (bad_set, *sealed.metadata_objects[1:])
        # Redirect callable refs that named the old set to the modified set.
        callables = tuple(
            CandidateObject.create(obj.tag, obj.body, (bad_set.cid,)) if obj.references == (first.cid,) else obj
            for obj in sealed.callable_objects
        )
        bad = Candidate(sealed.name, sealed.contract_objects, metadata, callables, sealed.calls, sealed.dispatch_by_callable)
        with self.assertRaises((ContractPlacementError, XaxError)):
            verify_candidate(self.corpus, bad)

    def test_referenced_wins_base_contract_cost_while_sealed_exposes_devirtualization(self):
        evidence = collect_evidence(include_timing=False)
        self.assertEqual(evidence["decision"]["base_contract_representation"], "referenced")
        reuse = evidence["workloads"]["reuse_heavy_960_calls"]
        sparse = evidence["workloads"]["sparse_callable_960_calls"]
        self.assertLess(reuse["referenced"]["persistent_bytes"], reuse["embedded"]["persistent_bytes"])
        self.assertGreater(sparse["referenced"]["persistent_bytes"], sparse["embedded"]["persistent_bytes"])
        for rows in (reuse, sparse):
            self.assertLess(rows["referenced"]["ideal_token_atoms"], rows["embedded"]["ideal_token_atoms"])
            self.assertLess(rows["referenced"]["ideal_token_atoms"], rows["sealed"]["ideal_token_atoms"])
            self.assertEqual(rows["sealed"]["devirtualization"]["exact_target_set_callable_fraction"], 1.0)
            self.assertGreater(rows["sealed"]["package_interface_stability"]["callable_contract_refs_changed"], 0)
            self.assertEqual(rows["referenced"]["package_interface_stability"]["callable_contract_refs_changed"], 0)

    def test_committed_evidence_reproduces_deterministic_fields(self):
        committed = json.loads((Path(__file__).parents[1] / "benchmarks" / "oi09_call_contract_evidence.json").read_text())
        actual = collect_evidence(include_timing=False)
        self.assertEqual(actual["schema"], committed["schema"])
        self.assertEqual(actual["token_metric"], committed["token_metric"])
        self.assertEqual(actual["corpus"], committed["corpus"])
        self.assertEqual(actual["decision"], committed["decision"])
        self.assertEqual(actual["claims"], committed["claims"])
        for workload in ("reuse_heavy_960_calls", "sparse_callable_960_calls"):
            for name in ("embedded", "referenced", "sealed"):
                expected = {k: v for k, v in committed["workloads"][workload][name].items() if k != "verification_timing"}
                self.assertEqual(actual["workloads"][workload][name], expected)


if __name__ == "__main__":
    unittest.main()
