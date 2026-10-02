import json
import unittest

from benchmarks import bench_oi02_granularity as bench
from xax_compiler import SemanticObject, XaxError


class GranularityEvidenceTests(unittest.TestCase):
    def test_committed_evidence_reproduces(self):
        result, _ = bench.run(collect_timing=False)
        self.assertEqual(json.loads(bench.OUTPUT.read_text()), json.loads(json.dumps(result, sort_keys=True)))

    def test_packing_is_deterministic_and_lossless(self):
        root, objects, _ = bench.build(bench.project_spec(3, 4, "chain"))
        first = bench.pack_modules(root, objects)
        again = bench.pack_modules(*bench.build(bench.project_spec(3, 4, "chain"))[:2])
        self.assertEqual([u.cid for u in first[1]], [u.cid for u in again[1]])
        unpacked = {o.cid: o for u in first[1] for o in bench.unpack(u)}
        self.assertEqual({o.cid: o for o in objects}, unpacked)

    def test_unrelated_objects_retain_cids(self):
        spec = bench.project_spec(3, 4, "star")
        _, base, _ = bench.build(spec)
        edited = {**spec, "constants": {**spec["constants"], (2, 3): (999, 2)}}
        _, cand, fns = bench.build(edited)
        base_cids, cand_cids = {o.cid for o in base}, {o.cid for o in cand}
        _, _, base_fns = bench.build(spec)
        for name, fn in base_fns.items():
            if name != (2, 3):
                self.assertEqual(fn.cid, fns[name].cid, name)
        self.assertLessEqual(len(cand_cids - base_cids), 5)

    def test_indirect_leaf_edit_keeps_caller_cids(self):
        spec = bench.project_spec(2, 4, "chain")
        _, _, base = bench.build(spec, "indirect")
        edited = {**spec, "constants": {**spec["constants"], (0, 0): (999, 2)}}
        _, _, cand = bench.build(edited, "indirect")
        self.assertNotEqual(base[(0, 0)].cid, cand[(0, 0)].cid)
        for name in base:
            if name != (0, 0):
                self.assertEqual(base[name].cid, cand[name].cid, name)

    def test_block_edit_rewrites_one_block_and_reassembles(self):
        spec = bench.project_spec(1, 2, "star", blocks=4)
        edited = {**spec, "constants": {**spec["constants"], (0, 1): (999, spec["constants"][(0, 1)][1])}}
        units = []
        for program in (spec, edited):
            bench.representation(program)  # raises unless block bytes reassemble to canonical CIDs
            _, objects, fns = bench.build(program, "block")
            fine = {o.cid: o for o in objects}
            units.append(set(bench.split_function(fine, fns[(0, 1)])[0].references))
        self.assertEqual((4, 3), (len(units[0]), len(units[0] & units[1])))

    def test_mismatched_binding_rejects(self):
        reps, _, _ = bench.representation(bench.project_spec(1, 2, "chain"))
        indirect = reps["call_indirect"]
        module = next(o for o in indirect["fine"].values() if o.kind == bench.Kind.MODULE)
        decl = next(c for c in indirect["bindings"])
        indirect["bindings"][decl] = next(v for k, v in indirect["bindings"].items() if k != decl)
        with self.assertRaises(ValueError):
            bench.verify_one(indirect, module.cid)

    def test_tampered_unit_rejects(self):
        root, objects, _ = bench.build(bench.project_spec(2, 2, "chain"))
        unit = bench.pack_modules(root, objects)[1][0]
        body = bytearray(unit.body)
        body[-1] ^= 1
        with self.assertRaises(XaxError):
            bench.unpack(SemanticObject.create(unit.kind, bytes(body), unit.references))

    def test_stable_interface_block_reassembles_and_keeps_callers(self):
        spec = bench.project_spec(2, 4, "chain", blocks=4)
        base, canonical, _ = bench.representation(spec)
        edited = {**spec, "constants": {**spec["constants"], (0, 0): (999, 2)}}
        cand, cand_canonical, _ = bench.representation(edited)
        stable, stable_cand = base["stable_interface_block"], cand["stable_interface_block"]
        leaf = stable["functions"][(0, 0)]
        self.assertNotEqual(leaf, stable_cand["functions"][(0, 0)])
        self.assertEqual(stable["declarations"][(0, 0)], stable_cand["declarations"][(0, 0)])
        for name in stable["functions"]:
            if name != (0, 0):
                self.assertEqual(stable["functions"][name], stable_cand["functions"][name], name)
        for name, body_cid in stable["functions"].items():
            self.assertEqual(stable["function_map"][body_cid].cid, canonical[name].cid)
        for name, body_cid in stable_cand["functions"].items():
            self.assertEqual(stable_cand["function_map"][body_cid].cid, cand_canonical[name].cid)

    def test_stale_interface_summary_rejects(self):
        reps, _, _ = bench.representation(bench.project_spec(1, 2, "chain", blocks=4))
        stable = reps["stable_interface_block"]
        body_cid = stable["functions"][(0, 1)]
        bad_summary = bench.call_contract((bench.B64, bench.B64), (bench.B64,), may_return=True, may_trap=True)
        bad_decl = bench.stable_declaration((0, 1), bad_summary)
        fine = dict(stable["fine"])
        fine[bad_summary.cid] = bad_summary
        fine[bad_decl.cid] = bad_decl
        decl_of_body = dict(stable["decl_of_body"])
        decl_of_body[body_cid] = bad_decl.cid
        with self.assertRaisesRegex(ValueError, "stale interface summary"):
            bench.reassemble_stable(fine, body_cid, stable["stable_bindings"], decl_of_body, {})

    def test_corrupt_stable_body_rejects(self):
        reps, _, _ = bench.representation(bench.project_spec(1, 1, "chain", blocks=4))
        stable = reps["stable_interface_block"]
        body = stable["objects"][stable["functions"][(0, 0)]]
        corrupt = SemanticObject.create(bench.BODY_KIND, body.body + b"\x00", body.references)
        fine = dict(stable["fine"])
        fine[corrupt.cid] = corrupt
        with self.assertRaises(XaxError):
            bench.split_body(fine, corrupt)

    def test_service_corpus_is_multimodule_multiblock_dag(self):
        spec = bench.service_spec()
        self.assertEqual((6, 8, 4), (spec["modules"], spec["functions"], spec["blocks"]))
        cross = sum(1 for (m, _), callee in spec["callees"].items() if callee is not None and callee[0] != m)
        local = sum(1 for (m, _), callee in spec["callees"].items() if callee is not None and callee[0] == m)
        self.assertGreater(cross, 0)
        self.assertGreater(local, 0)
        reps, canonical, indirect = bench.representation(spec)
        bench.check_semantics(spec, reps, canonical, indirect)

    def test_timing_sample_shapes_are_fixed(self):
        spec = bench.project_spec(1, 2, "star", blocks=4)
        mutations = [("edit", {"constants": {(0, 1): (1234, 2)}})]
        _, timing = bench.run_case("timing", spec, mutations, [], collect_timing=True)
        for metric in ("query_read_function_0_0", "store_encode", "store_decode"):
            for sample in timing[metric].values():
                self.assertEqual(bench.TIMING_SAMPLES, sample["count"])
                self.assertEqual(bench.TIMING_SAMPLES, len(sample["samples_ns"]))
        for sample in timing["verification"]["edit"].values():
            self.assertEqual(bench.TIMING_SAMPLES, sample["count"])


if __name__ == "__main__":
    unittest.main()
