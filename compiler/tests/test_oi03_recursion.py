import json
import unittest

from benchmarks import bench_oi03_recursion as bench
from xax_compiler import (
    Block,
    Kind,
    Node,
    Operation,
    RecursionMember,
    StoreReader,
    Terminator,
    ValueRef,
    XaxError,
    canonical_recursion_order,
    function,
    graph_fragment,
    object_with_refs,
    recursion_group,
    verify_store,
    write_store,
)


def store(carriers, extra):
    module = object_with_refs(Kind.MODULE, carriers)
    root = object_with_refs(Kind.PROGRAM_ROOT, [module])
    objects = {o.cid: o for o in (*extra, *carriers, module, root)}
    return StoreReader(write_store(root.cid, objects.values()))


def resolver(objects):
    return {o.cid: o for o in objects}.__getitem__


def ring(order):
    """Members for functions ``order`` (a rotation of 0..n-1), each calling its successor function."""
    position = {old: new for new, old in enumerate(order)}
    members, objects = [], [bench.B64]
    for old in order:
        graph, owned = bench.recursive_graph(old, position[(old + 1) % len(order)])
        members.append(RecursionMember(graph, (bench.B1, bench.B64), (bench.B64,)))
        objects.extend(owned)
    return members, objects


class RecursionCarrierEvidenceTests(unittest.TestCase):
    def test_committed_evidence_reproduces(self):
        self.assertEqual(json.loads(bench.OUTPUT.read_text()), json.loads(json.dumps(bench.run(), sort_keys=True)))

    def test_carriers_are_deterministic(self):
        for name, arms in bench.ARMS.items():
            for arm in arms:
                first, again = bench.workload(name, arm), bench.workload(name, arm)
                self.assertEqual([c.cid for c in first["carriers"]], [c.cid for c in again["carriers"]])

    def test_group_edit_changes_every_member_identity_only_in_its_scc(self):
        churn = bench.edit_churn("mutual", "group", bench.COUNT - 1)
        self.assertEqual(churn["changed_entity_identities"], 4)  # the size-4 ring, not the two size-2 rings

    def test_same_body_under_both_carriers_has_distinct_cids(self):
        graph, owned = bench.leaf_graph(0)
        direct = function(graph, (bench.B64, bench.B64), (bench.B64,))
        wrapped = recursion_group([RecursionMember(graph, (bench.B64, bench.B64), (bench.B64,))])
        self.assertNotEqual(direct.cid, wrapped.cid)
        self.assertEqual(len(wrapped.body), len(direct.body) + 1)  # only the member count differs

    def test_direct_call_into_group_rejects(self):
        graph, owned = bench.recursive_graph(0, 0)
        group = recursion_group([RecursionMember(graph, (bench.B1, bench.B64), (bench.B64,))])
        a, b = ValueRef.parameter(0, 0), ValueRef.parameter(0, 1)
        caller_graph = graph_fragment(
            [Block((bench.B1, bench.B64), (Node(Operation.CALL_DIRECT, (a, b), (bench.B64,), entity=group),), Terminator.return_((ValueRef.node_result(0, 0),)))]
        )
        caller = function(caller_graph, (bench.B1, bench.B64), (bench.B64,))
        with self.assertRaisesRegex(XaxError, "XAX.STRUCT.CALL_TARGET"):
            verify_store(store([caller, group], [bench.B64, *owned, caller_graph]))

    def test_group_member_call_in_direct_function_rejects(self):
        graph, owned = bench.recursive_graph(0, 0)
        carrier = function(graph, (bench.B1, bench.B64), (bench.B64,))
        with self.assertRaisesRegex(XaxError, "XAX.STRUCT.GROUP_CALL_CONTEXT"):
            verify_store(store([carrier], [bench.B64, *owned]))

    def test_non_recursive_singleton_group_rejects(self):
        graph, owned = bench.leaf_graph(0)
        group = recursion_group([RecursionMember(graph, (bench.B64, bench.B64), (bench.B64,))])
        with self.assertRaisesRegex(XaxError, "XAX.STRUCT.RECURSION_SCC"):
            verify_store(store([group], [bench.B64, *owned]))
        with self.assertRaises(ValueError):
            canonical_recursion_order([RecursionMember(graph, (bench.B64, bench.B64), (bench.B64,))], resolver([bench.B64, *owned]))

    def test_group_of_two_separate_sccs_rejects(self):
        (g0, o0), (g1, o1) = bench.recursive_graph(0, 0), bench.recursive_graph(1, 1)
        group = recursion_group([RecursionMember(g, (bench.B1, bench.B64), (bench.B64,)) for g in (g0, g1)])
        with self.assertRaisesRegex(XaxError, "XAX.STRUCT.RECURSION_SCC"):
            verify_store(store([group], [bench.B64, *o0, *o1]))

    def test_every_rotation_canonicalizes_to_one_group(self):
        size = 4
        cids, rejected = set(), 0
        for shift in range(size):
            order = [(i + shift) % size for i in range(size)]
            members, objects = ring(order)
            group = recursion_group(members)
            try:
                verify_store(store([group], objects))
            except XaxError as error:
                self.assertEqual(error.diagnostic.code, "XAX.CANON.RECURSION_ORDER")
                rejected += 1
            canonical = canonical_recursion_order(members, resolver(objects))
            members, objects = ring([order[i] for i in canonical])
            group = recursion_group(members)
            verify_store(store([group], objects))
            cids.add(group.cid)
        self.assertEqual(len(cids), 1)
        self.assertEqual(rejected, size - 1)

    def test_out_of_range_member_rejects(self):
        graph, owned = bench.recursive_graph(0, 1)
        group = recursion_group([RecursionMember(graph, (bench.B1, bench.B64), (bench.B64,))])
        with self.assertRaisesRegex(XaxError, "XAX.STRUCT.RECURSION_MEMBER"):
            verify_store(store([group], [bench.B64, *owned]))


if __name__ == "__main__":
    unittest.main()
