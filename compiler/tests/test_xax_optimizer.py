from __future__ import annotations

import unittest

from xax_compiler import (
    Block,
    Kind,
    Node,
    Operation,
    StoreReader,
    Terminator,
    ValueRef,
    bits_type,
    constant,
    execute,
    function,
    graph_fragment,
    object_with_refs,
    verify_store,
    write_store,
    x86_64_windows_target,
)
from xax_build import decode_optimization_policy, optimization_policy
from xax_optimizer import OptimizationBudget, ProfileData, optimize_function, target_cost


def store_for(functions, objects):
    module = object_with_refs(Kind.MODULE, tuple(functions))
    root = object_with_refs(Kind.PROGRAM_ROOT, (module,))
    return StoreReader(write_store(root.cid, (*objects, *functions, module, root)))


def parsed_nodes(reader, function_object):
    from xax_compiler import _decode_function_interface, _parse_graph

    objects = {obj.cid: obj for obj in reader.objects()}
    resolve = objects.__getitem__
    graph, _, _ = _decode_function_interface(function_object, resolve)
    return _parse_graph(graph, resolve).blocks


class M12OptimizerTests(unittest.TestCase):
    def test_fold_cse_dce_preserve_wrapping_semantics(self):
        b32 = bits_type(32)
        zero = constant(b32, 0)
        one = constant(b32, 1)
        graph = graph_fragment(
            [
                Block(
                    (b32,),
                    (
                        Node(Operation.CONSTANT, (), (b32,), entity=zero),
                        Node(Operation.ADD_WRAP, (ValueRef.parameter(0, 0), ValueRef.node_result(0, 0)), (b32,)),
                        Node(Operation.CONSTANT, (), (b32,), entity=one),
                        Node(Operation.MUL_WRAP, (ValueRef.node_result(0, 1), ValueRef.node_result(0, 2)), (b32,)),
                        Node(Operation.ADD_WRAP, (ValueRef.parameter(0, 0), ValueRef.node_result(0, 2)), (b32,)),
                        Node(Operation.ADD_WRAP, (ValueRef.parameter(0, 0), ValueRef.node_result(0, 2)), (b32,)),
                        Node(Operation.ADD_WRAP, (ValueRef.node_result(0, 4), ValueRef.node_result(0, 5)), (b32,)),
                        Node(Operation.MUL_WRAP, (ValueRef.parameter(0, 0), ValueRef.parameter(0, 0)), (b32,)),
                    ),
                    Terminator.return_((ValueRef.node_result(0, 6),)),
                )
            ]
        )
        fn = function(graph, (b32,), (b32,))
        reader = store_for((fn,), (b32, zero, one, graph))
        result = optimize_function(reader, fn.cid, enable_search=False)
        verify_store(result.reader)
        self.assertLess(len(parsed_nodes(result.reader, result.function)[0].nodes), 8)
        self.assertTrue(any(event.pass_name == "fold-cse-dce" for event in result.events))
        for value in (0, 1, 7, 0xFFFFFFFF, 0x80000000):
            self.assertEqual(execute(reader, fn.cid, (value,)), execute(result.reader, result.function.cid, (value,)))

    def test_cfg_constant_branch_eliminates_unreachable_block(self):
        b1 = bits_type(1)
        b32 = bits_type(32)
        false_value = constant(b1, 0)
        graph = graph_fragment(
            [
                Block(
                    (b32,),
                    (Node(Operation.CONSTANT, (), (b1,), entity=false_value),),
                    Terminator.conditional_branch(
                        ValueRef.node_result(0, 0),
                        1,
                        (ValueRef.parameter(0, 0),),
                        2,
                        (ValueRef.parameter(0, 0),),
                    ),
                ),
                Block((b32,), (), Terminator.return_((ValueRef.parameter(1, 0),))),
                Block((b32,), (), Terminator.return_((ValueRef.parameter(2, 0),))),
            ]
        )
        fn = function(graph, (b32,), (b32,))
        reader = store_for((fn,), (b1, b32, false_value, graph))
        result = optimize_function(reader, fn.cid, enable_search=False)
        blocks = parsed_nodes(result.reader, result.function)
        self.assertEqual(len(blocks), 2)
        self.assertEqual(blocks[0].terminator.kind.name, "BRANCH")
        self.assertEqual(execute(reader, fn.cid, (123,)), (123,))
        self.assertEqual(execute(result.reader, result.function.cid, (123,)), (123,))

    def test_profile_guides_profitability_but_is_not_semantic_input(self):
        b32 = bits_type(32)
        one = constant(b32, 1)
        callee_graph = graph_fragment(
            [
                Block(
                    (b32,),
                    (
                        Node(Operation.CONSTANT, (), (b32,), entity=one),
                        Node(Operation.ADD_WRAP, (ValueRef.parameter(0, 0), ValueRef.node_result(0, 0)), (b32,)),
                        Node(Operation.ADD_WRAP, (ValueRef.node_result(0, 1), ValueRef.node_result(0, 0)), (b32,)),
                        Node(Operation.ADD_WRAP, (ValueRef.node_result(0, 2), ValueRef.node_result(0, 0)), (b32,)),
                    ),
                    Terminator.return_((ValueRef.node_result(0, 3),)),
                )
            ]
        )
        callee = function(callee_graph, (b32,), (b32,))
        caller_graph = graph_fragment(
            [
                Block(
                    (b32,),
                    (Node(Operation.CALL_DIRECT, (ValueRef.parameter(0, 0),), (b32,), entity=callee),),
                    Terminator.return_((ValueRef.node_result(0, 0),)),
                )
            ]
        )
        caller = function(caller_graph, (b32,), (b32,))
        reader = store_for((callee, caller), (b32, one, callee_graph, caller_graph))
        budget = OptimizationBudget(inline_cold_nodes=2, inline_hot_nodes=8, hot_call_threshold=10, search_steps=0)
        cold = optimize_function(reader, caller.cid, budget=budget, enable_search=False)
        profile = ProfileData(b"m12-test-hot-profile", ((callee.cid, 100),))
        hot = optimize_function(reader, caller.cid, budget=budget, profile=profile, enable_search=False)
        cold_ops = tuple(node.operation for node in parsed_nodes(cold.reader, cold.function)[0].nodes)
        hot_ops = tuple(node.operation for node in parsed_nodes(hot.reader, hot.function)[0].nodes)
        self.assertIn(Operation.CALL_DIRECT, cold_ops)
        self.assertNotIn(Operation.CALL_DIRECT, hot_ops)
        self.assertNotEqual(cold.function.cid, hot.function.cid)
        self.assertEqual(hot.profile_identity, profile.identity)
        self.assertNotIn(profile.identity, hot.reader.data)
        for value in (0, 1, 100, 0xFFFFFFFF):
            expected = execute(reader, caller.cid, (value,))
            self.assertEqual(execute(cold.reader, cold.function.cid, (value,)), expected)
            self.assertEqual(execute(hot.reader, hot.function.cid, (value,)), expected)

    def test_bounded_search_uses_exact_equivalence_and_target_cost(self):
        b32 = bits_type(32)
        two = constant(b32, 2)
        graph = graph_fragment(
            [
                Block(
                    (b32,),
                    (
                        Node(Operation.CONSTANT, (), (b32,), entity=two),
                        Node(Operation.MUL_WRAP, (ValueRef.parameter(0, 0), ValueRef.node_result(0, 0)), (b32,)),
                    ),
                    Terminator.return_((ValueRef.node_result(0, 1),)),
                )
            ]
        )
        fn = function(graph, (b32,), (b32,))
        reader = store_for((fn,), (b32, two, graph))
        target = x86_64_windows_target()
        before = target_cost(reader, fn, target)
        budget = OptimizationBudget(search_steps=96, search_candidates=64, search_memory_bytes=1 << 18)
        result = optimize_function(reader, fn.cid, target=target, budget=budget)
        self.assertTrue(result.search.attempted)
        self.assertGreater(result.search.rejected_validation, 0)
        self.assertGreater(result.search.equivalent_candidates, 0)
        self.assertLessEqual(target_cost(result.reader, result.function, target).value, before.value)
        self.assertTrue(any(event.pass_name == "bounded-superopt" and event.accepted for event in result.events))
        for value in (0, 1, 2, 3, 17, 0x7FFFFFFF, 0xFFFFFFFF):
            self.assertEqual(execute(reader, fn.cid, (value,)), execute(result.reader, result.function.cid, (value,)))


    def test_machine_readable_policy_binds_explicit_search_and_memory_budgets(self):
        policy = optimization_policy(search_steps=73, search_candidates=29, search_memory_bytes=123456, polynomial_terms=31)
        view = decode_optimization_policy(policy)
        self.assertEqual(view.search_steps, 73)
        self.assertEqual(view.search_candidates, 29)
        self.assertEqual(view.search_memory_bytes, 123456)
        self.assertEqual(view.polynomial_terms, 31)
        b32 = bits_type(32)
        graph = graph_fragment([Block((b32,), (), Terminator.return_((ValueRef.parameter(0, 0),)))])
        fn = function(graph, (b32,), (b32,))
        reader = store_for((fn,), (b32, graph))
        result = optimize_function(reader, fn.cid, policy=policy, enable_search=False)
        self.assertEqual(result.policy_root, policy.cid)

    def test_search_is_deterministic_under_fixed_budget_and_target(self):
        b32 = bits_type(32)
        two = constant(b32, 2)
        graph = graph_fragment(
            [Block((b32,), (Node(Operation.CONSTANT, (), (b32,), entity=two), Node(Operation.MUL_WRAP, (ValueRef.parameter(0, 0), ValueRef.node_result(0, 0)), (b32,))), Terminator.return_((ValueRef.node_result(0, 1),)))]
        )
        fn = function(graph, (b32,), (b32,))
        reader = store_for((fn,), (b32, two, graph))
        target = x86_64_windows_target()
        budget = OptimizationBudget(search_steps=96, search_candidates=64, search_memory_bytes=1 << 18)
        first = optimize_function(reader, fn.cid, target=target, budget=budget)
        second = optimize_function(reader, fn.cid, target=target, budget=budget)
        self.assertEqual(first.function.cid, second.function.cid)
        self.assertEqual(first.reader.data, second.reader.data)
        self.assertEqual(first.search, second.search)
        self.assertEqual(first.cost_reports, second.cost_reports)


if __name__ == "__main__":
    unittest.main()
