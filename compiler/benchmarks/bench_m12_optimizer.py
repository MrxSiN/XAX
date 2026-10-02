"""Deterministic M12 optimizer/search evidence generator.

This records optimization structure and target code-size cost evidence.  It is
not a runtime-performance benchmark and makes no universal speed claim.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

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
    wasm32_target,
    write_store,
    x86_64_windows_target,
)
from xax_build import decode_optimization_policy, optimization_policy
from xax_optimizer import OptimizationBudget, ProfileData, optimize_function, target_cost


HERE = Path(__file__).resolve().parent
OUTPUT = HERE / "m12_optimizer_evidence.json"


def store_for(functions, objects):
    module = object_with_refs(Kind.MODULE, tuple(functions))
    root = object_with_refs(Kind.PROGRAM_ROOT, (module,))
    return StoreReader(write_store(root.cid, (*objects, *functions, module, root)))


def search_fixture():
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
    return store_for((fn,), (b32, two, graph)), fn


def profile_fixture():
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
        [Block((b32,), (Node(Operation.CALL_DIRECT, (ValueRef.parameter(0, 0),), (b32,), entity=callee),), Terminator.return_((ValueRef.node_result(0, 0),)))]
    )
    caller = function(caller_graph, (b32,), (b32,))
    reader = store_for((callee, caller), (b32, one, callee_graph, caller_graph))
    return reader, callee, caller


def cost_dict(report):
    return {
        "entity": report.entity.hex(),
        "target": report.target.hex(),
        "objective": report.objective.value,
        "value": report.value,
        "unit": report.unit,
        "model_identity": report.model_identity.hex(),
        "classification": report.classification,
        "artifact_bytes": report.artifact_bytes,
        "assumptions": list(report.assumptions),
    }


def search_dict(report):
    return {
        "attempted": report.attempted,
        "steps": report.steps,
        "candidates": report.candidates,
        "equivalent_candidates": report.equivalent_candidates,
        "rejected_validation": report.rejected_validation,
        "peak_memory_bytes": report.peak_memory_bytes,
        "validator_identity": report.validator_identity.hex(),
        "selected_function": None if report.selected_function is None else report.selected_function.hex(),
    }


def run() -> dict:
    reader, fn = search_fixture()
    budget = OptimizationBudget(search_steps=96, search_candidates=64, search_memory_bytes=1 << 18)
    policy = optimization_policy(
        pass_iterations=budget.pass_iterations,
        search_steps=budget.search_steps,
        search_candidates=budget.search_candidates,
        search_memory_bytes=budget.search_memory_bytes,
        polynomial_terms=budget.polynomial_terms,
        inline_cold_nodes=budget.inline_cold_nodes,
        inline_hot_nodes=budget.inline_hot_nodes,
        hot_call_threshold=budget.hot_call_threshold,
    )
    policy_view = decode_optimization_policy(policy)
    vectors = (0, 1, 2, 3, 17, 0x7FFFFFFF, 0xFFFFFFFF)
    targets = (x86_64_windows_target(), wasm32_target())
    target_records = []
    for target in targets:
        before = target_cost(reader, fn, target)
        first = optimize_function(reader, fn.cid, target=target, policy=policy)
        second = optimize_function(reader, fn.cid, target=target, policy=policy)
        after = target_cost(first.reader, first.function, target)
        comparisons = [
            {
                "arguments": [value],
                "before": list(execute(reader, fn.cid, (value,))),
                "after": list(execute(first.reader, first.function.cid, (value,))),
            }
            for value in vectors
        ]
        target_records.append(
            {
                "target_root": target.cid.hex(),
                "input_function": fn.cid.hex(),
                "selected_function": first.function.cid.hex(),
                "deterministic_function": first.function.cid == second.function.cid,
                "deterministic_store_bytes": first.reader.data == second.reader.data,
                "before_cost": cost_dict(before),
                "after_cost": cost_dict(after),
                "search": search_dict(first.search),
                "candidate_cost_reports": [cost_dict(item) for item in first.cost_reports],
                "vectors": comparisons,
                "vectors_match": all(item["before"] == item["after"] for item in comparisons),
            }
        )

    profile_reader, callee, caller = profile_fixture()
    profile_budget = OptimizationBudget(inline_cold_nodes=2, inline_hot_nodes=8, hot_call_threshold=10, search_steps=0)
    cold = optimize_function(profile_reader, caller.cid, budget=profile_budget, enable_search=False)
    profile = ProfileData(b"m12-evidence-hot-profile-v1", ((callee.cid, 100),))
    hot = optimize_function(profile_reader, caller.cid, budget=profile_budget, profile=profile, enable_search=False)
    profile_vectors = (0, 1, 100, 0xFFFFFFFF)
    profile_comparisons = [
        {
            "arguments": [value],
            "seed": list(execute(profile_reader, caller.cid, (value,))),
            "cold": list(execute(cold.reader, cold.function.cid, (value,))),
            "hot": list(execute(hot.reader, hot.function.cid, (value,))),
        }
        for value in profile_vectors
    ]

    return {
        "milestone": "M12",
        "scope": "optimizer expansion and validated search prototype",
        "claims": {
            "interprocedural": "pure single-block direct-call inlining with profile-separated profitability",
            "local": "constant folding, wrapping identities, CSE, DCE, constant-CFG simplification",
            "search": "deterministically bounded enumerative wrapping-arithmetic search",
            "validation": "ordinary verifier plus exact polynomial equivalence over Z/(2^N)",
            "cost": "target lowering-derived exact function byte extent used as code-size estimate",
            "profile": "tooling-only call weights; never serialized into canonical XAX objects",
        },
        "budget": asdict(budget),
        "optimization_policy_root": policy.cid.hex(),
        "optimization_policy": {
            "objective": policy_view.objective.name.lower(),
            "pass_iterations": policy_view.pass_iterations,
            "search_steps": policy_view.search_steps,
            "search_candidates": policy_view.search_candidates,
            "search_memory_bytes": policy_view.search_memory_bytes,
            "polynomial_terms": policy_view.polynomial_terms,
            "inline_cold_nodes": policy_view.inline_cold_nodes,
            "inline_hot_nodes": policy_view.inline_hot_nodes,
            "hot_call_threshold": policy_view.hot_call_threshold,
            "deterministic": policy_view.deterministic,
        },
        "targets": target_records,
        "profile_guided": {
            "callee": callee.cid.hex(),
            "caller": caller.cid.hex(),
            "profile_identity": profile.identity.hex(),
            "profile_tooling_digest_sha256": profile.tooling_digest.hex(),
            "cold_function": cold.function.cid.hex(),
            "hot_function": hot.function.cid.hex(),
            "different_profitability_output": cold.function.cid != hot.function.cid,
            "profile_bytes_absent_from_canonical_store": profile.identity not in hot.reader.data,
            "vectors": profile_comparisons,
            "vectors_match": all(item["seed"] == item["cold"] == item["hot"] for item in profile_comparisons),
        },
        "caveats": [
            "code-size cost is exact for the emitted candidate extent but is not runtime latency/throughput measurement",
            "search equivalence is currently limited to pure wrapping integer polynomial expressions",
            "effectful/resource/atomic regions are preserved conservatively and excluded from search/inlining",
            "profile data affects profitability only and is not semantic legality evidence",
        ],
    }


if __name__ == "__main__":
    result = run()
    OUTPUT.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, indent=2, sort_keys=True))
