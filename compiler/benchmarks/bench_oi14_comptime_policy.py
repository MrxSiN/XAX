"""OI-14 deterministic compile-time budget/capability evidence.

The semantic evidence is deterministic. Host elapsed time and tracemalloc peaks are
written separately and are explicitly non-semantic observations.
"""

from __future__ import annotations

import argparse
import gc
import hashlib
import json
import math
import statistics
import time
import tracemalloc
from dataclasses import asdict, replace
from pathlib import Path
from typing import Callable

from xax_compiler import (
    Block,
    CompileTimeBudget,
    CompileTimeEvaluator,
    CompileTimeInput,
    Kind,
    MetaCapability,
    Node,
    OpaqueKind,
    Operation,
    StoreReader,
    Terminator,
    ValueRef,
    XaxError,
    bits_type,
    constant,
    function,
    graph_fragment,
    object_with_refs,
    opaque_type,
    uleb,
    verify_store,
    write_store,
    x86_64_windows_general_target,
)

SCHEMA = "xax-oi14-comptime-policy-v1"
HERE = Path(__file__).resolve().parent
EVIDENCE_PATH = HERE / "oi14_comptime_policy_evidence.json"
HOST_PATH = HERE / "oi14_comptime_host_samples.json"


class Workload:
    def __init__(self, identity: str, reader: StoreReader, entry, arguments, capabilities, inputs=()):
        self.identity = identity
        self.reader = reader
        self.entry = entry
        self.arguments = tuple(arguments)
        self.capabilities = tuple(capabilities)
        self.inputs = tuple(inputs)

    def evaluate(self, *, budget: CompileTimeBudget = CompileTimeBudget(), evaluator: CompileTimeEvaluator | None = None):
        evaluator = evaluator or CompileTimeEvaluator()
        return evaluator.evaluate(
            self.reader,
            self.entry.cid,
            self.arguments,
            capabilities=self.capabilities,
            inputs=self.inputs,
            budget=budget,
        )


def _store(objects, root):
    reader = StoreReader(write_store(root.cid, objects))
    verify_store(reader)
    return reader


def compiler_like_workload() -> Workload:
    """Inspect interface + body and generate one derived constant function."""
    b32 = bits_type(32)
    fn_ref = opaque_type(OpaqueKind.FUNCTION)
    graph_ref = opaque_type(OpaqueKind.GRAPH)
    type_ref = opaque_type(OpaqueKind.TYPE)
    zero = constant(b32, 0)
    target_graph = graph_fragment((
        Block(
            (b32, b32),
            (
                Node(Operation.ADD_WRAP, (ValueRef.parameter(0, 0), ValueRef.parameter(0, 1)), (b32,)),
                Node(Operation.MUL_WRAP, (ValueRef.node_result(0, 0), ValueRef.parameter(0, 1)), (b32,)),
                Node(Operation.SUB_WRAP, (ValueRef.node_result(0, 1), ValueRef.parameter(0, 0)), (b32,)),
            ),
            Terminator.return_((ValueRef.node_result(0, 2),)),
        ),
    ))
    target_fn = function(target_graph, (b32, b32), (b32,))
    nodes = (
        Node(Operation.META_FUNCTION_PARAMETER_COUNT, (ValueRef.parameter(0, 0),), (b32,)),
        Node(Operation.META_FUNCTION_RETURN_COUNT, (ValueRef.parameter(0, 0),), (b32,)),
        Node(Operation.META_FUNCTION_GRAPH, (ValueRef.parameter(0, 0),), (graph_ref,)),
        Node(Operation.META_GRAPH_BLOCK_COUNT, (ValueRef.node_result(0, 2),), (b32,)),
        Node(Operation.CONSTANT, (), (b32,), entity=zero),
        Node(Operation.META_GRAPH_NODE_COUNT, (ValueRef.node_result(0, 2), ValueRef.node_result(0, 4)), (b32,)),
        Node(Operation.META_GRAPH_NODE_OPERATION, (ValueRef.node_result(0, 2), ValueRef.node_result(0, 4), ValueRef.node_result(0, 4)), (b32,)),
        Node(Operation.ADD_WRAP, (ValueRef.node_result(0, 0), ValueRef.node_result(0, 1)), (b32,)),
        Node(Operation.ADD_WRAP, (ValueRef.node_result(0, 7), ValueRef.node_result(0, 3)), (b32,)),
        Node(Operation.ADD_WRAP, (ValueRef.node_result(0, 8), ValueRef.node_result(0, 5)), (b32,)),
        Node(Operation.ADD_WRAP, (ValueRef.node_result(0, 9), ValueRef.node_result(0, 6)), (b32,)),
        Node(Operation.META_MATERIALIZE_CONSTANT_FUNCTION, (ValueRef.parameter(0, 1), ValueRef.node_result(0, 10)), (fn_ref,)),
    )
    entry_graph = graph_fragment((Block((fn_ref, type_ref), nodes, Terminator.return_((ValueRef.node_result(0, 11), ValueRef.node_result(0, 10)))),))
    entry = function(entry_graph, (fn_ref, type_ref), (fn_ref, b32))
    module = object_with_refs(Kind.MODULE, (target_fn, entry))
    root = object_with_refs(Kind.PROGRAM_ROOT, (module,))
    objects = (b32, fn_ref, graph_ref, type_ref, zero, target_graph, target_fn, entry_graph, entry, module, root)
    return Workload(
        "compiler-like-body-generation",
        _store(objects, root),
        entry,
        (target_fn, b32),
        (MetaCapability.INSPECT_FUNCTION_INTERFACE, MetaCapability.INSPECT_FUNCTION, MetaCapability.CONSTRUCT_SEMANTICS),
    )


def target_adapter_workload() -> Workload:
    """Inspect target + function interface, but deliberately not function body."""
    b1, b32 = bits_type(1), bits_type(32)
    fn_ref = opaque_type(OpaqueKind.FUNCTION)
    target_ref = opaque_type(OpaqueKind.TARGET)
    type_ref = opaque_type(OpaqueKind.TYPE)
    target_graph = graph_fragment((Block((b32,), (), Terminator.return_((ValueRef.parameter(0, 0),))),))
    target_fn = function(target_graph, (b32,), (b32,))
    target = x86_64_windows_general_target()
    nodes = (
        Node(Operation.META_FUNCTION_PARAMETER_COUNT, (ValueRef.parameter(0, 0),), (b32,)),
        Node(Operation.META_FUNCTION_RETURN_COUNT, (ValueRef.parameter(0, 0),), (b32,)),
        Node(Operation.META_TARGET_SUPPORTS, (ValueRef.parameter(0, 1),), (b1,), attributes=(Operation.ADD_WRAP,)),
        Node(Operation.META_TARGET_SUPPORTS, (ValueRef.parameter(0, 1),), (b1,), attributes=(Operation.FLOAT_ADD,)),
        Node(Operation.META_TYPE_BITS_WIDTH, (ValueRef.parameter(0, 2),), (b32,)),
        Node(Operation.ADD_WRAP, (ValueRef.node_result(0, 0), ValueRef.node_result(0, 1)), (b32,)),
        Node(Operation.ADD_WRAP, (ValueRef.node_result(0, 5), ValueRef.node_result(0, 4)), (b32,)),
        Node(Operation.META_MATERIALIZE_CONSTANT_FUNCTION, (ValueRef.parameter(0, 2), ValueRef.node_result(0, 6)), (fn_ref,)),
    )
    entry_graph = graph_fragment((Block((fn_ref, target_ref, type_ref), nodes, Terminator.return_((ValueRef.node_result(0, 7), ValueRef.node_result(0, 2), ValueRef.node_result(0, 3)))),))
    entry = function(entry_graph, (fn_ref, target_ref, type_ref), (fn_ref, b1, b1))
    module = object_with_refs(Kind.MODULE, (target_fn, entry, target))
    root = object_with_refs(Kind.PROGRAM_ROOT, (module,))
    objects = (b1, b32, fn_ref, target_ref, type_ref, target_graph, target_fn, target, entry_graph, entry, module, root)
    return Workload(
        "target-adapter-interface-generation",
        _store(objects, root),
        entry,
        (target_fn, target, b32),
        (MetaCapability.INSPECT_FUNCTION_INTERFACE, MetaCapability.INSPECT_TARGET, MetaCapability.INSPECT_TYPE, MetaCapability.CONSTRUCT_SEMANTICS),
    )


def generic_metaprogram_workload() -> Workload:
    """Nested generic computation + declared input + semantic construction."""
    b32 = bits_type(32)
    type_ref = opaque_type(OpaqueKind.TYPE)
    constant_ref = opaque_type(OpaqueKind.CONSTANT)
    fn_ref = opaque_type(OpaqueKind.FUNCTION)
    seven = constant(b32, 7)
    helper_nodes = (
        Node(Operation.META_TYPE_BITS_WIDTH, (ValueRef.parameter(0, 0),), (b32,)),
        Node(Operation.META_CONSTANT_VALUE, (ValueRef.parameter(0, 1),), (b32,)),
        Node(Operation.ADD_WRAP, (ValueRef.node_result(0, 0), ValueRef.node_result(0, 1)), (b32,)),
    )
    helper_graph = graph_fragment((Block((type_ref, constant_ref), helper_nodes, Terminator.return_((ValueRef.node_result(0, 2),))),))
    helper = function(helper_graph, (type_ref, constant_ref), (b32,))
    entry_nodes = (
        Node(Operation.CALL_DIRECT, (ValueRef.parameter(0, 0), ValueRef.parameter(0, 1)), (b32,), entity=helper),
        Node(Operation.META_DECLARED_INPUT, (), (b32,), attributes=(0,)),
        Node(Operation.ADD_WRAP, (ValueRef.node_result(0, 0), ValueRef.node_result(0, 1)), (b32,)),
        Node(Operation.META_MATERIALIZE_CONSTANT_FUNCTION, (ValueRef.parameter(0, 0), ValueRef.node_result(0, 2)), (fn_ref,)),
    )
    entry_graph = graph_fragment((Block((type_ref, constant_ref), entry_nodes, Terminator.return_((ValueRef.node_result(0, 3), ValueRef.node_result(0, 2)))),))
    entry = function(entry_graph, (type_ref, constant_ref), (fn_ref, b32))
    module = object_with_refs(Kind.MODULE, (helper, entry))
    root = object_with_refs(Kind.PROGRAM_ROOT, (module,))
    objects = (b32, type_ref, constant_ref, fn_ref, helper_graph, helper, entry_graph, entry, module, root)
    return Workload(
        "ordinary-generic-construction",
        _store(objects, root),
        entry,
        (b32, seven),
        (MetaCapability.INSPECT_TYPE, MetaCapability.INSPECT_CONSTANT, MetaCapability.READ_DECLARED_INPUT, MetaCapability.CONSTRUCT_SEMANTICS),
        (CompileTimeInput(b"generic-seed", b32, 5),),
    )


def workloads() -> tuple[Workload, ...]:
    return (compiler_like_workload(), target_adapter_workload(), generic_metaprogram_workload())


def _result_record(workload: Workload):
    result = workload.evaluate()
    return {
        "identity": workload.identity,
        "entry_cid": workload.entry.cid.hex(),
        "root_cid": workload.reader.root_cid.hex(),
        "capabilities": [cap.name.lower() for cap in workload.capabilities],
        "capability_packet_bytes": len(uleb(len(workload.capabilities)) + b"".join(uleb(int(cap)) for cap in sorted(workload.capabilities))),
        "capability_tokens": None,
        "steps": result.steps,
        "evaluated_blocks": result.evaluated_blocks,
        "evaluated_nodes": result.evaluated_nodes,
        "peak_frame_bytes": result.peak_memory_bytes,
        "max_call_depth": result.max_call_depth,
        "constructed_objects": len(result.created_objects),
        "emitted_graph_nodes": result.graph_nodes,
        "created_cids": [obj.cid.hex() for obj in result.created_objects],
        "values": [value.cid.hex() if hasattr(value, "cid") else value for value in result.values],
    }


def _diagnostic_record(error: XaxError):
    payload = json.dumps(asdict(error.diagnostic), sort_keys=True, separators=(",", ":")).encode()
    return {
        "code": error.diagnostic.code,
        "rule": error.diagnostic.rule,
        "actual": error.diagnostic.actual,
        "payload_bytes": len(payload),
    }


def boundary_evidence(workload: Workload):
    base = workload.evaluate()
    exact = {
        "steps": base.steps,
        "call_depth": base.max_call_depth,
        "memory_bytes": base.peak_memory_bytes,
        "semantic_objects": len(base.created_objects),
        "graph_nodes": base.graph_nodes,
    }
    records = {}
    root = workload.reader.root_cid
    for field, value in exact.items():
        if value <= 0:
            raise AssertionError(f"boundary fixture must consume {field}")
        below = replace(CompileTimeBudget(), **{field: value - 1})
        evaluator = CompileTimeEvaluator()
        try:
            workload.evaluate(budget=below, evaluator=evaluator)
        except XaxError as error:
            failure = _diagnostic_record(error)
        else:
            raise AssertionError(f"{field} below-limit unexpectedly succeeded")
        if evaluator.cache_size != 0 or workload.reader.root_cid != root:
            raise AssertionError("failed evaluation published cache/root state")
        at = workload.evaluate(budget=replace(CompileTimeBudget(), **{field: value}))
        above = workload.evaluate(budget=replace(CompileTimeBudget(), **{field: value + 1}))
        records[field] = {
            "below": value - 1,
            "at": value,
            "above": value + 1,
            "failure": failure,
            "cache_entries_after_failure": evaluator.cache_size,
            "at_steps": at.steps,
            "above_steps": above.steps,
            "root_unchanged": workload.reader.root_cid == root,
        }
    return records


def deterministic_evidence():
    ws = workloads()
    records = [_result_record(item) for item in ws]
    by_name = {item["identity"]: item for item in records}
    hard_caps = {
        "call_depth": max(item["max_call_depth"] for item in records),
        "memory_bytes": max(item["peak_frame_bytes"] for item in records),
        "semantic_objects": max(item["constructed_objects"] for item in records),
        "graph_nodes": max(item["emitted_graph_nodes"] for item in records),
    }
    vector_values = 5 * len(records)
    simple_values = len(records) + len(hard_caps)
    # The old coarse function-inspection policy would authorize interface reads with body authority.
    split_cap_bytes = {item.identity: _result_record(item)["capability_packet_bytes"] for item in ws}
    coarse_counts = {
        "compiler-like-body-generation": 2,  # INSPECT_FUNCTION + CONSTRUCT_SEMANTICS
        "target-adapter-interface-generation": 4,  # INSPECT_FUNCTION + target + type + construct
        "ordinary-generic-construction": 4,
    }
    coarse_bytes = {name: len(uleb(count) + b"".join(uleb(i + 1) for i in range(count))) for name, count in coarse_counts.items()}
    evidence = {
        "schema": SCHEMA,
        "workloads": records,
        "budget_models": {
            "current_vector": {
                "workload_specific_calibration_values": vector_values,
                "limits": {
                    item["identity"]: {
                        "steps": item["steps"],
                        "call_depth": item["max_call_depth"],
                        "memory_bytes": item["peak_frame_bytes"],
                        "semantic_objects": item["constructed_objects"],
                        "graph_nodes": item["emitted_graph_nodes"],
                    }
                    for item in records
                },
            },
            "semantic_steps_plus_hard_caps": {
                "workload_specific_step_limits": {item["identity"]: item["steps"] for item in records},
                "global_hard_caps": hard_caps,
                "calibration_values": simple_values,
                "host_dependent_terms": 0,
            },
            "selected": "semantic_steps_plus_hard_caps",
        },
        "boundary": boundary_evidence(generic_metaprogram_workload()),
        "capability_policy": {
            "selected": "function-interface separate from function-body; retain existing coarse domains otherwise",
            "new_capability": "inspect_function_interface",
            "interface_operations": ["meta_function_parameter_count", "meta_function_return_count"],
            "body_capability": "inspect_function",
            "target_adapter_has_body_authority": False,
            "split_packet_bytes": split_cap_bytes,
            "coarse_packet_bytes_conceptual": coarse_bytes,
            "tokenizer": None,
            "token_counts": None,
            "token_reason": "tiktoken/model tokenizer unavailable",
        },
        "implementation_delta": {
            "core_file": "compiler/src/xax_compiler.py",
            "added_lines": 37,
            "deleted_lines": 4,
            "new_capabilities": 1,
            "new_meta_operations": 2,
            "new_dependencies": 0,
        },
        "host_observations": {
            "semantic": False,
            "fuel_input": False,
            "artifact": HOST_PATH.name,
            "excluded_from_budget_and_reproducibility_hash": True,
        },
    }
    # Host observations are recorded in the evidence artifact, but never in the
    # deterministic projection or any compile-time budget/key.
    projection = json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode()
    evidence["deterministic_projection_sha256"] = hashlib.sha256(projection).hexdigest()
    if HOST_PATH.exists():
        raw = HOST_PATH.read_bytes()
        host = json.loads(raw)
        evidence["host_observations"].update({
            "raw_sha256": hashlib.sha256(raw).hexdigest(),
            "samples_per_workload": host["samples_per_workload"],
            "peak_memory_correlation_pearson_r": host.get("peak_memory_correlation_pearson_r"),
            "summary": [
                {
                    "identity": row["identity"],
                    "elapsed_median_ns": row["elapsed_median_ns"],
                    "elapsed_min_ns": row["elapsed_min_ns"],
                    "elapsed_max_ns": row["elapsed_max_ns"],
                    "tracemalloc_peak_median_bytes": row["tracemalloc_peak_median_bytes"],
                    "tracemalloc_peak_min_bytes": row["tracemalloc_peak_min_bytes"],
                    "tracemalloc_peak_max_bytes": row["tracemalloc_peak_max_bytes"],
                }
                for row in host["workloads"]
            ],
        })
    return evidence


def host_observations(samples: int = 11):
    rows = []
    for workload in workloads():
        elapsed = []
        peaks = []
        # One unrecorded warmup keeps import/lazy one-time costs out of the samples.
        workload.evaluate()
        for _ in range(samples):
            gc.collect()
            tracemalloc.start()
            start = time.perf_counter_ns()
            workload.evaluate(evaluator=CompileTimeEvaluator())
            elapsed.append(time.perf_counter_ns() - start)
            _, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()
            peaks.append(peak)
        elapsed_sorted = sorted(elapsed)
        peaks_sorted = sorted(peaks)
        rows.append({
            "identity": workload.identity,
            "elapsed_ns": elapsed,
            "tracemalloc_peak_bytes": peaks,
            "elapsed_median_ns": int(statistics.median(elapsed)),
            "elapsed_min_ns": elapsed_sorted[0],
            "elapsed_max_ns": elapsed_sorted[-1],
            "tracemalloc_peak_median_bytes": int(statistics.median(peaks)),
            "tracemalloc_peak_min_bytes": peaks_sorted[0],
            "tracemalloc_peak_max_bytes": peaks_sorted[-1],
        })
    deterministic = {item["identity"]: item for item in deterministic_evidence()["workloads"]}
    pairs = [
        [deterministic[row["identity"]]["peak_frame_bytes"], row["tracemalloc_peak_median_bytes"]]
        for row in rows
    ]
    xs = [pair[0] for pair in pairs]
    ys = [pair[1] for pair in pairs]
    mx, my = statistics.mean(xs), statistics.mean(ys)
    numerator = sum((x - mx) * (y - my) for x, y in pairs)
    denominator = math.sqrt(sum((x - mx) ** 2 for x in xs) * sum((y - my) ** 2 for y in ys))
    correlation = numerator / denominator if denominator else None
    return {
        "schema": "xax-oi14-host-observations-v1",
        "semantic": False,
        "fuel_input": False,
        "samples_per_workload": samples,
        "workloads": rows,
        "evaluator_peak_vs_host_peak_pairs": pairs,
        "peak_memory_correlation_pearson_r": correlation,
        "note": "Host time/memory are observations only and never enter compile-time keys or budgets; correlation is descriptive over three workloads only.",
    }


def write_artifacts(samples: int = 11):
    host = host_observations(samples)
    HOST_PATH.write_text(json.dumps(host, indent=2, sort_keys=True) + "\n")
    evidence = deterministic_evidence()
    EVIDENCE_PATH.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    return evidence, host


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--host-samples", type=int, default=11)
    parser.add_argument("--deterministic-hash", action="store_true")
    args = parser.parse_args()
    if args.write:
        evidence, _ = write_artifacts(args.host_samples)
    else:
        evidence = deterministic_evidence()
    if args.deterministic_hash:
        print(evidence["deterministic_projection_sha256"])
        return
    print(json.dumps(evidence, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
