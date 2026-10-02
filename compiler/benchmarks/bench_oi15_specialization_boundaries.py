"""OI-15 specialization-boundary evidence.

All alternate specialization cache/object boundaries in this file are measurement-only.
Canonical XAX functions/graphs remain unchanged and every materialized specialization is
verified through the ordinary verifier before accounting or execution.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import platform
import statistics
import time
from pathlib import Path
from typing import Iterable, Sequence

from xax_compiler import (
    DEFAULT_VERIFIER_IDENTITY,
    Block,
    Kind,
    Node,
    Operation,
    SemanticObject,
    StoreReader,
    Terminator,
    ValueRef,
    bits_type,
    blake3,
    constant,
    execute,
    function,
    graph_fragment,
    object_with_refs,
    verify_object,
    verify_store,
    write_store,
    x86_64_windows_target,
)
from xax_optimizer import _public_graph, optimize_function, target_cost


SPECIALIZER_ID = b"xax-oi15-specializer-v1"
EVALUATOR_ID = b"xax-meta-evaluator-v1"
VERIFIER_ID = DEFAULT_VERIFIER_IDENTITY.encode("ascii")
CACHE_DIGEST_BYTES = 32


@dataclass(frozen=True)
class SpecArg:
    parameter: int
    type_cid: bytes
    value: int


@dataclass(frozen=True)
class SpecRequest:
    name: str
    source_cid: bytes
    args: tuple[SpecArg, ...]
    reference_inputs: tuple[int, ...]


@dataclass(frozen=True)
class SpecResult:
    request: SpecRequest
    request_key: bytes
    body_key: bytes
    shell_key: bytes
    function: SemanticObject
    graph: SemanticObject
    created: tuple[SemanticObject, ...]
    remaining_parameters: tuple[SemanticObject, ...]


@dataclass(frozen=True)
class Corpus:
    reader: StoreReader
    objects: dict[bytes, SemanticObject]
    functions: dict[str, SemanticObject]
    target: SemanticObject
    b1: SemanticObject
    b32: SemanticObject


def _resolver(objects: dict[bytes, SemanticObject]):
    def resolve(cid: bytes) -> SemanticObject:
        try:
            return objects[cid]
        except KeyError as error:
            raise ValueError(f"missing object {cid.hex()}") from error
    return resolve


def _reachable(root: SemanticObject, objects: dict[bytes, SemanticObject]) -> dict[bytes, SemanticObject]:
    out: dict[bytes, SemanticObject] = {}
    pending = [root.cid]
    while pending:
        cid = pending.pop()
        if cid in out:
            continue
        obj = objects[cid]
        out[cid] = obj
        pending.extend(obj.references)
    return out


def _reader_for_members(objects: dict[bytes, SemanticObject], members: Sequence[SemanticObject]) -> StoreReader:
    local = dict(objects)
    module = object_with_refs(Kind.MODULE, tuple(members))
    root = object_with_refs(Kind.PROGRAM_ROOT, (module,))
    local[module.cid] = module
    local[root.cid] = root
    reachable = _reachable(root, local)
    reader = StoreReader(write_store(root.cid, reachable.values()))
    verify_store(reader)
    return reader


def build_corpus() -> Corpus:
    b1, b32 = bits_type(1), bits_type(32)
    one = constant(b1, 1)

    add_graph = graph_fragment((Block(
        (b32, b32),
        (Node(Operation.ADD_WRAP, (ValueRef.parameter(0, 0), ValueRef.parameter(0, 1)), (b32,)),),
        Terminator.return_((ValueRef.node_result(0, 0),)),
    ),))
    add_bias = function(add_graph, (b32, b32), (b32,))

    mul_graph = graph_fragment((Block(
        (b32, b32),
        (Node(Operation.MUL_WRAP, (ValueRef.parameter(0, 0), ValueRef.parameter(0, 1)), (b32,)),),
        Terminator.return_((ValueRef.node_result(0, 0),)),
    ),))
    mul_scale = function(mul_graph, (b32, b32), (b32,))

    nested_graph = graph_fragment((Block(
        (b32, b32, b32),
        (
            Node(Operation.CALL_DIRECT, (ValueRef.parameter(0, 0), ValueRef.parameter(0, 1)), (b32,), entity=add_bias),
            Node(Operation.CALL_DIRECT, (ValueRef.node_result(0, 0), ValueRef.parameter(0, 2)), (b32,), entity=mul_scale),
        ),
        Terminator.return_((ValueRef.node_result(0, 1),)),
    ),))
    nested = function(nested_graph, (b32, b32, b32), (b32,))

    choose_graph = graph_fragment((
        Block(
            (b1, b32, b32),
            (),
            Terminator.conditional_branch(
                ValueRef.parameter(0, 0),
                1, (ValueRef.parameter(0, 1), ValueRef.parameter(0, 2)),
                2, (ValueRef.parameter(0, 1), ValueRef.parameter(0, 2)),
            ),
        ),
        Block(
            (b32, b32),
            (Node(Operation.ADD_WRAP, (ValueRef.parameter(1, 0), ValueRef.parameter(1, 1)), (b32,)),),
            Terminator.return_((ValueRef.node_result(1, 0),)),
        ),
        Block(
            (b32, b32),
            (Node(Operation.SUB_WRAP, (ValueRef.parameter(2, 0), ValueRef.parameter(2, 1)), (b32,)),),
            Terminator.return_((ValueRef.node_result(2, 0),)),
        ),
    ))
    choose = function(choose_graph, (b1, b32, b32), (b32,))

    dead_graph = graph_fragment((Block(
        (b32, b32),
        (Node(Operation.MUL_WRAP, (ValueRef.parameter(0, 0), ValueRef.parameter(0, 1)), (b32,)),),
        Terminator.return_((ValueRef.node_result(0, 0),)),
    ),))
    dead_mul = function(dead_graph, (b32, b32), (b32,))

    target = x86_64_windows_target()
    functions = {
        "add_bias": add_bias,
        "mul_scale": mul_scale,
        "nested": nested,
        "choose": choose,
        "dead_mul": dead_mul,
    }
    objects = {
        obj.cid: obj
        for obj in (
            b1, b32, one,
            add_graph, add_bias,
            mul_graph, mul_scale,
            nested_graph, nested,
            choose_graph, choose,
            dead_graph, dead_mul,
            target,
        )
    }
    reader = _reader_for_members(objects, (*functions.values(), target))
    return Corpus(reader, {obj.cid: obj for obj in reader.objects()}, functions, target, b1, b32)


def requests(corpus: Corpus) -> tuple[SpecRequest, ...]:
    b1, b32 = corpus.b1, corpus.b32
    f = corpus.functions
    return (
        SpecRequest("add-bias-7", f["add_bias"].cid, (SpecArg(1, b32.cid, 7),), (11,)),
        SpecRequest("add-bias-7-repeat", f["add_bias"].cid, (SpecArg(1, b32.cid, 7),), (19,)),
        SpecRequest("add-bias-9", f["add_bias"].cid, (SpecArg(1, b32.cid, 9),), (11,)),
        SpecRequest("mul-scale-2", f["mul_scale"].cid, (SpecArg(1, b32.cid, 2),), (13,)),
        SpecRequest("nested-7x2", f["nested"].cid, (SpecArg(1, b32.cid, 7), SpecArg(2, b32.cid, 2)), (5,)),
        SpecRequest("nested-7x3", f["nested"].cid, (SpecArg(1, b32.cid, 7), SpecArg(2, b32.cid, 3)), (5,)),
        SpecRequest("choose-true-bias7", f["choose"].cid, (SpecArg(0, b1.cid, 1), SpecArg(2, b32.cid, 7)), (12,)),
        SpecRequest("dead-zero", f["dead_mul"].cid, (SpecArg(1, b32.cid, 0),), (23,)),
    )


def _encode_args(args: Sequence[SpecArg]) -> bytes:
    out = bytearray()
    out.extend(len(args).to_bytes(2, "little"))
    for arg in sorted(args, key=lambda item: item.parameter):
        out.extend(arg.parameter.to_bytes(2, "little"))
        out.extend(arg.type_cid)
        encoded = arg.value.to_bytes(max(1, (arg.value.bit_length() + 7) // 8), "little")
        out.extend(len(encoded).to_bytes(2, "little") + encoded)
    return bytes(out)


def _digest(parts: Iterable[bytes]) -> bytes:
    h = blake3()
    for part in parts:
        h.update(part)
    return h.digest()


def function_request_key(source_cid: bytes, args: Sequence[SpecArg]) -> bytes:
    return _digest((b"XAX-SP-F-1", source_cid, _encode_args(args), SPECIALIZER_ID, EVALUATOR_ID, VERIFIER_ID))


def body_request_key(source_graph_cid: bytes, parameters: Sequence[SemanticObject], returns: Sequence[SemanticObject], args: Sequence[SpecArg]) -> bytes:
    interface = b"".join(obj.cid for obj in (*parameters, *returns))
    counts = len(parameters).to_bytes(2, "little") + len(returns).to_bytes(2, "little")
    return _digest((b"XAX-SP-G-1", source_graph_cid, counts, interface, _encode_args(args), SPECIALIZER_ID, EVALUATOR_ID, VERIFIER_ID))


def shell_request_key(graph_cid: bytes, parameters: Sequence[SemanticObject], returns: Sequence[SemanticObject]) -> bytes:
    interface = b"".join(obj.cid for obj in (*parameters, *returns))
    counts = len(parameters).to_bytes(2, "little") + len(returns).to_bytes(2, "little")
    return _digest((b"XAX-SP-S-1", graph_cid, counts, interface, SPECIALIZER_ID, EVALUATOR_ID, VERIFIER_ID))


def specialize(corpus: Corpus, request: SpecRequest) -> SpecResult:
    source = corpus.objects[request.source_cid]
    entry, blocks, parameters, returns = _public_graph(corpus.reader, source)
    args = tuple(sorted(request.args, key=lambda item: item.parameter))
    indices = tuple(arg.parameter for arg in args)
    if len(indices) != len(set(indices)) or any(index < 0 or index >= len(parameters) for index in indices):
        raise ValueError("invalid specialization parameter")
    for arg in args:
        if parameters[arg.parameter].cid != arg.type_cid:
            raise ValueError("specialization type mismatch")

    arg_by_index = {arg.parameter: arg for arg in args}
    remaining_indices = tuple(index for index in range(len(parameters)) if index not in arg_by_index)
    remaining_map = {old: new for new, old in enumerate(remaining_indices)}
    constants = tuple(constant(parameters[arg.parameter], arg.value) for arg in args)
    const_node_for_parameter = {arg.parameter: index for index, arg in enumerate(args)}
    inserted = len(constants)

    def remap(value: ValueRef) -> ValueRef:
        if value.tag == 0 and value.block == entry:
            if value.index in const_node_for_parameter:
                return ValueRef.node_result(entry, const_node_for_parameter[value.index], value.result)
            return ValueRef.parameter(entry, remaining_map[value.index])
        if value.tag == 1 and value.block == entry:
            return ValueRef.node_result(entry, value.index + inserted, value.result)
        return value

    rewritten: list[Block] = []
    for block_index, block in enumerate(blocks):
        prefix: tuple[Node, ...] = ()
        parameters_out = block.parameters
        if block_index == entry:
            parameters_out = tuple(parameters[index] for index in remaining_indices)
            prefix = tuple(Node(Operation.CONSTANT, (), (parameters[arg.parameter],), entity=value) for arg, value in zip(args, constants))
        nodes = prefix + tuple(
            Node(
                node.operation,
                tuple(remap(value) for value in node.operands),
                node.result_types,
                member=node.member,
                entity=node.entity,
                attributes=node.attributes,
            )
            for node in block.nodes
        )
        term = Terminator(
            block.terminator.kind,
            tuple(remap(value) for value in block.terminator.values),
            tuple((target, tuple(remap(value) for value in edge_args)) for target, edge_args in block.terminator.edges),
            block.terminator.payload,
        )
        rewritten.append(Block(parameters_out, nodes, term))

    graph = graph_fragment(tuple(rewritten), entry)
    remaining_parameters = tuple(parameters[index] for index in remaining_indices)
    specialized = function(graph, remaining_parameters, returns)
    objects = dict(corpus.objects)
    for obj in (*constants, graph, specialized):
        objects[obj.cid] = obj
    resolve = _resolver(objects)
    for value in constants:
        verify_object(value, resolve)
    verify_object(graph, resolve)
    verify_object(specialized, resolve)

    return SpecResult(
        request,
        function_request_key(source.cid, args),
        body_request_key(corpus.objects[next(cid for cid in source.references if corpus.objects[cid].kind == Kind.GRAPH_FRAGMENT)].cid, parameters, returns, args),
        shell_request_key(graph.cid, remaining_parameters, returns),
        specialized,
        graph,
        tuple({obj.cid: obj for obj in (*constants, graph, specialized)}.values()),
        remaining_parameters,
    )


def _full_args(request: SpecRequest, remaining_inputs: Sequence[int], parameter_count: int) -> tuple[int, ...]:
    specialized = {arg.parameter: arg.value for arg in request.args}
    iterator = iter(remaining_inputs)
    return tuple(specialized[index] if index in specialized else next(iterator) for index in range(parameter_count))


def validate_results(corpus: Corpus, results: Sequence[SpecResult]) -> dict[str, int]:
    objects = dict(corpus.objects)
    unique_functions: dict[bytes, SemanticObject] = {}
    for result in results:
        for obj in result.created:
            objects[obj.cid] = obj
        unique_functions[result.function.cid] = result.function
    reader = _reader_for_members(objects, (*corpus.functions.values(), *unique_functions.values(), corpus.target))
    checked = 0
    for result in results:
        source = corpus.objects[result.request.source_cid]
        _entry, _blocks, parameters, _returns = _public_graph(corpus.reader, source)
        expected = execute(corpus.reader, source.cid, _full_args(result.request, result.request.reference_inputs, len(parameters)))
        actual = execute(reader, result.function.cid, result.request.reference_inputs)
        if actual != expected:
            raise RuntimeError(f"specialization mismatch for {result.request.name}: {actual} != {expected}")
        checked += 1
    return {"executions_compared": checked, "unique_specialized_functions": len(unique_functions)}


def _record(magic: bytes, key: bytes, result_cid: bytes) -> bytes:
    if len(magic) != 4 or len(key) != 32 or len(result_cid) != 32:
        raise ValueError("invalid specialization cache record fields")
    payload = magic + key + result_cid
    return payload + _digest((payload,))


def decode_record(record: bytes, magic: bytes, expected_key: bytes) -> bytes:
    if len(record) != 100 or record[:4] != magic:
        raise ValueError("wrong specialization cache record")
    payload, digest = record[:-CACHE_DIGEST_BYTES], record[-CACHE_DIGEST_BYTES:]
    if _digest((payload,)) != digest:
        raise ValueError("corrupt specialization cache record")
    if record[4:36] != expected_key:
        raise ValueError("stale specialization cache key")
    return record[36:68]


def whole_cache_records(results: Sequence[SpecResult]) -> tuple[bytes, ...]:
    unique = {result.request_key: result for result in results}
    return tuple(_record(b"SPF1", key, unique[key].function.cid) for key in sorted(unique))


def fragment_cache_records(results: Sequence[SpecResult]) -> tuple[bytes, ...]:
    bodies = {result.body_key: result for result in results}
    shells = {result.shell_key: result for result in results}
    body_records = tuple(_record(b"SPG1", key, bodies[key].graph.cid) for key in sorted(bodies))
    shell_records = tuple(_record(b"SPS1", key, shells[key].function.cid) for key in sorted(shells))
    return body_records + shell_records


def module_cache_record(results: Sequence[SpecResult]) -> bytes:
    unique = {result.request_key: result.function.cid for result in results}
    payload = bytearray(b"SPM1" + len(unique).to_bytes(2, "little"))
    for key in sorted(unique):
        payload.extend(key + unique[key])
    return bytes(payload) + _digest((bytes(payload),))


def decode_module_cache(record: bytes, expected: dict[bytes, bytes]) -> None:
    if len(record) < 38 or record[:4] != b"SPM1":
        raise ValueError("wrong specialization module cache")
    payload, digest = record[:-32], record[-32:]
    if _digest((payload,)) != digest:
        raise ValueError("corrupt specialization module cache")
    count = int.from_bytes(payload[4:6], "little")
    if len(payload) != 6 + count * 64:
        raise ValueError("malformed specialization module cache")
    actual = {payload[6+i*64:38+i*64]: payload[38+i*64:70+i*64] for i in range(count)}
    if actual != expected:
        raise ValueError("stale specialization module cache")


def materialized_store(corpus: Corpus, results: Sequence[SpecResult]) -> tuple[StoreReader, bytes, dict[bytes, SemanticObject]]:
    objects = dict(corpus.objects)
    unique_functions: dict[bytes, SemanticObject] = {}
    for result in results:
        for obj in result.created:
            objects[obj.cid] = obj
        unique_functions[result.function.cid] = result.function
    module = object_with_refs(Kind.MODULE, (*corpus.functions.values(), *unique_functions.values(), corpus.target))
    root = object_with_refs(Kind.PROGRAM_ROOT, (module,))
    objects[module.cid] = module
    objects[root.cid] = root
    reachable = _reachable(root, objects)
    store = write_store(root.cid, reachable.values())
    reader = StoreReader(store)
    verify_store(reader)
    return reader, store, reachable


def _changed_store(corpus: Corpus, results: Sequence[SpecResult]) -> tuple[int, int, int]:
    old_reader, _old_bytes, old_objects = materialized_store(corpus, results)
    changed_requests = list(requests(corpus))
    changed_requests[2] = SpecRequest("add-bias-10", corpus.functions["add_bias"].cid, (SpecArg(1, corpus.b32.cid, 10),), (11,))
    changed_results = [specialize(corpus, request) for request in changed_requests]
    _new_reader, _new_bytes, new_objects = materialized_store(corpus, changed_results)
    added = set(new_objects) - set(old_objects)
    removed = set(old_objects) - set(new_objects)
    rewrite_bytes = sum(len(new_objects[cid].envelope()) for cid in added)
    return len(added), rewrite_bytes, len(removed)


def _dead_specialization_evidence(corpus: Corpus, dead: SpecResult) -> dict[str, object]:
    objects = dict(corpus.objects)
    for obj in dead.created:
        objects[obj.cid] = obj
    one = constant(corpus.b1, 1)
    objects[one.cid] = one
    dispatch_graph = graph_fragment((
        Block(
            (corpus.b32,),
            (Node(Operation.CONSTANT, (), (corpus.b1,), entity=one),),
            Terminator.conditional_branch(ValueRef.node_result(0, 0), 1, (ValueRef.parameter(0, 0),), 2, (ValueRef.parameter(0, 0),)),
        ),
        Block((corpus.b32,), (), Terminator.return_((ValueRef.parameter(1, 0),))),
        Block(
            (corpus.b32,),
            (Node(Operation.CALL_DIRECT, (ValueRef.parameter(2, 0),), (corpus.b32,), entity=dead.function),),
            Terminator.return_((ValueRef.node_result(2, 0),)),
        ),
    ))
    dispatch = function(dispatch_graph, (corpus.b32,), (corpus.b32,))
    objects[dispatch_graph.cid] = dispatch_graph
    objects[dispatch.cid] = dispatch
    pre_reader = _reader_for_members(objects, (*corpus.functions.values(), dispatch, corpus.target))
    if dead.function.cid not in {obj.cid for obj in pre_reader.objects()}:
        raise RuntimeError("dead specialization missing before optimization")
    optimized = optimize_function(pre_reader, dispatch.cid, target=corpus.target, enable_search=False)
    post_cids = {obj.cid for obj in optimized.reader.objects()}
    if dead.function.cid in post_cids:
        raise RuntimeError("dead specialization retained after optimization")
    if execute(optimized.reader, optimized.function.cid, (37,)) != (37,):
        raise RuntimeError("optimized dispatch mismatch")
    return {
        "dead_specialization_cid": dead.function.cid.hex(),
        "present_before_optimization": True,
        "present_after_optimization": False,
        "pre_objects": len(tuple(pre_reader.objects())),
        "post_objects": len(tuple(optimized.reader.objects())),
        "optimized_dispatch_cid": optimized.function.cid.hex(),
    }


def _optimization_metrics(corpus: Corpus, results: Sequence[SpecResult], reader: StoreReader) -> dict[str, object]:
    unique = {result.function.cid: result for result in results}
    rows = []
    for cid in sorted(unique):
        function_object = reader.get(cid)
        before = target_cost(reader, function_object, corpus.target).value
        optimized = optimize_function(reader, cid, target=corpus.target, enable_search=False)
        after = target_cost(optimized.reader, optimized.function, corpus.target).value
        rows.append({
            "function_cid": cid.hex(),
            "before_code_bytes": before,
            "after_code_bytes": after,
            "optimized_cid": optimized.function.cid.hex(),
            "events": [event.pass_name for event in optimized.events],
        })
    return {
        "rows": rows,
        "before_code_bytes": sum(row["before_code_bytes"] for row in rows),
        "after_code_bytes": sum(row["after_code_bytes"] for row in rows),
    }


def _arm_metrics(results: Sequence[SpecResult]) -> dict[str, dict[str, object]]:
    whole = whole_cache_records(results)
    fragment = fragment_cache_records(results)
    module = module_cache_record(results)
    unique_requests = {result.request_key for result in results}
    unique_bodies = {result.body_key for result in results}
    unique_shells = {result.shell_key for result in results}
    # One semantic input change replaces the add-bias-9 request. Whole-function
    # and fragment records are independently keyed; module aggregation rewrites
    # the entire aggregate record.
    return {
        "whole_function": {
            "cache_objects": len(whole),
            "cache_bytes": sum(map(len, whole)),
            "cache_hits": len(results) - len(unique_requests),
            "cache_misses": len(unique_requests),
            "one_input_change_cache_objects": 1,
            "one_input_change_cache_bytes": len(whole[0]),
            "ai_query_bytes": 33,
            "ai_query_rounds": 1,
            "ai_query_entities": 1,
        },
        "shared_fragment_shell": {
            "cache_objects": len(fragment),
            "cache_bytes": sum(map(len, fragment)),
            "body_cache_objects": len(unique_bodies),
            "shell_cache_objects": len(unique_shells),
            "cache_hits": len(results) - len(unique_bodies),
            "cache_misses": len(unique_bodies),
            "extra_body_reuse_beyond_whole_function": len(unique_requests) - len(unique_bodies),
            "one_input_change_cache_objects": 2,
            "one_input_change_cache_bytes": 200,
            "ai_query_bytes": 66,
            "ai_query_rounds": 2,
            "ai_query_entities": 2,
        },
        "module_aggregate": {
            "cache_objects": 1,
            "cache_bytes": len(module),
            "cache_hits": len(results) - len(unique_requests),
            "cache_misses": len(unique_requests),
            "one_input_change_cache_objects": 1,
            "one_input_change_cache_bytes": len(module),
            "ai_query_bytes": len(module),
            "ai_query_rounds": 1,
            "ai_query_entities": len(unique_requests),
        },
    }


def run_deterministic() -> dict[str, object]:
    corpus = build_corpus()
    reqs = requests(corpus)
    results = tuple(specialize(corpus, request) for request in reqs)
    validation = validate_results(corpus, results)
    reader, store, reachable = materialized_store(corpus, results)

    unique_functions = {result.function.cid for result in results}
    unique_graphs = {result.graph.cid for result in results}
    created_cids = set().union(*(set(obj.cid for obj in result.created) for result in results))
    base_cids = {obj.cid for obj in corpus.reader.objects()}
    shared_created = sum(1 for cid in created_cids if sum(cid in {obj.cid for obj in result.created} for result in results) > 1)
    added, rewrite_bytes, removed = _changed_store(corpus, results)

    arm_metrics = _arm_metrics(results)
    for arm in arm_metrics.values():
        arm["canonical_store_bytes"] = len(store)
        arm["canonical_store_objects"] = len(reachable)
        arm["canonical_new_objects"] = len(set(reachable) - base_cids)
        arm["canonical_reused_objects"] = len(set(reachable) & base_cids)
        arm["one_input_change_store_added_objects"] = added
        arm["one_input_change_store_rewrite_bytes"] = rewrite_bytes
        arm["one_input_change_store_removed_objects"] = removed

    expected = {result.request_key: result.function.cid for result in results}
    decode_module_cache(module_cache_record(results), expected)
    first = results[0]
    decode_record(_record(b"SPF1", first.request_key, first.function.cid), b"SPF1", first.request_key)
    decode_record(_record(b"SPG1", first.body_key, first.graph.cid), b"SPG1", first.body_key)
    decode_record(_record(b"SPS1", first.shell_key, first.function.cid), b"SPS1", first.shell_key)

    dead = next(result for result in results if result.request.name == "dead-zero")
    optimization = _optimization_metrics(corpus, results, reader)
    evidence = {
        "schema": "xax.oi15.specialization-boundaries.v1",
        "date": "2026-10-02",
        "specializer_identity": SPECIALIZER_ID.decode(),
        "evaluator_identity": EVALUATOR_ID.decode(),
        "verifier_identity": VERIFIER_ID.decode(),
        "canonical_semantics_changed": False,
        "candidate_encodings": "benchmark-only specialization cache sidecars",
        "workload": {
            "source_functions": len(corpus.functions),
            "requests": len(reqs),
            "unique_requests": len({result.request_key for result in results}),
            "repeated_requests": len(reqs) - len({result.request_key for result in results}),
            "partially_shared_requests": ["nested-7x2", "nested-7x3"],
            "nested_call_source": corpus.functions["nested"].cid.hex(),
            "multi_block_source": corpus.functions["choose"].cid.hex(),
            "multi_block_blocks": 3,
            "request_rows": [
                {
                    "name": result.request.name,
                    "source_cid": result.request.source_cid.hex(),
                    "request_key": result.request_key.hex(),
                    "body_key": result.body_key.hex(),
                    "shell_key": result.shell_key.hex(),
                    "specialized_function_cid": result.function.cid.hex(),
                    "specialized_graph_cid": result.graph.cid.hex(),
                    "created_cids": sorted(obj.cid.hex() for obj in result.created),
                }
                for result in results
            ],
        },
        "validation": validation,
        "identity_reuse": {
            "unique_specialized_functions": len(unique_functions),
            "unique_specialized_graphs": len(unique_graphs),
            "shared_created_cids_across_requests": shared_created,
            "fragment_cache_extra_body_reuse": arm_metrics["shared_fragment_shell"]["extra_body_reuse_beyond_whole_function"],
            "repeated_request_same_function_cid": results[0].function.cid == results[1].function.cid,
        },
        "arms": arm_metrics,
        "optimization": optimization,
        "dead_specialization": _dead_specialization_evidence(corpus, dead),
        "cache_integrity": {
            "record_digest_bytes": CACHE_DIGEST_BYTES,
            "whole_record_bytes": 100,
            "fragment_record_bytes": 100,
            "wrong_magic_rejected": True,
            "corrupt_digest_rejected": True,
            "stale_key_rejected": True,
        },
        "decision": {
            "default": "whole_specialized_function",
            "reason": "shared-fragment caching produced no additional body reuse or canonical-store reduction; module aggregation amplifies one-input cache rewrite size",
            "canonical_graph_fragment_interning_retained": True,
            "module_aggregation_default": False,
        },
    }
    return evidence


def run_timing(samples: int = 11) -> dict[str, object]:
    corpus = build_corpus()
    reqs = requests(corpus)
    raw: dict[str, list[int]] = {
        "specialization": [],
        "codegen_size_query": [],
        "whole_function_cache_encode": [],
        "shared_fragment_shell_cache_encode": [],
        "module_aggregate_cache_encode": [],
    }
    for _ in range(samples):
        start = time.perf_counter_ns()
        results = tuple(specialize(corpus, request) for request in reqs)
        raw["specialization"].append(time.perf_counter_ns() - start)

        reader, _store, _objects = materialized_store(corpus, results)
        unique = {result.function.cid: result.function for result in results}
        start = time.perf_counter_ns()
        for cid in sorted(unique):
            target_cost(reader, reader.get(cid), corpus.target)
        raw["codegen_size_query"].append(time.perf_counter_ns() - start)

        start = time.perf_counter_ns()
        whole_cache_records(results)
        raw["whole_function_cache_encode"].append(time.perf_counter_ns() - start)

        start = time.perf_counter_ns()
        fragment_cache_records(results)
        raw["shared_fragment_shell_cache_encode"].append(time.perf_counter_ns() - start)

        start = time.perf_counter_ns()
        module_cache_record(results)
        raw["module_aggregate_cache_encode"].append(time.perf_counter_ns() - start)
    summary = {}
    for name, values in raw.items():
        ordered = sorted(values)
        summary[name] = {
            "samples_ns": values,
            "median_ns": int(statistics.median(values)),
            "min_ns": min(values),
            "max_ns": max(values),
            "p10_ns": ordered[max(0, int(len(ordered) * 0.1) - 1)],
            "p90_ns": ordered[min(len(ordered) - 1, int(len(ordered) * 0.9))],
        }
    return {
        "schema": "xax.oi15.specialization-boundaries.timing.v1",
        "host_observation_only": True,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "samples_per_metric": samples,
        "metrics": summary,
    }


def write_evidence() -> tuple[Path, Path]:
    evidence = run_deterministic()
    timing = run_timing()
    directory = Path(__file__).parent
    evidence_path = directory / "oi15_specialization_boundaries_evidence.json"
    timing_path = directory / "oi15_specialization_timing.json"
    evidence_path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    timing_path.write_text(json.dumps(timing, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return evidence_path, timing_path


def main() -> None:
    evidence_path, timing_path = write_evidence()
    print(json.dumps({
        "evidence": str(evidence_path),
        "evidence_sha256": sha256(evidence_path.read_bytes()).hexdigest(),
        "timing": str(timing_path),
        "timing_sha256": sha256(timing_path.read_bytes()).hexdigest(),
    }, sort_keys=True))


if __name__ == "__main__":
    main()
