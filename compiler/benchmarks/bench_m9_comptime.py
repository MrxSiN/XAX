"""Deterministic M9 compile-time evaluation record; deliberately non-timing."""

from __future__ import annotations

import hashlib
import json

from xax_compiler import (
    Block,
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
    bits_type,
    constant,
    execute,
    function,
    graph_fragment,
    materialize_compile_time,
    object_with_refs,
    opaque_type,
    write_store,
    x86_64_windows_target,
)
from xax_x86_64 import compile_native, run_native_isolated


def main() -> None:
    b1, b32 = bits_type(1), bits_type(32)
    type_ref, constant_ref = opaque_type(OpaqueKind.TYPE), opaque_type(OpaqueKind.CONSTANT)
    target_ref, function_ref = opaque_type(OpaqueKind.TARGET), opaque_type(OpaqueKind.FUNCTION)
    five, target = constant(b32, 5), x86_64_windows_target()
    nodes = (
        Node(Operation.META_TYPE_BITS_WIDTH, (ValueRef.parameter(0, 0),), (b32,)),
        Node(Operation.META_CONSTANT_VALUE, (ValueRef.parameter(0, 1),), (b32,)),
        Node(Operation.META_TARGET_SUPPORTS, (ValueRef.parameter(0, 2),), (b1,), attributes=(Operation.ADD_WRAP,)),
        Node(Operation.META_DECLARED_INPUT, (), (b32,), attributes=(0,)),
        Node(Operation.ADD_WRAP, (ValueRef.node_result(0, 0), ValueRef.node_result(0, 1)), (b32,)),
        Node(Operation.ADD_WRAP, (ValueRef.node_result(0, 4), ValueRef.node_result(0, 3)), (b32,)),
        Node(Operation.META_MATERIALIZE_CONSTANT_FUNCTION, (ValueRef.parameter(0, 0), ValueRef.node_result(0, 5)), (function_ref,)),
    )
    graph = graph_fragment((Block((type_ref, constant_ref, target_ref), nodes, Terminator.return_((ValueRef.node_result(0, 6), ValueRef.node_result(0, 2)))),))
    entry = function(graph, (type_ref, constant_ref, target_ref), (function_ref, b1))
    module = object_with_refs(Kind.MODULE, (entry, target))
    root = object_with_refs(Kind.PROGRAM_ROOT, (module,))
    reader = StoreReader(write_store(root.cid, (b1, b32, type_ref, constant_ref, target_ref, function_ref, target, graph, entry, module, root)))
    evaluator = CompileTimeEvaluator()
    first = evaluator.evaluate(
        reader,
        entry.cid,
        (b32, five, target),
        capabilities=tuple(MetaCapability),
        inputs=(CompileTimeInput(b"build-number", b32, 7),),
    )
    second = evaluator.evaluate(
        reader,
        entry.cid,
        (b32, five, target),
        capabilities=tuple(MetaCapability),
        inputs=(CompileTimeInput(b"build-number", b32, 7),),
    )
    generated = first.values[0]
    candidate = materialize_compile_time(reader, first)
    image = compile_native(candidate, generated.cid, target.cid)
    record = {
        "cache_hit": second.cache_hit,
        "compile_time_key": first.key.hex(),
        "created_cids": [obj.cid.hex() for obj in first.created_objects],
        "generated_function_cid": generated.cid.hex(),
        "artifact_bytes": len(image.code),
        "artifact_sha256": hashlib.sha256(image.code).hexdigest(),
        "reference_result": execute(candidate, generated.cid, ())[0],
        "native_result": run_native_isolated(image, ())[0],
        "steps": first.steps,
        "target_supports_add": first.values[1],
    }
    print(json.dumps(record, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
