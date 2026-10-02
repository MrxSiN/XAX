"""Deterministic non-timing accounting smoke for narrow workspace specialization."""

from __future__ import annotations

import json
import platform
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
    write_store,
)
from xax_workspace import (
    RootRef,
    SpecializationArgument,
    SpecializeFunction,
    Transaction,
    Workspace,
)


def fixture() -> tuple[StoreReader, bytes, bytes]:
    b8 = bits_type(8)
    source_graph = graph_fragment(
        [
            Block(
                (b8, b8),
                (Node(Operation.ADD_WRAP, (ValueRef.parameter(0, 0), ValueRef.parameter(0, 1)), (b8,)),),
                Terminator.return_((ValueRef.node_result(0, 0),)),
            )
        ]
    )
    source = function(source_graph, (b8, b8), (b8,))
    caller_graph = graph_fragment(
        [
            Block(
                (b8, b8),
                (Node(Operation.CALL_DIRECT, (ValueRef.parameter(0, 0), ValueRef.parameter(0, 1)), (b8,), entity=source),),
                Terminator.return_((ValueRef.node_result(0, 0),)),
            )
        ]
    )
    caller = function(caller_graph, (b8, b8), (b8,))
    module = object_with_refs(Kind.MODULE, (source, caller))
    root = object_with_refs(Kind.PROGRAM_ROOT, (module,))
    objects = (b8, source_graph, source, caller_graph, caller, module, root)
    return StoreReader(write_store(root.cid, objects)), source.cid, caller.cid


def main() -> None:
    reader, source_cid, caller_cid = fixture()
    workspace = Workspace(reader)
    source = workspace.callees(caller_cid, 1).entities[0]
    node = workspace.function_nodes(source_cid, 1).entities[0]
    type_handle = workspace.operands(node.handle, 2).entities[0].type_handle
    query_bytes = workspace.accounting.query_bytes
    transaction = Transaction(
        RootRef(0),
        (SpecializeFunction(source.handle, (SpecializationArgument(0, type_handle, 5),)),),
    )
    result = workspace.commit(transaction)
    if not result.committed:
        raise RuntimeError(result.diagnostic)
    if execute(workspace.reader, result.changed_entity, (3,)) != (8,):
        raise RuntimeError("specialized execution mismatch")
    if execute(workspace.reader, source_cid, (5, 3)) != (8,) or execute(workspace.reader, caller_cid, (5, 3)) != (8,):
        raise RuntimeError("source or caller changed")

    record = {
        "schema": "xax.m6.specialize.accounting.v1",
        "date": "2026-09-29",
        "measurement": "deterministic non-timing accounting smoke",
        "python": platform.python_version(),
        "platform": platform.platform(),
        "query_bytes": query_bytes,
        "entities_exposed": workspace.accounting.entities_exposed,
        "transaction_bytes": result.transaction_bytes,
        "touched_objects": result.touched_objects,
        "reused_objects": result.reused_objects,
        "verified_objects": result.verified_objects,
        "source_cid": source_cid.hex(),
        "specialized_cid": result.changed_entity.hex(),
        "root": result.root.hex(),
        "specialized_result": 8,
        "source_and_caller_preserved": True,
        "claims": ["accounting", "determinism", "semantic execution"],
        "non_claims": ["timing", "model success", "META conformance", "language performance"],
    }
    output = Path(__file__).with_name("m6_specialize_smoke.json")
    output.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(record, sort_keys=True))


if __name__ == "__main__":
    main()
