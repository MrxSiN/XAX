"""Deterministic non-timing accounting smoke for the DeleteNode workspace mutation."""

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
from xax_workspace import DeleteNode, RootRef, Transaction, Workspace


def fixture() -> tuple[StoreReader, bytes]:
    b8 = bits_type(8)
    unused = constant(b8, 9)
    callee_graph = graph_fragment(
        [
            Block(
                (b8, b8),
                (
                    Node(Operation.CONSTANT, (), (b8,), entity=unused),
                    Node(Operation.ADD_WRAP, (ValueRef.parameter(0, 0), ValueRef.parameter(0, 1)), (b8,)),
                ),
                Terminator.return_((ValueRef.node_result(0, 1),)),
            )
        ]
    )
    callee = function(callee_graph, (b8, b8), (b8,))
    caller_graph = graph_fragment(
        [
            Block(
                (b8, b8),
                (Node(Operation.CALL_DIRECT, (ValueRef.parameter(0, 0), ValueRef.parameter(0, 1)), (b8,), entity=callee),),
                Terminator.return_((ValueRef.node_result(0, 0),)),
            )
        ]
    )
    caller = function(caller_graph, (b8, b8), (b8,))
    unrelated = constant(b8, 255)
    module = object_with_refs(Kind.MODULE, (callee, caller, unrelated))
    root = object_with_refs(Kind.PROGRAM_ROOT, (module,))
    objects = (b8, unused, callee_graph, callee, caller_graph, caller, unrelated, module, root)
    return StoreReader(write_store(root.cid, objects)), callee.cid


def main() -> None:
    reader, callee_cid = fixture()
    workspace = Workspace(reader)
    node = workspace.function_nodes(callee_cid, 2).entities[0]
    before = execute(workspace.reader, callee_cid, (2, 3))
    result = workspace.commit(Transaction(RootRef(0), (DeleteNode(node.handle, 0, 0),)))
    if not result.committed:
        raise RuntimeError(result.diagnostic)
    after = execute(workspace.reader, result.changed_entity, (2, 3))
    record = {
        "schema": "xax-m6-delete-node-smoke-v1",
        "timing": False,
        "environment": {
            "python": platform.python_version(),
            "implementation": platform.python_implementation(),
            "platform": platform.platform(),
        },
        "mutation": "delete-node",
        "target_node_handle": node.handle,
        "expected_containment": [0, 0],
        "transaction_bytes": result.transaction_bytes,
        "touched_objects": result.touched_objects,
        "reused_objects": result.reused_objects,
        "verified_objects": result.verified_objects,
        "before_result": list(before),
        "after_result": list(after),
        "nodes_before": 2,
        "nodes_after": len(workspace.function_nodes(result.changed_entity, 2).entities),
        "caller_count_after": len(workspace.callers(result.changed_entity, 8).entities),
        "committed": result.committed,
    }
    output = Path(__file__).with_name("m6_delete_node_smoke.json")
    output.write_text(json.dumps(record, sort_keys=True, indent=2) + "\n")
    print(json.dumps(record, sort_keys=True))


if __name__ == "__main__":
    main()
