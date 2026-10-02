"""Deterministic non-timing accounting smoke for same-block pure-node move."""

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
from xax_workspace import MovePureNode, RootRef, Transaction, Workspace


def fixture() -> tuple[StoreReader, bytes]:
    b8 = bits_type(8)
    two, three = constant(b8, 2), constant(b8, 3)
    callee_graph = graph_fragment(
        [
            Block(
                (),
                (
                    Node(Operation.CONSTANT, (), (b8,), entity=two),
                    Node(Operation.CONSTANT, (), (b8,), entity=three),
                    Node(Operation.ADD_WRAP, (ValueRef.node_result(0, 0), ValueRef.node_result(0, 1)), (b8,)),
                ),
                Terminator.return_((ValueRef.node_result(0, 2),)),
            )
        ]
    )
    callee = function(callee_graph, (), (b8,))
    caller_graph = graph_fragment(
        [
            Block(
                (),
                (Node(Operation.CALL_DIRECT, (), (b8,), entity=callee),),
                Terminator.return_((ValueRef.node_result(0, 0),)),
            )
        ]
    )
    caller = function(caller_graph, (), (b8,))
    unrelated = constant(b8, 255)
    module = object_with_refs(Kind.MODULE, (callee, caller, unrelated))
    root = object_with_refs(Kind.PROGRAM_ROOT, (module,))
    objects = (b8, two, three, callee_graph, callee, caller_graph, caller, unrelated, module, root)
    return StoreReader(write_store(root.cid, objects)), callee.cid


def main() -> None:
    reader, callee_cid = fixture()
    workspace = Workspace(reader)
    before = execute(workspace.reader, callee_cid, ())
    nodes = workspace.function_nodes(callee_cid, 3).entities
    query_bytes = workspace.accounting.query_bytes
    entities_exposed = workspace.accounting.entities_exposed
    transaction = Transaction(
        RootRef(0),
        (MovePureNode(nodes[1].handle, 0, 1, nodes[0].handle, 0, 0),),
    )
    result = workspace.commit(transaction)
    if not result.committed:
        raise RuntimeError(result.diagnostic)
    after = execute(workspace.reader, result.changed_entity, ())
    current = workspace.function_nodes(result.changed_entity, 3).entities
    record = {
        "schema": "xax-m6-move-node-smoke-v1",
        "timing": False,
        "environment": {
            "python": platform.python_version(),
            "implementation": platform.python_implementation(),
            "platform": platform.platform(),
        },
        "mutation": "move-pure-node",
        "source_handle": nodes[1].handle,
        "expected_source": [0, 1],
        "destination_handle": nodes[0].handle,
        "expected_destination": [0, 0],
        "query_bytes": query_bytes,
        "entities_exposed": entities_exposed,
        "transaction_bytes": result.transaction_bytes,
        "touched_objects": result.touched_objects,
        "reused_objects": result.reused_objects,
        "verified_objects": result.verified_objects,
        "before_result": list(before),
        "after_result": list(after),
        "node_constants_after": [node.constant_value for node in current[:2]],
        "caller_count_after": len(workspace.callers(result.changed_entity, 8).entities),
        "committed": result.committed,
    }
    output = Path(__file__).with_name("m6_move_node_smoke.json")
    output.write_text(json.dumps(record, sort_keys=True, indent=2) + "\n")
    print(json.dumps(record, sort_keys=True))


if __name__ == "__main__":
    main()
