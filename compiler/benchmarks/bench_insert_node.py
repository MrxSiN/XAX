"""Deterministic non-timing accounting smoke for pure-node insertion."""

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
from xax_workspace import InsertPureNode, ReplaceUse, RootRef, Transaction, TransactionValueRef, Workspace


def fixture() -> tuple[StoreReader, bytes]:
    b8 = bits_type(8)
    two, three = constant(b8, 2), constant(b8, 3)
    graph = graph_fragment(
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
    entry = function(graph, (), (b8,))
    unrelated = constant(b8, 255)
    module = object_with_refs(Kind.MODULE, (entry, unrelated))
    root = object_with_refs(Kind.PROGRAM_ROOT, (module,))
    return StoreReader(write_store(root.cid, (b8, two, three, graph, entry, unrelated, module, root))), entry.cid


def main() -> None:
    reader, entry_cid = fixture()
    workspace = Workspace(reader)
    before = execute(workspace.reader, entry_cid, ())
    nodes = workspace.function_nodes(entry_cid, 3).entities
    type_handle = workspace.neighborhood(nodes[0].handle, 1).entities[0].type_handle
    query_bytes = workspace.accounting.query_bytes
    entities_exposed = workspace.accounting.entities_exposed
    transaction = Transaction(
        RootRef(0),
        (
            InsertPureNode(nodes[1].handle, 0, 1, 4, Operation.CONSTANT, (), type_handle, 9),
            ReplaceUse(nodes[2].handle, 0, ValueRef.node_result(0, 0), TransactionValueRef(4)),
        ),
    )
    result = workspace.commit(transaction)
    if not result.committed:
        raise RuntimeError(result.diagnostic)
    after = execute(workspace.reader, result.changed_entity, ())
    record = {
        "schema": "xax-m6-insert-node-smoke-v1",
        "timing": False,
        "environment": {
            "python": platform.python_version(),
            "implementation": platform.python_implementation(),
            "platform": platform.platform(),
        },
        "mutation": "insert-pure-node+replace-use",
        "insert_before": nodes[1].handle,
        "expected_position": [0, 1],
        "transaction_local_result": "I4.R0",
        "query_bytes": query_bytes,
        "entities_exposed": entities_exposed,
        "transaction_bytes": result.transaction_bytes,
        "touched_objects": result.touched_objects,
        "reused_objects": result.reused_objects,
        "verified_objects": result.verified_objects,
        "before_result": list(before),
        "after_result": list(after),
        "nodes_before": 3,
        "nodes_after": len(workspace.function_nodes(result.changed_entity, 4).entities),
        "committed": result.committed,
    }
    output = Path(__file__).with_name("m6_insert_node_smoke.json")
    output.write_text(json.dumps(record, sort_keys=True, indent=2) + "\n")
    print(json.dumps(record, sort_keys=True))


if __name__ == "__main__":
    main()
