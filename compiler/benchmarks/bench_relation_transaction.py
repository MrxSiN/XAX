"""Deterministic non-timing accounting smoke for the ReplaceUse workspace mutation."""

from __future__ import annotations

import json
import platform
import sys
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
    execute,
    function,
    graph_fragment,
    object_with_refs,
    write_store,
)
from xax_workspace import ReplaceUse, RootRef, Transaction, Workspace


def fixture() -> tuple[StoreReader, bytes]:
    b8 = bits_type(8)
    arithmetic_graph = graph_fragment(
        [
            Block(
                (b8, b8),
                (Node(Operation.ADD_WRAP, (ValueRef.parameter(0, 0), ValueRef.parameter(0, 1)), (b8,)),),
                Terminator.return_((ValueRef.node_result(0, 0),)),
            )
        ]
    )
    arithmetic = function(arithmetic_graph, (b8, b8), (b8,))
    caller_graph = graph_fragment(
        [
            Block(
                (b8, b8),
                (
                    Node(Operation.CALL_DIRECT, (ValueRef.parameter(0, 0), ValueRef.parameter(0, 1)), (b8,), entity=arithmetic),
                    Node(Operation.ADD_WRAP, (ValueRef.node_result(0, 0), ValueRef.parameter(0, 0)), (b8,)),
                ),
                Terminator.return_((ValueRef.node_result(0, 1),)),
            )
        ]
    )
    caller = function(caller_graph, (b8, b8), (b8,))
    module = object_with_refs(Kind.MODULE, (arithmetic, caller))
    root = object_with_refs(Kind.PROGRAM_ROOT, (module,))
    reader = StoreReader(write_store(root.cid, (b8, arithmetic_graph, arithmetic, caller_graph, caller, module, root)))
    return reader, arithmetic.cid


def main() -> None:
    reader, arithmetic_cid = fixture()
    workspace = Workspace(reader)
    node = workspace.function_nodes(arithmetic_cid, 1).entities[0]
    before = execute(workspace.reader, arithmetic_cid, (2, 3))
    result = workspace.commit(
        Transaction(
            RootRef(0),
            (
                ReplaceUse(
                    node.handle,
                    0,
                    ValueRef.parameter(0, 0),
                    ValueRef.parameter(0, 1),
                ),
            ),
        )
    )
    if not result.committed:
        raise RuntimeError(result.diagnostic)
    after = execute(workspace.reader, result.changed_entity, (2, 3))
    record = {
        "schema": "xax-m6-relation-transaction-smoke-v1",
        "timing": False,
        "environment": {
            "python": platform.python_version(),
            "implementation": platform.python_implementation(),
            "platform": platform.platform(),
        },
        "mutation": "replace-use",
        "target_node_handle": node.handle,
        "operand_index": 0,
        "expected_relation": [0, 0, 0, 0],
        "replacement_relation": [0, 0, 1, 0],
        "transaction_bytes": result.transaction_bytes,
        "touched_objects": result.touched_objects,
        "reused_objects": result.reused_objects,
        "verified_objects": result.verified_objects,
        "before_result": list(before),
        "after_result": list(after),
        "caller_count_after": len(workspace.callers(result.changed_entity, 8).entities),
        "committed": result.committed,
    }
    output = Path(__file__).with_name("m6_relation_transaction_smoke.json")
    output.write_text(json.dumps(record, sort_keys=True, indent=2) + "\n")
    print(json.dumps(record, sort_keys=True))


if __name__ == "__main__":
    main()
