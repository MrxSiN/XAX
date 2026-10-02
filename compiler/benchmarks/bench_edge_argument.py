"""Deterministic non-timing accounting smoke for block-edge argument reconnect."""

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
from xax_workspace import ConnectEdgeArgument, DisconnectEdgeArgument, RootRef, Transaction, Workspace


def fixture() -> tuple[StoreReader, bytes]:
    b8, b16 = bits_type(8), bits_type(16)
    one = constant(b8, 1)
    callee_graph = graph_fragment(
        [
            Block(
                (b8, b8, b16),
                (
                    Node(Operation.CONSTANT, (), (b8,), entity=one),
                    Node(Operation.ADD_WRAP, (ValueRef.parameter(0, 0), ValueRef.parameter(0, 1)), (b8,)),
                ),
                Terminator.branch(1, (ValueRef.parameter(0, 0),)),
            ),
            Block((b8,), (), Terminator.return_((ValueRef.parameter(1, 0),))),
        ]
    )
    callee = function(callee_graph, (b8, b8, b16), (b8,))
    caller_graph = graph_fragment(
        [
            Block(
                (b8, b8, b16),
                (
                    Node(
                        Operation.CALL_DIRECT,
                        (ValueRef.parameter(0, 0), ValueRef.parameter(0, 1), ValueRef.parameter(0, 2)),
                        (b8,),
                        entity=callee,
                    ),
                ),
                Terminator.return_((ValueRef.node_result(0, 0),)),
            )
        ]
    )
    caller = function(caller_graph, (b8, b8, b16), (b8,))
    unrelated = constant(b8, 255)
    module = object_with_refs(Kind.MODULE, (callee, caller, unrelated))
    root = object_with_refs(Kind.PROGRAM_ROOT, (module,))
    objects = (b8, b16, one, callee_graph, callee, caller_graph, caller, unrelated, module, root)
    return StoreReader(write_store(root.cid, objects)), callee.cid


def main() -> None:
    reader, callee_cid = fixture()
    workspace = Workspace(reader)
    before = execute(workspace.reader, callee_cid, (2, 3, 300))
    nodes = workspace.function_nodes(callee_cid, 2).entities
    query_bytes = workspace.accounting.query_bytes
    entities_exposed = workspace.accounting.entities_exposed
    anchor = nodes[1].handle
    transaction = Transaction(
        RootRef(0),
        (
            DisconnectEdgeArgument(anchor, 0, 0, 0, ValueRef.parameter(0, 0)),
            ConnectEdgeArgument(anchor, 0, 0, 0, ValueRef.parameter(0, 1)),
        ),
    )
    result = workspace.commit(transaction)
    if not result.committed:
        raise RuntimeError(result.diagnostic)
    after = execute(workspace.reader, result.changed_entity, (2, 3, 300))
    record = {
        "schema": "xax-m6-edge-argument-smoke-v1",
        "timing": False,
        "environment": {
            "python": platform.python_version(),
            "implementation": platform.python_implementation(),
            "platform": platform.platform(),
        },
        "mutation": "disconnect-edge-argument+connect-edge-argument",
        "anchor": anchor,
        "expected_block": 0,
        "edge_index": 0,
        "argument_index": 0,
        "expected_relation": [0, 0, 0, 0],
        "replacement_relation": [0, 0, 1, 0],
        "query_bytes": query_bytes,
        "entities_exposed": entities_exposed,
        "transaction_bytes": result.transaction_bytes,
        "touched_objects": result.touched_objects,
        "reused_objects": result.reused_objects,
        "verified_objects": result.verified_objects,
        "before_result": list(before),
        "after_result": list(after),
        "caller_count_after": len(workspace.callers(result.changed_entity, 2).entities),
        "committed": result.committed,
    }
    output = Path(__file__).with_name("m6_edge_argument_smoke.json")
    output.write_text(json.dumps(record, sort_keys=True, indent=2) + "\n")
    print(json.dumps(record, sort_keys=True))


if __name__ == "__main__":
    main()
