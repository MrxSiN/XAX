"""Deterministic non-timing accounting smoke for M6 proof-dependency reads."""

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
from xax_workspace import RootRef, SetOperation, Transaction, Workspace, _query_size


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
                    Node(
                        Operation.ADD_WRAP,
                        (ValueRef.node_result(0, 0), ValueRef.node_result(0, 1)),
                        (b8,),
                    ),
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
    node = workspace.function_nodes(entry_cid, 3).entities[2]
    before_query_bytes = workspace.accounting.query_bytes
    proof = workspace.proof(node.handle)
    proof_response_bytes = workspace.accounting.query_bytes - before_query_bytes
    if proof_response_bytes != _query_size(proof):
        raise RuntimeError("proof response accounting mismatch")
    before = execute(workspace.reader, entry_cid, ())
    result = workspace.commit(
        Transaction(
            RootRef(0),
            (SetOperation(node.handle, Operation.ADD_WRAP, Operation.MUL_WRAP),),
            (proof.dependency_handle,),
        )
    )
    if not result.committed:
        raise RuntimeError(result.diagnostic)
    after = execute(workspace.reader, result.changed_entity, ())
    current = workspace.function_nodes(result.changed_entity, 3).entities[2]
    stale = workspace.commit(
        Transaction(
            RootRef(1),
            (SetOperation(current.handle, Operation.MUL_WRAP, Operation.SUB_WRAP),),
            (proof.dependency_handle,),
        )
    )
    if stale.committed or stale.diagnostic is None:
        raise RuntimeError("changed proof dependency unexpectedly remained reusable")

    record = {
        "schema": "xax-m6-proof-dependency-smoke-v1",
        "timing": False,
        "environment": {
            "python": platform.python_version(),
            "implementation": platform.python_implementation(),
            "platform": platform.platform(),
        },
        "proof_subject_handle": node.handle,
        "proof_dependency_handle": proof.dependency_handle,
        "proof_response_bytes": proof_response_bytes,
        "transaction_bytes": result.transaction_bytes,
        "touched_objects": result.touched_objects,
        "reused_objects": result.reused_objects,
        "verified_objects": result.verified_objects,
        "before_result": list(before),
        "after_result": list(after),
        "committed": result.committed,
        "post_change_conflict_code": stale.diagnostic.code,
        "post_change_conflict_rule": stale.diagnostic.rule,
        "persistent_cids_exposed": any(
            isinstance(value, str) and len(value) == 64
            for _, value, _ in proof.facts
        ),
    }
    output = Path(__file__).with_name("m6_proof_dependency_smoke.json")
    output.write_text(json.dumps(record, sort_keys=True, indent=2) + "\n")
    print(json.dumps(record, sort_keys=True))


if __name__ == "__main__":
    main()
