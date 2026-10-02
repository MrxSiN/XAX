"""Deterministic non-timing accounting smoke for candidate-only verify/rollback."""

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
from xax_workspace import RootRef, SetOperation, Transaction, Workspace


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
    objects = (b8, two, three, graph, entry, unrelated, module, root)
    return StoreReader(write_store(root.cid, objects)), entry.cid


def main() -> None:
    reader, entry_cid = fixture()
    workspace = Workspace(reader)
    original_root = workspace.root
    before = execute(workspace.reader, entry_cid, ())
    nodes = workspace.function_nodes(entry_cid, 3).entities
    query_bytes = workspace.accounting.query_bytes
    entities_exposed = workspace.accounting.entities_exposed
    transaction = Transaction(
        RootRef(0),
        (SetOperation(nodes[2].handle, Operation.ADD_WRAP, Operation.MUL_WRAP),),
        (nodes[2].handle,),
    )

    verification = workspace.verify(transaction)
    if not verification.verified or verification.candidate_handle is None:
        raise RuntimeError(verification.diagnostic)
    root_after_verify = workspace.root
    generation_after_verify = workspace.generation
    rollback = workspace.rollback(verification.candidate_handle)
    if not rollback.rolled_back:
        raise RuntimeError(rollback.diagnostic)
    root_after_rollback = workspace.root
    generation_after_rollback = workspace.generation

    committed = workspace.commit(transaction)
    if not committed.committed:
        raise RuntimeError(committed.diagnostic)
    after = execute(workspace.reader, committed.changed_entity, ())

    record = {
        "schema": "xax-m6-candidate-verify-smoke-v1",
        "timing": False,
        "environment": {
            "python": platform.python_version(),
            "implementation": platform.python_implementation(),
            "platform": platform.platform(),
        },
        "operation": "verify+rollback+ordinary-commit",
        "query_bytes": query_bytes,
        "entities_exposed": entities_exposed,
        "candidate_handle": verification.candidate_handle,
        "candidate_transaction_bytes": verification.transaction_bytes,
        "candidate_touched_objects": verification.touched_objects,
        "candidate_reused_objects": verification.reused_objects,
        "candidate_verified_objects": verification.verified_objects,
        "candidate_verifications": workspace.accounting.candidate_verifications,
        "candidate_rollbacks": workspace.accounting.candidate_rollbacks,
        "candidate_accounted_transaction_bytes": workspace.accounting.candidate_transaction_bytes,
        "candidate_accounted_verified_objects": workspace.accounting.candidate_verified_objects,
        "canonical_root_unchanged_after_verify": root_after_verify == original_root,
        "canonical_root_unchanged_after_rollback": root_after_rollback == original_root,
        "generation_after_verify": generation_after_verify,
        "generation_after_rollback": generation_after_rollback,
        "before_result": list(before),
        "after_commit_result": list(after),
        "ordinary_commit_transaction_bytes": committed.transaction_bytes,
        "ordinary_commit_succeeded": committed.committed,
    }
    output = Path(__file__).with_name("m6_candidate_verify_smoke.json")
    output.write_text(json.dumps(record, sort_keys=True, indent=2) + "\n")
    print(json.dumps(record, sort_keys=True))


if __name__ == "__main__":
    main()
