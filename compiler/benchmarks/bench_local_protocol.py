"""Deterministic semantic evidence for the ordinary local protocol (ADR-186)."""

import argparse
import json
from pathlib import Path

from xax_compiler import Block, Kind, Node, Operation, StoreReader, Terminator, ValueRef, bits_type, constant, function, graph_fragment, object_with_refs, write_store
from xax_local_protocol import LocalMutationSession
from xax_workspace import RootRef, SetConstant, SetOperation, Transaction, Workspace

EVIDENCE = Path(__file__).with_name("local_protocol_evidence.json")


def fixture():
    typ = bits_type(32)
    value = constant(typ, 3)
    graph = graph_fragment([Block((typ,), (
        Node(Operation.CONSTANT, (), (typ,), entity=value),
        Node(Operation.ADD_WRAP, (ValueRef.parameter(0, 0), ValueRef.node_result(0, 0)), (typ,)),
    ), Terminator.return_((ValueRef.node_result(0, 1),)))])
    fn = function(graph, (typ,), (typ,))
    module = object_with_refs(Kind.MODULE, (fn,))
    root = object_with_refs(Kind.PROGRAM_ROOT, (module,))
    return Workspace(StoreReader(write_store(root.cid, [typ, value, graph, fn, module, root]))), fn.cid


def evidence():
    workspace, cid = fixture()
    base = workspace.root.hex()
    session = LocalMutationSession.for_function(workspace, cid)
    batch = "set-constant N0 7; set-op N1 mul.wrap"
    transaction = session.transaction(batch)
    exact = Transaction(RootRef(0), (
        SetConstant(session.aliases["N0"], 3, 7),
        SetOperation(session.aliases["N1"], Operation.ADD_WRAP, Operation.MUL_WRAP),
    ))
    assert transaction == exact
    result = workspace.commit(transaction)
    assert result.committed
    stale = session.commit("set-constant N0 9")
    assert not stale.committed and stale.diagnostic.code == "XAX.WORKSPACE.STALE_ROOT"
    target = workspace.root.hex()
    fresh = LocalMutationSession.for_function(workspace, result.changed_entity)
    rejected = fresh.commit("set-constant N0 11; delete N0")
    assert not rejected.committed and workspace.root.hex() == target
    return {
        "format": "xax-local-protocol-evidence-v1", "label": "EXECUTED",
        "authority": "bootstrap Python workspace verifier and transaction interface",
        "base_root": base, "target_root": target,
        "batch_expands_to_exact_transaction": transaction == exact,
        "stale_snapshot_diagnostic": stale.diagnostic.code,
        "invalid_batch_diagnostic": rejected.diagnostic.code,
        "invalid_batch_preserves_root": workspace.root.hex() == target,
        "limits": ["No model/token or JVM runtime-performance measurement.",
                   "No XAX-hosted compiler execution claim."],
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    encoded = json.dumps(evidence(), indent=2) + "\n"
    if args.write:
        EVIDENCE.write_text(encoded, encoding="utf-8", newline="\n")
    else:
        print(encoded, end="")


if __name__ == "__main__":
    main()
