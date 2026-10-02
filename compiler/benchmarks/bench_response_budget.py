"""Deterministic non-timing accounting smoke for workspace response-byte budgets."""

from __future__ import annotations

import json
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
    function,
    graph_fragment,
    object_with_refs,
    write_store,
)
from xax_workspace import Workspace, _query_size


def fixture():
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
    module = object_with_refs(Kind.MODULE, (entry,))
    root = object_with_refs(Kind.PROGRAM_ROOT, (module,))
    return StoreReader(write_store(root.cid, (b8, two, three, graph, entry, module, root))), entry


def main() -> None:
    reader, entry = fixture()
    unbounded = Workspace(reader).function_nodes(entry.cid, 3)
    one_pages = [Workspace(reader).function_nodes(entry.cid, 1, offset) for offset in range(3)]
    budget = max(_query_size(page) for page in one_pages)

    workspace = Workspace(reader)
    pages = []
    continuation = 0
    while continuation is not None:
        page = workspace.function_nodes(entry.cid, 3, continuation, byte_budget=budget)
        pages.append(page)
        continuation = page.continuation

    record = {
        "kind": "m6-response-byte-budget-accounting-v1",
        "timing": False,
        "budget_bytes": budget,
        "unbounded_response_bytes": _query_size(unbounded),
        "bounded_page_bytes": [_query_size(page) for page in pages],
        "bounded_total_response_bytes": sum(_query_size(page) for page in pages),
        "bounded_page_entity_counts": [len(page.entities) for page in pages],
        "continuations": [page.continuation for page in pages],
        "entities_exposed": workspace.accounting.entities_exposed,
        "query_count": workspace.accounting.queries,
        "accounted_query_bytes": workspace.accounting.query_bytes,
        "notes": "Exact deterministic bootstrap JSON bytes only; not model-token counts or timing evidence.",
    }
    path = Path(__file__).with_name("m6_response_budget_smoke.json")
    path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    print(json.dumps(record, sort_keys=True))


if __name__ == "__main__":
    main()
