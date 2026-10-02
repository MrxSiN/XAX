"""Deterministic non-timing accounting smoke for M6 x86 artifact mapping."""

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
    Permission,
    StoreReader,
    Terminator,
    ValueRef,
    bits_type,
    function,
    graph_fragment,
    memory_effect_type,
    object_with_refs,
    pointer_type,
    stack_owner_type,
    write_store,
    x86_64_windows_target,
)
from xax_workspace import Workspace


def fixture() -> tuple[StoreReader, bytes]:
    b32 = bits_type(32)
    pointer = pointer_type(b32, Permission.READ_WRITE, 4)
    owner = stack_owner_type()
    effect = memory_effect_type()
    nodes = (
        Node(Operation.STACK_ALLOC, (), (pointer, owner, effect), attributes=(4, 4)),
        Node(
            Operation.STORE_BITS_LE,
            (ValueRef.node_result(0, 0, 0), ValueRef.parameter(0, 0), ValueRef.node_result(0, 0, 2)),
            (effect,),
            attributes=(4, 4),
        ),
        Node(
            Operation.LOAD_BITS_LE,
            (ValueRef.node_result(0, 0, 0), ValueRef.node_result(0, 1)),
            (b32, effect),
            attributes=(4, 4),
        ),
        Node(Operation.STACK_END, (ValueRef.node_result(0, 0, 1), ValueRef.node_result(0, 2, 1)), ()),
    )
    graph = graph_fragment([Block((b32,), nodes, Terminator.return_((ValueRef.node_result(0, 2),)))])
    entry = function(graph, (b32,), (b32,))
    module = object_with_refs(Kind.MODULE, (entry,))
    root = object_with_refs(Kind.PROGRAM_ROOT, (module,))
    reader = StoreReader(write_store(root.cid, (b32, pointer, owner, effect, graph, entry, module, root)))
    return reader, entry.cid


def measured(workspace: Workspace, name: str, call):
    before = workspace.accounting.query_bytes
    result = call()
    return result, workspace.accounting.query_bytes - before


def main() -> int:
    reader, entry_cid = fixture()
    workspace = Workspace(reader, x86_64_windows_target())
    artifact, artifact_query_bytes = measured(workspace, "artifact", lambda: workspace.artifact(entry_cid))
    nodes, node_query_bytes = measured(workspace, "nodes", lambda: workspace.function_nodes(entry_cid, 8))
    function_map, function_map_bytes = measured(
        workspace, "map_function", lambda: workspace.map_semantic(artifact.entry_handle, artifact.handle, 1)
    )
    allocation_map, allocation_map_bytes = measured(
        workspace, "map_allocation", lambda: workspace.map_semantic(nodes.entities[0].handle, artifact.handle, 1)
    )
    store_map, store_map_bytes = measured(
        workspace, "map_store", lambda: workspace.map_semantic(nodes.entities[1].handle, artifact.handle, 1)
    )
    first, first_bytes = measured(
        workspace,
        "map_artifact_page_1",
        lambda: workspace.map_artifact(artifact.handle, store_map.ranges[0].start, 1, 1),
    )
    second, second_bytes = measured(
        workspace,
        "map_artifact_page_2",
        lambda: workspace.map_artifact(artifact.handle, store_map.ranges[0].start, 1, 1, first.continuation),
    )

    data = {
        "case": "m6_x86_artifact_mapping_accounting_v2",
        "claim_scope": "deterministic accounting/conformance smoke only; no timing or performance conclusion",
        "environment": {
            "python": platform.python_version(),
            "implementation": platform.python_implementation(),
            "platform": platform.platform(),
        },
        "artifact": {
            "handle": artifact.handle,
            "format": artifact.format,
            "size_bytes": artifact.size_bytes,
            "entry_offset": artifact.entry_offset,
            "target": artifact.target,
            "identity": artifact.identity,
            "digest": artifact.digest,
            "semantic_root": artifact.semantic_root,
            "compiler_identity": artifact.compiler_identity,
            "lowering_identity": artifact.lowering_identity,
        },
        "mappings": {
            "function": [[item.start, item.end, item.relation] for item in function_map.ranges],
            "stack_alloc_classification": allocation_map.classification,
            "store": [[item.start, item.end, item.relation] for item in store_map.ranges],
            "artifact_contributors_at_store_start": [
                [item.handle, item.kind, item.start, item.end] for item in (*first.entities, *second.entities)
            ],
        },
        "query_bytes": {
            "artifact": artifact_query_bytes,
            "function_nodes": node_query_bytes,
            "map_function": function_map_bytes,
            "map_stack_alloc": allocation_map_bytes,
            "map_store": store_map_bytes,
            "map_artifact_page_1": first_bytes,
            "map_artifact_page_2": second_bytes,
            "total": workspace.accounting.query_bytes,
        },
        "entities_exposed": workspace.accounting.entities_exposed,
        "queries": workspace.accounting.queries,
    }
    output = Path(__file__).with_name("m6_artifact_mapping_smoke.json")
    output.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(data, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
