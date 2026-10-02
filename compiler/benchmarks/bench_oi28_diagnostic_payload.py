"""OI-28 diagnostic-payload / repair-neighborhood measurement harness.

This is measurement-only tooling. Diagnostic packets are non-source projections and
never participate in canonical XAX identity.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import platform
import shutil
import statistics
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable

from xax_compiler import (
    Block,
    Diagnostic,
    EffectDomain,
    Kind,
    Node,
    Operation,
    ResourceFlags,
    StoreReader,
    Terminator,
    ValueRef,
    bits_type,
    constant,
    effect_type,
    function,
    graph_fragment,
    object_with_refs,
    resource_type,
    verify_store,
    write_store,
)
from xax_workspace import (
    ConnectEdgeArgument,
    DeleteNode,
    DisconnectEdgeArgument,
    InsertPureNode,
    MovePureNode,
    ReplaceUse,
    RootRef,
    SetConstant,
    SetOperation,
    Transaction,
    Workspace,
)

HERE = Path(__file__).resolve().parent
EVIDENCE_PATH = HERE / "oi28_diagnostic_payload_evidence.json"
TIMING_PATH = HERE / "oi28_diagnostic_payload_timing.json"
TASKS_PATH = HERE / "oi28_repair_tasks.json"
TRIALS_PATH = HERE / "oi28_model_trials.csv"
SCHEMA = "xax-oi28-diagnostic-payload-v1"
PAYLOAD_VERSION = "D1"
POLICIES = ("minimal", "near")
NEAR_ENTITY_CAP = 8
NEAR_BYTE_CAP = 1024
TRIAL_FIELDS = (
    "task_id", "arm", "trial", "model", "reasoning", "pass", "input_tokens", "output_tokens",
    "total_tokens", "turns", "invalid_followups", "queried_entities", "payload_bytes", "final_root", "notes",
)


@dataclass(frozen=True)
class RepairCase:
    task_id: str
    family: str
    prompt: str
    workspace: Workspace
    diagnostic: Diagnostic
    direct_handles: tuple[str, ...]
    target_root: str
    known_repair: tuple[dict[str, object], ...]


def _reader(root, objects) -> StoreReader:
    result = StoreReader(write_store(root.cid, objects))
    verify_store(result)
    return result


def _basic_fixture() -> tuple[StoreReader, bytes]:
    b8 = bits_type(8)
    two, three = constant(b8, 2), constant(b8, 3)
    graph = graph_fragment((Block(
        (),
        (
            Node(Operation.CONSTANT, (), (b8,), entity=two),
            Node(Operation.CONSTANT, (), (b8,), entity=three),
            Node(Operation.ADD_WRAP, (ValueRef.node_result(0, 0), ValueRef.node_result(0, 1)), (b8,)),
        ),
        Terminator.return_((ValueRef.node_result(0, 2),)),
    ),))
    entry = function(graph, (), (b8,))
    module = object_with_refs(Kind.MODULE, (entry,))
    root = object_with_refs(Kind.PROGRAM_ROOT, (module,))
    return _reader(root, (b8, two, three, graph, entry, module, root)), entry.cid


def _deletable_fixture() -> tuple[StoreReader, bytes]:
    b8 = bits_type(8)
    unused = constant(b8, 9)
    graph = graph_fragment((Block(
        (b8, b8),
        (
            Node(Operation.CONSTANT, (), (b8,), entity=unused),
            Node(Operation.ADD_WRAP, (ValueRef.parameter(0, 0), ValueRef.parameter(0, 1)), (b8,)),
        ),
        Terminator.return_((ValueRef.node_result(0, 1),)),
    ),))
    entry = function(graph, (b8, b8), (b8,))
    module = object_with_refs(Kind.MODULE, (entry,))
    root = object_with_refs(Kind.PROGRAM_ROOT, (module,))
    return _reader(root, (b8, unused, graph, entry, module, root)), entry.cid


def _edge_fixture() -> tuple[StoreReader, bytes]:
    b8, b16 = bits_type(8), bits_type(16)
    one = constant(b8, 1)
    graph = graph_fragment((
        Block(
            (b8, b8, b16),
            (
                Node(Operation.CONSTANT, (), (b8,), entity=one),
                Node(Operation.ADD_WRAP, (ValueRef.parameter(0, 0), ValueRef.parameter(0, 1)), (b8,)),
            ),
            Terminator.branch(1, (ValueRef.parameter(0, 0),)),
        ),
        Block((b8,), (), Terminator.return_((ValueRef.parameter(1, 0),))),
    ))
    entry = function(graph, (b8, b8, b16), (b8,))
    module = object_with_refs(Kind.MODULE, (entry,))
    root = object_with_refs(Kind.PROGRAM_ROOT, (module,))
    return _reader(root, (b8, b16, one, graph, entry, module, root)), entry.cid


def _type_fixture() -> tuple[StoreReader, bytes]:
    b8, b16 = bits_type(8), bits_type(16)
    graph = graph_fragment((Block(
        (b8, b8, b16, b8),
        (Node(Operation.ADD_WRAP, (ValueRef.parameter(0, 0), ValueRef.parameter(0, 1)), (b8,)),),
        Terminator.return_((ValueRef.node_result(0, 0),)),
    ),))
    entry = function(graph, (b8, b8, b16, b8), (b8,))
    module = object_with_refs(Kind.MODULE, (entry,))
    root = object_with_refs(Kind.PROGRAM_ROOT, (module,))
    return _reader(root, (b8, b16, graph, entry, module, root)), entry.cid


def _resource_fixture() -> tuple[StoreReader, bytes]:
    effect = effect_type(EffectDomain.FILESYSTEM, 4)
    resource = resource_type(2, 1, flags=ResourceFlags.ACQUIRABLE | ResourceFlags.RELEASABLE)
    graph = graph_fragment((Block(
        (effect,),
        (
            Node(Operation.RESOURCE_ACQUIRE, (ValueRef.parameter(0, 0),), (resource, effect)),
            Node(Operation.RESOURCE_ACQUIRE, (ValueRef.node_result(0, 0, 1),), (resource, effect)),
            Node(Operation.RESOURCE_RELEASE, (ValueRef.node_result(0, 0, 0), ValueRef.node_result(0, 1, 1)), (effect,)),
            Node(Operation.RESOURCE_RELEASE, (ValueRef.node_result(0, 1, 0), ValueRef.node_result(0, 2, 0)), (effect,)),
        ),
        Terminator.return_((ValueRef.node_result(0, 3, 0),)),
    ),))
    entry = function(graph, (effect,), (effect,))
    module = object_with_refs(Kind.MODULE, (entry,))
    root = object_with_refs(Kind.PROGRAM_ROOT, (module,))
    return _reader(root, (effect, resource, graph, entry, module, root)), entry.cid


def _must_fail(workspace: Workspace, transaction: Transaction) -> Diagnostic:
    result = workspace.commit(transaction)
    if result.committed or result.diagnostic is None:
        raise AssertionError("expected rejected transaction")
    return result.diagnostic


def _target_root(reader: StoreReader, function_cid: bytes, make_transaction: Callable[[Workspace, tuple], Transaction]) -> str:
    workspace = Workspace(reader)
    nodes = workspace.function_nodes(function_cid, 64).entities
    result = workspace.commit(make_transaction(workspace, nodes))
    if not result.committed:
        raise AssertionError(result.diagnostic)
    return result.root.hex()


def _case_stale_relation() -> RepairCase:
    reader, function_cid = _basic_fixture()
    workspace = Workspace(reader)
    nodes = workspace.function_nodes(function_cid, 8).entities
    bad = Transaction(RootRef(0), (ReplaceUse(nodes[2].handle, 0, ValueRef.node_result(0, 1), ValueRef.node_result(0, 1)),))
    diagnostic = _must_fail(workspace, bad)
    target = _target_root(reader, function_cid, lambda _w, n: Transaction(RootRef(0), (ReplaceUse(n[2].handle, 0, ValueRef.node_result(0, 0), ValueRef.node_result(0, 1)),)))
    return RepairCase(
        "relation", "stale-relation", "Repair the rejected operand relation update using only the diagnostic payload.", workspace,
        diagnostic, (nodes[2].handle,), target,
        ({"verb": "replace-use", "node": nodes[2].handle, "operand": 0, "expected": [1, 0, 0, 0], "value": [1, 0, 1, 0]},),
    )


def _case_containment() -> RepairCase:
    reader, function_cid = _deletable_fixture()
    workspace = Workspace(reader)
    nodes = workspace.function_nodes(function_cid, 8).entities
    diagnostic = _must_fail(workspace, Transaction(RootRef(0), (DeleteNode(nodes[0].handle, 0, 1),)))
    target = _target_root(reader, function_cid, lambda _w, n: Transaction(RootRef(0), (DeleteNode(n[0].handle, 0, 0),)))
    return RepairCase(
        "containment", "containment-drift", "Repair the stale containment precondition and delete the requested unused node.", workspace,
        diagnostic, (nodes[0].handle,), target,
        ({"verb": "delete", "node": nodes[0].handle, "expected_block": 0, "expected_index": 0},),
    )


def _case_delete_used() -> RepairCase:
    reader, function_cid = _basic_fixture()
    workspace = Workspace(reader)
    nodes = workspace.function_nodes(function_cid, 8).entities
    diagnostic = _must_fail(workspace, Transaction(RootRef(0), (DeleteNode(nodes[0].handle, 0, 0),)))

    target_workspace = Workspace(reader)
    target_nodes = target_workspace.function_nodes(function_cid, 8).entities
    first = target_workspace.commit(Transaction(RootRef(0), (
        ReplaceUse(target_nodes[2].handle, 0, ValueRef.node_result(0, 0), ValueRef.node_result(0, 1)),
    )))
    if not first.committed:
        raise AssertionError(first.diagnostic)
    current = target_workspace.function_nodes(first.changed_entity, 8).entities
    second = target_workspace.commit(Transaction(RootRef(1), (DeleteNode(current[0].handle, 0, 0),)))
    if not second.committed:
        raise AssertionError(second.diagnostic)
    target = second.root.hex()
    return RepairCase(
        "delete-used", "delete-used-node", "Repair the rejected deletion by removing the live use before deleting the node.", workspace,
        diagnostic, (nodes[0].handle,), target,
        (
            {"stage": 1, "verb": "replace-use", "node": nodes[2].handle, "operand": 0, "expected": [1, 0, 0, 0], "value": [1, 0, 1, 0]},
            {"stage": 2, "verb": "delete", "node": "refresh:N0", "expected_block": 0, "expected_index": 0},
        ),
    )


def _case_proof() -> RepairCase:
    reader, function_cid = _basic_fixture()
    workspace = Workspace(reader)
    nodes = workspace.function_nodes(function_cid, 8).entities
    proof = workspace.proof(nodes[2].handle)
    first = workspace.commit(Transaction(RootRef(0), (SetOperation(nodes[2].handle, Operation.ADD_WRAP, Operation.MUL_WRAP),)))
    if not first.committed:
        raise AssertionError(first.diagnostic)
    current = workspace.function_nodes(first.changed_entity, 8).entities
    diagnostic = _must_fail(workspace, Transaction(RootRef(1), (SetOperation(current[2].handle, Operation.MUL_WRAP, Operation.SUB_WRAP),), (proof.dependency_handle,)))

    target_workspace = Workspace(StoreReader(workspace.reader.canonical_bytes()))
    current2 = target_workspace.function_nodes(first.changed_entity, 8).entities
    fresh = target_workspace.proof(current2[2].handle)
    repaired = target_workspace.commit(Transaction(RootRef(0), (SetOperation(current2[2].handle, Operation.MUL_WRAP, Operation.SUB_WRAP),), (fresh.dependency_handle,)))
    if not repaired.committed:
        raise AssertionError(repaired.diagnostic)
    return RepairCase(
        "proof", "proof-dependency", "Refresh the invalid proof dependency and retry the same semantic operation change.", workspace,
        diagnostic, (current[2].handle, proof.dependency_handle), repaired.root.hex(),
        ({"verb": "refresh-proof", "node": current[2].handle}, {"verb": "set-op", "node": current[2].handle, "expected": "mul_wrap", "value": "sub_wrap"}),
    )


def _case_insert() -> RepairCase:
    reader, function_cid = _basic_fixture()
    workspace = Workspace(reader)
    nodes = workspace.function_nodes(function_cid, 8).entities
    type_handle = workspace.neighborhood(nodes[0].handle, 8).entities[0].type_handle
    diagnostic = _must_fail(workspace, Transaction(RootRef(0), (InsertPureNode(nodes[1].handle, 0, 0, 0, Operation.CONSTANT, (), type_handle, 9),)))

    def repair(w, n):
        t = w.neighborhood(n[0].handle, 8).entities[0].type_handle
        return Transaction(RootRef(0), (InsertPureNode(n[1].handle, 0, 1, 0, Operation.CONSTANT, (), t, 9),))

    target = _target_root(reader, function_cid, repair)
    return RepairCase(
        "insert", "insert-position", "Repair the stale insertion position and insert constant 9 immediately before the requested anchor.", workspace,
        diagnostic, (nodes[1].handle,), target,
        ({"verb": "insert-constant", "anchor": nodes[1].handle, "expected_block": 0, "expected_index": 1, "local_id": 0, "value": 9},),
    )


def _case_edge() -> RepairCase:
    reader, function_cid = _edge_fixture()
    workspace = Workspace(reader)
    nodes = workspace.function_nodes(function_cid, 8).entities
    anchor = nodes[1].handle
    diagnostic = _must_fail(workspace, Transaction(RootRef(0), (DisconnectEdgeArgument(anchor, 0, 0, 0, ValueRef.parameter(0, 1)),)))

    def repair(_w, n):
        a = n[1].handle
        return Transaction(RootRef(0), (
            DisconnectEdgeArgument(a, 0, 0, 0, ValueRef.parameter(0, 0)),
            ConnectEdgeArgument(a, 0, 0, 0, ValueRef.parameter(0, 1)),
        ))

    target = _target_root(reader, function_cid, repair)
    return RepairCase(
        "edge", "edge-argument", "Repair the stale edge-argument precondition and change B0's branch argument from P0 to P1.", workspace,
        diagnostic, (anchor,), target,
        (
            {"verb": "disconnect-edge", "node": anchor, "edge": 0, "argument": 0, "expected": [0, 0, 0, 0]},
            {"verb": "connect-edge", "node": anchor, "edge": 0, "argument": 0, "value": [0, 0, 1, 0]},
        ),
    )


def _case_move() -> RepairCase:
    reader, function_cid = _basic_fixture()
    workspace = Workspace(reader)
    nodes = workspace.function_nodes(function_cid, 8).entities
    diagnostic = _must_fail(workspace, Transaction(RootRef(0), (MovePureNode(nodes[2].handle, 0, 2, nodes[0].handle, 0, 0),)))
    target = _target_root(reader, function_cid, lambda _w, n: Transaction(RootRef(0), (MovePureNode(n[1].handle, 0, 1, n[0].handle, 0, 0),)))
    return RepairCase(
        "move", "move-dominance", "Repair the dominance-breaking move with the smallest valid move that satisfies the requested reorder.", workspace,
        diagnostic, (nodes[2].handle, nodes[0].handle), target,
        ({"verb": "move", "node": nodes[1].handle, "expected_block": 0, "expected_index": 1, "before": nodes[0].handle, "before_block": 0, "before_index": 0},),
    )


def _case_type() -> RepairCase:
    reader, function_cid = _type_fixture()
    workspace = Workspace(reader)
    node = workspace.function_nodes(function_cid, 8).entities[0]
    # Bind parameter values and their type handles through the node neighborhood.
    workspace.neighborhood(node.handle, 8)
    diagnostic = _must_fail(workspace, Transaction(RootRef(0), (ReplaceUse(node.handle, 1, ValueRef.parameter(0, 1), ValueRef.parameter(0, 2)),)))
    target = _target_root(reader, function_cid, lambda _w, n: Transaction(RootRef(0), (ReplaceUse(n[0].handle, 1, ValueRef.parameter(0, 1), ValueRef.parameter(0, 3)),)))
    return RepairCase(
        "type", "type-mismatch", "Repair the rejected operand replacement by selecting the requested compatible b8 parameter.", workspace,
        diagnostic, (node.handle,), target,
        ({"verb": "replace-use", "node": node.handle, "operand": 1, "expected": [0, 0, 1, 0], "value": [0, 0, 3, 0]},),
    )


def _case_resource() -> RepairCase:
    reader, function_cid = _resource_fixture()
    workspace = Workspace(reader)
    nodes = workspace.function_nodes(function_cid, 8).entities
    for node in nodes:
        workspace.neighborhood(node.handle, 8)
    diagnostic = _must_fail(workspace, Transaction(RootRef(0), (ReplaceUse(nodes[2].handle, 0, ValueRef.node_result(0, 0, 0), ValueRef.node_result(0, 1, 0)),)))

    def repair(_w, n):
        return Transaction(RootRef(0), (
            ReplaceUse(n[2].handle, 0, ValueRef.node_result(0, 0, 0), ValueRef.node_result(0, 1, 0)),
            ReplaceUse(n[3].handle, 0, ValueRef.node_result(0, 1, 0), ValueRef.node_result(0, 0, 0)),
        ))

    target = _target_root(reader, function_cid, repair)
    return RepairCase(
        "resource", "resource-effect", "Repair the linear-resource failure by completing the requested resource swap without changing the effect chain.", workspace,
        diagnostic, (nodes[2].handle, nodes[3].handle), target,
        (
            {"verb": "replace-use", "node": nodes[2].handle, "operand": 0, "expected": [1, 0, 0, 0], "value": [1, 0, 1, 0]},
            {"verb": "replace-use", "node": nodes[3].handle, "operand": 0, "expected": [1, 0, 1, 0], "value": [1, 0, 0, 0]},
        ),
    )


_CASES: tuple[Callable[[], RepairCase], ...] = (
    _case_stale_relation,
    _case_containment,
    _case_delete_used,
    _case_proof,
    _case_insert,
    _case_edge,
    _case_move,
    _case_type,
    _case_resource,
)


def cases() -> tuple[RepairCase, ...]:
    return tuple(make() for make in _CASES)


def _json_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _stable(value: object) -> object:
    if isinstance(value, tuple):
        return [_stable(item) for item in value]
    if isinstance(value, list):
        return [_stable(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _stable(value[key]) for key in sorted(value, key=str)}
    if hasattr(value, "name"):
        return str(value.name).lower()
    return value


def _direct_handles(case: RepairCase) -> tuple[str, ...]:
    return tuple(dict.fromkeys((*case.diagnostic.repair_neighborhood, *case.direct_handles)))


def minimal_payload(case: RepairCase) -> dict[str, object]:
    d = case.diagnostic
    return {
        "v": PAYLOAD_VERSION,
        "base": f"R0.{case.workspace.generation}",
        "code": d.code,
        "entity": d.entity,
        "rule": d.rule,
        "expected": _stable(d.expected),
        "actual": _stable(d.actual),
        "dependencies": list(d.dependencies),
        "repair": list(_direct_handles(case)),
    }


def _entity_record(workspace: Workspace, handle: str) -> dict[str, object] | None:
    if handle.startswith("P") or handle.startswith("R"):
        return None
    try:
        view = workspace.entity(handle)
    except Exception:
        return None
    return {"handle": view.handle, "kind": view.kind, "facts": [[name, _stable(value)] for name, value in view.facts]}


def _near_candidates(case: RepairCase) -> tuple[dict[str, object], ...]:
    workspace = case.workspace
    records: dict[str, dict[str, object]] = {}
    direct = _direct_handles(case)
    for handle in direct:
        record = _entity_record(workspace, handle)
        if record is not None:
            records[handle] = record
        if ".N" not in handle:
            continue
        try:
            neighborhood = workspace.neighborhood(handle, 32).entities
        except Exception:
            continue
        for value in neighborhood:
            key = value.handle
            records[key] = {"handle": key, "kind": "value", "type": value.type_handle, "relations": list(value.relations)}
            try:
                type_view = workspace.type(value.type_handle)
                type_key = value.type_handle
                records[type_key] = {"handle": type_key, "kind": "type", "form": type_view.form, "facts": [[name, _stable(v)] for name, v in type_view.facts]}
            except Exception:
                pass
            for relation in ("producer", "users"):
                try:
                    expanded = workspace.expand(value.handle, relation, 8, depth=1).entities
                except Exception:
                    continue
                for entity in expanded:
                    if entity.handle in direct:
                        continue
                    records[entity.handle] = {
                        "handle": entity.handle,
                        "kind": entity.kind,
                        "relation": entity.relation,
                        "operation": None if entity.operation is None else entity.operation.name.lower(),
                        "type": entity.type_handle,
                    }
        try:
            effect = workspace.effects(handle)
            if not effect.pure:
                records[f"{handle}#effect"] = {
                    "handle": handle,
                    "kind": "effect",
                    "domain": effect.domain,
                    "inputs": [value.handle for value in effect.inputs],
                    "outputs": [value.handle for value in effect.outputs],
                }
        except Exception:
            pass
    # The core always preserves the direct handles; near adds deterministic facts for them plus one-hop relations.
    return tuple(records[key] for key in sorted(records))


def near_payload(
    case: RepairCase,
    *,
    entity_cap: int = NEAR_ENTITY_CAP,
    byte_cap: int = NEAR_BYTE_CAP,
    continuation: int = 0,
) -> dict[str, object]:
    if entity_cap < 1 or byte_cap < 1 or continuation < 0:
        raise ValueError("positive caps and nonnegative continuation required")
    core = minimal_payload(case)
    extras = _near_candidates(case)
    if continuation > len(extras):
        raise ValueError("continuation beyond neighborhood")
    remaining = extras[continuation:]
    count = min(entity_cap, len(remaining))
    while count >= 0:
        end = continuation + count
        candidate = dict(core)
        candidate.update({
            "near": list(remaining[:count]),
            "truncated": end < len(extras),
            "continuation": end if end < len(extras) else None,
        })
        if len(_json_bytes(candidate)) <= byte_cap:
            if remaining and count == 0:
                raise ValueError("byte cap cannot make positive neighborhood progress")
            return candidate
        count -= 1
    raise ValueError("byte cap smaller than required diagnostic core")


def payload(case: RepairCase, policy: str, **kwargs) -> dict[str, object]:
    if policy == "minimal":
        result = minimal_payload(case)
        byte_cap = kwargs.get("byte_cap")
        if byte_cap is not None and len(_json_bytes(result)) > byte_cap:
            raise ValueError("byte cap smaller than required diagnostic core")
        return result
    if policy == "near":
        return near_payload(case, **kwargs)
    raise ValueError("policy must be minimal or near")




def payload_is_fresh(case: RepairCase, packet: dict[str, object]) -> bool:
    return packet.get("base") == f"R0.{case.workspace.generation}"


def prepare_trials(output: Path) -> int:
    output.mkdir(parents=True, exist_ok=True)
    count = 0
    for case in cases():
        for policy in POLICIES:
            directory = output / case.task_id / policy
            directory.mkdir(parents=True, exist_ok=True)
            task = {
                "schema": "xax-oi28-model-task-v1",
                "task_id": case.task_id,
                "arm": policy,
                "instruction": case.prompt,
                "diagnostic": payload(case, policy),
                "response_contract": {
                    "kind": "semantic-repair",
                    "require_exact_target": True,
                    "fresh_session": True,
                    "unrelated_context": False,
                },
            }
            (directory / "TASK.json").write_text(json.dumps(task, sort_keys=True, indent=2) + "\n", encoding="utf-8")
            count += 1
    return count

def _timed_payload(case: RepairCase, policy: str, samples: int = 31) -> tuple[dict[str, object], dict[str, object]]:
    values = []
    result = None
    for _ in range(samples):
        start = time.perf_counter_ns()
        result = payload(case, policy)
        values.append(time.perf_counter_ns() - start)
    assert result is not None
    ordered = sorted(values)
    return result, {
        "samples_ns": values,
        "median_ns": int(statistics.median(values)),
        "p10_ns": ordered[max(0, int(len(ordered) * 0.10) - 1)],
        "p90_ns": ordered[min(len(ordered) - 1, int(len(ordered) * 0.90))],
    }


def _availability() -> dict[str, object]:
    return {
        "executables": {name: shutil.which(name) for name in ("codex", "openai", "claude")},
        "credentials": {name: bool(os.environ.get(name)) for name in ("OPENAI_API_KEY", "CODEX_API_KEY", "ANTHROPIC_API_KEY")},
    }


def _task_record(case: RepairCase, payloads: dict[str, dict[str, object]]) -> dict[str, object]:
    return {
        "task_id": case.task_id,
        "family": case.family,
        "prompt": case.prompt,
        "expected_context_need": (
            "minimal-likely" if case.task_id in {"relation", "containment", "insert", "edge"}
            else "dependency-context-likely"
        ),
        "initial_failure": {
            "code": case.diagnostic.code,
            "rule": case.diagnostic.rule,
            "entity": case.diagnostic.entity,
            "expected": _stable(case.diagnostic.expected),
            "actual": _stable(case.diagnostic.actual),
        },
        "payloads": payloads,
        "known_repair": list(case.known_repair),
        "target_root": case.target_root,
    }


def _read_trials() -> list[dict[str, str]]:
    if not TRIALS_PATH.exists() or TRIALS_PATH.stat().st_size == 0:
        return []
    with TRIALS_PATH.open(newline="", encoding="utf-8") as stream:
        return list(csv.DictReader(stream))


def build_evidence(*, measure_timing: bool = True) -> tuple[dict[str, object], dict[str, object]]:
    rows = []
    task_records = []
    timing_rows = []
    for case in cases():
        task_payloads: dict[str, dict[str, object]] = {}
        for policy in POLICIES:
            if measure_timing:
                packet, timing = _timed_payload(case, policy)
            else:
                packet, timing = payload(case, policy), None
            encoded = _json_bytes(packet)
            task_payloads[policy] = packet
            near = packet.get("near", []) if policy == "near" else []
            rows.append({
                "task_id": case.task_id,
                "family": case.family,
                "policy": policy,
                "code": case.diagnostic.code,
                "rule": case.diagnostic.rule,
                "payload_bytes": len(encoded),
                "repair_handles": len(packet["repair"]),
                "near_entities": len(near),
                "truncated": bool(packet.get("truncated", False)),
                "target_root": case.target_root,
                "model_input_tokens": None,
                "model_output_tokens": None,
                "model_total_tokens": None,
                "repair_turns": None,
                "invalid_followups": None,
                "model_pass": None,
            })
            if timing is not None:
                timing_rows.append({"task_id": case.task_id, "policy": policy, **timing})
        task_records.append(_task_record(case, task_payloads))
    minimal_total = sum(row["payload_bytes"] for row in rows if row["policy"] == "minimal")
    near_total = sum(row["payload_bytes"] for row in rows if row["policy"] == "near")
    evidence = {
        "schema": SCHEMA,
        "timing": False,
        "payload_version": PAYLOAD_VERSION,
        "policies": {
            "minimal": "core diagnostic fields plus directly implicated repair handles",
            "near": f"minimal plus deterministic one-hop producers/users/types/effects capped at {NEAR_ENTITY_CAP} entities and {NEAR_BYTE_CAP} bytes",
        },
        "corpus_size": len(task_records),
        "rows": rows,
        "totals": {
            "minimal_payload_bytes": minimal_total,
            "near_payload_bytes": near_total,
            "near_overhead_bytes": near_total - minimal_total,
        },
        "tasks": task_records,
        "model_run": None if not _read_trials() else {"rows": _read_trials()},
        "model_access": _availability(),
        "decision": "open_pending_model_repair_trials",
    }
    timing = {
        "schema": "xax-oi28-diagnostic-payload-timing-v1",
        "timing": True,
        "environment": {
            "python": platform.python_version(),
            "implementation": platform.python_implementation(),
            "platform": platform.platform(),
        },
        "rows": timing_rows,
    }
    return evidence, timing


def write_artifacts() -> tuple[dict[str, object], dict[str, object]]:
    evidence, timing = build_evidence(measure_timing=True)
    EVIDENCE_PATH.write_text(json.dumps(evidence, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    TIMING_PATH.write_text(json.dumps(timing, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    TASKS_PATH.write_text(json.dumps({"schema": "xax-oi28-repair-tasks-v1", "tasks": evidence["tasks"]}, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    if not TRIALS_PATH.exists():
        with TRIALS_PATH.open("w", newline="", encoding="utf-8") as stream:
            csv.DictWriter(stream, fieldnames=TRIAL_FIELDS).writeheader()
    return evidence, timing


def record_trial(args: argparse.Namespace) -> None:
    if args.arm not in POLICIES:
        raise ValueError("arm must be minimal or near")
    if args.trial < 1 or args.turns < 1 or args.invalid_followups < 0 or args.queried_entities < 0:
        raise ValueError("trial/turn counts must be positive and counters nonnegative")
    for value in (args.input_tokens, args.output_tokens, args.total_tokens):
        if value is not None and value < 0:
            raise ValueError("token counts must be nonnegative")
    known = {case.task_id: case for case in cases()}
    if args.task_id not in known:
        raise ValueError("unknown task")
    rows = []
    if TRIALS_PATH.exists():
        with TRIALS_PATH.open(newline="", encoding="utf-8") as stream:
            rows = list(csv.DictReader(stream))
    if any(row["task_id"] == args.task_id and row["arm"] == args.arm and int(row["trial"]) == args.trial for row in rows):
        raise ValueError("trial already recorded")
    case = known[args.task_id]
    if args.outcome == "PASS" and args.final_root != case.target_root:
        raise ValueError("passing trial final root must equal exact target root")
    packet = payload(case, args.arm)
    total = args.total_tokens
    if total is None and args.input_tokens is not None and args.output_tokens is not None:
        total = args.input_tokens + args.output_tokens
    row = {
        "task_id": args.task_id,
        "arm": args.arm,
        "trial": args.trial,
        "model": args.model,
        "reasoning": args.reasoning,
        "pass": str(args.outcome == "PASS").upper(),
        "input_tokens": "" if args.input_tokens is None else args.input_tokens,
        "output_tokens": "" if args.output_tokens is None else args.output_tokens,
        "total_tokens": "" if total is None else total,
        "turns": args.turns,
        "invalid_followups": args.invalid_followups,
        "queried_entities": args.queried_entities,
        "payload_bytes": len(_json_bytes(packet)),
        "final_root": args.final_root,
        "notes": args.notes,
    }
    exists = TRIALS_PATH.exists() and TRIALS_PATH.stat().st_size > 0
    with TRIALS_PATH.open("a", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=TRIAL_FIELDS)
        if not exists:
            writer.writeheader()
        writer.writerow(row)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("evidence")
    show = sub.add_parser("show")
    show.add_argument("task_id")
    show.add_argument("arm", choices=POLICIES)
    prepare = sub.add_parser("prepare")
    prepare.add_argument("output", type=Path)
    record = sub.add_parser("record")
    record.add_argument("task_id")
    record.add_argument("arm", choices=POLICIES)
    record.add_argument("outcome", choices=("PASS", "FAIL"))
    record.add_argument("--trial", type=int, default=1)
    record.add_argument("--model", default="")
    record.add_argument("--reasoning", default="")
    record.add_argument("--input-tokens", type=int)
    record.add_argument("--output-tokens", type=int)
    record.add_argument("--total-tokens", type=int)
    record.add_argument("--turns", type=int, default=1)
    record.add_argument("--invalid-followups", type=int, default=0)
    record.add_argument("--queried-entities", type=int, default=0)
    record.add_argument("--final-root", default="")
    record.add_argument("--notes", default="")
    args = parser.parse_args(argv)
    if args.command == "show":
        known = {case.task_id: case for case in cases()}
        if args.task_id not in known:
            raise ValueError("unknown task")
        case = known[args.task_id]
        print(json.dumps({"task_id": case.task_id, "prompt": case.prompt, "diagnostic": payload(case, args.arm)}, sort_keys=True))
        return 0
    if args.command == "prepare":
        print(prepare_trials(args.output))
        return 0
    if args.command == "record":
        record_trial(args)
        return 0
    evidence, _ = write_artifacts()
    print(json.dumps({
        "schema": evidence["schema"],
        "corpus_size": evidence["corpus_size"],
        "totals": evidence["totals"],
        "model_run": evidence["model_run"],
        "evidence_sha256": _sha(EVIDENCE_PATH),
        "timing_sha256": _sha(TIMING_PATH),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
