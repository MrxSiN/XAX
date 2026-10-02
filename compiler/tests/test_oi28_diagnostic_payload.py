import csv
import json
import tempfile
from pathlib import Path

import pytest

from benchmarks import bench_oi28_diagnostic_payload as oi28
from xax_workspace import RootRef, SetConstant, Transaction


def test_failure_corpus_has_requested_families_and_exact_known_targets():
    corpus = oi28.cases()
    assert [case.family for case in corpus] == [
        "stale-relation",
        "containment-drift",
        "delete-used-node",
        "proof-dependency",
        "insert-position",
        "edge-argument",
        "move-dominance",
        "type-mismatch",
        "resource-effect",
    ]
    expected = {
        "relation": ("XAX.WORKSPACE.RELATION_CONFLICT", "WORKSPACE-OPERAND-PRECONDITION"),
        "containment": ("XAX.WORKSPACE.CONTAINMENT_CONFLICT", "WORKSPACE-NODE-CONTAINMENT"),
        "delete-used": ("XAX.WORKSPACE.DELETE_USE_CONFLICT", "WORKSPACE-DELETE-NODE-UNUSED"),
        "proof": ("XAX.WORKSPACE.PROOF_CONFLICT", "WORKSPACE-PROOF-DEPENDENCY"),
        "insert": ("XAX.WORKSPACE.CONTAINMENT_CONFLICT", "WORKSPACE-INSERT-POSITION"),
        "edge": ("XAX.WORKSPACE.RELATION_CONFLICT", "WORKSPACE-EDGE-ARGUMENT-PRECONDITION"),
        "move": ("XAX.STRUCT.SSA_DOMINANCE", "GRAPH-SSA-DOMINANCE"),
        "type": ("XAX.STRUCT.OP_TYPE", "GRAPH-OP-TYPE"),
        "resource": ("XAX.RESOURCE.DROP", "RESOURCE-LINEAR-CONTINUATION"),
    }
    for case in corpus:
        assert (case.diagnostic.code, case.diagnostic.rule) == expected[case.task_id]
        assert len(case.target_root) == 64
        int(case.target_root, 16)
        assert case.known_repair


def test_payloads_are_deterministic_and_near_is_strict_extension_of_minimal():
    first = oi28.cases()
    second = oi28.cases()
    for left, right in zip(first, second):
        assert oi28.minimal_payload(left) == oi28.minimal_payload(right)
        assert oi28.near_payload(left) == oi28.near_payload(right)
        minimal = oi28.minimal_payload(left)
        near = oi28.near_payload(left)
        for field in ("v", "base", "code", "entity", "rule", "expected", "actual", "dependencies", "repair"):
            assert near[field] == minimal[field]
        assert near["repair"]
        assert len(oi28._json_bytes(near)) >= len(oi28._json_bytes(minimal))


def test_near_payload_has_bounded_positive_progress_and_stable_order():
    case = {case.task_id: case for case in oi28.cases()}["resource"]
    all_entities = oi28.near_payload(case, entity_cap=128, byte_cap=1 << 20)["near"]
    seen = []
    continuation = 0
    pages = 0
    while True:
        page = oi28.near_payload(case, continuation=continuation)
        pages += 1
        assert page["repair"] == list(oi28._direct_handles(case))
        assert 0 < len(page["near"]) <= oi28.NEAR_ENTITY_CAP
        seen.extend(page["near"])
        if not page["truncated"]:
            break
        assert page["continuation"] > continuation
        continuation = page["continuation"]
    assert pages >= 2
    assert seen == all_entities
    assert [item["handle"] for item in seen] == sorted(item["handle"] for item in seen)


def test_too_small_budget_rejects_instead_of_omitting_failure_relation():
    case = oi28.cases()[0]
    required = len(oi28._json_bytes(oi28.minimal_payload(case)))
    with pytest.raises(ValueError, match="required diagnostic core"):
        oi28.payload(case, "minimal", byte_cap=required - 1)
    with pytest.raises(ValueError):
        oi28.near_payload(case, byte_cap=required)


def test_payload_base_detects_workspace_staleness():
    case = {case.task_id: case for case in oi28.cases()}["relation"]
    packet = oi28.minimal_payload(case)
    assert oi28.payload_is_fresh(case, packet)
    # Advance the exact same workspace without relying on the rejected mutation.
    nodes = case.workspace.function_nodes(next(obj.cid for obj in case.workspace.reader.objects() if obj.kind.name == "FUNCTION"), 8).entities
    result = case.workspace.commit(Transaction(RootRef(case.workspace.generation), (SetConstant(nodes[0].handle, nodes[0].constant_value, 4),)))
    assert result.committed
    assert not oi28.payload_is_fresh(case, packet)


def test_evidence_is_deterministic_without_host_timing_and_marks_model_fields_unavailable():
    first, _ = oi28.build_evidence(measure_timing=False)
    second, _ = oi28.build_evidence(measure_timing=False)
    assert first == second
    assert first["corpus_size"] == 9
    assert first["model_run"] is None
    assert all(row["model_total_tokens"] is None for row in first["rows"])
    assert first["totals"]["near_payload_bytes"] > first["totals"]["minimal_payload_bytes"]


def test_trial_preparation_exposes_payload_but_not_known_repair_or_target_root():
    with tempfile.TemporaryDirectory() as directory:
        count = oi28.prepare_trials(Path(directory))
        assert count == 18
        task = json.loads((Path(directory) / "type" / "near" / "TASK.json").read_text())
        text = json.dumps(task)
        assert "known_repair" not in text
        assert "target_root" not in text
        assert task["diagnostic"]["rule"] == "GRAPH-OP-TYPE"
        assert task["response_contract"]["fresh_session"] is True


def test_trial_recorder_is_flat_and_rejects_duplicate_cell(monkeypatch):
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "trials.csv"
        monkeypatch.setattr(oi28, "TRIALS_PATH", path)
        class Args:
            task_id = "relation"
            arm = "minimal"
            outcome = "PASS"
            trial = 1
            model = "model-x"
            reasoning = "fixed"
            input_tokens = 10
            output_tokens = 3
            total_tokens = None
            turns = 1
            invalid_followups = 0
            queried_entities = 1
            final_root = {case.task_id: case.target_root for case in oi28.cases()}["relation"]
            notes = ""
        oi28.record_trial(Args())
        with path.open(newline="") as stream:
            rows = list(csv.DictReader(stream))
        assert rows[0]["total_tokens"] == "13"
        assert rows[0]["payload_bytes"]
        with pytest.raises(ValueError, match="already recorded"):
            oi28.record_trial(Args())
