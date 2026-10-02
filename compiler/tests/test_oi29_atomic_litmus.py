from __future__ import annotations

import json
from pathlib import Path

import pytest

from benchmarks import bench_oi29_atomic_litmus as bench
from xax_compiler import (
    AtomicFamily,
    AtomicLitmusEvent,
    AtomicOrder,
    CompareExchangeStrength,
    XaxError,
    validate_atomic_litmus,
)

HERE = Path(__file__).resolve().parent
EVIDENCE = HERE.parent / "benchmarks" / "oi29_atomic_litmus_evidence.json"
RAW = HERE.parent / "benchmarks" / "oi29_atomic_litmus_timing.json"
CORPUS = HERE.parent / "benchmarks" / "oi29_atomic_litmus_corpus.json"


def test_all_semantic_cases_match_exact_expected_facts():
    for case in bench.litmus_cases():
        assert bench._signature(case) == bench._expected_signature(case), case.name


def test_failed_cmpxchg_uses_failure_order_for_acquire_and_sc():
    acquire_failure = next(case for case in bench.litmus_cases() if case.name == "cmpxchg_failure_acquire")
    result = validate_atomic_litmus(acquire_failure.events)
    assert (0, 1) in result.happens_before
    assert result.seq_cst_order == ()

    sc_failure = validate_atomic_litmus((
        AtomicLitmusEvent(0, "x", AtomicFamily.STORE, AtomicOrder.RELEASE),
        AtomicLitmusEvent(1, "x", AtomicFamily.CMPXCHG, AtomicOrder.SEQ_CST, reads_from=0,
                          failure_order=AtomicOrder.SEQ_CST, strength=CompareExchangeStrength.STRONG,
                          succeeded=False),
    ))
    assert sc_failure.seq_cst_order == (1,)


def test_race_case_rejects_with_stable_rule():
    case = bench.race_case()
    with pytest.raises(XaxError) as caught:
        bench.validate_memory_events(case.events)
    assert caught.value.diagnostic.rule == case.expected_rule


def test_every_injected_fault_is_detected_and_reversible():
    matrix = bench.fault_matrix()
    assert set(matrix) == set(bench.FAULTS)
    assert all(matrix[fault] for fault in bench.FAULTS)
    assert all(bench.corpus_results().values())


def test_greedy_minimum_preserves_required_semantics_and_fault_coverage():
    matrix = bench.fault_matrix()
    selected = bench.minimum_corpus(matrix)
    coverage = bench.coverage_by_case(matrix)
    union = set().union(*(coverage[name] for name in selected))
    for fault in bench.FAULTS:
        assert f"fault.{fault}" in union
    for required in (
        "order.relaxed", "order.acquire", "order.release", "order.acq_rel", "order.seq_cst",
        "family.load", "family.store", "family.rmw", "family.cmpxchg.success", "family.cmpxchg.failure",
        "family.fence", "release_sequence", "sc_total_order", "race_rejection",
        "target.x86_64", "target.aarch64", "target.wasm32", "capability.scope", "capability.alignment",
        "capability.width", "unsupported.reported",
    ):
        assert required in union
    for name in selected:
        remainder = [item for item in selected if item != name]
        remainder_union = set().union(*(coverage[item] for item in remainder)) if remainder else set()
        assert not union <= remainder_union


def test_target_matrix_reports_support_and_unsupported_explicitly():
    observed = bench.target_observation()
    assert bench.target_matches(observed)
    assert observed["x86_seq_cst_fence_count"] == 1
    assert observed["aarch64_seq_cst_fence_count"] == 2
    assert observed["aarch64_rmw"] == "unsupported"
    assert observed["wasm_load"] == "unsupported"
    assert observed["x86_bad_width"] == "unsupported"
    assert observed["x86_bad_alignment"] == "unsupported"
    assert observed["x86_bad_scope"] == "unsupported"


def test_faults_do_not_modify_real_target_or_semantic_state():
    baseline = bench.target_observation()
    _ = bench.target_observation("narrow_scope")
    _ = bench.target_observation("accept_unsupported_width_alignment")
    assert bench.target_observation() == baseline
    assert all(bench.corpus_results().values())


def test_corpus_artifact_has_machine_readable_outcomes_and_explicit_unsupported():
    corpus = bench.build_corpus_artifact()
    assert corpus["schema"] == "xax-atomic-litmus-v1"
    assert all(case["expected_outcomes"] for case in corpus["semantic_cases"])
    assert corpus["target_case"]["expected"]["wasm_load"] == "unsupported"


def test_committed_evidence_replays_from_raw_samples():
    raw = json.loads(RAW.read_text())
    expected = json.loads(EVIDENCE.read_text())
    assert bench.evidence_from_raw(raw) == expected
    assert expected["all_faults_detected"] is True
    assert expected["minimum_case_count"] <= expected["full_case_count"]
    assert json.loads(CORPUS.read_text()) == bench.build_corpus_artifact()
