import hashlib
import json
from pathlib import Path

from benchmarks import bench_oi17_cost_model as b


def test_candidate_corpus_verifies_and_equivalent():
    reader,_target,compiled=b.compiled_cases()
    assert len(compiled)==13
    assert all(b.semantic_checks(compiled).values())
    assert len({case.family for case,_,_ in compiled if not case.family.startswith("_cal_")})==4
    assert reader.root_cid


def test_corpus_covers_required_shapes():
    _r,_t,compiled=b.compiled_cases()
    by={c.family:[c for c,_,_ in compiled if c.family==c.family] for c,_,_ in compiled}
    names={c.name for c,_,_ in compiled}
    assert {"arith_add2","arith_mul2","branch_lazy","branch_eager","mem_direct","mem_stack_roundtrip","dep_chain4x","dep_parallel4x"}.issubset(names)


def test_raw_measurements_have_real_samples_and_environment():
    raw=json.loads(b.RAW_OUT.read_text())
    assert raw["schema"]=="xax-oi17-cost-model-raw-v1"
    assert raw["samples"]>=15
    assert raw["pinned_cpu"] is not None
    assert raw["host"]["model"]
    for case in raw["cases"].values():
        assert len(case["latency"]["raw_batch_ns"])==raw["samples"]
        assert len(case["throughput"]["raw_batch_ns"])==raw["samples"]
        assert case["code_bytes"]>0


def test_three_model_families_and_metrics():
    e=b.build()
    for objective in ("latency","throughput"):
        models=e["objectives"][objective]["models"]
        assert set(models)=={"static_table","symbolic","measured_calibrated"}
        for model in models.values():
            assert model["metrics"]["pairwise_total"]==4
            assert model["metrics"]["mean_normalized_absolute_error"]>=0


def test_calibration_is_nonsemantic_and_selection_verified():
    e=b.build()
    assert e["nonsemantic_guards"]["calibration_not_in_semantic_store"]
    assert e["nonsemantic_guards"]["timing_guarantee"] is None
    assert e["bounded_optimizer_choice"]["verified_before_emission"]
    assert e["bounded_optimizer_choice"]["selected"] == "mem_direct"
    assert e["bounded_optimizer_choice"]["family"] == "memory"
    assert e["candidate_count"] == 8 and e["calibration_function_count"] == 5
    assert len(e["calibration_identity"])==64


def test_evidence_build_deterministic_from_fixed_raw():
    one=json.dumps(b.build(),sort_keys=True,separators=(",",":"))
    two=json.dumps(b.build(),sort_keys=True,separators=(",",":"))
    assert hashlib.sha256(one.encode()).digest()==hashlib.sha256(two.encode()).digest()


def test_oi17_stays_open_without_second_microarchitecture():
    e=b.build()
    assert not e["closure"]["closed"]
    assert "second materially different real microarchitecture" in e["closure"]["remaining"][0]
