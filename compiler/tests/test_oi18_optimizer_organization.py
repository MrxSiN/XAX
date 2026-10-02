import hashlib, json
import pytest
from benchmarks import bench_oi18_optimizer_organization as b


def test_corpus_has_required_shapes_and_verifies():
    reader, workloads, _ = b.corpus()
    assert {w.name for w in workloads} == {"arithmetic","branch_merge","stack_memory","direct_call","seq_cst_atomic"}
    assert sum(1 for _ in reader.objects()) > 10


def test_both_organizations_emit_identical_bytes_on_two_targets():
    e=b.build()
    assert e["all_artifacts_byte_identical"]
    assert e["all_semantic_vectors_match"]
    assert {r["target"] for r in e["rows"]} == {"x86_64","aarch64"}
    assert len(e["rows"]) == 10


def test_atomic_case_is_real_target_specific_legalization():
    e=b.build(); rows=[r for r in e["rows"] if r["workload"]=="seq_cst_atomic"]
    assert len(rows)==2
    x=next(r for r in rows if r["target"]=="x86_64")
    a=next(r for r in rows if r["target"]=="aarch64")
    assert any("bounded_sequence" in x for group in x["legalizations"] for x in group)
    assert any("bounded_sequence" in x for group in a["legalizations"] for x in group)


def test_unsupported_atomic_legalization_fails_deterministically():
    e=b.build()
    assert e["unsupported_legalization_rule"] in {"OI18-TARGET-OPERATION","OI18-ATOMIC-SUPPORTED"}
    assert e["unsupported_backend_rule"] == "WASM-OP-TARGET-SUPPORTED"


def test_incremental_selector_reuses_unchanged_blocks_only():
    e=b.build()
    for data in e["incremental"].values():
        assert data["cache_hits_after_local_edit"] == 2
        assert data["cache_misses_after_local_edit"] == 1


def test_alternate_has_no_persistent_mir_or_production_delta():
    e=b.build(); impl=e["implementation"]
    assert impl["persistent_machine_ir_objects"] == 0
    assert impl["production_lines_changed"] == 0
    assert impl["alternate_selector_lines"] > 0


def test_raw_timing_samples_have_full_accounting():
    raw=json.loads(b.TIMING_OUT.read_text())
    assert raw["samples"] >= 7
    assert len(raw["cases"]) == 10
    for case in raw["cases"].values():
        for mode in ("baseline","demand"):
            assert len(case[mode]["wall_ns"]) == raw["samples"]
            assert len(case[mode]["peak_bytes"]) == raw["samples"]
            assert case[mode]["median_wall_ns"] > 0
            assert case[mode]["median_peak_bytes"] > 0


def test_evidence_is_deterministic_from_fixed_timing_sidecar():
    one=json.dumps(b.build(),sort_keys=True,separators=(",",":"))
    two=json.dumps(b.build(),sort_keys=True,separators=(",",":"))
    assert hashlib.sha256(one.encode()).digest()==hashlib.sha256(two.encode()).digest()


def test_closure_selects_simpler_current_organization():
    e=b.build()
    assert e["closure"]["closed"]
    assert "current staged semantic optimizer" in e["closure"]["selected"]
