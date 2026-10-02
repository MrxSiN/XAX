from __future__ import annotations

import json
from pathlib import Path

from benchmarks.bench_android_libxposed_hot_reload import APK_PATH, collect_evidence


def test_committed_android_libxposed_hot_reload_evidence_reproduces_exactly():
    expected = json.loads(
        (Path(__file__).parents[1] / "benchmarks" / "android_libxposed_hot_reload_evidence.json").read_text(encoding="utf-8")
    )
    assert collect_evidence() == expected


def test_hot_reload_is_bounded_atomic_replacement_with_unchanged_interceptor_hot_path():
    evidence = collect_evidence()
    assert APK_PATH.read_bytes()
    assert evidence["metadata"]["auto_hot_reload_line_present"] is True
    pre = evidence["managed_dex"]["on_hot_reloading"]
    assert pre["code_units"] == 11
    assert pre["invoke_interface_count"] == 1
    assert pre["missing_loader_reject_guard_count"] == 1
    post = evidence["managed_dex"]["on_hot_reloaded"]
    assert post["code_units"] == 51
    assert post["invoke_interface_count"] == 6
    assert post["invoke_virtual_count"] == 1
    assert post["saved_state_null_guard_count"] == 1
    assert post["empty_guard_count"] == 1
    assert post["id_mismatch_guard_count"] == 1
    assert post["check_cast_count"] == 2
    assert post["new_instance_count"] == 1
    assert post["new_array_count"] == 0
    assert post["iput_object_count"] == 2
    assert evidence["hooker_hot_path_regression"]["byte_identical"] is True
    assert all(value == "UNEXECUTED" for value in evidence["runtime_validation"].values())
