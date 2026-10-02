from __future__ import annotations

import json
from pathlib import Path

from benchmarks.bench_android_libxposed_remote_files import APK_PATH, collect_evidence


def test_committed_android_libxposed_remote_files_evidence_reproduces_exactly():
    expected = json.loads(
        (Path(__file__).parents[1] / "benchmarks" / "android_libxposed_remote_files_evidence.json").read_text(encoding="utf-8")
    )
    assert collect_evidence() == expected


def test_remote_files_are_capability_gated_nullable_and_allocation_free():
    evidence = collect_evidence()
    assert APK_PATH.read_bytes()
    for helper in evidence["managed_dex"]["helpers"].values():
        assert helper["code_units"] == 16
        assert helper["invoke_virtual_count"] == 2
        assert helper["if_eqz_count"] == 1
        assert helper["and_int_lit8_count"] == 1
        assert helper["null_fallback_count"] == 1
        assert helper["allocation_opcodes"] == 0
    assert all(value == "UNEXECUTED" for value in evidence["runtime_validation"].values())
