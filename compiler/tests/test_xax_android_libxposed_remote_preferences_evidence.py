from __future__ import annotations

import json
from pathlib import Path

from benchmarks.bench_android_libxposed_remote_preferences import APK_PATH, collect_evidence


def test_committed_android_libxposed_remote_preferences_evidence_reproduces_exactly():
    expected = json.loads(
        (Path(__file__).parents[1] / "benchmarks" / "android_libxposed_remote_preferences_evidence.json").read_text(encoding="utf-8")
    )
    assert collect_evidence() == expected


def test_remote_preferences_gate_and_typed_reads_are_allocation_free_and_read_only():
    evidence = collect_evidence()
    assert APK_PATH.read_bytes()
    acquire = evidence["managed_dex"]["acquire"]
    assert acquire == {
        "generated_method": "xaxRemotePreferencesIfSupported",
        "code_units": 16,
        "invoke_virtual_count": 2,
        "if_eqz_count": 1,
        "and_int_lit8_count": 1,
        "null_fallback_count": 1,
        "allocation_opcodes": 0,
    }
    for read in evidence["managed_dex"]["typed_reads"].values():
        assert read["code_units"] == 5
        assert read["invoke_interface_count"] == 1
        assert read["allocation_opcodes"] == 0
    assert all(evidence["managed_dex"]["write_surface_absent"].values())
