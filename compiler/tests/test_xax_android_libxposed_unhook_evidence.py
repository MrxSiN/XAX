from __future__ import annotations

import json
from pathlib import Path

from benchmarks.bench_android_libxposed_unhook import APK_PATH, collect_evidence


def test_committed_android_libxposed_unhook_evidence_reproduces_exactly():
    expected = json.loads(
        (Path(__file__).parents[1] / "benchmarks" / "android_libxposed_unhook_evidence.json").read_text(encoding="utf-8")
    )
    assert collect_evidence() == expected


def test_committed_android_libxposed_unhook_apk_matches_evidence_and_preserves_hot_hooker():
    evidence = collect_evidence()
    data = APK_PATH.read_bytes()
    assert len(data) == evidence["generic_apk"]["bytes"]
    assert evidence["managed_dex"]["instance_fields"] == 1
    assert evidence["managed_dex"]["install_iput_object_count"] == 1
    assert evidence["managed_dex"]["unhook_invoke_interface_count"] == 1
    assert evidence["managed_dex"]["unhook_iput_object_count"] == 1
    assert evidence["hot_hooker_regression"]["hooker_bytes_identical"] is True
    assert evidence["process_profile_regression"]["instance_fields"] == 0
