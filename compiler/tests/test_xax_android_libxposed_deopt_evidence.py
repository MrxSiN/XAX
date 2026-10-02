from __future__ import annotations

import json
from pathlib import Path

from benchmarks.bench_android_libxposed_deopt import APK_PATH, collect_evidence


def test_committed_android_libxposed_deopt_evidence_reproduces_exactly():
    expected = json.loads(
        (Path(__file__).parents[1] / "benchmarks" / "android_libxposed_deopt_evidence.json").read_text(encoding="utf-8")
    )
    assert collect_evidence() == expected


def test_committed_android_libxposed_deopt_apk_matches_evidence_and_hot_path_is_unchanged():
    evidence = collect_evidence()
    data = APK_PATH.read_bytes()
    assert len(data) == evidence["apk"]["bytes"]
    assert evidence["install_dex"]["deoptimize_call_count"] == 1
    assert evidence["install_dex"]["deoptimize_precedes_hook"] is True
    assert evidence["install_dex"]["extra_allocations_for_deoptimization"] == 0
    assert evidence["hot_hooker"]["deoptimize_string_present"] is False
    assert evidence["hot_hooker"]["opcode_counts"]["new_instance"] == 0
