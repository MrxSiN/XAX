from __future__ import annotations

import json
from pathlib import Path

from benchmarks.bench_android_libxposed_hook import APK_PATH, collect_evidence


def test_committed_android_libxposed_hook_evidence_reproduces_exactly():
    expected = json.loads(
        (Path(__file__).parents[1] / "benchmarks" / "android_libxposed_hook_evidence.json").read_text(encoding="utf-8")
    )
    assert collect_evidence() == expected


def test_committed_android_libxposed_hook_apk_matches_evidence():
    evidence = collect_evidence()
    data = APK_PATH.read_bytes()
    assert len(data) == evidence["generic_apk"]["bytes"]
    assert evidence["hot_hooker_dex"]["allocations_per_intercept_emitted"] == 0
    assert evidence["hot_hooker_dex"]["argument_reads"] == 0
    assert evidence["hot_hooker_dex"]["chain_proceed_calls"] == 1
