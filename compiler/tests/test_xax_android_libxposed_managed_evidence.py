from __future__ import annotations

import json
from pathlib import Path

from benchmarks.bench_android_libxposed_managed import APK_PATH, collect_evidence


def test_committed_android_libxposed_managed_evidence_reproduces_exactly():
    expected = json.loads((Path(__file__).parents[1] / "benchmarks" / "android_libxposed_managed_evidence.json").read_text(encoding="utf-8"))
    assert collect_evidence() == expected


def test_committed_android_libxposed_managed_apk_matches_evidence():
    evidence = collect_evidence()
    assert len(APK_PATH.read_bytes()) == evidence["generic_apk"]["bytes"]
