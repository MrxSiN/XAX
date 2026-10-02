from __future__ import annotations

import json
from pathlib import Path

from benchmarks.bench_android_libxposed import APK_PATH, collect_evidence


def test_committed_android_libxposed_native_evidence_reproduces_exactly():
    expected = json.loads((Path(__file__).parents[1] / "benchmarks" / "android_libxposed_evidence.json").read_text(encoding="utf-8"))
    assert collect_evidence() == expected


def test_committed_android_libxposed_native_fixture_matches_evidence():
    evidence = collect_evidence()
    assert APK_PATH.read_bytes()
    assert len(APK_PATH.read_bytes()) == evidence["generic_apk"]["bytes"]
