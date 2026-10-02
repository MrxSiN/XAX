from __future__ import annotations

import json
from pathlib import Path

from benchmarks.bench_android_sdk_import import collect_evidence


def test_committed_android_sdk_import_evidence_reproduces_exactly():
    path = Path(__file__).parents[1] / "benchmarks" / "android_sdk_import_evidence.json"
    assert collect_evidence() == json.loads(path.read_text(encoding="utf-8"))


def test_sdk_import_evidence_is_canonical_and_requires_explicit_api_guard():
    evidence = collect_evidence()
    assert evidence["zip_entry_order_independent"] is True
    assert evidence["external_compiler_invocations"] == 0
    assert evidence["api_guard_example"]["declared_since"] == 3
    assert evidence["api_guard_example"]["reachable_runtime_min"] == 3
