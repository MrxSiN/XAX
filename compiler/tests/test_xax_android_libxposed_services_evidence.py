from __future__ import annotations

import json
from pathlib import Path

from benchmarks.bench_android_libxposed_services import APK_PATH, collect_evidence


def test_committed_android_libxposed_services_evidence_reproduces_exactly():
    expected = json.loads(
        (Path(__file__).parents[1] / "benchmarks" / "android_libxposed_services_evidence.json").read_text(encoding="utf-8")
    )
    assert collect_evidence() == expected


def test_committed_android_libxposed_services_apk_has_allocation_free_wrappers():
    evidence = collect_evidence()
    data = APK_PATH.read_bytes()
    assert len(data) == evidence["apk"]["bytes"]
    assert evidence["managed_dex"]["remote_types_present"] == {
        "ParcelFileDescriptor": True,
        "SharedPreferences": True,
    }
    for wrapper in evidence["managed_dex"]["wrappers"].values():
        assert wrapper["code_units"] == 5
        assert wrapper["invoke_virtual_count"] == 1
        assert wrapper["allocation_opcodes"] == 0
