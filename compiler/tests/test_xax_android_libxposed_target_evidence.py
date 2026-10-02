from __future__ import annotations

import json
from pathlib import Path

from benchmarks.bench_android_libxposed_target import APK_PATH, collect_evidence


def test_committed_controlled_target_evidence_reproduces_exactly():
    expected = json.loads(
        (Path(__file__).parents[1] / "benchmarks" / "android_libxposed_target_evidence.json").read_text(encoding="utf-8")
    )
    assert collect_evidence() == expected


def test_controlled_target_apk_matches_exact_hook_contract():
    evidence = collect_evidence()
    assert APK_PATH.read_bytes()
    assert evidence["semantic_input"]["target_method_descriptor"] == "()Ljava/lang/String;"
    assert evidence["activity_dex"]["hook_target_code_units"] == 3
    assert evidence["activity_dex"]["hook_target_opcodes"] == ["0x1a", "0x11"]
    assert evidence["activity_dex"]["placeholder_present"] is False
    assert evidence["native_elf"]["imports"] == []
    assert evidence["native_elf"]["relocations"] == 0
