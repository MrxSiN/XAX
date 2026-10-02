from __future__ import annotations

import json
from pathlib import Path

from benchmarks.bench_android_libxposed_result import APK_PATH, collect_evidence


def test_committed_libxposed_result_evidence_reproduces_exactly():
    expected = json.loads(
        (Path(__file__).parents[1] / "benchmarks" / "android_libxposed_result_evidence.json").read_text(encoding="utf-8")
    )
    assert collect_evidence() == expected


def test_result_hook_is_one_proceed_zero_allocation_constant_replacement():
    evidence = collect_evidence()
    assert APK_PATH.read_bytes()
    hot = evidence["hot_hooker_dex"]
    assert hot["intercept_code_units"] == 7
    assert hot["intercept_instruction_opcodes"] == ["0x72", "0x0c", "0x1a", "0x11"]
    assert hot["chain_proceed_calls"] == 1
    assert hot["allocations_per_intercept_emitted"] == 0
    assert hot["argument_reads"] == 0
    assert hot["replacement_literal_present"] is True
    assert hot["lookup_strings_present"] == []
    assert evidence["target_contract"]["method_descriptor"] == "()Ljava/lang/String;"
