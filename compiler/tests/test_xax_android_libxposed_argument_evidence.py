from __future__ import annotations

import json
from pathlib import Path

from benchmarks.bench_android_libxposed_argument import EVIDENCE_PATH, collect_evidence
from benchmarks.bench_android_libxposed_argument_target import EVIDENCE_PATH as TARGET_EVIDENCE_PATH, collect_evidence as collect_target_evidence


def test_argument_target_evidence_replays_exactly():
    committed = json.loads(Path(TARGET_EVIDENCE_PATH).read_text(encoding="utf-8"))
    current = collect_target_evidence()
    assert current == committed
    assert current["activity_dex"]["hook_target_code_units"] == 1
    assert current["semantic_input"]["target_method_descriptor"] == "(Ljava/lang/String;)Ljava/lang/String;"


def test_argument_hook_evidence_replays_and_reports_explicit_allocation():
    committed = json.loads(Path(EVIDENCE_PATH).read_text(encoding="utf-8"))
    current = collect_evidence()
    assert current == committed
    hot = current["hot_hooker_dex"]
    assert hot["argument_reads"] == 1
    assert hot["chain_proceed_calls"] == 1
    assert hot["object_array_allocations_per_intercept_emitted"] == 1
    assert hot["object_allocations_per_intercept_emitted"] == 0
    assert current["allocation_policy"]["zero_allocation_claim"] is False
    assert current["runtime_validation"]["argument_replacement"] == "UNEXECUTED"
