import json
from pathlib import Path

import pytest

from benchmarks.bench_oi11_atomic_policy import LATENCY_OUT, build, fixture
from xax_aarch64 import compile_aarch64
from xax_compiler import (
    AtomicFamily,
    AtomicLegalizationPolicy,
    AtomicOrder,
    AtomicScope,
    AtomicSupport,
    AtomicTargetCapability,
    LockFree,
    RealtimeProfile,
    RetryBehavior,
    XaxError,
    aarch64_baremetal_atomic_target,
    analyze_realtime,
    atomic_capability,
    decode_native_target,
    execute,
    select_atomic_legalization,
    wasm32_target,
    x86_64_windows_target,
)
from xax_x86_64 import compile_native


def _atomic_node_bytes(image, node_index=2):
    ranges = [item for item in image.semantic_ranges if item.block_index == 0 and item.node_index == node_index]
    assert len(ranges) == 1
    item = ranges[0]
    return image.code[item.start : item.end]


def test_capability_distinguishes_native_bounded_and_cross_target_rejection():
    x86 = decode_native_target(x86_64_windows_target())
    aarch64 = decode_native_target(aarch64_baremetal_atomic_target())
    wasm = decode_native_target(wasm32_target())
    for target, expected_max in ((x86, 2), (aarch64, 3)):
        acquire = atomic_capability(target, 1, 32, 4, AtomicFamily.LOAD, AtomicOrder.ACQUIRE, AtomicScope.SYSTEM)
        seq_cst = atomic_capability(target, 1, 32, 4, AtomicFamily.LOAD, AtomicOrder.SEQ_CST, AtomicScope.SYSTEM)
        assert acquire.support == AtomicSupport.NATIVE
        assert seq_cst.support == AtomicSupport.BOUNDED_SEQUENCE
        assert seq_cst.lock_free == LockFree.ALWAYS
        assert seq_cst.retry_behavior == RetryBehavior.NONE
        assert seq_cst.max_inline_instructions == expected_max
        assert seq_cst.runtime_helper == b""
        assert seq_cst.latency_bound is None

    unsupported = atomic_capability(wasm, 1, 32, 4, AtomicFamily.LOAD, AtomicOrder.SEQ_CST, AtomicScope.SYSTEM)
    assert unsupported.support == AtomicSupport.UNSUPPORTED


def test_policy_requires_permission_and_explicit_runtime_helper_identity():
    bounded = atomic_capability(
        decode_native_target(aarch64_baremetal_atomic_target()),
        1, 32, 4, AtomicFamily.LOAD, AtomicOrder.SEQ_CST, AtomicScope.SYSTEM,
    )
    assert select_atomic_legalization(bounded) == AtomicSupport.BOUNDED_SEQUENCE
    with pytest.raises(XaxError) as caught:
        select_atomic_legalization(bounded, AtomicLegalizationPolicy(permit_bounded_inline=False))
    assert caught.value.diagnostic.rule == "ATOMIC-BOUNDED-INLINE-PERMITTED"

    assist = AtomicTargetCapability(
        AtomicSupport.RUNTIME_ASSIST,
        LockFree.NO,
        RetryBehavior.POTENTIALLY_UNBOUNDED,
        4,
        (AtomicOrder.SEQ_CST,),
        (AtomicScope.SYSTEM,),
    )
    with pytest.raises(XaxError) as caught:
        select_atomic_legalization(assist)
    assert caught.value.diagnostic.rule == "ATOMIC-RUNTIME-ASSIST-PERMITTED"
    with pytest.raises(XaxError) as caught:
        select_atomic_legalization(assist, AtomicLegalizationPolicy(permit_runtime_assist=True))
    assert caught.value.diagnostic.rule == "ATOMIC-RUNTIME-ASSIST-IDENTITY"

    explicit = AtomicTargetCapability(
        AtomicSupport.RUNTIME_ASSIST,
        LockFree.NO,
        RetryBehavior.POTENTIALLY_UNBOUNDED,
        4,
        (AtomicOrder.SEQ_CST,),
        (AtomicScope.SYSTEM,),
        None,
        None,
        b"h" * 32,
    )
    assert select_atomic_legalization(explicit, AtomicLegalizationPolicy(permit_runtime_assist=True)) == AtomicSupport.RUNTIME_ASSIST


def test_x86_seq_cst_load_is_deterministic_bounded_inline_without_helper():
    acquire_reader, _acquire_graph, acquire_entry, acquire_target = fixture(AtomicOrder.ACQUIRE)
    seq_reader, _seq_graph, seq_entry, seq_target = fixture(AtomicOrder.SEQ_CST)
    acquire_image = compile_native(acquire_reader, acquire_entry.cid, acquire_target.cid)
    first = compile_native(seq_reader, seq_entry.cid, seq_target.cid)
    second = compile_native(seq_reader, seq_entry.cid, seq_target.cid)

    acquire_bytes = _atomic_node_bytes(acquire_image)
    seq_bytes = _atomic_node_bytes(first)
    assert first.code == second.code
    assert execute(seq_reader, seq_entry.cid, (0x12345678,)) == (0x12345678,)
    assert b"\x0f\xae\xf0" not in acquire_bytes
    assert b"\x0f\xae\xf0" in seq_bytes
    assert len(seq_bytes) - len(acquire_bytes) == 3
    assert len(first.function_offsets) == 1


def test_aarch64_seq_cst_load_is_finite_four_instruction_lowering_without_helper():
    acquire_reader, _ag, acquire_entry, acquire_target = fixture(AtomicOrder.ACQUIRE, aarch64_baremetal_atomic_target)
    seq_reader, _sg, seq_entry, seq_target = fixture(AtomicOrder.SEQ_CST, aarch64_baremetal_atomic_target)
    acquire = compile_aarch64(acquire_reader, acquire_entry.cid, acquire_target.cid)
    first = compile_aarch64(seq_reader, seq_entry.cid, seq_target.cid)
    second = compile_aarch64(seq_reader, seq_entry.cid, seq_target.cid)

    acquire_bytes = _atomic_node_bytes(acquire)
    seq_bytes = _atomic_node_bytes(first)
    assert first.code == second.code
    assert execute(seq_reader, seq_entry.cid, (0x12345678,)) == (0x12345678,)
    assert acquire_bytes.hex() == "ea03009140fddf88"  # add x10,sp,#0; ldar w0,[x10]
    assert seq_bytes.hex() == "ea030091bf3b03d540fddf88bf3b03d5"
    assert len(acquire_bytes) == 8
    assert len(seq_bytes) == 16
    assert b"\xbf\x3b\x03\xd5" not in acquire_bytes
    assert seq_bytes.count(b"\xbf\x3b\x03\xd5") == 2


def test_aarch64_bounded_sequence_supports_64_bit_naturally_aligned_load():
    reader, _graph, entry, target = fixture(AtomicOrder.SEQ_CST, aarch64_baremetal_atomic_target, width=64)
    image = compile_aarch64(reader, entry.cid, target.cid)
    node = _atomic_node_bytes(image)
    assert len(node) == 16
    assert node.hex() == "ea030091bf3b03d540fddfc8bf3b03d5"
    assert execute(reader, entry.cid, (0x123456789ABCDEF0,)) == (0x123456789ABCDEF0,)


def test_disabling_bounded_inline_rejects_without_changing_canonical_identity_on_both_targets():
    for target_factory, compiler in (
        (x86_64_windows_target, compile_native),
        (aarch64_baremetal_atomic_target, compile_aarch64),
    ):
        reader, graph, entry, target = fixture(AtomicOrder.SEQ_CST, target_factory)
        cid = graph.cid
        with pytest.raises(XaxError) as caught:
            compiler(reader, entry.cid, target.cid, atomic_policy=AtomicLegalizationPolicy(permit_bounded_inline=False))
        assert caught.value.diagnostic.code == "XAX.ATOMIC.LEGALIZATION_POLICY"
        assert caught.value.diagnostic.rule == "ATOMIC-BOUNDED-INLINE-PERMITTED"
        assert graph.cid == cid


def test_bounded_loads_keep_wait_free_zero_retry_no_assist_analysis():
    for target_factory in (x86_64_windows_target, aarch64_baremetal_atomic_target):
        reader, _graph, entry, target = fixture(AtomicOrder.SEQ_CST, target_factory)
        properties = analyze_realtime(reader, entry.cid, target)
        assert properties.progress == "wait_free"
        assert properties.retry_bound == 0
        assert properties.runtime_assists == ()
        assert properties.unsupported_operations == ()


def test_aarch64_rejects_unsupported_width_alignment_and_scope_deterministically():
    cases = (
        ({"width": 16}, "AARCH64-ATOMIC-CAPABILITY"),
        ({"load_alignment": 2}, "AARCH64-ATOMIC-CAPABILITY"),
        ({"load_scope": AtomicScope.DEVICE}, "AARCH64-ATOMIC-CAPABILITY"),
    )
    for kwargs, rule in cases:
        reader, _graph, entry, target = fixture(AtomicOrder.SEQ_CST, aarch64_baremetal_atomic_target, **kwargs)
        with pytest.raises(XaxError) as caught:
            compile_aarch64(reader, entry.cid, target.cid)
        assert caught.value.diagnostic.code == "XAX.AARCH64.ATOMIC_UNSUPPORTED"
        assert caught.value.diagnostic.rule == rule


def test_invalid_load_order_rejects_before_lowering():
    reader, _graph, entry, target = fixture(AtomicOrder.RELEASE, aarch64_baremetal_atomic_target)
    with pytest.raises(XaxError) as caught:
        compile_aarch64(reader, entry.cid, target.cid)
    assert caught.value.diagnostic.code == "XAX.ATOMIC.ORDER"
    assert caught.value.diagnostic.rule == "ATOMIC-ORDER-LEGAL"


def test_aarch64_post_lowering_realtime_validation_preserves_unknown_timing():
    reader, _graph, entry, target = fixture(AtomicOrder.SEQ_CST, aarch64_baremetal_atomic_target)
    assert compile_aarch64(reader, entry.cid, target.cid, realtime_profile=RealtimeProfile()).code
    with pytest.raises(XaxError) as caught:
        compile_aarch64(
            reader,
            entry.cid,
            target.cid,
            realtime_profile=RealtimeProfile(require_target_timing_bound=True),
        )
    assert caught.value.diagnostic.code == "XAX.REALTIME.PROFILE"
    assert caught.value.diagnostic.rule == "REALTIME-TARGET-TIMING-BOUND"


def test_latency_artifact_contains_raw_observed_samples_not_guarantees():
    raw = json.loads(LATENCY_OUT.read_text())
    assert raw["schema"] == "xax-oi11-atomic-latency-v1"
    assert raw["iterations_per_sample"] > 0
    for case in raw["cases"].values():
        assert case["sample_count"] >= 5
        assert len(case["raw_batch_ns"]) == case["sample_count"]
        assert case["guarantee"] is None
        assert case["min_ns_per_call"] <= case["median_ns_per_call"] <= case["max_ns_per_call"]


def test_committed_evidence_reproduces():
    committed = json.loads((Path(__file__).parents[1] / "benchmarks" / "oi11_atomic_policy_evidence.json").read_text())
    assert build() == committed
