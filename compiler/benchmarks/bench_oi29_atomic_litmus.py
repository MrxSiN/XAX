"""OI-29 fault-oriented atomic litmus conformance corpus.

The corpus is derived from XAX atomic semantics.  Expected outcomes/facts and
fault injection live only in this benchmark; they do not define program
semantics.  Host timing is observational and kept separate from guarantees.
"""
from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import statistics
import time
import tracemalloc
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from xax_compiler import (
    AtomicFamily,
    AtomicLitmusEvent,
    AtomicOrder,
    AtomicScope,
    AtomicSupport,
    Block,
    CompareExchangeStrength,
    Kind,
    MemoryEvent,
    Node,
    Operation,
    Permission,
    StoreReader,
    Terminator,
    ValueRef,
    XaxError,
    aarch64_baremetal_atomic_target,
    atomic_capability,
    bits_type,
    decode_native_target,
    function,
    graph_fragment,
    memory_effect_type,
    object_with_refs,
    pointer_type,
    stack_owner_type,
    validate_atomic_litmus,
    validate_memory_events,
    wasm32_target,
    write_store,
    x86_64_windows_target,
)
from xax_aarch64 import compile_aarch64
from xax_x86_64 import compile_native

HERE = Path(__file__).resolve().parent
EVIDENCE = HERE / "oi29_atomic_litmus_evidence.json"
RAW = HERE / "oi29_atomic_litmus_timing.json"
CORPUS = HERE / "oi29_atomic_litmus_corpus.json"

SCHEMA = "xax-atomic-litmus-v1"
FAULTS = (
    "downgrade_order",
    "omit_fence",
    "swap_cas_failure_order",
    "break_release_sequence",
    "ignore_sc_total_order",
    "narrow_scope",
    "accept_unsupported_width_alignment",
)


@dataclass(frozen=True)
class LitmusCase:
    name: str
    events: tuple[AtomicLitmusEvent, ...]
    expected_hb: tuple[tuple[int, int], ...]
    expected_mo: tuple[tuple[str, tuple[int, ...]], ...]
    expected_sc: tuple[int, ...]
    outcomes: tuple[tuple[str, ...], ...]
    tags: frozenset[str]


@dataclass(frozen=True)
class RaceCase:
    name: str
    events: tuple[MemoryEvent, ...]
    expected_rule: str
    tags: frozenset[str]


def litmus_cases() -> tuple[LitmusCase, ...]:
    return (
        LitmusCase(
            "relaxed_read_from",
            (
                AtomicLitmusEvent(0, "x", AtomicFamily.STORE, AtomicOrder.RELAXED),
                AtomicLitmusEvent(1, "x", AtomicFamily.LOAD, AtomicOrder.RELAXED, reads_from=0),
            ),
            (), (("x", (0,)),), (), (("load1", "store0"),),
            frozenset(("order.relaxed", "family.load", "family.store")),
        ),
        LitmusCase(
            "release_acquire",
            (
                AtomicLitmusEvent(0, "flag", AtomicFamily.STORE, AtomicOrder.RELEASE),
                AtomicLitmusEvent(1, "flag", AtomicFamily.LOAD, AtomicOrder.ACQUIRE, reads_from=0),
            ),
            ((0, 1),), (("flag", (0,)),), (), (("load1", "store0", "hb0-1"),),
            frozenset(("order.release", "order.acquire", "synchronizes")),
        ),
        LitmusCase(
            "release_sequence_rmw",
            (
                AtomicLitmusEvent(0, "x", AtomicFamily.STORE, AtomicOrder.RELEASE),
                AtomicLitmusEvent(1, "x", AtomicFamily.RMW, AtomicOrder.RELAXED, reads_from=0),
                AtomicLitmusEvent(2, "x", AtomicFamily.LOAD, AtomicOrder.ACQUIRE, reads_from=1),
            ),
            ((0, 2),), (("x", (0, 1)),), (), (("load2", "rmw1", "release-head0"),),
            frozenset(("family.rmw", "release_sequence")),
        ),
        LitmusCase(
            "acq_rel_rmw",
            (
                AtomicLitmusEvent(0, "x", AtomicFamily.STORE, AtomicOrder.RELEASE),
                AtomicLitmusEvent(1, "x", AtomicFamily.RMW, AtomicOrder.ACQ_REL, reads_from=0),
            ),
            ((0, 1),), (("x", (0, 1)),), (), (("rmw1", "store0", "hb0-1"),),
            frozenset(("order.acq_rel", "family.rmw")),
        ),
        LitmusCase(
            "seq_cst_with_fence",
            (
                AtomicLitmusEvent(0, "x", AtomicFamily.STORE, AtomicOrder.SEQ_CST),
                AtomicLitmusEvent(0, "f", AtomicFamily.FENCE, AtomicOrder.SEQ_CST),
                AtomicLitmusEvent(1, "x", AtomicFamily.LOAD, AtomicOrder.SEQ_CST, reads_from=0),
            ),
            ((0, 1), (0, 2)), (("x", (0,)),), (0, 1, 2), (("load2", "store0", "sc0-1-2"),),
            frozenset(("order.seq_cst", "family.fence", "sc_total_order")),
        ),
        LitmusCase(
            "cmpxchg_success",
            (
                AtomicLitmusEvent(0, "x", AtomicFamily.STORE, AtomicOrder.RELEASE),
                AtomicLitmusEvent(1, "x", AtomicFamily.CMPXCHG, AtomicOrder.ACQ_REL, reads_from=0,
                                  failure_order=AtomicOrder.ACQUIRE, strength=CompareExchangeStrength.STRONG,
                                  succeeded=True),
            ),
            ((0, 1),), (("x", (0, 1)),), (), (("cas1", "success", "hb0-1"),),
            frozenset(("family.cmpxchg.success",)),
        ),
        LitmusCase(
            "release_acquire_redundant",
            (
                AtomicLitmusEvent(2, "ready", AtomicFamily.STORE, AtomicOrder.RELEASE),
                AtomicLitmusEvent(3, "ready", AtomicFamily.LOAD, AtomicOrder.ACQUIRE, reads_from=0),
            ),
            ((0, 1),), (("ready", (0,)),), (), (("load1", "store0", "hb0-1"),),
            frozenset(("order.release", "order.acquire", "synchronizes")),
        ),
        LitmusCase(
            "seq_cst_store_load_redundant",
            (
                AtomicLitmusEvent(0, "y", AtomicFamily.STORE, AtomicOrder.SEQ_CST),
                AtomicLitmusEvent(1, "y", AtomicFamily.LOAD, AtomicOrder.SEQ_CST, reads_from=0),
            ),
            ((0, 1),), (("y", (0,)),), (0, 1), (("load1", "store0", "sc0-1"),),
            frozenset(("order.seq_cst", "sc_total_order")),
        ),
        LitmusCase(
            "cmpxchg_failure_acquire",
            (
                AtomicLitmusEvent(0, "x", AtomicFamily.STORE, AtomicOrder.RELEASE),
                AtomicLitmusEvent(1, "x", AtomicFamily.CMPXCHG, AtomicOrder.SEQ_CST, reads_from=0,
                                  failure_order=AtomicOrder.ACQUIRE, strength=CompareExchangeStrength.WEAK,
                                  succeeded=False),
            ),
            ((0, 1),), (("x", (0,)),), (), (("cas1", "failure", "failure-order-acquire"),),
            frozenset(("family.cmpxchg.failure", "cmpxchg.failure_order")),
        ),
    )


def race_case() -> RaceCase:
    return RaceCase(
        "unordered_non_atomic_race",
        (MemoryEvent(0, "x", 0, 4, True, False), MemoryEvent(1, "x", 0, 4, False, False)),
        "CONCURRENCY-CONFLICT-HAPPENS-BEFORE",
        frozenset(("race_rejection",)),
    )


def _signature(case: LitmusCase, fault: str | None = None) -> dict[str, object]:
    events = list(case.events)
    if fault == "downgrade_order":
        downgraded = []
        for event in events:
            if event.family == AtomicFamily.FENCE:
                downgraded.append(dataclasses.replace(event, order=AtomicOrder.ACQUIRE))
            elif event.family == AtomicFamily.CMPXCHG:
                downgraded.append(dataclasses.replace(event, order=AtomicOrder.RELAXED, failure_order=AtomicOrder.RELAXED))
            else:
                downgraded.append(dataclasses.replace(event, order=AtomicOrder.RELAXED))
        events = downgraded
    elif fault == "omit_fence":
        # This fixture places the fence before any indexed read, so removal does
        # not require heuristic reads-from rewriting.
        events = [event for event in events if event.family != AtomicFamily.FENCE]
    elif fault == "swap_cas_failure_order":
        events = [
            dataclasses.replace(event, order=event.failure_order, failure_order=event.order)
            if event.family == AtomicFamily.CMPXCHG and event.failure_order is not None
            else event
            for event in events
        ]
    elif fault == "break_release_sequence":
        events = [
            dataclasses.replace(event, family=AtomicFamily.STORE, reads_from=None)
            if event.family == AtomicFamily.RMW and event.order == AtomicOrder.RELAXED
            else event
            for event in events
        ]
    try:
        result = validate_atomic_litmus(tuple(events))
    except XaxError as error:
        return {"accepted": False, "rule": error.diagnostic.rule}
    sc = result.seq_cst_order
    if fault == "ignore_sc_total_order":
        sc = ()
    return {
        "accepted": True,
        "hb": [list(edge) for edge in result.happens_before],
        "mo": [[location, list(indices)] for location, indices in result.modification_order],
        "sc": list(sc),
    }


def _expected_signature(case: LitmusCase) -> dict[str, object]:
    return {
        "accepted": True,
        "hb": [list(edge) for edge in case.expected_hb],
        "mo": [[location, list(indices)] for location, indices in case.expected_mo],
        "sc": list(case.expected_sc),
    }


def _load_fixture(order: AtomicOrder, target_factory: Callable[[], object]):
    b32 = bits_type(32)
    pointer = pointer_type(b32, Permission.READ_WRITE, 4)
    owner = stack_owner_type()
    effect = memory_effect_type()
    target = target_factory()
    nodes = (
        Node(Operation.STACK_ALLOC, (), (pointer, owner, effect), attributes=(4, 4)),
        Node(Operation.ATOMIC_STORE, (ValueRef.node_result(0, 0, 0), ValueRef.parameter(0, 0), ValueRef.node_result(0, 0, 2)), (effect,), attributes=(AtomicOrder.RELEASE, AtomicScope.SYSTEM, 4)),
        Node(Operation.ATOMIC_LOAD, (ValueRef.node_result(0, 0, 0), ValueRef.node_result(0, 1, 0)), (b32, effect), attributes=(order, AtomicScope.SYSTEM, 4)),
        Node(Operation.STACK_END, (ValueRef.node_result(0, 0, 1), ValueRef.node_result(0, 2, 1)), ()),
    )
    graph = graph_fragment((Block((b32,), nodes, Terminator.return_((ValueRef.node_result(0, 2, 0),))),))
    entry = function(graph, (b32,), (b32,))
    module = object_with_refs(Kind.MODULE, (entry, target))
    root = object_with_refs(Kind.PROGRAM_ROOT, (module,))
    reader = StoreReader(write_store(root.cid, (b32, pointer, owner, effect, graph, entry, target, module, root)))
    return reader, entry, target


def _node_bytes(image, node_index: int) -> bytes:
    matches = [item for item in image.semantic_ranges if item.block_index == 0 and item.node_index == node_index]
    if len(matches) != 1:
        raise AssertionError((node_index, matches))
    item = matches[0]
    return image.code[item.start:item.end]


def target_observation(fault: str | None = None) -> dict[str, object]:
    x86 = decode_native_target(x86_64_windows_target())
    arm = decode_native_target(aarch64_baremetal_atomic_target())
    wasm = decode_native_target(wasm32_target())
    if fault == "narrow_scope":
        x86 = dataclasses.replace(x86, atomic_scopes=(AtomicScope.DEVICE,))
        arm = dataclasses.replace(arm, atomic_scopes=(AtomicScope.DEVICE,))

    def support(target, width, alignment, family, order, scope):
        if fault == "accept_unsupported_width_alignment" and target.identity.startswith(b"x86_64"):
            # Inject the exact metadata bug: width/alignment are ignored while
            # family/order/scope remain checked.
            width, alignment = 32, 4
        return atomic_capability(target, 1, width, alignment, family, order, scope).support.name.lower()

    reader, entry, target = _load_fixture(AtomicOrder.SEQ_CST, x86_64_windows_target)
    x86_image = compile_native(reader, entry.cid, target.cid)
    x86_node = _node_bytes(x86_image, 2)
    reader, entry, target = _load_fixture(AtomicOrder.SEQ_CST, aarch64_baremetal_atomic_target)
    arm_image = compile_aarch64(reader, entry.cid, target.cid)
    arm_node = _node_bytes(arm_image, 2)
    x86_fences = x86_node.count(bytes.fromhex("0faef0"))
    arm_fences = arm_node.count(bytes.fromhex("bf3b03d5"))
    if fault == "omit_fence":
        x86_fences = 0
        arm_fences = 0
    return {
        "x86_seq_cst_load": support(x86, 32, 4, AtomicFamily.LOAD, AtomicOrder.SEQ_CST, AtomicScope.SYSTEM),
        "aarch64_seq_cst_load": support(arm, 32, 4, AtomicFamily.LOAD, AtomicOrder.SEQ_CST, AtomicScope.SYSTEM),
        "aarch64_rmw": support(arm, 32, 4, AtomicFamily.RMW, AtomicOrder.ACQ_REL, AtomicScope.SYSTEM),
        "wasm_load": support(wasm, 32, 4, AtomicFamily.LOAD, AtomicOrder.ACQUIRE, AtomicScope.SYSTEM),
        "x86_bad_width": support(x86, 16, 4, AtomicFamily.LOAD, AtomicOrder.ACQUIRE, AtomicScope.SYSTEM),
        "x86_bad_alignment": support(x86, 32, 2, AtomicFamily.LOAD, AtomicOrder.ACQUIRE, AtomicScope.SYSTEM),
        "x86_bad_scope": support(x86, 32, 4, AtomicFamily.LOAD, AtomicOrder.ACQUIRE, AtomicScope.DEVICE),
        "x86_seq_cst_fence_count": x86_fences,
        "aarch64_seq_cst_fence_count": arm_fences,
        "x86_atomic_node_hex": x86_node.hex(),
        "aarch64_atomic_node_hex": arm_node.hex(),
        "x86_artifact_bytes": len(x86_image.code),
        "aarch64_artifact_bytes": len(arm_image.code),
    }


TARGET_EXPECTED = {
    "x86_seq_cst_load": "bounded_sequence",
    "aarch64_seq_cst_load": "bounded_sequence",
    "aarch64_rmw": "unsupported",
    "wasm_load": "unsupported",
    "x86_bad_width": "unsupported",
    "x86_bad_alignment": "unsupported",
    "x86_bad_scope": "unsupported",
    "x86_seq_cst_fence_count": 1,
    "aarch64_seq_cst_fence_count": 2,
}


def target_matches(observation: dict[str, object]) -> bool:
    return all(observation[key] == value for key, value in TARGET_EXPECTED.items())


def corpus_results(fault: str | None = None) -> dict[str, bool]:
    results = {}
    for case in litmus_cases():
        results[case.name] = _signature(case, fault) == _expected_signature(case)
    race = race_case()
    try:
        validate_memory_events(race.events)
        results[race.name] = False
    except XaxError as error:
        results[race.name] = error.diagnostic.rule == race.expected_rule
    results["target_atomic_matrix"] = target_matches(target_observation(fault))
    return results


def fault_matrix() -> dict[str, list[str]]:
    baseline = corpus_results()
    if not all(baseline.values()):
        raise AssertionError({name: ok for name, ok in baseline.items() if not ok})
    matrix: dict[str, list[str]] = {}
    for fault in FAULTS:
        faulty = corpus_results(fault)
        matrix[fault] = sorted(name for name in baseline if faulty[name] != baseline[name])
        if not matrix[fault]:
            raise AssertionError(f"undetected fault: {fault}")
    return matrix


def coverage_by_case(matrix: dict[str, list[str]]) -> dict[str, set[str]]:
    coverage = {name: set() for name in corpus_results()}
    for fault, cases in matrix.items():
        for case in cases:
            coverage[case].add(f"fault.{fault}")
    for case in litmus_cases():
        coverage[case.name].update(case.tags)
    coverage[race_case().name].update(race_case().tags)
    coverage["target_atomic_matrix"].update({
        "target.x86_64", "target.aarch64", "target.wasm32", "capability.scope",
        "capability.alignment", "capability.width", "unsupported.reported",
    })
    return coverage


def minimum_corpus(matrix: dict[str, list[str]]) -> tuple[str, ...]:
    coverage = coverage_by_case(matrix)
    required = {f"fault.{fault}" for fault in FAULTS} | {
        "order.relaxed", "order.acquire", "order.release", "order.acq_rel", "order.seq_cst",
        "family.load", "family.store", "family.rmw", "family.cmpxchg.success", "family.cmpxchg.failure",
        "family.fence", "release_sequence", "sc_total_order", "race_rejection",
        "target.x86_64", "target.aarch64", "target.wasm32", "capability.scope", "capability.alignment",
        "capability.width", "unsupported.reported",
    }
    selected: list[str] = []
    remaining = set(required)
    while remaining:
        ranked = sorted(
            ((len(values & remaining), name) for name, values in coverage.items() if name not in selected),
            key=lambda item: (-item[0], item[1]),
        )
        if not ranked or ranked[0][0] == 0:
            raise AssertionError(f"uncovered requirements: {sorted(remaining)}")
        _, name = ranked[0]
        selected.append(name)
        remaining -= coverage[name]
    # Deterministically remove any case made redundant by later choices.
    changed = True
    while changed:
        changed = False
        for name in tuple(selected):
            trial = [item for item in selected if item != name]
            union = set().union(*(coverage[item] for item in trial)) if trial else set()
            if required <= union:
                selected = trial
                changed = True
                break
    return tuple(selected)


def _case_json(case: LitmusCase) -> dict[str, object]:
    return {
        "name": case.name,
        "events": [
            {
                "agent": e.agent,
                "location": e.location,
                "family": e.family.name.lower(),
                "order": e.order.name.lower(),
                "reads_from": e.reads_from,
                "failure_order": None if e.failure_order is None else e.failure_order.name.lower(),
                "strength": None if e.strength is None else e.strength.name.lower(),
                "succeeded": e.succeeded,
                "spurious_failure": e.spurious_failure,
            }
            for e in case.events
        ],
        "expected": _expected_signature(case),
        "expected_outcomes": [list(outcome) for outcome in case.outcomes],
        "coverage": sorted(case.tags),
    }


def build_corpus_artifact() -> dict[str, object]:
    matrix = fault_matrix()
    minimum = minimum_corpus(matrix)
    return {
        "schema": SCHEMA,
        "semantic_cases": [_case_json(case) for case in litmus_cases()],
        "race_case": {
            "name": race_case().name,
            "expected": {"accepted": False, "rule": race_case().expected_rule},
            "coverage": sorted(race_case().tags),
        },
        "target_case": {"name": "target_atomic_matrix", "expected": TARGET_EXPECTED},
        "faults": list(FAULTS),
        "fault_matrix": matrix,
        "minimum_corpus": list(minimum),
        "minimum_count": len(minimum),
        "scope": "sufficient only for the declared OI-29 fault model; target packages may add target-specific vectors",
    }


def _timed(callable_, samples: int = 31) -> dict[str, object]:
    values = []
    peaks = []
    for _ in range(samples):
        tracemalloc.start()
        start = time.perf_counter_ns()
        callable_()
        values.append(time.perf_counter_ns() - start)
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        peaks.append(peak)
    ordered = sorted(values)
    return {
        "samples": values,
        "sample_count": samples,
        "median_ns": int(statistics.median(values)),
        "p10_ns": ordered[(samples - 1) // 10],
        "p90_ns": ordered[((samples - 1) * 9) // 10],
        "median_peak_bytes": int(statistics.median(peaks)),
    }


def measure() -> dict[str, object]:
    corpus = build_corpus_artifact()
    minimum = set(corpus["minimum_corpus"])
    case_map = {case.name: case for case in litmus_cases()}

    def validate_semantic_minimum():
        for name in corpus["minimum_corpus"]:
            if name in case_map:
                assert _signature(case_map[name]) == _expected_signature(case_map[name])
            elif name == race_case().name:
                try:
                    validate_memory_events(race_case().events)
                except XaxError:
                    pass
                else:
                    raise AssertionError("race accepted")

    raw = {
        "schema": "xax-oi29-atomic-litmus-timing-v1",
        "minimum_corpus": sorted(minimum),
        "validator": _timed(validate_semantic_minimum),
        "x86_target_lowering": _timed(lambda: _compile_one(x86_64_windows_target, compile_native)),
        "aarch64_target_lowering": _timed(lambda: _compile_one(aarch64_baremetal_atomic_target, compile_aarch64)),
        "physical_concurrent_execution": {
            "performed": False,
            "reason": "forbidden outcomes are nondeterministic/rare; deterministic abstract/package conformance is primary for this corpus",
        },
    }
    RAW.write_text(json.dumps(raw, indent=2, sort_keys=True) + "\n")
    return raw


def _compile_one(target_factory, compiler):
    reader, entry, target = _load_fixture(AtomicOrder.SEQ_CST, target_factory)
    return compiler(reader, entry.cid, target.cid).code


def evidence_from_raw(raw: dict[str, object]) -> dict[str, object]:
    corpus = build_corpus_artifact()
    target = target_observation()
    matrix = corpus["fault_matrix"]
    return {
        "schema": "xax-oi29-atomic-litmus-evidence-v1",
        "corpus_schema": corpus["schema"],
        "full_case_count": len(litmus_cases()) + 2,
        "minimum_case_count": corpus["minimum_count"],
        "minimum_corpus": corpus["minimum_corpus"],
        "fault_count": len(FAULTS),
        "fault_detection": {fault: len(cases) for fault, cases in matrix.items()},
        "all_faults_detected": all(matrix[fault] for fault in FAULTS),
        "fault_matrix": matrix,
        "target_conformance": target,
        "unsupported": {
            "aarch64_rmw": "target package supports only atomic load/store",
            "wasm32_all_portable_atomics": "wasm32 target package declares no atomic capability",
            "x86_device_scope": "x86-64 package declares system scope only",
            "x86_width16": "x86-64 package declares 32/64-bit atomic widths only",
            "x86_alignment2_for_32": "natural alignment requirement is 4 bytes",
        },
        "deterministic_work_units": {
            "minimum_event_records": sum(len(case.events) for case in litmus_cases() if case.name in set(corpus["minimum_corpus"])),
            "target_capability_queries": 7 if "target_atomic_matrix" in set(corpus["minimum_corpus"]) else 0,
        },
        "timing": {
            "validator_median_ns": raw["validator"]["median_ns"],
            "validator_p10_ns": raw["validator"]["p10_ns"],
            "validator_p90_ns": raw["validator"]["p90_ns"],
            "validator_median_peak_bytes": raw["validator"]["median_peak_bytes"],
            "x86_lowering_median_ns": raw["x86_target_lowering"]["median_ns"],
            "aarch64_lowering_median_ns": raw["aarch64_target_lowering"]["median_ns"],
        },
        "physical_concurrent_execution": raw["physical_concurrent_execution"],
        "policy": {
            "version": SCHEMA,
            "portable_minimum": "the committed greedy minimum corpus",
            "target_additions": "add vectors for each target-only scope/family/legalization and every unsupported capability boundary claimed by that package",
            "unsupported_reporting": "unsupported is an explicit result with reason, never a silent pass/skip",
            "sufficiency": "only for the seven declared injected fault classes; extend the fault model before extending the corpus",
        },
    }


def write_artifacts(*, do_measure: bool) -> dict[str, object]:
    corpus = build_corpus_artifact()
    CORPUS.write_text(json.dumps(corpus, indent=2, sort_keys=True) + "\n")
    if do_measure or not RAW.exists():
        raw = measure()
    else:
        raw = json.loads(RAW.read_text())
    evidence = evidence_from_raw(raw)
    EVIDENCE.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    return evidence


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--measure", action="store_true")
    args = parser.parse_args()
    print(json.dumps(write_artifacts(do_measure=args.measure), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
