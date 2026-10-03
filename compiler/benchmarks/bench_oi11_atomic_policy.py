"""Deterministic OI-11 evidence for explicit non-native atomic legalization policy."""
from __future__ import annotations

import hashlib
import json
import platform
import shutil
import statistics
import subprocess
import tempfile
from pathlib import Path
from typing import Callable

from xax_compiler import (
    AtomicFamily,
    AtomicLegalizationPolicy,
    AtomicOrder,
    AtomicScope,
    AtomicSupport,
    AtomicTargetCapability,
    Block,
    Kind,
    LockFree,
    Node,
    Operation,
    Permission,
    RealtimeProfile,
    RetryBehavior,
    SemanticObject,
    StoreReader,
    Terminator,
    ValueRef,
    XaxError,
    aarch64_baremetal_atomic_target,
    analyze_realtime,
    atomic_capability,
    bits_type,
    decode_native_target,
    execute,
    function,
    graph_fragment,
    memory_effect_type,
    object_with_refs,
    pointer_type,
    select_atomic_legalization,
    stack_owner_type,
    wasm32_target,
    write_store,
    x86_64_windows_target,
)
from xax_aarch64 import compile_aarch64
from xax_x86_64 import compile_native

OUT = Path(__file__).with_name("oi11_atomic_policy_evidence.json")
LATENCY_OUT = Path(__file__).with_name("oi11_atomic_latency_samples.json")
INPUT_VALUE = 0x12345678


def fixture(
    order: AtomicOrder,
    target_factory: Callable[[], SemanticObject] = x86_64_windows_target,
    *,
    width: int = 32,
    load_alignment: int | None = None,
    load_scope: AtomicScope = AtomicScope.SYSTEM,
):
    size = (width + 7) // 8
    natural_alignment = max(1, size)
    load_alignment = natural_alignment if load_alignment is None else load_alignment
    value_type = bits_type(width)
    pointer = pointer_type(value_type, Permission.READ_WRITE, natural_alignment)
    owner = stack_owner_type()
    effect = memory_effect_type()
    target = target_factory()
    nodes = (
        Node(Operation.STACK_ALLOC, (), (pointer, owner, effect), attributes=(size, natural_alignment)),
        Node(
            Operation.ATOMIC_STORE,
            (ValueRef.node_result(0, 0, 0), ValueRef.parameter(0, 0), ValueRef.node_result(0, 0, 2)),
            (effect,),
            attributes=(AtomicOrder.RELEASE, AtomicScope.SYSTEM, natural_alignment),
        ),
        Node(
            Operation.ATOMIC_LOAD,
            (ValueRef.node_result(0, 0, 0), ValueRef.node_result(0, 1, 0)),
            (value_type, effect),
            attributes=(order, load_scope, load_alignment),
        ),
        Node(
            Operation.STACK_END,
            (ValueRef.node_result(0, 0, 1), ValueRef.node_result(0, 2, 1)),
            (),
        ),
    )
    graph = graph_fragment([Block((value_type,), nodes, Terminator.return_((ValueRef.node_result(0, 2, 0),)))])
    entry = function(graph, (value_type,), (value_type,))
    module = object_with_refs(Kind.MODULE, (entry, target))
    root = object_with_refs(Kind.PROGRAM_ROOT, (module,))
    reader = StoreReader(write_store(root.cid, (value_type, pointer, owner, effect, graph, entry, target, module, root)))
    return reader, graph, entry, target


def _node_bytes(image, node_index: int) -> bytes:
    matches = [
        item
        for item in image.semantic_ranges
        if item.block_index == 0 and item.node_index == node_index
    ]
    assert len(matches) == 1
    item = matches[0]
    return image.code[item.start : item.end]


def _progress(capability: AtomicTargetCapability, family: AtomicFamily) -> str:
    if capability.lock_free != LockFree.ALWAYS:
        return "unknown"
    if capability.retry_behavior == RetryBehavior.NONE and family in (AtomicFamily.LOAD, AtomicFamily.STORE, AtomicFamily.FENCE):
        return "wait_free"
    return "lock_free"


def _capability_record(capability: AtomicTargetCapability, family: AtomicFamily = AtomicFamily.LOAD) -> dict[str, object]:
    return {
        "support": capability.support.name.lower(),
        "lock_free": capability.lock_free.name.lower(),
        "retry_behavior": capability.retry_behavior.name.lower(),
        "progress": _progress(capability, family),
        "required_alignment": capability.required_alignment,
        "supported_orders": [item.name.lower() for item in capability.supported_orders],
        "supported_scopes": [item.name.lower() for item in capability.supported_scopes],
        "latency_bound": capability.latency_bound,
        "max_inline_instructions": capability.max_inline_instructions,
        "runtime_helper": capability.runtime_helper.hex() if capability.runtime_helper else None,
    }


def _case(
    label: str,
    order: AtomicOrder,
    target_factory: Callable[[], SemanticObject],
    compiler,
) -> tuple[str, dict[str, object]]:
    reader, graph, entry, target = fixture(order, target_factory)
    description = decode_native_target(target)
    capability = atomic_capability(description, 1, 32, 4, AtomicFamily.LOAD, order, AtomicScope.SYSTEM)
    image = compiler(reader, entry.cid, target.cid)
    repeat = compiler(reader, entry.cid, target.cid)
    node_bytes = _node_bytes(image, 2)
    realtime = analyze_realtime(reader, entry.cid, target)
    reference_result = execute(reader, entry.cid, (INPUT_VALUE,))[0]
    return label, {
        "architecture": description.identity.decode("ascii"),
        "order": order.name.lower(),
        "scope": "system",
        "width": 32,
        "alignment": 4,
        "capability": _capability_record(capability),
        "graph_cid": graph.cid.hex(),
        "target_cid": target.cid.hex(),
        "input": INPUT_VALUE,
        "reference_result": reference_result,
        "atomic_node_machine_hex": node_bytes.hex(),
        "atomic_node_machine_bytes": len(node_bytes),
        "artifact_bytes": len(image.code),
        "artifact_sha256": hashlib.sha256(image.code).hexdigest(),
        "deterministic_repeat": image.code == repeat.code,
        "progress": realtime.progress,
        "retry_bound": realtime.retry_bound,
        "runtime_assists": list(realtime.runtime_assists),
        "unsupported_operations": list(realtime.unsupported_operations),
    }


def _rejection(callable_) -> dict[str, object]:
    try:
        callable_()
    except XaxError as error:
        return {"code": error.diagnostic.code, "rule": error.diagnostic.rule}
    raise AssertionError("expected deterministic rejection")


def _latency_summary(samples: list[int], iterations: int) -> dict[str, object]:
    ordered = sorted(samples)
    median_batch = int(statistics.median(ordered))
    p10 = ordered[(len(ordered) - 1) // 10]
    p90 = ordered[((len(ordered) - 1) * 9) // 10]
    return {
        "sample_count": len(samples),
        "iterations_per_sample": iterations,
        "median_batch_ns": median_batch,
        "median_ns_per_call": median_batch / iterations,
        "min_ns_per_call": ordered[0] / iterations,
        "p10_ns_per_call": p10 / iterations,
        "p90_ns_per_call": p90 / iterations,
        "max_ns_per_call": ordered[-1] / iterations,
        "raw_batch_ns": samples,
        "guarantee": None,
    }


def _c_array(name: str, data: bytes) -> str:
    return f"static const unsigned char {name}[] = {{" + ",".join(f"0x{byte:02x}" for byte in data) + "};"


def measure_x86_latency(*, samples: int = 31, iterations: int = 500_000, warmup: int = 100_000) -> dict[str, object]:
    """Execute the emitted Win64 XAX functions on an x86-64 host via ms_abi calls."""
    if platform.machine().lower() not in ("x86_64", "amd64"):
        raise RuntimeError(f"x86-64 host required, found {platform.machine()}")
    cc = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if not cc:
        raise RuntimeError("C compiler required for executable latency harness")
    images = {}
    for label, order in (("native_acquire_load", AtomicOrder.ACQUIRE), ("bounded_seq_cst_load", AtomicOrder.SEQ_CST)):
        reader, _graph, entry, target = fixture(order)
        images[label] = compile_native(reader, entry.cid, target.cid).code
    source = f'''\n#define _GNU_SOURCE\n#include <stdint.h>\n#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n#include <sys/mman.h>\n#include <time.h>\ntypedef uint32_t (__attribute__((ms_abi)) *fn_t)(uint32_t);\n{_c_array("native_code", images["native_acquire_load"])}\n{_c_array("bounded_code", images["bounded_seq_cst_load"])}\nstatic void *map_code(const unsigned char *code, size_t size) {{\n    void *memory = mmap(NULL, 4096, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);\n    if (memory == MAP_FAILED) return NULL;\n    memcpy(memory, code, size);\n    __builtin___clear_cache(memory, (char *)memory + size);\n    return memory;\n}}\nstatic uint64_t now_ns(void) {{\n    struct timespec value;\n    if (clock_gettime(CLOCK_MONOTONIC_RAW, &value) != 0) exit(4);\n    return (uint64_t)value.tv_sec * 1000000000ull + (uint64_t)value.tv_nsec;\n}}\nint main(void) {{\n    fn_t functions[2] = {{(fn_t)map_code(native_code, sizeof native_code), (fn_t)map_code(bounded_code, sizeof bounded_code)}};\n    if (!functions[0] || !functions[1]) return 2;\n    volatile uint32_t sink = 0;\n    for (int which = 0; which < 2; ++which) {{\n        if (functions[which](0x12345678u) != 0x12345678u) return 3;\n        for (int i = 0; i < {warmup}; ++i) sink ^= functions[which]((uint32_t)i);\n        for (int sample = 0; sample < {samples}; ++sample) {{\n            uint64_t start = now_ns();\n            for (int i = 0; i < {iterations}; ++i) sink ^= functions[which]((uint32_t)i);\n            uint64_t end = now_ns();\n            printf("%d %llu\\n", which, (unsigned long long)(end - start));\n        }}\n    }}\n    return sink == 0x9e3779b9u;\n}}\n'''
    with tempfile.TemporaryDirectory(prefix="xax-oi11-latency-") as directory:
        src = Path(directory) / "bench.c"
        exe = Path(directory) / "bench"
        src.write_text(source)
        compile_run = subprocess.run([cc, "-O2", "-std=c11", str(src), "-o", str(exe)], capture_output=True, text=True, check=False)
        if compile_run.returncode:
            raise RuntimeError(compile_run.stderr.strip() or "latency harness compile failed")
        run = subprocess.run([str(exe)], capture_output=True, text=True, check=False, timeout=30)
        if run.returncode:
            raise RuntimeError(run.stderr.strip() or f"latency harness exited {run.returncode}")
    parsed = {"native_acquire_load": [], "bounded_seq_cst_load": []}
    for line in run.stdout.splitlines():
        which, elapsed = line.split()
        parsed[("native_acquire_load", "bounded_seq_cst_load")[int(which)]].append(int(elapsed))
    if any(len(values) != samples for values in parsed.values()):
        raise RuntimeError(f"unexpected sample counts: { {key: len(value) for key, value in parsed.items()} }")
    version = subprocess.run([cc, "--version"], capture_output=True, text=True, check=False).stdout.splitlines()
    artifact = {
        "schema": "xax-oi11-atomic-latency-v1",
        "host": {
            "system": platform.system(),
            "machine": platform.machine(),
            "release": platform.release(),
        },
        "compiler": {"path": cc, "version": version[0] if version else "unknown"},
        "clock": "CLOCK_MONOTONIC_RAW",
        "warmup_iterations": warmup,
        "iterations_per_sample": iterations,
        "cases": {
            key: _latency_summary(values, iterations)
            for key, values in parsed.items()
        },
        "notes": [
            "observed host latency only; not a target timing guarantee",
            "the harness calls emitted XAX Win64 code through an explicit ms_abi function pointer",
        ],
    }
    LATENCY_OUT.write_text(json.dumps(artifact, indent=2, sort_keys=True) + "\n")
    return artifact


def build() -> dict[str, object]:
    cases = dict((
        _case("x86_native_acquire_load", AtomicOrder.ACQUIRE, x86_64_windows_target, compile_native),
        _case("x86_bounded_seq_cst_load", AtomicOrder.SEQ_CST, x86_64_windows_target, compile_native),
        _case("aarch64_native_acquire_load", AtomicOrder.ACQUIRE, aarch64_baremetal_atomic_target, compile_aarch64),
        _case("aarch64_bounded_seq_cst_load", AtomicOrder.SEQ_CST, aarch64_baremetal_atomic_target, compile_aarch64),
    ))

    # Policy-disabled bounded inline must reject on both architectures without changing semantic identity.
    policy_rejections = {}
    for label, target_factory, compiler in (
        ("x86_64_windows", x86_64_windows_target, compile_native),
        ("aarch64_baremetal", aarch64_baremetal_atomic_target, compile_aarch64),
    ):
        reader, graph, entry, target = fixture(AtomicOrder.SEQ_CST, target_factory)
        rejected = _rejection(lambda: compiler(
            reader, entry.cid, target.cid,
            atomic_policy=AtomicLegalizationPolicy(permit_bounded_inline=False),
        ))
        rejected["graph_cid_after_rejection"] = graph.cid.hex()
        policy_rejections[label] = rejected

    # Runtime assistance has no implicit placeholder path: permission is necessary but an explicit helper identity is also required.
    synthetic_assist = AtomicTargetCapability(
        AtomicSupport.RUNTIME_ASSIST,
        LockFree.NO,
        RetryBehavior.POTENTIALLY_UNBOUNDED,
        4,
        (AtomicOrder.SEQ_CST,),
        (AtomicScope.SYSTEM,),
        None,
        None,
        b"",
    )
    assist_default = _rejection(lambda: select_atomic_legalization(synthetic_assist))
    assist_missing_identity = _rejection(lambda: select_atomic_legalization(
        synthetic_assist,
        AtomicLegalizationPolicy(permit_runtime_assist=True),
    ))

    # Exact capability negatives for the second architecture.
    negatives = {}
    for name, kwargs in (
        ("unsupported_width", {"width": 16}),
        ("unsupported_alignment", {"load_alignment": 2}),
        ("unsupported_scope", {"load_scope": AtomicScope.DEVICE}),
    ):
        reader, _graph, entry, target = fixture(AtomicOrder.SEQ_CST, aarch64_baremetal_atomic_target, **kwargs)
        negatives[name] = _rejection(lambda reader=reader, entry=entry, target=target: compile_aarch64(reader, entry.cid, target.cid))
    reader, _graph, entry, target = fixture(AtomicOrder.RELEASE, aarch64_baremetal_atomic_target)
    negatives["unsupported_order"] = _rejection(lambda: compile_aarch64(reader, entry.cid, target.cid))
    reader, _graph, entry, target = fixture(AtomicOrder.SEQ_CST, aarch64_baremetal_atomic_target)
    negatives["unknown_timing_strict_profile"] = _rejection(lambda: compile_aarch64(
        reader, entry.cid, target.cid,
        realtime_profile=RealtimeProfile(require_target_timing_bound=True),
    ))

    x86 = decode_native_target(x86_64_windows_target())
    aarch64 = decode_native_target(aarch64_baremetal_atomic_target())
    wasm = decode_native_target(wasm32_target())
    diversity = {}
    for label, description in (("x86_64_windows", x86), ("aarch64_baremetal", aarch64), ("wasm32_core", wasm)):
        diversity[label] = _capability_record(atomic_capability(
            description, 1, 32, 4, AtomicFamily.LOAD, AtomicOrder.SEQ_CST, AtomicScope.SYSTEM
        ))

    latency = json.loads(LATENCY_OUT.read_text()) if LATENCY_OUT.exists() else None
    x86_latency = latency["cases"] if latency else None
    aarch64_execution = {
        "harness": "xax_aarch64.run_aarch64_qemu",
        "hardware_latency_samples": None,
        "status": "not measured: no AArch64 hardware; emulated timing is not latency evidence",
    }

    return {
        "schema": "xax-oi11-atomic-policy-evidence-v2",
        "policy": {
            "native": "select only when exact target width/alignment/family/order/scope capability is native",
            "bounded_sequence": "select only when target declares bounded_sequence, retry bound is finite, exact max inline instructions are known, and permit_bounded_inline is true",
            "runtime_assist": "select only when target declares runtime_assist with an explicit 32-byte helper identity and permit_runtime_assist is true; no current target implements one",
            "reject": "unsupported exact capability, disabled bounded-inline policy, absent/disabled runtime helper, or post-lowering real-time profile violation",
            "default_permit_bounded_inline": True,
            "default_permit_runtime_assist": False,
            "runtime_assist_default": assist_default,
            "runtime_assist_missing_identity": assist_missing_identity,
        },
        "cases": cases,
        "measurements": {
            "x86_bounded_vs_native_node_delta_bytes": cases["x86_bounded_seq_cst_load"]["atomic_node_machine_bytes"] - cases["x86_native_acquire_load"]["atomic_node_machine_bytes"],
            "aarch64_bounded_vs_native_node_delta_bytes": cases["aarch64_bounded_seq_cst_load"]["atomic_node_machine_bytes"] - cases["aarch64_native_acquire_load"]["atomic_node_machine_bytes"],
            "x86_observed_latency": x86_latency,
            "aarch64_execution": aarch64_execution,
            "timing_guarantee": None,
            "timing_statement": "observed latency is cost evidence only; target timing bounds remain unknown",
        },
        "policy_rejections": policy_rejections,
        "negative_rejections": negatives,
        "target_diversity": diversity,
        "canonical_identity": {
            "policy_is_not_source_semantics": True,
            "x86_graph_cid_unchanged_by_policy_rejection": policy_rejections["x86_64_windows"]["graph_cid_after_rejection"] == cases["x86_bounded_seq_cst_load"]["graph_cid"],
            "aarch64_graph_cid_unchanged_by_policy_rejection": policy_rejections["aarch64_baremetal"]["graph_cid_after_rejection"] == cases["aarch64_bounded_seq_cst_load"]["graph_cid"],
        },
        "closure": {
            "status": "closed" if latency is not None else "open",
            "remaining": [] if latency is not None else ["measured executable-target latency samples"],
            "bounded_second_architecture": "AArch64 system-scope 32/64-bit seq-cst load: finite address + DMB ISH + LDAR + DMB ISH, retry_bound=0, no helper",
            "unknowns_preserved": ["AArch64 hardware latency/timing guarantee", "all target timing guarantees without explicit target metadata"],
        },
    }


if __name__ == "__main__":
    import sys
    if "--measure-latency" in sys.argv:
        measure_x86_latency()
    evidence = build()
    OUT.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    print(OUT)
