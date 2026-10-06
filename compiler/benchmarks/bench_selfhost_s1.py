"""Self-hosting step S1 evidence (ADR-116): the XAX-authored RISC-V encoder on the production path.

Records the canonical store identity, the encoder image size on each target,
agreement counts, the self-compilation fixed point, and the host cost of the
native leaf against the bootstrap Python encoders (per call and per RISC-V
compilation).  Run: ``PYTHONPATH=src python benchmarks/bench_selfhost_s1.py [--write]``.
"""

from __future__ import annotations

import hashlib
import json
import platform
import random
import statistics
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "tests"))

from xax_compiler import jvm_classfile_target, riscv64_baremetal_target  # noqa: E402
from xax_graph_builder import program_store  # noqa: E402
from xax_riscv64 import compile_riscv64_bound_target, run_riscv64  # noqa: E402
from xax_selfhost_riscv64 import STORE_PATH, load_encoder_program, native_encoder  # noqa: E402

EVIDENCE = HERE / "selfhost_s1_evidence.json"


def _median_time(action, repetitions: int) -> float:
    samples = []
    for _ in range(repetitions):
        start = time.perf_counter()
        action()
        samples.append(time.perf_counter() - start)
    return statistics.median(samples)


def measure() -> dict:
    from test_xax_jvm import _random_function
    from test_xax_selfhost_riscv64 import MASK64, _cases
    from xax_jvm import compile_jvm_bound_target

    reader, encode = load_encoder_program()
    native = native_encoder()
    cases = _cases(random.Random(7), 2000)
    native_agree = sum(native(*arguments) == expected for arguments, expected in cases)
    riscv = compile_riscv64_bound_target(reader, encode.cid, riscv64_baremetal_target(), encoder="xax")
    riscv_bootstrap = compile_riscv64_bound_target(reader, encode.cid, riscv64_baremetal_target(), encoder="python")
    riscv_cases = cases[:300]
    riscv_agree = sum(run_riscv64(riscv, tuple(v & MASK64 for v in arguments)) == expected for arguments, expected in riscv_cases)
    jvm = compile_jvm_bound_target(reader, encode.cid, jvm_classfile_target())

    per_call_native = _median_time(lambda: [native(1, 5, 2, 0, 10, 0x13) for _ in range(20000)], 5) / 20000
    import xax_riscv64 as rv
    per_call_python = _median_time(lambda: [rv._i(5, 2, 0, 10, 0x13) for _ in range(20000)], 5) / 20000
    target = riscv64_baremetal_target()
    entry, graph = _random_function(random.Random(5), 64)
    program = program_store(entry, target, tuple(graph.objects.values()))
    compile_xax = _median_time(lambda: compile_riscv64_bound_target(program, entry.cid, target, encoder="xax"), 9)
    compile_python = _median_time(lambda: compile_riscv64_bound_target(program, entry.cid, target, encoder="python"), 9)
    store = STORE_PATH.read_bytes()
    return {
        "format": "xax-selfhost-s1-evidence-v1",
        "component": "riscv64 instruction encoder + li planner (encode/7 -> bits<64>)",
        "store": {"path": "compiler/bootstrap/xax_riscv64_encoder.xax", "bytes": len(store), "sha256": hashlib.sha256(store).hexdigest(), "root_cid": reader.root_cid.hex(), "encode_cid": encode.cid.hex()},
        "images": {"x86_64_native_leaf_bytes": native.code_size, "riscv64_bytes": len(riscv.code), "jvm_class_bytes": len(jvm.class_bytes)},
        "agreement": {
            "native_leaf_vs_python": [native_agree, len(cases)],
            "riscv64_in_emulator_vs_python": [riscv_agree, len(riscv_cases)],
        },
        "self_compilation_fixed_point": riscv.code == riscv_bootstrap.code,
        "host_cost_nonsemantic": {
            "host": f"{platform.system()} {platform.machine()} Python {platform.python_version()}",
            "per_encode_call_us": {"xax_native_leaf": round(per_call_native * 1e6, 3), "python_bootstrap": round(per_call_python * 1e6, 3)},
            "riscv64_compile_ms_one_program": {"xax_encoder": round(compile_xax * 1e3, 2), "python_encoder": round(compile_python * 1e3, 2)},
            "note": "The native leaf pays a ctypes call per word; encoding is not the compiler's bottleneck, and S1's purpose is moving logic into XAX, not speed.",
        },
    }


if __name__ == "__main__":
    import os

    os.environ["XAX_REQUIRE_NATIVE"] = "1"  # a Python fallback is an error here, never XAX evidence
    evidence = measure()
    evidence["authority"] = __import__("xax_native").AUTHORITY
    text = json.dumps(evidence, indent=2) + "\n"
    if "--write" in sys.argv:
        EVIDENCE.write_text(text)
    print(text)
