"""MEASURED: frame (spill-every-value) vs register-resident lowering of the same loop.

Same verified `sum_to` graph compiled for `x86_64-windows-load-image-v5` (frame path)
and `x86_64-windows-pe-v1` (register path, U1.2b).  Intra-XAX comparison only; no
external baseline toolchain is available on the measuring host.
Run: PYTHONPATH=src:.:tests python -m benchmarks.bench_x86_register_path
"""
from __future__ import annotations

import json
import platform
import statistics
import time
from pathlib import Path

from tests.test_xax_pe import _sum_to
from xax_compiler import Kind, StoreReader, decode_native_target, object_with_refs, write_store, x86_64_windows_general_target, x86_64_windows_pe_target
from xax_x86_64 import compile_native_bound_target, run_native

EVIDENCE_PATH = Path(__file__).parent / "x86_register_path_evidence.json"
N, RUNS = 200_000_000, 7


def main() -> dict:
    function, objects = _sum_to()
    arms = {}
    for target in (x86_64_windows_general_target(), x86_64_windows_pe_target()):
        module = object_with_refs(Kind.MODULE, [function, target])
        root = object_with_refs(Kind.PROGRAM_ROOT, [module])
        reader = StoreReader(write_store(root.cid, list({o.cid: o for o in [*objects, function, target, module, root]}.values())))
        image = compile_native_bound_target(reader, function.cid, target)
        samples = []
        for _ in range(RUNS):
            start = time.perf_counter_ns()
            result = run_native(image, (N,))
            samples.append(time.perf_counter_ns() - start)
        assert result == ((N * (N + 1) // 2) & 0xFFFFFFFF,)
        samples.sort()
        arms[decode_native_target(target).identity.decode()] = {
            "code_bytes": len(image.code), "code_hex": image.code.hex(), "samples_ns": samples,
            "median_ns": int(statistics.median(samples)), "min_ns": samples[0], "max_ns": samples[-1],
        }
    frame, register = arms["x86_64-windows-load-image-v5"], arms["x86_64-windows-pe-v1"]
    evidence = {
        "claim": "MEASURED", "workload": f"sum_to({N}) b32 wrapping loop, one call via ctypes", "runs": RUNS,
        "host": {"system": platform.system(), "version": platform.version(), "machine": platform.machine(), "processor": platform.processor()},
        "arms": arms,
        "speedup_median": round(frame["median_ns"] / register["median_ns"], 2),
        "note": "intra-XAX lowering comparison; includes one ctypes call overhead per run; not a C/Rust comparison",
    }
    EVIDENCE_PATH.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    return evidence


if __name__ == "__main__":
    e = main()
    print({k: (v["code_bytes"], v["median_ns"]) for k, v in e["arms"].items()}, e["speedup_median"])
