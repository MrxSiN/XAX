"""S5a evidence (ADR-140): the XAX RISC-V backend program against the bootstrap code generator.

For each case: image bytes, byte identity, and median ``compile_riscv64`` wall
time (store verification and marshalling included) with ``backend="xax"`` and
``backend="python"``.  Medians on this host; host-dependent.

Run: PYTHONPATH=src:tests python benchmarks/bench_s5_backend.py
"""

from __future__ import annotations

import json
import random
import statistics
import sys
import time
from pathlib import Path

sys.path[:0] = [str(Path(__file__).resolve().parents[1] / "src"), str(Path(__file__).resolve().parents[1] / "tests")]

OUTPUT = Path(__file__).resolve().parent / "s5_backend_evidence.json"


def main() -> None:
    from test_xax_jvm import _random_function
    from test_xax_selfhost_riscv64_backend import _pressure
    from xax_compiler import riscv64_baremetal_target
    from xax_graph_builder import program_store
    from xax_riscv64 import compile_riscv64_bound_target

    entry, graph = _random_function(random.Random(3), 64)
    cases = {"random_64": (entry, tuple(graph.objects.values())), "loop_24_live": _pressure(24), "loop_300_live": _pressure(300)}
    results = {}
    for name, (function, objects) in cases.items():
        target = riscv64_baremetal_target()
        reader = program_store(function, target, objects)
        images = {backend: compile_riscv64_bound_target(reader, function.cid, target, backend=backend) for backend in ("python", "xax")}
        timings = {}
        for backend in ("python", "xax"):
            samples = []
            for _ in range(9):
                start = time.perf_counter()
                compile_riscv64_bound_target(reader, function.cid, target, backend=backend)
                samples.append(time.perf_counter() - start)
            timings[backend] = round(statistics.median(samples) * 1000, 2)
        results[name] = {"image_bytes": len(images["xax"].code), "byte_identical": images["xax"] == images["python"],
                         "compile_ms_xax": timings["xax"], "compile_ms_python": timings["python"]}
    evidence = {"step": "S5b", "adr": "ADR-140, ADR-141", "evidence_label": "MEASURED", "cases": results,
                "note": "median of 9 compile_riscv64 calls per backend in one process (store verification cached)"}
    OUTPUT.write_text(json.dumps(evidence, indent=1) + "\n")
    print(json.dumps(evidence, indent=1))


if __name__ == "__main__":
    main()
