"""Executed evidence for the first hosted XAX PE32+ executable (Windows x86-64).

XAX semantics -> verifier -> x86-64 lowering -> direct PE32+ container with
kernel32 imports -> Windows process.  No CRT, linker, assembler, or LLVM.
Run: PYTHONPATH=src:. python -m benchmarks.bench_windows_pe_hosted
"""
from __future__ import annotations

import hashlib
import json
import platform
import statistics
import subprocess
import tempfile
import time
from pathlib import Path

from tests.test_xax_pe import hosted_fixture
from xax_compiler import verify_store
from xax_pe import emit_pe_executable
from xax_x86_64 import compile_native_bound_target

EVIDENCE_PATH = Path(__file__).parent / "windows_pe_hosted_evidence.json"
RUNS = 20


def main() -> dict:
    reader, entry, target = hosted_fixture()
    verify_store(reader)
    image = compile_native_bound_target(reader, entry.cid, target)
    pe = emit_pe_executable(image)
    assert pe == emit_pe_executable(compile_native_bound_target(reader, entry.cid, target))
    evidence = {
        "claim": "EXECUTED",
        "target": target.cid.hex(),
        "entry": entry.cid.hex(),
        "pe_bytes": len(pe),
        "pe_sha256": hashlib.sha256(pe).hexdigest(),
        "code_bytes": len(image.code),
        "imports": sorted({f"{lib.decode()}!{name.decode()}" for _, lib, name in image.imports}),
        "runtime_dependencies": [],
        "host": {"system": platform.system(), "release": platform.release(), "version": platform.version(), "machine": platform.machine(), "processor": platform.processor()},
        "c_baseline": "UNAVAILABLE: no C toolchain on host; see benchmarks/windows_c_reference/hosted.c",
    }
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "xax_hosted.exe"
        path.write_bytes(pe)
        samples = []
        for _ in range(RUNS):
            start = time.perf_counter_ns()
            completed = subprocess.run([str(path)], capture_output=True, timeout=30)
            samples.append(time.perf_counter_ns() - start)
            assert (completed.stdout, completed.returncode) == (b"XAX\n", 1339), completed
    samples.sort()
    evidence["execution"] = {
        "stdout": "XAX\n", "exit_code": 1339, "runs": RUNS,
        "process_wall_ns": {"median": int(statistics.median(samples)), "p95": samples[int(0.95 * (RUNS - 1))], "min": samples[0], "max": samples[-1]},
        "note": "wall time includes CreateProcess/loader/pipe overhead measured from Python subprocess; not a code-quality claim",
    }
    EVIDENCE_PATH.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    return evidence


if __name__ == "__main__":
    print(json.dumps(main(), indent=2))
