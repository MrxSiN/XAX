"""Executed evidence for the first XAX WASI command module (wasm32 + host imports).

XAX semantics -> verifier -> direct wasm32 module (imports wasi_snapshot_preview1,
exports _start/memory) -> Node.js WASI host.  No wasm toolchain, JS glue, or libc.
Run: PYTHONPATH=src:.:tests python -m benchmarks.bench_wasi_command
"""
from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

from tests.test_xax_wasi import ARGS, wasi_fixture
from xax_compiler import verify_store
from xax_wasm import compile_wasm_bound_target, run_wasi_isolated

EVIDENCE_PATH = Path(__file__).parent / "wasi_command_evidence.json"
RUNS = 10


def main() -> dict:
    reader, entry, target = wasi_fixture()
    verify_store(reader)
    image = compile_wasm_bound_target(reader, entry.cid, target)
    assert image.module == compile_wasm_bound_target(reader, entry.cid, target).module
    results = {run_wasi_isolated(image, ARGS) for _ in range(RUNS)}
    assert results == {(97, b"XAX\n")}, results
    evidence = {
        "claim": "EXECUTED",
        "target": target.cid.hex(),
        "entry": entry.cid.hex(),
        "module_bytes": len(image.module),
        "module_sha256": hashlib.sha256(image.module).hexdigest(),
        "imports": ["wasi_snapshot_preview1!args_sizes_get", "wasi_snapshot_preview1!fd_write", "wasi_snapshot_preview1!proc_exit"],
        "exports": ["_start", "memory"],
        "host": {"runtime": "node " + subprocess.run(["node", "--version"], capture_output=True, text=True).stdout.strip(), "wasi": "preview1"},
        "execution": {"args": list(ARGS), "stdout": "XAX\n", "exit_code": 97, "runs": RUNS, "expected": "argc*10 + argv bytes + sum_to(10) + errnos = 30 + 12 + 55 + 0 + 0; stdout via fd_write iovec holding an exposed address"},
        "runtime_dependencies": ["platform-required WASI host (Node.js here)"],
    }
    EVIDENCE_PATH.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    return evidence


if __name__ == "__main__":
    print(json.dumps(main(), indent=2))
