"""Executed evidence for the hosted XAX PE32+ fixture under Wine (ADR-095).

The Windows-host evidence (``windows_pe_hosted_evidence.json``) covers the
bytes it records.  After allocator convergence changed the code, this runs
the current bytes under Wine on Linux.  Wine is a Windows API
reimplementation, not Windows: the claim is EXECUTED-UNDER-WINE, and Linux
reports the exit status modulo 256 (1339 -> 59).
Run: PYTHONPATH=src:. python -m benchmarks.bench_windows_pe_wine
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from tests.test_xax_pe import hosted_fixture
from xax_pe import emit_pe_executable
from xax_x86_64 import compile_native_bound_target

EVIDENCE_PATH = Path(__file__).parent / "windows_pe_wine_evidence.json"
RUNS = 20
WINE_CANDIDATES = ("wine64", "/usr/lib/wine/wine64", "wine")


def wine_executable() -> str | None:
    return next((path for path in (shutil.which(name) or (name if os.path.isfile(name) else None) for name in WINE_CANDIDATES) if path), None)


def run_under_wine(pe: bytes, wine: str, prefix: str) -> subprocess.CompletedProcess:
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "xax_hosted.exe"
        path.write_bytes(pe)
        environment = {**os.environ, "WINEPREFIX": prefix, "WINEDEBUG": "-all"}
        return subprocess.run([wine, str(path)], capture_output=True, timeout=120, env=environment, check=False)


def main() -> dict:
    wine = wine_executable()
    if wine is None:
        raise SystemExit("wine64 is required")
    reader, entry, target = hosted_fixture()
    image = compile_native_bound_target(reader, entry.cid, target)
    pe = emit_pe_executable(image)
    version = subprocess.run([wine, "--version"], capture_output=True, text=True, check=False).stdout.strip()
    with tempfile.TemporaryDirectory() as prefix:
        results = {(completed.stdout, completed.returncode) for completed in (run_under_wine(pe, wine, prefix) for _ in range(RUNS))}
    assert results == {(b"XAX\n", 1339 % 256)}, results
    evidence = {
        "claim": "EXECUTED-UNDER-WINE",
        "target": target.cid.hex(),
        "entry": entry.cid.hex(),
        "pe_bytes": len(pe),
        "pe_sha256": hashlib.sha256(pe).hexdigest(),
        "code_bytes": len(image.code),
        "imports": sorted({f"{lib.decode()}!{name.decode()}" for _, lib, name in image.imports}),
        "runtime_dependencies": [],
        "host": {"wine": version, "note": "Wine reimplements the Windows API on Linux; not a Windows host"},
        "execution": {"stdout": "XAX\n", "exit_code_mod_256": 1339 % 256, "runs": RUNS},
    }
    EVIDENCE_PATH.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    return evidence


if __name__ == "__main__":
    print(json.dumps(main(), indent=2))
