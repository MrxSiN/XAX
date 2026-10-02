"""First C comparison for the Windows PE row (U1.1/U1.2b), under Wine.

The XAX hosted fixture and its C twin (``windows_c_reference/hosted.c``, no
CRT, MinGW-w64 ``-O2``) both print ``XAX\\n`` and exit 1339.  Recorded: file
bytes, executable section bytes (``.text`` for C; the code image for XAX),
and process wall time over repeated runs under Wine.  Wine reimplements the
Windows API on Linux and dominates wall time, so time is a start-up
comparison, not a code-quality one.  Wine is not Windows.
Run: PYTHONPATH=src:. python -m benchmarks.bench_windows_pe_c_wine
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import statistics
import subprocess
import tempfile
import time
from pathlib import Path

from benchmarks.bench_windows_pe_wine import wine_executable
from tests.test_xax_pe import hosted_fixture
from xax_pe import emit_pe_executable
from xax_x86_64 import compile_native_bound_target

HERE = Path(__file__).parent
EVIDENCE_PATH = HERE / "windows_pe_c_wine_evidence.json"
C_SOURCE = HERE / "windows_c_reference" / "hosted.c"
CC = "x86_64-w64-mingw32-gcc"
C_FLAGS = ("-O2", "-nostdlib", "-ffreestanding", "-fno-asynchronous-unwind-tables", "-e", "start", "-s")
RUNS = 21


def build_c(directory: Path) -> Path:
    output = directory / "hosted_c.exe"
    subprocess.run([CC, *C_FLAGS, "-o", str(output), str(C_SOURCE), "-lkernel32"], check=True)
    return output


def text_bytes(path: Path) -> int:
    listing = subprocess.run(["x86_64-w64-mingw32-objdump", "-h", str(path)], capture_output=True, text=True, check=True).stdout
    return sum(int(line.split()[2], 16) for line in listing.splitlines() if line.split()[1:2] == [".text"])


def main() -> dict:
    wine = wine_executable()
    if wine is None or shutil.which(CC) is None:
        raise SystemExit("wine64 and x86_64-w64-mingw32-gcc are required")
    reader, entry, target = hosted_fixture()
    image = compile_native_bound_target(reader, entry.cid, target)
    xax_pe = emit_pe_executable(image)
    with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as prefix:
        work = Path(directory)
        arms = {"xax": work / "hosted_xax.exe", "c-mingw-O2": build_c(work)}
        arms["xax"].write_bytes(xax_pe)
        environment = {**os.environ, "WINEPREFIX": prefix, "WINEDEBUG": "-all"}
        subprocess.run([wine, "wineboot", "-i"], capture_output=True, env=environment, check=False)
        samples = {arm: [] for arm in arms}
        for _ in range(RUNS):
            for arm, path in arms.items():
                start = time.perf_counter_ns()
                completed = subprocess.run([wine, str(path)], capture_output=True, env=environment, timeout=120, check=False)
                samples[arm].append(time.perf_counter_ns() - start)
                assert (completed.stdout, completed.returncode) == (b"XAX\n", 1339 % 256), (arm, completed)
        sizes = {arm: path.stat().st_size for arm, path in arms.items()}
        executable = {"xax": len(image.code), "c-mingw-O2": text_bytes(arms["c-mingw-O2"])}
        digests = {arm: hashlib.sha256(path.read_bytes()).hexdigest() for arm, path in arms.items()}
    evidence = {
        "claim": "MEASURED-UNDER-WINE",
        "workload": "tests/test_xax_pe.py::hosted_fixture and its C twin: WriteFile, heap alloc/free, sum_to(10), VirtualAlloc squares sum, function-pointer dispatch; exit 1339",
        "compiler": subprocess.run([CC, "--version"], capture_output=True, text=True, check=True).stdout.splitlines()[0],
        "c_flags": " ".join(C_FLAGS) + " ... -lkernel32",
        "wine": subprocess.run([wine, "--version"], capture_output=True, text=True, check=False).stdout.strip(),
        "file_bytes": sizes,
        "executable_bytes": executable,
        "sha256": digests,
        "runs": RUNS,
        "process_wall_ms_median": {arm: round(statistics.median(values) / 1e6, 2) for arm, values in samples.items()},
        "note": "wall time is dominated by Wine process start-up; Wine is not Windows; gcc inlines and constant-folds sum_to(10) and the dispatch table and vectorizes the squares loops, all of which XAX executes at run time",
    }
    EVIDENCE_PATH.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    return evidence


if __name__ == "__main__":
    print(json.dumps(main(), indent=2))
