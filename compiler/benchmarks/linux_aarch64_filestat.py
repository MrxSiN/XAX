"""ADR-123 evidence: the U1.3 ``filestat`` graph built for Linux AArch64.

The semantic graph is the same one :mod:`benchmarks.linux_filestat` builds for
x86-64; only the platform package (``linux_aarch64_api``, ``aapcs64-linux-c``
zlib import, ``aarch64-linux-elf-dynexec-v1``) differs.  The baseline is the
same ``filestat.c`` compiled by ``aarch64-linux-gnu-gcc -O2``.

Execution is qemu-aarch64 user mode on an x86-64 host unless the host is
AArch64.  Under emulation, times are labeled MEASURED-EMULATED: they compare
two programs under the same translator and say nothing about hardware speed
(OI-44).  Sizes and outputs are exact.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
import zlib
from pathlib import Path

from benchmarks.linux_filestat import C_SOURCE, benchmark_input, build_filestat_program, reference_filestat
from xax_linux_aarch64 import SYSROOT, aarch64_runner, compile_linux_aarch64_executable

HERE = Path(__file__).resolve().parent
EVIDENCE = HERE / "linux_aarch64_filestat_evidence.json"
CROSS_GCC = "aarch64-linux-gnu-gcc"


def _c_twin(work: Path) -> Path:
    include = work / "zinc"
    include.mkdir()
    for header in ("zlib.h", "zconf.h"):
        shutil.copyfile(Path("/usr/include") / header, include / header)
    output = work / "filestat-gcc-O2"
    subprocess.run([CROSS_GCC, "-O2", f"-I{include}", "-o", str(output), str(C_SOURCE), f"{SYSROOT}/lib/libz.so.1"], check=True)
    stripped = work / "filestat-gcc-O2.stripped"
    subprocess.run(["aarch64-linux-gnu-strip", "-s", "-o", str(stripped), str(output)], check=True)
    return stripped


def _time(command: list[str], cwd: Path, repetitions: int, warmup: int) -> tuple[bytes, list[float]]:
    outputs, samples = set(), []
    for index in range(warmup + repetitions):
        start = time.perf_counter()
        completed = subprocess.run(command, cwd=cwd, capture_output=True, check=True)
        elapsed = time.perf_counter() - start
        outputs.add(completed.stdout)
        if index >= warmup:
            samples.append(elapsed)
    if len(outputs) != 1:
        raise AssertionError("nondeterministic output")
    return outputs.pop(), samples


def run_benchmark(size: int, repetitions: int, warmup: int) -> dict:
    runner = aarch64_runner()
    if runner is None:
        raise RuntimeError("needs an AArch64 host or qemu-aarch64")
    program = build_filestat_program("aarch64")
    executable = compile_linux_aarch64_executable(program.reader, program.entry.cid, program.target.cid)
    data = benchmark_input(size)
    with tempfile.TemporaryDirectory() as directory:
        work = Path(directory)
        (work / "input.dat").write_bytes(data)
        xax = work / "filestat-xax"
        xax.write_bytes(executable.data)
        xax.chmod(0o755)
        gcc = _c_twin(work)
        results = {}
        expected = reference_filestat(data)
        for arm, path in (("xax", xax), ("gcc-O2", gcc)):
            output, samples = _time([*runner, str(path)], work, repetitions, warmup)
            if output != expected:
                raise AssertionError(f"{arm} output {output!r} != {expected!r}")
            results[arm] = {
                "artifact_bytes": path.stat().st_size,
                "wall_seconds_median": round(statistics.median(samples), 6),
                "wall_seconds_stdev": round(statistics.stdev(samples), 6) if len(samples) > 1 else 0.0,
            }
    results["ratio_xax_over_gcc"] = {
        "artifact_bytes": round(results["xax"]["artifact_bytes"] / results["gcc-O2"]["artifact_bytes"], 3),
        "wall_seconds_median": round(results["xax"]["wall_seconds_median"] / results["gcc-O2"]["wall_seconds_median"], 3),
    }
    return {
        "format": "xax-linux-aarch64-filestat-evidence-v1",
        "evidence_label": "EXECUTED (outputs, sizes); MEASURED-EMULATED (times)" if runner else "MEASURED",
        "workload": "U1.3 filestat graph (openat/read loop, counts, FNV-1a 64, zlib crc32 via libz.so.1, histogram, decimal write)",
        "input": {"bytes": size, "sha256": hashlib.sha256(data).hexdigest()},
        "output": expected.decode(),
        "xax": {
            "program_root": program.reader.root_cid.hex(),
            "entry_function": program.entry.cid.hex(),
            "target": program.target.cid.hex(),
            "artifact_sha256": hashlib.sha256(executable.data).hexdigest(),
            "artifact_bytes": len(executable.data),
            "code_bytes": len(executable.bundle.code),
            "dt_needed": [item.decode() for item in executable.needed],
            "dynamic_loader": "/lib/ld-linux-aarch64.so.1 (requested by aarch64-linux-elf-dynexec-v1)",
            "runtime_dependencies": [],
            "codegen": "AAPCS64 frame path with liveness-shared value slots (ADR-123); no register allocation for this workload yet",
        },
        "results": results,
        "host": {
            "machine": platform.machine(),
            "executor": " ".join(Path(item).name for item in runner) or "native",
            "qemu": subprocess.run(["qemu-aarch64", "--version"], capture_output=True, text=True).stdout.splitlines()[0] if runner else None,
            "baseline_compiler": subprocess.run([CROSS_GCC, "--version"], capture_output=True, text=True).stdout.splitlines()[0],
            "zlib": zlib.ZLIB_RUNTIME_VERSION,
        },
        "method": {"repetitions": repetitions, "warmup": warmup, "timer": "time.perf_counter around the whole emulated process"},
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--size", type=int, default=4 << 20)
    parser.add_argument("--repetitions", type=int, default=7)
    parser.add_argument("--warmup", type=int, default=1)
    parser.add_argument("--write", action="store_true")
    arguments = parser.parse_args(argv)
    evidence = run_benchmark(arguments.size, arguments.repetitions, arguments.warmup)
    text = json.dumps(evidence, indent=2, sort_keys=True) + "\n"
    if arguments.write:
        EVIDENCE.write_text(text)
    sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
