"""ADR-123 evidence: the U1.3 ``filestat`` graph built for Linux AArch64.

The semantic graph is the same one :mod:`benchmarks.linux_filestat` builds for
x86-64; only the platform package (``linux_aarch64_api``, ``aapcs64-linux-c``
zlib import, ``aarch64-linux-elf-dynexec-v1``) differs.  The baseline is the
same ``filestat.c`` compiled by ``aarch64-linux-gnu-gcc -O2`` and by ``clang -O2``
(``--target=aarch64-linux-gnu``), plus the Rust twin (``rust_twins/filestat.rs``,
``rustc -C opt-level=3`` for ``aarch64-unknown-linux-gnu``): the §15.0
multi-language rule.  Arms run in interleaved rounds whose order rotates by one
(as ``linux_harness.py``), after untimed warmup rounds.

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
from benchmarks.linux_harness import classify
from xax_linux_aarch64 import SYSROOT, aarch64_runner, compile_linux_aarch64_executable

HERE = Path(__file__).resolve().parent
EVIDENCE = HERE / "linux_aarch64_filestat_evidence.json"
CROSS_GCC = "aarch64-linux-gnu-gcc"


RUST_SOURCE = HERE / "rust_twins" / "filestat.rs"
RUST_FLAGS = ("-C", "opt-level=3", "-C", "panic=abort", "-C", "codegen-units=1", "--target", "aarch64-unknown-linux-gnu", "-C", "linker=aarch64-linux-gnu-gcc")
CLANG_FLAGS = ("--target=aarch64-linux-gnu", "-B/usr/bin/aarch64-linux-gnu-", "--gcc-toolchain=/usr", "-O2")


def _strip(work: Path, output: Path) -> Path:
    stripped = output.with_name(output.name + ".stripped")
    subprocess.run(["aarch64-linux-gnu-strip", "-s", "-o", str(stripped), str(output)], check=True)
    return stripped


def _twins(work: Path) -> dict[str, Path]:
    include = work / "zinc"
    include.mkdir()
    for header in ("zlib.h", "zconf.h"):
        shutil.copyfile(Path("/usr/include") / header, include / header)
    twins = {}
    for arm, compiler in (("gcc-O2", [CROSS_GCC, "-O2"]), ("clang-O2", ["clang", *CLANG_FLAGS])):
        output = work / f"filestat-{arm}"
        subprocess.run([*compiler, f"-I{include}", "-o", str(output), str(C_SOURCE), f"{SYSROOT}/lib/libz.so.1"], check=True)
        twins[arm] = _strip(work, output)
    link = work / "zlink"
    link.mkdir()
    (link / "libz.so").symlink_to(f"{SYSROOT}/lib/libz.so.1")
    output = work / "filestat-rustc-O3"
    subprocess.run(["rustc", *RUST_FLAGS, "-L", str(link), "-o", str(output), str(RUST_SOURCE)], check=True, capture_output=True)
    twins["rustc-O3"] = _strip(work, output)
    return twins


def _time(arms: dict[str, list[str]], cwd: Path, repetitions: int, warmup: int, expected: bytes) -> dict[str, list[float]]:
    """Interleaved rounds; each round runs every arm once, the order rotating by one."""
    names, samples = list(arms), {name: [] for name in arms}
    for index in range(warmup + repetitions):
        shift = index % len(names)
        for name in names[shift:] + names[:shift]:
            start = time.perf_counter()
            completed = subprocess.run(arms[name], cwd=cwd, capture_output=True, check=True)
            elapsed = time.perf_counter() - start
            if completed.stdout != expected:
                raise AssertionError(f"{name} output {completed.stdout!r} != {expected!r}")
            if index >= warmup:
                samples[name].append(elapsed)
    return samples


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
        paths = {"xax": xax, **_twins(work)}
        expected = reference_filestat(data)
        samples = _time({arm: [*runner, str(path)] for arm, path in paths.items()}, work, repetitions, warmup, expected)
        results = {
            arm: {
                "artifact_bytes": paths[arm].stat().st_size,
                "wall_seconds_median": round(statistics.median(samples[arm]), 6),
                "wall_seconds_stdev": round(statistics.stdev(samples[arm]), 6) if len(samples[arm]) > 1 else 0.0,
            }
            for arm in paths
        }
    fastest = min(item["wall_seconds_median"] for item in results.values())
    for arm, item in results.items():
        item["time_ratio_vs_fastest"] = round(item["wall_seconds_median"] / fastest, 3)
    results["xax"]["performance_class"] = classify(results["xax"]["wall_seconds_median"] / fastest)
    results["ratio_xax_over_gcc"] = {
        "artifact_bytes": round(results["xax"]["artifact_bytes"] / results["gcc-O2"]["artifact_bytes"], 3),
        "wall_seconds_median": round(results["xax"]["wall_seconds_median"] / results["gcc-O2"]["wall_seconds_median"], 3),
    }
    return {
        "format": "xax-linux-aarch64-filestat-evidence-v2",
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
            "codegen": "function-wide register allocation for the Linux AArch64 profiles (ADR-168, xax_aarch64_regalloc)",
        },
        "results": results,
        "host": {
            "machine": platform.machine(),
            "executor": " ".join(Path(item).name for item in runner) or "native",
            "qemu": subprocess.run(["qemu-aarch64", "--version"], capture_output=True, text=True).stdout.splitlines()[0] if runner else None,
            "baseline_compiler": subprocess.run([CROSS_GCC, "--version"], capture_output=True, text=True).stdout.splitlines()[0],
            "clang": subprocess.run(["clang", "--version"], capture_output=True, text=True).stdout.splitlines()[0],
            "rustc": subprocess.run(["rustc", "--version"], capture_output=True, text=True).stdout.strip(),
            "flags": {"gcc-O2": "-O2", "clang-O2": " ".join(CLANG_FLAGS), "rustc-O3": " ".join(RUST_FLAGS)},
            "zlib": zlib.ZLIB_RUNTIME_VERSION,
        },
        "method": {"repetitions": repetitions, "warmup": warmup, "order": "interleaved rounds rotating by one", "timer": "time.perf_counter around the whole emulated process"},
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
