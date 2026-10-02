"""Shared measurement harness for Linux XAX-versus-C workloads (tooling only).

Every arm is timed by ``linux_filestat_c/runner.c`` (fork/exec/wait4 with
``CLOCK_MONOTONIC`` and ``ru_maxrss``); outputs are compared untimed.
"""

from __future__ import annotations

import os
import platform
import shutil
import statistics
import subprocess
from pathlib import Path
from typing import Callable

HERE = Path(__file__).resolve().parent
RUNNER_SOURCE = HERE / "linux_filestat_c" / "runner.c"
# Optimized baselines; every arm links the same libraries.
BASELINES = (
    ("gcc-O2", "gcc", ("-O2",)),
    ("gcc-O3", "gcc", ("-O3",)),
    ("clang-O2", "clang", ("-O2",)),
    ("gcc-O2-static", "gcc", ("-O2", "-static")),
)


def tool_version(command: list[str]) -> str:
    return subprocess.run(command, capture_output=True, text=True, check=True).stdout.splitlines()[0]


def run_output(program: Path, cwd: Path) -> tuple[bytes, int]:
    completed = subprocess.run([str(program)], cwd=cwd, capture_output=True, check=False)
    return completed.stdout, completed.returncode


def build_arms(work: Path, name: str, xax_bytes: bytes, c_source: Path, libraries: tuple[str, ...] = ()) -> tuple[dict[str, Path], dict[str, int]]:
    """Write the XAX artifact and compile every C baseline; return paths and stripped sizes."""
    artifacts = {"xax": work / f"{name}-xax"}
    artifacts["xax"].write_bytes(xax_bytes)
    artifacts["xax"].chmod(0o755)
    for arm, compiler, flags in BASELINES:
        subprocess.run([compiler, *flags, "-o", str(work / arm), str(c_source), *libraries], check=True)
        artifacts[arm] = work / arm
    stripped = {}
    for arm, path in artifacts.items():
        copy = work / f"{arm}.stripped"
        shutil.copyfile(path, copy)
        # The XAX image has no section table, so there is nothing to strip.
        stripped_ok = subprocess.run(["strip", "-s", str(copy)], check=False, capture_output=True).returncode == 0
        stripped[arm] = copy.stat().st_size if stripped_ok else path.stat().st_size
    return artifacts, stripped


def measure_arms(
    work: Path,
    artifacts: dict[str, Path],
    stripped: dict[str, int],
    repetitions: int,
    warmup: int,
    validate: Callable[[str, Path], bytes],
) -> tuple[dict, bytes, int]:
    """Validate each arm (``validate`` returns its output), then time it; outputs must agree."""
    runner = work / "runner"
    subprocess.run(["gcc", "-O2", "-o", str(runner), str(RUNNER_SOURCE)], check=True)
    reference_rss = int(subprocess.run([str(runner), "/bin/true"], capture_output=True, text=True, check=True).stdout.split()[2])
    results, outputs = {}, set()
    for arm, path in artifacts.items():
        outputs.add(validate(arm, path))

        def timed() -> tuple[float, int]:
            measured = subprocess.run([str(runner), str(path)], cwd=work, capture_output=True, text=True, check=True).stdout.split()
            if int(measured[1]) != 0:
                raise AssertionError(f"{arm} exited {measured[1]}")
            return int(measured[0]) / 1e9, int(measured[2])

        for _ in range(warmup):
            timed()
        samples = [timed() for _ in range(repetitions)]
        times = [item[0] for item in samples]
        results[arm] = {
            "file_bytes": path.stat().st_size,
            "stripped_bytes": stripped[arm],
            "wall_seconds_median": round(statistics.median(times), 6),
            "wall_seconds_min": round(min(times), 6),
            "wall_seconds_stdev": round(statistics.stdev(times), 6) if len(times) > 1 else 0.0,
            "peak_rss_kib_max": max(item[1] for item in samples),
        }
    if len(outputs) != 1:
        raise AssertionError(f"outputs differ: {outputs}")
    baseline = results["gcc-O2"]["wall_seconds_median"]
    best = min(item["wall_seconds_median"] for arm, item in results.items() if arm != "xax")
    for item in results.values():
        item["time_ratio_vs_gcc_O2"] = round(item["wall_seconds_median"] / baseline, 3)
        item["time_ratio_vs_best_baseline"] = round(item["wall_seconds_median"] / best, 3)
    return results, outputs.pop(), reference_rss


def host_info(**extra: str) -> dict:
    return {
        "machine": platform.machine(),
        "cpu": next((line.split(":", 1)[1].strip() for line in Path("/proc/cpuinfo").read_text().splitlines() if line.startswith("model name")), "unknown"),
        "kernel": platform.release(),
        "logical_cpus": os.cpu_count(),
        "python": platform.python_version(),
        "gcc": tool_version(["gcc", "--version"]),
        "clang": tool_version(["clang", "--version"]),
        **extra,
    }


def method_info(warmup: int, repetitions: int, reference_rss: int, link: str = "") -> dict:
    return {
        "warmup_runs": warmup,
        "repetitions": repetitions,
        "timer": "CLOCK_MONOTONIC around fork/exec/wait4 in runner.c; peak RSS from wait4 ru_maxrss",
        "reference_dynamic_bin_true_rss_kib": reference_rss,
        "rss_note": "ru_maxrss of the exec'd image; the dynamically linked /bin/true reference shows loader+libc residency under the same runner",
        "c_flags": {arm: f"{compiler} {' '.join(flags)}{' ... ' + link if link else ''}" for arm, compiler, flags in BASELINES},
    }
