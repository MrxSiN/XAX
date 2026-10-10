"""``jsonmin`` on AArch64 hardware: an Android device's Linux kernel runs the XAX static image (ADR-254).

The XAX arm is the Linux AArch64 static image of :func:`benchmarks.jsonmin.build_jsonmin`
(``aarch64-linux-elf-exec-v1``: raw syscalls, no libc or loader), which runs unchanged on
any AArch64 Linux kernel, an Android device's included.  The baselines are the same C
source (``jsonmin_c/jsonmin.c``) built by the NDK's ``clang -O2`` (bionic, dynamically
linked PIE, as Android executables normally are) and ``clang -O2 -static``, and the Rust
twin (``rust_twins/jsonmin.rs``) built by ``rustc -C opt-level=3`` for
``aarch64-linux-android``: the section 15.0 multi-language rule.

Every arm's output is checked against :func:`benchmarks.jsonmin.reference_jsonmin`.  Then
``WARMUP`` untimed rounds and ``ROUNDS`` timed rounds run every arm once each, the order
rotating by one per round, pinned to one core (``taskset``; ``XAX_JSONMIN_CPU_MASK``, the
X3 core of a Pixel 8 Pro by default) so a big.LITTLE scheduler cannot move an arm between
core types.  ``linux_filestat_c/runner.c`` (built by the NDK) times fork/exec/wait4 with
CLOCK_MONOTONIC and reports ``ru_maxrss``.  The input is ``benchmark_document(8 MiB)``.

Set ``ANDROID_NDK_HOME``; ``rustc`` needs the ``aarch64-linux-android`` target (``RUSTC``
names the compiler).  Run ``python -m benchmarks.android_jsonmin [--write]`` from
``compiler/`` with one device on ``adb``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shlex
import statistics
import subprocess
import sys
import tempfile
from pathlib import Path

from benchmarks.bench_android_ndk_twin import NDK, _llvm
from benchmarks.jsonmin import EXIT_OK, benchmark_document, build_jsonmin, reference_jsonmin
from xax_linux_aarch64 import compile_linux_aarch64_executable
from xax_replacement import faster_p_value

HERE = Path(__file__).resolve().parent
REMOTE = "/data/local/tmp/xax-jsonmin"
CPU_MASK = os.environ.get("XAX_JSONMIN_CPU_MASK", "100")
# The default mask's run is the cited evidence; a run pinned elsewhere is a cross-check beside it.
EVIDENCE = HERE / ("android_jsonmin_evidence.json" if CPU_MASK == "100" else f"android_jsonmin_cpu{CPU_MASK}_evidence.json")
RUSTC = os.environ.get("RUSTC", "rustc")
C_FLAGS = {"clang-O2": ("-O2",), "clang-O2-static": ("-O2", "-static")}
RUST_FLAGS = ("-C", "opt-level=3", "-C", "panic=abort", "-C", "codegen-units=1", "--target", "aarch64-linux-android")


def _adb(*arguments: str, timeout: int = 900) -> str:
    return subprocess.run(["adb", *arguments], check=True, capture_output=True, text=True, timeout=timeout).stdout.replace("\r", "")


def _shell(command: str, timeout: int = 900) -> str:
    return _adb("shell", command, timeout=timeout)


def build(work: Path) -> tuple[dict[str, Path], dict[str, int], dict]:
    """Every arm's binary, its stripped size, and the XAX program's identity."""
    program = build_jsonmin("aarch64")
    image = compile_linux_aarch64_executable(program.reader, program.entry.cid, program.target.cid).data
    arms = {"xax": work / "xax"}
    arms["xax"].write_bytes(image)
    clang = _llvm("aarch64-linux-android28-clang")
    source = HERE / "jsonmin_c" / "jsonmin.c"
    for arm, flags in C_FLAGS.items():
        subprocess.run([str(clang), *flags, "-o", str(work / arm), str(source)], check=True)
        arms[arm] = work / arm
    subprocess.run([RUSTC, *RUST_FLAGS, "-C", f"linker={clang}", "-o", str(work / "rustc-O3"), str(HERE / "rust_twins" / "jsonmin.rs")], check=True)
    arms["rustc-O3"] = work / "rustc-O3"
    subprocess.run([str(clang), "-O2", "-o", str(work / "runner"), str(HERE / "linux_filestat_c" / "runner.c")], check=True)
    stripped = {}
    for arm, path in arms.items():
        if arm == "xax":  # no section table: nothing to strip
            stripped[arm] = path.stat().st_size
            continue
        copy = work / f"{arm}.stripped"
        subprocess.run([str(_llvm("llvm-strip")), "-s", "-o", str(copy), str(path)], check=True)
        stripped[arm] = copy.stat().st_size
    identity = {
        "program_root": program.reader.root_cid.hex(),
        "entry_function": program.entry.cid.hex(),
        "target": program.target.cid.hex(),
        "artifact_sha256": hashlib.sha256(image).hexdigest(),
        "artifact_bytes": len(image),
        "runtime_dependencies": [],
        "container": "aarch64-linux-elf-exec-v1 (static; no libc, loader, or allocator)",
    }
    return arms, stripped, identity


def _device() -> dict:
    names = ("ro.product.model", "ro.soc.model", "ro.build.fingerprint", "ro.build.version.release", "ro.product.cpu.abilist", "ro.kernel.qemu", "ro.boot.qemu")
    info = {name: _shell(f"getprop {name}").strip() for name in names}
    info["kernel"] = _shell("uname -a").strip()
    cpu = int(CPU_MASK, 16).bit_length() - 1
    info["cpu_mask"] = CPU_MASK
    info["pinned_cpu_max_khz"] = _shell(f"cat /sys/devices/system/cpu/cpu{cpu}/cpufreq/cpuinfo_max_freq").strip()
    return info


def measure(arms: dict[str, Path], document: bytes, expected: bytes, rounds: int, warmup: int) -> tuple[dict, dict]:
    _shell(f"rm -rf {REMOTE} && mkdir -p {REMOTE}")
    with tempfile.TemporaryDirectory() as directory:
        (Path(directory) / "input.json").write_bytes(document)
        for path in (*arms.values(), arms["xax"].parent / "runner", Path(directory) / "input.json"):
            _adb("push", str(path), f"{REMOTE}/{path.name}")
    _shell(f"chmod 755 {REMOTE}/runner " + " ".join(f"{REMOTE}/{arm}" for arm in arms))
    digest = hashlib.sha256(expected).hexdigest()
    for arm in arms:  # exact output and status before any timing
        line = _shell(f"cd {REMOTE} && ./{arm} <input.json >out.bin; echo $? $(sha256sum out.bin)").split()
        if line[0] != "0" or line[1] != digest:
            raise AssertionError(f"{arm}: status {line[0]}, output sha256 {line[1]} (expected {digest})")
    names = list(arms)
    schedule = [names[index % len(names):] + names[:index % len(names)] for index in range(warmup + rounds)]
    script = "; ".join(f"echo {arm} $(taskset {CPU_MASK} ./runner ./{arm} input.json)" for order in schedule for arm in order)
    def thermal() -> str:
        return " ".join(_shell("dumpsys thermalservice | grep -E 'Thermal Status|mName=(BIG|MID|LITTLE),' | head -4").split())

    thermal_before = thermal()
    lines = _shell(f"cd {REMOTE} && {script}", timeout=3600).splitlines()
    thermal_after = thermal()
    reference_rss = int(_shell(f"{REMOTE}/runner /system/bin/true").split()[2])
    _shell(f"rm -rf {REMOTE}")
    samples: dict[str, list[tuple[float, int]]] = {arm: [] for arm in arms}
    for index, line in enumerate(lines):
        arm, nanoseconds, status, rss = line.split()
        if int(status) != 0:
            raise AssertionError(f"{arm} exited {status}")
        if index >= warmup * len(names):
            samples[arm].append((int(nanoseconds) / 1e9, int(rss)))
    results = {}
    for arm, rows in samples.items():
        times = [item[0] for item in rows]
        results[arm] = {
            "file_bytes": arms[arm].stat().st_size,
            "wall_seconds_median": round(statistics.median(times), 6),
            "wall_seconds_min": round(min(times), 6),
            "wall_seconds_stdev": round(statistics.stdev(times), 6),
            "wall_seconds_samples": times,
            "peak_rss_kib_max": max(item[1] for item in rows),
            "throughput_mib_s_median": round(len(document) / (1 << 20) / statistics.median(times), 2),
        }
    medians = {arm: statistics.median(item["wall_seconds_samples"]) for arm, item in results.items()}
    competitor = min((arm for arm in medians if arm != "xax"), key=medians.get)
    fastest = min(medians.values())
    for arm, item in results.items():
        item["time_ratio_vs_fastest"] = round(medians[arm] / fastest, 6)
    results["xax"]["time_ratio_vs_fastest_competitor"] = round(medians["xax"] / medians[competitor], 6)
    results["xax"]["faster_p_value_vs_competitor"] = round(faster_p_value(results["xax"]["wall_seconds_samples"], results[competitor]["wall_seconds_samples"]), 6)
    method = {
        "warmup_rounds": warmup,
        "rounds": rounds,
        "schedule": "warmup rounds, then timed rounds; each round runs every arm once, the arm order rotating by one per round; one adb shell session",
        "timer": "CLOCK_MONOTONIC around fork/exec/wait4 in runner.c (NDK clang -O2); peak RSS from wait4 ru_maxrss",
        "pinning": f"taskset {CPU_MASK} for every timed run",
        "thermal_status_before_after": [thermal_before, thermal_after],
        "reference_dynamic_system_bin_true_rss_kib": reference_rss,
        "fastest_competitor": competitor,
        "c_flags": {arm: "NDK aarch64-linux-android28-clang " + " ".join(flags) for arm, flags in C_FLAGS.items()},
        "rust_flags": {"rustc-O3": "rustc " + " ".join(RUST_FLAGS) + " -C linker=<NDK clang>"},
        "performance_rule": "XAX_BENCHMARKS.md section 15.0 (ADR-207): XAX median over the fastest non-XAX median; R4 needs <= 0.9999x and a significant advantage, recomputed from wall_seconds_samples",
    }
    return results, method


def run(rounds: int, warmup: int, size: int) -> dict:
    document = benchmark_document(size)
    status, expected, _stderr = reference_jsonmin(document)
    if status != EXIT_OK:
        raise AssertionError("benchmark document must be valid JSON")
    with tempfile.TemporaryDirectory() as directory:
        work = Path(directory)
        arms, stripped, identity = build(work)
        host = _device()
        results, method = measure(arms, document, expected, rounds, warmup)
    for arm, item in results.items():
        item["stripped_bytes"] = stripped[arm]
    emulated = "1" in (host["ro.kernel.qemu"], host["ro.boot.qemu"])
    host["toolchain"] = {
        "ndk": (NDK / "source.properties").read_text(encoding="utf-8").split("Pkg.Revision = ")[1].split()[0],
        "rustc": subprocess.run([RUSTC, "--version"], capture_output=True, text=True).stdout.strip(),
    }
    return {
        "format": "xax-android-jsonmin-evidence-v1",
        "decision": "ADR-254",
        "evidence_label": "EXECUTED" if emulated else "MEASURED",
        "hardware": not emulated,
        "workload": "jsonmin: read stdin, validate RFC 8259 JSON (depth <= 512), write it minified (benchmarks/jsonmin.py)",
        "input": {"bytes": len(document), "sha256": hashlib.sha256(document).hexdigest(), "generator": "benchmark_document(size, seed=125)"},
        "output": {"bytes": len(expected), "sha256": hashlib.sha256(expected).hexdigest()},
        "xax": identity,
        "results": results,
        "host": host,
        "method": method,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rounds", type=int, default=101)
    parser.add_argument("--warmup", type=int, default=3)
    parser.add_argument("--size", type=int, default=8 << 20)
    parser.add_argument("--write", action="store_true")
    arguments = parser.parse_args(argv)
    evidence = run(arguments.rounds, arguments.warmup, arguments.size)
    if arguments.write:
        EVIDENCE.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    summary = {arm: {key: item[key] for key in ("wall_seconds_median", "time_ratio_vs_fastest", "peak_rss_kib_max", "stripped_bytes")} for arm, item in evidence["results"].items()}
    print(json.dumps({"summary": summary, "xax_vs_competitor": evidence["results"]["xax"]["time_ratio_vs_fastest_competitor"],
                      "p": evidence["results"]["xax"]["faster_p_value_vs_competitor"], "thermal": evidence["method"]["thermal_status_before_after"]}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
