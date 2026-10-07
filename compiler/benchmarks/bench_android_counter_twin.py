"""Android row R4 baseline: the XAX counter app against a conventional Java + NDK twin (ADR-153).

The twin (``android_counter_twin/``) has the same package, classes, native methods,
state file, and behavior as ``android_counter_activity.apk`` (ADR-111): Java opens
the state file and detaches the descriptor, C reads the count, increments, writes,
and ``fdatasync``s it, and closes the descriptor.  It is built like
``bench_android_ndk_twin.py`` builds the minimal-Activity twin (``javac`` + ``d8``,
NDK ``clang -O2``, ``aapt2``, ``zipalign``, ``apksigner``).

Two measurements:

* **sizes** (MEASURED here): APK, DEX, manifest, and native-library bytes;
* **device** (``--device``): on the connected ``adb`` target, each APK is installed
  and, after warm-up launches, cold-started (``am force-stop``, then ``am start -W``:
  ``TotalTime``), with the process's total PSS from ``dumpsys meminfo`` after each
  start; each app's click path is checked once.  Both apps share one package name,
  so they cannot be installed together: the arms alternate in install-once passes
  (A then B, then B then A), ``RUNS`` samples per arm in all.  The result is performance and memory evidence only
  when ``hardware`` is true; an emulator run only shows that the harness works.

Set ``ANDROID_NDK_HOME``, ``ANDROID_BUILD_TOOLS``, and ``ANDROID_JAR`` as for
``bench_android_ndk_twin.py``; run ``python -m benchmarks.bench_android_counter_twin [--device]``
from ``compiler/``.
"""

from __future__ import annotations

import json
import os
import re
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from benchmarks import android_counter_app as app
from benchmarks.bench_android_ndk_twin import _measure, build_twin

HERE = Path(__file__).resolve().parent
TWIN = HERE / "android_counter_twin"
JAVA_TWIN = HERE / "android_counter_java_twin"  # pure Java: the non-C/C++ baseline (OI-45)
EVIDENCE = HERE / "android_counter_twin_evidence.json"
PACKAGE, COMPONENT = "xax.counter", "xax.counter/.CounterActivity"
# Defaults are the hardware protocol; the overrides exist to check the harness on slow
# targets (an emulator run is never performance evidence).
WARMUP = int(os.environ.get("XAX_TWIN_WARMUP", 3))
RUNS = int(os.environ.get("XAX_TWIN_RUNS", 16))
PASSES = int(os.environ.get("XAX_TWIN_PASSES", 4))
# Every arm is AOT-compiled the same way after install, so no arm's start-up depends on
# where background dexopt happened to be (the ADR-172 pass effect).
COMPILER_FILTER = os.environ.get("XAX_TWIN_COMPILER_FILTER", "speed")
UI_TIMEOUT = int(os.environ.get("XAX_UI_TIMEOUT", 60))
TAP_RETRY = int(os.environ.get("XAX_TAP_RETRY", 0))  # as in validate_counter_apk.sh
SIZE_KEYS = ("apk_bytes", "dex_bytes", "manifest_bytes", "native_library_bytes")


def _adb(*arguments: str, timeout: int = 600) -> str:
    return subprocess.run(["adb", *arguments], check=True, capture_output=True, text=True, timeout=timeout).stdout.replace("\r", "")


def _cold_start() -> dict[str, int | None]:
    """One cold start: ``TotalTime`` (``None`` when Android did not track the launch),
    ``WaitTime``, and the total PSS (KiB) of the started process."""
    _adb("shell", "am", "force-stop", PACKAGE)
    output = _adb("shell", "am", "start", "-W", "-n", COMPONENT)
    if "Status: ok" not in output:
        raise RuntimeError(f"launch failed:\n{output}")
    total = re.search(r"^TotalTime: (\d+)$", output, re.M)
    memory = _adb("shell", "dumpsys", "-t", "600", "meminfo", PACKAGE)  # dumpsys's own limit is 10 s
    return {
        "total_time_ms": int(total.group(1)) if total else None,
        "wait_time_ms": int(re.search(r"^WaitTime: (\d+)$", output, re.M).group(1)),
        "pss_kib": int(re.search(r"^\s*TOTAL(?: PSS)?:?\s+(\d+)", memory, re.M).group(1)),
    }


def _shown_count() -> int | None:
    """The number on the button, or ``None`` if the UI cannot be dumped right now."""
    dump = subprocess.run(["adb", "shell", "uiautomator", "dump", "/data/local/tmp/xax_twin_ui.xml"], capture_output=True, text=True, timeout=600)
    if dump.returncode:
        return None
    match = re.search(r'text="(\d+)"', _adb("exec-out", "cat", "/data/local/tmp/xax_twin_ui.xml"))
    return int(match.group(1)) if match else None


def _clicks_work() -> bool:
    """A tap on the full-screen button turns the shown count into count + 1 (polled, ``XAX_UI_TIMEOUT``)."""
    deadline = time.monotonic() + UI_TIMEOUT
    before = None
    while before is None and time.monotonic() < deadline:
        before = _shown_count()
    if before is None:
        return False
    size = _adb("shell", "wm", "size").strip().splitlines()[-1].split()[-1]
    width, height = (int(item) for item in size.split("x"))
    _adb("shell", "input", "tap", str(width // 2), str(height // 2))
    retry_at = time.monotonic() + TAP_RETRY if TAP_RETRY else None
    while time.monotonic() < deadline:
        shown = _shown_count()
        if shown is not None and shown != before:
            return shown == before + 1
        if retry_at is not None and time.monotonic() >= retry_at and shown == before:
            # A lost tap leaves the count unchanged; a late duplicate overshoots and fails.
            _adb("shell", "input", "tap", str(width // 2), str(height // 2))
            retry_at = time.monotonic() + TAP_RETRY
        time.sleep(2)
    return False


def _install(apk: Path, attempts: int = 3) -> None:
    """Replace whichever arm is installed (both use one package) with ``apk``."""
    for attempt in range(attempts):
        subprocess.run(["adb", "uninstall", PACKAGE], capture_output=True, text=True, timeout=300)
        completed = subprocess.run(["adb", "install", "-t", str(apk)], capture_output=True, text=True, timeout=900)
        if completed.returncode == 0 and "Success" in completed.stdout:
            return
        time.sleep(10)
    raise RuntimeError(f"adb install {apk.name} failed {attempts} times: {completed.stdout}{completed.stderr}")


def measure_device(apks: dict[str, Path]) -> dict:
    """Cold starts of every arm on the connected target, in alternating install-once passes."""
    properties = {name: _adb("shell", "getprop", name).strip() for name in (
        "ro.build.fingerprint", "ro.build.version.release", "ro.build.version.security_patch",
        "ro.product.model", "ro.product.cpu.abilist", "ro.soc.manufacturer", "ro.soc.model",
        "ro.kernel.qemu", "ro.boot.qemu",
    )}
    properties["kernel"] = _adb("shell", "uname", "-a").strip()
    samples: dict[str, dict[str, list[int | None]]] = {arm: {"total_time_ms": [], "wait_time_ms": [], "pss_kib": [], "pass": []} for arm in apks}
    clicks = {}
    for pass_index in range(PASSES):
        names = list(apks)
        for arm in names[pass_index % len(names):] + names[:pass_index % len(names)]:  # order rotates each pass
            _install(apks[arm])
            _adb("shell", "cmd", "package", "compile", "-f", "-m", COMPILER_FILTER, PACKAGE)
            for _ in range(WARMUP):
                _cold_start()
            if pass_index == 0:
                clicks[arm] = _clicks_work()
            for _ in range(RUNS // PASSES):
                for key, value in _cold_start().items():
                    samples[arm][key].append(value)
                samples[arm]["pass"].append(pass_index)
    subprocess.run(["adb", "uninstall", PACKAGE], capture_output=True, timeout=300)
    emulated = "1" in (properties["ro.kernel.qemu"], properties["ro.boot.qemu"])
    def stats(values: list[int | None]) -> tuple[float | None, float | None]:
        present = [value for value in values if value is not None]
        return (statistics.median(present) if present else None, round(statistics.stdev(present), 2) if len(present) > 1 else None)

    summary = {
        arm: {
            "clicks_work": clicks[arm],
            "untracked_launches": rows["total_time_ms"].count(None),
            **{f"median_{key}": stats(values)[0] for key, values in rows.items() if key != "pass"},
            **{f"stdev_{key}": stats(values)[1] for key, values in rows.items() if key != "pass"},
            "pass_median_total_time_ms": [stats([v for v, p in zip(rows["total_time_ms"], rows["pass"]) if p == index])[0] for index in range(PASSES)],
            "samples": rows,
        }
        for arm, rows in samples.items()
    }
    # TotalTime is the comparison; an arm with any untracked launch gets no ratio.
    tracked = all(item["untracked_launches"] == 0 for item in summary.values())
    fastest = min(item["median_total_time_ms"] for item in summary.values()) if tracked else None
    for item in summary.values():
        item["time_ratio_vs_fastest"] = round(item["median_total_time_ms"] / fastest, 3) if tracked else None
    # Pass effect: the XAX arm against the fastest arm of the same pass.
    pass_ratios = [round(summary["xax"]["pass_median_total_time_ms"][index] / min(item["pass_median_total_time_ms"][index] for item in summary.values()), 3)
                   for index in range(PASSES)] if tracked else None
    return {
        "label": "MEASURED" if not emulated else "EXECUTED",
        "hardware": not emulated,
        "note": "performance and memory evidence" if not emulated else "emulator run: shows the harness works; not performance or memory evidence",
        "target": properties,
        "warmup": WARMUP,
        "runs": RUNS,
        "passes": PASSES,
        "compiler_filter": COMPILER_FILTER,
        "pass_order": "arms rotate by one each pass; each pass reinstalls and recompiles every arm",
        "xax_pass_ratios_vs_fastest": pass_ratios,
        "arms": summary,
    }


def evidence(device: dict | None = None) -> dict:
    from benchmarks.bench_android_ndk_twin import ANDROID_JAR, BUILD_TOOLS, NDK, _ENV

    with tempfile.TemporaryDirectory() as directory:
        for name in ("ndk", "java"):
            (Path(directory) / name).mkdir()
        twin_apk = build_twin(Path(directory) / "ndk", TWIN, "xaxcounter")
        java_apk = build_twin(Path(directory) / "java", JAVA_TWIN, "xaxcounter")
        twin, java = _measure(twin_apk), _measure(java_apk)
        xax = _measure(app.APK)
        if device is None and "--device" in sys.argv[1:]:
            device = measure_device({"xax": app.APK, "clang_ndk_java": twin_apk, "java_d8": java_apk})
    if device is None and EVIDENCE.exists():
        committed = json.loads(EVIDENCE.read_text(encoding="utf-8"))
        if committed.get("xax", {}).get("apk_sha256") == xax["apk_sha256"] and "java_d8" in committed.get("device", {}).get("arms", {}):
            device = committed.get("device")
    hardware = bool(device and device.get("hardware"))
    return {
        "format": "xax-android-counter-twin-evidence-v2",
        "decision": "ADR-153",
        "label": "MEASURED",
        "toolchain": {
            "ndk": (NDK / "source.properties").read_text(encoding="utf-8").split("Pkg.Revision = ")[1].split()[0],
            "build_tools": (BUILD_TOOLS / "source.properties").read_text(encoding="utf-8").split("Pkg.Revision=")[1].split()[0],
            "javac": subprocess.run(["javac", "-version"], capture_output=True, text=True, env=_ENV).stdout.strip(),
            "android_jar": ANDROID_JAR.parent.name,
        },
        "behavior_match": xax["badging"] == twin["badging"] and set(xax["native_function_bytes"]) == set(twin["native_function_bytes"]),
        "xax": xax,
        "java_ndk": twin,
        "xax_over_java_ndk": {key: round(xax[key] / twin[key], 3) for key in SIZE_KEYS},
        "java": java,
        "java_behavior_match": xax["badging"] == java["badging"],
        "xax_over_java": {key: round(xax[key] / java[key], 3) for key in SIZE_KEYS if java[key]},
        # The section 15.0 verdict input (xax_replacement.recompute_runtime_verdict): cold-start TotalTime per arm.
        "host": device["target"] if hardware else None,
        "results": {
            arm: {
                "wall_seconds_samples": [value / 1000 for value in row["samples"]["total_time_ms"] if value is not None],
                "time_ratio_vs_fastest": row["time_ratio_vs_fastest"],
                "median_pss_kib": row["median_pss_kib"],
            }
            for arm, row in device["arms"].items()
        } if hardware else None,
        "device": device or {"label": "UNEXECUTED", "note": "start-up time and memory need an arm64 hardware device (--device)"},
    }


def main() -> int:
    result = evidence()
    EVIDENCE.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({key: result[key] for key in ("behavior_match", "xax_over_java_ndk")}, indent=2))
    device = result["device"]
    print("device:", device["label"], {arm: {key: value for key, value in row.items() if key.startswith(("median", "time", "clicks", "untracked"))} for arm, row in device.get("arms", {}).items()})
    return 0 if result["behavior_match"] else 1


if __name__ == "__main__":
    sys.exit(main())
