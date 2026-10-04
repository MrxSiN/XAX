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
EVIDENCE = HERE / "android_counter_twin_evidence.json"
PACKAGE, COMPONENT = "xax.counter", "xax.counter/.CounterActivity"
# Defaults are the hardware protocol; the overrides exist to check the harness on slow
# targets (an emulator run is never performance evidence).
WARMUP = int(os.environ.get("XAX_TWIN_WARMUP", 3))
RUNS = int(os.environ.get("XAX_TWIN_RUNS", 16))
PASSES = 2
UI_TIMEOUT = int(os.environ.get("XAX_UI_TIMEOUT", 60))
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
    while time.monotonic() < deadline:
        shown = _shown_count()
        if shown is not None and shown != before:
            return shown == before + 1
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
    properties = {name: _adb("shell", "getprop", name).strip() for name in ("ro.build.fingerprint", "ro.product.model", "ro.product.cpu.abilist", "ro.kernel.qemu", "ro.boot.qemu")}
    samples: dict[str, dict[str, list[int | None]]] = {arm: {"total_time_ms": [], "wait_time_ms": [], "pss_kib": []} for arm in apks}
    clicks = {}
    for pass_index in range(PASSES):
        for arm in (list(apks) if pass_index % 2 == 0 else list(reversed(apks))):
            _install(apks[arm])
            for _ in range(WARMUP):
                _cold_start()
            if pass_index == 0:
                clicks[arm] = _clicks_work()
            for _ in range(RUNS // PASSES):
                for key, value in _cold_start().items():
                    samples[arm][key].append(value)
    subprocess.run(["adb", "uninstall", PACKAGE], capture_output=True, timeout=300)
    emulated = "1" in (properties["ro.kernel.qemu"], properties["ro.boot.qemu"])
    def stats(values: list[int | None]) -> tuple[float | None, float | None]:
        present = [value for value in values if value is not None]
        return (statistics.median(present) if present else None, round(statistics.stdev(present), 2) if len(present) > 1 else None)

    summary = {
        arm: {
            "clicks_work": clicks[arm],
            "untracked_launches": rows["total_time_ms"].count(None),
            **{f"median_{key}": stats(values)[0] for key, values in rows.items()},
            **{f"stdev_{key}": stats(values)[1] for key, values in rows.items()},
            "samples": rows,
        }
        for arm, rows in samples.items()
    }
    # TotalTime is the comparison; an arm with any untracked launch gets no ratio.
    tracked = all(item["untracked_launches"] == 0 for item in summary.values())
    fastest = min(item["median_total_time_ms"] for item in summary.values()) if tracked else None
    for item in summary.values():
        item["time_ratio_vs_fastest"] = round(item["median_total_time_ms"] / fastest, 3) if tracked else None
    return {
        "label": "MEASURED" if not emulated else "EXECUTED",
        "hardware": not emulated,
        "note": "performance and memory evidence" if not emulated else "emulator run: shows the harness works; not performance or memory evidence",
        "target": properties,
        "warmup": WARMUP,
        "runs": RUNS,
        "passes": PASSES,
        "arms": summary,
    }


def evidence(device: dict | None = None) -> dict:
    from benchmarks.bench_android_ndk_twin import ANDROID_JAR, BUILD_TOOLS, NDK, _ENV

    with tempfile.TemporaryDirectory() as directory:
        twin_apk = build_twin(Path(directory), TWIN, "xaxcounter")
        twin = _measure(twin_apk)
        xax = _measure(app.APK)
        if device is None and "--device" in sys.argv[1:]:
            device = measure_device({"xax": app.APK, "java_ndk": twin_apk})
    if device is None and EVIDENCE.exists():
        committed = json.loads(EVIDENCE.read_text(encoding="utf-8"))
        if committed.get("xax", {}).get("apk_sha256") == xax["apk_sha256"]:
            device = committed.get("device")
    return {
        "format": "xax-android-counter-twin-evidence-v1",
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
