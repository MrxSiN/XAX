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
import re
import statistics
import subprocess
import sys
import tempfile
from pathlib import Path

from benchmarks import android_counter_app as app
from benchmarks.bench_android_ndk_twin import _measure, build_twin

HERE = Path(__file__).resolve().parent
TWIN = HERE / "android_counter_twin"
EVIDENCE = HERE / "android_counter_twin_evidence.json"
PACKAGE, COMPONENT = "xax.counter", "xax.counter/.CounterActivity"
WARMUP, RUNS, PASSES = 3, 16, 2
SIZE_KEYS = ("apk_bytes", "dex_bytes", "manifest_bytes", "native_library_bytes")


def _adb(*arguments: str, timeout: int = 600) -> str:
    return subprocess.run(["adb", *arguments], check=True, capture_output=True, text=True, timeout=timeout).stdout.replace("\r", "")


def _cold_start() -> tuple[int, int]:
    """One cold start: (``TotalTime`` ms, total PSS KiB of the started process)."""
    _adb("shell", "am", "force-stop", PACKAGE)
    output = _adb("shell", "am", "start", "-W", "-n", COMPONENT)
    if "Status: ok" not in output:
        raise RuntimeError(f"launch failed:\n{output}")
    total = int(re.search(r"^TotalTime: (\d+)$", output, re.M).group(1))
    memory = _adb("shell", "dumpsys", "meminfo", PACKAGE)
    pss = int(re.search(r"^\s*TOTAL(?: PSS)?:?\s+(\d+)", memory, re.M).group(1))
    return total, pss


def _clicks_work() -> bool:
    """A tap on the full-screen button turns the restored count into count + 1."""
    def text() -> str:
        _adb("shell", "uiautomator", "dump", "/data/local/tmp/xax_twin_ui.xml")
        return re.search(r'text="(\d+)"', _adb("exec-out", "cat", "/data/local/tmp/xax_twin_ui.xml")).group(1)

    before = int(text())
    size = _adb("shell", "wm", "size").strip().splitlines()[-1].split()[-1]
    width, height = (int(item) for item in size.split("x"))
    _adb("shell", "input", "tap", str(width // 2), str(height // 2))
    subprocess.run(["sleep", "2"], check=True)
    return int(text()) == before + 1


def measure_device(apks: dict[str, Path]) -> dict:
    """Cold starts of every arm on the connected target, in alternating install-once passes."""
    properties = {name: _adb("shell", "getprop", name).strip() for name in ("ro.build.fingerprint", "ro.product.model", "ro.product.cpu.abilist", "ro.kernel.qemu", "ro.boot.qemu")}
    samples: dict[str, dict[str, list[int]]] = {arm: {"total_time_ms": [], "pss_kib": []} for arm in apks}
    clicks = {}
    for pass_index in range(PASSES):
        for arm in (list(apks) if pass_index % 2 == 0 else list(reversed(apks))):
            if PACKAGE in _adb("shell", "pm", "list", "packages", PACKAGE):
                _adb("uninstall", PACKAGE, timeout=300)
            _adb("install", "-t", str(apks[arm]), timeout=900)
            for _ in range(WARMUP):
                _cold_start()
            if pass_index == 0:
                clicks[arm] = _clicks_work()
            for _ in range(RUNS // PASSES):
                total, pss = _cold_start()
                samples[arm]["total_time_ms"].append(total)
                samples[arm]["pss_kib"].append(pss)
    _adb("uninstall", PACKAGE, timeout=300)
    emulated = "1" in (properties["ro.kernel.qemu"], properties["ro.boot.qemu"])
    summary = {
        arm: {
            "clicks_work": clicks[arm],
            **{f"median_{key}": statistics.median(values) for key, values in rows.items()},
            **{f"stdev_{key}": round(statistics.stdev(values), 2) for key, values in rows.items()},
            "samples": rows,
        }
        for arm, rows in samples.items()
    }
    fastest = min(item["median_total_time_ms"] for item in summary.values())
    for item in summary.values():
        item["time_ratio_vs_fastest"] = round(item["median_total_time_ms"] / fastest, 3)
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
    print("device:", device["label"], {arm: {key: value for key, value in row.items() if key.startswith(("median", "time", "clicks"))} for arm, row in device.get("arms", {}).items()})
    return 0 if result["behavior_match"] else 1


if __name__ == "__main__":
    sys.exit(main())
