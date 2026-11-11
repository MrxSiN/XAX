"""Cold-start breakdown of the counter arms from atrace slices (run from compiler/ with the twin env set).

usage: startup_trace.py <out.json> <rounds>
Per arm and round: atrace (am wm view dalvik) around one cold start; from the app process's
main thread, the duration of every slice by name, plus fork-to-first-frame bounds.
"""
import json
import re
import statistics
import subprocess
import sys
import tempfile
from pathlib import Path

from benchmarks import android_counter_app as app
from benchmarks import bench_android_counter_twin as twin

OUT, ROUNDS = Path(sys.argv[1]), int(sys.argv[2])
LINE = re.compile(r"^\s*(.+?)-(\d+)\s+\(\s*([\d-]+)\)\s+\[\d+\]\s+\S+\s+([\d.]+): tracing_mark_write: ([BE])\|(\d+)\|?(.*)$")


def adb(*a, text=True):
    return subprocess.run(["adb", *a], check=True, capture_output=True, text=text, timeout=300).stdout


def trace_one(package):
    adb("shell", "am", "force-stop", package)
    adb("shell", "atrace", "--async_start", "-b", "32768", "am", "wm", "view", "dalvik")
    out = adb("shell", "am", "start", "-W", "-n", f"{package}/{twin.ACTIVITY}")
    total = re.search(r"^TotalTime: (\d+)", out.replace("\r", ""), re.M)
    adb("shell", "sleep", "1")
    raw = adb("exec-out", "atrace", "--async_stop", text=False).decode("utf-8", "replace")
    pid = adb("shell", "pidof", package).strip()
    return raw, pid, int(total.group(1)) if total else None


def slices(raw, pid):
    """name -> total ms on the app's main thread (tid == pid); and (first, last) slice timestamps."""
    stack, sums, first, last = [], {}, None, None
    for line in raw.splitlines():
        m = LINE.match(line)
        if not m or m.group(2) != pid:
            continue
        t = float(m.group(4))
        first = t if first is None else first
        last = t
        if m.group(5) == "B":
            stack.append((m.group(7), t))
        elif stack:
            name, start = stack.pop()
            name = re.sub(r"\d{3,}", "#", name)
            sums[name] = sums.get(name, 0.0) + (t - start) * 1000
    return sums, (last - first) * 1000 if first is not None else None


def main():
    with tempfile.TemporaryDirectory() as d:
        apks = {"xax": (twin.PACKAGE, app.APK)}
        for arm, (source, library, package) in twin.TWINS.items():
            work = Path(d) / arm
            work.mkdir()
            apks[arm] = (package, twin.build_twin(work, source, library, package))
        for arm, (package, apk) in apks.items():
            twin._install(apk, package)
            adb("shell", "cmd", "package", "compile", "-f", "-m", "speed", package)
            for _ in range(3):
                twin._cold_start(package)
        rows = {arm: [] for arm in apks}
        names = list(apks)
        for r in range(ROUNDS):
            for arm in names[r % 4:] + names[:r % 4]:
                raw, pid, total = trace_one(apks[arm][0])
                sums, span = slices(raw, pid)
                rows[arm].append({"total_time_ms": total, "main_thread_span_ms": span, "slices_ms": sums})
                if r == 0:
                    (OUT.parent / f"trace_{arm}.txt").write_text(raw, encoding="utf-8")
        for package, _ in apks.values():
            subprocess.run(["adb", "uninstall", package], capture_output=True)
    summary = {}
    for arm, runs in rows.items():
        keys = set().union(*(run["slices_ms"] for run in runs))
        med = {k: round(statistics.median(run["slices_ms"].get(k, 0.0) for run in runs), 3) for k in keys}
        summary[arm] = {
            "median_total_time_ms": statistics.median(x["total_time_ms"] for x in runs if x["total_time_ms"] is not None),
            "median_slices_ms": dict(sorted(med.items(), key=lambda kv: -kv[1])[:40]),
        }
    OUT.write_text(json.dumps({"rounds": ROUNDS, "summary": summary, "raw": rows}, indent=1), encoding="utf-8")
    for arm, s in summary.items():
        print(arm, s["median_total_time_ms"])
        for k, v in list(s["median_slices_ms"].items())[:25]:
            print(f"   {v:9.3f}  {k[:90]}")


main()
