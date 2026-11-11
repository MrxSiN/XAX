"""Measurement driver outside BBC and XAX: BBC's Android ARM64 executables on a device, before and after XAX ledger 0025.

usage: device_bench.py <old bbc.exe dir> <new bbc.exe dir> <out.json>
Each directory holds bbc.exe and the two host stores.  Every corpus program is built at -O0 and -O1 by both arms on
this Windows host and run on the adb device; output bytes and exit status 0 are compared with corpus/<name>.expected.
For the compute programs: user-mode instructions and cycles (simpleperf stat, 3 runs) and wall time (ROUNDS
interleaved rounds, device clock), every run pinned with taskset; brainfry linux-aarch64 is the outside arm.

bbc.exe as built does not start on Windows 11 (XAX OI-56: a 78 KB frame without a stack probe); the copy that runs
here has SizeOfStackCommit set to SizeOfStackReserve in its PE header.  That changes no compiler logic.
"""
import hashlib
import json
import os
import statistics
import struct
import subprocess
import sys
from pathlib import Path

HERE = Path(os.environ.get("BBC_BENCH_WORK", ".")).resolve()  # scratch directory
CORPUS = Path(os.environ["BBC_BENCH_CORPUS"])  # <name>.bf, <name>.expected and optional <name>.in
BRAINFRY = Path(os.environ["BRAINFRY"])  # brainfry's bfnative
ADB = os.environ.get("ADB", "adb")
REMOTE = "/data/local/tmp/r4bench"
MASK = "100"  # the Cortex-X3 core of a Pixel 8 Pro
ROUNDS = 15
COMPUTE = ("mandelbrot", "factor", "life")


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def adb(*a, data=None):
    return subprocess.run([ADB, *a], input=data, capture_output=True, timeout=900)


def shell(command):
    return adb("shell", command).stdout.decode("utf-8", "replace").replace("\r", "")


def runnable(directory, work):
    data = bytearray((directory / "bbc.exe").read_bytes())
    opt = struct.unpack_from("<I", data, 0x3C)[0] + 24
    struct.pack_into("<Q", data, opt + 80, struct.unpack_from("<Q", data, opt + 72)[0])
    work.mkdir(parents=True, exist_ok=True)
    (work / "bbc.exe").write_bytes(data)
    for host in ("bbc-android-arm64.xax", "bbc-windows-x86_64.xax"):
        (work / host).write_bytes((directory / host).read_bytes())
    return work


def main():
    old, new, out = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
    arms = {"before": runnable(old, HERE / "bench/before"), "after": runnable(new, HERE / "bench/after")}
    programs = sorted(p.stem for p in CORPUS.glob("*.bf"))
    shell(f"rm -rf {REMOTE}; mkdir -p {REMOTE}")
    record = {"bbc_exe_sha256": {"before": sha(old / "bbc.exe"), "after": sha(new / "bbc.exe")}, "programs": {}}
    for name in programs:
        source = (CORPUS / f"{name}.bf").read_bytes()
        expected = (CORPUS / f"{name}.expected").read_bytes()
        stdin = CORPUS / f"{name}.in"
        adb("push", str(stdin), f"{REMOTE}/{name}.in") if stdin.exists() else shell(f": > {REMOTE}/{name}.in")
        row = record["programs"][name] = {}
        for arm, work in arms.items():
            for level in ("O0", "O1"):
                exe = work / f"{name}-{level}"
                done = subprocess.run([str(work / "bbc.exe"), "compile", "android-arm64", f"-{level}", exe.name], input=source, cwd=work, capture_output=True, timeout=900)
                item = row[f"{arm}-{level}"] = {"build_exit": done.returncode}
                if done.returncode:
                    continue
                remote = f"{REMOTE}/{arm}-{name}-{level}"
                adb("push", str(exe), remote)
                shell(f"chmod 755 {remote}")
                run = adb("exec-out", f"{remote} < {REMOTE}/{name}.in; echo \"|exit=$?\"").stdout
                body, _, status = run.rpartition(b"|exit=")
                item.update(exe_bytes=exe.stat().st_size, exe_sha256=sha(exe), run_exit=int(status), output_matches=body == expected)
        if name in COMPUTE:
            fry = HERE / "bench" / f"brainfry-{name}"
            subprocess.run([str(BRAINFRY), "--target", "linux-aarch64", "-o", str(fry), str(CORPUS / f"{name}.bf")], check=True, capture_output=True)
            adb("push", str(fry), f"{REMOTE}/brainfry-{name}-O1")
            shell(f"chmod 755 {REMOTE}/brainfry-{name}-O1")
            run = adb("exec-out", f"{REMOTE}/brainfry-{name}-O1 < {REMOTE}/{name}.in").stdout
            row["brainfry"] = {"exe_bytes": fry.stat().st_size, "output_matches": run == expected}
    for name in COMPUTE:
        row = record["programs"][name]
        timed = {"before-O1": f"before-{name}-O1", "after-O1": f"after-{name}-O1", "brainfry": f"brainfry-{name}-O1"}
        timed = {arm: exe for arm, exe in timed.items() if row[arm].get("output_matches")}
        for arm, exe in timed.items():
            counts = []
            for _ in range(3):
                shell(f"cd {REMOTE}; taskset {MASK} simpleperf stat -e instructions:u,cpu-cycles:u -o st.txt ./{exe} < {name}.in > /dev/null 2>&1")
                text = shell(f"cat {REMOTE}/st.txt")
                counts.append([int(line.split()[0].replace(",", "")) for line in text.splitlines() if "instructions" in line or "cpu-cycles" in line])
            row[arm]["instructions_user"] = [c[0] for c in counts]
            row[arm]["cycles_user"] = [c[1] for c in counts]
        loop = "; ".join(f"s=$(date +%s%N); taskset {MASK} ./{exe} < {name}.in > /dev/null; echo {arm} $(( ($(date +%s%N)-s)/1000 ))" for arm, exe in timed.items())
        lines = shell(f"cd {REMOTE}; i=0; while [ $i -lt {ROUNDS} ]; do {loop}; i=$((i+1)); done").split("\n")
        for arm in timed:
            samples = [int(line.split()[1]) / 1e6 for line in lines if line.startswith(arm + " ")]
            row[arm]["wall_seconds_samples"] = samples
            row[arm]["wall_seconds_median"] = statistics.median(samples)
    record["device"] = {key: shell(f"getprop {key}").strip() for key in ("ro.product.model", "ro.build.fingerprint", "ro.soc.model")}
    record["device"]["kernel"] = shell("uname -r").strip()
    record["device"]["battery"] = shell("dumpsys battery | grep -E 'level|temperature|AC powered'").split("\n")
    shell(f"rm -rf {REMOTE}")
    out.write_text(json.dumps(record, indent=1), encoding="utf-8")
    builds = [v for row in record["programs"].values() for k, v in row.items() if k != "brainfry"]
    print("builds", sum(1 for v in builds if v["build_exit"] == 0), "of", len(builds), "matching runs", sum(1 for v in builds if v.get("output_matches") and v.get("run_exit") == 0),
          "declines", [(n, k) for n, row in record["programs"].items() for k, v in row.items() if k != "brainfry" and v["build_exit"]])
    for name in COMPUTE:
        row = record["programs"][name]
        for arm in ("before-O1", "after-O1", "brainfry"):
            if "cycles_user" in row[arm]:
                print(name, arm, "instr", statistics.median(row[arm]["instructions_user"]), "cycles", statistics.median(row[arm]["cycles_user"]), "wall", row[arm]["wall_seconds_median"], "bytes", row[arm]["exe_bytes"])


main()
