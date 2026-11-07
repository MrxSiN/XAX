"""Measurement driver outside BBC (BBC's AGENT.md, docs/06_PERFORMANCE_PLAN.md there): build and run Brainfuck programs
with bbc.exe under wine and record every sample.  It only runs commands and compares outputs.

Usage: bench.py <bbc.exe> <work directory> <out.json> <trials> <expected.json> <program.b> ...

For each program, level (-O0, -O1) and trial (order shuffled, seeded by the program's name): one `bbc.exe compile
windows-x86_64` (wall seconds) and one run of the result (wall seconds) on the recorded input, whose output's SHA-256 must
be the one <expected.json> records for the program's source SHA-256 (BBC's baseline benchmark record: brainfry's
interpreter).  A failed compile or a mismatch is recorded instead of timed.
"""
import hashlib
import json
import os
import random
import shutil
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from check import run  # noqa: E402


def timed(command, cwd, env, data=b""):
    start = time.perf_counter()
    done = run(command, data, cwd=cwd, env=env, timeout=1800)
    return done, round(time.perf_counter() - start, 4)


def main():
    bbc, work, out, trials = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), Path(sys.argv[3]), int(sys.argv[4])
    work.mkdir(parents=True, exist_ok=True)
    integration = Path(__file__).resolve().parents[4]
    for host in ("bbc-android-arm64.xax", "bbc-windows-x86_64.xax"):
        shutil.copy(integration / host, work / host)
    shutil.copy(bbc, work / "bbc.exe")
    env = {**os.environ, "WINEDEBUG": "-all"}
    known = {item["sha256"]: item for item in json.loads(Path(sys.argv[5]).read_text())["programs"].values()}
    rows = []
    for path in map(Path, sys.argv[6:]):
        source = path.read_bytes()
        reference = known[hashlib.sha256(source).hexdigest()]
        expected_exit, expected, given = reference["interp_exit"], reference["expected_sha256"], reference["stdin"].encode("latin-1")
        plan = [(level, k) for level in ("-O0", "-O1") for k in range(trials)]
        random.Random(path.stem).shuffle(plan)
        samples = {level: {"build_s": [], "run_s": []} for level in ("-O0", "-O1")}
        status = {}
        for level, _k in plan:
            exe = f"{path.stem}{level}.exe"
            built, seconds = timed(["wine", "bbc.exe", "compile", "windows-x86_64", level, exe], work, env, source)
            if built.returncode != 0:
                status[level] = f"compile exit {built.returncode}"
                continue
            samples[level]["build_s"].append(seconds)
            samples[level]["exe_bytes"] = (work / exe).stat().st_size
            ran, seconds = timed(["wine", exe], work, env, given)
            if hashlib.sha256(ran.stdout).hexdigest() != expected or ran.returncode != expected_exit:
                status[level] = f"mismatch (exit {ran.returncode})"
                continue
            samples[level]["run_s"].append(seconds)
        for level, data in samples.items():
            med = lambda xs: sorted(xs)[len(xs) // 2] if xs else None  # noqa: E731
            rows.append({"program": path.stem, "source_sha256": hashlib.sha256(source).hexdigest(), "compiler": f"bbc{level}",
                         "status": status.get(level, "ok"), **data,
                         "build_s_median": med(data["build_s"]), "run_s_median": med(data["run_s"])})
            print(json.dumps({k: v for k, v in rows[-1].items() if not k.endswith("_s")}), flush=True)
    out.write_text(json.dumps({"bbc_exe_sha256": hashlib.sha256(bbc.read_bytes()).hexdigest(), "trials": trials, "rows": rows}, indent=1))


if __name__ == "__main__":
    main()
