"""Measurement driver outside BBC (BBC's AGENTS.md, docs/06_PERFORMANCE_PLAN.md there): build and run Brainfuck programs
with one or more bbc.exe arms under wine and record every sample.  It only runs commands and compares outputs.

Usage: bench.py <arm>[,<arm>...] <work directory> <out.json> <trials> <expected.json> <program.b> ...
       where <arm> is <name>=<bbc.exe> (a bare path is the arm "bbc").

For each program, every (arm, level, trial) in one shuffled order (seeded by the program's name), so arms alternate:
one `bbc.exe compile windows-x86_64` (wall seconds) and one run of the result (wall seconds) on the recorded input,
whose output's SHA-256 must be the one <expected.json> records for the program's source SHA-256 (BBC's baseline
benchmark record: brainfry's interpreter).  A failed compile or a mismatch is recorded instead of timed.  Each arm
runs in its own directory beside its own copy of the host stores.
"""
import hashlib
import json
import os
import random
import shutil
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from check import run  # noqa: E402

LEVELS = ("-O0", "-O1")


def timed(command, cwd, env, data=b""):
    start = time.perf_counter()
    done = run(command, data, cwd=cwd, env=env, timeout=1800)
    return done, round(time.perf_counter() - start, 4)


def arms(spec):
    named = (item.split("=", 1) if "=" in item else ("bbc", item) for item in spec.split(","))
    return {name: Path(path).resolve() for name, path in named}


def median(xs):
    return sorted(xs)[len(xs) // 2] if xs else None


def main():
    exes, work, out, trials = arms(sys.argv[1]), Path(sys.argv[2]).resolve(), Path(sys.argv[3]), int(sys.argv[4])
    integration = Path(__file__).resolve().parents[4]
    for name, exe in exes.items():
        (work / name).mkdir(parents=True, exist_ok=True)
        for host in ("bbc-android-arm64.xax", "bbc-windows-x86_64.xax"):
            shutil.copy(integration / host, work / name / host)
        shutil.copy(exe, work / name / "bbc.exe")
    env = {**os.environ, "WINEDEBUG": "-all"}
    known = {item["sha256"]: item for item in json.loads(Path(sys.argv[5]).read_text())["programs"].values()}
    rows = []
    for path in map(Path, sys.argv[6:]):
        source = path.read_bytes()
        reference = known[hashlib.sha256(source).hexdigest()]
        expected_exit, expected, given = reference["interp_exit"], reference["expected_sha256"], reference["stdin"].encode("latin-1")
        plan = [(name, level, k) for name in exes for level in LEVELS for k in range(trials)]
        random.Random(path.stem).shuffle(plan)
        samples = {(name, level): {"build_s": [], "run_s": []} for name in exes for level in LEVELS}
        status = {}
        for name, level, _k in plan:
            here, exe = work / name, f"{path.stem}{level}.exe"
            built, seconds = timed(["wine", "bbc.exe", "compile", "windows-x86_64", level, exe], here, env, source)
            if built.returncode != 0:
                status[name, level] = f"compile exit {built.returncode}"
                continue
            samples[name, level]["build_s"].append(seconds)
            samples[name, level]["exe_bytes"] = (here / exe).stat().st_size
            samples[name, level]["exe_sha256"] = hashlib.sha256((here / exe).read_bytes()).hexdigest()
            ran, seconds = timed(["wine", exe], here, env, given)
            if hashlib.sha256(ran.stdout).hexdigest() != expected or ran.returncode != expected_exit:
                status[name, level] = f"mismatch (exit {ran.returncode})"
                continue
            samples[name, level]["run_s"].append(seconds)
        for (name, level), data in samples.items():
            rows.append({"program": path.stem, "source_sha256": hashlib.sha256(source).hexdigest(), "arm": name, "compiler": f"bbc{level}",
                         "status": status.get((name, level), "ok"), **data,
                         "build_s_median": median(data["build_s"]), "run_s_median": median(data["run_s"])})
            print(json.dumps({k: v for k, v in rows[-1].items() if not k.endswith("_s")}), flush=True)
    record = {"arms": {name: {"bbc_exe_sha256": hashlib.sha256(exe.read_bytes()).hexdigest(), "bytes": exe.stat().st_size}
                       for name, exe in exes.items()}, "trials": trials, "rows": rows}
    out.write_text(json.dumps(record, indent=1))


if __name__ == "__main__":
    main()
