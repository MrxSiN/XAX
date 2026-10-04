"""JVM row measurement (ADR-112): XAX -> class file versus javac on the same HotSpot.

Workload: total Collatz steps for every start value 1..N (u64 arithmetic,
nested loops, a data-dependent branch).  Both programs time only the kernel
with ``System.nanoTime`` and print ``result`` then ``nanoseconds``; JVM startup
is excluded from the kernel time and reported separately as whole-process
wall time.  Each repetition is a fresh JVM; the kernel runs ``WARMUP`` times
before the timed call so both sides are measured after C2 compilation.

The Java twin is the baseline written the way a Java programmer would: a
``long`` loop with ``x & 1`` and ``x >>> 1``.  Its source lives only in this
benchmark; it is not part of any XAX artifact.

Run: ``PYTHONPATH=src python benchmarks/bench_jvm_twin.py [--write]``.
"""

from __future__ import annotations

import json
import os
import platform
import resource
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from xax_compiler import EffectDomain, IntCompare, Operation, bits_type, effect_type, jvm_classfile_target
from xax_graph_builder import GraphBuilder, program_store
from xax_jvm import compile_jvm_bound_target, java_base_api

HERE = Path(__file__).resolve().parent
EVIDENCE = HERE / "jvm_twin_evidence.json"
N = 1_000_000
WARMUP = 5
REPETITIONS = 7

TWIN = """
public final class Twin {
  static long kernel(long n) {
    long acc = 0;
    for (long i = 1; i <= n; i++) {
      long x = i;
      while (x != 1) {
        if ((x & 1) != 0) x = 3 * x + 1; else x >>>= 1;
        acc++;
      }
    }
    return acc;
  }
  public static void main(String[] args) {
    long r = 0;
    for (int w = 0; w < %d; w++) r += kernel(%d);
    long t0 = System.nanoTime();
    long result = kernel(%d);
    long t1 = System.nanoTime();
    System.out.println(result);
    System.out.println(t1 - t0);
    if (r == 42) System.out.println();
  }
}
"""


def collatz_kernel():
    """kernel(n: u64) -> u64: total Collatz steps for 1..n."""
    b1, b64 = bits_type(1), bits_type(64)
    graph = GraphBuilder()
    entry = graph.block(b64)
    outer = graph.block(b64, b64, b64)          # i, acc, n
    inner = graph.block(b64, b64, b64, b64)     # x, acc, i, n
    step = graph.block(b64, b64, b64, b64)
    odd = graph.block(b64, b64, b64, b64)
    even = graph.block(b64, b64, b64, b64)
    following = graph.block(b64, b64, b64)      # i, acc, n
    done = graph.block(b64)
    (n,) = entry.params
    entry.br(outer, entry.const(b64, 1), entry.const(b64, 0), n)
    i, acc, n = outer.params
    outer.cbr(outer.op1(Operation.INT_COMPARE, (i, n), b1, attributes=(IntCompare.ULE,)), inner, (i, acc, i, n), done, (acc,))
    x, acc, i, n = inner.params
    inner.cbr(inner.op1(Operation.INT_COMPARE, (x, inner.const(b64, 1)), b1, attributes=(IntCompare.NE,)), step, (x, acc, i, n), following, (i, acc, n))
    x, acc, i, n = step.params
    low = step.op1(Operation.BIT_AND, (x, step.const(b64, 1)), b64)
    step.cbr(step.op1(Operation.INT_COMPARE, (low, step.const(b64, 0)), b1, attributes=(IntCompare.NE,)), odd, (x, acc, i, n), even, (x, acc, i, n))
    x, acc, i, n = odd.params
    tripled = odd.op1(Operation.ADD_WRAP, (odd.op1(Operation.MUL_WRAP, (x, odd.const(b64, 3)), b64), odd.const(b64, 1)), b64)
    odd.br(inner, tripled, odd.op1(Operation.ADD_WRAP, (acc, odd.const(b64, 1)), b64), i, n)
    x, acc, i, n = even.params
    halved = even.op1(Operation.UDIV, (x, even.const(b64, 2)), b64)
    even.br(inner, halved, even.op1(Operation.ADD_WRAP, (acc, even.const(b64, 1)), b64), i, n)
    i, acc, n = following.params
    following.br(outer, following.op1(Operation.ADD_WRAP, (i, following.const(b64, 1)), b64), acc, n)
    done.ret(done.params[0])
    return graph.function((b64,), (b64,)), graph


def xax_program():
    api = java_base_api()
    time_effect = effect_type(EffectDomain.TIME, 0)
    kernel, kernel_graph = collatz_kernel()
    graph = GraphBuilder()
    block = graph.block(api.io_effect, api.process_effect, time_effect)
    io, process, clock = block.params
    n = block.const(api.b64, N)
    for _ in range(WARMUP):
        block.op1(Operation.CALL_DIRECT, (n,), api.b64, entity=kernel)
    t0, clock = block.op(Operation.CALL_FOREIGN, (clock,), (api.b64, time_effect), entity=api.nano_time)
    result = block.op1(Operation.CALL_DIRECT, (n,), api.b64, entity=kernel)
    t1, clock = block.op(Operation.CALL_FOREIGN, (clock,), (api.b64, time_effect), entity=api.nano_time)
    stream, io = block.op(Operation.CALL_FOREIGN, (io,), (api.print_stream, api.io_effect), entity=api.system_out)
    io = block.op1(Operation.CALL_FOREIGN, (stream, result, io), api.io_effect, entity=api.println_long)
    io = block.op1(Operation.CALL_FOREIGN, (stream, block.op1(Operation.SUB_WRAP, (t1, t0), api.b64), io), api.io_effect, entity=api.println_long)
    block.ret(io, process, clock)
    effects = (api.io_effect, api.process_effect, time_effect)
    entry = graph.function(effects, effects)
    return entry, (*api.types, *kernel_graph.objects.values(), kernel, *graph.objects.values())


def _run(command: list[str], env: dict[str, str]) -> tuple[bytes, float, int]:
    start = time.perf_counter()
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    stdout, stderr = process.communicate()
    wall = time.perf_counter() - start
    if process.returncode:
        raise RuntimeError(stderr.decode())
    return stdout, wall, resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss


# A run is timed by a small runner process: a child's ru_maxrss counts the pages it
# held before exec, so forking a large benchmark process (building ``jsonmin``
# takes ~1 GB of Python heap) directly reports that size instead of the JVM's peak.
_RUNNER = r"""
import os, subprocess, sys, time
stdin, stdout, stderr, *command = sys.argv[1:]
with open(stdin or os.devnull, "rb") as i, open(stdout, "wb") as o, open(stderr, "wb") as e:
    start = time.perf_counter()
    process = subprocess.Popen(command, stdin=i, stdout=o, stderr=e)
    _pid, status, usage = os.wait4(process.pid, 0)
    print(time.perf_counter() - start, usage.ru_maxrss, os.waitstatus_to_exitcode(status))
"""


def _measured_run(command: list[str], env: dict[str, str], stdin: Path | None = None) -> tuple[float, int, int, bytes, bytes]:
    """Wall seconds, peak RSS (KiB), exit status, stdout, and stderr of one fresh process."""
    with tempfile.TemporaryDirectory() as directory:
        stdout, stderr = Path(directory, "stdout"), Path(directory, "stderr")
        report = subprocess.run([sys.executable, "-c", _RUNNER, str(stdin or ""), str(stdout), str(stderr), *command], check=True, capture_output=True, text=True, env=env)
        wall, rss, status = report.stdout.split()
        return float(wall), int(rss), int(status), stdout.read_bytes(), stderr.read_bytes()


def _peak_rss_kib(command: list[str], env: dict[str, str]) -> int:
    """Peak resident set of one run of a fresh JVM."""
    _wall, rss, status, _stdout, _stderr = _measured_run(command, env)
    if status:
        raise RuntimeError(f"exit status {status}")
    return rss


def _version(tool: str) -> str:
    completed = subprocess.run([tool, "-version"], capture_output=True, text=True, env=_env())
    return (completed.stdout + completed.stderr).strip().splitlines()[0]


def _env() -> dict[str, str]:
    return {key: value for key, value in os.environ.items() if key != "JAVA_TOOL_OPTIONS"}


def _cpu() -> str:
    try:
        for line in Path("/proc/cpuinfo").read_text().splitlines():
            if line.startswith("model name"):
                return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return platform.processor()


def measure() -> dict:
    java, javac = shutil.which("java"), shutil.which("javac")
    if not java or not javac:
        raise SystemExit("requires java and javac")
    env = _env()
    target = jvm_classfile_target()
    entry, objects = xax_program()
    reader = program_store(entry, target, objects)
    image = compile_jvm_bound_target(reader, entry.cid, target, process_entry=True)
    with tempfile.TemporaryDirectory(prefix="xax-jvm-twin-") as directory:
        jar = os.path.join(directory, "xax.jar")
        Path(jar).write_bytes(image.jar)
        source = os.path.join(directory, "Twin.java")
        Path(source).write_text(TWIN % (WARMUP, N, N))
        subprocess.run([javac, "-d", directory, source], check=True, env=env)
        twin_class = Path(directory, "Twin.class").read_bytes()
        subprocess.run(["jar", "--create", "--file", os.path.join(directory, "twin.jar"), "--main-class", "Twin", "-C", directory, "Twin.class"], check=True, env=env)
        twin_jar = Path(directory, "twin.jar").read_bytes()
        arms = {"xax": [java, "-jar", jar], "javac": [java, "-cp", directory, "Twin"]}
        samples: dict[str, dict[str, list]] = {name: {"kernel_ns": [], "wall_s": []} for name in arms}
        results = {}
        for _ in range(REPETITIONS):
            for name, command in arms.items():  # interleaved to share host drift
                stdout, wall, _ = _run(command, env)
                result, nanoseconds = (int(line) for line in stdout.split())
                results.setdefault(name, result)
                if results[name] != result:
                    raise AssertionError("nondeterministic result")
                samples[name]["kernel_ns"].append(nanoseconds)
                samples[name]["wall_s"].append(round(wall, 4))
        peak = {name: _peak_rss_kib(command, env) for name, command in arms.items()}
    if results["xax"] != results["javac"]:
        raise AssertionError(f"results differ: {results}")

    def summary(values):
        return {"median": statistics.median(values), "min": min(values), "max": max(values), "stdev": round(statistics.pstdev(values), 4), "samples": values}

    xax_median = statistics.median(samples["xax"]["kernel_ns"])
    javac_median = statistics.median(samples["javac"]["kernel_ns"])
    return {
        "format": "xax-jvm-twin-evidence-v1",
        "label": "MEASURED",
        "workload": {"name": "collatz-total-steps", "n": N, "result": results["xax"], "warmup_kernel_calls": WARMUP, "repetitions": REPETITIONS, "fresh_jvm_per_repetition": True},
        "host": {
            "cpu": _cpu(), "logical_cpus": os.cpu_count(), "os": f"{platform.system()} {platform.release()}",
            "java": _version(java), "javac": _version(javac), "jvm_flags": "defaults",
        },
        "xax": {"class_bytes": len(image.class_bytes), "jar_bytes": len(image.jar), "kernel_ns": summary(samples["xax"]["kernel_ns"]), "process_wall_s": summary(samples["xax"]["wall_s"]), "peak_rss_kib": peak["xax"]},
        "javac": {"class_bytes": len(twin_class), "jar_bytes": len(twin_jar), "kernel_ns": summary(samples["javac"]["kernel_ns"]), "process_wall_s": summary(samples["javac"]["wall_s"]), "peak_rss_kib": peak["javac"]},
        "ratio_xax_over_javac": {
            "kernel_time_median": round(xax_median / javac_median, 3),
            "class_bytes": round(len(image.class_bytes) / len(twin_class), 3),
            "peak_rss": round(peak["xax"] / peak["javac"], 3),
        },
        "notes": "Kernel time excludes JVM startup and is measured after warmup calls in the same JVM; both arms run on the same HotSpot with default flags. The Java twin uses a signed loop compare; the XAX kernel's compares are unsigned (bits are unsigned), lowered as sign-flipped lcmp.",
    }


if __name__ == "__main__":
    evidence = measure()
    text = json.dumps(evidence, indent=2) + "\n"
    if "--write" in sys.argv:
        EVIDENCE.write_text(text)
    print(text)
