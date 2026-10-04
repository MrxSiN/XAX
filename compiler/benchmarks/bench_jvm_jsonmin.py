"""JVM R3 application (ADR-156): ``jsonmin`` from XAX on HotSpot versus a ``javac`` twin.

The XAX arm is the unchanged ``benchmarks/jsonmin.py`` program built with
``build_jsonmin("jvm")``: the same parser group and entry as on Linux, over the
``jvm-classfile-memory-v1`` linear memory.  The Java twin (source below, a line
for line port of ``jsonmin_c/jsonmin.c``) is what a Java programmer would write:
``byte[]`` buffers, recursive descent, ``System.in``/``System.out``.

Both arms process the same ``SIZE``-byte document; each repetition is a fresh
JVM (whole-process wall time, so JVM start-up is included in both), with the arms
interleaved.  Outputs must equal :func:`reference_jsonmin`.  Peak RSS comes from
``wait4``.  Run ``PYTHONPATH=src:.:.. python -m benchmarks.bench_jvm_jsonmin [--write]``
from ``compiler/``.
"""

from __future__ import annotations

import json
import os
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from benchmarks.bench_jvm_twin import _cpu, _env, _version
from benchmarks.jsonmin import benchmark_document, build_jsonmin, reference_jsonmin

HERE = Path(__file__).resolve().parent
EVIDENCE = HERE / "jvm_jsonmin_evidence.json"
SIZE = 8 << 20
REPETITIONS = 7

TWIN = r"""
import java.io.*;

public final class Jsonmin {
  static final int CAPACITY = 16 << 20, MAX_DEPTH = 512;
  static byte[] in = new byte[CAPACITY + 1], out = new byte[CAPACITY + 1];
  static int pos, len, olen;

  static boolean atEnd() { return pos >= len; }
  static void copy() { out[olen++] = in[pos++]; }
  static int at() { return in[pos] & 0xFF; }
  static void ws() { while (pos < len) { int c = at(); if (c == ' ' || c == '\t' || c == '\n' || c == '\r') pos++; else break; } }
  static boolean optional(int c) { return pos < len && at() == c; }
  static boolean isDigit(int c) { return c >= '0' && c <= '9'; }

  static int string() {
    copy();
    for (;;) {
      if (atEnd()) return 1;
      int c = at();
      if (c < 0x20) return 3;
      copy();
      if (c == '\\') {
        if (atEnd()) return 1;
        int e = at();
        if (e == 'u') {
          copy();
          for (int i = 0; i < 4; i++) {
            if (atEnd()) return 1;
            int h = at();
            if (!(isDigit(h) || (h >= 'a' && h <= 'f') || (h >= 'A' && h <= 'F'))) return 4;
            copy();
          }
        } else if ("\"\\/bfnrt".indexOf(e) >= 0) {
          copy();
        } else {
          return 4;
        }
      } else if (c == '"') {
        return 0;
      }
    }
  }

  static int digits() {
    int count = 0;
    while (pos < len && isDigit(at())) { copy(); count++; }
    return count != 0 ? 0 : 5;
  }

  static int number() {
    if (optional('-')) copy();
    if (atEnd()) return 5;
    if (at() == '0') copy(); else if (digits() != 0) return 5;
    if (optional('.')) { copy(); if (digits() != 0) return 5; }
    if (optional('e') || optional('E')) {
      copy();
      if (optional('+') || optional('-')) copy();
      if (digits() != 0) return 5;
    }
    return 0;
  }

  static final String[] WORDS = {"true", "false", "null"};

  static int literal() {
    for (String word : WORDS) {
      if (at() == word.charAt(0)) {
        for (int i = 0; i < word.length(); i++) {
          if (atEnd()) return 1;
          if (at() != word.charAt(i)) return 6;
          copy();
        }
        return 0;
      }
    }
    return 6;
  }

  static int container(int depth, int closing, boolean keyed) {
    copy();
    ws();
    if (optional(closing)) { copy(); return 0; }
    for (;;) {
      if (keyed) {
        ws();
        if (!optional('"')) return 10;
        int status = string();
        if (status != 0) return status;
        ws();
        if (!optional(':')) return 11;
        copy();
      }
      int status = value(depth);
      if (status != 0) return status;
      ws();
      if (optional(',')) { copy(); continue; }
      if (!optional(closing)) return keyed ? 12 : 9;
      copy();
      return 0;
    }
  }

  static int value(int depth) {
    if (depth > MAX_DEPTH) return 7;
    ws();
    if (atEnd()) return 1;
    int c = at();
    if (c == '{') return container(depth + 1, '}', true);
    if (c == '[') return container(depth + 1, ']', false);
    if (c == '"') return string();
    if (c == '-' || isDigit(c)) return number();
    if (c == 't' || c == 'f' || c == 'n') return literal();
    return 8;
  }

  public static void main(String[] args) throws IOException {
    for (;;) {
      int n = System.in.read(in, len, CAPACITY + 1 - len);
      if (n < 0) break;
      len += n;
      if (len > CAPACITY) System.exit(2);
      if (len == CAPACITY + 1) break;
    }
    int status = value(0);
    if (status == 0) { ws(); if (pos != len) status = 13; }
    if (status != 0) {
      System.err.print("jsonmin: invalid JSON at byte " + pos + "\n");
      System.err.flush();
      System.exit(1);
    }
    out[olen++] = '\n';
    System.out.write(out, 0, olen);
    System.out.flush();
    System.exit(0);
  }
}
"""


def _wall(command: list[str], data: bytes, env: dict[str, str]) -> tuple[subprocess.CompletedProcess, float]:
    start = time.perf_counter()
    completed = subprocess.run(command, input=data, capture_output=True, env=env, check=False)
    return completed, time.perf_counter() - start


def _peak_rss_kib(command: list[str], data: bytes, env: dict[str, str]) -> int:
    with tempfile.TemporaryFile() as stdin:
        stdin.write(data)
        stdin.seek(0)
        process = subprocess.Popen(command, stdin=stdin, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env)
        _pid, _status, usage = os.wait4(process.pid, 0)
    return usage.ru_maxrss


def measure() -> dict:
    from xax_jvm import compile_jvm_bound_target

    java, javac = shutil.which("java"), shutil.which("javac")
    if not java or not javac:
        raise SystemExit("requires java and javac")
    env = _env()
    program = build_jsonmin("jvm")
    image = compile_jvm_bound_target(program.reader, program.entry.cid, program.target, process_entry=True)
    document = benchmark_document(SIZE, seed=1)
    expected = reference_jsonmin(document)
    with tempfile.TemporaryDirectory(prefix="xax-jvm-jsonmin-") as directory:
        jar = os.path.join(directory, "xax.jar")
        Path(jar).write_bytes(image.jar)
        Path(directory, "Jsonmin.java").write_text(TWIN)
        subprocess.run([javac, "--release", "17", "-d", directory, os.path.join(directory, "Jsonmin.java")], check=True, env=env)
        twin_class = Path(directory, "Jsonmin.class").read_bytes()
        arms = {"xax": [java, "-jar", jar], "javac": [java, "-cp", directory, "Jsonmin"]}
        samples: dict[str, list[float]] = {name: [] for name in arms}
        for _ in range(REPETITIONS):
            for name, command in arms.items():
                completed, wall = _wall(command, document, env)
                if (completed.returncode, completed.stdout, completed.stderr) != expected:
                    raise AssertionError(f"{name}: output differs from the reference")
                samples[name].append(round(wall, 4))
        peak = {name: _peak_rss_kib(command, document, env) for name, command in arms.items()}

    def summary(values):
        return {"median": statistics.median(values), "min": min(values), "max": max(values), "stdev": round(statistics.pstdev(values), 4), "samples": values}

    return {
        "format": "xax-jvm-jsonmin-evidence-v1",
        "decision": "ADR-156",
        "label": "MEASURED",
        "workload": {"name": "jsonmin", "input_bytes": len(document), "output_bytes": len(expected[1]), "repetitions": REPETITIONS, "fresh_jvm_per_repetition": True},
        "host": {"cpu": _cpu(), "logical_cpus": os.cpu_count(), "java": _version(java), "javac": _version(javac), "jvm_flags": "defaults"},
        "xax": {"class_bytes": len(image.class_bytes), "jar_bytes": len(image.jar), "process_wall_s": summary(samples["xax"]), "peak_rss_kib": peak["xax"]},
        "javac": {"class_bytes": len(twin_class), "process_wall_s": summary(samples["javac"]), "peak_rss_kib": peak["javac"]},
        "ratio_xax_over_javac": {
            "process_wall_median": round(statistics.median(samples["xax"]) / statistics.median(samples["javac"]), 3),
            "class_bytes": round(len(image.class_bytes) / len(twin_class), 3),
            "peak_rss": round(peak["xax"] / peak["javac"], 3),
        },
        "notes": "Whole-process wall time of a fresh JVM per run (start-up included in both arms), interleaved. Outputs equal reference_jsonmin. Not a CPU/native comparison under XAX_BENCHMARKS.md section 15.0: the baseline is the same platform's own compiler.",
    }


if __name__ == "__main__":
    evidence = measure()
    text = json.dumps(evidence, indent=2) + "\n"
    if "--write" in sys.argv:
        EVIDENCE.write_text(text)
    print(json.dumps({key: evidence[key] for key in ("ratio_xax_over_javac",)}, indent=2), evidence["xax"]["process_wall_s"]["median"], evidence["javac"]["process_wall_s"]["median"])
