"""JVM row R4 comparison (ADR-157): ``jsonmin`` from XAX on HotSpot versus ``javac`` and ``kotlinc`` twins.

The XAX arm is the unchanged ``benchmarks/jsonmin.py`` program built with
``build_jsonmin("jvm")``: the same parser group and entry as on Linux, over the
``jvm-classfile-memory-v1`` linear memory.  The twins (sources below, line for
line ports of ``jsonmin_c/jsonmin.c``) are what a Java or Kotlin programmer would
write: byte arrays, recursive descent, ``System.in``/``System.out``.  The
Kotlin twin is deployed as ``kotlinc -include-runtime`` builds it (its JAR
carries the Kotlin standard library); the Java twin is a one-class JAR.

Every arm is a ``java -jar`` process on the same ``SIZE``-byte document; each
repetition is a fresh JVM (whole-process wall time, so JVM start-up is in every
arm), in interleaved rounds whose arm order rotates by one (as
``linux_harness.py``), after ``WARMUP`` untimed rounds.  Every output must
equal :func:`reference_jsonmin`.  Peak RSS is the maximum ``wait4`` ``ru_maxrss``
over the timed runs.  Ratios follow XAX_BENCHMARKS.md section 15.0 with the JVM
baselines of section 15.0a.  Run ``PYTHONPATH=src:.:.. python -m
benchmarks.bench_jvm_jsonmin [--write]`` from ``compiler/``.
"""

from __future__ import annotations

import json
import os
import shutil
import statistics
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

from benchmarks.bench_jvm_twin import _cpu, _env, _measured_run, _version
from benchmarks.jsonmin import benchmark_document, build_jsonmin, reference_jsonmin
from benchmarks.linux_harness import classify

HERE = Path(__file__).resolve().parent
EVIDENCE = HERE / "jvm_jsonmin_evidence.json"
SIZE = 8 << 20
WARMUP = 2
REPETITIONS = 15

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


KOTLIN_TWIN = r"""
import kotlin.system.exitProcess

const val CAPACITY = 16 shl 20
const val MAX_DEPTH = 512
val input = ByteArray(CAPACITY + 1)
val output = ByteArray(CAPACITY + 1)
var pos = 0
var len = 0
var olen = 0

fun atEnd() = pos >= len
fun copy() { output[olen++] = input[pos++] }
fun at() = input[pos].toInt() and 0xFF
fun ws() { while (pos < len) { val c = at(); if (c == ' '.code || c == '\t'.code || c == '\n'.code || c == '\r'.code) pos++ else break } }
fun optional(c: Int) = pos < len && at() == c
fun isDigit(c: Int) = c >= '0'.code && c <= '9'.code

fun string(): Int {
    copy()
    while (true) {
        if (atEnd()) return 1
        val c = at()
        if (c < 0x20) return 3
        copy()
        if (c == '\\'.code) {
            if (atEnd()) return 1
            val e = at()
            if (e == 'u'.code) {
                copy()
                for (i in 0 until 4) {
                    if (atEnd()) return 1
                    val h = at()
                    if (!(isDigit(h) || (h >= 'a'.code && h <= 'f'.code) || (h >= 'A'.code && h <= 'F'.code))) return 4
                    copy()
                }
            } else if ("\"\\/bfnrt".indexOf(e.toChar()) >= 0) {
                copy()
            } else {
                return 4
            }
        } else if (c == '"'.code) {
            return 0
        }
    }
}

fun digits(): Int {
    var count = 0
    while (pos < len && isDigit(at())) { copy(); count++ }
    return if (count != 0) 0 else 5
}

fun number(): Int {
    if (optional('-'.code)) copy()
    if (atEnd()) return 5
    if (at() == '0'.code) copy() else if (digits() != 0) return 5
    if (optional('.'.code)) { copy(); if (digits() != 0) return 5 }
    if (optional('e'.code) || optional('E'.code)) {
        copy()
        if (optional('+'.code) || optional('-'.code)) copy()
        if (digits() != 0) return 5
    }
    return 0
}

val WORDS = arrayOf("true", "false", "null")

fun literal(): Int {
    for (word in WORDS) {
        if (at() == word[0].code) {
            for (ch in word) {
                if (atEnd()) return 1
                if (at() != ch.code) return 6
                copy()
            }
            return 0
        }
    }
    return 6
}

fun container(depth: Int, closing: Int, keyed: Boolean): Int {
    copy()
    ws()
    if (optional(closing)) { copy(); return 0 }
    while (true) {
        if (keyed) {
            ws()
            if (!optional('"'.code)) return 10
            val status = string()
            if (status != 0) return status
            ws()
            if (!optional(':'.code)) return 11
            copy()
        }
        val status = value(depth)
        if (status != 0) return status
        ws()
        if (optional(','.code)) { copy(); continue }
        if (!optional(closing)) return if (keyed) 12 else 9
        copy()
        return 0
    }
}

fun value(depth: Int): Int {
    if (depth > MAX_DEPTH) return 7
    ws()
    if (atEnd()) return 1
    val c = at()
    if (c == '{'.code) return container(depth + 1, '}'.code, true)
    if (c == '['.code) return container(depth + 1, ']'.code, false)
    if (c == '"'.code) return string()
    if (c == '-'.code || isDigit(c)) return number()
    if (c == 't'.code || c == 'f'.code || c == 'n'.code) return literal()
    return 8
}

fun main() {
    while (true) {
        val n = System.`in`.read(input, len, CAPACITY + 1 - len)
        if (n < 0) break
        len += n
        if (len > CAPACITY) exitProcess(2)
        if (len == CAPACITY + 1) break
    }
    var status = value(0)
    if (status == 0) { ws(); if (pos != len) status = 13 }
    if (status != 0) {
        System.err.print("jsonmin: invalid JSON at byte $pos\n")
        System.err.flush()
        exitProcess(1)
    }
    output[olen++] = '\n'.code.toByte()
    System.out.write(output, 0, olen)
    System.out.flush()
    exitProcess(0)
}
"""


def _run(command: list[str], document: Path, env: dict[str, str]) -> tuple[float, int, tuple[int, bytes, bytes]]:
    """Wall seconds, peak RSS (KiB), and (status, stdout, stderr) of one fresh process."""
    wall, rss, status, stdout, stderr = _measured_run(command, env, document)
    return wall, rss, (status, stdout, stderr)


def _program_class_bytes(jar: Path) -> int:
    """Bytes of the program's own classes: everything but the manifest and a bundled ``kotlin/`` runtime."""
    with zipfile.ZipFile(jar) as archive:
        return sum(item.file_size for item in archive.infolist() if item.filename.endswith(".class") and not item.filename.startswith(("kotlin/", "META-INF/")))


def measure() -> dict:
    from xax_jvm import compile_jvm_bound_target

    tools = {name: shutil.which(name) for name in ("java", "javac", "jar", "kotlinc")}
    if not all(tools.values()):
        raise SystemExit(f"requires {', '.join(name for name, path in tools.items() if not path)}")
    env = _env()
    program = build_jsonmin("jvm")
    image = compile_jvm_bound_target(program.reader, program.entry.cid, program.target, process_entry=True)
    document_bytes = benchmark_document(SIZE, seed=1)
    expected = reference_jsonmin(document_bytes)
    with tempfile.TemporaryDirectory(prefix="xax-jvm-jsonmin-") as directory:
        work = Path(directory)
        document = work / "input.json"
        document.write_bytes(document_bytes)
        jars = {"xax": work / "xax.jar", "javac": work / "javac.jar", "kotlinc": work / "kotlinc.jar"}
        jars["xax"].write_bytes(image.jar)
        (work / "java").mkdir()
        (work / "java" / "Jsonmin.java").write_text(TWIN)
        subprocess.run([tools["javac"], "--release", "17", "-d", str(work / "java"), str(work / "java" / "Jsonmin.java")], check=True, env=env)
        subprocess.run([tools["jar"], "--create", "--file", str(jars["javac"]), "--main-class", "Jsonmin", "-C", str(work / "java"), "Jsonmin.class"], check=True, env=env)
        (work / "Jsonmin.kt").write_text(KOTLIN_TWIN)
        subprocess.run([tools["kotlinc"], str(work / "Jsonmin.kt"), "-include-runtime", "-d", str(jars["kotlinc"])], check=True, env=env, capture_output=True)
        arms = [(name, [tools["java"], "-jar", str(path)]) for name, path in jars.items()]
        samples: dict[str, list[tuple[float, int]]] = {name: [] for name, _command in arms}
        for repetition in range(WARMUP + REPETITIONS):
            shift = repetition % len(arms)
            for name, command in arms[shift:] + arms[:shift]:
                wall, rss, observed = _run(command, document, env)
                if observed != expected:
                    raise AssertionError(f"{name}: output differs from the reference")
                if repetition >= WARMUP:
                    samples[name].append((round(wall, 4), rss))
        sizes = {name: {"jar_bytes": path.stat().st_size, "program_class_bytes": _program_class_bytes(path)} for name, path in jars.items()}

    results = {}
    for name, rows in samples.items():
        times = [wall for wall, _rss in rows]
        results[name] = {
            **sizes[name],
            "wall_seconds_median": statistics.median(times),
            "wall_seconds_min": min(times),
            "wall_seconds_max": max(times),
            "wall_seconds_stdev": round(statistics.stdev(times), 4),
            "wall_seconds_samples": times,
            "peak_rss_kib_max": max(rss for _wall, rss in rows),
        }
    fastest = min(item["wall_seconds_median"] for item in results.values())
    for name, item in results.items():
        item["time_ratio_vs_fastest"] = round(item["wall_seconds_median"] / fastest, 3)
        if name == "xax":
            item["performance_class"] = classify(item["wall_seconds_median"] / fastest)
    xax = results["xax"]
    return {
        "format": "xax-jvm-jsonmin-evidence-v2",
        "decision": "ADR-158",
        "label": "MEASURED",
        "workload": {"name": "jsonmin", "input_bytes": len(document_bytes), "output_bytes": len(expected[1]), "warmup_rounds": WARMUP, "repetitions": REPETITIONS, "fresh_jvm_per_repetition": True, "order": "interleaved, rotating by one per round"},
        "host": {
            "cpu": _cpu(), "logical_cpus": os.cpu_count(), "java": _version(tools["java"]), "javac": _version(tools["javac"]),
            "kotlinc": _version(tools["kotlinc"]), "jvm_flags": "defaults", "javac_flags": "--release 17", "kotlinc_flags": "-include-runtime",
        },
        "results": results,
        "xax_over": {
            name: {
                "wall_median": round(xax["wall_seconds_median"] / results[name]["wall_seconds_median"], 3),
                "program_class_bytes": round(xax["program_class_bytes"] / results[name]["program_class_bytes"], 3),
                "jar_bytes": round(xax["jar_bytes"] / results[name]["jar_bytes"], 3),
                "peak_rss": round(xax["peak_rss_kib_max"] / results[name]["peak_rss_kib_max"], 3),
            }
            for name in ("javac", "kotlinc")
        },
        "notes": "Whole-process wall time of a fresh JVM per run (start-up included in every arm). Outputs equal reference_jsonmin. Baselines are the platform's own compilers (XAX_BENCHMARKS.md section 15.0a).",
    }


if __name__ == "__main__":
    evidence = measure()
    text = json.dumps(evidence, indent=2) + "\n"
    if "--write" in sys.argv:
        EVIDENCE.write_text(text)
    print(json.dumps({name: {key: item[key] for key in ("wall_seconds_median", "time_ratio_vs_fastest", "program_class_bytes", "jar_bytes", "peak_rss_kib_max")} for name, item in evidence["results"].items()}, indent=2))
    print(json.dumps(evidence["xax_over"], indent=2))
