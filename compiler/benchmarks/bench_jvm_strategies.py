"""OI-35 on the JVM (ADR-165): direct class-file emission versus native code plus a generated bridge.

Both XAX arms build from the same ``benchmarks/jsonmin.py`` parser group:

* ``direct``: ``build_jsonmin("jvm")`` compiled to one class file
  (``jvm-classfile-memory-v1``, ADR-156/158);
* ``native-bridge``: ``build_jsonmin("jni")`` compiled for x86-64 Linux,
  packaged as a JNI library behind a generated bridge class (``xax_jvm_bridge``).

The ``javac`` twin of ``bench_jvm_jsonmin.py`` is the platform baseline.
Every run is a fresh ``java`` process, in interleaved rounds whose arm order
rotates by one, after ``WARMUP`` untimed rounds.  *Start-up* is the median wall
time on the two-byte document ``[]``; *process time* is the median on the
``SIZE``-byte document; *work* is their difference.  Peak RSS is the maximum
``ru_maxrss`` on the large document.  *Generated adapter* bytes are what the
compiler adds that is not compiled from the program: for ``direct``, the
launcher (``main``, ``run``, ``<init>``), the memory initializer (``<clinit>``), and the memory package members
(``xax$alloc/free/read/write``) as ``method_info`` bytes; for
``native-bridge``, the native entry adapter plus the bridge class.  Every
output must equal :func:`reference_jsonmin`.  Run ``PYTHONPATH=src:.:..
python -m benchmarks.bench_jvm_strategies [--write]`` from ``compiler/``.
"""

from __future__ import annotations

import json
import os
import shutil
import statistics
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

from benchmarks.bench_jvm_jsonmin import TWIN
from benchmarks.bench_jvm_twin import _cpu, _env, _measured_run, _version
from benchmarks.jsonmin import benchmark_document, build_jsonmin, reference_jsonmin

HERE = Path(__file__).resolve().parent
EVIDENCE = HERE / "jvm_strategies_evidence.json"
SIZE = 8 << 20
WARMUP = 2
REPETITIONS = 15
ADAPTER_METHODS = ("main", "run", "<init>", "<clinit>", "xax$alloc", "xax$free", "xax$read", "xax$write")


def method_info_sizes(class_bytes: bytes) -> dict[str, int]:
    """``method_info`` bytes by method name (names are unique in XAX classes)."""
    count = struct.unpack_from(">H", class_bytes, 8)[0]
    position, index, utf8 = 10, 1, {}
    while index < count:
        tag = class_bytes[position]
        if tag == 1:
            length = struct.unpack_from(">H", class_bytes, position + 1)[0]
            utf8[index] = class_bytes[position + 3:position + 3 + length].decode("utf-8", "replace")
            position += 3 + length
        elif tag in (3, 4, 9, 10, 11, 12, 17, 18):
            position += 5
        elif tag in (5, 6):
            position, index = position + 9, index + 1
        elif tag == 15:
            position += 4
        else:  # 7, 8, 16, 19, 20
            position += 3
        index += 1
    position += 6
    position += 2 + 2 * struct.unpack_from(">H", class_bytes, position)[0]

    cursor = position  # fields, then methods: each a u2 count followed by entries
    for table in range(2):
        entries = struct.unpack_from(">H", class_bytes, cursor)[0]
        cursor += 2
        sizes = {}
        for _ in range(entries):
            name = utf8[struct.unpack_from(">H", class_bytes, cursor + 2)[0]]
            end = cursor + 8
            for _attribute in range(struct.unpack_from(">H", class_bytes, cursor + 6)[0]):
                end += 6 + struct.unpack_from(">I", class_bytes, end + 2)[0]
            sizes[name] = end - cursor
            cursor = end
        if table == 1:
            return sizes
    return {}


def measure() -> dict:
    from xax_jvm import compile_jvm_bound_target
    from xax_jvm_bridge import compile_jni_bridge

    tools = {name: shutil.which(name) for name in ("java", "javac", "jar")}
    if not all(tools.values()):
        raise SystemExit(f"requires {', '.join(name for name, path in tools.items() if not path)}")
    env = _env()
    direct_program = build_jsonmin("jvm")
    direct = compile_jvm_bound_target(direct_program.reader, direct_program.entry.cid, direct_program.target, process_entry=True)
    native_program = build_jsonmin("jni")
    bridge = compile_jni_bridge(
        native_program.reader, native_program.entry.cid, native_program.target.cid,
        class_name="xax/Jsonmin", library_name="xaxjsonmin", process_entry=True,
    )
    large, small = benchmark_document(SIZE, seed=1), b"[]"
    expected = {"large": reference_jsonmin(large), "small": reference_jsonmin(small)}
    with tempfile.TemporaryDirectory(prefix="xax-jvm-strategies-") as directory:
        work = Path(directory)
        documents = {"large": work / "large.json", "small": work / "small.json"}
        documents["large"].write_bytes(large)
        documents["small"].write_bytes(small)
        (work / "direct.jar").write_bytes(direct.jar)
        (work / "native").mkdir()
        (work / "native" / "app.jar").write_bytes(bridge.jar)
        (work / "native" / "libxaxjsonmin.so").write_bytes(bridge.library)
        (work / "java").mkdir()
        (work / "java" / "Jsonmin.java").write_text(TWIN)
        subprocess.run([tools["javac"], "--release", "17", "-d", str(work / "java"), str(work / "java" / "Jsonmin.java")], check=True, env=env)
        subprocess.run([tools["jar"], "--create", "--file", str(work / "javac.jar"), "--main-class", "Jsonmin", "-C", str(work / "java"), "Jsonmin.class"], check=True, env=env)
        arms = [
            ("direct", [tools["java"], "-jar", str(work / "direct.jar")]),
            ("native-bridge", [tools["java"], f"-Djava.library.path={work / 'native'}", "-jar", str(work / "native" / "app.jar")]),
            ("javac", [tools["java"], "-jar", str(work / "javac.jar")]),
        ]
        samples = {name: {"large": [], "small": []} for name, _command in arms}
        for repetition in range(WARMUP + REPETITIONS):
            shift = repetition % len(arms)
            for name, command in arms[shift:] + arms[:shift]:
                for kind, path in documents.items():
                    wall, rss, status, stdout, stderr = _measured_run(command, env, path)
                    if (status, stdout, stderr) != expected[kind]:
                        raise AssertionError(f"{name}/{kind}: output differs from the reference")
                    if repetition >= WARMUP:
                        samples[name][kind].append((round(wall, 4), rss))
        artifact = {
            "direct": (work / "direct.jar").stat().st_size,
            "native-bridge": (work / "native" / "app.jar").stat().st_size + len(bridge.library),
            "javac": (work / "javac.jar").stat().st_size,
        }
    direct_methods = method_info_sizes(direct.class_bytes)
    adapters = {
        "direct": sum(size for name, size in direct_methods.items() if name in ADAPTER_METHODS),
        "native-bridge": bridge.generated_adapter_bytes,
        "javac": None,
    }
    results = {}
    for name, kinds in samples.items():
        startup = statistics.median(wall for wall, _rss in kinds["small"])
        process = statistics.median(wall for wall, _rss in kinds["large"])
        results[name] = {
            "startup_seconds_median": startup,
            "process_seconds_median": process,
            "work_seconds": round(process - startup, 4),
            "process_seconds_stdev": round(statistics.stdev(wall for wall, _rss in kinds["large"]), 4),
            "process_seconds_samples": [wall for wall, _rss in kinds["large"]],
            "startup_seconds_samples": [wall for wall, _rss in kinds["small"]],
            "peak_rss_kib_max": max(rss for _wall, rss in kinds["large"]),
            "startup_peak_rss_kib_max": max(rss for _wall, rss in kinds["small"]),
            "artifact_bytes": artifact[name],
            "generated_adapter_bytes": adapters[name],
        }
    results["direct"]["program_class_bytes"] = len(direct.class_bytes)
    results["native-bridge"].update({
        "library_bytes": len(bridge.library), "native_code_bytes": len(bridge.image.code), "native_adapter_bytes": bridge.adapter_bytes,
        "bridge_class_bytes": len(bridge.bridge_class), "bridge_jar_bytes": len(bridge.jar),
    })
    ratio = lambda key: round(results["native-bridge"][key] / results["direct"][key], 3)  # noqa: E731
    return {
        "format": "xax-jvm-strategies-evidence-v1",
        "decision": "ADR-165",
        "label": "MEASURED",
        "question": "OI-35: direct bytecode emission versus native code plus a generated bridge on the JVM",
        "workload": {
            "name": "jsonmin", "large_input_bytes": len(large), "small_input": small.decode(), "warmup_rounds": WARMUP,
            "repetitions": REPETITIONS, "fresh_jvm_per_run": True, "order": "interleaved, rotating by one per round",
        },
        "host": {"cpu": _cpu(), "logical_cpus": os.cpu_count(), "java": _version(tools["java"]), "javac": _version(tools["javac"]), "jvm_flags": "defaults"},
        "results": results,
        "native_bridge_over_direct": {
            "startup": ratio("startup_seconds_median"), "process": ratio("process_seconds_median"), "work": ratio("work_seconds"),
            "peak_rss": ratio("peak_rss_kib_max"), "artifact_bytes": ratio("artifact_bytes"), "generated_adapter_bytes": ratio("generated_adapter_bytes"),
        },
        "notes": "Whole-process wall time of a fresh JVM per run. Outputs equal reference_jsonmin. The native arm is x86-64 Linux only and is deployed as a JAR plus a .so on java.library.path.",
    }


if __name__ == "__main__":
    evidence = measure()
    text = json.dumps(evidence, indent=2) + "\n"
    if "--write" in sys.argv:
        EVIDENCE.write_text(text)
    print(json.dumps({name: {key: value for key, value in item.items() if not key.endswith("samples")} for name, item in evidence["results"].items()}, indent=2))
    print(json.dumps(evidence["native_bridge_over_direct"], indent=2))
