"""OI-36 evidence: two standard semantic library families used by an executed app.

Measures, for ``uniqcount`` (:mod:`benchmarks.uniqcount`) over the packages of
:mod:`xax_stdlib` (ADR-130):

1. execution on Linux x86-64 (native) and Linux AArch64 (qemu-aarch64) against
   :func:`reference_uniqcount`;
2. code contribution per used library function, from each artifact's
   semantic map (the extent of the function's mapped bytes), and the
   canonical store bytes each package contributes; unused exports are absent
   from the store and the artifact;
3. compile cost: package construction, store verification, and lowering
   (medians on this host);
Run: PYTHONPATH=src:. python -m benchmarks.bench_oi36_stdlib
"""

from __future__ import annotations

import json
import random
import statistics
import time
from pathlib import Path

from benchmarks.uniqcount import build_uniqcount, libraries, reference_uniqcount
from xax_compiler import verify_store

OUTPUT = Path(__file__).resolve().parent / "oi36_stdlib_evidence.json"
REPEATS = 5


def _median(action, repeats: int = REPEATS) -> float:
    samples = []
    for _ in range(repeats):
        start = time.perf_counter()
        action()
        samples.append(time.perf_counter() - start)
    return statistics.median(samples)


def corpus() -> dict[str, bytes]:
    rng = random.Random(36)
    return {
        "empty": b"",
        "mixed": b"a0b0c18446744073709551616 x 5,5;007 7\n",
        "random_20000": " ".join(str(rng.randrange(10 ** rng.randrange(1, 22))) for _ in range(20000)).encode(),
        "table_full": b" ".join(b"%d" % index for index in range(1, (1 << 16) + 2)),
    }


def _names(program) -> dict[bytes, str]:
    names = {program.entry.cid: "uniqcount.entry"}
    for library in program.libraries:
        suffix = "[extent=%d]" % library.parameters["extent"] if "extent" in library.parameters else ""
        for name, function in library.functions.items():
            names.setdefault(function.cid, f"{library.name}.{name}{suffix}")
    return names


def _function_bytes(ranges, names) -> dict[str, int]:
    spans: dict[bytes, list[int]] = {}
    for item in ranges:
        if item.function_cid in names:
            low, high = spans.setdefault(item.function_cid, [item.start, item.end])
            spans[item.function_cid] = [min(low, item.start), max(high, item.end)]
    return {names[cid]: high - low for cid, (low, high) in sorted(spans.items(), key=lambda pair: names[pair[0]])}


def run() -> dict:
    from xax_linux import compile_linux_executable, run_linux_executable
    from xax_linux_aarch64 import compile_linux_aarch64_executable, run_linux_aarch64_executable

    programs = {"x86_64": build_uniqcount("x86_64"), "aarch64": build_uniqcount("aarch64")}
    compilers = {
        "x86_64": lambda p: compile_linux_executable(p.reader, p.entry.cid, p.target.cid),
        "aarch64": lambda p: compile_linux_aarch64_executable(p.reader, p.entry.cid, p.target.cid),
    }
    runners = {"x86_64": run_linux_executable, "aarch64": run_linux_aarch64_executable}
    executables = {arch: compilers[arch](program) for arch, program in programs.items()}

    execution = {}
    for name, data in corpus().items():
        expected = reference_uniqcount(data)
        row = {"input_bytes": len(data), "expected": [expected[0], expected[1].decode()]}
        for arch, executable in executables.items():
            completed = runners[arch](executable.data, stdin=data)
            row[arch] = [completed.returncode, completed.stdout.decode()]
            if (completed.returncode, completed.stdout) != expected:
                raise AssertionError(f"{arch} {name}: {row[arch]} != {expected}")
        execution[name] = row

    program = programs["x86_64"]
    stored = {item.cid for item in program.reader.objects()}
    packages = {}
    for library in program.libraries:
        key = f"{library.name}{json.dumps(library.parameters, sort_keys=True, separators=(',', ':'))}"
        used = sorted(name for name, function in library.functions.items() if function.cid in stored)
        package_objects = [item for item in library.objects if item.cid in stored]
        packages[key] = {
            "manifest": library.manifest(),
            "exports": sorted(library.functions),
            "used_exports": used,
            "store_objects_contributed": len(package_objects),
            "store_bytes_contributed": sum(len(item.envelope()) for item in package_objects),
            "package_object_in_app_store": library.package.cid in stored,
        }
    same_cids = all(a.package.cid == b.package.cid for a, b in zip(programs["x86_64"].libraries, programs["aarch64"].libraries))

    cost = {
        "build_packages_ms": round(_median(libraries) * 1e3, 2),
        "build_program_ms": round(_median(build_uniqcount) * 1e3, 2),
        "verify_store_ms": round(_median(lambda: verify_store(program.reader)) * 1e3, 2),
        "compile_ms": {arch: round(_median(lambda arch=arch: compilers[arch](programs[arch])) * 1e3, 2) for arch in programs},
        "repeats": REPEATS,
    }
    return {
        "issue": "OI-36",
        "adr": "ADR-130",
        "evidence_label": {"execution": "EXECUTED", "x86_64": "native", "aarch64": "qemu-aarch64 user mode (emulated)", "sizes_cost": "MEASURED"},
        "execution": execution,
        "artifact_bytes": {arch: len(executable.data) for arch, executable in executables.items()},
        "function_code_bytes": {arch: _function_bytes(executable.semantic_ranges, _names(programs[arch])) for arch, executable in executables.items()},
        "packages": packages,
        "package_cids_identical_across_targets": same_cids,
        "app_store": {"objects": len(stored), "bytes": sum(len(item.envelope()) for item in program.reader.objects())},
        "compile_cost": cost,
    }


def main() -> None:
    result = run()
    OUTPUT.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({key: result[key] for key in ("artifact_bytes", "function_code_bytes", "compile_cost")}, indent=1))


if __name__ == "__main__":
    main()
