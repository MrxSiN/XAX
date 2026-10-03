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
4. AI tokens (offline ``tiktoken``; no model is run): the interface view a
   model reads to use the packages (query), and the node rendering it emits
   for the application with package calls versus with the library bodies
   written inline (mutation).  The rendering is the OI-37 measurement view,
   not XAX source.

Run: PYTHONPATH=src:. python -m benchmarks.bench_oi36_stdlib
"""

from __future__ import annotations

import json
import random
import statistics
import time
from pathlib import Path

from benchmarks.uniqcount import build_uniqcount, libraries, reference_uniqcount
from xax_compiler import Operation, _decode_function_interface, _parse_graph, store_resolver, verify_store

OUTPUT = Path(__file__).resolve().parent / "oi36_stdlib_evidence.json"
ENCODINGS = ("cl100k_base", "o200k_base")
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


def _render(function, resolve) -> list:
    graph_object, _parameters, _returns = _decode_function_interface(function, resolve)
    graph = _parse_graph(graph_object, resolve)
    return [[Operation(node.operation).name, [f"{ref.tag}.{ref.block}.{ref.index}.{ref.result}" for ref in node.operands], list(node.attributes)] for block in graph.blocks for node in block.nodes]


def run() -> dict:
    import tiktoken

    from xax_linux import compile_linux_executable, run_linux_executable
    from xax_linux_aarch64 import compile_linux_aarch64_executable, run_linux_aarch64_executable

    tokenizers = {name: tiktoken.get_encoding(name) for name in ENCODINGS}
    count = lambda text: {name: len(encoder.encode(text)) for name, encoder in tokenizers.items()}  # noqa: E731
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
    names = _names(program)
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

    resolve = store_resolver(program.reader)
    entry_nodes = _render(program.entry, resolve)
    used_functions = sorted({cid for cid in stored if cid in names and cid != program.entry.cid}, key=lambda cid: names[cid])
    library_nodes = {names[cid]: _render(resolve(cid), resolve) for cid in used_functions}
    calls = sum(1 for node in entry_nodes if node[0] == "CALL_DIRECT")
    inline_rendering = json.dumps([entry_nodes, *library_nodes.values()], separators=(",", ":"))
    interface = {
        names[cid]: [[item.hex()[:8] for item in parameters], [item.hex()[:8] for item in returns]]
        for cid in used_functions
        for _graph, parameters, returns in [_decode_function_interface(resolve(cid), resolve)]
    }

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
        "evidence_label": {"execution": "EXECUTED", "x86_64": "native", "aarch64": "qemu-aarch64 user mode (emulated)", "sizes_tokens_cost": "MEASURED"},
        "tokenizer": f"tiktoken {tiktoken.__version__}",
        "model_run": None,
        "execution": execution,
        "artifact_bytes": {arch: len(executable.data) for arch, executable in executables.items()},
        "function_code_bytes": {arch: _function_bytes(executable.semantic_ranges, _names(programs[arch])) for arch, executable in executables.items()},
        "packages": packages,
        "package_cids_identical_across_targets": same_cids,
        "app_store": {"objects": len(stored), "bytes": sum(len(item.envelope()) for item in program.reader.objects())},
        "compile_cost": cost,
        "ai_tokens": {
            "query_interface_view": {"functions": len(interface), "tokens": count(json.dumps(interface, separators=(",", ":")))},
            "mutation_with_packages": {"nodes": len(entry_nodes), "library_calls": calls, "tokens": count(json.dumps(entry_nodes, separators=(",", ":")))},
            "mutation_inline_bodies": {"nodes": len(entry_nodes) + sum(len(nodes) for nodes in library_nodes.values()), "tokens": count(inline_rendering)},
            "library_nodes_per_function": {name: len(nodes) for name, nodes in library_nodes.items()},
        },
    }


def main() -> None:
    result = run()
    OUTPUT.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({key: result[key] for key in ("artifact_bytes", "function_code_bytes", "compile_cost", "ai_tokens")}, indent=1))


if __name__ == "__main__":
    main()
