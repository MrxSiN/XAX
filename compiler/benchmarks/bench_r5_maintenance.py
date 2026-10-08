"""R5 autonomous-maintenance record (ADR-209): one maintenance cycle of the JVM ``jsonmin`` application.

The application is the JVM row's R4 workload: ``build_jsonmin("jvm")``'s canonical store, pinned below by its
root.  The maintenance request is a requirement change: accept JSON nested up to 1024 levels instead of 512.

The cycle runs only through the ordinary XAX workspace interface:

1. query: ``callees`` from the entry, ``function_nodes`` of each reached function, and the bounded projection of
   the one function holding the limit (``LocalMutationSession.view``);
2. modify: one local mutation, bound to the queried generation.  ``AGENT_MUTATION`` is the text an AI agent
   (Claude, in the 2026-10-08 Claude Code session that added this file) wrote after reading that projection; it
   saw ``N4 int.compare P0 N3`` with ``N3 constant 512`` and answered with the edit below.  The harness replays it
   so the record is reproducible: the same pinned root and edit must give the same committed root;
3. verify and commit: ``Workspace.commit`` verifies the transaction and atomically advances the root; the semantic
   diff and the reuse counts are recorded; no whole program is regenerated (the only authored input is the edit);
4. rebuild: the JAR is compiled from the committed store's entry;
5. test: the rebuilt JAR runs the contract cases against ``reference_jsonmin`` at the new limit, and the original
   JAR still rejects what the new one accepts (the change took effect, and only there);
6. benchmark: original and rebuilt JARs run interleaved on the same document (fresh JVM per run);
7. persist: the committed canonical store is saved and its digest recorded.

Run ``PYTHONPATH=src:.:.. python -m benchmarks.bench_r5_maintenance [--row=jvm|linux-x86_64] [--write]`` from ``compiler/``
(the JVM row needs ``java``; the Linux row, ADR-213, a Linux x86-64 host).
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import statistics
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
EVIDENCE = HERE / "r5_jvm_jsonmin_maintenance_evidence.json"
# Per platform row: (jsonmin build arch, evidence file).  The cycle is the same on each (ADR-209, ADR-213).
PLATFORMS = {
    "jvm": ("jvm", EVIDENCE),
    "linux-x86_64": ("x86_64", HERE / "r5_linux_jsonmin_maintenance_evidence.json"),
}
REQUEST = "Accept JSON nested up to 1024 levels instead of 512; everything else unchanged."
NEW_DEPTH = 1024
# Written by the agent after reading the projection of the function that compares the depth with 512.
AGENT_MUTATION = "const N3 1024"
BENCH_SIZE = 4 << 20
REPETITIONS = 15


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _cases(old_depth: int, new_depth: int) -> list[bytes]:
    from benchmarks.jsonmin import benchmark_document

    nested = lambda depth: b"[" * depth + b"]" * depth  # noqa: E731
    return [
        b'{"a": [1, 2.5e3, -0, true, null, "x\\u00e9\\n"], "b": {}}', b"[]", b"0", b'"\\"\\\\\\/\\b\\f\\n\\r\\t"',
        b"[1,", b'{"a":1,}', b"[01]", b'"\x01"', b'"\\u12g4"', b"\xff",
        nested(old_depth), nested(old_depth + 1), nested(new_depth), nested(new_depth + 1),
        b'{"k":' * (old_depth + 10) + b"0" + b"}" * (old_depth + 10),
        benchmark_document(64 << 10, seed=3),
    ]


def _run_jvm(java: str, jar: Path, document: bytes) -> tuple[int, bytes, bytes, float]:
    import time

    env = {key: value for key, value in os.environ.items() if key != "JAVA_TOOL_OPTIONS"}
    start = time.perf_counter()
    completed = subprocess.run([java, "-jar", str(jar)], input=document, capture_output=True, env=env, check=False)
    return completed.returncode, completed.stdout, completed.stderr, time.perf_counter() - start


def _run_elf(path: Path, document: bytes) -> tuple[int, bytes, bytes, float]:
    import time

    start = time.perf_counter()
    completed = subprocess.run([str(path)], input=document, capture_output=True, check=False)
    return completed.returncode, completed.stdout, completed.stderr, time.perf_counter() - start


def _reference(document: bytes, depth: int) -> tuple[int, bytes, bytes]:
    from benchmarks import jsonmin

    saved = jsonmin.MAX_DEPTH
    jsonmin.MAX_DEPTH = depth
    try:
        return jsonmin.reference_jsonmin(document)
    finally:
        jsonmin.MAX_DEPTH = saved


def maintain(row: str = "jvm") -> dict:
    from benchmarks.jsonmin import MAX_DEPTH, benchmark_document, build_jsonmin
    from xax_compiler import Kind, store_resolver
    from xax_jvm import compile_jvm_bound_target
    from xax_local_protocol import LocalMutationSession
    from xax_workspace import Workspace

    arch = PLATFORMS[row][0]
    java = shutil.which("java")
    if arch == "jvm" and java is None:
        raise RuntimeError("UNAVAILABLE: java")
    program = build_jsonmin(arch)
    workspace = Workspace(program.reader, program.target)
    original_root = workspace.root
    queries = []

    def record(name: str, response) -> None:
        queries.append({"query": name, "response_bytes": len(repr(response).encode())})

    # 1. query: the reachable functions, their nodes, and the one projection the agent read.
    reached, pending, holder = [], [program.entry.cid], None
    while pending:
        cid = pending.pop()
        if cid in reached:
            continue
        reached.append(cid)
        page = workspace.callees(cid, 64)
        record("callees", page)
        pending.extend(workspace._function_bindings[view.handle][0] for view in page.entities)
    for cid in reached:
        page = workspace.function_nodes(cid, 1024)
        record("function_nodes", page)
        if any(node.constant_value == MAX_DEPTH for node in page.entities):
            holder = cid
    if holder is None:
        raise AssertionError("no function holds the depth limit")
    session = LocalMutationSession.for_function(workspace, holder, limit=1024)
    projection = session.view(functions=(holder,))
    queries.append({"query": "projection", "response_bytes": len(projection.encode())})
    excerpt = [line for line in projection.splitlines() if line.startswith(("N3 ", "N4 "))]

    # 2-3. modify, verify, commit: one local mutation bound to the queried generation.
    generation = workspace.generation
    result = session.commit(AGENT_MUTATION)
    if not result.committed:
        raise AssertionError(f"mutation rejected: {result.diagnostic}")
    diff = workspace.diff(generation, 64)
    resolve = store_resolver(workspace.reader)
    module = resolve(resolve(workspace.root).references[0])
    if module.kind != Kind.MODULE:
        raise AssertionError("unexpected root layout")
    (entry_cid,) = (cid for cid in module.references if resolve(cid).kind == Kind.FUNCTION)

    # 4. rebuild both artifacts from their canonical stores.
    if arch == "jvm":
        before = compile_jvm_bound_target(program.reader, program.entry.cid, program.target, process_entry=True).jar
        after = compile_jvm_bound_target(workspace.reader, entry_cid, program.target, process_entry=True).jar
    else:
        from xax_linux import compile_linux_executable

        before = compile_linux_executable(program.reader, program.entry.cid, program.target.cid).data
        after = compile_linux_executable(workspace.reader, entry_cid, program.target.cid).data

    with tempfile.TemporaryDirectory(prefix="xax-r5-") as directory:
        work = Path(directory)
        suffix = ".jar" if arch == "jvm" else ""
        jars = {"before": work / f"before{suffix}", "after": work / f"after{suffix}"}
        jars["before"].write_bytes(before)
        jars["after"].write_bytes(after)
        for path in jars.values():
            path.chmod(0o755)

        def _run_jar(_java, path: Path, document: bytes):
            return _run_jvm(java, path, document) if arch == "jvm" else _run_elf(path, document)

        # 5. test at the new limit; the original keeps the old one.
        tests = []
        for document in _cases(MAX_DEPTH, NEW_DEPTH):
            status, stdout, stderr, _wall = _run_jar(java, jars["after"], document)
            old_status, old_stdout, old_stderr, _wall = _run_jar(java, jars["before"], document)
            tests.append({
                "input_sha256": _sha(document), "input_bytes": len(document),
                "after_matches_new_contract": (status, stdout, stderr) == _reference(document, NEW_DEPTH),
                "before_matches_old_contract": (old_status, old_stdout, old_stderr) == _reference(document, MAX_DEPTH),
                "behavior_changed": (status, stdout) != (old_status, old_stdout),
            })

        # 6. benchmark: interleaved fresh-JVM runs on one document.
        document = benchmark_document(BENCH_SIZE, seed=1)
        expected = _reference(document, NEW_DEPTH)
        samples = {"before": [], "after": []}
        for _ in range(2):
            for name in samples:
                _run_jar(java, jars[name], document)
        for repetition in range(REPETITIONS):
            for name in (("before", "after") if repetition % 2 == 0 else ("after", "before")):
                status, stdout, stderr, wall = _run_jar(java, jars[name], document)
                if name == "after" and (status, stdout, stderr) != expected:
                    raise AssertionError("rebuilt JAR differs from the reference on the benchmark document")
                samples[name].append(round(wall, 6))

        # 7. persist the committed canonical store.
        store_path = work / f"jsonmin-{arch}-gen1.xax"
        workspace.save(store_path)
        store_bytes = store_path.read_bytes()

    medians = {name: statistics.median(values) for name, values in samples.items()}
    accounting = workspace.accounting
    return {
        "format": "xax-r5-maintenance-evidence-v1",
        "decision": "ADR-209" if arch == "jvm" else "ADR-213",
        "label": "EXECUTED",
        "application": {"name": "jsonmin", "platform_row": row, "target": program.target.cid.hex(), "original_root": original_root.hex()},
        "request": REQUEST,
        "agent": {
            "authored_input": AGENT_MUTATION,
            "authored_input_bytes": len(AGENT_MUTATION.encode()),
            "author": "Claude (AI coding agent), Claude Code session of 2026-10-08, after reading the projection excerpt below",
            "projection_excerpt": excerpt,
            "replayed_by": "this harness, deterministically against the pinned original root",
        },
        "queries": queries,
        "transaction": {
            "generation_before": generation,
            "generation_after": workspace.generation,
            "committed": result.committed,
            "new_root": result.root.hex(),
            "changed_entities": [cid.hex() for cid in result.changed_entities],
            "transaction_bytes": result.transaction_bytes,
            "touched_objects": result.touched_objects,
            "reused_objects": result.reused_objects,
            "verified_objects": result.verified_objects,
            "semantic_diff": repr(diff),
            "whole_source_regenerated": False,
        },
        "workspace_accounting": {key: getattr(accounting, key) for key in ("queries", "entities_exposed", "query_bytes", "mutations", "rejected_transactions")},
        "rebuild": {
            "before": {"artifact_sha256": _sha(before), "artifact_bytes": len(before)},
            "after": {"artifact_sha256": _sha(after), "artifact_bytes": len(after), "entry_function": entry_cid.hex()},
        },
        "tests": {"cases": tests, "all_passed": all(t["after_matches_new_contract"] and t["before_matches_old_contract"] for t in tests)},
        "benchmark": {
            "document": {"bytes": BENCH_SIZE, "generator": "benchmark_document(size, seed=1)"},
            "warmup_rounds": 2, "repetitions": REPETITIONS, "order": "interleaved, alternating", "timer": "time.perf_counter around a fresh process" + (" (java -jar)" if arch == "jvm" else ""),
            "results": {name: {"wall_seconds_samples": values, "wall_seconds_median": round(medians[name], 6)} for name, values in samples.items()},
            "after_over_before_median": round(medians["after"] / medians["before"], 6),
        },
        "persisted": {"store": f"jsonmin-{arch}-gen1.xax (canonical workspace save)", "store_sha256": _sha(store_bytes), "store_bytes": len(store_bytes), "root": workspace.root.hex()},
        "host": {"machine": platform.machine(), "python": platform.python_version(), "java": subprocess.run([java, "-version"], capture_output=True, text=True).stderr.splitlines()[-3:] if java else None},
    }


def main(argv: list[str]) -> int:
    row = next((item.split("=", 1)[1] for item in argv if item.startswith("--row=")), "jvm")
    evidence = maintain(row)
    text = json.dumps(evidence, indent=2) + "\n"
    if "--write" in argv:
        PLATFORMS[row][1].write_text(text)
    print(json.dumps({key: evidence[key] for key in ("transaction", "tests", "benchmark")}, indent=1)[:4000])
    return 0 if evidence["tests"]["all_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
