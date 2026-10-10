"""R5 autonomous-maintenance record for the Android row (ADR-255): one maintenance cycle of the counter app.

The application is the Android row's R3/R4 workload, ``android_counter_activity.apk`` (ADR-111): its two JNI
methods are ordinary XAX functions in one canonical store (``xax_android_counter.counter_store``).  The
maintenance request is a requirement change: the button shows at most four digits, so a tap never raises the
count past 9999 (a stored count above 9999, from an older version, stays as it is).

Unlike the JVM and Linux records (ADR-209, ADR-213: one constant), this change is structural.  The agent read
``onClick``'s projection (``N8 load.bits.le``, ``N9 constant 1``, ``N10 add.wrap N8 N9``) and wrote two
transactions through the ordinary workspace interface:

1. insert ``constant 9999``, ``int.compare ult N8 9999`` (a new ``bits<1>``), and its ``int.zero_extend`` to
   ``bits<64>`` ahead of the add (one insertion per anchor);
2. at the next generation, make the add read the extended compare instead of ``constant 1``, so a click adds
   ``count < 9999 ? 1 : 0``;
3. at the next, delete that constant, now unused (a deletion is checked against the uses its generation has).

Each transaction is bound to the queried generation, verified, and committed; the harness replays the agent's
transactions against the pinned store, so the record is reproducible.  Then:

3. rebuild the native library from the committed store and the APK around it (same DEX, manifest, signing);
4. test on the connected arm64 device: the library under ``integration/android/counter_native_loader.c`` from
   counts 0, 9997, and 20000 (the old library from 9997 shows that the change took effect, and only there), and
   the rebuilt APK under the device oracle ``integration/android/validate_counter_apk.sh``;
5. benchmark: cold starts of the original and rebuilt APKs (one package, so the arms alternate in fresh-install
   blocks whose order rotates);
6. persist: the committed canonical store is saved and its digest recorded.

Run ``python -m benchmarks.bench_r5_android_counter [--write]`` from ``compiler/`` with one arm64 device on ``adb``
(``ANDROID_SERIAL`` selects one of several) and ``ANDROID_NDK_HOME`` set.
"""

from __future__ import annotations

import hashlib
import json
import os
import statistics
import subprocess
import sys
import tempfile
from pathlib import Path

from benchmarks import android_counter_app as app
from benchmarks import bench_android_counter_twin as twin
from benchmarks.bench_android_ndk_twin import _llvm
from xax_replacement import faster_p_value

HERE = Path(__file__).resolve().parent
EVIDENCE = HERE / "r5_android_counter_maintenance_evidence.json"
LOADER = HERE.parent / "integration/android/counter_native_loader.c"
REMOTE = "/data/local/tmp/xax-r5-counter"
REQUEST = "The button shows at most four digits: a tap never raises the count past 9999; a stored count above 9999 stays as it is."
CAP = 9999
AGENT_TRANSACTIONS = (
    "T1 @R0: insert-before F.N8 #0 constant bits<64> 9999; insert-before F.N9 #1 int.compare.ult N8 #0 -> bits<1>; "
    "insert-before F.N10 #2 int.zero_extend #1 -> bits<64>",
    "T2 @R1: replace-operand ADD 1 (was the constant 1) <- the zero_extend",
    "T3 @R2: delete the constant 1, now unused",
)
BLOCKS, RUNS = int(os.environ.get("XAX_R5_BLOCKS", 6)), int(os.environ.get("XAX_R5_RUNS", 10))


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _expected(initial: int | None, capped: bool) -> str:
    """The loader's line for: create, three clicks, restart (create), one click."""
    count, seen = initial or 0, []
    seen.append(count)
    for _ in range(3):
        count = count + 1 if not capped or count < CAP else count
        seen.append(count)
    seen.append(count)
    count = count + 1 if not capped or count < CAP else count
    seen.append(count)
    return f"XAX_COUNTER seen={','.join(map(str, seen))} file_bytes=8 stored={count} fds_closed=1"


def edit_store() -> dict:
    """Steps 1-2 on the host: the queries and the agent's three transactions, replayed against the pinned store."""
    from xax_android_counter import counter_activity_semantics, counter_store, decode_counter_activity
    from xax_compiler import IntCompare, Operation, ValueRef
    from xax_local_protocol import LocalMutationSession
    from xax_workspace import DeleteNode, InsertPureNode, ReplaceUse, RootRef, Transaction, TransactionValueRef, Workspace

    description = decode_counter_activity(counter_activity_semantics(**app.SEMANTICS))
    reader, target_object, on_create, on_click = counter_store(description)
    workspace = Workspace(reader, target_object)
    original_root = workspace.root
    queries = []

    def record(name: str, response) -> None:
        queries.append({"query": name, "response_bytes": len(repr(response).encode())})

    def nodes(function: bytes):
        page = workspace.function_nodes(function, 1024)
        record("function_nodes", page)
        return page.entities

    # 1. query: both methods' nodes; the one with an add is the click; its projection is what the agent read.
    holder = next(cid for cid in (on_create, on_click) if any(view.operation == Operation.ADD_WRAP for view in nodes(cid)))
    projection = LocalMutationSession.for_function(workspace, holder, limit=1024).view(functions=(holder,))
    queries.append({"query": "projection", "response_bytes": len(projection.encode())})
    views = nodes(holder)
    add = next(index for index, view in enumerate(views) if view.operation == Operation.ADD_WRAP)
    load, one = add - 2, add - 1  # N8 load.bits.le, N9 constant 1, N10 add.wrap N8 N9
    if views[load].operation != Operation.LOAD_BITS_LE or views[one].constant_value != 1:
        raise AssertionError("the click no longer has the shape the agent read")
    excerpt = [line for line in projection.splitlines() if line.startswith((f"N{load} ", f"N{one} ", f"N{add} "))]

    # 2. modify, verify, commit: two transactions, each bound to the generation it was written against.
    value = lambda index: ValueRef.node_result(0, index)  # noqa: E731
    first = workspace.commit(Transaction(RootRef(workspace.generation), (
        InsertPureNode(views[load].handle, 0, load, 0, Operation.CONSTANT, (), "bits<64>", CAP),
        InsertPureNode(views[one].handle, 0, one, 1, Operation.INT_COMPARE, (value(load), TransactionValueRef(0)), "bits<1>", attributes=(int(IntCompare.ULT),)),
        InsertPureNode(views[add].handle, 0, add, 2, Operation.INT_ZERO_EXTEND, (TransactionValueRef(1),), "bits<64>"),
    )))
    if not first.committed:
        raise AssertionError(f"transaction 1 rejected: {first.diagnostic}")
    clicked = next(cid for cid in first.changed_entities if cid != on_create)
    views = nodes(clicked)
    add = next(index for index, view in enumerate(views) if view.operation == Operation.ADD_WRAP)
    extend = next(index for index, view in enumerate(views) if view.operation == Operation.INT_ZERO_EXTEND)
    one = next(index for index, view in enumerate(views) if view.operation == Operation.CONSTANT and view.constant_value == 1 and index < add)
    second = workspace.commit(Transaction(RootRef(workspace.generation), (ReplaceUse(views[add].handle, 1, value(one), value(extend)),)))
    if not second.committed:
        raise AssertionError(f"transaction 2 rejected: {second.diagnostic}")
    clicked = next(cid for cid in second.changed_entities if cid != on_create)
    views = nodes(clicked)  # a node is deleted only once nothing uses it: the next generation
    one = next(index for index, view in enumerate(views) if view.operation == Operation.CONSTANT and view.constant_value == 1)
    third = workspace.commit(Transaction(RootRef(workspace.generation), (DeleteNode(views[one].handle, 0, one),)))
    if not third.committed:
        raise AssertionError(f"transaction 3 rejected: {third.diagnostic}")
    clicked = next(cid for cid in third.changed_entities if cid != on_create)
    return {
        "description": description, "reader": reader, "target": target_object, "on_create": on_create, "on_click": on_click,
        "workspace": workspace, "original_root": original_root, "queries": queries, "excerpt": excerpt,
        "results": (first, second, third), "clicked": clicked, "diff": workspace.diff(0, 64),
    }


def maintain() -> dict:
    from xax_android_counter import compile_counter_library

    edited = edit_store()
    description, reader, target_object = edited["description"], edited["reader"], edited["target"]
    on_create, on_click, clicked, workspace = edited["on_create"], edited["on_click"], edited["clicked"], edited["workspace"]
    first, second, third = edited["results"]
    original_root, queries, excerpt, diff = edited["original_root"], edited["queries"], edited["excerpt"], edited["diff"]


    # 3. rebuild: the library from the committed store, the APK around it.
    soname = f"lib{app.NATIVE_LIBRARY}.so".encode()
    before_library = compile_counter_library(reader, target_object, on_create, on_click, description, soname=soname)
    after_library = compile_counter_library(workspace.reader, target_object, on_create, clicked, description, soname=soname)
    built = app.build()
    if built["library"] != before_library or built["signed"] != app.APK.read_bytes():
        raise AssertionError("the pinned store no longer builds the committed APK")
    from benchmarks.bench_android_apk import _signing_capability
    from xax_apk import build_unsigned_apk
    from xax_apk_signing import sign_apk_v2

    unsigned = build_unsigned_apk(built["manifest"], built["activity_dex"], native_libraries={soname.decode(): after_library}, extra_entries={"classes2.dex": built["listener_dex"]})
    after_apk = sign_apk_v2(unsigned, _signing_capability())

    with tempfile.TemporaryDirectory(prefix="xax-r5-android-") as directory:
        work = Path(directory)
        (work / "before.apk").write_bytes(app.APK.read_bytes())
        (work / "after.apk").write_bytes(after_apk)
        tests = _device_tests(work, before_library, after_library, [item.decode() for item in built["symbols"].split(b",")], work / "after.apk")
        benchmark = _benchmark({"xax": work / "after.apk", "before": work / "before.apk"})
        store_path = work / "counter-gen3.xax"
        workspace.save(store_path)
        store_bytes = store_path.read_bytes()
    accounting = workspace.accounting
    return {
        "format": "xax-r5-maintenance-evidence-v1",
        "decision": "ADR-255",
        "label": "EXECUTED",
        "application": {"name": "xax.counter", "platform_row": "android-arm64", "target": target_object.cid.hex(), "original_root": original_root.hex()},
        "request": REQUEST,
        "agent": {
            "authored_input": list(AGENT_TRANSACTIONS),
            "author": "Claude (AI coding agent), Claude Code session of 2026-10-10, after reading the projection excerpt below",
            "projection_excerpt": excerpt,
            "replayed_by": "this harness, deterministically against the pinned original store",
        },
        "queries": queries,
        "transactions": [
            {
                "generation_after": index + 1, "committed": result.committed, "new_root": result.root.hex(),
                "changed_entities": [cid.hex() for cid in result.changed_entities], "transaction_bytes": result.transaction_bytes,
                "touched_objects": result.touched_objects, "reused_objects": result.reused_objects, "verified_objects": result.verified_objects,
            }
            for index, result in enumerate((first, second, third))
        ],
        "semantic_diff": repr(diff),
        "whole_source_regenerated": False,
        "workspace_accounting": {key: getattr(accounting, key) for key in ("queries", "entities_exposed", "query_bytes", "mutations", "rejected_transactions")},
        "rebuild": {
            "before": {"library_sha256": _sha(before_library), "library_bytes": len(before_library), "apk_sha256": _sha(app.APK.read_bytes())},
            "after": {"library_sha256": _sha(after_library), "library_bytes": len(after_library), "apk_sha256": _sha(after_apk), "apk_bytes": len(after_apk), "on_click": clicked.hex()},
        },
        "tests": tests,
        "benchmark": benchmark,
        "persisted": {"store": "counter-gen3.xax (canonical workspace save)", "store_sha256": _sha(store_bytes), "store_bytes": len(store_bytes), "root": workspace.root.hex()},
        "host": benchmark.pop("target"),
    }


def _adb(*arguments: str) -> str:
    return subprocess.run(["adb", *arguments], check=True, capture_output=True, text=True, timeout=900).stdout.replace("\r", "")


def _device_tests(work: Path, before: bytes, after: bytes, symbols: list[str], after_apk: Path) -> dict:
    """The native methods under the loader from several stored counts, then the whole APK under the device oracle."""
    loader = work / "loader"
    subprocess.run([str(_llvm("aarch64-linux-android28-clang")), "-O2", "-o", str(loader), str(LOADER)], check=True)
    (work / "before.so").write_bytes(before)
    (work / "after.so").write_bytes(after)
    _adb("shell", f"rm -rf {REMOTE} && mkdir -p {REMOTE}")
    for path in (loader, work / "before.so", work / "after.so"):
        _adb("push", str(path), f"{REMOTE}/{path.name}")
    _adb("shell", f"chmod 755 {REMOTE}/loader")
    cases = []
    for library, capped in (("after", True), ("before", False)):
        for initial in ((None, 9997, 20000) if capped else (None, 9997)):
            command = f"cd {REMOTE} && ./loader ./{library}.so ./state {' '.join(symbols)}" + (f" {initial}" if initial is not None else "")
            observed = _adb("shell", command).strip()
            expected = _expected(initial, capped)
            cases.append({"library": library, "initial": initial, "expected": expected, "observed": observed, "passed": observed == expected})
    _adb("shell", f"rm -rf {REMOTE}")
    oracle = subprocess.run(["bash", str(app.ORACLE)], capture_output=True, text=True, timeout=3600, env={**os.environ, "XAX_ANDROID_APK": str(after_apk)})
    apk = {
        "oracle": "integration/android/validate_counter_apk.sh",
        "output": [line for line in oracle.stdout.splitlines() if line.startswith(("ok:", app.ORACLE_PASSED))],
        "passed": oracle.returncode == 0 and app.ORACLE_PASSED in oracle.stdout,
    }
    changed = [case for case in cases if case["library"] == "before" and case["initial"] == 9997]
    return {
        "native": cases,
        "apk": apk,
        "change_took_effect": bool(changed) and changed[0]["observed"] != _expected(9997, True),
        "all_passed": all(case["passed"] for case in cases) and apk["passed"],
    }


def _benchmark(apks: dict[str, Path]) -> dict:
    """Cold starts (``TotalTime``) of both APKs; they share a package, so blocks alternate fresh installs."""
    properties = {name: _adb("shell", "getprop", name).strip() for name in ("ro.product.model", "ro.soc.model", "ro.build.fingerprint", "ro.kernel.qemu")}
    samples: dict[str, list[int]] = {arm: [] for arm in apks}
    names = list(apks)
    for block in range(BLOCKS):
        for arm in names[block % 2:] + names[:block % 2]:
            twin._install(apks[arm], twin.PACKAGE)
            _adb("shell", "cmd", "package", "compile", "-f", "-m", twin.COMPILER_FILTER, twin.PACKAGE)
            for _ in range(twin.WARMUP):
                twin._cold_start(twin.PACKAGE)
            for _ in range(RUNS):
                samples[arm].append(twin._cold_start(twin.PACKAGE)["total_time_ms"])
    subprocess.run(["adb", "uninstall", twin.PACKAGE], capture_output=True, timeout=300)
    medians = {arm: statistics.median(values) for arm, values in samples.items()}
    return {
        "protocol": f"{BLOCKS} blocks; each installs both APKs in turn (order alternating), compiles with {twin.COMPILER_FILTER}, {twin.WARMUP} warmup starts, then {RUNS} cold starts",
        "results": {("after" if arm == "xax" else arm): {"total_time_ms_samples": values, "median_total_time_ms": medians[arm]} for arm, values in samples.items()},
        "after_over_before_median": round(medians["xax"] / medians["before"], 6),
        # One-sided Mann-Whitney (section 15.0): is either build faster than the other?
        "p_after_faster": round(faster_p_value(samples["xax"], samples["before"]), 6),
        "p_before_faster": round(faster_p_value(samples["before"], samples["xax"]), 6),
        "target": properties,
    }


def main(argv: list[str]) -> int:
    evidence = maintain()
    if "--write" in argv:
        EVIDENCE.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({key: evidence[key] for key in ("transactions", "tests", "benchmark")}, indent=1)[:5000])
    return 0 if evidence["tests"]["all_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
