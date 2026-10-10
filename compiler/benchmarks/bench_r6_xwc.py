"""R6 record for the JVM row (ADR-257): ``xwc``, a word counter developed and maintained only in XAX.

``xwc`` reads standard input in 64 KiB chunks and prints its line, word, and byte counts as GNU ``wc`` does for
standard input (``%7d %7d %7d``).  Release 1 counts words as ``wc`` does in the C locale: a word is a run of
printable ASCII (0x21-0x7E) ended by one of the six ASCII white-space bytes; other bytes neither start nor end a
word.  Release 2 is a maintenance request: count words in UTF-8 text as ``wc`` does in a UTF-8 locale, i.e. bytes
0x80-0xFF also continue or start a word.

What is XAX here, and what is not:

* application logic: ``count_lines``, ``count_words``, ``put_count``, and ``main`` in canonical XAX;
* tests: the ``selftest`` entry, also XAX: counts over a ten-byte sample with control, DEL, and vertical-tab bytes,
  a word carried across a chunk boundary, a byte above 0x7F, and the width-7 and wider decimal output; its exit
  status is a bit set of the failing checks;
* build definitions: the canonical package (entries ``app`` and ``test``), profile, trust policy, request, and
  snapshot objects; every JAR comes out of ``xax_build.build`` with a provenance object;
* authored input: ``r6_xwc/construction_request.json`` is the one ``xax-construct-v1`` request the agent (Claude,
  in the 2026-10-10 Claude Code session) wrote, by hand, to create generation 0; it is a transport record, not
  source: the release is built from the committed store, and this harness checks that the request reconstructs it
  exactly.  Generation 1 came from one workspace transaction (``maintain``) on generation 0, never from a request;
* not XAX, disclosed: the Python bootstrap compiler and build service, this harness (it runs builds, runs the JARs,
  and compares them with GNU ``wc``, an external oracle), and the JVM.  None holds application logic.  The ``test``
  build request is derived mechanically from the package's declared entry.

Run ``python -m benchmarks.bench_r6_xwc [--write]`` from ``compiler/`` with ``java`` and GNU ``wc`` on ``PATH``.
"""

from __future__ import annotations

import hashlib
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent / "r6_xwc"
REQUEST = HERE / "construction_request.json"
STORES = {0: HERE / "xwc-gen0.xax", 1: HERE / "xwc-gen1.xax"}
EVIDENCE = Path(__file__).resolve().parent / "r6_xwc_evidence.json"
MAINTENANCE_REQUEST = "Release 2: count words in UTF-8 text as wc does in a UTF-8 locale (bytes 0x80-0xFF are word bytes), and keep the XAX tests in step."
# Written by the agent from the function_nodes and operands queries of generation 0.
MAINTENANCE_EDIT = (
    "F4.B2: insert-before N13 #0 constant bits<32> 128; insert-before N14 #1 int.compare.uge N1 #0 -> bits<1>; "
    "insert-before N15 #2 int.zero.extend #1 -> bits<64>; insert-before N16 #3 bit.or N15 #2 -> bits<64>; "
    "replace-operand N26 0 <- #3; F2.B0: set-constant N82 1"
)
SIZES = (0, 1, 2, 7, 64, 1000, 65535, 65536, 65537, 131073, 1 << 20)
TEXT = "a Z 9 ! é ü ñ ß € 中 文".split(" ") + [" ", "\t", "\n", "\r", "\x0b", "\x0c", "\x01", "\x7f", "  "]


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _java() -> str:
    java = shutil.which("java")
    if java is None:
        raise RuntimeError("UNAVAILABLE: java")
    return java


def _builds(reader) -> dict:
    """Release (``app``) and ``test`` JARs of a store, each built twice through the canonical build service."""
    from xax_build import ArtifactKind, build, build_request, decode_request, decode_snapshot, resolve_packages, snapshot_store

    resolve = reader.get
    snapshot = decode_snapshot(resolve(reader.root_cid), resolve)
    request = resolve(snapshot.request_root)
    view = decode_request(request, resolve)
    release, again = build(reader, request.cid), build(reader, request.cid)
    test_request = build_request(resolve(view.package_root), b"test", resolve(view.target_root), resolve(view.profile_root),
                                 requested_artifacts=(ArtifactKind.JVM_EXECUTABLE_JAR,))
    objects = (*reader.objects(), test_request)
    test_reader = snapshot_store(resolve_packages(test_request, objects, resolve(snapshot.trust_policy_root), snapshot.resolver_identity), objects)
    test, test_again = build(test_reader, test_request.cid), build(test_reader, test_request.cid)
    return {
        "app": {"artifact": release.artifact, "provenance": release.provenance.cid.hex(), "reproducible": release == again, "request": request.cid.hex()},
        "test": {"artifact": test.artifact, "provenance": test.provenance.cid.hex(), "reproducible": test == test_again, "request": test_request.cid.hex()},
    }


def _run_jar(jar: Path, data: bytes = b"") -> subprocess.CompletedProcess:
    env = {key: value for key, value in os.environ.items() if key != "JAVA_TOOL_OPTIONS"}
    return subprocess.run([_java(), "-jar", str(jar)], input=data, capture_output=True, env=env, timeout=300)


def _inputs(utf8: bool) -> list[tuple[str, bytes]]:
    """Random bytes (release 1 only: the C locale defines every byte) and text with BMP UTF-8 letters."""
    rng = random.Random(257)
    cases = []
    for size in SIZES:
        if not utf8:
            cases.append(("bytes", rng.randbytes(size)))
        text, length = [], 0
        while length < size:
            text.append(rng.choice(TEXT))
            length += len(text[-1].encode())
        cases.append(("text", "".join(text).encode()))
    return cases


def _deploy_and_check(artifacts: dict, utf8: bool, work: Path) -> dict:
    """Install the release JAR, run the XAX selftest JAR, and compare the release with GNU wc."""
    generation = 1 if utf8 else 0
    prefix = work / f"prefix-r{generation + 1}" / "lib"
    prefix.mkdir(parents=True)
    installed = prefix / "xwc.jar"
    installed.write_bytes(artifacts["app"]["artifact"])
    tests = prefix / "xwc-selftest.jar"
    tests.write_bytes(artifacts["test"]["artifact"])
    selftest = _run_jar(tests).returncode
    locale = "C.UTF-8" if utf8 else "C"
    oracle = shutil.which("wc")
    cases = []
    for kind, data in _inputs(utf8):
        ours = _run_jar(installed, data)
        theirs = subprocess.run([oracle], input=data, capture_output=True, env={**os.environ, "LC_ALL": locale})
        cases.append({"bytes": len(data), "kind": kind, "status": ours.returncode, "matches_oracle": ours.returncode == 0 and ours.stdout == theirs.stdout})
    version = subprocess.run([oracle, "--version"], capture_output=True, text=True).stdout.splitlines()[0]
    return {
        "installed_path": "prefix/lib/xwc.jar", "selftest_exit_status": selftest, "oracle": f"{version}, LC_ALL={locale}",
        "cases": len(cases), "matching": sum(case["matches_oracle"] for case in cases), "all_match": all(case["matches_oracle"] for case in cases),
    }


def maintain(workspace, functions: dict, *, with_test: bool = True) -> tuple[object, int]:
    """The agent's release-2 transaction on the queried generation: ``(result, queries made)``.

    Handles are the ones the agent read: in ``count_words`` block 2 (``F4.B2``), ``N1`` zero-extends the loaded
    byte and ``N15`` is the word-byte flag ``zext(byte - 33 <u 94)``, read by the new in-word flag ``N26 = bit.or N15
    N25``; in ``selftest`` (``F2.B0``), ``N82`` is the expected count_words state after a 0x80 byte with no word open.
    The edit inserts ``128``, ``byte >=u 128``, its extension, and ``N15 | that`` (one insertion per anchor, N13 to
    N16), points ``N26`` at the result, and changes the expectation from 0 to 1.  ``with_test=False`` leaves the
    expectation alone: the XAX selftest must then fail."""
    from xax_compiler import IntCompare, Operation, ValueRef
    from xax_workspace import InsertPureNode, ReplaceUse, RootRef, SetConstant, Transaction, TransactionValueRef

    words = {view.handle: view for view in workspace.function_nodes(functions["count_words"].cid, 1024).entities}
    test = {view.handle: view for view in workspace.function_nodes(functions["selftest"].cid, 1024).entities}
    shape = (
        words["F4.B2.N1"].operation == Operation.INT_ZERO_EXTEND and words["F4.B2.N15"].operation == Operation.INT_ZERO_EXTEND
        and words["F4.B2.N26"].operation == Operation.BIT_OR and words["F4.B2.N13"].constant_value == 94
        and test["F2.B0.N82"].constant_value == 0 and test["F2.B0.N83"].operation == Operation.INT_COMPARE
    )
    if not shape:
        raise AssertionError("the store no longer has the shape the agent read")
    value = lambda index: ValueRef.node_result(2, index)  # noqa: E731
    mutations = [
        InsertPureNode("F4.B2.N13", 2, 13, 0, Operation.CONSTANT, (), "bits<32>", 128),
        InsertPureNode("F4.B2.N14", 2, 14, 1, Operation.INT_COMPARE, (value(1), TransactionValueRef(0)), "bits<1>", attributes=(int(IntCompare.UGE),)),
        InsertPureNode("F4.B2.N15", 2, 15, 2, Operation.INT_ZERO_EXTEND, (TransactionValueRef(1),), "bits<64>"),
        InsertPureNode("F4.B2.N16", 2, 16, 3, Operation.BIT_OR, (value(15), TransactionValueRef(2)), "bits<64>"),
        ReplaceUse("F4.B2.N26", 0, value(15), TransactionValueRef(3)),
    ]
    if with_test:
        mutations.append(SetConstant("F2.B0.N82", 0, 1))
    return workspace.commit(Transaction(RootRef(workspace.generation), tuple(mutations))), 2


def run(write: bool = False, *, logic_only: bool = False) -> dict:
    from xax_compiler import StoreReader
    from xax_construct import construct
    from xax_workspace import Workspace

    request = json.loads(REQUEST.read_text(encoding="utf-8"))
    constructed = construct(request)
    if write:
        STORES[0].write_bytes(constructed.reader.canonical_bytes())
    gen0 = StoreReader(STORES[0].read_bytes())
    if gen0.canonical_bytes() != constructed.reader.canonical_bytes():
        raise AssertionError("construction request does not reconstruct the committed generation 0")

    workspace = Workspace(gen0, constructed.target)
    generation = workspace.generation
    result, queries = maintain(workspace, constructed.functions)
    if not result.committed:
        raise AssertionError(f"maintenance edit rejected: {result.diagnostic}")
    diff = workspace.diff(generation, 64)
    if write:
        workspace.save(STORES[1])
    gen1 = StoreReader(STORES[1].read_bytes())
    if gen1.root_cid != result.root:
        raise AssertionError("committed generation 1 differs from the replayed transaction")

    # The XAX tests guard the change: the same logic edit without the test expectation fails selftest.
    probe = Workspace(gen0, constructed.target)
    probe_result = maintain(probe, constructed.functions, with_test=False)[0]
    with tempfile.TemporaryDirectory(prefix="xax-r6-xwc-") as directory:
        work = Path(directory)
        guard_jar = work / "guard-selftest.jar"
        guard_jar.write_bytes(_builds(probe.reader)["test"]["artifact"])
        guard_status = _run_jar(guard_jar).returncode
        builds0, builds1 = _builds(gen0), _builds(gen1)
        release0 = _release_record(0, gen0, builds0, _deploy_and_check(builds0, False, work))
        release1 = _release_record(1, gen1, builds1, _deploy_and_check(builds1, True, work))

    return {
        "format": "xax-r6-evidence-v1",
        "decision": "ADR-257",
        "label": "EXECUTED",
        "application": {"name": "xwc", "kind": "command-line word counter (stdin to stdout, GNU wc-compatible counts and layout)",
                        "platform_row": "jvm", "functions": sorted(constructed.functions), "entries": {"app": "main", "test": "selftest"}},
        "construction": {"request": f"r6_xwc/{REQUEST.name}", "request_sha256": _sha(REQUEST.read_bytes()), "format": request["format"],
                         "author": "Claude (AI coding agent), Claude Code session of 2026-10-10, written by hand", "reconstructs_generation_0": True},
        "maintenance": {
            "request": MAINTENANCE_REQUEST, "authored_edit": MAINTENANCE_EDIT, "queries": queries,
            "generation_before": generation, "generation_after": workspace.generation, "committed": result.committed,
            "transaction_bytes": result.transaction_bytes, "touched_objects": result.touched_objects, "reused_objects": result.reused_objects,
            "semantic_diff": repr(diff), "whole_program_regenerated": False,
            "test_guard": {"edit": "the same count_words edit without the selftest expectation", "committed": probe_result.committed, "selftest_exit_status": guard_status},
        },
        "releases": [release0, release1],
        "host": {"java": subprocess.run([_java(), "-version"], capture_output=True, text=True).stderr.splitlines()[0]},
        "non_xax_components": [
            "Python bootstrap compiler and build service (xax_build.build); no application logic",
            "this harness: runs builds, installs the JARs, runs them, compares the release with GNU wc (external oracle)",
            "the JVM (platform)",
            "the test build request is derived from the package's declared 'test' entry",
        ],
    }


def _release_record(generation: int, reader, builds: dict, deployment: dict) -> dict:
    return {
        "generation": generation, "store": STORES[generation].name, "store_sha256": _sha(reader.canonical_bytes()), "root": reader.root_cid.hex(),
        "builds": {name: {"artifact_sha256": _sha(item["artifact"]), "artifact_bytes": len(item["artifact"]), "provenance": item["provenance"],
                          "request": item["request"], "reproducible": item["reproducible"]} for name, item in builds.items()},
        "deployment": deployment,
    }


def main(argv: list[str]) -> int:
    evidence = run("--write" in argv)
    text = json.dumps(evidence, indent=2) + "\n"
    if "--write" in argv:
        EVIDENCE.write_text(text, encoding="utf-8")
    print(json.dumps({"maintenance": {k: evidence["maintenance"][k] for k in ("committed", "transaction_bytes", "touched_objects", "reused_objects", "test_guard")},
                      "releases": [{k: r[k] for k in ("generation", "builds", "deployment")} for r in evidence["releases"]]}, indent=1)[:4000])
    ok = all(r["deployment"]["all_match"] and r["deployment"]["selftest_exit_status"] == 0 for r in evidence["releases"])
    return 0 if ok and evidence["maintenance"]["test_guard"]["selftest_exit_status"] != 0 else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
