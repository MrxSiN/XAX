"""R6 record (ADR-210): ``xb64``, a base64 encoder developed and maintained only in XAX.

What is XAX here, and what is not:

* application logic: four functions (``sextet_char``, ``encode_full``, ``finish``, ``main``) in canonical XAX;
* tests: the ``selftest`` entry, also XAX: RFC 4648 section 10 vectors and both line-wrap edges, exit status 0 or
  the number of the failing case;
* build definitions: the canonical package (entries ``app`` and ``test``), build profile, trust policy, request,
  and snapshot objects; every artifact comes out of ``xax_build.build`` with a provenance object;
* authored input: ``construction_request.json`` is the one ``xax-construct-v1`` request the agent (Claude, in the
  2026-10-08 Claude Code session) sent to create generation 0; it is a transport record, not source: the release
  is built from the committed store ``xb64-gen0.xax``, and this harness only checks that the request reconstructs
  it exactly.  The maintenance release ``xb64-gen1.xax`` came from one workspace transaction (``MAINTENANCE_EDIT``)
  on generation 0, never from the request;
* not XAX, disclosed: the Python bootstrap compiler and build service, this harness (it runs builds and compares
  the deployed executable with coreutils ``base64``, an external oracle), and the Linux kernel.  None holds
  application logic.  The ``test`` build request is derived mechanically from the package's declared entry.

Run ``PYTHONPATH=src:.:.. python -m benchmarks.bench_r6_xb64 [--write]`` from ``compiler/`` on Linux x86-64.
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

HERE = Path(__file__).resolve().parent / "r6_xb64"
REQUEST = HERE / "construction_request.json"
STORES = {0: HERE / "xb64-gen0.xax", 1: HERE / "xb64-gen1.xax"}
EVIDENCE = Path(__file__).resolve().parent / "r6_xb64_evidence.json"
MAINTENANCE_REQUEST = "Release 2: emit PEM-style 64-column lines (base64 -w 64) and keep the XAX tests in step."
# Written by the agent from the function_nodes query of generation 0 (constants 76 and 77 in encode_full and the
# selftest wrap cases): the wrap width and the two test expectations that depend on it, in one transaction.
MAINTENANCE_EDIT = "const F2.B2.N52 64; const F1.B8.N13 64; const F1.B8.N21 78; const F1.B9.N5 64"
# A deliberately incomplete edit (width only): the XAX tests must catch it.
INCOMPLETE_EDIT = "const F2.B2.N52 64"
SIZES = (0, 1, 2, 3, 4, 56, 57, 58, 75, 76, 77, 100, 4095, 49151, 49152, 49153, 49154, 98304, 98305, 1 << 20)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _builds(reader):
    """Release (``app``) and ``test`` artifacts of a store, each built twice through the canonical build service."""
    from xax_build import ArtifactKind, build, build_request, decode_request, decode_snapshot, resolve_packages, snapshot_store

    resolve = reader.get
    snapshot = decode_snapshot(resolve(reader.root_cid), resolve)
    request = resolve(snapshot.request_root)
    view = decode_request(request, resolve)
    release, again = build(reader, request.cid), build(reader, request.cid)
    test_request = build_request(resolve(view.package_root), b"test", resolve(view.target_root), resolve(view.profile_root),
                                 requested_artifacts=(ArtifactKind.NATIVE_IMAGE,))
    objects = (*reader.objects(), test_request)
    test_reader = snapshot_store(resolve_packages(test_request, objects, resolve(snapshot.trust_policy_root), snapshot.resolver_identity), objects)
    test, test_again = build(test_reader, test_request.cid), build(test_reader, test_request.cid)
    return {
        "app": {"artifact": release.artifact, "provenance": release.provenance.cid.hex(), "reproducible": release == again,
                "request": request.cid.hex()},
        "test": {"artifact": test.artifact, "provenance": test.provenance.cid.hex(), "reproducible": test == test_again,
                 "request": test_request.cid.hex()},
    }


def _deploy_and_check(artifacts: dict, wrap: int, work: Path) -> dict:
    """Install the release into ``work/prefix/bin``, run the XAX selftest, and compare with coreutils base64."""
    from xax_linux import run_linux_executable

    prefix = work / f"prefix-w{wrap}" / "bin"
    prefix.mkdir(parents=True)
    installed = prefix / "xb64"
    installed.write_bytes(artifacts["app"]["artifact"])
    installed.chmod(0o755)
    selftest = run_linux_executable(artifacts["test"]["artifact"]).returncode
    oracle = shutil.which("base64")
    rng = random.Random(210)
    cases = []
    for size in SIZES:
        for kind in ("random", "text"):
            data = bytes(rng.randrange(256) for _ in range(size)) if kind == "random" else bytes(rng.choice(b"abc xyz\n") for _ in range(size))
            ours = subprocess.run([str(installed)], input=data, capture_output=True)
            theirs = subprocess.run([oracle, "-w", str(wrap)], input=data, capture_output=True)
            cases.append({"bytes": size, "kind": kind, "status": ours.returncode, "matches_oracle": ours.stdout == theirs.stdout and ours.returncode == 0})
    return {
        "installed_path": "prefix/bin/xb64", "selftest_exit_status": selftest, "oracle": f"coreutils base64 -w {wrap}",
        "cases": len(cases), "matching": sum(case["matches_oracle"] for case in cases), "all_match": all(case["matches_oracle"] for case in cases),
    }


def _release_record(generation: int, reader, builds: dict, deployment: dict) -> dict:
    return {
        "generation": generation, "store": STORES[generation].name, "store_sha256": _sha(reader.canonical_bytes()), "root": reader.root_cid.hex(),
        "builds": {name: {"artifact_sha256": _sha(item["artifact"]), "artifact_bytes": len(item["artifact"]), "provenance": item["provenance"],
                          "request": item["request"], "reproducible": item["reproducible"]} for name, item in builds.items()},
        "deployment": deployment,
    }


def run(write: bool = False) -> dict:
    from xax_compiler import StoreReader
    from xax_construct import construct
    from xax_linux import run_linux_executable
    from xax_local_protocol import LocalMutationSession
    from xax_workspace import Workspace

    request = json.loads(REQUEST.read_text(encoding="utf-8"))
    constructed = construct(request)
    if write:
        STORES[0].write_bytes(constructed.reader.canonical_bytes())
    gen0 = StoreReader(STORES[0].read_bytes())
    if gen0.canonical_bytes() != constructed.reader.canonical_bytes():
        raise AssertionError("construction request does not reconstruct the committed generation 0")

    # Maintenance: one transaction on the committed generation 0 store, bound to the queried generation.
    workspace = Workspace(gen0, constructed.target)
    queries = 0
    for function in constructed.functions.values():
        workspace.function_nodes(function.cid, 1024)
        queries += 1
    generation = workspace.generation
    result = LocalMutationSession(workspace, expected_generation=generation).commit(MAINTENANCE_EDIT)
    if not result.committed:
        raise AssertionError(f"maintenance edit rejected: {result.diagnostic}")
    diff = workspace.diff(generation, 64)
    if write:
        workspace.save(STORES[1])
    gen1 = StoreReader(STORES[1].read_bytes())
    if gen1.root_cid != result.root:
        raise AssertionError("committed generation 1 differs from the replayed transaction")

    # The XAX tests guard the change: the width edit alone fails selftest.
    probe = Workspace(gen0, constructed.target)
    for function in constructed.functions.values():
        probe.function_nodes(function.cid, 1024)
    incomplete = LocalMutationSession(probe, expected_generation=probe.generation).commit(INCOMPLETE_EDIT)
    incomplete_status = run_linux_executable(_builds(probe.reader)["test"]["artifact"]).returncode

    with tempfile.TemporaryDirectory(prefix="xax-r6-") as directory:
        work = Path(directory)
        builds0, builds1 = _builds(gen0), _builds(gen1)
        release0 = _release_record(0, gen0, builds0, _deploy_and_check(builds0, 76, work))
        release1 = _release_record(1, gen1, builds1, _deploy_and_check(builds1, 64, work))

    return {
        "format": "xax-r6-evidence-v1",
        "decision": "ADR-210",
        "label": "EXECUTED",
        "application": {"name": "xb64", "kind": "command-line base64 encoder (stdin to stdout, GNU-compatible line wrapping)",
                        "platform_row": "linux-x86_64", "functions": sorted(constructed.functions), "entries": {"app": "main", "test": "selftest"}},
        "construction": {"request": REQUEST.name, "request_sha256": _sha(REQUEST.read_bytes()), "format": request["format"],
                         "author": "Claude (AI coding agent), Claude Code session of 2026-10-08", "reconstructs_generation_0": True},
        "maintenance": {
            "request": MAINTENANCE_REQUEST, "authored_edit": MAINTENANCE_EDIT, "function_queries": queries,
            "generation_before": generation, "generation_after": workspace.generation, "committed": result.committed,
            "transaction_bytes": result.transaction_bytes, "touched_objects": result.touched_objects, "reused_objects": result.reused_objects,
            "semantic_diff": repr(diff), "whole_program_regenerated": False,
            "test_guard": {"edit": INCOMPLETE_EDIT, "committed": incomplete.committed, "selftest_exit_status": incomplete_status},
        },
        "releases": [release0, release1],
        "non_xax_components": [
            "Python bootstrap compiler and build service (xax_build.build); no application logic",
            "this harness: runs builds, installs the executable, compares it with coreutils base64 (external oracle)",
            "Linux kernel (platform)",
            "the test build request is derived from the package's declared 'test' entry",
        ],
    }


def main(argv: list[str]) -> int:
    evidence = run("--write" in argv)
    text = json.dumps(evidence, indent=2) + "\n"
    if "--write" in argv:
        EVIDENCE.write_text(text)
    print(json.dumps({"maintenance": {k: evidence["maintenance"][k] for k in ("committed", "transaction_bytes", "test_guard")},
                      "releases": [{k: r[k] for k in ("generation", "builds", "deployment")} for r in evidence["releases"]]}, indent=1)[:3000])
    ok = all(r["deployment"]["all_match"] and r["deployment"]["selftest_exit_status"] == 0 for r in evidence["releases"])
    return 0 if ok and evidence["maintenance"]["test_guard"]["selftest_exit_status"] != 0 else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
