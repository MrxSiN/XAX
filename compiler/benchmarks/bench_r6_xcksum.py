"""R6 record (ADR-258): ``xcksum``, a POSIX ``cksum`` developed and maintained only in XAX, deployed on AArch64 Linux.

What is XAX here, and what is not:

* application logic: six functions (``crc_step``, ``crc_byte``, ``crc_buffer``, ``crc_length``, ``put_number``,
  ``render``) and the ``main`` entry in canonical XAX: the POSIX CRC-32 (polynomial 0x04C11DB7, most significant bit
  first) of standard input read in 64 KiB chunks, extended by the length's octets and complemented, printed as
  ``CRC SIZE``;
* tests: the ``selftest`` entry, also XAX: the CRC of ``abc``, of the empty input, and two rendered lines; exit
  status 0 or a bit set of failed checks;
* build definitions: the canonical package (entries ``app`` and ``test``), build profile, trust policy, request,
  and snapshot objects; every artifact comes out of ``xax_build.build`` with a provenance object;
* authored input: ``construction_request.json`` is the one ``xax-construct-v1`` request (platform
  ``linux-aarch64``) the agent (Claude, in the 2026-10-10 Claude Code session) wrote by hand to create generation
  0; it is a transport record, not source: the release is built from the committed store ``xcksum-gen0.xax``, and
  this harness only checks that the request reconstructs it exactly.  Release 2 (``cksum -H``: the CRC in
  zero-padded hexadecimal) ``xcksum-gen1.xax`` came from one workspace transaction (``MAINTENANCE_EDIT``) on
  generation 0, never from the request;
* not XAX, disclosed: the Python bootstrap compiler and build service, this harness (it builds, installs the
  executable on each phone, and compares it there with toybox ``cksum``, an external oracle), adb, and the
  phones' Linux kernels.  None holds application logic.  The ``test`` build request is derived mechanically from
  the package's declared entry (``bench_r6_xb64._builds``).

Run ``PYTHONPATH=src:.:.. python -m benchmarks.bench_r6_xcksum [--write]`` from ``compiler/`` with the AArch64
Android devices on ``adb`` (``XAX_R6_SERIALS``: comma-separated serials; default every attached device whose
kernel reports ``aarch64``).
"""

from __future__ import annotations

import hashlib
import json
import os
import random
import subprocess
import sys
import tempfile
from pathlib import Path

from benchmarks.bench_r6_xb64 import _builds

HERE = Path(__file__).resolve().parent / "r6_xcksum"
REQUEST = HERE / "construction_request.json"
STORES = {0: HERE / "xcksum-gen0.xax", 1: HERE / "xcksum-gen1.xax"}
EVIDENCE = Path(__file__).resolve().parent / "r6_xcksum_evidence.json"
MAINTENANCE_REQUEST = "Release 2: print the checksum in zero-padded hexadecimal (cksum -H) and keep the XAX tests in step."
# Written by the agent from the function_nodes query of generation 0: in render (F7.B0), N1 and N2 are the base (10)
# and minimum width (1) of the CRC's put_number call; in selftest (F4.B0), N33, N40, N44 and N60 are the expected
# length of the rendered "abc" line and its first two bytes, and the first byte of the rendered 69083669 line.
MAINTENANCE_EDIT = "const F7.B0.N1 16; const F7.B0.N2 8; const F4.B0.N33 11; const F4.B0.N40 52; const F4.B0.N44 56; const F4.B0.N60 48"
# The logic change without the test expectations: the XAX tests must catch it.
INCOMPLETE_EDIT = "const F7.B0.N1 16; const F7.B0.N2 8"
SIZES = (0, 1, 2, 3, 255, 256, 257, 65535, 65536, 65537, 131072, 200000, 1 << 20)
REMOTE = "/data/local/tmp/xax-r6-xcksum"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _adb(serial: str, *arguments: str, data: bytes | None = None) -> bytes:
    return subprocess.run(["adb", "-s", serial, *arguments], input=data, capture_output=True, check=True, timeout=600).stdout


def _serials() -> list[str]:
    if os.environ.get("XAX_R6_SERIALS"):
        return os.environ["XAX_R6_SERIALS"].split(",")
    lines = subprocess.run(["adb", "devices"], capture_output=True, text=True, check=True).stdout.splitlines()[1:]
    serials = [line.split()[0] for line in lines if line.endswith("device")]
    return [serial for serial in serials if _adb(serial, "shell", "uname -m").strip() == b"aarch64"]


def _inputs() -> list[tuple[str, bytes]]:
    rng = random.Random(258)
    cases = []
    for size in SIZES:
        cases.append(("random", bytes(rng.randrange(256) for _ in range(size))))
        cases.append(("text", bytes(rng.choice(b"abc xyz\n") for _ in range(size))))
    return cases


def _deploy_and_check(serial: str, artifacts: dict, hexadecimal: bool, work: Path) -> dict:
    """Install the release on the phone, run the XAX selftest there, and compare the release with toybox cksum."""
    generation = 1 if hexadecimal else 0
    cases = _inputs()
    _adb(serial, "shell", f"rm -rf {REMOTE} && mkdir -p {REMOTE}/prefix/bin {REMOTE}/in")
    local = work / f"{serial[:12]}-gen{generation}"
    local.mkdir()
    for name, data in (("xcksum", artifacts["app"]["artifact"]), ("xcksum-selftest", artifacts["test"]["artifact"])):
        (local / name).write_bytes(data)
        _adb(serial, "push", str(local / name), f"{REMOTE}/prefix/bin/{name}")
    for index, (_kind, data) in enumerate(cases):
        (local / str(index)).write_bytes(data)
    _adb(serial, "push", *(str(local / str(index)) for index in range(len(cases))), f"{REMOTE}/in/")
    oracle = "cksum -H" if hexadecimal else "cksum"
    script = (f"cd {REMOTE} && chmod 755 prefix/bin/* && prefix/bin/xcksum-selftest; echo selftest $?; "
              f"for i in $(seq 0 {len(cases) - 1}); do prefix/bin/xcksum <in/$i >x; s=$?; {oracle} <in/$i >o; "
              f"cmp -s x o; echo case $i $s $?; done")
    lines = _adb(serial, "shell", script).decode().replace("\r", "").splitlines()
    sample = _adb(serial, "exec-out", f"cd {REMOTE} && prefix/bin/xcksum <in/{len(cases) - 1}").decode().strip()
    toybox = _adb(serial, "shell", "toybox --version").decode().strip()
    _adb(serial, "shell", f"rm -rf {REMOTE}")
    selftest = int(next(line.split()[1] for line in lines if line.startswith("selftest ")))
    results = {int(index): (int(status), same == "0") for _case, index, status, same in (line.split() for line in lines if line.startswith("case "))}
    if len(results) != len(cases):
        raise AssertionError(f"{serial}: {len(results)} of {len(cases)} cases reported")
    matching = sum(status == 0 and same for status, same in results.values())
    return {
        "installed_path": "prefix/bin/xcksum", "selftest_exit_status": selftest, "oracle": f"{toybox} {oracle}",
        "cases": len(cases), "matching": matching, "all_match": matching == len(cases), "largest_input_output": sample,
    }


def _device(serial: str) -> dict:
    prop = lambda name: _adb(serial, "shell", f"getprop {name}").decode().strip()  # noqa: E731
    return {"model": prop("ro.product.model"), "soc": prop("ro.soc.model") or prop("ro.board.platform"),
            "android": prop("ro.build.version.release"), "kernel": _adb(serial, "shell", "uname -sr").decode().strip()}


def _release_record(generation: int, reader, builds: dict, deployments: list[dict]) -> dict:
    return {
        "generation": generation, "store": STORES[generation].name, "store_sha256": _sha(reader.canonical_bytes()), "root": reader.root_cid.hex(),
        "builds": {name: {"artifact_sha256": _sha(item["artifact"]), "artifact_bytes": len(item["artifact"]), "provenance": item["provenance"],
                          "request": item["request"], "reproducible": item["reproducible"]} for name, item in builds.items()},
        "deployments": deployments,
    }


def maintain(store, constructed, edit: str):
    """The agent's release-2 transaction on the queried generation: ``(workspace, result, generation, queries)``."""
    from xax_local_protocol import LocalMutationSession
    from xax_workspace import Workspace

    workspace = Workspace(store, constructed.target)
    queries = 0
    for function in constructed.functions.values():
        workspace.function_nodes(function.cid, 1024)
        queries += 1
    generation = workspace.generation
    return workspace, LocalMutationSession(workspace, expected_generation=generation).commit(edit), generation, queries


def run(write: bool = False) -> dict:
    from xax_compiler import StoreReader
    from xax_construct import construct

    request = json.loads(REQUEST.read_text(encoding="utf-8"))
    constructed = construct(request)
    if write:
        STORES[0].write_bytes(constructed.reader.canonical_bytes())
    gen0 = StoreReader(STORES[0].read_bytes())
    if gen0.canonical_bytes() != constructed.reader.canonical_bytes():
        raise AssertionError("construction request does not reconstruct the committed generation 0")

    workspace, result, generation, queries = maintain(gen0, constructed, MAINTENANCE_EDIT)
    if not result.committed:
        raise AssertionError(f"maintenance edit rejected: {result.diagnostic}")
    diff = workspace.diff(generation, 64)
    if write:
        workspace.save(STORES[1])
    gen1 = StoreReader(STORES[1].read_bytes())
    if gen1.root_cid != result.root:
        raise AssertionError("committed generation 1 differs from the replayed transaction")
    probe, incomplete, _generation, _queries = maintain(gen0, constructed, INCOMPLETE_EDIT)

    serials = _serials()
    if not serials:
        raise RuntimeError("UNAVAILABLE: no AArch64 device on adb")
    with tempfile.TemporaryDirectory(prefix="xax-r6-") as directory:
        work = Path(directory)
        builds0, builds1 = _builds(gen0), _builds(gen1)
        guard = _builds(probe.reader)["test"]["artifact"]
        (work / "guard").write_bytes(guard)
        _adb(serials[0], "push", str(work / "guard"), "/data/local/tmp/xax-r6-guard")
        incomplete_status = int(_adb(serials[0], "shell", "chmod 755 /data/local/tmp/xax-r6-guard; /data/local/tmp/xax-r6-guard; echo $?; "
                                     "rm -f /data/local/tmp/xax-r6-guard").split()[-1])
        devices = {serial: _device(serial) for serial in serials}
        release0 = _release_record(0, gen0, builds0, [{"device": devices[s], **_deploy_and_check(s, builds0, False, work)} for s in serials])
        release1 = _release_record(1, gen1, builds1, [{"device": devices[s], **_deploy_and_check(s, builds1, True, work)} for s in serials])

    return {
        "format": "xax-r6-evidence-v1",
        "decision": "ADR-258",
        "label": "EXECUTED",
        "application": {"name": "xcksum", "kind": "command-line POSIX cksum (stdin to stdout; release 2: cksum -H)",
                        "platform_row": "linux-aarch64", "functions": sorted(constructed.functions), "entries": {"app": "main", "test": "selftest"}},
        "construction": {"request": REQUEST.name, "request_sha256": _sha(REQUEST.read_bytes()), "format": request["format"], "platform": request["platform"],
                         "author": "Claude (AI coding agent), Claude Code session of 2026-10-10, by hand", "reconstructs_generation_0": True},
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
            "this harness: runs builds, installs the executable on each phone over adb, compares it there with toybox cksum (external oracle)",
            "adb and the phones' Linux kernels (platform); the image is static: no libc, loader, or allocator",
            "the test build request is derived from the package's declared 'test' entry",
        ],
    }


def main(argv: list[str]) -> int:
    evidence = run("--write" in argv)
    text = json.dumps(evidence, indent=2) + "\n"
    if "--write" in argv:
        EVIDENCE.write_text(text, encoding="utf-8")
    print(json.dumps({"maintenance": {k: evidence["maintenance"][k] for k in ("committed", "transaction_bytes", "test_guard")},
                      "releases": [{k: r[k] for k in ("generation", "builds", "deployments")} for r in evidence["releases"]]}, indent=1)[:4000])
    ok = all(d["all_match"] and d["selftest_exit_status"] == 0 for r in evidence["releases"] for d in r["deployments"])
    return 0 if ok and evidence["maintenance"]["test_guard"]["selftest_exit_status"] != 0 else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
