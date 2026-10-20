"""Build tooling: the editable seed store the native compiler-backed tools open.

The seed is a tiny windows-x86_64 program whose entry returns a constant through ``ExitProcess``.  It is written as a
store rooted at a **build request** (a form-2 build root), because that is the root kind the native ``edit``/``resolve``
commands accept and rebuild; a store rooted at the construction release request or at a resolved snapshot is not
editable (``XAX.WORKSPACE.TOPOLOGY`` / ``WORKSPACE-SUPPORTED-USER``).

Python here is build tooling in the XAX repository, run once when the MCP artifacts are prepared; the deployed
server never runs it and never invokes a Python interpreter.  ``chain.py`` drives the same seed through the native
compiler.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from dsl import Program  # noqa: E402

ENTRY = "app"
VALUE = 40
STORE_NAME = "xax-mcp-seed.xax"


def seed_request() -> dict:
    """The ``xax-construct-v1`` carrier for the seed program."""
    P = Program("xax_mcp_seed", {}, {})
    main = P.fn("main", (), [], [], [("code", "b32")], entry=True)
    b = main.entry
    b.set("code", ("b32", VALUE))
    (proc,) = b.op("call.foreign", ["code", "proc"], ["proc"], entity="win32.exit_process")
    b.set("proc", proc)
    b.ret_raw("code", "proc", "fs")
    return P.carrier({ENTRY: "main"}, ENTRY)


def write_seed(xax_src: Path, out: Path) -> dict:
    """Construct the seed and write its build-request store (and a reference snapshot/artifact)."""
    sys.path.insert(0, str(xax_src))
    from xax_build import ArtifactKind, build, build_profile, build_request, resolve_packages, snapshot_store, trust_policy
    from xax_compiler import Kind, StoreReader, verify_store, write_store, x86_64_windows_pe_target
    from xax_construct import construct

    constructed = construct(seed_request())
    objects = tuple(constructed.reader.objects())
    package = next(obj for obj in objects if obj.kind == Kind.PACKAGE)
    target, profile, policy = x86_64_windows_pe_target(), build_profile(), trust_policy()
    request = build_request(package, ENTRY.encode(), target, profile, requested_artifacts=(ArtifactKind.NATIVE_IMAGE,))
    everything = (*objects, target, profile, policy, request)
    snapshot = snapshot_store(resolve_packages(request, everything, policy, b"resolver-v1"), everything)

    # A store rooted at the build request itself: reachable objects only (canonical stores reject unreachable ones).
    available = {obj.cid: obj for obj in snapshot.objects()}
    reachable: dict[bytes, object] = {}
    pending = [request.cid]
    while pending:
        cid = pending.pop()
        if cid not in reachable:
            reachable[cid] = available[cid]
            pending.extend(available[cid].references)
    reader = StoreReader(write_store(request.cid, tuple(reachable.values())))
    verify_store(reader)

    out.mkdir(parents=True, exist_ok=True)
    (out / STORE_NAME).write_bytes(reader.canonical_bytes())
    (out / "xax-mcp-seed-snapshot.xax").write_bytes(snapshot.canonical_bytes())
    (out / "xax-mcp-seed.exe").write_bytes(build(snapshot, request.cid).artifact)
    return {"root": reader.root_cid.hex(), "store_bytes": len(reader.canonical_bytes()), "target": "windows-x86_64"}


if __name__ == "__main__":
    print(json.dumps(write_seed(Path(sys.argv[1]), Path(sys.argv[2])), indent=1))
