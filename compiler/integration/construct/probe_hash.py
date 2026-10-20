"""Probe: hash buffers with the committed S2 hash graph inside a self-contained native host.

Builds one Windows program that owns a 16 MiB byte view, writes a payload at ``DATA``, calls
``xax_selfhost_blake3.hash_span_function`` over it (scratch area inside the same view), and compares the
32-byte digest at ``DIGEST_OFFSET`` against the BLAKE3 the Python reference computes for the same bytes.
Exit 0 means every case matched; 1 means one did not.

The probe answers the questions the construct resolver's derived declarations depend on: a program that
owns its memory holds one live view, so the two-view ``hash_function`` cannot be called from it; with the
single-view variant, does the digest land where the caller reads it, on an input of each length class
(empty, sub-block, multi-block, multi-chunk)?  The scratch area starts past the longest payload, since the
caller must keep the two regions disjoint (an overlap silently hashes overwritten bytes).

    python -B compiler/integration/construct/probe_hash.py build/hash_probe --check
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from xax_build import (ArtifactKind, build, build_profile, build_request, package, resolve_packages,
                       snapshot_store, trust_policy)
from xax_compiler import (
    IntCompare,
    Kind,
    Operation,
    Permission,
    SemanticObject,
    StoreReader,
    bits_type,
    blake3,
    heap_view_type,
    memory_effect_type,
    object_with_refs,
    pointer_type,
    verify_store,
    write_store,
    x86_64_windows_pe_target,
)
from xax_platform import win32_kernel32_api, win32_stdio_api
from xax_selfhost_blake3 import DIGEST_OFFSET, hash_span_function
from xax_structured import B8, B32, B64, Proc

EXTENT = 1 << 24
DATA = 0x10000
GAP = 0x4000  # past the longest payload: the scratch area and the input must not overlap
MEM = memory_effect_type()

CASES = (b"", b"abc", b"x" * 64, b"y" * 65, bytes(range(256)) * 5, bytes(range(256)) * 40)


def build_main(api, stdio, hash_at, aligned):
    proc_type, fs_type, mem_type = api.process_effect, api.filesystem_effect, api.memory_effect
    pointer, view_type = stdio.bytes_rw, heap_view_type(EXTENT)
    declarations = {
        "allocate": api.virtual_alloc,
        "free": api.virtual_free_view(view_type, pointer),
        "exit": api.exit_process,
    }
    p = Proc((("proc", proc_type), ("fs", fs_type), ("mem", mem_type)))

    def c32(value):
        return p.const(value, B32)

    def add(left, right):
        return p.bin(Operation.ADD_WRAP, left, right, B32)

    def at(offset):
        return p.op1(Operation.ADDRESS_OFFSET, (p["vp"],), pointer, attributes=(offset,))

    def at4(offset):
        return p.op1(Operation.ADDRESS_OFFSET, (p["vp"],), aligned, attributes=(offset,))

    def ld32(offset):
        value, memory = p.op(Operation.CHECKED_LOAD_BITS_LE, (p["base"], offset, p["mem"]), (B32, mem_type),
                             attributes=(4, 1))
        p["mem"] = memory
        return value

    def st64(offset, value):
        (memory,) = p.op(Operation.CHECKED_STORE_BITS_LE, (p["base"], offset, value, p["mem"]), (mem_type,),
                         attributes=(8, 1))
        p["mem"] = memory

    block, owner, memory = p.op(Operation.CALL_FOREIGN,
                                (p.const(0, B64), p.const(EXTENT, B64), c32(0x3000), c32(4), p["mem"]),
                                (api.heap_ptr_rw, api.heap_resource, mem_type), entity=declarations["allocate"])
    p["mem"] = memory
    base, view, memory = p.op(Operation.HEAP_VIEW, (block, owner, p["mem"]),
                              (pointer, view_type, mem_type), attributes=(EXTENT, 4))
    p["mem"] = memory
    p.let("vp", pointer, base)
    p.let("vv", view_type, view)
    p.let("base", pointer, at(0))
    p.let("code", B32, c32(0))
    p.let("matched", B32, c32(0))

    for payload in CASES:
        for index in range(0, max(len(payload), 1), 8):
            chunk = payload[index:index + 8].ljust(8, b"\0")
            st64(c32(DATA + index), p.const(int.from_bytes(chunk, "little"), B64))
        expected = blake3(payload).digest()
        ptr_out, view_out, memory_out = p.op(
            Operation.CALL_DIRECT,
            (at4(0), p["vv"], p["mem"], p.const(DATA, B64), p.const(len(payload), B64)),
            (aligned, view_type, mem_type),
            entity=hash_at,
        )
        p["vv"], p["mem"] = view_out, memory_out
        p["matched"] = c32(0)
        for index in range(0, 32, 4):
            got = ld32(c32(DATA + GAP + DIGEST_OFFSET + index))
            want = int.from_bytes(expected[index:index + 4], "little")
            p.if_(p.cmp(IntCompare.EQ, got, c32(want), B32),
                  lambda _p: p.__setitem__("matched", add(p["matched"], c32(4))))
        p.if_(p.cmp(IntCompare.NE, p["matched"], c32(32), B32), lambda _p: p.__setitem__("code", c32(1)))

    p["mem"] = p.op(Operation.CALL_FOREIGN, (p["vp"], p.const(0, B64), c32(0x8000), p["vv"], p["mem"]),
                    (B32, mem_type), entity=declarations["free"])[1]
    p["proc"] = p.op1(Operation.CALL_FOREIGN, (p["code"], p["proc"]), proc_type, entity=declarations["exit"])
    p.ret(p["code"], p["proc"], p["fs"], p["mem"])
    return p.function((B32, proc_type, fs_type, mem_type)), tuple(p.graph.objects.values())


def build_program(name=b"xax-construct-hash-probe"):
    aligned = pointer_type(B8, Permission.READ_WRITE, 4, space=2)
    hash_at, hash_objects = hash_span_function(aligned, heap_view_type(EXTENT), DATA + GAP)
    api = win32_kernel32_api()
    stdio = win32_stdio_api(api)
    entry, objects = build_main(api, stdio, hash_at, aligned)
    platform = (*api.types, *api.symbols, *stdio.types, *stdio.symbols)
    module = object_with_refs(Kind.MODULE, (entry,))
    app = package(name, (module,), build_entries=((b"app", entry),))
    target, profile, policy = x86_64_windows_pe_target(), build_profile(), trust_policy()
    request = build_request(app, b"app", target, profile, requested_artifacts=(ArtifactKind.NATIVE_IMAGE,))
    everything = (*objects, *hash_objects, *platform, module, app, target, profile, policy, request)
    snapshot = snapshot_store(resolve_packages(request, everything, policy, name + b"-v1"), everything)

    available = {item.cid: item for item in snapshot.objects()}
    reachable: dict[bytes, SemanticObject] = {}
    pending = [request.cid]
    while pending:
        cid = pending.pop()
        if cid not in reachable:
            reachable[cid] = available[cid]
            pending.extend(available[cid].references)
    reader = StoreReader(write_store(request.cid, tuple(reachable.values())))
    verify_store(reader)
    return reader, snapshot, build(snapshot, request.cid)


def main(argv):
    out = Path(argv[1])
    reader, snapshot, artifact = build_program()
    out.mkdir(parents=True, exist_ok=True)
    (out / "probe.xax").write_bytes(reader.canonical_bytes())
    executable = out / "probe.exe"
    executable.write_bytes(artifact.artifact)
    entry = next(item for item in reader.objects() if item.kind == Kind.FUNCTION)
    print(f"entry     {reader.root_cid.hex()}")
    print(f"entry fn  {entry.cid.hex()}")
    print(f"store     {len(reader.canonical_bytes())} bytes")
    print(f"artifact  {len(artifact.artifact)} bytes")
    if "--check" in argv:
        result = subprocess.run([str(executable)], capture_output=True)
        print(f"hash      exit={result.returncode} cases={len(CASES)} "
              f"{'MATCH' if result.returncode == 0 else 'DIFF'}")
        return 0 if result.returncode == 0 else 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
