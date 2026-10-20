"""Authoring of the native construct host (work in progress, step 2 of README.md).

The host is a windows-x86_64 program authored with ``Proc`` over ``GraphBuilder`` -- the same
construction path ``probe_seed.py`` checks against the reference objects.  It exists to carry the
bytes a construct command needs in and out of the process without an interpreter:

    host.exe <carrier path> <store path>

Step 2 only proves the transport: the two command-line paths are extracted, the input file is read
into one heap view and written back out.  The carrier decoder replaces the copy in step 3, and the
store writer in step 5.

Input is the command line (``GetCommandLineA``/``lstrcpynA``), the way every Windows host here reads
it.  A quoted path is *not* understood: the quoting characters would reach ``_open``, which then
fails, and the process exits non-zero rather than guessing (fail closed).

Build (Python is build tooling here, exactly as every ``xax_selfhost_*`` module uses it)::

    python compiler/integration/construct/host.py <out directory>

writes ``host.xax`` (a build-request store the native driver accepts for ``resolve``), the resolved
``host-snapshot.xax`` and the built ``host.exe``.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import xax_compiler as X
from xax_compiler import IntCompare, Operation, foreign_function_symbol, heap_view_type, x86_64_windows_pe_target
from xax_platform import win32_kernel32_api, win32_stdio_api
from xax_structured import B8, B32, B64, Proc

# One heap view holds everything, so a single allocation and a single linear memory token cover the
# command-line copy, both path buffers and the data buffer.  Offsets are fixed and the work is
# bounded: an input that fills the data region is refused rather than truncated.
EXTENT = 8 << 20
COMMAND_CAP = 32768
PATH_ONE = 0x8000
PATH_TWO = 0x9000
PATH_CAP = 4096
DATA = 0x10000
DATA_CAP = 4 << 20
SPACE = 32

OPEN_READ, OPEN_WRITE, CREATE_MODE = 0x8000, 0x8301, 0x0180

EXIT_BAD_OPEN_IN = 2
EXIT_BAD_OPEN_OUT = 3
EXIT_READ = 4
EXIT_TOO_LARGE = 5
EXIT_SHORT_WRITE = 6
EXIT_TRAILING = 7


def _imports(api, pointer):
    """The foreign declarations the host calls, as the platform declares ``win32.import``."""
    process, filesystem, memory = api.process_effect, api.filesystem_effect, api.memory_effect
    abi = b"win64-c"
    return {
        "command_line": foreign_function_symbol(b"kernel32.dll", b"GetCommandLineA", (process,), (B64, process), abi=abi),
        "copy": foreign_function_symbol(b"kernel32.dll", b"lstrcpynA", (pointer, B64, B32, memory), (B64, memory), abi=abi),
        "open": foreign_function_symbol(b"msvcrt.dll", b"_open", (pointer, B32, B32, filesystem), (B32, filesystem), abi=abi),
        "read": foreign_function_symbol(b"msvcrt.dll", b"_read", (B32, pointer, B32, filesystem, memory),
                                        (B32, filesystem, memory), abi=abi),
        "write": foreign_function_symbol(b"msvcrt.dll", b"_write", (B32, pointer, B32, filesystem, memory),
                                         (B32, filesystem, memory), abi=abi),
        "close": foreign_function_symbol(b"msvcrt.dll", b"_close", (B32, filesystem), (B32, filesystem), abi=abi),
        "exit": api.exit_process,
        "allocate": api.virtual_alloc,
    }


def build_main(api, stdio):
    """``main(proc, fs, mem) -> (b32, proc, fs, mem)``: copy ``argv[1]`` to ``argv[2]``."""
    proc_type, fs_type, mem_type = api.process_effect, api.filesystem_effect, api.memory_effect
    pointer_type, view_type = stdio.bytes_rw, heap_view_type(EXTENT)
    declarations = _imports(api, pointer_type)
    declarations["free"] = api.virtual_free_view(view_type, pointer_type)
    p = Proc((("proc", proc_type), ("fs", fs_type), ("mem", mem_type)))

    def c32(value):
        return p.const(value, B32)

    def add(left, right):
        return p.bin(Operation.ADD_WRAP, left, right, B32)

    def load_byte(offset):
        value, memory = p.op(Operation.CHECKED_LOAD_BITS_LE, (p["vp"], offset, p["mem"]), (B8, mem_type),
                             attributes=(1, 1))
        p["mem"] = memory
        return value

    def store_byte(offset, value):
        (memory,) = p.op(Operation.CHECKED_STORE_BITS_LE, (p["vp"], offset, value, p["mem"]), (mem_type,),
                         attributes=(1, 1))
        p["mem"] = memory

    def address(offset):
        return p.op1(Operation.ADDRESS_OFFSET, (p["vp"],), pointer_type, attributes=(offset,))

    def exit_with(code):
        # One exit for every path: the view is a linear token, so it is handed back exactly once,
        # and the process ends with the code the first failed step recorded.
        p["mem"] = p.op(Operation.CALL_FOREIGN,
                        (p["vp"], p.const(0, B64), c32(0x8000), p["vv"], p["mem"]), (B32, mem_type),
                        entity=declarations["free"])[1]
        p["proc"] = p.op1(Operation.CALL_FOREIGN, (code, p["proc"]), proc_type, entity=declarations["exit"])
        p.ret(code, p["proc"], p["fs"], p["mem"])

    def guard(work):
        """Run ``work`` only while no step has failed."""
        p.if_(p.cmp(IntCompare.EQ, p["code"], c32(0), B32), lambda _p: work())

    def fail_if(condition, code):
        """Record ``code`` for the exit when ``condition`` holds and nothing has failed yet."""
        def mark(_p):
            p["code"] = c32(code)
        p.if_(p.all_of(p.cmp(IntCompare.EQ, p["code"], c32(0), B32), condition), mark)

    # One heap block: command-line copy, two path buffers, data buffer.
    block, owner, memory = p.op(
        Operation.CALL_FOREIGN, (p.const(0, B64), p.const(EXTENT, B64), c32(0x3000), c32(4), p["mem"]),
        (api.heap_ptr_rw, api.heap_resource, mem_type), entity=declarations["allocate"])
    p["mem"] = memory
    base, view, memory = p.op(Operation.HEAP_VIEW, (block, owner, p["mem"]), (pointer_type, view_type, mem_type),
                              attributes=(EXTENT, 1))
    p["mem"] = memory
    p.let("vp", pointer_type, base)
    p.let("vv", view_type, view)

    line, process = p.op(Operation.CALL_FOREIGN, (p["proc"],), (B64, proc_type), entity=declarations["command_line"])
    p["proc"] = process
    _, memory = p.op(Operation.CALL_FOREIGN, (address(0), line, c32(COMMAND_CAP), p["mem"]), (B64, mem_type),
                     entity=declarations["copy"])
    p["mem"] = memory

    p.let("code", B32, c32(0))
    p.let("i", B32, c32(0))
    p.let("n", B32, c32(0))
    p.let("byte", B32, c32(0))
    p.let("fd", B32, c32(0))
    p.let("got", B32, c32(0))
    p.let("written", B32, c32(0))

    def fetch():
        p["byte"] = p.widen(load_byte(p["i"]), B32)

    def advance():
        p["i"] = add(p["i"], c32(1))

    def live():
        return p.all_of(p.cmp(IntCompare.ULT, p["i"], c32(COMMAND_CAP), B32),
                        p.cmp(IntCompare.NE, p["byte"], c32(0), B32))

    def separated():
        return p.all_of(live(), p.cmp(IntCompare.EQ, p["byte"], c32(SPACE), B32))

    def word(limit):
        return p.all_of(live(), p.cmp(IntCompare.NE, p["byte"], c32(SPACE), B32),
                        p.cmp(IntCompare.ULT, p["n"], c32(limit), B32))

    def scan(condition):
        def check():
            fetch()
            return condition()
        p.while_(lambda _p: check(), lambda _p: advance())

    def copy_word(destination, limit):
        def body(_p):
            store_byte(add(c32(destination), p["n"]), load_byte(p["i"]))
            p["n"] = add(p["n"], c32(1))
            advance()
        p.while_(lambda _p: (fetch(), word(limit))[1], body)
        store_byte(add(c32(destination), p["n"]), p.const(0, B8))
        p["n"] = c32(0)

    # argv: the program name, then the carrier path, then the store path.  Anything after the store
    # path (including quoting, which this host does not interpret) is refused.
    scan(separated)
    scan(lambda: p.all_of(live(), p.cmp(IntCompare.NE, p["byte"], c32(SPACE), B32)))
    scan(separated)
    copy_word(PATH_ONE, PATH_CAP - 1)
    scan(separated)
    copy_word(PATH_TWO, PATH_CAP - 1)
    scan(separated)
    fail_if(p.cmp(IntCompare.NE, p["byte"], c32(0), B32), EXIT_TRAILING)

    def read_input():
        # Read the input, refuse anything the buffers cannot hold whole.
        p["fd"], p["fs"] = p.op(Operation.CALL_FOREIGN, (address(PATH_ONE), c32(OPEN_READ), c32(0), p["fs"]),
                                (B32, fs_type), entity=declarations["open"])
        fail_if(p.cmp(IntCompare.SLT, p["fd"], c32(0), B32), EXIT_BAD_OPEN_IN)
        p["got"], p["fs"], p["mem"] = p.op(Operation.CALL_FOREIGN,
                                           (p["fd"], address(DATA), c32(DATA_CAP), p["fs"], p["mem"]),
                                           (B32, fs_type, mem_type), entity=declarations["read"])
        p["fs"] = p.op(Operation.CALL_FOREIGN, (p["fd"], p["fs"]), (B32, fs_type), entity=declarations["close"])[1]
        fail_if(p.cmp(IntCompare.SLT, p["got"], c32(1), B32), EXIT_READ)
        fail_if(p.cmp(IntCompare.UGE, p["got"], c32(DATA_CAP), B32), EXIT_TOO_LARGE)

    def write_output():
        p["fd"], p["fs"] = p.op(Operation.CALL_FOREIGN, (address(PATH_TWO), c32(OPEN_WRITE), c32(CREATE_MODE),
                                                         p["fs"]), (B32, fs_type), entity=declarations["open"])
        fail_if(p.cmp(IntCompare.SLT, p["fd"], c32(0), B32), EXIT_BAD_OPEN_OUT)
        p["written"], p["fs"], p["mem"] = p.op(Operation.CALL_FOREIGN,
                                               (p["fd"], address(DATA), p["got"], p["fs"], p["mem"]),
                                               (B32, fs_type, mem_type), entity=declarations["write"])
        p["fs"] = p.op(Operation.CALL_FOREIGN, (p["fd"], p["fs"]), (B32, fs_type), entity=declarations["close"])[1]
        fail_if(p.cmp(IntCompare.NE, p["written"], p["got"], B32), EXIT_SHORT_WRITE)

    guard(read_input)
    guard(write_output)
    exit_with(p["code"])
    return p.function((B32, proc_type, fs_type, mem_type)), tuple(p.graph.objects.values())


def build_host():
    """Assemble, resolve and build the host; returns the request-rooted store and the artifact."""
    from xax_build import (ArtifactKind, build, build_profile, build_request, package, resolve_packages,
                           snapshot_store, trust_policy)
    from xax_compiler import Kind, StoreReader, object_with_refs, verify_store, write_store

    api = win32_kernel32_api()
    stdio = win32_stdio_api(api)
    entry, objects = build_main(api, stdio)
    platform_types = (*api.types, *api.symbols, *stdio.types, *stdio.symbols)
    module = object_with_refs(Kind.MODULE, (entry,))
    app = package(b"xax-construct-host", (module,), build_entries=((b"app", entry),))
    target, profile, policy = x86_64_windows_pe_target(), build_profile(), trust_policy()
    request = build_request(app, b"app", target, profile, requested_artifacts=(ArtifactKind.NATIVE_IMAGE,))
    everything = (*objects, *platform_types, module, app, target, profile, policy, request)
    snapshot = snapshot_store(resolve_packages(request, everything, policy, b"xax-construct-host-v1"), everything)

    available = {item.cid: item for item in snapshot.objects()}
    reachable: dict[bytes, object] = {}
    pending = [request.cid]
    while pending:
        cid = pending.pop()
        if cid not in reachable:
            reachable[cid] = available[cid]
            pending.extend(available[cid].references)
    reader = StoreReader(write_store(request.cid, tuple(reachable.values())))
    verify_store(reader)
    return reader, snapshot, build(snapshot, request.cid)


def check(out: Path) -> int:
    """Run the built host over a byte pattern: it must copy it exactly and exit 0."""
    executable, source, target = out / "host.exe", out / "in.bin", out / "out.bin"
    payload = bytes(range(256)) * 4
    source.write_bytes(payload)
    target.unlink(missing_ok=True)
    result = subprocess.run([str(executable), str(source), str(target)], capture_output=True)
    copied = target.read_bytes() if target.exists() else b""
    ok = result.returncode == 0 and copied == payload
    print(f"check     {'PASS' if ok else 'FAIL'} exit={result.returncode} bytes={len(copied)}")
    return 0 if ok else 1


def main(argv):
    out = Path(argv[1])
    reader, snapshot, artifact = build_host()
    out.mkdir(parents=True, exist_ok=True)
    (out / "host.xax").write_bytes(reader.canonical_bytes())
    (out / "host-snapshot.xax").write_bytes(snapshot.canonical_bytes())
    (out / "host.exe").write_bytes(artifact.artifact)
    entry = next(item for item in reader.objects() if item.kind == X.Kind.FUNCTION)
    print(f"entry     {entry.cid.hex()}")
    print(f"root      {reader.root_cid.hex()}")
    print(f"store     {len(reader.canonical_bytes())} bytes")
    print(f"artifact  {len(artifact.artifact)} bytes")
    return check(out) if "--check" in argv else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
