"""Constructs ``xax-mcp-sandbox``: the fixed executor boundary that runs a built artifact inside an OS sandbox.

Integration tooling in the XAX repository: this module writes the ``xax-construct-v1`` request for the launcher.
``xax_construct`` turns it into a verified canonical store (the authoritative program) and ``xax_build`` turns that
store into a PE32+ executable.  The launcher itself (job object, AppContainer, pipes, supervision, fail-closed
observation) is the XAX program; Python is not on its runtime path.

    python compiler/integration/mcp/sandbox.py <xax compiler/src> <output directory>

Interface (fixed, audited boundary; the server builds the argument vector, never a shell):

    xax-mcp-sandbox <artifact path> <work directory>

The launcher copies the artifact into ``<work>\\sandbox-run\\prog.exe``, launches it with no command line, and writes

    <work>\\sandbox-out.bin     child stdout (bounded)
    <work>\\sandbox-err.bin     child stderr (bounded)
    <work>\\sandbox-result.bin  b32 exit code, b32 status flags, b64 wall milliseconds

The launcher exits 0 when the sandbox ran (the result file holds the child's status) and a small non-zero code when
the sandbox could not be established (fail closed).  Stage 2a: process creation, wait and exit code; the AppContainer
and job object follow.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from dsl import Program  # noqa: E402

NATIVE_XAX_COMMIT = "f79b532fd4651ba808676d02f4b038e2cc271e6a"  # XAX main, 2026-10-19

OUT_CAP = 1024 * 1024
VIEWS = {"O": 8 * 1024 * 1024, "N": 64, "A": 32768 + 64, "W": 256}

O_OUT = 4 * 1024 * 1024  # captured stdout
O_ERR = 5 * 1024 * 1024  # captured stderr
O_SCR = 6 * 1024 * 1024  # structures, paths and small slots

S_SI, S_PI, S_SA = O_SCR + 0, O_SCR + 128, O_SCR + 160
S_TMP = O_SCR + 768
S_HOUTR, S_HOUTW, S_HERRR, S_HERRW = O_SCR + 832, O_SCR + 840, O_SCR + 848, O_SCR + 856
S_AVAIL, S_NREAD, S_AVAIL2, S_NREAD2 = O_SCR + 864, O_SCR + 868, O_SCR + 872, O_SCR + 876
P_ART, P_DIR, P_RUN, P_IMG = O_SCR + 1024, O_SCR + 2048, O_SCR + 3072, O_SCR + 4096
P_OUT, P_ERR, P_RES, P_NUL = O_SCR + 6144, O_SCR + 7168, O_SCR + 8192, O_SCR + 9216
S_JOB, S_ATTR = O_SCR + 10240, O_SCR + 10496
S_SEC, S_EA = O_SCR + 11520, O_SCR + 11552
S_OLDACL, S_NEWACL, S_SD, S_SID = O_SCR + 11616, O_SCR + 11624, O_SCR + 11632, O_SCR + 11640
S_ASIZE, S_CHILD, S_MITIG, S_INJOB = O_SCR + 11648, O_SCR + 11656, O_SCR + 11664, O_SCR + 11672
S_HLIST = O_SCR + 11680
W_IMG, W_RUN, W_CMD, W_NAME = O_SCR + 16384, O_SCR + 18432, O_SCR + 20480, O_SCR + 20608
R_BUF = O_SCR + 24576  # the 16-byte result

CREATE_UNICODE_ENVIRONMENT, DETACHED_PROCESS, STARTF_USESTDHANDLES = 0x400, 0x8, 0x100
EXTENDED_STARTUPINFO_PRESENT = 0x80000
CREATE_SUSPENDED = 0x4
PIPE_BUFFER = 65536
WALL_MS = 10_000
FLAG_TIMEOUT, FLAG_TRUNCATED = 1, 4
# job object limits: five seconds of CPU, one active process, 256 MiB, kill the tree when the handle closes
CPU_LIMIT_100NS, MEMORY_LIMIT = 50_000_000, 256 * 1024 * 1024
JOB_LIMITS = 0x2 | 0x8 | 0x100 | 0x400 | 0x2000


def build_program() -> Program:  # noqa: C901
    P = Program("xax_mcp_sandbox", VIEWS, {"N": "u32p"})
    b32 = lambda v: ("b32", v)  # noqa: E731
    fns: dict = {}

    def fn(name, views, params, returns, locals_=()):
        f = P.fn(name, views, params, returns, list(locals_))
        fns[name] = f
        return f

    def addr(b, view, off):
        return b.op1("address.offset", [f"{view}p"], P.ptr_type(view), attrs=[off])

    def raw(b, ref):
        return b.op1("pointer.address", [ref], "b64", attrs=[1])

    def icall(b, dll, symbol, inputs, results, *args):
        return b.op("call.foreign", list(args), results, entity={"win32.import": [dll, symbol, inputs, results]})

    def place(b, off, data: bytes):
        for k, byte in enumerate(data):
            b.store("O", b32(off + k), ("b8", byte), 1)

    def store64(b, off, value):
        b.store("O", b32(off), ("b64", value), 8)

    # -- path helpers ------------------------------------------------------------------------------------------
    f = fn("copyz", ("O",), [("dst", "b32"), ("src", "b32")], ["b32"], [("c", "b32")])
    f.entry.set("c", b32(0))
    loop = f.block()
    f.entry.jump(loop)
    loop.set("c", loop.load("O", "src"))
    done, body = loop.if_(loop.cmp("eq", "c", b32(0)))
    body.store("O", "dst", "c")
    body.set("dst", body.add("dst", b32(1)))
    body.set("src", body.add("src", b32(1)))
    body.jump(loop)
    done.store("O", "dst", ("b8", 0))
    done.ret("dst")

    suffixes: dict[bytes, object] = {}

    def suffix(data: bytes):
        if data not in suffixes:
            f = fn(f"suf{len(suffixes)}", ("O",), [("i", "b32")], ["b32"])
            bb = f.entry
            for k, byte in enumerate(data):
                bb.store("O", bb.add("i", b32(k)), ("b8", byte), 1)
            bb.store("O", bb.add("i", b32(len(data))), ("b8", 0), 1)
            bb.ret(bb.add("i", b32(len(data))))
            suffixes[data] = f
        return suffixes[data]

    def join(b, dst, base, tail: bytes):
        b.call(fns["copyz"], b32(dst), b32(base), into=("i",))
        b.call(suffix(tail), "i", into=("i",))

    # -- take_token: skip blanks, copy one (optionally quoted) argument into O[dst], NUL terminated -----------------
    f = fn("take_token", ("A", "O"), [("i", "b32"), ("dst", "b32"), ("cap", "b32")], ["b32"],
           [("c", "b32"), ("j", "b32"), ("q", "b32")])
    DONE = f.block()
    DONE.store("O", "j", ("b8", 0))
    DONE.ret("i")
    b = f.entry
    b.set("j", "dst")
    b.set("q", b32(0))
    b.set("c", b32(0))
    skip = f.block()
    b.jump(skip)
    skip.set("c", skip.load("A", "i"))
    blank, first = skip.if_(skip.cmp("ne", skip.bor(skip.flag("eq", "c", b32(32)), skip.flag("eq", "c", b32(9))), b32(0)))
    blank.set("i", blank.add("i", b32(1)))
    blank.jump(skip)
    quoted, plain = first.if_(first.cmp("eq", "c", b32(34)))
    quoted.set("q", b32(1))
    quoted.set("i", quoted.add("i", b32(1)))
    start = f.block()
    quoted.jump(start)
    plain.jump(start)
    read = f.block()
    start.jump(read)
    read.set("c", read.load("A", "i"))
    close, rest = read.if_(read.cmp("ne", read.band("q", read.flag("eq", "c", b32(34))), b32(0)))
    close.set("i", close.add("i", b32(1)))
    close.jump(DONE)
    at_end, take = rest.if_(rest.cmp("eq", "c", b32(0)))
    at_end.jump(DONE)
    stop, keep = take.if_(take.cmp("ne", take.band(take.sub(b32(1), "q"),
                                                   take.bor(take.flag("eq", "c", b32(32)),
                                                            take.flag("eq", "c", b32(9)))), b32(0)))
    stop.jump(DONE)
    # copy while the destination still has room for the byte and its terminator; past that, only advance
    room, full = keep.if_(keep.cmp("ult", "j", keep.sub(keep.add("dst", "cap"), b32(1))))
    full.set("i", full.add("i", b32(1)))
    full.jump(read)
    room.store("O", "j", "c")
    room.set("j", room.add("j", b32(1)))
    room.set("i", room.add("i", b32(1)))
    room.jump(read)

    # -- write a buffer to a file (spliced into the caller, like the server's emit_write) --------------------------
    def emit_write(b, path_ref, src_off, length):
        fd, fs = icall(b, "msvcrt.dll", "_open", ["ptr", "b32", "b32", "fs"], ["b32", "fs"],
                       path_ref, b32(0x8301), b32(0x0180), "fs")
        b.set("fs", fs)
        b.set("fd", fd)
        bad, ok, end = b.fn.block(), b.fn.block(), b.fn.block()
        b.branch(b.cmp("slt", "fd", b32(0)), bad, ok)
        bad.jump(end)
        written, fs, mem = icall(ok, "msvcrt.dll", "_write", ["b32", "ptr", "b32", "fs", "mem"],
                                 ["b32", "fs", "mem"], "fd", addr(ok, "O", src_off), length, "fs", "Om")
        ok.set("Om", mem)
        ok.set("fs", fs)
        _, fs = icall(ok, "msvcrt.dll", "_close", ["b32", "fs"], ["b32", "fs"], "fd", "fs")
        ok.set("fs", fs)
        ok.jump(end)
        return end

    views = tuple(VIEWS)
    main_locals = [(f"{v}p", P.ptr_type(v)) for v in views] + [(f"{v}v", P.view_type(v)) for v in views]
    main_locals += [(n, "b32") for n in ("i", "code", "ok", "n", "written", "fd", "rc", "flags", "t0", "now", "avail", "gotout", "goterr", "hr")]
    main_locals += [(n, "b64") for n in ("hnul", "hproc", "hthread", "houtr", "houtw", "herrr", "herrw", "hjob", "sid")]
    main = P.fn("main", views, [], [], main_locals, entry=True)
    b = main.entry
    for v, extent in VIEWS.items():
        pointer, owner, mem = b.op("call.foreign", [("b64", 0), ("b64", max(extent, 4096)), b32(0x3000), b32(4), f"{v}m"],
                                   ["win32.heap_ptr_rw", "win32.heap_resource", "mem"], entity="win32.virtual_alloc")
        vp, vv, vm = b.op("heap.view", [pointer, owner, mem], [P.ptr_type(v), P.view_type(v), "mem"],
                          attrs=[extent, 4 if v == "N" else 1])
        b.set(f"{v}p", vp)
        b.set(f"{v}v", vv)
        b.set(f"{v}m", vm)
    for name in ("i", "code", "ok", "n", "written", "fd", "rc", "flags", "t0", "now", "avail", "gotout", "goterr", "hr"):
        b.set(name, b32(0))
    for name in ("hnul", "hproc", "hthread", "houtr", "houtw", "herrr", "herrw", "hjob", "sid"):
        b.set(name, ("b64", 0))
    FAIL, DONE = main.block(), main.block()
    # command line -> A, then three tokens: program, artifact path, work directory
    command_line, proc = b.op("call.foreign", ["proc"], ["b64", "proc"],
                              entity={"win32.import": ["kernel32.dll", "GetCommandLineA", ["proc"], ["b64", "proc"]]})
    b.set("proc", proc)
    _, mem = b.op("call.foreign", ["Ap", command_line, b32(32768), "Am"], ["b64", "mem"],
                  entity={"win32.import": ["kernel32.dll", "lstrcpynA", ["ptr", "b64", "b32", "mem"], ["b64", "mem"]]})
    b.set("Am", mem)
    b.call(fns["take_token"], b32(0), b32(P_NUL), b32(1024), into=("i",))
    b.call(fns["take_token"], "i", b32(P_ART), b32(1024), into=("i",))
    b.call(fns["take_token"], "i", b32(P_DIR), b32(1024), into=("i",))
    join(b, P_RUN, P_DIR, b"\\sandbox-run")
    join(b, P_IMG, P_RUN, b"\\prog.exe")
    join(b, P_OUT, P_DIR, b"\\sandbox-out.bin")
    join(b, P_ERR, P_DIR, b"\\sandbox-err.bin")
    join(b, P_RES, P_DIR, b"\\sandbox-result.bin")
    place(b, P_NUL, b"NUL\x00")
    # the run directory (ignore "already exists"), then copy the artifact in
    _, fs = icall(b, "kernel32.dll", "CreateDirectoryA", ["ptr", "b64", "fs"], ["b32", "fs"],
                  addr(b, "O", P_RUN), ("b64", 0), "fs")
    b.set("fs", fs)
    # -- AppContainer: a capability-less LPAC.  Windows confirms the containment at launch; a refusal fails closed. ----
    place(b, W_NAME, "xax-mcp.sandbox".encode("utf-16-le"))
    b.store("O", b32(W_NAME + 32), ("b16", 0), 2)
    hr, = icall(b, "userenv.dll", "CreateAppContainerProfile", ["ptr", "ptr", "ptr", "b64", "b32", "ptr"], ["b32"],
                addr(b, "O", W_NAME), addr(b, "O", W_NAME), addr(b, "O", W_NAME),
                ("b64", 0), b32(0), addr(b, "O", S_SID))
    b.set("hr", hr)
    made, derive = b.if_(b.cmp("eq", "hr", b32(0)))
    hr2, = icall(derive, "userenv.dll", "DeriveAppContainerSidFromAppContainerName", ["ptr", "ptr"], ["b32"],
                 addr(derive, "O", W_NAME), addr(derive, "O", S_SID))
    derive.set("hr", hr2)
    derive.jump(made)
    b = made
    bad_sid, have_sid = b.if_(b.cmp("ne", "hr", b32(0)))
    bad_sid.set("code", b32(51))
    bad_sid.jump(FAIL)
    b = have_sid
    b.set("sid", b.load("O", b32(S_SID), 8))
    # grant the container read and execute on the run directory (never write, never full control)
    _, = icall(b, "advapi32.dll", "GetNamedSecurityInfoW",
               ["ptr", "b32", "b32", "b64", "b64", "ptr", "b64", "ptr"], ["b32"],
               addr(b, "O", W_RUN), b32(1), b32(4), ("b64", 0), ("b64", 0),
               addr(b, "O", S_OLDACL), ("b64", 0), addr(b, "O", S_SD))
    b.store("O", b32(S_EA + 0), ("b32", 0xA0000000), 4)
    b.store("O", b32(S_EA + 4), b32(1), 4)
    b.store("O", b32(S_EA + 8), b32(3), 4)
    store64(b, S_EA + 16, 0)
    b.store("O", b32(S_EA + 24), b32(0), 4)
    b.store("O", b32(S_EA + 28), b32(0), 4)
    b.store("O", b32(S_EA + 32), b32(0), 4)
    b.store("O", b32(S_EA + 40), "sid", 8)
    _, = icall(b, "advapi32.dll", "SetEntriesInAclW", ["b32", "ptr", "b64", "ptr"], ["b32"],
               b32(1), addr(b, "O", S_EA), b.load("O", b32(S_OLDACL), 8), addr(b, "O", S_NEWACL))
    _, = icall(b, "advapi32.dll", "SetNamedSecurityInfoW",
               ["ptr", "b32", "b32", "b64", "b64", "b64", "b64"], ["b32"],
               addr(b, "O", W_RUN), b32(1), b32(4), ("b64", 0), ("b64", 0),
               b.load("O", b32(S_NEWACL), 8), ("b64", 0))
    _, = icall(b, "kernel32.dll", "LocalFree", ["b64"], ["b64"], b.load("O", b32(S_NEWACL), 8))
    _, = icall(b, "kernel32.dll", "LocalFree", ["b64"], ["b64"], b.load("O", b32(S_SD), 8))
    # SECURITY_CAPABILITIES: { AppContainerSid, NULL capabilities, 0, 0 }
    b.store("O", b32(S_SEC + 0), "sid", 8)
    store64(b, S_SEC + 8, 0)
    b.store("O", b32(S_SEC + 16), b32(0), 4)
    b.store("O", b32(S_SEC + 20), b32(0), 4)
    ok, fs = icall(b, "kernel32.dll", "CopyFileA", ["ptr", "ptr", "b32", "fs"], ["b32", "fs"],
                   addr(b, "O", P_ART), addr(b, "O", P_IMG), b32(0), "fs")
    b.set("fs", fs)
    b.set("ok", ok)
    bad_copy, copied = b.if_(b.cmp("eq", "ok", b32(0)))
    err, proc = icall(bad_copy, "kernel32.dll", "GetLastError", ["proc"], ["b32", "proc"], "proc")
    bad_copy.set("proc", proc)
    bad_copy.set("code", err)
    bad_copy.jump(FAIL)
    b = copied
    # a job object with fixed limits; the child is assigned to it while suspended and resumed only afterwards
    store64(b, S_JOB + 0, CPU_LIMIT_100NS)
    b.store("O", b32(S_JOB + 16), b32(JOB_LIMITS), 4)
    b.store("O", b32(S_JOB + 40), b32(1), 4)
    store64(b, S_JOB + 112, MEMORY_LIMIT)
    hjob, proc = icall(b, "kernel32.dll", "CreateJobObjectW", ["b64", "b64", "proc"], ["b64", "proc"],
                       ("b64", 0), ("b64", 0), "proc")
    b.set("proc", proc)
    b.set("hjob", hjob)
    ok, proc = icall(b, "kernel32.dll", "SetInformationJobObject", ["b64", "b32", "ptr", "b32", "proc"],
                     ["b32", "proc"], "hjob", b32(9), addr(b, "O", S_JOB), b32(144), "proc")
    b.set("proc", proc)
    b.set("ok", ok)
    bad_job, jobbed = b.if_(b.cmp("eq", "ok", b32(0)))
    err, proc = icall(bad_job, "kernel32.dll", "GetLastError", ["proc"], ["b32", "proc"], "proc")
    bad_job.set("proc", proc)
    bad_job.set("code", err)
    bad_job.jump(FAIL)
    b = jobbed
    # SECURITY_ATTRIBUTES with bInheritHandle = 1, shared by the pipes and the NUL device
    store64(b, S_SA, 24)
    store64(b, S_SA + 8, 0)
    b.store("O", b32(S_SA + 16), b32(1), 4)
    # a NUL device for the child's standard input (the launcher feeds no input yet)
    hnul, fs = icall(b, "kernel32.dll", "CreateFileA",
                     ["ptr", "b32", "b32", "ptr", "b32", "b32", "b64", "fs"], ["b64", "fs"],
                     addr(b, "O", P_NUL), b32(0xC0000000), b32(3), addr(b, "O", S_SA), b32(3), b32(0), ("b64", 0), "fs")
    b.set("fs", fs)
    b.set("hnul", hnul)
    # stdout and stderr pipes: the child writes the write end, the launcher reads the read end
    for out_slot, in_slot in ((S_HOUTR, S_HOUTW), (S_HERRR, S_HERRW)):
        ok, fs = icall(b, "kernel32.dll", "CreatePipe", ["ptr", "ptr", "ptr", "b32", "fs"], ["b32", "fs"],
                       addr(b, "O", out_slot), addr(b, "O", in_slot), addr(b, "O", S_SA), b32(PIPE_BUFFER), "fs")
        b.set("fs", fs)
        b.set("ok", ok)
        bad_pipe, piped = b.if_(b.cmp("eq", "ok", b32(0)))
        err, proc = icall(bad_pipe, "kernel32.dll", "GetLastError", ["proc"], ["b32", "proc"], "proc")
        bad_pipe.set("proc", proc)
        bad_pipe.set("code", err)
        bad_pipe.jump(FAIL)
        b = piped
    b.set("houtr", b.load("O", b32(S_HOUTR), 8))
    b.set("houtw", b.load("O", b32(S_HOUTW), 8))
    b.set("herrr", b.load("O", b32(S_HERRR), 8))
    b.set("herrw", b.load("O", b32(S_HERRW), 8))
    # the read ends must stay private to the launcher
    for handle in ("houtr", "herrr"):
        _, = icall(b, "kernel32.dll", "SetHandleInformation", ["b64", "b32", "b32"], ["b32"], handle, b32(1), b32(0))
    # wide image path, run directory and command line
    _, fs = icall(b, "kernel32.dll", "MultiByteToWideChar", ["b32", "b32", "ptr", "b32", "ptr", "b32", "fs"],
                  ["b32", "fs"], b32(0), b32(0), addr(b, "O", P_IMG), b32(0xFFFFFFFF), addr(b, "O", W_IMG), b32(1024), "fs")
    b.set("fs", fs)
    _, fs = icall(b, "kernel32.dll", "MultiByteToWideChar", ["b32", "b32", "ptr", "b32", "ptr", "b32", "fs"],
                  ["b32", "fs"], b32(0), b32(0), addr(b, "O", P_RUN), b32(0xFFFFFFFF), addr(b, "O", W_RUN), b32(1024), "fs")
    b.set("fs", fs)
    for k, word in enumerate(b'"prog.exe"'):
        b.store("O", b32(W_CMD + 2 * k), ("b16", word), 2)
    b.store("O", b32(W_CMD + 16), ("b16", 0), 2)
    # STARTUPINFOEXW
    for k in range(0, 112, 8):
        store64(b, S_SI + k, 0)
    b.store("O", b32(S_SI), b32(112), 4)
    b.store("O", b32(S_SI + 60), b32(STARTF_USESTDHANDLES), 4)
    b.store("O", b32(S_SI + 80), "hnul", 8)
    b.store("O", b32(S_SI + 88), "houtw", 8)
    b.store("O", b32(S_SI + 96), "herrw", 8)
    # the process attribute list: the container, a restricted child policy, and the exact inheritable handle set
    b.store("O", b32(S_CHILD), b32(1), 4)
    b.store("O", b32(S_HLIST + 0), "hnul", 8)
    b.store("O", b32(S_HLIST + 8), "houtw", 8)
    b.store("O", b32(S_HLIST + 16), "herrw", 8)
    _, = icall(b, "kernel32.dll", "InitializeProcThreadAttributeList", ["b64", "b32", "b32", "ptr"], ["b32"],
               ("b64", 0), b32(3), b32(0), addr(b, "O", S_ASIZE))
    _, = icall(b, "kernel32.dll", "InitializeProcThreadAttributeList", ["ptr", "b32", "b32", "ptr"], ["b32"],
               addr(b, "O", S_ATTR), b32(3), b32(0), addr(b, "O", S_ASIZE))
    for attribute, value, size in ((0x20009, S_SEC, 24), (0x2000D, S_CHILD, 4), (0x20002, S_HLIST, 24)):
        _, = icall(b, "kernel32.dll", "UpdateProcThreadAttribute",
                   ["ptr", "b32", "b64", "ptr", "b64", "b64", "b64"], ["b32"],
                   addr(b, "O", S_ATTR), b32(0), ("b64", attribute), addr(b, "O", value),
                   ("b64", size), ("b64", 0), ("b64", 0))
    b.store("O", b32(S_SI + 104), raw(b, addr(b, "O", S_ATTR)), 8)
    # CreateProcessW: no command line beyond the image, no environment, the run directory
    ok, proc = icall(b, "kernel32.dll", "CreateProcessW",
                     ["ptr", "ptr", "b64", "b64", "b32", "b32", "b64", "ptr", "ptr", "ptr", "proc"], ["b32", "proc"],
                     addr(b, "O", W_IMG), addr(b, "O", W_CMD), ("b64", 0), ("b64", 0), b32(1),
                     b32(CREATE_UNICODE_ENVIRONMENT | DETACHED_PROCESS | CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT), ("b64", 0), addr(b, "O", W_RUN),
                     addr(b, "O", S_SI), addr(b, "O", S_PI), "proc")
    b.set("proc", proc)
    b.set("ok", ok)
    bad_spawn, spawned = b.if_(b.cmp("eq", "ok", b32(0)))
    err, proc = icall(bad_spawn, "kernel32.dll", "GetLastError", ["proc"], ["b32", "proc"], "proc")
    bad_spawn.set("proc", proc)
    bad_spawn.set("code", err)
    bad_spawn.jump(FAIL)
    b = spawned
    b.set("hproc", b.load("O", b32(S_PI + 0), 8))
    b.set("hthread", b.load("O", b32(S_PI + 8), 8))
    # contain the suspended child before it executes: assign it to the job, then confirm the assignment
    ok, proc = icall(b, "kernel32.dll", "AssignProcessToJobObject", ["b64", "b64", "proc"], ["b32", "proc"],
                     "hjob", "hproc", "proc")
    b.set("proc", proc)
    b.set("ok", ok)
    bad_assign, assigned = b.if_(b.cmp("eq", "ok", b32(0)))
    err, proc = icall(bad_assign, "kernel32.dll", "GetLastError", ["proc"], ["b32", "proc"], "proc")
    bad_assign.set("proc", proc)
    bad_assign.set("code", err)
    bad_assign.jump(FAIL)
    b = assigned
    _, = icall(b, "kernel32.dll", "IsProcessInJob", ["b64", "b64", "ptr"], ["b32"],
               "hproc", "hjob", addr(b, "O", S_INJOB))
    confined, unconfined = b.if_(b.cmp("ne", b.load("O", b32(S_INJOB), 4), b32(0)))
    unconfined.set("code", b32(41))
    unconfined.jump(FAIL)
    b = confined
    # the child owns the write ends now
    for handle in ("houtw", "herrw"):
        _, proc = icall(b, "kernel32.dll", "CloseHandle", ["b64", "proc"], ["b32", "proc"], handle, "proc")
        b.set("proc", proc)
    # wall-time limit: a timeout terminates the job and is reported, never ignored
    t0, = icall(b, "kernel32.dll", "GetTickCount", [], ["b32"])
    b.set("t0", t0)
    _, = icall(b, "kernel32.dll", "ResumeThread", ["b64"], ["b32"], "hthread")
    rc, proc = icall(b, "kernel32.dll", "WaitForSingleObject", ["b64", "b32", "proc"], ["b32", "proc"],
                     "hproc", b32(WALL_MS), "proc")
    b.set("proc", proc)
    b.set("rc", rc)
    timed_out, finished = b.if_(b.cmp("ne", "rc", b32(0)))
    timed_out.set("flags", timed_out.bor("flags", b32(FLAG_TIMEOUT)))
    _, proc = icall(timed_out, "kernel32.dll", "TerminateJobObject", ["b64", "b32", "proc"], ["b32", "proc"],
                    "hjob", b32(1), "proc")
    timed_out.set("proc", proc)
    timed_out.jump(finished)
    b = finished
    ok, proc = icall(b, "kernel32.dll", "GetExitCodeProcess", ["b64", "ptr", "proc"], ["b32", "proc"],
                     "hproc", addr(b, "O", S_TMP), "proc")
    b.set("proc", proc)
    b.set("n", b.load("O", b32(S_TMP), 4))
    # drain the pipes: ReadFile on a pipe returns what is buffered, at most the requested cap
    for read_end, avail_slot, count_slot, buffer in (("houtr", S_AVAIL, S_NREAD, O_OUT),
                                                     ("herrr", S_AVAIL2, S_NREAD2, O_ERR)):
        peeked, = icall(b, "kernel32.dll", "PeekNamedPipe", ["b64", "b64", "b32", "b64", "ptr", "b64"], ["b32"],
                        read_end, ("b64", 0), b32(0), ("b64", 0), addr(b, "O", avail_slot), ("b64", 0))
        b.set("ok", peeked)
        b.set("avail", b32(0))
        peeked_ok, after_peek = b.if_(b.cmp("ne", "ok", b32(0)))
        peeked_ok.set("avail", peeked_ok.load("O", b32(avail_slot), 4))
        peeked_ok.jump(after_peek)
        b = after_peek
        _, = icall(b, "kernel32.dll", "ReadFile", ["b64", "ptr", "b32", "ptr", "b64"], ["b32"],
                   read_end, addr(b, "O", buffer), b32(OUT_CAP), addr(b, "O", count_slot), ("b64", 0))
        truncated, not_truncated = b.if_(b.cmp("ugt", "avail", b32(OUT_CAP)))
        truncated.set("flags", truncated.bor("flags", b32(FLAG_TRUNCATED)))
        truncated.jump(not_truncated)
        b = not_truncated
    b.set("gotout", b.load("O", b32(S_NREAD), 4))
    for handle in ("houtr", "herrr", "hproc", "hthread", "hnul", "hjob"):
        _, proc = icall(b, "kernel32.dll", "CloseHandle", ["b64", "proc"], ["b32", "proc"], handle, "proc")
        b.set("proc", proc)
    # result file: exit code, status flags, wall milliseconds
    now, = icall(b, "kernel32.dll", "GetTickCount", [], ["b32"])
    b.set("now", now)
    b.store("O", b32(R_BUF), "n", 4)
    b.store("O", b32(R_BUF + 4), "flags", 4)
    b.store("O", b32(R_BUF + 8), b.zext(b.sub("now", "t0"), "b64"), 8)
    b = emit_write(b, addr(b, "O", P_RES), R_BUF, b32(16))
    b = emit_write(b, addr(b, "O", P_OUT), O_OUT, "gotout")
    b.set("goterr", b.load("O", b32(S_NREAD2), 4))
    b = emit_write(b, addr(b, "O", P_ERR), O_ERR, "goterr")
    b.set("code", b32(0))
    b.jump(DONE)
    FAIL.jump(DONE)
    for v, extent in VIEWS.items():
        _, mem = DONE.op("call.foreign", [f"{v}p", ("b64", 0), b32(0x8000), f"{v}v", f"{v}m"], ["b32", "mem"],
                         entity={"win32.virtual_free_view": [P.ptr_type(v), extent]})
        DONE.set(f"{v}m", mem)
    (proc,) = DONE.op("call.foreign", ["code", "proc"], ["proc"], entity="win32.exit_process")
    DONE.set("proc", proc)
    DONE.ret_raw("code", "proc", "fs", *(f"{v}m" for v in views))
    return P


def construction_request() -> dict:
    return build_program().carrier({"app": "main"}, "app")


def main(argv: list[str]) -> int:
    xax_src, out = Path(argv[1]), Path(argv[2])
    sys.path.insert(0, str(xax_src))
    import hashlib

    from xax_build import build
    from xax_construct import construct

    out.mkdir(parents=True, exist_ok=True)
    request = construction_request()
    (out / "sandbox_request.json").write_bytes(
        json.dumps(request, separators=(",", ":"), sort_keys=True).encode() + b"\n")
    constructed = construct(request)
    store = constructed.reader.canonical_bytes()
    (out / "xax-mcp-sandbox-gen0.xax").write_bytes(store)
    artifact = build(constructed.reader, constructed.release_request.cid).artifact
    (out / "xax-mcp-sandbox.exe").write_bytes(artifact)
    print(json.dumps({"xax": NATIVE_XAX_COMMIT, "root": constructed.reader.root_cid.hex(),
                      "store_bytes": len(store), "store_sha256": hashlib.sha256(store).hexdigest(),
                      "artifact_bytes": len(artifact), "artifact_sha256": hashlib.sha256(artifact).hexdigest(),
                      "functions": len(request["functions"])}, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))


