"""Constructs the native XAX MCP server (``xax-mcp-native``) as one ``xax-construct-v1`` request.

Integration tooling in the XAX repository: this module writes the construction request.  ``xax_construct`` turns it into a
verified canonical store, which is the authoritative program, and ``xax_build`` turns the store into a PE32+
executable.  The server itself (STDIO framing, JSON validation, JSON-RPC, MCP lifecycle, tool dispatch, host rights)
is the XAX program; Python is not on its request path.

    python compiler/integration/mcp/server.py <xax compiler/src> <output directory>
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from dsl import Program  # noqa: E402

VERSION = "0.7.0+native"
NATIVE_XAX_COMMIT = "f79b532fd4651ba808676d02f4b038e2cc271e6a"  # XAX main, 2026-10-19; host contract xax-host-contract-v1 r10
LMAX = 4 * 1024 * 1024  # largest accepted message line
MAX_ARGUMENTS = 1024 * 1024  # policy.max_request_bytes default
MAX_DEPTH = 64
HANDSHAKE_VERSIONS = ("2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25")
INSTRUCTIONS = ("Call xax_capabilities first; it reports the exact XAX pin and which tools this build implements. The "
                "native server implements the MCP protocol, capabilities, and (when the host grants a native XAX "
                "compiler, work directory and seed store through XAX_MCP_COMPILER/XAX_MCP_WORK/XAX_MCP_STORE) "
                "workspace/query, transaction and build. Execute additionally needs --allow-execute and a "
                "xax-mcp-sandbox.exe beside the server: it resolves and builds the current store, runs the artifact "
                "as a capability-less Windows AppContainer inside a job object, and reports its exit code, wall time "
                "and captured output. Construct needs a native carrier decoder XAX does not publish; it fails closed. "
                "Never silently substitute Python or another language. Carrier JSON is transport, never XAX source.")
RIGHTS = ("build", "execute", "mutate", "read")  # sorted; bit k is RIGHTS[k]
DEFAULT_RIGHTS = 0b1101  # read, mutate, build
TOOL_RIGHTS = {"xax_workspace": "read", "xax_query": "read", "xax_construct": "mutate", "xax_transaction": "mutate",
               "xax_build": "build", "xax_execute": "execute", "xax_result": "read"}
KEYS = ("jsonrpc", "id", "method", "params", "protocolVersion", "name", "arguments", "result", "error", "record")
RECORD_KEY = KEYS.index("record")
NO_KEY = 99
# RES slots (4 bytes each): 2k/2k+1 = value span of KEYS[k]; then status, member count, first key span, value start.
SLOT_COUNT, SLOT_KEY_START, SLOT_KEY_END, SLOT_TOP = 20, 21, 22, 23

RES = MAX_DEPTH  # W holds the depth stack at 0 and the RES slots at RES
# Win64 passes four machine arguments in registers, the most the register-resident lowering takes, so every function
# keeps to four machine arguments: the scanner's stack and slots share view W, spans travel packed as start | end << 32,
# and the host compiler configuration and every file buffer share view O at fixed offsets.  O is the server's output
# view: a response never exceeds two message lengths, so the configuration sits above that and file buffers sit below.
VIEWS = {"C": 65536, "L": LMAX + 64, "O": 3 * LMAX + (1 << 20), "W": RES + 128, "N": 4, "A": 32768 + 64}

# base64 of the ASCII hex digits, indexed by byte; 255 marks a non-hex byte (native/chain.py emits the carriers).
_HEX_TABLE = bytearray(255 for _ in range(256))
for _index, _byte in enumerate(b"0123456789"):
    _HEX_TABLE[_byte] = _index
for _index, _byte in enumerate(b"abcdef"):
    _HEX_TABLE[_byte] = 10 + _index
for _index, _byte in enumerate(b"ABCDEF"):
    _HEX_TABLE[_byte] = 10 + _index
HEX_TABLE = bytes(_HEX_TABLE)


def compact(value) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True, ensure_ascii=True).encode()


def escape(raw: bytes) -> bytes:
    """``raw`` as the contents of a JSON string (what ``json.dumps`` does to an ASCII JSON text)."""
    return raw.replace(b"\\", b"\\\\").replace(b'"', b'\\"')


def tools_json() -> bytes:
    from schemas import SCHEMA_VERSION, TOOLS

    return compact({"tools": [{"name": name, "title": spec["title"], "description": spec["description"],
                               "inputSchema": spec["inputSchema"], "annotations": spec["annotations"],
                               "_meta": {"xax-mcp/schema": SCHEMA_VERSION}} for name, spec in TOOLS.items()]})


def error_payload(code: str, message: str, repair=None, details=None) -> dict:
    error = {"code": code, "message": message}
    if repair:
        error["repair"] = repair
    if details:
        error["details"] = details
    return {"ok": False, "error": error}


def capabilities_payload() -> dict:
    compiler = ("EXECUTED against the host-granted native XAX compiler (XAX_MCP_COMPILER/XAX_MCP_WORK/XAX_MCP_STORE); "
                "fails closed with denied_capability when the host grants no compiler")
    tools = {"xax_workspace": compiler, "xax_query": compiler, "xax_transaction": compiler, "xax_build": compiler,
             "xax_construct": "UNIMPLEMENTED natively: XAX publishes no native carrier decoder (construct); fails closed",
             "xax_execute": ("PROTOTYPE (windows-x86_64): resolve+build the current store, then run the artifact in "
                             "xax-mcp-sandbox.exe (a capability-less AppContainer inside a job object); needs "
                             "--allow-execute and the launcher beside this server; Linux and typed I/O fail closed"),
             "xax_result": "UNIMPLEMENTED natively: result handles need session state, which the native server lacks"}
    return {"ok": True,
            "server": {"name": "xax-mcp", "version": VERSION, "transport": "stdio",
                       "implementation": "native XAX program (windows-x86_64 PE32+ built from a canonical .xax store)",
                       "python_on_request_path": False},
            "xax": {"pinned_commit": NATIVE_XAX_COMMIT, "host_contract": "xax-host-contract-v1 r10",
                    "role": "build-time compiler; the deployed server drives a host-granted native compiler but embeds no interpreter"},
            "protocol": {"framing": "newline-delimited JSON-RPC 2.0", "versions": list(HANDSHAKE_VERSIONS),
                         "max_message_bytes": LMAX, "max_json_depth": MAX_DEPTH},
            "authority": {"rights": "__RIGHTS__", "max_request_bytes": MAX_ARGUMENTS, "store_roots": 0,
                          "effects_granted": []},
            "tools": {"xax_capabilities": "EXECUTED (native)", **tools},
            "targets": [],
            "sandbox": {"available": "windows-x86_64 prototype only",
                        "launcher": "xax-mcp-sandbox.exe (built from native/sandbox.py), installed beside this server",
                        "reason": "without --allow-execute or the launcher, execution is refused; Linux confinement "
                                  "(namespaces, seccomp, rlimits) and typed input/output layouts are not implemented"},
            "maturity": {"stdio transport, JSON validation, MCP lifecycle, tool dispatch, host rights": "EXECUTED (tests/test_native_stdio.py)",
                         "workspace/query/transaction/build over a host-granted native compiler": "PROTOTYPE (docs/NATIVE.md)",
                         "execute in a Windows AppContainer + job object": "PROTOTYPE (measured; docs/NATIVE.md)",
                         "construct (no native carrier decoder)": "UNIMPLEMENTED natively",
                         "execute on Linux (namespaces, seccomp, rlimits)": "UNIMPLEMENTED natively",
                         "result (serves artifacts over the wire)": "UNIMPLEMENTED natively",
                         "modern protocol 2026-07-28": "UNIMPLEMENTED natively"}}


def build_program() -> Program:  # noqa: C901 - one straight-line description of the program
    P = Program("xax_mcp_native", VIEWS, {"N": "u32p"})
    fns: dict = {}

    def fn(name, views, params, returns, locals_=()):
        f = P.fn(name, views, params, returns, list(locals_))
        fns[name] = f
        return f

    b32 = lambda v: ("b32", v)  # noqa: E731

    def branch_any(b, x, values):
        """End ``b`` with a test of variable ``x`` against ``values``; returns (one of them, none of them).

        A chain of compares, not an OR of flags: before XAX ADR-284 the x86-64 register allocator turned such a
        predicate into a table read whose operands the fused cmp+jcc still needed (XAX.NATIVE.VALUE); the chain
        builds on both sides of that fix with the same bytes (docs/NATIVE.md)."""
        yes, no = b.fn.block(), b.fn.block()
        for value in values:
            nxt = b.fn.block()
            b.branch(b.cmp("eq", x, b32(value)), yes, nxt)
            b = nxt
        b.jump(no)
        return yes, no


    # -- byte writers -------------------------------------------------------------------------------------------
    literals: dict[bytes, object] = {}

    def literal(data: bytes):
        if data not in literals:
            f = fn(f"lit{len(literals)}", ("O",), [("pos", "b32")], ["pos"])
            b = f.entry
            for k in range(0, len(data) - len(data) % 8, 8):
                b.store("O", b.add("pos", b32(k)), ("b64", int.from_bytes(data[k:k + 8], "little")), 8)
            for k in range(len(data) - len(data) % 8, len(data)):
                b.store("O", b.add("pos", b32(k)), ("b8", data[k]), 1)
            b.ret(b.add("pos", b32(len(data))))
            literals[data] = f
        return literals[data]

    def emit(b, *parts):
        """Append parts at ``pos``: bytes literals, ("copy"|"esc", start, end) spans of L, or callables."""
        for part in parts:
            if isinstance(part, bytes):
                if part:
                    b.call(literal(part), "pos", into=("pos",))
            elif callable(part):
                part(b)
            else:
                kind, start, end = part
                b.call(fns["copy" if kind == "copy" else "copy_esc"], span(b, start, end), "pos", into=("pos",))

    def span(b, start, end):
        return b.bor(b.zext(start, "b64"), b.mul(b.zext(end, "b64"), ("b64", 1 << 32), "b64"), "b64")

    def unspan(b, packed, start, end):
        b.set(start, b.trunc(packed))
        b.set(end, b.trunc(b.op1("rotate.right", [packed], "b64", attrs=[32])))

    for name, escaped in (("copy", False), ("copy_esc", True)):
        f = fn(name, ("L", "O"), [("se", "b64"), ("pos", "b32")], ["pos"], [("c", "b32"), ("s", "b32"), ("e", "b32")])
        f.entry.set("c", b32(0))
        unspan(f.entry, "se", "s", "e")
        loop = f.block()
        f.entry.jump(loop)
        body, done = loop.if_(loop.cmp("ult", "s", "e"))
        done.ret("pos")
        body.set("c", body.load("L", "s"))
        if escaped:
            slash, plain = branch_any(body, "c", (34, 92))
            slash.store("O", "pos", ("b8", 92))
            slash.set("pos", slash.add("pos", b32(1)))
            slash.jump(plain)
            body = plain
        body.store("O", "pos", "c")
        body.set("pos", body.add("pos", b32(1)))
        body.set("s", body.add("s", b32(1)))
        body.jump(loop)

    f = fn("dec", ("O",), [("v", "b32"), ("pos", "b32")], ["pos"], [("p", "b32"), ("d", "b32")])
    f.entry.set("p", b32(1))
    f.entry.set("d", b32(0))
    grow = f.block()
    f.entry.jump(grow)
    more, digits = grow.if_(grow.cmp("uge", grow.udiv("v", "p"), b32(10)))
    more.set("p", more.mul("p", b32(10)))
    more.jump(grow)
    body, done = digits.if_(digits.cmp("ne", "p", b32(0)))
    done.ret("pos")
    body.set("d", body.udiv("v", "p"))
    body.store("O", "pos", body.add("d", b32(48)))
    body.set("pos", body.add("pos", b32(1)))
    body.set("v", body.sub("v", body.mul("d", "p")))
    body.set("p", body.udiv("p", b32(10)))
    body.jump(digits)

    for name, escaped in (("rights_raw", False), ("rights_esc", True)):
        f = fn(name, ("O",), [("rights", "b32"), ("pos", "b32")], ["pos"], [("first", "b32")])
        b = f.entry
        b.set("first", b32(1))
        emit(b, b"[")
        for bit, right in enumerate(RIGHTS):
            then, join = b.if_(b.cmp("ne", b.band("rights", b32(1 << bit)), b32(0)))
            comma, named = then.if_(then.cmp("eq", "first", b32(0)))
            emit(comma, b",")
            comma.jump(named)
            quoted = b'"' + right.encode() + b'"'
            emit(named, escape(quoted) if escaped else quoted)
            named.set("first", b32(0))
            named.jump(join)
            b = join
        emit(b, b"]")
        b.ret("pos")

    # -- comparisons --------------------------------------------------------------------------------------------
    equals: dict[tuple[str, bytes], object] = {}

    def eq(view: str, data: bytes):
        """fn(s, e) -> 1 when view[s:e] == data."""
        if (view, data) not in equals:
            f = fn(f"eq{len(equals)}", (view,), [("s", "b32"), ("e", "b32")], ["r"], [("r", "b32")])
            b = f.entry
            b.set("r", b32(0))
            same, differ = b.if_(b.cmp("eq", b.sub("e", "s"), b32(len(data))))
            differ.ret(b32(0))
            acc = b32(0)
            for k, byte in enumerate(data):
                acc = same.bor(acc, same.bxor(same.load(view, same.add("s", b32(k))), b32(byte)))
            same.ret(same.flag("eq", acc, b32(0)))
            equals[(view, data)] = f
        return equals[(view, data)]

    def switch(b, value, cases, default):
        """Branch to the target of the first case equal to ``value``; ``cases`` are (constant, block)."""
        for constant, target in cases:
            nxt = b.fn.block()
            b.branch(b.cmp("eq", value, b32(constant)), target, nxt)
            b = nxt
        b.jump(default)

    def match(b, view, start, end, names, var):
        """Set ``var`` to the index of the first of ``names`` equal to view[start:end], else NO_KEY."""
        b.set(var, b32(NO_KEY))
        join = b.fn.block()
        for k, name in enumerate(names):
            (flag,) = b.call(eq(view, name.encode()), start, end)
            hit, nxt = b.if_(b.cmp("ne", flag, b32(0)))
            hit.set(var, b32(k))
            hit.jump(join)
            b = nxt
        b.jump(join)
        return join

    # -- JSON (RFC 8259) validation over L, terminated by a 0 sentinel byte --------------------------------------
    f = fn("skip_ws", ("L",), [("i", "b32")], ["i"], [("c", "b32")])
    f.entry.set("c", b32(0))
    loop = f.block()
    f.entry.jump(loop)
    loop.set("c", loop.load("L", "i"))
    step, done = branch_any(loop, "c", (32, 9, 10, 13))
    step.set("i", step.add("i", b32(1)))
    step.jump(loop)
    done.ret("i")

    def digit(b, c):
        """b1 for a branch: c is an ASCII digit (one compare, so no predicate table; see branch_any)."""
        return b.cmp("ult", b.sub(c, b32(48)), b32(10))

    def is_digit(b, c):
        return b.flag("ult", b.sub(c, b32(48)), b32(10))

    f = fn("digits", ("L",), [("i", "b32")], ["i"])
    loop = f.block()
    f.entry.jump(loop)
    step, done = loop.if_(digit(loop, loop.load("L", "i")))
    step.set("i", step.add("i", b32(1)))
    step.jump(loop)
    done.ret("i")

    def digit_run(b):
        """Advance ``i`` over digits from block ``b``; returns the block after the run."""
        loop, after = b.fn.block(), b.fn.block()
        b.jump(loop)
        step, stop = loop.if_(digit(loop, loop.load("L", "i")))
        step.set("i", step.add("i", b32(1)))
        step.jump(loop)
        stop.jump(after)
        return after

    f = fn("scan_number", ("L",), [("i", "b32")], ["i"], [("ok", "b32"), ("c", "b32")])
    b = f.entry
    b.set("ok", b32(0))
    b.set("c", b.load("L", "i"))
    minus, intpart = b.if_(b.cmp("eq", "c", b32(45)))
    minus.set("i", minus.add("i", b32(1)))
    minus.jump(intpart)
    fail, frac, exp = f.block(), f.block(), f.block()
    fail.ret(b32(0))
    b = intpart
    b.set("c", b.load("L", "i"))
    zero, nonzero = b.if_(b.cmp("eq", "c", b32(48)))
    zero.set("i", zero.add("i", b32(1)))
    zero.jump(frac)
    lead = f.block()
    nonzero.branch(digit(nonzero, "c"), lead, fail)
    digit_run(lead).jump(frac)
    dot, nodot = frac.if_(frac.cmp("eq", frac.load("L", "i"), b32(46)))
    nodot.jump(exp)
    dot.set("i", dot.add("i", b32(1)))
    fracdigits = f.block()
    dot.branch(digit(dot, dot.load("L", "i")), fracdigits, fail)
    digit_run(fracdigits).jump(exp)
    e, done = exp.if_(exp.cmp("eq", exp.bor(exp.load("L", "i"), b32(32)), b32(101)))
    done.ret("i")
    e.set("i", e.add("i", b32(1)))
    e.set("c", e.load("L", "i"))
    sign, unsigned = branch_any(e, "c", (43, 45))
    sign.set("i", sign.add("i", b32(1)))
    sign.jump(unsigned)
    expdigits = f.block()
    unsigned.branch(digit(unsigned, unsigned.load("L", "i")), expdigits, fail)
    digit_run(expdigits).ret("i")

    def is_hex(b, c):
        return b.bor(is_digit(b, c), b.flag("ult", b.sub(b.bor(c, b32(32)), b32(97)), b32(6)))

    f = fn("scan_string", ("L",), [("i", "b32")], ["i"],
           [("ok", "b32"), ("c", "b32"), ("n", "b32"), ("lo", "b32"), ("hi", "b32"), ("x", "b32")])
    b = f.entry
    for name in ("ok", "c", "n", "lo", "hi", "x"):
        b.set(name, b32(0))
    b.set("i", b.add("i", b32(1)))
    loop, fail = f.block(), f.block()
    b.jump(loop)
    fail.ret(b32(0))
    loop.set("c", loop.load("L", "i"))
    close, esc, ctrl, ascii_, utf = f.block(), f.block(), f.block(), f.block(), f.block()
    switch(loop, "c", [(34, close), (92, esc)], ctrl)
    close.ret(close.add("i", b32(1)))
    ctrl.branch(ctrl.cmp("ult", "c", b32(32)), fail, ascii_)
    plain, high = ascii_.if_(ascii_.cmp("ult", "c", b32(128)))
    plain.set("i", plain.add("i", b32(1)))
    plain.jump(loop)
    high.jump(utf)
    # escapes: \" \\ \/ \b \f \n \r \t, or \uXXXX
    esc.set("x", esc.load("L", esc.add("i", b32(1))))
    short, other = branch_any(esc, "x", tuple(b'"\\/bfnrt'))
    short.set("i", short.add("i", b32(2)))
    short.jump(loop)
    unicode_ = f.block()
    other.branch(other.cmp("eq", "x", b32(117)), unicode_, fail)
    hexes = b32(1)
    for k in range(2, 6):
        hexes = unicode_.band(hexes, is_hex(unicode_, unicode_.load("L", unicode_.add("i", b32(k)))))
    good = f.block()
    unicode_.branch(unicode_.cmp("ne", hexes, b32(0)), good, fail)
    good.set("i", good.add("i", b32(6)))
    good.jump(loop)
    # UTF-8 (RFC 3629): no overlong forms, no surrogates, nothing above U+10FFFF
    two, notwo = f.block(), f.block()
    lowlead = f.block()
    utf.branch(utf.cmp("ult", "c", b32(0xC2)), fail, lowlead)
    lowlead.branch(lowlead.cmp("ult", "c", b32(0xE0)), two, notwo)
    first = f.block()
    two.set("n", b32(0))
    two.set("lo", b32(0x80))
    two.set("hi", b32(0xBF))
    two.jump(first)
    three, nothree = notwo.if_(notwo.cmp("ult", "c", b32(0xF0)))
    three.set("n", b32(1))
    three.set("lo", three.add(b32(0x80), three.mul(three.flag("eq", "c", b32(0xE0)), b32(0x20))))
    three.set("hi", three.sub(b32(0xBF), three.mul(three.flag("eq", "c", b32(0xED)), b32(0x20))))
    three.jump(first)
    four = f.block()
    nothree.branch(nothree.cmp("ult", "c", b32(0xF5)), four, fail)
    four.set("n", b32(2))
    four.set("lo", four.add(b32(0x80), four.mul(four.flag("eq", "c", b32(0xF0)), b32(0x10))))
    four.set("hi", four.sub(b32(0xBF), four.mul(four.flag("eq", "c", b32(0xF4)), b32(0x30))))
    four.jump(first)
    byte = first.load("L", first.add("i", b32(1)))
    inrange = first.cmp("ult", first.sub(byte, "lo"), first.add(first.sub("hi", "lo"), b32(1)))
    rest = f.block()
    ok_first = f.block()
    first.branch(inrange, ok_first, fail)
    ok_first.set("i", ok_first.add("i", b32(2)))
    ok_first.jump(rest)
    cont, finished = rest.if_(rest.cmp("ne", "n", b32(0)))
    finished.jump(loop)
    good_cont = f.block()
    cont.branch(cont.cmp("eq", cont.band(cont.load("L", "i"), b32(0xC0)), b32(0x80)), good_cont, fail)
    good_cont.set("i", good_cont.add("i", b32(1)))
    good_cont.set("n", good_cont.sub("n", b32(1)))
    good_cont.jump(rest)

    key_id = fn("key_id", ("L",), [("s", "b32"), ("e", "b32")], ["id"], [("id", "b32")])
    join = match(key_id.entry, "L", "s", "e", KEYS, "id")
    join.ret("id")

    # scan(start, end) -> status: validates one JSON value in L[start:end] and records, for an object, the value span
    # of every KEYS member (the last duplicate wins, like json.loads), the member count and the first key.
    scan_locals = [(n, "b32") for n in ("st", "i", "depth", "cur", "vstart", "count", "c", "top", "ks", "ke", "ok")]
    f = fn("scan", ("L", "W"), [("start", "b32"), ("end", "b32")], ["st"], scan_locals)
    b = f.entry
    for name, _ in scan_locals:
        b.set(name, b32(0))
    b.set("cur", b32(NO_KEY))
    for slot in range(24):
        b.store("W", b32(RES + 4 * slot), b32(0), 4)
    b.call(fns["skip_ws"], "start", into=("i",))
    b.store("W", b32(RES + 4 * SLOT_TOP), "i", 4)
    VAL, OBJ, ARR, KEY, STR, TRUE, FALSE, NULL, NUM, AFTER, END, ERR, DEEP = (f.block() for _ in range(13))
    b.jump(VAL)
    ERR.ret(b32(1))
    DEEP.ret(b32(2))
    VAL.call(fns["skip_ws"], "i", into=("i",))
    VAL.set("c", VAL.load("L", "i"))
    number = f.block()
    switch(VAL, "c", [(123, OBJ), (91, ARR), (34, STR), (116, TRUE), (102, FALSE), (110, NULL), (45, NUM)], number)
    number.branch(digit(number, "c"), NUM, ERR)
    for block, kind, closer, inner in ((OBJ, 1, 125, KEY), (ARR, 2, 93, VAL)):
        room = f.block()
        block.branch(block.cmp("uge", "depth", b32(MAX_DEPTH)), DEEP, room)
        room.store("W", "depth", b32(kind))
        room.set("depth", room.add("depth", b32(1)))
        room.call(fns["skip_ws"], room.add("i", b32(1)), into=("i",))
        empty, filled = room.if_(room.cmp("eq", room.load("L", "i"), b32(closer)))
        empty.set("i", empty.add("i", b32(1)))
        empty.set("depth", empty.sub("depth", b32(1)))
        empty.jump(AFTER)
        filled.jump(inner)
    quoted = f.block()
    KEY.branch(KEY.cmp("eq", KEY.load("L", "i"), b32(34)), quoted, ERR)
    quoted.set("ks", "i")
    quoted.call(fns["scan_string"], "i", into=("i",))
    keyed = f.block()
    quoted.branch(quoted.cmp("eq", "i", b32(0)), ERR, keyed)
    keyed.set("ke", "i")
    top, colon = keyed.if_(keyed.cmp("eq", "depth", b32(1)))
    top.set("count", top.add("count", b32(1)))
    firstkey, later = top.if_(top.cmp("eq", "count", b32(1)))
    firstkey.store("W", b32(RES + 4 * SLOT_KEY_START), firstkey.add("ks", b32(1)), 4)
    firstkey.store("W", b32(RES + 4 * SLOT_KEY_END), firstkey.sub("ke", b32(1)), 4)
    firstkey.jump(later)
    later.call(key_id, later.add("ks", b32(1)), later.sub("ke", b32(1)), into=("cur",))
    later.jump(colon)
    colon.call(fns["skip_ws"], "i", into=("i",))
    after_colon = f.block()
    colon.branch(colon.cmp("eq", colon.load("L", "i"), b32(58)), after_colon, ERR)
    after_colon.call(fns["skip_ws"], after_colon.add("i", b32(1)), into=("i",))
    member, nested = after_colon.if_(after_colon.cmp("eq", "depth", b32(1)))
    member.set("vstart", "i")
    member.jump(VAL)
    nested.jump(VAL)
    STR.call(fns["scan_string"], "i", into=("i",))
    STR.branch(STR.cmp("eq", "i", b32(0)), ERR, AFTER)
    NUM.call(fns["scan_number"], "i", into=("i",))
    NUM.branch(NUM.cmp("eq", "i", b32(0)), ERR, AFTER)
    for block, offset, word, size in ((TRUE, 0, b"true", 4), (NULL, 0, b"null", 4), (FALSE, 1, b"alse", 5)):
        hit = f.block()
        loaded = block.load("L", block.add("i", b32(offset)), 4)
        block.branch(block.cmp("eq", loaded, b32(int.from_bytes(word, "little"))), hit, ERR)
        hit.set("i", hit.add("i", b32(size)))
        hit.jump(AFTER)
    rec = f.block()
    a2 = f.block()
    record = AFTER.band(AFTER.flag("eq", "depth", b32(1)), AFTER.flag("ne", "cur", b32(NO_KEY)))
    AFTER.branch(AFTER.cmp("ne", record, b32(0)), rec, a2)
    rec.store("W", rec.add(rec.mul("cur", b32(8)), b32(RES)), "vstart", 4)
    rec.store("W", rec.add(rec.mul("cur", b32(8)), b32(RES + 4)), "i", 4)
    rec.set("cur", b32(NO_KEY))
    rec.jump(a2)
    inside = f.block()
    a2.branch(a2.cmp("eq", "depth", b32(0)), END, inside)
    inside.set("top", inside.load("W", inside.sub("depth", b32(1))))
    inside.call(fns["skip_ws"], "i", into=("i",))
    inside.set("c", inside.load("L", "i"))
    in_obj, in_arr = inside.if_(inside.cmp("eq", "top", b32(1)))
    for block, closer, after_comma in ((in_obj, 125, KEY), (in_arr, 93, VAL)):
        comma, close = f.block(), f.block()
        switch(block, "c", [(44, comma), (closer, close)], ERR)
        comma.call(fns["skip_ws"], comma.add("i", b32(1)), into=("i",))
        comma.jump(after_comma)
        close.set("i", close.add("i", b32(1)))
        close.set("depth", close.sub("depth", b32(1)))
        close.jump(AFTER)
    OK, trailing = f.block(), f.block()
    END.branch(END.cmp("eq", "i", "end"), OK, trailing)
    trailing.call(fns["skip_ws"], "i", into=("i",))
    trailing.branch(trailing.cmp("eq", "i", "end"), OK, ERR)
    OK.store("W", b32(RES + 4 * SLOT_COUNT), "count", 4)
    OK.ret(b32(0))

    # -- host rights from the command line (fail closed on anything else) ----------------------------------------
    f = fn("parse_args", ("A",), [], ["rights"],
           [(n, "b32") for n in ("rights", "ok", "i", "c", "s", "allow", "ro", "deny", "want", "hit", "quote")])
    b = f.entry
    for name in ("rights", "ok", "i", "c", "s", "allow", "ro", "deny", "want", "hit", "quote"):
        b.set(name, b32(0))
    fail, program_quoted, program_plain, tokens = f.block(), f.block(), f.block(), f.block()
    fail.ret(b32(0))
    b.branch(b.cmp("eq", b.load("A", b32(0)), b32(34)), program_quoted, program_plain)
    # the program token: "quoted path" or a bare word
    program_quoted.set("i", b32(1))
    pq = f.block()
    program_quoted.jump(pq)
    pq.set("c", pq.load("A", "i"))
    pq_end, pq_more = branch_any(pq, "c", (34, 0))
    pq_more.set("i", pq_more.add("i", b32(1)))
    pq_more.jump(pq)
    skip_quote = f.block()
    pq_end.branch(pq_end.cmp("eq", "c", b32(34)), skip_quote, tokens)
    skip_quote.set("i", skip_quote.add("i", b32(1)))
    skip_quote.jump(tokens)

    pp = f.block()
    program_plain.jump(pp)
    pp.set("c", pp.load("A", "i"))
    pp_end, pp_more = branch_any(pp, "c", (32, 9, 0))
    pp_more.set("i", pp_more.add("i", b32(1)))
    pp_more.jump(pp)
    pp_end.jump(tokens)
    # tokens: skip blanks, take a word, classify it
    tokens.set("c", tokens.load("A", "i"))
    blank, word = branch_any(tokens, "c", (32, 9))
    blank.set("i", blank.add("i", b32(1)))
    blank.jump(tokens)
    finish, start = word.if_(word.cmp("eq", "c", b32(0)))
    granted = finish.bor(b32(DEFAULT_RIGHTS), finish.mul("allow", b32(2)))
    chosen = finish.add(finish.mul("ro", b32(8)), finish.mul(finish.sub(b32(1), "ro"), granted))
    finish.ret(finish.bor(finish.band(chosen, finish.bxor("deny", b32(15))), b32(16)))  # bit 4: parsed
    start.set("s", "i")
    start.set("quote", b32(0))
    scan_word = f.block()
    start.jump(scan_word)
    scan_word.set("c", scan_word.load("A", "i"))
    word_end, word_more = branch_any(scan_word, "c", (32, 9, 0))
    word_more.set("quote", word_more.bor("quote", word_more.flag("eq", "c", b32(34))))
    word_more.set("i", word_more.add("i", b32(1)))
    word_more.jump(scan_word)
    classify = f.block()
    word_end.branch(word_end.cmp("ne", "quote", b32(0)), fail, classify)
    words = ["--allow-execute", "--read-only", "--no-warm-server", "--deny", *(f"--deny={r}" for r in RIGHTS)]
    joined = match(classify, "A", "s", "i", words, "hit")
    allow, ro, nop, deny_next, deny_eq, rest = (f.block() for _ in range(6))
    joined.branch(joined.cmp("eq", "hit", b32(0)), allow, rest)
    allow.set("allow", b32(1))
    allow.jump(tokens)
    r1, r2, r3 = f.block(), f.block(), f.block()
    rest.branch(rest.cmp("eq", "hit", b32(1)), ro, r1)
    ro.set("ro", b32(1))
    ro.jump(tokens)
    r1.branch(r1.cmp("eq", "hit", b32(2)), nop, r2)
    nop.jump(tokens)
    r2.branch(r2.cmp("eq", "hit", b32(3)), deny_next, r3)
    r3.branch(r3.cmp("eq", "hit", b32(NO_KEY)), fail, deny_eq)
    # --deny=<right>: words 4.. are the rights in RIGHTS order
    table = [f.block() for _ in RIGHTS]
    switch(deny_eq, "hit", [(4 + k, blk) for k, blk in enumerate(table)], fail)
    for k, blk in enumerate(table):
        blk.set("deny", blk.bor("deny", b32(1 << k)))
        blk.jump(tokens)
    # --deny <right>: the next word must be a right
    gap = f.block()
    deny_next.jump(gap)
    gap.set("c", gap.load("A", "i"))
    gap_blank, gap_word = branch_any(gap, "c", (32, 9))
    gap_blank.set("i", gap_blank.add("i", b32(1)))
    gap_blank.jump(gap)
    gap_word.set("s", "i")
    right_word = f.block()
    gap_word.jump(right_word)
    right_word.set("c", right_word.load("A", "i"))
    rw_end, rw_more = branch_any(right_word, "c", (32, 9, 0))
    rw_more.set("i", rw_more.add("i", b32(1)))
    rw_more.jump(right_word)
    rjoin = match(rw_end, "A", "s", "i", RIGHTS, "want")
    rtable = [f.block() for _ in RIGHTS]
    switch(rjoin, "want", [(k, blk) for k, blk in enumerate(rtable)], fail)
    for k, blk in enumerate(rtable):
        blk.set("deny", blk.bor("deny", b32(1 << k)))
        blk.jump(tokens)

    # -- native compiler service (host-granted) -----------------------------------------------------------------
    # XAX_MCP_COMPILER / XAX_MCP_WORK / XAX_MCP_STORE name a native XAX compiler, a writable work directory and a
    # canonical build-request seed store.  All three are granted together; without them the compiler-backed tools fail
    # closed.  The server drives the compiler's edit/resolve/build commands (native XAX processes); it never runs an
    # interpreter and never substitutes another language.
    O_READ = 4 * 1024 * 1024          # store leading bytes and a provenance object
    O_REC = O_READ + 128 * 1024       # decoded transaction carrier
    O_PATHS = 6 * 1024 * 1024         # host paths built by pathbase/suffix
    O_ARGV = O_PATHS + 16384          # child argv array
    O_CFG = 11 * 1024 * 1024          # configuration, above any possible response
    CFG_BASE = {"compiler": 0, "work": 1024, "store": 2048}
    CFG_SPAN = {"compiler": 3072, "work": 3080, "store": 3088}
    CFG_CMD = {"resolve": 4096, "build": 4160, "edit": 4224}
    CFG_TABLE = 8192
    CFG_NAMES = {"compiler": 12288, "work": 12352, "store": 12416}
    P_COMPILER, P_STORE, P_CURRENT, P_EDIT, P_NEXT, P_SNAP, P_ART, P_PROV = (n * 1024 for n in range(8))
    P_EXEC, P_SBOX, P_SOUT, P_SERR, P_SRES = (n * 1024 for n in range(8, 13))

    def addr(b, view, off):
        return b.op1("address.offset", [f"{view}p"], P.ptr_type(view), attrs=[off])

    def paddr(b, slot):
        return addr(b, "O", O_PATHS + slot)

    def raw(b, ref):
        return b.op1("pointer.address", [ref], "b64", attrs=[1])

    def icall(b, dll, symbol, inputs, results, *args):
        return b.op("call.foreign", list(args), results, entity={"win32.import": [dll, symbol, inputs, results]})

    def place(b, view, off, data):
        for k, byte in enumerate(data):
            b.store(view, b.add(b32(off), b32(k)), ("b8", byte), 1)
        b.store(view, b.add(b32(off), b32(len(data))), ("b8", 0), 1)

    lit_l: dict[bytes, object] = {}

    def literal_l(data):
        if data not in lit_l:
            f = fn(f"litL{len(lit_l)}", ("L",), [("pos", "b32")], ["pos"])
            bb = f.entry
            for k in range(0, len(data) - len(data) % 8, 8):
                bb.store("L", bb.add("pos", b32(k)), ("b64", int.from_bytes(data[k:k + 8], "little")), 8)
            for k in range(len(data) - len(data) % 8, len(data)):
                bb.store("L", bb.add("pos", b32(k)), ("b8", data[k]), 1)
            bb.ret(bb.add("pos", b32(len(data))))
            lit_l[data] = f
        return lit_l[data]

    def emit_l(b, *parts):
        for part in parts:
            if isinstance(part, bytes):
                if part:
                    b.call(literal_l(part), "pos", into=("pos",))
            else:
                part(b)

    f = fn("decL", ("L",), [("v", "b32"), ("pos", "b32")], ["pos"], [("p", "b32"), ("d", "b32")])
    f.entry.set("p", b32(1))
    f.entry.set("d", b32(0))
    grow = f.block()
    f.entry.jump(grow)
    more, digits = grow.if_(grow.cmp("uge", grow.udiv("v", "p"), b32(10)))
    more.set("p", more.mul("p", b32(10)))
    more.jump(grow)
    body, done = digits.if_(digits.cmp("ne", "p", b32(0)))
    done.ret("pos")
    body.set("d", body.udiv("v", "p"))
    body.store("L", "pos", body.add("d", b32(48)))
    body.set("pos", body.add("pos", b32(1)))
    body.set("v", body.sub("v", body.mul("d", "p")))
    body.set("p", body.udiv("p", b32(10)))
    body.jump(digits)

    def nibble(blk, val):
        small, big, join = blk.fn.block(), blk.fn.block(), blk.fn.block()
        blk.branch(blk.cmp("ult", val, b32(10)), small, big)
        small.store("L", "pos", small.add(val, b32(48)))
        small.set("pos", small.add("pos", b32(1)))
        small.jump(join)
        big.store("L", "pos", big.add(val, b32(87)))
        big.set("pos", big.add("pos", b32(1)))
        big.jump(join)
        return join

    f = fn("hexL", ("O", "L"), [("se", "b64"), ("pos", "b32")], ["pos"],
           [("i", "b32"), ("v", "b32"), ("x", "b32"), ("d", "b32"), ("off", "b32"), ("len", "b32")])
    unspan(f.entry, "se", "off", "len")
    f.entry.set("i", b32(0))
    f.entry.set("v", b32(0))
    f.entry.set("x", b32(0))
    f.entry.set("d", b32(0))
    loop = f.block()
    f.entry.jump(loop)
    body, done = loop.if_(loop.cmp("ult", "i", "len"))
    done.ret("pos")
    body.set("v", body.load("O", body.add(b32(O_READ), body.add("off", "i"))))
    body.set("x", body.udiv("v", b32(16)))
    body.set("d", body.sub("v", body.mul("x", b32(16))))
    after = nibble(body, "x")
    after = nibble(after, "d")
    after.set("i", after.add("i", b32(1)))
    after.jump(loop)

    f = fn("hexdec", ("L", "O"), [("se", "b64")], ["n"],
           [("i", "b32"), ("q", "b32"), ("h", "b32"), ("l", "b32"), ("c", "b32"), ("n", "b32"),
            ("s", "b32"), ("e", "b32")])
    unspan(f.entry, "se", "s", "e")
    f.entry.set("q", b32(0))
    f.entry.set("n", b32(0))
    f.entry.set("h", b32(0))
    f.entry.set("l", b32(0))
    f.entry.set("c", b32(0))
    f.entry.set("i", "s")
    fail = f.block()
    fail.set("n", b32(0xFFFFFFFF))
    fail.ret("n")
    loop = f.block()
    f.entry.jump(loop)
    body, done = loop.if_(loop.cmp("ult", "i", "e"))
    done.set("n", "q")
    done.ret("n")
    body.set("c", body.load("L", "i"))
    body.set("h", body.load("O", body.add(b32(O_CFG + CFG_TABLE), "c")))
    body.set("c", body.load("L", body.add("i", b32(1))))
    body.set("l", body.load("O", body.add(b32(O_CFG + CFG_TABLE), "c")))
    bad, good = body.if_(body.bor(body.cmp("eq", "h", b32(255)), body.cmp("eq", "l", b32(255)), "b1"))
    bad.jump(fail)
    good.store("O", good.add(b32(O_REC), "q"), good.bor(good.mul("h", b32(16)), "l"))
    good.set("q", good.add("q", b32(1)))
    good.set("i", good.add("i", b32(2)))
    good.jump(loop)

    f = fn("pathbase", ("O",), [("sp", "b32"), ("dst", "b32")], ["end"],
           [("s", "b32"), ("e", "b32"), ("i", "b32"), ("end", "b32"), ("packed", "b64")])
    f.entry.set("packed", f.entry.load("O", "sp", 8))
    unspan(f.entry, "packed", "s", "e")
    f.entry.set("end", b32(0))
    f.entry.set("i", "dst")
    loop = f.block()
    f.entry.jump(loop)
    body, done = loop.if_(loop.cmp("ult", "s", "e"))
    done.store("O", "i", ("b8", 0))
    done.ret("i")
    body.store("O", "i", body.load("O", "s"))
    body.set("i", body.add("i", b32(1)))
    body.set("s", body.add("s", b32(1)))
    body.jump(loop)

    suffixes: dict[bytes, object] = {}

    def suffix(data: bytes):
        if data not in suffixes:
            f = fn(f"suf{len(suffixes)}", ("O",), [("i", "b32")], ["end"], [("end", "b32")])
            bb = f.entry
            for k, byte in enumerate(data):
                bb.store("O", bb.add("i", b32(k)), ("b8", byte), 1)
            bb.store("O", bb.add("i", b32(len(data))), ("b8", 0), 1)
            bb.ret(bb.add("i", b32(len(data))))
            suffixes[data] = f
        return suffixes[data]

    # The executor ships beside this server: resolve "<server directory>\xax-mcp-sandbox.exe" from the module path.
    f = fn("sandbox_path", ("O",), [], ["r"], [("n", "b32"), ("k", "b32"), ("c", "b32"), ("r", "b32")])
    b = f.entry
    b.set("k", b32(0))
    b.set("c", b32(0))
    b.set("r", b32(0))
    done = f.block()
    done.ret("r")
    n, = icall(b, "kernel32.dll", "GetModuleFileNameA", ["b64", "ptr", "b32"], ["b32"],
               ("b64", 0), addr(b, "O", O_PATHS + P_SBOX), b32(1024))
    b.set("n", n)
    b.set("k", b.sub("n", b32(1)))
    seek = f.block()
    b.jump(seek)
    seek.set("c", seek.load("O", seek.add(b32(O_PATHS + P_SBOX), "k")))
    found, back = seek.if_(seek.cmp("eq", "c", b32(92)))
    stop, step = back.if_(back.cmp("ult", "k", b32(1)))
    stop.jump(done)
    step.set("k", step.sub("k", b32(1)))
    step.jump(seek)
    found.set("k", found.add("k", b32(1)))
    for index, byte in enumerate(b"xax-mcp-sandbox.exe"):
        found.store("O", found.add(b32(O_PATHS + P_SBOX), found.add("k", b32(index))), ("b8", byte), 1)
    found.store("O", found.add(b32(O_PATHS + P_SBOX), found.add("k", b32(19))), ("b8", 0), 1)
    found.set("r", b32(1))
    found.jump(done)

    tool_views = ("L", "O", "W")
    tool_params = [("fs", "fs"), ("proc", "proc")]
    tool_locals = [(n, t) for n, t in (("pos", "b32"), ("n", "b32"), ("iserr", "b32"), ("i", "b32"), ("q", "b32"),
                                       ("rc", "b32"), ("attr", "b32"), ("size", "b32"), ("pn", "b32"), ("ok", "b32"),
                                       ("fd", "b32"), ("got", "b32"), ("written", "b32"), ("st", "b32"),
                                       ("ec", "b32"), ("fl", "b32"), ("wall", "b32"), ("on", "b32"), ("en", "b32"),
                                       ("rn", "b32"),
                                       ("input", "ptr"), ("cur_ptr", "ptr"), ("store_ptr", "ptr"),
                                       ("sbox", "ptr"), ("artifact", "ptr"), ("exec", "ptr"))]

    def tool_fn(name):
        return fn(name, tool_views, tool_params, ["n", "fs", "proc"], tool_locals)

    def init_tool(f):
        b = f.entry
        for name, typ in tool_locals:
            b.set(name, addr(b, "O", 0) if typ == "ptr" else b32(0))
        return b

    def build_paths(b):
        b.call(fns["pathbase"], b32(O_CFG + CFG_SPAN["compiler"]), b32(O_PATHS + P_COMPILER), into=("i",))
        b.call(fns["pathbase"], b32(O_CFG + CFG_SPAN["store"]), b32(O_PATHS + P_STORE), into=("i",))
        for slot, tail in ((P_CURRENT, b"\\current.xax"), (P_EDIT, b"\\edit.rec"), (P_NEXT, b"\\next.xax"),
                           (P_SNAP, b"\\snapshot.xax"), (P_ART, b"\\artifact.exe"), (P_PROV, b"\\artifact.prov"),
                           (P_EXEC, b"\\exec"), (P_SOUT, b"\\exec\\sandbox-out.bin"),
                           (P_SERR, b"\\exec\\sandbox-err.bin"), (P_SRES, b"\\exec\\sandbox-result.bin")):
            b.call(fns["pathbase"], b32(O_CFG + CFG_SPAN["work"]), b32(O_PATHS + slot), into=("i",))
            b.call(suffix(tail), "i", into=("i",))

    def choose_input(b):
        b.set("cur_ptr", paddr(b, P_CURRENT))
        b.set("store_ptr", paddr(b, P_STORE))
        attr, fs = icall(b, "kernel32.dll", "GetFileAttributesA", ["ptr", "fs"], ["b32", "fs"], "cur_ptr", "fs")
        b.set("fs", fs)
        use_cur, use_store, join = b.fn.block(), b.fn.block(), b.fn.block()
        b.branch(b.cmp("ne", attr, b32(0xFFFFFFFF)), use_cur, use_store)
        use_cur.set("input", "cur_ptr")
        use_cur.jump(join)
        use_store.set("input", "store_ptr")
        use_store.jump(join)
        return join

    # File and process work is emitted inline in each tool: a helper that owns a heap view and performs a foreign call
    # would return a borrowed view pointer as a second machine value, which the frame lowering cannot call, so these
    # helpers splice nodes into the caller instead.
    def emit_write(b, path_ref, length):
        fd, fs = icall(b, "msvcrt.dll", "_open", ["ptr", "b32", "b32", "fs"], ["b32", "fs"],
                       path_ref, b32(0x8301), b32(0x0180), "fs")
        b.set("fs", fs)
        b.set("fd", fd)
        bad, ok, join = b.fn.block(), b.fn.block(), b.fn.block()
        b.branch(b.cmp("slt", "fd", b32(0)), bad, ok)
        bad.jump(join)
        written, fs, mem = icall(ok, "msvcrt.dll", "_write", ["b32", "ptr", "b32", "fs", "mem"],
                                 ["b32", "fs", "mem"], "fd", addr(ok, "O", O_REC), length, "fs", "Om")
        ok.set("Om", mem)
        ok.set("fs", fs)
        ok.set("written", written)
        _, fs = icall(ok, "msvcrt.dll", "_close", ["b32", "fs"], ["b32", "fs"], "fd", "fs")
        ok.set("fs", fs)
        ok.jump(join)
        return join

    def emit_read(b, path_ref, cap, out="got"):
        fd, fs = icall(b, "msvcrt.dll", "_open", ["ptr", "b32", "b32", "fs"], ["b32", "fs"],
                       path_ref, b32(0x8000), b32(0), "fs")
        b.set("fs", fs)
        b.set("fd", fd)
        b.set(out, b32(0))
        bad, ok, join = b.fn.block(), b.fn.block(), b.fn.block()
        b.branch(b.cmp("slt", "fd", b32(0)), bad, ok)
        bad.jump(join)
        n, fs, mem = icall(ok, "msvcrt.dll", "_read", ["b32", "ptr", "b32", "fs", "mem"],
                           ["b32", "fs", "mem"], "fd", addr(ok, "O", O_READ), cap, "fs", "Om")
        ok.set("Om", mem)
        ok.set("fs", fs)
        ok.set(out, n)
        _, fs = icall(ok, "msvcrt.dll", "_close", ["b32", "fs"], ["b32", "fs"], "fd", "fs")
        ok.set("fs", fs)
        ok.jump(join)
        return join

    def emit_size(b, path_ref, out="size"):
        fd, fs = icall(b, "msvcrt.dll", "_open", ["ptr", "b32", "b32", "fs"], ["b32", "fs"],
                       path_ref, b32(0x8000), b32(0), "fs")
        b.set("fs", fs)
        b.set("fd", fd)
        b.set(out, b32(0))
        bad, ok, join = b.fn.block(), b.fn.block(), b.fn.block()
        b.branch(b.cmp("slt", "fd", b32(0)), bad, ok)
        bad.jump(join)
        size, fs = icall(ok, "msvcrt.dll", "_lseek", ["b32", "b32", "b32", "fs"], ["b32", "fs"],
                         "fd", b32(0), b32(2), "fs")
        ok.set("fs", fs)
        ok.set(out, size)
        _, fs = icall(ok, "msvcrt.dll", "_close", ["b32", "fs"], ["b32", "fs"], "fd", "fs")
        ok.set("fs", fs)
        ok.jump(join)
        return join

    def emit_spawn(b, out_rc, *names):
        for k, name in enumerate(names):
            b.store("O", b.add(b32(O_ARGV), b32(8 * k)), raw(b, name), 8)
        b.store("O", b.add(b32(O_ARGV), b32(8 * len(names))), ("b64", 0), 8)
        code, proc = icall(b, "msvcrt.dll", "_spawnv", ["b32", "ptr", "ptr", "proc"], ["b32", "proc"],
                           b32(0), names[0], addr(b, "O", O_ARGV), "proc")
        b.set("proc", proc)
        b.set(out_rc, code)

    def finish_error(b, code, message):
        b.set("pos", b32(0))
        b.set("iserr", b32(1))
        emit_l(b, b'{"error":{"code":"' + code.encode() + b'","message":"' + message.encode() + b'"},"ok":false}')
        b.set("n", b.bor("pos", b.mul("iserr", b32(1 << 31))))

    # xax_build: resolve then build the current store; report root, artifact size and provenance.
    f = tool_fn("tool_build")
    done = f.block()
    b = init_tool(f)
    b.set("pos", b32(0))
    b.set("iserr", b32(0))
    b.set("size", b32(0))
    b.set("pn", b32(0))
    build_paths(b)
    b = choose_input(b)
    emit_spawn(b, "rc", paddr(b, P_COMPILER), addr(b, "O", O_CFG + CFG_CMD["resolve"]), "input", paddr(b, P_SNAP))
    bad, good = b.if_(b.cmp("ne", "rc", b32(0)))
    finish_error(bad, "compiler_rejected", "the native compiler rejected the request store while resolving")
    bad.jump(done)
    b = good
    emit_spawn(b, "rc", paddr(b, P_COMPILER), addr(b, "O", O_CFG + CFG_CMD["build"]), paddr(b, P_SNAP),
               paddr(b, P_ART), paddr(b, P_PROV))
    bad, good = b.if_(b.cmp("ne", "rc", b32(0)))
    finish_error(bad, "compiler_rejected", "the native compiler rejected the snapshot while building")
    bad.jump(done)
    b = good
    b = emit_size(b, paddr(b, P_ART), "size")
    b = emit_read(b, "input", b32(64))
    bad, good = b.if_(b.bor(b.cmp("ult", "got", b32(39)), b.cmp("eq", "size", b32(0)), "b1"))
    finish_error(bad, "build_failed", "the build produced no artifact or the store has no readable root")
    bad.jump(done)
    b = good
    b.set("pos", b32(0))
    emit_l(b, b'{"ok":true,"root":"')
    b.call(fns["hexL"], span(b, b32(7), b32(32)), "pos", into=("pos",))
    emit_l(b, b'","artifact":{"bytes":')
    b.call(fns["decL"], "size", "pos", into=("pos",))
    emit_l(b, b'},"provenance":{"bytes":')
    b = emit_read(b, paddr(b, P_PROV), b32(65536), "pn")
    bad, good = b.if_(b.cmp("eq", "pn", b32(0)))
    finish_error(bad, "build_failed", "the build produced no provenance object")
    bad.jump(done)
    b = good
    b.call(fns["decL"], "pn", "pos", into=("pos",))
    emit_l(b, b',"hex":"')
    b.call(fns["hexL"], span(b, b32(0), "pn"), "pos", into=("pos",))
    emit_l(b, b'"}}')
    b.set("n", b.bor("pos", b.mul("iserr", b32(1 << 31))))
    b.jump(done)
    done.ret("n", "fs", "proc")

    # xax_execute: resolve and build the current store, then run the artifact inside the native OS sandbox.
    # The launcher (xax-mcp-sandbox.exe, built from native/sandbox.py) creates a capability-less AppContainer in a job
    # object with fixed CPU/memory/process/wall limits, pipes the artifact's stdout/stderr back, and writes
    # <work>\exec\sandbox-{out,err,result}.bin.  The prototype takes no arguments; anything else fails closed.
    f = tool_fn("tool_execute")
    done = f.block()
    b = init_tool(f)
    b.set("pos", b32(0))
    b.set("iserr", b32(0))
    b.set("size", b32(0))
    b.set("pn", b32(0))
    build_paths(b)
    b.set("i", b.load("W", b32(RES + 96), 4))    # the dispatch parked the arguments span here
    b.set("q", b.load("W", b32(RES + 100), 4))
    b.call(fns["scan"], "i", "q", into=("st",))
    bad, ready = b.if_(b.cmp("ne", b.load("W", b32(RES + 4 * SLOT_COUNT), 4), b32(0)))
    finish_error(bad, "invalid_request",
                 "xax_execute takes no arguments yet: it builds the current store and runs that artifact "
                 "(input/output/argv/effects/limits are not implemented; docs/NATIVE.md)")
    bad.jump(done)
    b = ready
    b = choose_input(b)
    emit_spawn(b, "rc", paddr(b, P_COMPILER), addr(b, "O", O_CFG + CFG_CMD["resolve"]), "input", paddr(b, P_SNAP))
    bad, good = b.if_(b.cmp("ne", "rc", b32(0)))
    finish_error(bad, "compiler_rejected", "the native compiler rejected the request store while resolving")
    bad.jump(done)
    b = good
    emit_spawn(b, "rc", paddr(b, P_COMPILER), addr(b, "O", O_CFG + CFG_CMD["build"]), paddr(b, P_SNAP),
               paddr(b, P_ART), paddr(b, P_PROV))
    bad, good = b.if_(b.cmp("ne", "rc", b32(0)))
    finish_error(bad, "build_failed", "the native compiler could not build the current store")
    bad.jump(done)
    b = good
    b.call(fns["sandbox_path"], into=("pn",))
    bad, good = b.if_(b.cmp("eq", "pn", b32(0)))
    finish_error(bad, "sandbox_unavailable",
                 "no native sandbox launcher (xax-mcp-sandbox.exe) is installed beside this server")
    bad.jump(done)
    b = good
    _, = icall(b, "kernel32.dll", "CreateDirectoryA", ["ptr", "b64"], ["b32"], paddr(b, P_EXEC), ("b64", 0))
    b.set("artifact", paddr(b, P_ART))
    b.set("exec", paddr(b, P_EXEC))
    b.set("sbox", paddr(b, P_SBOX))
    emit_spawn(b, "rc", "sbox", "artifact", "exec")
    bad, good = b.if_(b.cmp("ne", "rc", b32(0)))
    finish_error(bad, "sandbox_failed",
                 "the native sandbox launcher refused to run the artifact (confinement or setup failure)")
    bad.jump(done)
    b = good
    b = emit_read(b, paddr(b, P_SRES), b32(64), "rn")
    bad, good = b.if_(b.cmp("ult", "rn", b32(16)))
    finish_error(bad, "sandbox_failed", "the native sandbox launcher wrote no result record")
    bad.jump(done)
    b = good
    b.set("ec", b.load("O", b32(O_READ), 4))
    b.set("fl", b.load("O", b32(O_READ + 4), 4))
    b.set("wall", b.trunc(b.load("O", b32(O_READ + 8), 8)))
    b = emit_read(b, paddr(b, P_SOUT), b32(1 << 20), "on")
    b.set("pos", b32(0))
    emit_l(b, b'{"duration_ms":')
    b.call(fns["decL"], "wall", "pos", into=("pos",))
    emit_l(b, b',"exit_code":')
    b.call(fns["decL"], "ec", "pos", into=("pos",))
    emit_l(b, b',"flags":')
    b.call(fns["decL"], "fl", "pos", into=("pos",))
    emit_l(b, b',"ok":true,"stdout_bytes":')
    b.call(fns["decL"], "on", "pos", into=("pos",))
    emit_l(b, b',"stdout_hex":"')
    b.call(fns["hexL"], span(b, b32(0), "on"), "pos", into=("pos",))
    emit_l(b, b'","stderr_bytes":')
    # the stderr read reuses the same buffer, so it happens after the stdout hex has been written out
    b = emit_read(b, paddr(b, P_SERR), b32(1 << 20), "en")
    b.call(fns["decL"], "en", "pos", into=("pos",))
    emit_l(b, b',"stderr_hex":"')
    b.call(fns["hexL"], span(b, b32(0), "en"), "pos", into=("pos",))
    emit_l(b, b'"}')
    b.set("n", b.bor("pos", b.mul("iserr", b32(1 << 31))))
    b.jump(done)
    done.ret("n", "fs", "proc")

    # xax_workspace / xax_query: describe the current store (root and size).
    f = tool_fn("tool_info")
    done = f.block()
    b = init_tool(f)
    b.set("pos", b32(0))
    b.set("iserr", b32(0))
    b.set("size", b32(0))
    build_paths(b)
    b = choose_input(b)
    b = emit_read(b, "input", b32(64))
    b = emit_size(b, "input", "size")
    bad, good = b.if_(b.cmp("ult", "got", b32(39)))
    finish_error(bad, "workspace_unavailable", "the current store could not be read (need at least 39 bytes)")
    bad.jump(done)
    b = good
    b.set("pos", b32(0))
    emit_l(b, b'{"bytes":')
    b.call(fns["decL"], "size", "pos", into=("pos",))
    emit_l(b, b',"ok":true,"root":"')
    b.call(fns["hexL"], span(b, b32(7), b32(32)), "pos", into=("pos",))
    emit_l(b, b'","workspace":"ws_0"}')
    b.set("n", b.bor("pos", b.mul("iserr", b32(1 << 31))))
    b.jump(done)
    done.ret("n", "fs", "proc")

    # xax_transaction: decode the hex XAXEDIT1 record, apply it with edit, replace the current store.
    f = tool_fn("tool_transaction")
    done = f.block()
    b = init_tool(f)
    b.set("pos", b32(0))
    b.set("iserr", b32(0))
    b.set("pn", b32(0))
    build_paths(b)
    b.set("i", b.load("W", b32(RES + 96), 4))  # handle parked the arguments span here
    b.set("q", b.load("W", b32(RES + 100), 4))
    b.call(fns["scan"], "i", "q", into=("st",))
    b.set("i", b.load("W", b32(RES + 8 * RECORD_KEY), 4))
    no_record, have_record = b.if_(b.cmp("eq", "i", b32(0)))
    finish_error(no_record, "invalid_request", "arguments must contain a hex 'record' string")
    no_record.jump(done)
    b = have_record
    b.set("q", b.load("W", b32(RES + 8 * RECORD_KEY + 4), 4))
    quoted, unquoted = b.if_(b.cmp("ne", b.load("L", "i"), b32(34)))
    finish_error(quoted, "invalid_request", "the record must be a JSON string")
    quoted.jump(done)
    b = unquoted
    b.call(fns["hexdec"], span(b, b.add("i", b32(1)), b.sub("q", b32(1))), into=("pn",))
    bad, good = b.if_(b.cmp("eq", "pn", b32(0xFFFFFFFF)))
    finish_error(bad, "invalid_request", "the record is not valid hex")
    bad.jump(done)
    b = good
    (flag,) = b.call(eq("O", b"XAXEDIT1"), b32(O_REC), b32(O_REC + 8))
    bad, good = b.if_(b.cmp("eq", flag, b32(0)))
    finish_error(bad, "invalid_request", "the record is not an XAXEDIT1 transaction")
    bad.jump(done)
    b = good
    b = choose_input(b)
    b = emit_write(b, paddr(b, P_EDIT), "pn")
    bad, good = b.if_(b.cmp("ne", "written", "pn"))
    finish_error(bad, "io_error", "the transaction record was not written completely")
    bad.jump(done)
    b = good
    emit_spawn(b, "rc", paddr(b, P_COMPILER), addr(b, "O", O_CFG + CFG_CMD["edit"]), "input",
               paddr(b, P_EDIT), paddr(b, P_NEXT))
    bad, good = b.if_(b.cmp("ne", "rc", b32(0)))
    finish_error(bad, "transaction_rejected", "the native compiler rejected the transaction record")
    bad.jump(done)
    b = good
    moved, fs = icall(b, "kernel32.dll", "MoveFileExA", ["ptr", "ptr", "b32", "fs"], ["b32", "fs"],
                      paddr(b, P_NEXT), paddr(b, P_CURRENT), b32(1), "fs")
    b.set("fs", fs)
    b.set("ok", moved)
    bad, good = b.if_(b.cmp("eq", "ok", b32(0)))
    finish_error(bad, "io_error", "the edited store could not replace the current store")
    bad.jump(done)
    b = good
    b = emit_read(b, paddr(b, P_CURRENT), b32(64))
    bad, good = b.if_(b.cmp("ult", "got", b32(39)))
    finish_error(bad, "transaction_rejected", "the edited store could not be read")
    bad.jump(done)
    b = good
    b.set("pos", b32(0))
    emit_l(b, b'{"generation":1,"ok":true,"root":"')
    b.call(fns["hexL"], span(b, b32(7), b32(32)), "pos", into=("pos",))
    emit_l(b, b'","workspace":"ws_0"}')
    b.set("n", b.bor("pos", b.mul("iserr", b32(1 << 31))))
    b.jump(done)
    done.ret("n", "fs", "proc")

    # -- one message: L[0:len] -> response bytes in O[0:pos] (pos 0: no response) --------------------------------
    f = fn("head", ("L", "O"), [("se", "b64"), ("pos", "b32")], ["pos"], [("ids", "b32"), ("ide", "b32")])
    unspan(f.entry, "se", "ids", "ide")
    with_id, null_id = f.entry.if_(f.entry.cmp("ne", "ids", b32(0)))
    emit(with_id, b'{"jsonrpc":"2.0","id":', ("copy", "ids", "ide"))
    with_id.ret("pos")
    emit(null_id, b'{"jsonrpc":"2.0","id":null')
    null_id.ret("pos")

    names = ["len", "over", "rights", "pos", "st", "c", "hasid", "ids", "ide", "js", "je", "ms", "me", "ps", "pe",
             "rs", "es", "ns", "ne", "as", "ae", "vs", "ve", "ver", "tool", "flag", "count", "ks", "ke", "xs", "xe",
             "configured", "plen", "iserr", "packed_out", "cs", "ce", "ws", "we", "ss", "se"]
    f = fn("handle", ("L", "O", "W"), [("packed", "b32"), ("fs", "fs"), ("proc", "proc")],
           ["pos", "fs", "proc"], [(n, "b32") for n in names])
    b = f.entry
    for name in names[3:]:
        b.set(name, b32(0))
    b.set("len", b.band("packed", b32((1 << 23) - 1)))  # packed = len | over << 23 | rights << 24
    b.set("over", b.band(b.udiv("packed", b32(1 << 23)), b32(1)))
    b.set("rights", b.udiv("packed", b32(1 << 24)))
    unspan(b, b.load("O", b32(O_CFG + CFG_SPAN["compiler"]), 8), "cs", "ce")
    unspan(b, b.load("O", b32(O_CFG + CFG_SPAN["work"]), 8), "ws", "we")
    unspan(b, b.load("O", b32(O_CFG + CFG_SPAN["store"]), 8), "ss", "se")
    b.set("configured", b.band(b.band(b.flag("ne", "cs", "ce"), b.flag("ne", "ws", "we")), b.flag("ne", "ss", "se")))

    def respond(block, *parts):
        block.call(fns["head"], span(block, block.mul("ids", "hasid"), "ide"), "pos", into=("pos",))
        emit(block, *parts)
        block.ret("pos", "fs", "proc")

    def rpc_error(code, message):
        return b',"error":{"code":%d,"message":"%s"}}\n' % (code, message.encode())

    def tool_result(payload: bytes, is_error: bool):
        return (b',"result":{"content":[{"text":"' + escape(payload) + b'","type":"text"}],"isError":'
                + (b"true" if is_error else b"false") + b',"structuredContent":' + payload + b"}}\n")

    def tool_result_parts(pieces, is_error: bool):
        """Like tool_result, for a payload of literal and dynamic pieces (written escaped, then raw)."""
        text = [escape(p) if isinstance(p, bytes) else p[1] for p in pieces]
        raw = [p if isinstance(p, bytes) else p[0] for p in pieces]
        return [b',"result":{"content":[{"text":"', *text, b'","type":"text"}],"isError":',
                b"true" if is_error else b"false", b',"structuredContent":', *raw, b"}}\n"]

    too_large, parse_error, invalid, ignore, not_found = (f.block() for _ in range(5))
    respond(too_large, rpc_error(-32600, f"Invalid Request: the message exceeds {LMAX} bytes"))
    respond(parse_error, rpc_error(-32700, "Parse error"))
    respond(invalid, rpc_error(-32600, "Invalid Request"))
    ignore.ret(b32(0), "fs", "proc")
    respond(not_found, b',"error":{"code":-32601,"message":"Method not found","data":', ("copy", "ms", "me"), b"}}\n")
    fits = f.block()
    b.branch(b.cmp("ne", "over", b32(0)), too_large, fits)
    b = fits
    b.store("L", "len", ("b8", 0))
    (start,) = b.call(fns["skip_ws"], b32(0))
    scan_it = f.block()
    b.branch(b.cmp("eq", start, "len"), ignore, scan_it)
    b = scan_it
    b.call(fns["scan"], b32(0), "len", into=("st",))
    parsed, object_ = f.block(), f.block()
    b.branch(b.cmp("ne", "st", b32(0)), parse_error, parsed)
    parsed.branch(parsed.cmp("eq", parsed.load("L", parsed.load("W", b32(RES + 4 * SLOT_TOP), 4)), b32(123)), object_, invalid)
    b = object_
    for name, slot in (("js", 0), ("je", 1), ("ids", 2), ("ide", 3), ("ms", 4), ("me", 5), ("ps", 6), ("pe", 7),
                       ("rs", 14), ("es", 16)):
        b.set(name, b.load("W", b32(RES + 4 * slot), 4))
    # id: absent (notification), or a string or a number (MCP forbids null ids)
    has_id, no_id = b.if_(b.cmp("ne", "ids", b32(0)))
    has_id.set("c", has_id.load("L", "ids"))
    valid_id = f.block()
    string_or_minus, other_id = branch_any(has_id, "c", (34, 45))
    string_or_minus.jump(valid_id)
    other_id.branch(digit(other_id, "c"), valid_id, invalid)
    valid_id.set("hasid", b32(1))
    valid_id.jump(no_id)
    b = no_id
    # "jsonrpc": "2.0"
    rpc_string, version_check = f.block(), f.block()
    b.branch(b.cmp("eq", "js", b32(0)), invalid, rpc_string)
    rpc_string.branch(rpc_string.cmp("eq", rpc_string.load("L", "js"), b32(34)), version_check, invalid)
    (flag,) = version_check.call(eq("L", b"2.0"), version_check.add("js", b32(1)), version_check.sub("je", b32(1)))
    methodless_check, has_method = f.block(), f.block()
    rpc_ok = f.block()
    version_check.branch(version_check.cmp("ne", flag, b32(0)), rpc_ok, invalid)
    rpc_ok.branch(rpc_ok.cmp("eq", "ms", b32(0)), methodless_check, has_method)
    # no method: a client response (result/error with an id) is ignored; anything else is invalid
    reply = methodless_check.band("hasid", methodless_check.flag("ne", methodless_check.bor("rs", "es"), b32(0)))
    methodless_check.branch(methodless_check.cmp("ne", reply, b32(0)), ignore, invalid)
    method_string, request = f.block(), f.block()
    has_method.branch(has_method.cmp("eq", has_method.load("L", "ms"), b32(34)), method_string, invalid)
    method_string.branch(method_string.cmp("eq", "hasid", b32(0)), ignore, request)  # notifications get no reply
    methods = ["initialize", "ping", "tools/list", "tools/call"]
    request.set("xs", request.add("ms", b32(1)))
    request.set("xe", request.sub("me", b32(1)))
    b = match(request, "L", "xs", "xe", methods, "flag")
    initialize, ping, tools_list, tools_call = (f.block() for _ in methods)
    switch(b, "flag", [(k, blk) for k, blk in enumerate((initialize, ping, tools_list, tools_call))], not_found)
    respond(ping, b',"result":{}}\n')
    respond(tools_list, b',"result":' + tools_json() + b"}\n")
    # initialize: echo a supported handshake version, otherwise offer the latest one
    b = initialize
    b.set("ver", b32(len(HANDSHAKE_VERSIONS) - 1))
    params_object, versioned = f.block(), f.block()
    rescan, no_params = b.if_(b.cmp("ne", "ps", b32(0)))
    no_params.jump(versioned)
    rescan.branch(rescan.cmp("eq", rescan.load("L", "ps"), b32(123)), params_object, versioned)
    params_object.call(fns["scan"], "ps", "pe", into=("st",))
    params_object.set("vs", params_object.load("W", b32(RES + 32), 4))
    params_object.set("ve", params_object.load("W", b32(RES + 36), 4))
    offered = f.block()
    params_object.branch(params_object.cmp("ne", "vs", b32(0)), offered, versioned)
    string_version = f.block()
    offered.branch(offered.cmp("eq", offered.load("L", "vs"), b32(34)), string_version, versioned)
    string_version.set("xs", string_version.add("vs", b32(1)))
    string_version.set("xe", string_version.sub("ve", b32(1)))
    joined = match(string_version, "L", "xs", "xe", HANDSHAKE_VERSIONS, "flag")
    known, unknown_version = joined.if_(joined.cmp("ne", "flag", b32(NO_KEY)))
    known.set("ver", "flag")
    known.jump(versioned)
    unknown_version.jump(versioned)
    b = versioned
    b.call(fns["head"], span(b, b.mul("ids", "hasid"), "ide"), "pos", into=("pos",))
    emit(b, b',"result":{"capabilities":{"tools":{"listChanged":false}},"instructions":' + json.dumps(INSTRUCTIONS).encode()
         + b',"protocolVersion":"')
    done = f.block()
    branches = [f.block() for _ in HANDSHAKE_VERSIONS]
    switch(b, "ver", [(k, blk) for k, blk in enumerate(branches)], done)
    for version, blk in zip(HANDSHAKE_VERSIONS, branches):
        emit(blk, version.encode())
        blk.jump(done)
    emit(done, b'","serverInfo":' + compact({"name": "xax-mcp", "title": "XAX MCP server", "version": VERSION}) + b"}}\n")
    done.ret("pos", "fs", "proc")
    # tools/call
    b = tools_call
    invalid_params = f.block()
    respond(invalid_params, rpc_error(-32602, "Invalid params"))
    p_object, named = f.block(), f.block()
    p_present = f.block()
    b.branch(b.cmp("eq", "ps", b32(0)), invalid_params, p_present)
    p_present.branch(p_present.cmp("eq", p_present.load("L", "ps"), b32(123)), p_object, invalid_params)
    p_object.call(fns["scan"], "ps", "pe", into=("st",))
    for name, slot in (("ns", 10), ("ne", 11), ("as", 12), ("ae", 13)):
        p_object.set(name, p_object.load("W", b32(RES + 4 * slot), 4))
    n_present = f.block()
    p_object.branch(p_object.cmp("eq", "ns", b32(0)), invalid_params, n_present)
    n_present.branch(n_present.cmp("eq", n_present.load("L", "ns"), b32(34)), named, invalid_params)
    args_ok, args_present = f.block(), f.block()
    named.branch(named.cmp("eq", "as", b32(0)), args_ok, args_present)
    args_present.branch(args_present.cmp("eq", args_present.load("L", "as"), b32(123)), args_ok, invalid_params)
    tool_names = ["xax_capabilities", *TOOL_RIGHTS]
    args_ok.set("xs", args_ok.add("ns", b32(1)))
    args_ok.set("xe", args_ok.sub("ne", b32(1)))
    b = match(args_ok, "L", "xs", "xe", tool_names, "tool")
    unknown, known_tool = f.block(), f.block()
    b.branch(b.cmp("eq", "tool", b32(NO_KEY)), unknown, known_tool)
    unknown.set("ns", unknown.add("ns", b32(1)))
    unknown.set("ne", unknown.sub("ne", b32(1)))
    name_span = (("copy", "ns", "ne"), ("esc", "ns", "ne"))
    respond(unknown, *tool_result_parts(
        [b'{"error":{"code":"unsupported","message":"unknown tool \'', name_span, b'\'"},"ok":false}'], True))
    # argument size (raw bytes; the Python server measures the compact re-serialization)
    sized, too_big = f.block(), f.block()
    known_tool.branch(known_tool.cmp("ugt", known_tool.sub("ae", "as"), b32(MAX_ARGUMENTS)), too_big, sized)
    size_digits = lambda blk: blk.call(fns["dec"], blk.sub("ae", "as"), "pos", into=("pos",))  # noqa: E731
    respond(too_big, *tool_result_parts([b'{"error":{"code":"resource_limit","message":"arguments are ',
                                         (size_digits, size_digits), b" bytes; the limit is %d\"},\"ok\":false}" % MAX_ARGUMENTS], True))
    capabilities, gated = f.block(), f.block()
    sized.branch(sized.cmp("eq", "tool", b32(0)), capabilities, gated)
    # xax_capabilities {}: no properties are allowed
    b = capabilities
    counted, report = f.block(), f.block()
    check_args, no_args = b.if_(b.cmp("ne", "as", b32(0)))
    no_args.jump(report)
    check_args.call(fns["scan"], "as", "ae", into=("st",))
    check_args.set("count", check_args.load("W", b32(RES + 4 * SLOT_COUNT), 4))
    check_args.set("ks", check_args.load("W", b32(RES + 4 * SLOT_KEY_START), 4))
    check_args.set("ke", check_args.load("W", b32(RES + 4 * SLOT_KEY_END), 4))
    check_args.branch(check_args.cmp("eq", "count", b32(0)), report, counted)
    one, many = counted.if_(counted.cmp("eq", "count", b32(1)))
    key_span = (("copy", "ks", "ke"), ("esc", "ks", "ke"))
    respond(one, *tool_result_parts([b'{"error":{"code":"invalid_request","details":{"errors":1},"message":"(root): '
                                     b"Additional properties are not allowed ('", key_span, b"' was unexpected)\"},\"ok\":false}"], True))
    count_digits = lambda blk: blk.call(fns["dec"], "count", "pos", into=("pos",))  # noqa: E731
    respond(many, *tool_result_parts([b'{"error":{"code":"invalid_request","details":{"errors":1},"message":"(root): '
                                      b"Additional properties are not allowed (", (count_digits, count_digits),
                                      b' properties were unexpected)"},"ok":false}'], True))
    head, tail = compact(capabilities_payload()).split(b'"__RIGHTS__"')
    rights_raw = lambda blk: blk.call(fns["rights_raw"], "rights", "pos", into=("pos",))  # noqa: E731
    rights_esc = lambda blk: blk.call(fns["rights_esc"], "rights", "pos", into=("pos",))  # noqa: E731
    respond(report, *tool_result_parts([head, (rights_raw, rights_esc), tail], False))
    # every other tool: the host right first, then the compiler-backed implementation or the honest report
    targets = [f.block() for _ in TOOL_RIGHTS]
    unreachable = f.block()
    unreachable.ret(b32(0), "fs", "proc")
    switch(gated, "tool", [(k + 1, blk) for k, blk in enumerate(targets)], unreachable)
    compiler_tools = {"xax_workspace": "tool_info", "xax_query": "tool_info", "xax_transaction": "tool_transaction",
                      "xax_build": "tool_build", "xax_execute": "tool_execute"}
    unsupported_reasons = {
        "xax_construct": "XAX publishes no native carrier decoder (construct)",
        "xax_result": "result handles need session state, which the native server does not implement yet",
    }
    for (tool, right), blk in zip(TOOL_RIGHTS.items(), targets):
        flag_ = "--allow-execute" if right == "execute" else f"--grant {right}"
        denied = error_payload("denied_capability", f"this server was not granted the '{right}' right by its host configuration",
                               repair=[f"the host owner may add {flag_} to the server launch command"])
        unsupported = error_payload("unsupported", f"{tool} is not implemented by the native XAX server: "
                                    f"{unsupported_reasons.get(tool, 'the tool has no native implementation')}; "
                                    "it fails closed (docs/NATIVE.md)")
        allowed, refused = blk.if_(blk.cmp("ne", blk.band("rights", b32(1 << RIGHTS.index(right))), b32(0)))
        respond(refused, tool_result(compact(denied), True))
        if tool in compiler_tools:
            ungranted = error_payload("denied_capability",
                                      "the host granted no native XAX compiler; set XAX_MCP_COMPILER, XAX_MCP_WORK and "
                                      "XAX_MCP_STORE in the server launch environment",
                                      repair=["set XAX_MCP_COMPILER/XAX_MCP_WORK/XAX_MCP_STORE to a native XAX compiler, "
                                              "a writable directory and a seed .xax store"])
            ready, unconfigured = allowed.if_(allowed.cmp("ne", "configured", b32(0)))
            respond(unconfigured, tool_result(compact(ungranted), True))
            ready.call(fns["head"], span(ready, ready.mul("ids", "hasid"), "ide"), "pos", into=("pos",))
            ready.store("W", b32(RES + 96), "as", 4)   # the tool reads the arguments span from here
            ready.store("W", b32(RES + 100), "ae", 4)
            ready.call(fns[compiler_tools[tool]], "fs", "proc", into=("packed_out", "fs", "proc"))
            ready.set("iserr", ready.udiv("packed_out", b32(1 << 31)))
            ready.set("plen", ready.band("packed_out", b32((1 << 31) - 1)))
            failed, succeeded = ready.if_(ready.cmp("ne", "iserr", b32(0)))
            emit(succeeded, b',"result":{"content":[{"text":"', ("esc", b32(0), "plen"),
                 b'","type":"text"}],"isError":false,"structuredContent":', ("copy", b32(0), "plen"), b"}}\n")
            succeeded.ret("pos", "fs", "proc")
            emit(failed, b',"result":{"content":[{"text":"', ("esc", b32(0), "plen"),
                 b'","type":"text"}],"isError":true,"structuredContent":', ("copy", b32(0), "plen"), b"}}\n")
            failed.ret("pos", "fs", "proc")
        else:
            respond(allowed, tool_result(compact(unsupported), True))

    # -- process entry: STDIO loop ------------------------------------------------------------------------------
    views = tuple(VIEWS)
    main_locals = [(f"{v}p", P.ptr_type(v)) for v in views] + [(f"{v}v", P.view_type(v)) for v in views]
    main_locals += [(n, "b64") for n in ("hin", "hout", "herr")]
    main_locals += [(n, "b32") for n in ("len", "over", "rights", "ok", "n", "j", "c", "out", "code")]
    main = P.fn("main", views, [], [], main_locals, entry=True)
    b = main.entry
    for var, handle in (("hin", 0xFFFFFFF6), ("hout", 0xFFFFFFF5), ("herr", 0xFFFFFFF4)):
        value, proc = b.op("call.foreign", [b32(handle), "proc"], ["b64", "proc"], entity="win32.get_std_handle")
        b.set("proc", proc)
        b.set(var, value)
    for v, extent in VIEWS.items():
        pointer, owner, mem = b.op("call.foreign", [("b64", 0), ("b64", max(extent, 4096)), b32(0x3000), b32(4), f"{v}m"],
                                   ["win32.heap_ptr_rw", "win32.heap_resource", "mem"], entity="win32.virtual_alloc")
        vp, vv, vm = b.op("heap.view", [pointer, owner, mem], [P.ptr_type(v), P.view_type(v), "mem"],
                          attrs=[extent, 4 if v == "N" else 1])
        b.set(f"{v}p", vp)
        b.set(f"{v}v", vv)
        b.set(f"{v}m", vm)
    for name in ("len", "over", "rights", "ok", "n", "j", "c", "out", "code"):
        b.set(name, b32(0))
    command_line, proc = b.op("call.foreign", ["proc"], ["b64", "proc"],
                              entity={"win32.import": ["kernel32.dll", "GetCommandLineA", ["proc"], ["b64", "proc"]]})
    b.set("proc", proc)
    _, mem = b.op("call.foreign", ["Ap", command_line, b32(32768), "Am"], ["b64", "mem"],
                  entity={"win32.import": ["kernel32.dll", "lstrcpynA", ["ptr", "b64", "b32", "mem"], ["b64", "mem"]]})
    b.set("Am", mem)
    # Host-granted native compiler configuration, the hex decode table and the environment variable names live in O,
    # above any response, so every compiler-backed tool reads them from there.
    place(b, "O", O_CFG + CFG_NAMES["compiler"], b"XAX_MCP_COMPILER")
    place(b, "O", O_CFG + CFG_NAMES["work"], b"XAX_MCP_WORK")
    place(b, "O", O_CFG + CFG_NAMES["store"], b"XAX_MCP_STORE")
    place(b, "O", O_CFG + CFG_TABLE, HEX_TABLE)
    for cmd in CFG_CMD:
        place(b, "O", O_CFG + CFG_CMD[cmd], cmd.encode())
    for key, buffer in CFG_BASE.items():
        length, mem = b.op("call.foreign", [addr(b, "O", O_CFG + CFG_NAMES[key]),
                                            addr(b, "O", O_CFG + buffer), b32(512), "Om"],
                           ["b32", "mem"],
                           entity={"win32.import": ["kernel32.dll", "GetEnvironmentVariableA",
                                                    ["ptr", "ptr", "b32", "mem"], ["b32", "mem"]]})
        b.set("Om", mem)
        # A missing variable returns 0; an over-long value would be truncated, so clamp it to zero length and let the
        # tool fail closed rather than read past the 512-byte buffer into the next configuration slot.
        fits = b.cmp("ult", length, b32(512))
        clamped = b.band(length, b.sub(b32(0), b.zext(fits, "b32")))
        b.store("O", b32(O_CFG + CFG_SPAN[key]),
                span(b, b32(O_CFG + buffer), b.add(b32(O_CFG + buffer), clamped)), 8)
    b.call(fns["parse_args"], into=("rights",))
    EXIT, READ, COPY, LINE, WRITE, EOF, refuse = (main.block() for _ in range(7))
    b.branch(b.cmp("eq", "rights", b32(0)), refuse, READ)
    # unsupported flags: report on stderr and exit 2 rather than run with authority the host did not intend
    refuse.set("out", b32(0))
    message = (b"xax-mcp-native: unsupported command-line argument (supported: --allow-execute, --read-only, "
               b"--deny RIGHT, --deny=RIGHT, --no-warm-server)\n")
    refuse.set("code", b32(2))
    refuse.call(literal(message), "out", into=("out",))
    rptr = refuse.op1("pointer.cast", ["Op"], "rptr")
    _, fs, mem = refuse.op("call.foreign", ["herr", rptr, "out", "Np", ("b64", 0), "fs", "Om"], ["b32", "fs", "mem"],
                           entity="win32.write_file")
    refuse.set("fs", fs)
    refuse.set("Om", mem)
    refuse.jump(EXIT)
    ok, fs, mem = READ.op("call.foreign", ["hin", "Cp", b32(VIEWS["C"]), "Np", ("b64", 0), "fs", "Nm"],
                          ["b32", "fs", "mem"], entity="win32.read_file")
    READ.set("fs", fs)
    READ.set("Nm", mem)
    READ.set("n", READ.load("N", b32(0), 4))
    READ.set("j", b32(0))
    stop = READ.bor(READ.flag("eq", ok, b32(0)), READ.flag("eq", "n", b32(0)))
    READ.branch(READ.cmp("ne", stop, b32(0)), EOF, COPY)
    take, refill = COPY.if_(COPY.cmp("ult", "j", "n"))
    refill.jump(READ)
    take.set("c", take.load("C", "j"))
    take.set("j", take.add("j", b32(1)))
    append = main.block()
    take.branch(take.cmp("eq", "c", b32(10)), LINE, append)
    room, full = append.if_(append.cmp("ult", "len", b32(LMAX)))
    room.store("L", "len", "c")
    room.set("len", room.add("len", b32(1)))
    room.jump(COPY)
    full.set("over", b32(1))
    full.jump(COPY)
    LINE.call(fns["handle"], LINE.bor(LINE.bor("len", LINE.mul("over", b32(1 << 23))), LINE.mul("rights", b32(1 << 24))),
              "fs", "proc", into=("out", "fs", "proc"))
    LINE.set("len", b32(0))
    LINE.set("over", b32(0))
    LINE.branch(LINE.cmp("eq", "out", b32(0)), COPY, WRITE)
    rptr = WRITE.op1("pointer.cast", ["Op"], "rptr")
    written, fs, mem = WRITE.op("call.foreign", ["hout", rptr, "out", "Np", ("b64", 0), "fs", "Om"], ["b32", "fs", "mem"],
                                entity="win32.write_file")
    WRITE.set("fs", fs)
    WRITE.set("Om", mem)
    WRITE.branch(WRITE.cmp("eq", written, b32(0)), EXIT, COPY)  # the client closed its end
    # end of input: a final line without its newline is still a message
    last, quiet = EOF.if_(EOF.cmp("ne", EOF.bor("len", "over"), b32(0)))
    quiet.jump(EXIT)
    last.call(fns["handle"], last.bor(last.bor("len", last.mul("over", b32(1 << 23))), last.mul("rights", b32(1 << 24))),
              "fs", "proc", into=("out", "fs", "proc"))
    flush = main.block()
    last.branch(last.cmp("eq", "out", b32(0)), EXIT, flush)
    rptr = flush.op1("pointer.cast", ["Op"], "rptr")
    _, fs, mem = flush.op("call.foreign", ["hout", rptr, "out", "Np", ("b64", 0), "fs", "Om"], ["b32", "fs", "mem"],
                          entity="win32.write_file")
    flush.set("fs", fs)
    flush.set("Om", mem)
    flush.jump(EXIT)
    for v, extent in VIEWS.items():
        _, mem = EXIT.op("call.foreign", [f"{v}p", ("b64", 0), b32(0x8000), f"{v}v", f"{v}m"], ["b32", "mem"],
                         entity={"win32.virtual_free_view": [P.ptr_type(v), extent]})
        EXIT.set(f"{v}m", mem)
    (proc,) = EXIT.op("call.foreign", ["code", "proc"], ["proc"], entity="win32.exit_process")
    EXIT.set("proc", proc)
    EXIT.ret_raw("code", "proc", "fs", *(f"{v}m" for v in views))
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
    (out / "construction_request.json").write_bytes(compact(request) + b"\n")
    constructed = construct(request)
    store = constructed.reader.canonical_bytes()
    (out / "xax-mcp-native-gen0.xax").write_bytes(store)
    artifact = build(constructed.reader, constructed.release_request.cid).artifact
    (out / "xax-mcp-native.exe").write_bytes(artifact)
    print(json.dumps({"xax": NATIVE_XAX_COMMIT, "root": constructed.reader.root_cid.hex(),
                      "release_request": constructed.release_request.cid.hex(),
                      "store_bytes": len(store), "store_sha256": hashlib.sha256(store).hexdigest(),
                      "artifact_bytes": len(artifact), "artifact_sha256": hashlib.sha256(artifact).hexdigest(),
                      "functions": len(request["functions"])}, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
