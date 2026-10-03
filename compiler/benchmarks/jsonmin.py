"""``jsonmin``: a JSON validator and minifier as an ordinary XAX program (R3 workload).

Behavior (identical to ``jsonmin_c/jsonmin.c`` and :func:`reference_jsonmin`):

* read all of standard input (at most ``CAPACITY`` bytes);
* validate it as one RFC 8259 JSON text: whitespace, ``true``/``false``/``null``,
  numbers, strings (control characters rejected; escapes ``\\" \\\\ \\/ \\b \\f
  \\n \\r \\t \\uXXXX``), arrays, and objects, nested at most ``MAX_DEPTH`` deep;
  bytes >= 0x80 inside strings are copied unchecked (no UTF-8 validation);
* valid: write the text with all insignificant whitespace removed, plus
  ``\\n``, to standard output and exit 0;
* invalid: write ``jsonmin: invalid JSON at byte N\\n`` to standard error and
  exit 1, where ``N`` is the offset of the first byte that cannot continue a
  valid text (the input length for a premature end); input larger than
  ``CAPACITY`` exits 2.

The parser is one recursion group (value, array, object: mutual recursion,
ADR-125) plus plain functions for whitespace, strings, numbers, and literals.
Each function borrows the input and output views and takes and returns its
state as one ``bits<64>``: position in the low half, output length in the
high half, or an error position with the high half all ones.  The input view
is one byte longer than ``CAPACITY`` and zero-filled, so the byte after the
input is always 0: no scan needs a bounds compare, because a 0 byte stops it
at the same position the contract reports for a premature end.  Python is
only the construction tool (:mod:`xax_structured`).
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass

from xax_compiler import (
    IntCompare,
    Operation,
    Permission,
    RecursionMember,
    SemanticObject,
    StoreReader,
    canonical_recursion_order,
    group_member_function,
    heap_view_type,
    memory_effect_type,
    pointer_type,
    recursion_group,
)
from xax_graph_builder import program_store
from xax_structured import B1, B8, B32, B64, Proc

CAPACITY = 16 << 20
MAX_DEPTH = 512
EXIT_OK, EXIT_INVALID, EXIT_TOO_LARGE = 0, 1, 2
CHUNK = 65536
MESSAGE = b"jsonmin: invalid JSON at byte "
ERROR = 0xFFFFFFFF  # high half of a failed state

LT, LE, GT, GE, EQ, NE = IntCompare.ULT, IntCompare.ULE, IntCompare.UGT, IntCompare.UGE, IntCompare.EQ, IntCompare.NE
MEM = memory_effect_type()
BYTES = pointer_type(B8, Permission.READ_WRITE, 1, space=2)
# The input view holds CAPACITY bytes, the 0 byte after the input, and room
# for one more CHUNK-byte read window past CAPACITY (the too-large check).
INPUT_EXTENT = CAPACITY + CHUNK + 1
IN_VIEW, OUT_VIEW = heap_view_type(INPUT_EXTENT), heap_view_type(CAPACITY + 1)
TRIPLES = (("ip", BYTES), ("iv", IN_VIEW), ("im", MEM), ("op", BYTES), ("ov", OUT_VIEW), ("om", MEM))
TRIPLE_TYPES = tuple(type_ for _name, type_ in TRIPLES)
NAMES = tuple(name for name, _type in TRIPLES)
STATE = (B64, *TRIPLE_TYPES)


def _views(proc: Proc) -> tuple:
    return tuple(proc[name] for name in NAMES)


def _take_views(proc: Proc, values) -> None:
    for name, value in zip(NAMES, values):
        proc[name] = value


def _low(proc: Proc, state):
    return proc.op1(Operation.INT_TRUNCATE, (state,), B32)


def _high(proc: Proc, state):
    return proc.op1(Operation.INT_TRUNCATE, (proc.op1(Operation.ROTATE_RIGHT, (state,), B64, attributes=(32,)),), B32)


def _pack(proc: Proc, low, high):
    shifted = proc.op1(Operation.ROTATE_RIGHT, (proc.widen(proc._value(high, B32), B64),), B64, attributes=(32,))
    return proc.op1(Operation.BIT_OR, (proc.widen(proc._value(low, B32), B64), shifted), B64)


def _peek(proc: Proc, position):
    value, proc["im"] = proc.op(Operation.CHECKED_LOAD_BITS_LE, (proc["ip"], position, proc["im"]), (B8, MEM), attributes=(1, 1))
    return proc.widen(value)


def _emit(proc: Proc, byte) -> None:
    narrow = proc.op1(Operation.INT_TRUNCATE, (byte,), B8) if not isinstance(byte, int) else proc.const(byte, B8)
    proc["om"] = proc.op1(Operation.CHECKED_STORE_BITS_LE, (proc["op"], proc["out"], narrow, proc["om"]), MEM, attributes=(1, 1))
    proc["out"] = proc.bin(Operation.ADD_WRAP, proc["out"], 1)


def _begin(proc: Proc) -> None:
    proc.let("pos", B32, _low(proc, proc["state"]))
    proc.let("out", B32, _high(proc, proc["state"]))


def _finish(proc: Proc, state=None) -> None:
    proc.ret(state if state is not None else _pack(proc, proc["pos"], proc["out"]), *_views(proc))


def _fail(proc: Proc) -> None:
    proc.ret(_pack(proc, proc["pos"], ERROR), *_views(proc))


def _failed(proc: Proc, state):
    return proc.cmp(EQ, _high(proc, state), ERROR)


def _call(proc: Proc, function: SemanticObject, depth=None) -> None:
    """Call a parser function; a failure returns from the caller unchanged."""
    extra = () if depth is None else (depth,)
    state, *views = proc.op(Operation.CALL_DIRECT, (*extra, _pack(proc, proc["pos"], proc["out"]), *_views(proc)), STATE, entity=function)
    _take_views(proc, views)
    proc.if_(_failed(proc, state), lambda p: _finish(p, state))
    proc["pos"], proc["out"] = _low(proc, state), _high(proc, state)


def _group(proc: Proc, member: int, depth) -> None:
    state, *views = proc.group_call(member, (depth, _pack(proc, proc["pos"], proc["out"]), *_views(proc)), STATE)
    _take_views(proc, views)
    proc.if_(_failed(proc, state), lambda p: _finish(p, state))
    proc["pos"], proc["out"] = _low(proc, state), _high(proc, state)


def _current(proc: Proc):
    return _peek(proc, proc["pos"])


def _advance(proc: Proc) -> None:
    proc["pos"] = proc.bin(Operation.ADD_WRAP, proc["pos"], 1)


def _copy(proc: Proc) -> None:
    _emit(proc, _current(proc))
    _advance(proc)


def _is(proc: Proc, value, *bytes_: int):
    return proc.any_of(*(proc.cmp(EQ, value, byte) for byte in bytes_))


def _in_range(proc: Proc, value, low: int, high: int):
    return proc.cmp(LE, proc.bin(Operation.SUB_WRAP, value, low), high - low)


def _new() -> Proc:
    proc = Proc((("state", B64), *TRIPLES))
    _begin(proc)
    return proc


def _done(proc: Proc):
    function = proc.function(STATE)
    return function, (*proc.graph.objects.values(), function)


def whitespace_function():
    proc = _new()
    proc.while_(lambda p: _is(p, _current(p), 0x20, 0x09, 0x0A, 0x0D), _advance)
    _finish(proc)
    return _done(proc)


def string_function():
    """At an opening quote: copy the string through its closing quote."""
    proc = _new()
    _copy(proc)
    proc.let("byte", B32, _current(proc))

    def body(p: Proc):
        byte = p["byte"]
        p.if_(p.cmp(LT, byte, 0x20), _fail)  # includes the 0 byte after the input
        _copy(p)

        def escape(q: Proc):
            escaped = _current(q)

            def unicode(r: Proc):
                _copy(r)
                for _ in range(4):
                    digit = _current(r)
                    hexadecimal = r.any_of(_in_range(r, digit, 0x30, 0x39), _in_range(r, digit, 0x41, 0x46), _in_range(r, digit, 0x61, 0x66))
                    r.if_(hexadecimal, None, _fail)
                    _copy(r)

            def simple(r: Proc):
                r.if_(_is(r, escaped, 0x22, 0x5C, 0x2F, 0x62, 0x66, 0x6E, 0x72, 0x74), None, _fail)
                _copy(r)

            q.if_(q.cmp(EQ, escaped, 0x75), unicode, simple)

        p.if_(p.cmp(EQ, byte, 0x5C), escape)
        p["byte"] = _current(p)

    # Loop until the byte just copied was the closing quote.
    proc.let("last", B32, proc.const(0))

    def step(p: Proc):
        p["last"] = p["byte"]
        body(p)

    proc.while_(lambda p: p.cmp(NE, p["last"], 0x22), step)
    _finish(proc)
    return _done(proc)


def _digits(proc: Proc, minimum: int) -> None:
    start = proc["pos"]
    proc.while_(lambda p: _in_range(p, _current(p), 0x30, 0x39), _copy)
    if minimum:
        proc.if_(proc.cmp(EQ, proc["pos"], start), _fail)


def _optional(proc: Proc, *bytes_: int):
    return _is(proc, _current(proc), *bytes_)


def number_function():
    proc = _new()
    proc.if_(_optional(proc, 0x2D), _copy)
    proc.if_(proc.cmp(EQ, _current(proc), 0x30), _copy, lambda p: _digits(p, 1))

    def fraction(p: Proc):
        _copy(p)
        _digits(p, 1)

    proc.if_(_optional(proc, 0x2E), fraction)

    def exponent(p: Proc):
        _copy(p)
        p.if_(_optional(p, 0x2B, 0x2D), _copy)
        _digits(p, 1)

    proc.if_(_optional(proc, 0x65, 0x45), exponent)
    _finish(proc)
    return _done(proc)


def literal_function():
    proc = _new()
    first = _current(proc)
    for word in (b"true", b"false", b"null"):
        def matched(p: Proc, word=word):
            for byte in word:
                p.if_(p.cmp(EQ, _current(p), byte), None, _fail)
                _emit(p, byte)
                _advance(p)
            _finish(p)

        proc.if_(proc.cmp(EQ, first, word[0]), matched)
    _fail(proc)
    return _done(proc)


@dataclass(frozen=True)
class Helpers:
    whitespace: SemanticObject
    string: SemanticObject
    number: SemanticObject
    literal: SemanticObject
    objects: tuple[SemanticObject, ...]


def helpers() -> Helpers:
    built = [whitespace_function(), string_function(), number_function(), literal_function()]
    return Helpers(*(function for function, _objects in built), tuple(item for _function, objects in built for item in objects))


def _member(kind: str, h: Helpers, index: dict[str, int]):
    """One recursion-group member graph; ``index`` maps value/array/object to member numbers."""
    proc = Proc((("depth", B32), ("state", B64), *TRIPLES))
    _begin(proc)
    if kind == "value":
        proc.if_(proc.cmp(GT, proc["depth"], MAX_DEPTH), _fail)
        _call(proc, h.whitespace)
        byte = _current(proc)
        nested = proc.bin(Operation.ADD_WRAP, proc["depth"], 1)
        for test, target in (
            (lambda p: p.cmp(EQ, byte, 0x7B), ("group", "object")),
            (lambda p: p.cmp(EQ, byte, 0x5B), ("group", "array")),
            (lambda p: p.cmp(EQ, byte, 0x22), ("call", h.string)),
            (lambda p: p.any_of(p.cmp(EQ, byte, 0x2D), _in_range(p, byte, 0x30, 0x39)), ("call", h.number)),
            (lambda p: _is(p, byte, 0x74, 0x66, 0x6E), ("call", h.literal)),
        ):
            def dispatch(p: Proc, target=target):
                if target[0] == "group":
                    state, *views = p.group_call(index[target[1]], (nested, _pack(p, p["pos"], p["out"]), *_views(p)), STATE)
                else:
                    state, *views = p.op(Operation.CALL_DIRECT, (_pack(p, p["pos"], p["out"]), *_views(p)), STATE, entity=target[1])
                _take_views(p, views)
                _finish(p, state)  # success or failure: the callee's state is the result

            proc.if_(test(proc), dispatch)
        _fail(proc)  # includes the 0 byte after the input
    else:
        opening, closing = (0x5B, 0x5D) if kind == "array" else (0x7B, 0x7D)
        _copy(proc)
        _call(proc, h.whitespace)
        proc.if_(_optional(proc, closing), lambda p: (_copy(p), _finish(p)))
        proc.let("more", B1, proc.const(1, B1))

        def element(p: Proc):
            if kind == "object":
                _call(p, h.whitespace)
                p.if_(_optional(p, 0x22), None, _fail)
                _call(p, h.string)
                _call(p, h.whitespace)
                p.if_(_optional(p, 0x3A), None, _fail)
                _copy(p)
            _group(p, index["value"], p["depth"])
            _call(p, h.whitespace)

            def close(q: Proc):
                q.if_(_optional(q, closing), None, _fail)
                _copy(q)
                q["more"] = q.const(0, B1)

            p.if_(_optional(p, 0x2C), _copy, close)

        proc.while_(lambda p: p.cmp(NE, p.widen(p["more"]), 0), element)
        _finish(proc)
    return RecursionMember(proc.fragment(), (B32, *STATE), STATE), tuple(proc.graph.objects.values())


def parser_group(h: Helpers):
    """The value/array/object group in canonical member order."""
    for permutation in itertools.permutations(("value", "array", "object")):
        index = {kind: position for position, kind in enumerate(permutation)}
        built = [_member(kind, h, index) for kind in permutation]
        members = [member for member, _objects in built]
        objects = {item.cid: item for _member_, extra in built for item in (*extra, _member_.graph)}
        objects.update((item.cid, item) for item in h.objects)
        if canonical_recursion_order(members, objects.__getitem__) == tuple(range(3)):
            group = recursion_group(members)
            return group, index, (*objects.values(), group)
    raise AssertionError("no canonical member order")


@dataclass(frozen=True)
class JsonminProgram:
    reader: StoreReader
    entry: SemanticObject
    target: SemanticObject


def build_jsonmin(arch: str = "x86_64") -> JsonminProgram:
    if arch == "aarch64":
        from xax_compiler import aarch64_linux_exec_target
        from xax_linux_aarch64 import linux_aarch64_api

        api, target = linux_aarch64_api(), aarch64_linux_exec_target()
    else:
        from xax_compiler import x86_64_linux_exec_target
        from xax_linux import linux_api

        api, target = linux_api(), x86_64_linux_exec_target()
    h = helpers()
    group, index, group_objects = parser_group(h)
    value = group_member_function(group, index["value"])
    proc = Proc((("proc", api.process_effect), ("fs", api.filesystem_effect), ("m1", MEM), ("m2", MEM)))

    def mapping(memory: str, extent: int, view, name: str):
        raw, owner, effect = proc.op(Operation.CALL_FOREIGN, (proc.const(extent, B64), proc.drop(memory)), (api.bytes_rw, api.heap_owner, MEM), entity=api.mmap_anonymous)
        p, v, m = proc.op(Operation.HEAP_VIEW, (raw, owner, effect), (BYTES, view, MEM), attributes=(extent, 1))
        for suffix, value_, type_ in (("p", p, BYTES), ("v", v, view), ("m", m, MEM)):
            proc.let(name + suffix, type_, value_)

    mapping("m1", INPUT_EXTENT, IN_VIEW, "i")
    mapping("m2", CAPACITY + 1, OUT_VIEW, "o")
    proc.let("total", B32, proc.const(0))
    proc.let("reading", B1, proc.const(1, B1))
    proc.let("code", B32, proc.const(EXIT_OK))
    # Read straight into the input view through a CHUNK-byte window at the
    # current length: the ADR-092 rebase idiom, checked against the view.
    base = proc.op1(Operation.POINTER_ADDRESS, (proc["ip"],), B64, attributes=(1,))

    def read_chunk(p: Proc):
        address = p.bin(Operation.ADD_WRAP, base, p.widen(p["total"], B64), B64)
        window = p.op1(Operation.POINTER_REBASE, (p["ip"], address), BYTES, attributes=(CHUNK,))
        count, p["fs"], p["im"] = p.op(Operation.CALL_FOREIGN, (p.const(0), window, p.const(CHUNK, B64), p["fs"], p["im"]), (B64, api.filesystem_effect, MEM), entity=api.read)

        def stop(q: Proc):
            q["code"] = q.const(EXIT_TOO_LARGE)
            q["reading"] = q.const(0, B1)

        def got(q: Proc):
            q["total"] = q.bin(Operation.ADD_WRAP, q["total"], q.op1(Operation.INT_TRUNCATE, (count,), B32))
            q.if_(q.cmp(GT, q["total"], CAPACITY), stop)

        # Zero ends input; a kernel error (-errno, unsigned) stops with status 2.
        p.if_(p.cmp(EQ, count, 0, B64), lambda q: q.__setitem__("reading", q.const(0, B1)), lambda q: q.if_(q.cmp(GT, count, CHUNK, B64), stop, got))

    proc.while_(lambda p: p.cmp(NE, p.widen(p["reading"]), 0), read_chunk)
    proc.let("where", B32, proc.const(0))  # error position, or output length on success

    def parse(p: Proc):
        state, *results = p.op(Operation.CALL_DIRECT, (p.const(0), p.const(0, B64), *_views_of(p)), STATE, entity=value)
        _take_entry_views(p, results)

        def trailing(q: Proc):
            after, *results = q.op(Operation.CALL_DIRECT, (state, *_views_of(q)), STATE, entity=h.whitespace)
            _take_entry_views(q, results)
            position = _low(q, after)
            q["where"] = _high(q, after)
            q.if_(q.cmp(NE, position, q["total"]), lambda r: (r.__setitem__("code", r.const(EXIT_INVALID)), r.__setitem__("where", position)))

        def failed(q: Proc):
            q["code"] = q.const(EXIT_INVALID)
            q["where"] = _low(q, state)

        p.if_(_failed(p, state), failed, trailing)

    proc.if_(proc.cmp(EQ, proc["code"], EXIT_OK), parse)

    def write(p: Proc, fd: int, length):
        readable = p.op1(Operation.POINTER_CAST, (p["op"],), api.bytes_read)
        _count, p["fs"], p["om"] = p.op(Operation.CALL_FOREIGN, (p.const(fd), readable, p.widen(length, B64), p["fs"], p["om"]), (B64, api.filesystem_effect, MEM), entity=api.write)

    def success(p: Proc):
        p["om"] = p.op1(Operation.CHECKED_STORE_BITS_LE, (p["op"], p["where"], p.const(0x0A, B8), p["om"]), MEM, attributes=(1, 1))
        write(p, 1, p.bin(Operation.ADD_WRAP, p["where"], 1))

    def invalid(p: Proc):
        position = p["where"]
        for offset, byte in enumerate(MESSAGE):
            p["om"] = p.op1(Operation.CHECKED_STORE_BITS_LE, (p["op"], p.const(offset), p.const(byte, B8), p["om"]), MEM, attributes=(1, 1))
        p.let("digits", B32, p.const(1))
        p.let("scan", B32, position)
        p.while_(lambda q: q.cmp(GE, q["scan"], 10), lambda q: (q.__setitem__("scan", q.bin(Operation.UDIV, q["scan"], 10)), q.__setitem__("digits", q.bin(Operation.ADD_WRAP, q["digits"], 1))))
        p.let("k", B32, p["digits"])
        p.let("v", B32, position)

        def digit(q: Proc):
            q["k"] = q.bin(Operation.SUB_WRAP, q["k"], 1)
            ascii_ = q.op1(Operation.INT_TRUNCATE, (q.bin(Operation.ADD_WRAP, q.bin(Operation.UREM, q["v"], 10), 0x30),), B8)
            q["om"] = q.op1(Operation.CHECKED_STORE_BITS_LE, (q["op"], q.bin(Operation.ADD_WRAP, q["k"], len(MESSAGE)), ascii_, q["om"]), MEM, attributes=(1, 1))
            q["v"] = q.bin(Operation.UDIV, q["v"], 10)

        p.while_(lambda q: q.cmp(NE, q["k"], 0), digit)
        end = p.bin(Operation.ADD_WRAP, p["digits"], len(MESSAGE))
        p["om"] = p.op1(Operation.CHECKED_STORE_BITS_LE, (p["op"], end, p.const(0x0A, B8), p["om"]), MEM, attributes=(1, 1))
        write(p, 2, p.bin(Operation.ADD_WRAP, end, 1))

    proc.if_(proc.cmp(EQ, proc["code"], EXIT_OK), success, lambda p: p.if_(p.cmp(EQ, p["code"], EXIT_INVALID), invalid))
    for name, extent in (("i", INPUT_EXTENT), ("o", CAPACITY + 1)):
        _result, proc[name + "m"] = proc.op(Operation.CALL_FOREIGN, (proc[name + "p"], proc[name + "v"], proc[name + "m"]), (B64, MEM), entity=api.munmap_view(BYTES, extent))
    process = proc.op1(Operation.CALL_FOREIGN, (proc["code"], proc["proc"]), api.process_effect, entity=api.exit_group)
    proc.ret(proc["code"], process, proc["fs"], proc["im"], proc["om"])
    entry = proc.function((B32, api.process_effect, api.filesystem_effect, MEM, MEM))
    objects = (*api.types, *proc.graph.objects.values(), *group_objects, value, *h.objects, B64)
    reader = program_store(entry, target, objects)
    return JsonminProgram(reader, entry, target)


_ENTRY_VIEWS = ("ip", "iv", "im", "op", "ov", "om")


def _views_of(proc: Proc) -> tuple:
    return tuple(proc[name] for name in _ENTRY_VIEWS)


def _take_entry_views(proc: Proc, values) -> None:
    for name, value in zip(_ENTRY_VIEWS, values):
        proc[name] = value


# -- the exact contract, stated independently ------------------------------------------


class _Invalid(Exception):
    def __init__(self, position: int):
        self.position = position


def reference_jsonmin(data: bytes) -> tuple[int, bytes, bytes]:
    """``(exit status, stdout, stderr)`` of jsonmin on ``data``."""
    if len(data) > CAPACITY:
        return EXIT_TOO_LARGE, b"", b""
    import sys

    sys.setrecursionlimit(max(sys.getrecursionlimit(), 6 * MAX_DEPTH + 100))
    out = bytearray()
    position = 0

    def ws():
        nonlocal position
        while position < len(data) and data[position] in b" \t\n\r":
            position += 1

    def fail():
        raise _Invalid(position)

    def need():
        if position >= len(data):
            fail()
        return data[position]

    def copy():
        nonlocal position
        out.append(data[position])
        position += 1

    def string():
        copy()
        while True:
            byte = need()
            if byte < 0x20:
                fail()
            copy()
            if byte == 0x5C:
                escaped = need()
                if escaped == 0x75:
                    copy()
                    for _ in range(4):
                        if need() not in b"0123456789abcdefABCDEF":
                            fail()
                        copy()
                elif escaped in b'"\\/bfnrt':
                    copy()
                else:
                    fail()
            elif byte == 0x22:
                return

    def digits(minimum: int):
        count = 0
        while position < len(data) and 0x30 <= data[position] <= 0x39:
            copy()
            count += 1
        if count < minimum:
            fail()

    def number():
        if data[position] == 0x2D:
            copy()
        if need() == 0x30:
            copy()
        else:
            digits(1)
        if position < len(data) and data[position] == 0x2E:
            copy()
            digits(1)
        if position < len(data) and data[position] in b"eE":
            copy()
            if position < len(data) and data[position] in b"+-":
                copy()
            digits(1)

    def literal():
        for word in (b"true", b"false", b"null"):
            if data[position] == word[0]:
                for byte in word:
                    if need() != byte:
                        fail()
                    copy()
                return
        fail()

    def value(depth: int):
        if depth > MAX_DEPTH:
            fail()
        ws()
        byte = need()
        if byte == 0x7B:
            container(depth + 1, 0x7B, 0x7D, True)
        elif byte == 0x5B:
            container(depth + 1, 0x5B, 0x5D, False)
        elif byte == 0x22:
            string()
        elif byte == 0x2D or 0x30 <= byte <= 0x39:
            number()
        elif byte in b"tfn":
            literal()
        else:
            fail()

    def container(depth: int, opening: int, closing: int, keyed: bool):
        nonlocal position
        copy()
        ws()
        if position < len(data) and data[position] == closing:
            copy()
            return
        while True:
            if keyed:
                ws()
                if not (position < len(data) and data[position] == 0x22):
                    fail()
                string()
                ws()
                if not (position < len(data) and data[position] == 0x3A):
                    fail()
                copy()
            value(depth)
            ws()
            if position < len(data) and data[position] == 0x2C:
                copy()
                continue
            if not (position < len(data) and data[position] == closing):
                fail()
            copy()
            return

    try:
        value(0)
        ws()
        if position != len(data):
            fail()
    except _Invalid as error:
        return EXIT_INVALID, b"", MESSAGE + str(error.position).encode() + b"\n"
    return EXIT_OK, bytes(out) + b"\n", b""


# -- measurement -------------------------------------------------------------------------

def benchmark_document(target_bytes: int, seed: int = 125) -> bytes:
    """Deterministic pretty-printed JSON of nested records, arrays, escapes, and numbers."""
    import random

    rng = random.Random(seed)
    words = ["alpha", "beta", "gamma", "delta", "epsilon", "zeta", "eta", "theta"]

    def scalar():
        kind = rng.randrange(6)
        if kind == 0:
            return str(rng.randrange(-10**6, 10**6))
        if kind == 1:
            return f"{rng.random() * 1000:.6f}e{rng.randrange(-5, 6)}"
        if kind == 2:
            return rng.choice(["true", "false", "null"])
        text = " ".join(rng.choice(words) for _ in range(rng.randrange(1, 6)))
        return '"' + text.replace("e", "\\n", 1).replace("a", "\\u00e1", 1) + '"'

    def node(depth: int, indent: str) -> str:
        if depth > 4 or rng.random() < 0.3:
            return scalar()
        inner = indent + "  "
        if rng.random() < 0.5:
            items = [inner + node(depth + 1, inner) for _ in range(rng.randrange(1, 6))]
            return "[\n" + ",\n".join(items) + "\n" + indent + "]"
        items = [f'{inner}"{rng.choice(words)}{index}" : {node(depth + 1, inner)}' for index in range(rng.randrange(1, 6))]
        return "{\n" + ",\n".join(items) + "\n" + indent + "}"

    records, size = [], 2
    while size < target_bytes:
        record = "  " + node(0, "  ")
        records.append(record)
        size += len(record) + 2
    return ("[\n" + ",\n".join(records) + "\n]\n").encode()


def run_benchmark(size: int, repetitions: int, warmup: int) -> dict:
    import hashlib
    import tempfile
    from pathlib import Path

    from benchmarks.linux_harness import build_arms, host_info, measure_arms, method_info, run_output
    from xax_linux import compile_linux_executable

    program = build_jsonmin()
    executable = compile_linux_executable(program.reader, program.entry.cid, program.target.cid)
    source = Path(__file__).resolve().parent / "jsonmin_c" / "jsonmin.c"
    document = benchmark_document(size)
    expected_status, expected, _stderr = reference_jsonmin(document)
    if expected_status != EXIT_OK:
        raise AssertionError("benchmark document must be valid JSON")
    with tempfile.TemporaryDirectory() as directory:
        work = Path(directory)
        artifacts, stripped = build_arms(work, "jsonmin", executable.data, source)
        input_path = work / "input.json"
        input_path.write_bytes(document)

        def validate(arm: str, path: Path) -> bytes:
            output, status = run_output(path, work, input_path)
            if status != 0 or output != expected:
                raise AssertionError(f"{arm}: status {status}, output differs from the reference")
            return output

        results, _output, reference_rss = measure_arms(work, artifacts, stripped, repetitions, warmup, validate, input_path)
    for item in results.values():
        item["throughput_mib_s_median"] = round(len(document) / (1 << 20) / item["wall_seconds_median"], 2)
    return {
        "format": "xax-jsonmin-evidence-v1",
        "evidence_label": "MEASURED",
        "workload": "jsonmin: read stdin, validate RFC 8259 JSON (depth <= 512), write it minified; recursive descent through a three-member recursion group (ADR-125)",
        "input": {"bytes": len(document), "sha256": hashlib.sha256(document).hexdigest(), "generator": "benchmark_document(size, seed=125)"},
        "output": {"bytes": len(expected), "sha256": hashlib.sha256(expected).hexdigest()},
        "xax": {
            "program_root": program.reader.root_cid.hex(),
            "entry_function": program.entry.cid.hex(),
            "target": program.target.cid.hex(),
            "artifact_sha256": hashlib.sha256(executable.data).hexdigest(),
            "artifact_bytes": len(executable.data),
            "runtime_dependencies": [],
            "container": "x86_64-linux-elf-exec-v1 (static; no libc, loader, or allocator: four explicit anonymous mappings)",
        },
        "results": results,
        "host": host_info(),
        "method": method_info(warmup, repetitions, reference_rss),
    }


def main(argv: list[str] | None = None) -> int:
    import argparse
    import json
    import sys
    from pathlib import Path

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--size", type=int, default=8 << 20)
    parser.add_argument("--repetitions", type=int, default=11)
    parser.add_argument("--warmup", type=int, default=2)
    parser.add_argument("--write", action="store_true")
    arguments = parser.parse_args(argv)
    evidence = run_benchmark(arguments.size, arguments.repetitions, arguments.warmup)
    text = json.dumps(evidence, indent=2, sort_keys=True) + "\n"
    if arguments.write:
        (Path(__file__).resolve().parent / "jsonmin_evidence.json").write_text(text)
    sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
