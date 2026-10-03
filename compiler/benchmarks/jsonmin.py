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
Every function borrows three heap views (input, output, a 12-byte context of
position, output length, and input length) and returns a status.  Python is
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
    bits_type,
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

LT, LE, GT, GE, EQ, NE = IntCompare.ULT, IntCompare.ULE, IntCompare.UGT, IntCompare.UGE, IntCompare.EQ, IntCompare.NE
MEM = memory_effect_type()
BYTES = pointer_type(B8, Permission.READ_WRITE, 1, space=2)
WORDS = pointer_type(B32, Permission.READ_WRITE, 4, space=2)
IN_VIEW, OUT_VIEW, CTX_VIEW = heap_view_type(CAPACITY), heap_view_type(CAPACITY + 1), heap_view_type(12)
TRIPLES = (("ip", BYTES), ("iv", IN_VIEW), ("im", MEM), ("op", BYTES), ("ov", OUT_VIEW), ("om", MEM), ("cp", WORDS), ("cv", CTX_VIEW), ("cm", MEM))
TRIPLE_TYPES = tuple(type_ for _name, type_ in TRIPLES)
NAMES = tuple(name for name, _type in TRIPLES)
POS, OUT, LEN = 0, 4, 8
OK = 0


def _views(proc: Proc) -> tuple:
    return tuple(proc[name] for name in NAMES)


def _take_views(proc: Proc, values) -> None:
    for name, value in zip(NAMES, values):
        proc[name] = value


def _load_ctx(proc: Proc, offset: int):
    value, proc["cm"] = proc.op(Operation.CHECKED_LOAD_BITS_LE, (proc["cp"], proc.const(offset), proc["cm"]), (B32, MEM), attributes=(4, 1))
    return value


def _store_ctx(proc: Proc, offset: int, value) -> None:
    proc["cm"] = proc.op1(Operation.CHECKED_STORE_BITS_LE, (proc["cp"], proc.const(offset), value, proc["cm"]), MEM, attributes=(4, 1))


def _peek(proc: Proc, position):
    value, proc["im"] = proc.op(Operation.CHECKED_LOAD_BITS_LE, (proc["ip"], position, proc["im"]), (B8, MEM), attributes=(1, 1))
    return proc.widen(value)


def _emit(proc: Proc, byte) -> None:
    narrow = proc.op1(Operation.INT_TRUNCATE, (byte,), B8) if not isinstance(byte, int) else proc.const(byte, B8)
    proc["om"] = proc.op1(Operation.CHECKED_STORE_BITS_LE, (proc["op"], proc["out"], narrow, proc["om"]), MEM, attributes=(1, 1))
    proc["out"] = proc.bin(Operation.ADD_WRAP, proc["out"], 1)


def _begin(proc: Proc) -> None:
    """Load position, output length, and input length into locals."""
    proc.let("pos", B32, _load_ctx(proc, POS))
    proc.let("out", B32, _load_ctx(proc, OUT))
    proc.let("len", B32, _load_ctx(proc, LEN))


def _save(proc: Proc) -> None:
    _store_ctx(proc, POS, proc["pos"])
    _store_ctx(proc, OUT, proc["out"])


def _finish(proc: Proc, status) -> None:
    """Write locals back and return ``status`` with the borrowed views."""
    _save(proc)
    proc.ret(proc._value(status, B32), *_views(proc))


def _fail_at(proc: Proc, code: int) -> None:
    _finish(proc, code)


def _call(proc: Proc, function: SemanticObject, extra=()):
    """Call a plain parser function: locals go through the context."""
    _save(proc)
    status, *views = proc.op(Operation.CALL_DIRECT, (*extra, *_views(proc)), (B32, *TRIPLE_TYPES), entity=function)
    _take_views(proc, views)
    proc["pos"] = _load_ctx(proc, POS)
    proc["out"] = _load_ctx(proc, OUT)
    return status


def _group(proc: Proc, member: int, depth):
    _save(proc)
    status, *views = proc.group_call(member, (depth, *_views(proc)), (B32, *TRIPLE_TYPES))
    _take_views(proc, views)
    proc["pos"] = _load_ctx(proc, POS)
    proc["out"] = _load_ctx(proc, OUT)
    return status


def _at_end(proc: Proc):
    return proc.cmp(GE, proc["pos"], proc["len"])


def _current(proc: Proc):
    return _peek(proc, proc["pos"])


def _advance(proc: Proc) -> None:
    proc["pos"] = proc.bin(Operation.ADD_WRAP, proc["pos"], 1)


def _is(proc: Proc, value, *bytes_: int):
    return proc.any_of(*(proc.cmp(EQ, value, byte) for byte in bytes_))


def _in_range(proc: Proc, value, low: int, high: int):
    return proc.cmp(LE, proc.bin(Operation.SUB_WRAP, value, low), high - low)


def _new() -> Proc:
    return Proc(TRIPLES)


def _done(proc: Proc):
    function = proc.function((B32, *TRIPLE_TYPES))
    return function, (*proc.graph.objects.values(), function)


def whitespace_function():
    proc = _new()
    _begin(proc)

    def more(p: Proc):
        ok = p.cmp(LT, p["pos"], p["len"])
        # Read only in bounds: the byte at len (or 0) is never consulted when ok is false.
        safe = p.op1(Operation.BIT_AND, (p["pos"], p.bin(Operation.SUB_WRAP, p.const(0), p.widen(ok))), B32)
        byte = _peek(p, safe)
        return p.all_of(ok, _is(p, byte, 0x20, 0x09, 0x0A, 0x0D))

    proc.while_(more, _advance)
    _finish(proc, OK)
    return _done(proc)


def string_function():
    """At an opening quote: copy the string through its closing quote."""
    proc = _new()
    _begin(proc)
    _emit(proc, 0x22)
    _advance(proc)
    proc.let("done", B1, proc.const(0, B1))

    def body(p: Proc):
        p.if_(_at_end(p), lambda q: _fail_at(q, 1))
        byte = _current(p)
        p.if_(p.cmp(LT, byte, 0x20), lambda q: _fail_at(q, 3))
        _emit(p, byte)
        _advance(p)

        def escape(q: Proc):
            q.if_(_at_end(q), lambda r: _fail_at(r, 1))
            escaped = _current(q)

            def unicode(r: Proc):
                _emit(r, escaped)
                _advance(r)
                for _ in range(4):
                    r.if_(_at_end(r), lambda s: _fail_at(s, 1))
                    digit = _current(r)
                    hexadecimal = r.any_of(_in_range(r, digit, 0x30, 0x39), _in_range(r, digit, 0x41, 0x46), _in_range(r, digit, 0x61, 0x66))
                    r.if_(hexadecimal, None, lambda s: _fail_at(s, 4))
                    _emit(r, digit)
                    _advance(r)

            def simple(r: Proc):
                r.if_(_is(r, escaped, 0x22, 0x5C, 0x2F, 0x62, 0x66, 0x6E, 0x72, 0x74), None, lambda s: _fail_at(s, 4))
                _emit(r, escaped)
                _advance(r)

            q.if_(q.cmp(EQ, escaped, 0x75), unicode, simple)

        p.if_(p.cmp(EQ, byte, 0x5C), escape)
        p["done"] = p.cmp(EQ, byte, 0x22)

    proc.while_(lambda p: p.cmp(EQ, p.widen(p["done"]), 0), body)
    _finish(proc, OK)
    return _done(proc)


def _digits(proc: Proc, minimum: int, code: int) -> None:
    """Copy one or more (``minimum`` 1) or zero or more ASCII digits."""
    proc.let("count", B32, proc.const(0))

    def more(p: Proc):
        ok = p.cmp(LT, p["pos"], p["len"])
        safe = p.op1(Operation.BIT_AND, (p["pos"], p.bin(Operation.SUB_WRAP, p.const(0), p.widen(ok))), B32)
        return p.all_of(ok, _in_range(p, _peek(p, safe), 0x30, 0x39))

    def copy(p: Proc):
        _emit(p, _current(p))
        _advance(p)
        p["count"] = p.bin(Operation.ADD_WRAP, p["count"], 1)

    proc.while_(more, copy)
    if minimum:
        proc.if_(proc.cmp(EQ, proc["count"], 0), lambda p: _fail_at(p, code))


def _optional(proc: Proc, *bytes_: int):
    """True (and the byte copied) when the current byte is one of ``bytes_``."""
    ok = proc.cmp(LT, proc["pos"], proc["len"])
    safe = proc.op1(Operation.BIT_AND, (proc["pos"], proc.bin(Operation.SUB_WRAP, proc.const(0), proc.widen(ok))), B32)
    return proc.all_of(ok, _is(proc, _peek(proc, safe), *bytes_))


def number_function():
    proc = _new()
    _begin(proc)

    def copy_one(p: Proc):
        _emit(p, _current(p))
        _advance(p)

    proc.if_(_optional(proc, 0x2D), copy_one)
    proc.if_(_at_end(proc), lambda p: _fail_at(p, 5))
    proc.if_(proc.cmp(EQ, _current(proc), 0x30), copy_one, lambda p: _digits(p, 1, 5))

    def fraction(p: Proc):
        copy_one(p)
        _digits(p, 1, 5)

    proc.if_(_optional(proc, 0x2E), fraction)

    def exponent(p: Proc):
        copy_one(p)
        p.if_(_optional(p, 0x2B, 0x2D), copy_one)
        _digits(p, 1, 5)

    proc.if_(_optional(proc, 0x65, 0x45), exponent)
    _finish(proc, OK)
    return _done(proc)


def literal_function():
    proc = _new()
    _begin(proc)
    first = _current(proc)
    for word in (b"true", b"false", b"null"):
        def matched(p: Proc, word=word):
            for byte in word:
                p.if_(_at_end(p), lambda q: _fail_at(q, 1))
                p.if_(p.cmp(EQ, _current(p), byte), None, lambda q: _fail_at(q, 6))
                _emit(p, byte)
                _advance(p)
            _finish(p, OK)

        proc.if_(proc.cmp(EQ, first, word[0]), matched)
    _fail_at(proc, 6)
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
    proc = Proc((("depth", B32), *TRIPLES))
    _begin(proc)

    def returned(status):
        proc.if_(proc.cmp(NE, status, OK), lambda p: _finish(p, status))

    if kind == "value":
        proc.if_(proc.cmp(GT, proc["depth"], MAX_DEPTH), lambda p: _fail_at(p, 7))
        _call(proc, h.whitespace)
        proc.if_(_at_end(proc), lambda p: _fail_at(p, 1))
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
                status = _group(p, index[target[1]], nested) if target[0] == "group" else _call(p, target[1])
                _finish(p, status)

            proc.if_(test(proc), dispatch)
        _fail_at(proc, 8)
    else:
        opening, closing = (0x5B, 0x5D) if kind == "array" else (0x7B, 0x7D)
        _emit(proc, opening)
        _advance(proc)
        _call(proc, h.whitespace)

        def empty(p: Proc):
            _emit(p, closing)
            _advance(p)
            _finish(p, OK)

        proc.if_(_optional(proc, closing), empty)
        proc.let("more", B1, proc.const(1, B1))

        def element(p: Proc):
            if kind == "object":
                _call(p, h.whitespace)
                p.if_(_optional(p, 0x22), None, lambda q: _fail_at(q, 10))
                returned_status = _call(p, h.string)
                p.if_(p.cmp(NE, returned_status, OK), lambda q: _finish(q, returned_status))
                _call(p, h.whitespace)
                p.if_(_optional(p, 0x3A), None, lambda q: _fail_at(q, 11))
                _emit(p, 0x3A)
                _advance(p)
            status = _group(p, index["value"], p["depth"])
            p.if_(p.cmp(NE, status, OK), lambda q: _finish(q, status))
            _call(p, h.whitespace)

            def comma(q: Proc):
                _emit(q, 0x2C)
                _advance(q)

            def close(q: Proc):
                q.if_(_optional(q, closing), None, lambda r: _fail_at(r, 9 if kind == "array" else 12))
                _emit(q, closing)
                _advance(q)
                q["more"] = q.const(0, B1)

            p.if_(_optional(p, 0x2C), comma, close)

        proc.while_(lambda p: p.cmp(NE, p.widen(p["more"]), 0), element)
        _finish(proc, OK)
    return RecursionMember(proc.fragment(), (B32, *TRIPLE_TYPES), (B32, *TRIPLE_TYPES)), tuple(proc.graph.objects.values())


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
    chunk_view = heap_view_type(CHUNK)
    parameters = (("proc", api.process_effect), ("fs", api.filesystem_effect), ("m1", MEM), ("m2", MEM), ("m3", MEM), ("m4", MEM))
    proc = Proc(parameters)

    def mapping(memory: str, extent: int, pointer, view, name: str):
        raw, owner, effect = proc.op(Operation.CALL_FOREIGN, (proc.const(extent, B64), proc.drop(memory)), (api.bytes_rw, api.heap_owner, MEM), entity=api.mmap_anonymous)
        p, v, m = proc.op(Operation.HEAP_VIEW, (raw, owner, effect), (pointer, view, MEM), attributes=(extent, 4 if pointer is WORDS else 1))
        for suffix, value_, type_ in (("p", p, pointer), ("v", v, view), ("m", m, MEM)):
            proc.let(name + suffix, type_, value_)

    mapping("m1", CAPACITY, BYTES, IN_VIEW, "i")
    mapping("m2", CAPACITY + 1, BYTES, OUT_VIEW, "o")
    mapping("m3", 12, WORDS, CTX_VIEW, "c")
    mapping("m4", CHUNK, BYTES, chunk_view, "k")
    proc.let("total", B32, proc.const(0))
    proc.let("reading", B1, proc.const(1, B1))
    proc.let("code", B32, proc.const(EXIT_OK))

    def read_chunk(p: Proc):
        count, p["fs"], p["km"] = p.op(Operation.CALL_FOREIGN, (p.const(0), p["kp"], p.const(CHUNK, B64), p["fs"], p["km"]), (B64, api.filesystem_effect, MEM), entity=api.read)
        p.if_(p.cmp(EQ, count, 0, B64), lambda q: q.__setitem__("reading", q.const(0, B1)))

        def stop(r: Proc):
            r["code"] = r.const(EXIT_TOO_LARGE)
            r["reading"] = r.const(0, B1)

        def got(q: Proc):
            # A kernel error (-errno, unsigned) also stops with status 2.
            q.if_(q.cmp(GT, count, CHUNK, B64), stop, accept)

        def accept(q: Proc):
            n = q.op1(Operation.INT_TRUNCATE, (count,), B32)

            def fits(r: Proc):
                r.let("j", B32, r.const(0))

                def copy(s: Proc):
                    byte, s["km"] = s.op(Operation.CHECKED_LOAD_BITS_LE, (s["kp"], s["j"], s["km"]), (B8, MEM), attributes=(1, 1))
                    s["im"] = s.op1(Operation.CHECKED_STORE_BITS_LE, (s["ip"], s.bin(Operation.ADD_WRAP, s["total"], s["j"]), byte, s["im"]), MEM, attributes=(1, 1))
                    s["j"] = s.bin(Operation.ADD_WRAP, s["j"], 1)

                r.while_(lambda s: s.cmp(LT, s["j"], n), copy)
                r["total"] = r.bin(Operation.ADD_WRAP, r["total"], n)

            too_large = q.cmp(GT, n, q.bin(Operation.SUB_WRAP, q.const(CAPACITY), q["total"]))
            q.if_(too_large, stop, fits)

        p.if_(p.cmp(NE, count, 0, B64), got)

    proc.while_(lambda p: p.cmp(NE, p.widen(p["reading"]), 0), read_chunk)

    def parse(p: Proc):
        for offset, value_ in ((POS, p.const(0)), (OUT, p.const(0)), (LEN, p["total"])):
            p["cm"] = p.op1(Operation.CHECKED_STORE_BITS_LE, (p["cp"], p.const(offset), value_, p["cm"]), MEM, attributes=(4, 1))
        views = ("ip", "iv", "im", "op", "ov", "om", "cp", "cv", "cm")
        status, *results = p.op(Operation.CALL_DIRECT, (p.const(0), *(p[name] for name in views)), (B32, *TRIPLE_TYPES), entity=value)
        for name, item in zip(views, results):
            p[name] = item

        def trailing(q: Proc):
            _status, *results = q.op(Operation.CALL_DIRECT, tuple(q[name] for name in views), (B32, *TRIPLE_TYPES), entity=h.whitespace)
            for name, item in zip(views, results):
                q[name] = item
            position, q["cm"] = q.op(Operation.CHECKED_LOAD_BITS_LE, (q["cp"], q.const(POS), q["cm"]), (B32, MEM), attributes=(4, 1))
            q.if_(q.cmp(NE, position, q["total"]), lambda r: r.__setitem__("code", r.const(EXIT_INVALID)))

        p.if_(p.cmp(EQ, status, OK), trailing, lambda q: q.__setitem__("code", q.const(EXIT_INVALID)))

    proc.if_(proc.cmp(EQ, proc["code"], EXIT_OK), parse)

    def write(p: Proc, fd: int, length):
        readable = p.op1(Operation.POINTER_CAST, (p["op"],), api.bytes_read)
        _count, p["fs"], p["om"] = p.op(Operation.CALL_FOREIGN, (p.const(fd), readable, p.widen(length, B64), p["fs"], p["om"]), (B64, api.filesystem_effect, MEM), entity=api.write)

    def success(p: Proc):
        length, p["cm"] = p.op(Operation.CHECKED_LOAD_BITS_LE, (p["cp"], p.const(OUT), p["cm"]), (B32, MEM), attributes=(4, 1))
        p["om"] = p.op1(Operation.CHECKED_STORE_BITS_LE, (p["op"], length, p.const(0x0A, B8), p["om"]), MEM, attributes=(1, 1))
        write(p, 1, p.bin(Operation.ADD_WRAP, length, 1))

    def invalid(p: Proc):
        position, p["cm"] = p.op(Operation.CHECKED_LOAD_BITS_LE, (p["cp"], p.const(POS), p["cm"]), (B32, MEM), attributes=(4, 1))
        for offset, byte in enumerate(MESSAGE):
            p["om"] = p.op1(Operation.CHECKED_STORE_BITS_LE, (p["op"], p.const(offset), p.const(byte, B8), p["om"]), MEM, attributes=(1, 1))
        # Decimal digits of the offset, most significant first.
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
    for name, extent, pointer in (("i", CAPACITY, BYTES), ("o", CAPACITY + 1, BYTES), ("c", 12, WORDS), ("k", CHUNK, BYTES)):
        _result, proc[name + "m"] = proc.op(
            Operation.CALL_FOREIGN, (proc[name + "p"], proc[name + "v"], proc[name + "m"]), (B64, MEM), entity=api.munmap_view(pointer, extent),
        )
    process = proc.op1(Operation.CALL_FOREIGN, (proc["code"], proc["proc"]), api.process_effect, entity=api.exit_group)
    proc.ret(proc["code"], process, proc["fs"], proc["im"], proc["om"], proc["cm"], proc["km"])
    entry = proc.function((B32, api.process_effect, api.filesystem_effect, MEM, MEM, MEM, MEM))
    objects = (*api.types, *proc.graph.objects.values(), *group_objects, value, *h.objects, WORDS, B64)
    reader = program_store(entry, target, objects)
    return JsonminProgram(reader, entry, target)


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
