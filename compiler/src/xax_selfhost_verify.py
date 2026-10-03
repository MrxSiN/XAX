"""Self-hosting step S6b.2 (ADR-144): store-level and object-level verification as XAX semantics.

One XAX program, run natively like the typing program (ADR-132), reads every
store object (the S5b object table: kind, reference indices, CID, and the
body bytes, or for a graph fragment the S3c XAX graph-decoder stream) and
decides, with the bootstrap's rules:

* functions (``_verify_function``, ordinary graphs): the exact interface
  body, a graph-fragment carrier, parameter and return types that are types
  the XAX object verdicts proved (ADR-143), exact reference use, no group
  member calls, and the graph contract: the entry block's parameters are the
  interface's, and every ``return`` returns values of the interface's types;
* module and program-root reference lists (``_verify_reference_list``);
* call contracts (``_decode_call_contract``);
* the store: every object reachable from the root, no reference cycle.

Its output is a verdict per object (and each proven function's graph object)
and a store verdict.  A verdict holds only when the bootstrap accepts; every
other object, and every rejection, takes the bootstrap path and its exact
diagnostic.  Recursion groups, group member functions, targets, and build
objects stay with the bootstrap.
"""

from __future__ import annotations

import ctypes
import mmap
import os
import platform
import sys
import threading
from pathlib import Path

from xax_compiler import Kind, Operation, TerminatorKind, x86_64_linux_exec_target
from xax_graph_builder import program_store
from xax_selfhost_facts import E, H_ARENA, H_ARENA_END, HEADER, NONE, _function, _uleb
from xax_selfhost_typing import IN_WORDS, OUT_WORDS

STORE_PATH = Path(__file__).resolve().parents[1] / "bootstrap" / "xax_store_verifier.xax"
VERDICTS_AT, GRAPHS_AT, ARENA_AT = 1 << 20, 6 << 20, 12 << 20
OK = 1
ENTITY_CODES = (5, 6, 30, 41, 42, 43)
ATTRIBUTE_CODES = (7, 8, 9, 10, 11, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 48, 52, 53, 55, 56, 57,
                   61, 63, 64, 65, 66, 73, 74, 75, 76)
MODULE_CHILDREN = (Kind.TYPE, Kind.CONSTANT, Kind.FUNCTION, Kind.TARGET, Kind.RECURSION_GROUP, Kind.CALL_CONTRACT)
# Globals (the first arena words): table pointers.
GLOBALS = ARENA_AT
G_REC, G_O, G_TYPEOK, G_MARK = range(4)
_FN: dict = {}


def _g(e: E, slot: int):
    return e.ld(GLOBALS + slot)


def _rec(e: E, obj):
    return e.ld(e.add(_g(e, G_REC), obj))


def _kind(e: E, obj):
    return e.rd(_rec(e, obj))


def _references(e: E, obj):
    return e.rd(e.add(_rec(e, obj), 1))


def _reference(e: E, obj, k):
    return e.rd(e.add(e.add(_rec(e, obj), 2), k))


def _payload(e: E, obj):
    return e.add(e.add(e.add(_rec(e, obj), 2), _references(e, obj)), 5)


def _type_ok(e: E, obj):
    return e.both(e.lt(obj, _g(e, G_O)), e.ne(e.rd(e.add(_g(e, G_TYPEOK), e.sel(e.lt(obj, _g(e, G_O)), obj, 0))), 0))


DECLINE_SITES: list[str] = []  # diagnosis: out[2] names the check that gave the last 0 verdict


def _no(e: E, condition):
    """Verdict 0 when ``condition``."""
    import inspect

    frame = inspect.stack()[1]
    code = len(DECLINE_SITES) + 1
    DECLINE_SITES.append(f"{frame.function}:{frame.lineno}")
    e.if_(condition, lambda: (e.st(2, code), e.give(0)))


def _read(e: E, name: str, end):
    """A canonical ULEB at ``p[name]``, inside ``end``; advances it (verdict 0 otherwise)."""
    p = e.p
    value, size, ok = _uleb(e, p[name])
    _no(e, e.not_(ok))
    e.set(name, e.add(p[name], size))
    _no(e, e.lt(end, p[name]))
    e.var(f"{name}_value", value)
    return p[f"{name}_value"]


def _clear_marks(e: E, count):
    p = e.p
    e.for_("mk", 0, count, lambda: e.st(e.add(_g(e, G_MARK), p["mk"]), 0))


def _mark(e: E, index):
    e.st(e.add(_g(e, G_MARK), index), 1)


def _all_marked(e: E, count):
    p = e.p
    e.var("marked", 1)
    e.for_("mk", 0, count, lambda: e.if_(e.eq(e.ld(e.add(_g(e, G_MARK), p["mk"])), 0), lambda: e.set("marked", 0)))
    return p["marked"]


def _type_reference(e: E, obj, name: str, end):
    """A reference index read at ``p[name]`` naming a proven type; marks it and returns the object."""
    p = e.p
    index = _read(e, name, end)
    e.var(f"{name}_index", index)
    _no(e, e.le(_references(e, obj), p[f"{name}_index"]))
    target = _reference(e, obj, p[f"{name}_index"])
    e.var(f"{name}_target", target)
    _no(e, e.not_(_type_ok(e, p[f"{name}_target"])))
    _mark(e, p[f"{name}_index"])
    return p[f"{name}_target"]


def _node_end(e: E, at):
    """The position after the graph-decoder node record at ``at``, and the record's fields."""
    p = e.p
    e.var("ne_at", at)
    operation = e.rd(p["ne_at"])
    e.var("ne_op", operation)
    e.set("ne_at", e.add(p["ne_at"], 1))
    e.if_(e.eq(p["ne_op"], int(Operation.CALL_GROUP_MEMBER)), lambda: e.set("ne_at", e.add(p["ne_at"], 3)))
    e.if_(e.either(*(e.eq(p["ne_op"], code) for code in ENTITY_CODES)), lambda: e.set("ne_at", e.add(p["ne_at"], 1)))
    count = e.rd(p["ne_at"])
    e.set("ne_at", e.add(p["ne_at"], 1))
    e.for_("nq", 0, count, lambda: e.set("ne_at", e.add(e.add(p["ne_at"], 3), e.flag(e.eq(e.rd(p["ne_at"]), 1)))))
    e.var("ne_results", p["ne_at"])
    e.set("ne_at", e.add(e.add(p["ne_at"], 1), e.rd(p["ne_at"])))
    e.if_(e.either(*(e.eq(p["ne_op"], code) for code in ATTRIBUTE_CODES)), lambda: e.set("ne_at", e.add(e.add(p["ne_at"], 1), e.rd(p["ne_at"]))))
    return p["ne_at"]


def _skip_values(e: E, name: str):
    p = e.p
    count = e.rd(p[name])
    e.set(name, e.add(p[name], 1))
    e.for_("sv", 0, count, lambda: e.set(name, e.add(e.add(p[name], 3), e.flag(e.eq(e.rd(p[name]), 1)))))


def _function_ok(tables):
    """``_verify_function`` for an ordinary function; 1 (and its graph object in GRAPHS) or 0."""
    def build(e: E):
        p = e.p
        f = p["f"]
        references = _references(e, f)
        e.var("refs", references)
        e.var("fa", _payload(e, f))
        end = e.add(p["fa"], e.rd(e.sub(p["fa"], 1)))
        e.var("fend", end)
        _clear_marks(e, p["refs"])
        graph_index = _read(e, "fa", p["fend"])
        e.var("gi", graph_index)
        _no(e, e.le(p["refs"], p["gi"]))
        e.var("graph", _reference(e, f, p["gi"]))
        _no(e, e.either(e.eq(p["graph"], NONE), e.ne(_kind(e, p["graph"]), int(Kind.GRAPH_FRAGMENT))))
        _mark(e, p["gi"])
        e.var("lists", e.alloc(e.add(e.sub(p["fend"], _payload(e, f)), 2)))  # at most one type per body byte
        _no(e, e.eq(p["lists"], NONE))
        e.var("np", _read(e, "fa", p["fend"]))
        e.for_("q", 0, p["np"], lambda: e.st(e.add(p["lists"], p["q"]), _type_reference(e, f, "fa", p["fend"])))
        e.var("nr", _read(e, "fa", p["fend"]))
        e.var("returns", e.add(p["lists"], p["np"]))
        e.for_("q", 0, p["nr"], lambda: e.st(e.add(p["returns"], p["q"]), _type_reference(e, f, "fa", p["fend"])))
        _no(e, e.ne(p["fa"], p["fend"]))
        _no(e, e.eq(_all_marked(e, p["refs"]), 0))
        # The graph: block and node positions, no group member calls.
        g = p["graph"]
        stream = _payload(e, g)
        e.var("gs", stream)
        e.var("B", e.rd(p["gs"]))
        e.var("entry", e.rd(e.add(p["gs"], 1)))
        _no(e, e.le(p["B"], p["entry"]))
        e.var("blocks", e.alloc(e.add(p["B"], 1)))
        e.var("firsts", e.alloc(e.add(p["B"], 1)))
        e.var("node_at", e.alloc(e.add(e.rd(e.sub(p["gs"], 1)), 1)))
        e.var("results_at", e.alloc(e.add(e.rd(e.sub(p["gs"], 1)), 1)))  # each node's result list
        e.var("term_at", e.alloc(e.add(p["B"], 1)))  # each block's terminator
        _no(e, e.either(e.eq(p["blocks"], NONE), e.eq(p["firsts"], NONE), e.eq(p["node_at"], NONE), e.eq(p["results_at"], NONE), e.eq(p["term_at"], NONE)))
        e.var("ga", e.add(p["gs"], 2))
        e.var("nodes", 0)

        def place():
            e.st(e.add(p["blocks"], p["b"]), p["ga"])
            e.set("ga", e.add(e.add(p["ga"], 1), e.rd(p["ga"])))
            count = e.rd(p["ga"])
            e.set("ga", e.add(p["ga"], 1))
            e.st(e.add(p["firsts"], p["b"]), p["nodes"])

            def node():
                e.st(e.add(p["node_at"], p["nodes"]), p["ga"])
                _no(e, e.eq(e.rd(p["ga"]), int(Operation.CALL_GROUP_MEMBER)))
                e.set("ga", _node_end(e, p["ga"]))
                e.st(e.add(p["results_at"], p["nodes"]), p["ne_results"])
                e.set("nodes", e.add(p["nodes"], 1))

            e.for_("m", 0, count, node)
            e.st(e.add(p["term_at"], p["b"]), p["ga"])
            kind = e.rd(p["ga"])
            e.set("ga", e.add(p["ga"], 1))

            def edge():
                e.set("ga", e.add(p["ga"], 1))
                _skip_values(e, "ga")

            def conditional():
                e.set("ga", e.add(e.add(p["ga"], 3), e.flag(e.eq(e.rd(p["ga"]), 1))))
                edge()
                edge()

            e.if_(e.eq(kind, 1), edge, lambda: e.if_(e.eq(kind, 2), conditional, lambda: e.if_(
                e.eq(kind, 3), lambda: _skip_values(e, "ga"), lambda: e.set("ga", e.add(p["ga"], 2)))))

        e.for_("b", 0, p["B"], place)
        # Entry parameters: exactly the interface's parameter types.
        entry_at = e.ld(e.add(p["blocks"], p["entry"]))
        _no(e, e.ne(e.rd(entry_at), p["np"]))
        e.for_("q", 0, p["np"], lambda: _no(e, e.ne(_reference(e, g, e.rd(e.add(e.add(entry_at, 1), p["q"]))), e.ld(e.add(p["lists"], p["q"])))))

        def value_type(name: str):
            """The type object of the value at ``p[name]`` (advanced past it)."""
            at = p[name]
            tag, block, index = e.rd(at), e.rd(e.add(at, 1)), e.rd(e.add(at, 2))
            _no(e, e.le(p["B"], block))
            block_at = e.ld(e.add(p["blocks"], block))
            e.var("vt_ref", NONE)

            def parameter():
                _no(e, e.le(e.rd(block_at), index))
                e.set("vt_ref", e.rd(e.add(e.add(block_at, 1), index)))

            def result():
                count_at = e.add(e.add(block_at, 1), e.rd(block_at))
                _no(e, e.le(e.rd(count_at), index))
                results = e.ld(e.add(p["results_at"], e.add(e.ld(e.add(p["firsts"], block)), index)))
                which = e.rd(e.add(at, 3))
                _no(e, e.le(e.rd(results), which))
                e.set("vt_ref", e.rd(e.add(e.add(results, 1), which)))

            e.if_(e.eq(tag, 0), parameter, result)
            e.set(name, e.add(e.add(at, 3), e.flag(e.eq(tag, 1))))
            return _reference(e, g, p["vt_ref"])

        # Every return: the interface's return types.
        def returns_of():
            e.var("ra", e.ld(e.add(p["term_at"], p["b"])))

            def returning():
                e.set("ra", e.add(p["ra"], 1))
                _no(e, e.ne(e.rd(p["ra"]), p["nr"]))
                e.set("ra", e.add(p["ra"], 1))
                e.for_("q", 0, p["nr"], lambda: _no(e, e.ne(value_type("ra"), e.ld(e.add(p["returns"], p["q"])))))

            e.if_(e.eq(e.rd(p["ra"]), int(TerminatorKind.RETURN)), returning)

        e.for_("b", 0, p["B"], returns_of)
        e.st(e.add(GRAPHS_AT, f), g)
        e.give(1)
    return _function(("f",), build, tables)


def _list_ok(tables, allowed):
    """``_verify_reference_list``: indices 0..n-1 in order, exact end, children of allowed kinds."""
    def build(e: E):
        p = e.p
        o = p["o"]
        e.var("la", _payload(e, o))
        end = e.add(p["la"], e.rd(e.sub(p["la"], 1)))
        e.var("lend", end)
        count = _read(e, "la", p["lend"])
        e.var("lcount", count)
        _no(e, e.ne(p["lcount"], _references(e, o)))
        e.for_("q", 0, p["lcount"], lambda: _no(e, e.ne(_read(e, "la", p["lend"]), p["q"])))
        _no(e, e.ne(p["la"], p["lend"]))

        def child():
            target = _reference(e, o, p["q"])
            _no(e, e.eq(target, NONE))
            _no(e, e.not_(e.either(*(e.eq(_kind(e, target), int(kind)) for kind in allowed))))

        e.for_("q", 0, p["lcount"], child)
        e.give(1)
    return _function(("o",), build, tables)


def _contract_ok(tables):
    """``_decode_call_contract``: proven input and output types, two canonical booleans, exact use."""
    def build(e: E):
        p = e.p
        o = p["o"]
        e.var("refs", _references(e, o))
        e.var("ca", _payload(e, o))
        end = e.add(p["ca"], e.rd(e.sub(p["ca"], 1)))
        e.var("cend", end)
        _clear_marks(e, p["refs"])
        for _part in range(2):
            e.var("ccount", _read(e, "ca", p["cend"]))
            e.for_("q", 0, p["ccount"], lambda: _type_reference(e, o, "ca", p["cend"]))
        for _flag in range(2):
            _no(e, e.le(p["cend"], p["ca"]))
            _no(e, e.lt(1, e.rd(p["ca"])))
            e.set("ca", e.add(p["ca"], 1))
        _no(e, e.ne(p["ca"], p["cend"]))
        _no(e, e.eq(_all_marked(e, p["refs"]), 0))
        e.give(1)
    return _function(("o",), build, tables)


def _program(tables):
    def build(e: E):
        p = e.p
        e.st(0, 0)
        e.st(1, 0)
        e.set_hd(H_ARENA, ARENA_AT + 16)
        e.set_hd(H_ARENA_END, HEADER - 1)
        O = e.rd(0)
        e.var("O", O)
        e.st(GLOBALS + G_O, p["O"])
        for slot, size in ((G_REC, p["O"]), (G_MARK, 1 << 16)):
            table = e.alloc(e.add(size, 1))
            e.if_(e.eq(table, NONE), lambda: e.give(NONE))
            e.st(GLOBALS + slot, table)
        e.var("ra", 2)

        def record():
            e.st(e.add(_g(e, G_REC), p["o"]), p["ra"])
            references = e.rd(e.add(p["ra"], 1))
            e.if_(e.lt(1 << 16, references), lambda: e.give(NONE))
            payload_at = e.add(e.add(e.add(p["ra"], 2), references), 4)
            e.set("ra", e.add(e.add(payload_at, 1), e.rd(payload_at)))

        e.for_("o", 0, p["O"], record)
        e.if_(e.lt(IN_WORDS, e.add(p["ra"], p["O"])), lambda: e.give(NONE))
        e.st(GLOBALS + G_TYPEOK, p["ra"])  # the proven-type flags follow the records

        # Per-object verdicts.
        def verdict():
            o = p["o"]
            kind = _kind(e, o)
            e.var("verdict", 0)
            e.if_(e.eq(kind, int(Kind.FUNCTION)), lambda: e.set("verdict", e.call(_FN["function"], o)))
            e.if_(e.eq(kind, int(Kind.MODULE)), lambda: e.set("verdict", e.call(_FN["module"], o)))
            e.if_(e.eq(kind, int(Kind.PROGRAM_ROOT)), lambda: e.set("verdict", e.call(_FN["root"], o)))
            e.if_(e.eq(kind, int(Kind.CALL_CONTRACT)), lambda: e.set("verdict", e.call(_FN["contract"], o)))
            e.st(e.add(VERDICTS_AT, o), e.sel(e.eq(p["verdict"], 1), 1, 0))

        e.for_("o", 0, p["O"], verdict)
        # The store: everything reachable from the root, no cycle (iterative depth-first search).
        root = e.rd(1)
        e.var("root", root)
        colour = e.alloc(e.add(p["O"], 1))
        stack = e.alloc(e.add(e.mul(p["O"], 2), 2))
        e.var("colour", colour)
        e.var("stack", stack)
        e.if_(e.either(e.eq(p["colour"], NONE), e.eq(p["stack"], NONE), e.le(p["O"], p["root"])), lambda: e.give(1))
        e.for_("o", 0, p["O"], lambda: e.st(e.add(p["colour"], p["o"]), 0))
        e.var("depth", 1)
        e.st(p["stack"], p["root"])
        e.st(e.add(p["stack"], 1), 0)
        e.st(e.add(p["colour"], p["root"]), 1)
        e.var("store_ok", 1)

        def step():
            top = e.add(p["stack"], e.mul(e.sub(p["depth"], 1), 2))
            node, child = e.ld(top), e.ld(e.add(top, 1))
            e.var("sn", node)

            def descend():
                target = _reference(e, p["sn"], child)
                e.st(e.add(top, 1), e.add(child, 1))
                e.var("st", target)

                def visit():
                    state = e.ld(e.add(p["colour"], p["st"]))
                    e.if_(e.eq(state, 1), lambda: e.set("store_ok", 0))

                    def push():
                        e.st(e.add(p["colour"], p["st"]), 1)
                        slot = e.add(p["stack"], e.mul(p["depth"], 2))
                        e.st(slot, p["st"])
                        e.st(e.add(slot, 1), 0)
                        e.set("depth", e.add(p["depth"], 1))

                    e.if_(e.eq(state, 0), push)

                e.if_(e.either(e.eq(p["st"], NONE), e.le(p["O"], p["st"])), lambda: e.set("store_ok", 0), visit)

            def finish():
                e.st(e.add(p["colour"], p["sn"]), 2)
                e.set("depth", e.sub(p["depth"], 1))

            e.if_(e.lt(child, _references(e, p["sn"])), descend, finish)

        e.while_(lambda: e.both(e.ne(p["depth"], 0), e.ne(p["store_ok"], 0)), step)
        e.for_("o", 0, p["O"], lambda: e.if_(e.ne(e.ld(e.add(p["colour"], p["o"])), 2), lambda: e.set("store_ok", 0)))
        e.st(1, p["store_ok"])
        e.st(0, OK)
        e.give(1)
    return _function((), build, tables)


def build_verifier_program():
    tables = None
    objects: list = []

    def add(name, made):
        function, items = made
        objects.extend(items)
        _FN[name] = function
        return function

    add("function", _function_ok(tables))
    add("module", _list_ok(tables, MODULE_CHILDREN))
    add("root", _list_ok(tables, (Kind.MODULE,)))
    add("contract", _contract_ok(tables))
    program = add("program", _program(tables))
    return program_store(program, x86_64_linux_exec_target(), tuple(objects)), program


def write_verifier_store() -> bytes:
    import xax_compiler

    building = xax_compiler._TYPING_BUILDING
    xax_compiler._TYPING_BUILDING = True
    try:
        reader, _function = build_verifier_program()
        STORE_PATH.write_bytes(reader.data)
    finally:
        xax_compiler._TYPING_BUILDING = building
    return reader.data


def load_verifier_program():
    from xax_compiler import StoreReader, verify_store

    if not STORE_PATH.exists():
        return build_verifier_program()
    reader = StoreReader(STORE_PATH.read_bytes())
    verify_store(reader)
    module = next(item for item in reader.objects() if item.kind == Kind.MODULE)
    function = next(reader.get(cid) for cid in module.references if reader.get(cid).kind == Kind.FUNCTION)
    return reader, function


def _native_image() -> tuple[bytes, int]:
    import hashlib
    import tempfile

    from xax_x86_64 import compile_native

    sources = Path(__file__).resolve().parent
    digest = hashlib.sha256(STORE_PATH.read_bytes() if STORE_PATH.exists() else b"")
    for name in ("xax_compiler.py", "xax_x86_64.py", "xax_x86_64_regalloc.py"):
        digest.update((sources / name).read_bytes())
    cache = Path(os.environ.get("XAX_NATIVE_CACHE", Path.home() / ".cache" / "xax-native"))
    entry = cache / f"store-verifier-{digest.hexdigest()}.bin"
    try:
        data = entry.read_bytes()
        return data[8:], int.from_bytes(data[:8], "little")
    except OSError:
        pass
    reader, function = load_verifier_program()
    target = next(item for item in reader.objects() if item.kind == Kind.TARGET)
    image = compile_native(reader, function.cid, target.cid)
    try:
        cache.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=cache, delete=False) as handle:
            handle.write(image.entry_offset.to_bytes(8, "little") + image.code)
        os.replace(handle.name, entry)
    except OSError:
        pass
    return image.code, image.entry_offset


class NativeStoreVerifier:
    def __init__(self) -> None:
        from xax_x86_64 import _SYSV_TO_WIN64_THUNK

        code, entry_offset = _native_image()
        thunk = _SYSV_TO_WIN64_THUNK + bytes(-len(_SYSV_TO_WIN64_THUNK) % 16)
        blob = thunk + code
        self._mapping = mmap.mmap(-1, len(blob), prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
        self._mapping.write(blob)
        base = ctypes.addressof(ctypes.c_char.from_buffer(self._mapping))
        self._call = ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint64, ctypes.c_void_p)(base)
        self._entry = base + len(thunk) + entry_offset
        self._in = (ctypes.c_uint64 * IN_WORDS)()
        self._out = (ctypes.c_uint64 * OUT_WORDS)()
        self._slots = (ctypes.c_uint64 * 4)()
        self._xmm = ctypes.c_uint64()
        self._lock = threading.Lock()

    def verify(self, words: list[int], count: int):
        """``(store verdict, per-object verdicts, per-object graph objects)``, or None when it cannot run."""
        if len(words) > IN_WORDS or any(not 0 <= word < 1 << 64 for word in words):
            return None
        with self._lock:
            self._in[: len(words)] = words
            self._slots[0], self._slots[1] = ctypes.addressof(self._in), ctypes.addressof(self._out)
            self._call(self._entry, ctypes.addressof(self._slots), 4, ctypes.addressof(self._xmm))
            out = self._out
            if out[0] != OK:
                return None
            return out[1] == 1, list(out[VERDICTS_AT : VERDICTS_AT + count]), list(out[GRAPHS_AT : GRAPHS_AT + count])


def object_table(objects, head: list[int]) -> list[int] | None:
    """The S5b object table (``head`` first): kind, reference indices, CID, payload (graph-decoder stream for
    graphs, body bytes otherwise); None when a graph body cannot be streamed."""
    from xax_compiler import _native_graph_decoder

    decoder = _native_graph_decoder()
    if decoder is None:
        return None
    index = {obj.cid: position for position, obj in enumerate(objects)}
    words = [len(objects), *head]
    for obj in objects:
        words += [int(obj.kind), len(obj.references), *(index.get(cid, NONE) for cid in obj.references)]
        words += [int.from_bytes(obj.cid[offset:offset + 8], "big") for offset in range(0, 32, 8)]
        if obj.kind == Kind.GRAPH_FRAGMENT:
            if len(obj.body) > decoder.capacity:
                return None
            status, stream = decoder.decode(obj.body, len(obj.references))
            if status != 0:
                return None
            payload = list(stream)
        elif obj.kind in (Kind.TYPE, Kind.CONSTANT, Kind.FUNCTION, Kind.TARGET, Kind.MODULE, Kind.PROGRAM_ROOT, Kind.CALL_CONTRACT):
            payload = list(obj.body)
        else:
            payload = []
        words += [len(payload), *payload]
    return words


_NATIVE: list = []
_BUILDING: list = []


def native_store_verifier():
    """The shared native store verifier, or None where it cannot run (or while it is being loaded: its own
    store is verified by the bootstrap)."""
    if _BUILDING:
        return None
    if not _NATIVE:
        usable = (sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")
                  and os.environ.get("XAX_VERIFY_PYTHON") != "1" and STORE_PATH.exists())
        _BUILDING.append(True)
        try:
            _NATIVE.append(NativeStoreVerifier() if usable else None)
        except (OSError, RuntimeError, ValueError):
            _NATIVE.append(None)
        finally:
            _BUILDING.clear()
    return _NATIVE[0]
