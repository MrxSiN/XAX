"""Standard semantic libraries, first two families (ADR-130, OI-36).

A library is a canonical ``PACKAGE`` object (``xax_build.package``): a
logical identity carrying name and version, one ``MODULE`` holding the
functions, and one named build entry per exported function.  Python is only
the construction tool (:mod:`xax_structured`); the package's meaning is its
objects.

Granularity is the function: an application references an exported function
by CID through ``call.direct``, so its canonical store holds exactly the
reachable closure.  Canonical stores reject unreachable objects, so an
unused function, or an unused package, contributes zero bytes to the store
and to every artifact compiled from it.  There is no runtime: every
function's memory access is an explicit borrowed heap-view triple
``(pointer, view, memory)`` (ADR-101) and nothing allocates.

Specialization is instantiation: a family is parameterized by the static
facts its functions' types carry (a view extent, a table capacity), and each
instance is its own package with its own CIDs.  Instances are target
independent: the same CIDs compile for x86-64 and AArch64 Linux.

Families:

* ``xax.text`` (``text_package(extent)``), over a byte view of ``extent``:
  ``find_digits`` finds the next maximal run of ASCII decimal digits in
  ``[pos, end)``; ``parse_u64`` reads the leading digit run's value modulo 2^64;
  ``format_u64`` writes a value in decimal; ``skip_spaces`` skips ASCII
  blanks.
* ``xax.collections.hashset_u64`` (``hashset_package(capacity)``), an
  open-addressing set of ``bits<64>`` keys in a caller-provided zeroed table
  of ``capacity + 1`` words (``capacity`` a power of two; slot ``capacity``
  records key 0): ``insert`` returns 1 when inserted, 0 when present, 2 when
  full; ``contains`` returns 1 or 0.
"""

from __future__ import annotations

from dataclasses import dataclass

from xax_build import package
from xax_compiler import (
    IntCompare,
    Kind,
    Operation,
    Permission,
    SemanticObject,
    heap_view_type,
    memory_effect_type,
    object_with_refs,
    pointer_type,
)
from xax_structured import B1, B8, B32, B64, Proc

MEM = memory_effect_type()
BYTES = pointer_type(B8, Permission.READ_WRITE, 1, space=2)
WORDS = pointer_type(B64, Permission.READ_WRITE, 8, space=2)
GOLDEN = 0x9E3779B97F4A7C15
LT, GE, EQ, NE, LE = IntCompare.ULT, IntCompare.UGE, IntCompare.EQ, IntCompare.NE, IntCompare.ULE


@dataclass(frozen=True)
class Library:
    """One package instance: the canonical package object plus its exports."""

    name: str
    version: int
    parameters: dict
    package: SemanticObject
    functions: dict[str, SemanticObject]
    objects: tuple[SemanticObject, ...]

    def __getitem__(self, name: str) -> SemanticObject:
        return self.functions[name]

    def manifest(self) -> dict:
        return {
            "package": self.name,
            "version": self.version,
            "parameters": self.parameters,
            "package_cid": self.package.cid.hex(),
            "functions": {name: function.cid.hex() for name, function in sorted(self.functions.items())},
        }


def _library(name: str, version: int, parameters: dict, exports: dict[str, tuple[SemanticObject, tuple]]) -> Library:
    functions = {key: value[0] for key, value in exports.items()}
    module = object_with_refs(Kind.MODULE, tuple(functions.values()))
    identity = f"{name}/{version}/" + ",".join(f"{key}={value}" for key, value in sorted(parameters.items()))
    package_object = package(identity.encode(), (module,), build_entries=tuple((key.encode(), value) for key, value in functions.items()))
    objects: dict[bytes, SemanticObject] = {}
    for _function, items in exports.values():
        for item in items:
            objects.setdefault(item.cid, item)
    return Library(name, version, dict(parameters), package_object, functions, (*objects.values(), module, package_object))


def _done(proc: Proc, returns) -> tuple[SemanticObject, tuple]:
    function = proc.function(returns)
    return function, (*proc.graph.objects.values(), function)


def _load(proc: Proc, offset, width: int = 1):
    pointer, element = ("p", B8) if width == 1 else ("p", B64)
    value, proc["m"] = proc.op(Operation.CHECKED_LOAD_BITS_LE, (proc[pointer], offset, proc["m"]), (element, MEM), attributes=(width, 1))
    return value


def _store(proc: Proc, offset, value, width: int = 1) -> None:
    proc["m"] = proc.op1(Operation.CHECKED_STORE_BITS_LE, (proc["p"], offset, value, proc["m"]), MEM, attributes=(width, 1))


def _digit(proc: Proc, byte):
    return proc.cmp(LE, proc.bin(Operation.SUB_WRAP, byte, 0x30), 9)


def _stop(proc: Proc) -> None:
    proc["go"] = proc.const(0, B1)


def _going(proc: Proc):
    return proc.cmp(NE, proc.widen(proc["go"]), 0)


# -- xax.text ---------------------------------------------------------------------

def _text_view(extent: int):
    return (("p", BYTES), ("v", heap_view_type(extent)), ("m", MEM))


def _find_digits(extent: int):
    """``(pos, end, view) -> (span, view)``: the next maximal digit run in ``[pos, end)``.

    ``span`` packs the run's start in the low and its end in the high 32 bits;
    start equals end (both ``end``) when there is none.
    """
    proc = Proc((("pos", B32), ("end", B32), *_text_view(extent)))
    proc.let("go", B1, proc.const(1, B1))

    def advance(q: Proc) -> None:
        q["pos"] = q.bin(Operation.ADD_WRAP, q["pos"], 1)

    def run(digits: bool):
        def step(p: Proc):
            def at(q: Proc):
                found = _digit(q, q.widen(_load(q, q["pos"])))
                q.if_(found, advance if digits else _stop, _stop if digits else advance)

            p.if_(p.cmp(GE, p["pos"], p["end"]), _stop, at)

        return step

    proc.while_(_going, run(False))
    proc.let("start", B32, proc["pos"])
    proc["go"] = proc.const(1, B1)
    proc.while_(_going, run(True))
    high = proc.op1(Operation.ROTATE_RIGHT, (proc.widen(proc["pos"], B64),), B64, attributes=(32,))
    proc.ret(proc.op1(Operation.BIT_OR, (proc.widen(proc["start"], B64), high), B64), proc["p"], proc["v"], proc["m"])
    return _done(proc, (B64, BYTES, heap_view_type(extent), MEM))


def _parse_u64(extent: int):
    """``(start, end, view) -> (value, view)``: the leading digit run of ``[start, end)``
    as decimal, modulo 2^64 (0 when the range starts with a non-digit)."""
    proc = Proc((("pos", B32), ("end", B32), *_text_view(extent)))
    proc.let("value", B64, proc.const(0, B64))
    proc.let("go", B1, proc.const(1, B1))

    def step(p: Proc):
        def at(q: Proc):
            digit = q.bin(Operation.SUB_WRAP, q.widen(_load(q, q["pos"])), 0x30)

            def add(r: Proc):
                r["value"] = r.bin(Operation.ADD_WRAP, r.bin(Operation.MUL_WRAP, r["value"], 10, B64), r.widen(digit, B64), B64)
                r["pos"] = r.bin(Operation.ADD_WRAP, r["pos"], 1)

            q.if_(q.cmp(LE, digit, 9), add, _stop)

        p.if_(p.cmp(GE, p["pos"], p["end"]), _stop, at)

    proc.while_(_going, step)
    proc.ret(proc["value"], proc["p"], proc["v"], proc["m"])
    return _done(proc, (B64, BYTES, heap_view_type(extent), MEM))


def _format_u64(extent: int):
    """``(value, at, view) -> (end, view)``: decimal digits written at ``at``."""
    proc = Proc((("value", B64), ("at", B32), *_text_view(extent)))
    proc.let("digits", B32, proc.const(1))
    proc.let("scan", B64, proc["value"])

    def count(p: Proc):
        p["scan"] = p.bin(Operation.UDIV, p["scan"], 10, B64)
        p["digits"] = p.bin(Operation.ADD_WRAP, p["digits"], 1)

    proc.while_(lambda p: p.cmp(GE, p["scan"], 10, B64), count)
    proc.let("k", B32, proc["digits"])

    def write(p: Proc):
        p["k"] = p.bin(Operation.SUB_WRAP, p["k"], 1)
        digit = p.op1(Operation.INT_TRUNCATE, (p.bin(Operation.ADD_WRAP, p.bin(Operation.UREM, p["value"], 10, B64), 0x30, B64),), B8)
        _store(p, p.bin(Operation.ADD_WRAP, p["at"], p["k"]), digit)
        p["value"] = p.bin(Operation.UDIV, p["value"], 10, B64)

    proc.while_(lambda p: p.cmp(NE, p["k"], 0), write)
    proc.ret(proc.bin(Operation.ADD_WRAP, proc["at"], proc["digits"]), proc["p"], proc["v"], proc["m"])
    return _done(proc, (B32, BYTES, heap_view_type(extent), MEM))


def _skip_spaces(extent: int):
    """``(pos, end, view) -> (next, view)``: skips ASCII space, tab, CR, LF."""
    proc = Proc((("pos", B32), ("end", B32), *_text_view(extent)))
    proc.let("go", B1, proc.const(1, B1))

    def step(p: Proc):
        def at(q: Proc):
            byte = q.widen(_load(q, q["pos"]))
            blank = q.any_of(*(q.cmp(EQ, byte, value) for value in (0x20, 0x09, 0x0D, 0x0A)))
            q.if_(blank, lambda r: r.__setitem__("pos", r.bin(Operation.ADD_WRAP, r["pos"], 1)), _stop)

        p.if_(p.cmp(GE, p["pos"], p["end"]), _stop, at)

    proc.while_(_going, step)
    proc.ret(proc["pos"], proc["p"], proc["v"], proc["m"])
    return _done(proc, (B32, BYTES, heap_view_type(extent), MEM))


def text_package(extent: int) -> Library:
    if not 0 < extent < 1 << 32:
        raise ValueError("text views are addressed by bits<32> offsets")
    return _library("xax.text", 1, {"extent": extent}, {"find_digits": _find_digits(extent), "parse_u64": _parse_u64(extent), "format_u64": _format_u64(extent), "skip_spaces": _skip_spaces(extent)})


# -- xax.collections.hashset_u64 ------------------------------------------------------

def _table(capacity: int):
    return (("p", WORDS), ("v", heap_view_type((capacity + 1) * 8)), ("m", MEM))


def _hashset(capacity: int, insert: bool):
    proc = Proc((("key", B64), *_table(capacity)))
    proc.let("result", B32, proc.const(2 if insert else 0))

    def zero(p: Proc):
        old = _load(p, p.const(capacity * 8), 8)
        if insert:
            p["result"] = p.op1(Operation.INT_TRUNCATE, (p.bin(Operation.SUB_WRAP, 1, old, B64),), B32)
            _store(p, p.const(capacity * 8), p.const(1, B64), 8)
        else:
            p["result"] = p.op1(Operation.INT_TRUNCATE, (old,), B32)

    def probe(p: Proc):
        mixed = p.op1(Operation.ROTATE_RIGHT, (p.bin(Operation.MUL_WRAP, p["key"], GOLDEN, B64),), B64, attributes=(32,))
        p.let("index", B32, p.bin(Operation.BIT_AND, p.op1(Operation.INT_TRUNCATE, (mixed,), B32), capacity - 1))
        p.let("probes", B32, p.const(0))
        p.let("go", B1, p.const(1, B1))

        def step(q: Proc):
            def look(r: Proc):
                offset = r.bin(Operation.MUL_WRAP, r["index"], 8)
                slot = _load(r, offset, 8)

                def empty(s: Proc):
                    if insert:
                        _store(s, offset, s["key"], 8)
                        s["result"] = s.const(1)
                    _stop(s)

                def found(s: Proc):
                    s["result"] = s.const(0 if insert else 1)
                    _stop(s)

                def next_(s: Proc):
                    s["index"] = s.bin(Operation.BIT_AND, s.bin(Operation.ADD_WRAP, s["index"], 1), capacity - 1)
                    s["probes"] = s.bin(Operation.ADD_WRAP, s["probes"], 1)

                r.if_(r.cmp(EQ, slot, r["key"], B64), found, lambda s: s.if_(s.cmp(EQ, slot, 0, B64), empty, next_))

            q.if_(q.cmp(EQ, q["probes"], capacity), _stop, look)

        p.while_(_going, step)

    proc.if_(proc.cmp(EQ, proc["key"], 0, B64), zero, probe)
    proc.ret(proc["result"], proc["p"], proc["v"], proc["m"])
    return _done(proc, (B32, WORDS, heap_view_type((capacity + 1) * 8), MEM))


def hashset_package(capacity: int) -> Library:
    if capacity < 2 or capacity & (capacity - 1) or (capacity + 1) * 8 >= 1 << 32:
        raise ValueError("capacity must be a power of two with a bits<32>-addressable table")
    return _library("xax.collections.hashset_u64", 1, {"capacity": capacity}, {"insert": _hashset(capacity, True), "contains": _hashset(capacity, False)})


def hashset_table_extent(capacity: int) -> int:
    return (capacity + 1) * 8
