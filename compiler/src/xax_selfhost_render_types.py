"""Self-hosting step S15b.2 (ADR-289): type and constant rejections rendered as exact diagnostics by XAX.

The typing program decides every type and constant rejection (``TYPE_SITES``, ``CONSTANT_SITES``) and records its
site and quoted values in its object tables (``CREJ``, ``COFF``, ``CLEN``, ``CWIDTH``, ``C4``-``C6``); the host rendered
them (``object_rejections``, ``_type_diagnostic``).  The general compiler driver keeps those words for each object while
it verifies (``RECORD_WORDS`` per object at ``xax_selfhost_render.TYPES_AT`` of its workspace) and, when
``verify_store``'s order reaches a type or constant the typing program rejected, ``render`` here writes the bootstrap's
diagnostic (with its dependencies and repair neighborhood) as the workspace's record.

``render`` has the S10e helper convention (``xax_selfhost_semantic``): the input view is the driver's object table
(located by ``index_objects``), the output its workspace; the object travels in control word ``T_OBJECT`` and the
outcome in ``T_STATUS`` (``ACCEPT``: written, else declined).
"""

from __future__ import annotations

import xax_compiler as X
import xax_selfhost_diagnostics as D
import xax_selfhost_render as R
import xax_selfhost_typing as TY
from xax_compiler import Kind
from xax_selfhost_facts import E, _function
from xax_selfhost_semantic import CTRL, _body, _cid_word, _kind, _nrefs, _ref

T_OBJECT, T_STATUS = 60, 61
ACCEPT, DECLINE = 0, 1
RECORD_WORDS = 8  # per object: CREJ, COFF, CLEN, CWIDTH, C4, C5, C6
FIELDS = (TY.CREJ, TY.COFF, TY.CLEN, TY.CWIDTH, TY.C4, TY.C5, TY.C6)
COUNTS_AT = 35 << 20  # workspace scratch: per object, how often a list quotes it (zero between uses)
BAD_AT = (34 << 20) - 1  # workspace word: set while the record quotes an index that names no stored object
assert R.TYPES_AT + RECORD_WORDS * (1 << 16) <= R.WORK_PLAN


class SemanticTable:
    """The driver's object table as the S10e helpers read it (records located by ``index_objects``)."""

    def __init__(self, e: E):
        self.e = e

    def objects(self):
        return self.e.rd(0)

    def kind(self, o):
        return _kind(self.e, o)

    def references(self, o):
        return _nrefs(self.e, o)

    def reference(self, o, k):
        return _ref(self.e, o, k)

    def cid_word(self, o, k):
        return _cid_word(self.e, o, k)

    def body(self, o):
        return _body(self.e, o)[1]


def _sorted_references(w: R.Writer, o, selected=None):
    """``sorted(cid.hex() for each reference [k selected])`` as a list of CIDs (store order is CID order)."""
    e, p, table = w.e, w.e.p, w.table
    k, q, r = w.fresh("tk"), w.fresh("tq"), w.fresh("tr")
    e.var("ts_total", 0)

    def count():
        target = table.reference(o, p[k])
        chosen = selected(p[k]) if selected is not None else e.eq(0, 0)
        e.if_(chosen, lambda: (e.st(e.add(COUNTS_AT, target), e.add(e.ld(e.add(COUNTS_AT, target)), 1)), e.set("ts_total", e.add(p["ts_total"], 1))))

    e.for_(k, 0, table.references(o), count)
    w.put(D.T_LIST)
    w.put(p["ts_total"])

    def emit():
        e.for_(r, 0, e.ld(e.add(COUNTS_AT, p[q])), lambda: w.cid(p[q]))
        e.st(e.add(COUNTS_AT, p[q]), 0)

    e.for_(q, 0, table.objects(), emit)


def _render(tables):
    def build(e: E):
        p = e.p
        table = SemanticTable(e)
        w = R.Writer(e, table, D.DIAG_AT, D.DIAG_AT + (1 << 20) - 2, BAD_AT, functions=_FN)
        e.var("o", e.ld(CTRL + T_OBJECT))
        o = p["o"]
        at = e.add(R.TYPES_AT, e.mul(o, RECORD_WORDS))
        e.var("site", e.ld(at))
        for k, name in enumerate(("offset", "length", "width", "fourth", "fifth", "sixth")):
            e.var(name, e.ld(e.add(at, k + 1)))
        e.st(BAD_AT, 0)
        e.st(CTRL + T_STATUS, DECLINE)
        D.begin(e)
        body_length, body = _body(e, o)
        e.var("blen", body_length)
        e.var("bat", body)
        refs = table.references(o)
        const = lambda value: lambda: w.const(value)  # noqa: E731
        integer = lambda value: lambda: w.integer(value)  # noqa: E731
        hexes = lambda: w.seq(D.T_LIST, table.references(o), lambda i: w.cid(table.reference(o, i)))  # noqa: E731
        empty = lambda: (w.put(D.T_LIST), w.put(0))  # noqa: E731

        def body_hex(start=0, length=None):
            return lambda: w.body_bytes(D.T_HEX, o, start, p["blen"] if length is None else length)

        def five(code, rule, expected, actual, dependencies=None, repair=None):
            w.text(code)
            w.cid(o)
            w.text(rule)
            expected()
            actual()
            (dependencies or empty)()
            (repair or empty)()
            e.st(CTRL + T_STATUS, ACCEPT)

        def non_minimal(start):
            """``_non_minimal``: the minimal encoding of the ULEB at ``start``, then its given bytes."""
            e.var("nm_end", start)
            e.while_(lambda: e.le(128, e.rd(e.add(p["bat"], p["nm_end"]))), lambda: e.set("nm_end", e.add(p["nm_end"], 1)))
            e.var("nm_last", start)
            e.for_("nm_k", start, e.add(p["nm_end"], 1), lambda: e.if_(e.ne(e.and_(e.rd(e.add(p["bat"], p["nm_k"])), 127), 0),
                                                                        lambda: e.set("nm_last", p["nm_k"])))
            size = e.add(e.sub(p["nm_last"], start), 1)
            e.var("nm_size", size)
            return (lambda: w.packed(D.T_HEX, p["nm_size"], lambda byte: e.for_("nm_q", 0, p["nm_size"], lambda: byte(e.sel(
                        e.eq(e.add(start, p["nm_q"]), p["nm_last"]), e.and_(e.rd(e.add(p["bat"], e.add(start, p["nm_q"]))), 127),
                        e.rd(e.add(p["bat"], e.add(start, p["nm_q"]))))))),
                    lambda: w.body_bytes(D.T_HEX, o, start, e.add(e.sub(p["nm_end"], start), 1)))

        def transitions():
            """``_transitions(obj, sixth)`` (``[]`` when the body ends before it)."""
            def read():
                e.var("tr_at", e.add(p["bat"], p["sixth"]))

                def uleb():
                    e.var("tu_value", 0)
                    e.var("tu_shift", 1)
                    e.var("tu_more", 1)

                    def step():
                        e.var("tu_byte", e.rd(p["tr_at"]))
                        e.set("tu_value", e.add(p["tu_value"], e.mul(e.and_(p["tu_byte"], 127), p["tu_shift"])))
                        e.set("tu_shift", e.mul(p["tu_shift"], 128))
                        e.set("tu_more", e.flag(e.le(128, p["tu_byte"])))
                        e.set("tr_at", e.add(p["tr_at"], 1))

                    e.while_(lambda: e.ne(p["tu_more"], 0), step)
                    return p["tu_value"]

                e.var("tr_count", uleb())
                w.seq(D.T_LIST, p["tr_count"], lambda _i: w.integer(uleb()))

            e.if_(e.lt(p["sixth"], p["blen"]), read, empty)

        listing = lambda *items: lambda: (w.put(D.T_LIST), w.put(len(items)), [item() for item in items])  # noqa: E731
        types = {
            "TYPE_TRAILING": lambda: five(R.TRAILING, "TYPE-BODY", const(0), integer(p["width"])),
            "TYPE_OPAQUE_KIND": lambda: five("XAX.TYPE.OPAQUE", "TYPE-OPAQUE-KIND", const(list(X.OpaqueKind)), integer(p["length"])),
            "TYPE_OPAQUE_CANONICAL": lambda: five("XAX.TYPE.OPAQUE", "TYPE-OPAQUE-CANONICAL", const("no references"), integer(refs)),
            "TYPE_EFFECT_DOMAIN": lambda: five("XAX.TYPE.EFFECT", "TYPE-EFFECT-DOMAIN", const(list(X.EffectDomain)), integer(p["length"])),
            "TYPE_EFFECT_CANONICAL": lambda: five("XAX.TYPE.EFFECT", "TYPE-EFFECT-CANONICAL", const("domain plus optional positive instance"), body_hex()),
            "TYPE_SUM_NONEMPTY": lambda: five("XAX.TYPE.SUM", "TYPE-SUM-NONEMPTY", const(">= 1"), const(0)),
            "TYPE_ULEB_UNTERMINATED": lambda: five("XAX.CANON.ULEB_UNTERMINATED", "SER-ULEB-TERMINATED", const("terminating byte"), const("end of input")),
            "TYPE_ULEB_BOUNDED": lambda: five("XAX.CANON.ULEB_OVERFLOW", "SER-ULEB-BOUNDED", const("at most 10 bytes"), const("more than 10 bytes")),
            "TYPE_ULEB_MINIMAL": lambda: five("XAX.CANON.ULEB_NON_MINIMAL", "SER-ULEB-MINIMAL", *non_minimal(p["fourth"])),
            "TYPE_POINTER_ELEMENT": lambda: five("XAX.TYPE.POINTER", "TYPE-POINTER-VALUE-ELEMENT", const("non-proof value type"),
                                                 lambda: w.cid(table.reference(o, p["width"]))),
            "TYPE_POINTER_UNUSED": lambda: five("XAX.CANON.UNUSED_REFERENCE", "SER-REFS-DIRECT-ONLY",
                                                lambda: (w.put(D.T_LIST), w.put(1), w.cid(table.reference(o, p["width"]))), hexes),
            "TYPE_IDENTITY_TRUNCATED": lambda: five("XAX.CANON.TRUNCATED", "SER-BOUNDS", lambda: w.fmt("{} available bytes", p["length"]),
                                                    integer(p["width"])),
            "TYPE_IDENTITY_CANONICAL": lambda: five("XAX.TYPE.OPAQUE_IDENTITY", "TYPE-OPAQUE-IDENTITY-CANONICAL",
                                                    const("nonempty identity and no references"),
                                                    listing(body_hex(e.sub(p["blen"], p["length"]), p["length"]), integer(refs))),
            "TYPE_TUPLE_ELEMENT": lambda: five("XAX.TYPE.TUPLE", "TYPE-TUPLE-VALUE-ELEMENT", const("non-proof value type"),
                                               lambda: w.cid(table.reference(o, p["width"]))),
            "TYPE_SUM_VARIANT": lambda: five("XAX.TYPE.SUM", "TYPE-SUM-VALUE-VARIANT", const("non-proof value type"),
                                             lambda: w.cid(table.reference(o, p["width"]))),
            "TYPE_LIST_UNUSED": lambda: five("XAX.CANON.UNUSED_REFERENCE", "SER-REFS-DIRECT-ONLY",
                                             lambda: _sorted_references(w, o, lambda k: e.ne(e.and_(e.udiv(p["fourth"], e.sel(
                                                 e.lt(k, 64), _power(e, k), 0)), 1), 0)),
                                             lambda: _sorted_references(w, o)),
            "TYPE_RESOURCE_STACK_OWNER": lambda: five("XAX.TYPE.RESOURCE", "TYPE-RESOURCE-STACK-OWNER", const("resource<stack-storage,live>"),
                                                      listing(integer(p["length"]), integer(p["width"]))),
            "TYPE_RESOURCE_CANONICAL": lambda: five("XAX.TYPE.RESOURCE", "TYPE-RESOURCE-CANONICAL",
                                                    const("positive kind/state, canonical flags/instance/transitions"),
                                                    listing(integer(p["length"]), integer(p["width"]), integer(p["fourth"]), integer(p["fifth"]),
                                                            transitions)),
            "TYPE_ARRAY_ELEMENT": lambda: five("XAX.TYPE.ARRAY", "TYPE-ARRAY-VALUE-ELEMENT", const("one non-proof value element"),
                                               listing(lambda: w.cid(table.reference(o, p["length"])), hexes)),
            "TYPE_REF_INDEX": lambda: five("XAX.STRUCT.REF_INDEX", "GRAPH-REF-INDEX", lambda: w.fmt("< {}", refs),
                                           lambda: w.integer(e.sel(e.eq(p["offset"], 9), p["length"], p["width"]))),
            "TYPE_POINTER_PERMISSION": lambda: five("XAX.TYPE.POINTER_PERMISSION", "TYPE-POINTER-PERMISSION", const(list(X.Permission)),
                                                    integer(p["width"])),
            "TYPE_POINTER": lambda: five("XAX.TYPE.POINTER", "TYPE-POINTER", const("form=2,positive address space,power-of-two alignment"),
                                         listing(integer(p["offset"]), integer(p["length"]), integer(p["width"]))),
            "TYPE_BITS": lambda: five("XAX.TYPE.BITS", "TYPE-BITS", const("form=1,width>=1"), listing(integer(p["offset"]), integer(p["length"]))),
            "TYPE_FLOAT_FORMAT": lambda: five("XAX.TYPE.FLOAT", "TYPE-FLOAT-FORMAT", const([1, 2]), integer(p["length"])),
            "TYPE_FLOAT": lambda: five("XAX.TYPE.FLOAT", "TYPE-FLOAT", const("form=7,known format"), listing(integer(p["offset"]), integer(p["length"]))),
            "TYPE_LINK": lambda: five("XAX.TYPE.LINK", "TYPE-LINK-CANONICAL", const("empty link body"), body_hex()),
            "TYPE_FORM": lambda: five("XAX.TYPE.FORM", "TYPE-FORM-SUPPORTED", const(list(range(1, 12))), integer(p["offset"])),
        }
        assert set(types) == set(TY.TYPE_SITES)
        type_hex = lambda: w.cid(table.reference(o, 0))  # noqa: E731
        value_hex = body_hex(p["offset"], p["length"])
        constants = {
            "CONST_REF_INDEX": lambda: five("XAX.STRUCT.REF_INDEX", "GRAPH-REF-INDEX", lambda: w.fmt("< {}", refs), integer(p["offset"])),
            "CONST_TRUNCATED": lambda: five("XAX.CANON.TRUNCATED", "SER-BOUNDS", lambda: w.fmt("{} available bytes", p["length"]), integer(p["width"])),
            "CONST_TRAILING": lambda: five(R.TRAILING, "CONST-BODY", const(0), integer(p["width"])),
            "BITS_WIDTH": lambda: five("XAX.CONSTANT.WIDTH", "CONST-BITS-WIDTH", lambda: w.fmt("{} canonical bits", p["width"]), value_hex,
                                       lambda: (w.put(D.T_LIST), w.put(1), type_hex()), lambda: (w.put(D.T_LIST), w.put(2), w.cid(o), type_hex())),
            "FLOAT_WIDTH": lambda: five("XAX.CONSTANT.WIDTH", "CONST-FLOAT-WIDTH", integer(e.udiv(p["width"], 8)), integer(p["length"])),
            "FLOAT_NAN": lambda: five("XAX.CONSTANT.FLOAT_NAN", "CONST-FLOAT-CANONICAL-NAN", const("canonical quiet NaN"), value_hex),
            "LINK_NULL": lambda: five("XAX.CONSTANT.LINK", "CONST-LINK-NULL-ONLY", const(bytes(8).hex()), value_hex),
            "SCALAR_TYPE": lambda: five("XAX.CONSTANT.TYPE", "CONST-SCALAR-TYPE", const(["bits<N>", "float<F>", "link (null)"]), type_hex),
        }
        assert set(constants) == set(TY.CONSTANT_SITES)
        site = p["site"]
        for number, name in enumerate(TY.CONSTANT_SITES, 1):
            e.if_(e.eq(site, number), constants[name])
        for number, name in enumerate(TY.TYPE_SITES, TY.TYPE_SITE_BASE + 1):
            e.if_(e.eq(site, number), types[name])
        bad = e.either(e.ne(e.ld(BAD_AT), 0), e.lt(D.DIAG_AT + (1 << 20) - 3, e.ld(D.DIAG_AT)))
        e.if_(bad, lambda: e.st(CTRL + T_STATUS, DECLINE))
        e.give(e.ld(CTRL + T_STATUS))
    return _function((), build, tables)


def _power(e: E, k):
    """``2 ** k`` (``k`` < 64)."""
    e.var("pw_value", 1)
    e.for_("pw_k", 0, k, lambda: e.set("pw_value", e.mul(e.p["pw_value"], 2)))
    return e.p["pw_value"]


_FN: dict = {}


def build_functions():
    """``{name: function}`` and the objects they need."""
    objects = []
    for name, make in (("put", lambda: R.put_function(D.DIAG_AT, D.DIAG_AT + (1 << 20) - 2)),
                       ("cid", lambda: _function(("o",), R.cid_function(SemanticTable, _FN), None))):
        function, items = make()
        _FN[name] = function
        objects.extend(items)
    function, items = _render(None)
    return {"render": function}, (*objects, *items)
