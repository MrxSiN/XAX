"""Step 4 of the native decode path: resolve a carrier's type and entity names.

The reader (step 3) turns carrier bytes into a tree.  This module turns the names in that tree into
canonical objects, in the shape the native store writer consumes -- ``kind``, ``schema``, references and
body -- one line per occurrence, in walk order::

    resolve.exe <carrier> <listing>

``?`` marks a spec that is not resolved yet (see below), so a run reports its own coverage instead of
claiming completeness.

The oracle is the reference decoder.  For every line the reference resolves, this program's line is
decoded into a ``SemanticObject`` and its CID is compared with ``xax_construct._Builder``'s object for
the same spec, so the claim is about object identity, not about text that happens to agree.

What resolves here
------------------

* a ``b<N>`` type -- body ``01`` then the width,
* an alias declared in the carrier's ``types`` map (recursive, depth-limited, so a cycle is refused, as
  the reference refuses one),
* ``win32.<name>`` -- the platform namespace, embedded as authoring data by ``namespace_layout`` from
  ``xax_platform.win32_kernel32_api`` and ``win32_stdio_api``, read exactly as ``xax_construct`` reads
  them,
* ``{"view": EXTENT}`` -- the heap-view type,
* entities that are ``win32.<name>`` strings: the platform declarations are already in the blob,
* ``{"win32.import": [DLL, SYMBOL, IN, OUT]}`` and ``{"win32.virtual_free_view": [TYPE, EXTENT]}`` --
  declarations whose body embeds the *CIDs* of their signature types.  Those CIDs are hashed in the
  program: the object's canonical content (``XAX-SEM-1``, kind, schema, references, body) is staged in
  the view and hashed by ``xax_selfhost_blake3.hash_span_function``, the committed S2 graph over one
  view (a program that owns its memory holds one effect token, so it cannot lend the two views
  ``hash_function`` asks for).

What does not, yet
------------------

``{"fn": NAME}`` needs the constructed functions, step 5.  Those are emitted as ``?`` and counted.  An
unknown name is a refusal (exit 11 for a type, 12 for an entity), never a guess.
"""

from __future__ import annotations

import dataclasses
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import reader as R  # noqa: E402
from xax_compiler import IntCompare, Kind, Operation, Permission, SemanticObject, bits_type, heap_view_type, pointer_type  # noqa: E402
from xax_platform import win32_kernel32_api, win32_stdio_api  # noqa: E402
from xax_selfhost_blake3 import DIGEST_OFFSET, hash_span_function  # noqa: E402
from xax_structured import B32, B64  # noqa: E402

HEX = b"0123456789abcdef"
SPACE, NL, COMMA, DASH = 32, 10, 44, 45
PREFIX = b"win32."
UNKNOWN_TYPE, UNKNOWN_ENTITY = 11, 12
DEPTH_LIMIT = 8              # alias chain bound: the reference recurses, this refuses
DOMAIN = b"XAX-SEM-1"        # the canonical content's domain separator (xax_compiler.semantic_cid)
FF_PREFIX, FF_ABI = b"foreign-function-v1", b"win64-c"
B8 = bits_type(8)

# Regions of the view the resolver stages objects in.  The canonical area holds one object's content;
# the hash's chaining-value stack and digest sit past the largest object, both inside the same view.
CANON = 0xE10000
HASH_GAP = 0x2000
HASH_SCRATCH = CANON + HASH_GAP
DBODY = 0xE20000            # a declaration's identity, up to a few KiB
DBOFF = 4                   # room for the identity's length prefix (a uleb of at most four bytes)
ALIGNED = pointer_type(B8, Permission.READ_WRITE, 4, space=2)  # the view base, word-aligned
HASH: dict = {}

# table entry, relative to the kind byte
T_KIND, T_SCHEMA, T_COUNT, T_REFS = 0, 1, 5, 9
T_BODY_LEN = T_REFS          # + 32 * count
T_BODY = T_BODY_LEN + 4      # + 32 * count


def namespace_entries() -> dict[str, SemanticObject]:
    """The ``win32.`` names ``xax_construct._Builder`` can reach, in its own namespace order."""
    api = win32_kernel32_api()
    stdio = win32_stdio_api(api)
    entries: dict[str, SemanticObject] = {}
    for namespace in (stdio, api):
        for field in dataclasses.fields(namespace):
            value = getattr(namespace, field.name)
            if isinstance(value, SemanticObject):
                entries.setdefault(field.name, value)
    return entries


def namespace_layout() -> tuple[bytes, dict[str, int]]:
    """The embedded table and the offset of each entry's kind byte.

    The table is the decode-time lookup for ``win32.<name>``; the offsets let a declaration that names a
    platform type (``b64``, ``b32``, ``memory_effect``) address it without a run-time name scan."""
    entries = namespace_entries()
    blob = bytearray(len(entries).to_bytes(4, "little"))
    offsets: dict[str, int] = {}
    for name in sorted(entries):
        obj = entries[name]
        key = name.encode()
        offsets[name] = len(blob) + 1 + len(key)
        blob += len(key).to_bytes(1, "little") + key
        blob += int(obj.kind).to_bytes(1, "little")
        blob += obj.schema_version.to_bytes(4, "little")
        blob += len(obj.references).to_bytes(4, "little")
        for reference in obj.references:
            blob += reference
        blob += len(obj.body).to_bytes(4, "little") + obj.body
    return bytes(blob), offsets


TABLE, TABLE_OFFSETS = namespace_layout()


def walk(environment):
    """Resolve every type occurrence and every platform entity in the parsed carrier."""
    p = environment["p"]
    E = environment
    get = E["get"]
    add, sub, mul, c32 = E["add"], E["sub"], E["mul"], E["c32"]
    eq, ne, lt = E["eq"], E["ne"], E["lt"]
    ld8, ld32, st8, st64 = E["ld8"], E["ld32"], E["st8"], E["st64"]
    byte, out_byte, out_dyn = E["byte"], E["out_byte"], E["out_dyn"]
    fail_if = E["fail"]
    strings, objects, integers = E["STRING"], E["OBJECT"], E["INTEGER"]
    kind_of, start_of, end_of = E["KIND"], E["START"], E["END"]
    first_of, next_of = E["FIRST"], E["NEXT"]

    def flag(value):
        return p.widen(value, B32)

    def div(left, right):
        return p.bin(Operation.UDIV, left, right, B32)

    def rem(left, right):
        return p.bin(Operation.UREM, left, right, B32)

    def gt(left, right):
        return p.cmp(IntCompare.UGT, left, right, B32)

    def ge(left, right):
        return p.cmp(IntCompare.UGE, left, right, B32)

    def zero(value):
        return p.cmp(IntCompare.EQ, value, c32(0), B32)

    def same(left, right):
        return p.cmp(IntCompare.EQ, left, right, B32)

    def fail_here(code):
        p.if_(zero(p["code"]), lambda _p: p.__setitem__("code", c32(code)))

    for name in ("w1", "w2", "w3", "w4", "w5", "w6", "w7", "whead", "wtail", "wdig", "weqi", "weqc",
                 "wcur", "wval", "wrefi", "wscan", "wname", "wnlen", "wentry", "wfound", "wpick",
                 "wrefs", "wblen", "wdepth", "wmember", "wss", "wse", "wnode", "wmore", "wcursor",
                 "wsrc", "wcnt", "wbyte", "wkind", "wschema", "wrefn", "wrefsrc", "wbody", "wbodyat",
                 "wcanonlen", "wln", "wlv", "wdbn", "wdbat", "w8", "w9"):
        p.let(name, B32, c32(0))

    def kind(node):
        return get(node, kind_of)

    def start(node):
        return get(node, start_of)

    def end(node):
        return get(node, end_of)

    def first(node):
        return get(node, first_of)

    def after(node):
        return get(node, next_of)

    def hex_char(value):
        """``0123456789abcdef`` for a computed nibble, without a branch."""
        return add(add(value, c32(48)), mul(flag(ge(value, c32(10))), c32(39)))

    def hexdump(offset, length):
        p["whead"] = offset
        p["wtail"] = add(offset, length)
        p.while_(lambda _p: lt(p["whead"], p["wtail"]),
                 lambda _p: (out_dyn(hex_char(div(flag(ld8(p["whead"])), c32(16)))),
                             out_dyn(hex_char(rem(flag(ld8(p["whead"])), c32(16)))),
                             p.__setitem__("whead", add(p["whead"], c32(1)))))

    def out_fixed(value):
        out_byte(HEX[value >> 4])
        out_byte(HEX[value & 15])

    def table_object(entry):
        """The object fields of a table entry: kind, schema, references, body."""
        p["wkind"] = flag(ld8(entry))
        p["wschema"] = flag(ld8(add(entry, c32(T_SCHEMA))))
        p["wrefn"] = ld32(add(entry, c32(T_COUNT)))
        p["wrefsrc"] = add(entry, c32(T_REFS))
        p["wblen"] = ld32(add(add(entry, c32(T_BODY_LEN)), mul(p["wrefn"], c32(32))))
        p["wbody"] = add(add(entry, c32(T_BODY)), mul(p["wrefn"], c32(32)))

    def emit_object():
        """``<kind> <schema> <refs|-> <body>``: the native writer's batch shape."""
        out_dyn(add(c32(48), p["wkind"]))
        out_byte(SPACE)
        out_dyn(add(c32(48), p["wschema"]))
        out_byte(SPACE)
        p["wrefi"] = c32(0)
        p.while_(lambda _p: lt(p["wrefi"], p["wrefn"]),
                 lambda _p: (p.if_(gt(p["wrefi"], c32(0)), lambda _q: out_byte(COMMA)),
                             hexdump(add(p["wrefsrc"], mul(p["wrefi"], c32(32))), c32(32)),
                             p.__setitem__("wrefi", add(p["wrefi"], c32(1)))))
        p.if_(zero(p["wrefn"]), lambda _q: out_byte(DASH))
        out_byte(SPACE)
        hexdump(add(c32(CANON), p["wbodyat"]), p["wblen"])
        out_byte(NL)

    # -- canonical staging: the content the store writer hashes ---------------------------------

    def canon_put(value):
        """One byte at ``CANON + wcursor``, then one past it."""
        st8(add(c32(CANON), p["wcursor"]), p.const(value, B8))
        p["wcursor"] = add(p["wcursor"], c32(1))

    def uleb_len(value):
        """The encoded length of ``uleb(value)``, into ``wln``."""
        p["wlv"] = value
        p["wln"] = c32(1)
        p.while_(lambda _p: ge(p["wlv"], c32(128)),
                 lambda _p: (p.__setitem__("wlv", div(p["wlv"], c32(128))),
                             p.__setitem__("wln", add(p["wln"], c32(1)))))
        return p["wln"]

    def canon_uleb(value):
        """Append ``uleb(value)`` at ``CANON + wcursor``."""
        p["wval"] = value
        p["wbyte"] = c32(1)
        p.while_(lambda _p: ne(p["wbyte"], 0),
                 lambda _p: (p.__setitem__("wdig", rem(p["wval"], c32(128))),
                             p.__setitem__("wval", div(p["wval"], c32(128))),
                             p.__setitem__("wbyte", flag(ne(p["wval"], 0))),
                             st8(add(c32(CANON), p["wcursor"]),
                                  p.op1(Operation.INT_TRUNCATE,
                                        (add(p["wdig"], mul(p["wbyte"], c32(128))),), B8)),
                             p.__setitem__("wcursor", add(p["wcursor"], c32(1)))))

    def canon_copy(offset, count):
        """Copy ``count`` bytes of the view at ``offset`` into the staging area."""
        p["wsrc"], p["wcnt"] = offset, count
        p.while_(lambda _p: ne(p["wcnt"], 0),
                 lambda _p: (st8(add(c32(CANON), p["wcursor"]), ld8(p["wsrc"])),
                             p.__setitem__("wsrc", add(p["wsrc"], c32(1))),
                             p.__setitem__("wcursor", add(p["wcursor"], c32(1))),
                             p.__setitem__("wcnt", sub(p["wcnt"], c32(1)))))

    def canon_begin(kind, schema, nrefs):
        """Start an object's canonical content: domain, kind, schema, reference count."""
        p["wcursor"] = c32(0)
        for value in DOMAIN:
            canon_put(value)
        canon_uleb(kind)
        canon_uleb(schema)
        canon_uleb(nrefs)

    def build_canonical():
        """Stage the object in ``wkind``/``wschema``/``wrefn``; keep the body offset and length."""
        canon_begin(p["wkind"], p["wschema"], p["wrefn"])
        p.if_(ne(p["wrefn"], 0), lambda _q: canon_copy(p["wrefsrc"], mul(p["wrefn"], c32(32))))
        canon_uleb(p["wblen"])
        p["wbodyat"] = p["wcursor"]
        canon_copy(p["wbody"], p["wblen"])
        p["wcanonlen"] = p["wcursor"]

    def set_scalar_object(kind, refs, body_len):
        p["wkind"], p["wschema"], p["wrefn"] = c32(kind), c32(1), c32(refs)
        p["wrefsrc"], p["wbody"] = c32(0), c32(0)
        p["wblen"] = body_len

    def bits_object(width):
        """A ``b<N>`` type: body ``01`` then the width."""
        set_scalar_object(4, 0, add(c32(1), uleb_len(width)))
        canon_begin(c32(4), c32(1), c32(0))
        canon_uleb(p["wblen"])
        p["wbodyat"] = p["wcursor"]
        canon_put(0x01)
        canon_uleb(width)
        p["wcanonlen"] = p["wcursor"]

    def view_object(extent):
        """A heap-view type: body ``04 81 02 01 04``, extent, ``00``."""
        set_scalar_object(4, 0, add(c32(6), uleb_len(extent)))
        canon_begin(c32(4), c32(1), c32(0))
        canon_uleb(p["wblen"])
        p["wbodyat"] = p["wcursor"]
        for value in (0x04, 0x81, 0x02, 0x01, 0x04):
            canon_put(value)
        canon_uleb(extent)
        canon_put(0x00)
        p["wcanonlen"] = p["wcursor"]

    def hash_canonical():
        """Hash the staged content; the digest lands at ``HASH_SCRATCH + DIGEST_OFFSET``."""
        base = p.op1(Operation.ADDRESS_OFFSET, (p["vp"],), ALIGNED, attributes=(0,))
        _pointer, view, memory = p.op(
            Operation.CALL_DIRECT,
            (base, p["vv"], p["mem"], p.const(CANON, B64), p.widen(p["wcanonlen"], B64)),
            (ALIGNED, E["view_type"], E["mem_type"]),
            entity=HASH["fn"])
        p["vv"], p["mem"] = view, memory

    def bytes_eq(offset, literal):
        """The input bytes at ``offset`` equal the literal (the literal is compile-time, so unrolled)."""
        terms = [eq(byte(add(offset, c32(index))), value) for index, value in enumerate(literal)]
        if not terms:
            return c32(1)
        return p.all_of(*terms)

    def span_eq(offset, stop, literal):
        """The input span equals the literal (length and every byte)."""
        return p.all_of(bytes_eq(offset, literal), eq(sub(stop, offset), len(literal)))

    def span_prefix(offset, stop, literal):
        """The input span starts with the literal."""
        return p.all_of(bytes_eq(offset, literal), ge(sub(stop, offset), c32(len(literal))))

    def span_eq_span(left_start, left_stop, right_start, right_stop):
        p["weqi"] = c32(0)
        p["weqc"] = c32(0)
        p["wval"] = sub(left_stop, left_start)
        p.while_(lambda _p: lt(p["weqc"], p["wval"]),
                 lambda _p: (p.__setitem__("weqi",
                                           add(p["weqi"], flag(same(byte(add(left_start, p["weqc"])),
                                                                    byte(add(right_start, p["weqc"])))))),
                             p.__setitem__("weqc", add(p["weqc"], c32(1)))))
        return p.all_of(same(p["wval"], sub(right_stop, right_start)), same(p["weqi"], p["wval"]))

    def parse_uint(offset, stop, limit):
        """The decimal integer in the span, into ``wval``; refuses anything else."""
        p["wval"] = c32(0)
        p["wcur"] = offset
        p.while_(lambda _p: lt(p["wcur"], stop),
                 lambda _p: (p.__setitem__("wdig", sub(byte(p["wcur"]), c32(48))),
                             fail_if(gt(p["wdig"], c32(9)), UNKNOWN_TYPE),
                             p.__setitem__("wval", add(mul(p["wval"], c32(10)), p["wdig"])),
                             p.__setitem__("wcur", add(p["wcur"], c32(1)))))
        fail_if(gt(p["wval"], c32(limit)), UNKNOWN_TYPE)

    def lookup(offset, stop):
        """The embedded entry for the name span, into ``wentry`` (0 when absent)."""
        p["wentry"] = c32(0)
        p["wscan"] = c32(E["NS"] + 4)
        p["wcur"] = c32(0)
        p["wname"] = ld32(c32(E["NS"]))
        p.while_(lambda _p: p.all_of(lt(p["wcur"], p["wname"]), zero(p["wentry"])),
                 lambda _p: (p.__setitem__("wnlen", flag(ld8(p["wscan"]))),
                             p.__setitem__("weqi", c32(0)),
                             p.__setitem__("weqc", c32(0)),
                             p.while_(lambda _q: lt(p["weqc"], p["wnlen"]),
                                      lambda _q: (p.__setitem__("weqi",
                                                                add(p["weqi"], flag(same(
                                                                    byte(add(offset, p["weqc"])),
                                                                    flag(ld8(add(add(p["wscan"], c32(1)),
                                                                                p["weqc"]))))))),
                                                  p.__setitem__("weqc", add(p["weqc"], c32(1))))),
                             p.__setitem__("wval", add(add(p["wscan"], c32(1)), p["wnlen"])),
                             p.if_(p.all_of(same(p["weqi"], p["wnlen"]), same(sub(stop, offset), p["wnlen"])),
                                   lambda _q: p.__setitem__("wentry", p["wval"])),
                             p.__setitem__("wrefs", ld32(add(p["wval"], c32(T_COUNT)))),
                             p.__setitem__("wblen", ld32(add(add(p["wval"], c32(T_BODY_LEN)),
                                                             mul(p["wrefs"], c32(32))))),
                             p.__setitem__("wscan", add(add(add(p["wval"], c32(T_BODY)),
                                                           mul(p["wrefs"], c32(32))), p["wblen"])),
                             p.__setitem__("wcur", add(p["wcur"], c32(1)))))
        return p["wentry"]

    def find_member(container, offset, stop):
        """The member node of ``container`` whose key is the span (0 when absent)."""
        p["wfound"] = c32(0)
        p.if_(ne(container, 0),
              lambda _q: (p.__setitem__("wcur", first(container)),
                          p.while_(lambda _r: p.all_of(ne(p["wcur"], 0), zero(p["wfound"])),
                                   lambda _r: (p.if_(span_eq_span(start(p["wcur"]), end(p["wcur"]),
                                                                  offset, stop),
                                                     lambda _s: p.__setitem__("wfound", p["wcur"])),
                                               p.__setitem__("wcur", after(p["wcur"]))))))
        return p["wfound"]

    def nth_value(node, name):
        """The value node of the first member ``name`` of an object (0 when absent)."""
        p["wentry"] = c32(0)
        p.if_(ne(node, 0),
              lambda _q: (p.__setitem__("wcur", first(node)),
                          p.while_(lambda _r: p.all_of(ne(p["wcur"], 0), zero(p["wentry"])),
                                   lambda _r: (p.if_(span_eq(start(p["wcur"]), end(p["wcur"]), name),
                                                     lambda _s: p.__setitem__("wentry",
                                                                              first(p["wcur"]))),
                                               p.__setitem__("wcur", after(p["wcur"]))))))
        return p["wentry"]

    def nth(array, index):
        """The ``index``-th child of an array."""
        p["wpick"] = first(array)
        p["wcur"] = c32(0)
        p.while_(lambda _p: lt(p["wcur"], c32(index)),
                 lambda _p: (p.__setitem__("wpick", after(p["wpick"])),
                             p.__setitem__("wcur", add(p["wcur"], c32(1)))))
        return p["wpick"]

    def resolve_platform(offset, stop, code):
        """``win32.<name>``: strip the prefix, look the declaration up, refuse a miss."""
        p.if_(span_prefix(offset, stop, PREFIX),
              lambda _q: (p.__setitem__("wentry", lookup(add(offset, c32(len(PREFIX))), stop)),
                          fail_if(zero(p["wentry"]), code),
                          p.if_(ne(p["wentry"], 0),
                                lambda _r: (table_object(p["wentry"]), build_canonical()))),
              lambda _q: fail_here(code))

    def resolve_type_node(node):
        p.if_(eq(kind(node), strings),
              lambda _q: resolve_type_spec(start(node), end(node)),
              lambda _q: resolve_type_object(node))

    def resolve_type_spec(offset, stop):
        """Follow the carrier's alias map at run time -- bounded, so a cycle is refused -- then stage."""
        p["wss"] = offset
        p["wse"] = stop
        p["wnode"] = c32(0)
        p["wmore"] = c32(1)
        p["wdepth"] = c32(0)
        p.while_(lambda _p: p.all_of(ne(p["wmore"], 0), lt(p["wdepth"], c32(DEPTH_LIMIT))),
                 lambda _p: (p.__setitem__("wmore", c32(0)),
                             p.__setitem__("wmember", find_member(TYPES, p["wss"], p["wse"])),
                             p.if_(ne(p["wmember"], 0),
                                   lambda _q: p.if_(eq(kind(first(p["wmember"])), strings),
                                                    lambda _r: (p.__setitem__("wss", start(first(p["wmember"]))),
                                                                p.__setitem__("wse", end(first(p["wmember"]))),
                                                                p.__setitem__("wdepth", add(p["wdepth"], c32(1))),
                                                                p.__setitem__("wmore", c32(1))),
                                                    lambda _r: p.__setitem__("wnode", first(p["wmember"]))))))
        fail_if(ne(p["wmore"], 0), UNKNOWN_TYPE)
        p.if_(ne(p["wnode"], 0), lambda _q: resolve_type_object(p["wnode"]),
              lambda _q: resolve_bits_or_platform(p["wss"], p["wse"]))

    def resolve_type_object(node):
        def as_view(_q):
            member = first(node)
            good = p.all_of(ne(member, 0), span_eq(start(member), end(member), b"view"),
                            zero(after(member)), eq(kind(first(member)), integers))
            p.if_(good,
                  lambda _r: (parse_uint(start(first(first(node))), end(first(first(node))), (1 << 28) - 1),
                              view_object(p["wval"])),
                  lambda _r: fail_here(UNKNOWN_TYPE))

        p.if_(eq(kind(node), objects), as_view, lambda _q: fail_here(UNKNOWN_TYPE))

    def resolve_bits_or_platform(offset, stop):
        is_bits = p.all_of(eq(byte(offset), ord("b")), gt(sub(stop, offset), c32(1)))
        p.if_(is_bits, lambda _q: resolve_bits_spec(offset, stop),
              lambda _q: resolve_platform(offset, stop, UNKNOWN_TYPE))

    def resolve_bits_spec(offset, stop):
        fail_if(eq(byte(add(offset, c32(1))), 48), UNKNOWN_TYPE)  # no leading zero
        parse_uint(add(offset, c32(1)), stop, 64)
        fail_if(zero(p["wval"]), UNKNOWN_TYPE)
        bits_object(p["wval"])

    def resolve_type_digest(node):
        """Stage a type spec and append its CID to the declaration body under construction."""
        resolve_type_node(node)
        hash_canonical()
        db_digest()

    def resolve_platform_digest(name):
        """Append a platform type's CID (from the embedded table) to the body under construction."""
        table_object(c32(E["NS"] + TABLE_OFFSETS[name]))
        build_canonical()
        hash_canonical()
        db_digest()

    def resolve_view_digest(node):
        """Append the CID of ``{"view": extent}`` to the body under construction."""
        parse_uint(start(node), end(node), (1 << 28) - 1)
        view_object(p["wval"])
        hash_canonical()
        db_digest()

    # -- declaration bodies: an ``import`` embeds the CIDs of its signature types ----------------

    def db_byte(value):
        st8(add(c32(DBODY), p["wdbn"]), value)
        p["wdbn"] = add(p["wdbn"], c32(1))

    def db_put(value):
        db_byte(p.const(value, B8))

    def db_uleb(value):
        p["wval"] = value
        p["wbyte"] = c32(1)
        p.while_(lambda _p: ne(p["wbyte"], 0),
                 lambda _p: (p.__setitem__("wdig", rem(p["wval"], c32(128))),
                             p.__setitem__("wval", div(p["wval"], c32(128))),
                             p.__setitem__("wbyte", flag(ne(p["wval"], 0))),
                             db_byte(p.op1(Operation.INT_TRUNCATE,
                                           (add(p["wdig"], mul(p["wbyte"], c32(128))),), B8))))

    def db_raw(blob):
        """Append the bytes as they are (the identity's own prefix carries no length)."""
        for value in blob:
            db_put(value)

    def db_literal(blob):
        """Append ``uleb(len), bytes`` -- the reference's string encoding."""
        db_uleb(c32(len(blob)))
        db_raw(blob)

    def in8(offset):
        """One byte of the carrier at ``offset`` (node spans are offsets into the input)."""
        return p.op1(Operation.INT_TRUNCATE, (byte(offset),), B8)

    def db_span(offset, stop):
        """Append the carrier's byte span as a length-prefixed string."""
        db_uleb(sub(stop, offset))
        p["wsrc"], p["wcnt"] = offset, sub(stop, offset)
        p.while_(lambda _p: ne(p["wcnt"], 0),
                 lambda _p: (db_byte(in8(p["wsrc"])),
                             p.__setitem__("wsrc", add(p["wsrc"], c32(1))),
                             p.__setitem__("wcnt", sub(p["wcnt"], c32(1)))))

    def db_digest():
        """Append the 32-byte digest the last hash left at ``HASH_SCRATCH + DIGEST_OFFSET``."""
        p["wcnt"] = c32(0)
        p.while_(lambda _p: lt(p["wcnt"], c32(32)),
                 lambda _p: (db_byte(ld8(add(c32(HASH_SCRATCH + DIGEST_OFFSET), p["wcnt"]))),
                             p.__setitem__("wcnt", add(p["wcnt"], c32(1)))))

    def finish_declaration():
        """Prepend the identity's length: a TARGET body is ``uleb(len) + identity``."""
        p["wdbn"] = sub(p["wdbn"], c32(DBOFF))
        uleb_len(p["wdbn"])                      # the prefix's own size lands in wln
        p["wcursor"] = c32(0)
        canon_uleb(p["wdbn"])                    # the prefix bytes, at CANON
        p["wdbat"] = sub(c32(DBOFF), p["wln"])
        p["wcnt"] = c32(0)
        p.while_(lambda _p: lt(p["wcnt"], p["wln"]),
                 lambda _p: (st8(add(add(c32(DBODY), p["wdbat"]), p["wcnt"]),
                                 ld8(add(c32(CANON), p["wcnt"]))),
                             p.__setitem__("wcnt", add(p["wcnt"], c32(1)))))

    def emit_declaration():
        """``6 1 - <body>``: a declaration, schema 1, no references."""
        out_byte(ord("6"))
        out_byte(SPACE)
        out_byte(ord("1"))
        out_byte(SPACE)
        out_byte(DASH)
        out_byte(SPACE)
        hexdump(add(c32(DBODY), p["wdbat"]), add(p["wdbn"], p["wln"]))
        out_byte(NL)

    def list_count(array):
        """The number of children of a list node, into ``wcnt``."""
        p["wcnt"] = c32(0)
        p["wcur"] = first(array)
        p.while_(lambda _p: ne(p["wcur"], 0),
                 lambda _p: (p.__setitem__("wcur", after(p["wcur"])),
                             p.__setitem__("wcnt", add(p["wcnt"], c32(1)))))
        return p["wcnt"]

    def emit_import(member):
        """``{"win32.import": [DLL, SYMBOL, IN, OUT]}``: a foreign function with hashed signature CIDs."""
        def shaped(_q):
            items = first(member)
            good = p.all_of(eq(kind(items), E["ARRAY"]),
                            ne(nth(items, 3), 0), zero(after(nth(items, 3))),
                            eq(kind(nth(items, 0)), strings),
                            eq(kind(nth(items, 1)), strings),
                            eq(kind(nth(items, 2)), E["ARRAY"]),
                            eq(kind(nth(items, 3)), E["ARRAY"]))
            p.if_(good,
                  lambda _r: (p.__setitem__("wdbn", c32(DBOFF)),
                              db_raw(FF_PREFIX),
                              db_literal(FF_ABI),
                              db_span(start(nth(items, 0)), end(nth(items, 0))),
                              db_span(start(nth(items, 1)), end(nth(items, 1))),
                              db_uleb(list_count(nth(items, 2))),
                              each(nth(items, 2), "w8", resolve_type_digest),
                              db_uleb(list_count(nth(items, 3))),
                              each(nth(items, 3), "w9", resolve_type_digest),
                              finish_declaration(),
                              p.if_(zero(p["code"]), lambda _s: emit_declaration())),
                  lambda _r: fail_here(UNKNOWN_ENTITY))

        p.if_(eq(kind(first(member)), E["ARRAY"]), shaped, lambda _q: fail_here(UNKNOWN_ENTITY))

    def emit_free_view(member):
        """``{"win32.virtual_free_view": [TYPE, EXTENT]}``: VirtualFree over a typed view."""
        def shaped(_q):
            items = first(member)
            good = p.all_of(eq(kind(items), E["ARRAY"]),
                            ne(nth(items, 1), 0), zero(after(nth(items, 1))),
                            eq(kind(nth(items, 1)), integers))
            p.if_(good,
                  lambda _r: (p.__setitem__("wdbn", c32(DBOFF)),
                              db_raw(FF_PREFIX),
                              db_literal(FF_ABI),
                              db_literal(b"kernel32.dll"),
                              db_literal(b"VirtualFree"),
                              db_uleb(c32(5)),
                              resolve_type_digest(nth(items, 0)),
                              resolve_platform_digest("b64"),
                              resolve_platform_digest("b32"),
                              resolve_view_digest(nth(items, 1)),
                              resolve_platform_digest("memory_effect"),
                              db_uleb(c32(2)),
                              resolve_platform_digest("b32"),
                              resolve_platform_digest("memory_effect"),
                              db_uleb(c32(2)),
                              db_uleb(c32(0)),
                              db_uleb(c32(3)),
                              finish_declaration(),
                              p.if_(zero(p["code"]), lambda _s: emit_declaration())),
                  lambda _r: fail_here(UNKNOWN_ENTITY))

        p.if_(eq(kind(first(member)), E["ARRAY"]), shaped, lambda _q: fail_here(UNKNOWN_ENTITY))

    def emit_entity_name(offset, stop):
        """``win32.<name>`` used as an entity: a declaration and an effect, never a type."""
        def named(_q):
            p["wentry"] = lookup(add(offset, c32(len(PREFIX))), stop)
            fail_if(zero(p["wentry"]), UNKNOWN_ENTITY)
            p.if_(ne(p["wentry"], 0),
                  lambda _r: (fail_if(same(flag(ld8(p["wentry"])), c32(4)), UNKNOWN_ENTITY),
                              p.if_(zero(p["code"]),
                                    lambda _s: (table_object(p["wentry"]),
                                                build_canonical(),
                                                emit_object()))))

        p.if_(span_prefix(offset, stop, PREFIX), named, lambda _q: fail_here(UNKNOWN_ENTITY))

    def emit_entity_object(node):
        """A declared entity object: import, free-view, or the function placeholder."""
        def dispatch(_q):
            member = first(node)
            p.if_(p.all_of(ne(member, 0), zero(after(member))),
                  lambda _r: p.if_(span_eq(start(member), end(member), b"win32.import"),
                                   lambda _s: emit_import(member),
                                   lambda _s: p.if_(
                                       span_eq(start(member), end(member), b"win32.virtual_free_view"),
                                       lambda _t: emit_free_view(member),
                                       lambda _t: p.if_(
                                           span_eq(start(member), end(member), b"fn"),
                                           lambda _u: (out_byte(ord("?")), out_byte(NL)),
                                           lambda _u: fail_here(UNKNOWN_ENTITY)))),
                  lambda _r: fail_here(UNKNOWN_ENTITY))

        p.if_(eq(kind(node), objects), dispatch, lambda _q: fail_here(UNKNOWN_ENTITY))

    def emit_type_node(node):
        """Resolve one type occurrence, then write its line (nothing if the resolution refused)."""
        resolve_type_node(node)
        p.if_(zero(p["code"]), lambda _q: emit_object())

    def emit_entity_node(node):
        p.if_(eq(kind(node), strings),
              lambda _q: emit_entity_name(start(node), end(node)),
              lambda _q: emit_entity_object(node))

    def each(container, cursor, body):
        p[cursor] = first(container)
        p.while_(lambda _p: ne(p[cursor], 0),
                 lambda _p: (body(p[cursor]), p.__setitem__(cursor, after(p[cursor]))))

    def each_type_list(list_node, cursor):
        p.if_(ne(list_node, 0), lambda _q: each(list_node, cursor, emit_type_node))

    def each_member(container, name, cursor, body):
        """For each member of ``container`` named ``name``, hand its value to ``body``."""
        p.if_(ne(container, 0),
              lambda _q: (p.__setitem__(cursor, first(container)),
                          p.while_(lambda _r: ne(p[cursor], 0),
                                   lambda _r: (p.if_(span_eq(start(p[cursor]), end(p[cursor]), name),
                                                     lambda _s: body(first(p[cursor]))),
                                               p.__setitem__(cursor, after(p[cursor]))))))

    def per_node(node):
        operation = first(node)
        is_const = span_eq(start(operation), end(operation), b"const")
        p.if_(is_const, lambda _q: emit_type_node(nth(node, 1)),
              lambda _q: (each(nth(node, 2), "w5", emit_type_node),
                          p.if_(ne(nth(node, 3), 0),
                                lambda _r: each_member(nth(node, 3), b"entity", "w6", emit_entity_node))))

    def per_block(block):
        each_type_list(nth_value(block, b"params"), "w7")
        nodes = nth_value(block, b"nodes")
        p.if_(ne(nodes, 0), lambda _q: each(nodes, "w4", per_node))

    def per_function(function):
        each_type_list(nth_value(function, b"params"), "w7")
        each_type_list(nth_value(function, b"returns"), "w7")
        blocks = nth_value(function, b"blocks")
        p.if_(ne(blocks, 0), lambda _q: each(blocks, "w3", per_block))

    # the embedded namespace must be in the view before anything is resolved
    for index in range(0, len(TABLE), 8):
        chunk = TABLE[index:index + 8].ljust(8, b"\0")
        st64(c32(E["NS"] + index), p.const(int.from_bytes(chunk, "little"), B64))

    root = p["root"]
    TYPES = nth_value(root, b"types")
    p["wdepth"] = c32(0)
    p.if_(ne(TYPES, 0), lambda _q: each(TYPES, "w1", lambda member: emit_type_node(first(member))))
    functions = nth_value(root, b"functions")
    p.if_(ne(functions, 0), lambda _q: each(functions, "w2", per_function))


def build_resolver():
    """The resolver: the reader's host, a word-aligned view, and the span hash linked in."""
    hash_at, hash_objects = hash_span_function(ALIGNED, heap_view_type(R.EXTENT), HASH_SCRATCH)
    HASH["fn"] = hash_at
    return R.build_reader(b"xax-construct-resolve", walk, view_alignment=4,
                          extra_objects=hash_objects)


# -- the oracle ----------------------------------------------------------------------------------------


def object_of(line: str) -> SemanticObject:
    """Decode one produced line into the object it denotes (the check's own reading of the bytes)."""
    kind, schema, refs, body = line.split(" ")
    references = () if refs == "-" else tuple(bytes.fromhex(item) for item in refs.split(","))
    return SemanticObject.create(Kind(int(kind)), bytes.fromhex(body), references, int(schema))


def reference_line(builder, spec, entity: bool) -> tuple[str, bytes]:
    obj = builder.entity(spec) if entity else builder.type(spec)
    references = ",".join(reference.hex() for reference in obj.references) or "-"
    return f"{int(obj.kind)} {obj.schema_version} {references} {obj.body.hex()}", obj.cid


def expected_lines(request: dict) -> list[tuple[str, bytes]]:
    """The reference's line and CID for each spec the program walks, in the same order."""
    import xax_construct as C

    builder = C._Builder(request)
    lines: list[tuple[str, bytes]] = []
    for _name, spec in request.get("types", {}).items():
        lines.append(reference_line(builder, spec, False))
    for record in request.get("functions", []):
        for spec in list(record.get("params", [])) + list(record.get("returns", [])):
            lines.append(reference_line(builder, spec, False))
        for block in record.get("blocks", []):
            for spec in block.get("params", []):
                lines.append(reference_line(builder, spec, False))
            for node in block.get("nodes", []):
                if node[0] == "const":
                    lines.append(reference_line(builder, node[1], False))
                else:
                    for spec in node[2]:
                        lines.append(reference_line(builder, spec, False))
                    extra = node[3] if len(node) == 4 else {}
                    if "entity" in extra:
                        spec = extra["entity"]
                        if isinstance(spec, dict) and "fn" in spec:
                            lines.append(("?", b""))
                        else:
                            lines.append(reference_line(builder, spec, True))
    return lines


def check(out: Path, carriers: list[Path]) -> int:
    executable, target = out / "resolve.exe", out / "resolve-listing.txt"
    good = True
    for carrier in carriers:
        target.unlink(missing_ok=True)
        result = subprocess.run([str(executable), str(carrier), str(target)],
                                capture_output=True, text=True)
        produced = target.read_text(encoding="ascii").splitlines() if target.exists() else []
        expected = expected_lines(json.loads(carrier.read_text(encoding="ascii")))
        resolved = sum(1 for line, _cid in expected if line != "?")
        deferred = len(expected) - resolved
        if result.returncode != 0 or len(produced) != len(expected):
            good = False
            print(f"carrier   {carrier.name:26} exit={result.returncode} lines={len(produced)}/{len(expected)} DIFF")
            if result.stderr.strip():
                print(f"          {result.stderr.strip()[:200]}")
            continue
        wrong = [index for index, (got, (want, _cid)) in enumerate(zip(produced, expected)) if got != want]
        if not wrong:
            # identity, not text: hash what the program wrote and compare the object's CID
            wrong = [index for index, (got, (_want, cid)) in enumerate(zip(produced, expected))
                     if got != "?" and object_of(got).cid != cid]
        good = good and not wrong
        if wrong:
            index = wrong[0]
            print(f"carrier   {carrier.name:26} exit=0 lines={len(produced)} resolved={resolved} "
                  f"deferred={deferred} DIFF at {wrong[:3]}")
            print(f"          got  {produced[index][:120]}")
            print(f"          want {expected[index][0][:120]}")
        else:
            print(f"carrier   {carrier.name:26} exit=0 lines={len(produced)} resolved={resolved} "
                  f"deferred={deferred} MATCH")
    return 0 if good else 1


def main(argv):
    out = Path(argv[1])
    carriers = [Path(item) for item in argv[2:] if not item.startswith("--")]
    store, snapshot, artifact = build_resolver()
    out.mkdir(parents=True, exist_ok=True)
    (out / "resolve.xax").write_bytes(store.canonical_bytes())
    (out / "resolve-snapshot.xax").write_bytes(snapshot.canonical_bytes())
    (out / "resolve.exe").write_bytes(artifact.artifact)
    entry = next(item for item in store.objects() if item.kind == Kind.FUNCTION)
    print(f"entry     {store.root_cid.hex()}")
    print(f"entry fn  {entry.cid.hex()}")
    print(f"store     {len(store.canonical_bytes())} bytes")
    print(f"artifact  {len(artifact.artifact)} bytes")
    print(f"namespace {len(TABLE)} bytes, {len(namespace_entries())} entries")
    if "--check" in argv:
        return check(out, carriers)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
