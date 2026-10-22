"""S15e.5 (ADR-327): ``xax_jvm``'s class file and JAR container as XAX functions.

Byte buffers are records ``[data, length, capacity]`` in the arena, one byte per word.  The constant pool
(``_Pool``) keeps its entries' bytes in one buffer and, per pool index, the entry's place there; an entry is found
again by its bytes (equal keys give equal bytes: the tag and the indices it names fix them).  Per index it also keeps
what ``_operand_stack_depth`` reads from the entry: a method's argument and result slots, a field's size.  The class
file (``_class_file``, ``_serialize_method``) and the deterministic stored JAR (``_jar``: the manifest, then the
class, CRC-32 over each, the 1980-01-01 date) are written byte for byte as the bootstrap writes them.
"""

from __future__ import annotations

from xax_selfhost_facts import E, NONE, _function
from xax_selfhost_views_backend import _call, _ok

BUF_WORDS = 3  # data, length, capacity
B_DATA, B_LEN, B_CAP = range(3)
POOL_CAP = 1 << 16  # pool indices
# Pool record: the bytes buffer, the next index, per index the entry start and length in the bytes, its argument slots
# (a method: parameters, plus the receiver for an instance call is the caller's), result slots, and field size.
(P_BYTES, P_COUNT, P_START, P_LENGTH, P_ARGS, P_RESULT, P_FIELD, P_SCRATCH) = range(8)
POOL_WORDS = 8
CRC_POLY = 0xEDB88320


def _bx(e: E, x, y):
    from xax_compiler import Operation

    return e.bin(Operation.BIT_XOR, x, y)


# -- buffers ------------------------------------------------------------------------------------------------------

def buffer(e: E, name: str, capacity):
    """A new buffer record into ``name`` (NONE: the arena is exhausted, the caller declines)."""
    p = e.p
    e.var(name, e.alloc(BUF_WORDS))
    _ok(e, e.ne(p[name], NONE))
    e.var(f"{name}_d", e.alloc(capacity))
    _ok(e, e.ne(p[f"{name}_d"], NONE))
    e.st(e.add(p[name], B_DATA), p[f"{name}_d"])
    e.st(e.add(p[name], B_LEN), 0)
    e.st(e.add(p[name], B_CAP), capacity)
    return p[name]


def blen(e: E, buf):
    return e.ld(e.add(buf, B_LEN))


def bdata(e: E, buf):
    return e.ld(e.add(buf, B_DATA))


def bat(e: E, buf, index):
    return e.ld(e.add(bdata(e, buf), index))


def _put_fn(tables):
    """``put(buf, word, n)``: the ``n`` bytes of ``word``, most significant first (the class file is big endian)."""
    def build(e: E):
        p = e.p
        e.var("bp_len", blen(e, p["buf"]))
        _ok(e, e.le(e.add(p["bp_len"], p["n"]), e.ld(e.add(p["buf"], B_CAP))))
        e.var("bp_w", p["word"])
        e.var("bp_k", p["n"])
        e.while_(lambda: e.lt(0, p["bp_k"]), lambda: (
            e.set("bp_k", e.sub(p["bp_k"], 1)),
            e.st(e.add(bdata(e, p["buf"]), e.add(p["bp_len"], p["bp_k"])), e.and_(p["bp_w"], 255)),
            e.set("bp_w", e.udiv(p["bp_w"], 256))))
        e.st(e.add(p["buf"], B_LEN), e.add(p["bp_len"], p["n"]))
        e.give(1)
    return _function(("buf", "word", "n"), build, tables)


def _le_fn(tables):
    """``le(buf, word, n)``: the ``n`` bytes of ``word``, least significant first (the ZIP container)."""
    def build(e: E):
        p = e.p
        e.var("bl_len", blen(e, p["buf"]))
        _ok(e, e.le(e.add(p["bl_len"], p["n"]), e.ld(e.add(p["buf"], B_CAP))))
        e.var("bl_w", p["word"])
        e.for_("bl_k", 0, p["n"], lambda: (e.st(e.add(bdata(e, p["buf"]), e.add(p["bl_len"], p["bl_k"])), e.and_(p["bl_w"], 255)),
                                           e.set("bl_w", e.udiv(p["bl_w"], 256))))
        e.st(e.add(p["buf"], B_LEN), e.add(p["bl_len"], p["n"]))
        e.give(1)
    return _function(("buf", "word", "n"), build, tables)


def _append_fn(tables):
    """``append(buf, data, n)``: ``n`` bytes (one per word) from ``data``."""
    def build(e: E):
        p = e.p
        e.var("ba_len", blen(e, p["buf"]))
        _ok(e, e.le(e.add(p["ba_len"], p["n"]), e.ld(e.add(p["buf"], B_CAP))))
        e.var("ba_to", e.add(bdata(e, p["buf"]), p["ba_len"]))
        e.for_("ba_k", 0, p["n"], lambda: e.st(e.add(p["ba_to"], p["ba_k"]), e.ld(e.add(p["data"], p["ba_k"]))))
        e.st(e.add(p["buf"], B_LEN), e.add(p["ba_len"], p["n"]))
        e.give(1)
    return _function(("buf", "data", "n"), build, tables)


def put(e: E, buf, word, n: int):
    _call(e, "jb_put", buf, word, n)


def u1(e: E, buf, word):
    put(e, buf, word, 1)


def u2(e: E, buf, word):
    put(e, buf, word, 2)


def u4(e: E, buf, word):
    put(e, buf, e.and_(word, 0xFFFFFFFF), 4)


def le(e: E, buf, word, n: int):
    _call(e, "jb_le", buf, word, n)


def append(e: E, buf, data, n):
    _call(e, "jb_append", buf, data, n)


def append_buf(e: E, buf, other):
    append(e, buf, bdata(e, other), blen(e, other))


def text(e: E, buf, value: str):
    """Literal ASCII text into ``buf``."""
    for start in range(0, len(value), 8):
        chunk = value[start:start + 8].encode("ascii")
        put(e, buf, int.from_bytes(chunk, "big"), len(chunk))


# -- CRC-32 (zlib's, reflected 0xEDB88320) --------------------------------------------------------------------------

def _crc_fn(tables):
    """``crc(data, n)``: CRC-32 of ``n`` bytes (one per word)."""
    def build(e: E):
        p = e.p
        e.var("cr_c", 0xFFFFFFFF)

        def byte():
            e.set("cr_c", _bx(e, p["cr_c"], e.ld(e.add(p["data"], p["cr_k"]))))

            def bit():
                e.var("cr_low", e.and_(p["cr_c"], 1))
                e.set("cr_c", e.udiv(p["cr_c"], 2))
                e.if_(e.ne(p["cr_low"], 0), lambda: e.set("cr_c", _bx(e, p["cr_c"], CRC_POLY)))

            e.for_("cr_b", 0, 8, bit)

        e.for_("cr_k", 0, p["n"], byte)
        e.give(_bx(e, p["cr_c"], 0xFFFFFFFF))
    return _function(("data", "n"), build, tables)


# -- the constant pool ----------------------------------------------------------------------------------------------

def _pf(e: E, pool, field: int):
    return e.ld(e.add(pool, field))


def pool_new(e: E, name: str):
    """A new pool record into ``name``: index 1 is the first entry."""
    p = e.p
    e.var(name, e.alloc(POOL_WORDS))
    _ok(e, e.ne(p[name], NONE))
    buffer(e, f"{name}_b", 1 << 20)
    e.st(e.add(p[name], P_BYTES), p[f"{name}_b"])
    e.st(e.add(p[name], P_COUNT), 1)
    for field in (P_START, P_LENGTH, P_ARGS, P_RESULT, P_FIELD):
        e.var(f"{name}_t", e.alloc(POOL_CAP + 2))
        _ok(e, e.ne(p[f"{name}_t"], NONE))
        e.st(e.add(p[name], field), p[f"{name}_t"])
    buffer(e, f"{name}_s", 1 << 16)
    e.st(e.add(p[name], P_SCRATCH), p[f"{name}_s"])
    return p[name]


def _pool_add_fn(tables):
    """``pool_add(pool, slots)``: the index of the entry whose bytes are the pool's scratch buffer (an existing equal
    entry, else a new one taking ``slots`` indices; JVM-CONSTANT-POOL-SIZE past 65535: declined)."""
    def build(e: E):
        p = e.p
        pool = p["pool"]
        e.var("pa_s", _pf(e, pool, P_SCRATCH))
        e.var("pa_n", blen(e, p["pa_s"]))
        e.var("pa_bytes", _pf(e, pool, P_BYTES))
        e.var("pa_found", NONE)

        def candidate():
            e.var("pa_len", e.ld(e.add(_pf(e, pool, P_LENGTH), p["pa_i"])))

            def compare():
                e.var("pa_at", e.add(bdata(e, p["pa_bytes"]), e.ld(e.add(_pf(e, pool, P_START), p["pa_i"]))))
                e.var("pa_same", 1)
                e.for_("pa_k", 0, p["pa_n"], lambda: e.if_(e.ne(e.ld(e.add(p["pa_at"], p["pa_k"])), bat(e, p["pa_s"], p["pa_k"])),
                                                         lambda: e.set("pa_same", 0)))
                e.if_(e.ne(p["pa_same"], 0), lambda: e.set("pa_found", p["pa_i"]))

            e.if_(e.both(e.eq(p["pa_found"], NONE), e.eq(p["pa_len"], p["pa_n"])), compare)

        e.for_("pa_i", 1, _pf(e, pool, P_COUNT), candidate)
        e.if_(e.ne(p["pa_found"], NONE), lambda: e.give(p["pa_found"]))
        e.var("pa_index", _pf(e, pool, P_COUNT))
        _ok(e, e.le(e.add(p["pa_index"], p["slots"]), 0xFFFF + 1))  # the bootstrap's JVM-CONSTANT-POOL-SIZE
        e.st(e.add(_pf(e, pool, P_START), p["pa_index"]), blen(e, p["pa_bytes"]))
        e.st(e.add(_pf(e, pool, P_LENGTH), p["pa_index"]), p["pa_n"])
        e.if_(e.eq(p["slots"], 2), lambda: e.st(e.add(_pf(e, pool, P_LENGTH), e.add(p["pa_index"], 1)), NONE))
        append_buf(e, p["pa_bytes"], p["pa_s"])
        e.st(e.add(pool, P_COUNT), e.add(p["pa_index"], p["slots"]))
        e.give(p["pa_index"])
    return _function(("pool", "slots"), build, tables)


def scratch(e: E, pool):
    """The pool's scratch buffer, emptied."""
    s = _pf(e, pool, P_SCRATCH)
    e.st(e.add(s, B_LEN), 0)
    return s


def pool_add(e: E, pool, slots: int = 1):
    return _call(e, "jp_add", pool, slots)


def _utf8_fn(tables):
    """``utf8(pool, data, n)``: CONSTANT_Utf8 of ``n`` ASCII bytes."""
    def build(e: E):
        p = e.p
        e.var("pu_s", scratch(e, p["pool"]))
        u1(e, p["pu_s"], 1)
        u2(e, p["pu_s"], p["n"])
        append(e, p["pu_s"], p["data"], p["n"])
        e.give(pool_add(e, p["pool"]))
    return _function(("pool", "data", "n"), build, tables)


def _ref1_fn(tables):
    """``ref1(pool, tag, index)``: a one-reference entry (Class 7, String 8)."""
    def build(e: E):
        p = e.p
        e.var("pr_s", scratch(e, p["pool"]))
        u1(e, p["pr_s"], p["tag"])
        u2(e, p["pr_s"], p["index"])
        e.give(pool_add(e, p["pool"]))
    return _function(("pool", "tag", "index"), build, tables)


def _ref2_fn(tables):
    """``ref2(pool, tag, first, second, args, result)``: NameAndType (12), Fieldref (9), Methodref (10),
    InterfaceMethodref (11); a member's stack effect is recorded under its index."""
    def build(e: E):
        p = e.p
        e.var("p2_s", scratch(e, p["pool"]))
        u1(e, p["p2_s"], p["tag"])
        u2(e, p["p2_s"], p["first"])
        u2(e, p["p2_s"], p["second"])
        e.var("p2_i", pool_add(e, p["pool"]))
        e.st(e.add(_pf(e, p["pool"], P_ARGS), p["p2_i"]), p["args"])
        e.st(e.add(_pf(e, p["pool"], P_RESULT), p["p2_i"]), p["result"])
        e.give(p["p2_i"])
    return _function(("pool", "tag", "first", "second", "args", "result"), build, tables)


def _number_fn(tables):
    """``number(pool, tag, value)``: Integer (3) and Float (4) take one index and 4 bytes, Long (5) and Double (6)
    two and 8."""
    def build(e: E):
        p = e.p
        e.var("pn_s", scratch(e, p["pool"]))
        e.var("pn_wide", e.flag(e.le(5, p["tag"])))
        u1(e, p["pn_s"], p["tag"])
        e.if_(e.ne(p["pn_wide"], 0), lambda: put(e, p["pn_s"], p["value"], 8), lambda: u4(e, p["pn_s"], p["value"]))
        e.if_(e.ne(p["pn_wide"], 0), lambda: e.give(_call(e, "jp_add", p["pool"], 2)))
        e.give(_call(e, "jp_add", p["pool"], 1))
    return _function(("pool", "tag", "value"), build, tables)


# -- texts ----------------------------------------------------------------------------------------------------------

def literal(e: E, name: str, value: str):
    """A byte array holding ``value`` into ``name`` and ``name_n``."""
    p = e.p
    e.var(name, e.alloc(len(value) + 1))
    _ok(e, e.ne(p[name], NONE))
    for k, ch in enumerate(value.encode("ascii")):
        e.st(e.add(p[name], k), ch)
    e.var(f"{name}_n", len(value))


def utf8_literal(e: E, pool, value: str, name: str):
    literal(e, f"{name}_t", value)
    return _call(e, "jp_utf8", pool, e.p[f"{name}_t"], len(value))


def klass_literal(e: E, pool, value: str, name: str):
    return _call(e, "jp_ref1", pool, 7, utf8_literal(e, pool, value, name))


def method_literal(e: E, pool, owner: str, member: str, descriptor: str, name: str, interface: bool = False):
    """A Methodref (or InterfaceMethodref) to a fixed member."""
    from xax_jvm import _descriptor_slots

    args, result = _descriptor_slots(descriptor)
    p = e.p
    e.var(f"{name}_c", klass_literal(e, pool, owner, f"{name}_o"))
    e.var(f"{name}_n", utf8_literal(e, pool, member, f"{name}_m"))
    e.var(f"{name}_d", utf8_literal(e, pool, descriptor, f"{name}_s"))
    e.var(f"{name}_nt", _call(e, "jp_ref2", pool, 12, p[f"{name}_n"], p[f"{name}_d"], 0, 0))
    return _call(e, "jp_ref2", pool, 11 if interface else 10, p[f"{name}_c"], p[f"{name}_nt"], args, result)


def add_class_functions(add, tables):
    for name, builder in (("jb_put", _put_fn), ("jb_le", _le_fn), ("jb_append", _append_fn), ("jb_crc", _crc_fn), ("jp_add", _pool_add_fn),
                          ("jp_utf8", _utf8_fn), ("jp_ref1", _ref1_fn), ("jp_ref2", _ref2_fn), ("jp_number", _number_fn)):
        add(name, builder(tables))
