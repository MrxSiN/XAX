"""Self-hosting step S15e.4 (ADR-322): the browser page's WebAssembly module and page written by the general program.

``xax_build.build`` makes the artifact of a ``wasm32-browser-v1`` target (architecture 2) with
``xax_wasm.compile_wasm_bound_target`` (its general profile: ``_function_closure``, the foreign carriers, the event
entries, ``_memory_layout``, the command container, ``_compile_function`` per function in CID order) and
``xax_web.emit_browser_page``.  The general x86-64 program takes this path for such a target
(``xax_selfhost_request.PATH_WASM_PAGE``): ``wasm`` decides the same rejections in the same order (``WASM-ABI-VALUE``,
``WASM-OP-TARGET-SUPPORTED``, ``WASM-FUNCTION-ADDRESS-EVENT-ENTRY``, ``WASM-TERMINATOR-TARGET-SUPPORTED``,
``WASM-REENTRANT-FRAME``, ``WASM-FOREIGN-ABI``, ``ABI-LAYOUT-VALUE-TYPE``, ``WASM-STATIC-MEMORY-LIMIT``,
``WASI-START-NO-MACHINE-VALUES``, the lowering's own, ``WEB-IMPORT-DECLARED``) and writes the page, byte for byte, as
the image record's container bytes.  Aggregate layouts are ``abi_layout``'s with 4-byte pointers (``W_ON``).  Values
the bootstrap would turn into an invalid module or a host exception (bits wider than 64, non-power-of-two
alignments, 32-bit immediates outside 32 bits, non-ASCII names) and capacities past the program's buffers decline.
"""

from __future__ import annotations

from xax_compiler import Kind, Operation, WASM32_BROWSER_EVENT_ABI, WASM32_BROWSER_IDENTITY, WASM32_WASI_IDENTITY
import xax_selfhost_diagnostics as D
from xax_selfhost_facts import E, NONE, _function
from xax_selfhost_views_backend import (
    GLOBALS, G_NI, G_O, G_PAY, G_SUP, G_SUP_AT, G_SUPT, G_SUPT_AT, NI_ATTRIBUTES, NI_ENTITY, NI_OP, NI_OPERANDS, NI_RESULTS,
    _FOREIGN_PREFIX, _at, _call, _cid_at, _cid_less, _cid_words, _g, _kind, _ok, _payload_uleb, _reference, _sar, _signed_lt,
    _target_list, _type_form,
)

WA = GLOBALS + 192
(W_ON, W_F, W_G, W_B, W_ENTRY, W_BLK, W_NODE, W_NV, W_VAL, W_IDS, W_IFACE, W_FUNCS, W_NF, W_FIDX, W_ACT, W_DONE, W_REC,
 W_STACK, W_DEPTH, W_CARR, W_NCARR, W_IMPIDX, W_EVT, W_EVL, W_NEVT, W_CURSOR, W_LOC, W_NLOC, W_PC, W_SCR, W_CUR, W_SIGS,
 W_NSIGS, W_TYIDX, W_IMPTY, W_SPAN, W_EF, W_THR, W_KIND) = (WA + k for k in range(39))
PAGE_KIND, COMMAND_KIND, PLAIN_KIND = 0, 1, 2  # ``W_KIND``: the browser page, a WASI command module, a plain core module (S15f.1)
# S15f.3 (ADR-324): 1 for a target off the general profile (``xax_wasm_legacy``: bits values only, static stack addresses);
# ``W_MEM``: the laid-out static memory's size.
W_LEG = WA + 39
W_MEM = WA + 60
BUF = WA + 40  # buffers: base, length, capacity
CODE, BODIES, MODULE, PART, PAGE = (BUF + 3 * k for k in range(5))
assert PAGE + 3 <= GLOBALS + 256
CAPS = {CODE: 1 << 18, BODIES: 1 << 20, MODULE: 1 << 20, PART: 1 << 20, PAGE: 1 << 21}
SIG_CAP = 1 << 16
VAL_W = 9
(V_TYPE, V_SLOT, V_TEMP, V_EXT, V_EXTK, V_ADDR, V_BLK, V_IDX, V_RES) = range(VAL_W)
NODE_W = 10
(N_OP, N_OPB, N_NOP, N_RES, N_ATTR, N_ENT, N_RBASE, N_NRES, N_SADDR, N_AT) = range(NODE_W)
BLK_W = 14
(B_PAT, B_PBASE, B_NP, B_NBASE, B_NN, B_TERM, B_TK, B_TC, B_T0, B_T0B, B_T0N, B_T1, B_T1B, B_T1N) = range(BLK_W)
FRAME_W = 4  # function, stream cursor, blocks left, nodes left (NONE: at a block's start)
(F_FN, F_AT, F_BL, F_NL) = range(FRAME_W)
I32, I64, F32, F64 = 0x7F, 0x7E, 0x7D, 0x7C
AGGREGATES = (8, 9, 10)
NULL_GUARD = 16
MEMORY_LIMIT = 65536
EVENT_IDENTITY = b"code-entry:" + WASM32_BROWSER_EVENT_ABI
IMPORT_ABI = b"wasm32-import"
# ``xax_web``: the library, the declared bindings (sorted, as ``WEB-IMPORT-DECLARED`` lists them) and their host code.
from xax_web import WEB_LIBRARY, _HOST  # noqa: E402

DECLARED = tuple(sorted(_HOST))
LOAD = {(32, 1): 0x2D, (32, 2): 0x2F, (32, 4): 0x28, (64, 1): 0x31, (64, 2): 0x33, (64, 4): 0x35, (64, 8): 0x29}
STORE = {(32, 1): 0x3A, (32, 2): 0x3B, (32, 4): 0x36, (64, 1): 0x3C, (64, 2): 0x3D, (64, 4): 0x3E, (64, 8): 0x37}
BITWISE = {Operation.BIT_AND: (0x71, 0x83), Operation.BIT_OR: (0x72, 0x84), Operation.BIT_XOR: (0x73, 0x85),
           Operation.UDIV: (0x6E, 0x80), Operation.UREM: (0x70, 0x82)}
INT_COMPARE32 = {1: 0x46, 2: 0x47, 7: 0x48, 3: 0x49, 9: 0x4A, 5: 0x4B, 8: 0x4C, 4: 0x4D, 10: 0x4E, 6: 0x4F}  # IntCompare
SIGNED_COMPARES = (7, 8, 9, 10)
FLOAT_COMPARE = {1: 0, 2: 1, 3: 2, 5: 3, 4: 4, 6: 5}  # FloatCompare -> offset from eq
TO_FLOAT = {(32, 32, 1): 0xB2, (32, 32, 0): 0xB3, (64, 32, 1): 0xB4, (64, 32, 0): 0xB5,
            (32, 64, 1): 0xB7, (32, 64, 0): 0xB8, (64, 64, 1): 0xB9, (64, 64, 0): 0xBA}
TRUNC = {(32, 32, 1): 0xA8, (32, 32, 0): 0xA9, (64, 32, 1): 0xAA, (64, 32, 0): 0xAB,
         (32, 64, 1): 0xAE, (32, 64, 0): 0xAF, (64, 64, 1): 0xB0, (64, 64, 0): 0xB1}


# -- small helpers --------------------------------------------------------------------------------

def _rec(e: E, table_slot, index, width, field):
    return e.ld(e.add(e.add(e.ld(table_slot), e.mul(index, width)), field))


def _set_rec(e: E, table_slot, index, width, field, value):
    e.st(e.add(e.add(e.ld(table_slot), e.mul(index, width)), field), value)


def _blk(e: E, b, field):
    return _rec(e, W_BLK, b, BLK_W, field)


def _node(e: E, k, field):
    return _rec(e, W_NODE, k, NODE_W, field)


def _val(e: E, v, field):
    return _rec(e, W_VAL, v, VAL_W, field)


def _set_val(e: E, v, field, value):
    _set_rec(e, W_VAL, v, VAL_W, field, value)


def _obj(e: E, slot, o):
    """Per-object table ``slot`` at object ``o``."""
    return e.ld(e.add(e.ld(slot), o))


def _set_obj(e: E, slot, o, value):
    e.st(e.add(e.ld(slot), o), value)


def _list(e: E, slot, k):
    return e.ld(e.add(e.ld(slot), k))


def _op_id(e: E, k, q):
    return e.ld(e.add(e.ld(W_IDS), e.add(_node(e, k, N_OPB), q)))


def _attr(e: E, k, q):
    return e.rd(e.add(_node(e, k, N_ATTR), e.add(q, 1)))


def _proof(e: E, t):
    form = _type_form(e, t)
    return e.either(e.eq(form, 3), e.eq(form, 4))


def _bits_width(e: E, t, name: str):
    """``decode_bits_width`` (a verified bits type) into ``name``."""
    e.var(f"{name}_at", e.add(_at(e, G_PAY, t), 1))
    e.var(name, _payload_uleb(e, f"{name}_at"))
    return e.p[name]


def _float_width(e: E, t):
    return e.sel(e.eq(e.rd(e.add(_at(e, G_PAY, t), 1)), 1), 32, 64)


def _width(e: E, t, name: str):
    """``_width``: bits and float widths, 32 for pointers, links and aggregates, NONE otherwise."""
    p = e.p
    e.var(f"{name}_f", _type_form(e, t))
    e.var(name, NONE)
    e.if_(e.eq(p[f"{name}_f"], 1), lambda: e.set(name, _bits_width(e, t, f"{name}_b")))
    e.if_(e.eq(p[f"{name}_f"], 7), lambda: e.set(name, _float_width(e, t)))
    e.if_(e.either(*(e.eq(p[f"{name}_f"], f) for f in (2, 11, 8, 9, 10))), lambda: e.set(name, 32))
    return p[name]


def _valtype(e: E, t, name: str):
    """``_valtype_for_cid``: the value type byte, 0 for none."""
    p = e.p
    e.var(f"{name}_f", _type_form(e, t))
    e.var(name, 0)
    e.if_(e.eq(p[f"{name}_f"], 1), lambda: e.set(name, e.sel(e.le(_bits_width(e, t, f"{name}_b"), 32), I32, I64)))
    e.if_(e.eq(p[f"{name}_f"], 7), lambda: e.set(name, e.sel(e.eq(_float_width(e, t), 32), F32, F64)))
    e.if_(e.either(*(e.eq(p[f"{name}_f"], f) for f in (2, 8, 9, 10, 11))), lambda: e.set(name, I32))
    return p[name]


def _slot_type(e: E, t, name: str):
    """The value type a value's local takes: ``_valtype``, or on the legacy lowering a ``bits`` value's alone."""
    p = e.p
    e.var(name, _valtype(e, t, f"{name}_g"))
    e.if_(e.both(e.ne(e.ld(W_LEG), 0), e.ne(_type_form(e, t), 1)), lambda: e.set(name, 0))
    return p[name]


def _aggregate(e: E, t):
    form = _type_form(e, t)
    return e.either(*(e.eq(form, f) for f in AGGREGATES))


def _log2(e: E, value, name: str):
    """``int(log2(value))`` of a power of two (declines otherwise)."""
    p = e.p
    _ok(e, e.power_of_two(value))
    e.var(f"{name}_v", value)
    e.var(name, 0)
    e.while_(lambda: e.lt(1, p[f"{name}_v"]), lambda: (e.set(f"{name}_v", e.udiv(p[f"{name}_v"], 2)), e.set(name, e.add(p[name], 1))))
    return p[name]


def _table(e: E, key_conditions):
    """The value of the first ``(condition, value)`` pair whose condition holds, else 0."""
    result = e.c(0)
    for condition, value in reversed(key_conditions):
        result = e.sel(condition, value, result)
    return result


def _graph_cid(e: E):
    D.cid(e, _cid_words(e, e.ld(W_G)))


def _reject(e: E, code: str, subject, rule: str, expected, actual):
    """Write the record unconditionally (the caller is on the rejecting path) and give NONE."""
    def write():
        D.text(e, code)
        subject()
        D.text(e, rule)
        expected()
        actual()
    D.reject_unless(e, e.eq(1, 0), write)


def _int_list(e: E, values):
    D.put(e, D.T_LIST)
    D.put(e, len(values))
    for value in values:
        D.integer(e, value)


# -- byte buffers: the current one is ``W_CUR``'s ------------------------------------------------

def _use(e: E, buf):
    e.st(W_CUR, buf)


def _b(e: E, byte):
    _call(e, "wa_b", byte)


def _bytes(e: E, data: bytes):
    for start in range(0, len(data), 7):
        chunk = data[start:start + 7]
        _call(e, "wa_bs", int.from_bytes(chunk, "little"), len(chunk))


def _u(e: E, value):
    _call(e, "wa_u", value)


def _iconst(e: E, value, wide):
    _call(e, "wa_i", value, wide)


def _get(e: E, v):
    _call(e, "wa_get", v)


def _set_local(e: E, v):
    _call(e, "wa_set", v)


def _local(e: E, opcode: int, index):
    _b(e, opcode)
    _u(e, index)


def _wa_b(tables):
    def build(e: E):
        p = e.p
        e.var("bb", e.ld(W_CUR))
        e.var("bn", e.ld(e.add(p["bb"], 1)))
        _ok(e, e.lt(p["bn"], e.ld(e.add(p["bb"], 2))))
        e.st(e.add(e.ld(p["bb"]), p["bn"]), e.and_(p["bx"], 255))
        e.st(e.add(p["bb"], 1), e.add(p["bn"], 1))
        e.give(1)
    return _function(("bx",), build, tables)


def _wa_bs(tables):
    def build(e: E):
        p = e.p
        e.var("bsv", p["bsx"])
        e.for_("bsk", 0, p["bsn"], lambda: (_b(e, e.and_(p["bsv"], 255)), e.set("bsv", e.udiv(p["bsv"], 256))))
        e.give(1)
    return _function(("bsx", "bsn"), build, tables)


def _wa_u(tables):
    def build(e: E):
        p = e.p
        e.var("uv", p["ux"])
        e.var("umore", 1)

        def step():
            e.var("ubyte", e.and_(p["uv"], 127))
            e.set("uv", e.udiv(p["uv"], 128))
            e.if_(e.eq(p["uv"], 0), lambda: e.set("umore", 0), lambda: e.set("ubyte", e.or_(p["ubyte"], 128)))
            _b(e, p["ubyte"])

        e.while_(lambda: e.ne(p["umore"], 0), step)
        e.give(1)
    return _function(("ux",), build, tables)


def _wa_s(tables):
    """``_sleb`` of a two's-complement 64-bit word."""
    def build(e: E):
        p = e.p
        e.var("sv", p["sx"])
        e.var("smore", 1)

        def step():
            e.var("sbyte", e.and_(p["sv"], 127))
            e.set("sv", _sar(e, p["sv"], 7))
            sign = e.ne(e.and_(p["sbyte"], 0x40), 0)
            done = e.either(e.both(e.eq(p["sv"], 0), e.not_(sign)), e.both(e.eq(p["sv"], e.c(-1)), sign))
            e.if_(done, lambda: e.set("smore", 0), lambda: e.set("sbyte", e.or_(p["sbyte"], 128)))
            _b(e, p["sbyte"])

        e.while_(lambda: e.ne(p["smore"], 0), step)
        e.give(1)
    return _function(("sx",), build, tables)


def _wa_i(tables):
    """``iconst``: ``i32.const`` of a value below 2**32 (as signed), or ``i64.const`` of a word."""
    def build(e: E):
        p = e.p

        def narrow():
            _ok(e, e.lt(p["ix"], 1 << 32))
            _b(e, 0x41)
            _call(e, "wa_s", e.sel(e.lt(p["ix"], 1 << 31), p["ix"], e.sub(p["ix"], 1 << 32)))

        def wide():
            _b(e, 0x42)
            _call(e, "wa_s", p["ix"])

        e.if_(e.eq(p["iw"], 0), narrow, wide)
        e.give(1)
    return _function(("ix", "iw"), build, tables)


def _wa_get(tables):
    def build(e: E):
        p = e.p
        e.var("gs", _val(e, p["gv"], V_SLOT))

        def missing():
            def actual():
                D.put(e, D.T_LIST)
                D.put(e, 3)
                for field in (V_BLK, V_IDX, V_RES):
                    D.integer(e, _val(e, p["gv"], field))
            e.if_(e.ne(e.ld(W_LEG), 0), lambda: _reject(e, "XAX.WASM.VALUE", lambda: _graph_cid(e), "WASM-VALUE-MACHINE-BITS",
                                                        lambda: D.text(e, "bits value"), actual))
            _reject(e, "XAX.WASM.VALUE", lambda: _graph_cid(e), "WASM-VALUE-MACHINE", lambda: D.text(e, "machine value"), actual)

        e.if_(e.eq(p["gs"], NONE), missing)
        _local(e, 0x20, p["gs"])
        e.give(1)
    return _function(("gv",), build, tables)


def _wa_set(tables):
    def build(e: E):
        p = e.p
        e.var("ss", _val(e, p["sv2"], V_SLOT))
        _ok(e, e.ne(p["ss"], NONE))
        _local(e, 0x21, p["ss"])
        e.give(1)
    return _function(("sv2",), build, tables)


def _wa_mask(tables):
    def build(e: E):
        p = e.p
        _ok(e, e.both(e.ne(p["mw"], 0), e.le(p["mw"], 64)))
        e.if_(e.both(e.ne(p["mw"], 32), e.ne(p["mw"], 64)), lambda: (
            _iconst(e, e.sub(e.sel(e.lt(p["mw"], 64), e.mul(1, _pow2(e, p["mw"])), 0), 1), e.flag(e.lt(32, p["mw"]))),
            _b(e, e.sel(e.le(p["mw"], 32), 0x71, 0x83))))
        e.give(1)
    return _function(("mw",), build, tables)


def _pow2(e: E, n):
    """``1 << n`` for ``n`` below 64 (a loop-free square-and-multiply over the six bits)."""
    result = e.c(1)
    for bit in range(6):
        result = e.mul(result, e.sel(e.ne(e.and_(n, 1 << bit), 0), 1 << (1 << bit), 1))
    return result


def _wa_gi(tables):
    """``get_integer(value, width, signed)``: ``gk`` = width * 2 + signed."""
    def build(e: E):
        p = e.p
        e.var("giw", e.udiv(p["gk"], 2))
        _ok(e, e.both(e.ne(p["giw"], 0), e.le(p["giw"], 64)))
        _get(e, p["gval"])
        e.var("giwide", e.flag(e.lt(32, p["giw"])))
        e.var("gist", e.sel(e.ne(p["giwide"], 0), 64, 32))

        def extend():
            e.var("gishift", e.sub(p["gist"], p["giw"]))
            _iconst(e, p["gishift"], p["giwide"])
            _b(e, e.sel(e.ne(p["giwide"], 0), 0x86, 0x74))
            _iconst(e, p["gishift"], p["giwide"])
            _b(e, e.sel(e.ne(p["giwide"], 0), 0x87, 0x75))

        e.if_(e.both(e.ne(e.and_(p["gk"], 1), 0), e.ne(p["giw"], p["gist"])), extend)
        e.give(1)
    return _function(("gval", "gk"), build, tables)


def _mask(e: E, width):
    _call(e, "wa_mask", width)


# -- the function index ----------------------------------------------------------------------------

def _vid(e: E, at):
    """The value id of the reference at stream position ``at`` (tag, block, index[, result])."""
    tag, block, index = e.rd(at), e.rd(e.add(at, 1)), e.rd(e.add(at, 2))
    param = e.add(_blk(e, block, B_PBASE), index)
    result = e.add(_node(e, e.add(_blk(e, block, B_NBASE), index), N_RBASE), e.rd(e.add(at, 3)))
    return e.sel(e.eq(tag, 0), param, result)


def _ref_size(e: E, at):
    return e.add(3, e.flag(e.eq(e.rd(at), 1)))


def _wa_index(tables):
    """Function ``xf``'s graph: blocks, nodes, values (type, origin) and the operand and terminator value ids."""
    def build(e: E):
        p = e.p
        e.st(W_F, p["xf"])
        e.var("xi", _call(e, "interface", p["xf"]))
        e.st(W_IFACE, p["xi"])
        e.var("xg", e.ld(p["xi"]))
        e.st(W_G, p["xg"])
        e.var("xs", _at(e, G_PAY, p["xg"]))
        e.var("xB", e.rd(p["xs"]))
        e.st(W_B, p["xB"])
        e.st(W_ENTRY, e.rd(e.add(p["xs"], 1)))
        _ok(e, e.lt(p["xB"], 1 << 16))
        e.var("xblk", e.alloc(e.add(e.mul(p["xB"], BLK_W), 1)))
        _ok(e, e.ne(p["xblk"], NONE))
        e.st(W_BLK, p["xblk"])
        e.var("xat", e.add(p["xs"], 2))
        e.var("xnn", 0)
        e.var("xnv", 0)

        def count_block():
            e.var("xcb", e.add(p["xblk"], e.mul(p["xbk"], BLK_W)))
            e.st(e.add(p["xcb"], B_PAT), p["xat"])
            e.st(e.add(p["xcb"], B_NP), e.rd(p["xat"]))
            e.st(e.add(p["xcb"], B_PBASE), p["xnv"])
            e.set("xnv", e.add(p["xnv"], e.rd(p["xat"])))
            e.set("xat", e.add(e.add(p["xat"], 1), e.rd(p["xat"])))
            e.var("xcn", e.rd(p["xat"]))
            e.st(e.add(p["xcb"], B_NN), p["xcn"])
            e.st(e.add(p["xcb"], B_NBASE), p["xnn"])
            e.set("xat", e.add(p["xat"], 1))

            def count_node():
                e.set("xat", _call(e, "node_info", p["xat"]))
                e.set("xnv", e.add(p["xnv"], e.rd(e.ld(e.add(_g(e, G_NI), NI_RESULTS)))))

            e.for_("xcq", 0, p["xcn"], count_node)
            e.set("xnn", e.add(p["xnn"], p["xcn"]))
            e.st(e.add(p["xcb"], B_TERM), p["xat"])
            e.set("xat", _call(e, "term_end", p["xat"]))

        e.for_("xbk", 0, p["xB"], count_block)
        _ok(e, e.both(e.lt(p["xnn"], 1 << 20), e.lt(p["xnv"], 1 << 20)))
        e.st(W_NV, p["xnv"])
        for slot, words in ((W_NODE, e.mul(e.add(p["xnn"], 1), NODE_W)), (W_VAL, e.mul(e.add(p["xnv"], 1), VAL_W)),
                            (W_IDS, e.add(e.rd(e.sub(p["xs"], 1)), 8))):
            e.var("xalloc", e.alloc(words))
            _ok(e, e.ne(p["xalloc"], NONE))
            e.st(slot, p["xalloc"])

        def fresh(v, block, index, result, type_ref):
            _set_val(e, v, V_TYPE, _reference(e, p["xg"], type_ref))
            for field, value in ((V_SLOT, NONE), (V_TEMP, NONE), (V_EXT, 0), (V_EXTK, 0), (V_ADDR, NONE), (V_BLK, block),
                                 (V_IDX, index), (V_RES, result)):
                _set_val(e, v, field, value)

        def records():
            e.var("ypat", _blk(e, p["ybk"], B_PAT))
            e.var("ypb", _blk(e, p["ybk"], B_PBASE))
            e.for_("ypq", 0, e.rd(p["ypat"]), lambda: fresh(e.add(p["ypb"], p["ypq"]), p["ybk"], p["ypq"], 0,
                                                             e.rd(e.add(e.add(p["ypat"], 1), p["ypq"]))))
            e.var("yat", e.add(e.add(p["ypat"], 1), e.rd(p["ypat"])))
            e.set("yat", e.add(p["yat"], 1))
            e.var("yk", _blk(e, p["ybk"], B_NBASE))
            e.var("yrb", e.add(p["ypb"], e.rd(p["ypat"])))

            def node():
                e.var("ynr", e.add(e.ld(W_NODE), e.mul(p["yk"], NODE_W)))
                e.st(e.add(p["ynr"], N_AT), p["yat"])
                e.set("yat", _call(e, "node_info", p["yat"]))
                ni = _g(e, G_NI)
                e.st(e.add(p["ynr"], N_OP), e.ld(e.add(ni, NI_OP)))
                e.st(e.add(p["ynr"], N_OPB), e.ld(e.add(ni, NI_OPERANDS)))  # the stream position, until the third pass
                e.st(e.add(p["ynr"], N_ATTR), e.ld(e.add(ni, NI_ATTRIBUTES)))
                e.var("yent", e.ld(e.add(ni, NI_ENTITY)))
                e.st(e.add(p["ynr"], N_ENT), e.sel(e.eq(p["yent"], NONE), NONE, _reference(e, p["xg"], e.sel(e.eq(p["yent"], NONE), 0, p["yent"]))))
                e.st(e.add(p["ynr"], N_RBASE), p["yrb"])
                e.var("yres", e.ld(e.add(ni, NI_RESULTS)))
                e.st(e.add(p["ynr"], N_RES), p["yres"])
                e.st(e.add(p["ynr"], N_NRES), e.rd(p["yres"]))
                e.st(e.add(p["ynr"], N_SADDR), NONE)
                e.for_("yrq", 0, e.rd(p["yres"]), lambda: fresh(e.add(p["yrb"], p["yrq"]), p["ybk"], e.sub(p["yk"], _blk(e, p["ybk"], B_NBASE)),
                                                                p["yrq"], e.rd(e.add(e.add(p["yres"], 1), p["yrq"]))))
                e.set("yrb", e.add(p["yrb"], e.rd(p["yres"])))
                e.set("yk", e.add(p["yk"], 1))

            e.for_("yq", 0, _blk(e, p["ybk"], B_NN), node)

        e.for_("ybk", 0, p["xB"], records)
        e.var("zn", 0)  # the next free id word

        def ids(at_name: str, count_field_base=None):
            """Copy ``[count, refs]`` at ``p[at_name]`` into the id array; give (base, count) in ``zb``/``zc``; advance."""
            e.var("zb", p["zn"])
            e.var("zc", e.rd(p[at_name]))
            e.set(at_name, e.add(p[at_name], 1))

            def one():
                e.st(e.add(e.ld(W_IDS), p["zn"]), _vid(e, p[at_name]))
                e.set("zn", e.add(p["zn"], 1))
                e.set(at_name, e.add(p[at_name], _ref_size(e, p[at_name])))

            e.for_("zq", 0, p["zc"], one)

        def operands():
            e.var("zk", _blk(e, p["zbk"], B_NBASE))

            def node():
                e.var("zat", _node(e, e.add(p["zk"], p["zq2"]), N_OPB))
                ids("zat")
                _set_rec(e, W_NODE, e.add(p["zk"], p["zq2"]), NODE_W, N_OPB, p["zb"])
                _set_rec(e, W_NODE, e.add(p["zk"], p["zq2"]), NODE_W, N_NOP, p["zc"])

            e.for_("zq2", 0, _blk(e, p["zbk"], B_NN), node)
            e.var("zt", _blk(e, p["zbk"], B_TERM))
            e.var("ztk", e.rd(p["zt"]))
            e.var("zcb", e.add(p["xblk"], e.mul(p["zbk"], BLK_W)))
            e.st(e.add(p["zcb"], B_TK), p["ztk"])
            e.set("zt", e.add(p["zt"], 1))

            def edge(target_field, base_field, count_field):
                e.st(e.add(p["zcb"], target_field), e.rd(p["zt"]))
                e.set("zt", e.add(p["zt"], 1))
                ids("zt")
                e.st(e.add(p["zcb"], base_field), p["zb"])
                e.st(e.add(p["zcb"], count_field), p["zc"])

            def conditional():
                e.st(e.add(p["zcb"], B_TC), _vid(e, p["zt"]))
                e.set("zt", e.add(p["zt"], _ref_size(e, p["zt"])))
                edge(B_T0, B_T0B, B_T0N)
                edge(B_T1, B_T1B, B_T1N)

            def returning():
                ids("zt")
                e.st(e.add(p["zcb"], B_T0B), p["zb"])
                e.st(e.add(p["zcb"], B_T0N), p["zc"])

            e.if_(e.eq(p["ztk"], 1), lambda: edge(B_T0, B_T0B, B_T0N), lambda: e.if_(
                e.eq(p["ztk"], 2), conditional, lambda: e.if_(e.eq(p["ztk"], 3), returning)))

        e.for_("zbk", 0, p["xB"], operands)
        _ok(e, e.le(p["zn"], e.add(e.rd(e.sub(p["xs"], 1)), 8)))
        e.give(1)
    return _function(("xf",), build, tables)


# -- the closure -------------------------------------------------------------------------------

def _wa_enter(tables):
    """``visit(function)``'s entry: a function on the active path marks the cycle recursive; a new one has its interface
    checked (``WASM-ABI-VALUE``) and is pushed."""
    def build(e: E):
        p = e.p
        f = p["ef"]
        e.var("eact", _obj(e, W_ACT, f))

        e.if_(e.both(e.ne(p["eact"], 0), e.ne(e.ld(W_LEG), 0)), lambda: _reject(
            e, "XAX.WASM.RECURSION", lambda: D.cid(e, _cid_words(e, f)), "WASM-DIRECT-CALL-ACYCLIC", lambda: D.text(e, "acyclic calls"),
            lambda: D.text(e, "cycle")))

        def cycle():
            e.for_("ed", e.sub(p["eact"], 1), e.ld(W_DEPTH), lambda: _set_obj(
                e, W_REC, e.ld(e.add(e.ld(W_STACK), e.add(e.mul(p["ed"], FRAME_W), F_FN))), 1))
            e.give(1)

        e.if_(e.ne(p["eact"], 0), cycle)
        e.if_(e.ne(_obj(e, W_DONE, f), 0), lambda: e.give(1))
        e.var("ei", _call(e, "interface", f))
        e.var("enp", e.ld(e.add(p["ei"], 1)))
        e.var("ert", e.add(e.add(p["ei"], 2), p["enp"]))
        e.var("emr", 0)
        e.var("ebad", 0)

        def check(t):
            e.var("ect", t)

            def machine():
                e.if_(e.eq(_valtype(e, p["ect"], "evt"), 0), lambda: e.set("ebad", 1))
                legacy_bad = e.either(e.ne(_type_form(e, p["ect"]), 1), e.lt(64, _bits_width(e, p["ect"], "ebw")))
                e.if_(e.both(e.ne(e.ld(W_LEG), 0), legacy_bad), lambda: e.set("ebad", 1))

            e.if_(e.not_(_proof(e, p["ect"])), machine)

        e.for_("eq", 0, p["enp"], lambda: check(e.ld(e.add(e.add(p["ei"], 2), p["eq"]))))

        def ret():
            check(e.ld(e.add(e.add(p["ert"], 1), p["eq2"])))
            e.if_(e.not_(_proof(e, p["ect"])), lambda: e.set("emr", e.add(p["emr"], 1)))

        e.for_("eq2", 0, e.ld(p["ert"]), ret)

        def abi():
            def actual():
                D.put(e, D.T_LIST)
                D.put(e, e.add(p["enp"], e.ld(p["ert"])))
                e.for_("eq3", 0, p["enp"], lambda: D.cid(e, _cid_words(e, e.ld(e.add(e.add(p["ei"], 2), p["eq3"])))))
                e.for_("eq4", 0, e.ld(p["ert"]), lambda: D.cid(e, _cid_words(e, e.ld(e.add(e.add(p["ert"], 1), p["eq4"])))))
            e.if_(e.ne(e.ld(W_LEG), 0), lambda: _reject(e, "XAX.WASM.ABI", lambda: D.cid(e, _cid_words(e, f)), "WASM-ABI-BITS",
                                                        lambda: D.text(e, "bits<1..64>, at most one return"), actual))
            _reject(e, "XAX.WASM.ABI", lambda: D.cid(e, _cid_words(e, f)), "WASM-ABI-VALUE",
                    lambda: D.text(e, "bits, float, pointer, or aggregate; at most one return"), actual)

        e.if_(e.either(e.lt(1, p["emr"]), e.ne(p["ebad"], 0)), abi)
        e.var("ed2", e.ld(W_DEPTH))
        _ok(e, e.lt(p["ed2"], _g(e, G_O)))
        e.var("efr", e.add(e.ld(W_STACK), e.mul(p["ed2"], FRAME_W)))
        e.st(e.add(p["efr"], F_FN), f)
        e.var("estream", _at(e, G_PAY, e.ld(p["ei"])))
        e.st(e.add(p["efr"], F_AT), e.add(p["estream"], 2))
        e.st(e.add(p["efr"], F_BL), e.rd(p["estream"]))
        e.st(e.add(p["efr"], F_NL), NONE)
        e.st(W_DEPTH, e.add(p["ed2"], 1))
        _set_obj(e, W_ACT, f, e.add(p["ed2"], 1))
        e.give(1)
    return _function(("ef",), build, tables)


def _entry_identity(e: E, t, name: str):
    """``name``: 1 when ``t`` is a pointer to the opaque identity ``code-entry:wasm32-browser-event``."""
    p = e.p
    e.var(name, 0)

    def pointer():
        e.var(f"{name}_at", e.add(_at(e, G_PAY, t), 1))
        _payload_uleb(e, f"{name}_at")  # space
        e.var(f"{name}_el", _reference(e, t, _payload_uleb(e, f"{name}_at")))

        def opaque():
            e.var(f"{name}_i", e.add(_at(e, G_PAY, p[f"{name}_el"]), 1))
            e.var(f"{name}_n", _payload_uleb(e, f"{name}_i"))
            e.set(name, e.flag(e.both(e.eq(p[f"{name}_n"], len(EVENT_IDENTITY)),
                                      *(e.eq(e.rd(e.add(p[f"{name}_i"], k)), byte) for k, byte in enumerate(EVENT_IDENTITY)))))

        e.if_(e.both(e.ne(p[f"{name}_el"], NONE), e.eq(_type_form(e, p[f"{name}_el"]), 6)), opaque)

    e.if_(e.eq(_type_form(e, t), 2), pointer)


def _wa_closure(tables):
    """``_function_closure`` from entry ``ce``: the functions in CID order (``W_FUNCS``), their recursion checked."""
    def build(e: E):
        p = e.p
        e.var("cO", _g(e, G_O))
        for slot in (W_FIDX, W_ACT, W_DONE, W_REC, W_IMPIDX, W_EVT):
            e.var("calloc", e.alloc(e.add(p["cO"], 1)))
            _ok(e, e.ne(p["calloc"], NONE))
            e.st(slot, p["calloc"])
            e.for_("cz", 0, p["cO"], lambda slot=slot: _set_obj(e, slot, p["cz"], NONE if slot in (W_FIDX, W_IMPIDX, W_EVT) else 0))
        for slot, words in ((W_STACK, e.mul(e.add(p["cO"], 1), FRAME_W)), (W_FUNCS, e.add(p["cO"], 1))):
            e.var("calloc2", e.alloc(words))
            _ok(e, e.ne(p["calloc2"], NONE))
            e.st(slot, p["calloc2"])
        e.st(W_DEPTH, 0)
        e.st(W_NF, 0)
        _call(e, "wa_enter", p["ce"])

        def step():
            e.var("cfr", e.add(e.ld(W_STACK), e.mul(e.sub(e.ld(W_DEPTH), 1), FRAME_W)))
            e.var("cfn", e.ld(e.add(p["cfr"], F_FN)))
            e.var("cg", e.ld(_call(e, "interface", p["cfn"])))
            e.var("cat", e.ld(e.add(p["cfr"], F_AT)))
            e.var("cnl", e.ld(e.add(p["cfr"], F_NL)))

            def block_start():
                def finished():
                    _set_obj(e, W_ACT, p["cfn"], 0)
                    _set_obj(e, W_DONE, p["cfn"], 1)
                    e.st(e.add(e.ld(W_FUNCS), e.ld(W_NF)), p["cfn"])
                    e.st(W_NF, e.add(e.ld(W_NF), 1))
                    e.st(W_DEPTH, e.sub(e.ld(W_DEPTH), 1))

                def next_block():
                    e.set("cat", e.add(e.add(p["cat"], 1), e.rd(p["cat"])))
                    e.st(e.add(p["cfr"], F_NL), e.rd(p["cat"]))
                    e.st(e.add(p["cfr"], F_AT), e.add(p["cat"], 1))
                    e.st(e.add(p["cfr"], F_BL), e.sub(e.ld(e.add(p["cfr"], F_BL)), 1))

                e.if_(e.eq(e.ld(e.add(p["cfr"], F_BL)), 0), finished, next_block)

            def node():
                e.st(e.add(p["cfr"], F_AT), _call(e, "node_info", p["cat"]))
                e.st(e.add(p["cfr"], F_NL), e.sub(p["cnl"], 1))
                ni = _g(e, G_NI)
                e.var("cop", e.ld(e.add(ni, NI_OP)))
                supported = e.both(e.lt(p["cop"], 256), e.ne(_at(e, G_SUP, e.sel(e.lt(p["cop"], 256), p["cop"], 0)), 0))
                e.if_(e.not_(supported), lambda: _reject(
                    e, "XAX.WASM.UNSUPPORTED_OPERATION", lambda: D.cid(e, _cid_words(e, p["cg"])), "WASM-OP-TARGET-SUPPORTED",
                    lambda: _target_list(e, G_SUP_AT), lambda: D.integer(e, p["cop"])))
                e.var("cent", e.ld(e.add(ni, NI_ENTITY)))
                e.var("cres", e.ld(e.add(ni, NI_RESULTS)))

                def direct():
                    e.var("ccallee", _reference(e, p["cg"], p["cent"]))
                    _ok(e, e.ne(p["ccallee"], NONE))
                    e.if_(e.eq(_call(e, "erased", p["ccallee"]), 0), lambda: _call(e, "wa_enter", p["ccallee"]))

                def address():
                    e.var("ctype", _reference(e, p["cg"], e.rd(e.add(p["cres"], 1))))
                    _ok(e, e.ne(p["ctype"], NONE))
                    _entry_identity(e, p["ctype"], "cevent")
                    e.if_(e.eq(p["cevent"], 0), lambda: _reject(
                        e, "XAX.WASM.FUNCTION_ADDRESS", lambda: D.cid(e, _cid_words(e, p["cg"])), "WASM-FUNCTION-ADDRESS-EVENT-ENTRY",
                        lambda: D.text(e, WASM32_BROWSER_EVENT_ABI.decode()), lambda: D.cid(e, _cid_words(e, p["ctype"]))))
                    e.var("chandler", _reference(e, p["cg"], p["cent"]))
                    _ok(e, e.ne(p["chandler"], NONE))
                    _call(e, "wa_enter", p["chandler"])

                e.if_(e.eq(p["cop"], int(Operation.CALL_DIRECT)), direct)
                e.if_(e.eq(p["cop"], int(Operation.FUNCTION_ADDRESS)), address)

            def terminator():
                e.var("ctk", e.rd(p["cat"]))
                supported = e.both(e.lt(p["ctk"], 8), e.ne(_at(e, G_SUPT, e.sel(e.lt(p["ctk"], 8), p["ctk"], 0)), 0))
                e.if_(e.not_(supported), lambda: _reject(
                    e, "XAX.WASM.UNSUPPORTED_TERMINATOR", lambda: D.cid(e, _cid_words(e, p["cg"])), "WASM-TERMINATOR-TARGET-SUPPORTED",
                    lambda: _target_list(e, G_SUPT_AT), lambda: D.tagged(e, D.T_TERMINATOR, p["ctk"])))
                e.st(e.add(p["cfr"], F_AT), _call(e, "term_end", p["cat"]))
                e.st(e.add(p["cfr"], F_NL), NONE)

            e.if_(e.eq(p["cnl"], NONE), block_start, lambda: e.if_(e.ne(p["cnl"], 0), node, terminator))

        e.while_(lambda: e.ne(e.ld(W_DEPTH), 0), step)
        _sort_by_cid(e, W_FUNCS, e.ld(W_NF), "cs")
        e.for_("cp", 0, e.ld(W_NF), lambda: _set_obj(e, W_FIDX, _list(e, W_FUNCS, p["cp"]), p["cp"]))

        # A function on a call cycle must not use static frame storage.
        def recursive():
            e.var("crf", _list(e, W_FUNCS, p["cr"]))

            def scan():
                e.var("cfound", 0)
                e.var("crg", e.ld(_call(e, "interface", p["crf"])))
                e.var("crs", _at(e, G_PAY, p["crg"]))
                e.var("cra", e.add(p["crs"], 2))

                def block():
                    e.set("cra", e.add(e.add(p["cra"], 1), e.rd(p["cra"])))
                    e.var("crn", e.rd(p["cra"]))
                    e.set("cra", e.add(p["cra"], 1))

                    def node():
                        e.set("cra", _call(e, "node_info", p["cra"]))
                        ni = _g(e, G_NI)
                        e.if_(e.eq(e.ld(e.add(ni, NI_OP)), int(Operation.STACK_ALLOC)), lambda: e.set("cfound", 1))
                        e.var("crr", e.ld(e.add(ni, NI_RESULTS)))
                        e.for_("crq", 0, e.rd(p["crr"]), lambda: e.if_(
                            _aggregate(e, _reference(e, p["crg"], e.rd(e.add(e.add(p["crr"], 1), p["crq"])))), lambda: e.set("cfound", 1)))

                    e.for_("crm", 0, p["crn"], node)
                    e.set("cra", _call(e, "term_end", p["cra"]))

                e.for_("crb", 0, e.rd(p["crs"]), block)
                e.if_(e.ne(p["cfound"], 0), lambda: _reject(
                    e, "XAX.WASM.RECURSION", lambda: D.cid(e, _cid_words(e, p["crf"])), "WASM-REENTRANT-FRAME",
                    lambda: D.text(e, "no static frame storage in a recursive function"), lambda: D.text(e, "stack allocation or aggregate result")))

            e.if_(e.ne(_obj(e, W_REC, p["crf"]), 0), scan)

        e.for_("cr", 0, e.ld(W_NF), recursive)
        e.give(1)
    return _function(("ce",), build, tables)


def _sort_by_cid(e: E, slot, count, name: str):
    """Insertion sort of the object list at ``slot`` by CID."""
    p = e.p
    e.var(f"{name}_base", e.ld(slot))

    def outer():
        e.var(f"{name}_x", e.ld(e.add(p[f"{name}_base"], p[f"{name}_i"])))
        e.var(f"{name}_j", p[f"{name}_i"])
        e.var(f"{name}_go", 1)

        def inner():
            e.var(f"{name}_y", e.ld(e.add(p[f"{name}_base"], e.sub(p[f"{name}_j"], 1))))
            e.if_(_cid_less(e, _cid_at(e, p[f"{name}_x"]), _cid_at(e, p[f"{name}_y"])), lambda: (
                e.st(e.add(p[f"{name}_base"], p[f"{name}_j"]), p[f"{name}_y"]), e.set(f"{name}_j", e.sub(p[f"{name}_j"], 1))),
                lambda: e.set(f"{name}_go", 0))

        e.while_(lambda: e.both(e.ne(p[f"{name}_go"], 0), e.ne(p[f"{name}_j"], 0)), inner)
        e.st(e.add(p[f"{name}_base"], p[f"{name}_j"]), p[f"{name}_x"])

    e.for_(f"{name}_i", 1, count, outer)


# -- imports and event entries ---------------------------------------------------------------------

def _declaration(e: E, carrier, name: str):
    """``decode_foreign_function``: ``name_abi``/``name_abin``, ``name_lib``/``name_libn``, ``name_sym``/``name_symn``, and
    ``name_types`` (the input count's position) of a carrier (declines unless it has the prefix)."""
    p = e.p
    e.var(f"{name}_at", _at(e, G_PAY, carrier))
    _payload_uleb(e, f"{name}_at")
    for k, byte in enumerate(_FOREIGN_PREFIX):
        _ok(e, e.eq(e.rd(e.add(p[f"{name}_at"], k)), byte))
    e.set(f"{name}_at", e.add(p[f"{name}_at"], len(_FOREIGN_PREFIX)))
    for field in ("abi", "lib", "sym"):
        e.var(f"{name}_{field}n", _payload_uleb(e, f"{name}_at"))
        e.var(f"{name}_{field}", p[f"{name}_at"])
        e.set(f"{name}_at", e.add(p[f"{name}_at"], p[f"{name}_{field}n"]))
    e.var(f"{name}_types", p[f"{name}_at"])


def _wa_imports(tables):
    """The foreign carriers (``WASM-FOREIGN-ABI``) sorted by (library, name), stably; the event entries in CID order."""
    from xax_selfhost_general_image import _less_input, _same_input
    from xax_selfhost_x86_64_general import _ascii
    from xax_selfhost_general_dll import _input_bytes

    def build(e: E):
        p = e.p
        e.var("mO", _g(e, G_O))
        for slot in (W_CARR, W_EVL):
            e.var("malloc", e.alloc(e.add(p["mO"], 1)))
            _ok(e, e.ne(p["malloc"], NONE))
            e.st(slot, p["malloc"])
        e.st(W_NCARR, 0)
        e.st(W_NEVT, 0)

        def function():
            e.var("mg", e.ld(_call(e, "interface", _list(e, W_FUNCS, p["mf"]))))
            e.var("ms", _at(e, G_PAY, p["mg"]))
            e.var("ma", e.add(p["ms"], 2))

            def block():
                e.set("ma", e.add(e.add(p["ma"], 1), e.rd(p["ma"])))
                e.var("mn", e.rd(p["ma"]))
                e.set("ma", e.add(p["ma"], 1))

                def node():
                    e.set("ma", _call(e, "node_info", p["ma"]))
                    ni = _g(e, G_NI)
                    e.var("mop", e.ld(e.add(ni, NI_OP)))
                    e.var("ment", e.ld(e.add(ni, NI_ENTITY)))

                    def foreign():
                        e.var("mc", _reference(e, p["mg"], p["ment"]))
                        _ok(e, e.both(e.ne(p["mc"], NONE), e.eq(_kind(e, p["mc"]), int(Kind.TARGET))))
                        _declaration(e, p["mc"], "md")
                        same = e.both(e.eq(p["md_abin"], len(IMPORT_ABI)), *(e.eq(e.rd(e.add(p["md_abi"], k)), byte) for k, byte in enumerate(IMPORT_ABI)))

                        def wrong():
                            _ascii(e, p["md_abi"], p["md_abin"], "mascii")
                            _ok(e, e.ne(p["mascii"], 0))
                            _reject(e, "XAX.FOREIGN.ABI", lambda: D.cid(e, _cid_words(e, p["mg"])), "WASM-FOREIGN-ABI",
                                    lambda: D.text(e, IMPORT_ABI.decode()), lambda: _input_bytes(e, D.T_STR, p["md_abi"], p["md_abin"], "mpk"))

                        e.if_(e.not_(same), wrong)

                        def first():
                            _set_obj(e, W_IMPIDX, p["mc"], 0)
                            e.st(e.add(e.ld(W_CARR), e.ld(W_NCARR)), p["mc"])
                            e.st(W_NCARR, e.add(e.ld(W_NCARR), 1))

                        e.if_(e.eq(_obj(e, W_IMPIDX, p["mc"]), NONE), first)

                    def address():
                        e.var("mh", _reference(e, p["mg"], p["ment"]))
                        _ok(e, e.ne(p["mh"], NONE))

                        def first():
                            _set_obj(e, W_EVT, p["mh"], 0)
                            e.st(e.add(e.ld(W_EVL), e.ld(W_NEVT)), p["mh"])
                            e.st(W_NEVT, e.add(e.ld(W_NEVT), 1))

                        e.if_(e.eq(_obj(e, W_EVT, p["mh"]), NONE), first)

                    e.if_(e.eq(p["mop"], int(Operation.CALL_FOREIGN)), foreign)
                    e.if_(e.eq(p["mop"], int(Operation.FUNCTION_ADDRESS)), address)

                e.for_("mm", 0, p["mn"], node)
                e.set("ma", _call(e, "term_end", p["ma"]))

            e.for_("mb", 0, e.rd(p["ms"]), block)

        e.for_("mf", 0, e.ld(W_NF), function)
        # A stable insertion sort by (library, name).
        e.var("mbase", e.ld(W_CARR))

        def outer():
            e.var("mx", e.ld(e.add(p["mbase"], p["mi"])))
            _declaration(e, p["mx"], "mxd")
            e.var("mj", p["mi"])
            e.var("mgo", 1)

            def inner():
                e.var("my", e.ld(e.add(p["mbase"], e.sub(p["mj"], 1))))
                _declaration(e, p["my"], "myd")
                _less_input(e, p["mxd_lib"], p["mxd_libn"], p["myd_lib"], p["myd_libn"], "mlib")
                _same_input(e, p["mxd_lib"], p["mxd_libn"], p["myd_lib"], p["myd_libn"], "mslib")
                _less_input(e, p["mxd_sym"], p["mxd_symn"], p["myd_sym"], p["myd_symn"], "msym")
                before = e.either(e.ne(p["mlib"], 0), e.both(e.ne(p["mslib"], 0), e.ne(p["msym"], 0)))
                e.if_(before, lambda: (e.st(e.add(p["mbase"], p["mj"]), p["my"]), e.set("mj", e.sub(p["mj"], 1))),
                      lambda: e.set("mgo", 0))

            e.while_(lambda: e.both(e.ne(p["mgo"], 0), e.ne(p["mj"], 0)), inner)
            e.st(e.add(p["mbase"], p["mj"]), p["mx"])

        e.for_("mi", 1, e.ld(W_NCARR), outer)
        e.for_("mk", 0, e.ld(W_NCARR), lambda: _set_obj(e, W_IMPIDX, _list(e, W_CARR, p["mk"]), p["mk"]))
        _sort_by_cid(e, W_EVL, e.ld(W_NEVT), "ms2")
        e.for_("mk2", 0, e.ld(W_NEVT), lambda: _set_obj(e, W_EVT, _list(e, W_EVL, p["mk2"]), p["mk2"]))
        e.give(1)
    return _function((), build, tables)


# -- static memory -----------------------------------------------------------------------------------

def _wa_addr(tables):
    """``_memory_layout`` for the indexed function, continuing ``W_CURSOR``: stack storage (``N_SADDR``) and aggregate
    results (``V_ADDR``)."""
    from xax_selfhost_x86_64_general import G_LALIGN

    def build(e: E):
        p = e.p

        def align(alignment):
            e.st(W_CURSOR, e.and_(e.add(e.ld(W_CURSOR), e.sub(alignment, 1)), e.sub(0, alignment)))

        def block():
            e.var("ak", _blk(e, p["ab"], B_NBASE))

            def node():
                e.var("an", e.add(p["ak"], p["aq"]))

                def stack():
                    e.var("aext", _attr(e, p["an"], 0))
                    e.var("aal", _attr(e, p["an"], 1))
                    align(p["aal"])
                    _set_rec(e, W_NODE, p["an"], NODE_W, N_SADDR, e.ld(W_CURSOR))
                    e.st(W_CURSOR, e.add(e.ld(W_CURSOR), p["aext"]))
                    _ok(e, e.lt(e.ld(W_CURSOR), 1 << 40))

                e.if_(e.eq(_node(e, p["an"], N_OP), int(Operation.STACK_ALLOC)), stack)
                e.var("arb", _node(e, p["an"], N_RBASE))

                def result():
                    e.var("at2", _val(e, e.add(p["arb"], p["ar"]), V_TYPE))

                    def aggregate():
                        e.var("asize", _call(e, "abi_layout", p["at2"]))
                        align(e.ld(e.add(_g(e, G_LALIGN), p["at2"])))
                        _set_val(e, e.add(p["arb"], p["ar"]), V_ADDR, e.ld(W_CURSOR))
                        e.st(W_CURSOR, e.add(e.ld(W_CURSOR), p["asize"]))
                        _ok(e, e.lt(e.ld(W_CURSOR), 1 << 40))

                    e.if_(_aggregate(e, p["at2"]), aggregate)

                e.for_("ar", 0, _node(e, p["an"], N_NRES), result)

            e.for_("aq", 0, _blk(e, p["ab"], B_NN), node)

        e.for_("ab", 0, e.ld(W_B), block)
        e.give(1)
    return _function((), build, tables)


# -- locals and pointer extents ----------------------------------------------------------------------

def _wa_slots(tables):
    def build(e: E):
        p = e.p
        iface = e.ld(W_IFACE)
        e.var("lnp", e.ld(e.add(iface, 1)))
        e.var("lmpc", 0)
        e.for_("lq", 0, p["lnp"], lambda: e.if_(e.not_(_proof(e, e.ld(e.add(e.add(e.ld(W_IFACE), 2), p["lq"])))),
                                                lambda: e.set("lmpc", e.add(p["lmpc"], 1))))
        e.var("lloc", e.alloc(e.add(e.mul(e.ld(W_NV), 2), 4)))
        _ok(e, e.ne(p["lloc"], NONE))
        e.st(W_LOC, p["lloc"])
        e.var("ln", 0)
        e.var("lmi", 0)
        e.var("lentry", e.ld(W_ENTRY))

        def entry_param():
            e.var("lv", e.add(_blk(e, p["lentry"], B_PBASE), p["lq2"]))

            def machine():
                _ok(e, e.ne(_slot_type(e, _val(e, p["lv"], V_TYPE), "lvt"), 0))
                _set_val(e, p["lv"], V_SLOT, p["lmi"])
                e.set("lmi", e.add(p["lmi"], 1))

            e.if_(e.not_(_proof(e, _val(e, p["lv"], V_TYPE))), machine)

        e.for_("lq2", 0, _blk(e, p["lentry"], B_NP), entry_param)

        def add(v, parameter: bool = False):
            e.var("lav", v)

            def machine():
                e.var("lat", _slot_type(e, _val(e, p["lav"], V_TYPE), "lvt2"))
                if parameter:  # ``xax_wasm_legacy``: a non-entry block parameter is a bits value
                    e.if_(e.both(e.ne(e.ld(W_LEG), 0), e.eq(p["lat"], 0)), lambda: _reject(
                        e, "XAX.WASM.BLOCK_TYPE", lambda: _graph_cid(e), "WASM-BLOCK-PARAMETER-BITS", lambda: D.text(e, "bits<1..64>"),
                        lambda: D.cid(e, _cid_words(e, _val(e, p["lav"], V_TYPE)))))
                e.if_(e.ne(p["lat"], 0), lambda: (_set_val(e, p["lav"], V_SLOT, e.add(p["lmpc"], p["ln"])),
                                                    e.st(e.add(p["lloc"], p["ln"]), p["lat"]), e.set("ln", e.add(p["ln"], 1))))

            e.if_(e.not_(_proof(e, _val(e, p["lav"], V_TYPE))), machine)

        def block():
            e.if_(e.ne(p["lb"], p["lentry"]), lambda: e.for_("lp", 0, _blk(e, p["lb"], B_NP), lambda: add(e.add(_blk(e, p["lb"], B_PBASE), p["lp"]), True)))
            e.var("lk", _blk(e, p["lb"], B_NBASE))
            e.for_("lm", 0, _blk(e, p["lb"], B_NN), lambda: (
                e.var("lrb", _node(e, e.add(p["lk"], p["lm"]), N_RBASE)),
                e.for_("lr", 0, _node(e, e.add(p["lk"], p["lm"]), N_NRES), lambda: add(e.add(p["lrb"], p["lr"])))))

        e.for_("lb", 0, e.ld(W_B), block)

        def temporaries():
            def one():
                e.var("ltv", e.add(_blk(e, p["lb2"], B_PBASE), p["lp2"]))
                e.var("ltt", _slot_type(e, _val(e, p["ltv"], V_TYPE), "lvt3"))
                e.if_(e.ne(p["ltt"], 0), lambda: (_set_val(e, p["ltv"], V_TEMP, e.add(p["lmpc"], p["ln"])),
                                                    e.st(e.add(p["lloc"], p["ln"]), p["ltt"]), e.set("ln", e.add(p["ln"], 1))))

            e.for_("lp2", 0, _blk(e, p["lb2"], B_NP), one)

        e.for_("lb2", 0, e.ld(W_B), temporaries)
        e.st(W_PC, e.add(p["lmpc"], p["ln"]))
        e.st(e.add(p["lloc"], p["ln"]), I32)
        e.st(W_SCR, e.add(p["lmpc"], e.add(p["ln"], 1)))
        e.st(e.add(p["lloc"], e.add(p["ln"], 1)), I32)
        e.st(W_NLOC, e.add(p["ln"], e.sel(e.ne(e.ld(W_LEG), 0), 1, 2)))  # the legacy lowering has no aggregate scratch

        # ``pointer_extents``, in block and node order.
        def extents():
            e.var("xk2", _blk(e, p["xb"], B_NBASE))

            def node():
                e.var("xn", e.add(p["xk2"], p["xq"]))
                e.var("xop", _node(e, p["xn"], N_OP))
                e.var("xr", _node(e, p["xn"], N_RBASE))
                known = lambda: _val(e, _op_id(e, p["xn"], 0), V_EXTK)  # noqa: E731
                extent = lambda: _val(e, _op_id(e, p["xn"], 0), V_EXT)  # noqa: E731

                def put(value):
                    e.var("xvalue", value)
                    _set_val(e, p["xr"], V_EXT, p["xvalue"])
                    _set_val(e, p["xr"], V_EXTK, 1)

                e.if_(e.eq(p["xop"], int(Operation.STACK_ALLOC)), lambda: put(_attr(e, p["xn"], 0)))

                def static():
                    """``xax_wasm_legacy``'s ``pointers``: a stack object's address, an offset's base plus its attribute."""
                    e.if_(e.eq(p["xop"], int(Operation.STACK_ALLOC)), lambda: _set_val(e, p["xr"], V_ADDR, _node(e, p["xn"], N_SADDR)))

                    def offset():
                        e.var("xbase", _val(e, _op_id(e, p["xn"], 0), V_ADDR))
                        _ok(e, e.ne(p["xbase"], NONE))  # the bootstrap fails (a pointer it did not lay out)
                        _set_val(e, p["xr"], V_ADDR, e.add(p["xbase"], _attr(e, p["xn"], 0)))

                    e.if_(e.eq(p["xop"], int(Operation.ADDRESS_OFFSET)), offset)

                e.if_(e.ne(e.ld(W_LEG), 0), static)
                e.if_(e.both(e.eq(p["xop"], int(Operation.ADDRESS_OFFSET)), e.ne(known(), 0)), lambda: put(e.sub(extent(), _attr(e, p["xn"], 0))))
                e.if_(e.both(e.eq(p["xop"], int(Operation.POINTER_CAST)), e.ne(known(), 0)), lambda: put(extent()))

            e.for_("xq", 0, _blk(e, p["xb"], B_NN), node)

        e.for_("xb", 0, e.ld(W_B), extents)
        e.give(1)
    return _function((), build, tables)


# -- the nodes -------------------------------------------------------------------------------------

def _store_value(e: E, address, v, t, name: str):
    """``store_value_at``."""
    p = e.p
    e.var(f"{name}_a", address)
    e.var(f"{name}_v", v)
    e.var(f"{name}_t", t)
    e.var(f"{name}_size", _call(e, "abi_layout", p[f"{name}_t"]))
    e.var(f"{name}_f", _type_form(e, p[f"{name}_t"]))

    def copy():
        _iconst(e, p[f"{name}_a"], 0)
        _get(e, p[f"{name}_v"])
        _iconst(e, p[f"{name}_size"], 0)
        _bytes(e, b"\xfc\x0a\x00\x00")

    def scalar():
        _iconst(e, p[f"{name}_a"], 0)
        _get(e, p[f"{name}_v"])

        def float_():
            e.var(f"{name}_w32", e.flag(e.eq(_float_width(e, p[f"{name}_t"]), 32)))
            _b(e, e.sel(e.ne(p[f"{name}_w32"], 0), 0x38, 0x39))
            _b(e, e.sel(e.ne(p[f"{name}_w32"], 0), 2, 3))
            _b(e, 0)

        def integer():
            e.var(f"{name}_vt", _valtype(e, p[f"{name}_t"], f"{name}_vtt"))
            vt, size = p[f"{name}_vt"], p[f"{name}_size"]
            e.var(f"{name}_op", _table(e, [(e.both(e.eq(vt, I32 if storage == 32 else I64), e.eq(size, width)), code)
                                          for (storage, width), code in STORE.items()]))

            def bad():
                def actual():
                    D.put(e, D.T_LIST)
                    D.put(e, 2)
                    D.integer(e, p[f"{name}_vt"])
                    D.integer(e, p[f"{name}_size"])
                _reject(e, "XAX.WASM.AGGREGATE", lambda: _graph_cid(e), "WASM-AGGREGATE-SCALAR-STORE",
                        lambda: D.text(e, "1/2/4/8-byte scalar"), actual)

            e.if_(e.eq(p[f"{name}_op"], 0), bad)
            _b(e, p[f"{name}_op"])
            _u(e, _log2(e, p[f"{name}_size"], f"{name}_lg"))
            _b(e, 0)

        e.if_(e.eq(p[f"{name}_f"], 7), float_, integer)

    e.if_(_aggregate(e, p[f"{name}_t"]), copy, scalar)


def _load_value(e: E, source, offset, result, t, name: str):
    """``load_value_from``."""
    p = e.p
    e.var(f"{name}_s", source)
    e.var(f"{name}_o", offset)
    e.var(f"{name}_r", result)
    e.var(f"{name}_t", t)
    e.var(f"{name}_size", _call(e, "abi_layout", p[f"{name}_t"]))
    e.var(f"{name}_f", _type_form(e, p[f"{name}_t"]))

    def address():
        _get(e, p[f"{name}_s"])
        e.if_(e.ne(p[f"{name}_o"], 0), lambda: (_iconst(e, p[f"{name}_o"], 0), _b(e, 0x6A)))
        _set_local(e, p[f"{name}_r"])

    def scalar():
        _get(e, p[f"{name}_s"])

        def float_():
            e.var(f"{name}_w32", e.flag(e.eq(_float_width(e, p[f"{name}_t"]), 32)))
            _b(e, e.sel(e.ne(p[f"{name}_w32"], 0), 0x2A, 0x2B))
            _b(e, e.sel(e.ne(p[f"{name}_w32"], 0), 2, 3))
            _u(e, p[f"{name}_o"])

        def integer():
            e.var(f"{name}_vt", _valtype(e, p[f"{name}_t"], f"{name}_vtt"))
            vt, size = p[f"{name}_vt"], p[f"{name}_size"]
            e.var(f"{name}_op", _table(e, [(e.both(e.eq(vt, I32 if storage == 32 else I64), e.eq(size, width)), code)
                                          for (storage, width), code in LOAD.items()]))

            def bad():
                def actual():
                    D.put(e, D.T_LIST)
                    D.put(e, 2)
                    D.integer(e, p[f"{name}_vt"])
                    D.integer(e, p[f"{name}_size"])
                _reject(e, "XAX.WASM.AGGREGATE", lambda: _graph_cid(e), "WASM-AGGREGATE-SCALAR-LOAD",
                        lambda: D.text(e, "1/2/4/8-byte scalar"), actual)

            e.if_(e.eq(p[f"{name}_op"], 0), bad)
            _b(e, p[f"{name}_op"])
            _u(e, _log2(e, p[f"{name}_size"], f"{name}_lg"))
            _u(e, p[f"{name}_o"])
            e.if_(e.eq(p[f"{name}_f"], 1), lambda: _mask(e, _bits_width(e, p[f"{name}_t"], f"{name}_bw")))

        e.if_(e.eq(p[f"{name}_f"], 7), float_, integer)
        _set_local(e, p[f"{name}_r"])

    e.if_(_aggregate(e, p[f"{name}_t"]), address, scalar)


def _zero(e: E, address, size):
    _iconst(e, address, 0)
    _iconst(e, 0, 0)
    _iconst(e, size, 0)
    _bytes(e, b"\xfc\x0b\x00")


def _ty(e: E, v):
    return _val(e, v, V_TYPE)


def _wa_node_int(tables):
    """Integer, constant, comparison, conversion and event-address nodes of node ``k``: 1 when lowered, 0 when not this
    part's."""
    def build(e: E):
        p = e.p
        k = p["k"]
        e.var("nop", _node(e, k, N_OP))
        e.var("r0", _node(e, k, N_RBASE))
        e.var("a0", _op_id(e, k, 0))
        e.var("a1", _op_id(e, k, 1))
        op = p["nop"]

        def wrap():
            _bits_width(e, _ty(e, p["r0"]), "ww")
            _ok(e, e.le(p["ww"], 64))
            _get(e, p["a0"])
            _get(e, p["a1"])
            _b(e, e.add(e.sel(e.le(p["ww"], 32), 0x6A, 0x7C), e.sub(op, 1)))
            _mask(e, p["ww"])
            _set_local(e, p["r0"])
            e.give(1)

        e.if_(e.either(*(e.eq(op, int(o)) for o in (Operation.ADD_WRAP, Operation.SUB_WRAP, Operation.MUL_WRAP))), wrap)

        def event():
            e.var("ev", _obj(e, W_EVT, _node(e, k, N_ENT)))
            _ok(e, e.ne(p["ev"], NONE))
            _iconst(e, p["ev"], 0)
            _set_local(e, p["r0"])
            e.give(1)

        e.if_(e.eq(op, int(Operation.FUNCTION_ADDRESS)), event)

        def bitwise():
            _bits_width(e, _ty(e, p["r0"]), "bw")
            _ok(e, e.le(p["bw"], 64))
            _get(e, p["a0"])
            _get(e, p["a1"])
            wide = e.lt(32, p["bw"])
            _b(e, _table(e, [(e.eq(op, int(o)), e.sel(wide, codes[1], codes[0])) for o, codes in BITWISE.items()]))
            _set_local(e, p["r0"])
            e.give(1)

        e.if_(e.either(*(e.eq(op, int(o)) for o in BITWISE)), bitwise)

        def resize():
            _bits_width(e, _ty(e, p["a0"]), "zs")
            _bits_width(e, _ty(e, p["r0"]), "zd")
            _ok(e, e.both(e.le(p["zs"], 64), e.le(p["zd"], 64)))
            _get(e, p["a0"])
            e.if_(e.both(e.lt(32, p["zs"]), e.le(p["zd"], 32)), lambda: _b(e, 0xA7),
                  lambda: e.if_(e.both(e.lt(32, p["zd"]), e.le(p["zs"], 32)), lambda: _b(e, 0xAD)))
            e.if_(e.eq(op, int(Operation.INT_TRUNCATE)), lambda: _mask(e, p["zd"]))
            _set_local(e, p["r0"])
            e.give(1)

        e.if_(e.either(e.eq(op, int(Operation.INT_TRUNCATE)), e.eq(op, int(Operation.INT_ZERO_EXTEND))), resize)

        def constant():
            e.var("cobj", _node(e, k, N_ENT))
            e.var("cat", _at(e, G_PAY, p["cobj"]))
            e.var("ctype", _reference(e, p["cobj"], _payload_uleb(e, "cat")))
            e.var("cn", _payload_uleb(e, "cat"))
            e.var("cform", _type_form(e, p["ctype"]))

            def float_():
                e.var("cw", _float_width(e, p["ctype"]))
                _ok(e, e.eq(p["cn"], e.udiv(p["cw"], 8)))
                _b(e, e.sel(e.eq(p["cw"], 32), 0x43, 0x44))
                e.for_("cq", 0, p["cn"], lambda: _b(e, e.rd(e.add(p["cat"], p["cq"]))))

            def integer():
                _ok(e, e.either(e.eq(p["cform"], 1), e.eq(p["cform"], 11)))
                _ok(e, e.le(p["cn"], 8))
                e.var("cv", 0)
                e.for_("cq2", 0, p["cn"], lambda: e.set("cv", e.add(p["cv"], e.mul(e.rd(e.add(p["cat"], p["cq2"])), _pow2(e, e.mul(p["cq2"], 8))))))
                e.var("cwid", _width(e, p["ctype"], "cwd"))
                _ok(e, e.le(p["cwid"], 64))
                _iconst(e, p["cv"], e.flag(e.lt(32, p["cwid"])))

            e.if_(e.eq(p["cform"], 7), float_, integer)
            _set_local(e, p["r0"])
            e.give(1)

        e.if_(e.eq(op, int(Operation.CONSTANT)), constant)

        def compare():
            e.var("qform", _type_form(e, _ty(e, p["a0"])))
            _ok(e, e.either(e.eq(p["qform"], 1), e.eq(p["qform"], 11)))
            e.var("qw", 32)
            e.if_(e.eq(p["qform"], 1), lambda: e.set("qw", _bits_width(e, _ty(e, p["a0"]), "qbw")))
            e.var("qc", _attr(e, k, 0))
            e.var("qs", e.flag(e.either(*(e.eq(p["qc"], c) for c in SIGNED_COMPARES))))
            _call(e, "wa_gi", p["a0"], e.add(e.mul(p["qw"], 2), p["qs"]))
            _call(e, "wa_gi", p["a1"], e.add(e.mul(p["qw"], 2), p["qs"]))
            e.var("qop", _table(e, [(e.eq(p["qc"], c), code) for c, code in INT_COMPARE32.items()]))
            _ok(e, e.ne(p["qop"], 0))
            _b(e, e.add(p["qop"], e.sel(e.lt(32, p["qw"]), 0x0B, 0)))
            _set_local(e, p["r0"])
            e.give(1)

        e.if_(e.eq(op, int(Operation.INT_COMPARE)), compare)

        def to_float():
            _bits_width(e, _ty(e, p["a0"]), "tsw")
            e.var("tdw", _float_width(e, _ty(e, p["r0"])))
            e.var("tsg", e.flag(e.eq(op, int(Operation.SINT_TO_FLOAT))))
            _call(e, "wa_gi", p["a0"], e.add(e.mul(p["tsw"], 2), p["tsg"]))
            e.var("tst", e.sel(e.le(p["tsw"], 32), 32, 64))
            _b(e, _table(e, [(e.both(e.eq(p["tst"], s), e.eq(p["tdw"], d), e.eq(p["tsg"], g)), code) for (s, d, g), code in TO_FLOAT.items()]))
            _set_local(e, p["r0"])
            e.give(1)

        e.if_(e.either(e.eq(op, int(Operation.UINT_TO_FLOAT)), e.eq(op, int(Operation.SINT_TO_FLOAT))), to_float)
        e.give(0)
    return _function(("k",), build, tables)


def _fconst(e: E, raw, width32):
    """``fconst``: the opcode, then the raw bits (4 or 8 bytes, little-endian)."""
    p = e.p
    e.var("fcr", raw)
    e.var("fcw", width32)
    _b(e, e.sel(e.ne(p["fcw"], 0), 0x43, 0x44))
    e.for_("fcq", 0, e.sel(e.ne(p["fcw"], 0), 4, 8), lambda: (_b(e, e.and_(p["fcr"], 255)), e.set("fcr", e.udiv(p["fcr"], 256))))


def _wa_trap_compare(tables):
    """``trap_compare(opcode, threshold)``: ``tq`` = opcode, plus 256 when the threshold (raw bits in ``W_THR``) is
    compared rather than the operand ``tv`` itself; the width flag is ``W_SPAN``'s."""
    def build(e: E):
        p = e.p
        _get(e, p["tv"])
        e.var("tcop", e.and_(p["tq"], 255))
        e.var("tcth", e.udiv(p["tq"], 256))
        e.if_(e.eq(p["tcth"], 0), lambda: _get(e, p["tv"]), lambda: _fconst(e, e.ld(W_THR), e.ld(W_SPAN)))
        _b(e, p["tcop"])
        _bytes(e, b"\x04\x40\x00\x0b")
        e.give(1)
    return _function(("tv", "tq"), build, tables)


def _wa_node_float(tables):
    """Float arithmetic, comparison, truncation and conversion nodes of node ``k``."""
    def build(e: E):
        p = e.p
        k = p["k"]
        e.var("nop", _node(e, k, N_OP))
        e.var("r0", _node(e, k, N_RBASE))
        e.var("a0", _op_id(e, k, 0))
        e.var("a1", _op_id(e, k, 1))
        op = p["nop"]

        def arithmetic():
            e.var("fw", _float_width(e, _ty(e, p["r0"])))
            _get(e, p["a0"])
            _get(e, p["a1"])
            _b(e, e.add(e.sel(e.eq(p["fw"], 32), 0x92, 0xA0), e.sub(op, int(Operation.FLOAT_ADD))))
            _set_local(e, p["r0"])
            e.give(1)

        e.if_(e.either(*(e.eq(op, int(o)) for o in (Operation.FLOAT_ADD, Operation.FLOAT_SUB, Operation.FLOAT_MUL, Operation.FLOAT_DIV))), arithmetic)

        def compare():
            e.var("fcw2", _float_width(e, _ty(e, p["a0"])))
            _get(e, p["a0"])
            _get(e, p["a1"])
            e.var("fck", _attr(e, k, 0))
            _ok(e, e.both(e.le(1, p["fck"]), e.le(p["fck"], 6)))
            _b(e, e.add(e.sel(e.eq(p["fcw2"], 32), 0x5B, 0x61), _table(e, [(e.eq(p["fck"], c), off) for c, off in FLOAT_COMPARE.items()])))
            _set_local(e, p["r0"])
            e.give(1)

        e.if_(e.eq(op, int(Operation.FLOAT_COMPARE)), compare)

        def truncate():
            e.var("tsw2", _float_width(e, _ty(e, p["a0"])))
            _bits_width(e, _ty(e, p["r0"]), "tdw2")
            _ok(e, e.le(p["tdw2"], 64))
            e.var("tsg2", e.flag(e.eq(op, int(Operation.FLOAT_TO_SINT_TRUNC))))
            e.var("t32", e.flag(e.eq(p["tsw2"], 32)))
            e.st(W_SPAN, p["t32"])
            e.var("tcb", e.sel(e.ne(p["t32"], 0), 0x5B, 0x61))
            e.var("tmb", e.sel(e.ne(p["t32"], 0), 23, 52))
            e.var("tbias", e.sel(e.ne(p["t32"], 0), 127, 1023))
            e.var("tsign", e.sel(e.ne(p["t32"], 0), 1 << 31, 1 << 63))

            def power(k_):  # the raw bits of 2 ** k
                return e.mul(e.add(p["tbias"], k_), _pow2(e, p["tmb"]))

            def threshold(raw):
                e.st(W_THR, raw)
                return 256

            _call(e, "wa_trap", p["a0"], e.add(p["tcb"], 1))

            def signed():
                e.var("tk", e.sub(p["tdw2"], 1))

                def exact():  # -(2 ** k + 1)
                    e.var("traw", e.add(p["tsign"], e.sel(e.eq(p["tk"], 0), power(1), e.add(power(p["tk"]), _pow2(e, e.sub(p["tmb"], p["tk"]))))))
                    _call(e, "wa_trap", p["a0"], e.add(e.add(p["tcb"], 4), threshold(p["traw"])))

                e.if_(e.le(p["tk"], p["tmb"]), exact, lambda: _call(
                    e, "wa_trap", p["a0"], e.add(e.add(p["tcb"], 2), threshold(e.add(p["tsign"], power(p["tk"]))))))
                _call(e, "wa_trap", p["a0"], e.add(e.add(p["tcb"], 5), threshold(power(p["tk"]))))

            def unsigned():
                _call(e, "wa_trap", p["a0"], e.add(e.add(p["tcb"], 2), threshold(0)))
                _call(e, "wa_trap", p["a0"], e.add(e.add(p["tcb"], 5), threshold(power(p["tdw2"]))))

            e.if_(e.ne(p["tsg2"], 0), signed, unsigned)
            _get(e, p["a0"])
            e.var("tst2", e.sel(e.le(p["tdw2"], 32), 32, 64))
            _b(e, _table(e, [(e.both(e.eq(p["tsw2"], s), e.eq(p["tst2"], st), e.eq(p["tsg2"], g)), code) for (s, st, g), code in TRUNC.items()]))
            _mask(e, p["tdw2"])
            _set_local(e, p["r0"])
            e.give(1)

        e.if_(e.either(e.eq(op, int(Operation.FLOAT_TO_UINT_TRUNC)), e.eq(op, int(Operation.FLOAT_TO_SINT_TRUNC))), truncate)

        def convert():
            e.var("csw", _float_width(e, _ty(e, p["a0"])))
            e.var("cdw", _float_width(e, _ty(e, p["r0"])))
            _get(e, p["a0"])
            e.if_(e.ne(p["csw"], p["cdw"]), lambda: _b(e, e.sel(e.eq(p["cdw"], 32), 0xB6, 0xBB)))
            _set_local(e, p["r0"])
            e.give(1)

        e.if_(e.eq(op, int(Operation.FLOAT_CONVERT)), convert)
        e.give(0)
    return _function(("k",), build, tables)


def _wa_node_value(tables):
    """Aggregate, sum and call nodes of node ``k``."""
    from xax_selfhost_general_frame import _component_offset, _payload_offset

    def build(e: E):
        p = e.p
        k = p["k"]
        e.var("nop", _node(e, k, N_OP))
        e.var("r0", _node(e, k, N_RBASE))
        e.var("a0", _op_id(e, k, 0))
        op = p["nop"]

        def address_of(v, name):
            e.var(name, _val(e, v, V_ADDR))
            _ok(e, e.ne(p[name], NONE))
            return p[name]

        def make():
            address_of(p["r0"], "gaddr")
            e.var("gt", _ty(e, p["r0"]))
            e.var("gsize", _call(e, "abi_layout", p["gt"]))
            _zero(e, p["gaddr"], p["gsize"])

            def component():
                e.var("gv", _op_id(e, k, p["gq"]))
                _component_offset(e, p["gt"], p["gq"], "goff")
                _store_value(e, e.add(p["gaddr"], p["goff"]), p["gv"], _ty(e, p["gv"]), "gst")

            e.for_("gq", 0, _node(e, k, N_NOP), component)
            _iconst(e, p["gaddr"], 0)
            _set_local(e, p["r0"])
            e.give(1)

        e.if_(e.eq(op, int(Operation.AGGREGATE_MAKE)), make)

        def get_():
            e.var("ht", _ty(e, p["a0"]))
            _call(e, "abi_layout", p["ht"])
            _component_offset(e, p["ht"], _attr(e, k, 0), "hoff")
            _load_value(e, p["a0"], p["hoff"], p["r0"], _ty(e, p["r0"]), "hld")
            e.give(1)

        e.if_(e.eq(op, int(Operation.AGGREGATE_GET)), get_)

        def sum_make():
            address_of(p["r0"], "saddr")
            e.var("st0", _ty(e, p["r0"]))
            e.var("ssize", _call(e, "abi_layout", p["st0"]))
            _zero(e, p["saddr"], p["ssize"])
            _iconst(e, p["saddr"], 0)
            _iconst(e, _attr(e, k, 0), 0)
            _bytes(e, b"\x36\x02\x00")
            _payload_offset(e, p["st0"], "spo")
            _store_value(e, e.add(p["saddr"], p["spo"]), p["a0"], _ty(e, p["a0"]), "sst")
            _iconst(e, p["saddr"], 0)
            _set_local(e, p["r0"])
            e.give(1)

        e.if_(e.eq(op, int(Operation.SUM_MAKE)), sum_make)

        def tag():
            _get(e, p["a0"])
            _bytes(e, b"\x28\x02\x00")
            _mask(e, _bits_width(e, _ty(e, p["r0"]), "tgw"))
            _set_local(e, p["r0"])
            e.give(1)

        e.if_(e.eq(op, int(Operation.SUM_TAG)), tag)

        def sum_get():
            e.var("ut", _ty(e, p["a0"]))
            _call(e, "abi_layout", p["ut"])
            _get(e, p["a0"])
            _bytes(e, b"\x28\x02\x00")
            _iconst(e, _attr(e, k, 0), 0)
            _bytes(e, b"\x46\x45\x04\x40\x00\x0b")
            _payload_offset(e, p["ut"], "upo")
            _load_value(e, p["a0"], p["upo"], p["r0"], _ty(e, p["r0"]), "uld")
            e.give(1)

        e.if_(e.eq(op, int(Operation.SUM_GET)), sum_get)

        def call():
            e.for_("kq", 0, _node(e, k, N_NOP), lambda: (
                e.var("kv", _op_id(e, k, p["kq"])),
                e.if_(e.not_(_proof(e, _ty(e, p["kv"]))), lambda: _get(e, p["kv"]))))
            e.var("kent", _node(e, k, N_ENT))

            def foreign():
                _b(e, 0x10)
                _u(e, _obj(e, W_IMPIDX, p["kent"]))

            def direct():
                def emit():
                    e.var("kidx", _obj(e, W_FIDX, p["kent"]))
                    _ok(e, e.ne(p["kidx"], NONE))
                    _b(e, 0x10)
                    _u(e, e.add(e.ld(W_NCARR), p["kidx"]))

                e.if_(e.eq(_call(e, "erased", p["kent"]), 0), emit)

            e.if_(e.eq(op, int(Operation.CALL_FOREIGN)), foreign, direct)
            e.var("kres", NONE)
            e.for_("kr", 0, _node(e, k, N_NRES), lambda: e.if_(
                e.both(e.eq(p["kres"], NONE), e.not_(_proof(e, _ty(e, e.add(p["r0"], p["kr"]))))), lambda: e.set("kres", e.add(p["r0"], p["kr"]))))

            def result():
                def aggregate():
                    _local(e, 0x21, e.ld(W_SCR))
                    address_of(p["kres"], "kaddr")
                    e.var("ksize", _call(e, "abi_layout", _ty(e, p["kres"])))
                    _zero(e, p["kaddr"], p["ksize"])
                    _iconst(e, p["kaddr"], 0)
                    _local(e, 0x20, e.ld(W_SCR))
                    _iconst(e, p["ksize"], 0)
                    _bytes(e, b"\xfc\x0a\x00\x00")
                    _iconst(e, p["kaddr"], 0)
                    _set_local(e, p["kres"])

                e.if_(_aggregate(e, _ty(e, p["kres"])), aggregate, lambda: _set_local(e, p["kres"]))

            e.if_(e.ne(p["kres"], NONE), result)
            e.give(1)

        e.if_(e.either(e.eq(op, int(Operation.CALL_DIRECT)), e.eq(op, int(Operation.CALL_FOREIGN))), call)
        e.give(0)
    return _function(("k",), build, tables)


def _wa_node_memory(tables):
    """Stack, pointer, memory-access and proof nodes of node ``k``."""
    def build(e: E):
        p = e.p
        k = p["k"]
        e.var("nop", _node(e, k, N_OP))
        e.var("r0", _node(e, k, N_RBASE))
        e.var("a0", _op_id(e, k, 0))
        e.var("a1", _op_id(e, k, 1))
        op = p["nop"]

        def lowered(*ops):
            return e.either(*(e.eq(op, int(o)) for o in ops))

        e.if_(e.eq(op, int(Operation.STACK_ALLOC)), lambda: (
            _iconst(e, _node(e, k, N_SADDR), 0), _set_local(e, p["r0"]), e.give(1)))
        e.if_(e.eq(op, int(Operation.ADDRESS_OFFSET)), lambda: (
            _get(e, p["a0"]), _iconst(e, _attr(e, k, 0), 0), _b(e, 0x6A), _set_local(e, p["r0"]), e.give(1)))
        e.if_(e.eq(op, int(Operation.POINTER_CAST)), lambda: (_get(e, p["a0"]), _set_local(e, p["r0"]), e.give(1)))

        def address():
            e.var("pw", _width(e, _ty(e, p["r0"]), "pwd"))
            e.if_(e.ne(p["pw"], 32), lambda: _reject(
                e, "XAX.WASM.ADDRESS_WIDTH", lambda: _graph_cid(e), "WASM-ADDRESS-POINTER-WIDTH", lambda: D.integer(e, 32),
                lambda: e.if_(e.eq(p["pw"], NONE), lambda: D.none(e), lambda: D.integer(e, p["pw"]))))
            _get(e, p["a0"])
            _set_local(e, p["r0"])
            e.give(1)

        e.if_(e.eq(op, int(Operation.POINTER_ADDRESS)), address)

        def width_reject(width):
            _reject(e, "XAX.WASM.MEMORY_WIDTH", lambda: _graph_cid(e), "WASM-MEMORY-WIDTH", lambda: _int_list(e, (8, 16, 32, 64)),
                    lambda: D.integer(e, width))

        def opcode(table, storage, size):
            return _table(e, [(e.both(e.eq(storage, s), e.eq(size, w)), code) for (s, w), code in table.items()])

        def checked():
            e.var("csz", _attr(e, k, 0))
            e.var("cal", _attr(e, k, 1))

            def unknown():
                def actual():
                    D.put(e, D.T_LIST)
                    D.put(e, 2)
                    D.integer(e, _val(e, p["a0"], V_BLK))
                    D.integer(e, _val(e, p["a0"], V_IDX))
                _reject(e, "XAX.WASM.POINTER", lambda: _graph_cid(e), "WASM-CHECKED-POINTER-EXTENT",
                        lambda: D.text(e, "known stack pointer extent"), actual)

            e.if_(e.eq(_val(e, p["a0"], V_EXTK), 0), unknown)
            e.var("cmax", e.sub(_val(e, p["a0"], V_EXT), p["csz"]))

            def access():
                e.var("ciw", _width(e, _ty(e, p["a1"]), "ciwd"))
                _ok(e, e.le(p["ciw"], 64))
                _get(e, p["a1"])
                _iconst(e, p["cmax"], e.flag(e.lt(32, p["ciw"])))
                _b(e, e.sel(e.le(p["ciw"], 32), 0x4B, 0x56))
                _bytes(e, b"\x04\x40\x00\x0b")
                _get(e, p["a0"])
                _get(e, p["a1"])
                e.if_(e.lt(32, p["ciw"]), lambda: _b(e, 0xA7))
                _b(e, 0x6A)
                e.var("cload", e.flag(e.eq(op, int(Operation.CHECKED_LOAD_BITS_LE))))
                e.var("cvt", e.sel(e.ne(p["cload"], 0), _ty(e, p["r0"]), _ty(e, _op_id(e, k, 2))))
                e.var("cw", _width(e, p["cvt"], "cwd"))
                _ok(e, e.ne(p["cw"], NONE))
                e.var("cform", _type_form(e, p["cvt"]))
                e.var("cst", e.sel(e.le(p["cw"], 32), 32, 64))
                e.var("copc", 0)

                def float_():
                    e.set("copc", e.sel(e.eq(p["cw"], 32), e.sel(e.ne(p["cload"], 0), 0x2A, 0x38), e.sel(e.ne(p["cload"], 0), 0x2B, 0x39)))

                e.if_(e.eq(p["cform"], 7), float_, lambda: e.set("copc", e.sel(e.ne(p["cload"], 0), opcode(LOAD, p["cst"], p["csz"]),
                                                                               opcode(STORE, p["cst"], p["csz"]))))
                e.if_(e.eq(p["copc"], 0), lambda: width_reject(p["cw"]))
                e.if_(e.eq(p["cload"], 0), lambda: _get(e, _op_id(e, k, 2)))
                _b(e, p["copc"])
                _u(e, _log2(e, p["cal"], "clg"))
                _b(e, 0)
                e.if_(e.ne(p["cload"], 0), lambda: (e.if_(e.eq(p["cform"], 1), lambda: _mask(e, p["cw"])), _set_local(e, p["r0"])))

            e.if_(_signed_lt(e, p["cmax"], 0), lambda: _b(e, 0), access)
            e.give(1)

        e.if_(lowered(Operation.CHECKED_LOAD_BITS_LE, Operation.CHECKED_STORE_BITS_LE), checked)

        def load():
            e.var("lal", _attr(e, k, 1))
            e.var("lal1", e.sel(e.eq(p["lal"], 0), 1, p["lal"]))

            def link():
                _get(e, p["a0"])
                _b(e, 0x29)
                _u(e, _log2(e, p["lal1"], "llg"))
                _bytes(e, b"\x00\xa7")
                _set_local(e, p["r0"])

            def plain():
                e.var("lsz", _attr(e, k, 0))
                e.var("lw", _width(e, _ty(e, p["r0"]), "lwd"))
                _ok(e, e.ne(p["lw"], NONE))
                _get(e, p["a0"])
                e.var("lform", _type_form(e, _ty(e, p["r0"])))
                e.var("lopc", e.sel(e.eq(p["lform"], 7), e.sel(e.eq(p["lw"], 32), 0x2A, 0x2B), opcode(LOAD, e.sel(e.le(p["lw"], 32), 32, 64), p["lsz"])))
                e.if_(e.eq(p["lopc"], 0), lambda: width_reject(p["lw"]))
                _b(e, p["lopc"])
                _u(e, _log2(e, p["lal1"], "llg2"))
                _b(e, 0)
                e.if_(e.eq(p["lform"], 1), lambda: _mask(e, p["lw"]))
                _set_local(e, p["r0"])

            e.if_(e.eq(_type_form(e, _ty(e, p["r0"])), 11), link, plain)
            e.give(1)

        e.if_(lowered(Operation.RAW_LOAD_BITS_LE, Operation.LOAD_BITS_LE), load)

        def store():
            def link():
                e.var("sal", _attr(e, k, 1))
                _get(e, p["a0"])
                _get(e, p["a1"])
                _bytes(e, b"\xad\x37")
                _u(e, _log2(e, e.sel(e.eq(p["sal"], 0), 1, p["sal"]), "slg"))
                _b(e, 0)

            def plain():
                e.var("ssz", _attr(e, k, 0))
                e.var("sal2", _attr(e, k, 1))
                e.var("sw", _width(e, _ty(e, p["a1"]), "swd"))
                _ok(e, e.ne(p["sw"], NONE))
                _get(e, p["a0"])
                _get(e, p["a1"])
                e.var("sopc", e.sel(e.eq(_type_form(e, _ty(e, p["a1"])), 7), e.sel(e.eq(p["sw"], 32), 0x38, 0x39),
                                    opcode(STORE, e.sel(e.le(p["sw"], 32), 32, 64), p["ssz"])))
                e.if_(e.eq(p["sopc"], 0), lambda: width_reject(p["sw"]))
                _b(e, p["sopc"])
                _u(e, _log2(e, p["sal2"], "slg2"))
                _b(e, 0)

            e.if_(e.eq(_type_form(e, _ty(e, p["a1"])), 11), link, plain)
            e.give(1)

        e.if_(e.eq(op, int(Operation.STORE_BITS_LE)), store)
        from xax_compiler import RESOURCE_EFFECT_OPERATIONS

        e.if_(lowered(Operation.STACK_END, Operation.LINK_TARGET, *RESOURCE_EFFECT_OPERATIONS), lambda: e.give(1))
        e.give(0)
    return _function(("k",), build, tables)


def _wa_node_legacy(tables):
    """``xax_wasm_legacy``'s memory nodes of node ``k``: storage at static addresses, nothing emitted for stack objects,
    offsets, stack ends and resource steps; 1 when lowered, 0 when not this part's."""
    def build(e: E):
        p = e.p
        k = p["k"]
        e.var("nop", _node(e, k, N_OP))
        e.var("r0", _node(e, k, N_RBASE))
        e.var("a0", _op_id(e, k, 0))
        op = p["nop"]
        from xax_compiler import RESOURCE_EFFECT_OPERATIONS

        quiet = (Operation.STACK_ALLOC, Operation.ADDRESS_OFFSET, Operation.STACK_END, *RESOURCE_EFFECT_OPERATIONS)
        e.if_(e.either(*(e.eq(op, int(o)) for o in quiet)), lambda: e.give(1))

        def address():
            e.var("ladr", _val(e, p["a0"], V_ADDR))
            _ok(e, e.ne(p["ladr"], NONE))  # the bootstrap fails (a pointer it did not lay out)
            return p["ladr"]

        def bits(t, name):
            _ok(e, e.eq(_type_form(e, t), 1))
            _bits_width(e, t, name)
            _ok(e, e.le(e.p[name], 64))
            return e.p[name]

        def opcode(table, width, size):
            st = e.sel(e.le(width, 32), 32, 64)
            return _table(e, [(e.both(e.eq(st, s_), e.eq(size, w)), code) for (s_, w), code in table.items()])

        def access(load: bool, value_type, size, alignment_log):
            e.var("lw", bits(value_type, "lbw"))
            e.var("lopc", opcode(LOAD if load else STORE, p["lw"], size))
            e.if_(e.eq(p["lopc"], 0), lambda: _reject(e, "XAX.WASM.MEMORY_WIDTH", lambda: _graph_cid(e), "WASM-MEMORY-WIDTH",
                                                     lambda: _int_list(e, (8, 16, 32, 64)), lambda: D.integer(e, p["lw"])))
            _b(e, p["lopc"])
            _u(e, alignment_log)
            _b(e, 0)

        def checked():
            e.var("lload", e.flag(e.eq(op, int(Operation.CHECKED_LOAD_BITS_LE))))
            e.var("lat", address())
            _ok(e, e.ne(_val(e, p["a0"], V_EXTK), 0))  # the bootstrap fails (no extent)
            e.var("lsz", _attr(e, k, 0))
            e.var("lal", _attr(e, k, 1))
            e.var("lmax", e.sub(_val(e, p["a0"], V_EXT), p["lsz"]))

            def in_range():
                e.var("la1", _op_id(e, k, 1))
                _get(e, p["la1"])
                _iconst(e, p["lmax"], 0)
                _b(e, 0x4B)  # i32.gt_u
                _bytes(e, b"\x04\x40\x00\x0b")
                _iconst(e, p["lat"], 0)
                _get(e, p["la1"])
                _b(e, 0x6A)

                def load():
                    access(True, _ty(e, p["r0"]), p["lsz"], _log2(e, p["lal"], "llg"))
                    _mask(e, p["lw"])
                    _set_local(e, p["r0"])

                def store():
                    e.var("lval", _op_id(e, k, 2))
                    _get(e, p["lval"])
                    access(False, _ty(e, p["lval"]), p["lsz"], _log2(e, p["lal"], "llg2"))

                e.if_(e.ne(p["lload"], 0), load, store)

            e.if_(_signed_lt(e, p["lmax"], 0), lambda: _b(e, 0), in_range)
            e.give(1)

        e.if_(e.either(e.eq(op, int(Operation.CHECKED_LOAD_BITS_LE)), e.eq(op, int(Operation.CHECKED_STORE_BITS_LE))), checked)

        def plain_load():
            e.var("lpa", address())
            e.var("lpal", _attr(e, k, 1))
            e.var("lpal1", e.sel(e.both(e.eq(op, int(Operation.RAW_LOAD_BITS_LE)), e.eq(p["lpal"], 0)), 1, p["lpal"]))
            _iconst(e, p["lpa"], 0)
            access(True, _ty(e, p["r0"]), _attr(e, k, 0), _log2(e, p["lpal1"], "llg3"))
            _mask(e, p["lw"])
            _set_local(e, p["r0"])
            e.give(1)

        e.if_(e.either(e.eq(op, int(Operation.RAW_LOAD_BITS_LE)), e.eq(op, int(Operation.LOAD_BITS_LE))), plain_load)

        def plain_store():
            e.var("lsa", address())
            e.var("lsv", _op_id(e, k, 1))
            _iconst(e, p["lsa"], 0)
            _get(e, p["lsv"])
            access(False, _ty(e, p["lsv"]), _attr(e, k, 0), _log2(e, _attr(e, k, 1), "llg4"))
            e.give(1)

        e.if_(e.eq(op, int(Operation.STORE_BITS_LE)), plain_store)
        e.give(0)
    return _function(("k",), build, tables)


def _wa_node(tables):
    def build(e: E):
        p = e.p
        e.if_(e.ne(e.ld(W_LEG), 0), lambda: e.if_(e.ne(_call(e, "wa_node_legacy", p["nk"]), 0), lambda: e.give(1)))
        for part in ("wa_node_int", "wa_node_float", "wa_node_value", "wa_node_memory"):
            e.if_(e.ne(_call(e, part, p["nk"]), 0), lambda: e.give(1))
        e.give(NONE)  # an operation the target lists but the lowering does not (``WASM-OP-LOWERED``): declined
    return _function(("nk",), build, tables)


def _copy_edge(e: E, target, base, count, depth):
    p = e.p
    e.var("et", target)
    e.var("eb", base)
    e.var("en", count)
    pair = lambda q: (e.ld(e.add(e.ld(W_IDS), e.add(p["eb"], q))), e.add(_blk(e, p["et"], B_PBASE), q))  # noqa: E731

    def both_machine(q):
        argument, parameter = pair(q)
        return e.both(e.ne(_val(e, argument, V_SLOT), NONE), e.ne(_val(e, parameter, V_SLOT), NONE))

    e.for_("eq", 0, p["en"], lambda: e.if_(both_machine(p["eq"]), lambda: (
        _get(e, pair(p["eq"])[0]), _local(e, 0x21, _val(e, pair(p["eq"])[1], V_TEMP)))))
    e.for_("eq2", 0, p["en"], lambda: e.if_(both_machine(p["eq2"]), lambda: (
        _local(e, 0x20, _val(e, pair(p["eq2"])[1], V_TEMP)), _set_local(e, pair(p["eq2"])[1]))))
    _iconst(e, p["et"], 0)
    _local(e, 0x21, e.ld(W_PC))
    _b(e, 0x0C)
    _u(e, depth)


def _wa_term(tables):
    def build(e: E):
        p = e.p
        b = p["tb"]
        e.var("tk", _blk(e, b, B_TK))

        def returning():
            iface = e.ld(W_IFACE)
            e.var("trt", e.add(e.add(iface, 2), e.ld(e.add(iface, 1))))
            e.var("tdone", 0)

            def one():
                e.var("tty", e.ld(e.add(e.add(p["trt"], 1), p["tq"])))

                def first():
                    _get(e, e.ld(e.add(e.ld(W_IDS), e.add(_blk(e, b, B_T0B), p["tq"]))))
                    e.set("tdone", 1)

                e.if_(e.both(e.eq(p["tdone"], 0), e.not_(_proof(e, p["tty"]))), first)

            e.for_("tq", 0, _blk(e, b, B_T0N), one)
            _b(e, 0x0F)

        def conditional():
            _get(e, _blk(e, b, B_TC))
            _bytes(e, b"\x04\x40")
            _copy_edge(e, _blk(e, b, B_T0), _blk(e, b, B_T0B), _blk(e, b, B_T0N), 2)
            _b(e, 0x05)
            _copy_edge(e, _blk(e, b, B_T1), _blk(e, b, B_T1B), _blk(e, b, B_T1N), 2)
            _b(e, 0x0B)

        e.if_(e.eq(p["tk"], 3), returning, lambda: e.if_(
            e.eq(p["tk"], 1), lambda: _copy_edge(e, _blk(e, b, B_T0), _blk(e, b, B_T0B), _blk(e, b, B_T0N), 1), lambda: e.if_(
                e.eq(p["tk"], 2), conditional, lambda: _b(e, 0x00))))
        _b(e, 0x0B)
        e.give(1)
    return _function(("tb",), build, tables)


def _buffer_reset(e: E, buf):
    e.st(buf + 1, 0)


def _append(e: E, dst, src):
    """Append buffer ``src``'s bytes to buffer ``dst``."""
    p = e.p
    e.var("apn", e.ld(src + 1))
    e.var("apd", e.ld(dst + 1))
    _ok(e, e.le(e.add(p["apd"], p["apn"]), e.ld(dst + 2)))
    e.var("aps", e.ld(src))
    e.var("apt", e.add(e.ld(dst), p["apd"]))
    e.for_("apq", 0, p["apn"], lambda: e.st(e.add(p["apt"], p["apq"]), e.ld(e.add(p["aps"], p["apq"]))))
    e.st(dst + 1, e.add(p["apd"], p["apn"]))


def _wa_function(tables):
    """``_compile_function`` of the ``fp``-th function: its body (size, locals, code) appended to ``BODIES``."""
    def build(e: E):
        p = e.p
        _call(e, "wa_index", _list(e, W_FUNCS, p["fp"]))
        _call(e, "wa_addr")
        _call(e, "wa_slots")
        _buffer_reset(e, CODE)
        _use(e, CODE)
        _iconst(e, e.ld(W_ENTRY), 0)
        _local(e, 0x21, e.ld(W_PC))
        _bytes(e, b"\x03\x40")

        def block():
            _local(e, 0x20, e.ld(W_PC))
            _iconst(e, p["fb"], 0)
            _bytes(e, b"\x46\x04\x40")
            e.var("fk", _blk(e, p["fb"], B_NBASE))
            e.for_("fq", 0, _blk(e, p["fb"], B_NN), lambda: _call(e, "wa_node", e.add(p["fk"], p["fq"])))
            _call(e, "wa_term", p["fb"])

        e.for_("fb", 0, e.ld(W_B), block)
        _bytes(e, b"\x00\x0b\x00")
        _b(e, 0x0B)  # the body's end
        # The locals declarations: runs of one value type.
        _buffer_reset(e, PART)
        _use(e, PART)
        e.var("fruns", 0)
        e.var("fprev", 0)
        e.for_("fl", 0, e.ld(W_NLOC), lambda: (
            e.var("fvt", e.ld(e.add(e.ld(W_LOC), p["fl"]))),
            e.if_(e.ne(p["fvt"], p["fprev"]), lambda: (e.set("fruns", e.add(p["fruns"], 1)), e.set("fprev", p["fvt"])))))
        _u(e, p["fruns"])
        e.var("fcount", 0)
        e.set("fprev", 0)

        def run():
            e.var("fvt2", e.ld(e.add(e.ld(W_LOC), p["fl2"])))
            e.if_(e.both(e.ne(p["fvt2"], p["fprev"]), e.ne(p["fprev"], 0)), lambda: (_u(e, p["fcount"]), _b(e, p["fprev"]), e.set("fcount", 0)))
            e.set("fprev", p["fvt2"])
            e.set("fcount", e.add(p["fcount"], 1))

        e.for_("fl2", 0, e.ld(W_NLOC), run)
        e.if_(e.ne(p["fcount"], 0), lambda: (_u(e, p["fcount"]), _b(e, p["fprev"])))
        _use(e, BODIES)
        _u(e, e.add(e.ld(PART + 1), e.ld(CODE + 1)))
        _append(e, BODIES, PART)
        _append(e, BODIES, CODE)
        e.give(1)
    return _function(("fp",), build, tables)


# -- the module ----------------------------------------------------------------------------------

def _section(e: E, section_id: int):
    """``_section(id, PART)`` appended to ``MODULE``; ``PART`` is emptied."""
    _use(e, MODULE)
    _b(e, section_id)
    _u(e, e.ld(PART + 1))
    _append(e, MODULE, PART)
    _buffer_reset(e, PART)
    _use(e, PART)


def _type_by_cid(e: E, at, name: str):
    """``name``: the object whose CID is the 32 input bytes at ``at`` (declines when none is listed)."""
    p = e.p
    for k in range(4):
        e.var(f"{name}_w{k}", 0)
        e.for_(f"{name}_q{k}", 0, 8, lambda k=k: e.set(f"{name}_w{k}", e.add(e.mul(p[f"{name}_w{k}"], 256),
                                                                               e.rd(e.add(at, e.add(8 * k, p[f"{name}_q{k}"]))))))
    e.var(name, NONE)

    def check():
        cid = _cid_words(e, p[f"{name}_o"])
        e.if_(e.both(*(e.eq(cid[k], p[f"{name}_w{k}"]) for k in range(4))), lambda: e.set(name, p[f"{name}_o"]))

    e.for_(f"{name}_o", 0, _g(e, G_O), check)
    _ok(e, e.ne(p[name], NONE))


def _wa_signature(tables):
    """``type_index``: the signature in ``PART`` (``0x60``, parameters, results) found in or appended to ``W_SIGS``."""
    def build(e: E):
        p = e.p
        e.var("sn", e.ld(PART + 1))
        e.var("spart", e.ld(PART))
        e.var("sfound", NONE)
        e.var("spos", 0)

        def candidate():
            e.var("sstart", e.ld(e.add(e.ld(W_SIGS), e.mul(p["sk"], 2))))
            e.var("slen", e.ld(e.add(e.ld(W_SIGS), e.add(e.mul(p["sk"], 2), 1))))
            e.var("ssame", e.flag(e.eq(p["slen"], p["sn"])))
            e.if_(e.ne(p["ssame"], 0), lambda: e.for_("sq3", 0, p["sn"], lambda: e.if_(
                e.ne(e.ld(e.add(_sig_bytes(e), e.add(p["sstart"], p["sq3"]))), e.ld(e.add(p["spart"], p["sq3"]))), lambda: e.set("ssame", 0))))
            e.if_(e.both(e.ne(p["ssame"], 0), e.eq(p["sfound"], NONE)), lambda: e.set("sfound", p["sk"]))
            e.set("spos", e.add(p["sstart"], p["slen"]))

        e.for_("sk", 0, e.ld(W_NSIGS), candidate)

        def append():
            _ok(e, e.both(e.lt(e.ld(W_NSIGS), 4096), e.le(e.add(p["spos"], p["sn"]), SIG_CAP)))
            e.st(e.add(e.ld(W_SIGS), e.mul(e.ld(W_NSIGS), 2)), p["spos"])
            e.st(e.add(e.ld(W_SIGS), e.add(e.mul(e.ld(W_NSIGS), 2), 1)), p["sn"])
            e.for_("sq4", 0, p["sn"], lambda: e.st(e.add(_sig_bytes(e), e.add(p["spos"], p["sq4"])), e.ld(e.add(p["spart"], p["sq4"]))))
            e.set("sfound", e.ld(W_NSIGS))
            e.st(W_NSIGS, e.add(e.ld(W_NSIGS), 1))

        e.if_(e.eq(p["sfound"], NONE), append)
        _buffer_reset(e, PART)
        e.give(p["sfound"])
    return _function((), build, tables)


def _sig_bytes(e: E):
    return e.add(e.ld(W_SIGS), 2 * 4096)


def _valtypes(e: E, types_at, count, by_cid: bool, name: str):
    """``_vector`` of the non-proof types' value types into ``PART``: ``types_at`` holds object indices (or, ``by_cid``,
    32-byte CIDs in the input)."""
    p = e.p
    e.var(f"{name}_n", 0)

    def each(counting: bool):
        def one():
            if by_cid:
                _type_by_cid(e, e.add(types_at, e.mul(p[f"{name}_q"], 32)), f"{name}_t")
            else:
                e.var(f"{name}_t", e.ld(e.add(types_at, p[f"{name}_q"])))

            def machine():
                if counting:
                    e.set(f"{name}_n", e.add(p[f"{name}_n"], 1))
                else:
                    e.var(f"{name}_vt", _valtype(e, p[f"{name}_t"], f"{name}_v"))
                    _ok(e, e.ne(p[f"{name}_vt"], 0))
                    _b(e, p[f"{name}_vt"])

            e.if_(e.not_(_proof(e, p[f"{name}_t"])), machine)

        e.for_(f"{name}_q", 0, count, one)

    each(True)
    _u(e, p[f"{name}_n"])
    each(False)


def _wa_module(tables):
    """The module's sections into ``MODULE`` (``_compile_wasm_with_target``'s command container)."""
    def build(e: E):
        p = e.p
        for buf, cap in CAPS.items():
            e.var("walloc", e.alloc(cap))
            _ok(e, e.ne(p["walloc"], NONE))
            e.st(buf, p["walloc"])
            e.st(buf + 1, 0)
            e.st(buf + 2, cap)
        e.var("wsigs", e.alloc(2 * 4096 + SIG_CAP))
        _ok(e, e.ne(p["wsigs"], NONE))
        e.st(W_SIGS, p["wsigs"])
        e.st(W_NSIGS, 0)
        for slot, count in ((W_IMPTY, W_NCARR), (W_TYIDX, W_NF)):
            e.var("wty", e.alloc(e.add(e.ld(count), 1)))
            _ok(e, e.ne(p["wty"], NONE))
            e.st(slot, p["wty"])
        _use(e, PART)

        def import_type():
            _declaration(e, _list(e, W_CARR, p["wi"]), "wd")
            _b(e, 0x60)
            e.var("wins", e.add(p["wd_types"], 0))
            e.var("wnin", _payload_uleb(e, "wins"))
            _valtypes(e, p["wins"], p["wnin"], True, "wvi")
            e.var("wouts", e.add(p["wins"], e.mul(p["wnin"], 32)))
            e.var("wnout", _payload_uleb(e, "wouts"))
            _valtypes(e, p["wouts"], p["wnout"], True, "wvo")
            e.st(e.add(e.ld(W_IMPTY), p["wi"]), _call(e, "wa_signature"))

        e.for_("wi", 0, e.ld(W_NCARR), import_type)

        def function_type():
            e.var("wfi", _call(e, "interface", _list(e, W_FUNCS, p["wf"])))
            _b(e, 0x60)
            _valtypes(e, e.add(p["wfi"], 2), e.ld(e.add(p["wfi"], 1)), False, "wfp")
            e.var("wfr", e.add(e.add(p["wfi"], 2), e.ld(e.add(p["wfi"], 1))))
            _valtypes(e, e.add(p["wfr"], 1), e.ld(p["wfr"]), False, "wfrt")
            e.st(e.add(e.ld(W_TYIDX), p["wf"]), _call(e, "wa_signature"))

        e.for_("wf", 0, e.ld(W_NF), function_type)

        e.give(1)
    return _function((), build, tables)


def _decimal(e: E, value, name: str):
    """The decimal digits of ``value`` into the current buffer."""
    p = e.p
    e.var(f"{name}_v", value)
    e.var(f"{name}_d", 1)
    e.while_(lambda: e.le(e.mul(p[f"{name}_d"], 10), p[f"{name}_v"]), lambda: e.set(f"{name}_d", e.mul(p[f"{name}_d"], 10)))

    def digit():
        _b(e, e.add(48, e.urem(e.udiv(p[f"{name}_v"], p[f"{name}_d"]), 10)))
        e.set(f"{name}_d", e.udiv(p[f"{name}_d"], 10))

    e.while_(lambda: e.ne(p[f"{name}_d"], 0), digit)


def _digits(e: E, value, name: str):
    """The number of decimal digits of ``value``."""
    p = e.p
    e.var(f"{name}_n", 1)
    e.var(f"{name}_d", 10)
    e.while_(lambda: e.le(p[f"{name}_d"], value), lambda: (e.set(f"{name}_n", e.add(p[f"{name}_n"], 1)), e.set(f"{name}_d", e.mul(p[f"{name}_d"], 10))))
    return p[f"{name}_n"]


def _input_copy(e: E, at, n, name: str):
    p = e.p
    e.var(f"{name}_at", at)
    e.for_(f"{name}_q", 0, n, lambda: _b(e, e.rd(e.add(p[f"{name}_at"], p[f"{name}_q"]))))


def _wa_sections(tables):
    """The type, import, function, memory, export and code sections (the code from ``BODIES``)."""
    def build(e: E):
        p = e.p
        _buffer_reset(e, MODULE)
        _use(e, MODULE)
        _bytes(e, b"\x00asm\x01\x00\x00\x00")
        _buffer_reset(e, PART)
        _use(e, PART)
        _u(e, e.ld(W_NSIGS))
        e.for_("ys", 0, e.ld(W_NSIGS), lambda: (
            e.var("ysa", e.add(_sig_bytes(e), e.ld(e.add(e.ld(W_SIGS), e.mul(p["ys"], 2))))),
            e.for_("ysq", 0, e.ld(e.add(e.ld(W_SIGS), e.add(e.mul(p["ys"], 2), 1))), lambda: _b(e, e.ld(e.add(p["ysa"], p["ysq"]))))))
        _section(e, 1)

        def imports():
            _u(e, e.ld(W_NCARR))

            def one():
                _declaration(e, _list(e, W_CARR, p["yi"]), "yd")
                _u(e, p["yd_libn"])
                _input_copy(e, p["yd_lib"], p["yd_libn"], "ycl")
                _u(e, p["yd_symn"])
                _input_copy(e, p["yd_sym"], p["yd_symn"], "ycs")
                _b(e, 0)
                _u(e, e.ld(e.add(e.ld(W_IMPTY), p["yi"])))

            e.for_("yi", 0, e.ld(W_NCARR), one)
            _section(e, 2)

        e.if_(e.ne(e.ld(W_NCARR), 0), imports)
        _u(e, e.ld(W_NF))
        e.for_("yf", 0, e.ld(W_NF), lambda: _u(e, e.ld(e.add(e.ld(W_TYIDX), p["yf"]))))
        _section(e, 3)
        def memory():
            _bytes(e, b"\x01\x00\x01")
            _section(e, 5)

        e.if_(e.either(e.eq(e.ld(W_LEG), 0), e.ne(e.ld(W_MEM), 0)), memory)  # the legacy module has memory only when used
        def command():
            _u(e, e.add(e.ld(W_NEVT), 2))
            _bytes(e, b"\x06_start\x00")
            _u(e, e.add(e.ld(W_NCARR), _obj(e, W_FIDX, e.ld(W_EF))))
            _bytes(e, b"\x06memory\x02\x00")

            def event():
                _u(e, e.add(6, _digits(e, p["ye"], "ydg")))
                _bytes(e, b"entry_")
                _decimal(e, p["ye"], "ydc")
                _b(e, 0)
                _u(e, e.add(e.ld(W_NCARR), _obj(e, W_FIDX, _list(e, W_EVL, p["ye"]))))

            e.for_("ye", 0, e.ld(W_NEVT), event)

        def plain():  # one export: ``entry``
            _bytes(e, b"\x01\x05entry\x00")
            _u(e, e.add(e.ld(W_NCARR), _obj(e, W_FIDX, e.ld(W_EF))))

        e.if_(e.eq(e.ld(W_KIND), PLAIN_KIND), plain, command)
        _section(e, 7)
        _u(e, e.ld(W_NF))
        _append(e, PART, BODIES)
        _section(e, 10)
        e.give(1)
    return _function((), build, tables)


# -- the page --------------------------------------------------------------------------------------

PAGE_HEAD = b'<!doctype html>\n<meta charset="utf-8">\n<title>XAX</title>\n<body>\n<script type="module">\nconst bytes = Uint8Array.from(atob("'
PAGE_MIDDLE = (b'"), c => c.charCodeAt(0));\nlet memory, exports;\nconst view = () => new Uint8Array(memory.buffer);\nconst imports = {"'
               + WEB_LIBRARY + b'": {\n')
PAGE_TAIL = (b"}};\nconst { instance } = await WebAssembly.instantiate(bytes, imports);\n({ memory } = exports = instance.exports);\n"
             b"exports._start();\n</script>\n")
ALPHABET = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def _sextet(e: E, value):
    return e.sel(e.lt(value, 26), e.add(value, 65), e.sel(e.lt(value, 52), e.add(value, 71), e.sel(
        e.lt(value, 62), e.sub(value, 4), e.sel(e.eq(value, 62), 43, 47))))


def _wa_page(tables):
    """``emit_browser_page``: each import declared (``WEB-IMPORT-DECLARED``), then the page into ``PAGE``."""
    from xax_selfhost_x86_64_general import G_TARGET, _ascii
    from xax_selfhost_general_dll import _pack_begin, _pack_byte, _pack_end, _pack_input

    def build(e: E):
        p = e.p

        def check():
            _declaration(e, _list(e, W_CARR, p["pi"]), "pd")
            library = e.both(e.eq(p["pd_libn"], len(WEB_LIBRARY)), *(e.eq(e.rd(e.add(p["pd_lib"], k)), byte) for k, byte in enumerate(WEB_LIBRARY)))
            declared = e.either(*(e.both(e.eq(p["pd_symn"], len(name)), *(e.eq(e.rd(e.add(p["pd_sym"], k)), byte) for k, byte in enumerate(name)))
                                  for name in DECLARED))

            def undeclared():
                _ascii(e, p["pd_lib"], p["pd_libn"], "pal")
                _ascii(e, p["pd_sym"], p["pd_symn"], "pas")
                _ok(e, e.both(e.ne(p["pal"], 0), e.ne(p["pas"], 0)))

                def actual():
                    _pack_begin(e, D.T_STR, e.add(e.add(p["pd_libn"], p["pd_symn"]), 1))
                    _pack_input(e, p["pd_lib"], p["pd_libn"], "ppl")
                    _pack_byte(e, ord("."))
                    _pack_input(e, p["pd_sym"], p["pd_symn"], "pps")
                    _pack_end(e)

                def expected():
                    D.put(e, D.T_LIST)
                    D.put(e, len(DECLARED))
                    for name in DECLARED:
                        D.text(e, name.decode())

                _reject(e, "XAX.WEB.IMPORT", lambda: D.cid(e, _cid_words(e, _g(e, G_TARGET))), "WEB-IMPORT-DECLARED", expected, actual)

            e.if_(e.not_(e.both(library, declared)), undeclared)

        e.for_("pi", 0, e.ld(W_NCARR), check)
        _buffer_reset(e, PAGE)
        _use(e, PAGE)
        _bytes(e, PAGE_HEAD)
        # base64 of the module, 3 bytes to 4 characters, ``=`` padded.
        e.var("pn", e.ld(MODULE + 1))
        e.var("pm", e.ld(MODULE))

        def group():
            e.var("pg", e.mul(p["pq"], 3))
            e.var("pleft", e.sub(p["pn"], p["pg"]))
            byte = lambda k: e.sel(e.lt(k, p["pleft"]), e.ld(e.add(p["pm"], e.add(p["pg"], k))), 0)  # noqa: E731
            e.var("pw", e.add(e.add(e.mul(byte(0), 1 << 16), e.mul(byte(1), 1 << 8)), byte(2)))
            _b(e, _sextet(e, e.udiv(p["pw"], 1 << 18)))
            _b(e, _sextet(e, e.and_(e.udiv(p["pw"], 1 << 12), 63)))
            _b(e, e.sel(e.lt(1, p["pleft"]), _sextet(e, e.and_(e.udiv(p["pw"], 1 << 6), 63)), 61))
            _b(e, e.sel(e.lt(2, p["pleft"]), _sextet(e, e.and_(p["pw"], 63)), 61))

        e.for_("pq", 0, e.udiv(e.add(p["pn"], 2), 3), group)
        _bytes(e, PAGE_MIDDLE)

        def entry():
            _declaration(e, _list(e, W_CARR, p["pe"]), "pe2")
            for name in DECLARED:
                same = e.both(e.eq(p["pe2_symn"], len(name)), *(e.eq(e.rd(e.add(p["pe2_sym"], k)), byte) for k, byte in enumerate(name)))
                e.if_(same, lambda name=name: _call(e, "wa_host_" + name.decode()))

        e.for_("pe", 0, e.ld(W_NCARR), entry)
        _bytes(e, PAGE_TAIL)
        e.give(1)
    return _function((), build, tables)


def _wa_host(name: bytes):
    def make(tables):
        def build(e: E):
            _bytes(e, b'  "' + name + b'": ' + _HOST[name].encode() + b",\n")
            e.give(1)
        return _function((), build, tables)
    return make


def _wasm(tables):
    """``compile_wasm_bound_target`` and ``emit_browser_page`` for function ``wf``: 1 with the page in the image record,
    NONE when rejected or declined."""
    from xax_selfhost_general_image import IMAGE_AT, IMAGE_END
    from xax_selfhost_x86_64_general import G_GENERAL, G_TARGET

    def build(e: E):
        p = e.p
        f = p["wf"]
        _ok(e, e.eq(_kind(e, f), int(Kind.FUNCTION)))
        e.var("wt", _g(e, G_TARGET))
        e.var("wta", _at(e, G_PAY, p["wt"]))
        e.var("wtn", _payload_uleb(e, "wta"))

        def named(identity: bytes):
            return e.both(e.eq(p["wtn"], len(identity)), *(e.eq(e.rd(e.add(p["wta"], k)), byte) for k, byte in enumerate(identity)))

        e.st(W_KIND, PLAIN_KIND)  # S15f.1: any other architecture-2 target on the general profile is a plain core module
        e.if_(named(WASM32_WASI_IDENTITY), lambda: e.st(W_KIND, COMMAND_KIND))
        e.if_(named(WASM32_BROWSER_IDENTITY), lambda: e.st(W_KIND, PAGE_KIND))
        e.st(W_LEG, e.flag(e.eq(_g(e, G_GENERAL), 0)))  # S15f.3: off the general profile, ``xax_wasm_legacy``
        e.if_(e.ne(e.ld(W_LEG), 0), lambda: e.st(W_KIND, PLAIN_KIND))
        e.st(W_ON, 1)
        e.st(W_EF, f)
        _call(e, "wa_closure", f)
        _call(e, "wa_imports")
        e.st(W_CURSOR, e.sel(e.ne(e.ld(W_LEG), 0), 0, NULL_GUARD))  # the legacy layout starts at address 0
        e.for_("wl", 0, e.ld(W_NF), lambda: (_call(e, "wa_index", _list(e, W_FUNCS, p["wl"])), _call(e, "wa_addr")))
        e.st(W_MEM, e.ld(W_CURSOR))
        e.if_(e.lt(MEMORY_LIMIT, e.ld(W_CURSOR)), lambda: _reject(
            e, "XAX.WASM.MEMORY", lambda: D.text(e, "module"), "WASM-STATIC-MEMORY-LIMIT", lambda: D.text(e, "<= 65536 bytes"),
            lambda: D.integer(e, e.ld(W_CURSOR))))
        _call(e, "wa_types")
        # The command entry takes and returns no machine values.
        e.var("wi", _call(e, "interface", f))
        e.var("wnp", e.ld(e.add(p["wi"], 1)))
        e.var("wrt", e.add(e.add(p["wi"], 2), p["wnp"]))
        e.var("wmachine", 0)
        e.for_("wq", 0, p["wnp"], lambda: e.if_(e.not_(_proof(e, e.ld(e.add(e.add(p["wi"], 2), p["wq"])))), lambda: e.set("wmachine", 1)))
        e.for_("wq2", 0, e.ld(p["wrt"]), lambda: e.if_(e.not_(_proof(e, e.ld(e.add(e.add(p["wrt"], 1), p["wq2"])))), lambda: e.set("wmachine", 1)))

        def machine():
            def actual():
                D.put(e, D.T_LIST)
                D.put(e, e.add(p["wnp"], e.ld(p["wrt"])))
                e.for_("wq3", 0, p["wnp"], lambda: D.cid(e, _cid_words(e, e.ld(e.add(e.add(p["wi"], 2), p["wq3"])))))
                e.for_("wq4", 0, e.ld(p["wrt"]), lambda: D.cid(e, _cid_words(e, e.ld(e.add(e.add(p["wrt"], 1), p["wq4"])))))
            _reject(e, "XAX.WASM.WASI_ENTRY", lambda: D.cid(e, _cid_words(e, f)), "WASI-START-NO-MACHINE-VALUES", lambda: D.text(e, "() -> ()"), actual)

        e.if_(e.both(e.ne(p["wmachine"], 0), e.ne(e.ld(W_KIND), PLAIN_KIND)), machine)
        _buffer_reset(e, BODIES)
        e.st(W_CURSOR, e.sel(e.ne(e.ld(W_LEG), 0), 0, NULL_GUARD))  # the compile pass lays the storage out again, in the same order
        e.for_("wc", 0, e.ld(W_NF), lambda: _call(e, "wa_function", p["wc"]))
        _call(e, "wa_sections")
        # The image record: no code, the page (or, S15f.1, the module) as the container bytes, nothing else.
        e.var("wout", MODULE)

        def page():
            _call(e, "wa_page")
            e.set("wout", PAGE)

        e.if_(e.eq(e.ld(W_KIND), PAGE_KIND), page)
        e.var("wlen", e.ld(e.add(p["wout"], 1)))
        e.st(IMAGE_AT, 1)
        e.st(IMAGE_AT + 1, 0)
        e.st(IMAGE_AT + 2, p["wlen"])
        e.var("wbase", e.ld(p["wout"]))
        e.var("wwords", e.udiv(e.add(p["wlen"], 7), 8))
        _ok(e, e.lt(e.add(IMAGE_AT + 8, p["wwords"]), IMAGE_END))

        def word():
            e.var("ww", 0)
            e.for_("wk", 0, 8, lambda: e.set("ww", e.add(p["ww"], e.mul(
                e.sel(e.lt(e.add(e.mul(p["wo"], 8), p["wk"]), p["wlen"]), e.ld(e.add(p["wbase"], e.add(e.mul(p["wo"], 8), p["wk"]))), 0),
                _pow2(e, e.mul(p["wk"], 8))))))
            e.st(e.add(IMAGE_AT + 3, p["wo"]), p["ww"])

        e.for_("wo", 0, p["wwords"], word)
        e.for_("wz", 0, 5, lambda: e.st(e.add(e.add(IMAGE_AT + 3, p["wwords"]), p["wz"]), 0))
        e.give(1)
    return _function(("wf",), build, tables)


def add_wasm_functions(add, tables):
    for name, builder in (("wa_b", _wa_b), ("wa_bs", _wa_bs), ("wa_u", _wa_u), ("wa_s", _wa_s), ("wa_i", _wa_i), ("wa_get", _wa_get),
                          ("wa_set", _wa_set), ("wa_mask", _wa_mask), ("wa_gi", _wa_gi), ("wa_index", _wa_index), ("wa_enter", _wa_enter),
                          ("wa_closure", _wa_closure), ("wa_imports", _wa_imports), ("wa_addr", _wa_addr), ("wa_slots", _wa_slots),
                          ("wa_trap", _wa_trap_compare), ("wa_node_int", _wa_node_int), ("wa_node_float", _wa_node_float),
                          ("wa_node_value", _wa_node_value), ("wa_node_memory", _wa_node_memory), ("wa_node_legacy", _wa_node_legacy),
                          ("wa_node", _wa_node),
                          ("wa_term", _wa_term), ("wa_function", _wa_function), ("wa_signature", _wa_signature), ("wa_types", _wa_module),
                          ("wa_sections", _wa_sections), *((f"wa_host_{name.decode()}", _wa_host(name)) for name in DECLARED),
                          ("wa_page", _wa_page), ("wasm", _wasm)):
        add(name, builder(tables))


def wasm_page_with_xax(reader, function_cid: bytes, target_object, required: bool = False) -> bytes | None:
    """The page the general program writes for a verified store (``xax_selfhost_general_accel.accelerator_with_xax``'s
    shape)."""
    from xax_selfhost_general_accel import accelerator_with_xax

    return accelerator_with_xax(reader, function_cid, target_object, required)


def browser_page(reader, function_cid: bytes, target_object, *, frontend: str = "auto") -> bytes:
    """``build``'s browser page: S15e.4 (ADR-322) decided by the XAX general program where it runs and decides (``"auto"``;
    ``"xax"`` requires it), else ``xax_wasm.compile_wasm_bound_target`` and ``xax_web.emit_browser_page``.  With
    ``XAX_GENERAL_FRONTEND_DIFF=1`` the two must agree."""
    import os

    from xax_compiler import XaxError
    from xax_wasm import compile_wasm_bound_target
    from xax_web import emit_browser_page

    def reference() -> bytes:
        return emit_browser_page(compile_wasm_bound_target(reader, function_cid, target_object))

    if frontend == "python":
        return reference()
    page = wasm_page_with_xax(reader, function_cid, target_object, required=frontend == "xax")
    if page is None:
        return reference()
    if os.environ.get("XAX_GENERAL_FRONTEND_DIFF") == "1":
        try:
            expected = reference()
        except XaxError as error:
            raise AssertionError(f"S15e.4: the bootstrap rejects ({error.diagnostic.rule}) a page the XAX program wrote") from error
        if page != expected:
            raise AssertionError("S15e.4 browser pages disagree")
    return page


def wasm_module(reader, function_cid: bytes, target_object, *, frontend: str = "auto") -> bytes:
    """``build``'s module for an architecture-2 target other than the browser page (S15f.1, ADR-324): the XAX general
    program where it runs and decides (``"auto"``; ``"xax"`` requires it), else ``compile_wasm_bound_target``.  With
    ``XAX_GENERAL_FRONTEND_DIFF=1`` the two must agree."""
    import os

    from xax_compiler import XaxError
    from xax_wasm import compile_wasm_bound_target

    def reference() -> bytes:
        return compile_wasm_bound_target(reader, function_cid, target_object).artifact_bytes

    if frontend == "python":
        return reference()
    module = wasm_page_with_xax(reader, function_cid, target_object, required=frontend == "xax")
    if module is None:
        return reference()
    if os.environ.get("XAX_GENERAL_FRONTEND_DIFF") == "1":
        try:
            expected = reference()
        except XaxError as error:
            raise AssertionError(f"S15f.1: the bootstrap rejects ({error.diagnostic.rule}) a module the XAX program wrote") from error
        if module != expected:
            raise AssertionError("S15f.1 Wasm modules disagree")
    return module
