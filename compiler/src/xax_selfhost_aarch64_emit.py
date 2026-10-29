"""Self-hosting step S15e.2 (ADR-315): ``xax_aarch64_regalloc._Lowering``'s code generation as XAX functions.

After the allocation (``xax_selfhost_aarch64_lower``): the frame (saved callee registers and the link register, then
spill slots), the prologue, the entry moves, every block in layout order (its nodes, then its terminator: returns,
traps, branches with their edge copies, a duplicated short test, conditional branches through stubs), the stubs, the
shared trap stubs, the predicate tables, and the branch fixups.

The assembler keeps the code as bytes (one per word) at ``A_CODE`` with labels by number: a block's label is its
index; trap ``code``'s is ``NB + code``; stub ``k``'s ``NB + 16 + k``; a predicate table's ``NB + 16 + 2 * NB + 1 +
k`` for its ``k``-th address (``V_LABEL``).  A fixup is ``(position, label, kind)`` with kind 26 (``b``/``bl``), 19
(``b.cond``/``cbz``) or 21 (``adr``).

A location is two words: a kind (``L_REG``, ``L_SLOT``, ``L_CONST``, ``L_TABLE``) and its register, frame offset,
constant, or table address value.
"""

from __future__ import annotations

from xax_compiler import IntCompare, Operation, TerminatorKind
from xax_selfhost_facts import E, NONE, _function
import xax_selfhost_diagnostics as D
from xax_selfhost_general_view import N_ATTR, N_NOPS, N_NRES, _f, _operand as _operand_, _output
from xax_selfhost_general_regalloc import _eop  # a group-member call is the direct call the bootstrap's graph shows
from xax_selfhost_views_backend import _FN, _call, _g, _ok


def _in_(e: E, value, items):
    return e.either(*(e.eq(value, item) for item in items))

L_REG, L_SLOT, L_CONST, L_TABLE = range(4)
ZR, SP, LR = 31, 31, 30
CYCLE, TRANSFER = 16, 17
SCRATCH = (16, 17, 15, 14)
BRK_NULL_HEAP, BRK_MEMORY_CHECK, BRK_DIVIDE_BY_ZERO = 3, 4, 6
DUPLICATE_LIMIT = 4
COND = {
    IntCompare.EQ: 0, IntCompare.NE: 1, IntCompare.UGE: 2, IntCompare.ULT: 3, IntCompare.UGT: 8, IntCompare.ULE: 9,
    IntCompare.SGE: 10, IntCompare.SLT: 11, IntCompare.SGT: 12, IntCompare.SLE: 13,
}
SWAPPED = {
    IntCompare.EQ: IntCompare.EQ, IntCompare.NE: IntCompare.NE, IntCompare.ULT: IntCompare.UGT, IntCompare.UGT: IntCompare.ULT,
    IntCompare.ULE: IntCompare.UGE, IntCompare.UGE: IntCompare.ULE, IntCompare.SLT: IntCompare.SGT, IntCompare.SGT: IntCompare.SLT,
    IntCompare.SLE: IntCompare.SGE, IntCompare.SGE: IntCompare.SLE,
}
SIGNED = tuple(int(k) for k in (IntCompare.SLT, IntCompare.SLE, IntCompare.SGT, IntCompare.SGE))
ADD, SUB, MUL = (0x0B000000, 0x8B000000), (0x4B000000, 0xCB000000), (0x1B007C00, 0x9B007C00)
AND, ORR, EOR = (0x0A000000, 0x8A000000), (0x2A000000, 0xAA000000), (0x4A000000, 0xCA000000)
LOGIC_IMM = {Operation.BIT_AND: (0x12000000, 0x92000000), Operation.BIT_OR: (0x32000000, 0xB2000000), Operation.BIT_XOR: (0x52000000, 0xD2000000)}
LOGIC_REG = {Operation.BIT_AND: AND, Operation.BIT_OR: ORR, Operation.BIT_XOR: EOR}
UNSIGNED_OFFSET = {1: (0x39400000, 0x39000000), 2: (0x79400000, 0x79000000), 4: (0xB9400000, 0xB9000000), 8: (0xF9400000, 0xF9000000)}
REGISTER_OFFSET = {1: (0x38606800, 0x38206800), 2: (0x78606800, 0x78206800), 4: (0xB8606800, 0xB8206800), 8: (0xF8606800, 0xF8206800)}

# Emission state: words of the AArch64 lowering's globals (``xax_selfhost_aarch64_lower._a``) from ``EMIT_BASE``.
EMIT_BASE = 60
(X_CODE, X_LEN, X_LABELS, X_FIX, X_NFIX, X_CALLS, X_NCALLS, X_FOREIGN, X_NFOREIGN, X_RANGES, X_NRANGES, X_FREE, X_NFREE, X_STUBS,
 X_NSTUBS, X_TRAPS, X_FRAME, X_SAVED, X_NSAVED, X_SPILL_BASE, X_FOLLOWING, X_MOVES, X_NMOVES, X_NTABLES, X_HAS_CALL, X_CAP) = range(
    EMIT_BASE, EMIT_BASE + 26)
CODE_CAP = 1 << 22  # code bytes of one function
FIX_CAP = 1 << 18


def _a(e: E, slot: int):
    from xax_selfhost_aarch64_lower import _a as get

    return get(e, slot)


def _set_a(e: E, slot: int, value):
    from xax_selfhost_aarch64_lower import _set_a as put

    put(e, slot, value)


# -- the assembler ---------------------------------------------------------------------------------------------------

def _emit_fn(tables):
    """Append the 32-bit ``word`` (little endian) to the code."""
    def build(e: E):
        p = e.p
        e.var("em_len", _a(e, X_LEN))
        _ok(e, e.lt(e.add(p["em_len"], 4), CODE_CAP))
        e.var("em_w", e.and_(p["word"], 0xFFFFFFFF))
        e.var("em_at", e.add(_a(e, X_CODE), p["em_len"]))
        for k in range(4):
            e.st(e.add(p["em_at"], k), e.and_(e.udiv(p["em_w"], 1 << (8 * k)), 255))
        _set_a(e, X_LEN, e.add(p["em_len"], 4))
        e.give(0)
    return _function(("word",), build, tables)


def _emit(e: E, *words):
    for word in words:
        _call(e, "x_emit", word)


def _label(e: E, label):
    e.st(e.add(_a(e, X_LABELS), label), _a(e, X_LEN))


def _branch_fn(tables):
    """``asm.branch(word, label, bits)``: a fixup at the current position, then the word."""
    def build(e: E):
        p = e.p
        e.var("br_n", _a(e, X_NFIX))
        _ok(e, e.lt(p["br_n"], FIX_CAP))
        e.var("br_at", e.add(_a(e, X_FIX), e.mul(p["br_n"], 3)))
        e.st(p["br_at"], _a(e, X_LEN))
        e.st(e.add(p["br_at"], 1), p["label"])
        e.st(e.add(p["br_at"], 2), p["bits"])
        _set_a(e, X_NFIX, e.add(p["br_n"], 1))
        _call(e, "x_emit", p["word"])
        e.give(0)
    return _function(("word", "label", "bits"), build, tables)


def _branch(e: E, word, label, bits: int):
    _call(e, "x_branch", word, label, bits)


# -- encodings ---------------------------------------------------------------------------------------------------------

def _sel_wide(e: E, wide, pair):
    return e.sel(e.ne(wide, 0), pair[1], pair[0])


def _mov(e: E, d, s):
    return e.add(e.add(0xAA0003E0, e.mul(s, 1 << 16)), d)


def _three(e: E, pair, wide, d, n, m):
    return e.add(e.add(e.add(_sel_wide(e, wide, pair), e.mul(m, 1 << 16)), e.mul(n, 32)), d)


def _addsub_imm(e: E, subtract, wide, d, n, encoded):
    """``_addsub_imm`` with the immediate as ``a64_addsub`` encodes it (``imm12 + 4096 * shift``)."""
    base = e.sel(e.ne(subtract, 0), e.sel(e.ne(wide, 0), 0xD1000000, 0x51000000), e.sel(e.ne(wide, 0), 0x91000000, 0x11000000))
    return e.add(e.add(e.add(e.add(base, e.mul(e.udiv(encoded, 4096), 1 << 22)), e.mul(e.and_(encoded, 4095), 1 << 10)), e.mul(n, 32)), d)


def _cmp_imm(e: E, wide, n, encoded):
    return e.add(e.add(e.add(e.sel(e.ne(wide, 0), 0xF100001F, 0x7100001F), e.mul(e.udiv(encoded, 4096), 1 << 22)), e.mul(e.and_(encoded, 4095), 1 << 10)),
                 e.mul(n, 32))


def _cmp_reg(e: E, wide, n, m):
    return e.add(e.add(e.sel(e.ne(wide, 0), 0xEB00001F, 0x6B00001F), e.mul(m, 1 << 16)), e.mul(n, 32))


def _lsl(e: E, d, n, shift, wide):
    """``_lsl``: ``ubfm`` with ``immr = -shift mod size``, ``imms = size - 1 - shift``."""
    wide_word = e.add(e.add(e.add(e.add(0xD3400000, e.mul(e.and_(e.sub(64, shift), 63), 1 << 16)), e.mul(e.sub(63, shift), 1 << 10)), e.mul(n, 32)), d)
    narrow = e.add(e.add(e.add(e.add(0x53000000, e.mul(e.and_(e.sub(32, shift), 31), 1 << 16)), e.mul(e.sub(31, shift), 1 << 10)), e.mul(n, 32)), d)
    return e.sel(e.ne(wide, 0), wide_word, narrow)


def _lsr(e: E, d, n, shift, wide):
    return e.add(e.add(e.add(e.sel(e.ne(wide, 0), 0xD340FC00, 0x53007C00), e.mul(shift, 1 << 16)), e.mul(n, 32)), d)


def _ror(e: E, d, n, shift, wide):
    return e.add(e.add(e.add(e.add(e.sel(e.ne(wide, 0), 0x93C00000, 0x13800000), e.mul(n, 1 << 16)), e.mul(shift, 1 << 10)), e.mul(n, 32)), d)


def _sbfx(e: E, d, n, width):
    return e.add(e.add(e.add(0x93400000, e.mul(e.sub(width, 1), 1 << 10)), e.mul(n, 32)), d)


def _cset(e: E, d, condition):
    return e.add(e.add(0x1A9F07E0, e.mul(e.bin(Operation.BIT_XOR, condition, 1), 1 << 12)), d)


def _size_select(e: E, size, table, load):
    """``table[size][0 if load else 1]`` for a run-time size of 1, 2, 4 or 8."""
    index = 0 if load is True else 1 if load is False else None
    words = {k: (v[0] if index == 0 else v[1]) if index is not None else e.sel(e.ne(load, 0), v[0], v[1]) for k, v in table.items()}
    return e.sel(e.eq(size, 1), words[1], e.sel(e.eq(size, 2), words[2], e.sel(e.eq(size, 4), words[4], words[8])))


def _access(e: E, load, register, base, offset, size):
    return e.add(e.add(e.add(_size_select(e, size, UNSIGNED_OFFSET, load), e.mul(e.udiv(offset, size), 1 << 10)), e.mul(base, 32)), register)


def _indexed(e: E, load, register, base, index, size, scaled):
    return e.add(e.add(e.add(e.add(_size_select(e, size, REGISTER_OFFSET, load), e.mul(e.flag(e.ne(scaled, 0)), 0x1000)), e.mul(index, 1 << 16)),
                       e.mul(base, 32)), register)


def _brk(e: E, code):
    return e.add(0xD4200000, e.mul(code, 32))


def _movimm_fn(tables):
    """``_move_immediate(register, value, wide)`` emitted."""
    from xax_selfhost_aarch64_lower import _power

    def build(e: E):
        p = e.p
        reg = p["register"]
        e.var("mi_wide", p["wide"])
        e.var("mi_v", e.sel(e.ne(p["mi_wide"], 0), p["value"], e.and_(p["value"], 0xFFFFFFFF)))
        e.if_(e.eq(p["mi_v"], 0), lambda: (_emit(e, e.add(e.sel(e.ne(p["mi_wide"], 0), 0xD2800000, 0x52800000), reg)), e.give(0)))
        e.var("mi_inv", e.sub(e.sel(e.ne(p["mi_wide"], 0), (1 << 64) - 1, 0xFFFFFFFF), p["mi_v"]))
        e.var("mi_parts", e.sel(e.ne(p["mi_wide"], 0), 4, 2))
        e.var("mi_h", 0)
        e.var("mi_ih", 0)
        e.var("mi_first_inv", NONE)
        half = lambda value, k: e.and_(e.udiv(value, _power(e, e.mul(k, 16))), 0xFFFF)  # noqa: E731

        def count():
            e.if_(e.ne(half(p["mi_v"], p["mi_k"]), 0), lambda: e.set("mi_h", e.add(p["mi_h"], 1)))

            def inverted():
                e.set("mi_ih", e.add(p["mi_ih"], 1))
                e.if_(e.eq(p["mi_first_inv"], NONE), lambda: e.set("mi_first_inv", p["mi_k"]))

            e.if_(e.ne(half(p["mi_inv"], p["mi_k"]), 0), inverted)

        e.for_("mi_k", 0, p["mi_parts"], count)

        def movn():
            e.var("mi_index", e.sel(e.eq(p["mi_first_inv"], NONE), 0, p["mi_first_inv"]))
            _emit(e, e.add(e.add(e.add(e.sel(e.ne(p["mi_wide"], 0), 0x92800000, 0x12800000), e.mul(p["mi_index"], 1 << 21)),
                                 e.mul(half(p["mi_inv"], p["mi_index"]), 32)), reg))
            e.give(0)

        e.if_(e.both(e.le(p["mi_ih"], 1), e.lt(1, p["mi_h"])), movn)
        e.var("mi_enc", e.call(_FN["a64_logical"], p["mi_v"], p["mi_wide"]))

        def orr():
            _emit(e, e.add(e.add(e.add(e.sel(e.ne(p["mi_wide"], 0), 0xB2000000, 0x32000000), e.mul(p["mi_enc"], 1 << 10)), e.mul(ZR, 32)), reg))
            e.give(0)

        e.if_(e.both(e.ne(p["mi_enc"], NONE), e.lt(1, p["mi_h"])), orr)
        e.var("mi_any", 0)

        def part():
            e.var("mi_part", half(p["mi_v"], p["mi_k"]))

            def word():
                base = e.sel(e.ne(p["mi_any"], 0), e.sel(e.ne(p["mi_wide"], 0), 0xF2800000, 0x72800000), e.sel(e.ne(p["mi_wide"], 0), 0xD2800000, 0x52800000))
                _emit(e, e.add(e.add(e.add(base, e.mul(p["mi_k"], 1 << 21)), e.mul(p["mi_part"], 32)), reg))
                e.set("mi_any", 1)

            e.if_(e.ne(p["mi_part"], 0), word)

        e.for_("mi_k", 0, p["mi_parts"], part)
        e.give(0)
    return _function(("register", "value", "wide"), build, tables)


def _mask_fn(tables):
    """``_mask(register, source, width)`` emitted: zero-extend the low ``width`` bits."""
    def build(e: E):
        p = e.p
        r, s, w = p["register"], p["source"], p["width"]
        e.if_(e.le(64, w), lambda: (e.if_(e.ne(r, s), lambda: _emit(e, _mov(e, r, s))), e.give(0)))
        e.if_(e.eq(w, 32), lambda: (_emit(e, e.add(e.add(0x2A0003E0, e.mul(s, 1 << 16)), r)), e.give(0)))
        _emit(e, e.add(e.add(e.add(0xD3400000, e.mul(e.sub(w, 1), 1 << 10)), e.mul(s, 32)), r))
        e.give(0)
    return _function(("register", "source", "width"), build, tables)


# -- locations ---------------------------------------------------------------------------------------------------------

def _location_into(e: E, value, kind: str, where: str):
    """``location(value)`` into variables ``kind`` and ``where``."""
    from xax_selfhost_aarch64_lower import V_REG, V_SLOT, _av

    p = e.p
    e.var(f"{kind}_v", value)
    e.var(kind, L_REG)
    e.var(where, _av(e, V_REG, p[f"{kind}_v"]))
    e.if_(e.eq(p[where], NONE), lambda: (e.set(kind, L_SLOT), e.set(where, e.add(_a(e, X_SPILL_BASE), e.mul(_av(e, V_SLOT, p[f"{kind}_v"]), 8)))))


def _source_into(e: E, operand, kind: str, where: str):
    """``source(operand)`` into ``kind`` and ``where``: a constant or table not hoisted, else the location."""
    from xax_selfhost_aarch64_lower import V_HOIST, V_TDATA, _av, _canon, _is_constant
    from xax_selfhost_general_ranges import G2_CVAL, _t

    p = e.p
    e.var(f"{kind}_c", _canon(e, operand, f"{kind}_cv"))
    c = p[f"{kind}_c"]
    e.var(kind, 0)
    e.var(where, 0)
    hoisted = e.ne(_av(e, V_HOIST, c), 0)

    def located():
        _location_into(e, c, f"{kind}_l", f"{where}_l")
        e.set(kind, p[f"{kind}_l"])
        e.set(where, p[f"{where}_l"])

    e.if_(e.both(_is_constant(e, c), e.not_(hoisted)), lambda: (e.set(kind, L_CONST), e.set(where, _t(e, G2_CVAL, c))), lambda: e.if_(
        e.both(e.ne(_av(e, V_TDATA, c), 0), e.not_(hoisted)), lambda: (e.set(kind, L_TABLE), e.set(where, c)), located))


def _transfer_fn(tables):
    """``_transfer(destination, source, scratch)``: one move between locations."""
    def build(e: E):
        p = e.p
        dk, dx, sk, sx, scratch = p["dk"], p["dx"], p["sk"], p["sx"], p["scratch"]
        e.if_(e.both(e.eq(dk, sk), e.eq(dx, sx)), lambda: e.give(0))

        def to_register():
            e.if_(e.eq(sk, L_REG), lambda: _emit(e, _mov(e, dx, sx)), lambda: e.if_(
                e.eq(sk, L_SLOT), lambda: _emit(e, _access(e, True, dx, SP, sx, 8)), lambda: _call(e, "x_movimm", dx, sx, 1)))
            e.give(0)

        e.if_(e.eq(dk, L_REG), to_register)
        e.if_(e.eq(sk, L_REG), lambda: (_emit(e, _access(e, False, sx, SP, dx, 8)), e.give(0)))

        def from_slot():
            _emit(e, _access(e, True, scratch, SP, sx, 8))

        def from_constant():
            e.if_(e.eq(sx, 0), lambda: (_emit(e, _access(e, False, ZR, SP, dx, 8)), e.give(0)))
            _call(e, "x_movimm", scratch, sx, 1)

        e.if_(e.eq(sk, L_SLOT), from_slot, from_constant)
        _emit(e, _access(e, False, scratch, SP, dx, 8))
        e.give(0)
    return _function(("dk", "dx", "sk", "sx", "scratch"), build, tables)


def _parallel_fn(tables):
    """``_parallel(moves)`` over ``count`` moves at ``moves`` (four words each: destination kind and place, source kind
    and place): moves whose destination no pending move reads go first; a cycle goes through ``x16``."""
    def build(e: E):
        p = e.p
        e.var("pm_pend", e.alloc(e.add(e.mul(p["count"], 4), 4)))
        _ok(e, e.ne(p["pm_pend"], NONE))
        e.var("pm_n", 0)
        at = lambda k, f: e.add(p["pm_pend"], e.add(e.mul(k, 4), f))  # noqa: E731

        def keep():
            src = e.add(p["moves"], e.mul(p["pm_k"], 4))
            same = e.both(e.eq(e.ld(src), e.ld(e.add(src, 2))), e.eq(e.ld(e.add(src, 1)), e.ld(e.add(src, 3))))
            e.if_(e.not_(same), lambda: (e.for_("pm_f", 0, 4, lambda: e.st(at(p["pm_n"], p["pm_f"]), e.ld(e.add(src, p["pm_f"])))), e.set("pm_n", e.add(p["pm_n"], 1))))

        e.for_("pm_k", 0, p["count"], keep)

        def step():
            e.var("pm_index", NONE)

            def candidate():
                e.var("pm_read", 0)
                e.for_("pm_j", 0, p["pm_n"], lambda: e.if_(e.both(e.ne(e.ld(at(p["pm_j"], 2)), L_CONST), e.eq(e.ld(at(p["pm_j"], 2)), e.ld(at(p["pm_i"], 0))),
                                                                  e.eq(e.ld(at(p["pm_j"], 3)), e.ld(at(p["pm_i"], 1)))), lambda: e.set("pm_read", 1)))
                e.if_(e.both(e.eq(p["pm_index"], NONE), e.eq(p["pm_read"], 0)), lambda: e.set("pm_index", p["pm_i"]))

            e.for_("pm_i", 0, p["pm_n"], candidate)

            def move():
                e.var("pm_dk", e.ld(at(p["pm_index"], 0)))
                e.var("pm_dx", e.ld(at(p["pm_index"], 1)))
                e.var("pm_sk", e.ld(at(p["pm_index"], 2)))
                e.var("pm_sx", e.ld(at(p["pm_index"], 3)))
                e.for_("pm_j", p["pm_index"], e.sub(p["pm_n"], 1), lambda: e.for_("pm_f", 0, 4, lambda: e.st(at(p["pm_j"], p["pm_f"]), e.ld(at(e.add(p["pm_j"], 1), p["pm_f"])))))
                e.set("pm_n", e.sub(p["pm_n"], 1))
                _call(e, "x_transfer", p["pm_dk"], p["pm_dx"], p["pm_sk"], p["pm_sx"], TRANSFER)

            def cycle():
                e.var("pm_sk0", e.ld(at(0, 2)))
                e.var("pm_sx0", e.ld(at(0, 3)))
                _call(e, "x_transfer", L_REG, CYCLE, p["pm_sk0"], p["pm_sx0"], TRANSFER)
                e.for_("pm_j", 0, p["pm_n"], lambda: e.if_(e.both(e.eq(e.ld(at(p["pm_j"], 2)), p["pm_sk0"]), e.eq(e.ld(at(p["pm_j"], 3)), p["pm_sx0"])),
                                                         lambda: (e.st(at(p["pm_j"], 2), L_REG), e.st(at(p["pm_j"], 3), CYCLE))))

            e.if_(e.ne(p["pm_index"], NONE), move, cycle)

        e.while_(lambda: e.ne(p["pm_n"], 0), step)
        e.give(0)
    return _function(("moves", "count"), build, tables)


def _moves_reset(e: E):
    _set_a(e, X_NMOVES, 0)


def _moves_add(e: E, dk, dx, sk, sx):
    p = e.p
    e.var("mv_n", _a(e, X_NMOVES))
    e.var("mv_at", e.add(_a(e, X_MOVES), e.mul(p["mv_n"], 4)))
    for k, word in enumerate((dk, dx, sk, sx)):
        e.st(e.add(p["mv_at"], k), word)
    _set_a(e, X_NMOVES, e.add(p["mv_n"], 1))


def _moves_run(e: E):
    _call(e, "x_parallel", _a(e, X_MOVES), _a(e, X_NMOVES))


# -- register access within one node -------------------------------------------------------------------------------------

def _begin(e: E):
    for k, register in enumerate(SCRATCH):
        e.st(e.add(_a(e, X_FREE), k), register)
    _set_a(e, X_NFREE, len(SCRATCH))


def _scratch_fn(tables):
    """``_scratch()``: the first free per-node scratch register."""
    def build(e: E):
        p = e.p
        e.var("sr_n", _a(e, X_NFREE))
        _ok(e, e.lt(0, p["sr_n"]))
        e.var("sr_r", e.ld(_a(e, X_FREE)))
        e.for_("sr_k", 0, e.sub(p["sr_n"], 1), lambda: e.st(e.add(_a(e, X_FREE), p["sr_k"]), e.ld(e.add(_a(e, X_FREE), e.add(p["sr_k"], 1)))))
        _set_a(e, X_NFREE, e.sub(p["sr_n"], 1))
        e.give(p["sr_r"])
    return _function((), build, tables)


def _scratch(e: E):
    return _call(e, "x_scratch")


def _read_fn(tables):
    """``read(operand)``: its register, loading or materializing it into a scratch register."""
    from xax_selfhost_aarch64_lower import _av, V_LABEL

    def build(e: E):
        p = e.p
        _source_into(e, p["operand"], "rd_k", "rd_x")
        e.if_(e.eq(p["rd_k"], L_REG), lambda: e.give(p["rd_x"]))
        e.var("rd_r", _scratch(e))

        def zero():
            e.var("rd_n", _a(e, X_NFREE))
            e.for_("rd_j", 0, p["rd_n"], lambda: e.st(e.add(_a(e, X_FREE), e.sub(p["rd_n"], p["rd_j"])), e.ld(e.add(_a(e, X_FREE), e.sub(e.sub(p["rd_n"], p["rd_j"]), 1)))))
            e.st(_a(e, X_FREE), p["rd_r"])
            _set_a(e, X_NFREE, e.add(p["rd_n"], 1))
            e.give(ZR)

        e.if_(e.eq(p["rd_k"], L_SLOT), lambda: _emit(e, _access(e, True, p["rd_r"], SP, p["rd_x"], 8)), lambda: e.if_(
            e.eq(p["rd_k"], L_TABLE), lambda: _branch(e, e.add(0x10000000, p["rd_r"]), _av(e, V_LABEL, p["rd_x"]), 21), lambda: e.if_(
                e.eq(p["rd_x"], 0), zero, lambda: _call(e, "x_movimm", p["rd_r"], p["rd_x"], 1))))
        e.give(p["rd_r"])
    return _function(("operand",), build, tables)


def _read(e: E, operand):
    return _call(e, "x_read", operand)


def _read_source_fn(tables):
    """``read_source(operand)``: ``read``, with the zero register made a real zero (register 31 is SP there)."""
    def build(e: E):
        p = e.p
        e.var("rs_r", _read(e, p["operand"]))

        def zero():
            e.set("rs_r", _scratch(e))
            _call(e, "x_movimm", p["rs_r"], 0, 1)

        e.if_(e.eq(p["rs_r"], ZR), zero)
        e.give(p["rs_r"])
    return _function(("operand",), build, tables)


def _target_fn(tables):
    """``target_register(value)``: its register, or a scratch register for a slot."""
    def build(e: E):
        p = e.p
        _location_into(e, p["value"], "tg_k", "tg_x")
        e.if_(e.eq(p["tg_k"], L_REG), lambda: e.give(p["tg_x"]))
        e.give(_scratch(e))
    return _function(("value",), build, tables)


def _commit_fn(tables):
    """``commit(value, register)``: store to the value's slot, or move to its register."""
    def build(e: E):
        p = e.p
        _location_into(e, p["value"], "cm_k", "cm_x")
        e.if_(e.eq(p["cm_k"], L_SLOT), lambda: _emit(e, _access(e, False, p["register"], SP, p["cm_x"], 8)), lambda: e.if_(
            e.ne(p["cm_x"], p["register"]), lambda: _emit(e, _mov(e, p["cm_x"], p["register"]))))
        e.give(0)
    return _function(("value", "register"), build, tables)


# -- nodes (``_Lowering._node``) ------------------------------------------------------------------------------------------

def _trap(e: E, code: int):
    """``_trap(code)``: its stub's label, the stub marked used."""
    e.st(e.add(_a(e, X_TRAPS), code), 1)
    return e.add(_nb(e), code)


def _nb(e: E):
    from xax_selfhost_aarch64_lower import A_NB

    return _a(e, A_NB)


def _w(e: E, value):
    from xax_selfhost_general_regalloc import T_RW
    from xax_selfhost_aarch64_lower import _rt_

    return _rt_(e, T_RW, value)


def _binary_fn(tables):
    """``_binary(node, result)``: add, sub, mul, and, or, xor with a folded constant or two registers."""
    from xax_selfhost_aarch64_lower import _const

    def build(e: E):
        p = e.p
        node, result = p["node"], p["result"]
        e.var("bi_op", _eop(e, node))
        op = p["bi_op"]
        e.var("bi_width", _w(e, result))
        e.var("bi_wide", e.flag(e.lt(32, p["bi_width"])))
        e.var("bi_left", _operand_(e, node, 0))
        e.var("bi_right", _operand_(e, node, 1))
        e.var("bi_fr", _call(e, "a64_folds", node, 1))
        e.var("bi_fl", _call(e, "a64_folds", node, 0))
        e.if_(e.both(e.ne(op, int(Operation.SUB_WRAP)), e.ne(p["bi_fl"], 0), e.eq(p["bi_fr"], 0)), lambda: (
            e.var("bi_t", p["bi_left"]), e.set("bi_left", p["bi_right"]), e.set("bi_right", p["bi_t"]), e.set("bi_fr", 1)))
        e.var("bi_has_c", 0)
        e.var("bi_c", 0)
        e.if_(e.ne(p["bi_fr"], 0), lambda: (_const(e, p["bi_right"], "bi_k"), e.set("bi_has_c", p["bi_k_is"]), e.set("bi_c", p["bi_k"])))
        e.var("bi_dest", 0)
        addsub = e.either(e.eq(op, int(Operation.ADD_WRAP)), e.eq(op, int(Operation.SUB_WRAP)))

        def constant():
            e.var("bi_src", 0)
            e.if_(addsub, lambda: e.set("bi_src", _call(e, "x_read_source", p["bi_left"])), lambda: e.set("bi_src", _read(e, p["bi_left"])))
            e.set("bi_dest", _call(e, "x_target", result))

            def zero():
                e.if_(e.either(e.eq(op, int(Operation.MUL_WRAP)), e.eq(op, int(Operation.BIT_AND))), lambda: _emit(e, _mov(e, p["bi_dest"], ZR)),
                      lambda: e.if_(e.ne(p["bi_dest"], p["bi_src"]), lambda: _emit(e, _mov(e, p["bi_dest"], p["bi_src"]))))
                _call(e, "x_commit", result, p["bi_dest"])
                e.give(0)

            e.if_(e.eq(p["bi_c"], 0), zero)

            def add_sub():
                e.var("bi_sub", e.flag(e.eq(op, int(Operation.SUB_WRAP))))
                e.var("bi_imm", e.call(_FN["a64_addsub"], p["bi_c"]))

                def negate():
                    e.var("bi_neg", e.sub(0, p["bi_c"]))
                    e.if_(e.eq(p["bi_wide"], 0), lambda: e.set("bi_neg", e.and_(p["bi_neg"], 0xFFFFFFFF)))
                    e.set("bi_imm", e.call(_FN["a64_addsub"], p["bi_neg"]))
                    e.set("bi_sub", e.sub(1, p["bi_sub"]))

                e.if_(e.eq(p["bi_imm"], NONE), negate)
                _emit(e, _addsub_imm(e, p["bi_sub"], p["bi_wide"], p["bi_dest"], p["bi_src"], p["bi_imm"]))

            def multiply():
                e.var("bi_shift", 0)
                e.var("bi_x", p["bi_c"])
                e.while_(lambda: e.lt(1, p["bi_x"]), lambda: (e.set("bi_x", e.udiv(p["bi_x"], 2)), e.set("bi_shift", e.add(p["bi_shift"], 1))))
                e.if_(e.ne(p["bi_shift"], 0), lambda: _emit(e, _lsl(e, p["bi_dest"], p["bi_src"], p["bi_shift"], p["bi_wide"])), lambda: e.if_(
                    e.ne(p["bi_dest"], p["bi_src"]), lambda: _emit(e, _mov(e, p["bi_dest"], p["bi_src"]))))

            def logic():
                e.var("bi_enc", e.call(_FN["a64_logical"], p["bi_c"], p["bi_wide"]))
                base = e.c(0)
                for operation, pair in LOGIC_IMM.items():
                    base = e.add(base, e.mul(e.flag(e.eq(op, int(operation))), _sel_wide(e, p["bi_wide"], pair)))
                _emit(e, e.add(e.add(e.add(base, e.mul(p["bi_enc"], 1 << 10)), e.mul(p["bi_src"], 32)), p["bi_dest"]))

            e.if_(addsub, add_sub, lambda: e.if_(e.eq(op, int(Operation.MUL_WRAP)), multiply, logic))

        def registers():
            e.var("bi_lr", _read(e, p["bi_left"]))
            e.var("bi_rr", _read(e, p["bi_right"]))
            e.set("bi_dest", _call(e, "x_target", result))
            base = e.c(0)
            for operation, pair in ((Operation.ADD_WRAP, ADD), (Operation.SUB_WRAP, SUB), (Operation.MUL_WRAP, MUL), *LOGIC_REG.items()):
                base = e.add(base, e.mul(e.flag(e.eq(op, int(operation))), _sel_wide(e, p["bi_wide"], pair)))
            e.var("bi_base", base)
            _emit(e, e.add(e.add(e.add(p["bi_base"], e.mul(p["bi_rr"], 1 << 16)), e.mul(p["bi_lr"], 32)), p["bi_dest"]))

        e.if_(e.ne(p["bi_has_c"], 0), constant, registers)
        narrow = e.both(e.ne(p["bi_width"], 32), e.ne(p["bi_width"], 64), _in_(e, op, (int(Operation.ADD_WRAP), int(Operation.SUB_WRAP), int(Operation.MUL_WRAP))))
        e.if_(narrow, lambda: _call(e, "x_mask", p["bi_dest"], p["bi_dest"], p["bi_width"]))
        _call(e, "x_commit", result, p["bi_dest"])
        e.give(0)
    return _function(("node", "result"), build, tables)


def _divide_fn(tables):
    """``_divide(node, result)``: by a power of two, or ``udiv``/``msub`` after the zero check."""
    from xax_selfhost_aarch64_lower import _const

    def build(e: E):
        p = e.p
        node, result = p["node"], p["result"]
        e.var("dv_op", _eop(e, node))
        e.var("dv_width", _w(e, result))
        e.var("dv_wide", e.flag(e.lt(32, p["dv_width"])))
        e.var("dv_dividend", _read(e, _operand_(e, node, 0)))
        _const(e, _operand_(e, node, 1), "dv_c")
        e.var("dv_dest", _call(e, "x_target", result))
        power = e.both(e.ne(p["dv_c_is"], 0), e.ne(p["dv_c"], 0), e.eq(e.and_(p["dv_c"], e.sub(p["dv_c"], 1)), 0))

        def shifted():
            e.var("dv_shift", 0)
            e.var("dv_x", p["dv_c"])
            e.while_(lambda: e.lt(1, p["dv_x"]), lambda: (e.set("dv_x", e.udiv(p["dv_x"], 2)), e.set("dv_shift", e.add(p["dv_shift"], 1))))

            def udiv():
                e.if_(e.ne(p["dv_shift"], 0), lambda: _emit(e, _lsr(e, p["dv_dest"], p["dv_dividend"], p["dv_shift"], p["dv_wide"])),
                      lambda: _emit(e, _mov(e, p["dv_dest"], p["dv_dividend"])))

            def urem():
                e.if_(e.ne(p["dv_shift"], 0), lambda: _call(e, "x_mask", p["dv_dest"], p["dv_dividend"], p["dv_shift"]),
                      lambda: _emit(e, _mov(e, p["dv_dest"], ZR)))

            e.if_(e.eq(p["dv_op"], int(Operation.UDIV)), udiv, urem)
            _call(e, "x_commit", result, p["dv_dest"])
            e.give(0)

        e.if_(power, shifted)
        e.var("dv_divisor", _read(e, _operand_(e, node, 1)))
        e.if_(e.eq(p["dv_c_is"], 0), lambda: _branch(e, e.add(e.sel(e.ne(p["dv_wide"], 0), 0xB4000000, 0x34000000), p["dv_divisor"]), _trap(e, BRK_DIVIDE_BY_ZERO), 19))
        e.if_(e.both(e.ne(p["dv_c_is"], 0), e.eq(p["dv_c"], 0)), lambda: _branch(e, 0x14000000, _trap(e, BRK_DIVIDE_BY_ZERO), 26))
        udiv_base = e.sel(e.ne(p["dv_wide"], 0), 0x9AC00800, 0x1AC00800)

        def udiv():
            _emit(e, e.add(e.add(e.add(udiv_base, e.mul(p["dv_divisor"], 1 << 16)), e.mul(p["dv_dividend"], 32)), p["dv_dest"]))

        def urem():
            e.var("dv_q", _scratch(e))
            _emit(e, e.add(e.add(e.add(udiv_base, e.mul(p["dv_divisor"], 1 << 16)), e.mul(p["dv_dividend"], 32)), p["dv_q"]))
            _emit(e, e.add(e.add(e.add(e.add(e.sel(e.ne(p["dv_wide"], 0), 0x9B008000, 0x1B008000), e.mul(p["dv_divisor"], 1 << 16)),
                                       e.mul(p["dv_dividend"], 1 << 10)), e.mul(p["dv_q"], 32)), p["dv_dest"]))

        e.if_(e.eq(p["dv_op"], int(Operation.UDIV)), udiv, urem)
        _call(e, "x_commit", result, p["dv_dest"])
        e.give(0)
    return _function(("node", "result"), build, tables)


def _compare_fn(tables):
    """``_compare(node)``: the flag-setting compare emitted; the condition code."""
    from xax_selfhost_aarch64_lower import _canon, _const

    def build(e: E):
        p = e.p
        node = p["node"]
        e.var("cp_kind", e.rd(e.add(_f(e, node, N_ATTR), 1)))
        e.var("cp_left", _operand_(e, node, 0))
        e.var("cp_right", _operand_(e, node, 1))
        e.var("cp_width", _w(e, p["cp_left"]))
        e.if_(e.eq(p["cp_width"], 0), lambda: e.set("cp_width", _w(e, _canon(e, p["cp_left"], "cp_lc"))))
        e.if_(e.eq(p["cp_width"], 0), lambda: e.set("cp_width", 64))
        e.var("cp_f0", _call(e, "a64_folds", node, 0))
        e.var("cp_f1", _call(e, "a64_folds", node, 1))

        def swap():
            e.var("cp_t", p["cp_left"])
            e.set("cp_left", p["cp_right"])
            e.set("cp_right", p["cp_t"])
            kind = e.c(0)
            for k, swapped in SWAPPED.items():
                kind = e.add(kind, e.mul(e.flag(e.eq(p["cp_kind"], int(k))), int(swapped)))
            e.var("cp_sk", kind)
            e.set("cp_kind", p["cp_sk"])

        e.if_(e.both(e.ne(p["cp_f0"], 0), e.eq(p["cp_f1"], 0)), swap)
        e.var("cp_wide", e.flag(e.lt(32, p["cp_width"])))
        cond = e.c(0)
        for k, code in COND.items():
            cond = e.add(cond, e.mul(e.flag(e.eq(p["cp_kind"], int(k))), code))
        e.var("cp_cond", cond)
        e.var("cp_lr", _call(e, "x_read_source", p["cp_left"]))
        signed = e.both(_in_(e, p["cp_kind"], SIGNED), e.ne(p["cp_width"], 32), e.ne(p["cp_width"], 64))

        def sign_extended():
            e.var("cp_rr", _read(e, p["cp_right"]))
            e.var("cp_a", e.sel(_in_(e, p["cp_lr"], SCRATCH), p["cp_lr"], 0))
            e.if_(e.not_(_in_(e, p["cp_lr"], SCRATCH)), lambda: e.set("cp_a", _scratch(e)))
            e.var("cp_b", e.sel(e.both(_in_(e, p["cp_rr"], SCRATCH), e.ne(p["cp_rr"], p["cp_a"])), p["cp_rr"], 0))
            e.if_(e.not_(e.both(_in_(e, p["cp_rr"], SCRATCH), e.ne(p["cp_rr"], p["cp_a"]))), lambda: e.set("cp_b", _scratch(e)))
            _emit(e, _sbfx(e, p["cp_a"], p["cp_lr"], p["cp_width"]), _sbfx(e, p["cp_b"], p["cp_rr"], p["cp_width"]), _cmp_reg(e, 1, p["cp_a"], p["cp_b"]))
            e.give(p["cp_cond"])

        e.if_(signed, sign_extended)
        _const(e, p["cp_right"], "cp_rc")
        e.var("cp_imm", e.call(_FN["a64_addsub"], p["cp_rc"]))
        # ``self._folds(node, 1 if right == node.operands[1] else 0)``
        e.var("cp_fold_right", e.sel(e.eq(p["cp_right"], _operand_(e, node, 1)), p["cp_f1"], p["cp_f0"]))
        immediate = e.both(e.ne(p["cp_rc_is"], 0), e.either(e.eq(p["cp_rc"], 0), e.ne(p["cp_imm"], NONE)), e.ne(p["cp_fold_right"], 0))

        def with_immediate():
            e.if_(e.eq(p["cp_rc"], 0), lambda: _emit(e, _cmp_reg(e, p["cp_wide"], p["cp_lr"], ZR)), lambda: _emit(e, _cmp_imm(e, p["cp_wide"], p["cp_lr"], p["cp_imm"])))

        e.if_(immediate, with_immediate, lambda: _emit(e, _cmp_reg(e, p["cp_wide"], p["cp_lr"], _read(e, p["cp_right"]))))
        e.give(p["cp_cond"])
    return _function(("node",), build, tables)


def _compare_constant(e: E, register, value):
    """``_compare_constant``: ``cmp`` with an immediate, or through a scratch register."""
    p = e.p
    e.var("cc_imm", e.call(_FN["a64_addsub"], value))

    def scratch():
        e.var("cc_t", _scratch(e))
        _call(e, "x_movimm", p["cc_t"], value, 1)
        _emit(e, _cmp_reg(e, 1, register, p["cc_t"]))

    e.if_(e.ne(p["cc_imm"], NONE), lambda: _emit(e, _cmp_imm(e, 1, register, p["cc_imm"])), scratch)


def _checked_fn(tables):
    """``_checked``: a checked load or store, by a constant offset, a scaled index, or a bounds-checked index."""
    from xax_selfhost_aarch64_lower import A_CHECK, _const, _node_word

    def build(e: E):
        p = e.p
        node, result = p["node"], p["result"]
        e.var("ck_size", e.rd(e.add(_f(e, node, N_ATTR), 1)))
        e.var("ck_ext", _call(e, "extent", _operand_(e, node, 0)))
        e.var("ck_load", e.flag(e.eq(_eop(e, node), int(Operation.CHECKED_LOAD_BITS_LE))))
        _const(e, _operand_(e, node, 1), "ck_ic")
        e.var("ck_neg", e.flag(e.lt(p["ck_ext"], p["ck_size"])))
        e.var("ck_bound", e.sub(p["ck_ext"], p["ck_size"]))
        e.if_(e.either(e.ne(p["ck_neg"], 0), e.both(e.ne(p["ck_ic_is"], 0), e.lt(p["ck_bound"], p["ck_ic"]))), lambda: (
            _branch(e, 0x14000000, _trap(e, BRK_MEMORY_CHECK), 26), e.give(0)))
        e.var("ck_base", _read(e, _operand_(e, node, 0)))
        e.var("ck_value", 0)
        e.if_(e.eq(p["ck_load"], 0), lambda: e.set("ck_value", _read(e, _operand_(e, node, 2))))

        def offset():
            def load():
                e.var("ck_d", _call(e, "x_target", result))
                _emit(e, _access(e, True, p["ck_d"], p["ck_base"], p["ck_ic"], p["ck_size"]))
                _call(e, "x_commit", result, p["ck_d"])

            e.if_(e.ne(p["ck_load"], 0), load, lambda: _emit(e, _access(e, False, p["ck_value"], p["ck_base"], p["ck_ic"], p["ck_size"])))
            e.give(0)

        e.if_(e.both(e.ne(p["ck_ic_is"], 0), e.eq(e.sub(p["ck_ic"], e.mul(e.udiv(p["ck_ic"], p["ck_size"]), p["ck_size"])), 0),
                     e.lt(e.udiv(p["ck_ic"], p["ck_size"]), 4096)), offset)
        e.var("ck_scaled", e.call(_FN["a64_scaled"], node))
        e.var("ck_index", 0)
        e.var("ck_shifted", 0)

        def scaled():
            e.set("ck_index", _read(e, p["ck_scaled"]))
            e.set("ck_shifted", 1)

        def checked():
            e.set("ck_index", _read(e, _operand_(e, node, 1)))
            e.var("ck_cb", e.ld(_node_word(e, A_CHECK, p["blk"], p["m"])))

            def with_bound():
                _emit(e, _cmp_reg(e, 1, p["ck_index"], _read(e, p["ck_cb"])))
                _branch(e, 0x54000000 | 8, _trap(e, BRK_MEMORY_CHECK), 19)

            def unproven():
                _compare_constant(e, p["ck_index"], p["ck_bound"])
                _branch(e, 0x54000000 | 8, _trap(e, BRK_MEMORY_CHECK), 19)

            e.if_(e.ne(p["ck_cb"], NONE), with_bound, lambda: e.if_(e.eq(_call(e, "a64_proven", node), 0), unproven))

        e.if_(e.ne(p["ck_scaled"], NONE), scaled, checked)

        def load():
            e.var("ck_d2", _call(e, "x_target", result))
            _emit(e, _indexed(e, True, p["ck_d2"], p["ck_base"], p["ck_index"], p["ck_size"], p["ck_shifted"]))
            _call(e, "x_commit", result, p["ck_d2"])

        e.if_(e.ne(p["ck_load"], 0), load, lambda: _emit(e, _indexed(e, False, p["ck_value"], p["ck_base"], p["ck_index"], p["ck_size"], p["ck_shifted"])))
        e.give(0)
    return _function(("blk", "m", "node", "result"), build, tables)


SYSCALL_ABI, C_ABI = b"linux-aarch64-syscall-v1", b"aapcs64-linux-c"
ANDROID_C_ABI = b"android-aapcs64-c"  # S15e.6h.1 (ADR-354): the Android shared object profiles' only foreign convention
ABI_SYSCALL_CLASS, ABI_C_CLASS, ABI_ANDROID_CLASS = 1, 2, 3


def _foreign_class(e: E, obj, name: str):
    """The foreign declaration ``obj``'s ABI: ``ABI_SYSCALL_CLASS``, ``ABI_C_CLASS``, ``ABI_ANDROID_CLASS``, or 0 for
    any other."""
    from xax_selfhost_views_backend import _FOREIGN_PREFIX, G_PAY, _at, _payload_uleb

    p = e.p
    e.var(name, 0)
    e.var(f"{name}_ok", 1)
    e.var(f"{name}_cur", _at(e, G_PAY, obj))
    _payload_uleb(e, f"{name}_cur")
    for k, value in enumerate(_FOREIGN_PREFIX):
        e.if_(e.ne(e.rd(e.add(p[f"{name}_cur"], k)), value), lambda: e.set(f"{name}_ok", 0))
    e.set(f"{name}_cur", e.add(p[f"{name}_cur"], len(_FOREIGN_PREFIX)))
    e.var(f"{name}_alen", _payload_uleb(e, f"{name}_cur"))
    for kind, abi in ((ABI_SYSCALL_CLASS, SYSCALL_ABI), (ABI_C_CLASS, C_ABI), (ABI_ANDROID_CLASS, ANDROID_C_ABI)):
        e.var(f"{name}_m", e.flag(e.both(e.ne(p[f"{name}_ok"], 0), e.eq(p[f"{name}_alen"], len(abi)))))
        for k, value in enumerate(abi):
            e.if_(e.ne(e.rd(e.add(p[f"{name}_cur"], k)), value), lambda: e.set(f"{name}_m", 0))
        e.if_(e.ne(p[f"{name}_m"], 0), lambda kind=kind: e.set(name, kind))
    return p[name]


def foreign_abi_rule(e: E, cls, name: str, function):
    """``_require_foreign_abi`` of a declaration of class ``cls`` (``_foreign_class`` under ``name``) in ``function``:
    on an Android shared object profile only ``android-aapcs64-c`` (S15e.6h.1, ADR-354); on Linux a syscall always and
    a C import only on the dynamic-loader profile.  Otherwise ``AARCH64-FOREIGN-ABI`` on the function's graph, quoting
    the declaration's ABI."""
    from xax_selfhost_aarch64_frame import G_A64ANDROID
    from xax_selfhost_x86_64_general import G_TFMT
    from xax_selfhost_views_backend import GLOBALS

    p = e.p
    e.var(f"{name}_android", e.flag(e.ne(e.ld(GLOBALS + G_A64ANDROID), 0)))
    e.var(f"{name}_dynamic", e.flag(e.both(e.eq(p[f"{name}_android"], 0), e.eq(e.ld(GLOBALS + G_TFMT), 7))))
    allowed = e.sel(e.ne(p[f"{name}_android"], 0), e.flag(e.eq(cls, ABI_ANDROID_CLASS)), e.flag(e.either(
        e.eq(cls, ABI_SYSCALL_CLASS), e.both(e.eq(cls, ABI_C_CLASS), e.ne(p[f"{name}_dynamic"], 0)))))

    def write():
        from xax_selfhost_aarch64_general import SITE

        e.call(_FN["diagnostic"], SITE["AARCH64-FOREIGN-ABI"], e.ld(_call(e, "interface", function)))
        D.put(e, D.T_LIST)
        e.if_(e.ne(p[f"{name}_android"], 0), lambda: (D.put(e, 1), D.text(e, ANDROID_C_ABI.decode())), lambda: (
            D.put(e, e.add(1, p[f"{name}_dynamic"])), D.text(e, SYSCALL_ABI.decode()),
            e.if_(e.ne(p[f"{name}_dynamic"], 0), lambda: D.text(e, C_ABI.decode()))))
        _call(e, "text_at", p[f"{name}_cur"], p[f"{name}_alen"])

    D.reject_unless(e, e.ne(allowed, 0), write)


def _call_fn(tables):
    """``_call(node, result)``: arguments into x0.. by parallel moves, ``bl`` (fixed up at assembly), the result
    masked to its width when something reads it."""
    from xax_selfhost_aarch64_lower import NOT_MACHINE, V_READ, _av, _machine_width
    from xax_selfhost_general_regalloc import _callee_object
    from xax_selfhost_general_view import G_VTYPE, N_GRAPH, N_OPSAT, _vf
    from xax_selfhost_views_backend import _reference

    def build(e: E):
        p = e.p
        node, result = p["node"], p["result"]
        e.var("cl_op", _eop(e, node))
        e.var("cl_target", NONE)

        def direct():
            _callee_object(e, node, "cl_callee")
            _ok(e, e.ne(p["cl_callee"], NONE))
            e.if_(e.ne(_call(e, "erased", p["cl_callee"]), 0), lambda: e.give(0))
            e.set("cl_target", p["cl_callee"])

        def foreign():
            e.var("cl_decl", _reference(e, _f(e, node, N_GRAPH), e.rd(e.sub(_f(e, node, N_OPSAT), 1))))
            _ok(e, e.ne(p["cl_decl"], NONE))
            e.var("cl_class", _foreign_class(e, p["cl_decl"], "cl_abi"))
            from xax_selfhost_aarch64_lower import A_FN

            foreign_abi_rule(e, p["cl_class"], "cl_abi", _a(e, A_FN))
            e.set("cl_target", e.add(p["cl_decl"], 1 << 40))

        e.if_(e.eq(p["cl_op"], int(Operation.CALL_DIRECT)), direct, foreign)
        _moves_reset(e)
        e.var("cl_index", 0)

        def operand():
            e.var("cl_o", _operand_(e, node, p["cl_k"]))

            def machine():
                _source_into(e, p["cl_o"], "cl_sk", "cl_sx")
                _moves_add(e, L_REG, p["cl_index"], p["cl_sk"], p["cl_sx"])
                e.set("cl_index", e.add(p["cl_index"], 1))

            e.if_(e.ne(_machine_width(e, _vf(e, G_VTYPE, p["cl_o"]), "cl_mw"), NOT_MACHINE), machine)

        e.for_("cl_k", 0, _f(e, node, N_NOPS), operand)
        _moves_run(e)
        e.var("cl_n", _a(e, X_NCALLS))
        e.st(e.add(_a(e, X_CALLS), e.mul(p["cl_n"], 2)), _a(e, X_LEN))
        e.st(e.add(_a(e, X_CALLS), e.add(e.mul(p["cl_n"], 2), 1)), p["cl_target"])
        _set_a(e, X_NCALLS, e.add(p["cl_n"], 1))
        _emit(e, 0x94000000)

        def masked():
            _location_into(e, result, "cl_rk", "cl_rx")
            e.var("cl_reg", e.sel(e.eq(p["cl_rk"], L_REG), p["cl_rx"], TRANSFER))
            _call(e, "x_mask", p["cl_reg"], 0, _w(e, result))
            e.if_(e.eq(p["cl_rk"], L_SLOT), lambda: _emit(e, _access(e, False, p["cl_reg"], SP, p["cl_rx"], 8)))

        e.if_(e.ne(result, NONE), lambda: e.if_(e.ne(_av(e, V_READ, result), 0), masked))
        e.give(0)
    return _function(("node", "result"), build, tables)


def _node_fn(tables):
    """``_node(block, node)``: one node's code."""
    from xax_selfhost_aarch64_lower import (
        A_FUSED, RESOURCE, V_BCLEAR, V_BKEEP, V_MLOW, V_MMASK, V_MSUBJ, V_TADDR, V_TSUBJ, _av, _canon,
    )
    from xax_selfhost_general_view import B_NODES, G_BLIST, G_VTYPE, _vf

    def build(e: E):
        p = e.p
        e.var("nd_b", e.ld(e.add(_g(e, G_BLIST), p["blk"])))
        e.var("nd_node", e.ld(e.add(_f(e, p["nd_b"], B_NODES), p["m"])))
        node = p["nd_node"]
        e.var("nd_op", _eop(e, node))
        op = p["nd_op"]
        e.var("nd_result", e.call(_FN["a64_defines"], p["blk"], p["m"]))
        result = p["nd_result"]
        nothing = (int(Operation.CONSTANT), int(Operation.POINTER_CAST), int(Operation.POINTER_ADDRESS), int(Operation.INT_ZERO_EXTEND),
                   int(Operation.STACK_END), *RESOURCE)
        e.if_(_in_(e, op, nothing), lambda: e.give(0))
        e.if_(e.eq(p["m"], e.ld(e.add(_a(e, A_FUSED), p["blk"]))), lambda: e.give(0))

        def truncate():
            e.if_(e.eq(result, NONE), lambda: e.give(0))
            e.var("nd_src", _read(e, _operand_(e, node, 0)))
            e.var("nd_dst", _call(e, "x_target", result))
            _call(e, "x_mask", p["nd_dst"], p["nd_src"], _w(e, result))
            _call(e, "x_commit", result, p["nd_dst"])
            e.give(0)

        e.if_(e.eq(op, int(Operation.INT_TRUNCATE)), truncate)
        has = e.ne(result, NONE)
        e.var("nd_r", e.sel(has, result, 0))

        def table():
            e.var("nd_i", _read(e, _av(e, V_TSUBJ, result)))
            e.var("nd_t", _read(e, _av(e, V_TADDR, result)))
            e.var("nd_dst", _call(e, "x_target", result))
            _emit(e, _indexed(e, True, p["nd_dst"], p["nd_t"], p["nd_i"], 1, 0))
            _call(e, "x_commit", result, p["nd_dst"])
            e.give(0)

        e.if_(e.both(has, e.ne(_av(e, V_TSUBJ, p["nd_r"]), NONE)), table)

        def member():
            from xax_selfhost_aarch64_lower import _q

            e.var("nd_low", _av(e, V_MLOW, result))
            e.var("nd_off", _call(e, "x_read_source", _av(e, V_MSUBJ, result)))

            def subtract():
                e.var("nd_src", p["nd_off"])
                e.if_(e.not_(_in_(e, p["nd_off"], SCRATCH)), lambda: e.set("nd_off", _scratch(e)))
                e.var("nd_imm", _q(e, "a64_addsub", p["nd_low"]))
                e.if_(e.ne(p["nd_imm"], NONE), lambda: _emit(e, _addsub_imm(e, 1, 1, p["nd_off"], p["nd_src"], p["nd_imm"])), lambda: (
                    _call(e, "x_movimm", p["nd_off"], p["nd_low"], 1), _emit(e, _three(e, SUB, 1, p["nd_off"], p["nd_src"], p["nd_off"]))))

            e.if_(e.ne(p["nd_low"], 0), subtract)
            e.var("nd_mask", _read(e, _av(e, V_MMASK, result)))
            e.var("nd_guard", _scratch(e))
            _emit(e, _lsr(e, p["nd_guard"], p["nd_off"], 6, 1), _addsub_imm(e, 1, 1, p["nd_guard"], p["nd_guard"], 1), _lsr(e, p["nd_guard"], p["nd_guard"], 63, 1))
            e.var("nd_dst", _call(e, "x_target", result))
            _emit(e, e.add(e.add(e.add(0x9AC02400, e.mul(p["nd_off"], 1 << 16)), e.mul(p["nd_mask"], 32)), p["nd_dst"]))
            _emit(e, _three(e, AND, 1, p["nd_dst"], p["nd_dst"], p["nd_guard"]))
            _call(e, "x_commit", result, p["nd_dst"])
            e.give(0)

        e.if_(e.both(has, e.ne(_av(e, V_MSUBJ, p["nd_r"]), NONE)), member)

        def bic():
            e.var("nd_keep", _read(e, _av(e, V_BKEEP, result)))
            e.var("nd_clear", _read(e, _av(e, V_BCLEAR, result)))
            e.var("nd_dst", _call(e, "x_target", result))
            _emit(e, e.add(e.add(e.add(0x8A200000, e.mul(p["nd_clear"], 1 << 16)), e.mul(p["nd_keep"], 32)), p["nd_dst"]))
            _call(e, "x_commit", result, p["nd_dst"])
            e.give(0)

        e.if_(e.both(has, e.ne(_av(e, V_BKEEP, p["nd_r"]), NONE)), bic)
        binary = tuple(int(x) for x in (Operation.ADD_WRAP, Operation.SUB_WRAP, Operation.MUL_WRAP, Operation.BIT_AND, Operation.BIT_OR, Operation.BIT_XOR))
        e.if_(_in_(e, op, binary), lambda: (_call(e, "x_binary", node, result), e.give(0)))
        e.if_(_in_(e, op, (int(Operation.UDIV), int(Operation.UREM))), lambda: (_call(e, "x_divide", node, result), e.give(0)))

        def compare():
            e.var("nd_cond", _call(e, "x_compare", node))
            e.var("nd_dst", _call(e, "x_target", result))
            _emit(e, _cset(e, p["nd_dst"], p["nd_cond"]))
            _call(e, "x_commit", result, p["nd_dst"])
            e.give(0)

        e.if_(e.eq(op, int(Operation.INT_COMPARE)), compare)

        def rotate():
            e.var("nd_width", _w(e, result))
            e.var("nd_attr", e.rd(e.add(_f(e, node, N_ATTR), 1)))
            e.var("nd_amount", e.sub(p["nd_attr"], e.mul(e.udiv(p["nd_attr"], p["nd_width"]), p["nd_width"])))
            e.var("nd_src", _read(e, _operand_(e, node, 0)))
            e.var("nd_dst", _call(e, "x_target", result))

            def zero():
                e.if_(e.ne(p["nd_dst"], p["nd_src"]), lambda: _emit(e, _mov(e, p["nd_dst"], p["nd_src"])))

            def native():
                _emit(e, _ror(e, p["nd_dst"], p["nd_src"], p["nd_amount"], e.flag(e.eq(p["nd_width"], 64))))

            def composed():
                e.var("nd_tmp", _scratch(e))
                _emit(e, _lsr(e, p["nd_tmp"], p["nd_src"], p["nd_amount"], 1), _lsl(e, p["nd_dst"], p["nd_src"], e.sub(p["nd_width"], p["nd_amount"]), 1))
                _emit(e, _three(e, ORR, 1, p["nd_dst"], p["nd_dst"], p["nd_tmp"]))
                _call(e, "x_mask", p["nd_dst"], p["nd_dst"], p["nd_width"])

            e.if_(e.eq(p["nd_amount"], 0), zero, lambda: e.if_(e.either(e.eq(p["nd_width"], 32), e.eq(p["nd_width"], 64)), native, composed))
            _call(e, "x_commit", result, p["nd_dst"])
            e.give(0)

        e.if_(e.eq(op, int(Operation.ROTATE_RIGHT)), rotate)

        def offset():
            from xax_selfhost_aarch64_lower import _q

            e.var("nd_base", _call(e, "x_read_source", _operand_(e, node, 0)))
            e.var("nd_dst", _call(e, "x_target", result))
            e.var("nd_offset", e.rd(e.add(_f(e, node, N_ATTR), 1)))
            e.var("nd_imm", _q(e, "a64_addsub", p["nd_offset"]))

            def scratch():
                e.var("nd_tmp", _scratch(e))
                _call(e, "x_movimm", p["nd_tmp"], p["nd_offset"], 1)
                _emit(e, _three(e, ADD, 1, p["nd_dst"], p["nd_base"], p["nd_tmp"]))

            e.if_(e.ne(p["nd_imm"], NONE), lambda: _emit(e, _addsub_imm(e, 0, 1, p["nd_dst"], p["nd_base"], p["nd_imm"])), scratch)
            _call(e, "x_commit", result, p["nd_dst"])
            e.give(0)

        e.if_(e.eq(op, int(Operation.ADDRESS_OFFSET)), offset)
        e.if_(e.eq(op, int(Operation.HEAP_VIEW)), lambda: (
            e.var("nd_raw", _read(e, _operand_(e, node, 0))), _branch(e, e.add(0xB4000000, p["nd_raw"]), _trap(e, BRK_NULL_HEAP), 19), e.give(0)))

        def rebase():
            """S15e.2b (ADR-316): trap unless ``0 <= address - view <= span`` and the distance is a multiple of the
            result's alignment (one rotate and one unsigned compare); the result aliases the address."""
            from xax_selfhost_views_backend import G_PAY, _at, _payload_uleb

            e.var("nd_extent", _call(e, "extent", _operand_(e, node, 0)))
            e.var("nd_wanted", e.rd(e.add(_f(e, node, N_ATTR), 1)))
            e.if_(e.lt(p["nd_extent"], p["nd_wanted"]), lambda: (_branch(e, 0x14000000, _trap(e, BRK_MEMORY_CHECK), 26), e.give(0)))
            e.var("nd_pat", e.add(_at(e, G_PAY, _vf(e, G_VTYPE, _output(e, node, 0))), 1))  # (an aliased result is no value here)
            for _field in range(3):  # the space, the element, the permission
                _payload_uleb(e, "nd_pat")
            e.var("nd_alignment", _payload_uleb(e, "nd_pat"))
            e.var("nd_shift", 0)
            e.var("nd_unit", 1)  # 2 ** shift: the alignment's highest power of two
            e.while_(lambda: e.le(e.mul(p["nd_unit"], 2), p["nd_alignment"]), lambda: (e.set("nd_shift", e.add(p["nd_shift"], 1)), e.set("nd_unit", e.mul(p["nd_unit"], 2))))
            e.var("nd_address", _read(e, _operand_(e, node, 1)))
            e.var("nd_view", _read(e, _operand_(e, node, 0)))
            e.var("nd_distance", _scratch(e))
            _emit(e, _three(e, SUB, 1, p["nd_distance"], p["nd_address"], p["nd_view"]))
            e.if_(e.ne(p["nd_shift"], 0), lambda: _emit(e, _ror(e, p["nd_distance"], p["nd_distance"], p["nd_shift"], 1)))
            _compare_constant(e, p["nd_distance"], e.udiv(e.sub(p["nd_extent"], p["nd_wanted"]), p["nd_unit"]))
            _branch(e, 0x54000000 | 8, _trap(e, BRK_MEMORY_CHECK), 19)  # b.hi
            e.give(0)

        e.if_(e.eq(op, int(Operation.POINTER_REBASE)), rebase)

        def load():
            e.var("nd_base", _read(e, _operand_(e, node, 0)))
            e.var("nd_dst", _call(e, "x_target", result))
            _emit(e, _access(e, True, p["nd_dst"], p["nd_base"], 0, e.rd(e.add(_f(e, node, N_ATTR), 1))))
            _call(e, "x_commit", result, p["nd_dst"])
            e.give(0)

        e.if_(_in_(e, op, (int(Operation.LOAD_BITS_LE), int(Operation.RAW_LOAD_BITS_LE))), load)

        def store():
            e.var("nd_base", _read(e, _operand_(e, node, 0)))
            e.var("nd_value", _read(e, _operand_(e, node, 1)))
            _emit(e, _access(e, False, p["nd_value"], p["nd_base"], 0, e.rd(e.add(_f(e, node, N_ATTR), 1))))
            e.give(0)

        e.if_(e.eq(op, int(Operation.STORE_BITS_LE)), store)
        e.if_(_in_(e, op, (int(Operation.CHECKED_LOAD_BITS_LE), int(Operation.CHECKED_STORE_BITS_LE))), lambda: (
            _call(e, "x_checked", p["blk"], p["m"], node, result), e.give(0)))
        e.if_(_in_(e, op, (int(Operation.CALL_DIRECT), int(Operation.CALL_FOREIGN))), lambda: (_call(e, "x_call", node, result), e.give(0)))
        _ok(e, e.eq(0, 1))  # ``raise AssertionError(op)``
        e.give(0)
    return _function(("blk", "m"), build, tables)


# -- terminators (``_terminator``, ``_conditional``, ``_through``, ``_duplicable``) ---------------------------------------

NO_CODE = tuple(int(op) for op in (Operation.CONSTANT, Operation.POINTER_CAST, Operation.POINTER_ADDRESS, Operation.INT_ZERO_EXTEND, Operation.STACK_END))


def _edge_moves_fn(tables):
    """``_edge_moves(block, edge)``: the moves into ``X_MOVES`` (only those whose destination differs from the source);
    the target block's index."""
    from xax_selfhost_aarch64_lower import V_IV, _av
    from xax_selfhost_general_view import B_EDGES, B_INPUTS, B_POS, EDGE, G_BLIST

    def build(e: E):
        p = e.p
        e.var("em_b", e.ld(e.add(_g(e, G_BLIST), p["blk"])))
        e.var("em_e", e.add(_f(e, p["em_b"], B_EDGES), e.mul(p["edge"], EDGE)))
        e.var("em_t", _f(e, p["em_e"], 0))
        _moves_reset(e)

        def argument():
            e.var("em_param", e.ld(e.add(_f(e, p["em_t"], B_INPUTS), p["em_a"])))

            def move():
                _location_into(e, p["em_param"], "em_dk", "em_dx")
                _source_into(e, e.ld(e.add(_f(e, p["em_e"], 2), p["em_a"])), "em_sk", "em_sx")
                e.if_(e.not_(e.both(e.eq(p["em_dk"], p["em_sk"]), e.eq(p["em_dx"], p["em_sx"]))), lambda: _moves_add(e, p["em_dk"], p["em_dx"], p["em_sk"], p["em_sx"]))

            e.if_(e.ne(_av(e, V_IV, p["em_param"]), 0), move)

        e.for_("em_a", 0, _f(e, p["em_e"], 1), argument)
        e.give(_f(e, p["em_t"], B_POS))
    return _function(("blk", "edge"), build, tables)


def _copy_moves(e: E, name: str):
    """A copy of the current moves (``X_MOVES``) into a fresh array: ``name`` its address, ``name_n`` its count."""
    p = e.p
    e.var(f"{name}_n", _a(e, X_NMOVES))
    e.var(name, e.alloc(e.add(e.mul(p[f"{name}_n"], 4), 1)))
    _ok(e, e.ne(p[name], NONE))
    e.for_(f"{name}_k", 0, e.mul(p[f"{name}_n"], 4), lambda: e.st(e.add(p[name], p[f"{name}_k"]), e.ld(e.add(_a(e, X_MOVES), p[f"{name}_k"]))))


def _emitting(e: E, blk, m, node, name: str):
    """The node emits code: not the fused compare, not dead, not a no-code operation or resource effect."""
    from xax_selfhost_aarch64_lower import A_DEAD, A_FUSED, RESOURCE, _node_word

    e.var(name, e.flag(e.both(e.ne(m, e.ld(e.add(_a(e, A_FUSED), blk))), e.eq(e.ld(_node_word(e, A_DEAD, blk, m)), 0),
                              e.not_(_in_(e, _eop(e, node), NO_CODE)), e.not_(_in_(e, _eop(e, node), RESOURCE)))))
    return e.p[name]


def _duplicable_fn(tables):
    """``_duplicable(block)``: a conditional block of at most four code-emitting nodes and no calls."""
    from xax_selfhost_general_view import B_KIND, B_NNODES, B_NODES, CONDITIONAL, G_BLIST

    def build(e: E):
        p = e.p
        e.var("du_b", e.ld(e.add(_g(e, G_BLIST), p["blk"])))
        e.if_(e.ne(_f(e, p["du_b"], B_KIND), CONDITIONAL), lambda: e.give(0))
        e.var("du_n", 0)
        e.var("du_call", 0)

        def node():
            e.var("du_node", e.ld(e.add(_f(e, p["du_b"], B_NODES), p["du_m"])))
            e.if_(e.ne(_emitting(e, p["blk"], p["du_m"], p["du_node"], "du_e"), 0), lambda: (
                e.set("du_n", e.add(p["du_n"], 1)), e.if_(_in_(e, _eop(e, p["du_node"]), (int(Operation.CALL_DIRECT), int(Operation.CALL_FOREIGN))),
                                                          lambda: e.set("du_call", 1))))

        e.for_("du_m", 0, _f(e, p["du_b"], B_NNODES), node)
        e.give(e.flag(e.both(e.le(p["du_n"], DUPLICATE_LIMIT), e.eq(p["du_call"], 0))))
    return _function(("blk",), build, tables)


def _through_fn(tables):
    """``_through(target)``: past blocks that emit nothing and branch on without copies."""
    from xax_selfhost_aarch64_lower import A_DEAD, RESOURCE, _node_word
    from xax_selfhost_general_view import B_KIND, B_NNODES, B_NODES, BRANCH, G_BLIST

    def build(e: E):
        p = e.p
        e.var("th_t", p["target"])
        e.var("th_seen", e.alloc(e.add(_nb(e), 1)))
        _ok(e, e.ne(p["th_seen"], NONE))
        e.for_("th_k", 0, _nb(e), lambda: e.st(e.add(p["th_seen"], p["th_k"]), 0))
        e.var("th_go", 1)

        def step():
            e.st(e.add(p["th_seen"], p["th_t"]), 1)
            e.var("th_b", e.ld(e.add(_g(e, G_BLIST), p["th_t"])))
            e.var("th_quiet", e.flag(e.eq(_f(e, p["th_b"], B_KIND), BRANCH)))
            e.for_("th_m", 0, _f(e, p["th_b"], B_NNODES), lambda: (e.var("th_node", e.ld(e.add(_f(e, p["th_b"], B_NODES), p["th_m"]))), e.if_(e.not_(e.either(
                e.ne(e.ld(_node_word(e, A_DEAD, p["th_t"], p["th_m"])), 0), _in_(e, _eop(e, p["th_node"]), NO_CODE), _in_(e, _eop(e, p["th_node"]), RESOURCE))),
                lambda: e.set("th_quiet", 0))))

            def follow():
                e.var("th_next", _call(e, "x_edge_moves", p["th_t"], 0))
                e.if_(e.ne(_a(e, X_NMOVES), 0), lambda: e.set("th_go", 0), lambda: e.set("th_t", p["th_next"]))

            e.if_(e.ne(p["th_quiet"], 0), follow, lambda: e.set("th_go", 0))

        e.while_(lambda: e.both(e.ne(p["th_go"], 0), e.eq(e.ld(e.add(p["th_seen"], p["th_t"])), 0)), step)
        e.give(p["th_t"])
    return _function(("target",), build, tables)


def _conditional_fn(tables):
    """``_conditional(block, following)``: the taken edge's copies before the test when nothing the test or the other
    path reads lives where they write; the test (a fused compare's flags, or ``cbz``/``cbnz``); stubs for edges with
    copies."""
    from xax_selfhost_aarch64_lower import A_FUSED, A_LIVEIN, A_WORDS, V_IV, _av, _bit_has
    from xax_selfhost_general_view import B_NODES, B_VALUES, G_BLIST, G_VCOUNT

    def build(e: E):
        p = e.p
        blk, following = p["blk"], p["following"]
        e.var("cd_b", e.ld(e.add(_g(e, G_BLIST), blk)))
        e.var("cd_tt", _call(e, "x_edge_moves", blk, 0))
        _copy_moves(e, "cd_tm")
        e.var("cd_ft", _call(e, "x_edge_moves", blk, 1))
        _copy_moves(e, "cd_fm")
        e.var("cd_fused", e.ld(e.add(_a(e, A_FUSED), blk)))
        # The values the test reads: a fused compare's terminator reads, else the condition (when located).
        e.var("cd_cv", e.alloc(16))
        _ok(e, e.ne(p["cd_cv"], NONE))
        e.var("cd_cn", 0)

        def fused_values():
            from xax_selfhost_aarch64_lower import A_TBUF

            e.var("cd_r", _call(e, "a64_treads", blk))
            e.for_("cd_k", 0, p["cd_r"], lambda: (e.st(e.add(p["cd_cv"], p["cd_cn"]), e.ld(e.add(_a(e, A_TBUF), p["cd_k"]))), e.set("cd_cn", e.add(p["cd_cn"], 1))))

        def condition_value():
            from xax_selfhost_aarch64_lower import _q

            e.var("cd_loc", _q(e, "a64_located", e.ld(_f(e, p["cd_b"], B_VALUES))))
            e.if_(e.ne(p["cd_loc"], NONE), lambda: (e.st(p["cd_cv"], p["cd_loc"]), e.set("cd_cn", 1)))

        e.if_(e.ne(p["cd_fused"], NONE), fused_values, condition_value)

        def early():
            # ``written & read`` empty and neither x16 nor x17 read.
            e.var("cd_clash", 0)
            tm = lambda k, f: e.ld(e.add(p["cd_tm"], e.add(e.mul(k, 4), f)))  # noqa: E731
            fm = lambda k, f: e.ld(e.add(p["cd_fm"], e.add(e.mul(k, 4), f)))  # noqa: E731

            def against(kind, where):
                e.var("ag_k", kind)
                e.var("ag_x", where)
                e.for_("cd_w", 0, p["cd_tm_n"], lambda: e.if_(e.both(e.eq(tm(p["cd_w"], 0), p["ag_k"]), e.eq(tm(p["cd_w"], 1), p["ag_x"])), lambda: e.set("cd_clash", 1)))
                e.if_(e.both(e.eq(p["ag_k"], L_REG), e.either(e.eq(p["ag_x"], CYCLE), e.eq(p["ag_x"], TRANSFER))), lambda: e.set("cd_clash", 1))

            e.for_("cd_j", 0, p["cd_fm_n"], lambda: e.if_(e.ne(fm(p["cd_j"], 2), L_CONST), lambda: against(fm(p["cd_j"], 2), fm(p["cd_j"], 3))))
            e.var("cd_in", e.add(_a(e, A_LIVEIN), e.mul(p["cd_ft"], _a(e, A_WORDS))))

            def live_value():
                e.if_(e.both(_bit_has(e, p["cd_in"], p["cd_v"]), e.ne(_av(e, V_IV, p["cd_v"]), 0)), lambda: (
                    _location_into(e, p["cd_v"], "cd_lk", "cd_lx"), against(p["cd_lk"], p["cd_lx"])))

            e.for_("cd_v", 0, _g(e, G_VCOUNT), live_value)
            e.for_("cd_j", 0, p["cd_cn"], lambda: e.if_(e.ne(_av(e, V_IV, e.ld(e.add(p["cd_cv"], p["cd_j"]))), 0), lambda: (
                _location_into(e, e.ld(e.add(p["cd_cv"], p["cd_j"])), "cd_ck", "cd_cx"), against(p["cd_ck"], p["cd_cx"]))))
            e.if_(e.eq(p["cd_clash"], 0), lambda: (_call(e, "x_parallel", p["cd_tm"], p["cd_tm_n"]), e.set("cd_tm_n", 0)))

        e.if_(e.both(e.ne(p["cd_tm_n"], 0), e.ne(p["cd_tt"], following)), early)
        e.var("cd_cond", 0)
        e.var("cd_reg", 0)

        def fused_test():
            e.var("cd_cmp", e.ld(e.add(_f(e, p["cd_b"], B_NODES), p["cd_fused"])))
            e.set("cd_cond", _call(e, "x_compare", p["cd_cmp"]))

        e.if_(e.ne(p["cd_fused"], NONE), fused_test, lambda: e.set("cd_reg", _read(e, e.ld(_f(e, p["cd_b"], B_VALUES)))))

        def jump(when_true, label):
            word = e.sel(e.ne(p["cd_fused"], NONE), e.add(0x54000000, e.sel(e.ne(when_true, 0), p["cd_cond"], e.bin(Operation.BIT_XOR, p["cd_cond"], 1))),
                         e.add(e.sel(e.ne(when_true, 0), 0x35000000, 0x34000000), p["cd_reg"]))
            _branch(e, word, label, 19)

        def stub(target, moves, count, name):
            """A stub for an edge with copies (its label), or the target's label through quiet blocks."""
            e.var(name, 0)

            def direct():
                e.set(name, _call(e, "x_through", target))

            def make():
                e.var(f"{name}_k", _a(e, X_NSTUBS))
                e.var(f"{name}_at", e.add(_a(e, X_STUBS), e.mul(p[f"{name}_k"], 3)))
                e.st(p[f"{name}_at"], moves)
                e.st(e.add(p[f"{name}_at"], 1), count)
                e.st(e.add(p[f"{name}_at"], 2), target)
                _set_a(e, X_NSTUBS, e.add(p[f"{name}_k"], 1))
                e.set(name, e.add(e.add(_nb(e), 16), p[f"{name}_k"]))

            e.if_(e.eq(count, 0), direct, make)
            return p[name]

        def false_only():
            jump(0, stub(p["cd_ft"], p["cd_fm"], p["cd_fm_n"], "cd_sf"))
            e.give(0)

        e.if_(e.both(e.eq(p["cd_tt"], following), e.eq(p["cd_tm_n"], 0)), false_only)
        jump(1, stub(p["cd_tt"], p["cd_tm"], p["cd_tm_n"], "cd_st"))
        _call(e, "x_parallel", p["cd_fm"], p["cd_fm_n"])
        e.if_(e.ne(p["cd_ft"], following), lambda: _branch(e, 0x14000000, p["cd_ft"], 26))
        e.give(0)
    return _function(("blk", "following"), build, tables)


def _terminator_fn(tables):
    """``_terminator(block)``: a return (its value into x0, the epilogue, ``ret``), a trap, a branch (its copies, then
    a duplicated short test or a jump), or a conditional branch."""
    from xax_selfhost_aarch64_lower import A_DEAD, A_IFACE, A_OWNB, NOT_MACHINE, _machine_width, _node_word
    from xax_selfhost_general_view import B_KIND, B_NNODES, B_NODES, B_NVALUES, B_PB, B_PFN, B_VALUES, BRANCH, G_BLIST, RETURN, TRAP

    def build(e: E):
        p = e.p
        blk, following = p["blk"], p["following"]
        e.var("tm_b", e.ld(e.add(_g(e, G_BLIST), blk)))
        e.var("tm_kind", _f(e, p["tm_b"], B_KIND))

        def ret():
            e.var("tm_rt", e.add(e.add(_a(e, A_IFACE), 2), e.ld(e.add(_a(e, A_IFACE), 1))))
            e.var("tm_first", NONE)
            e.for_("tm_k", 0, _f(e, p["tm_b"], B_NVALUES), lambda: e.if_(e.both(
                e.eq(p["tm_first"], NONE), e.ne(_machine_width(e, e.ld(e.add(e.add(p["tm_rt"], 1), p["tm_k"])), "tm_mw"), NOT_MACHINE),
                e.eq(e.ld(e.add(_a(e, A_OWNB), p["tm_k"])), NONE)), lambda: e.set("tm_first", e.ld(e.add(_f(e, p["tm_b"], B_VALUES), p["tm_k"])))))

            def value():
                _moves_reset(e)
                _source_into(e, p["tm_first"], "tm_sk", "tm_sx")
                _moves_add(e, L_REG, 0, p["tm_sk"], p["tm_sx"])
                _moves_run(e)

            e.if_(e.ne(p["tm_first"], NONE), value)
            _call(e, "x_epilogue")
            _emit(e, 0xD65F03C0)
            e.give(0)

        e.if_(e.eq(p["tm_kind"], RETURN), ret)

        def trap():
            e.var("tm_reason", _call(e, "x_trap_reason", _f(e, p["tm_b"], B_PFN), _f(e, p["tm_b"], B_PB)))
            _call(e, "x_movimm", 0, p["tm_reason"], 1)
            _emit(e, _brk(e, e.and_(p["tm_reason"], 0xFFFF)))
            e.give(0)

        e.if_(e.eq(p["tm_kind"], TRAP), trap)

        def branch():
            e.var("tm_t", _call(e, "x_edge_moves", blk, 0))
            _moves_run(e)

            def duplicate():
                e.var("tm_tb", e.ld(e.add(_g(e, G_BLIST), p["tm_t"])))

                def node():
                    def emit():
                        _begin(e)
                        _call(e, "x_node", p["tm_t"], p["tm_m"])

                    e.if_(e.eq(e.ld(_node_word(e, A_DEAD, p["tm_t"], p["tm_m"])), 0), emit)

                e.for_("tm_m", 0, _f(e, p["tm_tb"], B_NNODES), node)
                _begin(e)
                _call(e, "x_conditional", p["tm_t"], following)

            go = e.both(e.ne(p["tm_t"], following), e.ne(p["tm_t"], blk))
            e.if_(e.both(go, e.ne(_call(e, "x_duplicable", p["tm_t"]), 0)), duplicate, lambda: e.if_(
                e.ne(p["tm_t"], following), lambda: _branch(e, 0x14000000, p["tm_t"], 26)))
            e.give(0)

        e.if_(e.eq(p["tm_kind"], BRANCH), branch)
        _call(e, "x_conditional", blk, following)
        e.give(0)
    return _function(("blk", "following"), build, tables)


# -- the frame -----------------------------------------------------------------------------------------------------------

def _saved(e: E, k):
    return e.ld(e.add(_a(e, X_SAVED), k))


def _folded(e: E):
    """The first saved pair allocates the frame (a pre-indexed ``stp``): at least two saved registers, frame <= 504."""
    return e.both(e.le(2, _a(e, X_NSAVED)), e.le(_a(e, X_FRAME), 504))


def _pair(e: E, base, offset, first, second):
    return e.add(e.add(e.add(e.add(base, e.mul(e.udiv(offset, 8), 1 << 15)), e.mul(second, 1 << 10)), SP * 32), first)


def _save_rest(e: E, load: bool, name: str):
    """The saved registers after the folded pair (``name_k`` from, ``name_off`` the offset): pairs, then a single."""
    p = e.p

    def step():
        k, off = p[f"{name}_k"], p[f"{name}_off"]

        def two():
            _emit(e, _pair(e, 0xA9400000 if load else 0xA9000000, off, _saved(e, k), _saved(e, e.add(k, 1))))
            e.set(f"{name}_k", e.add(k, 2))
            e.set(f"{name}_off", e.add(off, 16))

        def one():
            _emit(e, _access(e, load, _saved(e, k), SP, off, 8))
            e.set(f"{name}_k", e.add(k, 1))
            e.set(f"{name}_off", e.add(off, 8))

        e.if_(e.lt(e.add(k, 1), _a(e, X_NSAVED)), two, one)

    e.while_(lambda: e.lt(p[f"{name}_k"], _a(e, X_NSAVED)), step)


def _prologue_fn(tables):
    """``_prologue()``: the frame allocated (folded into the first ``stp`` when it fits), the saved registers stored."""
    def build(e: E):
        p = e.p
        e.var("pr_k", 0)
        e.var("pr_off", 0)
        frame = _a(e, X_FRAME)

        def folded():
            _emit(e, _pair(e, 0xA9800000, e.mul(e.and_(e.sub(128, e.udiv(frame, 8)), 0x7F), 8), _saved(e, 0), _saved(e, 1)))
            e.set("pr_k", 2)
            e.set("pr_off", 16)

        e.if_(_folded(e), folded, lambda: e.if_(e.ne(frame, 0), lambda: _emit(e, e.add(e.add(0xD1000000, e.mul(frame, 1 << 10)), SP * 32 + SP))))
        _save_rest(e, False, "pr")
        e.give(0)
    return _function((), build, tables)


def _epilogue_fn(tables):
    """``_epilogue()``: the saved registers reloaded, the frame released (folded into the last ``ldp``)."""
    def build(e: E):
        p = e.p
        e.var("ep_fold", e.flag(_folded(e)))
        e.var("ep_k", e.sel(e.ne(p["ep_fold"], 0), 2, 0))
        e.var("ep_off", e.sel(e.ne(p["ep_fold"], 0), 16, 0))
        _save_rest(e, True, "ep")
        frame = _a(e, X_FRAME)
        e.if_(e.ne(p["ep_fold"], 0), lambda: _emit(e, _pair(e, 0xA8C00000, frame, _saved(e, 0), _saved(e, 1))), lambda: e.if_(
            e.ne(frame, 0), lambda: _emit(e, e.add(e.add(0x91000000, e.mul(frame, 1 << 10)), SP * 32 + SP))))
        e.give(0)
    return _function((), build, tables)


def _entry_fn(tables):
    """``_entry_moves()``: the machine parameters from x0.. into their locations (a narrow register-to-register move
    fused with its zero-extension when no other copy reads its destination or writes its source, the other narrow
    ones masked in place), then the hoisted values: a table's address by ``adr``, a constant materialized."""
    from xax_selfhost_aarch64_lower import A_ENTRY, A_IVLIST, A_NIV, V_HOIST, V_IV, V_LABEL, V_TDATA, _av
    from xax_selfhost_general_ranges import G2_CVAL, _t
    from xax_selfhost_general_view import B_INPUTS, B_NP, G_BLIST, G_VPOS, _vf

    def build(e: E):
        p = e.p
        e.var("en_b", e.ld(e.add(_g(e, G_BLIST), _a(e, A_ENTRY))))
        e.var("en_np", _f(e, p["en_b"], B_NP))
        e.var("en_mv", e.alloc(e.add(e.mul(p["en_np"], 6), 1)))  # dk, dx, sk, sx, parameter, fused
        _ok(e, e.ne(p["en_mv"], NONE))
        e.var("en_n", 0)
        e.var("en_machine", 0)
        mv = lambda k, f: e.add(p["en_mv"], e.add(e.mul(k, 6), f))  # noqa: E731

        def parameter():
            e.var("en_p", e.ld(e.add(_f(e, p["en_b"], B_INPUTS), p["en_k"])))

            def machine():
                def move():
                    _location_into(e, p["en_p"], "en_dk", "en_dx")
                    for f, word in enumerate((p["en_dk"], p["en_dx"], L_REG, p["en_machine"], p["en_p"], 0)):
                        e.st(mv(p["en_n"], f), word)
                    e.set("en_n", e.add(p["en_n"], 1))

                e.if_(e.ne(_av(e, V_IV, p["en_p"]), 0), move)
                e.set("en_machine", e.add(p["en_machine"], 1))

            e.if_(e.ne(_w(e, p["en_p"]), 0), machine)

        e.for_("en_k", 0, p["en_np"], parameter)

        def fuse():
            e.var("en_ok", e.flag(e.both(e.lt(_w(e, e.ld(mv(p["en_i"], 4))), 64), e.eq(e.ld(mv(p["en_i"], 0)), L_REG),
                                         e.ne(e.ld(mv(p["en_i"], 1)), e.ld(mv(p["en_i"], 3))))))

            def other():
                e.if_(e.both(e.eq(e.ld(mv(p["en_j"], 3)), e.ld(mv(p["en_i"], 1))), e.ne(p["en_j"], p["en_i"])), lambda: e.set("en_ok", 0))
                e.if_(e.both(e.eq(e.ld(mv(p["en_j"], 0)), L_REG), e.eq(e.ld(mv(p["en_j"], 1)), e.ld(mv(p["en_i"], 3))), e.ne(p["en_j"], p["en_i"])),
                      lambda: e.set("en_ok", 0))

            e.if_(e.ne(p["en_ok"], 0), lambda: e.for_("en_j", 0, p["en_n"], other))
            e.st(mv(p["en_i"], 5), p["en_ok"])

        e.for_("en_i", 0, p["en_n"], fuse)
        _moves_reset(e)
        e.for_("en_i", 0, p["en_n"], lambda: e.if_(e.eq(e.ld(mv(p["en_i"], 5)), 0), lambda: e.if_(
            e.not_(e.both(e.eq(e.ld(mv(p["en_i"], 0)), L_REG), e.eq(e.ld(mv(p["en_i"], 1)), e.ld(mv(p["en_i"], 3))))),
            lambda: _moves_add(e, e.ld(mv(p["en_i"], 0)), e.ld(mv(p["en_i"], 1)), L_REG, e.ld(mv(p["en_i"], 3))))))
        _moves_run(e)
        e.for_("en_i", 0, p["en_n"], lambda: e.if_(e.ne(e.ld(mv(p["en_i"], 5)), 0), lambda: _call(
            e, "x_mask", e.ld(mv(p["en_i"], 1)), e.ld(mv(p["en_i"], 3)), _w(e, e.ld(mv(p["en_i"], 4))))))

        def narrow():
            e.var("en_width", _w(e, e.ld(mv(p["en_i"], 4))))
            e.var("en_where", e.ld(mv(p["en_i"], 1)))

            def in_slot():
                _emit(e, _access(e, True, TRANSFER, SP, p["en_where"], 8))
                _call(e, "x_mask", TRANSFER, TRANSFER, p["en_width"])
                _emit(e, _access(e, False, TRANSFER, SP, p["en_where"], 8))

            e.if_(e.both(e.lt(p["en_width"], 64), e.eq(e.ld(mv(p["en_i"], 5)), 0)), lambda: e.if_(
                e.eq(e.ld(mv(p["en_i"], 0)), L_REG), lambda: _call(e, "x_mask", p["en_where"], p["en_where"], p["en_width"]), in_slot))

        e.for_("en_i", 0, p["en_n"], narrow)
        # The hoisted values by their node position.
        e.var("en_list", e.alloc(e.add(_a(e, A_NIV), 1)))
        _ok(e, e.ne(p["en_list"], NONE))
        e.var("en_h", 0)

        def hoisted():
            e.var("en_v", e.ld(e.add(_a(e, A_IVLIST), p["en_k"])))

            def insert():
                e.var("en_j", p["en_h"])
                key = lambda v: _vf(e, G_VPOS, v)  # noqa: E731
                before = lambda: e.both(e.lt(0, p["en_j"]), e.lt(key(p["en_v"]), key(e.ld(e.add(p["en_list"], e.sub(p["en_j"], 1))))))  # noqa: E731
                e.while_(before, lambda: (e.st(e.add(p["en_list"], p["en_j"]), e.ld(e.add(p["en_list"], e.sub(p["en_j"], 1)))), e.set("en_j", e.sub(p["en_j"], 1))))
                e.st(e.add(p["en_list"], p["en_j"]), p["en_v"])
                e.set("en_h", e.add(p["en_h"], 1))

            e.if_(e.ne(_av(e, V_HOIST, p["en_v"]), 0), insert)

        e.for_("en_k", 0, _a(e, A_NIV), hoisted)

        def place():
            e.var("en_v", e.ld(e.add(p["en_list"], p["en_k"])))
            _location_into(e, p["en_v"], "en_lk", "en_lx")

            def table():
                e.var("en_r", e.sel(e.eq(p["en_lk"], L_REG), p["en_lx"], TRANSFER))
                _branch(e, e.add(0x10000000, p["en_r"]), _av(e, V_LABEL, p["en_v"]), 21)
                e.if_(e.eq(p["en_lk"], L_SLOT), lambda: _emit(e, _access(e, False, p["en_r"], SP, p["en_lx"], 8)))

            def constant():
                _moves_reset(e)
                _moves_add(e, p["en_lk"], p["en_lx"], L_CONST, _t(e, G2_CVAL, p["en_v"]))
                _moves_run(e)

            e.if_(e.ne(_av(e, V_TDATA, p["en_v"]), 0), table, constant)

        e.for_("en_k", 0, p["en_h"], place)
        e.give(0)
    return _function((), build, tables)


def _trap_reason_fn(tables):
    """``decode_trap_payload``'s reason for the trap block ``pb`` of closure function ``pfn``'s graph: the ULEB heading
    its payload (the request's trap section), 0 (unspecified) for an empty payload."""
    from xax_selfhost_aarch64_lower import A_TRAPSEC
    from xax_selfhost_views_backend import G_ORDER, _cid_words

    def build(e: E):
        p = e.p
        e.var("tr_fn", e.ld(e.add(_g(e, G_ORDER), p["pfn"])))
        e.var("tr_graph", e.ld(_call(e, "interface", p["tr_fn"])))
        e.var("tr_at", _a(e, A_TRAPSEC))
        e.var("tr_n", e.rd(p["tr_at"]))
        e.set("tr_at", e.add(p["tr_at"], 1))
        cid = _cid_words(e, p["tr_graph"])
        e.var("tr_head", NONE)

        def graph():
            e.var("tr_same", e.flag(e.both(*(e.eq(e.rd(e.add(p["tr_at"], k)), word) for k, word in enumerate(cid)))))
            e.var("tr_count", e.rd(e.add(p["tr_at"], 4)))
            e.set("tr_at", e.add(p["tr_at"], 5))

            def entry():
                e.if_(e.both(e.ne(p["tr_same"], 0), e.eq(e.rd(p["tr_at"]), p["pb"])), lambda: e.set("tr_head", e.add(p["tr_at"], 2)))
                e.set("tr_at", e.add(e.add(p["tr_at"], 2), e.rd(e.add(p["tr_at"], 1))))

            e.for_("tr_j", 0, p["tr_count"], entry)

        e.for_("tr_q", 0, p["tr_n"], graph)
        e.if_(e.eq(p["tr_head"], NONE), lambda: e.give(0))
        from xax_selfhost_views_backend import _payload_uleb

        e.give(_payload_uleb(e, "tr_head"))
    return _function(("pfn", "pb"), build, tables)


# -- the function ----------------------------------------------------------------------------------------------------------

STUB_CAP, CALL_CAP, RANGE_CAP, MOVE_CAP = 1 << 16, 1 << 17, 1 << 18, 1 << 16


def emit_prologue(e: E):
    """The emission buffers (once, with the lowering's tables)."""
    for slot, words in ((X_CODE, CODE_CAP + 8), (X_FIX, 3 * FIX_CAP), (X_CALLS, 2 * CALL_CAP), (X_RANGES, 4 * RANGE_CAP), (X_FREE, 8),
                        (X_STUBS, 3 * STUB_CAP), (X_TRAPS, 16), (X_SAVED, 16), (X_MOVES, 4 * MOVE_CAP)):
        at = e.alloc(words)
        _ok(e, e.ne(at, NONE))
        _set_a(e, slot, at)


def _fixups_fn(tables):
    """Every branch fixup patched with its label's offset: 26-bit ``b``/``bl``, 21-bit ``adr``, else 19-bit (``cbz``,
    ``cbnz``, ``b.cond``); an unplaced label declines."""
    def build(e: E):
        p = e.p

        def fixup():
            e.var("fx_at", e.add(_a(e, X_FIX), e.mul(p["fx_k"], 3)))
            e.var("fx_pos", e.ld(p["fx_at"]))
            e.var("fx_bits", e.ld(e.add(p["fx_at"], 2)))
            e.var("fx_target", e.ld(e.add(_a(e, X_LABELS), e.ld(e.add(p["fx_at"], 1)))))
            _ok(e, e.ne(p["fx_target"], NONE))
            e.var("fx_code", e.add(_a(e, X_CODE), p["fx_pos"]))
            e.var("fx_word", 0)
            for k in range(4):
                e.set("fx_word", e.add(p["fx_word"], e.mul(e.ld(e.add(p["fx_code"], k)), 1 << (8 * k))))
            # The byte offset modulo 2^32 (a backward offset wraps), then its fields.
            e.var("fx_off", e.and_(e.sub(e.add(p["fx_target"], 1 << 32), p["fx_pos"]), 0xFFFFFFFF))
            e.if_(e.eq(p["fx_bits"], 26), lambda: e.set("fx_word", e.add(p["fx_word"], e.and_(e.udiv(p["fx_off"], 4), 0x3FFFFFF))), lambda: e.if_(
                e.eq(p["fx_bits"], 21), lambda: e.set("fx_word", e.add(e.add(p["fx_word"], e.mul(e.and_(p["fx_off"], 3), 1 << 29)),
                                                                     e.mul(e.and_(e.udiv(p["fx_off"], 4), 0x7FFFF), 32))),
                lambda: e.set("fx_word", e.add(p["fx_word"], e.mul(e.and_(e.udiv(p["fx_off"], 4), 0x7FFFF), 32)))))
            for k in range(4):
                e.st(e.add(p["fx_code"], k), e.and_(e.udiv(p["fx_word"], 1 << (8 * k)), 255))

        e.for_("fx_k", 0, _a(e, X_NFIX), fixup)
        e.give(0)
    return _function((), build, tables)


def _function_fn(tables):
    """``run()`` after the allocation: the frame, the prologue, the entry moves, a jump to the entry when it is not
    first, every block in layout order with its node ranges, the stubs, the used trap stubs (by code), the referenced
    predicate tables (by node position), padding, and the branch fixups.  Declined (another path) when the frame
    reaches 4096 bytes."""
    from xax_selfhost_aarch64_lower import (
        A_DEAD, A_ENTRY, A_IVLIST, A_NB, A_NCALLS, A_NIV, A_ORDER, A_SPILLS, CALLEE, V_LABEL, V_REG, V_TADDR, V_TCOUNT, V_TDATA, _av, _node_word,
        _power, _set_av,
    )
    from xax_selfhost_general_view import B_NNODES, B_NODES, G_BLIST

    def build(e: E):
        p = e.p
        nb = _a(e, A_NB)
        e.var("fn_mask", 0)

        def used():
            e.var("fn_r", _av(e, V_REG, e.ld(e.add(_a(e, A_IVLIST), p["fn_k"]))))
            # (``both`` evaluates every operand: the power is read only for a register.)
            e.if_(e.both(e.ne(p["fn_r"], NONE), e.le(CALLEE[0], p["fn_r"]), e.le(p["fn_r"], CALLEE[-1])), lambda: e.if_(
                e.eq(e.and_(e.udiv(p["fn_mask"], _power(e, p["fn_r"])), 1), 0), lambda: e.set("fn_mask", e.add(p["fn_mask"], _power(e, p["fn_r"])))))

        e.for_("fn_k", 0, _a(e, A_NIV), used)
        e.var("fn_ns", 0)
        for register in CALLEE:
            e.if_(e.ne(e.and_(e.udiv(p["fn_mask"], 1 << register), 1), 0), lambda register=register: (
                e.st(e.add(_a(e, X_SAVED), p["fn_ns"]), register), e.set("fn_ns", e.add(p["fn_ns"], 1))))
        _set_a(e, X_HAS_CALL, e.flag(e.ne(_a(e, A_NCALLS), 0)))
        e.if_(e.ne(_a(e, X_HAS_CALL), 0), lambda: (e.st(e.add(_a(e, X_SAVED), p["fn_ns"]), LR), e.set("fn_ns", e.add(p["fn_ns"], 1))))
        _set_a(e, X_NSAVED, p["fn_ns"])
        _set_a(e, X_SPILL_BASE, e.mul(p["fn_ns"], 8))
        e.var("fn_frame", e.mul(e.udiv(e.add(e.add(e.mul(p["fn_ns"], 8), e.mul(_a(e, A_SPILLS), 8)), 15), 16), 16))
        _ok(e, e.lt(p["fn_frame"], 4096))  # the bootstrap's frame path
        _set_a(e, X_FRAME, p["fn_frame"])
        # Labels: blocks, trap codes, stubs, then the predicate tables in node order.
        e.var("fn_ntab", 0)
        e.var("fn_tlist", e.alloc(e.add(_a(e, A_NIV), 1)))
        _ok(e, e.ne(p["fn_tlist"], NONE))

        def block_tables():
            e.var("fn_b", e.ld(e.add(_g(e, G_BLIST), p["fn_q"])))

            def node():
                e.var("fn_node", e.ld(e.add(_f(e, p["fn_b"], B_NODES), p["fn_m"])))

                def root():
                    e.var("fn_addr", _av(e, V_TADDR, _output(e, p["fn_node"], 0)))

                    def table():
                        _set_av(e, V_LABEL, p["fn_addr"], e.add(e.add(e.mul(nb, 3), 17), p["fn_ntab"]))
                        e.st(e.add(p["fn_tlist"], p["fn_ntab"]), p["fn_addr"])
                        e.set("fn_ntab", e.add(p["fn_ntab"], 1))

                    e.if_(e.ne(p["fn_addr"], NONE), table)

                e.if_(e.ne(_f(e, p["fn_node"], N_NRES), 0), root)

            e.for_("fn_m", 0, _f(e, p["fn_b"], B_NNODES), node)

        e.for_("fn_q", 0, nb, block_tables)
        e.var("fn_nlabels", e.add(e.add(e.mul(nb, 3), 17), p["fn_ntab"]))
        e.var("fn_labels", e.alloc(e.add(p["fn_nlabels"], 1)))
        _ok(e, e.ne(p["fn_labels"], NONE))
        e.for_("fn_k", 0, p["fn_nlabels"], lambda: e.st(e.add(p["fn_labels"], p["fn_k"]), NONE))
        _set_a(e, X_LABELS, p["fn_labels"])
        for slot in (X_LEN, X_NFIX, X_NCALLS, X_NRANGES, X_NSTUBS, X_NMOVES):
            _set_a(e, slot, 0)
        e.for_("fn_k", 0, 16, lambda: e.st(e.add(_a(e, X_TRAPS), p["fn_k"]), 0))
        _call(e, "x_prologue")
        _call(e, "x_entry")
        e.if_(e.ne(e.ld(_a(e, A_ORDER)), _a(e, A_ENTRY)), lambda: _branch(e, 0x14000000, _a(e, A_ENTRY), 26))

        def block():
            e.var("fn_bi", e.ld(e.add(_a(e, A_ORDER), p["fn_k"])))
            e.var("fn_following", e.sel(e.lt(e.add(p["fn_k"], 1), nb), e.ld(e.add(_a(e, A_ORDER), e.add(p["fn_k"], 1))), NONE))
            e.var("fn_b", e.ld(e.add(_g(e, G_BLIST), p["fn_bi"])))
            _label(e, p["fn_bi"])

            def node():
                def emit():
                    e.var("fn_start", _a(e, X_LEN))
                    _begin(e)
                    _call(e, "x_node", p["fn_bi"], p["fn_m"])

                    def ranged():
                        e.var("fn_r", _a(e, X_NRANGES))
                        _ok(e, e.lt(p["fn_r"], RANGE_CAP))
                        e.var("fn_rat", e.add(_a(e, X_RANGES), e.mul(p["fn_r"], 4)))
                        for k, word in enumerate((p["fn_bi"], p["fn_m"], p["fn_start"], _a(e, X_LEN))):
                            e.st(e.add(p["fn_rat"], k), word)
                        _set_a(e, X_NRANGES, e.add(p["fn_r"], 1))

                    e.if_(e.lt(p["fn_start"], _a(e, X_LEN)), ranged)

                e.if_(e.eq(e.ld(_node_word(e, A_DEAD, p["fn_bi"], p["fn_m"])), 0), emit)

            e.for_("fn_m", 0, _f(e, p["fn_b"], B_NNODES), node)
            _begin(e)
            _call(e, "x_terminator", p["fn_bi"], p["fn_following"])

        e.for_("fn_k", 0, nb, block)

        def stub():
            e.var("fn_sat", e.add(_a(e, X_STUBS), e.mul(p["fn_k"], 3)))
            _label(e, e.add(e.add(nb, 16), p["fn_k"]))
            _call(e, "x_parallel", e.ld(p["fn_sat"]), e.ld(e.add(p["fn_sat"], 1)))
            _branch(e, 0x14000000, e.ld(e.add(p["fn_sat"], 2)), 26)

        e.for_("fn_k", 0, _a(e, X_NSTUBS), stub)
        e.for_("fn_k", 0, 16, lambda: e.if_(e.ne(e.ld(e.add(_a(e, X_TRAPS), p["fn_k"])), 0), lambda: (
            _label(e, e.add(nb, p["fn_k"])), _emit(e, _brk(e, p["fn_k"])))))

        def table():
            e.var("fn_addr", e.ld(e.add(p["fn_tlist"], p["fn_k"])))
            e.var("fn_lab", _av(e, V_LABEL, p["fn_addr"]))
            e.var("fn_ref", 0)
            e.for_("fn_j", 0, _a(e, X_NFIX), lambda: e.if_(e.eq(e.ld(e.add(_a(e, X_FIX), e.add(e.mul(p["fn_j"], 3), 1))), p["fn_lab"]), lambda: e.set("fn_ref", 1)))

            def place():
                _label(e, p["fn_lab"])
                e.var("fn_len", _a(e, X_LEN))
                e.var("fn_count", _av(e, V_TCOUNT, p["fn_addr"]))
                _ok(e, e.lt(e.add(p["fn_len"], p["fn_count"]), CODE_CAP))
                e.for_("fn_j", 0, p["fn_count"], lambda: e.st(e.add(e.add(_a(e, X_CODE), p["fn_len"]), p["fn_j"]), e.ld(e.add(_av(e, V_TDATA, p["fn_addr"]), p["fn_j"]))))
                _set_a(e, X_LEN, e.add(p["fn_len"], p["fn_count"]))

            e.if_(e.ne(p["fn_ref"], 0), place)

        e.for_("fn_k", 0, p["fn_ntab"], table)
        e.while_(lambda: e.ne(e.and_(_a(e, X_LEN), 3), 0), lambda: (e.st(e.add(_a(e, X_CODE), _a(e, X_LEN)), 0), _set_a(e, X_LEN, e.add(_a(e, X_LEN), 1))))

        _call(e, "x_fixups")
        e.give(0)
    return _function((), build, tables)


def _write_fn(tables):
    """The function's code to the view output: its length and bytes, its calls (position, 1 for a foreign
    declaration, the callee's or declaration's CID words), its node ranges (block, node, start, end)."""
    from xax_selfhost_general_view import _out
    from xax_selfhost_views_backend import _cid_words

    def build(e: E):
        p = e.p
        _out(e, _a(e, X_LEN))
        e.for_("wr_k", 0, _a(e, X_LEN), lambda: _out(e, e.ld(e.add(_a(e, X_CODE), p["wr_k"]))))
        _out(e, _a(e, X_NCALLS))

        def call():
            e.var("wr_at", e.add(_a(e, X_CALLS), e.mul(p["wr_k"], 2)))
            e.var("wr_t", e.ld(e.add(p["wr_at"], 1)))
            e.var("wr_foreign", e.flag(e.le(1 << 40, p["wr_t"])))
            e.if_(e.ne(p["wr_foreign"], 0), lambda: e.set("wr_t", e.sub(p["wr_t"], 1 << 40)))
            _out(e, e.ld(p["wr_at"]))
            _out(e, p["wr_foreign"])
            for word in _cid_words(e, p["wr_t"]):
                _out(e, word)

        e.for_("wr_k", 0, _a(e, X_NCALLS), call)
        _out(e, _a(e, X_NRANGES))
        e.for_("wr_k", 0, e.mul(_a(e, X_NRANGES), 4), lambda: _out(e, e.ld(e.add(_a(e, X_RANGES), p["wr_k"]))))
        e.give(0)
    return _function((), build, tables)


def add_emit_functions(add, tables):
    """Every emission function, each after the functions it calls."""
    for name, builder in (("x_emit", _emit_fn), ("x_branch", _branch_fn), ("x_movimm", _movimm_fn), ("x_mask", _mask_fn),
                          ("x_transfer", _transfer_fn), ("x_parallel", _parallel_fn), ("x_scratch", _scratch_fn), ("x_read", _read_fn),
                          ("x_read_source", _read_source_fn), ("x_target", _target_fn), ("x_commit", _commit_fn), ("x_binary", _binary_fn),
                          ("x_divide", _divide_fn), ("x_compare", _compare_fn), ("x_checked", _checked_fn), ("x_call", _call_fn),
                          ("x_node", _node_fn), ("x_edge_moves", _edge_moves_fn), ("x_duplicable", _duplicable_fn), ("x_through", _through_fn),
                          ("x_conditional", _conditional_fn), ("x_prologue", _prologue_fn), ("x_epilogue", _epilogue_fn), ("x_entry", _entry_fn),
                          ("x_trap_reason", _trap_reason_fn), ("x_terminator", _terminator_fn), ("x_fixups", _fixups_fn), ("x_function", _function_fn), ("x_write", _write_fn)):
        add(name, builder(tables))
