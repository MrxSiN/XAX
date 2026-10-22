"""S15e.5 (ADR-327): ``xax_jvm``'s method code buffer (``_Code``/``_HookedCode``) as XAX functions.

The method state (``_m``, the record at ``GLOBALS + M_STATE``) holds the code buffer, the labels (block ``b`` is
``b``, its false stub ``NB + b``, the trap ``2 NB``, a fresh local label ``2 NB + 1 + k``), the fixups, the branch
targets, the ``ended`` flag, and the two deferred values (``pending``: left on the operand stack; ``stored``: its store
waits).  Every emission flushes them first (``_HookedCode.before``).  Descriptor codes: ``D_I`` ... ``D_A``.
"""

from __future__ import annotations

from xax_selfhost_facts import E, NONE, _function
from xax_selfhost_jvm_class import B_LEN, bdata, blen, put, u2
from xax_selfhost_views_backend import GLOBALS, _call, _ok

M_STATE = 210  # GLOBALS slot: the method state record
D_NONE, D_I, D_J, D_F, D_D, D_A = range(6)
D_REF = 16  # a reference descriptor: D_REF + k is the class's k-th interned descriptor text (``jk_intern``)
SLOTS = {D_I: 1, D_J: 2, D_F: 1, D_D: 2, D_A: 1}
LOAD = {D_I: 0x15, D_J: 0x16, D_F: 0x17, D_D: 0x18, D_A: 0x19}
STORE = {D_I: 0x36, D_J: 0x37, D_F: 0x38, D_D: 0x39, D_A: 0x3A}
RETURN = {D_I: 0xAC, D_J: 0xAD, D_F: 0xAE, D_D: 0xAF, D_A: 0xB0}
ZERO = {D_I: 0x03, D_J: 0x09, D_F: 0x0B, D_D: 0x0E, D_A: 0x01}
SHORT_LOCAL = {0x15: 0x1A, 0x16: 0x1E, 0x17: 0x22, 0x18: 0x26, 0x19: 0x2A, 0x36: 0x3B, 0x37: 0x3F, 0x38: 0x43, 0x39: 0x47, 0x3A: 0x4B}
NO_FALLTHROUGH = (0xA7, 0xC8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0, 0xB1, 0xBF)
GOTO = 0xA7
CODE_CAP = 1 << 17
SLOT_LATE = 1 << 40  # ``slot_of`` -1: a constant or a value evaluated where it is read

# Method state words: the code (buffer, ended, labels, targets, fixups), the deferred values, the lines, the pool,
# the per-value slot tables, and the analyses' tables (``xax_selfhost_jvm_method``).
(C_BUF, C_ENDED, C_LABELS, C_TARGET, C_FIX, C_NFIX, C_PENDING, C_STORED, C_LINES, C_NLINES, C_POOL, C_VSLOT, C_VSDESC, C_NLABELS,
 C_READS, C_COUNTING) = range(16)
CODE_FIELDS = 16


def _m(e: E, field: int):
    return e.ld(e.add(e.ld(GLOBALS + M_STATE), field))


def _set_m(e: E, field: int, value):
    e.st(e.add(e.ld(GLOBALS + M_STATE), field), value)


def kind(e: E, desc):
    """The opcode family of a descriptor code: a reference is ``D_A``."""
    return e.sel(e.lt(desc, D_REF), desc, D_A)


def _in(e: E, value, items):
    return e.either(*(e.eq(value, item) for item in items))


def _pick(e: E, key, table: dict, default=0):
    """``table[key]`` for a computed key (``default`` outside the table)."""
    result = e.c(default)
    for k, v in table.items():
        result = e.sel(e.eq(key, k), v, result)
    return result


def _emit(e: E, word, n):
    """Append the ``n`` bytes of ``word`` (big endian), no flush."""
    put(e, _m(e, C_BUF), word, n)


def _length(e: E):
    return blen(e, _m(e, C_BUF))


def _flush_fn(tables):
    """``flush``: the pending value, then the stored one, stored to their locals."""
    def build(e: E):
        p = e.p
        for holder in (C_PENDING, C_STORED):
            def one(holder=holder):
                e.var("fl_ref", _m(e, holder))
                _set_m(e, holder, NONE)
                _local_bytes(e, e.c(1), e.ld(e.add(_m(e, C_VSDESC), p["fl_ref"])), e.ld(e.add(_m(e, C_VSLOT), p["fl_ref"])), _emit_ended)

            e.if_(e.ne(_m(e, holder), NONE), one)
        e.give(1)
    return _function((), build, tables)


def _flush(e: E):
    e.if_(e.either(e.ne(_m(e, C_PENDING), NONE), e.ne(_m(e, C_STORED), NONE)), lambda: _call(e, "jc_flush"))


def _op_fn(tables):
    """``code.op``: flush, the ``n`` bytes of ``word`` (big endian); ``ended`` when its first byte never falls
    through."""
    def build(e: E):
        p = e.p
        _flush(e)
        _emit(e, p["word"], p["n"])
        e.var("op_first", e.udiv(p["word"], e.sel(e.eq(p["n"], 1), 1, e.sel(e.eq(p["n"], 2), 1 << 8, e.sel(e.eq(p["n"], 3), 1 << 16, 1 << 24)))))
        _set_m(e, C_ENDED, e.flag(_in(e, e.and_(p["op_first"], 255), NO_FALLTHROUGH)))
        e.give(1)
    return _function(("word", "n"), build, tables)


def op(e: E, *values: int):
    """``code.op`` of constant bytes (at most 4 per call; longer runs are split, keeping the first's ``ended``)."""
    word = 0
    for value in values[:4]:
        word = (word << 8) | value
    _call(e, "jc_op", word, len(values[:4]))
    if len(values) > 4:
        raw(e, int.from_bytes(bytes(values[4:]), "big"), len(values) - 4)


def opx(e: E, word, n: int):
    """``code.op`` of computed bytes."""
    _call(e, "jc_op", word, n)


def _raw_fn(tables):
    def build(e: E):
        p = e.p
        _flush(e)
        _emit(e, p["word"], p["n"])
        e.give(1)
    return _function(("word", "n"), build, tables)


def raw(e: E, word, n: int):
    _call(e, "jc_raw", word, n)


def _branch_fn(tables):
    """``code.branch(opcode, label)``: a fixup, the label a target, the opcode and two zero bytes."""
    def build(e: E):
        p = e.p
        _flush(e)
        e.var("br_n", _m(e, C_NFIX))
        e.var("br_at", e.add(_m(e, C_FIX), e.mul(p["br_n"], 2)))
        e.st(p["br_at"], _length(e))
        e.st(e.add(p["br_at"], 1), p["label"])
        _set_m(e, C_NFIX, e.add(p["br_n"], 1))
        e.st(e.add(_m(e, C_TARGET), p["label"]), 1)
        _emit(e, e.mul(p["opcode"], 1 << 16), 3)
        _set_m(e, C_ENDED, e.flag(e.eq(p["opcode"], GOTO)))
        e.give(1)
    return _function(("opcode", "label"), build, tables)


def branch(e: E, opcode, label):
    _call(e, "jc_branch", opcode, label)


def _mark_fn(tables):
    """``code.mark(label)``: its position; a target when the code before it never falls through."""
    def build(e: E):
        p = e.p
        _flush(e)
        e.st(e.add(_m(e, C_LABELS), p["label"]), _length(e))
        e.if_(e.ne(_m(e, C_ENDED), 0), lambda: e.st(e.add(_m(e, C_TARGET), p["label"]), 1))
        e.give(1)
    return _function(("label",), build, tables)


def mark(e: E, label):
    _call(e, "jc_mark", label)


def _emit_ended(e: E, word, n):
    """``code.op`` without a flush: a load or store never ends the code."""
    _emit(e, word, n)
    _set_m(e, C_ENDED, 0)


def _local_bytes(e: E, store, desc, slot, out):
    """The load (``store`` 0) or store of ``slot`` through ``out(e, word, n)``."""
    p = e.p
    e.var("lo_k", kind(e, desc))
    e.var("lo_op", e.sel(e.ne(store, 0), _pick(e, p["lo_k"], STORE), _pick(e, p["lo_k"], LOAD)))
    _ok(e, e.ne(p["lo_op"], 0))
    e.var("lo_slot", slot)
    e.if_(e.le(p["lo_slot"], 3), lambda: out(e, e.add(_pick(e, p["lo_op"], SHORT_LOCAL), p["lo_slot"]), 1), lambda: e.if_(
        e.le(p["lo_slot"], 0xFF), lambda: out(e, e.add(e.mul(p["lo_op"], 256), p["lo_slot"]), 2),
        lambda: (out(e, e.add(0xC400, p["lo_op"]), 2), _emit(e, p["lo_slot"], 2))))


def _local_fn(tables):
    """``local(table, descriptor, slot)``: ``store`` 1 is the store table, 0 the load table."""
    def build(e: E):
        p = e.p
        _local_bytes(e, p["store"], p["desc"], p["slot"], opx)
        e.give(1)
    return _function(("store", "desc", "slot"), build, tables)


def local(e: E, store: bool, desc, slot):
    _call(e, "jc_local", 1 if store else 0, desc, slot)


# -- constants ------------------------------------------------------------------------------------------------------

def _ldc_fn(tables):
    def build(e: E):
        p = e.p
        e.if_(e.le(p["index"], 0xFF), lambda: opx(e, e.add(0x1200, p["index"]), 2), lambda: (op(e, 0x13), raw(e, p["index"], 2)))
        e.give(1)
    return _function(("index",), build, tables)


def _iconst_fn(tables):
    """``iconst(value)``: ``iconst_m1``..``iconst_5``, ``bipush``, ``sipush``, else ``ldc`` of an Integer."""
    def build(e: E):
        p = e.p
        e.var("ic_v", e.and_(p["value"], 0xFFFFFFFF))
        # signed + 2^31 orders the signed values as unsigned ones
        e.var("ic_b", _bx(e, p["ic_v"], 1 << 31))

        def small():
            opx(e, e.and_(e.add(0x03, e.sub(p["ic_v"], 0)), 0xFF), 1)

        in_range = lambda low, high: e.both(e.le((1 << 31) + low, p["ic_b"]), e.le(p["ic_b"], (1 << 31) + high))  # noqa: E731
        e.if_(in_range(-1, 5), lambda: opx(e, e.and_(e.add(p["ic_v"], 3), 0xFF), 1), lambda: e.if_(
            in_range(-128, 127), lambda: opx(e, e.add(0x1000, e.and_(p["ic_v"], 0xFF)), 2), lambda: e.if_(
                in_range(-32768, 32767), lambda: (op(e, 0x11), raw(e, e.and_(p["ic_v"], 0xFFFF), 2)),
                lambda: _call(e, "jc_ldc", _call(e, "jp_number", _m(e, C_POOL), 3, p["ic_v"])))))
        e.give(1)
    return _function(("value",), build, tables)


def iconst(e: E, value):
    _call(e, "jc_iconst", value)


def _lconst_fn(tables):
    def build(e: E):
        p = e.p
        e.if_(e.lt(p["value"], 2), lambda: opx(e, e.add(0x09, p["value"]), 1),
              lambda: (op(e, 0x14), e.var("lc_i", _call(e, "jp_number", _m(e, C_POOL), 5, p["value"])), raw(e, p["lc_i"], 2)))
        e.give(1)
    return _function(("value",), build, tables)


def _fconst_fn(tables):
    """``fconst_bits(bits, width)``: ``fconst_0``..``fconst_2``/``dconst_0``..``dconst_1``, else ``ldc`` of a Float or
    ``ldc2_w`` of a Double (raw bits, so NaN payloads stay exact)."""
    def build(e: E):
        p = e.p

        def single():
            e.if_(e.eq(p["bits"], 0), lambda: op(e, 0x0B), lambda: e.if_(e.eq(p["bits"], 0x3F800000), lambda: op(e, 0x0C), lambda: e.if_(
                e.eq(p["bits"], 0x40000000), lambda: op(e, 0x0D), lambda: _call(e, "jc_ldc", _call(e, "jp_number", _m(e, C_POOL), 4, p["bits"])))))

        def double():
            e.if_(e.eq(p["bits"], 0), lambda: op(e, 0x0E), lambda: e.if_(e.eq(p["bits"], 0x3FF0000000000000), lambda: op(e, 0x0F), lambda: (
                op(e, 0x14), e.var("fk_i", _call(e, "jp_number", _m(e, C_POOL), 6, p["bits"])), raw(e, p["fk_i"], 2))))

        e.if_(e.eq(p["width"], 32), single, double)
        e.give(1)
    return _function(("bits", "width"), build, tables)


def fconst(e: E, bits, width):
    _call(e, "jc_fconst", bits, width)


def lconst(e: E, value):
    _call(e, "jc_lconst", value)


def const(e: E, desc, value):
    e.if_(e.eq(desc, D_I), lambda: iconst(e, value), lambda: lconst(e, value))


def _bx(e: E, x, y):
    from xax_compiler import Operation

    return e.bin(Operation.BIT_XOR, x, y)


def invoke(e: E, opcode: int, index):
    """``invokestatic``/``invokespecial``/``new``... of a pool index."""
    op(e, opcode)
    raw(e, index, 2)


# -- the operand stack's depth (``_operand_stack_depth``) -------------------------------------------------------------

def _effects():
    """(length, pops, pushes) of every fixed-form opcode, 0 length for the ones read from the pool or decoded."""
    from xax_jvm import _STACK_EFFECT

    return {opcode: effect for opcode, effect in _STACK_EFFECT.items()}


def _depth_fn(tables):
    """The deepest operand stack the method code reaches: one pass, restarting at each frame offset (``frames``,
    sorted, ``nframes``) and after an instruction that never falls through.  Pool-reading forms read the argument and
    result slots the pool recorded; ``tableswitch``, ``lookupswitch`` and ``multianewarray`` are never emitted here."""
    from xax_selfhost_jvm_class import P_ARGS, P_RESULT

    effects = _effects()

    def build(e: E):
        p = e.p
        e.var("dp_code", bdata(e, _m(e, C_BUF)))
        e.var("dp_n", _length(e))
        e.var("dp_pool", _m(e, C_POOL))
        e.var("dp_depth", 0)
        e.var("dp_deep", 0)
        e.var("dp_pc", 0)
        e.var("dp_f", 0)

        def byte(k):
            return e.ld(e.add(p["dp_code"], e.add(p["dp_pc"], k)))

        def step():
            e.while_(lambda: e.both(e.lt(p["dp_f"], p["nframes"]), e.lt(e.ld(e.add(p["frames"], p["dp_f"])), p["dp_pc"])),
                     lambda: e.set("dp_f", e.add(p["dp_f"], 1)))
            e.if_(e.both(e.lt(p["dp_f"], p["nframes"]), e.eq(e.ld(e.add(p["frames"], p["dp_f"])), p["dp_pc"])), lambda: e.set("dp_depth", 0))
            e.var("dp_op", byte(0))
            e.var("dp_len", 0)
            e.var("dp_pops", 0)
            e.var("dp_push", 0)
            for opcode, (length, pops, pushes) in effects.items():
                e.if_(e.eq(p["dp_op"], opcode), lambda length=length, pops=pops, pushes=pushes: (
                    e.set("dp_len", length), e.set("dp_pops", pops), e.set("dp_push", pushes)))

            def invocation():
                e.var("dp_ix", e.add(e.mul(byte(1), 256), byte(2)))
                e.set("dp_len", e.sel(e.eq(p["dp_op"], 0xB9), 5, 3))
                e.set("dp_pops", e.add(e.ld(e.add(_pool_field(e, p["dp_pool"], P_ARGS), p["dp_ix"])), e.flag(e.ne(p["dp_op"], 0xB8))))
                e.set("dp_push", e.ld(e.add(_pool_field(e, p["dp_pool"], P_RESULT), p["dp_ix"])))

            e.if_(_in(e, p["dp_op"], (0xB6, 0xB7, 0xB8, 0xB9)), invocation)

            def field_access():
                # getstatic, putstatic, getfield, putfield: the field's size is its entry's recorded result slots.
                e.var("dp_fx", e.add(e.mul(byte(1), 256), byte(2)))
                e.var("dp_size", e.ld(e.add(_pool_field(e, p["dp_pool"], P_RESULT), p["dp_fx"])))
                e.set("dp_len", 3)
                e.var("dp_fo", e.sub(p["dp_op"], 0xB2))
                e.set("dp_pops", e.sel(e.eq(p["dp_fo"], 0), 0, e.sel(e.eq(p["dp_fo"], 1), p["dp_size"], e.sel(e.eq(p["dp_fo"], 2), 1, e.add(1, p["dp_size"])))))
                e.set("dp_push", e.sel(e.either(e.eq(p["dp_fo"], 0), e.eq(p["dp_fo"], 2)), p["dp_size"], 0))

            e.if_(_in(e, p["dp_op"], (0xB2, 0xB3, 0xB4, 0xB5)), field_access)

            def wide():
                e.var("dp_inner", byte(1))
                e.set("dp_len", e.sel(e.eq(p["dp_inner"], 0x84), 6, 4))
                for opcode, (_length2, pops, pushes) in effects.items():
                    e.if_(e.eq(p["dp_inner"], opcode), lambda pops=pops, pushes=pushes: (e.set("dp_pops", pops), e.set("dp_push", pushes)))

            e.if_(e.eq(p["dp_op"], 0xC4), wide)
            _ok(e, e.ne(p["dp_len"], 0))  # a form this backend does not emit here
            e.set("dp_depth", e.sub(e.add(p["dp_depth"], p["dp_push"]), p["dp_pops"]))
            e.if_(e.both(e.lt(p["dp_deep"], p["dp_depth"]), e.lt(p["dp_depth"], 1 << 62)), lambda: e.set("dp_deep", p["dp_depth"]))
            e.if_(_in(e, p["dp_op"], NO_FALLTHROUGH), lambda: e.set("dp_depth", 0))
            e.set("dp_pc", e.add(p["dp_pc"], p["dp_len"]))

        e.while_(lambda: e.lt(p["dp_pc"], p["dp_n"]), step)
        e.give(p["dp_deep"])
    return _function(("frames", "nframes"), build, tables)


def _pool_field(e: E, pool, field):
    return e.ld(e.add(pool, field))


def add_code_functions(add, tables):
    for name, builder in (("jc_flush", _flush_fn), ("jc_op", _op_fn), ("jc_raw", _raw_fn), ("jc_local", _local_fn), ("jc_branch", _branch_fn),
                          ("jc_mark", _mark_fn), ("jc_ldc", _ldc_fn), ("jc_iconst", _iconst_fn), ("jc_lconst", _lconst_fn), ("jc_fconst", _fconst_fn), ("jc_depth", _depth_fn)):
        add(name, builder(tables))
