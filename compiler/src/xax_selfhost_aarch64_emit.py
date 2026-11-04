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

from xax_selfhost_facts import E, NONE
from xax_selfhost_views_backend import _FN, _call


SCRATCH = (16, 17, 15, 14)

# Emission state: words of the AArch64 lowering's globals (``xax_selfhost_aarch64_lower._a``) from ``EMIT_BASE``.
EMIT_BASE = 60
(X_CODE, X_LEN, X_LABELS, X_FIX, X_NFIX, X_CALLS, X_NCALLS, X_FOREIGN, X_NFOREIGN, X_RANGES, X_NRANGES, X_FREE, X_NFREE, X_STUBS,
 X_NSTUBS, X_TRAPS, X_FRAME, X_SAVED, X_NSAVED, X_SPILL_BASE, X_FOLLOWING, X_MOVES, X_NMOVES, X_NTABLES, X_HAS_CALL, X_CAP) = range(
    EMIT_BASE, EMIT_BASE + 26)


def _a(e: E, slot: int):
    from xax_selfhost_aarch64_lower import _a as get

    return get(e, slot)


def _set_a(e: E, slot: int, value):
    from xax_selfhost_aarch64_lower import _set_a as put

    put(e, slot, value)


# -- the assembler ---------------------------------------------------------------------------------------------------


def _emit(e: E, *words):
    for word in words:
        _call(e, "x_emit", word)


def _label(e: E, label):
    e.st(e.add(_a(e, X_LABELS), label), _a(e, X_LEN))


# -- encodings ---------------------------------------------------------------------------------------------------------


def _cmp_imm(e: E, wide, n, encoded):
    return e.add(e.add(e.add(e.sel(e.ne(wide, 0), 0xF100001F, 0x7100001F), e.mul(e.udiv(encoded, 4096), 1 << 22)), e.mul(e.and_(encoded, 4095), 1 << 10)),
                 e.mul(n, 32))


def _cmp_reg(e: E, wide, n, m):
    return e.add(e.add(e.sel(e.ne(wide, 0), 0xEB00001F, 0x6B00001F), e.mul(m, 1 << 16)), e.mul(n, 32))


# -- locations ---------------------------------------------------------------------------------------------------------


# -- register access within one node -------------------------------------------------------------------------------------

def _begin(e: E):
    for k, register in enumerate(SCRATCH):
        e.st(e.add(_a(e, X_FREE), k), register)
    _set_a(e, X_NFREE, len(SCRATCH))


def _scratch(e: E):
    return _call(e, "x_scratch")


def _read(e: E, operand):
    return _call(e, "x_read", operand)


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


def _compare_constant(e: E, register, value):
    """``_compare_constant``: ``cmp`` with an immediate, or through a scratch register."""
    p = e.p
    e.var("cc_imm", e.call(_FN["a64_addsub"], value))

    def scratch():
        e.var("cc_t", _scratch(e))
        _call(e, "x_movimm", p["cc_t"], value, 1)
        _emit(e, _cmp_reg(e, 1, register, p["cc_t"]))

    e.if_(e.ne(p["cc_imm"], NONE), lambda: _emit(e, _cmp_imm(e, 1, register, p["cc_imm"])), scratch)


# -- terminators (``_terminator``, ``_conditional``, ``_through``, ``_duplicable``) ---------------------------------------


# -- the frame -----------------------------------------------------------------------------------------------------------

def _saved(e: E, k):
    return e.ld(e.add(_a(e, X_SAVED), k))


# -- the function ----------------------------------------------------------------------------------------------------------


