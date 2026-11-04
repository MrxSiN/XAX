"""S15e.5 (ADR-327): ``xax_jvm``'s method code buffer (``_Code``/``_HookedCode``) as XAX functions.

The method state (``_m``, the record at ``GLOBALS + M_STATE``) holds the code buffer, the labels (block ``b`` is
``b``, its false stub ``NB + b``, the trap ``2 NB``, a fresh local label ``2 NB + 1 + k``), the fixups, the branch
targets, the ``ended`` flag, and the two deferred values (``pending``: left on the operand stack; ``stored``: its store
waits).  Every emission flushes them first (``_HookedCode.before``).  Descriptor codes: ``D_I`` ... ``D_A``.
"""

from __future__ import annotations

from xax_selfhost_facts import E
from xax_selfhost_jvm_class import blen, put
from xax_selfhost_views_backend import GLOBALS, _call

M_STATE = 210  # GLOBALS slot: the method state record
D_NONE, D_I, D_J, D_F, D_D, D_A = range(6)
D_REF = 16  # a reference descriptor: D_REF + k is the class's k-th interned descriptor text (``jk_intern``)
SLOTS = {D_I: 1, D_J: 2, D_F: 1, D_D: 2, D_A: 1}
LOAD = {D_I: 0x15, D_J: 0x16, D_F: 0x17, D_D: 0x18, D_A: 0x19}
STORE = {D_I: 0x36, D_J: 0x37, D_F: 0x38, D_D: 0x39, D_A: 0x3A}
RETURN = {D_I: 0xAC, D_J: 0xAD, D_F: 0xAE, D_D: 0xAF, D_A: 0xB0}
ZERO = {D_I: 0x03, D_J: 0x09, D_F: 0x0B, D_D: 0x0E, D_A: 0x01}

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


def _emit(e: E, word, n):
    """Append the ``n`` bytes of ``word`` (big endian), no flush."""
    put(e, _m(e, C_BUF), word, n)


def _length(e: E):
    return blen(e, _m(e, C_BUF))


def op(e: E, *values: int):
    """``code.op`` of constant bytes (at most 4 per call; longer runs are split, keeping the first's ``ended``)."""
    word = 0
    for value in values[:4]:
        word = (word << 8) | value
    _call(e, "jc_op", word, len(values[:4]))
    if len(values) > 4:
        raw(e, int.from_bytes(bytes(values[4:]), "big"), len(values) - 4)


def raw(e: E, word, n: int):
    _call(e, "jc_raw", word, n)


def branch(e: E, opcode, label):
    _call(e, "jc_branch", opcode, label)


def mark(e: E, label):
    _call(e, "jc_mark", label)


def local(e: E, store: bool, desc, slot):
    _call(e, "jc_local", 1 if store else 0, desc, slot)


# -- constants ------------------------------------------------------------------------------------------------------


def iconst(e: E, value):
    _call(e, "jc_iconst", value)


def fconst(e: E, bits, width):
    _call(e, "jc_fconst", bits, width)


def lconst(e: E, value):
    _call(e, "jc_lconst", value)


def const(e: E, desc, value):
    e.if_(e.eq(desc, D_I), lambda: iconst(e, value), lambda: lconst(e, value))


def invoke(e: E, opcode: int, index):
    """``invokestatic``/``invokespecial``/``new``... of a pool index."""
    op(e, opcode)
    raw(e, index, 2)


# -- the operand stack's depth (``_operand_stack_depth``) -------------------------------------------------------------


