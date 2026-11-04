"""S15e.5 (ADR-327): the analyses of ``xax_jvm._compile_method_pass`` as XAX functions (stage S15e.5a: the integer
subset of ``jvm-classfile-v1``).

Over the function's own graph (``lift``; a value's ``G_VPOS`` is its ``ValueRef`` order), in the bootstrap's order:
integer constants and their folding, aliases (a block entered by exactly one edge takes that edge's arguments),
the values ``needed`` (dead pure nodes are eliminated), the descriptors, known widths, uses, copies, the implicit
reads, fused compares, the expression trees evaluated where they are read (the second pass), liveness over the
CFG, interference, coalescing hints, the framed values, and the slot coloring with the frame's local types.

Per-value tables are ``_v(table, value)``; per-node flags ``_n(table, node id)`` (a node's id is its block's base
plus its index); per-block words ``_b(table, block)``.  Sets over the tracked values are word arrays (one word per
tracked value), so liveness and interference are those arrays and a ``T x T`` matrix.
"""

from __future__ import annotations

from xax_compiler import Operation
from xax_selfhost_facts import E, NONE
from xax_selfhost_general_frame import _bits_width
from xax_selfhost_general_regalloc import _eop
from xax_selfhost_general_view import G_VTYPE, _vf
from xax_selfhost_jvm_code import CODE_FIELDS, _m
from xax_selfhost_views_backend import _call

# Per-value tables (``_v``), after the code state's fields.
VALUE_TABLES = ("V_DESC", "V_CONST", "V_CVAL", "V_FOLDED", "V_ALIAS", "V_NEEDED", "V_DESCOF", "V_KW", "V_USES", "V_IMPLICIT", "V_FUSED",
                "V_INLINED", "V_COPYOF", "V_BIT", "V_SINGLE", "V_SITE", "V_NUSERS", "V_USER", "V_KEPT", "V_HINTS")
(V_DESC, V_CONST, V_CVAL, V_FOLDED, V_ALIAS, V_NEEDED, V_DESCOF, V_KW, V_USES, V_IMPLICIT, V_FUSED, V_INLINED, V_COPYOF, V_BIT, V_SINGLE,
 V_SITE, V_NUSERS, V_USER, V_KEPT, V_HINTS) = range(CODE_FIELDS, CODE_FIELDS + len(VALUE_TABLES))
# Per-node and per-block tables, and scalars.
(N_ELIM, N_COPY, N_LINE, BL_BASE, BL_INC, BL_REACH, BL_UP, BL_DEF, BL_LIVE, BL_PRED, BL_NPRED, BL_RESOLVED, BL_ORDER, BL_PLACED,
 M_NV, M_NB, M_NN, M_ENTRY, M_T, M_TRACK, M_INTER, M_ACROSS, M_FRAMED, M_HINT, M_NHINT, M_STYPE, M_SOCC, M_NSOCC, M_FREED, M_NEXT,
 M_PEND, M_GEND, M_TYPED, M_FTYPES, M_NFTYPES, M_PASS, M_KEPTNONE, M_FN, M_SCRATCH, M_MAXLOC, M_NORDER, M_MAXSLOTS, M_ONE, M_WORK,
 M_RETTYPES, M_NRET, M_TRAPUSED, M_MAXCALL, M_LABELN, M_FOLLOW, M_NEEDS_PK, M_NEEDZ, M_PSLOTS, M_ISENTRY, M_MNEEDS, M_MBYTES, M_MNBYTES,
 N_RUN, N_INRUN, M_FSLOT, M_FSIZE, N_FOFF) = range(CODE_FIELDS + len(VALUE_TABLES), CODE_FIELDS + len(VALUE_TABLES) + 62)

ARITHMETIC = tuple(int(op) for op in (Operation.ADD_WRAP, Operation.SUB_WRAP, Operation.MUL_WRAP, Operation.BIT_AND, Operation.BIT_OR,
                                      Operation.BIT_XOR))
OP = {name: int(getattr(Operation, name)) for name in (
    "ADD_WRAP", "SUB_WRAP", "MUL_WRAP", "BIT_AND", "BIT_OR", "BIT_XOR", "ROTATE_RIGHT", "INT_TRUNCATE", "INT_ZERO_EXTEND", "INT_COMPARE",
    "CONSTANT", "CALL_DIRECT", "UDIV", "UREM", "HEAP_VIEW", "POINTER_CAST", "FLOAT_ADD", "FLOAT_SUB", "FLOAT_MUL", "FLOAT_DIV",
    "FLOAT_CONVERT", "FLOAT_COMPARE", "UINT_TO_FLOAT", "SINT_TO_FLOAT", "FLOAT_TO_UINT_TRUNC", "FLOAT_TO_SINT_TRUNC", "CALL_FOREIGN",
    "FUNCTION_ADDRESS", "AGGREGATE_MAKE", "AGGREGATE_GET", "SUM_MAKE", "SUM_TAG", "SUM_GET", "LOAD_BITS_LE", "STORE_BITS_LE",
    "CHECKED_LOAD_BITS_LE", "CHECKED_STORE_BITS_LE", "ADDRESS_OFFSET", "POINTER_ADDRESS", "POINTER_REBASE")}


# -- accessors --------------------------------------------------------------------------------------------------------

def _v(e: E, table: int, value):
    return e.ld(e.add(_m(e, table), value))


def _type(e: E, value):
    return _vf(e, G_VTYPE, value)


def _width(e: E, value, name: str):
    """``_width`` of the value's bits type into ``name`` (a link is 32 bits, ADR-160)."""
    type_width(e, _type(e, value), name)


def type_width(e: E, t, name: str):
    """``_width`` of TYPE ``t`` into ``name``: a link's 32 bits, else its bits width."""
    from xax_selfhost_views_backend import _type_form

    e.var(f"{name}_t", t)
    _bits_width(e, e.p[f"{name}_t"], name)
    e.if_(e.eq(_type_form(e, e.p[f"{name}_t"]), 11), lambda: e.set(name, 32))


def canon(e: E, value):
    return _call(e, "jm_canon", value)


# -- stage 1: types, constants, folding -------------------------------------------------------------------------------


# -- aliases, needed values, eliminated nodes ---------------------------------------------------------------------------


def carried(e: E, target, param):
    """``carried(target, index)``: the parameter is not an alias, and needed or the entry's."""
    return e.both(e.eq(_v(e, V_ALIAS, param), NONE), e.either(e.ne(_v(e, V_NEEDED, param), 0), e.eq(target, _m(e, M_ENTRY))))


# -- descriptors, widths, uses, copies -----------------------------------------------------------------------------------


def elided(e: E, node, name: str):
    """``borrowed_view_returns`` of a direct call of a function that is not an erased proof function: per result the
    operand it gives back (NONE: a machine result), else NONE."""
    from xax_selfhost_general_regalloc import _callee_object

    p = e.p
    e.var(name, NONE)

    def direct():
        _callee_object(e, node, f"{name}_f")
        e.if_(e.ne(p[f"{name}_f"], NONE), lambda: e.if_(e.eq(_call(e, "erased", p[f"{name}_f"]), 0), lambda: e.set(name, _call(e, "borrowed", p[f"{name}_f"]))))

    e.if_(e.eq(_eop(e, node), OP["CALL_DIRECT"]), direct)
    return p[name]


def late(e: E, value):
    return e.either(e.ne(_v(e, V_INLINED, value), 0), e.ne(_v(e, V_FUSED, value), 0))


# -- tracked values, liveness, interference -------------------------------------------------------------------------------


# -- hints, framed values, slots --------------------------------------------------------------------------------------


