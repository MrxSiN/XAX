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

from xax_compiler import IntCompare, Operation, RESOURCE_EFFECT_OPERATIONS
from xax_selfhost_facts import E, NONE, _function
from xax_selfhost_general_frame import _bits_width, _form
from xax_selfhost_general_ranges import _attribute, _block_at, _node_at
from xax_selfhost_general_regalloc import _eop
from xax_selfhost_general_view import (
    B_EDGES, B_INPUTS, B_KIND, B_NEDGES, B_NNODES, B_NP, B_NVALUES, B_VALUES, BRANCH, CONDITIONAL, EDGE, G_BCOUNT, G_BENTRY, G_VCOUNT,
    G_VPOS, G_VPROD, G_VTYPE, N_GRAPH, N_N, N_NOPS, N_NRES, N_OPSAT, POS_BLOCK, POS_INDEX, RETURN, TRAP, _f, _operand, _output, _vf,
)
from xax_selfhost_jvm_code import CODE_FIELDS, C_READS, C_VSDESC, C_VSLOT, D_D, D_F, D_I, D_J, D_NONE, SLOT_LATE, SLOTS, _in, _m, _set_m
from xax_selfhost_views_backend import _call, _g, _ok

# Per-value tables (``_v``), after the code state's fields.
VALUE_TABLES = ("V_DESC", "V_CONST", "V_CVAL", "V_FOLDED", "V_ALIAS", "V_NEEDED", "V_DESCOF", "V_KW", "V_USES", "V_IMPLICIT", "V_FUSED",
                "V_INLINED", "V_COPYOF", "V_BIT", "V_SINGLE", "V_SITE", "V_NUSERS", "V_USER", "V_KEPT", "V_HINTS")
(V_DESC, V_CONST, V_CVAL, V_FOLDED, V_ALIAS, V_NEEDED, V_DESCOF, V_KW, V_USES, V_IMPLICIT, V_FUSED, V_INLINED, V_COPYOF, V_BIT, V_SINGLE,
 V_SITE, V_NUSERS, V_USER, V_KEPT, V_HINTS) = range(CODE_FIELDS, CODE_FIELDS + len(VALUE_TABLES))
# Per-node and per-block tables, and scalars.
(N_ELIM, N_COPY, N_LINE, BL_BASE, BL_INC, BL_REACH, BL_UP, BL_DEF, BL_LIVE, BL_PRED, BL_NPRED, BL_RESOLVED, BL_ORDER, BL_PLACED,
 M_NV, M_NB, M_NN, M_ENTRY, M_T, M_TRACK, M_INTER, M_ACROSS, M_FRAMED, M_HINT, M_NHINT, M_STYPE, M_SOCC, M_NSOCC, M_FREED, M_NEXT,
 M_PEND, M_GEND, M_TYPED, M_FTYPES, M_NFTYPES, M_PASS, M_KEPTNONE, M_FN, M_SCRATCH, M_MAXLOC, M_NORDER, M_MAXSLOTS, M_ONE, M_WORK,
 M_RETTYPES, M_NRET, M_TRAPUSED, M_MAXCALL, M_LABELN, M_FOLLOW, M_NEEDS_PK, M_NEEDZ, M_PSLOTS, M_ISENTRY) = range(
    CODE_FIELDS + len(VALUE_TABLES), CODE_FIELDS + len(VALUE_TABLES) + 54)
STATE_WORDS = CODE_FIELDS + len(VALUE_TABLES) + 54
T_CAP = 3000  # tracked values (the interference matrix is T x T words)
ST_FREED, ST_TOP = 6, 7  # slot types beyond the descriptors: a freed parameter slot (None), Top ("T")

TREE = tuple(sorted(int(op) for op in (
    Operation.ADD_WRAP, Operation.SUB_WRAP, Operation.MUL_WRAP, Operation.BIT_AND, Operation.BIT_OR, Operation.BIT_XOR, Operation.ROTATE_RIGHT,
    Operation.INT_TRUNCATE, Operation.INT_ZERO_EXTEND, Operation.INT_COMPARE, Operation.ADDRESS_OFFSET, Operation.POINTER_ADDRESS)))
DEAD_IF_UNREAD = tuple(sorted({*TREE, *(int(op) for op in (
    Operation.CONSTANT, Operation.POINTER_CAST, Operation.AGGREGATE_MAKE, Operation.AGGREGATE_GET, Operation.SUM_MAKE, Operation.SUM_TAG,
    Operation.FUNCTION_ADDRESS))}))
ARITHMETIC = tuple(int(op) for op in (Operation.ADD_WRAP, Operation.SUB_WRAP, Operation.MUL_WRAP, Operation.BIT_AND, Operation.BIT_OR,
                                      Operation.BIT_XOR))
FOLDABLE = (*ARITHMETIC, int(Operation.INT_ZERO_EXTEND), int(Operation.INT_TRUNCATE), int(Operation.ROTATE_RIGHT))
# The operations lowered (``jvm-classfile-v1`` without platform calls); another declines.
LOWERED = tuple(sorted({*FOLDABLE, *(int(op) for op in (Operation.CALL_DIRECT, Operation.CONSTANT, Operation.INT_COMPARE, Operation.UDIV,
                                                         Operation.UREM)), *(int(op) for op in RESOURCE_EFFECT_OPERATIONS)}))
OP = {name: int(getattr(Operation, name)) for name in (
    "ADD_WRAP", "SUB_WRAP", "MUL_WRAP", "BIT_AND", "BIT_OR", "BIT_XOR", "ROTATE_RIGHT", "INT_TRUNCATE", "INT_ZERO_EXTEND", "INT_COMPARE",
    "CONSTANT", "CALL_DIRECT", "UDIV", "UREM", "HEAP_VIEW", "POINTER_CAST", "FLOAT_ADD", "FLOAT_SUB", "FLOAT_MUL", "FLOAT_DIV",
    "FLOAT_CONVERT", "FLOAT_COMPARE", "UINT_TO_FLOAT", "SINT_TO_FLOAT", "FLOAT_TO_UINT_TRUNC", "FLOAT_TO_SINT_TRUNC")}
# Lowerings that place their own branch targets inside a node (``_INTERNAL_LABELS``).
INTERNAL_LABELS = tuple(int(op) for op in (Operation.ATOMIC_CMPXCHG, Operation.UINT_TO_FLOAT, Operation.SINT_TO_FLOAT,
                                           Operation.FLOAT_TO_UINT_TRUNC, Operation.FLOAT_TO_SINT_TRUNC))


# -- accessors --------------------------------------------------------------------------------------------------------

def _v(e: E, table: int, value):
    return e.ld(e.add(_m(e, table), value))


def _set_v(e: E, table: int, value, word):
    e.st(e.add(_m(e, table), value), word)


def _type(e: E, value):
    return _vf(e, G_VTYPE, value)


def _desc(e: E, value):
    return _v(e, V_DESC, value)


def _block_of(e: E, value):
    return e.and_(e.udiv(_vf(e, G_VPOS, value), POS_BLOCK), (1 << 22) - 1)


def _is_param(e: E, value):
    return e.lt(_vf(e, G_VPOS, value), 1 << 62)


def _node_id(e: E, b, node):
    return e.add(_v(e, BL_BASE, b), _f(e, node, N_N))


def _def(e: E, value):
    """``definition(ref)``: the node producing ``value`` (NONE for a parameter)."""
    return _vf(e, G_VPROD, value)


def _result0(e: E, node):
    return e.sel(e.ne(_f(e, node, N_NRES), 0), _output(e, node, 0), NONE)


def _width(e: E, value, name: str):
    """``_width`` of the value's bits type into ``name``."""
    _bits_width(e, _type(e, value), name)


def _canon_fn(tables):
    def build(e: E):
        p = e.p
        e.var("cn_r", p["value"])
        e.while_(lambda: e.ne(_v(e, V_ALIAS, p["cn_r"]), NONE), lambda: e.set("cn_r", _v(e, V_ALIAS, p["cn_r"])))
        e.give(p["cn_r"])
    return _function(("value",), build, tables)


def canon(e: E, value):
    return _call(e, "jm_canon", value)


def _each_node(e: E, visit, prefix: str):
    """``visit(b, node, m)`` for every node in graph order."""
    p = e.p

    def block():
        e.var(f"{prefix}_b", _block_at(e, p[f"{prefix}_bi"]))
        e.for_(f"{prefix}_m", 0, _f(e, p[f"{prefix}_b"], B_NNODES), lambda: (
            e.var(f"{prefix}_n", _node_at(e, p[f"{prefix}_b"], p[f"{prefix}_m"])), visit(p[f"{prefix}_bi"], p[f"{prefix}_n"], p[f"{prefix}_m"])))

    e.for_(f"{prefix}_bi", 0, _g(e, G_BCOUNT), block)


def _each_edge(e: E, b, visit, prefix: str):
    """``visit(target index, argument count, arguments)`` for each edge of block record ``b``."""
    p = e.p
    e.for_(f"{prefix}_q", 0, _f(e, b, B_NEDGES), lambda: (
        e.var(f"{prefix}_at", e.add(_f(e, b, B_EDGES), e.mul(p[f"{prefix}_q"], EDGE))),
        visit(_target_index(e, p[f"{prefix}_at"]), _f(e, p[f"{prefix}_at"], 1), _f(e, p[f"{prefix}_at"], 2))))


def _target_index(e: E, edge):
    from xax_selfhost_general_view import B_POS

    return _f(e, _f(e, edge, 0), B_POS)


# -- stage 1: types, constants, folding -------------------------------------------------------------------------------

def _types_fn(tables):
    """``value_type`` of every value: ``int`` for bits of at most 32 bits, ``long`` to 64, ``float``/``double`` for
    binary32/binary64, none for a proof value; anything else declines."""
    def build(e: E):
        p = e.p

        def one():
            e.var("ty_t", _type(e, p["ty_v"]))
            e.var("ty_form", _form(e, p["ty_t"]))
            e.var("ty_d", D_NONE)

            def bits():
                _bits_width(e, p["ty_t"], "ty_w")
                _ok(e, e.both(e.lt(0, p["ty_w"]), e.le(p["ty_w"], 64)))  # wider: JVM-VALUE-REPRESENTABLE, the bootstrap's
                e.set("ty_d", e.sel(e.le(p["ty_w"], 32), D_I, D_J))

            def floating():
                from xax_selfhost_general_frame import _float_width

                _float_width(e, p["ty_t"], "ty_fw")
                e.set("ty_d", e.sel(e.eq(p["ty_fw"], 32), D_F, D_D))

            e.if_(e.eq(p["ty_form"], 1), bits, lambda: e.if_(e.eq(p["ty_form"], 7), floating, lambda: _ok(e, _in(e, p["ty_form"], (3, 4)))))
            _set_v(e, V_DESC, p["ty_v"], p["ty_d"])

        e.for_("ty_v", 0, _m(e, M_NV), one)
        e.give(1)
    return _function((), build, tables)


def _constant_value(e: E, node, name: str):
    """A bits constant's little-endian value bytes (at most 8) into ``name``."""
    from xax_selfhost_views_backend import G_PAY, _at, _payload_uleb, _reference

    p = e.p
    e.var(f"{name}_o", _reference(e, _f(e, node, N_GRAPH), e.rd(e.sub(_f(e, node, N_OPSAT), 1))))
    _ok(e, e.ne(p[f"{name}_o"], NONE))
    e.var(f"{name}_at", _at(e, G_PAY, p[f"{name}_o"]))
    _payload_uleb(e, f"{name}_at")  # the type
    e.var(f"{name}_len", _payload_uleb(e, f"{name}_at"))
    _ok(e, e.le(p[f"{name}_len"], 8))
    e.var(name, 0)
    e.var(f"{name}_w", 1)
    e.for_(f"{name}_k", 0, p[f"{name}_len"], lambda: (
        e.set(name, e.add(p[name], e.mul(e.rd(e.add(p[f"{name}_at"], p[f"{name}_k"])), p[f"{name}_w"]))),
        e.set(f"{name}_w", e.mul(p[f"{name}_w"], 256))))


def _pow2(e: E, k):
    """``2 ** k`` (0 for ``k`` 64: the shift past the word)."""
    return _call(e, "jm_pow2", k)


def _pow2_fn(tables):
    def build(e: E):
        p = e.p
        e.var("pw_r", 1)
        e.for_("pw_k", 0, p["k"], lambda: e.set("pw_r", e.mul(p["pw_r"], 2)))
        e.give(p["pw_r"])
    return _function(("k",), build, tables)


def _mask_word(e: E, width):
    """``(1 << width) - 1``."""
    return e.sub(_pow2(e, width), 1)


def _constants_fn(tables):
    """Integer constants by value, then the folding of pure integer nodes over constants (results masked)."""
    from xax_selfhost_jvm_code import _bx

    def build(e: E):
        p = e.p
        e.for_("ct_v", 0, _m(e, M_NV), lambda: (_set_v(e, V_CONST, p["ct_v"], 0), _set_v(e, V_FOLDED, p["ct_v"], 0)))

        def constant(b, node, m):
            def take():
                e.var("ct_r", _output(e, node, 0))

                def integer():
                    _constant_value(e, node, "ct_val")
                    _set_v(e, V_CONST, p["ct_r"], 1)
                    _set_v(e, V_CVAL, p["ct_r"], p["ct_val"])

                e.if_(_in(e, _desc(e, p["ct_r"]), (D_I, D_J)), integer)

            e.if_(e.eq(_eop(e, node), OP["CONSTANT"]), take)

        _each_node(e, constant, "ctn")
        e.var("ct_changed", 1)

        def fold(b, node, m):
            e.var("fd_op", _eop(e, node))
            e.var("fd_r", _result0(e, node))
            candidate = e.both(e.eq(_f(e, node, N_NRES), 1), _in(e, p["fd_op"], FOLDABLE))

            def check():
                e.var("fd_all", e.flag(e.both(e.eq(_v(e, V_CONST, p["fd_r"]), 0), _in(e, _desc(e, p["fd_r"]), (D_I, D_J)))))
                e.for_("fd_k", 0, _f(e, node, N_NOPS), lambda: e.if_(e.eq(_v(e, V_CONST, _operand(e, node, p["fd_k"])), 0), lambda: e.set("fd_all", 0)))

                def compute():
                    _width(e, p["fd_r"], "fd_w")
                    e.var("fd_a", _v(e, V_CVAL, _operand(e, node, 0)))
                    e.var("fd_b", e.sel(e.lt(1, _f(e, node, N_NOPS)), _v(e, V_CVAL, _operand(e, node, e.sel(e.lt(1, _f(e, node, N_NOPS)), 1, 0))), 0))
                    e.var("fd_x", p["fd_a"])
                    op = p["fd_op"]
                    e.if_(e.eq(op, OP["ADD_WRAP"]), lambda: e.set("fd_x", e.add(p["fd_a"], p["fd_b"])))
                    e.if_(e.eq(op, OP["SUB_WRAP"]), lambda: e.set("fd_x", e.sub(p["fd_a"], p["fd_b"])))
                    e.if_(e.eq(op, OP["MUL_WRAP"]), lambda: e.set("fd_x", e.mul(p["fd_a"], p["fd_b"])))
                    e.if_(e.eq(op, OP["BIT_AND"]), lambda: e.set("fd_x", e.and_(p["fd_a"], p["fd_b"])))
                    e.if_(e.eq(op, OP["BIT_OR"]), lambda: e.set("fd_x", e.or_(p["fd_a"], p["fd_b"])))
                    e.if_(e.eq(op, OP["BIT_XOR"]), lambda: e.set("fd_x", _bx(e, p["fd_a"], p["fd_b"])))

                    def rotate():
                        e.var("fd_amt", e.sel(e.ne(p["fd_w"], 0), e.urem(_attribute(e, node, 0), e.sel(e.ne(p["fd_w"], 0), p["fd_w"], 1)), 0))
                        e.set("fd_x", e.or_(e.udiv(p["fd_a"], _pow2(e, p["fd_amt"])), e.mul(p["fd_a"], _pow2(e, e.sub(p["fd_w"], p["fd_amt"])))))

                    e.if_(e.eq(op, OP["ROTATE_RIGHT"]), rotate)
                    _set_v(e, V_CVAL, p["fd_r"], e.and_(p["fd_x"], _mask_word(e, p["fd_w"])))
                    _set_v(e, V_CONST, p["fd_r"], 1)
                    _set_v(e, V_FOLDED, p["fd_r"], 1)
                    e.set("ct_changed", 1)

                e.if_(e.ne(p["fd_all"], 0), compute)

            e.if_(candidate, check)

        e.while_(lambda: e.ne(p["ct_changed"], 0), lambda: (e.set("ct_changed", 0), _each_node(e, fold, "fdn")))
        e.give(1)
    return _function((), build, tables)


# -- aliases, needed values, eliminated nodes ---------------------------------------------------------------------------

def _aliases_fn(tables):
    """A reachable block other than the entry entered by exactly one edge: its parameters alias that edge's
    arguments."""
    def build(e: E):
        p = e.p
        nb = _m(e, M_NB)
        e.for_("al_v", 0, _m(e, M_NV), lambda: _set_v(e, V_ALIAS, p["al_v"], NONE))
        e.for_("al_b", 0, nb, lambda: (_set_v(e, BL_INC, p["al_b"], 0), _set_v(e, BL_REACH, p["al_b"], 0)))

        def count(b):
            e.var("al_rec", _block_at(e, b))
            _each_edge(e, p["al_rec"], lambda target, n, args: _set_v(e, BL_INC, target, e.add(_v(e, BL_INC, target), 1)), "alc")

        e.for_("al_bi", 0, nb, lambda: count(p["al_bi"]))
        # Reachability from the entry (a worklist).
        e.var("al_work", _m(e, M_WORK))
        e.var("al_top", 1)
        e.st(p["al_work"], _m(e, M_ENTRY))
        _set_v(e, BL_REACH, _m(e, M_ENTRY), 1)

        def visit():
            e.set("al_top", e.sub(p["al_top"], 1))
            e.var("al_rec", _block_at(e, e.ld(e.add(p["al_work"], p["al_top"]))))

            def edge(target, n, args):
                e.var("al_t", target)
                e.if_(e.eq(_v(e, BL_REACH, p["al_t"]), 0), lambda: (_set_v(e, BL_REACH, p["al_t"], 1), e.st(e.add(p["al_work"], p["al_top"]), p["al_t"]),
                                                                     e.set("al_top", e.add(p["al_top"], 1))))

            _each_edge(e, p["al_rec"], edge, "alr")

        e.while_(lambda: e.lt(0, p["al_top"]), visit)

        def single(b):
            e.var("al_sb", b)

            def from_edges():
                e.var("al_src", _block_at(e, p["al_sbi"]))

                def edge(target, n, args):
                    e.var("al_args", args)
                    e.if_(e.eq(target, p["al_sb"]), lambda: e.for_("al_k", 0, n, lambda: _set_v(
                        e, V_ALIAS, e.ld(e.add(_f(e, _block_at(e, p["al_sb"]), B_INPUTS), p["al_k"])), e.ld(e.add(p["al_args"], p["al_k"])))))

                _each_edge(e, p["al_src"], edge, "als")

            e.for_("al_sbi", 0, nb, from_edges)

        e.for_("al_bi", 0, nb, lambda: e.if_(e.both(e.ne(_v(e, BL_REACH, p["al_bi"]), 0), e.ne(p["al_bi"], _m(e, M_ENTRY)),
                                                     e.eq(_v(e, BL_INC, p["al_bi"]), 1)), lambda: single(p["al_bi"])))
        e.give(1)
    return _function((), build, tables)


def _need(e: E, value, name: str):
    e.var(name, canon(e, value))
    e.if_(e.eq(_v(e, V_NEEDED, e.p[name]), 0), lambda: (_set_v(e, V_NEEDED, e.p[name], 1), e.set("nd_changed", 1)))


def _needed_fn(tables):
    """``needed``: what impure nodes and terminators read (a return its machine results), then closed over edges into
    needed parameters and pure nodes with a needed result; pure nodes nothing reads are eliminated."""
    def build(e: E):
        p = e.p
        e.for_("nd_v", 0, _m(e, M_NV), lambda: _set_v(e, V_NEEDED, p["nd_v"], 0))
        e.for_("nd_i", 0, _m(e, M_NN), lambda: _set_v(e, N_ELIM, p["nd_i"], 0))
        e.var("nd_changed", 0)

        def impure(b, node, m):
            e.if_(e.not_(_in(e, _eop(e, node), DEAD_IF_UNREAD)), lambda: e.for_("nd_k", 0, _f(e, node, N_NOPS), lambda: _need(e, _operand(e, node, p["nd_k"]), "nd_c")))

        _each_node(e, impure, "ndi")

        def terminator():
            e.var("nd_b", _block_at(e, p["nd_bi"]))

            def returned():
                e.for_("nd_k", 0, _f(e, p["nd_b"], B_NVALUES), lambda: e.if_(
                    e.both(e.lt(p["nd_k"], _m(e, M_NRET)), e.ne(e.ld(e.add(_m(e, M_RETTYPES), p["nd_k"])), D_NONE)),
                    lambda: _need(e, e.ld(e.add(_f(e, p["nd_b"], B_VALUES), p["nd_k"])), "nd_c")))

            e.if_(e.eq(_f(e, p["nd_b"], B_KIND), RETURN), returned,
                  lambda: e.for_("nd_k", 0, _f(e, p["nd_b"], B_NVALUES), lambda: _need(e, e.ld(e.add(_f(e, p["nd_b"], B_VALUES), p["nd_k"])), "nd_c")))

        e.for_("nd_bi", 0, _m(e, M_NB), terminator)
        e.set("nd_changed", 1)

        def round_():
            e.set("nd_changed", 0)

            def edges():
                e.var("nd_src", _block_at(e, p["nd_ebi"]))

                def edge(target, n, args):
                    e.var("nd_tb", _block_at(e, target))
                    e.var("nd_args", args)

                    def argument():
                        e.var("nd_param", e.ld(e.add(_f(e, p["nd_tb"], B_INPUTS), p["nd_k"])))
                        e.var("nd_arg", canon(e, e.ld(e.add(p["nd_args"], p["nd_k"]))))
                        e.if_(e.both(e.ne(_v(e, V_NEEDED, p["nd_param"]), 0), e.eq(_v(e, V_ALIAS, p["nd_param"]), NONE), e.eq(_v(e, V_NEEDED, p["nd_arg"]), 0)),
                              lambda: (_set_v(e, V_NEEDED, p["nd_arg"], 1), e.set("nd_changed", 1)))

                    e.for_("nd_k", 0, n, argument)

                _each_edge(e, p["nd_src"], edge, "nde")

            e.for_("nd_ebi", 0, _m(e, M_NB), edges)

            def pure(b, node, m):
                e.var("nd_id", _node_id(e, b, node))

                def live():
                    e.var("nd_any", 0)
                    e.for_("nd_r", 0, _f(e, node, N_NRES), lambda: e.if_(e.ne(_v(e, V_NEEDED, _output(e, node, p["nd_r"])), 0), lambda: e.set("nd_any", 1)))
                    e.if_(e.ne(p["nd_any"], 0), lambda: e.for_("nd_k", 0, _f(e, node, N_NOPS), lambda: _need(e, _operand(e, node, p["nd_k"]), "nd_c")))

                e.if_(e.both(_in(e, _eop(e, node), DEAD_IF_UNREAD), e.eq(_v(e, N_ELIM, p["nd_id"]), 0)), live)

            _each_node(e, pure, "ndp")

        e.while_(lambda: e.ne(p["nd_changed"], 0), round_)

        def eliminate(b, node, m):
            e.var("nd_any", 0)
            e.for_("nd_r", 0, _f(e, node, N_NRES), lambda: e.if_(e.ne(_v(e, V_NEEDED, _output(e, node, p["nd_r"])), 0), lambda: e.set("nd_any", 1)))
            e.if_(e.both(_in(e, _eop(e, node), DEAD_IF_UNREAD), e.eq(p["nd_any"], 0)), lambda: _set_v(e, N_ELIM, _node_id(e, b, node), 1))

        _each_node(e, eliminate, "ndx")
        e.give(1)
    return _function((), build, tables)


def carried(e: E, target, param):
    """``carried(target, index)``: the parameter is not an alias, and needed or the entry's."""
    return e.both(e.eq(_v(e, V_ALIAS, param), NONE), e.either(e.ne(_v(e, V_NEEDED, param), 0), e.eq(target, _m(e, M_ENTRY))))


def each_edge_read(e: E, b_rec, visit, prefix: str):
    """``edge_reads(block)``: ``visit(canon(argument), target, parameter, argument)`` for every carried argument."""
    p = e.p

    def edge(target, n, args):
        e.var(f"{prefix}_t", target)
        e.var(f"{prefix}_tb", _block_at(e, target))
        e.var(f"{prefix}_args", args)

        def argument():
            e.var(f"{prefix}_param", e.ld(e.add(_f(e, p[f"{prefix}_tb"], B_INPUTS), p[f"{prefix}_k"])))
            e.var(f"{prefix}_arg", e.ld(e.add(p[f"{prefix}_args"], p[f"{prefix}_k"])))
            e.if_(carried(e, p[f"{prefix}_t"], p[f"{prefix}_param"]), lambda: visit(canon(e, p[f"{prefix}_arg"]), p[f"{prefix}_t"], p[f"{prefix}_param"],
                                                                                   p[f"{prefix}_arg"]))

        e.for_(f"{prefix}_k", 0, n, argument)

    _each_edge(e, b_rec, edge, f"{prefix}e")


# -- descriptors, widths, uses, copies -----------------------------------------------------------------------------------

def _facts_fn(tables):
    """``descriptor_of``, ``known_width``, ``uses``, ``copy_like`` per node, ``copy_of``, the implicit reads, the users,
    and the fused compares."""
    def build(e: E):
        p = e.p
        nv = _m(e, M_NV)
        for table, word in ((V_DESCOF, 0), (V_KW, NONE), (V_USES, 0), (V_IMPLICIT, 0), (V_FUSED, 0), (V_COPYOF, NONE), (V_NUSERS, 0), (V_USER, NONE)):
            e.for_("fc_v", 0, nv, lambda table=table, word=word: _set_v(e, table, p["fc_v"], word))

        def params():
            e.var("fc_b", _block_at(e, p["fc_bi"]))
            e.for_("fc_k", 0, _f(e, p["fc_b"], B_NP), lambda: (
                e.var("fc_pv", e.ld(e.add(_f(e, p["fc_b"], B_INPUTS), p["fc_k"]))),
                e.if_(e.both(e.ne(_desc(e, p["fc_pv"]), D_NONE), e.either(e.eq(p["fc_bi"], _m(e, M_ENTRY)), carried(e, p["fc_bi"], p["fc_pv"]))),
                      lambda: _set_v(e, V_DESCOF, p["fc_pv"], 1))))

        e.for_("fc_bi", 0, _m(e, M_NB), params)

        def results(b, node, m):
            e.var("fc_id", _node_id(e, b, node))
            e.for_("fc_r", 0, _f(e, node, N_NRES), lambda: (e.var("fc_rv", _output(e, node, p["fc_r"])), e.if_(
                e.both(e.ne(_desc(e, p["fc_rv"]), D_NONE), e.eq(_v(e, V_ALIAS, p["fc_rv"]), NONE), e.eq(_v(e, N_ELIM, p["fc_id"]), 0)),
                lambda: _set_v(e, V_DESCOF, p["fc_rv"], 1))))

        _each_node(e, results, "fcr")

        # Known widths (two rounds).
        def widths(b, node, m):
            e.var("kw_op", _eop(e, node))
            e.var("kw_r", _result0(e, node))

            def zext():
                e.var("kw_src", _operand(e, node, 0))
                _width(e, p["kw_src"], "kw_sw")
                _set_v(e, V_KW, p["kw_r"], e.sel(e.ne(_v(e, V_KW, p["kw_src"]), NONE), _v(e, V_KW, p["kw_src"]), p["kw_sw"]))

            def trunc():
                e.var("kw_src", _operand(e, node, 0))
                _width(e, p["kw_r"], "kw_rw")
                e.var("kw_o", e.sel(e.ne(_v(e, V_KW, p["kw_src"]), NONE), _v(e, V_KW, p["kw_src"]), 64))
                _set_v(e, V_KW, p["kw_r"], e.sel(e.lt(p["kw_o"], p["kw_rw"]), p["kw_o"], p["kw_rw"]))

            e.if_(e.eq(p["kw_op"], OP["INT_ZERO_EXTEND"]), zext)
            e.if_(e.eq(p["kw_op"], OP["INT_TRUNCATE"]), trunc)

        for _ in range(2):
            _each_node(e, widths, "kwn")

        # Uses: operands of the nodes not eliminated, terminator values and edge reads (canonical).
        def count(value):
            e.var("us_c", canon(e, value))
            _set_v(e, V_USES, p["us_c"], e.add(_v(e, V_USES, p["us_c"]), 1))

        e.for_("us_bi", 0, _m(e, M_NB), lambda: (
            e.var("us_b", _block_at(e, p["us_bi"])),
            e.for_("us_m", 0, _f(e, p["us_b"], B_NNODES), lambda: (
                e.var("us_n", _node_at(e, p["us_b"], p["us_m"])),
                e.if_(e.eq(_v(e, N_ELIM, _node_id(e, p["us_bi"], p["us_n"])), 0), lambda: e.for_(
                    "us_k", 0, _f(e, p["us_n"], N_NOPS), lambda: count(_operand(e, p["us_n"], p["us_k"])))))),
            e.for_("us_k", 0, _f(e, p["us_b"], B_NVALUES), lambda: count(e.ld(e.add(_f(e, p["us_b"], B_VALUES), p["us_k"])))),
            each_edge_read(e, p["us_b"], lambda c, t, param, arg: (e.var("us_c", c), _set_v(e, V_USES, p["us_c"], e.add(_v(e, V_USES, p["us_c"]), 1))), "use")))

        # copy_like per node, copy_of, the implicit reads.
        def copy(b, node, m):
            e.var("cp_id", _node_id(e, b, node))
            e.var("cp_op", _eop(e, node))
            e.var("cp_like", 0)

            def extension():
                e.var("cp_src", _operand(e, node, 0))
                e.var("cp_r", _output(e, node, 0))
                _width(e, p["cp_r"], "cp_rw")
                ok = e.both(e.eq(_desc(e, p["cp_src"]), _desc(e, p["cp_r"])), e.ne(_v(e, V_USES, p["cp_src"]), 1),
                            e.not_(e.both(e.eq(p["cp_op"], OP["INT_TRUNCATE"]),
                                          e.lt(p["cp_rw"], e.sel(e.ne(_v(e, V_KW, p["cp_src"]), NONE), _v(e, V_KW, p["cp_src"]), 64)))),
                            e.eq(_v(e, V_CONST, p["cp_src"]), 0), e.ne(_desc(e, p["cp_r"]), D_NONE))
                e.set("cp_like", e.flag(ok))

            e.if_(_in(e, p["cp_op"], (OP["INT_ZERO_EXTEND"], OP["INT_TRUNCATE"])), extension)
            _set_v(e, N_COPY, p["cp_id"], p["cp_like"])

            def mark():
                _set_v(e, V_COPYOF, _output(e, node, 0), _operand(e, node, 0))
                e.var("cp_c", canon(e, _operand(e, node, 0)))
                _set_v(e, V_IMPLICIT, p["cp_c"], 1)

            e.if_(e.ne(p["cp_like"], 0), mark)

        _each_node(e, copy, "cpn")
        e.for_("im_bi", 0, _m(e, M_NB), lambda: each_edge_read(e, _block_at(e, p["im_bi"]), lambda c, t, param, arg: (
            e.var("im_c", c), _set_v(e, V_IMPLICIT, p["im_c"], 1)), "imp"))

        # Users (operand occurrences of nodes not eliminated, canonical).
        def users(b, node, m):
            e.if_(e.eq(_v(e, N_ELIM, _node_id(e, b, node)), 0), lambda: e.for_("ur_k", 0, _f(e, node, N_NOPS), lambda: (
                e.var("ur_c", canon(e, _operand(e, node, p["ur_k"]))),
                e.if_(e.eq(_v(e, V_NUSERS, p["ur_c"]), 0), lambda: _set_v(e, V_USER, p["ur_c"], node)),
                _set_v(e, V_NUSERS, p["ur_c"], e.add(_v(e, V_NUSERS, p["ur_c"]), 1)))))

        _each_node(e, users, "urn")

        # Fused compares: a compare whose only use is its own block's conditional branch.
        def fused():
            e.var("fu_b", _block_at(e, p["fu_bi"]))

            def check():
                e.var("fu_c", e.ld(_f(e, p["fu_b"], B_VALUES)))
                e.var("fu_n", _def(e, p["fu_c"]))
                e.if_(e.both(e.ne(p["fu_n"], NONE), e.eq(_block_of(e, p["fu_c"]), p["fu_bi"]), e.eq(_v(e, V_USES, p["fu_c"]), 1)), lambda: e.if_(
                    _in(e, _eop(e, p["fu_n"]), (OP["INT_COMPARE"], OP["FLOAT_COMPARE"])), lambda: _set_v(e, V_FUSED, p["fu_c"], 1)))

            e.if_(e.eq(_f(e, p["fu_b"], B_KIND), CONDITIONAL), check)

        e.for_("fu_bi", 0, _m(e, M_NB), fused)
        e.give(1)
    return _function((), build, tables)


def copy_like(e: E, b, node):
    return e.ne(_v(e, N_COPY, _node_id(e, b, node)), 0)


def sole_user(e: E, value):
    """``sole_user(ref)``: the one node reading ``value`` (NONE otherwise)."""
    return e.sel(e.both(e.eq(_v(e, V_USES, value), 1), e.eq(_v(e, V_NUSERS, value), 1)), _v(e, V_USER, value), NONE)


def _inlined_fn(tables):
    """The second pass's expression trees: a pure integer tree node read once, by a node or the terminator of its own
    block, not implicitly, not a constant or a copy."""
    def build(e: E):
        p = e.p
        e.for_("il_v", 0, _m(e, M_NV), lambda: (_set_v(e, V_INLINED, p["il_v"], 0), _set_v(e, V_SITE, p["il_v"], NONE)))
        e.if_(e.eq(_m(e, M_PASS), 1), lambda: e.give(1))

        def site():
            e.var("il_b", _block_at(e, p["il_bi"]))

            def node():
                e.var("il_n", _node_at(e, p["il_b"], p["il_m"]))
                e.if_(e.not_(copy_like(e, p["il_bi"], p["il_n"])), lambda: e.for_("il_k", 0, _f(e, p["il_n"], N_NOPS), lambda: _set_v(
                    e, V_SITE, _operand(e, p["il_n"], p["il_k"]), p["il_bi"])))

            e.for_("il_m", 0, _f(e, p["il_b"], B_NNODES), node)
            e.for_("il_k", 0, _f(e, p["il_b"], B_NVALUES), lambda: _set_v(e, V_SITE, e.ld(e.add(_f(e, p["il_b"], B_VALUES), p["il_k"])), p["il_bi"]))

        e.for_("il_bi", 0, _m(e, M_NB), site)

        def tree(b, node, m):
            e.var("il_r", _result0(e, node))
            ok = e.both(_in(e, _eop(e, node), TREE), e.eq(_f(e, node, N_NRES), 1), _in(e, _desc(e, p["il_r"]), (D_I, D_J)),
                        e.ne(_v(e, V_SINGLE, p["il_r"]), 0), e.eq(_v(e, V_IMPLICIT, p["il_r"]), 0), e.eq(_v(e, V_CONST, p["il_r"]), 0),
                        e.eq(_v(e, V_USES, p["il_r"]), 1), e.eq(_v(e, V_SITE, p["il_r"]), b), e.not_(copy_like(e, b, node)))
            e.if_(ok, lambda: _set_v(e, V_INLINED, p["il_r"], 1))

        _each_node(e, tree, "iln")
        e.give(1)
    return _function((), build, tables)


def late(e: E, value):
    return e.either(e.ne(_v(e, V_INLINED, value), 0), e.ne(_v(e, V_FUSED, value), 0))


def _repacked_fn(tables):
    """``repacked(node)``: ``s`` when ``node`` is ``zext(trunc(s)) | rotr(zext(trunc(rotr(s, 32))), 32)`` (64-bit), else
    NONE."""
    def build(e: E):
        p = e.p
        e.if_(e.ne(_eop(e, p["node"]), OP["BIT_OR"]), lambda: e.give(NONE))
        _width(e, _output(e, p["node"], 0), "rp_w")
        e.if_(e.ne(p["rp_w"], 64), lambda: e.give(NONE))

        def node_of(value):
            return _def(e, canon(e, value))

        def attempt(low_ref, high_ref):
            e.var("rp_lz", node_of(low_ref))
            e.var("rp_hr", node_of(high_ref))

            def inner():
                e.var("rp_hz", node_of(_operand(e, p["rp_hr"], 0)))
                e.var("rp_lt", node_of(_operand(e, p["rp_lz"], 0)))

                def deeper():
                    e.var("rp_ht", node_of(_operand(e, p["rp_hz"], 0)))

                    def truncs():
                        _width(e, _output(e, p["rp_lt"], 0), "rp_lw")
                        _width(e, _output(e, p["rp_ht"], 0), "rp_hw")

                        def split():
                            e.var("rp_sp", node_of(_operand(e, p["rp_ht"], 0)))

                            def whole():
                                e.var("rp_whole", canon(e, _operand(e, p["rp_lt"], 0)))
                                _width(e, _operand(e, p["rp_lt"], 0), "rp_ow")
                                e.if_(e.both(e.eq(p["rp_ow"], 64), e.eq(_desc(e, _output(e, p["node"], 0)), D_J)), lambda: e.give(p["rp_whole"]))

                            e.if_(e.both(e.ne(p["rp_sp"], NONE), e.eq(_eop(e, e.sel(e.ne(p["rp_sp"], NONE), p["rp_sp"], p["node"])), OP["ROTATE_RIGHT"])), lambda: e.if_(
                                e.both(e.eq(_attribute(e, p["rp_sp"], 0), 32), e.eq(canon(e, _operand(e, p["rp_sp"], 0)), canon(e, _operand(e, p["rp_lt"], 0)))), whole))

                        e.if_(e.both(e.eq(p["rp_lw"], 32), e.eq(p["rp_hw"], 32)), split)

                    e.if_(e.both(e.ne(p["rp_ht"], NONE), e.ne(p["rp_lt"], NONE)), lambda: e.if_(e.both(
                        e.eq(_eop(e, p["rp_lt"]), OP["INT_TRUNCATE"]), e.eq(_eop(e, p["rp_ht"]), OP["INT_TRUNCATE"])), truncs))

                e.if_(e.both(e.ne(p["rp_hz"], NONE), e.ne(p["rp_lt"], NONE)), lambda: e.if_(e.eq(_eop(e, p["rp_hz"]), OP["INT_ZERO_EXTEND"]), deeper))

            ok = e.both(e.ne(p["rp_lz"], NONE), e.ne(p["rp_hr"], NONE))
            e.if_(ok, lambda: e.if_(e.both(e.eq(_eop(e, p["rp_lz"]), OP["INT_ZERO_EXTEND"]), e.eq(_eop(e, p["rp_hr"]), OP["ROTATE_RIGHT"]),
                                           e.eq(_attribute(e, p["rp_hr"], 0), 32)), inner))

        attempt(_operand(e, p["node"], 0), _operand(e, p["node"], 1))
        attempt(_operand(e, p["node"], 1), _operand(e, p["node"], 0))
        e.give(NONE)
    return _function(("node",), build, tables)


def repacked(e: E, node):
    return _call_none(e, "jm_repacked", node)


def _call_none(e: E, name: str, *arguments):
    """A call whose NONE result is a value, not a decline."""
    from xax_selfhost_views_backend import _FN

    return e.call(_FN[name], *arguments)


def _effective_fn(tables):
    """``effective(refs)`` of a value into the set ``into`` (one word per tracked value): the value, or, when it is
    evaluated where it is read, what its repacked source or its node's operands are, recursively."""
    def build(e: E):
        p = e.p
        e.var("ef_stack", _m(e, M_WORK))
        e.var("ef_top", 1)
        e.st(p["ef_stack"], canon(e, p["value"]))

        def step():
            e.set("ef_top", e.sub(p["ef_top"], 1))
            e.var("ef_r", e.ld(e.add(p["ef_stack"], p["ef_top"])))

            def push(value):
                _ok(e, e.lt(p["ef_top"], 1 << 20))
                e.st(e.add(p["ef_stack"], p["ef_top"]), canon(e, value))
                e.set("ef_top", e.add(p["ef_top"], 1))

            def expand():
                e.var("ef_n", _def(e, p["ef_r"]))
                e.var("ef_rp", repacked(e, p["ef_n"]))
                # The operands in order: pushed in reverse.
                e.if_(e.ne(p["ef_rp"], NONE), lambda: push(p["ef_rp"]), lambda: (
                    e.var("ef_k", _f(e, p["ef_n"], N_NOPS)),
                    e.while_(lambda: e.lt(0, p["ef_k"]), lambda: (e.set("ef_k", e.sub(p["ef_k"], 1)), push(_operand(e, p["ef_n"], p["ef_k"]))))))

            def leaf():
                e.var("ef_bit", _v(e, V_BIT, p["ef_r"]))
                e.if_(e.ne(p["ef_bit"], NONE), lambda: e.st(e.add(p["into"], p["ef_bit"]), 1))

            e.if_(late(e, p["ef_r"]), expand, leaf)

        e.while_(lambda: e.lt(0, p["ef_top"]), step)
        e.give(1)
    return _function(("value", "into"), build, tables)


def effective(e: E, value, into):
    _call(e, "jm_effective", value, into)


# -- tracked values, liveness, interference -------------------------------------------------------------------------------

def _tracked_fn(tables):
    """``tracked``: ``descriptor_of`` in its order (parameters, then node results, block by block) without constants
    and late values; each one's bit."""
    def build(e: E):
        p = e.p
        e.for_("tr_v", 0, _m(e, M_NV), lambda: _set_v(e, V_BIT, p["tr_v"], NONE))
        e.var("tr_n", 0)

        def take(value):
            e.var("tr_x", value)
            e.if_(e.both(e.ne(_v(e, V_DESCOF, p["tr_x"]), 0), e.eq(_v(e, V_CONST, p["tr_x"]), 0), e.not_(late(e, p["tr_x"]))), lambda: (
                _ok(e, e.lt(p["tr_n"], T_CAP)), e.st(e.add(_m(e, M_TRACK), p["tr_n"]), p["tr_x"]), _set_v(e, V_BIT, p["tr_x"], p["tr_n"]),
                e.set("tr_n", e.add(p["tr_n"], 1))))

        def block():
            e.var("tr_b", _block_at(e, p["tr_bi"]))
            e.for_("tr_k", 0, _f(e, p["tr_b"], B_NP), lambda: take(e.ld(e.add(_f(e, p["tr_b"], B_INPUTS), p["tr_k"]))))
            e.for_("tr_m", 0, _f(e, p["tr_b"], B_NNODES), lambda: (e.var("tr_nd", _node_at(e, p["tr_b"], p["tr_m"])), e.for_(
                "tr_r", 0, _f(e, p["tr_nd"], N_NRES), lambda: take(_output(e, p["tr_nd"], p["tr_r"])))))

        e.for_("tr_bi", 0, _m(e, M_NB), block)
        _set_m(e, M_T, p["tr_n"])
        e.give(p["tr_n"])
    return _function((), build, tables)


def _set_of(e: E, base, b):
    """Block ``b``'s set in the per-block array ``base`` (``T`` words each)."""
    return e.add(_m(e, base), e.mul(b, _m(e, M_T)))


def _clear(e: E, s, name: str):
    e.for_(name, 0, _m(e, M_T), lambda: e.st(e.add(s, e.p[name]), 0))


def _bits_of(e: E, value, into):
    """``bits((value,))`` into the set ``into``."""
    e.var("bo_bit", _v(e, V_BIT, value))
    e.if_(e.ne(e.p["bo_bit"], NONE), lambda: e.st(e.add(into, e.p["bo_bit"]), 1))


def _liveness_fn(tables):
    """``upward``/``defined`` per block, then ``live_in`` to its fixed point (blocks in reverse order)."""
    def build(e: E):
        p = e.p
        nb = _m(e, M_NB)
        e.var("lv_tmp", e.alloc(e.add(_m(e, M_T), 1)))
        _ok(e, e.ne(p["lv_tmp"], NONE))

        def block():
            e.var("lv_b", _block_at(e, p["lv_bi"]))
            e.var("lv_seen", _set_of(e, BL_DEF, p["lv_bi"]))
            e.var("lv_up", _set_of(e, BL_UP, p["lv_bi"]))
            _clear(e, p["lv_seen"], "lv_c1")
            _clear(e, p["lv_up"], "lv_c2")
            _clear(e, _set_of(e, BL_LIVE, p["lv_bi"]), "lv_c3")
            e.for_("lv_k", 0, _f(e, p["lv_b"], B_NP), lambda: _bits_of(e, e.ld(e.add(_f(e, p["lv_b"], B_INPUTS), p["lv_k"])), p["lv_seen"]))

            def node():
                e.var("lv_n", _node_at(e, p["lv_b"], p["lv_m"]))
                e.var("lv_r0", _result0(e, p["lv_n"]))
                skip = e.either(e.both(e.ne(p["lv_r0"], NONE), late(e, e.sel(e.ne(p["lv_r0"], NONE), p["lv_r0"], 0))),
                                e.ne(_v(e, N_ELIM, _node_id(e, p["lv_bi"], p["lv_n"])), 0))

                def body():
                    _clear(e, p["lv_tmp"], "lv_c4")
                    e.for_("lv_k", 0, _f(e, p["lv_n"], N_NOPS), lambda: effective(e, _operand(e, p["lv_n"], p["lv_k"]), p["lv_tmp"]))
                    e.for_("lv_t", 0, _m(e, M_T), lambda: e.if_(e.both(e.ne(e.ld(e.add(p["lv_tmp"], p["lv_t"])), 0), e.eq(e.ld(e.add(p["lv_seen"], p["lv_t"])), 0)),
                                                                lambda: e.st(e.add(p["lv_up"], p["lv_t"]), 1)))
                    e.for_("lv_r", 0, _f(e, p["lv_n"], N_NRES), lambda: _bits_of(e, _output(e, p["lv_n"], p["lv_r"]), p["lv_seen"]))

                e.if_(e.not_(skip), body)

            e.for_("lv_m", 0, _f(e, p["lv_b"], B_NNODES), node)
            _clear(e, p["lv_tmp"], "lv_c5")
            e.for_("lv_k", 0, _f(e, p["lv_b"], B_NVALUES), lambda: effective(e, e.ld(e.add(_f(e, p["lv_b"], B_VALUES), p["lv_k"])), p["lv_tmp"]))
            each_edge_read(e, p["lv_b"], lambda c, t, param, arg: effective(e, c, p["lv_tmp"]), "lve")
            e.for_("lv_t", 0, _m(e, M_T), lambda: e.if_(e.both(e.ne(e.ld(e.add(p["lv_tmp"], p["lv_t"])), 0), e.eq(e.ld(e.add(p["lv_seen"], p["lv_t"])), 0)),
                                                        lambda: e.st(e.add(p["lv_up"], p["lv_t"]), 1)))

        e.for_("lv_bi", 0, nb, block)
        e.var("lv_changed", 1)

        def round_():
            e.set("lv_changed", 0)
            e.var("lv_bi", nb)

            def one():
                e.set("lv_bi", e.sub(p["lv_bi"], 1))
                e.var("lv_b", _block_at(e, p["lv_bi"]))
                _clear(e, p["lv_tmp"], "lv_c6")
                _each_edge(e, p["lv_b"], lambda target, n, args: (e.var("lv_succ", _set_of(e, BL_LIVE, target)), e.for_(
                    "lv_t", 0, _m(e, M_T), lambda: e.if_(e.ne(e.ld(e.add(p["lv_succ"], p["lv_t"])), 0), lambda: e.st(e.add(p["lv_tmp"], p["lv_t"]), 1)))), "lvs")
                e.var("lv_in", _set_of(e, BL_LIVE, p["lv_bi"]))
                e.var("lv_def", _set_of(e, BL_DEF, p["lv_bi"]))
                e.var("lv_up", _set_of(e, BL_UP, p["lv_bi"]))

                def word():
                    e.var("lv_new", e.flag(e.either(e.ne(e.ld(e.add(p["lv_up"], p["lv_t"])), 0),
                                                    e.both(e.ne(e.ld(e.add(p["lv_tmp"], p["lv_t"])), 0), e.eq(e.ld(e.add(p["lv_def"], p["lv_t"])), 0)))))
                    e.if_(e.ne(p["lv_new"], e.ld(e.add(p["lv_in"], p["lv_t"]))), lambda: (e.st(e.add(p["lv_in"], p["lv_t"]), p["lv_new"]), e.set("lv_changed", 1)))

                e.for_("lv_t", 0, _m(e, M_T), word)

            e.while_(lambda: e.lt(0, p["lv_bi"]), one)

        e.while_(lambda: e.ne(p["lv_changed"], 0), round_)
        e.give(1)
    return _function((), build, tables)


def _inter(e: E, a, b):
    return e.add(_m(e, M_INTER), e.add(e.mul(a, _m(e, M_T)), b))


def _interfere_fn(tables):
    """``interfere(defs, live)``: every value of ``defs`` interferes with every other of ``live``, both ways."""
    def build(e: E):
        p = e.p

        def one():
            def other():
                e.if_(e.both(e.ne(e.ld(e.add(p["live"], p["if_o"])), 0), e.ne(p["if_o"], p["if_d"])), lambda: (
                    e.st(_inter(e, p["if_d"], p["if_o"]), 1), e.st(_inter(e, p["if_o"], p["if_d"]), 1)))

            e.if_(e.ne(e.ld(e.add(p["defs"], p["if_d"])), 0), lambda: e.for_("if_o", 0, _m(e, M_T), other))

        e.for_("if_d", 0, _m(e, M_T), one)
        e.give(1)
    return _function(("defs", "live"), build, tables)


def _interference_fn(tables):
    """The interference of the tracked values, block by block backwards; the values live across a lowering's own
    labels (a conditional's terminator reads)."""
    def build(e: E):
        p = e.p
        t = _m(e, M_T)
        e.for_("in_i", 0, e.mul(t, t), lambda: e.st(e.add(_m(e, M_INTER), p["in_i"]), 0))
        _clear(e, _m(e, M_ACROSS), "in_c0")
        sets = ("in_live", "in_defs", "in_ops", "in_tmp", "in_reads", "in_with")
        for name in sets:
            e.var(name, e.alloc(e.add(t, 1)))
            _ok(e, e.ne(p[name], NONE))

        def union(into, source):
            e.for_("in_u", 0, t, lambda: e.if_(e.ne(e.ld(e.add(source, p["in_u"])), 0), lambda: e.st(e.add(into, p["in_u"]), 1)))

        def block():
            e.var("in_b", _block_at(e, p["in_bi"]))
            _clear(e, p["in_live"], "in_c1")
            _each_edge(e, p["in_b"], lambda target, n, args: union(p["in_live"], _set_of(e, BL_LIVE, target)), "ins")
            _clear(e, p["in_reads"], "in_c2")
            e.for_("in_k", 0, _f(e, p["in_b"], B_NVALUES), lambda: effective(e, e.ld(e.add(_f(e, p["in_b"], B_VALUES), p["in_k"])), p["in_reads"]))
            union(p["in_live"], p["in_reads"])
            each_edge_read(e, p["in_b"], lambda c, tg, param, arg: _bits_of(e, c, p["in_live"]), "ine")
            e.if_(e.eq(_f(e, p["in_b"], B_KIND), CONDITIONAL), lambda: union(_m(e, M_ACROSS), p["in_reads"]))
            e.var("in_m", _f(e, p["in_b"], B_NNODES))

            def node():
                e.set("in_m", e.sub(p["in_m"], 1))
                e.var("in_n", _node_at(e, p["in_b"], p["in_m"]))
                e.var("in_r0", _result0(e, p["in_n"]))
                skip = e.either(e.both(e.ne(p["in_r0"], NONE), late(e, e.sel(e.ne(p["in_r0"], NONE), p["in_r0"], 0))),
                                e.ne(_v(e, N_ELIM, _node_id(e, p["in_bi"], p["in_n"])), 0))

                def body():
                    _clear(e, p["in_defs"], "in_c3")
                    e.for_("in_r", 0, _f(e, p["in_n"], N_NRES), lambda: _bits_of(e, _output(e, p["in_n"], p["in_r"]), p["in_defs"]))
                    _clear(e, p["in_ops"], "in_c4")
                    e.for_("in_k", 0, _f(e, p["in_n"], N_NOPS), lambda: effective(e, _operand(e, p["in_n"], p["in_k"]), p["in_ops"]))
                    e.var("in_reads_first", e.flag(_in(e, _eop(e, p["in_n"]), ARITHMETIC)))
                    e.var("in_copy", e.flag(copy_like(e, p["in_bi"], p["in_n"])))

                    def result():
                        e.var("in_rv", _output(e, p["in_n"], p["in_r"]))
                        e.var("in_rb", _v(e, V_BIT, p["in_rv"]))

                        def interfere():
                            _clear(e, p["in_tmp"], "in_c5")
                            e.st(e.add(p["in_tmp"], p["in_rb"]), 1)
                            _clear(e, p["in_with"], "in_c7")
                            union(p["in_with"], p["in_live"])
                            union(p["in_with"], p["in_defs"])
                            e.if_(e.eq(p["in_reads_first"], 0), lambda: union(p["in_with"], p["in_ops"]))

                            def same():
                                e.var("in_sb", _v(e, V_BIT, canon(e, _operand(e, p["in_n"], 0))))
                                e.if_(e.ne(p["in_sb"], NONE), lambda: e.st(e.add(p["in_with"], p["in_sb"]), 0))

                            e.if_(e.both(e.eq(p["in_reads_first"], 0), e.ne(p["in_copy"], 0), e.eq(p["in_r"], 0)), same)
                            _call(e, "jm_interfere", p["in_tmp"], p["in_with"])

                        e.if_(e.ne(p["in_rb"], NONE), interfere)

                    e.for_("in_r", 0, _f(e, p["in_n"], N_NRES), result)
                    e.if_(_in(e, _eop(e, p["in_n"]), INTERNAL_LABELS), lambda: (
                        union(_m(e, M_ACROSS), p["in_live"]), union(_m(e, M_ACROSS), p["in_defs"]), union(_m(e, M_ACROSS), p["in_ops"])))
                    e.for_("in_t", 0, t, lambda: e.if_(e.ne(e.ld(e.add(p["in_defs"], p["in_t"])), 0), lambda: e.st(e.add(p["in_live"], p["in_t"]), 0)))
                    union(p["in_live"], p["in_ops"])

                e.if_(e.not_(skip), body)

            e.while_(lambda: e.lt(0, p["in_m"]), node)
            _clear(e, p["in_defs"], "in_c6")
            e.for_("in_k", 0, _f(e, p["in_b"], B_NP), lambda: _bits_of(e, e.ld(e.add(_f(e, p["in_b"], B_INPUTS), p["in_k"])), p["in_defs"]))
            union(p["in_live"], p["in_defs"])
            _call(e, "jm_interfere", p["in_defs"], p["in_live"])

        e.for_("in_bi", 0, _m(e, M_NB), block)
        e.give(1)
    return _function((), build, tables)


# -- hints, framed values, slots --------------------------------------------------------------------------------------

def _hint(e: E, a, b):
    """``hints.setdefault(a, []).append(b)``: the pair at the end of the hint list."""
    p = e.p
    e.var("hn_i", _m(e, M_NHINT))
    _ok(e, e.lt(p["hn_i"], 1 << 20))
    e.st(e.add(_m(e, M_HINT), e.mul(p["hn_i"], 2)), a)
    e.st(e.add(_m(e, M_HINT), e.add(e.mul(p["hn_i"], 2), 1)), b)
    _set_m(e, M_NHINT, e.add(p["hn_i"], 1))


def _hints_fn(tables):
    """Coalescing hints: a copy and its operand, ``x = x +- c`` (an ``iinc``), and a block parameter and the
    arguments passed to it; then the framed values."""
    def build(e: E):
        p = e.p
        _set_m(e, M_NHINT, 0)

        def node(b, nd, m):
            e.var("hi_r", _result0(e, nd))

            def copy():
                e.var("hi_o", _operand(e, nd, 0))
                e.if_(e.both(e.ne(_v(e, V_BIT, p["hi_r"]), NONE), e.ne(_v(e, V_BIT, p["hi_o"]), NONE)), lambda: (_hint(e, p["hi_r"], p["hi_o"]),
                                                                                                         _hint(e, p["hi_o"], p["hi_r"])))

            e.if_(copy_like(e, b, nd), copy)

            def increment():
                e.var("hi_o", canon(e, _operand(e, nd, 0)))
                e.if_(e.both(e.ne(_v(e, V_BIT, p["hi_r"]), NONE), e.ne(_v(e, V_BIT, p["hi_o"]), NONE)), lambda: _hint(e, p["hi_r"], p["hi_o"]))

            e.if_(_in(e, _eop(e, nd), (OP["ADD_WRAP"], OP["SUB_WRAP"])), increment)

        _each_node(e, node, "hin")

        def edges():
            e.var("hi_b", _block_at(e, p["hi_bi"]))

            def edge(target, n, args):
                e.var("hi_tb", _block_at(e, target))
                e.var("hi_args", args)

                def argument():
                    e.var("hi_param", e.ld(e.add(_f(e, p["hi_tb"], B_INPUTS), p["hi_k"])))
                    e.var("hi_arg", canon(e, e.ld(e.add(p["hi_args"], p["hi_k"]))))
                    e.if_(e.both(e.ne(_v(e, V_BIT, p["hi_param"]), NONE), e.ne(_v(e, V_BIT, p["hi_arg"]), NONE)), lambda: (
                        _hint(e, p["hi_param"], p["hi_arg"]), _hint(e, p["hi_arg"], p["hi_param"])))

                e.for_("hi_k", 0, n, argument)

            _each_edge(e, p["hi_b"], edge, "hie")

        e.for_("hi_bi", 0, _m(e, M_NB), edges)
        # Framed: across labels, every block's live-in, the parameters of blocks a branch enters, and edge reads.
        t = _m(e, M_T)
        e.var("hi_fr", _m(e, M_FRAMED))
        e.for_("hi_t", 0, t, lambda: e.st(e.add(p["hi_fr"], p["hi_t"]), e.ld(e.add(_m(e, M_ACROSS), p["hi_t"]))))
        e.for_("hi_bi", 0, _m(e, M_NB), lambda: (e.var("hi_in", _set_of(e, BL_LIVE, p["hi_bi"])), e.for_(
            "hi_t", 0, t, lambda: e.if_(e.ne(e.ld(e.add(p["hi_in"], p["hi_t"])), 0), lambda: e.st(e.add(p["hi_fr"], p["hi_t"]), 1)))))
        e.for_("hi_bi", 0, _m(e, M_NB), lambda: e.if_(e.lt(0, _v(e, BL_INC, p["hi_bi"])), lambda: (
            e.var("hi_pb", _block_at(e, p["hi_bi"])),
            e.for_("hi_k", 0, _f(e, p["hi_pb"], B_NP), lambda: _bits_of(e, e.ld(e.add(_f(e, p["hi_pb"], B_INPUTS), p["hi_k"])), p["hi_fr"])))))
        e.for_("hi_bi", 0, _m(e, M_NB), lambda: each_edge_read(e, _block_at(e, p["hi_bi"]), lambda c, tg, param, arg: _bits_of(e, c, p["hi_fr"]), "hif"))
        e.give(1)
    return _function((), build, tables)


def _slot_type(e: E, slot):
    return e.ld(e.add(_m(e, M_STYPE), slot))


def _occupy(e: E, slot, value):
    """``occupants[slot] |= bit[value]``."""
    p = e.p
    e.var("oc_i", _m(e, M_NSOCC))
    _ok(e, e.lt(p["oc_i"], 1 << 20))
    e.st(e.add(_m(e, M_SOCC), e.mul(p["oc_i"], 2)), slot)
    e.st(e.add(_m(e, M_SOCC), e.add(e.mul(p["oc_i"], 2), 1)), _v(e, V_BIT, value))
    _set_m(e, M_NSOCC, e.add(p["oc_i"], 1))


def _assign(e: E, value, slot):
    _set_v(e, C_VSLOT, value, slot)
    _set_v(e, C_VSDESC, value, _desc(e, value))
    _occupy(e, slot, value)


def _new_slot_fn(tables):
    def build(e: E):
        p = e.p
        e.var("ns_s", _m(e, M_NEXT))
        _ok(e, e.lt(e.add(p["ns_s"], 2), _m(e, M_MAXSLOTS)))
        _set_m(e, M_NEXT, e.add(p["ns_s"], _pick_slots(e, p["desc"])))
        e.st(e.add(_m(e, M_STYPE), p["ns_s"]), p["desc"])
        e.give(p["ns_s"])
    return _function(("desc",), build, tables)


def _pick_slots(e: E, desc):
    return e.sel(_in(e, desc, (D_J, 4)), 2, 1)


def _fits_fn(tables):
    """1 when ``value`` may take ``slot``: the slot's type is the value's (or a freed one-slot part), and no occupant
    of the slot interferes with it."""
    def build(e: E):
        p = e.p
        e.var("fi_st", _slot_type(e, p["slot"]))
        e.var("fi_d", _desc(e, p["value"]))
        e.if_(e.not_(e.either(e.eq(p["fi_st"], p["fi_d"]), e.both(e.eq(p["fi_st"], ST_FREED), e.eq(_pick_slots(e, p["fi_d"]), 1)))), lambda: e.give(0))
        e.var("fi_bit", _v(e, V_BIT, p["value"]))
        e.for_("fi_i", 0, _m(e, M_NSOCC), lambda: e.if_(e.eq(e.ld(e.add(_m(e, M_SOCC), e.mul(p["fi_i"], 2))), p["slot"]), lambda: e.if_(
            e.ne(e.ld(_inter(e, p["fi_bit"], e.ld(e.add(_m(e, M_SOCC), e.add(e.mul(p["fi_i"], 2), 1))))), 0), lambda: e.give(0))))
        e.give(1)
    return _function(("value", "slot"), build, tables)


def _slots_fn(tables):
    """The slot coloring: the incoming parameters first (the internal order unless the entry), a parameter no branch
    target sees freed (its slots untyped, kept parameters excepted), then every other tracked value in order: a hinted
    slot first, then the slots in order, else a new slot.  Then constants and late values (-1), aliases (their
    canonical value's slot), the typed slots and the frame's local types."""
    def build(e: E):
        p = e.p
        nv = _m(e, M_NV)
        e.for_("sl_v", 0, nv, lambda: (_set_v(e, C_VSLOT, p["sl_v"], NONE), _set_v(e, C_VSDESC, p["sl_v"], D_NONE)))
        e.for_("sl_s", 0, _m(e, M_MAXSLOTS), lambda: (e.st(e.add(_m(e, M_STYPE), p["sl_s"]), NONE), e.st(e.add(_m(e, M_FREED), p["sl_s"]), NONE),
                                                     e.st(e.add(_m(e, M_TYPED), p["sl_s"]), 0)))
        _set_m(e, M_NEXT, 0)
        _set_m(e, M_NSOCC, 0)
        e.var("sl_eb", _block_at(e, _m(e, M_ENTRY)))
        # Incoming parameters: ints and floats first unless the entry (``_internal_order``).
        for wide_pass in (0, 1):
            def incoming(wide_pass=wide_pass):
                e.var("sl_pv", e.ld(e.add(_f(e, p["sl_eb"], B_INPUTS), p["sl_k"])))
                wide = _pick_slots(e, _desc(e, p["sl_pv"]))
                select = e.sel(e.ne(_m(e, M_ISENTRY), 0), e.flag(e.eq(wide_pass, 0)), e.flag(e.eq(wide, 1 + wide_pass)))
                e.if_(e.both(e.ne(_v(e, V_DESCOF, p["sl_pv"]), 0), e.ne(select, 0)), lambda: _assign(e, p["sl_pv"], _call(e, "jm_new_slot", _desc(e, p["sl_pv"]))))

            e.for_("sl_k", 0, _f(e, p["sl_eb"], B_NP), incoming)
        _set_m(e, M_PEND, _m(e, M_NEXT))

        def free():
            e.var("sl_pv", e.ld(e.add(_f(e, p["sl_eb"], B_INPUTS), p["sl_k"])))
            e.var("sl_bit", _v(e, V_BIT, p["sl_pv"]))
            freeable = e.both(e.ne(_v(e, V_DESCOF, p["sl_pv"]), 0), e.ne(p["sl_bit"], NONE), e.eq(_m(e, M_KEPTNONE), 0),
                              e.eq(_v(e, V_KEPT, p["sl_pv"]), 0))

            def freed():
                e.var("sl_slot", _v(e, C_VSLOT, p["sl_pv"]))
                e.for_("sl_part", 0, _pick_slots(e, _desc(e, p["sl_pv"])), lambda: (
                    e.st(e.add(_m(e, M_STYPE), e.add(p["sl_slot"], p["sl_part"])), ST_FREED),
                    e.st(e.add(_m(e, M_FREED), e.add(p["sl_slot"], p["sl_part"])), p["sl_pv"]),
                    _occupy(e, e.add(p["sl_slot"], p["sl_part"]), p["sl_pv"])))

            e.if_(freeable, lambda: e.if_(e.eq(e.ld(e.add(_m(e, M_FRAMED), e.sel(e.ne(p["sl_bit"], NONE), p["sl_bit"], 0))), 0), freed))

        # ``list(slot_of.items())`` is the incoming order.
        for wide_pass in (0, 1):
            def ordered_free(wide_pass=wide_pass):
                e.var("sl_pv0", e.ld(e.add(_f(e, p["sl_eb"], B_INPUTS), p["sl_k"])))
                wide = _pick_slots(e, _desc(e, p["sl_pv0"]))
                select = e.sel(e.ne(_m(e, M_ISENTRY), 0), e.flag(e.eq(wide_pass, 0)), e.flag(e.eq(wide, 1 + wide_pass)))
                e.if_(e.ne(select, 0), free)

            e.for_("sl_k", 0, _f(e, p["sl_eb"], B_NP), ordered_free)

        def color():
            e.var("sl_v", e.ld(e.add(_m(e, M_TRACK), p["sl_i"])))

            def place():
                e.var("sl_done", 0)
                # Hinted slots, in hint order (a slot may appear twice), then every typed slot in order.
                def hinted():
                    e.var("sl_h", e.add(_m(e, M_HINT), e.mul(p["sl_hi"], 2)))
                    e.var("sl_other", e.ld(e.add(p["sl_h"], 1)))
                    e.if_(e.both(e.eq(p["sl_done"], 0), e.eq(e.ld(p["sl_h"]), p["sl_v"]), e.ne(_v(e, C_VSLOT, p["sl_other"]), NONE)), lambda: (
                        e.var("sl_cand", _v(e, C_VSLOT, p["sl_other"])),
                        e.if_(e.ne(_call(e, "jm_fits", p["sl_v"], p["sl_cand"]), 0), lambda: (
                            e.st(e.add(_m(e, M_STYPE), p["sl_cand"]), _desc(e, p["sl_v"])), _assign(e, p["sl_v"], p["sl_cand"]), e.set("sl_done", 1)))))

                e.for_("sl_hi", 0, _m(e, M_NHINT), hinted)

                def in_order():
                    e.var("sl_hinted", 0)
                    e.for_("sl_hj", 0, _m(e, M_NHINT), lambda: (e.var("sl_h2", e.add(_m(e, M_HINT), e.mul(p["sl_hj"], 2))), e.if_(
                        e.both(e.eq(e.ld(p["sl_h2"]), p["sl_v"]), e.ne(_v(e, C_VSLOT, e.ld(e.add(p["sl_h2"], 1))), NONE),
                               e.eq(_v(e, C_VSLOT, e.ld(e.add(p["sl_h2"], 1))), p["sl_s"])), lambda: e.set("sl_hinted", 1))))
                    e.if_(e.both(e.eq(p["sl_done"], 0), e.eq(p["sl_hinted"], 0), e.ne(_slot_type(e, p["sl_s"]), NONE)), lambda: e.if_(
                        e.ne(_call(e, "jm_fits", p["sl_v"], p["sl_s"]), 0), lambda: (
                            e.st(e.add(_m(e, M_STYPE), p["sl_s"]), _desc(e, p["sl_v"])), _assign(e, p["sl_v"], p["sl_s"]), e.set("sl_done", 1))))

                e.for_("sl_s", 0, _m(e, M_NEXT), in_order)
                e.if_(e.eq(p["sl_done"], 0), lambda: _assign(e, p["sl_v"], _call(e, "jm_new_slot", _desc(e, p["sl_v"]))))

            e.if_(e.eq(_v(e, C_VSLOT, p["sl_v"]), NONE), place)

        e.for_("sl_i", 0, _m(e, M_T), color)
        # Constants and late values: no local; aliases: their canonical value's slot.
        e.for_("sl_v", 0, nv, lambda: e.if_(e.both(e.ne(_v(e, V_DESCOF, p["sl_v"]), 0), e.either(e.ne(_v(e, V_CONST, p["sl_v"]), 0), late(e, p["sl_v"]))), lambda: (
            _set_v(e, C_VSLOT, p["sl_v"], SLOT_LATE), _set_v(e, C_VSDESC, p["sl_v"], _desc(e, p["sl_v"])))))

        def alias():
            e.var("sl_c", canon(e, p["sl_v"]))
            e.if_(e.ne(_v(e, C_VSLOT, p["sl_c"]), NONE), lambda: (_set_v(e, C_VSLOT, p["sl_v"], _v(e, C_VSLOT, p["sl_c"])),
                                                                 _set_v(e, C_VSDESC, p["sl_v"], _v(e, C_VSDESC, p["sl_c"]))))

        e.for_("sl_v", 0, nv, lambda: e.if_(e.ne(_v(e, V_ALIAS, p["sl_v"]), NONE), alias))
        _set_m(e, M_GEND, _m(e, M_NEXT))
        e.for_("sl_s", 0, _m(e, M_NEXT), lambda: e.if_(e.eq(_slot_type(e, p["sl_s"]), ST_FREED), lambda: e.st(e.add(_m(e, M_STYPE), p["sl_s"]), ST_TOP)))
        # Typed slots: the framed tracked values' slots, the parameters' slots that were not freed.
        e.for_("sl_i", 0, _m(e, M_T), lambda: e.if_(e.ne(e.ld(e.add(_m(e, M_FRAMED), p["sl_i"])), 0), lambda: e.st(
            e.add(_m(e, M_TYPED), _v(e, C_VSLOT, e.ld(e.add(_m(e, M_TRACK), p["sl_i"])))), 1)))
        e.for_("sl_s", 0, _m(e, M_PEND), lambda: e.if_(e.both(e.ne(_slot_type(e, p["sl_s"]), NONE), e.eq(e.ld(e.add(_m(e, M_FREED), p["sl_s"])), NONE)),
                                                       lambda: e.st(e.add(_m(e, M_TYPED), p["sl_s"]), 1)))
        # The frame's locals: each slot's type where typed, else Top for each of its slots; trailing Tops dropped.
        e.var("sl_nf", 0)

        def frame_type():
            e.var("sl_t", _slot_type(e, p["sl_s"]))

            def push(word):
                e.st(e.add(_m(e, M_FTYPES), p["sl_nf"]), word)
                e.set("sl_nf", e.add(p["sl_nf"], 1))

            e.if_(e.ne(p["sl_t"], NONE), lambda: e.if_(e.both(e.ne(e.ld(e.add(_m(e, M_TYPED), p["sl_s"])), 0), e.ne(p["sl_t"], ST_TOP)), lambda: push(p["sl_t"]),
                                                      lambda: e.for_("sl_q", 0, e.sel(e.eq(p["sl_t"], ST_TOP), 1, _pick_slots(e, p["sl_t"])), lambda: push(ST_TOP))))

        e.for_("sl_s", 0, _m(e, M_NEXT), frame_type)
        e.while_(lambda: e.both(e.lt(0, p["sl_nf"]), e.eq(e.ld(e.add(_m(e, M_FTYPES), e.sub(p["sl_nf"], 1))), ST_TOP)), lambda: e.set("sl_nf", e.sub(p["sl_nf"], 1)))
        _set_m(e, M_NFTYPES, p["sl_nf"])
        e.give(1)
    return _function((), build, tables)


def add_method_functions(add, tables):
    for name, builder in (("jm_canon", _canon_fn), ("jm_pow2", _pow2_fn), ("jm_types", _types_fn), ("jm_constants", _constants_fn),
                          ("jm_aliases", _aliases_fn), ("jm_needed", _needed_fn), ("jm_facts", _facts_fn), ("jm_inlined", _inlined_fn),
                          ("jm_repacked", _repacked_fn), ("jm_effective", _effective_fn), ("jm_tracked", _tracked_fn), ("jm_liveness", _liveness_fn),
                          ("jm_interfere", _interfere_fn), ("jm_interference", _interference_fn), ("jm_hints", _hints_fn), ("jm_new_slot", _new_slot_fn),
                          ("jm_fits", _fits_fn), ("jm_slots", _slots_fn)):
        add(name, builder(tables))
