"""Self-hosting step S15e.2 (ADR-315): the Linux AArch64 lowering of ``xax_aarch64_regalloc`` as XAX functions.

``xax_aarch64._compile_function`` lowers each closure function for the Linux AArch64 profiles with the function-wide
register allocator first (``compile_linux_function``): over the lowering view (``xax_inline.inline_leaf_calls``), a
``_Lowering`` decides eligibility, then its analyses (copies, fused compares, predicate tables, membership tests, bit
clears, loops and layout), its plan (hoisted values, loop check bounds, dead pure nodes), liveness, live intervals and
a linear-scan allocation, and emits the code.  This module adds those steps to the AArch64 program
(``xax_selfhost_aarch64_general``), on the view's records (``xax_selfhost_general_view``), in the bootstrap's order.

A function the register allocator declines (``eligible`` false, a frame of 4096 bytes or more) is lowered by another
bootstrap path; the program then declines the whole build, and the bootstrap builds.

Output, after the closure order (``xax_selfhost_x86_64_general``'s words), per closure function in image order from
``VIEW_AT``: its image index and lowering view (``xax_selfhost_general_view._lower``'s words), then its status
(``A_DECLINED``, ``A_LOWERED``).
"""

from __future__ import annotations

from xax_compiler import Operation, RESOURCE_EFFECT_OPERATIONS, TerminatorKind
from xax_selfhost_facts import E, H_ARENA, NONE, _function
from xax_selfhost_general_view import (
    B_KIND, B_NNODES, B_NODES, B_NP, B_INPUTS, CONDITIONAL, G_AUDIT, G_BCOUNT, G_BENTRY, G_BLIST, G_CAND, G_CIDX, G_FKEYN,
    G_FKEYS, G_GEXT, G_LIFT_ENTRY, G_STAMP, G_VCOUNT, G_VEXT, G_VFWD, G_VIEW_OUT, G_VMULTI, G_VPARAM, G_VPOS, G_VPROD, G_VREAD,
    G_VSTAMP, G_VSTAMP2, G_VTYPE, N_ATTR, N_NOPS, N_NRES, NOT_CALL, VCAP, VIEW_AT, _f, _globals, _operand, _out, _output, _simplify,
    _vf,
)
from xax_selfhost_general_regalloc import _eop  # a group-member call is the direct call the bootstrap's graph shows
from xax_selfhost_views_backend import _FN, CID_WORDS, G_PAY, _at, _call, _g, _ok, _payload_uleb, _type_form

A_DECLINED, A_LOWERED = 0, 1
TRACE_AT = 2  # output word: the last stage the lowering began (development and decline diagnosis)
G_A64 = 61  # the AArch64 lowering's globals table (``_a``)
A64_WORDS = 256
# Per-value tables (``_av``), VCAP + 1 words each.  ``V_W`` is the shared register tables' ``T_RW`` (``widths``).
(V_W, V_ELIDED, V_TINT, V_TSUBJ, V_TADDR, V_TDATA, V_TCOUNT, V_MSUBJ, V_MLOW, V_MMASK, V_BKEEP, V_BCLEAR, V_MINT, V_HOIST,
 V_READ, V_IV, V_WEIGHT, V_RANGES, V_NRANGES, V_CROSS, V_REG, V_SLOT, V_PARENT, V_HINT, V_PARTNERS, V_NPART, V_FIRST, V_LAST, V_STAMP,
 V_ORDER, V_LABEL) = range(31)
VALUE_TABLES = 31
# Globals after the tables' pointers: the view's block count and entry position, per-block arrays (fused compare
# node, on a cycle, loop depth), the layout order; per node (``A_NODES``: per block a word array) the check bound
# value of a loop's checked access and the dead flag; the function, its interface and borrowed-view map; the read
# buffers of ``reads`` and ``terminator_reads``.
(A_STATUS, A_NB, A_ENTRY, A_FUSED, A_INLOOP, A_DEPTH, A_ORDER, A_CHECK, A_DEAD, A_FN, A_IFACE, A_OWNB, A_RBUF, A_TBUF,
 A_BSTART, A_TERMAT, A_NODEAT, A_CALLS, A_NCALLS, A_LIVEIN, A_LIVEOUT, A_WORDS, A_POOL, A_NPOOL, A_SPILLS, A_IVLIST, A_NIV,
 A_TRAPSEC) = range(VALUE_TABLES, VALUE_TABLES + 28)
assert A_TRAPSEC < 60  # the emission's words follow (``xax_selfhost_aarch64_emit.EMIT_BASE``)
CALLER = tuple(range(0, 14))  # x0-x13
CALLEE = tuple(range(19, 30))  # x19-x29
LR = 30

SUPPORTED = tuple(sorted({int(op) for op in (
    Operation.CONSTANT, Operation.ADD_WRAP, Operation.SUB_WRAP, Operation.MUL_WRAP, Operation.BIT_AND, Operation.BIT_OR,
    Operation.BIT_XOR, Operation.INT_COMPARE, Operation.INT_TRUNCATE, Operation.INT_ZERO_EXTEND, Operation.ROTATE_RIGHT,
    Operation.ADDRESS_OFFSET, Operation.POINTER_CAST, Operation.POINTER_ADDRESS, Operation.UDIV, Operation.UREM, Operation.CALL_DIRECT,
    Operation.CALL_FOREIGN, Operation.HEAP_VIEW, Operation.LOAD_BITS_LE, Operation.RAW_LOAD_BITS_LE, Operation.STORE_BITS_LE,
    Operation.CHECKED_LOAD_BITS_LE, Operation.CHECKED_STORE_BITS_LE, Operation.POINTER_REBASE, Operation.STACK_END, *RESOURCE_EFFECT_OPERATIONS,
)}))
RESOURCE = tuple(sorted(int(op) for op in RESOURCE_EFFECT_OPERATIONS))
CALLS = (int(Operation.CALL_DIRECT), int(Operation.CALL_FOREIGN))
MEMORY = tuple(int(op) for op in (Operation.LOAD_BITS_LE, Operation.RAW_LOAD_BITS_LE, Operation.STORE_BITS_LE, Operation.CHECKED_LOAD_BITS_LE,
                                  Operation.CHECKED_STORE_BITS_LE))
TERMINATORS = tuple(int(k) for k in (TerminatorKind.RETURN, TerminatorKind.BRANCH, TerminatorKind.CONDITIONAL_BRANCH, TerminatorKind.TRAP))
NOT_MACHINE, WIDE = 0, NONE  # ``_machine_width``: a proof value; anything but bits<=64 or a pointer (the bootstrap's False)


# -- accessors ------------------------------------------------------------------------------------------------

def _a(e: E, slot: int):
    return e.ld(e.add(_g(e, G_A64), slot))


def _set_a(e: E, slot: int, value):
    e.st(e.add(_g(e, G_A64), slot), value)


def _av(e: E, table: int, value):
    if table == V_W:
        from xax_selfhost_general_regalloc import T_RW, _rt

        return _rt(e, T_RW, value)
    return e.ld(e.add(_a(e, table), value))


def _set_av(e: E, table: int, value, word):
    if table == V_W:
        from xax_selfhost_general_regalloc import T_RW, _set_rt

        _set_rt(e, T_RW, value, word)
        return
    e.st(e.add(_a(e, table), value), word)


def _q(e: E, name: str, *arguments):
    """A call of a helper whose NONE result is an answer, not a decline (``_call`` declines on NONE)."""
    return e.call(_FN[name], *arguments)


def _in(e: E, value, items):
    return e.either(*(e.eq(value, item) for item in items))


def _machine_width(e: E, type_obj, name: str):
    """``xax_aarch64_regalloc._machine_width`` into ``name``: a proof value ``NOT_MACHINE`` (0), ``bits<1..64>`` its
    width, a pointer 64, anything else ``WIDE`` (the bootstrap's False)."""
    p = e.p
    e.var(f"{name}_form", _type_form(e, type_obj))
    e.var(name, WIDE)

    def bits():
        e.var(f"{name}_at", e.add(_at(e, G_PAY, type_obj), 1))
        e.var(f"{name}_w", _payload_uleb(e, f"{name}_at"))
        e.if_(e.both(e.ne(p[f"{name}_w"], 0), e.le(p[f"{name}_w"], 64)), lambda: e.set(name, p[f"{name}_w"]))

    form = p[f"{name}_form"]
    e.if_(e.eq(form, 1), bits, lambda: e.if_(e.eq(form, 2), lambda: e.set(name, 64), lambda: e.if_(
        e.either(e.eq(form, 3), e.eq(form, 4)), lambda: e.set(name, NOT_MACHINE))))
    return p[name]


# -- eligibility (``_Lowering.eligible``) ------------------------------------------------------------------------

def _eligible(tables):
    """1 when ``compile_linux_function`` lowers function ``f``'s view, with every machine value's width in ``V_W`` and
    each call's given-back view marked in ``V_ELIDED`` (the operand it lent); 0 when it returns None."""
    def build(e: E):
        p = e.p
        n = _g(e, G_VCOUNT)
        e.for_("el_v", 0, n, lambda: (_set_av(e, V_W, p["el_v"], 0), _set_av(e, V_ELIDED, p["el_v"], NONE)))
        e.var("el_ok", 1)

        def fail():
            e.set("el_ok", 0)

        # The interface: machine parameters and results (borrowed views given back elided), each bits<=64 or a pointer.
        e.var("el_i", _call(e, "interface", p["f"]))
        e.var("el_np", e.ld(e.add(p["el_i"], 1)))
        e.var("el_rt", e.add(e.add(p["el_i"], 2), p["el_np"]))
        e.var("el_b", _call(e, "borrowed", p["f"]))
        e.var("el_mp", 0)

        def parameter():
            e.var("el_pw", _machine_width(e, e.ld(e.add(e.add(p["el_i"], 2), p["el_q"])), "el_pmw"))
            e.if_(e.eq(p["el_pw"], WIDE), fail)
            e.if_(e.ne(p["el_pw"], NOT_MACHINE), lambda: e.set("el_mp", e.add(p["el_mp"], 1)))

        e.for_("el_q", 0, p["el_np"], parameter)
        e.var("el_mr", 0)

        def result():
            e.var("el_rw", _machine_width(e, e.ld(e.add(e.add(p["el_rt"], 1), p["el_q"])), "el_rmw"))
            e.if_(e.both(e.eq(p["el_rw"], WIDE), e.eq(e.ld(e.add(p["el_b"], p["el_q"])), NONE)), fail)
            e.if_(e.both(e.ne(p["el_rw"], NOT_MACHINE), e.ne(p["el_rw"], WIDE), e.eq(e.ld(e.add(p["el_b"], p["el_q"])), NONE)),
                  lambda: e.set("el_mr", e.add(p["el_mr"], 1)))

        e.for_("el_q", 0, e.ld(p["el_rt"]), result)
        e.if_(e.either(e.lt(8, p["el_mp"]), e.lt(1, p["el_mr"])), fail)

        def width_of(value, name):
            e.var(f"{name}_v", value)
            e.var(name, _machine_width(e, _vf(e, G_VTYPE, p[f"{name}_v"]), f"{name}_mw"))
            e.if_(e.eq(p[name], WIDE), fail, lambda: e.if_(e.ne(p[name], NOT_MACHINE), lambda: _set_av(e, V_W, p[f"{name}_v"], p[name])))
            return p[name]

        def block():
            e.var("el_blk", e.ld(e.add(_g(e, G_BLIST), p["el_k"])))
            e.for_("el_j", 0, _f(e, p["el_blk"], B_NP), lambda: width_of(e.ld(e.add(_f(e, p["el_blk"], B_INPUTS), p["el_j"])), "el_bp"))

            def node():
                e.var("el_n", e.ld(e.add(_f(e, p["el_blk"], B_NODES), p["el_m"])))
                e.var("el_op", _eop(e, p["el_n"]))
                e.if_(e.not_(_in(e, p["el_op"], SUPPORTED)), fail)
                e.for_("el_o", 0, _f(e, p["el_n"], N_NOPS), lambda: e.if_(
                    e.eq(_machine_width(e, _vf(e, G_VTYPE, _operand(e, p["el_n"], p["el_o"])), "el_ow"), WIDE), fail))
                e.var("el_mres", 0)
                e.for_("el_r", 0, _f(e, p["el_n"], N_NRES), lambda: e.if_(
                    e.ne(width_of(_output(e, p["el_n"], p["el_r"]), "el_res"), NOT_MACHINE), lambda: e.if_(
                        e.ne(p["el_res"], WIDE), lambda: e.set("el_mres", e.add(p["el_mres"], 1)))))
                e.if_(e.both(e.either(_in(e, p["el_op"], RESOURCE), e.eq(p["el_op"], int(Operation.STACK_END))), e.ne(p["el_mres"], 0)), fail)

                def call():
                    e.var("el_erased", 0)

                    def direct():
                        from xax_selfhost_general_regalloc import _callee_object

                        _callee_object(e, p["el_n"], "el_callee")
                        _ok(e, e.ne(p["el_callee"], NONE))
                        e.set("el_erased", _call(e, "erased", p["el_callee"]))

                    e.if_(e.eq(p["el_op"], int(Operation.CALL_DIRECT)), direct)

                    def counted():
                        e.var("el_mops", 0)
                        e.for_("el_o", 0, _f(e, p["el_n"], N_NOPS), lambda: e.if_(e.ne(
                            _machine_width(e, _vf(e, G_VTYPE, _operand(e, p["el_n"], p["el_o"])), "el_cw"), NOT_MACHINE),
                            lambda: e.set("el_mops", e.add(p["el_mops"], 1))))
                        e.var("el_nelided", 0)
                        e.if_(e.eq(p["el_op"], int(Operation.CALL_DIRECT)), lambda: e.set("el_nelided", _call(e, "a64_call_elided", p["el_n"])))
                        e.if_(e.either(e.lt(8, p["el_mops"]), e.lt(e.add(1, p["el_nelided"]), p["el_mres"])), fail)

                    e.if_(e.eq(p["el_erased"], 0), counted)

                e.if_(_in(e, p["el_op"], CALLS), call)
                e.if_(e.both(_in(e, p["el_op"], MEMORY), e.not_(_in(e, e.rd(e.add(_f(e, p["el_n"], N_ATTR), 1)), (1, 2, 4, 8)))), fail)

            e.for_("el_m", 0, _f(e, p["el_blk"], B_NNODES), node)
            e.if_(e.not_(_in(e, _f(e, p["el_blk"], B_KIND), TERMINATORS)), fail)

        e.for_("el_k", 0, _g(e, G_BCOUNT), block)
        e.give(p["el_ok"])
    return _function(("f",), build, tables)


def _call_elided(tables):
    """``borrowed_view_returns(node.operand_types, node.results)`` of direct call ``node``: each given-back result's
    ``V_ELIDED`` is the operand it lent; the count."""
    def build(e: E):
        p = e.p
        from xax_selfhost_general_regalloc import _callee_object

        _callee_object(e, p["node"], "ce_callee")
        _ok(e, e.ne(p["ce_callee"], NONE))
        e.var("ce_map", _call(e, "borrowed", p["ce_callee"]))
        e.var("ce_count", 0)

        def each():
            e.var("ce_param", e.ld(e.add(p["ce_map"], p["ce_r"])))

            def elided():
                _set_av(e, V_ELIDED, _output(e, p["node"], p["ce_r"]), _operand(e, p["node"], p["ce_param"]))
                e.set("ce_count", e.add(p["ce_count"], 1))

            e.if_(e.ne(p["ce_param"], NONE), elided)

        e.for_("ce_r", 0, _f(e, p["node"], N_NRES), each)
        e.give(p["ce_count"])
    return _function(("node",), build, tables)


# -- analyses (``_Lowering._analyze``) -----------------------------------------------------------------------------

def _rt_(e: E, table: int, value):
    from xax_selfhost_general_regalloc import _rt

    return _rt(e, table, value)


def _set_rt_(e: E, table: int, value, word):
    from xax_selfhost_general_regalloc import _set_rt

    _set_rt(e, table, value, word)


def _canon(e: E, value, name: str):
    """``canon(value)`` into ``name``: the alias chain (``T_ALIAS``) followed to its representative."""
    from xax_selfhost_general_regalloc import T_ALIAS

    p = e.p
    e.var(name, value)
    e.while_(lambda: e.ne(_rt_(e, T_ALIAS, p[name]), NONE), lambda: e.set(name, _rt_(e, T_ALIAS, p[name])))
    return p[name]


def _const(e: E, value, name: str):
    """``const(value)``: sets ``name`` to the constant of ``canon(value)`` and ``name_is`` to 1 when it is one."""
    from xax_selfhost_general_ranges import G2_CONST, G2_CVAL, _t

    p = e.p
    c = _canon(e, value, f"{name}_c")
    e.var(f"{name}_is", e.flag(e.ne(_t(e, G2_CONST, c), 0)))
    e.var(name, e.sel(e.ne(p[f"{name}_is"], 0), _t(e, G2_CVAL, c), 0))
    return p[name]


def _pos(e: E, block, index, result):
    """A node result's packed position (``G_VPOS``)."""
    from xax_selfhost_general_view import POS_BLOCK, POS_INDEX, POS_TAG

    return e.add(e.add(e.add(POS_TAG, e.mul(block, POS_BLOCK)), e.mul(index, POS_INDEX)), result)


def _synthetic(e: E, block, index, result, name: str):
    """A synthetic value ``ValueRef.node_result(block, index, result)`` (a mask, a table address, a check bound): a
    fresh value id of width 64, no constant yet."""
    from xax_selfhost_general_ranges import G2_CONST, _set_t
    from xax_selfhost_general_view import _new_value, _set_vf

    p = e.p
    _new_value(e, 0, name)
    _set_vf(e, G_VPOS, p[name], _pos(e, block, index, result))
    _set_av(e, V_W, p[name], 64)
    _set_t(e, G2_CONST, p[name], 0)
    for table in range(1, VALUE_TABLES):
        _set_av(e, table, p[name], NONE if table in (V_ELIDED, V_TSUBJ, V_TADDR, V_MSUBJ, V_BKEEP) else 0)
    from xax_selfhost_general_regalloc import T_ALIAS, T_EARLY, T_S1, T_S2, T_USES

    _set_rt_(e, T_ALIAS, p[name], NONE)
    _set_rt_(e, T_USES, p[name], 0)
    _set_rt_(e, T_EARLY, p[name], 0)
    _set_rt_(e, T_S1, p[name], 0)
    _set_rt_(e, T_S2, p[name], 0)


def _block_values(e: E, visit, *, nodes=True, terminator=True, edges=True):
    """``visit(value)`` for every operand of every block's nodes, terminator value, and edge argument, in the
    bootstrap's order (block by block)."""
    from xax_selfhost_general_view import B_EDGES, B_NEDGES, B_NVALUES, B_VALUES, EDGE

    p = e.p

    def block():
        e.var("bv_b", e.ld(e.add(_g(e, G_BLIST), p["bv_q"])))
        b = p["bv_b"]
        if nodes:
            def node():
                e.var("bv_n", e.ld(e.add(_f(e, b, B_NODES), p["bv_m"])))
                e.for_("bv_o", 0, _f(e, p["bv_n"], N_NOPS), lambda: visit(_operand(e, p["bv_n"], p["bv_o"])))

            e.for_("bv_m", 0, _f(e, b, B_NNODES), node)
        if terminator:
            e.for_("bv_o", 0, _f(e, b, B_NVALUES), lambda: visit(e.ld(e.add(_f(e, b, B_VALUES), p["bv_o"]))))
        if edges:
            def edge():
                e.var("bv_e", e.add(_f(e, b, B_EDGES), e.mul(p["bv_k"], EDGE)))
                e.for_("bv_o", 0, _f(e, p["bv_e"], 1), lambda: visit(e.ld(e.add(_f(e, p["bv_e"], 2), p["bv_o"]))))

            e.for_("bv_k", 0, _f(e, b, B_NEDGES), edge)

    e.for_("bv_q", 0, _g(e, G_BCOUNT), block)


def _aliases(tables):
    """The constants and range analysis, then copies (``alias``): pointer casts and addresses, heap views, zero
    extensions, lossless truncations, rebased pointers, given-back views; then block parameters that every incoming
    argument gives one value, to a fixed point in the bootstrap's order."""
    from xax_selfhost_general_ranges import G2_BITWISE, G2_RNONE, G2_WIDTHS, _g2, _limit, _pos_block, _pos_index, _set_g2
    from xax_selfhost_general_regalloc import T_ALIAS, T_EARLY, T_RW, T_S1, T_S2, T_USES, _ra, _stamp
    from xax_selfhost_general_view import B_EDGES, B_NEDGES, B_POS, EDGE

    def build(e: E):
        p = e.p
        n = _g(e, G_VCOUNT)
        e.var("al_n", n)

        def init():
            v = p["al_v"]
            _set_rt_(e, T_ALIAS, v, NONE)
            _set_rt_(e, T_USES, v, 0)
            _set_rt_(e, T_EARLY, v, 0)
            # The stamp counter restarts every run and the program's memory is not cleared between runs.
            _set_rt_(e, T_S1, v, 0)
            _set_rt_(e, T_S2, v, 0)
            for table in range(1, VALUE_TABLES):
                if table != V_ELIDED:
                    _set_av(e, table, v, NONE if table in (V_TSUBJ, V_TADDR, V_MSUBJ, V_BKEEP) else 0)

        e.for_("al_v", 0, p["al_n"], init)
        _set_a(e, A_NB, _g(e, G_BCOUNT))
        _set_a(e, A_ENTRY, _f(e, _g(e, G_BENTRY), B_POS))
        # ``upper_bounds(graph, widths, constants, bitwise=True)``.
        _set_g2(e, G2_WIDTHS, _ra(e, T_RW))
        _set_g2(e, G2_BITWISE, 1)
        _call(e, "bounds")

        def node_aliases():
            e.var("na_b", e.ld(e.add(_g(e, G_BLIST), p["na_q"])))

            def node():
                e.var("na_node", e.ld(e.add(_f(e, p["na_b"], B_NODES), p["na_m"])))
                e.if_(e.eq(_f(e, p["na_node"], N_NRES), 0), lambda: None, lambda: one())

            def one():
                e.var("na_r", _output(e, p["na_node"], 0))
                e.var("na_op", _eop(e, p["na_node"]))
                op = p["na_op"]

                def machine():
                    copies = (Operation.POINTER_CAST, Operation.POINTER_ADDRESS, Operation.HEAP_VIEW, Operation.INT_ZERO_EXTEND)
                    e.if_(_in(e, op, tuple(int(x) for x in copies)), lambda: _set_rt_(e, T_ALIAS, p["na_r"], _operand(e, p["na_node"], 0)))
                    e.if_(e.eq(op, int(Operation.POINTER_REBASE)), lambda: _set_rt_(e, T_ALIAS, p["na_r"], _operand(e, p["na_node"], 1)))

                    def truncate():
                        e.var("na_bound", e.call(_FN["maximum0"], _operand(e, p["na_node"], 0)))
                        e.var("na_limit", _limit(e, _rt_(e, T_RW, p["na_r"])))
                        e.if_(e.both(e.eq(_g2(e, G2_RNONE), 0), e.le(p["na_bound"], p["na_limit"])),
                              lambda: _set_rt_(e, T_ALIAS, p["na_r"], _operand(e, p["na_node"], 0)))

                    e.if_(e.eq(op, int(Operation.INT_TRUNCATE)), truncate)

                e.if_(e.ne(_rt_(e, T_RW, p["na_r"]), 0), machine)

            e.for_("na_m", 0, _f(e, p["na_b"], B_NNODES), node)

        e.for_("na_q", 0, _g(e, G_BCOUNT), node_aliases)
        # A view a call gives back is a copy of the operand it lent.
        e.for_("al_v", 0, p["al_n"], lambda: e.if_(e.ne(_av(e, V_ELIDED, p["al_v"]), NONE), lambda: _set_rt_(e, T_ALIAS, p["al_v"], _av(e, V_ELIDED, p["al_v"]))))
        # Block parameters, in the order they first appear as an edge's parameter.
        e.var("al_list", e.alloc(e.add(p["al_n"], 1)))
        _ok(e, e.ne(p["al_list"], NONE))
        e.var("al_count", 0)
        e.var("al_seen", _stamp(e))

        def first(target, index):
            e.var("fp_param", e.ld(e.add(_f(e, target, B_INPUTS), index)))
            e.if_(e.ne(_rt_(e, T_S1, p["fp_param"]), p["al_seen"]), lambda: (
                _set_rt_(e, T_S1, p["fp_param"], p["al_seen"]), e.st(e.add(p["al_list"], p["al_count"]), p["fp_param"]),
                e.set("al_count", e.add(p["al_count"], 1))))

        def edges_of(visit):
            def block():
                e.var("ae_b", e.ld(e.add(_g(e, G_BLIST), p["ae_q"])))

                def edge():
                    e.var("ae_e", e.add(_f(e, p["ae_b"], B_EDGES), e.mul(p["ae_k"], EDGE)))
                    e.for_("ae_a", 0, _f(e, p["ae_e"], 1), lambda: visit(_f(e, p["ae_e"], 0), p["ae_a"], e.ld(e.add(_f(e, p["ae_e"], 2), p["ae_a"]))))

                e.for_("ae_k", 0, _f(e, p["ae_b"], B_NEDGES), edge)

            e.for_("ae_q", 0, _g(e, G_BCOUNT), block)

        edges_of(lambda target, index, _argument: first(target, index))
        e.var("al_changed", 1)

        def round_():
            e.set("al_changed", 0)

            def parameter():
                e.var("ap_v", e.ld(e.add(p["al_list"], p["ap_k"])))
                v = p["ap_v"]
                skip = e.either(e.eq(_pos_block(e, v), _a(e, A_ENTRY)), e.eq(_rt_(e, T_RW, v), 0), e.ne(_rt_(e, T_ALIAS, v), NONE))

                def sources():
                    e.var("ap_mark", _stamp(e))
                    e.var("ap_distinct", 0)
                    e.var("ap_one", NONE)

                    def argument(target, index, value):
                        def mine():
                            c = _canon(e, value, "ap_c")

                            def new():
                                _set_rt_(e, T_S2, c, p["ap_mark"])
                                e.set("ap_distinct", e.add(p["ap_distinct"], 1))
                                e.set("ap_one", c)

                            e.if_(e.both(e.ne(c, v), e.ne(_rt_(e, T_S2, c), p["ap_mark"])), new)

                        e.if_(e.both(e.eq(_f(e, target, B_POS), _pos_block(e, v)), e.eq(index, _pos_index(e, v))), mine)

                    edges_of(argument)
                    e.if_(e.eq(p["ap_distinct"], 1), lambda: (_set_rt_(e, T_ALIAS, v, p["ap_one"]), e.set("al_changed", 1)))

                e.if_(e.not_(skip), sources)

            e.for_("ap_k", 0, p["al_count"], parameter)

        e.while_(lambda: e.ne(p["al_changed"], 0), round_)
        e.give(1)
    return _function((), build, tables)


def _uses(tables):
    """``uses`` (canonical: ``T_USES``) and ``raw_uses`` (``T_EARLY``) of every operand, terminator value and edge
    argument; then the fused compares (``A_FUSED``): a conditional branch's condition, an ``int.compare`` result 0 of
    its own block used once."""
    from xax_selfhost_general_ranges import _is_param, _pos_block, _pos_index, _pos_result
    from xax_selfhost_general_regalloc import T_EARLY, T_USES
    from xax_selfhost_general_view import B_VALUES

    def build(e: E):
        p = e.p

        def count(value):
            e.var("us_v", value)
            _set_rt_(e, T_EARLY, p["us_v"], e.add(_rt_(e, T_EARLY, p["us_v"]), 1))
            c = _canon(e, p["us_v"], "us_c")
            _set_rt_(e, T_USES, c, e.add(_rt_(e, T_USES, c), 1))

        _block_values(e, count)
        e.var("uf_fused", e.alloc(e.add(_a(e, A_NB), 1)))
        _ok(e, e.ne(p["uf_fused"], NONE))
        _set_a(e, A_FUSED, p["uf_fused"])

        def block():
            e.var("uf_b", e.ld(e.add(_g(e, G_BLIST), p["uf_q"])))
            e.st(e.add(p["uf_fused"], p["uf_q"]), NONE)

            def conditional():
                c = _canon(e, e.ld(_f(e, p["uf_b"], B_VALUES)), "uf_c")
                local = e.both(e.not_(_is_param(e, c)), e.eq(_pos_block(e, c), p["uf_q"]), e.eq(_pos_result(e, c), 0), e.eq(_rt_(e, T_USES, c), 1))
                e.if_(local, lambda: e.if_(e.eq(_eop(e, _vf(e, G_VPROD, c)), int(Operation.INT_COMPARE)),
                                           lambda: e.st(e.add(p["uf_fused"], p["uf_q"]), _pos_index(e, c))))

            e.if_(e.eq(_f(e, p["uf_b"], B_KIND), CONDITIONAL), conditional)

        e.for_("uf_q", 0, _g(e, G_BCOUNT), block)
        e.give(1)
    return _function((), build, tables)


def _tables(tables):
    """Predicate tables (ADR-208, ADR-254): per block, nodes in reverse, a table-operation root of a machine width,
    not a copy, not the fused compare, not internal to an earlier table, whose expression reads one byte-bounded value
    (``xax_ranges.predicate_table``, the shared XAX analysis): its subject and a synthetic address (result 2, width
    64) whose data is the table."""
    from xax_selfhost_general_regalloc import T_ALIAS

    def build(e: E):
        p = e.p
        table_ops = tuple(int(op) for op in (Operation.INT_COMPARE, Operation.ADD_WRAP, Operation.SUB_WRAP, Operation.MUL_WRAP, Operation.BIT_AND,
                                             Operation.BIT_OR, Operation.BIT_XOR))

        def block():
            e.var("tb_b", e.ld(e.add(_g(e, G_BLIST), p["tb_q"])))
            e.var("tb_m", _f(e, p["tb_b"], B_NNODES))

            def node():
                e.set("tb_m", e.sub(p["tb_m"], 1))
                e.var("tb_node", e.ld(e.add(_f(e, p["tb_b"], B_NODES), p["tb_m"])))
                e.var("tb_root", _output(e, p["tb_node"], 0))
                root = p["tb_root"]
                candidate = e.both(e.ne(_f(e, p["tb_node"], N_NRES), 0), e.eq(_av(e, V_TINT, e.sel(e.ne(_f(e, p["tb_node"], N_NRES), 0), root, 0)), 0))

                def check():
                    skip = e.either(e.eq(_av(e, V_W, root), 0), e.ne(_rt_(e, T_ALIAS, root), NONE),
                                    e.eq(p["tb_m"], e.ld(e.add(_a(e, A_FUSED), p["tb_q"]))), e.not_(_in(e, _eop(e, p["tb_node"]), table_ops)))

                    def found():
                        e.var("tb_rec", _call(e, "predicate_table", p["tb_q"], root))

                        def table():
                            _synthetic(e, p["tb_q"], p["tb_m"], 2, "tb_address")
                            _set_av(e, V_TSUBJ, root, e.ld(p["tb_rec"]))
                            _set_av(e, V_TADDR, root, p["tb_address"])
                            _set_av(e, V_TDATA, p["tb_address"], e.ld(e.add(p["tb_rec"], 1)))
                            _set_av(e, V_TCOUNT, p["tb_address"], e.ld(e.add(p["tb_rec"], 2)))
                            e.var("tb_flags", e.ld(e.add(p["tb_rec"], 3)))
                            e.for_("tb_k", 0, _f(e, p["tb_b"], B_NNODES), lambda: e.if_(e.ne(e.ld(e.add(p["tb_flags"], p["tb_k"])), 0), lambda: e.if_(
                                e.ne(_f(e, e.ld(e.add(_f(e, p["tb_b"], B_NODES), p["tb_k"])), N_NRES), 0),
                                lambda: _set_av(e, V_TINT, _output(e, e.ld(e.add(_f(e, p["tb_b"], B_NODES), p["tb_k"])), 0), 1))))

                        e.if_(e.ne(p["tb_rec"], NOT_CALL), table)

                    e.if_(e.not_(skip), found)

                e.if_(candidate, check)

            e.while_(lambda: e.ne(p["tb_m"], 0), node)

        e.for_("tb_q", 0, _g(e, G_BCOUNT), block)
        e.give(1)
    return _function((), build, tables)


def _successors(e: E, block_index, visit):
    """``visit(target position)`` for each edge of block ``block_index`` in order (duplicates kept)."""
    from xax_selfhost_general_view import B_EDGES, B_NEDGES, B_POS, EDGE

    p = e.p
    e.var("sc_b", e.ld(e.add(_g(e, G_BLIST), block_index)))
    e.for_("sc_k", 0, _f(e, p["sc_b"], B_NEDGES), lambda: visit(_f(e, _f(e, e.add(_f(e, p["sc_b"], B_EDGES), e.mul(p["sc_k"], EDGE)), 0), B_POS)))


def _loops(tables):
    """``in_loop`` (blocks on a CFG cycle), ``_loop_depths`` (natural loops of back edges, by dominators), and
    ``_layout`` (reverse postorder, a block's deepest-loop successor visited last), into ``A_INLOOP``, ``A_DEPTH``,
    ``A_ORDER``."""
    def build(e: E):
        p = e.p
        e.var("lp_n", _a(e, A_NB))
        n = p["lp_n"]
        e.var("lp_edges", 0)
        e.for_("lp_q", 0, n, lambda: _successors(e, p["lp_q"], lambda target: e.set("lp_edges", e.add(p["lp_edges"], 1))))
        # Successor lists (edge order) and predecessor lists (by source, then edge).
        e.var("lp_succ_at", e.alloc(e.add(n, 1)))
        e.var("lp_succ_n", e.alloc(e.add(n, 1)))
        e.var("lp_succ", e.alloc(e.add(p["lp_edges"], 1)))
        e.var("lp_pred_at", e.alloc(e.add(n, 1)))
        e.var("lp_pred_n", e.alloc(e.add(n, 1)))
        e.var("lp_pred", e.alloc(e.add(p["lp_edges"], 1)))
        for name in ("lp_succ_at", "lp_succ_n", "lp_succ", "lp_pred_at", "lp_pred_n", "lp_pred"):
            _ok(e, e.ne(p[name], NONE))
        e.var("lp_k", 0)

        def lists():
            e.st(e.add(p["lp_succ_at"], p["lp_q"]), p["lp_k"])
            _successors(e, p["lp_q"], lambda target: (e.st(e.add(p["lp_succ"], p["lp_k"]), target), e.set("lp_k", e.add(p["lp_k"], 1))))
            e.st(e.add(p["lp_succ_n"], p["lp_q"]), e.sub(p["lp_k"], e.ld(e.add(p["lp_succ_at"], p["lp_q"]))))
            e.st(e.add(p["lp_pred_n"], p["lp_q"]), 0)

        e.for_("lp_q", 0, n, lists)
        succ = lambda block, k: e.ld(e.add(p["lp_succ"], e.add(e.ld(e.add(p["lp_succ_at"], block)), k)))  # noqa: E731
        nsucc = lambda block: e.ld(e.add(p["lp_succ_n"], block))  # noqa: E731
        e.for_("lp_q", 0, n, lambda: e.for_("lp_j", 0, nsucc(p["lp_q"]), lambda: (
            e.var("lp_t", succ(p["lp_q"], p["lp_j"])), e.st(e.add(p["lp_pred_n"], p["lp_t"]), e.add(e.ld(e.add(p["lp_pred_n"], p["lp_t"])), 1)))))
        e.set("lp_k", 0)
        e.for_("lp_q", 0, n, lambda: (e.st(e.add(p["lp_pred_at"], p["lp_q"]), p["lp_k"]), e.set("lp_k", e.add(p["lp_k"], e.ld(e.add(p["lp_pred_n"], p["lp_q"])))),
                                      e.st(e.add(p["lp_pred_n"], p["lp_q"]), 0)))
        e.for_("lp_q", 0, n, lambda: e.for_("lp_j", 0, nsucc(p["lp_q"]), lambda: (
            e.var("lp_t", succ(p["lp_q"], p["lp_j"])),
            e.st(e.add(p["lp_pred"], e.add(e.ld(e.add(p["lp_pred_at"], p["lp_t"])), e.ld(e.add(p["lp_pred_n"], p["lp_t"])))), p["lp_q"]),
            e.st(e.add(p["lp_pred_n"], p["lp_t"]), e.add(e.ld(e.add(p["lp_pred_n"], p["lp_t"])), 1)))))
        pred = lambda block, k: e.ld(e.add(p["lp_pred"], e.add(e.ld(e.add(p["lp_pred_at"], block)), k)))  # noqa: E731
        npred = lambda block: e.ld(e.add(p["lp_pred_n"], block))  # noqa: E731
        # ``in_loop``: ``_reaches(successors, b, b)``.
        e.var("lp_inloop", e.alloc(e.add(n, 1)))
        e.var("lp_seen", e.alloc(e.add(n, 1)))
        e.var("lp_stack", e.alloc(e.add(e.add(p["lp_edges"], n), 2)))
        for name in ("lp_inloop", "lp_seen", "lp_stack"):
            _ok(e, e.ne(p[name], NONE))
        _set_a(e, A_INLOOP, p["lp_inloop"])

        def reaches():
            e.st(e.add(p["lp_inloop"], p["lp_q"]), 0)
            e.for_("lp_z", 0, n, lambda: e.st(e.add(p["lp_seen"], p["lp_z"]), 0))
            e.var("lp_sp", 0)
            e.for_("lp_j", 0, nsucc(p["lp_q"]), lambda: (e.st(e.add(p["lp_stack"], p["lp_sp"]), succ(p["lp_q"], p["lp_j"])), e.set("lp_sp", e.add(p["lp_sp"], 1))))

            def step():
                e.set("lp_sp", e.sub(p["lp_sp"], 1))
                e.var("lp_x", e.ld(e.add(p["lp_stack"], p["lp_sp"])))

                def found():
                    e.st(e.add(p["lp_inloop"], p["lp_q"]), 1)
                    e.set("lp_sp", 0)

                def expand():
                    e.st(e.add(p["lp_seen"], p["lp_x"]), 1)

                    def push():
                        e.st(e.add(p["lp_stack"], p["lp_sp"]), succ(p["lp_x"], p["lp_j"]))
                        e.set("lp_sp", e.add(p["lp_sp"], 1))

                    e.for_("lp_j", 0, nsucc(p["lp_x"]), push)

                e.if_(e.eq(p["lp_x"], p["lp_q"]), found, lambda: e.if_(e.eq(e.ld(e.add(p["lp_seen"], p["lp_x"])), 0), expand))

            e.while_(lambda: e.ne(p["lp_sp"], 0), step)

        e.for_("lp_q", 0, n, reaches)
        # Dominators, as bit sets of ``lp_w`` words per block.
        e.var("lp_w", e.udiv(e.add(n, 63), 64))
        e.var("lp_dom", e.alloc(e.add(e.mul(n, p["lp_w"]), 1)))
        e.var("lp_new", e.alloc(e.add(p["lp_w"], 1)))
        _ok(e, e.both(e.ne(p["lp_dom"], NONE), e.ne(p["lp_new"], NONE)))
        word = lambda block, k: e.add(e.add(p["lp_dom"], e.mul(block, p["lp_w"])), k)  # noqa: E731

        e.var("lp_entry", _a(e, A_ENTRY))

        def full(block):
            def each():
                e.var("lp_full", (1 << 64) - 1)
                e.var("lp_rest", e.sub(n, e.mul(p["lp_wk"], 64)))
                e.if_(e.lt(p["lp_rest"], 64), lambda: e.set("lp_full", e.sub(_power(e, p["lp_rest"]), 1)))
                e.st(word(block, p["lp_wk"]), p["lp_full"])

            e.for_("lp_wk", 0, p["lp_w"], each)

        e.for_("lp_q", 0, n, lambda: full(p["lp_q"]))
        e.for_("lp_wk", 0, p["lp_w"], lambda: e.st(word(p["lp_entry"], p["lp_wk"]), 0))
        set_bit = lambda at, index: e.st(e.add(at, e.udiv(index, 64)), e.bin(Operation.BIT_OR, e.ld(e.add(at, e.udiv(index, 64))), _power(e, e.and_(index, 63))))  # noqa: E731
        set_bit(word(p["lp_entry"], 0), p["lp_entry"])
        e.var("lp_changed", 1)

        def dominator_round():
            e.set("lp_changed", 0)

            def block():
                def compute():
                    e.var("lp_np", npred(p["lp_q"]))
                    e.for_("lp_wk", 0, p["lp_w"], lambda: e.st(e.add(p["lp_new"], p["lp_wk"]), e.sel(e.eq(p["lp_np"], 0), 0, (1 << 64) - 1)))
                    e.for_("lp_j", 0, p["lp_np"], lambda: (e.var("lp_pp", pred(p["lp_q"], p["lp_j"])), e.for_("lp_wk", 0, p["lp_w"], lambda: e.st(
                        e.add(p["lp_new"], p["lp_wk"]), e.and_(e.ld(e.add(p["lp_new"], p["lp_wk"])), e.ld(word(p["lp_pp"], p["lp_wk"])))))))
                    set_bit(p["lp_new"], p["lp_q"])
                    e.var("lp_diff", 0)
                    e.for_("lp_wk", 0, p["lp_w"], lambda: e.if_(e.ne(e.ld(e.add(p["lp_new"], p["lp_wk"])), e.ld(word(p["lp_q"], p["lp_wk"]))), lambda: e.set("lp_diff", 1)))
                    e.if_(e.ne(p["lp_diff"], 0), lambda: (e.for_("lp_wk", 0, p["lp_w"], lambda: e.st(word(p["lp_q"], p["lp_wk"]), e.ld(e.add(p["lp_new"], p["lp_wk"])))),
                                                          e.set("lp_changed", 1)))

                e.if_(e.ne(p["lp_q"], p["lp_entry"]), compute)

            e.for_("lp_q", 0, n, block)

        e.while_(lambda: e.ne(p["lp_changed"], 0), dominator_round)
        has = lambda block, index: e.ne(e.and_(e.ld(word(block, e.udiv(index, 64))), _power(e, e.and_(index, 63))), 0)  # noqa: E731
        # Depths: each back edge's natural loop adds one to its blocks.
        e.var("lp_depth", e.alloc(e.add(n, 1)))
        e.var("lp_body", e.alloc(e.add(n, 1)))
        _ok(e, e.both(e.ne(p["lp_depth"], NONE), e.ne(p["lp_body"], NONE)))
        _set_a(e, A_DEPTH, p["lp_depth"])
        e.for_("lp_q", 0, n, lambda: (e.st(e.add(p["lp_depth"], p["lp_q"]), 0), e.st(e.add(p["lp_body"], p["lp_q"]), 0)))
        e.var("lp_mark", 0)

        def back_edges():
            def edge():
                e.var("lp_h", succ(p["lp_q"], p["lp_j"]))

                def loop():
                    e.set("lp_mark", e.add(p["lp_mark"], 1))
                    e.st(e.add(p["lp_body"], p["lp_h"]), p["lp_mark"])
                    e.st(e.add(p["lp_body"], p["lp_q"]), p["lp_mark"])
                    e.var("lp_sp", 1)
                    e.st(p["lp_stack"], p["lp_q"])

                    def walk():
                        e.set("lp_sp", e.sub(p["lp_sp"], 1))
                        e.var("lp_x", e.ld(e.add(p["lp_stack"], p["lp_sp"])))
                        e.if_(e.ne(p["lp_x"], p["lp_h"]), lambda: e.for_("lp_i", 0, npred(p["lp_x"]), lambda: (
                            e.var("lp_y", pred(p["lp_x"], p["lp_i"])),
                            e.if_(e.ne(e.ld(e.add(p["lp_body"], p["lp_y"])), p["lp_mark"]), lambda: (
                                e.st(e.add(p["lp_body"], p["lp_y"]), p["lp_mark"]), e.st(e.add(p["lp_stack"], p["lp_sp"]), p["lp_y"]),
                                e.set("lp_sp", e.add(p["lp_sp"], 1)))))))

                    e.while_(lambda: e.ne(p["lp_sp"], 0), walk)
                    e.for_("lp_z", 0, n, lambda: e.if_(e.eq(e.ld(e.add(p["lp_body"], p["lp_z"])), p["lp_mark"]), lambda: e.st(
                        e.add(p["lp_depth"], p["lp_z"]), e.add(e.ld(e.add(p["lp_depth"], p["lp_z"])), 1))))

                e.if_(has(p["lp_q"], p["lp_h"]), loop)

            e.for_("lp_j", 0, nsucc(p["lp_q"]), edge)

        e.for_("lp_q", 0, n, back_edges)
        # The layout: depth first from the entry over successors sorted by (depth, -index).
        e.var("lp_sorted", e.alloc(e.add(p["lp_edges"], 1)))
        _ok(e, e.ne(p["lp_sorted"], NONE))

        def sort_block():
            e.var("lp_at", e.ld(e.add(p["lp_succ_at"], p["lp_q"])))
            e.for_("lp_j", 0, nsucc(p["lp_q"]), lambda: e.st(e.add(p["lp_sorted"], e.add(p["lp_at"], p["lp_j"])), succ(p["lp_q"], p["lp_j"])))

            def insert():
                e.var("lp_item", e.ld(e.add(p["lp_sorted"], e.add(p["lp_at"], p["lp_s"]))))
                e.var("lp_i", p["lp_s"])
                key_less = lambda a, b: e.either(e.lt(e.ld(e.add(p["lp_depth"], a)), e.ld(e.add(p["lp_depth"], b))), e.both(  # noqa: E731
                    e.eq(e.ld(e.add(p["lp_depth"], a)), e.ld(e.add(p["lp_depth"], b))), e.lt(b, a)))
                before = lambda: e.both(e.lt(0, p["lp_i"]), key_less(p["lp_item"], e.ld(e.add(p["lp_sorted"], e.add(p["lp_at"], e.sub(p["lp_i"], 1))))))  # noqa: E731
                e.while_(before, lambda: (e.st(e.add(p["lp_sorted"], e.add(p["lp_at"], p["lp_i"])), e.ld(e.add(p["lp_sorted"], e.add(p["lp_at"], e.sub(p["lp_i"], 1))))),
                                          e.set("lp_i", e.sub(p["lp_i"], 1))))
                e.st(e.add(p["lp_sorted"], e.add(p["lp_at"], p["lp_i"])), p["lp_item"])

            e.for_("lp_s", 1, nsucc(p["lp_q"]), insert)

        e.for_("lp_q", 0, n, sort_block)
        e.var("lp_order", e.alloc(e.add(n, 1)))
        e.var("lp_frame_b", e.alloc(e.add(n, 1)))
        e.var("lp_frame_c", e.alloc(e.add(n, 1)))
        for name in ("lp_order", "lp_frame_b", "lp_frame_c"):
            _ok(e, e.ne(p[name], NONE))
        _set_a(e, A_ORDER, p["lp_order"])
        e.for_("lp_q", 0, n, lambda: e.st(e.add(p["lp_seen"], p["lp_q"]), 0))
        e.var("lp_count", 0)
        e.st(e.add(p["lp_seen"], p["lp_entry"]), 1)
        e.st(p["lp_frame_b"], p["lp_entry"])
        e.st(p["lp_frame_c"], 0)
        e.var("lp_depth_s", 1)

        def dfs():
            e.var("lp_top", e.sub(p["lp_depth_s"], 1))
            e.var("lp_cur", e.ld(e.add(p["lp_frame_b"], p["lp_top"])))
            e.var("lp_child", NONE)

            def advance():
                e.var("lp_c", e.ld(e.add(p["lp_frame_c"], p["lp_top"])))
                e.st(e.add(p["lp_frame_c"], p["lp_top"]), e.add(p["lp_c"], 1))
                e.var("lp_cand", e.ld(e.add(p["lp_sorted"], e.add(e.ld(e.add(p["lp_succ_at"], p["lp_cur"])), p["lp_c"]))))
                e.if_(e.eq(e.ld(e.add(p["lp_seen"], p["lp_cand"])), 0), lambda: e.set("lp_child", p["lp_cand"]))

            e.while_(lambda: e.both(e.eq(p["lp_child"], NONE), e.lt(e.ld(e.add(p["lp_frame_c"], p["lp_top"])), nsucc(p["lp_cur"]))), advance)

            def post():
                e.st(e.add(p["lp_order"], p["lp_count"]), p["lp_cur"])
                e.set("lp_count", e.add(p["lp_count"], 1))
                e.set("lp_depth_s", p["lp_top"])

            def push():
                e.st(e.add(p["lp_seen"], p["lp_child"]), 1)
                e.st(e.add(p["lp_frame_b"], p["lp_depth_s"]), p["lp_child"])
                e.st(e.add(p["lp_frame_c"], p["lp_depth_s"]), 0)
                e.set("lp_depth_s", e.add(p["lp_depth_s"], 1))

            e.if_(e.eq(p["lp_child"], NONE), post, push)

        e.while_(lambda: e.ne(p["lp_depth_s"], 0), dfs)
        # Reverse, then the unreached blocks in index order.
        e.for_("lp_q", 0, e.udiv(p["lp_count"], 2), lambda: (
            e.var("lp_a", e.ld(e.add(p["lp_order"], p["lp_q"]))),
            e.st(e.add(p["lp_order"], p["lp_q"]), e.ld(e.add(p["lp_order"], e.sub(e.sub(p["lp_count"], 1), p["lp_q"])))),
            e.st(e.add(p["lp_order"], e.sub(e.sub(p["lp_count"], 1), p["lp_q"])), p["lp_a"])))
        e.for_("lp_q", 0, n, lambda: e.if_(e.eq(e.ld(e.add(p["lp_seen"], p["lp_q"])), 0), lambda: (
            e.st(e.add(p["lp_order"], p["lp_count"]), p["lp_q"]), e.set("lp_count", e.add(p["lp_count"], 1)))))
        e.give(1)
    return _function((), build, tables)


def _power(e: E, k):
    """``2 ** k`` for ``0 <= k < 64`` (the range analysis's table of powers)."""
    from xax_selfhost_general_ranges import G2_SCRATCH, _g2

    return e.ld(e.add(_g2(e, G2_SCRATCH), k))


def _maximum0(e: E, value, name: str):
    """``maximum(value)`` into ``name`` and ``name_none`` (1: no bound)."""
    from xax_selfhost_general_ranges import G2_RNONE, _g2

    p = e.p
    e.var(name, e.call(_FN["maximum0"], value))
    e.var(f"{name}_none", _g2(e, G2_RNONE))
    return p[name]


def _definition(e: E, value, name: str):
    """``definition.get(value)`` into ``name``: the node of a result-0 node value, else NONE."""
    from xax_selfhost_general_ranges import _is_param, _pos_result

    e.var(name, e.sel(e.both(e.not_(_is_param(e, value)), e.eq(_pos_result(e, value), 0)), _vf(e, G_VPROD, value), NONE))


def _membership(tables):
    """``_membership(block, root, uses)``: ``x == a | x == b | ...``, an OR tree of equality tests in one block.  When
    it is a membership test (one subject, three or more tests, values spanning less than 64 above ``low``): the
    subject, ``low`` and a synthetic mask constant (result 1 of the root, width 64) in ``V_MSUBJ``/``V_MLOW``/``V_MMASK``,
    and the inner OR nodes marked with ``stamp`` in ``V_MINT``.  1 when found."""
    from xax_compiler import IntCompare
    from xax_selfhost_general_ranges import _pos_block, _pos_index
    from xax_selfhost_general_regalloc import T_RW, T_USES

    def build(e: E):
        p = e.p
        e.var("mb_mark", e.hd(H_ARENA))
        n = _g(e, G_VCOUNT)
        e.var("mb_pending", e.alloc(e.add(e.mul(n, 2), 2)))
        e.var("mb_inner", e.alloc(e.add(n, 1)))
        e.var("mb_tests", e.alloc(e.add(e.mul(n, 3), 3)))
        for name in ("mb_pending", "mb_inner", "mb_tests"):
            _ok(e, e.ne(p[name], NONE))
        e.st(p["mb_pending"], p["root"])
        e.var("mb_sp", 1)
        e.var("mb_ninner", 0)
        e.var("mb_ntests", 0)
        e.var("mb_ok", 1)

        def step():
            e.set("mb_sp", e.sub(p["mb_sp"], 1))
            v = _canon(e, e.ld(e.add(p["mb_pending"], p["mb_sp"])), "mb_v")
            from xax_selfhost_general_ranges import _is_param, _pos_result

            local = e.both(e.not_(_is_param(e, v)), e.eq(_pos_block(e, v), p["blk"]), e.eq(_pos_result(e, v), 0))
            e.var("mb_node", e.sel(local, _vf(e, G_VPROD, v), NONE))

            def node():
                e.var("mb_op", _eop(e, p["mb_node"]))

                def or_():
                    e.if_(e.ne(v, p["root"]), lambda: (e.st(e.add(p["mb_inner"], p["mb_ninner"]), v), e.set("mb_ninner", e.add(p["mb_ninner"], 1))))
                    e.for_("mb_o", 0, _f(e, p["mb_node"], N_NOPS), lambda: (e.st(e.add(p["mb_pending"], p["mb_sp"]), _operand(e, p["mb_node"], p["mb_o"])),
                                                                             e.set("mb_sp", e.add(p["mb_sp"], 1))))

                def compare():
                    e.var("mb_subject", _operand(e, p["mb_node"], 0))
                    e.var("mb_constant", _operand(e, p["mb_node"], 1))
                    _const(e, p["mb_subject"], "mb_sc")
                    e.if_(e.ne(p["mb_sc_is"], 0), lambda: (e.var("mb_t", p["mb_subject"]), e.set("mb_subject", p["mb_constant"]), e.set("mb_constant", p["mb_t"])))
                    e.var("mb_width", _rt_(e, T_RW, p["mb_subject"]))
                    e.if_(e.eq(p["mb_width"], 0), lambda: e.set("mb_width", _rt_(e, T_RW, _canon(e, p["mb_subject"], "mb_sw"))))
                    _const(e, p["mb_constant"], "mb_cv")
                    _const(e, p["mb_subject"], "mb_sv")
                    limit = e.sel(e.le(64, p["mb_width"]), (1 << 64) - 1, e.sub(_power(e, e.sel(e.le(64, p["mb_width"]), 0, p["mb_width"])), 1))
                    bad = e.either(e.eq(p["mb_cv_is"], 0), e.ne(p["mb_sv_is"], 0), e.lt(limit, p["mb_cv"]))

                    def test():
                        e.var("mb_at", e.add(p["mb_tests"], e.mul(p["mb_ntests"], 3)))
                        e.st(p["mb_at"], _canon(e, p["mb_subject"], "mb_ts"))
                        e.st(e.add(p["mb_at"], 1), p["mb_cv"])
                        e.st(e.add(p["mb_at"], 2), p["mb_width"])
                        e.set("mb_ntests", e.add(p["mb_ntests"], 1))

                    e.if_(bad, lambda: e.set("mb_ok", 0), test)

                is_or = e.both(e.eq(p["mb_op"], int(Operation.BIT_OR)), e.either(e.eq(v, p["root"]), e.eq(_rt_(e, T_USES, v), 1)))
                is_eq = e.both(e.eq(p["mb_op"], int(Operation.INT_COMPARE)), e.eq(e.rd(e.add(_f(e, p["mb_node"], N_ATTR), 1)), int(IntCompare.EQ)))
                e.if_(is_or, or_, lambda: e.if_(is_eq, compare, lambda: e.set("mb_ok", 0)))

            e.if_(e.eq(p["mb_node"], NONE), lambda: e.set("mb_ok", 0), node)

        e.while_(lambda: e.both(e.ne(p["mb_sp"], 0), e.ne(p["mb_ok"], 0)), step)
        e.if_(e.eq(p["mb_ok"], 0), lambda: (e.set_hd(H_ARENA, p["mb_mark"]), e.give(0)))
        # One subject, at least three tests, the values within 64 of ``low``.
        e.var("mb_same", 1)
        e.var("mb_low", NONE)
        e.var("mb_high", 0)

        def summarize():
            e.var("mb_at", e.add(p["mb_tests"], e.mul(p["mb_k"], 3)))
            e.if_(e.ne(e.ld(p["mb_at"]), e.ld(p["mb_tests"])), lambda: e.set("mb_same", 0))
            e.var("mb_value", e.ld(e.add(p["mb_at"], 1)))
            e.if_(e.lt(p["mb_value"], p["mb_low"]), lambda: e.set("mb_low", p["mb_value"]))
            e.if_(e.lt(p["mb_high"], p["mb_value"]), lambda: e.set("mb_high", p["mb_value"]))

        e.for_("mb_k", 0, p["mb_ntests"], summarize)
        e.var("mb_base", e.sel(e.lt(p["mb_high"], 64), 0, p["mb_low"]))
        good = e.both(e.ne(p["mb_same"], 0), e.le(3, p["mb_ntests"]), e.lt(e.sub(p["mb_high"], p["mb_base"]), 64))
        e.if_(e.not_(good), lambda: (e.set_hd(H_ARENA, p["mb_mark"]), e.give(0)))
        e.var("mb_mask", 0)
        e.for_("mb_k", 0, p["mb_ntests"], lambda: e.set("mb_mask", e.bin(Operation.BIT_OR, p["mb_mask"], _power(
            e, e.sub(e.ld(e.add(e.add(p["mb_tests"], e.mul(p["mb_k"], 3)), 1)), p["mb_base"])))))
        e.var("mb_subj", e.ld(p["mb_tests"]))
        e.for_("mb_k", 0, p["mb_ninner"], lambda: _set_av(e, V_MINT, e.ld(e.add(p["mb_inner"], p["mb_k"])), p["stamp"]))
        e.set_hd(H_ARENA, p["mb_mark"])
        _synthetic(e, p["blk"], _pos_index(e, p["root"]), 1, "mb_maskv")
        from xax_selfhost_general_ranges import G2_CONST, G2_CVAL, _set_t

        _set_t(e, G2_CONST, p["mb_maskv"], 1)
        _set_t(e, G2_CVAL, p["mb_maskv"], p["mb_mask"])
        _set_av(e, V_MSUBJ, p["root"], p["mb_subj"])
        _set_av(e, V_MLOW, p["root"], p["mb_base"])
        _set_av(e, V_MMASK, p["root"], p["mb_maskv"])
        e.give(1)
    return _function(("blk", "root", "stamp"), build, tables)


def _patterns(tables):
    """Per block, nodes in reverse: membership tests (``_membership``) of OR roots not internal to an earlier one or to
    a predicate table, and bit clears (``bic``: ``and(xor(x, 1), y)`` of 0/1 values)."""
    from xax_selfhost_general_regalloc import T_RW, T_USES, _stamp

    def build(e: E):
        p = e.p

        def block():
            e.var("pa_b", e.ld(e.add(_g(e, G_BLIST), p["pa_q"])))
            e.var("pa_stamp", _stamp(e))
            e.var("pa_m", _f(e, p["pa_b"], B_NNODES))

            def node():
                e.set("pa_m", e.sub(p["pa_m"], 1))
                e.var("pa_node", e.ld(e.add(_f(e, p["pa_b"], B_NODES), p["pa_m"])))

                def with_result():
                    e.var("pa_root", _output(e, p["pa_node"], 0))
                    e.var("pa_op", _eop(e, p["pa_node"]))
                    root = p["pa_root"]
                    member = e.both(e.eq(p["pa_op"], int(Operation.BIT_OR)), e.ne(_rt_(e, T_RW, root), 0), e.ne(_av(e, V_MINT, root), p["pa_stamp"]),
                                    e.eq(_av(e, V_TINT, root), 0))
                    e.if_(member, lambda: _call(e, "a64_membership", p["pa_q"], root, p["pa_stamp"]))

                    def bic():
                        e.var("pa_done", 0)

                        def attempt(flipped, other):
                            def body():
                                e.var("pa_other", other)
                                e.var("pa_fc", _canon(e, flipped, "pa_fcan"))
                                _definition(e, p["pa_fc"], "pa_xor")

                                def xor():
                                    _maximum0(e, p["pa_other"], "pa_om")
                                    good = e.both(e.eq(_eop(e, p["pa_xor"]), int(Operation.BIT_XOR)), e.eq(_rt_(e, T_USES, p["pa_fc"]), 1),
                                                  e.eq(p["pa_om_none"], 0), e.le(p["pa_om"], 1))

                                    def operands():
                                        e.var("pa_x", _operand(e, p["pa_xor"], 0))
                                        e.var("pa_one", _operand(e, p["pa_xor"], 1))
                                        _const(e, p["pa_one"], "pa_c1")
                                        e.if_(e.not_(e.both(e.ne(p["pa_c1_is"], 0), e.eq(p["pa_c1"], 1))), lambda: (
                                            e.var("pa_t", p["pa_x"]), e.set("pa_x", p["pa_one"]), e.set("pa_one", p["pa_t"])))
                                        _const(e, p["pa_one"], "pa_k1")
                                        _const(e, p["pa_x"], "pa_kx")
                                        _maximum0(e, p["pa_x"], "pa_xm")
                                        hit = e.both(e.ne(p["pa_k1_is"], 0), e.eq(p["pa_k1"], 1), e.eq(p["pa_kx_is"], 0), e.eq(p["pa_xm_none"], 0), e.le(p["pa_xm"], 1))
                                        e.if_(hit, lambda: (_set_av(e, V_BKEEP, root, p["pa_other"]), _set_av(e, V_BCLEAR, root, p["pa_x"]), e.set("pa_done", 1)))

                                    e.if_(good, operands)

                                e.if_(e.ne(p["pa_xor"], NONE), xor)

                            e.if_(e.eq(p["pa_done"], 0), body)

                        attempt(_operand(e, p["pa_node"], 0), _operand(e, p["pa_node"], 1))
                        attempt(_operand(e, p["pa_node"], 1), _operand(e, p["pa_node"], 0))

                    e.if_(e.both(e.eq(p["pa_op"], int(Operation.BIT_AND)), e.ne(_rt_(e, T_RW, root), 0)), bic)

                e.if_(e.ne(_f(e, p["pa_node"], N_NRES), 0), with_result)

            e.while_(lambda: e.ne(p["pa_m"], 0), node)

        e.for_("pa_q", 0, _g(e, G_BCOUNT), block)
        e.give(1)
    return _function((), build, tables)


def _write_analysis(tables):
    """The audit record of ``_analyze`` (tests): per view value (block by block: parameters, then node outputs) its
    alias (position or NONE); per block the fused node, on-a-cycle flag and depth; the layout order; then per table
    root its subject, the table's bytes; per membership root its subject, low and mask; per bit clear its operands."""
    from xax_selfhost_general_ranges import G2_CVAL, _t
    from xax_selfhost_general_regalloc import T_ALIAS
    from xax_selfhost_general_view import _out_value

    def build(e: E):
        p = e.p

        def each_value(visit):
            def block():
                e.var("wa_b", e.ld(e.add(_g(e, G_BLIST), p["wa_q"])))
                e.for_("wa_k", 0, _f(e, p["wa_b"], B_NP), lambda: visit(e.ld(e.add(_f(e, p["wa_b"], B_INPUTS), p["wa_k"]))))

                def node():
                    e.var("wa_n", e.ld(e.add(_f(e, p["wa_b"], B_NODES), p["wa_m"])))
                    e.for_("wa_r", 0, _f(e, p["wa_n"], N_NRES), lambda: visit(_output(e, p["wa_n"], p["wa_r"])))

                e.for_("wa_m", 0, _f(e, p["wa_b"], B_NNODES), node)

            e.for_("wa_q", 0, _g(e, G_BCOUNT), block)

        def alias(v):
            e.var("wa_v", v)
            e.var("wa_t", _rt_(e, T_ALIAS, p["wa_v"]))
            e.if_(e.eq(p["wa_t"], NONE), lambda: _out(e, 0), lambda: (_out(e, 1), _out_value(e, p["wa_t"])))

        each_value(alias)
        e.var("wa_nb", _a(e, A_NB))
        e.for_("wa_q", 0, p["wa_nb"], lambda: (_out(e, e.ld(e.add(_a(e, A_FUSED), p["wa_q"]))), _out(e, e.ld(e.add(_a(e, A_INLOOP), p["wa_q"]))),
                                              _out(e, e.ld(e.add(_a(e, A_DEPTH), p["wa_q"]))), _out(e, e.ld(e.add(_a(e, A_ORDER), p["wa_q"])))))

        def facts(v):
            e.var("wf_v", v)

            def table():
                _out(e, 1)
                _out_value(e, p["wf_v"])
                _out_value(e, _av(e, V_TSUBJ, p["wf_v"]))
                e.var("wf_addr", _av(e, V_TADDR, p["wf_v"]))
                e.var("wf_count", _av(e, V_TCOUNT, p["wf_addr"]))
                _out(e, p["wf_count"])
                e.for_("wf_k", 0, p["wf_count"], lambda: _out(e, e.ld(e.add(_av(e, V_TDATA, p["wf_addr"]), p["wf_k"]))))

            def member():
                _out(e, 2)
                _out_value(e, p["wf_v"])
                _out_value(e, _av(e, V_MSUBJ, p["wf_v"]))
                _out(e, _av(e, V_MLOW, p["wf_v"]))
                _out(e, _t(e, G2_CVAL, _av(e, V_MMASK, p["wf_v"])))

            def bic():
                _out(e, 3)
                _out_value(e, p["wf_v"])
                _out_value(e, _av(e, V_BKEEP, p["wf_v"]))
                _out_value(e, _av(e, V_BCLEAR, p["wf_v"]))

            e.if_(e.ne(_av(e, V_TSUBJ, p["wf_v"]), NONE), table)
            e.if_(e.ne(_av(e, V_MSUBJ, p["wf_v"]), NONE), member)
            e.if_(e.ne(_av(e, V_BKEEP, p["wf_v"]), NONE), bic)

        each_value(facts)
        _out(e, 0)
        e.give(1)
    return _function((), build, tables)


# -- per-node plans and the plan (``_Lowering.reads`` ... ``_plan``) ------------------------------------------------

WIDE_LIMIT = 32
LOGIC = tuple(int(op) for op in (Operation.BIT_AND, Operation.BIT_OR, Operation.BIT_XOR))
PURE = tuple(int(op) for op in (
    Operation.CONSTANT, Operation.ADD_WRAP, Operation.SUB_WRAP, Operation.MUL_WRAP, Operation.BIT_AND, Operation.BIT_OR,
    Operation.BIT_XOR, Operation.INT_COMPARE, Operation.INT_TRUNCATE, Operation.INT_ZERO_EXTEND, Operation.ROTATE_RIGHT,
    Operation.ADDRESS_OFFSET, Operation.POINTER_CAST, Operation.POINTER_ADDRESS,
))
CHECKED = (int(Operation.CHECKED_LOAD_BITS_LE), int(Operation.CHECKED_STORE_BITS_LE))
STORES = (int(Operation.STORE_BITS_LE), int(Operation.CHECKED_STORE_BITS_LE))


def _node_word(e: E, table: int, block, index):
    return e.add(e.ld(e.add(_a(e, table), block)), index)


def _addsub_fn(tables):
    """``_addsub_immediate(value)``: ``imm12 + 4096 * shift``, or NONE."""
    def build(e: E):
        p = e.p
        v = p["value"]
        e.if_(e.lt(v, 4096), lambda: e.give(v))
        e.if_(e.both(e.eq(e.and_(v, 4095), 0), e.lt(e.udiv(v, 4096), 4096)), lambda: e.give(e.add(e.udiv(v, 4096), 4096)))
        e.give(NONE)
    return _function(("value",), build, tables)


def _logical_fn(tables):
    """``_logical_immediate(value, wide)``: the 13-bit ``N:immr:imms``, or NONE."""
    def build(e: E):
        p = e.p
        e.var("li_size", e.sel(e.ne(p["wide"], 0), 64, 32))
        e.var("li_v", e.sel(e.ne(p["wide"], 0), p["value"], e.and_(p["value"], 0xFFFFFFFF)))
        e.var("li_all", e.sel(e.ne(p["wide"], 0), (1 << 64) - 1, 0xFFFFFFFF))
        e.if_(e.either(e.eq(p["li_v"], 0), e.eq(p["li_v"], p["li_all"])), lambda: e.give(NONE))
        e.var("li_element", p["li_size"])
        e.var("li_go", 1)

        def shrink():
            e.var("li_half", e.udiv(p["li_element"], 2))
            e.var("li_m", e.sub(_power(e, p["li_half"]), 1))
            same = e.eq(e.and_(p["li_v"], p["li_m"]), e.and_(e.udiv(p["li_v"], _power(e, p["li_half"])), p["li_m"]))
            e.if_(same, lambda: e.set("li_element", p["li_half"]), lambda: e.set("li_go", 0))

        e.while_(lambda: e.both(e.ne(p["li_go"], 0), e.lt(2, p["li_element"])), shrink)
        e.var("li_emask", e.sel(e.eq(p["li_element"], 64), (1 << 64) - 1, e.sub(_power(e, e.sel(e.eq(p["li_element"], 64), 0, p["li_element"])), 1)))
        e.var("li_pattern", e.and_(p["li_v"], p["li_emask"]))

        def rotation():
            r = p["li_r"]
            e.var("li_rot", p["li_pattern"])
            e.if_(e.ne(r, 0), lambda: e.set("li_rot", e.and_(e.bin(Operation.BIT_OR, e.udiv(p["li_pattern"], _power(e, r)),
                                                                    e.mul(p["li_pattern"], _power(e, e.sub(p["li_element"], r)))), p["li_emask"])))
            e.var("li_ones", 0)
            e.var("li_x", p["li_rot"])
            e.while_(lambda: e.ne(p["li_x"], 0), lambda: (e.set("li_ones", e.add(p["li_ones"], e.and_(p["li_x"], 1))), e.set("li_x", e.udiv(p["li_x"], 2))))
            run = e.sel(e.eq(p["li_ones"], 64), (1 << 64) - 1, e.sub(_power(e, e.sel(e.eq(p["li_ones"], 64), 0, p["li_ones"])), 1))

            def found():
                e.var("li_n", e.flag(e.eq(p["li_element"], 64)))
                imms = e.bin(Operation.BIT_OR, e.and_(e.mul(e.sub((1 << 64) - 1, e.sub(p["li_element"], 1)), 2), 0x3F), e.sub(p["li_ones"], 1))
                e.var("li_imms", e.and_(imms, 0x3F))
                e.var("li_immr", e.and_(e.sub(p["li_element"], r), e.sub(p["li_element"], 1)))
                e.give(e.add(e.add(e.mul(p["li_n"], 4096), e.mul(p["li_immr"], 64)), p["li_imms"]))

            e.if_(e.eq(p["li_rot"], run), found)

        e.for_("li_r", 0, p["li_element"], rotation)
        e.give(NONE)
    return _function(("value", "wide"), build, tables)


def _movlen_fn(tables):
    """``len(_move_immediate(register, value, wide))``."""
    def build(e: E):
        p = e.p
        e.var("ml_size", e.sel(e.ne(p["wide"], 0), 64, 32))
        e.var("ml_v", e.sel(e.ne(p["wide"], 0), p["value"], e.and_(p["value"], 0xFFFFFFFF)))
        e.if_(e.eq(p["ml_v"], 0), lambda: e.give(1))
        e.var("ml_inv", e.sub(e.sel(e.ne(p["wide"], 0), (1 << 64) - 1, 0xFFFFFFFF), p["ml_v"]))
        e.var("ml_h", 0)
        e.var("ml_ih", 0)
        e.for_("ml_k", 0, e.udiv(p["ml_size"], 16), lambda: (
            e.if_(e.ne(e.and_(e.udiv(p["ml_v"], _power(e, e.mul(p["ml_k"], 16))), 0xFFFF), 0), lambda: e.set("ml_h", e.add(p["ml_h"], 1))),
            e.if_(e.ne(e.and_(e.udiv(p["ml_inv"], _power(e, e.mul(p["ml_k"], 16))), 0xFFFF), 0), lambda: e.set("ml_ih", e.add(p["ml_ih"], 1)))))
        e.if_(e.both(e.le(p["ml_ih"], 1), e.lt(1, p["ml_h"])), lambda: e.give(1))
        e.if_(e.both(e.ne(_q(e, "a64_logical", p["ml_v"], p["wide"]), NONE), e.lt(1, p["ml_h"])), lambda: e.give(1))
        e.give(p["ml_h"])
    return _function(("value", "wide"), build, tables)


def _width_of(e: E, value, name: str):
    """``self.width(value)`` when the value or its representative has a width, else 64 (``_folds``' fallback)."""
    from xax_selfhost_general_regalloc import T_RW

    p = e.p
    e.var(name, _rt_(e, T_RW, value))
    e.if_(e.eq(p[name], 0), lambda: e.set(name, _rt_(e, T_RW, _canon(e, value, f"{name}_c"))))
    e.if_(e.eq(p[name], 0), lambda: e.set(name, 64))
    return p[name]


def _folds_fn(tables):
    """``_folds(node, position)``: 1 when operand ``position`` is a constant the node encodes without a register."""
    from xax_compiler import IntCompare

    def build(e: E):
        p = e.p
        node, position = p["node"], p["position"]
        e.var("fo_operand", _operand(e, node, position))
        _const(e, p["fo_operand"], "fo_v")
        e.if_(e.eq(p["fo_v_is"], 0), lambda: e.give(0))
        e.var("fo_op", _eop(e, node))
        op = p["fo_op"]
        e.var("fo_w", _width_of(e, p["fo_operand"], "fo_wd"))
        v = p["fo_v"]
        zero_ops = tuple(int(x) for x in (Operation.ADD_WRAP, Operation.SUB_WRAP, Operation.BIT_AND, Operation.BIT_OR, Operation.BIT_XOR,
                                          Operation.INT_COMPARE, Operation.MUL_WRAP, Operation.STORE_BITS_LE, Operation.CHECKED_STORE_BITS_LE))
        e.if_(e.both(e.eq(v, 0), _in(e, op, zero_ops)), lambda: e.give(e.flag(e.either(e.ne(position, 0), e.not_(_in(e, op, STORES))))))
        e.var("fo_other_is", 0)

        def other_const(k):
            _const(e, _operand(e, node, k), "fo_oc")
            e.set("fo_other_is", p["fo_oc_is"])

        def addsub():
            other_const(e.sub(1, position))
            e.if_(e.both(e.eq(position, 0), e.either(e.eq(op, int(Operation.SUB_WRAP)), e.ne(p["fo_other_is"], 0))), lambda: e.give(0))
            e.var("fo_neg", e.sub(0, v))
            e.if_(e.le(p["fo_w"], WIDE_LIMIT), lambda: e.set("fo_neg", e.and_(p["fo_neg"], 0xFFFFFFFF)))
            e.give(e.flag(e.either(e.ne(_q(e, "a64_addsub", v), NONE), e.ne(_q(e, "a64_addsub", p["fo_neg"]), NONE))))

        e.if_(_in(e, op, (int(Operation.ADD_WRAP), int(Operation.SUB_WRAP))), addsub)
        other_const(1)
        first_blocked = e.both(e.eq(position, 0), e.ne(p["fo_other_is"], 0))
        e.var("fo_blocked", e.flag(first_blocked))
        e.if_(e.eq(op, int(Operation.MUL_WRAP)), lambda: e.give(e.flag(e.both(e.eq(p["fo_blocked"], 0), e.eq(e.and_(v, e.sub(v, 1)), 0)))))
        e.if_(_in(e, op, LOGIC), lambda: e.give(e.flag(e.both(e.eq(p["fo_blocked"], 0), e.ne(_q(e, "a64_logical", v, e.flag(e.lt(WIDE_LIMIT, p["fo_w"]))), NONE)))))

        def compare():
            e.var("fo_kind", e.rd(e.add(_f(e, node, N_ATTR), 1)))
            signed = e.both(_in(e, p["fo_kind"], tuple(int(k) for k in (IntCompare.SLT, IntCompare.SLE, IntCompare.SGT, IntCompare.SGE))),
                            e.ne(p["fo_w"], 32), e.ne(p["fo_w"], 64))
            e.give(e.flag(e.both(e.eq(p["fo_blocked"], 0), e.not_(signed), e.ne(_q(e, "a64_addsub", v), NONE))))

        e.if_(e.eq(op, int(Operation.INT_COMPARE)), compare)
        e.if_(e.both(_in(e, op, (int(Operation.UDIV), int(Operation.UREM))), e.eq(position, 1)),
              lambda: e.give(e.flag(e.both(e.ne(v, 0), e.eq(e.and_(v, e.sub(v, 1)), 0)))))
        e.if_(e.both(_in(e, op, CHECKED), e.eq(position, 1)), lambda: e.give(1))
        e.give(0)
    return _function(("node", "position"), build, tables)


def _proven_fn(tables):
    """``_proven(node)``: the checked access's index is bounded within the pointer's extent."""
    def build(e: E):
        p = e.p
        _maximum0(e, _operand(e, p["node"], 1), "pv_b")
        e.if_(e.ne(p["pv_b_none"], 0), lambda: e.give(0))
        e.var("pv_ext", _call(e, "extent", _operand(e, p["node"], 0)))
        e.var("pv_size", e.rd(e.add(_f(e, p["node"], N_ATTR), 1)))
        e.give(e.flag(e.both(e.le(p["pv_size"], p["pv_ext"]), e.le(p["pv_b"], e.sub(p["pv_ext"], p["pv_size"])))))
    return _function(("node",), build, tables)


def _scaled_fn(tables):
    """``_scaled(node)``: for a proven checked access whose index is ``x * size``, ``x``; else NONE."""
    def build(e: E):
        p = e.p
        e.var("sd_size", e.rd(e.add(_f(e, p["node"], N_ATTR), 1)))
        e.if_(e.either(e.eq(p["sd_size"], 1), e.eq(_call(e, "a64_proven", p["node"]), 0)), lambda: e.give(NONE))
        _definition(e, _canon(e, _operand(e, p["node"], 1), "sd_i"), "sd_mul")
        e.if_(e.eq(p["sd_mul"], NONE), lambda: e.give(NONE))
        e.if_(e.ne(_eop(e, p["sd_mul"]), int(Operation.MUL_WRAP)), lambda: e.give(NONE))
        e.var("sd_x", _operand(e, p["sd_mul"], 0))
        e.var("sd_f", _operand(e, p["sd_mul"], 1))
        _const(e, p["sd_f"], "sd_fc")
        e.if_(e.not_(e.both(e.ne(p["sd_fc_is"], 0), e.eq(p["sd_fc"], p["sd_size"]))), lambda: (
            e.var("sd_t", p["sd_x"]), e.set("sd_x", p["sd_f"]), e.set("sd_f", p["sd_t"])))
        _const(e, p["sd_f"], "sd_fc2")
        _const(e, p["sd_x"], "sd_xc")
        e.if_(e.either(e.eq(p["sd_fc2_is"], 0), e.ne(p["sd_fc2"], p["sd_size"]), e.ne(p["sd_xc_is"], 0)), lambda: e.give(NONE))
        _maximum0(e, p["sd_x"], "sd_b")
        e.if_(e.ne(p["sd_b_none"], 0), lambda: e.give(NONE))
        # bound * size < 2 ** 64
        e.give(e.sel(e.le(p["sd_b"], e.udiv((1 << 64) - 1, p["sd_size"])), p["sd_x"], NONE))
    return _function(("node",), build, tables)


def _is_constant(e: E, value):
    from xax_selfhost_general_ranges import G2_CONST, _t

    return e.ne(_t(e, G2_CONST, value), 0)


def _located_fn(tables):
    """``_located(operand)``: the representative to read, or NONE for a constant or table materialized at its use."""
    def build(e: E):
        p = e.p
        v = _canon(e, p["operand"], "lo_v")
        e.give(e.sel(e.both(e.either(_is_constant(e, v), e.ne(_av(e, V_TDATA, v), 0)), e.eq(_av(e, V_HOIST, v), 0)), NONE, v))
    return _function(("operand",), build, tables)


def _buffer_put(e: E, slot: int, count: str, value):
    """Append ``value`` (unless NONE) to the read buffer in ``slot``."""
    p = e.p
    e.var(f"{count}_x", value)
    e.if_(e.ne(p[f"{count}_x"], NONE), lambda: (e.st(e.add(_a(e, slot), p[count]), p[f"{count}_x"]), e.set(count, e.add(p[count], 1))))


def _reads_fn(tables):
    """``reads(block, node)``: the representatives node ``m`` of block ``blk`` reads from a location, into
    ``A_RBUF``; their count."""
    from xax_selfhost_general_regalloc import T_ALIAS

    def build(e: E):
        p = e.p
        e.var("rd_n", 0)
        e.var("rd_b", e.ld(e.add(_g(e, G_BLIST), p["blk"])))
        e.var("rd_node", e.ld(e.add(_f(e, p["rd_b"], B_NODES), p["m"])))
        node = p["rd_node"]
        e.var("rd_op", _eop(e, node))
        op = p["rd_op"]
        none = e.either(e.eq(p["m"], e.ld(e.add(_a(e, A_FUSED), p["blk"]))), _in(e, op, (int(Operation.CONSTANT), int(Operation.STACK_END), *RESOURCE)),
                        _in(e, op, tuple(int(x) for x in (Operation.POINTER_CAST, Operation.POINTER_ADDRESS, Operation.INT_ZERO_EXTEND))))
        e.if_(none, lambda: e.give(0))
        e.var("rd_res", e.sel(e.ne(_f(e, node, N_NRES), 0), _output(e, node, 0), NONE))
        res = p["rd_res"]
        e.if_(e.both(e.eq(op, int(Operation.INT_TRUNCATE)), e.ne(res, NONE)), lambda: e.if_(e.ne(_rt_(e, T_ALIAS, res), NONE), lambda: e.give(0)))
        put = lambda value: _buffer_put(e, A_RBUF, "rd_n", _q(e, "a64_located", value))  # noqa: E731

        def pattern(first, second):
            put(first)
            put(second)
            e.give(p["rd_n"])

        e.if_(e.ne(res, NONE), lambda: (
            e.if_(e.ne(_av(e, V_TSUBJ, res), NONE), lambda: pattern(_av(e, V_TSUBJ, res), _av(e, V_TADDR, res))),
            e.if_(e.ne(_av(e, V_MSUBJ, res), NONE), lambda: pattern(_av(e, V_MSUBJ, res), _av(e, V_MMASK, res))),
            e.if_(e.ne(_av(e, V_BKEEP, res), NONE), lambda: pattern(_av(e, V_BKEEP, res), _av(e, V_BCLEAR, res)))))

        def checked():
            put(_operand(e, node, 0))
            e.var("rd_scaled", _q(e, "a64_scaled", node))
            _const(e, _operand(e, node, 1), "rd_ic")
            e.if_(e.ne(p["rd_scaled"], NONE), lambda: put(p["rd_scaled"]), lambda: e.if_(e.eq(p["rd_ic_is"], 0), lambda: put(_operand(e, node, 1))))
            e.if_(e.both(e.eq(op, int(Operation.CHECKED_STORE_BITS_LE)), e.eq(_call(e, "a64_folds", node, 2), 0)), lambda: put(_operand(e, node, 2)))
            e.var("rd_bound", e.ld(_node_word(e, A_CHECK, p["blk"], p["m"])))
            e.if_(e.ne(p["rd_bound"], NONE), lambda: put(p["rd_bound"]))
            e.give(p["rd_n"])

        e.if_(_in(e, op, CHECKED), checked)

        def erased_call():
            from xax_selfhost_general_regalloc import _callee_object

            _callee_object(e, node, "rd_callee")
            e.if_(e.ne(_call(e, "erased", p["rd_callee"]), 0), lambda: e.give(0))

        e.if_(e.eq(op, int(Operation.CALL_DIRECT)), erased_call)
        e.var("rd_call", e.flag(_in(e, op, CALLS)))

        def operand():
            e.var("rd_o", _operand(e, node, p["rd_k"]))
            machine = e.ne(_machine_width(e, _vf(e, G_VTYPE, p["rd_o"]), "rd_mw"), NOT_MACHINE)

            def take():
                e.if_(e.either(e.ne(p["rd_call"], 0), e.eq(_call(e, "a64_folds", node, p["rd_k"]), 0)), lambda: put(p["rd_o"]))

            e.if_(machine, take)

        e.for_("rd_k", 0, _f(e, node, N_NOPS), operand)
        e.give(p["rd_n"])
    return _function(("blk", "m"), build, tables)


def _defines_fn(tables):
    """``defines(block, node)``: the value node ``m`` of block ``blk`` writes to a location, or NONE."""
    from xax_selfhost_general_regalloc import T_ALIAS, T_RW

    def build(e: E):
        p = e.p
        e.var("df_b", e.ld(e.add(_g(e, G_BLIST), p["blk"])))
        e.var("df_node", e.ld(e.add(_f(e, p["df_b"], B_NODES), p["m"])))
        node = p["df_node"]
        e.if_(e.eq(_eop(e, node), int(Operation.CONSTANT)), lambda: e.give(NONE))
        e.var("df_first", NONE)
        e.for_("df_r", 0, _f(e, node, N_NRES), lambda: (e.var("df_v", _output(e, node, p["df_r"])), e.if_(
            e.both(e.eq(p["df_first"], NONE), e.ne(_rt_(e, T_RW, p["df_v"]), 0), e.eq(_av(e, V_ELIDED, p["df_v"]), NONE)), lambda: e.set("df_first", p["df_v"]))))
        e.if_(e.either(e.eq(p["df_first"], NONE), e.eq(p["m"], e.ld(e.add(_a(e, A_FUSED), p["blk"]))), e.ne(_rt_(e, T_ALIAS, p["df_first"]), NONE)),
              lambda: e.give(NONE))
        e.give(p["df_first"])
    return _function(("blk", "m"), build, tables)


def _treads_fn(tables):
    """``terminator_reads(block)`` into ``A_TBUF``; the count."""
    from xax_selfhost_general_regalloc import T_ALIAS, T_RW
    from xax_selfhost_general_view import B_EDGES, B_NEDGES, B_NVALUES, B_VALUES, EDGE, RETURN

    def build(e: E):
        p = e.p
        e.var("tr_n", 0)
        e.var("tr_b", e.ld(e.add(_g(e, G_BLIST), p["blk"])))
        b = p["tr_b"]
        put = lambda value: _buffer_put(e, A_TBUF, "tr_n", _q(e, "a64_located", value))  # noqa: E731

        def ret():
            e.var("tr_rt", e.add(e.add(_a(e, A_IFACE), 2), e.ld(e.add(_a(e, A_IFACE), 1))))

            def value():
                e.var("tr_t", e.ld(e.add(e.add(p["tr_rt"], 1), p["tr_k"])))
                machine = e.ne(_machine_width(e, p["tr_t"], "tr_mw"), NOT_MACHINE)
                kept = e.eq(e.ld(e.add(_a(e, A_OWNB), p["tr_k"])), NONE)
                e.if_(e.both(machine, kept), lambda: put(e.ld(e.add(_f(e, b, B_VALUES), p["tr_k"]))))

            e.for_("tr_k", 0, _f(e, b, B_NVALUES), value)

        e.if_(e.eq(_f(e, b, B_KIND), RETURN), ret)

        def conditional():
            e.var("tr_fused", e.ld(e.add(_a(e, A_FUSED), p["blk"])))

            def fused():
                e.var("tr_cmp", e.ld(e.add(_f(e, b, B_NODES), p["tr_fused"])))
                e.for_("tr_k", 0, _f(e, p["tr_cmp"], N_NOPS), lambda: e.if_(e.eq(_call(e, "a64_folds", p["tr_cmp"], p["tr_k"]), 0),
                                                                          lambda: put(_operand(e, p["tr_cmp"], p["tr_k"]))))

            e.if_(e.ne(p["tr_fused"], NONE), fused, lambda: put(e.ld(_f(e, b, B_VALUES))))

        e.if_(e.eq(_f(e, b, B_KIND), CONDITIONAL), conditional)

        def edge():
            e.var("tr_e", e.add(_f(e, b, B_EDGES), e.mul(p["tr_j"], EDGE)))
            e.var("tr_target", _f(e, p["tr_e"], 0))

            def argument():
                e.var("tr_param", e.ld(e.add(_f(e, p["tr_target"], B_INPUTS), p["tr_a"])))
                e.if_(e.both(e.ne(_rt_(e, T_RW, p["tr_param"]), 0), e.eq(_rt_(e, T_ALIAS, p["tr_param"]), NONE)),
                      lambda: put(e.ld(e.add(_f(e, p["tr_e"], 2), p["tr_a"]))))

            e.for_("tr_a", 0, _f(e, p["tr_e"], 1), argument)

        e.for_("tr_j", 0, _f(e, b, B_NEDGES), edge)
        e.give(p["tr_n"])
    return _function(("blk",), build, tables)


def _plan_fn(tables):
    """``_plan``: hoisted values (loop tables' addresses, loop check bounds the compare cannot encode, constants of two
    or more instructions used unfolded in a loop), then dead pure nodes to a fixed point, and the read counts."""
    from xax_selfhost_general_ranges import G2_CONST, G2_CVAL, _set_t, _t
    from xax_selfhost_general_regalloc import T_RW

    def build(e: E):
        p = e.p
        n = _a(e, A_NB)
        e.var("pl_nb", n)
        for slot in (A_CHECK, A_DEAD):
            e.var(f"pl_t{slot}", e.alloc(e.add(p["pl_nb"], 1)))
            _ok(e, e.ne(p[f"pl_t{slot}"], NONE))
            _set_a(e, slot, p[f"pl_t{slot}"])

        def per_block():
            e.var("pl_b", e.ld(e.add(_g(e, G_BLIST), p["pl_q"])))
            for slot in (A_CHECK, A_DEAD):
                e.var(f"pl_w{slot}", e.alloc(e.add(_f(e, p["pl_b"], B_NNODES), 1)))
                _ok(e, e.ne(p[f"pl_w{slot}"], NONE))
                e.st(e.add(_a(e, slot), p["pl_q"]), p[f"pl_w{slot}"])
                e.for_("pl_m", 0, _f(e, p["pl_b"], B_NNODES), lambda slot=slot: e.st(e.add(p[f"pl_w{slot}"], p["pl_m"]), NONE if slot == A_CHECK else 0))

        e.for_("pl_q", 0, p["pl_nb"], per_block)
        e.var("pl_buf", e.alloc(e.add(e.mul(_g(e, G_VCOUNT), 2), 64)))
        e.var("pl_tbuf", e.alloc(e.add(e.mul(_g(e, G_VCOUNT), 2), 64)))
        _ok(e, e.both(e.ne(p["pl_buf"], NONE), e.ne(p["pl_tbuf"], NONE)))
        _set_a(e, A_RBUF, p["pl_buf"])
        _set_a(e, A_TBUF, p["pl_tbuf"])
        inloop = lambda q: e.ne(e.ld(e.add(_a(e, A_INLOOP), q)), 0)  # noqa: E731
        e.st(TRACE_AT + 1, 1)
        # Table addresses used in a loop.
        e.for_("pl_v", 0, _g(e, G_VCOUNT), lambda: e.if_(e.ne(_av(e, V_TSUBJ, p["pl_v"]), NONE), lambda: e.if_(
            inloop(e.and_(e.udiv(_vf(e, G_VPOS, p["pl_v"]), 1 << 40), (1 << 22) - 1)), lambda: _set_av(e, V_HOIST, _av(e, V_TADDR, p["pl_v"]), 1))))
        # Loop check bounds: one synthetic constant per distinct bound (result 3 of its first checked access).
        e.var("pl_bounds", e.alloc(e.add(e.mul(_g(e, G_VCOUNT), 2), 2)))
        _ok(e, e.ne(p["pl_bounds"], NONE))
        e.var("pl_nbounds", 0)

        def check_block():
            e.var("pl_b", e.ld(e.add(_g(e, G_BLIST), p["pl_q"])))

            def node():
                e.var("pl_node", e.ld(e.add(_f(e, p["pl_b"], B_NODES), p["pl_m"])))
                node_ = p["pl_node"]

                def checked():
                    _const(e, _operand(e, node_, 1), "pl_ic")
                    skip = e.either(e.ne(p["pl_ic_is"], 0), e.ne(_q(e, "a64_scaled", node_), NONE), e.ne(_call(e, "a64_proven", node_), 0))

                    def bound():
                        e.var("pl_ext", _call(e, "extent", _operand(e, node_, 0)))
                        e.var("pl_size", e.rd(e.add(_f(e, node_, N_ATTR), 1)))

                        def nonnegative():
                            e.var("pl_bound", e.sub(p["pl_ext"], p["pl_size"]))

                            def hoist():
                                e.var("pl_found", NONE)
                                e.for_("pl_k", 0, p["pl_nbounds"], lambda: e.if_(e.eq(e.ld(e.add(p["pl_bounds"], e.mul(p["pl_k"], 2))), p["pl_bound"]),
                                                                                 lambda: e.set("pl_found", e.ld(e.add(p["pl_bounds"], e.add(e.mul(p["pl_k"], 2), 1))))))

                                def new():
                                    _synthetic(e, p["pl_q"], p["pl_m"], 3, "pl_value")
                                    _set_t(e, G2_CONST, p["pl_value"], 1)
                                    _set_t(e, G2_CVAL, p["pl_value"], p["pl_bound"])
                                    _set_av(e, V_HOIST, p["pl_value"], 1)
                                    e.st(e.add(p["pl_bounds"], e.mul(p["pl_nbounds"], 2)), p["pl_bound"])
                                    e.st(e.add(p["pl_bounds"], e.add(e.mul(p["pl_nbounds"], 2), 1)), p["pl_value"])
                                    e.set("pl_nbounds", e.add(p["pl_nbounds"], 1))
                                    e.set("pl_found", p["pl_value"])

                                e.if_(e.eq(p["pl_found"], NONE), new)
                                e.st(_node_word(e, A_CHECK, p["pl_q"], p["pl_m"]), p["pl_found"])

                            e.if_(e.eq(_q(e, "a64_addsub", p["pl_bound"]), NONE), hoist)

                        e.if_(e.le(p["pl_size"], p["pl_ext"]), nonnegative)

                    e.if_(e.not_(skip), bound)

                e.if_(_in(e, _eop(e, node_), CHECKED), checked)

            e.for_("pl_m", 0, _f(e, p["pl_b"], B_NNODES), node)

        e.st(TRACE_AT + 1, 2)
        e.for_("pl_q", 0, p["pl_nb"], lambda: e.if_(inloop(p["pl_q"]), check_block))
        e.st(TRACE_AT + 1, 3)

        # Constants of two or more instructions used unfolded in a loop.
        def hoist_block():
            e.var("pl_b", e.ld(e.add(_g(e, G_BLIST), p["pl_q"])))

            def candidate(value):
                e.var("pl_cv", value)
                e.if_(e.le(2, _call(e, "a64_movlen", _t(e, G2_CVAL, p["pl_cv"]), 1)), lambda: _set_av(e, V_HOIST, p["pl_cv"], 1))

            def node():
                e.var("pl_node", e.ld(e.add(_f(e, p["pl_b"], B_NODES), p["pl_m"])))

                def operands():
                    def operand():
                        e.var("pl_o", _operand(e, p["pl_node"], p["pl_k"]))
                        _const(e, p["pl_o"], "pl_oc")
                        e.var("pl_oc_v", _canon(e, p["pl_o"], "pl_ocv"))
                        e.if_(e.both(e.ne(p["pl_oc_is"], 0), e.ne(_rt_(e, T_RW, p["pl_oc_v"]), 0)), lambda: e.if_(
                            e.eq(_call(e, "a64_folds", p["pl_node"], p["pl_k"]), 0), lambda: candidate(p["pl_oc_v"])))

                    e.for_("pl_k", 0, _f(e, p["pl_node"], N_NOPS), operand)

                e.if_(e.not_(_in(e, _eop(e, p["pl_node"]), CALLS)), operands)

            e.for_("pl_m", 0, _f(e, p["pl_b"], B_NNODES), node)

            def masks():
                e.var("pl_node", e.ld(e.add(_f(e, p["pl_b"], B_NODES), p["pl_m"])))
                e.if_(e.ne(_f(e, p["pl_node"], N_NRES), 0), lambda: e.if_(e.ne(_av(e, V_MSUBJ, _output(e, p["pl_node"], 0)), NONE),
                                                                          lambda: candidate(_av(e, V_MMASK, _output(e, p["pl_node"], 0)))))

            e.for_("pl_m", 0, _f(e, p["pl_b"], B_NNODES), masks)

        e.for_("pl_q", 0, p["pl_nb"], lambda: e.if_(inloop(p["pl_q"]), hoist_block))
        e.st(TRACE_AT + 1, 4)
        # Dead pure nodes, to a fixed point; the read counts of the last round.
        e.var("pl_changed", 1)

        def round_():
            e.set("pl_changed", 0)
            e.for_("pl_v", 0, _g(e, G_VCOUNT), lambda: _set_av(e, V_READ, p["pl_v"], 0))

            def count_block():
                e.var("pl_b", e.ld(e.add(_g(e, G_BLIST), p["pl_q"])))

                def node():
                    def counted():
                        e.var("pl_r", _call(e, "a64_reads", p["pl_q"], p["pl_m"]))
                        e.for_("pl_k", 0, p["pl_r"], lambda: (e.var("pl_x", e.ld(e.add(_a(e, A_RBUF), p["pl_k"]))),
                                                              _set_av(e, V_READ, p["pl_x"], e.add(_av(e, V_READ, p["pl_x"]), 1))))

                    e.if_(e.eq(e.ld(_node_word(e, A_DEAD, p["pl_q"], p["pl_m"])), 0), counted)

                e.for_("pl_m", 0, _f(e, p["pl_b"], B_NNODES), node)
                e.var("pl_t", _call(e, "a64_treads", p["pl_q"]))
                e.for_("pl_k", 0, p["pl_t"], lambda: (e.var("pl_x", e.ld(e.add(_a(e, A_TBUF), p["pl_k"]))),
                                                      _set_av(e, V_READ, p["pl_x"], e.add(_av(e, V_READ, p["pl_x"]), 1))))

            e.for_("pl_q", 0, p["pl_nb"], count_block)

            def kill_block():
                e.var("pl_b", e.ld(e.add(_g(e, G_BLIST), p["pl_q"])))

                def node():
                    e.var("pl_node", e.ld(e.add(_f(e, p["pl_b"], B_NODES), p["pl_m"])))
                    alive = e.both(e.eq(e.ld(_node_word(e, A_DEAD, p["pl_q"], p["pl_m"])), 0), _in(e, _eop(e, p["pl_node"]), PURE))

                    def check():
                        e.var("pl_d", _q(e, "a64_defines", p["pl_q"], p["pl_m"]))
                        e.if_(e.ne(p["pl_d"], NONE), lambda: e.if_(e.eq(_av(e, V_READ, p["pl_d"]), 0), lambda: (
                            e.st(_node_word(e, A_DEAD, p["pl_q"], p["pl_m"]), 1), e.set("pl_changed", 1))))

                    e.if_(alive, check)

                e.for_("pl_m", 0, _f(e, p["pl_b"], B_NNODES), node)

            e.for_("pl_q", 0, p["pl_nb"], kill_block)

        e.while_(lambda: e.ne(p["pl_changed"], 0), round_)
        e.give(1)
    return _function((), build, tables)


def _write_plan(tables):
    """The audit record of ``_plan`` (tests): per view value its hoisted flag and read count; per node its check
    bound (a value or none) and dead flag; then the synthetic values (position, hoisted, constant)."""
    from xax_selfhost_general_ranges import G2_CONST, G2_CVAL, _t
    from xax_selfhost_general_view import _out_value

    def build(e: E):
        p = e.p

        def block():
            e.var("wp_b", e.ld(e.add(_g(e, G_BLIST), p["wp_q"])))

            def node():
                e.var("wp_cb", e.ld(_node_word(e, A_CHECK, p["wp_q"], p["wp_m"])))
                e.if_(e.eq(p["wp_cb"], NONE), lambda: _out(e, 0), lambda: (_out(e, 1), _out_value(e, p["wp_cb"])))
                _out(e, e.ld(_node_word(e, A_DEAD, p["wp_q"], p["wp_m"])))

            e.for_("wp_m", 0, _f(e, p["wp_b"], B_NNODES), node)

        e.for_("wp_q", 0, _a(e, A_NB), block)
        e.var("wp_n", _g(e, G_VCOUNT))

        def value():
            e.if_(e.ne(_vf(e, G_VPOS, p["wp_v"]), NONE), lambda: (
                _out(e, 1), _out_value(e, p["wp_v"]), _out(e, _av(e, V_HOIST, p["wp_v"])), _out(e, _av(e, V_READ, p["wp_v"])),
                _out(e, _t(e, G2_CONST, p["wp_v"])), _out(e, _t(e, G2_CVAL, p["wp_v"]))))

        e.for_("wp_v", 0, p["wp_n"], value)
        _out(e, 0)
        e.give(1)
    return _function((), build, tables)


# -- liveness, intervals, allocation (``_liveness``, ``_intervals``, ``_allocate``) -------------------------------

def _bit_set(e: E, base, index):
    e.st(e.add(base, e.udiv(index, 64)), e.bin(Operation.BIT_OR, e.ld(e.add(base, e.udiv(index, 64))), _power(e, e.and_(index, 63))))


def _bit_has(e: E, base, index):
    return e.ne(e.and_(e.ld(e.add(base, e.udiv(index, 64))), _power(e, e.and_(index, 63))), 0)


def _is_call_node(e: E, node, name: str):
    """A call that is not an erased proof function's (``_liveness``' ``calls_at``) into ``name``."""
    p = e.p
    e.var(name, e.flag(_in(e, _eop(e, node), CALLS)))

    def direct():
        from xax_selfhost_general_regalloc import _callee_object

        _callee_object(e, node, f"{name}_callee")
        e.if_(e.ne(_call(e, "erased", p[f"{name}_callee"]), 0), lambda: e.set(name, 0))

    e.if_(e.eq(_eop(e, node), int(Operation.CALL_DIRECT)), direct)
    return p[name]


def _machine_param(e: E, value):
    """A block parameter in ``widths`` that is not a copy."""
    from xax_selfhost_general_regalloc import T_ALIAS, T_RW

    return e.both(e.ne(_rt_(e, T_RW, value), 0), e.eq(_rt_(e, T_ALIAS, value), NONE))


def _liveness_fn(tables):
    """``_liveness``: positions in layout order (a block start, two per node, two at the terminator), the calls'
    positions, and live-in/live-out bit sets (``A_WORDS`` words per block over value ids) to a fixed point over the
    layout order reversed."""
    from xax_selfhost_general_view import B_EDGES, B_NEDGES, EDGE, B_POS

    def build(e: E):
        p = e.p
        e.var("lv_nb", _a(e, A_NB))
        nb = p["lv_nb"]
        e.var("lv_nv", _g(e, G_VCOUNT))
        e.var("lv_w", e.udiv(e.add(p["lv_nv"], 63), 64))
        _set_a(e, A_WORDS, p["lv_w"])
        for slot in (A_BSTART, A_TERMAT, A_NODEAT):
            e.var(f"lv_t{slot}", e.alloc(e.add(nb, 1)))
            _ok(e, e.ne(p[f"lv_t{slot}"], NONE))
            _set_a(e, slot, p[f"lv_t{slot}"])
        e.var("lv_nodes", 0)
        e.for_("lv_q", 0, nb, lambda: e.set("lv_nodes", e.add(p["lv_nodes"], _f(e, e.ld(e.add(_g(e, G_BLIST), p["lv_q"])), B_NNODES))))
        e.var("lv_calls", e.alloc(e.add(p["lv_nodes"], 1)))
        _ok(e, e.ne(p["lv_calls"], NONE))
        _set_a(e, A_CALLS, p["lv_calls"])
        e.var("lv_ncalls", 0)
        e.var("lv_pos", 0)

        def place():
            e.var("lv_bi", e.ld(e.add(_a(e, A_ORDER), p["lv_k"])))
            e.var("lv_b", e.ld(e.add(_g(e, G_BLIST), p["lv_bi"])))
            e.st(e.add(_a(e, A_BSTART), p["lv_bi"]), p["lv_pos"])
            e.set("lv_pos", e.add(p["lv_pos"], 1))
            e.var("lv_at", e.alloc(e.add(_f(e, p["lv_b"], B_NNODES), 1)))
            _ok(e, e.ne(p["lv_at"], NONE))
            e.st(e.add(_a(e, A_NODEAT), p["lv_bi"]), p["lv_at"])

            def node():
                e.st(e.add(p["lv_at"], p["lv_m"]), p["lv_pos"])
                e.var("lv_node", e.ld(e.add(_f(e, p["lv_b"], B_NODES), p["lv_m"])))
                e.if_(e.ne(_is_call_node(e, p["lv_node"], "lv_call"), 0), lambda: (e.st(e.add(p["lv_calls"], p["lv_ncalls"]), p["lv_pos"]),
                                                                                  e.set("lv_ncalls", e.add(p["lv_ncalls"], 1))))
                e.set("lv_pos", e.add(p["lv_pos"], 2))

            e.for_("lv_m", 0, _f(e, p["lv_b"], B_NNODES), node)
            e.st(e.add(_a(e, A_TERMAT), p["lv_bi"]), p["lv_pos"])
            e.set("lv_pos", e.add(p["lv_pos"], 2))

        e.for_("lv_k", 0, nb, place)
        _set_a(e, A_NCALLS, p["lv_ncalls"])
        # Upward-exposed uses and definitions per block (index order).
        size = e.add(e.mul(nb, p["lv_w"]), 1)
        for name in ("lv_up", "lv_def", "lv_in", "lv_out"):
            e.var(name, e.alloc(size))
            _ok(e, e.ne(p[name], NONE))
            e.for_("lv_z", 0, size, lambda name=name: e.st(e.add(p[name], p["lv_z"]), 0))
        _set_a(e, A_LIVEIN, p["lv_in"])
        _set_a(e, A_LIVEOUT, p["lv_out"])
        row = lambda base, block: e.add(base, e.mul(block, p["lv_w"]))  # noqa: E731

        def local():
            e.var("lv_b", e.ld(e.add(_g(e, G_BLIST), p["lv_q"])))
            e.var("lv_defs", row(p["lv_def"], p["lv_q"]))
            e.var("lv_ups", row(p["lv_up"], p["lv_q"]))
            e.for_("lv_k", 0, _f(e, p["lv_b"], B_NP), lambda: (e.var("lv_pv", e.ld(e.add(_f(e, p["lv_b"], B_INPUTS), p["lv_k"]))),
                                                               e.if_(_machine_param(e, p["lv_pv"]), lambda: _bit_set(e, p["lv_defs"], p["lv_pv"]))))
            e.if_(e.eq(p["lv_q"], _a(e, A_ENTRY)), lambda: e.for_("lv_v", 0, p["lv_nv"], lambda: e.if_(e.ne(_av(e, V_HOIST, p["lv_v"]), 0),
                                                                                                        lambda: _bit_set(e, p["lv_defs"], p["lv_v"]))))

            def node():
                def alive():
                    e.var("lv_r", _call(e, "a64_reads", p["lv_q"], p["lv_m"]))
                    e.for_("lv_k", 0, p["lv_r"], lambda: (e.var("lv_x", e.ld(e.add(_a(e, A_RBUF), p["lv_k"]))),
                                                          e.if_(e.not_(_bit_has(e, p["lv_defs"], p["lv_x"])), lambda: _bit_set(e, p["lv_ups"], p["lv_x"]))))
                    e.var("lv_d", _q(e, "a64_defines", p["lv_q"], p["lv_m"]))
                    e.if_(e.ne(p["lv_d"], NONE), lambda: _bit_set(e, p["lv_defs"], p["lv_d"]))

                e.if_(e.eq(e.ld(_node_word(e, A_DEAD, p["lv_q"], p["lv_m"])), 0), alive)

            e.for_("lv_m", 0, _f(e, p["lv_b"], B_NNODES), node)
            e.var("lv_t", _call(e, "a64_treads", p["lv_q"]))
            e.for_("lv_k", 0, p["lv_t"], lambda: (e.var("lv_x", e.ld(e.add(_a(e, A_TBUF), p["lv_k"]))),
                                                  e.if_(e.not_(_bit_has(e, p["lv_defs"], p["lv_x"])), lambda: _bit_set(e, p["lv_ups"], p["lv_x"]))))

        e.for_("lv_q", 0, nb, local)
        e.for_("lv_z", 0, e.mul(nb, p["lv_w"]), lambda: e.st(e.add(p["lv_in"], p["lv_z"]), e.ld(e.add(p["lv_up"], p["lv_z"]))))
        e.var("lv_scratch", e.alloc(e.add(p["lv_w"], 1)))
        e.var("lv_params", e.alloc(e.add(p["lv_w"], 1)))
        _ok(e, e.both(e.ne(p["lv_scratch"], NONE), e.ne(p["lv_params"], NONE)))
        e.var("lv_changed", 1)

        def round_():
            e.set("lv_changed", 0)
            e.var("lv_k", nb)

            def block():
                e.set("lv_k", e.sub(p["lv_k"], 1))
                e.var("lv_bi", e.ld(e.add(_a(e, A_ORDER), p["lv_k"])))
                e.var("lv_b", e.ld(e.add(_g(e, G_BLIST), p["lv_bi"])))
                e.for_("lv_z", 0, p["lv_w"], lambda: e.st(e.add(p["lv_scratch"], p["lv_z"]), 0))

                def edge():
                    e.var("lv_tb", _f(e, e.add(_f(e, p["lv_b"], B_EDGES), e.mul(p["lv_j"], EDGE)), 0))
                    e.var("lv_ti", _f(e, p["lv_tb"], B_POS))
                    e.for_("lv_z", 0, p["lv_w"], lambda: e.st(e.add(p["lv_params"], p["lv_z"]), 0))
                    e.for_("lv_a", 0, _f(e, p["lv_tb"], B_NP), lambda: _bit_set(e, p["lv_params"], e.ld(e.add(_f(e, p["lv_tb"], B_INPUTS), p["lv_a"]))))
                    e.for_("lv_z", 0, p["lv_w"], lambda: e.st(e.add(p["lv_scratch"], p["lv_z"]), e.bin(Operation.BIT_OR, e.ld(e.add(p["lv_scratch"], p["lv_z"])), e.and_(
                        e.ld(e.add(row(p["lv_in"], p["lv_ti"]), p["lv_z"])), e.bin(Operation.BIT_XOR, e.ld(e.add(p["lv_params"], p["lv_z"])), (1 << 64) - 1)))))

                e.for_("lv_j", 0, _f(e, p["lv_b"], B_NEDGES), edge)

                def word():
                    e.var("lv_o", e.ld(e.add(p["lv_scratch"], p["lv_z"])))
                    e.var("lv_i", e.bin(Operation.BIT_OR, e.ld(e.add(row(p["lv_up"], p["lv_bi"]), p["lv_z"])), e.and_(p["lv_o"], e.bin(
                        Operation.BIT_XOR, e.ld(e.add(row(p["lv_def"], p["lv_bi"]), p["lv_z"])), (1 << 64) - 1))))
                    e.if_(e.either(e.ne(p["lv_o"], e.ld(e.add(row(p["lv_out"], p["lv_bi"]), p["lv_z"]))), e.ne(p["lv_i"], e.ld(e.add(row(p["lv_in"], p["lv_bi"]), p["lv_z"])))),
                          lambda: e.set("lv_changed", 1))
                    e.st(e.add(row(p["lv_out"], p["lv_bi"]), p["lv_z"]), p["lv_o"])
                    e.st(e.add(row(p["lv_in"], p["lv_bi"]), p["lv_z"]), p["lv_i"])

                e.for_("lv_z", 0, p["lv_w"], word)

            e.while_(lambda: e.ne(p["lv_k"], 0), block)

        e.while_(lambda: e.ne(p["lv_changed"], 0), round_)
        e.give(1)
    return _function((), build, tables)


def _add_range(e: E, value, start, end):
    """``interval(value).add(start, end)``: a range in the pool, linked from the value's list."""
    p = e.p
    e.var("ar_at", e.add(_a(e, A_POOL), e.mul(_a(e, A_NPOOL), 3)))
    e.st(p["ar_at"], start)
    e.st(e.add(p["ar_at"], 1), end)
    e.st(e.add(p["ar_at"], 2), _av(e, V_RANGES, value))
    _set_av(e, V_RANGES, value, p["ar_at"])
    _set_a(e, A_NPOOL, e.add(_a(e, A_NPOOL), 1))


def _interval(e: E, value):
    """``interval(value)``: created on first use (``V_IV``), listed in creation order."""
    p = e.p
    e.var("iv_v", value)

    def create():
        _set_av(e, V_IV, p["iv_v"], 1)
        _set_av(e, V_WEIGHT, p["iv_v"], 0)
        _set_av(e, V_RANGES, p["iv_v"], 0)
        _set_av(e, V_REG, p["iv_v"], NONE)
        _set_av(e, V_SLOT, p["iv_v"], NONE)
        e.st(e.add(_a(e, A_IVLIST), _a(e, A_NIV)), p["iv_v"])
        _set_a(e, A_NIV, e.add(_a(e, A_NIV), 1))

    e.if_(e.eq(_av(e, V_IV, p["iv_v"]), 0), create)
    return p["iv_v"]


def _intervals_fn(tables):
    """``_intervals``: per block (index order) each value's first and last positions (reads, definitions, terminator
    reads, live-in, live-out) as ranges, with weights ``10 ** min(depth, 4)``; a block parameter is also written at
    the end of each predecessor; then each value's ranges sorted and merged, and whether one spans a call."""
    from xax_selfhost_general_view import B_EDGES, B_NEDGES, EDGE, B_POS

    def build(e: E):
        p = e.p
        e.var("it_nb", _a(e, A_NB))
        nb = p["it_nb"]
        e.var("it_nv", _g(e, G_VCOUNT))
        nv = p["it_nv"]
        e.var("it_pool", e.alloc(e.add(e.mul(e.add(e.mul(nb, nv), e.mul(nb, 4)), 3), 64)))
        e.var("it_list", e.alloc(e.add(nv, 1)))
        _ok(e, e.both(e.ne(p["it_pool"], NONE), e.ne(p["it_list"], NONE)))
        _set_a(e, A_POOL, p["it_pool"])
        _set_a(e, A_NPOOL, 0)
        _set_a(e, A_IVLIST, p["it_list"])
        _set_a(e, A_NIV, 0)
        e.for_("it_v", 0, nv, lambda: (_set_av(e, V_IV, p["it_v"], 0), _set_av(e, V_STAMP, p["it_v"], 0)))
        e.var("it_mark", 0)
        e.var("it_touched", e.alloc(e.add(nv, 1)))
        _ok(e, e.ne(p["it_touched"], NONE))
        w = _a(e, A_WORDS)
        e.var("it_w", w)

        def block():
            e.set("it_mark", e.add(p["it_mark"], 1))
            e.var("it_nt", 0)  # the values with a first or last position in this block, in first-touch order
            e.var("it_b", e.ld(e.add(_g(e, G_BLIST), p["it_q"])))
            e.var("it_depth", e.ld(e.add(_a(e, A_DEPTH), p["it_q"])))
            e.var("it_factor", 1)
            e.for_("it_d", 0, e.sel(e.lt(p["it_depth"], 4), p["it_depth"], 4), lambda: e.set("it_factor", e.mul(p["it_factor"], 10)))
            e.var("it_start", e.ld(e.add(_a(e, A_BSTART), p["it_q"])))

            def touch(value):
                e.var("tc_v", value)

                def new():
                    _set_av(e, V_STAMP, p["tc_v"], p["it_mark"])
                    _set_av(e, V_FIRST, p["tc_v"], NONE)
                    _set_av(e, V_LAST, p["tc_v"], NONE)
                    e.st(e.add(p["it_touched"], p["it_nt"]), p["tc_v"])
                    e.set("it_nt", e.add(p["it_nt"], 1))

                e.if_(e.ne(_av(e, V_STAMP, p["tc_v"]), p["it_mark"]), new)
                return p["tc_v"]

            def set_first(value, position):
                v = touch(value)
                _set_av(e, V_FIRST, v, position)

            def set_last(value, position):
                v = touch(value)
                _set_av(e, V_LAST, v, position)

            def weigh(value):
                e.var("wg_v", value)
                _interval(e, p["wg_v"])
                _set_av(e, V_WEIGHT, p["wg_v"], e.add(_av(e, V_WEIGHT, p["wg_v"]), p["it_factor"]))

            e.for_("it_k", 0, _f(e, p["it_b"], B_NP), lambda: (e.var("it_pv", e.ld(e.add(_f(e, p["it_b"], B_INPUTS), p["it_k"]))),
                                                               e.if_(_machine_param(e, p["it_pv"]), lambda: set_first(p["it_pv"], p["it_start"]))))

            def hoisted():
                # ``sorted(self.hoisted, key=(block, index))``: synthetic and real values by their node position
                e.var("hs_list", e.alloc(e.add(nv, 1)))
                _ok(e, e.ne(p["hs_list"], NONE))
                e.var("hs_n", 0)
                e.for_("hs_v", 0, _g(e, G_VCOUNT), lambda: e.if_(e.ne(_av(e, V_HOIST, p["hs_v"]), 0), lambda: (
                    e.st(e.add(p["hs_list"], p["hs_n"]), p["hs_v"]), e.set("hs_n", e.add(p["hs_n"], 1)))))
                key = lambda v: e.udiv(_vf(e, G_VPOS, v), 1 << 16)  # noqa: E731  (tag, block, index): the hoisted are node results

                def insert():
                    e.var("hs_item", e.ld(e.add(p["hs_list"], p["hs_s"])))
                    e.var("hs_j", p["hs_s"])
                    before = lambda: e.both(e.lt(0, p["hs_j"]), e.lt(key(p["hs_item"]), key(e.ld(e.add(p["hs_list"], e.sub(p["hs_j"], 1))))))  # noqa: E731
                    e.while_(before, lambda: (e.st(e.add(p["hs_list"], p["hs_j"]), e.ld(e.add(p["hs_list"], e.sub(p["hs_j"], 1)))), e.set("hs_j", e.sub(p["hs_j"], 1))))
                    e.st(e.add(p["hs_list"], p["hs_j"]), p["hs_item"])

                e.for_("hs_s", 1, p["hs_n"], insert)
                e.for_("hs_k", 0, p["hs_n"], lambda: set_first(e.ld(e.add(p["hs_list"], p["hs_k"])), p["it_start"]))

            e.if_(e.eq(p["it_q"], _a(e, A_ENTRY)), hoisted)

            def node():
                def alive():
                    e.var("it_at", e.ld(_node_word(e, A_NODEAT, p["it_q"], p["it_m"])))
                    e.var("it_r", _call(e, "a64_reads", p["it_q"], p["it_m"]))
                    e.for_("it_k", 0, p["it_r"], lambda: (e.var("it_x", e.ld(e.add(_a(e, A_RBUF), p["it_k"]))), set_last(p["it_x"], p["it_at"]), weigh(p["it_x"])))
                    e.var("it_d", _q(e, "a64_defines", p["it_q"], p["it_m"]))

                    def defined():
                        v = touch(p["it_d"])
                        e.if_(e.eq(_av(e, V_FIRST, v), NONE), lambda: _set_av(e, V_FIRST, v, e.add(p["it_at"], 1)))
                        e.if_(e.eq(_av(e, V_LAST, v), NONE), lambda: _set_av(e, V_LAST, v, e.add(p["it_at"], 1)))
                        weigh(p["it_d"])

                    e.if_(e.ne(p["it_d"], NONE), defined)

                e.if_(e.eq(e.ld(_node_word(e, A_DEAD, p["it_q"], p["it_m"])), 0), alive)

            e.for_("it_m", 0, _f(e, p["it_b"], B_NNODES), node)
            e.var("it_t", _call(e, "a64_treads", p["it_q"]))
            e.var("it_term", e.ld(e.add(_a(e, A_TERMAT), p["it_q"])))
            e.for_("it_k", 0, p["it_t"], lambda: (e.var("it_x", e.ld(e.add(_a(e, A_TBUF), p["it_k"]))), set_last(p["it_x"], p["it_term"]), weigh(p["it_x"])))
            e.var("it_in", e.add(_a(e, A_LIVEIN), e.mul(p["it_q"], p["it_w"])))
            e.var("it_out", e.add(_a(e, A_LIVEOUT), e.mul(p["it_q"], p["it_w"])))
            e.var("it_end", e.add(p["it_term"], 1))
            e.for_("it_v", 0, nv, lambda: e.if_(_bit_has(e, p["it_in"], p["it_v"]), lambda: set_first(p["it_v"], p["it_start"])))
            e.for_("it_v", 0, nv, lambda: e.if_(_bit_has(e, p["it_out"], p["it_v"]), lambda: set_last(p["it_v"], p["it_end"])))

            def ranges():
                e.var("it_x", e.ld(e.add(p["it_touched"], p["it_k"])))
                e.var("it_first", _av(e, V_FIRST, p["it_x"]))
                e.var("it_last", _av(e, V_LAST, p["it_x"]))

                def with_last():
                    _interval(e, p["it_x"])
                    _add_range(e, p["it_x"], e.sel(e.eq(p["it_first"], NONE), p["it_start"], p["it_first"]), p["it_last"])

                e.if_(e.ne(p["it_last"], NONE), with_last, lambda: e.if_(e.ne(_av(e, V_IV, p["it_x"]), 0), lambda: _add_range(e, p["it_x"], p["it_first"], p["it_first"])))

            e.for_("it_k", 0, p["it_nt"], ranges)

        e.for_("it_q", 0, nb, block)

        def edges():
            e.var("ie_b", e.ld(e.add(_g(e, G_BLIST), p["ie_q"])))
            e.var("ie_end", e.add(e.ld(e.add(_a(e, A_TERMAT), p["ie_q"])), 1))

            def edge():
                e.var("ie_t", _f(e, e.add(_f(e, p["ie_b"], B_EDGES), e.mul(p["ie_j"], EDGE)), 0))
                e.for_("ie_a", 0, _f(e, p["ie_t"], B_NP), lambda: (e.var("ie_pv", e.ld(e.add(_f(e, p["ie_t"], B_INPUTS), p["ie_a"]))),
                                                                   e.if_(e.ne(_av(e, V_IV, p["ie_pv"]), 0), lambda: _add_range(e, p["ie_pv"], p["ie_end"], p["ie_end"]))))

            e.for_("ie_j", 0, _f(e, p["ie_b"], B_NEDGES), edge)

        e.for_("ie_q", 0, nb, edges)
        _call(e, "a64_normalize")
        e.give(1)
    return _function((), build, tables)


def _normalize_fn(tables):
    """Each interval's ranges sorted by (start, end) and merged where they touch, into a compact array
    (``V_RANGES``, ``V_NRANGES``: two words per range); whether one spans a call (``V_CROSS``)."""
    def build(e: E):
        p = e.p

        def each():
            e.var("nz_v", e.ld(e.add(_a(e, A_IVLIST), p["nz_k"])))
            e.var("nz_n", 0)
            e.var("nz_at", _av(e, V_RANGES, p["nz_v"]))
            e.while_(lambda: e.ne(p["nz_at"], 0), lambda: (e.set("nz_n", e.add(p["nz_n"], 1)), e.set("nz_at", e.ld(e.add(p["nz_at"], 2)))))
            e.var("nz_arr", e.alloc(e.add(e.mul(p["nz_n"], 2), 2)))
            _ok(e, e.ne(p["nz_arr"], NONE))
            e.var("nz_i", 0)
            e.set("nz_at", _av(e, V_RANGES, p["nz_v"]))

            def copy():
                e.st(e.add(p["nz_arr"], e.mul(p["nz_i"], 2)), e.ld(p["nz_at"]))
                e.st(e.add(p["nz_arr"], e.add(e.mul(p["nz_i"], 2), 1)), e.ld(e.add(p["nz_at"], 1)))
                e.set("nz_i", e.add(p["nz_i"], 1))
                e.set("nz_at", e.ld(e.add(p["nz_at"], 2)))

            e.while_(lambda: e.ne(p["nz_at"], 0), copy)
            start = lambda k: e.ld(e.add(p["nz_arr"], e.mul(k, 2)))  # noqa: E731
            end = lambda k: e.ld(e.add(p["nz_arr"], e.add(e.mul(k, 2), 1)))  # noqa: E731

            def insert():
                e.var("nz_s0", start(p["nz_s"]))
                e.var("nz_e0", end(p["nz_s"]))
                e.var("nz_j", p["nz_s"])
                less = lambda k: e.either(e.lt(p["nz_s0"], start(k)), e.both(e.eq(p["nz_s0"], start(k)), e.lt(p["nz_e0"], end(k))))  # noqa: E731
                e.while_(lambda: e.both(e.lt(0, p["nz_j"]), less(e.sub(p["nz_j"], 1))), lambda: (
                    e.st(e.add(p["nz_arr"], e.mul(p["nz_j"], 2)), start(e.sub(p["nz_j"], 1))),
                    e.st(e.add(p["nz_arr"], e.add(e.mul(p["nz_j"], 2), 1)), end(e.sub(p["nz_j"], 1))),
                    e.set("nz_j", e.sub(p["nz_j"], 1))))
                e.st(e.add(p["nz_arr"], e.mul(p["nz_j"], 2)), p["nz_s0"])
                e.st(e.add(p["nz_arr"], e.add(e.mul(p["nz_j"], 2), 1)), p["nz_e0"])

            e.for_("nz_s", 1, p["nz_n"], insert)
            e.var("nz_m", 0)

            def merge():
                e.var("nz_a", start(p["nz_k2"]))
                e.var("nz_b", end(p["nz_k2"]))

                def extend():
                    e.var("nz_last", e.sub(p["nz_m"], 1))
                    e.if_(e.lt(end(p["nz_last"]), p["nz_b"]), lambda: e.st(e.add(p["nz_arr"], e.add(e.mul(p["nz_last"], 2), 1)), p["nz_b"]))

                def append():
                    e.st(e.add(p["nz_arr"], e.mul(p["nz_m"], 2)), p["nz_a"])
                    e.st(e.add(p["nz_arr"], e.add(e.mul(p["nz_m"], 2), 1)), p["nz_b"])
                    e.set("nz_m", e.add(p["nz_m"], 1))

                e.if_(e.both(e.lt(0, p["nz_m"]), e.le(p["nz_a"], e.add(end(e.sub(p["nz_m"], 1)), 1))), extend, append)

            e.for_("nz_k2", 0, p["nz_n"], merge)
            _set_av(e, V_RANGES, p["nz_v"], p["nz_arr"])
            _set_av(e, V_NRANGES, p["nz_v"], p["nz_m"])
            e.var("nz_cross", 0)
            e.for_("nz_r", 0, p["nz_m"], lambda: e.for_("nz_c", 0, _a(e, A_NCALLS), lambda: (
                e.var("nz_call", e.ld(e.add(_a(e, A_CALLS), p["nz_c"]))),
                e.if_(e.both(e.lt(start(p["nz_r"]), p["nz_call"]), e.lt(p["nz_call"], end(p["nz_r"]))), lambda: e.set("nz_cross", 1)))))
            _set_av(e, V_CROSS, p["nz_v"], p["nz_cross"])

        e.for_("nz_k", 0, _a(e, A_NIV), each)
        e.give(1)
    return _function((), build, tables)


def _overlaps_fn(tables):
    """``_Interval.overlaps``: two intervals' sorted ranges intersect."""
    def build(e: E):
        p = e.p
        e.var("ov_a", _av(e, V_RANGES, p["x"]))
        e.var("ov_na", _av(e, V_NRANGES, p["x"]))
        e.var("ov_b", _av(e, V_RANGES, p["y"]))
        e.var("ov_nb", _av(e, V_NRANGES, p["y"]))
        e.var("ov_i", 0)
        e.var("ov_j", 0)
        a = lambda k, f: e.ld(e.add(p["ov_a"], e.add(e.mul(k, 2), f)))  # noqa: E731
        b = lambda k, f: e.ld(e.add(p["ov_b"], e.add(e.mul(k, 2), f)))  # noqa: E731

        def step():
            e.if_(e.lt(a(p["ov_i"], 1), b(p["ov_j"], 0)), lambda: e.set("ov_i", e.add(p["ov_i"], 1)), lambda: e.if_(
                e.lt(b(p["ov_j"], 1), a(p["ov_i"], 0)), lambda: e.set("ov_j", e.add(p["ov_j"], 1)), lambda: e.give(1)))

        e.while_(lambda: e.both(e.lt(p["ov_i"], p["ov_na"]), e.lt(p["ov_j"], p["ov_nb"])), step)
        e.give(0)
    return _function(("x", "y"), build, tables)


def _allocate_fn(tables):
    """``_allocate``: copy partners and their groups (union of a block parameter with its arguments), register hints
    (entry parameters, call results, returned values), then the intervals by weight (ties by start and position),
    each taking its group's, a partner's, or its hinted register when free, else an unreserved free one, else
    evicting cheaper conflicts or taking a frame slot."""
    from xax_selfhost_general_view import B_EDGES, B_NEDGES, EDGE, B_POS, RETURN

    def build(e: E):
        p = e.p
        e.var("al_niv", _a(e, A_NIV))
        niv = p["al_niv"]
        e.var("al_nv", _g(e, G_VCOUNT))
        e.for_("al_v", 0, p["al_nv"], lambda: (_set_av(e, V_PARENT, p["al_v"], NONE), _set_av(e, V_HINT, p["al_v"], NONE), _set_av(e, V_NPART, p["al_v"], 0)))

        def find(value, name):
            e.var(name, value)
            e.while_(lambda: e.ne(_av(e, V_PARENT, p[name]), NONE), lambda: e.set(name, _av(e, V_PARENT, p[name])))
            return p[name]

        # Partners: count, then fill (per value, in edge order).
        e.var("al_pool", e.alloc(e.add(e.mul(niv, 4), e.mul(_a(e, A_NPOOL), 2))))
        _ok(e, e.ne(p["al_pool"], NONE))

        def each_copy(visit):
            def block():
                e.var("ac_b", e.ld(e.add(_g(e, G_BLIST), p["ac_q"])))

                def edge():
                    e.var("ac_e", e.add(_f(e, p["ac_b"], B_EDGES), e.mul(p["ac_j"], EDGE)))
                    e.var("ac_t", _f(e, p["ac_e"], 0))

                    def argument():
                        e.var("ac_param", e.ld(e.add(_f(e, p["ac_t"], B_INPUTS), p["ac_a"])))
                        e.var("ac_src", _canon(e, e.ld(e.add(_f(e, p["ac_e"], 2), p["ac_a"])), "ac_cs"))
                        e.if_(e.both(e.ne(_av(e, V_IV, p["ac_param"]), 0), e.ne(_av(e, V_IV, p["ac_src"]), 0)), lambda: visit(p["ac_param"], p["ac_src"]))

                    e.for_("ac_a", 0, _f(e, p["ac_e"], 1), argument)

                e.for_("ac_j", 0, _f(e, p["ac_b"], B_NEDGES), edge)

            e.for_("ac_q", 0, _g(e, G_BCOUNT), block)

        each_copy(lambda a, b: (_set_av(e, V_NPART, a, e.add(_av(e, V_NPART, a), 1)), _set_av(e, V_NPART, b, e.add(_av(e, V_NPART, b), 1))))
        e.var("al_cursor", p["al_pool"])
        e.for_("al_k", 0, niv, lambda: (e.var("al_x", e.ld(e.add(_a(e, A_IVLIST), p["al_k"]))), _set_av(e, V_PARTNERS, p["al_x"], p["al_cursor"]),
                                        e.set("al_cursor", e.add(p["al_cursor"], _av(e, V_NPART, p["al_x"]))), _set_av(e, V_NPART, p["al_x"], 0)))

        def link(param, source):
            def add(x, y):
                e.st(e.add(_av(e, V_PARTNERS, x), _av(e, V_NPART, x)), y)
                _set_av(e, V_NPART, x, e.add(_av(e, V_NPART, x), 1))

            e.var("lk_p", param)
            e.var("lk_s", source)
            add(p["lk_p"], p["lk_s"])
            add(p["lk_s"], p["lk_p"])
            find(p["lk_p"], "lk_a")
            find(p["lk_s"], "lk_b")
            e.if_(e.ne(p["lk_a"], p["lk_b"]), lambda: _set_av(e, V_PARENT, p["lk_a"], p["lk_b"]))

        each_copy(link)
        # Hints.
        e.var("al_entry", e.ld(e.add(_g(e, G_BLIST), _a(e, A_ENTRY))))
        e.var("al_mi", 0)
        from xax_selfhost_general_regalloc import T_RW

        e.for_("al_k", 0, _f(e, p["al_entry"], B_NP), lambda: (e.var("al_pv", e.ld(e.add(_f(e, p["al_entry"], B_INPUTS), p["al_k"]))), e.if_(
            e.ne(_rt_(e, T_RW, p["al_pv"]), 0), lambda: (_set_av(e, V_HINT, p["al_pv"], p["al_mi"]), e.set("al_mi", e.add(p["al_mi"], 1))))))

        def hint_block():
            e.var("ah_b", e.ld(e.add(_g(e, G_BLIST), p["ah_q"])))

            def node():
                e.var("ah_node", e.ld(e.add(_f(e, p["ah_b"], B_NODES), p["ah_m"])))
                e.if_(_in(e, _eop(e, p["ah_node"]), CALLS), lambda: (e.var("ah_d", _q(e, "a64_defines", p["ah_q"], p["ah_m"])),
                                                                         e.if_(e.ne(p["ah_d"], NONE), lambda: _set_av(e, V_HINT, p["ah_d"], 0))))

            e.for_("ah_m", 0, _f(e, p["ah_b"], B_NNODES), node)

            def returns():
                e.var("ah_t", _call(e, "a64_treads", p["ah_q"]))
                e.for_("ah_k", 0, p["ah_t"], lambda: (e.var("ah_x", e.ld(e.add(_a(e, A_TBUF), p["ah_k"]))), e.if_(
                    e.eq(_av(e, V_HINT, p["ah_x"]), NONE), lambda: _set_av(e, V_HINT, p["ah_x"], 0))))

            e.if_(e.eq(_f(e, p["ah_b"], B_KIND), RETURN), returns)

        e.for_("ah_q", 0, _g(e, G_BCOUNT), hint_block)
        # The order: weight descending, then start, then (tag, block, index, result).
        e.var("al_order", e.alloc(e.add(niv, 1)))
        _ok(e, e.ne(p["al_order"], NONE))
        e.for_("al_k", 0, niv, lambda: e.st(e.add(p["al_order"], p["al_k"]), e.ld(e.add(_a(e, A_IVLIST), p["al_k"]))))
        first = lambda v: e.ld(_av(e, V_RANGES, v))  # noqa: E731

        def less(a, b):
            wa, wb = _av(e, V_WEIGHT, a), _av(e, V_WEIGHT, b)
            return e.either(e.lt(wb, wa), e.both(e.eq(wa, wb), e.either(e.lt(first(a), first(b)), e.both(e.eq(first(a), first(b)), e.lt(_vf(e, G_VPOS, a), _vf(e, G_VPOS, b))))))

        def insert():
            e.var("ai_item", e.ld(e.add(p["al_order"], p["ai_s"])))
            e.var("ai_j", p["ai_s"])
            e.while_(lambda: e.both(e.lt(0, p["ai_j"]), less(p["ai_item"], e.ld(e.add(p["al_order"], e.sub(p["ai_j"], 1))))), lambda: (
                e.st(e.add(p["al_order"], p["ai_j"]), e.ld(e.add(p["al_order"], e.sub(p["ai_j"], 1)))), e.set("ai_j", e.sub(p["ai_j"], 1))))
            e.st(e.add(p["al_order"], p["ai_j"]), p["ai_item"])

        e.for_("ai_s", 1, niv, insert)
        # Per register its assigned intervals (in assignment order), and each group's register.
        e.var("al_assigned", e.alloc(e.add(e.mul(32, e.add(niv, 1)), 1)))
        e.var("al_count", e.alloc(33))
        e.var("al_group", e.alloc(e.add(p["al_nv"], 1)))
        e.var("al_reserved", e.alloc(33))
        e.var("al_conflict", e.alloc(33))
        for name in ("al_assigned", "al_count", "al_group", "al_reserved", "al_conflict"):
            _ok(e, e.ne(p[name], NONE))
        e.for_("al_r", 0, 32, lambda: (e.st(e.add(p["al_count"], p["al_r"]), 0), e.st(e.add(p["al_reserved"], p["al_r"]), 0)))
        e.for_("al_v", 0, p["al_nv"], lambda: e.st(e.add(p["al_group"], p["al_v"]), NONE))
        e.var("al_slots", 0)
        slot_of = lambda r, k: e.add(p["al_assigned"], e.add(e.mul(r, e.add(niv, 1)), k))  # noqa: E731
        registers = (*CALLER, *CALLEE)

        def allocate():
            e.var("aa_v", e.ld(e.add(p["al_order"], p["aa_k"])))
            v = p["aa_v"]
            find(v, "aa_g")
            e.var("aa_cross", _av(e, V_CROSS, v))
            classes = lambda r: e.either(e.eq(p["aa_cross"], 0), e.le(19, r))  # noqa: E731
            # Conflicts per register (count and weight).
            for r in registers:
                e.st(e.add(p["al_conflict"], r), 0)

            def conflicts(r):
                e.var(f"aa_w{r}", 0)
                e.var(f"aa_n{r}", 0)
                e.for_(f"aa_i{r}", 0, e.ld(e.add(p["al_count"], r)), lambda: (e.var(f"aa_o{r}", e.ld(slot_of(r, p[f"aa_i{r}"]))), e.if_(
                    e.ne(_call(e, "a64_overlaps", p[f"aa_o{r}"], v), 0), lambda: (e.set(f"aa_n{r}", e.add(p[f"aa_n{r}"], 1)),
                                                                                  e.set(f"aa_w{r}", e.add(p[f"aa_w{r}"], _av(e, V_WEIGHT, p[f"aa_o{r}"])))))))
                e.st(e.add(p["al_conflict"], r), p[f"aa_n{r}"])
                e.st(e.add(p["al_conflict"], e.add(r, 0)), p[f"aa_n{r}"])
                return p[f"aa_w{r}"]

            e.var("aa_weights", e.alloc(33))
            _ok(e, e.ne(p["aa_weights"], NONE))
            for r in registers:
                e.st(e.add(p["aa_weights"], r), conflicts(r))
            free = lambda r: e.both(classes(r), e.eq(e.ld(e.add(p["al_conflict"], r)), 0))  # noqa: E731
            e.var("aa_chosen", NONE)

            def prefer(register):
                e.var("pf_r", register)
                e.if_(e.both(e.eq(p["aa_chosen"], NONE), e.ne(p["pf_r"], NONE)), lambda: e.if_(
                    e.both(e.lt(p["pf_r"], 32), e.either(*(e.both(e.eq(p["pf_r"], r), free(r)) for r in registers))), lambda: e.set("aa_chosen", p["pf_r"])))

            prefer(e.ld(e.add(p["al_group"], p["aa_g"])))
            e.for_("aa_pk", 0, _av(e, V_NPART, v), lambda: prefer(_av(e, V_REG, e.ld(e.add(_av(e, V_PARTNERS, v), p["aa_pk"])))))
            prefer(_av(e, V_HINT, v))

            def any_free():
                for r in reversed(registers):
                    e.if_(free(r), lambda r=r: e.set("aa_chosen", r))
                e.var("aa_unreserved", NONE)
                for r in reversed(registers):
                    e.if_(e.both(free(r), e.eq(e.ld(e.add(p["al_reserved"], r)), 0)), lambda r=r: e.set("aa_unreserved", r))
                e.if_(e.ne(p["aa_unreserved"], NONE), lambda: e.set("aa_chosen", p["aa_unreserved"]))

            e.if_(e.eq(p["aa_chosen"], NONE), any_free)

            def spill():
                e.var("aa_best", NONE)
                e.var("aa_best_w", 0)
                for r in registers:
                    e.if_(classes(r), lambda r=r: e.if_(e.either(e.eq(p["aa_best"], NONE), e.lt(e.ld(e.add(p["aa_weights"], r)), p["aa_best_w"])), lambda: (
                        e.set("aa_best", r), e.set("aa_best_w", e.ld(e.add(p["aa_weights"], r))))))

                def evict():
                    e.var("ev_r", p["aa_best"])
                    e.var("ev_kept", 0)

                    def each():
                        e.var("ev_o", e.ld(slot_of(p["ev_r"], p["ev_i"])))

                        def drop():
                            _set_av(e, V_REG, p["ev_o"], NONE)
                            _set_av(e, V_SLOT, p["ev_o"], p["al_slots"])
                            e.set("al_slots", e.add(p["al_slots"], 1))

                        def keep():
                            e.st(slot_of(p["ev_r"], p["ev_kept"]), p["ev_o"])
                            e.set("ev_kept", e.add(p["ev_kept"], 1))

                        e.if_(e.ne(_call(e, "a64_overlaps", p["ev_o"], v), 0), drop, keep)

                    e.for_("ev_i", 0, e.ld(e.add(p["al_count"], p["ev_r"])), each)
                    e.st(e.add(p["al_count"], p["ev_r"]), p["ev_kept"])
                    e.set("aa_chosen", p["ev_r"])

                def slot():
                    _set_av(e, V_SLOT, v, p["al_slots"])
                    e.set("al_slots", e.add(p["al_slots"], 1))

                e.if_(e.lt(p["aa_best_w"], _av(e, V_WEIGHT, v)), evict, slot)

            e.if_(e.eq(p["aa_chosen"], NONE), spill)

            def assign():
                _set_av(e, V_REG, v, p["aa_chosen"])
                e.st(slot_of(p["aa_chosen"], e.ld(e.add(p["al_count"], p["aa_chosen"]))), v)
                e.st(e.add(p["al_count"], p["aa_chosen"]), e.add(e.ld(e.add(p["al_count"], p["aa_chosen"])), 1))

                def group():
                    e.st(e.add(p["al_group"], p["aa_g"]), p["aa_chosen"])
                    e.st(e.add(p["al_reserved"], p["aa_chosen"]), e.add(e.ld(e.add(p["al_reserved"], p["aa_chosen"])), 1))

                e.if_(e.eq(e.ld(e.add(p["al_group"], p["aa_g"])), NONE), group)

            e.if_(e.ne(p["aa_chosen"], NONE), assign)

        e.for_("aa_k", 0, niv, allocate)
        _set_a(e, A_SPILLS, p["al_slots"])
        e.give(1)
    return _function((), build, tables)


def _write_allocation(tables):
    """The audit record of the allocation (tests): per interval (creation order) its value, weight, whether it
    crosses a call, its ranges, register (or NONE) and slot (or NONE); then the spill slot count."""
    from xax_selfhost_general_view import _out_value

    def build(e: E):
        p = e.p

        def each():
            e.var("wl_v", e.ld(e.add(_a(e, A_IVLIST), p["wl_k"])))
            _out_value(e, p["wl_v"])
            for table in (V_WEIGHT, V_CROSS, V_NRANGES):
                _out(e, _av(e, table, p["wl_v"]))
            e.for_("wl_r", 0, e.mul(_av(e, V_NRANGES, p["wl_v"]), 2), lambda: _out(e, e.ld(e.add(_av(e, V_RANGES, p["wl_v"]), p["wl_r"]))))
            _out(e, _av(e, V_REG, p["wl_v"]))
            _out(e, _av(e, V_SLOT, p["wl_v"]))

        _out(e, _a(e, A_NIV))
        e.for_("wl_k", 0, _a(e, A_NIV), each)
        _out(e, _a(e, A_SPILLS))
        e.give(1)
    return _function((), build, tables)


# -- the view, then the lowering --------------------------------------------------------------------------------

def _view(tables):
    """``inline_leaf_calls`` of function ``f`` (image index ``fidx``), then ``compile_linux_function``."""
    from xax_selfhost_general_view import B_NODES as _B_NODES, N_NRES as _N_NRES

    def build(e: E):
        p = e.p
        _globals(e, G_VCOUNT, 0)
        _globals(e, G_FKEYN, 0)
        e.var("vw_blocks", _call(e, "lift", p["f"], p["fidx"]))
        e.var("vw_graph", e.ld(_call(e, "interface", p["f"])))
        e.var("vw_n", e.rd(_at(e, G_PAY, p["vw_graph"])))
        _globals(e, G_BENTRY, _g(e, G_LIFT_ENTRY))
        e.var("vw_list", e.alloc(e.add(p["vw_n"], 1)))
        _ok(e, e.ne(p["vw_list"], NONE))
        e.for_("vw_q", 0, p["vw_n"], lambda: e.st(e.add(p["vw_list"], p["vw_q"]), e.ld(e.add(p["vw_blocks"], p["vw_q"]))))
        _globals(e, G_BLIST, p["vw_list"])
        _globals(e, G_BCOUNT, p["vw_n"])

        # ``_compile_function`` proves every atomic node's capability first: an atomic node declines here.
        def atomics():
            from xax_compiler import ATOMIC_OPERATIONS

            e.var("vw_b", e.ld(e.add(p["vw_blocks"], p["vw_q"])))
            e.for_("vw_m", 0, _f(e, p["vw_b"], B_NNODES), lambda: _ok(e, e.not_(_in(
                e, _eop(e, e.ld(e.add(_f(e, p["vw_b"], _B_NODES), p["vw_m"]))), tuple(int(op) for op in ATOMIC_OPERATIONS)))))

        e.for_("vw_q", 0, p["vw_n"], atomics)
        e.var("vw_any", 0)

        def scan():
            e.var("vw_b", e.ld(e.add(p["vw_blocks"], p["vw_q"])))

            def node():
                e.var("vw_node", e.ld(e.add(_f(e, p["vw_b"], _B_NODES), p["vw_m"])))
                e.var("vw_c", _call(e, "node_callee", p["vw_node"]))
                e.if_(e.ne(p["vw_c"], NOT_CALL), lambda: e.if_(e.ne(_call(e, "candidate", p["vw_c"], _f(e, p["vw_node"], _N_NRES)), 0),
                                                            lambda: e.set("vw_any", 1)))

            e.for_("vw_m", 0, _f(e, p["vw_b"], B_NNODES), node)

        e.for_("vw_q", 0, p["vw_n"], scan)

        def inline():
            e.var("vw_go", 1)

            def once():
                e.set("vw_go", 0)
                e.var("vw_q", 0)
                e.var("vw_count", _g(e, G_BCOUNT))
                e.var("vw_snapshot", _g(e, G_BLIST))

                def block():
                    e.var("vw_b", e.ld(e.add(p["vw_snapshot"], p["vw_q"])))
                    e.var("vw_m", 0)

                    def node():
                        e.var("vw_node", e.ld(e.add(_f(e, p["vw_b"], _B_NODES), p["vw_m"])))
                        e.var("vw_c", _call(e, "node_callee", p["vw_node"]))

                        def check():
                            e.if_(e.ne(_call(e, "candidate", p["vw_c"], _f(e, p["vw_node"], _N_NRES)), 0), lambda: (
                                _call(e, "splice", p["vw_b"], p["vw_m"], p["vw_c"]), e.set("vw_go", 1)))

                        e.if_(e.ne(p["vw_c"], NOT_CALL), check)
                        e.set("vw_m", e.add(p["vw_m"], 1))

                    e.while_(lambda: e.both(e.eq(p["vw_go"], 0), e.lt(p["vw_m"], B_NNODES_of(e, p["vw_b"]))), node)
                    e.set("vw_q", e.add(p["vw_q"], 1))

                e.while_(lambda: e.both(e.eq(p["vw_go"], 0), e.lt(p["vw_q"], p["vw_count"])), block)

            e.while_(lambda: e.ne(p["vw_go"], 0), once)
            _simplify(e, True)

        e.if_(e.ne(p["vw_any"], 0), inline, lambda: _simplify(e, False))
        _call(e, "layout")
        _call(e, "positions")
        # ``compile_linux_function`` returns None for an ineligible view: S15e.2b (ADR-316), the frame path from the
        # function's own graph (or the legacy register path, which declines).  Eligibility reads types only.
        e.var("vw_status", A_DECLINED)
        e.if_(e.ne(_call(e, "a64_eligible", p["f"]), 0), lambda: e.set("vw_status", A_LOWERED))
        e.if_(e.eq(p["vw_status"], A_DECLINED), lambda: (_call(e, "a64f_function", p["f"], p["fidx"]), _call(e, "a64_image_add", p["fidx"]), e.give(1)))
        _ok(e, e.ne(e.call(_FN["value_facts"]), NONE))  # a value wider than 64 bits or a float constant: declined
        _out(e, p["fidx"])
        _call(e, "lower")
        _out(e, p["vw_status"])
        for k, stage in enumerate(("a64_aliases", "a64_uses", "a64_tables", "a64_loops", "a64_patterns")):
            e.st(TRACE_AT, 10 + k)
            _call(e, stage)
        e.if_(e.ne(_g(e, G_AUDIT), 0), lambda: _call(e, "a64_write_analysis"))
        _set_a(e, A_FN, p["f"])
        _set_a(e, A_IFACE, _call(e, "interface", p["f"]))
        _set_a(e, A_OWNB, _call(e, "borrowed", p["f"]))
        e.st(TRACE_AT, 20)
        _call(e, "a64_plan")
        e.st(TRACE_AT, 21)
        e.if_(e.ne(_g(e, G_AUDIT), 0), lambda: _call(e, "a64_write_plan"))
        for k, stage in enumerate(("a64_liveness", "a64_intervals", "a64_allocate")):
            e.st(TRACE_AT, 30 + k)
            _call(e, stage)
        e.st(TRACE_AT, 40)
        e.if_(e.ne(_g(e, G_AUDIT), 0), lambda: _call(e, "a64_write_allocation"))
        e.st(TRACE_AT, 50)
        _call(e, "x_function")
        e.st(TRACE_AT, 60)
        e.if_(e.ne(_g(e, G_AUDIT), 0), lambda: _call(e, "x_write"))
        _call(e, "a64_image_add", p["fidx"])
        e.give(1)
    return _function(("f", "fidx"), build, tables)


def B_NNODES_of(e: E, block):
    return _f(e, block, B_NNODES)


def add_lower_functions(add, tables):
    """Add the view, the range analysis, and the AArch64 lowering to the program under construction."""
    from xax_selfhost_general_ranges import add_range_functions
    from xax_selfhost_general_view import (
        _candidate, _dead, _distance, _fold, _layout, _lift, _locals, _lower, _merge, _node_callee, _positions, _replace_uses,
        _resolve, _splice, _stores, _thread, _unpack,
    )
    for name, builder in (("lift", _lift), ("resolve", _resolve), ("replace_uses", _replace_uses), ("node_callee", _node_callee),
                          ("candidate", _candidate), ("splice", _splice), ("merge", _merge), ("thread", _thread), ("unpack", _unpack),
                          ("fold", _fold), ("stores", _stores), ("locals", _locals), ("dead", _dead), ("distance", _distance),
                          ("layout", _layout), ("positions", _positions), ("lower", _lower)):
        add(name, builder(tables))
    add_range_functions(add, tables)
    add("a64_call_elided", _call_elided(tables))
    add("a64_eligible", _eligible(tables))
    from xax_selfhost_general_regalloc import _predicate_table

    add("predicate_table", _predicate_table(tables))
    add("a64_aliases", _aliases(tables))
    add("a64_uses", _uses(tables))
    add("a64_tables", _tables(tables))
    add("a64_loops", _loops(tables))
    add("a64_membership", _membership(tables))
    add("a64_patterns", _patterns(tables))
    add("a64_write_analysis", _write_analysis(tables))
    for name, builder in (("a64_addsub", _addsub_fn), ("a64_logical", _logical_fn), ("a64_movlen", _movlen_fn), ("a64_folds", _folds_fn),
                          ("a64_proven", _proven_fn), ("a64_scaled", _scaled_fn), ("a64_located", _located_fn), ("a64_reads", _reads_fn),
                          ("a64_defines", _defines_fn), ("a64_treads", _treads_fn), ("a64_plan", _plan_fn), ("a64_write_plan", _write_plan),
                          ("a64_liveness", _liveness_fn), ("a64_normalize", _normalize_fn), ("a64_intervals", _intervals_fn),
                          ("a64_overlaps", _overlaps_fn), ("a64_allocate", _allocate_fn), ("a64_write_allocation", _write_allocation)):
        add(name, builder(tables))
    from xax_selfhost_aarch64_emit import add_emit_functions

    add_emit_functions(add, tables)
    from xax_selfhost_aarch64_image import add_image_functions

    add_image_functions(add, tables)
    from xax_selfhost_aarch64_frame import add_frame_functions

    add_frame_functions(add, tables)
    add("a64_view", _view(tables))


def lower_closure(e: E, total, order, members):
    """After the front end: the view tables, the extents section, and every closure function lowered in image order."""
    from xax_selfhost_general_ranges import ranges_prologue

    p = e.p
    for slot in (G_VEXT, G_VTYPE, G_VPROD, G_VREAD, G_VMULTI, G_VFWD, G_VPARAM, G_VSTAMP, G_VSTAMP2, G_VPOS):
        table = e.alloc(VCAP + 1)
        _ok(e, e.ne(table, NONE))
        _globals(e, slot, table)
    keys = e.alloc(VCAP + 2)
    _ok(e, e.ne(keys, NONE))
    _globals(e, G_FKEYS, keys)
    for slot in (G_GEXT, G_CIDX, G_CAND):
        table = e.alloc(e.add(total, 2))
        _ok(e, e.ne(table, NONE))
        _globals(e, slot, table)
        e.for_("vp_o", 0, total, lambda table=table: e.st(e.add(table, p["vp_o"]), NONE))
    _globals(e, G_STAMP, 1)
    e.for_("vp_q", 0, members, lambda: e.st(e.add(_g(e, G_CIDX), e.ld(e.add(order, p["vp_q"]))), p["vp_q"]))
    e.var("vp_at", p["ext_at"])
    e.var("vp_n", e.rd(p["vp_at"]))
    e.set("vp_at", e.add(p["vp_at"], 1))

    def graph():
        e.var("vp_g", e.call(_FN["find"], p["vp_at"]))
        e.set("vp_at", e.add(p["vp_at"], CID_WORDS))
        e.if_(e.ne(p["vp_g"], NONE), lambda: e.st(e.add(_g(e, G_GEXT), p["vp_g"]), p["vp_at"]))
        e.set("vp_at", e.add(e.add(p["vp_at"], 1), e.mul(e.rd(p["vp_at"]), 5)))

    e.for_("vp_k", 0, p["vp_n"], graph)
    _globals(e, G_AUDIT, e.rd(p["vp_at"]))
    e.var("vp_traps", e.add(p["vp_at"], 1))
    _globals(e, G_VIEW_OUT, VIEW_AT)
    ranges_prologue(e)
    from xax_selfhost_general_regalloc import regalloc_prologue

    regalloc_prologue(e)  # the per-value tables the shared predicate-table analysis reads (``T_RW``, ``T_EARLY``, ...)
    more = e.alloc(A64_WORDS)
    _ok(e, e.ne(more, NONE))
    _globals(e, G_A64, more)
    for table in range(VALUE_TABLES):
        t = e.alloc(VCAP + 1)
        _ok(e, e.ne(t, NONE))
        _set_a(e, table, t)
    _set_a(e, A_TRAPSEC, p["vp_traps"])
    from xax_selfhost_aarch64_emit import emit_prologue

    emit_prologue(e)
    from xax_selfhost_aarch64_image import image_after_views, image_prologue

    image_prologue(e)

    def each():
        e.var("vp_mark", e.hd(H_ARENA))
        _call(e, "a64_view", e.ld(e.add(order, p["vp_q"])), p["vp_q"])
        e.set_hd(H_ARENA, p["vp_mark"])

    e.for_("vp_q", 0, members, each)
    image_after_views(e, members)
    e.st(0, 1)
