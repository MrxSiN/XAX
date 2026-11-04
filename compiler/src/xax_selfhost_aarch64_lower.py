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

from xax_compiler import Operation, RESOURCE_EFFECT_OPERATIONS
from xax_selfhost_facts import E, H_ARENA, NONE, _function
from xax_selfhost_general_view import (
    B_NNODES, G_AUDIT, G_BCOUNT, G_BENTRY, G_BLIST, G_FKEYN, G_LIFT_ENTRY, G_VCOUNT, G_VPOS, G_VPROD, N_ATTR, N_NOPS, NOT_CALL, _f, _globals, _operand, _out, _simplify, _vf)
from xax_selfhost_general_regalloc import _eop  # a group-member call is the direct call the bootstrap's graph shows
from xax_selfhost_views_backend import _FN, G_PAY, _at, _call, _g, _ok

A_DECLINED, A_LOWERED = 0, 1
TRACE_AT = 2  # output word: the last stage the lowering began (development and decline diagnosis)
G_A64 = 61  # the AArch64 lowering's globals table (``_a``)
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
LR = 30

RESOURCE = tuple(sorted(int(op) for op in RESOURCE_EFFECT_OPERATIONS))
CALLS = (int(Operation.CALL_DIRECT), int(Operation.CALL_FOREIGN))
MEMORY = tuple(int(op) for op in (Operation.LOAD_BITS_LE, Operation.RAW_LOAD_BITS_LE, Operation.STORE_BITS_LE, Operation.CHECKED_LOAD_BITS_LE,
                                  Operation.CHECKED_STORE_BITS_LE))
NOT_MACHINE, WIDE = 0, NONE  # ``_machine_width``: a proof value; anything but bits<=64 or a pointer (the bootstrap's False)


# -- accessors ------------------------------------------------------------------------------------------------

def _a(e: E, slot: int):
    return e.ld(e.add(_g(e, G_A64), slot))


def _set_a(e: E, slot: int, value):
    e.st(e.add(_g(e, G_A64), slot), value)


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


# -- eligibility (``_Lowering.eligible``) ------------------------------------------------------------------------


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


def _power(e: E, k):
    """``2 ** k`` for ``0 <= k < 64`` (the range analysis's table of powers)."""
    from xax_selfhost_general_ranges import G2_SCRATCH, _g2

    return e.ld(e.add(_g2(e, G2_SCRATCH), k))


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


# -- per-node plans and the plan (``_Lowering.reads`` ... ``_plan``) ------------------------------------------------

STORES = (int(Operation.STORE_BITS_LE), int(Operation.CHECKED_STORE_BITS_LE))


# -- liveness, intervals, allocation (``_liveness``, ``_intervals``, ``_allocate``) -------------------------------


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
        # S15f.4 (ADR-325): a bare-metal image has no function-wide register allocation (``compile_linux_function`` is
        # the Linux and Android profiles'): the frame path or the legacy register path from the function's own graph.
        # S15e.6h.1 (ADR-354): so has an Android profile outside ``ANDROID_ARM64_GENERAL_IDENTITIES`` (``G_A64ANDROID`` 1).
        from xax_selfhost_aarch64_frame import G_A64ANDROID, G_A64RAW
        from xax_selfhost_views_backend import GLOBALS

        e.if_(e.either(e.ne(e.ld(GLOBALS + G_A64RAW), 0), e.eq(e.ld(GLOBALS + G_A64ANDROID), 1)),
              lambda: (_call(e, "a64f_function", p["f"], p["fidx"]), _call(e, "a64_image_add", p["fidx"]), e.give(1)))
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

        # ``compile_linux_function`` builds the lowering view (``inline_leaf_calls``) only for the Linux ABI; an Android
        # profile (S15e.6h.1, ADR-354) lowers the function's graph as parsed.
        e.if_(e.eq(e.ld(GLOBALS + G_A64ANDROID), 0), lambda: (e.if_(e.ne(p["vw_any"], 0), inline, lambda: _simplify(e, False)), _call(e, "layout")))
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


