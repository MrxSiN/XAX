"""Self-hosting step S12c.1 (ADR-270): value ranges and next-iteration prefetch selection as XAX semantics.

``xax_ranges.upper_bounds`` bounds integer SSA values (constants, ``udiv`` by a constant, ``add``, ``and``, ``mul``
by a constant, width changes, compares; block parameters by a widening-then-narrowing fixed point over their incoming
edges, refined by the unsigned compare that selects an edge).  ``xax_prefetch.prefetch_next_iteration`` uses it to
append, to a loop body that starts a dependent walk, the next iteration's head load, and marks that load's result
with the inner walk's arrays to prefetch.  Both run on a function's lowering view.

These builders add both to the S12 general backend program (``xax_x86_64_general.xax``).  They work on the view's
arena records after layout (``xax_selfhost_general_view``): blocks in list order are the view's positions, values
are dense ids with positions (``G_VPOS``).  Ranges are computed for a *width table* (``G2_WIDTHS``: a value's width,
0 when it has none), because the prefetch (bits-typed values) and the register lowering (machine values) bound
different value sets.  A bound is a 64-bit word; ``maximum`` reports "no bound" through ``G2_RNONE``.  ``maximum``
recurses to depth 8 in the bootstrap; here each depth is its own function (no recursion), and only depth 0 is
cached, per round, as in the bootstrap.

A function the program cannot bound exactly (a ``bits<N>`` above 64, a float constant, a pointer extent the view does
not prove) is declined as a whole and keeps the bootstrap's prefetch selection.
"""

from __future__ import annotations

from xax_compiler import IntCompare, Kind, Operation
from xax_selfhost_facts import E, NONE, _function
from xax_selfhost_general_view import (
    B_BB, B_EDGES, B_INPUTS, B_KIND, B_NEDGES, B_NODES, B_NNODES, B_NP, B_NVALUES, B_POS, B_VALUES, BRANCH, CONDITIONAL, EDGE, G_BCOUNT,
    G_BLIST, G_BENTRY, G_VCOUNT, G_VPARAM, G_VPOS, G_VPROD, G_VTYPE, N_ATTR, N_GRAPH, N_HDR, N_NOPS, N_NRES, N_OP, N_OPSAT, NOT_CALL,
    POS_BLOCK, POS_INDEX, POS_TAG, _bits_width, _f, _globals, _new_value, _operand, _output, _set, _set_vf, _vf,
)
from xax_selfhost_views_backend import (
    _FN, G_PAY, GLOBALS, _at, _call, _g, _kind, _ok, _payload_uleb, _reference, _type_form, _view_extent,
)

G_MORE = 58  # pointer to the second globals table (``_g2``)
MORE_WORDS = 256
# Second globals.
(G2_WIDTHS, G2_CONST, G2_CVAL, G2_RNONE, G2_PBOUND, G2_ISPARAM, G2_CACHE, G2_CSTAMP, G2_ROUND, G2_MARKS, G2_NMARKS, G2_WBITS,
 G2_EXPR, G2_RECOMP, G2_COPY, G2_BODYSET, G2_SCRATCH) = range(17)
# S15e.2 (ADR-315): ``upper_bounds(..., bitwise=True)`` bounds ``or``/``xor`` too (the AArch64 lowering); 0 on x86-64.
G2_BITWISE = 17
DEPTH = 8  # ``_maximum`` follows nodes up to depth 8
SCALES = (1, 2, 4, 8)
PREFETCH_PURE = tuple(int(op) for op in (
    Operation.ADD_WRAP, Operation.SUB_WRAP, Operation.MUL_WRAP, Operation.BIT_XOR, Operation.BIT_AND, Operation.BIT_OR,
    Operation.UDIV, Operation.UREM, Operation.INT_TRUNCATE, Operation.INT_ZERO_EXTEND, Operation.ROTATE_RIGHT,
))
# ``_UPPER``: (compare kind, taken edge) -> relation of the left operand to the right.
LT, LE, GT, GE, EQ = range(1, 6)
UPPER = {
    (IntCompare.ULT, True): LT, (IntCompare.UGE, False): LT, (IntCompare.ULE, True): LE, (IntCompare.UGT, False): LE,
    (IntCompare.UGT, True): GT, (IntCompare.ULE, False): GT, (IntCompare.UGE, True): GE, (IntCompare.ULT, False): GE,
    (IntCompare.EQ, True): EQ, (IntCompare.NE, False): EQ,
}
SWAP = {LT: GT, LE: GE, GT: LT, GE: LE, EQ: EQ}
ALL = (1 << 64) - 1
SCRATCH_DONE = 70  # ``G2_SCRATCH``: powers of two at 0..63, then flags
MARK_WORDS = 3  # a prefetch mark: the appended load's result, its (pointer, scale) list, the list's length


def _g2(e: E, slot: int):
    return e.ld(e.add(_g(e, G_MORE), slot))


def _set_g2(e: E, slot: int, value):
    e.st(e.add(_g(e, G_MORE), slot), value)


def _t(e: E, slot: int, value):
    """Entry ``value`` of the per-value table in second-globals ``slot``."""
    return e.ld(e.add(_g2(e, slot), value))


def _set_t(e: E, slot: int, value, word):
    e.st(e.add(_g2(e, slot), value), word)


def _limit(e: E, width):
    """``(1 << width) - 1`` for ``1 <= width <= 64``."""
    return e.sel(e.eq(width, 64), ALL, e.sub(e.ld(e.add(_g2(e, G2_SCRATCH), width)), 1))


def _pos_block(e: E, value):
    return e.and_(e.udiv(_vf(e, G_VPOS, value), POS_BLOCK), (1 << 22) - 1)


def _pos_index(e: E, value):
    return e.and_(e.udiv(_vf(e, G_VPOS, value), POS_INDEX), (1 << 24) - 1)


def _pos_result(e: E, value):
    return e.and_(_vf(e, G_VPOS, value), (1 << 16) - 1)


def _is_param(e: E, value):
    return e.ne(_vf(e, G_VPARAM, value), NONE)


def _block_at(e: E, index):
    return e.ld(e.add(_g(e, G_BLIST), index))


def _node_at(e: E, block, index):
    return e.ld(e.add(_f(e, block, B_NODES), index))


def _attribute(e: E, node, k: int):
    return e.rd(e.add(_f(e, node, N_ATTR), 1 + k))


# -- per-value facts: constants and widths ----------------------------------------------------------------

def _clear_stamps(e: E, value):
    """Clear ``value``'s stamp words (cache, expression, copy, and recomputation marks): stamps are compared with
    rounds that restart in every run, and the output view is reused between runs."""
    from xax_selfhost_general_view import VCAP

    for slot, offset in ((G2_CSTAMP, 0), (G2_EXPR, 0), (G2_COPY, VCAP), (G2_RECOMP, VCAP)):
        e.st(e.add(e.add(_g2(e, slot), offset), value), 0)


def _value_facts(tables):
    """Constants (``G2_CONST``/``G2_CVAL``) and bits widths (``G2_WBITS``: ``decode_bits_width``, 0 when not bits) of
    every value; NONE (decline) for a value of the final view wider than 64 bits or a float constant in it (the
    prefetch bounds those as Python numbers).  S12f.4 (ADR-280): such a value the simplifications removed (``G_VPOS``
    NONE: not in the final view) is ignored, so a dead one leaves the function on the register-resident path."""
    def build(e: E):
        p = e.p
        n = _g(e, G_VCOUNT)
        e.var("vf_n", n)

        def each():
            v = p["vf_v"]
            e.var("vf_w", _bits_width(e, _vf(e, G_VTYPE, v)))
            e.var("vf_live", e.flag(e.ne(_vf(e, G_VPOS, v), NONE)))
            e.if_(e.lt(64, p["vf_w"]), lambda: (_ok(e, e.eq(p["vf_live"], 0)), e.set("vf_w", 0)))
            _set_t(e, G2_WBITS, v, p["vf_w"])
            _set_t(e, G2_CONST, v, 0)
            _clear_stamps(e, v)
            e.var("vf_node", _vf(e, G_VPROD, v))

            def constant():
                node = p["vf_node"]
                obj = _reference(e, _f(e, node, N_GRAPH), e.rd(e.sub(_f(e, node, N_OPSAT), 1)))
                e.var("vf_obj", obj)
                _ok(e, e.both(e.ne(p["vf_obj"], NONE), e.eq(_kind(e, p["vf_obj"]), int(Kind.CONSTANT))))
                e.var("vf_at", _at(e, G_PAY, p["vf_obj"]))
                type_obj = _reference(e, p["vf_obj"], _payload_uleb(e, "vf_at"))
                e.var("vf_form", _type_form(e, type_obj))
                e.var("vf_len", _payload_uleb(e, "vf_at"))

                def known():
                    _ok(e, e.le(p["vf_len"], 8))
                    e.var("vf_value", 0)
                    e.var("vf_weight", 1)
                    e.for_("vf_k", 0, p["vf_len"], lambda: (e.set("vf_value", e.add(p["vf_value"], e.mul(e.rd(e.add(p["vf_at"], p["vf_k"])), p["vf_weight"]))),
                                                            e.set("vf_weight", e.mul(p["vf_weight"], 256))))
                    _set_t(e, G2_CONST, v, 1)
                    _set_t(e, G2_CVAL, v, p["vf_value"])

                bits_or_link = e.either(e.eq(p["vf_form"], 1), e.eq(p["vf_form"], 11))
                e.if_(e.not_(bits_or_link), lambda: _ok(e, e.eq(p["vf_live"], 0)))  # a live float constant declines
                # A removed wide constant is no constant (it has no width here either).
                e.if_(e.both(bits_or_link, e.either(e.eq(p["vf_form"], 11), e.ne(p["vf_w"], 0))), known)

            e.if_(e.both(e.ne(p["vf_node"], NONE), e.eq(_f(e, e.sel(e.ne(p["vf_node"], NONE), p["vf_node"], 0), N_OP), int(Operation.CONSTANT))), constant)

        e.for_("vf_v", 0, p["vf_n"], each)
        e.give(1)
    return _function((), build, tables)


# -- upper bounds -------------------------------------------------------------------------------------------

def _maximum(tables, depth: int):
    """``maximum(value, depth)``: the bound of ``v``, with ``G2_RNONE`` = 1 for "no bound".  Depth 0 is cached per
    round (``G2_ROUND``): the bound in ``G2_CACHE[v]``, its none flag in ``G2_CACHE[v + VCAP]``."""
    from xax_selfhost_general_view import VCAP

    def build(e: E):
        p = e.p
        v = p["v"]
        e.var("mx_out", 0)
        e.var("mx_none", 0)
        e.var("mx_done", 0)

        def finish(value, none=0):
            e.set("mx_out", value)
            e.set("mx_none", none)
            e.set("mx_done", 1)

        if depth == 0:
            def hit():
                e.set("mx_out", _t(e, G2_CACHE, v))
                e.set("mx_none", e.ld(e.add(_g2(e, G2_CACHE), e.add(v, VCAP))))
                e.set("mx_done", 1)

            e.if_(e.eq(_t(e, G2_CSTAMP, v), _g2(e, G2_ROUND)), hit)
            e.var("mx_cached", p["mx_done"])

        def compute():
            e.if_(e.ne(_t(e, G2_CONST, v), 0), lambda: finish(_t(e, G2_CVAL, v)))

            def typed():
                e.var("mx_w", _t(e, G2_WIDTHS, v))
                e.if_(e.eq(p["mx_w"], 0), lambda: finish(0, 1))

                def bounded():
                    e.var("mx_limit", _limit(e, p["mx_w"]))

                    def parameter():
                        e.var("mx_pb", _t(e, G2_PBOUND, v))
                        finish(e.sel(e.both(e.ne(_t(e, G2_ISPARAM, v), 0), e.lt(p["mx_pb"], p["mx_limit"])), p["mx_pb"], p["mx_limit"]))

                    def produced():
                        e.if_(e.ne(_pos_result(e, v), 0), lambda: finish(p["mx_limit"]))
                        if depth > DEPTH:
                            e.if_(e.eq(p["mx_done"], 0), lambda: finish(p["mx_limit"]))
                            return

                        def node():
                            e.var("mx_node", _vf(e, G_VPROD, v))
                            n = p["mx_node"]
                            e.var("mx_op", _f(e, n, N_OP))
                            op = p["mx_op"]

                            def sub(value, name):
                                """``maximum(value, depth + 1)`` into ``name`` (and ``name_none``)."""
                                e.var(name, e.call(_FN[f"maximum{depth + 1}"], value))
                                e.var(f"{name}_none", _g2(e, G2_RNONE))

                            def operand_constant(k):
                                return _t(e, G2_CONST, _operand(e, n, k))

                            def operand_value(k):
                                return _t(e, G2_CVAL, _operand(e, n, k))

                            def udiv():
                                sub(_operand(e, n, 0), "mx_a")
                                e.var("mx_c", operand_value(1))
                                finish(e.udiv(e.sel(e.ne(p["mx_a_none"], 0), p["mx_limit"], p["mx_a"]), p["mx_c"]))

                            def add():
                                sub(_operand(e, n, 0), "mx_a")
                                sub(_operand(e, n, 1), "mx_b")
                                none = e.either(e.ne(p["mx_a_none"], 0), e.ne(p["mx_b_none"], 0))
                                # sum > limit, without overflow: b > limit, or a > limit - b
                                over = e.either(e.lt(p["mx_limit"], p["mx_b"]), e.lt(e.sub(p["mx_limit"], p["mx_b"]), p["mx_a"]))
                                finish(e.sel(e.either(none, over), p["mx_limit"], e.add(p["mx_a"], p["mx_b"])))

                            def and_():
                                sub(_operand(e, n, 0), "mx_a")
                                sub(_operand(e, n, 1), "mx_b")
                                a_ok, b_ok = e.eq(p["mx_a_none"], 0), e.eq(p["mx_b_none"], 0)
                                smaller = e.sel(e.lt(p["mx_a"], p["mx_b"]), p["mx_a"], p["mx_b"])
                                finish(e.sel(e.both(a_ok, b_ok), smaller, e.sel(a_ok, p["mx_a"], e.sel(b_ok, p["mx_b"], p["mx_limit"]))))

                            def bitwise():
                                """``min(limit, (1 << max(bounds).bit_length()) - 1)`` (ADR-168)."""
                                sub(_operand(e, n, 0), "mx_a")
                                sub(_operand(e, n, 1), "mx_b")
                                e.var("mx_ones", 0)
                                e.var("mx_top", e.sel(e.lt(p["mx_a"], p["mx_b"]), p["mx_b"], p["mx_a"]))
                                e.while_(lambda: e.lt(p["mx_ones"], p["mx_top"]), lambda: e.set("mx_ones", e.add(e.mul(p["mx_ones"], 2), 1)))
                                none = e.either(e.ne(p["mx_a_none"], 0), e.ne(p["mx_b_none"], 0))
                                finish(e.sel(e.either(none, e.lt(p["mx_limit"], p["mx_ones"])), p["mx_limit"], p["mx_ones"]))

                            def mul():
                                sub(_operand(e, n, 0), "mx_a")
                                e.var("mx_c", operand_value(1))
                                c = p["mx_c"]
                                over = e.both(e.ne(c, 0), e.lt(e.udiv(p["mx_limit"], e.sel(e.eq(c, 0), 1, c)), p["mx_a"]))
                                finish(e.sel(e.either(e.ne(p["mx_a_none"], 0), over), p["mx_limit"], e.mul(p["mx_a"], c)))

                            def width_change():
                                sub(_operand(e, n, 0), "mx_a")
                                smaller = e.sel(e.lt(p["mx_a"], p["mx_limit"]), p["mx_a"], p["mx_limit"])
                                finish(e.sel(e.ne(p["mx_a_none"], 0), p["mx_limit"], smaller))

                            divide = e.both(e.eq(op, int(Operation.UDIV)), e.ne(operand_constant(1), 0), e.ne(operand_value(1), 0))
                            multiply = e.both(e.eq(op, int(Operation.MUL_WRAP)), e.ne(operand_constant(1), 0))
                            e.if_(divide, udiv, lambda: e.if_(e.eq(op, int(Operation.ADD_WRAP)), add, lambda: e.if_(
                                e.eq(op, int(Operation.BIT_AND)), and_, lambda: e.if_(e.both(
                                    e.ne(_g2(e, G2_BITWISE), 0), e.either(e.eq(op, int(Operation.BIT_OR)), e.eq(op, int(Operation.BIT_XOR)))), bitwise,
                                    lambda: e.if_(multiply, mul, lambda: e.if_(
                                    e.either(e.eq(op, int(Operation.INT_TRUNCATE)), e.eq(op, int(Operation.INT_ZERO_EXTEND))), width_change,
                                    lambda: e.if_(e.eq(op, int(Operation.INT_COMPARE)), lambda: finish(1), lambda: finish(p["mx_limit"]))))))))

                        e.if_(e.eq(p["mx_done"], 0), node)

                    e.if_(_is_param(e, v), parameter, produced)

                e.if_(e.eq(p["mx_done"], 0), bounded)

            e.if_(e.eq(p["mx_done"], 0), typed)

        e.if_(e.eq(p["mx_done"], 0), compute)
        if depth == 0:
            def remember():
                _set_t(e, G2_CSTAMP, v, _g2(e, G2_ROUND))
                _set_t(e, G2_CACHE, v, p["mx_out"])
                e.st(e.add(_g2(e, G2_CACHE), e.add(v, VCAP)), p["mx_none"])

            e.if_(e.eq(p["mx_cached"], 0), remember)
        _set_g2(e, G2_RNONE, p["mx_none"])
        e.give(p["mx_out"])
    return _function(("v",), build, tables)


def _edge_bound(tables):
    """``edge_bound(source block, edge index, argument)``: the argument's bound refined by the source's unsigned
    branch compare; ``G2_RNONE`` for none."""
    def build(e: E):
        p = e.p
        e.var("eb_b", e.call(_FN["maximum0"], p["arg"]))
        e.var("eb_none", _g2(e, G2_RNONE))
        e.if_(e.ne(p["eb_none"], 0), lambda: (_set_g2(e, G2_RNONE, 1), e.give(0)))
        e.var("eb_src", _block_at(e, p["src"]))
        src = p["eb_src"]
        e.var("eb_out", p["eb_b"])

        def conditional():
            e.var("eb_cond", e.ld(_f(e, src, B_VALUES)))
            cond = p["eb_cond"]
            local = e.both(e.not_(_is_param(e, cond)), e.eq(_pos_block(e, cond), p["src"]), e.eq(_pos_result(e, cond), 0))

            def compare():
                e.var("eb_cmp", _vf(e, G_VPROD, cond))
                cmp = p["eb_cmp"]

                def relation():
                    e.var("eb_kind", _attribute(e, cmp, 0))
                    e.var("eb_rel", 0)
                    taken = e.eq(p["edge"], 0)
                    for (kind, is_taken), rel in UPPER.items():
                        e.if_(e.both(e.eq(p["eb_kind"], int(kind)), taken if is_taken else e.not_(taken)), lambda rel=rel: e.set("eb_rel", rel))
                    e.var("eb_left", _operand(e, cmp, 0))
                    e.var("eb_right", _operand(e, cmp, 1))
                    is_left, is_right = e.eq(p["arg"], p["eb_left"]), e.eq(p["arg"], p["eb_right"])

                    def refine():
                        def swap():
                            for rel, other in SWAP.items():
                                e.if_(e.eq(p["eb_rel0"], rel), lambda other=other: e.set("eb_rel", other))

                        e.var("eb_rel0", p["eb_rel"])
                        e.if_(is_right, swap)  # ``if argument == right``, whether or not it is also the left operand
                        e.var("eb_other", e.call(_FN["maximum0"], e.sel(is_left, p["eb_right"], p["eb_left"])))
                        e.var("eb_onone", _g2(e, G2_RNONE))

                        def tighten():
                            rel = p["eb_rel"]
                            other = p["eb_other"]
                            lower = e.sel(e.lt(p["eb_out"], e.sub(other, 1)), p["eb_out"], e.sub(other, 1))
                            e.if_(e.both(e.eq(rel, LT), e.ne(other, 0)), lambda: e.set("eb_out", lower))
                            capped = e.sel(e.lt(p["eb_out"], other), p["eb_out"], other)
                            e.if_(e.either(e.eq(rel, LE), e.eq(rel, EQ)), lambda: e.set("eb_out", capped))

                        e.if_(e.eq(p["eb_onone"], 0), tighten)

                    e.if_(e.both(e.ne(p["eb_rel"], 0), e.either(is_left, is_right)), refine)

                e.if_(e.eq(_f(e, cmp, N_OP), int(Operation.INT_COMPARE)), relation)

            e.if_(local, compare)

        e.if_(e.eq(_f(e, src, B_KIND), CONDITIONAL), conditional)
        _set_g2(e, G2_RNONE, 0)
        e.give(p["eb_out"])
    return _function(("src", "edge", "arg"), build, tables)


def _for_incoming(e: E, visit):
    """``visit(source index, edge index, parameter, argument)`` for every incoming argument of a bounded parameter, in
    the bootstrap's order (source block, edge, argument index)."""
    p = e.p

    def block():
        e.var("fi_b", _block_at(e, p["fi_s"]))

        def edge():
            e.var("fi_e", e.add(_f(e, p["fi_b"], B_EDGES), e.mul(p["fi_k"], EDGE)))
            e.var("fi_t", _f(e, p["fi_e"], 0))

            def argument():
                e.var("fi_p", e.ld(e.add(_f(e, p["fi_t"], B_INPUTS), p["fi_a"])))
                e.if_(e.ne(_t(e, G2_ISPARAM, p["fi_p"]), 0), lambda: visit(p["fi_s"], p["fi_k"], p["fi_p"], e.ld(e.add(_f(e, p["fi_e"], 2), p["fi_a"]))))

            e.for_("fi_a", 0, _f(e, p["fi_e"], 1), argument)

        e.for_("fi_k", 0, _f(e, p["fi_b"], B_NEDGES), edge)

    e.for_("fi_s", 0, _g(e, G_BCOUNT), block)


def _bounds(tables):
    """``upper_bounds``' fixed point for the width table ``G2_WIDTHS``: parameter bounds (``G2_PBOUND``) of the
    non-entry blocks' parameters that have a width (``G2_ISPARAM``), widened then narrowed."""
    def build(e: E):
        p = e.p
        n = _g(e, G_VCOUNT)
        e.for_("bd_v", 0, n, lambda: (_set_t(e, G2_ISPARAM, p["bd_v"], 0), _set_t(e, G2_PBOUND, p["bd_v"], 0)))

        def block():
            e.var("bd_b", _block_at(e, p["bd_q"]))
            e.if_(e.ne(p["bd_b"], _g(e, G_BENTRY)), lambda: e.for_("bd_k", 0, _f(e, p["bd_b"], B_NP), lambda: (
                e.var("bd_v", e.ld(e.add(_f(e, p["bd_b"], B_INPUTS), p["bd_k"]))),
                e.if_(e.ne(_t(e, G2_WIDTHS, p["bd_v"]), 0), lambda: _set_t(e, G2_ISPARAM, p["bd_v"], 1)))))

        e.for_("bd_q", 0, _g(e, G_BCOUNT), block)
        e.var("bd_rounds", e.add(e.mul(_g(e, G_BCOUNT), 4), 16))
        e.var("bd_round", 0)
        e.var("bd_changed", 1)

        def clamp(name):
            """The edge bound (``G2_RNONE``-aware) capped at the parameter's limit, into ``name``."""
            limit = _limit(e, _t(e, G2_WIDTHS, p["bd_param"]))
            e.var("bd_limit", limit)
            e.var(name, e.sel(e.ne(_g2(e, G2_RNONE), 0), p["bd_limit"], e.sel(e.lt(p["bd_eb"], p["bd_limit"]), p["bd_eb"], p["bd_limit"])))

        def widen_round():
            _set_g2(e, G2_ROUND, e.add(_g2(e, G2_ROUND), 1))  # maximum_cache.clear()
            e.set("bd_changed", 0)

            def visit(source, edge, parameter, argument):
                e.var("bd_param", parameter)
                e.var("bd_eb", e.call(_FN["edge_bound"], source, edge, argument))
                clamp("bd_bound")

                def grow():
                    e.var("bd_new", e.sel(e.lt(p["bd_round"], 3), p["bd_bound"], p["bd_limit"]))
                    _set_t(e, G2_PBOUND, p["bd_param"], p["bd_new"])
                    e.set("bd_changed", 1)

                e.if_(e.lt(_t(e, G2_PBOUND, p["bd_param"]), p["bd_bound"]), grow)

            _for_incoming(e, visit)
            e.set("bd_round", e.add(p["bd_round"], 1))

        e.while_(lambda: e.both(e.ne(p["bd_changed"], 0), e.lt(p["bd_round"], p["bd_rounds"])), widen_round)
        # No fixed point within the cap: every parameter takes its width limit (``parameter_bound.clear()``).
        e.var("bd_bounded", e.flag(e.eq(p["bd_changed"], 0)))
        e.if_(e.eq(p["bd_bounded"], 0), lambda: e.for_("bd_v", 0, n, lambda: _set_t(e, G2_ISPARAM, p["bd_v"], 0)))

        def narrowing():
            from xax_selfhost_general_view import VCAP

            e.var("bd_left", e.add(_g(e, G_BCOUNT), 4))
            e.var("bd_narrowed", 1)
            recomputed = _g2(e, G2_RECOMP)  # per value: the recomputed bound at v, the round it was seen at v + VCAP
            e.var("bd_rc", recomputed)

            def narrow_round():
                _set_g2(e, G2_ROUND, e.add(_g2(e, G2_ROUND), 1))
                e.var("bd_seen_round", _g2(e, G2_ROUND))

                def visit(source, edge, parameter, argument):
                    e.var("bd_param", parameter)
                    e.var("bd_eb", e.call(_FN["edge_bound"], source, edge, argument))
                    clamp("bd_bound")
                    e.var("bd_at", e.add(p["bd_rc"], p["bd_param"]))
                    e.var("bd_seen", e.flag(e.eq(e.ld(e.add(p["bd_at"], VCAP)), p["bd_seen_round"])))
                    # recomputed[parameter] = max(recomputed.get(parameter, 0), bound)
                    best = e.sel(e.both(e.ne(p["bd_seen"], 0), e.lt(p["bd_bound"], e.ld(p["bd_at"]))), e.ld(p["bd_at"]), p["bd_bound"])
                    e.st(p["bd_at"], best)
                    e.st(e.add(p["bd_at"], VCAP), p["bd_seen_round"])

                _for_incoming(e, visit)
                e.set("bd_narrowed", 0)

                def lower():
                    e.var("bd_at", e.add(p["bd_rc"], p["bd_v"]))

                    def apply():
                        e.var("bd_rb", e.ld(p["bd_at"]))
                        e.if_(e.lt(p["bd_rb"], _t(e, G2_PBOUND, p["bd_v"])), lambda: (_set_t(e, G2_PBOUND, p["bd_v"], p["bd_rb"]), e.set("bd_narrowed", 1)))

                    seen = e.eq(e.ld(e.add(p["bd_at"], VCAP)), p["bd_seen_round"])
                    e.if_(e.both(seen, e.ne(_t(e, G2_ISPARAM, p["bd_v"]), 0)), apply)

                e.for_("bd_v", 0, n, lower)
                e.set("bd_left", e.sub(p["bd_left"], 1))

            e.while_(lambda: e.both(e.ne(p["bd_narrowed"], 0), e.ne(p["bd_left"], 0)), narrow_round)

        e.if_(e.ne(p["bd_bounded"], 0), narrowing)
        _set_g2(e, G2_ROUND, e.add(_g2(e, G2_ROUND), 1))  # the final maximum_cache.clear()
        e.give(1)
    return _function((), build, tables)


# -- pointer extents (``pointer_extent_from_graph`` on the view) ---------------------------------------------

def _extent(tables):
    """The verified extent of pointer value ``v`` in the view, through address offsets and casts; NONE (decline)
    where the bootstrap raises."""
    from xax_selfhost_general_view import G_VEXT

    def build(e: E):
        p = e.p
        e.var("ex_v", p["v"])
        e.var("ex_sub", 0)
        e.var("ex_out", NONE)
        e.var("ex_go", 1)

        def step():
            v = p["ex_v"]

            def parameter():
                block = _vf(e, G_VPARAM, v)
                e.var("ex_blk", block)
                e.var("ex_i", _pos_index(e, v))
                e.var("ex_info", 0)
                e.if_(e.lt(e.add(p["ex_i"], 1), _f(e, p["ex_blk"], B_NP)), lambda: e.set("ex_info", _view_extent(
                    e, _vf(e, G_VTYPE, e.ld(e.add(_f(e, p["ex_blk"], B_INPUTS), e.add(p["ex_i"], 1)))))))
                e.if_(e.ne(p["ex_info"], 0), lambda: e.set("ex_out", p["ex_info"]),
                      lambda: e.if_(e.ne(_vf(e, G_VEXT, v), NONE), lambda: e.set("ex_out", _vf(e, G_VEXT, v))))
                e.set("ex_go", 0)

            def produced():
                e.var("ex_node", _vf(e, G_VPROD, v))
                op = _f(e, p["ex_node"], N_OP)
                e.var("ex_op", op)
                fixed = e.either(*(e.eq(p["ex_op"], int(item)) for item in (Operation.STACK_ALLOC, Operation.HEAP_VIEW, Operation.POINTER_REBASE)))

                def follow(offset):
                    e.set("ex_sub", e.add(p["ex_sub"], offset))
                    e.set("ex_v", _operand(e, p["ex_node"], 0))

                def other():
                    e.if_(e.ne(_vf(e, G_VEXT, v), NONE), lambda: e.set("ex_out", _vf(e, G_VEXT, v)))
                    e.set("ex_go", 0)

                e.if_(fixed, lambda: (e.set("ex_out", _attribute(e, p["ex_node"], 0)), e.set("ex_go", 0)), lambda: e.if_(
                    e.eq(p["ex_op"], int(Operation.ADDRESS_OFFSET)), lambda: follow(_attribute(e, p["ex_node"], 0)), lambda: e.if_(
                        e.eq(p["ex_op"], int(Operation.POINTER_CAST)), lambda: follow(0), other)))

            e.if_(_is_param(e, v), parameter, produced)

        e.while_(lambda: e.ne(p["ex_go"], 0), step)
        _ok(e, e.both(e.ne(p["ex_out"], NONE), e.le(p["ex_sub"], p["ex_out"])))  # a negative extent: decline
        e.give(e.sub(p["ex_out"], p["ex_sub"]))
    return _function(("v",), build, tables)


# -- next-iteration prefetch ----------------------------------------------------------------------------------

def _cycle(tables):
    """``_cycle_blocks(graph, start, avoid)``: stamp ``G2_BODYSET`` (per block position) with ``G2_ROUND`` + 1 for the
    blocks on a cycle through ``start`` that does not pass ``avoid``; the count."""
    def build(e: E):
        p = e.p
        n = _g(e, G_BCOUNT)
        e.var("cy_n", n)
        _ok(e, e.ne(p["start"], p["avoid"]))  # the bootstrap fails on a block that branches to itself here
        forward, backward = _g2(e, G2_BODYSET), e.add(_g2(e, G2_BODYSET), 1 << 16)
        e.var("cy_f", forward)
        e.var("cy_bk", backward)
        e.for_("cy_q", 0, p["cy_n"], lambda: (e.st(e.add(p["cy_f"], p["cy_q"]), 0), e.st(e.add(p["cy_bk"], p["cy_q"]), 0)))
        stack = e.add(_g2(e, G2_BODYSET), 2 << 16)
        e.var("cy_stack", stack)
        e.var("cy_sp", 1)
        e.st(p["cy_stack"], p["start"])

        def successors_of(index, visit):
            block = _block_at(e, index)
            e.var("cy_blk", block)
            e.for_("cy_k", 0, _f(e, p["cy_blk"], B_NEDGES), lambda: visit(_f(e, _f(e, e.add(_f(e, p["cy_blk"], B_EDGES), e.mul(p["cy_k"], EDGE)), 0), B_POS)))

        def forward_step():
            e.set("cy_sp", e.sub(p["cy_sp"], 1))
            e.var("cy_x", e.ld(e.add(p["cy_stack"], p["cy_sp"])))

            def visit(target):
                e.var("cy_t", target)
                e.if_(e.both(e.ne(p["cy_t"], p["avoid"]), e.eq(e.ld(e.add(p["cy_f"], p["cy_t"])), 0)), lambda: (
                    e.st(e.add(p["cy_f"], p["cy_t"]), 1), e.st(e.add(p["cy_stack"], p["cy_sp"]), p["cy_t"]), e.set("cy_sp", e.add(p["cy_sp"], 1))))

            successors_of(p["cy_x"], visit)

        e.while_(lambda: e.ne(p["cy_sp"], 0), forward_step)
        # Backward: blocks (other than avoid) with an edge into the set, to a fixed point.
        e.st(e.add(p["cy_bk"], p["start"]), 1)
        e.var("cy_grew", 1)

        def backward_round():
            e.set("cy_grew", 0)

            def source():
                def visit(target):
                    e.var("cy_t", target)
                    hit = e.both(e.ne(p["cy_s"], p["avoid"]), e.ne(p["cy_t"], p["avoid"]), e.ne(e.ld(e.add(p["cy_bk"], p["cy_t"])), 0),
                                 e.eq(e.ld(e.add(p["cy_bk"], p["cy_s"])), 0))
                    e.if_(hit, lambda: (e.st(e.add(p["cy_bk"], p["cy_s"]), 1), e.set("cy_grew", 1)))

                successors_of(p["cy_s"], visit)

            e.for_("cy_s", 0, p["cy_n"], source)

        e.while_(lambda: e.ne(p["cy_grew"], 0), backward_round)
        e.var("cy_count", 0)
        e.for_("cy_q", 0, p["cy_n"], lambda: e.if_(e.both(e.ne(e.ld(e.add(p["cy_f"], p["cy_q"])), 0), e.ne(e.ld(e.add(p["cy_bk"], p["cy_q"])), 0)),
                                                       lambda: e.set("cy_count", e.add(p["cy_count"], 1)),
                                                       lambda: e.st(e.add(p["cy_f"], p["cy_q"]), 0)))
        e.give(p["cy_count"])
    return _function(("start", "avoid"), build, tables)


def _scaled_index(e: E, value, out_base: str, out_scale: str):
    """``_scaled_index``: ``(v, s)`` for ``v * s`` (optionally truncated) with ``v`` a block parameter; ``out_base`` is
    NONE otherwise.  ``s`` is the scale's constant value (its node is a constant)."""
    p = e.p
    e.var(out_base, NONE)
    e.var(out_scale, 0)
    e.var("si_v", value)

    def produced(name):
        return e.both(e.not_(_is_param(e, p[name])), e.eq(_pos_result(e, p[name]), 0))

    def through():
        e.var("si_node", _vf(e, G_VPROD, p["si_v"]))
        e.if_(e.eq(_f(e, p["si_node"], N_OP), int(Operation.INT_TRUNCATE)), lambda: e.set("si_v", _operand(e, p["si_node"], 0)))

        def multiply():
            e.var("si_mul", _vf(e, G_VPROD, p["si_v"]))

            def check():
                e.var("si_base", _operand(e, p["si_mul"], 0))
                e.var("si_scale", _operand(e, p["si_mul"], 1))
                scale_node = e.both(e.not_(_is_param(e, p["si_scale"])), e.eq(_pos_result(e, p["si_scale"]), 0))

                def constant():
                    node = _vf(e, G_VPROD, p["si_scale"])
                    ok = e.both(e.eq(_f(e, node, N_OP), int(Operation.CONSTANT)), _is_param(e, p["si_base"]))
                    e.if_(ok, lambda: (e.set(out_base, p["si_base"]), e.set(out_scale, _t(e, G2_CVAL, p["si_scale"]))))

                e.if_(scale_node, constant)

            e.if_(e.eq(_f(e, p["si_mul"], N_OP), int(Operation.MUL_WRAP)), check)

        e.if_(produced("si_v"), multiply)

    e.if_(produced("si_v"), through)


def _prefetch(tables):
    """``prefetch_next_iteration`` on the view: per loop body (in order), the first eligible checked load gets a copy
    of its pure index expression for the next iteration's guess, one more load, and the inner walk's prefetches
    (``G2_MARKS``).  1, or NONE (declined)."""
    def build(e: E):
        p = e.p
        _set_g2(e, G2_WIDTHS, _g2(e, G2_WBITS))
        _set_g2(e, G2_NMARKS, 0)
        e.var("pf_nb", _g(e, G_BCOUNT))

        def body():
            e.var("pf_body", _block_at(e, p["pf_bi"]))
            body_ = p["pf_body"]

            def branch():
                e.var("pf_edge", _f(e, body_, B_EDGES))
                e.var("pf_walk", _f(e, _f(e, p["pf_edge"], 0), B_POS))
                e.var("pf_nargs", _f(e, p["pf_edge"], 1))
                e.var("pf_args", _f(e, p["pf_edge"], 2))
                e.var("pf_inner", _call(e, "cycle", p["pf_walk"], p["pf_bi"]))

                def loads():
                    e.var("pf_nn", _f(e, body_, B_NNODES))
                    e.var("pf_li", 0)
                    e.var("pf_done", 0)

                    def load():
                        e.var("pf_load", _node_at(e, body_, p["pf_li"]))
                        _call(e, "prefetch_load", p["pf_load"], p["pf_bi"])
                        e.set("pf_done", e.ld(e.add(_g2(e, G2_SCRATCH), SCRATCH_DONE)))
                        e.set("pf_li", e.add(p["pf_li"], 1))

                    e.st(e.add(_g2(e, G2_SCRATCH), SCRATCH_DONE), 0)
                    e.while_(lambda: e.both(e.eq(p["pf_done"], 0), e.lt(p["pf_li"], p["pf_nn"])), load)

                e.if_(e.ne(p["pf_inner"], 0), loads)

            e.if_(e.eq(_f(e, body_, B_KIND), BRANCH), branch)

        e.for_("pf_bi", 0, p["pf_nb"], body)
        e.give(1)
    return _function((), build, tables)


def _prefetch_load(tables):
    """One load ``ld`` of body block ``bi`` (``prefetch_next_iteration``'s inner loop).  On success the body is
    rewritten, a mark recorded, and the done flag set; 1, or NONE (declined)."""
    from xax_selfhost_general_view import VCAP

    def build(e: E):
        p = e.p
        e.var("pl_body", _block_at(e, p["bi"]))
        body = p["pl_body"]
        e.var("pl_edge", _f(e, body, B_EDGES))
        e.var("pl_nargs", _f(e, p["pl_edge"], 1))
        e.var("pl_args", _f(e, p["pl_edge"], 2))
        ld = p["ld"]
        e.if_(e.ne(_f(e, ld, N_OP), int(Operation.CHECKED_LOAD_BITS_LE)), lambda: e.give(1))
        e.var("pl_head", _output(e, ld, 0))
        e.var("pl_token", _output(e, ld, 1))

        def passed(value_name):
            e.var(f"{value_name}_in", 0)
            e.for_("pl_k", 0, p["pl_nargs"], lambda: e.if_(e.eq(e.ld(e.add(p["pl_args"], p["pl_k"])), p[value_name]),
                                                            lambda: e.set(f"{value_name}_in", 1)))
            return p[f"{value_name}_in"]

        e.var("pl_ok", e.flag(e.both(e.ne(passed("pl_head"), 0), e.ne(passed("pl_token"), 0))))
        e.var("pl_nn", _f(e, body, B_NNODES))

        def token_unused():
            def node():
                n = _node_at(e, body, p["pl_m"])
                e.var("pl_n", n)
                e.for_("pl_o", 0, _f(e, p["pl_n"], N_NOPS), lambda: e.if_(e.eq(_operand(e, p["pl_n"], p["pl_o"]), p["pl_token"]), lambda: e.set("pl_ok", 0)))

            e.for_("pl_m", 0, p["pl_nn"], node)

        e.if_(e.ne(p["pl_ok"], 0), token_unused)
        e.if_(e.eq(p["pl_ok"], 0), lambda: e.give(1))
        # The pure index expression and its single input (a parameter of the body).
        e.var("pl_stamp", e.add(_g2(e, G2_ROUND), 0))
        _set_g2(e, G2_ROUND, e.add(p["pl_stamp"], 1))
        e.set("pl_stamp", e.add(p["pl_stamp"], 1))
        expr = _g2(e, G2_EXPR)
        e.var("pl_expr", expr)
        e.var("pl_stack", e.alloc(e.add(_g(e, G_VCOUNT), 2)))
        _ok(e, e.ne(p["pl_stack"], NONE))
        e.st(p["pl_stack"], _operand(e, ld, 1))
        e.var("pl_sp", 1)
        e.var("pl_seed", NONE)
        e.var("pl_two", 0)
        e.var("pl_bad", 0)

        def visit():
            e.set("pl_sp", e.sub(p["pl_sp"], 1))
            e.var("pl_v", e.ld(e.add(p["pl_stack"], p["pl_sp"])))
            v = p["pl_v"]
            seen = e.either(e.eq(e.ld(e.add(p["pl_expr"], v)), p["pl_stamp"]), e.ne(_t(e, G2_CONST, v), 0))

            def fresh():
                local_parameter = e.both(_is_param(e, v), e.eq(_pos_block(e, v), p["bi"]))

                def input_():
                    e.if_(e.eq(p["pl_seed"], NONE), lambda: e.set("pl_seed", v), lambda: e.if_(e.ne(p["pl_seed"], v), lambda: e.set("pl_two", 1)))

                def node():
                    local = e.both(e.not_(_is_param(e, v)), e.eq(_pos_block(e, v), p["bi"]), e.eq(_pos_result(e, v), 0))
                    e.var("pl_def", e.sel(local, _vf(e, G_VPROD, v), 0))
                    e.var("pl_op", e.sel(local, _f(e, p["pl_def"], N_OP), NONE))
                    pure = e.either(*(e.eq(p["pl_op"], op) for op in PREFETCH_PURE))
                    division = e.either(e.eq(p["pl_op"], int(Operation.UDIV)), e.eq(p["pl_op"], int(Operation.UREM)))
                    e.var("pl_divisor", e.sel(division, _operand(e, p["pl_def"], 1), 0))
                    nonzero = e.both(e.ne(_t(e, G2_CONST, p["pl_divisor"]), 0), e.ne(_t(e, G2_CVAL, p["pl_divisor"]), 0))
                    good = e.both(local, pure, e.either(e.not_(division), nonzero))

                    def expand():
                        e.st(e.add(p["pl_expr"], v), p["pl_stamp"])
                        e.for_("pl_o", 0, _f(e, p["pl_def"], N_NOPS), lambda: (
                            e.st(e.add(p["pl_stack"], p["pl_sp"]), _operand(e, p["pl_def"], p["pl_o"])), e.set("pl_sp", e.add(p["pl_sp"], 1))))

                    e.if_(good, expand, lambda: e.set("pl_bad", 1))

                e.if_(local_parameter, input_, node)

            e.if_(e.not_(seen), fresh)

        e.while_(lambda: e.both(e.ne(p["pl_sp"], 0), e.eq(p["pl_bad"], 0)), visit)
        e.if_(e.either(e.ne(p["pl_bad"], 0), e.eq(p["pl_seed"], NONE), e.ne(p["pl_two"], 0)), lambda: e.give(1))
        # The guess: the body passes it on in the seed's own parameter position.
        e.var("pl_si", _pos_index(e, p["pl_seed"]))
        e.if_(e.le(p["pl_nargs"], p["pl_si"]), lambda: e.give(1))
        e.var("pl_guess", e.ld(e.add(p["pl_args"], p["pl_si"])))
        e.if_(e.ne(e.ld(e.add(p["pl_expr"], p["pl_guess"])), p["pl_stamp"]), lambda: e.give(1))
        # Inner-loop arrays read at block-parameter * scale, with pointers defined in the entry block.
        e.var("pl_list", e.alloc(e.add(e.mul(_g(e, G_VCOUNT), 2), 2)))
        _ok(e, e.ne(p["pl_list"], NONE))
        e.var("pl_count", 0)
        e.var("pl_entry", _f(e, _g(e, G_BENTRY), B_POS))
        inner = _g2(e, G2_BODYSET)

        def inner_block():
            e.var("pl_ib", _block_at(e, p["pl_q"]))

            def node():
                e.var("pl_in", _node_at(e, p["pl_ib"], p["pl_m"]))

                def checked():
                    _scaled_index(e, _operand(e, p["pl_in"], 1), "pl_base", "pl_scale")
                    e.var("pl_ptr", _operand(e, p["pl_in"], 0))
                    ok = e.both(e.ne(p["pl_base"], NONE), e.eq(_pos_block(e, p["pl_ptr"]), p["pl_entry"]),
                                e.either(*(e.eq(p["pl_scale"], scale) for scale in SCALES)))

                    def add():
                        e.var("pl_dup", 0)
                        e.for_("pl_k", 0, p["pl_count"], lambda: e.if_(e.both(
                            e.eq(e.ld(e.add(p["pl_list"], e.mul(p["pl_k"], 2))), p["pl_ptr"]),
                            e.eq(e.ld(e.add(p["pl_list"], e.add(e.mul(p["pl_k"], 2), 1))), p["pl_scale"])), lambda: e.set("pl_dup", 1)))

                        def append():
                            e.st(e.add(p["pl_list"], e.mul(p["pl_count"], 2)), p["pl_ptr"])
                            e.st(e.add(p["pl_list"], e.add(e.mul(p["pl_count"], 2), 1)), p["pl_scale"])
                            e.set("pl_count", e.add(p["pl_count"], 1))

                        e.if_(e.eq(p["pl_dup"], 0), append)

                    e.if_(ok, add)

                e.if_(e.eq(_f(e, p["pl_in"], N_OP), int(Operation.CHECKED_LOAD_BITS_LE)), checked)

            e.for_("pl_m", 0, _f(e, p["pl_ib"], B_NNODES), node)

        e.for_("pl_q", 0, _g(e, G_BCOUNT), lambda: e.if_(e.ne(e.ld(e.add(inner, p["pl_q"])), 0), inner_block))
        e.if_(e.eq(p["pl_count"], 0), lambda: e.give(1))

        # The candidate: copies of the expression (in node order), then the extra load; the edge passes its token.
        copies = _g2(e, G2_COPY)  # [mapped value] at v, [stamp] at v + VCAP
        e.var("pl_copies", copies)

        def mapped(value):
            stamped = e.eq(e.ld(e.add(p["pl_copies"], e.add(value, VCAP))), p["pl_stamp"])
            return e.sel(stamped, e.ld(e.add(p["pl_copies"], value)), value)

        def map_(key, value):
            e.st(e.add(p["pl_copies"], key), value)
            e.st(e.add(p["pl_copies"], e.add(key, VCAP)), p["pl_stamp"])

        map_(p["pl_seed"], p["pl_guess"])
        e.var("pl_old_nodes", _f(e, body, B_NODES))
        e.var("pl_new_nodes", e.alloc(e.add(e.mul(p["pl_nn"], 2), 2)))
        _ok(e, e.ne(p["pl_new_nodes"], NONE))
        e.for_("pl_m", 0, p["pl_nn"], lambda: e.st(e.add(p["pl_new_nodes"], p["pl_m"]), _node_at(e, body, p["pl_m"])))
        e.var("pl_w", p["pl_nn"])

        def copy_node(source, operands):
            """Append a copy of node ``source`` with ``operands(k)`` and fresh outputs; the copy."""
            from xax_selfhost_general_view import N_GRAPH as NG

            e.var("pl_src", source)
            e.var("pl_new", e.alloc(e.add(e.add(N_HDR, _f(e, p["pl_src"], N_NOPS)), _f(e, p["pl_src"], N_NRES))))
            _ok(e, e.ne(p["pl_new"], NONE))
            e.for_("pl_k", 0, N_HDR, lambda: _set(e, p["pl_new"], p["pl_k"], _f(e, p["pl_src"], p["pl_k"])))
            e.for_("pl_k", 0, _f(e, p["pl_src"], N_NOPS), lambda: e.st(e.add(e.add(p["pl_new"], N_HDR), p["pl_k"]), operands(p["pl_k"])))

            def output():
                old = _output(e, p["pl_src"], p["pl_r"])
                e.var("pl_old", old)
                _new_value(e, _vf(e, G_VTYPE, p["pl_old"]), "pl_nv")
                _set_vf(e, G_VPROD, p["pl_nv"], p["pl_new"])
                _set_vf(e, G_VPOS, p["pl_nv"], e.add(e.add(e.add(POS_TAG, e.mul(p["bi"], POS_BLOCK)), e.mul(p["pl_w"], POS_INDEX)), p["pl_r"]))
                _set_t(e, G2_WBITS, p["pl_nv"], _bits_width(e, _vf(e, G_VTYPE, p["pl_nv"])))
                _set_t(e, G2_CONST, p["pl_nv"], 0)
                _clear_stamps(e, p["pl_nv"])
                e.st(e.add(e.add(e.add(p["pl_new"], N_HDR), _f(e, p["pl_new"], N_NOPS)), p["pl_r"]), p["pl_nv"])

            e.for_("pl_r", 0, _f(e, p["pl_src"], N_NRES), output)
            e.st(e.add(p["pl_new_nodes"], p["pl_w"]), p["pl_new"])
            e.set("pl_w", e.add(p["pl_w"], 1))

        def copy_expression():
            e.var("pl_xn", _node_at(e, body, p["pl_m"]))
            e.var("pl_x0", _output(e, p["pl_xn"], 0))

            def copy():
                copy_node(p["pl_xn"], lambda k: mapped(_operand(e, p["pl_xn"], k)))
                map_(p["pl_x0"], _output(e, p["pl_new"], 0))

            e.if_(e.eq(e.ld(e.add(p["pl_expr"], p["pl_x0"])), p["pl_stamp"]), copy)

        e.for_("pl_m", 0, p["pl_nn"], copy_expression)
        e.var("pl_index", mapped(_operand(e, ld, 1)))
        copy_node(ld, lambda k: e.sel(e.eq(k, 0), _operand(e, ld, 0), e.sel(e.eq(k, 1), p["pl_index"], p["pl_token"])))
        e.var("pl_extra", p["pl_new"])
        e.var("pl_next_head", _output(e, p["pl_extra"], 0))
        e.var("pl_next_token", _output(e, p["pl_extra"], 1))
        e.var("pl_new_args", e.alloc(e.add(p["pl_nargs"], 1)))
        _ok(e, e.ne(p["pl_new_args"], NONE))
        e.for_("pl_k", 0, p["pl_nargs"], lambda: (e.var("pl_a", e.ld(e.add(p["pl_args"], p["pl_k"]))), e.st(
            e.add(p["pl_new_args"], p["pl_k"]), e.sel(e.eq(p["pl_a"], p["pl_token"]), p["pl_next_token"], p["pl_a"]))))
        # Apply the candidate; the added load must be provably in bounds (it may never trap).
        _set(e, body, B_NODES, p["pl_new_nodes"])
        _set(e, body, B_NNODES, p["pl_w"])
        _set(e, p["pl_edge"], 2, p["pl_new_args"])
        _call(e, "bounds")
        e.var("pl_bound", e.call(_FN["maximum0"], p["pl_index"]))
        e.var("pl_bnone", _g2(e, G2_RNONE))
        e.var("pl_extent", _call(e, "extent", _operand(e, ld, 0)))
        e.var("pl_size", _attribute(e, ld, 0))
        fits = e.both(e.eq(p["pl_bnone"], 0), e.le(p["pl_size"], p["pl_extent"]), e.le(p["pl_bound"], e.sub(p["pl_extent"], p["pl_size"])))

        def commit():
            e.var("pl_mark", e.add(_g2(e, G2_MARKS), e.mul(_g2(e, G2_NMARKS), MARK_WORDS)))
            for field, value in ((0, p["pl_next_head"]), (1, p["pl_list"]), (2, p["pl_count"])):
                e.st(e.add(p["pl_mark"], field), value)
            _set_g2(e, G2_NMARKS, e.add(_g2(e, G2_NMARKS), 1))
            e.st(e.add(_g2(e, G2_SCRATCH), SCRATCH_DONE), 1)

        def rollback():
            _set(e, body, B_NODES, p["pl_old_nodes"])
            _set(e, body, B_NNODES, p["pl_nn"])
            _set(e, p["pl_edge"], 2, p["pl_args"])

        e.if_(fits, commit, rollback)
        e.give(1)
    return _function(("ld", "bi"), build, tables)


def add_range_functions(add, tables):
    add("value_facts", _value_facts(tables))
    for depth in range(DEPTH + 1, -1, -1):  # callees first
        add(f"maximum{depth}", _maximum(tables, depth))
    add("edge_bound", _edge_bound(tables))
    add("bounds", _bounds(tables))
    add("extent", _extent(tables))
    add("cycle", _cycle(tables))
    add("prefetch_load", _prefetch_load(tables))
    add("prefetch", _prefetch(tables))


def ranges_prologue(e: E):
    """Allocate the second globals and the per-value range tables (once, before the views)."""
    from xax_selfhost_general_view import VCAP

    more = e.alloc(MORE_WORDS)
    _ok(e, e.ne(more, NONE))
    e.st(GLOBALS + G_MORE, more)
    _set_g2(e, G2_BITWISE, 0)
    for slot, size in ((G2_CONST, VCAP), (G2_CVAL, VCAP), (G2_PBOUND, VCAP), (G2_ISPARAM, VCAP), (G2_CACHE, 2 * VCAP), (G2_CSTAMP, VCAP),
                       (G2_WBITS, VCAP), (G2_EXPR, VCAP), (G2_RECOMP, 2 * VCAP), (G2_COPY, 2 * VCAP), (G2_BODYSET, 3 << 16), (G2_MARKS, MARK_WORDS * VCAP),
                       (G2_SCRATCH, 128)):
        table = e.alloc(size + 1)
        _ok(e, e.ne(table, NONE))
        _set_g2(e, slot, table)
    e.var("rp_power", 1)
    e.for_("rp_v", 0, 64, lambda: (e.st(e.add(_g2(e, G2_SCRATCH), e.p["rp_v"]), e.p["rp_power"]), e.set("rp_power", e.mul(e.p["rp_power"], 2))))
    _set_g2(e, G2_ROUND, 1)
