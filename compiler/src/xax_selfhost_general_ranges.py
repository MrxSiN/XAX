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

from xax_compiler import Operation
from xax_selfhost_facts import E, NONE, _function
from xax_selfhost_general_view import (
    B_INPUTS, B_NODES, B_NP, G_BLIST, G_VPARAM, G_VPOS, G_VPROD, G_VTYPE, N_ATTR, N_OP, POS_BLOCK, POS_INDEX, _f, _operand, _vf)
from xax_selfhost_views_backend import _g, _ok, _view_extent

G_MORE = 58  # pointer to the second globals table (``_g2``)
# Second globals.
(G2_WIDTHS, G2_CONST, G2_CVAL, G2_RNONE, G2_PBOUND, G2_ISPARAM, G2_CACHE, G2_CSTAMP, G2_ROUND, G2_MARKS, G2_NMARKS, G2_WBITS,
 G2_EXPR, G2_RECOMP, G2_COPY, G2_BODYSET, G2_SCRATCH) = range(17)
SCALES = (1, 2, 4, 8)
# ``_UPPER``: (compare kind, taken edge) -> relation of the left operand to the right.
LT, LE, GT, GE, EQ = range(1, 6)
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


# -- upper bounds -------------------------------------------------------------------------------------------


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


