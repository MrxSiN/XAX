"""Self-hosting step S12b (ADR-269): the general x86-64 backend's lowering view as XAX semantics.

Before the register-resident lowering, ``xax_x86_64._compile_function`` rewrites each function's parsed graph into a
*lowering view* (``xax_inline.inline_leaf_calls``): every ``call.direct`` of a small leaf function (no call of any
kind, at most ``INLINE_NODE_LIMIT`` nodes, every return giving the call's result count) is replaced by the callee's
blocks; then exact simplifications run to a fixed point -- a block entered by one branch merges into its predecessor,
edges into forwarding blocks are threaded, ``bits<32>`` halves read back out of a packed ``bits<64>`` are the halves,
a store of a truncation stores its source, a single-predecessor block reads edge arguments through its own
parameters, and unused pure nodes are deleted -- and finally the blocks are laid out for fall-through.

This module builds those decisions as functions of the S12 general backend program (``xax_x86_64_general.xax``).
The program lifts each closure function's graph-decoder stream into arena records (values, nodes, blocks, edges),
applies the same rewrites in the same order with the same tie-breaks, and writes the view as *origins and operands*:
every node is named by the (function, block, node) it came from, every block by the graph block or the call it was
made for, and every operand, terminator value, and edge argument by its new position.  The host rebuilds the view
exactly as ``xax_inline._lower`` does (``replace(node, operands=...)``); it decides nothing.

Pointer extents are the verifier's facts (the parsed graph's ``pointer_extents``); the host supplies them per graph
fragment after the object table.  The next-iteration prefetch rewrite needs value ranges and moves to S12c.

View output (output words from ``VIEW_AT``), per closure function in image order:

    entry position, block count,
    per block: origin kind (0 graph block, 1 call continuation), function index, block, node, node count,
        per node: function index, block, node, operand count, operands (4 words each: tag, block, index, result),
        terminator kind, payload origin (function index, block; NONE when empty), value count, values,
        edge count, per edge: target position, argument count, arguments
    extent count, per extent: value (4 words), extent

A function index is the function's position in the image order (the closure by CID).
"""

from __future__ import annotations

from xax_compiler import Operation, TerminatorKind
from xax_selfhost_facts import E, NONE, _function
from xax_selfhost_views_backend import _FN, G_PAY, _at, _call, _g, _ok, _payload_uleb, _type_form

VIEW_AT, VIEW_END = 32 << 20, 120 << 20  # S14a (ADR-284): the compiler's own closure (above the front end's globals); S15d.0 (ADR-303): 36M words; S15e.4 (ADR-322): 41M; S15f (ADR-323): 88M
VCAP = 1 << 18  # values per function view

# Globals (``GLOBALS + slot``), after the front end's.
(G_VEXT, G_VTYPE, G_VPROD, G_VREAD, G_VMULTI, G_VFWD, G_VPARAM, G_VSTAMP, G_VPOS, G_VCOUNT, G_STAMP, G_BLIST, G_BCOUNT, G_BENTRY,
 G_GEXT, G_CIDX, G_CAND, G_FKEYS, G_FKEYN, G_LIFT_ENTRY, G_VIEW_OUT, G_VSTAMP2) = range(36, 58)
G_AUDIT = 59  # (58 is ``xax_selfhost_general_ranges.G_MORE``)
assert G_AUDIT < 64

# Node record: origin, stream positions, counts, then operand and output value ids.
N_FN, N_B, N_N, N_OP, N_ATTR, N_NOPS, N_NRES, N_OPSAT, N_GRAPH = range(9)
N_HDR = 9
# Block record.
(B_KIND0, B_FN, B_BB, B_NN, B_NP, B_INPUTS, B_NODES, B_NNODES, B_KIND, B_PFN, B_PB, B_VALUES, B_NVALUES, B_EDGES, B_NEDGES, B_TERM,
 B_POS, B_PLACED, B_INCOMING, B_MARK, B_DIST, B_GRAPH, B_SNAP_SRC, B_SNAP_ARGS) = range(24)
EDGE = 3  # target block, argument count, arguments
CALLS = (int(Operation.CALL_GROUP_MEMBER), int(Operation.CALL_DIRECT), int(Operation.CALL_FOREIGN), int(Operation.CALL_INDIRECT))
BRANCH, CONDITIONAL, RETURN, TRAP = (int(k) for k in (TerminatorKind.BRANCH, TerminatorKind.CONDITIONAL_BRANCH, TerminatorKind.RETURN, TerminatorKind.TRAP))
FAR = 1 << 30
POS_TAG, POS_BLOCK, POS_INDEX = 1 << 62, 1 << 40, 1 << 16
NOT_CALL = NONE - 1  # "no" from a helper whose NONE means decline


# -- small accessors ------------------------------------------------------------------------------------

def _f(e: E, record, field):
    return e.ld(e.add(record, field))


def _set(e: E, record, field, value):
    e.st(e.add(record, field), value)


def _vf(e: E, slot: int, value):
    return e.ld(e.add(_g(e, slot), value))


def _set_vf(e: E, slot: int, value, word):
    e.st(e.add(_g(e, slot), value), word)


def _bits_width(e: E, obj):
    """The width of TYPE ``obj`` when it is ``bits<N>``, else 0."""
    p = e.p
    e.var("bw", 0)

    def bits():
        e.var("bw_at", e.add(_at(e, G_PAY, obj), 1))
        e.set("bw", _payload_uleb(e, "bw_at"))

    e.if_(e.eq(_type_form(e, obj), 1), bits)
    return p["bw"]


def _new_value(e: E, type_obj, name: str):
    """A fresh value of type ``type_obj`` into variable ``name`` (no extent, producer, or parameter yet)."""
    p = e.p
    e.var(name, _g(e, G_VCOUNT))
    _ok(e, e.lt(p[name], VCAP))
    from xax_selfhost_views_backend import GLOBALS

    e.st(GLOBALS + G_VCOUNT, e.add(p[name], 1))
    for slot, word in ((G_VEXT, NONE), (G_VTYPE, type_obj), (G_VPROD, NONE), (G_VPARAM, NONE), (G_VFWD, NONE), (G_VSTAMP, 0),
                       (G_VSTAMP2, 0), (G_VREAD, NONE), (G_VMULTI, 0)):
        _set_vf(e, slot, p[name], word)


def _globals(e: E, slot: int, value):
    from xax_selfhost_views_backend import GLOBALS

    e.st(GLOBALS + slot, value)


def _stamp(e: E):
    """A fresh mark for the stamped value sets (``G_VSTAMP``)."""
    _globals(e, G_STAMP, e.add(_g(e, G_STAMP), 1))
    return _g(e, G_STAMP)


# -- lifting a graph-decoder stream ------------------------------------------------------------------

def _read_value(e: E, at_name: str, out: str, fixed: bool = False):
    """The value id of the stream value at ``p[at_name]`` (advanced past it) in the function being lifted (``p["la"]``
    is its block array).  ``fixed``: always four words (tag, block, index, result), as in the extents section."""
    p = e.p
    at = p[at_name]
    e.var("rv_tag", e.rd(at))
    e.var("rv_block", e.rd(e.add(at, 1)))
    e.var("rv_index", e.rd(e.add(at, 2)))
    e.var("rv_result", e.sel(e.eq(p["rv_tag"], 1), e.rd(e.add(at, 3)), 0))
    e.set(at_name, e.add(at, 4) if fixed else e.add(e.add(at, 3), p["rv_tag"]))
    e.var("rv_blk", e.ld(e.add(p["la"], p["rv_block"])))

    def parameter():
        e.set(out, e.ld(e.add(_f(e, p["rv_blk"], B_INPUTS), p["rv_index"])))

    def result():
        node = e.ld(e.add(_f(e, p["rv_blk"], B_NODES), p["rv_index"]))
        e.set(out, e.ld(e.add(e.add(node, e.add(N_HDR, _f(e, node, N_NOPS))), p["rv_result"])))

    e.if_(e.eq(p["rv_tag"], 0), parameter, result)


# -- inlining ------------------------------------------------------------------------------------------


# -- value replacement ---------------------------------------------------------------------------------


def _resolve(tables):
    def build(e: E):
        p = e.p
        e.var("rs", p["v"])
        e.while_(lambda: e.ne(_vf(e, G_VFWD, p["rs"]), NONE), lambda: e.set("rs", _vf(e, G_VFWD, p["rs"])))
        e.give(p["rs"])
    return _function(("v",), build, tables)


def _carry(e: E, source, target):
    """``_carry_extent(source, target)``."""
    p = e.p
    e.var("ce_s", source)
    e.var("ce_t", target)
    e.if_(e.both(e.eq(_vf(e, G_VEXT, p["ce_t"]), NONE), e.ne(_vf(e, G_VEXT, p["ce_s"]), NONE)),
          lambda: _set_vf(e, G_VEXT, p["ce_t"], _vf(e, G_VEXT, p["ce_s"])))


# -- the simplifications -------------------------------------------------------------------------------

def _count_incoming(e: E):
    """``B_INCOMING`` of every listed block: the edges into it (one per edge, duplicates counted)."""
    p = e.p
    e.for_("ci_q", 0, _g(e, G_BCOUNT), lambda: _set(e, e.ld(e.add(_g(e, G_BLIST), p["ci_q"])), B_INCOMING, 0))

    def block():
        e.var("ci_b", e.ld(e.add(_g(e, G_BLIST), p["ci_q"])))

        def edge():
            e.var("ci_t", _f(e, e.add(_f(e, p["ci_b"], B_EDGES), e.mul(p["ci_k"], EDGE)), 0))
            _set(e, p["ci_t"], B_INCOMING, e.add(_f(e, p["ci_t"], B_INCOMING), 1))

        e.for_("ci_k", 0, _f(e, p["ci_b"], B_NEDGES), edge)

    e.for_("ci_q", 0, _g(e, G_BCOUNT), block)


def _operand(e: E, node, k):
    return e.ld(e.add(e.add(node, N_HDR), k))


def _output(e: E, node, k):
    return e.ld(e.add(e.add(e.add(node, N_HDR), _f(e, node, N_NOPS)), k))


def _stores(tables):
    """``_store_truncations``: a ``w``-bit store of ``trunc_w(x)`` stores ``x``."""
    def build(e: E):
        p = e.p
        e.var("st_changed", 0)

        def block():
            e.var("st_b", e.ld(e.add(_g(e, G_BLIST), p["st_q"])))

            def node():
                e.var("st_n", e.ld(e.add(_f(e, p["st_b"], B_NODES), p["st_m"])))
                op = _f(e, p["st_n"], N_OP)
                e.var("st_op", op)
                e.var("st_pos", e.sel(e.eq(p["st_op"], int(Operation.STORE_BITS_LE)), 1, e.sel(e.eq(p["st_op"], int(Operation.CHECKED_STORE_BITS_LE)), 2, NONE)))

                def store():
                    e.var("st_v", _operand(e, p["st_n"], p["st_pos"]))
                    e.var("st_t", _vf(e, G_VPROD, p["st_v"]))

                    def truncation():
                        width = _bits_width(e, _vf(e, G_VTYPE, p["st_v"]))
                        e.var("st_w", width)
                        size = e.rd(e.add(_f(e, p["st_n"], N_ATTR), 1))
                        e.if_(e.both(e.ne(p["st_w"], 0), e.eq(p["st_w"], e.mul(size, 8))), lambda: (
                            e.st(e.add(e.add(p["st_n"], N_HDR), p["st_pos"]), _operand(e, p["st_t"], 0)), e.set("st_changed", 1)))

                    e.if_(e.ne(p["st_t"], NONE), lambda: e.if_(e.eq(_f(e, p["st_t"], N_OP), int(Operation.INT_TRUNCATE)), truncation))

                e.if_(e.ne(p["st_pos"], NONE), store)

            e.for_("st_m", 0, _f(e, p["st_b"], B_NNODES), node)

        e.for_("st_q", 0, _g(e, G_BCOUNT), block)
        e.give(p["st_changed"])
    return _function((), build, tables)


# -- layout ---------------------------------------------------------------------------------------------


def _layout(tables):
    """``xax_inline._layout``: chains of fall-through successors ranked by (distance back to the block, ends the
    function, more incoming edges first, edge order), unchosen successors on a stack; the new block list."""
    def build(e: E):
        p = e.p
        _count_incoming(e)
        n = _g(e, G_BCOUNT)
        e.var("ly_n", n)
        e.for_("ly_q", 0, p["ly_n"], lambda: _set(e, e.ld(e.add(_g(e, G_BLIST), p["ly_q"])), B_PLACED, 0))
        e.var("ly_order", e.alloc(e.add(p["ly_n"], 1)))
        e.var("ly_pending", e.alloc(e.add(e.mul(p["ly_n"], 4), 2)))  # every edge can push its target once per placement
        _ok(e, e.both(e.ne(p["ly_order"], NONE), e.ne(p["ly_pending"], NONE)))
        e.var("ly_count", 0)
        e.var("ly_sp", 1)
        e.st(p["ly_pending"], _g(e, G_BENTRY))
        e.var("ly_cap", e.add(e.mul(p["ly_n"], 4), 2))

        def chain():
            e.set("ly_sp", e.sub(p["ly_sp"], 1))
            e.var("ly_b", e.ld(e.add(p["ly_pending"], p["ly_sp"])))

            def place():
                b = p["ly_b"]
                e.st(e.add(p["ly_order"], p["ly_count"]), b)
                e.set("ly_count", e.add(p["ly_count"], 1))
                _set(e, b, B_PLACED, 1)
                # Options: unplaced successors with their rank keys; sorted by (distance, ends, -incoming, edge).
                e.var("ly_ne", _f(e, b, B_NEDGES))
                e.var("ly_opts", e.alloc(e.add(e.mul(p["ly_ne"], 5), 1)))
                _ok(e, e.ne(p["ly_opts"], NONE))
                e.var("ly_no", 0)

                def option():
                    e.var("ly_t", _f(e, e.add(_f(e, b, B_EDGES), e.mul(p["ly_k"], EDGE)), 0))

                    def add():
                        at = e.add(p["ly_opts"], e.mul(p["ly_no"], 5))
                        e.var("ly_at", at)
                        _set(e, p["ly_at"], 0, _call(e, "distance", p["ly_t"], b))
                        kind = _f(e, p["ly_t"], B_KIND)
                        _set(e, p["ly_at"], 1, e.flag(e.either(e.eq(kind, RETURN), e.eq(kind, TRAP))))
                        _set(e, p["ly_at"], 2, e.sub(FAR, _f(e, p["ly_t"], B_INCOMING)))
                        _set(e, p["ly_at"], 3, p["ly_k"])
                        _set(e, p["ly_at"], 4, p["ly_t"])
                        e.set("ly_no", e.add(p["ly_no"], 1))

                    e.if_(e.eq(_f(e, p["ly_t"], B_PLACED), 0), add)

                e.for_("ly_k", 0, p["ly_ne"], option)

                # Insertion sort of the options (at most a few).
                def less(x, y):
                    result, equal = e.c(0), e.c(1)
                    for k in range(4):
                        wx, wy = _f(e, x, k), _f(e, y, k)
                        result = e.or_(result, e.flag(e.both(e.ne(equal, 0), e.lt(wx, wy))))
                        equal = e.flag(e.both(e.ne(equal, 0), e.eq(wx, wy)))
                    return e.ne(result, 0)

                def insert():
                    e.var("ly_j", p["ly_s"])

                    def swap():
                        a = e.add(p["ly_opts"], e.mul(e.sub(p["ly_j"], 1), 5))
                        c = e.add(p["ly_opts"], e.mul(p["ly_j"], 5))
                        e.var("ly_a", a)
                        e.var("ly_c", c)
                        for k in range(5):
                            e.var("ly_tmp", _f(e, p["ly_a"], k))
                            _set(e, p["ly_a"], k, _f(e, p["ly_c"], k))
                            _set(e, p["ly_c"], k, p["ly_tmp"])
                        e.set("ly_j", e.sub(p["ly_j"], 1))

                    e.while_(lambda: e.both(e.lt(0, p["ly_j"]), less(e.add(p["ly_opts"], e.mul(p["ly_j"], 5)),
                                                                        e.add(p["ly_opts"], e.mul(e.sub(p["ly_j"], 1), 5)))), swap)

                e.for_("ly_s", 1, p["ly_no"], insert)
                # pending.extend(reversed(options[1:])): the second-best is popped first.
                e.var("ly_r", p["ly_no"])

                def push():
                    e.set("ly_r", e.sub(p["ly_r"], 1))
                    _ok(e, e.lt(p["ly_sp"], p["ly_cap"]))
                    e.st(e.add(p["ly_pending"], p["ly_sp"]), _f(e, e.add(p["ly_opts"], e.mul(p["ly_r"], 5)), 4))
                    e.set("ly_sp", e.add(p["ly_sp"], 1))

                e.while_(lambda: e.lt(1, p["ly_r"]), push)
                e.set("ly_b", e.sel(e.ne(p["ly_no"], 0), _f(e, p["ly_opts"], 4), NONE))

            e.while_(lambda: e.both(e.ne(p["ly_b"], NONE), e.eq(_f(e, e.sel(e.ne(p["ly_b"], NONE), p["ly_b"], _g(e, G_BENTRY)), B_PLACED), 0)), place)

            def rest():
                # pending.extend(block for block in reversed(blocks) if unplaced): the first unplaced is popped first.
                e.var("ly_q", p["ly_n"])

                def each():
                    e.set("ly_q", e.sub(p["ly_q"], 1))
                    e.var("ly_x", e.ld(e.add(_g(e, G_BLIST), p["ly_q"])))
                    e.if_(e.eq(_f(e, p["ly_x"], B_PLACED), 0), lambda: (_ok(e, e.lt(p["ly_sp"], p["ly_cap"])),
                                                                        e.st(e.add(p["ly_pending"], p["ly_sp"]), p["ly_x"]), e.set("ly_sp", e.add(p["ly_sp"], 1))))

                e.while_(lambda: e.ne(p["ly_q"], 0), each)

            e.if_(e.eq(p["ly_sp"], 0), rest)

        e.while_(lambda: e.ne(p["ly_sp"], 0), chain)
        _ok(e, e.eq(p["ly_count"], p["ly_n"]))
        _globals(e, G_BLIST, p["ly_order"])
        e.give(1)
    return _function((), build, tables)


# -- the view of one function --------------------------------------------------------------------------

def _out(e: E, word):
    p = e.p
    e.var("vo_at", _g(e, G_VIEW_OUT))
    _ok(e, e.lt(p["vo_at"], VIEW_END))
    e.st(p["vo_at"], word)
    _globals(e, G_VIEW_OUT, e.add(p["vo_at"], 1))


def _out_value(e: E, value):
    """A value as its four position words (tag, block, index, result)."""
    p = e.p
    e.var("ov_pos", _vf(e, G_VPOS, value))
    _ok(e, e.ne(p["ov_pos"], NONE))
    pos = p["ov_pos"]
    _out(e, e.udiv(pos, POS_TAG))
    _out(e, e.and_(e.udiv(pos, POS_BLOCK), (1 << 22) - 1))
    _out(e, e.and_(e.udiv(pos, POS_INDEX), (1 << 24) - 1))
    _out(e, e.and_(pos, (1 << 16) - 1))


def _simplify(e: E, with_fold: bool):
    """``while merge or thread [or fold] or stores or locals or dead: pass``."""
    p = e.p
    e.var("sp_go", 1)
    names = ["merge", "thread", *(("fold",) if with_fold else ()), "stores", "locals", "dead"]

    def round_():
        e.var("sp_hit", 0)
        for name in names:
            e.if_(e.eq(p["sp_hit"], 0), lambda name=name: e.set("sp_hit", _call_value(e, name)))
        e.set("sp_go", p["sp_hit"])

    e.while_(lambda: e.ne(p["sp_go"], 0), round_)


def _call_value(e: E, name: str):
    """A call whose 0 or 1 result is a value (NONE still declines)."""
    result = e.call(_FN[name])
    _ok(e, e.ne(result, NONE))
    return result


def _view(tables):
    """``inline_leaf_calls`` of function ``f`` (image index ``fidx``), written to the view output."""
    def build(e: E):
        p = e.p
        from xax_selfhost_general_emit import E_FAIL
        from xax_selfhost_general_regalloc import _ra

        e.if_(e.ne(_ra(e, E_FAIL), 0), lambda: e.give(1))  # S12f.2: an earlier function was rejected
        _globals(e, G_VCOUNT, 0)
        _globals(e, G_FKEYN, 0)
        e.var("vw_blocks", _call(e, "lift", p["f"], p["fidx"]))
        e.var("vw_n", e.rd(_at(e, G_PAY, e.ld(_call(e, "interface", p["f"])))))
        e.var("vw_graph", e.ld(_call(e, "interface", p["f"])))
        _globals(e, G_BENTRY, _g(e, G_LIFT_ENTRY))
        e.var("vw_list", e.alloc(e.add(p["vw_n"], 1)))
        _ok(e, e.ne(p["vw_list"], NONE))
        e.for_("vw_q", 0, p["vw_n"], lambda: e.st(e.add(p["vw_list"], p["vw_q"]), e.ld(e.add(p["vw_blocks"], p["vw_q"]))))
        _globals(e, G_BLIST, p["vw_list"])
        _globals(e, G_BCOUNT, p["vw_n"])
        # S12f.3 (ADR-279): ``_compile_function`` first proves every atomic node's capability on the function's graph.
        _call(e, "atomic_check", p["f"])
        e.if_(e.ne(_ra(e, E_FAIL), 0), lambda: e.give(1))
        # Any candidate in the original graph?
        e.var("vw_any", 0)

        def scan():
            e.var("vw_b", e.ld(e.add(p["vw_blocks"], p["vw_q"])))

            def node():
                e.var("vw_node", e.ld(e.add(_f(e, p["vw_b"], B_NODES), p["vw_m"])))
                e.var("vw_c", _call(e, "node_callee", p["vw_node"]))
                e.if_(e.ne(p["vw_c"], NOT_CALL), lambda: e.if_(e.ne(_call(e, "candidate", p["vw_c"], _f(e, p["vw_node"], N_NRES)), 0),
                                                            lambda: e.set("vw_any", 1)))

            e.for_("vw_m", 0, _f(e, p["vw_b"], B_NNODES), node)

        e.for_("vw_q", 0, p["vw_n"], scan)

        def inline():
            e.var("vw_go", 1)

            def once():
                e.set("vw_go", 0)
                e.var("vw_q", 0)
                e.var("vw_count", _g(e, G_BCOUNT))
                e.var("vw_snapshot", _g(e, G_BLIST))  # ``for block in list(blocks)``

                def block():
                    e.var("vw_b", e.ld(e.add(p["vw_snapshot"], p["vw_q"])))
                    e.var("vw_m", 0)

                    def node():
                        e.var("vw_node", e.ld(e.add(_f(e, p["vw_b"], B_NODES), p["vw_m"])))
                        e.var("vw_c", _call(e, "node_callee", p["vw_node"]))

                        def check():
                            e.if_(e.ne(_call(e, "candidate", p["vw_c"], _f(e, p["vw_node"], N_NRES)), 0), lambda: (
                                _call(e, "splice", p["vw_b"], p["vw_m"], p["vw_c"]), e.set("vw_go", 1)))

                        e.if_(e.ne(p["vw_c"], NOT_CALL), check)
                        e.set("vw_m", e.add(p["vw_m"], 1))

                    e.while_(lambda: e.both(e.eq(p["vw_go"], 0), e.lt(p["vw_m"], _f(e, p["vw_b"], B_NNODES))), node)
                    e.set("vw_q", e.add(p["vw_q"], 1))

                e.while_(lambda: e.both(e.eq(p["vw_go"], 0), e.lt(p["vw_q"], p["vw_count"])), block)

            e.while_(lambda: e.ne(p["vw_go"], 0), once)
            _simplify(e, True)

        e.if_(e.ne(p["vw_any"], 0), inline, lambda: _simplify(e, False))
        _call(e, "layout")
        # S12c.1 (ADR-270): prefetch selection on the laid-out view, when its values are all bounded exactly.
        _call(e, "positions")
        e.var("vw_facts", e.call(_FN["value_facts"]))
        e.if_(e.ne(p["vw_facts"], NONE), lambda: _call(e, "prefetch"))
        _out(e, p["fidx"])
        _call(e, "lower")
        _write_marks(e, e.ne(p["vw_facts"], NONE))
        e.if_(e.ne(_g(e, G_AUDIT), 0), lambda: _write_audit(e, e.ne(p["vw_facts"], NONE)))
        # S12c.2 (ADR-271): the register-resident analyses of the final view (when its values are bounded exactly).
        from xax_selfhost_general_regalloc import STATUS_INELIGIBLE, STATUS_UNDECIDED

        e.var("vw_status", STATUS_UNDECIDED)
        from xax_selfhost_x86_64_general import G_RAWWIN

        # S15f.2: a Windows load image has no register-resident lowering (``target.abi`` is neither Linux nor the PE profile).
        e.if_(e.both(e.ne(p["vw_facts"], NONE), e.eq(_g(e, G_RAWWIN), 0)), lambda: e.set("vw_status", _call(e, "analyse", p["f"])))
        e.if_(e.ne(_g(e, G_RAWWIN), 0), lambda: e.set("vw_status", STATUS_INELIGIBLE))
        e.if_(e.ne(_g(e, G_AUDIT), 0), lambda: _call(e, "write_analysis", p["vw_status"]))
        # S12d (ADR-272): the function's register-resident code (0 not decided, 1 not this path, 2 emitted).
        from xax_selfhost_general_regalloc import STATUS_ANALYSED, STATUS_INELIGIBLE

        e.var("vw_emit", 0)
        e.if_(e.eq(p["vw_status"], STATUS_INELIGIBLE), lambda: e.set("vw_emit", 1))

        def emit():
            e.var("vw_code", e.call(_FN["emit_function"], p["f"]))
            e.if_(e.eq(p["vw_code"], 0), lambda: e.set("vw_emit", 1), lambda: e.if_(e.eq(p["vw_code"], 1), lambda: e.set("vw_emit", 2)))

        e.if_(e.eq(p["vw_status"], STATUS_ANALYSED), emit)
        from xax_selfhost_general_emit import E_FAIL
        from xax_selfhost_general_regalloc import _ra

        # S12f (ADR-275): the frame lowering where the bootstrap takes it (not after a rejection, S12f.2).
        e.if_(e.eq(_ra(e, E_FAIL), 0), lambda: e.set("vw_emit", _call(e, "frame_fallback", p["f"], p["fidx"], p["vw_status"], p["vw_emit"])))
        _call(e, "write_emission", p["vw_emit"])
        from xax_selfhost_general_image import I_OK
        from xax_selfhost_general_regalloc import _set_ra

        e.if_(e.eq(p["vw_emit"], 2), lambda: _call(e, "image_add", p["fidx"]), lambda: _set_ra(e, I_OK, 0))
        e.give(1)
    return _function(("f", "fidx"), build, tables)


def _write_audit(e: E, decided):
    """S12c.1 audit (tests only): whether the bounds were computed, then for every value of the final view (per block
    in order: parameters, then node outputs) its ``upper_bounds`` with bits widths: a none flag and the bound."""
    from xax_selfhost_general_ranges import G2_RNONE, G2_WBITS, G2_WIDTHS, _g2, _set_g2

    p = e.p
    e.var("au_decided", e.flag(decided))
    _out(e, p["au_decided"])

    def audit():
        _set_g2(e, G2_WIDTHS, _g2(e, G2_WBITS))
        _call(e, "bounds")

        def value(v):
            e.var("au_v", v)
            e.var("au_b", e.call(_FN["maximum0"], p["au_v"]))
            _out(e, _g2(e, G2_RNONE))
            _out(e, p["au_b"])

        def block():
            e.var("au_blk", e.ld(e.add(_g(e, G_BLIST), p["au_q"])))
            e.for_("au_k", 0, _f(e, p["au_blk"], B_NP), lambda: value(e.ld(e.add(_f(e, p["au_blk"], B_INPUTS), p["au_k"]))))

            def node():
                e.var("au_n", e.ld(e.add(_f(e, p["au_blk"], B_NODES), p["au_m"])))
                e.for_("au_r", 0, _f(e, p["au_n"], N_NRES), lambda: value(_output(e, p["au_n"], p["au_r"])))

            e.for_("au_m", 0, _f(e, p["au_blk"], B_NNODES), node)

        e.for_("au_q", 0, _g(e, G_BCOUNT), block)

    e.if_(e.ne(p["au_decided"], 0), audit)


def _write_marks(e: E, decided):
    """After a view: whether the prefetch was decided here (else the host selects it), then the marks: the appended
    load's result, and its (array pointer, scale) prefetches."""
    from xax_selfhost_general_ranges import G2_MARKS, G2_NMARKS, MARK_WORDS, _g2

    p = e.p
    e.var("wm_decided", e.flag(decided))
    _out(e, p["wm_decided"])
    e.var("wm_n", e.mul(p["wm_decided"], _g2(e, G2_NMARKS)))
    _out(e, p["wm_n"])

    def mark():
        e.var("wm_at", e.add(_g2(e, G2_MARKS), e.mul(p["wm_q"], MARK_WORDS)))
        _out_value(e, e.ld(p["wm_at"]))
        e.var("wm_list", e.ld(e.add(p["wm_at"], 1)))
        e.var("wm_count", e.ld(e.add(p["wm_at"], 2)))
        _out(e, p["wm_count"])
        e.for_("wm_k", 0, p["wm_count"], lambda: (_out_value(e, e.ld(e.add(p["wm_list"], e.mul(p["wm_k"], 2)))),
                                                   _out(e, e.ld(e.add(p["wm_list"], e.add(e.mul(p["wm_k"], 2), 1))))))

    e.for_("wm_q", 0, p["wm_n"], mark)


