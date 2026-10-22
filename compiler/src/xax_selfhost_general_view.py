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

from xax_compiler import Kind, Operation, TerminatorKind
from xax_selfhost_facts import E, H_ARENA, NONE, _function
from xax_selfhost_views_backend import (
    _FN, CID_WORDS, G_NI, G_PAY, NI_ATTRIBUTES, NI_ENTITY, NI_OPERANDS, NI_RESULTS, _at, _call, _g, _kind, _ok, _payload_uleb,
    _reference, _type_form,
)

INLINE_NODE_LIMIT = 256
VIEW_AT, VIEW_END = 32 << 20, 120 << 20  # S14a (ADR-284): the compiler's own closure (above the front end's globals); S15d.0 (ADR-303): 36M words; S15e.4 (ADR-322): 41M; S15f (ADR-323): 88M
VCAP = 1 << 18  # values per function view
MAX_HOPS = 8

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
B_WORDS = 24
# Scratch fields every new block record starts with cleared (the output view is reused between runs).
B_SCRATCH = (B_POS, B_PLACED, B_INCOMING, B_MARK, B_DIST, B_SNAP_SRC, B_SNAP_ARGS)
EDGE = 3  # target block, argument count, arguments
CALLS = (int(Operation.CALL_GROUP_MEMBER), int(Operation.CALL_DIRECT), int(Operation.CALL_FOREIGN), int(Operation.CALL_INDIRECT))
PURE = tuple(int(op) for op in (
    Operation.CONSTANT, Operation.ADD_WRAP, Operation.SUB_WRAP, Operation.MUL_WRAP, Operation.BIT_XOR, Operation.BIT_AND,
    Operation.BIT_OR, Operation.INT_COMPARE, Operation.INT_TRUNCATE, Operation.INT_ZERO_EXTEND, Operation.ROTATE_RIGHT,
    Operation.ADDRESS_OFFSET, Operation.POINTER_CAST, Operation.POINTER_ADDRESS,
))
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


def _lift(tables):
    """``xax_inline._lift`` of function ``f`` (closure index ``fidx``): its blocks as records, in graph order, with
    fresh values; the block array (``G_LIFT_ENTRY`` gets the entry block)."""
    def build(e: E):
        p = e.p
        iface = _call(e, "interface", p["f"])
        e.var("lg", e.ld(iface))
        e.var("ls", _at(e, G_PAY, p["lg"]))
        e.var("lnb", e.rd(p["ls"]))
        e.var("la", e.alloc(e.add(p["lnb"], 1)))
        _ok(e, e.both(e.ne(p["la"], NONE), e.ne(p["lnb"], 0), e.lt(e.rd(e.add(p["ls"], 1)), p["lnb"])))
        e.var("lat", e.add(p["ls"], 2))

        def block():
            e.var("lb", e.alloc(B_WORDS))
            _ok(e, e.ne(p["lb"], NONE))
            e.st(e.add(p["la"], p["bq"]), p["lb"])
            for field, value in ((B_KIND0, 0), (B_FN, p["fidx"]), (B_BB, p["bq"]), (B_NN, NONE), (B_PFN, p["fidx"]), (B_PB, p["bq"]),
                                 (B_GRAPH, p["lg"]), *((field, 0) for field in B_SCRATCH)):
                _set(e, p["lb"], field, value)
            e.var("lnp", e.rd(p["lat"]))
            e.set("lat", e.add(p["lat"], 1))
            _set(e, p["lb"], B_NP, p["lnp"])
            e.var("lin", e.alloc(e.add(p["lnp"], 1)))
            _ok(e, e.ne(p["lin"], NONE))

            def parameter():
                _new_value(e, _reference(e, p["lg"], e.rd(e.add(p["lat"], p["pq"]))), "lv")
                _set_vf(e, G_VPARAM, p["lv"], p["lb"])
                e.st(e.add(p["lin"], p["pq"]), p["lv"])

            e.for_("pq", 0, p["lnp"], parameter)
            e.set("lat", e.add(p["lat"], p["lnp"]))
            _set(e, p["lb"], B_INPUTS, p["lin"])
            e.var("lnn", e.rd(p["lat"]))
            e.set("lat", e.add(p["lat"], 1))
            e.var("lnodes", e.alloc(e.add(p["lnn"], 1)))
            _ok(e, e.ne(p["lnodes"], NONE))

            def node():
                e.var("lstart", p["lat"])
                e.set("lat", _call(e, "node_info", p["lat"]))
                ni = _g(e, G_NI)
                e.var("lops_at", e.ld(e.add(ni, NI_OPERANDS)))
                e.var("lres_at", e.ld(e.add(ni, NI_RESULTS)))
                e.var("lnops", e.rd(p["lops_at"]))
                e.var("lnres", e.rd(p["lres_at"]))
                e.var("lnode", e.alloc(e.add(e.add(N_HDR, p["lnops"]), p["lnres"])))
                _ok(e, e.ne(p["lnode"], NONE))
                for field, value in ((N_FN, p["fidx"]), (N_B, p["bq"]), (N_N, p["nq"]), (N_OP, e.rd(p["lstart"])),
                                     (N_ATTR, e.ld(e.add(ni, NI_ATTRIBUTES))), (N_NOPS, p["lnops"]), (N_NRES, p["lnres"]),
                                     (N_OPSAT, p["lops_at"])):
                    _set(e, p["lnode"], field, value)
                _set(e, p["lnode"], N_GRAPH, p["lg"])

                def output():
                    _new_value(e, _reference(e, p["lg"], e.rd(e.add(e.add(p["lres_at"], 1), p["rq"]))), "lv")
                    _set_vf(e, G_VPROD, p["lv"], p["lnode"])
                    e.st(e.add(e.add(e.add(p["lnode"], N_HDR), p["lnops"]), p["rq"]), p["lv"])

                e.for_("rq", 0, p["lnres"], output)
                e.st(e.add(p["lnodes"], p["nq"]), p["lnode"])

            e.for_("nq", 0, p["lnn"], node)
            _set(e, p["lb"], B_NODES, p["lnodes"])
            _set(e, p["lb"], B_NNODES, p["lnn"])
            _set(e, p["lb"], B_TERM, p["lat"])
            _set(e, p["lb"], B_KIND, e.rd(p["lat"]))
            e.set("lat", _call(e, "term_end", p["lat"]))

        e.for_("bq", 0, p["lnb"], block)

        # Wire operands and terminators (values may be defined in later blocks).
        def wire():
            e.var("wb", e.ld(e.add(p["la"], p["bq"])))

            def node():
                e.var("wn", e.ld(e.add(_f(e, p["wb"], B_NODES), p["nq"])))
                e.var("wat", e.add(_f(e, p["wn"], N_OPSAT), 1))
                e.var("wv", 0)

                def operand():
                    _read_value(e, "wat", "wv")
                    e.st(e.add(e.add(p["wn"], N_HDR), p["oq"]), p["wv"])

                e.for_("oq", 0, _f(e, p["wn"], N_NOPS), operand)

            e.for_("nq", 0, _f(e, p["wb"], B_NNODES), node)
            e.var("tat", _f(e, p["wb"], B_TERM))
            e.var("tkind", e.rd(p["tat"]))
            e.set("tat", e.add(p["tat"], 1))
            e.var("tv", 0)
            e.var("tvalues", e.alloc(2))
            e.var("tnv", 0)
            e.var("tedges", e.alloc(2 * EDGE))
            e.var("tne", 0)
            _ok(e, e.both(e.ne(p["tvalues"], NONE), e.ne(p["tedges"], NONE)))

            def edge():
                at = e.add(p["tedges"], e.mul(p["tne"], EDGE))
                e.var("te", at)
                _set(e, p["te"], 0, e.ld(e.add(p["la"], e.rd(p["tat"]))))
                e.var("tna", e.rd(e.add(p["tat"], 1)))
                e.set("tat", e.add(p["tat"], 2))
                e.var("targs", e.alloc(e.add(p["tna"], 1)))
                _ok(e, e.ne(p["targs"], NONE))

                def argument():
                    _read_value(e, "tat", "tv")
                    e.st(e.add(p["targs"], p["aq"]), p["tv"])

                e.for_("aq", 0, p["tna"], argument)
                _set(e, p["te"], 1, p["tna"])
                _set(e, p["te"], 2, p["targs"])
                e.set("tne", e.add(p["tne"], 1))

            def returns():
                e.var("tcount", e.rd(p["tat"]))
                e.set("tat", e.add(p["tat"], 1))
                e.set("tvalues", e.alloc(e.add(p["tcount"], 1)))
                _ok(e, e.ne(p["tvalues"], NONE))

                def value():
                    _read_value(e, "tat", "tv")
                    e.st(e.add(p["tvalues"], p["vq"]), p["tv"])

                e.for_("vq", 0, p["tcount"], value)
                e.set("tnv", p["tcount"])

            def conditional():
                _read_value(e, "tat", "tv")
                e.st(p["tvalues"], p["tv"])
                e.set("tnv", 1)
                edge()
                edge()

            e.if_(e.eq(p["tkind"], BRANCH), edge, lambda: e.if_(e.eq(p["tkind"], CONDITIONAL), conditional, lambda: e.if_(
                e.eq(p["tkind"], RETURN), returns)))
            for field, value in ((B_VALUES, p["tvalues"]), (B_NVALUES, p["tnv"]), (B_EDGES, p["tedges"]), (B_NEDGES, p["tne"])):
                _set(e, p["wb"], field, value)
            # A trap's payload, like every terminator's, stays its origin block's (empty for the other kinds).
            e.if_(e.ne(p["tkind"], TRAP), lambda: (_set(e, p["wb"], B_PFN, NONE), _set(e, p["wb"], B_PB, NONE)))

        e.for_("bq", 0, p["lnb"], wire)

        # The verifier's pointer extents of this graph.
        e.var("xat", e.ld(e.add(_g(e, G_GEXT), p["lg"])))

        def extents():
            e.var("xn", e.rd(p["xat"]))
            e.set("xat", e.add(p["xat"], 1))
            e.var("xv", 0)

            def one():
                _read_value(e, "xat", "xv", fixed=True)
                _set_vf(e, G_VEXT, p["xv"], e.rd(p["xat"]))
                e.set("xat", e.add(p["xat"], 1))

            e.for_("xq", 0, p["xn"], one)

        e.if_(e.ne(p["xat"], NONE), extents)
        from xax_selfhost_views_backend import GLOBALS

        e.st(GLOBALS + G_LIFT_ENTRY, e.ld(e.add(p["la"], e.rd(e.add(p["ls"], 1)))))
        e.give(p["la"])
    return _function(("f", "fidx"), build, tables)


# -- inlining ------------------------------------------------------------------------------------------

def _candidate(tables):
    """``_inline_candidate`` for a ``call.direct`` of object ``c`` with ``nres`` results: 1 or 0 (the callee-only part
    cached per object in ``G_CAND``)."""
    def build(e: E):
        p = e.p
        _ok(e, e.eq(_kind(e, p["c"]), int(Kind.FUNCTION)))  # a graph-fragment callee: the bootstrap cannot inline-check it
        cache = e.add(_g(e, G_CAND), p["c"])
        e.var("cv", e.ld(cache))

        def compute():
            e.var("cok", 1)
            e.if_(e.ne(_call(e, "erased", p["c"]), 0), lambda: e.set("cok", 0))
            iface = _call(e, "interface", p["c"])
            from xax_selfhost_x86_64_general import G_GROUPOF

            e.if_(e.ne(e.ld(e.add(_g(e, G_GROUPOF), p["c"])), NONE), lambda: e.set("cok", 0))
            e.var("cs", _at(e, G_PAY, e.ld(iface)))
            e.var("cat", e.add(p["cs"], 2))
            e.var("cnodes", 0)

            def block():
                e.set("cat", e.add(e.add(p["cat"], 1), e.rd(p["cat"])))
                e.var("cn", e.rd(p["cat"]))
                e.set("cat", e.add(p["cat"], 1))
                e.set("cnodes", e.add(p["cnodes"], p["cn"]))

                def node():
                    op = e.rd(p["cat"])
                    e.if_(e.either(*(e.eq(op, call) for call in CALLS)), lambda: e.set("cok", 0))
                    e.set("cat", _call(e, "node_info", p["cat"]))

                e.for_("cm", 0, p["cn"], node)
                e.set("cat", _call(e, "term_end", p["cat"]))

            e.for_("cb", 0, e.rd(p["cs"]), block)
            e.if_(e.lt(INLINE_NODE_LIMIT, p["cnodes"]), lambda: e.set("cok", 0))
            e.st(cache, p["cok"])
            e.set("cv", p["cok"])

        e.if_(e.eq(p["cv"], NONE), compute)
        e.if_(e.eq(p["cv"], 0), lambda: e.give(0))
        # Every return gives as many values as the call has results.
        e.var("cs", _at(e, G_PAY, e.ld(_call(e, "interface", p["c"]))))
        e.var("cat", e.add(p["cs"], 2))
        e.var("cret", 1)

        def block():
            e.set("cat", e.add(e.add(p["cat"], 1), e.rd(p["cat"])))
            e.var("cn", e.rd(p["cat"]))
            e.set("cat", e.add(p["cat"], 1))
            e.for_("cm", 0, p["cn"], lambda: e.set("cat", _call(e, "node_info", p["cat"])))
            e.if_(e.both(e.eq(e.rd(p["cat"]), RETURN), e.ne(e.rd(e.add(p["cat"], 1)), p["nres"])), lambda: e.set("cret", 0))
            e.set("cat", _call(e, "term_end", p["cat"]))

        e.for_("cb", 0, e.rd(p["cs"]), block)
        e.give(p["cret"])
    return _function(("c", "nres"), build, tables)


def _node_callee(tables):
    """The object index lifted ``call.direct`` node ``n`` calls (resolved in the node's own graph), or ``NOT_CALL``."""
    def build(e: E):
        p = e.p
        e.if_(e.ne(_f(e, p["n"], N_OP), int(Operation.CALL_DIRECT)), lambda: e.give(NOT_CALL))
        entity = e.rd(e.sub(_f(e, p["n"], N_OPSAT), 1))  # the entity reference precedes the operand count
        e.var("nc_c", _reference(e, _f(e, p["n"], N_GRAPH), entity))
        _ok(e, e.ne(p["nc_c"], NONE))
        e.give(p["nc_c"])
    return _function(("n",), build, tables)


def _list_insert(e: E, after_block, items, count):
    """Insert ``count`` block records from array ``items`` into the block list after ``after_block``."""
    p = e.p
    e.var("li_n", _g(e, G_BCOUNT))
    e.var("li_new", e.alloc(e.add(e.add(p["li_n"], count), 1)))
    _ok(e, e.ne(p["li_new"], NONE))
    e.var("li_w", 0)

    def each():
        e.var("li_b", e.ld(e.add(_g(e, G_BLIST), p["li_q"])))
        e.st(e.add(p["li_new"], p["li_w"]), p["li_b"])
        e.set("li_w", e.add(p["li_w"], 1))

        def insert():
            e.for_("li_k", 0, count, lambda: (e.st(e.add(p["li_new"], p["li_w"]), e.ld(e.add(items, p["li_k"]))), e.set("li_w", e.add(p["li_w"], 1))))

        e.if_(e.eq(p["li_b"], after_block), insert)

    e.for_("li_q", 0, p["li_n"], each)
    _globals(e, G_BLIST, p["li_new"])
    _globals(e, G_BCOUNT, p["li_w"])


def _splice(tables):
    """``xax_inline._splice``: inline callee ``c`` at node position ``pos`` of block ``b``."""
    def build(e: E):
        p = e.p
        e.var("sitem", e.ld(e.add(_f(e, p["b"], B_NODES), p["pos"])))
        item = p["sitem"]
        e.var("snops", _f(e, item, N_NOPS))
        e.var("snres", _f(e, item, N_NRES))
        e.var("sinner", _call(e, "lift", p["c"], e.ld(e.add(_g(e, G_CIDX), p["c"]))))
        e.var("sentry", _g(e, G_LIFT_ENTRY))
        _ok(e, e.eq(_f(e, p["sentry"], B_NP), p["snops"]))  # the bootstrap raises here; never for a verified call
        e.var("sinner_n", e.rd(_at(e, G_PAY, e.ld(_call(e, "interface", p["c"])))))
        # The continuation: the call's results as parameters, the rest of the block, the block's terminator.
        e.var("scont", e.alloc(B_WORDS))
        _ok(e, e.ne(p["scont"], NONE))
        cont = p["scont"]
        for field, value in ((B_KIND0, 1), (B_FN, _f(e, item, N_FN)), (B_BB, _f(e, item, N_B)), (B_NN, _f(e, item, N_N)), (B_NP, p["snres"]),
                             (B_GRAPH, _f(e, p["b"], B_GRAPH)), *((field, 0) for field in B_SCRATCH)):
            _set(e, cont, field, value)
        e.var("sin", e.alloc(e.add(p["snres"], 1)))
        _ok(e, e.ne(p["sin"], NONE))

        def parameter():
            result = e.ld(e.add(e.add(e.add(item, N_HDR), p["snops"]), p["q"]))
            e.var("sres", result)
            _new_value(e, _vf(e, G_VTYPE, p["sres"]), "sv")
            _set_vf(e, G_VPARAM, p["sv"], cont)
            e.st(e.add(p["sin"], p["q"]), p["sv"])
            # _carry_extent(result, parameter)
            e.if_(e.both(e.eq(_vf(e, G_VEXT, p["sv"]), NONE), e.ne(_vf(e, G_VEXT, p["sres"]), NONE)),
                  lambda: _set_vf(e, G_VEXT, p["sv"], _vf(e, G_VEXT, p["sres"])))

        e.for_("q", 0, p["snres"], parameter)
        _set(e, cont, B_INPUTS, p["sin"])
        e.var("snn", _f(e, p["b"], B_NNODES))
        e.var("srest", e.alloc(e.add(e.sub(p["snn"], p["pos"]), 1)))
        _ok(e, e.ne(p["srest"], NONE))
        e.for_("q", e.add(p["pos"], 1), p["snn"], lambda: e.st(e.add(p["srest"], e.sub(e.sub(p["q"], p["pos"]), 1)),
                                                               e.ld(e.add(_f(e, p["b"], B_NODES), p["q"]))))
        _set(e, cont, B_NODES, p["srest"])
        _set(e, cont, B_NNODES, e.sub(e.sub(p["snn"], p["pos"]), 1))
        for field in (B_KIND, B_VALUES, B_NVALUES, B_EDGES, B_NEDGES, B_PFN, B_PB):
            _set(e, cont, field, _f(e, p["b"], field))
        # The block now ends by branching to the callee's entry with the call's operands.
        _set(e, p["b"], B_NNODES, p["pos"])
        e.var("sedge", e.alloc(EDGE))
        e.var("sargs", e.alloc(e.add(p["snops"], 1)))
        _ok(e, e.both(e.ne(p["sedge"], NONE), e.ne(p["sargs"], NONE)))
        e.for_("q", 0, p["snops"], lambda: e.st(e.add(p["sargs"], p["q"]), e.ld(e.add(e.add(item, N_HDR), p["q"]))))
        for field, value in ((0, p["sentry"]), (1, p["snops"]), (2, p["sargs"])):
            _set(e, p["sedge"], field, value)
        for field, value in ((B_KIND, BRANCH), (B_NVALUES, 0), (B_EDGES, p["sedge"]), (B_NEDGES, 1), (B_PFN, NONE), (B_PB, NONE)):
            _set(e, p["b"], field, value)

        # Every callee return branches to the continuation with its values.
        def callee_block():
            e.var("cb", e.ld(e.add(p["sinner"], p["q"])))

            def retarget():
                e.var("redge", e.alloc(EDGE))
                _ok(e, e.ne(p["redge"], NONE))
                for field, value in ((0, cont), (1, _f(e, p["cb"], B_NVALUES)), (2, _f(e, p["cb"], B_VALUES))):
                    _set(e, p["redge"], field, value)
                for field, value in ((B_KIND, BRANCH), (B_EDGES, p["redge"]), (B_NEDGES, 1), (B_NVALUES, 0)):
                    _set(e, p["cb"], field, value)

            e.if_(e.eq(_f(e, p["cb"], B_KIND), RETURN), retarget)

        e.for_("q", 0, p["sinner_n"], callee_block)
        e.st(e.add(p["sinner"], p["sinner_n"]), cont)
        _list_insert(e, p["b"], p["sinner"], e.add(p["sinner_n"], 1))
        # The call's results are the continuation's parameters.
        e.for_("q", 0, p["snres"], lambda: _map(e, e.ld(e.add(e.add(e.add(item, N_HDR), p["snops"]), p["q"])), e.ld(e.add(p["sin"], p["q"]))))
        _call(e, "replace_uses")
        e.give(1)
    return _function(("b", "pos", "c"), build, tables)


# -- value replacement ---------------------------------------------------------------------------------

def _map(e: E, key, value):
    """Record ``key -> value`` for the next ``replace_uses``."""
    keys = _g(e, G_FKEYS)
    n = _g(e, G_FKEYN)
    e.var("mk_n", n)
    _ok(e, e.lt(e.p["mk_n"], VCAP))
    e.st(e.add(keys, e.p["mk_n"]), key)
    _globals(e, G_FKEYN, e.add(e.p["mk_n"], 1))
    _set_vf(e, G_VFWD, key, value)


def _resolve(tables):
    def build(e: E):
        p = e.p
        e.var("rs", p["v"])
        e.while_(lambda: e.ne(_vf(e, G_VFWD, p["rs"]), NONE), lambda: e.set("rs", _vf(e, G_VFWD, p["rs"])))
        e.give(p["rs"])
    return _function(("v",), build, tables)


def _each_use(e: E, visit, *, edges_in_place=True):
    """Call ``visit(array, index)`` for every node operand, terminator value, and edge argument of every block."""
    p = e.p

    def block():
        e.var("eu_b", e.ld(e.add(_g(e, G_BLIST), p["eu_q"])))

        def node():
            e.var("eu_n", e.ld(e.add(_f(e, p["eu_b"], B_NODES), p["eu_m"])))
            e.for_("eu_o", 0, _f(e, p["eu_n"], N_NOPS), lambda: visit(e.add(p["eu_n"], N_HDR), p["eu_o"], p["eu_b"]))

        e.for_("eu_m", 0, _f(e, p["eu_b"], B_NNODES), node)
        e.for_("eu_o", 0, _f(e, p["eu_b"], B_NVALUES), lambda: visit(_f(e, p["eu_b"], B_VALUES), p["eu_o"], p["eu_b"]))

        def edge():
            e.var("eu_e", e.add(_f(e, p["eu_b"], B_EDGES), e.mul(p["eu_k"], EDGE)))
            e.for_("eu_o", 0, _f(e, p["eu_e"], 1), lambda: visit(_f(e, p["eu_e"], 2), p["eu_o"], p["eu_b"]))

        e.for_("eu_k", 0, _f(e, p["eu_b"], B_NEDGES), edge)

    e.for_("eu_q", 0, _g(e, G_BCOUNT), block)


def _replace_uses(tables):
    """``xax_inline._replace_uses`` with the recorded mapping (chains followed), then the mapping cleared."""
    def build(e: E):
        p = e.p

        def visit(array, index, _block):
            e.var("ru_at", e.add(array, index))
            e.st(p["ru_at"], _call(e, "resolve", e.ld(p["ru_at"])))

        _each_use(e, visit)
        e.for_("ru_k", 0, _g(e, G_FKEYN), lambda: _set_vf(e, G_VFWD, e.ld(e.add(_g(e, G_FKEYS), p["ru_k"])), NONE))
        _globals(e, G_FKEYN, 0)
        e.give(1)
    return _function((), build, tables)


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


def _merge(tables):
    """``_merge_blocks``: the first block (list order) ending in a branch to a block with one predecessor edge, which
    is neither the entry nor itself, absorbs it.  1 when merged."""
    def build(e: E):
        p = e.p
        _count_incoming(e)
        e.var("mg_found", NONE)

        def block():
            e.var("mg_b", e.ld(e.add(_g(e, G_BLIST), p["mg_q"])))

            def branch():
                e.var("mg_t", _f(e, _f(e, p["mg_b"], B_EDGES), 0))
                ok = e.both(e.ne(p["mg_t"], _g(e, G_BENTRY)), e.ne(p["mg_t"], p["mg_b"]), e.eq(_f(e, p["mg_t"], B_INCOMING), 1))
                e.if_(ok, lambda: e.set("mg_found", p["mg_b"]))

            e.if_(e.both(e.eq(p["mg_found"], NONE), e.eq(_f(e, p["mg_b"], B_KIND), BRANCH)), branch)

        e.for_("mg_q", 0, _g(e, G_BCOUNT), block)
        e.if_(e.eq(p["mg_found"], NONE), lambda: e.give(0))
        b = p["mg_found"]
        e.var("mg_edge", _f(e, b, B_EDGES))
        e.var("mg_t", _f(e, p["mg_edge"], 0))
        t = p["mg_t"]
        e.for_("mg_k", 0, _f(e, t, B_NP), lambda: _carry(e, e.ld(e.add(_f(e, t, B_INPUTS), p["mg_k"])), e.ld(e.add(_f(e, p["mg_edge"], 2), p["mg_k"]))))
        e.for_("mg_k", 0, _f(e, t, B_NP), lambda: _map(e, e.ld(e.add(_f(e, t, B_INPUTS), p["mg_k"])), e.ld(e.add(_f(e, p["mg_edge"], 2), p["mg_k"]))))
        # Concatenate the node lists; take the target's terminator.
        e.var("mg_n1", _f(e, b, B_NNODES))
        e.var("mg_n2", _f(e, t, B_NNODES))
        e.var("mg_nodes", e.alloc(e.add(e.add(p["mg_n1"], p["mg_n2"]), 1)))
        _ok(e, e.ne(p["mg_nodes"], NONE))
        e.for_("mg_k", 0, p["mg_n1"], lambda: e.st(e.add(p["mg_nodes"], p["mg_k"]), e.ld(e.add(_f(e, b, B_NODES), p["mg_k"]))))
        e.for_("mg_k", 0, p["mg_n2"], lambda: e.st(e.add(p["mg_nodes"], e.add(p["mg_n1"], p["mg_k"])), e.ld(e.add(_f(e, t, B_NODES), p["mg_k"]))))
        _set(e, b, B_NODES, p["mg_nodes"])
        _set(e, b, B_NNODES, e.add(p["mg_n1"], p["mg_n2"]))
        for field in (B_KIND, B_VALUES, B_NVALUES, B_EDGES, B_NEDGES, B_PFN, B_PB):
            _set(e, b, field, _f(e, t, field))
        # Remove the target from the list.
        e.var("mg_w", 0)

        def keep():
            e.var("mg_x", e.ld(e.add(_g(e, G_BLIST), p["mg_q"])))
            e.if_(e.ne(p["mg_x"], t), lambda: (e.st(e.add(_g(e, G_BLIST), p["mg_w"]), p["mg_x"]), e.set("mg_w", e.add(p["mg_w"], 1))))

        e.for_("mg_q", 0, _g(e, G_BCOUNT), keep)
        _globals(e, G_BCOUNT, p["mg_w"])
        _call(e, "replace_uses")
        e.give(1)
    return _function((), build, tables)


def _thread(tables):
    """``_thread_jumps``: edges into parameter-forwarding empty branch blocks go straight on (at most 8 hops), then
    blocks unreachable from the entry are dropped.  1 when changed."""
    def build(e: E):
        p = e.p
        # Readers: each value's first reading block, and whether a second block reads it.
        e.var("th_n", _g(e, G_VCOUNT))
        e.for_("th_v", 0, p["th_n"], lambda: (_set_vf(e, G_VREAD, p["th_v"], NONE), _set_vf(e, G_VMULTI, p["th_v"], 0)))

        def read(array, index, block):
            e.var("th_r", e.ld(e.add(array, index)))
            first = _vf(e, G_VREAD, p["th_r"])
            e.var("th_first", first)
            e.if_(e.eq(p["th_first"], NONE), lambda: _set_vf(e, G_VREAD, p["th_r"], block),
                  lambda: e.if_(e.ne(p["th_first"], block), lambda: _set_vf(e, G_VMULTI, p["th_r"], 1)))

        _each_use(e, read)
        e.var("th_changed", 0)

        def elsewhere(parameter, owner):
            """A forwarding block's parameter read by another block (or by more than one)."""
            reader = _vf(e, G_VREAD, parameter)
            return e.either(e.ne(_vf(e, G_VMULTI, parameter), 0), e.both(e.ne(reader, NONE), e.ne(reader, owner)))

        def block():
            e.var("th_b", e.ld(e.add(_g(e, G_BLIST), p["th_q"])))

            def edge():
                e.var("th_e", e.add(_f(e, p["th_b"], B_EDGES), e.mul(p["th_k"], EDGE)))
                e.var("th_t", _f(e, p["th_e"], 0))
                e.var("th_nargs", _f(e, p["th_e"], 1))
                e.var("th_args", _f(e, p["th_e"], 2))
                e.var("th_hops", 0)
                e.var("th_go", 1)

                def hop():
                    t = p["th_t"]
                    e.var("th_read", 0)
                    e.for_("th_p", 0, _f(e, t, B_NP), lambda: e.if_(elsewhere(e.ld(e.add(_f(e, t, B_INPUTS), p["th_p"])), t),
                                                                    lambda: e.set("th_read", 1)))
                    forwarding = e.both(e.ne(t, _g(e, G_BENTRY)), e.eq(_f(e, t, B_NNODES), 0), e.eq(_f(e, t, B_KIND), BRANCH),
                                        e.ne(_f(e, _f(e, t, B_EDGES), 0), t), e.lt(p["th_hops"], MAX_HOPS), e.eq(p["th_read"], 0))

                    def go():
                        e.var("th_next", _f(e, t, B_EDGES))
                        e.var("th_fn", _f(e, p["th_next"], 1))
                        e.var("th_new", e.alloc(e.add(p["th_fn"], 1)))
                        _ok(e, e.ne(p["th_new"], NONE))

                        def forward():
                            e.var("th_fv", e.ld(e.add(_f(e, p["th_next"], 2), p["th_a"])))
                            e.var("th_mapped", p["th_fv"])
                            e.for_("th_p", 0, _f(e, t, B_NP), lambda: e.if_(
                                e.eq(e.ld(e.add(_f(e, t, B_INPUTS), p["th_p"])), p["th_fv"]),
                                lambda: e.set("th_mapped", e.ld(e.add(p["th_args"], p["th_p"])))))
                            e.st(e.add(p["th_new"], p["th_a"]), p["th_mapped"])

                        e.for_("th_a", 0, p["th_fn"], forward)
                        e.set("th_args", p["th_new"])
                        e.set("th_nargs", p["th_fn"])
                        e.set("th_t", _f(e, p["th_next"], 0))
                        e.set("th_hops", e.add(p["th_hops"], 1))
                        e.set("th_changed", 1)

                    e.if_(forwarding, go, lambda: e.set("th_go", 0))

                e.while_(lambda: e.ne(p["th_go"], 0), hop)
                for field, name in ((0, "th_t"), (1, "th_nargs"), (2, "th_args")):
                    _set(e, p["th_e"], field, p[name])

            e.for_("th_k", 0, _f(e, p["th_b"], B_NEDGES), edge)

        e.for_("th_q", 0, _g(e, G_BCOUNT), block)
        # Drop blocks unreachable from the entry.
        e.for_("th_q", 0, _g(e, G_BCOUNT), lambda: _set(e, e.ld(e.add(_g(e, G_BLIST), p["th_q"])), B_MARK, 0))
        e.var("th_stack", e.alloc(e.add(_g(e, G_BCOUNT), 1)))
        _ok(e, e.ne(p["th_stack"], NONE))
        e.st(p["th_stack"], _g(e, G_BENTRY))
        _set(e, _g(e, G_BENTRY), B_MARK, 1)
        e.var("th_sp", 1)

        def visit():
            e.set("th_sp", e.sub(p["th_sp"], 1))
            e.var("th_x", e.ld(e.add(p["th_stack"], p["th_sp"])))

            def edge():
                e.var("th_y", _f(e, e.add(_f(e, p["th_x"], B_EDGES), e.mul(p["th_k"], EDGE)), 0))
                e.if_(e.eq(_f(e, p["th_y"], B_MARK), 0), lambda: (_set(e, p["th_y"], B_MARK, 1), e.st(e.add(p["th_stack"], p["th_sp"]), p["th_y"]),
                                                                  e.set("th_sp", e.add(p["th_sp"], 1))))

            e.for_("th_k", 0, _f(e, p["th_x"], B_NEDGES), edge)

        e.while_(lambda: e.ne(p["th_sp"], 0), visit)
        e.var("th_w", 0)

        def keep():
            e.var("th_x", e.ld(e.add(_g(e, G_BLIST), p["th_q"])))
            e.if_(e.ne(_f(e, p["th_x"], B_MARK), 0), lambda: (e.st(e.add(_g(e, G_BLIST), p["th_w"]), p["th_x"]), e.set("th_w", e.add(p["th_w"], 1))))

        e.for_("th_q", 0, _g(e, G_BCOUNT), keep)
        e.if_(e.ne(p["th_w"], _g(e, G_BCOUNT)), lambda: e.set("th_changed", 1))
        _globals(e, G_BCOUNT, p["th_w"])
        e.give(p["th_changed"])
    return _function((), build, tables)


def _width32(e: E, value):
    """``_bits32_width_of``: a produced value's producer has a ``bits<32>`` first result; a parameter is ``bits<32>``."""
    producer = _vf(e, G_VPROD, value)
    known = e.ne(producer, NONE)
    first = _output(e, e.sel(known, producer, 0), 0)
    typed = e.sel(known, first, value)
    return e.eq(_bits_width(e, _vf(e, G_VTYPE, typed)), 32)


def _producer_op(e: E, value):
    """The raw operation of ``value``'s producer node, or NONE for a parameter."""
    producer = _vf(e, G_VPROD, value)
    known = e.ne(producer, NONE)
    return e.sel(known, _f(e, e.sel(known, producer, 0), N_OP), NONE)


def _single_attribute(e: E, node, value: int):
    """``node.attributes == (value,)``."""
    at = _f(e, node, N_ATTR)
    known = e.ne(at, NONE)
    safe = e.sel(known, at, 0)
    return e.both(known, e.eq(e.rd(safe), 1), e.eq(e.rd(e.add(safe, 1)), value))


def _operand(e: E, node, k):
    return e.ld(e.add(e.add(node, N_HDR), k))


def _output(e: E, node, k):
    return e.ld(e.add(e.add(e.add(node, N_HDR), _f(e, node, N_NOPS)), k))


def _mark_used(e: E):
    """Stamp every used value (operands, terminator values, edge arguments) with a fresh ``G_VSTAMP2`` mark; the mark."""
    p = e.p
    _globals(e, G_STAMP, e.add(_g(e, G_STAMP), 1))
    e.var("mu_s", _g(e, G_STAMP))
    _each_use(e, lambda array, index, _block: _set_vf(e, G_VSTAMP2, e.ld(e.add(array, index)), p["mu_s"]))
    return p["mu_s"]


def _unpack(tables):
    """``_fold_pack``'s ``unpack``: for ``zext(lo) | ror(zext(hi), 32)`` with 32-bit ``lo``/``hi``, ``lo`` (and ``hi`` in
    ``G_FKEYS``' scratch word ``VCAP``); ``NOT_CALL`` otherwise."""
    def build(e: E):
        p = e.p
        e.var("up_or", _vf(e, G_VPROD, p["v"]))
        e.if_(e.eq(p["up_or"], NONE), lambda: e.give(NOT_CALL))
        e.if_(e.ne(_f(e, p["up_or"], N_OP), int(Operation.BIT_OR)), lambda: e.give(NOT_CALL))
        e.var("up_low", _vf(e, G_VPROD, _operand(e, p["up_or"], 0)))
        e.var("up_high", _vf(e, G_VPROD, _operand(e, p["up_or"], 1)))
        e.if_(e.either(e.eq(p["up_low"], NONE), e.eq(p["up_high"], NONE)), lambda: e.give(NOT_CALL))
        e.if_(e.ne(_f(e, p["up_low"], N_OP), int(Operation.INT_ZERO_EXTEND)), lambda: e.give(NOT_CALL))
        e.if_(e.ne(_f(e, p["up_high"], N_OP), int(Operation.ROTATE_RIGHT)), lambda: e.give(NOT_CALL))
        e.if_(e.not_(_single_attribute(e, p["up_high"], 32)), lambda: e.give(NOT_CALL))
        e.var("up_wide", _vf(e, G_VPROD, _operand(e, p["up_high"], 0)))
        e.if_(e.eq(p["up_wide"], NONE), lambda: e.give(NOT_CALL))
        e.if_(e.ne(_f(e, p["up_wide"], N_OP), int(Operation.INT_ZERO_EXTEND)), lambda: e.give(NOT_CALL))
        e.var("up_lo", _operand(e, p["up_low"], 0))
        e.var("up_hi", _operand(e, p["up_wide"], 0))
        e.if_(e.not_(e.both(_width32(e, p["up_lo"]), _width32(e, p["up_hi"]))), lambda: e.give(NOT_CALL))
        e.st(e.add(_g(e, G_FKEYS), VCAP), p["up_hi"])
        e.give(p["up_lo"])
    return _function(("v",), build, tables)


def _fold(tables):
    """``_fold_pack``: a used ``bits<32>`` truncation of a packed pair (or of the pair rotated by 32) is the half."""
    def build(e: E):
        p = e.p
        e.var("fp_used", _mark_used(e))
        e.var("fp_any", 0)

        def block():
            e.var("fp_b", e.ld(e.add(_g(e, G_BLIST), p["fp_q"])))

            def node():
                e.var("fp_n", e.ld(e.add(_f(e, p["fp_b"], B_NODES), p["fp_m"])))
                n = p["fp_n"]

                def candidate():
                    e.var("fp_out", _output(e, n, 0))
                    used = e.eq(_vf(e, G_VSTAMP2, p["fp_out"]), p["fp_used"])
                    wide32 = _width32(e, p["fp_out"])

                    def fold():
                        e.var("fp_src", _operand(e, n, 0))
                        e.var("fp_rot", _vf(e, G_VPROD, p["fp_src"]))
                        rotated = e.both(e.ne(p["fp_rot"], NONE), e.eq(_producer_op(e, p["fp_src"]), int(Operation.ROTATE_RIGHT)))
                        e.var("fp_isrot", e.flag(rotated))
                        e.if_(e.ne(p["fp_isrot"], 0), lambda: e.set("fp_isrot", e.flag(_single_attribute(e, p["fp_rot"], 32))))

                        def high():
                            e.var("fp_lo", _call(e, "unpack", _operand(e, p["fp_rot"], 0)))
                            e.if_(e.ne(p["fp_lo"], NOT_CALL), lambda: (_map(e, p["fp_out"], e.ld(e.add(_g(e, G_FKEYS), VCAP))), e.set("fp_any", 1)))

                        def low():
                            e.var("fp_lo", _call(e, "unpack", p["fp_src"]))
                            e.if_(e.ne(p["fp_lo"], NOT_CALL), lambda: (_map(e, p["fp_out"], p["fp_lo"]), e.set("fp_any", 1)))

                        e.if_(e.ne(p["fp_isrot"], 0), high, low)

                    e.if_(e.both(used, wide32), fold)

                e.if_(e.eq(_f(e, n, N_OP), int(Operation.INT_TRUNCATE)), candidate)

            e.for_("fp_m", 0, _f(e, p["fp_b"], B_NNODES), node)

        e.for_("fp_q", 0, _g(e, G_BCOUNT), block)
        e.if_(e.ne(p["fp_any"], 0), lambda: _call(e, "replace_uses"), lambda: _globals(e, G_FKEYN, 0))
        e.give(p["fp_any"])
    return _function((), build, tables)


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


def _locals(tables):
    """``_local_parameters`` (ADR-212): in a block entered by exactly one edge from another block, values that edge
    passes are read through the block's own parameters.  Edge argument arrays are never changed in place here, so the
    incoming edge seen at the start (``B_SNAP_SRC``, ``B_SNAP_ARGS``) keeps its arguments."""
    def build(e: E):
        p = e.p
        e.var("lp_changed", 0)
        # Snapshot: per block, its single incoming edge (source block, arguments) or a count.
        _count_incoming(e)

        def block():
            e.var("lp_b", e.ld(e.add(_g(e, G_BLIST), p["lp_q"])))

            def edge():
                e.var("lp_e", e.add(_f(e, p["lp_b"], B_EDGES), e.mul(p["lp_k"], EDGE)))
                e.var("lp_t", _f(e, p["lp_e"], 0))
                e.if_(e.eq(_f(e, p["lp_t"], B_INCOMING), 1), lambda: (_set(e, p["lp_t"], B_SNAP_SRC, p["lp_b"]),
                                                                        _set(e, p["lp_t"], B_SNAP_ARGS, _f(e, p["lp_e"], 2))))

            e.for_("lp_k", 0, _f(e, p["lp_b"], B_NEDGES), edge)

        e.for_("lp_q", 0, _g(e, G_BCOUNT), block)

        def rewrite():
            e.var("lp_b", e.ld(e.add(_g(e, G_BLIST), p["lp_q"])))
            b = p["lp_b"]
            single = e.both(e.ne(b, _g(e, G_BENTRY)), e.eq(_f(e, b, B_INCOMING), 1))

            def local():
                e.var("lp_src", _f(e, b, B_SNAP_SRC))
                e.var("lp_args", _f(e, b, B_SNAP_ARGS))

                def mapped():
                    # Mapping: argument -> parameter (first occurrence; an argument that is its own parameter skipped).
                    e.var("lp_any", 0)

                    def pair():
                        e.var("lp_param", e.ld(e.add(_f(e, b, B_INPUTS), p["lp_k"])))
                        e.var("lp_arg", e.ld(e.add(p["lp_args"], p["lp_k"])))
                        fresh = e.both(e.ne(p["lp_arg"], p["lp_param"]), e.eq(_vf(e, G_VFWD, p["lp_arg"]), NONE))
                        e.if_(fresh, lambda: (_map(e, p["lp_arg"], p["lp_param"]), e.set("lp_any", 1)))

                    e.for_("lp_k", 0, _f(e, b, B_NP), pair)

                    def apply():
                        def node():
                            e.var("lp_n", e.ld(e.add(_f(e, b, B_NODES), p["lp_m"])))

                            def operand():
                                e.var("lp_at", e.add(e.add(p["lp_n"], N_HDR), p["lp_o"]))
                                e.var("lp_old", e.ld(p["lp_at"]))
                                e.var("lp_new", _vf(e, G_VFWD, p["lp_old"]))
                                e.if_(e.ne(p["lp_new"], NONE), lambda: (e.st(p["lp_at"], p["lp_new"]), e.set("lp_changed", 1)))

                            e.for_("lp_o", 0, _f(e, p["lp_n"], N_NOPS), operand)

                        e.for_("lp_m", 0, _f(e, b, B_NNODES), node)

                        def fresh_array(source, count, store):
                            """A copy of ``count`` values from ``source`` with the mapping applied (when anything maps)."""
                            e.var("lp_hit", 0)
                            e.for_("lp_o", 0, count, lambda: e.if_(e.ne(_vf(e, G_VFWD, e.ld(e.add(source, p["lp_o"]))), NONE), lambda: e.set("lp_hit", 1)))

                            def copy():
                                e.var("lp_copy", e.alloc(e.add(count, 1)))
                                _ok(e, e.ne(p["lp_copy"], NONE))

                                def one():
                                    e.var("lp_v", e.ld(e.add(source, p["lp_o"])))
                                    e.var("lp_w", _vf(e, G_VFWD, p["lp_v"]))
                                    e.st(e.add(p["lp_copy"], p["lp_o"]), e.sel(e.eq(p["lp_w"], NONE), p["lp_v"], p["lp_w"]))

                                e.for_("lp_o", 0, count, one)
                                store(p["lp_copy"])
                                e.set("lp_changed", 1)

                            e.if_(e.ne(p["lp_hit"], 0), copy)

                        fresh_array(_f(e, b, B_VALUES), _f(e, b, B_NVALUES), lambda copy: _set(e, b, B_VALUES, copy))

                        def edge():
                            e.var("lp_e", e.add(_f(e, b, B_EDGES), e.mul(p["lp_k"], EDGE)))
                            fresh_array(_f(e, p["lp_e"], 2), _f(e, p["lp_e"], 1), lambda copy: _set(e, p["lp_e"], 2, copy))

                        e.for_("lp_k", 0, _f(e, b, B_NEDGES), edge)
                        e.for_("lp_k", 0, _f(e, b, B_NP), lambda: _carry(e, e.ld(e.add(p["lp_args"], p["lp_k"])), e.ld(e.add(_f(e, b, B_INPUTS), p["lp_k"]))))

                    e.if_(e.ne(p["lp_any"], 0), apply)
                    # Clear the mapping (it is local to this block).
                    e.for_("lp_k", 0, _g(e, G_FKEYN), lambda: _set_vf(e, G_VFWD, e.ld(e.add(_g(e, G_FKEYS), p["lp_k"])), NONE))
                    _globals(e, G_FKEYN, 0)

                e.if_(e.ne(p["lp_src"], b), mapped)

            e.if_(single, local)

        e.for_("lp_q", 0, _g(e, G_BCOUNT), rewrite)
        e.give(p["lp_changed"])
    return _function((), build, tables)


def _dead(tables):
    """``_dead_code``: pure nodes none of whose outputs is used are deleted (one pass over every block)."""
    def build(e: E):
        p = e.p
        e.var("dc_used", _mark_used(e))
        e.var("dc_changed", 0)

        def block():
            e.var("dc_b", e.ld(e.add(_g(e, G_BLIST), p["dc_q"])))
            e.var("dc_w", 0)
            e.var("dc_nodes", _f(e, p["dc_b"], B_NODES))

            def node():
                e.var("dc_n", e.ld(e.add(p["dc_nodes"], p["dc_m"])))
                op = _f(e, p["dc_n"], N_OP)
                pure = e.either(*(e.eq(op, item) for item in PURE))
                e.var("dc_live", e.flag(e.not_(pure)))
                e.for_("dc_r", 0, _f(e, p["dc_n"], N_NRES), lambda: e.if_(e.eq(_vf(e, G_VSTAMP2, _output(e, p["dc_n"], p["dc_r"])), p["dc_used"]),
                                                                           lambda: e.set("dc_live", 1)))
                e.if_(e.ne(p["dc_live"], 0), lambda: (e.st(e.add(p["dc_nodes"], p["dc_w"]), p["dc_n"]), e.set("dc_w", e.add(p["dc_w"], 1))))

            e.for_("dc_m", 0, _f(e, p["dc_b"], B_NNODES), node)
            e.if_(e.ne(p["dc_w"], _f(e, p["dc_b"], B_NNODES)), lambda: (_set(e, p["dc_b"], B_NNODES, p["dc_w"]), e.set("dc_changed", 1)))

        e.for_("dc_q", 0, _g(e, G_BCOUNT), block)
        e.give(p["dc_changed"])
    return _function((), build, tables)


# -- layout ---------------------------------------------------------------------------------------------

def _distance(tables):
    """``_layout``'s ``distance(start, goal)``: edges from ``start`` back to ``goal`` (breadth first), FAR when ``goal``
    is not reachable from ``start`` (``start`` itself counts only when it is ``goal``)."""
    def build(e: E):
        p = e.p
        e.if_(e.eq(p["s"], p["g"]), lambda: e.give(0))
        n = _g(e, G_BCOUNT)
        e.var("ds_queue", e.alloc(e.add(n, 1)))
        _ok(e, e.ne(p["ds_queue"], NONE))
        e.var("ds_mark", e.add(_g(e, G_STAMP), 1))
        _globals(e, G_STAMP, p["ds_mark"])
        # Breadth first from ``start``; levels by distance.
        e.st(p["ds_queue"], p["s"])
        _set(e, p["s"], B_DIST, p["ds_mark"])
        e.var("ds_head", 0)
        e.var("ds_tail", 1)
        e.var("ds_level_end", 1)
        e.var("ds_steps", 0)
        e.var("ds_found", FAR)

        def step():
            e.var("ds_x", e.ld(e.add(p["ds_queue"], p["ds_head"])))
            e.set("ds_head", e.add(p["ds_head"], 1))

            def edge():
                e.var("ds_y", _f(e, e.add(_f(e, p["ds_x"], B_EDGES), e.mul(p["ds_k"], EDGE)), 0))

                def fresh():
                    _set(e, p["ds_y"], B_DIST, p["ds_mark"])
                    e.st(e.add(p["ds_queue"], p["ds_tail"]), p["ds_y"])
                    e.set("ds_tail", e.add(p["ds_tail"], 1))

                e.if_(e.both(e.eq(p["ds_found"], FAR), e.eq(p["ds_y"], p["g"])), lambda: e.set("ds_found", e.add(p["ds_steps"], 1)))
                e.if_(e.ne(_f(e, p["ds_y"], B_DIST), p["ds_mark"]), fresh)

            e.for_("ds_k", 0, _f(e, p["ds_x"], B_NEDGES), edge)
            e.if_(e.eq(p["ds_head"], p["ds_level_end"]), lambda: (e.set("ds_level_end", p["ds_tail"]), e.set("ds_steps", e.add(p["ds_steps"], 1))))

        e.while_(lambda: e.both(e.eq(p["ds_found"], FAR), e.lt(p["ds_head"], p["ds_tail"])), step)
        e.give(p["ds_found"])
    return _function(("s", "g"), build, tables)


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


def _positions(tables):
    """``xax_inline._lower``'s positions: every value's (tag, block, index, result) in the final block order."""
    def build(e: E):
        p = e.p
        e.for_("lw_v", 0, _g(e, G_VCOUNT), lambda: _set_vf(e, G_VPOS, p["lw_v"], NONE))

        def position():
            e.var("lw_b", e.ld(e.add(_g(e, G_BLIST), p["lw_q"])))
            _set(e, p["lw_b"], B_POS, p["lw_q"])
            _ok(e, e.both(e.lt(p["lw_q"], 1 << 22), e.lt(_f(e, p["lw_b"], B_NNODES), 1 << 24)))
            e.for_("lw_k", 0, _f(e, p["lw_b"], B_NP), lambda: _set_vf(e, G_VPOS, e.ld(e.add(_f(e, p["lw_b"], B_INPUTS), p["lw_k"])),
                                                                     e.add(e.mul(p["lw_q"], POS_BLOCK), e.mul(p["lw_k"], POS_INDEX))))

            def node():
                e.var("lw_n", e.ld(e.add(_f(e, p["lw_b"], B_NODES), p["lw_m"])))
                e.for_("lw_r", 0, _f(e, p["lw_n"], N_NRES), lambda: _set_vf(
                    e, G_VPOS, _output(e, p["lw_n"], p["lw_r"]),
                    e.add(e.add(e.add(POS_TAG, e.mul(p["lw_q"], POS_BLOCK)), e.mul(p["lw_m"], POS_INDEX)), p["lw_r"])))

            e.for_("lw_m", 0, _f(e, p["lw_b"], B_NNODES), node)

        e.for_("lw_q", 0, _g(e, G_BCOUNT), position)
        e.give(1)
    return _function((), build, tables)


def _lower(tables):
    """``xax_inline._lower``: positions in the final block order, then the view's words (module docstring)."""
    def build(e: E):
        p = e.p
        _call(e, "positions")
        _out(e, _f(e, _g(e, G_BENTRY), B_POS))
        _out(e, _g(e, G_BCOUNT))

        def block():
            e.var("lw_b", e.ld(e.add(_g(e, G_BLIST), p["lw_q"])))
            b = p["lw_b"]
            for field in (B_KIND0, B_FN, B_BB, B_NN, B_NNODES):
                _out(e, _f(e, b, field))

            def node():
                e.var("lw_n", e.ld(e.add(_f(e, b, B_NODES), p["lw_m"])))
                for field in (N_FN, N_B, N_N, N_NOPS):
                    _out(e, _f(e, p["lw_n"], field))
                e.for_("lw_o", 0, _f(e, p["lw_n"], N_NOPS), lambda: _out_value(e, _operand(e, p["lw_n"], p["lw_o"])))

            e.for_("lw_m", 0, _f(e, b, B_NNODES), node)
            for field in (B_KIND, B_PFN, B_PB, B_NVALUES):
                _out(e, _f(e, b, field))
            e.for_("lw_o", 0, _f(e, b, B_NVALUES), lambda: _out_value(e, e.ld(e.add(_f(e, b, B_VALUES), p["lw_o"]))))
            _out(e, _f(e, b, B_NEDGES))

            def edge():
                e.var("lw_e", e.add(_f(e, b, B_EDGES), e.mul(p["lw_k"], EDGE)))
                _out(e, _f(e, _f(e, p["lw_e"], 0), B_POS))
                _out(e, _f(e, p["lw_e"], 1))
                e.for_("lw_o", 0, _f(e, p["lw_e"], 1), lambda: _out_value(e, e.ld(e.add(_f(e, p["lw_e"], 2), p["lw_o"]))))

            e.for_("lw_k", 0, _f(e, b, B_NEDGES), edge)

        e.for_("lw_q", 0, _g(e, G_BCOUNT), block)
        # Extents: per block in order, parameters then node outputs.
        e.var("lw_ext_at", _g(e, G_VIEW_OUT))
        _out(e, 0)
        e.var("lw_next", 0)

        def extent(value):
            e.var("lw_x", value)

            def write():
                _out_value(e, p["lw_x"])
                _out(e, _vf(e, G_VEXT, p["lw_x"]))
                e.set("lw_next", e.add(p["lw_next"], 1))

            e.if_(e.ne(_vf(e, G_VEXT, p["lw_x"]), NONE), write)

        def block_extents():
            e.var("lw_b", e.ld(e.add(_g(e, G_BLIST), p["lw_q"])))
            e.for_("lw_k", 0, _f(e, p["lw_b"], B_NP), lambda: extent(e.ld(e.add(_f(e, p["lw_b"], B_INPUTS), p["lw_k"]))))

            def node():
                e.var("lw_n", e.ld(e.add(_f(e, p["lw_b"], B_NODES), p["lw_m"])))
                e.for_("lw_r", 0, _f(e, p["lw_n"], N_NRES), lambda: extent(_output(e, p["lw_n"], p["lw_r"])))

            e.for_("lw_m", 0, _f(e, p["lw_b"], B_NNODES), node)

        e.for_("lw_q", 0, _g(e, G_BCOUNT), block_extents)
        e.st(p["lw_ext_at"], p["lw_next"])
        e.give(1)
    return _function((), build, tables)


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


def add_view_functions(add, tables):
    """Add the S12b functions to a program under construction (``add(name, (function, objects))``)."""
    add("lift", _lift(tables))
    add("resolve", _resolve(tables))
    add("replace_uses", _replace_uses(tables))
    add("node_callee", _node_callee(tables))
    add("candidate", _candidate(tables))
    add("splice", _splice(tables))
    add("merge", _merge(tables))
    add("thread", _thread(tables))
    add("unpack", _unpack(tables))
    add("fold", _fold(tables))
    add("stores", _stores(tables))
    add("locals", _locals(tables))
    add("dead", _dead(tables))
    add("distance", _distance(tables))
    add("layout", _layout(tables))
    add("positions", _positions(tables))
    add("lower", _lower(tables))
    from xax_selfhost_general_ranges import add_range_functions
    from xax_selfhost_general_regalloc import add_regalloc_functions

    add_range_functions(add, tables)
    add_regalloc_functions(add, tables)
    from xax_selfhost_general_rejects import add_reject_functions

    add_reject_functions(add, tables)  # S15b.4: before the emission and frame paths that call them
    from xax_selfhost_general_emit import add_emit_functions

    add_emit_functions(add, tables)
    from xax_selfhost_general_frame import add_frame_functions
    from xax_selfhost_general_image import add_image_functions

    add_frame_functions(add, tables)

    add_image_functions(add, tables)
    add("write_analysis", _writer(tables, "analysis"))
    add("write_emission", _writer(tables, "emission"))
    add("view", _view(tables))


def _writer(tables, kind: str):
    """The S12c.2 analysis audit record or the S12d emission record of the function just lowered (``status``)."""
    from xax_selfhost_general_emit import write_emission
    from xax_selfhost_general_regalloc import _write_analysis

    def build(e: E):
        p = e.p
        if kind == "analysis":
            _write_analysis(e, lambda w: _out(e, w), lambda v: _out_value(e, v), p["status"])
        else:
            write_emission(e, lambda w: _out(e, w), p["status"])
        e.give(1)
    return _function(("status",), build, tables)


def views_prologue(e: E, total, order, members):
    """After the front end: allocate the view tables, index the extents section, and lower every closure function's
    view in image order.  ``total`` objects; ``order`` the image order; ``members`` its length; the extents section
    starts at input word ``p["ext_at"]``."""
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
    # Extents section: count, then per graph: four CID words, count, (tag, block, index, result, extent) each.
    e.var("vp_at", p["ext_at"])
    e.var("vp_n", e.rd(p["vp_at"]))
    e.set("vp_at", e.add(p["vp_at"], 1))

    def graph():
        e.var("vp_g", e.call(_FN["find"], p["vp_at"]))
        e.set("vp_at", e.add(p["vp_at"], CID_WORDS))
        e.if_(e.ne(p["vp_g"], NONE), lambda: e.st(e.add(_g(e, G_GEXT), p["vp_g"]), p["vp_at"]))
        e.set("vp_at", e.add(e.add(p["vp_at"], 1), e.mul(e.rd(p["vp_at"]), 5)))

    e.for_("vp_k", 0, p["vp_n"], graph)
    # S12c.1: an audit flag follows the extents (1: also write every value's range bound after each view).
    _globals(e, G_AUDIT, e.rd(p["vp_at"]))
    # S12d: the trap payload heads follow (``general_object_table``).
    e.var("vp_traps", e.add(p["vp_at"], 1))
    _globals(e, G_VIEW_OUT, VIEW_AT)
    from xax_selfhost_general_emit import emit_prologue, set_trap_section
    from xax_selfhost_general_image import image_after_views, image_prologue
    from xax_selfhost_general_ranges import ranges_prologue
    from xax_selfhost_general_regalloc import regalloc_prologue

    ranges_prologue(e)
    regalloc_prologue(e)
    emit_prologue(e)
    set_trap_section(e, p["vp_traps"])
    image_prologue(e)

    def each():
        e.var("vp_mark", e.hd(H_ARENA))  # every allocation of a view is dead once it is written
        _call(e, "view", e.ld(e.add(order, p["vp_q"])), p["vp_q"])
        e.set_hd(H_ARENA, p["vp_mark"])

    e.for_("vp_q", 0, members, each)
    # S12e (ADR-273): the image and its container, when every function's code is the program's.
    image_after_views(e, members)
