"""Self-hosting step S12c.2 (ADR-271): the register-resident lowering's analyses as XAX semantics.

``xax_x86_64_regalloc.compile_register_resident`` lowers a function's view for the hosted x86-64 profiles.  Before it
emits a byte it decides, from the view alone: whether the function is eligible (every machine value a scalar of at
most 64 bits, every operation one it lowers), each value's machine width, the constants, the stack storage, the
block parameters proven nonzero by their edges, value ranges over the machine widths, the compares fused into their
branch, the predicate tables (ADR-208) for branches and values, the membership bit tests (ADR-131), the address
offsets folded into displacements, the checked indices folded into scaled addressing, the read-modify-write stores,
the compare loads, the edge-sunk additions (ADR-211), the borrowed-view call aliases (ADR-101), every value's uses
per block, the home slots, the pinned registers (ADR-091), the loop headers, the allocatable registers, the hoisted
64-bit constants, and the frame (shadow space, edge spills, homes, loop-parameter slots, stack storage).

This module adds those decisions to the S12 general backend program (``xax_x86_64_general.xax``), on the final view's
records (``xax_selfhost_general_view``, ``xax_selfhost_general_ranges``), in the bootstrap's order.  With the audit
flag the program writes them per function (``AUDIT`` order); ``xax_x86_64_regalloc.analysis_audit`` is the bootstrap's
record of the same decisions, and the two must be equal.  S12d emits the code from them.

Values are dense ids; a value's position is ``G_VPOS`` (tag, block, index, result), whose packed order is the
bootstrap's ``(tag, block, index, result)`` sort key.  Value-keyed decisions live in per-value tables (``_rt``);
block-keyed ones in per-block arrays; node-index sets (a membership tree, a table's erased nodes) as per-node flags of
their block.
"""

from __future__ import annotations

from xax_compiler import IntCompare, Operation, RESOURCE_EFFECT_OPERATIONS
from xax_selfhost_facts import E, H_ARENA, NONE, _function
from xax_selfhost_general_ranges import (
    G2_CONST, G2_CVAL, G2_RNONE, G2_SCRATCH, G2_WIDTHS, _attribute, _block_at, _g2, _is_param, _node_at, _pos_block, _pos_index, _pos_result,
    _set_g2, _t,
)
from xax_selfhost_general_view import (
    B_EDGES, B_INPUTS, B_KIND, B_NEDGES, B_NNODES, B_NODES, B_NP, B_NVALUES, B_POS, B_VALUES, BRANCH, CONDITIONAL, EDGE, G_BCOUNT,
    G_BENTRY, G_BLIST, G_VCOUNT, G_VPOS, G_VPROD, G_VTYPE, N_NOPS, N_NRES, N_OP, N_OPSAT, N_FN, NOT_CALL, RETURN, TRAP, VCAP, _f, _operand,
    _output, _set, _set_vf, _vf,
)
from xax_selfhost_views_backend import _FN, G_PAY, GLOBALS, _at, _call, _g, _ok, _payload_uleb, _type_form

G_RA = 60  # pointer to the register-allocation globals table (``_ra``/``_set_ra``)
RA_WORDS = 256
# Per-value tables (``_rt``): VCAP words each.
(T_RW, T_USES, T_EARLY, T_FOLD_BASE, T_FOLD_DISP, T_SCALE_BASE, T_SCALE, T_ERASED, T_RMW, T_RMW_ERASED, T_VT_SUBJECT, T_VT_TABLE,
 T_MV_SUBJECT, T_MV_LOW, T_MV_MASK, T_MEMBER_ERASED, T_TABLE_ERASED, T_CL, T_SINK_OPERAND, T_SINK_AMOUNT, T_ALIAS, T_HOME, T_PIN,
 T_PSLOT, T_STACK, T_NONZERO, T_MEMORY_USES, T_OTHER_USE, T_INDEX_USES, T_MPARAM) = range(30)
# Scratch per-value tables: T_S1/T_S2 stamps, T_S3 values (predicate tables), T_S4 a use-record index; T_USTAMP and
# T_UCOUNT are ``_uses``' own (a stamp must never be compared with a table that holds other numbers).
(T_S1, T_S2, T_S3, T_S4, T_USTAMP, T_UCOUNT, T_WEIGHT, T_WSTAMP, T_PARENT, T_CAND) = range(30, 40)
# S12d emission (``xax_selfhost_general_emit``): the register of a value, then fields valid while ``T_ESTAMP`` is current.
(T_REG, T_SPOFF, T_SPID, T_ESTAMP, T_ULIST, T_ULEN, T_HINT, T_EUSE) = range(40, 48)
# S12f frame lowering (``xax_selfhost_general_frame``): slot, layout size, frame pointer, heap root and offset, extent.
(T_FSLOT, T_FSIZE, T_FPTR, T_FHROOT, T_FHOFF, T_FEXT, T_FESC) = range(48, 55)
VALUE_TABLES = 55
# Register-allocation globals (``_ra``), after the value tables' pointers.
(R_ELIGIBLE, R_HAS_CALL, R_STACKS, R_NSTACKS, R_FUSED, R_BTAB, R_MEMB, R_CL_RECORDS, R_NHOMES, R_HOMES, R_LOOPHDR, R_ALLOC, R_NALLOC,
 R_HOISTED, R_NHOISTED, R_SHADOW, R_EDGE_SPILL_BASE, R_HOME_BASE, R_SLOT_BASE, R_NSLOTS, R_DYN_BASE, R_USES, R_OWN_ELIDED, R_NPARAMS,
 R_PARAMS, R_RETURNS, R_NRETURNS, R_STAMP, R_CYCLIC, R_MPARAMS) = range(VALUE_TABLES, VALUE_TABLES + 30)
assert R_MPARAMS < RA_WORDS

CALLEE_SAVED = (3, 5, 6, 7, 12, 13, 14, 15)
PINNABLE = (3, 5, 12, 13, 14, 15)
ARGUMENT_REGISTERS = (1, 2, 8, 9)  # the hosted x86-64 targets' (``decode_native_target``; checked by the front end)
SCRATCH_REGISTER, RESULT_REGISTER = 10, 0
CYCLE_WEIGHT = 8
ROTATE_LIMIT = 16
TABLE_SUBJECT_LIMIT = 256
TABLE_MIN_OPERATIONS = 3


def _op(name: Operation) -> int:
    return int(name)


PURE_BINARY = tuple(_op(op) for op in (Operation.ADD_WRAP, Operation.SUB_WRAP, Operation.MUL_WRAP, Operation.BIT_XOR, Operation.BIT_AND, Operation.BIT_OR))
COMMUTATIVE = tuple(_op(op) for op in (Operation.ADD_WRAP, Operation.MUL_WRAP, Operation.BIT_XOR, Operation.BIT_AND, Operation.BIT_OR))
COPY = tuple(_op(op) for op in (Operation.INT_ZERO_EXTEND, Operation.POINTER_CAST, Operation.LINK_MAKE))
MEMORY = tuple(_op(op) for op in (Operation.LOAD_BITS_LE, Operation.STORE_BITS_LE, Operation.CHECKED_LOAD_BITS_LE, Operation.CHECKED_STORE_BITS_LE,
                                  Operation.RAW_LOAD_BITS_LE))
CALLS = tuple(_op(op) for op in (Operation.CALL_DIRECT, Operation.CALL_FOREIGN, Operation.CALL_INDIRECT))
SUPPORTED = tuple(sorted({
    *PURE_BINARY, *COPY, *MEMORY, *(_op(op) for op in RESOURCE_EFFECT_OPERATIONS),
    *(_op(op) for op in (Operation.UDIV, Operation.UREM, Operation.CONSTANT, Operation.INT_COMPARE, Operation.INT_TRUNCATE, Operation.ROTATE_RIGHT,
                         Operation.ADDRESS_OFFSET, Operation.HEAP_VIEW, Operation.CALL_DIRECT, Operation.CALL_FOREIGN, Operation.POINTER_ADDRESS,
                         Operation.POINTER_REBASE, Operation.FUNCTION_ADDRESS, Operation.STACK_ALLOC, Operation.STACK_END, Operation.CALL_INDIRECT,
                         Operation.LINK_FOLLOW, Operation.LINK_TARGET)),
}))
TABLE_OPERATIONS = tuple(_op(op) for op in (Operation.INT_COMPARE, Operation.ADD_WRAP, Operation.SUB_WRAP, Operation.MUL_WRAP, Operation.BIT_AND,
                                            Operation.BIT_OR, Operation.BIT_XOR, Operation.INT_ZERO_EXTEND, Operation.INT_TRUNCATE))
ROTATABLE = tuple(sorted({_op(Operation.CONSTANT), _op(Operation.INT_COMPARE), *PURE_BINARY, *COPY, _op(Operation.INT_TRUNCATE),
                          _op(Operation.ROTATE_RIGHT), _op(Operation.ADDRESS_OFFSET), _op(Operation.LOAD_BITS_LE),
                          _op(Operation.CHECKED_LOAD_BITS_LE)}))
GROUP_CALL, DIRECT_CALL = _op(Operation.CALL_GROUP_MEMBER), _op(Operation.CALL_DIRECT)


# -- accessors -----------------------------------------------------------------------------------------------

def _ra(e: E, slot: int):
    return e.ld(e.add(_g(e, G_RA), slot))


def _set_ra(e: E, slot: int, value):
    e.st(e.add(_g(e, G_RA), slot), value)


def _rt(e: E, table: int, value):
    return e.ld(e.add(_ra(e, table), value))


def _set_rt(e: E, table: int, value, word):
    e.st(e.add(_ra(e, table), value), word)


def _eop(e: E, node):
    """The operation the bootstrap's view shows: a group-member call is a direct call (``parse_function_graph``)."""
    op = _f(e, node, N_OP)
    return e.sel(e.eq(op, GROUP_CALL), DIRECT_CALL, op)


def _in(e: E, value, items):
    return e.either(*(e.eq(value, item) for item in items))


def _key(e: E, value):
    """The bootstrap's ``(tag, block, index, result)`` order of a value: its packed position."""
    return _vf(e, G_VPOS, value)


def _width(e: E, value):
    """The value's machine width (``widths``), 0 when it has none."""
    return _rt(e, T_RW, value)


def _machine_width(e: E, type_obj):
    """``_eligible``'s ``machine_width``: bits<1..64> its width, a pointer or link 64; NONE otherwise (floats,
    aggregates, opaque values, wider bits)."""
    form = _type_form(e, type_obj)
    e.var("mw_form", form)
    e.var("mw_out", NONE)

    def bits():
        e.var("mw_at", e.add(_at(e, G_PAY, type_obj), 1))
        e.var("mw_w", _payload_uleb(e, "mw_at"))
        e.if_(e.both(e.ne(e.p["mw_w"], 0), e.le(e.p["mw_w"], 64)), lambda: e.set("mw_out", e.p["mw_w"]))

    e.if_(e.eq(e.p["mw_form"], 1), bits, lambda: e.if_(e.either(e.eq(e.p["mw_form"], 2), e.eq(e.p["mw_form"], 11)), lambda: e.set("mw_out", 64)))
    return e.p["mw_out"]


def _proof_type(e: E, type_obj):
    form = _type_form(e, type_obj)
    return e.either(e.eq(form, 3), e.eq(form, 4))


# -- eligibility (``_eligible``) -------------------------------------------------------------------------------

def _callee_object(e: E, node, name: str):
    """The function object a direct call (or a group-member call, as its direct call) of the view names, into
    ``name``; NONE when it names none."""
    from xax_selfhost_x86_64_general import G_GROUPOF, G_MTAB
    from xax_selfhost_general_view import G_CIDX, N_GRAPH
    from xax_selfhost_views_backend import G_ORDER, _reference

    p = e.p
    e.var(name, NONE)
    op = _f(e, node, N_OP)

    def direct():
        e.set(name, _reference(e, _f(e, node, N_GRAPH), e.rd(e.sub(_f(e, node, N_OPSAT), 1))))

    def member():
        owner = e.ld(e.add(_g(e, G_ORDER), _f(e, node, N_FN)))  # the node's origin function (image order)
        group = e.ld(e.add(_g(e, G_GROUPOF), owner))
        e.var(f"{name}_g", group)

        def known():
            members = e.ld(e.add(_g(e, G_MTAB), p[f"{name}_g"]))
            e.var(f"{name}_m", members)
            index = e.rd(e.sub(_f(e, node, N_OPSAT), 3))  # [4, member, span start, span end] precede the operands
            e.var(f"{name}_k", index)
            e.if_(e.both(e.ne(p[f"{name}_m"], NONE), e.lt(p[f"{name}_k"], e.ld(p[f"{name}_m"]))),
                  lambda: e.set(name, e.ld(e.add(e.add(p[f"{name}_m"], 1), p[f"{name}_k"]))))

        e.if_(e.ne(p[f"{name}_g"], NONE), known)

    e.if_(e.eq(op, DIRECT_CALL), direct, lambda: e.if_(e.eq(op, GROUP_CALL), member))
    del G_CIDX


def _node_types(e: E, node, results: bool):
    """The type object of a node's result (or operand) ``k``: the value's type."""
    return (lambda k: _vf(e, G_VTYPE, _output(e, node, k))) if results else (lambda k: _vf(e, G_VTYPE, _operand(e, node, k)))


def _eligible(tables):
    """``_eligible``: 1 when the function's view can be lowered here, with every machine value's width in ``T_RW``;
    0 when the bootstrap returns None (another path lowers it)."""
    def build(e: E):
        p = e.p
        n = _g(e, G_VCOUNT)
        e.for_("el_v", 0, n, lambda: _set_rt(e, T_RW, p["el_v"], 0))
        # The function's interface: at most four machine parameters and one machine result (borrowed views elided).
        e.var("el_np", _ra(e, R_NPARAMS))
        e.var("el_nr", _ra(e, R_NRETURNS))
        e.var("el_mp", 0)
        e.var("el_bad", 0)

        def parameter():
            t = e.ld(e.add(_ra(e, R_PARAMS), p["el_q"]))
            e.var("el_t", t)

            def machine():
                e.set("el_mp", e.add(p["el_mp"], 1))
                e.if_(e.eq(_machine_width(e, p["el_t"]), NONE), lambda: e.set("el_bad", 1))

            e.if_(e.not_(_proof_type(e, p["el_t"])), machine)

        e.for_("el_q", 0, p["el_np"], parameter)
        e.var("el_mr", 0)
        elided = _ra(e, R_OWN_ELIDED)

        def returned():
            t = e.ld(e.add(_ra(e, R_RETURNS), p["el_q"]))
            e.var("el_t", t)

            def machine():
                e.set("el_mr", e.add(p["el_mr"], 1))
                e.if_(e.eq(_machine_width(e, p["el_t"]), NONE), lambda: e.set("el_bad", 1))

            e.if_(e.both(e.not_(_proof_type(e, p["el_t"])), e.eq(e.ld(e.add(elided, p["el_q"])), NONE)), machine)

        e.for_("el_q", 0, p["el_nr"], returned)
        e.if_(e.either(e.lt(4, p["el_mp"]), e.lt(1, p["el_mr"]), e.ne(p["el_bad"], 0)), lambda: e.give(0))

        def block():
            e.var("el_b", _block_at(e, p["el_bi"]))
            # (every terminator kind is one of return, branch, conditional branch, trap)

            def parameter_width():
                e.var("el_pv", e.ld(e.add(_f(e, p["el_b"], B_INPUTS), p["el_k"])))
                e.var("el_pt", _vf(e, G_VTYPE, p["el_pv"]))

                def machine():
                    e.var("el_w", _machine_width(e, p["el_pt"]))
                    e.if_(e.eq(p["el_w"], NONE), lambda: e.give(0))
                    _set_rt(e, T_RW, p["el_pv"], p["el_w"])

                e.if_(e.not_(_proof_type(e, p["el_pt"])), machine)

            e.for_("el_k", 0, _f(e, p["el_b"], B_NP), parameter_width)

            def node():
                e.var("el_n", _node_at(e, p["el_b"], p["el_m"]))
                n_ = p["el_n"]
                e.var("el_op", _eop(e, n_))
                op = p["el_op"]
                e.if_(e.not_(_in(e, op, SUPPORTED)), lambda: e.give(0))

                def rotate():
                    e.var("el_rw", _machine_width(e, _vf(e, G_VTYPE, _output(e, n_, 0))))
                    e.if_(e.not_(e.either(e.eq(p["el_rw"], 32), e.eq(p["el_rw"], 64))), lambda: e.give(0))

                e.if_(e.eq(op, _op(Operation.ROTATE_RIGHT)), rotate)
                e.var("el_erased", 0)

                def direct():
                    _callee_object(e, n_, "el_callee")
                    e.if_(e.ne(p["el_callee"], NONE), lambda: e.set("el_erased", _call(e, "erased", p["el_callee"])))

                e.if_(e.eq(op, DIRECT_CALL), direct)

                def checked():
                    def call():
                        e.var("el_inputs", 0)

                        def operand():
                            e.var("el_ot", _vf(e, G_VTYPE, _operand(e, n_, p["el_o"])))

                            def machine():
                                e.set("el_inputs", e.add(p["el_inputs"], 1))
                                e.if_(e.eq(_machine_width(e, p["el_ot"]), NONE), lambda: e.give(0))

                            e.if_(e.not_(_proof_type(e, p["el_ot"])), machine)

                        e.for_("el_o", 0, _f(e, n_, N_NOPS), operand)
                        limit = e.add(4, e.flag(e.eq(op, _op(Operation.CALL_INDIRECT))))
                        e.if_(e.both(e.either(e.eq(op, DIRECT_CALL), e.eq(op, _op(Operation.CALL_INDIRECT))), e.lt(limit, p["el_inputs"])), lambda: e.give(0))

                    e.if_(_in(e, op, CALLS), call)

                    def result():
                        e.var("el_rv", _output(e, n_, p["el_r"]))
                        e.var("el_rt", _vf(e, G_VTYPE, p["el_rv"]))

                        def machine():
                            e.var("el_w", _machine_width(e, p["el_rt"]))
                            e.if_(e.eq(p["el_w"], NONE), lambda: e.give(0))
                            _set_rt(e, T_RW, p["el_rv"], p["el_w"])

                        e.if_(e.not_(_proof_type(e, p["el_rt"])), machine)

                    e.for_("el_r", 0, _f(e, n_, N_NRES), result)

                e.if_(e.eq(p["el_erased"], 0), checked)  # an erased proof call is skipped whole (``continue``)

            e.for_("el_m", 0, _f(e, p["el_b"], B_NNODES), node)

        e.for_("el_bi", 0, _g(e, G_BCOUNT), block)
        e.give(1)
    return _function((), build, tables)


# -- basic facts ------------------------------------------------------------------------------------------------



def _release(e: E, mark, result):
    """Return ``result`` after releasing every arena allocation made since ``mark`` (helpers run per value or per
    block, so scratch that does not escape would otherwise grow with their product)."""
    e.set_hd(H_ARENA, mark)
    e.give(result)


def _stamp(e: E):
    """A fresh stamp for the scratch tables."""
    _set_ra(e, R_STAMP, e.add(_ra(e, R_STAMP), 1))
    return _ra(e, R_STAMP)


def _constant(e: E, value):
    return e.ne(_t(e, G2_CONST, value), 0)


def _cval(e: E, value):
    return _t(e, G2_CVAL, value)


def _each_value_use(e: E, block, visit, *, terminator_values=True, edges=True):
    """``visit(value)`` for every operand of ``block``'s nodes, then (optionally) its terminator values, then its edge
    arguments."""
    p = e.p

    def node():
        e.var("vu_n", _node_at(e, block, p["vu_m"]))
        e.for_("vu_o", 0, _f(e, p["vu_n"], N_NOPS), lambda: visit(_operand(e, p["vu_n"], p["vu_o"])))

    e.for_("vu_m", 0, _f(e, block, B_NNODES), node)
    if terminator_values:
        e.for_("vu_o", 0, _f(e, block, B_NVALUES), lambda: visit(e.ld(e.add(_f(e, block, B_VALUES), p["vu_o"]))))
    if edges:
        def edge():
            e.var("vu_e", e.add(_f(e, block, B_EDGES), e.mul(p["vu_k"], EDGE)))
            e.for_("vu_o", 0, _f(e, p["vu_e"], 1), lambda: visit(e.ld(e.add(_f(e, p["vu_e"], 2), p["vu_o"]))))

        e.for_("vu_k", 0, _f(e, block, B_NEDGES), edge)


def _basics(tables):
    """Machine parameters, ``has_call``, stack storage (an alignment above 16 makes the function ineligible: 0),
    early use counts, block parameters proven nonzero, value ranges over the machine widths, and fused compares."""
    def build(e: E):
        p = e.p
        n = _g(e, G_VCOUNT)
        e.var("ba_n", n)
        # Every stamp table is cleared here: stamps restart with every run, and the output view is reused between runs.
        for table in (T_EARLY, T_NONZERO, T_S1, T_S2, T_S3, T_S4, T_USTAMP, T_UCOUNT, T_WSTAMP, T_CAND, T_ERASED, T_RMW_ERASED, T_TABLE_ERASED,
                      T_MEMBER_ERASED):
            e.for_("ba_v", 0, p["ba_n"], lambda table=table: _set_rt(e, table, p["ba_v"], 0))
        for table in (T_FOLD_BASE, T_SCALE_BASE, T_RMW, T_VT_SUBJECT, T_MV_SUBJECT, T_CL, T_SINK_OPERAND, T_ALIAS, T_HOME, T_PIN, T_PSLOT,
                      T_STACK):
            e.for_("ba_v", 0, p["ba_n"], lambda table=table: _set_rt(e, table, p["ba_v"], NONE))
        nb = _g(e, G_BCOUNT)
        e.var("ba_nb", nb)
        # has_call: any call except an erased proof call.
        e.var("ba_call", 0)
        e.var("ba_stacks", e.alloc(e.add(e.mul(p["ba_n"], 3), 1)))
        _ok(e, e.ne(p["ba_stacks"], NONE))
        e.var("ba_nstacks", 0)

        def block():
            e.var("ba_b", _block_at(e, p["ba_bi"]))

            def node():
                e.var("ba_node", _node_at(e, p["ba_b"], p["ba_m"]))
                e.var("ba_op", _eop(e, p["ba_node"]))

                def call():
                    e.var("ba_er", 0)

                    def direct():
                        _callee_object(e, p["ba_node"], "ba_callee")
                        e.if_(e.ne(p["ba_callee"], NONE), lambda: e.set("ba_er", _call(e, "erased", p["ba_callee"])))

                    e.if_(e.eq(p["ba_op"], DIRECT_CALL), direct)
                    e.if_(e.eq(p["ba_er"], 0), lambda: e.set("ba_call", 1))

                e.if_(_in(e, p["ba_op"], CALLS), call)

                def stack():
                    e.var("ba_align", _attribute(e, p["ba_node"], 1))
                    e.if_(e.lt(16, p["ba_align"]), lambda: e.give(0))  # the frame base is only 16-byte aligned
                    at = e.add(p["ba_stacks"], e.mul(p["ba_nstacks"], 3))
                    e.var("ba_at", at)
                    e.st(p["ba_at"], _output(e, p["ba_node"], 0))
                    e.st(e.add(p["ba_at"], 1), _attribute(e, p["ba_node"], 0))
                    e.st(e.add(p["ba_at"], 2), p["ba_align"])
                    e.set("ba_nstacks", e.add(p["ba_nstacks"], 1))

                e.if_(e.eq(p["ba_op"], _op(Operation.STACK_ALLOC)), stack)

            e.for_("ba_m", 0, _f(e, p["ba_b"], B_NNODES), node)
            _each_value_use(e, p["ba_b"], lambda v: (e.var("ba_u", v), _set_rt(e, T_EARLY, p["ba_u"], e.add(_rt(e, T_EARLY, p["ba_u"]), 1))))

        e.for_("ba_bi", 0, p["ba_nb"], block)
        _set_ra(e, R_HAS_CALL, p["ba_call"])
        _set_ra(e, R_STACKS, p["ba_stacks"])
        _set_ra(e, R_NSTACKS, p["ba_nstacks"])
        e.for_("ba_k", 0, p["ba_nstacks"], lambda: _set_rt(e, T_STACK, e.ld(e.add(p["ba_stacks"], e.mul(p["ba_k"], 3))), 0))  # stack values (offsets later)

        # Nonzero parameters: every incoming edge is the taken side of ``x != 0`` (or the other side of ``x == 0``) and
        # passes x.  T_S1 counts each block's incoming edges; T_NONZERO starts 1 for the candidates and is cleared.
        entry = _f(e, _g(e, G_BENTRY), B_POS)
        e.var("ba_entry", entry)

        def candidates():
            e.var("ba_b", _block_at(e, p["ba_bi"]))
            e.var("ba_incoming", 0)

            def source():
                e.var("ba_s", _block_at(e, p["ba_si"]))
                e.for_("ba_k", 0, _f(e, p["ba_s"], B_NEDGES), lambda: e.if_(
                    e.eq(_f(e, _f(e, e.add(_f(e, p["ba_s"], B_EDGES), e.mul(p["ba_k"], EDGE)), 0), B_POS), p["ba_bi"]),
                    lambda: e.set("ba_incoming", e.add(p["ba_incoming"], 1))))

            e.for_("ba_si", 0, p["ba_nb"], source)
            mark = e.both(e.ne(p["ba_bi"], p["ba_entry"]), e.ne(p["ba_incoming"], 0))
            e.for_("ba_k", 0, _f(e, p["ba_b"], B_NP), lambda: _set_rt(e, T_NONZERO, e.ld(e.add(_f(e, p["ba_b"], B_INPUTS), p["ba_k"])), e.flag(mark)))

        e.for_("ba_bi", 0, p["ba_nb"], candidates)

        def proofs():
            e.var("ba_s", _block_at(e, p["ba_si"]))

            def edge():
                e.var("ba_e", e.add(_f(e, p["ba_s"], B_EDGES), e.mul(p["ba_k"], EDGE)))
                e.var("ba_t", _f(e, p["ba_e"], 0))

                def argument():
                    e.var("ba_param", e.ld(e.add(_f(e, p["ba_t"], B_INPUTS), p["ba_a"])))
                    e.if_(e.ne(_rt(e, T_NONZERO, p["ba_param"]), 0), lambda: e.if_(e.eq(_call(e, "edge_nonzero", p["ba_si"], p["ba_k"], p["ba_a"]), 0),
                                                                                    lambda: _set_rt(e, T_NONZERO, p["ba_param"], 0)))

                e.for_("ba_a", 0, _f(e, p["ba_t"], B_NP), argument)

            e.for_("ba_k", 0, _f(e, p["ba_s"], B_NEDGES), edge)

        e.for_("ba_si", 0, p["ba_nb"], proofs)
        # Value ranges over the machine widths.
        _set_g2(e, G2_WIDTHS, _ra(e, T_RW))
        _call(e, "bounds")
        # Fused compares: a compare consumed only by its block's conditional branch.
        e.var("ba_fused", e.alloc(e.add(p["ba_nb"], 1)))
        _ok(e, e.ne(p["ba_fused"], NONE))
        _set_ra(e, R_FUSED, p["ba_fused"])

        def fuse():
            e.var("ba_b", _block_at(e, p["ba_bi"]))
            e.st(e.add(p["ba_fused"], p["ba_bi"]), NONE)

            def conditional():
                e.var("ba_cond", e.ld(_f(e, p["ba_b"], B_VALUES)))
                local = e.both(e.not_(_is_param(e, p["ba_cond"])), e.eq(_pos_block(e, p["ba_cond"]), p["ba_bi"]))

                def check():
                    e.var("ba_ci", _pos_index(e, p["ba_cond"]))
                    e.var("ba_consumers", 0)
                    _each_value_use(e, p["ba_b"], lambda v: e.if_(e.eq(v, p["ba_cond"]), lambda: e.set("ba_consumers", e.add(p["ba_consumers"], 1))),
                                    terminator_values=False)
                    compare = e.eq(_eop(e, _node_at(e, p["ba_b"], p["ba_ci"])), _op(Operation.INT_COMPARE))
                    e.if_(e.both(compare, e.eq(p["ba_consumers"], 0)), lambda: e.st(e.add(p["ba_fused"], p["ba_bi"]), p["ba_ci"]))

                e.if_(local, check)

            e.if_(e.eq(_f(e, p["ba_b"], B_KIND), CONDITIONAL), conditional)

        e.for_("ba_bi", 0, p["ba_nb"], fuse)
        e.give(1)
    return _function((), build, tables)


def _edge_nonzero(tables):
    """``edge_proves_nonzero(source, edge index, arguments, parameter)``: 1 or 0."""
    def build(e: E):
        p = e.p
        e.var("en_s", _block_at(e, p["src"]))
        e.if_(e.ne(_f(e, p["en_s"], B_KIND), CONDITIONAL), lambda: e.give(0))
        e.var("en_cond", e.ld(_f(e, p["en_s"], B_VALUES)))
        e.if_(e.either(_is_param(e, p["en_cond"]), e.ne(_pos_block(e, p["en_cond"]), p["src"])), lambda: e.give(0))
        e.var("en_cmp", _node_at(e, p["en_s"], _pos_index(e, p["en_cond"])))  # (the bootstrap does not check the result)
        e.var("en_e", e.add(_f(e, p["en_s"], B_EDGES), e.mul(p["edge"], EDGE)))
        e.if_(e.either(e.ne(_eop(e, p["en_cmp"]), _op(Operation.INT_COMPARE)), e.le(_f(e, p["en_e"], 1), p["param"])), lambda: e.give(0))
        e.var("en_tested", _operand(e, p["en_cmp"], 0))
        e.var("en_other", _operand(e, p["en_cmp"], 1))

        def zero(value):
            return e.both(_constant(e, value), e.eq(_cval(e, value), 0))

        def swap():
            e.var("en_tmp", p["en_tested"])
            e.set("en_tested", p["en_other"])
            e.set("en_other", p["en_tmp"])

        e.if_(e.not_(zero(p["en_other"])), swap)
        kind = _attribute(e, p["en_cmp"], 0)
        e.var("en_kind", kind)
        taken = e.either(e.both(e.eq(p["en_kind"], int(IntCompare.NE)), e.eq(p["edge"], 0)), e.both(e.eq(p["en_kind"], int(IntCompare.EQ)), e.eq(p["edge"], 1)))
        passes = e.eq(e.ld(e.add(_f(e, p["en_e"], 2), p["param"])), p["en_tested"])
        e.give(e.flag(e.both(zero(p["en_other"]), taken, passes)))
    return _function(("src", "edge", "param"), build, tables)


# -- predicate tables (``xax_ranges.predicate_table``, ADR-208) ------------------------------------------------

def _local_table_node(e: E, value, block_index, name: str):
    """``local(value)`` into ``name``: the defining node when ``value`` is result 0 of a table operation in block
    ``block_index`` with a machine width, else NONE."""
    p = e.p
    e.var(name, NONE)
    local = e.both(e.not_(_is_param(e, value)), e.eq(_pos_block(e, value), block_index), e.eq(_pos_result(e, value), 0), e.ne(_width(e, value), 0))

    def check():
        node = _vf(e, G_VPROD, value)
        e.var(f"{name}_n", node)
        e.if_(_in(e, _eop(e, p[f"{name}_n"]), TABLE_OPERATIONS), lambda: e.set(name, p[f"{name}_n"]))

    e.if_(local, check)


def _predicate_table(tables):
    """``predicate_table(graph, block, root, ...)``: a record ``[subject, entries, count, erased node flags]`` (entries
    one byte per word, erased flags one word per node of the block), or ``NOT_CALL`` when ``root`` is not one."""
    def build(e: E):
        p = e.p
        b = p["blk"]
        e.var("pt_mark", e.hd(H_ARENA))  # scratch is released when the root is not a table
        e.var("pt_block", _block_at(e, b))
        _local_table_node(e, p["root"], b, "pt_root")
        e.if_(e.eq(p["pt_root"], NONE), lambda: _release(e, p["pt_mark"], NOT_CALL))
        # Sets: nodes (T_S1 = stamp), leaves (T_S2 = stamp), with arrays to iterate them in insertion order.
        e.var("pt_stamp", _stamp(e))
        n = _g(e, G_VCOUNT)
        e.var("pt_nodes", e.alloc(e.add(n, 1)))
        e.var("pt_leaves", e.alloc(e.add(e.mul(n, 4), 1)))
        e.var("pt_pending", e.alloc(e.add(e.mul(n, 4), 1)))
        _ok(e, e.both(e.ne(p["pt_nodes"], NONE), e.ne(p["pt_leaves"], NONE), e.ne(p["pt_pending"], NONE)))
        e.var("pt_nn", 0)
        e.var("pt_nl", 0)
        e.var("pt_leaf_count", 0)

        def expand(start):
            e.var("pt_start", start)
            e.var("pt_sp", 1)
            e.st(p["pt_pending"], p["pt_start"])

            def step():
                e.set("pt_sp", e.sub(p["pt_sp"], 1))
                e.var("pt_v", e.ld(e.add(p["pt_pending"], p["pt_sp"])))
                v = p["pt_v"]
                skip = e.either(e.eq(_rt(e, T_S1, v), p["pt_stamp"]), _constant(e, v))

                def visit():
                    _local_table_node(e, v, b, "pt_local")
                    take = e.both(e.ne(p["pt_local"], NONE), e.either(e.eq(v, p["pt_start"]), e.eq(_rt(e, T_EARLY, v), 1)))

                    def node():
                        e.if_(e.eq(_rt(e, T_S2, v), p["pt_stamp"]), lambda: (_set_rt(e, T_S2, v, 0), e.set("pt_leaf_count", e.sub(p["pt_leaf_count"], 1))))
                        _set_rt(e, T_S1, v, p["pt_stamp"])
                        e.st(e.add(p["pt_nodes"], p["pt_nn"]), v)
                        e.set("pt_nn", e.add(p["pt_nn"], 1))
                        e.for_("pt_o", 0, _f(e, p["pt_local"], N_NOPS), lambda: (
                            e.st(e.add(p["pt_pending"], p["pt_sp"]), _operand(e, p["pt_local"], p["pt_o"])), e.set("pt_sp", e.add(p["pt_sp"], 1))))

                    def leaf():
                        def add():
                            _set_rt(e, T_S2, v, p["pt_stamp"])
                            e.st(e.add(p["pt_leaves"], p["pt_nl"]), v)
                            e.set("pt_nl", e.add(p["pt_nl"], 1))
                            e.set("pt_leaf_count", e.add(p["pt_leaf_count"], 1))

                        e.if_(e.ne(_rt(e, T_S2, v), p["pt_stamp"]), add)

                    e.if_(take, node, leaf)

                e.if_(e.not_(skip), visit)

            e.while_(lambda: e.ne(p["pt_sp"], 0), step)

        expand(p["root"])

        def more():
            # The leaf with the largest index among the expandable ones.
            e.var("pt_best", NONE)
            e.var("pt_best_index", 0)

            def candidate():
                e.var("pt_l", e.ld(e.add(p["pt_leaves"], p["pt_k"])))
                live = e.eq(_rt(e, T_S2, p["pt_l"]), p["pt_stamp"])

                def check():
                    _local_table_node(e, p["pt_l"], b, "pt_cl")
                    better = e.either(e.eq(p["pt_best"], NONE), e.lt(p["pt_best_index"], _pos_index(e, p["pt_l"])))
                    e.if_(e.both(e.ne(p["pt_cl"], NONE), better), lambda: (e.set("pt_best", p["pt_l"]), e.set("pt_best_index", _pos_index(e, p["pt_l"]))))

                e.if_(live, check)

            e.for_("pt_k", 0, p["pt_nl"], candidate)
            e.if_(e.eq(p["pt_best"], NONE), lambda: _release(e, p["pt_mark"], NOT_CALL))
            expand(p["pt_best"])

        e.while_(lambda: e.lt(1, p["pt_leaf_count"]), more)
        e.if_(e.ne(p["pt_leaf_count"], 1), lambda: _release(e, p["pt_mark"], NOT_CALL))
        e.var("pt_ops", 0)
        e.for_("pt_k", 0, p["pt_nn"], lambda: e.if_(e.ne(_eop(e, _vf(e, G_VPROD, e.ld(e.add(p["pt_nodes"], p["pt_k"])))), _op(Operation.INT_ZERO_EXTEND)),
                                                       lambda: e.set("pt_ops", e.add(p["pt_ops"], 1))))
        e.if_(e.lt(p["pt_ops"], TABLE_MIN_OPERATIONS), lambda: _release(e, p["pt_mark"], NOT_CALL))
        e.var("pt_subject", NONE)
        e.for_("pt_k", 0, p["pt_nl"], lambda: e.if_(e.eq(_rt(e, T_S2, e.ld(e.add(p["pt_leaves"], p["pt_k"]))), p["pt_stamp"]),
                                                       lambda: e.set("pt_subject", e.ld(e.add(p["pt_leaves"], p["pt_k"])))))
        subject = p["pt_subject"]
        e.var("pt_bound", e.call(_FN["maximum0"], subject))
        e.var("pt_none", _g2(e, G2_RNONE))
        e.if_(e.either(e.eq(_width(e, subject), 0), e.ne(p["pt_none"], 0), e.le(TABLE_SUBJECT_LIMIT, p["pt_bound"])), lambda: _release(e, p["pt_mark"], NOT_CALL))
        # Order: by node index (operands precede their uses within a block).
        def insert():
            e.var("pt_item", e.ld(e.add(p["pt_nodes"], p["pt_s"])))
            e.var("pt_j", p["pt_s"])
            before = lambda: e.both(e.lt(0, p["pt_j"]), e.lt(_pos_index(e, p["pt_item"]), _pos_index(e, e.ld(e.add(p["pt_nodes"], e.sub(p["pt_j"], 1))))))  # noqa: E731
            e.while_(before, lambda: (e.st(e.add(p["pt_nodes"], p["pt_j"]), e.ld(e.add(p["pt_nodes"], e.sub(p["pt_j"], 1)))), e.set("pt_j", e.sub(p["pt_j"], 1))))
            e.st(e.add(p["pt_nodes"], p["pt_j"]), p["pt_item"])

        e.for_("pt_s", 1, p["pt_nn"], insert)
        # Evaluate the expression for every subject value 0..bound (T_S3 holds each value's current value).
        e.var("pt_count", e.add(p["pt_bound"], 1))
        e.var("pt_entries", e.alloc(e.add(p["pt_count"], 1)))
        _ok(e, e.ne(p["pt_entries"], NONE))

        def entry():
            _set_rt(e, T_S3, subject, p["pt_x"])

            def evaluate():
                e.var("pt_v", e.ld(e.add(p["pt_nodes"], p["pt_k"])))
                e.var("pt_node", _vf(e, G_VPROD, p["pt_v"]))
                node = p["pt_node"]

                def operand(k):
                    value = _operand(e, node, k)
                    return e.sel(_constant(e, value), _cval(e, value), _rt(e, T_S3, value))

                e.var("pt_a", operand(0))
                e.var("pt_rw", _width(e, p["pt_v"]))
                mask = e.sel(e.eq(p["pt_rw"], 64), (1 << 64) - 1, e.sub(e.ld(e.add(_g2(e, G2_SCRATCH), p["pt_rw"])), 1))  # G2_SCRATCH powers
                e.var("pt_mask", mask)
                e.var("pt_op", _eop(e, node))
                op = p["pt_op"]

                def unary():
                    _set_rt(e, T_S3, p["pt_v"], e.and_(p["pt_a"], p["pt_mask"]))

                def binary():
                    e.var("pt_b", operand(1))

                    def compare():
                        first, last = _operand(e, node, 0), _operand(e, node, e.sub(_f(e, node, N_NOPS), 1))
                        e.var("pt_ow", _width(e, first))
                        e.if_(e.eq(p["pt_ow"], 0), lambda: e.set("pt_ow", _width(e, last)))
                        e.if_(e.eq(p["pt_ow"], 0), lambda: e.set("pt_ow", 64))
                        e.var("pt_kind", _attribute(e, node, 0))
                        signed = _in(e, p["pt_kind"], (int(IntCompare.SLT), int(IntCompare.SLE), int(IntCompare.SGT), int(IntCompare.SGE)))
                        half = e.ld(e.add(_g2(e, G2_SCRATCH), e.sub(p["pt_ow"], 1)))  # 2 ** (operand_width - 1)
                        e.var("pt_l", e.sel(signed, e.bin(Operation.BIT_XOR, p["pt_a"], half), p["pt_a"]))
                        e.var("pt_r", e.sel(signed, e.bin(Operation.BIT_XOR, p["pt_b"], half), p["pt_b"]))
                        l, r = p["pt_l"], p["pt_r"]
                        e.var("pt_out", 0)
                        for kinds, result in (((IntCompare.EQ,), e.eq(l, r)), ((IntCompare.NE,), e.ne(l, r)),
                                              ((IntCompare.ULT, IntCompare.SLT), e.lt(l, r)), ((IntCompare.ULE, IntCompare.SLE), e.le(l, r)),
                                              ((IntCompare.UGT, IntCompare.SGT), e.lt(r, l)), ((IntCompare.UGE, IntCompare.SGE), e.le(r, l))):
                            e.if_(_in(e, p["pt_kind"], tuple(int(k) for k in kinds)), lambda result=result: e.set("pt_out", e.flag(result)))
                        _set_rt(e, T_S3, p["pt_v"], p["pt_out"])

                    def arithmetic():
                        value = e.c(0)
                        for operation in (Operation.ADD_WRAP, Operation.SUB_WRAP, Operation.MUL_WRAP, Operation.BIT_AND, Operation.BIT_OR, Operation.BIT_XOR):
                            value = e.add(value, e.mul(e.flag(e.eq(op, _op(operation))), e.bin(operation, p["pt_a"], p["pt_b"])))
                        _set_rt(e, T_S3, p["pt_v"], e.and_(value, p["pt_mask"]))

                    e.if_(e.eq(op, _op(Operation.INT_COMPARE)), compare, arithmetic)

                e.if_(_in(e, op, (_op(Operation.INT_ZERO_EXTEND), _op(Operation.INT_TRUNCATE))), unary, binary)

            e.for_("pt_k", 0, p["pt_nn"], evaluate)
            e.var("pt_result", _rt(e, T_S3, p["root"]))
            e.if_(e.lt(1, p["pt_result"]), lambda: _release(e, p["pt_mark"], NOT_CALL))
            e.st(e.add(p["pt_entries"], p["pt_x"]), p["pt_result"])

        e.for_("pt_x", 0, p["pt_count"], entry)
        # Erase exactly the nodes all of whose uses are erased nodes (the root's users read the table).
        e.var("pt_flags", e.alloc(e.add(_f(e, p["pt_block"], B_NNODES), 1)))
        _ok(e, e.ne(p["pt_flags"], NONE))
        e.for_("pt_k", 0, _f(e, p["pt_block"], B_NNODES), lambda: e.st(e.add(p["pt_flags"], p["pt_k"]), 0))
        e.st(e.add(p["pt_flags"], _pos_index(e, p["root"])), 1)
        e.var("pt_erased", e.alloc(e.add(p["pt_nn"], 1)))  # erased values, to count their operand uses
        _ok(e, e.ne(p["pt_erased"], NONE))
        e.st(p["pt_erased"], p["root"])
        e.var("pt_ne", 1)
        e.var("pt_k", p["pt_nn"])

        def backwards():
            e.set("pt_k", e.sub(p["pt_k"], 1))
            e.var("pt_v", e.ld(e.add(p["pt_nodes"], p["pt_k"])))

            def consider():
                e.var("pt_uses", 0)

                def user():
                    e.var("pt_user", _vf(e, G_VPROD, e.ld(e.add(p["pt_erased"], p["pt_u"]))))
                    e.for_("pt_o", 0, _f(e, p["pt_user"], N_NOPS), lambda: e.if_(e.eq(_operand(e, p["pt_user"], p["pt_o"]), p["pt_v"]),
                                                                                    lambda: e.set("pt_uses", e.add(p["pt_uses"], 1))))

                e.for_("pt_u", 0, p["pt_ne"], user)

                def erase():
                    e.st(e.add(p["pt_erased"], p["pt_ne"]), p["pt_v"])
                    e.set("pt_ne", e.add(p["pt_ne"], 1))
                    e.st(e.add(p["pt_flags"], _pos_index(e, p["pt_v"])), 1)

                e.if_(e.eq(p["pt_uses"], _rt(e, T_EARLY, p["pt_v"])), erase)

            e.if_(e.ne(p["pt_v"], p["root"]), consider)

        e.while_(lambda: e.ne(p["pt_k"], 0), backwards)
        e.var("pt_record", e.alloc(4))
        _ok(e, e.ne(p["pt_record"], NONE))
        for field, value in ((0, subject), (1, p["pt_entries"]), (2, p["pt_count"]), (3, p["pt_flags"])):
            e.st(e.add(p["pt_record"], field), value)
        e.give(p["pt_record"])
    return _function(("blk", "root"), build, tables)


# -- folding decisions ------------------------------------------------------------------------------------------

LOADS_PLAIN = tuple(_op(op) for op in (Operation.LOAD_BITS_LE, Operation.RAW_LOAD_BITS_LE, Operation.STORE_BITS_LE))
CHECKED = (_op(Operation.CHECKED_LOAD_BITS_LE), _op(Operation.CHECKED_STORE_BITS_LE))
WRITES = (_op(Operation.STORE_BITS_LE), _op(Operation.CHECKED_STORE_BITS_LE), *CALLS)


def _definition(e: E, value, name: str):
    """``definition.get(value)`` (result 0 of a node) into ``name``, else NONE."""
    produced = e.both(e.not_(_is_param(e, value)), e.eq(_pos_result(e, value), 0))
    e.var(name, e.sel(produced, _vf(e, G_VPROD, value), NONE))


def _local_definition(e: E, value, block_index, name: str):
    """As ``_definition``, only for a value of block ``block_index``."""
    produced = e.both(e.not_(_is_param(e, value)), e.eq(_pos_result(e, value), 0), e.eq(_pos_block(e, value), block_index))
    e.var(name, e.sel(produced, _vf(e, G_VPROD, value), NONE))


def _access_proven(tables):
    """``access_proven(node)``: the index's bound fits the pointer's extent less the access size."""
    def build(e: E):
        p = e.p
        e.var("ap_bound", e.call(_FN["maximum0"], _operand(e, p["n"], 1)))
        e.var("ap_none", _g2(e, G2_RNONE))
        e.var("ap_extent", _call(e, "extent", _operand(e, p["n"], 0)))
        e.var("ap_size", _attribute(e, p["n"], 0))
        fits = e.both(e.eq(p["ap_none"], 0), e.le(p["ap_size"], p["ap_extent"]), e.le(p["ap_bound"], e.sub(p["ap_extent"], p["ap_size"])))
        e.give(e.flag(fits))
    return _function(("n",), build, tables)


def _attribute_count(e: E, node):
    at = _f(e, node, 4)  # N_ATTR: the attribute list's stream position, NONE without one
    return e.sel(e.ne(at, NONE), e.rd(e.sel(e.ne(at, NONE), at, 0)), 0)


def _immediate(e: E, value, width):
    """``immediate(value, width)`` is not None: a constant that fits an imm32 at ``width``."""
    c = _cval(e, value)
    fits = e.sel(e.lt(32, width), e.flag(e.lt(c, 1 << 31)), e.flag(e.lt(c, 1 << 32)))
    return e.both(_constant(e, value), e.ne(fits, 0))


def _mask_bits(e: E, values, count, low, name: str):
    """OR of ``1 << (v - low)`` over ``count`` values at ``values`` (word stride 1), into ``name``."""
    p = e.p
    e.var(name, 0)
    e.for_(f"{name}_k", 0, count, lambda: e.set(name, e.or_(p[name], e.ld(e.add(_g2(e, G2_SCRATCH), e.sub(e.ld(e.add(values, p[f"{name}_k"])), low))))))


def _branch_membership(tables):
    """``membership`` for the conditional branch of block ``blk`` (fused and table branches excluded by the caller):
    a record ``[subject, low, mask, tree flags]`` or ``NOT_CALL``."""
    def build(e: E):
        p = e.p
        b = p["blk"]
        e.var("bm_mark", e.hd(H_ARENA))
        e.var("bm_block", _block_at(e, b))
        block = p["bm_block"]
        e.var("bm_cond", e.ld(_f(e, block, B_VALUES)))
        local = e.both(e.not_(_is_param(e, p["bm_cond"])), e.eq(_pos_block(e, p["bm_cond"]), b))
        e.if_(e.not_(local), lambda: _release(e, p["bm_mark"], NOT_CALL))
        e.var("bm_ci", _pos_index(e, p["bm_cond"]))
        e.if_(e.ne(_eop(e, _node_at(e, block, p["bm_ci"])), _op(Operation.BIT_OR)), lambda: _release(e, p["bm_mark"], NOT_CALL))

        def counts(value, name):
            """``counts[value]``: uses among the block's node operands and edge arguments."""
            e.var(name, 0)
            _each_value_use(e, block, lambda v: e.if_(e.eq(v, value), lambda: e.set(name, e.add(e.p[name], 1))), terminator_values=False)

        counts(p["bm_cond"], "bm_cc")
        e.if_(e.ne(p["bm_cc"], 0), lambda: _release(e, p["bm_mark"], NOT_CALL))
        e.var("bm_n", _f(e, block, B_NNODES))
        e.var("bm_flags", e.alloc(e.add(p["bm_n"], 1)))
        e.var("bm_pending", e.alloc(e.add(e.mul(_g(e, G_VCOUNT), 2), 2)))
        e.var("bm_subjects", e.alloc(e.add(p["bm_n"], 1)))
        e.var("bm_values", e.alloc(e.add(p["bm_n"], 1)))
        _ok(e, e.both(e.ne(p["bm_flags"], NONE), e.ne(p["bm_pending"], NONE), e.ne(p["bm_subjects"], NONE), e.ne(p["bm_values"], NONE)))
        e.for_("bm_k", 0, p["bm_n"], lambda: e.st(e.add(p["bm_flags"], p["bm_k"]), 0))
        e.st(p["bm_pending"], p["bm_ci"])
        e.var("bm_sp", 1)
        e.var("bm_nt", 0)
        e.var("bm_bad", 0)

        def step():
            e.set("bm_sp", e.sub(p["bm_sp"], 1))
            e.var("bm_i", e.ld(e.add(p["bm_pending"], p["bm_sp"])))
            e.var("bm_node", _node_at(e, block, p["bm_i"]))
            node = p["bm_node"]
            e.st(e.add(p["bm_flags"], p["bm_i"]), 1)
            e.var("bm_op", _eop(e, node))
            e.var("bm_all", e.flag(e.eq(p["bm_op"], _op(Operation.BIT_OR))))

            def operands():
                def each():
                    e.var("bm_o", _operand(e, node, p["bm_k"]))
                    counts(p["bm_o"], "bm_oc")
                    ok = e.both(e.not_(_is_param(e, p["bm_o"])), e.eq(_pos_block(e, p["bm_o"]), b), e.eq(p["bm_oc"], 1))
                    e.if_(e.not_(ok), lambda: e.set("bm_all", 0))

                e.for_("bm_k", 0, _f(e, node, N_NOPS), each)

            e.if_(e.ne(p["bm_all"], 0), operands)

            def expand():
                e.for_("bm_k", 0, _f(e, node, N_NOPS), lambda: (e.st(e.add(p["bm_pending"], p["bm_sp"]), _pos_index(e, _operand(e, node, p["bm_k"]))),
                                                                 e.set("bm_sp", e.add(p["bm_sp"], 1))))

            def leaf():
                e.var("bm_x", _operand(e, node, 0))
                e.var("bm_c", _operand(e, node, 1))
                good = e.both(e.eq(p["bm_op"], _op(Operation.INT_COMPARE)), e.eq(_attribute(e, node, 0), int(IntCompare.EQ)),
                              _constant(e, p["bm_c"]), e.not_(_constant(e, p["bm_x"])))

                def record():
                    e.st(e.add(p["bm_subjects"], p["bm_nt"]), p["bm_x"])
                    e.st(e.add(p["bm_values"], p["bm_nt"]), e.and_(_cval(e, p["bm_c"]), 0xFFFFFFFF))
                    e.set("bm_nt", e.add(p["bm_nt"], 1))

                e.if_(good, record, lambda: e.set("bm_bad", 1))

            e.if_(e.ne(p["bm_all"], 0), expand, leaf)

        e.while_(lambda: e.both(e.ne(p["bm_sp"], 0), e.eq(p["bm_bad"], 0)), step)
        e.if_(e.either(e.ne(p["bm_bad"], 0), e.lt(p["bm_nt"], 3)), lambda: _release(e, p["bm_mark"], NOT_CALL))
        e.var("bm_subject", e.ld(p["bm_subjects"]))
        e.for_("bm_k", 0, p["bm_nt"], lambda: e.if_(e.ne(e.ld(e.add(p["bm_subjects"], p["bm_k"])), p["bm_subject"]), lambda: _release(e, p["bm_mark"], NOT_CALL)))
        e.if_(e.ne(_width(e, p["bm_subject"]), 32), lambda: _release(e, p["bm_mark"], NOT_CALL))
        e.var("bm_low", e.ld(p["bm_values"]))
        e.var("bm_high", e.ld(p["bm_values"]))
        e.for_("bm_k", 0, p["bm_nt"], lambda: (e.var("bm_w", e.ld(e.add(p["bm_values"], p["bm_k"]))),
                                                e.if_(e.lt(p["bm_w"], p["bm_low"]), lambda: e.set("bm_low", p["bm_w"])),
                                                e.if_(e.lt(p["bm_high"], p["bm_w"]), lambda: e.set("bm_high", p["bm_w"]))))
        e.if_(e.lt(62, e.sub(p["bm_high"], p["bm_low"])), lambda: _release(e, p["bm_mark"], NOT_CALL))
        _mask_bits(e, p["bm_values"], p["bm_nt"], p["bm_low"], "bm_mask")
        e.var("bm_record", e.alloc(4))
        _ok(e, e.ne(p["bm_record"], NONE))
        for field, value in ((0, p["bm_subject"]), (1, p["bm_low"]), (2, p["bm_mask"]), (3, p["bm_flags"])):
            e.st(e.add(p["bm_record"], field), value)
        e.give(p["bm_record"])
    return _function(("blk",), build, tables)


def _member_value(tables):
    """``member_values`` for the OR at ``root`` in block ``blk``: records the value (``T_MV_*``) and its erased
    values (``T_MEMBER_ERASED``); 1 when it is one, 0 otherwise."""
    def build(e: E):
        p = e.p
        b = p["blk"]
        e.var("mv_mark", e.hd(H_ARENA))  # the result is in the value tables: all scratch is released
        e.var("mv_pending", e.alloc(e.add(e.mul(_g(e, G_VCOUNT), 2), 2)))
        e.var("mv_internal", e.alloc(e.add(_g(e, G_VCOUNT), 1)))
        e.var("mv_chains", e.alloc(e.add(e.mul(_g(e, G_VCOUNT), 2), 2)))
        e.var("mv_values", e.alloc(e.add(_g(e, G_VCOUNT), 1)))
        _ok(e, e.both(e.ne(p["mv_pending"], NONE), e.ne(p["mv_internal"], NONE), e.ne(p["mv_chains"], NONE), e.ne(p["mv_values"], NONE)))
        e.st(p["mv_pending"], p["root"])
        e.var("mv_sp", 1)
        e.var("mv_ni", 0)
        e.var("mv_nt", 0)
        e.var("mv_subject", NONE)
        e.var("mv_bad", 0)

        def step():
            e.set("mv_sp", e.sub(p["mv_sp"], 1))
            e.var("mv_v", e.ld(e.add(p["mv_pending"], p["mv_sp"])))
            v = p["mv_v"]
            _local_definition(e, v, b, "mv_node")

            def known():
                node = p["mv_node"]
                internal = e.both(e.eq(_eop(e, node), _op(Operation.BIT_OR)), e.either(e.eq(v, p["root"]), e.eq(_rt(e, T_EARLY, v), 1)))

                def expand():
                    e.st(e.add(p["mv_internal"], p["mv_ni"]), v)
                    e.set("mv_ni", e.add(p["mv_ni"], 1))
                    e.for_("mv_k", 0, _f(e, node, N_NOPS), lambda: (e.st(e.add(p["mv_pending"], p["mv_sp"]), _operand(e, node, p["mv_k"])),
                                                                     e.set("mv_sp", e.add(p["mv_sp"], 1))))

                def leaf():
                    e.var("mv_inner", NONE)
                    e.var("mv_test", node)

                    def through():
                        e.set("mv_inner", _operand(e, node, 0))
                        _local_definition(e, p["mv_inner"], b, "mv_innernode")
                        e.set("mv_test", p["mv_innernode"])

                    e.if_(e.eq(_eop(e, node), _op(Operation.INT_ZERO_EXTEND)), through)
                    t = p["mv_test"]
                    known_test = e.ne(t, NONE)
                    safe = e.sel(known_test, t, 0)
                    e.var("mv_x", _operand(e, safe, 0))
                    e.var("mv_c", _operand(e, safe, 1))
                    good = e.both(known_test, e.eq(_eop(e, safe), _op(Operation.INT_COMPARE)), e.eq(_attribute(e, safe, 0), int(IntCompare.EQ)),
                                  _constant(e, p["mv_c"]), e.not_(_constant(e, p["mv_x"])), e.lt(_cval(e, p["mv_c"]), 1 << 32))

                    def record():
                        e.if_(e.eq(p["mv_subject"], NONE), lambda: e.set("mv_subject", p["mv_x"]), lambda: e.if_(
                            e.ne(p["mv_subject"], p["mv_x"]), lambda: e.set("mv_subject", NOT_CALL)))  # two subjects: rejected below
                        e.st(e.add(p["mv_values"], p["mv_nt"]), _cval(e, p["mv_c"]))
                        at = e.add(p["mv_chains"], e.mul(p["mv_nt"], 2))
                        e.var("mv_at", at)
                        e.st(p["mv_at"], v)
                        e.st(e.add(p["mv_at"], 1), p["mv_inner"])
                        e.set("mv_nt", e.add(p["mv_nt"], 1))

                    e.if_(good, record, lambda: e.set("mv_bad", 1))

                e.if_(internal, expand, leaf)

            e.if_(e.eq(p["mv_node"], NONE), lambda: e.set("mv_bad", 1), known)

        e.while_(lambda: e.both(e.ne(p["mv_sp"], 0), e.eq(p["mv_bad"], 0)), step)
        e.if_(e.either(e.ne(p["mv_bad"], 0), e.lt(p["mv_nt"], 3), e.eq(p["mv_subject"], NOT_CALL)), lambda: _release(e, p["mv_mark"], 0))
        subject = p["mv_subject"]
        e.var("mv_bound", e.call(_FN["maximum0"], subject))
        e.var("mv_none", _g2(e, G2_RNONE))
        e.var("mv_low", e.ld(p["mv_values"]))
        e.var("mv_high", e.ld(p["mv_values"]))
        e.for_("mv_k", 0, p["mv_nt"], lambda: (e.var("mv_w", e.ld(e.add(p["mv_values"], p["mv_k"]))),
                                                e.if_(e.lt(p["mv_w"], p["mv_low"]), lambda: e.set("mv_low", p["mv_w"])),
                                                e.if_(e.lt(p["mv_high"], p["mv_w"]), lambda: e.set("mv_high", p["mv_w"]))))
        e.if_(e.either(e.ne(p["mv_none"], 0), e.le(1 << 32, p["mv_bound"]), e.lt(62, e.sub(p["mv_high"], p["mv_low"]))), lambda: _release(e, p["mv_mark"], 0))
        _mask_bits(e, p["mv_values"], p["mv_nt"], p["mv_low"], "mv_mask")
        root = p["root"]
        _set_rt(e, T_MV_SUBJECT, root, subject)
        _set_rt(e, T_MV_LOW, root, p["mv_low"])
        _set_rt(e, T_MV_MASK, root, p["mv_mask"])
        e.for_("mv_k", 0, p["mv_ni"], lambda: (e.var("mv_x", e.ld(e.add(p["mv_internal"], p["mv_k"]))),
                                                e.if_(e.ne(p["mv_x"], root), lambda: _set_rt(e, T_MEMBER_ERASED, p["mv_x"], 1))))

        def chain():
            e.var("mv_a", e.ld(e.add(p["mv_chains"], e.mul(p["mv_k"], 2))))
            e.var("mv_b", e.ld(e.add(p["mv_chains"], e.add(e.mul(p["mv_k"], 2), 1))))
            single = e.both(e.eq(_rt(e, T_EARLY, p["mv_a"]), 1), e.either(e.eq(p["mv_b"], NONE), e.eq(_rt(e, T_EARLY, e.sel(e.eq(p["mv_b"], NONE), 0, p["mv_b"])), 1)))
            e.if_(single, lambda: (_set_rt(e, T_MEMBER_ERASED, p["mv_a"], 1), e.if_(e.ne(p["mv_b"], NONE), lambda: _set_rt(e, T_MEMBER_ERASED, p["mv_b"], 1))))

        e.for_("mv_k", 0, p["mv_nt"], chain)
        _release(e, p["mv_mark"], 1)
    return _function(("blk", "root"), build, tables)


def _folding(tables):
    """Branch tables, membership tests, folded offsets, scaled indices, read-modify-write stores, value tables, member
    values, compare loads, edge-sunk additions, and call aliases, in the bootstrap's order (1, or NONE)."""
    def build(e: E):
        p = e.p
        nb = _g(e, G_BCOUNT)
        e.var("fo_nb", nb)
        e.var("fo_fused", _ra(e, R_FUSED))
        e.var("fo_btab", e.alloc(e.add(p["fo_nb"], 1)))
        e.var("fo_memb", e.alloc(e.add(p["fo_nb"], 1)))
        _ok(e, e.both(e.ne(p["fo_btab"], NONE), e.ne(p["fo_memb"], NONE)))
        _set_ra(e, R_BTAB, p["fo_btab"])
        _set_ra(e, R_MEMB, p["fo_memb"])
        n = _g(e, G_VCOUNT)
        e.var("fo_n", n)

        def fused_at(bi):
            return e.ld(e.add(p["fo_fused"], bi))

        # Branch tables: a conditional branch (not fused) on a single-use local condition.
        def branch_table():
            e.var("fo_b", _block_at(e, p["fo_bi"]))
            e.st(e.add(p["fo_btab"], p["fo_bi"]), NONE)

            def check():
                e.var("fo_cond", e.ld(_f(e, p["fo_b"], B_VALUES)))
                local = e.both(e.not_(_is_param(e, p["fo_cond"])), e.eq(_pos_block(e, p["fo_cond"]), p["fo_bi"]), e.eq(_rt(e, T_EARLY, p["fo_cond"]), 1))

                def table():
                    e.var("fo_found", _call(e, "predicate_table", p["fo_bi"], p["fo_cond"]))
                    e.if_(e.ne(p["fo_found"], NOT_CALL), lambda: e.st(e.add(p["fo_btab"], p["fo_bi"]), p["fo_found"]))

                e.if_(local, table)

            e.if_(e.both(e.eq(_f(e, p["fo_b"], B_KIND), CONDITIONAL), e.eq(fused_at(p["fo_bi"]), NONE)), check)

        e.for_("fo_bi", 0, p["fo_nb"], branch_table)

        # Membership: a branch on an OR tree of ``x == c`` tests (ADR-131).
        def membership():
            e.var("fo_b", _block_at(e, p["fo_bi"]))
            e.st(e.add(p["fo_memb"], p["fo_bi"]), NONE)
            eligible = e.both(e.eq(_f(e, p["fo_b"], B_KIND), CONDITIONAL), e.eq(fused_at(p["fo_bi"]), NONE), e.eq(e.ld(e.add(p["fo_btab"], p["fo_bi"])), NONE))

            def check():
                e.var("fo_found", _call(e, "branch_membership", p["fo_bi"]))
                e.if_(e.ne(p["fo_found"], NOT_CALL), lambda: e.st(e.add(p["fo_memb"], p["fo_bi"]), p["fo_found"]))

            e.if_(eligible, check)

        e.for_("fo_bi", 0, p["fo_nb"], membership)

        # Address offsets used only as plain load/store addresses fold into their displacement.
        e.for_("fo_v", 0, p["fo_n"], lambda: (_set_rt(e, T_MEMORY_USES, p["fo_v"], 0), _set_rt(e, T_OTHER_USE, p["fo_v"], 0),
                                               _set_rt(e, T_INDEX_USES, p["fo_v"], 0)))

        def address_uses():
            e.var("fo_b", _block_at(e, p["fo_bi"]))

            def node():
                e.var("fo_node", _node_at(e, p["fo_b"], p["fo_m"]))
                e.var("fo_plain", e.flag(_in(e, _eop(e, p["fo_node"]), LOADS_PLAIN)))

                def operand():
                    e.var("fo_o", _operand(e, p["fo_node"], p["fo_k"]))
                    e.if_(e.both(e.ne(p["fo_plain"], 0), e.eq(p["fo_k"], 0)), lambda: _set_rt(e, T_MEMORY_USES, p["fo_o"], e.add(_rt(e, T_MEMORY_USES, p["fo_o"]), 1)),
                          lambda: _set_rt(e, T_OTHER_USE, p["fo_o"], 1))

                e.for_("fo_k", 0, _f(e, p["fo_node"], N_NOPS), operand)

            e.for_("fo_m", 0, _f(e, p["fo_b"], B_NNODES), node)
            e.for_("fo_k", 0, _f(e, p["fo_b"], B_NVALUES), lambda: _set_rt(e, T_OTHER_USE, e.ld(e.add(_f(e, p["fo_b"], B_VALUES), p["fo_k"])), 1))

            def edge():
                e.var("fo_e", e.add(_f(e, p["fo_b"], B_EDGES), e.mul(p["fo_j"], EDGE)))
                e.for_("fo_k", 0, _f(e, p["fo_e"], 1), lambda: _set_rt(e, T_OTHER_USE, e.ld(e.add(_f(e, p["fo_e"], 2), p["fo_k"])), 1))

            e.for_("fo_j", 0, _f(e, p["fo_b"], B_NEDGES), edge)

        e.for_("fo_bi", 0, p["fo_nb"], address_uses)

        def fold():
            e.var("fo_b", _block_at(e, p["fo_bi"]))

            def node():
                e.var("fo_node", _node_at(e, p["fo_b"], p["fo_m"]))
                e.var("fo_v", _output(e, p["fo_node"], 0))
                ok = e.both(e.eq(_eop(e, p["fo_node"]), _op(Operation.ADDRESS_OFFSET)), e.ne(_rt(e, T_MEMORY_USES, p["fo_v"]), 0),
                            e.eq(_rt(e, T_OTHER_USE, p["fo_v"]), 0), e.lt(_attribute(e, p["fo_node"], 0), 1 << 31))
                e.if_(ok, lambda: (_set_rt(e, T_FOLD_BASE, p["fo_v"], _operand(e, p["fo_node"], 0)), _set_rt(e, T_FOLD_DISP, p["fo_v"], _attribute(e, p["fo_node"], 0))))

            e.for_("fo_m", 0, _f(e, p["fo_b"], B_NNODES), node)

        e.for_("fo_bi", 0, p["fo_nb"], fold)

        # Proven checked accesses: their indices' uses; an index used only by them folds into the SIB scale.
        def index_uses():
            e.var("fo_b", _block_at(e, p["fo_bi"]))

            def node():
                e.var("fo_node", _node_at(e, p["fo_b"], p["fo_m"]))

                def proven():
                    e.if_(e.ne(_call_value(e, "access_proven", p["fo_node"]), 0), lambda: (
                        e.var("fo_ix", _operand(e, p["fo_node"], 1)), _set_rt(e, T_INDEX_USES, p["fo_ix"], e.add(_rt(e, T_INDEX_USES, p["fo_ix"]), 1))))

                e.if_(_in(e, _eop(e, p["fo_node"]), CHECKED), proven)

            e.for_("fo_m", 0, _f(e, p["fo_b"], B_NNODES), node)

        e.for_("fo_bi", 0, p["fo_nb"], index_uses)

        def scale():
            v = p["fo_v"]
            counted = e.both(e.ne(_rt(e, T_INDEX_USES, v), 0), e.eq(_rt(e, T_EARLY, v), _rt(e, T_INDEX_USES, v)), e.not_(_is_param(e, v)))

            def check():
                _definition(e, v, "fo_def")
                e.var("fo_inner", NONE)

                def truncation():
                    e.var("fo_tb", e.call(_FN["maximum0"], _operand(e, p["fo_def"], 0)))
                    e.var("fo_tn", _g2(e, G2_RNONE))

                    def narrow():
                        e.set("fo_inner", _operand(e, p["fo_def"], 0))
                        ok = e.both(e.eq(_rt(e, T_EARLY, p["fo_inner"]), 1), e.not_(_is_param(e, p["fo_inner"])), e.eq(_pos_block(e, p["fo_inner"]), _pos_block(e, v)))
                        e.if_(ok, lambda: _definition(e, p["fo_inner"], "fo_def"), lambda: e.set("fo_def", NOT_CALL))

                    e.if_(e.both(e.eq(p["fo_tn"], 0), e.lt(p["fo_tb"], 1 << 32)), narrow)

                e.if_(e.both(e.ne(p["fo_def"], NONE), e.eq(_eop(e, e.sel(e.ne(p["fo_def"], NONE), p["fo_def"], 0)), _op(Operation.INT_TRUNCATE))), truncation)

                def multiply():
                    d = p["fo_def"]
                    e.var("fo_sc", _operand(e, d, 1))
                    good = e.both(e.eq(_eop(e, d), _op(Operation.MUL_WRAP)), _constant(e, p["fo_sc"]), _in(e, _cval(e, p["fo_sc"]), (2, 4, 8)),
                                  e.not_(_constant(e, _operand(e, d, 0))))

                    def record():
                        _set_rt(e, T_SCALE_BASE, v, _operand(e, d, 0))
                        _set_rt(e, T_SCALE, v, _cval(e, p["fo_sc"]))
                        _set_rt(e, T_ERASED, v, 1)
                        e.if_(e.ne(p["fo_inner"], NONE), lambda: _set_rt(e, T_ERASED, p["fo_inner"], 1))

                    e.if_(good, record)

                e.if_(e.both(e.ne(p["fo_def"], NONE), e.ne(p["fo_def"], NOT_CALL)), multiply)

            e.if_(counted, check)

        e.for_("fo_v", 0, p["fo_n"], scale)

        # store(p, i, load(p, i) + c) with a proven index: one ``add [p + i*s], c``.
        def rmw():
            e.var("fo_b", _block_at(e, p["fo_bi"]))

            def node():
                e.var("fo_node", _node_at(e, p["fo_b"], p["fo_m"]))
                node_ = p["fo_node"]
                store = e.both(e.eq(_eop(e, node_), _op(Operation.CHECKED_STORE_BITS_LE)), _in(e, _attribute(e, node_, 0), (4, 8)))

                def check():
                    e.var("fo_total", _operand(e, node_, 2))
                    _definition(e, p["fo_total"], "fo_add")
                    add_ok = e.both(e.ne(p["fo_add"], NONE), e.eq(_eop(e, e.sel(e.ne(p["fo_add"], NONE), p["fo_add"], 0)), _op(Operation.ADD_WRAP)),
                                    e.eq(_pos_block(e, p["fo_total"]), p["fo_bi"]), e.eq(_rt(e, T_EARLY, p["fo_total"]), 1))

                    def operands():
                        a = p["fo_add"]
                        second_constant = _constant(e, _operand(e, a, 1))
                        e.var("fo_loaded", e.sel(second_constant, _operand(e, a, 0), _operand(e, a, 1)))
                        e.var("fo_addend", e.sel(second_constant, _operand(e, a, 1), _operand(e, a, 0)))
                        _definition(e, p["fo_loaded"], "fo_load")
                        c = _cval(e, p["fo_addend"])
                        load = p["fo_load"]
                        safe = e.sel(e.ne(load, NONE), load, 0)
                        token = _output(e, safe, 1)
                        good = e.both(_constant(e, p["fo_addend"]), e.lt(c, 1 << 31), e.ne(load, NONE),
                                      e.eq(_eop(e, safe), _op(Operation.CHECKED_LOAD_BITS_LE)), e.eq(_pos_block(e, p["fo_loaded"]), p["fo_bi"]),
                                      e.eq(_operand(e, safe, 0), _operand(e, node_, 0)), e.eq(_operand(e, safe, 1), _operand(e, node_, 1)),
                                      e.eq(_attribute(e, safe, 0), _attribute(e, node_, 0)), e.eq(_rt(e, T_EARLY, p["fo_loaded"]), 1),
                                      e.eq(_width(e, p["fo_loaded"]), e.mul(8, _attribute(e, node_, 0))), e.eq(_operand(e, node_, 3), token))

                        def record():
                            _set_rt(e, T_RMW, _output(e, node_, 0), c)
                            _set_rt(e, T_RMW_ERASED, p["fo_loaded"], 1)
                            _set_rt(e, T_RMW_ERASED, p["fo_total"], 1)

                        e.if_(good, record)

                    e.if_(add_ok, operands)

                e.if_(store, lambda: e.if_(e.ne(_call_value(e, "access_proven", node_), 0), check))

            e.for_("fo_m", 0, _f(e, p["fo_b"], B_NNODES), node)

        e.for_("fo_bi", 0, p["fo_nb"], rmw)

        # Value tables (per block, last node first), then member values.
        def value_tables():
            e.var("fo_b", _block_at(e, p["fo_bi"]))
            e.var("fo_tab", e.ld(e.add(p["fo_btab"], p["fo_bi"])))
            e.var("fo_m", _f(e, p["fo_b"], B_NNODES))

            def node():
                e.set("fo_m", e.sub(p["fo_m"], 1))
                e.var("fo_node", _node_at(e, p["fo_b"], p["fo_m"]))
                e.var("fo_root", _output(e, p["fo_node"], 0))
                root = p["fo_root"]
                in_tree = e.both(e.ne(p["fo_tab"], NONE), e.ne(e.ld(e.add(e.ld(e.add(e.sel(e.ne(p["fo_tab"], NONE), p["fo_tab"], 0), 3)), p["fo_m"])), 0))
                skip = e.either(e.eq(_f(e, p["fo_node"], N_NRES), 0), e.ne(_rt(e, T_TABLE_ERASED, root), 0), e.eq(_width(e, root), 0), in_tree,
                                e.not_(_in(e, _eop(e, p["fo_node"]), TABLE_OPERATIONS)),
                                e.eq(fused_at(p["fo_bi"]), p["fo_m"]))  # ADR-284: not the fused branch compare

                def check():
                    e.var("fo_found", _call(e, "predicate_table", p["fo_bi"], root))

                    def record():
                        found = p["fo_found"]
                        _set_rt(e, T_VT_SUBJECT, root, e.ld(found))
                        _set_rt(e, T_VT_TABLE, root, found)
                        e.var("fo_flags", e.ld(e.add(found, 3)))
                        e.for_("fo_k", 0, _f(e, p["fo_b"], B_NNODES), lambda: e.if_(
                            e.both(e.ne(e.ld(e.add(p["fo_flags"], p["fo_k"])), 0), e.ne(p["fo_k"], p["fo_m"])),
                            lambda: _set_rt(e, T_TABLE_ERASED, _output(e, _node_at(e, p["fo_b"], p["fo_k"]), 0), 1)))

                    e.if_(e.ne(p["fo_found"], NOT_CALL), record)

                e.if_(e.not_(skip), check)

            e.while_(lambda: e.ne(p["fo_m"], 0), node)

        e.for_("fo_bi", 0, p["fo_nb"], value_tables)
        e.for_("fo_v", 0, p["fo_n"], lambda: e.if_(e.ne(_rt(e, T_TABLE_ERASED, p["fo_v"]), 0), lambda: _set_rt(e, T_ERASED, p["fo_v"], 1)))

        def member_values():
            e.var("fo_b", _block_at(e, p["fo_bi"]))
            e.var("fo_mrec", e.ld(e.add(p["fo_memb"], p["fo_bi"])))
            e.var("fo_m", _f(e, p["fo_b"], B_NNODES))

            def node():
                e.set("fo_m", e.sub(p["fo_m"], 1))
                e.var("fo_node", _node_at(e, p["fo_b"], p["fo_m"]))
                e.var("fo_root", _output(e, p["fo_node"], 0))
                root = p["fo_root"]
                in_tree = e.both(e.ne(p["fo_mrec"], NONE), e.ne(e.ld(e.add(e.ld(e.add(e.sel(e.ne(p["fo_mrec"], NONE), p["fo_mrec"], 0), 3)), p["fo_m"])), 0))
                skip = e.either(e.eq(_f(e, p["fo_node"], N_NRES), 0), e.ne(_eop(e, p["fo_node"]), _op(Operation.BIT_OR)), e.ne(_rt(e, T_MEMBER_ERASED, root), 0),
                                e.eq(_width(e, root), 0), e.ne(_rt(e, T_TABLE_ERASED, root), 0), e.ne(_rt(e, T_VT_SUBJECT, root), NONE), in_tree)
                e.if_(e.not_(skip), lambda: _call(e, "member_value", p["fo_bi"], root))

            e.while_(lambda: e.ne(p["fo_m"], 0), node)

        e.for_("fo_bi", 0, p["fo_nb"], member_values)
        e.for_("fo_v", 0, p["fo_n"], lambda: e.if_(e.ne(_rt(e, T_MEMBER_ERASED, p["fo_v"]), 0), lambda: _set_rt(e, T_ERASED, p["fo_v"], 1)))
        _call(e, "compare_loads")
        _call(e, "edge_sinking")
        _call(e, "call_aliases")
        e.give(1)
    return _function((), build, tables)


def _call_value(e: E, name: str, *arguments):
    """A call whose 0 or 1 result is a value (NONE still declines)."""
    result = e.call(_FN[name], *arguments)
    _ok(e, e.ne(result, NONE))
    return result


def _compare_loads(tables):
    """``compare_load``: a 4/8-byte load whose only use is a fused compare, with no write or call after it in its
    block, becomes the compare's memory operand: ``T_CL`` holds a record ``[base, index or NONE, scale, displacement]``."""
    def build(e: E):
        p = e.p
        e.var("cl_fused", _ra(e, R_FUSED))

        def block():
            e.var("cl_fi", e.ld(e.add(p["cl_fused"], p["cl_bi"])))

            def fused():
                e.var("cl_b", _block_at(e, p["cl_bi"]))
                e.var("cl_cmp", _node_at(e, p["cl_b"], p["cl_fi"]))
                e.var("cl_done", 0)
                for first in (0, 1):
                    def attempt(first=first):
                        e.var("cl_cand", _operand(e, p["cl_cmp"], first))
                        e.var("cl_other", _operand(e, p["cl_cmp"], 1 - first))
                        cand = p["cl_cand"]
                        basic = e.both(e.not_(_is_param(e, cand)), e.eq(_pos_block(e, cand), p["cl_bi"]), e.eq(_pos_result(e, cand), 0),
                                       e.eq(_rt(e, T_EARLY, cand), 1), e.ne(p["cl_other"], cand))

                        def loaded():
                            e.var("cl_ci", _pos_index(e, cand))
                            e.var("cl_load", _node_at(e, p["cl_b"], p["cl_ci"]))
                            load = p["cl_load"]
                            e.var("cl_size", e.sel(e.ne(_attribute_count(e, load), 0), _attribute(e, load, 0), 0))
                            size = p["cl_size"]
                            sized = e.both(_in(e, size, (4, 8)), e.eq(_width(e, cand), e.mul(size, 8)), e.ne(_width(e, p["cl_other"]), 0),
                                           e.not_(_immediate(e, p["cl_other"], _width(e, cand))))

                            def placed():
                                e.var("cl_later", 0)
                                e.for_("cl_k", e.add(p["cl_ci"], 1), _f(e, p["cl_b"], B_NNODES), lambda: e.if_(
                                    _in(e, _eop(e, _node_at(e, p["cl_b"], p["cl_k"])), WRITES), lambda: e.set("cl_later", 1)))
                                free = e.both(e.eq(p["cl_later"], 0), e.eq(_rt(e, T_RMW_ERASED, cand), 0), e.eq(_rt(e, T_MEMBER_ERASED, cand), 0),
                                              e.eq(_rt(e, T_TABLE_ERASED, cand), 0))

                                def decide():
                                    e.set("cl_done", 1)  # ``break`` whether or not the load qualifies below
                                    e.var("cl_op", _eop(e, load))

                                    def record(base, index, scale, displacement):
                                        e.var("cl_rec", e.alloc(4))
                                        _ok(e, e.ne(p["cl_rec"], NONE))
                                        for field, value in enumerate((base, index, scale, displacement)):
                                            e.st(e.add(p["cl_rec"], field), value)
                                        _set_rt(e, T_CL, cand, p["cl_rec"])

                                    def plain():
                                        e.var("cl_ptr", _operand(e, load, 0))
                                        folded = e.ne(_rt(e, T_FOLD_BASE, p["cl_ptr"]), NONE)
                                        record(e.sel(folded, _rt(e, T_FOLD_BASE, p["cl_ptr"]), p["cl_ptr"]), NONE, 1,
                                               e.sel(folded, _rt(e, T_FOLD_DISP, p["cl_ptr"]), 0))

                                    def checked():
                                        e.var("cl_ix", _operand(e, load, 1))
                                        scaled = e.ne(_rt(e, T_SCALE_BASE, p["cl_ix"]), NONE)
                                        record(_operand(e, load, 0), e.sel(scaled, _rt(e, T_SCALE_BASE, p["cl_ix"]), p["cl_ix"]),
                                               e.sel(scaled, _rt(e, T_SCALE, p["cl_ix"]), 1), 0)

                                    e.if_(e.eq(p["cl_op"], _op(Operation.LOAD_BITS_LE)), plain, lambda: e.if_(
                                        e.eq(p["cl_op"], _op(Operation.CHECKED_LOAD_BITS_LE)), lambda: e.if_(
                                            e.ne(_call_value(e, "access_proven", load), 0), checked)))

                                e.if_(free, decide)

                            e.if_(sized, placed)

                        e.if_(basic, loaded)

                    e.if_(e.eq(p["cl_done"], 0), attempt)

            e.if_(e.ne(p["cl_fi"], NONE), fused)

        e.for_("cl_bi", 0, _g(e, G_BCOUNT), block)
        e.give(1)
    return _function((), build, tables)


def _edge_sinking(tables):
    """``edge_sunk`` (ADR-211): an add/sub of an imm32 whose only use is one argument of its block's conditional
    branch edges is computed on that edge (``T_SINK_*``; the value is erased from the body)."""
    def build(e: E):
        p = e.p

        def block():
            e.var("es_b", _block_at(e, p["es_bi"]))

            def conditional():
                def node():
                    e.var("es_node", _node_at(e, p["es_b"], p["es_m"]))
                    node_ = p["es_node"]
                    e.var("es_v", _output(e, node_, 0))
                    v = p["es_v"]
                    e.var("es_w", _width(e, v))
                    e.var("es_op", _eop(e, node_))
                    candidate = e.both(e.ne(_f(e, node_, N_NRES), 0), _in(e, p["es_op"], (_op(Operation.ADD_WRAP), _op(Operation.SUB_WRAP))),
                                       _in(e, p["es_w"], (32, 64)), e.eq(_rt(e, T_ERASED, v), 0))

                    def check():
                        e.var("es_l", _operand(e, node_, 0))
                        e.var("es_r", _operand(e, node_, 1))
                        shape = e.both(_constant(e, p["es_r"]), e.not_(_constant(e, p["es_l"])), e.eq(_width(e, p["es_l"]), p["es_w"]))

                        def amount():
                            c = _cval(e, p["es_r"])
                            raw = e.sel(e.eq(p["es_op"], _op(Operation.ADD_WRAP)), c, e.sub(0, c))
                            masked = e.sel(e.eq(p["es_w"], 64), raw, e.and_(raw, 0xFFFFFFFF))
                            e.var("es_amount", masked)
                            # signed at the width; must lie in [-2^31, 2^31)
                            half = e.sel(e.eq(p["es_w"], 64), 1 << 63, 1 << 31)
                            negative = e.le(half, p["es_amount"])
                            e.var("es_neg", e.flag(negative))
                            magnitude = e.sel(negative, e.sub(e.sel(e.eq(p["es_w"], 64), 0, 1 << 32), p["es_amount"]), p["es_amount"])
                            e.var("es_mag", magnitude)
                            fits = e.sel(negative, e.flag(e.le(p["es_mag"], 1 << 31)), e.flag(e.lt(p["es_mag"], 1 << 31)))
                            signed = e.sel(negative, e.sub(0, p["es_mag"]), p["es_mag"])  # two's complement word
                            e.var("es_signed", signed)

                            def counted():
                                e.var("es_args", 0)

                                def edge():
                                    e.var("es_e", e.add(_f(e, p["es_b"], B_EDGES), e.mul(p["es_k"], EDGE)))
                                    e.for_("es_a", 0, _f(e, p["es_e"], 1), lambda: e.if_(e.eq(e.ld(e.add(_f(e, p["es_e"], 2), p["es_a"])), v),
                                                                                         lambda: e.set("es_args", e.add(p["es_args"], 1))))

                                e.for_("es_k", 0, _f(e, p["es_b"], B_NEDGES), edge)
                                e.var("es_tv", 0)
                                e.for_("es_k", 0, _f(e, p["es_b"], B_NVALUES), lambda: e.if_(e.eq(e.ld(e.add(_f(e, p["es_b"], B_VALUES), p["es_k"])), v),
                                                                                              lambda: e.set("es_tv", 1)))
                                sink = e.both(e.eq(_rt(e, T_EARLY, v), 1), e.eq(p["es_args"], 1), e.eq(p["es_tv"], 0))
                                e.if_(sink, lambda: (_set_rt(e, T_SINK_OPERAND, v, p["es_l"]), _set_rt(e, T_SINK_AMOUNT, v, p["es_signed"])))

                            e.if_(e.ne(fits, 0), counted)

                        e.if_(shape, amount)

                    e.if_(candidate, check)

                e.for_("es_m", 0, _f(e, p["es_b"], B_NNODES), node)

            e.if_(e.eq(_f(e, p["es_b"], B_KIND), CONDITIONAL), conditional)

        e.for_("es_bi", 0, _g(e, G_BCOUNT), block)
        e.for_("es_v", 0, _g(e, G_VCOUNT), lambda: e.if_(e.ne(_rt(e, T_SINK_OPERAND, p["es_v"]), NONE), lambda: _set_rt(e, T_ERASED, p["es_v"], 1)))
        e.give(1)
    return _function((), build, tables)


def _call_aliases(tables):
    """Borrowed views a direct call gives back (ADR-101): ``T_ALIAS`` maps each such result to the passed operand."""
    def build(e: E):
        p = e.p

        def block():
            e.var("ca_b", _block_at(e, p["ca_bi"]))

            def node():
                e.var("ca_node", _node_at(e, p["ca_b"], p["ca_m"]))

                def direct():
                    _callee_object(e, p["ca_node"], "ca_callee")
                    _ok(e, e.ne(p["ca_callee"], NONE))
                    e.var("ca_map", _call(e, "borrowed", p["ca_callee"]))
                    e.for_("ca_r", 0, _f(e, p["ca_node"], N_NRES), lambda: e.if_(e.ne(e.ld(e.add(p["ca_map"], p["ca_r"])), NONE), lambda: _set_rt(
                        e, T_ALIAS, _output(e, p["ca_node"], p["ca_r"]), _operand(e, p["ca_node"], e.ld(e.add(p["ca_map"], p["ca_r"]))))))

                e.if_(e.eq(_eop(e, p["ca_node"]), DIRECT_CALL), direct)

            e.for_("ca_m", 0, _f(e, p["ca_b"], B_NNODES), node)

        e.for_("ca_bi", 0, _g(e, G_BCOUNT), block)
        e.give(1)
    return _function((), build, tables)


# -- uses, homes, pins, and the frame ---------------------------------------------------------------------------

# Per block (``R_USES`` array, by position): a record ``[count, values, position lists, list lengths]``.
U_COUNT, U_VALUES, U_LISTS, U_LENGTHS = range(4)
T_UIDX = T_S4  # value -> index in the current block's use record (stamped by T_S3)


def _uses_record(e: E, bi):
    return e.ld(e.add(_ra(e, R_USES), bi))


def _enumerate_uses(e: E, bi, block, use):
    """``use(value, position)`` for every use the bootstrap records in block ``bi`` (``uses_by_block``), in its order."""
    from xax_selfhost_general_ranges import G2_MARKS, G2_NMARKS, MARK_WORDS

    p = e.p
    e.var("eu_position", _f(e, block, B_NNODES))
    fused = e.ld(e.add(_ra(e, R_FUSED), bi))
    e.var("eu_fused", fused)
    e.var("eu_btab", e.ld(e.add(_ra(e, R_BTAB), bi)))
    e.var("eu_memb", e.ld(e.add(_ra(e, R_MEMB), bi)))

    def with_aliases(value):
        use_value = value
        e.var("eu_x", use_value)
        e.if_(e.ne(_width(e, p["eu_x"]), 0), lambda: use(p["eu_x"], p["eu_use_position"]))
        e.var("eu_alias", _rt(e, T_ALIAS, p["eu_x"]))
        e.if_(e.both(e.ne(p["eu_alias"], NONE), e.ne(_width(e, p["eu_alias"]), 0)), lambda: use(p["eu_alias"], p["eu_use_position"]))

    def node():
        e.var("eu_node", _node_at(e, block, p["eu_m"]))
        node_ = p["eu_node"]
        e.var("eu_result", e.sel(e.ne(_f(e, node_, N_NRES), 0), _output(e, node_, 0), NONE))
        result = p["eu_result"]
        has = e.ne(result, NONE)
        safe = e.sel(has, result, 0)
        erased = e.both(has, e.either(e.ne(_rt(e, T_ERASED, safe), 0), e.ne(_rt(e, T_RMW_ERASED, safe), 0)))
        e.var("eu_cl", e.sel(has, _rt(e, T_CL, safe), NONE))

        def compare_load():
            e.var("eu_cb", e.ld(p["eu_cl"]))
            e.var("eu_ci", e.ld(e.add(p["eu_cl"], 1)))
            e.if_(e.ne(_width(e, p["eu_cb"]), 0), lambda: use(p["eu_cb"], p["eu_position"]))
            e.if_(e.both(e.ne(p["eu_ci"], NONE), e.ne(_width(e, e.sel(e.ne(p["eu_ci"], NONE), p["eu_ci"], 0)), 0)), lambda: use(p["eu_ci"], p["eu_position"]))

        def ordinary():
            m = p["eu_m"]
            in_tree = e.either(
                e.eq(p["eu_fused"], m),
                e.both(e.ne(p["eu_memb"], NONE), e.ne(e.ld(e.add(e.ld(e.add(e.sel(e.ne(p["eu_memb"], NONE), p["eu_memb"], 0), 3)), m)), 0)),
                e.both(e.ne(p["eu_btab"], NONE), e.ne(e.ld(e.add(e.ld(e.add(e.sel(e.ne(p["eu_btab"], NONE), p["eu_btab"], 0), 3)), m)), 0)))
            e.var("eu_use_position", e.sel(in_tree, p["eu_position"], m))
            # operands_of: a value table or member value reads only its subject.
            e.var("eu_vt", e.sel(has, _rt(e, T_VT_SUBJECT, safe), NONE))
            e.var("eu_mv", e.sel(has, _rt(e, T_MV_SUBJECT, safe), NONE))

            def operand(value):
                e.var("eu_o", value)
                scaled = e.ne(_rt(e, T_SCALE_BASE, p["eu_o"]), NONE)
                folded = e.ne(_rt(e, T_FOLD_BASE, p["eu_o"]), NONE)
                e.var("eu_t", e.sel(scaled, _rt(e, T_SCALE_BASE, p["eu_o"]), e.sel(folded, _rt(e, T_FOLD_BASE, p["eu_o"]), p["eu_o"])))

                def each(item):
                    e.var("eu_i", item)
                    ok = e.both(e.ne(_width(e, p["eu_i"]), 0), e.eq(_rt(e, T_RMW_ERASED, p["eu_i"]), 0), e.eq(_rt(e, T_CL, p["eu_i"]), NONE))
                    e.if_(ok, lambda: use(p["eu_i"], p["eu_use_position"]))

                each(p["eu_t"])
                e.var("eu_ta", _rt(e, T_ALIAS, p["eu_t"]))
                e.if_(e.ne(p["eu_ta"], NONE), lambda: each(p["eu_ta"]))

            e.if_(e.ne(p["eu_vt"], NONE), lambda: operand(p["eu_vt"]), lambda: e.if_(
                e.ne(p["eu_mv"], NONE), lambda: operand(p["eu_mv"]), lambda: e.for_("eu_k", 0, _f(e, node_, N_NOPS), lambda: operand(_operand(e, node_, p["eu_k"])))))

            # The prefetches after a marked load read their array pointers.
            def marks():
                def mark():
                    e.var("eu_mk", e.add(_g2(e, G2_MARKS), e.mul(p["eu_q"], MARK_WORDS)))

                    def hit():
                        e.var("eu_list", e.ld(e.add(p["eu_mk"], 1)))
                        e.for_("eu_j", 0, e.ld(e.add(p["eu_mk"], 2)), lambda: use(e.ld(e.add(p["eu_list"], e.mul(p["eu_j"], 2))), m))

                    e.if_(e.eq(e.ld(p["eu_mk"]), result), hit)

                e.for_("eu_q", 0, _g2(e, G2_NMARKS), mark)

            e.if_(has, marks)

            def aliases():
                def each():
                    e.var("eu_r", _output(e, node_, p["eu_k"]))
                    e.var("eu_ao", _rt(e, T_ALIAS, p["eu_r"]))
                    e.if_(e.both(e.ne(p["eu_ao"], NONE), e.ne(_width(e, e.sel(e.ne(p["eu_ao"], NONE), p["eu_ao"], 0)), 0)), lambda: use(p["eu_ao"], e.add(m, 1)))

                e.for_("eu_k", 0, _f(e, node_, N_NRES), each)

            e.if_(e.eq(_eop(e, node_), DIRECT_CALL), aliases)

        e.if_(e.not_(erased), lambda: e.if_(e.ne(p["eu_cl"], NONE), compare_load, ordinary))

    e.for_("eu_m", 0, _f(e, block, B_NNODES), node)
    e.var("eu_use_position", p["eu_position"])
    e.for_("eu_k", 0, _f(e, block, B_NVALUES), lambda: with_aliases(e.ld(e.add(_f(e, block, B_VALUES), p["eu_k"]))))

    def edge():
        e.var("eu_e", e.add(_f(e, block, B_EDGES), e.mul(p["eu_j"], EDGE)))

        def argument():
            e.var("eu_a", e.ld(e.add(_f(e, p["eu_e"], 2), p["eu_k"])))
            sunk = e.ne(_rt(e, T_SINK_OPERAND, p["eu_a"]), NONE)
            with_aliases(e.sel(sunk, _rt(e, T_SINK_OPERAND, p["eu_a"]), p["eu_a"]))

        e.for_("eu_k", 0, _f(e, p["eu_e"], 1), argument)

    e.for_("eu_j", 0, _f(e, block, B_NEDGES), edge)


def _uses(tables):
    """``uses_by_block`` (each block's values in first-use order, with sorted use positions) and ``homes`` (values used
    outside their block, not constants or stack storage, sorted)."""
    def build(e: E):
        p = e.p
        nb = _g(e, G_BCOUNT)
        e.var("us_nb", nb)
        e.var("us_records", e.alloc(e.add(p["us_nb"], 1)))
        _ok(e, e.ne(p["us_records"], NONE))
        _set_ra(e, R_USES, p["us_records"])
        n = _g(e, G_VCOUNT)
        e.var("us_n", n)
        e.var("us_homes", e.alloc(e.add(p["us_n"], 1)))
        _ok(e, e.ne(p["us_homes"], NONE))
        e.var("us_nh", 0)
        e.var("us_home_stamp", _stamp(e))

        def block():
            e.var("us_b", _block_at(e, p["us_bi"]))
            e.var("us_stamp", _stamp(e))
            e.var("us_count", 0)

            def count(value, _position):
                e.var("us_v", value)

                def first():
                    _set_rt(e, T_USTAMP, p["us_v"], p["us_stamp"])
                    _set_rt(e, T_UIDX, p["us_v"], p["us_count"])
                    _set_rt(e, T_UCOUNT, p["us_v"], 0)
                    e.set("us_count", e.add(p["us_count"], 1))

                e.if_(e.ne(_rt(e, T_USTAMP, p["us_v"]), p["us_stamp"]), first)
                _set_rt(e, T_UCOUNT, p["us_v"], e.add(_rt(e, T_UCOUNT, p["us_v"]), 1))

            _enumerate_uses(e, p["us_bi"], p["us_b"], count)
            # ADR-284: the block's values, in first-use order, in an array of the block's own size (a function's whole
            # value count per block exhausted the arena on the compiler's own functions).
            e.var("us_values", e.alloc(e.add(p["us_count"], 1)))
            _ok(e, e.ne(p["us_values"], NONE))
            _enumerate_uses(e, p["us_bi"], p["us_b"], lambda value, _position: e.st(e.add(p["us_values"], _rt(e, T_UIDX, value)), value))
            e.var("us_lists", e.alloc(e.add(p["us_count"], 1)))
            e.var("us_lengths", e.alloc(e.add(p["us_count"], 1)))
            _ok(e, e.both(e.ne(p["us_lists"], NONE), e.ne(p["us_lengths"], NONE)))

            def allocate():
                e.var("us_v", e.ld(e.add(p["us_values"], p["us_k"])))
                e.var("us_list", e.alloc(e.add(_rt(e, T_UCOUNT, p["us_v"]), 1)))
                _ok(e, e.ne(p["us_list"], NONE))
                e.st(e.add(p["us_lists"], p["us_k"]), p["us_list"])
                e.st(e.add(p["us_lengths"], p["us_k"]), 0)

            e.for_("us_k", 0, p["us_count"], allocate)

            def fill(value, position):
                e.var("us_v", value)
                e.var("us_i", _rt(e, T_UIDX, p["us_v"]))
                e.var("us_len_at", e.add(p["us_lengths"], p["us_i"]))
                e.st(e.add(e.ld(e.add(p["us_lists"], p["us_i"])), e.ld(p["us_len_at"])), position)
                e.st(p["us_len_at"], e.add(e.ld(p["us_len_at"]), 1))

            _enumerate_uses(e, p["us_bi"], p["us_b"], fill)

            def sort():
                e.var("us_list", e.ld(e.add(p["us_lists"], p["us_k"])))
                e.var("us_len", e.ld(e.add(p["us_lengths"], p["us_k"])))

                def insert():
                    e.var("us_item", e.ld(e.add(p["us_list"], p["us_s"])))
                    e.var("us_j", p["us_s"])
                    e.while_(lambda: e.both(e.lt(0, p["us_j"]), e.lt(p["us_item"], e.ld(e.add(p["us_list"], e.sub(p["us_j"], 1))))),
                             lambda: (e.st(e.add(p["us_list"], p["us_j"]), e.ld(e.add(p["us_list"], e.sub(p["us_j"], 1)))), e.set("us_j", e.sub(p["us_j"], 1))))
                    e.st(e.add(p["us_list"], p["us_j"]), p["us_item"])

                e.for_("us_s", 1, p["us_len"], insert)

            e.for_("us_k", 0, p["us_count"], sort)
            e.var("us_record", e.alloc(4))
            _ok(e, e.ne(p["us_record"], NONE))
            for field, value in ((U_COUNT, p["us_count"]), (U_VALUES, p["us_values"]), (U_LISTS, p["us_lists"]), (U_LENGTHS, p["us_lengths"])):
                e.st(e.add(p["us_record"], field), value)
            e.st(e.add(p["us_records"], p["us_bi"]), p["us_record"])

            def home():
                e.var("us_v", e.ld(e.add(p["us_values"], p["us_k"])))
                v = p["us_v"]
                candidate = e.both(e.ne(_pos_block(e, v), p["us_bi"]), e.not_(_constant(e, v)), e.eq(_rt(e, T_STACK, v), NONE),
                                   e.ne(_rt(e, T_S1, v), p["us_home_stamp"]))
                e.if_(candidate, lambda: (_set_rt(e, T_S1, v, p["us_home_stamp"]), e.st(e.add(p["us_homes"], p["us_nh"]), v), e.set("us_nh", e.add(p["us_nh"], 1))))

            e.for_("us_k", 0, p["us_count"], home)

        e.for_("us_bi", 0, p["us_nb"], block)
        _sort_by_key(e, p["us_homes"], p["us_nh"], "us_hs")
        _set_ra(e, R_HOMES, p["us_homes"])
        _set_ra(e, R_NHOMES, p["us_nh"])
        e.give(1)
    return _function((), build, tables)


def _sort_by_key(e: E, array, count, prefix: str):
    """Insertion sort of value ids at ``array`` by their positions (the bootstrap's ValueRef order)."""
    p = e.p

    def insert():
        e.var(f"{prefix}_item", e.ld(e.add(array, p[f"{prefix}_s"])))
        e.var(f"{prefix}_j", p[f"{prefix}_s"])
        before = lambda: e.both(e.lt(0, p[f"{prefix}_j"]), e.lt(_key(e, p[f"{prefix}_item"]), _key(e, e.ld(e.add(array, e.sub(p[f"{prefix}_j"], 1))))))  # noqa: E731
        e.while_(before, lambda: (e.st(e.add(array, p[f"{prefix}_j"]), e.ld(e.add(array, e.sub(p[f"{prefix}_j"], 1)))), e.set(f"{prefix}_j", e.sub(p[f"{prefix}_j"], 1))))
        e.st(e.add(array, p[f"{prefix}_j"]), p[f"{prefix}_item"])

    e.for_(f"{prefix}_s", 1, count, insert)


def _uses_in(e: E, bi, value, name: str):
    """The index of ``value`` in block ``bi``'s use record, into ``name`` (NONE when the block does not use it)."""
    p = e.p
    e.var(f"{name}_rec", _uses_record(e, bi))
    e.var(name, NONE)
    e.for_(f"{name}_k", 0, e.ld(e.add(p[f"{name}_rec"], U_COUNT)), lambda: e.if_(
        e.eq(e.ld(e.add(e.ld(e.add(p[f"{name}_rec"], U_VALUES)), p[f"{name}_k"])), value), lambda: e.set(name, p[f"{name}_k"])))


def _successor_positions(e: E, block, visit):
    """``visit(target position)`` for each edge of ``block``, in order."""
    p = e.p
    e.for_("sp_k", 0, _f(e, block, B_NEDGES), lambda: visit(_f(e, _f(e, e.add(_f(e, block, B_EDGES), e.mul(p["sp_k"], EDGE)), 0), B_POS)))


def _reaches(tables):
    """1 when block ``goal`` is reachable from block ``start`` (``start`` itself included), else 0 (by positions)."""
    def build(e: E):
        p = e.p
        e.if_(e.eq(p["start"], p["goal"]), lambda: e.give(1))
        e.var("rc_mark", e.hd(H_ARENA))
        n = _g(e, G_BCOUNT)
        e.var("rc_seen", e.alloc(e.add(n, 1)))
        e.var("rc_stack", e.alloc(e.add(e.mul(n, 4), 2)))
        _ok(e, e.both(e.ne(p["rc_seen"], NONE), e.ne(p["rc_stack"], NONE)))
        e.for_("rc_k", 0, n, lambda: e.st(e.add(p["rc_seen"], p["rc_k"]), 0))
        e.st(p["rc_stack"], p["start"])
        e.var("rc_sp", 1)
        e.var("rc_found", 0)

        def step():
            e.set("rc_sp", e.sub(p["rc_sp"], 1))
            e.var("rc_x", e.ld(e.add(p["rc_stack"], p["rc_sp"])))
            e.if_(e.eq(p["rc_x"], p["goal"]), lambda: e.set("rc_found", 1))

            def visit():
                e.st(e.add(p["rc_seen"], p["rc_x"]), 1)
                _successor_positions(e, _block_at(e, p["rc_x"]), lambda t: (e.st(e.add(p["rc_stack"], p["rc_sp"]), t), e.set("rc_sp", e.add(p["rc_sp"], 1))))

            e.if_(e.both(e.eq(p["rc_found"], 0), e.eq(e.ld(e.add(p["rc_seen"], p["rc_x"])), 0)), visit)

        e.while_(lambda: e.both(e.ne(p["rc_sp"], 0), e.eq(p["rc_found"], 0)), step)
        _release(e, p["rc_mark"], p["rc_found"])
    return _function(("start", "goal"), build, tables)


def _machine_params(e: E, block, visit):
    """``visit(index in the machine parameters, value)`` for each block parameter with a machine width."""
    p = e.p
    e.var("mpv_i", 0)

    def each():
        e.var("mpv_v", e.ld(e.add(_f(e, block, B_INPUTS), p["mpv_k"])))
        e.if_(e.ne(_width(e, p["mpv_v"]), 0), lambda: (visit(p["mpv_i"], p["mpv_v"]), e.set("mpv_i", e.add(p["mpv_i"], 1))))

    e.for_("mpv_k", 0, _f(e, block, B_NP), each)


def _pressure(tables):
    """``_block_pressure(block bi)``: the peak count of live machine values; ``ignore_constants`` = 1 also ignores
    constants and the block's machine parameters used only at its end (``hoisted constants``' demand)."""
    def build(e: E):
        p = e.p
        e.var("pr_b", _block_at(e, p["bi"]))
        e.var("pr_rec", _uses_record(e, p["bi"]))
        e.var("pr_count", e.ld(e.add(p["pr_rec"], U_COUNT)))
        e.var("pr_n", _f(e, p["pr_b"], B_NNODES))
        e.var("pr_last", e.alloc(e.add(p["pr_count"], 1)))
        e.var("pr_def", e.alloc(e.add(p["pr_count"], 1)))
        e.var("pr_skip", e.alloc(e.add(p["pr_count"], 1)))
        _ok(e, e.both(e.ne(p["pr_last"], NONE), e.ne(p["pr_def"], NONE), e.ne(p["pr_skip"], NONE)))

        def entry():
            e.var("pr_v", e.ld(e.add(e.ld(e.add(p["pr_rec"], U_VALUES)), p["pr_k"])))
            e.var("pr_len", e.ld(e.add(e.ld(e.add(p["pr_rec"], U_LENGTHS)), p["pr_k"])))
            e.var("pr_list", e.ld(e.add(e.ld(e.add(p["pr_rec"], U_LISTS)), p["pr_k"])))
            e.st(e.add(p["pr_last"], p["pr_k"]), e.ld(e.add(p["pr_list"], e.sub(p["pr_len"], 1))))
            local = e.both(e.not_(_is_param(e, p["pr_v"])), e.eq(_pos_block(e, p["pr_v"]), p["bi"]))
            e.st(e.add(p["pr_def"], p["pr_k"]), e.sel(local, e.add(_pos_index(e, p["pr_v"]), 1), 0))  # defined_at + 1 (0: -1)
            e.var("pr_ignore", 0)

            def ignorable():
                e.if_(_constant(e, p["pr_v"]), lambda: e.set("pr_ignore", 1))
                at_end = e.both(_is_param(e, p["pr_v"]), e.eq(_pos_block(e, p["pr_v"]), p["bi"]), e.ne(_width(e, p["pr_v"]), 0))

                def all_at_end():
                    e.var("pr_all", 1)
                    e.for_("pr_j", 0, p["pr_len"], lambda: e.if_(e.ne(e.ld(e.add(p["pr_list"], p["pr_j"])), p["pr_n"]), lambda: e.set("pr_all", 0)))
                    e.if_(e.ne(p["pr_all"], 0), lambda: e.set("pr_ignore", 1))

                e.if_(at_end, all_at_end)

            e.if_(e.ne(p["ignore_constants"], 0), ignorable)
            e.st(e.add(p["pr_skip"], p["pr_k"]), p["pr_ignore"])

        e.for_("pr_k", 0, p["pr_count"], entry)
        e.var("pr_peak", 0)

        def position():
            e.var("pr_live", 0)

            def each():
                live = e.both(e.eq(e.ld(e.add(p["pr_skip"], p["pr_k"])), 0))
                d1 = e.ld(e.add(p["pr_def"], p["pr_k"]))  # defined_at + 1
                end = e.ld(e.add(p["pr_last"], p["pr_k"]))
                pos1 = e.add(p["pr_pos"], 1)
                spanning = e.both(e.le(d1, pos1), e.lt(p["pr_pos"], end))
                defined_here = e.both(e.eq(d1, pos1), e.le(end, p["pr_pos"]))
                e.if_(e.both(live, e.either(spanning, defined_here)), lambda: e.set("pr_live", e.add(p["pr_live"], 1)))

            e.for_("pr_k", 0, p["pr_count"], each)
            e.if_(e.lt(p["pr_peak"], p["pr_live"]), lambda: e.set("pr_peak", p["pr_live"]))

        e.for_("pr_pos", 0, e.add(p["pr_n"], 1), position)
        e.give(p["pr_peak"])
    return _function(("bi", "ignore_constants"), build, tables)


def _copied(e: E, value, name: str):
    """``copied(value)`` into ``name``: the source of a copy node's result 0 (zext, pointer cast, link make), else NONE."""
    p = e.p
    e.var(name, NONE)
    produced = e.both(e.not_(_is_param(e, value)), e.eq(_pos_result(e, value), 0))

    def check():
        node = _vf(e, G_VPROD, value)
        e.var(f"{name}_n", node)
        e.if_(_in(e, _eop(e, p[f"{name}_n"]), COPY), lambda: e.set(name, _operand(e, p[f"{name}_n"], 0)))

    e.if_(produced, check)


def _in_weights(e: E, value, stamp):
    known = e.ne(value, NONE)
    return e.both(known, e.eq(_rt(e, T_WSTAMP, e.sel(known, value, 0)), stamp))


def _registers(tables):
    """Pins (``_choose_pins``), loop headers, the allocatable registers, hoisted wide constants, and the frame:
    shadow space, edge spills, homes, loop-parameter slots, stack storage, the dynamic spill base."""
    def build(e: E):
        p = e.p
        nb = _g(e, G_BCOUNT)
        e.var("rg_nb", nb)
        # Cyclic blocks: a block reachable from one of its successors.
        e.var("rg_cyclic", e.alloc(e.add(p["rg_nb"], 1)))
        _ok(e, e.ne(p["rg_cyclic"], NONE))
        _set_ra(e, R_CYCLIC, p["rg_cyclic"])

        def cyclic():
            e.var("rg_c", 0)
            _successor_positions(e, _block_at(e, p["rg_bi"]), lambda t: e.if_(e.ne(_call_value(e, "reaches", t, p["rg_bi"]), 0), lambda: e.set("rg_c", 1)))
            e.st(e.add(p["rg_cyclic"], p["rg_bi"]), p["rg_c"])

        e.for_("rg_bi", 0, p["rg_nb"], cyclic)
        # Weights of the homes used in a cyclic block other than their own.
        e.var("rg_wstamp", _stamp(e))
        e.var("rg_homes", _ra(e, R_HOMES))
        e.var("rg_nh", _ra(e, R_NHOMES))
        e.var("rg_ranked", e.alloc(e.add(p["rg_nh"], 1)))
        _ok(e, e.ne(p["rg_ranked"], NONE))
        e.var("rg_nr", 0)

        def weigh():
            e.var("rg_v", e.ld(e.add(p["rg_homes"], p["rg_k"])))
            e.var("rg_w", 0)
            e.var("rg_any", 0)

            def block():
                def used():
                    c = e.ld(e.add(p["rg_cyclic"], p["rg_bi"]))
                    e.set("rg_w", e.add(p["rg_w"], e.sel(e.ne(c, 0), CYCLE_WEIGHT, 1)))
                    e.if_(e.ne(c, 0), lambda: e.set("rg_any", 1))

                _uses_in(e, p["rg_bi"], p["rg_v"], "rg_u")
                e.if_(e.both(e.ne(p["rg_bi"], _pos_block(e, p["rg_v"])), e.ne(p["rg_u"], NONE)), used)

            e.for_("rg_bi", 0, p["rg_nb"], block)

            def weighted():
                _set_rt(e, T_WSTAMP, p["rg_v"], p["rg_wstamp"])
                _set_rt(e, T_WEIGHT, p["rg_v"], p["rg_w"])
                e.st(e.add(p["rg_ranked"], p["rg_nr"]), p["rg_v"])
                e.set("rg_nr", e.add(p["rg_nr"], 1))

            e.if_(e.ne(p["rg_any"], 0), weighted)

        e.for_("rg_k", 0, p["rg_nh"], weigh)

        # ranked: weight descending, then value order.
        def insert():
            e.var("rg_item", e.ld(e.add(p["rg_ranked"], p["rg_s"])))
            e.var("rg_j", p["rg_s"])

            def before():
                prev = e.ld(e.add(p["rg_ranked"], e.sub(e.sel(e.lt(0, p["rg_j"]), p["rg_j"], 1), 1)))
                wi, wp = _rt(e, T_WEIGHT, p["rg_item"]), _rt(e, T_WEIGHT, prev)
                earlier = e.either(e.lt(wp, wi), e.both(e.eq(wp, wi), e.lt(_key(e, p["rg_item"]), _key(e, prev))))
                return e.both(e.lt(0, p["rg_j"]), earlier)

            e.while_(before, lambda: (e.st(e.add(p["rg_ranked"], p["rg_j"]), e.ld(e.add(p["rg_ranked"], e.sub(p["rg_j"], 1)))), e.set("rg_j", e.sub(p["rg_j"], 1))))
            e.st(e.add(p["rg_ranked"], p["rg_j"]), p["rg_item"])

        e.for_("rg_s", 1, p["rg_nr"], insert)
        # Pins: PINNABLE handed out in order; a copy of a weighted value shares its source's pin.
        e.var("rg_free", 0)  # index of the next free pinnable register

        def take(value):
            e.if_(e.lt(p["rg_free"], len(PINNABLE)), lambda: (
                _set_rt(e, T_PIN, value, _select(e, p["rg_free"], PINNABLE)), e.set("rg_free", e.add(p["rg_free"], 1))))

        def first_pass():
            e.var("rg_v", e.ld(e.add(p["rg_ranked"], p["rg_k"])))
            _copied(e, p["rg_v"], "rg_c")
            e.if_(e.not_(_in_weights(e, p["rg_c"], p["rg_wstamp"])), lambda: take(p["rg_v"]))

        e.for_("rg_k", 0, p["rg_nr"], first_pass)

        def second_pass():
            e.var("rg_v", e.ld(e.add(p["rg_ranked"], p["rg_k"])))
            _copied(e, p["rg_v"], "rg_source")

            def follow():
                def climb():
                    _copied(e, p["rg_source"], "rg_up")
                    e.var("rg_go", e.flag(e.both(_in_weights(e, p["rg_up"], p["rg_wstamp"]), e.eq(_rt(e, T_PIN, p["rg_source"]), NONE))))
                    e.if_(e.ne(p["rg_go"], 0), lambda: e.set("rg_source", p["rg_up"]))
                    return p["rg_go"]

                e.var("rg_go", 1)
                e.while_(lambda: e.ne(p["rg_go"], 0), lambda: climb())
                e.if_(e.ne(_rt(e, T_PIN, p["rg_source"]), NONE), lambda: _set_rt(e, T_PIN, p["rg_v"], _rt(e, T_PIN, p["rg_source"])), lambda: take(p["rg_v"]))

            e.if_(_in_weights(e, p["rg_source"], p["rg_wstamp"]), follow)

        e.for_("rg_k", 0, p["rg_nr"], second_pass)
        _call(e, "frame")
        e.give(1)
    return _function((), build, tables)


def _select(e: E, index, items):
    """``items[index]`` for a constant tuple."""
    result = e.c(items[-1])
    for position in range(len(items) - 2, -1, -1):
        result = e.sel(e.eq(index, position), items[position], result)
    return result


def _rotatable(e: E, block):
    """``_rotatable``: a conditional branch with at most 16 nodes, all rotatable."""
    p = e.p
    e.var("ro_ok", e.flag(e.both(e.eq(_f(e, block, B_KIND), CONDITIONAL), e.le(_f(e, block, B_NNODES), ROTATE_LIMIT))))
    e.for_("ro_k", 0, _f(e, block, B_NNODES), lambda: e.if_(e.not_(_in(e, _eop(e, _node_at(e, block, p["ro_k"])), ROTATABLE)), lambda: e.set("ro_ok", 0)))
    return e.ne(p["ro_ok"], 0)


def _frame(tables):
    """Loop headers, allocatable registers, hoisted constants, then the frame's offsets and loop-parameter slots."""
    def build(e: E):
        p = e.p
        nb = _g(e, G_BCOUNT)
        e.var("fr_nb", nb)
        # Loop headers: targets of backward edges, and the successors after a rotatable header.
        e.var("fr_hdr", e.alloc(e.add(p["fr_nb"], 1)))
        _ok(e, e.ne(p["fr_hdr"], NONE))
        _set_ra(e, R_LOOPHDR, p["fr_hdr"])
        e.for_("fr_bi", 0, p["fr_nb"], lambda: e.st(e.add(p["fr_hdr"], p["fr_bi"]), 0))
        e.for_("fr_bi", 0, p["fr_nb"], lambda: _successor_positions(e, _block_at(e, p["fr_bi"]), lambda t: e.if_(
            e.le(t, p["fr_bi"]), lambda: e.st(e.add(p["fr_hdr"], t), 1))))
        e.var("fr_rot", e.alloc(e.add(p["fr_nb"], 1)))
        _ok(e, e.ne(p["fr_rot"], NONE))
        e.for_("fr_bi", 0, p["fr_nb"], lambda: e.st(e.add(p["fr_rot"], p["fr_bi"]), 0))

        def rotation():
            e.var("fr_h", _block_at(e, p["fr_bi"]))
            e.if_(e.both(e.ne(e.ld(e.add(p["fr_hdr"], p["fr_bi"])), 0), _rotatable(e, p["fr_h"])), lambda: _successor_positions(
                e, p["fr_h"], lambda t: e.if_(e.lt(p["fr_bi"], t), lambda: e.st(e.add(p["fr_rot"], t), 1))))

        e.for_("fr_bi", 0, p["fr_nb"], rotation)
        e.for_("fr_bi", 0, p["fr_nb"], lambda: e.if_(e.ne(e.ld(e.add(p["fr_rot"], p["fr_bi"])), 0), lambda: e.st(e.add(p["fr_hdr"], p["fr_bi"]), 1)))
        # Homes without pins, in order.
        e.var("fr_homes", _ra(e, R_HOMES))
        e.var("fr_nh", 0)
        e.for_("fr_k", 0, _ra(e, R_NHOMES), lambda: (e.var("fr_v", e.ld(e.add(p["fr_homes"], p["fr_k"]))), e.if_(
            e.eq(_rt(e, T_PIN, p["fr_v"]), NONE), lambda: (e.st(e.add(p["fr_homes"], p["fr_nh"]), p["fr_v"]), e.set("fr_nh", e.add(p["fr_nh"], 1))))))
        _set_ra(e, R_NHOMES, p["fr_nh"])
        # Allocatable: argument registers, the scratch register, the result register, the callee-saved ones, unpinned.
        e.var("fr_alloc", e.alloc(16))
        _ok(e, e.ne(p["fr_alloc"], NONE))
        e.var("fr_na", 0)
        n = _g(e, G_VCOUNT)
        e.var("fr_n", n)
        for register in (*ARGUMENT_REGISTERS, SCRATCH_REGISTER, RESULT_REGISTER, *CALLEE_SAVED):
            e.var("fr_pinned", 0)
            e.for_("fr_v", 0, p["fr_n"], lambda register=register: e.if_(e.eq(_rt(e, T_PIN, p["fr_v"]), register), lambda: e.set("fr_pinned", 1)))
            e.if_(e.eq(p["fr_pinned"], 0), lambda register=register: (e.st(e.add(p["fr_alloc"], p["fr_na"]), register), e.set("fr_na", e.add(p["fr_na"], 1))))

        # Hoisted constants: wide (no imm32) constants used in cyclic blocks, most blocks first.
        e.var("fr_cyclic", _ra(e, R_CYCLIC))
        e.var("fr_consts", e.alloc(e.add(e.mul(p["fr_n"], 2), 2)))  # (constant, block-set array) pairs
        e.var("fr_nc", 0)
        _ok(e, e.ne(p["fr_consts"], NONE))

        def wide_uses():
            e.var("fr_rec", _uses_record(e, p["fr_bi"]))

            def value():
                e.var("fr_v", e.ld(e.add(e.ld(e.add(p["fr_rec"], U_VALUES)), p["fr_k"])))
                wide = e.both(_constant(e, p["fr_v"]), e.le(1 << 31, _cval(e, p["fr_v"])))

                def add():
                    e.var("fr_c", _cval(e, p["fr_v"]))
                    e.var("fr_at", NONE)
                    e.for_("fr_j", 0, p["fr_nc"], lambda: e.if_(e.eq(e.ld(e.add(p["fr_consts"], e.mul(p["fr_j"], 2))), p["fr_c"]),
                                                                  lambda: e.set("fr_at", p["fr_j"])))

                    def new():
                        e.var("fr_set", e.alloc(e.add(p["fr_nb"], 1)))
                        _ok(e, e.ne(p["fr_set"], NONE))
                        e.for_("fr_x", 0, p["fr_nb"], lambda: e.st(e.add(p["fr_set"], p["fr_x"]), 0))
                        e.st(e.add(p["fr_consts"], e.mul(p["fr_nc"], 2)), p["fr_c"])
                        e.st(e.add(p["fr_consts"], e.add(e.mul(p["fr_nc"], 2), 1)), p["fr_set"])
                        e.set("fr_at", p["fr_nc"])
                        e.set("fr_nc", e.add(p["fr_nc"], 1))

                    e.if_(e.eq(p["fr_at"], NONE), new)
                    e.st(e.add(e.ld(e.add(p["fr_consts"], e.add(e.mul(p["fr_at"], 2), 1))), p["fr_bi"]), 1)

                e.if_(wide, add)

            e.for_("fr_k", 0, e.ld(e.add(p["fr_rec"], U_COUNT)), value)

        e.for_("fr_bi", 0, p["fr_nb"], lambda: e.if_(e.ne(e.ld(e.add(p["fr_cyclic"], p["fr_bi"])), 0), wide_uses))
        # Order: more blocks first, then the constant's value.
        e.var("fr_sizes", e.alloc(e.add(p["fr_nc"], 1)))
        _ok(e, e.ne(p["fr_sizes"], NONE))

        def size():
            e.var("fr_set", e.ld(e.add(p["fr_consts"], e.add(e.mul(p["fr_j"], 2), 1))))
            e.var("fr_count", 0)
            e.for_("fr_x", 0, p["fr_nb"], lambda: e.set("fr_count", e.add(p["fr_count"], e.ld(e.add(p["fr_set"], p["fr_x"])))))
            e.st(e.add(p["fr_sizes"], p["fr_j"]), p["fr_count"])

        e.for_("fr_j", 0, p["fr_nc"], size)
        e.var("fr_order", e.alloc(e.add(p["fr_nc"], 1)))
        _ok(e, e.ne(p["fr_order"], NONE))
        e.for_("fr_j", 0, p["fr_nc"], lambda: e.st(e.add(p["fr_order"], p["fr_j"]), p["fr_j"]))

        def insert():
            e.var("fr_item", e.ld(e.add(p["fr_order"], p["fr_s"])))
            e.var("fr_i", p["fr_s"])

            def before():
                prev = e.ld(e.add(p["fr_order"], e.sub(e.sel(e.lt(0, p["fr_i"]), p["fr_i"], 1), 1)))
                si, sp = e.ld(e.add(p["fr_sizes"], p["fr_item"])), e.ld(e.add(p["fr_sizes"], prev))
                ci, cp = e.ld(e.add(p["fr_consts"], e.mul(p["fr_item"], 2))), e.ld(e.add(p["fr_consts"], e.mul(prev, 2)))
                return e.both(e.lt(0, p["fr_i"]), e.either(e.lt(sp, si), e.both(e.eq(sp, si), e.lt(ci, cp))))

            e.while_(before, lambda: (e.st(e.add(p["fr_order"], p["fr_i"]), e.ld(e.add(p["fr_order"], e.sub(p["fr_i"], 1)))), e.set("fr_i", e.sub(p["fr_i"], 1))))
            e.st(e.add(p["fr_order"], p["fr_i"]), p["fr_item"])

        e.for_("fr_s", 1, p["fr_nc"], insert)
        e.var("fr_hoisted", e.alloc(e.add(e.mul(p["fr_nc"], 2), 2)))  # (constant, register)
        _ok(e, e.ne(p["fr_hoisted"], NONE))
        e.var("fr_nhoisted", 0)
        e.var("fr_stop", 0)

        def hoist():
            e.var("fr_j", e.ld(e.add(p["fr_order"], p["fr_q"])))
            # free: the pinnable registers still allocatable; the last one is taken.
            e.var("fr_free", NONE)
            for register in PINNABLE:
                e.var("fr_has", 0)
                e.for_("fr_x", 0, p["fr_na"], lambda register=register: e.if_(e.eq(e.ld(e.add(p["fr_alloc"], p["fr_x"])), register), lambda: e.set("fr_has", 1)))
                e.if_(e.ne(p["fr_has"], 0), lambda register=register: e.set("fr_free", register))
            e.if_(e.eq(p["fr_free"], NONE), lambda: e.set("fr_stop", 1))

            def demand():
                e.var("fr_set", e.ld(e.add(p["fr_consts"], e.add(e.mul(p["fr_j"], 2), 1))))
                e.var("fr_demand", 0)
                e.for_("fr_x", 0, p["fr_nb"], lambda: e.if_(e.ne(e.ld(e.add(p["fr_set"], p["fr_x"])), 0), lambda: (
                    e.var("fr_d", _call_value(e, "pressure", p["fr_x"], 1)), e.if_(e.lt(p["fr_demand"], p["fr_d"]), lambda: e.set("fr_demand", p["fr_d"])))))

                def take():
                    e.st(e.add(p["fr_hoisted"], e.mul(p["fr_nhoisted"], 2)), e.ld(e.add(p["fr_consts"], e.mul(p["fr_j"], 2))))
                    e.st(e.add(p["fr_hoisted"], e.add(e.mul(p["fr_nhoisted"], 2), 1)), p["fr_free"])
                    e.set("fr_nhoisted", e.add(p["fr_nhoisted"], 1))
                    e.var("fr_w", 0)
                    e.for_("fr_x", 0, p["fr_na"], lambda: (e.var("fr_r", e.ld(e.add(p["fr_alloc"], p["fr_x"]))), e.if_(
                        e.ne(p["fr_r"], p["fr_free"]), lambda: (e.st(e.add(p["fr_alloc"], p["fr_w"]), p["fr_r"]), e.set("fr_w", e.add(p["fr_w"], 1))))))
                    e.set("fr_na", p["fr_w"])

                e.if_(e.le(p["fr_demand"], e.sub(p["fr_na"], 1)), take)

            e.if_(e.eq(p["fr_stop"], 0), demand)

        e.for_("fr_q", 0, p["fr_nc"], hoist)
        _set_ra(e, R_ALLOC, p["fr_alloc"])
        _set_ra(e, R_NALLOC, p["fr_na"])
        _set_ra(e, R_HOISTED, p["fr_hoisted"])
        _set_ra(e, R_NHOISTED, p["fr_nhoisted"])
        # Every constant node of a hoisted value is pinned to its register.
        e.for_("fr_v", 0, p["fr_n"], lambda: e.if_(_constant(e, p["fr_v"]), lambda: e.for_("fr_q", 0, p["fr_nhoisted"], lambda: e.if_(
            e.eq(_cval(e, p["fr_v"]), e.ld(e.add(p["fr_hoisted"], e.mul(p["fr_q"], 2)))),
            lambda: _set_rt(e, T_PIN, p["fr_v"], e.ld(e.add(p["fr_hoisted"], e.add(e.mul(p["fr_q"], 2), 1))))))))
        # The frame.  S15e.3 (ADR-317): on Windows a foreign call passes its fifth and later arguments on the stack above
        # the shadow space; the frame reserves the largest such area.
        e.var("fr_outgoing", 0)

        def outgoing():
            e.var("fr_ob", _block_at(e, p["fr_bi"]))

            def node():
                e.var("fr_on", _node_at(e, p["fr_ob"], p["fr_m"]))

                def foreign():
                    e.var("fr_om", 0)
                    e.for_("fr_k", 0, _f(e, p["fr_on"], N_NOPS), lambda: e.if_(e.not_(_proof_type(e, _vf(e, G_VTYPE, _operand(e, p["fr_on"], p["fr_k"])))),
                                                                                   lambda: e.set("fr_om", e.add(p["fr_om"], 1))))
                    e.if_(e.lt(e.add(p["fr_outgoing"], 4), p["fr_om"]), lambda: e.set("fr_outgoing", e.sub(p["fr_om"], 4)))

                e.if_(e.eq(_eop(e, p["fr_on"]), _op(Operation.CALL_FOREIGN)), foreign)

            e.for_("fr_m", 0, _f(e, p["fr_ob"], B_NNODES), node)

        from xax_selfhost_x86_64_general import G_WINDOWS

        e.if_(e.ne(_g(e, G_WINDOWS), 0), lambda: e.for_("fr_bi", 0, p["fr_nb"], outgoing))
        e.var("fr_shadow", e.mul(_ra(e, R_HAS_CALL), e.add(32, e.mul(p["fr_outgoing"], 8))))
        e.var("fr_spills", 0)

        def spills():
            e.var("fr_mp", 0)
            _machine_params(e, _block_at(e, p["fr_bi"]), lambda _i, _v: e.set("fr_mp", e.add(p["fr_mp"], 1)))
            e.if_(e.lt(e.add(p["fr_spills"], p["fr_na"]), p["fr_mp"]), lambda: e.set("fr_spills", e.sub(p["fr_mp"], p["fr_na"])))

        e.for_("fr_bi", 0, p["fr_nb"], spills)
        _set_ra(e, R_SHADOW, p["fr_shadow"])
        _set_ra(e, R_EDGE_SPILL_BASE, p["fr_shadow"])
        e.var("fr_home_base", e.add(p["fr_shadow"], e.mul(p["fr_spills"], 8)))
        _set_ra(e, R_HOME_BASE, p["fr_home_base"])
        e.for_("fr_k", 0, p["fr_nh"], lambda: _set_rt(e, T_HOME, e.ld(e.add(p["fr_homes"], p["fr_k"])), e.add(p["fr_home_base"], e.mul(p["fr_k"], 8))))
        e.var("fr_slot_base", e.add(p["fr_home_base"], e.mul(p["fr_nh"], 8)))
        _set_ra(e, R_SLOT_BASE, p["fr_slot_base"])
        e.var("fr_nslots", _call(e, "loop_slots"))
        e.var("fr_cursor", e.add(p["fr_slot_base"], e.mul(p["fr_nslots"], 8)))
        e.var("fr_stacks", _ra(e, R_STACKS))

        def stack():
            at = e.add(p["fr_stacks"], e.mul(p["fr_k"], 3))
            e.var("fr_sat", at)
            e.var("fr_align", e.ld(e.add(p["fr_sat"], 2)))
            e.set("fr_cursor", e.mul(e.udiv(e.add(p["fr_cursor"], e.sub(p["fr_align"], 1)), p["fr_align"]), p["fr_align"]))
            _set_rt(e, T_STACK, e.ld(p["fr_sat"]), p["fr_cursor"])
            e.set("fr_cursor", e.add(p["fr_cursor"], e.ld(e.add(p["fr_sat"], 1))))

        e.for_("fr_k", 0, _ra(e, R_NSTACKS), stack)
        _set_ra(e, R_DYN_BASE, e.mul(e.udiv(e.add(p["fr_cursor"], 7), 8), 8))
        e.give(1)
    return _function((), build, tables)


def _loop_slots(tables):
    """``_loop_parameter_slots``: frame slots (``T_PSLOT``, offsets from the slot base) for loop pass-through block
    parameters under register pressure; the number of distinct slots."""
    def build(e: E):
        p = e.p
        nb = _g(e, G_BCOUNT)
        e.var("ls_nb", nb)
        e.var("ls_entry", _f(e, _g(e, G_BENTRY), B_POS))
        e.var("ls_na", _ra(e, R_NALLOC))
        # Reachability matrix: R[i][j] = 1 when j is reachable from i by at least one edge.
        e.var("ls_r", e.alloc(e.add(e.mul(p["ls_nb"], p["ls_nb"]), 1)))
        e.var("ls_stack", e.alloc(e.add(e.mul(p["ls_nb"], 4), 2)))
        _ok(e, e.both(e.ne(p["ls_r"], NONE), e.ne(p["ls_stack"], NONE)))

        def reach_row():
            e.var("ls_row", e.add(p["ls_r"], e.mul(p["ls_i"], p["ls_nb"])))
            e.for_("ls_j", 0, p["ls_nb"], lambda: e.st(e.add(p["ls_row"], p["ls_j"]), 0))
            e.var("ls_sp", 0)
            _successor_positions(e, _block_at(e, p["ls_i"]), lambda t: (e.st(e.add(p["ls_stack"], p["ls_sp"]), t), e.set("ls_sp", e.add(p["ls_sp"], 1))))

            def step():
                e.set("ls_sp", e.sub(p["ls_sp"], 1))
                e.var("ls_x", e.ld(e.add(p["ls_stack"], p["ls_sp"])))

                def visit():
                    e.st(e.add(p["ls_row"], p["ls_x"]), 1)
                    _successor_positions(e, _block_at(e, p["ls_x"]), lambda t: (e.st(e.add(p["ls_stack"], p["ls_sp"]), t), e.set("ls_sp", e.add(p["ls_sp"], 1))))

                e.if_(e.eq(e.ld(e.add(p["ls_row"], p["ls_x"])), 0), visit)

            e.while_(lambda: e.ne(p["ls_sp"], 0), step)

        e.for_("ls_i", 0, p["ls_nb"], reach_row)

        def reach(i, j):
            return e.ne(e.ld(e.add(p["ls_r"], e.add(e.mul(i, p["ls_nb"]), j))), 0)

        # Candidates: machine parameters a block only forwards on edges, in a CFG cycle, not pinned or homed.
        e.var("ls_cstamp", _stamp(e))
        e.var("ls_cands", e.alloc(e.add(_g(e, G_VCOUNT), 1)))
        _ok(e, e.ne(p["ls_cands"], NONE))
        e.var("ls_nc", 0)

        def block():
            e.var("ls_b", _block_at(e, p["ls_bi"]))

            def param(_index, value):
                e.var("ls_v", value)
                v = p["ls_v"]
                e.var("ls_ok", e.flag(e.both(e.eq(_rt(e, T_PIN, v), NONE), e.eq(_rt(e, T_HOME, v), NONE), e.ne(p["ls_bi"], p["ls_entry"]),
                                             reach(p["ls_bi"], p["ls_bi"]))))

                def read():
                    e.for_("ls_k", 0, _f(e, p["ls_b"], B_NVALUES), lambda: e.if_(e.eq(e.ld(e.add(_f(e, p["ls_b"], B_VALUES), p["ls_k"])), v), lambda: e.set("ls_ok", 0)))

                    def node():
                        e.var("ls_node", _node_at(e, p["ls_b"], p["ls_m"]))
                        e.for_("ls_k", 0, _f(e, p["ls_node"], N_NOPS), lambda: e.if_(e.eq(_operand(e, p["ls_node"], p["ls_k"]), v), lambda: e.set("ls_ok", 0)))

                    e.for_("ls_m", 0, _f(e, p["ls_b"], B_NNODES), node)
                    _uses_in(e, p["ls_bi"], v, "ls_u")
                    e.if_(e.eq(p["ls_u"], NONE), lambda: e.set("ls_ok", 0))

                e.if_(e.ne(p["ls_ok"], 0), read)

                def candidate():
                    _set_rt(e, T_CAND, v, p["ls_cstamp"])
                    _set_rt(e, T_PARENT, v, v)
                    e.st(e.add(p["ls_cands"], p["ls_nc"]), v)
                    e.set("ls_nc", e.add(p["ls_nc"], 1))

                e.if_(e.ne(p["ls_ok"], 0), candidate)

            _machine_params(e, p["ls_b"], param)

        e.for_("ls_bi", 0, p["ls_nb"], block)

        def is_candidate(value):
            return e.eq(_rt(e, T_CAND, value), p["ls_cstamp"])

        def find(value, name):
            e.var(name, value)
            e.while_(lambda: e.ne(_rt(e, T_PARENT, p[name]), p[name]), lambda: e.set(name, _rt(e, T_PARENT, p[name])))

        def each_edge_argument(visit):
            def source():
                e.var("ee_s", _block_at(e, p["ee_si"]))

                def edge():
                    e.var("ee_e", e.add(_f(e, p["ee_s"], B_EDGES), e.mul(p["ee_k"], EDGE)))
                    e.var("ee_t", _f(e, p["ee_e"], 0))
                    e.for_("ee_a", 0, _f(e, p["ee_e"], 1), lambda: visit(p["ee_si"], e.ld(e.add(_f(e, p["ee_e"], 2), p["ee_a"])),
                                                                          e.ld(e.add(_f(e, p["ee_t"], B_INPUTS), p["ee_a"]))))

                e.for_("ee_k", 0, _f(e, p["ee_s"], B_NEDGES), edge)

            e.for_("ee_si", 0, p["ls_nb"], source)

        def union(source, argument, destination):
            e.var("un_a", argument)
            e.var("un_d", destination)

            def join():
                find(p["un_a"], "un_ra")
                find(p["un_d"], "un_rd")
                _set_rt(e, T_PARENT, p["un_ra"], p["un_rd"])

            e.if_(e.both(is_candidate(p["un_a"]), is_candidate(p["un_d"]), e.eq(_pos_block(e, p["un_a"]), source)), join)

        each_edge_argument(union)
        # Classes, in sorted candidate order (by block, index): class id per root (T_S3 under stamp T_S1).
        _sort_by_key(e, p["ls_cands"], p["ls_nc"], "ls_cs")
        e.var("ls_rstamp", _stamp(e))
        e.var("ls_classes", e.alloc(e.add(e.mul(p["ls_nc"], 3), 3)))  # per class: members array, count, rejected
        _ok(e, e.ne(p["ls_classes"], NONE))
        e.var("ls_ncl", 0)

        # ADR-284: classes are numbered and counted first, then each gets a members array of its own size (an array of
        # every candidate per class exhausted the arena on the compiler's own functions), then filled in the same order.
        def classify():
            e.var("ls_v", e.ld(e.add(p["ls_cands"], p["ls_k"])))
            find(p["ls_v"], "ls_root")

            def new_class():
                _set_rt(e, T_S1, p["ls_root"], p["ls_rstamp"])
                _set_rt(e, T_S3, p["ls_root"], p["ls_ncl"])
                at = e.add(p["ls_classes"], e.mul(p["ls_ncl"], 3))
                e.st(at, 0)
                e.st(e.add(at, 1), 0)
                e.st(e.add(at, 2), 0)
                e.set("ls_ncl", e.add(p["ls_ncl"], 1))

            e.if_(e.ne(_rt(e, T_S1, p["ls_root"]), p["ls_rstamp"]), new_class)
            e.var("ls_cat", e.add(p["ls_classes"], e.mul(_rt(e, T_S3, p["ls_root"]), 3)))
            e.st(e.add(p["ls_cat"], 1), e.add(e.ld(e.add(p["ls_cat"], 1)), 1))

        e.for_("ls_k", 0, p["ls_nc"], classify)

        def members():
            e.var("ls_cat", e.add(p["ls_classes"], e.mul(p["ls_q"], 3)))
            e.var("ls_members", e.alloc(e.add(e.ld(e.add(p["ls_cat"], 1)), 1)))
            _ok(e, e.ne(p["ls_members"], NONE))
            e.st(p["ls_cat"], p["ls_members"])
            e.st(e.add(p["ls_cat"], 1), 0)

        e.for_("ls_q", 0, p["ls_ncl"], members)

        def fill():
            e.var("ls_v", e.ld(e.add(p["ls_cands"], p["ls_k"])))
            find(p["ls_v"], "ls_root")
            e.var("ls_cat", e.add(p["ls_classes"], e.mul(_rt(e, T_S3, p["ls_root"]), 3)))
            e.st(e.add(e.ld(p["ls_cat"]), e.ld(e.add(p["ls_cat"], 1))), p["ls_v"])
            e.st(e.add(p["ls_cat"], 1), e.add(e.ld(e.add(p["ls_cat"], 1)), 1))

        e.for_("ls_k", 0, p["ls_nc"], fill)

        def class_at(index):
            return e.add(p["ls_classes"], e.mul(index, 3))

        def member_in(cat, block, name):
            """``member_of[(root, block)]``: the last member of the class in ``block``, else NONE."""
            e.var(name, NONE)
            e.for_(f"{name}_k", 0, e.ld(e.add(cat, 1)), lambda: (e.var(f"{name}_m", e.ld(e.add(e.ld(cat), p[f"{name}_k"]))), e.if_(
                e.eq(_pos_block(e, p[f"{name}_m"]), block), lambda: e.set(name, p[f"{name}_m"]))))

        # A class with two members in one block is rejected.
        def duplicates():
            e.var("ls_cat", class_at(p["ls_q"]))
            e.var("ls_cm", e.ld(p["ls_cat"]))
            e.var("ls_cn", e.ld(e.add(p["ls_cat"], 1)))
            e.for_("ls_x", 0, p["ls_cn"], lambda: e.for_("ls_y", e.add(p["ls_x"], 1), p["ls_cn"], lambda: e.if_(
                e.eq(_pos_block(e, e.ld(e.add(p["ls_cm"], p["ls_x"]))), _pos_block(e, e.ld(e.add(p["ls_cm"], p["ls_y"])))),
                lambda: e.st(e.add(p["ls_cat"], 2), 1))))

        e.for_("ls_q", 0, p["ls_ncl"], duplicates)

        # An edge between two blocks of a class must pass the class member to the class member.
        def check(source, argument, destination):
            e.var("ck_a", argument)
            e.var("ck_d", destination)

            def candidate():
                find(p["ck_d"], "ck_root")
                e.var("ck_cat", class_at(_rt(e, T_S3, p["ck_root"])))
                member_in(p["ck_cat"], source, "ck_member")
                e.if_(e.both(e.ne(p["ck_member"], NONE), e.ne(p["ck_member"], p["ck_a"])), lambda: e.st(e.add(p["ck_cat"], 2), 1))

            e.if_(is_candidate(p["ck_d"]), candidate)

        each_edge_argument(check)
        # Slots: a class serving a pressured loop made only of its member blocks.
        e.var("ls_pressured", e.alloc(e.add(p["ls_nb"], 1)))
        _ok(e, e.ne(p["ls_pressured"], NONE))
        e.for_("ls_bi", 0, p["ls_nb"], lambda: e.st(e.add(p["ls_pressured"], p["ls_bi"]), e.flag(e.both(
            reach(p["ls_bi"], p["ls_bi"]), e.lt(p["ls_na"], _call_value(e, "pressure", p["ls_bi"], 0))))))
        e.var("ls_slots", 0)
        e.var("ls_inset", e.alloc(e.add(p["ls_nb"], 1)))
        e.var("ls_seen", e.alloc(e.add(p["ls_nb"], 1)))
        _ok(e, e.both(e.ne(p["ls_inset"], NONE), e.ne(p["ls_seen"], NONE)))

        def slot():
            e.var("ls_cat", class_at(p["ls_q"]))

            def accepted():
                e.for_("ls_bi", 0, p["ls_nb"], lambda: e.st(e.add(p["ls_inset"], p["ls_bi"]), 0))
                e.for_("ls_k", 0, e.ld(e.add(p["ls_cat"], 1)), lambda: e.st(e.add(p["ls_inset"], _pos_block(e, e.ld(e.add(e.ld(p["ls_cat"]), p["ls_k"])))), 1))
                e.var("ls_serves", 0)

                def loops_within():
                    # depth first from the start's successors inside the set, back to the start
                    e.for_("ls_x", 0, p["ls_nb"], lambda: e.st(e.add(p["ls_seen"], p["ls_x"]), 0))
                    e.var("ls_sp", 0)
                    push = lambda t: e.if_(e.ne(e.ld(e.add(p["ls_inset"], t)), 0), lambda: (e.st(e.add(p["ls_stack"], p["ls_sp"]), t), e.set("ls_sp", e.add(p["ls_sp"], 1))))  # noqa: E731
                    _successor_positions(e, _block_at(e, p["ls_bi"]), push)
                    e.var("ls_back", 0)

                    def step():
                        e.set("ls_sp", e.sub(p["ls_sp"], 1))
                        e.var("ls_x", e.ld(e.add(p["ls_stack"], p["ls_sp"])))
                        e.if_(e.eq(p["ls_x"], p["ls_bi"]), lambda: e.set("ls_back", 1))

                        def visit():
                            e.st(e.add(p["ls_seen"], p["ls_x"]), 1)
                            _successor_positions(e, _block_at(e, p["ls_x"]), push)

                        e.if_(e.both(e.eq(p["ls_back"], 0), e.eq(e.ld(e.add(p["ls_seen"], p["ls_x"])), 0)), visit)

                    e.while_(lambda: e.both(e.ne(p["ls_sp"], 0), e.eq(p["ls_back"], 0)), step)
                    e.if_(e.ne(p["ls_back"], 0), lambda: e.set("ls_serves", 1))

                e.for_("ls_bi", 0, p["ls_nb"], lambda: e.if_(e.both(e.eq(p["ls_serves"], 0), e.ne(e.ld(e.add(p["ls_inset"], p["ls_bi"])), 0),
                                                                    e.ne(e.ld(e.add(p["ls_pressured"], p["ls_bi"])), 0)), loops_within))

                def assign():
                    offset = e.add(_ra(e, R_SLOT_BASE), e.mul(p["ls_slots"], 8))
                    e.var("ls_offset", offset)
                    e.for_("ls_k", 0, e.ld(e.add(p["ls_cat"], 1)), lambda: _set_rt(e, T_PSLOT, e.ld(e.add(e.ld(p["ls_cat"]), p["ls_k"])), p["ls_offset"]))
                    e.set("ls_slots", e.add(p["ls_slots"], 1))

                e.if_(e.ne(p["ls_serves"], 0), assign)

            e.if_(e.eq(e.ld(e.add(p["ls_cat"], 2)), 0), accepted)

        e.for_("ls_q", 0, p["ls_ncl"], slot)
        e.give(p["ls_slots"])
    return _function((), build, tables)


# -- the analyses of one function, and their audit -------------------------------------------------------------

STATUS_UNDECIDED, STATUS_INELIGIBLE, STATUS_ANALYSED = range(3)


def _analyse(tables):
    """The register-resident analyses of function ``f`` (its final view is in the records): ``STATUS_INELIGIBLE``
    when the bootstrap's lowering returns None before emitting, else ``STATUS_ANALYSED``."""
    def build(e: E):
        p = e.p
        iface = _call(e, "interface", p["f"])
        e.var("an_i", iface)
        e.var("an_np", e.ld(e.add(p["an_i"], 1)))
        _set_ra(e, R_NPARAMS, p["an_np"])
        _set_ra(e, R_PARAMS, e.add(p["an_i"], 2))
        e.var("an_rt", e.add(e.add(p["an_i"], 2), p["an_np"]))
        _set_ra(e, R_NRETURNS, e.ld(p["an_rt"]))
        _set_ra(e, R_RETURNS, e.add(p["an_rt"], 1))
        _set_ra(e, R_OWN_ELIDED, _call(e, "borrowed", p["f"]))
        e.if_(e.eq(_call_value(e, "eligible"), 0), lambda: e.give(STATUS_INELIGIBLE))
        e.if_(e.eq(_call_value(e, "basics"), 0), lambda: e.give(STATUS_INELIGIBLE))
        _call(e, "folding")
        _call(e, "uses")
        _call(e, "registers")
        e.give(STATUS_ANALYSED)
    return _function(("f",), build, tables)


def _write_analysis(e: E, out, out_value, status):
    """The audit record of one function's analyses (``xax_x86_64_regalloc.analysis_audit`` order)."""
    p = e.p
    e.var("wa_status", status)
    out(p["wa_status"])

    def each_value(visit):
        """``visit(value)`` for every value of the view, per block in order: parameters, then node outputs."""
        def block():
            e.var("wa_b", _block_at(e, p["wa_bi"]))
            e.for_("wa_k", 0, _f(e, p["wa_b"], B_NP), lambda: visit(e.ld(e.add(_f(e, p["wa_b"], B_INPUTS), p["wa_k"]))))

            def node():
                e.var("wa_node", _node_at(e, p["wa_b"], p["wa_m"]))
                e.for_("wa_r", 0, _f(e, p["wa_node"], N_NRES), lambda: visit(_output(e, p["wa_node"], p["wa_r"])))

            e.for_("wa_m", 0, _f(e, p["wa_b"], B_NNODES), node)

        e.for_("wa_bi", 0, _g(e, G_BCOUNT), block)

    def table(condition, fields):
        """A value-keyed table: its count, then per value in view order its position and ``fields(value)``."""
        e.var("wa_count", 0)
        each_value(lambda v: e.if_(condition(v), lambda: e.set("wa_count", e.add(p["wa_count"], 1))))
        out(p["wa_count"])

        def write(v):
            e.var("wa_v", v)

            def emit():
                out_value(p["wa_v"])
                fields(p["wa_v"])

            e.if_(condition(p["wa_v"]), emit)

        each_value(write)

    def node_flags(flags_array, block):
        e.var("wa_fc", 0)
        e.for_("wa_x", 0, _f(e, block, B_NNODES), lambda: e.if_(e.ne(e.ld(e.add(flags_array, p["wa_x"])), 0), lambda: e.set("wa_fc", e.add(p["wa_fc"], 1))))
        out(p["wa_fc"])
        e.for_("wa_x", 0, _f(e, block, B_NNODES), lambda: e.if_(e.ne(e.ld(e.add(flags_array, p["wa_x"])), 0), lambda: out(p["wa_x"])))

    def analysed():
        table(lambda v: e.ne(_width(e, v), 0), lambda v: out(_width(e, v)))
        out(_ra(e, R_HAS_CALL))
        e.var("wa_stacks", _ra(e, R_STACKS))
        out(_ra(e, R_NSTACKS))
        e.for_("wa_k", 0, _ra(e, R_NSTACKS), lambda: (out_value(e.ld(e.add(p["wa_stacks"], e.mul(p["wa_k"], 3)))),
                                                       out(e.ld(e.add(p["wa_stacks"], e.add(e.mul(p["wa_k"], 3), 1)))),
                                                       out(e.ld(e.add(p["wa_stacks"], e.add(e.mul(p["wa_k"], 3), 2))))))
        table(lambda v: e.ne(_rt(e, T_NONZERO, v), 0), lambda v: None)
        nb = _g(e, G_BCOUNT)
        e.for_("wa_bi", 0, nb, lambda: out(e.ld(e.add(_ra(e, R_FUSED), p["wa_bi"]))))

        def branch_table():
            e.var("wa_t", e.ld(e.add(_ra(e, R_BTAB), p["wa_bi"])))

            def present():
                out(1)
                out_value(e.ld(p["wa_t"]))
                e.var("wa_tn", e.ld(e.add(p["wa_t"], 2)))
                out(p["wa_tn"])
                e.for_("wa_x", 0, p["wa_tn"], lambda: out(e.ld(e.add(e.ld(e.add(p["wa_t"], 1)), p["wa_x"]))))
                node_flags(e.ld(e.add(p["wa_t"], 3)), _block_at(e, p["wa_bi"]))

            e.if_(e.ne(p["wa_t"], NONE), present, lambda: out(0))

        e.for_("wa_bi", 0, nb, branch_table)

        def membership():
            e.var("wa_t", e.ld(e.add(_ra(e, R_MEMB), p["wa_bi"])))

            def present():
                out(1)
                out_value(e.ld(p["wa_t"]))
                out(e.ld(e.add(p["wa_t"], 1)))
                out(e.ld(e.add(p["wa_t"], 2)))
                node_flags(e.ld(e.add(p["wa_t"], 3)), _block_at(e, p["wa_bi"]))

            e.if_(e.ne(p["wa_t"], NONE), present, lambda: out(0))

        e.for_("wa_bi", 0, nb, membership)
        table(lambda v: e.ne(_rt(e, T_FOLD_BASE, v), NONE), lambda v: (out_value(_rt(e, T_FOLD_BASE, v)), out(_rt(e, T_FOLD_DISP, v))))
        table(lambda v: e.ne(_rt(e, T_SCALE_BASE, v), NONE), lambda v: (out_value(_rt(e, T_SCALE_BASE, v)), out(_rt(e, T_SCALE, v))))
        table(lambda v: e.ne(_rt(e, T_ERASED, v), 0), lambda v: None)
        table(lambda v: e.ne(_rt(e, T_RMW, v), NONE), lambda v: out(_rt(e, T_RMW, v)))
        table(lambda v: e.ne(_rt(e, T_RMW_ERASED, v), 0), lambda v: None)

        def value_table(v):
            e.var("wa_vt", _rt(e, T_VT_TABLE, v))
            out_value(e.ld(p["wa_vt"]))
            e.var("wa_tn", e.ld(e.add(p["wa_vt"], 2)))
            out(p["wa_tn"])
            e.for_("wa_x", 0, p["wa_tn"], lambda: out(e.ld(e.add(e.ld(e.add(p["wa_vt"], 1)), p["wa_x"]))))

        table(lambda v: e.ne(_rt(e, T_VT_SUBJECT, v), NONE), value_table)
        table(lambda v: e.ne(_rt(e, T_MV_SUBJECT, v), NONE), lambda v: (out_value(_rt(e, T_MV_SUBJECT, v)), out(_rt(e, T_MV_LOW, v)), out(_rt(e, T_MV_MASK, v))))

        def compare_load(v):
            e.var("wa_cl", _rt(e, T_CL, v))
            out_value(e.ld(p["wa_cl"]))
            e.var("wa_ci", e.ld(e.add(p["wa_cl"], 1)))
            e.if_(e.eq(p["wa_ci"], NONE), lambda: out(0), lambda: (out(1), out_value(p["wa_ci"])))
            out(e.ld(e.add(p["wa_cl"], 2)))
            out(e.ld(e.add(p["wa_cl"], 3)))

        table(lambda v: e.ne(_rt(e, T_CL, v), NONE), compare_load)
        table(lambda v: e.ne(_rt(e, T_SINK_OPERAND, v), NONE), lambda v: (out_value(_rt(e, T_SINK_OPERAND, v)), out(_rt(e, T_SINK_AMOUNT, v))))
        table(lambda v: e.ne(_rt(e, T_ALIAS, v), NONE), lambda v: out_value(_rt(e, T_ALIAS, v)))

        def uses():
            e.var("wa_rec", _uses_record(e, p["wa_bi"]))
            e.var("wa_un", e.ld(e.add(p["wa_rec"], U_COUNT)))
            out(p["wa_un"])

            def entry():
                out_value(e.ld(e.add(e.ld(e.add(p["wa_rec"], U_VALUES)), p["wa_k"])))
                e.var("wa_len", e.ld(e.add(e.ld(e.add(p["wa_rec"], U_LENGTHS)), p["wa_k"])))
                e.var("wa_list", e.ld(e.add(e.ld(e.add(p["wa_rec"], U_LISTS)), p["wa_k"])))
                out(p["wa_len"])
                e.for_("wa_x", 0, p["wa_len"], lambda: out(e.ld(e.add(p["wa_list"], p["wa_x"]))))

            e.for_("wa_k", 0, p["wa_un"], entry)

        e.for_("wa_bi", 0, nb, uses)
        out(_ra(e, R_NHOMES))
        e.for_("wa_k", 0, _ra(e, R_NHOMES), lambda: out_value(e.ld(e.add(_ra(e, R_HOMES), p["wa_k"]))))
        table(lambda v: e.ne(_rt(e, T_PIN, v), NONE), lambda v: out(_rt(e, T_PIN, v)))
        e.var("wa_lh", 0)
        e.for_("wa_bi", 0, nb, lambda: e.if_(e.ne(e.ld(e.add(_ra(e, R_LOOPHDR), p["wa_bi"])), 0), lambda: e.set("wa_lh", e.add(p["wa_lh"], 1))))
        out(p["wa_lh"])
        e.for_("wa_bi", 0, nb, lambda: e.if_(e.ne(e.ld(e.add(_ra(e, R_LOOPHDR), p["wa_bi"])), 0), lambda: out(p["wa_bi"])))
        out(_ra(e, R_NALLOC))
        e.for_("wa_k", 0, _ra(e, R_NALLOC), lambda: out(e.ld(e.add(_ra(e, R_ALLOC), p["wa_k"]))))
        out(_ra(e, R_NHOISTED))
        e.for_("wa_k", 0, e.mul(_ra(e, R_NHOISTED), 2), lambda: out(e.ld(e.add(_ra(e, R_HOISTED), p["wa_k"]))))
        out(_ra(e, R_SHADOW))
        out(_ra(e, R_EDGE_SPILL_BASE))
        table(lambda v: e.ne(_rt(e, T_HOME, v), NONE), lambda v: out(_rt(e, T_HOME, v)))
        table(lambda v: e.ne(_rt(e, T_PSLOT, v), NONE), lambda v: out(_rt(e, T_PSLOT, v)))
        table(lambda v: e.ne(_rt(e, T_STACK, v), NONE), lambda v: out(_rt(e, T_STACK, v)))
        out(_ra(e, R_DYN_BASE))

    e.if_(e.eq(p["wa_status"], STATUS_ANALYSED), analysed)


def add_regalloc_functions(add, tables):
    add("eligible", _eligible(tables))
    add("edge_nonzero", _edge_nonzero(tables))
    add("basics", _basics(tables))
    add("predicate_table", _predicate_table(tables))
    add("branch_membership", _branch_membership(tables))
    add("member_value", _member_value(tables))
    add("access_proven", _access_proven(tables))
    add("compare_loads", _compare_loads(tables))
    add("edge_sinking", _edge_sinking(tables))
    add("call_aliases", _call_aliases(tables))
    add("folding", _folding(tables))
    add("uses", _uses(tables))
    add("reaches", _reaches(tables))
    add("pressure", _pressure(tables))
    add("loop_slots", _loop_slots(tables))
    add("frame", _frame(tables))
    add("registers", _registers(tables))
    add("analyse", _analyse(tables))


def regalloc_prologue(e: E):
    """Allocate the register-allocation globals and per-value tables (once, before the views)."""
    more = e.alloc(RA_WORDS)
    _ok(e, e.ne(more, NONE))
    e.st(GLOBALS + G_RA, more)
    for table in range(VALUE_TABLES):
        t = e.alloc(VCAP + 1)
        _ok(e, e.ne(t, NONE))
        _set_ra(e, table, t)
    _set_ra(e, R_STAMP, 1)
