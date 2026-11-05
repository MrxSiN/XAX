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

from xax_compiler import Operation
from xax_selfhost_facts import E, H_ARENA, NONE, _function
from xax_selfhost_general_ranges import G2_CONST, G2_CVAL, _block_at, _is_param, _node_at, _pos_block, _pos_index, _t
from xax_selfhost_general_view import (
    B_EDGES, B_INPUTS, B_KIND, B_NEDGES, B_NNODES, B_NP, B_POS, CONDITIONAL, EDGE, G_BCOUNT, G_VCOUNT, G_VPOS, G_VTYPE, N_NOPS, N_OP, N_OPSAT, N_FN, _f, _operand, _output, _vf)
from xax_selfhost_views_backend import _FN, _call, _g, _ok, _type_form

G_RA = 60  # pointer to the register-allocation globals table (``_ra``/``_set_ra``)
RA_WORDS = 256
# Per-value tables (``_rt``): VCAP words each.
(T_RW, T_USES, T_EARLY, T_FOLD_BASE, T_FOLD_DISP, T_SCALE_BASE, T_SCALE, T_ERASED, T_RMW, T_RMW_ERASED, T_VT_SUBJECT, T_VT_TABLE,
 T_MV_SUBJECT, T_MV_LOW, T_MV_MASK, T_MEMBER_ERASED, T_TABLE_ERASED, T_CL, T_SINK_OPERAND, T_SINK_AMOUNT, T_ALIAS, T_HOME, T_PIN,
 T_PSLOT, T_STACK, T_NONZERO, T_MEMORY_USES, T_OTHER_USE, T_INDEX_USES, T_MPARAM) = range(30)
# Scratch per-value tables: T_S1/T_S2 stamps, T_S3 values (predicate tables), T_S4 a use-record index; T_USTAMP and
# T_UCOUNT are ``_uses``' own (a stamp must never be compared with a table that holds other numbers).
(T_S1, T_S2, T_S3, T_S4, T_USTAMP, T_UCOUNT, T_WEIGHT, T_WSTAMP, T_PARENT, T_CAND) = range(30, 40)
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
ROTATE_LIMIT = 16


def _op(name: Operation) -> int:
    return int(name)


PURE_BINARY = tuple(_op(op) for op in (Operation.ADD_WRAP, Operation.SUB_WRAP, Operation.MUL_WRAP, Operation.BIT_XOR, Operation.BIT_AND, Operation.BIT_OR))
COPY = tuple(_op(op) for op in (Operation.INT_ZERO_EXTEND, Operation.POINTER_CAST, Operation.LINK_MAKE))
MEMORY = tuple(_op(op) for op in (Operation.LOAD_BITS_LE, Operation.STORE_BITS_LE, Operation.CHECKED_LOAD_BITS_LE, Operation.CHECKED_STORE_BITS_LE,
                                  Operation.RAW_LOAD_BITS_LE, Operation.GROWABLE_LOAD_BITS_LE, Operation.GROWABLE_STORE_BITS_LE))
CALLS = tuple(_op(op) for op in (Operation.CALL_DIRECT, Operation.CALL_FOREIGN, Operation.CALL_INDIRECT))
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


# -- basic facts ------------------------------------------------------------------------------------------------


def _release(e: E, mark, result):
    """Return ``result`` after releasing every arena allocation made since ``mark`` (helpers run per value or per
    block, so scratch that does not escape would otherwise grow with their product)."""
    e.set_hd(H_ARENA, mark)
    e.give(result)


def _constant(e: E, value):
    return e.ne(_t(e, G2_CONST, value), 0)


def _cval(e: E, value):
    return _t(e, G2_CVAL, value)


# -- predicate tables (``xax_ranges.predicate_table``, ADR-208) ------------------------------------------------


# -- folding decisions ------------------------------------------------------------------------------------------


def _call_value(e: E, name: str, *arguments):
    """A call whose 0 or 1 result is a value (NONE still declines)."""
    result = e.call(_FN[name], *arguments)
    _ok(e, e.ne(result, NONE))
    return result


# -- uses, homes, pins, and the frame ---------------------------------------------------------------------------

# Per block (``R_USES`` array, by position): a record ``[count, values, position lists, list lengths]``.
U_COUNT, U_VALUES, U_LISTS, U_LENGTHS = range(4)


def _uses_record(e: E, bi):
    return e.ld(e.add(_ra(e, R_USES), bi))


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


# -- the analyses of one function, and their audit -------------------------------------------------------------

STATUS_UNDECIDED, STATUS_INELIGIBLE, STATUS_ANALYSED = range(3)


