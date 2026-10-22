"""S15e.5 (ADR-327): ``xax_jvm._compile_method``'s driver as XAX functions: the two passes (the first counts each
value's reads in a throwaway pool; the second keeps a value read once on the operand stack), the retry that keeps
parameters a zero store would have to initialize, and per pass the analyses, the definite assignment, the zero
stores, the layout (fallthrough chains, jump threading), every block (its nodes, its terminator with the edges'
parallel copies, tail merging of equal return blocks), the trap, the line table, the fixups, the frames and the
operand stack's depth.  The method's result goes to the class's method store (``xax_selfhost_jvm``).
"""

from __future__ import annotations

from xax_selfhost_facts import E, H_ARENA, NONE, _function
from xax_selfhost_general_ranges import _block_at, _node_at
from xax_selfhost_general_regalloc import _eop
from xax_selfhost_general_view import (
    B_EDGES, B_INPUTS, B_KIND, B_NEDGES, B_NNODES, B_NP, B_NVALUES, B_VALUES, BRANCH, CONDITIONAL, EDGE, G_BCOUNT, G_BENTRY, G_VCOUNT,
    N_NRES, RETURN, TRAP, _f, _output,
)
from xax_selfhost_jvm_class import B_LEN, POOL_CAP, P_BYTES, P_COUNT, bdata, blen, buffer
from xax_selfhost_jvm_code import (
    C_BUF, C_COUNTING, C_ENDED, C_FIX, C_LABELS, C_LINES, C_NFIX, C_NLABELS, C_NLINES, C_PENDING, C_POOL, C_READS, C_STORED, C_TARGET,
    C_VSDESC, C_VSLOT, CODE_CAP, D_I, D_J, D_NONE, GOTO, M_STATE, RETURN as RETURN_OPS, SLOT_LATE, ZERO, _flush, _in, _length, _m, _pick, _set_m,
    branch, local, mark, op, opx,
)
from xax_selfhost_jvm_lower import K_GET, K_JUMP, K_NODE, run
from xax_selfhost_jvm_method import (
    BL_BASE, BL_DEF, BL_INC, BL_LIVE, BL_NPRED, BL_ORDER, BL_PLACED, BL_PRED, BL_REACH, BL_RESOLVED, BL_UP, M_ACROSS, M_ENTRY, M_FN,
    M_FOLLOW, M_FRAMED, M_FREED, M_FTYPES, M_GEND, M_HINT, M_INTER, M_ISENTRY, M_KEPTNONE, M_LABELN, M_MAXCALL, M_MAXLOC, M_MAXSLOTS,
    M_NB, M_NEEDZ, M_NEXT, M_NFTYPES, M_NN, M_NORDER, M_NRET, M_NV, M_ONE, M_PASS, M_PEND, M_PSLOTS, M_RETTYPES, M_SCRATCH, M_SOCC,
    M_STYPE, M_T, M_TRACK, M_TRAPUSED, M_TYPED, M_WORK, N_COPY, N_ELIM, N_LINE, ST_TOP, STATE_WORDS, T_CAP, V_DESC, V_IMPLICIT, V_KEPT,
    V_SINGLE, VALUE_TABLES, INTERNAL_LABELS, _desc, _each_edge, _node_id, _pick_slots, _result0, _set_v, _target_index, _v, canon, carried, late,
)
from xax_selfhost_views_backend import GLOBALS, _call, _g, _ok

WORK_WORDS = (1 << 21) + 5 * (1 << 18)  # the effective/reachability worklist, then the task stack


def _edge_record(e: E, b_rec, k):
    return e.add(_f(e, b_rec, B_EDGES), e.mul(k, EDGE))


# -- edge copies ---------------------------------------------------------------------------------------------------------

def _moves(e: E, edge, into: str, count: str):
    """``edge_moves_needed``: (destination slot, descriptor, source value) per carried machine parameter whose argument
    is a constant or lives in another slot, into the triples at ``into``."""
    p = e.p
    e.var(f"{into}_t", _target_index(e, edge))
    e.var(f"{into}_tb", _block_at(e, p[f"{into}_t"]))
    e.var(f"{into}_args", _f(e, edge, 2))
    e.var(count, 0)

    def argument():
        e.var(f"{into}_param", e.ld(e.add(_f(e, p[f"{into}_tb"], B_INPUTS), p[f"{into}_k"])))
        e.var(f"{into}_arg", e.ld(e.add(p[f"{into}_args"], p[f"{into}_k"])))

        def machine():
            _ok(e, e.both(e.ne(_v(e, C_VSLOT, p[f"{into}_arg"]), NONE), e.ne(_v(e, C_VSLOT, p[f"{into}_param"]), NONE)))  # the bootstrap's KeyError
            from xax_selfhost_jvm_method import V_CONST

            e.if_(e.either(e.ne(_v(e, V_CONST, p[f"{into}_arg"]), 0), e.ne(_v(e, C_VSLOT, p[f"{into}_arg"]), _v(e, C_VSLOT, p[f"{into}_param"]))), lambda: (
                e.var(f"{into}_at", e.add(p[into], e.mul(p[count], 4))),
                e.st(p[f"{into}_at"], _v(e, C_VSLOT, p[f"{into}_param"])),
                e.st(e.add(p[f"{into}_at"], 1), _v(e, C_VSDESC, p[f"{into}_param"])),
                e.st(e.add(p[f"{into}_at"], 2), p[f"{into}_arg"]),
                e.st(e.add(p[f"{into}_at"], 3), NONE),  # a temporary source's slot (else NONE)
                e.set(count, e.add(p[count], 1))))

        e.if_(e.both(e.ne(_desc(e, p[f"{into}_param"]), D_NONE), carried(e, p[f"{into}_t"], p[f"{into}_param"])), machine)

    e.for_(f"{into}_k", 0, _f(e, edge, 1), argument)


def _needs_moves_fn(tables):
    """1 when the edge needs a copy."""
    def build(e: E):
        p = e.p
        e.var("nm_buf", e.alloc(e.add(e.mul(_f(e, p["edge"], 1), 4), 4)))
        _ok(e, e.ne(p["nm_buf"], NONE))
        _moves(e, p["edge"], "nm_buf", "nm_n")
        e.give(e.flag(e.lt(0, p["nm_n"])))
    return _function(("edge",), build, tables)


def _scratch_slot(e: E, desc, name: str):
    p = e.p
    e.var(name, _m(e, M_SCRATCH))
    _set_m(e, M_SCRATCH, e.add(p[name], _pick_slots(e, desc)))
    e.if_(e.lt(_m(e, M_MAXLOC), _m(e, M_SCRATCH)), lambda: _set_m(e, M_MAXLOC, _m(e, M_SCRATCH)))


def _copy_edge_fn(tables):
    """``copy_edge``: a parallel copy (a move whose destination no pending move reads first, else the first move's
    source into a temporary), then ``goto`` the resolved target unless it follows (or ``force``)."""
    from xax_selfhost_jvm_method import V_CONST

    def build(e: E):
        p = e.p
        e.var("ce_buf", e.alloc(e.add(e.mul(_f(e, p["edge"], 1), 4), 4)))
        _ok(e, e.ne(p["ce_buf"], NONE))
        _moves(e, p["edge"], "ce_buf", "ce_n")

        def field(k, f):
            return e.ld(e.add(e.add(p["ce_buf"], e.mul(k, 4)), f))

        def source_slot(k):
            """The slot a pending move reads (NONE for a constant source)."""
            return e.sel(e.ne(field(k, 3), NONE), field(k, 3), e.sel(e.ne(_v(e, V_CONST, field(k, 2)), 0), NONE, _v(e, C_VSLOT, field(k, 2))))

        def step():
            e.var("ce_ready", NONE)

            def check():
                e.var("ce_dst", field(p["ce_i"], 0))
                e.var("ce_read", 0)
                e.for_("ce_j", 0, p["ce_n"], lambda: e.if_(e.eq(source_slot(p["ce_j"]), p["ce_dst"]), lambda: e.set("ce_read", 1)))
                e.if_(e.both(e.eq(p["ce_ready"], NONE), e.eq(p["ce_read"], 0)), lambda: e.set("ce_ready", p["ce_i"]))

            e.for_("ce_i", 0, p["ce_n"], check)

            def cycle():
                _ok(e, e.eq(field(0, 3), NONE))  # a temporary in a remaining cycle: the bootstrap's own failure
                e.var("ce_src", field(0, 2))
                e.var("ce_kd", field(0, 1))
                _scratch_slot(e, p["ce_kd"], "ce_tmp")
                run(e, K_GET, p["ce_src"])
                local(e, True, p["ce_kd"], p["ce_tmp"])
                e.for_("ce_j", 0, p["ce_n"], lambda: e.if_(e.both(e.eq(field(p["ce_j"], 3), NONE), e.eq(field(p["ce_j"], 2), p["ce_src"])), lambda: (
                    e.st(e.add(e.add(p["ce_buf"], e.mul(p["ce_j"], 4)), 3), p["ce_tmp"]),
                    e.st(e.add(e.add(p["ce_buf"], e.mul(p["ce_j"], 4)), 2), p["ce_kd"]))))

            def move():
                e.var("ce_r", p["ce_ready"])
                e.if_(e.ne(field(p["ce_r"], 3), NONE), lambda: local(e, False, field(p["ce_r"], 2), field(p["ce_r"], 3)),
                      lambda: run(e, K_GET, field(p["ce_r"], 2)))
                local(e, True, field(p["ce_r"], 1), field(p["ce_r"], 0))
                e.var("ce_k", p["ce_r"])
                e.while_(lambda: e.lt(e.add(p["ce_k"], 1), p["ce_n"]), lambda: (
                    e.for_("ce_f", 0, 4, lambda: e.st(e.add(e.add(p["ce_buf"], e.mul(p["ce_k"], 4)), p["ce_f"]), field(e.add(p["ce_k"], 1), p["ce_f"]))),
                    e.set("ce_k", e.add(p["ce_k"], 1))))
                e.set("ce_n", e.sub(p["ce_n"], 1))

            e.if_(e.eq(p["ce_ready"], NONE), cycle, move)

        e.while_(lambda: e.lt(0, p["ce_n"]), step)
        e.var("ce_target", _v(e, BL_RESOLVED, _target_index(e, p["edge"])))
        e.if_(e.both(e.ne(p["jump"], 0), e.either(e.ne(p["force"], 0), e.ne(p["ce_target"], _m(e, M_FOLLOW)))), lambda: branch(e, GOTO, p["ce_target"]))
        e.give(1)
    return _function(("edge", "jump", "force"), build, tables)


# -- definite assignment ---------------------------------------------------------------------------------------------------

def _stores_result(e: E, value):
    """A node result's local is written where it is defined (not one left on the operand stack)."""
    slot = _v(e, C_VSLOT, value)
    kept = e.both(e.eq(_m(e, M_PASS), 2), e.ne(_v(e, V_SINGLE, value), 0), e.eq(_v(e, V_IMPLICIT, value), 0))
    return e.both(e.ne(slot, NONE), e.ne(slot, SLOT_LATE), e.not_(kept))


def _assignment_fn(tables):
    """The slots a typed frame needs zeroed: a typed slot missing from the slots assigned at some branch target.  1
    when one of them is a freed parameter's (those parameters are kept and the pass retried), else the zero stores and
    0."""
    def build(e: E):
        p = e.p
        nb = _m(e, M_NB)
        s = _m(e, M_NEXT)
        e.var("da_s", s)
        e.var("da_in", e.alloc(e.add(e.mul(nb, p["da_s"]), 1)))
        e.var("da_wr", e.alloc(e.add(e.mul(nb, p["da_s"]), 1)))
        e.var("da_tmp", e.alloc(e.add(p["da_s"], 1)))
        e.var("da_acc", e.alloc(e.add(p["da_s"], 1)))
        e.var("da_need", e.alloc(e.add(p["da_s"], 1)))
        _ok(e, e.both(e.ne(p["da_in"], NONE), e.ne(p["da_wr"], NONE), e.ne(p["da_tmp"], NONE), e.ne(p["da_acc"], NONE), e.ne(p["da_need"], NONE)))

        def row(base, b):
            return e.add(base, e.mul(b, p["da_s"]))

        def key(slot):
            return e.ne(e.ld(e.add(_m(e, M_STYPE), slot)), NONE)

        def param_slot(slot):
            return e.both(key(slot), e.lt(slot, _m(e, M_PEND)), e.eq(e.ld(e.add(_m(e, M_FREED), slot)), NONE))

        # writes
        def writes():
            e.var("da_b", _block_at(e, p["da_bi"]))
            e.var("da_w", row(p["da_wr"], p["da_bi"]))
            e.for_("da_k", 0, p["da_s"], lambda: e.st(e.add(p["da_w"], p["da_k"]), 0))

            def node():
                e.var("da_n", _node_at(e, p["da_b"], p["da_m"]))
                e.for_("da_r", 0, _f(e, p["da_n"], N_NRES), lambda: (e.var("da_rv", _output(e, p["da_n"], p["da_r"])), e.if_(
                    _stores_result(e, p["da_rv"]), lambda: e.st(e.add(p["da_w"], _v(e, C_VSLOT, p["da_rv"])), 1))))

            e.for_("da_m", 0, _f(e, p["da_b"], B_NNODES), node)

            def edge(target, n, args):
                e.var("da_tb", _block_at(e, target))
                e.for_("da_k", 0, _f(e, p["da_tb"], B_NP), lambda: (e.var("da_pv", e.ld(e.add(_f(e, p["da_tb"], B_INPUTS), p["da_k"]))), e.if_(
                    e.both(e.ne(_v(e, C_VSLOT, p["da_pv"]), NONE), e.ne(_v(e, C_VSLOT, p["da_pv"]), SLOT_LATE)), lambda: e.st(e.add(p["da_w"], _v(e, C_VSLOT, p["da_pv"])), 1))))

            _each_edge(e, p["da_b"], edge, "dae")

        e.for_("da_bi", 0, nb, writes)
        # assigned_in: the entry's parameter slots, every slot elsewhere; then intersections to the fixed point.
        e.for_("da_bi", 0, nb, lambda: (e.var("da_r", row(p["da_in"], p["da_bi"])), e.for_("da_k", 0, p["da_s"], lambda: e.st(
            e.add(p["da_r"], p["da_k"]), e.sel(e.eq(p["da_bi"], _m(e, M_ENTRY)), e.flag(param_slot(p["da_k"])), e.flag(key(p["da_k"])))))))
        e.var("da_changed", 1)

        def round_():
            e.set("da_changed", 0)

            def block():
                e.var("da_any", 0)
                e.for_("da_k", 0, p["da_s"], lambda: e.st(e.add(p["da_acc"], p["da_k"]), 1))

                def predecessor():
                    e.var("da_pb", _block_at(e, p["da_pi"]))

                    def edge(target, n, args):
                        def meet():
                            e.set("da_any", 1)
                            e.var("da_pr", row(p["da_in"], p["da_pi"]))
                            e.var("da_pw", row(p["da_wr"], p["da_pi"]))
                            e.for_("da_k", 0, p["da_s"], lambda: e.if_(e.both(e.eq(e.ld(e.add(p["da_pr"], p["da_k"])), 0), e.eq(e.ld(e.add(p["da_pw"], p["da_k"])), 0)),
                                                                     lambda: e.st(e.add(p["da_acc"], p["da_k"]), 0)))

                        e.if_(e.eq(target, p["da_bi"]), meet)

                    _each_edge(e, p["da_pb"], edge, "dap")

                e.for_("da_pi", 0, nb, predecessor)

                def entry():
                    e.set("da_any", 1)
                    e.for_("da_k", 0, p["da_s"], lambda: e.if_(e.not_(param_slot(p["da_k"])), lambda: e.st(e.add(p["da_acc"], p["da_k"]), 0)))

                e.if_(e.eq(p["da_bi"], _m(e, M_ENTRY)), entry)

                def update():
                    e.var("da_r", row(p["da_in"], p["da_bi"]))
                    e.for_("da_k", 0, p["da_s"], lambda: e.if_(e.ne(e.ld(e.add(p["da_r"], p["da_k"])), e.ld(e.add(p["da_acc"], p["da_k"]))), lambda: (
                        e.st(e.add(p["da_r"], p["da_k"]), e.ld(e.add(p["da_acc"], p["da_k"]))), e.set("da_changed", 1))))

                e.if_(e.ne(p["da_any"], 0), update)

            e.for_("da_bi", 0, nb, block)

        e.while_(lambda: e.ne(p["da_changed"], 0), round_)
        # The points: a block's label (when it has predecessors), and after its nodes unless it returns or branches.
        e.for_("da_k", 0, p["da_s"], lambda: e.st(e.add(p["da_need"], p["da_k"]), 0))

        def check(point):
            e.for_("da_k", 0, p["da_s"], lambda: e.if_(e.both(e.ne(e.ld(e.add(_m(e, M_TYPED), p["da_k"])), 0), e.eq(e.ld(e.add(point, p["da_k"])), 0)),
                                                     lambda: e.st(e.add(p["da_need"], p["da_k"]), 1)))

        def points():
            e.var("da_b", _block_at(e, p["da_bi"]))
            e.var("da_r", row(p["da_in"], p["da_bi"]))
            e.if_(e.lt(0, _v(e, BL_INC, p["da_bi"])), lambda: check(p["da_r"]))
            e.for_("da_k", 0, p["da_s"], lambda: e.st(e.add(p["da_tmp"], p["da_k"]), e.ld(e.add(p["da_r"], p["da_k"]))))

            def node():
                e.var("da_n", _node_at(e, p["da_b"], p["da_m"]))
                e.if_(_in(e, _eop(e, p["da_n"]), INTERNAL_LABELS), lambda: check(p["da_tmp"]))  # a label inside it
                e.for_("da_rr", 0, _f(e, p["da_n"], N_NRES), lambda: (e.var("da_rv", _output(e, p["da_n"], p["da_rr"])), e.if_(
                    _stores_result(e, p["da_rv"]), lambda: e.st(e.add(p["da_tmp"], _v(e, C_VSLOT, p["da_rv"])), 1))))

            e.for_("da_m", 0, _f(e, p["da_b"], B_NNODES), node)
            e.if_(e.not_(e.either(e.eq(_f(e, p["da_b"], B_KIND), RETURN), e.eq(_f(e, p["da_b"], B_KIND), BRANCH))), lambda: check(p["da_tmp"]))

        e.for_("da_bi", 0, nb, points)
        e.var("da_retry", 0)
        e.for_("da_k", 0, p["da_s"], lambda: e.if_(e.both(e.ne(e.ld(e.add(p["da_need"], p["da_k"])), 0), e.ne(e.ld(e.add(_m(e, M_FREED), p["da_k"])), NONE)), lambda: (
            _set_v(e, V_KEPT, e.ld(e.add(_m(e, M_FREED), p["da_k"])), 1), e.set("da_retry", 1))))
        e.if_(e.ne(p["da_retry"], 0), lambda: e.give(1))
        e.for_("da_k", _m(e, M_PEND), p["da_s"], lambda: e.if_(e.ne(e.ld(e.add(p["da_need"], p["da_k"])), 0), lambda: (
            e.var("da_t", e.ld(e.add(_m(e, M_STYPE), p["da_k"]))),
            opx(e, _pick(e, p["da_t"], ZERO), 1),
            local(e, True, p["da_t"], p["da_k"]))))
        e.give(0)
    return _function((), build, tables)


# -- layout ---------------------------------------------------------------------------------------------------------------

def _layout_fn(tables):
    """Jump threading (an empty non-entry block whose one edge needs no copy forwards), each block's resolved target,
    the fallthrough chains, and the line numbers in layout order."""
    def build(e: E):
        p = e.p
        nb = _m(e, M_NB)
        e.var("ly_fwd", e.alloc(e.add(nb, 1)))
        e.var("ly_seen", e.alloc(e.add(nb, 1)))
        _ok(e, e.both(e.ne(p["ly_fwd"], NONE), e.ne(p["ly_seen"], NONE)))

        def forwards():
            e.var("ly_b", _block_at(e, p["ly_bi"]))
            e.st(e.add(p["ly_fwd"], p["ly_bi"]), NONE)
            empty = e.both(e.ne(p["ly_bi"], _m(e, M_ENTRY)), e.eq(_f(e, p["ly_b"], B_NNODES), 0), e.eq(_f(e, p["ly_b"], B_KIND), BRANCH))
            e.if_(empty, lambda: e.if_(e.eq(_call(e, "je_needs_moves", _edge_record(e, p["ly_b"], 0)), 0), lambda: e.st(
                e.add(p["ly_fwd"], p["ly_bi"]), _target_index(e, _edge_record(e, p["ly_b"], 0)))))

        e.for_("ly_bi", 0, nb, forwards)
        e.var("ly_stamp", 0)

        def resolve():
            e.set("ly_stamp", e.add(p["ly_stamp"], 1))
            e.var("ly_t", p["ly_bi"])
            e.var("ly_go", 1)

            def follow():
                e.st(e.add(p["ly_seen"], p["ly_t"]), p["ly_stamp"])
                e.var("ly_next", e.ld(e.add(p["ly_fwd"], p["ly_t"])))
                e.if_(e.eq(p["ly_next"], NONE), lambda: e.set("ly_go", 0), lambda: e.set("ly_t", p["ly_next"]))

            e.while_(lambda: e.both(e.ne(p["ly_go"], 0), e.ne(e.ld(e.add(p["ly_seen"], p["ly_t"])), p["ly_stamp"])), follow)
            _set_v(e, BL_RESOLVED, p["ly_bi"], p["ly_t"])

        e.for_("ly_z", 0, nb, lambda: e.st(e.add(p["ly_seen"], p["ly_z"]), 0))
        e.for_("ly_bi", 0, nb, resolve)
        # Fallthrough chains.
        e.for_("ly_bi", 0, nb, lambda: _set_v(e, BL_PLACED, p["ly_bi"], 0))
        e.var("ly_n", 0)

        def chain(start):
            e.var("ly_cur", e.sel(e.eq(_v(e, BL_RESOLVED, start), start), start, NONE))

            def place():
                e.st(e.add(_m(e, BL_ORDER), p["ly_n"]), p["ly_cur"])
                e.set("ly_n", e.add(p["ly_n"], 1))
                _set_v(e, BL_PLACED, p["ly_cur"], 1)
                e.var("ly_cb", _block_at(e, p["ly_cur"]))
                e.var("ly_kind", _f(e, p["ly_cb"], B_KIND))
                e.var("ly_following", NONE)
                e.if_(e.eq(p["ly_kind"], BRANCH), lambda: e.set("ly_following", _v(e, BL_RESOLVED, _target_index(e, _edge_record(e, p["ly_cb"], 0)))))

                def conditional():
                    e.var("ly_true", _v(e, BL_RESOLVED, _target_index(e, _edge_record(e, p["ly_cb"], 0))))
                    e.var("ly_false", _v(e, BL_RESOLVED, _target_index(e, _edge_record(e, p["ly_cb"], 1))))
                    returns = lambda b: e.eq(_f(e, _block_at(e, b), B_KIND), RETURN)  # noqa: E731
                    e.if_(e.both(returns(p["ly_false"]), e.not_(returns(p["ly_true"])), e.eq(_v(e, BL_PLACED, p["ly_true"]), 0)),
                          lambda: e.set("ly_following", p["ly_true"]),
                          lambda: e.set("ly_following", e.sel(e.eq(_v(e, BL_PLACED, p["ly_false"]), 0), p["ly_false"], p["ly_true"])))

                e.if_(e.eq(p["ly_kind"], CONDITIONAL), conditional)
                e.set("ly_cur", p["ly_following"])

            e.while_(lambda: e.both(e.ne(p["ly_cur"], NONE), e.eq(_v(e, BL_PLACED, e.sel(e.ne(p["ly_cur"], NONE), p["ly_cur"], 0)), 0)), place)

        chain(_m(e, M_ENTRY))
        e.for_("ly_bi", 0, nb, lambda: chain(p["ly_bi"]))
        _set_m(e, M_NORDER, p["ly_n"])
        # Line numbers: every node of the placed blocks, in layout order.
        e.var("ly_line", 0)
        e.for_("ly_q", 0, p["ly_n"], lambda: (
            e.var("ly_ob", e.ld(e.add(_m(e, BL_ORDER), p["ly_q"]))), e.var("ly_obr", _block_at(e, p["ly_ob"])),
            e.for_("ly_m", 0, _f(e, p["ly_obr"], B_NNODES), lambda: (
                e.set("ly_line", e.add(p["ly_line"], 1)),
                _set_v(e, N_LINE, e.add(_v(e, BL_BASE, p["ly_ob"]), p["ly_m"]), p["ly_line"])))))
        e.give(1)
    return _function((), build, tables)


# -- blocks ---------------------------------------------------------------------------------------------------------------

def _terminator_fn(tables):
    """The block's terminator (its index ``bi``)."""
    from xax_selfhost_jvm_lower import _desc_get

    def build(e: E):
        p = e.p
        e.var("tm_b", _block_at(e, p["bi"]))
        e.var("tm_kind", _f(e, p["tm_b"], B_KIND))

        def returned():
            e.var("tm_v", NONE)
            e.for_("tm_k", 0, _f(e, p["tm_b"], B_NVALUES), lambda: e.if_(e.both(e.eq(p["tm_v"], NONE), e.lt(p["tm_k"], _m(e, M_NRET)),
                                                                              e.ne(e.ld(e.add(_m(e, M_RETTYPES), p["tm_k"])), D_NONE)),
                                                                       lambda: e.set("tm_v", e.ld(e.add(_f(e, p["tm_b"], B_VALUES), p["tm_k"])))))

            def value():
                e.var("tm_d", _desc_get(e, p["tm_v"]))
                run(e, K_GET, p["tm_v"])
                opx(e, _pick(e, p["tm_d"], RETURN_OPS), 1)

            e.if_(e.ne(p["tm_v"], NONE), value, lambda: op(e, 0xB1))

        def conditional():
            e.var("tm_c", e.ld(_f(e, p["tm_b"], B_VALUES)))
            e.var("tm_te", _edge_record(e, p["tm_b"], 0))
            e.var("tm_fe", _edge_record(e, p["tm_b"], 1))
            e.var("tm_tm", _call(e, "je_needs_moves", p["tm_te"]))
            e.var("tm_fm", _call(e, "je_needs_moves", p["tm_fe"]))
            e.var("tm_tr", _v(e, BL_RESOLVED, _target_index(e, p["tm_te"])))
            e.var("tm_fr", _v(e, BL_RESOLVED, _target_index(e, p["tm_fe"])))
            e.if_(e.both(e.eq(p["tm_tm"], 0), e.either(e.ne(p["tm_fm"], 0), e.eq(p["tm_fr"], _m(e, M_FOLLOW)))), lambda: (
                run(e, K_JUMP, p["tm_c"], 1, p["tm_tr"]), _call(e, "je_copy_edge", p["tm_fe"], 1, 0)), lambda: e.if_(
                e.eq(p["tm_fm"], 0), lambda: (run(e, K_JUMP, p["tm_c"], 0, p["tm_fr"]), _call(e, "je_copy_edge", p["tm_te"], 1, 0)), lambda: e.if_(
                    e.eq(p["tm_tm"], 0), lambda: (run(e, K_JUMP, p["tm_c"], 1, p["tm_tr"]), _call(e, "je_copy_edge", p["tm_fe"], 1, 0)), lambda: (
                        e.var("tm_stub", e.add(_m(e, M_NB), p["bi"])),
                        run(e, K_JUMP, p["tm_c"], 0, p["tm_stub"]),
                        _call(e, "je_copy_edge", p["tm_te"], 1, 1),
                        mark(e, p["tm_stub"]),
                        _call(e, "je_copy_edge", p["tm_fe"], 1, 0)))))

        def trap():
            _set_m(e, M_TRAPUSED, 1)
            branch(e, GOTO, e.mul(_m(e, M_NB), 2))

        e.if_(e.eq(p["tm_kind"], RETURN), returned, lambda: e.if_(e.eq(p["tm_kind"], BRANCH), lambda: _call(e, "je_copy_edge", _edge_record(e, p["tm_b"], 0), 1, 0),
                                                                  lambda: e.if_(e.eq(p["tm_kind"], CONDITIONAL), conditional, trap)))
        e.give(1)
    return _function(("bi",), build, tables)


def _blocks_fn(tables):
    """Every placed block: its label, its nodes not evaluated late or eliminated, its terminator; a return block only
    reached by a jump and byte-identical to an earlier one is that one (tail merging)."""
    def build(e: E):
        p = e.p
        e.var("bk_returns", e.alloc(e.add(e.mul(_m(e, M_NORDER), 2), 2)))
        _ok(e, e.ne(p["bk_returns"], NONE))
        e.var("bk_nret", 0)

        def block():
            e.var("bk_bi", e.ld(e.add(_m(e, BL_ORDER), p["bk_q"])))
            _set_m(e, M_FOLLOW, e.sel(e.lt(e.add(p["bk_q"], 1), _m(e, M_NORDER)), e.ld(e.add(_m(e, BL_ORDER), e.add(p["bk_q"], 1))), NONE))
            e.var("bk_b", _block_at(e, p["bk_bi"]))
            _flush(e)
            e.var("bk_start", _length(e))
            e.var("bk_fix", _m(e, C_NFIX))
            e.var("bk_lines", _m(e, C_NLINES))
            e.var("bk_jumped", _m(e, C_ENDED))
            mark(e, p["bk_bi"])
            _set_m(e, M_SCRATCH, _m(e, M_GEND))

            def node():
                e.var("bk_n", _node_at(e, p["bk_b"], p["bk_m"]))
                e.var("bk_r0", _result0(e, p["bk_n"]))
                skip = e.either(e.both(e.ne(p["bk_r0"], NONE), late(e, e.sel(e.ne(p["bk_r0"], NONE), p["bk_r0"], 0))),
                                e.ne(_v(e, N_ELIM, _node_id(e, p["bk_bi"], p["bk_n"])), 0))
                e.if_(e.not_(skip), lambda: run(e, K_NODE, p["bk_n"]))

            e.for_("bk_m", 0, _f(e, p["bk_b"], B_NNODES), node)
            _call(e, "je_terminator", p["bk_bi"])

            def merge():
                e.var("bk_len", e.sub(_length(e), p["bk_start"]))
                e.var("bk_code", bdata(e, _m(e, C_BUF)))
                e.var("bk_found", NONE)

                def compare():
                    e.var("bk_os", e.ld(e.add(p["bk_returns"], e.mul(p["bk_i"], 2))))
                    e.var("bk_ol", e.ld(e.add(p["bk_returns"], e.add(e.mul(p["bk_i"], 2), 1))))

                    def same():
                        e.var("bk_eq", 1)
                        e.for_("bk_k", 0, p["bk_len"], lambda: e.if_(e.ne(e.ld(e.add(p["bk_code"], e.add(p["bk_os"], p["bk_k"]))),
                                                                           e.ld(e.add(p["bk_code"], e.add(p["bk_start"], p["bk_k"])))), lambda: e.set("bk_eq", 0)))
                        e.if_(e.ne(p["bk_eq"], 0), lambda: e.set("bk_found", p["bk_os"]))

                    e.if_(e.both(e.eq(p["bk_found"], NONE), e.eq(p["bk_ol"], p["bk_len"])), same)

                e.for_("bk_i", 0, p["bk_nret"], compare)

                def drop():
                    e.st(e.add(_m(e, C_BUF), B_LEN), p["bk_start"])
                    e.st(e.add(_m(e, C_LABELS), p["bk_bi"]), p["bk_found"])
                    _set_m(e, C_ENDED, 1)

                def keep():
                    e.st(e.add(p["bk_returns"], e.mul(p["bk_nret"], 2)), p["bk_start"])
                    e.st(e.add(p["bk_returns"], e.add(e.mul(p["bk_nret"], 2), 1)), p["bk_len"])
                    e.set("bk_nret", e.add(p["bk_nret"], 1))

                e.if_(e.ne(p["bk_found"], NONE), drop, keep)

            mergeable = e.both(e.eq(_f(e, p["bk_b"], B_KIND), RETURN), e.ne(p["bk_jumped"], 0), e.eq(_m(e, C_PENDING), NONE), e.eq(_m(e, C_STORED), NONE),
                               e.eq(_m(e, C_NFIX), p["bk_fix"]), e.eq(_m(e, C_NLINES), p["bk_lines"]))
            e.if_(mergeable, merge)

        e.for_("bk_q", 0, _m(e, M_NORDER), block)

        def trap():
            from xax_selfhost_jvm_class import klass_literal, method_literal
            from xax_selfhost_jvm_code import invoke

            mark(e, e.mul(_m(e, M_NB), 2))
            op(e, 0xBB)
            e.var("bk_err", klass_literal(e, _m(e, C_POOL), "java/lang/Error", "bk_e"))
            from xax_selfhost_jvm_code import raw

            raw(e, p["bk_err"], 2)
            op(e, 0x59)
            from xax_selfhost_jvm_class import utf8_literal

            e.var("bk_msg", _call(e, "jp_ref1", _m(e, C_POOL), 8, utf8_literal(e, _m(e, C_POOL), "XAX trap", "bk_t")))
            _call(e, "jc_ldc", p["bk_msg"])
            op(e, 0xB7)
            e.var("bk_init", method_literal(e, _m(e, C_POOL), "java/lang/Error", "<init>", "(Ljava/lang/String;)V", "bk_i"))
            raw(e, p["bk_init"], 2)
            op(e, 0xBF)

        e.if_(e.ne(_m(e, M_TRAPUSED), 0), trap)
        e.give(1)
    return _function((), build, tables)


def add_emit_functions(add, tables):
    for name, builder in (("je_needs_moves", _needs_moves_fn), ("je_copy_edge", _copy_edge_fn), ("je_assignment", _assignment_fn),
                          ("je_layout", _layout_fn), ("je_terminator", _terminator_fn), ("je_blocks", _blocks_fn)):
        add(name, builder(tables))
