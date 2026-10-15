"""S12f.4 (ADR-280): the bootstrap's legacy register path for the Linux profiles, as XAX functions.

``xax_x86_64._compile_function`` tries ``_compile_register_resident_function`` on a function's own graph when the
register-resident lowering (S12d) returns None for its lowering view and the function is not the process entry.
The view inlines small leaf callees, so a function made only of ``add``/``sub``/``mul``, constants, and direct calls
reaches this path whenever an inlined callee keeps the view off the register-resident path (a float, say).  On a
Linux profile (not the hosted PE one) the path lowers exactly those operations, the resource operations (nothing),
and ``return``/``branch``/``conditional branch`` terminators:

* every bits value of at most 64 bits is a machine value; block parameters arrive in the allocatable registers
  (``rcx, rdx, r8, r9, r10, rax``) and then edge spill slots after the shadow space (when the function calls);
* a value used outside its defining block has a home slot, written at its definition;
* per block, values live in registers; one is spilled to a slot (the lowest free one) when no register is free,
  the victim being the value whose next use is furthest (then the register, then the value's position);
* a direct call spills every value live after it (keeping the copy), moves the operands to the argument registers
  (parallel moves through ``r11``), and kills every register; the result is in ``rax``;
* a dry run first sizes the dynamic spill area, then the real run emits.

The code, fixups, and ranges go to the emission record (S12d), so image assembly is unchanged.  Where the bootstrap
fails (NATIVE-BITS-SUPPORTED: arithmetic other than 32 or 64 bits wide) the program writes its diagnostic.
"""

from __future__ import annotations

from xax_compiler import Operation
from xax_selfhost_facts import E, NONE, _function
from xax_selfhost_general_emit import (
    E_CLEN, E_NRANGES, E_RANGES, E_REAL, _bx, _label, _load, _movabs, _new_label, _record_call, _relative, _store, _test,
)
from xax_selfhost_general_frame import (
    ARGUMENT_REGISTERS, CALLS, _bits_width, _each_node, _eop, _op, _proof, _relative2,
)
from xax_selfhost_general_ranges import _block_at, _node_at
from xax_selfhost_general_regalloc import _callee_object, _ra, _set_ra
from xax_selfhost_general_view import (
    B_EDGES, B_INPUTS, B_KIND, B_NEDGES, B_NNODES, B_NP, B_NVALUES, B_POS, B_VALUES, BRANCH, CONDITIONAL, EDGE, G_BCOUNT,
    G_BENTRY, G_VCOUNT, G_VPOS, G_VPROD, G_VTYPE, N_GRAPH, N_NOPS, N_NRES, N_OPSAT, POS_BLOCK, RETURN, _f, _operand, _output, _vf,
)
from xax_selfhost_views_backend import _FN, _call, _g, _ok

ALLOCATABLE = (1, 2, 8, 9, 10, 0)  # (*argument registers, scratch_registers[0], result register), deduplicated
SCRATCH = 11  # scratch_registers[1]
SHADOW = 32
RAX = 0
L_STATE = 242  # ``_ra`` slot: the legacy lowering's state record
# State words: per-value tables (each VCOUNT words), the register map, the spill slot flags, and scalars.
(S_WIDTH, S_HOME, S_REG, S_SPILL, S_SPID, S_LAST, S_UCOUNT, S_UAT, S_ULIST, S_VREG, S_FREE, S_NEXT, S_MAX, S_BI, S_DYN,
 S_EDGEB, S_P1, S_P2, S_NFREE, S_POSN) = range(20)
STATE_WORDS = 20
MOVE_CAP = 8


def _s(e: E, field: int):
    return e.ld(e.add(_ra(e, L_STATE), field))


def _set_s(e: E, field: int, value):
    e.st(e.add(_ra(e, L_STATE), field), value)


def _t(e: E, table: int, value):
    return e.ld(e.add(_s(e, table), value))


def _set_t(e: E, table: int, value, word):
    e.st(e.add(_s(e, table), value), word)


def _width_bytes(e: E, value):
    return e.sel(e.eq(_t(e, S_WIDTH, value), 64), 8, 4)


def _block_of(e: E, value):
    """The value's block in the function's own graph (``ValueRef.block``)."""
    return e.and_(e.udiv(_vf(e, G_VPOS, value), POS_BLOCK), (1 << 22) - 1)


def _real(e: E, body):
    e.if_(e.ne(_ra(e, E_REAL), 0), body)


# -- the allocator -----------------------------------------------------------------------------------------------

def _unbind(e: E, value):
    p = e.p
    e.var("ub_r", _t(e, S_REG, value))
    _set_t(e, S_REG, value, NONE)
    e.if_(e.both(e.ne(p["ub_r"], NONE), e.eq(e.ld(e.add(_s(e, S_VREG), e.sel(e.eq(p["ub_r"], NONE), 0, p["ub_r"]))), value)),
          lambda: e.st(e.add(_s(e, S_VREG), p["ub_r"]), NONE))


def _bind_fn(tables):
    """``bind(value, register)``."""
    def build(e: E):
        p = e.p
        e.var("bd_old", e.ld(e.add(_s(e, S_VREG), p["register"])))
        e.if_(e.both(e.ne(p["bd_old"], NONE), e.ne(p["bd_old"], p["value"])), lambda: _set_t(e, S_REG, p["bd_old"], NONE))
        e.var("bd_oreg", _t(e, S_REG, p["value"]))
        e.if_(e.both(e.ne(p["bd_oreg"], NONE), e.ne(p["bd_oreg"], p["register"])), lambda: e.st(e.add(_s(e, S_VREG), p["bd_oreg"]), NONE))
        _set_t(e, S_REG, p["value"], p["register"])
        e.st(e.add(_s(e, S_VREG), p["register"]), p["value"])
        e.give(1)
    return _function(("value", "register"), build, tables)


def _release_fn(tables):
    """``release(value)``: unbound, and its dynamic spill slot freed."""
    def build(e: E):
        p = e.p
        _unbind(e, p["value"])
        e.var("rl_id", _t(e, S_SPID, p["value"]))

        def free():
            _set_t(e, S_SPID, p["value"], NONE)
            _set_t(e, S_SPILL, p["value"], NONE)
            e.st(e.add(_s(e, S_FREE), p["rl_id"]), 1)

        e.if_(e.ne(p["rl_id"], NONE), free)
        e.give(1)
    return _function(("value",), build, tables)


def _define_fn(tables):
    """``define(value, register)``: bound; written to its home; released when the block never uses it."""
    def build(e: E):
        p = e.p
        _call(e, "lg_bind", p["value"], p["register"])
        e.var("df_home", _t(e, S_HOME, p["value"]))

        def home():
            _store(e, p["register"], p["df_home"], _width_bytes(e, p["value"]))
            _set_t(e, S_SPILL, p["value"], p["df_home"])

        e.if_(e.ne(p["df_home"], NONE), home)
        e.if_(e.eq(_t(e, S_LAST, p["value"]), NONE), lambda: _call(e, "lg_release", p["value"]))
        e.give(1)
    return _function(("value", "register"), build, tables)


def _spill_fn(tables):
    """``spill(value, keep)``: its register's content to a slot (its home, an existing slot, or the lowest free one)."""
    def build(e: E):
        p = e.p
        e.var("sp_reg", _t(e, S_REG, p["value"]))

        def allocate():
            e.var("sp_slot", NONE)
            e.for_("sp_q", 0, _s(e, S_NEXT), lambda: e.if_(e.both(e.eq(p["sp_slot"], NONE), e.ne(e.ld(e.add(_s(e, S_FREE), p["sp_q"])), 0)),
                                                            lambda: e.set("sp_slot", p["sp_q"])))

            def fresh():
                e.set("sp_slot", _s(e, S_NEXT))
                _set_s(e, S_NEXT, e.add(_s(e, S_NEXT), 1))
                e.if_(e.lt(_s(e, S_MAX), _s(e, S_NEXT)), lambda: _set_s(e, S_MAX, _s(e, S_NEXT)))

            e.if_(e.eq(p["sp_slot"], NONE), fresh, lambda: e.st(e.add(_s(e, S_FREE), p["sp_slot"]), 0))
            _ok(e, e.lt(p["sp_slot"], _s(e, S_NFREE)))
            _set_t(e, S_SPID, p["value"], p["sp_slot"])
            _set_t(e, S_SPILL, p["value"], e.add(_s(e, S_DYN), e.mul(p["sp_slot"], 8)))
            _store(e, p["sp_reg"], _t(e, S_SPILL, p["value"]), _width_bytes(e, p["value"]))

        e.if_(e.eq(_t(e, S_SPILL, p["value"]), NONE), allocate)
        e.if_(e.eq(p["keep"], 0), lambda: _unbind(e, p["value"]))
        e.give(1)
    return _function(("value", "keep"), build, tables)


def _next_use(e: E, value, position, name: str):
    """``next_use(value, position)``: its first use in the block after ``position``, else 2^30."""
    p = e.p
    e.var(name, 1 << 30)
    e.var(f"{name}_at", _t(e, S_UAT, value))
    e.for_(f"{name}_q", 0, _t(e, S_UCOUNT, value), lambda: (
        e.var(f"{name}_u", e.ld(e.add(_s(e, S_ULIST), e.add(p[f"{name}_at"], p[f"{name}_q"])))),
        e.if_(e.both(e.eq(p[name], 1 << 30), e.lt(position, p[f"{name}_u"])), lambda: e.set(name, p[f"{name}_u"]))))


def _acquire_fn(tables):
    """``acquire(position, protected)``: a free allocatable register, else the victim's (spilled); the protected values
    are the state's ``S_P1``/``S_P2`` (NONE: none)."""
    def build(e: E):
        p = e.p
        e.var("aq_reg", NONE)
        for register in ALLOCATABLE:
            e.if_(e.both(e.eq(p["aq_reg"], NONE), e.eq(e.ld(e.add(_s(e, S_VREG), register)), NONE)), lambda register=register: e.set("aq_reg", register))
        e.if_(e.ne(p["aq_reg"], NONE), lambda: e.give(p["aq_reg"]))
        # The victim: the largest (next use, register, position) among the bound values not protected.
        e.var("aq_v", NONE)
        e.var("aq_kn", 0)
        e.var("aq_kr", 0)
        e.var("aq_kp", 0)
        for register in ALLOCATABLE:
            def candidate(register=register):
                e.var("aq_c", e.ld(e.add(_s(e, S_VREG), register)))

                def consider():
                    _next_use(e, p["aq_c"], p["position"], "aq_n")
                    e.var("aq_cp", _vf(e, G_VPOS, p["aq_c"]))
                    better = e.either(e.eq(p["aq_v"], NONE), e.lt(p["aq_kn"], p["aq_n"]),
                                      e.both(e.eq(p["aq_kn"], p["aq_n"]), e.either(e.lt(p["aq_kr"], register),
                                                                                    e.both(e.eq(p["aq_kr"], register), e.lt(p["aq_kp"], p["aq_cp"])))))
                    e.if_(better, lambda: (e.set("aq_v", p["aq_c"]), e.set("aq_kn", p["aq_n"]), e.set("aq_kr", register), e.set("aq_kp", p["aq_cp"])))

                e.if_(e.both(e.ne(p["aq_c"], NONE), e.ne(p["aq_c"], _s(e, S_P1)), e.ne(p["aq_c"], _s(e, S_P2))), consider)

            candidate()
        _ok(e, e.ne(p["aq_v"], NONE))  # NATIVE-SPILLABLE-REGISTER (unreachable: at most two values are protected)
        e.var("aq_vr", _t(e, S_REG, p["aq_v"]))
        _call(e, "lg_spill", p["aq_v"], 0)
        e.give(p["aq_vr"])
    return _function(("position",), build, tables)


def _ensure_fn(tables):
    """``ensure(value, position)`` (protected values in the state): its register, loaded from its slot if spilled."""
    def build(e: E):
        p = e.p
        e.if_(e.ne(_t(e, S_REG, p["value"]), NONE), lambda: e.give(_t(e, S_REG, p["value"])))
        e.var("en_off", _t(e, S_SPILL, p["value"]))
        _ok(e, e.ne(p["en_off"], NONE))  # NATIVE-VALUE-LOCATION (unreachable: dominance)
        e.var("en_reg", _call(e, "lg_acquire", p["position"]))
        _load(e, p["en_reg"], p["en_off"], _width_bytes(e, p["value"]))
        _call(e, "lg_bind", p["value"], p["en_reg"])
        e.give(p["en_reg"])
    return _function(("value", "position"), build, tables)


def _protect(e: E, first=NONE, second=NONE):
    _set_s(e, S_P1, first)
    _set_s(e, S_P2, second)


def _ensure(e: E, value, position, first=NONE, second=NONE):
    _protect(e, first, second)
    return _call(e, "lg_ensure", value, position)


def _acquire(e: E, position, first=NONE, second=NONE):
    _protect(e, first, second)
    return _call(e, "lg_acquire", position)


# -- moves, edges, calls -----------------------------------------------------------------------------------------

def _moves_fn(tables):
    """``parallel_moves`` of the ``count`` (destination, source, width) triples at ``at``: a move whose destination no
    pending move reads first, else the first pending source through ``r11``."""
    def build(e: E):
        p = e.p
        e.var("pm_n", 0)
        # Drop the moves onto themselves.
        e.for_("pm_q", 0, p["count"], lambda: (
            e.var("pm_t", e.add(p["at"], e.mul(p["pm_q"], 3))),
            e.if_(e.ne(e.ld(p["pm_t"]), e.ld(e.add(p["pm_t"], 1))), lambda: (
                e.var("pm_d", e.add(p["at"], e.mul(p["pm_n"], 3))),
                e.st(p["pm_d"], e.ld(p["pm_t"])), e.st(e.add(p["pm_d"], 1), e.ld(e.add(p["pm_t"], 1))), e.st(e.add(p["pm_d"], 2), e.ld(e.add(p["pm_t"], 2))),
                e.set("pm_n", e.add(p["pm_n"], 1))))))

        def step():
            e.var("pm_safe", NONE)

            def check():
                e.var("pm_dst", e.ld(e.add(p["at"], e.mul(p["pm_i"], 3))))
                e.var("pm_read", 0)
                e.for_("pm_j", 0, p["pm_n"], lambda: e.if_(e.eq(e.ld(e.add(e.add(p["at"], e.mul(p["pm_j"], 3)), 1)), p["pm_dst"]), lambda: e.set("pm_read", 1)))
                e.if_(e.both(e.eq(p["pm_safe"], NONE), e.eq(p["pm_read"], 0)), lambda: e.set("pm_safe", p["pm_i"]))

            e.for_("pm_i", 0, p["pm_n"], check)

            def remove(index):
                e.var("pm_k", index)
                e.while_(lambda: e.lt(e.add(p["pm_k"], 1), p["pm_n"]), lambda: (
                    e.for_("pm_f", 0, 3, lambda: e.st(e.add(e.add(p["at"], e.mul(p["pm_k"], 3)), p["pm_f"]),
                                                      e.ld(e.add(e.add(p["at"], e.mul(e.add(p["pm_k"], 1), 3)), p["pm_f"])))),
                    e.set("pm_k", e.add(p["pm_k"], 1))))
                e.set("pm_n", e.sub(p["pm_n"], 1))

            def safe():
                e.var("pm_s", e.add(p["at"], e.mul(p["pm_safe"], 3)))
                _call(e, "mov", e.ld(p["pm_s"]), e.ld(e.add(p["pm_s"], 1)), e.ld(e.add(p["pm_s"], 2)))
                remove(p["pm_safe"])

            def cycle():
                e.var("pm_src", e.ld(e.add(p["at"], 1)))
                _call(e, "mov", SCRATCH, p["pm_src"], e.ld(e.add(p["at"], 2)))
                e.for_("pm_j", 0, p["pm_n"], lambda: e.if_(e.eq(e.ld(e.add(e.add(p["at"], e.mul(p["pm_j"], 3)), 1)), p["pm_src"]),
                                                            lambda: e.st(e.add(e.add(p["at"], e.mul(p["pm_j"], 3)), 1), SCRATCH)))

            e.if_(e.ne(p["pm_safe"], NONE), safe, cycle)

        e.while_(lambda: e.lt(0, p["pm_n"]), step)
        e.give(1)
    return _function(("at", "count"), build, tables)


def _location(e: E, value, kind: str, where: str):
    """``location(value)``: ``kind`` 1 for a register, 0 for a slot; ``where`` the register or offset."""
    p = e.p
    e.var(kind, e.flag(e.ne(_t(e, S_REG, value), NONE)))
    e.var(where, e.sel(e.ne(p[kind], 0), _t(e, S_REG, value), _t(e, S_SPILL, value)))
    _ok(e, e.either(e.ne(p[kind], 0), e.ne(p[where], NONE)))  # NATIVE-VALUE-LOCATION


def _copy_edge_fn(tables):
    """``copy_edge``: the edge's arguments into the target block's machine parameters (``at``: the edge record)."""
    def build(e: E):
        p = e.p
        e.var("ce_target", e.ld(e.add(p["edge"], 0)))
        e.var("ce_n", e.ld(e.add(p["edge"], 1)))
        e.var("ce_args", e.ld(e.add(p["edge"], 2)))
        e.var("ce_moves", e.alloc(3 * MOVE_CAP))
        e.var("ce_delayed", e.alloc(3 * MOVE_CAP))
        _ok(e, e.both(e.ne(p["ce_moves"], NONE), e.ne(p["ce_delayed"], NONE)))
        e.var("ce_nm", 0)
        e.var("ce_nd", 0)
        for stage in (0, 1):
            def pair(stage=stage):
                e.var("ce_arg", e.ld(e.add(p["ce_args"], p["ce_k"])))
                e.var("ce_dest", e.ld(e.add(_f(e, p["ce_target"], B_INPUTS), p["ce_k"])))

                def machine():
                    # The destination's index among the target's machine parameters.
                    e.var("ce_index", 0)
                    e.for_("ce_q", 0, p["ce_k"], lambda: e.if_(e.ne(_t(e, S_WIDTH, e.ld(e.add(_f(e, p["ce_target"], B_INPUTS), p["ce_q"]))), 0),
                                                               lambda: e.set("ce_index", e.add(p["ce_index"], 1))))
                    _location(e, p["ce_arg"], "ce_kind", "ce_where")
                    if stage == 0:
                        def stacked():
                            e.var("ce_off", e.add(_s(e, S_EDGEB), e.mul(e.sub(p["ce_index"], len(ALLOCATABLE)), 8)))
                            e.if_(e.ne(p["ce_kind"], 0), lambda: _store(e, p["ce_where"], p["ce_off"], _width_bytes(e, p["ce_dest"])),
                                  lambda: e.if_(e.ne(p["ce_where"], p["ce_off"]), lambda: (
                                      _load(e, SCRATCH, p["ce_where"], _width_bytes(e, p["ce_arg"])), _store(e, SCRATCH, p["ce_off"], _width_bytes(e, p["ce_dest"])))))

                        e.if_(e.le(len(ALLOCATABLE), p["ce_index"]), stacked)
                    else:
                        def registered():
                            e.var("ce_reg", _select(e, p["ce_index"], ALLOCATABLE))

                            def move():
                                _ok(e, e.lt(p["ce_nm"], MOVE_CAP))
                                e.var("ce_m", e.add(p["ce_moves"], e.mul(p["ce_nm"], 3)))
                                for field, value in enumerate((p["ce_reg"], p["ce_where"], _t(e, S_WIDTH, p["ce_dest"]))):
                                    e.st(e.add(p["ce_m"], field), value)
                                e.set("ce_nm", e.add(p["ce_nm"], 1))

                            def delay():
                                _ok(e, e.lt(p["ce_nd"], MOVE_CAP))
                                e.var("ce_m", e.add(p["ce_delayed"], e.mul(p["ce_nd"], 3)))
                                for field, value in enumerate((p["ce_reg"], p["ce_where"], _width_bytes(e, p["ce_dest"]))):
                                    e.st(e.add(p["ce_m"], field), value)
                                e.set("ce_nd", e.add(p["ce_nd"], 1))

                            e.if_(e.ne(p["ce_kind"], 0), move, delay)

                        e.if_(e.lt(p["ce_index"], len(ALLOCATABLE)), registered)

                e.if_(e.both(e.ne(_t(e, S_WIDTH, p["ce_arg"]), 0), e.ne(_t(e, S_WIDTH, p["ce_dest"]), 0)), machine)

            e.for_("ce_k", 0, p["ce_n"], pair)
        _call(e, "lg_moves", p["ce_moves"], p["ce_nm"])
        e.for_("ce_q", 0, p["ce_nd"], lambda: (e.var("ce_dl", e.add(p["ce_delayed"], e.mul(p["ce_q"], 3))),
                                                 _load(e, e.ld(p["ce_dl"]), e.ld(e.add(p["ce_dl"], 1)), e.ld(e.add(p["ce_dl"], 2)))))
        e.give(1)
    return _function(("edge",), build, tables)


def _select(e: E, index, items):
    value = e.c(items[0])
    for k, item in enumerate(items[1:], 1):
        value = e.sel(e.eq(index, k), item, value)
    return value


def _call_node_fn(tables):
    """A direct call (``prepare_call``, the call, the killed registers, the released slots, the result in rax)."""
    def build(e: E):
        p = e.p
        node, position = p["node"], p["position"]
        e.var("cn_n", 0)  # machine operands
        e.var("cn_ops", e.alloc(8))
        _ok(e, e.ne(p["cn_ops"], NONE))

        def operand():
            e.var("cn_o", _operand(e, node, p["cn_k"]))
            e.if_(e.ne(_t(e, S_WIDTH, p["cn_o"]), 0), lambda: (_ok(e, e.lt(p["cn_n"], 8)), e.st(e.add(p["cn_ops"], p["cn_n"]), p["cn_o"]),
                                                               e.set("cn_n", e.add(p["cn_n"], 1))))

        e.for_("cn_k", 0, _f(e, node, N_NOPS), operand)
        e.for_("cn_k", 0, p["cn_n"], lambda: _ensure(e, e.ld(e.add(p["cn_ops"], p["cn_k"])), position))
        # Every value live after the call: kept, and spilled if in a register (in position order).
        e.var("cn_live", e.alloc(e.add(_g(e, G_VCOUNT), 1)))
        _ok(e, e.ne(p["cn_live"], NONE))
        e.for_("cn_v", 0, _g(e, G_VCOUNT), lambda: e.st(e.add(p["cn_live"], p["cn_v"]), e.flag(e.both(
            e.either(e.ne(_t(e, S_REG, p["cn_v"]), NONE), e.ne(_t(e, S_SPILL, p["cn_v"]), NONE)),
            e.ne(_t(e, S_LAST, p["cn_v"]), NONE), e.lt(position, _t(e, S_LAST, p["cn_v"]))))))
        # Spilled in their positions' order (``sorted(live_after)``).
        e.var("cn_last", NONE)

        def spill_next():
            e.var("cn_best", NONE)
            e.var("cn_bp", 0)
            e.for_("cn_v", 0, _g(e, G_VCOUNT), lambda: e.if_(e.both(e.ne(e.ld(e.add(p["cn_live"], p["cn_v"])), 0), e.ne(_t(e, S_REG, p["cn_v"]), NONE),
                                                                     e.either(e.eq(p["cn_last"], NONE), e.lt(p["cn_last"], _vf(e, G_VPOS, p["cn_v"]))),
                                                                     e.either(e.eq(p["cn_best"], NONE), e.lt(_vf(e, G_VPOS, p["cn_v"]), p["cn_bp"]))),
                                                              lambda: (e.set("cn_best", p["cn_v"]), e.set("cn_bp", _vf(e, G_VPOS, p["cn_v"])))))
            e.if_(e.ne(p["cn_best"], NONE), lambda: (_call(e, "lg_spill", p["cn_best"], 1), e.set("cn_last", p["cn_bp"])))
            return p["cn_best"]

        e.var("cn_more", 1)
        e.while_(lambda: e.ne(p["cn_more"], 0), lambda: e.set("cn_more", e.flag(e.ne(spill_next(), NONE))))
        e.var("cn_moves", e.alloc(3 * MOVE_CAP))
        _ok(e, e.ne(p["cn_moves"], NONE))
        e.var("cn_nm", 0)

        def register_moves():
            e.var("cn_o", e.ld(e.add(p["cn_ops"], p["cn_k"])))
            e.if_(e.ne(_t(e, S_REG, p["cn_o"]), NONE), lambda: (
                e.var("cn_m", e.add(p["cn_moves"], e.mul(p["cn_nm"], 3))),
                e.st(p["cn_m"], _select(e, p["cn_k"], ARGUMENT_REGISTERS)), e.st(e.add(p["cn_m"], 1), _t(e, S_REG, p["cn_o"])),
                e.st(e.add(p["cn_m"], 2), _t(e, S_WIDTH, p["cn_o"])), e.set("cn_nm", e.add(p["cn_nm"], 1))))

        e.for_("cn_k", 0, e.sel(e.lt(4, p["cn_n"]), 4, p["cn_n"]), register_moves)
        _call(e, "lg_moves", p["cn_moves"], p["cn_nm"])
        e.for_("cn_k", 0, e.sel(e.lt(4, p["cn_n"]), 4, p["cn_n"]), lambda: (
            e.var("cn_o", e.ld(e.add(p["cn_ops"], p["cn_k"]))),
            e.if_(e.eq(_t(e, S_REG, p["cn_o"]), NONE), lambda: _load(e, _select(e, p["cn_k"], ARGUMENT_REGISTERS), _t(e, S_SPILL, p["cn_o"]),
                                                                    _width_bytes(e, p["cn_o"])))))
        _callee_object(e, node, "cn_callee")
        _ok(e, e.ne(p["cn_callee"], NONE))

        def call():
            _bx(e, 0xE8, 1, True)
            _real(e, lambda: _record_call(e, p["cn_callee"], 0))
            _bx(e, 0, 4, True)

        call()
        # Every register is killed; slots of values not live after the call are freed.
        e.for_("cn_v", 0, _g(e, G_VCOUNT), lambda: e.if_(e.ne(_t(e, S_REG, p["cn_v"]), NONE), lambda: _unbind(e, p["cn_v"])))
        e.for_("cn_v", 0, _g(e, G_VCOUNT), lambda: e.if_(e.both(e.ne(_t(e, S_SPID, p["cn_v"]), NONE), e.eq(e.ld(e.add(p["cn_live"], p["cn_v"])), 0)),
                                                          lambda: _call(e, "lg_release", p["cn_v"])))
        e.var("cn_res", NONE)
        e.for_("cn_k", 0, _f(e, node, N_NRES), lambda: e.if_(e.both(e.eq(p["cn_res"], NONE), e.ne(_t(e, S_WIDTH, _output(e, node, p["cn_k"])), 0)),
                                                             lambda: e.set("cn_res", _output(e, node, p["cn_k"]))))
        e.if_(e.ne(p["cn_res"], NONE), lambda: _call(e, "lg_define", p["cn_res"], RAX))
        e.give(1)
    return _function(("node", "position"), build, tables)


# -- one block ---------------------------------------------------------------------------------------------------

def _uses(e: E, b):
    """``block_uses``: each machine value's use positions in block ``b`` (node indices, the terminator as the node
    count), and ``last_use``."""
    p = e.p
    n = _g(e, G_VCOUNT)
    e.for_("us_v", 0, n, lambda: (_set_t(e, S_UCOUNT, p["us_v"], 0), _set_t(e, S_LAST, p["us_v"], NONE)))

    def each_use(visit):
        def node():
            e.var("us_n", _node_at(e, b, p["us_m"]))
            e.for_("us_k", 0, _f(e, p["us_n"], N_NOPS), lambda: visit(_operand(e, p["us_n"], p["us_k"]), p["us_m"]))

        e.for_("us_m", 0, _f(e, b, B_NNODES), node)
        e.var("us_end", _f(e, b, B_NNODES))
        e.for_("us_k", 0, _f(e, b, B_NVALUES), lambda: visit(e.ld(e.add(_f(e, b, B_VALUES), p["us_k"])), p["us_end"]))

        def edge():
            e.var("us_at", e.add(_f(e, b, B_EDGES), e.mul(p["us_q"], EDGE)))
            e.for_("us_k", 0, _f(e, p["us_at"], 1), lambda: visit(e.ld(e.add(_f(e, p["us_at"], 2), p["us_k"])), p["us_end"]))

        e.for_("us_q", 0, _f(e, b, B_NEDGES), edge)

    def count(value, position):
        e.var("us_cv", value)
        e.if_(e.ne(_t(e, S_WIDTH, p["us_cv"]), 0), lambda: _set_t(e, S_UCOUNT, p["us_cv"], e.add(_t(e, S_UCOUNT, p["us_cv"]), 1)))

    each_use(count)
    e.var("us_total", 0)
    e.for_("us_v", 0, n, lambda: (_set_t(e, S_UAT, p["us_v"], p["us_total"]), e.set("us_total", e.add(p["us_total"], _t(e, S_UCOUNT, p["us_v"]))),
                                  _set_t(e, S_UCOUNT, p["us_v"], 0)))
    e.var("us_list", e.alloc(e.add(p["us_total"], 1)))
    _ok(e, e.ne(p["us_list"], NONE))
    _set_s(e, S_ULIST, p["us_list"])

    def fill(value, position):
        e.var("us_fv", value)

        def put():
            e.st(e.add(p["us_list"], e.add(_t(e, S_UAT, p["us_fv"]), _t(e, S_UCOUNT, p["us_fv"]))), position)
            _set_t(e, S_UCOUNT, p["us_fv"], e.add(_t(e, S_UCOUNT, p["us_fv"]), 1))
            _set_t(e, S_LAST, p["us_fv"], position)

        e.if_(e.ne(_t(e, S_WIDTH, p["us_fv"]), 0), put)

    each_use(fill)


def _arithmetic(e: E, node, op, result, m):
    """``add``/``sub``/``mul`` of two machine values (32 or 64 bits wide; the bootstrap fails otherwise)."""
    p = e.p
    e.var("ar_width", _t(e, S_WIDTH, result))

    def bits():
        import xax_selfhost_diagnostics as D
        from xax_selfhost_general_emit import reject_at

        def write():
            D.text(e, "XAX.NATIVE.BITS")
            D.text(e, "x86_64")
            D.text(e, "NATIVE-BITS-SUPPORTED")
            D.put(e, D.T_LIST)
            D.put(e, 2)
            D.integer(e, 32)
            D.integer(e, 64)
            D.integer(e, p["ar_width"])

        reject_at(e, write)

    e.var("ar_left", _operand(e, node, 0))
    e.var("ar_right", _operand(e, node, 1))
    e.var("ar_lr", _ensure(e, p["ar_left"], m))
    e.var("ar_rr", _ensure(e, p["ar_right"], m, e.sel(e.ne(p["ar_right"], p["ar_left"]), p["ar_left"], NONE)))
    e.var("ar_dst", NONE)
    e.var("ar_src", NONE)
    commutes = e.either(e.eq(op, _op(Operation.ADD_WRAP)), e.eq(op, _op(Operation.MUL_WRAP)))
    e.if_(e.eq(_t(e, S_LAST, p["ar_left"]), m), lambda: (e.set("ar_dst", p["ar_lr"]), e.set("ar_src", p["ar_rr"])), lambda: e.if_(
        e.both(e.eq(_t(e, S_LAST, p["ar_right"]), m), commutes), lambda: (e.set("ar_dst", p["ar_rr"]), e.set("ar_src", p["ar_lr"])), lambda: (
            e.set("ar_dst", _acquire(e, m, p["ar_left"], p["ar_right"])), e.set("ar_src", p["ar_rr"]),
            _call(e, "mov", p["ar_dst"], p["ar_lr"], p["ar_width"]))))
    e.if_(e.not_(e.either(e.eq(p["ar_width"], 32), e.eq(p["ar_width"], 64))), bits)
    _call(e, "arith", op, p["ar_dst"], p["ar_src"], p["ar_width"])
    e.if_(e.eq(_t(e, S_LAST, p["ar_left"]), m), lambda: _call(e, "lg_release", p["ar_left"]))
    e.if_(e.both(e.ne(p["ar_right"], p["ar_left"]), e.eq(_t(e, S_LAST, p["ar_right"]), m)), lambda: _call(e, "lg_release", p["ar_right"]))
    _call(e, "lg_define", result, p["ar_dst"])


def _constant(e: E, node, result, m):
    """A bits constant (at most 64 bits; its little-endian value bytes) into a fresh register: ``mov r64, imm64``."""
    from xax_selfhost_views_backend import G_PAY, _at, _payload_uleb, _reference

    p = e.p
    e.var("cs_obj", _reference(e, _f(e, node, N_GRAPH), e.rd(e.sub(_f(e, node, N_OPSAT), 1))))
    _ok(e, e.ne(p["cs_obj"], NONE))
    e.var("cs_at", _at(e, G_PAY, p["cs_obj"]))
    _payload_uleb(e, "cs_at")  # the type
    e.var("cs_len", _payload_uleb(e, "cs_at"))
    _ok(e, e.le(p["cs_len"], 8))
    e.var("cs_value", 0)
    e.var("cs_weight", 1)
    e.for_("cs_k", 0, p["cs_len"], lambda: (e.set("cs_value", e.add(p["cs_value"], e.mul(e.rd(e.add(p["cs_at"], p["cs_k"])), p["cs_weight"]))),
                                            e.set("cs_weight", e.mul(p["cs_weight"], 256))))
    e.var("cs_reg", _acquire(e, m))
    _movabs(e, p["cs_reg"], p["cs_value"])
    _call(e, "lg_define", result, p["cs_reg"])


def _block_fn(tables):
    """``lower_block(bi)``: the block's code (in the real run), and its dynamic spill count."""
    from xax_selfhost_general_emit import E_F

    def build(e: E):
        p = e.p
        e.var("lb_b", _block_at(e, p["bi"]))
        b = p["lb_b"]
        n = _g(e, G_VCOUNT)
        _uses(e, b)
        # The block's state: no register bound, homes of other blocks' values as their slots, no dynamic slot.
        e.for_("lb_v", 0, n, lambda: (_set_t(e, S_REG, p["lb_v"], NONE), _set_t(e, S_SPID, p["lb_v"], NONE), _set_t(
            e, S_SPILL, p["lb_v"], e.sel(e.both(e.ne(_t(e, S_HOME, p["lb_v"]), NONE), e.ne(_block_of(e, p["lb_v"]), p["bi"])), _t(e, S_HOME, p["lb_v"]), NONE))))
        e.for_("lb_r", 0, 16, lambda: e.st(e.add(_s(e, S_VREG), p["lb_r"]), NONE))
        e.for_("lb_q", 0, _s(e, S_NFREE), lambda: e.st(e.add(_s(e, S_FREE), p["lb_q"]), 0))
        _set_s(e, S_NEXT, 0)
        _set_s(e, S_MAX, 0)
        _real(e, lambda: _label(e, p["bi"]))
        # Machine parameters: the allocatable registers, then the edge spill slots.
        e.var("lb_i", 0)

        def parameter():
            e.var("lb_pv", e.ld(e.add(_f(e, b, B_INPUTS), p["lb_k"])))

            def machine():
                e.if_(e.lt(p["lb_i"], len(ALLOCATABLE)), lambda: _call(e, "lg_bind", p["lb_pv"], _select(e, p["lb_i"], ALLOCATABLE)),
                      lambda: _set_t(e, S_SPILL, p["lb_pv"], e.add(_s(e, S_EDGEB), e.mul(e.sub(p["lb_i"], len(ALLOCATABLE)), 8))))
                e.set("lb_i", e.add(p["lb_i"], 1))

            e.if_(e.ne(_t(e, S_WIDTH, p["lb_pv"]), 0), machine)

        e.for_("lb_k", 0, _f(e, b, B_NP), parameter)

        def homed():
            e.var("lb_pv", e.ld(e.add(_f(e, b, B_INPUTS), p["lb_k"])))

            def machine():
                e.var("lb_home", _t(e, S_HOME, p["lb_pv"]))

                def home():
                    e.var("lb_reg", _t(e, S_REG, p["lb_pv"]))
                    e.if_(e.ne(p["lb_reg"], NONE), lambda: _store(e, p["lb_reg"], p["lb_home"], _width_bytes(e, p["lb_pv"])), lambda: (
                        _load(e, SCRATCH, _t(e, S_SPILL, p["lb_pv"]), _width_bytes(e, p["lb_pv"])), _store(e, SCRATCH, p["lb_home"], _width_bytes(e, p["lb_pv"]))))
                    _set_t(e, S_SPILL, p["lb_pv"], p["lb_home"])

                e.if_(e.ne(p["lb_home"], NONE), home)
                e.if_(e.eq(_t(e, S_LAST, p["lb_pv"]), NONE), lambda: _call(e, "lg_release", p["lb_pv"]))

            e.if_(e.ne(_t(e, S_WIDTH, p["lb_pv"]), 0), machine)

        e.for_("lb_k", 0, _f(e, b, B_NP), homed)
        _call(e, "lg_nodes", p["bi"])
        _call(e, "lg_term", p["bi"])
        e.give(_s(e, S_MAX))
    return _function(("bi",), build, tables)


def _nodes_fn(tables):
    """The block's nodes, each with its semantic range."""
    def build(e: E):
        p = e.p
        e.var("ln_b", _block_at(e, p["bi"]))

        def node():
            e.var("ln_n", _node_at(e, p["ln_b"], p["ln_m"]))
            e.var("ln_op", _eop(e, p["ln_n"]))
            e.var("ln_res", e.sel(e.ne(_f(e, p["ln_n"], N_NRES), 0), _output(e, p["ln_n"], 0), NONE))
            e.var("ln_start", _ra(e, E_CLEN))
            arithmetic = (_op(Operation.ADD_WRAP), _op(Operation.SUB_WRAP), _op(Operation.MUL_WRAP))
            e.if_(e.either(*(e.eq(p["ln_op"], op) for op in arithmetic)), lambda: _arithmetic(e, p["ln_n"], p["ln_op"], p["ln_res"], p["ln_m"]))
            e.if_(e.eq(p["ln_op"], _op(Operation.CONSTANT)), lambda: _constant(e, p["ln_n"], p["ln_res"], p["ln_m"]))

            def direct():
                _callee_object(e, p["ln_n"], "ln_callee")
                _ok(e, e.ne(p["ln_callee"], NONE))
                e.if_(e.eq(_call(e, "erased", p["ln_callee"]), 0), lambda: _call(e, "lg_call", p["ln_n"], p["ln_m"]))

            e.if_(e.eq(p["ln_op"], _op(Operation.CALL_DIRECT)), direct)

            def record():
                from xax_selfhost_general_emit import _se

                e.var("ln_k", _ra(e, E_NRANGES))
                e.var("ln_at", e.add(_ra(e, E_RANGES), e.mul(p["ln_k"], 4)))
                for field, value in enumerate((p["bi"], p["ln_m"], p["ln_start"], _ra(e, E_CLEN))):
                    e.st(e.add(p["ln_at"], field), value)
                _set_ra(e, E_NRANGES, e.add(p["ln_k"], 1))

            e.if_(e.lt(p["ln_start"], _ra(e, E_CLEN)), record)

        e.for_("ln_m", 0, _f(e, p["ln_b"], B_NNODES), node)
        e.give(1)
    return _function(("bi",), build, tables)


def _term_fn(tables):
    """The block's terminator: the return value into rax, or the edges' copies and jumps."""
    def build(e: E):
        p = e.p
        e.var("lt_b", _block_at(e, p["bi"]))
        b = p["lt_b"]
        e.var("lt_kind", _f(e, b, B_KIND))
        e.var("lt_pos", _f(e, b, B_NNODES))

        def returned():
            e.var("lt_v", NONE)
            e.for_("lt_k", 0, _f(e, b, B_NVALUES), lambda: e.if_(e.both(e.eq(p["lt_v"], NONE), e.ne(_t(e, S_WIDTH, e.ld(e.add(_f(e, b, B_VALUES), p["lt_k"]))), 0)),
                                                                lambda: e.set("lt_v", e.ld(e.add(_f(e, b, B_VALUES), p["lt_k"])))))

            def value():
                e.var("lt_reg", _t(e, S_REG, p["lt_v"]))
                e.if_(e.ne(p["lt_reg"], NONE), lambda: e.if_(e.ne(p["lt_reg"], RAX), lambda: _call(e, "mov", RAX, p["lt_reg"], _t(e, S_WIDTH, p["lt_v"]))),
                      lambda: _load(e, RAX, _t(e, S_SPILL, p["lt_v"]), _width_bytes(e, p["lt_v"])))

            e.if_(e.ne(p["lt_v"], NONE), value, lambda: _bx(e, 0xC031, 2))

        def jump(edge):
            e.var("lt_edge", edge)
            _call(e, "lg_edge", p["lt_edge"])
            _relative(e, 0xE9, _f(e, _f(e, p["lt_edge"], 0), B_POS))

        def branch():
            jump(_f(e, b, B_EDGES))

        def conditional():
            e.var("lt_cond", e.ld(_f(e, b, B_VALUES)))
            e.var("lt_reg", _ensure(e, p["lt_cond"], p["lt_pos"]))
            _test(e, p["lt_reg"], _t(e, S_WIDTH, p["lt_cond"]))
            e.var("lt_false", _new_label(e))
            _real(e, lambda: _relative2(e, 0x840F, p["lt_false"]))
            jump(_f(e, b, B_EDGES))
            _real(e, lambda: _label(e, p["lt_false"]))
            jump(e.add(_f(e, b, B_EDGES), EDGE))

        e.if_(e.eq(p["lt_kind"], RETURN), returned, lambda: e.if_(e.eq(p["lt_kind"], BRANCH), branch, conditional))
        e.give(1)
    return _function(("bi",), build, tables)


# -- the function ------------------------------------------------------------------------------------------------

def _prepare_fn(tables):
    """The state: machine widths, homes of the values used outside their block (in position order), the edge spill
    slots, and the dynamic spill base."""
    def build(e: E):
        p = e.p
        n = _g(e, G_VCOUNT)
        e.var("lp_state", e.alloc(STATE_WORDS))
        _ok(e, e.ne(p["lp_state"], NONE))
        _set_ra(e, L_STATE, p["lp_state"])
        for field in (S_WIDTH, S_HOME, S_REG, S_SPILL, S_SPID, S_LAST, S_UCOUNT, S_UAT):
            e.var("lp_t", e.alloc(e.add(n, 1)))
            _ok(e, e.ne(p["lp_t"], NONE))
            _set_s(e, field, p["lp_t"])
        e.var("lp_vreg", e.alloc(16))
        _ok(e, e.ne(p["lp_vreg"], NONE))
        _set_s(e, S_VREG, p["lp_vreg"])
        _set_s(e, S_NFREE, e.add(n, 1))
        e.var("lp_free", e.alloc(e.add(n, 1)))
        _ok(e, e.ne(p["lp_free"], NONE))
        _set_s(e, S_FREE, p["lp_free"])

        # Widths: bits values of at most 64 bits (a wider one, or a constant of another type, is declined).
        def width():
            e.var("lp_type", _vf(e, G_VTYPE, p["lp_v"]))
            _bits_width(e, p["lp_type"], "lp_w")
            _ok(e, e.le(p["lp_w"], 64))
            _set_t(e, S_WIDTH, p["lp_v"], p["lp_w"])
            _set_t(e, S_HOME, p["lp_v"], NONE)
            e.var("lp_prod", _vf(e, G_VPROD, p["lp_v"]))
            e.if_(e.both(e.ne(p["lp_prod"], NONE), e.eq(_eop(e, e.sel(e.ne(p["lp_prod"], NONE), p["lp_prod"], 0)), _op(Operation.CONSTANT))),
                  lambda: _ok(e, e.ne(p["lp_w"], 0)))

        e.for_("lp_v", 0, n, width)
        # Crossing values: referenced in a block other than their own.
        e.var("lp_cross", e.alloc(e.add(n, 1)))
        _ok(e, e.ne(p["lp_cross"], NONE))
        e.for_("lp_v", 0, n, lambda: e.st(e.add(p["lp_cross"], p["lp_v"]), 0))
        e.var("lp_calls", 0)
        e.var("lp_edges", 0)

        def mark(value, bi):
            e.var("lp_mv", value)
            e.if_(e.both(e.ne(_t(e, S_WIDTH, p["lp_mv"]), 0), e.ne(_block_of(e, p["lp_mv"]), bi)), lambda: e.st(e.add(p["lp_cross"], p["lp_mv"]), 1))

        def block():
            e.var("lp_b", _block_at(e, p["lp_bi"]))

            def node():
                e.var("lp_n", _node_at(e, p["lp_b"], p["lp_m"]))
                e.for_("lp_k", 0, _f(e, p["lp_n"], N_NOPS), lambda: mark(_operand(e, p["lp_n"], p["lp_k"]), p["lp_bi"]))

                def call():
                    _callee_object(e, p["lp_n"], "lp_callee")
                    _ok(e, e.ne(p["lp_callee"], NONE))
                    e.if_(e.eq(_call(e, "erased", p["lp_callee"]), 0), lambda: e.set("lp_calls", 1))

                e.if_(e.eq(_eop(e, p["lp_n"]), _op(Operation.CALL_DIRECT)), call)

            e.for_("lp_m", 0, _f(e, p["lp_b"], B_NNODES), node)
            e.for_("lp_k", 0, _f(e, p["lp_b"], B_NVALUES), lambda: mark(e.ld(e.add(_f(e, p["lp_b"], B_VALUES), p["lp_k"])), p["lp_bi"]))

            def edge():
                e.var("lp_at", e.add(_f(e, p["lp_b"], B_EDGES), e.mul(p["lp_q"], EDGE)))
                e.for_("lp_k", 0, _f(e, p["lp_at"], 1), lambda: mark(e.ld(e.add(_f(e, p["lp_at"], 2), p["lp_k"])), p["lp_bi"]))

            e.for_("lp_q", 0, _f(e, p["lp_b"], B_NEDGES), edge)
            # Machine parameters beyond the allocatable registers take edge spill slots.
            e.var("lp_np", 0)
            e.for_("lp_k", 0, _f(e, p["lp_b"], B_NP), lambda: e.if_(e.ne(_t(e, S_WIDTH, e.ld(e.add(_f(e, p["lp_b"], B_INPUTS), p["lp_k"]))), 0),
                                                                     lambda: e.set("lp_np", e.add(p["lp_np"], 1))))
            e.if_(e.lt(e.add(p["lp_edges"], len(ALLOCATABLE)), p["lp_np"]), lambda: e.set("lp_edges", e.sub(p["lp_np"], len(ALLOCATABLE))))

        e.for_("lp_bi", 0, _g(e, G_BCOUNT), block)
        _set_s(e, S_EDGEB, e.mul(p["lp_calls"], SHADOW))
        e.var("lp_home", e.add(_s(e, S_EDGEB), e.mul(p["lp_edges"], 8)))

        # Homes in position order: every block's parameters (tag 0), then every block's node results (tag 1).
        def assign(value):
            e.var("lp_av", value)
            e.if_(e.ne(e.ld(e.add(p["lp_cross"], p["lp_av"])), 0), lambda: (_set_t(e, S_HOME, p["lp_av"], p["lp_home"]), e.set("lp_home", e.add(p["lp_home"], 8))))

        e.for_("lp_bi", 0, _g(e, G_BCOUNT), lambda: (e.var("lp_b", _block_at(e, p["lp_bi"])), e.for_(
            "lp_k", 0, _f(e, p["lp_b"], B_NP), lambda: assign(e.ld(e.add(_f(e, p["lp_b"], B_INPUTS), p["lp_k"]))))))
        e.for_("lp_bi", 0, _g(e, G_BCOUNT), lambda: (e.var("lp_b", _block_at(e, p["lp_bi"])), e.for_(
            "lp_m", 0, _f(e, p["lp_b"], B_NNODES), lambda: (e.var("lp_n", _node_at(e, p["lp_b"], p["lp_m"])), e.for_(
                "lp_r", 0, _f(e, p["lp_n"], N_NRES), lambda: assign(_output(e, p["lp_n"], p["lp_r"])))))))
        _set_s(e, S_DYN, p["lp_home"])
        e.give(1)
    return _function(("f",), build, tables)


def _legacy_fn(tables):
    """``_compile_register_resident_function`` of the relifted function: the dry run sizes the dynamic spill area, the
    real run emits (the frame, the entry jump, every block, ``add rsp``/``ret`` after a return)."""
    def build(e: E):
        p = e.p
        _call(e, "lg_prepare", p["f"])
        _set_ra(e, E_REAL, 0)
        e.var("lf_spills", 0)
        e.for_("lf_bi", 0, _g(e, G_BCOUNT), lambda: (e.var("lf_s", _call(e, "lg_block", p["lf_bi"])),
                                                     e.if_(e.lt(p["lf_spills"], p["lf_s"]), lambda: e.set("lf_spills", p["lf_s"]))))
        e.var("lf_payload", e.add(_s(e, S_DYN), e.mul(p["lf_spills"], 8)))
        e.var("lf_frame", e.sel(e.ne(p["lf_payload"], 0), e.sub(e.and_(e.add(e.add(p["lf_payload"], 8), 15), (1 << 64) - 16), 8), 0))
        _ok(e, e.lt(p["lf_frame"], 1 << 32))  # ``frame_size.to_bytes(4)``; an access past 2^31 is the encoders' rejection
        _set_ra(e, E_REAL, 1)
        e.if_(e.ne(p["lf_frame"], 0), lambda: (_bx(e, 0xEC8148, 3, True), _bx(e, p["lf_frame"], 4, True)))
        e.var("lf_entry", _f(e, _g(e, G_BENTRY), B_POS))
        e.if_(e.ne(p["lf_entry"], 0), lambda: _relative(e, 0xE9, p["lf_entry"]))

        def block():
            e.var("lf_s", _call(e, "lg_block", p["lf_bi"]))
            _ok(e, e.le(p["lf_s"], p["lf_spills"]))  # NATIVE-SPILL-PLAN-DETERMINISTIC
            e.if_(e.eq(_f(e, _block_at(e, p["lf_bi"]), B_KIND), RETURN), lambda: (
                e.if_(e.ne(p["lf_frame"], 0), lambda: (_bx(e, 0xC48148, 3, True), _bx(e, p["lf_frame"], 4, True))), _bx(e, 0xC3, 1, True)))

        e.for_("lf_bi", 0, _g(e, G_BCOUNT), block)
        e.give(1)
    return _function(("f",), build, tables)


def add_legacy_functions(add, tables):
    add("lg_bind", _bind_fn(tables))
    add("lg_release", _release_fn(tables))
    add("lg_spill", _spill_fn(tables))
    add("lg_define", _define_fn(tables))
    add("lg_acquire", _acquire_fn(tables))
    add("lg_ensure", _ensure_fn(tables))
    add("lg_moves", _moves_fn(tables))
    add("lg_edge", _copy_edge_fn(tables))
    add("lg_call", _call_node_fn(tables))
    add("lg_nodes", _nodes_fn(tables))
    add("lg_term", _term_fn(tables))
    add("lg_block", _block_fn(tables))
    add("lg_prepare", _prepare_fn(tables))
    add("legacy_function", _legacy_fn(tables))
