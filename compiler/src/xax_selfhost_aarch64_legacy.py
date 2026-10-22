"""S15f.4 (ADR-325): the bootstrap's AArch64 legacy register path as XAX functions.

``xax_aarch64._compile_function`` lowers a function on the legacy register path when the target is not a
``_general_aarch64_target`` (the bare-metal load-image and atomic profiles), or when it is one and the function's own
graph is ``_register_path_eligible``.  On that path:

* every bits value of at most 64 bits and every pointer is a machine value; block parameters arrive in the
  allocatable registers (``x0``-``x7``, ``x9``) and then edge spill slots; ``x10`` is the scratch register;
* explicit stack objects come first in the frame (from offset 0), then the link register's slot (a function that
  calls), the edge spill slots, the homes of the values used outside their defining block (written once at their
  definition), and the dynamic spill slots; a stack object's pointer is rematerialized from ``sp`` where it is used;
* per block, values live in registers; one is spilled to a slot (the lowest free one) when no register is free, the
  victim being the value whose next use is furthest (then the highest register);
* a direct call spills every value live after it (keeping the copy), moves the operands to ``x0``-``x7`` (parallel
  moves through ``x10``), and kills every register; the result is in ``x0``;
* a dry run first sizes the dynamic spill area, then the real run emits.

Lowered: ``add``/``sub``/``mul``, integer compares, constants, direct calls, heap views, full loads and stores
through stack or heap pointers, stack objects and address offsets, the resource and effect operations (nothing), and
return/branch/conditional/trap terminators.  Declined (the bootstrap lowers or fails): atomic operations, foreign and
indirect calls, code addresses, target operations, float or aggregate values, a stack pointer used outside its block,
and the encodings the bootstrap fails with an internal error.  The encoders' rejections (arithmetic width, memory
width, stack address and access offsets, the frame size) are the program's diagnostics.

The code, calls and node ranges go to the emission record (``xax_selfhost_aarch64_emit``), so the image is unchanged.
"""

from __future__ import annotations

from xax_compiler import IntCompare, Operation, RESOURCE_EFFECT_OPERATIONS
import xax_selfhost_diagnostics as D
from xax_selfhost_aarch64_emit import X_LEN, X_NCALLS, X_NFIX, X_NRANGES, X_RANGES, RANGE_CAP, _a, _branch, _emit, _label, _set_a
from xax_selfhost_aarch64_frame import F_NEXT_LABEL, _brk, _movimm, _new_label, _record_call
from xax_selfhost_facts import E, NONE, _function
from xax_selfhost_general_frame import _bits_width, _form
from xax_selfhost_general_ranges import _attribute, _block_at, _node_at
from xax_selfhost_general_regalloc import _callee_object, _eop
from xax_selfhost_general_view import (
    B_EDGES, B_INPUTS, B_KIND, B_NEDGES, B_NNODES, B_NP, B_NVALUES, B_PB, B_PFN, B_POS, B_VALUES, BRANCH, CONDITIONAL, EDGE, G_BCOUNT,
    G_BENTRY, G_VCOUNT, G_VPOS, G_VPROD, G_VTYPE, N_GRAPH, N_NOPS, N_NRES, N_OPSAT, POS_BLOCK, RETURN, _f, _operand, _output, _vf,
)
from xax_selfhost_views_backend import _call, _cid_words, _g, _ok

ALLOCATABLE = (0, 1, 2, 3, 4, 5, 6, 7, 9)  # (*argument registers, scratch_registers[0]), deduplicated
ARGUMENTS = (0, 1, 2, 3, 4, 5, 6, 7)
SCRATCH = 10  # scratch_registers[1]
RESULT, LR = 0, 30
BRK_NULL_HEAP = 3
L_STATE = 130  # ``_a`` slot (after the frame path's): the legacy lowering's state record
# State words: per-value tables (each VCOUNT words), the register map, the spill slot flags, and scalars.
(S_WIDTH, S_HOME, S_REG, S_SPILL, S_SPID, S_LAST, S_UCOUNT, S_UAT, S_PTR, S_LIVE, S_ULIST, S_VREG, S_FREE, S_NEXT, S_MAX, S_DYN,
 S_EDGEB, S_P1, S_P2, S_NFREE, S_LINK, S_HASCALL, S_FRAME, S_GRAPH) = range(24)
TABLES = (S_WIDTH, S_HOME, S_REG, S_SPILL, S_SPID, S_LAST, S_UCOUNT, S_UAT, S_PTR, S_LIVE)
STATE_WORDS = 24
MOVE_CAP = 16
ARITHMETIC = {Operation.ADD_WRAP: (0x0B000000, 0x8B000000), Operation.SUB_WRAP: (0x4B000000, 0xCB000000),
              Operation.MUL_WRAP: (0x1B007C00, 0x9B007C00)}
CONDITION = {IntCompare.EQ: 0, IntCompare.NE: 1, IntCompare.UGE: 2, IntCompare.ULT: 3, IntCompare.UGT: 8, IntCompare.ULE: 9,
             IntCompare.SGE: 10, IntCompare.SLT: 11, IntCompare.SGT: 12, IntCompare.SLE: 13}
EXACT = {1: (0x39400000, 0x39000000), 2: (0x79400000, 0x79000000), 4: (0xB9400000, 0xB9000000), 8: (0xF9400000, 0xF9000000)}
QUIET = tuple(sorted(int(op) for op in (Operation.STACK_END, *RESOURCE_EFFECT_OPERATIONS)))
LOWERED = tuple(sorted(int(op) for op in (
    Operation.ADD_WRAP, Operation.SUB_WRAP, Operation.MUL_WRAP, Operation.INT_COMPARE, Operation.CONSTANT, Operation.CALL_DIRECT,
    Operation.HEAP_VIEW, Operation.LOAD_BITS_LE, Operation.STORE_BITS_LE, Operation.STACK_ALLOC, Operation.ADDRESS_OFFSET,
    Operation.STACK_END, *RESOURCE_EFFECT_OPERATIONS)))


def _op(operation) -> int:
    return int(operation)


def _in(e: E, value, items):
    return e.either(*(e.eq(value, item) for item in items))


def _s(e: E, field: int):
    return e.ld(e.add(_a(e, L_STATE), field))


def _set_s(e: E, field: int, value):
    e.st(e.add(_a(e, L_STATE), field), value)


def _t(e: E, table: int, value):
    return e.ld(e.add(_s(e, table), value))


def _set_t(e: E, table: int, value, word):
    e.st(e.add(_s(e, table), value), word)


def _block_of(e: E, value):
    return e.and_(e.udiv(_vf(e, G_VPOS, value), POS_BLOCK), (1 << 22) - 1)


def _select(e: E, index, items):
    value = e.c(items[0])
    for k, item in enumerate(items[1:], 1):
        value = e.sel(e.eq(index, k), item, value)
    return value


def _align(e: E, value, alignment):
    return e.and_(e.add(value, e.sub(alignment, 1)), e.sub(0, alignment))


# -- encodings and their rejections -----------------------------------------------------------------------------------

def _reject(e: E, condition, code: str, rule: str, expected, actual, entity=None):
    """Unless ``condition``: the bootstrap's encoder failure (object ``"aarch64"``, or the graph's CID)."""
    def write():
        D.text(e, code)
        if entity is None:
            D.text(e, "aarch64")
        else:
            D.cid(e, _cid_words(e, entity))
        D.text(e, rule)
        expected()
        actual()

    D.reject_unless(e, condition, write)


def _integers(e: E, values):
    D.put(e, D.T_LIST)
    D.put(e, len(values))
    for value in values:
        D.integer(e, value)


def _ls(e: E, load: bool, register, offset, width):
    """``_load_store``: a 32-bit (``width`` at most 32) or 64-bit access at ``[sp, #offset]`` (a spill slot, a home,
    the link register's slot; never out of range for a frame below 4096 bytes)."""
    e.var("ls_scale", e.sel(e.lt(32, width), 8, 4))
    e.var("ls_off", offset)
    p = e.p
    _ok(e, e.both(e.eq(e.urem(p["ls_off"], p["ls_scale"]), 0), e.lt(e.udiv(p["ls_off"], p["ls_scale"]), 4096)))
    opcode = e.sel(e.eq(p["ls_scale"], 8), 0xF94003E0 if load else 0xF90003E0, 0xB94003E0 if load else 0xB90003E0)
    _emit(e, e.add(e.add(opcode, e.mul(e.udiv(p["ls_off"], p["ls_scale"]), 1 << 10)), register))


def _mov(e: E, destination, source, width):
    """``_move_register``: ``mov wd, ws`` (``width`` at most 32) or ``mov xd, xs``."""
    _emit(e, e.add(e.add(e.sel(e.lt(32, width), 0xAA0003E0, 0x2A0003E0), e.mul(source, 1 << 16)), destination))


def _address(e: E, destination, offset):
    """``_address_from_sp``: ``add xd, sp, #offset`` (AARCH64-STACK-ADDRESS-OFFSET past 4095)."""
    e.var("ad_off", offset)
    p = e.p
    _reject(e, e.lt(p["ad_off"], 4096), "XAX.AARCH64.FRAME", "AARCH64-STACK-ADDRESS-OFFSET", lambda: D.text(e, "< 4096 bytes"),
            lambda: D.integer(e, p["ad_off"]))
    _emit(e, e.add(e.add(0x910003E0, e.mul(p["ad_off"], 1 << 10)), destination))


def _exact(e: E, load: bool, register, offset, size):
    """``_exact_memory_load_store``: an access of ``size`` bytes at ``[sp, #offset]`` (AARCH64-SP-OFFSET unless
    aligned and in range)."""
    e.var("ex_off", offset)
    e.var("ex_size", size)
    p = e.p

    def expected():
        for scale in (1, 2, 4, 8):
            e.if_(e.eq(p["ex_size"], scale), lambda scale=scale: D.text(e, f"aligned {scale}-byte offset < {4096 * scale}"))

    _reject(e, e.both(e.eq(e.urem(p["ex_off"], p["ex_size"]), 0), e.lt(e.udiv(p["ex_off"], p["ex_size"]), 4096)), "XAX.AARCH64.MEMORY_ENCODING",
            "AARCH64-SP-OFFSET", expected, lambda: D.integer(e, p["ex_off"]))
    opcode = _select(e, e.sub(e.sel(e.eq(p["ex_size"], 8), 4, e.sel(e.eq(p["ex_size"], 4), 3, p["ex_size"])), 1),
                     tuple(EXACT[size][0 if load else 1] for size in (1, 2, 4, 8)))
    _emit(e, e.add(e.add(e.add(opcode, e.mul(e.udiv(p["ex_off"], p["ex_size"]), 1 << 10)), 31 << 5), register))


def _based(e: E, load: bool, register, base, size):
    """``_base_access(load, register, base, 0, size)``."""
    opcode = _select(e, e.sub(e.sel(e.eq(size, 8), 4, e.sel(e.eq(size, 4), 3, size)), 1), tuple(EXACT[k][0 if load else 1] for k in (1, 2, 4, 8)))
    _emit(e, e.add(e.add(opcode, e.mul(base, 1 << 5)), register))


def _memory_width(e: E, size):
    """``width not in (8, 16, 32, 64)``: AARCH64-MEMORY-WIDTH on the function's graph."""
    e.var("mw_w", e.mul(size, 8))
    p = e.p
    _reject(e, _in(e, p["mw_w"], (8, 16, 32, 64)), "XAX.AARCH64.MEMORY_WIDTH", "AARCH64-MEMORY-WIDTH", lambda: _integers(e, (8, 16, 32, 64)),
            lambda: D.integer(e, p["mw_w"]), entity=_s(e, S_GRAPH))


# -- the allocator ----------------------------------------------------------------------------------------------------

def _unbind(e: E, value):
    p = e.p
    e.var("ub_r", _t(e, S_REG, value))
    _set_t(e, S_REG, value, NONE)
    e.if_(e.both(e.ne(p["ub_r"], NONE), e.eq(e.ld(e.add(_s(e, S_VREG), e.sel(e.eq(p["ub_r"], NONE), 0, p["ub_r"]))), value)),
          lambda: e.st(e.add(_s(e, S_VREG), p["ub_r"]), NONE))


def _bind_fn(tables):
    """``bind_register(value, register)``."""
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
    """``release_value(value)``: unbound, and its dynamic spill slot freed."""
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
    """A node's result in ``register``: bound, written to its home (then backed by it), released when the block never
    uses it."""
    def build(e: E):
        p = e.p
        _call(e, "a64l_bind", p["value"], p["register"])
        e.var("df_home", _t(e, S_HOME, p["value"]))

        def home():
            _ls(e, False, p["register"], p["df_home"], _t(e, S_WIDTH, p["value"]))
            _set_t(e, S_SPILL, p["value"], p["df_home"])

        e.if_(e.ne(p["df_home"], NONE), home)
        e.if_(e.eq(_t(e, S_LAST, p["value"]), NONE), lambda: _call(e, "a64l_release", p["value"]))
        e.give(1)
    return _function(("value", "register"), build, tables)


def _spill_fn(tables):
    """``spill_value(value, keep)``: its register's content to a slot (its home or an existing slot, else the lowest
    free one)."""
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
            _ls(e, False, p["sp_reg"], _t(e, S_SPILL, p["value"]), _t(e, S_WIDTH, p["value"]))

        e.if_(e.ne(p["sp_reg"], NONE), lambda: e.if_(e.eq(_t(e, S_SPILL, p["value"]), NONE), allocate))
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
    """``acquire_register(position, protected)``: a free allocatable register, else the victim's (spilled), the victim
    being the largest (next use, register) among the bound values not protected (the state's ``S_P1``/``S_P2``)."""
    def build(e: E):
        p = e.p
        e.var("aq_reg", NONE)
        for register in ALLOCATABLE:
            e.if_(e.both(e.eq(p["aq_reg"], NONE), e.eq(e.ld(e.add(_s(e, S_VREG), register)), NONE)), lambda register=register: e.set("aq_reg", register))
        e.if_(e.ne(p["aq_reg"], NONE), lambda: e.give(p["aq_reg"]))
        e.var("aq_v", NONE)
        e.var("aq_kn", 0)
        e.var("aq_kr", 0)
        for register in ALLOCATABLE:
            def candidate(register=register):
                e.var("aq_c", e.ld(e.add(_s(e, S_VREG), register)))

                def consider():
                    _next_use(e, p["aq_c"], p["position"], "aq_n")
                    better = e.either(e.eq(p["aq_v"], NONE), e.lt(p["aq_kn"], p["aq_n"]), e.both(e.eq(p["aq_kn"], p["aq_n"]), e.lt(p["aq_kr"], register)))
                    e.if_(better, lambda: (e.set("aq_v", p["aq_c"]), e.set("aq_kn", p["aq_n"]), e.set("aq_kr", register)))

                e.if_(e.both(e.ne(p["aq_c"], NONE), e.ne(p["aq_c"], _s(e, S_P1)), e.ne(p["aq_c"], _s(e, S_P2))), consider)

            candidate()
        _ok(e, e.ne(p["aq_v"], NONE))  # AARCH64-SPILLABLE-REGISTER (unreachable: at most two values are protected)
        e.var("aq_vr", _t(e, S_REG, p["aq_v"]))
        _call(e, "a64l_spill", p["aq_v"], 0)
        e.give(p["aq_vr"])
    return _function(("position",), build, tables)


def _ensure_fn(tables):
    """``ensure_register(value, position)`` (protected values in the state): its register, a stack object's address
    rematerialized, or a load from its slot."""
    def build(e: E):
        p = e.p
        e.if_(e.ne(_t(e, S_REG, p["value"]), NONE), lambda: e.give(_t(e, S_REG, p["value"])))

        def pointer():
            e.var("en_reg", _call(e, "a64l_acquire", p["position"]))
            _address(e, p["en_reg"], _t(e, S_PTR, p["value"]))
            _call(e, "a64l_bind", p["value"], p["en_reg"])
            e.give(p["en_reg"])

        e.if_(e.ne(_t(e, S_PTR, p["value"]), NONE), pointer)
        e.var("en_off", _t(e, S_SPILL, p["value"]))
        _ok(e, e.ne(p["en_off"], NONE))  # AARCH64-VALUE-LOCATION: the bootstrap's failure
        e.var("en_reg", _call(e, "a64l_acquire", p["position"]))
        _ls(e, True, p["en_reg"], p["en_off"], _t(e, S_WIDTH, p["value"]))
        _call(e, "a64l_bind", p["value"], p["en_reg"])
        e.give(p["en_reg"])
    return _function(("value", "position"), build, tables)


def _protect(e: E, first=NONE, second=NONE):
    _set_s(e, S_P1, first)
    _set_s(e, S_P2, second)


def _ensure(e: E, value, position, first=NONE, second=NONE):
    _protect(e, first, second)
    return _call(e, "a64l_ensure", value, position)


def _acquire(e: E, position, first=NONE, second=NONE):
    _protect(e, first, second)
    return _call(e, "a64l_acquire", position)


def _release_dead(e: E, value, position):
    e.var("rd_v", value)
    p = e.p
    e.if_(e.both(e.ne(_t(e, S_WIDTH, p["rd_v"]), 0), e.eq(_t(e, S_LAST, p["rd_v"]), position)), lambda: _call(e, "a64l_release", p["rd_v"]))


# -- moves, edges, calls ----------------------------------------------------------------------------------------------

def _moves_fn(tables):
    """``emit_parallel_register_moves`` of the ``count`` (destination, source, width) triples at ``at``: a move whose
    destination no pending move reads first, else the smallest pending triple's source through ``x10``."""
    def build(e: E):
        p = e.p
        e.var("pm_n", 0)
        e.for_("pm_q", 0, p["count"], lambda: (
            e.var("pm_t", e.add(p["at"], e.mul(p["pm_q"], 3))),
            e.if_(e.ne(e.ld(p["pm_t"]), e.ld(e.add(p["pm_t"], 1))), lambda: (
                e.var("pm_d", e.add(p["at"], e.mul(p["pm_n"], 3))),
                e.st(p["pm_d"], e.ld(p["pm_t"])), e.st(e.add(p["pm_d"], 1), e.ld(e.add(p["pm_t"], 1))), e.st(e.add(p["pm_d"], 2), e.ld(e.add(p["pm_t"], 2))),
                e.set("pm_n", e.add(p["pm_n"], 1))))))

        def field(index, k):
            return e.ld(e.add(e.add(p["at"], e.mul(index, 3)), k))

        def step():
            e.var("pm_safe", NONE)

            def check():
                e.var("pm_dst", field(p["pm_i"], 0))
                e.var("pm_read", 0)
                e.for_("pm_j", 0, p["pm_n"], lambda: e.if_(e.eq(field(p["pm_j"], 1), p["pm_dst"]), lambda: e.set("pm_read", 1)))
                e.if_(e.both(e.eq(p["pm_safe"], NONE), e.eq(p["pm_read"], 0)), lambda: e.set("pm_safe", p["pm_i"]))

            e.for_("pm_i", 0, p["pm_n"], check)

            def safe():
                _mov(e, field(p["pm_safe"], 0), field(p["pm_safe"], 1), field(p["pm_safe"], 2))
                e.var("pm_k", p["pm_safe"])
                e.while_(lambda: e.lt(e.add(p["pm_k"], 1), p["pm_n"]), lambda: (
                    e.for_("pm_f", 0, 3, lambda: e.st(e.add(e.add(p["at"], e.mul(p["pm_k"], 3)), p["pm_f"]), field(e.add(p["pm_k"], 1), p["pm_f"]))),
                    e.set("pm_k", e.add(p["pm_k"], 1))))
                e.set("pm_n", e.sub(p["pm_n"], 1))

            def cycle():
                # The smallest (destination, source, width) triple.
                e.var("pm_m", 0)

                def smaller():
                    less = e.either(e.lt(field(p["pm_i"], 0), field(p["pm_m"], 0)), e.both(e.eq(field(p["pm_i"], 0), field(p["pm_m"], 0)), e.either(
                        e.lt(field(p["pm_i"], 1), field(p["pm_m"], 1)), e.both(e.eq(field(p["pm_i"], 1), field(p["pm_m"], 1)),
                                                                              e.lt(field(p["pm_i"], 2), field(p["pm_m"], 2))))))
                    e.if_(less, lambda: e.set("pm_m", p["pm_i"]))

                e.for_("pm_i", 1, p["pm_n"], smaller)
                e.var("pm_src", field(p["pm_m"], 1))
                _mov(e, SCRATCH, p["pm_src"], field(p["pm_m"], 2))
                e.for_("pm_j", 0, p["pm_n"], lambda: e.if_(e.eq(field(p["pm_j"], 1), p["pm_src"]),
                                                            lambda: e.st(e.add(e.add(p["at"], e.mul(p["pm_j"], 3)), 1), SCRATCH)))

            e.if_(e.ne(p["pm_safe"], NONE), safe, cycle)

        e.while_(lambda: e.lt(0, p["pm_n"]), step)
        e.give(1)
    return _function(("at", "count"), build, tables)


def _location(e: E, value, kind: str, where: str):
    """``source_location(value)``: ``kind`` 1 for a register, 0 for a slot; ``where`` the register or offset (neither:
    the bootstrap's AARCH64-VALUE-LOCATION)."""
    p = e.p
    e.var(kind, e.flag(e.ne(_t(e, S_REG, value), NONE)))
    e.var(where, e.sel(e.ne(p[kind], 0), _t(e, S_REG, value), _t(e, S_SPILL, value)))
    _ok(e, e.either(e.ne(p[kind], 0), e.ne(p[where], NONE)))


def _put_move(e: E, table: str, count: str, triple):
    p = e.p
    _ok(e, e.lt(p[count], MOVE_CAP))
    e.var("pv_at", e.add(p[table], e.mul(p[count], 3)))
    for k, value in enumerate(triple):
        e.st(e.add(p["pv_at"], k), value)
    e.set(count, e.add(p[count], 1))


def _copy_edge_fn(tables):
    """``copy_edge``: the edge's machine arguments into the target block's machine parameters: spilled destinations
    first, then the register destinations by parallel moves, then the ones loaded from slots."""
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
                    e.var("ce_index", 0)
                    e.for_("ce_q", 0, p["ce_k"], lambda: e.if_(e.ne(_t(e, S_WIDTH, e.ld(e.add(_f(e, p["ce_target"], B_INPUTS), p["ce_q"]))), 0),
                                                               lambda: e.set("ce_index", e.add(p["ce_index"], 1))))
                    if stage == 0:
                        def stacked():
                            _location(e, p["ce_arg"], "ce_kind", "ce_where")
                            e.var("ce_off", e.add(_s(e, S_EDGEB), e.mul(e.sub(p["ce_index"], len(ALLOCATABLE)), 8)))
                            e.if_(e.ne(p["ce_kind"], 0), lambda: _ls(e, False, p["ce_where"], p["ce_off"], _t(e, S_WIDTH, p["ce_dest"])),
                                  lambda: e.if_(e.ne(p["ce_where"], p["ce_off"]), lambda: (
                                      _ls(e, True, SCRATCH, p["ce_where"], _t(e, S_WIDTH, p["ce_arg"])),
                                      _ls(e, False, SCRATCH, p["ce_off"], _t(e, S_WIDTH, p["ce_dest"])))))

                        e.if_(e.le(len(ALLOCATABLE), p["ce_index"]), stacked)
                    else:
                        def registered():
                            _location(e, p["ce_arg"], "ce_kind", "ce_where")
                            e.var("ce_reg", _select(e, p["ce_index"], ALLOCATABLE))
                            triple = (p["ce_reg"], p["ce_where"], _t(e, S_WIDTH, p["ce_dest"]))
                            e.if_(e.ne(p["ce_kind"], 0), lambda: _put_move(e, "ce_moves", "ce_nm", triple), lambda: _put_move(e, "ce_delayed", "ce_nd", triple))

                        e.if_(e.lt(p["ce_index"], len(ALLOCATABLE)), registered)

                e.if_(e.both(e.ne(_t(e, S_WIDTH, p["ce_arg"]), 0), e.ne(_t(e, S_WIDTH, p["ce_dest"]), 0)), machine)

            e.for_("ce_k", 0, p["ce_n"], pair)
        _call(e, "a64l_moves", p["ce_moves"], p["ce_nm"])
        e.for_("ce_q", 0, p["ce_nd"], lambda: (e.var("ce_dl", e.add(p["ce_delayed"], e.mul(p["ce_q"], 3))),
                                                 _ls(e, True, e.ld(p["ce_dl"]), e.ld(e.add(p["ce_dl"], 1)), e.ld(e.add(p["ce_dl"], 2)))))
        e.give(1)
    return _function(("edge",), build, tables)


def _call_node_fn(tables):
    """A direct call: ``prepare_real_call`` (the operands in registers, every value live after the call spilled with its
    register kept, the operands shuffled to ``x0``-``x7``), ``bl``, then ``finish_real_call`` (every register killed,
    the slots of values not live after it freed, the result in ``x0``)."""
    def build(e: E):
        p = e.p
        node, position = p["node"], p["position"]
        n = _g(e, G_VCOUNT)
        e.var("cn_n", 0)
        e.var("cn_ops", e.alloc(9))
        _ok(e, e.ne(p["cn_ops"], NONE))

        def operand():
            e.var("cn_o", _operand(e, node, p["cn_k"]))
            e.if_(e.ne(_t(e, S_WIDTH, p["cn_o"]), 0), lambda: (_ok(e, e.lt(p["cn_n"], 8)), e.st(e.add(p["cn_ops"], p["cn_n"]), p["cn_o"]),
                                                               e.set("cn_n", e.add(p["cn_n"], 1))))

        e.for_("cn_k", 0, _f(e, node, N_NOPS), operand)
        e.for_("cn_k", 0, p["cn_n"], lambda: _ensure(e, e.ld(e.add(p["cn_ops"], p["cn_k"])), position))
        # Live after the call: in a register or a slot, and used later in the block.
        e.for_("cn_v", 0, n, lambda: _set_t(e, S_LIVE, p["cn_v"], e.flag(e.both(
            e.either(e.ne(_t(e, S_REG, p["cn_v"]), NONE), e.ne(_t(e, S_SPILL, p["cn_v"]), NONE)),
            e.ne(_t(e, S_LAST, p["cn_v"]), NONE), e.lt(position, _t(e, S_LAST, p["cn_v"]))))))
        e.var("cn_last", NONE)

        def spill_next():
            e.var("cn_best", NONE)
            e.var("cn_bp", 0)
            e.for_("cn_v", 0, n, lambda: e.if_(e.both(e.ne(_t(e, S_LIVE, p["cn_v"]), 0), e.ne(_t(e, S_REG, p["cn_v"]), NONE),
                                                      e.either(e.eq(p["cn_last"], NONE), e.lt(p["cn_last"], _vf(e, G_VPOS, p["cn_v"]))),
                                                      e.either(e.eq(p["cn_best"], NONE), e.lt(_vf(e, G_VPOS, p["cn_v"]), p["cn_bp"]))),
                                               lambda: (e.set("cn_best", p["cn_v"]), e.set("cn_bp", _vf(e, G_VPOS, p["cn_v"])))))
            e.if_(e.ne(p["cn_best"], NONE), lambda: (_call(e, "a64l_spill", p["cn_best"], 1), e.set("cn_last", p["cn_bp"])))
            return p["cn_best"]

        e.var("cn_more", 1)
        e.while_(lambda: e.ne(p["cn_more"], 0), lambda: e.set("cn_more", e.flag(e.ne(spill_next(), NONE))))
        e.var("cn_moves", e.alloc(3 * MOVE_CAP))
        _ok(e, e.ne(p["cn_moves"], NONE))
        e.var("cn_nm", 0)
        e.for_("cn_k", 0, p["cn_n"], lambda: (e.var("cn_o", e.ld(e.add(p["cn_ops"], p["cn_k"]))), e.if_(
            e.ne(_t(e, S_REG, p["cn_o"]), NONE), lambda: _put_move(e, "cn_moves", "cn_nm", (_select(e, p["cn_k"], ARGUMENTS), _t(e, S_REG, p["cn_o"]),
                                                                                             _t(e, S_WIDTH, p["cn_o"]))))))
        _call(e, "a64l_moves", p["cn_moves"], p["cn_nm"])
        e.for_("cn_k", 0, p["cn_n"], lambda: (e.var("cn_o", e.ld(e.add(p["cn_ops"], p["cn_k"]))), e.if_(
            e.eq(_t(e, S_REG, p["cn_o"]), NONE), lambda: (_location(e, p["cn_o"], "cn_kind", "cn_where"),
                                                          _ls(e, True, _select(e, p["cn_k"], ARGUMENTS), p["cn_where"], _t(e, S_WIDTH, p["cn_o"]))))))
        _callee_object(e, node, "cn_callee")
        _ok(e, e.ne(p["cn_callee"], NONE))
        _record_call(e, p["cn_callee"])
        e.for_("cn_v", 0, n, lambda: e.if_(e.ne(_t(e, S_REG, p["cn_v"]), NONE), lambda: _unbind(e, p["cn_v"])))
        e.for_("cn_v", 0, n, lambda: e.if_(e.both(e.ne(_t(e, S_SPID, p["cn_v"]), NONE), e.eq(_t(e, S_LIVE, p["cn_v"]), 0)),
                                           lambda: _call(e, "a64l_release", p["cn_v"])))
        e.var("cn_res", NONE)
        e.for_("cn_k", 0, _f(e, node, N_NRES), lambda: e.if_(e.both(e.eq(p["cn_res"], NONE), e.ne(_t(e, S_WIDTH, _output(e, node, p["cn_k"])), 0)),
                                                             lambda: e.set("cn_res", _output(e, node, p["cn_k"]))))
        e.if_(e.ne(p["cn_res"], NONE), lambda: _call(e, "a64l_define", p["cn_res"], RESULT))
        e.give(1)
    return _function(("node", "position"), build, tables)


# -- nodes ------------------------------------------------------------------------------------------------------------

def _arithmetic(e: E, node, op, result, m):
    """``add``/``sub``/``mul``: the destination is a dead operand's register (the left first), else a fresh one."""
    p = e.p
    e.var("ar_width", _t(e, S_WIDTH, result))
    e.var("ar_left", _operand(e, node, 0))
    e.var("ar_right", _operand(e, node, 1))
    e.var("ar_lr", _ensure(e, p["ar_left"], m))
    e.var("ar_rr", _ensure(e, p["ar_right"], m, e.sel(e.ne(p["ar_right"], p["ar_left"]), p["ar_left"], NONE)))
    e.var("ar_dst", NONE)
    e.if_(e.eq(_t(e, S_LAST, p["ar_left"]), m), lambda: e.set("ar_dst", p["ar_lr"]), lambda: e.if_(
        e.eq(_t(e, S_LAST, p["ar_right"]), m), lambda: e.set("ar_dst", p["ar_rr"]), lambda: e.set("ar_dst", _acquire(e, m, p["ar_left"], p["ar_right"]))))
    _reject(e, _in(e, p["ar_width"], (32, 64)), "XAX.AARCH64.BITS", "AARCH64-ARITHMETIC-BITS", lambda: _integers(e, (32, 64)),
            lambda: D.integer(e, p["ar_width"]))
    e.var("ar_base", NONE)
    for operation, (narrow, wide) in ARITHMETIC.items():
        e.if_(e.eq(op, _op(operation)), lambda narrow=narrow, wide=wide: e.set("ar_base", e.sel(e.eq(p["ar_width"], 64), wide, narrow)))
    _emit(e, e.add(e.add(e.add(p["ar_base"], e.mul(p["ar_rr"], 1 << 16)), e.mul(p["ar_lr"], 1 << 5)), p["ar_dst"]))
    _release_dead(e, p["ar_left"], m)
    e.if_(e.ne(p["ar_right"], p["ar_left"]), lambda: _release_dead(e, p["ar_right"], m))
    _call(e, "a64l_define", result, p["ar_dst"])


def _compare(e: E, node, result, m):
    """``cmp`` (64 bits unless the operands are 32 bits wide), then ``cset`` into a fresh register."""
    p = e.p
    e.var("cp_left", _operand(e, node, 0))
    e.var("cp_right", _operand(e, node, 1))
    e.var("cp_width", _t(e, S_WIDTH, p["cp_left"]))
    e.var("cp_lr", _ensure(e, p["cp_left"], m))
    e.var("cp_rr", _ensure(e, p["cp_right"], m, e.sel(e.ne(p["cp_right"], p["cp_left"]), p["cp_left"], NONE)))
    e.var("cp_dst", _acquire(e, m, p["cp_left"], p["cp_right"]))
    _emit(e, e.add(e.add(e.sel(e.eq(p["cp_width"], 32), 0x6B00001F, 0xEB00001F), e.mul(p["cp_rr"], 1 << 16)), e.mul(p["cp_lr"], 1 << 5)))
    e.var("cp_kind", _attribute(e, node, 0))
    e.var("cp_cond", NONE)
    for kind, condition in CONDITION.items():
        e.if_(e.eq(p["cp_kind"], int(kind)), lambda condition=condition: e.set("cp_cond", condition))
    _ok(e, e.ne(p["cp_cond"], NONE))
    _emit(e, e.add(e.add(0x1A9F07E0, e.mul(e.bin(Operation.BIT_XOR, p["cp_cond"], 1), 1 << 12)), p["cp_dst"]))
    _release_dead(e, p["cp_left"], m)
    e.if_(e.ne(p["cp_right"], p["cp_left"]), lambda: _release_dead(e, p["cp_right"], m))
    _call(e, "a64l_define", result, p["cp_dst"])


def _constant(e: E, node, result, m):
    """A bits constant (at most 8 value bytes, little endian) into a fresh register: ``_move_immediate``."""
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
    _movimm(e, p["cs_reg"], p["cs_value"], _t(e, S_WIDTH, result))
    _call(e, "a64l_define", result, p["cs_reg"])


def _heap_view(e: E, node, result, m):
    """The nullable allocation's null trap (``cbnz``, ``brk``), then the view in the raw pointer's register when it
    dies here, else in a copy."""
    p = e.p
    e.var("hv_raw", _operand(e, node, 0))
    e.var("hv_reg", _ensure(e, p["hv_raw"], m))
    e.var("hv_label", _new_label(e, "hv_l"))
    _branch(e, e.add(0xB5000000, p["hv_reg"]), p["hv_label"], 19)
    _emit(e, _brk(e, BRK_NULL_HEAP))
    _label(e, p["hv_label"])

    def dies():
        _call(e, "a64l_release", p["hv_raw"])
        _call(e, "a64l_define", result, p["hv_reg"])

    def copy():
        e.var("hv_dst", _acquire(e, m, p["hv_raw"]))
        _mov(e, p["hv_dst"], p["hv_reg"], 64)
        _call(e, "a64l_define", result, p["hv_dst"])

    e.if_(e.eq(_t(e, S_LAST, p["hv_raw"]), m), dies, copy)


def _store_node(e: E, node, m):
    p = e.p
    e.var("st_size", _attribute(e, node, 0))
    _memory_width(e, p["st_size"])
    e.var("st_ptr", _operand(e, node, 0))
    e.var("st_val", _operand(e, node, 1))
    _ok(e, e.ne(_t(e, S_WIDTH, p["st_val"]), 0))

    def static():
        e.var("st_reg", _ensure(e, p["st_val"], m))
        _exact(e, False, p["st_reg"], _t(e, S_PTR, p["st_ptr"]), p["st_size"])

    def heap():
        e.var("st_base", _ensure(e, p["st_ptr"], m))
        e.var("st_reg", _ensure(e, p["st_val"], m, p["st_ptr"]))
        _based(e, False, p["st_reg"], p["st_base"], p["st_size"])

    e.if_(e.ne(_t(e, S_PTR, p["st_ptr"]), NONE), static, heap)
    _release_dead(e, p["st_ptr"], m)
    e.if_(e.ne(p["st_val"], p["st_ptr"]), lambda: _release_dead(e, p["st_val"], m))


def _load_node(e: E, node, result, m):
    p = e.p
    e.var("lo_size", _attribute(e, node, 0))
    _memory_width(e, p["lo_size"])
    e.var("lo_ptr", _operand(e, node, 0))
    e.var("lo_dst", NONE)

    def static():
        e.set("lo_dst", _acquire(e, m))
        _exact(e, True, p["lo_dst"], _t(e, S_PTR, p["lo_ptr"]), p["lo_size"])

    def heap():
        e.var("lo_base", _ensure(e, p["lo_ptr"], m))
        e.if_(e.eq(_t(e, S_LAST, p["lo_ptr"]), m), lambda: (_call(e, "a64l_release", p["lo_ptr"]), e.set("lo_dst", p["lo_base"])),
              lambda: e.set("lo_dst", _acquire(e, m, p["lo_ptr"])))
        _based(e, True, p["lo_dst"], p["lo_base"], p["lo_size"])

    e.if_(e.ne(_t(e, S_PTR, p["lo_ptr"]), NONE), static, heap)
    _call(e, "a64l_define", result, p["lo_dst"])


def _node_fn(tables):
    """Node ``m`` of block ``bi`` and its semantic range."""
    def build(e: E):
        p = e.p
        e.var("nd_n", _node_at(e, _block_at(e, p["bi"]), p["m"]))
        node, m = p["nd_n"], p["m"]
        e.var("nd_op", _eop(e, node))
        op = p["nd_op"]
        e.var("nd_res", e.sel(e.ne(_f(e, node, N_NRES), 0), _output(e, node, 0), NONE))
        result = p["nd_res"]
        e.var("nd_start", _a(e, X_LEN))
        e.if_(_in(e, op, tuple(_op(item) for item in ARITHMETIC)), lambda: _arithmetic(e, node, op, result, m))
        e.if_(e.eq(op, _op(Operation.INT_COMPARE)), lambda: _compare(e, node, result, m))
        e.if_(e.eq(op, _op(Operation.CONSTANT)), lambda: _constant(e, node, result, m))
        e.if_(e.eq(op, _op(Operation.HEAP_VIEW)), lambda: _heap_view(e, node, result, m))
        e.if_(e.eq(op, _op(Operation.STORE_BITS_LE)), lambda: _store_node(e, node, m))
        e.if_(e.eq(op, _op(Operation.LOAD_BITS_LE)), lambda: _load_node(e, node, result, m))

        def direct():
            _callee_object(e, node, "nd_callee")
            _ok(e, e.ne(p["nd_callee"], NONE))
            e.if_(e.eq(_call(e, "erased", p["nd_callee"]), 0), lambda: _call(e, "a64l_call", node, m))

        e.if_(e.eq(op, _op(Operation.CALL_DIRECT)), direct)

        def ranged():
            e.var("nd_r", _a(e, X_NRANGES))
            _ok(e, e.lt(p["nd_r"], RANGE_CAP))
            e.var("nd_rat", e.add(_a(e, X_RANGES), e.mul(p["nd_r"], 4)))
            for k, word in enumerate((p["bi"], m, p["nd_start"], _a(e, X_LEN))):
                e.st(e.add(p["nd_rat"], k), word)
            _set_a(e, X_NRANGES, e.add(p["nd_r"], 1))

        e.if_(e.lt(p["nd_start"], _a(e, X_LEN)), ranged)
        e.give(1)
    return _function(("bi", "m"), build, tables)


# -- one block --------------------------------------------------------------------------------------------------------

def _uses(e: E, b):
    """``uses_for_block``: each machine value's use positions in block ``b`` (node indices, the terminator as the node
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


def _term_fn(tables):
    """The block's terminator: the return value into ``x0`` and the epilogue, the edges' copies and branches, or the
    trap (its reason in ``x0``, ``brk``)."""
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

                def spilled():
                    _ok(e, e.ne(_t(e, S_SPILL, p["lt_v"]), NONE))  # ``backing_offset[value]``: the bootstrap's KeyError
                    _ls(e, True, RESULT, _t(e, S_SPILL, p["lt_v"]), _t(e, S_WIDTH, p["lt_v"]))

                e.if_(e.ne(p["lt_reg"], NONE), lambda: e.if_(e.ne(p["lt_reg"], RESULT), lambda: _mov(e, RESULT, p["lt_reg"], _t(e, S_WIDTH, p["lt_v"]))),
                      spilled)

            e.if_(e.ne(p["lt_v"], NONE), value)
            e.if_(e.ne(_s(e, S_HASCALL), 0), lambda: _ls(e, True, LR, _s(e, S_LINK), 64))
            e.if_(e.ne(_s(e, S_FRAME), 0), lambda: _emit(e, e.add(0x910003FF, e.mul(_s(e, S_FRAME), 1 << 10))))
            _emit(e, 0xD65F03C0)

        def jump(edge):
            e.var("lt_edge", edge)
            _call(e, "a64l_edge", p["lt_edge"])
            _branch(e, 0x14000000, _f(e, _f(e, p["lt_edge"], 0), B_POS), 26)

        def conditional():
            e.var("lt_cond", e.ld(_f(e, b, B_VALUES)))
            e.var("lt_reg", _ensure(e, p["lt_cond"], p["lt_pos"]))
            e.var("lt_false", _new_label(e, "lt_label"))
            _branch(e, e.add(0x34000000, p["lt_reg"]), p["lt_false"], 19)
            jump(_f(e, b, B_EDGES))
            _label(e, p["lt_false"])
            jump(e.add(_f(e, b, B_EDGES), EDGE))

        def trap():
            e.var("lt_reason", _call(e, "x_trap_reason", _f(e, b, B_PFN), _f(e, b, B_PB)))
            _movimm(e, RESULT, p["lt_reason"], 64)
            _emit(e, _brk(e, p["lt_reason"]))

        e.if_(e.eq(p["lt_kind"], RETURN), returned, lambda: e.if_(e.eq(p["lt_kind"], BRANCH), lambda: jump(_f(e, b, B_EDGES)), lambda: e.if_(
            e.eq(p["lt_kind"], CONDITIONAL), conditional, trap)))
        e.give(1)
    return _function(("bi",), build, tables)


def _block_fn(tables):
    """``lower_block(bi)``: the block's code, and its dynamic spill count."""
    def build(e: E):
        p = e.p
        e.var("lb_b", _block_at(e, p["bi"]))
        b = p["lb_b"]
        n = _g(e, G_VCOUNT)
        _uses(e, b)
        # The block's state: no register bound, homes of other blocks' values as their slots, no dynamic slot.
        e.for_("lb_v", 0, n, lambda: (_set_t(e, S_REG, p["lb_v"], NONE), _set_t(e, S_SPID, p["lb_v"], NONE), _set_t(
            e, S_SPILL, p["lb_v"], e.sel(e.both(e.ne(_t(e, S_HOME, p["lb_v"]), NONE), e.ne(_block_of(e, p["lb_v"]), p["bi"])), _t(e, S_HOME, p["lb_v"]), NONE))))
        e.for_("lb_r", 0, 32, lambda: e.st(e.add(_s(e, S_VREG), p["lb_r"]), NONE))
        e.for_("lb_q", 0, _s(e, S_NFREE), lambda: e.st(e.add(_s(e, S_FREE), p["lb_q"]), 0))
        _set_s(e, S_NEXT, 0)
        _set_s(e, S_MAX, 0)
        _label(e, p["bi"])
        # Machine parameters: the allocatable registers, then the edge spill slots.
        e.var("lb_i", 0)

        def parameter():
            e.var("lb_pv", e.ld(e.add(_f(e, b, B_INPUTS), p["lb_k"])))

            def machine():
                e.if_(e.lt(p["lb_i"], len(ALLOCATABLE)), lambda: _call(e, "a64l_bind", p["lb_pv"], _select(e, p["lb_i"], ALLOCATABLE)),
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
                    e.var("lb_w", _t(e, S_WIDTH, p["lb_pv"]))
                    e.if_(e.ne(p["lb_reg"], NONE), lambda: _ls(e, False, p["lb_reg"], p["lb_home"], p["lb_w"]), lambda: (
                        _ls(e, True, SCRATCH, _t(e, S_SPILL, p["lb_pv"]), p["lb_w"]), _ls(e, False, SCRATCH, p["lb_home"], p["lb_w"])))
                    _set_t(e, S_SPILL, p["lb_pv"], p["lb_home"])

                e.if_(e.ne(p["lb_home"], NONE), home)
                e.if_(e.eq(_t(e, S_LAST, p["lb_pv"]), NONE), lambda: _call(e, "a64l_release", p["lb_pv"]))

            e.if_(e.ne(_t(e, S_WIDTH, p["lb_pv"]), 0), machine)

        e.for_("lb_k", 0, _f(e, b, B_NP), homed)
        e.for_("lb_m", 0, _f(e, b, B_NNODES), lambda: _call(e, "a64l_node", p["bi"], p["lb_m"]))
        _call(e, "a64l_term", p["bi"])
        e.give(_s(e, S_MAX))
    return _function(("bi",), build, tables)


# -- the function -----------------------------------------------------------------------------------------------------

def _prepare_fn(tables):
    """The state: machine widths, stack object offsets, the call flag, homes of the values used outside their block
    (parameters, then node results, in position order), the link register's and the edge spill slots, and the dynamic
    spill base.  What the bootstrap does not lower here declines."""
    def build(e: E):
        p = e.p
        n = _g(e, G_VCOUNT)
        e.var("lp_state", e.alloc(STATE_WORDS))
        _ok(e, e.ne(p["lp_state"], NONE))
        _set_a(e, L_STATE, p["lp_state"])
        for field in TABLES:
            e.var("lp_t", e.alloc(e.add(n, 1)))
            _ok(e, e.ne(p["lp_t"], NONE))
            _set_s(e, field, p["lp_t"])
        e.var("lp_vreg", e.alloc(32))
        _ok(e, e.ne(p["lp_vreg"], NONE))
        _set_s(e, S_VREG, p["lp_vreg"])
        _set_s(e, S_NFREE, e.add(n, 1))
        e.var("lp_free", e.alloc(e.add(n, 1)))
        _ok(e, e.ne(p["lp_free"], NONE))
        _set_s(e, S_FREE, p["lp_free"])
        _set_s(e, S_GRAPH, e.ld(_call(e, "interface", p["f"])))
        _set_s(e, S_FRAME, 0)

        # Widths: a bits value of at most 64 bits or a pointer (64); a float, an aggregate, a sum or a wider bits value
        # declines; anything else is semantic only.
        def width():
            e.var("lp_type", _vf(e, G_VTYPE, p["lp_v"]))
            e.var("lp_form", _form(e, p["lp_type"]))
            _ok(e, e.not_(_in(e, p["lp_form"], (7, 8, 9, 10))))
            _bits_width(e, p["lp_type"], "lp_w")
            _ok(e, e.le(p["lp_w"], 64))
            e.if_(e.eq(p["lp_form"], 2), lambda: e.set("lp_w", 64))
            _set_t(e, S_WIDTH, p["lp_v"], p["lp_w"])
            _set_t(e, S_HOME, p["lp_v"], NONE)
            _set_t(e, S_PTR, p["lp_v"], NONE)
            e.var("lp_prod", _vf(e, G_VPROD, p["lp_v"]))
            e.if_(e.both(e.ne(p["lp_prod"], NONE), e.eq(_eop(e, e.sel(e.ne(p["lp_prod"], NONE), p["lp_prod"], 0)), _op(Operation.CONSTANT))),
                  lambda: _ok(e, e.ne(p["lp_w"], 0)))

        e.for_("lp_v", 0, n, width)
        # Nodes: the operations lowered here; stack object offsets in graph order; calls.
        e.var("lp_cursor", 0)
        e.var("lp_calls", 0)

        def node():
            e.var("lp_n", _node_at(e, p["lp_b"], p["lp_m"]))
            e.var("lp_op", _eop(e, p["lp_n"]))
            _ok(e, _in(e, p["lp_op"], LOWERED))
            e.var("lp_mres", 0)
            e.for_("lp_k", 0, _f(e, p["lp_n"], N_NRES), lambda: e.if_(e.ne(_t(e, S_WIDTH, _output(e, p["lp_n"], p["lp_k"])), 0),
                                                                      lambda: e.set("lp_mres", e.add(p["lp_mres"], 1))))
            _ok(e, e.le(p["lp_mres"], 1))
            e.if_(_in(e, p["lp_op"], QUIET), lambda: _ok(e, e.eq(p["lp_mres"], 0)))

            def stack():
                e.set("lp_cursor", _align(e, p["lp_cursor"], _attribute(e, p["lp_n"], 1)))
                _set_t(e, S_PTR, _output(e, p["lp_n"], 0), p["lp_cursor"])
                e.set("lp_cursor", e.add(p["lp_cursor"], _attribute(e, p["lp_n"], 0)))

            def offset():
                e.var("lp_base", _t(e, S_PTR, _operand(e, p["lp_n"], 0)))
                _ok(e, e.ne(p["lp_base"], NONE))  # ``pointers[node.operands[0]]``: the bootstrap's KeyError
                _set_t(e, S_PTR, _output(e, p["lp_n"], 0), e.add(p["lp_base"], _attribute(e, p["lp_n"], 0)))

            def direct():
                _callee_object(e, p["lp_n"], "lp_callee")
                _ok(e, e.ne(p["lp_callee"], NONE))
                e.if_(e.eq(_call(e, "erased", p["lp_callee"]), 0), lambda: e.set("lp_calls", 1),
                      lambda: _ok(e, e.eq(p["lp_mres"], 0)))

            e.if_(e.eq(p["lp_op"], _op(Operation.STACK_ALLOC)), stack)
            e.if_(e.eq(p["lp_op"], _op(Operation.ADDRESS_OFFSET)), offset)
            e.if_(e.eq(p["lp_op"], _op(Operation.CALL_DIRECT)), direct)

        e.for_("lp_bi", 0, _g(e, G_BCOUNT), lambda: (e.var("lp_b", _block_at(e, p["lp_bi"])), e.for_("lp_m", 0, _f(e, p["lp_b"], B_NNODES), node)))
        _set_s(e, S_HASCALL, p["lp_calls"])
        _set_s(e, S_LINK, NONE)
        e.if_(e.ne(p["lp_calls"], 0), lambda: (e.set("lp_cursor", _align(e, p["lp_cursor"], 8)), _set_s(e, S_LINK, p["lp_cursor"]),
                                               e.set("lp_cursor", e.add(p["lp_cursor"], 8))))
        # Crossing values: referenced in a block other than their own.
        e.var("lp_cross", e.alloc(e.add(n, 1)))
        _ok(e, e.ne(p["lp_cross"], NONE))
        e.for_("lp_v", 0, n, lambda: e.st(e.add(p["lp_cross"], p["lp_v"]), 0))
        e.var("lp_edges", 0)

        def mark(value, bi):
            e.var("lp_mv", value)
            e.if_(e.both(e.ne(_t(e, S_WIDTH, p["lp_mv"]), 0), e.ne(_block_of(e, p["lp_mv"]), bi)), lambda: e.st(e.add(p["lp_cross"], p["lp_mv"]), 1))

        def block():
            e.var("lp_b", _block_at(e, p["lp_bi"]))
            e.for_("lp_m", 0, _f(e, p["lp_b"], B_NNODES), lambda: (e.var("lp_n", _node_at(e, p["lp_b"], p["lp_m"])), e.for_(
                "lp_k", 0, _f(e, p["lp_n"], N_NOPS), lambda: mark(_operand(e, p["lp_n"], p["lp_k"]), p["lp_bi"]))))
            e.for_("lp_k", 0, _f(e, p["lp_b"], B_NVALUES), lambda: mark(e.ld(e.add(_f(e, p["lp_b"], B_VALUES), p["lp_k"])), p["lp_bi"]))

            def edge():
                e.var("lp_at", e.add(_f(e, p["lp_b"], B_EDGES), e.mul(p["lp_q"], EDGE)))
                e.for_("lp_k", 0, _f(e, p["lp_at"], 1), lambda: mark(e.ld(e.add(_f(e, p["lp_at"], 2), p["lp_k"])), p["lp_bi"]))

            e.for_("lp_q", 0, _f(e, p["lp_b"], B_NEDGES), edge)
            e.var("lp_np", 0)
            e.for_("lp_k", 0, _f(e, p["lp_b"], B_NP), lambda: e.if_(e.ne(_t(e, S_WIDTH, e.ld(e.add(_f(e, p["lp_b"], B_INPUTS), p["lp_k"]))), 0),
                                                                     lambda: e.set("lp_np", e.add(p["lp_np"], 1))))
            e.if_(e.lt(e.add(p["lp_edges"], len(ALLOCATABLE)), p["lp_np"]), lambda: e.set("lp_edges", e.sub(p["lp_np"], len(ALLOCATABLE))))

        e.for_("lp_bi", 0, _g(e, G_BCOUNT), block)
        _set_s(e, S_EDGEB, _align(e, p["lp_cursor"], 8))
        e.var("lp_home", e.add(_s(e, S_EDGEB), e.mul(p["lp_edges"], 8)))

        def assign(value):
            e.var("lp_av", value)

            def home():
                _ok(e, e.eq(_t(e, S_PTR, p["lp_av"]), NONE))  # a stack object's home: the bootstrap's KeyError
                _set_t(e, S_HOME, p["lp_av"], p["lp_home"])
                e.set("lp_home", e.add(p["lp_home"], 8))

            e.if_(e.ne(e.ld(e.add(p["lp_cross"], p["lp_av"])), 0), home)

        e.for_("lp_bi", 0, _g(e, G_BCOUNT), lambda: (e.var("lp_b", _block_at(e, p["lp_bi"])), e.for_(
            "lp_k", 0, _f(e, p["lp_b"], B_NP), lambda: assign(e.ld(e.add(_f(e, p["lp_b"], B_INPUTS), p["lp_k"]))))))
        e.for_("lp_bi", 0, _g(e, G_BCOUNT), lambda: (e.var("lp_b", _block_at(e, p["lp_bi"])), e.for_(
            "lp_m", 0, _f(e, p["lp_b"], B_NNODES), lambda: (e.var("lp_n", _node_at(e, p["lp_b"], p["lp_m"])), e.for_(
                "lp_r", 0, _f(e, p["lp_n"], N_NRES), lambda: assign(_output(e, p["lp_n"], p["lp_r"])))))))
        _set_s(e, S_DYN, p["lp_home"])
        e.give(1)
    return _function(("f",), build, tables)


def _legacy_fn(tables):
    """The legacy register path of function ``f`` (its own graph lifted, the emission state set): the dry run sizes
    the dynamic spill area, then the frame (``sub sp``), the link register's slot, a branch to the entry block when
    it is not first, and every block."""
    def build(e: E):
        p = e.p
        _call(e, "a64l_prepare", p["f"])
        e.var("lf_labels", _a(e, F_NEXT_LABEL))
        e.var("lf_spills", 0)
        e.for_("lf_bi", 0, _g(e, G_BCOUNT), lambda: (e.var("lf_s", _call(e, "a64l_block", p["lf_bi"])),
                                                     e.if_(e.lt(p["lf_spills"], p["lf_s"]), lambda: e.set("lf_spills", p["lf_s"]))))
        e.var("lf_payload", e.add(_s(e, S_DYN), e.mul(p["lf_spills"], 8)))
        e.var("lf_frame", e.sel(e.ne(p["lf_payload"], 0), _align(e, p["lf_payload"], 16), 0))
        for slot in (X_LEN, X_NFIX, X_NCALLS, X_NRANGES):
            _set_a(e, slot, 0)
        _set_a(e, F_NEXT_LABEL, p["lf_labels"])
        _set_s(e, S_FRAME, p["lf_frame"])

        def prologue():
            _reject(e, e.lt(p["lf_frame"], 4096), "XAX.AARCH64.FRAME", "AARCH64-FRAME-SIZE", lambda: D.text(e, "< 4096 bytes"),
                    lambda: D.integer(e, p["lf_frame"]))
            _emit(e, e.add(0xD10003FF, e.mul(p["lf_frame"], 1 << 10)))

        e.if_(e.ne(p["lf_frame"], 0), prologue)
        e.if_(e.ne(_s(e, S_HASCALL), 0), lambda: _ls(e, False, LR, _s(e, S_LINK), 64))
        e.var("lf_entry", _f(e, _g(e, G_BENTRY), B_POS))
        e.if_(e.ne(p["lf_entry"], 0), lambda: _branch(e, 0x14000000, p["lf_entry"], 26))
        e.for_("lf_bi", 0, _g(e, G_BCOUNT), lambda: (e.var("lf_s", _call(e, "a64l_block", p["lf_bi"])),
                                                     _ok(e, e.le(p["lf_s"], p["lf_spills"]))))  # AARCH64-SPILL-PLAN-DETERMINISTIC
        e.give(1)
    return _function(("f",), build, tables)


def add_legacy_functions(add, tables):
    """Every legacy register path function, each after the functions it calls (the emission's and the frame path's
    are added before)."""
    for name, builder in (("a64l_bind", _bind_fn), ("a64l_release", _release_fn), ("a64l_define", _define_fn), ("a64l_spill", _spill_fn),
                          ("a64l_acquire", _acquire_fn), ("a64l_ensure", _ensure_fn), ("a64l_moves", _moves_fn), ("a64l_edge", _copy_edge_fn),
                          ("a64l_call", _call_node_fn), ("a64l_node", _node_fn), ("a64l_term", _term_fn), ("a64l_block", _block_fn),
                          ("a64l_prepare", _prepare_fn), ("a64l_function", _legacy_fn)):
        add(name, builder(tables))
