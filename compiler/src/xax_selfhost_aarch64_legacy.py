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

from xax_compiler import IntCompare, Operation
from xax_selfhost_aarch64_emit import _a, _emit
from xax_selfhost_aarch64_frame import _movimm
from xax_selfhost_facts import E, NONE
from xax_selfhost_general_ranges import _attribute
from xax_selfhost_general_view import N_GRAPH, N_OPSAT, _f, _operand
from xax_selfhost_views_backend import _call, _ok

SCRATCH = 10  # scratch_registers[1]
L_STATE = 130  # ``_a`` slot (after the frame path's): the legacy lowering's state record
# State words: per-value tables (each VCOUNT words), the register map, the spill slot flags, and scalars.
(S_WIDTH, S_HOME, S_REG, S_SPILL, S_SPID, S_LAST, S_UCOUNT, S_UAT, S_PTR, S_LIVE, S_ULIST, S_VREG, S_FREE, S_NEXT, S_MAX, S_DYN,
 S_EDGEB, S_P1, S_P2, S_NFREE, S_LINK, S_HASCALL, S_FRAME, S_GRAPH) = range(24)
ARITHMETIC = {Operation.ADD_WRAP: (0x0B000000, 0x8B000000), Operation.SUB_WRAP: (0x4B000000, 0xCB000000),
              Operation.MUL_WRAP: (0x1B007C00, 0x9B007C00)}
CONDITION = {IntCompare.EQ: 0, IntCompare.NE: 1, IntCompare.UGE: 2, IntCompare.ULT: 3, IntCompare.UGT: 8, IntCompare.ULE: 9,
             IntCompare.SGE: 10, IntCompare.SLT: 11, IntCompare.SGT: 12, IntCompare.SLE: 13}
CALL_KINDS = {Operation.CALL_DIRECT: 0, Operation.CALL_FOREIGN: 1, Operation.CALL_INDIRECT: 2}


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


def _align(e: E, value, alignment):
    return e.and_(e.add(value, e.sub(alignment, 1)), e.sub(0, alignment))


# -- encodings and their rejections -----------------------------------------------------------------------------------


# -- the allocator ----------------------------------------------------------------------------------------------------


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


# -- nodes ------------------------------------------------------------------------------------------------------------


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


# -- one block --------------------------------------------------------------------------------------------------------


# -- the function -----------------------------------------------------------------------------------------------------


