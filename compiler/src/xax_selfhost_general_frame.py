"""S12f (ADR-275): the general x86-64 backend's frame lowering as XAX functions.

``xax_x86_64._compile_function``'s frame path, for the Linux profiles: every machine value of the function's own
graph (not the inlined view) owns a frame slot; each node loads its operands from their slots, computes in fixed
registers, and stores its result.  The bootstrap takes this path when the register-resident lowering rejects the
function (its eligibility, or a node it does not lower) and the legacy register path does not apply (always for a
process entry; otherwise the program declines where the legacy path's static checks would accept, so the bootstrap
decides).

Covered: integer arithmetic, division with its zero trap, width changes, rotation, constants (bits and floats),
compares, the SSE float operations under an IEEE MXCSR, float/integer conversions with their range traps, float
width conversion, products, sums, function addresses, stack storage (static accesses, escaping addresses),
first-class pointers and heap views (dynamic accesses), SysV C imports with INTEGER and SSE scalars, Linux syscalls,
direct and indirect calls, returns, branches, and traps; S12f.3 (ADR-279): atomics of stack storage with the
capability check, and aggregates passed by reference or returned through the hidden pointer.  Declined (the bootstrap
lowers or rejects): links and rebases (which the bootstrap rejects on this path), and the startup reads.

The code, fixups, and ranges go to the same emission record as the register-resident code (S12d), so image
assembly (S12e.1) is unchanged.
"""

from __future__ import annotations

import struct

from xax_compiler import IntCompare, Operation, RESOURCE_EFFECT_OPERATIONS
from xax_selfhost_facts import E, NONE, _function
from xax_selfhost_general_emit import (
    E_CALLS, E_CLEN, E_FWD_ON, E_LABELS, E_NBRANCHES, E_NCALLS, E_NLABELS, E_NRANGES, E_RANGES, E_REAL, E_CAP_ON, _b, _bx, _jcc, _label, _lea,
    _load, _modrm, _movabs, _new_label, _record_call, _relative, _rex, _store, _zero32,
)
from xax_selfhost_general_ranges import _attribute, _block_at, _node_at
from xax_selfhost_general_regalloc import (
    T_FESC, T_FEXT, T_FHOFF, T_FHROOT, T_FPTR, T_FSIZE, T_FSLOT, _callee_object, _eop, _in, _ra, _rt, _set_ra, _set_rt,
)
from xax_selfhost_general_view import (
    B_EDGES, B_INPUTS, B_KIND, B_NEDGES, B_NNODES, B_NP, B_NVALUES, B_PB, B_PFN, B_POS, B_VALUES, BRANCH, CONDITIONAL, EDGE, G_BCOUNT,
    G_BENTRY, G_VCOUNT, G_VTYPE, N_GRAPH, N_NOPS, N_NRES, N_OPSAT, RETURN, _f, _operand, _output, _vf,
)
from xax_selfhost_views_backend import _FN, G_PAY, _at, _call, _g, _ok, _payload_uleb, _reference, _type_form

RAX, RCX, RDX, RSP = 0, 1, 2, 4
SCRATCH0, SCRATCH1 = 10, 11  # the Linux targets' scratch registers
ARGUMENT_REGISTERS = (1, 2, 8, 9)
SYSV_REGISTERS = (7, 6, 2, 1, 8, 9)
SYSCALL_REGISTERS = (7, 6, 2, 10, 8, 9)
SHADOW = 32
INTEGER_DIVIDE_BY_ZERO = 2
# Frame state (``_ra`` slots).
(F_FRAME, F_TEMP, F_MXOLD, F_PROCESS, F_DYN, F_ENTRYB) = range(232, 238)
# S12f.3 (ADR-279): the hidden return pointer's slot (NONE without one), and the call copies of by-reference
# arguments: ``[node, operand index, offset]`` triples and their count.
F_RETPTR, F_COPIES, F_NCOPIES = 239, 240, 241
ARITHMETIC_64 = {Operation.ADD_WRAP: b"\x4c\x01\xd0", Operation.SUB_WRAP: b"\x4c\x29\xd0", Operation.MUL_WRAP: b"\x49\x0f\xaf\xc2",
                 Operation.BIT_XOR: b"\x4c\x31\xd0", Operation.BIT_AND: b"\x4c\x21\xd0", Operation.BIT_OR: b"\x4c\x09\xd0"}
ARITHMETIC_32 = {Operation.ADD_WRAP: b"\x44\x01\xd0", Operation.SUB_WRAP: b"\x44\x29\xd0", Operation.MUL_WRAP: b"\x41\x0f\xaf\xc2",
                 Operation.BIT_XOR: b"\x44\x31\xd0", Operation.BIT_AND: b"\x44\x21\xd0", Operation.BIT_OR: b"\x44\x09\xd0"}
SETCC = {IntCompare.EQ: 0x94, IntCompare.NE: 0x95, IntCompare.ULT: 0x92, IntCompare.ULE: 0x96, IntCompare.UGT: 0x97, IntCompare.UGE: 0x93,
         IntCompare.SLT: 0x9C, IntCompare.SLE: 0x9E, IntCompare.SGT: 0x9F, IntCompare.SGE: 0x9D}
FLOAT_BINARY = {Operation.FLOAT_ADD: 0x58, Operation.FLOAT_SUB: 0x5C, Operation.FLOAT_MUL: 0x59, Operation.FLOAT_DIV: 0x5E}
# ``_float_setcc`` per FloatCompare (1 EQ, 2 NE, 3 LT, 4 LE, 5 GT, 6 GE).
FLOAT_SETCC = {1: b"\x0f\x94\xc0\x0f\x9b\xc2\x20\xd0\x0f\xb6\xc0", 2: b"\x0f\x95\xc0\x0f\x9a\xc2\x08\xd0\x0f\xb6\xc0",
               3: b"\x0f\x92\xc0\x0f\x9b\xc2\x20\xd0\x0f\xb6\xc0", 4: b"\x0f\x96\xc0\x0f\x9b\xc2\x20\xd0\x0f\xb6\xc0",
               5: b"\x0f\x97\xc0\x0f\xb6\xc0", 6: b"\x0f\x93\xc0\x0f\xb6\xc0"}
FLOAT_OPERATIONS = tuple(int(op) for op in (Operation.FLOAT_ADD, Operation.FLOAT_SUB, Operation.FLOAT_MUL, Operation.FLOAT_DIV, Operation.FLOAT_COMPARE,
                                            Operation.UINT_TO_FLOAT, Operation.FLOAT_TO_UINT_TRUNC, Operation.FLOAT_CONVERT,
                                            Operation.SINT_TO_FLOAT, Operation.FLOAT_TO_SINT_TRUNC))
CALLS = tuple(int(op) for op in (Operation.CALL_DIRECT, Operation.CALL_FOREIGN, Operation.CALL_INDIRECT))
ATOMICS = tuple(int(op) for op in (Operation.ATOMIC_LOAD, Operation.ATOMIC_STORE, Operation.ATOMIC_RMW, Operation.ATOMIC_CMPXCHG, Operation.ATOMIC_FENCE))
STATIC_POINTER_CONSUMERS = tuple(int(op) for op in (Operation.LOAD_BITS_LE, Operation.STORE_BITS_LE, Operation.CHECKED_LOAD_BITS_LE,
                                                    Operation.CHECKED_STORE_BITS_LE, Operation.RAW_LOAD_BITS_LE, Operation.ADDRESS_OFFSET,
                                                    Operation.POINTER_CAST, *(Operation(op) for op in ATOMICS)))
DYNAMIC_MEMORY = tuple(int(op) for op in (Operation.LOAD_BITS_LE, Operation.STORE_BITS_LE, Operation.CHECKED_LOAD_BITS_LE,
                                          Operation.CHECKED_STORE_BITS_LE, Operation.RAW_LOAD_BITS_LE))
LEGACY_ALLOWED = tuple(sorted({int(op) for op in (Operation.ADD_WRAP, Operation.SUB_WRAP, Operation.MUL_WRAP, Operation.CONSTANT, Operation.CALL_DIRECT,
                                                  *RESOURCE_EFFECT_OPERATIONS)}))

# S15e.3: ``_compile_register_resident_function``'s hosted (PE) additions and its memory operations.
HOSTED_ALLOWED = tuple(sorted(int(op) for op in (
    Operation.INT_COMPARE, Operation.CALL_FOREIGN, Operation.FUNCTION_ADDRESS, Operation.HEAP_VIEW, Operation.ADDRESS_OFFSET,
    Operation.POINTER_CAST, Operation.LOAD_BITS_LE, Operation.STORE_BITS_LE, Operation.CHECKED_LOAD_BITS_LE,
    Operation.CHECKED_STORE_BITS_LE, Operation.POINTER_ADDRESS)))
HOSTED_MEMORY = tuple(sorted(int(op) for op in (
    Operation.ADDRESS_OFFSET, Operation.POINTER_CAST, Operation.LOAD_BITS_LE, Operation.STORE_BITS_LE, Operation.CHECKED_LOAD_BITS_LE,
    Operation.CHECKED_STORE_BITS_LE, Operation.POINTER_ADDRESS)))


def _op(operation) -> int:
    return int(operation)


# -- types --------------------------------------------------------------------------------------------------------

def _form(e: E, type_obj):
    return _type_form(e, type_obj)


def _proof(e: E, type_obj):
    form = _form(e, type_obj)
    return e.either(e.eq(form, 3), e.eq(form, 4))


def _is_float(e: E, type_obj):
    return e.eq(_form(e, type_obj), 7)


def _is_aggregate(e: E, type_obj):
    form = _form(e, type_obj)
    return e.either(e.eq(form, 8), e.eq(form, 9), e.eq(form, 10))


def _float_width(e: E, type_obj, name: str):
    """``decode_float_width``: 32 for binary32 (format 1), else 64."""
    e.var(f"{name}_at", e.add(_at(e, G_PAY, type_obj), 1))
    e.var(name, e.sel(e.eq(_payload_uleb(e, f"{name}_at"), 1), 32, 64))


def _bits_width(e: E, type_obj, name: str):
    """``_bits_width``: the width of a bits type, 0 otherwise."""
    e.var(name, 0)

    def bits():
        e.var(f"{name}_at", e.add(_at(e, G_PAY, type_obj), 1))
        e.set(name, _payload_uleb(e, f"{name}_at"))

    e.if_(e.eq(_form(e, type_obj), 1), bits)


def _layout_size(e: E, type_obj, name: str):
    """``_layout(type).size``, or NONE when the bootstrap's ``_layout`` is None (proof values, links, other forms)."""
    form = _form(e, type_obj)
    e.var(f"{name}_form", form)
    e.var(name, NONE)
    laid = e.either(*(e.eq(e.p[f"{name}_form"], f) for f in (1, 2, 7, 8, 9, 10)))
    e.if_(laid, lambda: e.set(name, _call(e, "abi_layout", type_obj)))


def _slot_bytes(e: E, size):
    """``_slot_bytes``: max(8, align(size, 8))."""
    aligned = e.and_(e.add(size, 7), (1 << 64) - 8)
    return e.sel(e.lt(aligned, 8), 8, aligned)


def _by_reference(e: E, type_obj, size):
    """``_win64_by_reference``: an aggregate whose size is not 1, 2, 4, or 8."""
    return e.both(_is_aggregate(e, type_obj), e.not_(e.either(*(e.eq(size, s) for s in (1, 2, 4, 8)))))


def _align_to(e: E, value, alignment):
    """``(value + alignment - 1) & -alignment``."""
    return e.and_(e.add(value, e.sub(alignment, 1)), e.sub(0, alignment))


# -- encoders (frame path) --------------------------------------------------------------------------------------

def _xmm_memory(e: E, load: bool, xmm, offset, width):
    """``_xmm_memory``: movss/movsd between xmm and ``[rsp + offset]`` (NATIVE-XMM-MEMORY beyond it, S15b.4)."""
    from xax_selfhost_general_rejects import XMM, encoding_reject

    e.if_(e.not_(e.both(e.either(e.eq(width, 32), e.eq(width, 64)), e.lt(offset, 1 << 31), e.lt(xmm, 16))),
          lambda: encoding_reject(e, XMM, xmm, offset, width))
    _bx(e, e.sel(e.eq(width, 32), 0xF3, 0xF2), 1)
    e.if_(e.le(8, xmm), lambda: _bx(e, 0x44, 1))
    _xmm_modrm(e, 0x10 if load else 0x11, xmm, offset)


def _xmm_modrm(e: E, opcode, xmm, offset):
    """``0f opcode`` with ``[rsp + offset]`` (disp8 below 128, else disp32) for xmm register ``xmm``."""
    reg = e.mul(e.and_(xmm, 7), 8)
    e.var("xm_reg", reg)
    e.var("xm_off", offset)
    e.var("xm_op", opcode)
    e.if_(e.lt(e.p["xm_off"], 128), lambda: _bx(e, e.add(e.add(e.add(0x0F, e.mul(e.p["xm_op"], 256)), e.mul(e.add(0x44, e.p["xm_reg"]), 1 << 16)),
                                                       e.add(0x24000000, e.mul(e.p["xm_off"], 1 << 32))), 5),
          lambda: (_bx(e, e.add(e.add(e.add(0x0F, e.mul(e.p["xm_op"], 256)), e.mul(e.add(0x84, e.p["xm_reg"]), 1 << 16)), 0x24000000), 4),
                   _bx(e, e.p["xm_off"], 4)))


def _xmm_compare_memory(e: E, xmm, offset, width):
    e.if_(e.eq(width, 64), lambda: _bx(e, 0x66, 1))
    e.if_(e.le(8, xmm), lambda: _bx(e, 0x44, 1))
    reg = e.mul(e.and_(xmm, 7), 8)
    e.var("xc_reg", reg)
    e.var("xc_off", offset)
    e.if_(e.lt(e.p["xc_off"], 128), lambda: _bx(e, e.add(e.add(0x2E0F, e.mul(e.add(0x44, e.p["xc_reg"]), 1 << 16)), e.add(0x24000000, e.mul(e.p["xc_off"], 1 << 32))), 5),
          lambda: (_bx(e, e.add(e.add(0x2E0F, e.mul(e.add(0x84, e.p["xc_reg"]), 1 << 16)), 0x24000000), 4), _bx(e, e.p["xc_off"], 4)))


def _mov_gpr_xmm(e: E, to_xmm: bool, xmm: int, register: int, width):
    """``_mov_gpr_xmm`` (movd/movq) for fixed registers."""
    _bx(e, 0x66, 1)
    e.if_(e.eq(width, 64), lambda: _bx(e, 0x40 | 0x08 | (0x04 if xmm >= 8 else 0) | (0x01 if register >= 8 else 0), 1),
          lambda: (_bx(e, 0x40 | (0x04 if xmm >= 8 else 0) | (0x01 if register >= 8 else 0), 1) if (xmm >= 8 or register >= 8) else None))
    _b(e, (b"\x0f\x6e" if to_xmm else b"\x0f\x7e") + bytes((0xC0 | ((xmm & 7) << 3) | (register & 7),)))


def _xmm_compare_registers(e: E, left: int, right: int, width):
    e.if_(e.eq(width, 64), lambda: _bx(e, 0x66, 1))
    _b(e, b"\x0f\x2e" + bytes((0xC0 | ((left & 7) << 3) | (right & 7),)))


def _float_prefix(e: E, width):
    _bx(e, e.sel(e.eq(width, 32), 0xF3, 0xF2), 1)


def _mxcsr(e: E, store: bool, offset):
    """``_mxcsr_store``/``_mxcsr_load``."""
    digit = 0x5C if store else 0x54
    e.var("mx_off", offset)
    e.if_(e.lt(e.p["mx_off"], 128), lambda: (_b(e, bytes((0x0F, 0xAE, digit, 0x24))), _bx(e, e.p["mx_off"], 1)),
          lambda: (_b(e, bytes((0x0F, 0xAE, digit + 0x40, 0x24))), _bx(e, e.p["mx_off"], 4)))


def _and_imm(e: E, register: int, value, wide):
    """``_and_immediate`` for a fixed register (``value`` within 32 bits)."""
    e.if_(e.ne(wide, 0), lambda: _bx(e, 0x48 | (0x01 if register >= 8 else 0), 1),
          lambda: (_bx(e, 0x41, 1) if register >= 8 else None))
    _b(e, bytes((0x81, 0xE0 | (register & 7))))
    _bx(e, value, 4)


def _mask_register(e: E, register: int, width):
    """``mask_register``: keep the low ``width`` bits (nothing at 64)."""
    p = e.p
    e.var("mr_w", width)

    def mask():
        e.var("mr_m", 1)
        e.for_("mr_k", 0, p["mr_w"], lambda: e.set("mr_m", e.mul(p["mr_m"], 2)))
        e.set("mr_m", e.sub(p["mr_m"], 1))
        temporary = SCRATCH1 if register != SCRATCH1 else RAX

        def wide_mask():
            _movabs(e, temporary, p["mr_m"])
            _b(e, bytes((0x48 | (0x04 if temporary >= 8 else 0) | (0x01 if register >= 8 else 0), 0x21, 0xC0 | ((temporary & 7) << 3) | (register & 7))))

        e.if_(e.lt(p["mr_m"], 1 << 32), lambda: _and_imm(e, register, p["mr_m"], e.flag(e.lt(32, p["mr_w"]))), wide_mask)

    e.if_(e.lt(p["mr_w"], 64), mask)


def _cmp_imm32(e: E, register: int, value):
    from xax_selfhost_general_rejects import CHECKED_BOUND, encoding_reject

    e.if_(e.le(1 << 31, value), lambda: encoding_reject(e, CHECKED_BOUND, value))
    _b(e, bytes((0x48 | (0x01 if register >= 8 else 0), 0x81, 0xF8 | (register & 7))))
    _bx(e, value, 4)


def _zero_bytes(e: E, base: int, offset, size, temp: int = RAX):
    """``_zero_bytes``: zero ``size`` bytes (a multiple of 8) at ``[base + offset]``."""
    p = e.p
    _zero32(e, temp)
    e.var("zb_off", offset)
    e.var("zb_n", size)
    e.var("zb_k", 0)
    e.while_(lambda: e.lt(p["zb_k"], p["zb_n"]), lambda: (
        _call(e, "store_exact", temp, base, e.add(p["zb_off"], p["zb_k"]), 8), e.set("zb_k", e.add(p["zb_k"], 8))))


def _copy_bytes(e: E, destination_base, destination, source_base, source, size, temp: int = RAX):
    """``_copy_bytes``: the widest chunk (8, 4, 2, 1) at each step."""
    p = e.p
    e.var("cb_db", destination_base)
    e.var("cb_d", destination)
    e.var("cb_sb", source_base)
    e.var("cb_s", source)
    e.var("cb_n", size)
    e.var("cb_done", 0)

    def step():
        e.var("cb_left", e.sub(p["cb_n"], p["cb_done"]))
        e.var("cb_c", e.sel(e.le(8, p["cb_left"]), 8, e.sel(e.le(4, p["cb_left"]), 4, e.sel(e.le(2, p["cb_left"]), 2, 1))))
        _call(e, "load_exact", temp, p["cb_sb"], e.add(p["cb_s"], p["cb_done"]), p["cb_c"])
        _call(e, "store_exact", temp, p["cb_db"], e.add(p["cb_d"], p["cb_done"]), p["cb_c"])
        e.set("cb_done", e.add(p["cb_done"], p["cb_c"]))

    e.while_(lambda: e.lt(p["cb_done"], p["cb_n"]), step)


def _indexed(e: E, opcode: int, register: int, index: int, offset, width):
    """``_indexed_memory_instruction``: ``[rsp + index + disp32]`` of 4/8 bytes (NATIVE-INDEXED-MEMORY-ENCODABLE otherwise)."""
    from xax_selfhost_general_rejects import INDEXED, encoding_reject

    e.if_(e.not_(e.both(e.either(e.eq(width, 4), e.eq(width, 8)), e.lt(offset, 1 << 31))), lambda: encoding_reject(e, INDEXED, width, offset))
    rex = e.add(0x40 | (0x04 if register >= 8 else 0) | (0x02 if index >= 8 else 0), e.mul(e.flag(e.eq(width, 8)), 8))
    e.var("ix_rex", rex)
    e.if_(e.ne(e.p["ix_rex"], 0x40), lambda: _bx(e, e.p["ix_rex"], 1))
    _b(e, bytes((opcode, 0x84 | ((register & 7) << 3), ((index & 7) << 3) | 0x04)))
    _bx(e, offset, 4)


def _base_index(e: E, store: bool, register: int, base: int, index: int, offset, size):
    """``_base_index_load``/``_base_index_store``: ``[base + index + disp32]`` of 1/2/4/8 bytes."""
    p = e.p
    e.var("bi_size", size)
    if store:
        e.if_(e.eq(p["bi_size"], 2), lambda: _bx(e, 0x66, 1))
    rex = e.add(0x40 | (0x04 if register >= 8 else 0) | (0x02 if index >= 8 else 0) | (0x01 if base >= 8 else 0), e.mul(e.flag(e.eq(p["bi_size"], 8)), 8))
    e.var("bi_rex", rex)
    forced = e.eq(p["bi_size"], 1) if 4 <= register < 8 else e.eq(1, 0)
    e.if_(e.either(e.ne(p["bi_rex"], 0x40), forced), lambda: _bx(e, p["bi_rex"], 1))
    if store:
        e.if_(e.eq(p["bi_size"], 1), lambda: _bx(e, 0x88, 1), lambda: _bx(e, 0x89, 1))
    else:
        e.if_(e.eq(p["bi_size"], 1), lambda: _bx(e, 0xB60F, 2), lambda: e.if_(e.eq(p["bi_size"], 2), lambda: _bx(e, 0xB70F, 2), lambda: _bx(e, 0x8B, 1)))
    _b(e, bytes((0x84 | ((register & 7) << 3), ((index & 7) << 3) | (base & 7))))
    _bx(e, e.and_(offset, 0xFFFFFFFF), 4)


# -- the frame ----------------------------------------------------------------------------------------------------

def _each_node(e: E, visit):
    """``visit(block record, block index, node, node index)`` over the lifted graph in order."""
    p = e.p

    def block():
        e.var("en_b", _block_at(e, p["en_bi"]))

        def node():
            e.var("en_n", _node_at(e, p["en_b"], p["en_m"]))
            visit(p["en_b"], p["en_bi"], p["en_n"], p["en_m"])

        e.for_("en_m", 0, _f(e, p["en_b"], B_NNODES), node)

    e.for_("en_bi", 0, _g(e, G_BCOUNT), block)


def _machine_inputs(e: E, node, skip_first, name: str):
    """``name``: the count of the node's non-proof operand types (from operand ``skip_first``)."""
    p = e.p
    e.var(name, 0)
    e.for_(f"{name}_k", skip_first, _f(e, node, N_NOPS), lambda: e.if_(e.not_(_proof(e, _vf(e, G_VTYPE, _operand(e, node, p[f"{name}_k"])))),
                                                                       lambda: e.set(name, e.add(p[name], 1))))


def _machine_results(e: E, node, name: str):
    """``name``: the count of non-proof results; ``name_first`` the first such result (NONE when none)."""
    p = e.p
    e.var(name, 0)
    e.var(f"{name}_first", NONE)

    def each():
        e.var(f"{name}_v", _output(e, node, p[f"{name}_k"]))
        machine = e.not_(_proof(e, _vf(e, G_VTYPE, p[f"{name}_v"])))
        e.if_(machine, lambda: (e.if_(e.eq(p[f"{name}_first"], NONE), lambda: e.set(f"{name}_first", p[f"{name}_v"])), e.set(name, e.add(p[name], 1))))

    e.for_(f"{name}_k", 0, _f(e, node, N_NRES), each)


def _frame_layout_fn(tables):
    """The frame: every value's slot and layout size, stack storage and heap-view pointers with their extents,
    escaping pointers, the MXCSR save slots, and the frame size.  Declined for aggregates passed by reference (left to
    the bootstrap)."""
    def build(e: E):
        p = e.p
        n = _g(e, G_VCOUNT)
        for table in (T_FSLOT, T_FSIZE, T_FPTR, T_FHROOT, T_FHOFF, T_FEXT):
            e.for_("fl_v", 0, n, lambda table=table: _set_rt(e, table, p["fl_v"], NONE))
        e.for_("fl_v", 0, n, lambda: _set_rt(e, T_FESC, p["fl_v"], 0))
        # Outgoing stack arguments: the most any call passes beyond the argument registers.
        e.var("fl_out", 0)

        def outgoing(block, bi, node, m):
            e.var("fl_op", _eop(e, node))

            def call():
                _machine_inputs(e, node, e.flag(e.eq(p["fl_op"], _op(Operation.CALL_INDIRECT))), "fl_in")
                # A by-reference result travels as a hidden first argument.
                _machine_results(e, node, "fl_cr")
                e.set("fl_in", e.add(p["fl_in"], _hidden_result(e, p["fl_cr_first"], "fl_ch")))
                e.if_(e.lt(4, p["fl_in"]), lambda: e.if_(e.lt(p["fl_out"], e.sub(p["fl_in"], 4)), lambda: e.set("fl_out", e.sub(p["fl_in"], 4))))

            e.if_(_in(e, p["fl_op"], CALLS), call)

        _each_node(e, outgoing)
        e.var("fl_cursor", e.add(SHADOW, e.mul(p["fl_out"], 8)))

        def slot(value, type_obj):
            e.var("fl_t", type_obj)
            _layout_size(e, p["fl_t"], "fl_size")

            def assign():
                # Win64-style by-reference aggregates keep a 16-byte aligned slot (a valid indirect temporary).
                e.if_(_by_reference(e, p["fl_t"], p["fl_size"]), lambda: e.set("fl_cursor", _align_to(e, p["fl_cursor"], 16)))
                _set_rt(e, T_FSLOT, value, p["fl_cursor"])
                _set_rt(e, T_FSIZE, value, p["fl_size"])
                e.set("fl_cursor", e.add(p["fl_cursor"], _slot_bytes(e, p["fl_size"])))

            e.if_(e.both(e.ne(p["fl_size"], NONE), e.either(_is_aggregate(e, p["fl_t"]), e.le(p["fl_size"], 8))), assign)

        def block_values():
            e.var("fl_b", _block_at(e, p["fl_bi"]))

            def parameter():
                e.var("fl_pv", e.ld(e.add(_f(e, p["fl_b"], B_INPUTS), p["fl_k"])))
                e.var("fl_pt", _vf(e, G_VTYPE, p["fl_pv"]))

                def machine():
                    _layout_size(e, p["fl_pt"], "fl_psize")

                    def reject():
                        """S12f.4 (ADR-280): the bootstrap's NATIVE-BLOCK-PARAMETER-VALUE, naming the parameter's type."""
                        import xax_selfhost_diagnostics as D
                        from xax_selfhost_general_emit import graph_cid_words, reject_at
                        from xax_selfhost_views_backend import _cid_words

                        def write():
                            D.text(e, "XAX.NATIVE.BLOCK_TYPE")
                            D.cid(e, graph_cid_words(e, p["f"]))
                            D.text(e, "NATIVE-BLOCK-PARAMETER-VALUE")
                            D.text(e, "scalar <=64 bits or aggregate")
                            D.cid(e, _cid_words(e, p["fl_pt"]))

                        reject_at(e, write)

                    e.if_(e.not_(e.both(e.ne(p["fl_psize"], NONE), e.either(_is_aggregate(e, p["fl_pt"]), e.le(p["fl_psize"], 8)))), reject)
                    slot(p["fl_pv"], p["fl_pt"])

                e.if_(e.not_(_proof(e, p["fl_pt"])), machine)

            e.for_("fl_k", 0, _f(e, p["fl_b"], B_NP), parameter)

            def node():
                e.var("fl_n", _node_at(e, p["fl_b"], p["fl_m"]))
                e.for_("fl_r", 0, _f(e, p["fl_n"], N_NRES), lambda: (e.var("fl_rv", _output(e, p["fl_n"], p["fl_r"])), slot(p["fl_rv"], _vf(e, G_VTYPE, p["fl_rv"]))))

            e.for_("fl_m", 0, _f(e, p["fl_b"], B_NNODES), node)

        e.for_("fl_bi", 0, _g(e, G_BCOUNT), block_values)
        # Edge temporaries: the most parameter bytes any block takes.
        _set_ra(e, F_TEMP, p["fl_cursor"])
        e.var("fl_max", 0)

        def temporaries():
            e.var("fl_b", _block_at(e, p["fl_bi"]))
            e.var("fl_sum", 0)
            e.for_("fl_k", 0, _f(e, p["fl_b"], B_NP), lambda: (
                e.var("fl_pv", e.ld(e.add(_f(e, p["fl_b"], B_INPUTS), p["fl_k"]))),
                e.if_(e.ne(_rt(e, T_FSLOT, p["fl_pv"]), NONE), lambda: e.set("fl_sum", e.add(p["fl_sum"], _slot_bytes(e, _rt(e, T_FSIZE, p["fl_pv"])))))))
            e.if_(e.lt(p["fl_max"], p["fl_sum"]), lambda: e.set("fl_max", p["fl_sum"]))

        e.for_("fl_bi", 0, _g(e, G_BCOUNT), temporaries)
        e.set("fl_cursor", e.add(p["fl_cursor"], p["fl_max"]))

        # Stack storage and heap-view pointers.
        def pointers(block, bi, node, m):
            e.var("fl_op", _eop(e, node))
            e.var("fl_res", e.sel(e.ne(_f(e, node, N_NRES), 0), _output(e, node, 0), NONE))
            result = p["fl_res"]

            def stack():
                e.set("fl_cursor", _align_to(e, p["fl_cursor"], _attribute(e, node, 1)))
                _set_rt(e, T_FPTR, result, p["fl_cursor"])
                _set_rt(e, T_FEXT, result, _attribute(e, node, 0))
                e.set("fl_cursor", e.add(p["fl_cursor"], _attribute(e, node, 0)))

            def offset():
                e.var("fl_src", _operand(e, node, 0))

                def heap():
                    _set_rt(e, T_FHROOT, result, _rt(e, T_FHROOT, p["fl_src"]))
                    _set_rt(e, T_FHOFF, result, e.add(_rt(e, T_FHOFF, p["fl_src"]), _attribute(e, node, 0)))
                    _set_rt(e, T_FEXT, result, e.sub(_rt(e, T_FEXT, p["fl_src"]), _attribute(e, node, 0)))

                def frame():
                    _set_rt(e, T_FPTR, result, e.add(_rt(e, T_FPTR, p["fl_src"]), _attribute(e, node, 0)))
                    _set_rt(e, T_FEXT, result, e.sub(_rt(e, T_FEXT, p["fl_src"]), _attribute(e, node, 0)))

                e.if_(e.ne(_rt(e, T_FHROOT, p["fl_src"]), NONE), heap, lambda: e.if_(
                    e.ne(_rt(e, T_FPTR, p["fl_src"]), NONE), frame, lambda: _ok(e, e.ne(_ra(e, F_DYN), 0))))

            def cast():
                e.var("fl_src", _operand(e, node, 0))
                e.if_(e.ne(_rt(e, T_FPTR, p["fl_src"]), NONE), lambda: (_set_rt(e, T_FPTR, result, _rt(e, T_FPTR, p["fl_src"])), _set_rt(e, T_FEXT, result, _rt(e, T_FEXT, p["fl_src"]))),
                      lambda: e.if_(e.ne(_rt(e, T_FHROOT, p["fl_src"]), NONE), lambda: (
                          _set_rt(e, T_FHROOT, result, _rt(e, T_FHROOT, p["fl_src"])), _set_rt(e, T_FHOFF, result, _rt(e, T_FHOFF, p["fl_src"])),
                          _set_rt(e, T_FEXT, result, _rt(e, T_FEXT, p["fl_src"])))))

            def view():
                _set_rt(e, T_FHROOT, result, result)
                _set_rt(e, T_FHOFF, result, 0)
                _set_rt(e, T_FEXT, result, _attribute(e, node, 0))

            e.if_(e.eq(p["fl_op"], _op(Operation.STACK_ALLOC)), stack, lambda: e.if_(e.eq(p["fl_op"], _op(Operation.ADDRESS_OFFSET)), offset, lambda: e.if_(
                e.eq(p["fl_op"], _op(Operation.POINTER_CAST)), cast, lambda: e.if_(e.eq(p["fl_op"], _op(Operation.HEAP_VIEW)), view))))

        _each_node(e, pointers)

        # Escaping frame pointers (dynamic-pointer profiles only).
        def escaping(block, bi, node, m):
            e.var("fl_op", _eop(e, node))

            def operand():
                e.var("fl_o", _operand(e, node, p["fl_q"]))
                static = e.both(e.eq(p["fl_q"], 0), _in(e, p["fl_op"], STATIC_POINTER_CONSUMERS))
                e.if_(e.both(e.ne(_rt(e, T_FPTR, p["fl_o"]), NONE), e.not_(static)), lambda: _set_rt(e, T_FESC, p["fl_o"], 1))

            e.for_("fl_q", 0, _f(e, node, N_NOPS), operand)

        def escaping_terminators():
            e.var("fl_b", _block_at(e, p["fl_bi"]))
            mark = lambda v: e.if_(e.ne(_rt(e, T_FPTR, v), NONE), lambda: _set_rt(e, T_FESC, v, 1))  # noqa: E731
            e.for_("fl_k", 0, _f(e, p["fl_b"], B_NVALUES), lambda: (e.var("fl_tv", e.ld(e.add(_f(e, p["fl_b"], B_VALUES), p["fl_k"]))), mark(p["fl_tv"])))

            def edge():
                e.var("fl_at", e.add(_f(e, p["fl_b"], B_EDGES), e.mul(p["fl_q"], EDGE)))
                e.for_("fl_k", 0, _f(e, p["fl_at"], 1), lambda: (e.var("fl_tv", e.ld(e.add(_f(e, p["fl_at"], 2), p["fl_k"]))), mark(p["fl_tv"])))

            e.for_("fl_q", 0, _f(e, p["fl_b"], B_NEDGES), edge)

        def mark_escapes():
            _each_node(e, escaping)
            e.for_("fl_bi", 0, _g(e, G_BCOUNT), escaping_terminators)

        e.if_(e.ne(_ra(e, F_DYN), 0), mark_escapes)
        # MXCSR save slots when any float operation runs.
        e.var("fl_float", 0)
        _each_node(e, lambda block, bi, node, m: e.if_(_in(e, _eop(e, node), FLOAT_OPERATIONS), lambda: e.set("fl_float", 1)))
        _set_ra(e, F_MXOLD, NONE)
        e.if_(e.ne(p["fl_float"], 0), lambda: (_set_ra(e, F_MXOLD, p["fl_cursor"]), e.set("fl_cursor", e.add(p["fl_cursor"], 8))))
        # The hidden return pointer's slot, then each by-reference call argument's 16-byte aligned copy.
        e.var("fl_i", _call(e, "interface", p["f"]))
        e.var("fl_np", e.ld(e.add(p["fl_i"], 1)))
        e.var("fl_rt", e.add(e.add(p["fl_i"], 2), p["fl_np"]))
        e.var("fl_first", NONE)
        e.for_("fl_k", 0, e.ld(p["fl_rt"]), lambda: (e.var("fl_t", e.ld(e.add(e.add(p["fl_rt"], 1), p["fl_k"]))), e.if_(
            e.both(e.eq(p["fl_first"], NONE), e.not_(_proof(e, p["fl_t"]))), lambda: e.set("fl_first", p["fl_t"]))))
        _set_ra(e, F_RETPTR, NONE)
        e.if_(e.ne(p["fl_first"], NONE), lambda: (_layout_size(e, p["fl_first"], "fl_rsize"), e.if_(
            e.both(e.ne(p["fl_rsize"], NONE), _by_reference(e, p["fl_first"], p["fl_rsize"])),
            lambda: (_set_ra(e, F_RETPTR, p["fl_cursor"]), e.set("fl_cursor", e.add(p["fl_cursor"], 8))))))
        e.var("fl_ncopies", 0)
        _each_node(e, lambda block, bi, node, m: e.if_(_in(e, _eop(e, node), CALLS), lambda: e.set("fl_ncopies", e.add(p["fl_ncopies"], _f(e, node, N_NOPS)))))
        e.var("fl_copies", e.alloc(e.add(e.mul(p["fl_ncopies"], 3), 1)))
        _ok(e, e.ne(p["fl_copies"], NONE))
        _set_ra(e, F_COPIES, p["fl_copies"])
        _set_ra(e, F_NCOPIES, 0)

        def copies(block, bi, node, m):
            def each():
                e.var("fl_cv", _operand(e, node, p["fl_ck"]))
                e.var("fl_ct", _vf(e, G_VTYPE, p["fl_cv"]))

                def aggregate():
                    _layout_size(e, p["fl_ct"], "fl_csize")

                    def copy():
                        e.set("fl_cursor", _align_to(e, p["fl_cursor"], 16))
                        e.var("fl_cat", e.add(p["fl_copies"], e.mul(_ra(e, F_NCOPIES), 3)))
                        for field, value in enumerate((node, p["fl_ck"], p["fl_cursor"])):
                            e.st(e.add(p["fl_cat"], field), value)
                        _set_ra(e, F_NCOPIES, e.add(_ra(e, F_NCOPIES), 1))
                        e.set("fl_cursor", e.add(p["fl_cursor"], _slot_bytes(e, p["fl_csize"])))

                    e.if_(e.both(e.ne(p["fl_csize"], NONE), _by_reference(e, p["fl_ct"], p["fl_csize"])), copy)

                e.if_(e.both(e.not_(_proof(e, p["fl_ct"])), _is_aggregate(e, p["fl_ct"])), aggregate)

            e.if_(_in(e, _eop(e, node), CALLS), lambda: e.for_("fl_ck", 0, _f(e, node, N_NOPS), each))

        _each_node(e, copies)
        bias = e.sel(e.ne(_ra(e, F_PROCESS), 0), 0, 8)
        e.var("fl_bias", bias)
        e.var("fl_frame", e.sub(_align_to(e, e.add(p["fl_cursor"], p["fl_bias"]), 16), p["fl_bias"]))
        _ok(e, e.lt(p["fl_frame"], 1 << 32))  # ``frame_size.to_bytes(4)``; an access past 2^31 is the encoders' rejection
        _set_ra(e, F_FRAME, p["fl_frame"])
        e.give(1)
    return _function(("f",), build, tables)


def _hidden_result(e: E, first, name: str):
    """1 when a call's first machine result ``first`` (NONE: none) is an aggregate returned through a hidden pointer."""
    p = e.p
    e.var(name, 0)

    def result():
        e.var(f"{name}_t", _vf(e, G_VTYPE, first))
        _layout_size(e, p[f"{name}_t"], f"{name}_size")
        e.if_(e.both(e.ne(p[f"{name}_size"], NONE), _by_reference(e, p[f"{name}_t"], p[f"{name}_size"])), lambda: e.set(name, 1))

    e.if_(e.ne(first, NONE), result)
    return p[name]


def _copy_at(e: E, node, operand):
    """The frame offset of call ``node``'s copy of by-reference argument ``operand``."""
    p = e.p
    e.var("ca_at", NONE)
    e.for_("ca_q", 0, _ra(e, F_NCOPIES), lambda: (e.var("ca_r", e.add(_ra(e, F_COPIES), e.mul(p["ca_q"], 3))), e.if_(
        e.both(e.eq(e.ld(p["ca_r"]), node), e.eq(e.ld(e.add(p["ca_r"], 1)), operand)), lambda: e.set("ca_at", e.ld(e.add(p["ca_r"], 2))))))
    _ok(e, e.ne(p["ca_at"], NONE))
    return p["ca_at"]


def _slot(e: E, value):
    """``value_slot``: the value's frame slot; S12f.4 (ADR-280): a value without one (wider than 64 bits, not laid out)
    is the bootstrap's NATIVE-VALUE-MACHINE rejection, naming the value's (block, index, result)."""
    e.var("vs_s", _rt(e, T_FSLOT, value))
    e.var("vs_v", value)
    e.if_(e.eq(e.p["vs_s"], NONE), lambda: _call(e, "value_reject", e.p["vs_v"]))
    return e.p["vs_s"]


def _value_reject_fn(tables):
    """NATIVE-VALUE-MACHINE for ``value`` of the function being lowered (``reject_at``)."""
    from xax_selfhost_general_view import G_VPOS, POS_BLOCK, POS_INDEX

    def build(e: E):
        import xax_selfhost_diagnostics as D
        from xax_selfhost_general_emit import graph_cid_words, reject_at

        p = e.p
        e.var("vr_pos", _vf(e, G_VPOS, p["value"]))
        _ok(e, e.ne(p["vr_pos"], NONE))

        def write():
            D.text(e, "XAX.NATIVE.VALUE")
            D.cid(e, graph_cid_words(e, _ra(e, F_FN)))
            D.text(e, "NATIVE-VALUE-MACHINE")
            D.text(e, "scalar/compact value <=64 bits")
            D.put(e, D.T_LIST)
            D.put(e, 3)
            D.integer(e, e.and_(e.udiv(p["vr_pos"], POS_BLOCK), (1 << 22) - 1))
            D.integer(e, e.and_(e.udiv(p["vr_pos"], POS_INDEX), (1 << 24) - 1))
            D.integer(e, e.and_(p["vr_pos"], (1 << 16) - 1))

        reject_at(e, write)
    return _function(("value",), build, tables)


def _fixed_reject_fn(tables):
    """A frame-path rejection of the function being lowered whose fields are constant: ``which`` selects it."""
    def build(e: E):
        import xax_selfhost_diagnostics as D
        from xax_selfhost_general_emit import graph_cid_words, reject_at

        p = e.p

        def write():
            for which, (code, rule, expected, actual) in enumerate(FIXED_REJECTIONS):
                e.if_(e.eq(p["which"], which), lambda code=code: D.text(e, code))
            D.cid(e, graph_cid_words(e, _ra(e, F_FN)))
            for which, (code, rule, expected, actual) in enumerate(FIXED_REJECTIONS):
                e.if_(e.eq(p["which"], which), lambda rule=rule, expected=expected, actual=actual: (D.text(e, rule), D.text(e, expected), D.text(e, actual)))

        reject_at(e, write)
    return _function(("which",), build, tables)


WIDTH_DIVISION, WIDTH_ARITHMETIC, WIDTH_ROTATE = range(3)
F_AMOUNT = 243  # ``_ra`` slot: a rotation's amount, for its rejection


def _width_reject_fn(tables):
    """The bootstrap's width rejections on the frame path: ``which`` 0 division (NATIVE-BITS-SUPPORTED, naming the
    graph), 1 arithmetic (``_arithmetic``: NATIVE-BITS-SUPPORTED on "x86_64"), 2 rotation (NATIVE-ROTATE-RIGHT)."""
    def build(e: E):
        import xax_selfhost_diagnostics as D
        from xax_selfhost_general_emit import graph_cid_words, reject_at

        p = e.p

        def write():
            def bits(graph: bool):
                D.text(e, "XAX.NATIVE.BITS")
                if graph:
                    D.cid(e, graph_cid_words(e, _ra(e, F_FN)))
                else:
                    D.text(e, "x86_64")
                D.text(e, "NATIVE-BITS-SUPPORTED")
                D.put(e, D.T_LIST)
                D.put(e, 2)
                D.integer(e, 32)
                D.integer(e, 64)
                D.integer(e, p["width"])

            def rotate():
                D.text(e, "XAX.NATIVE.ROTATE")
                D.text(e, "x86_64")
                D.text(e, "NATIVE-ROTATE-RIGHT")
                D.put(e, D.T_LIST)
                D.put(e, 3)
                D.integer(e, 32)
                D.integer(e, 64)
                D.text(e, "amount < width")
                D.put(e, D.T_LIST)
                D.put(e, 2)
                D.integer(e, p["width"])
                D.integer(e, _ra(e, F_AMOUNT))

            e.if_(e.eq(p["which"], WIDTH_DIVISION), lambda: bits(True), lambda: e.if_(e.eq(p["which"], WIDTH_ARITHMETIC), lambda: bits(False), rotate))

        reject_at(e, write)
    return _function(("which", "width"), build, tables)


FIXED_REJECTIONS = (
    ("XAX.NATIVE.LINK", "NATIVE-LINK-REGISTER-PATH", "register-resident hosted function", "frame lowering"),
    ("XAX.NATIVE.REBASE", "NATIVE-REBASE-REGISTER-PATH", "register-resident Linux function", "frame lowering"),
)
LINK_REJECTION, REBASE_REJECTION = range(2)


def _begin_float(e: E):
    def save():
        _mxcsr(e, True, _ra(e, F_MXOLD))
        _load(e, RAX, _ra(e, F_MXOLD), 4)
        _and_imm(e, RAX, 0xFFFF1FBF, 0)
        _store(e, RAX, e.add(_ra(e, F_MXOLD), 4), 4)
        _mxcsr(e, False, e.add(_ra(e, F_MXOLD), 4))

    e.if_(e.ne(_ra(e, F_MXOLD), NONE), save)


def _end_float(e: E):
    e.if_(e.ne(_ra(e, F_MXOLD), NONE), lambda: _mxcsr(e, False, _ra(e, F_MXOLD)))


def _heap_base(e: E, pointer, name: str):
    """``heap_base_register``: load the view root's slot into r11; ``name`` the offset."""
    _load(e, SCRATCH1, _slot(e, _rt(e, T_FHROOT, pointer)), 8)
    e.var(name, _rt(e, T_FHOFF, pointer))


# -- nodes ----------------------------------------------------------------------------------------------------------

def _node_prelude(e: E):
    """``fn_node``, ``fn_op``, ``fn_res`` (result 0 or NONE) for node ``m`` of block ``bi``."""
    p = e.p
    e.var("fn_block", _block_at(e, p["bi"]))
    e.var("fn_node", _node_at(e, p["fn_block"], p["m"]))
    e.var("fn_op", _eop(e, p["fn_node"]))
    e.var("fn_res", e.sel(e.ne(_f(e, p["fn_node"], N_NRES), 0), _output(e, p["fn_node"], 0), NONE))
    e.var("fn_a", e.sel(e.ne(_f(e, p["fn_node"], N_NOPS), 0), _operand(e, p["fn_node"], 0), NONE))
    e.var("fn_b", e.sel(e.lt(1, _f(e, p["fn_node"], N_NOPS)), _operand(e, p["fn_node"], e.sel(e.lt(1, _f(e, p["fn_node"], N_NOPS)), 1, 0)), NONE))
    return p["fn_node"], p["fn_op"], p["fn_res"]


def _result_type(e: E, value):
    return _vf(e, G_VTYPE, value)


def _constant_bytes(e: E, node, name: str):
    """The constant entity's value bytes as a little-endian word in ``name`` (declined above 8 bytes)."""
    p = e.p
    e.var(f"{name}_obj", _reference(e, _f(e, node, N_GRAPH), e.rd(e.sub(_f(e, node, N_OPSAT), 1))))
    _ok(e, e.ne(p[f"{name}_obj"], NONE))
    e.var(f"{name}_at", _at(e, G_PAY, p[f"{name}_obj"]))
    _payload_uleb(e, f"{name}_at")  # the type reference
    e.var(f"{name}_n", _payload_uleb(e, f"{name}_at"))
    _ok(e, e.le(p[f"{name}_n"], 8))
    e.var(name, 0)
    e.var(f"{name}_k", p[f"{name}_n"])
    e.while_(lambda: e.ne(p[f"{name}_k"], 0), lambda: (
        e.set(f"{name}_k", e.sub(p[f"{name}_k"], 1)), e.set(name, e.add(e.mul(p[name], 256), e.rd(e.add(p[f"{name}_at"], p[f"{name}_k"]))))))


def _int_node_fn(tables):
    """Division, width changes, arithmetic, rotation, constants, integer compares: 1, or 0 when not this group."""
    from xax_selfhost_general_emit import _cmp_rr

    def build(e: E):
        p = e.p
        node, op, result = _node_prelude(e)

        def division():
            _bits_width(e, _result_type(e, result), "fi_w")
            width = p["fi_w"]
            e.if_(e.not_(e.either(e.eq(width, 32), e.eq(width, 64))), lambda: _call(e, "width_reject", WIDTH_DIVISION, width))
            e.var("fi_bytes", e.sel(e.eq(width, 64), 8, 4))
            _load(e, RAX, _slot(e, p["fn_a"]), p["fi_bytes"])
            _constant_divisor(e, p["fn_b"], "fi_c")

            def guarded():
                _load(e, SCRATCH0, _slot(e, p["fn_b"]), p["fi_bytes"])
                e.var("fi_wr", width)
                _test10(e, p["fi_wr"])
                e.var("fi_ok", _new_label(e))
                _relative2(e, 0x850F, p["fi_ok"])
                _movabs(e, RAX, INTEGER_DIVIDE_BY_ZERO)
                _bx(e, 0x0B0F, 2)
                _label(e, p["fi_ok"])

            e.if_(e.eq(p["fi_c"], 0), guarded, lambda: _load(e, SCRATCH0, _slot(e, p["fn_b"]), p["fi_bytes"]))
            _zero32(e, RDX)
            e.if_(e.eq(width, 64), lambda: _bx(e, 0xF2F749, 3), lambda: _bx(e, 0xF2F741, 3))  # div r10
            _store(e, e.sel(e.eq(op, _op(Operation.UDIV)), RAX, RDX), _slot(e, result), 8)
            e.give(1)

        e.if_(_in(e, op, (_op(Operation.UDIV), _op(Operation.UREM))), division)

        def width_change():
            _load(e, RAX, _slot(e, p["fn_a"]), 8)
            e.if_(e.eq(op, _op(Operation.INT_TRUNCATE)), lambda: (_bits_width(e, _result_type(e, result), "fi_tw"), _ok(e, e.ne(p["fi_tw"], 0)), _mask_register(e, RAX, p["fi_tw"])))
            _store(e, RAX, _slot(e, result), 8)
            e.give(1)

        e.if_(_in(e, op, (_op(Operation.INT_TRUNCATE), _op(Operation.INT_ZERO_EXTEND))), width_change)

        def arithmetic():
            _bits_width(e, _result_type(e, result), "fi_w")
            width = p["fi_w"]
            e.var("fi_bytes", e.sel(e.eq(width, 64), 8, 4))
            _load(e, RAX, _slot(e, p["fn_a"]), p["fi_bytes"])
            _load(e, SCRATCH0, _slot(e, p["fn_b"]), p["fi_bytes"])
            # ``_arithmetic`` fails after the operands' loads (S12f.4); S15f.2: a width below 32 is done at 32 and masked.
            e.var("fi_narrow", e.flag(e.both(e.lt(0, width), e.lt(width, 32))))
            e.if_(e.not_(e.either(e.eq(width, 32), e.eq(width, 64), e.ne(p["fi_narrow"], 0))), lambda: _call(e, "width_reject", WIDTH_ARITHMETIC, width))
            for operation in ARITHMETIC_64:
                e.if_(e.eq(op, _op(operation)), lambda operation=operation: e.if_(e.eq(width, 64), lambda: _b(e, ARITHMETIC_64[operation]), lambda: _b(e, ARITHMETIC_32[operation])))
            e.if_(e.ne(p["fi_narrow"], 0), lambda: _mask_register(e, RAX, width))
            _store(e, RAX, _slot(e, result), 8)
            e.give(1)

        e.if_(_in(e, op, tuple(_op(o) for o in ARITHMETIC_64)), arithmetic)

        def rotate():
            _bits_width(e, _result_type(e, result), "fi_w")
            width = p["fi_w"]
            e.var("fi_amount", _attribute(e, node, 0))
            e.var("fi_bytes", e.sel(e.eq(width, 64), 8, 4))
            _load(e, RAX, _slot(e, p["fn_a"]), p["fi_bytes"])
            # ``_rotate_right_immediate`` fails after the operand's load (S12f.4).
            _set_ra(e, F_AMOUNT, p["fi_amount"])
            e.if_(e.not_(e.both(e.either(e.eq(width, 32), e.eq(width, 64)), e.lt(p["fi_amount"], width))),
                  lambda: _call(e, "width_reject", WIDTH_ROTATE, width))
            e.if_(e.eq(width, 64), lambda: _bx(e, 0x48, 1))
            _bx(e, 0xC8C1, 2)
            _bx(e, p["fi_amount"], 1)
            _store(e, RAX, _slot(e, result), 8)
            e.give(1)

        e.if_(e.eq(op, _op(Operation.ROTATE_RIGHT)), rotate)

        def constant():
            _constant_bytes(e, node, "fi_v")
            e.var("fi_t", _result_type(e, result))
            _movabs(e, RAX, p["fi_v"])

            def floating():
                _float_width(e, p["fi_t"], "fi_fw")
                _store(e, RAX, _slot(e, result), e.udiv(p["fi_fw"], 8))

            e.if_(_is_float(e, p["fi_t"]), floating, lambda: _store(e, RAX, _slot(e, result), 8))
            e.give(1)

        e.if_(e.eq(op, _op(Operation.CONSTANT)), constant)

        def compare():
            e.var("fi_ot", _vf(e, G_VTYPE, p["fn_a"]))
            _ok(e, e.eq(_form(e, p["fi_ot"]), 1))  # decode_bits_width
            _bits_width(e, p["fi_ot"], "fi_w")
            width = p["fi_w"]
            e.var("fi_bytes", e.sel(e.eq(width, 64), 8, 4))
            _load(e, RAX, _slot(e, p["fn_a"]), p["fi_bytes"])
            _load(e, SCRATCH0, _slot(e, p["fn_b"]), p["fi_bytes"])
            _cmp_rr(e, RAX, SCRATCH0, width)
            _call(e, "setcc", _attribute(e, node, 0), RAX, 1)
            _store(e, RAX, _slot(e, result), 8)
            e.give(1)

        e.if_(e.eq(op, _op(Operation.INT_COMPARE)), compare)
        e.give(0)
    return _function(("bi", "m"), build, tables)


def _constant_divisor(e: E, value, name: str):
    """``_constant_value(graph, value)`` or 0: the integer of a CONSTANT node producing ``value``."""
    from xax_selfhost_general_ranges import _is_param
    from xax_selfhost_general_view import G_VPROD

    p = e.p
    e.var(name, 0)
    e.var(f"{name}_node", e.sel(_is_param(e, value), NONE, _vf(e, G_VPROD, value)))

    def produced():
        e.if_(e.eq(_eop(e, p[f"{name}_node"]), _op(Operation.CONSTANT)), lambda: e.if_(
            e.eq(_form(e, _vf(e, G_VTYPE, value)), 1), lambda: (_constant_bytes(e, p[f"{name}_node"], f"{name}_v"), e.set(name, p[f"{name}_v"]))))

    e.if_(e.ne(p[f"{name}_node"], NONE), produced)


def _test10(e: E, width):
    """``_test_register(r10, width)``."""
    e.if_(e.eq(width, 64), lambda: _bx(e, 0xD2854D, 3), lambda: _bx(e, 0xD28545, 3))


def _relative2(e: E, opcode: int, label):
    """``assembler.relative`` with a two-byte opcode (``0f 8x``)."""
    from xax_selfhost_general_emit import _record_branch

    _bx(e, opcode, 2, True)
    _record_branch(e, label)
    _bx(e, 0, 4, True)


def _float_raw(e: E, exponent, width, negative: bool = False, extra_bit=None):
    """The raw bits of ``±2**exponent`` (optionally plus one mantissa bit ``extra_bit``) in binary32/binary64."""
    mantissa_bits = e.sel(e.eq(width, 32), 23, 52)
    bias = e.sel(e.eq(width, 32), 127, 1023)
    e.var("fr_mb", mantissa_bits)
    e.var("fr_scale", 1)
    e.for_("fr_k", 0, e.p["fr_mb"], lambda: e.set("fr_scale", e.mul(e.p["fr_scale"], 2)))
    value = e.mul(e.add(bias, exponent), e.p["fr_scale"])
    if negative:
        value = e.add(value, e.sel(e.eq(width, 32), 1 << 31, 1 << 63))
    if extra_bit is not None:
        value = e.add(value, extra_bit)
    return value


def _compare_with(e: E, raw, width):
    """``compare_with``: ``mov rax, raw; movq xmm1, rax; ucomis xmm0, xmm1``."""
    _movabs(e, RAX, raw)
    _mov_gpr_xmm(e, True, 1, RAX, width)
    _xmm_compare_registers(e, 0, 1, width)


def _float_node_fn(tables):
    """The SSE float operations, conversions, and compares (under the IEEE MXCSR): 1, or 0 when not this group."""
    def build(e: E):
        p = e.p
        node, op, result = _node_prelude(e)

        def binary():
            _float_width(e, _result_type(e, result), "ff_w")
            _begin_float(e)
            _xmm_memory(e, True, 0, _slot(e, p["fn_a"]), p["ff_w"])
            code = e.c(0)
            for operation, opcode in FLOAT_BINARY.items():
                code = e.add(code, e.mul(e.flag(e.eq(op, _op(operation))), opcode))
            e.var("ff_op", code)
            _float_prefix(e, p["ff_w"])
            _xmm_modrm(e, p["ff_op"], 0, _slot(e, p["fn_b"]))
            _xmm_memory(e, False, 0, _slot(e, result), p["ff_w"])
            _end_float(e)
            e.give(1)

        e.if_(_in(e, op, tuple(_op(o) for o in FLOAT_BINARY)), binary)

        def compare():
            _float_width(e, _vf(e, G_VTYPE, p["fn_a"]), "ff_w")
            _begin_float(e)
            _xmm_memory(e, True, 0, _slot(e, p["fn_a"]), p["ff_w"])
            _xmm_compare_memory(e, 0, _slot(e, p["fn_b"]), p["ff_w"])
            e.var("ff_kind", _attribute(e, node, 0))
            for kind, data in FLOAT_SETCC.items():
                e.if_(e.eq(p["ff_kind"], kind), lambda data=data: _b(e, data))
            _store(e, RAX, _slot(e, result), 8)
            _end_float(e)
            e.give(1)

        e.if_(e.eq(op, _op(Operation.FLOAT_COMPARE)), compare)

        def to_float():
            _float_width(e, _result_type(e, result), "ff_w")
            _bits_width(e, _vf(e, G_VTYPE, p["fn_a"]), "ff_sw")
            _ok(e, e.ne(p["ff_sw"], 0))
            e.var("ff_signed", e.flag(e.eq(op, _op(Operation.SINT_TO_FLOAT))))
            _begin_float(e)
            _load(e, RAX, _slot(e, p["fn_a"]), e.sel(e.le(p["ff_sw"], 32), 4, 8))
            e.if_(e.ne(p["ff_signed"], 0), lambda: e.if_(e.eq(p["ff_sw"], 32), lambda: _bx(e, 0xC06348, 3), lambda: e.if_(
                e.lt(p["ff_sw"], 64), lambda: (_bx(e, 0xE0C148, 3), _bx(e, e.sub(64, p["ff_sw"]), 1), _bx(e, 0xF8C148, 3), _bx(e, e.sub(64, p["ff_sw"]), 1)))))

            def single():
                _float_prefix(e, p["ff_w"])
                _bx(e, 0xC02A0F48, 4)  # cvtsi2s xmm0, rax

            def unsigned64():
                e.var("ff_large", _new_label(e))
                e.var("ff_done", _new_label(e))
                _bx(e, 0xC08548, 3)  # test rax, rax
                _relative2(e, 0x880F, p["ff_large"])
                single()
                _relative(e, 0xE9, p["ff_done"])
                _label(e, p["ff_large"])
                _bx(e, 0xC28949, 3)  # mov r10, rax
                _bx(e, 0xEAD149, 3)  # shr r10, 1
                _bx(e, 0x01E083, 3)  # and eax, 1
                _bx(e, 0xC20949, 3)  # or r10, rax
                _float_prefix(e, p["ff_w"])
                _bx(e, 0xC22A0F49, 4)  # cvtsi2s xmm0, r10
                _float_prefix(e, p["ff_w"])
                _bx(e, 0xC0580F, 3)  # adds xmm0, xmm0
                _label(e, p["ff_done"])

            e.if_(e.either(e.ne(p["ff_signed"], 0), e.lt(p["ff_sw"], 64)), single, unsigned64)
            _xmm_memory(e, False, 0, _slot(e, result), p["ff_w"])
            _end_float(e)
            e.give(1)

        e.if_(_in(e, op, (_op(Operation.UINT_TO_FLOAT), _op(Operation.SINT_TO_FLOAT))), to_float)

        def convert():
            _float_width(e, _vf(e, G_VTYPE, p["fn_a"]), "ff_sw")
            _float_width(e, _result_type(e, result), "ff_dw")
            _begin_float(e)
            _xmm_memory(e, True, 0, _slot(e, p["fn_a"]), p["ff_sw"])
            e.if_(e.both(e.eq(p["ff_sw"], 32), e.eq(p["ff_dw"], 64)), lambda: _bx(e, 0xC05A0FF3, 4))
            e.if_(e.both(e.eq(p["ff_sw"], 64), e.eq(p["ff_dw"], 32)), lambda: _bx(e, 0xC05A0FF2, 4))
            _xmm_memory(e, False, 0, _slot(e, result), p["ff_dw"])
            _end_float(e)
            e.give(1)

        e.if_(e.eq(op, _op(Operation.FLOAT_CONVERT)), convert)
        e.give(0)
    return _function(("bi", "m"), build, tables)


def _float_trunc_fn(tables):
    """The trapping float-to-integer truncations: 1, or 0 when not this group."""
    def build(e: E):
        p = e.p
        node, op, result = _node_prelude(e)

        def to_integer():
            _float_width(e, _vf(e, G_VTYPE, p["fn_a"]), "ff_w")
            w = p["ff_w"]
            _bits_width(e, _result_type(e, result), "ff_ow")
            _ok(e, e.both(e.ne(p["ff_ow"], 0), e.le(p["ff_ow"], 64)))
            ow = p["ff_ow"]
            e.var("ff_signed", e.flag(e.eq(op, _op(Operation.FLOAT_TO_SINT_TRUNC))))
            e.var("ff_trap", _new_label(e))
            e.var("ff_end", _new_label(e))

            def cvtt():
                _float_prefix(e, w)
                _bx(e, 0xC02C0F48, 4)

            _begin_float(e)
            _xmm_memory(e, True, 0, _slot(e, p["fn_a"]), w)

            def signed():
                # Fits iff -2**(w-1)-1 < v < 2**(w-1); when -2**(w-1)-1 is not representable, -2**(w-1) is the bound.
                e.var("ff_n", e.sub(ow, 1))
                precision = e.sel(e.eq(w, 32), 24, 53)
                exact = e.le(p["ff_n"], e.sub(precision, 1))

                def below_exact():
                    e.var("ff_extra", 0)

                    def bit():
                        e.set("ff_extra", 1)
                        e.for_("ff_k", 0, e.sub(e.sel(e.eq(w, 32), 23, 52), p["ff_n"]), lambda: e.set("ff_extra", e.mul(p["ff_extra"], 2)))

                    e.if_(e.eq(p["ff_n"], 0), lambda: _compare_with(e, _float_raw(e, 1, w, True), w),
                          lambda: (bit(), _compare_with(e, _float_raw(e, p["ff_n"], w, True, p["ff_extra"]), w)))
                    _relative2(e, 0x860F, p["ff_trap"])

                def below():
                    _compare_with(e, _float_raw(e, p["ff_n"], w, True), w)
                    _relative2(e, 0x820F, p["ff_trap"])

                e.if_(exact, below_exact, below)
                _compare_with(e, _float_raw(e, p["ff_n"], w), w)
                _relative2(e, 0x830F, p["ff_trap"])
                cvtt()
                _mask_register(e, RAX, ow)

            def unsigned():
                _movabs(e, RAX, 0)
                _mov_gpr_xmm(e, True, 1, RAX, w)
                _xmm_compare_registers(e, 0, 1, w)
                _relative2(e, 0x820F, p["ff_trap"])
                _compare_with(e, _float_raw(e, ow, w), w)
                _relative2(e, 0x830F, p["ff_trap"])

                def wide():
                    e.var("ff_small", _new_label(e))
                    e.var("ff_conv", _new_label(e))
                    _compare_with(e, _float_raw(e, 63, w), w)
                    _relative2(e, 0x820F, p["ff_small"])
                    _float_prefix(e, w)
                    _bx(e, 0xC15C0F, 3)  # subs xmm0, xmm1
                    cvtt()
                    _bx(e, 0x3FF8BA0F48, 5)  # btc rax, 63
                    _relative(e, 0xE9, p["ff_conv"])
                    _label(e, p["ff_small"])
                    cvtt()
                    _label(e, p["ff_conv"])

                e.if_(e.lt(ow, 64), cvtt, wide)

            e.if_(e.ne(p["ff_signed"], 0), signed, unsigned)
            _store(e, RAX, _slot(e, result), 8)
            _end_float(e)
            _relative(e, 0xE9, p["ff_end"])
            _label(e, p["ff_trap"])
            _end_float(e)
            _bx(e, 0x0B0F, 2)
            _label(e, p["ff_end"])
            e.give(1)

        e.if_(_in(e, op, (_op(Operation.FLOAT_TO_UINT_TRUNC), _op(Operation.FLOAT_TO_SINT_TRUNC))), to_integer)

        e.give(0)
    return _function(("bi", "m"), build, tables)


def _component_offset(e: E, type_obj, index, name: str):
    """``abi_layout(type).offsets[index]`` (tuples: C struct order; arrays: ``index * element size``)."""
    from xax_selfhost_general_ranges import _attribute as _unused  # noqa: F401

    p = e.p
    e.var(f"{name}_at", e.add(_at(e, G_PAY, type_obj), 1))
    e.var(name, 0)

    def tuple_():
        e.var(f"{name}_n", _payload_uleb(e, f"{name}_at"))
        e.var(f"{name}_cursor", 0)

        def component():
            e.var(f"{name}_item", _reference(e, type_obj, _payload_uleb(e, f"{name}_at")))
            e.var(f"{name}_size", _call(e, "abi_layout", p[f"{name}_item"]))
            e.var(f"{name}_align", e.ld(e.add(_g(e, _lalign_slot()), p[f"{name}_item"])))
            e.set(f"{name}_cursor", _align_to(e, p[f"{name}_cursor"], p[f"{name}_align"]))
            e.if_(e.eq(p[f"{name}_k"], index), lambda: e.set(name, p[f"{name}_cursor"]))
            e.set(f"{name}_cursor", e.add(p[f"{name}_cursor"], p[f"{name}_size"]))

        e.for_(f"{name}_k", 0, p[f"{name}_n"], component)

    def array():
        e.var(f"{name}_item", _reference(e, type_obj, _payload_uleb(e, f"{name}_at")))
        e.set(name, e.mul(index, _call(e, "abi_layout", p[f"{name}_item"])))

    e.if_(e.eq(_form(e, type_obj), 8), tuple_, lambda: e.if_(e.eq(_form(e, type_obj), 9), array, lambda: _ok(e, e.eq(1, 0))))


def _lalign_slot():
    from xax_selfhost_x86_64_general import G_LALIGN

    return G_LALIGN


def _payload_offset(e: E, type_obj, name: str):
    """A sum's ``payload_offset``: the tag's four bytes aligned to the variants' largest alignment."""
    p = e.p
    _call(e, "abi_layout", type_obj)
    e.var(f"{name}_at", e.add(_at(e, G_PAY, type_obj), 1))
    e.var(f"{name}_n", _payload_uleb(e, f"{name}_at"))
    e.var(f"{name}_align", 1)

    def variant():
        e.var(f"{name}_item", _reference(e, type_obj, _payload_uleb(e, f"{name}_at")))
        _call(e, "abi_layout", p[f"{name}_item"])
        e.var(f"{name}_ia", e.ld(e.add(_g(e, _lalign_slot()), p[f"{name}_item"])))
        e.if_(e.lt(p[f"{name}_align"], p[f"{name}_ia"]), lambda: e.set(f"{name}_align", p[f"{name}_ia"]))

    e.for_(f"{name}_k", 0, p[f"{name}_n"], variant)
    e.var(name, _align_to(e, 4, p[f"{name}_align"]))


def _dynamic_memory(e: E, node, op, result, extent, static_base):
    """``_emit_dynamic_memory``: a byte-addressed access through a first-class pointer (``static_base`` NONE) or a
    1/2-byte access of frame storage."""
    p = e.p
    e.var("dm_static", static_base)
    e.var("dm_base", RSP)
    e.var("dm_disp", p["dm_static"])

    def dynamic():
        e.set("dm_base", RCX)
        e.set("dm_disp", 0)
        _load(e, RCX, _slot(e, p["fn_a"]), 8)

    e.if_(e.eq(p["dm_static"], NONE), dynamic)
    e.var("dm_size", _attribute(e, node, 0))

    def load():
        _call(e, "load_exact", RAX, p["dm_base"], p["dm_disp"], p["dm_size"])
        _store(e, RAX, _slot(e, result), 8)
        e.give(1)

    e.if_(_in(e, op, (_op(Operation.LOAD_BITS_LE), _op(Operation.RAW_LOAD_BITS_LE))), load)

    def store():
        _load(e, RAX, _slot(e, p["fn_b"]), 8)
        _call(e, "store_exact", RAX, p["dm_base"], p["dm_disp"], p["dm_size"])
        e.give(1)

    e.if_(e.eq(op, _op(Operation.STORE_BITS_LE)), store)
    e.var("dm_extent", extent)
    e.if_(e.lt(p["dm_extent"], p["dm_size"]), lambda: (_bx(e, 0x0B0F, 2), e.give(1)))
    _load(e, SCRATCH0, _slot(e, p["fn_b"]), 4)
    _cmp_imm32(e, SCRATCH0, e.sub(p["dm_extent"], p["dm_size"]))
    e.var("dm_ok", _new_label(e))
    _relative2(e, 0x860F, p["dm_ok"])
    _bx(e, 0x0B0F, 2)
    _label(e, p["dm_ok"])

    def checked_load():
        e.if_(e.eq(p["dm_base"], RCX), lambda: _base_index(e, False, RAX, RCX, SCRATCH0, p["dm_disp"], p["dm_size"]),
              lambda: _base_index(e, False, RAX, RSP, SCRATCH0, p["dm_disp"], p["dm_size"]))
        _store(e, RAX, _slot(e, result), 8)

    def checked_store():
        _load(e, RAX, _slot(e, _operand(e, node, 2)), 8)
        e.if_(e.eq(p["dm_base"], RCX), lambda: _base_index(e, True, RAX, RCX, SCRATCH0, p["dm_disp"], p["dm_size"]),
              lambda: _base_index(e, True, RAX, RSP, SCRATCH0, p["dm_disp"], p["dm_size"]))

    e.if_(e.eq(op, _op(Operation.CHECKED_LOAD_BITS_LE)), checked_load, checked_store)
    e.give(1)


def _data_node_fn(tables):
    """Products, sums, function addresses, pointers, stack and heap memory: 1, or 0 when not this group."""
    def build(e: E):
        p = e.p
        node, op, result = _node_prelude(e)
        pointer = p["fn_a"]
        is_frame = lambda v: e.ne(_rt(e, T_FPTR, v), NONE)  # noqa: E731
        is_heap = lambda v: e.ne(_rt(e, T_FHROOT, v), NONE)  # noqa: E731

        def aggregate_make():
            e.var("fd_dest", _slot(e, result))
            _zero_bytes(e, RSP, p["fd_dest"], _slot_bytes(e, _rt(e, T_FSIZE, result)))

            def component():
                e.var("fd_o", _operand(e, node, p["fd_k"]))
                _component_offset(e, _result_type(e, result), p["fd_k"], "fd_off")
                _copy_bytes(e, RSP, e.add(p["fd_dest"], p["fd_off"]), RSP, _slot(e, p["fd_o"]), _rt(e, T_FSIZE, p["fd_o"]))

            e.for_("fd_k", 0, _f(e, node, N_NOPS), component)
            e.give(1)

        e.if_(e.eq(op, _op(Operation.AGGREGATE_MAKE)), aggregate_make)

        def aggregate_get():
            _component_offset(e, _vf(e, G_VTYPE, pointer), _attribute(e, node, 0), "fd_off")
            e.var("fd_dest", _slot(e, result))
            _zero_bytes(e, RSP, p["fd_dest"], _slot_bytes(e, _rt(e, T_FSIZE, result)))
            _copy_bytes(e, RSP, p["fd_dest"], RSP, e.add(_slot(e, pointer), p["fd_off"]), _rt(e, T_FSIZE, result))
            e.give(1)

        e.if_(e.eq(op, _op(Operation.AGGREGATE_GET)), aggregate_get)

        def sum_make():
            e.var("fd_dest", _slot(e, result))
            _zero_bytes(e, RSP, p["fd_dest"], _slot_bytes(e, _rt(e, T_FSIZE, result)))
            _movabs(e, RAX, _attribute(e, node, 0))
            _call(e, "store_exact", RAX, RSP, p["fd_dest"], 4)
            _payload_offset(e, _result_type(e, result), "fd_po")
            _copy_bytes(e, RSP, e.add(p["fd_dest"], p["fd_po"]), RSP, _slot(e, pointer), _rt(e, T_FSIZE, pointer))
            e.give(1)

        e.if_(e.eq(op, _op(Operation.SUM_MAKE)), sum_make)

        def sum_tag():
            _call(e, "load_exact", RAX, RSP, _slot(e, pointer), 4)
            _store(e, RAX, _slot(e, result), 8)
            e.give(1)

        e.if_(e.eq(op, _op(Operation.SUM_TAG)), sum_tag)

        def sum_get():
            e.var("fd_src", _slot(e, pointer))
            e.var("fd_ok", _new_label(e))
            _call(e, "load_exact", RAX, RSP, p["fd_src"], 4)
            _cmp_imm32(e, RAX, _attribute(e, node, 0))
            _relative2(e, 0x840F, p["fd_ok"])
            _bx(e, 0x0B0F, 2)
            _label(e, p["fd_ok"])
            e.var("fd_dest", _slot(e, result))
            _zero_bytes(e, RSP, p["fd_dest"], _slot_bytes(e, _rt(e, T_FSIZE, result)))
            _payload_offset(e, _vf(e, G_VTYPE, pointer), "fd_po")
            _copy_bytes(e, RSP, p["fd_dest"], RSP, e.add(p["fd_src"], p["fd_po"]), _rt(e, T_FSIZE, result))
            e.give(1)

        e.if_(e.eq(op, _op(Operation.SUM_GET)), sum_get)

        def function_address():
            from xax_selfhost_x86_64_general import EA_LEND, EA_SYSV

            e.var("fd_target", _reference(e, _f(e, node, N_GRAPH), e.rd(e.sub(_f(e, node, N_OPSAT), 1))))
            _ok(e, e.ne(p["fd_target"], NONE))
            e.var("fd_abi", _call(e, "entry_abi", _result_type(e, result)))
            _bx(e, 0x058D48, 3, True)  # lea rax, [rip + target]
            _record_call(e, p["fd_target"], e.flag(e.either(e.eq(p["fd_abi"], EA_SYSV), e.eq(p["fd_abi"], EA_LEND))))
            _bx(e, 0, 4, True)
            _store(e, RAX, _slot(e, result), 8)
            e.give(1)

        e.if_(e.eq(op, _op(Operation.FUNCTION_ADDRESS)), function_address)
        escaping = e.both(_in(e, op, (_op(Operation.STACK_ALLOC), _op(Operation.ADDRESS_OFFSET), _op(Operation.POINTER_CAST))),
                          e.ne(result, NONE), e.ne(_rt(e, T_FESC, e.sel(e.ne(result, NONE), result, 0)), 0))
        e.if_(escaping, lambda: (_lea(e, RAX, RSP, _rt(e, T_FPTR, result)), _store(e, RAX, _slot(e, result), 8), e.give(1)))
        dynamic_offset = e.both(e.ne(_ra(e, F_DYN), 0), e.eq(op, _op(Operation.ADDRESS_OFFSET)), e.not_(is_frame(result)), e.not_(is_heap(result)))
        e.if_(dynamic_offset, lambda: (_load(e, RAX, _slot(e, pointer), 8), _lea(e, RAX, RAX, _attribute(e, node, 0)), _store(e, RAX, _slot(e, result), 8), e.give(1)))
        e.give(0)
    return _function(("bi", "m"), build, tables)


def _memory_node_fn(tables):
    """The memory operations and the remaining pointer operations (after the calls): 1, or 0 when not this group."""
    def build(e: E):
        p = e.p
        node, op, result = _node_prelude(e)
        pointer = p["fn_a"]
        is_frame = lambda v: e.ne(_rt(e, T_FPTR, v), NONE)  # noqa: E731
        is_heap = lambda v: e.ne(_rt(e, T_FHROOT, v), NONE)  # noqa: E731
        e.var("fm_size", e.sel(e.ne(_attribute_count(e, node), 0), _attribute(e, node, 0), 0))
        size = p["fm_size"]
        dynamic = e.both(e.ne(_ra(e, F_DYN), 0), _in(e, op, DYNAMIC_MEMORY), e.not_(is_frame(pointer)), e.not_(is_heap(pointer)))

        def dynamic_access():
            e.var("fm_ext", 0)
            e.if_(_in(e, op, (_op(Operation.CHECKED_LOAD_BITS_LE), _op(Operation.CHECKED_STORE_BITS_LE))), lambda: e.set("fm_ext", _call(e, "extent", pointer)))
            _dynamic_memory(e, node, op, result, p["fm_ext"], NONE)

        e.if_(dynamic, dynamic_access)
        narrow = e.both(_in(e, op, tuple(_op(o) for o in (Operation.CHECKED_LOAD_BITS_LE, Operation.CHECKED_STORE_BITS_LE, Operation.LOAD_BITS_LE,
                                                            Operation.STORE_BITS_LE))), e.ne(size, 4), e.ne(size, 8), is_frame(pointer))
        e.if_(narrow, lambda: _dynamic_memory(e, node, op, result, _rt(e, T_FEXT, pointer), _rt(e, T_FPTR, pointer)))
        e.give(0)
    return _function(("bi", "m"), build, tables)


def _attribute_count(e: E, node):
    from xax_selfhost_general_regalloc import _attribute_count as count

    return count(e, node)


def _memory_tail_fn(tables):
    """The memory and pointer operations after the call cases (checked accesses with 4/8 bytes, frame and heap
    loads and stores, heap views, materialized heap addresses, pointer addresses, casts): 1, or 0."""
    def build(e: E):
        p = e.p
        node, op, result = _node_prelude(e)
        pointer = p["fn_a"]
        is_frame = lambda v: e.ne(_rt(e, T_FPTR, v), NONE)  # noqa: E731
        is_heap = lambda v: e.ne(_rt(e, T_FHROOT, v), NONE)  # noqa: E731

        def checked():
            e.var("ft_size", _attribute(e, node, 0))
            e.var("ft_ext", _rt(e, T_FEXT, pointer))
            _ok(e, e.ne(p["ft_ext"], NONE))
            e.if_(e.lt(p["ft_ext"], p["ft_size"]), lambda: (_bx(e, 0x0B0F, 2), e.give(1)))
            _load(e, SCRATCH0, _slot(e, p["fn_b"]), 4)
            _cmp_imm32(e, SCRATCH0, e.sub(p["ft_ext"], p["ft_size"]))
            e.var("ft_ok", _new_label(e))
            _relative2(e, 0x860F, p["ft_ok"])
            _bx(e, 0x0B0F, 2)
            _label(e, p["ft_ok"])
            store = e.eq(op, _op(Operation.CHECKED_STORE_BITS_LE))
            e.var("ft_store", e.flag(store))
            e.if_(e.ne(p["ft_store"], 0), lambda: _load(e, RAX, _slot(e, _operand(e, node, 2)), 8))

            def heap():
                _heap_base(e, pointer, "ft_off")
                e.if_(e.ne(p["ft_store"], 0), lambda: _base_index(e, True, RAX, SCRATCH1, SCRATCH0, p["ft_off"], p["ft_size"]),
                      lambda: _base_index(e, False, RAX, SCRATCH1, SCRATCH0, p["ft_off"], p["ft_size"]))

            def frame():
                e.if_(e.ne(p["ft_store"], 0), lambda: _indexed(e, 0x89, RAX, SCRATCH0, _rt(e, T_FPTR, pointer), p["ft_size"]),
                      lambda: _indexed(e, 0x8B, RAX, SCRATCH0, _rt(e, T_FPTR, pointer), p["ft_size"]))

            e.if_(is_frame(pointer), frame, lambda: (_ok(e, is_heap(pointer)), heap()))
            e.if_(e.eq(p["ft_store"], 0), lambda: _store(e, RAX, _slot(e, result), 8))
            e.give(1)

        e.if_(_in(e, op, (_op(Operation.CHECKED_LOAD_BITS_LE), _op(Operation.CHECKED_STORE_BITS_LE))), checked)

        def raw_frame():
            _load(e, RAX, _rt(e, T_FPTR, pointer), _attribute(e, node, 0))
            _store(e, RAX, _slot(e, result), 8)
            e.give(1)

        e.if_(e.both(e.eq(op, _op(Operation.RAW_LOAD_BITS_LE)), is_frame(pointer)), raw_frame)
        _ok(e, e.ne(op, _op(Operation.RAW_LOAD_BITS_LE)))  # ``pointers[op0]`` raises for any other raw load

        def heap_store():
            _load(e, RAX, _slot(e, p["fn_b"]), 8)
            _heap_base(e, pointer, "ft_off")
            _call(e, "store_exact", RAX, SCRATCH1, p["ft_off"], _attribute(e, node, 0))
            e.give(1)

        e.if_(e.both(e.eq(op, _op(Operation.STORE_BITS_LE)), is_heap(pointer)), heap_store)

        def heap_load():
            _heap_base(e, pointer, "ft_off")
            _call(e, "load_exact", RAX, SCRATCH1, p["ft_off"], _attribute(e, node, 0))
            _store(e, RAX, _slot(e, result), 8)
            e.give(1)

        e.if_(e.both(_in(e, op, (_op(Operation.LOAD_BITS_LE), _op(Operation.RAW_LOAD_BITS_LE))), is_heap(pointer)), heap_load)

        def heap_view():
            _load(e, RAX, _slot(e, pointer), 8)
            _bx(e, 0xC08548, 3)  # test rax, rax
            e.var("ft_nonnull", _new_label(e))
            _relative2(e, 0x850F, p["ft_nonnull"])
            _bx(e, 0x0B0F, 2)
            _label(e, p["ft_nonnull"])
            _store(e, RAX, _slot(e, result), 8)
            e.give(1)

        e.if_(e.eq(op, _op(Operation.HEAP_VIEW)), heap_view)

        def heap_address():
            _heap_base(e, result, "ft_off")
            _lea(e, RAX, SCRATCH1, p["ft_off"])
            _store(e, RAX, _slot(e, result), 8)
            e.give(1)

        e.if_(e.both(_in(e, op, (_op(Operation.ADDRESS_OFFSET), _op(Operation.POINTER_CAST))), e.ne(result, NONE), is_heap(result)), heap_address)
        e.if_(e.eq(op, _op(Operation.LINK_TARGET)), lambda: e.give(1))
        # LINK_MAKE, LINK_FOLLOW, POINTER_REBASE: the bootstrap rejects them on this path (S12f.4, ADR-280).
        e.if_(_in(e, op, (_op(Operation.LINK_MAKE), _op(Operation.LINK_FOLLOW))), lambda: _call(e, "fixed_reject", LINK_REJECTION))
        e.if_(e.eq(op, _op(Operation.POINTER_REBASE)), lambda: _call(e, "fixed_reject", REBASE_REJECTION))

        def pointer_address():
            from xax_selfhost_general_rejects import ADDRESS_POINTER_WIDTH

            _bits_width(e, _result_type(e, result), "ft_w")
            e.if_(e.ne(p["ft_w"], 64), lambda: _call(e, "pointer_width_reject", ADDRESS_POINTER_WIDTH, 64, p["ft_w"], _ra(e, F_FN)))
            e.if_(is_frame(pointer), lambda: _lea(e, RAX, RSP, _rt(e, T_FPTR, pointer)), lambda: e.if_(
                is_heap(pointer), lambda: (_heap_base(e, pointer, "ft_off"), _lea(e, RAX, SCRATCH1, p["ft_off"])),
                lambda: _load(e, RAX, _slot(e, pointer), 8)))
            _store(e, RAX, _slot(e, result), 8)
            e.give(1)

        e.if_(e.eq(op, _op(Operation.POINTER_ADDRESS)), pointer_address)

        def frame_store():
            _ok(e, is_frame(pointer))
            _load(e, RAX, _slot(e, p["fn_b"]), 8)
            _store(e, RAX, _rt(e, T_FPTR, pointer), _attribute(e, node, 0))
            e.give(1)

        e.if_(e.eq(op, _op(Operation.STORE_BITS_LE)), frame_store)

        def frame_load():
            _ok(e, is_frame(pointer))
            _load(e, RAX, _rt(e, T_FPTR, pointer), _attribute(e, node, 0))
            _store(e, RAX, _slot(e, result), 8)
            e.give(1)

        e.if_(e.eq(op, _op(Operation.LOAD_BITS_LE)), frame_load)

        def cast():
            e.if_(e.not_(is_frame(result)), lambda: (_load(e, RAX, _slot(e, pointer), 8), _store(e, RAX, _slot(e, result), 8)))
            e.give(1)

        e.if_(e.eq(op, _op(Operation.POINTER_CAST)), cast)
        quiet = tuple(_op(o) for o in (Operation.STACK_ALLOC, Operation.ADDRESS_OFFSET, Operation.STACK_END, *RESOURCE_EFFECT_OPERATIONS))
        _ok(e, _in(e, op, quiet))  # the bootstrap fails (NATIVE-OP-LOWERED)
        e.give(1)
    return _function(("bi", "m"), build, tables)


# -- calls ----------------------------------------------------------------------------------------------------------

def _store_call_result(e: E, node):
    """The first machine result of a call: xmm0 for a float, rax masked to its value width otherwise (``mask``) or
    for a direct/indirect call an aggregate's bytes; stored to its slot."""
    p = e.p
    _machine_results(e, node, "sr_r")

    def store():
        e.var("sr_v", p["sr_r_first"])
        e.var("sr_t", _vf(e, G_VTYPE, p["sr_v"]))
        e.if_(_is_float(e, p["sr_t"]), lambda: (_float_width(e, p["sr_t"], "sr_fw"), _xmm_memory(e, False, 0, _slot(e, p["sr_v"]), p["sr_fw"])),
              lambda: e.if_(_is_aggregate(e, p["sr_t"]), lambda: (
                  _zero_bytes(e, RSP, _slot(e, p["sr_v"]), 8, temp=SCRATCH0), _call(e, "store_exact", RAX, RSP, _slot(e, p["sr_v"]), _rt(e, T_FSIZE, p["sr_v"]))),
                  lambda: _store(e, RAX, _slot(e, p["sr_v"]), 8)))

    e.if_(e.ne(p["sr_r_first"], NONE), store)


def _store_foreign_result(e: E, node):
    """``mask_register(rax, value width or 64)`` then the slot, or xmm0 for a float."""
    p = e.p
    _machine_results(e, node, "sf_r")

    def store():
        e.var("sf_v", p["sf_r_first"])
        e.var("sf_t", _vf(e, G_VTYPE, p["sf_v"]))

        def integer():
            _value_width(e, p["sf_t"], "sf_w")
            _mask_register(e, RAX, e.sel(e.eq(p["sf_w"], 0), 64, p["sf_w"]))
            _store(e, RAX, _slot(e, p["sf_v"]), 8)

        e.if_(_is_float(e, p["sf_t"]), lambda: (_float_width(e, p["sf_t"], "sf_fw"), _xmm_memory(e, False, 0, _slot(e, p["sf_v"]), p["sf_fw"])), integer)

    e.if_(e.ne(p["sf_r_first"], NONE), store)


def _value_width(e: E, type_obj, name: str):
    """``_value_width`` for the INTEGER-class carriers: bits (<= 64), a pointer or link 64; 0 otherwise."""
    p = e.p
    e.var(f"{name}_f", _form(e, type_obj))
    e.var(name, 0)
    e.if_(e.either(e.eq(p[f"{name}_f"], 2), e.eq(p[f"{name}_f"], 11)), lambda: e.set(name, 64))

    def bits():
        _bits_width(e, type_obj, f"{name}_b")
        e.if_(e.le(p[f"{name}_b"], 64), lambda: e.set(name, p[f"{name}_b"]))

    e.if_(e.eq(p[f"{name}_f"], 1), bits)


def _integer_class(e: E, type_obj):
    """``_sysv_integer_class``: bits <= 64, a pointer, or a link."""
    form = _form(e, type_obj)
    e.var("ic_f", form)
    e.var("ic_ok", e.flag(e.either(e.eq(e.p["ic_f"], 2), e.eq(e.p["ic_f"], 11))))

    def bits():
        _bits_width(e, type_obj, "ic_b")
        e.if_(e.both(e.ne(e.p["ic_b"], 0), e.le(e.p["ic_b"], 64)), lambda: e.set("ic_ok", 1))

    e.if_(e.eq(e.p["ic_f"], 1), bits)
    return e.ne(e.p["ic_ok"], 0)


def _foreign_node_fn(tables):
    """``CALL_FOREIGN`` of a Linux syscall or a SysV C import on the frame path: 1, or 0 when not this case."""
    from xax_selfhost_general_emit import SYSCALL_HEADER, _foreign_abi

    def build(e: E):
        p = e.p
        node, op, result = _node_prelude(e)
        e.if_(e.ne(op, _op(Operation.CALL_FOREIGN)), lambda: e.give(0))
        e.var("fc_obj", _reference(e, _f(e, node, N_GRAPH), e.rd(e.sub(_f(e, node, N_OPSAT), 1))))
        _ok(e, e.ne(p["fc_obj"], NONE))
        _machine_inputs(e, node, 0, "fc_n")
        _machine_results(e, node, "fc_r")
        _foreign_abi(e, p["fc_obj"], "fc_sysv")
        e.var("fc_rec", _call(e, "syscall", p["fc_obj"], p["fc_n"]))
        from xax_selfhost_general_rejects import ABI_SYSCALL, foreign_identity

        foreign_identity(e, p["fc_obj"], "fc_abi")

        def syscall_checks():
            """``_linux_syscall``: SYSCALL-ONE-RESULT (the node's results), then the name (``decode_syscall_name``)."""
            e.if_(e.lt(1, p["fc_r"]), lambda: _call(e, "one_result_reject", _ra(e, F_FN), _f(e, node, N_NRES)))
            e.if_(e.eq(p["fc_rec"], 0), lambda: _call(e, "template_reject", p["fc_obj"], p["fc_n"]))

        from xax_selfhost_x86_64_general import G_TABI, G_WINDOWS, LINUX_ABI

        def syscall_target():
            """``_linux_syscall`` on Windows: NATIVE-FOREIGN-ABI-TARGET (the syscall ABI and the Linux ABI)."""
            import xax_selfhost_diagnostics as D
            from xax_selfhost_general_emit import E_F, _e, graph_cid_words, reject_at

            def write():
                D.text(e, "XAX.NATIVE.FOREIGN_ABI")
                D.cid(e, graph_cid_words(e, _e(e, E_F)))
                D.text(e, "NATIVE-FOREIGN-ABI-TARGET")
                D.put(e, D.T_LIST), D.put(e, 2), D.text(e, "linux-x86_64-syscall-v1"), D.integer(e, LINUX_ABI)
                D.put(e, D.T_LIST), D.put(e, 2), D.text(e, "linux-x86_64-syscall-v1"), D.integer(e, _g(e, G_TABI))

            reject_at(e, write)

        e.if_(e.both(e.eq(p["fc_abi"], ABI_SYSCALL), e.ne(_g(e, G_WINDOWS), 0)), syscall_target)
        e.if_(e.eq(p["fc_abi"], ABI_SYSCALL), syscall_checks)
        e.var("fc_start", 0)
        from xax_selfhost_general_emit import _startup_name

        _startup_name(e, p["fc_obj"], "fc_start")
        e.if_(e.both(e.eq(p["fc_sysv"], 0), e.either(e.eq(p["fc_rec"], 0), e.ne(p["fc_start"], 0))), lambda: e.give(0))  # another ABI: the call path

        def operand_at(index, name):
            """The ``index``-th machine operand into ``name``."""
            e.var(name, NONE)
            e.var(f"{name}_c", 0)

            def each():
                e.var(f"{name}_o", _operand(e, node, p[f"{name}_k"]))

                def machine():
                    e.if_(e.eq(p[f"{name}_c"], index), lambda: e.set(name, p[f"{name}_o"]))
                    e.set(f"{name}_c", e.add(p[f"{name}_c"], 1))

                e.if_(e.not_(_proof(e, _vf(e, G_VTYPE, p[f"{name}_o"]))), machine)

            e.for_(f"{name}_k", 0, _f(e, node, N_NOPS), each)

        def sysv():
            from xax_selfhost_x86_64_general import G_TFMT

            from xax_selfhost_general_emit import reject_at, write_dynamic_profile

            e.if_(e.either(e.ne(_g(e, G_TFMT), 6), e.ne(_g(e, G_TABI), LINUX_ABI)), lambda: reject_at(e, lambda: write_dynamic_profile(e)))

            def scalar_class():
                """``_emit_sysv_c_call``: outside the lowered register-passed subset."""
                def write():
                    import xax_selfhost_diagnostics as D
                    from xax_selfhost_general_emit import E_F, _e, graph_cid_words

                    D.text(e, "XAX.NATIVE.FOREIGN_ABI")
                    D.cid(e, graph_cid_words(e, _e(e, E_F)))
                    D.text(e, "SYSV-C-SCALAR-CLASS")
                    D.text(e, "<=6 INTEGER and <=8 SSE scalar arguments, <=1 scalar result")
                    D.put(e, D.T_LIST)
                    D.put(e, 2)
                    D.integer(e, p["fc_n"])
                    D.integer(e, p["fc_r"])

                reject_at(e, write)

            e.if_(e.lt(1, p["fc_r"]), scalar_class)
            e.var("fc_ints", 0)
            e.var("fc_vecs", 0)

            def argument():
                e.var("fc_o", _operand(e, node, p["fc_k"]))
                e.var("fc_t", _vf(e, G_VTYPE, p["fc_o"]))

                def machine():
                    def sse():
                        _float_width(e, p["fc_t"], "fc_fw")
                        _xmm_memory(e, True, p["fc_vecs"], _slot(e, p["fc_o"]), p["fc_fw"])
                        e.set("fc_vecs", e.add(p["fc_vecs"], 1))

                    def gpr():
                        e.if_(e.not_(e.both(_integer_class(e, p["fc_t"]), e.lt(p["fc_ints"], 6))), scalar_class)
                        e.var("fc_reg", _select(e, p["fc_ints"], SYSV_REGISTERS))
                        _load(e, p["fc_reg"], _slot(e, p["fc_o"]), 8)
                        e.set("fc_ints", e.add(p["fc_ints"], 1))

                    e.if_(e.both(_is_float(e, p["fc_t"]), e.lt(p["fc_vecs"], 8)), sse, gpr)

                e.if_(e.not_(_proof(e, p["fc_t"])), machine)

            e.for_("fc_k", 0, _f(e, node, N_NOPS), argument)
            # The result's class (at most one scalar).
            e.if_(e.ne(p["fc_r_first"], NONE), lambda: (e.var("fc_rt", _vf(e, G_VTYPE, p["fc_r_first"])),
                                                         e.if_(e.not_(e.either(_is_float(e, p["fc_rt"]), _integer_class(e, p["fc_rt"]))), scalar_class)))
            _bx(e, 0x15FF, 2, True)
            _record_call(e, p["fc_obj"], 0)
            _bx(e, 0, 4, True)

        def syscall():

            def item():
                e.var("fc_tag", e.ld(e.add(p["fc_rec"], e.add(SYSCALL_HEADER, e.mul(p["fc_i"], 2)))))
                e.var("fc_val", e.ld(e.add(p["fc_rec"], e.add(SYSCALL_HEADER + 1, e.mul(p["fc_i"], 2)))))
                e.var("fc_reg", _select(e, p["fc_i"], SYSCALL_REGISTERS))
                e.if_(e.eq(p["fc_tag"], 0), lambda: (operand_at(p["fc_val"], "fc_arg"), _load(e, p["fc_reg"], _slot(e, p["fc_arg"]), 8)),
                      lambda: _movabs_any(e, p["fc_reg"], p["fc_val"]))

            e.for_("fc_i", 0, e.ld(e.add(p["fc_rec"], 1)), item)
            _bx(e, 0xB8, 1)
            _bx(e, e.ld(p["fc_rec"]), 4)
            _bx(e, 0x050F, 2)
            from xax_selfhost_general_emit import NULL_ON_ERROR

            e.if_(e.ne(e.ld(e.add(p["fc_rec"], 2)), 0), lambda: _b(e, NULL_ON_ERROR))

        e.if_(e.ne(p["fc_sysv"], 0), sysv, syscall)
        _store_foreign_result(e, node)
        e.give(1)
    return _function(("bi", "m"), build, tables)


def _select(e: E, index, items):
    result = e.c(items[-1])
    for position in range(len(items) - 2, -1, -1):
        result = e.sel(e.eq(index, position), items[position], result)
    return result


def _movabs_any(e: E, register, value):
    """``_immediate(register, value)`` for a computed register."""
    _bx(e, e.add(e.add(0x48, e.flag(e.le(8, register))), e.mul(e.add(0xB8, e.and_(register, 7)), 256)), 2)
    _bx(e, value, 8)


def _call_node_fn(tables):
    """Direct, indirect and (S15e.3, Windows) ``win64-c`` foreign calls (the internal convention: four argument
    registers, then the stack after the shadow space).  A foreign call the foreign node did not lower takes the
    bootstrap's Win64 call path (``_win64_foreign_call``): any ABI but ``win64-c`` is NATIVE-FOREIGN-ABI, a malformed
    COM method WIN64-COM-METHOD; a ``win64-c`` call on Linux declines."""
    from xax_selfhost_general_rejects import COM_MALFORMED
    from xax_selfhost_x86_64_general import G_WINDOWS

    def build(e: E):
        p = e.p
        node, op, result = _node_prelude(e)
        e.if_(e.not_(_in(e, op, CALLS)), lambda: e.give(0))
        e.var("cl_obj", NONE)
        e.var("cl_com", NONE)

        def foreign():
            from xax_selfhost_general_rejects import ABI_WIN64_C, foreign_identity

            e.set("cl_obj", _reference(e, _f(e, node, N_GRAPH), e.rd(e.sub(_f(e, node, N_OPSAT), 1))))
            _ok(e, e.ne(p["cl_obj"], NONE))
            foreign_identity(e, p["cl_obj"], "cl_abi")

            def win64():
                _ok(e, e.ne(_g(e, G_WINDOWS), 0))
                e.set("cl_com", e.call(_FN["com_method"], p["cl_obj"]))
                e.if_(e.eq(p["cl_com"], COM_MALFORMED), lambda: _call(e, "com_reject", p["cl_obj"], _ra(e, F_FN)))

            e.if_(e.eq(p["cl_abi"], ABI_WIN64_C), win64, lambda: _call(e, "abi_reject", p["cl_obj"], _ra(e, F_FN), 1))

        e.if_(e.eq(op, _op(Operation.CALL_FOREIGN)), foreign)
        _machine_results(e, node, "cl_r")

        def arity():
            """NATIVE-CALL-ARITY: the machine arguments (an indirect call's target not counted, a hidden result pointer
            counted) and results."""
            _machine_inputs(e, node, 0, "cl_mi")
            _hidden_result(e, p["cl_r_first"], "cl_h0")
            arguments = e.add(e.sub(p["cl_mi"], e.flag(e.eq(op, _op(Operation.CALL_INDIRECT)))), p["cl_h0"])
            _call(e, "arity_reject", arguments, p["cl_r"], _ra(e, F_FN))

        e.if_(e.lt(1, p["cl_r"]), arity)
        e.var("cl_indirect", e.flag(e.eq(op, _op(Operation.CALL_INDIRECT))))
        e.var("cl_pos", 0)
        e.var("cl_seen", 0)  # machine operands seen (the first is the callee of an indirect call)
        e.var("cl_node", node)
        _hidden_result(e, p["cl_r_first"], "cl_hidden")

        # Each by-reference argument's caller-owned copy first.
        def copy():
            e.var("cl_o", _operand(e, node, p["cl_k"]))
            e.var("cl_t", _vf(e, G_VTYPE, p["cl_o"]))

            def aggregate():
                e.var("cl_size", _rt(e, T_FSIZE, p["cl_o"]))
                e.if_(_by_reference(e, p["cl_t"], p["cl_size"]), lambda: _copy_bytes(e, RSP, _copy_at(e, node, p["cl_k"]), RSP, _slot(e, p["cl_o"]), p["cl_size"]))

            e.if_(e.both(e.not_(_proof(e, p["cl_t"])), _is_aggregate(e, p["cl_t"])), aggregate)

        e.for_("cl_k", 0, _f(e, node, N_NOPS), copy)

        # The bootstrap loads the callee first, then the arguments in order.
        def callee_first():
            def find():
                e.var("cl_o", _operand(e, node, p["cl_k"]))
                e.if_(e.both(e.eq(p["cl_seen"], 0), e.not_(_proof(e, _vf(e, G_VTYPE, p["cl_o"])))),
                      lambda: (_load(e, SCRATCH1, _slot(e, p["cl_o"]), 8), e.set("cl_seen", 1)))

            e.for_("cl_k", 0, _f(e, node, N_NOPS), find)
            e.set("cl_seen", 0)

        e.if_(e.ne(p["cl_indirect"], 0), callee_first)
        e.if_(e.ne(p["cl_hidden"], 0), lambda: (_lea_any(e, ARGUMENT_REGISTERS[0], RSP, _slot(e, p["cl_r_first"])), e.set("cl_pos", 1)))

        def operand_skip_callee():
            e.var("cl_o", _operand(e, node, p["cl_k"]))
            e.var("cl_t", _vf(e, G_VTYPE, p["cl_o"]))

            def machine():
                e.if_(e.both(e.ne(p["cl_indirect"], 0), e.eq(p["cl_seen"], 0)), lambda: None, lambda: _argument(e, p))
                e.set("cl_seen", e.add(p["cl_seen"], 1))

            e.if_(e.not_(_proof(e, p["cl_t"])), machine)

        e.for_("cl_k", 0, _f(e, node, N_NOPS), operand_skip_callee)

        def direct():
            _callee_object(e, node, "cl_callee")
            _ok(e, e.ne(p["cl_callee"], NONE))

            def call():
                _bx(e, 0xE8, 1, True)
                _record_call(e, p["cl_callee"], 0)
                _bx(e, 0, 4, True)

            e.if_(e.eq(_call(e, "erased", p["cl_callee"]), 0), call)

        def imported():
            """``mov rax, [rcx]; call [rax + 8k]`` for a COM method, else ``call [rip + slot]`` (the image binds it)."""
            e.if_(e.ne(p["cl_com"], NONE), lambda: (_bx(e, 0xFF018B48, 4, True), _bx(e, 0x90, 1, True), _bx(e, e.mul(p["cl_com"], 8), 4, True)),
                  lambda: (_bx(e, 0x15FF, 2, True), _record_call(e, p["cl_obj"], 0), _bx(e, 0, 4, True)))

        e.if_(e.ne(p["cl_indirect"], 0), lambda: _bx(e, 0xD3FF41, 3), lambda: e.if_(e.eq(op, _op(Operation.CALL_FOREIGN)), imported, direct))  # call r11
        e.if_(e.eq(p["cl_hidden"], 0), lambda: _store_call_result(e, node))
        e.give(1)
    return _function(("bi", "m"), build, tables)


def _argument(e: E, p):
    """One machine argument of a direct or indirect call at position ``cl_pos`` (register or stack)."""
    e.var("cl_byref", 0)
    e.if_(_is_aggregate(e, p["cl_t"]), lambda: e.set("cl_byref", e.flag(_by_reference(e, p["cl_t"], _rt(e, T_FSIZE, p["cl_o"])))))

    def register():
        e.var("cl_reg", _select(e, p["cl_pos"], ARGUMENT_REGISTERS))
        e.if_(_is_float(e, p["cl_t"]), lambda: (_float_width(e, p["cl_t"], "cl_fw"), _xmm_memory(e, True, p["cl_pos"], _slot(e, p["cl_o"]), p["cl_fw"])),
              lambda: e.if_(e.ne(p["cl_byref"], 0), lambda: _lea_any(e, p["cl_reg"], RSP, _copy_at(e, p["cl_node"], p["cl_k"])),
                            lambda: e.if_(e.ne(_rt(e, T_FPTR, p["cl_o"]), NONE), lambda: _lea_any(e, p["cl_reg"], RSP, _rt(e, T_FPTR, p["cl_o"])),
                                          lambda: _load(e, p["cl_reg"], _slot(e, p["cl_o"]), 8))))

    def stack():
        e.var("cl_out", e.add(SHADOW, e.mul(e.sub(p["cl_pos"], 4), 8)))

        def floating():
            _float_width(e, p["cl_t"], "cl_fw")
            _xmm_memory(e, True, 4, _slot(e, p["cl_o"]), p["cl_fw"])
            _xmm_memory(e, False, 4, p["cl_out"], p["cl_fw"])

        def aggregate():
            _call(e, "load_exact", SCRATCH0, RSP, _slot(e, p["cl_o"]), _rt(e, T_FSIZE, p["cl_o"]))
            _call(e, "store_exact", SCRATCH0, RSP, p["cl_out"], _rt(e, T_FSIZE, p["cl_o"]))

        def scalar():
            e.if_(e.ne(_rt(e, T_FPTR, p["cl_o"]), NONE), lambda: _lea(e, SCRATCH0, RSP, _rt(e, T_FPTR, p["cl_o"])),
                  lambda: _load(e, SCRATCH0, _slot(e, p["cl_o"]), 8))
            _store(e, SCRATCH0, p["cl_out"], 8)

        def by_reference():
            _lea_any(e, SCRATCH0, RSP, _copy_at(e, p["cl_node"], p["cl_k"]))
            _store(e, SCRATCH0, p["cl_out"], 8)

        e.if_(_is_float(e, p["cl_t"]), floating, lambda: e.if_(e.ne(p["cl_byref"], 0), by_reference, lambda: e.if_(_is_aggregate(e, p["cl_t"]), aggregate, scalar)))

    e.if_(e.lt(p["cl_pos"], 4), register, stack)
    e.set("cl_pos", e.add(p["cl_pos"], 1))


def _lea_any(e: E, register, base: int, offset):
    """``_lea`` for a computed register."""
    _lea(e, register, base, offset)


FENCES = {1: None, 2: 0xE8AE0F, 3: 0xF8AE0F, 4: 0xF0AE0F, 5: 0xF0AE0F}  # ``_fence``: acquire lfence, release sfence, mfence
SEQ_CST = 5


def _atomic_access(e: E, opcodes: int, count: int, register: int, offset, size, locked):
    """``_atomic_memory_instruction`` on ``[rsp + offset]`` (``size`` 4 or 8; NATIVE-ATOMIC-ENCODABLE otherwise)."""
    from xax_selfhost_general_rejects import ATOMIC, encoding_reject

    e.if_(e.not_(e.both(e.either(e.eq(size, 4), e.eq(size, 8)), e.lt(offset, 1 << 31))), lambda: encoding_reject(e, ATOMIC, size, offset))
    e.if_(e.ne(locked, 0), lambda: _bx(e, 0xF0, 1))
    e.var("aa_rex", e.add(e.add(0x40, e.mul(e.flag(e.eq(size, 8)), 8)), 4 if register >= 8 else 0))
    e.if_(e.ne(e.p["aa_rex"], 0x40), lambda: _bx(e, e.p["aa_rex"], 1))
    _bx(e, opcodes, count)
    head = 0x44 | ((register & 7) << 3)
    e.if_(e.lt(offset, 128), lambda: (_bx(e, head + 0x2400, 2), _bx(e, offset, 1)),
          lambda: (_bx(e, (head | 0x80) + 0x2400, 2), _bx(e, offset, 4)))


def _atomic_node_fn(tables):
    """The frame path's atomics (``_compile_function``): fences, and loads, stores, read-modify-writes, and
    compare-exchanges of stack storage; a heap view rejects (NATIVE-ATOMIC-STACK-STORAGE): 1, or 0 when not this group."""
    from xax_compiler import AtomicRmwKind

    def build(e: E):
        p = e.p
        node, op, result = _node_prelude(e)
        e.if_(e.not_(_in(e, op, ATOMICS)), lambda: e.give(0))

        def fence():
            e.var("an_order", _attribute(e, node, 0))
            _ok(e, e.both(e.le(2, p["an_order"]), e.le(p["an_order"], 5)))
            for order, word in FENCES.items():
                if word is not None:
                    e.if_(e.eq(p["an_order"], order), lambda word=word: _bx(e, word, 3))
            e.give(1)

        e.if_(e.eq(op, _op(Operation.ATOMIC_FENCE)), fence)
        e.var("an_ptr", _operand(e, node, 0))

        def heap():
            from xax_selfhost_general_emit import E_F, _e, graph_cid_words, reject_at
            import xax_selfhost_diagnostics as D

            def write():
                D.text(e, "XAX.NATIVE.POINTER")
                D.cid(e, graph_cid_words(e, _e(e, E_F)))
                D.text(e, "NATIVE-ATOMIC-STACK-STORAGE")
                D.text(e, "stack storage")
                D.text(e, "heap view")

            reject_at(e, write)

        e.if_(e.ne(_rt(e, T_FHROOT, p["an_ptr"]), NONE), heap)
        e.var("an_at", _rt(e, T_FPTR, p["an_ptr"]))
        _ok(e, e.ne(p["an_at"], NONE))  # neither: the bootstrap has no frame offset for it
        at = p["an_at"]

        def size_of(type_obj):
            _bits_width(e, type_obj, "an_w")
            e.var("an_size", e.udiv(p["an_w"], 8))

        def load():
            size_of(_result_type(e, result))
            _load(e, RAX, at, p["an_size"])
            e.if_(e.eq(_attribute(e, node, 0), SEQ_CST), lambda: _bx(e, FENCES[SEQ_CST], 3))
            _store(e, RAX, _slot(e, result), 8)
            e.give(1)

        e.if_(e.eq(op, _op(Operation.ATOMIC_LOAD)), load)

        def store():
            e.var("an_v", _operand(e, node, 1))
            size_of(_vf(e, G_VTYPE, p["an_v"]))
            _load(e, RAX, _slot(e, p["an_v"]), 8)
            e.if_(e.eq(_attribute(e, node, 0), SEQ_CST), lambda: _atomic_access(e, 0x87, 1, RAX, at, p["an_size"], 0),
                  lambda: _store(e, RAX, at, p["an_size"]))
            e.give(1)

        e.if_(e.eq(op, _op(Operation.ATOMIC_STORE)), store)

        def rmw():
            size_of(_result_type(e, result))
            _load(e, RAX, _slot(e, _operand(e, node, 1)), 8)
            e.var("an_kind", _attribute(e, node, 0))
            exchange = e.eq(p["an_kind"], int(AtomicRmwKind.EXCHANGE))
            e.if_(exchange, lambda: _atomic_access(e, 0x87, 1, RAX, at, p["an_size"], 0),
                  lambda: _atomic_access(e, 0xC10F, 2, RAX, at, p["an_size"], e.flag(e.eq(p["an_kind"], int(AtomicRmwKind.ADD_WRAP)))))
            _store(e, RAX, _slot(e, result), 8)
            e.give(1)

        e.if_(e.eq(op, _op(Operation.ATOMIC_RMW)), rmw)
        # ATOMIC_CMPXCHG: lock cmpxchg [rsp+at], r10 with the expected value in rax; the flag zero-extended.
        size_of(_result_type(e, result))
        _load(e, RAX, _slot(e, _operand(e, node, 1)), 8)
        _load(e, 10, _slot(e, _operand(e, node, 2)), 8)
        _atomic_access(e, 0xB10F, 2, 10, at, p["an_size"], 1)
        _store(e, RAX, _slot(e, result), 8)
        _b(e, bytes.fromhex("0f94c00fb6c0"))
        _store(e, RAX, _slot(e, _output(e, node, 1)), 8)
        e.give(1)
    return _function(("bi", "m"), build, tables)


def _atomic_check_fn(tables):
    """``_compile_function``'s first step on function ``f``'s own (lifted) graph: every atomic node's capability
    (``atomic_capability`` with the default policy); an unsupported one is the bootstrap's NATIVE-ATOMIC-CAPABILITY
    rejection.  1 when every node is supported."""
    from xax_selfhost_x86_64_general import G_TATOMIC, G_TPROFILE

    def build(e: E):
        p = e.p
        e.var("ac_ok", 1)
        # The target's atomic widths, scopes, and families (empty unless the profile carries them).
        e.var("ac_has", e.flag(e.either(e.eq(_g(e, G_TPROFILE), 2), e.eq(_g(e, G_TPROFILE), 5))))

        def member(list_index, value, name):
            """``name``: 1 when ``value`` is in the target's ``list_index``-th atomic list."""
            e.var(name, 0)

            def scan():
                e.var(f"{name}_at", _g(e, G_TATOMIC))
                for skip in range(list_index):
                    e.var(f"{name}_n{skip}", _payload_uleb(e, f"{name}_at"))
                    e.for_(f"{name}_s{skip}", 0, p[f"{name}_n{skip}"], lambda: _payload_uleb(e, f"{name}_at"))
                e.var(f"{name}_n", _payload_uleb(e, f"{name}_at"))
                e.for_(f"{name}_q", 0, p[f"{name}_n"], lambda: e.if_(e.eq(_payload_uleb(e, f"{name}_at"), value), lambda: e.set(name, 1)))

            e.if_(e.ne(p["ac_has"], 0), scan)

        def node(block, bi, n, m):
            e.var("ac_op", _eop(e, n))

            def atomic():
                e.var("ac_family", 5)
                for family, operation in enumerate((Operation.ATOMIC_LOAD, Operation.ATOMIC_STORE, Operation.ATOMIC_RMW, Operation.ATOMIC_CMPXCHG), 1):
                    e.if_(e.eq(p["ac_op"], _op(operation)), lambda family=family: e.set("ac_family", family))
                e.var("ac_width", 0)
                e.var("ac_align", 1)
                e.var("ac_scope", _attribute(e, n, 1))

                def memory():
                    e.var("ac_pt", _vf(e, G_VTYPE, _operand(e, n, 0)))
                    e.var("ac_pa", e.add(_at(e, G_PAY, p["ac_pt"]), 1))
                    _payload_uleb(e, "ac_pa")  # space
                    e.var("ac_elem", _reference(e, p["ac_pt"], _payload_uleb(e, "ac_pa")))
                    _ok(e, e.ne(p["ac_elem"], NONE))
                    _bits_width(e, p["ac_elem"], "ac_bw")
                    e.set("ac_width", p["ac_bw"])
                    e.var("ac_na", _attribute_count(e, n))
                    cmpxchg = e.eq(p["ac_family"], 4)
                    from xax_selfhost_general_ranges import N_ATTR

                    # ``attributes[-2]`` for a compare-exchange, else ``attributes[-1]`` (word 1 + k holds attribute k).
                    e.set("ac_align", e.rd(e.add(_f(e, n, N_ATTR), e.sub(p["ac_na"], e.sel(cmpxchg, 1, 0)))))
                    e.if_(e.either(cmpxchg, e.eq(p["ac_family"], 3)), lambda: e.set("ac_scope", _attribute(e, n, 2)))

                e.if_(e.ne(p["ac_family"], 5), memory)
                member(0, p["ac_width"], "ac_wok")
                member(1, p["ac_scope"], "ac_sok")
                member(2, p["ac_family"], "ac_fok")
                e.var("ac_need", e.sel(e.eq(p["ac_family"], 5), 1, e.sel(e.lt(p["ac_width"], 8), 1, e.udiv(p["ac_width"], 8))))
                supported = e.both(e.either(e.eq(p["ac_family"], 5), e.ne(p["ac_wok"], 0)), e.ne(p["ac_fok"], 0), e.ne(p["ac_sok"], 0),
                                   e.le(p["ac_need"], p["ac_align"]))

                def unsupported():
                    e.if_(e.ne(p["ac_ok"], 0), lambda: (e.set("ac_ok", 0), _call(e, "atomic_reject", p["f"])))

                e.if_(e.not_(supported), unsupported)

            e.if_(_in(e, p["ac_op"], ATOMICS), atomic)

        _each_node(e, node)
        e.give(p["ac_ok"])
    return _function(("f",), build, tables)


def _atomic_reject_fn(tables):
    """The NATIVE-ATOMIC-CAPABILITY rejection of function ``f`` (``reject_at``: exact when every earlier function's
    code is the program's)."""
    def build(e: E):
        from xax_selfhost_general_emit import graph_cid_words, reject_at
        import xax_selfhost_diagnostics as D

        p = e.p

        def write():
            D.text(e, "XAX.NATIVE.ATOMIC_UNSUPPORTED")
            D.cid(e, graph_cid_words(e, p["f"]))
            D.text(e, "NATIVE-ATOMIC-CAPABILITY")
            D.put(e, D.T_LIST)
            D.put(e, 2)
            D.text(e, "native")
            D.text(e, "bounded_sequence")
            D.text(e, "unsupported")

        reject_at(e, write)
    return _function(("f",), build, tables)


def _frame_node_fn(tables):
    """One node of the frame path, in the bootstrap's case order, with its semantic range."""
    def build(e: E):
        p = e.p
        node, op, result = _node_prelude(e)
        e.var("fx_start", _ra(e, E_CLEN))
        # A pointer element must be pointer-sized (NATIVE-POINTER-ELEMENT-WIDTH).
        loads = (_op(Operation.LOAD_BITS_LE), _op(Operation.CHECKED_LOAD_BITS_LE))
        stores = (_op(Operation.STORE_BITS_LE), _op(Operation.CHECKED_STORE_BITS_LE))

        def element_width():
            e.var("fx_vt", e.sel(_in(e, op, loads), _vf(e, G_VTYPE, e.sel(e.ne(result, NONE), result, 0)),
                                 _vf(e, G_VTYPE, _operand(e, node, e.sub(_f(e, node, N_NOPS), 2)))))
            from xax_selfhost_general_rejects import POINTER_ELEMENT_WIDTH

            e.if_(e.both(e.eq(_form(e, p["fx_vt"]), 2), e.ne(_attribute(e, node, 0), 8)),
                  lambda: _call(e, "pointer_width_reject", POINTER_ELEMENT_WIDTH, 8, _attribute(e, node, 0), _ra(e, F_FN)))

        e.if_(_in(e, op, (*loads, *stores)), element_width)
        e.var("fx_done", 0)
        for group in ("fr_int", "fr_float", "fr_ftrunc", "fr_data", "fr_foreign", "fr_memory", "fr_atomic", "fr_call", "fr_tail"):
            e.if_(e.eq(p["fx_done"], 0), lambda group=group: e.set("fx_done", _call(e, group, p["bi"], p["m"])))

        def record():
            e.var("fx_n", _ra(e, E_NRANGES))
            e.var("fx_at", e.add(_ra(e, E_RANGES), e.mul(p["fx_n"], 4)))
            for field, value in enumerate((p["bi"], p["m"], p["fx_start"], _ra(e, E_CLEN))):
                e.st(e.add(p["fx_at"], field), value)
            _set_ra(e, E_NRANGES, e.add(p["fx_n"], 1))

        e.if_(e.lt(p["fx_start"], _ra(e, E_CLEN)), record)
        e.give(1)
    return _function(("bi", "m"), build, tables)


def _copy_edge(e: E, target_block, arguments, count):
    """``copy_edge``: every machine argument through the edge temporaries, qword by qword."""
    p = e.p
    e.var("ce_tb", target_block)
    e.var("ce_args", arguments)
    e.var("ce_n", count)
    e.var("ce_pairs", e.alloc(e.add(e.mul(p["ce_n"], 3), 1)))
    _ok(e, e.ne(p["ce_pairs"], NONE))
    e.var("ce_np", 0)
    e.var("ce_temp", _ra(e, F_TEMP))

    def pair():
        e.var("ce_a", e.ld(e.add(p["ce_args"], p["ce_k"])))
        e.var("ce_d", e.ld(e.add(_f(e, p["ce_tb"], B_INPUTS), p["ce_k"])))

        def copy():
            e.var("ce_size", _slot_bytes(e, _rt(e, T_FSIZE, p["ce_d"])))
            e.var("ce_q", 0)
            e.while_(lambda: e.lt(p["ce_q"], p["ce_size"]), lambda: (
                _load(e, SCRATCH1, e.add(_rt(e, T_FSLOT, p["ce_a"]), p["ce_q"]), 8), _store(e, SCRATCH1, e.add(p["ce_temp"], p["ce_q"]), 8),
                e.set("ce_q", e.add(p["ce_q"], 8))))
            e.var("ce_at", e.add(p["ce_pairs"], e.mul(p["ce_np"], 3)))
            for field, value in enumerate((p["ce_temp"], p["ce_d"], p["ce_size"])):
                e.st(e.add(p["ce_at"], field), value)
            e.set("ce_np", e.add(p["ce_np"], 1))
            e.set("ce_temp", e.add(p["ce_temp"], p["ce_size"]))

        e.if_(e.both(e.ne(_rt(e, T_FSLOT, p["ce_a"]), NONE), e.ne(_rt(e, T_FSLOT, p["ce_d"]), NONE)), copy)

    e.for_("ce_k", 0, p["ce_n"], pair)

    def place():
        e.var("ce_at", e.add(p["ce_pairs"], e.mul(p["ce_j"], 3)))
        e.var("ce_q", 0)
        e.while_(lambda: e.lt(p["ce_q"], e.ld(e.add(p["ce_at"], 2))), lambda: (
            _load(e, SCRATCH1, e.add(e.ld(p["ce_at"]), p["ce_q"]), 8), _store(e, SCRATCH1, e.add(_rt(e, T_FSLOT, e.ld(e.add(p["ce_at"], 1))), p["ce_q"]), 8),
            e.set("ce_q", e.add(p["ce_q"], 8))))

    e.for_("ce_j", 0, p["ce_np"], place)


def _frame_term_fn(tables):
    """The terminator of block ``bi`` on the frame path."""
    def build(e: E):
        p = e.p
        e.var("ft_b", _block_at(e, p["bi"]))
        block = p["ft_b"]
        e.var("ft_kind", _f(e, block, B_KIND))

        def returned():
            # The first machine return value (by the function's return types, borrowed views included).
            e.var("ft_iface", _call(e, "interface", _ra(e, F_FN)))
            e.var("ft_np", e.ld(e.add(p["ft_iface"], 1)))
            e.var("ft_rt", e.add(e.add(p["ft_iface"], 2), p["ft_np"]))
            e.var("ft_first", NONE)
            e.var("ft_ftype", 0)
            e.for_("ft_k", 0, _f(e, block, B_NVALUES), lambda: (
                e.var("ft_t", e.ld(e.add(e.add(p["ft_rt"], 1), p["ft_k"]))),
                e.if_(e.both(e.eq(p["ft_first"], NONE), e.not_(_proof(e, p["ft_t"]))),
                      lambda: (e.set("ft_first", e.ld(e.add(_f(e, block, B_VALUES), p["ft_k"]))), e.set("ft_ftype", p["ft_t"])))))

            def hidden():
                _load(e, SCRATCH0, _ra(e, F_RETPTR), 8)
                _copy_bytes(e, SCRATCH0, 0, RSP, _slot(e, p["ft_first"]), _rt(e, T_FSIZE, p["ft_first"]))
                _bx(e, 0xD0894C, 3)  # mov rax, r10

            def value():
                e.if_(_is_float(e, p["ft_ftype"]), lambda: (_float_width(e, p["ft_ftype"], "ft_fw"), _xmm_memory(e, True, 0, _slot(e, p["ft_first"]), p["ft_fw"])),
                      lambda: e.if_(e.ne(_ra(e, F_RETPTR), NONE), hidden, lambda: _load(e, RAX, _slot(e, p["ft_first"]), 8)))

            e.if_(e.ne(p["ft_first"], NONE), value, lambda: _bx(e, 0xC031, 2))
            e.if_(e.ne(_ra(e, F_PROCESS), 0), lambda: _bx(e, 0x0B0F, 2), lambda: (_bx(e, 0xC48148, 3), _bx(e, _ra(e, F_FRAME), 4), _bx(e, 0xC3, 1)))

        def branch():
            e.var("ft_at", _f(e, block, B_EDGES))
            _copy_edge(e, _f(e, p["ft_at"], 0), _f(e, p["ft_at"], 2), _f(e, p["ft_at"], 1))
            _relative(e, 0xE9, _f(e, _f(e, p["ft_at"], 0), B_POS))

        def conditional():
            _load(e, RAX, _slot(e, e.ld(_f(e, block, B_VALUES))), 8)
            _bx(e, 0xC08548, 3)
            e.var("ft_false", _new_label(e))
            _relative2(e, 0x840F, p["ft_false"])
            e.var("ft_at", _f(e, block, B_EDGES))
            _copy_edge(e, _f(e, p["ft_at"], 0), _f(e, p["ft_at"], 2), _f(e, p["ft_at"], 1))
            _relative(e, 0xE9, _f(e, _f(e, p["ft_at"], 0), B_POS))
            _label(e, p["ft_false"])
            e.var("ft_at", e.add(_f(e, block, B_EDGES), EDGE))
            _copy_edge(e, _f(e, p["ft_at"], 0), _f(e, p["ft_at"], 2), _f(e, p["ft_at"], 1))
            _relative(e, 0xE9, _f(e, _f(e, p["ft_at"], 0), B_POS))

        def trap():
            from xax_selfhost_views_backend import G_ORDER
            from xax_selfhost_general_view import B_TERM

            e.var("ft_reason", 0)

            def decode():
                e.var("ft_fn_obj", e.ld(e.add(_g(e, G_ORDER), _f(e, block, B_PFN))))
                e.var("ft_graph", e.ld(_call(e, "interface", p["ft_fn_obj"])))
                e.var("ft_pa", _call(e, "trap_payload", p["ft_graph"], _f(e, block, B_PB)))
                e.set("ft_reason", _payload_uleb(e, "ft_pa"))

            e.if_(e.ne(e.rd(e.add(_f(e, block, B_TERM), 1)), 0), decode)
            _movabs(e, RAX, p["ft_reason"])
            _bx(e, 0x0B0F, 2)

        e.if_(e.eq(p["ft_kind"], RETURN), returned, lambda: e.if_(e.eq(p["ft_kind"], BRANCH), branch, lambda: e.if_(
            e.eq(p["ft_kind"], CONDITIONAL), conditional, trap)))
        e.give(1)
    return _function(("bi",), build, tables)


F_FN = 238  # the function being lowered (``_ra`` slot)


def _legacy_static(e: E, f, name: str):
    """``name``: 1 when ``_compile_register_resident_function``'s static checks accept the lifted graph, so the
    bootstrap would try that path before the frame lowering.  S15e.3: on Windows the hosted profile's checks (the
    larger operation list, heap-view memory only, 32/64-bit compares, integer foreign calls of at most four
    arguments)."""
    from xax_selfhost_x86_64_general import G_RAWWIN, G_WINDOWS

    p = e.p
    e.var(name, 1)
    e.var(f"{name}_w", e.flag(e.both(e.ne(_g(e, G_WINDOWS), 0), e.eq(_g(e, G_RAWWIN), 0))))  # the hosted (PE) variant
    e.var(f"{name}_heap", e.alloc(e.add(_g(e, G_VCOUNT), 1)))
    _ok(e, e.ne(p[f"{name}_heap"], NONE))
    e.for_(f"{name}_z", 0, _g(e, G_VCOUNT), lambda: e.st(e.add(p[f"{name}_heap"], p[f"{name}_z"]), 0))

    def heap(v):
        return e.ld(e.add(p[f"{name}_heap"], v))

    def hosted(n):
        """The hosted profile's per-node checks (``heap_values`` in node order)."""
        op = p[f"{name}_op"]
        e.var(f"{name}_a", e.sel(e.lt(0, _f(e, n, N_NOPS)), _operand(e, n, 0), 0))
        e.if_(e.eq(op, _op(Operation.HEAP_VIEW)), lambda: e.st(e.add(p[f"{name}_heap"], _output(e, n, 0)), 1))
        e.if_(e.both(_in(e, op, (_op(Operation.ADDRESS_OFFSET), _op(Operation.POINTER_CAST))), e.ne(heap(p[f"{name}_a"]), 0)),
              lambda: e.st(e.add(p[f"{name}_heap"], _output(e, n, 0)), 1))
        e.if_(e.both(_in(e, op, HOSTED_MEMORY), e.eq(heap(p[f"{name}_a"]), 0)), lambda: e.set(name, 0))

        def compare():
            _bits_width(e, _vf(e, G_VTYPE, p[f"{name}_a"]), f"{name}_cw")
            e.if_(e.not_(e.either(e.eq(p[f"{name}_cw"], 32), e.eq(p[f"{name}_cw"], 64))), lambda: e.set(name, 0))

        e.if_(e.eq(op, _op(Operation.INT_COMPARE)), compare)

        def scalar(t):
            e.var(f"{name}_st", t)
            e.if_(e.both(e.not_(_proof(e, p[f"{name}_st"])), e.either(_is_float(e, p[f"{name}_st"]), _is_aggregate(e, p[f"{name}_st"]))),
                  lambda: e.set(name, 0))

        def foreign():
            _machine_inputs(e, n, 0, f"{name}_fi")
            _machine_results(e, n, f"{name}_fr")
            e.if_(e.either(e.lt(4, p[f"{name}_fi"]), e.lt(1, p[f"{name}_fr"])), lambda: e.set(name, 0))
            e.for_(f"{name}_k", 0, _f(e, n, N_NOPS), lambda: scalar(_vf(e, G_VTYPE, _operand(e, n, p[f"{name}_k"]))))
            e.for_(f"{name}_k", 0, _f(e, n, N_NRES), lambda: scalar(_vf(e, G_VTYPE, _output(e, n, p[f"{name}_k"]))))

        e.if_(e.eq(op, _op(Operation.CALL_FOREIGN)), foreign)
        e.if_(_in(e, op, (_op(Operation.LOAD_BITS_LE), _op(Operation.CHECKED_LOAD_BITS_LE))), lambda: scalar(_vf(e, G_VTYPE, _output(e, n, 0))))
        e.if_(_in(e, op, (_op(Operation.STORE_BITS_LE), _op(Operation.CHECKED_STORE_BITS_LE))),
              lambda: scalar(_vf(e, G_VTYPE, _operand(e, n, e.sub(_f(e, n, N_NOPS), 2)))))

    def node(block, bi, n, m):
        e.var(f"{name}_op", _eop(e, n))
        e.if_(e.not_(e.either(_in(e, p[f"{name}_op"], LEGACY_ALLOWED), e.both(e.ne(p[f"{name}_w"], 0), _in(e, p[f"{name}_op"], HOSTED_ALLOWED)))),
              lambda: e.set(name, 0))
        e.if_(e.ne(p[f"{name}_w"], 0), lambda: hosted(n))

        def direct():
            _machine_inputs(e, n, 0, f"{name}_in")
            e.if_(e.lt(4, p[f"{name}_in"]), lambda: e.set(name, 0))

            def bits(v):
                e.var(f"{name}_t", _vf(e, G_VTYPE, v))
                e.if_(e.both(e.not_(_proof(e, p[f"{name}_t"])), e.ne(_form(e, p[f"{name}_t"]), 1)), lambda: e.set(name, 0))

            e.for_(f"{name}_k", 0, _f(e, n, N_NOPS), lambda: bits(_operand(e, n, p[f"{name}_k"])))
            e.for_(f"{name}_k", 0, _f(e, n, N_NRES), lambda: bits(_output(e, n, p[f"{name}_k"])))

        e.if_(e.eq(p[f"{name}_op"], _op(Operation.CALL_DIRECT)), direct)

    _each_node(e, node)

    def terminators():
        e.var(f"{name}_b", _block_at(e, p[f"{name}_bi"]))
        e.if_(e.not_(_in(e, _f(e, p[f"{name}_b"], B_KIND), (RETURN, BRANCH, CONDITIONAL))), lambda: e.set(name, 0))

    e.for_(f"{name}_bi", 0, _g(e, G_BCOUNT), terminators)
    # The interface: at most four machine parameters, every machine parameter and result a bits type.
    e.var(f"{name}_i", _call(e, "interface", f))
    e.var(f"{name}_np", e.ld(e.add(p[f"{name}_i"], 1)))
    e.var(f"{name}_mp", 0)

    def interface_type(t):
        e.var(f"{name}_it", t)
        e.if_(e.not_(_proof(e, p[f"{name}_it"])), lambda: (e.set(f"{name}_mp", e.add(p[f"{name}_mp"], 1)),
                                                            e.if_(e.ne(_form(e, p[f"{name}_it"]), 1), lambda: e.set(name, 0))))

    e.for_(f"{name}_k", 0, p[f"{name}_np"], lambda: interface_type(e.ld(e.add(e.add(p[f"{name}_i"], 2), p[f"{name}_k"]))))
    e.if_(e.lt(4, p[f"{name}_mp"]), lambda: e.set(name, 0))
    e.var(f"{name}_rt", e.add(e.add(p[f"{name}_i"], 2), p[f"{name}_np"]))
    e.var(f"{name}_mp", 0)
    e.for_(f"{name}_k", 0, e.ld(p[f"{name}_rt"]), lambda: interface_type(e.ld(e.add(e.add(p[f"{name}_rt"], 1), p[f"{name}_k"]))))


def _frame_function_fn(tables):
    """The frame lowering of function ``f`` (image index ``fidx``) from its own graph, or the legacy register path where
    the bootstrap takes it (S12f.4): 1 emitted."""
    from xax_selfhost_general_view import G_BLIST, G_FKEYN, G_LIFT_ENTRY, _globals
    from xax_selfhost_x86_64_general import G_ENTRY, G_RAWWIN, G_WINDOWS

    def build(e: E):
        p = e.p
        from xax_selfhost_general_emit import E_F

        _set_ra(e, E_F, p["f"])  # S12f.2: the function a rejection names
        # The function's own graph: lift it again (the view's records were rewritten).
        _globals(e, G_VCOUNT, 0)
        _globals(e, G_FKEYN, 0)
        e.var("ff_blocks", _call(e, "lift", p["f"], p["fidx"]))
        e.var("ff_n", e.rd(_at(e, G_PAY, e.ld(_call(e, "interface", p["f"])))))
        _globals(e, G_BENTRY, _g(e, G_LIFT_ENTRY))
        e.var("ff_list", e.alloc(e.add(p["ff_n"], 1)))
        _ok(e, e.ne(p["ff_list"], NONE))
        e.for_("ff_q", 0, p["ff_n"], lambda: e.st(e.add(p["ff_list"], p["ff_q"]), e.ld(e.add(p["ff_blocks"], p["ff_q"]))))
        _globals(e, G_BLIST, p["ff_list"])
        _globals(e, G_BCOUNT, p["ff_n"])
        _call(e, "positions")
        _set_ra(e, F_FN, p["f"])
        _set_ra(e, F_PROCESS, e.flag(e.both(e.eq(p["f"], _g(e, G_ENTRY)), e.eq(_g(e, G_WINDOWS), 0))))  # S15e.3: no process entry on PE
        # The Linux profiles support heap views: pointers are first-class values (S15e.3: not on Windows).
        _set_ra(e, F_DYN, e.flag(e.eq(_g(e, G_WINDOWS), 0)))
        # S12f.4 (ADR-280): a function the legacy register path's static checks accept is lowered by that path.
        e.var("ff_legacy", 0)
        e.if_(e.eq(_ra(e, F_PROCESS), 0), lambda: (_legacy_static(e, p["f"], "ff_static"), e.set("ff_legacy", p["ff_static"])))
        # S15e.3: the hosted (Windows) legacy register path is the bootstrap's alone.
        _ok(e, e.either(e.eq(p["ff_legacy"], 0), e.eq(_g(e, G_WINDOWS), 0), e.ne(_g(e, G_RAWWIN), 0)))  # S15f.2: load images' is Linux's
        _set_ra(e, E_FWD_ON, e.flag(e.both(e.ne(_g(e, G_WINDOWS), 0), e.eq(_g(e, G_RAWWIN), 0))))  # ``forward_stores``: the PE frame path
        # The emission state (``xax_selfhost_general_emit``): the real run only.
        for slot in (E_CLEN, E_NBRANCHES, E_NCALLS, E_NRANGES, E_CAP_ON):
            _set_ra(e, slot, 0)
        _set_ra(e, E_REAL, 1)
        _set_ra(e, E_NLABELS, _g(e, G_BCOUNT))
        e.for_("ff_l", 0, _g(e, G_BCOUNT), lambda: e.st(e.add(_ra(e, E_LABELS), p["ff_l"]), NONE))

        def frame_body():
            _call(e, "frame_layout", p["f"])
            e.var("ff_frame", _ra(e, F_FRAME))
            _bx(e, 0xEC8148, 3, True)
            _bx(e, p["ff_frame"], 4, True)
            # The entry block's parameters from the argument registers or the caller's stack.
            e.var("ff_entry", _g(e, G_BENTRY))
            e.var("ff_pos", 0)
            e.if_(e.ne(_ra(e, F_RETPTR), NONE), lambda: (_store(e, ARGUMENT_REGISTERS[0], _ra(e, F_RETPTR), 8), e.set("ff_pos", 1)))

            def parameter():
                e.var("ff_v", e.ld(e.add(_f(e, p["ff_entry"], B_INPUTS), p["ff_k"])))
                e.var("ff_t", _vf(e, G_VTYPE, p["ff_v"]))

                def machine():
                    e.var("ff_dest", _slot(e, p["ff_v"]))
                    e.var("ff_size", _rt(e, T_FSIZE, p["ff_v"]))

                    e.var("ff_byref", 0)
                    e.if_(_is_aggregate(e, p["ff_t"]), lambda: e.set("ff_byref", e.flag(_by_reference(e, p["ff_t"], p["ff_size"]))))

                    def register():
                        e.var("ff_reg", _select(e, p["ff_pos"], ARGUMENT_REGISTERS))
                        e.if_(_is_float(e, p["ff_t"]), lambda: (_float_width(e, p["ff_t"], "ff_fw"), _xmm_memory(e, False, p["ff_pos"], p["ff_dest"], p["ff_fw"])),
                              lambda: e.if_(_is_aggregate(e, p["ff_t"]), lambda: (
                                  _zero_bytes(e, RSP, p["ff_dest"], _slot_bytes(e, p["ff_size"])), e.if_(
                                      e.ne(p["ff_byref"], 0), lambda: _copy_bytes(e, RSP, p["ff_dest"], p["ff_reg"], 0, p["ff_size"]),
                                      lambda: _call(e, "store_exact", p["ff_reg"], RSP, p["ff_dest"], p["ff_size"]))),
                                  lambda: _store(e, p["ff_reg"], p["ff_dest"], 8)))

                    def stacked():
                        e.var("ff_in", e.add(e.add(p["ff_frame"], 8 + SHADOW), e.mul(e.sub(p["ff_pos"], 4), 8)))
                        e.if_(_is_float(e, p["ff_t"]), lambda: (_float_width(e, p["ff_t"], "ff_fw"), _xmm_memory(e, True, 4, p["ff_in"], p["ff_fw"]),
                                                                _xmm_memory(e, False, 4, p["ff_dest"], p["ff_fw"])),
                              lambda: e.if_(_is_aggregate(e, p["ff_t"]), lambda: (
                                  _zero_bytes(e, RSP, p["ff_dest"], _slot_bytes(e, p["ff_size"])), e.if_(
                                      e.ne(p["ff_byref"], 0), lambda: (_load(e, SCRATCH0, p["ff_in"], 8), _copy_bytes(e, RSP, p["ff_dest"], SCRATCH0, 0, p["ff_size"])),
                                      lambda: (_call(e, "load_exact", SCRATCH0, RSP, p["ff_in"], p["ff_size"]),
                                               _call(e, "store_exact", SCRATCH0, RSP, p["ff_dest"], p["ff_size"])))),
                                  lambda: (_load(e, SCRATCH0, p["ff_in"], 8), _store(e, SCRATCH0, p["ff_dest"], 8))))

                    e.if_(e.lt(p["ff_pos"], 4), register, stacked)
                    e.set("ff_pos", e.add(p["ff_pos"], 1))

                e.if_(e.not_(_proof(e, p["ff_t"])), machine)

            e.for_("ff_k", 0, _f(e, p["ff_entry"], B_NP), parameter)
            e.var("ff_ei", _f(e, p["ff_entry"], B_POS))
            e.if_(e.ne(p["ff_ei"], 0), lambda: _relative(e, 0xE9, p["ff_ei"]))

            def block():
                _label(e, p["ff_bi"])
                e.for_("ff_m", 0, _f(e, _block_at(e, p["ff_bi"]), B_NNODES), lambda: _call(e, "fr_node", p["ff_bi"], p["ff_m"]))
                _call(e, "fr_term", p["ff_bi"])

            e.for_("ff_bi", 0, _g(e, G_BCOUNT), block)


        e.if_(e.ne(p["ff_legacy"], 0), lambda: _call(e, "legacy_function", p["f"]), frame_body)

        def fixup():
            from xax_selfhost_general_emit import E_BRANCHES, E_CODE, _store_bytes

            e.var("ff_at", e.add(_ra(e, E_BRANCHES), e.mul(p["ff_k"], 2)))
            e.var("ff_p", e.ld(p["ff_at"]))
            e.var("ff_target", e.ld(e.add(_ra(e, E_LABELS), e.ld(e.add(p["ff_at"], 1)))))
            _ok(e, e.ne(p["ff_target"], NONE))
            _store_bytes(e, e.add(_ra(e, E_CODE), p["ff_p"]), e.sub(p["ff_target"], e.add(p["ff_p"], 4)), 4)

        e.for_("ff_k", 0, _ra(e, E_NBRANCHES), fixup)
        _set_ra(e, E_FWD_ON, 0)
        e.give(1)
    return _function(("f", "fidx"), build, tables)


def _fallback_fn(tables):
    """After a view's analyses and emission: the frame path where the bootstrap takes it.  ``status`` is the
    analysis status, ``emitted`` the emission outcome (0 not decided, 1 not the register-resident path, 2 emitted);
    the new outcome is returned."""
    from xax_selfhost_general_regalloc import STATUS_ANALYSED, STATUS_INELIGIBLE, STATUS_UNDECIDED

    def build(e: E):
        p = e.p
        e.if_(e.eq(p["emitted"], 2), lambda: e.give(2))
        e.var("fb_frame", e.flag(e.either(e.eq(p["status"], STATUS_INELIGIBLE), e.both(e.eq(p["status"], STATUS_ANALYSED), e.eq(p["emitted"], 1)))))

        def undecided():
            e.var("fb_eligible", e.call(_FN["eligible_only"], p["f"]))
            e.if_(e.eq(p["fb_eligible"], 0), lambda: e.set("fb_frame", 1))

        e.if_(e.eq(p["status"], STATUS_UNDECIDED), undecided)
        e.if_(e.eq(p["fb_frame"], 0), lambda: e.give(p["emitted"]))
        e.var("fb_r", e.call(_FN["frame_function"], p["f"], p["fidx"]))
        e.give(e.sel(e.eq(p["fb_r"], 1), 2, 0))
    return _function(("f", "fidx", "status", "emitted"), build, tables)


def _eligible_only_fn(tables):
    """The register-resident eligibility alone (``_analyse``'s first step) for a view whose values the ranges do not
    bound exactly: 0 when the bootstrap's register-resident lowering returns None, 1 otherwise, NONE declined."""
    from xax_selfhost_general_regalloc import R_NPARAMS, R_NRETURNS, R_OWN_ELIDED, R_PARAMS, R_RETURNS

    def build(e: E):
        p = e.p
        e.var("eo_i", _call(e, "interface", p["f"]))
        e.var("eo_np", e.ld(e.add(p["eo_i"], 1)))
        _set_ra(e, R_NPARAMS, p["eo_np"])
        _set_ra(e, R_PARAMS, e.add(p["eo_i"], 2))
        e.var("eo_rt", e.add(e.add(p["eo_i"], 2), p["eo_np"]))
        _set_ra(e, R_NRETURNS, e.ld(p["eo_rt"]))
        _set_ra(e, R_RETURNS, e.add(p["eo_rt"], 1))
        _set_ra(e, R_OWN_ELIDED, _call(e, "borrowed", p["f"]))
        e.give(_call(e, "eligible"))
    return _function(("f",), build, tables)


def add_frame_functions(add, tables):
    from xax_selfhost_general_legacy import add_legacy_functions

    from xax_selfhost_x86_64_general import _layout

    add("abi_layout", _layout(tables, wasm=True))  # the front end's ``layout`` (the view's block layout took that name); S15e.4
    add("value_reject", _value_reject_fn(tables))
    add("width_reject", _width_reject_fn(tables))
    add("fixed_reject", _fixed_reject_fn(tables))
    add("frame_layout", _frame_layout_fn(tables))
    add("fr_int", _int_node_fn(tables))
    add("fr_float", _float_node_fn(tables))
    add("fr_ftrunc", _float_trunc_fn(tables))
    add("fr_data", _data_node_fn(tables))
    add("fr_foreign", _foreign_node_fn(tables))
    add("fr_memory", _memory_node_fn(tables))
    add("fr_call", _call_node_fn(tables))
    add("fr_tail", _memory_tail_fn(tables))
    add("fr_atomic", _atomic_node_fn(tables))
    add("atomic_reject", _atomic_reject_fn(tables))
    add("atomic_check", _atomic_check_fn(tables))
    add("fr_node", _frame_node_fn(tables))
    add("fr_term", _frame_term_fn(tables))
    add_legacy_functions(add, tables)
    add("frame_function", _frame_function_fn(tables))
    add("eligible_only", _eligible_only_fn(tables))
    add("frame_fallback", _fallback_fn(tables))
