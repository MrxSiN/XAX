"""Self-hosting step S15e.2b (ADR-316): the AArch64 frame path as XAX functions.

``xax_aarch64._compile_function`` lowers a Linux function by the register allocator over its lowering view
(``xax_selfhost_aarch64_lower``); when that returns None it takes the *frame path*
(``_compile_general_function``) unless the function's own graph is register-path eligible
(``_register_path_eligible``, then the legacy register path, which this program declines).  On the frame path every
machine value of the function's own graph (not the inlined view) owns an ABI-layout frame slot; each node loads its
operands into fixed registers (x16, x17, x9 and v16, v17), computes, and stores its result.  Slots are shared between
values whose live hulls are disjoint (ADR-123), in the bootstrap's order.

Covered: integer arithmetic, bitwise operations, division and remainder with the zero trap, width changes, rotation,
constants (bits and floats), compares, the float operations, conversions with their range traps, float width
conversion, products, sums, stack storage, first-class pointers, pointer rebases, heap views, plain and checked
memory accesses, direct calls and Linux syscalls and C imports under AAPCS64 (general, pair, float, homogeneous float
and by-reference classes, stack arguments), returns, branches, and traps.  Declined (the bootstrap lowers or
rejects): indirect calls, code addresses, target operations, and every encoding the bootstrap would reject except
the frame size.

The code, calls and node ranges go to the register path's emission record (``xax_selfhost_aarch64_emit``), so the
image (``xax_selfhost_aarch64_image``) is unchanged.
"""

from __future__ import annotations

from xax_compiler import FloatCompare, IntCompare, Operation, RESOURCE_EFFECT_OPERATIONS
import xax_selfhost_diagnostics as D
from xax_selfhost_aarch64_emit import (
    ABI_C_CLASS, ABI_SYSCALL_CLASS, C_ABI, CALL_CAP, CODE_CAP, FIX_CAP, RANGE_CAP, SYSCALL_ABI, X_CALLS, X_CODE, X_FIX, X_LABELS, X_LEN,
    X_NCALLS, X_NFIX, X_NRANGES, X_RANGES, _a, _branch, _emit, _foreign_class, _label, _set_a,
)
from xax_selfhost_facts import E, NONE, _function
from xax_selfhost_general_frame import _align_to, _component_offset, _constant_bytes, _float_width, _form, _is_aggregate, _is_float, _payload_offset, _proof
from xax_selfhost_general_ranges import _attribute, _block_at, _node_at
from xax_selfhost_general_regalloc import T_FEXT, T_FESC, T_FHOFF, T_FHROOT, T_FPTR, T_FSIZE, T_FSLOT, _callee_object, _eop, _rt, _set_rt
from xax_selfhost_general_view import (
    B_EDGES, B_INPUTS, B_KIND, B_NEDGES, B_NNODES, B_NP, B_NVALUES, B_PB, B_PFN, B_POS, B_VALUES, BRANCH, CONDITIONAL, EDGE, G_BCOUNT,
    G_BENTRY, G_VCOUNT, G_VPOS, G_VTYPE, N_GRAPH, N_NOPS, N_NRES, N_OPSAT, POS_BLOCK, RETURN, _f, _operand, _output, _vf,
)
from xax_selfhost_views_backend import _FN, G_PAY, _at, _call, _g, _ok, _payload_uleb, _reference

TEMP, TEMP2, REMAINDER = 16, 17, 9  # x16 (IP0), x17 (IP1), x9 (a declared scratch register on this path)
FP_TEMP, FP_TEMP2 = 16, 17
SP, LR = 31, 30
BRK_FLOAT_CONVERSION, BRK_NULL_HEAP, BRK_MEMORY_CHECK, BRK_SUM_VARIANT, BRK_DIVIDE_BY_ZERO = 2, 3, 4, 5, 6
COND = {"eq": 0, "ne": 1, "hs": 2, "lo": 3, "mi": 4, "pl": 5, "vs": 6, "vc": 7, "hi": 8, "ls": 9, "ge": 10, "lt": 11, "gt": 12, "le": 13}
INT_CONDITION = {IntCompare.EQ: COND["eq"], IntCompare.NE: COND["ne"], IntCompare.ULT: COND["lo"], IntCompare.ULE: COND["ls"],
                 IntCompare.UGT: COND["hi"], IntCompare.UGE: COND["hs"], IntCompare.SLT: COND["lt"], IntCompare.SLE: COND["le"],
                 IntCompare.SGT: COND["gt"], IntCompare.SGE: COND["ge"]}
FLOAT_CONDITION = {FloatCompare.EQ: COND["eq"], FloatCompare.NE: COND["ne"], FloatCompare.LT: COND["mi"], FloatCompare.LE: COND["ls"],
                   FloatCompare.GT: COND["gt"], FloatCompare.GE: COND["ge"]}
SIGNED = tuple(int(kind) for kind in (IntCompare.SLT, IntCompare.SLE, IntCompare.SGT, IntCompare.SGE))
ARITHMETIC = {Operation.ADD_WRAP: (0x0B000000, 0x8B000000), Operation.SUB_WRAP: (0x4B000000, 0xCB000000), Operation.MUL_WRAP: (0x1B007C00, 0x9B007C00)}
LOGICAL = {Operation.BIT_AND: 0x0A000000, Operation.BIT_OR: 0x2A000000, Operation.BIT_XOR: 0x4A000000}
FLOAT_BINARY = {Operation.FLOAT_ADD: 0x1E202800, Operation.FLOAT_SUB: 0x1E203800, Operation.FLOAT_MUL: 0x1E200800, Operation.FLOAT_DIV: 0x1E201800}
BASE_ACCESS = {1: (0x39400000, 0x39000000), 2: (0x79400000, 0x79000000), 4: (0xB9400000, 0xB9000000), 8: (0xF9400000, 0xF9000000)}
FP_ACCESS = {4: (0xBD400000, 0xBD000000), 8: (0xFD400000, 0xFD000000)}
CALLS = tuple(int(op) for op in (Operation.CALL_DIRECT, Operation.CALL_FOREIGN, Operation.CALL_INDIRECT))
REGISTER_PATH_OPERATIONS = tuple(sorted(int(op) for op in (
    Operation.ADD_WRAP, Operation.SUB_WRAP, Operation.MUL_WRAP, Operation.CONSTANT, Operation.INT_COMPARE, Operation.CALL_DIRECT,
    Operation.CALL_FOREIGN, Operation.CALL_INDIRECT, Operation.FUNCTION_ADDRESS, Operation.HEAP_VIEW, Operation.LOAD_BITS_LE,
    Operation.STORE_BITS_LE)))
# AAPCS64 classes (``_abi_class``) and argument locations (``_abi_argument_plan``).
K_GPR, K_GPR2, K_FPR, K_HFA, K_REF, K_STACK = range(6)
PLAN_WORDS = 4  # kind, register or stack offset, count (a stack entry: its original class code), member bytes
HFA_STACK = 64  # the classification's explicit stack; a deeper type declines

# Frame state: words of the AArch64 lowering's globals (``_a``) from ``FRAME_BASE`` (after the emission's).
FRAME_BASE = 100
(F_FN, F_FRAME, F_LINK, F_RETPTR, F_EDGE_TEMP, F_COPIES, F_NCOPIES, F_HASCALL, F_HIDDEN, F_NEXT_LABEL, F_CLASS_COUNT, F_CLASS_MEMBER,
 F_PLAN, F_ENTRY, F_STARTS, F_PREDS, F_NPREDS) = range(FRAME_BASE, FRAME_BASE + 17)
# Per-value tables (the frame lowering's, ``xax_selfhost_general_regalloc._rt``): the slot, the layout size, a stack
# object's offset, the live hull, the layout alignment, and the machine flag.
T_SLOT, T_SIZE, T_STACK, T_HULL_START, T_HULL_END, T_ALIGN, T_MACHINE = T_FSLOT, T_FSIZE, T_FPTR, T_FHROOT, T_FHOFF, T_FEXT, T_FESC


def _op(operation) -> int:
    return int(operation)


def _in(e: E, value, items):
    return e.either(*(e.eq(value, item) for item in items))


def _imm(e: E, value, shift: int):
    return e.mul(value, 1 << shift)


# -- encodings (``xax_aarch64``'s) -----------------------------------------------------------------------------------

def _ubfx(e: E, d, s, lsb, width):
    return e.add(e.add(e.add(e.add(0xD3400000, _imm(e, lsb, 16)), _imm(e, e.sub(e.add(lsb, width), 1), 10)), _imm(e, s, 5)), d)


def _sbfx(e: E, d, s, width):
    return e.add(e.add(e.add(0x93400000, _imm(e, e.sub(width, 1), 10)), _imm(e, s, 5)), d)


def _bfi(e: E, d, s, lsb, width):
    return e.add(e.add(e.add(e.add(0xB3400000, _imm(e, e.and_(e.sub(64, lsb), 63), 16)), _imm(e, e.sub(width, 1), 10)), _imm(e, s, 5)), d)


def _lsr(e: E, d, s, shift):
    return e.add(e.add(e.add(0xD340FC00, _imm(e, shift, 16)), _imm(e, s, 5)), d)


def _lsl(e: E, d, s, shift):
    return e.add(e.add(e.add(e.add(0xD3400000, _imm(e, e.and_(e.sub(64, shift), 63), 16)), _imm(e, e.sub(63, shift), 10)), _imm(e, s, 5)), d)


def _three(e: E, base, d, n, m):
    return e.add(e.add(e.add(base, _imm(e, m, 16)), _imm(e, n, 5)), d)


def _base_access(e: E, load: bool, register, base, offset, size):
    """``_base_access``: an exact-width access at ``[base, #offset]`` (offsets are chunk-aligned and below 4096 * size
    here; another declines)."""
    _ok(e, e.lt(e.udiv(offset, size), 4096))
    opcode = e.sel(e.eq(size, 1), BASE_ACCESS[1][0 if load else 1], e.sel(e.eq(size, 2), BASE_ACCESS[2][0 if load else 1], e.sel(
        e.eq(size, 4), BASE_ACCESS[4][0 if load else 1], BASE_ACCESS[8][0 if load else 1])))
    return e.add(e.add(e.add(opcode, _imm(e, e.udiv(offset, size), 10)), _imm(e, base, 5)), register)


def _fp_access(e: E, load: bool, register, base, offset, size):
    _ok(e, e.both(e.eq(e.urem(offset, size), 0), e.lt(e.udiv(offset, size), 4096)))
    opcode = e.sel(e.eq(size, 4), FP_ACCESS[4][0 if load else 1], FP_ACCESS[8][0 if load else 1])
    return e.add(e.add(e.add(opcode, _imm(e, e.udiv(offset, size), 10)), _imm(e, base, 5)), register)


def _fmov_to_fp(e: E, fp, gpr, width):
    return e.add(e.add(e.sel(e.eq(width, 32), 0x1E270000, 0x9E670000), _imm(e, gpr, 5)), fp)


def _fmov_from_fp(e: E, gpr, fp, width):
    return e.add(e.add(e.sel(e.eq(width, 32), 0x1E260000, 0x9E660000), _imm(e, fp, 5)), gpr)


def _wide64(e: E, width):
    return e.sel(e.eq(width, 64), 0x00400000, 0)


def _fcmp(e: E, left, right, width):
    return e.add(e.add(e.add(0x1E202000, _wide64(e, width)), _imm(e, right, 16)), _imm(e, left, 5))


def _cset(e: E, d, condition):
    return e.add(e.add(0x1A9F07E0, _imm(e, e.bin(Operation.BIT_XOR, condition, 1), 12)), d)


def _cmp_registers(e: E, left, right, width):
    return e.add(e.add(e.sel(e.le(width, 32), 0x6B00001F, 0xEB00001F), _imm(e, right, 16)), _imm(e, left, 5))


def _cmp_immediate(e: E, register, value, width):
    return e.add(e.add(e.sel(e.le(width, 32), 0x7100001F, 0xF100001F), _imm(e, value, 10)), _imm(e, register, 5))


def _brk(e: E, code):
    return e.add(0xD4200000, _imm(e, e.and_(code, 0xFFFF), 5))


def _address_from_sp(e: E, d, offset):
    _ok(e, e.lt(offset, 4096))  # the bootstrap's AARCH64-STACK-ADDRESS-OFFSET
    return e.add(e.add(0x910003E0, _imm(e, offset, 10)), d)


def _load_store64(e: E, load: bool, register, offset):
    """``_load_store(load, register, offset, 64)`` against SP."""
    _ok(e, e.both(e.eq(e.and_(offset, 7), 0), e.lt(e.udiv(offset, 8), 4096)))
    return e.add(e.add(0xF94003E0 if load else 0xF90003E0, _imm(e, e.udiv(offset, 8), 10)), register)


def _float_raw_power(e: E, k, width):
    """The raw bits of ``float(2 ** k)`` in a binary32 or binary64 (``0 <= k < 64``)."""
    return e.sel(e.eq(width, 32), e.mul(e.add(127, k), 1 << 23), e.mul(e.add(1023, k), 1 << 52))


# -- small emitters (``xax_aarch64``'s word lists) ----------------------------------------------------------------------

def _chunk_fn(tables):
    """``_chunk(remaining, a, b)``: the largest of 8, 4, 2, 1 at most ``remaining`` dividing both offsets."""
    def build(e: E):
        p = e.p
        for size in (8, 4, 2):
            fits = e.both(e.le(size, p["remaining"]), e.eq(e.and_(p["a"], size - 1), 0), e.eq(e.and_(p["b"], size - 1), 0))
            e.if_(fits, lambda size=size: e.give(size))
        e.give(1)
    return _function(("remaining", "a", "b"), build, tables)


def _load_bytes_fn(tables):
    """``_load_register_bytes(destination, base, offset, size)``."""
    def build(e: E):
        p = e.p
        e.var("lb_done", 0)

        def step():
            e.var("lb_at", e.add(p["offset"], p["lb_done"]))
            e.var("lb_c", e.call(_FN["a64f_chunk"], e.sub(p["size"], p["lb_done"]), p["lb_at"], p["lb_at"]))
            e.if_(e.eq(p["lb_done"], 0), lambda: _emit(e, _base_access(e, True, p["destination"], p["base"], p["lb_at"], p["lb_c"])), lambda: (
                _emit(e, _base_access(e, True, TEMP, p["base"], p["lb_at"], p["lb_c"])),
                _emit(e, _bfi(e, p["destination"], TEMP, e.mul(p["lb_done"], 8), e.mul(p["lb_c"], 8)))))
            e.set("lb_done", e.add(p["lb_done"], p["lb_c"]))

        e.while_(lambda: e.lt(p["lb_done"], p["size"]), step)
        e.give(0)
    return _function(("destination", "base", "offset", "size"), build, tables)


def _store_bytes_fn(tables):
    """``_store_register_bytes(register, base, offset, size)``."""
    def build(e: E):
        p = e.p
        e.var("sb_done", 0)

        def step():
            e.var("sb_at", e.add(p["offset"], p["sb_done"]))
            e.var("sb_c", e.call(_FN["a64f_chunk"], e.sub(p["size"], p["sb_done"]), p["sb_at"], p["sb_at"]))
            e.var("sb_source", p["register"])
            e.if_(e.ne(p["sb_done"], 0), lambda: (_emit(e, _lsr(e, TEMP, p["register"], e.mul(p["sb_done"], 8))), e.set("sb_source", TEMP)))
            _emit(e, _base_access(e, False, p["sb_source"], p["base"], p["sb_at"], p["sb_c"]))
            e.set("sb_done", e.add(p["sb_done"], p["sb_c"]))

        e.while_(lambda: e.lt(p["sb_done"], p["size"]), step)
        e.give(0)
    return _function(("register", "base", "offset", "size"), build, tables)


def _zero_fn(tables):
    """``_zero_memory(base, offset, size)``: stores of the zero register."""
    def build(e: E):
        p = e.p
        e.var("zm_done", 0)

        def step():
            e.var("zm_at", e.add(p["offset"], p["zm_done"]))
            e.var("zm_c", e.call(_FN["a64f_chunk"], e.sub(p["size"], p["zm_done"]), p["zm_at"], p["zm_at"]))
            _emit(e, _base_access(e, False, 31, p["base"], p["zm_at"], p["zm_c"]))
            e.set("zm_done", e.add(p["zm_done"], p["zm_c"]))

        e.while_(lambda: e.lt(p["zm_done"], p["size"]), step)
        e.give(0)
    return _function(("base", "offset", "size"), build, tables)


def _copy_fn(tables):
    """``_copy_memory(destination base, destination, source base, source, size)`` through x16."""
    def build(e: E):
        p = e.p
        e.var("cm_done", 0)

        def step():
            e.var("cm_d", e.add(p["destination"], p["cm_done"]))
            e.var("cm_s", e.add(p["source"], p["cm_done"]))
            e.var("cm_c", e.call(_FN["a64f_chunk"], e.sub(p["size"], p["cm_done"]), p["cm_d"], p["cm_s"]))
            _emit(e, _base_access(e, True, TEMP, p["source_base"], p["cm_s"], p["cm_c"]))
            _emit(e, _base_access(e, False, TEMP, p["destination_base"], p["cm_d"], p["cm_c"]))
            e.set("cm_done", e.add(p["cm_done"], p["cm_c"]))

        e.while_(lambda: e.lt(p["cm_done"], p["size"]), step)
        e.give(0)
    return _function(("destination_base", "destination", "source_base", "source", "size"), build, tables)


def _movimm_fn(tables):
    """``_move_immediate(register, value, width)``: ``movz`` of the low halfword, ``movk`` of every other nonzero one."""
    def build(e: E):
        p = e.p
        e.var("mv_wide", e.flag(e.lt(32, p["width"])))
        e.var("mv_v", e.sel(e.ne(p["mv_wide"], 0), p["value"], e.and_(p["value"], 0xFFFFFFFF)))
        _emit(e, e.add(e.add(e.sel(e.ne(p["mv_wide"], 0), 0xD2800000, 0x52800000), _imm(e, e.and_(p["mv_v"], 0xFFFF), 5)), p["register"]))
        for half in (1, 2, 3):
            part = e.and_(e.udiv(p["mv_v"], 1 << (16 * half)), 0xFFFF)
            e.var("mv_part", part)
            present = e.ne(p["mv_part"], 0) if half == 1 else e.both(e.ne(p["mv_wide"], 0), e.ne(p["mv_part"], 0))
            e.if_(present, lambda half=half: _emit(e, e.add(e.add(e.add(e.sel(e.ne(p["mv_wide"], 0), 0xF2800000, 0x72800000), half << 21),
                                                                   _imm(e, p["mv_part"], 5)), p["register"])))
        e.give(0)
    return _function(("register", "value", "width"), build, tables)


def _mask(e: E, register, width):
    """``_mask_register_words``: ``ubfx`` to ``width`` unless it is 32 or 64."""
    e.if_(e.both(e.ne(width, 32), e.lt(width, 64)), lambda: _emit(e, _ubfx(e, register, register, 0, width)))


def _load(e: E, destination, base, offset, size):
    _call(e, "a64f_load_bytes", destination, base, offset, size)


def _store(e: E, register, base, offset, size):
    _call(e, "a64f_store_bytes", register, base, offset, size)


def _zero(e: E, base, offset, size):
    _call(e, "a64f_zero", base, offset, size)


def _copy(e: E, destination_base, destination, source_base, source, size):
    _call(e, "a64f_copy", destination_base, destination, source_base, source, size)


def _movimm(e: E, register, value, width):
    _call(e, "a64f_movimm", register, value, width)


def _new_label(e: E, name: str):
    """A fresh local label (after the blocks') into ``name``."""
    e.var(name, _a(e, F_NEXT_LABEL))
    _set_a(e, F_NEXT_LABEL, e.add(e.p[name], 1))
    return e.p[name]


def _slot_size(e: E, size):
    """``_slot_size``: ``align(max(1, size), 8)``."""
    return _align_to(e, e.sel(e.lt(size, 1), 1, size), 8)


# -- values ---------------------------------------------------------------------------------------------------------

def _type(e: E, value):
    return _vf(e, G_VTYPE, value)


def _slot(e: E, value):
    """The value's slot; a value without one (the bootstrap's AARCH64-VALUE-SLOT) declines."""
    e.var("vs_s", _rt(e, T_SLOT, value))
    _ok(e, e.ne(e.p["vs_s"], NONE))
    return e.p["vs_s"]


def _load_value_fn(tables):
    """``load_gpr(value, register, type)``: the first ``min(size, 8)`` bytes of the slot (``type`` NONE: the value's)."""
    def build(e: E):
        p = e.p
        e.var("lv_t", e.sel(e.eq(p["type"], NONE), _type(e, p["value"]), p["type"]))
        e.var("lv_size", _call(e, "abi_layout", p["lv_t"]))
        _load(e, p["register"], SP, _slot(e, p["value"]), e.sel(e.lt(8, p["lv_size"]), 8, p["lv_size"]))
        e.give(0)
    return _function(("value", "register", "type"), build, tables)


def _store_value_fn(tables):
    """``store_gpr(value, register, type)``: the slot zeroed, then ``min(size, 8)`` bytes of the register."""
    def build(e: E):
        p = e.p
        e.var("sv_t", e.sel(e.eq(p["type"], NONE), _type(e, p["value"]), p["type"]))
        e.var("sv_size", _call(e, "abi_layout", p["sv_t"]))
        e.var("sv_at", _slot(e, p["value"]))
        _zero(e, SP, p["sv_at"], _slot_size(e, p["sv_size"]))
        _store(e, p["register"], SP, p["sv_at"], e.sel(e.lt(8, p["sv_size"]), 8, p["sv_size"]))
        e.give(0)
    return _function(("value", "register", "type"), build, tables)


def _load_value(e: E, value, register, type_obj=NONE):
    _call(e, "a64f_load_value", value, register, type_obj)


def _store_value(e: E, value, register, type_obj=NONE):
    _call(e, "a64f_store_value", value, register, type_obj)


def _copy_value(e: E, destination, source, size=None):
    """``copy_ref``: the destination's layout size (or ``size``) bytes from the source's slot."""
    e.var("cv_d", destination)
    e.var("cv_s", source)
    amount = _rt(e, T_SIZE, e.p["cv_d"]) if size is None else size
    _copy(e, SP, _slot(e, e.p["cv_d"]), SP, _slot(e, e.p["cv_s"]), amount)


# -- AAPCS64 classes ---------------------------------------------------------------------------------------------------

def _homogeneous_fn(tables):
    """``abi_homogeneous_float(t)`` for a tuple or array type: its member bytes, its count in ``F_CLASS_COUNT``; 0
    when it is none.  The scalar leaves are walked in order with an explicit stack (``abi_scalar_leaves``): a sum is
    no static field list; more than four leaves is none; an array of more than four elements is none unless its
    element has no leaves (size 0, skipped)."""
    def build(e: E):
        p = e.p
        e.var("hf_stack", e.alloc(2 * HFA_STACK + 2))
        _ok(e, e.ne(p["hf_stack"], NONE))
        e.var("hf_leaves", e.alloc(2 * 5))
        _ok(e, e.ne(p["hf_leaves"], NONE))
        e.var("hf_n", 0)  # leaves
        e.var("hf_depth", 1)
        e.st(p["hf_stack"], p["t"])
        e.st(e.add(p["hf_stack"], 1), 0)
        e.var("hf_none", 0)

        def push(type_obj, base):
            _ok(e, e.lt(p["hf_depth"], HFA_STACK))
            e.st(e.add(p["hf_stack"], e.mul(p["hf_depth"], 2)), type_obj)
            e.st(e.add(p["hf_stack"], e.add(e.mul(p["hf_depth"], 2), 1)), base)
            e.set("hf_depth", e.add(p["hf_depth"], 1))

        def step():
            e.set("hf_depth", e.sub(p["hf_depth"], 1))
            e.var("hf_t", e.ld(e.add(p["hf_stack"], e.mul(p["hf_depth"], 2))))
            e.var("hf_base", e.ld(e.add(p["hf_stack"], e.add(e.mul(p["hf_depth"], 2), 1))))
            e.var("hf_form", _form(e, p["hf_t"]))
            form = p["hf_form"]

            def leaf():
                e.if_(e.eq(p["hf_n"], 4), lambda: e.set("hf_none", 1), lambda: (
                    e.st(e.add(p["hf_leaves"], e.mul(p["hf_n"], 2)), p["hf_base"]),
                    e.st(e.add(p["hf_leaves"], e.add(e.mul(p["hf_n"], 2), 1)), e.sel(e.eq(form, 7), _call(e, "abi_layout", p["hf_t"]), 0)),
                    e.set("hf_n", e.add(p["hf_n"], 1))))

            def tuple_():
                e.var("hf_at", e.add(_at(e, G_PAY, p["hf_t"]), 1))
                e.var("hf_count", _payload_uleb(e, "hf_at"))
                _ok(e, e.le(e.add(p["hf_depth"], p["hf_count"]), HFA_STACK))
                # Pushed last component first, so the first is walked first.
                e.var("hf_k", p["hf_count"])

                def component():
                    e.set("hf_k", e.sub(p["hf_k"], 1))
                    _component_offset(e, p["hf_t"], p["hf_k"], "hf_off")
                    e.var("hf_cat", e.add(_at(e, G_PAY, p["hf_t"]), 1))
                    _payload_uleb(e, "hf_cat")
                    e.for_("hf_j", 0, p["hf_k"], lambda: _payload_uleb(e, "hf_cat"))
                    push(_reference(e, p["hf_t"], _payload_uleb(e, "hf_cat")), e.add(p["hf_base"], p["hf_off"]))

                e.while_(lambda: e.ne(p["hf_k"], 0), component)

            def array():
                e.var("hf_aat", e.add(_at(e, G_PAY, p["hf_t"]), 1))
                e.var("hf_element", _reference(e, p["hf_t"], _payload_uleb(e, "hf_aat")))
                e.var("hf_elements", _payload_uleb(e, "hf_aat"))
                e.var("hf_esize", _call(e, "abi_layout", p["hf_element"]))

                def each_element():
                    e.set("hf_k", e.sub(p["hf_k"], 1))
                    push(p["hf_element"], e.add(p["hf_base"], e.mul(p["hf_k"], p["hf_esize"])))

                def elements():
                    e.var("hf_k", p["hf_elements"])
                    e.if_(e.lt(4, p["hf_elements"]), lambda: e.set("hf_none", 1), lambda: e.while_(lambda: e.ne(p["hf_k"], 0), each_element))

                e.if_(e.ne(p["hf_esize"], 0), elements)

            e.if_(_in(e, form, (1, 2, 7, 11)), leaf, lambda: e.if_(e.eq(form, 8), tuple_, lambda: e.if_(
                e.eq(form, 9), array, lambda: e.set("hf_none", 1))))

        e.while_(lambda: e.both(e.ne(p["hf_depth"], 0), e.eq(p["hf_none"], 0)), step)
        e.if_(e.either(e.ne(p["hf_none"], 0), e.eq(p["hf_n"], 0)), lambda: e.give(0))
        e.var("hf_member", e.ld(e.add(p["hf_leaves"], 1)))

        def check():
            e.var("hf_size", e.ld(e.add(p["hf_leaves"], e.add(e.mul(p["hf_q"], 2), 1))))
            e.var("hf_offset", e.ld(e.add(p["hf_leaves"], e.mul(p["hf_q"], 2))))
            # A non-float leaf has size 0 here, so it never matches a float member.
            e.if_(e.either(e.eq(p["hf_size"], 0), e.ne(p["hf_size"], p["hf_member"]), e.ne(p["hf_offset"], e.mul(p["hf_q"], p["hf_member"]))),
                  lambda: e.set("hf_none", 1))

        e.for_("hf_q", 0, p["hf_n"], check)
        e.if_(e.ne(p["hf_none"], 0), lambda: e.give(0))
        _set_a(e, F_CLASS_COUNT, p["hf_n"])
        e.give(p["hf_member"])
    return _function(("t",), build, tables)


def _class_fn(tables):
    """``_abi_class(t)``: the kind (``K_*``); its register count and member bytes in ``F_CLASS_COUNT`` and
    ``F_CLASS_MEMBER``."""
    def build(e: E):
        p = e.p
        e.var("cl_form", _form(e, p["t"]))

        def answer(kind, count, member):
            _set_a(e, F_CLASS_COUNT, count)
            _set_a(e, F_CLASS_MEMBER, member)
            e.give(kind)

        def float_():
            _float_width(e, p["t"], "cl_fw")
            answer(K_FPR, 1, e.udiv(p["cl_fw"], 8))

        def aggregate():
            e.var("cl_hfa", 0)
            e.if_(_in(e, p["cl_form"], (8, 9)), lambda: e.set("cl_hfa", _call(e, "a64f_homogeneous", p["t"])))
            e.if_(e.ne(p["cl_hfa"], 0), lambda: answer(K_HFA, _a(e, F_CLASS_COUNT), p["cl_hfa"]))
            e.var("cl_size", _call(e, "abi_layout", p["t"]))
            e.if_(e.le(p["cl_size"], 8), lambda: answer(K_GPR, 1, p["cl_size"]))
            e.if_(e.le(p["cl_size"], 16), lambda: answer(K_GPR2, 2, p["cl_size"]))
            answer(K_REF, 1, p["cl_size"])

        e.if_(e.eq(p["cl_form"], 7), float_)
        e.if_(_in(e, p["cl_form"], (8, 9, 10)), aggregate)
        answer(K_GPR, 1, 8)
    return _function(("t",), build, tables)


def _plan_fn(tables):
    """``_abi_argument_plan`` of the ``n`` types at ``types``: ``PLAN_WORDS`` per entry at ``out``; the stack bytes."""
    def build(e: E):
        p = e.p
        e.var("pl_gpr", 0)
        e.var("pl_fpr", 0)
        e.var("pl_stack", 0)

        def entry(kind, place, count, member):
            at = e.add(p["out"], e.mul(p["pl_k"], PLAN_WORDS))
            e.var("pl_at", at)
            for field, value in enumerate((kind, place, count, member)):
                e.st(e.add(p["pl_at"], field), value)

        def each():
            e.var("pl_t", e.ld(e.add(p["types"], p["pl_k"])))
            e.var("pl_kind", _call(e, "a64f_class", p["pl_t"]))
            e.var("pl_count", _a(e, F_CLASS_COUNT))
            e.var("pl_member", _a(e, F_CLASS_MEMBER))
            e.var("pl_size", _call(e, "abi_layout", p["pl_t"]))
            e.var("pl_align", e.ld(e.add(_g(e, _lalign()), p["pl_t"])))
            e.var("pl_done", 0)
            floats = _in(e, p["pl_kind"], (K_FPR, K_HFA))

            def vector():
                entry(p["pl_kind"], p["pl_fpr"], p["pl_count"], p["pl_member"])
                e.set("pl_fpr", e.add(p["pl_fpr"], p["pl_count"]))

            def vector_stack():
                e.set("pl_fpr", 8)
                e.var("pl_sa", e.sel(e.lt(p["pl_align"], 8), 8, e.sel(e.lt(16, p["pl_align"]), 16, p["pl_align"])))
                e.set("pl_stack", _align_to(e, p["pl_stack"], p["pl_sa"]))
                entry(K_STACK, p["pl_stack"], 3, p["pl_member"])
                e.set("pl_stack", e.add(p["pl_stack"], _align_to(e, p["pl_size"], 8)))

            def general():
                e.var("pl_needed", e.sel(e.eq(p["pl_kind"], K_GPR2), 2, 1))

                def register():
                    entry(p["pl_kind"], p["pl_gpr"], p["pl_needed"], p["pl_member"])
                    e.set("pl_gpr", e.add(p["pl_gpr"], p["pl_needed"]))

                def stacked():
                    e.set("pl_gpr", 8)
                    e.set("pl_stack", _align_to(e, p["pl_stack"], 8))
                    e.if_(e.eq(p["pl_kind"], K_REF), lambda: (entry(K_STACK, p["pl_stack"], 4, p["pl_member"]), e.set("pl_stack", e.add(p["pl_stack"], 8))),
                          lambda: (entry(K_STACK, p["pl_stack"], e.sel(e.eq(p["pl_kind"], K_GPR2), 2, 1), p["pl_member"]),
                                   e.set("pl_stack", e.add(p["pl_stack"], _align_to(e, p["pl_size"], 8)))))

                e.if_(e.le(e.add(p["pl_gpr"], p["pl_needed"]), 8), register, stacked)

            e.if_(floats, lambda: e.if_(e.le(e.add(p["pl_fpr"], p["pl_count"]), 8), vector, vector_stack), general)

        e.for_("pl_k", 0, p["n"], each)
        e.give(e.sel(e.ne(p["pl_stack"], 0), _align_to(e, p["pl_stack"], 16), 0))
    return _function(("types", "n", "out"), build, tables)


def _lalign():
    from xax_selfhost_x86_64_general import G_LALIGN

    return G_LALIGN


def _machine_operands(e: E, node, skip_first, name: str):
    """``name``: an array of the node's non-proof operand values (from operand ``skip_first``), ``name_n`` its count, and
    ``name_types`` their types."""
    p = e.p
    e.var(name, e.alloc(e.add(e.mul(_f(e, node, N_NOPS), 2), 2)))
    _ok(e, e.ne(p[name], NONE))
    e.var(f"{name}_types", e.add(p[name], e.add(_f(e, node, N_NOPS), 1)))
    e.var(f"{name}_n", 0)

    def each():
        e.var(f"{name}_v", _operand(e, node, p[f"{name}_k"]))
        e.if_(e.not_(_proof(e, _type(e, p[f"{name}_v"]))), lambda: (
            e.st(e.add(p[name], p[f"{name}_n"]), p[f"{name}_v"]), e.st(e.add(p[f"{name}_types"], p[f"{name}_n"]), _type(e, p[f"{name}_v"])),
            e.set(f"{name}_n", e.add(p[f"{name}_n"], 1))))

    e.for_(f"{name}_k", skip_first, _f(e, node, N_NOPS), each)


# -- eligibility for the other paths -------------------------------------------------------------------------------

def _register_path_fn(tables):
    """``_register_path_eligible`` of function ``f``'s own graph (lifted): 1 when the bootstrap takes the legacy
    register path (this program declines), 0 when it takes the frame path."""
    def build(e: E):
        p = e.p
        e.var("rp_ok", 1)

        def fail():
            e.set("rp_ok", 0)

        def scalar(type_obj, narrow: bool):
            e.var("rp_t", type_obj)
            form = _form(e, p["rp_t"])
            e.var("rp_form", form)

            def bits():
                e.var("rp_at", e.add(_at(e, G_PAY, p["rp_t"]), 1))
                e.var("rp_w", _payload_uleb(e, "rp_at"))
                widths = (1, 32, 64) if narrow else (32, 64)
                e.if_(e.not_(_in(e, p["rp_w"], widths)), fail)

            e.if_(e.eq(p["rp_form"], 1), bits, lambda: e.if_(e.not_(_in(e, p["rp_form"], (2, 3, 4))), fail))

        e.var("rp_i", _call(e, "interface", p["f"]))
        e.var("rp_np", e.ld(e.add(p["rp_i"], 1)))
        e.var("rp_rt", e.add(e.add(p["rp_i"], 2), p["rp_np"]))
        e.for_("rp_k", 0, p["rp_np"], lambda: scalar(e.ld(e.add(e.add(p["rp_i"], 2), p["rp_k"])), False))
        e.var("rp_mr", 0)
        e.for_("rp_k", 0, e.ld(p["rp_rt"]), lambda: (e.var("rp_r", e.ld(e.add(e.add(p["rp_rt"], 1), p["rp_k"]))), scalar(p["rp_r"], False),
                                                    e.if_(e.not_(_proof(e, p["rp_r"])), lambda: e.set("rp_mr", e.add(p["rp_mr"], 1)))))
        e.if_(e.lt(1, p["rp_mr"]), fail)

        def block():
            e.var("rp_b", _block_at(e, p["rp_bi"]))
            e.for_("rp_k", 0, _f(e, p["rp_b"], B_NP), lambda: scalar(_type(e, e.ld(e.add(_f(e, p["rp_b"], B_INPUTS), p["rp_k"]))), True))

            def node():
                e.var("rp_n", _node_at(e, p["rp_b"], p["rp_m"]))
                e.var("rp_op", _eop(e, p["rp_n"]))
                e.if_(e.not_(_in(e, p["rp_op"], REGISTER_PATH_OPERATIONS)), fail)
                e.for_("rp_o", 0, _f(e, p["rp_n"], N_NOPS), lambda: scalar(_type(e, _operand(e, p["rp_n"], p["rp_o"])), False))
                e.if_(e.ne(p["rp_op"], _op(Operation.INT_COMPARE)), lambda: e.for_(
                    "rp_o", 0, _f(e, p["rp_n"], N_NRES), lambda: scalar(_type(e, _output(e, p["rp_n"], p["rp_o"])), False)))

                def full_width():
                    e.var("rp_vt", e.sel(e.eq(p["rp_op"], _op(Operation.LOAD_BITS_LE)), _type(e, _output(e, p["rp_n"], 0)),
                                         _type(e, _operand(e, p["rp_n"], 1))))
                    e.var("rp_vat", e.add(_at(e, G_PAY, p["rp_vt"]), 1))
                    e.var("rp_vw", e.sel(e.eq(_form(e, p["rp_vt"]), 1), _payload_uleb(e, "rp_vat"), NONE))
                    e.if_(e.ne(p["rp_vw"], e.mul(_attribute(e, p["rp_n"], 0), 8)), fail)

                e.if_(_in(e, p["rp_op"], (_op(Operation.LOAD_BITS_LE), _op(Operation.STORE_BITS_LE))), full_width)

                def call():
                    e.var("rp_mo", 0)
                    e.for_("rp_o", 0, _f(e, p["rp_n"], N_NOPS), lambda: e.if_(e.not_(_proof(e, _type(e, _operand(e, p["rp_n"], p["rp_o"])))),
                                                                          lambda: e.set("rp_mo", e.add(p["rp_mo"], 1))))
                    e.var("rp_mres", 0)
                    e.for_("rp_o", 0, _f(e, p["rp_n"], N_NRES), lambda: e.if_(e.not_(_proof(e, _type(e, _output(e, p["rp_n"], p["rp_o"])))),
                                                                          lambda: e.set("rp_mres", e.add(p["rp_mres"], 1))))
                    e.if_(e.either(e.lt(e.add(8, e.flag(e.eq(p["rp_op"], _op(Operation.CALL_INDIRECT)))), p["rp_mo"]), e.lt(1, p["rp_mres"])), fail)

                e.if_(_in(e, p["rp_op"], CALLS), call)

            e.for_("rp_m", 0, _f(e, p["rp_b"], B_NNODES), node)

        e.for_("rp_bi", 0, _g(e, G_BCOUNT), block)
        e.give(p["rp_ok"])
    return _function(("f",), build, tables)


# -- the frame (``_compile_general_function``'s layout) -------------------------------------------------------------

def _def_block(e: E, value):
    return e.and_(e.udiv(_vf(e, G_VPOS, value), POS_BLOCK), (1 << 22) - 1)


def _cover(e: E, value, first, last):
    """``cover``: a machine value's hull grows to ``[first, last]``."""
    e.var("cv_v", value)
    e.var("cv_first", first)
    e.var("cv_last", last)
    p = e.p

    def grow():
        e.if_(e.eq(_rt(e, T_HULL_START, p["cv_v"]), NONE), lambda: (_set_rt(e, T_HULL_START, p["cv_v"], p["cv_first"]), _set_rt(e, T_HULL_END, p["cv_v"], p["cv_last"])),
              lambda: (e.if_(e.lt(p["cv_first"], _rt(e, T_HULL_START, p["cv_v"])), lambda: _set_rt(e, T_HULL_START, p["cv_v"], p["cv_first"])),
                       e.if_(e.lt(_rt(e, T_HULL_END, p["cv_v"]), p["cv_last"]), lambda: _set_rt(e, T_HULL_END, p["cv_v"], p["cv_last"]))))

    e.if_(e.ne(_rt(e, T_MACHINE, p["cv_v"]), 0), grow)


def _each_reference(e: E, visit):
    """``visit(value, block index, position)`` for every operand, terminator value and edge argument of the graph in
    order, with its position (``_frame_live_hulls``' numbering)."""
    p = e.p

    def block():
        e.var("er_b", _block_at(e, p["er_bi"]))
        e.var("er_start", e.ld(e.add(_a(e, F_STARTS), p["er_bi"])))

        def node():
            e.var("er_n", _node_at(e, p["er_b"], p["er_m"]))
            e.var("er_here", e.add(e.add(p["er_start"], 1), p["er_m"]))
            e.for_("er_o", 0, _f(e, p["er_n"], N_NOPS), lambda: visit(_operand(e, p["er_n"], p["er_o"]), p["er_bi"], p["er_here"]))

        e.for_("er_m", 0, _f(e, p["er_b"], B_NNODES), node)
        e.var("er_end", e.add(e.add(p["er_start"], _f(e, p["er_b"], B_NNODES)), 1))
        e.for_("er_k", 0, _f(e, p["er_b"], B_NVALUES), lambda: visit(e.ld(e.add(_f(e, p["er_b"], B_VALUES), p["er_k"])), p["er_bi"], p["er_end"]))

        def edge():
            e.var("er_at", e.add(_f(e, p["er_b"], B_EDGES), e.mul(p["er_q"], EDGE)))
            e.for_("er_k", 0, _f(e, p["er_at"], 1), lambda: visit(e.ld(e.add(_f(e, p["er_at"], 2), p["er_k"])), p["er_bi"], p["er_end"]))

        e.for_("er_q", 0, _f(e, p["er_b"], B_NEDGES), edge)

    e.for_("er_bi", 0, _g(e, G_BCOUNT), block)


def _hulls_fn(tables):
    """``_frame_live_hulls``: every machine value's hull ``[T_HULL_START, T_HULL_END]``.  Block liveness is the least
    fixed point of the bootstrap's backward dataflow, computed per value as reachability backwards from its uses in
    other blocks, stopping at its defining block."""
    def build(e: E):
        p = e.p
        n, nb = _g(e, G_VCOUNT), _g(e, G_BCOUNT)
        e.var("hl_n", n)
        e.var("hl_nb", nb)
        e.for_("hl_v", 0, p["hl_n"], lambda: (_set_rt(e, T_HULL_START, p["hl_v"], NONE), _set_rt(e, T_HULL_END, p["hl_v"], NONE)))
        # Block starts.
        e.var("hl_starts", e.alloc(e.add(p["hl_nb"], 1)))
        _ok(e, e.ne(p["hl_starts"], NONE))
        _set_a(e, F_STARTS, p["hl_starts"])
        e.var("hl_pos", 1)
        e.for_("hl_bi", 0, p["hl_nb"], lambda: (e.st(e.add(p["hl_starts"], p["hl_bi"]), p["hl_pos"]),
                                                e.set("hl_pos", e.add(e.add(p["hl_pos"], _f(e, _block_at(e, p["hl_bi"]), B_NNODES)), 2))))
        # Predecessors (one entry per edge).
        e.var("hl_np", e.alloc(e.add(p["hl_nb"], 1)))
        e.var("hl_pat", e.alloc(e.add(p["hl_nb"], 1)))
        _ok(e, e.both(e.ne(p["hl_np"], NONE), e.ne(p["hl_pat"], NONE)))
        e.for_("hl_bi", 0, p["hl_nb"], lambda: e.st(e.add(p["hl_np"], p["hl_bi"]), 0))
        e.var("hl_edges", 0)

        def count_edges():
            e.var("hl_b", _block_at(e, p["hl_bi"]))
            e.for_("hl_q", 0, _f(e, p["hl_b"], B_NEDGES), lambda: (
                e.var("hl_t", _f(e, _f(e, e.add(_f(e, p["hl_b"], B_EDGES), e.mul(p["hl_q"], EDGE)), 0), B_POS)),
                e.st(e.add(p["hl_np"], p["hl_t"]), e.add(e.ld(e.add(p["hl_np"], p["hl_t"])), 1)), e.set("hl_edges", e.add(p["hl_edges"], 1))))

        e.for_("hl_bi", 0, p["hl_nb"], count_edges)
        e.var("hl_preds", e.alloc(e.add(p["hl_edges"], 1)))
        _ok(e, e.ne(p["hl_preds"], NONE))
        e.var("hl_sum", 0)
        e.for_("hl_bi", 0, p["hl_nb"], lambda: (e.st(e.add(p["hl_pat"], p["hl_bi"]), p["hl_sum"]),
                                                e.set("hl_sum", e.add(p["hl_sum"], e.ld(e.add(p["hl_np"], p["hl_bi"])))),
                                                e.st(e.add(p["hl_np"], p["hl_bi"]), 0)))

        def fill_edges():
            e.var("hl_b", _block_at(e, p["hl_bi"]))
            e.for_("hl_q", 0, _f(e, p["hl_b"], B_NEDGES), lambda: (
                e.var("hl_t", _f(e, _f(e, e.add(_f(e, p["hl_b"], B_EDGES), e.mul(p["hl_q"], EDGE)), 0), B_POS)),
                e.st(e.add(p["hl_preds"], e.add(e.ld(e.add(p["hl_pat"], p["hl_t"])), e.ld(e.add(p["hl_np"], p["hl_t"])))), p["hl_bi"]),
                e.st(e.add(p["hl_np"], p["hl_t"]), e.add(e.ld(e.add(p["hl_np"], p["hl_t"])), 1))))

        e.for_("hl_bi", 0, p["hl_nb"], fill_edges)
        # Positions: parameters, node operands and results, terminator references.
        entry = _f(e, _g(e, G_BENTRY), B_POS)
        e.var("hl_entry", entry)

        def block_positions():
            e.var("hl_b", _block_at(e, p["hl_bi"]))
            e.var("hl_start", e.ld(e.add(p["hl_starts"], p["hl_bi"])))
            e.for_("hl_k", 0, _f(e, p["hl_b"], B_NP), lambda: _cover(e, e.ld(e.add(_f(e, p["hl_b"], B_INPUTS), p["hl_k"])),
                                                                   e.sel(e.eq(p["hl_bi"], p["hl_entry"]), 0, p["hl_start"]), p["hl_start"]))

            def node():
                e.var("hl_nd", _node_at(e, p["hl_b"], p["hl_m"]))
                e.var("hl_here", e.add(e.add(p["hl_start"], 1), p["hl_m"]))
                e.for_("hl_o", 0, _f(e, p["hl_nd"], N_NRES), lambda: _cover(e, _output(e, p["hl_nd"], p["hl_o"]), p["hl_here"], p["hl_here"]))

            e.for_("hl_m", 0, _f(e, p["hl_b"], B_NNODES), node)

        e.for_("hl_bi", 0, p["hl_nb"], block_positions)
        _each_reference(e, lambda value, _bi, position: _cover(e, value, position, position))  # operands and terminator references
        # Liveness: the references of a value in a block other than its own, as an inverted index.
        e.var("hl_count", e.alloc(e.add(p["hl_n"], 1)))
        _ok(e, e.ne(p["hl_count"], NONE))
        e.for_("hl_v", 0, e.add(p["hl_n"], 1), lambda: e.st(e.add(p["hl_count"], p["hl_v"]), 0))
        e.var("hl_refs", 0)

        def count(value, bi, _position):
            e.var("hl_cv", value)
            e.if_(e.both(e.ne(_rt(e, T_MACHINE, p["hl_cv"]), 0), e.ne(_def_block(e, p["hl_cv"]), bi)), lambda: (
                e.st(e.add(p["hl_count"], p["hl_cv"]), e.add(e.ld(e.add(p["hl_count"], p["hl_cv"])), 1)), e.set("hl_refs", e.add(p["hl_refs"], 1))))

        _each_reference(e, count)
        e.var("hl_first", e.alloc(e.add(p["hl_n"], 1)))
        e.var("hl_uses", e.alloc(e.add(p["hl_refs"], 1)))
        _ok(e, e.both(e.ne(p["hl_first"], NONE), e.ne(p["hl_uses"], NONE)))
        e.set("hl_sum", 0)
        e.for_("hl_v", 0, p["hl_n"], lambda: (e.st(e.add(p["hl_first"], p["hl_v"]), p["hl_sum"]),
                                              e.set("hl_sum", e.add(p["hl_sum"], e.ld(e.add(p["hl_count"], p["hl_v"])))),
                                              e.st(e.add(p["hl_count"], p["hl_v"]), 0)))

        def fill(value, bi, _position):
            e.var("hl_fv", value)
            e.var("hl_fb", bi)

            def put():
                e.var("hl_slot", e.add(e.ld(e.add(p["hl_first"], p["hl_fv"])), e.ld(e.add(p["hl_count"], p["hl_fv"]))))
                e.st(e.add(p["hl_uses"], p["hl_slot"]), p["hl_fb"])
                e.st(e.add(p["hl_count"], p["hl_fv"]), e.add(e.ld(e.add(p["hl_count"], p["hl_fv"])), 1))

            e.if_(e.both(e.ne(_rt(e, T_MACHINE, p["hl_fv"]), 0), e.ne(_def_block(e, p["hl_fv"]), p["hl_fb"])), put)

        _each_reference(e, fill)
        # Per value: blocks it is live into (stamp ``v + 1``) and out of, from its uses backwards.
        e.var("hl_in", e.alloc(e.add(p["hl_nb"], 1)))
        e.var("hl_out", e.alloc(e.add(p["hl_nb"], 1)))
        e.var("hl_work", e.alloc(e.add(p["hl_nb"], 1)))
        _ok(e, e.both(e.ne(p["hl_in"], NONE), e.ne(p["hl_out"], NONE), e.ne(p["hl_work"], NONE)))
        e.for_("hl_bi", 0, p["hl_nb"], lambda: (e.st(e.add(p["hl_in"], p["hl_bi"]), 0), e.st(e.add(p["hl_out"], p["hl_bi"]), 0)))

        def value():
            e.var("hl_mark", e.add(p["hl_v"], 1))
            e.var("hl_home", _def_block(e, p["hl_v"]))
            e.var("hl_top", 0)

            def live_in(block):
                e.var("hl_x", block)
                e.if_(e.ne(e.ld(e.add(p["hl_in"], p["hl_x"])), p["hl_mark"]), lambda: (
                    e.st(e.add(p["hl_in"], p["hl_x"]), p["hl_mark"]), e.st(e.add(p["hl_work"], p["hl_top"]), p["hl_x"]), e.set("hl_top", e.add(p["hl_top"], 1)),
                    _cover(e, p["hl_v"], e.ld(e.add(p["hl_starts"], p["hl_x"])), e.ld(e.add(p["hl_starts"], p["hl_x"])))))

            e.for_("hl_u", 0, e.ld(e.add(p["hl_count"], p["hl_v"])), lambda: live_in(e.ld(e.add(p["hl_uses"], e.add(e.ld(e.add(p["hl_first"], p["hl_v"])), p["hl_u"])))))

            def propagate():
                e.set("hl_top", e.sub(p["hl_top"], 1))
                e.var("hl_y", e.ld(e.add(p["hl_work"], p["hl_top"])))

                def predecessor():
                    e.var("hl_pp", e.ld(e.add(p["hl_preds"], e.add(e.ld(e.add(p["hl_pat"], p["hl_y"])), p["hl_j"]))))

                    def out():
                        e.st(e.add(p["hl_out"], p["hl_pp"]), p["hl_mark"])
                        e.var("hl_pend", e.add(e.add(e.ld(e.add(p["hl_starts"], p["hl_pp"])), _f(e, _block_at(e, p["hl_pp"]), B_NNODES)), 1))
                        _cover(e, p["hl_v"], p["hl_pend"], p["hl_pend"])

                    e.if_(e.ne(e.ld(e.add(p["hl_out"], p["hl_pp"])), p["hl_mark"]), out)
                    e.if_(e.ne(p["hl_pp"], p["hl_home"]), lambda: live_in(p["hl_pp"]))

                e.for_("hl_j", 0, e.ld(e.add(p["hl_np"], p["hl_y"])), predecessor)

            e.while_(lambda: e.ne(p["hl_top"], 0), propagate)

        e.for_("hl_v", 0, p["hl_n"], lambda: e.if_(e.ne(_rt(e, T_MACHINE, p["hl_v"]), 0), value))
        e.for_("hl_v", 0, p["hl_n"], lambda: e.if_(e.both(e.ne(_rt(e, T_MACHINE, p["hl_v"]), 0), e.eq(_rt(e, T_HULL_START, p["hl_v"]), NONE)),
                                                   lambda: (_set_rt(e, T_HULL_START, p["hl_v"], 0), _set_rt(e, T_HULL_END, p["hl_v"], 0))))
        e.give(0)
    return _function((), build, tables)


def _merge_sort(e: E, items, n, less):
    """Sort the ``n`` words at ``items`` in place by ``less(a, b)`` (bottom-up merges through a scratch array)."""
    p = e.p
    e.var("ms_items", items)
    e.var("ms_n", n)
    e.var("ms_tmp", e.alloc(e.add(p["ms_n"], 1)))
    _ok(e, e.ne(p["ms_tmp"], NONE))
    e.var("ms_width", 1)

    def rounds():
        e.var("ms_lo", 0)

        def merge():
            e.var("ms_mid", e.sel(e.lt(e.add(p["ms_lo"], p["ms_width"]), p["ms_n"]), e.add(p["ms_lo"], p["ms_width"]), p["ms_n"]))
            e.var("ms_hi", e.sel(e.lt(e.add(p["ms_mid"], p["ms_width"]), p["ms_n"]), e.add(p["ms_mid"], p["ms_width"]), p["ms_n"]))
            e.var("ms_i", p["ms_lo"])
            e.var("ms_j", p["ms_mid"])
            e.var("ms_k", p["ms_lo"])

            def take():
                e.var("ms_left", e.flag(e.lt(p["ms_i"], p["ms_mid"])))

                def choose():
                    e.var("ms_a", e.ld(e.add(p["ms_items"], p["ms_i"])))
                    e.var("ms_b", e.ld(e.add(p["ms_items"], p["ms_j"])))
                    e.set("ms_left", e.flag(e.not_(less(p["ms_b"], p["ms_a"]))))

                e.if_(e.both(e.ne(p["ms_left"], 0), e.lt(p["ms_j"], p["ms_hi"])), choose)
                e.if_(e.ne(p["ms_left"], 0), lambda: (e.st(e.add(p["ms_tmp"], p["ms_k"]), e.ld(e.add(p["ms_items"], p["ms_i"]))), e.set("ms_i", e.add(p["ms_i"], 1))),
                      lambda: (e.st(e.add(p["ms_tmp"], p["ms_k"]), e.ld(e.add(p["ms_items"], p["ms_j"]))), e.set("ms_j", e.add(p["ms_j"], 1))))
                e.set("ms_k", e.add(p["ms_k"], 1))

            e.while_(lambda: e.lt(p["ms_k"], p["ms_hi"]), take)
            e.for_("ms_c", p["ms_lo"], p["ms_hi"], lambda: e.st(e.add(p["ms_items"], p["ms_c"]), e.ld(e.add(p["ms_tmp"], p["ms_c"]))))
            e.set("ms_lo", p["ms_hi"])

        e.while_(lambda: e.lt(p["ms_lo"], p["ms_n"]), merge)
        e.set("ms_width", e.mul(p["ms_width"], 2))

    e.while_(lambda: e.lt(p["ms_width"], p["ms_n"]), rounds)


def _layout_fn(tables):
    """``_compile_general_function``'s frame: the outgoing argument area at offset 0, stack objects, value slots shared
    by disjoint hulls (ADR-123, the Linux profiles), the edge temporaries, the call copies of by-reference
    arguments, the link register's slot, the hidden return pointer's slot; the frame size, or AARCH64-FRAME-SIZE."""
    def build(e: E):
        p = e.p
        n = _g(e, G_VCOUNT)
        e.var("fl_n", n)
        e.for_("fl_v", 0, p["fl_n"], lambda: (
            _set_rt(e, T_SLOT, p["fl_v"], NONE), _set_rt(e, T_STACK, p["fl_v"], NONE),
            _set_rt(e, T_MACHINE, p["fl_v"], e.flag(e.not_(_proof(e, _type(e, p["fl_v"])))))))

        def each_node(visit):
            def block():
                e.var("fe_b", _block_at(e, p["fe_bi"]))
                e.for_("fe_m", 0, _f(e, p["fe_b"], B_NNODES), lambda: (e.var("fe_n", _node_at(e, p["fe_b"], p["fe_m"])), visit(p["fe_n"], p["fe_bi"], p["fe_m"])))

            e.for_("fe_bi", 0, _g(e, G_BCOUNT), block)

        # The outgoing area: the most stack bytes any call's machine arguments need; by-reference arguments' copies.
        e.var("fl_out", 0)
        e.var("fl_ncopies", 0)
        each_node(lambda node, bi, m: e.if_(_in(e, _eop(e, node), CALLS), lambda: e.set("fl_ncopies", e.add(p["fl_ncopies"], _f(e, node, N_NOPS)))))
        e.var("fl_copies", e.alloc(e.add(e.mul(p["fl_ncopies"], 3), 1)))
        _ok(e, e.ne(p["fl_copies"], NONE))
        _set_a(e, F_COPIES, p["fl_copies"])
        _set_a(e, F_NCOPIES, 0)
        e.var("fl_plan", e.alloc(e.mul(PLAN_WORDS, 1 << 12)))
        _ok(e, e.ne(p["fl_plan"], NONE))
        _set_a(e, F_PLAN, p["fl_plan"])

        def outgoing(node, bi, m):
            def call():
                _machine_operands(e, node, e.flag(e.eq(_eop(e, node), _op(Operation.CALL_INDIRECT))), "fl_mo")
                _ok(e, e.lt(p["fl_mo_n"], 1 << 12))
                e.var("fl_bytes", _call(e, "a64f_plan", p["fl_mo_types"], p["fl_mo_n"], p["fl_plan"]))
                e.if_(e.lt(p["fl_out"], p["fl_bytes"]), lambda: e.set("fl_out", p["fl_bytes"]))

                def copy():
                    e.var("fl_ckind", _call(e, "a64f_class", e.ld(e.add(p["fl_mo_types"], p["fl_ck"]))))

                    def record():
                        e.var("fl_cat", e.add(p["fl_copies"], e.mul(_a(e, F_NCOPIES), 3)))
                        e.st(p["fl_cat"], node)
                        e.st(e.add(p["fl_cat"], 1), p["fl_ck"])
                        e.st(e.add(p["fl_cat"], 2), NONE)
                        _set_a(e, F_NCOPIES, e.add(_a(e, F_NCOPIES), 1))

                    e.if_(e.eq(p["fl_ckind"], K_REF), record)

                e.for_("fl_ck", 0, p["fl_mo_n"], copy)

            e.if_(_in(e, _eop(e, node), CALLS), call)

        each_node(outgoing)
        e.var("fl_cursor", p["fl_out"])

        # Stack objects.
        def stack(node, bi, m):
            def place():
                e.set("fl_cursor", _align_to(e, p["fl_cursor"], _attribute(e, node, 1)))
                _set_rt(e, T_STACK, _output(e, node, 0), p["fl_cursor"])
                e.set("fl_cursor", e.add(p["fl_cursor"], _attribute(e, node, 0)))

            e.if_(e.eq(_eop(e, node), _op(Operation.STACK_ALLOC)), place)

        each_node(stack)
        # Value slots: machine values (block parameters, then node results, block by block), laid out.
        e.var("fl_values", e.alloc(e.add(p["fl_n"], 1)))
        _ok(e, e.ne(p["fl_values"], NONE))
        e.var("fl_count", 0)

        def gather():
            e.var("fl_b", _block_at(e, p["fl_bi"]))

            def add(value):
                e.var("fl_av", value)

                def machine():
                    e.var("fl_size", _call(e, "abi_layout", _type(e, p["fl_av"])))
                    _set_rt(e, T_SIZE, p["fl_av"], p["fl_size"])
                    _set_rt(e, T_ALIGN, p["fl_av"], e.ld(e.add(_g(e, _lalign()), _type(e, p["fl_av"]))))
                    e.st(e.add(p["fl_values"], p["fl_count"]), p["fl_av"])
                    e.set("fl_count", e.add(p["fl_count"], 1))

                e.if_(e.ne(_rt(e, T_MACHINE, p["fl_av"]), 0), machine)

            e.for_("fl_k", 0, _f(e, p["fl_b"], B_NP), lambda: add(e.ld(e.add(_f(e, p["fl_b"], B_INPUTS), p["fl_k"]))))
            e.for_("fl_m", 0, _f(e, p["fl_b"], B_NNODES), lambda: (e.var("fl_nd", _node_at(e, p["fl_b"], p["fl_m"])), e.for_(
                "fl_r", 0, _f(e, p["fl_nd"], N_NRES), lambda: add(_output(e, p["fl_nd"], p["fl_r"])))))

        e.for_("fl_bi", 0, _g(e, G_BCOUNT), gather)
        _call(e, "a64f_hulls")
        # The bootstrap's order: (hull start, tag, block, index, result); a value's position orders the last four.
        _merge_sort(e, p["fl_values"], p["fl_count"], lambda a, b: e.either(
            e.lt(_rt(e, T_HULL_START, a), _rt(e, T_HULL_START, b)),
            e.both(e.eq(_rt(e, T_HULL_START, a), _rt(e, T_HULL_START, b)), e.lt(_vf(e, G_VPOS, a), _vf(e, G_VPOS, b)))))
        # Free slots: (slot size, alignment, offset, busy until), in the order they were made.
        e.var("fl_free", e.alloc(e.add(e.mul(p["fl_count"], 4), 4)))
        _ok(e, e.ne(p["fl_free"], NONE))
        e.var("fl_nfree", 0)

        def assign():
            e.var("fl_v", e.ld(e.add(p["fl_values"], p["fl_q"])))
            e.var("fl_ks", _slot_size(e, _rt(e, T_SIZE, p["fl_v"])))
            e.var("fl_ka", e.sel(e.lt(_rt(e, T_ALIGN, p["fl_v"]), 8), 8, _rt(e, T_ALIGN, p["fl_v"])))
            e.var("fl_start", _rt(e, T_HULL_START, p["fl_v"]))
            e.var("fl_reuse", NONE)
            e.for_("fl_j", 0, p["fl_nfree"], lambda: (e.var("fl_fat", e.add(p["fl_free"], e.mul(p["fl_j"], 4))), e.if_(
                e.both(e.eq(p["fl_reuse"], NONE), e.eq(e.ld(p["fl_fat"]), p["fl_ks"]), e.eq(e.ld(e.add(p["fl_fat"], 1)), p["fl_ka"]),
                       e.lt(e.ld(e.add(p["fl_fat"], 3)), p["fl_start"])), lambda: e.set("fl_reuse", p["fl_fat"]))))

            def fresh():
                e.set("fl_cursor", _align_to(e, p["fl_cursor"], p["fl_ka"]))
                e.var("fl_new", e.add(p["fl_free"], e.mul(p["fl_nfree"], 4)))
                for field, word in enumerate((p["fl_ks"], p["fl_ka"], p["fl_cursor"], _rt(e, T_HULL_END, p["fl_v"]))):
                    e.st(e.add(p["fl_new"], field), word)
                e.set("fl_nfree", e.add(p["fl_nfree"], 1))
                _set_rt(e, T_SLOT, p["fl_v"], p["fl_cursor"])
                e.set("fl_cursor", e.add(p["fl_cursor"], p["fl_ks"]))

            def reuse():
                _set_rt(e, T_SLOT, p["fl_v"], e.ld(e.add(p["fl_reuse"], 2)))
                e.st(e.add(p["fl_reuse"], 3), _rt(e, T_HULL_END, p["fl_v"]))

            e.if_(e.eq(p["fl_reuse"], NONE), fresh, reuse)

        e.for_("fl_q", 0, p["fl_count"], assign)
        # The edge temporaries: the most slot bytes of any block's machine parameters.
        e.var("fl_temp", 0)

        def temporaries():
            e.var("fl_b", _block_at(e, p["fl_bi"]))
            e.var("fl_sum", 0)
            e.for_("fl_k", 0, _f(e, p["fl_b"], B_NP), lambda: (e.var("fl_pv", e.ld(e.add(_f(e, p["fl_b"], B_INPUTS), p["fl_k"]))), e.if_(
                e.ne(_rt(e, T_MACHINE, p["fl_pv"]), 0), lambda: e.set("fl_sum", e.add(p["fl_sum"], _slot_size(e, _rt(e, T_SIZE, p["fl_pv"])))))))
            e.if_(e.lt(p["fl_temp"], p["fl_sum"]), lambda: e.set("fl_temp", p["fl_sum"]))

        e.for_("fl_bi", 0, _g(e, G_BCOUNT), temporaries)
        e.set("fl_cursor", _align_to(e, p["fl_cursor"], 8))
        _set_a(e, F_EDGE_TEMP, p["fl_cursor"])
        e.set("fl_cursor", e.add(p["fl_cursor"], p["fl_temp"]))

        # The call copies.
        def copies():
            e.var("fl_cat", e.add(p["fl_copies"], e.mul(p["fl_c"], 3)))
            e.var("fl_ct", NONE)
            e.var("fl_cnode", e.ld(p["fl_cat"]))
            _machine_operands(e, p["fl_cnode"], 0, "fl_cmo")
            e.set("fl_ct", e.ld(e.add(p["fl_cmo_types"], e.ld(e.add(p["fl_cat"], 1)))))
            e.var("fl_csize", _call(e, "abi_layout", p["fl_ct"]))
            e.var("fl_calign", e.ld(e.add(_g(e, _lalign()), p["fl_ct"])))
            e.set("fl_cursor", _align_to(e, p["fl_cursor"], e.sel(e.lt(p["fl_calign"], 8), 8, p["fl_calign"])))
            e.st(e.add(p["fl_cat"], 2), p["fl_cursor"])
            e.set("fl_cursor", e.add(p["fl_cursor"], _slot_size(e, p["fl_csize"])))

        e.for_("fl_c", 0, _a(e, F_NCOPIES), copies)
        # The link register's slot when the function calls (an erased proof function is no call).
        e.var("fl_calls", 0)

        def calls(node, bi, m):
            e.var("fl_cop", _eop(e, node))

            def direct():
                _callee_object(e, node, "fl_callee")
                _ok(e, e.ne(p["fl_callee"], NONE))
                e.if_(e.eq(_call(e, "erased", p["fl_callee"]), 0), lambda: e.set("fl_calls", 1))

            e.if_(_in(e, p["fl_cop"], (_op(Operation.CALL_FOREIGN), _op(Operation.CALL_INDIRECT))), lambda: e.set("fl_calls", 1),
                  lambda: e.if_(e.eq(p["fl_cop"], _op(Operation.CALL_DIRECT)), direct))

        each_node(calls)
        _set_a(e, F_HASCALL, p["fl_calls"])
        _set_a(e, F_LINK, NONE)
        e.if_(e.ne(p["fl_calls"], 0), lambda: (e.set("fl_cursor", _align_to(e, p["fl_cursor"], 8)), _set_a(e, F_LINK, p["fl_cursor"]),
                                               e.set("fl_cursor", e.add(p["fl_cursor"], 8))))
        # The hidden return pointer: the first machine return (borrowed views given back excluded) is by reference.
        e.var("fl_i", _a(e, A_IFACE_SLOT()))
        e.var("fl_np", e.ld(e.add(p["fl_i"], 1)))
        e.var("fl_rt", e.add(e.add(p["fl_i"], 2), p["fl_np"]))
        e.var("fl_first", NONE)
        e.for_("fl_k", 0, e.ld(p["fl_rt"]), lambda: (e.var("fl_t", e.ld(e.add(e.add(p["fl_rt"], 1), p["fl_k"]))), e.if_(
            e.both(e.eq(p["fl_first"], NONE), e.not_(_proof(e, p["fl_t"])), e.eq(e.ld(e.add(_a(e, A_OWNB_SLOT()), p["fl_k"])), NONE)),
            lambda: e.set("fl_first", p["fl_t"]))))
        _set_a(e, F_HIDDEN, 0)
        e.if_(e.ne(p["fl_first"], NONE), lambda: e.if_(e.eq(_call(e, "a64f_class", p["fl_first"]), K_REF), lambda: _set_a(e, F_HIDDEN, 1)))
        _set_a(e, F_RETPTR, NONE)
        e.if_(e.ne(_a(e, F_HIDDEN), 0), lambda: (e.set("fl_cursor", _align_to(e, p["fl_cursor"], 8)), _set_a(e, F_RETPTR, p["fl_cursor"]),
                                                 e.set("fl_cursor", e.add(p["fl_cursor"], 8))))
        e.var("fl_frame", e.sel(e.ne(p["fl_cursor"], 0), _align_to(e, p["fl_cursor"], 16), 0))

        def too_large():
            from xax_selfhost_aarch64_general import SITE

            def write():
                e.call(_FN["diagnostic"], SITE["AARCH64-FRAME-SIZE"], e.ld(_call(e, "interface", _a(e, F_FN))))
                D.text(e, "< 4096 bytes")
                D.integer(e, p["fl_frame"])

            D.reject_unless(e, e.eq(1, 0), write)

        e.if_(e.le(4096, p["fl_frame"]), too_large)
        _set_a(e, F_FRAME, p["fl_frame"])
        e.give(1)
    return _function(("f",), build, tables)


def A_IFACE_SLOT():
    from xax_selfhost_aarch64_lower import A_IFACE

    return A_IFACE


def A_OWNB_SLOT():
    from xax_selfhost_aarch64_lower import A_OWNB

    return A_OWNB


def _copy_slot(e: E, node, operand):
    """The frame offset of call ``node``'s copy of its by-reference machine argument number ``operand``."""
    p = e.p
    e.var("cs_at", NONE)
    e.for_("cs_q", 0, _a(e, F_NCOPIES), lambda: (e.var("cs_r", e.add(_a(e, F_COPIES), e.mul(p["cs_q"], 3))), e.if_(
        e.both(e.eq(p["cs_at"], NONE), e.eq(e.ld(p["cs_r"]), node), e.eq(e.ld(e.add(p["cs_r"], 1)), operand)),
        lambda: e.set("cs_at", e.ld(e.add(p["cs_r"], 2))))))
    _ok(e, e.ne(p["cs_at"], NONE))
    return p["cs_at"]


# -- nodes ----------------------------------------------------------------------------------------------------------

def _prelude(e: E):
    """``nd_node``, ``nd_op``, ``nd_res`` (result 0 or NONE), ``nd_a``/``nd_b`` (operands 0 and 1 or NONE) of node ``m``
    of block ``bi``."""
    p = e.p
    e.var("nd_block", _block_at(e, p["bi"]))
    e.var("nd_node", _node_at(e, p["nd_block"], p["m"]))
    e.var("nd_op", _eop(e, p["nd_node"]))
    e.var("nd_res", e.sel(e.ne(_f(e, p["nd_node"], N_NRES), 0), _output(e, p["nd_node"], 0), NONE))
    e.var("nd_a", e.sel(e.ne(_f(e, p["nd_node"], N_NOPS), 0), _operand(e, p["nd_node"], 0), NONE))
    e.var("nd_b", e.sel(e.lt(1, _f(e, p["nd_node"], N_NOPS)), _operand(e, p["nd_node"], e.sel(e.lt(1, _f(e, p["nd_node"], N_NOPS)), 1, 0)), NONE))
    return p["nd_node"], p["nd_op"], p["nd_res"]


def _bits(e: E, type_obj, name: str):
    """``decode_bits_width`` of a bits type into ``name`` (0 for another form)."""
    p = e.p
    e.var(name, 0)
    e.var(f"{name}_t", type_obj)

    def read():
        e.var(f"{name}_at", e.add(_at(e, G_PAY, p[f"{name}_t"]), 1))
        e.set(name, _payload_uleb(e, f"{name}_at"))

    e.if_(e.eq(_form(e, p[f"{name}_t"]), 1), read)
    return p[name]


def _integer_fn(tables):
    """Arithmetic, bitwise operations, division, width changes, rotation, constants, integer compares: 1, or 0 when
    the node is not one of them."""
    def build(e: E):
        p = e.p
        node, op, result = _prelude(e)

        def arithmetic():
            _bits(e, _type(e, result), "ar_w")
            _load_value(e, p["nd_a"], TEMP)
            _load_value(e, p["nd_b"], TEMP2)
            e.var("ar_wide", e.flag(e.lt(32, p["ar_w"])))
            base = e.c(0)
            for operation, (narrow, wide) in ARITHMETIC.items():
                base = e.sel(e.eq(op, _op(operation)), e.sel(e.ne(p["ar_wide"], 0), wide, narrow), base)
            _emit(e, _three(e, base, TEMP, TEMP, TEMP2))
            _mask(e, TEMP, p["ar_w"])
            _store_value(e, result, TEMP, _type(e, result))
            e.give(1)

        e.if_(_in(e, op, tuple(_op(item) for item in ARITHMETIC)), arithmetic)

        def completion():
            _bits(e, _type(e, result), "cp_w")
            e.var("cp_wide", e.flag(e.lt(32, p["cp_w"])))
            _load_value(e, p["nd_a"], TEMP)
            _load_value(e, p["nd_b"], TEMP2)

            def division():
                e.var("cp_ok", _new_label(e, "cp_label"))
                _branch(e, e.add(e.sel(e.ne(p["cp_wide"], 0), 0xB5000000, 0x35000000), TEMP2), p["cp_ok"], 19)  # cbnz
                _emit(e, _brk(e, BRK_DIVIDE_BY_ZERO))
                _label(e, p["cp_ok"])
                udiv = lambda d: e.add(e.add(e.add(e.sel(e.ne(p["cp_wide"], 0), 0x9AC00800, 0x1AC00800), _imm(e, TEMP2, 16)), _imm(e, TEMP, 5)), d)  # noqa: E731
                e.if_(e.eq(op, _op(Operation.UDIV)), lambda: _emit(e, udiv(TEMP)), lambda: (
                    _emit(e, udiv(REMAINDER)),
                    _emit(e, e.add(e.add(e.add(e.add(e.sel(e.ne(p["cp_wide"], 0), 0x9B008000, 0x1B008000), _imm(e, TEMP2, 16)), _imm(e, TEMP, 10)),
                                         _imm(e, REMAINDER, 5)), TEMP))))

            def logical():
                base = e.c(0)
                for operation, word in LOGICAL.items():
                    base = e.sel(e.eq(op, _op(operation)), word, base)
                _emit(e, _three(e, e.add(base, e.sel(e.ne(p["cp_wide"], 0), 0x80000000, 0)), TEMP, TEMP, TEMP2))

            e.if_(_in(e, op, (_op(Operation.UDIV), _op(Operation.UREM))), division, logical)
            _store_value(e, result, TEMP, _type(e, result))
            e.give(1)

        e.if_(_in(e, op, tuple(_op(item) for item in (*LOGICAL, Operation.UDIV, Operation.UREM))), completion)

        def width_change():
            _load_value(e, p["nd_a"], TEMP, _type(e, p["nd_a"]))
            _mask(e, TEMP, _bits(e, _type(e, result), "wc_w"))
            _store_value(e, result, TEMP, _type(e, result))
            e.give(1)

        e.if_(_in(e, op, (_op(Operation.INT_TRUNCATE), _op(Operation.INT_ZERO_EXTEND))), width_change)

        def rotate():
            _bits(e, _type(e, result), "rt_w")
            e.var("rt_amount", _attribute(e, node, 0))
            _load_value(e, p["nd_a"], TEMP)

            def rotated():
                _emit(e, _lsr(e, TEMP2, TEMP, p["rt_amount"]))
                _emit(e, _lsl(e, TEMP, TEMP, e.sub(p["rt_w"], p["rt_amount"])))
                _emit(e, _three(e, 0xAA000000, TEMP, TEMP, TEMP2))
                _mask(e, TEMP, p["rt_w"])

            e.if_(e.ne(p["rt_amount"], 0), rotated)
            _store_value(e, result, TEMP, _type(e, result))
            e.give(1)

        e.if_(e.eq(op, _op(Operation.ROTATE_RIGHT)), rotate)

        def constant():
            e.var("ct_t", _type(e, result))
            _constant_bytes(e, node, "ct_value")
            e.var("ct_width", 0)
            e.if_(e.eq(_form(e, p["ct_t"]), 7), lambda: (_float_width(e, p["ct_t"], "ct_fw"), e.set("ct_width", p["ct_fw"])), lambda: (
                _bits(e, p["ct_t"], "ct_bw"), e.set("ct_width", e.sel(e.lt(64, p["ct_bw"]), 64, e.sel(e.lt(p["ct_bw"], 32), 32, p["ct_bw"])))))
            _movimm(e, TEMP, p["ct_value"], p["ct_width"])
            _store_value(e, result, TEMP, p["ct_t"])
            e.give(1)

        e.if_(e.eq(op, _op(Operation.CONSTANT)), constant)

        def compare():
            _bits(e, _type(e, p["nd_a"]), "ic_w")
            _load_value(e, p["nd_a"], TEMP)
            _load_value(e, p["nd_b"], TEMP2)
            e.var("ic_kind", _attribute(e, node, 0))
            e.if_(e.both(_in(e, p["ic_kind"], SIGNED), e.lt(p["ic_w"], 64)), lambda: (
                _emit(e, _sbfx(e, TEMP, TEMP, p["ic_w"])), _emit(e, _sbfx(e, TEMP2, TEMP2, p["ic_w"]))))
            _emit(e, _cmp_registers(e, TEMP, TEMP2, e.sel(e.le(p["ic_w"], 32), 32, 64)))
            condition = e.c(0)
            for kind, code in INT_CONDITION.items():
                condition = e.sel(e.eq(p["ic_kind"], int(kind)), code, condition)
            _emit(e, _cset(e, TEMP, condition))
            _store_value(e, result, TEMP, _type(e, result))
            e.give(1)

        e.if_(e.eq(op, _op(Operation.INT_COMPARE)), compare)
        e.give(0)
    return _function(("bi", "m"), build, tables)


def _float_fn(tables):
    """The float operations, conversions and compares: 1, or 0 when the node is not one of them."""
    def build(e: E):
        p = e.p
        node, op, result = _prelude(e)

        def binary():
            _float_width(e, _type(e, result), "fb_w")
            _load_value(e, p["nd_a"], TEMP)
            _emit(e, _fmov_to_fp(e, FP_TEMP, TEMP, p["fb_w"]))
            _load_value(e, p["nd_b"], TEMP2)
            _emit(e, _fmov_to_fp(e, FP_TEMP2, TEMP2, p["fb_w"]))
            base = e.c(0)
            for operation, word in FLOAT_BINARY.items():
                base = e.sel(e.eq(op, _op(operation)), word, base)
            _emit(e, _three(e, e.add(base, _wide64(e, p["fb_w"])), FP_TEMP, FP_TEMP, FP_TEMP2))
            _emit(e, _fmov_from_fp(e, TEMP, FP_TEMP, p["fb_w"]))
            _store_value(e, result, TEMP, _type(e, result))
            e.give(1)

        e.if_(_in(e, op, tuple(_op(item) for item in FLOAT_BINARY)), binary)

        def compare():
            _float_width(e, _type(e, p["nd_a"]), "fc_w")
            _load_value(e, p["nd_a"], TEMP)
            _emit(e, _fmov_to_fp(e, FP_TEMP, TEMP, p["fc_w"]))
            _load_value(e, p["nd_b"], TEMP2)
            _emit(e, _fmov_to_fp(e, FP_TEMP2, TEMP2, p["fc_w"]))
            _emit(e, _fcmp(e, FP_TEMP, FP_TEMP2, p["fc_w"]))
            e.var("fc_kind", _attribute(e, node, 0))
            condition = e.c(0)
            for kind, code in FLOAT_CONDITION.items():
                condition = e.sel(e.eq(p["fc_kind"], int(kind)), code, condition)
            _emit(e, _cset(e, TEMP, condition))
            _store_value(e, result, TEMP, _type(e, result))
            e.give(1)

        e.if_(e.eq(op, _op(Operation.FLOAT_COMPARE)), compare)

        def to_float():
            _bits(e, _type(e, p["nd_a"]), "tf_sw")
            _float_width(e, _type(e, result), "tf_fw")
            _load_value(e, p["nd_a"], TEMP)
            e.var("tf_signed", e.flag(e.eq(op, _op(Operation.SINT_TO_FLOAT))))
            e.if_(e.lt(p["tf_sw"], 64), lambda: e.if_(e.ne(p["tf_signed"], 0), lambda: _emit(e, _sbfx(e, TEMP, TEMP, p["tf_sw"])),
                                                      lambda: _mask(e, TEMP, p["tf_sw"])))
            _emit(e, e.add(e.add(e.add(e.sel(e.ne(p["tf_signed"], 0), 0x9E220000, 0x9E230000), _wide64(e, p["tf_fw"])), _imm(e, TEMP, 5)), FP_TEMP))
            _emit(e, _fmov_from_fp(e, TEMP, FP_TEMP, p["tf_fw"]))
            _store_value(e, result, TEMP, _type(e, result))
            e.give(1)

        e.if_(_in(e, op, (_op(Operation.UINT_TO_FLOAT), _op(Operation.SINT_TO_FLOAT))), to_float)

        def truncate():
            _float_width(e, _type(e, p["nd_a"]), "ft_iw")
            _bits(e, _type(e, result), "ft_ow")
            e.var("ft_signed", e.flag(e.eq(op, _op(Operation.FLOAT_TO_SINT_TRUNC))))
            _load_value(e, p["nd_a"], TEMP)
            _emit(e, _fmov_to_fp(e, FP_TEMP, TEMP, p["ft_iw"]))
            e.var("ft_trap", _new_label(e, "ft_l1"))
            e.var("ft_done", _new_label(e, "ft_l2"))

            def threshold(raw):
                _movimm(e, TEMP2, raw, p["ft_iw"])
                _emit(e, _fmov_to_fp(e, FP_TEMP2, TEMP2, p["ft_iw"]))
                _emit(e, _fcmp(e, FP_TEMP, FP_TEMP2, p["ft_iw"]))

            def bcond(condition):
                _branch(e, 0x54000000 | condition, p["ft_trap"], 19)

            sign = e.sel(e.eq(p["ft_iw"], 32), 0x80000000, 1 << 63)
            threshold(0)  # NaN is unordered and traps for every integer conversion
            bcond(COND["vs"])

            def signed():
                e.var("ft_n", e.sub(p["ft_ow"], 1))  # lower = -(2 ** n)
                # ``float(lower - 1)`` is exact while 2 ** n + 1 fits the significand (24 or 53 bits).
                exact = e.le(p["ft_n"], e.sel(e.eq(p["ft_iw"], 32), 23, 52))

                def below():
                    # -(2 ** n + 1): 2 for n = 0, else exponent n with the significand's lowest bit at n.
                    e.var("ft_raw", e.sel(e.eq(p["ft_n"], 0), _float_raw_power(e, 1, p["ft_iw"]), e.add(
                        _float_raw_power(e, p["ft_n"], p["ft_iw"]), _power(e, e.sub(e.sel(e.eq(p["ft_iw"], 32), 23, 52), p["ft_n"])))))
                    threshold(e.add(p["ft_raw"], sign))
                    bcond(COND["le"])

                def lowest():
                    threshold(e.add(_float_raw_power(e, p["ft_n"], p["ft_iw"]), sign))
                    bcond(COND["mi"])

                e.if_(exact, below, lowest)
                threshold(_float_raw_power(e, p["ft_n"], p["ft_iw"]))
                bcond(COND["ge"])

            def unsigned():
                threshold(0)
                bcond(COND["mi"])
                threshold(_float_raw_power(e, p["ft_ow"], p["ft_iw"]))
                bcond(COND["ge"])

            e.if_(e.ne(p["ft_signed"], 0), signed, unsigned)
            _emit(e, e.add(e.add(e.add(e.sel(e.ne(p["ft_signed"], 0), 0x9E380000, 0x9E390000), _wide64(e, p["ft_iw"])), _imm(e, FP_TEMP, 5)), TEMP))
            _mask(e, TEMP, p["ft_ow"])
            _store_value(e, result, TEMP, _type(e, result))
            _branch(e, 0x14000000, p["ft_done"], 26)
            _label(e, p["ft_trap"])
            _emit(e, _brk(e, BRK_FLOAT_CONVERSION))
            _label(e, p["ft_done"])
            e.give(1)

        e.if_(_in(e, op, (_op(Operation.FLOAT_TO_UINT_TRUNC), _op(Operation.FLOAT_TO_SINT_TRUNC))), truncate)

        def convert():
            _float_width(e, _type(e, p["nd_a"]), "cv_sw")
            _float_width(e, _type(e, result), "cv_dw")
            _load_value(e, p["nd_a"], TEMP)
            _emit(e, _fmov_to_fp(e, FP_TEMP, TEMP, p["cv_sw"]))
            e.if_(e.ne(p["cv_sw"], p["cv_dw"]), lambda: _emit(e, e.add(e.add(e.sel(e.eq(p["cv_sw"], 32), 0x1E22C000, 0x1E624000), _imm(e, FP_TEMP, 5)), FP_TEMP)))
            _emit(e, _fmov_from_fp(e, TEMP, FP_TEMP, p["cv_dw"]))
            _store_value(e, result, TEMP, _type(e, result))
            e.give(1)

        e.if_(e.eq(op, _op(Operation.FLOAT_CONVERT)), convert)
        e.give(0)
    return _function(("bi", "m"), build, tables)


def _power(e: E, k, name: str = "pw"):
    """``2 ** k`` for ``0 <= k < 64``, computed (the range analysis's table is not filled on this path)."""
    e.var(f"{name}_k", k)
    e.var(name, 1)
    e.for_(f"{name}_i", 0, e.p[f"{name}_k"], lambda: e.set(name, e.mul(e.p[name], 2)))
    return e.p[name]


def _data_fn(tables):
    """Products, sums, stack objects, pointers, rebases, heap views, plain and checked memory: 1, or 0 when the node is
    not one of them."""
    def build(e: E):
        p = e.p
        node, op, result = _prelude(e)

        def make():
            e.var("ag_t", _type(e, result))
            e.var("ag_at", _slot(e, result))
            _zero(e, SP, p["ag_at"], _slot_size(e, _rt(e, T_SIZE, result)))

            def component():
                e.var("ag_v", _operand(e, node, p["ag_k"]))
                _component_offset(e, p["ag_t"], p["ag_k"], "ag_off")
                _copy(e, SP, e.add(p["ag_at"], p["ag_off"]), SP, _slot(e, p["ag_v"]), _rt(e, T_SIZE, p["ag_v"]))

            e.for_("ag_k", 0, _f(e, node, N_NOPS), component)
            e.give(1)

        e.if_(e.eq(op, _op(Operation.AGGREGATE_MAKE)), make)

        def get():
            _component_offset(e, _type(e, p["nd_a"]), _attribute(e, node, 0), "gt_off")
            e.var("gt_at", _slot(e, result))
            _zero(e, SP, p["gt_at"], _slot_size(e, _rt(e, T_SIZE, result)))
            _copy(e, SP, p["gt_at"], SP, e.add(_slot(e, p["nd_a"]), p["gt_off"]), _rt(e, T_SIZE, result))
            e.give(1)

        e.if_(e.eq(op, _op(Operation.AGGREGATE_GET)), get)

        def sum_make():
            e.var("sm_at", _slot(e, result))
            _zero(e, SP, p["sm_at"], _slot_size(e, _rt(e, T_SIZE, result)))
            _movimm(e, TEMP, _attribute(e, node, 0), 32)
            _emit(e, _base_access(e, False, TEMP, SP, p["sm_at"], 4))
            _payload_offset(e, _type(e, result), "sm_off")
            _copy(e, SP, e.add(p["sm_at"], p["sm_off"]), SP, _slot(e, p["nd_a"]), _rt(e, T_SIZE, p["nd_a"]))
            e.give(1)

        e.if_(e.eq(op, _op(Operation.SUM_MAKE)), sum_make)

        def sum_tag():
            _emit(e, _base_access(e, True, TEMP, SP, _slot(e, p["nd_a"]), 4))
            _store_value(e, result, TEMP, _type(e, result))
            e.give(1)

        e.if_(e.eq(op, _op(Operation.SUM_TAG)), sum_tag)

        def sum_get():
            e.var("sg_ok", _new_label(e, "sg_label"))
            _emit(e, _base_access(e, True, TEMP, SP, _slot(e, p["nd_a"]), 4))
            _emit(e, _cmp_immediate(e, TEMP, _attribute(e, node, 0), 32))
            _branch(e, 0x54000000 | COND["eq"], p["sg_ok"], 19)
            _emit(e, _brk(e, BRK_SUM_VARIANT))
            _label(e, p["sg_ok"])
            e.var("sg_at", _slot(e, result))
            _zero(e, SP, p["sg_at"], _slot_size(e, _rt(e, T_SIZE, result)))
            _payload_offset(e, _type(e, p["nd_a"]), "sg_off")
            _copy(e, SP, p["sg_at"], SP, e.add(_slot(e, p["nd_a"]), p["sg_off"]), _rt(e, T_SIZE, result))
            e.give(1)

        e.if_(e.eq(op, _op(Operation.SUM_GET)), sum_get)

        def stack():
            _emit(e, _address_from_sp(e, TEMP, _rt(e, T_STACK, result)))
            _store_value(e, result, TEMP, _type(e, result))
            e.give(1)

        e.if_(e.eq(op, _op(Operation.STACK_ALLOC)), stack)

        def offset():
            _load_value(e, p["nd_a"], TEMP)
            e.var("ao_off", _attribute(e, node, 0))
            e.if_(e.lt(p["ao_off"], 4096), lambda: _emit(e, e.add(e.add(e.add(0x91000000, _imm(e, p["ao_off"], 10)), _imm(e, TEMP, 5)), TEMP)),
                  lambda: (_movimm(e, TEMP2, p["ao_off"], 64), _emit(e, _three(e, 0x8B000000, TEMP, TEMP, TEMP2))))
            _store_value(e, result, TEMP, _type(e, result))
            e.give(1)

        e.if_(e.eq(op, _op(Operation.ADDRESS_OFFSET)), offset)
        e.if_(_in(e, op, (_op(Operation.POINTER_CAST), _op(Operation.POINTER_ADDRESS))), lambda: (_copy_value(e, result, p["nd_a"]), e.give(1)))

        def rebase():
            # ``span = extent(view) - extent``; ``shift``: the result pointer type's alignment, a power of two.
            e.var("rb_view", p["nd_a"])
            e.var("rb_address", p["nd_b"])
            e.var("rb_extent", _call(e, "extent", p["rb_view"]))
            e.var("rb_negative", e.flag(e.lt(p["rb_extent"], _attribute(e, node, 0))))
            e.var("rb_span", e.sel(e.ne(p["rb_negative"], 0), 0, e.sub(p["rb_extent"], _attribute(e, node, 0))))
            e.var("rb_pat", e.add(_at(e, G_PAY, _type(e, result)), 1))
            _payload_uleb(e, "rb_pat")  # the address space
            _payload_uleb(e, "rb_pat")  # the element
            _payload_uleb(e, "rb_pat")  # the permission
            e.var("rb_alignment", _payload_uleb(e, "rb_pat"))
            e.var("rb_shift", 0)
            e.var("rb_unit", 1)  # 2 ** shift
            e.while_(lambda: e.le(e.mul(p["rb_unit"], 2), p["rb_alignment"]), lambda: (e.set("rb_shift", e.add(p["rb_shift"], 1)), e.set("rb_unit", e.mul(p["rb_unit"], 2))))
            _load_value(e, p["rb_address"], TEMP)
            _load_value(e, p["rb_view"], TEMP2)
            _emit(e, _three(e, 0xCB000000, REMAINDER, TEMP, TEMP2))  # sub x9, address, view
            e.if_(e.ne(p["rb_shift"], 0), lambda: _emit(e, e.add(e.add(e.add(e.add(0x93C00000, _imm(e, REMAINDER, 16)), _imm(e, p["rb_shift"], 10)),
                                                                     _imm(e, REMAINDER, 5)), REMAINDER)))  # ror x9, x9, #shift
            _movimm(e, TEMP2, e.udiv(p["rb_span"], p["rb_unit"]), 64)
            e.var("rb_ok", _new_label(e, "rb_label"))
            _emit(e, _cmp_registers(e, REMAINDER, TEMP2, 64))
            e.if_(e.eq(p["rb_negative"], 0), lambda: _branch(e, 0x54000000 | COND["ls"], p["rb_ok"], 19))
            _emit(e, _brk(e, BRK_MEMORY_CHECK))
            _label(e, p["rb_ok"])
            _store_value(e, result, TEMP, _type(e, result))
            e.give(1)

        e.if_(e.eq(op, _op(Operation.POINTER_REBASE)), rebase)

        def heap_view():
            _load_value(e, p["nd_a"], TEMP)
            e.var("hv_ok", _new_label(e, "hv_label"))
            _emit(e, _cmp_immediate(e, TEMP, 0, 64))
            _branch(e, 0x54000000 | COND["ne"], p["hv_ok"], 19)
            _emit(e, _brk(e, BRK_NULL_HEAP))
            _label(e, p["hv_ok"])
            _store_value(e, result, TEMP, _type(e, result))
            e.give(1)

        e.if_(e.eq(op, _op(Operation.HEAP_VIEW)), heap_view)

        def plain():
            e.var("pm_size", _attribute(e, node, 0))
            _ok(e, _in(e, p["pm_size"], (1, 2, 4, 8)))  # the bootstrap's AARCH64-MEMORY-WIDTH
            _load_value(e, p["nd_a"], TEMP)

            def load():
                _emit(e, _base_access(e, True, TEMP2, TEMP, 0, p["pm_size"]))
                _store_value(e, result, TEMP2, _type(e, result))

            def store():
                _load_value(e, p["nd_b"], TEMP2)
                _emit(e, _base_access(e, False, TEMP2, TEMP, 0, p["pm_size"]))

            e.if_(e.eq(op, _op(Operation.STORE_BITS_LE)), store, load)
            e.give(1)

        e.if_(_in(e, op, (_op(Operation.LOAD_BITS_LE), _op(Operation.RAW_LOAD_BITS_LE), _op(Operation.STORE_BITS_LE))), plain)

        def checked():
            e.var("ck_size", _attribute(e, node, 0))
            e.var("ck_extent", _call(e, "extent", p["nd_a"]))

            def access():
                e.var("ck_max", e.sub(p["ck_extent"], p["ck_size"]))
                e.var("ck_iw", _bits(e, _type(e, p["nd_b"]), "ck_bw"))
                _load_value(e, p["nd_b"], TEMP2)
                e.if_(e.lt(p["ck_iw"], 64), lambda: _mask(e, TEMP2, p["ck_iw"]))
                e.var("ck_ok", _new_label(e, "ck_label"))
                e.if_(e.le(p["ck_max"], 4095), lambda: _emit(e, _cmp_immediate(e, TEMP2, p["ck_max"], 64)), lambda: (
                    _movimm(e, TEMP, p["ck_max"], 64), _emit(e, _cmp_registers(e, TEMP2, TEMP, 64))))
                _branch(e, 0x54000000 | COND["ls"], p["ck_ok"], 19)
                _emit(e, _brk(e, BRK_MEMORY_CHECK))
                _label(e, p["ck_ok"])
                _load_value(e, p["nd_a"], TEMP)
                _emit(e, _three(e, 0x8B000000, TEMP, TEMP, TEMP2))

                def load():
                    _emit(e, _base_access(e, True, TEMP2, TEMP, 0, p["ck_size"]))
                    _store_value(e, result, TEMP2, _type(e, result))

                def store():
                    _load_value(e, _operand(e, node, 2), TEMP2)
                    _emit(e, _base_access(e, False, TEMP2, TEMP, 0, p["ck_size"]))

                e.if_(e.eq(op, _op(Operation.CHECKED_STORE_BITS_LE)), store, load)

            e.if_(e.lt(p["ck_extent"], p["ck_size"]), lambda: _emit(e, _brk(e, BRK_MEMORY_CHECK)), access)
            e.give(1)

        e.if_(_in(e, op, (_op(Operation.CHECKED_LOAD_BITS_LE), _op(Operation.CHECKED_STORE_BITS_LE))), checked)
        e.give(0)
    return _function(("bi", "m"), build, tables)


def _record_call(e: E, target):
    """``assembler.call``: the position and target (a declaration ``+ 2 ** 40``), then ``bl``."""
    p = e.p
    e.var("rc_n", _a(e, X_NCALLS))
    _ok(e, e.lt(p["rc_n"], CALL_CAP))
    e.st(e.add(_a(e, X_CALLS), e.mul(p["rc_n"], 2)), _a(e, X_LEN))
    e.st(e.add(_a(e, X_CALLS), e.add(e.mul(p["rc_n"], 2), 1)), target)
    _set_a(e, X_NCALLS, e.add(p["rc_n"], 1))
    _emit(e, 0x94000000)


def _call_fn(tables):
    """Direct calls (an erased proof function is none), syscalls and C imports: ``marshal_call``.  1, or 0 when the
    node is not a call."""
    def build(e: E):
        p = e.p
        node, op, result = _prelude(e)
        e.if_(e.not_(_in(e, op, (_op(Operation.CALL_DIRECT), _op(Operation.CALL_FOREIGN)))), lambda: e.give(0))
        e.var("mc_target", NONE)

        def direct():
            _callee_object(e, node, "mc_callee")
            _ok(e, e.ne(p["mc_callee"], NONE))
            e.if_(e.ne(_call(e, "erased", p["mc_callee"]), 0), lambda: e.give(1))
            e.set("mc_target", p["mc_callee"])

        def foreign():
            e.var("mc_decl", _reference(e, _f(e, node, N_GRAPH), e.rd(e.sub(_f(e, node, N_OPSAT), 1))))
            _ok(e, e.ne(p["mc_decl"], NONE))
            e.var("mc_class", _foreign_class(e, p["mc_decl"], "mc_abi"))
            from xax_selfhost_x86_64_general import G_TFMT
            from xax_selfhost_views_backend import GLOBALS

            e.var("mc_dynamic", e.flag(e.eq(e.ld(GLOBALS + G_TFMT), 7)))
            allowed = e.either(e.eq(p["mc_class"], ABI_SYSCALL_CLASS), e.both(e.eq(p["mc_class"], ABI_C_CLASS), e.ne(p["mc_dynamic"], 0)))

            def write():
                from xax_selfhost_aarch64_general import SITE

                e.call(_FN["diagnostic"], SITE["AARCH64-FOREIGN-ABI"], e.ld(_call(e, "interface", _a(e, F_FN))))
                D.put(e, D.T_LIST)
                D.put(e, e.add(1, p["mc_dynamic"]))
                D.text(e, SYSCALL_ABI.decode())
                e.if_(e.ne(p["mc_dynamic"], 0), lambda: D.text(e, C_ABI.decode()))
                _call(e, "text_at", p["mc_abi_cur"], p["mc_abi_alen"])

            D.reject_unless(e, allowed, write)
            e.set("mc_target", e.add(p["mc_decl"], 1 << 40))

        e.if_(e.eq(op, _op(Operation.CALL_DIRECT)), direct, foreign)
        # The machine results (given-back borrowed views excluded): at most one.
        e.var("mc_nelided", 0)
        from xax_selfhost_aarch64_lower import V_ELIDED, _av, _set_av

        e.for_("mc_r", 0, _f(e, node, N_NRES), lambda: _set_av(e, V_ELIDED, _output(e, node, p["mc_r"]), NONE))
        e.if_(e.eq(op, _op(Operation.CALL_DIRECT)), lambda: e.set("mc_nelided", _call(e, "a64_call_elided", node)))
        e.var("mc_result", NONE)
        e.var("mc_nres", 0)
        e.for_("mc_r", 0, _f(e, node, N_NRES), lambda: (e.var("mc_rv", _output(e, node, p["mc_r"])), e.if_(
            e.both(e.not_(_proof(e, _type(e, p["mc_rv"]))), e.eq(_av(e, V_ELIDED, p["mc_rv"]), NONE)), lambda: (
                e.if_(e.eq(p["mc_result"], NONE), lambda: e.set("mc_result", p["mc_rv"])), e.set("mc_nres", e.add(p["mc_nres"], 1))))))
        _ok(e, e.le(p["mc_nres"], 1))  # the bootstrap's AARCH64-CALL-RETURNS
        _machine_operands(e, node, 0, "mc_mo")
        e.var("mc_plan", _a(e, F_PLAN))
        _call(e, "a64f_plan", p["mc_mo_types"], p["mc_mo_n"], p["mc_plan"])

        def argument():
            e.var("mc_v", e.ld(e.add(p["mc_mo"], p["mc_k"])))
            e.var("mc_t", e.ld(e.add(p["mc_mo_types"], p["mc_k"])))
            e.var("mc_pat", e.add(p["mc_plan"], e.mul(p["mc_k"], PLAN_WORDS)))
            e.var("mc_kind", e.ld(p["mc_pat"]))
            e.var("mc_place", e.ld(e.add(p["mc_pat"], 1)))
            e.var("mc_count", e.ld(e.add(p["mc_pat"], 2)))
            e.var("mc_member", e.ld(e.add(p["mc_pat"], 3)))
            e.var("mc_size", _rt(e, T_SIZE, p["mc_v"]))
            e.var("mc_source", _slot(e, p["mc_v"]))

            def by_reference():
                e.var("mc_copy", _copy_slot(e, node, p["mc_k"]))
                _copy(e, SP, p["mc_copy"], SP, p["mc_source"], p["mc_size"])
                e.set("mc_source", p["mc_copy"])

            e.if_(e.eq(_call(e, "a64f_class", p["mc_t"]), K_REF), by_reference)

            def gpr():
                _load(e, p["mc_place"], SP, p["mc_source"], p["mc_size"])

            def gpr2():
                _load(e, p["mc_place"], SP, p["mc_source"], e.sel(e.lt(8, p["mc_size"]), 8, p["mc_size"]))
                e.if_(e.lt(8, p["mc_size"]), lambda: _load(e, e.add(p["mc_place"], 1), SP, e.add(p["mc_source"], 8), e.sub(p["mc_size"], 8)))

            def fpr():
                _emit(e, _fp_access(e, True, p["mc_place"], SP, p["mc_source"], p["mc_member"]))

            def hfa():
                e.for_("mc_i", 0, p["mc_count"], lambda: _emit(e, _fp_access(e, True, e.add(p["mc_place"], p["mc_i"]), SP,
                                                                              e.add(p["mc_source"], e.mul(p["mc_i"], p["mc_member"])), p["mc_member"])))

            def ref():
                _emit(e, _address_from_sp(e, p["mc_place"], p["mc_source"]))

            def stacked():
                e.if_(e.eq(p["mc_count"], 4), lambda: (_emit(e, _address_from_sp(e, TEMP, p["mc_source"])),
                                                        _emit(e, _base_access(e, False, TEMP, SP, p["mc_place"], 8))),
                      lambda: _copy(e, SP, p["mc_place"], SP, p["mc_source"], p["mc_size"]))

            kind = p["mc_kind"]
            e.if_(e.eq(kind, K_GPR), gpr, lambda: e.if_(e.eq(kind, K_GPR2), gpr2, lambda: e.if_(e.eq(kind, K_FPR), fpr, lambda: e.if_(
                e.eq(kind, K_HFA), hfa, lambda: e.if_(e.eq(kind, K_REF), ref, stacked)))))

        e.for_("mc_k", 0, p["mc_mo_n"], argument)
        e.var("mc_rkind", NONE)
        e.if_(e.ne(p["mc_result"], NONE), lambda: e.set("mc_rkind", _call(e, "a64f_class", _type(e, p["mc_result"]))))
        e.if_(e.eq(p["mc_rkind"], K_REF), lambda: _emit(e, _address_from_sp(e, 8, _slot(e, p["mc_result"]))))
        _record_call(e, p["mc_target"])

        def returned():
            e.var("mc_rcount", _a(e, F_CLASS_COUNT))
            e.var("mc_rmember", _a(e, F_CLASS_MEMBER))
            e.var("mc_rsize", _rt(e, T_SIZE, p["mc_result"]))
            e.var("mc_dest", _slot(e, p["mc_result"]))
            _zero(e, SP, p["mc_dest"], _slot_size(e, p["mc_rsize"]))
            kind = p["mc_rkind"]
            e.if_(e.eq(kind, K_GPR), lambda: _store(e, 0, SP, p["mc_dest"], p["mc_rsize"]), lambda: e.if_(e.eq(kind, K_GPR2), lambda: (
                _store(e, 0, SP, p["mc_dest"], e.sel(e.lt(8, p["mc_rsize"]), 8, p["mc_rsize"])),
                e.if_(e.lt(8, p["mc_rsize"]), lambda: _store(e, 1, SP, e.add(p["mc_dest"], 8), e.sub(p["mc_rsize"], 8)))), lambda: e.if_(
                e.eq(kind, K_FPR), lambda: _emit(e, _fp_access(e, False, 0, SP, p["mc_dest"], p["mc_rmember"])), lambda: e.for_(
                    "mc_i", 0, p["mc_rcount"], lambda: _emit(e, _fp_access(e, False, p["mc_i"], SP, e.add(p["mc_dest"], e.mul(p["mc_i"], p["mc_rmember"])),
                                                                             p["mc_rmember"]))))))

        e.if_(e.both(e.ne(p["mc_result"], NONE), e.ne(p["mc_rkind"], K_REF)), lambda: (_call(e, "a64f_class", _type(e, p["mc_result"])), returned()))

        def elided():
            e.var("mc_ev", _output(e, node, p["mc_r"]))
            e.if_(e.ne(_av(e, V_ELIDED, p["mc_ev"]), NONE), lambda: _copy_value(e, p["mc_ev"], _av(e, V_ELIDED, p["mc_ev"])))

        e.if_(e.eq(op, _op(Operation.CALL_DIRECT)), lambda: e.for_("mc_r", 0, _f(e, node, N_NRES), elided))
        e.give(1)
    return _function(("bi", "m"), build, tables)


def _node_fn(tables):
    """One node of block ``bi``: its code and node range; a node no group lowers declines."""
    from xax_selfhost_aarch64_emit import X_NRANGES as _NR

    def build(e: E):
        p = e.p
        e.var("fn_start", _a(e, X_LEN))
        e.var("fn_op", _eop(e, _node_at(e, _block_at(e, p["bi"]), p["m"])))
        quiet = e.either(e.eq(p["fn_op"], _op(Operation.STACK_END)), *(e.eq(p["fn_op"], _op(item)) for item in RESOURCE_EFFECT_OPERATIONS))
        e.var("fn_done", e.flag(quiet))
        for group in ("a64f_integer", "a64f_float", "a64f_data", "a64f_call"):
            e.if_(e.eq(p["fn_done"], 0), lambda group=group: e.set("fn_done", _call(e, group, p["bi"], p["m"])))
        _ok(e, e.ne(p["fn_done"], 0))  # function addresses, indirect and target operations: the bootstrap

        def ranged():
            e.var("fn_r", _a(e, _NR))
            _ok(e, e.lt(p["fn_r"], RANGE_CAP))
            e.var("fn_rat", e.add(_a(e, X_RANGES), e.mul(p["fn_r"], 4)))
            for k, word in enumerate((p["bi"], p["m"], p["fn_start"], _a(e, X_LEN))):
                e.st(e.add(p["fn_rat"], k), word)
            _set_a(e, _NR, e.add(p["fn_r"], 1))

        e.if_(e.lt(p["fn_start"], _a(e, X_LEN)), ranged)
        e.give(0)
    return _function(("bi", "m"), build, tables)


# -- terminators and the function -------------------------------------------------------------------------------------

def _edge_copy(e: E, edge):
    """``edge_copy``: every machine argument through the edge temporaries, then into the target's parameter slots."""
    p = e.p
    e.var("ec_target", _f(e, edge, 0))
    e.var("ec_args", _f(e, edge, 2))
    e.var("ec_n", _f(e, edge, 1))
    e.var("ec_pairs", e.alloc(e.add(e.mul(p["ec_n"], 3), 1)))
    _ok(e, e.ne(p["ec_pairs"], NONE))
    e.var("ec_np", 0)
    e.var("ec_temp", _a(e, F_EDGE_TEMP))

    def pair():
        e.var("ec_a", e.ld(e.add(p["ec_args"], p["ec_k"])))
        e.var("ec_d", e.ld(e.add(_f(e, p["ec_target"], B_INPUTS), p["ec_k"])))

        def copy():
            e.var("ec_size", _rt(e, T_SIZE, p["ec_d"]))
            _copy(e, SP, p["ec_temp"], SP, _slot(e, p["ec_a"]), p["ec_size"])
            e.var("ec_at", e.add(p["ec_pairs"], e.mul(p["ec_np"], 3)))
            for field, value in enumerate((p["ec_temp"], p["ec_d"], p["ec_size"])):
                e.st(e.add(p["ec_at"], field), value)
            e.set("ec_np", e.add(p["ec_np"], 1))
            e.set("ec_temp", e.add(p["ec_temp"], _slot_size(e, p["ec_size"])))

        e.if_(e.both(e.ne(_rt(e, T_SLOT, p["ec_a"]), NONE), e.ne(_rt(e, T_SLOT, p["ec_d"]), NONE)), copy)

    e.for_("ec_k", 0, p["ec_n"], pair)

    def place():
        e.var("ec_at", e.add(p["ec_pairs"], e.mul(p["ec_j"], 3)))
        _copy(e, SP, _slot(e, e.ld(e.add(p["ec_at"], 1))), SP, e.ld(p["ec_at"]), e.ld(e.add(p["ec_at"], 2)))

    e.for_("ec_j", 0, p["ec_np"], place)


def _epilogue(e: E):
    e.if_(e.ne(_a(e, F_HASCALL), 0), lambda: _emit(e, _load_store64(e, True, LR, _a(e, F_LINK))))
    e.if_(e.ne(_a(e, F_FRAME), 0), lambda: _emit(e, e.add(0x910003FF, _imm(e, _a(e, F_FRAME), 10))))
    _emit(e, 0xD65F03C0)


def _term_fn(tables):
    """The terminator of block ``bi``."""
    def build(e: E):
        p = e.p
        e.var("tm_b", _block_at(e, p["bi"]))
        block = p["tm_b"]
        e.var("tm_kind", _f(e, block, B_KIND))

        def returned():
            e.var("tm_i", _a(e, A_IFACE_SLOT()))
            e.var("tm_np", e.ld(e.add(p["tm_i"], 1)))
            e.var("tm_rt", e.add(e.add(p["tm_i"], 2), p["tm_np"]))
            e.var("tm_first", NONE)
            e.var("tm_ftype", NONE)
            e.for_("tm_k", 0, _f(e, block, B_NVALUES), lambda: (e.var("tm_t", e.ld(e.add(e.add(p["tm_rt"], 1), p["tm_k"]))), e.if_(
                e.both(e.eq(p["tm_first"], NONE), e.not_(_proof(e, p["tm_t"])), e.eq(e.ld(e.add(_a(e, A_OWNB_SLOT()), p["tm_k"])), NONE)),
                lambda: (e.set("tm_first", e.ld(e.add(_f(e, block, B_VALUES), p["tm_k"]))), e.set("tm_ftype", p["tm_t"])))))

            def value():
                e.var("tm_kind2", _call(e, "a64f_class", p["tm_ftype"]))
                e.var("tm_count", _a(e, F_CLASS_COUNT))
                e.var("tm_member", _a(e, F_CLASS_MEMBER))
                e.var("tm_size", _call(e, "abi_layout", p["tm_ftype"]))
                e.var("tm_src", _slot(e, p["tm_first"]))
                kind = p["tm_kind2"]

                def by_reference():
                    _emit(e, _load_store64(e, True, TEMP, _a(e, F_RETPTR)))
                    _copy(e, TEMP, 0, SP, p["tm_src"], p["tm_size"])

                e.if_(e.eq(kind, K_GPR), lambda: _load(e, 0, SP, p["tm_src"], p["tm_size"]), lambda: e.if_(e.eq(kind, K_GPR2), lambda: (
                    _load(e, 0, SP, p["tm_src"], e.sel(e.lt(8, p["tm_size"]), 8, p["tm_size"])),
                    e.if_(e.lt(8, p["tm_size"]), lambda: _load(e, 1, SP, e.add(p["tm_src"], 8), e.sub(p["tm_size"], 8)))), lambda: e.if_(
                    e.eq(kind, K_FPR), lambda: _emit(e, _fp_access(e, True, 0, SP, p["tm_src"], p["tm_member"])), lambda: e.if_(
                        e.eq(kind, K_HFA), lambda: e.for_("tm_q", 0, p["tm_count"], lambda: _emit(e, _fp_access(
                            e, True, p["tm_q"], SP, e.add(p["tm_src"], e.mul(p["tm_q"], p["tm_member"])), p["tm_member"]))), by_reference))))

            e.if_(e.ne(p["tm_first"], NONE), value)
            _epilogue(e)

        def branch():
            e.var("tm_edge", _f(e, block, B_EDGES))
            _edge_copy(e, p["tm_edge"])
            _branch(e, 0x14000000, _f(e, _f(e, p["tm_edge"], 0), B_POS), 26)

        def conditional():
            _load_value(e, e.ld(_f(e, block, B_VALUES)), TEMP)
            e.var("tm_false", _new_label(e, "tm_label"))
            _branch(e, 0x34000000 | TEMP, p["tm_false"], 19)  # cbz w16
            e.var("tm_edge", _f(e, block, B_EDGES))
            _edge_copy(e, p["tm_edge"])
            _branch(e, 0x14000000, _f(e, _f(e, p["tm_edge"], 0), B_POS), 26)
            _label(e, p["tm_false"])
            e.var("tm_edge", e.add(_f(e, block, B_EDGES), EDGE))
            _edge_copy(e, p["tm_edge"])
            _branch(e, 0x14000000, _f(e, _f(e, p["tm_edge"], 0), B_POS), 26)

        def trap():
            e.var("tm_reason", _call(e, "x_trap_reason", _f(e, block, B_PFN), _f(e, block, B_PB)))
            _movimm(e, 0, p["tm_reason"], 64)
            _emit(e, _brk(e, p["tm_reason"]))

        e.if_(e.eq(p["tm_kind"], RETURN), returned, lambda: e.if_(e.eq(p["tm_kind"], BRANCH), branch, lambda: e.if_(
            e.eq(p["tm_kind"], CONDITIONAL), conditional, trap)))
        e.give(0)
    return _function(("bi",), build, tables)


def _entry(e: E):
    """The prologue: the frame, the link register, the hidden return pointer; the entry block's parameters from their
    AAPCS64 locations into their slots."""
    p = e.p
    e.if_(e.ne(_a(e, F_FRAME), 0), lambda: _emit(e, e.add(0xD10003FF, _imm(e, _a(e, F_FRAME), 10))))
    e.if_(e.ne(_a(e, F_HASCALL), 0), lambda: _emit(e, _load_store64(e, False, LR, _a(e, F_LINK))))
    e.if_(e.ne(_a(e, F_HIDDEN), 0), lambda: _emit(e, _load_store64(e, False, 8, _a(e, F_RETPTR))))
    e.var("en_block", _g(e, G_BENTRY))
    e.var("en_values", e.alloc(e.add(e.mul(_f(e, p["en_block"], B_NP), 2), 2)))
    _ok(e, e.ne(p["en_values"], NONE))
    e.var("en_types", e.add(p["en_values"], e.add(_f(e, p["en_block"], B_NP), 1)))
    e.var("en_n", 0)

    def gather():
        e.var("en_v", e.ld(e.add(_f(e, p["en_block"], B_INPUTS), p["en_k"])))
        e.if_(e.ne(_rt(e, T_MACHINE, p["en_v"]), 0), lambda: (e.st(e.add(p["en_values"], p["en_n"]), p["en_v"]),
                                                               e.st(e.add(p["en_types"], p["en_n"]), _type(e, p["en_v"])), e.set("en_n", e.add(p["en_n"], 1))))

    e.for_("en_k", 0, _f(e, p["en_block"], B_NP), gather)
    _ok(e, e.lt(p["en_n"], 1 << 12))
    _call(e, "a64f_plan", p["en_types"], p["en_n"], _a(e, F_PLAN))

    def parameter():
        e.var("en_v", e.ld(e.add(p["en_values"], p["en_k"])))
        e.var("en_pat", e.add(_a(e, F_PLAN), e.mul(p["en_k"], PLAN_WORDS)))
        e.var("en_kind", e.ld(p["en_pat"]))
        e.var("en_place", e.ld(e.add(p["en_pat"], 1)))
        e.var("en_count", e.ld(e.add(p["en_pat"], 2)))
        e.var("en_member", e.ld(e.add(p["en_pat"], 3)))
        e.var("en_size", _rt(e, T_SIZE, p["en_v"]))
        e.var("en_dest", _slot(e, p["en_v"]))
        _zero(e, SP, p["en_dest"], _slot_size(e, p["en_size"]))
        kind = p["en_kind"]

        def stacked():
            e.var("en_source", e.add(_a(e, F_FRAME), p["en_place"]))
            e.if_(e.eq(p["en_count"], 4), lambda: (_emit(e, _base_access(e, True, TEMP, SP, p["en_source"], 8)), _copy(e, SP, p["en_dest"], TEMP, 0, p["en_size"])),
                  lambda: _copy(e, SP, p["en_dest"], SP, p["en_source"], p["en_size"]))

        e.if_(e.eq(kind, K_GPR), lambda: _store(e, p["en_place"], SP, p["en_dest"], p["en_size"]), lambda: e.if_(e.eq(kind, K_GPR2), lambda: (
            _store(e, p["en_place"], SP, p["en_dest"], e.sel(e.lt(8, p["en_size"]), 8, p["en_size"])),
            e.if_(e.lt(8, p["en_size"]), lambda: _store(e, e.add(p["en_place"], 1), SP, e.add(p["en_dest"], 8), e.sub(p["en_size"], 8)))), lambda: e.if_(
            e.eq(kind, K_FPR), lambda: _emit(e, _fp_access(e, False, p["en_place"], SP, p["en_dest"], p["en_member"])), lambda: e.if_(
                e.eq(kind, K_HFA), lambda: e.for_("en_q", 0, p["en_count"], lambda: _emit(e, _fp_access(
                    e, False, e.add(p["en_place"], p["en_q"]), SP, e.add(p["en_dest"], e.mul(p["en_q"], p["en_member"])), p["en_member"]))), lambda: e.if_(
                    e.eq(kind, K_REF), lambda: _copy(e, SP, p["en_dest"], p["en_place"], 0, p["en_size"]), stacked)))))

    e.for_("en_k", 0, p["en_n"], parameter)


def _function_fn(tables):
    """``_compile_general_function`` of closure function ``f`` (image index ``fidx``) from its own graph: the frame,
    the prologue and entry moves, a branch to the entry block when it is not first, every block in graph order, and
    the branch fixups.  The code goes to the emission record ``a64_image_add`` places."""
    from xax_selfhost_general_view import G_BLIST, G_FKEYN, G_LIFT_ENTRY, _globals
    from xax_selfhost_aarch64_lower import A_FN, A_IFACE, A_OWNB

    def build(e: E):
        p = e.p
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
        e.if_(e.ne(_call(e, "a64f_register_path", p["f"]), 0), lambda: e.give(NONE))  # the legacy register path: the bootstrap
        for slot, value in ((F_FN, p["f"]), (A_FN, p["f"]), (A_IFACE, _call(e, "interface", p["f"])), (A_OWNB, _call(e, "borrowed", p["f"]))):
            _set_a(e, slot, value)
        _call(e, "a64f_layout", p["f"])
        # The emission state: labels for the blocks, then the nodes' own (four per node at most).
        e.var("ff_nodes", 0)
        e.for_("ff_q", 0, p["ff_n"], lambda: e.set("ff_nodes", e.add(p["ff_nodes"], _f(e, _block_at(e, p["ff_q"]), B_NNODES))))
        e.var("ff_nlabels", e.add(e.add(p["ff_n"], e.mul(p["ff_nodes"], 4)), 16))
        e.var("ff_labels", e.alloc(e.add(p["ff_nlabels"], 1)))
        _ok(e, e.ne(p["ff_labels"], NONE))
        e.for_("ff_k", 0, p["ff_nlabels"], lambda: e.st(e.add(p["ff_labels"], p["ff_k"]), NONE))
        _set_a(e, X_LABELS, p["ff_labels"])
        _set_a(e, F_NEXT_LABEL, p["ff_n"])
        for slot in (X_LEN, X_NFIX, X_NCALLS, X_NRANGES):
            _set_a(e, slot, 0)
        _entry(e)
        e.var("ff_entry", _f(e, _g(e, G_BENTRY), B_POS))
        e.if_(e.ne(p["ff_entry"], 0), lambda: _branch(e, 0x14000000, p["ff_entry"], 26))

        def block():
            _label(e, p["ff_bi"])
            e.for_("ff_m", 0, _f(e, _block_at(e, p["ff_bi"]), B_NNODES), lambda: _call(e, "a64f_node", p["ff_bi"], p["ff_m"]))
            _call(e, "a64f_term", p["ff_bi"])

        e.for_("ff_bi", 0, p["ff_n"], block)
        _call(e, "x_fixups")
        e.give(1)
    return _function(("f", "fidx"), build, tables)


def add_frame_functions(add, tables):
    """Every frame-path function, each after the functions it calls (the AArch64 emission's and ``abi_layout`` are added
    before)."""
    for name, builder in (("a64f_chunk", _chunk_fn), ("a64f_load_bytes", _load_bytes_fn), ("a64f_store_bytes", _store_bytes_fn), ("a64f_zero", _zero_fn),
                          ("a64f_copy", _copy_fn), ("a64f_movimm", _movimm_fn), ("a64f_load_value", _load_value_fn),
                          ("a64f_store_value", _store_value_fn), ("a64f_homogeneous", _homogeneous_fn), ("a64f_class", _class_fn),
                          ("a64f_plan", _plan_fn), ("a64f_register_path", _register_path_fn), ("a64f_hulls", _hulls_fn), ("a64f_layout", _layout_fn),
                          ("a64f_integer", _integer_fn), ("a64f_float", _float_fn), ("a64f_data", _data_fn), ("a64f_call", _call_fn),
                          ("a64f_node", _node_fn), ("a64f_term", _term_fn), ("a64f_function", _function_fn)):
        add(name, builder(tables))

