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

from xax_compiler import Operation
from xax_selfhost_aarch64_emit import _a, _emit
from xax_selfhost_facts import E, NONE
from xax_selfhost_general_frame import _align_to, _form
from xax_selfhost_general_regalloc import T_FEXT, T_FESC, T_FHOFF, T_FHROOT, T_FPTR, T_FSIZE, T_FSLOT, _rt
from xax_selfhost_general_view import B_INPUTS, B_NP, G_BENTRY, G_VTYPE, _f, _vf
from xax_selfhost_views_backend import G_PAY, _at, _call, _g, _ok, _payload_uleb

TEMP, TEMP2, REMAINDER = 16, 17, 9  # x16 (IP0), x17 (IP1), x9 (a declared scratch register on this path)
SP, LR = 31, 30
ARITHMETIC = {Operation.ADD_WRAP: (0x0B000000, 0x8B000000), Operation.SUB_WRAP: (0x4B000000, 0xCB000000), Operation.MUL_WRAP: (0x1B007C00, 0x9B007C00)}
BASE_ACCESS = {1: (0x39400000, 0x39000000), 2: (0x79400000, 0x79000000), 4: (0xB9400000, 0xB9000000), 8: (0xF9400000, 0xF9000000)}
FP_ACCESS = {4: (0xBD400000, 0xBD000000), 8: (0xFD400000, 0xFD000000)}
CALLS = tuple(int(op) for op in (Operation.CALL_DIRECT, Operation.CALL_FOREIGN, Operation.CALL_INDIRECT))
# AAPCS64 classes (``_abi_class``) and argument locations (``_abi_argument_plan``).
K_GPR, K_GPR2, K_FPR, K_HFA, K_REF, K_STACK = range(6)
PLAN_WORDS = 4  # kind, register or stack offset, count (a stack entry: its original class code), member bytes

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


def _load_store64(e: E, load: bool, register, offset):
    """``_load_store(load, register, offset, 64)`` against SP."""
    _ok(e, e.both(e.eq(e.and_(offset, 7), 0), e.lt(e.udiv(offset, 8), 4096)))
    return e.add(e.add(0xF94003E0 if load else 0xF90003E0, _imm(e, e.udiv(offset, 8), 10)), register)


# -- small emitters (``xax_aarch64``'s word lists) ----------------------------------------------------------------------


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


# -- AAPCS64 classes ---------------------------------------------------------------------------------------------------


# -- eligibility for the other paths -------------------------------------------------------------------------------

G_A64RAW = 191  # GLOBALS slot: 1 for a bare-metal load image (S15f.4, ADR-325), whose frames share no slots
# GLOBALS slot (S15e.6h.1, ADR-354): an Android shared object's bundle, 1 for a profile without function-wide register
# allocation (``android-arm64-v8a-shared-v3``), 2 for one with it (v4, v5); 0 otherwise.
G_A64ANDROID = 189


def _general(e: E):
    """``_general_aarch64_target``: the target lists a float, aggregate or sum operation."""
    from xax_selfhost_views_backend import G_SUP

    return e.flag(e.either(*(e.ne(e.ld(e.add(_g(e, G_SUP), _op(op))), 0) for op in (Operation.FLOAT_ADD, Operation.AGGREGATE_MAKE, Operation.SUM_MAKE))))


# -- the frame (``_compile_general_function``'s layout) -------------------------------------------------------------


# -- nodes ----------------------------------------------------------------------------------------------------------


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


# -- terminators and the function -------------------------------------------------------------------------------------


def _epilogue(e: E):
    e.if_(e.ne(_a(e, F_HASCALL), 0), lambda: _emit(e, _load_store64(e, True, LR, _a(e, F_LINK))))
    e.if_(e.ne(_a(e, F_FRAME), 0), lambda: _emit(e, e.add(0x910003FF, _imm(e, _a(e, F_FRAME), 10))))
    _emit(e, 0xD65F03C0)


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


