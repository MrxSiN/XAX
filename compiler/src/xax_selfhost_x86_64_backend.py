"""Self-hosting step S7a (ADR-152): the x86-64 views-profile backend as XAX semantics.

``xax_x86_64_views`` lowers a verified function closure to raw x86-64 code in the
repository's x86-64 convention.  This module builds the same backend as one XAX
program from the instruction-set-neutral builders in ``xax_selfhost_views_backend``
(front end, liveness, linear scan, edge copies, driver) and the x86-64 hooks and
lowering below.  Its output is the code (one byte per output word), the function
order and byte offsets, the per-node code ranges, and the entry's machine parameter
and return widths, all byte-identical to the bootstrap generator's.

Like the RISC-V program, it accepts or declines; on a decline the bootstrap
generator runs and raises the exact diagnostic.
"""

from __future__ import annotations

from pathlib import Path

from xax_compiler import IntCompare, Operation, RESOURCE_EFFECT_OPERATIONS, TerminatorKind, x86_64_linux_exec_target
from xax_graph_builder import program_store
from xax_selfhost_facts import E, NONE, _function
from xax_selfhost_views_backend import (
    _FN, A_AREAS, A_BASE, A_OUT, A_POINTER, JUMPS_AT, JUMPS_LIMIT, RANGES_AT, RANGES_LIMIT, S_AGG, S_BASE, S_BLOCK_AT, S_BLOCK_LABELS,
    S_COUNT, S_FALSE_LABELS, S_FN, S_FRAME, S_JUMPS, S_OFFSETS, S_POW, S_RANGES, S_REG, S_SAVED, S_SLOT, S_TRAP, S_TRAP_USED, S_WIDTH, WORDS_AT,
    WORDS_LIMIT, NativeProgram, _aggregate, _borrowed, _call, _compile_function, _diagnostic, _copy_edge, _erased, _field, _frontend, _interface,
    _node_info, _ok, _payload_uleb, _program, _result_fields, _target, _term_end, _translate, _value, collect_program_output,
)

from xax_native import bootstrap_dir  # noqa: E402
from xax_x86_64_views import ISA, LOWERED_OPERATIONS  # noqa: E402

STORE_PATH = bootstrap_dir() / "xax_x86_64_backend.xax"
RAX, RCX, RDX, RSP = 0, 1, 2, 4
T0, T1 = 10, 11
ARGUMENTS = (RCX, RDX, 8, 9)
SHADOW = 32
ALLOCATABLE = (3, 5, 6, 7, 12, 13, 14, 15)
PAD = 0xCC
ALU = {Operation.ADD_WRAP: 0x01, Operation.SUB_WRAP: 0x29, Operation.BIT_XOR: 0x31, Operation.BIT_OR: 0x09, Operation.BIT_AND: 0x21}
SETCC = {IntCompare.EQ: 0x94, IntCompare.NE: 0x95, IntCompare.ULT: 0x92, IntCompare.ULE: 0x96, IntCompare.UGT: 0x97,
         IntCompare.UGE: 0x93, IntCompare.SLT: 0x9C, IntCompare.SLE: 0x9E, IntCompare.SGT: 0x9F, IntCompare.SGE: 0x9D}
JMP, JZ, JA, CALL = (0xE9, 1), (0x840F, 2), (0x870F, 2), (0xE8, 1)  # opcode bytes, little-endian, and their count


# -- byte emission and encoders (``xax_x86_64_views``) ---------------------------------------------

def _emit(e: E, byte):
    count = e.hd(S_COUNT)
    e.st(e.add(WORDS_AT, count), byte)
    e.set_hd(S_COUNT, e.add(count, 1))


def _emit_n(tables):
    """The ``n`` low bytes of ``value``, least significant first."""
    def build(e: E):
        p = e.p
        e.var("ev", p["value"])
        e.for_("k", 0, p["n"], lambda: (_emit(e, e.and_(p["ev"], 0xFF)), e.set("ev", e.udiv(p["ev"], 256))))
        e.give(1)
    return _function(("value", "n"), build, tables)


def _bytes(e: E, value, n):
    _call(e, "emit", value, n)


def _rex(e: E, w, reg, index, base, force=0):
    """Emit REX when it carries a bit or ``force`` (byte registers spl..dil)."""
    value = e.add(e.add(e.add(e.add(0x40, e.mul(w, 8)), e.mul(e.udiv(reg, 8), 4)), e.mul(e.udiv(index, 8), 2)), e.udiv(base, 8))
    e.var("rex", value)
    p = e.p
    e.if_(e.either(e.ne(p["rex"], 0x40), e.ne(e.v(force), 0)), lambda: _emit(e, p["rex"]))


def _modrm(e: E, mod: int, reg, rm):
    return e.add(e.add(mod << 6, e.mul(e.and_(reg, 7), 8)), e.and_(rm, 7))


def _reg_reg(tables):
    """``opcode`` (``oplen`` bytes) with a register ModRM: ``reg`` field, ``rm`` operand."""
    def build(e: E):
        p = e.p
        _rex(e, p["w"], p["reg"], 0, p["rm"])
        _bytes(e, p["opcode"], p["oplen"])
        _emit(e, _modrm(e, 3, p["reg"], p["rm"]))
        e.give(1)
    return _function(("reg", "rm", "opcode", "oplen", "w"), build, tables)


def _rr(e: E, opcode: int, oplen: int, reg, rm, w=1):
    _call(e, "rr", reg, rm, opcode, oplen, w)


def _stack(tables):
    """``opcode`` on ``[rsp + offset]`` (disp8 below 128, else disp32)."""
    def build(e: E):
        p = e.p
        _rex(e, p["w"], p["reg"], 0, RSP)
        _bytes(e, p["opcode"], p["oplen"])

        def near():
            _emit(e, _modrm(e, 1, p["reg"], RSP))
            _emit(e, 0x24)
            _emit(e, p["offset"])

        def far():
            _emit(e, _modrm(e, 2, p["reg"], RSP))
            _emit(e, 0x24)
            _bytes(e, p["offset"], 4)

        e.if_(e.lt(p["offset"], 128), near, far)
        e.give(1)
    return _function(("reg", "offset", "opcode", "oplen", "w"), build, tables)


def _st(e: E, opcode: int, reg, offset, w=1, oplen=1):
    _call(e, "stack", reg, offset, opcode, oplen, w)


def _indexed(tables):
    """``opcode`` on ``[base + index]`` after an optional 0x66 ``prefix``; rbp/r13 bases take a zero disp8."""
    def build(e: E):
        p = e.p
        e.if_(e.ne(p["prefix"], 0), lambda: _emit(e, p["prefix"]))
        _rex(e, p["w"], p["reg"], p["index"], p["base"], p["force"])
        _bytes(e, p["opcode"], p["oplen"])
        sib = e.add(e.mul(e.and_(p["index"], 7), 8), e.and_(p["base"], 7))
        e.var("sib", sib)

        def rbp():
            _emit(e, _modrm(e, 1, p["reg"], 4))
            _emit(e, p["sib"])
            _emit(e, 0)

        def plain():
            _emit(e, _modrm(e, 0, p["reg"], 4))
            _emit(e, p["sib"])

        e.if_(e.eq(e.and_(p["base"], 7), 5), rbp, plain)
        e.give(1)
    return _function(("reg", "base", "index", "prefix", "opcode", "oplen", "w", "force"), build, tables)


def _shift_fn(tables):
    """``shl``/``shr``/``sar``/``ror`` (ModRM extension 4/5/7/1) by an immediate."""
    def build(e: E):
        p = e.p
        _rex(e, p["w"], 0, 0, p["reg"])
        _emit(e, 0xC1)
        _emit(e, _modrm(e, 3, p["ext"], p["reg"]))
        _emit(e, p["amount"])
        e.give(1)
    return _function(("reg", "amount", "ext", "w"), build, tables)


def _shift(e: E, extension: int, reg, amount, w=1):
    _call(e, "shift", reg, amount, extension, w)


def _move(e: E, destination, source):
    e.if_(e.ne(destination, source), lambda: _rr(e, 0x89, 1, source, destination))


def _constant(tables):
    """``load_constant``: xor, mov r32 imm32, mov r/m64 simm32, or movabs."""
    def build(e: E):
        p = e.p
        reg, value = p["reg"], p["value"]

        def zero():
            _rr(e, 0x31, 1, reg, reg, 0)

        def small():
            _rex(e, 0, 0, 0, reg)
            _emit(e, e.or_(0xB8, e.and_(reg, 7)))
            _bytes(e, value, 4)

        def negative():
            _rex(e, 1, 0, 0, reg)
            _emit(e, 0xC7)
            _emit(e, _modrm(e, 3, 0, reg))
            _bytes(e, value, 4)

        def wide():
            _rex(e, 1, 0, 0, reg)
            _emit(e, e.or_(0xB8, e.and_(reg, 7)))
            _bytes(e, value, 8)

        e.if_(e.eq(value, 0), zero, lambda: e.if_(e.lt(value, 1 << 32), small, lambda: e.if_(
            e.le((1 << 64) - (1 << 31), value), negative, wide)))
        e.give(1)
    return _function(("reg", "value"), build, tables)


def _mask(tables):
    def build(e: E):
        p = e.p
        reg, width = p["reg"], p["width"]

        def narrow():
            value = e.sub(e.ld(e.add(e.hd(S_POW), width)), 1)
            e.var("mv", value)

            def imm8():
                _rex(e, 0, 0, 0, reg)
                _emit(e, 0x83)
                _emit(e, _modrm(e, 3, 4, reg))
                _emit(e, p["mv"])

            def imm32():
                _rex(e, 0, 0, 0, reg)
                _emit(e, 0x81)
                _emit(e, _modrm(e, 3, 4, reg))
                _bytes(e, p["mv"], 4)

            e.if_(e.lt(p["mv"], 128), imm8, imm32)

        def wide():
            _shift(e, 4, reg, e.sub(64, width))
            _shift(e, 5, reg, e.sub(64, width))

        e.if_(e.lt(width, 64), lambda: e.if_(e.eq(width, 32), lambda: _rr(e, 0x89, 1, reg, reg, 0), lambda: e.if_(e.lt(width, 32), narrow, wide)))
        e.give(1)
    return _function(("reg", "width"), build, tables)


def _sign_extend(e: E, register, width):
    def narrow():
        _shift(e, 4, register, e.sub(64, width))
        _shift(e, 7, register, e.sub(64, width))

    e.if_(e.lt(width, 64), narrow)


def _jump_fn(tables):
    """``jmp``/``jcc``/``call`` rel32 to the label whose position ``label_slot`` will hold (patched at the end)."""
    def build(e: E):
        p = e.p
        _bytes(e, p["opcode"], p["oplen"])
        count = e.hd(S_JUMPS)
        _ok(e, e.lt(count, JUMPS_LIMIT // 3))
        at = e.add(JUMPS_AT, e.mul(count, 3))
        e.st(at, e.hd(S_COUNT))
        e.st(e.add(at, 1), p["slot"])
        e.st(e.add(at, 2), 0)
        e.set_hd(S_JUMPS, e.add(count, 1))
        _bytes(e, 0, 4)
        e.give(1)
    return _function(("slot", "opcode", "oplen"), build, tables)


def _jump(e: E, kind: tuple[int, int], label_slot):
    _call(e, "jump", label_slot, kind[0], kind[1])


def _frame_access(tables):
    """``mov [rsp + offset], register`` or ``mov register, [rsp + offset]`` (the shared code's ``frame``)."""
    def build(e: E):
        p = e.p
        e.if_(e.ne(p["store"], 0), lambda: _st(e, 0x89, p["register"], p["offset"]), lambda: _st(e, 0x8B, p["register"], p["offset"]))
        e.give(1)
    return _function(("store", "register", "offset"), build, tables)


def _read(tables):
    def build(e: E):
        p = e.p
        value, scratch = p["value"], p["scratch"]
        register = _value(e, S_REG, value)
        e.if_(e.ne(register, 0), lambda: e.give(register))
        _st(e, 0x8B, scratch, _value(e, S_SLOT, value))
        e.give(scratch)
    return _function(("value", "scratch"), build, tables)


def _write(tables):
    def build(e: E):
        p = e.p
        value, register = p["value"], p["register"]
        allocated = _value(e, S_REG, value)
        e.if_(e.ne(allocated, 0), lambda: _move(e, allocated, register), lambda: _st(e, 0x89, register, _value(e, S_SLOT, value)))
        e.give(1)
    return _function(("value", "register"), build, tables)


def _read_into(e: E, value, register):
    source = _call(e, "read", value, register)
    _move(e, register, source)


def _argument_register(e: E, position):
    return e.sel(e.eq(position, 0), RCX, e.sel(e.eq(position, 1), RDX, e.sel(e.eq(position, 2), 8, 9)))


def _adjust(e: E, extension: int, frame):
    """``sub``/``add`` rsp, frame (ModRM extension 5/0)."""
    def near():
        _bytes(e, 0x8348 | ((0xC0 | (extension << 3) | RSP) << 16), 3)
        _emit(e, frame)

    def far():
        _bytes(e, 0x8148 | ((0xC0 | (extension << 3) | RSP) << 16), 3)
        _bytes(e, frame, 4)

    e.if_(e.lt(frame, 128), near, far)


def _epilogue(tables):
    def build(e: E):
        p = e.p
        saved = e.hd(S_SAVED)
        e.var("saved_at", e.ld(e.add(e.hd(S_AGG), A_OUT)))
        e.var("nsaved", 0)
        e.while_(lambda: e.both(e.lt(p["nsaved"], len(ALLOCATABLE)), e.ne(e.ld(e.add(saved, p["nsaved"])), 0)), lambda: e.set("nsaved", e.add(p["nsaved"], 1)))
        e.for_("q", 0, p["nsaved"], lambda: _st(e, 0x8B, e.ld(e.add(saved, p["q"])), e.add(p["saved_at"], e.mul(8, p["q"]))))
        _adjust(e, 0, e.hd(S_FRAME))
        _emit(e, 0xC3)
        e.give(1)
    return _function((), build, tables)


# -- the x86-64 hooks of the shared generator ------------------------------------------------------

class X86_64:
    """x86-64 views profile: Win64 registers, ``[shadow][outgoing][saved]...``, byte-sized code.

    On this ISA the frame record's first field (``A_OUT``) holds where the saved registers start."""

    ARCHITECTURE = 1
    DIAGNOSTICS = ISA  # S7b (ADR-179): this program decides target legality and writes the rejection diagnostics
    LOWERED = LOWERED_OPERATIONS
    LOWERED_NAME = "x86-64 views subset"
    ALLOCATABLE = ALLOCATABLE
    ARGUMENT_REGISTERS = len(ARGUMENTS)
    T0 = T0
    CODE_LIMIT = WORDS_LIMIT

    @staticmethod
    def declare(e: E, p) -> None:
        e.var("calls", 0)

    @staticmethod
    def on_call(e: E, p) -> None:
        e.set("calls", 1)

    @staticmethod
    def saved_end(e: E, p):
        e.set("out", e.add(e.mul(SHADOW, p["calls"]), p["out"]))  # from here on: where the saved registers start
        return e.add(p["out"], e.mul(8, p["nsaved"]))

    @staticmethod
    def frame_size(e: E, cursor):
        return e.sub(e.and_(e.add(cursor, 8 + 15), (1 << 64) - 16), 8)

    @staticmethod
    def prologue(e: E, p, index, saved, entry_base, entry) -> None:
        e.while_(lambda: e.ne(e.and_(e.hd(S_COUNT), 15), 0), lambda: _emit(e, PAD))
        e.st(e.add(e.hd(S_OFFSETS), index), e.hd(S_COUNT))
        _adjust(e, 5, p["frame"])
        e.for_("q", 0, p["nsaved"], lambda: _st(e, 0x89, e.ld(e.add(saved, p["q"])), e.add(p["out"], e.mul(8, p["q"]))))
        e.if_(e.ne(p["sret"], 0), lambda: _st(e, 0x89, RCX, p["pointer_slot"]))
        e.var("arg", p["sret"])

        def parameter():
            value = e.add(entry_base, p["q"])
            e.var("pv", value)

            def stacked():
                _st(e, 0x8B, T0, e.add(e.add(p["frame"], 8 + SHADOW), e.mul(8, e.sub(p["arg"], len(ARGUMENTS)))))  # the caller's stack argument
                _call(e, "write", p["pv"], T0)

            e.if_(e.lt(p["arg"], len(ARGUMENTS)), lambda: _call(e, "write", p["pv"], _argument_register(e, p["arg"])), stacked)
            e.set("arg", e.add(p["arg"], 1))

        e.for_("q", 0, e.ld(e.add(p["params"], entry)), lambda: e.if_(e.ne(e.ld(e.add(p["width"], e.add(entry_base, p["q"]))), 0), parameter))

    @staticmethod
    def trap(e: E) -> None:
        e.st(e.hd(S_TRAP), e.hd(S_COUNT))
        _bytes(e, 0x0B0F, 2)  # ud2

    @staticmethod
    def jump(e: E, label_slot) -> None:
        _jump(e, JMP, label_slot)

    @staticmethod
    def skip_target_machine(e: E) -> None:
        """Stack alignment, shadow space, argument registers, result register, scratch registers."""
        p = e.p
        _payload_uleb(e, "ta")
        _payload_uleb(e, "ta")
        e.var("tlist", _payload_uleb(e, "ta"))
        e.for_("q", 0, p["tlist"], lambda: _payload_uleb(e, "ta"))
        _payload_uleb(e, "ta")
        e.set("tlist", _payload_uleb(e, "ta"))
        e.for_("q", 0, p["tlist"], lambda: _payload_uleb(e, "ta"))

    @staticmethod
    def patch(e: E) -> None:
        p = e.p

        def patch():
            at = e.add(JUMPS_AT, e.mul(p["j"], 3))
            position, label = e.ld(at), e.ld(e.ld(e.add(at, 1)))
            _ok(e, e.ne(label, NONE))
            e.var("delta", e.and_(e.sub(label, e.add(position, 4)), 0xFFFFFFFF))
            e.var("rel_at", e.add(WORDS_AT, position))
            for k in range(4):
                e.st(e.add(p["rel_at"], k), _field(e, p["delta"], 8 * k, 8))

        e.for_("j", 0, e.hd(S_JUMPS), patch)


# -- one block -------------------------------------------------------------------------------------

def _block(tables):
    """Lower one block (its nodes and terminator), as ``xax_x86_64_views._compile_function`` does."""
    def build(e: E):
        p = e.p
        b = p["b"]
        e.st(e.add(e.hd(S_BLOCK_LABELS), b), e.hd(S_COUNT))
        position = e.ld(e.add(e.hd(S_BLOCK_AT), b))
        params = e.ld(position)
        e.var("na", e.add(e.add(position, 2), params))
        nodes = e.ld(e.sub(p["na"], 1))
        e.var("vid", e.add(p["vbase"], params))

        def node():
            e.var("start", e.hd(S_COUNT))
            at = p["na"]
            operation, results = e.ld(at), e.ld(e.add(at, 1))
            operands_at = e.add(e.add(at, 2), results)
            operands = e.ld(operands_at)
            attributes_at = e.add(e.add(operands_at, 1), operands)
            extra = e.ld(e.add(e.add(attributes_at, 1), e.ld(attributes_at)))
            operand = lambda k: e.ld(e.add(e.add(operands_at, 1), k))  # noqa: E731
            attribute = lambda k: e.ld(e.add(e.add(attributes_at, 1), k))  # noqa: E731
            result = p["vid"]
            width = _value(e, S_WIDTH, result)
            e.var("handled", 0)

            def case(codes, body):
                e.if_(e.either(*(e.eq(operation, int(code)) for code in codes)), lambda: (body(), e.set("handled", 1)))

            for code in (*ALU, Operation.MUL_WRAP):
                def arithmetic(code=code):
                    e.var("left", _call(e, "read", operand(0), T0))
                    e.var("right", _call(e, "read", operand(1), T1))
                    e.var("dst", _target(e, result, T0))

                    def apply(destination, source):
                        if code == Operation.MUL_WRAP:
                            _rr(e, 0xAF0F, 2, destination, source)  # imul destination, source
                        else:
                            _rr(e, ALU[code], 1, source, destination)

                    def swapped():
                        if code in (Operation.ADD_WRAP, Operation.MUL_WRAP, Operation.BIT_XOR, Operation.BIT_OR, Operation.BIT_AND):
                            apply(p["dst"], p["left"])
                        else:
                            e.set("dst", T0)
                            _move(e, T0, p["left"])
                            apply(T0, p["right"])

                    def ordered():
                        _move(e, p["dst"], p["left"])
                        apply(p["dst"], p["right"])

                    e.if_(e.both(e.eq(p["dst"], p["right"]), e.ne(p["dst"], p["left"])), swapped, ordered)
                    if code in (Operation.ADD_WRAP, Operation.SUB_WRAP, Operation.MUL_WRAP):
                        _call(e, "mask", p["dst"], width)
                    _call(e, "write", result, p["dst"])

                case((code,), arithmetic)
            for code, quotient in ((Operation.UDIV, True), (Operation.UREM, False)):
                def divide(quotient=quotient):
                    e.set_hd(S_TRAP_USED, 1)
                    e.var("right", _call(e, "read", operand(1), T1))
                    _rr(e, 0x85, 1, p["right"], p["right"])
                    _jump(e, JZ, e.hd(S_TRAP))
                    _read_into(e, operand(0), RAX)
                    _rr(e, 0x31, 1, RDX, RDX, 0)
                    _rr(e, 0xF7, 1, 6, p["right"])
                    _call(e, "write", result, RAX if quotient else RDX)

                case((code,), divide)

            def rotate():
                amount = attribute(0)
                e.var("amount", amount)
                e.var("src", _call(e, "read", operand(0), T0))
                e.var("dst", _target(e, result, T0))

                def native():
                    _move(e, p["dst"], p["src"])
                    _shift(e, 1, p["dst"], p["amount"], e.flag(e.eq(width, 64)))

                def composed():
                    _move(e, T1, p["src"])
                    _shift(e, 5, T1, p["amount"])
                    _move(e, p["dst"], p["src"])
                    _shift(e, 4, p["dst"], e.sub(width, p["amount"]))
                    _rr(e, 0x09, 1, T1, p["dst"])
                    _call(e, "mask", p["dst"], width)

                e.if_(e.eq(p["amount"], 0), lambda: _move(e, p["dst"], p["src"]), lambda: e.if_(
                    e.either(e.eq(width, 32), e.eq(width, 64)), native, composed))
                _call(e, "write", result, p["dst"])

            case((Operation.ROTATE_RIGHT,), rotate)

            def width_change():
                e.var("dst", _target(e, result, T0))
                _read_into(e, operand(0), p["dst"])
                e.if_(e.eq(operation, int(Operation.INT_TRUNCATE)), lambda: _call(e, "mask", p["dst"], width))
                _call(e, "write", result, p["dst"])

            case((Operation.INT_TRUNCATE, Operation.INT_ZERO_EXTEND), width_change)

            def constant():
                e.var("dst", _target(e, result, T0))
                _call(e, "constant", p["dst"], extra)
                _call(e, "write", result, p["dst"])

            case((Operation.CONSTANT,), constant)

            def compare():
                kind = attribute(0)
                e.var("kind", kind)
                operand_width = _value(e, S_WIDTH, operand(0))
                signed = e.both(e.le(int(IntCompare.SLT), p["kind"]), e.le(p["kind"], int(IntCompare.SGE)))
                e.var("left", 0)
                e.var("right", 0)

                def extended():
                    _read_into(e, operand(0), T0)
                    _read_into(e, operand(1), T1)
                    _sign_extend(e, T0, operand_width)
                    _sign_extend(e, T1, operand_width)
                    e.set("left", T0)
                    e.set("right", T1)

                def plain():
                    e.set("left", _call(e, "read", operand(0), T0))
                    e.set("right", _call(e, "read", operand(1), T1))

                e.if_(e.both(signed, e.lt(operand_width, 64)), extended, plain)
                e.var("dst", _target(e, result, T0))
                _rr(e, 0x39, 1, p["right"], p["left"])
                code = e.c(0)
                for item, value in SETCC.items():
                    code = e.sel(e.eq(p["kind"], int(item)), value, code)
                e.var("setcc", code)
                byte = e.flag(e.le(4, p["dst"]))
                _rex(e, 0, 0, 0, p["dst"], byte)
                _emit(e, 0x0F)
                _emit(e, p["setcc"])
                _emit(e, _modrm(e, 3, 0, p["dst"]))
                _rex(e, 0, p["dst"], 0, p["dst"], e.flag(e.le(4, p["dst"])))
                _bytes(e, 0xB60F, 2)  # movzx
                _emit(e, _modrm(e, 3, p["dst"], p["dst"]))
                _call(e, "write", result, p["dst"])

            case((Operation.INT_COMPARE,), compare)

            def call():
                def machine():
                    e.var("hidden", e.flag(e.eq(e.ld(attributes_at), 1)))
                    e.var("arg", p["hidden"])

                    def stacked():
                        e.if_(e.le(len(ARGUMENTS), p["arg"]), lambda: _st(e, 0x89, _call(e, "read", operand(p["q"]), T0),
                                                                        e.add(SHADOW, e.mul(8, e.sub(p["arg"], len(ARGUMENTS))))))
                        e.set("arg", e.add(p["arg"], 1))

                    e.for_("q", 0, operands, lambda: e.if_(e.ne(_value(e, S_WIDTH, operand(p["q"])), 0), stacked))
                    e.set("arg", p["hidden"])

                    def registered():
                        e.if_(e.lt(p["arg"], len(ARGUMENTS)), lambda: _read_into(e, operand(p["q"]), _argument_register(e, p["arg"])))
                        e.set("arg", e.add(p["arg"], 1))

                    e.for_("q", 0, operands, lambda: e.if_(e.ne(_value(e, S_WIDTH, operand(p["q"])), 0), registered))

                    def area():
                        record = e.hd(S_AGG)
                        relative = e.ld(e.add(e.ld(e.add(record, A_AREAS)), result))
                        _ok(e, e.ne(relative, NONE))
                        _st(e, 0x8D, RCX, e.add(e.ld(e.add(record, A_BASE)), relative))  # lea rcx, [rsp + area]

                    e.if_(e.ne(p["hidden"], 0), area)
                    _jump(e, CALL, e.add(e.hd(S_OFFSETS), extra))
                    e.var("machine_results", 0)
                    e.for_("q", 0, results, lambda: e.if_(e.ne(_value(e, S_WIDTH, e.add(result, p["q"])), 0), lambda: (
                        _ok(e, e.eq(p["machine_results"], 0)), _call(e, "write", e.add(result, p["q"]), RAX), e.set("machine_results", 1))))

                e.if_(e.ne(extra, NONE), machine)

            case((Operation.CALL_DIRECT,), call)
            for code in (Operation.CHECKED_LOAD_BITS_LE, Operation.CHECKED_STORE_BITS_LE):
                def checked(store=code == Operation.CHECKED_STORE_BITS_LE):
                    e.set_hd(S_TRAP_USED, 1)
                    e.var("size", attribute(0))
                    _ok(e, e.both(e.ne(extra, NONE), e.either(*(e.eq(p["size"], k) for k in (1, 2, 4, 8)))))
                    e.var("pointer", _call(e, "read", operand(0), T0))
                    e.var("offset", _call(e, "read", operand(1), T1))

                    def bounded():
                        e.var("limit", e.sub(extra, p["size"]))

                        def imm32():
                            _rex(e, 1, 0, 0, p["offset"])
                            _emit(e, 0x81)
                            _emit(e, _modrm(e, 3, 7, p["offset"]))
                            _bytes(e, p["limit"], 4)

                        def wide():
                            _call(e, "constant", RAX, p["limit"])
                            _rr(e, 0x39, 1, RAX, p["offset"])

                        e.if_(e.lt(p["limit"], 1 << 31), imm32, wide)
                        _jump(e, JA, e.hd(S_TRAP))

                    e.if_(e.lt(extra, p["size"]), lambda: _jump(e, JMP, e.hd(S_TRAP)), bounded)
                    one, two, eight = e.eq(p["size"], 1), e.eq(p["size"], 2), e.eq(p["size"], 8)
                    if store:
                        e.var("stored", _call(e, "read", operand(2), RAX))
                        _call(e, "indexed", p["stored"], p["pointer"], p["offset"], e.sel(two, 0x66, 0), e.sel(one, 0x88, 0x89), 1,
                              e.flag(eight), e.flag(e.both(one, e.le(4, p["stored"]))))
                    else:
                        e.var("dst", _target(e, result, T0))
                        _call(e, "indexed", p["dst"], p["pointer"], p["offset"], 0, e.sel(one, 0xB60F, e.sel(two, 0xB70F, 0x8B)),
                              e.sel(e.either(one, two), 2, 1), e.flag(eight), 0)
                        _call(e, "write", result, p["dst"])

                case((code,), checked)

            def get():
                def load():
                    record = e.hd(S_AGG)
                    relative = e.ld(e.add(e.ld(e.add(record, A_AREAS)), operand(0)))
                    _ok(e, e.ne(relative, NONE))
                    e.var("field_at", e.add(e.add(e.ld(e.add(record, A_BASE)), relative), e.mul(8, attribute(0))))
                    e.var("dst", _target(e, result, T0))
                    _st(e, 0x8B, p["dst"], p["field_at"])
                    _call(e, "write", result, p["dst"])

                e.if_(e.ne(width, 0), load)

            case((Operation.AGGREGATE_GET,), get)
            case((*RESOURCE_EFFECT_OPERATIONS, Operation.AGGREGATE_MAKE), lambda: None)
            _ok(e, e.ne(p["handled"], 0))

            def record():
                count = e.hd(S_RANGES)
                _ok(e, e.lt(count, RANGES_LIMIT // 5))
                at = e.add(RANGES_AT, e.mul(count, 5))
                for k, value in enumerate((e.hd(S_FN), b, p["m"], p["start"], e.hd(S_COUNT))):
                    e.st(e.add(at, k), value)
                e.set_hd(S_RANGES, e.add(count, 1))

            e.if_(e.lt(p["start"], e.hd(S_COUNT)), record)
            e.set("vid", e.add(p["vid"], results))
            e.set("na", e.add(e.add(e.add(attributes_at, 1), e.ld(attributes_at)), 1))

        e.for_("m", 0, nodes, node)
        term = p["na"]
        kind, values = e.ld(term), e.ld(e.add(term, 1))
        value = lambda k: e.ld(e.add(e.add(term, 2), k))  # noqa: E731
        flag = lambda k: e.ld(e.add(e.add(e.add(term, 2), values), k))  # noqa: E731
        edges_at = e.add(e.add(term, 2), e.mul(values, 2))
        first_edge = e.add(edges_at, 1)
        base_of = lambda t: e.ld(e.add(e.hd(S_BASE), t))  # noqa: E731

        def returns():
            e.var("machine", 0)
            e.var("fields", 0)
            e.for_("q", 0, values, lambda: e.if_(e.eq(flag(p["q"]), 2), lambda: e.set("fields", 1)))

            def stored():
                _st(e, 0x8B, RAX, e.ld(e.add(e.hd(S_AGG), A_POINTER)))
                e.set("fields", 0)

                def field():
                    e.var("field_reg", _call(e, "read", value(p["q"]), T0))
                    _rex(e, 1, p["field_reg"], 0, RAX)
                    _emit(e, 0x89)

                    def near():
                        _emit(e, _modrm(e, 1, p["field_reg"], RAX))
                        _emit(e, e.mul(8, p["fields"]))

                    def far():
                        _emit(e, _modrm(e, 2, p["field_reg"], RAX))
                        _bytes(e, e.mul(8, p["fields"]), 4)

                    e.if_(e.lt(p["fields"], 16), near, far)
                    e.set("fields", e.add(p["fields"], 1))

                e.for_("q", 0, values, lambda: e.if_(e.eq(flag(p["q"]), 2), field))

            def scalar():
                e.for_("q", 0, values, lambda: e.if_(e.ne(flag(p["q"]), 0), lambda: (
                    _ok(e, e.eq(p["machine"], 0)), _read_into(e, value(p["q"]), RAX), e.set("machine", 1))))

            e.if_(e.ne(p["fields"], 0), stored, scalar)
            _ok(e, e.ne(e.call(_FN["epilogue"]), NONE))

        def branch():
            _call(e, "edge", first_edge, base_of(e.ld(first_edge)))

        def conditional():
            e.var("condition", _call(e, "read", value(0), T0))
            _rr(e, 0x85, 1, p["condition"], p["condition"])
            false_label = e.add(e.hd(S_FALSE_LABELS), b)
            e.var("false_label", false_label)
            _jump(e, JZ, p["false_label"])
            _call(e, "edge", first_edge, base_of(e.ld(first_edge)))
            second = e.add(e.add(first_edge, 2), e.ld(e.add(first_edge, 1)))
            e.st(p["false_label"], e.hd(S_COUNT))
            _call(e, "edge", second, base_of(e.ld(second)))

        def trap():
            e.set_hd(S_TRAP_USED, 1)
            _jump(e, JMP, e.hd(S_TRAP))

        e.if_(e.eq(kind, int(TerminatorKind.RETURN)), returns, lambda: e.if_(e.eq(kind, int(TerminatorKind.BRANCH)), branch, lambda: e.if_(
            e.eq(kind, int(TerminatorKind.CONDITIONAL_BRANCH)), conditional, lambda: (_ok(e, e.eq(kind, int(TerminatorKind.TRAP))), trap()))))
        e.give(1)
    return _function(("b", "vbase"), build, tables)


# -- the program -----------------------------------------------------------------------------------

def build_backend_program():
    """``(reader, function)``: the backend program's store and its entry."""
    tables = None
    objects: list = []
    _FN.clear()

    def add(name, made):
        function, items = made
        objects.extend(items)
        _FN[name] = function
        return function

    add("diagnostic", _diagnostic(tables, X86_64))
    add("emit", _emit_n(tables))
    add("rr", _reg_reg(tables))
    add("stack", _stack(tables))
    add("indexed", _indexed(tables))
    add("shift", _shift_fn(tables))
    add("constant", _constant(tables))
    add("mask", _mask(tables))
    add("jump", _jump_fn(tables))
    add("frame", _frame_access(tables))
    add("read", _read(tables))
    add("write", _write(tables))
    add("epilogue", _epilogue(tables))
    add("edge", _copy_edge(tables, X86_64))
    add("block", _block(tables))
    add("node_info", _node_info(tables))
    add("term_end", _term_end(tables))
    add("interface", _interface(tables))
    add("erased", _erased(tables))
    add("borrowed", _borrowed(tables))
    add("aggregate", _aggregate(tables))
    add("result_fields", _result_fields(tables, X86_64))
    add("translate", _translate(tables, X86_64))
    add("frontend", _frontend(tables, X86_64))
    compile_function = add("function", _compile_function(tables, X86_64))
    program = add("program", _program(tables, compile_function, X86_64))
    return program_store(program, x86_64_linux_exec_target(), tuple(objects)), program


_PROGRAM = NativeProgram(STORE_PATH, build_backend_program, "x86-64-views-backend")
load_backend_program = _PROGRAM.load
write_backend_store = _PROGRAM.write


def collect_output(read):
    """``(code bytes, function order, function byte offsets, node ranges, entry parameter widths, entry return
    widths)`` from the program's output view (``read(start word, count)``), or None (declined)."""
    result = collect_program_output(read)
    if result is None:
        return None
    words, order, offsets, ranges, parameters, returns = result
    return bytes(words), order, offsets, ranges, parameters, returns


def native_backend():
    """The shared native x86-64 backend program, or None where it cannot run."""
    return _PROGRAM.native("XAX_X86_64_BACKEND_PYTHON")


def compile_with_xax(reader, entry, target_object, required: bool):
    """The ``X86ViewsImage`` from the XAX backend program, or None (the bootstrap generator then runs).

    S7b (ADR-179): when the program rejects the closure, the ``XaxError`` carries the diagnostic it wrote; no Python
    check decides it."""
    from xax_compiler import XaxError, fail
    from xax_riscv64 import _object_table
    from xax_selfhost_diagnostics import decode_diagnostic

    native = native_backend()
    words = None if native is None else _object_table(reader, entry, target_object)
    outcome = None if words is None else native.run(words, lambda read: (collect_output(read), decode_diagnostic(read)))
    result, diagnostic = outcome if outcome is not None else (None, None)
    if diagnostic is not None:
        raise XaxError(diagnostic)
    if result is None:
        if required:
            fail("XAX.X86_64_VIEWS.BACKEND", entry.cid.hex(), "X86_64_VIEWS-XAX-BACKEND", "accepted by the XAX backend program", "unavailable or declined")
        return None
    return image_from_backend_output(reader, target_object, result)


def image_from_backend_output(reader, target_object, result):
    from xax_artifact import ArtifactSemanticRange
    from xax_riscv64 import _table_objects
    from xax_x86_64_views import X86ViewsImage, _function_ranges

    code, order, byte_offsets, ranges, parameter_widths, return_widths = result
    objects = _table_objects(reader, target_object)
    functions = [objects[position] for position in order]
    offsets = {function.cid: offset for function, offset in zip(functions, byte_offsets)}
    node_ranges = [ArtifactSemanticRange(functions[f].cid, block, node, start, end) for f, block, node, start, end in ranges]
    return X86ViewsImage(code, 0, tuple(sorted(offsets.items())), parameter_widths, return_widths, target_object.cid,
                         (*_function_ranges(functions, offsets, len(code)), *node_ranges))


# -- helper programs for this host -------------------------------------------------------------------

_SOURCES = ("xax_compiler.py", "xax_views_lowering.py", "xax_x86_64_views.py")


def _bootstrap_order() -> str | None:
    """Why the bootstrap generator must lower the image being made now, or None when the XAX backend can.

    The backend's own image precedes it by construction.  So do the images made while the BLAKE3 hash, the store
    decoder, or the graph decoder is being built: the backend reads graph-decoder streams, which cannot load then."""
    import sys

    import xax_compiler

    if _PROGRAM._building:
        return "the XAX backend's own image is lowered by the bootstrap generator"
    hashing = sys.modules.get("blake3")
    hash_building = hashing is not None and (getattr(hashing, "_HASHER_BUILDING", False) or getattr(hashing, "_NATIVE_BUILDING", False))
    if hash_building or xax_compiler._DECODER_BUILDING or xax_compiler._GRAPH_DECODER_BUILDING:
        return "lowered before the graph decoder the XAX backend reads can load (bootstrap order)"
    return None


def host_image(reader, function, cache_name: str | None = None) -> tuple[bytes, int]:
    """``(code, entry offset)``: an XAX helper program lowered for this host by the XAX x86-64 backend (ADR-152).

    Where that backend cannot run, or while its own image is being made, the bootstrap generator gives the same
    bytes (B1); which one lowered it is recorded in ``xax_native.AUTHORITY`` under ``lowering:<cache_name>``.  With
    ``cache_name`` the image is cached on disk (``XAX_NATIVE_CACHE``) in an authenticated entry keyed by every input
    that determines it: the cache schema, the helper store, its entry function, the target profile, the generator
    sources, and the backend store.  A malformed or mismatching entry is ignored and rebuilt."""
    import hashlib
    import os
    import tempfile

    import xax_native
    from xax_compiler import XaxError, x86_64_views_target
    from xax_x86_64_views import compile_x86_64_views

    target = x86_64_views_target()
    path = key = None
    directory = xax_native.cache_dir() if cache_name is not None else None
    if directory is not None:
        sources = Path(__file__).resolve().parent
        digest = hashlib.sha256(xax_native.CACHE_MAGIC + reader.data + function.cid + target.cid)
        for name in _SOURCES:
            digest.update((sources / name).read_bytes())
        digest.update(STORE_PATH.read_bytes() if STORE_PATH.exists() else b"")
        key = digest.digest()
        path = directory / f"{cache_name}-{key.hex()}.bin"
        cached = xax_native.cache_read(path, key)
        if cached is not None:
            if cache_name is not None:
                xax_native.loaded(cache_name, reader.root_cid, cached[0])
            return cached
    lowering = f"lowering:{cache_name}"
    bootstrap_order = _bootstrap_order()
    if bootstrap_order is not None:  # the bootstrap generator makes these images by design
        xax_native.fallback(lowering, bootstrap_order, requested="python")
        image = compile_x86_64_views(reader, function.cid, target, backend="python")
    else:
        try:
            image = compile_x86_64_views(reader, function.cid, target, backend="xax")
            xax_native.loaded(lowering, reader.root_cid, image.code)
        except XaxError as error:
            xax_native.fallback(lowering, f"XAX x86-64 backend unavailable or declined ({error.diagnostic.code})")
            image = compile_x86_64_views(reader, function.cid, target, backend="python")
    if path is not None:
        try:
            with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as handle:
                handle.write(xax_native.cache_entry(key, image.code, image.entry_offset))
            os.replace(handle.name, path)
        except OSError:
            pass  # an unwritable cache only costs the next process a recompile
    if cache_name is not None:
        xax_native.loaded(cache_name, reader.root_cid, image.code)
    return image.code, image.entry_offset
