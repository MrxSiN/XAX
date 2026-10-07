"""Self-hosting steps S5a and S5b (ADR-140, ADR-141): the RISC-V RV64IM backend as XAX semantics.

``xax_riscv64`` (ADR-113) lowers a verified function closure to a raw
position-independent image.  This module builds the whole backend after
verification as one XAX program, run natively (x86-64) like the typing program
(ADR-132), from store objects to image words.

The front end (S5b) reads every store object: kind, reference indices, CID,
and payload.  For a graph fragment the payload is the S3c XAX graph-decoder
stream; for anything else it is the body bytes.  From these it decides:

* the target's operation and terminator sets (RISC-V architecture only);
* each function's interface;
* value widths and proof types (``_machine_width``);
* constant values;
* the call closure from the entry, skipping erased proof callees, checking
  every operation and terminator against the target, and ordering the
  functions entry first, then by CID.

It writes an internal stream that the code generator (S5a) consumes:

* block-level liveness over bitsets and values' interval hulls;
* a linear scan over s1-s11 that spills to frame slots;
* the frame layout;
* lowering of every operation in the subset and of the four terminators,
  with parallel edge copies through temporaries;
* the ``li`` planner, far frame accesses, and PC-relative jump fixups.

Its output is the code words, the function order and offsets, the per-node code
ranges, and the entry's machine parameter and return widths.  All of it is
byte-identical to the bootstrap.

The program accepts or declines.  It declines where the bootstrap would
raise (an unsupported operation or terminator, a non-``bits<=64`` value, more
than one machine result, an aggregate outside ``aggregate.get`` and returns, a
jump past +-1 MiB) or where a buffer would overflow.  Arguments past a7 go on the
stack, and an aggregate result returns through a caller-owned area whose
address is the hidden first argument (ADR-151), as in ``xax_riscv64``.  On a decline the bootstrap backend runs and
raises the exact diagnostic.
"""

from __future__ import annotations

from pathlib import Path

from xax_compiler import IntCompare, Operation, RESOURCE_EFFECT_OPERATIONS, RISCV64_ARCHITECTURE, TerminatorKind, x86_64_linux_exec_target
from xax_graph_builder import program_store
from xax_selfhost_facts import E, NONE, _function
from xax_selfhost_views_backend import (
    _FN, A_AREAS, A_BASE, A_OUT, A_POINTER, G_FAR, JUMPS_AT, JUMPS_LIMIT, RANGES_AT, RANGES_LIMIT, S_AGG, S_BASE, S_BLOCK_AT,
    S_BLOCK_LABELS, S_COUNT, S_FALSE_LABELS, S_FN, S_FRAME, S_JUMPS, S_LEVELS, S_OFFSETS, S_POW, S_RANGES, S_REG, S_SAVED, S_SLOT, S_TRAP,
    S_TRAP_USED, S_WIDTH, WORDS_AT, WORDS_LIMIT, _aggregate, _borrowed, _call, _compile_function, _copy_edge, _erased,
    NativeProgram, _field, _find, _frontend, _g, _interface, _node_info, _ok, _ors, _program, _result_fields, _sar, _shl, _term_end, _translate, _value, _xor, collect_program_output,
)
from xax_selfhost_views_backend import _target as _views_target

from xax_native import bootstrap_dir  # noqa: E402

STORE_PATH = bootstrap_dir() / "xax_riscv64_backend.xax"
ZERO, RA, SP, T0, T1, T2, A0, T3 = 0, 1, 2, 5, 6, 7, 10, 28
UNIMP = 0xC0001073
ALLOCATABLE = (9, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27)
ARGUMENT_REGISTERS = 8
SIMPLE = {Operation.ADD_WRAP: (0, 0), Operation.SUB_WRAP: (0x20, 0), Operation.MUL_WRAP: (1, 0),
          Operation.BIT_XOR: (0, 4), Operation.BIT_OR: (0, 6), Operation.BIT_AND: (0, 7)}



# -- encoders (constant shifts become multiplies and unsigned divides) --------------------------

def enc_r(e, funct7, rs2, rs1, funct3, rd, opcode=0x33):
    return _ors(e, _shl(e, e.v(funct7), 25), _shl(e, e.v(rs2), 20), _shl(e, e.v(rs1), 15), _shl(e, e.v(funct3), 12), _shl(e, e.v(rd), 7), e.v(opcode))


def enc_i(e, imm, rs1, funct3, rd, opcode=0x13):
    return _ors(e, _shl(e, e.and_(imm, 0xFFF), 20), _shl(e, e.v(rs1), 15), _shl(e, e.v(funct3), 12), _shl(e, e.v(rd), 7), e.v(opcode))


def enc_s(e, imm, rs2, rs1, funct3=3, opcode=0x23):
    imm = e.and_(imm, 0xFFF)
    return _ors(e, _shl(e, _field(e, imm, 5, 7), 25), _shl(e, e.v(rs2), 20), _shl(e, e.v(rs1), 15), _shl(e, e.v(funct3), 12),
                _shl(e, _field(e, imm, 0, 5), 7), e.v(opcode))


def enc_b(e, offset, rs2, rs1, funct3):
    imm = e.and_(offset, 0x1FFF)
    return _ors(e, _shl(e, _field(e, imm, 12, 1), 31), _shl(e, _field(e, imm, 5, 6), 25), _shl(e, e.v(rs2), 20), _shl(e, e.v(rs1), 15),
                _shl(e, e.v(funct3), 12), _shl(e, _field(e, imm, 1, 4), 8), _shl(e, _field(e, imm, 11, 1), 7), e.v(0x63))


def enc_j(e, offset, rd):
    imm = e.and_(offset, 0x1FFFFF)
    return _ors(e, _shl(e, _field(e, imm, 20, 1), 31), _shl(e, _field(e, imm, 1, 10), 21), _shl(e, _field(e, imm, 11, 1), 20),
                _shl(e, _field(e, imm, 12, 8), 12), _shl(e, e.v(rd), 7), e.v(0x6F))


def _emit(e: E, word):
    count = e.hd(S_COUNT)
    e.st(e.add(WORDS_AT, count), word)
    e.set_hd(S_COUNT, e.add(count, 1))


# -- helper functions -----------------------------------------------------------------------------

def _li(tables):
    """``li rd, value`` (bootstrap ``_li_words``): lui/addiw or addi, then slli/addi levels."""
    def build(e: E):
        p = e.p
        rd = p["rd"]
        levels = e.hd(S_LEVELS)
        e.var("v", p["value"])
        e.var("depth", 0)
        e.var("done", 0)

        def level():
            v = p["v"]
            small = e.lt(e.add(v, 2048), 4096)
            word32 = e.lt(e.add(v, 1 << 31), 1 << 32)

            def split():
                low = e.sub(_xor(e, e.and_(v, 0xFFF), 0x800), 0x800)
                # (v - low) >> 12 without the 64-bit overflow at v near 2^63: low is v's sign-extended low 12 bits.
                e.var("high", e.add(_sar(e, v, 12), _field(e, v, 11, 1)))
                e.var("shift", 12)
                e.while_(lambda: e.eq(e.and_(p["high"], 1), 0), lambda: (e.set("high", _sar(e, p["high"], 1)), e.set("shift", e.add(p["shift"], 1))))
                e.st(e.add(levels, e.mul(p["depth"], 2)), p["shift"])
                e.st(e.add(levels, e.add(e.mul(p["depth"], 2), 1)), low)
                e.set("depth", e.add(p["depth"], 1))
                _ok(e, e.lt(p["depth"], 16))
                e.set("v", p["high"])

            e.if_(e.either(small, word32), lambda: e.set("done", 1), split)

        e.while_(lambda: e.eq(p["done"], 0), level)
        v = p["v"]

        def base_small():
            _emit(e, enc_i(e, v, ZERO, 0, rd))

        def base_32():
            high = e.and_(e.udiv(e.add(v, 0x800), 1 << 12), 0xFFFFF)
            upper = _shl(e, high, 12)
            low = e.sub(v, e.sub(_xor(e, upper, 0x80000000), 0x80000000))
            _emit(e, _ors(e, upper, _shl(e, rd, 7), e.v(0x37)))
            e.if_(e.ne(low, 0), lambda: _emit(e, enc_i(e, low, rd, 0, rd, 0x1B)))

        e.if_(e.lt(e.add(v, 2048), 4096), base_small, base_32)

        def unwind():
            e.set("depth", e.sub(p["depth"], 1))
            shift = e.ld(e.add(levels, e.mul(p["depth"], 2)))
            low = e.ld(e.add(levels, e.add(e.mul(p["depth"], 2), 1)))
            _emit(e, enc_i(e, shift, rd, 1, rd))
            e.if_(e.ne(low, 0), lambda: _emit(e, enc_i(e, low, rd, 0, rd)))

        e.while_(lambda: e.ne(p["depth"], 0), unwind)
        e.give(1)
    return _function(("rd", "value"), build, tables)


def _frame_access(tables):
    """Load or store ``register`` at frame ``offset`` (through t2 past the 12-bit range)."""
    def build(e: E):
        p = e.p
        store, register, offset = p["store"], p["register"], p["offset"]

        def near():
            e.if_(e.ne(store, 0), lambda: _emit(e, enc_s(e, offset, register, SP)), lambda: _emit(e, enc_i(e, offset, SP, 3, register, 0x03)))

        def far():
            _call(e, "li", T2, offset)
            _emit(e, enc_r(e, 0, SP, T2, 0, T2))
            e.if_(e.ne(store, 0), lambda: _emit(e, enc_s(e, 0, register, T2)), lambda: _emit(e, enc_i(e, 0, T2, 3, register, 0x03)))

        e.if_(e.lt(offset, 2048), near, far)
        e.give(1)
    return _function(("store", "register", "offset"), build, tables)


def _read(tables):
    """The register holding a value: its allocation, or ``scratch`` after a reload."""
    def build(e: E):
        p = e.p
        value, scratch = p["value"], p["scratch"]
        register = _value(e, S_REG, value)
        e.if_(e.ne(register, 0), lambda: e.give(register))
        _call(e, "frame", 0, scratch, _value(e, S_SLOT, value))
        e.give(scratch)
    return _function(("value", "scratch"), build, tables)


def _move(e: E, destination, source):
    e.if_(e.ne(destination, source), lambda: _emit(e, enc_i(e, 0, source, 0, destination)))


def _write(tables):
    def build(e: E):
        p = e.p
        value, register = p["value"], p["register"]
        allocated = _value(e, S_REG, value)
        e.if_(e.ne(allocated, 0), lambda: _move(e, allocated, register), lambda: _call(e, "frame", 1, register, _value(e, S_SLOT, value)))
        e.give(1)
    return _function(("value", "register"), build, tables)


def _read_into(e: E, value, register):
    source = _call(e, "read", value, register)
    _move(e, register, source)


def _target(e: E, value):
    return _views_target(e, value, T0)


def _mask(tables):
    def build(e: E):
        p = e.p
        register, width = p["register"], p["width"]

        def narrow():
            def small():
                _emit(e, enc_i(e, e.sub(e.ld(e.add(e.hd(S_POW), width)), 1), register, 7, register))

            def wide():
                _emit(e, enc_i(e, e.sub(64, width), register, 1, register))
                _emit(e, enc_i(e, e.sub(64, width), register, 5, register))

            e.if_(e.le(width, 11), small, wide)

        e.if_(e.lt(width, 64), narrow)
        e.give(1)
    return _function(("register", "width"), build, tables)


def _sign_extend(e: E, register, width):
    def narrow():
        _emit(e, enc_i(e, e.sub(64, width), register, 1, register))
        _emit(e, enc_i(e, e.or_(0x400, e.sub(64, width)), register, 5, register))

    e.if_(e.lt(width, 64), narrow)


def _skip(e: E):
    """The branch offset that skips one jump (12 for the views profile's two-word jumps)."""
    return e.sel(e.ne(_g(e, G_FAR), 0), 12, 8)


def _jal(e: E, label_slot, rd):
    """A ``jal`` to the label whose word index ``label_slot`` will hold; patched at the end."""
    count = e.hd(S_JUMPS)
    _ok(e, e.lt(count, JUMPS_LIMIT // 3))
    at = e.add(JUMPS_AT, e.mul(count, 3))
    e.st(at, e.hd(S_COUNT))
    e.st(e.add(at, 1), label_slot)
    e.st(e.add(at, 2), rd)
    e.set_hd(S_JUMPS, e.add(count, 1))
    _emit(e, 0)
    e.if_(e.ne(_g(e, G_FAR), 0), lambda: _emit(e, 0))  # views profile: auipc; jalr


# -- one function ---------------------------------------------------------------------------------

def _epilogue(tables):
    def build(e: E):
        p = e.p
        saved = e.hd(S_SAVED)
        e.var("nsaved", 0)
        e.while_(lambda: e.both(e.lt(p["nsaved"], 11), e.ne(e.ld(e.add(saved, p["nsaved"])), 0)), lambda: e.set("nsaved", e.add(p["nsaved"], 1)))
        out = e.ld(e.add(e.hd(S_AGG), A_OUT))
        e.var("out", out)
        e.for_("q", 0, p["nsaved"], lambda: _call(e, "frame", 0, e.ld(e.add(saved, p["q"])), e.add(e.add(p["out"], 8), e.mul(8, p["q"]))))
        _call(e, "frame", 0, RA, p["out"])
        frame = e.hd(S_FRAME)

        def large():
            _call(e, "li", T0, frame)
            _emit(e, enc_r(e, 0, T0, SP, 0, SP))

        e.if_(e.lt(frame, 2048), lambda: _emit(e, enc_i(e, frame, SP, 0, SP)), large)
        _emit(e, enc_i(e, 0, RA, 0, ZERO, 0x67))
        e.give(1)
    return _function((), build, tables)


def _block(tables):
    """Lower one block (its nodes and terminator)."""
    def build(e: E):
        p = e.p
        b = p["b"]
        e.st(e.add(e.hd(S_BLOCK_LABELS), b), e.hd(S_COUNT))
        position = e.ld(e.add(e.hd(S_BLOCK_AT), b))  # the block's stream position (pass 1)
        params = e.ld(position)
        e.var("na", e.add(e.add(position, 2), params))
        nodes = e.ld(e.sub(p["na"], 1))
        e.var("vid", e.add(p["vbase"], params))

        def node():
            start = e.hd(S_COUNT)
            e.var("start", start)
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

            for code, (funct7, funct3) in SIMPLE.items():
                def simple(code=code, funct7=funct7, funct3=funct3):
                    left = _call(e, "read", operand(0), T0)
                    e.var("left", left)
                    right = _call(e, "read", operand(1), T1)
                    destination = _target(e, result)
                    e.var("dst", destination)
                    _emit(e, enc_r(e, funct7, right, p["left"], funct3, p["dst"]))
                    if code in (Operation.ADD_WRAP, Operation.SUB_WRAP, Operation.MUL_WRAP):
                        _call(e, "mask", p["dst"], width)
                    _call(e, "write", result, p["dst"])

                case((code,), simple)
            for code, funct3 in ((Operation.UDIV, 5), (Operation.UREM, 7)):
                def divide(funct3=funct3):
                    e.set_hd(S_TRAP_USED, 1)
                    e.var("left", _call(e, "read", operand(0), T0))
                    e.var("right", _call(e, "read", operand(1), T1))
                    _emit(e, enc_b(e, _skip(e), ZERO, p["right"], 1))
                    _jal(e, e.hd(S_TRAP), ZERO)
                    e.var("dst", _target(e, result))
                    _emit(e, enc_r(e, 1, p["right"], p["left"], funct3, p["dst"]))
                    _call(e, "write", result, p["dst"])

                case((code,), divide)

            def rotate():
                amount = attribute(0)
                e.var("src", _call(e, "read", operand(0), T0))
                e.var("dst", _target(e, result))

                def rotated():
                    _emit(e, enc_i(e, amount, p["src"], 5, T1))
                    _emit(e, enc_i(e, e.sub(width, amount), p["src"], 1, p["dst"]))
                    _emit(e, enc_r(e, 0, T1, p["dst"], 6, p["dst"]))
                    _call(e, "mask", p["dst"], width)

                e.if_(e.ne(amount, 0), rotated, lambda: _move(e, p["dst"], p["src"]))
                _call(e, "write", result, p["dst"])

            case((Operation.ROTATE_RIGHT,), rotate)

            def width_change():
                e.var("dst", _target(e, result))
                _read_into(e, operand(0), p["dst"])
                e.if_(e.eq(operation, int(Operation.INT_TRUNCATE)), lambda: _call(e, "mask", p["dst"], width))
                _call(e, "write", result, p["dst"])

            case((Operation.INT_TRUNCATE, Operation.INT_ZERO_EXTEND), width_change)

            def constant():
                e.var("dst", _target(e, result))
                _call(e, "li", p["dst"], extra)
                _call(e, "write", result, p["dst"])

            case((Operation.CONSTANT,), constant)

            def compare():
                kind = attribute(0)
                operand_width = _value(e, S_WIDTH, operand(0))
                signed = e.both(e.le(int(IntCompare.SLT), kind), e.le(kind, int(IntCompare.SGE)))
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
                e.var("dst", _target(e, result))
                left, right, destination = p["left"], p["right"], p["dst"]
                less = e.sel(signed, 2, 3)
                is_ = lambda *kinds: e.either(*(e.eq(kind, int(item)) for item in kinds))  # noqa: E731

                def eq():
                    _emit(e, enc_r(e, 0, right, left, 4, destination))
                    _emit(e, enc_i(e, 1, destination, 3, destination))

                def ne():
                    _emit(e, enc_r(e, 0, right, left, 4, destination))
                    _emit(e, enc_r(e, 0, destination, ZERO, 3, destination))

                e.if_(is_(IntCompare.EQ), eq, lambda: e.if_(is_(IntCompare.NE), ne, lambda: e.if_(
                    is_(IntCompare.ULT, IntCompare.SLT), lambda: _emit(e, enc_r(e, 0, right, left, less, destination)), lambda: e.if_(
                        is_(IntCompare.UGT, IntCompare.SGT), lambda: _emit(e, enc_r(e, 0, left, right, less, destination)), lambda: e.if_(
                            is_(IntCompare.ULE, IntCompare.SLE), lambda: (_emit(e, enc_r(e, 0, left, right, less, destination)), _emit(e, enc_i(e, 1, destination, 4, destination))),
                            lambda: (_emit(e, enc_r(e, 0, right, left, less, destination)), _emit(e, enc_i(e, 1, destination, 4, destination))))))))
                _call(e, "write", result, destination)

            case((Operation.INT_COMPARE,), compare)

            def call():
                def machine():
                    # ADR-151: an aggregate result's area address is the hidden first argument; arguments past a7 go to
                    # the outgoing area, stored before the registers are loaded.
                    e.var("hidden", e.flag(e.eq(e.ld(attributes_at), 1)))
                    e.var("arg", p["hidden"])

                    def stacked():
                        e.if_(e.le(ARGUMENT_REGISTERS, p["arg"]), lambda: _call(e, "frame", 1, _call(e, "read", operand(p["q"]), T0),
                                                                                e.mul(8, e.sub(p["arg"], ARGUMENT_REGISTERS))))
                        e.set("arg", e.add(p["arg"], 1))

                    e.for_("q", 0, operands, lambda: e.if_(e.ne(_value(e, S_WIDTH, operand(p["q"])), 0), stacked))
                    e.set("arg", p["hidden"])

                    def registered():
                        e.if_(e.lt(p["arg"], ARGUMENT_REGISTERS), lambda: _read_into(e, operand(p["q"]), e.add(A0, p["arg"])))
                        e.set("arg", e.add(p["arg"], 1))

                    e.for_("q", 0, operands, lambda: e.if_(e.ne(_value(e, S_WIDTH, operand(p["q"])), 0), registered))

                    def area():
                        record = e.hd(S_AGG)
                        relative = e.ld(e.add(e.ld(e.add(record, A_AREAS)), result))
                        _ok(e, e.ne(relative, NONE))
                        e.var("area_at", e.add(e.ld(e.add(record, A_BASE)), relative))

                        def far():
                            _call(e, "li", A0, p["area_at"])
                            _emit(e, enc_r(e, 0, SP, A0, 0, A0))

                        e.if_(e.lt(p["area_at"], 2048), lambda: _emit(e, enc_i(e, p["area_at"], SP, 0, A0)), far)

                    e.if_(e.ne(p["hidden"], 0), area)
                    _jal(e, e.add(e.hd(S_OFFSETS), extra), RA)
                    e.var("machine_results", 0)
                    e.for_("q", 0, results, lambda: e.if_(e.ne(_value(e, S_WIDTH, e.add(result, p["q"])), 0), lambda: (
                        _ok(e, e.eq(p["machine_results"], 0)), _call(e, "write", e.add(result, p["q"]), A0), e.set("machine_results", 1))))

                e.if_(e.ne(extra, NONE), machine)

            case((Operation.CALL_DIRECT,), call)
            for code in (Operation.CHECKED_LOAD_BITS_LE, Operation.CHECKED_STORE_BITS_LE):
                def checked(store=code == Operation.CHECKED_STORE_BITS_LE):
                    # Views profile (ADR-145): trap unless offset + size <= the pointer's extent (``extra``).
                    e.set_hd(S_TRAP_USED, 1)
                    size = attribute(0)
                    e.var("size", size)
                    _ok(e, e.both(e.ne(extra, NONE), e.either(*(e.eq(p["size"], k) for k in (1, 2, 4, 8)))))
                    e.var("pointer", _call(e, "read", operand(0), T0))
                    e.var("offset", _call(e, "read", operand(1), T1))
                    fits = e.le(p["size"], extra)
                    _call(e, "li", T3, e.sel(fits, e.sub(extra, p["size"]), 0))
                    e.if_(fits, lambda: _emit(e, enc_b(e, _skip(e), p["offset"], T3, 7)))
                    _jal(e, e.hd(S_TRAP), ZERO)
                    funct3 = e.sel(e.eq(p["size"], 1), 0, e.sel(e.eq(p["size"], 2), 1, e.sel(e.eq(p["size"], 4), 2, 3)))
                    if store:
                        e.var("stored", _call(e, "read", operand(2), T3))
                        _emit(e, enc_r(e, 0, p["offset"], p["pointer"], 0, T2))
                        _emit(e, enc_s(e, 0, p["stored"], T2, funct3))
                    else:
                        _emit(e, enc_r(e, 0, p["offset"], p["pointer"], 0, T2))
                        e.var("dst", _target(e, result))
                        load3 = e.sel(e.eq(p["size"], 1), 4, e.sel(e.eq(p["size"], 2), 5, e.sel(e.eq(p["size"], 4), 6, 3)))
                        _emit(e, enc_i(e, 0, T2, load3, p["dst"], 0x03))
                        _call(e, "write", result, p["dst"])

                case((code,), checked)

            def get():
                # A field of a call's aggregate is loaded from its area; a made aggregate's field is that operand (no code).
                def load():
                    record = e.hd(S_AGG)
                    relative = e.ld(e.add(e.ld(e.add(record, A_AREAS)), operand(0)))
                    _ok(e, e.ne(relative, NONE))
                    e.var("field_at", e.add(e.add(e.ld(e.add(record, A_BASE)), relative), e.mul(8, attribute(0))))
                    e.var("dst", _target(e, result))
                    _call(e, "frame", 0, p["dst"], p["field_at"])
                    _call(e, "write", result, p["dst"])

                e.if_(e.ne(width, 0), load)

            case((Operation.AGGREGATE_GET,), get)
            case((*RESOURCE_EFFECT_OPERATIONS, Operation.AGGREGATE_MAKE), lambda: None)
            _ok(e, e.ne(p["handled"], 0))

            def record():
                count = e.hd(S_RANGES)
                _ok(e, e.lt(count, RANGES_LIMIT // 5))
                at = e.add(RANGES_AT, e.mul(count, 5))
                for k, value in enumerate((e.hd(S_FN), b, p["m"], e.mul(p["start"], 4), e.mul(e.hd(S_COUNT), 4))):
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
                # ADR-151: each field into the caller's result area, as one doubleword.
                _call(e, "frame", 0, T1, e.ld(e.add(e.hd(S_AGG), A_POINTER)))
                e.set("fields", 0)
                e.for_("q", 0, values, lambda: e.if_(e.eq(flag(p["q"]), 2), lambda: (
                    _emit(e, enc_s(e, e.mul(8, p["fields"]), _call(e, "read", value(p["q"]), T0), T1)), e.set("fields", e.add(p["fields"], 1)))))

            def scalar():
                e.for_("q", 0, values, lambda: e.if_(e.ne(flag(p["q"]), 0), lambda: (
                    _ok(e, e.eq(p["machine"], 0)), _read_into(e, value(p["q"]), A0), e.set("machine", 1))))

            e.if_(e.ne(p["fields"], 0), stored, scalar)
            _ok(e, e.ne(e.call(_FN["epilogue"]), NONE))

        def branch():
            _call(e, "edge", first_edge, base_of(e.ld(first_edge)))

        def conditional():
            condition = _call(e, "read", value(0), T0)
            _emit(e, enc_b(e, _skip(e), ZERO, condition, 1))
            false_label = e.add(e.hd(S_FALSE_LABELS), b)
            _jal(e, false_label, ZERO)
            _call(e, "edge", first_edge, base_of(e.ld(first_edge)))
            second = e.add(e.add(first_edge, 2), e.ld(e.add(first_edge, 1)))
            e.st(false_label, e.hd(S_COUNT))
            _call(e, "edge", second, base_of(e.ld(second)))

        def trap():
            e.set_hd(S_TRAP_USED, 1)
            _jal(e, e.hd(S_TRAP), ZERO)

        e.if_(e.eq(kind, int(TerminatorKind.RETURN)), returns, lambda: e.if_(e.eq(kind, int(TerminatorKind.BRANCH)), branch, lambda: e.if_(
            e.eq(kind, int(TerminatorKind.CONDITIONAL_BRANCH)), conditional, lambda: (_ok(e, e.eq(kind, int(TerminatorKind.TRAP))), trap()))))
        e.give(1)
    return _function(("b", "vbase"), build, tables)






# -- the RISC-V hooks of the shared generator (``xax_selfhost_views_backend``) ------------------------

class RISCV64:
    """RV64 views profile: LP64 registers, ``[out] ra``, then the saved registers; word-sized code."""

    ARCHITECTURE = RISCV64_ARCHITECTURE
    ALLOCATABLE = ALLOCATABLE
    ARGUMENT_REGISTERS = ARGUMENT_REGISTERS
    T0 = T0
    CODE_LIMIT = WORDS_LIMIT

    @staticmethod
    def declare(e: E, p) -> None:
        pass

    @staticmethod
    def on_call(e: E, p) -> None:
        pass

    @staticmethod
    def saved_end(e: E, p):
        """Where spill slots start: after the outgoing arguments, ra, and the saved registers."""
        return e.add(e.add(p["out"], 8), e.mul(8, p["nsaved"]))

    @staticmethod
    def frame_size(e: E, cursor):
        return e.and_(e.add(cursor, 15), (1 << 64) - 16)

    @staticmethod
    def prologue(e: E, p, index, saved, entry_base, entry) -> None:
        e.st(e.add(e.hd(S_OFFSETS), index), e.hd(S_COUNT))

        def small_frame():
            _emit(e, enc_i(e, e.sub(0, p["frame"]), SP, 0, SP))

        def large_frame():
            _call(e, "li", T0, p["frame"])
            _emit(e, enc_r(e, 0x20, T0, SP, 0, SP))

        e.if_(e.lt(p["frame"], 2048), small_frame, large_frame)
        _call(e, "frame", 1, RA, p["out"])
        e.for_("q", 0, p["nsaved"], lambda: _call(e, "frame", 1, e.ld(e.add(saved, p["q"])), e.add(e.add(p["out"], 8), e.mul(8, p["q"]))))
        e.if_(e.ne(p["sret"], 0), lambda: _call(e, "frame", 1, A0, p["pointer_slot"]))
        e.var("arg", p["sret"])

        def parameter():
            value = e.add(entry_base, p["q"])
            e.var("pv", value)

            def stacked():
                _call(e, "frame", 0, T0, e.add(p["frame"], e.mul(8, e.sub(p["arg"], ARGUMENT_REGISTERS))))  # the caller's outgoing area
                _call(e, "write", p["pv"], T0)

            e.if_(e.lt(p["arg"], ARGUMENT_REGISTERS), lambda: _call(e, "write", p["pv"], e.add(A0, p["arg"])), stacked)
            e.set("arg", e.add(p["arg"], 1))

        e.for_("q", 0, e.ld(e.add(p["params"], entry)), lambda: e.if_(e.ne(e.ld(e.add(p["width"], e.add(entry_base, p["q"]))), 0), parameter))

    @staticmethod
    def trap(e: E) -> None:
        e.st(e.hd(S_TRAP), e.hd(S_COUNT))
        _emit(e, UNIMP)

    @staticmethod
    def jump(e: E, label_slot) -> None:
        _jal(e, label_slot, ZERO)

    @staticmethod
    def skip_target_machine(e: E) -> None:
        pass

    @staticmethod
    def patch(e: E) -> None:
        p = e.p

        def patch():
            at = e.add(JUMPS_AT, e.mul(p["j"], 3))
            index, label, rd = e.ld(at), e.ld(e.ld(e.add(at, 1))), e.ld(e.add(at, 2))
            _ok(e, e.ne(label, NONE))
            delta = e.mul(e.sub(label, index), 4)

            def far():
                _ok(e, e.lt(e.add(delta, 1 << 31), (1 << 32) - 2048))
                base = e.sel(e.ne(rd, ZERO), rd, T3)
                high = e.and_(_sar(e, e.add(delta, 0x800), 12), 0xFFFFF)
                upper = _shl(e, high, 12)
                low = e.sub(delta, e.sub(_xor(e, upper, 0x80000000), 0x80000000))
                e.st(e.add(WORDS_AT, index), _ors(e, upper, _shl(e, base, 7), e.v(0x17)))
                e.st(e.add(WORDS_AT, e.add(index, 1)), enc_i(e, low, base, 0, rd, 0x67))

            def near():
                _ok(e, e.lt(e.add(delta, 1 << 20), 1 << 21))
                e.st(e.add(WORDS_AT, index), enc_j(e, delta, rd))

            e.if_(e.ne(_g(e, G_FAR), 0), far, near)

        e.for_("j", 0, e.hd(S_JUMPS), patch)


# -- the program -----------------------------------------------------------------------------------

def build_backend_program():
    """``(reader, function)``: the backend program's store and its entry."""
    tables = None
    objects: list = []

    def add(name, made):
        function, items = made
        objects.extend(items)
        _FN[name] = function
        return function

    add("find", _find(tables))
    add("li", _li(tables))
    add("frame", _frame_access(tables))
    add("read", _read(tables))
    add("write", _write(tables))
    add("mask", _mask(tables))
    add("epilogue", _epilogue(tables))
    add("edge", _copy_edge(tables, RISCV64))
    add("block", _block(tables))
    add("node_info", _node_info(tables))
    add("term_end", _term_end(tables))
    add("interface", _interface(tables))
    add("erased", _erased(tables))
    add("borrowed", _borrowed(tables))
    add("aggregate", _aggregate(tables))
    add("result_fields", _result_fields(tables))
    add("translate", _translate(tables))
    add("frontend", _frontend(tables, RISCV64))
    compile_function = add("function", _compile_function(tables, RISCV64))
    program = add("program", _program(tables, compile_function, RISCV64))
    return program_store(program, x86_64_linux_exec_target(), tuple(objects)), program


_PROGRAM = NativeProgram(STORE_PATH, build_backend_program, "riscv64-backend")
load_backend_program = _PROGRAM.load
write_backend_store = _PROGRAM.write


class NativeBackend:
    """The XAX backend program, run in-process."""

    def __init__(self, runner) -> None:
        self._runner = runner

    def compile(self, words: list[int]):
        """``collect_program_output``, or None when the program declines."""
        return self._runner.run(words, collect_output)


def collect_output(read):
    """The program's result from its output view, read as ``read(start word, count)`` (``collect_program_output``),
    or None (declined)."""
    return collect_program_output(read)


def native_backend():
    """The shared native backend, or None where it cannot run."""
    runner = _PROGRAM.native("XAX_RISCV64_BACKEND_PYTHON")
    return None if runner is None else NativeBackend(runner)
