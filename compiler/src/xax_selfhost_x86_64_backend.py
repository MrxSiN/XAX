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

from xax_compiler import IntCompare, Operation, RESOURCE_EFFECT_OPERATIONS, TerminatorKind
from xax_selfhost_facts import E, HEADER, NONE, _function
from xax_selfhost_views_backend import (
    _FN, A_AREAS, A_BASE, A_OUT, A_POINTER, S_AGG, S_BASE, S_BLOCK_AT, S_BLOCK_LABELS, S_COUNT, S_FALSE_LABELS, S_FN, S_FRAME, S_OFFSETS, S_POW, S_RANGES, S_REG, S_SAVED, S_SLOT, S_TRAP, S_TRAP_USED, S_WIDTH, WORDS_AT, NativeProgram, _call, SYSCALL_HEADER, _ok, _target, _value, collect_program_output, G_PROCESS, GLOBALS, _g)

from xax_native import bootstrap_dir  # noqa: E402
from xax_x86_64_views import ARG_COPY_LOOP, NULL_ON_ERROR, STARTUP_ARGC, SYSCALL_ARGUMENT_REGISTERS

STORE_PATH = bootstrap_dir() / "xax_x86_64_backend.xax"
RAX, RCX, RDX, RSP = 0, 1, 2, 4
T0, T1 = 10, 11
ARGUMENTS = (RCX, RDX, 8, 9)
SHADOW = 32
ALLOCATABLE = (3, 5, 6, 7, 12, 13, 14, 15)
ALU = {Operation.ADD_WRAP: 0x01, Operation.SUB_WRAP: 0x29, Operation.BIT_XOR: 0x31, Operation.BIT_OR: 0x09, Operation.BIT_AND: 0x21}
SETCC = {IntCompare.EQ: 0x94, IntCompare.NE: 0x95, IntCompare.ULT: 0x92, IntCompare.ULE: 0x96, IntCompare.UGT: 0x97,
         IntCompare.UGE: 0x93, IntCompare.SLT: 0x9C, IntCompare.SLE: 0x9E, IntCompare.SGT: 0x9F, IntCompare.SGE: 0x9D}
JMP, JZ, JA, JAE, CALL = (0xE9, 1), (0x840F, 2), (0x870F, 2), (0x830F, 2), (0xE8, 1)  # opcode bytes, little-endian, and their count


# -- byte emission and encoders (``xax_x86_64_views``) ---------------------------------------------

# ADR-266: code bytes are packed eight to an output word (little-endian), and a node range takes three words, so one
# program (the S10 driver with its verifier components) fits: 40 MiB of code, 699,050 ranges.
# ADR-314: the x86-64 program's own layout of the shared regions (the RISC-V program keeps ``xax_selfhost_views_backend``'s):
# a range takes two words (its function, block and node in one, its code offsets in the other) and a jump two (ADR-313).
# S15e.2 (ADR-315): the code may take 76 MiB.  S15e.3 (ADR-317): the internal stream (21M words; the driver's is 16.1M,
# past the shared region's 16M) starts at the shared code region, the jumps (524,288) and ranges (2,097,152) follow it
# below the globals, and the code sits below the header, above the program's arena.
# S15e.5 (ADR-334): the stream (the driver with the JVM program takes 21.3M words) moves below the code, 32M words,
# and the arena ends at it; the jumps (2,097,152) and ranges (4,194,304; the driver has 2,134,204) take the shared
# code region below the globals.
# S15e.6h.4 (ADR-356): the code may take 128 MiB (the driver with the Android program takes 79.7 MiB past function 685
# of 799); the arena ends 6.5M words lower.
X86_WORDS_LIMIT = 16 << 20
X86_STREAM_LIMIT = 32 << 20
X86_JUMPS_LIMIT, X86_RANGES_LIMIT = 1 << 22, 1 << 23
X86_JUMPS_AT = WORDS_AT
X86_RANGES_AT = X86_JUMPS_AT + X86_JUMPS_LIMIT
X86_CODE_AT = HEADER - 1 - X86_WORDS_LIMIT
X86_STREAM_AT = X86_CODE_AT - X86_STREAM_LIMIT
X86_ARENA_END = X86_STREAM_AT
assert X86_RANGES_AT + X86_RANGES_LIMIT <= GLOBALS and X86_ARENA_END > (160 << 20)  # replaces the shared layout
RANGE_WORDS = 2


def _byte_weight(e: E, position):
    """``256 ** (position mod 8)``: the weight of byte ``position`` within its word."""
    return e.ld(e.add(e.hd(S_POW), e.mul(e.and_(position, 7), 8)))


def _emit(e: E, byte):
    count = e.hd(S_COUNT)
    word = e.add(X86_CODE_AT, e.udiv(count, 8))
    first = e.eq(e.and_(count, 7), 0)
    e.st(word, e.add(e.mul(e.sel(first, 0, 1), e.ld(word)), e.mul(byte, _byte_weight(e, count))))  # a new word starts clear
    e.set_hd(S_COUNT, e.add(count, 1))


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


def _rr(e: E, opcode: int, oplen: int, reg, rm, w=1):
    _call(e, "rr", reg, rm, opcode, oplen, w)


def _st(e: E, opcode: int, reg, offset, w=1, oplen=1):
    _call(e, "stack", reg, offset, opcode, oplen, w)


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


def _jump(e: E, kind: tuple[int, int], label_slot):
    _call(e, "jump", label_slot, kind[0], kind[1])


def _read(tables):
    def build(e: E):
        p = e.p
        value, scratch = p["value"], p["scratch"]
        register = _value(e, S_REG, value)
        e.if_(e.ne(register, 0), lambda: e.give(register))
        _st(e, 0x8B, scratch, _value(e, S_SLOT, value))
        e.give(scratch)
    return _function(("value", "scratch"), build, tables)


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


def _process(e: E):
    """S11 (ADR-267): the function being lowered is the process entry (the first under the exec profile)."""
    return e.both(e.ne(_g(e, G_PROCESS), 0), e.eq(e.hd(S_FN), 0))


def _epilogue(tables):
    def build(e: E):
        p = e.p
        e.if_(_process(e), lambda: (_bytes(e, 0x0B0F, 2), e.give(1)))  # ud2: the process ends only by exit_group
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

            def machine_operand(k):
                """The ``k``-th operand with a machine width (NONE declines)."""
                e.var("mo_seen", 0)
                e.var("mo_ref", NONE)
                e.for_("k", 0, operands, lambda: e.if_(e.ne(_value(e, S_WIDTH, operand(p["k"])), 0), lambda: (
                    e.if_(e.eq(p["mo_seen"], k), lambda: e.set("mo_ref", operand(p["k"]))), e.set("mo_seen", e.add(p["mo_seen"], 1)))))
                _ok(e, e.ne(p["mo_ref"], NONE))
                return p["mo_ref"]

            def first_result():
                e.var("sc_written", 0)
                e.for_("q", 0, results, lambda: e.if_(e.both(e.ne(_value(e, S_WIDTH, e.add(result, p["q"])), 0), e.eq(p["sc_written"], 0)), lambda: (
                    _call(e, "write", e.add(result, p["q"]), RAX), e.set("sc_written", 1))))

            def startup():
                """S11: ``xax_x86_64_views``'s ``_startup``: ``argc`` at the entry RSP; ``arg_copy``'s bounded byte loop."""
                def copy():
                    e.set_hd(S_TRAP_USED, 1)
                    _read_into(e, machine_operand(0), RAX)
                    _read_into(e, machine_operand(1), RDX)
                    _st(e, 0x8D, T1, e.hd(S_FRAME))  # lea r11, [rsp + frame]: &argc
                    _bytes(e, 0x033B49, 3)  # cmp rax, [r11]
                    _jump(e, JAE, e.hd(S_TRAP))
                    _bytes(e, 0xC931_08C35C8B4D, 7)  # mov r11, [r11 + rax*8 + 8]; xor ecx, ecx
                    _bytes(e, 0xF98148, 3)
                    _bytes(e, extra, 4)  # cmp rcx, extent
                    for at in range(0, len(ARG_COPY_LOOP), 8):
                        chunk = ARG_COPY_LOOP[at:at + 8]
                        _bytes(e, int.from_bytes(chunk, "little"), len(chunk))

                e.if_(e.eq(attribute(0), STARTUP_ARGC), lambda: _st(e, 0x8B, RAX, e.hd(S_FRAME)), copy)
                first_result()

            def foreign():
                """S10a: ``xax_x86_64_views``'s ``_syscall``: rsi and rdi pushed, the template placed, ``syscall``; S11: a
                startup read."""
                e.if_(e.le(STARTUP_ARGC, attribute(0)), startup, syscall)

            def syscall():
                _emit(e, 0x56)
                _emit(e, 0x57)  # push rsi; push rdi

                def argument():
                    e.var("sc_reg", 0)
                    for position, register in enumerate(SYSCALL_ARGUMENT_REGISTERS):
                        e.if_(e.eq(p["q"], position), lambda register=register: e.set("sc_reg", register))
                    e.var("sc_value", attribute(e.add(SYSCALL_HEADER + 1, e.mul(p["q"], 2))))

                    def operand_value():
                        e.var("sc_seen", 0)
                        e.var("sc_ref", NONE)
                        e.for_("k", 0, operands, lambda: e.if_(e.ne(_value(e, S_WIDTH, operand(p["k"])), 0), lambda: (
                            e.if_(e.eq(p["sc_seen"], p["sc_value"]), lambda: e.set("sc_ref", operand(p["k"]))), e.set("sc_seen", e.add(p["sc_seen"], 1)))))
                        _ok(e, e.ne(p["sc_ref"], NONE))
                        e.var("sc_source", _value(e, S_REG, p["sc_ref"]))
                        e.if_(e.either(e.eq(p["sc_source"], 6), e.eq(p["sc_source"], 7)),  # rsi, rdi: their pushed copies
                              lambda: _st(e, 0x8B, p["sc_reg"], e.sel(e.eq(p["sc_source"], 6), 8, 0)),
                              lambda: e.if_(e.ne(p["sc_source"], 0), lambda: _move(e, p["sc_reg"], p["sc_source"]),
                                            lambda: _st(e, 0x8B, p["sc_reg"], e.add(_value(e, S_SLOT, p["sc_ref"]), 16))))

                    e.if_(e.eq(attribute(e.add(SYSCALL_HEADER, e.mul(p["q"], 2))), 1), lambda: _call(e, "constant", p["sc_reg"], p["sc_value"]), operand_value)

                e.for_("q", 0, attribute(1), argument)
                _emit(e, 0xB8)
                _bytes(e, attribute(0), 4)  # mov eax, nr
                _bytes(e, 0x050F, 2)  # syscall
                e.if_(e.ne(attribute(2), 0), lambda: [_emit(e, byte) for byte in NULL_ON_ERROR])  # S10b: a nullable allocator result
                _bytes(e, 0x5E5F, 2)  # pop rdi; pop rsi
                first_result()

            case((Operation.CALL_FOREIGN,), foreign)
            # S10b (ADR-265): a heap view's pointer and a narrowed pointer are their operand's address.
            case((Operation.HEAP_VIEW, Operation.POINTER_CAST), lambda: _call(e, "write", result, _call(e, "read", operand(0), T0)))
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
                _ok(e, e.both(e.lt(count, X86_RANGES_LIMIT // RANGE_WORDS), e.lt(e.hd(S_FN), 1 << 24), e.lt(b, 1 << 20), e.lt(p["m"], 1 << 20)))
                at = e.add(X86_RANGES_AT, e.mul(count, RANGE_WORDS))
                for k, value in enumerate((e.add(e.add(e.mul(e.hd(S_FN), 1 << 40), e.mul(b, 1 << 20)), p["m"]),
                                           e.add(e.mul(p["start"], 1 << 32), e.hd(S_COUNT)))):
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


_PROGRAM = NativeProgram(STORE_PATH, "x86-64-views-backend")
load_backend_program = _PROGRAM.load


def collect_output(read):
    """``collect_program_output`` with the packed code as bytes and the packed range records unpacked, or None
    (declined)."""
    def code(count):
        return b"".join(word.to_bytes(8, "little") for word in read(X86_CODE_AT, (count + 7) // 8))[:count]

    def ranges(count):
        flat = read(X86_RANGES_AT, RANGE_WORDS * count)
        return [(a >> 40, (a >> 20) & 0xFFFFF, a & 0xFFFFF, c >> 32, c & 0xFFFFFFFF) for a, c in zip(flat[0::2], flat[1::2])]

    return collect_program_output(read, read_code=code, read_ranges=ranges, stream_at=X86_STREAM_AT)


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
    """The ``X86ViewsImage`` of the program's collected output (``collect_output``); every field is the program's."""
    from xax_riscv64 import image_record
    from xax_x86_64_views import X86ViewsImage

    code, offsets, ranges = image_record(result, 1)
    return X86ViewsImage(code, 0, tuple(sorted(offsets.items())), result[4], result[5], target_object.cid, tuple(ranges))


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
    verified = xax_native.component_store_verified(reader)  # its loader just verified it (ADR-250)
    bootstrap_order = _bootstrap_order()
    if bootstrap_order is not None:  # the bootstrap generator makes these images by design
        xax_native.fallback(lowering, bootstrap_order, requested="python")
        image = compile_x86_64_views(reader, function.cid, target, backend="python", verified=verified)
    else:
        try:
            image = compile_x86_64_views(reader, function.cid, target, backend="xax", verified=verified)
            xax_native.loaded(lowering, reader.root_cid, image.code)
        except XaxError as error:
            xax_native.fallback(lowering, f"XAX x86-64 backend unavailable or declined ({error.diagnostic.code})")
            image = compile_x86_64_views(reader, function.cid, target, backend="python", verified=verified)
    if path is not None:  # atomic (ADR-250); an unwritable cache only costs the next process a recompile
        xax_native.cache_write(path, xax_native.cache_entry(key, image.code, image.entry_offset))
    if cache_name is not None:
        xax_native.loaded(cache_name, reader.root_cid, image.code)
    return image.code, image.entry_offset
