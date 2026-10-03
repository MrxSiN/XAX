"""Self-hosting step S5a (ADR-140): the RISC-V RV64IM backend's code generation as XAX semantics.

``xax_riscv64`` (ADR-113) lowers a verified function closure to a raw
position-independent image: block-level liveness, interval hulls, a linear
scan over the callee-saved registers s1-s11 with spills to frame slots, the
frame layout, per-operation lowering, the ``li`` constant planner, parallel
edge copies, traps, and PC-relative jump fixups.  This module builds the same
code generation as one XAX program, run natively (x86-64) like the typing
program (ADR-132).  Its input is a structural stream of the verified closure
that ``xax_riscv64`` marshals; its output is the code words, the function
offsets, and the per-node code ranges, byte-identical to the bootstrap.

The program accepts or declines.  It declines where the bootstrap would raise
(more than eight machine arguments or one machine result, a jump past +-1 MiB,
an operation outside the subset) or where a buffer would overflow; on decline
the bootstrap backend runs and raises the exact diagnostic.

Input stream (words): ``F``, then per function (entry first, then the closure
in CID order): ``B, entry block, V`` and per block in index order ``P,
P widths, N``, per node ``[operation, result count, result widths, operand
count, operand value ids, attribute count, attributes, extra]`` (``extra``: a
constant's value, a direct call's callee function index or ``NONE`` for an
erased proof function, else 0), and the terminator ``[kind, value count, value
ids, machine flags, edge count, per edge: target, argument count, argument
ids]``.  Widths are 0 for proof values.  Value ids number each block's
parameters, then its node results, block by block.
"""

from __future__ import annotations

import ctypes
import mmap
import os
import platform
import sys
import threading
from pathlib import Path

from xax_compiler import IntCompare, Operation, RESOURCE_EFFECT_OPERATIONS, TerminatorKind, x86_64_linux_exec_target
from xax_graph_builder import program_store
from xax_selfhost_facts import E, H_ARENA, H_ARENA_END, HEADER, NONE, _function
from xax_selfhost_typing import IN_WORDS, OUT_WORDS

STORE_PATH = Path(__file__).resolve().parents[1] / "bootstrap" / "xax_riscv64_backend.xax"
ZERO, RA, SP, T0, T1, T2, A0 = 0, 1, 2, 5, 6, 7, 10
UNIMP = 0xC0001073
ALLOCATABLE = (9, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27)
ARGUMENT_REGISTERS = 8
SIMPLE = {Operation.ADD_WRAP: (0, 0), Operation.SUB_WRAP: (0x20, 0), Operation.MUL_WRAP: (1, 0),
          Operation.BIT_XOR: (0, 4), Operation.BIT_OR: (0, 6), Operation.BIT_AND: (0, 7)}
# Output regions (word indices of the output view).
WORDS_AT, WORDS_LIMIT = 1 << 20, 4 << 20
JUMPS_AT, JUMPS_LIMIT = 6 << 20, 3 << 20  # 3 words per jump
RANGES_AT, RANGES_LIMIT = 10 << 20, 5 << 20  # 5 words per range
ARENA_AT = 16 << 20
# Backend state in the header (after the argument words).
(S_COUNT, S_JUMPS, S_RANGES, S_FN, S_OFFSETS, S_REG, S_SLOT, S_WIDTH, S_TRAP, S_TRAP_USED, S_POW, S_FRAME, S_TEMPS,
 S_SAVED, S_BLOCK_LABELS, S_FALSE_LABELS, S_BASE, S_BLOCK_AT, S_LEVELS) = range(44, 63)
OK = 1


# -- encoders (constant shifts become multiplies and unsigned divides) --------------------------

def _shl(e: E, value, amount: int):
    return e.mul(value, 1 << amount)


def _field(e: E, value, low: int, width: int):
    """Bits ``low .. low + width`` of ``value``."""
    return e.and_(e.udiv(value, 1 << low) if low else value, (1 << width) - 1)


def _ors(e: E, *parts):
    result = parts[0]
    for part in parts[1:]:
        result = e.or_(result, part)
    return result


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


def _xor(e: E, x, y):
    return e.bin(Operation.BIT_XOR, x, y)


def _signed_lt(e: E, x, y):
    """Signed ``x < y`` on two's-complement words."""
    bias = 1 << 63
    return e.lt(_xor(e, x, bias), _xor(e, y, bias))


def _sar(e: E, value, amount: int):
    """Arithmetic shift right by a constant."""
    logical = e.udiv(value, 1 << amount)
    fill = ((1 << 64) - 1) ^ ((1 << (64 - amount)) - 1)
    return e.or_(logical, e.sel(e.lt(value, 1 << 63), 0, fill))


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


def _ok(e: E, condition):
    """Decline (NONE) unless ``condition``."""
    e.if_(e.not_(condition), lambda: e.give(NONE))


_FN: dict = {}


def _call(e: E, name, *arguments):
    result = e.call(_FN[name], *arguments)
    _ok(e, e.ne(result, NONE))
    return result


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


def _value(e: E, field: int, value):
    return e.ld(e.add(e.hd(field), value))


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
    register = _value(e, S_REG, value)
    return e.sel(e.ne(register, 0), register, T0)


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


def _bit(e: E, value):
    return e.ld(e.add(e.hd(S_POW), e.urem(value, 64)))


def _has(e: E, bitset, value):
    return e.ne(e.and_(e.ld(e.add(bitset, e.udiv(value, 64))), _bit(e, value)), 0)


def _put(e: E, bitset, value):
    word = e.add(bitset, e.udiv(value, 64))
    e.st(word, e.or_(e.ld(word), _bit(e, value)))


# -- one function ---------------------------------------------------------------------------------

def _compile_function(tables):
    """Lower the function at stream ``cursor`` (index ``index``); the cursor after it, or NONE."""
    def build(e: E):
        p = e.p
        index = p["index"]
        e.set_hd(S_FN, index)
        B, entry, V = (e.rd(e.add(p["cursor"], k)) for k in range(3))
        _ok(e, e.both(e.ne(B, 0), e.lt(entry, B)))
        e.var("V", V)
        e.var("B", B)
        words = e.add(e.udiv(e.add(V, 63), 64), 1)
        e.var("W", words)

        def array(name, size, fill=0):
            e.var(name, e.alloc(size))
            _ok(e, e.ne(p[name], NONE))
            e.for_("fill_k", 0, size, lambda: e.st(e.add(p[name], p["fill_k"]), fill))
            return p[name]

        for name in ("width", "reg", "slot", "rank", "lo", "hi"):
            array(name, e.add(V, 1), NONE if name == "lo" else 0)
        e.set_hd(S_WIDTH, p["width"])
        e.set_hd(S_REG, p["reg"])
        e.set_hd(S_SLOT, p["slot"])
        for name in ("block_at", "base", "params", "order", "bstart", "bend", "nodes_at", "term_at"):
            array(name, e.add(B, 1))
        array("block_labels", e.add(B, 1), NONE)
        array("false_labels", e.add(B, 1), NONE)
        e.set_hd(S_BLOCK_LABELS, p["block_labels"])
        e.set_hd(S_FALSE_LABELS, p["false_labels"])
        for name in ("uses", "defs", "lin", "lout", "pmask"):
            array(name, e.add(e.mul(B, words), 1))
        array("trap", 1, NONE)
        e.set_hd(S_TRAP, p["trap"])
        e.set_hd(S_TRAP_USED, 0)

        # Pass 1: block positions, value ids, widths, and the largest parameter count.
        e.var("at", e.add(p["cursor"], 3))
        e.var("next_id", 0)
        e.var("max_params", 0)

        def place():
            b = p["b"]
            e.st(e.add(p["block_at"], b), p["at"])
            e.st(e.add(p["base"], b), p["next_id"])
            count = e.rd(p["at"])
            e.st(e.add(p["params"], b), count)
            e.if_(e.lt(p["max_params"], count), lambda: e.set("max_params", count))
            e.for_("q", 0, count, lambda: (e.st(e.add(p["width"], e.add(p["next_id"], p["q"])), e.rd(e.add(e.add(p["at"], 1), p["q"]))),
                                           _put(e, e.add(p["pmask"], e.mul(b, p["W"])), e.add(p["next_id"], p["q"]))))
            e.set("next_id", e.add(p["next_id"], count))
            e.set("at", e.add(e.add(p["at"], 1), count))
            nodes = e.rd(p["at"])
            e.st(e.add(p["nodes_at"], b), e.add(p["at"], 1))
            e.set("at", e.add(p["at"], 1))

            def node():
                results = e.rd(e.add(p["at"], 1))
                e.for_("q", 0, results, lambda: e.st(e.add(p["width"], e.add(p["next_id"], p["q"])), e.rd(e.add(e.add(p["at"], 2), p["q"]))))
                e.set("next_id", e.add(p["next_id"], results))
                operands_at = e.add(e.add(p["at"], 2), results)
                attributes_at = e.add(e.add(operands_at, 1), e.rd(operands_at))
                e.set("at", e.add(e.add(e.add(attributes_at, 1), e.rd(attributes_at)), 1))

            e.for_("m", 0, nodes, node)
            e.st(e.add(p["term_at"], b), p["at"])
            values = e.rd(e.add(p["at"], 1))
            e.set("at", e.add(e.add(p["at"], 2), e.mul(values, 2)))
            edges = e.rd(p["at"])
            e.set("at", e.add(p["at"], 1))
            e.for_("x", 0, edges, lambda: e.set("at", e.add(e.add(p["at"], 2), e.rd(e.add(p["at"], 1)))))

        e.for_("b", 0, B, place)
        _ok(e, e.eq(p["next_id"], V))
        e.set_hd(S_BLOCK_AT, p["block_at"])
        e.set_hd(S_BASE, p["base"])
        e.var("after", p["at"])

        # Linear-scan ranks: (tag, block, index, result) order -- parameters first, then node results.
        e.var("ordinal", 0)
        for parameters in (True, False):
            def ranks(parameters=parameters):
                b = p["b"]
                base, count = e.ld(e.add(p["base"], b)), e.ld(e.add(p["params"], b))
                end = e.sel(e.lt(e.add(b, 1), B), e.ld(e.add(p["base"], e.add(b, 1))), V)
                low, high = (base, e.add(base, count)) if parameters else (e.add(base, count), end)
                e.for_("q", low, high, lambda: (e.st(e.add(p["rank"], p["q"]), p["ordinal"]), e.set("ordinal", e.add(p["ordinal"], 1))))

            e.for_("b", 0, B, ranks)
        # Block order: the entry, then the others by index.
        e.st(p["order"], entry)
        e.var("o", 1)
        e.for_("b", 0, B, lambda: e.if_(e.ne(p["b"], entry), lambda: (e.st(e.add(p["order"], p["o"]), p["b"]), e.set("o", e.add(p["o"], 1)))))

        # Positions, uses, and definitions.
        def touch(value, position):
            lo, hi = e.add(p["lo"], value), e.add(p["hi"], value)
            e.if_(e.either(e.eq(e.ld(lo), NONE), e.lt(position, e.ld(lo))), lambda: e.st(lo, position))
            e.if_(e.lt(e.ld(hi), position), lambda: e.st(hi, position))

        def use(b, value, position):
            touch(value, position)
            defs = e.add(p["defs"], e.mul(b, p["W"]))
            e.if_(e.not_(_has(e, defs, value)), lambda: _put(e, e.add(p["uses"], e.mul(b, p["W"])), value))

        e.var("pos", 0)

        def walk():
            b = e.ld(e.add(p["order"], p["k"]))
            e.var("wb", b)
            e.st(e.add(p["bstart"], b), p["pos"])
            base = e.ld(e.add(p["base"], b))
            e.var("vid", base)
            defs = e.add(p["defs"], e.mul(b, p["W"]))
            e.for_("q", 0, e.ld(e.add(p["params"], b)), lambda: (_put(e, defs, p["vid"]), touch(p["vid"], p["pos"]), e.set("vid", e.add(p["vid"], 1))))
            e.var("na_at", e.ld(e.add(p["nodes_at"], b)))
            nodes = e.rd(e.sub(p["na_at"], 1))

            def node():
                e.set("pos", e.add(p["pos"], 1))
                at = p["na_at"]
                results = e.rd(e.add(at, 1))
                operands_at = e.add(e.add(at, 2), results)
                e.for_("q", 0, e.rd(operands_at), lambda: use(p["wb"], e.rd(e.add(e.add(operands_at, 1), p["q"])), p["pos"]))
                e.for_("q", 0, results, lambda: (_put(e, defs, p["vid"]), touch(p["vid"], p["pos"]), e.set("vid", e.add(p["vid"], 1))))
                attributes_at = e.add(e.add(operands_at, 1), e.rd(operands_at))
                e.set("na_at", e.add(e.add(e.add(attributes_at, 1), e.rd(attributes_at)), 1))

            e.for_("m", 0, nodes, node)
            e.set("pos", e.add(p["pos"], 1))
            term = e.ld(e.add(p["term_at"], b))
            values = e.rd(e.add(term, 1))
            e.for_("q", 0, values, lambda: use(p["wb"], e.rd(e.add(e.add(term, 2), p["q"])), p["pos"]))
            e.var("edge_at", e.add(e.add(e.add(term, 2), e.mul(values, 2)), 1))

            def edge():
                at = p["edge_at"]
                arguments = e.rd(e.add(at, 1))
                e.for_("q", 0, arguments, lambda: use(p["wb"], e.rd(e.add(e.add(at, 2), p["q"])), p["pos"]))
                e.set("edge_at", e.add(e.add(at, 2), arguments))

            e.for_("x", 0, e.rd(e.sub(p["edge_at"], 1)), edge)
            e.st(e.add(p["bend"], b), p["pos"])
            e.set("pos", e.add(p["pos"], 1))

        e.for_("k", 0, B, walk)

        # Liveness to a fixpoint: out = U (live_in[t] - params[t]), in = uses | (out - defs).
        e.var("changed", 1)

        def iterate():
            e.set("changed", 0)

            def block():
                b = e.ld(e.add(p["order"], e.sub(e.sub(B, 1), p["k"])))
                e.var("lb", b)
                term = e.ld(e.add(p["term_at"], b))
                values = e.rd(e.add(term, 1))
                edges_at = e.add(e.add(term, 2), e.mul(values, 2))

                def word():
                    w = p["w"]
                    e.var("out_word", 0)
                    e.var("e_at", e.add(edges_at, 1))

                    def edge():
                        t = e.rd(p["e_at"])
                        live = e.ld(e.add(e.add(p["lin"], e.mul(t, p["W"])), w))
                        own = e.ld(e.add(e.add(p["pmask"], e.mul(t, p["W"])), w))
                        e.set("out_word", e.or_(p["out_word"], e.and_(live, _xor(e, own, (1 << 64) - 1))))
                        e.set("e_at", e.add(e.add(p["e_at"], 2), e.rd(e.add(p["e_at"], 1))))

                    e.for_("x", 0, e.rd(edges_at), edge)
                    offset = e.add(e.mul(p["lb"], p["W"]), w)
                    defs = e.ld(e.add(p["defs"], offset))
                    new_in = e.or_(e.ld(e.add(p["uses"], offset)), e.and_(p["out_word"], _xor(e, defs, (1 << 64) - 1)))
                    e.if_(e.either(e.ne(new_in, e.ld(e.add(p["lin"], offset))), e.ne(p["out_word"], e.ld(e.add(p["lout"], offset)))), lambda: (
                        e.st(e.add(p["lin"], offset), new_in), e.st(e.add(p["lout"], offset), p["out_word"]), e.set("changed", 1)))

                e.for_("w", 0, p["W"], word)

            e.for_("k", 0, B, block)

        e.while_(lambda: e.ne(p["changed"], 0), iterate)

        def boundaries():
            b = p["b"]

            def word():
                live_in = e.ld(e.add(e.add(p["lin"], e.mul(b, p["W"])), p["w"]))
                live_out = e.ld(e.add(e.add(p["lout"], e.mul(b, p["W"])), p["w"]))

                def bit():
                    value = e.add(e.mul(p["w"], 64), p["z"])
                    mask = e.ld(e.add(e.hd(S_POW), p["z"]))
                    e.if_(e.ne(e.and_(live_in, mask), 0), lambda: touch(value, e.ld(e.add(p["bstart"], b))))
                    e.if_(e.ne(e.and_(live_out, mask), 0), lambda: touch(value, e.ld(e.add(p["bend"], b))))

                e.if_(e.ne(e.or_(live_in, live_out), 0), lambda: e.for_("z", 0, 64, bit))

            e.for_("w", 0, p["W"], word)

        e.for_("b", 0, B, boundaries)

        # Linear scan over machine values sorted by (start, end, rank).
        sorted_ = array("sorted", e.add(V, 1))
        e.var("n", 0)

        def before(x, y):
            lo_x, lo_y = e.ld(e.add(p["lo"], x)), e.ld(e.add(p["lo"], y))
            hi_x, hi_y = e.ld(e.add(p["hi"], x)), e.ld(e.add(p["hi"], y))
            rank_x, rank_y = e.ld(e.add(p["rank"], x)), e.ld(e.add(p["rank"], y))
            return e.either(e.lt(lo_x, lo_y), e.both(e.eq(lo_x, lo_y), e.either(e.lt(hi_x, hi_y), e.both(e.eq(hi_x, hi_y), e.lt(rank_x, rank_y)))))

        def insert():
            value = p["v"]

            def add():
                e.var("j", p["n"])
                e.while_(lambda: e.both(e.ne(p["j"], 0), before(value, e.ld(e.add(sorted_, e.sub(p["j"], 1))))), lambda: (
                    e.st(e.add(sorted_, p["j"]), e.ld(e.add(sorted_, e.sub(p["j"], 1)))), e.set("j", e.sub(p["j"], 1))))
                e.st(e.add(sorted_, p["j"]), value)
                e.set("n", e.add(p["n"], 1))

            e.if_(e.ne(e.ld(e.add(p["width"], value)), 0), add)

        e.for_("v", 0, V, insert)
        active = array("active", 16)
        e.var("active_n", 0)
        e.var("free", sum(1 << r for r in ALLOCATABLE))

        def scan():
            value = e.ld(e.add(sorted_, p["s"]))
            start, end = e.ld(e.add(p["lo"], value)), e.ld(e.add(p["hi"], value))
            # Expire intervals that ended before this one starts.
            e.var("keep", 0)

            def expire():
                item = e.ld(e.add(active, p["a"]))
                e.if_(e.lt(e.ld(e.add(p["hi"], item)), start), lambda: e.set("free", e.or_(p["free"], _bit(e, e.ld(e.add(p["reg"], item))))), lambda: (
                    e.st(e.add(active, p["keep"]), item), e.set("keep", e.add(p["keep"], 1))))

            e.for_("a", 0, p["active_n"], expire)
            e.set("active_n", p["keep"])

            def assign():
                e.var("pick", 0)
                for register in reversed(ALLOCATABLE):
                    e.if_(e.ne(e.and_(p["free"], 1 << register), 0), lambda register=register: e.set("pick", register))
                e.st(e.add(p["reg"], value), p["pick"])
                e.set("free", e.and_(p["free"], _xor(e, _bit(e, p["pick"]), (1 << 64) - 1)))
                e.st(e.add(active, p["active_n"]), value)
                e.set("active_n", e.add(p["active_n"], 1))

            def spill():
                e.var("furthest", 0)

                def pick():
                    item, best = e.ld(e.add(active, p["a"])), e.ld(e.add(active, p["furthest"]))
                    hi_i, hi_b = e.ld(e.add(p["hi"], item)), e.ld(e.add(p["hi"], best))
                    later = e.either(e.lt(hi_b, hi_i), e.both(e.eq(hi_b, hi_i), e.lt(e.ld(e.add(p["rank"], best)), e.ld(e.add(p["rank"], item)))))
                    e.if_(later, lambda: e.set("furthest", p["a"]))

                e.for_("a", 1, p["active_n"], pick)
                victim = e.ld(e.add(active, p["furthest"]))

                def steal():
                    e.st(e.add(p["reg"], value), e.ld(e.add(p["reg"], victim)))
                    e.st(e.add(p["reg"], victim), 0)
                    e.st(e.add(active, p["furthest"]), value)

                e.if_(e.lt(end, e.ld(e.add(p["hi"], victim))), steal)

            e.if_(e.ne(p["free"], 0), assign, spill)

        e.for_("s", 0, p["n"], scan)

        # Frame: [0] ra, the saved s-registers in use (ascending), spill slots, edge temporaries.
        e.var("used", 0)
        e.for_("v", 0, V, lambda: e.if_(e.ne(e.ld(e.add(p["reg"], p["v"])), 0), lambda: e.set("used", e.or_(p["used"], _bit(e, e.ld(e.add(p["reg"], p["v"])))))))
        saved = array("saved_at", 32)
        e.set_hd(S_SAVED, saved)
        e.var("nsaved", 0)
        for register in ALLOCATABLE:
            e.if_(e.ne(e.and_(p["used"], 1 << register), 0), lambda register=register: (
                e.st(e.add(saved, p["nsaved"]), register), e.set("nsaved", e.add(p["nsaved"], 1))))
        e.var("frame_cursor", e.add(8, e.mul(8, p["nsaved"])))
        e.for_("v", 0, V, lambda: e.if_(e.both(e.ne(e.ld(e.add(p["width"], p["v"])), 0), e.eq(e.ld(e.add(p["reg"], p["v"])), 0)), lambda: (
            e.st(e.add(p["slot"], p["v"]), p["frame_cursor"]), e.set("frame_cursor", e.add(p["frame_cursor"], 8)))))
        e.set_hd(S_TEMPS, p["frame_cursor"])
        frame = e.and_(e.add(e.add(p["frame_cursor"], e.mul(8, p["max_params"])), 15), (1 << 64) - 16)
        e.var("frame", frame)
        e.set_hd(S_FRAME, frame)
        # Entry machine parameters: at most eight.
        entry_base = e.ld(e.add(p["base"], entry))
        e.var("machine_params", 0)
        e.for_("q", 0, e.ld(e.add(p["params"], entry)), lambda: e.if_(e.ne(e.ld(e.add(p["width"], e.add(entry_base, p["q"]))), 0), lambda: e.set(
            "machine_params", e.add(p["machine_params"], 1))))
        _ok(e, e.le(p["machine_params"], ARGUMENT_REGISTERS))

        # Prologue.
        e.st(e.add(e.hd(S_OFFSETS), index), e.hd(S_COUNT))

        def small_frame():
            _emit(e, enc_i(e, e.sub(0, p["frame"]), SP, 0, SP))

        def large_frame():
            _call(e, "li", T0, p["frame"])
            _emit(e, enc_r(e, 0x20, T0, SP, 0, SP))

        e.if_(e.lt(p["frame"], 2048), small_frame, large_frame)
        _emit(e, enc_s(e, 0, RA, SP))
        e.for_("q", 0, p["nsaved"], lambda: _call(e, "frame", 1, e.ld(e.add(saved, p["q"])), e.add(8, e.mul(8, p["q"]))))
        e.var("arg", 0)
        e.for_("q", 0, e.ld(e.add(p["params"], entry)), lambda: e.if_(e.ne(e.ld(e.add(p["width"], e.add(entry_base, p["q"]))), 0), lambda: (
            _call(e, "write", e.add(entry_base, p["q"]), e.add(A0, p["arg"])), e.set("arg", e.add(p["arg"], 1)))))

        # Blocks in order.
        e.for_("k", 0, B, lambda: _ok(e, e.ne(e.call(_FN["block"], e.ld(e.add(p["order"], p["k"])), e.ld(e.add(p["base"], e.ld(e.add(p["order"], p["k"])))), ), NONE)))

        def trap():
            e.st(e.hd(S_TRAP), e.hd(S_COUNT))
            _emit(e, UNIMP)

        e.if_(e.ne(e.hd(S_TRAP_USED), 0), trap)
        e.give(p["after"])
    return _function(("cursor", "index"), build, tables)


def _epilogue(tables):
    def build(e: E):
        p = e.p
        saved = e.hd(S_SAVED)
        e.var("nsaved", 0)
        e.while_(lambda: e.both(e.lt(p["nsaved"], 11), e.ne(e.ld(e.add(saved, p["nsaved"])), 0)), lambda: e.set("nsaved", e.add(p["nsaved"], 1)))
        e.for_("q", 0, p["nsaved"], lambda: _call(e, "frame", 0, e.ld(e.add(saved, p["q"])), e.add(8, e.mul(8, p["q"]))))
        _emit(e, enc_i(e, 0, SP, 3, RA, 0x03))
        frame = e.hd(S_FRAME)

        def large():
            _call(e, "li", T0, frame)
            _emit(e, enc_r(e, 0, T0, SP, 0, SP))

        e.if_(e.lt(frame, 2048), lambda: _emit(e, enc_i(e, frame, SP, 0, SP)), large)
        _emit(e, enc_i(e, 0, RA, 0, ZERO, 0x67))
        e.give(1)
    return _function((), build, tables)


def _location(e: E, value):
    register = _value(e, S_REG, value)
    return e.sel(e.ne(register, 0), register, e.add(1 << 32, _value(e, S_SLOT, value)))


def _copy_edge(tables):
    """Edge arguments into the target's parameters (through the temporaries when a destination is also a source)."""
    def build(e: E):
        p = e.p
        at = p["edge"]  # [target, argument count, argument ids]
        target, count = e.rd(at), e.rd(e.add(at, 1))
        base = p["target_base"]
        moves = e.alloc(e.add(e.mul(count, 2), 1))
        _ok(e, e.ne(moves, NONE))
        e.var("moves_n", 0)

        def collect():
            destination, argument = e.add(base, p["q"]), e.rd(e.add(e.add(at, 2), p["q"]))
            needed = e.both(e.ne(_value(e, S_WIDTH, destination), 0), e.ne(_location(e, destination), _location(e, argument)))
            e.if_(needed, lambda: (e.st(e.add(moves, e.mul(p["moves_n"], 2)), destination), e.st(e.add(moves, e.add(e.mul(p["moves_n"], 2), 1)), argument),
                                   e.set("moves_n", e.add(p["moves_n"], 1))))

        e.for_("q", 0, count, collect)
        e.var("conflict", 0)

        def check():
            destination = _location(e, e.ld(e.add(moves, e.mul(p["q"], 2))))
            e.for_("r", 0, p["moves_n"], lambda: e.if_(e.eq(destination, _location(e, e.ld(e.add(moves, e.add(e.mul(p["r"], 2), 1))))), lambda: e.set("conflict", 1)))

        e.for_("q", 0, p["moves_n"], check)
        temporaries = e.hd(S_TEMPS)

        def through():
            e.for_("q", 0, p["moves_n"], lambda: _call(e, "frame", 1, _call(e, "read", e.ld(e.add(moves, e.add(e.mul(p["q"], 2), 1))), T0),
                                                        e.add(temporaries, e.mul(8, p["q"]))))

            def back():
                destination = e.ld(e.add(moves, e.mul(p["q"], 2)))
                register = _target(e, destination)
                _call(e, "frame", 0, register, e.add(temporaries, e.mul(8, p["q"])))
                _call(e, "write", destination, register)

            e.for_("q", 0, p["moves_n"], back)

        def direct():
            e.for_("q", 0, p["moves_n"], lambda: _call(e, "write", e.ld(e.add(moves, e.mul(p["q"], 2))), _call(e, "read", e.ld(e.add(moves, e.add(e.mul(p["q"], 2), 1))), T0)))

        e.if_(e.ne(p["conflict"], 0), through, direct)
        _jal(e, e.add(e.hd(S_BLOCK_LABELS), target), ZERO)
        e.give(1)
    return _function(("edge", "target_base"), build, tables)


def _block(tables):
    """Lower one block (its nodes and terminator)."""
    def build(e: E):
        p = e.p
        b = p["b"]
        e.st(e.add(e.hd(S_BLOCK_LABELS), b), e.hd(S_COUNT))
        position = e.ld(e.add(e.hd(S_BLOCK_AT), b))  # the block's stream position (pass 1)
        params = e.rd(position)
        e.var("na", e.add(e.add(position, 2), params))
        nodes = e.rd(e.sub(p["na"], 1))
        e.var("vid", e.add(p["vbase"], params))

        def node():
            start = e.hd(S_COUNT)
            e.var("start", start)
            at = p["na"]
            operation, results = e.rd(at), e.rd(e.add(at, 1))
            operands_at = e.add(e.add(at, 2), results)
            operands = e.rd(operands_at)
            attributes_at = e.add(e.add(operands_at, 1), operands)
            extra = e.rd(e.add(e.add(attributes_at, 1), e.rd(attributes_at)))
            operand = lambda k: e.rd(e.add(e.add(operands_at, 1), k))  # noqa: E731
            attribute = lambda k: e.rd(e.add(e.add(attributes_at, 1), k))  # noqa: E731
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
                    _emit(e, enc_b(e, 8, ZERO, p["right"], 1))
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
                    e.var("arg", 0)
                    e.for_("q", 0, operands, lambda: e.if_(e.ne(_value(e, S_WIDTH, operand(p["q"])), 0), lambda: (
                        _ok(e, e.lt(p["arg"], ARGUMENT_REGISTERS)), _read_into(e, operand(p["q"]), e.add(A0, p["arg"])), e.set("arg", e.add(p["arg"], 1)))))
                    _jal(e, e.add(e.hd(S_OFFSETS), extra), RA)
                    e.var("machine_results", 0)
                    e.for_("q", 0, results, lambda: e.if_(e.ne(_value(e, S_WIDTH, e.add(result, p["q"])), 0), lambda: (
                        _ok(e, e.eq(p["machine_results"], 0)), _call(e, "write", e.add(result, p["q"]), A0), e.set("machine_results", 1))))

                e.if_(e.ne(extra, NONE), machine)

            case((Operation.CALL_DIRECT,), call)
            case(tuple(RESOURCE_EFFECT_OPERATIONS), lambda: None)
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
            e.set("na", e.add(e.add(e.add(attributes_at, 1), e.rd(attributes_at)), 1))

        e.for_("m", 0, nodes, node)
        term = p["na"]
        kind, values = e.rd(term), e.rd(e.add(term, 1))
        value = lambda k: e.rd(e.add(e.add(term, 2), k))  # noqa: E731
        flag = lambda k: e.rd(e.add(e.add(e.add(term, 2), values), k))  # noqa: E731
        edges_at = e.add(e.add(term, 2), e.mul(values, 2))
        first_edge = e.add(edges_at, 1)
        base_of = lambda t: e.ld(e.add(e.hd(S_BASE), t))  # noqa: E731

        def returns():
            e.var("machine", 0)
            e.for_("q", 0, values, lambda: e.if_(e.ne(flag(p["q"]), 0), lambda: (
                _ok(e, e.eq(p["machine"], 0)), _read_into(e, value(p["q"]), A0), e.set("machine", 1))))
            _ok(e, e.ne(e.call(_FN["epilogue"]), NONE))

        def branch():
            _call(e, "edge", first_edge, base_of(e.rd(first_edge)))

        def conditional():
            condition = _call(e, "read", value(0), T0)
            _emit(e, enc_b(e, 8, ZERO, condition, 1))
            false_label = e.add(e.hd(S_FALSE_LABELS), b)
            _jal(e, false_label, ZERO)
            _call(e, "edge", first_edge, base_of(e.rd(first_edge)))
            second = e.add(e.add(first_edge, 2), e.rd(e.add(first_edge, 1)))
            e.st(false_label, e.hd(S_COUNT))
            _call(e, "edge", second, base_of(e.rd(second)))

        def trap():
            e.set_hd(S_TRAP_USED, 1)
            _jal(e, e.hd(S_TRAP), ZERO)

        e.if_(e.eq(kind, int(TerminatorKind.RETURN)), returns, lambda: e.if_(e.eq(kind, int(TerminatorKind.BRANCH)), branch, lambda: e.if_(
            e.eq(kind, int(TerminatorKind.CONDITIONAL_BRANCH)), conditional, lambda: (_ok(e, e.eq(kind, int(TerminatorKind.TRAP))), trap()))))
        e.give(1)
    return _function(("b", "vbase"), build, tables)


# -- the program -----------------------------------------------------------------------------------

def _program(tables, compile_function):
    def build(e: E):
        p = e.p
        e.st(0, 0)
        e.set_hd(H_ARENA, ARENA_AT)
        e.set_hd(H_ARENA_END, HEADER - 1)
        e.set_hd(S_COUNT, 0)
        e.set_hd(S_JUMPS, 0)
        e.set_hd(S_RANGES, 0)
        powers = e.alloc(64)
        e.var("power", 1)
        e.for_("z", 0, 64, lambda: (e.st(e.add(powers, p["z"]), p["power"]), e.set("power", e.mul(p["power"], 2))))
        e.set_hd(S_POW, powers)
        e.set_hd(S_LEVELS, e.alloc(32))
        functions = e.rd(0)
        offsets = e.alloc(e.add(functions, 1))
        _ok(e, e.ne(offsets, NONE))
        e.set_hd(S_OFFSETS, offsets)
        e.for_("f", 0, functions, lambda: e.st(e.add(offsets, p["f"]), NONE))
        e.var("cursor", 1)

        def each():
            e.set("cursor", e.call(compile_function, p["cursor"], p["f"]))
            _ok(e, e.ne(p["cursor"], NONE))
            _ok(e, e.lt(e.hd(S_COUNT), WORDS_LIMIT))

        e.for_("f", 0, functions, each)
        # Jumps.
        def patch():
            at = e.add(JUMPS_AT, e.mul(p["j"], 3))
            index, label, rd = e.ld(at), e.ld(e.ld(e.add(at, 1))), e.ld(e.add(at, 2))
            _ok(e, e.ne(label, NONE))
            delta = e.mul(e.sub(label, index), 4)
            _ok(e, e.lt(e.add(delta, 1 << 20), 1 << 21))
            e.st(e.add(WORDS_AT, index), enc_j(e, delta, rd))

        e.for_("j", 0, e.hd(S_JUMPS), patch)
        e.st(1, e.hd(S_COUNT))
        e.st(2, e.hd(S_RANGES))
        e.st(3, offsets)
        e.st(0, OK)
        e.give(1)
    return _function((), build, tables)


def build_backend_program():
    """``(reader, function)``: the backend program's store and its entry."""
    tables = None
    objects: list = []

    def add(name, made):
        function, items = made
        objects.extend(items)
        _FN[name] = function
        return function

    add("li", _li(tables))
    add("frame", _frame_access(tables))
    add("read", _read(tables))
    add("write", _write(tables))
    add("mask", _mask(tables))
    add("epilogue", _epilogue(tables))
    add("edge", _copy_edge(tables))
    add("block", _block(tables))
    compile_function = add("function", _compile_function(tables))
    program = add("program", _program(tables, compile_function))
    return program_store(program, x86_64_linux_exec_target(), tuple(objects)), program


def load_backend_program():
    from xax_compiler import Kind, StoreReader, verify_store

    if not STORE_PATH.exists():
        return build_backend_program()
    reader = StoreReader(STORE_PATH.read_bytes())
    verify_store(reader)
    module = next(item for item in reader.objects() if item.kind == Kind.MODULE)
    function = next(reader.get(cid) for cid in module.references if reader.get(cid).kind == Kind.FUNCTION)
    return reader, function


def write_backend_store() -> bytes:
    import xax_compiler

    building = xax_compiler._TYPING_BUILDING
    xax_compiler._TYPING_BUILDING = True  # the helper graphs are verified by the bootstrap while it is built
    try:
        reader, _function = build_backend_program()
        STORE_PATH.write_bytes(reader.data)
    finally:
        xax_compiler._TYPING_BUILDING = building
    return reader.data


def _native_image() -> tuple[bytes, int]:
    """``(machine code, entry offset)``, cached on disk like the typing program's (ADR-138)."""
    import hashlib
    import tempfile

    from xax_compiler import Kind
    from xax_x86_64 import compile_native

    sources = Path(__file__).resolve().parent
    digest = hashlib.sha256(STORE_PATH.read_bytes() if STORE_PATH.exists() else b"")
    for name in ("xax_compiler.py", "xax_x86_64.py", "xax_x86_64_regalloc.py"):
        digest.update((sources / name).read_bytes())
    cache = Path(os.environ.get("XAX_NATIVE_CACHE", Path.home() / ".cache" / "xax-native"))
    entry = cache / f"riscv64-backend-{digest.hexdigest()}.bin"
    try:
        data = entry.read_bytes()
        return data[8:], int.from_bytes(data[:8], "little")
    except OSError:
        pass
    reader, function = load_backend_program()
    target = next(item for item in reader.objects() if item.kind == Kind.TARGET)
    image = compile_native(reader, function.cid, target.cid)
    try:
        cache.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=cache, delete=False) as handle:
            handle.write(image.entry_offset.to_bytes(8, "little") + image.code)
        os.replace(handle.name, entry)
    except OSError:
        pass
    return image.code, image.entry_offset


class NativeBackend:
    """The XAX backend program, run in-process."""

    def __init__(self) -> None:
        from xax_x86_64 import _SYSV_TO_WIN64_THUNK

        code, entry_offset = _native_image()
        thunk = _SYSV_TO_WIN64_THUNK + bytes(-len(_SYSV_TO_WIN64_THUNK) % 16)
        blob = thunk + code
        self._mapping = mmap.mmap(-1, len(blob), prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
        self._mapping.write(blob)
        base = ctypes.addressof(ctypes.c_char.from_buffer(self._mapping))
        self._call = ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint64, ctypes.c_void_p)(base)
        self._entry = base + len(thunk) + entry_offset
        self._in = (ctypes.c_uint64 * IN_WORDS)()
        self._out = (ctypes.c_uint64 * OUT_WORDS)()
        self._slots = (ctypes.c_uint64 * 4)()
        self._xmm = ctypes.c_uint64()
        self._lock = threading.Lock()

    def compile(self, words: list[int], functions: int):
        """``(code words, function word offsets, node ranges)``, or None when the program declines."""
        if len(words) > IN_WORDS or any(not 0 <= word < 1 << 64 for word in words):
            return None
        with self._lock:
            self._in[: len(words)] = words
            self._slots[0], self._slots[1] = ctypes.addressof(self._in), ctypes.addressof(self._out)
            self._call(self._entry, ctypes.addressof(self._slots), 4, ctypes.addressof(self._xmm))
            out = self._out
            if out[0] != OK:
                return None
            count, ranges, offsets_at = out[1], out[2], out[3]
            code = list(out[WORDS_AT : WORDS_AT + count])
            offsets = list(out[offsets_at : offsets_at + functions])
            flat = list(out[RANGES_AT : RANGES_AT + 5 * ranges])
        return code, offsets, [tuple(flat[k : k + 5]) for k in range(0, len(flat), 5)]


_NATIVE: list = []


def native_backend():
    """The shared native backend, or None where it cannot run."""
    if not _NATIVE:
        usable = (sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")
                  and os.environ.get("XAX_RISCV64_BACKEND_PYTHON") != "1" and STORE_PATH.exists())
        try:
            _NATIVE.append(NativeBackend() if usable else None)
        except (OSError, RuntimeError, ValueError):
            _NATIVE.append(None)
    return _NATIVE[0]
