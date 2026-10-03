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
than eight machine arguments or one machine result, a jump past +-1 MiB) or
where a buffer would overflow.  On a decline the bootstrap backend runs and
raises the exact diagnostic.
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
ZERO, RA, SP, T0, T1, T2, A0, T3 = 0, 1, 2, 5, 6, 7, 10, 28
UNIMP = 0xC0001073
ALLOCATABLE = (9, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27)
ARGUMENT_REGISTERS = 8
SIMPLE = {Operation.ADD_WRAP: (0, 0), Operation.SUB_WRAP: (0x20, 0), Operation.MUL_WRAP: (1, 0),
          Operation.BIT_XOR: (0, 4), Operation.BIT_OR: (0, 6), Operation.BIT_AND: (0, 7)}
# Output regions (word indices of the output view).
WORDS_AT, WORDS_LIMIT = 1 << 20, 4 << 20
JUMPS_AT, JUMPS_LIMIT = 6 << 20, 3 << 20  # 3 words per jump
RANGES_AT, RANGES_LIMIT = 10 << 20, 5 << 20  # 5 words per range
META_AT = 15 << 20  # entry machine parameter and return widths; the function order
ARENA_AT, ARENA_END = 16 << 20, (24 << 20) - 1
STREAM_AT = 24 << 20  # the front end's internal stream (S5a format), read by the code generator
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
        B, entry, V = (e.ld(e.add(p["cursor"], k)) for k in range(3))
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
            count = e.ld(p["at"])
            e.st(e.add(p["params"], b), count)
            e.if_(e.lt(p["max_params"], count), lambda: e.set("max_params", count))
            e.for_("q", 0, count, lambda: (e.st(e.add(p["width"], e.add(p["next_id"], p["q"])), e.ld(e.add(e.add(p["at"], 1), p["q"]))),
                                           _put(e, e.add(p["pmask"], e.mul(b, p["W"])), e.add(p["next_id"], p["q"]))))
            e.set("next_id", e.add(p["next_id"], count))
            e.set("at", e.add(e.add(p["at"], 1), count))
            nodes = e.ld(p["at"])
            e.st(e.add(p["nodes_at"], b), e.add(p["at"], 1))
            e.set("at", e.add(p["at"], 1))

            def node():
                results = e.ld(e.add(p["at"], 1))
                e.for_("q", 0, results, lambda: e.st(e.add(p["width"], e.add(p["next_id"], p["q"])), e.ld(e.add(e.add(p["at"], 2), p["q"]))))
                e.set("next_id", e.add(p["next_id"], results))
                operands_at = e.add(e.add(p["at"], 2), results)
                attributes_at = e.add(e.add(operands_at, 1), e.ld(operands_at))
                e.set("at", e.add(e.add(e.add(attributes_at, 1), e.ld(attributes_at)), 1))

            e.for_("m", 0, nodes, node)
            e.st(e.add(p["term_at"], b), p["at"])
            values = e.ld(e.add(p["at"], 1))
            e.set("at", e.add(e.add(p["at"], 2), e.mul(values, 2)))
            edges = e.ld(p["at"])
            e.set("at", e.add(p["at"], 1))
            e.for_("x", 0, edges, lambda: e.set("at", e.add(e.add(p["at"], 2), e.ld(e.add(p["at"], 1)))))

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
            nodes = e.ld(e.sub(p["na_at"], 1))

            def node():
                e.set("pos", e.add(p["pos"], 1))
                at = p["na_at"]
                results = e.ld(e.add(at, 1))
                operands_at = e.add(e.add(at, 2), results)
                e.for_("q", 0, e.ld(operands_at), lambda: use(p["wb"], e.ld(e.add(e.add(operands_at, 1), p["q"])), p["pos"]))
                e.for_("q", 0, results, lambda: (_put(e, defs, p["vid"]), touch(p["vid"], p["pos"]), e.set("vid", e.add(p["vid"], 1))))
                attributes_at = e.add(e.add(operands_at, 1), e.ld(operands_at))
                e.set("na_at", e.add(e.add(e.add(attributes_at, 1), e.ld(attributes_at)), 1))

            e.for_("m", 0, nodes, node)
            e.set("pos", e.add(p["pos"], 1))
            term = e.ld(e.add(p["term_at"], b))
            values = e.ld(e.add(term, 1))
            e.for_("q", 0, values, lambda: use(p["wb"], e.ld(e.add(e.add(term, 2), p["q"])), p["pos"]))
            e.var("edge_at", e.add(e.add(e.add(term, 2), e.mul(values, 2)), 1))

            def edge():
                at = p["edge_at"]
                arguments = e.ld(e.add(at, 1))
                e.for_("q", 0, arguments, lambda: use(p["wb"], e.ld(e.add(e.add(at, 2), p["q"])), p["pos"]))
                e.set("edge_at", e.add(e.add(at, 2), arguments))

            e.for_("x", 0, e.ld(e.sub(p["edge_at"], 1)), edge)
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
                values = e.ld(e.add(term, 1))
                edges_at = e.add(e.add(term, 2), e.mul(values, 2))

                def word():
                    w = p["w"]
                    e.var("out_word", 0)
                    e.var("e_at", e.add(edges_at, 1))

                    def edge():
                        t = e.ld(p["e_at"])
                        live = e.ld(e.add(e.add(p["lin"], e.mul(t, p["W"])), w))
                        own = e.ld(e.add(e.add(p["pmask"], e.mul(t, p["W"])), w))
                        e.set("out_word", e.or_(p["out_word"], e.and_(live, _xor(e, own, (1 << 64) - 1))))
                        e.set("e_at", e.add(e.add(p["e_at"], 2), e.ld(e.add(p["e_at"], 1))))

                    e.for_("x", 0, e.ld(edges_at), edge)
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
        target, count = e.ld(at), e.ld(e.add(at, 1))
        base = p["target_base"]
        moves = e.alloc(e.add(e.mul(count, 2), 1))
        _ok(e, e.ne(moves, NONE))
        e.var("moves_n", 0)

        def collect():
            destination, argument = e.add(base, p["q"]), e.ld(e.add(e.add(at, 2), p["q"]))
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
                    e.var("arg", 0)
                    e.for_("q", 0, operands, lambda: e.if_(e.ne(_value(e, S_WIDTH, operand(p["q"])), 0), lambda: (
                        _ok(e, e.lt(p["arg"], ARGUMENT_REGISTERS)), _read_into(e, operand(p["q"]), e.add(A0, p["arg"])), e.set("arg", e.add(p["arg"], 1)))))
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
            e.for_("q", 0, values, lambda: e.if_(e.ne(flag(p["q"]), 0), lambda: (
                _ok(e, e.eq(p["machine"], 0)), _read_into(e, value(p["q"]), A0), e.set("machine", 1))))
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



# -- S5b: the front end (store objects and graph-decoder streams to the internal stream) -------------
#
# Input view: ``O, entry object, target object``, then per object ``[kind, reference count, reference object
# indices (NONE: not listed), CID as four big-endian words, payload length, payload]``.  The payload is the body,
# one byte per word, for types, constants, functions, and targets; a graph fragment's is the S3c graph-decoder
# stream (``xax_selfhost_graph``); other kinds have none.

GLOBALS = ARENA_AT  # the front end's table pointers (the first arena words)
(G_REC, G_PAY, G_TW, G_FIDX, G_ERASED, G_IFACE, G_SUP, G_SUPT, G_NI, G_O, G_ORDER, G_F, G_OUT, G_WIDTHS, G_FAR) = range(15)
NI_OP, NI_ENTITY, NI_OPERANDS, NI_RESULTS, NI_ATTRIBUTES = range(5)
ENTITY_CODES = (5, 6, 30, 41, 42, 43)
ATTRIBUTE_CODES = (7, 8, 9, 10, 11, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 48, 52, 53, 55, 56, 57,
                   61, 63, 64, 65, 66, 73, 74, 75, 76)


def _g(e: E, slot: int):
    return e.ld(GLOBALS + slot)


def _at(e: E, table: int, index):
    return e.ld(e.add(_g(e, table), index))


def _reference(e: E, obj, k):
    """Object index of ``obj``'s ``k``-th reference (NONE when that object is not listed)."""
    return e.rd(e.add(e.add(_at(e, G_REC, obj), 2), k))


def _kind(e: E, obj):
    return e.rd(_at(e, G_REC, obj))


def _in_set(e: E, value, codes):
    return e.either(*(e.eq(value, code) for code in codes))


def _payload_uleb(e: E, name: str):
    """Read a ULEB at input word ``p[name]`` (one byte per word) and advance it."""
    from xax_selfhost_facts import _uleb

    p = e.p
    value, size, ok = _uleb(e, p[name])
    _ok(e, ok)
    e.set(name, e.add(p[name], size))
    return value


def _node_info(tables):
    """Graph-decoder node record at ``at``: fields into the NI scratch words; returns the next record."""
    def build(e: E):
        p = e.p
        ni = _g(e, G_NI)
        e.var("at", p["at"])
        operation = e.rd(p["at"])
        e.st(e.add(ni, NI_OP), operation)
        e.set("at", e.add(p["at"], 1))
        e.if_(e.eq(operation, int(Operation.CALL_GROUP_MEMBER)), lambda: e.set("at", e.add(p["at"], 3)))
        e.st(e.add(ni, NI_ENTITY), NONE)
        e.if_(_in_set(e, operation, ENTITY_CODES), lambda: (e.st(e.add(ni, NI_ENTITY), e.rd(p["at"])), e.set("at", e.add(p["at"], 1))))
        e.st(e.add(ni, NI_OPERANDS), p["at"])
        count = e.rd(p["at"])
        e.set("at", e.add(p["at"], 1))
        e.for_("q", 0, count, lambda: e.set("at", e.add(e.add(p["at"], 3), e.flag(e.eq(e.rd(p["at"]), 1)))))
        e.st(e.add(ni, NI_RESULTS), p["at"])
        e.set("at", e.add(e.add(p["at"], 1), e.rd(p["at"])))
        e.st(e.add(ni, NI_ATTRIBUTES), NONE)
        e.if_(_in_set(e, operation, ATTRIBUTE_CODES), lambda: (e.st(e.add(ni, NI_ATTRIBUTES), p["at"]), e.set("at", e.add(e.add(p["at"], 1), e.rd(p["at"])))))
        e.give(p["at"])
    return _function(("at",), build, tables)


def _skip_values(e: E, name: str):
    """Advance ``p[name]`` past ``[count, values]``."""
    p = e.p
    count = e.rd(p[name])
    e.set(name, e.add(p[name], 1))
    e.for_("sv", 0, count, lambda: e.set(name, e.add(e.add(p[name], 3), e.flag(e.eq(e.rd(p[name]), 1)))))


def _term_end(tables):
    """The position after the terminator at ``at``."""
    def build(e: E):
        p = e.p
        kind = e.rd(p["at"])
        e.var("at", e.add(p["at"], 1))

        def edge():
            e.set("at", e.add(p["at"], 1))
            _skip_values(e, "at")

        def conditional():
            e.set("at", e.add(e.add(p["at"], 3), e.flag(e.eq(e.rd(p["at"]), 1))))
            edge()
            edge()

        e.if_(e.eq(kind, 1), edge, lambda: e.if_(e.eq(kind, 2), conditional, lambda: e.if_(
            e.eq(kind, 3), lambda: _skip_values(e, "at"), lambda: e.set("at", e.add(p["at"], 2)))))
        e.give(p["at"])
    return _function(("at",), build, tables)


def _type_width(e: E, obj):
    """``_machine_width``: bits width <= 64, 0 for a proof value (effect or resource), else NONE."""
    from xax_compiler import Kind

    p = e.p
    e.var("tw", NONE)

    def typed():
        pay = _at(e, G_PAY, obj)
        first = e.rd(pay)
        e.if_(e.either(e.eq(first, 3), e.eq(first, 4)), lambda: e.set("tw", 0))
        e.if_(e.eq(first, 2), lambda: e.set("tw", 64))  # views profile: a pointer is one 64-bit address

        def bits():
            e.var("tw_at", e.add(pay, 1))
            width = _payload_uleb(e, "tw_at")
            e.if_(e.both(e.ne(width, 0), e.le(width, 64)), lambda: e.set("tw", width))

        e.if_(e.eq(first, 1), bits)

    known = e.lt(obj, _g(e, G_O))
    listed = e.sel(known, obj, 0)
    nonempty = e.ne(e.rd(e.sub(_at(e, G_PAY, listed), 1)), 0)
    e.if_(e.both(known, e.eq(_kind(e, listed), int(Kind.TYPE)), nonempty), typed)
    return p["tw"]


def _interface(tables):
    """``_decode_function_interface`` of a verified function: ``[graph, P, types, R, types]`` (cached); NONE for a
    group member or an unlisted graph."""
    from xax_compiler import Kind

    def build(e: E):
        p = e.p
        f = p["f"]
        cached = _at(e, G_IFACE, f)
        e.if_(e.ne(cached, NONE), lambda: e.give(cached))
        _ok(e, e.eq(_kind(e, f), int(Kind.FUNCTION)))
        e.var("ia", _at(e, G_PAY, f))
        graph = _reference(e, f, _payload_uleb(e, "ia"))
        e.var("graph", graph)
        _ok(e, e.both(e.ne(p["graph"], NONE), e.eq(_kind(e, p["graph"]), int(Kind.GRAPH_FRAGMENT))))
        params = _payload_uleb(e, "ia")
        e.var("np", params)
        e.var("record", e.alloc(e.add(p["np"], 2)))
        _ok(e, e.ne(p["record"], NONE))
        e.st(p["record"], p["graph"])
        e.st(e.add(p["record"], 1), p["np"])
        e.for_("q", 0, p["np"], lambda: e.st(e.add(e.add(p["record"], 2), p["q"]), _reference(e, f, _payload_uleb(e, "ia"))))
        returns = _payload_uleb(e, "ia")
        e.var("nr", returns)
        e.var("rec2", e.alloc(e.add(p["nr"], 1)))
        _ok(e, e.both(e.ne(p["rec2"], NONE), e.eq(p["rec2"], e.add(e.add(p["record"], 2), p["np"]))))  # contiguous
        e.st(p["rec2"], p["nr"])
        e.for_("q", 0, p["nr"], lambda: e.st(e.add(e.add(p["rec2"], 1), p["q"]), _reference(e, f, _payload_uleb(e, "ia"))))
        e.st(e.add(_g(e, G_IFACE), f), p["record"])
        e.give(p["record"])
    return _function(("f",), build, tables)


def _erased(tables):
    """``_is_erased_proof_function``: proof-only interface and one block of resource/effect nodes returning."""
    def build(e: E):
        p = e.p
        f = p["f"]
        cached = _at(e, G_ERASED, f)
        e.if_(e.ne(cached, NONE), lambda: e.give(cached))
        iface = _call(e, "interface", f)
        e.var("erased", 1)
        params = e.ld(e.add(iface, 1))
        returns_at = e.add(e.add(iface, 2), params)
        e.for_("q", 0, params, lambda: e.if_(e.ne(_type_width(e, e.ld(e.add(e.add(iface, 2), p["q"]))), 0), lambda: e.set("erased", 0)))
        e.for_("q", 0, e.ld(returns_at), lambda: e.if_(e.ne(_type_width(e, e.ld(e.add(e.add(returns_at, 1), p["q"]))), 0), lambda: e.set("erased", 0)))

        def shape():
            stream = _at(e, G_PAY, e.ld(iface))
            e.if_(e.ne(e.rd(stream), 1), lambda: e.set("erased", 0))

            def one_block():
                e.var("ea", e.add(e.add(stream, 3), e.rd(e.add(stream, 2))))
                nodes = e.rd(p["ea"])
                e.set("ea", e.add(p["ea"], 1))

                def node():
                    e.set("ea", _call(e, "node_info", p["ea"]))
                    e.if_(e.not_(_in_set(e, e.ld(e.add(_g(e, G_NI), NI_OP)), tuple(int(op) for op in RESOURCE_EFFECT_OPERATIONS))), lambda: e.set("erased", 0))

                e.for_("m", 0, nodes, node)
                e.if_(e.ne(e.rd(p["ea"]), int(TerminatorKind.RETURN)), lambda: e.set("erased", 0))

            e.if_(e.ne(p["erased"], 0), one_block)

        e.if_(e.ne(p["erased"], 0), shape)
        e.st(e.add(_g(e, G_ERASED), f), p["erased"])
        e.give(p["erased"])
    return _function(("f",), build, tables)


def _type_form(e: E, obj):
    """The first payload byte of listed, nonempty TYPE ``obj`` (NONE otherwise)."""
    from xax_compiler import Kind

    known = e.lt(obj, _g(e, G_O))
    listed = e.sel(known, obj, 0)
    pay = _at(e, G_PAY, listed)
    typed = e.both(known, e.eq(_kind(e, listed), int(Kind.TYPE)), e.ne(e.rd(e.sub(pay, 1)), 0))
    return e.sel(typed, e.rd(e.sel(typed, pay, 0)), NONE)


def _view_extent(e: E, obj):
    """``_heap_view_info``: the instance (extent) of heap-view type ``obj``; 0 when it is not a heap view."""
    p = e.p
    e.var("vx", 0)

    def resource():
        pay = _at(e, G_PAY, obj)
        e.var("vx_at", e.add(pay, 1))
        e.var("vx_end", e.add(pay, e.rd(e.sub(pay, 1))))
        kind = _payload_uleb(e, "vx_at")
        e.var("vx_kind", kind)
        state = _payload_uleb(e, "vx_at")
        e.var("vx_state", state)

        def described():
            _payload_uleb(e, "vx_at")  # flags
            instance = _payload_uleb(e, "vx_at")
            e.if_(e.both(e.eq(p["vx_kind"], 0x101), e.either(e.eq(p["vx_state"], 1), e.eq(p["vx_state"], 2))), lambda: e.set("vx", instance))

        e.if_(e.lt(p["vx_at"], p["vx_end"]), described)

    e.if_(e.eq(_type_form(e, obj), 4), resource)
    return p["vx"]


def _borrowed(tables):
    """``borrowed_view_returns`` of function ``f``: ``R`` words, return position -> parameter position (NONE when the
    return stays a machine value)."""
    def build(e: E):
        p = e.p
        iface = _call(e, "interface", p["f"])
        e.var("bi", iface)
        e.var("bnp", e.ld(e.add(p["bi"], 1)))
        e.var("brt", e.add(e.add(p["bi"], 2), p["bnp"]))
        e.var("bnr", e.ld(p["brt"]))
        e.var("bout", e.alloc(e.add(e.add(p["bnr"], p["bnp"]), 1)))
        _ok(e, e.ne(p["bout"], NONE))
        e.var("bused", e.add(p["bout"], p["bnr"]))
        e.for_("q", 0, p["bnr"], lambda: e.st(e.add(p["bout"], p["q"]), NONE))
        e.for_("q", 0, p["bnp"], lambda: e.st(e.add(p["bused"], p["q"]), 0))
        e.var("bmachine", 0)
        e.for_("q", 0, p["bnr"], lambda: e.if_(e.ne(_type_width(e, e.ld(e.add(e.add(p["brt"], 1), p["q"]))), 0),
                                              lambda: e.set("bmachine", e.add(p["bmachine"], 1))))
        e.var("bfound", 0)
        e.var("btype", 0)

        def pair():
            def returned():
                e.set("btype", e.ld(e.add(e.add(p["brt"], 1), p["r"])))

                def view():
                    e.set("bfound", 0)

                    def match():
                        e.st(e.add(p["bused"], p["j"]), 1)
                        e.st(e.add(p["bout"], e.sub(p["r"], 1)), e.sub(p["j"], 1))
                        e.set("bfound", 1)

                    e.for_("j", 1, p["bnp"], lambda: e.if_(e.both(e.eq(p["bfound"], 0), e.eq(e.ld(e.add(p["bused"], p["j"])), 0),
                                                                  e.eq(e.ld(e.add(e.add(p["bi"], 2), p["j"])), p["btype"])), match))

                e.if_(e.ne(_view_extent(e, p["btype"]), 0), view)

            e.for_("r", 1, p["bnr"], returned)

        e.if_(e.lt(1, p["bmachine"]), pair)
        e.give(p["bout"])
    return _function(("f",), build, tables)


def _emit_out(e: E, value):
    at = _g(e, G_OUT)
    e.st(at, value)
    e.st(GLOBALS + G_OUT, e.add(at, 1))


def _translate(tables):
    """One closure function into the internal stream (the S5a format) at ``G_OUT``."""
    from xax_compiler import Kind

    def build(e: E):
        p = e.p
        f = p["f"]
        iface = _call(e, "interface", f)
        graph = e.ld(iface)
        e.var("graph", graph)
        stream = _at(e, G_PAY, graph)
        B, entry = e.rd(stream), e.rd(e.add(stream, 1))
        e.var("B", B)
        # Pass A: value bases per block and per node.
        e.var("base", e.alloc(e.add(B, 1)))
        e.var("first", e.alloc(e.add(B, 1)))
        e.var("node_base", e.alloc(e.add(e.rd(e.sub(_at(e, G_PAY, graph), 1)), 1)))  # at most one node per stream word
        _ok(e, e.both(e.ne(p["base"], NONE), e.ne(p["first"], NONE), e.ne(p["node_base"], NONE)))
        e.var("pa", e.add(stream, 2))
        e.var("id", 0)
        e.var("nodes", 0)

        def block_a():
            b = p["b"]
            e.st(e.add(p["base"], b), p["id"])
            params = e.rd(p["pa"])
            e.set("id", e.add(p["id"], params))
            e.set("pa", e.add(e.add(p["pa"], 1), params))
            count = e.rd(p["pa"])
            e.set("pa", e.add(p["pa"], 1))
            e.st(e.add(p["first"], b), p["nodes"])

            def node():
                e.st(e.add(p["node_base"], p["nodes"]), p["id"])
                e.set("pa", _call(e, "node_info", p["pa"]))
                e.set("id", e.add(p["id"], e.rd(e.ld(e.add(_g(e, G_NI), NI_RESULTS)))))
                e.set("nodes", e.add(p["nodes"], 1))

            e.for_("m", 0, count, node)
            e.set("pa", _call(e, "term_end", p["pa"]))

        e.for_("b", 0, B, block_a)
        _emit_out(e, B)
        _emit_out(e, entry)
        _emit_out(e, p["id"])

        def width_of(reference):
            width = _type_width(e, _reference(e, p["graph"], reference))
            _ok(e, e.ne(width, NONE))
            return width

        def raw_value_id(name: str):
            """The value at ``p[name]`` as a value id; advances past it."""
            at = p[name]
            tag, block, index = e.rd(at), e.rd(e.add(at, 1)), e.rd(e.add(at, 2))
            e.var("vid_out", e.add(e.ld(e.add(p["base"], block)), index))
            e.if_(e.eq(tag, 1), lambda: e.set("vid_out", e.add(e.ld(e.add(p["node_base"], e.add(e.ld(e.add(p["first"], block)), index))), e.rd(e.add(at, 3)))))
            e.set(name, e.add(e.add(at, 3), e.flag(e.eq(tag, 1))))
            return p["vid_out"]

        # Pass A2 (views profile, ADR-145): pointer extents from the following heap-view type, and each borrowed view a
        # direct call gives back aliased to the pointer passed in (``_pointer_extents``, ``_rewrite_borrowed_views``).
        e.var("ext", e.alloc(e.add(p["id"], 1)))
        e.var("alias", e.alloc(e.add(p["id"], 1)))
        _ok(e, e.both(e.ne(p["ext"], NONE), e.ne(p["alias"], NONE)))
        e.for_("q", 0, p["id"], lambda: (e.st(e.add(p["ext"], p["q"]), 0), e.st(e.add(p["alias"], p["q"]), NONE)))

        def scan(types_at, count, first_id):
            """Extents of ``count`` types at input ``types_at`` whose values start at id ``first_id``."""
            e.var("sc_at", types_at)
            e.var("sc_id", first_id)

            def pair():
                extent = _view_extent(e, _reference(e, p["graph"], e.rd(e.add(e.add(p["sc_at"], p["k"]), 1))))
                e.var("sc_ext", extent)
                pointer = e.eq(_type_form(e, _reference(e, p["graph"], e.rd(e.add(p["sc_at"], p["k"])))), 2)
                e.if_(e.both(e.ne(p["sc_ext"], 0), pointer), lambda: e.st(e.add(p["ext"], e.add(p["sc_id"], p["k"])), p["sc_ext"]))

            e.for_("k", 0, e.sub(e.add(count, e.flag(e.eq(count, 0))), 1), pair)

        e.set("pa", e.add(stream, 2))
        e.set("nodes", 0)

        def block_a2():
            params = e.rd(p["pa"])
            scan(e.add(p["pa"], 1), params, e.ld(e.add(p["base"], p["b"])))
            e.set("pa", e.add(e.add(p["pa"], 1), e.rd(p["pa"])))
            count = e.rd(p["pa"])
            e.set("pa", e.add(p["pa"], 1))

            def node():
                e.set("pa", _call(e, "node_info", p["pa"]))
                ni = _g(e, G_NI)
                e.var("a2_op", e.ld(e.add(ni, NI_OP)))
                e.var("a2_entity", e.ld(e.add(ni, NI_ENTITY)))
                e.var("a2_ops", e.ld(e.add(ni, NI_OPERANDS)))
                e.var("a2_results", e.ld(e.add(ni, NI_RESULTS)))
                e.var("a2_id", e.ld(e.add(p["node_base"], p["nodes"])))
                scan(e.add(p["a2_results"], 1), e.rd(p["a2_results"]), p["a2_id"])

                def call():
                    e.var("a2_callee", _reference(e, p["graph"], p["a2_entity"]))
                    _ok(e, e.ne(p["a2_callee"], NONE))

                    def kept():
                        e.var("a2_map", _call(e, "borrowed", p["a2_callee"]))

                        def aliased():
                            e.var("a2_at", e.add(p["a2_ops"], 1))
                            e.for_("j", 0, e.ld(e.add(p["a2_map"], p["r"])), lambda: raw_value_id("a2_at"))
                            e.st(e.add(p["alias"], e.add(p["a2_id"], p["r"])), raw_value_id("a2_at"))

                        e.for_("r", 0, e.rd(p["a2_results"]), lambda: e.if_(e.ne(e.ld(e.add(p["a2_map"], p["r"])), NONE), aliased))

                    e.if_(e.eq(_call(e, "erased", p["a2_callee"]), 0), kept)

                e.if_(e.eq(p["a2_op"], int(Operation.CALL_DIRECT)), call)
                e.set("nodes", e.add(p["nodes"], 1))

            e.for_("m", 0, count, node)
            e.set("pa", _call(e, "term_end", p["pa"]))

        e.for_("b", 0, B, block_a2)

        def value_id(name: str):
            """``raw_value_id`` through the borrowed-view aliases."""
            e.var("vid_c", raw_value_id(name))
            e.while_(lambda: e.ne(e.ld(e.add(p["alias"], p["vid_c"])), NONE), lambda: e.set("vid_c", e.ld(e.add(p["alias"], p["vid_c"]))))
            return p["vid_c"]

        def values(name: str, emit=True):
            count = e.rd(p[name])
            e.set(name, e.add(p[name], 1))
            if emit:
                _emit_out(e, count)
            e.for_("vv", 0, count, lambda: _emit_out(e, value_id(name)))
            return count

        # Pass B: the stream.
        e.set("pa", e.add(stream, 2))
        e.set("nodes", 0)
        e.var("own", _call(e, "borrowed", f))
        returns_at = e.add(e.add(iface, 2), e.ld(e.add(iface, 1)))

        def block_b():
            params = e.rd(p["pa"])
            _emit_out(e, params)
            e.for_("q", 0, params, lambda: _emit_out(e, width_of(e.rd(e.add(e.add(p["pa"], 1), p["q"])))))
            e.set("pa", e.add(e.add(p["pa"], 1), params))
            count = e.rd(p["pa"])
            e.set("pa", e.add(p["pa"], 1))
            _emit_out(e, count)

            def node():
                e.var("next_node", _call(e, "node_info", p["pa"]))
                ni = _g(e, G_NI)
                operation, entity = e.ld(e.add(ni, NI_OP)), e.ld(e.add(ni, NI_ENTITY))
                results_at, attributes_at = e.ld(e.add(ni, NI_RESULTS)), e.ld(e.add(ni, NI_ATTRIBUTES))
                e.var("na_ops", e.ld(e.add(ni, NI_OPERANDS)))
                _emit_out(e, operation)
                results = e.rd(results_at)
                _emit_out(e, results)
                e.var("nb_id", e.ld(e.add(p["node_base"], p["nodes"])))
                e.var("nb_results", results_at)
                e.for_("q", 0, results, lambda: e.if_(e.ne(e.ld(e.add(p["alias"], e.add(p["nb_id"], p["q"]))), NONE), lambda: _emit_out(e, 0),
                                                      lambda: _emit_out(e, width_of(e.rd(e.add(e.add(p["nb_results"], 1), p["q"]))))))
                e.var("op0_at", e.add(p["na_ops"], 1))
                e.var("op0", NONE)
                e.if_(e.ne(e.rd(p["na_ops"]), 0), lambda: e.set("op0", value_id("op0_at")))
                values("na_ops")
                e.if_(e.eq(attributes_at, NONE), lambda: _emit_out(e, 0), lambda: (
                    _emit_out(e, e.rd(attributes_at)), e.for_("q", 0, e.rd(attributes_at), lambda: _emit_out(e, e.rd(e.add(e.add(attributes_at, 1), p["q"]))))))
                e.var("extra", 0)

                def constant():
                    obj = _reference(e, p["graph"], entity)
                    _ok(e, e.both(e.ne(obj, NONE), e.eq(_kind(e, obj), int(Kind.CONSTANT))))
                    e.var("ca", _at(e, G_PAY, obj))
                    _payload_uleb(e, "ca")
                    length = _payload_uleb(e, "ca")
                    e.var("clen", length)
                    _ok(e, e.le(p["clen"], 8))
                    e.var("factor", 1)
                    e.for_("q", 0, p["clen"], lambda: (e.set("extra", e.add(p["extra"], e.mul(e.rd(e.add(p["ca"], p["q"])), p["factor"]))),
                                                       e.set("factor", e.mul(p["factor"], 256))))

                def call():
                    callee = _reference(e, p["graph"], entity)
                    e.var("callee", callee)
                    _ok(e, e.ne(p["callee"], NONE))
                    erased = _call(e, "erased", p["callee"])
                    e.if_(e.ne(erased, 0), lambda: e.set("extra", NONE), lambda: (
                        _ok(e, e.ne(_at(e, G_FIDX, p["callee"]), NONE)), e.set("extra", _at(e, G_FIDX, p["callee"]))))

                def checked():
                    known = e.ne(p["op0"], NONE)
                    extent = e.ld(e.add(p["ext"], e.sel(known, p["op0"], 0)))
                    e.set("extra", e.sel(e.both(known, e.ne(extent, 0)), extent, NONE))

                e.if_(e.eq(operation, int(Operation.CONSTANT)), constant, lambda: e.if_(e.eq(operation, int(Operation.CALL_DIRECT)), call, lambda: e.if_(
                    e.either(e.eq(operation, int(Operation.CHECKED_LOAD_BITS_LE)), e.eq(operation, int(Operation.CHECKED_STORE_BITS_LE))), checked)))
                _emit_out(e, p["extra"])
                e.set("pa", p["next_node"])
                e.set("nodes", e.add(p["nodes"], 1))

            e.for_("m", 0, count, node)
            kind = e.rd(p["pa"])
            e.var("tk", kind)
            e.set("pa", e.add(p["pa"], 1))
            _emit_out(e, kind)

            def edge_out():
                _emit_out(e, e.rd(p["pa"]))
                e.set("pa", e.add(p["pa"], 1))
                values("pa")

            def branch():
                _emit_out(e, 0)
                _emit_out(e, 1)
                edge_out()

            def conditional():
                _emit_out(e, 1)
                _emit_out(e, value_id("pa"))
                _emit_out(e, 0)
                _emit_out(e, 2)
                edge_out()
                edge_out()

            def returns():
                count = e.rd(p["pa"])
                e.var("rc", count)
                e.set("pa", e.add(p["pa"], 1))
                _emit_out(e, p["rc"])
                e.var("rv_at", p["pa"])
                e.for_("vv", 0, p["rc"], lambda: _emit_out(e, value_id("pa")))
                def flag():
                    declared = e.lt(p["q"], e.ld(returns_at))
                    position = e.sel(declared, p["q"], 0)
                    machine = e.both(declared, e.ne(_type_width(e, e.ld(e.add(e.add(returns_at, 1), position))), 0),
                                     e.eq(e.ld(e.add(p["own"], position)), NONE))  # an elided borrowed view is no machine value
                    _emit_out(e, e.flag(machine))

                e.for_("q", 0, p["rc"], flag)
                _emit_out(e, 0)

            def trap():
                e.set("pa", e.add(p["pa"], 2))
                _emit_out(e, 0)
                _emit_out(e, 0)

            e.if_(e.eq(kind, 1), branch, lambda: e.if_(e.eq(kind, 2), conditional, lambda: e.if_(e.eq(kind, 3), returns, trap)))

        e.for_("b", 0, B, block_b)
        e.give(1)
    return _function(("f",), build, tables)


def _frontend(tables):
    """The closure, the target's operation sets, the function order, and the internal stream."""
    from xax_compiler import Kind, RISCV64_ARCHITECTURE

    def build(e: E):
        p = e.p
        O = e.rd(0)
        e.st(GLOBALS + G_O, O)
        for slot in (G_REC, G_PAY, G_TW, G_FIDX, G_ERASED, G_IFACE, G_ORDER):
            table = e.alloc(e.add(O, 1))
            _ok(e, e.ne(table, NONE))
            e.st(GLOBALS + slot, table)
        for slot, size in ((G_SUP, 256), (G_SUPT, 8), (G_NI, 8)):
            table = e.alloc(size)
            _ok(e, e.ne(table, NONE))
            e.st(GLOBALS + slot, table)
            e.for_("q", 0, size, lambda table=table: e.st(e.add(table, p["q"]), 0))
        e.var("ra", 3)

        def record():
            o = p["o"]
            e.st(e.add(_g(e, G_REC), o), p["ra"])
            references = e.rd(e.add(p["ra"], 1))
            payload_at = e.add(e.add(e.add(p["ra"], 2), references), 4)
            e.st(e.add(_g(e, G_PAY), o), e.add(payload_at, 1))
            for slot in (G_FIDX, G_ERASED, G_IFACE):
                e.st(e.add(_g(e, slot), o), NONE)
            e.set("ra", e.add(e.add(payload_at, 1), e.rd(payload_at)))

        e.for_("o", 0, O, record)
        _ok(e, e.le(p["ra"], IN_WORDS))
        entry, target = e.rd(1), e.rd(2)
        e.var("entry", entry)
        _ok(e, e.both(e.lt(p["entry"], O), e.eq(_kind(e, p["entry"]), int(Kind.FUNCTION)), e.lt(target, O)))
        # The target's operation and terminator sets (a verified RISC-V package).
        e.var("ta", _at(e, G_PAY, target))
        identity = _payload_uleb(e, "ta")
        e.set("ta", e.add(p["ta"], identity))
        fields = [_payload_uleb(e, "ta") for _ in range(6)]
        e.var("arch", fields[1])
        _ok(e, e.eq(p["arch"], RISCV64_ARCHITECTURE))
        for table in (G_SUP, G_SUPT):
            count = _payload_uleb(e, "ta")
            e.var("tcount", count)
            e.for_("q", 0, p["tcount"], lambda table=table: (lambda value: (_ok(e, e.lt(value, 256 if table == G_SUP else 8)), e.st(e.add(_g(e, table), value), 1)))(
                _payload_uleb(e, "ta")))
        e.st(GLOBALS + G_FAR, _at(e, G_SUP, int(Operation.CHECKED_LOAD_BITS_LE)))  # views profile: far jumps
        # The closure from the entry (callees that are not erased proof functions).
        work = e.alloc(e.add(O, 1))
        _ok(e, e.ne(work, NONE))
        e.var("work", work)
        e.var("wn", 1)
        e.st(p["work"], p["entry"])
        e.var("members", 0)
        visited = _g(e, G_TW)  # reused as visited flags
        e.for_("o", 0, O, lambda: e.st(e.add(visited, p["o"]), 0))

        def visit():
            e.set("wn", e.sub(p["wn"], 1))
            f = e.ld(e.add(p["work"], p["wn"]))
            e.var("cf", f)

            def fresh():
                e.st(e.add(visited, p["cf"]), 1)
                e.st(e.add(_g(e, G_ORDER), p["members"]), p["cf"])
                e.set("members", e.add(p["members"], 1))
                iface = _call(e, "interface", p["cf"])
                e.var("cg", e.ld(iface))
                stream = _at(e, G_PAY, p["cg"])
                e.var("wa", e.add(stream, 2))

                def block():
                    e.set("wa", e.add(e.add(p["wa"], 1), e.rd(p["wa"])))
                    count = e.rd(p["wa"])
                    e.set("wa", e.add(p["wa"], 1))

                    def node():
                        e.set("wa", _call(e, "node_info", p["wa"]))
                        ni = _g(e, G_NI)
                        operation = e.ld(e.add(ni, NI_OP))
                        _ok(e, e.both(e.lt(operation, 256), e.ne(_at(e, G_SUP, e.sel(e.lt(operation, 256), operation, 0)), 0)))

                        def callee():
                            e.var("cc", _reference(e, p["cg"], e.ld(e.add(ni, NI_ENTITY))))
                            _ok(e, e.both(e.ne(p["cc"], NONE), e.eq(_kind(e, p["cc"]), int(Kind.FUNCTION))))
                            e.if_(e.both(e.eq(_call(e, "erased", p["cc"]), 0), e.eq(e.ld(e.add(visited, p["cc"])), 0)), lambda: (
                                e.st(e.add(p["work"], p["wn"]), p["cc"]), e.set("wn", e.add(p["wn"], 1)), _ok(e, e.le(p["wn"], O))))

                        e.if_(e.eq(operation, int(Operation.CALL_DIRECT)), callee)

                    e.for_("m", 0, count, node)
                    kind = e.rd(p["wa"])
                    _ok(e, e.both(e.lt(kind, 8), e.ne(_at(e, G_SUPT, e.sel(e.lt(kind, 8), kind, 0)), 0)))
                    e.set("wa", _call(e, "term_end", p["wa"]))

                e.for_("b", 0, e.rd(stream), block)

            e.if_(e.eq(e.ld(e.add(visited, p["cf"])), 0), fresh)

        e.while_(lambda: e.ne(p["wn"], 0), visit)
        # Order: the entry, then the others by CID.
        order = _g(e, G_ORDER)
        e.for_("q", 0, p["members"], lambda: e.if_(e.eq(e.ld(e.add(order, p["q"])), p["entry"]), lambda: (
            e.st(e.add(order, p["q"]), e.ld(order)), e.st(order, p["entry"]))))

        def cid_before(x, y):
            def word(obj, k):
                record = _at(e, G_REC, obj)
                return e.rd(e.add(e.add(e.add(record, 2), e.rd(e.add(record, 1))), k))
            result = e.c(0)
            equal = e.c(1)
            for k in range(4):
                wx, wy = word(x, k), word(y, k)
                result = e.or_(result, e.flag(e.both(e.ne(equal, 0), e.lt(wx, wy))))
                equal = e.flag(e.both(e.ne(equal, 0), e.eq(wx, wy)))
            return e.ne(result, 0)

        def insert():
            e.var("item", e.ld(e.add(order, p["s"])))
            e.var("j", p["s"])
            e.while_(lambda: e.both(e.lt(1, p["j"]), cid_before(p["item"], e.ld(e.add(order, e.sub(p["j"], 1))))), lambda: (
                e.st(e.add(order, p["j"]), e.ld(e.add(order, e.sub(p["j"], 1)))), e.set("j", e.sub(p["j"], 1))))
            e.st(e.add(order, p["j"]), p["item"])

        e.for_("s", 2, p["members"], insert)
        e.for_("q", 0, p["members"], lambda: e.st(e.add(_g(e, G_FIDX), e.ld(e.add(order, p["q"]))), p["q"]))
        e.st(GLOBALS + G_F, p["members"])
        # The internal stream.
        e.st(GLOBALS + G_OUT, STREAM_AT)
        _emit_out(e, p["members"])
        e.for_("q", 0, p["members"], lambda: _call(e, "translate", e.ld(e.add(order, p["q"]))))
        _ok(e, e.lt(_g(e, G_OUT), STREAM_AT + (7 << 20)))
        # The entry's machine parameter and return widths.
        iface = _call(e, "interface", p["entry"])
        widths = e.alloc(e.add(e.add(e.ld(e.add(iface, 1)), e.ld(e.add(e.add(iface, 2), e.ld(e.add(iface, 1))))), 4))
        _ok(e, e.ne(widths, NONE))
        e.st(GLOBALS + G_WIDTHS, widths)
        e.var("wc", 0)
        e.var("wbase", widths)
        for part in range(2):
            def lists(part=part):
                at = e.add(iface, 1) if part == 0 else e.add(e.add(iface, 2), e.ld(e.add(iface, 1)))
                e.var("wcount_at", p["wc"])
                e.set("wc", e.add(p["wc"], 1))
                e.var("machine", 0)

                def each():
                    width = _type_width(e, e.ld(e.add(e.add(at, 1), p["q"])))
                    e.var("ew", width)
                    _ok(e, e.ne(p["ew"], NONE))
                    e.if_(e.ne(p["ew"], 0), lambda: (e.st(e.add(widths, p["wc"]), p["ew"]), e.set("wc", e.add(p["wc"], 1)), e.set("machine", e.add(p["machine"], 1))))

                e.for_("q", 0, e.ld(at), each)
                e.st(e.add(widths, p["wcount_at"]), p["machine"])

            lists()
        e.give(1)
    return _function((), build, tables)


# -- the program -----------------------------------------------------------------------------------

def _program(tables, compile_function):
    def build(e: E):
        p = e.p
        e.st(0, 0)
        e.set_hd(H_ARENA, ARENA_AT + 64)  # the front end's GLOBALS come first
        e.set_hd(H_ARENA_END, ARENA_END)
        e.set_hd(S_COUNT, 0)
        e.set_hd(S_JUMPS, 0)
        e.set_hd(S_RANGES, 0)
        powers = e.alloc(64)
        e.var("power", 1)
        e.for_("z", 0, 64, lambda: (e.st(e.add(powers, p["z"]), p["power"]), e.set("power", e.mul(p["power"], 2))))
        e.set_hd(S_POW, powers)
        e.set_hd(S_LEVELS, e.alloc(32))
        _ok(e, e.ne(e.call(_FN["frontend"]), NONE))
        functions = e.ld(STREAM_AT)
        offsets = e.alloc(e.add(functions, 1))
        _ok(e, e.ne(offsets, NONE))
        e.set_hd(S_OFFSETS, offsets)
        e.for_("f", 0, functions, lambda: e.st(e.add(offsets, p["f"]), NONE))
        e.var("cursor", STREAM_AT + 1)

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
        e.st(1, e.hd(S_COUNT))
        e.st(2, e.hd(S_RANGES))
        e.st(3, offsets)
        e.st(4, _g(e, G_ORDER))
        e.st(5, _g(e, G_WIDTHS))
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
    add("node_info", _node_info(tables))
    add("term_end", _term_end(tables))
    add("interface", _interface(tables))
    add("erased", _erased(tables))
    add("borrowed", _borrowed(tables))
    add("translate", _translate(tables))
    add("frontend", _frontend(tables))
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

    def compile(self, words: list[int]):
        """``(code words, function order, function word offsets, node ranges, entry parameter widths, entry return
        widths)``, or None when the program declines."""
        if len(words) > IN_WORDS or any(not 0 <= word < 1 << 64 for word in words):
            return None
        with self._lock:
            self._in[: len(words)] = words
            self._slots[0], self._slots[1] = ctypes.addressof(self._in), ctypes.addressof(self._out)
            self._call(self._entry, ctypes.addressof(self._slots), 4, ctypes.addressof(self._xmm))
            out = self._out
            result = collect_output(lambda start, count: list(out[start : start + count]))
        return result




def collect_output(read):
    """The program's result from its output view, read as ``read(start word, count)``: ``(code words, function
    order, function word offsets, node ranges, entry parameter widths, entry return widths)``, or None (declined)."""
    status, count, ranges, offsets_at, order_at, widths_at = read(0, 6)
    if status != OK:
        return None
    (functions,) = read(STREAM_AT, 1)
    code = read(WORDS_AT, count)
    order = read(order_at, functions)
    offsets = read(offsets_at, functions)
    flat = read(RANGES_AT, 5 * ranges)
    (parameters,) = read(widths_at, 1)
    parameter_widths = tuple(read(widths_at + 1, parameters))
    returns_at = widths_at + 1 + parameters
    (returns,) = read(returns_at, 1)
    return_widths = tuple(read(returns_at + 1, returns))
    return code, order, offsets, [tuple(flat[k : k + 5]) for k in range(0, len(flat), 5)], parameter_widths, return_widths


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
