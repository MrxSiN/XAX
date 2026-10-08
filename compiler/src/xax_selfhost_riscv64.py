"""Self-hosting step S1 (ADR-116): the RISC-V instruction encoder as XAX semantics.

The RISC-V backend's instruction encoding (the R/I/S/B/J/U formats) and its
64-bit constant materialization planner (``li``) are one ordinary XAX function,
``encode(kind, a1, a2, a3, a4, a5, a6) -> bits<64>``:

====  =========================================  ===================================
kind  operands                                   result
====  =========================================  ===================================
0     funct7, rs2, rs1, funct3, rd, opcode       R-type word
1     imm, rs1, funct3, rd, opcode               I-type word (imm taken mod 2^12)
2     imm, rs2, rs1, funct3, opcode              S-type word
3     offset, rs2, rs1, funct3                   B-type word (opcode 0x63)
4     offset, rd                                 J-type word (opcode 0x6F)
5     imm20, rd, opcode                          U-type word
6     rd, value, index                           index-th word of ``li rd, value``,
                                                 or 0 past the end of the sequence
====  =========================================  ===================================

Every operand is a ``bits<64>`` holding the two's-complement value; fields
are masked to their width, so the function is total.  ``li`` uses only loops
over block parameters (no memory): one pass sizes the sequence, a second
finds the requested word, so a caller asks for words 0, 1, ... until 0.

The canonical store is committed at ``bootstrap/xax_riscv64_encoder.xax``.
The production RISC-V backend calls this function natively: it is lowered by
the XAX x86-64 backend and called in-process (``NativeEncoder``).  The Python
encoders in ``xax_riscv64`` remain the bootstrap reference and the fallback on
hosts that cannot execute the leaf.  The same graph also compiles to RISC-V and
to the JVM, so one compiler component runs on three targets.
"""

from __future__ import annotations

import ctypes
import mmap
import os
import platform
import sys
from dataclasses import dataclass
from pathlib import Path

from xax_compiler import (
    IntCompare,
    Kind,
    Operation,
    SemanticObject,
    StoreReader,
    bits_type,
    x86_64_linux_exec_target,
)
from xax_graph_builder import BlockBuilder, GraphBuilder, program_store

from xax_native import bootstrap_dir  # noqa: E402

STORE_PATH = bootstrap_dir() / "xax_riscv64_encoder.xax"
B1, B64 = bits_type(1), bits_type(64)
KIND_R, KIND_I, KIND_S, KIND_B, KIND_J, KIND_U, KIND_LI = range(7)
_MASK64 = (1 << 64) - 1


class _Ops:
    """Expression helpers over one block: shifts by constants are exact compositions (ADR-084)."""

    def __init__(self, block: BlockBuilder):
        self.b = block

    def c(self, value: int):
        return self.b.const(B64, value & _MASK64)

    def add(self, x, y):
        return self.b.op1(Operation.ADD_WRAP, (x, y), B64)

    def sub(self, x, y):
        return self.b.op1(Operation.SUB_WRAP, (x, y), B64)

    def mul(self, x, y):
        return self.b.op1(Operation.MUL_WRAP, (x, y), B64)

    def and_(self, x, mask: int):
        return self.b.op1(Operation.BIT_AND, (x, self.c(mask)), B64)

    def or_(self, *values):
        result = values[0]
        for value in values[1:]:
            result = self.b.op1(Operation.BIT_OR, (result, value), B64)
        return result

    def xor(self, x, value: int):
        return self.b.op1(Operation.BIT_XOR, (x, self.c(value)), B64)

    def shl(self, x, amount: int):
        return x if amount == 0 else self.mul(x, self.c(1 << amount))

    def shr(self, x, amount: int):
        return x if amount == 0 else self.b.op1(Operation.UDIV, (x, self.c(1 << amount)), B64)

    def field(self, x, low: int, width: int, at: int):
        """``((x >> low) & (2^width - 1)) << at``."""
        return self.shl(self.and_(self.shr(x, low), (1 << width) - 1), at)

    def compare(self, kind: IntCompare, x, y):
        return self.b.op1(Operation.INT_COMPARE, (x, y), B1, attributes=(kind,))

    def flag(self, kind: IntCompare, x, y):
        return self.b.op1(Operation.INT_ZERO_EXTEND, (self.compare(kind, x, y),), B64)

    def asr(self, x, amount: int, sign_of=None):
        """Arithmetic shift right: the logical shift, plus the sign bits when ``sign_of`` (default x) < 0."""
        negative = self.flag(IntCompare.SLT, x if sign_of is None else sign_of, self.c(0))
        fill = ((1 << amount) - 1) << (64 - amount)
        return self.or_(self.shr(x, amount), self.mul(negative, self.c(fill)))

    def sext(self, x, width: int):
        sign = 1 << (width - 1)
        return self.sub(self.xor(self.and_(x, (1 << width) - 1), sign), self.c(sign))

    def fits(self, x, width: int):
        """1 when x (signed) fits in ``width`` signed bits."""
        return self.compare(IntCompare.ULT, self.add(x, self.c(1 << (width - 1))), self.c(1 << width))

    # Instruction formats (fields masked so the function is total).
    def word_i(self, imm, rs1, funct3, rd, opcode):
        return self.or_(self.field(imm, 0, 12, 20), self.field(rs1, 0, 5, 15), self.field(funct3, 0, 3, 12), self.field(rd, 0, 5, 7), self.and_(opcode, 0x7F))


def build_encoder_program() -> tuple[StoreReader, SemanticObject]:
    """Build the canonical encoder store; returns ``(reader, encode function)``."""
    graph = GraphBuilder()
    entry = graph.block(*(B64,) * 7)
    kind, a1, a2, a3, a4, a5, a6 = entry.params
    formats = [graph.block() for _ in range(6)]
    li_size = graph.block(B64, B64)          # L, pair words so far
    li_step = graph.block(B64, B64)
    li_strip = graph.block(B64, B64)         # H, pair words: drop trailing zeros
    li_strip_body = graph.block(B64, B64)
    li_base = graph.block(B64, B64)          # base value, pair words
    li_base_small = graph.block(B64, B64)
    li_base_large = graph.block(B64, B64)
    li_select = graph.block(B64, B64, B64, B64)  # w0, w1, base length, total length
    li_base_word = graph.block(B64, B64)
    li_walk = graph.block(B64, B64)          # L, end
    li_level = graph.block(B64, B64)
    li_level_strip = graph.block(B64, B64, B64, B64, B64)  # H, shift, low, low words, end
    li_level_strip_body = graph.block(B64, B64, B64, B64, B64)
    li_level_end = graph.block(B64, B64, B64, B64, B64)
    li_level_word = graph.block(B64, B64, B64)  # shift, low, start
    done = graph.block(B64)
    li_check = graph.block(B64)              # total length
    dispatch = [graph.block() for _ in range(5)]

    # Dispatch on kind: a chain of equality tests; kind >= 6 is li.
    current = entry
    for position in range(6):
        ops = _Ops(current)
        is_kind = ops.compare(IntCompare.EQ, kind, ops.c(position))
        if position < 5:
            current.cbr(is_kind, formats[position], (), dispatch[position], ())
            current = dispatch[position]
        else:
            current.cbr(is_kind, formats[5], (), li_size, (a2, ops.c(0)))

    # R: funct7, rs2, rs1, funct3, rd, opcode
    ops = _Ops(formats[0])
    formats[0].br(done, ops.or_(ops.field(a1, 0, 7, 25), ops.field(a2, 0, 5, 20), ops.field(a3, 0, 5, 15), ops.field(a4, 0, 3, 12), ops.field(a5, 0, 5, 7), ops.and_(a6, 0x7F)))
    # I: imm, rs1, funct3, rd, opcode
    ops = _Ops(formats[1])
    formats[1].br(done, ops.word_i(a1, a2, a3, a4, a5))
    # S: imm, rs2, rs1, funct3, opcode
    ops = _Ops(formats[2])
    formats[2].br(done, ops.or_(ops.field(a1, 5, 7, 25), ops.field(a2, 0, 5, 20), ops.field(a3, 0, 5, 15), ops.field(a4, 0, 3, 12), ops.field(a1, 0, 5, 7), ops.and_(a5, 0x7F)))
    # B: offset, rs2, rs1, funct3
    ops = _Ops(formats[3])
    formats[3].br(done, ops.or_(
        ops.field(a1, 12, 1, 31), ops.field(a1, 5, 6, 25), ops.field(a2, 0, 5, 20), ops.field(a3, 0, 5, 15),
        ops.field(a4, 0, 3, 12), ops.field(a1, 1, 4, 8), ops.field(a1, 11, 1, 7), ops.c(0x63),
    ))
    # J: offset, rd
    ops = _Ops(formats[4])
    formats[4].br(done, ops.or_(
        ops.field(a1, 20, 1, 31), ops.field(a1, 1, 10, 21), ops.field(a1, 11, 1, 20), ops.field(a1, 12, 8, 12),
        ops.field(a2, 0, 5, 7), ops.c(0x6F),
    ))
    # U: imm20, rd, opcode
    ops = _Ops(formats[5])
    formats[5].br(done, ops.or_(ops.field(a1, 0, 20, 12), ops.field(a2, 0, 5, 7), ops.and_(a3, 0x7F)))

    # li rd=a1, value=a2, index=a3.  A level L does not fit in 32 bits, so
    # (L - low) has L's sign even when the 64-bit subtraction wraps; the shift
    # takes that sign, matching the exact-integer reference.  Pass 1: walk the levels that do not fit
    # in 32 signed bits, counting their words (slli, plus addi when low != 0).
    rd, index = a1, a3
    level, pair_words = li_size.params
    ops = _Ops(li_size)
    li_size.cbr(ops.fits(level, 32), li_base, (level, pair_words), li_step, (level, pair_words))
    level, pair_words = li_step.params
    ops = _Ops(li_step)
    low = ops.sext(level, 12)
    words = ops.add(ops.add(pair_words, ops.c(1)), ops.flag(IntCompare.NE, low, ops.c(0)))
    li_step.br(li_strip, ops.asr(ops.sub(level, low), 12, sign_of=level), words)
    high, pair_words = li_strip.params
    ops = _Ops(li_strip)
    even = ops.compare(IntCompare.EQ, ops.and_(high, 1), ops.c(0))
    li_strip.cbr(even, li_strip_body, (high, pair_words), li_size, (high, pair_words))
    high, pair_words = li_strip_body.params
    ops = _Ops(li_strip_body)
    li_strip_body.br(li_strip, ops.asr(high, 1), pair_words)

    # Base: addi when it fits in 12 bits, else lui (+ addiw when the low part is nonzero).
    base, pair_words = li_base.params
    ops = _Ops(li_base)
    li_base.cbr(ops.fits(base, 12), li_base_small, (base, pair_words), li_base_large, (base, pair_words))
    base, pair_words = li_base_small.params
    ops = _Ops(li_base_small)
    li_base_small.br(li_select, ops.word_i(base, ops.c(0), ops.c(0), rd, ops.c(0x13)), ops.c(0), ops.c(1), ops.add(pair_words, ops.c(1)))
    base, pair_words = li_base_large.params
    ops = _Ops(li_base_large)
    high20 = ops.and_(ops.shr(ops.add(base, ops.c(0x800)), 12), 0xFFFFF)
    low = ops.sub(base, ops.sext(ops.shl(high20, 12), 32))
    has_low = ops.flag(IntCompare.NE, low, ops.c(0))
    lui = ops.or_(ops.shl(high20, 12), ops.field(rd, 0, 5, 7), ops.c(0x37))
    addiw = ops.word_i(low, rd, ops.c(0), rd, ops.c(0x1B))
    base_words = ops.add(ops.c(1), has_low)
    li_base_large.br(li_select, lui, addiw, base_words, ops.add(pair_words, base_words))

    first, second, base_words, total = li_select.params
    ops = _Ops(li_select)
    li_select.cbr(ops.compare(IntCompare.ULT, index, base_words), li_base_word, (first, second), li_check, (total,))
    (total,) = li_check.params
    ops = _Ops(li_check)
    li_check.cbr(ops.compare(IntCompare.ULT, index, total), li_walk, (a2, total), done, (ops.c(0),))
    first, second = li_base_word.params
    ops = _Ops(li_base_word)
    li_base_word.cbr(ops.compare(IntCompare.EQ, index, ops.c(0)), done, (first,), done, (second,))

    # Pass 2: levels again, outermost first; level t's words end at ``end``.
    level, end = li_walk.params
    ops = _Ops(li_walk)
    li_walk.cbr(ops.fits(level, 32), done, (ops.c(0),), li_level, (level, end))
    level, end = li_level.params
    ops = _Ops(li_level)
    low = ops.sext(level, 12)
    li_level.br(li_level_strip, ops.asr(ops.sub(level, low), 12, sign_of=level), ops.c(12), low, ops.flag(IntCompare.NE, low, ops.c(0)), end)
    high, shift, low, low_words, end = li_level_strip.params
    ops = _Ops(li_level_strip)
    even = ops.compare(IntCompare.EQ, ops.and_(high, 1), ops.c(0))
    li_level_strip.cbr(even, li_level_strip_body, (high, shift, low, low_words, end), li_level_end, (high, shift, low, low_words, end))
    high, shift, low, low_words, end = li_level_strip_body.params
    ops = _Ops(li_level_strip_body)
    li_level_strip_body.br(li_level_strip, ops.asr(high, 1), ops.add(shift, ops.c(1)), low, low_words, end)
    high, shift, low, low_words, end = li_level_end.params
    ops = _Ops(li_level_end)
    start = ops.sub(end, ops.add(ops.c(1), low_words))
    li_level_end.cbr(ops.compare(IntCompare.UGE, index, start), li_level_word, (shift, low, start), li_walk, (high, start))
    shift, low, start = li_level_word.params
    ops = _Ops(li_level_word)
    slli = ops.word_i(shift, rd, ops.c(1), rd, ops.c(0x13))
    addi = ops.word_i(low, rd, ops.c(0), rd, ops.c(0x13))
    li_level_word.cbr(ops.compare(IntCompare.EQ, index, start), done, (slli,), done, (addi,))

    done.ret(done.params[0])
    encode = graph.function((B64,) * 7, (B64,))
    reader = program_store(encode, x86_64_linux_exec_target(), tuple(graph.objects.values()))
    return reader, encode


def load_encoder_program() -> tuple[StoreReader, SemanticObject]:
    """The committed canonical store, verified on load."""
    from xax_native import verify_component_store

    reader = StoreReader(STORE_PATH.read_bytes())
    verify_component_store(reader, "riscv64-encoder")
    module = next(item for item in reader.objects() if item.kind == Kind.MODULE)
    encode = next(reader.get(cid) for cid in module.references if reader.get(cid).kind == Kind.FUNCTION)
    return reader, encode


def write_encoder_store() -> bytes:
    reader, _encode = build_encoder_program()
    data = reader.data
    STORE_PATH.write_bytes(data)
    return data


# ------------------------------------------------------------------ native leaf


@dataclass
class NativeEncoder:
    """The encoder lowered by the XAX x86-64 backend and called in-process.

    The code is mapped once; each call goes through the harness thunk that
    adapts the host's SysV ABI to the image's Win64-style internal convention
    (``xax_x86_64._SYSV_TO_WIN64_THUNK``).  No encoding logic lives outside
    the XAX image.
    """

    code_size: int
    _mapping: mmap.mmap
    _call: object
    _entry: int
    _slots: object
    _xmm: object

    @classmethod
    def load(cls) -> "NativeEncoder":
        from xax_selfhost_x86_64_backend import host_image
        from xax_x86_64 import _SYSV_TO_WIN64_THUNK

        machine_code, entry_offset = host_image(*load_encoder_program(), "riscv64-encoder")
        thunk = _SYSV_TO_WIN64_THUNK + bytes(-len(_SYSV_TO_WIN64_THUNK) % 16)
        code = thunk + machine_code
        from xax_native import executable_mapping

        mapping, base = executable_mapping(code)
        call = ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint64, ctypes.c_void_p)(base)
        return cls(len(machine_code), mapping, call, base + len(thunk) + entry_offset, (ctypes.c_uint64 * 7)(), ctypes.c_uint64())

    def __call__(self, kind: int, *operands: int) -> int:
        slots = self._slots
        slots[0] = kind
        for position in range(6):
            slots[position + 1] = (operands[position] if position < len(operands) else 0) & _MASK64
        return self._call(self._entry, ctypes.addressof(slots), 7, ctypes.addressof(self._xmm))


_native: list[NativeEncoder | None] = []


def native_encoder() -> NativeEncoder | None:
    """The in-process XAX encoder, or ``None`` where it cannot run.

    It runs on Linux x86-64 hosts; ``XAX_RISCV64_PYTHON_ENCODER=1`` forces the
    bootstrap Python encoders.
    """
    if not _native:
        import xax_native

        usable = xax_native.usable("riscv64-encoder", STORE_PATH, "XAX_RISCV64_PYTHON_ENCODER")
        _native.append(NativeEncoder.load() if usable else None)
    return _native[0]
