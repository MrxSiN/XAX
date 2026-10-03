"""Direct AArch64 bare-metal load-image backend for the XAX prototype."""

from __future__ import annotations

import subprocess
import tempfile
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Sequence

from xax_artifact import ArtifactSemanticRange

from xax_compiler import parse_function_graph
from xax_compiler import (
    store_resolver,
    borrowed_view_returns,
    AAPCS64_LINUX_C_ABI,
    AAPCS64_STATIC_C_ABI,
    AARCH64_LINUX_ABI,
    AARCH64_LINUX_ELF_DYNAMIC_FORMAT,
    AARCH64_LINUX_IDENTITIES,
    ANDROID_AAPCS64_C_ABI,
    LINUX_AARCH64_SYSCALL_ABI,
    XaxError,
    foreign_entry_abi,
    ATOMIC_OPERATIONS,
    AtomicLegalizationPolicy,
    AtomicOrder,
    AtomicSupport,
    ANDROID_ARM64_SHARED_IDENTITIES,
    ANDROID_JNI_REFERENCE_WORD_BORROWED_OPERATION,
    ANDROID_JNI_REFERENCE_WORD_GLOBAL_OPERATION,
    ANDROID_JNI_REFERENCE_WORD_LOCAL_OPERATION,
    FloatCompare,
    IntCompare,
    Kind,
    NativeTargetDescription,
    Operation,
    RealtimeProfile,
    RESOURCE_EFFECT_OPERATIONS,
    SemanticObject,
    StoreReader,
    TerminatorKind,
    decode_trap_payload,
    decode_foreign_function,
    ValueRef,
    _decode_constant,
    _decode_function_interface,
    _float_raw_bits,
    _int_to_float,
    _heap_view_info,
    pointer_extent_from_graph,
    _is_proof_type,
    _is_erased_proof_function,
    _parse_graph,
    _atomic_node_request,
    _decode_pointer_type,
    abi_homogeneous_float,
    abi_layout,
    atomic_capability,
    analyze_realtime,
    decode_bits_width,
    decode_float_width,
    decode_native_target,
    fail,
    select_atomic_legalization,
    validate_realtime_profile,
    verify_store,
)


@dataclass(frozen=True)
class Aarch64Image:
    code: bytes
    entry_offset: int
    parameter_widths: tuple[int, ...]
    return_widths: tuple[int, ...]
    target_cid: bytes
    function_offsets: tuple[tuple[bytes, int], ...]
    semantic_ranges: tuple[ArtifactSemanticRange, ...] = ()
    # "u" for X-register carriers, "f" for V-register floats (AAPCS64).
    parameter_kinds: tuple[str, ...] = ()
    return_kinds: tuple[str, ...] = ()

    @property
    def artifact_bytes(self) -> bytes:
        return self.code


@dataclass(frozen=True)
class Aarch64Bundle:
    code: bytes
    target_cid: bytes
    function_offsets: tuple[tuple[bytes, int], ...]
    foreign_calls: tuple[tuple[int, bytes, bytes], ...] = ()
    semantic_ranges: tuple[ArtifactSemanticRange, ...] = ()


class _Assembler:
    def __init__(self) -> None:
        self.code = bytearray()
        self.labels: dict[str, int] = {}
        self.branches: list[tuple[int, str, int, int | None, int]] = []
        self.calls: list[tuple[int, bytes]] = []
        self.foreign_calls: list[tuple[int, bytes, bytes]] = []
        self.addresses: list[tuple[int, int, bytes]] = []

    def emit(self, word: int) -> None:
        self.code.extend(word.to_bytes(4, "little"))

    def label(self, name: str) -> None:
        self.labels[name] = len(self.code)

    def branch(self, label: str) -> None:
        self.branches.append((len(self.code), label, 26, None, 0x14000000))
        self.emit(0x14000000)

    def cbz(self, register: int, label: str) -> None:
        self.branches.append((len(self.code), label, 19, register, 0x34000000))
        self.emit(0x34000000 | register)

    def cbnz(self, register: int, label: str, wide: bool = True) -> None:
        base = 0xB5000000 if wide else 0x35000000
        self.branches.append((len(self.code), label, 19, register, base))
        self.emit(base | register)

    def bcond(self, condition: int, label: str) -> None:
        # B.cond uses imm19 in bits 23:5.  A zero pseudo-register keeps the
        # existing branch patcher on its imm19 path without changing encoding.
        base = 0x54000000 | (condition & 0xF)
        self.branches.append((len(self.code), label, 19, 0, base))
        self.emit(base)

    def call(self, callee: bytes) -> None:
        self.calls.append((len(self.code), callee))
        self.emit(0x94000000)

    def foreign_call(self, library: bytes, name: bytes) -> None:
        self.foreign_calls.append((len(self.code), library, name))
        self.emit(0x94000000)

    def address(self, register: int, function_cid: bytes) -> None:
        self.addresses.append((len(self.code), register, function_cid))
        self.emit(0x10000000 | register)

    def finish(self) -> tuple[bytes, tuple[tuple[int, bytes], ...], tuple[tuple[int, bytes, bytes], ...], tuple[tuple[int, int, bytes], ...]]:
        for position, label, bits, register, base in self.branches:
            try:
                displacement = self.labels[label] - position
            except KeyError:
                fail("XAX.AARCH64.LABEL", "aarch64", "AARCH64-LABEL-RESOLVED", label, "missing")
            immediate = displacement // 4
            if displacement % 4 or not -(1 << (bits - 1)) <= immediate < 1 << (bits - 1):
                fail("XAX.AARCH64.BRANCH", "aarch64", "AARCH64-BRANCH-RANGE", bits, displacement)
            opcode = (base | register | ((immediate & 0x7FFFF) << 5)) if register is not None else (base | (immediate & 0x3FFFFFF))
            self.code[position:position + 4] = opcode.to_bytes(4, "little")
        return bytes(self.code), tuple(self.calls), tuple(self.foreign_calls), tuple(self.addresses)


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) & -alignment


def _width(resolve: Callable[[bytes], SemanticObject], cid: bytes) -> int | None:
    """GPR carrier width of a register-resident machine value, else None.

    Floats travel in GPRs as raw bits and visit V registers only around FP
    instructions and ABI boundaries.  Aggregates and sums up to 8 bytes are
    their C layout bytes in one GPR; larger ones live in frame memory.
    """
    obj = resolve(cid)
    if obj.kind != Kind.TYPE or not obj.body:
        return None
    if obj.body[0] == 1:
        return decode_bits_width(obj)
    if obj.body[0] == 2:
        # All current AArch64 targets use 64-bit pointers.  Pointer provenance
        # remains semantic; this is only its machine carrier width.
        return 64
    if obj.body[0] == 7:
        return decode_float_width(obj)
    if obj.body[0] in (8, 9, 10):
        size = abi_layout(obj, resolve).size
        return 8 * size if 0 < size <= 8 else None
    return None


def _memory_size(resolve: Callable[[bytes], SemanticObject], cid: bytes) -> int | None:
    """Byte size of an aggregate too large for one GPR (held in frame memory)."""
    obj = resolve(cid)
    if obj.kind != Kind.TYPE or not obj.body or obj.body[0] not in (8, 9, 10):
        return None
    size = abi_layout(obj, resolve).size
    return size if size > 8 else None


def _abi_class(resolve: Callable[[bytes], SemanticObject], cid: bytes) -> tuple[str, int, int]:
    """AAPCS64 class ``(kind, registers, member bytes)``.

    kind: ``gpr`` one X register, ``gpr2`` an X register pair (9..16 byte
    composite), ``fpr`` one V register, ``hfa`` 1..4 V registers, ``ref`` a
    pointer to a caller copy (composite over 16 bytes, or x8 for results).
    """
    obj = resolve(cid)
    form = obj.body[0]
    if form == 7:
        return ("fpr", 1, decode_float_width(obj) // 8)
    if form in (8, 9, 10):
        hfa = abi_homogeneous_float(obj, resolve)
        if hfa is not None:
            return ("hfa", hfa[1], hfa[0])
        size = abi_layout(obj, resolve).size
        if size <= 8:
            return ("gpr", 1, size)
        return ("gpr2", 2, size) if size <= 16 else ("ref", 1, size)
    return ("gpr", 1, 8)


def _assign_arguments(classes: Sequence[tuple[str, int, int]]) -> list[int] | None:
    """First X or V register number per argument, or None when AAPCS64 needs the stack."""
    next_gpr = next_fpr = 0
    locations: list[int] = []
    for kind, count, _member in classes:
        if kind in ("fpr", "hfa"):
            if next_fpr + count > 8:
                return None
            locations.append(next_fpr)
            next_fpr += count
        else:
            needed = 2 if kind == "gpr2" else 1
            if next_gpr + needed > 8:
                return None
            locations.append(next_gpr)
            next_gpr += needed
    return locations


_SP = 31
_TEMP = 16  # IP0: never allocated, never an argument; free inside one node
_TEMP2 = 17  # IP1
_FP_TEMP = 16
_FP_TEMP2 = 17
_COND = {"eq": 0, "ne": 1, "hs": 2, "lo": 3, "mi": 4, "pl": 5, "vs": 6, "vc": 7, "hi": 8, "ls": 9, "ge": 10, "lt": 11, "gt": 12, "le": 13}
_FLOAT_CONDITION = {
    FloatCompare.EQ: _COND["eq"], FloatCompare.NE: _COND["ne"], FloatCompare.LT: _COND["mi"],
    FloatCompare.LE: _COND["ls"], FloatCompare.GT: _COND["gt"], FloatCompare.GE: _COND["ge"],
}
_INT_CONDITION = {
    IntCompare.EQ: _COND["eq"], IntCompare.NE: _COND["ne"], IntCompare.ULT: _COND["lo"], IntCompare.ULE: _COND["ls"],
    IntCompare.UGT: _COND["hi"], IntCompare.UGE: _COND["hs"], IntCompare.SLT: _COND["lt"], IntCompare.SLE: _COND["le"],
    IntCompare.SGT: _COND["gt"], IntCompare.SGE: _COND["ge"],
}
_FLOAT_BINARY = {
    Operation.FLOAT_ADD: 0x1E202800, Operation.FLOAT_SUB: 0x1E203800,
    Operation.FLOAT_MUL: 0x1E200800, Operation.FLOAT_DIV: 0x1E201800,
}
# Trap immediates for checks emitted inside one node.
_BRK_FLOAT_CONVERSION = 2
_BRK_NULL_HEAP = 3
_BRK_MEMORY_CHECK = 4
_BRK_SUM_VARIANT = 5


def _fmov_to_fp(fp: int, gpr: int, width: int) -> int:
    return (0x1E270000 if width == 32 else 0x9E670000) | (gpr << 5) | fp


def _fmov_from_fp(gpr: int, fp: int, width: int) -> int:
    return (0x1E260000 if width == 32 else 0x9E660000) | (fp << 5) | gpr


def _float_binary(operation: Operation, destination: int, left: int, right: int, width: int) -> int:
    return _FLOAT_BINARY[operation] | (0x00400000 if width == 64 else 0) | (right << 16) | (left << 5) | destination


def _fcmp(left: int, right: int, width: int) -> int:
    return 0x1E202000 | (0x00400000 if width == 64 else 0) | (right << 16) | (left << 5)


def _cset(destination: int, condition: int) -> int:
    return 0x1A9F07E0 | ((condition ^ 1) << 12) | destination


def _fcvt(destination: int, source: int, source_width: int) -> int:
    return (0x1E22C000 if source_width == 32 else 0x1E624000) | (source << 5) | destination


def _int_to_fp(destination: int, source: int, float_width: int, source64: bool, signed: bool) -> int:
    base = 0x1E220000 if signed else 0x1E230000
    return base | (0x00400000 if float_width == 64 else 0) | (0x80000000 if source64 else 0) | (source << 5) | destination


def _fp_to_int64(destination: int, source: int, float_width: int, signed: bool) -> int:
    return (0x9E380000 if signed else 0x9E390000) | (0x00400000 if float_width == 64 else 0) | (source << 5) | destination


def _ubfx(destination: int, source: int, lsb: int, width: int) -> int:
    return 0xD3400000 | (lsb << 16) | ((lsb + width - 1) << 10) | (source << 5) | destination


def _sbfx(destination: int, source: int, lsb: int, width: int) -> int:
    return 0x93400000 | (lsb << 16) | ((lsb + width - 1) << 10) | (source << 5) | destination


def _bfi(destination: int, source: int, lsb: int, width: int) -> int:
    return 0xB3400000 | (((-lsb) % 64) << 16) | ((width - 1) << 10) | (source << 5) | destination


def _lsr(destination: int, source: int, shift: int) -> int:
    return 0xD340FC00 | (shift << 16) | (source << 5) | destination


def _lsl(destination: int, source: int, shift: int) -> int:
    """``lsl Xd, Xn, #shift`` (``ubfm Xd, Xn, #(-shift % 64), #(63 - shift)``)."""
    return 0xD3400000 | (((-shift) % 64) << 16) | ((63 - shift) << 10) | (source << 5) | destination


def _udiv(destination: int, left: int, right: int, wide: bool) -> int:
    return (0x9AC00800 if wide else 0x1AC00800) | (right << 16) | (left << 5) | destination


def _msub(destination: int, left: int, right: int, minuend: int, wide: bool) -> int:
    """``msub Rd, Rn, Rm, Ra``: Ra - Rn * Rm."""
    return (0x9B008000 if wide else 0x1B008000) | (right << 16) | (minuend << 10) | (left << 5) | destination


_LOGICAL_BASE = {Operation.BIT_AND: 0x0A000000, Operation.BIT_OR: 0x2A000000, Operation.BIT_XOR: 0x4A000000}


def _logical(operation: Operation, destination: int, left: int, right: int, wide: bool) -> int:
    return _LOGICAL_BASE[operation] | (0x80000000 if wide else 0) | (right << 16) | (left << 5) | destination


_INTEGER_COMPLETION_BINARY = frozenset({Operation.BIT_AND, Operation.BIT_OR, Operation.BIT_XOR, Operation.UDIV, Operation.UREM})
_BRK_DIVIDE_BY_ZERO = 6
BOARD_IDENTITY = b"aarch64-qemu-virt-v1"
# Frame path only: a third per-node scratch (x9 is a declared scratch register
# and holds no value across nodes there).
_REMAINDER_TEMP = 9


def _cmp_registers(left: int, right: int, width: int) -> int:
    return (0x6B00001F if width <= 32 else 0xEB00001F) | (right << 16) | (left << 5)


def _cmp_immediate(register: int, value: int, width: int) -> int:
    return (0x7100001F if width <= 32 else 0xF100001F) | (value << 10) | (register << 5)


def _skip_if(condition: int) -> int:
    """B.cond over the next instruction (the trap)."""
    return 0x54000040 | condition


def _brk(code: int) -> int:
    return 0xD4200000 | ((code & 0xFFFF) << 5)


def _add_immediate(destination: int, source: int, value: int) -> int:
    return 0x91000000 | (value << 10) | (source << 5) | destination


def _add_registers(destination: int, left: int, right: int) -> int:
    return 0x8B000000 | (right << 16) | (left << 5) | destination


_BASE_ACCESS = {1: (0x39400000, 0x39000000), 2: (0x79400000, 0x79000000), 4: (0xB9400000, 0xB9000000), 8: (0xF9400000, 0xF9000000)}
_INDEX_ACCESS = {1: (0x38604800, 0x38204800), 2: (0x78604800, 0x78204800), 4: (0xB8604800, 0xB8204800), 8: (0xF8604800, 0xF8204800)}


def _base_access(load: bool, register: int, base: int, offset: int, size: int) -> int:
    """Exact-width zero-extending load / store at ``[base, #offset]`` (base 31 = SP)."""
    opcode = _BASE_ACCESS[size][0 if load else 1]
    if offset < 0 or offset % size or offset // size >= 4096:
        fail("XAX.AARCH64.MEMORY_ENCODING", "aarch64", "AARCH64-BASE-OFFSET", f"aligned {size}-byte offset < {4096 * size}", offset)
    return opcode | ((offset // size) << 10) | (base << 5) | register


_DMB_ISH = 0xD5033BBF


def _atomic_load_register(destination: int, base: int, width: int, acquire: bool) -> int:
    if width == 32:
        opcode = 0x88DFFC00 if acquire else 0xB9400000
    elif width == 64:
        opcode = 0xC8DFFC00 if acquire else 0xF9400000
    else:
        fail("XAX.AARCH64.ATOMIC_WIDTH", "aarch64", "AARCH64-ATOMIC-WIDTH", [32, 64], width)
    return opcode | (base << 5) | destination


def _atomic_store_register(source: int, base: int, width: int, release: bool) -> int:
    if width == 32:
        opcode = 0x889FFC00 if release else 0xB9000000
    elif width == 64:
        opcode = 0xC89FFC00 if release else 0xF9000000
    else:
        fail("XAX.AARCH64.ATOMIC_WIDTH", "aarch64", "AARCH64-ATOMIC-WIDTH", [32, 64], width)
    return opcode | (base << 5) | source


def _index_access(load: bool, register: int, base: int, index: int, size: int) -> int:
    """``[base, w_index, uxtw]`` access of 1/2/4/8 bytes."""
    return _INDEX_ACCESS[size][0 if load else 1] | (index << 16) | (base << 5) | register


def _fp_access(load: bool, register: int, base: int, offset: int, size: int) -> int:
    opcode = {4: (0xBD400000, 0xBD000000), 8: (0xFD400000, 0xFD000000)}[size][0 if load else 1]
    if offset < 0 or offset % size or offset // size >= 4096:
        fail("XAX.AARCH64.MEMORY_ENCODING", "aarch64", "AARCH64-FP-OFFSET", f"aligned {size}-byte offset < {4096 * size}", offset)
    return opcode | ((offset // size) << 10) | (base << 5) | register


def _chunk(remaining: int, *offsets: int) -> int:
    return next(size for size in (8, 4, 2, 1) if size <= remaining and all(offset % size == 0 for offset in offsets))


def _copy_memory(destination_base: int, destination: int, source_base: int, source: int, size: int) -> list[int]:
    words: list[int] = []
    done = 0
    while done < size:
        chunk = _chunk(size - done, destination + done, source + done)
        words.append(_base_access(True, _TEMP, source_base, source + done, chunk))
        words.append(_base_access(False, _TEMP, destination_base, destination + done, chunk))
        done += chunk
    return words


def _store_register_bytes(register: int, base: int, offset: int, size: int) -> list[int]:
    words: list[int] = []
    done = 0
    while done < size:
        chunk = _chunk(size - done, offset + done)
        source = register
        if done:
            words.append(_lsr(_TEMP, register, 8 * done))
            source = _TEMP
        words.append(_base_access(False, source, base, offset + done, chunk))
        done += chunk
    return words


def _load_register_bytes(destination: int, base: int, offset: int, size: int) -> list[int]:
    words: list[int] = []
    done = 0
    while done < size:
        chunk = _chunk(size - done, offset + done)
        if not done:
            words.append(_base_access(True, destination, base, offset, chunk))
        else:
            words.append(_base_access(True, _TEMP, base, offset + done, chunk))
            words.append(_bfi(destination, _TEMP, 8 * done, 8 * chunk))
        done += chunk
    return words


def _hfa_to_vector(source: int, first: int, count: int, member: int) -> list[int]:
    """Spread a <=8-byte homogeneous float aggregate from a GPR into V registers."""
    words: list[int] = []
    for index in range(count):
        words.append(_ubfx(_TEMP, source, 8 * member * index, 8 * member) if count > 1 else (0xAA0003E0 | (source << 16) | _TEMP))
        words.append(_fmov_to_fp(first + index, _TEMP, 8 * member))
    return words


def _hfa_from_vector(destination: int, first: int, count: int, member: int) -> list[int]:
    words = [_fmov_from_fp(destination, first, 8 * member)]
    for index in range(1, count):
        words.append(_fmov_from_fp(_TEMP, first + index, 8 * member))
        words.append(_bfi(destination, _TEMP, 8 * member * index, 8 * member))
    return words


def _parallel_moves(assignments: Sequence[tuple[int, int, int]], scratch: int) -> list[int]:
    words: list[int] = []
    pending = [(destination, source, width) for destination, source, width in assignments if destination != source]
    while pending:
        sources = {source for _, source, _ in pending}
        safe_index = next((index for index, (destination, _, _) in enumerate(pending) if destination not in sources), None)
        if safe_index is not None:
            destination, source, width = pending.pop(safe_index)
            words.append(_move_register(destination, source, width))
            continue
        destination, source, width = min(pending, key=lambda item: (item[0], item[1], item[2]))
        words.append(_move_register(scratch, source, width))
        pending = [(dest, scratch if src == source else src, item_width) for dest, src, item_width in pending]
    return words


def _load_store(load: bool, register: int, offset: int, width: int) -> int:
    if 1 <= width <= 32:
        base, scale = (0xB9400000 if load else 0xB9000000), 4
    elif 33 <= width <= 64:
        base, scale = (0xF9400000 if load else 0xF9000000), 8
    else:
        fail("XAX.AARCH64.BITS", "aarch64", "AARCH64-BITS-SUPPORTED", [32, 64], width)
    if offset < 0 or offset % scale or offset // scale >= 4096:
        fail("XAX.AARCH64.MEMORY_ENCODING", "aarch64", "AARCH64-SP-OFFSET", f"aligned {scale}-byte offset < {4096 * scale}", offset)
    return base | ((offset // scale) << 10) | (31 << 5) | register


def _exact_memory_load_store(load: bool, register: int, offset: int, width: int) -> int:
    """Encode an exact-width unsigned load/store against SP-backed semantic memory."""
    table = {
        8: ((0x39400000 if load else 0x39000000), 1),
        16: ((0x79400000 if load else 0x79000000), 2),
        32: ((0xB9400000 if load else 0xB9000000), 4),
        64: ((0xF9400000 if load else 0xF9000000), 8),
    }
    try:
        base, scale = table[width]
    except KeyError:
        fail("XAX.AARCH64.MEMORY_WIDTH", "aarch64", "AARCH64-MEMORY-WIDTH", [8, 16, 32, 64], width)
    if offset < 0 or offset % scale or offset // scale >= 4096:
        fail("XAX.AARCH64.MEMORY_ENCODING", "aarch64", "AARCH64-SP-OFFSET", f"aligned {scale}-byte offset < {4096 * scale}", offset)
    return base | ((offset // scale) << 10) | (31 << 5) | register


def _load_from_register(destination: int, base_register: int, offset: int, width: int) -> int:
    if width == 32:
        opcode, scale = 0xB9400000, 4
    elif width == 64:
        opcode, scale = 0xF9400000, 8
    else:
        fail("XAX.AARCH64.BITS", "aarch64", "AARCH64-REGISTER-LOAD-BITS", [32, 64], width)
    if offset < 0 or offset % scale or offset // scale >= 4096:
        fail("XAX.AARCH64.MEMORY_ENCODING", "aarch64", "AARCH64-BASE-OFFSET", f"aligned {scale}-byte offset < {4096 * scale}", offset)
    return opcode | ((offset // scale) << 10) | (base_register << 5) | destination


def _blr(register: int) -> int:
    return 0xD63F0000 | (register << 5)


def _move_immediate(register: int, value: int, width: int) -> tuple[int, ...]:
    storage = 32 if width <= 32 else 64
    words = [(0x52800000 if storage == 32 else 0xD2800000) | ((value & 0xFFFF) << 5) | register]
    for halfword in range(1, storage // 16):
        part = (value >> (halfword * 16)) & 0xFFFF
        if part:
            words.append((0x72800000 if storage == 32 else 0xF2800000) | (halfword << 21) | (part << 5) | register)
    return tuple(words)


def _address_from_sp(destination: int, offset: int) -> int:
    if offset < 0 or offset >= 4096:
        fail("XAX.AARCH64.FRAME", "aarch64", "AARCH64-STACK-ADDRESS-OFFSET", "< 4096 bytes", offset)
    return 0x91000000 | (offset << 10) | (31 << 5) | destination


def _add_sub_sp(subtract: bool, amount: int) -> int:
    if amount < 0 or amount >= 4096:
        fail("XAX.AARCH64.FRAME", "aarch64", "AARCH64-FRAME-SIZE", "< 4096 bytes", amount)
    return (0xD1000000 if subtract else 0x91000000) | (amount << 10) | (31 << 5) | 31


def _move_register(destination: int, source: int, width: int) -> int:
    if destination == source:
        raise ValueError("self move should be elided")
    if 1 <= width <= 32:
        return 0x2A0003E0 | (source << 16) | destination
    if 33 <= width <= 64:
        return 0xAA0003E0 | (source << 16) | destination
    fail("XAX.AARCH64.BITS", "aarch64", "AARCH64-MOVE-BITS", "bits<1..64>", width)


def _arithmetic(operation: Operation, destination: int, left: int, right: int, width: int) -> int:
    if width not in (32, 64):
        fail("XAX.AARCH64.BITS", "aarch64", "AARCH64-ARITHMETIC-BITS", [32, 64], width)
    base = {
        Operation.ADD_WRAP: 0x0B000000 if width == 32 else 0x8B000000,
        Operation.SUB_WRAP: 0x4B000000 if width == 32 else 0xCB000000,
        Operation.MUL_WRAP: 0x1B007C00 if width == 32 else 0x9B007C00,
    }[operation]
    return base | (right << 16) | (left << 5) | destination


# AArch64 condition codes for IntCompare (cmp left, right; cset on the condition).
_CONDITION = {
    IntCompare.EQ: 0, IntCompare.NE: 1, IntCompare.UGE: 2, IntCompare.ULT: 3, IntCompare.UGT: 8, IntCompare.ULE: 9,
    IntCompare.SGE: 10, IntCompare.SLT: 11, IntCompare.SGT: 12, IntCompare.SLE: 13,
}


def _compare(left: int, right: int, width: int) -> int:
    """``cmp`` (``subs`` to the zero register) of two 32- or 64-bit registers."""
    return (0x6B000000 if width == 32 else 0xEB000000) | (right << 16) | (left << 5) | 31


def _cset_compare(destination: int, comparison: IntCompare) -> int:
    """``cset Wd, cond`` (``csinc Wd, wzr, wzr, !cond``)."""
    return 0x1A9F07E0 | ((_CONDITION[comparison] ^ 1) << 12) | destination


# Operations the register-resident path lowers.  A general-target function
# uses it only when all its operations are here and all its machine values
# are 32/64-bit integers, pointers, or compare results (ADR-110); anything
# else keeps the uniform frame path.
_REGISTER_PATH_OPERATIONS = frozenset({
    Operation.ADD_WRAP, Operation.SUB_WRAP, Operation.MUL_WRAP, Operation.CONSTANT, Operation.INT_COMPARE,
    Operation.CALL_DIRECT, Operation.CALL_FOREIGN, Operation.CALL_INDIRECT, Operation.FUNCTION_ADDRESS,
})


def _require_foreign_abi(declaration, target: NativeTargetDescription, graph_object: SemanticObject) -> None:
    """Each foreign convention belongs to exactly one AArch64 platform profile.

    Android: ``android-aapcs64-c``.  Linux (ADR-123): ``linux-aarch64-syscall-v1``
    always, and ``aapcs64-linux-c`` only when the profile explicitly requests
    the dynamic loader.
    """
    if target.abi == AARCH64_LINUX_ABI:
        allowed = (LINUX_AARCH64_SYSCALL_ABI,) + ((AAPCS64_LINUX_C_ABI,) if target.image_format == AARCH64_LINUX_ELF_DYNAMIC_FORMAT else ())
    elif target.identity == BOARD_IDENTITY:
        allowed = (AAPCS64_STATIC_C_ABI,)  # resolved by the board image's static link (ADR-129)
    else:
        allowed = (ANDROID_AAPCS64_C_ABI,)
    if declaration.abi not in allowed:
        fail("XAX.FOREIGN.ABI", graph_object.cid.hex(), "AARCH64-FOREIGN-ABI", [item.decode() for item in allowed], declaration.abi.decode("ascii", "replace"))


def _register_path_eligible(graph, parameters, returns, resolve: Callable[[bytes], SemanticObject]) -> bool:
    def scalar(cid: bytes, widths: tuple[int, ...] = (32, 64)) -> bool:
        obj = resolve(cid)
        if _is_proof_type(obj):
            return True
        if obj.body[:1] == b"\x02":
            return True
        return obj.body[:1] == b"\x01" and decode_bits_width(obj) in widths

    if not all(scalar(cid) for cid in (*parameters, *returns)):
        return False
    if sum(not _is_proof_type(resolve(cid)) for cid in returns) > 1:
        return False  # borrowed-view return elision lives on the frame path
    for block in graph.blocks:
        if not all(scalar(cid, (1, 32, 64)) for cid in block.parameters):
            return False
        for node in block.nodes:
            if node.operation not in _REGISTER_PATH_OPERATIONS:
                return False
            if node.operation == Operation.INT_COMPARE:
                if not all(scalar(cid) for cid in node.operand_types):
                    return False
            elif not all(scalar(cid) for cid in (*node.operand_types, *node.results)):
                return False
            if node.operation in (Operation.CALL_DIRECT, Operation.CALL_FOREIGN, Operation.CALL_INDIRECT):
                machine = [cid for cid in node.operand_types if not _is_proof_type(resolve(cid))]
                if len(machine) > 8 + (node.operation == Operation.CALL_INDIRECT):
                    return False
                if sum(not _is_proof_type(resolve(cid)) for cid in node.results) > 1:
                    return False
    return True


def _function_closure(
    entry: SemanticObject,
    resolve: Callable[[bytes], SemanticObject],
    target: NativeTargetDescription,
) -> tuple[SemanticObject, ...]:
    functions: dict[bytes, SemanticObject] = {}

    def visit(function: SemanticObject) -> None:
        if function.cid in functions:
            return
        functions[function.cid] = function
        graph_object, parameters, returns = _decode_function_interface(function, resolve)
        machine_parameters = tuple(cid for cid in parameters if not _is_proof_type(resolve(cid)))
        # Borrowed views a function gives back stay out of registers (ADR-101 on AArch64, ADR-125).
        elided = borrowed_view_returns(parameters, returns, resolve)
        machine_returns = tuple(cid for index, cid in enumerate(returns) if not _is_proof_type(resolve(cid)) and index not in elided)
        widths = [_width(resolve, cid) or (_memory_size(resolve, cid) and 128) for cid in (*machine_parameters, *machine_returns)]
        if _general_aarch64_target(target):
            try:
                for cid in (*machine_parameters, *machine_returns):
                    abi_layout(resolve(cid), resolve)
            except Exception:
                fail("XAX.AARCH64.ABI", function.cid.hex(), "AARCH64-ABI-VALUE", "AAPCS64 layoutable value", [cid.hex() for cid in (*machine_parameters, *machine_returns)])
            if len(machine_returns) > 1:
                fail("XAX.AARCH64.ABI", function.cid.hex(), "AARCH64-ABI-RETURNS", 1, len(machine_returns))
        else:
            scalar_ok = all(
                width and (width <= 64 or _memory_size(resolve, cid) is not None)
                for width, cid in zip(widths, (*machine_parameters, *machine_returns))
            )
            if (
                len(machine_returns) > 1
                or not scalar_ok
                or _assign_arguments([_abi_class(resolve, cid) for cid in machine_parameters]) is None
            ):
                fail("XAX.AARCH64.ABI", function.cid.hex(), "AARCH64-ABI", [len(target.argument_registers), 1, "AAPCS64 register-assigned values"], [len(machine_parameters), len(machine_returns), widths])
        graph = parse_function_graph(function, resolve)
        for block in graph.blocks:
            for node in block.nodes:
                if node.operation not in target.supported_operations:
                    fail("XAX.AARCH64.UNSUPPORTED_OPERATION", graph_object.cid.hex(), "AARCH64-OP-TARGET-SUPPORTED", list(target.supported_operations), node.operation)
                if node.operation == Operation.CALL_DIRECT:
                    if not _is_erased_proof_function(node.entity, resolve):
                        visit(node.entity)
                elif node.operation == Operation.FUNCTION_ADDRESS:
                    entry_abi = foreign_entry_abi(resolve(node.results[0]), resolve)
                    if entry_abi is not None:
                        _require_android_entry(node.entity, entry_abi, resolve, target, graph_object)
                    visit(node.entity)
            if block.terminator.kind not in target.supported_terminators:
                fail("XAX.AARCH64.UNSUPPORTED_TERMINATOR", graph_object.cid.hex(), "AARCH64-TERMINATOR-TARGET-SUPPORTED", list(target.supported_terminators), block.terminator.kind)

    visit(entry)
    return tuple(functions[cid] for cid in sorted(functions))




def _type_form(resolve: Callable[[bytes], SemanticObject], cid: bytes) -> int | None:
    obj = resolve(cid)
    return obj.body[0] if obj.kind == Kind.TYPE and obj.body else None


def _is_aggregate(resolve: Callable[[bytes], SemanticObject], cid: bytes) -> bool:
    return _type_form(resolve, cid) in (8, 9, 10)


def _slot_size(layout) -> int:
    return _align(max(1, layout.size), 8)


def _zero_memory(base: int, offset: int, size: int) -> list[int]:
    words: list[int] = []
    done = 0
    while done < size:
        chunk = _chunk(size - done, offset + done)
        words.append(_base_access(False, 31, base, offset + done, chunk))
        done += chunk
    return words


def _mask_register_words(register: int, width: int) -> list[int]:
    if width in (32, 64):
        return []
    if width < 32:
        return [_ubfx(register, register, 0, width)]
    if width < 64:
        return [_ubfx(register, register, 0, width)]
    return []


def _abi_argument_plan(
    type_cids: Sequence[bytes], resolve: Callable[[bytes], SemanticObject]
) -> tuple[list[tuple[str, int, int, int]], int]:
    """AAPCS64 argument locations.

    Each entry is ``(kind, index_or_stack_offset, count, member_bytes)`` where
    kind is ``gpr``, ``fpr``, ``hfa``, ``gpr2``, ``ref``, or ``stack``.  Stack
    entries carry the original ABI class in ``count`` via a compact code only
    internally: 1 scalar/gpr, 2 gpr2, 3 fp/hfa, 4 by-reference pointer.
    """
    ngpr = nfpr = 0
    stack = 0
    out: list[tuple[str, int, int, int]] = []
    for cid in type_cids:
        kind, count, member = _abi_class(resolve, cid)
        layout = abi_layout(resolve(cid), resolve)
        if kind in ("fpr", "hfa") and nfpr + count <= 8:
            out.append((kind, nfpr, count, member))
            nfpr += count
            continue
        if kind in ("fpr", "hfa"):
            nfpr = 8
            align = max(8, min(16, layout.alignment))
            stack = _align(stack, align)
            out.append(("stack", stack, 3, member))
            stack += _align(layout.size, 8)
            continue
        needed = 2 if kind == "gpr2" else 1
        if ngpr + needed <= 8:
            out.append((kind, ngpr, needed, member))
            ngpr += needed
            continue
        ngpr = 8
        align = 8
        stack = _align(stack, align)
        if kind == "ref":
            out.append(("stack", stack, 4, member))
            stack += 8
        else:
            out.append(("stack", stack, 2 if kind == "gpr2" else 1, member))
            stack += _align(layout.size, 8)
    return out, _align(stack, 16) if stack else 0


def _general_aarch64_target(target: NativeTargetDescription) -> bool:
    return (
        Operation.FLOAT_ADD in target.supported_operations
        or Operation.AGGREGATE_MAKE in target.supported_operations
        or Operation.SUM_MAKE in target.supported_operations
    )


def _frame_live_hulls(graph, machine_values: set) -> dict:
    """Linear ``[first, last]`` position hull of each machine value's liveness.

    Positions number blocks in index order (block start, each node, the
    terminator).  Block liveness is the usual backward dataflow, so a value
    live around a loop covers every block of the loop.  Entry parameters are
    defined at position 0, before any block runs.
    """
    starts, uses, defs = [], [], []
    position = 1
    for block_index, block in enumerate(graph.blocks):
        starts.append(position)
        position += len(block.nodes) + 2
        used: set = set()
        defined = {ValueRef.parameter(block_index, index) for index in range(len(block.parameters))}
        for node_index, node in enumerate(block.nodes):
            used.update(ref for ref in node.operands if ref in machine_values and ref not in defined)
            defined.update(ValueRef.node_result(block_index, node_index, index) for index in range(len(node.results)))
        terminator = block.terminator
        refs = (*terminator.values, *(ref for _target, arguments in terminator.edges for ref in arguments))
        used.update(ref for ref in refs if ref in machine_values and ref not in defined)
        uses.append(used)
        defs.append(defined)
    successors = [tuple(target for target, _arguments in block.terminator.edges) for block in graph.blocks]
    live_in = [set(item) for item in uses]
    live_out: list[set] = [set() for _ in graph.blocks]
    changed = True
    while changed:
        changed = False
        for block_index in reversed(range(len(graph.blocks))):
            out = set().union(*(live_in[target] for target in successors[block_index])) if successors[block_index] else set()
            incoming = uses[block_index] | (out - defs[block_index])
            if out != live_out[block_index] or incoming != live_in[block_index]:
                live_out[block_index], live_in[block_index] = out, incoming
                changed = True
    hull: dict = {}

    def cover(ref, first: int, last: int) -> None:
        if ref in machine_values:
            low, high = hull.get(ref, (first, last))
            hull[ref] = (min(low, first), max(high, last))

    for block_index, block in enumerate(graph.blocks):
        start = starts[block_index]
        end = start + len(block.nodes) + 1
        for index in range(len(block.parameters)):
            cover(ValueRef.parameter(block_index, index), 0 if block_index == graph.entry else start, start)
        for node_index, node in enumerate(block.nodes):
            here = start + 1 + node_index
            for ref in node.operands:
                cover(ref, here, here)
            for index in range(len(node.results)):
                cover(ValueRef.node_result(block_index, node_index, index), here, here)
        terminator = block.terminator
        for ref in (*terminator.values, *(ref for _target, arguments in terminator.edges for ref in arguments)):
            cover(ref, end, end)
        for ref in live_in[block_index]:
            cover(ref, start, start)
        for ref in live_out[block_index]:
            cover(ref, end, end)
    for ref in machine_values:
        hull.setdefault(ref, (0, 0))
    return hull


def _compile_general_function(
    function: SemanticObject,
    resolve: Callable[[bytes], SemanticObject],
    target: NativeTargetDescription,
) -> tuple[bytes, tuple[tuple[int, bytes], ...], tuple[tuple[int, bytes, bytes], ...], tuple[tuple[int, int, bytes], ...], tuple[ArtifactSemanticRange, ...]]:
    """Complete AAPCS64 lowering for the general-language target.

    The optimized legacy path keeps scalar SSA values register-resident.  This
    path intentionally uses ABI-layout frame slots for every machine value so
    arbitrary products/sums, HFA values, >16-byte composites, foreign heap
    views, and cross-call copies all have one uniform physical representation.
    """
    graph_object, parameter_types, return_types = _decode_function_interface(function, resolve)
    graph = parse_function_graph(function, resolve)

    machine_parameter_types = tuple(cid for cid in parameter_types if not _is_proof_type(resolve(cid)))
    own_elided = borrowed_view_returns(parameter_types, return_types, resolve)
    machine_return_types = tuple(cid for index, cid in enumerate(return_types) if not _is_proof_type(resolve(cid)) and index not in own_elided)
    if len(machine_return_types) > 1:
        fail("XAX.AARCH64.ABI", function.cid.hex(), "AARCH64-ABI-RETURNS", "at most one machine return", len(machine_return_types))

    # Validate all operations before layout so target declarations cannot claim
    # code generation that this backend does not actually implement.
    for block in graph.blocks:
        for node in block.nodes:
            if node.operation not in target.supported_operations:
                fail("XAX.AARCH64.UNSUPPORTED_OPERATION", graph_object.cid.hex(), "AARCH64-OP-TARGET-SUPPORTED", list(target.supported_operations), node.operation)
        if block.terminator.kind not in target.supported_terminators:
            fail("XAX.AARCH64.UNSUPPORTED_TERMINATOR", graph_object.cid.hex(), "AARCH64-TERMINATOR-TARGET-SUPPORTED", list(target.supported_terminators), block.terminator.kind)

    # Maximum ABI stack argument area.  Keep it at frame offset zero so SP at a
    # call already points at the AAPCS64 outgoing argument area.
    outgoing_size = 0
    call_ref_copy_specs: list[tuple[tuple[int, int, int], bytes]] = []
    for block_index, block in enumerate(graph.blocks):
        for node_index, node in enumerate(block.nodes):
            if node.operation not in (Operation.CALL_DIRECT, Operation.CALL_FOREIGN, Operation.CALL_INDIRECT):
                continue
            pairs = [(i, cid) for i, cid in enumerate(node.operand_types) if not _is_proof_type(resolve(cid))]
            if node.operation == Operation.CALL_INDIRECT:
                pairs = pairs[1:]
            plan, stack_bytes = _abi_argument_plan([cid for _, cid in pairs], resolve)
            outgoing_size = max(outgoing_size, stack_bytes)
            for (operand_index, cid), location in zip(pairs, plan):
                if _abi_class(resolve, cid)[0] == "ref":
                    call_ref_copy_specs.append(((block_index, node_index, operand_index), cid))

    cursor = outgoing_size

    # Explicit stack objects are real semantic storage.  Value slots follow.
    stack_object_offsets: dict[ValueRef, int] = {}
    for block_index, block in enumerate(graph.blocks):
        for node_index, node in enumerate(block.nodes):
            if node.operation == Operation.STACK_ALLOC:
                extent, alignment = node.attributes
                cursor = _align(cursor, alignment)
                stack_object_offsets[ValueRef.node_result(block_index, node_index, 0)] = cursor
                cursor += extent

    slots: dict[ValueRef, int] = {}
    layouts: dict[ValueRef, object] = {}
    values: list[tuple[ValueRef, object]] = []
    for block_index, block in enumerate(graph.blocks):
        for index, cid in enumerate(block.parameters):
            if not _is_proof_type(resolve(cid)):
                values.append((ValueRef.parameter(block_index, index), abi_layout(resolve(cid), resolve)))
        for node_index, node in enumerate(block.nodes):
            for result_index, cid in enumerate(node.results):
                if not _is_proof_type(resolve(cid)):
                    values.append((ValueRef.node_result(block_index, node_index, result_index), abi_layout(resolve(cid), resolve)))
    # Values share a slot only when their conservative live hulls are
    # disjoint (ADR-123).  A node's operands and results always overlap, so
    # lowerings that write a result before their last operand read stay exact.
    # Profiles whose committed artifacts predate ADR-123 keep one slot per
    # value, so their executed evidence stays byte-identical.
    share = target.identity in AARCH64_LINUX_IDENTITIES
    intervals = _frame_live_hulls(graph, {ref for ref, _layout in values}) if share else {}
    free: dict[tuple[int, int], list[tuple[int, int]]] = {}
    ordered = sorted(values, key=lambda item: (intervals[item[0]][0], item[0].tag, item[0].block, item[0].index, item[0].result)) if share else values
    for ref, layout in ordered:
        start, end = intervals[ref] if share else (0, 0)
        key = (_slot_size(layout), max(8, layout.alignment))
        candidates = free.setdefault(key, [])
        reuse = next((position for position, (offset, busy_until) in enumerate(candidates) if busy_until < start), None) if share else None
        if reuse is None:
            cursor = _align(cursor, key[1])
            offset = cursor
            cursor += key[0]
            candidates.append((offset, end))
        else:
            offset = candidates[reuse][0]
            candidates[reuse] = (offset, end)
        slots[ref] = offset
        layouts[ref] = layout

    # Whole-edge temporary area makes CFG parameter assignment a true parallel
    # copy even for overlapping aggregate values.
    edge_temp_size = max(
        (
            sum(_slot_size(abi_layout(resolve(cid), resolve)) for cid in block.parameters if not _is_proof_type(resolve(cid)))
            for block in graph.blocks
        ),
        default=0,
    )
    edge_temp_base = _align(cursor, 8)
    cursor = edge_temp_base + edge_temp_size

    call_ref_copies: dict[tuple[int, int, int], int] = {}
    for key, cid in call_ref_copy_specs:
        layout = abi_layout(resolve(cid), resolve)
        cursor = _align(cursor, max(8, layout.alignment))
        call_ref_copies[key] = cursor
        cursor += _slot_size(layout)

    has_call = any(
        node.operation in (Operation.CALL_FOREIGN, Operation.CALL_INDIRECT)
        or (node.operation == Operation.CALL_DIRECT and not _is_erased_proof_function(node.entity, resolve))
        for block in graph.blocks for node in block.nodes
    )
    link_slot = None
    if has_call:
        cursor = _align(cursor, 8)
        link_slot = cursor
        cursor += 8

    hidden_return = bool(machine_return_types) and _abi_class(resolve, machine_return_types[0])[0] == "ref"
    return_pointer_slot = None
    if hidden_return:
        cursor = _align(cursor, 8)
        return_pointer_slot = cursor
        cursor += 8

    frame_size = _align(cursor, target.stack_alignment) if cursor else 0
    if frame_size >= 4096:
        fail("XAX.AARCH64.FRAME", graph_object.cid.hex(), "AARCH64-FRAME-SIZE", "< 4096 bytes", frame_size)

    assembler = _Assembler()
    emit = assembler.emit
    if frame_size:
        emit(_add_sub_sp(True, frame_size))
    if has_call:
        assert link_slot is not None
        emit(_load_store(False, 30, link_slot, 64))
    if hidden_return:
        assert return_pointer_slot is not None
        emit(_load_store(False, 8, return_pointer_slot, 64))

    def slot(ref: ValueRef) -> int:
        try:
            return slots[ref]
        except KeyError:
            fail("XAX.AARCH64.VALUE", graph_object.cid.hex(), "AARCH64-VALUE-SLOT", "machine value", [ref.block, ref.index, ref.result])

    def cid_layout(cid: bytes):
        return abi_layout(resolve(cid), resolve)

    def load_gpr(ref: ValueRef, register: int, cid: bytes | None = None) -> None:
        type_cid = cid or _value_type_for_ref(graph, ref)
        layout = cid_layout(type_cid)
        for word in _load_register_bytes(register, _SP, slot(ref), min(layout.size, 8)):
            emit(word)

    def store_gpr(ref: ValueRef, register: int, cid: bytes | None = None) -> None:
        type_cid = cid or _value_type_for_ref(graph, ref)
        layout = cid_layout(type_cid)
        for word in _zero_memory(_SP, slot(ref), _slot_size(layout)):
            emit(word)
        for word in _store_register_bytes(register, _SP, slot(ref), min(layout.size, 8)):
            emit(word)

    # Entry ABI -> semantic frame slots.
    parameter_refs = [
        (ValueRef.parameter(graph.entry, index), cid)
        for index, cid in enumerate(graph.blocks[graph.entry].parameters)
        if not _is_proof_type(resolve(cid))
    ]
    entry_plan, _entry_stack = _abi_argument_plan([cid for _, cid in parameter_refs], resolve)
    for (ref, cid), location in zip(parameter_refs, entry_plan):
        kind, place, count, member = location
        layout = cid_layout(cid)
        destination = slot(ref)
        for word in _zero_memory(_SP, destination, _slot_size(layout)):
            emit(word)
        if kind == "gpr":
            for word in _store_register_bytes(place, _SP, destination, layout.size):
                emit(word)
        elif kind == "gpr2":
            for word in _store_register_bytes(place, _SP, destination, min(8, layout.size)):
                emit(word)
            if layout.size > 8:
                for word in _store_register_bytes(place + 1, _SP, destination + 8, layout.size - 8):
                    emit(word)
        elif kind == "fpr":
            emit(_fp_access(False, place, _SP, destination, member))
        elif kind == "hfa":
            for index in range(count):
                emit(_fp_access(False, place + index, _SP, destination + index * member, member))
        elif kind == "ref":
            for word in _copy_memory(_SP, destination, place, 0, layout.size):
                emit(word)
        else:
            source = frame_size + place
            stack_code = count
            if stack_code == 4:  # pointer to caller copy
                emit(_base_access(True, _TEMP, _SP, source, 8))
                for word in _copy_memory(_SP, destination, _TEMP, 0, layout.size):
                    emit(word)
            else:
                for word in _copy_memory(_SP, destination, _SP, source, layout.size):
                    emit(word)

    if graph.entry:
        assembler.branch(f"block-{graph.entry}")

    node_ranges: list[ArtifactSemanticRange] = []

    def value_type(ref: ValueRef) -> bytes:
        return _value_type_for_ref(graph, ref)

    def copy_ref(destination_ref: ValueRef, source_ref: ValueRef, size: int | None = None) -> None:
        amount = size if size is not None else layouts[destination_ref].size
        for word in _copy_memory(_SP, slot(destination_ref), _SP, slot(source_ref), amount):
            emit(word)

    def memory_base(pointer_ref: ValueRef) -> int:
        load_gpr(pointer_ref, _TEMP)
        return _TEMP

    def emit_checked_index(pointer_ref: ValueRef, index_ref: ValueRef, maximum: int) -> int:
        index_width = decode_bits_width(resolve(value_type(index_ref)))
        load_gpr(index_ref, _TEMP2)
        if index_width < 64:
            for word in _mask_register_words(_TEMP2, index_width):
                emit(word)
        ok = f"memory-check-{pointer_ref.block}-{pointer_ref.index}-{index_ref.block}-{index_ref.index}-{len(assembler.code)}"
        if maximum <= 4095:
            emit(_cmp_immediate(_TEMP2, maximum, 64))
        else:
            for word in _move_immediate(_TEMP, maximum, 64):
                emit(word)
            emit(_cmp_registers(_TEMP2, _TEMP, 64))
        assembler.bcond(_COND["ls"], ok)
        emit(_brk(_BRK_MEMORY_CHECK))
        assembler.label(ok)
        load_gpr(pointer_ref, _TEMP)
        emit(_add_registers(_TEMP, _TEMP, _TEMP2))
        return _TEMP

    def marshal_call(
        block_index: int,
        node_index: int,
        operands: list[tuple[int, ValueRef, bytes]],
        result: tuple[ValueRef, bytes] | None,
        *,
        indirect: ValueRef | None = None,
        direct: bytes | None = None,
        foreign: tuple[bytes, bytes] | None = None,
    ) -> None:
        type_cids = [cid for _, _, cid in operands]
        plan, _stack_bytes = _abi_argument_plan(type_cids, resolve)
        for (operand_index, ref, cid), location in zip(operands, plan):
            kind, place, count, member = location
            layout = cid_layout(cid)
            source = slot(ref)
            if _abi_class(resolve, cid)[0] == "ref":
                copy_at = call_ref_copies[(block_index, node_index, operand_index)]
                for word in _copy_memory(_SP, copy_at, _SP, source, layout.size):
                    emit(word)
                source = copy_at
            if kind == "gpr":
                for word in _load_register_bytes(place, _SP, source, layout.size):
                    emit(word)
            elif kind == "gpr2":
                for word in _load_register_bytes(place, _SP, source, min(8, layout.size)):
                    emit(word)
                if layout.size > 8:
                    for word in _load_register_bytes(place + 1, _SP, source + 8, layout.size - 8):
                        emit(word)
            elif kind == "fpr":
                emit(_fp_access(True, place, _SP, source, member))
            elif kind == "hfa":
                for i in range(count):
                    emit(_fp_access(True, place + i, _SP, source + i * member, member))
            elif kind == "ref":
                emit(_address_from_sp(place, source))
            else:
                stack_code = count
                if stack_code == 4:
                    emit(_address_from_sp(_TEMP, source))
                    emit(_base_access(False, _TEMP, _SP, place, 8))
                else:
                    for word in _copy_memory(_SP, place, _SP, source, layout.size):
                        emit(word)

        if result is not None and _abi_class(resolve, result[1])[0] == "ref":
            emit(_address_from_sp(8, slot(result[0])))

        if indirect is not None:
            load_gpr(indirect, _TEMP2)
            emit(_blr(_TEMP2))
        elif direct is not None:
            assembler.call(direct)
        else:
            assert foreign is not None
            assembler.foreign_call(*foreign)

        if result is None:
            return
        result_ref, cid = result
        kind, count, member = _abi_class(resolve, cid)
        layout = cid_layout(cid)
        destination = slot(result_ref)
        if kind == "ref":
            return  # callee wrote directly through x8
        for word in _zero_memory(_SP, destination, _slot_size(layout)):
            emit(word)
        if kind == "gpr":
            for word in _store_register_bytes(0, _SP, destination, layout.size):
                emit(word)
        elif kind == "gpr2":
            for word in _store_register_bytes(0, _SP, destination, min(8, layout.size)):
                emit(word)
            if layout.size > 8:
                for word in _store_register_bytes(1, _SP, destination + 8, layout.size - 8):
                    emit(word)
        elif kind == "fpr":
            emit(_fp_access(False, 0, _SP, destination, member))
        elif kind == "hfa":
            for i in range(count):
                emit(_fp_access(False, i, _SP, destination + i * member, member))

    for block_index, block in enumerate(graph.blocks):
        assembler.label(f"block-{block_index}")
        for node_index, node in enumerate(block.nodes):
            start = len(assembler.code)
            result0 = ValueRef.node_result(block_index, node_index, 0)

            if node.operation in (Operation.ADD_WRAP, Operation.SUB_WRAP, Operation.MUL_WRAP):
                width = decode_bits_width(resolve(node.results[0]))
                load_gpr(node.operands[0], _TEMP)
                load_gpr(node.operands[1], _TEMP2)
                arithmetic_width = 32 if width <= 32 else 64
                emit(_arithmetic(node.operation, _TEMP, _TEMP, _TEMP2, arithmetic_width))
                for word in _mask_register_words(_TEMP, width):
                    emit(word)
                store_gpr(result0, _TEMP, node.results[0])

            elif node.operation in _INTEGER_COMPLETION_BINARY:
                # Integer completion (ADR-084 on AArch64, ADR-123): operands are
                # zero-extended in their slots, so bitwise results need no mask.
                width = decode_bits_width(resolve(node.results[0]))
                wide = width > 32
                load_gpr(node.operands[0], _TEMP)
                load_gpr(node.operands[1], _TEMP2)
                if node.operation in (Operation.UDIV, Operation.UREM):
                    ok = f"divisor-nonzero-{block_index}-{node_index}"
                    assembler.cbnz(_TEMP2, ok, wide)
                    emit(_brk(_BRK_DIVIDE_BY_ZERO))
                    assembler.label(ok)
                    if node.operation == Operation.UDIV:
                        emit(_udiv(_TEMP, _TEMP, _TEMP2, wide))
                    else:
                        emit(_udiv(_REMAINDER_TEMP, _TEMP, _TEMP2, wide))
                        emit(_msub(_TEMP, _REMAINDER_TEMP, _TEMP2, _TEMP, wide))
                else:
                    emit(_logical(node.operation, _TEMP, _TEMP, _TEMP2, wide))
                store_gpr(result0, _TEMP, node.results[0])

            elif node.operation in (Operation.INT_TRUNCATE, Operation.INT_ZERO_EXTEND):
                load_gpr(node.operands[0], _TEMP, node.operand_types[0])
                for word in _mask_register_words(_TEMP, decode_bits_width(resolve(node.results[0]))):
                    emit(word)
                store_gpr(result0, _TEMP, node.results[0])

            elif node.operation == Operation.ROTATE_RIGHT:
                width = decode_bits_width(resolve(node.results[0]))
                amount = node.attributes[0]
                load_gpr(node.operands[0], _TEMP)
                if amount:
                    # (v >> a) | (v << (w - a)), then the exact w-bit mask.
                    emit(_lsr(_TEMP2, _TEMP, amount))
                    emit(_lsl(_TEMP, _TEMP, width - amount))
                    emit(_logical(Operation.BIT_OR, _TEMP, _TEMP, _TEMP2, True))
                    for word in _mask_register_words(_TEMP, width):
                        emit(word)
                store_gpr(result0, _TEMP, node.results[0])

            elif node.operation == Operation.CONSTANT:
                cid, value = _decode_constant(node.entity, resolve)
                if _type_form(resolve, cid) == 7:
                    raw = _float_raw_bits(value, decode_float_width(resolve(cid)))
                    for word in _move_immediate(_TEMP, raw, decode_float_width(resolve(cid))):
                        emit(word)
                else:
                    for word in _move_immediate(_TEMP, int(value), min(64, max(32, decode_bits_width(resolve(cid))))):
                        emit(word)
                store_gpr(result0, _TEMP, cid)

            elif node.operation in (Operation.FLOAT_ADD, Operation.FLOAT_SUB, Operation.FLOAT_MUL, Operation.FLOAT_DIV):
                width = decode_float_width(resolve(node.results[0]))
                load_gpr(node.operands[0], _TEMP)
                emit(_fmov_to_fp(_FP_TEMP, _TEMP, width))
                load_gpr(node.operands[1], _TEMP2)
                emit(_fmov_to_fp(_FP_TEMP2, _TEMP2, width))
                emit(_float_binary(node.operation, _FP_TEMP, _FP_TEMP, _FP_TEMP2, width))
                emit(_fmov_from_fp(_TEMP, _FP_TEMP, width))
                store_gpr(result0, _TEMP, node.results[0])

            elif node.operation == Operation.FLOAT_COMPARE:
                width = decode_float_width(resolve(node.operand_types[0]))
                load_gpr(node.operands[0], _TEMP)
                emit(_fmov_to_fp(_FP_TEMP, _TEMP, width))
                load_gpr(node.operands[1], _TEMP2)
                emit(_fmov_to_fp(_FP_TEMP2, _TEMP2, width))
                emit(_fcmp(_FP_TEMP, _FP_TEMP2, width))
                emit(_cset(_TEMP, _FLOAT_CONDITION[FloatCompare(node.attributes[0])]))
                store_gpr(result0, _TEMP, node.results[0])

            elif node.operation == Operation.INT_COMPARE:
                width = decode_bits_width(resolve(node.operand_types[0]))
                load_gpr(node.operands[0], _TEMP)
                load_gpr(node.operands[1], _TEMP2)
                kind = IntCompare(node.attributes[0])
                if kind in (IntCompare.SLT, IntCompare.SLE, IntCompare.SGT, IntCompare.SGE) and width < 64:
                    emit(_sbfx(_TEMP, _TEMP, 0, width))
                    emit(_sbfx(_TEMP2, _TEMP2, 0, width))
                emit(_cmp_registers(_TEMP, _TEMP2, 32 if width <= 32 else 64))
                emit(_cset(_TEMP, _INT_CONDITION[kind]))
                store_gpr(result0, _TEMP, node.results[0])

            elif node.operation in (Operation.UINT_TO_FLOAT, Operation.SINT_TO_FLOAT):
                source_width = decode_bits_width(resolve(node.operand_types[0]))
                float_width = decode_float_width(resolve(node.results[0]))
                load_gpr(node.operands[0], _TEMP)
                signed = node.operation == Operation.SINT_TO_FLOAT
                if signed and source_width < 64:
                    emit(_sbfx(_TEMP, _TEMP, 0, source_width))
                elif not signed and source_width < 64:
                    for word in _mask_register_words(_TEMP, source_width):
                        emit(word)
                emit(_int_to_fp(_FP_TEMP, _TEMP, float_width, True, signed))
                emit(_fmov_from_fp(_TEMP, _FP_TEMP, float_width))
                store_gpr(result0, _TEMP, node.results[0])

            elif node.operation in (Operation.FLOAT_TO_UINT_TRUNC, Operation.FLOAT_TO_SINT_TRUNC):
                in_width = decode_float_width(resolve(node.operand_types[0]))
                out_width = decode_bits_width(resolve(node.results[0]))
                signed = node.operation == Operation.FLOAT_TO_SINT_TRUNC
                load_gpr(node.operands[0], _TEMP)
                emit(_fmov_to_fp(_FP_TEMP, _TEMP, in_width))
                trap = f"float-convert-trap-{block_index}-{node_index}"
                done = f"float-convert-done-{block_index}-{node_index}"

                def compare_threshold(value: float) -> None:
                    raw = _float_raw_bits(value, in_width)
                    for word in _move_immediate(_TEMP2, raw, in_width):
                        emit(word)
                    emit(_fmov_to_fp(_FP_TEMP2, _TEMP2, in_width))
                    emit(_fcmp(_FP_TEMP, _FP_TEMP2, in_width))

                # NaN is unordered and must trap for every integer conversion.
                compare_threshold(0.0)
                assembler.bcond(_COND["vs"], trap)
                if signed:
                    lower = -(1 << (out_width - 1))
                    if _int_to_float(lower - 1, in_width) == lower - 1:
                        compare_threshold(float(lower - 1))
                        assembler.bcond(_COND["le"], trap)
                    else:
                        compare_threshold(float(lower))
                        assembler.bcond(_COND["mi"], trap)
                    compare_threshold(float(1 << (out_width - 1)))
                    assembler.bcond(_COND["ge"], trap)
                else:
                    compare_threshold(0.0)
                    assembler.bcond(_COND["mi"], trap)
                    compare_threshold(float(1 << out_width))
                    assembler.bcond(_COND["ge"], trap)
                emit(_fp_to_int64(_TEMP, _FP_TEMP, in_width, signed))
                for word in _mask_register_words(_TEMP, out_width):
                    emit(word)
                store_gpr(result0, _TEMP, node.results[0])
                assembler.branch(done)
                assembler.label(trap)
                emit(_brk(_BRK_FLOAT_CONVERSION))
                assembler.label(done)

            elif node.operation == Operation.FLOAT_CONVERT:
                source_width = decode_float_width(resolve(node.operand_types[0]))
                destination_width = decode_float_width(resolve(node.results[0]))
                load_gpr(node.operands[0], _TEMP)
                emit(_fmov_to_fp(_FP_TEMP, _TEMP, source_width))
                if source_width != destination_width:
                    emit(_fcvt(_FP_TEMP, _FP_TEMP, source_width))
                emit(_fmov_from_fp(_TEMP, _FP_TEMP, destination_width))
                store_gpr(result0, _TEMP, node.results[0])

            elif node.operation == Operation.AGGREGATE_MAKE:
                layout = layouts[result0]
                for word in _zero_memory(_SP, slot(result0), _slot_size(layout)):
                    emit(word)
                for operand, offset in zip(node.operands, layout.offsets):
                    for word in _copy_memory(_SP, slot(result0) + offset, _SP, slot(operand), layouts[operand].size):
                        emit(word)

            elif node.operation == Operation.AGGREGATE_GET:
                source = node.operands[0]
                offset = layouts[source].offsets[node.attributes[0]]
                for word in _zero_memory(_SP, slot(result0), _slot_size(layouts[result0])):
                    emit(word)
                for word in _copy_memory(_SP, slot(result0), _SP, slot(source) + offset, layouts[result0].size):
                    emit(word)

            elif node.operation == Operation.SUM_MAKE:
                layout = layouts[result0]
                for word in _zero_memory(_SP, slot(result0), _slot_size(layout)):
                    emit(word)
                for word in _move_immediate(_TEMP, node.attributes[0], 32):
                    emit(word)
                emit(_base_access(False, _TEMP, _SP, slot(result0), 4))
                for word in _copy_memory(_SP, slot(result0) + layout.payload_offset, _SP, slot(node.operands[0]), layouts[node.operands[0]].size):
                    emit(word)

            elif node.operation == Operation.SUM_TAG:
                emit(_base_access(True, _TEMP, _SP, slot(node.operands[0]), 4))
                store_gpr(result0, _TEMP, node.results[0])

            elif node.operation == Operation.SUM_GET:
                source = node.operands[0]
                ok = f"sum-get-ok-{block_index}-{node_index}"
                emit(_base_access(True, _TEMP, _SP, slot(source), 4))
                emit(_cmp_immediate(_TEMP, node.attributes[0], 32))
                assembler.bcond(_COND["eq"], ok)
                emit(_brk(_BRK_SUM_VARIANT))
                assembler.label(ok)
                for word in _zero_memory(_SP, slot(result0), _slot_size(layouts[result0])):
                    emit(word)
                for word in _copy_memory(_SP, slot(result0), _SP, slot(source) + layouts[source].payload_offset, layouts[result0].size):
                    emit(word)

            elif node.operation == Operation.FUNCTION_ADDRESS:
                assembler.address(_TEMP, node.entity.cid)
                store_gpr(result0, _TEMP, node.results[0])

            elif node.operation in (Operation.CALL_DIRECT, Operation.CALL_FOREIGN, Operation.CALL_INDIRECT):
                machine = [
                    (index, operand, cid)
                    for index, (operand, cid) in enumerate(zip(node.operands, node.operand_types))
                    if not _is_proof_type(resolve(cid))
                ]
                indirect_ref = None
                if node.operation == Operation.CALL_INDIRECT:
                    _, indirect_ref, _ = machine.pop(0)
                call_elided = borrowed_view_returns(node.operand_types, node.results, resolve) if node.operation == Operation.CALL_DIRECT else {}
                machine_results = [
                    (ValueRef.node_result(block_index, node_index, i), cid)
                    for i, cid in enumerate(node.results) if not _is_proof_type(resolve(cid)) and i not in call_elided
                ]
                if len(machine_results) > 1:
                    fail("XAX.AARCH64.ABI", graph_object.cid.hex(), "AARCH64-CALL-RETURNS", "at most one machine return", len(machine_results))
                if node.operation == Operation.CALL_DIRECT and _is_erased_proof_function(node.entity, resolve):
                    pass
                elif node.operation == Operation.CALL_DIRECT:
                    marshal_call(block_index, node_index, machine, machine_results[0] if machine_results else None, direct=node.entity.cid)
                    for result_index, parameter_index in call_elided.items():
                        copy_ref(ValueRef.node_result(block_index, node_index, result_index), node.operands[parameter_index])
                elif node.operation == Operation.CALL_FOREIGN:
                    declaration = decode_foreign_function(node.entity)
                    _require_foreign_abi(declaration, target, graph_object)
                    marshal_call(block_index, node_index, machine, machine_results[0] if machine_results else None, foreign=(declaration.library, declaration.name))
                else:
                    marshal_call(block_index, node_index, machine, machine_results[0] if machine_results else None, indirect=indirect_ref)

            elif node.operation == Operation.TARGET_OP and decode_native_target(node.entity).identity == BOARD_IDENTITY:
                # Board register and instruction operations (ADR-128): the
                # operand (if any) is loaded into x16, a result comes back in x16.
                from xax_board import board_operation_words

                if target.identity != BOARD_IDENTITY:
                    fail("XAX.AARCH64.TARGET_OP", graph_object.cid.hex(), "AARCH64-TARGET-OP-PACKAGE", "the board being compiled for", target.identity.decode("ascii", "replace"))
                contract = next(item for item in decode_native_target(node.entity).target_operations if item.operation_id == node.attributes[0])
                machine_operands = [operand for operand, cid in zip(node.operands, node.operand_types) if not _is_proof_type(resolve(cid))]
                machine_results = [ValueRef.node_result(block_index, node_index, i) for i, cid in enumerate(node.results) if not _is_proof_type(resolve(cid))]
                if machine_operands:
                    load_gpr(machine_operands[0], _TEMP)
                for word in board_operation_words(contract.semantic_code, contract.encoding_opcode, _TEMP, _TEMP2):
                    emit(word)
                if machine_results:
                    store_gpr(machine_results[0], _TEMP, node.results[0])

            elif node.operation == Operation.TARGET_OP:
                description = decode_native_target(node.entity)
                if description.identity not in ANDROID_ARM64_SHARED_IDENTITIES:
                    fail("XAX.AARCH64.TARGET_OP", graph_object.cid.hex(), "AARCH64-TARGET-OP-PACKAGE", [item.decode("ascii", "replace") for item in ANDROID_ARM64_SHARED_IDENTITIES], description.identity.decode("ascii", "replace"))
                operation_id = node.attributes[0]
                contract = next(item for item in description.target_operations if item.operation_id == operation_id)
                machine_operands = [operand for operand, cid in zip(node.operands, node.operand_types) if not _is_proof_type(resolve(cid))]
                machine_results = [ValueRef.node_result(block_index, node_index, i) for i, cid in enumerate(node.results) if not _is_proof_type(resolve(cid))]
                if operation_id in {ANDROID_JNI_REFERENCE_WORD_BORROWED_OPERATION, ANDROID_JNI_REFERENCE_WORD_LOCAL_OPERATION, ANDROID_JNI_REFERENCE_WORD_GLOBAL_OPERATION}:
                    copy_ref(machine_results[0], machine_operands[0])
                else:
                    load_gpr(machine_operands[0], _TEMP)
                    emit(_load_from_register(_TEMP, _TEMP, contract.encoding_opcode, 64 if cid_layout(value_type(machine_results[0])).size == 8 else 32))
                    store_gpr(machine_results[0], _TEMP)

            elif node.operation == Operation.STACK_ALLOC:
                address = stack_object_offsets[result0]
                emit(_address_from_sp(_TEMP, address))
                store_gpr(result0, _TEMP, node.results[0])

            elif node.operation == Operation.ADDRESS_OFFSET:
                load_gpr(node.operands[0], _TEMP)
                offset = node.attributes[0]
                if offset < 4096:
                    emit(_add_immediate(_TEMP, _TEMP, offset))
                else:
                    for word in _move_immediate(_TEMP2, offset, 64):
                        emit(word)
                    emit(_add_registers(_TEMP, _TEMP, _TEMP2))
                store_gpr(result0, _TEMP, node.results[0])

            elif node.operation == Operation.POINTER_CAST:
                copy_ref(result0, node.operands[0])

            elif node.operation == Operation.POINTER_ADDRESS:
                copy_ref(result0, node.operands[0])

            elif node.operation == Operation.POINTER_REBASE:
                # ADR-092 on AArch64 (ADR-126): trap unless 0 <= address - view
                # <= span and the distance is a multiple of the alignment; the
                # rotate folds both tests into one unsigned compare.
                view, address = node.operands
                span = pointer_extent_from_graph(graph, view, resolve) - node.attributes[0]
                shift = _decode_pointer_type(resolve(node.results[0]), resolve)[2].bit_length() - 1
                load_gpr(address, _TEMP)
                load_gpr(view, _TEMP2)
                emit(0xCB000000 | (_TEMP2 << 16) | (_TEMP << 5) | _REMAINDER_TEMP)  # sub x9, address, view
                if shift:
                    emit(0x93C00000 | (_REMAINDER_TEMP << 16) | (shift << 10) | (_REMAINDER_TEMP << 5) | _REMAINDER_TEMP)  # ror x9, x9, #shift
                for word in _move_immediate(_TEMP2, max(span, 0) >> shift, 64):
                    emit(word)
                ok = f"rebase-in-range-{block_index}-{node_index}"
                emit(_cmp_registers(_REMAINDER_TEMP, _TEMP2, 64))
                if span >= 0:
                    assembler.bcond(_COND["ls"], ok)
                emit(_brk(_BRK_MEMORY_CHECK))
                assembler.label(ok)
                store_gpr(result0, _TEMP, node.results[0])

            elif node.operation == Operation.HEAP_VIEW:
                # The allocator contract is nullable.  Producing a proven heap
                # view establishes non-null provenance, so that proof must be
                # backed by an explicit runtime trap rather than an assumption.
                load_gpr(node.operands[0], _TEMP)
                nonnull = f"heap-view-nonnull-{block_index}-{node_index}"
                emit(_cmp_immediate(_TEMP, 0, 64))
                assembler.bcond(_COND["ne"], nonnull)
                emit(_brk(_BRK_NULL_HEAP))
                assembler.label(nonnull)
                store_gpr(result0, _TEMP, node.results[0])

            elif node.operation in (Operation.LOAD_BITS_LE, Operation.RAW_LOAD_BITS_LE):
                size = node.attributes[0]
                if size not in (1, 2, 4, 8):
                    fail("XAX.AARCH64.MEMORY_WIDTH", graph_object.cid.hex(), "AARCH64-MEMORY-WIDTH", [1, 2, 4, 8], size)
                base = memory_base(node.operands[0])
                emit(_base_access(True, _TEMP2, base, 0, size))
                store_gpr(result0, _TEMP2, node.results[0])

            elif node.operation == Operation.STORE_BITS_LE:
                size = node.attributes[0]
                if size not in (1, 2, 4, 8):
                    fail("XAX.AARCH64.MEMORY_WIDTH", graph_object.cid.hex(), "AARCH64-MEMORY-WIDTH", [1, 2, 4, 8], size)
                base = memory_base(node.operands[0])
                load_gpr(node.operands[1], _TEMP2)
                emit(_base_access(False, _TEMP2, base, 0, size))

            elif node.operation == Operation.CHECKED_LOAD_BITS_LE:
                size, _alignment = node.attributes
                # Extent is statically carried by stack allocation or heap view.
                extent = pointer_extent_from_graph(graph, node.operands[0], resolve)
                maximum = extent - size
                if maximum < 0:
                    emit(_brk(_BRK_MEMORY_CHECK))
                else:
                    base = emit_checked_index(node.operands[0], node.operands[1], maximum)
                    emit(_base_access(True, _TEMP2, base, 0, size))
                    store_gpr(result0, _TEMP2, node.results[0])

            elif node.operation == Operation.CHECKED_STORE_BITS_LE:
                size, _alignment = node.attributes
                extent = pointer_extent_from_graph(graph, node.operands[0], resolve)
                maximum = extent - size
                if maximum < 0:
                    emit(_brk(_BRK_MEMORY_CHECK))
                else:
                    base = emit_checked_index(node.operands[0], node.operands[1], maximum)
                    load_gpr(node.operands[2], _TEMP2)
                    emit(_base_access(False, _TEMP2, base, 0, size))

            elif node.operation == Operation.STACK_END or node.operation in RESOURCE_EFFECT_OPERATIONS:
                pass

            else:
                fail("XAX.AARCH64.UNSUPPORTED_OPERATION", graph_object.cid.hex(), "AARCH64-OP-LOWERED", list(target.supported_operations), node.operation)

            end = len(assembler.code)
            if end > start:
                node_ranges.append(ArtifactSemanticRange(function.cid, block_index, node_index, start, end))

        term = block.terminator
        if term.kind == TerminatorKind.RETURN:
            machine_values = [(value, cid) for index, (value, cid) in enumerate(zip(term.values, return_types)) if not _is_proof_type(resolve(cid)) and index not in own_elided]
            if machine_values:
                value, cid = machine_values[0]
                kind, count, member = _abi_class(resolve, cid)
                layout = cid_layout(cid)
                source = slot(value)
                if kind == "gpr":
                    for word in _load_register_bytes(0, _SP, source, layout.size):
                        emit(word)
                elif kind == "gpr2":
                    for word in _load_register_bytes(0, _SP, source, min(8, layout.size)):
                        emit(word)
                    if layout.size > 8:
                        for word in _load_register_bytes(1, _SP, source + 8, layout.size - 8):
                            emit(word)
                elif kind == "fpr":
                    emit(_fp_access(True, 0, _SP, source, member))
                elif kind == "hfa":
                    for i in range(count):
                        emit(_fp_access(True, i, _SP, source + i * member, member))
                else:
                    assert return_pointer_slot is not None
                    emit(_load_store(True, _TEMP, return_pointer_slot, 64))
                    for word in _copy_memory(_TEMP, 0, _SP, source, layout.size):
                        emit(word)
            if has_call:
                assert link_slot is not None
                emit(_load_store(True, 30, link_slot, 64))
            if frame_size:
                emit(_add_sub_sp(False, frame_size))
            emit(0xD65F03C0)

        elif term.kind in (TerminatorKind.BRANCH, TerminatorKind.CONDITIONAL_BRANCH):
            def edge_copy(target_block: int, arguments: tuple[ValueRef, ...]) -> None:
                temp = edge_temp_base
                placements: list[tuple[int, ValueRef, int]] = []
                for index, argument in enumerate(arguments):
                    destination = ValueRef.parameter(target_block, index)
                    if argument not in slots or destination not in slots:
                        continue
                    size = layouts[destination].size
                    for word in _copy_memory(_SP, temp, _SP, slot(argument), size):
                        emit(word)
                    placements.append((temp, destination, size))
                    temp += _slot_size(layouts[destination])
                for temporary, destination, size in placements:
                    for word in _copy_memory(_SP, slot(destination), _SP, temporary, size):
                        emit(word)

            if term.kind == TerminatorKind.BRANCH:
                target_block, arguments = term.edges[0]
                edge_copy(target_block, arguments)
                assembler.branch(f"block-{target_block}")
            else:
                load_gpr(term.values[0], _TEMP)
                false_label = f"false-{block_index}"
                assembler.cbz(_TEMP, false_label)
                target_block, arguments = term.edges[0]
                edge_copy(target_block, arguments)
                assembler.branch(f"block-{target_block}")
                assembler.label(false_label)
                target_block, arguments = term.edges[1]
                edge_copy(target_block, arguments)
                assembler.branch(f"block-{target_block}")
        else:
            reason, _ = decode_trap_payload(term.payload)
            for word in _move_immediate(0, reason, 64):
                emit(word)
            emit(_brk(reason))

    return (*assembler.finish()[:4], tuple(node_ranges))


def _value_type_for_ref(graph, ref: ValueRef) -> bytes:
    if ref.tag == 0:
        return graph.blocks[ref.block].parameters[ref.index]
    return graph.blocks[ref.block].nodes[ref.index].results[ref.result]


def _compile_function(
    function: SemanticObject,
    resolve: Callable[[bytes], SemanticObject],
    target: NativeTargetDescription,
    atomic_policy: AtomicLegalizationPolicy = AtomicLegalizationPolicy(),
) -> tuple[bytes, tuple[tuple[int, bytes], ...], tuple[tuple[int, bytes, bytes], ...], tuple[tuple[int, int, bytes], ...], tuple[ArtifactSemanticRange, ...]]:
    graph_object, parameter_types, return_types = _decode_function_interface(function, resolve)
    graph = parse_function_graph(function, resolve)
    for block in graph.blocks:
        for node in block.nodes:
            if node.operation not in ATOMIC_OPERATIONS:
                continue
            capability = atomic_capability(target, *_atomic_node_request(node, resolve))
            selected = select_atomic_legalization(capability, atomic_policy)
            if selected == AtomicSupport.UNSUPPORTED:
                fail(
                    "XAX.AARCH64.ATOMIC_UNSUPPORTED",
                    graph_object.cid.hex(),
                    "AARCH64-ATOMIC-CAPABILITY",
                    [AtomicSupport.NATIVE.name.lower(), AtomicSupport.BOUNDED_SEQUENCE.name.lower()],
                    capability.support.name.lower(),
                )
            if selected == AtomicSupport.RUNTIME_ASSIST:
                fail(
                    "XAX.AARCH64.ATOMIC_RUNTIME_ASSIST",
                    graph_object.cid.hex(),
                    "AARCH64-ATOMIC-RUNTIME-ASSIST-EXPLICIT",
                    "backend-declared explicit assist",
                    capability.runtime_helper.hex() if capability.runtime_helper else "none",
                )
    if _general_aarch64_target(target) and not _register_path_eligible(graph, parameter_types, return_types, resolve):
        return _compile_general_function(function, resolve, target)

    # AArch64 machine values remain in caller-saved registers by default.  The
    # stack is reserved for explicit XAX stack objects, the link register of a
    # real non-leaf function, and values that actually require spilling.
    allocatable_registers = tuple(dict.fromkeys((*target.argument_registers, target.scratch_registers[0])))
    scratch_register = target.scratch_registers[1]
    if not allocatable_registers or scratch_register in allocatable_registers:
        fail(
            "XAX.AARCH64.REGISTERS",
            graph_object.cid.hex(),
            "AARCH64-REGISTER-POOL",
            "nonempty caller-saved pool plus one reserved scratch register",
            [list(allocatable_registers), scratch_register],
        )

    widths: dict[ValueRef, int] = {}
    machine_parameters: dict[int, tuple[ValueRef, ...]] = {}
    for block_index, block in enumerate(graph.blocks):
        params: list[ValueRef] = []
        for index, type_cid in enumerate(block.parameters):
            width = _width(resolve, type_cid)
            if width is None:
                # Effects/resources/proofs are semantic-only values for this
                # native backend and consume no ABI register.
                continue
            if width > 64:
                fail(
                    "XAX.AARCH64.BLOCK_TYPE",
                    graph_object.cid.hex(),
                    "AARCH64-BLOCK-PARAMETER-MACHINE",
                    "bits/pointer<1..64>",
                    width,
                )
            value = ValueRef.parameter(block_index, index)
            widths[value] = width
            params.append(value)
        machine_parameters[block_index] = tuple(params)
        for node_index, node in enumerate(block.nodes):
            for result_index, type_cid in enumerate(node.results):
                width = _width(resolve, type_cid)
                if width and width <= 64:
                    widths[ValueRef.node_result(block_index, node_index, result_index)] = width

    # Explicit stack-object layout remains semantic and is never optimized into
    # compiler-created SSA storage.
    pointers: dict[ValueRef, int] = {}
    explicit_cursor = 0
    for block_index, block in enumerate(graph.blocks):
        for node_index, node in enumerate(block.nodes):
            result = ValueRef.node_result(block_index, node_index)
            if node.operation == Operation.STACK_ALLOC:
                explicit_cursor = _align(explicit_cursor, node.attributes[1])
                pointers[result] = explicit_cursor
                explicit_cursor += node.attributes[0]
            elif node.operation == Operation.ADDRESS_OFFSET:
                pointers[result] = pointers[node.operands[0]] + node.attributes[0]

    has_call = any(
        (node.operation == Operation.CALL_DIRECT and not _is_erased_proof_function(node.entity, resolve))
        or node.operation in (Operation.CALL_FOREIGN, Operation.CALL_INDIRECT)
        for block in graph.blocks
        for node in block.nodes
    )
    cursor = explicit_cursor
    link_slot: int | None = None
    if has_call:
        link_slot = _align(cursor, 8)
        cursor = link_slot + 8
    edge_spill_base = _align(cursor, 8)
    edge_spill_count = max(
        (max(0, len(machine_parameters[index]) - len(allocatable_registers)) for index in range(len(graph.blocks))),
        default=0,
    )
    dynamic_spill_base = edge_spill_base + edge_spill_count * 8

    def uses_for_block(block_index: int) -> dict[ValueRef, tuple[int, ...]]:
        block = graph.blocks[block_index]
        uses: dict[ValueRef, list[int]] = {}
        for node_index, node in enumerate(block.nodes):
            for operand in node.operands:
                if operand in widths:
                    uses.setdefault(operand, []).append(node_index)
        terminator_position = len(block.nodes)
        for value in block.terminator.values:
            if value in widths:
                uses.setdefault(value, []).append(terminator_position)
        for _, arguments in block.terminator.edges:
            for value in arguments:
                if value in widths:
                    uses.setdefault(value, []).append(terminator_position)
        return {value: tuple(positions) for value, positions in uses.items()}

    block_uses = {index: uses_for_block(index) for index in range(len(graph.blocks))}

    # A value used outside its defining block (by dominance) gets one frame
    # "home", written once at its definition and reloaded where needed (as on
    # x86-64, ADR-089).  SSA values never change, so a home is never rewritten.
    defined_in: dict[ValueRef, int] = {value: index for index, values in machine_parameters.items() for value in values}
    for index, block in enumerate(graph.blocks):
        for node_index, node in enumerate(block.nodes):
            for result_index in range(len(node.results)):
                value = ValueRef.node_result(index, node_index, result_index)
                if value in widths:
                    defined_in[value] = index
    homed = sorted(
        {value for index, uses in block_uses.items() for value in uses if defined_in.get(value, index) != index},
        key=lambda value: (value.tag, value.block, value.index, value.result),
    )
    home_offset = {value: dynamic_spill_base + 8 * position for position, value in enumerate(homed)}
    dynamic_spill_base += 8 * len(homed)

    def lower_block(
        block_index: int,
        assembler: _Assembler | None,
        frame_size: int = 0,
        node_ranges: list[ArtifactSemanticRange] | None = None,
    ) -> int:
        block = graph.blocks[block_index]
        uses = block_uses[block_index]
        last_use = {value: positions[-1] for value, positions in uses.items()}
        register_for: dict[ValueRef, int] = {}
        value_for_register: dict[int, ValueRef] = {}
        backing_offset: dict[ValueRef, int] = {}
        dynamic_slot_for: dict[ValueRef, int] = {}
        free_dynamic_slots: list[int] = []
        next_dynamic_slot = 0
        max_dynamic_slots = 0

        def emit(word: int) -> None:
            if assembler is not None:
                assembler.emit(word)

        def value_key(value: ValueRef) -> tuple[int, int, int, int]:
            return value.tag, value.block, value.index, value.result

        def next_use(value: ValueRef, position: int) -> int:
            for candidate in uses.get(value, ()):
                if candidate > position:
                    return candidate
            return 1 << 30

        def bind_register(value: ValueRef, register: int) -> None:
            previous = value_for_register.get(register)
            if previous is not None and previous != value:
                register_for.pop(previous, None)
            old = register_for.get(value)
            if old is not None and old != register:
                value_for_register.pop(old, None)
            register_for[value] = register
            value_for_register[register] = value

        def unbind_register(value: ValueRef) -> int | None:
            register = register_for.pop(value, None)
            if register is not None and value_for_register.get(register) == value:
                del value_for_register[register]
            return register

        def allocate_dynamic_slot(value: ValueRef) -> int:
            nonlocal next_dynamic_slot, max_dynamic_slots
            if value in dynamic_slot_for:
                return dynamic_slot_for[value]
            if free_dynamic_slots:
                slot_id = min(free_dynamic_slots)
                free_dynamic_slots.remove(slot_id)
            else:
                slot_id = next_dynamic_slot
                next_dynamic_slot += 1
                max_dynamic_slots = max(max_dynamic_slots, next_dynamic_slot)
            dynamic_slot_for[value] = slot_id
            backing_offset[value] = dynamic_spill_base + slot_id * 8
            return slot_id

        def release_value(value: ValueRef) -> None:
            unbind_register(value)
            slot_id = dynamic_slot_for.pop(value, None)
            if slot_id is not None:
                backing_offset.pop(value, None)
                free_dynamic_slots.append(slot_id)
            elif value in backing_offset and value.tag != 0:
                backing_offset.pop(value, None)

        def spill_value(value: ValueRef, *, keep_register: bool = False) -> None:
            register = register_for.get(value)
            if register is None:
                if value not in backing_offset:
                    fail(
                        "XAX.AARCH64.SPILL",
                        graph_object.cid.hex(),
                        "AARCH64-SPILL-SOURCE",
                        "register or existing spill backing",
                        list(value_key(value)),
                    )
                return
            if value not in backing_offset:
                allocate_dynamic_slot(value)
                emit(_load_store(False, register, backing_offset[value], widths[value]))
            if not keep_register:
                unbind_register(value)

        def choose_victim(protected: set[ValueRef], position: int) -> ValueRef:
            candidates = [value for value in register_for if value not in protected]
            if not candidates:
                fail(
                    "XAX.AARCH64.REGISTER_PRESSURE",
                    graph_object.cid.hex(),
                    "AARCH64-SPILLABLE-REGISTER",
                    "one non-protected live value",
                    [list(value_key(value)) for value in protected],
                )
            return max(
                candidates,
                key=lambda value: (next_use(value, position), register_for[value], value_key(value)),
            )

        def acquire_register(position: int, protected: set[ValueRef] | None = None) -> int:
            protected = protected or set()
            for register in allocatable_registers:
                if register not in value_for_register:
                    return register
            victim = choose_victim(protected, position)
            register = register_for[victim]
            spill_value(victim)
            return register

        def ensure_register(value: ValueRef, position: int, protected: set[ValueRef] | None = None) -> int:
            register = register_for.get(value)
            if register is not None:
                return register
            if value in pointers:
                register = acquire_register(position, protected)
                emit(_address_from_sp(register, pointers[value]))
                bind_register(value, register)
                return register
            if value not in backing_offset:
                fail(
                    "XAX.AARCH64.VALUE",
                    graph_object.cid.hex(),
                    "AARCH64-VALUE-LOCATION",
                    "register, explicit stack address, or spill backing",
                    list(value_key(value)),
                )
            register = acquire_register(position, protected)
            emit(_load_store(True, register, backing_offset[value], widths[value]))
            bind_register(value, register)
            return register

        def emit_parallel_register_moves(assignments: list[tuple[int, int, int]]) -> None:
            pending = [(destination, source, width) for destination, source, width in assignments if destination != source]
            while pending:
                sources = {source for _, source, _ in pending}
                safe_index = next((index for index, (destination, _, _) in enumerate(pending) if destination not in sources), None)
                if safe_index is not None:
                    destination, source, width = pending.pop(safe_index)
                    emit(_move_register(destination, source, width))
                    continue
                destination, source, width = min(pending, key=lambda item: (item[0], item[1], item[2]))
                emit(_move_register(scratch_register, source, width))
                pending = [
                    (dest, scratch_register if src == source else src, item_width)
                    for dest, src, item_width in pending
                ]

        # Entry arguments already occupy their ABI registers.  Other block
        # parameters use the same deterministic register homes, established by
        # predecessor edge copies.  Excess parameters use the bounded edge-spill
        # area only when block arity exceeds the caller-saved pool.
        for machine_index, value in enumerate(machine_parameters[block_index]):
            if machine_index < len(allocatable_registers):
                bind_register(value, allocatable_registers[machine_index])
            else:
                backing_offset[value] = edge_spill_base + (machine_index - len(allocatable_registers)) * 8
        for value, offset in home_offset.items():
            if defined_in[value] == block_index:
                last_use.setdefault(value, -1)  # keep it until its home is written
            else:
                backing_offset[value] = offset
        for value in machine_parameters[block_index]:
            if value in home_offset:
                if value in register_for:
                    emit(_load_store(False, register_for[value], home_offset[value], widths[value]))
                else:  # an edge-spilled parameter: copy its slot to its home
                    emit(_load_store(True, scratch_register, backing_offset[value], widths[value]))
                    emit(_load_store(False, scratch_register, home_offset[value], widths[value]))
                if last_use[value] == -1:
                    release_value(value)
                backing_offset[value] = home_offset[value]
        # Parameters with no semantic use must not occupy registers merely
        # because the ABI delivered them there.  Releasing them here lets leaf
        # ABI entry points place their first real result directly in x0.
        for value in machine_parameters[block_index]:
            if value not in last_use:
                release_value(value)

        def source_location(value: ValueRef) -> tuple[str, int]:
            if value in register_for:
                return "register", register_for[value]
            if value in backing_offset:
                return "spill", backing_offset[value]
            fail(
                "XAX.AARCH64.VALUE",
                graph_object.cid.hex(),
                "AARCH64-VALUE-LOCATION",
                "register or spill backing",
                list(value_key(value)),
            )

        def copy_edge(target_block: int, arguments: tuple[ValueRef, ...]) -> None:
            destinations = machine_parameters[target_block]
            machine_pairs: list[tuple[ValueRef, int, ValueRef]] = []
            for index, argument in enumerate(arguments):
                destination = ValueRef.parameter(target_block, index)
                if argument in widths and destination in widths:
                    machine_index = destinations.index(destination)
                    machine_pairs.append((argument, machine_index, destination))

            # Spill destinations are written before any register destinations
            # can overwrite source registers.
            for source, machine_index, destination in machine_pairs:
                if machine_index < len(allocatable_registers):
                    continue
                destination_offset = edge_spill_base + (machine_index - len(allocatable_registers)) * 8
                kind, location = source_location(source)
                if kind == "register":
                    emit(_load_store(False, location, destination_offset, widths[destination]))
                elif location != destination_offset:
                    emit(_load_store(True, scratch_register, location, widths[source]))
                    emit(_load_store(False, scratch_register, destination_offset, widths[destination]))

            register_moves: list[tuple[int, int, int]] = []
            delayed_loads: list[tuple[int, int, int]] = []
            for source, machine_index, destination in machine_pairs:
                if machine_index >= len(allocatable_registers):
                    continue
                destination_register = allocatable_registers[machine_index]
                kind, location = source_location(source)
                if kind == "register":
                    register_moves.append((destination_register, location, widths[destination]))
                else:
                    delayed_loads.append((destination_register, location, widths[destination]))
            emit_parallel_register_moves(register_moves)
            for destination_register, source_offset, width in delayed_loads:
                emit(_load_store(True, destination_register, source_offset, width))

        def shuffle_call_arguments(machine_operands: tuple[ValueRef, ...]) -> None:
            register_moves: list[tuple[int, int, int]] = []
            for destination_register, operand in zip(target.argument_registers, machine_operands):
                kind, location = source_location(operand)
                if kind == "register":
                    register_moves.append((destination_register, location, widths[operand]))
            emit_parallel_register_moves(register_moves)
            for destination_register, source_offset, operand in (
                (destination_register, source_offset, operand)
                for destination_register, operand in zip(target.argument_registers, machine_operands)
                for kind, source_offset in (source_location(operand),)
                if kind == "spill"
            ):
                emit(_load_store(True, destination_register, source_offset, widths[operand]))

        def _call_argument_moves(machine_operands: tuple[ValueRef, ...]) -> list[tuple[int, int, int]]:
            return [
                (destination_register, location, widths[operand])
                for destination_register, operand in zip(target.argument_registers, machine_operands)
                for kind, location in (source_location(operand),)
                if kind == "register" and destination_register != location
            ]

        def _parallel_moves_have_cycle(assignments: list[tuple[int, int, int]]) -> bool:
            pending = [(destination, source) for destination, source, _ in assignments if destination != source]
            while pending:
                sources = {source for _, source in pending}
                safe_index = next((index for index, (destination, _) in enumerate(pending) if destination not in sources), None)
                if safe_index is None:
                    return True
                pending.pop(safe_index)
            return False

        def prepare_real_call(node_index: int, machine_operands: tuple[ValueRef, ...]) -> set[ValueRef]:
            for operand in machine_operands:
                ensure_register(operand, node_index)
            live_after = {
                value
                for value in set((*register_for.keys(), *backing_offset.keys()))
                if last_use.get(value, -1) > node_index
            }
            for value in sorted(live_after, key=value_key):
                if value in register_for:
                    spill_value(value, keep_register=True)
            shuffle_call_arguments(machine_operands)
            return live_after

        def finish_real_call(live_after: set[ValueRef], machine_results: tuple[ValueRef, ...]) -> None:
            for value in tuple(register_for):
                unbind_register(value)
            for value in tuple(set((*backing_offset.keys(), *dynamic_slot_for.keys()))):
                if value not in live_after:
                    release_value(value)
            if machine_results:
                call_result = machine_results[0]
                bind_register(call_result, target.result_register)
                if call_result not in last_use:
                    release_value(call_result)

        if assembler is not None:
            assembler.label(f"block-{block_index}")

        for node_index, node in enumerate(block.nodes):
            node_start = len(assembler.code) if assembler is not None else 0
            result = ValueRef.node_result(block_index, node_index)

            if node.operation in (Operation.ADD_WRAP, Operation.SUB_WRAP, Operation.MUL_WRAP):
                width = widths[result]
                left_value, right_value = node.operands
                left_register = ensure_register(left_value, node_index)
                right_register = ensure_register(right_value, node_index, {left_value} if right_value != left_value else set())
                dead_left = last_use.get(left_value, -1) == node_index
                dead_right = last_use.get(right_value, -1) == node_index
                if dead_left:
                    destination_register = left_register
                elif dead_right:
                    destination_register = right_register
                else:
                    destination_register = acquire_register(node_index, {left_value, right_value})
                emit(_arithmetic(node.operation, destination_register, left_register, right_register, width))
                for operand in {left_value, right_value}:
                    if last_use.get(operand, -1) == node_index:
                        release_value(operand)
                bind_register(result, destination_register)
                if result not in last_use:
                    release_value(result)

            elif node.operation == Operation.INT_COMPARE:
                width = widths[node.operands[0]]
                left_value, right_value = node.operands
                left_register = ensure_register(left_value, node_index)
                right_register = ensure_register(right_value, node_index, {left_value} if right_value != left_value else set())
                destination_register = acquire_register(node_index, {left_value, right_value})
                emit(_compare(left_register, right_register, width))
                emit(_cset_compare(destination_register, IntCompare(node.attributes[0])))
                for operand in {left_value, right_value}:
                    if last_use.get(operand, -1) == node_index:
                        release_value(operand)
                bind_register(result, destination_register)
                if result not in last_use:
                    release_value(result)

            elif node.operation == Operation.CONSTANT:
                type_cid, value = _decode_constant(node.entity, resolve)
                destination_register = acquire_register(node_index)
                for word in _move_immediate(destination_register, value, _width(resolve, type_cid)):
                    emit(word)
                bind_register(result, destination_register)
                if result not in last_use:
                    release_value(result)

            elif node.operation == Operation.CALL_DIRECT:
                machine_operands = tuple(operand for operand in node.operands if operand in widths)
                machine_results = tuple(
                    ValueRef.node_result(block_index, node_index, result_index)
                    for result_index, type_cid in enumerate(node.results)
                    if _width(resolve, type_cid) is not None
                )
                if not _is_erased_proof_function(node.entity, resolve):
                    live_after = prepare_real_call(node_index, machine_operands)
                    if assembler is not None:
                        assembler.call(node.entity.cid)
                    finish_real_call(live_after, machine_results)

            elif node.operation == Operation.CALL_FOREIGN:
                machine_operands = tuple(operand for operand in node.operands if operand in widths)
                machine_results = tuple(
                    ValueRef.node_result(block_index, node_index, result_index)
                    for result_index, type_cid in enumerate(node.results)
                    if _width(resolve, type_cid) is not None
                )
                live_after = prepare_real_call(node_index, machine_operands)
                declaration = decode_foreign_function(node.entity)
                _require_foreign_abi(declaration, target, graph_object)
                if assembler is not None:
                    assembler.foreign_call(declaration.library, declaration.name)
                finish_real_call(live_after, machine_results)

            elif node.operation == Operation.CALL_INDIRECT:
                function_pointer = node.operands[0]
                machine_operands = tuple(operand for operand in node.operands[1:] if operand in widths)
                machine_results = tuple(
                    ValueRef.node_result(block_index, node_index, result_index)
                    for result_index, type_cid in enumerate(node.results)
                    if _width(resolve, type_cid) is not None
                )
                # x10 is both the indirect-call target register and the parallel-copy
                # cycle breaker.  If ABI argument placement itself forms a cycle,
                # preserve the function pointer in its lazy spill slot until after
                # the shuffle so the cycle breaker cannot overwrite it.
                pointer_register = ensure_register(function_pointer, node_index)
                for operand in machine_operands:
                    ensure_register(operand, node_index)
                if _parallel_moves_have_cycle(_call_argument_moves(machine_operands)):
                    spill_value(function_pointer, keep_register=True)
                    live_after = prepare_real_call(node_index, machine_operands)
                    emit(_load_store(True, scratch_register, backing_offset[function_pointer], 64))
                else:
                    if pointer_register != scratch_register:
                        emit(_move_register(scratch_register, pointer_register, 64))
                    live_after = prepare_real_call(node_index, machine_operands)
                emit(_blr(scratch_register))
                finish_real_call(live_after, machine_results)

            elif node.operation == Operation.FUNCTION_ADDRESS:
                destination_register = acquire_register(node_index)
                if assembler is not None:
                    assembler.address(destination_register, node.entity.cid)
                bind_register(result, destination_register)
                if result not in last_use:
                    release_value(result)

            elif node.operation == Operation.TARGET_OP:
                description = decode_native_target(node.entity)
                if description.identity not in (b"android-arm64-v8a-shared-v1", b"android-arm64-v8a-shared-v2", b"android-arm64-v8a-shared-v3"):
                    fail("XAX.AARCH64.TARGET_OP", graph_object.cid.hex(), "AARCH64-TARGET-OP-PACKAGE", ["android-arm64-v8a-shared-v1", "android-arm64-v8a-shared-v2", "android-arm64-v8a-shared-v3"], description.identity.decode("ascii", "replace"))
                operation_id = node.attributes[0]
                contract = next(item for item in description.target_operations if item.operation_id == operation_id)
                machine_operands = tuple(operand for operand in node.operands if operand in widths)
                machine_results = tuple(
                    ValueRef.node_result(block_index, node_index, result_index)
                    for result_index, type_cid in enumerate(node.results)
                    if _width(resolve, type_cid) is not None
                )
                if operation_id in {
                    ANDROID_JNI_REFERENCE_WORD_BORROWED_OPERATION,
                    ANDROID_JNI_REFERENCE_WORD_LOCAL_OPERATION,
                    ANDROID_JNI_REFERENCE_WORD_GLOBAL_OPERATION,
                }:
                    if len(machine_operands) != 1 or len(machine_results) != 1 or widths[machine_operands[0]] != 64 or widths[machine_results[0]] != 64:
                        fail("XAX.AARCH64.TARGET_OP", graph_object.cid.hex(), "AARCH64-JNI-REFERENCE-WORD", [1, 1, 64], [len(machine_operands), len(machine_results), 0 if not machine_operands else widths[machine_operands[0]]])
                    source = machine_operands[0]
                    source_register = ensure_register(source, node_index)
                    if last_use.get(source, -1) == node_index:
                        # The JNI handle already is the required AAPCS64 word.
                        # Rebind the same physical register: semantic projection,
                        # zero emitted instructions.
                        bind_register(machine_results[0], source_register)
                    else:
                        # Preserve a still-live reference handle while exposing
                        # its jvalue.l ABI word in a distinct SSA value.
                        destination_register = acquire_register(node_index, {source})
                        emit(_move_register(destination_register, source_register, 64))
                        bind_register(machine_results[0], destination_register)
                    if machine_results[0] not in last_use:
                        release_value(machine_results[0])
                    continue
                if len(machine_operands) != 1 or len(machine_results) != 1:
                    fail("XAX.AARCH64.TARGET_OP", graph_object.cid.hex(), "AARCH64-ANDROID-ABI-LOAD", [1, 1], [len(machine_operands), len(machine_results)])
                base_register = ensure_register(machine_operands[0], node_index)
                destination_register = base_register if last_use.get(machine_operands[0], -1) == node_index else acquire_register(node_index, {machine_operands[0]})
                width = widths[machine_results[0]]
                emit(_load_from_register(destination_register, base_register, contract.encoding_opcode, width))
                if last_use.get(machine_operands[0], -1) == node_index:
                    release_value(machine_operands[0])
                bind_register(machine_results[0], destination_register)
                if machine_results[0] not in last_use:
                    release_value(machine_results[0])

            elif node.operation == Operation.ATOMIC_STORE:
                width = decode_bits_width(resolve(node.operand_types[1]))
                order = AtomicOrder(node.attributes[0])
                value = node.operands[1]
                value_register = ensure_register(value, node_index)
                emit(_address_from_sp(scratch_register, pointers[node.operands[0]]))
                if order == AtomicOrder.SEQ_CST:
                    emit(_DMB_ISH)
                emit(_atomic_store_register(value_register, scratch_register, width, order != AtomicOrder.RELAXED))
                if order == AtomicOrder.SEQ_CST:
                    emit(_DMB_ISH)
                if last_use.get(value, -1) == node_index:
                    release_value(value)

            elif node.operation == Operation.ATOMIC_LOAD:
                width = decode_bits_width(resolve(node.results[0]))
                order = AtomicOrder(node.attributes[0])
                destination_register = acquire_register(node_index)
                emit(_address_from_sp(scratch_register, pointers[node.operands[0]]))
                if order == AtomicOrder.SEQ_CST:
                    emit(_DMB_ISH)
                emit(_atomic_load_register(destination_register, scratch_register, width, order != AtomicOrder.RELAXED))
                if order == AtomicOrder.SEQ_CST:
                    emit(_DMB_ISH)
                bind_register(result, destination_register)
                if result not in last_use:
                    release_value(result)

            elif node.operation == Operation.STORE_BITS_LE:
                width = node.attributes[0] * 8
                if width not in (8, 16, 32, 64):
                    fail("XAX.AARCH64.MEMORY_WIDTH", graph_object.cid.hex(), "AARCH64-MEMORY-WIDTH", [8, 16, 32, 64], width)
                value = node.operands[1]
                register = ensure_register(value, node_index)
                emit(_exact_memory_load_store(False, register, pointers[node.operands[0]], width))
                if last_use.get(value, -1) == node_index:
                    release_value(value)

            elif node.operation == Operation.LOAD_BITS_LE:
                width = node.attributes[0] * 8
                if width not in (8, 16, 32, 64):
                    fail("XAX.AARCH64.MEMORY_WIDTH", graph_object.cid.hex(), "AARCH64-MEMORY-WIDTH", [8, 16, 32, 64], width)
                destination_register = acquire_register(node_index)
                emit(_exact_memory_load_store(True, destination_register, pointers[node.operands[0]], width))
                bind_register(result, destination_register)
                if result not in last_use:
                    release_value(result)

            elif node.operation not in (Operation.STACK_ALLOC, Operation.ADDRESS_OFFSET, Operation.STACK_END, *RESOURCE_EFFECT_OPERATIONS):
                fail("XAX.AARCH64.UNSUPPORTED_OPERATION", graph_object.cid.hex(), "AARCH64-OP-LOWERED", list(target.supported_operations), node.operation)

            for result_index in range(len(node.results)):
                value = ValueRef.node_result(block_index, node_index, result_index)
                if value in home_offset:
                    emit(_load_store(False, register_for[value], home_offset[value], widths[value]))
                    if last_use[value] in (-1, node_index):
                        release_value(value)
                    else:
                        backing_offset[value] = home_offset[value]

            if assembler is not None and node_ranges is not None:
                node_end = len(assembler.code)
                if node_end > node_start:
                    node_ranges.append(ArtifactSemanticRange(function.cid, block_index, node_index, node_start, node_end))

        terminator = block.terminator
        terminator_position = len(block.nodes)
        if terminator.kind == TerminatorKind.RETURN:
            machine_values = tuple(value for value in terminator.values if value in widths)
            if machine_values:
                value = machine_values[0]
                source_register = register_for.get(value)
                if source_register is not None:
                    if source_register != target.result_register:
                        emit(_move_register(target.result_register, source_register, widths[value]))
                else:
                    emit(_load_store(True, target.result_register, backing_offset[value], widths[value]))
            if has_call:
                assert link_slot is not None
                emit(_load_store(True, 30, link_slot, 64))
            if frame_size:
                emit(_add_sub_sp(False, frame_size))
            emit(0xD65F03C0)

        elif terminator.kind == TerminatorKind.BRANCH:
            target_block, arguments = terminator.edges[0]
            copy_edge(target_block, arguments)
            if assembler is not None:
                assembler.branch(f"block-{target_block}")

        elif terminator.kind == TerminatorKind.CONDITIONAL_BRANCH:
            condition = terminator.values[0]
            condition_register = ensure_register(condition, terminator_position)
            false_label = f"false-{block_index}"
            if assembler is not None:
                assembler.cbz(condition_register, false_label)
            true_target, true_arguments = terminator.edges[0]
            copy_edge(true_target, true_arguments)
            if assembler is not None:
                assembler.branch(f"block-{true_target}")
                assembler.label(false_label)
            false_target, false_arguments = terminator.edges[1]
            copy_edge(false_target, false_arguments)
            if assembler is not None:
                assembler.branch(f"block-{false_target}")
        else:
            reason, _target_data = decode_trap_payload(terminator.payload)
            for word in _move_immediate(target.result_register, reason, 64):
                emit(word)
            emit(0xD4200000 | ((reason & 0xFFFF) << 5))

        return max_dynamic_slots

    # Dry-run the same deterministic allocator to determine the exact number of
    # simultaneously required pressure/call spill slots before encoding the
    # frame.  No slot is reserved per SSA value.
    dynamic_spill_count = max((lower_block(index, None) for index in range(len(graph.blocks))), default=0)
    frame_payload = dynamic_spill_base + dynamic_spill_count * 8
    frame_size = _align(frame_payload, target.stack_alignment) if frame_payload else 0

    assembler = _Assembler()
    if frame_size:
        assembler.emit(_add_sub_sp(True, frame_size))
    if has_call:
        assert link_slot is not None
        assembler.emit(_load_store(False, 30, link_slot, 64))
    if graph.entry:
        assembler.branch(f"block-{graph.entry}")

    node_ranges: list[ArtifactSemanticRange] = []
    for block_index in range(len(graph.blocks)):
        observed_spills = lower_block(block_index, assembler, frame_size, node_ranges)
        if observed_spills > dynamic_spill_count:
            fail(
                "XAX.AARCH64.SPILL_PLAN",
                graph_object.cid.hex(),
                "AARCH64-SPILL-PLAN-DETERMINISTIC",
                dynamic_spill_count,
                observed_spills,
            )

    code, calls, foreign_calls, addresses = assembler.finish()
    return code, calls, foreign_calls, addresses, tuple(node_ranges)

def compile_aarch64_bundle_bound_target(
    reader: StoreReader,
    function_cids: Sequence[bytes],
    target_object: SemanticObject,
    realtime_profile: RealtimeProfile | None = None,
    atomic_policy: AtomicLegalizationPolicy = AtomicLegalizationPolicy(),
) -> Aarch64Bundle:
    verify_store(reader)
    resolve = store_resolver(reader)
    entries = tuple(resolve(cid) for cid in function_cids)
    if not entries or any(entry.kind != Kind.FUNCTION for entry in entries):
        fail("XAX.AARCH64.FUNCTION", "bundle", "AARCH64-ENTRY-FUNCTIONS", "one or more FUNCTION objects", [entry.kind.name for entry in entries])
    target = decode_native_target(target_object)
    if target.architecture != 3:
        fail("XAX.AARCH64.TARGET", target_object.cid.hex(), "AARCH64-TARGET-PROFILE", 3, target.architecture)
    functions_by_cid: dict[bytes, SemanticObject] = {}
    for entry in entries:
        for function in _function_closure(entry, resolve, target):
            functions_by_cid[function.cid] = function
    functions = tuple(functions_by_cid[cid] for cid in sorted(functions_by_cid))
    fragments = {function.cid: _compile_function(function, resolve, target, atomic_policy) for function in functions}
    offsets: dict[bytes, int] = {}
    image = bytearray()
    semantic_ranges: list[ArtifactSemanticRange] = []
    foreign_calls: list[tuple[int, bytes, bytes]] = []
    for function in functions:
        while len(image) % 16:
            image.extend((0xD503201F).to_bytes(4, "little"))
        base = len(image)
        offsets[function.cid] = base
        fragment = fragments[function.cid][0]
        image.extend(fragment)
        semantic_ranges.append(ArtifactSemanticRange(function.cid, None, None, base, base + len(fragment)))
        semantic_ranges.extend(
            ArtifactSemanticRange(item.function_cid, item.block_index, item.node_index, base + item.start, base + item.end)
            for item in fragments[function.cid][4]
        )
        foreign_calls.extend((base + position, library, name) for position, library, name in fragments[function.cid][2])
    for function in functions:
        base = offsets[function.cid]
        for local_position, callee in fragments[function.cid][1]:
            position = base + local_position
            displacement = offsets[callee] - position
            immediate = displacement // 4
            if displacement % 4 or not -(1 << 25) <= immediate < 1 << 25:
                fail("XAX.AARCH64.CALL", function.cid.hex(), "AARCH64-CALL-RANGE", "signed imm26", displacement)
            image[position:position + 4] = (0x94000000 | (immediate & 0x3FFFFFF)).to_bytes(4, "little")
        for local_position, register, addressed in fragments[function.cid][3]:
            position = base + local_position
            displacement = offsets[addressed] - position
            if not -(1 << 20) <= displacement < 1 << 20:
                fail("XAX.AARCH64.ADDRESS", function.cid.hex(), "AARCH64-ADR-RANGE", "signed 21-bit byte displacement", displacement)
            imm = displacement & 0x1FFFFF
            word = 0x10000000 | ((imm & 0x3) << 29) | (((imm >> 2) & 0x7FFFF) << 5) | register
            image[position:position + 4] = word.to_bytes(4, "little")
    bundle = Aarch64Bundle(
        bytes(image),
        target_object.cid,
        tuple((function.cid, offsets[function.cid]) for function in functions),
        tuple(sorted(foreign_calls, key=lambda item: item[0])),
        tuple(semantic_ranges),
    )
    if realtime_profile is not None:
        for function_cid in function_cids:
            validate_realtime_profile(analyze_realtime(reader, function_cid, target_object), realtime_profile)
    return bundle


def _compile_aarch64_with_target(
    reader: StoreReader,
    function_cid: bytes,
    target_object: SemanticObject,
    realtime_profile: RealtimeProfile | None = None,
    atomic_policy: AtomicLegalizationPolicy = AtomicLegalizationPolicy(),
) -> Aarch64Image:
    bundle = compile_aarch64_bundle_bound_target(reader, (function_cid,), target_object, realtime_profile, atomic_policy)
    resolve = store_resolver(reader)
    entry = resolve(function_cid)
    _, parameters, returns = _decode_function_interface(entry, resolve)
    offsets = dict(bundle.function_offsets)
    return Aarch64Image(
        bundle.code,
        offsets[function_cid],
        tuple(_width(resolve, cid) for cid in parameters if _width(resolve, cid) is not None),
        tuple(_width(resolve, cid) for cid in returns if _width(resolve, cid) is not None),
        bundle.target_cid,
        bundle.function_offsets,
        bundle.semantic_ranges,
    )


def compile_aarch64(
    reader: StoreReader,
    function_cid: bytes,
    target_cid: bytes,
    realtime_profile: RealtimeProfile | None = None,
    atomic_policy: AtomicLegalizationPolicy = AtomicLegalizationPolicy(),
) -> Aarch64Image:
    resolve = store_resolver(reader)
    return _compile_aarch64_with_target(reader, function_cid, resolve(target_cid), realtime_profile, atomic_policy)


def compile_aarch64_bound_target(
    reader: StoreReader,
    function_cid: bytes,
    target_object: SemanticObject,
    realtime_profile: RealtimeProfile | None = None,
    atomic_policy: AtomicLegalizationPolicy = AtomicLegalizationPolicy(),
) -> Aarch64Image:
    """Compile against an explicitly bound target package that need not be stored under the program root."""
    return _compile_aarch64_with_target(reader, function_cid, target_object, realtime_profile, atomic_policy)


def _kernel(image: Aarch64Image, arguments: Sequence[int]) -> bytes:
    words: list[int] = []
    words.extend(_move_immediate(20, 0x41000000, 64))
    words.append(0x91000000 | (20 << 5) | 31)
    for register, (argument, width) in enumerate(zip(arguments, image.parameter_widths)):
        words.extend(_move_immediate(register, argument, width))
    call_index = len(words)
    words.append(0x94000000)
    if image.return_widths:
        words.extend((_add_sub_sp(True, 16), _load_store(False, 0, 0, 64)))
        for offset in range(8):
            words.extend((*_move_immediate(0, 3, 64), 0x91000000 | (offset << 10) | (31 << 5) | 1, 0xD45E0000))
        words.append(_add_sub_sp(False, 16))
    words.extend((*_move_immediate(0, 0x18, 64), *_move_immediate(1, 0x20026, 64), 0xD45E0000))
    while len(words) * 4 % 16:
        words.append(0xD503201F)
    entry = len(words) * 4 + image.entry_offset
    call_position = call_index * 4
    words[call_index] = 0x94000000 | (((entry - call_position) // 4) & 0x3FFFFFF)
    return b"".join(word.to_bytes(4, "little") for word in words) + image.code


def _require_android_entry(function: SemanticObject, abi: bytes, resolve, target: NativeTargetDescription, graph_object: SemanticObject) -> None:
    """An ``android-aapcs64-c`` entry is the function's own address (ADR-107).

    XAX AArch64 code allocates only x0-x7 and x9, never x18 (the Android
    platform register) or x19-x28, and keeps SP 16-byte aligned, so it already
    meets the AAPCS64 callee obligations and needs no adapter.  AAPCS64 leaves
    the upper bits of narrow arguments unspecified, so entry parameters must be
    64-bit integers or pointers.
    """
    if abi != ANDROID_AAPCS64_C_ABI or target.abi != 4:
        fail("XAX.AARCH64.FOREIGN_ENTRY", graph_object.cid.hex(), "AARCH64-FOREIGN-ENTRY-TARGET", [ANDROID_AAPCS64_C_ABI.decode(), 4], [abi.decode("ascii", "replace"), target.abi])
    _graph, parameters, returns = _decode_function_interface(function, resolve)
    wide = lambda cid: _sysv_like_width(resolve, cid) == 64
    if len(parameters) > 8 or len(returns) > 1 or not all(wide(cid) for cid in parameters) or not all(_sysv_like_width(resolve, cid) for cid in returns):
        fail("XAX.AARCH64.FOREIGN_ENTRY", function.cid.hex(), "AARCH64-ENTRY-SIGNATURE", "<=8 64-bit integer/pointer parameters, <=1 integer/pointer result", [[cid.hex() for cid in parameters], [cid.hex() for cid in returns]])


def _sysv_like_width(resolve, cid: bytes) -> int:
    """Width of an integer or pointer scalar, or 0 for anything else."""
    obj = resolve(cid)
    if obj.body[:1] == b"\x01":
        return decode_bits_width(obj)
    try:
        _decode_pointer_type(obj, resolve)
    except XaxError:
        return 0
    return 64


def run_aarch64_qemu(
    image: Aarch64Image,
    arguments: Sequence[int],
    qemu_executable: str | None = None,
) -> tuple[int, ...]:
    if len(arguments) != len(image.parameter_widths):
        fail("XAX.AARCH64.ARGUMENT_COUNT", "entry", "AARCH64-ARGUMENT-COUNT", len(image.parameter_widths), len(arguments))
    for argument, width in zip(arguments, image.parameter_widths):
        if argument < 0 or argument >= 1 << width:
            fail("XAX.AARCH64.ARGUMENT_RANGE", "entry", "AARCH64-ARGUMENT-RANGE", f"bits<{width}>", argument)
    qemu = qemu_executable or shutil.which("qemu-system-aarch64")
    if not qemu:
        fallback = Path(r"C:\msys64\ucrt64\bin\qemu-system-aarch64.exe")
        qemu = str(fallback) if fallback.exists() else None
    if not qemu:
        if qemu_executable is None and _unicorn_available():
            return _run_aarch64_unicorn(image, arguments)
        fail("XAX.AARCH64.HOST", "host", "AARCH64-HOST-QEMU", "qemu-system-aarch64 executable", "missing")
    with tempfile.TemporaryDirectory(prefix="xax-aarch64-") as directory:
        kernel = Path(directory) / "kernel.bin"
        kernel.write_bytes(_kernel(image, arguments))
        completed = subprocess.run(
            [qemu, "-M", "virt", "-cpu", "cortex-a72", "-nographic", "-net", "none", "-monitor", "none", "-serial", "none", "-semihosting-config", "enable=on,target=native", "-kernel", str(kernel)],
            check=False,
            capture_output=True,
            timeout=15,
        )
    if completed.returncode not in (0, 1):
        raise RuntimeError(completed.stderr.decode(errors="replace").strip() or f"qemu exited {completed.returncode}")
    output = completed.stdout + completed.stderr
    if not image.return_widths:
        if output:
            raise RuntimeError(f"unexpected QEMU output: {output!r}")
        return ()
    if len(output) != 8:
        raise RuntimeError(f"unexpected QEMU result length {len(output)}: {output!r}")
    result = int.from_bytes(output, "little")
    return (result & ((1 << image.return_widths[0]) - 1),)


def _unicorn_available() -> bool:
    try:
        import unicorn  # noqa: F401
    except ImportError:
        return False
    return True


def _run_aarch64_unicorn(image: Aarch64Image, arguments: Sequence[int]) -> tuple[int, ...]:
    """Harness fallback when QEMU is absent: run the raw image in Unicorn's ARM64 CPU.

    The image bytes are the ones QEMU would load after the semihosting
    prologue; here the harness calls the entry directly with x0-x7 set and
    a sentinel link register.  The emulator is a host tool, not the artifact.
    """
    import unicorn
    from unicorn import arm64_const as arm

    emulator = unicorn.Uc(unicorn.UC_ARCH_ARM64, unicorn.UC_MODE_ARM)
    base, sentinel, stack_top = 0x40080000, 0x1000, 0x41000000
    emulator.mem_map(base, (len(image.code) + 0xFFF) & -0x1000)
    emulator.mem_write(base, image.code)
    emulator.mem_map(sentinel, 0x1000)
    emulator.mem_map(stack_top - (1 << 20), 1 << 20)
    emulator.reg_write(arm.UC_ARM64_REG_SP, stack_top)
    emulator.reg_write(arm.UC_ARM64_REG_LR, sentinel)
    for register, argument in enumerate(arguments):
        emulator.reg_write(arm.UC_ARM64_REG_X0 + register, argument)
    emulator.emu_start(base + image.entry_offset, sentinel, count=50_000_000)
    if emulator.reg_read(arm.UC_ARM64_REG_PC) != sentinel:
        raise RuntimeError("aarch64 entry did not return")
    if not image.return_widths:
        return ()
    return (emulator.reg_read(arm.UC_ARM64_REG_X0) & ((1 << image.return_widths[0]) - 1),)
