"""Direct x86-64 Windows load-image backend for the verified XAX prototype."""

from __future__ import annotations

import ctypes
import json
import platform
import subprocess
import sys
from dataclasses import dataclass
from typing import Callable, Sequence

from xax_artifact import ArtifactSemanticRange

from xax_compiler import (
    store_resolver,
    ATOMIC_OPERATIONS,
    AbiLayout,
    AtomicFamily,
    AtomicLegalizationPolicy,
    AtomicOrder,
    AtomicRmwKind,
    AtomicSupport,
    FloatCompare,
    IntCompare,
    Kind,
    NativeTargetDescription,
    Operation,
    LINUX_X86_64_SYSCALL_ABI,
    SYSV_X86_64_C_ABI,
    X86_64_LINUX_ABI,
    X86_64_LINUX_ELF_DYNAMIC_FORMAT,
    decode_foreign_function,
    pointer_extent_from_graph,
    RealtimeProfile,
    RESOURCE_EFFECT_OPERATIONS,
    SemanticObject,
    StoreReader,
    TerminatorKind,
    TrapReason,
    decode_trap_payload,
    ValueRef,
    _decode_constant,
    _decode_function_interface,
    _decode_pointer_type,
    _float_raw_bits,
    _int_to_float,
    _is_proof_type,
    abi_layout,
    _is_erased_proof_function,
    _parse_graph,
    _atomic_node_request,
    atomic_capability,
    analyze_realtime,
    decode_bits_width,
    decode_float_width,
    value_bit_width,
    decode_native_target,
    fail,
    select_atomic_legalization,
    verify_store,
    validate_realtime_profile,
)


@dataclass(frozen=True)
class NativeImage:
    code: bytes
    entry_offset: int
    parameter_widths: tuple[int, ...]
    return_widths: tuple[int, ...]
    target_cid: bytes
    function_offsets: tuple[tuple[bytes, int], ...]
    semantic_ranges: tuple[ArtifactSemanticRange, ...] = ()
    # Win64 carrier per machine value: "u<bits>", "f32"/"f64", or "a<bytes>"
    # for an aggregate passed by value or by hidden reference per its size.
    parameter_kinds: tuple[str, ...] = ()
    return_kinds: tuple[str, ...] = ()
    # (image offset of a rel32 GOT displacement, library, symbol) for SysV C imports.
    foreign_calls: tuple[tuple[int, bytes, bytes], ...] = ()

    @property
    def artifact_bytes(self) -> bytes:
        return self.code


class _Assembler:
    def __init__(self) -> None:
        self.code = bytearray()
        self.labels: dict[str, int] = {}
        self.branches: list[tuple[int, str]] = []
        self.calls: list[tuple[int, bytes]] = []
        self.foreign_calls: list[tuple[int, bytes, bytes]] = []

    def emit(self, data: bytes) -> None:
        self.code.extend(data)

    def label(self, name: str) -> None:
        self.labels[name] = len(self.code)

    def relative(self, opcode: bytes, label: str) -> None:
        self.emit(opcode)
        self.branches.append((len(self.code), label))
        self.emit(bytes(4))

    def call(self, callee: bytes) -> None:
        self.emit(b"\xe8")
        self.calls.append((len(self.code), callee))
        self.emit(bytes(4))

    def foreign_call(self, library: bytes, name: bytes) -> None:
        """``call qword [rip + GOT slot]``; the artifact emitter resolves the slot."""
        self.emit(b"\xff\x15")
        self.foreign_calls.append((len(self.code), library, name))
        self.emit(bytes(4))

    def address(self, register: int, callee: bytes) -> None:
        rex = 0x48 | (0x04 if register >= 8 else 0)
        self.emit(bytes((rex, 0x8D, 0x05 | ((register & 7) << 3))))
        self.calls.append((len(self.code), callee))
        self.emit(bytes(4))

    def finish(self) -> tuple[bytes, tuple[tuple[int, bytes], ...]]:
        for position, label in self.branches:
            try:
                target = self.labels[label]
            except KeyError:
                fail("XAX.NATIVE.LABEL", "x86_64", "NATIVE-LABEL-RESOLVED", label, "missing")
            displacement = target - (position + 4)
            self.code[position : position + 4] = displacement.to_bytes(4, "little", signed=True)
        return bytes(self.code), tuple(self.calls)


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) & -alignment


def _memory_instruction(opcode: int, register: int, offset: int, width: int) -> bytes:
    if width not in (4, 8) or offset < 0 or offset >= 1 << 31:
        fail("XAX.NATIVE.MEMORY_ENCODING", "x86_64", "NATIVE-MEMORY-ENCODABLE", "4/8-byte access with disp32", [width, offset])
    rex = 0x40 | (0x08 if width == 8 else 0) | (0x04 if register >= 8 else 0)
    prefix = bytes((rex,)) if rex != 0x40 else b""
    if offset < 128:
        return prefix + bytes((opcode, 0x44 | ((register & 7) << 3), 0x24, offset))
    return prefix + bytes((opcode, 0x84 | ((register & 7) << 3), 0x24)) + offset.to_bytes(4, "little")


def _atomic_memory_instruction(opcodes: bytes, register: int, offset: int, width: int, *, locked: bool = False) -> bytes:
    if width not in (4, 8) or offset < 0 or offset >= 1 << 31:
        fail("XAX.NATIVE.ATOMIC_ENCODING", "x86_64", "NATIVE-ATOMIC-ENCODABLE", "aligned 4/8-byte access with disp32", [width, offset])
    rex = 0x40 | (0x08 if width == 8 else 0) | (0x04 if register >= 8 else 0)
    prefix = (b"\xf0" if locked else b"") + (bytes((rex,)) if rex != 0x40 else b"")
    modrm = 0x44 | ((register & 7) << 3)
    if offset < 128:
        return prefix + opcodes + bytes((modrm, 0x24, offset))
    return prefix + opcodes + bytes((0x84 | ((register & 7) << 3), 0x24)) + offset.to_bytes(4, "little")


def _fence(order: AtomicOrder) -> bytes:
    return {
        AtomicOrder.ACQUIRE: b"\x0f\xae\xe8",  # lfence
        AtomicOrder.RELEASE: b"\x0f\xae\xf8",  # sfence
        AtomicOrder.ACQ_REL: b"\x0f\xae\xf0",  # mfence
        AtomicOrder.SEQ_CST: b"\x0f\xae\xf0",
    }[order]


def _load(register: int, offset: int, width: int = 8) -> bytes:
    return _memory_instruction(0x8B, register, offset, width)


def _store(register: int, offset: int, width: int = 8) -> bytes:
    return _memory_instruction(0x89, register, offset, width)


def _indexed_memory_instruction(opcode: int, register: int, index: int, offset: int, width: int) -> bytes:
    if width not in (4, 8) or offset < 0 or offset >= 1 << 31:
        fail("XAX.NATIVE.MEMORY_ENCODING", "x86_64", "NATIVE-INDEXED-MEMORY-ENCODABLE", "4/8-byte access with rsp+index+disp32", [width, offset])
    rex = 0x40 | (0x08 if width == 8 else 0) | (0x04 if register >= 8 else 0) | (0x02 if index >= 8 else 0)
    prefix = bytes((rex,)) if rex != 0x40 else b""
    modrm = 0x84 | ((register & 7) << 3)
    sib = ((index & 7) << 3) | 0x04
    return prefix + bytes((opcode, modrm, sib)) + offset.to_bytes(4, "little")


def _indexed_load(register: int, index: int, offset: int, width: int) -> bytes:
    return _indexed_memory_instruction(0x8B, register, index, offset, width)


def _indexed_store(register: int, index: int, offset: int, width: int) -> bytes:
    return _indexed_memory_instruction(0x89, register, index, offset, width)


def _cmp_imm32(register: int, value: int) -> bytes:
    if value < 0 or value >= 1 << 31:
        fail("XAX.NATIVE.MEMORY_ENCODING", "x86_64", "NATIVE-CHECKED-BOUND-ENCODABLE", "0..2^31-1", value)
    rex = 0x48 | (0x01 if register >= 8 else 0)
    return bytes((rex, 0x81, 0xF8 | (register & 7))) + value.to_bytes(4, "little")


def _immediate(register: int, value: int) -> bytes:
    return bytes((0x48 | (1 if register >= 8 else 0), 0xB8 + (register & 7))) + value.to_bytes(8, "little")


def _arithmetic(operation: int, width: int) -> bytes:
    if width == 64:
        return {
            Operation.ADD_WRAP: b"\x4c\x01\xd0",
            Operation.SUB_WRAP: b"\x4c\x29\xd0",
            Operation.MUL_WRAP: b"\x49\x0f\xaf\xc2",
            Operation.BIT_XOR: b"\x4c\x31\xd0",
            Operation.BIT_AND: b"\x4c\x21\xd0",
            Operation.BIT_OR: b"\x4c\x09\xd0",
        }[operation]
    if width == 32:
        return {
            Operation.ADD_WRAP: b"\x44\x01\xd0",
            Operation.SUB_WRAP: b"\x44\x29\xd0",
            Operation.MUL_WRAP: b"\x41\x0f\xaf\xc2",
            Operation.BIT_XOR: b"\x44\x31\xd0",
            Operation.BIT_AND: b"\x44\x21\xd0",
            Operation.BIT_OR: b"\x44\x09\xd0",
        }[operation]
    fail("XAX.NATIVE.BITS", "x86_64", "NATIVE-BITS-SUPPORTED", [32, 64], width)


def _move_register(destination: int, source: int, width: int) -> bytes:
    if width <= 0 or width > 64:
        fail("XAX.NATIVE.BITS", "x86_64", "NATIVE-BITS-SUPPORTED", "bits<1..64>", width)
    width = 64 if width == 64 else 32
    rex = 0x40 | (0x08 if width == 64 else 0) | (0x04 if source >= 8 else 0) | (0x01 if destination >= 8 else 0)
    prefix = bytes((rex,)) if rex != 0x40 else b""
    return prefix + bytes((0x89, 0xC0 | ((source & 7) << 3) | (destination & 7)))


def _register_arithmetic(operation: int, destination: int, source: int, width: int) -> bytes:
    if width not in (32, 64):
        fail("XAX.NATIVE.BITS", "x86_64", "NATIVE-BITS-SUPPORTED", [32, 64], width)
    rex_w = 0x08 if width == 64 else 0
    if operation in (Operation.ADD_WRAP, Operation.SUB_WRAP, Operation.BIT_XOR, Operation.BIT_AND, Operation.BIT_OR):
        opcode = {Operation.ADD_WRAP: 0x01, Operation.SUB_WRAP: 0x29, Operation.BIT_XOR: 0x31, Operation.BIT_AND: 0x21, Operation.BIT_OR: 0x09}[operation]
        rex = 0x40 | rex_w | (0x04 if source >= 8 else 0) | (0x01 if destination >= 8 else 0)
        prefix = bytes((rex,)) if rex != 0x40 else b""
        return prefix + bytes((opcode, 0xC0 | ((source & 7) << 3) | (destination & 7)))
    if operation == Operation.MUL_WRAP:
        rex = 0x40 | rex_w | (0x04 if destination >= 8 else 0) | (0x01 if source >= 8 else 0)
        prefix = bytes((rex,)) if rex != 0x40 else b""
        return prefix + b"\x0f\xaf" + bytes((0xC0 | ((destination & 7) << 3) | (source & 7),))
    fail("XAX.NATIVE.OPERATION", "x86_64", "NATIVE-ARITHMETIC-OPERATION", [Operation.ADD_WRAP, Operation.SUB_WRAP, Operation.MUL_WRAP, Operation.BIT_XOR], operation)


def _rotate_right_immediate(register: int, amount: int, width: int) -> bytes:
    if width not in (32, 64) or not 0 <= amount < width:
        fail("XAX.NATIVE.ROTATE", "x86_64", "NATIVE-ROTATE-RIGHT", [32, 64, "amount < width"], [width, amount])
    rex = 0x40 | (0x08 if width == 64 else 0) | (0x01 if register >= 8 else 0)
    prefix = bytes((rex,)) if rex != 0x40 else b""
    return prefix + bytes((0xC1, 0xC8 | (register & 7), amount))


def _test_register(register: int, width: int) -> bytes:
    width = 64 if width == 64 else 32
    rex = 0x40 | (0x08 if width == 64 else 0) | (0x04 if register >= 8 else 0) | (0x01 if register >= 8 else 0)
    prefix = bytes((rex,)) if rex != 0x40 else b""
    return prefix + bytes((0x85, 0xC0 | ((register & 7) << 3) | (register & 7)))


def _type_form(resolve: Callable[[bytes], SemanticObject], cid: bytes) -> int:
    obj = resolve(cid)
    if obj.kind != Kind.TYPE or not obj.body:
        return 0
    from xax_compiler import Cursor
    return Cursor(obj.body, obj.cid.hex()).uleb()


def _value_width(resolve: Callable[[bytes], SemanticObject], cid: bytes) -> int | None:
    width = value_bit_width(resolve(cid), resolve)
    return width if width is not None and 0 < width <= 64 else None


def _is_float_cid(resolve: Callable[[bytes], SemanticObject], cid: bytes) -> bool:
    return _type_form(resolve, cid) == 7


def _xmm_memory(load: bool, xmm: int, offset: int, width: int) -> bytes:
    if width not in (32, 64) or offset < 0 or offset >= 1 << 31 or xmm >= 16:
        fail("XAX.NATIVE.FLOAT_ENCODING", "x86_64", "NATIVE-XMM-MEMORY", "f32/f64 stack access", [xmm, offset, width])
    prefix = b"\xf3" if width == 32 else b"\xf2"
    rex = bytes((0x44,)) if xmm >= 8 else b""
    opcode = 0x10 if load else 0x11
    reg = xmm & 7
    if offset < 128:
        return prefix + rex + b"\x0f" + bytes((opcode, 0x44 | (reg << 3), 0x24, offset))
    return prefix + rex + b"\x0f" + bytes((opcode, 0x84 | (reg << 3), 0x24)) + offset.to_bytes(4, "little")


def _xmm_binary_memory(operation: Operation, xmm: int, offset: int, width: int) -> bytes:
    opcode = {
        Operation.FLOAT_ADD: 0x58,
        Operation.FLOAT_SUB: 0x5C,
        Operation.FLOAT_MUL: 0x59,
        Operation.FLOAT_DIV: 0x5E,
    }[operation]
    prefix = b"\xf3" if width == 32 else b"\xf2"
    reg = xmm & 7
    rex = bytes((0x44,)) if xmm >= 8 else b""
    if offset < 128:
        return prefix + rex + b"\x0f" + bytes((opcode, 0x44 | (reg << 3), 0x24, offset))
    return prefix + rex + b"\x0f" + bytes((opcode, 0x84 | (reg << 3), 0x24)) + offset.to_bytes(4, "little")


def _xmm_compare_registers(left: int, right: int, width: int) -> bytes:
    if width not in (32, 64):
        fail("XAX.NATIVE.FLOAT_ENCODING", "x86_64", "NATIVE-XMM-COMPARE", [32, 64], width)
    prefix = b"" if width == 32 else b"\x66"
    rex = 0x40 | (0x04 if left >= 8 else 0) | (0x01 if right >= 8 else 0)
    rex_bytes = bytes((rex,)) if rex != 0x40 else b""
    return prefix + rex_bytes + b"\x0f\x2e" + bytes((0xC0 | ((left & 7) << 3) | (right & 7),))


def _cvtsi_uint32_to_float(width: int) -> bytes:
    prefix = b"\xf3" if width == 32 else b"\xf2"
    return prefix + b"\x48\x0f\x2a\xc0"


def _cvtt_float_to_int64(width: int) -> bytes:
    prefix = b"\xf3" if width == 32 else b"\xf2"
    return prefix + b"\x48\x0f\x2c\xc0"


def _float_convert_xmm(source_width: int, destination_width: int) -> bytes:
    if source_width == destination_width:
        return b""
    if (source_width, destination_width) == (32, 64):
        return b"\xf3\x0f\x5a\xc0"
    if (source_width, destination_width) == (64, 32):
        return b"\xf2\x0f\x5a\xc0"
    fail("XAX.NATIVE.FLOAT_ENCODING", "x86_64", "NATIVE-FLOAT-CONVERT", [[32, 64], [64, 32]], [source_width, destination_width])


def _xmm_compare_memory(xmm: int, offset: int, width: int) -> bytes:
    prefix = b"" if width == 32 else b"\x66"
    reg = xmm & 7
    rex = bytes((0x44,)) if xmm >= 8 else b""
    if offset < 128:
        return prefix + rex + b"\x0f\x2e" + bytes((0x44 | (reg << 3), 0x24, offset))
    return prefix + rex + b"\x0f\x2e" + bytes((0x84 | (reg << 3), 0x24)) + offset.to_bytes(4, "little")


def _mov_gpr_xmm(to_xmm: bool, xmm: int, register: int, width: int) -> bytes:
    # MOVD/MOVQ between integer and XMM carriers; raw float bits are preserved.
    if width not in (32, 64):
        fail("XAX.NATIVE.FLOAT_ENCODING", "x86_64", "NATIVE-XMM-MOVE", [32, 64], width)
    prefix = b"\x66"
    rex = 0x40 | (0x08 if width == 64 else 0) | (0x04 if xmm >= 8 else 0) | (0x01 if register >= 8 else 0)
    rex_bytes = bytes((rex,)) if rex != 0x40 else b""
    opcode = b"\x0f\x6e" if to_xmm else b"\x0f\x7e"
    return prefix + rex_bytes + opcode + bytes((0xC0 | ((xmm & 7) << 3) | (register & 7),))


def _call_register(register: int) -> bytes:
    rex = bytes((0x41,)) if register >= 8 else b""
    return rex + b"\xff" + bytes((0xD0 | (register & 7),))


def _and_immediate(register: int, value: int, width: int = 64) -> bytes:
    if not 0 <= value <= 0xFFFFFFFF:
        fail("XAX.NATIVE.IMMEDIATE", "x86_64", "NATIVE-AND-IMM32", "0..2^32-1", value)
    rex = 0x40 | (0x08 if width == 64 else 0) | (0x01 if register >= 8 else 0)
    prefix = bytes((rex,)) if rex != 0x40 else b""
    return prefix + b"\x81" + bytes((0xE0 | (register & 7),)) + value.to_bytes(4, "little")


def _or_register(destination: int, source: int) -> bytes:
    rex = 0x48 | (0x04 if source >= 8 else 0) | (0x01 if destination >= 8 else 0)
    return bytes((rex, 0x09, 0xC0 | ((source & 7) << 3) | (destination & 7)))


def _and_register(destination: int, source: int) -> bytes:
    rex = 0x48 | (0x04 if source >= 8 else 0) | (0x01 if destination >= 8 else 0)
    return bytes((rex, 0x21, 0xC0 | ((source & 7) << 3) | (destination & 7)))


def _cmp_registers(left: int, right: int, width: int) -> bytes:
    width = 64 if width == 64 else 32
    rex = 0x40 | (0x08 if width == 64 else 0) | (0x04 if right >= 8 else 0) | (0x01 if left >= 8 else 0)
    prefix = bytes((rex,)) if rex != 0x40 else b""
    return prefix + b"\x39" + bytes((0xC0 | ((right & 7) << 3) | (left & 7),))


def _setcc(kind: IntCompare) -> bytes:
    opcode = {
        IntCompare.EQ: 0x94, IntCompare.NE: 0x95,
        IntCompare.ULT: 0x92, IntCompare.ULE: 0x96,
        IntCompare.UGT: 0x97, IntCompare.UGE: 0x93,
        IntCompare.SLT: 0x9C, IntCompare.SLE: 0x9E,
        IntCompare.SGT: 0x9F, IntCompare.SGE: 0x9D,
    }[kind]
    return b"\x0f" + bytes((opcode, 0xC0)) + b"\x0f\xb6\xc0"


def _float_setcc(kind: FloatCompare) -> bytes:
    if kind == FloatCompare.EQ:
        return b"\x0f\x94\xc0\x0f\x9b\xc2\x20\xd0\x0f\xb6\xc0"
    if kind == FloatCompare.NE:
        return b"\x0f\x95\xc0\x0f\x9a\xc2\x08\xd0\x0f\xb6\xc0"
    opcode = {FloatCompare.LT: 0x92, FloatCompare.LE: 0x96, FloatCompare.GT: 0x97, FloatCompare.GE: 0x93}[kind]
    prefix = b"\x0f" + bytes((opcode, 0xC0))
    if kind in (FloatCompare.LT, FloatCompare.LE):
        prefix += b"\x0f\x9b\xc2\x20\xd0"
    return prefix + b"\x0f\xb6\xc0"


def _mxcsr_store(offset: int) -> bytes:
    # STMXCSR m32, /3
    if offset < 128:
        return b"\x0f\xae\x5c\x24" + bytes((offset,))
    return b"\x0f\xae\x9c\x24" + offset.to_bytes(4, "little")


def _mxcsr_load(offset: int) -> bytes:
    # LDMXCSR m32, /2
    if offset < 128:
        return b"\x0f\xae\x54\x24" + bytes((offset,))
    return b"\x0f\xae\x94\x24" + offset.to_bytes(4, "little")


RSP = 4
RAX = 0
RDX = 2


def _layout(resolve: Callable[[bytes], SemanticObject], cid: bytes) -> AbiLayout | None:
    obj = resolve(cid)
    if obj.kind != Kind.TYPE or not obj.body or _is_proof_type(obj) or _type_form(resolve, cid) not in (1, 2, 7, 8, 9, 10):
        return None
    return abi_layout(obj, resolve, 8)


def _slot_bytes(layout: AbiLayout) -> int:
    return max(8, _align(layout.size, 8))


def _is_aggregate_cid(resolve: Callable[[bytes], SemanticObject], cid: bytes) -> bool:
    return _type_form(resolve, cid) in (8, 9, 10)


def _win64_by_reference(resolve: Callable[[bytes], SemanticObject], cid: bytes) -> bool:
    """Win64 passes and returns aggregates of 1, 2, 4, or 8 bytes in a GPR, others by reference."""
    return _is_aggregate_cid(resolve, cid) and _layout(resolve, cid).size not in (1, 2, 4, 8)


def _abi_kind(resolve: Callable[[bytes], SemanticObject], cid: bytes) -> str:
    if _is_float_cid(resolve, cid):
        return f"f{decode_float_width(resolve(cid))}"
    if _is_aggregate_cid(resolve, cid):
        return f"a{_layout(resolve, cid).size}"
    return f"u{_value_width(resolve, cid) or 64}"


def _rex(wide: bool, reg: int, base: int, *, force: bool = False) -> bytes:
    value = 0x40 | (0x08 if wide else 0) | (0x04 if reg >= 8 else 0) | (0x01 if base >= 8 else 0)
    return bytes((value,)) if value != 0x40 or force else b""


def _modrm_base(reg: int, base: int, offset: int) -> bytes:
    rm = base & 7
    if -128 <= offset < 128:
        head, displacement = 0x40, offset.to_bytes(1, "little", signed=True)
    else:
        head, displacement = 0x80, offset.to_bytes(4, "little", signed=True)
    return bytes((head | ((reg & 7) << 3) | rm,)) + (b"\x24" if rm == 4 else b"") + displacement


def _load_exact(reg: int, base: int, offset: int, size: int) -> bytes:
    """Zero-extending load of 1/2/4/8 bytes from [base+offset]."""
    opcode = {1: b"\x0f\xb6", 2: b"\x0f\xb7", 4: b"\x8b", 8: b"\x8b"}[size]
    return _rex(size == 8, reg, base) + opcode + _modrm_base(reg, base, offset)


def _store_exact(reg: int, base: int, offset: int, size: int) -> bytes:
    if size == 1:
        return _rex(False, reg, base, force=4 <= reg < 8) + b"\x88" + _modrm_base(reg, base, offset)
    return (b"\x66" if size == 2 else b"") + _rex(size == 8, reg, base) + b"\x89" + _modrm_base(reg, base, offset)


def _lea(reg: int, base: int, offset: int) -> bytes:
    return _rex(True, reg, base) + b"\x8d" + _modrm_base(reg, base, offset)


def _zero32(reg: int) -> bytes:
    return _rex(False, reg, reg) + b"\x31" + bytes((0xC0 | ((reg & 7) << 3) | (reg & 7),))


def _copy_bytes(destination_base: int, destination: int, source_base: int, source: int, size: int, temp: int = RAX) -> bytes:
    out, done = bytearray(), 0
    while done < size:
        chunk = next(item for item in (8, 4, 2, 1) if item <= size - done)
        out += _load_exact(temp, source_base, source + done, chunk) + _store_exact(temp, destination_base, destination + done, chunk)
        done += chunk
    return bytes(out)


def _zero_bytes(base: int, offset: int, size: int, temp: int = RAX) -> bytes:
    """Zero an 8-byte-multiple region so aggregate padding is deterministic."""
    return _zero32(temp) + b"".join(_store_exact(temp, base, offset + item, 8) for item in range(0, size, 8))


def _bits_width(resolve: Callable[[bytes], SemanticObject], cid: bytes) -> int | None:
    obj = resolve(cid)
    if obj.kind != Kind.TYPE or not obj.body or obj.body[0] != 1:
        return None
    return decode_bits_width(obj)


def _constant_value(graph, ref: ValueRef, resolve: Callable[[bytes], SemanticObject]) -> int | None:
    """Integer value of ``ref`` when it is directly produced by a CONSTANT node."""
    if ref.tag != 1:
        return None
    node = graph.blocks[ref.block].nodes[ref.index]
    if node.operation != Operation.CONSTANT or node.entity is None:
        return None
    _type, value = _decode_constant(node.entity, resolve)
    return value if isinstance(value, int) else None


# Pointer consumers that address a frame-resident pointer by its static offset.
_STATIC_POINTER_CONSUMERS = frozenset(
    {
        Operation.LOAD_BITS_LE,
        Operation.STORE_BITS_LE,
        Operation.CHECKED_LOAD_BITS_LE,
        Operation.CHECKED_STORE_BITS_LE,
        Operation.RAW_LOAD_BITS_LE,
        Operation.ADDRESS_OFFSET,
        Operation.POINTER_CAST,
        *ATOMIC_OPERATIONS,
    }
)
DYNAMIC_MEMORY_OPERATIONS = frozenset(
    {
        Operation.LOAD_BITS_LE,
        Operation.STORE_BITS_LE,
        Operation.CHECKED_LOAD_BITS_LE,
        Operation.CHECKED_STORE_BITS_LE,
        Operation.RAW_LOAD_BITS_LE,
    }
)


def _escaping_pointers(graph, pointers: dict[ValueRef, int]) -> frozenset[ValueRef]:
    """Frame-resident pointers whose address value is observed outside a static access."""
    escaping: set[ValueRef] = set()
    for block in graph.blocks:
        for node in block.nodes:
            for position, operand in enumerate(node.operands):
                if operand in pointers and not (position == 0 and node.operation in _STATIC_POINTER_CONSUMERS):
                    escaping.add(operand)
        uses = (*block.terminator.values, *(value for _target, arguments in block.terminator.edges for value in arguments))
        escaping.update(value for value in uses if value in pointers)
    return frozenset(escaping)


def _indexed_exact(load: bool, register: int, base: int, index: int, displacement: int, size: int) -> bytes:
    """``[base + index + disp32]`` zero-extending load or exact-width store of 1/2/4/8 bytes."""
    if size not in (1, 2, 4, 8) or index == RSP or not -(1 << 31) <= displacement < 1 << 31:
        fail("XAX.NATIVE.MEMORY_ENCODING", "x86_64", "NATIVE-INDEXED-MEMORY-ENCODABLE", "1/2/4/8-byte [base+index+disp32]", [size, index, displacement])
    rex = 0x40 | (0x08 if size == 8 else 0) | (0x04 if register >= 8 else 0) | (0x02 if index >= 8 else 0) | (0x01 if base >= 8 else 0)
    if load:
        opcode = {1: b"\x0f\xb6", 2: b"\x0f\xb7", 4: b"\x8b", 8: b"\x8b"}[size]
        prefix = b""
    else:
        opcode = b"\x88" if size == 1 else b"\x89"
        prefix = b"\x66" if size == 2 else b""
    # A byte store from spl/bpl/sil/dil needs an otherwise-empty REX prefix.
    force_rex = not load and size == 1 and 4 <= register < 8
    rex_bytes = bytes((rex,)) if rex != 0x40 or force_rex else b""
    modrm = 0x84 | ((register & 7) << 3)
    sib = ((index & 7) << 3) | (base & 7)
    return prefix + rex_bytes + opcode + bytes((modrm, sib)) + displacement.to_bytes(4, "little", signed=True)


def _emit_dynamic_memory(
    assembler: "_Assembler",
    node,
    target: NativeTargetDescription,
    value_slot: Callable[[ValueRef], int],
    result_ref: ValueRef,
    block_index: int,
    node_index: int,
    *,
    pointer_extent: int,
    static_base: int | None = None,
) -> None:
    """Lower a byte-addressed access whose base is a first-class pointer value.

    ``static_base`` reuses the same encoding for frame pointers whose access
    width the legacy fixed-offset path cannot encode (1/2-byte accesses).
    """
    if static_base is None:
        base, displacement = target.argument_registers[0], 0
        assembler.emit(_load(base, value_slot(node.operands[0])))
    else:
        base, displacement = RSP, static_base
    size = node.attributes[0]
    if node.operation in (Operation.LOAD_BITS_LE, Operation.RAW_LOAD_BITS_LE):
        assembler.emit(_load_exact(target.result_register, base, displacement, size))
        assembler.emit(_store(target.result_register, value_slot(result_ref)))
        return
    if node.operation == Operation.STORE_BITS_LE:
        assembler.emit(_load(target.result_register, value_slot(node.operands[1])))
        assembler.emit(_store_exact(target.result_register, base, displacement, size))
        return
    maximum = pointer_extent - size
    if maximum < 0:
        assembler.emit(b"\x0f\x0b")
        return
    index = target.scratch_registers[0]
    assembler.emit(_load(index, value_slot(node.operands[1]), 4))
    assembler.emit(_cmp_imm32(index, maximum))
    in_bounds = f"dynamic-checked-{block_index}-{node_index}"
    assembler.relative(b"\x0f\x86", in_bounds)
    assembler.emit(b"\x0f\x0b")
    assembler.label(in_bounds)
    if node.operation == Operation.CHECKED_LOAD_BITS_LE:
        assembler.emit(_indexed_exact(True, target.result_register, base, index, displacement, size))
        assembler.emit(_store(target.result_register, value_slot(result_ref)))
    else:
        assembler.emit(_load(target.result_register, value_slot(node.operands[2])))
        assembler.emit(_indexed_exact(False, target.result_register, base, index, displacement, size))


# linux-x86_64-syscall-v1: integer/pointer arguments in this register order.
_SYSCALL_ARGUMENT_REGISTERS = (7, 6, 2, 10, 8, 9)  # rdi, rsi, rdx, r10, r8, r9


def encode_syscall_name(number: int, arguments: Sequence[int | str] | None = None) -> bytes:
    """Encode an explicit syscall register template as a foreign symbol name.

    ``arguments`` items are ``"$k"`` (the k-th machine operand) or exact
    unsigned 64-bit literals.  ``None`` passes the machine operands in order.
    The template is semantic identity: no argument is supplied implicitly.
    """
    if not 0 <= number < 1 << 31:
        raise ValueError("syscall number out of range")
    if arguments is None:
        return str(number).encode("ascii")
    items = []
    for item in arguments:
        if isinstance(item, str):
            if not (item.startswith("$") and item[1:].isdigit()):
                raise ValueError("syscall operand reference must be $k")
            items.append(item)
        else:
            if not 0 <= item < 1 << 64:
                raise ValueError("syscall literal must be an unsigned 64-bit value")
            items.append(str(item))
    if len(items) > len(_SYSCALL_ARGUMENT_REGISTERS):
        raise ValueError("Linux x86-64 syscalls take at most six arguments")
    return f"{number}:{','.join(items)}".encode("ascii")


def decode_syscall_name(name: bytes, machine_inputs: int) -> tuple[int, tuple[int | str, ...]]:
    """Inverse of :func:`encode_syscall_name`, validated against the operand count."""
    try:
        text = name.decode("ascii")
        number_text, _, template = text.partition(":")
        number = int(number_text)
        if str(number) != number_text:
            raise ValueError
        if not _:
            arguments: tuple[int | str, ...] = tuple(f"${index}" for index in range(machine_inputs))
        else:
            arguments = tuple(item if item.startswith("$") else int(item) for item in template.split(","))
        if encode_syscall_name(number, arguments if _ else None) != name:
            raise ValueError
    except ValueError:
        fail("XAX.FOREIGN.SYSCALL", name.hex(), "SYSCALL-TEMPLATE-CANONICAL", "nr or nr:arg,...", name.decode("ascii", "replace"))
    references = sorted(int(item[1:]) for item in arguments if isinstance(item, str))
    if references != list(range(machine_inputs)) or len(arguments) > len(_SYSCALL_ARGUMENT_REGISTERS):
        fail("XAX.FOREIGN.SYSCALL", name.hex(), "SYSCALL-TEMPLATE-OPERANDS", f"each of {machine_inputs} machine operands exactly once", list(arguments))
    return number, arguments


# sysv-x86_64-c: INTEGER-class arguments in this order (System V AMD64 psABI).
_SYSV_ARGUMENT_REGISTERS = (7, 6, 2, 1, 8, 9)  # rdi, rsi, rdx, rcx, r8, r9


def _sysv_integer_class(resolve: Callable[[bytes], SemanticObject], cid: bytes) -> bool:
    """bits<1..64> or a pointer: the psABI INTEGER class this lowering supports."""
    width = _value_width(resolve, cid)
    return bool(width) and width <= 64 and not _is_float_cid(resolve, cid) and not _is_aggregate_cid(resolve, cid)


def require_sysv_profile(target: NativeTargetDescription, graph_object: SemanticObject) -> None:
    """C imports need the profile that explicitly requests the dynamic loader."""
    if target.abi != X86_64_LINUX_ABI or target.image_format != X86_64_LINUX_ELF_DYNAMIC_FORMAT:
        fail("XAX.NATIVE.FOREIGN_ABI", graph_object.cid.hex(), "SYSV-C-REQUIRES-DYNAMIC-PROFILE", [X86_64_LINUX_ABI, X86_64_LINUX_ELF_DYNAMIC_FORMAT], [target.abi, target.image_format])


def _emit_sysv_c_call(assembler: "_Assembler", node, resolve, target: NativeTargetDescription, value_slot, graph_object) -> None:
    """Call an imported C function through its GOT slot.

    Only the bounded INTEGER-class subset is lowered: at most six integer or
    pointer arguments of at most 64 bits and at most one such result.  Spill
    code keeps no value in registers across a node and every frame keeps RSP
    16-byte aligned at calls, so the psABI caller obligations are met without
    saving anything.  Floats, aggregates, stack arguments, and variadic calls
    reject rather than being guessed.
    """
    declaration = decode_foreign_function(node.entity)
    require_sysv_profile(target, graph_object)
    machine = [(operand, cid) for operand, cid in zip(node.operands, node.operand_types) if not _is_proof_type(resolve(cid))]
    results = [cid for cid in node.results if not _is_proof_type(resolve(cid))]
    if len(machine) > len(_SYSV_ARGUMENT_REGISTERS) or len(results) > 1 or not all(_sysv_integer_class(resolve, cid) for cid in (*(cid for _, cid in machine), *results)):
        fail("XAX.NATIVE.FOREIGN_ABI", graph_object.cid.hex(), "SYSV-C-INTEGER-CLASS", "<=6 integer/pointer arguments, <=1 integer/pointer result", [len(machine), len(results)])
    for register, (operand, _cid) in zip(_SYSV_ARGUMENT_REGISTERS, machine):
        assembler.emit(_load(register, value_slot(operand)))
    assembler.foreign_call(declaration.library, declaration.name)


def _linux_syscall(node, resolve, target: NativeTargetDescription, value_slot, graph_object) -> bytes:
    declaration = decode_foreign_function(node.entity)
    if declaration.abi != LINUX_X86_64_SYSCALL_ABI or target.abi != X86_64_LINUX_ABI:
        fail("XAX.NATIVE.FOREIGN_ABI", graph_object.cid.hex(), "NATIVE-FOREIGN-ABI-TARGET", [LINUX_X86_64_SYSCALL_ABI.decode(), X86_64_LINUX_ABI], [declaration.abi.decode("ascii", "replace"), target.abi])
    machine = tuple(operand for operand, cid in zip(node.operands, node.operand_types) if not _is_proof_type(resolve(cid)))
    if sum(1 for cid in node.results if not _is_proof_type(resolve(cid))) > 1:
        fail("XAX.NATIVE.FOREIGN_ABI", graph_object.cid.hex(), "SYSCALL-ONE-RESULT", 1, len(node.results))
    number, arguments = decode_syscall_name(declaration.name, len(machine))
    code = bytearray()
    for register, argument in zip(_SYSCALL_ARGUMENT_REGISTERS, arguments):
        if isinstance(argument, str):
            code += _load(register, value_slot(machine[int(argument[1:])]))
        else:
            code += _immediate(register, argument)
    code += b"\xb8" + number.to_bytes(4, "little")  # mov eax, nr
    code += b"\x0f\x05"  # syscall (clobbers rcx, r11; no value lives in registers here)
    if declaration.allocator is not None:
        # The kernel reports failure as -4095..-1; the allocator contract's
        # nullable result is the explicit ABI projection of that range.
        code += b"\x48\x3d\x01\xf0\xff\xff"  # cmp rax, -4095
        code += b"\x72\x02"  # jb success
        code += b"\x31\xc0"  # xor eax, eax
    return bytes(code)


def _general_x86_target(target: NativeTargetDescription) -> bool:
    return (
        Operation.FLOAT_ADD in target.supported_operations
        or Operation.AGGREGATE_MAKE in target.supported_operations
        or Operation.SUM_MAKE in target.supported_operations
    )


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
        machine_returns = tuple(cid for cid in returns if not _is_proof_type(resolve(cid)))
        # A Win64 by-reference return consumes the first argument position.
        # The legacy raw profile remains register-only; the general profile
        # follows Win64 into 8-byte stack argument slots after the first four.
        hidden = int(bool(machine_returns) and _win64_by_reference(resolve, machine_returns[0]))
        if len(machine_returns) > 1 or (not _general_x86_target(target) and len(machine_parameters) + hidden > len(target.argument_registers)):
            fail("XAX.NATIVE.ABI", function.cid.hex(), "NATIVE-ABI-ARITY", ["Win64 stack arguments" if _general_x86_target(target) else len(target.argument_registers), 1], [len(machine_parameters) + hidden, len(machine_returns)])
        for cid in (*machine_parameters, *machine_returns):
            layout = _layout(resolve, cid)
            if layout is None or (not _is_aggregate_cid(resolve, cid) and layout.size > 8):
                fail("XAX.NATIVE.VALUE", function.cid.hex(), "NATIVE-ABI-VALUE", "scalar <=64 bits or aggregate with a target ABI layout", [cid.hex() for cid in (*parameters, *returns)])
        graph = _parse_graph(graph_object, resolve)
        for block in graph.blocks:
            for node in block.nodes:
                if node.operation not in target.supported_operations:
                    fail("XAX.NATIVE.UNSUPPORTED_OPERATION", graph_object.cid.hex(), "NATIVE-OP-TARGET-SUPPORTED", list(target.supported_operations), node.operation)
                if node.operation in (Operation.CALL_DIRECT, Operation.FUNCTION_ADDRESS):
                    if node.entity is not None and node.entity.kind == Kind.FUNCTION and not _is_erased_proof_function(node.entity, resolve):
                        visit(node.entity)
            if block.terminator.kind not in target.supported_terminators:
                fail("XAX.NATIVE.UNSUPPORTED_TERMINATOR", graph_object.cid.hex(), "NATIVE-TERMINATOR-TARGET-SUPPORTED", list(target.supported_terminators), block.terminator.kind)

    visit(entry)
    return tuple(functions[cid] for cid in sorted(functions))


def _compile_register_resident_function(
    function: SemanticObject,
    graph_object: SemanticObject,
    graph,
    return_types: tuple[bytes, ...],
    resolve: Callable[[bytes], SemanticObject],
    target: NativeTargetDescription,
) -> tuple[bytes, tuple[tuple[int, bytes], ...], tuple[ArtifactSemanticRange, ...]] | None:
    allowed = {
        Operation.ADD_WRAP,
        Operation.SUB_WRAP,
        Operation.MUL_WRAP,
        Operation.CONSTANT,
        Operation.CALL_DIRECT,
        *RESOURCE_EFFECT_OPERATIONS,
    }
    if any(node.operation not in allowed for block in graph.blocks for node in block.nodes):
        return None
    if any(block.terminator.kind not in (TerminatorKind.RETURN, TerminatorKind.BRANCH, TerminatorKind.CONDITIONAL_BRANCH) for block in graph.blocks):
        return None
    _graph, function_parameters, function_returns = _decode_function_interface(function, resolve)
    machine_function_parameters = tuple(cid for cid in function_parameters if not _is_proof_type(resolve(cid)))
    if len(machine_function_parameters) > len(target.argument_registers):
        return None
    if any(not _bits_width(resolve, cid) for cid in (*function_parameters, *function_returns) if not _is_proof_type(resolve(cid))):
        return None
    for block in graph.blocks:
        for node in block.nodes:
            if node.operation == Operation.CALL_DIRECT:
                machine_call_inputs = tuple(cid for cid in node.operand_types if not _is_proof_type(resolve(cid)))
                if len(machine_call_inputs) > len(target.argument_registers):
                    return None
                if any(not _bits_width(resolve, cid) for cid in (*node.operand_types, *node.results) if not _is_proof_type(resolve(cid))):
                    return None

    allocatable = tuple(dict.fromkeys((*target.argument_registers, target.scratch_registers[0], target.result_register)))
    scratch = target.scratch_registers[1]
    if target.result_register is None or scratch in allocatable:
        return None

    widths: dict[ValueRef, int] = {}
    machine_parameters: dict[int, tuple[ValueRef, ...]] = {}
    for block_index, block in enumerate(graph.blocks):
        params: list[ValueRef] = []
        for index, type_cid in enumerate(block.parameters):
            width = _bits_width(resolve, type_cid)
            if width and width <= 64:
                value = ValueRef.parameter(block_index, index)
                widths[value] = width
                params.append(value)
        machine_parameters[block_index] = tuple(params)
        for node_index, node in enumerate(block.nodes):
            for result_index, type_cid in enumerate(node.results):
                width = _value_width(resolve, type_cid)
                if width and width <= 64:
                    widths[ValueRef.node_result(block_index, node_index, result_index)] = width

    has_call = any(
        node.operation == Operation.CALL_DIRECT and not _is_erased_proof_function(node.entity, resolve)
        for block in graph.blocks
        for node in block.nodes
    )
    edge_spill_base = target.shadow_space if has_call else 0
    edge_spill_count = max(
        (max(0, len(machine_parameters[index]) - len(allocatable)) for index in range(len(graph.blocks))),
        default=0,
    )
    dynamic_spill_base = edge_spill_base + edge_spill_count * 8

    def block_uses(block_index: int) -> dict[ValueRef, tuple[int, ...]]:
        block = graph.blocks[block_index]
        uses: dict[ValueRef, list[int]] = {}
        for node_index, node in enumerate(block.nodes):
            for operand in node.operands:
                if operand in widths:
                    uses.setdefault(operand, []).append(node_index)
        position = len(block.nodes)
        for value in block.terminator.values:
            if value in widths:
                uses.setdefault(value, []).append(position)
        for _, arguments in block.terminator.edges:
            for value in arguments:
                if value in widths:
                    uses.setdefault(value, []).append(position)
        return {value: tuple(items) for value, items in uses.items()}

    uses_by_block = {index: block_uses(index) for index in range(len(graph.blocks))}

    def lower_block(block_index: int, assembler: _Assembler | None, ranges: list[ArtifactSemanticRange] | None = None) -> int:
        block = graph.blocks[block_index]
        uses = uses_by_block[block_index]
        last_use = {value: positions[-1] for value, positions in uses.items()}
        register_for: dict[ValueRef, int] = {}
        value_for_register: dict[int, ValueRef] = {}
        spill_offset: dict[ValueRef, int] = {}
        spill_id: dict[ValueRef, int] = {}
        free_spills: list[int] = []
        next_spill = 0
        max_spills = 0

        def emit(data: bytes) -> None:
            if assembler is not None:
                assembler.emit(data)

        def width_bytes(value: ValueRef) -> int:
            return 8 if widths[value] == 64 else 4

        def bind(value: ValueRef, register: int) -> None:
            old_value = value_for_register.get(register)
            if old_value is not None and old_value != value:
                register_for.pop(old_value, None)
            old_register = register_for.get(value)
            if old_register is not None and old_register != register:
                value_for_register.pop(old_register, None)
            register_for[value] = register
            value_for_register[register] = value

        def unbind(value: ValueRef) -> None:
            register = register_for.pop(value, None)
            if register is not None and value_for_register.get(register) == value:
                value_for_register.pop(register, None)

        def release(value: ValueRef) -> None:
            unbind(value)
            slot = spill_id.pop(value, None)
            if slot is not None:
                spill_offset.pop(value, None)
                free_spills.append(slot)

        def next_use(value: ValueRef, position: int) -> int:
            return next((item for item in uses.get(value, ()) if item > position), 1 << 30)

        def spill(value: ValueRef, keep: bool = False) -> None:
            nonlocal next_spill, max_spills
            register = register_for[value]
            if value not in spill_offset:
                if free_spills:
                    slot = min(free_spills)
                    free_spills.remove(slot)
                else:
                    slot = next_spill
                    next_spill += 1
                    max_spills = max(max_spills, next_spill)
                spill_id[value] = slot
                spill_offset[value] = dynamic_spill_base + slot * 8
                emit(_store(register, spill_offset[value], width_bytes(value)))
            if not keep:
                unbind(value)

        def acquire(position: int, protected: set[ValueRef] | None = None) -> int:
            protected = protected or set()
            for register in allocatable:
                if register not in value_for_register:
                    return register
            candidates = [value for value in register_for if value not in protected]
            if not candidates:
                fail("XAX.NATIVE.REGISTER_PRESSURE", graph_object.cid.hex(), "NATIVE-SPILLABLE-REGISTER", "one non-protected live value", len(protected))
            victim = max(candidates, key=lambda value: (next_use(value, position), register_for[value], value.tag, value.block, value.index, value.result))
            register = register_for[victim]
            spill(victim)
            return register

        def ensure(value: ValueRef, position: int, protected: set[ValueRef] | None = None) -> int:
            if value in register_for:
                return register_for[value]
            try:
                offset = spill_offset[value]
            except KeyError:
                fail("XAX.NATIVE.VALUE", graph_object.cid.hex(), "NATIVE-VALUE-LOCATION", "register or spill", [value.block, value.index, value.result])
            register = acquire(position, protected)
            emit(_load(register, offset, width_bytes(value)))
            bind(value, register)
            return register

        def parallel_moves(assignments: list[tuple[int, int, int]]) -> None:
            pending = [(dst, src, width) for dst, src, width in assignments if dst != src]
            while pending:
                sources = {src for _, src, _ in pending}
                safe = next((i for i, (dst, _, _) in enumerate(pending) if dst not in sources), None)
                if safe is not None:
                    dst, src, width = pending.pop(safe)
                    emit(_move_register(dst, src, width))
                    continue
                dst, src, width = pending[0]
                emit(_move_register(scratch, src, width))
                pending = [(d, scratch if s == src else s, w) for d, s, w in pending]

        for index, value in enumerate(machine_parameters[block_index]):
            if index < len(allocatable):
                bind(value, allocatable[index])
            else:
                spill_offset[value] = edge_spill_base + (index - len(allocatable)) * 8
        for value in machine_parameters[block_index]:
            if value not in last_use:
                release(value)

        def location(value: ValueRef) -> tuple[str, int]:
            if value in register_for:
                return "reg", register_for[value]
            if value in spill_offset:
                return "spill", spill_offset[value]
            fail("XAX.NATIVE.VALUE", graph_object.cid.hex(), "NATIVE-VALUE-LOCATION", "register or spill", [value.block, value.index, value.result])

        def copy_edge(target_block: int, arguments: tuple[ValueRef, ...]) -> None:
            destinations = machine_parameters[target_block]
            pairs: list[tuple[ValueRef, int, ValueRef]] = []
            for index, argument in enumerate(arguments):
                destination = ValueRef.parameter(target_block, index)
                if argument in widths and destination in widths:
                    pairs.append((argument, destinations.index(destination), destination))
            for source, index, destination in pairs:
                if index < len(allocatable):
                    continue
                destination_offset = edge_spill_base + (index - len(allocatable)) * 8
                kind, source_location = location(source)
                if kind == "reg":
                    emit(_store(source_location, destination_offset, width_bytes(destination)))
                elif source_location != destination_offset:
                    emit(_load(scratch, source_location, width_bytes(source)))
                    emit(_store(scratch, destination_offset, width_bytes(destination)))
            moves: list[tuple[int, int, int]] = []
            delayed: list[tuple[int, int, int]] = []
            for source, index, destination in pairs:
                if index >= len(allocatable):
                    continue
                kind, source_location = location(source)
                if kind == "reg":
                    moves.append((allocatable[index], source_location, widths[destination]))
                else:
                    delayed.append((allocatable[index], source_location, width_bytes(destination)))
            parallel_moves(moves)
            for register, offset, width in delayed:
                emit(_load(register, offset, width))

        def prepare_call(position: int, operands: tuple[ValueRef, ...]) -> set[ValueRef]:
            for operand in operands:
                ensure(operand, position)
            live_after = {value for value in set((*register_for, *spill_offset)) if last_use.get(value, -1) > position}
            for value in sorted(live_after, key=lambda item: (item.tag, item.block, item.index, item.result)):
                if value in register_for:
                    spill(value, keep=True)
            moves: list[tuple[int, int, int]] = []
            for destination, operand in zip(target.argument_registers, operands):
                kind, source = location(operand)
                if kind == "reg":
                    moves.append((destination, source, widths[operand]))
            parallel_moves(moves)
            for destination, operand in zip(target.argument_registers, operands):
                kind, source = location(operand)
                if kind == "spill":
                    emit(_load(destination, source, width_bytes(operand)))
            return live_after

        if assembler is not None:
            assembler.label(f"block-{block_index}")

        for node_index, node in enumerate(block.nodes):
            start = len(assembler.code) if assembler is not None else 0
            result = ValueRef.node_result(block_index, node_index)
            if node.operation in (Operation.ADD_WRAP, Operation.SUB_WRAP, Operation.MUL_WRAP):
                width = widths[result]
                left, right = node.operands
                left_register = ensure(left, node_index)
                right_register = ensure(right, node_index, {left} if right != left else set())
                if last_use.get(left) == node_index:
                    destination, source = left_register, right_register
                elif last_use.get(right) == node_index and node.operation in (Operation.ADD_WRAP, Operation.MUL_WRAP):
                    destination, source = right_register, left_register
                else:
                    destination, source = acquire(node_index, {left, right}), right_register
                    emit(_move_register(destination, left_register, width))
                emit(_register_arithmetic(node.operation, destination, source, width))
                for operand in {left, right}:
                    if last_use.get(operand) == node_index:
                        release(operand)
                bind(result, destination)
                if result not in last_use:
                    release(result)

            elif node.operation == Operation.CONSTANT:
                _, value = _decode_constant(node.entity, resolve)
                register = acquire(node_index)
                emit(_immediate(register, value))
                bind(result, register)
                if result not in last_use:
                    release(result)

            elif node.operation == Operation.CALL_DIRECT and not _is_erased_proof_function(node.entity, resolve):
                operands = tuple(operand for operand in node.operands if operand in widths)
                results = tuple(
                    ValueRef.node_result(block_index, node_index, result_index)
                    for result_index, type_cid in enumerate(node.results)
                    if _bits_width(resolve, type_cid) is not None
                )
                live_after = prepare_call(node_index, operands)
                if assembler is not None:
                    assembler.call(node.entity.cid)
                for value in tuple(register_for):
                    unbind(value)
                for value in tuple(spill_id):
                    if value not in live_after:
                        release(value)
                if results:
                    bind(results[0], target.result_register)
                    if results[0] not in last_use:
                        release(results[0])

            elif node.operation not in RESOURCE_EFFECT_OPERATIONS and node.operation != Operation.CALL_DIRECT:
                return max_spills

            if assembler is not None and ranges is not None and len(assembler.code) > start:
                ranges.append(ArtifactSemanticRange(function.cid, block_index, node_index, start, len(assembler.code)))

        terminator = block.terminator
        position = len(block.nodes)
        if terminator.kind == TerminatorKind.RETURN:
            values = tuple(value for value in terminator.values if value in widths)
            if values:
                value = values[0]
                if value in register_for:
                    source = register_for[value]
                    if source != target.result_register:
                        emit(_move_register(target.result_register, source, widths[value]))
                else:
                    emit(_load(target.result_register, spill_offset[value], width_bytes(value)))
            else:
                emit(b"\x31\xc0")
            return max_spills
        if terminator.kind == TerminatorKind.BRANCH:
            target_block, arguments = terminator.edges[0]
            copy_edge(target_block, arguments)
            if assembler is not None:
                assembler.relative(b"\xe9", f"block-{target_block}")
        elif terminator.kind == TerminatorKind.CONDITIONAL_BRANCH:
            condition = terminator.values[0]
            register = ensure(condition, position)
            emit(_test_register(register, widths[condition]))
            false_label = f"false-{block_index}"
            if assembler is not None:
                assembler.relative(b"\x0f\x84", false_label)
            target_block, arguments = terminator.edges[0]
            copy_edge(target_block, arguments)
            if assembler is not None:
                assembler.relative(b"\xe9", f"block-{target_block}")
                assembler.label(false_label)
            target_block, arguments = terminator.edges[1]
            copy_edge(target_block, arguments)
            if assembler is not None:
                assembler.relative(b"\xe9", f"block-{target_block}")
        else:
            reason, _ = decode_trap_payload(terminator.payload)
            emit(_immediate(target.result_register, reason))
            emit(b"\x0f\x0b")
        return max_spills

    spill_count = max((lower_block(index, None) for index in range(len(graph.blocks))), default=0)
    payload = dynamic_spill_base + spill_count * 8
    frame_size = (_align(payload + 8, target.stack_alignment) - 8) if payload else 0
    assembler = _Assembler()
    if frame_size:
        assembler.emit(b"\x48\x81\xec" + frame_size.to_bytes(4, "little"))
    if graph.entry:
        assembler.relative(b"\xe9", f"block-{graph.entry}")
    ranges: list[ArtifactSemanticRange] = []
    for block_index, block in enumerate(graph.blocks):
        observed = lower_block(block_index, assembler, ranges)
        if observed > spill_count:
            fail("XAX.NATIVE.SPILL_PLAN", graph_object.cid.hex(), "NATIVE-SPILL-PLAN-DETERMINISTIC", spill_count, observed)
        if block.terminator.kind == TerminatorKind.RETURN:
            if frame_size:
                assembler.emit(b"\x48\x81\xc4" + frame_size.to_bytes(4, "little"))
            assembler.emit(b"\xc3")
    code, calls = assembler.finish()
    return code, calls, tuple(ranges)


def _compile_function(
    function: SemanticObject,
    resolve: Callable[[bytes], SemanticObject],
    target: NativeTargetDescription,
    atomic_policy: AtomicLegalizationPolicy,
) -> tuple[bytes, tuple[tuple[int, bytes], ...], tuple[ArtifactSemanticRange, ...]]:
    graph_object, parameter_types, return_types = _decode_function_interface(function, resolve)
    graph = _parse_graph(graph_object, resolve)
    for block in graph.blocks:
        for node in block.nodes:
            if node.operation in ATOMIC_OPERATIONS:
                capability = atomic_capability(target, *_atomic_node_request(node, resolve))
                selected = select_atomic_legalization(capability, atomic_policy)
                if selected == AtomicSupport.UNSUPPORTED:
                    fail(
                        "XAX.NATIVE.ATOMIC_UNSUPPORTED",
                        graph_object.cid.hex(),
                        "NATIVE-ATOMIC-CAPABILITY",
                        [AtomicSupport.NATIVE.name.lower(), AtomicSupport.BOUNDED_SEQUENCE.name.lower()],
                        capability.support.name.lower(),
                    )
                if selected == AtomicSupport.RUNTIME_ASSIST:
                    fail(
                        "XAX.NATIVE.ATOMIC_RUNTIME_ASSIST",
                        graph_object.cid.hex(),
                        "NATIVE-ATOMIC-RUNTIME-ASSIST-EXPLICIT",
                        "backend-declared explicit assist",
                        "none",
                    )
    if target.abi == X86_64_LINUX_ABI:
        from xax_x86_64_regalloc import compile_register_resident

        allocated = compile_register_resident(function, graph_object, graph, parameter_types, return_types, resolve, target)
        if allocated is not None:
            return allocated
    register_resident = _compile_register_resident_function(
        function, graph_object, graph, return_types, resolve, target
    )
    if register_resident is not None:
        return (*register_resident, ())

    # Every machine value owns a frame slot holding its target ABI layout bytes
    # (zero padded to 8).  Scalars keep the historical one-qword slot; larger
    # aggregates occupy consecutive qwords.
    slots: dict[ValueRef, int] = {}
    layouts: dict[ValueRef, AbiLayout] = {}
    outgoing_stack_slots = 0
    for block in graph.blocks:
        for node in block.nodes:
            if node.operation not in (Operation.CALL_DIRECT, Operation.CALL_FOREIGN, Operation.CALL_INDIRECT):
                continue
            machine_inputs = [cid for cid in node.operand_types if not _is_proof_type(resolve(cid))]
            if node.operation == Operation.CALL_INDIRECT and machine_inputs:
                machine_inputs = machine_inputs[1:]
            machine_results = [cid for cid in node.results if not _is_proof_type(resolve(cid))]
            hidden_call_return = int(bool(machine_results) and _win64_by_reference(resolve, machine_results[0]))
            outgoing_stack_slots = max(
                outgoing_stack_slots,
                max(0, len(machine_inputs) + hidden_call_return - len(target.argument_registers)),
            )
    # At every real call RSP already names the mandatory 32-byte Win64 home
    # area; stack arguments occupy successive 8-byte slots immediately after it.
    cursor = target.shadow_space + outgoing_stack_slots * 8

    for block_index, block in enumerate(graph.blocks):
        for index, type_cid in enumerate(block.parameters):
            if _is_proof_type(resolve(type_cid)):
                continue
            layout = _layout(resolve, type_cid)
            if layout is None or (not _is_aggregate_cid(resolve, type_cid) and layout.size > 8):
                fail("XAX.NATIVE.BLOCK_TYPE", graph_object.cid.hex(), "NATIVE-BLOCK-PARAMETER-VALUE", "scalar <=64 bits or aggregate", type_cid.hex())
            if _win64_by_reference(resolve, type_cid):
                # Win64 requires caller-provided indirect aggregate temporaries
                # to be 16-byte aligned.  Align every by-reference aggregate
                # slot so the same storage is also valid as a hidden-return
                # destination or a subsequent indirect argument source.
                cursor = _align(cursor, 16)
            slots[ValueRef.parameter(block_index, index)] = cursor
            layouts[ValueRef.parameter(block_index, index)] = layout
            cursor += _slot_bytes(layout)
        for node_index, node in enumerate(block.nodes):
            for result_index, type_cid in enumerate(node.results):
                layout = _layout(resolve, type_cid)
                if layout is not None and (_is_aggregate_cid(resolve, type_cid) or layout.size <= 8):
                    if _win64_by_reference(resolve, type_cid):
                        cursor = _align(cursor, 16)
                    slots[ValueRef.node_result(block_index, node_index, result_index)] = cursor
                    layouts[ValueRef.node_result(block_index, node_index, result_index)] = layout
                    cursor += _slot_bytes(layout)

    temporary_base = cursor
    cursor += max(
        (
            sum(_slot_bytes(layouts[ValueRef.parameter(block_index, index)]) for index in range(len(block.parameters)) if ValueRef.parameter(block_index, index) in slots)
            for block_index, block in enumerate(graph.blocks)
        ),
        default=0,
    )
    pointers: dict[ValueRef, int] = {}
    pointer_extents: dict[ValueRef, int] = {}
    # Profiles with a foreign/heap boundary treat pointers as first-class
    # machine values; legacy profiles keep their frame-offset-only pointers.
    dynamic_pointers = Operation.HEAP_VIEW in target.supported_operations and target.abi == X86_64_LINUX_ABI
    for block_index, block in enumerate(graph.blocks):
        for node_index, node in enumerate(block.nodes):
            result = ValueRef.node_result(block_index, node_index)
            if node.operation == Operation.STACK_ALLOC:
                cursor = _align(cursor, node.attributes[1])
                pointers[result] = cursor
                pointer_extents[result] = node.attributes[0]
                cursor += node.attributes[0]
            elif node.operation == Operation.ADDRESS_OFFSET:
                if node.operands[0] in pointers:
                    pointers[result] = pointers[node.operands[0]] + node.attributes[0]
                    pointer_extents[result] = pointer_extents[node.operands[0]] - node.attributes[0]
                elif not dynamic_pointers:
                    fail("XAX.NATIVE.POINTER", graph_object.cid.hex(), "NATIVE-POINTER-LOCAL", "local stack pointer", node.operands[0].index)
            elif node.operation == Operation.POINTER_CAST:
                if node.operands[0] in pointers:
                    pointers[result] = pointers[node.operands[0]]
                    pointer_extents[result] = pointer_extents[node.operands[0]]

    escaping_pointers = _escaping_pointers(graph, pointers) if dynamic_pointers else frozenset()
    float_control = any(
        node.operation in (
            Operation.FLOAT_ADD, Operation.FLOAT_SUB, Operation.FLOAT_MUL, Operation.FLOAT_DIV,
            Operation.FLOAT_COMPARE, Operation.UINT_TO_FLOAT, Operation.FLOAT_TO_UINT_TRUNC, Operation.FLOAT_CONVERT,
            Operation.SINT_TO_FLOAT, Operation.FLOAT_TO_SINT_TRUNC,
        )
        for block in graph.blocks for node in block.nodes
    )
    mxcsr_old = mxcsr_ieee = None
    if float_control:
        mxcsr_old, mxcsr_ieee = cursor, cursor + 4
        cursor += 8
    machine_returns = tuple(cid for cid in return_types if not _is_proof_type(resolve(cid)))
    hidden_return = bool(machine_returns) and _win64_by_reference(resolve, machine_returns[0])
    return_pointer_slot = None
    if hidden_return:
        return_pointer_slot = cursor
        cursor += 8
    # A by-reference argument is a caller-owned copy the callee may write, so
    # each such argument of each call gets its own frame copy.
    call_copies: dict[tuple[int, int, int], int] = {}
    for block_index, block in enumerate(graph.blocks):
        for node_index, node in enumerate(block.nodes):
            if node.operation not in (Operation.CALL_DIRECT, Operation.CALL_FOREIGN, Operation.CALL_INDIRECT):
                continue
            for operand_index, type_cid in enumerate(node.operand_types):
                if not _is_proof_type(resolve(type_cid)) and _win64_by_reference(resolve, type_cid):
                    cursor = _align(cursor, 16)
                    call_copies[(block_index, node_index, operand_index)] = cursor
                    cursor += _slot_bytes(_layout(resolve, type_cid))
    frame_size = _align(cursor + 8, target.stack_alignment) - 8
    assembler = _Assembler()
    assembler.emit(b"\x48\x81\xec" + frame_size.to_bytes(4, "little"))
    entry = graph.blocks[graph.entry]
    argument_position = 0
    if hidden_return:
        assembler.emit(_store(target.argument_registers[0], return_pointer_slot))
        argument_position = 1
    for index, type_cid in enumerate(entry.parameters):
        if _is_proof_type(resolve(type_cid)):
            continue
        value_ref = ValueRef.parameter(graph.entry, index)
        destination = slots[value_ref]
        layout = layouts[value_ref]
        if argument_position < len(target.argument_registers):
            if _is_float_cid(resolve, type_cid):
                assembler.emit(_xmm_memory(False, argument_position, destination, decode_float_width(resolve(type_cid))))
            elif _is_aggregate_cid(resolve, type_cid):
                register = target.argument_registers[argument_position]
                assembler.emit(_zero_bytes(RSP, destination, _slot_bytes(layout)))
                if _win64_by_reference(resolve, type_cid):
                    assembler.emit(_copy_bytes(RSP, destination, register, 0, layout.size))
                else:
                    assembler.emit(_store_exact(register, RSP, destination, layout.size))
            else:
                assembler.emit(_store(target.argument_registers[argument_position], destination))
        else:
            incoming = frame_size + 8 + target.shadow_space + (argument_position - len(target.argument_registers)) * 8
            if _is_float_cid(resolve, type_cid):
                assembler.emit(_xmm_memory(True, 4, incoming, decode_float_width(resolve(type_cid))))
                assembler.emit(_xmm_memory(False, 4, destination, decode_float_width(resolve(type_cid))))
            elif _is_aggregate_cid(resolve, type_cid):
                assembler.emit(_zero_bytes(RSP, destination, _slot_bytes(layout)))
                if _win64_by_reference(resolve, type_cid):
                    assembler.emit(_load(target.scratch_registers[0], incoming))
                    assembler.emit(_copy_bytes(RSP, destination, target.scratch_registers[0], 0, layout.size))
                else:
                    assembler.emit(_load_exact(target.scratch_registers[0], RSP, incoming, layout.size))
                    assembler.emit(_store_exact(target.scratch_registers[0], RSP, destination, layout.size))
            else:
                assembler.emit(_load(target.scratch_registers[0], incoming))
                assembler.emit(_store(target.scratch_registers[0], destination))
        argument_position += 1
    if graph.entry:
        assembler.relative(b"\xe9", f"block-{graph.entry}")
    node_ranges: list[ArtifactSemanticRange] = []

    def value_slot(value: ValueRef) -> int:
        try:
            return slots[value]
        except KeyError:
            fail("XAX.NATIVE.VALUE", graph_object.cid.hex(), "NATIVE-VALUE-MACHINE", "scalar/compact value <=64 bits", [value.block, value.index, value.result])

    def begin_float() -> None:
        if mxcsr_old is None or mxcsr_ieee is None:
            return
        assembler.emit(_mxcsr_store(mxcsr_old))
        assembler.emit(_load(target.result_register, mxcsr_old, 4))
        assembler.emit(_and_immediate(target.result_register, 0xFFFF1FBF, width=32))
        assembler.emit(_store(target.result_register, mxcsr_ieee, 4))
        assembler.emit(_mxcsr_load(mxcsr_ieee))

    def end_float() -> None:
        if mxcsr_old is not None:
            assembler.emit(_mxcsr_load(mxcsr_old))

    def mask_register(register: int, width: int) -> None:
        if width >= 64:
            return
        mask = (1 << width) - 1
        if mask <= 0xFFFFFFFF:
            assembler.emit(_and_immediate(register, mask, width=32 if width <= 32 else 64))
            return
        temporary = target.scratch_registers[1] if register != target.scratch_registers[1] else target.result_register
        assembler.emit(_immediate(temporary, mask))
        assembler.emit(_and_register(register, temporary))

    def copy_edge(target_block: int, arguments: tuple[ValueRef, ...]) -> None:
        machine_arguments = tuple(
            (argument, ValueRef.parameter(target_block, index))
            for index, argument in enumerate(arguments)
            if argument in slots and ValueRef.parameter(target_block, index) in slots
        )
        placements: list[tuple[int, ValueRef, int]] = []
        temporary = temporary_base
        for argument, destination in machine_arguments:
            size = _slot_bytes(layouts[destination])
            for qword in range(0, size, 8):
                assembler.emit(_load(target.scratch_registers[1], value_slot(argument) + qword))
                assembler.emit(_store(target.scratch_registers[1], temporary + qword))
            placements.append((temporary, destination, size))
            temporary += size
        for temporary, destination, size in placements:
            for qword in range(0, size, 8):
                assembler.emit(_load(target.scratch_registers[1], temporary + qword))
                assembler.emit(_store(target.scratch_registers[1], slots[destination] + qword))

    for block_index, block in enumerate(graph.blocks):
        assembler.label(f"block-{block_index}")
        for node_index, node in enumerate(block.nodes):
            node_start = len(assembler.code)
            result_ref = ValueRef.node_result(block_index, node_index)
            if node.operation in (Operation.UDIV, Operation.UREM):
                width = _bits_width(resolve, node.results[0])
                if width not in (32, 64):
                    fail("XAX.NATIVE.BITS", graph_object.cid.hex(), "NATIVE-BITS-SUPPORTED", [32, 64], width)
                divisor = target.scratch_registers[0]
                assembler.emit(_load(target.result_register, value_slot(node.operands[0]), 8 if width == 64 else 4))
                if (_constant_value(graph, node.operands[1], resolve) or 0) == 0:
                    # Divisor not proven nonzero: the explicit portable trap is emitted.
                    assembler.emit(_load(divisor, value_slot(node.operands[1]), 8 if width == 64 else 4))
                    assembler.emit(_test_register(divisor, width))
                    nonzero = f"divisor-nonzero-{block_index}-{node_index}"
                    assembler.relative(b"\x0f\x85", nonzero)
                    assembler.emit(_immediate(target.result_register, TrapReason.INTEGER_DIVIDE_BY_ZERO))
                    assembler.emit(b"\x0f\x0b")
                    assembler.label(nonzero)
                else:
                    assembler.emit(_load(divisor, value_slot(node.operands[1]), 8 if width == 64 else 4))
                assembler.emit(_zero32(RDX))
                assembler.emit(_rex(width == 64, 0, divisor) + b"\xf7" + bytes((0xF0 | (divisor & 7),)))  # div divisor
                quotient_or_remainder = target.result_register if node.operation == Operation.UDIV else RDX
                assembler.emit(_store(quotient_or_remainder, value_slot(result_ref)))
            elif node.operation in (Operation.INT_TRUNCATE, Operation.INT_ZERO_EXTEND):
                # Machine slots hold zero-extended values, so widening is a copy
                # and narrowing masks to the exact result width.
                assembler.emit(_load(target.result_register, value_slot(node.operands[0])))
                if node.operation == Operation.INT_TRUNCATE:
                    mask_register(target.result_register, _bits_width(resolve, node.results[0]))
                assembler.emit(_store(target.result_register, value_slot(result_ref)))
            elif node.operation in (Operation.ADD_WRAP, Operation.SUB_WRAP, Operation.MUL_WRAP, Operation.BIT_XOR, Operation.BIT_AND, Operation.BIT_OR):
                width = _bits_width(resolve, node.results[0])
                assembler.emit(_load(target.result_register, value_slot(node.operands[0]), 8 if width == 64 else 4))
                assembler.emit(_load(target.scratch_registers[0], value_slot(node.operands[1]), 8 if width == 64 else 4))
                assembler.emit(_arithmetic(node.operation, width))
                assembler.emit(_store(target.result_register, value_slot(result_ref)))
            elif node.operation == Operation.ROTATE_RIGHT:
                width = _bits_width(resolve, node.results[0])
                assembler.emit(_load(target.result_register, value_slot(node.operands[0]), 8 if width == 64 else 4))
                assembler.emit(_rotate_right_immediate(target.result_register, node.attributes[0], width))
                assembler.emit(_store(target.result_register, value_slot(result_ref)))
            elif node.operation == Operation.CONSTANT:
                type_cid, value = _decode_constant(node.entity, resolve)
                if _is_float_cid(resolve, type_cid):
                    width = decode_float_width(resolve(type_cid))
                    assembler.emit(_immediate(target.result_register, _float_raw_bits(value, width)))
                    assembler.emit(_store(target.result_register, value_slot(result_ref), width // 8))
                else:
                    assembler.emit(_immediate(target.result_register, value))
                    assembler.emit(_store(target.result_register, value_slot(result_ref)))
            elif node.operation in (Operation.FLOAT_ADD, Operation.FLOAT_SUB, Operation.FLOAT_MUL, Operation.FLOAT_DIV):
                width = decode_float_width(resolve(node.results[0]))
                begin_float()
                assembler.emit(_xmm_memory(True, 0, value_slot(node.operands[0]), width))
                assembler.emit(_xmm_binary_memory(node.operation, 0, value_slot(node.operands[1]), width))
                assembler.emit(_xmm_memory(False, 0, value_slot(result_ref), width))
                end_float()
            elif node.operation == Operation.FLOAT_COMPARE:
                width = decode_float_width(resolve(node.operand_types[0]))
                begin_float()
                assembler.emit(_xmm_memory(True, 0, value_slot(node.operands[0]), width))
                assembler.emit(_xmm_compare_memory(0, value_slot(node.operands[1]), width))
                assembler.emit(_float_setcc(FloatCompare(node.attributes[0])))
                assembler.emit(_store(target.result_register, value_slot(result_ref)))
                end_float()
            elif node.operation in (Operation.UINT_TO_FLOAT, Operation.SINT_TO_FLOAT):
                width = decode_float_width(resolve(node.results[0]))
                source_width = decode_bits_width(resolve(node.operand_types[0]))
                signed = node.operation == Operation.SINT_TO_FLOAT
                begin_float()
                assembler.emit(_load(target.result_register, value_slot(node.operands[0]), 4 if source_width <= 32 else 8))
                if signed and source_width == 32:
                    assembler.emit(b"\x48\x63\xc0")  # movsxd rax, eax
                elif signed and source_width < 64:
                    assembler.emit(bytes((0x48, 0xC1, 0xE0, 64 - source_width)))  # shl rax, 64-w
                    assembler.emit(bytes((0x48, 0xC1, 0xF8, 64 - source_width)))  # sar rax, 64-w
                if signed or source_width < 64:
                    # Every unsigned value below 2**63 is exactly representable
                    # as a signed 64-bit source; one cvtsi2s rounds once.
                    assembler.emit(_cvtsi_uint32_to_float(width))
                else:
                    large = f"uint64-to-float-large-{block_index}-{node_index}"
                    converted = f"uint64-to-float-done-{block_index}-{node_index}"
                    assembler.emit(b"\x48\x85\xc0")  # test rax, rax
                    assembler.relative(b"\x0f\x88", large)
                    assembler.emit(_cvtsi_uint32_to_float(width))
                    assembler.relative(b"\xe9", converted)
                    assembler.label(large)
                    # Halve with a sticky low bit, convert, double: one correct rounding.
                    assembler.emit(_move_register(10, RAX, 64))
                    assembler.emit(b"\x49\xd1\xea")  # shr r10, 1
                    assembler.emit(b"\x83\xe0\x01")  # and eax, 1
                    assembler.emit(_or_register(10, RAX))
                    assembler.emit((b"\xf3" if width == 32 else b"\xf2") + b"\x49\x0f\x2a\xc2")  # cvtsi2s xmm0, r10
                    assembler.emit((b"\xf3" if width == 32 else b"\xf2") + b"\x0f\x58\xc0")  # adds xmm0, xmm0
                    assembler.label(converted)
                assembler.emit(_xmm_memory(False, 0, value_slot(result_ref), width))
                end_float()
            elif node.operation in (Operation.FLOAT_TO_UINT_TRUNC, Operation.FLOAT_TO_SINT_TRUNC):
                in_width = decode_float_width(resolve(node.operand_types[0]))
                out_width = decode_bits_width(resolve(node.results[0]))
                signed = node.operation == Operation.FLOAT_TO_SINT_TRUNC
                trap = f"float-convert-trap-{block_index}-{node_index}"
                done = f"float-convert-done-{block_index}-{node_index}"
                prefix = b"\xf3" if in_width == 32 else b"\xf2"

                def compare_with(value: float) -> None:
                    assembler.emit(_immediate(target.result_register, _float_raw_bits(value, in_width)))
                    assembler.emit(_mov_gpr_xmm(True, 1, target.result_register, in_width))
                    assembler.emit(_xmm_compare_registers(0, 1, in_width))

                begin_float()
                assembler.emit(_xmm_memory(True, 0, value_slot(node.operands[0]), in_width))
                if signed:
                    # Truncation fits iff -2**(w-1)-1 < v < 2**(w-1).  When the
                    # exclusive lower bound is not representable, the next
                    # representable value up is -2**(w-1) itself.  Unordered
                    # compares set CF, so NaN traps on the lower check.
                    lower = -(1 << (out_width - 1))
                    if _int_to_float(lower - 1, in_width) == lower - 1:
                        compare_with(float(lower - 1))
                        assembler.relative(b"\x0f\x86", trap)
                    else:
                        compare_with(float(lower))
                        assembler.relative(b"\x0f\x82", trap)
                    compare_with(float(1 << (out_width - 1)))
                    assembler.relative(b"\x0f\x83", trap)
                    assembler.emit(_cvtt_float_to_int64(in_width))
                    mask_register(target.result_register, out_width)
                else:
                    assembler.emit(_immediate(target.result_register, 0))
                    assembler.emit(_mov_gpr_xmm(True, 1, target.result_register, in_width))
                    assembler.emit(_xmm_compare_registers(0, 1, in_width))
                    assembler.relative(b"\x0f\x82", trap)
                    compare_with(float(1 << out_width))
                    assembler.relative(b"\x0f\x83", trap)
                    if out_width < 64:
                        assembler.emit(_cvtt_float_to_int64(in_width))
                    else:
                        small = f"float-to-uint64-small-{block_index}-{node_index}"
                        converted = f"float-to-uint64-done-{block_index}-{node_index}"
                        compare_with(float(1 << 63))
                        assembler.relative(b"\x0f\x82", small)
                        assembler.emit(prefix + b"\x0f\x5c\xc1")  # subs xmm0, xmm1
                        assembler.emit(_cvtt_float_to_int64(in_width))
                        assembler.emit(b"\x48\x0f\xba\xf8\x3f")  # btc rax, 63
                        assembler.relative(b"\xe9", converted)
                        assembler.label(small)
                        assembler.emit(_cvtt_float_to_int64(in_width))
                        assembler.label(converted)
                assembler.emit(_store(target.result_register, value_slot(result_ref)))
                end_float()
                assembler.relative(b"\xe9", done)
                assembler.label(trap)
                end_float()
                assembler.emit(b"\x0f\x0b")
                assembler.label(done)
            elif node.operation == Operation.FLOAT_CONVERT:
                source_width = decode_float_width(resolve(node.operand_types[0]))
                destination_width = decode_float_width(resolve(node.results[0]))
                begin_float()
                assembler.emit(_xmm_memory(True, 0, value_slot(node.operands[0]), source_width))
                conversion = _float_convert_xmm(source_width, destination_width)
                if conversion:
                    assembler.emit(conversion)
                assembler.emit(_xmm_memory(False, 0, value_slot(result_ref), destination_width))
                end_float()
            elif node.operation == Operation.INT_COMPARE:
                width = decode_bits_width(resolve(node.operand_types[0]))
                assembler.emit(_load(target.result_register, value_slot(node.operands[0]), 8 if width == 64 else 4))
                assembler.emit(_load(target.scratch_registers[0], value_slot(node.operands[1]), 8 if width == 64 else 4))
                assembler.emit(_cmp_registers(target.result_register, target.scratch_registers[0], width))
                assembler.emit(_setcc(IntCompare(node.attributes[0])))
                assembler.emit(_store(target.result_register, value_slot(result_ref)))
            elif node.operation == Operation.AGGREGATE_MAKE:
                layout = layouts[result_ref]
                destination = value_slot(result_ref)
                assembler.emit(_zero_bytes(RSP, destination, _slot_bytes(layout)))
                for operand, offset in zip(node.operands, layout.offsets):
                    assembler.emit(_copy_bytes(RSP, destination + offset, RSP, value_slot(operand), layouts[operand].size))
            elif node.operation == Operation.AGGREGATE_GET:
                offset = layouts[node.operands[0]].offsets[node.attributes[0]]
                destination = value_slot(result_ref)
                assembler.emit(_zero_bytes(RSP, destination, _slot_bytes(layouts[result_ref])))
                assembler.emit(_copy_bytes(RSP, destination, RSP, value_slot(node.operands[0]) + offset, layouts[result_ref].size))
            elif node.operation == Operation.SUM_MAKE:
                layout = layouts[result_ref]
                destination = value_slot(result_ref)
                assembler.emit(_zero_bytes(RSP, destination, _slot_bytes(layout)))
                assembler.emit(_immediate(target.result_register, node.attributes[0]))
                assembler.emit(_store_exact(target.result_register, RSP, destination, 4))
                assembler.emit(_copy_bytes(RSP, destination + layout.payload_offset, RSP, value_slot(node.operands[0]), layouts[node.operands[0]].size))
            elif node.operation == Operation.SUM_TAG:
                assembler.emit(_load_exact(target.result_register, RSP, value_slot(node.operands[0]), 4))
                assembler.emit(_store(target.result_register, value_slot(result_ref)))
            elif node.operation == Operation.SUM_GET:
                source = value_slot(node.operands[0])
                ok = f"sum-get-ok-{block_index}-{node_index}"
                assembler.emit(_load_exact(target.result_register, RSP, source, 4))
                assembler.emit(_cmp_imm32(target.result_register, node.attributes[0]))
                assembler.relative(b"\x0f\x84", ok)
                assembler.emit(b"\x0f\x0b")
                assembler.label(ok)
                destination = value_slot(result_ref)
                assembler.emit(_zero_bytes(RSP, destination, _slot_bytes(layouts[result_ref])))
                assembler.emit(_copy_bytes(RSP, destination, RSP, source + layouts[node.operands[0]].payload_offset, layouts[result_ref].size))
            elif node.operation == Operation.FUNCTION_ADDRESS:
                assembler.address(target.result_register, node.entity.cid)
                assembler.emit(_store(target.result_register, value_slot(result_ref)))
            elif node.operation in (Operation.CALL_DIRECT, Operation.CALL_INDIRECT):
                operand_pairs = tuple(
                    (operand, cid, operand_index)
                    for operand_index, (operand, cid) in enumerate(zip(node.operands, node.operand_types))
                    if not _is_proof_type(resolve(cid))
                )
                if node.operation == Operation.CALL_INDIRECT:
                    function_operand = operand_pairs[0]
                    operand_pairs = operand_pairs[1:]
                machine_results = tuple((index, cid) for index, cid in enumerate(node.results) if not _is_proof_type(resolve(cid)))
                hidden = bool(machine_results) and _win64_by_reference(resolve, machine_results[0][1])
                if len(machine_results) > 1:
                    fail("XAX.NATIVE.ABI", graph_object.cid.hex(), "NATIVE-CALL-ARITY", ["Win64 stack arguments", 1], [len(operand_pairs) + hidden, len(machine_results)])
                for operand, cid, operand_index in operand_pairs:
                    if _win64_by_reference(resolve, cid):
                        assembler.emit(_copy_bytes(RSP, call_copies[(block_index, node_index, operand_index)], RSP, value_slot(operand), layouts[operand].size))
                if node.operation == Operation.CALL_INDIRECT:
                    assembler.emit(_load(target.scratch_registers[1], value_slot(function_operand[0])))
                if hidden:
                    assembler.emit(_lea(target.argument_registers[0], RSP, value_slot(ValueRef.node_result(block_index, node_index, machine_results[0][0]))))
                for position, (operand, cid, operand_index) in enumerate(operand_pairs, start=int(hidden)):
                    if position < len(target.argument_registers):
                        if _is_float_cid(resolve, cid):
                            assembler.emit(_xmm_memory(True, position, value_slot(operand), decode_float_width(resolve(cid))))
                        elif _win64_by_reference(resolve, cid):
                            assembler.emit(_lea(target.argument_registers[position], RSP, call_copies[(block_index, node_index, operand_index)]))
                        else:
                            assembler.emit(_load(target.argument_registers[position], value_slot(operand)))
                        continue
                    outgoing = target.shadow_space + (position - len(target.argument_registers)) * 8
                    if _is_float_cid(resolve, cid):
                        assembler.emit(_xmm_memory(True, 4, value_slot(operand), decode_float_width(resolve(cid))))
                        assembler.emit(_xmm_memory(False, 4, outgoing, decode_float_width(resolve(cid))))
                    elif _win64_by_reference(resolve, cid):
                        assembler.emit(_lea(target.scratch_registers[0], RSP, call_copies[(block_index, node_index, operand_index)]))
                        assembler.emit(_store(target.scratch_registers[0], outgoing))
                    elif _is_aggregate_cid(resolve, cid):
                        layout = layouts[operand]
                        assembler.emit(_load_exact(target.scratch_registers[0], RSP, value_slot(operand), layout.size))
                        assembler.emit(_store_exact(target.scratch_registers[0], RSP, outgoing, layout.size))
                    else:
                        assembler.emit(_load(target.scratch_registers[0], value_slot(operand)))
                        assembler.emit(_store(target.scratch_registers[0], outgoing))
                if node.operation == Operation.CALL_INDIRECT:
                    assembler.emit(_call_register(target.scratch_registers[1]))
                elif not _is_erased_proof_function(node.entity, resolve):
                    assembler.call(node.entity.cid)
                if machine_results and not hidden:
                    result_index, cid = machine_results[0]
                    slot = value_slot(ValueRef.node_result(block_index, node_index, result_index))
                    if _is_float_cid(resolve, cid):
                        assembler.emit(_xmm_memory(False, 0, slot, decode_float_width(resolve(cid))))
                    elif _is_aggregate_cid(resolve, cid):
                        # Bytes above the aggregate in RAX are unspecified by Win64.
                        assembler.emit(_zero_bytes(RSP, slot, 8, temp=target.scratch_registers[0]))
                        assembler.emit(_store_exact(target.result_register, RSP, slot, _layout(resolve, cid).size))
                    else:
                        assembler.emit(_store(target.result_register, slot))
            elif node.operation in (Operation.STACK_ALLOC, Operation.ADDRESS_OFFSET, Operation.POINTER_CAST) and result_ref in escaping_pointers:
                # A frame-resident pointer that flows into a call, edge, or
                # return is materialized once at its definition.
                assembler.emit(_lea(target.result_register, RSP, pointers[result_ref]))
                assembler.emit(_store(target.result_register, value_slot(result_ref)))
            elif node.operation == Operation.ADDRESS_OFFSET and result_ref not in pointers:
                assembler.emit(_load(target.result_register, value_slot(node.operands[0])))
                assembler.emit(_lea(target.result_register, target.result_register, node.attributes[0]))
                assembler.emit(_store(target.result_register, value_slot(result_ref)))
            elif node.operation == Operation.HEAP_VIEW:
                # The allocator result is nullable; the proven view is backed by
                # an explicit runtime trap, never by an assumption.
                nonnull = f"heap-view-nonnull-{block_index}-{node_index}"
                assembler.emit(_load(target.result_register, value_slot(node.operands[0])))
                assembler.emit(_test_register(target.result_register, 64))
                assembler.relative(b"\x0f\x85", nonnull)
                assembler.emit(b"\x0f\x0b")
                assembler.label(nonnull)
                assembler.emit(_store(target.result_register, value_slot(result_ref)))
            elif node.operation == Operation.CALL_FOREIGN:
                if decode_foreign_function(node.entity).abi == SYSV_X86_64_C_ABI:
                    _emit_sysv_c_call(assembler, node, resolve, target, value_slot, graph_object)
                else:
                    assembler.emit(_linux_syscall(node, resolve, target, value_slot, graph_object))
                machine_results = tuple((index, cid) for index, cid in enumerate(node.results) if not _is_proof_type(resolve(cid)))
                if machine_results:
                    result_index, cid = machine_results[0]
                    mask_register(target.result_register, _value_width(resolve, cid) or 64)
                    assembler.emit(_store(target.result_register, value_slot(ValueRef.node_result(block_index, node_index, result_index))))
            elif dynamic_pointers and node.operation in DYNAMIC_MEMORY_OPERATIONS and node.operands[0] not in pointers:
                _emit_dynamic_memory(assembler, node, target, value_slot, result_ref, block_index, node_index, pointer_extent=pointer_extent_from_graph(graph, node.operands[0], resolve) if node.operation in (Operation.CHECKED_LOAD_BITS_LE, Operation.CHECKED_STORE_BITS_LE) else 0)
            elif node.operation in (Operation.CHECKED_LOAD_BITS_LE, Operation.CHECKED_STORE_BITS_LE, Operation.LOAD_BITS_LE, Operation.STORE_BITS_LE) and node.attributes[0] not in (4, 8):
                _emit_dynamic_memory(assembler, node, target, value_slot, result_ref, block_index, node_index, pointer_extent=pointer_extents[node.operands[0]], static_base=pointers[node.operands[0]])
            elif node.operation == Operation.CHECKED_LOAD_BITS_LE:
                size, _alignment = node.attributes
                base = pointers[node.operands[0]]
                extent = pointer_extents[node.operands[0]]
                maximum = extent - size
                if maximum < 0:
                    assembler.emit(b"\x0f\x0b")
                else:
                    index_register = target.scratch_registers[0]
                    assembler.emit(_load(index_register, value_slot(node.operands[1]), 4))
                    assembler.emit(_cmp_imm32(index_register, maximum))
                    ok = f"checked-load-{block_index}-{node_index}"
                    assembler.relative(b"\x0f\x86", ok)
                    assembler.emit(b"\x0f\x0b")
                    assembler.label(ok)
                    assembler.emit(_indexed_load(target.result_register, index_register, base, size))
                    assembler.emit(_store(target.result_register, value_slot(result_ref)))
            elif node.operation == Operation.CHECKED_STORE_BITS_LE:
                size, _alignment = node.attributes
                base = pointers[node.operands[0]]
                extent = pointer_extents[node.operands[0]]
                maximum = extent - size
                if maximum < 0:
                    assembler.emit(b"\x0f\x0b")
                else:
                    index_register = target.scratch_registers[0]
                    assembler.emit(_load(index_register, value_slot(node.operands[1]), 4))
                    assembler.emit(_cmp_imm32(index_register, maximum))
                    ok = f"checked-store-{block_index}-{node_index}"
                    assembler.relative(b"\x0f\x86", ok)
                    assembler.emit(b"\x0f\x0b")
                    assembler.label(ok)
                    assembler.emit(_load(target.result_register, value_slot(node.operands[2])))
                    assembler.emit(_indexed_store(target.result_register, index_register, base, size))
            elif node.operation == Operation.RAW_LOAD_BITS_LE:
                assembler.emit(_load(target.result_register, pointers[node.operands[0]], node.attributes[0]))
                assembler.emit(_store(target.result_register, value_slot(result_ref)))
            elif node.operation == Operation.STORE_BITS_LE:
                assembler.emit(_load(target.result_register, value_slot(node.operands[1])))
                assembler.emit(_store(target.result_register, pointers[node.operands[0]], node.attributes[0]))
            elif node.operation == Operation.LOAD_BITS_LE:
                assembler.emit(_load(target.result_register, pointers[node.operands[0]], node.attributes[0]))
                assembler.emit(_store(target.result_register, value_slot(result_ref)))
            elif node.operation == Operation.ATOMIC_LOAD:
                width = _bits_width(resolve, node.results[0])
                size = width // 8
                assembler.emit(_load(target.result_register, pointers[node.operands[0]], size))
                if AtomicOrder(node.attributes[0]) == AtomicOrder.SEQ_CST:
                    assembler.emit(_fence(AtomicOrder.SEQ_CST))
                assembler.emit(_store(target.result_register, value_slot(result_ref)))
            elif node.operation == Operation.ATOMIC_STORE:
                width = _bits_width(resolve, node.operand_types[1])
                size = width // 8
                assembler.emit(_load(target.result_register, value_slot(node.operands[1])))
                if AtomicOrder(node.attributes[0]) == AtomicOrder.SEQ_CST:
                    assembler.emit(_atomic_memory_instruction(b"\x87", target.result_register, pointers[node.operands[0]], size))
                else:
                    assembler.emit(_store(target.result_register, pointers[node.operands[0]], size))
            elif node.operation == Operation.ATOMIC_RMW:
                width = _bits_width(resolve, node.results[0])
                size = width // 8
                assembler.emit(_load(target.result_register, value_slot(node.operands[1])))
                kind = AtomicRmwKind(node.attributes[0])
                opcode = b"\x87" if kind == AtomicRmwKind.EXCHANGE else b"\x0f\xc1"
                assembler.emit(_atomic_memory_instruction(opcode, target.result_register, pointers[node.operands[0]], size, locked=kind == AtomicRmwKind.ADD_WRAP))
                assembler.emit(_store(target.result_register, value_slot(result_ref)))
            elif node.operation == Operation.ATOMIC_CMPXCHG:
                width = _bits_width(resolve, node.results[0])
                size = width // 8
                assembler.emit(_load(target.result_register, value_slot(node.operands[1])))
                assembler.emit(_load(target.scratch_registers[0], value_slot(node.operands[2])))
                assembler.emit(_atomic_memory_instruction(b"\x0f\xb1", target.scratch_registers[0], pointers[node.operands[0]], size, locked=True))
                assembler.emit(_store(target.result_register, value_slot(result_ref)))
                assembler.emit(b"\x0f\x94\xc0\x0f\xb6\xc0")
                assembler.emit(_store(target.result_register, value_slot(ValueRef.node_result(block_index, node_index, 1))))
            elif node.operation == Operation.ATOMIC_FENCE:
                assembler.emit(_fence(AtomicOrder(node.attributes[0])))
            elif node.operation == Operation.POINTER_CAST:
                if result_ref not in pointers:
                    assembler.emit(_load(target.result_register, value_slot(node.operands[0])))
                    assembler.emit(_store(target.result_register, value_slot(result_ref)))
            elif node.operation not in (Operation.STACK_ALLOC, Operation.ADDRESS_OFFSET, Operation.STACK_END, *RESOURCE_EFFECT_OPERATIONS):
                fail("XAX.NATIVE.UNSUPPORTED_OPERATION", graph_object.cid.hex(), "NATIVE-OP-LOWERED", list(target.supported_operations), node.operation)
            node_end = len(assembler.code)
            if node_end > node_start:
                node_ranges.append(ArtifactSemanticRange(function.cid, block_index, node_index, node_start, node_end))

        terminator = block.terminator
        if terminator.kind == TerminatorKind.RETURN:
            machine_values = tuple((value, cid) for value, cid in zip(terminator.values, return_types) if not _is_proof_type(resolve(cid)))
            if machine_values:
                value, cid = machine_values[0]
                if _is_float_cid(resolve, cid):
                    assembler.emit(_xmm_memory(True, 0, value_slot(value), decode_float_width(resolve(cid))))
                elif hidden_return:
                    pointer_register = target.scratch_registers[0]
                    assembler.emit(_load(pointer_register, return_pointer_slot))
                    assembler.emit(_copy_bytes(pointer_register, 0, RSP, value_slot(value), layouts[value].size))
                    assembler.emit(_move_register(target.result_register, pointer_register, 64))
                else:
                    assembler.emit(_load(target.result_register, value_slot(value)))
            else:
                assembler.emit(b"\x31\xc0")
            assembler.emit(b"\x48\x81\xc4" + frame_size.to_bytes(4, "little") + b"\xc3")
        elif terminator.kind == TerminatorKind.BRANCH:
            target_block, arguments = terminator.edges[0]
            copy_edge(target_block, arguments)
            assembler.relative(b"\xe9", f"block-{target_block}")
        elif terminator.kind == TerminatorKind.CONDITIONAL_BRANCH:
            assembler.emit(_load(target.result_register, value_slot(terminator.values[0])))
            assembler.emit(b"\x48\x85\xc0")
            false_label = f"false-{block_index}"
            assembler.relative(b"\x0f\x84", false_label)
            true_target, true_arguments = terminator.edges[0]
            copy_edge(true_target, true_arguments)
            assembler.relative(b"\xe9", f"block-{true_target}")
            assembler.label(false_label)
            false_target, false_arguments = terminator.edges[1]
            copy_edge(false_target, false_arguments)
            assembler.relative(b"\xe9", f"block-{false_target}")
        else:
            reason, _target_data = decode_trap_payload(terminator.payload)
            assembler.emit(_immediate(target.result_register, reason))
            assembler.emit(b"\x0f\x0b")
    code, calls = assembler.finish()
    return code, calls, tuple(node_ranges), tuple(assembler.foreign_calls)


def _compile_native_with_target(
    reader: StoreReader,
    function_cid: bytes,
    target_object: SemanticObject,
    realtime_profile: RealtimeProfile | None = None,
    atomic_policy: AtomicLegalizationPolicy = AtomicLegalizationPolicy(),
) -> NativeImage:
    verify_store(reader)
    resolve = store_resolver(reader)
    entry = resolve(function_cid)
    if entry.kind != Kind.FUNCTION:
        fail("XAX.NATIVE.FUNCTION", function_cid.hex(), "NATIVE-ENTRY-FUNCTION", Kind.FUNCTION.name, entry.kind.name)
    description = decode_native_target(target_object)
    functions = _function_closure(entry, resolve, description)
    fragments: dict[bytes, tuple[bytes, tuple[tuple[int, bytes], ...], tuple[ArtifactSemanticRange, ...], tuple[tuple[int, bytes, bytes], ...]]] = {
        function.cid: _compile_function(function, resolve, description, atomic_policy) for function in functions
    }
    if realtime_profile is not None:
        validate_realtime_profile(analyze_realtime(reader, function_cid, target_object), realtime_profile)
    offsets: dict[bytes, int] = {}
    image = bytearray()
    semantic_ranges: list[ArtifactSemanticRange] = []
    for function in functions:
        while len(image) % 16:
            image.append(0x90)
        base = len(image)
        offsets[function.cid] = base
        fragment = fragments[function.cid][0]
        image.extend(fragment)
        semantic_ranges.append(ArtifactSemanticRange(function.cid, None, None, base, base + len(fragment)))
        semantic_ranges.extend(
            ArtifactSemanticRange(item.function_cid, item.block_index, item.node_index, base + item.start, base + item.end)
            for item in fragments[function.cid][2]
        )
    for function in functions:
        base = offsets[function.cid]
        for local_position, callee in fragments[function.cid][1]:
            position = base + local_position
            displacement = offsets[callee] - (position + 4)
            image[position : position + 4] = displacement.to_bytes(4, "little", signed=True)
    foreign_calls = tuple(
        (offsets[function.cid] + position, library, name)
        for function in functions
        for position, library, name in fragments[function.cid][3]
    )
    _, parameter_types, return_types = _decode_function_interface(entry, resolve)
    return NativeImage(
        bytes(image),
        offsets[entry.cid],
        tuple(_value_width(resolve, cid) or 64 for cid in parameter_types if not _is_proof_type(resolve(cid))),
        tuple(_value_width(resolve, cid) or 64 for cid in return_types if not _is_proof_type(resolve(cid))),
        target_object.cid,
        tuple((function.cid, offsets[function.cid]) for function in functions),
        tuple(semantic_ranges),
        tuple(_abi_kind(resolve, cid) for cid in parameter_types if not _is_proof_type(resolve(cid))),
        tuple(_abi_kind(resolve, cid) for cid in return_types if not _is_proof_type(resolve(cid))),
        foreign_calls,
    )


def compile_native(
    reader: StoreReader,
    function_cid: bytes,
    target_cid: bytes,
    realtime_profile: RealtimeProfile | None = None,
    atomic_policy: AtomicLegalizationPolicy = AtomicLegalizationPolicy(),
) -> NativeImage:
    resolve = store_resolver(reader)
    return _compile_native_with_target(reader, function_cid, resolve(target_cid), realtime_profile, atomic_policy)


def compile_native_bound_target(
    reader: StoreReader,
    function_cid: bytes,
    target_object: SemanticObject,
    realtime_profile: RealtimeProfile | None = None,
    atomic_policy: AtomicLegalizationPolicy = AtomicLegalizationPolicy(),
) -> NativeImage:
    """Compile against an explicitly bound target package that need not be stored under the program root."""
    return _compile_native_with_target(reader, function_cid, target_object, realtime_profile, atomic_policy)


def _ctype(kind: str):
    if kind == "f32":
        return ctypes.c_float
    if kind == "f64":
        return ctypes.c_double
    if kind.startswith("a"):
        # Win64 classifies aggregates purely by size, so a byte-array struct
        # of the same size exercises exactly the ABI the compiler targets.
        return type(f"XaxAggregate{kind[1:]}", (ctypes.Structure,), {"_fields_": [("bytes", ctypes.c_ubyte * int(kind[1:]))]})
    return ctypes.c_uint64


def run_native(image: NativeImage, arguments: Sequence[object]) -> tuple[object, ...]:
    """Call the entry through libffi.  Floats are Python floats; aggregates are layout bytes."""
    if sys.platform != "win32" or platform.machine().lower() not in ("amd64", "x86_64"):
        fail("XAX.NATIVE.HOST", "host", "NATIVE-HOST-X86-64-WINDOWS", "Windows x86-64", [sys.platform, platform.machine()])
    if len(arguments) != len(image.parameter_widths):
        fail("XAX.NATIVE.ARGUMENT_COUNT", "entry", "NATIVE-ARGUMENT-COUNT", len(image.parameter_widths), len(arguments))
    parameter_kinds = image.parameter_kinds or tuple(f"u{width}" for width in image.parameter_widths)
    return_kinds = image.return_kinds or tuple(f"u{width}" for width in image.return_widths)
    for argument, width, kind in zip(arguments, image.parameter_widths, parameter_kinds):
        if kind.startswith("u") and (argument < 0 or argument >= 1 << width):
            fail("XAX.NATIVE.ARGUMENT_RANGE", "entry", "NATIVE-ARGUMENT-RANGE", f"bits<{width}>", argument)

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.VirtualAlloc.argtypes = (ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_uint32)
    kernel32.VirtualAlloc.restype = ctypes.c_void_p
    kernel32.VirtualProtect.argtypes = (ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32))
    kernel32.VirtualProtect.restype = ctypes.c_int
    kernel32.VirtualFree.argtypes = (ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32)
    kernel32.VirtualFree.restype = ctypes.c_int
    kernel32.GetCurrentProcess.restype = ctypes.c_void_p
    kernel32.FlushInstructionCache.argtypes = (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t)
    kernel32.FlushInstructionCache.restype = ctypes.c_int
    address = kernel32.VirtualAlloc(None, len(image.code), 0x3000, 0x04)
    if not address:
        raise OSError(ctypes.get_last_error(), "VirtualAlloc")
    try:
        ctypes.memmove(address, image.code, len(image.code))
        old_protection = ctypes.c_uint32()
        if not kernel32.VirtualProtect(address, len(image.code), 0x20, ctypes.byref(old_protection)):
            raise OSError(ctypes.get_last_error(), "VirtualProtect")
        kernel32.FlushInstructionCache(kernel32.GetCurrentProcess(), address, len(image.code))
        argument_types = [_ctype(kind) for kind in parameter_kinds]
        values = [
            argument_type.from_buffer_copy(bytes(argument)) if kind.startswith("a") else argument
            for argument, argument_type, kind in zip(arguments, argument_types, parameter_kinds)
        ]
        restype = _ctype(return_kinds[0]) if return_kinds else ctypes.c_uint64
        prototype = ctypes.CFUNCTYPE(restype, *argument_types)
        result = prototype(address + image.entry_offset)(*values)
        if not return_kinds:
            return ()
        if return_kinds[0].startswith("a"):
            return (bytes(result),)
        if return_kinds[0].startswith("f"):
            return (float(result),)
        return (result & ((1 << image.return_widths[0]) - 1),)
    finally:
        kernel32.VirtualFree(address, 0, 0x8000)


def run_native_isolated(image: NativeImage, arguments: Sequence[object]) -> tuple[object, ...]:
    payload = {
        "code": image.code.hex(),
        "entry": image.entry_offset,
        "parameter_widths": list(image.parameter_widths),
        "return_widths": list(image.return_widths),
        "parameter_kinds": list(image.parameter_kinds),
        "return_kinds": list(image.return_kinds),
        "arguments": [{"hex": bytes(item).hex()} if isinstance(item, (bytes, bytearray)) else item for item in arguments],
    }
    command = [sys.executable, "-m", "xax_x86_64", "--json", json.dumps(payload)]
    completed = subprocess.run(command, check=False, capture_output=True, text=True)
    if completed.returncode:
        raise RuntimeError(completed.stderr.strip() or f"native child exited {completed.returncode}")
    return tuple(bytes.fromhex(item["hex"]) if isinstance(item, dict) else item for item in json.loads(completed.stdout))


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if len(arguments) != 2 or arguments[0] != "--json":
        return 2
    payload = json.loads(arguments[1])
    image = NativeImage(
        bytes.fromhex(payload["code"]), payload["entry"], tuple(payload["parameter_widths"]), tuple(payload["return_widths"]),
        bytes(32), (), (), tuple(payload["parameter_kinds"]), tuple(payload["return_kinds"]),
    )
    values = tuple(bytes.fromhex(item["hex"]) if isinstance(item, dict) else item for item in payload["arguments"])
    results = run_native(image, values)
    print(json.dumps([{"hex": item.hex()} if isinstance(item, bytes) else item for item in results]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
