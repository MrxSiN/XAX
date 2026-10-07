"""Direct RISC-V RV64IM backend (ADR-113): verified XAX -> raw position-independent image.

``riscv64-baremetal-raw-v1`` is the integer subset: ``bits<N>`` (N <= 64)
values, wrapping arithmetic, bitwise operations, unsigned division, rotates,
width changes, compares, direct calls, and the four terminators.  It needs
only the RV64I base ISA plus the M extension (``mul``/``divu``/``remu``).

Lowering contract:

* every XAX function follows the LP64 integer calling convention: machine
  arguments in a0-a7 and then on the stack (8 bytes each, at the caller's
  sp), one machine result in a0, return address in ra;
* views profile aggregates (ADR-151): a tuple or array of ``bits<N <= 64>``
  fields is no machine value.  ``aggregate.make`` emits nothing and
  ``aggregate.get`` of a made aggregate is that field; a function returning
  an aggregate takes the address of a caller-owned result area as a hidden
  first argument (LP64's indirect return) and stores each field there as one
  zero-extended doubleword; ``aggregate.get`` of a call's aggregate loads it;
* values are kept zero-extended to their width in 64-bit registers and
  frame slots; a linear scan over block-liveness interval hulls keeps values
  in the eleven callee-saved registers (s1-s11) and spills the rest;
* RISC-V ``divu``/``remu`` do not trap on a zero divisor, so the lowering
  emits the explicit test that makes a zero divisor the XAX trap;
* a trap is ``unimp`` (an illegal-instruction exception): on bare metal it
  enters the platform's exception vector; nothing else is emitted;
* every control transfer is PC-relative (``jal``/branches), so the image runs
  at any address; there is no runtime, loader, relocation, or data section.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Sequence

from xax_artifact import ArtifactSemanticRange
from xax_views_lowering import (
    Aggregates,
    allocate_registers,
    apply_aliases,
    function_closure,
    machine_width,
    pointer_extents,
    result_fields,
    rewrite_borrowed_views,
)
from xax_compiler import parse_function_graph
from xax_compiler import (
    IntCompare,
    Kind,
    Operation,
    RESOURCE_EFFECT_OPERATIONS,
    RISCV64_ARCHITECTURE,
    SemanticObject,
    StoreReader,
    TerminatorKind,
    ValueRef,
    _decode_constant,
    borrowed_view_returns,
    _decode_function_interface,
    _is_erased_proof_function,
    _is_proof_type,
    decode_bits_width,
    decode_native_target,
    XaxError,
    fail,
    store_resolver,
    verify_store,
)

ZERO, RA, SP, T0, T1, T2, A0, T3 = 0, 1, 2, 5, 6, 7, 10, 28
UNIMP = 0xC0001073  # csrrw x0, cycle, x0: the canonical illegal instruction
ARGUMENT_REGISTERS = 8


@dataclass(frozen=True)
class Riscv64Image:
    code: bytes
    entry_offset: int
    function_offsets: tuple[tuple[bytes, int], ...]
    parameter_widths: tuple[int, ...]
    return_widths: tuple[int, ...]
    target_cid: bytes
    semantic_ranges: tuple[ArtifactSemanticRange, ...]

    @property
    def artifact_bytes(self) -> bytes:
        return self.code


# ------------------------------------------------------------------ encoding


def _r(funct7: int, rs2: int, rs1: int, funct3: int, rd: int, opcode: int = 0x33) -> int:
    return (funct7 << 25) | (rs2 << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | opcode


def _i(imm: int, rs1: int, funct3: int, rd: int, opcode: int = 0x13) -> int:
    return ((imm & 0xFFF) << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | opcode


def _s(imm: int, rs2: int, rs1: int, funct3: int = 3, opcode: int = 0x23) -> int:
    imm &= 0xFFF
    return ((imm >> 5) << 25) | (rs2 << 20) | (rs1 << 15) | (funct3 << 12) | ((imm & 0x1F) << 7) | opcode


def _b(offset: int, rs2: int, rs1: int, funct3: int) -> int:
    imm = offset & 0x1FFF
    return (
        ((imm >> 12) & 1) << 31 | ((imm >> 5) & 0x3F) << 25 | (rs2 << 20) | (rs1 << 15) | (funct3 << 12)
        | ((imm >> 1) & 0xF) << 8 | ((imm >> 11) & 1) << 7 | 0x63
    )


def _j(offset: int, rd: int) -> int:
    imm = offset & 0x1FFFFF
    return ((imm >> 20) & 1) << 31 | ((imm >> 1) & 0x3FF) << 21 | ((imm >> 11) & 1) << 20 | ((imm >> 12) & 0xFF) << 12 | (rd << 7) | 0x6F


def _signed64(value: int) -> int:
    value &= (1 << 64) - 1
    return value - (1 << 64) if value >> 63 else value


def _li_words(rd: int, value: int) -> list[int]:
    """Bootstrap reference for ``li rd, value`` (lui/addiw, then slli/addi levels)."""
    value = _signed64(value)
    if -2048 <= value < 2048:
        return [_i(value, ZERO, 0, rd)]
    if -(1 << 31) <= value < 1 << 31:
        high = ((value + 0x800) >> 12) & 0xFFFFF
        low = value - _signed64(((high << 12) ^ 0x80000000) - 0x80000000)
        return [(high << 12) | (rd << 7) | 0x37] + ([_i(low, rd, 0, rd, 0x1B)] if low else [])  # lui; addiw
    low = ((value & 0xFFF) ^ 0x800) - 0x800
    high = (value - low) >> 12
    shift = 12
    while not high & 1:
        high >>= 1
        shift += 1
    return _li_words(rd, high) + [_i(shift, rd, 1, rd)] + ([_i(low, rd, 0, rd)] if low else [])  # slli; addi


class PythonEncoder:
    """The bootstrap Python encoders (reference and fallback)."""

    identity = "python-bootstrap"
    r, i, s, b, j = staticmethod(_r), staticmethod(_i), staticmethod(_s), staticmethod(_b), staticmethod(_j)
    li = staticmethod(_li_words)


class XaxEncoder:
    """The encoder authored as XAX semantics and run natively (ADR-116, ``xax_selfhost_riscv64``)."""

    identity = "xax-native"

    def __init__(self, native) -> None:
        self.native = native

    def r(self, funct7, rs2, rs1, funct3, rd, opcode=0x33):
        return self.native(0, funct7, rs2, rs1, funct3, rd, opcode)

    def i(self, imm, rs1, funct3, rd, opcode=0x13):
        return self.native(1, imm, rs1, funct3, rd, opcode)

    def s(self, imm, rs2, rs1, funct3=3, opcode=0x23):
        return self.native(2, imm, rs2, rs1, funct3, opcode)

    def b(self, offset, rs2, rs1, funct3):
        return self.native(3, offset, rs2, rs1, funct3)

    def j(self, offset, rd):
        return self.native(4, offset, rd)

    def li(self, rd, value):
        words = []
        while True:
            word = self.native(6, rd, value, len(words))
            if not word:
                return words
            words.append(word)


_ACTIVE: list = []


def _encoder():
    return _ACTIVE[-1] if _ACTIVE else PythonEncoder


def select_encoder(choice: str = "auto"):
    """``"python"``, ``"xax"`` (fails where the leaf cannot run), or ``"auto"`` (XAX when it can run)."""
    if choice == "python":
        return PythonEncoder
    from xax_selfhost_riscv64 import native_encoder

    native = native_encoder()
    if native is None:
        if choice == "xax":
            fail("XAX.RISCV64.HOST", "host", "RISCV64-XAX-ENCODER", "Linux x86-64 host for the native XAX encoder", "unavailable")
        return PythonEncoder
    return XaxEncoder(native)


class _Emitter:
    def __init__(self, where: str, far: bool = False) -> None:
        self.where = where
        self.words: list[int] = []
        self.labels: dict[object, int] = {}
        self.jumps: list[tuple[int, object, int]] = []  # (word index, label, rd)
        # Views profile (ADR-145): every jump is ``auipc; jalr`` (+-2 GiB), as images exceed jal's +-1 MiB.
        self.far = far

    @property
    def skip(self) -> int:
        """The branch offset that skips one jump."""
        return 12 if self.far else 8

    @property
    def offset(self) -> int:
        return 4 * len(self.words)

    def emit(self, word: int) -> None:
        self.words.append(word)

    def mark(self, label: object) -> None:
        self.labels[label] = self.offset

    def jal(self, label: object, rd: int = ZERO) -> None:
        self.jumps.append((len(self.words), label, rd))
        self.words.append(0)
        if self.far:
            self.words.append(0)

    def li(self, rd: int, value: int) -> None:
        for word in _encoder().li(rd, value):
            self.emit(word)

    def frame_access(self, store: bool, register: int, offset: int) -> None:
        if offset < 2048:
            self.emit(_encoder().s(offset, register, SP) if store else _encoder().i(offset, SP, 3, register, 0x03))
        else:
            self.li(T2, offset)
            self.emit(_encoder().r(0, SP, T2, 0, T2))  # add t2, t2, sp
            self.emit(_encoder().s(0, register, T2) if store else _encoder().i(0, T2, 3, register, 0x03))

    def finish(self, function_labels: dict[bytes, int] | None = None) -> list[int]:
        for index, label, rd in self.jumps:
            target = function_labels[label[1]] if isinstance(label, tuple) and label[0] == "function" else self.labels[label]
            delta = target - 4 * index
            if self.far:
                if not -(1 << 31) <= delta < (1 << 31) - 2048:
                    fail("XAX.RISCV64.LIMIT", self.where, "RISCV64-FAR-RANGE", "+-2 GiB", delta)
                base = rd if rd != ZERO else T3
                high = ((delta + 0x800) >> 12) & 0xFFFFF
                low = delta - ((((high << 12) ^ 0x80000000) - 0x80000000))
                self.words[index] = (high << 12) | (base << 7) | 0x17  # auipc base, high
                self.words[index + 1] = _encoder().i(low, base, 0, rd, 0x67)  # jalr rd, low(base)
                continue
            if not -(1 << 20) <= delta < 1 << 20:
                fail("XAX.RISCV64.LIMIT", self.where, "RISCV64-JAL-RANGE", "+-1 MiB", delta)
            self.words[index] = _encoder().j(delta, rd)
        return self.words


# ------------------------------------------------------------------ lowering


# Callee-saved registers available to the allocator: s1, s2-s11.
ALLOCATABLE = (9, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27)
ISA = "RISCV64"


def _compile_function(function: SemanticObject, resolve, emitter: _Emitter) -> list[tuple[int, int, int, int]]:
    graph_object, parameter_types, return_types = _decode_function_interface(function, resolve)
    graph, elided = rewrite_borrowed_views(parse_function_graph(function, resolve), resolve)
    elided_returns = set(borrowed_view_returns(parameter_types, return_types, resolve))
    extents = pointer_extents(graph, resolve)
    where = graph_object.cid.hex()
    result_fields_ = result_fields(function, resolve, ISA)
    aggregates = Aggregates(graph, resolve, where, result_fields_, ISA)
    graph = apply_aliases(graph, aggregates.alias, aggregates.made if result_fields_ is not None else None)
    elided = elided | aggregates.elided
    width_of: dict[ValueRef, int] = {}
    for block_index, block in enumerate(graph.blocks):
        for index, cid in enumerate(block.parameters):
            width = machine_width(resolve, cid, where, ISA)
            if width is not None:
                width_of[ValueRef.parameter(block_index, index)] = width
        for node_index, node in enumerate(block.nodes):
            for result_index, cid in enumerate(node.results):
                if ValueRef.node_result(block_index, node_index, result_index) in elided:
                    continue
                width = machine_width(resolve, cid, where, ISA)
                if width is not None:
                    width_of[ValueRef.node_result(block_index, node_index, result_index)] = width
    order = [graph.entry] + [index for index in range(len(graph.blocks)) if index != graph.entry]
    register_of = allocate_registers(graph, order, set(width_of), ALLOCATABLE)
    saved = sorted(set(register_of.values()))

    def machine_arguments(node) -> list[ValueRef]:
        return [operand for operand, cid in zip(node.operands, node.operand_types) if not _is_proof_type(resolve(cid))]

    calls = [(block_index, node_index, node) for block_index, block in enumerate(graph.blocks) for node_index, node in enumerate(block.nodes)
             if node.operation == Operation.CALL_DIRECT and not _is_erased_proof_function(node.entity, resolve)]
    hidden = {(b, n): int(ValueRef.node_result(b, n) in aggregates.returned) for b, n, _node in calls}
    # Frame: outgoing stack arguments, [out] ra, the saved s-registers, spill slots, edge temporaries, the hidden
    # result pointer, then one result area per aggregate call.
    out = 8 * max([len(machine_arguments(node)) + hidden[b, n] - ARGUMENT_REGISTERS for b, n, node in calls] + [0])
    cursor = out + 8 + 8 * len(saved)
    slot_of: dict[ValueRef, int] = {}
    for ref in sorted(width_of, key=lambda ref: (ref.block, ref.tag, ref.index, ref.result)):
        if ref not in register_of:
            slot_of[ref] = cursor
            cursor += 8
    temporaries = cursor
    cursor += 8 * max([len(block.parameters) for block in graph.blocks] + [0])
    result_pointer = cursor
    cursor += 8 * (result_fields_ is not None)
    area_of: dict[ValueRef, int] = {}
    for ref in sorted(aggregates.returned, key=lambda ref: (ref.block, ref.index, ref.result)):
        area_of[ref] = cursor
        cursor += 8 * aggregates.returned[ref]
    frame = (cursor + 15) & -16
    machine_parameters = [ValueRef.parameter(graph.entry, index) for index in range(len(graph.blocks[graph.entry].parameters)) if ValueRef.parameter(graph.entry, index) in width_of]

    e = emitter

    def move(destination: int, source: int) -> None:
        if destination != source:
            e.emit(_encoder().i(0, source, 0, destination))  # mv

    def read(ref: ValueRef, scratch: int) -> int:
        """Register holding ``ref``: its allocated register, or ``scratch`` after a reload."""
        if ref in register_of:
            return register_of[ref]
        e.frame_access(False, scratch, slot_of[ref])
        return scratch

    def read_into(ref: ValueRef, register: int) -> None:
        move(register, read(ref, register))

    def target_register(ref: ValueRef) -> int:
        return register_of.get(ref, T0)

    def write(ref: ValueRef, register: int) -> None:
        if ref in register_of:
            move(register_of[ref], register)
        else:
            e.frame_access(True, register, slot_of[ref])

    def mask(register: int, width: int) -> None:
        if width < 64:
            if width <= 11:
                e.emit(_encoder().i((1 << width) - 1, register, 7, register))  # andi
            else:
                e.emit(_encoder().i(64 - width, register, 1, register))  # slli
                e.emit(_encoder().i(64 - width, register, 5, register))  # srli

    def sign_extend(register: int, width: int) -> None:
        if width < 64:
            e.emit(_encoder().i(64 - width, register, 1, register))  # slli
            e.emit(_encoder().i(0x400 | (64 - width), register, 5, register))  # srai

    # Prologue: allocate the frame, save ra and the s-registers in use, home the arguments.
    if frame < 2048:
        e.emit(_encoder().i(-frame, SP, 0, SP))
    else:
        e.li(T0, frame)
        e.emit(_encoder().r(0x20, T0, SP, 0, SP))  # sub sp, sp, t0
    e.frame_access(True, RA, out)
    for position, register in enumerate(saved):
        e.frame_access(True, register, out + 8 + 8 * position)
    if result_fields_ is not None:
        e.frame_access(True, A0, result_pointer)
    for position, ref in enumerate(machine_parameters, result_fields_ is not None):
        if position < ARGUMENT_REGISTERS:
            write(ref, A0 + position)
        else:
            e.frame_access(False, T0, frame + 8 * (position - ARGUMENT_REGISTERS))  # the caller's outgoing area
            write(ref, T0)

    def epilogue() -> None:
        for position, register in enumerate(saved):
            e.frame_access(False, register, out + 8 + 8 * position)
        e.frame_access(False, RA, out)
        if frame < 2048:
            e.emit(_encoder().i(frame, SP, 0, SP))
        else:
            e.li(T0, frame)
            e.emit(_encoder().r(0, T0, SP, 0, SP))
        e.emit(_encoder().i(0, RA, 0, ZERO, 0x67))  # ret

    def location(ref: ValueRef) -> tuple[str, int]:
        return ("r", register_of[ref]) if ref in register_of else ("m", slot_of[ref])

    def copy_edge(target: int, arguments: Sequence[ValueRef]) -> None:
        moves = [
            (ValueRef.parameter(target, index), argument) for index, argument in enumerate(arguments)
            if ValueRef.parameter(target, index) in width_of and location(ValueRef.parameter(target, index)) != location(argument)
        ]
        sources = {location(argument) for _destination, argument in moves}
        if any(location(destination) in sources for destination, _argument in moves):
            # A destination is also a source: copy through the temporaries.
            for position, (_destination, argument) in enumerate(moves):
                e.frame_access(True, read(argument, T0), temporaries + 8 * position)
            for position, (destination, _argument) in enumerate(moves):
                register = target_register(destination)
                e.frame_access(False, register, temporaries + 8 * position)
                write(destination, register)
        else:
            for destination, argument in moves:
                write(destination, read(argument, T0))
        e.jal(("block", function.cid, target))

    ranges: list[tuple[int, int, int, int]] = []
    trap_used = False
    simple = {
        Operation.ADD_WRAP: (0, 0), Operation.SUB_WRAP: (0x20, 0), Operation.MUL_WRAP: (1, 0),
        Operation.BIT_XOR: (0, 4), Operation.BIT_OR: (0, 6), Operation.BIT_AND: (0, 7),
    }
    for block_index in order:
        block = graph.blocks[block_index]
        e.mark(("block", function.cid, block_index))
        for node_index, node in enumerate(block.nodes):
            start = e.offset
            result = ValueRef.node_result(block_index, node_index)
            operation = node.operation
            if operation in simple:
                funct7, funct3 = simple[Operation(operation)]
                left, right = read(node.operands[0], T0), read(node.operands[1], T1)
                destination = target_register(result)
                e.emit(_encoder().r(funct7, right, left, funct3, destination))
                if operation in (Operation.ADD_WRAP, Operation.SUB_WRAP, Operation.MUL_WRAP):
                    mask(destination, width_of[result])
                write(result, destination)
            elif operation in (Operation.UDIV, Operation.UREM):
                trap_used = True
                left, right = read(node.operands[0], T0), read(node.operands[1], T1)
                e.emit(_encoder().b(e.skip, ZERO, right, 1))  # bne divisor, zero: skip the trap jump
                e.jal(("trap", function.cid))
                destination = target_register(result)
                e.emit(_encoder().r(1, right, left, 5 if operation == Operation.UDIV else 7, destination))  # divu / remu
                write(result, destination)
            elif operation == Operation.ROTATE_RIGHT:
                width, amount = width_of[result], node.attributes[0]
                source = read(node.operands[0], T0)
                destination = target_register(result)
                if amount:
                    e.emit(_encoder().i(amount, source, 5, T1))  # srli t1, x, k
                    e.emit(_encoder().i(width - amount, source, 1, destination))  # slli d, x, w-k
                    e.emit(_encoder().r(0, T1, destination, 6, destination))  # or
                    mask(destination, width)
                else:
                    move(destination, source)
                write(result, destination)
            elif operation in (Operation.INT_TRUNCATE, Operation.INT_ZERO_EXTEND):
                destination = target_register(result)
                read_into(node.operands[0], destination)
                if operation == Operation.INT_TRUNCATE:
                    mask(destination, width_of[result])
                write(result, destination)
            elif operation == Operation.CONSTANT:
                _type, value = _decode_constant(node.entity, resolve)
                destination = target_register(result)
                e.li(destination, int(value))
                write(result, destination)
            elif operation == Operation.INT_COMPARE:
                kind = IntCompare(node.attributes[0])
                width = decode_bits_width(resolve(node.operand_types[0]))
                signed = kind in (IntCompare.SLT, IntCompare.SLE, IntCompare.SGT, IntCompare.SGE)
                if signed and width < 64:
                    read_into(node.operands[0], T0); read_into(node.operands[1], T1)
                    sign_extend(T0, width); sign_extend(T1, width)
                    left, right = T0, T1
                else:
                    left, right = read(node.operands[0], T0), read(node.operands[1], T1)
                destination = target_register(result)
                less = 2 if signed else 3  # slt / sltu
                if kind == IntCompare.EQ:
                    e.emit(_encoder().r(0, right, left, 4, destination)); e.emit(_encoder().i(1, destination, 3, destination))  # xor; seqz
                elif kind == IntCompare.NE:
                    e.emit(_encoder().r(0, right, left, 4, destination)); e.emit(_encoder().r(0, destination, ZERO, 3, destination))  # xor; snez
                elif kind in (IntCompare.ULT, IntCompare.SLT):
                    e.emit(_encoder().r(0, right, left, less, destination))
                elif kind in (IntCompare.UGT, IntCompare.SGT):
                    e.emit(_encoder().r(0, left, right, less, destination))
                elif kind in (IntCompare.ULE, IntCompare.SLE):
                    e.emit(_encoder().r(0, left, right, less, destination)); e.emit(_encoder().i(1, destination, 4, destination))  # !(b < a)
                else:
                    e.emit(_encoder().r(0, right, left, less, destination)); e.emit(_encoder().i(1, destination, 4, destination))  # !(a < b)
                write(result, destination)
            elif operation == Operation.CALL_DIRECT:
                if not _is_erased_proof_function(node.entity, resolve):
                    first = hidden[block_index, node_index]
                    arguments = list(enumerate(machine_arguments(node), first))
                    for position, argument in arguments:
                        if position >= ARGUMENT_REGISTERS:
                            e.frame_access(True, read(argument, T0), 8 * (position - ARGUMENT_REGISTERS))
                    for position, argument in arguments:
                        if position < ARGUMENT_REGISTERS:
                            read_into(argument, A0 + position)
                    if first:
                        area = area_of[result]
                        if area < 2048:
                            e.emit(_encoder().i(area, SP, 0, A0))  # addi a0, sp, area
                        else:
                            e.li(A0, area)
                            e.emit(_encoder().r(0, SP, A0, 0, A0))  # add a0, a0, sp
                    e.jal(("function", node.entity.cid), RA)
                    machine_results = [ValueRef.node_result(block_index, node_index, index) for index in range(len(node.results)) if ValueRef.node_result(block_index, node_index, index) in width_of]  # elided views excluded
                    if len(machine_results) > 1:
                        fail("XAX.RISCV64.ABI", where, "RISCV64-SINGLE-RESULT", 1, len(machine_results))
                    if machine_results:
                        write(machine_results[0], A0)
            elif operation in (Operation.CHECKED_LOAD_BITS_LE, Operation.CHECKED_STORE_BITS_LE):
                # Views profile (ADR-145): trap unless offset + size <= the pointer's view extent, then access.
                trap_used = True
                size = node.attributes[0]
                funct3 = {1: 0, 2: 1, 4: 2, 8: 3}.get(size)
                extent = extents.get(node.operands[0])
                if funct3 is None or extent is None:
                    fail("XAX.RISCV64.UNSUPPORTED_OPERATION", where, "RISCV64-CHECKED-ACCESS", "1/2/4/8-byte access through a view pointer", [size, extent])
                pointer = read(node.operands[0], T0)
                offset = read(node.operands[1], T1)
                e.li(T3, (extent - size) & ((1 << 64) - 1) if extent >= size else 0)
                if extent >= size:
                    e.emit(_encoder().b(e.skip, offset, T3, 7))  # bgeu t3, offset: in bounds, skip the trap jump
                e.jal(("trap", function.cid))
                if operation == Operation.CHECKED_STORE_BITS_LE:
                    value = read(node.operands[2], T3)
                    e.emit(_encoder().r(0, offset, pointer, 0, T2))  # add t2, pointer, offset
                    e.emit(_encoder().s(0, value, T2, funct3))
                else:
                    e.emit(_encoder().r(0, offset, pointer, 0, T2))
                    destination = target_register(result)
                    e.emit(_encoder().i(0, T2, {1: 4, 2: 5, 4: 6, 8: 3}[size], destination, 0x03))  # lbu/lhu/lwu/ld
                    write(result, destination)
            elif operation == Operation.AGGREGATE_GET:
                if result in width_of:  # a field of a call's aggregate (a made one's field is that operand)
                    destination = target_register(result)
                    e.frame_access(False, destination, area_of[node.operands[0]] + 8 * node.attributes[0])
                    write(result, destination)
            elif operation in RESOURCE_EFFECT_OPERATIONS or operation == Operation.AGGREGATE_MAKE:
                pass
            else:
                fail("XAX.RISCV64.UNSUPPORTED_OPERATION", where, "RISCV64-OP-LOWERED", "riscv64 integer subset", operation)
            if e.offset > start:
                ranges.append((block_index, node_index, start, e.offset))

        terminator = block.terminator
        if terminator.kind == TerminatorKind.RETURN and result_fields_ is not None:
            e.frame_access(False, T1, result_pointer)
            for position, value in enumerate(value for value in terminator.values if value in width_of):
                e.emit(_encoder().s(8 * position, read(value, T0), T1))  # sd field, 8k(result area)
            epilogue()
        elif terminator.kind == TerminatorKind.RETURN:
            machine = [value for position, (value, cid) in enumerate(zip(terminator.values, return_types))
                       if not _is_proof_type(resolve(cid)) and position not in elided_returns]
            if len(machine) > 1:
                fail("XAX.RISCV64.ABI", where, "RISCV64-SINGLE-RESULT", 1, len(machine))
            if machine:
                read_into(machine[0], A0)
            epilogue()
        elif terminator.kind == TerminatorKind.BRANCH:
            copy_edge(*terminator.edges[0])
        elif terminator.kind == TerminatorKind.CONDITIONAL_BRANCH:
            condition = read(terminator.values[0], T0)
            false_label = ("false", function.cid, block_index)
            e.emit(_encoder().b(e.skip, ZERO, condition, 1))  # bne cond, zero: the true edge follows the jump
            e.jal(false_label)
            copy_edge(*terminator.edges[0])
            e.mark(false_label)
            copy_edge(*terminator.edges[1])
        else:
            trap_used = True
            e.jal(("trap", function.cid))
    if trap_used:
        e.mark(("trap", function.cid))
        e.emit(UNIMP)
    return ranges


def compile_riscv64_bound_target(
    reader: StoreReader, function_cid: bytes, target_object: SemanticObject, *, encoder: str = "auto", backend: str = "auto",
) -> Riscv64Image:
    """``backend``: ``"auto"`` (the XAX backend program where it runs, ADR-140), ``"xax"`` (fails where it
    cannot run or declines), or ``"python"`` (the bootstrap code generator)."""
    _ACTIVE.append(select_encoder(encoder))
    try:
        return _compile_riscv64(reader, function_cid, target_object, backend)
    finally:
        _ACTIVE.pop()


_NONE = 0xFFFFFFFF


def _cid_words(cid: bytes) -> list[int]:
    return [int.from_bytes(cid[offset:offset + 8], "big") for offset in range(0, 32, 8)]


def _object_table(reader: StoreReader, entry: SemanticObject, target_object: SemanticObject) -> list[int] | None:
    """S7b.2 (ADR-181): the input of the XAX backend programs (see ``xax_selfhost_views_backend._frontend``).

    The store's objects in store order, then the bound target: each one's kind, its references and its own identity
    as CID words, and its payload (for a graph fragment the S3c XAX graph-decoder stream, else its body bytes).
    Nothing is selected, resolved, or interpreted here: the program picks the target, finds the entry, and resolves
    every reference.  None when a graph body cannot be streamed (the bootstrap generator then runs)."""
    from xax_compiler import _native_graph_decoder

    decoder = _native_graph_decoder()
    if decoder is None:
        return None
    objects = list(reader.objects())
    words = [len(objects), *_cid_words(entry.cid)]
    for obj in (*objects, target_object):
        words += [int(obj.kind), len(obj.references)]
        for cid in obj.references:
            words += _cid_words(cid)
        words += _cid_words(obj.cid)
        if obj.kind == Kind.GRAPH_FRAGMENT:
            if len(obj.body) > decoder.capacity:
                return None
            status, stream = decoder.decode(obj.body, len(obj.references))
            if status != 0:
                return None
            payload = list(stream)
        else:
            payload = list(obj.body)
        words += [len(payload), *payload]
    return words


def image_record(result, unit: int) -> tuple[Sequence[int], dict[bytes, int], list[ArtifactSemanticRange]]:
    """``(code units, function offsets in bytes by CID, semantic ranges)`` rendered from a views backend program's
    collected output (``collect_program_output``): the program decided every field (S7b.2); ``unit`` is the bytes per
    code unit."""
    code_units, cids, spans, ranges, _parameters, _returns = result
    offsets = {cid: unit * start for cid, (start, _end) in zip(cids, spans)}
    function_ranges = [ArtifactSemanticRange(cid, None, None, unit * start, unit * end) for cid, (start, end) in zip(cids, spans)]
    node_ranges = [ArtifactSemanticRange(cids[f], block, node, start, end) for f, block, node, start, end in ranges]
    return code_units, offsets, [*function_ranges, *node_ranges]


def _compile_riscv64(reader: StoreReader, function_cid: bytes, target_object: SemanticObject, backend: str = "python") -> Riscv64Image:
    verify_store(reader)
    resolve = store_resolver(reader)
    entry = resolve(function_cid)
    if entry.kind != Kind.FUNCTION:
        fail("XAX.RISCV64.FUNCTION", function_cid.hex(), "RISCV64-ENTRY-FUNCTION", Kind.FUNCTION.name, entry.kind.name)
    target = decode_native_target(target_object)
    if target.architecture != RISCV64_ARCHITECTURE:
        fail("XAX.RISCV64.TARGET", target_object.cid.hex(), "RISCV64-TARGET-PROFILE", RISCV64_ARCHITECTURE, target.architecture)
    if backend != "python":
        # S5b: the XAX program computes the closure, order, and stream from the store objects itself.
        image = _compile_with_xax(reader, entry, function_cid, target_object, backend == "xax")
        if image is not None:
            return image
    functions = function_closure(entry, resolve, target.supported_operations, target.supported_terminators, ISA)
    # The entry is laid out first so the image starts at its entry point.
    functions = (entry, *(function for function in functions if function.cid != entry.cid))
    emitter = _Emitter(function_cid.hex(), far=int(Operation.CHECKED_LOAD_BITS_LE) in target.supported_operations)
    offsets: dict[bytes, int] = {}
    node_ranges: list[ArtifactSemanticRange] = []
    for function in functions:
        offsets[function.cid] = emitter.offset
        for block, node, start, end in _compile_function(function, resolve, emitter):
            node_ranges.append(ArtifactSemanticRange(function.cid, block, node, start, end))
    words = emitter.finish(offsets)
    code = b"".join(word.to_bytes(4, "little") for word in words)
    function_ranges = []
    for index, function in enumerate(functions):
        end = offsets[functions[index + 1].cid] if index + 1 < len(functions) else len(code)
        function_ranges.append(ArtifactSemanticRange(function.cid, None, None, offsets[function.cid], end))
    _graph, parameters, returns = _decode_function_interface(entry, resolve)
    widths = lambda cids: tuple(w for w in (machine_width(resolve, cid, function_cid.hex(), ISA) for cid in cids) if w is not None)
    return Riscv64Image(
        code, 0, tuple(sorted(offsets.items())), widths(parameters), widths(returns), target_object.cid,
        (*function_ranges, *node_ranges),
    )


def _compile_with_xax(reader: StoreReader, entry, function_cid: bytes, target_object: SemanticObject, required: bool) -> Riscv64Image | None:
    """The image from the XAX backend program (ADR-140, ADR-141), or None (the bootstrap generator then runs and
    raises any diagnostic)."""
    from xax_selfhost_riscv64_backend import native_backend

    native = native_backend()
    words = None if native is None else _object_table(reader, entry, target_object)
    result, diagnostic = (None, None) if words is None else native.compile(words)
    if diagnostic is not None:  # S7b.3: the program decided the rejection and wrote its diagnostic
        raise XaxError(diagnostic)
    if result is None:
        if required:
            fail("XAX.RISCV64.BACKEND", function_cid.hex(), "RISCV64-XAX-BACKEND", "accepted by the XAX backend program", "unavailable or declined")
        return None
    return image_from_backend_output(reader, target_object, result)


def image_from_backend_output(reader: StoreReader, target_object: SemanticObject, result) -> Riscv64Image:
    """The ``Riscv64Image`` of the XAX backend program's collected output (``collect_output``), wherever it ran."""
    code_words, offsets, ranges = image_record(result, 4)
    code = b"".join(word.to_bytes(4, "little") for word in code_words)
    return Riscv64Image(code, 0, tuple(sorted(offsets.items())), result[4], result[5], target_object.cid, tuple(ranges))


def compile_riscv64(reader: StoreReader, function_cid: bytes, target_cid: bytes, *, encoder: str = "auto", backend: str = "auto") -> Riscv64Image:
    return compile_riscv64_bound_target(reader, function_cid, store_resolver(reader)(target_cid), encoder=encoder, backend=backend)


# ------------------------------------------------------------------ harness

_CODE_BASE = 0x10000
_RETURN_SENTINEL = 0x1000
_STACK_TOP = 0x80000000
_STACK_SIZE = 1 << 20


def run_riscv64(image: Riscv64Image, arguments: Sequence[int], *, instruction_limit: int = 50_000_000) -> int | str:
    """Test harness: execute the raw image in the Unicorn RV64 emulator.

    Returns the masked result, or ``"trap"`` when execution reaches ``unimp``.
    The emulator is a host tool, not part of the artifact.
    """
    try:
        import unicorn
        from unicorn import riscv_const as rv
    except ImportError:
        fail("XAX.RISCV64.HOST", "host", "RISCV64-HOST-EMULATOR", "unicorn", "missing")
    if len(arguments) != len(image.parameter_widths):
        fail("XAX.RISCV64.ARGUMENT_COUNT", "entry", "RISCV64-ARGUMENT-COUNT", len(image.parameter_widths), len(arguments))
    emulator = unicorn.Uc(unicorn.UC_ARCH_RISCV, unicorn.UC_MODE_RISCV64)
    size = (len(image.code) + 0xFFF) & -0x1000
    emulator.mem_map(_CODE_BASE, size)
    emulator.mem_write(_CODE_BASE, image.code)
    emulator.mem_map(_RETURN_SENTINEL, 0x1000)
    emulator.mem_map(_STACK_TOP - _STACK_SIZE, _STACK_SIZE)
    emulator.reg_write(rv.UC_RISCV_REG_SP, _STACK_TOP)
    emulator.reg_write(rv.UC_RISCV_REG_RA, _RETURN_SENTINEL)
    for register, (value, width) in enumerate(zip(arguments, image.parameter_widths)):
        if not 0 <= value < 1 << width:
            fail("XAX.RISCV64.ARGUMENT_RANGE", "entry", "RISCV64-ARGUMENT-RANGE", f"bits<{width}>", value)
        emulator.reg_write(rv.UC_RISCV_REG_A0 + register, value)
    try:
        emulator.emu_start(_CODE_BASE + image.entry_offset, _RETURN_SENTINEL, count=instruction_limit)
    except unicorn.UcError as error:
        if error.errno == unicorn.UC_ERR_EXCEPTION:
            # Unicorn reports the exception with pc past the faulting word.
            pc = emulator.reg_read(rv.UC_RISCV_REG_PC)
            for address in (pc - 4, pc):
                if _CODE_BASE <= address < _CODE_BASE + len(image.code) and int.from_bytes(emulator.mem_read(address, 4), "little") == UNIMP:
                    return "trap"
        raise
    if emulator.reg_read(rv.UC_RISCV_REG_PC) != _RETURN_SENTINEL:
        fail("XAX.RISCV64.HOST", "entry", "RISCV64-INSTRUCTION-LIMIT", instruction_limit, "exceeded")
    if not image.return_widths:
        return 0
    return emulator.reg_read(rv.UC_RISCV_REG_A0) & ((1 << image.return_widths[0]) - 1)


_VIEWS_IN_BASE = 0x20000000
_VIEWS_OUT_BASE = 0x40000000


def run_riscv64_views(image: Riscv64Image, input_words: Sequence[int], input_capacity: int, output_capacity: int,
                      read_back: Callable[[Callable[[int, int], list[int]]], object], *, instruction_limit: int = 20_000_000_000,
                      extra_arguments: Sequence[int] = ()):
    """Test harness (views profile, ADR-145): run an image whose entry takes ``(in view, out view)`` pointers.

    ``input_words`` fill the input view (``input_capacity`` bytes); the output view (``output_capacity`` bytes)
    starts zeroed.  After the call, ``read_back(read_words)`` collects the result, where ``read_words(start,
    count)`` reads 64-bit words of the output view; ``extra_arguments`` go in a2, a3, ...  Returns ``(a0, read_back
    result)``; a trap returns ``"trap"``."""
    try:
        import unicorn
        from unicorn import riscv_const as rv
    except ImportError:
        fail("XAX.RISCV64.HOST", "host", "RISCV64-HOST-EMULATOR", "unicorn", "missing")
    emulator = unicorn.Uc(unicorn.UC_ARCH_RISCV, unicorn.UC_MODE_RISCV64)
    size = (len(image.code) + 0xFFF) & -0x1000
    emulator.mem_map(_CODE_BASE, size)
    emulator.mem_write(_CODE_BASE, image.code)
    emulator.mem_map(_RETURN_SENTINEL, 0x1000)
    emulator.mem_map(_STACK_TOP - _STACK_SIZE, _STACK_SIZE)
    emulator.mem_map(_VIEWS_IN_BASE, (input_capacity + 0xFFF) & -0x1000)
    emulator.mem_map(_VIEWS_OUT_BASE, (output_capacity + 0xFFF) & -0x1000)
    data = b"".join(int(word).to_bytes(8, "little") for word in input_words)
    emulator.mem_write(_VIEWS_IN_BASE, data)
    emulator.reg_write(rv.UC_RISCV_REG_SP, _STACK_TOP)
    emulator.reg_write(rv.UC_RISCV_REG_RA, _RETURN_SENTINEL)
    emulator.reg_write(rv.UC_RISCV_REG_A0, _VIEWS_IN_BASE)
    emulator.reg_write(rv.UC_RISCV_REG_A1, _VIEWS_OUT_BASE)
    for register, value in enumerate(extra_arguments, rv.UC_RISCV_REG_A2):
        emulator.reg_write(register, value)
    try:
        emulator.emu_start(_CODE_BASE + image.entry_offset, _RETURN_SENTINEL, count=instruction_limit)
    except unicorn.UcError as error:
        if error.errno == unicorn.UC_ERR_EXCEPTION:
            pc = emulator.reg_read(rv.UC_RISCV_REG_PC)
            for address in (pc - 4, pc):
                if _CODE_BASE <= address < _CODE_BASE + len(image.code) and int.from_bytes(emulator.mem_read(address, 4), "little") == UNIMP:
                    return "trap", None
        raise
    if emulator.reg_read(rv.UC_RISCV_REG_PC) != _RETURN_SENTINEL:
        fail("XAX.RISCV64.HOST", "entry", "RISCV64-INSTRUCTION-LIMIT", instruction_limit, "exceeded")

    def read_words(start: int, count: int) -> list[int]:
        raw = bytes(emulator.mem_read(_VIEWS_OUT_BASE + 8 * start, 8 * count)) if count else b""
        return [int.from_bytes(raw[k:k + 8], "little") for k in range(0, len(raw), 8)]

    return emulator.reg_read(rv.UC_RISCV_REG_A0), read_back(read_words)
