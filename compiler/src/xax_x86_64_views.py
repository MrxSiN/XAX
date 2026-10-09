"""x86-64 views-profile code generator (ADR-152): verified XAX -> raw position-independent x86-64 code.

``x86_64-linux-views-v1`` compiles the same operations as the RISC-V views
profile (``xax_compiler.views_operations``): ``bits<N <= 64>`` arithmetic,
compares, width changes, rotates, unsigned division, direct calls, checked
accesses through lent views, and aggregates of scalar fields.  It is the
bootstrap reference for the XAX-authored x86-64 backend
(``xax_selfhost_x86_64_backend``), which must reproduce it byte for byte, and it
shares the instruction-set-neutral analysis with the RISC-V generator
(``xax_views_lowering``).

Lowering contract (the repository's x86-64 convention, Win64 registers):

* machine arguments in rcx, rdx, r8, r9, then 8-byte stack slots above the
  caller's 32-byte shadow area; one machine result in rax; an aggregate result
  is stored, field k as a zero-extended quadword at offset 8k, into a
  caller-owned area whose address is the hidden first argument and is returned
  in rax;
* rbx, rbp, rsi, rdi, r12-r15 are callee-saved and hold values (a linear scan
  over block-liveness interval hulls); r10/r11 are scratch, rax/rdx serve
  division and results; every other value lives in a frame slot;
* values are kept zero-extended to their width;
* a zero divisor or an out-of-view access jumps to the function's ``ud2``;
* every transfer is rel32, so the image runs at any address; there is no
  runtime, loader, relocation, or data section.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from xax_artifact import ArtifactSemanticRange
from xax_compiler import (
    IntCompare,
    Kind,
    Operation,
    RESOURCE_EFFECT_OPERATIONS,
    SemanticObject,
    StoreReader,
    TerminatorKind,
    ValueRef,
    _decode_constant,
    _decode_function_interface,
    _is_erased_proof_function,
    _is_proof_type,
    borrowed_view_returns,
    decode_bits_width,
    decode_native_target,
    fail,
    parse_function_graph,
    store_resolver,
    verify_store,
)
from xax_views_lowering import (  # noqa: F401  (LOWERED_OPERATIONS is part of this module's interface)
    LOWERED_OPERATIONS,
    Aggregates,
    allocate_registers,
    apply_aliases,
    function_closure,
    machine_width,
    pointer_extents,
    result_fields,
    rewrite_borrowed_views,
)

ISA = "X86_64_VIEWS"
IDENTITY = b"x86_64-linux-views-v1"
RAX, RCX, RDX, RSP = 0, 1, 2, 4
T0, T1 = 10, 11
ARGUMENT_REGISTERS = (RCX, RDX, 8, 9)
SHADOW = 32
# Callee-saved registers available to the allocator (Win64): rbx, rbp, rsi, rdi, r12-r15.
ALLOCATABLE = (3, 5, 6, 7, 12, 13, 14, 15)
UD2 = b"\x0f\x0b"
PAD = 0xCC  # int3 between functions
SETCC = {IntCompare.EQ: 0x94, IntCompare.NE: 0x95, IntCompare.ULT: 0x92, IntCompare.ULE: 0x96, IntCompare.UGT: 0x97,
         IntCompare.UGE: 0x93, IntCompare.SLT: 0x9C, IntCompare.SLE: 0x9E, IntCompare.SGT: 0x9F, IntCompare.SGE: 0x9D}
# ``op r/m64, r64`` opcodes; multiplication is ``imul r64, r/m64``.
ALU = {Operation.ADD_WRAP: 0x01, Operation.SUB_WRAP: 0x29, Operation.BIT_XOR: 0x31, Operation.BIT_OR: 0x09, Operation.BIT_AND: 0x21}
COMMUTATIVE = frozenset({Operation.ADD_WRAP, Operation.MUL_WRAP, Operation.BIT_XOR, Operation.BIT_OR, Operation.BIT_AND})
# Every operation ``_compile_function`` lowers; any other one in a closure rejects with ``OP-LOWERED``.
LOWERED_OPERATIONS = tuple(sorted({*map(int, ALU), int(Operation.MUL_WRAP), int(Operation.UDIV), int(Operation.UREM), int(Operation.ROTATE_RIGHT),
                                   int(Operation.INT_TRUNCATE), int(Operation.INT_ZERO_EXTEND), int(Operation.CONSTANT), int(Operation.INT_COMPARE),
                                   int(Operation.CALL_DIRECT), int(Operation.CHECKED_LOAD_BITS_LE), int(Operation.CHECKED_STORE_BITS_LE),
                                   int(Operation.AGGREGATE_GET), int(Operation.AGGREGATE_MAKE), *map(int, RESOURCE_EFFECT_OPERATIONS)}))


@dataclass(frozen=True)
class X86ViewsImage:
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


def _rex(w: int, reg: int, index: int, base: int, force: bool = False) -> bytes:
    value = 0x40 | (w << 3) | ((reg >> 3) << 2) | ((index >> 3) << 1) | (base >> 3)
    return bytes((value,)) if value != 0x40 or force else b""


def _modrm(mod: int, reg: int, rm: int) -> int:
    return (mod << 6) | ((reg & 7) << 3) | (rm & 7)


def reg_reg(opcode: bytes, reg: int, rm: int, w: int = 1) -> bytes:
    """``opcode`` with a register ModRM (``reg`` field, ``rm`` operand)."""
    return _rex(w, reg, 0, rm) + opcode + bytes((_modrm(3, reg, rm),))


def stack(opcode: bytes, reg: int, offset: int, w: int = 1) -> bytes:
    """``opcode`` on ``[rsp + offset]`` (disp8 below 128, else disp32)."""
    if offset < 128:
        return _rex(w, reg, 0, RSP) + opcode + bytes((_modrm(1, reg, RSP), 0x24, offset))
    return _rex(w, reg, 0, RSP) + opcode + bytes((_modrm(2, reg, RSP), 0x24)) + offset.to_bytes(4, "little")


def indexed(prefix: bytes, opcode: bytes, reg: int, base: int, index: int, w: int, force: bool = False) -> bytes:
    """``opcode`` on ``[base + index]``; rbp/r13 bases take a zero disp8."""
    rex = _rex(w, reg, index, base, force)
    if base & 7 == 5:
        return prefix + rex + opcode + bytes((_modrm(1, reg, 4), ((index & 7) << 3) | (base & 7), 0))
    return prefix + rex + opcode + bytes((_modrm(0, reg, 4), ((index & 7) << 3) | (base & 7)))


def shift(extension: int, reg: int, amount: int, w: int = 1) -> bytes:
    """``shl``/``shr``/``sar``/``ror`` (ModRM extension 4/5/7/1) by an immediate."""
    return _rex(w, 0, 0, reg) + bytes((0xC1, _modrm(3, extension, reg), amount))


def move(destination: int, source: int) -> bytes:
    return b"" if destination == source else reg_reg(b"\x89", source, destination)


def load_constant(reg: int, value: int) -> bytes:
    value &= (1 << 64) - 1
    if value == 0:
        return reg_reg(b"\x31", reg, reg, w=0)  # xor r32, r32
    if value < 1 << 32:
        return _rex(0, 0, 0, reg) + bytes((0xB8 | (reg & 7),)) + value.to_bytes(4, "little")
    if value >= (1 << 64) - (1 << 31):
        return _rex(1, 0, 0, reg) + bytes((0xC7, _modrm(3, 0, reg))) + (value & 0xFFFFFFFF).to_bytes(4, "little")
    return _rex(1, 0, 0, reg) + bytes((0xB8 | (reg & 7),)) + value.to_bytes(8, "little")


def mask(reg: int, width: int) -> bytes:
    """Zero the bits above ``width``."""
    if width >= 64:
        return b""
    if width == 32:
        return reg_reg(b"\x89", reg, reg, w=0)  # mov r32, r32
    if width < 32:
        value = (1 << width) - 1
        if value < 128:
            return _rex(0, 0, 0, reg) + bytes((0x83, _modrm(3, 4, reg), value))
        return _rex(0, 0, 0, reg) + bytes((0x81, _modrm(3, 4, reg))) + value.to_bytes(4, "little")
    return shift(4, reg, 64 - width) + shift(5, reg, 64 - width)


def sign_extend(reg: int, width: int) -> bytes:
    return b"" if width >= 64 else shift(4, reg, 64 - width) + shift(7, reg, 64 - width)


def frame_size(cursor: int) -> int:
    """The smallest frame holding ``cursor`` bytes that keeps rsp 16-aligned at calls (rsp is 8 mod 16 on entry)."""
    return ((cursor + 8 + 15) & -16) - 8


class _Emitter:
    def __init__(self) -> None:
        self.code = bytearray()
        self.labels: dict[object, int] = {}
        self.jumps: list[tuple[int, object]] = []  # (position of the rel32, label)

    @property
    def offset(self) -> int:
        return len(self.code)

    def emit(self, data: bytes) -> None:
        self.code.extend(data)

    def mark(self, label: object) -> None:
        self.labels[label] = self.offset

    def jump(self, opcode: bytes, label: object) -> None:
        """``jmp``/``jcc``/``call`` rel32 to ``label`` (patched by ``finish``)."""
        self.code.extend(opcode)
        self.jumps.append((self.offset, label))
        self.code.extend(bytes(4))

    def finish(self, function_labels: dict[bytes, int]) -> bytes:
        for position, label in self.jumps:
            target = function_labels[label[1]] if label[0] == "function" else self.labels[label]
            self.code[position:position + 4] = ((target - (position + 4)) & 0xFFFFFFFF).to_bytes(4, "little")
        return bytes(self.code)


JMP, JZ, JA, CALL = b"\xe9", b"\x0f\x84", b"\x0f\x87", b"\xe8"


# ------------------------------------------------------------------ lowering


def _compile_function(function: SemanticObject, resolve, e: _Emitter) -> list[tuple[int, int, int, int]]:
    graph_object, parameter_types, return_types = _decode_function_interface(function, resolve)
    graph, elided = rewrite_borrowed_views(parse_function_graph(function, resolve), resolve)
    elided_returns = set(borrowed_view_returns(parameter_types, return_types, resolve))
    extents = pointer_extents(graph, resolve)
    where = graph_object.cid.hex()
    returned_fields = result_fields(function, resolve, ISA)
    aggregates = Aggregates(graph, resolve, where, returned_fields, ISA)
    graph = apply_aliases(graph, aggregates.alias, aggregates.made if returned_fields is not None else None)
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
    # Frame: the shadow area and outgoing stack arguments (when it calls), the saved registers, spill slots, edge
    # temporaries, the hidden result pointer, then one result area per aggregate call.
    shadow = SHADOW if calls else 0
    out = 8 * max([len(machine_arguments(node)) + hidden[b, n] - len(ARGUMENT_REGISTERS) for b, n, node in calls] + [0])
    cursor = shadow + out + 8 * len(saved)
    slot_of: dict[ValueRef, int] = {}
    for ref in sorted(width_of, key=lambda ref: (ref.block, ref.tag, ref.index, ref.result)):
        if ref not in register_of:
            slot_of[ref] = cursor
            cursor += 8
    temporaries = cursor
    cursor += 8 * max([len(block.parameters) for block in graph.blocks] + [0])
    result_pointer = cursor
    cursor += 8 * (returned_fields is not None)
    area_of: dict[ValueRef, int] = {}
    for ref in sorted(aggregates.returned, key=lambda ref: (ref.block, ref.index, ref.result)):
        area_of[ref] = cursor
        cursor += 8 * aggregates.returned[ref]
    frame = frame_size(cursor)
    machine_parameters = [ValueRef.parameter(graph.entry, index) for index in range(len(graph.blocks[graph.entry].parameters)) if ValueRef.parameter(graph.entry, index) in width_of]

    def read(ref: ValueRef, scratch: int) -> int:
        if ref in register_of:
            return register_of[ref]
        e.emit(stack(b"\x8b", scratch, slot_of[ref]))
        return scratch

    def read_into(ref: ValueRef, register: int) -> None:
        e.emit(move(register, read(ref, register)))

    def target_register(ref: ValueRef) -> int:
        return register_of.get(ref, T0)

    def write(ref: ValueRef, register: int) -> None:
        if ref in register_of:
            e.emit(move(register_of[ref], register))
        else:
            e.emit(stack(b"\x89", register, slot_of[ref]))

    def adjust(extension: int) -> bytes:
        """``sub``/``add`` rsp, frame (ModRM extension 5/0)."""
        if frame < 128:
            return _rex(1, 0, 0, RSP) + bytes((0x83, _modrm(3, extension, RSP), frame))
        return _rex(1, 0, 0, RSP) + bytes((0x81, _modrm(3, extension, RSP))) + frame.to_bytes(4, "little")

    # Prologue: the frame, the saved registers in use, the hidden result pointer, the parameters.
    saved_at = shadow + out
    e.emit(adjust(5))
    for position, register in enumerate(saved):
        e.emit(stack(b"\x89", register, saved_at + 8 * position))
    if returned_fields is not None:
        e.emit(stack(b"\x89", RCX, result_pointer))
    for position, ref in enumerate(machine_parameters, returned_fields is not None):
        if position < len(ARGUMENT_REGISTERS):
            write(ref, ARGUMENT_REGISTERS[position])
        else:
            e.emit(stack(b"\x8b", T0, frame + 8 + SHADOW + 8 * (position - len(ARGUMENT_REGISTERS))))  # the caller's stack argument
            write(ref, T0)

    def epilogue() -> None:
        for position, register in enumerate(saved):
            e.emit(stack(b"\x8b", register, saved_at + 8 * position))
        e.emit(adjust(0))
        e.emit(b"\xc3")

    def location(ref: ValueRef) -> tuple[str, int]:
        return ("r", register_of[ref]) if ref in register_of else ("m", slot_of[ref])

    def copy_edge(target: int, arguments: Sequence[ValueRef]) -> None:
        moves = [
            (ValueRef.parameter(target, index), argument) for index, argument in enumerate(arguments)
            if ValueRef.parameter(target, index) in width_of and location(ValueRef.parameter(target, index)) != location(argument)
        ]
        sources = {location(argument) for _destination, argument in moves}
        if any(location(destination) in sources for destination, _argument in moves):
            for position, (_destination, argument) in enumerate(moves):
                e.emit(stack(b"\x89", read(argument, T0), temporaries + 8 * position))
            for position, (destination, _argument) in enumerate(moves):
                register = target_register(destination)
                e.emit(stack(b"\x8b", register, temporaries + 8 * position))
                write(destination, register)
        else:
            for destination, argument in moves:
                write(destination, read(argument, T0))
        e.jump(JMP, ("block", function.cid, target))

    ranges: list[tuple[int, int, int, int]] = []
    trap_used = False
    trap = ("trap", function.cid)
    for block_index in order:
        block = graph.blocks[block_index]
        e.mark(("block", function.cid, block_index))
        for node_index, node in enumerate(block.nodes):
            start = e.offset
            result = ValueRef.node_result(block_index, node_index)
            operation = node.operation
            if operation in ALU or operation == Operation.MUL_WRAP:
                left, right = read(node.operands[0], T0), read(node.operands[1], T1)
                destination = target_register(result)
                apply = (lambda d, s: reg_reg(b"\x0f\xaf", d, s)) if operation == Operation.MUL_WRAP else (lambda d, s, o=ALU[operation]: reg_reg(bytes((o,)), s, d))
                if destination == right and destination != left:
                    if operation in COMMUTATIVE:
                        e.emit(apply(destination, left))
                    else:
                        destination = T0
                        e.emit(move(T0, left) + apply(T0, right))
                else:
                    e.emit(move(destination, left) + apply(destination, right))
                if operation in (Operation.ADD_WRAP, Operation.SUB_WRAP, Operation.MUL_WRAP):
                    e.emit(mask(destination, width_of[result]))
                write(result, destination)
            elif operation in (Operation.UDIV, Operation.UREM):
                trap_used = True
                right = read(node.operands[1], T1)
                e.emit(reg_reg(b"\x85", right, right))  # test divisor, divisor
                e.jump(JZ, trap)
                read_into(node.operands[0], RAX)
                e.emit(reg_reg(b"\x31", RDX, RDX, w=0))  # xor edx, edx
                e.emit(reg_reg(b"\xf7", 6, right))  # div divisor
                write(result, RAX if operation == Operation.UDIV else RDX)
            elif operation == Operation.ROTATE_RIGHT:
                width, amount = width_of[result], node.attributes[0]
                source = read(node.operands[0], T0)
                destination = target_register(result)
                if amount and width in (32, 64):
                    e.emit(move(destination, source) + shift(1, destination, amount, w=int(width == 64)))
                elif amount:
                    e.emit(move(T1, source) + shift(5, T1, amount))
                    e.emit(move(destination, source) + shift(4, destination, width - amount))
                    e.emit(reg_reg(b"\x09", T1, destination) + mask(destination, width))
                else:
                    e.emit(move(destination, source))
                write(result, destination)
            elif operation in (Operation.INT_TRUNCATE, Operation.INT_ZERO_EXTEND):
                destination = target_register(result)
                read_into(node.operands[0], destination)
                if operation == Operation.INT_TRUNCATE:
                    e.emit(mask(destination, width_of[result]))
                write(result, destination)
            elif operation == Operation.CONSTANT:
                _type, value = _decode_constant(node.entity, resolve)
                destination = target_register(result)
                e.emit(load_constant(destination, int(value)))
                write(result, destination)
            elif operation == Operation.INT_COMPARE:
                kind = IntCompare(node.attributes[0])
                width = decode_bits_width(resolve(node.operand_types[0]))
                if kind in (IntCompare.SLT, IntCompare.SLE, IntCompare.SGT, IntCompare.SGE) and width < 64:
                    read_into(node.operands[0], T0)
                    read_into(node.operands[1], T1)
                    e.emit(sign_extend(T0, width) + sign_extend(T1, width))
                    left, right = T0, T1
                else:
                    left, right = read(node.operands[0], T0), read(node.operands[1], T1)
                destination = target_register(result)
                e.emit(reg_reg(b"\x39", right, left))  # cmp left, right
                e.emit(_rex(0, 0, 0, destination, destination >= 4) + bytes((0x0F, SETCC[kind], _modrm(3, 0, destination))))
                e.emit(_rex(0, destination, 0, destination, destination >= 4) + bytes((0x0F, 0xB6, _modrm(3, destination, destination))))  # movzx
                write(result, destination)
            elif operation == Operation.CALL_DIRECT:
                if not _is_erased_proof_function(node.entity, resolve):
                    first = hidden[block_index, node_index]
                    arguments = list(enumerate(machine_arguments(node), first))
                    for position, argument in arguments:
                        if position >= len(ARGUMENT_REGISTERS):
                            e.emit(stack(b"\x89", read(argument, T0), SHADOW + 8 * (position - len(ARGUMENT_REGISTERS))))
                    for position, argument in arguments:
                        if position < len(ARGUMENT_REGISTERS):
                            read_into(argument, ARGUMENT_REGISTERS[position])
                    if first:
                        e.emit(stack(b"\x8d", RCX, area_of[result]))  # lea rcx, [rsp + area]
                    e.jump(CALL, ("function", node.entity.cid))
                    machine_results = [ValueRef.node_result(block_index, node_index, index) for index in range(len(node.results))
                                       if ValueRef.node_result(block_index, node_index, index) in width_of]
                    if len(machine_results) > 1:
                        fail(f"XAX.{ISA}.ABI", where, f"{ISA}-SINGLE-RESULT", 1, len(machine_results))
                    if machine_results:
                        write(machine_results[0], RAX)
            elif operation in (Operation.CHECKED_LOAD_BITS_LE, Operation.CHECKED_STORE_BITS_LE):
                # Trap unless offset + size <= the pointer's view extent, then access [pointer + offset].
                trap_used = True
                size = node.attributes[0]
                extent = extents.get(node.operands[0])
                if size not in (1, 2, 4, 8) or extent is None:
                    fail(f"XAX.{ISA}.UNSUPPORTED_OPERATION", where, f"{ISA}-CHECKED-ACCESS", "1/2/4/8-byte access through a view pointer", [size, extent])
                pointer = read(node.operands[0], T0)
                offset = read(node.operands[1], T1)
                if extent < size:
                    e.jump(JMP, trap)
                else:
                    limit = extent - size
                    if limit < 1 << 31:
                        e.emit(_rex(1, 0, 0, offset) + bytes((0x81, _modrm(3, 7, offset))) + limit.to_bytes(4, "little"))  # cmp offset, limit
                    else:
                        e.emit(load_constant(RAX, limit) + reg_reg(b"\x39", RAX, offset))
                    e.jump(JA, trap)
                if operation == Operation.CHECKED_STORE_BITS_LE:
                    value = read(node.operands[2], RAX)
                    prefix, opcode, w = {1: (b"", b"\x88", 0), 2: (b"\x66", b"\x89", 0), 4: (b"", b"\x89", 0), 8: (b"", b"\x89", 1)}[size]
                    e.emit(indexed(prefix, opcode, value, pointer, offset, w, force=size == 1 and value >= 4))
                else:
                    destination = target_register(result)
                    opcode, w = {1: (b"\x0f\xb6", 0), 2: (b"\x0f\xb7", 0), 4: (b"\x8b", 0), 8: (b"\x8b", 1)}[size]
                    e.emit(indexed(b"", opcode, destination, pointer, offset, w))
                    write(result, destination)
            elif operation == Operation.AGGREGATE_GET:
                if result in width_of:  # a field of a call's aggregate (a made one's field is that operand)
                    destination = target_register(result)
                    e.emit(stack(b"\x8b", destination, area_of[node.operands[0]] + 8 * node.attributes[0]))
                    write(result, destination)
            elif operation in RESOURCE_EFFECT_OPERATIONS or operation == Operation.AGGREGATE_MAKE:
                pass
            else:
                fail(f"XAX.{ISA}.UNSUPPORTED_OPERATION", where, f"{ISA}-OP-LOWERED", "x86-64 views subset", operation)
            if e.offset > start:
                ranges.append((block_index, node_index, start, e.offset))

        terminator = block.terminator
        if terminator.kind == TerminatorKind.RETURN and returned_fields is not None:
            e.emit(stack(b"\x8b", RAX, result_pointer))
            for position, value in enumerate(value for value in terminator.values if value in width_of):
                register = read(value, T0)
                e.emit(_rex(1, register, 0, RAX) + bytes((0x89, _modrm(1, register, RAX), 8 * position)) if position < 16
                       else _rex(1, register, 0, RAX) + bytes((0x89, _modrm(2, register, RAX))) + (8 * position).to_bytes(4, "little"))
            epilogue()
        elif terminator.kind == TerminatorKind.RETURN:
            machine = [value for position, (value, cid) in enumerate(zip(terminator.values, return_types))
                       if not _is_proof_type(resolve(cid)) and position not in elided_returns]
            if len(machine) > 1:
                fail(f"XAX.{ISA}.ABI", where, f"{ISA}-SINGLE-RESULT", 1, len(machine))
            if machine:
                read_into(machine[0], RAX)
            epilogue()
        elif terminator.kind == TerminatorKind.BRANCH:
            copy_edge(*terminator.edges[0])
        elif terminator.kind == TerminatorKind.CONDITIONAL_BRANCH:
            condition = read(terminator.values[0], T0)
            false_label = ("false", function.cid, block_index)
            e.emit(reg_reg(b"\x85", condition, condition))  # test condition, condition
            e.jump(JZ, false_label)
            copy_edge(*terminator.edges[0])
            e.mark(false_label)
            copy_edge(*terminator.edges[1])
        else:
            trap_used = True
            e.jump(JMP, trap)
    if trap_used:
        e.mark(trap)
        e.emit(UD2)
    return ranges


def compile_x86_64_views(reader: StoreReader, function_cid: bytes, target_object: SemanticObject, *, backend: str = "python",
                         verified: bool = False) -> X86ViewsImage:
    """``backend``: ``"python"`` (this bootstrap generator), ``"xax"`` (the XAX program; fails where it cannot run or
    declines), or ``"auto"`` (the XAX program where it runs).  ``verified``: ``verify_store`` already accepted exactly
    ``reader``'s bytes in this process (``xax_native.component_store_verified``), so it is not run again (ADR-250)."""
    if not verified:
        verify_store(reader)
    resolve = store_resolver(reader)
    entry = resolve(function_cid)
    if entry.kind != Kind.FUNCTION:
        fail(f"XAX.{ISA}.FUNCTION", function_cid.hex(), f"{ISA}-ENTRY-FUNCTION", Kind.FUNCTION.name, entry.kind.name)
    target = decode_native_target(target_object)
    if target.identity != IDENTITY:
        fail(f"XAX.{ISA}.TARGET", target_object.cid.hex(), f"{ISA}-TARGET-PROFILE", IDENTITY.decode(), target.identity.decode(errors="replace"))
    if backend != "python":
        from xax_selfhost_x86_64_backend import compile_with_xax

        image = compile_with_xax(reader, entry, target_object, backend == "xax")
        if image is not None:
            return image
    functions = function_closure(entry, resolve, target.supported_operations, target.supported_terminators, ISA)
    functions = (entry, *(function for function in functions if function.cid != entry.cid))
    emitter = _Emitter()
    offsets: dict[bytes, int] = {}
    node_ranges: list[ArtifactSemanticRange] = []
    for function in functions:
        while emitter.offset % 16:
            emitter.emit(bytes((PAD,)))
        offsets[function.cid] = emitter.offset
        for block, node, start, end in _compile_function(function, resolve, emitter):
            node_ranges.append(ArtifactSemanticRange(function.cid, block, node, start, end))
    code = emitter.finish(offsets)
    _graph, parameters, returns = _decode_function_interface(entry, resolve)
    widths = lambda cids: tuple(w for w in (machine_width(resolve, cid, function_cid.hex(), ISA) for cid in cids) if w is not None)  # noqa: E731
    return X86ViewsImage(code, 0, tuple(sorted(offsets.items())), widths(parameters), widths(returns), target_object.cid,
                         (*_function_ranges(functions, offsets, len(code)), *node_ranges))


def _function_ranges(functions: Sequence[SemanticObject], offsets: dict[bytes, int], size: int) -> list[ArtifactSemanticRange]:
    ranges = []
    for index, function in enumerate(functions):
        end = offsets[functions[index + 1].cid] if index + 1 < len(functions) else size
        ranges.append(ArtifactSemanticRange(function.cid, None, None, offsets[function.cid], end))
    return ranges


# ------------------------------------------------------------------ native execution (Linux x86-64 hosts)


class NativeViewsImage:
    """An image mapped executable in this process and called through the Win64 thunk (``xax_x86_64``)."""

    def __init__(self, image: X86ViewsImage) -> None:
        import ctypes
        import mmap

        from xax_x86_64 import _SYSV_TO_WIN64_THUNK

        thunk = _SYSV_TO_WIN64_THUNK + bytes(-len(_SYSV_TO_WIN64_THUNK) % 16)
        blob = thunk + image.code
        from xax_native import executable_mapping

        self._mapping, base = executable_mapping(blob)
        self._call = ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint64, ctypes.c_void_p)(base)
        self._entry = base + len(thunk) + image.entry_offset
        self._slots = (ctypes.c_uint64 * 16)()
        self._xmm = ctypes.c_uint64()
        self.image = image

    def __call__(self, *arguments: int) -> int:
        """Call the entry with machine ``arguments`` (integers or buffer addresses); returns rax."""
        import ctypes

        if len(arguments) > len(self._slots):
            raise ValueError("too many arguments")
        for index, value in enumerate(arguments):
            self._slots[index] = value
        return self._call(self._entry, ctypes.addressof(self._slots), max(4, len(arguments)), ctypes.addressof(self._xmm))


def run_x86_64_views(image: X86ViewsImage, arguments: Sequence[int]) -> int | str:
    """Test harness: call the entry in a forked child; ``"trap"`` when it dies on ``ud2`` (SIGILL), else the result
    masked to the entry's return width (0 with none)."""
    import os
    import signal

    if len(arguments) != len(image.parameter_widths):
        fail(f"XAX.{ISA}.ARGUMENT_COUNT", "entry", f"{ISA}-ARGUMENT-COUNT", len(image.parameter_widths), len(arguments))
    reader, writer = os.pipe()
    child = os.fork()
    if child == 0:
        os.close(reader)
        try:
            os.write(writer, NativeViewsImage(image)(*arguments).to_bytes(8, "little"))
        finally:
            os._exit(0)
    os.close(writer)
    data = os.read(reader, 8)
    os.close(reader)
    _pid, status = os.waitpid(child, 0)
    if os.WIFSIGNALED(status) and os.WTERMSIG(status) == signal.SIGILL:
        return "trap"
    if len(data) != 8:
        fail(f"XAX.{ISA}.HOST", "entry", f"{ISA}-NATIVE-RUN", "a result or a ud2 trap", status)
    return int.from_bytes(data, "little") & ((1 << image.return_widths[0]) - 1) if image.return_widths else 0
