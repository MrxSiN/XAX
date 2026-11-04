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
# S10a (ADR-264): v1 plus Linux syscalls; the closure check against the target's operations keeps v1 programs free of them.
IDENTITIES = (IDENTITY, b"x86_64-linux-views-v2")
# S11 (ADR-267): v2 whose entry is the Linux process entry, packaged as a static ELF64 executable.
EXEC_IDENTITY = b"x86_64-linux-views-exec-v1"
IDENTITIES += (EXEC_IDENTITY,)
SYSCALL_ARGUMENT_REGISTERS = (7, 6, 2, 10, 8, 9)  # rdi, rsi, rdx, r10, r8, r9
RSI, RDI = 6, 7
SYSCALL_EXPECTED = "linux-x86_64-syscall-v1 declaration: a canonical template naming each machine operand once, at most six arguments, at most one machine result"
# S11: the ``linux-x86_64-startup-v1`` reads the views profile lowers (``syscall_template`` gives each a number past
# every syscall's), only in the process entry; ``arg_copy``'s destination is a view under 2 GiB.
STARTUP_ARGC, STARTUP_ARG_COPY = 1 << 32, (1 << 32) + 1
STARTUP_READS = {b"argc": (STARTUP_ARGC, 0), b"arg_copy": (STARTUP_ARG_COPY, 2)}
STARTUP_EXPECTED = "argc, or arg_copy into a view under 2 GiB, in the process entry function"
# An allocator contract's nullable result: the kernel's -4095..-1 becomes 0 (``xax_x86_64._linux_syscall``).
NULL_ON_ERROR = b"\x48\x3d\x01\xf0\xff\xff\x72\x02\x31\xc0"  # cmp rax, -4095; jb +2; xor eax, eax
RAX, RCX, RDX, RSP = 0, 1, 2, 4
T0, T1 = 10, 11
ARGUMENT_REGISTERS = (RCX, RDX, 8, 9)
SHADOW = 32
# Callee-saved registers available to the allocator (Win64): rbx, rbp, rsi, rdi, r12-r15.
ALLOCATABLE = (3, 5, 6, 7, 12, 13, 14, 15)
UD2 = b"\x0f\x0b"
# S11: ``arg_copy``'s byte loop after ``cmp rcx, extent`` (r11 = the string, rdx = the destination, rcx = the count):
# jae done; movzx eax, byte [r11 + rcx]; test eax, eax; je done; mov [rdx + rcx], al; add rcx, 1; jmp top; done:
# mov rax, rcx.
ARG_COPY_LOOP = bytes.fromhex("7312" "410fb6040b" "85c0" "7409" "88040a" "4883c101" "ebe5" "4889c8")
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
# S10b (ADR-265): v2 also lowers owned-memory operations; each is a copy of its pointer operand.
X86_LOWERED_OPERATIONS = tuple(sorted({*LOWERED_OPERATIONS, int(Operation.HEAP_VIEW), int(Operation.POINTER_CAST)}))


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


JMP, JZ, JA, JAE, CALL = b"\xe9", b"\x0f\x84", b"\x0f\x87", b"\x0f\x83", b"\xe8"


# ------------------------------------------------------------------ lowering


def _compile_function(function: SemanticObject, resolve, e: _Emitter, process: bool = False) -> list[tuple[int, int, int, int]]:
    """Lower ``function``; ``process``: it is the process entry (S11): no machine parameters, a 16-byte aligned frame
    over ``argc``, startup reads, and ``ud2`` for a return."""
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
    frame = ((cursor + 15) & -16) if process else frame_size(cursor)  # a process entry starts aligned, with no return address
    machine_parameters = [ValueRef.parameter(graph.entry, index) for index in range(len(graph.blocks[graph.entry].parameters)) if ValueRef.parameter(graph.entry, index) in width_of]
    if process and (machine_parameters or returned_fields is not None):
        fail(f"XAX.{ISA}.ABI", where, f"{ISA}-PROCESS-ENTRY", 0, len(machine_parameters) + (returned_fields is not None))

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
        if process:
            e.emit(UD2)  # the process ends only by an explicit exit_group
            return
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

    def _syscall(node, result: ValueRef, block_index: int, node_index: int) -> None:
        """S10a (ADR-264): ``syscall`` with the declaration's register template.  rsi and rdi may hold values (they are
        callee-saved here, argument registers to the kernel), so both are pushed first and read back from the stack."""
        template = syscall_template(node, resolve)
        if template is None:
            fail(f"XAX.{ISA}.FOREIGN_ABI", where, f"{ISA}-SYSCALL", SYSCALL_EXPECTED, node.entity.cid.hex())
        number, arguments, allocator = template
        machine = machine_arguments(node)
        if number >= STARTUP_ARGC:
            _startup(node, number, machine, block_index, node_index)
            return
        e.emit(b"\x56\x57")  # push rsi; push rdi
        for register, argument in zip(SYSCALL_ARGUMENT_REGISTERS, arguments):
            if isinstance(argument, int):
                e.emit(load_constant(register, argument))
                continue
            ref = machine[int(argument[1:])]
            source = register_of.get(ref)
            if source in (RSI, RDI):
                e.emit(stack(b"\x8b", register, 8 if source == RSI else 0))
            elif source is not None:
                e.emit(move(register, source))
            else:
                e.emit(stack(b"\x8b", register, slot_of[ref] + 16))
        e.emit(b"\xb8" + number.to_bytes(4, "little") + b"\x0f\x05")  # mov eax, nr; syscall
        if allocator:
            e.emit(NULL_ON_ERROR)
        e.emit(b"\x5f\x5e")  # pop rdi; pop rsi
        results = [ValueRef.node_result(block_index, node_index, index) for index in range(len(node.results))
                   if ValueRef.node_result(block_index, node_index, index) in width_of]
        if results:
            write(results[0], RAX)

    def _startup(node, number: int, machine: list[ValueRef], block_index: int, node_index: int) -> None:
        """S11: ``argc`` is the word at the entry RSP (``rsp + frame``); ``arg_copy(index, destination)`` traps unless
        ``index < argc``, then copies ``argv[index]`` up to its NUL or the destination's extent and returns the count."""
        nonlocal trap_used
        extent = extents.get(machine[1]) if number == STARTUP_ARG_COPY else 0
        if not process or extent is None or extent >= 1 << 31:
            fail(f"XAX.{ISA}.FOREIGN_ABI", where, f"{ISA}-STARTUP", STARTUP_EXPECTED, node.entity.cid.hex())
        if number == STARTUP_ARGC:
            e.emit(stack(b"\x8b", RAX, frame))
        else:
            trap_used = True
            read_into(machine[0], RAX)
            read_into(machine[1], RDX)
            e.emit(stack(b"\x8d", T1, frame))  # lea r11, [rsp + frame]: &argc
            e.emit(b"\x49\x3b\x03")  # cmp rax, [r11]
            e.jump(JAE, trap)
            e.emit(b"\x4d\x8b\x5c\xc3\x08\x31\xc9")  # mov r11, [r11 + rax*8 + 8]; xor ecx, ecx
            e.emit(b"\x48\x81\xf9" + extent.to_bytes(4, "little") + ARG_COPY_LOOP)  # cmp rcx, extent; the loop
        results = [ValueRef.node_result(block_index, node_index, index) for index in range(len(node.results))
                   if ValueRef.node_result(block_index, node_index, index) in width_of]
        if results:
            write(results[0], RAX)

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
            elif operation == Operation.CALL_FOREIGN:
                _syscall(node, result, block_index, node_index)
            elif operation in (Operation.HEAP_VIEW, Operation.POINTER_CAST):
                write(result, read(node.operands[0], T0))  # S10b: the view's (or narrowed) pointer is the address
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


def syscall_template(node, resolve) -> tuple[int, tuple[int | str, ...], bool] | None:
    """S10a/S10b: ``(number, register template, allocator)`` of a ``call.foreign`` the views profile lowers, or None
    (rejected with ``X86_64_VIEWS-SYSCALL``): a ``linux-x86_64-syscall-v1`` declaration with at most one machine
    result and a template ``decode_syscall_name`` accepts for the machine operands.  With an allocator contract the
    result is nullable: a kernel error becomes 0.  S11: a ``linux-x86_64-startup-v1`` declaration of a read in
    ``STARTUP_READS`` (no heap contracts, its machine operands, at most one machine result) is ``STARTUP_*`` over
    them."""
    from xax_compiler import LINUX_X86_64_STARTUP_ABI, LINUX_X86_64_SYSCALL_ABI, XaxError, decode_foreign_function
    from xax_x86_64 import decode_syscall_name

    declaration = decode_foreign_function(node.entity)
    results = sum(1 for cid in node.results if not _is_proof_type(resolve(cid)))
    machine = sum(1 for cid in node.operand_types if not _is_proof_type(resolve(cid)))
    if declaration.abi == LINUX_X86_64_STARTUP_ABI and declaration.allocator is None and declaration.deallocator is None:
        number, operands = STARTUP_READS.get(declaration.name, (None, None))  # S11: a startup read (``_startup``)
        if number is None or machine != operands or results > 1:
            return None
        return number, tuple(f"${k}" for k in range(operands)), False
    if declaration.abi != LINUX_X86_64_SYSCALL_ABI:
        return None
    if results > 1:
        return None
    try:
        return (*decode_syscall_name(declaration.name, machine), declaration.allocator is not None)
    except XaxError:
        return None


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
    if target.identity not in IDENTITIES:
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
        process = target.identity == EXEC_IDENTITY and function is entry
        for block, node, start, end in _compile_function(function, resolve, emitter, process):
            node_ranges.append(ArtifactSemanticRange(function.cid, block, node, start, end))
    code = emitter.finish(offsets)
    _graph, parameters, returns = _decode_function_interface(entry, resolve)
    widths = lambda cids: tuple(w for w in (machine_width(resolve, cid, function_cid.hex(), ISA) for cid in cids) if w is not None)  # noqa: E731
    return X86ViewsImage(code, 0, tuple(sorted(offsets.items())), widths(parameters), widths(returns), target_object.cid,
                         (*_function_ranges(functions, offsets, len(code)), *node_ranges))


def views_executable(image: X86ViewsImage) -> bytes:
    """S11 (ADR-267): an image lowered for ``x86_64-linux-views-exec-v1`` as a static ELF64 ``ET_EXEC``: the Linux
    package's container (``xax_linux``: one read/execute load segment at 0x400000 and a non-executable stack), whose
    ``e_entry`` is the entry function.  The container adds no code."""
    from xax_linux import _emit_static

    return _emit_static(image)[0]


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
