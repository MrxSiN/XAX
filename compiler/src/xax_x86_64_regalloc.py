"""Register-resident x86-64 lowering for the Linux profiles (U1.2b, ADR-089, OI-38).

The legacy register-resident path in :mod:`xax_x86_64` covers only scalar
add/sub/mul/call graphs and is kept byte-stable for committed artifacts.  This
module lowers the larger operation set used by hosted programs while keeping
SSA values in registers:

* allocation is per block with furthest-next-use eviction (as in the legacy
  path), extended with the x64 callee-saved registers, which are saved and
  restored only when used;
* block parameters arrive in fixed registers or fixed edge slots;
* a value used outside its defining block by dominance gets one frame
  "home" slot written at its definition;
* calls (internal, syscall, SysV C) spill every live value and treat all
  registers as clobbered, which satisfies every calling convention involved.

Unsupported operations return ``None`` so the caller falls back to the
spill-every-value lowering; nothing is guessed.
"""

from __future__ import annotations

from typing import Callable

from xax_artifact import ArtifactSemanticRange
from xax_compiler import (
    IntCompare,
    LINUX_X86_64_SYSCALL_ABI,
    NativeTargetDescription,
    Operation,
    RESOURCE_EFFECT_OPERATIONS,
    SYSV_X86_64_C_ABI,
    SemanticObject,
    TerminatorKind,
    TrapReason,
    ValueRef,
    _decode_constant,
    _is_erased_proof_function,
    _is_proof_type,
    decode_foreign_function,
    decode_trap_payload,
    fail,
    pointer_extent_from_graph,
)
from xax_x86_64 import (
    RAX,
    RDX,
    _SYSCALL_ARGUMENT_REGISTERS,
    _SYSV_ARGUMENT_REGISTERS,
    _Assembler,
    _align,
    _and_immediate,
    _cmp_imm32,
    _cmp_registers,
    _constant_value,
    _immediate,
    _base_index_load,
    _base_index_store,
    _is_aggregate_cid,
    _is_float_cid,
    _lea,
    _load,
    _load_exact,
    _move_register,
    _register_arithmetic,
    _rex,
    _setcc_register,
    _store,
    _store_exact,
    _sysv_integer_class,
    _test_register,
    _value_width,
    _zero32,
    decode_syscall_name,
    require_sysv_profile,
)

RBX, RBP, RSI, RDI = 3, 5, 6, 7
CALLEE_SAVED = (RBX, RBP, RSI, RDI, 12, 13, 14, 15)
_SHADOW_SPACE = 32
_SCRATCH = 11

_PURE_BINARY = frozenset({Operation.ADD_WRAP, Operation.SUB_WRAP, Operation.MUL_WRAP, Operation.BIT_XOR, Operation.BIT_AND, Operation.BIT_OR})
_COMMUTATIVE = frozenset({Operation.ADD_WRAP, Operation.MUL_WRAP, Operation.BIT_XOR, Operation.BIT_AND, Operation.BIT_OR})
_COPY = frozenset({Operation.INT_ZERO_EXTEND, Operation.POINTER_CAST})
_MEMORY = frozenset({Operation.LOAD_BITS_LE, Operation.STORE_BITS_LE, Operation.CHECKED_LOAD_BITS_LE, Operation.CHECKED_STORE_BITS_LE, Operation.RAW_LOAD_BITS_LE})
SUPPORTED_OPERATIONS = frozenset(
    {
        *_PURE_BINARY, *_COPY, *_MEMORY, *RESOURCE_EFFECT_OPERATIONS,
        Operation.UDIV, Operation.UREM, Operation.CONSTANT, Operation.INT_COMPARE, Operation.INT_TRUNCATE,
        Operation.ADDRESS_OFFSET, Operation.HEAP_VIEW, Operation.CALL_DIRECT, Operation.CALL_FOREIGN,
    }
)
_CALLS = frozenset({Operation.CALL_DIRECT, Operation.CALL_FOREIGN})
_GROUP1 = {Operation.ADD_WRAP: 0, Operation.BIT_OR: 1, Operation.BIT_AND: 4, Operation.SUB_WRAP: 5, Operation.BIT_XOR: 6}
_JUMP_IF_FALSE = {
    IntCompare.EQ: 0x85, IntCompare.NE: 0x84, IntCompare.ULT: 0x83, IntCompare.ULE: 0x87,
    IntCompare.UGT: 0x86, IntCompare.UGE: 0x82, IntCompare.SLT: 0x8D, IntCompare.SLE: 0x8F,
    IntCompare.SGT: 0x8E, IntCompare.SGE: 0x8C,
}


def _immediate_fits(value: int, width: int) -> bool:
    """imm32 is sign-extended for 64-bit operations, zero-extension-free for 32-bit."""
    return 0 <= value < (1 << 31) if width > 32 else 0 <= value < (1 << 32)


def _load_constant(register: int, value: int) -> bytes:
    if value == 0:
        return _zero32(register)
    if value < 1 << 32:
        return _rex(False, 0, register) + bytes((0xB8 + (register & 7),)) + value.to_bytes(4, "little")
    return _immediate(register, value)


def _group1_immediate(operation: Operation, register: int, value: int, width: int) -> bytes:
    """``op r, imm32`` for add/or/and/sub/xor (and cmp as digit 7)."""
    digit = 7 if operation is None else _GROUP1[operation]
    return _rex(width > 32, 0, register) + b"\x81" + bytes((0xC0 | (digit << 3) | (register & 7),)) + (value & 0xFFFFFFFF).to_bytes(4, "little")


def _shift_immediate(left: bool, register: int, amount: int, width: int) -> bytes:
    return _rex(width > 32, 0, register) + b"\xc1" + bytes((0xC0 | ((4 if left else 5) << 3) | (register & 7), amount))


def _imul_immediate(destination: int, source: int, value: int, width: int) -> bytes:
    return _rex(width > 32, destination, source) + b"\x69" + bytes((0xC0 | ((destination & 7) << 3) | (source & 7),)) + value.to_bytes(4, "little")


def _power_of_two(value: int | None) -> int | None:
    return value.bit_length() - 1 if value and value & (value - 1) == 0 else None


def _push(register: int) -> bytes:
    return (b"\x41" if register >= 8 else b"") + bytes((0x50 + (register & 7),))


def _pop(register: int) -> bytes:
    return (b"\x41" if register >= 8 else b"") + bytes((0x58 + (register & 7),))


def _eligible(graph, parameter_types, return_types, resolve) -> dict[ValueRef, int] | None:
    """Machine widths for every value, or ``None`` when the graph needs the general path."""
    machine_parameters = [cid for cid in parameter_types if not _is_proof_type(resolve(cid))]
    machine_returns = [cid for cid in return_types if not _is_proof_type(resolve(cid))]
    if len(machine_parameters) > 4 or len(machine_returns) > 1:
        return None

    def machine_width(cid: bytes) -> int | None:
        if _is_float_cid(resolve, cid) or _is_aggregate_cid(resolve, cid):
            return None
        width = _value_width(resolve, cid)
        return width if width and width <= 64 else None

    if any(machine_width(cid) is None for cid in (*machine_parameters, *machine_returns)):
        return None
    widths: dict[ValueRef, int] = {}
    for block_index, block in enumerate(graph.blocks):
        if block.terminator.kind not in (TerminatorKind.RETURN, TerminatorKind.BRANCH, TerminatorKind.CONDITIONAL_BRANCH, TerminatorKind.TRAP):
            return None
        for index, cid in enumerate(block.parameters):
            if not _is_proof_type(resolve(cid)):
                width = machine_width(cid)
                if width is None:
                    return None
                widths[ValueRef.parameter(block_index, index)] = width
        for node_index, node in enumerate(block.nodes):
            if node.operation not in SUPPORTED_OPERATIONS:
                return None
            if node.operation == Operation.CALL_DIRECT and _is_erased_proof_function(node.entity, resolve):
                continue
            if node.operation in _CALLS:
                inputs = [cid for cid in node.operand_types if not _is_proof_type(resolve(cid))]
                if node.operation == Operation.CALL_DIRECT and len(inputs) > 4:
                    return None
                if any(machine_width(cid) is None for cid in inputs):
                    return None
            for result_index, cid in enumerate(node.results):
                if not _is_proof_type(resolve(cid)):
                    width = machine_width(cid)
                    if width is None:
                        return None
                    widths[ValueRef.node_result(block_index, node_index, result_index)] = width
    return widths


def compile_register_resident(
    function: SemanticObject,
    graph_object: SemanticObject,
    graph,
    parameter_types: tuple[bytes, ...],
    return_types: tuple[bytes, ...],
    resolve: Callable[[bytes], SemanticObject],
    target: NativeTargetDescription,
    process_entry: bool = False,
):
    """Return ``(code, calls, ranges)`` or ``None`` when ineligible.

    Foreign C calls are recorded in ``calls`` against their declaration CID;
    the native image turns them into ``imports`` for the container emitter.
    """
    widths = _eligible(graph, parameter_types, return_types, resolve)
    if widths is None:
        return None
    allocatable = (*target.argument_registers, target.scratch_registers[0], target.result_register, *CALLEE_SAVED)
    machine_parameters = {
        block_index: tuple(ValueRef.parameter(block_index, index) for index in range(len(block.parameters)) if ValueRef.parameter(block_index, index) in widths)
        for block_index, block in enumerate(graph.blocks)
    }
    has_call = any(
        node.operation in _CALLS and not (node.operation == Operation.CALL_DIRECT and _is_erased_proof_function(node.entity, resolve))
        for block in graph.blocks for node in block.nodes
    )

    constants: dict[ValueRef, int] = {}
    for block_index, block in enumerate(graph.blocks):
        for node_index, node in enumerate(block.nodes):
            if node.operation == Operation.CONSTANT:
                constants[ValueRef.node_result(block_index, node_index)] = _decode_constant(node.entity, resolve)[1]

    def immediate(value: ValueRef, width: int) -> int | None:
        constant = constants.get(value)
        return constant if constant is not None and _immediate_fits(constant, width) else None

    # A compare consumed only by its block's conditional branch fuses into cmp+jcc.
    fused: dict[int, int] = {}
    for block_index, block in enumerate(graph.blocks):
        terminator = block.terminator
        if terminator.kind != TerminatorKind.CONDITIONAL_BRANCH:
            continue
        condition = terminator.values[0]
        if condition.tag != 1 or condition.block != block_index:
            continue
        node = block.nodes[condition.index]
        consumers = sum(operand == condition for other in block.nodes for operand in other.operands)
        consumers += sum(value == condition for _target, arguments in terminator.edges for value in arguments)
        if node.operation == Operation.INT_COMPARE and consumers == 0:
            fused[block_index] = condition.index

    # Values used in a block other than the one defining them live in a home slot.
    uses_by_block: dict[int, dict[ValueRef, tuple[int, ...]]] = {}
    homes: list[ValueRef] = []
    for block_index, block in enumerate(graph.blocks):
        uses: dict[ValueRef, list[int]] = {}
        position = len(block.nodes)
        for node_index, node in enumerate(block.nodes):
            use_position = position if fused.get(block_index) == node_index else node_index
            for operand in node.operands:
                if operand in widths:
                    uses.setdefault(operand, []).append(use_position)
        for value in (*block.terminator.values, *(value for _target, arguments in block.terminator.edges for value in arguments)):
            if value in widths:
                uses.setdefault(value, []).append(position)
        uses_by_block[block_index] = {value: tuple(sorted(items)) for value, items in uses.items()}
        for value in uses:
            if value.block != block_index and value not in homes and value not in constants:
                homes.append(value)
    homes.sort(key=lambda value: (value.tag, value.block, value.index, value.result))

    shadow = _SHADOW_SPACE if has_call else 0
    edge_spill_count = max((max(0, len(params) - len(allocatable)) for params in machine_parameters.values()), default=0)
    edge_spill_base = shadow
    home_base = edge_spill_base + edge_spill_count * 8
    home_offset = {value: home_base + index * 8 for index, value in enumerate(homes)}
    dynamic_spill_base = home_base + len(homes) * 8

    def width_bytes(value: ValueRef) -> int:
        return 8 if widths[value] > 32 else 4

    def lower_block(block_index: int, assembler: _Assembler | None, ranges: list | None, used_registers: set[int], epilogue: bytes) -> int:
        block = graph.blocks[block_index]
        uses = uses_by_block[block_index]
        last_use = {value: positions[-1] for value, positions in uses.items()}
        register_for: dict[ValueRef, int] = {}
        value_for_register: dict[int, ValueRef] = {}
        spill_offset: dict[ValueRef, int] = {value: home_offset[value] for value in uses if value.block != block_index}
        spill_id: dict[ValueRef, int] = {}
        free_spills: list[int] = []
        state = {"next": 0, "max": 0}
        checked: set[tuple[ValueRef, ValueRef, int]] = set()  # proven in-bounds (pointer, index, maximum)

        def emit(data: bytes) -> None:
            if assembler is not None:
                assembler.emit(data)

        def jump(opcode: bytes, label: str) -> None:
            if assembler is not None:
                assembler.relative(opcode, label)

        def label(name: str) -> None:
            if assembler is not None:
                assembler.label(name)

        def bind(value: ValueRef, register: int) -> None:
            old_value = value_for_register.get(register)
            if old_value is not None and old_value != value:
                register_for.pop(old_value, None)
            old_register = register_for.get(value)
            if old_register is not None and old_register != register:
                value_for_register.pop(old_register, None)
            register_for[value] = register
            value_for_register[register] = value
            used_registers.add(register)

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
            register = register_for[value]
            if value in constants:  # rematerialized on demand, never stored
                if not keep:
                    unbind(value)
                return
            if value not in spill_offset:
                if free_spills:
                    slot = min(free_spills)
                    free_spills.remove(slot)
                else:
                    slot = state["next"]
                    state["next"] += 1
                    state["max"] = max(state["max"], state["next"])
                spill_id[value] = slot
                spill_offset[value] = dynamic_spill_base + slot * 8
                emit(_store(register, spill_offset[value], width_bytes(value)))
            if not keep:
                unbind(value)

        def acquire(position: int, protected: frozenset | set = frozenset(), excluded: tuple[int, ...] = ()) -> int:
            for register in allocatable:
                if register not in value_for_register and register not in excluded:
                    return register
            candidates = [value for value, register in register_for.items() if value not in protected and register not in excluded]
            if not candidates:
                fail("XAX.NATIVE.REGISTER_PRESSURE", graph_object.cid.hex(), "NATIVE-SPILLABLE-REGISTER", "one non-protected live value", len(protected))
            victim = max(candidates, key=lambda value: (next_use(value, position), register_for[value], value.tag, value.block, value.index, value.result))
            register = register_for[victim]
            spill(victim)
            return register

        def ensure(value: ValueRef, position: int, protected: frozenset | set = frozenset(), excluded: tuple[int, ...] = ()) -> int:
            if value in register_for and register_for[value] not in excluded:
                return register_for[value]
            if value in register_for:
                register = acquire(position, {*protected, value}, excluded)
                emit(_move_register(register, register_for[value], 64))
                unbind(value)
                bind(value, register)
                return register
            if value in constants:
                register = acquire(position, protected, excluded)
                emit(_load_constant(register, constants[value]))
                bind(value, register)
                return register
            try:
                offset = spill_offset[value]
            except KeyError:
                fail("XAX.NATIVE.VALUE", graph_object.cid.hex(), "NATIVE-VALUE-LOCATION", "register, spill, or home", [value.block, value.index, value.result])
            register = acquire(position, protected, excluded)
            emit(_load(register, offset, width_bytes(value)))
            bind(value, register)
            return register

        def define(value: ValueRef, register: int) -> None:
            bind(value, register)
            if value in home_offset and value.block == block_index:
                emit(_store(register, home_offset[value], width_bytes(value)))
                spill_offset[value] = home_offset[value]  # later evictions need no store
            if value not in last_use:
                release(value)

        def retire(position: int, *operands: ValueRef) -> None:
            for operand in set(operands):
                if last_use.get(operand) == position:
                    release(operand)

        def destination_for(position: int, source: ValueRef, protected: set) -> int:
            """Reuse the source register when this is its last use, else a fresh one."""
            source_register = register_for[source]
            if last_use.get(source) == position:
                unbind(source)
                return source_register
            register = acquire(position, {*protected, source})
            emit(_move_register(register, source_register, 64))
            return register

        def parallel_moves(assignments: list[tuple[int, int, int]]) -> None:
            pending = [(dst, src, width) for dst, src, width in assignments if dst != src]
            while pending:
                sources = {src for _, src, _ in pending}
                safe = next((i for i, (dst, _, _) in enumerate(pending) if dst not in sources), None)
                if safe is not None:
                    dst, src, width = pending.pop(safe)
                    emit(_move_register(dst, src, 64))
                    continue
                dst, src, width = pending[0]
                emit(_move_register(_SCRATCH, src, 64))
                pending = [(d, _SCRATCH if s == src else s, w) for d, s, w in pending]

        def location(value: ValueRef) -> tuple[str, int]:
            if value in register_for:
                return "reg", register_for[value]
            if value in constants:
                return "const", constants[value]
            if value in spill_offset:
                return "spill", spill_offset[value]
            fail("XAX.NATIVE.VALUE", graph_object.cid.hex(), "NATIVE-VALUE-LOCATION", "register or spill", [value.block, value.index, value.result])

        def place_arguments(position: int, operands: tuple[ValueRef, ...], registers: tuple[int, ...]) -> None:
            """Spill everything live after ``position``, then load operands into ``registers``."""
            live_after = sorted(
                (value for value in register_for if last_use.get(value, -1) > position),
                key=lambda item: (item.tag, item.block, item.index, item.result),
            )
            for value in live_after:
                spill(value, keep=True)
            moves = []
            for destination, operand in zip(registers, operands):
                kind, source = location(operand)
                if kind == "reg":
                    moves.append((destination, source, widths[operand]))
            parallel_moves(moves)
            for destination, operand in zip(registers, operands):
                kind, source = location(operand)
                if kind == "spill":
                    emit(_load(destination, source, width_bytes(operand)))
                elif kind == "const":
                    emit(_load_constant(destination, source))

        def emit_compare(position: int, left: ValueRef, right: ValueRef) -> None:
            value = immediate(right, widths[left])
            left_register = ensure(left, position)
            if value is not None:
                emit(_group1_immediate(None, left_register, value, widths[left]))
            else:
                right_register = ensure(right, position, {left})
                emit(_cmp_registers(left_register, right_register, widths[left]))

        def after_call(position: int, operands: tuple[ValueRef, ...]) -> None:
            for value in tuple(register_for):
                unbind(value)
            for operand in set(operands):
                if last_use.get(operand) == position:
                    release(operand)

        def copy_edge(target_block: int, arguments: tuple[ValueRef, ...]) -> None:
            destinations = machine_parameters[target_block]
            pairs = []
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
                    emit(_store(source_location, destination_offset, 8))
                elif kind == "const":
                    emit(_load_constant(_SCRATCH, source_location))
                    emit(_store(_SCRATCH, destination_offset, 8))
                elif source_location != destination_offset:
                    emit(_load(_SCRATCH, source_location, width_bytes(source)))
                    emit(_store(_SCRATCH, destination_offset, 8))
            moves, delayed = [], []
            for source, index, destination in pairs:
                if index >= len(allocatable):
                    continue
                kind, source_location = location(source)
                if kind == "reg":
                    moves.append((allocatable[index], source_location, widths[destination]))
                else:
                    delayed.append((allocatable[index], kind, source_location, width_bytes(source)))
            parallel_moves(moves)
            for register, kind, where, width in delayed:
                emit(_load_constant(register, where) if kind == "const" else _load(register, where, width))

        label(f"block-{block_index}")
        for index, value in enumerate(machine_parameters[block_index]):
            if index < len(allocatable):
                bind(value, allocatable[index])
            else:
                spill_offset[value] = edge_spill_base + (index - len(allocatable)) * 8
        for value in machine_parameters[block_index]:
            if value in home_offset:
                kind, where = location(value)
                if kind == "reg":
                    emit(_store(where, home_offset[value], 8))
                else:
                    emit(_load(_SCRATCH, where, 8))
                    emit(_store(_SCRATCH, home_offset[value], 8))
            if value not in last_use:
                release(value)

        for node_index, node in enumerate(block.nodes):
            start = len(assembler.code) if assembler is not None else 0
            result = ValueRef.node_result(block_index, node_index)
            operation = node.operation
            machine_operands = tuple(operand for operand in node.operands if operand in widths)

            if operation in _PURE_BINARY and immediate(node.operands[1], widths[result]) is None and operation in _COMMUTATIVE and immediate(node.operands[0], widths[result]) is not None:
                node_operands = (node.operands[1], node.operands[0])
            else:
                node_operands = node.operands
            if operation in _PURE_BINARY and immediate(node_operands[1], widths[result]) is not None:
                left, right = node_operands
                width = widths[result]
                value = constants[right]
                ensure(left, node_index)
                destination = destination_for(node_index, left, set())
                shift = _power_of_two(value) if operation == Operation.MUL_WRAP else None
                if operation == Operation.MUL_WRAP and shift is not None:
                    emit(_shift_immediate(True, destination, shift, width))
                elif operation == Operation.MUL_WRAP:
                    emit(_imul_immediate(destination, destination, value, width))
                else:
                    emit(_group1_immediate(operation, destination, value, width))
                if width < 64 and width != 32:
                    emit(_and_immediate(destination, (1 << width) - 1, width=32))
                retire(node_index, left, right)
                define(result, destination)

            elif operation in _PURE_BINARY:
                left, right = node.operands
                width = widths[result]
                left_register = ensure(left, node_index)
                right_register = ensure(right, node_index, {left})
                if last_use.get(left) == node_index and left != right:
                    destination, source = left_register, right_register
                    unbind(left)
                elif last_use.get(right) == node_index and operation in _COMMUTATIVE and left != right:
                    destination, source = right_register, left_register
                    unbind(right)
                else:
                    destination, source = acquire(node_index, {left, right}), right_register
                    emit(_move_register(destination, left_register, width))
                emit(_register_arithmetic(operation, destination, source, width))
                retire(node_index, left, right)
                define(result, destination)

            elif operation in (Operation.UDIV, Operation.UREM) and _power_of_two(constants.get(node.operands[1])) is not None and (constants[node.operands[1]] - 1) < (1 << 31):
                dividend, divisor = node.operands
                shift = _power_of_two(constants[divisor])
                ensure(dividend, node_index)
                destination = destination_for(node_index, dividend, set())
                if operation == Operation.UDIV:
                    if shift:
                        emit(_shift_immediate(False, destination, shift, widths[result]))
                else:
                    emit(_group1_immediate(Operation.BIT_AND, destination, constants[divisor] - 1, widths[result]))
                retire(node_index, dividend, divisor)
                define(result, destination)

            elif operation in (Operation.UDIV, Operation.UREM):
                dividend, divisor = node.operands
                width = widths[result]
                divisor_register = ensure(divisor, node_index, {dividend}, excluded=(RAX, RDX))
                if (_constant_value(graph, divisor, resolve) or 0) == 0:
                    nonzero = f"ra-divisor-{block_index}-{node_index}"
                    emit(_test_register(divisor_register, width))
                    jump(b"\x0f\x85", nonzero)
                    emit(_immediate(RAX, TrapReason.INTEGER_DIVIDE_BY_ZERO) + b"\x0f\x0b")
                    label(nonzero)
                for fixed in (RDX, RAX):
                    occupant = value_for_register.get(fixed)
                    if occupant is None or (fixed == RAX and occupant == dividend):
                        continue
                    if occupant == dividend:
                        moved = acquire(node_index, {dividend, divisor}, excluded=(RAX, RDX))
                        emit(_move_register(moved, fixed, 64))
                        unbind(dividend)
                        bind(dividend, moved)
                    elif next_use(occupant, node_index - 1) < (1 << 30):
                        spill(occupant)
                    else:
                        release(occupant)
                dividend_register = ensure(dividend, node_index, {divisor}, excluded=(RDX,))
                if last_use.get(dividend) != node_index or dividend in home_offset:
                    spill(dividend, keep=True)
                if dividend_register != RAX:
                    emit(_move_register(RAX, dividend_register, 64))
                emit(_zero32(RDX))
                emit(_rex(width == 64, 0, divisor_register) + b"\xf7" + bytes((0xF0 | (divisor_register & 7),)))
                for fixed in (RAX, RDX):
                    occupant = value_for_register.get(fixed)
                    if occupant is not None:
                        unbind(occupant)
                retire(node_index, dividend, divisor)
                define(result, RAX if operation == Operation.UDIV else RDX)

            elif operation == Operation.CONSTANT:
                pass  # rematerialized at each use

            elif operation == Operation.INT_COMPARE and fused.get(block_index) == node_index:
                pass  # emitted as cmp+jcc by the terminator

            elif operation == Operation.INT_COMPARE:
                left, right = node.operands
                emit_compare(node_index, left, right)
                retire(node_index, left, right)
                register = acquire(node_index, {left, right})
                emit(_setcc_register(IntCompare(node.attributes[0]), register))
                define(result, register)

            elif operation == Operation.INT_TRUNCATE:
                source = node.operands[0]
                ensure(source, node_index)
                register = destination_for(node_index, source, set())
                width = widths[result]
                if width == 32:
                    emit(_move_register(register, register, 32))
                else:
                    emit(_and_immediate(register, (1 << width) - 1, width=32))
                retire(node_index, source)
                define(result, register)

            elif operation in _COPY:
                source = node.operands[0]
                ensure(source, node_index)
                register = destination_for(node_index, source, set())
                retire(node_index, source)
                define(result, register)

            elif operation == Operation.ADDRESS_OFFSET:
                source = node.operands[0]
                ensure(source, node_index)
                register = destination_for(node_index, source, set())
                if node.attributes[0]:
                    emit(_lea(register, register, node.attributes[0]))
                retire(node_index, source)
                define(result, register)

            elif operation == Operation.HEAP_VIEW:
                source = node.operands[0]
                source_register = ensure(source, node_index)
                nonnull = f"ra-heap-view-{block_index}-{node_index}"
                emit(_test_register(source_register, 64))
                jump(b"\x0f\x85", nonnull)
                emit(b"\x0f\x0b")
                label(nonnull)
                register = destination_for(node_index, source, set())
                retire(node_index, source)
                define(result, register)

            elif operation in _MEMORY:
                if operation == Operation.STACK_ALLOC:  # pragma: no cover - excluded by eligibility
                    return -1
                pointer = node.operands[0]
                base = ensure(pointer, node_index)
                size = node.attributes[0]
                if operation in (Operation.LOAD_BITS_LE, Operation.RAW_LOAD_BITS_LE):
                    register = acquire(node_index, {pointer})
                    emit(_load_exact(register, base, 0, size))
                    retire(node_index, pointer)
                    define(result, register)
                elif operation == Operation.STORE_BITS_LE:
                    value = node.operands[1]
                    value_register = ensure(value, node_index, {pointer})
                    emit(_store_exact(value_register, base, 0, size))
                    retire(node_index, pointer, value)
                else:
                    index_value = node.operands[1]
                    maximum = pointer_extent_from_graph(graph, pointer, resolve) - size
                    index = ensure(index_value, node_index, {pointer})
                    if maximum < 0:
                        emit(b"\x0f\x0b")
                    elif (pointer, index_value, maximum) in checked:
                        pass  # an earlier check in this block already proved this exact access
                    else:
                        checked.add((pointer, index_value, maximum))
                        in_bounds = f"ra-checked-{block_index}-{node_index}"
                        emit(_cmp_imm32(index, maximum))
                        jump(b"\x0f\x86", in_bounds)
                        emit(b"\x0f\x0b")
                        label(in_bounds)
                    if operation == Operation.CHECKED_LOAD_BITS_LE:
                        register = acquire(node_index, {pointer, index_value})
                        emit(_base_index_load(register, base, index, 0, size))
                        retire(node_index, pointer, index_value)
                        define(result, register)
                    else:
                        value = node.operands[2]
                        value_register = ensure(value, node_index, {pointer, index_value})
                        emit(_base_index_store(value_register, base, index, 0, size))
                        retire(node_index, pointer, index_value, value)

            elif operation == Operation.CALL_DIRECT:
                if _is_erased_proof_function(node.entity, resolve):
                    continue
                place_arguments(node_index, machine_operands, target.argument_registers)
                if assembler is not None:
                    assembler.call(node.entity.cid)
                after_call(node_index, machine_operands)
                results = [ValueRef.node_result(block_index, node_index, index) for index, cid in enumerate(node.results) if not _is_proof_type(resolve(cid))]
                if results:
                    define(results[0], RAX)

            elif operation == Operation.CALL_FOREIGN:
                declaration = decode_foreign_function(node.entity)
                results = [ValueRef.node_result(block_index, node_index, index) for index, cid in enumerate(node.results) if not _is_proof_type(resolve(cid))]
                if declaration.abi == SYSV_X86_64_C_ABI:
                    require_sysv_profile(target, graph_object)
                    if not all(_sysv_integer_class(resolve, cid) for cid in node.operand_types if not _is_proof_type(resolve(cid))):
                        return -1
                    place_arguments(node_index, machine_operands, _SYSV_ARGUMENT_REGISTERS)
                    if assembler is not None:
                        assembler.call_import(node.entity.cid)
                elif declaration.abi == LINUX_X86_64_SYSCALL_ABI:
                    number, template = decode_syscall_name(declaration.name, len(machine_operands))
                    ordered = tuple(machine_operands[int(item[1:])] for item in template if isinstance(item, str))
                    registers = tuple(register for register, item in zip(_SYSCALL_ARGUMENT_REGISTERS, template) if isinstance(item, str))
                    place_arguments(node_index, ordered, registers)
                    for register, item in zip(_SYSCALL_ARGUMENT_REGISTERS, template):
                        if not isinstance(item, str):
                            emit(_immediate(register, item))
                    emit(b"\xb8" + number.to_bytes(4, "little") + b"\x0f\x05")
                    if declaration.allocator is not None:
                        emit(b"\x48\x3d\x01\xf0\xff\xff\x72\x02\x31\xc0")
                else:
                    return -1
                after_call(node_index, machine_operands)
                if results:
                    width = widths[results[0]]
                    if width < 64:
                        emit(_move_register(RAX, RAX, 32) if width == 32 else _and_immediate(RAX, (1 << width) - 1, width=32))
                    define(results[0], RAX)

            elif operation not in RESOURCE_EFFECT_OPERATIONS:
                return -1

            if assembler is not None and ranges is not None and len(assembler.code) > start:
                ranges.append(ArtifactSemanticRange(function.cid, block_index, node_index, start, len(assembler.code)))

        terminator = block.terminator
        position = len(block.nodes)
        if terminator.kind == TerminatorKind.RETURN:
            values = [value for value in terminator.values if value in widths]
            if values:
                kind, where = location(values[0])
                if kind == "reg":
                    if where != RAX:
                        emit(_move_register(RAX, where, 64))
                else:
                    emit(_load(RAX, where, width_bytes(values[0])))
            else:
                emit(b"\x31\xc0")
            emit(epilogue)
        elif terminator.kind == TerminatorKind.BRANCH:
            target_block, arguments = terminator.edges[0]
            copy_edge(target_block, arguments)
            jump(b"\xe9", f"block-{target_block}")
        elif terminator.kind == TerminatorKind.CONDITIONAL_BRANCH:
            condition = terminator.values[0]
            false_label = f"false-{block_index}"
            if block_index in fused:
                compare = block.nodes[fused[block_index]]
                emit_compare(position, *compare.operands)
                jump(b"\x0f" + bytes((_JUMP_IF_FALSE[IntCompare(compare.attributes[0])],)), false_label)
            else:
                register = ensure(condition, position)
                emit(_test_register(register, widths[condition]))
                jump(b"\x0f\x84", false_label)
            target_block, arguments = terminator.edges[0]
            copy_edge(target_block, arguments)
            jump(b"\xe9", f"block-{target_block}")
            label(false_label)
            target_block, arguments = terminator.edges[1]
            copy_edge(target_block, arguments)
            jump(b"\xe9", f"block-{target_block}")
        else:
            reason, _ = decode_trap_payload(terminator.payload)
            emit(_immediate(RAX, reason) + b"\x0f\x0b")
        return state["max"]

    # Dry run: spill count and used callee-saved registers, without emission.
    used: set[int] = set()
    plan = [lower_block(index, None, None, used, b"") for index in range(len(graph.blocks))]
    if any(item < 0 for item in plan):
        return None
    spill_count = max(plan, default=0)
    # A process entry never returns to a caller, so it has nothing to preserve.
    saved = () if process_entry else tuple(register for register in CALLEE_SAVED if register in used)
    payload = dynamic_spill_base + spill_count * 8
    # A called function starts with RSP % 16 == 8; a process entry starts
    # aligned.  Keep RSP 16-byte aligned at every call either way.
    pushed = (0 if process_entry else 8) + 8 * len(saved)
    frame_size = _align(payload + pushed, 16) - pushed if (payload or has_call) else 0
    if process_entry:
        epilogue = b"\x0f\x0b"  # the process contract requires an explicit exit call; returning traps
    else:
        epilogue = (b"\x48\x81\xc4" + frame_size.to_bytes(4, "little") if frame_size else b"") + b"".join(_pop(register) for register in reversed(saved)) + b"\xc3"

    assembler = _Assembler()
    for register in saved:
        assembler.emit(_push(register))
    if frame_size:
        assembler.emit(b"\x48\x81\xec" + frame_size.to_bytes(4, "little"))
    if graph.entry:
        assembler.relative(b"\xe9", f"block-{graph.entry}")
    ranges: list[ArtifactSemanticRange] = []
    for block_index in range(len(graph.blocks)):
        observed = lower_block(block_index, assembler, ranges, set(), epilogue)
        if observed > spill_count or observed < 0:
            fail("XAX.NATIVE.SPILL_PLAN", graph_object.cid.hex(), "NATIVE-SPILL-PLAN-DETERMINISTIC", spill_count, observed)
    code, calls = assembler.finish()
    return code, calls, tuple(ranges)

