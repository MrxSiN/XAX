"""Register-resident x86-64 lowering for the hosted profiles (U1.2b, ADR-089, OI-38).

Linux (static and dynamic ELF) and, since ADR-095, the Windows PE profile use
this allocator first; functions it cannot lower fall back to the legacy
allocator (ADR-083) and then to frame lowering.

The legacy register-resident path in :mod:`xax_x86_64` covers only scalar
add/sub/mul/call graphs and is kept byte-stable for committed artifacts.  This
module lowers the larger operation set used by hosted programs while keeping
SSA values in registers:

* allocation is per block with furthest-next-use eviction (as in the legacy
  path), extended with the x64 callee-saved registers, which are saved and
  restored only when used;
* block parameters arrive in fixed registers or fixed edge slots;
* a value used outside its defining block by dominance is either *pinned*
  (ADR-091): it owns one of ``PINNABLE`` for the whole function, ranked by
  uses in blocks on a CFG cycle; or gets one frame "home" slot written at
  its definition;
* calls (internal, syscall, SysV C) spill every unpinned live value and treat
  the volatile registers as clobbered.  Pinned registers survive every call:
  SysV C callees preserve them, syscalls touch only rax/rcx/r11, and XAX
  callees either never use them (frame and legacy paths) or save them here;
* a conditional branch jumps straight to a successor whose edge needs no
  copies, and a jump to the block laid out next is omitted; when one
  successor is laid out next with no copies, it falls through and the other
  edge's copies move to an out-of-line stub after the last block; when both
  edges copy, the next block (else the innermost loop header) stays inline;
* trap paths (bounds, null view, zero divisor) are shared out-of-line
  stubs, so a passing check is a not-taken branch;
* a block entered by a backward jump (a loop header in layout order) starts
  on a ``LOOP_ALIGNMENT`` boundary, padded with recommended multi-byte NOPs.
  Functions start 16-byte aligned in the image, so the boundary is absolute.

Unsupported operations return ``None`` so the caller falls back to the
spill-every-value lowering; nothing is guessed.
"""

from __future__ import annotations

from collections import Counter
from typing import Callable

from xax_artifact import ArtifactSemanticRange
from xax_compiler import (
    IntCompare,
    LINUX_X86_64_STARTUP_ABI,
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
    _decode_pointer_type,
    borrowed_view_returns,
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
    PE_HOSTED_IDENTITY,
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
    code_address_label,
    decode_syscall_name,
    require_sysv_profile,
)

RBX, RBP, RSI, RDI = 3, 5, 6, 7
CALLEE_SAVED = (RBX, RBP, RSI, RDI, 12, 13, 14, 15)
_SHADOW_SPACE = 32
_SCRATCH = 11
WIN64_C_ABI = b"win64-c"
# Preserved across every Linux call kind; see the module docstring (ADR-091).
PINNABLE = (RBX, RBP, 12, 13, 14, 15)
_CYCLE_WEIGHT = 8
LOOP_ALIGNMENT = 16
# Intel SDM recommended NOP encodings, 1 to 9 bytes.
_NOPS = (
    b"\x90", b"\x66\x90", b"\x0f\x1f\x00", b"\x0f\x1f\x40\x00", b"\x0f\x1f\x44\x00\x00",
    b"\x66\x0f\x1f\x44\x00\x00", b"\x0f\x1f\x80\x00\x00\x00\x00",
    b"\x0f\x1f\x84\x00\x00\x00\x00\x00", b"\x66\x0f\x1f\x84\x00\x00\x00\x00\x00",
)


def _nop_padding(length: int) -> bytes:
    padding = b""
    while length:
        step = min(length, len(_NOPS))
        padding += _NOPS[step - 1]
        length -= step
    return padding

_PURE_BINARY = frozenset({Operation.ADD_WRAP, Operation.SUB_WRAP, Operation.MUL_WRAP, Operation.BIT_XOR, Operation.BIT_AND, Operation.BIT_OR})
_COMMUTATIVE = frozenset({Operation.ADD_WRAP, Operation.MUL_WRAP, Operation.BIT_XOR, Operation.BIT_AND, Operation.BIT_OR})
_COPY = frozenset({Operation.INT_ZERO_EXTEND, Operation.POINTER_CAST, Operation.LINK_MAKE})
_MEMORY = frozenset({Operation.LOAD_BITS_LE, Operation.STORE_BITS_LE, Operation.CHECKED_LOAD_BITS_LE, Operation.CHECKED_STORE_BITS_LE, Operation.RAW_LOAD_BITS_LE})
SUPPORTED_OPERATIONS = frozenset(
    {
        *_PURE_BINARY, *_COPY, *_MEMORY, *RESOURCE_EFFECT_OPERATIONS,
        Operation.UDIV, Operation.UREM, Operation.CONSTANT, Operation.INT_COMPARE, Operation.INT_TRUNCATE, Operation.ROTATE_RIGHT,
        Operation.ADDRESS_OFFSET, Operation.HEAP_VIEW, Operation.CALL_DIRECT, Operation.CALL_FOREIGN,
        Operation.POINTER_ADDRESS, Operation.POINTER_REBASE, Operation.FUNCTION_ADDRESS,
        Operation.STACK_ALLOC, Operation.STACK_END, Operation.CALL_INDIRECT, Operation.LINK_FOLLOW, Operation.LINK_TARGET,
    }
)
_CALLS = frozenset({Operation.CALL_DIRECT, Operation.CALL_FOREIGN, Operation.CALL_INDIRECT})
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


def _member_bit_test(register: int, low: int, mask: int, temporary: int) -> bytes:
    """CF = bit ``x - low`` of ``mask``, for a bits<32> ``x``; indices above 62 read bit 63 (clear)."""
    lea = bytes((0x44 | (register >= 8), 0x8D, 0x98 | (register & 7))) + (b"\x24" if register & 7 == 4 else b"") + ((-low) & 0xFFFFFFFF).to_bytes(4, "little")
    clamp = (
        b"\x41\x83\xfb\x3f"  # cmp r11d, 63
        + _rex(False, 0, temporary) + bytes((0xB8 + (temporary & 7),)) + (63).to_bytes(4, "little")  # mov tmp, 63
        + bytes((0x44 | (temporary >= 8), 0x0F, 0x47, 0xD8 | (temporary & 7)))  # cmova r11d, tmp
    )
    return lea + clamp + _load_constant(temporary, mask) + bytes((0x4C | (temporary >= 8), 0x0F, 0xA3, 0xD8 | (temporary & 7)))  # bt tmp, r11


def _group1_immediate(operation: Operation, register: int, value: int, width: int) -> bytes:
    """``op r, imm32`` for add/or/and/sub/xor (and cmp as digit 7)."""
    digit = 7 if operation is None else _GROUP1[operation]
    return _rex(width > 32, 0, register) + b"\x81" + bytes((0xC0 | (digit << 3) | (register & 7),)) + (value & 0xFFFFFFFF).to_bytes(4, "little")


def _rotate_right_immediate(register: int, amount: int) -> bytes:
    return _rex(True, 0, register) + b"\xc1" + bytes((0xC0 | (1 << 3) | (register & 7), amount))


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
    elided = borrowed_view_returns(parameter_types, return_types, resolve)
    machine_returns = [cid for index, cid in enumerate(return_types) if not _is_proof_type(resolve(cid)) and index not in elided]
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
            if node.operation == Operation.ROTATE_RIGHT and _value_width(resolve, node.results[0]) not in (32, 64):
                return None  # a native `ror` exists only at register widths
            if node.operation == Operation.CALL_DIRECT and _is_erased_proof_function(node.entity, resolve):
                continue
            if node.operation in _CALLS:
                inputs = [cid for cid in node.operand_types if not _is_proof_type(resolve(cid))]
                if node.operation in (Operation.CALL_DIRECT, Operation.CALL_INDIRECT) and len(inputs) > 4 + (node.operation == Operation.CALL_INDIRECT):
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


def _choose_pins(graph, homes: list[ValueRef], uses_by_block: dict[int, dict[ValueRef, tuple[int, ...]]]) -> dict[ValueRef, int]:
    """Give ``PINNABLE`` registers to the cross-block values used most inside CFG cycles.

    A pinned register holds one value from its definition to the end of the
    function, so every later use reads it without a home-slot reload.  Only
    values used in a block on a cycle qualify; ties break by value order, so
    the choice is deterministic.
    """
    successors = [tuple(target for target, _arguments in block.terminator.edges) for block in graph.blocks]

    def reaches(start: int, goal: int) -> bool:
        seen, stack = set(), [start]
        while stack:
            block = stack.pop()
            if block == goal:
                return True
            if block not in seen:
                seen.add(block)
                stack.extend(successors[block])
        return False

    cyclic = {index for index in range(len(graph.blocks)) if any(reaches(successor, index) for successor in successors[index])}
    weights = {}
    for value in homes:
        using = [block for block, uses in uses_by_block.items() if block != value.block and value in uses]
        if any(block in cyclic for block in using):
            weights[value] = sum(_CYCLE_WEIGHT if block in cyclic else 1 for block in using)
    ranked = sorted(weights, key=lambda value: (-weights[value], value.tag, value.block, value.index, value.result))
    return dict(zip(ranked, PINNABLE))


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
    machine_parameters = {
        block_index: tuple(ValueRef.parameter(block_index, index) for index in range(len(block.parameters)) if ValueRef.parameter(block_index, index) in widths)
        for block_index, block in enumerate(graph.blocks)
    }
    has_call = any(
        node.operation in _CALLS and not (node.operation == Operation.CALL_DIRECT and _is_erased_proof_function(node.entity, resolve))
        for block in graph.blocks for node in block.nodes
    )

    windows = target.identity == PE_HOSTED_IDENTITY
    startup_frame = {"size": 0}  # set before emission; the dry run's code is discarded
    constants: dict[ValueRef, int] = {}
    for block_index, block in enumerate(graph.blocks):
        for node_index, node in enumerate(block.nodes):
            if node.operation == Operation.CONSTANT:
                constants[ValueRef.node_result(block_index, node_index)] = _decode_constant(node.entity, resolve)[1]

    # Stack storage lives in the frame; its pointers are rematerialized with
    # ``lea`` at each use (like constants), so they never need homes or spills.
    stack_storage: list[tuple[ValueRef, int, int]] = []
    for block_index, block in enumerate(graph.blocks):
        for node_index, node in enumerate(block.nodes):
            if node.operation == Operation.STACK_ALLOC:
                extent, alignment = node.attributes
                if alignment > 16:
                    return None  # the frame base is only 16-byte aligned
                stack_storage.append((ValueRef.node_result(block_index, node_index), extent, alignment))
    stack_values = {value for value, _extent, _alignment in stack_storage}

    # Block parameters proven nonzero by every incoming edge: the edge is the
    # taken side of ``x != 0`` (or not-taken side of ``x == 0``) and passes x.
    incoming: dict[int, list[tuple[int, int, tuple[ValueRef, ...]]]] = {}
    for source, block in enumerate(graph.blocks):
        for edge_index, (target_block, arguments) in enumerate(block.terminator.edges):
            incoming.setdefault(target_block, []).append((source, edge_index, arguments))

    def edge_proves_nonzero(source: int, edge_index: int, arguments: tuple[ValueRef, ...], parameter: int) -> bool:
        terminator = graph.blocks[source].terminator
        condition = terminator.values[0] if terminator.kind == TerminatorKind.CONDITIONAL_BRANCH else None
        if condition is None or condition.tag != 1 or condition.block != source:
            return False
        compare = graph.blocks[source].nodes[condition.index]
        if compare.operation != Operation.INT_COMPARE or parameter >= len(arguments):
            return False
        tested, other = compare.operands
        if constants.get(other) != 0:
            tested, other = other, tested
        kind = IntCompare(compare.attributes[0])
        taken = (kind == IntCompare.NE and edge_index == 0) or (kind == IntCompare.EQ and edge_index == 1)
        return constants.get(other) == 0 and taken and arguments[parameter] == tested

    nonzero_parameters = {
        block_index: {
            ValueRef.parameter(block_index, parameter)
            for parameter in range(len(block.parameters))
            if block_index != graph.entry and incoming.get(block_index)
            and all(edge_proves_nonzero(*edge, parameter) for edge in incoming[block_index])
        }
        for block_index, block in enumerate(graph.blocks)
    }

    # Upper bounds of integer values, enough to prove index arithmetic in range.
    definition = {ValueRef.node_result(b, i): node for b, block in enumerate(graph.blocks) for i, node in enumerate(block.nodes)}

    def maximum(value: ValueRef, depth: int = 0) -> int | None:
        if value in constants:
            return constants[value]
        node = definition.get(value)
        if node is None or depth > 8 or value not in widths:
            return None
        limit = (1 << widths[value]) - 1
        left = node.operands[0] if node.operands else None
        if node.operation == Operation.UDIV and constants.get(node.operands[1]):
            bound = maximum(left, depth + 1)
            return (limit if bound is None else bound) // constants[node.operands[1]]
        if node.operation == Operation.BIT_AND:
            bounds = [b for b in (maximum(left, depth + 1), maximum(node.operands[1], depth + 1)) if b is not None]
            return min(bounds) if bounds else limit
        if node.operation == Operation.MUL_WRAP and constants.get(node.operands[1]) is not None:
            bound = maximum(left, depth + 1)
            return None if bound is None or bound * constants[node.operands[1]] > limit else bound * constants[node.operands[1]]
        if node.operation in (Operation.INT_TRUNCATE, Operation.INT_ZERO_EXTEND):
            bound = maximum(left, depth + 1)
            return limit if bound is None else min(bound, limit)
        return None

    def multiple_of(value: ValueRef, factor: int) -> bool:
        node = definition.get(value)
        if value in constants:
            return constants[value] % factor == 0
        return node is not None and node.operation == Operation.MUL_WRAP and constants.get(node.operands[1], 1) % factor == 0

    def proven_rebase(node) -> bool:
        """``pointer_rebase(view, pointer_address(view) + offset)`` with offset provably in range and aligned."""
        view, address = node.operands
        add = definition.get(address)
        if add is None or add.operation != Operation.ADD_WRAP:
            return False
        for base, offset in (add.operands, add.operands[::-1]):
            exposed = definition.get(base)
            if exposed is not None and exposed.operation == Operation.POINTER_ADDRESS and exposed.operands[0] == view:
                span = pointer_extent_from_graph(graph, view, resolve) - node.attributes[0]
                bound = maximum(offset)
                alignment = _decode_pointer_type(resolve(node.results[0]), resolve)[2]
                return bound is not None and bound <= span and multiple_of(offset, alignment)
        return False

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

    # A branch on an OR tree of ``x == c`` tests of one bits<32> value against
    # constants spanning at most 63 values becomes one bit test against a mask.
    membership: dict[int, tuple[ValueRef, int, int, frozenset[int]]] = {}
    for block_index, block in enumerate(graph.blocks):
        terminator = block.terminator
        if terminator.kind != TerminatorKind.CONDITIONAL_BRANCH or block_index in fused:
            continue
        condition = terminator.values[0]
        if condition.tag != 1 or condition.block != block_index or block.nodes[condition.index].operation != Operation.BIT_OR:
            continue
        counts = Counter(operand for node in block.nodes for operand in node.operands)
        counts.update(value for _target, arguments in terminator.edges for value in arguments)
        if counts[condition]:
            continue
        tree, tests, pending = set(), [], [condition.index]
        while pending and tests is not None:
            index = pending.pop()
            node = block.nodes[index]
            tree.add(index)
            if node.operation == Operation.BIT_OR and all(operand.tag == 1 and operand.block == block_index and counts[operand] == 1 for operand in node.operands):
                pending.extend(operand.index for operand in node.operands)
            elif node.operation == Operation.INT_COMPARE and IntCompare(node.attributes[0]) == IntCompare.EQ and node.operands[1] in constants and node.operands[0] not in constants:
                tests.append((node.operands[0], constants[node.operands[1]] & 0xFFFFFFFF))
            else:
                tests = None
        if tests is None or len(tests) < 3 or len({subject for subject, _value in tests}) != 1 or widths.get(tests[0][0]) != 32:
            continue
        low = min(value for _subject, value in tests)
        if max(value for _subject, value in tests) - low > 62:
            continue
        mask = sum({1 << (value - low) for _subject, value in tests})
        membership[block_index] = (tests[0][0], low, mask, frozenset(tree))

    # Values used in a block other than the one defining them live in a home slot.
    # A constant ``address_offset`` used only as the address of plain loads and
    # stores folds into their displacement: no register copy, and the base
    # pointer carries the liveness (``[base + disp]``).
    memory_address_uses: dict[ValueRef, int] = {}
    other_uses: set[ValueRef] = set()
    for block in graph.blocks:
        for node in block.nodes:
            for position, operand in enumerate(node.operands):
                plain = node.operation in (Operation.LOAD_BITS_LE, Operation.RAW_LOAD_BITS_LE, Operation.STORE_BITS_LE) and position == 0
                if plain:
                    memory_address_uses[operand] = memory_address_uses.get(operand, 0) + 1
                else:
                    other_uses.add(operand)
        other_uses.update(block.terminator.values)
        other_uses.update(value for _target, arguments in block.terminator.edges for value in arguments)
    folded: dict[ValueRef, tuple[ValueRef, int]] = {}
    for block_index, block in enumerate(graph.blocks):
        for node_index, node in enumerate(block.nodes):
            value = ValueRef.node_result(block_index, node_index)
            if node.operation == Operation.ADDRESS_OFFSET and memory_address_uses.get(value) and value not in other_uses and node.attributes[0] < 1 << 31:
                folded[value] = (node.operands[0], node.attributes[0])

    def through_fold(value: ValueRef) -> ValueRef:
        return folded[value][0] if value in folded else value

    # Borrowed views a call gives back keep the passed pointer (ADR-101): the
    # result is a copy of the operand, which therefore stays live across the call.
    call_aliases: dict[ValueRef, ValueRef] = {}
    for block_index, block in enumerate(graph.blocks):
        for node_index, node in enumerate(block.nodes):
            if node.operation == Operation.CALL_DIRECT:
                for result_index, parameter_index in borrowed_view_returns(node.operand_types, node.results, resolve).items():
                    call_aliases[ValueRef.node_result(block_index, node_index, result_index)] = node.operands[parameter_index]
    own_elided = borrowed_view_returns(parameter_types, return_types, resolve)

    def with_aliases(value: ValueRef) -> tuple[ValueRef, ...]:
        return (value, call_aliases[value]) if value in call_aliases else (value,)

    uses_by_block: dict[int, dict[ValueRef, tuple[int, ...]]] = {}
    homes: list[ValueRef] = []
    for block_index, block in enumerate(graph.blocks):
        uses: dict[ValueRef, list[int]] = {}
        position = len(block.nodes)
        for node_index, node in enumerate(block.nodes):
            use_position = position if fused.get(block_index) == node_index or node_index in membership.get(block_index, (None, 0, 0, frozenset()))[3] else node_index
            for operand in (item for value in map(through_fold, node.operands) for item in with_aliases(value)):
                if operand in widths:
                    uses.setdefault(operand, []).append(use_position)
            if node.operation == Operation.CALL_DIRECT:  # aliased operands are read again after the call
                for result, operand in call_aliases.items():
                    if result.block == block_index and result.index == node_index and operand in widths:
                        uses.setdefault(operand, []).append(node_index + 1)
        for value in (item for value in (*block.terminator.values, *(value for _target, arguments in block.terminator.edges for value in arguments)) for item in with_aliases(value)):
            if value in widths:
                uses.setdefault(value, []).append(position)
        uses_by_block[block_index] = {value: tuple(sorted(items)) for value, items in uses.items()}
        for value in uses:
            if value.block != block_index and value not in homes and value not in constants and value not in stack_values:
                homes.append(value)
    homes.sort(key=lambda value: (value.tag, value.block, value.index, value.result))
    pinned = _choose_pins(graph, homes, uses_by_block)
    loop_headers = {target for source, block in enumerate(graph.blocks) for target, _arguments in block.terminator.edges if target <= source}
    # Rotation (header duplication) makes the duplicated header's successors
    # the real backward-branch targets, so they are aligned too.
    loop_headers |= {
        target
        for header in tuple(loop_headers)
        if graph.blocks[header].terminator.kind == TerminatorKind.CONDITIONAL_BRANCH
        and len(graph.blocks[header].nodes) <= 2
        and all(node.operation in (Operation.CONSTANT, Operation.INT_COMPARE) for node in graph.blocks[header].nodes)
        for target, _arguments in graph.blocks[header].terminator.edges
        if target > header
    }
    homes = [value for value in homes if value not in pinned]
    allocatable = tuple(
        register
        for register in (*target.argument_registers, target.scratch_registers[0], target.result_register, *CALLEE_SAVED)
        if register not in pinned.values()
    )

    # Win64 foreign calls pass arguments past the fourth on the stack, above
    # the 32-byte shadow space; reserve the largest such outgoing area.
    outgoing = max(
        (
            max(0, sum(1 for cid in node.operand_types if not _is_proof_type(resolve(cid))) - len(target.argument_registers))
            for block in graph.blocks for node in block.nodes
            if windows and node.operation == Operation.CALL_FOREIGN
        ),
        default=0,
    )
    shadow = _SHADOW_SPACE + 8 * outgoing if has_call else 0
    edge_spill_count = max((max(0, len(params) - len(allocatable)) for params in machine_parameters.values()), default=0)
    edge_spill_base = shadow
    home_base = edge_spill_base + edge_spill_count * 8
    home_offset = {value: home_base + index * 8 for index, value in enumerate(homes)}
    stack_offset: dict[ValueRef, int] = {}
    cursor = home_base + len(homes) * 8
    for value, extent, alignment in stack_storage:
        cursor = _align(cursor, alignment)
        stack_offset[value] = cursor
        cursor += extent
    dynamic_spill_base = _align(cursor, 8)

    def width_bytes(value: ValueRef) -> int:
        return 8 if widths[value] > 32 else 4

    def duplicable(target_block: int) -> bool:
        """A header that only tests and branches can be copied into a jumping predecessor (loop rotation)."""
        header = graph.blocks[target_block]
        return (
            header.terminator.kind == TerminatorKind.CONDITIONAL_BRANCH and len(header.nodes) <= 2
            and all(node.operation in (Operation.CONSTANT, Operation.INT_COMPARE) for node in header.nodes)
        )

    def lower_block(block_index: int, assembler: _Assembler | None, ranges: list | None, used_registers: set[int], epilogue: bytes, stubs: list, traps: dict, copy_tag: str = "", copy_following: int | None = None) -> int:
        """Lower one block; with ``copy_tag`` emit an inline copy (no label) followed by ``copy_following``."""
        following = copy_following if copy_tag else block_index + 1
        block = graph.blocks[block_index]
        uses = uses_by_block[block_index]
        nonzero = nonzero_parameters[block_index]
        # Register hints: a value of this block passed once on an edge prefers
        # the target parameter's register, which saves the edge copy.
        hint: dict[str, ValueRef | None] = {"value": None}
        edge_hints: dict[ValueRef, int] = {}
        edge_uses = Counter(value for _target, arguments in block.terminator.edges for value in arguments)
        for target_block, arguments in block.terminator.edges:
            for index, value in enumerate(machine_parameters[target_block]):
                argument = arguments[value.index]
                if argument.tag == 1 and argument.block == block_index and edge_uses[argument] == 1 and value not in pinned and index < len(allocatable):
                    edge_hints[argument] = allocatable[index]
        last_use = {value: positions[-1] for value, positions in uses.items()}
        register_for: dict[ValueRef, int] = {}
        value_for_register: dict[int, ValueRef] = {}
        spill_offset: dict[ValueRef, int] = {value: home_offset[value] for value in uses if value.block != block_index and value in home_offset}
        spill_id: dict[ValueRef, int] = {}
        free_spills: list[int] = []
        state = {"next": 0, "max": 0}
        capture: list[bytearray] = []  # edge copies are measured before choosing the branch layout
        checked: set[tuple[ValueRef, ValueRef, int]] = set()  # proven in-bounds (pointer, index, maximum)

        def emit(data: bytes) -> None:
            if capture:
                capture[-1] += data
            elif assembler is not None:
                assembler.emit(data)

        def jump(opcode: bytes, label: str) -> None:
            if assembler is not None:
                assembler.relative(opcode, label)

        def label(name: str) -> None:
            if assembler is not None:
                assembler.label(name)

        def trap_if(condition_code: int, trap: bytes) -> None:
            """Jump to the shared out-of-line stub executing ``trap`` when the condition holds."""
            jump(b"\x0f" + bytes((condition_code,)), traps.setdefault(trap, f"trap-{len(traps)}"))

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

        def consumable(value: ValueRef, position: int) -> bool:
            """Whether the value's register may become the result register here."""
            return last_use.get(value) == position and value not in pinned

        def spill(value: ValueRef, keep: bool = False) -> None:
            register = register_for[value]
            if value in constants or value in pinned or value in stack_offset:  # rematerialized on demand, never stored
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
            preferred = edge_hints.get(hint["value"])
            if preferred is not None and preferred not in value_for_register and preferred not in excluded:
                return preferred  # the result goes straight into its successor's parameter register
            for register in allocatable:
                if register not in value_for_register and register not in excluded:
                    return register
            candidates = [value for value, register in register_for.items() if value not in protected and value not in pinned and register not in excluded]
            if not candidates:
                fail("XAX.NATIVE.REGISTER_PRESSURE", graph_object.cid.hex(), "NATIVE-SPILLABLE-REGISTER", "one non-protected live value", len(protected))
            victim = max(candidates, key=lambda value: (next_use(value, position), register_for[value], value.tag, value.block, value.index, value.result))
            register = register_for[victim]
            spill(victim)
            return register

        def ensure(value: ValueRef, position: int, protected: frozenset | set = frozenset(), excluded: tuple[int, ...] = ()) -> int:
            if value in pinned and pinned[value] not in excluded:
                bind(value, pinned[value])
                return pinned[value]
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
            if value in stack_offset:
                register = acquire(position, protected, excluded)
                emit(_lea(register, 4, stack_offset[value]))  # lea reg, [rsp + storage]
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
            if value in pinned and register != pinned[value]:
                emit(_move_register(pinned[value], register, 64))
                register = pinned[value]
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
            if consumable(source, position):
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
            if value in pinned:
                return "reg", pinned[value]
            if value in register_for:
                return "reg", register_for[value]
            if value in constants:
                return "const", constants[value]
            if value in stack_offset:
                return "stack", stack_offset[value]
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
                elif kind == "stack":
                    emit(_lea(destination, 4, source))

        def emit_startup_read(name: bytes, extent: int, prefix: str) -> None:
            """Inline ``linux-x86_64-startup-v1`` read (ADR-094); result in rax.

            At process entry RSP pointed at argc; the entry frame has no pushes,
            so that address is RSP + frame size.  Uses only volatile registers.
            """
            labels = iter(f"{prefix}-{index}" for index in range(16))

            def loop_until_zero(test: bytes, step: bytes) -> None:
                top, done = next(labels), next(labels)
                label(top); emit(test); jump(b"\x0f\x84", done); emit(step); jump(b"\xe9", top); label(done)

            def environment_count() -> None:  # rsi = &envp[0]; rcx = envc
                emit(_load_exact(RAX, _SCRATCH, 0, 8))
                emit(bytes.fromhex("498d74c310"))  # lea rsi, [r11 + rax*8 + 16]
                emit(bytes.fromhex("31c9"))  # xor ecx, ecx
                loop_until_zero(bytes.fromhex("48833cce00"), bytes.fromhex("4883c101"))  # cmp [rsi+rcx*8], 0 / add rcx, 1

            def string_length_and_copy() -> None:  # rsi = string; rax = length, or bytes copied to rdx when extent
                emit(bytes.fromhex("31c0"))
                loop_until_zero(bytes.fromhex("803c0600"), bytes.fromhex("4883c001"))  # cmp byte [rsi+rax], 0 / add rax, 1
                if extent:
                    fits = next(labels)
                    emit(bytes.fromhex("4889c1"))  # mov rcx, rax
                    emit(_cmp_imm32(1, extent)); jump(b"\x0f\x86", fits)
                    emit(b"\xb9" + extent.to_bytes(4, "little"))  # mov ecx, extent
                    label(fits)
                    emit(bytes.fromhex("4889c8"))  # mov rax, rcx: the copy returns the copied byte count
                    emit(_move_register(RDI, RDX, 64) + b"\xf3\xa4")  # rep movsb

            emit(_lea(_SCRATCH, 4, startup_frame["size"]))  # r11 = &argc
            if name == b"argc":
                emit(_load_exact(RAX, _SCRATCH, 0, 8))
            elif name in (b"arg_length", b"arg_copy"):
                emit(bytes.fromhex("493b3b")); trap_if(0x83, b"\x0f\x0b")  # cmp rdi, [r11]; index >= argc traps
                emit(bytes.fromhex("498b74fb08"))  # mov rsi, [r11 + rdi*8 + 8]
                string_length_and_copy()
            elif name == b"envc":
                environment_count()
                emit(bytes.fromhex("4889c8"))  # mov rax, rcx
            elif name in (b"env_length", b"env_copy"):
                environment_count()
                emit(bytes.fromhex("4839cf")); trap_if(0x83, b"\x0f\x0b")  # cmp rdi, rcx; index >= envc traps
                emit(bytes.fromhex("488b34fe"))  # mov rsi, [rsi + rdi*8]
                string_length_and_copy()
            elif name == b"auxv_value":
                environment_count()
                emit(bytes.fromhex("488d74ce08"))  # lea rsi, [rsi + rcx*8 + 8]: first auxv pair
                top, absent, found, done = next(labels), next(labels), next(labels), next(labels)
                label(top)
                emit(bytes.fromhex("488b06")); emit(bytes.fromhex("4885c0")); jump(b"\x0f\x84", absent)  # AT_NULL ends
                emit(bytes.fromhex("4839f8")); jump(b"\x0f\x84", found)  # cmp rax, rdi
                emit(bytes.fromhex("4883c610")); jump(b"\xe9", top)
                label(absent); emit(bytes.fromhex("31c0")); jump(b"\xe9", done)
                label(found); emit(bytes.fromhex("488b4608"))  # mov rax, [rsi + 8]
                label(done)
            else:
                fail("XAX.NATIVE.STARTUP", graph_object.cid.hex(), "LINUX-STARTUP-NAME", "argc|arg_length|arg_copy|envc|env_length|env_copy|auxv_value", name.decode("ascii", "replace"))

        def emit_compare(position: int, left: ValueRef, right: ValueRef) -> None:
            value = immediate(right, widths[left])
            left_register = ensure(left, position)
            if value == 0:
                emit(_test_register(left_register, widths[left]))  # same flags as cmp with zero
            elif value is not None:
                emit(_group1_immediate(None, left_register, value, widths[left]))
            else:
                right_register = ensure(right, position, {left})
                emit(_cmp_registers(left_register, right_register, widths[left]))

        def after_call(position: int, operands: tuple[ValueRef, ...]) -> None:
            for value in tuple(register_for):
                if value not in pinned:
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
                if index < len(allocatable) or destination in pinned:
                    continue
                destination_offset = edge_spill_base + (index - len(allocatable)) * 8
                kind, source_location = location(source)
                if kind == "reg":
                    emit(_store(source_location, destination_offset, 8))
                elif kind in ("const", "stack"):
                    emit(_load_constant(_SCRATCH, source_location) if kind == "const" else _lea(_SCRATCH, 4, source_location))
                    emit(_store(_SCRATCH, destination_offset, 8))
                elif source_location != destination_offset:
                    emit(_load(_SCRATCH, source_location, width_bytes(source)))
                    emit(_store(_SCRATCH, destination_offset, 8))
            moves, delayed = [], []
            for source, index, destination in pairs:
                if destination in pinned:
                    register = pinned[destination]
                elif index < len(allocatable):
                    register = allocatable[index]
                else:
                    continue
                kind, source_location = location(source)
                if kind == "reg":
                    moves.append((register, source_location, widths[destination]))
                else:
                    delayed.append((register, kind, source_location, width_bytes(source)))
            parallel_moves(moves)
            for register, kind, where, width in delayed:
                emit(_load_constant(register, where) if kind == "const" else _lea(register, 4, where) if kind == "stack" else _load(register, where, width))

        def edge_code(target_block: int, arguments: tuple[ValueRef, ...]) -> bytes:
            capture.append(bytearray())
            copy_edge(target_block, arguments)
            return bytes(capture.pop())

        def goto(target_block: int) -> None:
            if target_block != following:
                jump(b"\xe9", f"block-{target_block}")

        def continue_to(target_block: int) -> None:
            """Jump to ``target_block``, or run a copy of it here when it only tests and branches."""
            if not copy_tag and target_block not in (following, block_index) and duplicable(target_block):
                # The header's entry state is canonical (parameters in their fixed
                # registers), so its test-and-branch can run here instead of a jump.
                state["max"] = max(state["max"], lower_block(target_block, assembler, None, used_registers, epilogue, stubs, traps, f"-from{block_index}", following))
            else:
                goto(target_block)

        if not copy_tag:
            if assembler is not None and block_index in loop_headers:
                assembler.emit(_nop_padding(-len(assembler.code) % LOOP_ALIGNMENT))
            label(f"block-{block_index}")
        for index, value in enumerate(machine_parameters[block_index]):
            if value in pinned:
                bind(value, pinned[value])  # edges write pinned parameters directly
            elif index < len(allocatable):
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
            if block_index in membership and node_index in membership[block_index][3]:
                continue  # emitted as a bit test by the terminator
            start = len(assembler.code) if assembler is not None else 0
            result = ValueRef.node_result(block_index, node_index)
            hint["value"] = result
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
                if consumable(left, node_index) and left != right:
                    destination, source = left_register, right_register
                    unbind(left)
                elif consumable(right, node_index) and operation in _COMMUTATIVE and left != right:
                    destination, source = right_register, left_register
                    unbind(right)
                else:
                    destination, source = acquire(node_index, {left, right}), right_register
                    emit(_move_register(destination, left_register, width))
                # Narrow values stay zero-extended: compute at 32 bits and mask
                # only when the operation can carry out of the width.
                emit(_register_arithmetic(operation, destination, source, 64 if width == 64 else 32))
                if width < 32 and operation not in (Operation.BIT_AND, Operation.BIT_OR, Operation.BIT_XOR):
                    emit(_and_immediate(destination, (1 << width) - 1, width=32))
                retire(node_index, left, right)
                define(result, destination)

            elif operation in (Operation.UDIV, Operation.UREM) and _power_of_two(constants.get(node.operands[1])) is not None:
                dividend, divisor = node.operands
                shift = _power_of_two(constants[divisor])
                mask = constants[divisor] - 1
                width = widths[result]
                ensure(dividend, node_index)
                destination = destination_for(node_index, dividend, set())
                if operation == Operation.UDIV:
                    if shift:
                        emit(_shift_immediate(False, destination, shift, width))
                elif mask < (1 << 31):
                    emit(_group1_immediate(Operation.BIT_AND, destination, mask, width))
                elif mask == 0xFFFFFFFF:
                    emit(_move_register(destination, destination, 32))
                else:
                    emit(_load_constant(_SCRATCH, mask))
                    emit(_register_arithmetic(Operation.BIT_AND, destination, _SCRATCH, width))
                retire(node_index, dividend, divisor)
                define(result, destination)

            elif operation in (Operation.UDIV, Operation.UREM):
                dividend, divisor = node.operands
                width = widths[result]
                divisor_register = ensure(divisor, node_index, {dividend}, excluded=(RAX, RDX))
                if (_constant_value(graph, divisor, resolve) or 0) == 0:
                    emit(_test_register(divisor_register, width))
                    trap_if(0x84, _immediate(RAX, TrapReason.INTEGER_DIVIDE_BY_ZERO) + b"\x0f\x0b")
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

            elif operation in (Operation.CONSTANT, Operation.STACK_ALLOC, Operation.STACK_END, Operation.LINK_TARGET):
                pass  # constants and stack pointers are rematerialized at each use; lifetimes and link declarations erase

            elif operation == Operation.CALL_INDIRECT:
                callee, *arguments = machine_operands
                place_arguments(node_index, (*arguments, callee), (*target.argument_registers[: len(arguments)], RAX))
                emit(b"\xff\xd0")  # call rax
                after_call(node_index, machine_operands)
                results = [ValueRef.node_result(block_index, node_index, index) for index, cid in enumerate(node.results) if not _is_proof_type(resolve(cid))]
                if results:
                    define(results[0], RAX)

            elif operation == Operation.INT_COMPARE and fused.get(block_index) == node_index:
                pass  # emitted as cmp+jcc by the terminator

            elif operation == Operation.INT_COMPARE:
                left, right = node.operands
                emit_compare(node_index, left, right)
                retire(node_index, left, right)
                register = acquire(node_index, {left, right})
                emit(_setcc_register(IntCompare(node.attributes[0]), register))
                define(result, register)

            elif operation == Operation.ROTATE_RIGHT:
                source = node.operands[0]
                ensure(source, node_index)
                register = destination_for(node_index, source, set())
                amount = node.attributes[0]
                if amount:
                    emit(_rex(widths[result] > 32, 0, register) + b"\xc1" + bytes((0xC8 | (register & 7), amount)))  # ror r, imm8
                retire(node_index, source)
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

            elif operation == Operation.ADDRESS_OFFSET and result in folded:
                retire(node_index, node.operands[0])  # folded into the loads/stores that use it

            elif operation == Operation.ADDRESS_OFFSET:
                source = node.operands[0]
                ensure(source, node_index)
                register = destination_for(node_index, source, set())
                if node.attributes[0]:
                    emit(_lea(register, register, node.attributes[0]))
                retire(node_index, source)
                define(result, register)

            elif operation == Operation.FUNCTION_ADDRESS:
                register = acquire(node_index)
                if assembler is not None:
                    assembler.address(register, code_address_label(node, resolve))  # lea reg, [rip + function or its entry adapter]
                define(result, register)

            elif operation == Operation.POINTER_ADDRESS:
                # Pointers are already addresses in registers on this path.
                if widths[result] != 64:
                    return -1
                source = node.operands[0]
                ensure(source, node_index)
                register = destination_for(node_index, source, set())
                retire(node_index, source)
                define(result, register)

            elif operation == Operation.POINTER_REBASE:
                # ADR-092: trap unless view <= address <= view + span and the
                # distance is a multiple of the result alignment.
                view, address = node.operands
                span = pointer_extent_from_graph(graph, view, resolve) - node.attributes[0]
                alignment = _decode_pointer_type(resolve(node.results[0]), resolve)[2]
                if widths[address] != 64 or span >= 1 << 31:
                    return -1
                if proven_rebase(node):
                    # Value ranges prove the check (OI-38 range elimination): the result is the address.
                    ensure(address, node_index)
                else:
                    base = ensure(view, node_index)
                    address_register = ensure(address, node_index, {view})
                    emit(_move_register(_SCRATCH, address_register, 64))
                    emit(_register_arithmetic(Operation.SUB_WRAP, _SCRATCH, base, 64))
                    # One unsigned compare checks both: rotating right by log2(alignment)
                    # moves any misaligned low bits to the top, above every valid quotient.
                    shift = alignment.bit_length() - 1
                    if shift:
                        emit(_rotate_right_immediate(_SCRATCH, shift))
                    emit(_cmp_imm32(_SCRATCH, span >> shift))
                    trap_if(0x87, b"\x0f\x0b")
                register = destination_for(node_index, address, {view})
                retire(node_index, view, address)
                define(result, register)

            elif operation == Operation.LINK_FOLLOW:
                # ADR-097: a link is null or a record start of the view's
                # storage, so only null needs a (cold) trap.
                link = node.operands[1]
                link_register = ensure(link, node_index, {node.operands[0]})
                if link not in nonzero:
                    emit(_test_register(link_register, 64))
                    trap_if(0x84, b"\x0f\x0b")
                register = destination_for(node_index, link, set())
                retire(node_index, *node.operands)
                define(result, register)

            elif operation == Operation.HEAP_VIEW:
                source = node.operands[0]
                source_register = ensure(source, node_index)
                emit(_test_register(source_register, 64))
                trap_if(0x84, b"\x0f\x0b")
                register = destination_for(node_index, source, set())
                retire(node_index, source)
                define(result, register)

            elif operation in _MEMORY:
                if operation == Operation.STACK_ALLOC:  # pragma: no cover - excluded by eligibility
                    return -1
                pointer, displacement = folded.get(node.operands[0], (node.operands[0], 0))
                base = ensure(pointer, node_index)
                size = node.attributes[0]
                if operation in (Operation.LOAD_BITS_LE, Operation.RAW_LOAD_BITS_LE):
                    hinted = edge_hints.get(result)
                    if consumable(pointer, node_index) and (hinted is None or hinted == base or hinted in value_for_register):
                        register = base  # the base dies here; load into it (``mov r, [r + d]``)
                        unbind(pointer)
                    else:
                        register = acquire(node_index, {pointer})
                    emit(_load_exact(register, base, displacement, size))
                    retire(node_index, pointer)
                    define(result, register)
                elif operation == Operation.STORE_BITS_LE:
                    value = node.operands[1]
                    value_register = ensure(value, node_index, {pointer})
                    emit(_store_exact(value_register, base, displacement, size))
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
                        emit(_cmp_imm32(index, maximum))
                        trap_if(0x87, b"\x0f\x0b")  # ja: unsigned index above the last valid offset
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
                results = [
                    ValueRef.node_result(block_index, node_index, index) for index, cid in enumerate(node.results)
                    if not _is_proof_type(resolve(cid)) and ValueRef.node_result(block_index, node_index, index) not in call_aliases
                ]
                if results:
                    define(results[0], RAX)
                for alias, operand in call_aliases.items():
                    if alias.block == block_index and alias.index == node_index:
                        source = ensure(operand, node_index + 1, {results[0]} if results else set())
                        register = acquire(node_index + 1, {operand, *results})
                        emit(_move_register(register, source, 64))
                        define(alias, register)

            elif operation == Operation.CALL_FOREIGN:
                declaration = decode_foreign_function(node.entity)
                results = [ValueRef.node_result(block_index, node_index, index) for index, cid in enumerate(node.results) if not _is_proof_type(resolve(cid))]
                owned = (WIN64_C_ABI,) if windows else (SYSV_X86_64_C_ABI, LINUX_X86_64_SYSCALL_ABI, LINUX_X86_64_STARTUP_ABI)
                if declaration.abi not in owned:
                    fail("XAX.FOREIGN.ABI", graph_object.cid.hex(), "NATIVE-FOREIGN-ABI", [abi.decode() for abi in owned], declaration.abi.decode("ascii", "replace"))
                if declaration.abi == WIN64_C_ABI:
                    # Win64: integer arguments in rcx, rdx, r8, r9; the frame
                    # reserves the 32-byte shadow space for every call.
                    registers = len(target.argument_registers)
                    for position, operand in enumerate(machine_operands[registers:]):
                        slot = _SHADOW_SPACE + 8 * position  # stack arguments sit above the shadow space
                        kind, where = location(operand)
                        if kind == "reg":
                            emit(_store(where, slot, 8))
                        else:
                            emit(_load_constant(_SCRATCH, where) if kind == "const" else _lea(_SCRATCH, 4, where) if kind == "stack" else _load(_SCRATCH, where, width_bytes(operand)))
                            emit(_store(_SCRATCH, slot, 8))
                    place_arguments(node_index, machine_operands[:registers], target.argument_registers)
                    if assembler is not None:
                        assembler.call_import(node.entity.cid)
                elif declaration.abi == SYSV_X86_64_C_ABI:
                    require_sysv_profile(target, graph_object)
                    if len(machine_operands) > len(_SYSV_ARGUMENT_REGISTERS) or len(results) > 1 or not all(
                        _sysv_integer_class(resolve, cid) for cid in (*node.operand_types, *node.results) if not _is_proof_type(resolve(cid))
                    ):
                        return -1  # SSE-class values use the frame path, which also rejects stack arguments
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
                            emit(_load_constant(register, item) if item >= 0 else _immediate(register, item))
                    emit(b"\xb8" + number.to_bytes(4, "little") + b"\x0f\x05")
                    if declaration.allocator is not None:
                        emit(b"\x48\x3d\x01\xf0\xff\xff\x72\x02\x31\xc0")
                elif declaration.abi == LINUX_X86_64_STARTUP_ABI:
                    if not process_entry:
                        fail("XAX.NATIVE.STARTUP", graph_object.cid.hex(), "LINUX-STARTUP-PROCESS-ENTRY", "process entry function", "called function")
                    extent = pointer_extent_from_graph(graph, machine_operands[1], resolve) if declaration.name.endswith(b"_copy") else 0
                    place_arguments(node_index, machine_operands, (RDI, RDX)[: len(machine_operands)])
                    emit_startup_read(declaration.name, extent, f"startup-{block_index}-{node_index}")
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
            values = [value for index, value in enumerate(terminator.values) if value in widths and index not in own_elided]
            if values:
                kind, where = location(values[0])
                if kind == "reg":
                    if where != RAX:
                        emit(_move_register(RAX, where, 64))
                elif kind == "const":
                    emit(_load_constant(RAX, where))
                elif kind == "stack":
                    emit(_lea(RAX, 4, where))
                else:
                    emit(_load(RAX, where, width_bytes(values[0])))
            else:
                emit(b"\x31\xc0")
            emit(epilogue)
        elif terminator.kind == TerminatorKind.BRANCH:
            target_block, arguments = terminator.edges[0]
            emit(edge_code(target_block, arguments))
            continue_to(target_block)
        elif terminator.kind == TerminatorKind.CONDITIONAL_BRANCH:
            condition = terminator.values[0]
            if block_index in fused:
                compare = block.nodes[fused[block_index]]
                emit_compare(position, *compare.operands)
                if_false = _JUMP_IF_FALSE[IntCompare(compare.attributes[0])]
            elif block_index in membership:
                subject, low, mask, _tree = membership[block_index]
                register = ensure(subject, position)
                temporary = acquire(position, {subject})
                emit(_member_bit_test(register, low, mask, temporary))
                if_false = 0x83  # jnc: the bit is clear
            else:
                register = ensure(condition, position)
                emit(_test_register(register, widths[condition]))
                if_false = 0x84
            (true_block, true_arguments), (false_block, false_arguments) = terminator.edges
            # Edge copies never change allocation state, so measuring them is free.
            true_copies, false_copies = edge_code(true_block, true_arguments), edge_code(false_block, false_arguments)
            if (false_block == following and not false_copies) or (true_block == following and not true_copies):
                # Fall through to the next block; the other edge leaves via a stub when it copies.
                taken, condition_code, copies = (true_block, if_false ^ 1, true_copies) if false_block == following and not false_copies else (false_block, if_false, false_copies)
                destination = f"block-{taken}"
                if copies:
                    destination = f"stub-{block_index}{copy_tag}"
                    stubs.append((destination, copies, taken))
                jump(b"\x0f" + bytes((condition_code,)), destination)
            elif copy_tag and not true_copies:
                # A rotated loop test: branch back into the body, leave on the other edge.
                jump(b"\x0f" + bytes((if_false ^ 1,)), f"block-{true_block}")
                emit(false_copies)
                goto(false_block)
            elif not false_copies:
                jump(b"\x0f" + bytes((if_false,)), f"block-{false_block}")
                emit(true_copies)
                continue_to(true_block)
            elif not true_copies:
                jump(b"\x0f" + bytes((if_false ^ 1,)), f"block-{true_block}")  # jcc condition codes pair by their low bit
                emit(false_copies)
                continue_to(false_block)
            else:
                # Both edges copy: keep the next block inline (it needs no jump),
                # else the edge to the innermost loop header; stub the other.
                def nearness(target: int) -> int:
                    return 1 << 30 if target == following else target if target <= block_index else -1
                if nearness(false_block) > nearness(true_block):
                    inline, inline_copies, stubbed, stubbed_copies, condition_code = false_block, false_copies, true_block, true_copies, if_false ^ 1
                else:
                    inline, inline_copies, stubbed, stubbed_copies, condition_code = true_block, true_copies, false_block, false_copies, if_false
                stub = f"stub-{block_index}{copy_tag}"
                stubs.append((stub, stubbed_copies, stubbed))
                jump(b"\x0f" + bytes((condition_code,)), stub)
                emit(inline_copies)
                continue_to(inline)
        else:
            reason, _ = decode_trap_payload(terminator.payload)
            emit(_immediate(RAX, reason) + b"\x0f\x0b")
        return state["max"]

    # Dry run: spill count and used callee-saved registers, without emission.
    used: set[int] = set()
    plan = [lower_block(index, None, None, used, b"", [], {}) for index in range(len(graph.blocks))]
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

    startup_frame["size"] = frame_size
    assembler = _Assembler()
    for register in saved:
        assembler.emit(_push(register))
    if frame_size:
        assembler.emit(b"\x48\x81\xec" + frame_size.to_bytes(4, "little"))
    # Edges write pinned parameters directly; the function's own arguments
    # arrive in argument registers instead.
    for index, value in enumerate(machine_parameters[graph.entry]):
        if value in pinned:
            assembler.emit(_move_register(pinned[value], allocatable[index], 64))
    if graph.entry:
        assembler.relative(b"\xe9", f"block-{graph.entry}")
    ranges: list[ArtifactSemanticRange] = []
    stubs: list[tuple[str, bytes, int]] = []
    traps: dict[bytes, str] = {}
    for block_index in range(len(graph.blocks)):
        observed = lower_block(block_index, assembler, ranges, set(), epilogue, stubs, traps)
        if observed > spill_count or observed < 0:
            fail("XAX.NATIVE.SPILL_PLAN", graph_object.cid.hex(), "NATIVE-SPILL-PLAN-DETERMINISTIC", spill_count, observed)
    for name, copies, target_block in stubs:
        assembler.label(name)
        assembler.emit(copies)
        assembler.relative(b"\xe9", f"block-{target_block}")
    for trap, name in traps.items():
        assembler.label(name)
        assembler.emit(trap)
    code, calls = assembler.finish()
    return code, calls, tuple(ranges)

