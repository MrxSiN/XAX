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
from xax_ranges import TABLE_OPERATIONS as _TABLE_OPERATIONS, predicate_table as shared_predicate_table, upper_bounds
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
    _modrm_base,
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
# Set-membership values of a subject below this bound use a byte lookup table (ADR-208).
MEMBER_TABLE_LIMIT = 256
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
    """``op r, imm`` for add/or/and/sub/xor (and cmp as digit 7); imm8 when it sign-extends to ``value``."""
    digit = 7 if operation is None else _GROUP1[operation]
    if 0 <= value < 128:
        return _rex(width > 32, 0, register) + b"\x83" + bytes((0xC0 | (digit << 3) | (register & 7), value))
    return _rex(width > 32, 0, register) + b"\x81" + bytes((0xC0 | (digit << 3) | (register & 7),)) + (value & 0xFFFFFFFF).to_bytes(4, "little")


def _compare_immediate(register: int, value: int) -> bytes:
    """64-bit ``cmp r, imm`` for a bound in 0..2^31-1."""
    if not 0 <= value < 1 << 31:
        fail("XAX.NATIVE.MEMORY_ENCODING", "x86_64", "NATIVE-CHECKED-BOUND-ENCODABLE", "0..2^31-1", value)
    return _group1_immediate(None, register, value, 64)


def _scaled_access(opcode: bytes, register: int, base: int, index: int, scale: int, width: int, *, force_rex: bool = False) -> bytes:
    """``[base + index*scale]`` access of 1/2/4/8 bytes, without a displacement when the base allows it."""
    rex = 0x40 | (0x08 if width == 8 else 0) | (0x04 if register >= 8 else 0) | (0x02 if index >= 8 else 0) | (0x01 if base >= 8 else 0)
    prefix = (b"\x66" if width == 2 else b"") + (bytes((rex,)) if rex != 0x40 or force_rex else b"")
    sib = (scale.bit_length() - 1) << 6 | ((index & 7) << 3) | (base & 7)
    if base & 7 == 5:  # rbp/r13 bases need a displacement byte
        return prefix + opcode + bytes((0x44 | ((register & 7) << 3), sib, 0))
    return prefix + opcode + bytes((0x04 | ((register & 7) << 3), sib))


def _memory_operand_instruction(opcode: bytes, register: int, base: int, index: int | None, scale: int, displacement: int, wide: bool) -> bytes:
    """``opcode reg, [base + index*scale + disp]`` (or with no index) for any general registers."""
    rex = 0x40 | (0x08 if wide else 0) | (0x04 if register >= 8 else 0) | (0x02 if index is not None and index >= 8 else 0) | (0x01 if base >= 8 else 0)
    prefix = bytes((rex,)) if rex != 0x40 else b""
    if displacement == 0 and base & 7 != 5:
        mod, tail = 0x00, b""
    elif -128 <= displacement < 128:
        mod, tail = 0x40, displacement.to_bytes(1, "little", signed=True)
    else:
        mod, tail = 0x80, displacement.to_bytes(4, "little", signed=True)
    if index is None and base & 7 != 4:
        return prefix + opcode + bytes((mod | ((register & 7) << 3) | (base & 7),)) + tail
    sib = ((scale.bit_length() - 1) << 6 | ((index & 7) << 3) | (base & 7)) if index is not None else 0x24
    return prefix + opcode + bytes((mod | ((register & 7) << 3) | 4, sib)) + tail


def _scaled_load(register: int, base: int, index: int, scale: int, size: int) -> bytes:
    """Zero-extending load."""
    return _scaled_access({1: b"\x0f\xb6", 2: b"\x0f\xb7", 4: b"\x8b", 8: b"\x8b"}[size], register, base, index, scale, 4 if size < 4 else size)


def _scaled_store(register: int, base: int, index: int, scale: int, size: int) -> bytes:
    if size == 1:
        return _scaled_access(b"\x88", register, base, index, scale, 1, force_rex=4 <= register < 8)
    return _scaled_access(b"\x89", register, base, index, scale, size)


def _scaled_add_immediate(base: int, index: int, scale: int, size: int, value: int) -> bytes:
    """``add size [base + index*scale], imm`` (read-modify-write); 4/8-byte accesses."""
    if 0 <= value < 128:
        return _scaled_access(b"\x83", 0, base, index, scale, size) + bytes((value,))
    return _scaled_access(b"\x81", 0, base, index, scale, size) + (value & 0xFFFFFFFF).to_bytes(4, "little")


def _rotate_right_immediate(register: int, amount: int) -> bytes:
    return _rex(True, 0, register) + b"\xc1" + bytes((0xC0 | (1 << 3) | (register & 7), amount))


def _shift_immediate(left: bool, register: int, amount: int, width: int) -> bytes:
    return _rex(width > 32, 0, register) + b"\xc1" + bytes((0xC0 | ((4 if left else 5) << 3) | (register & 7), amount))


def _imul_immediate(destination: int, source: int, value: int, width: int) -> bytes:
    if 0 <= value < 128:
        return _rex(width > 32, destination, source) + b"\x6b" + bytes((0xC0 | ((destination & 7) << 3) | (source & 7), value))
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

    def copied(value: ValueRef) -> ValueRef | None:
        if value.tag != 1 or value.result:
            return None
        node = graph.blocks[value.block].nodes[value.index]
        return node.operands[0] if node.operation in _COPY else None

    # A copy of a pinned value holds the same bits for the rest of the
    # function, so it shares the source's register instead of taking one.
    pins: dict[ValueRef, int] = {}
    free = list(PINNABLE)
    for value in ranked:
        if copied(value) not in weights and free:
            pins[value] = free.pop(0)
    for value in ranked:
        source = copied(value)
        if source in weights:
            while copied(source) in weights and source not in pins:
                source = copied(source)
            if source in pins:
                pins[value] = pins[source]
            elif free:
                pins[value] = free.pop(0)
    return pins


# Operations a loop header may contain and still be copied into a jumping
# predecessor (rotation): pure, non-trapping-by-construction or shared-stub code.
_ROTATABLE = frozenset({
    Operation.CONSTANT, Operation.INT_COMPARE, *_PURE_BINARY, *_COPY, Operation.INT_TRUNCATE, Operation.ROTATE_RIGHT,
    Operation.ADDRESS_OFFSET, Operation.LOAD_BITS_LE, Operation.CHECKED_LOAD_BITS_LE,
})
_ROTATE_LIMIT = 16


def _rotatable(header) -> bool:
    """A small test-and-branch header that can be copied into a jumping predecessor (loop rotation)."""
    return (
        header.terminator.kind == TerminatorKind.CONDITIONAL_BRANCH and len(header.nodes) <= _ROTATE_LIMIT
        and all(node.operation in _ROTATABLE for node in header.nodes)
    )


def _reachable(graph, start: int) -> set[int]:
    """Blocks reachable from ``start`` (including itself)."""
    seen, stack = set(), [start]
    while stack:
        block = stack.pop()
        if block not in seen:
            seen.add(block)
            stack.extend(target for target, _arguments in graph.blocks[block].terminator.edges)
    return seen


def _block_pressure(graph, machine_parameters, uses_by_block, block_index: int, ignored: frozenset = frozenset()) -> int:
    """Peak number of simultaneously live machine values in a block (an estimate of register demand)."""
    block = graph.blocks[block_index]
    last = {value: positions[-1] for value, positions in uses_by_block[block_index].items() if value not in ignored}
    defined_at = {value: value.index if value.tag == 1 and value.block == block_index else -1 for value in last}
    peak = 0
    for position in range(len(block.nodes) + 1):
        live = sum(1 for value, end in last.items() if defined_at[value] <= position and end > position)
        live += sum(1 for value, end in last.items() if defined_at[value] == position and end <= position)  # a result needs a register at its definition
        peak = max(peak, live)
    return peak


def _loop_parameter_slots(graph, machine_parameters, uses_by_block, homes, pinned, registers: int, entry: int) -> dict[ValueRef, int]:
    """Frame slots for loop pass-through block parameters under register pressure.

    A parameter that its block only forwards on edges, inside a CFG cycle,
    needs no register.  Parameters joined by such forwarding edges share one
    slot (a class); a class is kept only when it is closed inside its
    strongly connected component (every in-component edge into a member
    passes the same class's member, and members are forwarded only to
    members), so in-loop edge copies are no-ops and the slot is written on
    loop entry and read on exit.  Only blocks whose machine parameters plus
    peak in-block temporaries exceed the allocatable registers qualify, so
    loops with free registers keep their values in registers.
    """
    count = len(graph.blocks)
    successors = [tuple(target for target, _arguments in block.terminator.edges) for block in graph.blocks]

    def reachable(start: int) -> set[int]:
        seen, stack = set(), list(successors[start])
        while stack:
            block = stack.pop()
            if block not in seen:
                seen.add(block)
                stack.extend(successors[block])
        return seen

    reach = [reachable(index) for index in range(count)]
    component = [frozenset({index} | {other for other in reach[index] if index in reach[other]}) if index in reach[index] else frozenset() for index in range(count)]

    def pressure(block_index: int) -> int:
        return _block_pressure(graph, machine_parameters, uses_by_block, block_index)

    def forwarded_only(value: ValueRef) -> bool:
        block = graph.blocks[value.block]
        if value in pinned or value in homes or value.block == entry or not component[value.block]:
            return False
        if value in block.terminator.values or any(value in node.operands for node in block.nodes):
            return False
        return value in uses_by_block[value.block]

    candidates = {value for values in machine_parameters.values() for value in values if forwarded_only(value)}
    parent = {value: value for value in candidates}

    def find(value: ValueRef) -> ValueRef:
        while parent[value] != value:
            parent[value] = parent[parent[value]]
            value = parent[value]
        return value

    for source, block in enumerate(graph.blocks):
        for target, arguments in block.terminator.edges:
            for index, argument in enumerate(arguments):
                destination = ValueRef.parameter(target, index)
                if argument in candidates and destination in candidates and argument.block == source:
                    parent[find(argument)] = find(destination)
    classes: dict[ValueRef, list[ValueRef]] = {}
    for value in sorted(candidates, key=lambda item: (item.block, item.index)):
        classes.setdefault(find(value), []).append(value)
    rejected = set()
    member_of: dict[tuple[ValueRef, int], ValueRef] = {}
    for root, members in classes.items():
        if len({member.block for member in members}) != len(members):
            rejected.add(root)
        for member in members:
            member_of[(root, member.block)] = member
    # An edge between two blocks of a class must pass the class member to the
    # class member: then its copy is a no-op and the slot never holds two values.
    for source, block in enumerate(graph.blocks):
        for target, arguments in block.terminator.edges:
            for index, argument in enumerate(arguments):
                destination = ValueRef.parameter(target, index)
                if destination not in candidates:
                    continue
                root = find(destination)
                if (root, source) in member_of and member_of[(root, source)] != argument:
                    rejected.add(root)
    pressured = {index for index in range(count) if component[index] and pressure(index) > registers}
    slots: dict[ValueRef, int] = {}
    for root, members in classes.items():
        if root in rejected:
            continue
        # The slot must serve a loop made only of member blocks (the hot loop);
        # entry and exit copies then run outside it.
        blocks = {member.block for member in members}

        def loops_within(start: int) -> bool:
            seen, stack = set(), [target for target in successors[start] if target in blocks]
            while stack:
                block = stack.pop()
                if block == start:
                    return True
                if block not in seen:
                    seen.add(block)
                    stack.extend(target for target in successors[block] if target in blocks)
            return False

        if not any(block in pressured and loops_within(block) for block in blocks):
            continue
        slot = len(set(slots.values()))
        for member in members:
            slots[member] = slot
    return slots


def compile_register_resident(
    function: SemanticObject,
    graph_object: SemanticObject,
    graph,
    parameter_types: tuple[bytes, ...],
    return_types: tuple[bytes, ...],
    resolve: Callable[[bytes], SemanticObject],
    target: NativeTargetDescription,
    process_entry: bool = False,
    prefetches: dict | None = None,
):
    """Return ``(code, calls, ranges)`` or ``None`` when ineligible.

    ``prefetches`` (ADR-211, ``xax_prefetch``) maps a load result to ``((pointer, scale), ...)``: after that load
    the backend emits ``prefetcht0 [pointer + result * scale]`` for each, and nothing else reads the result.

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

    # Upper bounds of integer values, enough to prove index arithmetic in range (shared with AArch64).
    definition = {ValueRef.node_result(b, i): node for b, block in enumerate(graph.blocks) for i, node in enumerate(block.nodes)}
    maximum = upper_bounds(graph, widths, constants)

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

    # A boolean computed only from one value below MEMBER_TABLE_LIMIT and constants, by at least
    # _TABLE_MIN_OPERATIONS compares/arithmetic nodes whose results have no other use, is read from a
    # byte table instead (ADR-208): the table is the expression evaluated exactly for every value.
    early_uses = Counter(operand for block in graph.blocks for node in block.nodes for operand in node.operands)
    early_uses.update(value for block in graph.blocks for value in block.terminator.values)
    early_uses.update(value for block in graph.blocks for _target, arguments in block.terminator.edges for value in arguments)

    def predicate_table(block_index: int, root: ValueRef) -> tuple[ValueRef, bytes, frozenset[int]] | None:
        return shared_predicate_table(graph, block_index, root, definition, widths, constants, maximum, early_uses)

    branch_tables: dict[int, tuple[ValueRef, bytes, frozenset[int]]] = {}
    for block_index, block in enumerate(graph.blocks):
        terminator = block.terminator
        if terminator.kind != TerminatorKind.CONDITIONAL_BRANCH or block_index in fused:
            continue
        condition = terminator.values[0]
        if condition.tag == 1 and condition.block == block_index and early_uses[condition] == 1:
            found = predicate_table(block_index, condition)
            if found is not None:
                branch_tables[block_index] = found

    # A branch on an OR tree of ``x == c`` tests of one bits<32> value against
    # constants spanning at most 63 values becomes one bit test against a mask.
    membership: dict[int, tuple[ValueRef, int, int, frozenset[int]]] = {}
    for block_index, block in enumerate(graph.blocks):
        terminator = block.terminator
        if terminator.kind != TerminatorKind.CONDITIONAL_BRANCH or block_index in fused or block_index in branch_tables:
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

    # Checked accesses whose index is provably in range need no check (OI-38
    # range elimination).  Such an index ``x * s`` (s = 1/2/4/8, possibly
    # truncated without loss) used only by these accesses folds into the SIB
    # scale, so ``x`` is the only register read.
    use_count = Counter(operand for block in graph.blocks for node in block.nodes for operand in node.operands)
    use_count.update(value for block in graph.blocks for value in block.terminator.values)
    use_count.update(value for block in graph.blocks for _target, arguments in block.terminator.edges for value in arguments)
    checked_access = (Operation.CHECKED_LOAD_BITS_LE, Operation.CHECKED_STORE_BITS_LE)

    def access_proven(node) -> bool:
        bound = maximum(node.operands[1])
        return bound is not None and bound <= pointer_extent_from_graph(graph, node.operands[0], resolve) - node.attributes[0]

    index_uses: Counter = Counter()
    for block in graph.blocks:
        for node in block.nodes:
            if node.operation in checked_access and access_proven(node):
                index_uses[node.operands[1]] += 1
    scaled: dict[ValueRef, tuple[ValueRef, int]] = {}
    erased_index_nodes: set[ValueRef] = set()
    for value, count in index_uses.items():
        if use_count[value] != count or value.tag != 1:
            continue
        node = definition.get(value)
        chain = [value]
        if node is not None and node.operation == Operation.INT_TRUNCATE and maximum(node.operands[0]) is not None and maximum(node.operands[0]) < 1 << 32:
            inner = node.operands[0]
            if use_count[inner] != 1 or inner.tag != 1 or inner.block != value.block:
                continue
            chain.append(inner)
            node = definition.get(inner)
        if node is None or node.operation != Operation.MUL_WRAP or constants.get(node.operands[1]) not in (2, 4, 8) or node.operands[0] in constants:
            continue
        scaled[value] = (node.operands[0], constants[node.operands[1]])
        erased_index_nodes.update(chain)

    # ``store(p, i, load(p, i) + c)`` with a proven index, where the loaded and
    # summed values have no other use, is one ``add [p + i*s], c``.
    read_modify_write: dict[ValueRef, int] = {}  # store node -> constant
    rmw_erased: set[ValueRef] = set()
    for block_index, block in enumerate(graph.blocks):
        for node_index, node in enumerate(block.nodes):
            if node.operation != Operation.CHECKED_STORE_BITS_LE or node.attributes[0] not in (4, 8) or not access_proven(node):
                continue
            pointer, index, total, _memory = node.operands
            add = definition.get(total)
            if add is None or add.operation != Operation.ADD_WRAP or total.block != block_index or use_count[total] != 1:
                continue
            loaded, addend = add.operands if add.operands[1] in constants else add.operands[::-1]
            load = definition.get(loaded)
            if (
                addend not in constants or not _immediate_fits(constants[addend], 32) or constants[addend] >= 1 << 31
                or load is None or load.operation != Operation.CHECKED_LOAD_BITS_LE or loaded.block != block_index
                or load.operands[:2] != (pointer, index) or load.attributes[0] != node.attributes[0] or use_count[loaded] != 1
                or widths.get(loaded) != 8 * node.attributes[0]
                or node.operands[3] != ValueRef.node_result(loaded.block, loaded.index, 1)
            ):
                continue
            read_modify_write[ValueRef.node_result(block_index, node_index)] = constants[addend]
            rmw_erased.update((loaded, total))

    # A value that is an OR tree of ``x == c`` tests (optionally zero-extended)
    # of one value below 2^32 against constants spanning at most 63 values is
    # one bit test (ADR-131 applied to values).  Tests with other uses stay.
    value_tables: dict[ValueRef, tuple[ValueRef, bytes]] = {}
    table_erased: set[ValueRef] = set()
    for block_index, block in enumerate(graph.blocks):
        tree = branch_tables[block_index][2] if block_index in branch_tables else frozenset()
        for node_index in range(len(block.nodes) - 1, -1, -1):
            root = ValueRef.node_result(block_index, node_index)
            if root in table_erased or root not in widths or node_index in tree or block.nodes[node_index].operation not in _TABLE_OPERATIONS:
                continue
            found = predicate_table(block_index, root)
            if found is not None:
                subject, table, indices = found
                value_tables[root] = (subject, table)
                table_erased.update(ValueRef.node_result(block_index, index) for index in indices if index != node_index)
    erased_index_nodes |= table_erased

    member_values: dict[ValueRef, tuple[ValueRef, int, int]] = {}
    member_erased: set[ValueRef] = set()
    for block_index, block in enumerate(graph.blocks):
        for node_index in range(len(block.nodes) - 1, -1, -1):
            root = ValueRef.node_result(block_index, node_index)
            if block.nodes[node_index].operation != Operation.BIT_OR or root in member_erased or root not in widths or root in table_erased or root in value_tables:
                continue
            if block_index in membership and node_index in membership[block_index][3]:
                continue
            tests, internal, leaves, pending = [], [], [], [root]
            while pending and tests is not None:
                value = pending.pop()
                node = definition.get(value) if value.tag == 1 and value.block == block_index and value.result == 0 else None
                if node is None:
                    tests = None
                elif node.operation == Operation.BIT_OR and (value == root or use_count[value] == 1):
                    internal.append(value)
                    pending.extend(node.operands)
                else:
                    chain = [value]
                    if node.operation == Operation.INT_ZERO_EXTEND:
                        inner = node.operands[0]
                        node = definition.get(inner) if inner.tag == 1 and inner.block == block_index and inner.result == 0 else None
                        chain.append(inner)
                    if (
                        node is None or node.operation != Operation.INT_COMPARE or IntCompare(node.attributes[0]) != IntCompare.EQ
                        or node.operands[1] not in constants or node.operands[0] in constants or constants[node.operands[1]] >= 1 << 32
                    ):
                        tests = None
                    else:
                        tests.append((node.operands[0], constants[node.operands[1]]))
                        leaves.append(chain)
            if tests is None or len(tests) < 3 or len({subject for subject, _value in tests}) != 1:
                continue
            subject = tests[0][0]
            bound = maximum(subject)
            low = min(value for _subject, value in tests)
            if bound is None or bound >= 1 << 32 or max(value for _subject, value in tests) - low > 62:
                continue
            member_values[root] = (subject, low, sum({1 << (value - low) for _subject, value in tests}))
            member_erased.update(value for value in internal if value != root)
            for chain in leaves:  # a test with no other use is not computed separately
                if all(use_count[value] == 1 for value in chain):
                    member_erased.update(chain)
    erased_index_nodes |= member_erased

    # A 4/8-byte load whose only use is a compare fused into its block's branch,
    # with no store or call after it in the block, becomes the compare's memory
    # operand (``cmp reg, [mem]``): the load runs at the branch instead.
    compare_load: dict[ValueRef, tuple] = {}  # load result -> (base pointer, index or None, scale, displacement)
    _WRITES = (Operation.STORE_BITS_LE, Operation.CHECKED_STORE_BITS_LE, *_CALLS)
    for block_index, node_index in fused.items():
        block = graph.blocks[block_index]
        left, right = block.nodes[node_index].operands
        for candidate, other in ((left, right), (right, left)):
            if candidate.tag != 1 or candidate.block != block_index or candidate.result or use_count[candidate] != 1 or other == candidate:
                continue
            load = block.nodes[candidate.index]
            size = load.attributes[0] if load.attributes else 0
            if size not in (4, 8) or widths.get(candidate) != 8 * size or other not in widths or immediate(other, widths[candidate]) is not None:
                continue
            if any(node.operation in _WRITES for node in block.nodes[candidate.index + 1:]) or candidate in rmw_erased or candidate in member_erased or candidate in table_erased:
                continue
            if load.operation == Operation.LOAD_BITS_LE:
                base, displacement = folded.get(load.operands[0], (load.operands[0], 0))
                compare_load[candidate] = (base, None, 1, displacement)
            elif load.operation == Operation.CHECKED_LOAD_BITS_LE and access_proven(load):
                index, scale = scaled.get(load.operands[1], (load.operands[1], 1))
                compare_load[candidate] = (load.operands[0], index, scale, 0)
            break

    # An add/sub of an immediate whose only use is one argument of its block's conditional-branch edge is computed
    # on that edge, as ``lea``, instead of on every path (ADR-211): a loop's exit-only ``found + 1`` leaves the loop.
    edge_sunk: dict[ValueRef, tuple[ValueRef, int]] = {}
    for block_index, block in enumerate(graph.blocks):
        terminator = block.terminator
        if terminator.kind != TerminatorKind.CONDITIONAL_BRANCH:
            continue
        edge_arguments = Counter(value for _target, arguments in terminator.edges for value in arguments)
        for node_index, node in enumerate(block.nodes):
            value = ValueRef.node_result(block_index, node_index)
            width = widths.get(value)
            if node.operation not in (Operation.ADD_WRAP, Operation.SUB_WRAP) or width not in (32, 64) or value in erased_index_nodes:
                continue
            left, right = node.operands
            if right not in constants or left in constants or widths.get(left) != width:
                continue
            amount = (constants[right] if node.operation == Operation.ADD_WRAP else -constants[right]) % (1 << width)
            amount = amount - (1 << width) if amount >= 1 << (width - 1) else amount
            if not -(1 << 31) <= amount < 1 << 31:
                continue
            if use_count[value] == 1 and edge_arguments[value] == 1 and value not in terminator.values:
                edge_sunk[value] = (left, amount)
    erased_index_nodes |= set(edge_sunk)

    def operands_of(block_index: int, node_index: int, node) -> tuple[ValueRef, ...]:
        root = ValueRef.node_result(block_index, node_index)
        if root in value_tables:
            return (value_tables[root][0],)
        return (member_values[root][0],) if root in member_values else node.operands

    def through_fold(value: ValueRef) -> ValueRef:
        if value in scaled:
            return scaled[value][0]
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
            if ValueRef.node_result(block_index, node_index) in erased_index_nodes or ValueRef.node_result(block_index, node_index) in rmw_erased:
                continue  # folded into the access that uses it
            if ValueRef.node_result(block_index, node_index) in compare_load:  # read by the branch's compare
                base, index, _scale, _displacement = compare_load[ValueRef.node_result(block_index, node_index)]
                for operand in (base, index):
                    if operand in widths:
                        uses.setdefault(operand, []).append(position)
                continue
            use_position = position if (
                fused.get(block_index) == node_index or node_index in membership.get(block_index, (None, 0, 0, frozenset()))[3]
                or node_index in branch_tables.get(block_index, (None, b"", frozenset()))[2]
            ) else node_index
            for operand in (item for value in map(through_fold, operands_of(block_index, node_index, node)) for item in with_aliases(value)):
                if operand in widths and operand not in rmw_erased and operand not in compare_load:
                    uses.setdefault(operand, []).append(use_position)
            for pointer, _scale in (prefetches or {}).get(ValueRef.node_result(block_index, node_index), ()):
                uses.setdefault(pointer, []).append(node_index)  # read by the prefetches after the load
            if node.operation == Operation.CALL_DIRECT:  # aliased operands are read again after the call
                for result, operand in call_aliases.items():
                    if result.block == block_index and result.index == node_index and operand in widths:
                        uses.setdefault(operand, []).append(node_index + 1)
        for value in (item for value in (*block.terminator.values, *(edge_sunk.get(value, (value,))[0] for _target, arguments in block.terminator.edges for value in arguments)) for item in with_aliases(value)):
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
        if _rotatable(graph.blocks[header])
        for target, _arguments in graph.blocks[header].terminator.edges
        if target > header
    }
    homes = [value for value in homes if value not in pinned]
    allocatable = tuple(
        register
        for register in (*target.argument_registers, target.scratch_registers[0], target.result_register, *CALLEE_SAVED)
        if register not in pinned.values()
    )
    # A 64-bit constant with no imm32 form, used inside a CFG cycle, gets a
    # free pinnable register loaded once in the prologue (loop-invariant
    # hoisting) when every cyclic block using it keeps enough registers; every
    # constant node of that value shares it.
    cyclic_blocks = {index for index in range(len(graph.blocks)) if any(index in _reachable(graph, successor) for successor in (t for t, _a in graph.blocks[index].terminator.edges))}
    wide_uses: dict[int, set[int]] = {}
    for block_index in cyclic_blocks:
        for value in uses_by_block[block_index]:
            if value in constants and not _immediate_fits(constants[value], 64):
                wide_uses.setdefault(constants[value], set()).add(block_index)
    hoisted_constants: dict[int, int] = {}
    for constant in sorted(wide_uses, key=lambda item: (-len(wide_uses[item]), item)):
        free = [register for register in PINNABLE if register in allocatable]
        if not free:
            break
        demand = max(
            _block_pressure(graph, machine_parameters, uses_by_block, block_index, frozenset(constants) | frozenset(
                value for value in machine_parameters[block_index]
                if all(position == len(graph.blocks[block_index].nodes) for position in uses_by_block[block_index].get(value, ()))))
            for block_index in wide_uses[constant]
        )
        if demand > len(allocatable) - 1:
            continue
        register = free[-1]
        hoisted_constants[constant] = register
        allocatable = tuple(item for item in allocatable if item != register)
    for value, constant in constants.items():
        if constant in hoisted_constants:
            pinned[value] = hoisted_constants[constant]

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
    parameter_slot = _loop_parameter_slots(graph, machine_parameters, uses_by_block, homes, pinned, len(allocatable), graph.entry)
    slot_base = home_base + len(homes) * 8
    parameter_slot = {value: slot_base + 8 * slot for value, slot in parameter_slot.items()}
    stack_offset: dict[ValueRef, int] = {}
    cursor = slot_base + 8 * len(set(parameter_slot.values()))
    for value, extent, alignment in stack_storage:
        cursor = _align(cursor, alignment)
        stack_offset[value] = cursor
        cursor += extent
    dynamic_spill_base = _align(cursor, 8)

    def width_bytes(value: ValueRef) -> int:
        return 8 if widths[value] > 32 else 4

    def duplicable(target_block: int) -> bool:
        """A header that only tests and branches can be copied into a jumping predecessor (loop rotation)."""
        return _rotatable(graph.blocks[target_block])

    closed = {"at": 0}  # code length right after the last unconditional transfer
    tables: dict[bytes, str] = {}  # read-only lookup tables placed after the code, by contents

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
                if argument.tag == 1 and argument.block == block_index and edge_uses[argument] == 1 and value not in pinned and value not in parameter_slot and index < len(allocatable):
                    edge_hints[argument] = allocatable[index]
        last_use = {value: positions[-1] for value, positions in uses.items()}
        call_positions = tuple(
            index for index, node in enumerate(block.nodes)
            if node.operation in _CALLS and not (node.operation == Operation.CALL_DIRECT and _is_erased_proof_function(node.entity, resolve))
        )
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
                if opcode == b"\xe9":
                    closed["at"] = len(assembler.code)

        def label(name: str) -> None:
            if assembler is not None:
                assembler.label(name)

        def table_address(table: bytes) -> None:
            """``lea r11, [rip + table]``; the table is placed after the code (ADR-208).  r11 is the scratch register,
            so the subject's register and the destination may coincide."""
            name = tables.setdefault(table, f"table-{len(tables)}")
            if capture:
                fail("XAX.NATIVE.TABLE", function.cid.hex(), "NATIVE-TABLE-NOT-IN-EDGE-COPY", "no table read in edge copies", name)
            if assembler is not None:
                assembler.emit(b"\x4c\x8d\x1d")
                assembler.branches.append((len(assembler.code), name))
                assembler.emit(bytes(4))

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
            value = hint["value"]
            if value is not None and any(position < call < last_use.get(value, -1) for call in call_positions):
                # Live across a call: a callee-saved register keeps it without a spill.
                for register in allocatable:
                    if register in PINNABLE and register not in value_for_register and register not in excluded:
                        return register
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

        def parallel_moves(assignments: list[tuple]) -> None:
            """Register moves ``(dst, src, width[, offset])``; an offset makes the move ``lea dst, [src + offset]``."""
            pending = [(item[0], item[1], item[2], item[3] if len(item) > 3 else 0) for item in assignments]
            pending = [item for item in pending if item[0] != item[1] or item[3]]
            while pending:
                sources = {src for _, src, _, _ in pending}
                safe = next((i for i, (dst, src, _, offset) in enumerate(pending) if dst not in sources or (dst == src and offset and sum(s == dst for _, s, _, _ in pending) == 1)), None)
                if safe is not None:
                    dst, src, width, offset = pending.pop(safe)
                    emit(_rex(width == 64, dst, src) + b"\x8d" + _modrm_base(dst, src, offset) if offset else _move_register(dst, src, 64))
                    continue
                dst, src, width, offset = pending[0]
                emit(_move_register(_SCRATCH, src, 64))
                pending = [(d, _SCRATCH if s == src else s, w, o) for d, s, w, o in pending]

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
            # Values in PINNABLE registers survive every call kind (see the module
            # docstring), so only the volatile ones are stored.
            live_after = sorted(
                (value for value in register_for if last_use.get(value, -1) > position and register_for[value] not in PINNABLE),
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
            if left in compare_load or right in compare_load:
                loaded, other = (left, right) if left in compare_load else (right, left)
                base_value, index_value, scale, displacement = compare_load[loaded]
                base = ensure(base_value, position)
                index = ensure(index_value, position, {base_value}) if index_value is not None else None
                other_register = ensure(other, position, {base_value, *([index_value] if index_value is not None else [])})
                # cmp [mem], reg (0x39) is mem - reg; cmp reg, [mem] (0x3B) is reg - mem.
                opcode = b"\x39" if loaded == left else b"\x3b"
                emit(_memory_operand_instruction(opcode, other_register, base, index, scale, displacement, widths[loaded] == 64))
                return
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
                if value not in pinned and register_for[value] not in PINNABLE:
                    unbind(value)
            for operand in set(operands):
                if last_use.get(operand) == position:
                    release(operand)

        def copy_edge(target_block: int, arguments: tuple[ValueRef, ...]) -> None:
            destinations = machine_parameters[target_block]
            pairs = []
            for index, argument in enumerate(arguments):
                destination = ValueRef.parameter(target_block, index)
                # A parameter the target never reads (not in its block, not elsewhere through a home or pin) needs no copy.
                dead = destination not in uses_by_block[target_block] and destination not in home_offset and destination not in pinned
                if argument in widths and destination in widths and not dead:
                    pairs.append((argument, destinations.index(destination), destination))
            sunk = {}
            for position, (source, index, destination) in enumerate(pairs):
                if source in edge_sunk:
                    operand, amount = edge_sunk[source]
                    sunk[destination] = amount
                    pairs[position] = (operand, index, destination)
            for source, index, destination in pairs:
                if destination in parameter_slot:
                    destination_offset = parameter_slot[destination]
                elif index < len(allocatable) or destination in pinned:
                    continue
                else:
                    destination_offset = edge_spill_base + (index - len(allocatable)) * 8
                kind, source_location = location(source)
                if destination in sunk:
                    emit(_move_register(_SCRATCH, source_location, 64) if kind == "reg" else _load(_SCRATCH, source_location, width_bytes(source)))
                    emit(_rex(widths[destination] == 64, _SCRATCH, _SCRATCH) + b"\x8d" + _modrm_base(_SCRATCH, _SCRATCH, sunk[destination]))
                    emit(_store(_SCRATCH, destination_offset, 8))
                elif kind == "reg":
                    emit(_store(source_location, destination_offset, 8))
                elif kind in ("const", "stack"):
                    emit(_load_constant(_SCRATCH, source_location) if kind == "const" else _lea(_SCRATCH, 4, source_location))
                    emit(_store(_SCRATCH, destination_offset, 8))
                elif source_location != destination_offset:
                    emit(_load(_SCRATCH, source_location, width_bytes(source)))
                    emit(_store(_SCRATCH, destination_offset, 8))
            moves, delayed = [], []
            for source, index, destination in pairs:
                if destination in parameter_slot:
                    continue
                if destination in pinned:
                    register = pinned[destination]
                elif index < len(allocatable):
                    register = allocatable[index]
                else:
                    continue
                kind, source_location = location(source)
                if kind == "reg":
                    moves.append((register, source_location, widths[destination], sunk.get(destination, 0)))
                else:
                    delayed.append((register, kind, source_location, width_bytes(source), sunk.get(destination, 0), widths[destination]))
            parallel_moves(moves)
            for register, kind, where, width, offset, value_width in delayed:
                emit(_load_constant(register, where) if kind == "const" else _lea(register, 4, where) if kind == "stack" else _load(register, where, width))
                if offset:
                    emit(_rex(value_width == 64, register, register) + b"\x8d" + _modrm_base(register, register, offset))

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
            # Pad unless a block of the same loop falls through: its NOPs would run every iteration.
            if assembler is not None and block_index in loop_headers and (closed["at"] == len(assembler.code) or block_index - 1 not in _reachable(graph, block_index)):
                assembler.emit(_nop_padding(-len(assembler.code) % LOOP_ALIGNMENT))
            label(f"block-{block_index}")
        for index, value in enumerate(machine_parameters[block_index]):
            if value in pinned:
                bind(value, pinned[value])  # edges write pinned parameters directly
            elif value in parameter_slot:
                spill_offset[value] = parameter_slot[value]
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
            if block_index in branch_tables and node_index in branch_tables[block_index][2]:
                continue  # read from a table by the terminator
            start = len(assembler.code) if assembler is not None else 0
            result = ValueRef.node_result(block_index, node_index)
            if result in erased_index_nodes or result in rmw_erased or result in compare_load:
                continue  # emitted by the access or compare that uses it
            hint["value"] = result
            operation = node.operation
            machine_operands = tuple(operand for operand in node.operands if operand in widths)

            if result in value_tables:
                subject, table = value_tables[result]
                register = ensure(subject, node_index)
                retire(node_index, subject)
                destination = acquire(node_index, {subject} if subject in register_for else set())
                table_address(table)
                emit(_scaled_load(destination, _SCRATCH, register, 1, 1))  # movzx destination, byte [r11 + subject]
                define(result, destination)
                if assembler is not None and ranges is not None:
                    ranges.append(ArtifactSemanticRange(function.cid, block_index, node_index, start, len(assembler.code)))
                continue

            if result in member_values:
                subject, low, mask = member_values[result]
                register = ensure(subject, node_index)
                retire(node_index, subject)
                destination = acquire(node_index, {subject} if subject in register_for else set())
                emit(_member_bit_test(register, low, mask, destination))
                emit(_setcc_register(IntCompare.ULT, destination))  # setc: the tested bit
                define(result, destination)
                if assembler is not None and ranges is not None:
                    ranges.append(ArtifactSemanticRange(function.cid, block_index, node_index, start, len(assembler.code)))
                continue

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
                elif operation == Operation.ADD_WRAP and width == 32 and (maximum(left) or 0) + value < 1 << 32:
                    # No 32-bit carry is possible, so the 64-bit add gives the same zero-extended
                    # value; 64-bit add-immediate is cheaper on recent cores (an induction step).
                    emit(_group1_immediate(operation, destination, value, 64))
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
                # xor-zero the result before the compare, then setcc: no movzx and
                # no false dependency on the register's previous value.
                left, right = node.operands
                ensure(left, node_index)
                if immediate(right, widths[left]) is None:
                    ensure(right, node_index, {left})
                register = acquire(node_index, {left, right})
                emit(_zero32(register))
                emit_compare(node_index, left, right)
                retire(node_index, left, right)
                emit(_setcc_register(IntCompare(node.attributes[0]), register)[:-3 - (register >= 4)])
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
                bound = maximum(source)
                if bound is not None and bound < 1 << width:
                    pass  # the value already fits: registers hold it zero-extended
                elif width == 32:
                    emit(_move_register(register, register, 32))
                else:
                    emit(_and_immediate(register, (1 << width) - 1, width=32))
                retire(node_index, source)
                define(result, register)

            elif operation in _COPY and result in pinned and pinned[result] == pinned.get(source := node.operands[0]):
                bind(result, pinned[result])  # the copy shares its pinned source's register
                retire(node_index, source)

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
                    emit(_compare_immediate(_SCRATCH, span >> shift))
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
                    index_value, scale = scaled.get(node.operands[1], (node.operands[1], 1))
                    last_offset = pointer_extent_from_graph(graph, pointer, resolve) - size
                    index = ensure(index_value, node_index, {pointer})
                    if last_offset < 0:
                        emit(b"\x0f\x0b")
                    elif access_proven(node) or (pointer, index_value, last_offset) in checked:
                        pass  # value ranges, or an earlier check in this block, prove this exact access
                    else:
                        checked.add((pointer, index_value, last_offset))
                        emit(_compare_immediate(index, last_offset))
                        trap_if(0x87, b"\x0f\x0b")  # ja: unsigned index above the last valid offset
                    if result in read_modify_write:
                        emit(_scaled_add_immediate(base, index, scale, size, read_modify_write[result]))
                        retire(node_index, pointer, index_value)
                    elif operation == Operation.CHECKED_LOAD_BITS_LE:
                        hinted = edge_hints.get(result)
                        if consumable(index_value, node_index) and index_value != pointer and (hinted is None or hinted == index or hinted in value_for_register):
                            register = index  # the index dies here; load into it
                            unbind(index_value)
                        else:
                            register = acquire(node_index, {pointer, index_value})
                        emit(_scaled_load(register, base, index, scale, size))
                        retire(node_index, pointer, index_value)
                        hints = (prefetches or {}).get(result, ())
                        if hints:
                            bind(result, register)
                            for array, array_scale in hints:
                                array_register = ensure(array, node_index, {result})
                                emit(_scaled_access(b"\x0f\x18", 1, array_register, register, array_scale, 4))  # prefetcht0
                                retire(node_index, array)
                            unbind(result)
                        define(result, register)
                    else:
                        value = node.operands[2]
                        value_register = ensure(value, node_index, {pointer, index_value})
                        emit(_scaled_store(value_register, base, index, scale, size))
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
            if assembler is not None and not capture:
                closed["at"] = len(assembler.code)
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
            elif block_index in branch_tables:
                subject, table, _tree = branch_tables[block_index]
                register = ensure(subject, position)
                table_address(table)
                emit(_scaled_access(b"\x80", 7, _SCRATCH, register, 1, 1) + b"\x00")  # cmp byte [r11 + subject], 0
                if_false = 0x84  # je: the table says false
            elif block_index in membership:
                # Out of the mask's span branches straight to the false edge (through a stub
                # carrying its copies); in span, one bit test decides: no clamp needed.
                subject, low, mask, _tree = membership[block_index]
                register = ensure(subject, position)
                temporary = acquire(position, {subject})
                (_true_target, _true_arguments), (false_target, false_arguments) = terminator.edges
                outside = f"member-out-{block_index}{copy_tag}"
                stubs.append((outside, edge_code(false_target, false_arguments), false_target))
                emit(bytes((0x44 | (register >= 8), 0x8D, 0x98 | (register & 7))) + (b"\x24" if register & 7 == 4 else b"") + ((-low) & 0xFFFFFFFF).to_bytes(4, "little"))  # lea r11d, [x - low]
                emit(b"\x41\x83\xfb" + bytes((mask.bit_length() - 1,)))  # cmp r11d, highest member offset
                jump(b"\x0f\x87", outside)  # ja: above every member
                emit(_load_constant(temporary, mask) + bytes((0x4C | (temporary >= 8), 0x0F, 0xA3, 0xD8 | (temporary & 7))))  # bt tmp, r11
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
            if assembler is not None and not capture:
                closed["at"] = len(assembler.code)
        return state["max"]

    # Dry run: spill count and used callee-saved registers, without emission.
    used: set[int] = set()
    plan = [lower_block(index, None, None, used, b"", [], {}) for index in range(len(graph.blocks))]
    if any(item < 0 for item in plan):
        return None
    spill_count = max(plan, default=0)
    # A process entry never returns to a caller, so it has nothing to preserve.
    # SysV preserves rbx, rbp, r12-r15 only (rsi/rdi are caller-saved there, and this
    # allocator never keeps a value in them across a call); Win64 also preserves rsi/rdi.
    preserved = CALLEE_SAVED if windows else PINNABLE
    saved = () if process_entry else tuple(register for register in CALLEE_SAVED if register in used and register in preserved)
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
    for constant, register in sorted(hoisted_constants.items(), key=lambda item: item[1]):
        assembler.emit(_load_constant(register, constant))
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
    if tables:  # data after the last instruction is never executed; int3 padding keeps it so
        assembler.emit(b"\xcc" * (-len(assembler.code) % 16))
        for table, name in tables.items():
            assembler.label(name)
            assembler.emit(table)
    code, calls = assembler.finish()
    return code, calls, tuple(ranges)

