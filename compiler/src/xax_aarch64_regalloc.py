"""Function-wide register allocation for the Linux AArch64 profiles (ADR-168, OI-38).

The general AArch64 path keeps every value in a frame slot (ADR-123), and the
older register path (ADR-110/154) covers only scalar add/sub/mul/compare/call
graphs.  This module lowers the hosted operation set with SSA values in
registers, for ``aarch64-linux-elf-exec-v1`` and ``-dynexec-v1`` only, so
Android and board artifacts stay byte-identical:

* **Values.** Copies share one value: pointer casts, pointer addresses, heap
  views (after their null check), zero extensions, and truncations proven
  lossless by the shared range analysis (``xax_ranges``).  Constants are
  folded into immediates or the zero register, materialized at their use,
  or, when used in a loop and costing two or more instructions, hoisted to the
  entry into a register.  Pure nodes whose result nobody reads are dropped.
* **Allocation.** Linear scan over conservative live hulls in layout order:
  liveness is exact (SSA dataflow), and a value owns its location from the
  first to the last position where it is live.  A block parameter is defined
  at the end of each predecessor, so loop-carried values coalesce with their
  next iteration through register hints.  Values live across a call take
  x19-x29 (callee-saved); others prefer x0-x13.  x14-x17 are per-node
  scratch.  When registers run out, the lowest-weight hull (uses, times 10 in
  loops) moves to a frame slot for its whole life.
* **Code.** Compares that only feed their block's branch fuse into
  ``cmp``/``b.cond``.  Checked accesses whose index is proven in range need no
  check, and a proven ``x * size`` index becomes a scaled register offset.
  Failing checks branch to shared out-of-line ``brk`` stubs with the frame
  path's trap codes.  Edge copies are parallel moves; a branch edge with
  copies goes through an out-of-line stub.

Functions with other operations or value forms return ``None`` and keep the
existing paths; nothing is guessed.
"""

from __future__ import annotations

from collections import Counter
from typing import Callable

from xax_artifact import ArtifactSemanticRange
from xax_compiler import (
    IntCompare,
    NativeTargetDescription,
    Operation,
    RESOURCE_EFFECT_OPERATIONS,
    SemanticObject,
    TerminatorKind,
    ValueRef,
    _decode_constant,
    _decode_function_interface,
    _decode_pointer_type,
    _is_erased_proof_function,
    _is_proof_type,
    borrowed_view_returns,
    decode_foreign_function,
    decode_trap_payload,
    parse_function_graph,
    pointer_extent_from_graph,
)
from xax_compiler import AARCH64_LINUX_ABI
from xax_ranges import TABLE_OPERATIONS, predicate_table, upper_bounds

_CALLER = tuple(range(0, 14))  # x0-x13
_CALLEE = tuple(range(19, 30))  # x19-x29
_SCRATCH = (16, 17, 15, 14)
_CYCLE, _TRANSFER = 16, 17  # parallel-move scratch
_ZR, _SP, _LR = 31, 31, 30
_BRK_NULL_HEAP, _BRK_MEMORY_CHECK, _BRK_DIVIDE_BY_ZERO = 3, 4, 6

_PURE = frozenset({
    Operation.CONSTANT, Operation.ADD_WRAP, Operation.SUB_WRAP, Operation.MUL_WRAP, Operation.BIT_AND, Operation.BIT_OR,
    Operation.BIT_XOR, Operation.INT_COMPARE, Operation.INT_TRUNCATE, Operation.INT_ZERO_EXTEND, Operation.ROTATE_RIGHT,
    Operation.ADDRESS_OFFSET, Operation.POINTER_CAST, Operation.POINTER_ADDRESS,
})
_SUPPORTED = _PURE | frozenset({
    Operation.UDIV, Operation.UREM, Operation.CALL_DIRECT, Operation.CALL_FOREIGN, Operation.HEAP_VIEW,
    Operation.LOAD_BITS_LE, Operation.RAW_LOAD_BITS_LE, Operation.STORE_BITS_LE, Operation.CHECKED_LOAD_BITS_LE,
    Operation.CHECKED_STORE_BITS_LE, Operation.POINTER_REBASE, Operation.STACK_END, *RESOURCE_EFFECT_OPERATIONS,
})
_CALLS = (Operation.CALL_DIRECT, Operation.CALL_FOREIGN)
_DUPLICATE_LIMIT = 4  # code-emitting nodes of a test block copied into a jumping predecessor
_NO_CODE = frozenset({Operation.CONSTANT, Operation.POINTER_CAST, Operation.POINTER_ADDRESS, Operation.INT_ZERO_EXTEND, Operation.STACK_END})
_COND = {
    IntCompare.EQ: 0, IntCompare.NE: 1, IntCompare.UGE: 2, IntCompare.ULT: 3, IntCompare.UGT: 8, IntCompare.ULE: 9,
    IntCompare.SGE: 10, IntCompare.SLT: 11, IntCompare.SGT: 12, IntCompare.SLE: 13,
}
_SWAPPED = {
    IntCompare.EQ: IntCompare.EQ, IntCompare.NE: IntCompare.NE, IntCompare.ULT: IntCompare.UGT, IntCompare.UGT: IntCompare.ULT,
    IntCompare.ULE: IntCompare.UGE, IntCompare.UGE: IntCompare.ULE, IntCompare.SLT: IntCompare.SGT, IntCompare.SGT: IntCompare.SLT,
    IntCompare.SLE: IntCompare.SGE, IntCompare.SGE: IntCompare.SLE,
}
_SIGNED = frozenset({IntCompare.SLT, IntCompare.SLE, IntCompare.SGT, IntCompare.SGE})


# ---------------------------------------------------------------- encodings


def _wide(width: int) -> bool:
    return width > 32


def _addsub_immediate(value: int) -> tuple[int, int] | None:
    """``(imm12, shift)`` for an ADD/SUB immediate, else None."""
    if 0 <= value < 4096:
        return value, 0
    if value % 4096 == 0 and 0 <= value >> 12 < 4096:
        return value >> 12, 1
    return None


def _logical_immediate(value: int, wide: bool) -> int | None:
    """``N:immr:imms`` (13 bits) of a bitmask immediate, else None."""
    size = 64 if wide else 32
    value &= (1 << size) - 1
    if value in (0, (1 << size) - 1):
        return None
    element = size
    while element > 2:
        half = element // 2
        if (value & ((1 << half) - 1)) != ((value >> half) & ((1 << half) - 1)):
            break
        element = half
    pattern = value & ((1 << element) - 1)
    for rotation in range(element):
        rotated = ((pattern >> rotation) | (pattern << (element - rotation))) & ((1 << element) - 1)
        ones = bin(rotated).count("1")
        if rotated == (1 << ones) - 1:
            n = 1 if element == 64 else 0
            imms = ((~(element - 1) << 1) & 0x3F) | (ones - 1)
            immr = (element - rotation) % element
            return (n << 12) | (immr << 6) | (imms & 0x3F)
    return None


def _move_immediate(register: int, value: int, wide: bool) -> list[int]:
    size = 64 if wide else 32
    value &= (1 << size) - 1
    if value == 0:
        return [(0xD2800000 if wide else 0x52800000) | register]
    inverted = ~value & ((1 << size) - 1)
    halves = [(value >> (16 * index)) & 0xFFFF for index in range(size // 16)]
    inverted_halves = [(inverted >> (16 * index)) & 0xFFFF for index in range(size // 16)]
    if sum(part != 0 for part in inverted_halves) <= 1 and sum(part != 0 for part in halves) > 1:
        index = next((i for i, part in enumerate(inverted_halves) if part), 0)
        words = [(0x92800000 if wide else 0x12800000) | (index << 21) | (inverted_halves[index] << 5) | register]  # movn
        return words
    encoded = _logical_immediate(value, wide)
    if encoded is not None and sum(part != 0 for part in halves) > 1:
        return [(0xB2000000 if wide else 0x32000000) | (encoded << 10) | (_ZR << 5) | register]  # orr rd, zr, #imm
    words: list[int] = []
    for index, part in enumerate(halves):
        if part:
            base = (0xF2800000 if wide else 0x72800000) if words else (0xD2800000 if wide else 0x52800000)
            words.append(base | (index << 21) | (part << 5) | register)
    return words


def _mov(destination: int, source: int) -> int:
    return 0xAA0003E0 | (source << 16) | destination


def _mask(register: int, source: int, width: int) -> list[int]:
    """Zero-extend the low ``width`` bits of ``source`` into ``register``."""
    if width >= 64:
        return [] if register == source else [_mov(register, source)]
    if width == 32:
        return [0x2A0003E0 | (source << 16) | register]
    return [0xD3400000 | ((width - 1) << 10) | (source << 5) | register]  # ubfx


def _three(base_w: int, base_x: int, wide: bool, d: int, n: int, m: int) -> int:
    return (base_x if wide else base_w) | (m << 16) | (n << 5) | d


_ADD, _SUB, _MUL = (0x0B000000, 0x8B000000), (0x4B000000, 0xCB000000), (0x1B007C00, 0x9B007C00)
_AND, _ORR, _EOR = (0x0A000000, 0x8A000000), (0x2A000000, 0xAA000000), (0x4A000000, 0xCA000000)
_LOGIC_IMM = {Operation.BIT_AND: (0x12000000, 0x92000000), Operation.BIT_OR: (0x32000000, 0xB2000000), Operation.BIT_XOR: (0x52000000, 0xD2000000)}
_LOGIC_REG = {Operation.BIT_AND: _AND, Operation.BIT_OR: _ORR, Operation.BIT_XOR: _EOR}


def _addsub_imm(subtract: bool, wide: bool, d: int, n: int, imm: tuple[int, int]) -> int:
    base = (0xD1000000 if wide else 0x51000000) if subtract else (0x91000000 if wide else 0x11000000)
    return base | (imm[1] << 22) | (imm[0] << 10) | (n << 5) | d


def _cmp_imm(wide: bool, n: int, imm: tuple[int, int]) -> int:
    return (0xF100001F if wide else 0x7100001F) | (imm[1] << 22) | (imm[0] << 10) | (n << 5)


def _cmp_reg(wide: bool, n: int, m: int) -> int:
    return (0xEB00001F if wide else 0x6B00001F) | (m << 16) | (n << 5)


def _lsl(d: int, n: int, shift: int, wide: bool) -> int:
    if wide:
        return 0xD3400000 | (((-shift) % 64) << 16) | ((63 - shift) << 10) | (n << 5) | d
    return 0x53000000 | (((-shift) % 32) << 16) | ((31 - shift) << 10) | (n << 5) | d


def _lsr(d: int, n: int, shift: int, wide: bool) -> int:
    return (0xD340FC00 if wide else 0x53007C00) | (shift << 16) | (n << 5) | d


def _ror(d: int, n: int, shift: int, wide: bool) -> int:
    return (0x93C00000 if wide else 0x13800000) | (n << 16) | (shift << 10) | (n << 5) | d


def _sbfx(d: int, n: int, width: int) -> int:
    return 0x93400000 | ((width - 1) << 10) | (n << 5) | d


def _cset(d: int, condition: int) -> int:
    return 0x1A9F07E0 | ((condition ^ 1) << 12) | d


_UNSIGNED_OFFSET = {1: (0x39400000, 0x39000000), 2: (0x79400000, 0x79000000), 4: (0xB9400000, 0xB9000000), 8: (0xF9400000, 0xF9000000)}
_REGISTER_OFFSET = {1: (0x38606800, 0x38206800), 2: (0x78606800, 0x78206800), 4: (0xB8606800, 0xB8206800), 8: (0xF8606800, 0xF8206800)}


def _access(load: bool, register: int, base: int, offset: int, size: int) -> int:
    return _UNSIGNED_OFFSET[size][0 if load else 1] | ((offset // size) << 10) | (base << 5) | register


def _indexed(load: bool, register: int, base: int, index: int, size: int, scaled: bool) -> int:
    return _REGISTER_OFFSET[size][0 if load else 1] | (0x1000 if scaled else 0) | (index << 16) | (base << 5) | register


def _brk(code: int) -> int:
    return 0xD4200000 | (code << 5)


class _Assembler:
    def __init__(self) -> None:
        self.code = bytearray()
        self.labels: dict[object, int] = {}
        self.fixups: list[tuple[int, object, int]] = []  # (position, label, kind) kind 26 or 19
        self.calls: list[tuple[int, bytes]] = []
        self.foreign_calls: list[tuple[int, bytes, bytes]] = []

    def emit(self, *words: int) -> None:
        for word in words:
            self.code.extend((word & 0xFFFFFFFF).to_bytes(4, "little"))

    def label(self, name: object) -> None:
        self.labels[name] = len(self.code)

    def branch(self, word: int, label: object, bits: int) -> None:
        self.fixups.append((len(self.code), label, bits))
        self.emit(word)

    def finish(self) -> bytes:
        for position, label, bits in self.fixups:
            displacement = (self.labels[label] - position) // 4
            word = int.from_bytes(self.code[position:position + 4], "little")
            if bits == 26:
                word |= displacement & 0x3FFFFFF
            elif bits == 21:  # adr: a byte displacement, immlo in bits 29-30 and immhi in bits 5-23
                offset = self.labels[label] - position
                word |= ((offset & 3) << 29) | (((offset >> 2) & 0x7FFFF) << 5)
            else:
                word |= (displacement & 0x7FFFF) << 5
            self.code[position:position + 4] = word.to_bytes(4, "little")
        return bytes(self.code)


# ---------------------------------------------------------------- analysis


def _machine_width(resolve, cid: bytes) -> int | None | bool:
    """Width of a bits/pointer value, None for a proof value, False for anything else."""
    obj = resolve(cid)
    if _is_proof_type(obj):
        return None
    form = obj.body[:1]
    if form == b"\x01":
        from xax_compiler import decode_bits_width

        width = decode_bits_width(obj)
        return width if width <= 64 else False
    if form == b"\x02":
        return 64
    return False


def compile_linux_function(function: SemanticObject, resolve: Callable[[bytes], SemanticObject], target: NativeTargetDescription):
    """``(code, calls, foreign_calls, addresses, node_ranges)``, or ``None`` when the function is ineligible."""
    graph_object, parameter_types, return_types = _decode_function_interface(function, resolve)
    graph = parse_function_graph(function, resolve)
    if target.abi == AARCH64_LINUX_ABI:  # small leaf callees inline into the lowering view (as on x86-64; ADR-254)
        from xax_inline import inline_leaf_calls

        graph = inline_leaf_calls(graph, resolve)
    lowering = _Lowering(function, graph_object, graph, parameter_types, return_types, resolve, target)
    return lowering.run() if lowering.eligible() else None


class _Interval:
    """A value's live ranges (sorted, disjoint, inclusive) and its assignment."""

    __slots__ = ("value", "ranges", "crosses", "weight", "register", "slot")

    def __init__(self, value: ValueRef) -> None:
        self.value, self.crosses, self.weight, self.register, self.slot = value, False, 0, None, None
        self.ranges: list[list[int]] = []

    def add(self, start: int, end: int) -> None:
        self.ranges.append([start, end])

    def normalize(self) -> None:
        merged: list[list[int]] = []
        for start, end in sorted(self.ranges):
            if merged and start <= merged[-1][1] + 1:
                merged[-1][1] = max(merged[-1][1], end)
            else:
                merged.append([start, end])
        self.ranges = merged

    @property
    def start(self) -> int:
        return self.ranges[0][0]

    def overlaps(self, other: "_Interval") -> bool:
        a, b, i, j = self.ranges, other.ranges, 0, 0
        while i < len(a) and j < len(b):
            if a[i][1] < b[j][0]:
                i += 1
            elif b[j][1] < a[i][0]:
                j += 1
            else:
                return True
        return False


class _Lowering:
    def __init__(self, function, graph_object, graph, parameter_types, return_types, resolve, target) -> None:
        self.function, self.graph_object, self.graph = function, graph_object, graph
        self.parameter_types, self.return_types, self.resolve, self.target = parameter_types, return_types, resolve, target

    # -- eligibility and value facts ---------------------------------------------------
    def eligible(self) -> bool:
        graph, resolve = self.graph, self.resolve
        widths: dict[ValueRef, int] = {}
        machine_parameters = [cid for cid in self.parameter_types if _machine_width(resolve, cid) is not None]
        # Borrowed views given back are the lent pointers (ADR-101): not returned in registers.
        self.own_elided = borrowed_view_returns(self.parameter_types, self.return_types, resolve)
        machine_returns = [cid for index, cid in enumerate(self.return_types) if _machine_width(resolve, cid) is not None and index not in self.own_elided]
        if any(_machine_width(resolve, cid) is False for cid in (*machine_parameters, *machine_returns)):
            return False
        if len(machine_parameters) > 8 or len(machine_returns) > 1:
            return False
        self.call_elided: dict[ValueRef, ValueRef] = {}  # a call's given-back view -> the operand it lent
        for block_index, block in enumerate(graph.blocks):
            for index, cid in enumerate(block.parameters):
                width = _machine_width(resolve, cid)
                if width is False:
                    return False
                if width is not None:
                    widths[ValueRef.parameter(block_index, index)] = width
            for node_index, node in enumerate(block.nodes):
                if node.operation not in _SUPPORTED:
                    return False
                for cid in node.operand_types:
                    if _machine_width(resolve, cid) is False:
                        return False
                for result_index, cid in enumerate(node.results):
                    width = _machine_width(resolve, cid)
                    if width is False:
                        return False
                    if width is not None:
                        widths[ValueRef.node_result(block_index, node_index, result_index)] = width
                machine_results = [cid for cid in node.results if _machine_width(resolve, cid) is not None]
                if node.operation in RESOURCE_EFFECT_OPERATIONS or node.operation == Operation.STACK_END:
                    if machine_results:
                        return False
                if node.operation in _CALLS:
                    if node.operation == Operation.CALL_DIRECT and _is_erased_proof_function(node.entity, resolve):
                        continue
                    machine_operands = [cid for cid in node.operand_types if _machine_width(resolve, cid) is not None]
                    elided = borrowed_view_returns(node.operand_types, node.results, resolve) if node.operation == Operation.CALL_DIRECT else {}
                    for result_index, parameter_index in elided.items():
                        self.call_elided[ValueRef.node_result(block_index, node_index, result_index)] = node.operands[parameter_index]
                    if len(machine_operands) > 8 or len(machine_results) - len(elided) > 1:
                        return False
                if node.operation in (Operation.LOAD_BITS_LE, Operation.RAW_LOAD_BITS_LE, Operation.STORE_BITS_LE, Operation.CHECKED_LOAD_BITS_LE, Operation.CHECKED_STORE_BITS_LE):
                    if node.attributes[0] not in (1, 2, 4, 8):
                        return False
            if block.terminator.kind not in (TerminatorKind.RETURN, TerminatorKind.BRANCH, TerminatorKind.CONDITIONAL_BRANCH, TerminatorKind.TRAP):
                return False
        self.widths = widths
        return True

    def _analyze(self) -> None:
        graph, resolve, widths = self.graph, self.resolve, self.widths
        self.constants: dict[ValueRef, int] = {}
        self.definition: dict[ValueRef, object] = {}
        for block_index, block in enumerate(graph.blocks):
            for node_index, node in enumerate(block.nodes):
                self.definition[ValueRef.node_result(block_index, node_index)] = node
                if node.operation == Operation.CONSTANT:
                    self.constants[ValueRef.node_result(block_index, node_index)] = _decode_constant(node.entity, resolve)[1] & ((1 << 64) - 1)
        self.maximum = upper_bounds(graph, widths, self.constants, bitwise=True)
        # Copies share one value (the alias's representative).
        self.alias: dict[ValueRef, ValueRef] = {}
        for block_index, block in enumerate(graph.blocks):
            for node_index, node in enumerate(block.nodes):
                result = ValueRef.node_result(block_index, node_index)
                if result not in widths:
                    continue
                if node.operation in (Operation.POINTER_CAST, Operation.POINTER_ADDRESS, Operation.HEAP_VIEW, Operation.INT_ZERO_EXTEND):
                    self.alias[result] = node.operands[0]
                elif node.operation == Operation.POINTER_REBASE:
                    self.alias[result] = node.operands[1]
                elif node.operation == Operation.INT_TRUNCATE:
                    bound = self.maximum(node.operands[0])
                    if bound is not None and bound < 1 << widths[result]:
                        self.alias[result] = node.operands[0]
        # A view a call gives back is a copy of the operand, which therefore stays live across the call.
        self.alias.update(self.call_elided)
        # A block parameter whose every incoming argument is one value (or the parameter itself, through
        # other such parameters) is that value: loop-invariant values passed around a loop need no copies.
        incoming: dict[ValueRef, list[ValueRef]] = {}
        for block in graph.blocks:
            for target, arguments in block.terminator.edges:
                for index, argument in enumerate(arguments):
                    incoming.setdefault(ValueRef.parameter(target, index), []).append(argument)
        changed = True
        while changed:
            changed = False
            for parameter, arguments in incoming.items():
                if parameter.block == graph.entry or parameter not in widths or parameter in self.alias:
                    continue
                sources = {self.canon(argument) for argument in arguments} - {parameter}
                if len(sources) == 1:
                    self.alias[parameter] = sources.pop()
                    changed = True
        # Fused compares: consumed only by their block's conditional branch.
        uses = Counter(self.canon(operand) for block in graph.blocks for node in block.nodes for operand in node.operands)
        uses.update(self.canon(value) for block in graph.blocks for value in block.terminator.values)
        uses.update(self.canon(value) for block in graph.blocks for _t, arguments in block.terminator.edges for value in arguments)
        self.fused: dict[int, int] = {}
        for block_index, block in enumerate(graph.blocks):
            terminator = block.terminator
            if terminator.kind != TerminatorKind.CONDITIONAL_BRANCH:
                continue
            condition = self.canon(terminator.values[0])
            if condition.tag == 1 and condition.block == block_index and condition.result == 0 and uses[condition] == 1:
                if block.nodes[condition.index].operation == Operation.INT_COMPARE:
                    self.fused[block_index] = condition.index
        # Predicate tables (ADR-208, ADR-254): a boolean of one byte-bounded value read from a byte table.
        # The table's address is a synthetic value (result 2 of the root) hoisted to the entry.
        raw_uses = Counter(operand for block in graph.blocks for node in block.nodes for operand in node.operands)
        raw_uses.update(value for block in graph.blocks for value in block.terminator.values)
        raw_uses.update(value for block in graph.blocks for _target, arguments in block.terminator.edges for value in arguments)
        self.tables: dict[ValueRef, tuple[ValueRef, ValueRef]] = {}  # root -> (subject, table address)
        self.table_data: dict[ValueRef, bytes] = {}
        table_internal: set[ValueRef] = set()
        for block_index, block in enumerate(graph.blocks):
            for node_index in reversed(range(len(block.nodes))):
                root = ValueRef.node_result(block_index, node_index)
                node = block.nodes[node_index]
                if (
                    root in table_internal or root not in widths or root in self.alias or node_index == self.fused.get(block_index)
                    or node.operation not in TABLE_OPERATIONS or node.operation in (Operation.INT_ZERO_EXTEND, Operation.INT_TRUNCATE)
                ):
                    continue
                found = predicate_table(graph, block_index, root, self.definition, widths, self.constants, self.maximum, raw_uses)
                if found is not None:
                    subject, table, indices = found
                    address = ValueRef.node_result(block_index, node_index, 2)
                    self.widths[address] = 64
                    self.tables[root], self.table_data[address] = (subject, address), table
                    table_internal.update(ValueRef.node_result(block_index, index) for index in indices)
        # Loops: blocks on a CFG cycle, and each block's natural-loop nesting depth.
        successors = {index: [t for t, _a in block.terminator.edges] for index, block in enumerate(graph.blocks)}
        self.in_loop = {index for index in successors if self._reaches(successors, index, index)}
        self.depth = self._loop_depths(successors)
        self.order = self._layout(successors)
        self.member: dict[ValueRef, tuple[ValueRef, int, ValueRef]] = {}  # OR-of-equalities root -> (subject, low, mask constant)
        self.bic: dict[ValueRef, tuple[ValueRef, ValueRef]] = {}  # and(xor(x, 1), y) of 0/1 values -> (y, x)
        for block_index, block in enumerate(graph.blocks):
            internal: set[ValueRef] = set()
            for node_index in reversed(range(len(block.nodes))):
                root = ValueRef.node_result(block_index, node_index)
                node = block.nodes[node_index]
                if node.operation == Operation.BIT_OR and root in widths and root not in internal and root not in table_internal:
                    found = self._membership(block_index, root, uses)
                    if found is not None:
                        tests, inner = found
                        subjects = {subject for subject, _value, _width in tests}
                        values = sorted({value for _s, value, _w in tests})
                        low = 0 if values[-1] < 64 else values[0]
                        if len(subjects) == 1 and len(tests) >= 3 and values[-1] - low < 64:
                            mask = ValueRef.node_result(block_index, node_index, 1)  # a synthetic constant: the mask
                            self.constants[mask], self.widths[mask] = sum(1 << (value - low) for value in values), 64
                            self.member[root] = (subjects.pop(), low, mask)
                            internal |= inner
                if node.operation == Operation.BIT_AND and root in widths:
                    for flipped, other in (node.operands, node.operands[::-1]):
                        xor = self.definition.get(self.canon(flipped))
                        if (
                            xor is not None and xor.operation == Operation.BIT_XOR and uses[self.canon(flipped)] == 1
                            and self.maximum(other) is not None and self.maximum(other) <= 1
                        ):
                            x, one = xor.operands if self.const(xor.operands[1]) == 1 else xor.operands[::-1]
                            if self.const(one) == 1 and self.const(x) is None and self.maximum(x) is not None and self.maximum(x) <= 1:
                                self.bic[root] = (other, x)
                                break

    def _membership(self, block_index: int, root: ValueRef, uses) -> tuple[list, set] | None:
        """``x == a | x == b | ...`` (an OR tree of equality tests in one block): its tests and inner OR nodes."""
        tests, inner, pending = [], set(), [root]
        while pending:
            value = self.canon(pending.pop())
            node = self.definition.get(value) if value.tag == 1 and value.block == block_index and value.result == 0 else None
            if node is None:
                return None
            if node.operation == Operation.BIT_OR and (value == root or uses[value] == 1):
                if value != root:
                    inner.add(value)
                pending.extend(node.operands)
            elif node.operation == Operation.INT_COMPARE and IntCompare(node.attributes[0]) == IntCompare.EQ:
                subject, constant = node.operands
                if self.const(subject) is not None:
                    subject, constant = constant, subject
                width = self.width(subject)
                if self.const(constant) is None or self.const(subject) is not None or self.const(constant) >= 1 << min(width, 64):
                    return None
                tests.append((self.canon(subject), self.const(constant), width))
            else:
                return None
        return tests, inner

    def _layout(self, successors) -> list[int]:
        """Reverse postorder; a block's deepest-loop successor is visited last, so it is laid out next."""
        order, seen = [], set()

        def visit(block: int) -> None:
            stack = [(block, iter(sorted(successors[block], key=lambda item: (self.depth.get(item, 0), -item))))]
            seen.add(block)
            while stack:
                current, children = stack[-1]
                child = next((item for item in children if item not in seen), None)
                if child is None:
                    order.append(current)
                    stack.pop()
                else:
                    seen.add(child)
                    stack.append((child, iter(sorted(successors[child], key=lambda item: (self.depth.get(item, 0), -item)))))

        visit(self.graph.entry)
        order.reverse()
        order.extend(index for index in successors if index not in seen)
        return order

    def _loop_depths(self, successors) -> dict[int, int]:
        blocks = list(successors)
        predecessors = {index: [] for index in blocks}
        for source, targets in successors.items():
            for target in targets:
                predecessors[target].append(source)
        entry = self.graph.entry
        dominators = {index: set(blocks) for index in blocks}
        dominators[entry] = {entry}
        changed = True
        while changed:
            changed = False
            for index in blocks:
                if index == entry:
                    continue
                incoming = [dominators[p] for p in predecessors[index]]
                new = (set.intersection(*incoming) if incoming else set()) | {index}
                if new != dominators[index]:
                    dominators[index], changed = new, True
        depth = Counter()
        for tail, targets in successors.items():
            for header in targets:
                if header in dominators[tail]:  # a back edge: its natural loop
                    body, pending = {header, tail}, [tail]
                    while pending:
                        block = pending.pop()
                        if block != header:
                            for p in predecessors[block]:
                                if p not in body:
                                    body.add(p)
                                    pending.append(p)
                    for block in body:
                        depth[block] += 1
        return {index: depth[index] for index in blocks}

    @staticmethod
    def _reaches(successors, start: int, goal: int) -> bool:
        seen, pending = set(), list(successors[start])
        while pending:
            block = pending.pop()
            if block == goal:
                return True
            if block not in seen:
                seen.add(block)
                pending.extend(successors[block])
        return False

    def canon(self, value: ValueRef) -> ValueRef:
        while value in self.alias:
            value = self.alias[value]
        return value

    def const(self, value: ValueRef) -> int | None:
        return self.constants.get(self.canon(value))

    def width(self, value: ValueRef) -> int:
        return self.widths[value] if value in self.widths else self.widths[self.canon(value)]

    # -- per-node plans: which values a node reads in registers ------------------------
    def _scaled(self, node) -> tuple[ValueRef, int] | None:
        """A proven checked access whose index is ``x * size``: address with ``[base, x, lsl #log2(size)]``."""
        size = node.attributes[0]
        if size == 1 or not self._proven(node):
            return None
        multiply = self.definition.get(self.canon(node.operands[1]))
        if multiply is None or multiply.operation != Operation.MUL_WRAP:
            return None
        x, factor = multiply.operands
        if self.const(factor) != size:
            x, factor = factor, x
        if self.const(factor) != size or self.const(x) is not None:
            return None
        bound = self.maximum(x)
        return (x, size) if bound is not None and bound * size < 1 << 64 else None

    def _proven(self, node) -> bool:
        bound = self.maximum(node.operands[1])
        return bound is not None and bound <= pointer_extent_from_graph(self.graph, node.operands[0], self.resolve) - node.attributes[0]

    def _folds(self, node, position: int) -> bool:
        """True when operand ``position`` is a constant the node encodes without a register."""
        operand = node.operands[position]
        value = self.const(operand)
        if value is None:
            return False
        op = node.operation
        width = self.width(operand) if operand in self.widths or self.canon(operand) in self.widths else 64
        if value == 0 and op in (Operation.ADD_WRAP, Operation.SUB_WRAP, Operation.BIT_AND, Operation.BIT_OR, Operation.BIT_XOR, Operation.INT_COMPARE, Operation.MUL_WRAP, Operation.STORE_BITS_LE, Operation.CHECKED_STORE_BITS_LE):
            return position != 0 or op not in (Operation.STORE_BITS_LE, Operation.CHECKED_STORE_BITS_LE)
        if op in (Operation.ADD_WRAP, Operation.SUB_WRAP):
            other = node.operands[1 - position]
            if position == 0 and (op == Operation.SUB_WRAP or self.const(other) is not None):
                return False
            negated = (-value) % (1 << (64 if width > 32 else 32))
            return _addsub_immediate(value) is not None or _addsub_immediate(negated) is not None
        if op == Operation.MUL_WRAP:
            if position == 0 and self.const(node.operands[1]) is not None:
                return False
            return value & (value - 1) == 0
        if op in _LOGIC_REG:
            if position == 0 and self.const(node.operands[1]) is not None:
                return False
            return _logical_immediate(value, width > 32) is not None
        if op == Operation.INT_COMPARE:
            if position == 0 and self.const(node.operands[1]) is not None:
                return False
            signed = IntCompare(node.attributes[0]) in _SIGNED and width not in (32, 64)
            return not signed and _addsub_immediate(value) is not None
        if op in (Operation.UDIV, Operation.UREM) and position == 1:
            return value != 0 and value & (value - 1) == 0
        if op in (Operation.CHECKED_LOAD_BITS_LE, Operation.CHECKED_STORE_BITS_LE) and position == 1:
            return True  # a constant index is checked statically
        return False

    def reads(self, block_index: int, node_index: int, node) -> tuple[ValueRef, ...]:
        """Canonical values the node reads from a location (register or slot)."""
        op = node.operation
        if node_index == self.fused.get(block_index) or op in (Operation.CONSTANT, Operation.STACK_END) or op in RESOURCE_EFFECT_OPERATIONS:
            return ()
        if op in (Operation.POINTER_CAST, Operation.POINTER_ADDRESS, Operation.INT_ZERO_EXTEND):
            return ()
        result = ValueRef.node_result(block_index, node_index)
        if op == Operation.INT_TRUNCATE and result in self.alias:
            return ()
        if result in self.tables:
            return tuple(value for value in (self._located(item) for item in self.tables[result]) if value is not None)
        if result in self.member:
            subject, _low, mask = self.member[result]
            return tuple(value for value in (self._located(subject), self._located(mask)) if value is not None)
        if result in self.bic:
            return tuple(value for value in (self._located(item) for item in self.bic[result]) if value is not None)
        if op in (Operation.CHECKED_LOAD_BITS_LE, Operation.CHECKED_STORE_BITS_LE):
            scaled = self._scaled(node)
            picked = [node.operands[0]]
            if scaled is not None:
                picked.append(scaled[0])
            elif self.const(node.operands[1]) is None:
                picked.append(node.operands[1])
            if op == Operation.CHECKED_STORE_BITS_LE and not self._folds(node, 2):
                picked.append(node.operands[2])
            if (block_index, node_index) in self.check_bound:
                picked.append(self.check_bound[(block_index, node_index)])
            return tuple(value for value in (self._located(operand) for operand in picked) if value is not None)
        machine = [(index, operand) for index, (operand, cid) in enumerate(zip(node.operands, node.operand_types)) if _machine_width(self.resolve, cid) is not None]
        if op == Operation.CALL_DIRECT and _is_erased_proof_function(node.entity, self.resolve):
            return ()
        picked = [operand for index, operand in machine if not (op not in _CALLS and self._folds(node, index))]
        return tuple(value for value in (self._located(operand) for operand in picked) if value is not None)

    def _located(self, operand: ValueRef) -> ValueRef | None:
        """The canonical value to read, or None for a constant materialized at its use."""
        value = self.canon(operand)
        if (value in self.constants or value in self.table_data) and value not in self.hoisted:
            return None
        return value

    def defines(self, block_index: int, node_index: int, node) -> ValueRef | None:
        if node.operation == Operation.CONSTANT:
            return None
        machine = [ValueRef.node_result(block_index, node_index, index) for index, cid in enumerate(node.results) if _machine_width(self.resolve, cid) is not None]
        machine = [value for value in machine if value not in self.call_elided]
        if not machine or node_index == self.fused.get(block_index) or machine[0] in self.alias:
            return None
        return machine[0]

    def terminator_reads(self, block_index: int) -> tuple[ValueRef, ...]:
        terminator = self.graph.blocks[block_index].terminator
        values: list[ValueRef] = []
        if terminator.kind == TerminatorKind.RETURN:
            machine = [value for index, (value, cid) in enumerate(zip(terminator.values, self.return_types))
                       if _machine_width(self.resolve, cid) is not None and index not in self.own_elided]
            values.extend(machine)
        elif terminator.kind == TerminatorKind.CONDITIONAL_BRANCH:
            if block_index in self.fused:
                compare = self.graph.blocks[block_index].nodes[self.fused[block_index]]
                values.extend(operand for index, operand in enumerate(compare.operands) if not self._folds(compare, index))
            else:
                values.append(terminator.values[0])
        for target, arguments in terminator.edges:
            for index, argument in enumerate(arguments):
                if ValueRef.parameter(target, index) in self.widths and ValueRef.parameter(target, index) not in self.alias:
                    values.append(argument)
        return tuple(value for value in (self._located(item) for item in values) if value is not None)

    # -- liveness, intervals, allocation -------------------------------------------------
    def _plan(self) -> None:
        graph = self.graph
        # Table addresses used in a loop, and the bounds of loop checks a compare cannot encode, live in registers.
        self.hoisted: set[ValueRef] = {address for root, (_subject, address) in self.tables.items() if root.block in self.in_loop}
        self.check_bound: dict[tuple[int, int], ValueRef] = {}
        bound_values: dict[int, ValueRef] = {}
        for block_index in sorted(self.in_loop):
            for node_index, node in enumerate(graph.blocks[block_index].nodes):
                if node.operation not in (Operation.CHECKED_LOAD_BITS_LE, Operation.CHECKED_STORE_BITS_LE):
                    continue
                if self.const(node.operands[1]) is not None or self._scaled(node) is not None or self._proven(node):
                    continue
                bound = pointer_extent_from_graph(graph, node.operands[0], self.resolve) - node.attributes[0]
                if bound < 0 or _addsub_immediate(bound) is not None:
                    continue
                if bound not in bound_values:
                    value = bound_values[bound] = ValueRef.node_result(block_index, node_index, 3)
                    self.constants[value], self.widths[value] = bound, 64
                    self.hoisted.add(value)
                self.check_bound[(block_index, node_index)] = bound_values[bound]
        # Hoist expensive constants used (unfolded) inside loops.
        for block_index, block in enumerate(graph.blocks):
            if block_index not in self.in_loop:
                continue
            candidates = []
            for node_index, node in enumerate(block.nodes):
                if node.operation in _CALLS:
                    continue
                for index, operand in enumerate(node.operands):
                    if self.const(operand) is not None and not self._folds(node, index) and self.canon(operand) in self.widths:
                        candidates.append(self.canon(operand))
            for node_index, node in enumerate(block.nodes):
                root = ValueRef.node_result(block_index, node_index)
                if root in self.member:
                    candidates.append(self.member[root][2])
            for value in candidates:
                if len(_move_immediate(0, self.constants[value], True)) >= 2:
                    self.hoisted.add(value)
        # Dead pure nodes (iterated: a dropped node reads nothing).
        self.dead: set[tuple[int, int]] = set()
        while True:
            read = Counter()
            for block_index, block in enumerate(graph.blocks):
                for node_index, node in enumerate(block.nodes):
                    if (block_index, node_index) not in self.dead:
                        read.update(self.reads(block_index, node_index, node))
                read.update(self.terminator_reads(block_index))
            changed = False
            for block_index, block in enumerate(graph.blocks):
                for node_index, node in enumerate(block.nodes):
                    if (block_index, node_index) in self.dead or node.operation not in _PURE:
                        continue
                    defined = self.defines(block_index, node_index, node)
                    if defined is not None and read[defined] == 0:
                        self.dead.add((block_index, node_index))
                        changed = True
            if not changed:
                break
        self.read_counts = read

    def _liveness(self) -> None:
        graph = self.graph
        count = len(graph.blocks)
        position = 0
        self.block_start, self.terminator_at, self.block_end, self.node_at = {}, {}, {}, {}
        self.calls_at: list[int] = []
        for block_index in self.order:
            block = graph.blocks[block_index]
            self.block_start[block_index] = position
            position += 1
            for node_index, node in enumerate(block.nodes):
                self.node_at[(block_index, node_index)] = position
                if node.operation in _CALLS and not (node.operation == Operation.CALL_DIRECT and _is_erased_proof_function(node.entity, self.resolve)):
                    self.calls_at.append(position)
                position += 2
            self.terminator_at[block_index] = position
            self.block_end[block_index] = position + 1
            position += 2
        uses_up: dict[int, set] = {}
        defs: dict[int, set] = {}
        for block_index, block in enumerate(graph.blocks):
            defined = {ValueRef.parameter(block_index, index) for index in range(len(block.parameters)) if ValueRef.parameter(block_index, index) in self.widths and ValueRef.parameter(block_index, index) not in self.alias}
            if block_index == graph.entry:
                defined |= self.hoisted
            upward = set()
            for node_index, node in enumerate(block.nodes):
                if (block_index, node_index) in self.dead:
                    continue
                upward |= {value for value in self.reads(block_index, node_index, node) if value not in defined}
                value = self.defines(block_index, node_index, node)
                if value is not None:
                    defined.add(value)
            upward |= {value for value in self.terminator_reads(block_index) if value not in defined}
            uses_up[block_index], defs[block_index] = upward, defined
        live_in = {index: set(uses_up[index]) for index in range(count)}
        live_out = {index: set() for index in range(count)}
        changed = True
        while changed:
            changed = False
            for block_index in reversed(self.order):
                out = set()
                for target, _arguments in graph.blocks[block_index].terminator.edges:
                    params = {ValueRef.parameter(target, index) for index in range(len(graph.blocks[target].parameters))}
                    out |= live_in[target] - params
                new_in = uses_up[block_index] | (out - defs[block_index])
                if out != live_out[block_index] or new_in != live_in[block_index]:
                    live_out[block_index], live_in[block_index] = out, new_in
                    changed = True
        self.live_in, self.live_out = live_in, live_out

    def _intervals(self) -> None:
        graph = self.graph
        intervals: dict[ValueRef, _Interval] = {}

        def interval(value: ValueRef) -> _Interval:
            if value not in intervals:
                intervals[value] = _Interval(value)
            return intervals[value]

        for block_index, block in enumerate(graph.blocks):
            factor = 10 ** min(self.depth.get(block_index, 0), 4)
            first: dict[ValueRef, int] = {}
            last: dict[ValueRef, int] = {}
            start = self.block_start[block_index]
            defined_at_start = [ValueRef.parameter(block_index, index) for index in range(len(block.parameters)) if ValueRef.parameter(block_index, index) in self.widths and ValueRef.parameter(block_index, index) not in self.alias]
            if block_index == graph.entry:
                defined_at_start += sorted(self.hoisted, key=lambda value: (value.block, value.index))
            for value in defined_at_start:
                first[value] = start
            for node_index, node in enumerate(block.nodes):
                if (block_index, node_index) in self.dead:
                    continue
                at = self.node_at[(block_index, node_index)]
                for value in self.reads(block_index, node_index, node):
                    last[value] = at
                    interval(value).weight += factor
                value = self.defines(block_index, node_index, node)
                if value is not None:
                    first.setdefault(value, at + 1)
                    last.setdefault(value, at + 1)
                    interval(value).weight += factor
            for value in self.terminator_reads(block_index):
                last[value] = self.terminator_at[block_index]
                interval(value).weight += factor
            for value in self.live_in[block_index]:
                first[value] = start
            for value in self.live_out[block_index]:
                last[value] = self.block_end[block_index]
            for value, end in last.items():
                interval(value).add(first.get(value, start), end)
            for value, begin in first.items():
                if value not in last and value in intervals:
                    interval(value).add(begin, begin)
        # A block parameter is written at the end of each predecessor (its edge copies).
        for block_index, block in enumerate(graph.blocks):
            for target, _arguments in block.terminator.edges:
                for index in range(len(graph.blocks[target].parameters)):
                    parameter = ValueRef.parameter(target, index)
                    if parameter in intervals:
                        intervals[parameter].add(self.block_end[block_index], self.block_end[block_index])
        for item in intervals.values():
            item.normalize()
            item.crosses = any(start < call < end for start, end in item.ranges for call in self.calls_at)
        self.intervals = intervals

    def _allocate(self) -> bool:
        graph = self.graph
        # Phi groups: a block parameter and its arguments prefer one register.
        parent: dict[ValueRef, ValueRef] = {}
        partners: dict[ValueRef, list[ValueRef]] = {}  # direct edge copies: parameter <-> argument

        def find(value: ValueRef) -> ValueRef:
            while parent.get(value, value) != value:
                value = parent[value]
            return value

        for block_index, block in enumerate(graph.blocks):
            for target, arguments in block.terminator.edges:
                for index, argument in enumerate(arguments):
                    parameter = ValueRef.parameter(target, index)
                    source = self.canon(argument)
                    if parameter in self.intervals and source in self.intervals:
                        partners.setdefault(parameter, []).append(source)
                        partners.setdefault(source, []).append(parameter)
                        a, b = find(parameter), find(source)
                        if a != b:
                            parent[a] = b
        hint: dict[ValueRef, int] = {}
        entry = graph.blocks[graph.entry]
        machine_index = 0
        for index, cid in enumerate(entry.parameters):
            parameter = ValueRef.parameter(graph.entry, index)
            if parameter in self.widths:
                hint[parameter] = machine_index
                machine_index += 1
        for block_index, block in enumerate(graph.blocks):
            for node_index, node in enumerate(block.nodes):
                if node.operation in _CALLS:
                    value = self.defines(block_index, node_index, node)
                    if value is not None:
                        hint[value] = 0
            if block.terminator.kind == TerminatorKind.RETURN:
                for value in self.terminator_reads(block_index):
                    hint.setdefault(value, 0)
        group_register: dict[ValueRef, int] = {}
        assigned: dict[int, list[_Interval]] = {}
        slots = 0
        ordered = sorted(self.intervals.values(), key=lambda item: (-item.weight, item.start, item.value.tag, item.value.block, item.value.index, item.value.result))
        for interval in ordered:
            group = find(interval.value)
            classes = _CALLEE if interval.crosses else (*_CALLER, *_CALLEE)
            conflicts = {register: [item for item in assigned.get(register, ()) if item.overlaps(interval)] for register in classes}
            free = [register for register in classes if not conflicts[register]]
            chosen = None
            # A copy partner's register, when free, removes that edge's move.
            partner_registers = [self.intervals[other].register for other in partners.get(interval.value, ())]
            for register in (group_register.get(group), *partner_registers, hint.get(interval.value)):
                if register is not None and register in free:
                    chosen = register
                    break
            if chosen is None and free:
                reserved = set(group_register.values())
                chosen = next((register for register in free if register not in reserved), free[0])
            if chosen is None:
                register = min(classes, key=lambda item: (sum(other.weight for other in conflicts[item]), item))
                if sum(other.weight for other in conflicts[register]) < interval.weight:
                    for other in conflicts[register]:
                        assigned[register].remove(other)
                        other.register, other.slot, slots = None, slots, slots + 1
                    chosen = register
                else:
                    interval.slot, slots = slots, slots + 1
            if chosen is not None:
                interval.register = chosen
                assigned.setdefault(chosen, []).append(interval)
                group_register.setdefault(group, chosen)
        self.spill_slots = slots
        return True

    # -- code generation ---------------------------------------------------------------
    def run(self):
        self._analyze()
        self._plan()
        self._liveness()
        self._intervals()
        self._allocate()
        used_callee = sorted({item.register for item in self.intervals.values() if item.register in _CALLEE})
        self.has_call = bool(self.calls_at)
        saved = used_callee + ([_LR] if self.has_call else [])
        # Saved registers sit at the bottom of the frame (pairs, the first one
        # allocating the frame with a pre-indexed ``stp``); spill slots follow.
        self.save_base = 0
        self.spill_base = 8 * len(saved)
        self.frame = (self.spill_base + 8 * self.spill_slots + 15) & ~15
        if self.frame >= 4096:
            return None
        self.saved = saved
        asm = self.asm = _Assembler()
        asm.emit(*self._prologue())
        self._entry_moves()
        if self.order[0] != self.graph.entry:
            asm.branch(0x14000000, ("block", self.graph.entry), 26)
        self.stubs: list[tuple[object, list, object]] = []
        self.traps: dict[int, object] = {}
        node_ranges: list[ArtifactSemanticRange] = []
        for position, block_index in enumerate(self.order):
            self.following = self.order[position + 1] if position + 1 < len(self.order) else None
            self._block(block_index, node_ranges)
        for label, moves, target in self.stubs:
            asm.label(label)
            self._parallel(moves)
            asm.branch(0x14000000, ("block", target), 26)
        for code, label in sorted(self.traps.items(), key=lambda item: item[0]):
            asm.label(label)
            asm.emit(_brk(code))
        referenced = {label for _position, label, _kind in asm.fixups}
        for address in sorted(self.table_data, key=lambda item: (item.block, item.index)):
            if ("table", address) in referenced:
                asm.label(("table", address))
                asm.code.extend(self.table_data[address])
        asm.code.extend(bytes(-len(asm.code) % 4))
        return asm.finish(), tuple(asm.calls), tuple(asm.foreign_calls), (), tuple(node_ranges)

    def _prologue(self) -> list[int]:
        frame, saved, words = self.frame, self.saved, []
        pairs = [saved[index:index + 2] for index in range(0, len(saved), 2)]
        if pairs and len(pairs[0]) == 2 and frame <= 504:
            first, second = pairs[0]
            words.append(0xA9800000 | (((-frame // 8) & 0x7F) << 15) | (second << 10) | (_SP << 5) | first)  # stp, pre-index
            rest = pairs[1:]
            offset = 16
        else:
            if frame:
                words.append(0xD1000000 | (frame << 10) | (_SP << 5) | _SP)
            rest, offset = pairs, 0
        for pair in rest:
            if len(pair) == 2:
                words.append(0xA9000000 | ((offset // 8) << 15) | (pair[1] << 10) | (_SP << 5) | pair[0])  # stp
            else:
                words.append(_access(False, pair[0], _SP, offset, 8))
            offset += 8 * len(pair)
        return words

    def _epilogue(self) -> list[int]:
        frame, saved, words = self.frame, self.saved, []
        pairs = [saved[index:index + 2] for index in range(0, len(saved), 2)]
        folded = bool(pairs) and len(pairs[0]) == 2 and frame <= 504
        offset = 16 if folded else 0
        for pair in pairs[1:] if folded else pairs:
            if len(pair) == 2:
                words.append(0xA9400000 | ((offset // 8) << 15) | (pair[1] << 10) | (_SP << 5) | pair[0])  # ldp
            else:
                words.append(_access(True, pair[0], _SP, offset, 8))
            offset += 8 * len(pair)
        if folded:
            first, second = pairs[0]
            words.append(0xA8C00000 | ((frame // 8) << 15) | (second << 10) | (_SP << 5) | first)  # ldp, post-index
        elif frame:
            words.append(0x91000000 | (frame << 10) | (_SP << 5) | _SP)
        return words

    def location(self, value: ValueRef):
        interval = self.intervals[value]
        if interval.register is not None:
            return ("reg", interval.register)
        return ("slot", self.spill_base + 8 * interval.slot)

    def source(self, operand: ValueRef):
        value = self.canon(operand)
        if value in self.constants and value not in self.hoisted:
            return ("const", self.constants[value])
        if value in self.table_data and value not in self.hoisted:
            return ("table", value)
        return self.location(value)

    def _trap(self, code: int) -> object:
        return self.traps.setdefault(code, ("trap", code))

    def _entry_moves(self) -> None:
        moves = []  # (destination, source register, parameter)
        for machine_index, parameter in enumerate(self._entry_parameters()):
            if parameter in self.intervals:
                moves.append((self.location(parameter), ("reg", machine_index), parameter))
        narrow = {parameter for _d, _s, parameter in moves if self.widths[parameter] < 64}
        # A narrow parameter moving register to register zero-extends in the move itself, after
        # the other copies, when no other copy reads its destination or writes its source.
        fused = []
        for move in moves:
            destination, source, parameter = move
            others = [item for item in moves if item is not move]
            if (
                parameter in narrow and destination[0] == "reg" and destination != source
                and destination not in {item[1] for item in others} and source not in {item[0] for item in others}
            ):
                fused.append(move)
        self._parallel([(d, s) for d, s, parameter in moves if (d, s, parameter) not in fused])
        for destination, source, parameter in fused:
            self.asm.emit(*_mask(destination[1], source[1], self.widths[parameter]))
        for destination, _source, parameter in moves:
            if parameter not in narrow or (destination, _source, parameter) in fused:
                continue
            if destination[0] == "reg":
                self.asm.emit(*_mask(destination[1], destination[1], self.widths[parameter]))
            else:
                where = destination[1]
                self.asm.emit(_access(True, _TRANSFER, _SP, where, 8), *_mask(_TRANSFER, _TRANSFER, self.widths[parameter]), _access(False, _TRANSFER, _SP, where, 8))
        for value in sorted(self.hoisted, key=lambda item: (item.block, item.index, item.result)):
            if value not in self.intervals:
                continue
            if value in self.table_data:
                kind, where = self.location(value)
                register = where if kind == "reg" else _TRANSFER
                self.asm.branch(0x10000000 | register, ("table", value), 21)  # adr
                if kind == "slot":
                    self.asm.emit(_access(False, register, _SP, where, 8))
            else:
                self._parallel([(self.location(value), ("const", self.constants[value]))])

    def _entry_parameters(self) -> list[ValueRef]:
        entry = self.graph.blocks[self.graph.entry]
        return [ValueRef.parameter(self.graph.entry, index) for index in range(len(entry.parameters)) if ValueRef.parameter(self.graph.entry, index) in self.widths]

    def _transfer(self, destination, source, scratch: int) -> None:
        """One move between locations (``reg``/``slot``/``const``)."""
        asm = self.asm
        if destination == source:
            return
        if destination[0] == "reg":
            if source[0] == "reg":
                asm.emit(_mov(destination[1], source[1]))
            elif source[0] == "slot":
                asm.emit(_access(True, destination[1], _SP, source[1], 8))
            else:
                asm.emit(*_move_immediate(destination[1], source[1], True))
            return
        if source[0] == "reg":
            asm.emit(_access(False, source[1], _SP, destination[1], 8))
            return
        if source[0] == "slot":
            asm.emit(_access(True, scratch, _SP, source[1], 8))
        else:
            if source[1] == 0:
                asm.emit(_access(False, _ZR, _SP, destination[1], 8))
                return
            asm.emit(*_move_immediate(scratch, source[1], True))
        asm.emit(_access(False, scratch, _SP, destination[1], 8))

    def _parallel(self, moves) -> None:
        pending = [(d, s) for d, s in moves if d != s]
        while pending:
            sources = {s for _d, s in pending if s[0] != "const"}
            index = next((i for i, (d, _s) in enumerate(pending) if d not in sources), None)
            if index is not None:
                destination, source = pending.pop(index)
                self._transfer(destination, source, _TRANSFER)
                continue
            destination, source = pending[0]
            self._transfer(("reg", _CYCLE), source, _TRANSFER)
            pending = [(d, ("reg", _CYCLE) if s == source else s) for d, s in pending]

    # Register access within one node ---------------------------------------------------
    def _begin(self) -> None:
        self.free_scratch = list(_SCRATCH)

    def _scratch(self) -> int:
        return self.free_scratch.pop(0)

    def read(self, operand: ValueRef) -> int:
        kind, where = self.source(operand)
        if kind == "reg":
            return where
        register = self._scratch()
        if kind == "slot":
            self.asm.emit(_access(True, register, _SP, where, 8))
        elif kind == "table":
            self.asm.branch(0x10000000 | register, ("table", where), 21)  # adr
        elif where == 0:
            self.free_scratch.insert(0, register)
            return _ZR
        else:
            self.asm.emit(*_move_immediate(register, where, True))
        return register

    def read_source(self, operand: ValueRef) -> int:
        """``read`` for an add/sub/compare immediate form, where register 31 is SP, not the zero register."""
        register = self.read(operand)
        if register == _ZR:
            register = self._scratch()
            self.asm.emit(*_move_immediate(register, 0, True))
        return register

    def target_register(self, value: ValueRef) -> int:
        kind, where = self.location(value)
        return where if kind == "reg" else self._scratch()

    def commit(self, value: ValueRef, register: int) -> None:
        kind, where = self.location(value)
        if kind == "slot":
            self.asm.emit(_access(False, register, _SP, where, 8))
        elif where != register:
            self.asm.emit(_mov(where, register))

    def _block(self, block_index: int, node_ranges: list) -> None:
        asm, block = self.asm, self.graph.blocks[block_index]
        asm.label(("block", block_index))
        for node_index, node in enumerate(block.nodes):
            if (block_index, node_index) in self.dead:
                continue
            start = len(asm.code)
            self._begin()
            self._node(block_index, node_index, node)
            if len(asm.code) > start:
                node_ranges.append(ArtifactSemanticRange(self.function.cid, block_index, node_index, start, len(asm.code)))
        self._begin()
        self._terminator(block_index)

    def _node(self, block_index: int, node_index: int, node) -> None:
        op, asm = node.operation, self.asm
        result = self.defines(block_index, node_index, node)
        if op in (Operation.CONSTANT, Operation.POINTER_CAST, Operation.POINTER_ADDRESS, Operation.INT_ZERO_EXTEND, Operation.STACK_END) or op in RESOURCE_EFFECT_OPERATIONS:
            return
        if node_index == self.fused.get(block_index):
            return
        if op == Operation.INT_TRUNCATE:
            if result is None:
                return
            source = self.read(node.operands[0])
            destination = self.target_register(result)
            asm.emit(*_mask(destination, source, self.widths[result]))
            self.commit(result, destination)
            return
        if result in self.tables:
            subject, address = self.tables[result]
            index, table = self.read(subject), self.read(address)
            destination = self.target_register(result)
            asm.emit(_indexed(True, destination, table, index, 1, False))  # ldrb destination, [table, subject]
            self.commit(result, destination)
            return
        if result in self.member:
            # Bit test without flags: (mask >> (x - low)) & 1, and 0 unless 0 <= x - low < 64
            # (((x - low) >> 6) - 1) >> 63 is 1 exactly then).
            subject, low, mask = self.member[result]
            offset = self.read_source(subject)
            if low:
                source, offset = offset, (offset if offset in _SCRATCH else self._scratch())
                immediate = _addsub_immediate(low)
                if immediate is not None:
                    asm.emit(_addsub_imm(True, True, offset, source, immediate))
                else:
                    asm.emit(*_move_immediate(offset, low, True), _three(*_SUB, True, offset, source, offset))
            mask_register = self.read(mask)
            guard = self._scratch()
            asm.emit(_lsr(guard, offset, 6, True), _addsub_imm(True, True, guard, guard, (1, 0)), _lsr(guard, guard, 63, True))
            destination = self.target_register(result)
            asm.emit(0x9AC02400 | (offset << 16) | (mask_register << 5) | destination)  # lsrv
            asm.emit(_three(*_AND, True, destination, destination, guard))
            self.commit(result, destination)
            return
        if result in self.bic:
            keep, clear = (self.read(item) for item in self.bic[result])
            destination = self.target_register(result)
            asm.emit(0x8A200000 | (clear << 16) | (keep << 5) | destination)  # bic: keep & ~clear
            self.commit(result, destination)
            return
        if op in (Operation.ADD_WRAP, Operation.SUB_WRAP, Operation.MUL_WRAP, Operation.BIT_AND, Operation.BIT_OR, Operation.BIT_XOR):
            self._binary(node, result)
            return
        if op in (Operation.UDIV, Operation.UREM):
            self._divide(node, result)
            return
        if op == Operation.INT_COMPARE:
            condition = self._compare(node)
            destination = self.target_register(result)
            asm.emit(_cset(destination, condition))
            self.commit(result, destination)
            return
        if op == Operation.ROTATE_RIGHT:
            width, amount = self.widths[result], node.attributes[0] % self.widths[result]
            source = self.read(node.operands[0])
            destination = self.target_register(result)
            if amount == 0:
                if destination != source:
                    asm.emit(_mov(destination, source))
            elif width in (32, 64):
                asm.emit(_ror(destination, source, amount, width == 64))
            else:
                temporary = self._scratch()
                asm.emit(_lsr(temporary, source, amount, True), _lsl(destination, source, width - amount, True))
                asm.emit(_three(*_ORR, True, destination, destination, temporary), *_mask(destination, destination, width))
            self.commit(result, destination)
            return
        if op == Operation.ADDRESS_OFFSET:
            base = self.read_source(node.operands[0])
            destination = self.target_register(result)
            offset = node.attributes[0]
            immediate = _addsub_immediate(offset)
            if immediate is not None:
                asm.emit(_addsub_imm(False, True, destination, base, immediate))
            else:
                temporary = self._scratch()
                asm.emit(*_move_immediate(temporary, offset, True), _three(*_ADD, True, destination, base, temporary))
            self.commit(result, destination)
            return
        if op == Operation.HEAP_VIEW:
            raw = self.read(node.operands[0])
            asm.branch(0xB4000000 | raw, self._trap(_BRK_NULL_HEAP), 19)  # cbz
            return
        if op == Operation.POINTER_REBASE:
            view, address = node.operands
            span = pointer_extent_from_graph(self.graph, view, self.resolve) - node.attributes[0]
            shift = _decode_pointer_type(self.resolve(node.results[0]), self.resolve)[2].bit_length() - 1
            if span < 0:
                asm.branch(0x14000000, self._trap(_BRK_MEMORY_CHECK), 26)
                return
            address_register, view_register = self.read(address), self.read(view)
            distance = self._scratch()
            asm.emit(_three(*_SUB, True, distance, address_register, view_register))
            if shift:
                asm.emit(_ror(distance, distance, shift, True))
            self._compare_constant(distance, span >> shift)
            asm.branch(0x54000000 | 8, self._trap(_BRK_MEMORY_CHECK), 19)  # b.hi
            return
        if op in (Operation.LOAD_BITS_LE, Operation.RAW_LOAD_BITS_LE):
            base = self.read(node.operands[0])
            destination = self.target_register(result)
            asm.emit(_access(True, destination, base, 0, node.attributes[0]))
            self.commit(result, destination)
            return
        if op == Operation.STORE_BITS_LE:
            base = self.read(node.operands[0])
            value = self.read(node.operands[1])
            asm.emit(_access(False, value, base, 0, node.attributes[0]))
            return
        if op in (Operation.CHECKED_LOAD_BITS_LE, Operation.CHECKED_STORE_BITS_LE):
            self._checked(block_index, node_index, node, result)
            return
        if op in _CALLS:
            self._call(node, result)
            return
        raise AssertionError(op)

    def _compare_constant(self, register: int, value: int) -> None:
        immediate = _addsub_immediate(value)
        if immediate is not None:
            self.asm.emit(_cmp_imm(True, register, immediate))
        else:
            temporary = self._scratch()
            self.asm.emit(*_move_immediate(temporary, value, True), _cmp_reg(True, register, temporary))

    def _binary(self, node, result: ValueRef) -> None:
        asm, op = self.asm, node.operation
        width = self.widths[result]
        wide = width > 32
        left, right = node.operands
        folds_right, folds_left = self._folds(node, 1), self._folds(node, 0)
        if op != Operation.SUB_WRAP and folds_left and not folds_right:
            left, right = right, left
            folds_right = True
        constant = self.const(right) if folds_right else None
        destination = None
        if constant is not None:
            source = self.read_source(left) if op in (Operation.ADD_WRAP, Operation.SUB_WRAP) else self.read(left)
            destination = self.target_register(result)
            if constant == 0:
                if op == Operation.MUL_WRAP or op == Operation.BIT_AND:
                    asm.emit(_mov(destination, _ZR))
                elif destination != source:
                    asm.emit(_mov(destination, source))
                self.commit(result, destination)
                return
            if op in (Operation.ADD_WRAP, Operation.SUB_WRAP):
                subtract = op == Operation.SUB_WRAP
                immediate = _addsub_immediate(constant)
                if immediate is None:
                    constant = (-constant) % (1 << (64 if wide else 32))
                    immediate, subtract = _addsub_immediate(constant), not subtract
                asm.emit(_addsub_imm(subtract, wide, destination, source, immediate))
            elif op == Operation.MUL_WRAP:
                shift = constant.bit_length() - 1
                if shift:
                    asm.emit(_lsl(destination, source, shift, wide))
                elif destination != source:
                    asm.emit(_mov(destination, source))
            else:
                encoded = _logical_immediate(constant, wide)
                asm.emit(_LOGIC_IMM[op][1 if wide else 0] | (encoded << 10) | (source << 5) | destination)
        else:
            left_register, right_register = self.read(left), self.read(right)
            destination = self.target_register(result)
            table = {Operation.ADD_WRAP: _ADD, Operation.SUB_WRAP: _SUB, Operation.MUL_WRAP: _MUL, **_LOGIC_REG}[op]
            asm.emit(_three(*table, wide, destination, left_register, right_register))
        if width not in (32, 64) and op in (Operation.ADD_WRAP, Operation.SUB_WRAP, Operation.MUL_WRAP):
            asm.emit(*_mask(destination, destination, width))
        self.commit(result, destination)

    def _divide(self, node, result: ValueRef) -> None:
        asm = self.asm
        width = self.widths[result]
        wide = width > 32
        dividend = self.read(node.operands[0])
        constant = self.const(node.operands[1])
        destination = self.target_register(result)
        if constant is not None and constant and constant & (constant - 1) == 0:
            shift = constant.bit_length() - 1
            if node.operation == Operation.UDIV:
                asm.emit(_lsr(destination, dividend, shift, wide) if shift else _mov(destination, dividend))
            elif shift:
                asm.emit(*_mask(destination, dividend, shift))
            else:
                asm.emit(_mov(destination, _ZR))
            self.commit(result, destination)
            return
        divisor = self.read(node.operands[1])
        if constant is None:
            asm.branch((0xB4000000 if wide else 0x34000000) | divisor, self._trap(_BRK_DIVIDE_BY_ZERO), 19)
        if constant == 0:
            asm.branch(0x14000000, self._trap(_BRK_DIVIDE_BY_ZERO), 26)
        if node.operation == Operation.UDIV:
            asm.emit((0x9AC00800 if wide else 0x1AC00800) | (divisor << 16) | (dividend << 5) | destination)
        else:
            quotient = self._scratch()
            asm.emit((0x9AC00800 if wide else 0x1AC00800) | (divisor << 16) | (dividend << 5) | quotient)
            asm.emit((0x9B008000 if wide else 0x1B008000) | (divisor << 16) | (dividend << 10) | (quotient << 5) | destination)
        self.commit(result, destination)

    def _compare(self, node) -> int:
        """Emit the flag-setting compare; return the condition code."""
        asm = self.asm
        kind = IntCompare(node.attributes[0])
        left, right = node.operands
        width = self.width(left) if self.canon(left) in self.widths or left in self.widths else 64
        if self._folds(node, 0) and not self._folds(node, 1):
            left, right, kind = right, left, _SWAPPED[kind]
        wide = width > 32
        left_register = self.read_source(left)
        if kind in _SIGNED and width not in (32, 64):
            right_register = self.read(right)
            a = left_register if left_register in _SCRATCH else self._scratch()
            b = right_register if right_register in _SCRATCH and right_register != a else self._scratch()
            asm.emit(_sbfx(a, left_register, width), _sbfx(b, right_register, width), _cmp_reg(True, a, b))
            return _COND[kind]
        constant = self.const(right)
        if constant is not None and (constant == 0 or _addsub_immediate(constant) is not None) and self._folds(node, 1 if right == node.operands[1] else 0):
            if constant == 0:
                asm.emit(_cmp_reg(wide, left_register, _ZR))
            else:
                asm.emit(_cmp_imm(wide, left_register, _addsub_immediate(constant)))
        else:
            asm.emit(_cmp_reg(wide, left_register, self.read(right)))
        return _COND[kind]

    def _checked(self, block_index: int, node_index: int, node, result) -> None:
        asm = self.asm
        size = node.attributes[0]
        extent = pointer_extent_from_graph(self.graph, node.operands[0], self.resolve)
        bound = extent - size
        load = node.operation == Operation.CHECKED_LOAD_BITS_LE
        index_constant = self.const(node.operands[1])
        if bound < 0 or (index_constant is not None and index_constant > bound):
            asm.branch(0x14000000, self._trap(_BRK_MEMORY_CHECK), 26)
            return
        base = self.read(node.operands[0])
        value = None if load else self.read(node.operands[2])
        if index_constant is not None and index_constant % size == 0 and index_constant // size < 4096:
            if load:
                destination = self.target_register(result)
                asm.emit(_access(True, destination, base, index_constant, size))
                self.commit(result, destination)
            else:
                asm.emit(_access(False, value, base, index_constant, size))
            return
        scaled = self._scaled(node)
        if scaled is not None:
            index, shifted = self.read(scaled[0]), True
        else:
            index, shifted = self.read(node.operands[1]), False
            if (block_index, node_index) in self.check_bound:
                asm.emit(_cmp_reg(True, index, self.read(self.check_bound[(block_index, node_index)])))
                asm.branch(0x54000000 | 8, self._trap(_BRK_MEMORY_CHECK), 19)  # b.hi
            elif not self._proven(node):
                self._compare_constant(index, bound)
                asm.branch(0x54000000 | 8, self._trap(_BRK_MEMORY_CHECK), 19)  # b.hi
        if load:
            destination = self.target_register(result)
            asm.emit(_indexed(True, destination, base, index, size, shifted))
            self.commit(result, destination)
        else:
            asm.emit(_indexed(False, value, base, index, size, shifted))

    def _call(self, node, result) -> None:
        asm = self.asm
        if node.operation == Operation.CALL_DIRECT and _is_erased_proof_function(node.entity, self.resolve):
            return
        machine = [operand for operand, cid in zip(node.operands, node.operand_types) if _machine_width(self.resolve, cid) is not None]
        self._parallel([(("reg", index), self.source(operand)) for index, operand in enumerate(machine)])
        if node.operation == Operation.CALL_DIRECT:
            asm.calls.append((len(asm.code), node.entity.cid))
            asm.emit(0x94000000)
        else:
            declaration = decode_foreign_function(node.entity)
            from xax_aarch64 import _require_foreign_abi

            _require_foreign_abi(declaration, self.target, self.graph_object)
            asm.foreign_calls.append((len(asm.code), declaration.library, declaration.name))
            asm.emit(0x94000000)
        if result is not None and self.read_counts[result]:  # an unread result needs no copy or mask
            width = self.widths[result]
            kind, where = self.location(result)
            register = where if kind == "reg" else _TRANSFER
            asm.emit(*_mask(register, 0, width))  # a narrower result is masked whatever the callee's ABI
            if kind == "slot":
                asm.emit(_access(False, register, _SP, where, 8))

    def _edge_moves(self, block_index: int, edge: int):
        target, arguments = self.graph.blocks[block_index].terminator.edges[edge]
        moves = []
        for index, argument in enumerate(arguments):
            parameter = ValueRef.parameter(target, index)
            if parameter in self.intervals:
                moves.append((self.location(parameter), self.source(argument)))
        return target, [(d, s) for d, s in moves if d != s]

    def _terminator(self, block_index: int) -> None:
        asm, terminator = self.asm, self.graph.blocks[block_index].terminator
        following = self.following
        if terminator.kind == TerminatorKind.RETURN:
            machine = [value for index, (value, cid) in enumerate(zip(terminator.values, self.return_types))
                       if _machine_width(self.resolve, cid) is not None and index not in self.own_elided]
            if machine:
                self._parallel([(("reg", 0), self.source(machine[0]))])
            asm.emit(*self._epilogue(), 0xD65F03C0)
            return
        if terminator.kind == TerminatorKind.TRAP:
            reason, _ = decode_trap_payload(terminator.payload)
            asm.emit(*_move_immediate(0, reason, True), _brk(reason & 0xFFFF))
            return
        if terminator.kind == TerminatorKind.BRANCH:
            target, moves = self._edge_moves(block_index, 0)
            self._parallel(moves)
            if target != following and target != block_index and self._duplicable(target):
                # The target is a short test (a loop header, typically): run it here, so a loop
                # ends in its own conditional branch instead of a jump back to the test.
                for node_index, node in enumerate(self.graph.blocks[target].nodes):
                    if (target, node_index) not in self.dead:
                        self._begin()
                        self._node(target, node_index, node)
                self._begin()
                self._conditional(target, following)
            elif target != following:
                asm.branch(0x14000000, ("block", target), 26)
            return
        self._conditional(block_index, following)

    def _duplicable(self, block_index: int) -> bool:
        """A conditional block of at most _DUPLICATE_LIMIT code-emitting nodes and no calls."""
        block = self.graph.blocks[block_index]
        if block.terminator.kind != TerminatorKind.CONDITIONAL_BRANCH:
            return False
        emitting = [
            node for index, node in enumerate(block.nodes)
            if index != self.fused.get(block_index) and (block_index, index) not in self.dead
            and node.operation not in _NO_CODE and node.operation not in RESOURCE_EFFECT_OPERATIONS
        ]
        return len(emitting) <= _DUPLICATE_LIMIT and not any(node.operation in _CALLS for node in emitting)

    def _through(self, target: int) -> int:
        """Where a branch to ``target`` can go directly: past blocks that emit nothing and branch on without copies."""
        seen = set()
        while target not in seen:
            seen.add(target)
            block = self.graph.blocks[target]
            if block.terminator.kind != TerminatorKind.BRANCH or not all(
                (target, index) in self.dead or node.operation in _NO_CODE or node.operation in RESOURCE_EFFECT_OPERATIONS
                for index, node in enumerate(block.nodes)
            ):
                break
            successor, moves = self._edge_moves(target, 0)
            if moves:
                break
            target = successor
        return target

    def _conditional(self, block_index: int, following) -> None:
        asm, terminator = self.asm, self.graph.blocks[block_index].terminator
        block = self.graph.blocks[block_index]
        true_target, true_moves = self._edge_moves(block_index, 0)
        false_target, false_moves = self._edge_moves(block_index, 1)
        fused = block_index in self.fused
        compare = block.nodes[self.fused[block_index]] if fused else None
        condition_values = self.terminator_reads(block_index) if fused else tuple(
            value for value in (self._located(terminator.values[0]),) if value is not None
        )
        # Copies for the taken edge run before the test when nothing the test or the
        # other path reads lives where they write: the branch then goes straight to its block.
        if true_moves and true_target != following:
            written = {destination for destination, _source in true_moves}
            read = {source for _destination, source in false_moves if source[0] != "const"}
            read |= {self.location(value) for value in self.live_in[false_target] if value in self.intervals}
            read |= {self.location(value) for value in condition_values if value in self.intervals}
            if not written & read and not ({("reg", _CYCLE), ("reg", _TRANSFER)} & read):
                self._parallel(true_moves)
                true_moves = []
        if fused:
            condition = self._compare(compare)

            def jump(when_true: bool, label) -> None:
                asm.branch(0x54000000 | (condition if when_true else condition ^ 1), label, 19)
        else:
            register = self.read(terminator.values[0])

            def jump(when_true: bool, label) -> None:
                asm.branch((0x35000000 if when_true else 0x34000000) | register, label, 19)

        def stub(target: int, moves) -> object:
            if not moves:
                return ("block", self._through(target))
            label = ("stub", block_index, target, len(self.stubs), len(asm.code))
            self.stubs.append((label, moves, target))
            return label

        if true_target == following and not true_moves:
            jump(False, stub(false_target, false_moves))
            return
        jump(True, stub(true_target, true_moves))
        self._parallel(false_moves)
        if false_target != following:
            asm.branch(0x14000000, ("block", false_target), 26)
