"""Direct WebAssembly core-module backend for the verified XAX prototype."""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass
from math import log2
from typing import Callable, Sequence

from xax_artifact import ArtifactSemanticRange

from xax_compiler import (
    _decode_pointer_type,
    store_resolver,
    FloatCompare,
    IntCompare,
    Kind,
    Operation,
    RESOURCE_EFFECT_OPERATIONS,
    SemanticObject,
    StoreReader,
    TerminatorKind,
    ValueRef,
    _decode_constant,
    _float_raw_bits,
    _int_to_float,
    _decode_function_interface,
    _is_proof_type,
    _is_erased_proof_function,
    _parse_graph,
    WASM32_WASI_IDENTITY,
    abi_layout,
    decode_foreign_function,
    decode_bits_width,
    decode_float_width,
    decode_native_target,
    fail,
    uleb,
    verify_store,
)


@dataclass(frozen=True)
class WasmImage:
    module: bytes
    entry_offset: int
    parameter_widths: tuple[int, ...]
    return_widths: tuple[int, ...]
    target_cid: bytes
    function_indices: tuple[tuple[bytes, int], ...]
    semantic_ranges: tuple[ArtifactSemanticRange, ...] = ()
    parameter_kinds: tuple[str, ...] = ()
    return_kinds: tuple[str, ...] = ()

    @property
    def artifact_bytes(self) -> bytes:
        return self.module


def _section(section_id: int, payload: bytes) -> bytes:
    return bytes((section_id,)) + uleb(len(payload)) + payload


def _vector(items: Sequence[bytes]) -> bytes:
    return uleb(len(items)) + b"".join(items)


def _sleb(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        done = (value == 0 and not byte & 0x40) or (value == -1 and byte & 0x40)
        out.append(byte | (0 if done else 0x80))
        if done:
            return bytes(out)


def _form(resolve: Callable[[bytes], SemanticObject], cid: bytes) -> int | None:
    obj = resolve(cid)
    return obj.body[0] if obj.kind == Kind.TYPE and obj.body else None


def _width(resolve: Callable[[bytes], SemanticObject], cid: bytes) -> int | None:
    form = _form(resolve, cid)
    if form == 1:
        return decode_bits_width(resolve(cid))
    if form == 7:
        return decode_float_width(resolve(cid))
    if form in (2, 11):
        return 32  # pointers and link values are wasm32 addresses (links occupy 8 bytes in memory)
    if form in (8, 9, 10):
        return 32  # internal ABI pointer to C-layout bytes in linear memory
    return None


def _kind(resolve: Callable[[bytes], SemanticObject], cid: bytes) -> str | None:
    form = _form(resolve, cid)
    if form == 1:
        return "i"
    if form == 7:
        return "f"
    if form in (2, 11):
        return "p"
    if form in (8, 9, 10):
        return "a"
    return None


def _valtype_for_cid(resolve: Callable[[bytes], SemanticObject], cid: bytes) -> int | None:
    form = _form(resolve, cid)
    if form == 1:
        return 0x7F if decode_bits_width(resolve(cid)) <= 32 else 0x7E
    if form == 7:
        return 0x7D if decode_float_width(resolve(cid)) == 32 else 0x7C
    if form in (2, 8, 9, 10, 11):
        return 0x7F
    return None


def _function_closure(
    entry: SemanticObject,
    resolve: Callable[[bytes], SemanticObject],
    supported_operations: tuple[int, ...],
    supported_terminators: tuple[int, ...],
) -> tuple[SemanticObject, ...]:
    functions: dict[bytes, SemanticObject] = {}
    active: set[bytes] = set()

    def visit(function: SemanticObject) -> None:
        if function.cid in active:
            fail("XAX.WASM.RECURSION", function.cid.hex(), "WASM-DIRECT-CALL-ACYCLIC", "acyclic calls", "cycle")
        if function.cid in functions:
            return
        active.add(function.cid)
        graph_object, parameters, returns = _decode_function_interface(function, resolve)
        machine_parameters = tuple(cid for cid in parameters if not _is_proof_type(resolve(cid)))
        machine_returns = tuple(cid for cid in returns if not _is_proof_type(resolve(cid)))
        if len(machine_returns) > 1 or any(_valtype_for_cid(resolve, cid) is None for cid in (*machine_parameters, *machine_returns)):
            fail("XAX.WASM.ABI", function.cid.hex(), "WASM-ABI-VALUE", "bits, float, pointer, or aggregate; at most one return", [cid.hex() for cid in (*parameters, *returns)])
        graph = _parse_graph(graph_object, resolve)
        for block in graph.blocks:
            for node in block.nodes:
                if node.operation not in supported_operations:
                    fail("XAX.WASM.UNSUPPORTED_OPERATION", graph_object.cid.hex(), "WASM-OP-TARGET-SUPPORTED", list(supported_operations), node.operation)
                if node.operation == Operation.CALL_DIRECT:
                    if not _is_erased_proof_function(node.entity, resolve):
                        visit(node.entity)
            if block.terminator.kind not in supported_terminators:
                fail("XAX.WASM.UNSUPPORTED_TERMINATOR", graph_object.cid.hex(), "WASM-TERMINATOR-TARGET-SUPPORTED", list(supported_terminators), block.terminator.kind)
        active.remove(function.cid)
        functions[function.cid] = function

    visit(entry)
    return tuple(functions[cid] for cid in sorted(functions))


_NULL_GUARD_BYTES = 16


def _memory_layout(
    functions: Sequence[SemanticObject], resolve: Callable[[bytes], SemanticObject]
) -> tuple[dict[tuple[bytes, int, int], int], dict[tuple[bytes, int, int, int, int], int], int]:
    stack_addresses: dict[tuple[bytes, int, int], int] = {}
    aggregate_addresses: dict[tuple[bytes, int, int, int, int], int] = {}
    # Address 0 is never storage, so an exposed storage address is never the
    # null link a program may use as a terminator (ADR-092).
    cursor = _NULL_GUARD_BYTES
    for function in functions:
        graph_object, _, _ = _decode_function_interface(function, resolve)
        graph = _parse_graph(graph_object, resolve)
        for block_index, block in enumerate(graph.blocks):
            for node_index, node in enumerate(block.nodes):
                if node.operation == Operation.STACK_ALLOC:
                    extent, alignment = node.attributes
                    cursor = (cursor + alignment - 1) & -alignment
                    stack_addresses[(function.cid, block_index, node_index)] = cursor
                    cursor += extent
                for result_index, cid in enumerate(node.results):
                    if _kind(resolve, cid) != "a":
                        continue
                    layout = abi_layout(resolve(cid), resolve, pointer_bytes=4)
                    cursor = (cursor + layout.alignment - 1) & -layout.alignment
                    aggregate_addresses[(function.cid, 1, block_index, node_index, result_index)] = cursor
                    cursor += layout.size
    if cursor > 65536:
        fail("XAX.WASM.MEMORY", "module", "WASM-STATIC-MEMORY-LIMIT", "<= 65536 bytes", cursor)
    return stack_addresses, aggregate_addresses, cursor


def _compile_function(
    function: SemanticObject,
    resolve: Callable[[bytes], SemanticObject],
    function_indices: dict[bytes, int],
    import_indices: dict[bytes, int],
    stack_addresses: dict[tuple[bytes, int, int], int],
    aggregate_addresses: dict[tuple[bytes, int, int, int, int], int],
) -> tuple[bytes, tuple[ArtifactSemanticRange, ...]]:
    graph_object, parameter_types, return_types = _decode_function_interface(function, resolve)
    graph = _parse_graph(graph_object, resolve)
    locals_: list[int] = []
    slots: dict[ValueRef, int] = {}
    machine_parameter_count = sum(not _is_proof_type(resolve(cid)) for cid in parameter_types)

    def value_type(ref: ValueRef) -> bytes:
        if ref.tag == 0:
            return graph.blocks[ref.block].parameters[ref.index]
        return graph.blocks[ref.block].nodes[ref.index].results[ref.result]

    machine_index = 0
    for index, type_cid in enumerate(graph.blocks[graph.entry].parameters):
        if _is_proof_type(resolve(type_cid)):
            continue
        valtype = _valtype_for_cid(resolve, type_cid)
        if valtype is None:
            fail("XAX.WASM.BLOCK_TYPE", graph_object.cid.hex(), "WASM-BLOCK-PARAMETER-VALUE", "machine value", type_cid.hex())
        slots[ValueRef.parameter(graph.entry, index)] = machine_index
        machine_index += 1

    def add_slot(value: ValueRef, type_cid: bytes) -> None:
        valtype = _valtype_for_cid(resolve, type_cid)
        if valtype is not None:
            slots[value] = machine_parameter_count + len(locals_)
            locals_.append(valtype)

    for block_index, block in enumerate(graph.blocks):
        if block_index != graph.entry:
            for index, type_cid in enumerate(block.parameters):
                if not _is_proof_type(resolve(type_cid)):
                    add_slot(ValueRef.parameter(block_index, index), type_cid)
        for node_index, node in enumerate(block.nodes):
            for result_index, type_cid in enumerate(node.results):
                if not _is_proof_type(resolve(type_cid)):
                    add_slot(ValueRef.node_result(block_index, node_index, result_index), type_cid)

    temporary_slots: dict[tuple[int, int], int] = {}
    for block_index, block in enumerate(graph.blocks):
        for index, type_cid in enumerate(block.parameters):
            valtype = _valtype_for_cid(resolve, type_cid)
            if valtype is not None:
                temporary_slots[(block_index, index)] = machine_parameter_count + len(locals_)
                locals_.append(valtype)
    pc_slot = machine_parameter_count + len(locals_)
    locals_.append(0x7F)
    aggregate_scratch_slot = machine_parameter_count + len(locals_)
    locals_.append(0x7F)

    pointer_extents: dict[ValueRef, int] = {}
    for block_index, block in enumerate(graph.blocks):
        for node_index, node in enumerate(block.nodes):
            result = ValueRef.node_result(block_index, node_index)
            if node.operation == Operation.STACK_ALLOC:
                pointer_extents[result] = node.attributes[0]
            elif node.operation == Operation.ADDRESS_OFFSET and node.operands[0] in pointer_extents:
                pointer_extents[result] = pointer_extents[node.operands[0]] - node.attributes[0]
            elif node.operation == Operation.POINTER_CAST and node.operands[0] in pointer_extents:
                pointer_extents[result] = pointer_extents[node.operands[0]]
            elif node.operation == Operation.POINTER_REBASE:
                pointer_extents[result] = node.attributes[0]

    code = bytearray()
    node_ranges: list[tuple[int, int, int, int]] = []

    def get(value: ValueRef) -> None:
        try:
            code.extend(b"\x20" + uleb(slots[value]))
        except KeyError:
            fail("XAX.WASM.VALUE", graph_object.cid.hex(), "WASM-VALUE-MACHINE", "machine value", [value.block, value.index, value.result])

    def set_(value: ValueRef) -> None:
        code.extend(b"\x21" + uleb(slots[value]))

    def local_get(index: int) -> None:
        code.extend(b"\x20" + uleb(index))

    def local_set(index: int) -> None:
        code.extend(b"\x21" + uleb(index))

    def iconst(value: int, width: int = 32) -> None:
        storage = 32 if width <= 32 else 64
        signed = value - (1 << storage) if value >= 1 << (storage - 1) else value
        code.extend(bytes((0x41 if storage == 32 else 0x42,)) + _sleb(signed))

    def fconst(value: float, width: int) -> None:
        raw = _float_raw_bits(value, width)
        code.append(0x43 if width == 32 else 0x44)
        code.extend(raw.to_bytes(width // 8, "little"))

    def mask(width: int) -> None:
        storage = 32 if width <= 32 else 64
        if width != storage:
            iconst((1 << width) - 1, storage)
            code.append(0x71 if storage == 32 else 0x83)

    def get_integer(value: ValueRef, width: int, *, signed: bool = False) -> None:
        get(value)
        storage = 32 if width <= 32 else 64
        if signed and width != storage:
            shift = storage - width
            iconst(shift, storage)
            code.append(0x74 if storage == 32 else 0x86)  # shl
            iconst(shift, storage)
            code.append(0x75 if storage == 32 else 0x87)  # shr_s

    def aggregate_address(ref: ValueRef) -> int:
        try:
            return aggregate_addresses[(function.cid, ref.tag, ref.block, ref.index, ref.result)]
        except KeyError:
            fail("XAX.WASM.AGGREGATE", graph_object.cid.hex(), "WASM-AGGREGATE-STORAGE", "aggregate node result storage", [ref.block, ref.index, ref.result])

    def zero_memory(address: int, size: int) -> None:
        iconst(address)
        iconst(0)
        iconst(size)
        code.extend(b"\xfc\x0b\x00")  # memory.fill memory 0

    def copy_memory_const_dest(address: int, source_ref: ValueRef, size: int, source_offset: int = 0) -> None:
        iconst(address)
        get(source_ref)
        if source_offset:
            iconst(source_offset)
            code.append(0x6A)
        iconst(size)
        code.extend(b"\xfc\x0a\x00\x00")  # memory.copy 0 0

    def store_value_at(address: int, ref: ValueRef, cid: bytes) -> None:
        form = _form(resolve, cid)
        layout = abi_layout(resolve(cid), resolve, pointer_bytes=4)
        if form in (8, 9, 10):
            copy_memory_const_dest(address, ref, layout.size)
            return
        iconst(address)
        get(ref)
        if form == 7:
            width = decode_float_width(resolve(cid))
            code.extend(bytes((0x38 if width == 32 else 0x39,)) + uleb(2 if width == 32 else 3) + b"\x00")
            return
        size = layout.size
        valtype = _valtype_for_cid(resolve, cid)
        opcode = {
            (0x7F, 1): 0x3A, (0x7F, 2): 0x3B, (0x7F, 4): 0x36,
            (0x7E, 1): 0x3C, (0x7E, 2): 0x3D, (0x7E, 4): 0x3E, (0x7E, 8): 0x37,
        }.get((valtype, size))
        if opcode is None:
            fail("XAX.WASM.AGGREGATE", graph_object.cid.hex(), "WASM-AGGREGATE-SCALAR-STORE", "1/2/4/8-byte scalar", [valtype, size])
        code.extend(bytes((opcode,)) + uleb(int(log2(size))) + b"\x00")

    def load_value_from(source_ref: ValueRef, offset: int, result_ref: ValueRef, cid: bytes) -> None:
        form = _form(resolve, cid)
        layout = abi_layout(resolve(cid), resolve, pointer_bytes=4)
        if form in (8, 9, 10):
            get(source_ref)
            if offset:
                iconst(offset)
                code.append(0x6A)
            set_(result_ref)
            return
        get(source_ref)
        if form == 7:
            width = decode_float_width(resolve(cid))
            code.extend(bytes((0x2A if width == 32 else 0x2B,)) + uleb(2 if width == 32 else 3) + uleb(offset))
            set_(result_ref)
            return
        valtype = _valtype_for_cid(resolve, cid)
        size = layout.size
        opcode = {
            (0x7F, 1): 0x2D, (0x7F, 2): 0x2F, (0x7F, 4): 0x28,
            (0x7E, 1): 0x31, (0x7E, 2): 0x33, (0x7E, 4): 0x35, (0x7E, 8): 0x29,
        }.get((valtype, size))
        if opcode is None:
            fail("XAX.WASM.AGGREGATE", graph_object.cid.hex(), "WASM-AGGREGATE-SCALAR-LOAD", "1/2/4/8-byte scalar", [valtype, size])
        code.extend(bytes((opcode,)) + uleb(int(log2(size))) + uleb(offset))
        if form == 1:
            mask(decode_bits_width(resolve(cid)))
        set_(result_ref)

    def copy_edge(target: int, arguments: tuple[ValueRef, ...], depth: int) -> None:
        machine_arguments = tuple(
            (index, argument)
            for index, argument in enumerate(arguments)
            if argument in slots and ValueRef.parameter(target, index) in slots
        )
        for index, argument in machine_arguments:
            temporary = temporary_slots[(target, index)]
            get(argument)
            local_set(temporary)
        for index, _ in machine_arguments:
            temporary = temporary_slots[(target, index)]
            local_get(temporary)
            set_(ValueRef.parameter(target, index))
        iconst(target)
        local_set(pc_slot)
        code.extend(b"\x0c" + uleb(depth))

    iconst(graph.entry)
    local_set(pc_slot)
    code.extend(b"\x03\x40")
    for block_index, block in enumerate(graph.blocks):
        local_get(pc_slot)
        iconst(block_index)
        code.extend(b"\x46\x04\x40")
        for node_index, node in enumerate(block.nodes):
            node_start = len(code)
            result = ValueRef.node_result(block_index, node_index)
            if node.operation in (Operation.ADD_WRAP, Operation.SUB_WRAP, Operation.MUL_WRAP):
                width = decode_bits_width(resolve(node.results[0]))
                get(node.operands[0]); get(node.operands[1])
                base = 0x6A if width <= 32 else 0x7C
                code.append(base + (node.operation - Operation.ADD_WRAP))
                mask(width)
                set_(result)

            elif node.operation == Operation.CONSTANT:
                type_cid, value = _decode_constant(node.entity, resolve)
                if _form(resolve, type_cid) == 7:
                    fconst(float(value), decode_float_width(resolve(type_cid)))
                else:
                    iconst(int(value), _width(resolve, type_cid))
                set_(result)

            elif node.operation in (Operation.FLOAT_ADD, Operation.FLOAT_SUB, Operation.FLOAT_MUL, Operation.FLOAT_DIV):
                width = decode_float_width(resolve(node.results[0]))
                get(node.operands[0]); get(node.operands[1])
                op = {
                    (32, Operation.FLOAT_ADD): 0x92, (32, Operation.FLOAT_SUB): 0x93,
                    (32, Operation.FLOAT_MUL): 0x94, (32, Operation.FLOAT_DIV): 0x95,
                    (64, Operation.FLOAT_ADD): 0xA0, (64, Operation.FLOAT_SUB): 0xA1,
                    (64, Operation.FLOAT_MUL): 0xA2, (64, Operation.FLOAT_DIV): 0xA3,
                }[(width, Operation(node.operation))]
                code.append(op); set_(result)

            elif node.operation == Operation.FLOAT_COMPARE:
                width = decode_float_width(resolve(node.operand_types[0]))
                get(node.operands[0]); get(node.operands[1])
                base = 0x5B if width == 32 else 0x61
                kind = FloatCompare(node.attributes[0])
                offset = {
                    FloatCompare.EQ: 0, FloatCompare.NE: 1, FloatCompare.LT: 2,
                    FloatCompare.GT: 3, FloatCompare.LE: 4, FloatCompare.GE: 5,
                }[kind]
                code.append(base + offset); set_(result)

            elif node.operation == Operation.INT_COMPARE:
                width = 32 if _form(resolve, node.operand_types[0]) == 11 else decode_bits_width(resolve(node.operand_types[0]))
                comparison = IntCompare(node.attributes[0])
                signed_comparison = comparison in (IntCompare.SLT, IntCompare.SLE, IntCompare.SGT, IntCompare.SGE)
                get_integer(node.operands[0], width, signed=signed_comparison)
                get_integer(node.operands[1], width, signed=signed_comparison)
                mapping32 = {
                    IntCompare.EQ: 0x46, IntCompare.NE: 0x47, IntCompare.SLT: 0x48, IntCompare.ULT: 0x49,
                    IntCompare.SGT: 0x4A, IntCompare.UGT: 0x4B, IntCompare.SLE: 0x4C, IntCompare.ULE: 0x4D,
                    IntCompare.SGE: 0x4E, IntCompare.UGE: 0x4F,
                }
                mapping64 = {
                    IntCompare.EQ: 0x51, IntCompare.NE: 0x52, IntCompare.SLT: 0x53, IntCompare.ULT: 0x54,
                    IntCompare.SGT: 0x55, IntCompare.UGT: 0x56, IntCompare.SLE: 0x57, IntCompare.ULE: 0x58,
                    IntCompare.SGE: 0x59, IntCompare.UGE: 0x5A,
                }
                code.append((mapping32 if width <= 32 else mapping64)[comparison]); set_(result)

            elif node.operation in (Operation.UINT_TO_FLOAT, Operation.SINT_TO_FLOAT):
                source_width = decode_bits_width(resolve(node.operand_types[0]))
                destination_width = decode_float_width(resolve(node.results[0]))
                signed = node.operation == Operation.SINT_TO_FLOAT
                get_integer(node.operands[0], source_width, signed=signed)
                opcode = {
                    (32, 32, True): 0xB2, (32, 32, False): 0xB3,
                    (64, 32, True): 0xB4, (64, 32, False): 0xB5,
                    (32, 64, True): 0xB7, (32, 64, False): 0xB8,
                    (64, 64, True): 0xB9, (64, 64, False): 0xBA,
                }[(32 if source_width <= 32 else 64, destination_width, signed)]
                code.append(opcode); set_(result)

            elif node.operation in (Operation.FLOAT_TO_UINT_TRUNC, Operation.FLOAT_TO_SINT_TRUNC):
                source_width = decode_float_width(resolve(node.operand_types[0]))
                destination_width = decode_bits_width(resolve(node.results[0]))
                signed = node.operation == Operation.FLOAT_TO_SINT_TRUNC
                compare_base = 0x5B if source_width == 32 else 0x61

                def trap_compare(compare_opcode: int, threshold: float | None = None) -> None:
                    get(node.operands[0])
                    if threshold is None:
                        get(node.operands[0])
                    else:
                        fconst(threshold, source_width)
                    code.append(compare_opcode)
                    code.extend(b"\x04\x40\x00\x0b")

                # NaN must trap; wasm's ordered range comparisons alone would
                # all be false for it.
                trap_compare(compare_base + 1)  # ne self
                if signed:
                    lower = -(1 << (destination_width - 1))
                    if _int_to_float(lower - 1, source_width) == lower - 1:
                        trap_compare(compare_base + 4, float(lower - 1))  # <= exclusive lower bound
                    else:
                        trap_compare(compare_base + 2, float(lower))  # < representable lower bound
                    trap_compare(compare_base + 5, float(1 << (destination_width - 1)))  # >= upper
                else:
                    trap_compare(compare_base + 2, 0.0)
                    trap_compare(compare_base + 5, float(1 << destination_width))
                get(node.operands[0])
                storage = 32 if destination_width <= 32 else 64
                opcode = {
                    (32, 32, True): 0xA8, (32, 32, False): 0xA9,
                    (64, 32, True): 0xAA, (64, 32, False): 0xAB,
                    (32, 64, True): 0xAE, (32, 64, False): 0xAF,
                    (64, 64, True): 0xB0, (64, 64, False): 0xB1,
                }[(source_width, storage, signed)]
                code.append(opcode); mask(destination_width); set_(result)

            elif node.operation == Operation.FLOAT_CONVERT:
                source_width = decode_float_width(resolve(node.operand_types[0]))
                destination_width = decode_float_width(resolve(node.results[0]))
                get(node.operands[0])
                if source_width != destination_width:
                    code.append(0xB6 if destination_width == 32 else 0xBB)
                set_(result)

            elif node.operation == Operation.AGGREGATE_MAKE:
                address = aggregate_address(result)
                layout = abi_layout(resolve(node.results[0]), resolve, pointer_bytes=4)
                zero_memory(address, layout.size)
                for operand, offset, cid in zip(node.operands, layout.offsets, node.operand_types):
                    store_value_at(address + offset, operand, cid)
                iconst(address); set_(result)

            elif node.operation == Operation.AGGREGATE_GET:
                source = node.operands[0]
                layout = abi_layout(resolve(node.operand_types[0]), resolve, pointer_bytes=4)
                load_value_from(source, layout.offsets[node.attributes[0]], result, node.results[0])

            elif node.operation == Operation.SUM_MAKE:
                address = aggregate_address(result)
                layout = abi_layout(resolve(node.results[0]), resolve, pointer_bytes=4)
                zero_memory(address, layout.size)
                iconst(address); iconst(node.attributes[0]); code.extend(b"\x36\x02\x00")
                store_value_at(address + layout.payload_offset, node.operands[0], node.operand_types[0])
                iconst(address); set_(result)

            elif node.operation == Operation.SUM_TAG:
                get(node.operands[0]); code.extend(b"\x28\x02\x00"); mask(decode_bits_width(resolve(node.results[0]))); set_(result)

            elif node.operation == Operation.SUM_GET:
                source = node.operands[0]
                layout = abi_layout(resolve(node.operand_types[0]), resolve, pointer_bytes=4)
                get(source); code.extend(b"\x28\x02\x00"); iconst(node.attributes[0]); code.extend(b"\x46\x45\x04\x40\x00\x0b")
                load_value_from(source, layout.payload_offset, result, node.results[0])

            elif node.operation in (Operation.CALL_DIRECT, Operation.CALL_FOREIGN):
                machine_operands = tuple(operand for operand, cid in zip(node.operands, node.operand_types) if not _is_proof_type(resolve(cid)))
                machine_results = tuple((i, cid) for i, cid in enumerate(node.results) if not _is_proof_type(resolve(cid)))
                for operand in machine_operands:
                    get(operand)
                if node.operation == Operation.CALL_FOREIGN:
                    code.extend(b"\x10" + uleb(import_indices[node.entity.cid]))
                elif not _is_erased_proof_function(node.entity, resolve):
                    code.extend(b"\x10" + uleb(function_indices[node.entity.cid]))
                if machine_results:
                    result_index, result_cid = machine_results[0]
                    result_ref = ValueRef.node_result(block_index, node_index, result_index)
                    if _kind(resolve, result_cid) == "a":
                        local_set(aggregate_scratch_slot)
                        address = aggregate_address(result_ref)
                        size = abi_layout(resolve(result_cid), resolve, pointer_bytes=4).size
                        zero_memory(address, size)
                        iconst(address); local_get(aggregate_scratch_slot); iconst(size); code.extend(b"\xfc\x0a\x00\x00")
                        iconst(address); set_(result_ref)
                    else:
                        set_(result_ref)

            elif node.operation == Operation.STACK_ALLOC:
                iconst(stack_addresses[(function.cid, block_index, node_index)]); set_(result)

            elif node.operation == Operation.ADDRESS_OFFSET:
                get(node.operands[0]); iconst(node.attributes[0]); code.append(0x6A); set_(result)

            elif node.operation == Operation.POINTER_CAST:
                get(node.operands[0]); set_(result)

            elif node.operation == Operation.POINTER_ADDRESS:
                if _width(resolve, node.results[0]) != 32:
                    fail("XAX.WASM.ADDRESS_WIDTH", graph_object.cid.hex(), "WASM-ADDRESS-POINTER-WIDTH", 32, _width(resolve, node.results[0]))
                get(node.operands[0]); set_(result)

            elif node.operation == Operation.POINTER_REBASE:
                # ADR-092: trap unless 0 <= address - view <= span with the
                # distance a multiple of the alignment; rotr folds both tests.
                view, address = node.operands
                if _width(resolve, node.operand_types[1]) != 32:
                    fail("XAX.WASM.ADDRESS_WIDTH", graph_object.cid.hex(), "WASM-ADDRESS-POINTER-WIDTH", 32, _width(resolve, node.operand_types[1]))
                if view not in pointer_extents:
                    fail("XAX.WASM.POINTER", graph_object.cid.hex(), "WASM-REBASE-VIEW-EXTENT", "known view extent", [view.block, view.index])
                shift = _decode_pointer_type(resolve(node.results[0]), resolve)[2].bit_length() - 1
                get(address); get(view); code.append(0x6B)  # i32.sub
                if shift:
                    iconst(shift); code.append(0x78)  # i32.rotr
                iconst((pointer_extents[view] - node.attributes[0]) >> shift); code.append(0x4B)  # i32.gt_u
                code.extend(b"\x04\x40\x00\x0b")  # if unreachable end
                get(address); set_(result)

            elif node.operation in (Operation.CHECKED_LOAD_BITS_LE, Operation.CHECKED_STORE_BITS_LE):
                size, alignment = node.attributes
                extent = pointer_extents.get(node.operands[0])
                if extent is None:
                    fail("XAX.WASM.POINTER", graph_object.cid.hex(), "WASM-CHECKED-POINTER-EXTENT", "known stack pointer extent", [node.operands[0].block, node.operands[0].index])
                maximum = extent - size
                if maximum < 0:
                    code.append(0x00)
                else:
                    get(node.operands[1]); iconst(maximum, _width(resolve, node.operand_types[1])); code.append(0x4B if _width(resolve, node.operand_types[1]) <= 32 else 0x56)
                    code.extend(b"\x04\x40\x00\x0b")
                    get(node.operands[0]); get(node.operands[1])
                    if _width(resolve, node.operand_types[1]) > 32:
                        code.append(0xA7)  # i32.wrap_i64
                    code.append(0x6A)
                    value_cid = node.results[0] if node.operation == Operation.CHECKED_LOAD_BITS_LE else node.operand_types[2]
                    width = _width(resolve, value_cid)
                    form = _form(resolve, value_cid)
                    storage = 32 if width <= 32 else 64
                    if node.operation == Operation.CHECKED_LOAD_BITS_LE:
                        if form == 7:
                            opcode = 0x2A if width == 32 else 0x2B
                        else:
                            opcode = {(32, 1): 0x2D, (32, 2): 0x2F, (32, 4): 0x28, (64, 1): 0x31, (64, 2): 0x33, (64, 4): 0x35, (64, 8): 0x29}.get((storage, size))
                        if opcode is None:
                            fail("XAX.WASM.MEMORY_WIDTH", graph_object.cid.hex(), "WASM-MEMORY-WIDTH", [8, 16, 32, 64], width)
                        code.extend(bytes((opcode,)) + uleb(int(log2(alignment))) + b"\x00")
                        if form == 1:
                            mask(width)
                        set_(result)
                    else:
                        get(node.operands[2])
                        if form == 7:
                            opcode = 0x38 if width == 32 else 0x39
                        else:
                            opcode = {(32, 1): 0x3A, (32, 2): 0x3B, (32, 4): 0x36, (64, 1): 0x3C, (64, 2): 0x3D, (64, 4): 0x3E, (64, 8): 0x37}.get((storage, size))
                        if opcode is None:
                            fail("XAX.WASM.MEMORY_WIDTH", graph_object.cid.hex(), "WASM-MEMORY-WIDTH", [8, 16, 32, 64], width)
                        code.extend(bytes((opcode,)) + uleb(int(log2(alignment))) + b"\x00")

            elif node.operation in (Operation.RAW_LOAD_BITS_LE, Operation.LOAD_BITS_LE) and _form(resolve, node.results[0]) == 11:
                # A link field is 8 bytes holding a zero-extended wasm32 address (ADR-097).
                get(node.operands[0])
                code.extend(b"\x29" + uleb(int(log2(max(1, node.attributes[1])))) + b"\x00\xa7")  # i64.load; i32.wrap_i64
                set_(result)

            elif node.operation == Operation.STORE_BITS_LE and _form(resolve, node.operand_types[1]) == 11:
                get(node.operands[0]); get(node.operands[1])
                code.extend(b"\xad\x37" + uleb(int(log2(max(1, node.attributes[1])))) + b"\x00")  # i64.extend_i32_u; i64.store

            elif node.operation == Operation.LINK_MAKE:
                get(node.operands[0]); set_(result)

            elif node.operation == Operation.LINK_FOLLOW:
                get(node.operands[1]); code.extend(b"\x45\x04\x40\x00\x0b")  # i32.eqz; if unreachable end
                get(node.operands[1]); set_(result)

            elif node.operation in (Operation.RAW_LOAD_BITS_LE, Operation.LOAD_BITS_LE):
                size = node.attributes[0]
                alignment = max(1, node.attributes[1])
                width = _width(resolve, node.results[0])
                get(node.operands[0])
                if _form(resolve, node.results[0]) == 7:
                    opcode = 0x2A if width == 32 else 0x2B
                else:
                    opcode = {(32, 1): 0x2D, (32, 2): 0x2F, (32, 4): 0x28, (64, 1): 0x31, (64, 2): 0x33, (64, 4): 0x35, (64, 8): 0x29}.get((32 if width <= 32 else 64, size))
                if opcode is None:
                    fail("XAX.WASM.MEMORY_WIDTH", graph_object.cid.hex(), "WASM-MEMORY-WIDTH", [8, 16, 32, 64], width)
                code.extend(bytes((opcode,)) + uleb(int(log2(alignment))) + b"\x00")
                if _form(resolve, node.results[0]) == 1:
                    mask(width)
                set_(result)

            elif node.operation == Operation.STORE_BITS_LE:
                size, alignment = node.attributes
                width = _width(resolve, node.operand_types[1])
                get(node.operands[0]); get(node.operands[1])
                if _form(resolve, node.operand_types[1]) == 7:
                    opcode = 0x38 if width == 32 else 0x39
                else:
                    opcode = {(32, 1): 0x3A, (32, 2): 0x3B, (32, 4): 0x36, (64, 1): 0x3C, (64, 2): 0x3D, (64, 4): 0x3E, (64, 8): 0x37}.get((32 if width <= 32 else 64, size))
                if opcode is None:
                    fail("XAX.WASM.MEMORY_WIDTH", graph_object.cid.hex(), "WASM-MEMORY-WIDTH", [8, 16, 32, 64], width)
                code.extend(bytes((opcode,)) + uleb(int(log2(alignment))) + b"\x00")

            elif node.operation in (Operation.STACK_END, *RESOURCE_EFFECT_OPERATIONS):
                pass

            else:
                fail("XAX.WASM.UNSUPPORTED_OPERATION", graph_object.cid.hex(), "WASM-OP-LOWERED", "declared general subset", node.operation)

            node_end = len(code)
            if node_end > node_start:
                node_ranges.append((block_index, node_index, node_start, node_end))

        terminator = block.terminator
        if terminator.kind == TerminatorKind.RETURN:
            machine_values = tuple(value for value, cid in zip(terminator.values, return_types) if not _is_proof_type(resolve(cid)))
            if machine_values:
                get(machine_values[0])
            code.append(0x0F)
        elif terminator.kind == TerminatorKind.BRANCH:
            copy_edge(*terminator.edges[0], 1)
        elif terminator.kind == TerminatorKind.CONDITIONAL_BRANCH:
            get(terminator.values[0])
            code.extend(b"\x04\x40")
            copy_edge(*terminator.edges[0], 2)
            code.append(0x05)
            copy_edge(*terminator.edges[1], 2)
            code.append(0x0B)
        else:
            code.append(0x00)
        code.append(0x0B)
    code.extend(b"\x00\x0b\x00")

    declarations: list[tuple[int, int]] = []
    for valtype in locals_:
        if declarations and declarations[-1][1] == valtype:
            declarations[-1] = (declarations[-1][0] + 1, valtype)
        else:
            declarations.append((1, valtype))
    locals_blob = uleb(len(declarations)) + b"".join(uleb(count) + bytes((valtype,)) for count, valtype in declarations)
    body = locals_blob + bytes(code) + b"\x0b"
    size_prefix = uleb(len(body))
    code_base = len(size_prefix) + len(locals_blob)
    ranges = tuple(
        ArtifactSemanticRange(function.cid, block_index, node_index, code_base + start, code_base + end)
        for block_index, node_index, start, end in node_ranges
    )
    return size_prefix + body, ranges


def _compile_wasm_with_target(reader: StoreReader, function_cid: bytes, target_object: SemanticObject) -> WasmImage:
    verify_store(reader)
    resolve = store_resolver(reader)
    entry = resolve(function_cid)
    if entry.kind != Kind.FUNCTION:
        fail("XAX.WASM.FUNCTION", function_cid.hex(), "WASM-ENTRY-FUNCTION", Kind.FUNCTION.name, entry.kind.name)
    target = decode_native_target(target_object)
    if target.architecture != 2:
        fail("XAX.WASM.TARGET", target_object.cid.hex(), "WASM-TARGET-PROFILE", 2, target.architecture)
    general_profile = any(
        operation in target.supported_operations
        for operation in (Operation.FLOAT_ADD, Operation.AGGREGATE_MAKE, Operation.SUM_MAKE)
    )
    if not general_profile:
        # Preserve the v1/measurement-profile byte identity exactly.  The new
        # value model intentionally lives behind the general target contract,
        # so legacy targets keep their historical lowering and evidence hashes.
        from xax_wasm_legacy import _compile_wasm_with_target as _compile_legacy_wasm
        legacy = _compile_legacy_wasm(reader, function_cid, target_object)
        return WasmImage(
            legacy.module, legacy.entry_offset, legacy.parameter_widths, legacy.return_widths,
            legacy.target_cid, legacy.function_indices, legacy.semantic_ranges,
            tuple("i" for _ in legacy.parameter_widths), tuple("i" for _ in legacy.return_widths),
        )
    functions = _function_closure(entry, resolve, target.supported_operations, target.supported_terminators)
    wasi = target.identity == WASM32_WASI_IDENTITY
    # Imports take the first function indices; one per distinct foreign carrier.
    carriers: dict[bytes, SemanticObject] = {}
    for function in functions:
        graph_object, _, _ = _decode_function_interface(function, resolve)
        for block in _parse_graph(graph_object, resolve).blocks:
            for node in block.nodes:
                if node.operation == Operation.CALL_FOREIGN:
                    declaration = decode_foreign_function(node.entity)
                    if declaration.abi != b"wasm32-import":
                        fail("XAX.FOREIGN.ABI", graph_object.cid.hex(), "WASM-FOREIGN-ABI", "wasm32-import", declaration.abi.decode("ascii", "replace"))
                    carriers[node.entity.cid] = node.entity
    imports = sorted(carriers.values(), key=lambda carrier: (decode_foreign_function(carrier).library, decode_foreign_function(carrier).name))
    import_indices = {carrier.cid: index for index, carrier in enumerate(imports)}
    indices = {function.cid: len(imports) + index for index, function in enumerate(functions)}
    stack_addresses, aggregate_addresses, memory_size = _memory_layout(functions, resolve)

    signatures: list[bytes] = []

    def type_index(parameters: Sequence[bytes], returns: Sequence[bytes]) -> int:
        signature = b"\x60" + _vector([bytes((_valtype_for_cid(resolve, cid),)) for cid in parameters if not _is_proof_type(resolve(cid))]) + _vector([bytes((_valtype_for_cid(resolve, cid),)) for cid in returns if not _is_proof_type(resolve(cid))])
        if signature not in signatures:
            signatures.append(signature)
        return signatures.index(signature)

    import_entries = []
    for carrier in imports:
        declaration = decode_foreign_function(carrier)
        index = type_index(declaration.inputs, declaration.outputs)
        import_entries.append(uleb(len(declaration.library)) + declaration.library + uleb(len(declaration.name)) + declaration.name + b"\x00" + uleb(index))
    type_indices = [type_index(*_decode_function_interface(function, resolve)[1:]) for function in functions]

    module = bytearray(b"\x00asm\x01\x00\x00\x00")
    module.extend(_section(1, _vector(signatures)))
    if import_entries:
        module.extend(_section(2, _vector(import_entries)))
    module.extend(_section(3, _vector([uleb(index) for index in type_indices])))
    if memory_size or wasi:
        module.extend(_section(5, b"\x01\x00\x01"))
    if wasi:
        _, entry_parameters, entry_returns = _decode_function_interface(entry, resolve)
        if any(not _is_proof_type(resolve(cid)) for cid in (*entry_parameters, *entry_returns)):
            fail("XAX.WASM.WASI_ENTRY", function_cid.hex(), "WASI-START-NO-MACHINE-VALUES", "() -> ()", [cid.hex() for cid in (*entry_parameters, *entry_returns)])
        # WASI command ABI: the host calls `_start` and reads `memory`; exit is an explicit proc_exit import.
        module.extend(_section(7, _vector([uleb(6) + b"_start" + b"\x00" + uleb(indices[entry.cid]), uleb(6) + b"memory" + b"\x02\x00"])))
    else:
        module.extend(_section(7, b"\x01" + uleb(5) + b"entry" + b"\x00" + uleb(indices[entry.cid])))

    compiled = [_compile_function(function, resolve, indices, import_indices, stack_addresses, aggregate_addresses) for function in functions]
    bodies = [item[0] for item in compiled]
    vector_prefix = uleb(len(bodies))
    code_payload = vector_prefix + b"".join(bodies)
    section_prefix = bytes((10,)) + uleb(len(code_payload))
    cursor = len(module) + len(section_prefix) + len(vector_prefix)
    semantic_ranges: list[ArtifactSemanticRange] = []
    entry_offset: int | None = None
    for function, (body, ranges) in zip(functions, compiled):
        body_start = cursor
        body_end = body_start + len(body)
        semantic_ranges.append(ArtifactSemanticRange(function.cid, None, None, body_start, body_end))
        semantic_ranges.extend(
            ArtifactSemanticRange(item.function_cid, item.block_index, item.node_index, body_start + item.start, body_start + item.end)
            for item in ranges
        )
        if function.cid == entry.cid:
            entry_offset = body_start
        cursor = body_end
    module.extend(section_prefix + code_payload)
    if entry_offset is None:
        fail("XAX.WASM.ENTRY", function_cid.hex(), "WASM-ENTRY-BODY", "compiled entry body", "missing")
    _, parameter_types, return_types = _decode_function_interface(entry, resolve)
    machine_parameter_types = tuple(cid for cid in parameter_types if not _is_proof_type(resolve(cid)))
    machine_return_types = tuple(cid for cid in return_types if not _is_proof_type(resolve(cid)))
    return WasmImage(
        bytes(module),
        entry_offset,
        tuple(_width(resolve, cid) for cid in machine_parameter_types),
        tuple(_width(resolve, cid) for cid in machine_return_types),
        target_object.cid,
        tuple((function.cid, indices[function.cid]) for function in functions),
        tuple(semantic_ranges),
        tuple(_kind(resolve, cid) for cid in machine_parameter_types),
        tuple(_kind(resolve, cid) for cid in machine_return_types),
    )


def compile_wasm(reader: StoreReader, function_cid: bytes, target_cid: bytes) -> WasmImage:
    resolve = store_resolver(reader)
    return _compile_wasm_with_target(reader, function_cid, resolve(target_cid))


def compile_wasm_bound_target(reader: StoreReader, function_cid: bytes, target_object: SemanticObject) -> WasmImage:
    """Compile against an explicitly bound target package that need not be stored under the program root."""
    return _compile_wasm_with_target(reader, function_cid, target_object)


def run_wasm_isolated(
    image: WasmImage, arguments: Sequence[int | float], node_executable: str | None = None
) -> tuple[int | float, ...]:
    if len(arguments) != len(image.parameter_widths):
        fail("XAX.WASM.ARGUMENT_COUNT", "entry", "WASM-ARGUMENT-COUNT", len(image.parameter_widths), len(arguments))
    parameter_kinds = image.parameter_kinds or tuple("i" for _ in image.parameter_widths)
    return_kinds = image.return_kinds or tuple("i" for _ in image.return_widths)
    encoded_arguments: list[str | float] = []
    for argument, width, kind in zip(arguments, image.parameter_widths, parameter_kinds):
        if kind == "f":
            if not isinstance(argument, (int, float)):
                fail("XAX.WASM.ARGUMENT_TYPE", "entry", "WASM-FLOAT-ARGUMENT", "number", type(argument).__name__)
            encoded_arguments.append(float(argument))
        elif kind in ("i", "p"):
            if not isinstance(argument, int) or argument < 0 or argument >= 1 << width:
                fail("XAX.WASM.ARGUMENT_RANGE", "entry", "WASM-ARGUMENT-RANGE", f"bits<{width}>", argument)
            encoded_arguments.append(str(argument))
        else:
            fail("XAX.WASM.ARGUMENT_TYPE", "entry", "WASM-HOST-AGGREGATE-ARGUMENT", "scalar entry argument", kind)
    if any(kind == "a" for kind in return_kinds):
        fail("XAX.WASM.RETURN_TYPE", "entry", "WASM-HOST-AGGREGATE-RETURN", "scalar entry return", "aggregate")
    node = node_executable or shutil.which("node")
    if not node:
        fail("XAX.WASM.HOST", "host", "WASM-HOST-NODE", "node executable", "missing")
    script = """
const bytes = Buffer.from(process.argv[1], "hex");
const widths = JSON.parse(process.argv[2]);
const kinds = JSON.parse(process.argv[3]);
const raw = JSON.parse(process.argv[4]);
const values = raw.map((v, i) => kinds[i] === "f" ? Number(v) : (widths[i] > 32 ? BigInt(v) : Number(v)));
const instance = new WebAssembly.Instance(new WebAssembly.Module(bytes));
const result = instance.exports.entry(...values);
if (result === undefined) { console.log("[]"); }
else if (typeof result === "bigint") { console.log(JSON.stringify([{kind:"i", value:result.toString()}])); }
else { console.log(JSON.stringify([{kind:(Number.isInteger(result) ? "i" : "f"), value:result.toString()}])); }
"""
    completed = subprocess.run(
        [node, "-e", script, image.module.hex(), json.dumps(image.parameter_widths), json.dumps(parameter_kinds), json.dumps(encoded_arguments)],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode:
        raise RuntimeError(completed.stderr.strip() or f"wasm child exited {completed.returncode}")
    raw_values = json.loads(completed.stdout)
    values: list[int | float] = []
    for item, width, kind in zip(raw_values, image.return_widths, return_kinds):
        if kind == "f":
            values.append(float(item["value"]))
        else:
            values.append(int(item["value"]) & ((1 << width) - 1))
    return tuple(values)


def run_wasi_isolated(image: WasmImage, arguments: Sequence[str] = (), node_executable: str | None = None) -> tuple[int, bytes]:
    """Run a WASI command module under Node's ``node:wasi`` host; returns (exit code, stdout).

    The host is a platform-required runtime and test harness, not part of the artifact.
    """
    node = node_executable or shutil.which("node")
    if not node:
        fail("XAX.WASM.HOST", "host", "WASM-HOST-NODE", "node executable", "missing")
    script = """
const { WASI } = require("node:wasi");
const wasi = new WASI({ version: "preview1", args: JSON.parse(process.argv[2]), env: {}, returnOnExit: true });
const instance = new WebAssembly.Instance(new WebAssembly.Module(Buffer.from(process.argv[1], "hex")), wasi.getImportObject());
process.exitCode = wasi.start(instance);
"""
    completed = subprocess.run(
        [node, "--no-warnings", "-e", script, image.module.hex(), json.dumps(list(arguments))],
        check=False, capture_output=True,
    )
    if completed.stderr.strip():
        raise RuntimeError(completed.stderr.decode(errors="replace").strip())
    return completed.returncode, completed.stdout
