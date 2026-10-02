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
    store_resolver,
    Kind,
    Operation,
    RESOURCE_EFFECT_OPERATIONS,
    SemanticObject,
    StoreReader,
    TerminatorKind,
    ValueRef,
    _decode_constant,
    _decode_function_interface,
    _is_proof_type,
    _is_erased_proof_function,
    _parse_graph,
    decode_bits_width,
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


def _width(resolve: Callable[[bytes], SemanticObject], cid: bytes) -> int | None:
    obj = resolve(cid)
    if obj.kind != Kind.TYPE or not obj.body or obj.body[0] != 1:
        return None
    return decode_bits_width(obj)


def _valtype(width: int) -> int:
    return 0x7F if width <= 32 else 0x7E


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
        if len(machine_returns) > 1 or any(not (width := _width(resolve, cid)) or width > 64 for cid in (*machine_parameters, *machine_returns)):
            fail("XAX.WASM.ABI", function.cid.hex(), "WASM-ABI-BITS", "bits<1..64>, at most one return", [cid.hex() for cid in (*parameters, *returns)])
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


def _memory_layout(
    functions: Sequence[SemanticObject], resolve: Callable[[bytes], SemanticObject]
) -> tuple[dict[tuple[bytes, int, int], int], int]:
    addresses: dict[tuple[bytes, int, int], int] = {}
    cursor = 0
    for function in functions:
        graph_object, _, _ = _decode_function_interface(function, resolve)
        graph = _parse_graph(graph_object, resolve)
        for block_index, block in enumerate(graph.blocks):
            for node_index, node in enumerate(block.nodes):
                if node.operation == Operation.STACK_ALLOC:
                    extent, alignment = node.attributes
                    cursor = (cursor + alignment - 1) & -alignment
                    addresses[(function.cid, block_index, node_index)] = cursor
                    cursor += extent
    if cursor > 65536:
        fail("XAX.WASM.MEMORY", "module", "WASM-STATIC-MEMORY-LIMIT", "<= 65536 bytes", cursor)
    return addresses, cursor


def _compile_function(
    function: SemanticObject,
    resolve: Callable[[bytes], SemanticObject],
    function_indices: dict[bytes, int],
    addresses: dict[tuple[bytes, int, int], int],
) -> tuple[bytes, tuple[ArtifactSemanticRange, ...]]:
    graph_object, parameter_types, return_types = _decode_function_interface(function, resolve)
    graph = _parse_graph(graph_object, resolve)
    locals_: list[int] = []
    slots: dict[ValueRef, int] = {}
    machine_parameter_count = sum(not _is_proof_type(resolve(cid)) for cid in parameter_types)

    machine_index = 0
    for index, type_cid in enumerate(graph.blocks[graph.entry].parameters):
        if _is_proof_type(resolve(type_cid)):
            continue
        slots[ValueRef.parameter(graph.entry, index)] = machine_index
        machine_index += 1

    def add_slot(value: ValueRef, type_cid: bytes) -> None:
        width = _width(resolve, type_cid)
        if width:
            slots[value] = machine_parameter_count + len(locals_)
            locals_.append(_valtype(width))

    for block_index, block in enumerate(graph.blocks):
        if block_index != graph.entry:
            for index, type_cid in enumerate(block.parameters):
                if _is_proof_type(resolve(type_cid)):
                    continue
                if not _width(resolve, type_cid):
                    fail("XAX.WASM.BLOCK_TYPE", graph_object.cid.hex(), "WASM-BLOCK-PARAMETER-BITS", "bits<1..64>", type_cid.hex())
                add_slot(ValueRef.parameter(block_index, index), type_cid)
        for node_index, node in enumerate(block.nodes):
            for result_index, type_cid in enumerate(node.results):
                add_slot(ValueRef.node_result(block_index, node_index, result_index), type_cid)

    temporary_slots: dict[tuple[int, int], int] = {}
    for block_index, block in enumerate(graph.blocks):
        for index, type_cid in enumerate(block.parameters):
            width = _width(resolve, type_cid)
            if width:
                temporary_slots[(block_index, index)] = machine_parameter_count + len(locals_)
                locals_.append(_valtype(width))
    pc_slot = machine_parameter_count + len(locals_)
    locals_.append(0x7F)

    pointers: dict[ValueRef, int] = {}
    pointer_extents: dict[ValueRef, int] = {}
    for block_index, block in enumerate(graph.blocks):
        for node_index, node in enumerate(block.nodes):
            result = ValueRef.node_result(block_index, node_index)
            if node.operation == Operation.STACK_ALLOC:
                pointers[result] = addresses[(function.cid, block_index, node_index)]
                pointer_extents[result] = node.attributes[0]
            elif node.operation == Operation.ADDRESS_OFFSET:
                pointers[result] = pointers[node.operands[0]] + node.attributes[0]
                pointer_extents[result] = pointer_extents[node.operands[0]] - node.attributes[0]

    code = bytearray()
    node_ranges: list[tuple[int, int, int, int]] = []

    def get(value: ValueRef) -> None:
        try:
            code.extend(b"\x20" + uleb(slots[value]))
        except KeyError:
            fail("XAX.WASM.VALUE", graph_object.cid.hex(), "WASM-VALUE-MACHINE-BITS", "bits value", [value.block, value.index, value.result])

    def set_(value: ValueRef) -> None:
        code.extend(b"\x21" + uleb(slots[value]))

    def const(value: int, width: int = 32) -> None:
        storage = 32 if width <= 32 else 64
        signed = value - (1 << storage) if value >= 1 << (storage - 1) else value
        code.extend(bytes((0x41 if storage == 32 else 0x42,)) + _sleb(signed))

    def mask(width: int) -> None:
        storage = 32 if width <= 32 else 64
        if width != storage:
            const((1 << width) - 1, storage)
            code.append(0x71 if storage == 32 else 0x83)

    def copy_edge(target: int, arguments: tuple[ValueRef, ...], depth: int) -> None:
        machine_arguments = tuple(
            (index, argument)
            for index, argument in enumerate(arguments)
            if argument in slots and ValueRef.parameter(target, index) in slots
        )
        for index, argument in machine_arguments:
            temporary = temporary_slots[(target, index)]
            get(argument)
            code.extend(b"\x21" + uleb(temporary))
        for index, _ in machine_arguments:
            temporary = temporary_slots[(target, index)]
            code.extend(b"\x20" + uleb(temporary))
            set_(ValueRef.parameter(target, index))
        const(target)
        code.extend(b"\x21" + uleb(pc_slot) + b"\x0c" + uleb(depth))

    const(graph.entry)
    code.extend(b"\x21" + uleb(pc_slot) + b"\x03\x40")
    for block_index, block in enumerate(graph.blocks):
        code.extend(b"\x20" + uleb(pc_slot))
        const(block_index)
        code.extend(b"\x46\x04\x40")
        for node_index, node in enumerate(block.nodes):
            node_start = len(code)
            result = ValueRef.node_result(block_index, node_index)
            if node.operation in (Operation.ADD_WRAP, Operation.SUB_WRAP, Operation.MUL_WRAP):
                width = _width(resolve, node.results[0])
                get(node.operands[0])
                get(node.operands[1])
                base = 0x6A if width <= 32 else 0x7C
                code.append(base + (node.operation - Operation.ADD_WRAP))
                mask(width)
                set_(result)
            elif node.operation == Operation.CONSTANT:
                type_cid, value = _decode_constant(node.entity, resolve)
                const(value, _width(resolve, type_cid))
                set_(result)
            elif node.operation == Operation.CALL_DIRECT:
                machine_operands = tuple(operand for operand, cid in zip(node.operands, node.operand_types) if not _is_proof_type(resolve(cid)))
                machine_results = tuple(index for index, cid in enumerate(node.results) if not _is_proof_type(resolve(cid)))
                for operand in machine_operands:
                    get(operand)
                if not _is_erased_proof_function(node.entity, resolve):
                    code.extend(b"\x10" + uleb(function_indices[node.entity.cid]))
                if machine_results:
                    set_(ValueRef.node_result(block_index, node_index, machine_results[0]))
            elif node.operation == Operation.CHECKED_LOAD_BITS_LE:
                address = pointers[node.operands[0]]
                extent = pointer_extents[node.operands[0]]
                size, alignment = node.attributes
                width = _width(resolve, node.results[0])
                maximum = extent - size
                if maximum < 0:
                    code.append(0x00)
                else:
                    get(node.operands[1])
                    const(maximum)
                    code.append(0x4B)  # i32.gt_u
                    code.extend(b"\x04\x40\x00\x0b")
                    const(address)
                    get(node.operands[1])
                    code.append(0x6A)  # i32.add
                    opcode = {(32, 1): 0x2D, (32, 2): 0x2F, (32, 4): 0x28, (64, 1): 0x31, (64, 2): 0x33, (64, 4): 0x35, (64, 8): 0x29}.get((32 if width <= 32 else 64, size))
                    if opcode is None:
                        fail("XAX.WASM.MEMORY_WIDTH", graph_object.cid.hex(), "WASM-MEMORY-WIDTH", [8, 16, 32, 64], width)
                    code.extend(bytes((opcode,)) + uleb(int(log2(alignment))) + b"\x00")
                    mask(width)
                    set_(result)
            elif node.operation == Operation.CHECKED_STORE_BITS_LE:
                address = pointers[node.operands[0]]
                extent = pointer_extents[node.operands[0]]
                size, alignment = node.attributes
                width = _width(resolve, node.operand_types[2])
                maximum = extent - size
                if maximum < 0:
                    code.append(0x00)
                else:
                    get(node.operands[1])
                    const(maximum)
                    code.append(0x4B)  # i32.gt_u
                    code.extend(b"\x04\x40\x00\x0b")
                    const(address)
                    get(node.operands[1])
                    code.append(0x6A)
                    get(node.operands[2])
                    opcode = {(32, 1): 0x3A, (32, 2): 0x3B, (32, 4): 0x36, (64, 1): 0x3C, (64, 2): 0x3D, (64, 4): 0x3E, (64, 8): 0x37}.get((32 if width <= 32 else 64, size))
                    if opcode is None:
                        fail("XAX.WASM.MEMORY_WIDTH", graph_object.cid.hex(), "WASM-MEMORY-WIDTH", [8, 16, 32, 64], width)
                    code.extend(bytes((opcode,)) + uleb(int(log2(alignment))) + b"\x00")
            elif node.operation == Operation.RAW_LOAD_BITS_LE:
                address = pointers[node.operands[0]]
                size, alignment, _waivers = node.attributes
                width = _width(resolve, node.results[0])
                const(address)
                opcode = {(32, 1): 0x2D, (32, 2): 0x2F, (32, 4): 0x28, (64, 1): 0x31, (64, 2): 0x33, (64, 4): 0x35, (64, 8): 0x29}.get((32 if width <= 32 else 64, size))
                if opcode is None:
                    fail("XAX.WASM.MEMORY_WIDTH", graph_object.cid.hex(), "WASM-MEMORY-WIDTH", [8, 16, 32, 64], width)
                code.extend(bytes((opcode,)) + uleb(int(log2(max(1, alignment)))) + b"\x00")
                mask(width)
                set_(result)
            elif node.operation == Operation.STORE_BITS_LE:
                address = pointers[node.operands[0]]
                size, alignment = node.attributes
                width = _width(resolve, node.operand_types[1])
                const(address)
                get(node.operands[1])
                opcode = {(32, 1): 0x3A, (32, 2): 0x3B, (32, 4): 0x36, (64, 1): 0x3C, (64, 2): 0x3D, (64, 4): 0x3E, (64, 8): 0x37}.get((32 if width <= 32 else 64, size))
                if opcode is None:
                    fail("XAX.WASM.MEMORY_WIDTH", graph_object.cid.hex(), "WASM-MEMORY-WIDTH", [8, 16, 32, 64], width)
                code.extend(bytes((opcode,)) + uleb(int(log2(alignment))) + b"\x00")
            elif node.operation == Operation.LOAD_BITS_LE:
                address = pointers[node.operands[0]]
                size, alignment = node.attributes
                width = _width(resolve, node.results[0])
                const(address)
                opcode = {(32, 1): 0x2D, (32, 2): 0x2F, (32, 4): 0x28, (64, 1): 0x31, (64, 2): 0x33, (64, 4): 0x35, (64, 8): 0x29}.get((32 if width <= 32 else 64, size))
                if opcode is None:
                    fail("XAX.WASM.MEMORY_WIDTH", graph_object.cid.hex(), "WASM-MEMORY-WIDTH", [8, 16, 32, 64], width)
                code.extend(bytes((opcode,)) + uleb(int(log2(alignment))) + b"\x00")
                mask(width)
                set_(result)
            elif node.operation not in (Operation.STACK_ALLOC, Operation.ADDRESS_OFFSET, Operation.STACK_END, *RESOURCE_EFFECT_OPERATIONS):
                fail("XAX.WASM.UNSUPPORTED_OPERATION", graph_object.cid.hex(), "WASM-OP-LOWERED", "declared subset", node.operation)
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
    functions = _function_closure(entry, resolve, target.supported_operations, target.supported_terminators)
    indices = {function.cid: index for index, function in enumerate(functions)}
    addresses, memory_size = _memory_layout(functions, resolve)

    signatures: list[bytes] = []
    type_indices: list[int] = []
    for function in functions:
        _, parameters, returns = _decode_function_interface(function, resolve)
        signature = b"\x60" + _vector([bytes((_valtype(_width(resolve, cid)),)) for cid in parameters if not _is_proof_type(resolve(cid))]) + _vector([bytes((_valtype(_width(resolve, cid)),)) for cid in returns if not _is_proof_type(resolve(cid))])
        if signature not in signatures:
            signatures.append(signature)
        type_indices.append(signatures.index(signature))

    module = bytearray(b"\x00asm\x01\x00\x00\x00")
    module.extend(_section(1, _vector(signatures)))
    module.extend(_section(3, _vector([uleb(index) for index in type_indices])))
    if memory_size:
        module.extend(_section(5, b"\x01\x00\x01"))
    export = uleb(5) + b"entry" + b"\x00" + uleb(indices[entry.cid])
    module.extend(_section(7, b"\x01" + export))

    compiled = [_compile_function(function, resolve, indices, addresses) for function in functions]
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
    return WasmImage(
        bytes(module),
        entry_offset,
        tuple(decode_bits_width(resolve(cid)) for cid in parameter_types if not _is_proof_type(resolve(cid))),
        tuple(decode_bits_width(resolve(cid)) for cid in return_types if not _is_proof_type(resolve(cid))),
        target_object.cid,
        tuple((function.cid, indices[function.cid]) for function in functions),
        tuple(semantic_ranges),
    )


def compile_wasm(reader: StoreReader, function_cid: bytes, target_cid: bytes) -> WasmImage:
    resolve = store_resolver(reader)
    return _compile_wasm_with_target(reader, function_cid, resolve(target_cid))


def compile_wasm_bound_target(reader: StoreReader, function_cid: bytes, target_object: SemanticObject) -> WasmImage:
    """Compile against an explicitly bound target package that need not be stored under the program root."""
    return _compile_wasm_with_target(reader, function_cid, target_object)


def run_wasm_isolated(
    image: WasmImage, arguments: Sequence[int], node_executable: str | None = None
) -> tuple[int, ...]:
    if len(arguments) != len(image.parameter_widths):
        fail("XAX.WASM.ARGUMENT_COUNT", "entry", "WASM-ARGUMENT-COUNT", len(image.parameter_widths), len(arguments))
    for argument, width in zip(arguments, image.parameter_widths):
        if argument < 0 or argument >= 1 << width:
            fail("XAX.WASM.ARGUMENT_RANGE", "entry", "WASM-ARGUMENT-RANGE", f"bits<{width}>", argument)
    node = node_executable or shutil.which("node")
    if not node:
        fail("XAX.WASM.HOST", "host", "WASM-HOST-NODE", "node executable", "missing")
    script = """
const bytes = Buffer.from(process.argv[1], "hex");
const widths = JSON.parse(process.argv[2]);
const values = JSON.parse(process.argv[3]).map((v, i) => widths[i] > 32 ? BigInt(v) : Number(v));
const instance = new WebAssembly.Instance(new WebAssembly.Module(bytes));
const result = instance.exports.entry(...values);
console.log(result === undefined ? "[]" : JSON.stringify([result.toString()]));
"""
    completed = subprocess.run(
        [node, "-e", script, image.module.hex(), json.dumps(image.parameter_widths), json.dumps([str(value) for value in arguments])],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode:
        raise RuntimeError(completed.stderr.strip() or f"wasm child exited {completed.returncode}")
    values = tuple(int(value) for value in json.loads(completed.stdout))
    return tuple(value & ((1 << width) - 1) for value, width in zip(values, image.return_widths))
