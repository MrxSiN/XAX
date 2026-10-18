"""BBX import construction tooling; the verified graph, not this carrier, runs decisions.

The internal function borrows distinct, live initialized input/output/tape
views. It resets its 65536-byte tape on every call. Its native caller
must establish these view obligations; this is not an untrusted raw-pointer ABI.
The scalar result is (output_length << 32) | status: 0 success, 1 tape bounds,
2 output capacity, 3 invalid logical lengths. Borrowed triples are returned
unchanged except their memory frontiers and are erased from the native return.
"""
from __future__ import annotations

from dataclasses import dataclass

from xax_compiler import (
    IntCompare, Operation, Permission, SemanticObject, StoreReader,
    android_arm64_shared_integer_target, bits_type, heap_view_type,
    memory_effect_type, pointer_type,
)
from xax_graph_builder import GraphBuilder, program_store

B1, B8, B32, B64 = (bits_type(n) for n in (1, 8, 32, 64))
MEM = memory_effect_type()
READ = pointer_type(B8, Permission.READ, 1, space=2)
WRITE = pointer_type(B8, Permission.READ_WRITE, 1, space=2)
TAPE_SIZE = 65536


def decode_bbx(record: bytes) -> tuple[bytes, dict[int, int]]:
    """Reject malformed records before constructing any graph objects."""
    if not isinstance(record, bytes) or len(record) < 7 or record[:4] != b"BBX\x01" or record[4] != 0:
        raise ValueError("BBX requires magic BBX, version 1 and a successful complete record")
    count = int.from_bytes(record[5:7], "little")
    if count > 3840 or len(record) != 7 + count:
        raise ValueError("BBX count or exact record length is invalid")
    code = record[7:]
    stack, pairs = [], {}
    for index, byte in enumerate(code):
        if byte not in b"><+-.,[]":
            raise ValueError("BBX payload contains a noninstruction")
        if byte == 91:
            stack.append(index)
            if len(stack) > 255:
                raise ValueError("BBX nesting exceeds 255")
        elif byte == 93:
            if not stack:
                raise ValueError("BBX unmatched closing bracket")
            opening = stack.pop()
            pairs[opening], pairs[index] = index, opening
    if stack:
        raise ValueError("BBX unmatched opening bracket")
    return code, pairs


@dataclass(frozen=True)
class ImportedBBX:
    reader: StoreReader
    function: SemanticObject
    target: SemanticObject
    input_extent: int
    output_extent: int


def construct_bbx(record: bytes, *, input_extent: int = 65536, output_extent: int = 65536) -> ImportedBBX:
    """Create an Android-target verified graph with one native operation path per opcode.

    Parameters: input triple, output triple, tape triple, input_length:u32,
    output_capacity:u32. Each triple is (pointer, extent-bearing view, memory).
    All buffers must already have initialized-view proofs; tape contents
    may be arbitrary because this graph explicitly zeroes the entire tape.
    """
    code, pairs = decode_bbx(record)
    if any(type(n) is not int or not 1 <= n <= 65536 for n in (input_extent, output_extent)):
        raise ValueError("BBX buffer view extents must be integers from 1 through 65536")
    iv, ov, tv = heap_view_type(input_extent), heap_view_type(output_extent), heap_view_type(TAPE_SIZE)
    graph = GraphBuilder()
    triples = (READ, iv, MEM, WRITE, ov, MEM, WRITE, tv, MEM)
    entry = graph.block(*triples, B32, B32)
    ip, _, _, op, _, _, tape, _, _, length, capacity = entry.params
    state_types = (B32, B32, B32, iv, MEM, ov, MEM, tv, MEM)
    nodes = [graph.block(*state_types) for _ in range(len(code) + 1)]
    reset, clear = graph.block(*state_types), graph.block(*state_types)
    statuses = {3}
    if 62 in code or 60 in code:
        statuses.add(1)
    if 46 in code:
        statuses.add(2)
    failures = {status: graph.block(*state_types) for status in sorted(statuses)}

    def compare(block, kind, left, right):
        return block.op1(Operation.INT_COMPARE, (left, right), B1, attributes=(kind,))

    def step(block, operation, value, amount=1):
        return block.op1(operation, (value, block.const(B32, amount)), B32)

    def load(block, pointer, offset, memory):
        return block.op(Operation.CHECKED_LOAD_BITS_LE, (pointer, offset, memory), (B8, MEM), attributes=(1, 1))

    def store(block, pointer, offset, value, memory):
        return block.op1(Operation.CHECKED_STORE_BITS_LE, (pointer, offset, value, memory), MEM, attributes=(1, 1))

    def finish(block, status):
        state = block.params
        count = block.op1(Operation.INT_ZERO_EXTEND, (state[2],), B64)
        packed = block.op1(Operation.ROTATE_RIGHT, (count,), B64, attributes=(32,))
        packed = block.op1(Operation.BIT_OR, (packed, block.const(B64, status)), B64)
        block.ret(packed, ip, state[3], state[4], op, state[5], state[6], tape, state[7], state[8])

    initial = (entry.const(B32, 0),) * 3 + (entry.params[1], entry.params[2], entry.params[4], entry.params[5], entry.params[7], entry.params[8])
    invalid = entry.op1(Operation.BIT_OR, (
        compare(entry, IntCompare.UGT, length, entry.const(B32, input_extent)),
        compare(entry, IntCompare.UGT, capacity, entry.const(B32, output_extent)),
    ), B1)
    entry.cbr(invalid, failures[3], initial, reset, initial)
    state = list(reset.params)
    reset.cbr(compare(reset, IntCompare.ULT, state[0], reset.const(B32, TAPE_SIZE)), clear, state,
              nodes[0], (reset.const(B32, 0), *state[1:]))
    state = list(clear.params)
    state[8] = store(clear, tape, state[0], clear.const(B8, 0), state[8])
    state[0] = step(clear, Operation.ADD_WRAP, state[0])
    clear.br(reset, *state)

    for index, byte in enumerate(code):
        block, following = nodes[index], nodes[index + 1]
        state = list(block.params)
        if byte in (62, 60):
            edge = 65535 if byte == 62 else 0
            moved = list(state)
            moved[0] = step(block, Operation.ADD_WRAP if byte == 62 else Operation.SUB_WRAP, state[0])
            block.cbr(compare(block, IntCompare.EQ, state[0], block.const(B32, edge)), failures[1], state, following, moved)
        elif byte in (43, 45):
            value, state[8] = load(block, tape, state[0], state[8])
            value = block.op1(Operation.ADD_WRAP if byte == 43 else Operation.SUB_WRAP, (value, block.const(B8, 1)), B8)
            state[8] = store(block, tape, state[0], value, state[8])
            block.br(following, *state)
        elif byte in (91, 93):
            value, state[8] = load(block, tape, state[0], state[8])
            nonzero = compare(block, IntCompare.NE, value, block.const(B8, 0))
            yes, no = (following, nodes[pairs[index] + 1]) if byte == 91 else (nodes[pairs[index] + 1], following)
            block.cbr(nonzero, yes, state, no, state)
        elif byte == 44:
            read, eof = graph.block(*state_types), graph.block(*state_types)
            block.cbr(compare(block, IntCompare.ULT, state[1], length), read, state, eof, state)
            state = list(read.params)
            value, state[4] = load(read, ip, state[1], state[4])
            state[8] = store(read, tape, state[0], value, state[8])
            state[1] = step(read, Operation.ADD_WRAP, state[1])
            read.br(following, *state)
            state = list(eof.params)
            state[8] = store(eof, tape, state[0], eof.const(B8, 0), state[8])
            eof.br(following, *state)
        else:
            write = graph.block(*state_types)
            block.cbr(compare(block, IntCompare.ULT, state[2], capacity), write, state, failures[2], state)
            state = list(write.params)
            value, state[8] = load(write, tape, state[0], state[8])
            state[6] = store(write, op, state[2], value, state[6])
            state[2] = step(write, Operation.ADD_WRAP, state[2])
            write.br(following, *state)
    finish(nodes[-1], 0)
    for status, block in failures.items():
        finish(block, status)
    function = graph.function((*triples, B32, B32), (B64, *triples))
    target = android_arm64_shared_integer_target()
    reader = program_store(function, target, tuple(graph.objects.values()))
    return ImportedBBX(reader, function, target, input_extent, output_extent)
