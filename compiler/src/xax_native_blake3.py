"""Native BLAKE3 compression implemented as an ordinary XAX graph.

This module is deliberately a leaf accelerator.  The semantic implementation is
committed as a canonical XAX store, can be regenerated with the public graph
vocabulary, is verified when loaded, and is lowered through ``compile_native``
using the normal x86-64 target path.  The small POSIX thunk is only a host-ABI
adapter from SysV Python/ctypes into the repository's Win64 x86-64 ABI; it
contains no BLAKE3 logic.
"""

from __future__ import annotations

import ctypes
import mmap
import platform
import threading
from dataclasses import dataclass
from typing import Sequence

from xax_compiler import (
    Block,
    Kind,
    Node,
    Operation,
    SemanticObject,
    StoreReader,
    Terminator,
    ValueRef,
    bits_type,
    constant,
    function,
    graph_fragment,
    object_with_refs,
    tuple_type,
    verify_store,
    write_store,
    x86_64_windows_general_target,
)
from xax_x86_64 import NativeImage, compile_native

_MASK32 = 0xFFFFFFFF
_IV = (
    0x6A09E667,
    0xBB67AE85,
    0x3C6EF372,
    0xA54FF53A,
    0x510E527F,
    0x9B05688C,
    0x1F83D9AB,
    0x5BE0CD19,
)
_MSG_PERMUTATION = (2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8)


@dataclass(frozen=True)
class Blake3XaxProgram:
    reader: StoreReader
    function: SemanticObject
    target: SemanticObject
    graph: SemanticObject


def load_blake3_compress_program() -> Blake3XaxProgram:
    """Load the committed canonical XAX implementation used by the accelerator."""
    from xax_native_blake3_store import FUNCTION_CID, GRAPH_CID, STORE_BYTES, TARGET_CID

    reader = StoreReader(STORE_BYTES)
    verify_store(reader)
    function_object = reader.get(FUNCTION_CID)
    graph_object = reader.get(GRAPH_CID)
    target_object = reader.get(TARGET_CID)
    return Blake3XaxProgram(reader, function_object, target_object, graph_object)


class _GraphBuilder:
    def __init__(self, b32: SemanticObject):
        self.b32 = b32
        self.nodes: list[Node] = []

    def emit(self, operation: Operation, operands: Sequence[ValueRef], *, attributes: tuple[int, ...] = ()) -> ValueRef:
        index = len(self.nodes)
        self.nodes.append(Node(operation, tuple(operands), (self.b32,), attributes=attributes))
        return ValueRef.node_result(0, index)

    def add(self, a: ValueRef, b: ValueRef) -> ValueRef:
        return self.emit(Operation.ADD_WRAP, (a, b))

    def xor(self, a: ValueRef, b: ValueRef) -> ValueRef:
        return self.emit(Operation.BIT_XOR, (a, b))

    def ror(self, value: ValueRef, amount: int) -> ValueRef:
        return self.emit(Operation.ROTATE_RIGHT, (value,), attributes=(amount,))

    def g(self, state: list[ValueRef], a: int, b: int, c: int, d: int, x: ValueRef, y: ValueRef) -> None:
        state[a] = self.add(self.add(state[a], state[b]), x)
        state[d] = self.ror(self.xor(state[d], state[a]), 16)
        state[c] = self.add(state[c], state[d])
        state[b] = self.ror(self.xor(state[b], state[c]), 12)
        state[a] = self.add(self.add(state[a], state[b]), y)
        state[d] = self.ror(self.xor(state[d], state[a]), 8)
        state[c] = self.add(state[c], state[d])
        state[b] = self.ror(self.xor(state[b], state[c]), 7)


def build_blake3_compress_program() -> Blake3XaxProgram:
    """Build ``compress(cv[8], block[16], counter_lo, counter_hi, len, flags)``.

    For a simple machine ABI the graph uses 28 scalar ``bits<32>`` parameters and
    returns one ``tuple<bits<32> x16>``.  The tuple is the exact 16-word BLAKE3
    compression output before byte serialization.
    """

    b32 = bits_type(32)
    output_type = tuple_type((b32,) * 16)
    iv_constants = tuple(constant(b32, word) for word in _IV[:4])
    builder = _GraphBuilder(b32)

    cv = [ValueRef.parameter(0, i) for i in range(8)]
    message = [ValueRef.parameter(0, 8 + i) for i in range(16)]
    counter_lo = ValueRef.parameter(0, 24)
    counter_hi = ValueRef.parameter(0, 25)
    block_len = ValueRef.parameter(0, 26)
    flags = ValueRef.parameter(0, 27)

    iv_refs: list[ValueRef] = []
    for item in iv_constants:
        node_index = len(builder.nodes)
        builder.nodes.append(Node(Operation.CONSTANT, (), (b32,), entity=item))
        iv_refs.append(ValueRef.node_result(0, node_index))

    state = [*cv, *iv_refs, counter_lo, counter_hi, block_len, flags]
    schedule = list(range(16))
    for _round in range(7):
        m = [message[index] for index in schedule]
        builder.g(state, 0, 4, 8, 12, m[0], m[1])
        builder.g(state, 1, 5, 9, 13, m[2], m[3])
        builder.g(state, 2, 6, 10, 14, m[4], m[5])
        builder.g(state, 3, 7, 11, 15, m[6], m[7])
        builder.g(state, 0, 5, 10, 15, m[8], m[9])
        builder.g(state, 1, 6, 11, 12, m[10], m[11])
        builder.g(state, 2, 7, 8, 13, m[12], m[13])
        builder.g(state, 3, 4, 9, 14, m[14], m[15])
        schedule = [schedule[index] for index in _MSG_PERMUTATION]

    output: list[ValueRef] = []
    for i in range(8):
        output.append(builder.xor(state[i], state[i + 8]))
    for i in range(8):
        output.append(builder.xor(state[i + 8], cv[i]))

    result_index = len(builder.nodes)
    builder.nodes.append(Node(Operation.AGGREGATE_MAKE, tuple(output), (output_type,)))
    result = ValueRef.node_result(0, result_index)
    parameters = (b32,) * 28
    graph = graph_fragment((Block(parameters, tuple(builder.nodes), Terminator.return_((result,))),))
    entry = function(graph, parameters, (output_type,))
    target = x86_64_windows_general_target()
    module = object_with_refs(Kind.MODULE, (entry, target))
    root = object_with_refs(Kind.PROGRAM_ROOT, (module,))
    objects = (b32, output_type, *iv_constants, graph, entry, target, module, root)
    reader = StoreReader(write_store(root.cid, objects))
    verify_store(reader)
    return Blake3XaxProgram(reader, entry, target, graph)


def compile_blake3_compress_native(program: Blake3XaxProgram | None = None) -> NativeImage:
    program = program or load_blake3_compress_program()
    return compile_native(program.reader, program.function.cid, program.target.cid)


def _mov_eax_from_rsi(displacement: int) -> bytes:
    if displacement == 0:
        return b"\x8b\x06"
    if displacement < 128:
        return b"\x8b\x46" + bytes((displacement,))
    return b"\x8b\x86" + displacement.to_bytes(4, "little")


def _mov_rax_to_rsp(displacement: int) -> bytes:
    if displacement < 128:
        return b"\x48\x89\x44\x24" + bytes((displacement,))
    return b"\x48\x89\x84\x24" + displacement.to_bytes(4, "little")


def _sysv_to_win64_blake3_thunk(entry_address: int) -> bytes:
    """SysV ``void(out*, in28*)`` -> Win64 hidden-return + 28 u32 args."""

    # Win64 has four argument positions total.  Position 0 is the hidden return
    # pointer, positions 1..3 carry the first three u32 parameters, and the
    # remaining 25 parameters occupy 8-byte stack slots after 32-byte home space.
    required = 32 + 25 * 8
    frame = required + ((8 - required) % 16)  # SysV entry RSP%16==8; align before call.
    code = bytearray(b"\x48\x81\xec" + frame.to_bytes(4, "little"))
    code.extend(b"\x48\x89\xf9")  # mov rcx, rdi -- hidden aggregate return pointer
    code.extend(b"\x8b\x16")      # mov edx, [rsi] -- parameter 0
    code.extend(b"\x44\x8b\x46\x04")  # mov r8d, [rsi+4]
    code.extend(b"\x44\x8b\x4e\x08")  # mov r9d, [rsi+8]
    for parameter in range(3, 28):
        code.extend(_mov_eax_from_rsi(parameter * 4))
        stack_offset = 32 + (parameter - 3) * 8
        code.extend(_mov_rax_to_rsp(stack_offset))
    code.extend(b"\x48\xb8" + entry_address.to_bytes(8, "little"))
    code.extend(b"\xff\xd0")  # call rax
    code.extend(b"\x48\x81\xc4" + frame.to_bytes(4, "little"))
    code.extend(b"\xc3")
    return bytes(code)


class NativeBlake3Compressor:
    """Own executable storage for one XAX-lowered BLAKE3 compression leaf."""

    def __init__(self, image: NativeImage):
        machine = platform.machine().lower()
        if machine not in ("x86_64", "amd64"):
            raise RuntimeError(f"native XAX BLAKE3 requires x86-64 host, got {machine}")
        if image.parameter_widths != (32,) * 28 or image.return_kinds != ("a64",):
            raise RuntimeError(f"unexpected BLAKE3 XAX ABI: {image.parameter_widths!r} -> {image.return_kinds!r}")
        from xax_native import seal, writable_mapping

        # Allocate once, then place the ordinary XAX image followed by a host ABI
        # adapter.  The adapter only marshals arguments; it has no hash semantics.
        reserve = len(image.code) + 1024
        self._mapping, base = writable_mapping(reserve)
        self._mapping[: len(image.code)] = image.code
        entry = base + image.entry_offset
        thunk = _sysv_to_win64_blake3_thunk(entry)
        thunk_offset = (len(image.code) + 15) & ~15
        if thunk_offset + len(thunk) > reserve:
            raise RuntimeError("BLAKE3 native thunk reserve exhausted")
        self._mapping[thunk_offset : thunk_offset + len(thunk)] = thunk
        seal(base, reserve)
        prototype = ctypes.CFUNCTYPE(
            None,
            ctypes.POINTER(ctypes.c_uint32),
            ctypes.POINTER(ctypes.c_uint32),
        )
        self._call = prototype(base + thunk_offset)
        self.image = image
        self.thunk_size = len(thunk)
        # ADR-249: the 28 argument words and the aligned 16-word result are allocated once, not per block.  The
        # Win64 aggregate-return contract expects suitably aligned caller storage; ctypes only promises the element
        # alignment for a c_uint32 array, so over-allocate and align the result explicitly.
        self._inputs = (ctypes.c_uint32 * 28)()
        self._output_storage = (ctypes.c_uint8 * (64 + 15))()
        output_address = (ctypes.addressof(self._output_storage) + 15) & ~15
        self._output = (ctypes.c_uint32 * 16).from_address(output_address)
        self._output_pointer = ctypes.cast(output_address, ctypes.POINTER(ctypes.c_uint32))
        self._lock = threading.Lock()

    def compress(
        self,
        chaining_value: Sequence[int],
        block_words: Sequence[int],
        counter: int,
        block_len: int,
        flags: int,
    ) -> tuple[int, ...]:
        if len(chaining_value) != 8 or len(block_words) != 16:
            raise ValueError("BLAKE3 compression expects 8 CV words and 16 block words")
        with self._lock:
            inputs = self._inputs
            inputs[0:8] = [word & _MASK32 for word in chaining_value]
            inputs[8:24] = [word & _MASK32 for word in block_words]
            inputs[24:28] = [counter & _MASK32, (counter >> 32) & _MASK32, block_len & _MASK32, flags & _MASK32]
            self._call(self._output_pointer, inputs)
            return tuple(self._output)


_native_singleton: NativeBlake3Compressor | None = None


def native_blake3_compressor() -> NativeBlake3Compressor:
    global _native_singleton
    if _native_singleton is None:
        _native_singleton = NativeBlake3Compressor(compile_blake3_compress_native())
    return _native_singleton


__all__ = [
    "Blake3XaxProgram",
    "NativeBlake3Compressor",
    "build_blake3_compress_program",
    "compile_blake3_compress_native",
    "load_blake3_compress_program",
    "native_blake3_compressor",
]
