"""Direct JVM class-file backend (ADR-112).

Verified XAX semantics lower straight to one JVM class file (major version 61,
so floating point is strict IEEE 754) packaged as a deterministic stored JAR.
No Java source, ``javac``, ASM library, or XAX runtime is involved.

Representation (``jvm-classfile-v1``):

* ``bits<N>`` with N <= 32 is an ``int`` and with N <= 64 a ``long``; values
  are kept zero-extended to N bits, exactly as the wasm backend keeps them;
* ``f32``/``f64`` are ``float``/``double``;
* a JVM object reference is ``ptr<opaque-identity "jvm-ref:<descriptor>">``
  (``jvm_reference_type``): an unforgeable handle that no XAX memory
  operation accepts; it exists only as a foreign result or argument;
* every XAX function is a ``public static`` method; block parameters and
  node results are method locals; edges copy arguments and ``goto``.  All
  locals are typed for the whole method, so every branch target carries the
  same full StackMapTable frame;
* a trap is ``athrow`` of a ``java.lang.Error`` (the platform's abnormal
  termination); integer division by zero is the JVM's own
  ``ArithmeticException``.  The allocation exists only on the trap path;
* ``LineNumberTable`` line *k* is the method's *k*-th XAX node (1-based), so a
  JVM stack trace names the exact semantic node (``JvmImage.line_map``).

Foreign members are typed declarations under three ABIs; their identity
carries the class internal name and the exact member descriptor, which must
agree with the declared XAX types.  A Java exception escaping a foreign call
terminates the program like a trap: XAX code never observes or recovers it.

The process entry (``process_entry=True``) takes and returns only proof
values; the JAR's ``Main-Class`` is a generated ``main(String[])`` that calls
it and returns, which ends the JVM with status 0 (the platform lifecycle).
Any other status is an explicit ``java/lang/System.exit`` foreign call.
"""

from __future__ import annotations

import os
import shutil
import struct
import subprocess
import tempfile
import zipfile
import io
from dataclasses import dataclass
from typing import Callable, Sequence

from xax_artifact import ArtifactSemanticRange
from xax_compiler import parse_function_graph
from xax_compiler import (
    EffectDomain,
    FloatCompare,
    FloatFormat,
    bits_type,
    effect_type,
    float_type,
    IntCompare,
    JVM_ARCHITECTURE,
    JVM_FOREIGN_ABIS,
    JVM_GETSTATIC_ABI,
    JVM_INVOKESTATIC_ABI,
    JVM_INVOKEVIRTUAL_ABI,
    Kind,
    Operation,
    Permission,
    RESOURCE_EFFECT_OPERATIONS,
    SemanticObject,
    StoreReader,
    TerminatorKind,
    ValueRef,
    _decode_constant,
    _decode_function_interface,
    _decode_opaque_identity_type,
    _decode_pointer_type,
    _float_raw_bits,
    _int_to_float,
    _is_erased_proof_function,
    _is_proof_type,
    _parse_graph,
    decode_bits_width,
    decode_float_width,
    decode_foreign_function,
    decode_native_target,
    fail,
    foreign_function_symbol,
    opaque_identity_type,
    pointer_type,
    store_resolver,
    verify_store,
)

REFERENCE_PREFIX = b"jvm-ref:"
CLASS_MAJOR_VERSION = 61  # Java 17: strict IEEE floating point everywhere (JEP 306)
_ZIP_DATE = (1980, 1, 1, 0, 0, 0)


def jvm_reference_type(descriptor: bytes) -> SemanticObject:
    """A JVM reference to an object of field descriptor ``descriptor`` (``Ljava/lang/String;``, ``[I``)."""
    if not descriptor or descriptor[:1] not in (b"L", b"["):
        raise ValueError("JVM reference descriptor must be an object or array descriptor")
    return pointer_type(opaque_identity_type(REFERENCE_PREFIX + descriptor), Permission.READ, 8)


def jvm_static(class_name: bytes, member: bytes, inputs, outputs) -> SemanticObject:
    """``invokestatic class_name.member`` where ``member`` is ``name(descriptor)``."""
    return foreign_function_symbol(class_name, member, inputs, outputs, abi=JVM_INVOKESTATIC_ABI)


def jvm_virtual(class_name: bytes, member: bytes, inputs, outputs) -> SemanticObject:
    """``invokevirtual``; the first machine input is the receiver of type ``L<class_name>;``."""
    return foreign_function_symbol(class_name, member, inputs, outputs, abi=JVM_INVOKEVIRTUAL_ABI)


def jvm_static_field(class_name: bytes, field: bytes, inputs, outputs) -> SemanticObject:
    """``getstatic class_name.name`` where ``field`` is ``name:descriptor``."""
    return foreign_function_symbol(class_name, field, inputs, outputs, abi=JVM_GETSTATIC_ABI)


@dataclass(frozen=True)
class JavaBaseApi:
    """A bounded ``java.base`` package: standard output, process exit, and a few statics.

    Printing is ordered by the I/O effect and ending the process by the
    process effect; nothing else is reachable through these declarations.
    """

    b1: SemanticObject
    b16: SemanticObject
    b32: SemanticObject
    b64: SemanticObject
    f64: SemanticObject
    io_effect: SemanticObject
    process_effect: SemanticObject
    print_stream: SemanticObject
    system_out: SemanticObject
    println_long: SemanticObject
    println_double: SemanticObject
    print_char: SemanticObject
    flush: SemanticObject
    exit: SemanticObject
    sqrt: SemanticObject
    nano_time: SemanticObject
    bit_count: SemanticObject

    @property
    def types(self) -> tuple[SemanticObject, ...]:
        return (
            self.b1, self.b16, self.b32, self.b64, self.f64, self.io_effect, self.process_effect, self.print_stream,
            opaque_identity_type(REFERENCE_PREFIX + b"Ljava/io/PrintStream;"), effect_type(EffectDomain.TIME, 0),
        )

    @property
    def symbols(self) -> tuple[SemanticObject, ...]:
        return (
            self.system_out, self.println_long, self.println_double, self.print_char, self.flush,
            self.exit, self.sqrt, self.nano_time, self.bit_count,
        )


def java_base_api() -> JavaBaseApi:
    b1, b16, b32, b64, f64 = bits_type(1), bits_type(16), bits_type(32), bits_type(64), float_type(FloatFormat.BINARY64)
    io, process = effect_type(EffectDomain.IO, 0), effect_type(EffectDomain.SYSCALL, 0)
    time = effect_type(EffectDomain.TIME, 0)
    stream = jvm_reference_type(b"Ljava/io/PrintStream;")
    printer = b"java/io/PrintStream"
    return JavaBaseApi(
        b1, b16, b32, b64, f64, io, process, stream,
        jvm_static_field(b"java/lang/System", b"out:Ljava/io/PrintStream;", (io,), (stream, io)),
        jvm_virtual(printer, b"println(J)V", (stream, b64, io), (io,)),
        jvm_virtual(printer, b"println(D)V", (stream, f64, io), (io,)),
        jvm_virtual(printer, b"print(C)V", (stream, b16, io), (io,)),
        jvm_virtual(printer, b"flush()V", (stream, io), (io,)),
        # Never returns; the explicit call is the only nonzero-status exit path.
        jvm_static(b"java/lang/System", b"exit(I)V", (b32, process), (process,)),
        jvm_static(b"java/lang/Math", b"sqrt(D)D", (f64,), (f64,)),
        jvm_static(b"java/lang/System", b"nanoTime()J", (time,), (b64, time)),
        jvm_static(b"java/lang/Long", b"bitCount(J)I", (b64,), (b32,)),
    )


@dataclass(frozen=True)
class JvmImage:
    jar: bytes
    class_bytes: bytes
    class_name: str  # internal name, e.g. "xax/P0123abcd4567ef89"
    methods: tuple[tuple[bytes, str, str], ...]  # (function CID, name, descriptor)
    entry_method: str
    target_cid: bytes
    semantic_ranges: tuple[ArtifactSemanticRange, ...]
    line_map: tuple[tuple[str, int, bytes, int, int], ...]  # (method, line, function CID, block, node)
    parameter_kinds: tuple[str, ...]
    return_kinds: tuple[str, ...]
    main_class: bool
    entry_offset: int  # JAR offset of the entry method's code array

    @property
    def artifact_bytes(self) -> bytes:
        return self.jar


# ---------------------------------------------------------------- types


def _jvm_type(resolve: Callable[[bytes], SemanticObject], cid: bytes, where: str) -> str | None:
    """Field descriptor of a machine value, or ``None`` for an erased proof value."""
    obj = resolve(cid)
    if _is_proof_type(obj):
        return None
    form = obj.body[0] if obj.kind == Kind.TYPE and obj.body else None
    if form == 1:
        width = decode_bits_width(obj)
        if width <= 32:
            return "I"
        if width <= 64:
            return "J"
    elif form == 7:
        return "F" if decode_float_width(obj) == 32 else "D"
    elif form == 2:
        element, _permission, _alignment = _decode_pointer_type(obj, resolve)
        element_object = resolve(element)
        if element_object.body[:1] == b"\x06":
            identity = _decode_opaque_identity_type(element_object)
            if identity.startswith(REFERENCE_PREFIX):
                return identity[len(REFERENCE_PREFIX):].decode("ascii")
    fail("XAX.JVM.VALUE", where, "JVM-VALUE-REPRESENTABLE", "bits<=64, f32, f64, or jvm-ref", cid.hex())


def _slots(descriptor: str) -> int:
    return 2 if descriptor in ("J", "D") else 1


def _kind_letter(descriptor: str) -> str:
    return descriptor if descriptor in ("I", "J", "F", "D") else "A"


def _width(resolve: Callable[[bytes], SemanticObject], cid: bytes) -> int:
    return decode_bits_width(resolve(cid))


def _parse_method_descriptor(descriptor: str, where: str) -> tuple[tuple[str, ...], str]:
    if not descriptor.startswith("(") or ")" not in descriptor:
        fail("XAX.JVM.DESCRIPTOR", where, "JVM-METHOD-DESCRIPTOR", "(params)return", descriptor)
    inner, result = descriptor[1:].split(")", 1)
    params: list[str] = []
    index = 0
    while index < len(inner):
        start = index
        while inner[index] == "[":
            index += 1
        if inner[index] == "L":
            end = inner.find(";", index)
            if end < 0:
                fail("XAX.JVM.DESCRIPTOR", where, "JVM-METHOD-DESCRIPTOR", "terminated class descriptor", descriptor)
            index = end + 1
        elif inner[index] in "ZBCSIJFD":
            index += 1
        else:
            fail("XAX.JVM.DESCRIPTOR", where, "JVM-METHOD-DESCRIPTOR", "field descriptors", descriptor)
        params.append(inner[start:index])
    return tuple(params), result


# Narrow JVM parameter/result types and the XAX value each one carries.
_NARROW_WIDTH = {"Z": 1, "B": 8, "C": 16, "S": 16, "I": 32, "J": 64}


def _descriptor_matches(jvm: str, resolve: Callable[[bytes], SemanticObject], cid: bytes, where: str) -> bool:
    xax = _jvm_type(resolve, cid, where)
    if jvm in _NARROW_WIDTH:
        return xax in ("I", "J") and _width(resolve, cid) == _NARROW_WIDTH[jvm]
    return xax == jvm


@dataclass(frozen=True)
class _ForeignMember:
    opcode: int
    class_name: str
    name: str
    descriptor: str
    parameters: tuple[str, ...]  # JVM parameter descriptors in push order (receiver first)
    result: str  # JVM result descriptor, "V" for none


def _foreign_member(carrier: SemanticObject, resolve: Callable[[bytes], SemanticObject]) -> _ForeignMember:
    declaration = decode_foreign_function(carrier)
    where = carrier.cid.hex()
    if declaration.abi not in JVM_FOREIGN_ABIS:
        fail("XAX.FOREIGN.ABI", where, "JVM-FOREIGN-ABI", [abi.decode() for abi in JVM_FOREIGN_ABIS], declaration.abi.decode("ascii", "replace"))
    class_name = declaration.library.decode("ascii")
    member = declaration.name.decode("ascii")
    inputs = [cid for cid in declaration.inputs if not _is_proof_type(resolve(cid))]
    outputs = [cid for cid in declaration.outputs if not _is_proof_type(resolve(cid))]
    if declaration.abi == JVM_GETSTATIC_ABI:
        if ":" not in member:
            fail("XAX.JVM.DESCRIPTOR", where, "JVM-FIELD-MEMBER", "name:descriptor", member)
        name, descriptor = member.split(":", 1)
        parameters, result, opcode = (), descriptor, 0xB2
    else:
        if "(" not in member:
            fail("XAX.JVM.DESCRIPTOR", where, "JVM-METHOD-MEMBER", "name(descriptor)", member)
        name, rest = member.split("(", 1)
        descriptor = "(" + rest
        parameters, result = _parse_method_descriptor(descriptor, where)
        opcode = 0xB8
        if declaration.abi == JVM_INVOKEVIRTUAL_ABI:
            parameters = (f"L{class_name};", *parameters)
            opcode = 0xB6
    if not name or len(inputs) != len(parameters) or len(outputs) != (result != "V"):
        fail("XAX.JVM.FOREIGN", where, "JVM-FOREIGN-ARITY", [list(parameters), result], [len(inputs), len(outputs)])
    for jvm, cid in (*zip(parameters, inputs), *((result, cid) for cid in outputs)):
        if not _descriptor_matches(jvm, resolve, cid, where):
            fail("XAX.JVM.FOREIGN", where, "JVM-FOREIGN-DESCRIPTOR-TYPE", jvm, cid.hex())
    return _ForeignMember(opcode, class_name, name, descriptor, parameters, result)


# ---------------------------------------------------------------- class file


def _u2(value: int) -> bytes:
    return struct.pack(">H", value)


def _u4(value: int) -> bytes:
    return struct.pack(">I", value & 0xFFFFFFFF)


class _Pool:
    def __init__(self) -> None:
        self.data = bytearray()
        self.count = 1
        self.index: dict[tuple, int] = {}

    def _add(self, key: tuple, blob: bytes, slots: int = 1) -> int:
        if key not in self.index:
            self.index[key] = self.count
            self.data.extend(blob)
            self.count += slots
            if self.count > 0xFFFF:
                fail("XAX.JVM.LIMIT", "class", "JVM-CONSTANT-POOL-SIZE", "<= 65535 entries", self.count)
        return self.index[key]

    def utf8(self, text: str) -> int:
        raw = text.encode("ascii")
        return self._add(("u", text), b"\x01" + _u2(len(raw)) + raw)

    def klass(self, name: str) -> int:
        return self._add(("c", name), b"\x07" + _u2(self.utf8(name)))

    def string(self, text: str) -> int:
        return self._add(("s", text), b"\x08" + _u2(self.utf8(text)))

    def integer(self, value: int) -> int:
        return self._add(("i", value & 0xFFFFFFFF), b"\x03" + _u4(value))

    def float_bits(self, bits: int) -> int:
        return self._add(("f", bits), b"\x04" + _u4(bits))

    def long(self, value: int) -> int:
        value &= (1 << 64) - 1
        return self._add(("l", value), b"\x05" + struct.pack(">Q", value), 2)

    def double_bits(self, bits: int) -> int:
        return self._add(("d", bits), b"\x06" + struct.pack(">Q", bits), 2)

    def name_type(self, name: str, descriptor: str) -> int:
        return self._add(("nt", name, descriptor), b"\x0c" + _u2(self.utf8(name)) + _u2(self.utf8(descriptor)))

    def method(self, owner: str, name: str, descriptor: str) -> int:
        return self._add(("m", owner, name, descriptor), b"\x0a" + _u2(self.klass(owner)) + _u2(self.name_type(name, descriptor)))

    def field(self, owner: str, name: str, descriptor: str) -> int:
        return self._add(("fd", owner, name, descriptor), b"\x09" + _u2(self.klass(owner)) + _u2(self.name_type(name, descriptor)))

    def verification_type(self, descriptor: str) -> bytes:
        tag = {"I": 1, "F": 2, "D": 3, "J": 4}.get(descriptor)
        if tag is not None:
            return bytes((tag,))
        name = descriptor[1:-1] if descriptor.startswith("L") else descriptor
        return b"\x07" + _u2(self.klass(name))


@dataclass
class _Method:
    name: str
    descriptor: str
    code: bytes
    max_stack: int
    max_locals: int
    frames: tuple[int, ...]  # sorted branch-target offsets (all share one full frame)
    frame_locals: tuple[str, ...]
    lines: tuple[tuple[int, int], ...]  # (start pc, line)
    node_ranges: tuple[tuple[int, int, int, int, int], ...] = ()  # (block, node, line, start, end)
    function_cid: bytes | None = None


class _Code:
    def __init__(self, where: str) -> None:
        self.where = where
        self.buf = bytearray()
        self.labels: dict[object, int] = {}
        self.fixups: list[tuple[int, object]] = []
        self.targets: set[object] = set()

    def op(self, *values: int) -> None:
        self.buf.extend(values)

    def raw(self, blob: bytes) -> None:
        self.buf.extend(blob)

    def branch(self, opcode: int, label: object) -> None:
        self.fixups.append((len(self.buf), label))
        self.targets.add(label)
        self.buf.extend((opcode, 0, 0))

    def mark(self, label: object) -> None:
        self.labels[label] = len(self.buf)
        self.targets.add(label)

    def finish(self) -> tuple[bytes, tuple[int, ...]]:
        for position, label in self.fixups:
            delta = self.labels[label] - position
            if not -0x8000 <= delta <= 0x7FFF:
                fail("XAX.JVM.LIMIT", self.where, "JVM-BRANCH-RANGE", "16-bit branch offset", delta)
            self.buf[position + 1 : position + 3] = struct.pack(">h", delta)
        if len(self.buf) > 0xFFFF:
            fail("XAX.JVM.LIMIT", self.where, "JVM-METHOD-CODE-SIZE", "<= 65535 bytes", len(self.buf))
        return bytes(self.buf), tuple(sorted({self.labels[label] for label in self.targets}))


_LOAD = {"I": 0x15, "J": 0x16, "F": 0x17, "D": 0x18, "A": 0x19}
_STORE = {"I": 0x36, "J": 0x37, "F": 0x38, "D": 0x39, "A": 0x3A}
_RETURN = {"I": 0xAC, "J": 0xAD, "F": 0xAE, "D": 0xAF, "A": 0xB0}
_ZERO = {"I": (0x03,), "J": (0x09,), "F": (0x0B,), "D": (0x0E,), "A": (0x01,)}
_ARITHMETIC = {  # (int, long, float, double) opcode bases
    Operation.ADD_WRAP: (0x60, 0x61), Operation.SUB_WRAP: (0x64, 0x65), Operation.MUL_WRAP: (0x68, 0x69),
    Operation.BIT_AND: (0x7E, 0x7F), Operation.BIT_OR: (0x80, 0x81), Operation.BIT_XOR: (0x82, 0x83),
}
_FLOAT_ARITHMETIC = {
    Operation.FLOAT_ADD: (0x62, 0x63), Operation.FLOAT_SUB: (0x66, 0x67),
    Operation.FLOAT_MUL: (0x6A, 0x6B), Operation.FLOAT_DIV: (0x6E, 0x6F),
}
_TRAP_MESSAGE = "XAX trap"


def _function_closure(entry: SemanticObject, resolve, supported_operations, supported_terminators) -> tuple[SemanticObject, ...]:
    functions: dict[bytes, SemanticObject] = {}
    pending = [entry]
    while pending:
        function = pending.pop()
        if function.cid in functions:
            continue
        functions[function.cid] = function
        graph_object, _parameters, _returns = _decode_function_interface(function, resolve)
        for block in parse_function_graph(function, resolve).blocks:
            for node in block.nodes:
                if node.operation not in supported_operations:
                    fail("XAX.JVM.UNSUPPORTED_OPERATION", graph_object.cid.hex(), "JVM-OP-TARGET-SUPPORTED", list(supported_operations), node.operation)
                if node.operation == Operation.CALL_DIRECT and not _is_erased_proof_function(node.entity, resolve):
                    pending.append(node.entity)
            if block.terminator.kind not in supported_terminators:
                fail("XAX.JVM.UNSUPPORTED_TERMINATOR", graph_object.cid.hex(), "JVM-TERMINATOR-TARGET-SUPPORTED", list(supported_terminators), block.terminator.kind)
    return tuple(functions[cid] for cid in sorted(functions))


def _signature(function: SemanticObject, resolve) -> tuple[tuple[str, ...], tuple[str, ...]]:
    _graph, parameters, returns = _decode_function_interface(function, resolve)
    where = function.cid.hex()
    machine_parameters = tuple(t for t in (_jvm_type(resolve, cid, where) for cid in parameters) if t is not None)
    machine_returns = tuple(t for t in (_jvm_type(resolve, cid, where) for cid in returns) if t is not None)
    if len(machine_returns) > 1:
        fail("XAX.JVM.ABI", where, "JVM-SINGLE-RESULT", "at most one machine result", list(machine_returns))
    return machine_parameters, machine_returns


def _method_descriptor(parameters: Sequence[str], returns: Sequence[str]) -> str:
    return "(" + "".join(parameters) + ")" + (returns[0] if returns else "V")


def _compile_method(
    function: SemanticObject,
    name: str,
    resolve: Callable[[bytes], SemanticObject],
    pool: _Pool,
    class_name: str,
    methods: dict[bytes, tuple[str, str]],
) -> _Method:
    graph_object, parameter_types, return_types = _decode_function_interface(function, resolve)
    graph = parse_function_graph(function, resolve)
    where = graph_object.cid.hex()
    parameters, returns = _signature(function, resolve)
    code = _Code(where)

    slot_of: dict[ValueRef, tuple[int, str]] = {}
    frame_locals: list[str] = []
    next_slot = 0

    def allocate(descriptor: str) -> int:
        nonlocal next_slot
        slot = next_slot
        next_slot += _slots(descriptor)
        frame_locals.append(descriptor)
        return slot

    def value_type(cid: bytes) -> str | None:
        return _jvm_type(resolve, cid, where)

    def edge_moves(target: int, arguments: Sequence[ValueRef]) -> list[tuple[int, ValueRef]]:
        return [
            (index, argument) for index, argument in enumerate(arguments)
            if value_type(graph.blocks[target].parameters[index]) is not None
        ]

    # Method-wide ("global") locals: block parameters and values used outside
    # their block.  They are typed in every frame and zeroed by the prelude.
    # Every other value lives in a per-block scratch region that frames leave
    # as Top, so it needs no initialization and is reused by the next block.
    use_blocks: dict[ValueRef, set[int]] = {}
    for block_index, block in enumerate(graph.blocks):
        for node in block.nodes:
            for operand in node.operands:
                use_blocks.setdefault(operand, set()).add(block_index)
        for value in (*block.terminator.values, *(argument for _target, arguments in block.terminator.edges for argument in arguments)):
            use_blocks.setdefault(value, set()).add(block_index)
    labelled_blocks = set()  # blocks whose lowering places branch targets between nodes
    stub_arguments: set[ValueRef] = set()  # copied after a false-edge stub label
    for block_index, block in enumerate(graph.blocks):
        for node in block.nodes:
            if (node.operation == Operation.UINT_TO_FLOAT and _width(resolve, node.operand_types[0]) == 64) or (
                node.operation == Operation.FLOAT_TO_UINT_TRUNC and _width(resolve, node.results[0]) == 64
            ):
                labelled_blocks.add(block_index)
        terminator = block.terminator
        if terminator.kind == TerminatorKind.CONDITIONAL_BRANCH and all(edge_moves(*edge) for edge in terminator.edges):
            stub_arguments.update(argument for _index, argument in edge_moves(*terminator.edges[1]))

    def is_global(ref: ValueRef) -> bool:
        return ref.tag == 0 or ref.block in labelled_blocks or ref in stub_arguments or use_blocks.get(ref, set()) - {ref.block} != set()

    for index, cid in enumerate(graph.blocks[graph.entry].parameters):
        descriptor = value_type(cid)
        if descriptor is not None:
            slot_of[ValueRef.parameter(graph.entry, index)] = (allocate(descriptor), descriptor)
    parameter_slot_end = next_slot
    for block_index, block in enumerate(graph.blocks):
        if block_index != graph.entry:
            for index, cid in enumerate(block.parameters):
                descriptor = value_type(cid)
                if descriptor is not None:
                    slot_of[ValueRef.parameter(block_index, index)] = (allocate(descriptor), descriptor)
        for node_index, node in enumerate(block.nodes):
            for result_index, cid in enumerate(node.results):
                ref = ValueRef.node_result(block_index, node_index, result_index)
                descriptor = value_type(cid)
                if descriptor is not None and is_global(ref):
                    slot_of[ref] = (allocate(descriptor), descriptor)
    global_slot_end = next_slot
    scratch = [global_slot_end]
    max_locals = [global_slot_end]

    def scratch_slot(descriptor: str) -> int:
        slot = scratch[0]
        scratch[0] += _slots(descriptor)
        max_locals[0] = max(max_locals[0], scratch[0])
        return slot

    def enter_block(block_index: int) -> None:
        scratch[0] = global_slot_end
        for node_index, node in enumerate(graph.blocks[block_index].nodes):
            for result_index, cid in enumerate(node.results):
                ref = ValueRef.node_result(block_index, node_index, result_index)
                descriptor = value_type(cid)
                if descriptor is not None and ref not in slot_of:
                    slot_of[ref] = (scratch_slot(descriptor), descriptor)

    def local(opcode_table: dict[str, int], descriptor: str, slot: int) -> None:
        opcode = opcode_table[_kind_letter(descriptor)]
        if slot <= 0xFF:
            code.op(opcode, slot)
        else:
            code.op(0xC4, opcode)
            code.raw(_u2(slot))

    def get(ref: ValueRef) -> str:
        try:
            slot, descriptor = slot_of[ref]
        except KeyError:
            fail("XAX.JVM.VALUE", where, "JVM-VALUE-MACHINE", "machine value", [ref.tag, ref.block, ref.index, ref.result])
        local(_LOAD, descriptor, slot)
        return descriptor

    def put(ref: ValueRef) -> None:
        slot, descriptor = slot_of[ref]
        local(_STORE, descriptor, slot)

    def iconst(value: int) -> None:
        value = value & 0xFFFFFFFF
        signed = value - (1 << 32) if value >> 31 else value
        if -1 <= signed <= 5:
            code.op(0x03 + signed)
        elif -128 <= signed <= 127:
            code.op(0x10, signed & 0xFF)
        elif -32768 <= signed <= 32767:
            code.op(0x11)
            code.raw(struct.pack(">h", signed))
        else:
            ldc(pool.integer(value))

    def lconst(value: int) -> None:
        value &= (1 << 64) - 1
        if value in (0, 1):
            code.op(0x09 + value)
        else:
            code.op(0x14)
            code.raw(_u2(pool.long(value)))

    def ldc(index: int) -> None:
        if index <= 0xFF:
            code.op(0x12, index)
        else:
            code.op(0x13)
            code.raw(_u2(index))

    def fconst(value: float, width: int) -> None:
        fconst_bits(_float_raw_bits(value, width), width)

    def fconst_bits(bits: int, width: int) -> None:
        if width == 32:
            special = {0x00000000: 0x0B, 0x3F800000: 0x0C, 0x40000000: 0x0D}.get(bits)
            code.op(special) if special is not None else ldc(pool.float_bits(bits))
        else:
            special = {0x0000000000000000: 0x0E, 0x3FF0000000000000: 0x0F}.get(bits)
            if special is not None:
                code.op(special)
            else:
                code.op(0x14)
                code.raw(_u2(pool.double_bits(bits)))

    def const(descriptor: str, value: int) -> None:
        iconst(value) if descriptor == "I" else lconst(value)

    def mask(descriptor: str, width: int) -> None:
        if descriptor == "I" and width < 32:
            iconst((1 << width) - 1)
            code.op(0x7E)
        elif descriptor == "J" and width < 64:
            lconst((1 << width) - 1)
            code.op(0x7F)

    def sign_extend(descriptor: str, width: int) -> None:
        storage = 32 if descriptor == "I" else 64
        if width < storage:
            iconst(storage - width)
            code.op(0x78 if descriptor == "I" else 0x79)  # shl
            iconst(storage - width)
            code.op(0x7A if descriptor == "I" else 0x7B)  # shr

    def get_as_long(ref: ValueRef, width: int, signed: bool) -> None:
        """Push ``ref`` widened to a long whose signed order is the requested order."""
        descriptor = get(ref)
        if signed:
            sign_extend(descriptor, width)
            if descriptor == "I":
                code.op(0x85)
        elif descriptor == "I":
            code.op(0x85)
            if width == 32:
                lconst(0xFFFFFFFF)
                code.op(0x7F)
        elif width == 64:
            lconst(1 << 63)
            code.op(0x83)  # flip the sign bit: unsigned order becomes signed order

    def compare_to_int(node) -> str:
        """Push an int r in {-1, 0, 1} ordered like the operands; return the relation r must satisfy."""
        if node.operation == Operation.FLOAT_COMPARE:
            kind = FloatCompare(node.attributes[0])
            descriptor = get(node.operands[0]); get(node.operands[1])
            # Pick the NaN result that makes each ordered relation false and NE true.
            float_cmp(32 if descriptor == "F" else 64, nan_high=kind in (FloatCompare.LT, FloatCompare.LE))
            return _FLOAT_RELATION[kind]
        kind = IntCompare(node.attributes[0])
        width = _width(resolve, node.operand_types[0])
        signed = kind in (IntCompare.SLT, IntCompare.SLE, IntCompare.SGT, IntCompare.SGE)
        get_as_long(node.operands[0], width, signed)
        get_as_long(node.operands[1], width, signed)
        code.op(0x94)  # lcmp
        return _INT_RELATION[kind]

    label_counter = [0]

    def fresh() -> tuple:
        label_counter[0] += 1
        return ("local", label_counter[0])

    def float_cmp(width: int, nan_high: bool) -> None:
        code.op((0x96 if nan_high else 0x95) if width == 32 else (0x98 if nan_high else 0x97))

    def trap_if(compare: Callable[[], None], branch: int) -> None:
        compare()
        code.branch(branch, "trap")

    # Integer constants by value reference, for strength reduction.
    constants: dict[ValueRef, int] = {}
    for block_index, block in enumerate(graph.blocks):
        for node_index, node in enumerate(block.nodes):
            if node.operation == Operation.CONSTANT and value_type(node.results[0]) in ("I", "J"):
                constants[ValueRef.node_result(block_index, node_index)] = int(_decode_constant(node.entity, resolve)[1])

    # A compare whose only use is its own block's conditional branch fuses
    # into that branch (``lcmp``/``fcmp`` + ``if<cond>``), as javac emits it.
    uses: dict[ValueRef, int] = {}
    for block in graph.blocks:
        for node in block.nodes:
            for operand in node.operands:
                uses[operand] = uses.get(operand, 0) + 1
        for value in (*block.terminator.values, *(argument for _target, arguments in block.terminator.edges for argument in arguments)):
            uses[value] = uses.get(value, 0) + 1
    fused: set[ValueRef] = set()
    for block_index, block in enumerate(graph.blocks):
        if block.terminator.kind == TerminatorKind.CONDITIONAL_BRANCH:
            condition = block.terminator.values[0]
            if condition.tag == 1 and condition.block == block_index and uses.get(condition) == 1:
                if block.nodes[condition.index].operation in (Operation.INT_COMPARE, Operation.FLOAT_COMPARE):
                    fused.add(condition)

    lines: list[tuple[int, int]] = []
    node_ranges: list[tuple[int, int, int, int, int]] = []
    line = 0

    # Prelude: give every non-parameter local its type before the first branch target.
    position = 0
    for descriptor in frame_locals:
        if position >= parameter_slot_end:
            code.op(*_ZERO[_kind_letter(descriptor)])
            local(_STORE, descriptor, position)
        position += _slots(descriptor)
    if not code.buf:
        code.op(0x00)  # a branch target may not be the implicit frame at offset 0

    def copy_edge(target: int, arguments: Sequence[ValueRef], *, jump: bool = True, force: bool = False) -> None:
        moves = [move for move in edge_moves(target, arguments) if move[1] != ValueRef.parameter(target, move[0])]
        overlapping = any(argument.tag == 0 and argument.block == target for _index, argument in moves)
        if overlapping:
            temporaries = []
            for _index, argument in moves:
                descriptor = get(argument)
                temporary = scratch_slot(descriptor)
                local(_STORE, descriptor, temporary)
                temporaries.append(temporary)
            for (index, _argument), temporary in zip(moves, temporaries):
                _slot, descriptor = slot_of[ValueRef.parameter(target, index)]
                local(_LOAD, descriptor, temporary)
                put(ValueRef.parameter(target, index))
        else:
            for index, argument in moves:
                get(argument)
                put(ValueRef.parameter(target, index))
        if jump and (force or target != following_block[0]):
            code.branch(0xA7, ("block", target))

    order = [graph.entry] + [index for index in range(len(graph.blocks)) if index != graph.entry]
    trap_used = False
    max_call_slots = 0
    following_block = [None]
    for position_in_order, block_index in enumerate(order):
        following_block[0] = order[position_in_order + 1] if position_in_order + 1 < len(order) else None
        block = graph.blocks[block_index]
        code.mark(("block", block_index))
        enter_block(block_index)
        for node_index, node in enumerate(block.nodes):
            line += 1
            start = len(code.buf)
            lines.append((start, line))
            result = ValueRef.node_result(block_index, node_index)
            operation = node.operation

            if operation in _ARITHMETIC:
                width = _width(resolve, node.results[0])
                descriptor = get(node.operands[0])
                get(node.operands[1])
                code.op(_ARITHMETIC[Operation(operation)][descriptor == "J"])
                if operation in (Operation.ADD_WRAP, Operation.SUB_WRAP, Operation.MUL_WRAP):
                    mask(descriptor, width)
                put(result)

            elif operation in (Operation.UDIV, Operation.UREM):
                # A zero divisor raises the JVM's ArithmeticException: the trap.
                width = _width(resolve, node.results[0])
                divide = operation == Operation.UDIV
                divisor = constants.get(node.operands[1])
                if divisor and divisor & (divisor - 1) == 0:
                    # Power-of-two divisor: exact shift or mask, no trap possible.
                    descriptor = get(node.operands[0])
                    if divide:
                        iconst(divisor.bit_length() - 1); code.op(0x7D if descriptor == "J" else 0x7C)
                    else:
                        const(descriptor, divisor - 1); code.op(0x7F if descriptor == "J" else 0x7E)
                elif width == 64:
                    get(node.operands[0]); get(node.operands[1])
                    code.op(0xB8)
                    code.raw(_u2(pool.method("java/lang/Long", "divideUnsigned" if divide else "remainderUnsigned", "(JJ)J")))
                elif width == 32:
                    get_as_long(node.operands[0], 32, False); get_as_long(node.operands[1], 32, False)
                    code.op(0x6D if divide else 0x71, 0x88)  # ldiv/lrem; l2i
                else:
                    descriptor = get(node.operands[0]); get(node.operands[1])
                    code.op((0x6C if divide else 0x70) + (descriptor == "J"))
                put(result)

            elif operation == Operation.ROTATE_RIGHT:
                width = _width(resolve, node.results[0])
                amount = node.attributes[0]
                descriptor = get(node.operands[0])
                if amount:
                    long_ = descriptor == "J"
                    iconst(amount); code.op(0x7D if long_ else 0x7C)  # ushr
                    get(node.operands[0]); iconst(width - amount); code.op(0x79 if long_ else 0x78)  # shl
                    code.op(0x81 if long_ else 0x80)  # or
                    mask(descriptor, width)
                put(result)

            elif operation in (Operation.INT_TRUNCATE, Operation.INT_ZERO_EXTEND):
                source = _width(resolve, node.operand_types[0])
                destination = _width(resolve, node.results[0])
                source_descriptor = get(node.operands[0])
                destination_descriptor = slot_of[result][1]
                if source_descriptor == "J" and destination_descriptor == "I":
                    code.op(0x88)
                elif source_descriptor == "I" and destination_descriptor == "J":
                    code.op(0x85)
                    if source == 32:
                        lconst(0xFFFFFFFF); code.op(0x7F)
                if operation == Operation.INT_TRUNCATE:
                    mask(destination_descriptor, destination)
                put(result)

            elif operation == Operation.CONSTANT:
                type_cid, value = _decode_constant(node.entity, resolve)
                descriptor = slot_of[result][1]
                if descriptor in ("F", "D"):
                    # Raw constant bits, so NaN payloads stay exact.
                    width = 32 if descriptor == "F" else 64
                    fconst_bits(int.from_bytes(node.entity.body[-(width // 8):], "little"), width)
                else:
                    const(descriptor, int(value))
                put(result)

            elif operation in _FLOAT_ARITHMETIC:
                descriptor = get(node.operands[0]); get(node.operands[1])
                code.op(_FLOAT_ARITHMETIC[Operation(operation)][descriptor == "D"])
                put(result)

            elif operation == Operation.FLOAT_CONVERT:
                source = get(node.operands[0])
                destination = slot_of[result][1]
                if source != destination:
                    code.op(0x8D if source == "F" else 0x90)
                put(result)

            elif operation in (Operation.FLOAT_COMPARE, Operation.INT_COMPARE):
                if result not in fused:
                    relation = compare_to_int(node)
                    _compare_result(code, iconst, relation)
                    put(result)

            elif operation in (Operation.UINT_TO_FLOAT, Operation.SINT_TO_FLOAT):
                width = _width(resolve, node.operand_types[0])
                destination = slot_of[result][1]
                signed = operation == Operation.SINT_TO_FLOAT
                to_float = destination == "F"
                if not signed and width == 64:
                    # u64: values with the top bit set halve with a sticky bit, convert, and double.
                    negative, done = fresh(), fresh()
                    get(node.operands[0]); lconst(0); code.op(0x94); code.branch(0x9B, negative)
                    get(node.operands[0]); code.op(0x89 if to_float else 0x8A); put(result); code.branch(0xA7, done)
                    code.mark(negative)
                    get(node.operands[0]); iconst(1); code.op(0x7D)
                    get(node.operands[0]); lconst(1); code.op(0x7F, 0x81)
                    code.op(0x89 if to_float else 0x8A)
                    code.op(0x59, 0x62) if to_float else code.op(0x5C, 0x63)  # dup/dup2; add
                    put(result)
                    code.mark(done)
                else:
                    source_long = slot_of[node.operands[0]][1] == "J" or (width == 32 and not signed)
                    if source_long:
                        get_as_long(node.operands[0], width, signed)
                    else:
                        descriptor = get(node.operands[0])
                        if signed:
                            sign_extend(descriptor, width)
                    code.op((0x89 if to_float else 0x8A) if source_long else (0x86 if to_float else 0x87))
                    put(result)

            elif operation in (Operation.FLOAT_TO_UINT_TRUNC, Operation.FLOAT_TO_SINT_TRUNC):
                trap_used = True
                source = slot_of[node.operands[0]][1]
                source_width = 32 if source == "F" else 64
                width = _width(resolve, node.results[0])
                destination = slot_of[result][1]
                signed = operation == Operation.FLOAT_TO_SINT_TRUNC

                def against(threshold: float, nan_high: bool) -> Callable[[], None]:
                    def emit() -> None:
                        get(node.operands[0]); fconst(threshold, source_width); float_cmp(source_width, nan_high)
                    return emit

                # NaN traps: v compared with itself is unordered only for NaN.
                get(node.operands[0]); get(node.operands[0]); float_cmp(source_width, False); code.branch(0x9A, "trap")
                if signed:
                    lower = -(1 << (width - 1))
                    if _int_to_float(lower - 1, source_width) == lower - 1:
                        trap_if(against(float(lower - 1), False), 0x9E)  # v <= lower-1
                    else:
                        trap_if(against(float(lower), False), 0x9B)  # v < lower
                    trap_if(against(float(1 << (width - 1)), False), 0x9C)  # v >= 2^(w-1)
                    get(node.operands[0])
                    code.op((0x8B if source == "F" else 0x8E) if destination == "I" else (0x8C if source == "F" else 0x8F))
                    mask(destination, width)
                    put(result)
                else:
                    trap_if(against(0.0, False), 0x9B)  # v < 0
                    trap_if(against(float(1 << width), False), 0x9C)  # v >= 2^w
                    to_long = 0x8C if source == "F" else 0x8F
                    if width == 64:
                        small, done = fresh(), fresh()
                        against(float(1 << 63), False)(); code.branch(0x9B, small)
                        get(node.operands[0]); fconst(float(1 << 63), source_width); code.op(0x66 if source == "F" else 0x67, to_long)
                        lconst(1 << 63); code.op(0x83); put(result); code.branch(0xA7, done)
                        code.mark(small)
                        get(node.operands[0]); code.op(to_long); put(result)
                        code.mark(done)
                    elif destination == "I":
                        get(node.operands[0])
                        code.op(to_long, 0x88) if width == 32 else code.op(0x8B if source == "F" else 0x8E)
                        put(result)
                    else:
                        get(node.operands[0]); code.op(to_long); put(result)

            elif operation == Operation.CALL_DIRECT:
                if not _is_erased_proof_function(node.entity, resolve):
                    machine = [operand for operand, cid in zip(node.operands, node.operand_types) if value_type(cid) is not None]
                    slots = 0
                    for operand in machine:
                        slots += _slots(get(operand))
                    max_call_slots = max(max_call_slots, slots)
                    callee_name, callee_descriptor = methods[node.entity.cid]
                    code.op(0xB8)
                    code.raw(_u2(pool.method(class_name, callee_name, callee_descriptor)))
                    _store_call_result(node, block_index, node_index, slot_of, put)

            elif operation == Operation.CALL_FOREIGN:
                member = _foreign_member(node.entity, resolve)
                machine = [operand for operand, cid in zip(node.operands, node.operand_types) if value_type(cid) is not None]
                slots = 0
                for operand, parameter in zip(machine, member.parameters):
                    slots += _slots(get(operand))
                    narrow = {"B": 0x91, "C": 0x92, "S": 0x93}.get(parameter)
                    if narrow is not None:
                        code.op(narrow)
                max_call_slots = max(max_call_slots, slots)
                reference = (pool.field if member.opcode == 0xB2 else pool.method)(member.class_name, member.name, member.descriptor)
                code.op(member.opcode)
                code.raw(_u2(reference))
                if member.result in ("B", "S"):
                    mask("I", _NARROW_WIDTH[member.result])  # the JVM returns these sign-extended
                _store_call_result(node, block_index, node_index, slot_of, put)

            elif operation in RESOURCE_EFFECT_OPERATIONS:
                pass  # proof values only: erased

            else:
                fail("XAX.JVM.UNSUPPORTED_OPERATION", where, "JVM-OP-LOWERED", "jvm-classfile-v1 subset", operation)
            node_ranges.append((block_index, node_index, line, start, len(code.buf)))

        terminator = block.terminator
        if terminator.kind == TerminatorKind.RETURN:
            machine = [value for value, cid in zip(terminator.values, return_types) if value_type(cid) is not None]
            if machine:
                descriptor = get(machine[0])
                code.op(_RETURN[_kind_letter(descriptor)])
            else:
                code.op(0xB1)
        elif terminator.kind == TerminatorKind.BRANCH:
            copy_edge(*terminator.edges[0])
        elif terminator.kind == TerminatorKind.CONDITIONAL_BRANCH:
            condition = terminator.values[0]
            if condition in fused:
                branch_if_not = _BRANCH_IF_NOT[compare_to_int(block.nodes[condition.index])]
            else:
                get(condition)
                branch_if_not = 0x99  # ifeq
            (true_target, true_arguments), (false_target, false_arguments) = terminator.edges
            true_moves = [m for m in edge_moves(true_target, true_arguments) if m[1] != ValueRef.parameter(true_target, m[0])]
            false_moves = [m for m in edge_moves(false_target, false_arguments) if m[1] != ValueRef.parameter(false_target, m[0])]
            if not false_moves:
                code.branch(branch_if_not, ("block", false_target))
                copy_edge(true_target, true_arguments)
            elif not true_moves:
                code.branch(_INVERSE_BRANCH[branch_if_not], ("block", true_target))
                copy_edge(false_target, false_arguments)
            else:
                false_stub = ("false", block_index)
                code.branch(branch_if_not, false_stub)
                copy_edge(true_target, true_arguments, force=True)  # the false stub follows, not the next block
                code.mark(false_stub)
                copy_edge(false_target, false_arguments)
        else:
            trap_used = True
            code.branch(0xA7, "trap")
    if trap_used:
        code.mark("trap")
        code.op(0xBB); code.raw(_u2(pool.klass("java/lang/Error")))
        code.op(0x59)
        ldc(pool.string(_TRAP_MESSAGE))
        code.op(0xB7); code.raw(_u2(pool.method("java/lang/Error", "<init>", "(Ljava/lang/String;)V")))
        code.op(0xBF)
    blob, frames = code.finish()
    max_stack = max(8, max_call_slots + 2)
    return _Method(
        name, _method_descriptor(parameters, returns), blob, max_stack, max_locals[0],
        frames, tuple(frame_locals), tuple(lines), tuple(node_ranges), function.cid,
    )


_FLOAT_RELATION = {
    FloatCompare.EQ: "eq", FloatCompare.NE: "ne", FloatCompare.LT: "lt",
    FloatCompare.LE: "le", FloatCompare.GT: "gt", FloatCompare.GE: "ge",
}
_INT_RELATION = {
    IntCompare.EQ: "eq", IntCompare.NE: "ne",
    IntCompare.ULT: "lt", IntCompare.SLT: "lt", IntCompare.ULE: "le", IntCompare.SLE: "le",
    IntCompare.UGT: "gt", IntCompare.SGT: "gt", IntCompare.UGE: "ge", IntCompare.SGE: "ge",
}
# if<cond> on r that branches when the relation is false.
_BRANCH_IF_NOT = {"eq": 0x9A, "ne": 0x99, "lt": 0x9C, "ge": 0x9B, "gt": 0x9E, "le": 0x9D}
_INVERSE_BRANCH = {0x99: 0x9A, 0x9A: 0x99, 0x9B: 0x9C, 0x9C: 0x9B, 0x9D: 0x9E, 0x9E: 0x9D}


def _compare_result(code: _Code, iconst, relation: str) -> None:
    """Turn a ``lcmp``/``fcmp`` result r in {-1, 0, 1} into 0/1 without branching."""
    if relation == "eq":
        iconst(1); code.op(0x7E); iconst(1); code.op(0x82)  # (r & 1) ^ 1
    elif relation == "ne":
        iconst(1); code.op(0x7E)  # r & 1
    elif relation == "lt":
        iconst(31); code.op(0x7C)  # r >>> 31
    elif relation == "gt":
        code.op(0x74); iconst(31); code.op(0x7C)  # -r >>> 31
    elif relation == "le":
        code.op(0x74); iconst(31); code.op(0x7C); iconst(1); code.op(0x82)
    else:  # ge
        iconst(31); code.op(0x7C); iconst(1); code.op(0x82)


def _store_call_result(node, block_index: int, node_index: int, slot_of, put) -> None:
    machine = [index for index in range(len(node.results)) if ValueRef.node_result(block_index, node_index, index) in slot_of]
    if len(machine) > 1:
        fail("XAX.JVM.ABI", "call", "JVM-SINGLE-RESULT", "at most one machine result", len(machine))
    if machine:
        put(ValueRef.node_result(block_index, node_index, machine[0]))


def _main_method(pool: _Pool, class_name: str, entry_name: str) -> _Method:
    code = bytes((0xB8,)) + _u2(pool.method(class_name, entry_name, "()V")) + bytes((0xB1,))
    return _Method("main", "([Ljava/lang/String;)V", code, 0, 1, (), (), ())


def _serialize_method(method: _Method, pool: _Pool) -> bytes:
    attributes = []
    if method.frames:
        entries = bytearray()
        previous = -1
        locals_blob = b"".join(pool.verification_type(descriptor) for descriptor in method.frame_locals)
        for offset in method.frames:
            delta = offset - previous - 1
            if previous < 0:
                entries.extend(bytes((255,)) + _u2(delta) + _u2(len(method.frame_locals)) + locals_blob + _u2(0))
            elif delta < 64:
                entries.append(delta)  # same_frame: every frame equals the first
            else:
                entries.extend(bytes((251,)) + _u2(delta))  # same_frame_extended
            previous = offset
        body = _u2(len(method.frames)) + bytes(entries)
        attributes.append(_u2(pool.utf8("StackMapTable")) + _u4(len(body)) + body)
    if method.lines:
        body = _u2(len(method.lines)) + b"".join(_u2(pc) + _u2(min(line, 0xFFFF)) for pc, line in method.lines)
        attributes.append(_u2(pool.utf8("LineNumberTable")) + _u4(len(body)) + body)
    code_body = (
        _u2(method.max_stack) + _u2(method.max_locals) + _u4(len(method.code)) + method.code
        + _u2(0) + _u2(len(attributes)) + b"".join(attributes)
    )
    code_attribute = _u2(pool.utf8("Code")) + _u4(len(code_body)) + code_body
    return _u2(0x0009) + _u2(pool.utf8(method.name)) + _u2(pool.utf8(method.descriptor)) + _u2(1) + code_attribute


def _class_file(class_name: str, methods: Sequence[_Method], pool: _Pool) -> tuple[bytes, dict[str, int]]:
    """Return the class bytes and the file offset of each method's code array."""
    this_index = pool.klass(class_name)
    super_index = pool.klass("java/lang/Object")
    source_name = pool.utf8("SourceFile")
    source_value = pool.utf8("XAX")
    method_blobs = [_serialize_method(method, pool) for method in methods]  # finalizes the pool
    head = b"\xca\xfe\xba\xbe" + _u2(0) + _u2(CLASS_MAJOR_VERSION) + _u2(pool.count) + bytes(pool.data)
    head += _u2(0x0031) + _u2(this_index) + _u2(super_index) + _u2(0) + _u2(0) + _u2(len(method_blobs))
    code_offsets: dict[str, int] = {}
    cursor = len(head)
    for method, blob in zip(methods, method_blobs):
        # method_info: access, name, descriptor, attribute count (8), then the Code
        # attribute header (6) and max_stack/max_locals/code_length (8).
        code_offsets[method.name] = cursor + 8 + 6 + 8
        cursor += len(blob)
    tail = _u2(1) + _u2(source_name) + _u4(2) + _u2(source_value)
    return head + b"".join(method_blobs) + tail, code_offsets


def _jar(class_name: str, class_bytes: bytes, main_class: bool) -> tuple[bytes, int]:
    """Deterministic stored JAR; returns the bytes and the class data offset."""
    manifest = b"Manifest-Version: 1.0\r\nCreated-By: xax-jvm-classfile-v1\r\n"
    if main_class:
        manifest += b"Main-Class: " + class_name.replace("/", ".").encode("ascii") + b"\r\n"
    manifest += b"\r\n"
    out = io.BytesIO()
    entry_name = class_name + ".class"
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, data in (("META-INF/MANIFEST.MF", manifest), (entry_name, class_bytes)):
            info = zipfile.ZipInfo(name, _ZIP_DATE)
            info.external_attr = 0o100644 << 16
            info.create_system = 0
            archive.writestr(info, data)
    jar = out.getvalue()
    with zipfile.ZipFile(io.BytesIO(jar)) as archive:
        header_offset = archive.getinfo(entry_name).header_offset
    name_length, extra_length = struct.unpack_from("<HH", jar, header_offset + 26)
    return jar, header_offset + 30 + name_length + extra_length


def validate_process_entry(entry: SemanticObject, resolve) -> None:
    """The JAR entry takes and returns only proof values (WASI ``_start`` shape)."""
    parameters, returns = _signature(entry, resolve)
    if parameters or returns:
        fail("XAX.JVM.ENTRY", entry.cid.hex(), "JVM-PROCESS-ENTRY-CONTRACT", "fn(proof...) -> (proof...)", [list(parameters), list(returns)])


def compile_jvm_bound_target(
    reader: StoreReader, function_cid: bytes, target_object: SemanticObject, *, process_entry: bool = False
) -> JvmImage:
    verify_store(reader)
    resolve = store_resolver(reader)
    entry = resolve(function_cid)
    if entry.kind != Kind.FUNCTION:
        fail("XAX.JVM.FUNCTION", function_cid.hex(), "JVM-ENTRY-FUNCTION", Kind.FUNCTION.name, entry.kind.name)
    target = decode_native_target(target_object)
    if target.architecture != JVM_ARCHITECTURE:
        fail("XAX.JVM.TARGET", target_object.cid.hex(), "JVM-TARGET-PROFILE", JVM_ARCHITECTURE, target.architecture)
    if process_entry:
        validate_process_entry(entry, resolve)
    functions = _function_closure(entry, resolve, target.supported_operations, target.supported_terminators)
    class_name = "xax/P" + function_cid.hex()[:16]
    names: dict[bytes, tuple[str, str]] = {}
    for index, function in enumerate(functions):
        name = "entry" if function.cid == entry.cid else f"f{index}"
        names[function.cid] = (name, _method_descriptor(*_signature(function, resolve)))
    pool = _Pool()
    methods = [_compile_method(function, names[function.cid][0], resolve, pool, class_name, names) for function in functions]
    if process_entry:
        methods.append(_main_method(pool, class_name, "entry"))
    class_bytes, code_offsets = _class_file(class_name, methods, pool)
    jar, class_offset = _jar(class_name, class_bytes, process_entry)
    entry_offset = class_offset + code_offsets["entry"]
    ranges: list[ArtifactSemanticRange] = []
    line_map: list[tuple[str, int, bytes, int, int]] = []
    for method in methods:
        if method.function_cid is None:
            continue
        base = class_offset + code_offsets[method.name]
        ranges.append(ArtifactSemanticRange(method.function_cid, None, None, base, base + len(method.code)))
        for block, node, line, start, end in method.node_ranges:
            line_map.append((method.name, line, method.function_cid, block, node))
            if end > start:
                ranges.append(ArtifactSemanticRange(method.function_cid, block, node, base + start, base + end))
    _graph, parameters, returns = _decode_function_interface(entry, resolve)
    kinds = lambda cids: tuple(t for t in (_jvm_type(resolve, cid, entry.cid.hex()) for cid in cids) if t is not None)
    return JvmImage(
        jar, class_bytes, class_name, tuple((cid, *names[cid]) for cid in sorted(names)), "entry", target_object.cid,
        tuple(ranges), tuple(line_map), kinds(parameters), kinds(returns), process_entry, entry_offset,
    )


def compile_jvm(reader: StoreReader, function_cid: bytes, target_cid: bytes, *, process_entry: bool = False) -> JvmImage:
    resolve = store_resolver(reader)
    return compile_jvm_bound_target(reader, function_cid, resolve(target_cid), process_entry=process_entry)


# ---------------------------------------------------------------- test harness

# Test tooling, not part of any artifact: loads the JAR, calls a static method
# reflectively once per argument line, and prints raw result bits.
_HARNESS_SOURCE = r"""
import java.lang.reflect.*;
import java.net.*;
import java.io.*;
public final class XaxJvmHarness {
  public static void main(String[] a) throws Exception {
    URLClassLoader loader = new URLClassLoader(new URL[]{new File(a[0]).toURI().toURL()});
    Class<?> c = Class.forName(a[1], true, loader);
    Method m = null;
    for (Method x : c.getDeclaredMethods()) if (x.getName().equals(a[2])) m = x;
    Class<?>[] p = m.getParameterTypes();
    BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
    for (String line; (line = in.readLine()) != null; ) {
      String[] f = line.isEmpty() ? new String[0] : line.split(" ");
      Object[] v = new Object[p.length];
      for (int i = 0; i < p.length; i++) {
        long bits = Long.parseUnsignedLong(f[i]);
        if (p[i] == int.class) v[i] = (int) bits;
        else if (p[i] == long.class) v[i] = bits;
        else if (p[i] == float.class) v[i] = Float.intBitsToFloat((int) bits);
        else v[i] = Double.longBitsToDouble(bits);
      }
      try {
        Object r = m.invoke(null, v);
        if (r == null) System.out.println("void");
        else if (r instanceof Integer) System.out.println(Integer.toUnsignedString((Integer) r));
        else if (r instanceof Long) System.out.println(Long.toUnsignedString((Long) r));
        else if (r instanceof Float) System.out.println(Integer.toUnsignedString(Float.floatToRawIntBits((Float) r)));
        else System.out.println(Long.toUnsignedString(Double.doubleToRawLongBits((Double) r)));
      } catch (InvocationTargetException e) {
        System.out.println("trap " + e.getCause().getClass().getName());
      }
    }
  }
}
"""
_harness_directory: list[str] = []


def _harness() -> str:
    if not _harness_directory:
        javac = shutil.which("javac")
        if not javac:
            fail("XAX.JVM.HOST", "host", "JVM-HOST-JAVAC", "javac for the test harness", "missing")
        directory = tempfile.mkdtemp(prefix="xax-jvm-harness-")
        source = os.path.join(directory, "XaxJvmHarness.java")
        with open(source, "w", encoding="ascii") as handle:
            handle.write(_HARNESS_SOURCE)
        subprocess.run([javac, "-d", directory, source], check=True, capture_output=True)
        _harness_directory.append(directory)
    return _harness_directory[0]


def _encode(value: int | float, kind: str) -> str:
    if kind == "F":
        return str(struct.unpack("<I", struct.pack("<f", value))[0])
    if kind == "D":
        return str(struct.unpack("<Q", struct.pack("<d", value))[0])
    return str(int(value))


def _decode(text: str, kind: str, width: int) -> int | float | str:
    if text.startswith("trap ") or text == "void":
        return text
    bits = int(text)
    if kind == "F":
        return struct.unpack("<f", struct.pack("<I", bits))[0]
    if kind == "D":
        return struct.unpack("<d", struct.pack("<Q", bits))[0]
    return bits & ((1 << width) - 1)


def run_jvm_calls(
    image: JvmImage, calls: Sequence[Sequence[int | float]], *, method: str | None = None, result_width: int = 64
) -> tuple[int | float | str, ...]:
    """Call one static method once per argument tuple in a single JVM; returns decoded results.

    A trap is reported as ``"trap <exception class>"``.  ``result_width``
    masks integer results to the XAX width.
    """
    java = shutil.which("java")
    if not java:
        fail("XAX.JVM.HOST", "host", "JVM-HOST-JAVA", "java executable", "missing")
    harness = _harness()
    with tempfile.TemporaryDirectory(prefix="xax-jvm-") as directory:
        jar = os.path.join(directory, "program.jar")
        with open(jar, "wb") as handle:
            handle.write(image.jar)
        kinds = image.parameter_kinds
        lines = "".join(" ".join(_encode(value, kind) for value, kind in zip(call, kinds)) + "\n" for call in calls)
        completed = subprocess.run(
            [java, "-Xshare:auto", "-cp", harness, "XaxJvmHarness", jar, image.class_name.replace("/", "."), method or image.entry_method],
            input=lines, capture_output=True, text=True, check=False,
        )
    if completed.returncode:
        raise RuntimeError(completed.stderr.strip() or f"java exited {completed.returncode}")
    result_kind = image.return_kinds[0] if image.return_kinds else "V"
    return tuple(_decode(line, result_kind, result_width) for line in completed.stdout.splitlines())


def run_jvm_jar(image: JvmImage, *, timeout: float = 120.0, java: str | None = None) -> subprocess.CompletedProcess:
    """Run the JAR with ``java -jar`` (the platform launcher); returns the completed process."""
    java = java or shutil.which("java")
    if not java:
        fail("XAX.JVM.HOST", "host", "JVM-HOST-JAVA", "java executable", "missing")
    with tempfile.TemporaryDirectory(prefix="xax-jvm-") as directory:
        jar = os.path.join(directory, "program.jar")
        with open(jar, "wb") as handle:
            handle.write(image.jar)
        # The host's JAVA_TOOL_OPTIONS banner would otherwise appear on stderr.
        env = {key: value for key, value in os.environ.items() if key != "JAVA_TOOL_OPTIONS"}
        return subprocess.run([java, "-jar", jar], capture_output=True, timeout=timeout, check=False, env=env)
