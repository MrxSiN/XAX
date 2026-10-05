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
  node results are method locals; edges copy arguments and ``goto``.  Values
  never live together share a local of one fixed type (ADR-157), so every
  branch target carries the same full StackMapTable frame; a local that holds
  no value across a branch target is Top in it and is never initialized;
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
    ForeignAllocatorContract,
    ForeignDeallocatorContract,
    JVM_CLASSFILE_MEMORY_IDENTITY,
    heap_owner_type,
    heap_view_type,
    memory_effect_type,
    pointer_extent_from_graph,
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
    borrowed_view_returns,
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


# The generated memory package (ADR-156).  Declarations name this reserved class;
# the backend implements its members as static methods of the generated class
# itself (compiler-generated adapters, UR-001), never as a library on the class path.
MEMORY_CLASS = b"xax/jvm/Memory"
_MEMORY_MEMBERS = {
    "alloc(J)I": "xax$alloc", "free(I)J": "xax$free", "read(IIJ)J": "xax$read", "write(IIJ)J": "xax$write",
}
# Offsets below this are never storage, so 0 is never a valid block address.
_HEAP_START, _INITIAL_MEMORY = 16, 1 << 16


@dataclass(frozen=True)
class JvmMemoryApi:
    """Linear memory, standard streams, and exit for ``jvm-classfile-memory-v1``.

    The surface mirrors ``xax_linux.LinuxApi`` (``read``/``write`` on
    descriptors 0, 1, 2 returning a count or ``-errno``; zero-filled anonymous
    blocks; an explicit exit), so the same XAX program builds for both.
    ``mmap_anonymous`` returns a fresh, zero-filled, 16-byte-aligned block of
    the one ``byte[]`` memory, or 0 when the request exceeds 2^31 - 1 bytes.
    Blocks are never reused (``munmap_view`` ends the view; the bytes stay
    until the process exits).
    """

    b8: SemanticObject
    b32: SemanticObject
    b64: SemanticObject
    bytes_rw: SemanticObject
    bytes_read: SemanticObject
    memory_effect: SemanticObject
    filesystem_effect: SemanticObject
    process_effect: SemanticObject
    heap_owner: SemanticObject
    read: SemanticObject
    write: SemanticObject
    mmap_anonymous: SemanticObject
    exit_group: SemanticObject

    def munmap_view(self, view_pointer: SemanticObject, extent: int) -> SemanticObject:
        return foreign_function_symbol(
            MEMORY_CLASS, b"free(I)J", (view_pointer, heap_view_type(extent), self.memory_effect), (self.b64, self.memory_effect),
            abi=JVM_INVOKESTATIC_ABI, deallocator=ForeignDeallocatorContract(0, 1),
        )

    @property
    def types(self) -> tuple[SemanticObject, ...]:
        return (
            self.b8, self.b32, self.b64, self.bytes_rw, self.bytes_read,
            self.memory_effect, self.filesystem_effect, self.process_effect, self.heap_owner,
        )

    @property
    def symbols(self) -> tuple[SemanticObject, ...]:
        return (self.read, self.write, self.mmap_anonymous, self.exit_group)


def jvm_memory_api() -> JvmMemoryApi:
    b8, b32, b64 = bits_type(8), bits_type(32), bits_type(64)
    bytes_rw = pointer_type(b8, Permission.READ_WRITE, 1, space=2)
    bytes_read = pointer_type(b8, Permission.READ, 1, space=2)
    memory = memory_effect_type()
    filesystem = effect_type(EffectDomain.FILESYSTEM, 0)
    process = effect_type(EffectDomain.SYSCALL, 0)
    heap = heap_owner_type()
    return JvmMemoryApi(
        b8, b32, b64, bytes_rw, bytes_read, memory, filesystem, process, heap,
        jvm_static(MEMORY_CLASS, b"read(IIJ)J", (b32, bytes_rw, b64, filesystem, memory), (b64, filesystem, memory)),
        jvm_static(MEMORY_CLASS, b"write(IIJ)J", (b32, bytes_read, b64, filesystem, memory), (b64, filesystem, memory)),
        foreign_function_symbol(
            MEMORY_CLASS, b"alloc(J)I", (b64, memory), (bytes_rw, heap, memory),
            abi=JVM_INVOKESTATIC_ABI, allocator=ForeignAllocatorContract((0,), 0, 1, _HEAP_START, True),
        ),
        jvm_static(b"java/lang/System", b"exit(I)V", (b32, process), (process,)),
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
        else:
            return "I"  # an offset into the linear memory (ADR-156)
    fail("XAX.JVM.VALUE", where, "JVM-VALUE-REPRESENTABLE", "bits<=64, f32, f64, jvm-ref, or memory pointer", cid.hex())


def _signed32(value: int) -> int:
    value &= 0xFFFFFFFF
    return value - (1 << 32) if value >> 31 else value


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
    if resolve(cid).body[:1] == b"\x02" and xax == "I":
        return jvm == "I"  # a memory pointer is an int offset (ADR-156)
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
        tag = {"T": 0, "I": 1, "F": 2, "D": 3, "J": 4}.get(descriptor)
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
    access: int = 0x0009  # public static
    bare_frame: int | None = None  # a frame with no locals (the trap: it reads none)


_NO_FALLTHROUGH = frozenset({0xA7, 0xC8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0, 0xB1, 0xBF})  # goto, ret, switches, returns, athrow


class _Code:
    def __init__(self, where: str) -> None:
        self.where = where
        self.buf = bytearray()
        self.labels: dict[object, int] = {}
        self.fixups: list[tuple[int, object]] = []
        self.targets: set[object] = set()
        self.ended = False  # the last instruction never falls through

    def op(self, *values: int) -> None:
        self.buf.extend(values)
        self.ended = values[0] in _NO_FALLTHROUGH

    def raw(self, blob: bytes) -> None:
        self.buf.extend(blob)

    def branch(self, opcode: int, label: object) -> None:
        self.fixups.append((len(self.buf), label))
        self.targets.add(label)
        self.buf.extend((opcode, 0, 0))
        self.ended = opcode == 0xA7

    def mark(self, label: object) -> None:
        # A frame only where the verifier needs one (ADR-157): a branch target, or code
        # after an instruction that never falls through.
        self.labels[label] = len(self.buf)
        if self.ended:
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


def _bits_of(mask: int):
    while mask:
        low = mask & -mask
        yield low
        mask ^= low


_SHORT_LOCAL = {0x15: 0x1A, 0x16: 0x1E, 0x17: 0x22, 0x18: 0x26, 0x19: 0x2A, 0x36: 0x3B, 0x37: 0x3F, 0x38: 0x43, 0x39: 0x47, 0x3A: 0x4B}
class _HookedCode(_Code):
    """``_Code`` that runs ``before`` ahead of every emission (the deferred-store flush, ADR-157)."""

    def __init__(self, where: str) -> None:
        super().__init__(where)
        self.before: Callable[[], None] = lambda: None

    def op(self, *values: int) -> None:
        self.before(); super().op(*values)

    def raw(self, blob: bytes) -> None:
        self.before(); super().raw(blob)

    def branch(self, opcode: int, label: object) -> None:
        self.before(); super().branch(opcode, label)

    def mark(self, label: object) -> None:
        self.before(); super().mark(label)


# Operations whose bytecode can raise a JVM exception or be a caller frame.
_MAY_RAISE = frozenset({
    Operation.CALL_DIRECT, Operation.CALL_FOREIGN, Operation.UDIV, Operation.UREM,
    Operation.LOAD_BITS_LE, Operation.STORE_BITS_LE, Operation.CHECKED_LOAD_BITS_LE, Operation.CHECKED_STORE_BITS_LE,
})
# Lowerings that place their own branch targets inside a node.
_INTERNAL_LABELS = frozenset({
    Operation.UINT_TO_FLOAT, Operation.SINT_TO_FLOAT, Operation.FLOAT_TO_UINT_TRUNC, Operation.FLOAT_TO_SINT_TRUNC,
})
# Pure integer operations a single-use value may be evaluated from at its reader.
_TREE_OPERATIONS = frozenset({
    Operation.ADD_WRAP, Operation.SUB_WRAP, Operation.MUL_WRAP, Operation.BIT_AND, Operation.BIT_OR, Operation.BIT_XOR,
    Operation.ROTATE_RIGHT, Operation.INT_TRUNCATE, Operation.INT_ZERO_EXTEND, Operation.INT_COMPARE,
    Operation.ADDRESS_OFFSET, Operation.POINTER_ADDRESS,
})
# Pure nodes: never lowered when nothing reads their results (ADR-157).
_DEAD_IF_UNREAD = frozenset({*_TREE_OPERATIONS, Operation.CONSTANT, Operation.POINTER_CAST})
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
# Pure integer operations folded when every operand is a constant (results are masked to width).
_FOLDABLE = {
    Operation.ADD_WRAP: lambda a, b: a + b, Operation.SUB_WRAP: lambda a, b: a - b, Operation.MUL_WRAP: lambda a, b: a * b,
    Operation.BIT_AND: lambda a, b: a & b, Operation.BIT_OR: lambda a, b: a | b, Operation.BIT_XOR: lambda a, b: a ^ b,
    Operation.INT_ZERO_EXTEND: lambda a: a, Operation.INT_TRUNCATE: lambda a: a, Operation.ROTATE_RIGHT: None,
}


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
    elided = borrowed_view_returns(parameters, returns, resolve)  # views given back are the lent ones (ADR-101)
    machine_parameters = tuple(t for t in (_jvm_type(resolve, cid, where) for cid in parameters) if t is not None)
    machine_returns = tuple(t for t in (_jvm_type(resolve, cid, where) for index, cid in enumerate(returns) if index not in elided) if t is not None)
    if len(machine_returns) > 1:
        fail("XAX.JVM.ABI", where, "JVM-SINGLE-RESULT", "at most one machine result", list(machine_returns))
    return machine_parameters, machine_returns


def _internal_order(items: Sequence, descriptors: Sequence[str] | None = None) -> list:
    """Parameters of a method only this class calls, one-slot types first (ADR-157): more
    of the hot ones land in locals 0-3, which have one-byte loads and stores."""
    descriptors = items if descriptors is None else descriptors
    return [items[index] for index in sorted(range(len(items)), key=lambda index: (_slots(descriptors[index]) == 2, index))]


def _method_descriptor(parameters: Sequence[str], returns: Sequence[str]) -> str:
    return "(" + "".join(parameters) + ")" + (returns[0] if returns else "V")


def _compile_method(
    function: SemanticObject,
    name: str,
    resolve: Callable[[bytes], SemanticObject],
    pool: _Pool,
    class_name: str,
    methods: dict[bytes, tuple[str, str]],
    needs: set[str] | None = None,
) -> _Method:
    """Lower one function.  ``needs`` collects the generated memory members it uses (ADR-156).

    Two passes (ADR-157): the first counts how often the lowering reads each
    value; the second keeps a value on the operand stack instead of storing and
    reloading it when its single read comes right after its definition.
    """
    reads: dict[ValueRef, int] = {}
    # The counting pass lowers into a scratch pool, so nothing only it used reaches the class.
    _compile_method_pass(function, name, resolve, _Pool(), class_name, methods, set(), reads, None, None)
    single = frozenset(ref for ref, count in reads.items() if count == 1)
    kept: frozenset = frozenset()
    while True:
        try:
            return _compile_method_pass(function, name, resolve, pool, class_name, methods, needs, {}, single, kept)
        except _KeepParameters as retry:
            kept |= retry.parameters  # their slots must hold them until a zero store


class _KeepParameters(Exception):
    """Reusing these dead parameters' slots would need a zero store before they are read."""

    def __init__(self, parameters: frozenset) -> None:
        super().__init__()
        self.parameters = parameters


def _compile_method_pass(
    function: SemanticObject,
    name: str,
    resolve: Callable[[bytes], SemanticObject],
    pool: _Pool,
    class_name: str,
    methods: dict[bytes, tuple[str, str]],
    needs: set[str] | None,
    reads: dict[ValueRef, int],
    single_read: frozenset | None,
    kept_parameters: frozenset | None = frozenset(),
) -> _Method:
    needs = needs if needs is not None else set()
    graph_object, parameter_types, return_types = _decode_function_interface(function, resolve)
    graph = parse_function_graph(function, resolve)
    where = graph_object.cid.hex()
    parameters, returns = _signature(function, resolve)
    if name != "entry":
        parameters = _internal_order(parameters)
    code = _HookedCode(where)
    pending: list = [None]  # a value left on the operand stack instead of stored

    stored: list = [None]  # a value whose store waits: if it is read next, ``dup`` first

    def flush() -> None:
        for holder in (pending, stored):
            ref = holder[0]
            if ref is not None:
                holder[0] = None
                slot, descriptor = slot_of[ref]
                local(_STORE, descriptor, slot)

    code.before = flush

    def value_type(cid: bytes) -> str | None:
        return _jvm_type(resolve, cid, where)

    def edge_moves(target: int, arguments: Sequence[ValueRef]) -> list[tuple[int, ValueRef]]:
        return [
            (index, argument) for index, argument in enumerate(arguments)
            if value_type(graph.blocks[target].parameters[index]) is not None and carried(target, index)
        ]

    # Locals (ADR-157): every machine value gets a slot of one fixed JVM type for
    # the whole method, so every frame lists the same typed locals.  Values that
    # are never live at the same time share a slot (liveness over the CFG, then
    # greedy coloring per type); a block parameter prefers the slot of an argument
    # passed to it, which turns that edge copy into nothing.  Integer constants
    # have no slot: each use rematerializes them.
    # Integer constants by value reference, for rematerialization and strength
    # reduction.  Pure integer nodes over constants fold to constants (ADR-157).
    constants: dict[ValueRef, int] = {}
    for block_index, block in enumerate(graph.blocks):
        for node_index, node in enumerate(block.nodes):
            if node.operation == Operation.CONSTANT and value_type(node.results[0]) in ("I", "J"):
                constants[ValueRef.node_result(block_index, node_index)] = int(_decode_constant(node.entity, resolve)[1])
    folded: set[ValueRef] = set()
    changed = True
    while changed:
        changed = False
        for block_index, block in enumerate(graph.blocks):
            for node_index, node in enumerate(block.nodes):
                ref = ValueRef.node_result(block_index, node_index)
                if ref in constants or node.operation not in _FOLDABLE or len(node.results) != 1 or value_type(node.results[0]) not in ("I", "J"):
                    continue
                if not all(operand in constants for operand in node.operands):
                    continue
                values = [constants[operand] for operand in node.operands]
                width = _width(resolve, node.results[0])
                if node.operation == Operation.ROTATE_RIGHT:
                    amount = node.attributes[0] % width if width else 0
                    value = (values[0] >> amount) | (values[0] << (width - amount))
                else:
                    value = _FOLDABLE[node.operation](*values)
                constants[ref] = value & ((1 << width) - 1)
                folded.add(ref)
                changed = True
    # One name per value (ADR-157).  A block entered by exactly one edge has
    # parameters that are that edge's arguments, so they alias them instead of
    # taking locals and copies.  A load from the same place as a load whose memory
    # it consumes, with nothing stored in between, is that load's value: it emits
    # nothing (it cannot trap: the first one did not).
    alias: dict[ValueRef, ValueRef] = {}
    incoming: dict[int, list[tuple[int, Sequence[ValueRef]]]] = {index: [] for index in range(len(graph.blocks))}
    for block_index, block in enumerate(graph.blocks):
        for target, arguments in block.terminator.edges:
            incoming[target].append((block_index, arguments))
    reachable, frontier = {graph.entry}, [graph.entry]
    while frontier:
        for target, _arguments in graph.blocks[frontier.pop()].terminator.edges:
            if target not in reachable:
                reachable.add(target)
                frontier.append(target)
    for block_index in reachable:
        if block_index != graph.entry and len(incoming[block_index]) == 1:
            for index, argument in enumerate(incoming[block_index][0][1]):
                alias[ValueRef.parameter(block_index, index)] = argument

    def canon(ref: ValueRef) -> ValueRef:
        while ref in alias:
            ref = alias[ref]
        return ref

    def same_index(left: ValueRef, right: ValueRef) -> bool:
        left, right = canon(left), canon(right)
        return left == right or (left in constants and right in constants and constants[left] == constants[right])

    eliminated: set[tuple[int, int]] = set()
    changed = True
    while changed:
        changed = False
        for block_index in reachable:
            for node_index, node in enumerate(graph.blocks[block_index].nodes):
                if node.operation not in (Operation.LOAD_BITS_LE, Operation.CHECKED_LOAD_BITS_LE) or (block_index, node_index) in eliminated:
                    continue
                memory = canon(node.operands[-1])
                if memory.tag != 1 or memory.result != 1:
                    continue
                earlier = graph.blocks[memory.block].nodes[memory.index]
                if earlier.operation != node.operation or earlier.attributes != node.attributes or tuple(earlier.results) != tuple(node.results):
                    continue
                if not all(same_index(a, b) for a, b in zip(earlier.operands[:-1], node.operands[:-1])):
                    continue
                alias[ValueRef.node_result(block_index, node_index, 0)] = ValueRef.node_result(memory.block, memory.index, 0)
                alias[ValueRef.node_result(block_index, node_index, 1)] = node.operands[-1]
                eliminated.add((block_index, node_index))
                changed = True

    # Dead block parameters (ADR-157): structured code carries every variable along
    # every edge; a parameter nothing reads, directly or by passing it on to a
    # parameter that is read, gets no local, and its edges copy nothing.
    needed: set[ValueRef] = set()
    for block_index, block in enumerate(graph.blocks):
        for node_index, node in enumerate(block.nodes):
            if (block_index, node_index) not in eliminated and node.operation not in _DEAD_IF_UNREAD:
                needed.update(canon(operand) for operand in node.operands)
        if block.terminator.kind == TerminatorKind.RETURN:
            # Only the machine result is returned: views given back are elided (ADR-101).
            returned_elided = borrowed_view_returns(parameter_types, return_types, resolve)
            needed.update(canon(value) for index, (value, cid) in enumerate(zip(block.terminator.values, return_types)) if value_type(cid) is not None and index not in returned_elided)
        else:
            needed.update(canon(value) for value in block.terminator.values)
    changed = True
    while changed:
        changed = False
        for block in graph.blocks:
            for target, arguments in block.terminator.edges:
                for index, argument in enumerate(arguments):
                    parameter = ValueRef.parameter(target, index)
                    if parameter in needed and parameter not in alias and canon(argument) not in needed:
                        needed.add(canon(argument))
                        changed = True
        for block_index, block in enumerate(graph.blocks):
            for node_index, node in enumerate(block.nodes):
                # A pure node is live when one of its results is read.
                if node.operation in _DEAD_IF_UNREAD and (block_index, node_index) not in eliminated:
                    if any(ValueRef.node_result(block_index, node_index, index) in needed for index in range(len(node.results))):
                        for operand in map(canon, node.operands):
                            if operand not in needed:
                                needed.add(operand)
                                changed = True
    for block_index, block in enumerate(graph.blocks):
        for node_index, node in enumerate(block.nodes):
            if node.operation in _DEAD_IF_UNREAD and not any(ValueRef.node_result(block_index, node_index, index) in needed for index in range(len(node.results))):
                eliminated.add((block_index, node_index))  # dead: never lowered

    def carried(target: int, index: int) -> bool:
        """An edge argument the target's parameter takes: live, and not an alias of it."""
        parameter = ValueRef.parameter(target, index)
        return parameter not in alias and (parameter in needed or target == graph.entry)

    def edge_reads(block) -> list[ValueRef]:
        return [canon(argument) for target, arguments in block.terminator.edges for index, argument in enumerate(arguments) if carried(target, index)]

    constant_refs: set[ValueRef] = set(constants)
    descriptor_of: dict[ValueRef, str] = {}
    for block_index, block in enumerate(graph.blocks):
        for index, cid in enumerate(block.parameters):
            descriptor = value_type(cid)
            if descriptor is not None and (block_index == graph.entry or carried(block_index, index)):
                descriptor_of[ValueRef.parameter(block_index, index)] = descriptor
        for node_index, node in enumerate(block.nodes):
            for result_index, cid in enumerate(node.results):
                descriptor = value_type(cid)
                if descriptor is not None and ValueRef.node_result(block_index, node_index, result_index) not in alias and (block_index, node_index) not in eliminated:
                    descriptor_of[ValueRef.node_result(block_index, node_index, result_index)] = descriptor
    # Known widths: an upper bound on the significant bits of integer values whose
    # producer bounds them (byte loads, zero extensions, truncations), so a
    # truncation that cannot change its operand is a copy.
    known_width: dict[ValueRef, int] = {}
    for _ in range(2):
        for block_index, block in enumerate(graph.blocks):
            for node_index, node in enumerate(block.nodes):
                ref = ValueRef.node_result(block_index, node_index)
                if node.operation in (Operation.LOAD_BITS_LE, Operation.CHECKED_LOAD_BITS_LE) and value_type(node.results[0]) in ("I", "J"):
                    known_width[ref] = min(8 * node.attributes[0], _width(resolve, node.results[0]))
                elif node.operation == Operation.INT_ZERO_EXTEND:
                    known_width[ref] = known_width.get(node.operands[0], _width(resolve, node.operand_types[0]))
                elif node.operation == Operation.INT_TRUNCATE:
                    known_width[ref] = min(_width(resolve, node.results[0]), known_width.get(node.operands[0], 64))

    uses: dict[ValueRef, int] = {}
    for block_index, block in enumerate(graph.blocks):
        for node_index, node in enumerate(block.nodes):
            if (block_index, node_index) not in eliminated:
                for operand in node.operands:
                    uses[canon(operand)] = uses.get(canon(operand), 0) + 1
        for value in (*block.terminator.values, *edge_reads(block)):
            uses[canon(value)] = uses.get(canon(value), 0) + 1

    def copy_like(node) -> bool:
        """A node whose result is its operand's value in the same representation."""
        if node.operation in (Operation.POINTER_CAST, Operation.HEAP_VIEW):
            pass  # a heap view's pointer is its raw block (the null check reads only the operand)
        elif node.operation not in (Operation.INT_ZERO_EXTEND, Operation.INT_TRUNCATE) or value_type(node.operand_types[0]) != value_type(node.results[0]):
            return False
        elif uses.get(node.operands[0]) == 1:
            return False  # its operand's only reader: an expression on the stack, not a second name
        elif node.operation == Operation.INT_TRUNCATE and known_width.get(node.operands[0], 64) > _width(resolve, node.results[0]):
            return False
        return node.operands[0] not in constant_refs and value_type(node.results[0]) is not None

    def aliases(block_index: int, node_index: int, node) -> dict[ValueRef, ValueRef]:
        """Results that are an operand's value: a copy, or a view a call gives back (ADR-101)."""
        if copy_like(node):
            return {ValueRef.node_result(block_index, node_index): node.operands[0]}
        if node.operation == Operation.CALL_DIRECT and not _is_erased_proof_function(node.entity, resolve):
            elided = borrowed_view_returns(node.operand_types, node.results, resolve)
            return {ValueRef.node_result(block_index, node_index, result): node.operands[parameter] for result, parameter in elided.items() if value_type(node.results[result]) is not None}
        return {}

    copy_of: dict[ValueRef, ValueRef] = {}
    for block_index, block in enumerate(graph.blocks):
        for node_index, node in enumerate(block.nodes):
            if copy_like(node) and node.operation != Operation.HEAP_VIEW:
                copy_of[ValueRef.node_result(block_index, node_index)] = node.operands[0]

    # Only a value nothing reads through its slot implicitly may stay on the stack:
    # edge arguments and copy operands can share a slot with the value they feed.
    implicit: set[ValueRef] = set()
    for block in graph.blocks:
        implicit.update(edge_reads(block))
    for block_index, block in enumerate(graph.blocks):
        for node_index, node in enumerate(block.nodes):
            implicit.update(canon(value) for value in aliases(block_index, node_index, node).values())

    # A compare whose only use is its own block's conditional branch fuses
    # into that branch (``lcmp``/``fcmp`` + ``if<cond>``), as javac emits it.
    users: dict[ValueRef, list] = {}
    for block_index, block in enumerate(graph.blocks):
        for node_index, node in enumerate(block.nodes):
            if (block_index, node_index) not in eliminated:
                for operand in node.operands:
                    users.setdefault(canon(operand), []).append(node)

    def sole_user(ref: ValueRef):
        """The one node that reads ``ref``, when nothing else (a terminator included) does."""
        return users[ref][0] if uses.get(ref) == 1 and len(users.get(ref, ())) == 1 else None

    def definition(ref: ValueRef):
        return graph.blocks[ref.block].nodes[ref.index] if ref.tag == 1 else None

    fused: set[ValueRef] = set()
    for block_index, block in enumerate(graph.blocks):
        if block.terminator.kind == TerminatorKind.CONDITIONAL_BRANCH:
            condition = block.terminator.values[0]
            if condition.tag == 1 and condition.block == block_index and uses.get(condition) == 1:
                if block.nodes[condition.index].operation in (Operation.INT_COMPARE, Operation.FLOAT_COMPARE):
                    fused.add(condition)

    # Expression trees (ADR-157): a pure integer node read exactly once, by a later
    # node or the terminator of its own block, has no local.  It is emitted where
    # it is read, as javac evaluates an expression on the operand stack, and its
    # operands are live up to that point.
    inlined: set[ValueRef] = set()
    if single_read is not None:
        site: dict[ValueRef, int] = {}  # value -> block of its one reader
        for block_index, block in enumerate(graph.blocks):
            for node in block.nodes:
                if not copy_like(node):
                    for operand in node.operands:
                        site[operand] = block_index
            for value in block.terminator.values:
                site[value] = block_index
        for block_index, block in enumerate(graph.blocks):
            for node_index, node in enumerate(block.nodes):
                ref = ValueRef.node_result(block_index, node_index)
                if (
                    node.operation in _TREE_OPERATIONS and len(node.results) == 1 and value_type(node.results[0]) in ("I", "J")
                    and ref in single_read and ref not in implicit and ref not in constants and uses.get(ref) == 1
                    and site.get(ref) == block_index and not copy_like(node)
                ):
                    inlined.add(ref)
    evaluated_late = inlined | fused  # no local: lowered where they are read

    def node_of(ref: ValueRef):
        ref = canon(ref)
        return graph.blocks[ref.block].nodes[ref.index] if ref.tag == 1 else None

    def repacked(node) -> ValueRef | None:
        """``s`` when ``node`` is ``zext(trunc(s)) | rotr(zext(trunc(rotr(s, 32))), 32)``: the u64
        rebuilt from its own two 32-bit halves is ``s`` itself (ADR-157)."""
        if node.operation != Operation.BIT_OR or _width(resolve, node.results[0]) != 64:
            return None
        for low_ref, high_ref in (node.operands, node.operands[::-1]):
            low_zext, high_rotate = node_of(low_ref), node_of(high_ref)
            if low_zext is None or high_rotate is None or low_zext.operation != Operation.INT_ZERO_EXTEND:
                continue
            if high_rotate.operation != Operation.ROTATE_RIGHT or high_rotate.attributes[0] != 32:
                continue
            high_zext = node_of(high_rotate.operands[0])
            low_trunc = node_of(low_zext.operands[0])
            if high_zext is None or low_trunc is None or high_zext.operation != Operation.INT_ZERO_EXTEND:
                continue
            high_trunc = node_of(high_zext.operands[0])
            if high_trunc is None or low_trunc.operation != Operation.INT_TRUNCATE or high_trunc.operation != Operation.INT_TRUNCATE:
                continue
            if _width(resolve, low_trunc.results[0]) != 32 or _width(resolve, high_trunc.results[0]) != 32:
                continue
            split = node_of(high_trunc.operands[0])
            if split is None or split.operation != Operation.ROTATE_RIGHT or split.attributes[0] != 32 or canon(split.operands[0]) != canon(low_trunc.operands[0]):
                continue
            whole = canon(low_trunc.operands[0])
            if _width(resolve, low_trunc.operand_types[0]) == 64 and value_type(node.results[0]) == "J":
                return whole
        return None

    def effective(refs) -> list[ValueRef]:
        """Values read through ``refs``, looking through the trees evaluated where they are read."""
        out = []
        for ref in map(canon, refs):
            if ref in evaluated_late and repacked(definition(ref)) is not None:
                out.extend(effective((repacked(definition(ref)),)))
            elif ref in evaluated_late:
                out.extend(effective(definition(ref).operands))
            else:
                out.append(ref)
        return out

    tracked = [ref for ref in descriptor_of if ref not in constant_refs and ref not in evaluated_late]
    bit = {ref: 1 << index for index, ref in enumerate(tracked)}

    def bits(refs) -> int:
        mask = 0
        for ref in refs:
            mask |= bit.get(ref, 0)
        return mask

    successors = {index: [target for target, _arguments in block.terminator.edges] for index, block in enumerate(graph.blocks)}
    upward: dict[int, int] = {}
    defined: dict[int, int] = {}
    for block_index, block in enumerate(graph.blocks):
        seen = bits(ValueRef.parameter(block_index, index) for index in range(len(block.parameters)))
        exposed = 0
        for node_index, node in enumerate(block.nodes):
            if ValueRef.node_result(block_index, node_index) in evaluated_late or (block_index, node_index) in eliminated:
                continue
            exposed |= bits(effective(node.operands)) & ~seen
            seen |= bits(ValueRef.node_result(block_index, node_index, index) for index in range(len(node.results)))
        terminator_uses = bits(effective((*block.terminator.values, *edge_reads(block))))
        upward[block_index] = exposed | (terminator_uses & ~seen)
        defined[block_index] = seen
    live_in = {index: 0 for index in range(len(graph.blocks))}
    changed = True
    while changed:
        changed = False
        for block_index in reversed(range(len(graph.blocks))):
            out = 0
            for successor in successors[block_index]:
                out |= live_in[successor]
            value = upward[block_index] | (out & ~defined[block_index])
            if value != live_in[block_index]:
                live_in[block_index] = value
                changed = True
    interference: dict[ValueRef, int] = {ref: 0 for ref in tracked}
    by_bit = {bit[ref]: ref for ref in tracked}

    def interfere(defs: int, live: int) -> None:
        for ref_bit in _bits_of(defs):
            interference[by_bit[ref_bit]] |= live & ~ref_bit
            for other in _bits_of(live & ~ref_bit):
                interference[by_bit[other]] |= ref_bit

    across_labels = 0  # values a lowering's own branch targets must type
    for block_index, block in enumerate(graph.blocks):
        live = 0
        for successor in successors[block_index]:
            live |= live_in[successor]
        terminator_reads = bits(effective(block.terminator.values))
        live |= terminator_reads | bits(edge_reads(block))
        if block.terminator.kind == TerminatorKind.CONDITIONAL_BRANCH:
            across_labels |= terminator_reads  # a short-circuit condition reads leaves after its own labels
        for node_index in reversed(range(len(block.nodes))):
            node = block.nodes[node_index]
            if ValueRef.node_result(block_index, node_index) in evaluated_late or (block_index, node_index) in eliminated:
                continue
            defs = bits(ValueRef.node_result(block_index, node_index, index) for index in range(len(node.results)))
            operands = bits(effective(node.operands))
            # A result never shares a slot with its own node's operands (lowerings may reread
            # them), except a copy, which may share its operand's slot and then emits nothing.
            same_value = aliases(block_index, node_index, node)
            reads_first = node.operation in _ARITHMETIC  # reads every operand before it writes
            for result_index in range(len(node.results)):
                ref = ValueRef.node_result(block_index, node_index, result_index)
                if ref in bit:
                    if reads_first:
                        interfere(bit[ref], live | defs)  # may take a dying operand's local
                    else:
                        # A copy holds its operand's value: it may share that local even while both live.
                        interfere(bit[ref], (live | defs | operands) & ~bits((canon(same_value[ref]),)) if ref in same_value else live | defs | operands)
            if node.operation in _INTERNAL_LABELS:
                across_labels |= live | defs | operands
            live = (live & ~defs) | operands
        params = bits(ValueRef.parameter(block_index, index) for index in range(len(block.parameters)))
        interfere(params, live | params)

    # Coalescing hints: a block parameter and the arguments passed to it; a copy and its operand.
    hints: dict[ValueRef, list[ValueRef]] = {}
    for block_index, block in enumerate(graph.blocks):
        for node_index, node in enumerate(block.nodes):
            for result, operand in aliases(block_index, node_index, node).items():
                if result in bit and operand in bit:
                    hints.setdefault(result, []).append(operand)
                    hints.setdefault(operand, []).append(result)
            if node.operation in (Operation.ADD_WRAP, Operation.SUB_WRAP):
                result = ValueRef.node_result(block_index, node_index)
                operand = canon(node.operands[0])
                if result in bit and operand in bit:  # x = x + c, as one iinc
                    hints.setdefault(result, []).append(operand)
    for block in graph.blocks:
        for target, arguments in block.terminator.edges:
            for index, argument in enumerate(arguments):
                parameter, argument = ValueRef.parameter(target, index), canon(argument)
                if parameter in bit and argument in bit:
                    hints.setdefault(parameter, []).append(argument)
                    hints.setdefault(argument, []).append(parameter)

    # Frames type only the slots that hold a value across a branch target: a block's
    # live-in values and parameters, edge arguments (read after a false stub), and
    # values live at a lowering's internal label.  Every other slot is Top in every
    # frame, so it needs no initialization (ADR-157).
    entered = {target for block in graph.blocks for target, _arguments in block.terminator.edges}
    framed = across_labels
    for block_index, block in enumerate(graph.blocks):
        framed |= live_in[block_index]
        if block_index in entered:  # the entry's parameters are only framed if a branch enters it
            framed |= bits(ValueRef.parameter(block_index, index) for index in range(len(block.parameters)))
        framed |= bits(edge_reads(block))

    slot_of: dict[ValueRef, tuple[int, str]] = {}
    frame_locals: list[str] = []
    slot_types: dict[int, str] = {}
    occupants: dict[int, int] = {}  # slot -> bits of the values assigned to it
    next_slot = 0

    def new_slot(descriptor: str) -> int:
        nonlocal next_slot
        slot = next_slot
        next_slot += _slots(descriptor)
        frame_locals.append(descriptor)
        slot_types[slot] = descriptor
        occupants[slot] = 0
        return slot

    def assign(ref: ValueRef, slot: int) -> None:
        slot_of[ref] = (slot, descriptor_of[ref])
        occupants[slot] |= bit[ref]

    incoming_parameters = [ValueRef.parameter(graph.entry, index) for index in range(len(graph.blocks[graph.entry].parameters))]
    incoming_parameters = [ref for ref in incoming_parameters if ref in descriptor_of]
    if name != "entry":
        incoming_parameters = _internal_order(incoming_parameters, [descriptor_of[ref] for ref in incoming_parameters])
    for ref in incoming_parameters:
        assign(ref, new_slot(descriptor_of[ref]))  # the JVM passes parameters in the first slots
    parameter_slot_end = next_slot
    # A parameter no branch target sees (read only before the first one) frees its
    # slots for values of any one-slot type: the low slots have one-byte loads and
    # stores (ADR-157).  Freed slots are untyped (None) until a value takes them.
    freed: dict[int, ValueRef] = {}
    for ref, (slot, descriptor) in list(slot_of.items()):
        if ref.tag == 0 and ref.block == graph.entry and ref in bit and not bit[ref] & framed and kept_parameters is not None and ref not in kept_parameters:
            del slot_types[slot]
            for part in range(slot, slot + _slots(descriptor)):
                slot_types[part] = None
                occupants[part] = bit[ref]
                freed[part] = ref
    ordered = [ref for ref in tracked if ref not in slot_of]
    for ref in ordered:
        descriptor = descriptor_of[ref]
        candidates = [slot_of[hint][0] for hint in hints.get(ref, ()) if hint in slot_of]
        candidates += [slot for slot in sorted(slot_types) if slot not in candidates]
        for slot in candidates:
            fits = slot_types.get(slot) == descriptor or (slot_types.get(slot, "") is None and _slots(descriptor) == 1)
            if fits and not occupants[slot] & interference[ref]:
                slot_types[slot] = descriptor
                assign(ref, slot)
                break
        else:
            assign(ref, new_slot(descriptor))
    for ref in (*constant_refs, *evaluated_late):
        if ref in descriptor_of:
            slot_of[ref] = (-1, descriptor_of[ref])
    for ref in alias:
        if canon(ref) in slot_of:
            slot_of[ref] = slot_of[canon(ref)]  # the same value, in its one local
    global_slot_end = next_slot
    for slot in [slot for slot, descriptor in slot_types.items() if descriptor is None]:
        slot_types[slot] = "T"  # a freed slot no value took
    typed_slots = {slot_of[ref][0] for ref in tracked if bit[ref] & framed}
    typed_slots |= {slot for slot in slot_types if slot < parameter_slot_end and slot not in freed}
    frame_types: list[str] = []
    for slot in sorted(slot_types):
        if slot in typed_slots and slot_types[slot] != "T":
            frame_types.append(slot_types[slot])
        else:
            frame_types.extend("T" * _slots(slot_types[slot]))
    while frame_types and frame_types[-1] == "T":
        frame_types.pop()
    scratch = [global_slot_end]
    max_locals = [global_slot_end]

    def scratch_slot(descriptor: str) -> int:
        """A temporary past the typed locals: frames leave it Top, so it never lives across a branch target."""
        slot = scratch[0]
        scratch[0] += _slots(descriptor)
        max_locals[0] = max(max_locals[0], scratch[0])
        return slot

    def enter_block(block_index: int) -> None:
        scratch[0] = global_slot_end

    def local(opcode_table: dict[str, int], descriptor: str, slot: int) -> None:
        opcode = opcode_table[_kind_letter(descriptor)]
        if slot <= 3:
            code.op(_SHORT_LOCAL[opcode] + slot)  # iload_0 .. astore_3
        elif slot <= 0xFF:
            code.op(opcode, slot)
        else:
            code.op(0xC4, opcode)
            code.raw(_u2(slot))

    def get(ref: ValueRef) -> str:
        ref = canon(ref)
        while ref in copy_of and ref in slot_of and slot_of[ref][0] >= 0 and slot_of[ref][0] == slot_of.get(canon(copy_of[ref]), (-2,))[0]:
            ref = canon(copy_of[ref])  # a coalesced copy is its operand, in the same local
        try:
            slot, descriptor = slot_of[ref]
        except KeyError:
            fail("XAX.JVM.VALUE", where, "JVM-VALUE-MACHINE", "machine value", [ref.tag, ref.block, ref.index, ref.result])
        if ref in constants:
            const(descriptor, constants[ref])  # integer constants are rematerialized at each use
            return descriptor
        if ref in inlined:
            lower_node(ref.block, ref.index)  # an expression tree: evaluated where it is read
            return descriptor
        reads[ref] = reads.get(ref, 0) + 1
        if pending[0] == ref:
            pending[0] = None  # its only read: the value is already on top of the stack
            return descriptor
        if stored[0] == ref:
            stored[0] = None  # read right after it is computed: dup, store, and use the copy
            code.op(0x5C if descriptor in ("J", "D") else 0x59)
            local(_STORE, descriptor, slot)
            return descriptor
        local(_LOAD, descriptor, slot)
        return descriptor

    def put(ref: ValueRef) -> None:
        if ref in inlined:
            return  # stays on the operand stack for its reader
        flush()
        if single_read is not None and ref in single_read and ref not in implicit:
            pending[0] = ref
            return
        stored[0] = ref

    def keep(ref: ValueRef) -> None:
        """Store a call's result, or drop it when nothing reads it."""
        if ref in needed:
            put(ref)
        else:
            code.op(0x58 if slot_of[ref][1] in ("J", "D") else 0x57)  # pop2 / pop

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
        if ref in constants:
            value = constants[ref]
            if signed and value >> (width - 1):
                value -= 1 << width
            elif not signed and width == 64:
                value ^= 1 << 63
            lconst(value)  # the transform folded
            return
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

    def unsigned_long(width: int) -> None:
        """Widen the int on the stack (a ``width``-bit value) to its unsigned long."""
        if width == 32:
            code.op(0xB8); code.raw(_u2(pool.method("java/lang/Integer", "toUnsignedLong", "(I)J")))
        else:
            code.op(0x85)  # narrower values are non-negative ints

    def get_zero_extended(ref: ValueRef, width: int) -> None:
        """Push ``ref`` as a long holding its unsigned value (address and index arithmetic)."""
        if get(ref) == "I":
            unsigned_long(width)

    def int_branch_if_not(node) -> int | None:
        """``if_icmp<cond>`` that branches when an int compare is false; ``None`` when it needs the long path."""
        if node.operation != Operation.INT_COMPARE or slot_of[node.operands[0]][1] != "I":
            return None
        kind = IntCompare(node.attributes[0])
        width = _width(resolve, node.operand_types[0])
        signed = kind in (IntCompare.SLT, IntCompare.SLE, IntCompare.SGT, IntCompare.SGE)
        if signed and width < 32:
            return None
        flip = not signed and width == 32 and kind not in (IntCompare.EQ, IntCompare.NE)
        if not flip and constants.get(node.operands[1]) == 0:
            get(node.operands[0])
            return _BRANCH_IF_NOT[_INT_RELATION[kind]]  # if<cond>: against zero
        for operand in node.operands:
            source = definition(operand) if operand in inlined else None
            if flip and operand in constants:
                iconst(constants[operand] ^ (1 << 31))  # folded sign flip
            elif flip and source is not None and source.operation in (Operation.ADD_WRAP, Operation.SUB_WRAP) and source.operands[1] in constants:
                # (a +- c) ^ 2^31 == a + (2^31 +- c): one add for the offset and the flip
                offset = constants[source.operands[1]]
                get(source.operands[0])
                iconst(((1 << 31) + (offset if source.operation == Operation.ADD_WRAP else -offset)) & 0xFFFFFFFF); code.op(0x60)
            else:
                get(operand)
                if flip:
                    iconst(-(1 << 31)); code.op(0x82)  # unsigned order becomes signed order
        # Zero-extended values below 32 bits are non-negative, so signed int order is their order.
        return _INT_BRANCH_IF_NOT[_INT_RELATION[kind]]

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
        if kind in (IntCompare.EQ, IntCompare.NE) and slot_of[node.operands[0]][1] == "J":
            get(node.operands[0]); get(node.operands[1])  # equality needs no order transform
        else:
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

    def memory_field() -> None:
        code.op(0xB2); code.raw(_u2(pool.field(class_name, "M", "[B")))

    def memory_access(load: bool, size: int, value_cid: bytes, value_ref, push_address, result_ref) -> None:
        """Little-endian access of ``size`` bytes at the pushed address (ADR-156)."""
        is_float = resolve(value_cid).body[:1] == b"\x07"
        if load:
            descriptor = slot_of[result_ref][1]
            if size == 1:
                memory_field(); push_address(); code.op(0x33); iconst(0xFF); code.op(0x7E)  # baload & 0xff
                if descriptor == "J":
                    code.op(0x85)
            else:
                needs.add(f"ld{size}")
                push_address()
                code.op(0xB8); code.raw(_u2(pool.method(class_name, f"xax$ld{size}", "(I)J" if size == 8 else "(I)I")))
                if is_float:
                    code.op(0xB8)
                    code.raw(_u2(pool.method("java/lang/Float", "intBitsToFloat", "(I)F") if size == 4 else pool.method("java/lang/Double", "longBitsToDouble", "(J)D")))
                elif descriptor == "J" and size != 8:
                    code.op(0x85); lconst((1 << (8 * size)) - 1); code.op(0x7F)
                elif descriptor == "I" and size == 8:
                    code.op(0x88)
            if not is_float and _width(resolve, value_cid) < 8 * size:
                mask(descriptor, _width(resolve, value_cid))
            put(result_ref)
            return
        if size == 1:
            memory_field(); push_address()
            if get(value_ref) == "J":
                code.op(0x88)
            code.op(0x54)  # bastore keeps the low byte
            return
        needs.add(f"st{size}")
        push_address()
        descriptor = get(value_ref)
        if descriptor == "F":
            code.op(0xB8); code.raw(_u2(pool.method("java/lang/Float", "floatToRawIntBits", "(F)I")))
        elif descriptor == "D":
            code.op(0xB8); code.raw(_u2(pool.method("java/lang/Double", "doubleToRawLongBits", "(D)J")))
        elif size == 8 and descriptor == "I":
            code.op(0x85)
        elif size != 8 and descriptor == "J":
            code.op(0x88)
        code.op(0xB8); code.raw(_u2(pool.method(class_name, f"xax$st{size}", "(IJ)V" if size == 8 else "(II)V")))

    lines: list[tuple[int, int]] = []
    node_ranges: list[tuple[int, int, int, int, int]] = []

    # Prelude: give every non-parameter local its type before the first branch target.
    # Definite assignment (ADR-157): a typed slot needs a zero store before the first
    # branch target only if some branch target can be reached before a value is
    # stored in it.  A block's labels see at least what is assigned on entry to it.
    def stored_slots(block_index: int, edges: bool = True) -> set[int]:
        out = set()
        block = graph.blocks[block_index]
        for node_index, node in enumerate(block.nodes):
            for result_index in range(len(node.results)):
                ref = ValueRef.node_result(block_index, node_index, result_index)
                if ref in slot_of and slot_of[ref][0] >= 0 and not (single_read is not None and ref in single_read and ref not in implicit):
                    out.add(slot_of[ref][0])
        for target, _arguments in (block.terminator.edges if edges else ()):
            out.update(slot_of[ValueRef.parameter(target, index)][0] for index in range(len(graph.blocks[target].parameters)) if ValueRef.parameter(target, index) in slot_of)
        return out

    every_slot = frozenset(slot_types)
    predecessors: dict[int, list[int]] = {index: [] for index in range(len(graph.blocks))}
    for block_index, block in enumerate(graph.blocks):
        for target, _arguments in block.terminator.edges:
            predecessors[target].append(block_index)
    writes = {index: stored_slots(index) for index in range(len(graph.blocks))}
    parameter_slots = frozenset(slot for slot in slot_types if slot < parameter_slot_end and slot not in freed)
    assigned_in = {index: (parameter_slots if index == graph.entry else every_slot) for index in range(len(graph.blocks))}
    changed = True
    while changed:
        changed = False
        for block_index in range(len(graph.blocks)):
            incoming = [assigned_in[p] | writes[p] for p in predecessors[block_index]]
            if block_index == graph.entry:
                incoming.append(parameter_slots)
            value = frozenset.intersection(*map(frozenset, incoming)) if incoming else assigned_in[block_index]
            if value != assigned_in[block_index]:
                assigned_in[block_index] = value
                changed = True
    points = []  # slots assigned at every branch target a block can contain
    for block_index, block in enumerate(graph.blocks):
        if predecessors[block_index]:
            points.append(assigned_in[block_index])  # its own label
        so_far = set(assigned_in[block_index])
        for node_index, node in enumerate(block.nodes):
            if node.operation in _INTERNAL_LABELS:
                points.append(frozenset(so_far))  # a label inside it (the trap's frame has no locals)
            for result_index in range(len(node.results)):
                ref = ValueRef.node_result(block_index, node_index, result_index)
                if ref in slot_of and slot_of[ref][0] >= 0 and not (single_read is not None and ref in single_read and ref not in implicit):
                    so_far.add(slot_of[ref][0])
        if block.terminator.kind not in (TerminatorKind.RETURN, TerminatorKind.BRANCH):
            points.append(frozenset(so_far))  # short-circuit and stub labels
    needs_zero = {slot for slot in typed_slots if any(slot not in point for point in points)}
    if needs_zero & set(freed):
        raise _KeepParameters(frozenset(freed[slot] for slot in needs_zero & set(freed)))

    for slot in sorted(needs_zero):
        if slot >= parameter_slot_end:
            descriptor = slot_types[slot]
            code.op(*_ZERO[_kind_letter(descriptor)])
            local(_STORE, descriptor, slot)
    if not code.buf and any(graph.entry == target for block in graph.blocks for target, _arguments in block.terminator.edges):
        code.op(0x00)  # a branch target may not be the implicit frame at offset 0

    def edge_moves_needed(target: int, arguments: Sequence[ValueRef]) -> list[tuple[ValueRef, ValueRef]]:
        """(parameter, argument) pairs that need a copy: different slots, or a constant argument."""
        pairs = []
        for index, argument in edge_moves(target, arguments):
            parameter = ValueRef.parameter(target, index)
            if argument in constant_refs or slot_of[argument][0] != slot_of[parameter][0]:
                pairs.append((parameter, argument))
        return pairs

    def copy_edge(target: int, arguments: Sequence[ValueRef], *, jump: bool = True, force: bool = False) -> None:
        # Parallel copy: write a slot only once no pending move still reads it; a cycle
        # goes through one temporary.
        pending = [(slot_of[parameter][0], slot_of[parameter][1], argument) for parameter, argument in edge_moves_needed(target, arguments)]
        while pending:
            sources = {slot_of[source][0] for _slot, _descriptor, source in pending if isinstance(source, ValueRef) and source not in constant_refs}
            sources |= {source[0] for _slot, _descriptor, source in pending if isinstance(source, tuple) and not isinstance(source, ValueRef)}
            ready = next((move for move in pending if move[0] not in sources), None)
            if ready is None:
                destination, descriptor, source = pending[0]
                temporary = scratch_slot(descriptor)
                get(source); local(_STORE, descriptor, temporary)
                pending = [(d, k, (temporary, descriptor) if s == source else s) for d, k, s in pending]
                continue
            destination, descriptor, source = ready
            if isinstance(source, ValueRef):
                get(source)
            else:
                local(_LOAD, source[1], source[0])
            local(_STORE, descriptor, destination)
            pending.remove(ready)
        if jump and (force or resolved(target) != following_block[0]):
            code.branch(0xA7, ("block", resolved(target)))

    # Jump threading: an empty block whose one edge needs no copy is never emitted;
    # branches to it go straight to where it leads.
    def forwards_to(block_index: int) -> int | None:
        block = graph.blocks[block_index]
        if block_index == graph.entry or block.nodes or block.terminator.kind != TerminatorKind.BRANCH:
            return None
        target, arguments = block.terminator.edges[0]
        return None if edge_moves_needed(target, arguments) else target

    def resolved(target: int) -> int:
        seen = set()
        while target not in seen:
            seen.add(target)
            following = forwards_to(target)
            if following is None:
                return target
            target = following
        return target  # a cycle of empty blocks: emit the first one reached

    # Layout (ADR-157): chains of fallthrough.  After a block comes the successor it can
    # fall into (a branch's target; a conditional branch's false side, else its true
    # side), when that one is not placed yet.
    order: list[int] = []
    placed: set[int] = set()
    for start in [graph.entry] + list(range(len(graph.blocks))):
        current = start if resolved(start) == start else None
        while current is not None and current not in placed:
            order.append(current)
            placed.add(current)
            terminator = graph.blocks[current].terminator
            following = None
            if terminator.kind == TerminatorKind.BRANCH:
                following = resolved(terminator.edges[0][0])
            elif terminator.kind == TerminatorKind.CONDITIONAL_BRANCH:
                true_side, false_side = (resolved(target) for target, _arguments in terminator.edges)
                is_return = {side: graph.blocks[side].terminator.kind == TerminatorKind.RETURN for side in (true_side, false_side)}
                if is_return[false_side] and not is_return[true_side] and true_side not in placed:
                    following = true_side  # a return is better reached by a jump: equal ones merge
                else:
                    following = false_side if false_side not in placed else true_side
            current = following
    trap_used = False
    max_call_slots = 0
    following_block = [None]
    def statically_in_bounds(node) -> bool:
        """A checked one-byte access at a constant index inside its view: it cannot trap."""
        if node.operation not in (Operation.CHECKED_LOAD_BITS_LE, Operation.CHECKED_STORE_BITS_LE) or node.operands[1] not in constants:
            return False
        maximum = pointer_extent_from_graph(graph, node.operands[0], resolve) - node.attributes[0]
        return 0 <= constants[node.operands[1]] <= maximum

    # String runs (ADR-157): checked one-byte stores of constant ASCII bytes to consecutive
    # constant indices of one view, each consuming the previous one's memory, become one
    # call that stores a String constant's characters in the same order.
    runs: dict[tuple[int, int], tuple[ValueRef, int, str]] = {}
    in_run: set[tuple[int, int]] = set()
    for block_index, block in enumerate(graph.blocks):
        members: list[int] = []

        def close_run() -> None:
            if len(members) >= 3:
                first = block.nodes[members[0]]
                text = "".join(chr(constants[block.nodes[index].operands[2]]) for index in members)
                runs[(block_index, members[0])] = (first.operands[0], constants[first.operands[1]], text)
                in_run.update((block_index, index) for index in members[1:])
            members.clear()

        for node_index, node in enumerate(block.nodes):
            if ValueRef.node_result(block_index, node_index) in constants:
                continue  # emits nothing
            fits = (
                node.operation == Operation.CHECKED_STORE_BITS_LE and node.attributes[0] == 1 and statically_in_bounds(node)
                and node.operands[2] in constants and 0 < constants[node.operands[2]] < 0x80
            )
            if fits and members:
                previous = block.nodes[members[-1]]
                fits = (
                    node.operands[0] == previous.operands[0] and constants[node.operands[1]] == constants[previous.operands[1]] + 1
                    and node.operands[3] == ValueRef.node_result(block_index, members[-1]) and uses.get(node.operands[3]) == 1
                )
                if not fits:
                    close_run()
                    fits = True  # it may start the next run
            if fits:
                members.append(node_index)
            else:
                close_run()
        close_run()

    def freeing(node) -> bool:
        """The memory package's free: lowered to a constant, it cannot raise."""
        if node.operation != Operation.CALL_FOREIGN or decode_foreign_function(node.entity).library != MEMORY_CLASS:
            return False
        member = _foreign_member(node.entity, resolve)
        return member.name + member.descriptor == "free(I)J"

    line_of: dict[tuple[int, int], int] = {}
    for block_index in order:
        for node_index in range(len(graph.blocks[block_index].nodes)):
            line_of[(block_index, node_index)] = len(line_of) + 1

    def lower_node(block_index: int, node_index: int) -> None:
        nonlocal trap_used, max_call_slots
        node = graph.blocks[block_index].nodes[node_index]
        line = line_of[(block_index, node_index)]
        start = len(code.buf)
        if node.operation in _MAY_RAISE and not statically_in_bounds(node) and not freeing(node):
            # Only a pc that can raise or call shows up in a stack trace (ADR-157);
            # every pc still maps to its node through the artifact's semantic ranges.
            lines.append((start, line))
        result = ValueRef.node_result(block_index, node_index)
        operation = node.operation

        if result in folded:
            pass  # a constant: every use rematerializes it

        elif (block_index, node_index) in in_run:
            pass  # stored by the first node of its string run

        elif (block_index, node_index) in runs:
            pointer, first_index, text = runs[(block_index, node_index)]
            needs.add("memory")
            # text.getBytes(0, n, M, p + i): each char's low byte, in order (indices proven in range)
            ldc(pool.string(text)); iconst(0); iconst(len(text)); memory_field()
            get(pointer); iconst(first_index); code.op(0x60)
            code.op(0xB6); code.raw(_u2(pool.method("java/lang/String", "getBytes", "(II[BI)V")))

        elif result in inlined and repacked(node) is not None:
            get(repacked(node)); put(result)  # the halves of s, packed again: s

        elif pack_operands(node) is not None:
            low, high = pack_operands(node)
            get(low)
            iconst(high[1]) if isinstance(high, tuple) and high[0] == "constant" else get(high)
            needs.add("shared:pk")
            code.op(0xB8); code.raw(_u2(pool.method(class_name, "xax$pk", "(II)J")))
            put(result)

        elif (
            operation in (Operation.ADD_WRAP, Operation.SUB_WRAP) and slot_of[result][1] == "I" and _width(resolve, node.results[0]) == 32
            and canon(node.operands[1]) in constants and slot_of[result][0] >= 0 and slot_of[result][0] == slot_of[canon(node.operands[0])][0]
            and -128 <= _signed32(constants[canon(node.operands[1])] * (1 if operation == Operation.ADD_WRAP else -1)) <= 127
            and pending[0] != canon(node.operands[0]) and not (single_read is not None and result in single_read and result not in implicit)
        ):
            flush()
            if stored[0] == canon(node.operands[0]):
                flush()
            delta = _signed32(constants[canon(node.operands[1])] * (1 if operation == Operation.ADD_WRAP else -1))
            reads[canon(node.operands[0])] = reads.get(canon(node.operands[0]), 0) + 1  # a read, as both passes count it
            slot = slot_of[result][0]
            if slot <= 0xFF:
                code.op(0x84, slot, delta & 0xFF)  # iinc: the local is its own operand
            else:
                code.op(0xC4, 0x84); code.raw(_u2(slot) + struct.pack(">h", delta))

        elif operation in _ARITHMETIC:
            width = _width(resolve, node.results[0])
            first, second = node.operands
            if pending[0] == second and operation != Operation.SUB_WRAP:
                first, second = second, first  # commutative: read the stacked value first
            descriptor = get(first)
            get(second)
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
            source = definition(node.operands[0])
            reader = sole_user(result)
            long_ = width == 64
            descriptor = get(node.operands[0])
            if amount and width in (32, 64) and source is not None and source.operation == Operation.INT_ZERO_EXTEND and _width(resolve, source.operand_types[0]) <= amount:
                iconst(width - amount); code.op(0x79 if long_ else 0x78)  # no bits above the amount: a left shift
            elif amount and width in (32, 64) and reader is not None and reader.operation == Operation.INT_TRUNCATE and _width(resolve, reader.results[0]) <= width - amount:
                iconst(amount); code.op(0x7D if long_ else 0x7C)  # only the low bits are read: a right shift
            elif amount and width in (32, 64):
                iconst(amount)  # Integer/Long.rotateRight: a JIT intrinsic (one ror)
                owner, signature = ("java/lang/Long", "(JI)J") if width == 64 else ("java/lang/Integer", "(II)I")
                code.op(0xB8); code.raw(_u2(pool.method(owner, "rotateRight", signature)))
            elif amount:
                long_ = descriptor == "J"
                iconst(amount); code.op(0x7D if long_ else 0x7C)  # ushr
                get(node.operands[0]); iconst(width - amount); code.op(0x79 if long_ else 0x78)  # shl
                code.op(0x81 if long_ else 0x80)  # or
                mask(descriptor, width)
            put(result)

        elif copy_like(node) and operation != Operation.HEAP_VIEW and slot_of[node.operands[0]][0] == slot_of[result][0]:
            pass  # coalesced copy

        elif operation in (Operation.INT_TRUNCATE, Operation.INT_ZERO_EXTEND):
            source = _width(resolve, node.operand_types[0])
            destination = _width(resolve, node.results[0])
            source_descriptor = get(node.operands[0])
            destination_descriptor = slot_of[result][1]
            if source_descriptor == "J" and destination_descriptor == "I":
                code.op(0x88)
            elif source_descriptor == "I" and destination_descriptor == "J":
                reader = sole_user(result)
                if reader is not None and reader.operation == Operation.ROTATE_RIGHT and reader.attributes[0] == 32 and _width(resolve, reader.results[0]) == 64:
                    code.op(0x85)  # i2l: the rotation's left shift by 32 drops the sign copies
                else:
                    unsigned_long(source)
            if operation == Operation.INT_TRUNCATE and known_width.get(node.operands[0], 64) > destination:
                mask(destination_descriptor, destination)
            put(result)

        elif operation == Operation.CONSTANT:
            type_cid, value = _decode_constant(node.entity, resolve)
            descriptor = slot_of[result][1]
            if descriptor in ("F", "D"):
                # Raw constant bits, so NaN payloads stay exact.
                width = 32 if descriptor == "F" else 64
                fconst_bits(int.from_bytes(node.entity.body[-(width // 8):], "little"), width)
                put(result)
            # integer constants: nothing to store, every use rematerializes them

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
                kind = IntCompare(node.attributes[0]) if operation == Operation.INT_COMPARE else None
                if kind in (IntCompare.EQ, IntCompare.NE) and slot_of[node.operands[0]][1] == "I":
                    # x = a ^ b; (x | -x) >>> 31 is 1 exactly when a != b.
                    get(node.operands[0]); get(node.operands[1]); code.op(0x82, 0x59, 0x74, 0x80)
                    iconst(31); code.op(0x7C)
                    if kind == IntCompare.EQ:
                        iconst(1); code.op(0x82)
                else:
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
                if methods[node.entity.cid][0] != "entry":
                    machine = _internal_order(machine, [value_type(cid) for cid in node.operand_types if value_type(cid) is not None])
                slots = 0
                for operand in machine:
                    slots += _slots(get(operand))
                max_call_slots = max(max_call_slots, slots)
                callee_name, callee_descriptor = methods[node.entity.cid]
                code.op(0xB8)
                code.raw(_u2(pool.method(class_name, callee_name, callee_descriptor)))
                call_elided = borrowed_view_returns(node.operand_types, node.results, resolve)
                returned = [index for index in range(len(node.results)) if index not in call_elided and ValueRef.node_result(block_index, node_index, index) in slot_of]
                if len(returned) > 1:
                    fail("XAX.JVM.ABI", where, "JVM-SINGLE-RESULT", "at most one machine result", len(returned))
                if returned:
                    keep(ValueRef.node_result(block_index, node_index, returned[0]))
                for result_index, parameter_index in sorted(call_elided.items()):
                    given_back = ValueRef.node_result(block_index, node_index, result_index)
                    if given_back in needed and given_back in slot_of and slot_of[given_back][0] != slot_of[node.operands[parameter_index]][0]:
                        get(node.operands[parameter_index]); put(given_back)

        elif operation == Operation.HEAP_VIEW:
            # The allocator contract is nullable; the view's non-null proof is an explicit trap.
            trap_used = True
            needs.add("memory")
            get(node.operands[0]); code.branch(0x99, "trap")  # ifeq
            if slot_of[node.operands[0]][0] != slot_of[result][0]:
                get(node.operands[0]); put(result)

        elif operation == Operation.ADDRESS_OFFSET:
            get(node.operands[0]); iconst(node.attributes[0]); code.op(0x60); put(result)

        elif operation == Operation.POINTER_CAST:
            get(node.operands[0]); put(result)

        elif operation == Operation.POINTER_ADDRESS:
            get(node.operands[0])
            if slot_of[result][1] == "J":
                code.op(0x85)  # offsets are below 2^31, so i2l is the zero extension
            put(result)

        elif operation == Operation.POINTER_REBASE:
            # ADR-092: trap unless 0 <= address - view <= extent - window and the
            # distance is a multiple of the result's alignment.
            trap_used = True
            view, address = node.operands
            width = _width(resolve, node.operand_types[1])
            span = pointer_extent_from_graph(graph, view, resolve) - node.attributes[0]
            alignment = _decode_pointer_type(resolve(node.results[0]), resolve)[2]
            get_zero_extended(address, width); get(view); code.op(0x85, 0x65)  # i2l; lsub
            if alignment > 1:
                code.op(0x5C); lconst(alignment - 1); code.op(0x7F); lconst(0); code.op(0x94); code.branch(0x9A, "trap")
            if span < 0:
                code.op(0x58); iconst(1); code.branch(0x9A, "trap")  # pop2; always traps
            else:
                lconst(span)
                code.op(0xB8); code.raw(_u2(pool.method("java/lang/Long", "compareUnsigned", "(JJ)I")))
                code.branch(0x9D, "trap")  # ifgt
            get_zero_extended(address, width); code.op(0x88); put(result)

        elif operation in (Operation.LOAD_BITS_LE, Operation.STORE_BITS_LE, Operation.CHECKED_LOAD_BITS_LE, Operation.CHECKED_STORE_BITS_LE):
            needs.add("memory")
            checked = operation in (Operation.CHECKED_LOAD_BITS_LE, Operation.CHECKED_STORE_BITS_LE)
            load = operation in (Operation.LOAD_BITS_LE, Operation.CHECKED_LOAD_BITS_LE)
            size = node.attributes[0]
            pointer = node.operands[0]
            value_cid = node.results[0] if load else node.operand_types[2 if checked else 1]
            value_ref = None if load else node.operands[2 if checked else 1]
            if size not in (1, 2, 4, 8):
                fail("XAX.JVM.MEMORY_WIDTH", where, "JVM-MEMORY-WIDTH", [1, 2, 4, 8], size)
            helper_check = False
            if checked:
                index, index_width = node.operands[1], _width(resolve, node.operand_types[1])
                maximum = pointer_extent_from_graph(graph, pointer, resolve) - size
                trap_used = trap_used or not (0 <= maximum < 1 << 31 and index_width <= 32)
                if maximum < 0:
                    iconst(1); code.branch(0x9A, "trap")  # always traps
                elif index_width <= 32 and maximum < 1 << 31:
                    helper_check = True  # xax$ix while the address is pushed
                else:
                    get_zero_extended(index, index_width); lconst(maximum)
                    if index_width > 63:
                        code.op(0xB8); code.raw(_u2(pool.method("java/lang/Long", "compareUnsigned", "(JJ)I")))
                    else:
                        code.op(0x94)  # lcmp: both are non-negative longs
                    code.branch(0x9D, "trap")  # ifgt

            def push_address() -> None:
                get(pointer)
                if helper_check:
                    get(index); iconst(maximum)
                    needs.add("ix")
                    code.op(0xB8); code.raw(_u2(pool.method(class_name, "xax$ix", "(II)I")))
                    code.op(0x60)
                elif checked:
                    if get(index) == "J":
                        code.op(0x88)
                    code.op(0x60)

            if size == 1 and (helper_check or (load and not checked)):
                # Byte accesses through generated members (ADR-157), as a Java programmer's
                # at()/put() helpers: one call per access, inlined by the JIT.
                if not load and get(value_ref) == "J":  # the byte first: often already on the stack
                    code.op(0x88)
                get(pointer)
                if helper_check:
                    get(index)  # the bound is part of the member: one per view extent
                if load:
                    member, signature = (f"xax$l{maximum:x}", "(II)I") if helper_check else ("xax$ld1", "(I)I")
                else:
                    member, signature = f"xax$s{maximum:x}", "(III)V"
                needs.add(member[4:] if member == "xax$ld1" else f"b{member[4]}:{maximum:x}")
                code.op(0xB8); code.raw(_u2(pool.method(class_name, member, signature)))
                if load:
                    descriptor = slot_of[result][1]
                    if descriptor == "J":
                        code.op(0x85)
                    if _width(resolve, value_cid) < 8:
                        mask(descriptor, _width(resolve, value_cid))
                    put(result)
            else:
                memory_access(load, size, value_cid, value_ref, push_address, result if load else None)

        elif operation == Operation.CALL_FOREIGN and decode_foreign_function(node.entity).library == MEMORY_CLASS:
            member = _foreign_member(node.entity, resolve)
            key = member.name + member.descriptor
            if key not in _MEMORY_MEMBERS:
                fail("XAX.JVM.FOREIGN", where, "JVM-MEMORY-MEMBER", sorted(_MEMORY_MEMBERS), key)
            needs.add("memory")
            if key == "free(I)J":
                # Blocks are never reused (ADR-156): free is the constant 0, no call.
                if ValueRef.node_result(block_index, node_index) in slot_of and ValueRef.node_result(block_index, node_index) in needed:
                    code.op(0x09)  # lconst_0
                    put(ValueRef.node_result(block_index, node_index))
                node_ranges.append((block_index, node_index, line, start, len(code.buf)))
                return
            needs.add(key)
            machine = [operand for operand, cid in zip(node.operands, node.operand_types) if value_type(cid) is not None]
            slots = sum(_slots(get(operand)) for operand in machine)
            max_call_slots = max(max_call_slots, slots)
            code.op(0xB8); code.raw(_u2(pool.method(class_name, _MEMORY_MEMBERS[key], member.descriptor)))
            _store_call_result(node, block_index, node_index, slot_of, keep)

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
            _store_call_result(node, block_index, node_index, slot_of, keep)

        elif operation in RESOURCE_EFFECT_OPERATIONS:
            pass  # proof values only: erased

        else:
            fail("XAX.JVM.UNSUPPORTED_OPERATION", where, "JVM-OP-LOWERED", "jvm-classfile-v1 subset", operation)
        node_ranges.append((block_index, node_index, line, start, len(code.buf)))

    def pack_operands(node):
        """(low, high) of ``zext(low) | rotr(zext(high), 32)``, two 32-bit halves in one u64,
        when both halves are expression trees here: lowered as one call to ``xax$pk``."""
        if node.operation != Operation.BIT_OR or _width(resolve, node.results[0]) != 64:
            return None
        for low_ref, high_ref in (node.operands, node.operands[::-1]):
            if high_ref in constants and constants[high_ref] & 0xFFFFFFFF == 0:
                low = definition(low_ref) if low_ref in inlined else None
                if low is not None and low.operation == Operation.INT_ZERO_EXTEND and slot_of.get(low.operands[0], (0, ""))[1] == "I" and _width(resolve, low.operand_types[0]) == 32:
                    return low.operands[0], ("constant", constants[high_ref] >> 32)
                continue
            low, high = (definition(ref) if ref in inlined else None for ref in (low_ref, high_ref))
            if low is None or high is None or low.operation != Operation.INT_ZERO_EXTEND or high.operation != Operation.ROTATE_RIGHT or high.attributes[0] != 32:
                continue
            widened = definition(high.operands[0]) if high.operands[0] in inlined else None
            if widened is None or widened.operation != Operation.INT_ZERO_EXTEND:
                continue
            if all(slot_of.get(ref, (0, ""))[1] == "I" and _width(resolve, cid) == 32 for ref, cid in ((low.operands[0], low.operand_types[0]), (widened.operands[0], widened.operand_types[0]))):
                return low.operands[0], widened.operands[0]
        return None

    def jump_if(condition: ValueRef, when: bool, label) -> None:
        """Branch to ``label`` when ``condition`` is ``when``: an OR/AND tree of
        compares short-circuits (javac's ``||``/``&&``) instead of materializing."""
        condition = canon(condition)
        node = definition(condition) if condition in evaluated_late else None
        if node is not None and node.operation in (Operation.BIT_OR, Operation.BIT_AND) and _width(resolve, node.results[0]) == 1:
            first, second = node.operands
            if (node.operation == Operation.BIT_OR) == when:
                jump_if(first, when, label)
                jump_if(second, when, label)
            else:
                skip = fresh()
                jump_if(first, not when, skip)
                jump_if(second, when, label)
                code.mark(skip)
            node_ranges.append((condition.block, condition.index, line_of[(condition.block, condition.index)], len(code.buf), len(code.buf)))
            return
        if node is not None and node.operation in (Operation.INT_COMPARE, Operation.FLOAT_COMPARE):
            start = len(code.buf)
            branch_if_not = int_branch_if_not(node)
            if branch_if_not is None:
                branch_if_not = _BRANCH_IF_NOT[compare_to_int(node)]
            code.branch(_INVERSE_BRANCH[branch_if_not] if when else branch_if_not, label)
            node_ranges.append((condition.block, condition.index, line_of[(condition.block, condition.index)], start, len(code.buf)))
            return
        get(condition)
        code.branch(0x9A if when else 0x99, label)  # ifne / ifeq

    return_blocks: dict[bytes, int] = {}
    for position_in_order, block_index in enumerate(order):
        following_block[0] = order[position_in_order + 1] if position_in_order + 1 < len(order) else None
        block = graph.blocks[block_index]
        flush()
        block_start, block_fixups, block_lines, block_ranges, entered_by_jump = len(code.buf), len(code.fixups), len(lines), len(node_ranges), code.ended
        code.mark(("block", block_index))
        enter_block(block_index)
        for node_index in range(len(block.nodes)):
            if ValueRef.node_result(block_index, node_index) not in evaluated_late and (block_index, node_index) not in eliminated:
                lower_node(block_index, node_index)

        terminator = block.terminator
        if terminator.kind == TerminatorKind.RETURN:
            own_elided = borrowed_view_returns(parameter_types, return_types, resolve)
            machine = [value for index, (value, cid) in enumerate(zip(terminator.values, return_types)) if value_type(cid) is not None and index not in own_elided]
            if machine:
                descriptor = get(machine[0])
                code.op(_RETURN[_kind_letter(descriptor)])
            else:
                code.op(0xB1)
        elif terminator.kind == TerminatorKind.BRANCH:
            copy_edge(*terminator.edges[0])
        elif terminator.kind == TerminatorKind.CONDITIONAL_BRANCH:
            condition = terminator.values[0]
            (true_target, true_arguments), (false_target, false_arguments) = terminator.edges
            true_moves = edge_moves_needed(true_target, true_arguments)
            false_moves = edge_moves_needed(false_target, false_arguments)
            if not true_moves and (false_moves or resolved(false_target) == following_block[0]):
                jump_if(condition, True, ("block", resolved(true_target)))  # fall through to the false side
                copy_edge(false_target, false_arguments)
            elif not false_moves:
                jump_if(condition, False, ("block", resolved(false_target)))
                copy_edge(true_target, true_arguments)
            elif not true_moves:
                jump_if(condition, True, ("block", resolved(true_target)))
                copy_edge(false_target, false_arguments)
            else:
                false_stub = ("false", block_index)
                jump_if(condition, False, false_stub)
                copy_edge(true_target, true_arguments, force=True)  # the false stub follows, not the next block
                code.mark(false_stub)
                copy_edge(false_target, false_arguments)
        else:
            trap_used = True
            code.branch(0xA7, "trap")
        if (
            terminator.kind == TerminatorKind.RETURN and entered_by_jump and pending[0] is None and stored[0] is None
            and len(code.fixups) == block_fixups and len(lines) == block_lines
        ):
            # Tail merging (ADR-157): a return block only reached by a jump, byte-identical to
            # an earlier one (same locals, same frame), is that one.
            body = bytes(code.buf[block_start:])
            if body in return_blocks:
                del code.buf[block_start:]
                code.labels[("block", block_index)] = return_blocks[body]
                del node_ranges[block_ranges:]
                code.ended = True
            else:
                return_blocks[body] = block_start
    if trap_used:
        code.mark("trap")
        code.op(0xBB); code.raw(_u2(pool.klass("java/lang/Error")))
        code.op(0x59)
        ldc(pool.string(_TRAP_MESSAGE))
        code.op(0xB7); code.raw(_u2(pool.method("java/lang/Error", "<init>", "(Ljava/lang/String;)V")))
        code.op(0xBF)
    # One LineNumberTable entry per code start: nodes that emitted nothing (rematerialized
    # constants, coalesced copies) share the pc of the node after them, which owns it.
    deduplicated: list[tuple[int, int]] = []
    for start, number in lines:
        if deduplicated and deduplicated[-1][0] == start:
            deduplicated[-1] = (start, number)
        else:
            deduplicated.append((start, number))
    lines = deduplicated
    blob, frames = code.finish()
    max_stack = max(8, max_call_slots + 2)
    return _Method(
        name, _method_descriptor(parameters, returns), blob, max_stack, max_locals[0],
        frames, tuple(frame_types), tuple(lines), tuple(node_ranges), function.cid,
        bare_frame=code.labels.get("trap"),
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
_INVERSE_BRANCH = {
    0x99: 0x9A, 0x9A: 0x99, 0x9B: 0x9C, 0x9C: 0x9B, 0x9D: 0x9E, 0x9E: 0x9D,
    0x9F: 0xA0, 0xA0: 0x9F, 0xA1: 0xA2, 0xA2: 0xA1, 0xA3: 0xA4, 0xA4: 0xA3,
}
# if_icmp<cond> on two ints that branches when the relation is false.
_INT_BRANCH_IF_NOT = {"eq": 0xA0, "ne": 0x9F, "lt": 0xA2, "ge": 0xA1, "gt": 0xA4, "le": 0xA3}


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


def _initial_memory(functions: Sequence[SemanticObject], resolve) -> int:
    """Bytes for ``M`` at class initialization: every constant-size ``alloc`` site once, 16-aligned.

    Like a wasm module's initial memory, this sizes the common case so the
    allocator never copies; a site that runs more than once grows ``M`` at run time.
    """
    total = _HEAP_START
    for function in functions:
        graph = parse_function_graph(function, resolve)
        for block in graph.blocks:
            for node in block.nodes:
                if node.operation != Operation.CALL_FOREIGN or decode_foreign_function(node.entity).library != MEMORY_CLASS:
                    continue
                size = node.operands[0]
                if decode_foreign_function(node.entity).name != b"alloc(J)I" or size.tag != 1:
                    continue
                source = graph.blocks[size.block].nodes[size.index]
                if source.operation == Operation.CONSTANT:
                    total = ((total + 15) & -16) + int(_decode_constant(source.entity, resolve)[1])
    return max(_INITIAL_MEMORY, min(total, 1 << 30))


def _shared_methods(pool: _Pool, shared: set[str], class_name: str) -> list[_Method]:
    """Pure members the lowering shares across call sites (ADR-157); any profile."""
    out: list[_Method] = []
    if "pk" in shared:
        # lo, hi: (lo & 0xffffffffL) | (long) hi << 32
        code = _Code("xax$pk")
        code.op(0x1A, 0xB8); code.raw(_u2(pool.method("java/lang/Integer", "toUnsignedLong", "(I)J")))
        code.op(0x1B, 0x85, 0x10, 32, 0x79, 0x81, 0xAD)
        blob, _frames = code.finish()
        out.append(_Method("xax$pk", "(II)J", blob, 5, 2, (), (), ()))
    return out


def _memory_methods(pool: _Pool, class_name: str, needs: set[str], initial: int = _INITIAL_MEMORY) -> list[_Method]:
    """``<clinit>`` and the generated memory members a class uses (ADR-156).

    ``M`` is the linear memory and ``H`` the next free offset.  Every member is
    ordinary bytecode in the generated class: no class outside ``java.base``.
    """
    if "memory" not in needs:
        return []
    if "ld8" in needs:
        needs.add("ld4")
    if "st8" in needs:
        needs.add("st4")
    M, H = pool.field(class_name, "M", "[B"), pool.field(class_name, "H", "I")
    out: list[_Method] = []

    def method(name: str, descriptor: str, code: _Code, locals_: tuple[str, ...], max_locals: int) -> None:
        blob, frames = code.finish()
        out.append(_Method(name, descriptor, blob, 8, max_locals, frames, locals_ if frames else (), ()))

    def get_static(code: _Code, index: int) -> None:
        code.op(0xB2); code.raw(_u2(index))

    def put_static(code: _Code, index: int) -> None:
        code.op(0xB3); code.raw(_u2(index))

    def int_const(code: _Code, value: int) -> None:
        if -1 <= value <= 5:
            code.op(0x03 + value)
        elif -128 <= value <= 127:
            code.op(0x10, value & 0xFF)
        else:
            code.op(0x13); code.raw(_u2(pool.integer(value)))

    def long_const(code: _Code, value: int) -> None:
        code.op(0x14); code.raw(_u2(pool.long(value)))

    def call(code: _Code, owner: str, name: str, descriptor: str, opcode: int = 0xB8) -> None:
        code.op(opcode); code.raw(_u2(pool.method(owner, name, descriptor)))

    # <clinit>: M = new byte[64 KiB]; H = 16
    code = _Code("clinit")
    int_const(code, initial); code.op(0xBC, 8); put_static(code, M)
    int_const(code, _HEAP_START); put_static(code, H)
    code.op(0xB1)
    method("<clinit>", "()V", code, (), 0)

    if "alloc(J)I" in needs:
        # locals: n (J, 0-1), a (I, 2), end (J, 3-4)
        code = _Code("xax$alloc")
        get_static(code, H); int_const(code, 15); code.op(0x60); int_const(code, -16); code.op(0x7E, 0x3D)  # a
        code.op(0x1C, 0x85, 0x1E, 0x61, 0x42)  # end = (long) a + n
        code.op(0x1E, 0x09, 0x94); code.branch(0x9B, "null")  # n < 0 (unsigned >= 2^63)
        code.op(0x21); long_const(code, 0x7FFFFFFF); code.op(0x94); code.branch(0x9D, "null")  # end > 2^31 - 1
        code.op(0x21); get_static(code, M); code.op(0xBE, 0x85, 0x94); code.branch(0x9E, "fits")
        get_static(code, M); get_static(code, M); code.op(0xBE, 0x04, 0x78, 0x21, 0x88)  # M, 2 * |M|, (int) end
        call(code, "java/lang/Math", "max", "(II)I"); call(code, "java/util/Arrays", "copyOf", "([BI)[B"); put_static(code, M)
        code.mark("fits")
        code.op(0x21, 0x88); put_static(code, H); code.op(0x1C, 0xAC)  # H = end; return a
        code.mark("null")
        code.op(0x03, 0xAC)
        method("xax$alloc", "(J)I", code, ("J", "I", "J"), 5)
    if "ld1" in needs:
        code = _Code("xax$ld1")
        get_static(code, M); code.op(0x1A, 0x33); int_const(code, 0xFF); code.op(0x7E, 0xAC)  # M[a] & 0xff
        method("xax$ld1", "(I)I", code, (), 1)
    for item in sorted(needs):
        # Checked byte members, one per view bound (ADR-157): p, i -> M[p + i] & 0xff and
        # v, p, i -> M[p + i] = (byte) v, trapping unless i <= max (unsigned).
        if item.startswith(("bl:", "bs:")):
            maximum = int(item[3:], 16)
            load = item[1] == "l"
            member = f"xax${item[1]}{item[3:]}"
            index = 0x1B if load else 0x1C  # iload_1 / iload_2
            code = _Code(member)
            code.op(index); int_const(code, -(1 << 31)); code.op(0x82); int_const(code, maximum ^ (1 << 31) if maximum < 1 << 31 else maximum - (1 << 32))
            code.branch(0xA3, "trap")  # if_icmpgt: unsigned i > max
            get_static(code, M)
            if load:
                code.op(0x1A, 0x1B, 0x60, 0x33); int_const(code, 0xFF); code.op(0x7E, 0xAC)
            else:
                code.op(0x1B, 0x1C, 0x60, 0x1A, 0x54, 0xB1)
            code.mark("trap")
            code.op(0xBB); code.raw(_u2(pool.klass("java/lang/Error"))); code.op(0x59)
            code.op(0x13); code.raw(_u2(pool.string(_TRAP_MESSAGE)))
            call(code, "java/lang/Error", "<init>", "(Ljava/lang/String;)V", 0xB7); code.op(0xBF)
            method(member, "(II)I" if load else "(III)V", code, ("I", "I") if load else ("I", "I", "I"), 2 if load else 3)
    if "ix" in needs:
        # Checked index (ADR-157): i when 0 <= i <= max unsigned, else the trap.  One
        # small shared method instead of a compare and branch at every checked access.
        code = _Code("xax$ix")
        code.op(0x1A, 0x1B); call(code, "java/lang/Integer", "compareUnsigned", "(II)I"); code.branch(0x9D, "trap")  # ifgt
        code.op(0x1A, 0xAC)
        code.mark("trap")
        code.op(0xBB); code.raw(_u2(pool.klass("java/lang/Error"))); code.op(0x59)
        code.op(0x13); code.raw(_u2(pool.string(_TRAP_MESSAGE)))
        call(code, "java/lang/Error", "<init>", "(Ljava/lang/String;)V", 0xB7); code.op(0xBF)
        method("xax$ix", "(II)I", code, ("I", "I"), 2)
    if "free(I)J" in needs:
        # Blocks are never reused: the view ends, the bytes stay until exit.
        code = _Code("xax$free")
        code.op(0x09, 0xAD)
        method("xax$free", "(I)J", code, (), 1)
    if "read(IIJ)J" in needs:
        # locals: fd (0), p (1), n (J, 2-3), count (4).  EOF is 0; fd != 0 is -EBADF.
        code = _Code("xax$read")
        code.op(0x03, 0x36, 4)
        code.op(0x1A); code.branch(0x9A, "bad")
        get_static(code, pool.field("java/lang/System", "in", "Ljava/io/InputStream;")); get_static(code, M); code.op(0x1B, 0x20)
        long_const(code, 0x7FFFFFFF); call(code, "java/lang/Math", "min", "(JJ)J"); code.op(0x88)
        call(code, "java/io/InputStream", "read", "([BII)I", 0xB6); code.op(0x36, 4)
        code.op(0x15, 4); code.branch(0x9C, "got")  # ifge
        code.op(0x09, 0xAD)
        code.mark("got")
        code.op(0x15, 4, 0x85, 0xAD)
        code.mark("bad")
        long_const(code, -9); code.op(0xAD)
        method("xax$read", "(IIJ)J", code, ("I", "I", "J", "I"), 5)
    if "write(IIJ)J" in needs:
        # locals: fd (0), p (1), n (J, 2-3), stream (4).  fd 1 is System.out, 2 System.err.
        stream = "Ljava/io/PrintStream;"
        code = _Code("xax$write")
        code.op(0x01, 0x3A, 4)
        code.op(0x1A, 0x04); code.branch(0xA0, "not-out")  # if_icmpne
        get_static(code, pool.field("java/lang/System", "out", stream)); code.op(0x3A, 4); code.branch(0xA7, "go")
        code.mark("not-out")
        code.op(0x1A, 0x05); code.branch(0xA0, "bad")
        get_static(code, pool.field("java/lang/System", "err", stream)); code.op(0x3A, 4)
        code.mark("go")
        code.op(0x19, 4); get_static(code, M); code.op(0x1B, 0x20, 0x88)
        call(code, "java/io/PrintStream", "write", "([BII)V", 0xB6)
        code.op(0x19, 4); call(code, "java/io/PrintStream", "flush", "()V", 0xB6)
        code.op(0x20, 0xAD)
        code.mark("bad")
        long_const(code, -9); code.op(0xAD)
        method("xax$write", "(IIJ)J", code, ("I", "I", "J", stream), 5)
    for size in (2, 4):
        if f"ld{size}" in needs:
            code = _Code(f"xax$ld{size}")
            for k in range(size):
                get_static(code, M); code.op(0x1A)
                if k:
                    int_const(code, k); code.op(0x60)
                code.op(0x33); int_const(code, 0xFF); code.op(0x7E)
                if k:
                    int_const(code, 8 * k); code.op(0x78, 0x80)  # ishl; ior
            code.op(0xAC)
            method(f"xax$ld{size}", "(I)I", code, (), 1)
        if f"st{size}" in needs:
            code = _Code(f"xax$st{size}")
            for k in range(size):
                get_static(code, M); code.op(0x1A)
                if k:
                    int_const(code, k); code.op(0x60)
                code.op(0x1B)
                if k:
                    int_const(code, 8 * k); code.op(0x7C)  # iushr
                code.op(0x54)
            code.op(0xB1)
            method(f"xax$st{size}", "(II)V", code, (), 2)
    if "ld8" in needs:
        code = _Code("xax$ld8")
        code.op(0x1A); call(code, class_name, "xax$ld4", "(I)I"); code.op(0x85); long_const(code, 0xFFFFFFFF); code.op(0x7F)
        code.op(0x1A, 0x07, 0x60); call(code, class_name, "xax$ld4", "(I)I"); code.op(0x85); int_const(code, 32); code.op(0x79, 0x81, 0xAD)
        method("xax$ld8", "(I)J", code, (), 1)
    if "st8" in needs:
        code = _Code("xax$st8")
        code.op(0x1A, 0x1F, 0x88); call(code, class_name, "xax$st4", "(II)V")
        code.op(0x1A, 0x07, 0x60, 0x1F); int_const(code, 32); code.op(0x7D, 0x88); call(code, class_name, "xax$st4", "(II)V")
        code.op(0xB1)
        method("xax$st8", "(IJ)V", code, (), 3)
    return out


# The memory profile's process entry runs on its own thread with this stack
# (ADR-156): XAX recursion depth is the program's, and JVM frames are larger
# than native ones, so the launcher's default 1 MiB stack is not the platform limit.
ENTRY_STACK_BYTES = 256 << 20


def _threaded_launcher(pool: _Pool, class_name: str, entry_name: str) -> list[_Method]:
    """``main`` starts ``run`` on a thread with ``ENTRY_STACK_BYTES`` of stack and joins it.

    ``run`` calls the entry and then ends the JVM with status 0, as returning
    from ``main`` does (ADR-157).  An entry that ended by an uncaught throwable
    (a trap) never gets there: ``join`` returns and ``main`` exits with status 1,
    as the launcher does for an uncaught exception in ``main``.
    """
    exit_ = pool.method("java/lang/System", "exit", "(I)V")
    init = bytes((0x2A, 0xB7)) + _u2(pool.method("java/lang/Object", "<init>", "()V")) + bytes((0xB1,))
    run = bytes((0xB8,)) + _u2(pool.method(class_name, entry_name, "()V")) + bytes((0x03, 0xB8)) + _u2(exit_) + bytes((0xB1,))
    code = _Code("main")
    thread = "java/lang/Thread"
    code.op(0xBB); code.raw(_u2(pool.klass(thread))); code.op(0x59, 0x01)
    code.op(0xBB); code.raw(_u2(pool.klass(class_name))); code.op(0x59, 0xB7); code.raw(_u2(pool.method(class_name, "<init>", "()V")))
    code.op(0x13); code.raw(_u2(pool.string("xax-entry")))
    code.op(0x14); code.raw(_u2(pool.long(ENTRY_STACK_BYTES)))
    code.op(0xB7); code.raw(_u2(pool.method(thread, "<init>", "(Ljava/lang/ThreadGroup;Ljava/lang/Runnable;Ljava/lang/String;J)V")))
    code.op(0x59, 0xB6); code.raw(_u2(pool.method(thread, "start", "()V")))  # dup; start
    code.op(0xB6); code.raw(_u2(pool.method(thread, "join", "()V")))
    code.op(0x04, 0xB8); code.raw(_u2(exit_))  # only after a trap
    code.op(0xB1)
    blob, frames = code.finish()
    return [
        _Method("<init>", "()V", init, 1, 1, (), (), (), access=0x0001),
        _Method("run", "()V", run, 2, 1, (), (), (), access=0x0001),
        _Method("main", "([Ljava/lang/String;)V", blob, 8, 1, frames, ("[Ljava/lang/String;",), ()),
    ]


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
            if offset == method.bare_frame:
                entries.extend(bytes((255,)) + _u2(delta) + _u2(0) + _u2(0))  # last: the trap
            elif previous < 0:
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
    return _u2(method.access) + _u2(pool.utf8(method.name)) + _u2(pool.utf8(method.descriptor)) + _u2(1) + code_attribute


def _class_file(
    class_name: str, methods: Sequence[_Method], pool: _Pool, fields: Sequence[tuple[str, str]] = (), interfaces: Sequence[str] = (),
) -> tuple[bytes, dict[str, int]]:
    """Return the class bytes and the file offset of each method's code array.

    ``fields`` are private static fields (name, descriptor)."""
    this_index = pool.klass(class_name)
    interface_indices = b"".join(_u2(pool.klass(name)) for name in interfaces)
    field_blobs = [_u2(0x000A) + _u2(pool.utf8(name)) + _u2(pool.utf8(descriptor)) + _u2(0) for name, descriptor in fields]
    super_index = pool.klass("java/lang/Object")
    source_name = pool.utf8("SourceFile")
    source_value = pool.utf8("XAX")
    method_blobs = [_serialize_method(method, pool) for method in methods]  # finalizes the pool
    head = b"\xca\xfe\xba\xbe" + _u2(0) + _u2(CLASS_MAJOR_VERSION) + _u2(pool.count) + bytes(pool.data)
    head += _u2(0x0031) + _u2(this_index) + _u2(super_index) + _u2(len(interfaces)) + interface_indices + _u2(len(field_blobs)) + b"".join(field_blobs) + _u2(len(method_blobs))
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
        parameters, returns = _signature(function, resolve)
        names[function.cid] = (name, _method_descriptor(parameters if name == "entry" else _internal_order(parameters), returns))
    pool = _Pool()
    needs: set[str] = set()
    methods = [_compile_method(function, names[function.cid][0], resolve, pool, class_name, names, needs) for function in functions]
    shared = {item.split(":", 1)[1] for item in needs if item.startswith("shared:")}
    needs -= {f"shared:{item}" for item in shared}
    if needs and target.identity != JVM_CLASSFILE_MEMORY_IDENTITY:
        fail("XAX.JVM.TARGET", target_object.cid.hex(), "JVM-MEMORY-PROFILE", JVM_CLASSFILE_MEMORY_IDENTITY.decode(), target.identity.decode("ascii", "replace"))
    methods.extend(_shared_methods(pool, shared, class_name))
    methods.extend(_memory_methods(pool, class_name, needs, _initial_memory(functions, resolve) if needs else _INITIAL_MEMORY))
    threaded = process_entry and target.identity == JVM_CLASSFILE_MEMORY_IDENTITY
    if threaded:
        methods.extend(_threaded_launcher(pool, class_name, "entry"))
    elif process_entry:
        methods.append(_main_method(pool, class_name, "entry"))
    fields = (("M", "[B"), ("H", "I")) if needs else ()
    class_bytes, code_offsets = _class_file(class_name, methods, pool, fields, ("java/lang/Runnable",) if threaded else ())
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


def run_jvm_jar(image: JvmImage, *, timeout: float = 120.0, java: str | None = None, stdin: bytes | None = None) -> subprocess.CompletedProcess:
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
        return subprocess.run([java, "-jar", jar], input=stdin, capture_output=True, timeout=timeout, check=False, env=env)
