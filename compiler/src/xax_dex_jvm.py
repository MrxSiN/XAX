"""JVM class files to one DEX file (ADR-259): XAX on ART with no native library.

The JVM class-file backend (``xax_jvm``, ADR-112) already lowers verified XAX
semantics to typed bytecode.  This module lowers those class files to DEX, the
format ART loads, so an Android app's XAX logic runs as ordinary DEX code: no
JNI, no shared object, no ``System.loadLibrary``.  It is a deterministic
compiler-generated transcoding of one artifact into another (UR-001); no
``d8`` or other external tool is involved.

Lowering (``jvm-to-dex-v1``):

* JVM local *i* and operand-stack slot *k* each get a fixed DEX register.  The
  stack slots come first (after a few scratch registers), the locals that are
  not parameters next, and the parameters last, where DEX requires them.  A
  long or double takes a register pair, exactly as it takes two JVM slots;
* each instruction becomes the DEX instruction with the same meaning on those
  registers; an operand whose register is beyond the instruction format's
  reach is copied through a scratch register (``move/16``).  ART's compiler
  (dex2oat) rebuilds SSA from the DEX code, so these copies cost nothing after
  installation-time compilation;
* the operand stack must be empty at every branch target (the backend's own
  invariant: every frame it writes has an empty stack), so no value crosses a
  merge in a stack register;
* array loads and stores pick the DEX form from the array's descriptor, which
  is tracked from method signatures, field and array types, casts, and the
  class file's ``StackMapTable``.

Classes are written with ``write_dex``: one DEX 039 file, every identifier
section sorted as the format requires, adler32 checksum and SHA-1 signature.
Debug information is not emitted.
"""

from __future__ import annotations

import hashlib
import struct
import zlib
from dataclasses import dataclass
from typing import Sequence

from xax_compiler import fail
from xax_dex import ACC_CONSTRUCTOR, ACC_PRIVATE, ACC_STATIC, ACC_SUPER, _mutf8, _uleb, _utf16_units

LOWERING_IDENTITY = "jvm-to-dex-v1"
NO_INDEX = 0xFFFFFFFF
_SCRATCH = 6  # registers reserved for operands a format cannot reach (three operands, each possibly wide)


# ---------------------------------------------------------------- DEX model


@dataclass(frozen=True)
class DexCode:
    """A method body: 16-bit code units, where a ``(kind, key)`` unit is a 16-bit index resolved by ``write_dex``.

    ``kind`` is ``string`` (key: text), ``type`` (descriptor), ``field`` (class, name, type), or
    ``method`` (class, name, return, parameters)."""

    registers: int
    ins: int
    outs: int
    units: tuple


@dataclass(frozen=True)
class DexFieldDef:
    name: str
    type: str
    access: int


@dataclass(frozen=True)
class DexMethodDef:
    name: str
    returns: str
    parameters: tuple[str, ...]
    access: int
    code: DexCode | None


@dataclass(frozen=True)
class DexClassDef:
    descriptor: str
    access: int
    superclass: str | None
    interfaces: tuple[str, ...] = ()
    fields: tuple[DexFieldDef, ...] = ()
    methods: tuple[DexMethodDef, ...] = ()


def _shorty(returns: str, parameters: Sequence[str]) -> str:
    return "".join("L" if item[0] in "L[" else item for item in (returns, *parameters))


def _direct(method: DexMethodDef) -> bool:
    return bool(method.access & (ACC_STATIC | ACC_PRIVATE | ACC_CONSTRUCTOR))


def write_dex(classes: Sequence[DexClassDef]) -> bytes:
    """One canonical DEX 039 file holding ``classes`` (a class's superclass and interfaces precede it)."""
    # S15e.6g.1 (ADR-349): the XAX writer program first; ``XAX_GENERAL_FRONTEND_DIFF=1`` compares it with this one.
    import os

    from xax_selfhost_dex_writer import write_dex_with_xax

    built = write_dex_with_xax(tuple(classes))
    if built is not None and os.environ.get("XAX_GENERAL_FRONTEND_DIFF") != "1":
        return built
    reference = _write_dex_python(classes)
    if built is not None and built != reference:
        raise AssertionError("S15e.6g DEX files disagree")
    return reference


def _write_dex_python(classes: Sequence[DexClassDef]) -> bytes:
    """The bootstrap's writer."""
    defined = [item.descriptor for item in classes]
    if len(set(defined)) != len(defined):
        fail("XAX.DEX.CLASS", ",".join(defined), "DEX-DUPLICATE-CLASS", "distinct classes", defined)
    strings: set[str] = set()
    types: set[str] = set()
    protos: set[tuple[str, tuple[str, ...]]] = set()
    fields: set[tuple[str, str, str]] = set()
    methods: set[tuple[str, str, str, tuple[str, ...]]] = set()

    def add_proto(returns: str, parameters: tuple[str, ...]) -> None:
        protos.add((returns, parameters))
        types.update((returns, *parameters))
        strings.add(_shorty(returns, parameters))

    def add_field(key) -> None:
        fields.add(key)
        types.update((key[0], key[2]))
        strings.add(key[1])

    def add_method(key) -> None:
        methods.add(key)
        types.add(key[0])
        strings.add(key[1])
        add_proto(key[2], key[3])

    for item in classes:
        types.update((item.descriptor, *item.interfaces, *((item.superclass,) if item.superclass else ())))
        for field in item.fields:
            add_field((item.descriptor, field.name, field.type))
        for method in item.methods:
            add_method((item.descriptor, method.name, method.returns, method.parameters))
            for unit in method.code.units if method.code else ():
                if isinstance(unit, tuple):
                    kind, key = unit
                    if kind == "string":
                        strings.add(key)
                    elif kind == "type":
                        types.add(key)
                    elif kind == "field":
                        add_field(key)
                    else:
                        add_method(key)
    strings.update(types)
    string_list = sorted(strings, key=_utf16_units)
    string_index = {value: index for index, value in enumerate(string_list)}
    type_list = sorted(types, key=lambda value: string_index[value])
    type_index = {value: index for index, value in enumerate(type_list)}
    proto_list = sorted(protos, key=lambda p: (type_index[p[0]], [type_index[t] for t in p[1]]))
    proto_index = {value: index for index, value in enumerate(proto_list)}
    field_list = sorted(fields, key=lambda f: (type_index[f[0]], string_index[f[1]], type_index[f[2]]))
    field_index = {value: index for index, value in enumerate(field_list)}
    method_list = sorted(methods, key=lambda m: (type_index[m[0]], string_index[m[1]], proto_index[(m[2], m[3])]))
    method_index = {value: index for index, value in enumerate(method_list)}
    for count, what in ((len(type_list), "types"), (len(proto_list), "prototypes"), (len(field_list), "fields"), (len(method_list), "methods")):
        if count > 0xFFFF:
            fail("XAX.DEX.LIMIT", what, "DEX-INDEX-CAPACITY", "<= 65535", count)

    def resolve(unit) -> int:
        if not isinstance(unit, tuple):
            return unit
        kind, key = unit
        index = {"string": string_index, "type": type_index, "field": field_index, "method": lambda k: method_index[k]}[kind]
        value = index(key) if callable(index) else index[key]
        if value > 0xFFFF:
            fail("XAX.DEX.LIMIT", str(key), "DEX-INDEX-UNIT", "<= 65535", value)
        return value

    header_size = 0x70
    offsets = {}
    cursor = header_size
    for name, size, count in (("string", 4, len(string_list)), ("type", 4, len(type_list)), ("proto", 12, len(proto_list)),
                              ("field", 8, len(field_list)), ("method", 8, len(method_list)), ("class", 32, len(classes))):
        offsets[name] = cursor if count else 0
        cursor += size * count
    data_off = cursor
    data = bytearray()

    def here() -> int:
        return data_off + len(data)

    def align() -> None:
        data.extend(b"\x00" * ((-here()) % 4))

    map_items: list[tuple[int, int, int]] = []
    # code items
    align()
    code_start, code_count, code_offset = here(), 0, {}
    for item in classes:
        for method in item.methods:
            if method.code is None:
                continue
            align()
            code_offset[(item.descriptor, method.name, method.returns, method.parameters)] = here()
            code = method.code
            units = [resolve(unit) for unit in code.units]
            data.extend(struct.pack("<HHHHII", code.registers, code.ins, code.outs, 0, 0, len(units)))
            data.extend(struct.pack(f"<{len(units)}H", *units))
            code_count += 1
    if code_count:
        map_items.append((0x2001, code_count, code_start))
    # type lists: prototype parameters and interfaces, shared when equal
    align()
    lists_start, list_offset = here(), {}
    for entries in sorted({p[1] for p in proto_list if p[1]} | {item.interfaces for item in classes if item.interfaces},
                          key=lambda entries: [type_index[t] for t in entries]):
        align()
        list_offset[entries] = here()
        data.extend(struct.pack("<I", len(entries)) + struct.pack(f"<{len(entries)}H", *(type_index[t] for t in entries)))
    if list_offset:
        map_items.append((0x1001, len(list_offset), lists_start))
    # string data
    strings_start, string_offset = here(), []
    for value in string_list:
        string_offset.append(here())
        data.extend(_uleb(len(_utf16_units(value))) + _mutf8(value) + b"\x00")
    if string_list:
        map_items.append((0x2002, len(string_list), strings_start))
    # class data
    class_data_start, class_data_offset = here(), {}
    for item in classes:
        statics = sorted((f for f in item.fields if f.access & ACC_STATIC), key=lambda f: field_index[(item.descriptor, f.name, f.type)])
        instances = sorted((f for f in item.fields if not f.access & ACC_STATIC), key=lambda f: field_index[(item.descriptor, f.name, f.type)])
        key = lambda m: method_index[(item.descriptor, m.name, m.returns, m.parameters)]  # noqa: E731
        direct = sorted((m for m in item.methods if _direct(m)), key=key)
        virtual = sorted((m for m in item.methods if not _direct(m)), key=key)
        if not (statics or instances or direct or virtual):
            continue
        class_data_offset[item.descriptor] = here()
        blob = bytearray(_uleb(len(statics)) + _uleb(len(instances)) + _uleb(len(direct)) + _uleb(len(virtual)))
        for group in (statics, instances):
            previous = 0
            for f in group:
                index = field_index[(item.descriptor, f.name, f.type)]
                blob += _uleb(index - previous) + _uleb(f.access)
                previous = index
        for group in (direct, virtual):
            previous = 0
            for m in group:
                index = key(m)
                blob += _uleb(index - previous) + _uleb(m.access) + _uleb(code_offset.get((item.descriptor, m.name, m.returns, m.parameters), 0))
                previous = index
        data.extend(blob)
    if class_data_offset:
        map_items.append((0x2000, len(class_data_offset), class_data_start))
    align()
    map_off = here()
    sections = [(0x0000, 1, 0)] + [(kind, count, offsets[name]) for kind, name, count in (
        (0x0001, "string", len(string_list)), (0x0002, "type", len(type_list)), (0x0003, "proto", len(proto_list)),
        (0x0004, "field", len(field_list)), (0x0005, "method", len(method_list)), (0x0006, "class", len(classes)),
    ) if count] + map_items + [(0x1000, 1, map_off)]
    sections.sort(key=lambda item: item[2])
    data.extend(struct.pack("<I", len(sections)) + b"".join(struct.pack("<HHII", kind, 0, count, offset) for kind, count, offset in sections))

    ids = bytearray()
    ids += b"".join(struct.pack("<I", offset) for offset in string_offset)
    ids += b"".join(struct.pack("<I", string_index[value]) for value in type_list)
    ids += b"".join(struct.pack("<III", string_index[_shorty(*p)], type_index[p[0]], list_offset.get(p[1], 0)) for p in proto_list)
    ids += b"".join(struct.pack("<HHI", type_index[f[0]], type_index[f[2]], string_index[f[1]]) for f in field_list)
    ids += b"".join(struct.pack("<HHI", type_index[m[0]], proto_index[(m[2], m[3])], string_index[m[1]]) for m in method_list)
    for item in classes:
        ids += struct.pack(
            "<IIIIIIII", type_index[item.descriptor], item.access, type_index[item.superclass] if item.superclass else NO_INDEX,
            list_offset.get(item.interfaces, 0), NO_INDEX, 0, class_data_offset.get(item.descriptor, 0), 0,
        )
    body = bytes(ids) + bytes(data)
    file_size = header_size + len(body)
    header = bytearray(b"dex\n039\x00" + bytes(24))
    header += struct.pack("<IIIIII", file_size, header_size, 0x12345678, 0, 0, map_off)
    for name, count in (("string", len(string_list)), ("type", len(type_list)), ("proto", len(proto_list)),
                        ("field", len(field_list)), ("method", len(method_list)), ("class", len(classes))):
        header += struct.pack("<II", count, offsets[name])
    header += struct.pack("<II", len(data), data_off)
    out = bytearray(header + body)
    out[12:32] = hashlib.sha1(bytes(out[32:])).digest()
    out[8:12] = struct.pack("<I", zlib.adler32(bytes(out[12:])))
    return bytes(out)


# ---------------------------------------------------------------- class files


@dataclass(frozen=True)
class _JvmMethod:
    access: int
    name: str
    descriptor: str
    max_stack: int
    max_locals: int
    code: bytes
    frames: dict  # branch target -> {local index: descriptor}


@dataclass(frozen=True)
class _JvmClass:
    access: int
    name: str
    superclass: str | None
    interfaces: tuple[str, ...]
    fields: tuple[tuple[int, str, str], ...]
    methods: tuple[_JvmMethod, ...]
    pool: tuple


def _parse_classfile(data: bytes) -> _JvmClass:
    pos = 0

    def take(size: int) -> bytes:
        nonlocal pos
        if pos + size > len(data):
            fail("XAX.DEX.CLASSFILE", "class", "DEX-CLASSFILE-TRUNCATED", pos + size, len(data))
        pos += size
        return data[pos - size:pos]

    u1 = lambda: take(1)[0]  # noqa: E731
    u2 = lambda: struct.unpack(">H", take(2))[0]  # noqa: E731
    u4 = lambda: struct.unpack(">I", take(4))[0]  # noqa: E731
    if u4() != 0xCAFEBABE:
        fail("XAX.DEX.CLASSFILE", "class", "DEX-CLASSFILE-MAGIC", "0xCAFEBABE", data[:4].hex())
    take(4)
    count = u2()
    pool: list = [None] * count
    index = 1
    while index < count:
        tag = u1()
        if tag == 1:
            pool[index] = ("utf8", take(u2()).decode("utf-8"))
        elif tag in (3, 4):
            pool[index] = ({3: "int", 4: "float"}[tag], u4())
        elif tag in (5, 6):
            pool[index] = ({5: "long", 6: "double"}[tag], struct.unpack(">Q", take(8))[0])
            index += 1
        elif tag in (7, 8):
            pool[index] = ({7: "class", 8: "string"}[tag], u2())
        elif tag in (9, 10, 11, 12):
            pool[index] = ({9: "field", 10: "method", 11: "imethod", 12: "nat"}[tag], u2(), u2())
        else:
            fail("XAX.DEX.CLASSFILE", "class", "DEX-CLASSFILE-POOL-TAG", "tags 1, 3-12", tag)
        index += 1
    utf8 = lambda i: pool[i][1]  # noqa: E731
    klass = lambda i: utf8(pool[i][1])  # noqa: E731
    access, this, super_index = u2(), klass(u2()), u2()
    interfaces = tuple(klass(u2()) for _ in range(u2()))

    def attributes():
        for _ in range(u2()):
            name, length = utf8(u2()), u4()
            yield name, take(length)

    fields = []
    for _ in range(u2()):
        field = (u2(), utf8(u2()), utf8(u2()))
        tuple(attributes())
        fields.append(field)
    methods = []
    for _ in range(u2()):
        flags, name, descriptor = u2(), utf8(u2()), utf8(u2())
        code = None
        for attribute, blob in attributes():
            if attribute == "Code":
                code = _parse_code(blob, pool, flags, name, descriptor, this)
        methods.append(code or _JvmMethod(flags, name, descriptor, 0, 0, b"", {}))
    tuple(attributes())
    return _JvmClass(access, this, klass(super_index) if super_index else None, interfaces, tuple(fields), tuple(methods), tuple(pool))


def _parse_code(blob: bytes, pool, flags: int, name: str, descriptor: str, this: str) -> _JvmMethod:
    max_stack, max_locals, length = struct.unpack_from(">HHI", blob, 0)
    code = blob[8:8 + length]
    pos = 8 + length
    if struct.unpack_from(">H", blob, pos)[0]:
        fail("XAX.DEX.CLASSFILE", name, "DEX-EXCEPTION-TABLE", "no exception handlers", "handlers")
    pos += 2
    frames: dict[int, dict[int, str]] = {}
    for _ in range(struct.unpack_from(">H", blob, pos)[0]):
        attribute, size = struct.unpack_from(">HI", blob, pos + 2)
        if pool[attribute][1] == "StackMapTable":
            frames = _stack_map(blob[pos + 8:pos + 8 + size], pool, _initial_locals(flags, name, descriptor, this))
        pos += 6 + size
    return _JvmMethod(flags, name, descriptor, max_stack, max_locals, code, frames)


def _descriptor_of(name: str) -> str:
    return name if name.startswith("[") else f"L{name};"


def _parameters(descriptor: str) -> tuple[tuple[str, ...], str]:
    close, items, index = descriptor.index(")"), [], 1
    while index < close:
        start = index
        while descriptor[index] == "[":
            index += 1
        index = descriptor.index(";", index) + 1 if descriptor[index] == "L" else index + 1
        items.append(descriptor[start:index])
    return tuple(items), descriptor[close + 1:]


def _initial_locals(flags: int, name: str, descriptor: str, this: str) -> dict[int, str]:
    locals_: dict[int, str] = {}
    slot = 0
    if not flags & ACC_STATIC:
        locals_[0] = _descriptor_of(this)
        slot = 1
    for item in _parameters(descriptor)[0]:
        locals_[slot] = item
        slot += 2 if item in ("J", "D") else 1
    return locals_


def _stack_map(blob: bytes, pool, initial: dict[int, str]) -> dict[int, dict[int, str]]:
    """Locals' descriptors at every frame (only frames with an empty stack: the backend's invariant)."""
    pos, offset, current = 2, -1, dict(initial)

    def verification() -> str | None:
        nonlocal pos
        tag = blob[pos]
        pos += 1
        if tag in (7, 8):
            index = struct.unpack_from(">H", blob, pos)[0]
            pos += 2
            return _descriptor_of(pool[pool[index][1]][1]) if tag == 7 else None
        return {1: "I", 2: "F", 3: "D", 4: "J"}.get(tag)

    def place(items) -> dict[int, str]:
        result, slot = {}, 0
        for item in items:
            if item is not None:
                result[slot] = item
            slot += 2 if item in ("J", "D") else 1
        return result

    def ordered(locals_: dict[int, str]) -> list:
        items, slot = [], 0
        while slot <= max(locals_, default=-1):
            item = locals_.get(slot)
            items.append(item)
            slot += 2 if item in ("J", "D") else 1
        return items

    frames = {}
    for _ in range(struct.unpack_from(">H", blob, 0)[0]):
        kind = blob[pos]
        pos += 1
        if kind < 64:
            delta = kind
        elif kind == 251:
            delta = struct.unpack_from(">H", blob, pos)[0]; pos += 2
        elif 248 <= kind <= 250:
            delta = struct.unpack_from(">H", blob, pos)[0]; pos += 2
            current = place(ordered(current)[:-(251 - kind)])
        elif 252 <= kind <= 254:
            delta = struct.unpack_from(">H", blob, pos)[0]; pos += 2
            current = place(ordered(current) + [verification() for _ in range(kind - 251)])
        elif kind == 255:
            delta, count = struct.unpack_from(">HH", blob, pos); pos += 4
            current = place([verification() for _ in range(count)])
            stack = struct.unpack_from(">H", blob, pos)[0]; pos += 2
            if stack:
                fail("XAX.DEX.CLASSFILE", "frame", "DEX-FRAME-STACK", "empty operand stack at every frame", stack)
        else:
            fail("XAX.DEX.CLASSFILE", "frame", "DEX-FRAME-STACK", "empty operand stack at every frame", kind)
        offset += delta + 1
        frames[offset] = dict(current)
    return frames


# ---------------------------------------------------------------- translation

_WIDE = ("J", "D")
_PRIMITIVE_KIND = {"I": "I", "Z": "I", "B": "I", "C": "I", "S": "I", "F": "F", "J": "J", "D": "D"}
_MOVE = {"I": 0x01, "F": 0x01, "J": 0x04, "D": 0x04, "A": 0x07}  # +1: /from16, +2: /16
_MOVE_RESULT = {"I": 0x0A, "F": 0x0A, "J": 0x0B, "D": 0x0B, "A": 0x0C}
_RETURN = {"I": 0x0F, "F": 0x0F, "J": 0x10, "D": 0x10, "A": 0x11}
# aget/aput/iget/iput/sget/sput variant by element or field descriptor (references: 2)
_VARIANT = {"I": 0, "F": 0, "J": 1, "D": 1, "Z": 3, "B": 4, "C": 5, "S": 6}
_AGET, _APUT, _IGET, _IPUT, _SGET, _SPUT = 0x44, 0x4B, 0x52, 0x59, 0x60, 0x67
_NO_FALLTHROUGH = frozenset({0xA7, 0xC8, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0, 0xB1, 0xBF})
_LOAD_KIND = {0: "I", 1: "J", 2: "F", 3: "D", 4: "A"}
# JVM binary operations -> (DEX opcode, result kind); shift counts are ints
_BINARY: dict[int, tuple[int, str]] = {}
for _i, _base in enumerate((0x60, 0x64, 0x68, 0x6C, 0x70)):  # add sub mul div rem
    for _k, (_kind_name, _dex) in enumerate((("I", 0x90), ("J", 0x9B), ("F", 0xA6), ("D", 0xAB))):
        _BINARY[_base + _k] = (_dex + _i, _kind_name)
_BINARY.update({0x78: (0x98, "I"), 0x79: (0xA3, "J"), 0x7A: (0x99, "I"), 0x7B: (0xA4, "J"), 0x7C: (0x9A, "I"), 0x7D: (0xA5, "J"),
                0x7E: (0x95, "I"), 0x7F: (0xA0, "J"), 0x80: (0x96, "I"), 0x81: (0xA1, "J"), 0x82: (0x97, "I"), 0x83: (0xA2, "J"),
                0x94: (0x31, "I"), 0x95: (0x2D, "I"), 0x96: (0x2E, "I"), 0x97: (0x2F, "I"), 0x98: (0x30, "I")})
# JVM negation and conversion -> (DEX opcode, result kind); DEX keeps the JVM's conversion order, 4 lower
_UNARY = {0x74: (0x7B, "I"), 0x75: (0x7D, "J"), 0x76: (0x7F, "F"), 0x77: (0x80, "D")}
_UNARY.update({op: (op - 4, kind) for op, kind in zip(range(0x85, 0x94), "JFDIFDIJDIJFIII")})
_INVERSE = {0x32: 0x33, 0x33: 0x32, 0x34: 0x35, 0x35: 0x34, 0x36: 0x37, 0x37: 0x36}
_INVERSE.update({op + 6: inverse + 6 for op, inverse in list(_INVERSE.items())})


def _kind(descriptor: str) -> str:
    return _PRIMITIVE_KIND.get(descriptor, "A")


def _size(kind: str) -> int:
    return 2 if kind in _WIDE else 1


def _length(code: bytes, pc: int) -> int:
    op = code[pc]
    if op in (0x10, 0x12, 0x15, 0x16, 0x17, 0x18, 0x19, 0x36, 0x37, 0x38, 0x39, 0x3A, 0xA9, 0xBC):
        return 2
    if op in (0x11, 0x13, 0x14, 0x84, 0xBB, 0xBD, 0xC0, 0xC1, 0xC6, 0xC7) or 0x99 <= op <= 0xA8 or 0xB2 <= op <= 0xB8:
        return 3
    if op in (0xB9, 0xBA, 0xC8):
        return 5
    if op == 0xC5:
        return 4
    if op == 0xC4:
        return 6 if code[pc + 1] == 0x84 else 4
    if op in (0xAA, 0xAB):
        base = (pc + 4) & ~3
        if op == 0xAA:
            low, high = struct.unpack_from(">ii", code, base + 4)
            return base + 12 + 4 * (high - low + 1) - pc
        return base + 8 + 8 * struct.unpack_from(">i", code, base + 4)[0] - pc
    return 1


def _switch(code: bytes, pc: int) -> tuple[int, list[tuple[int, int]]]:
    """``(default target, [(key, target)])`` of the tableswitch or lookupswitch at ``pc``."""
    base = (pc + 4) & ~3
    default = pc + struct.unpack_from(">i", code, base)[0]
    if code[pc] == 0xAA:
        low, high = struct.unpack_from(">ii", code, base + 4)
        return default, [(low + i, pc + struct.unpack_from(">i", code, base + 12 + 4 * i)[0]) for i in range(high - low + 1)]
    count = struct.unpack_from(">i", code, base + 4)[0]
    pairs = (struct.unpack_from(">ii", code, base + 8 + 8 * i) for i in range(count))
    return default, [(key, pc + offset) for key, offset in pairs]


class _Retry(Exception):
    """The current register layout or branch width does not fit; translate again with more room."""


class _Method:
    """One JVM method lowered to DEX code (the register layout is in the module docstring)."""

    def __init__(self, cls: _JvmClass, method: _JvmMethod, rename: dict[str, str], scratch: int, long_branches: bool) -> None:
        self.cls, self.method, self.rename, self.long = cls, method, rename, long_branches
        self.where = f"{cls.name}.{method.name}{method.descriptor}"
        parameters, _ = _parameters(method.descriptor)
        self.ins = (0 if method.access & ACC_STATIC else 1) + sum(_size(_kind(p)) for p in parameters)
        self.scratch = scratch
        self.free_base = scratch + method.max_stack
        self.param_base = self.free_base + method.max_locals - self.ins
        self.registers = scratch + method.max_stack + method.max_locals
        self.units: list = []
        self.stack: list[tuple[str, str | None]] = []
        self.locals = _initial_locals(method.access, method.name, method.descriptor, cls.name)
        self.labels: dict[int, int] = {}
        self.fixups: list[tuple[int, int, int, int]] = []  # (instruction unit, offset unit, target pc, width)
        self.payloads: list[tuple[int, int, list[tuple[int, int]]]] = []
        self.outs = 0
        self.scratch_used = 0
        self._next = 0

    # registers ------------------------------------------------------------
    def local(self, index: int) -> int:
        return self.param_base + index if index < self.ins else self.free_base + index - self.ins

    def depth(self) -> int:
        return sum(_size(kind) for kind, _ in self.stack)

    def push(self, kind: str, descriptor: str | None = None) -> int:
        register = self.scratch + self.depth()
        self.stack.append((kind, descriptor))
        if self.depth() > self.method.max_stack:
            fail("XAX.DEX.CLASSFILE", self.where, "DEX-STACK-DEPTH", self.method.max_stack, self.depth())
        return register

    def pop(self) -> tuple[int, str, str | None]:
        if not self.stack:
            fail("XAX.DEX.CLASSFILE", self.where, "DEX-STACK-UNDERFLOW", "an operand", "empty stack")
        kind, descriptor = self.stack.pop()
        return self.scratch + self.depth(), kind, descriptor

    def begin(self) -> list:
        self._next = 0
        return []

    def _scratch(self, kind: str) -> int:
        register = self._next
        self._next += _size(kind)
        if self._next > self.scratch:
            raise _Retry
        self.scratch_used = max(self.scratch_used, self._next)
        return register

    def src(self, register: int, kind: str, limit: int) -> int:
        if register <= limit:
            return register
        staged = self._scratch(kind)
        self.move(staged, register, kind)
        return staged

    def dst(self, register: int, kind: str, limit: int, after: list) -> int:
        if register <= limit:
            return register
        staged = self._scratch(kind)
        after.append((register, staged, kind))
        return staged

    def end(self, after: list) -> None:
        for register, staged, kind in after:
            self.move(register, staged, kind)

    def move(self, destination: int, source: int, kind: str) -> None:
        if destination == source:
            return
        op = _MOVE[kind]
        if destination < 16 and source < 16:
            self.units.append((source << 12) | (destination << 8) | op)
        elif destination < 256:
            self.units += [(destination << 8) | (op + 1), source]
        else:
            self.units += [op + 2, destination, source]

    # emission -------------------------------------------------------------
    def const(self, register: int, value: int, kind: str) -> None:
        after = self.begin()
        if kind in _WIDE:
            value &= (1 << 64) - 1
            value = value - (1 << 64) if value >> 63 else value
            r = self.dst(register, kind, 255, after)
            if -0x8000 <= value < 0x8000:
                self.units += [(r << 8) | 0x16, value & 0xFFFF]
            elif -(1 << 31) <= value < (1 << 31):
                self.units += [(r << 8) | 0x17, value & 0xFFFF, (value >> 16) & 0xFFFF]
            elif value & 0xFFFFFFFFFFFF == 0:
                self.units += [(r << 8) | 0x19, (value >> 48) & 0xFFFF]
            else:
                self.units += [(r << 8) | 0x18, *((value >> shift) & 0xFFFF for shift in (0, 16, 32, 48))]
        else:
            value &= 0xFFFFFFFF
            value = value - (1 << 32) if value >> 31 else value
            if -8 <= value < 8 and register < 16:
                self.units.append(((value & 0xF) << 12) | (register << 8) | 0x12)
            else:
                r = self.dst(register, kind, 255, after)
                if -0x8000 <= value < 0x8000:
                    self.units += [(r << 8) | 0x13, value & 0xFFFF]
                elif value & 0xFFFF == 0:
                    self.units += [(r << 8) | 0x15, (value >> 16) & 0xFFFF]
                else:
                    self.units += [(r << 8) | 0x14, value & 0xFFFF, (value >> 16) & 0xFFFF]
        self.end(after)

    def x21c(self, op: int, register: int, kind: str, reference, write: bool) -> None:
        after = self.begin()
        r = self.dst(register, kind, 255, after) if write else self.src(register, kind, 255)
        self.units += [(r << 8) | op, reference]
        self.end(after)

    def x11x(self, op: int, register: int, kind: str, write: bool = False) -> None:
        after = self.begin()
        r = self.dst(register, kind, 255, after) if write else self.src(register, kind, 255)
        self.units.append((r << 8) | op)
        self.end(after)

    def x12x(self, op: int, a: int, a_kind: str, b: int, b_kind: str, reference=None, a_written: bool = True) -> None:
        after = self.begin()
        rb = self.src(b, b_kind, 15)
        ra = self.dst(a, a_kind, 15, after) if a_written else self.src(a, a_kind, 15)
        self.units.append((rb << 12) | (ra << 8) | op)
        if reference is not None:
            self.units.append(reference)
        self.end(after)

    def x23x(self, op: int, a: int, a_kind: str, b: int, b_kind: str, c: int, c_kind: str, a_written: bool = True) -> None:
        after = self.begin()
        rb, rc = self.src(b, b_kind, 255), self.src(c, c_kind, 255)
        ra = self.dst(a, a_kind, 255, after) if a_written else self.src(a, a_kind, 255)
        self.units += [(ra << 8) | op, (rc << 8) | rb]
        self.end(after)

    def branch(self, op: int, operands: tuple[tuple[int, str], ...], target: int) -> None:
        self.begin()
        if len(operands) == 1:
            first = (self.src(*operands[0], 255) << 8) | op
        else:
            a, b = (self.src(register, kind, 15) for register, kind in operands)
            first = (b << 12) | (a << 8) | op
        if self.long:  # the inverted test jumps over a goto/32
            self.units += [(first & ~0xFF) | _INVERSE[op], 5]
            self.goto(target)
        else:
            self.fixups.append((len(self.units), len(self.units) + 1, target, 16))
            self.units += [first, 0]

    def goto(self, target: int) -> None:
        if self.long:
            self.fixups.append((len(self.units), len(self.units) + 1, target, 32))
            self.units += [0x2A, 0, 0]
        else:
            self.fixups.append((len(self.units), len(self.units) + 1, target, 16))
            self.units += [0x29, 0]

    # references -----------------------------------------------------------
    def descriptor(self, descriptor: str) -> str:
        out, index = [], 0
        while index < len(descriptor):
            if descriptor[index] == "L":
                end = descriptor.index(";", index)
                name = descriptor[index + 1:end]
                out.append(f"L{self.rename.get(name, name)};")
                index = end + 1
            else:
                out.append(descriptor[index])
                index += 1
        return "".join(out)

    def class_type(self, name: str) -> str:
        return self.descriptor(_descriptor_of(name))

    def member(self, index: int) -> tuple[str, str, str]:
        pool = self.cls.pool
        _tag, owner, name_type = pool[index]
        _nat, name, descriptor = pool[name_type]
        return pool[pool[owner][1]][1], pool[name][1], pool[descriptor][1]

    def pool_class(self, index: int) -> str:
        return self.class_type(self.cls.pool[self.cls.pool[index][1]][1])

    # translation ----------------------------------------------------------
    def translate(self) -> DexCode:
        code, frames = self.method.code, self.method.frames
        pcs, targets = [], set()
        pc = 0
        while pc < len(code):
            pcs.append(pc)
            op = code[pc]
            if 0x99 <= op <= 0xA7 or op in (0xC6, 0xC7):
                targets.add(pc + struct.unpack_from(">h", code, pc + 1)[0])
            elif op == 0xC8:
                targets.add(pc + struct.unpack_from(">i", code, pc + 1)[0])
            elif op in (0xAA, 0xAB):
                default, cases = _switch(code, pc)
                targets.update((default, *(target for _key, target in cases)))
            elif op in (0xA8, 0xA9, 0xBA):
                fail("XAX.DEX.CLASSFILE", self.where, "DEX-UNSUPPORTED-INSTRUCTION", "no jsr, ret, or invokedynamic", hex(op))
            pc += _length(code, pc)
        reachable = True
        for pc in pcs:
            if pc in targets:
                if reachable and self.stack:
                    fail("XAX.DEX.CLASSFILE", self.where, "DEX-STACK-AT-TARGET", "empty operand stack at a branch target", pc)
                self.stack, reachable = [], True
                if pc in frames:
                    self.locals = dict(frames[pc])
            self.labels[pc] = len(self.units)
            if reachable:  # code no branch reaches is never lowered
                self.instruction(code, pc)
                reachable = code[pc] not in _NO_FALLTHROUGH
        return self.finish()

    def finish(self) -> DexCode:
        units = self.units
        for start, field, target, width in self.fixups:
            delta = self.labels[target] - start
            if width == 16:
                if not -0x8000 <= delta < 0x8000:
                    raise _Retry
                units[field] = delta & 0xFFFF
            else:
                units[field], units[field + 1] = delta & 0xFFFF, (delta >> 16) & 0xFFFF
        for start, field, cases in self.payloads:
            if len(units) % 2:
                units.append(0)  # nop: a payload starts 4-byte aligned
            delta = len(units) - start
            units[field], units[field + 1] = delta & 0xFFFF, (delta >> 16) & 0xFFFF
            keys = [key for key, _target in cases]
            if _dense(keys):
                units += [0x0100, len(keys), keys[0] & 0xFFFF, (keys[0] >> 16) & 0xFFFF]
            else:
                units += [0x0200, len(keys), *(part for key in keys for part in (key & 0xFFFF, (key >> 16) & 0xFFFF))]
            units += [part for _key, target in cases for part in ((self.labels[target] - start) & 0xFFFF, ((self.labels[target] - start) >> 16) & 0xFFFF)]
        return DexCode(self.registers, self.ins, self.outs, tuple(units))

    def rearrange(self, take: int, order: tuple[int, ...]) -> None:
        """The JVM's dup_x/dup2/swap forms: the top ``take`` entries, copied out, pushed back in ``order``."""
        entries = self.stack[-take:]
        del self.stack[-take:]
        position = self.scratch + self.depth()
        self.begin()
        staged = []
        for kind, descriptor in entries:
            register = self._scratch(kind)
            self.move(register, position, kind)
            staged.append(register)
            position += _size(kind)
        for index in order:
            self.move(self.push(*entries[index]), staged[index], entries[index][0])

    def invoke(self, op: int, index: int) -> None:
        owner, name, descriptor = self.member(index)
        parameters, result = _parameters(descriptor)
        receiver = op != 0xB8
        for _ in range(len(parameters) + receiver):
            self.pop()
        first, count = self.scratch + self.depth(), receiver + sum(_size(_kind(p)) for p in parameters)
        if op == 0xB7:
            dex = 0x76 if name == "<init>" or owner == self.cls.name else 0x75  # direct, or super
        else:
            dex = {0xB6: 0x74, 0xB8: 0x77, 0xB9: 0x78}[op]
        if count > 255:
            fail("XAX.DEX.LIMIT", self.where, "DEX-INVOKE-ARGUMENTS", "<= 255 argument registers", count)
        reference = ("method", (self.class_type(owner), name, self.descriptor(result), tuple(self.descriptor(p) for p in parameters)))
        self.units += [(count << 8) | dex, reference, first if count else 0]
        self.outs = max(self.outs, count)
        if result != "V":
            kind = _kind(result)
            self.x11x(_MOVE_RESULT[kind], self.push(kind, self.descriptor(result) if kind == "A" else None), kind, write=True)

    def array_element(self, array_descriptor: str | None, op: int, base: int) -> str:
        if op - base == 5:  # baload/bastore: byte[] or boolean[]
            if array_descriptor not in ("[B", "[Z"):
                fail("XAX.DEX.CLASSFILE", self.where, "DEX-ARRAY-TYPE", "a known byte[] or boolean[]", array_descriptor)
            return array_descriptor[1]
        if op - base == 4:
            return array_descriptor[1:] if array_descriptor else "Ljava/lang/Object;"
        return "IJFD..CS"[op - base]

    def instruction(self, code: bytes, pc: int) -> None:  # noqa: C901 (one table of JVM instructions)
        op = code[pc]
        u1 = lambda offset: code[pc + offset]  # noqa: E731
        u2 = lambda offset: struct.unpack_from(">H", code, pc + offset)[0]  # noqa: E731
        s1 = lambda offset: struct.unpack_from(">b", code, pc + offset)[0]  # noqa: E731
        s2 = lambda offset: struct.unpack_from(">h", code, pc + offset)[0]  # noqa: E731
        pool = self.cls.pool
        wide_operand = op == 0xC4
        inner = u1(1) if wide_operand else op
        if op == 0x00:
            return None
        if op == 0x01:
            return self.const(self.push("A"), 0, "I")
        if 0x02 <= op <= 0x08:
            return self.const(self.push("I"), op - 0x03, "I")
        if op in (0x09, 0x0A):
            return self.const(self.push("J"), op - 0x09, "J")
        if 0x0B <= op <= 0x0D:
            return self.const(self.push("F"), (0, 0x3F800000, 0x40000000)[op - 0x0B], "F")
        if op in (0x0E, 0x0F):
            return self.const(self.push("D"), (0, 0x3FF0000000000000)[op - 0x0E], "D")
        if op in (0x10, 0x11):
            return self.const(self.push("I"), s1(1) if op == 0x10 else s2(1), "I")
        if op in (0x12, 0x13, 0x14):
            entry = pool[u1(1) if op == 0x12 else u2(1)]
            if entry[0] in ("int", "float", "long", "double"):
                kind = {"int": "I", "float": "F", "long": "J", "double": "D"}[entry[0]]
                return self.const(self.push(kind), entry[1], kind)
            if entry[0] == "string":
                return self.x21c(0x1A, self.push("A", "Ljava/lang/String;"), "A", ("string", pool[entry[1]][1]), True)
            if entry[0] == "class":
                return self.x21c(0x1C, self.push("A", "Ljava/lang/Class;"), "A", ("type", self.class_type(pool[entry[1]][1])), True)
            fail("XAX.DEX.CLASSFILE", self.where, "DEX-LDC-CONSTANT", "int, float, long, double, String, or class", entry[0])
        if 0x15 <= inner <= 0x19 or 0x1A <= op <= 0x2D:
            if wide_operand:
                kind, index = _LOAD_KIND[inner - 0x15], u2(2)
            elif op <= 0x19:
                kind, index = _LOAD_KIND[op - 0x15], u1(1)
            else:
                kind, index = _LOAD_KIND[(op - 0x1A) // 4], (op - 0x1A) % 4
            descriptor = self.locals.get(index) if kind == "A" else None
            return self.move(self.push(kind, descriptor), self.local(index), kind)
        if 0x36 <= inner <= 0x3A or 0x3B <= op <= 0x4E:
            index = u2(2) if wide_operand else u1(1) if op <= 0x3A else (op - 0x3B) % 4
            register, kind, descriptor = self.pop()
            self.locals[index] = descriptor if kind == "A" else kind
            return self.move(self.local(index), register, kind)
        if 0x2E <= op <= 0x35:
            index, _k, _d = self.pop()
            array, _k, array_descriptor = self.pop()
            element = self.array_element(array_descriptor, op, 0x2E)
            kind = _kind(element)
            result = self.push(kind, element if kind == "A" else None)
            return self.x23x(_AGET + _VARIANT.get(element, 2), result, kind, array, "A", index, "I")
        if 0x4F <= op <= 0x56:
            value, kind, _d = self.pop()
            index, _k, _d = self.pop()
            array, _k, array_descriptor = self.pop()
            element = self.array_element(array_descriptor, op, 0x4F)
            return self.x23x(_APUT + _VARIANT.get(element, 2), value, kind, array, "A", index, "I", a_written=False)
        if op == 0x57:
            self.pop()
            return None
        if op == 0x58:
            _r, kind, _d = self.pop()
            if kind not in _WIDE:
                self.pop()
            return None
        if op == 0x59:
            register, kind, descriptor = self.pop()
            self.stack.append((kind, descriptor))
            return self.move(self.push(kind, descriptor), register, kind)
        wide = lambda depth: self.stack[-depth][0] in _WIDE  # noqa: E731
        if op == 0x5A:
            return self.rearrange(2, (1, 0, 1))
        if op == 0x5B:
            return self.rearrange(2, (1, 0, 1)) if wide(2) else self.rearrange(3, (2, 0, 1, 2))
        if op == 0x5C:
            return self.rearrange(1, (0, 0)) if wide(1) else self.rearrange(2, (0, 1, 0, 1))
        if op == 0x5D:
            return self.rearrange(2, (1, 0, 1)) if wide(1) else self.rearrange(3, (1, 2, 0, 1, 2))
        if op == 0x5E:
            if wide(1):
                return self.rearrange(2, (1, 0, 1)) if wide(2) else self.rearrange(3, (2, 0, 1, 2))
            return self.rearrange(3, (1, 2, 0, 1, 2)) if wide(3) else self.rearrange(4, (2, 3, 0, 1, 2, 3))
        if op == 0x5F:
            return self.rearrange(2, (1, 0))
        if op in _BINARY:
            dex, kind = _BINARY[op]
            b, b_kind, _d = self.pop()
            a, a_kind, _d = self.pop()
            return self.x23x(dex, self.push(kind), kind, a, a_kind, b, b_kind)
        if op in _UNARY:
            dex, kind = _UNARY[op]
            a, a_kind, _d = self.pop()
            return self.x12x(dex, self.push(kind), kind, a, a_kind)
        if inner == 0x84:
            index, amount = (u2(2), s2(4)) if wide_operand else (u1(1), s1(2))
            register = self.local(index)
            after = self.begin()
            constant = self._scratch("I")
            self.units += [(constant << 8) | 0x13, amount & 0xFFFF]
            source = self.src(register, "I", 255)
            target = self.dst(register, "I", 255, after)
            self.units += [(target << 8) | 0x90, (constant << 8) | source]
            return self.end(after)
        if 0x99 <= op <= 0x9E or op in (0xC6, 0xC7):
            register, kind, _d = self.pop()
            return self.branch({0xC6: 0x38, 0xC7: 0x39}.get(op, 0x38 + op - 0x99), ((register, kind),), pc + s2(1))
        if 0x9F <= op <= 0xA6:
            b, b_kind, _d = self.pop()
            a, a_kind, _d = self.pop()
            return self.branch(0x32 + op - (0x9F if op <= 0xA4 else 0xA5), ((a, a_kind), (b, b_kind)), pc + s2(1))
        if op in (0xA7, 0xC8):
            return self.goto(pc + (s2(1) if op == 0xA7 else struct.unpack_from(">i", code, pc + 1)[0]))
        if op in (0xAA, 0xAB):
            register, kind, _d = self.pop()
            default, cases = _switch(code, pc)
            if cases:
                self.begin()
                r = self.src(register, kind, 255)
                self.payloads.append((len(self.units), len(self.units) + 1, cases))
                self.units += [(r << 8) | (0x2B if _dense([key for key, _t in cases]) else 0x2C), 0, 0]
            return self.goto(default)
        if 0xAC <= op <= 0xB0:
            register, kind, _d = self.pop()
            return self.x11x(_RETURN[kind], register, kind)
        if op == 0xB1:
            self.units.append(0x0E)
            return None
        if 0xB2 <= op <= 0xB5:
            owner, name, descriptor = self.member(u2(1))
            reference = ("field", (self.class_type(owner), name, self.descriptor(descriptor)))
            kind, variant = _kind(descriptor), _VARIANT.get(descriptor, 2)
            held = self.descriptor(descriptor) if kind == "A" else None
            if op == 0xB2:
                return self.x21c(_SGET + variant, self.push(kind, held), kind, reference, True)
            if op == 0xB3:
                register, kind, _d = self.pop()
                return self.x21c(_SPUT + variant, register, kind, reference, False)
            if op == 0xB4:
                instance, _k, _d = self.pop()
                return self.x12x(_IGET + variant, self.push(kind, held), kind, instance, "A", reference)
            value, value_kind, _d = self.pop()
            instance, _k, _d = self.pop()
            return self.x12x(_IPUT + variant, value, value_kind, instance, "A", reference, a_written=False)
        if 0xB6 <= op <= 0xB9:
            return self.invoke(op, u2(1))
        if op == 0xBB:
            descriptor = self.pool_class(u2(1))
            return self.x21c(0x22, self.push("A", descriptor), "A", ("type", descriptor), True)
        if op in (0xBC, 0xBD):
            if op == 0xBC:
                descriptor = "[" + {4: "Z", 5: "C", 6: "F", 7: "D", 8: "B", 9: "S", 10: "I", 11: "J"}[u1(1)]
            else:
                descriptor = "[" + self.pool_class(u2(1))
            size, _k, _d = self.pop()
            return self.x12x(0x23, self.push("A", descriptor), "A", size, "I", ("type", descriptor))
        if op == 0xBE:
            array, _k, _d = self.pop()
            return self.x12x(0x21, self.push("I"), "I", array, "A")
        if op == 0xBF:
            register, _k, _d = self.pop()
            return self.x11x(0x27, register, "A")
        if op == 0xC0:
            descriptor = self.pool_class(u2(1))
            register, _k, _d = self.pop()
            self.push("A", descriptor)
            after = self.begin()
            r = self.dst(register, "A", 255, after)
            if r != register:
                self.move(r, register, "A")
            self.units += [(r << 8) | 0x1F, ("type", descriptor)]
            return self.end(after)
        if op == 0xC1:
            descriptor = self.pool_class(u2(1))
            register, _k, _d = self.pop()
            return self.x12x(0x20, self.push("I"), "I", register, "A", ("type", descriptor))
        if op in (0xC2, 0xC3):
            register, _k, _d = self.pop()
            return self.x11x(0x1D if op == 0xC2 else 0x1E, register, "A")
        fail("XAX.DEX.CLASSFILE", self.where, "DEX-UNSUPPORTED-INSTRUCTION", "a supported JVM instruction", hex(op))


def _dense(keys: list[int]) -> bool:
    return bool(keys) and keys == list(range(keys[0], keys[0] + len(keys)))


def _method_access(access: int, name: str) -> int:
    flags = access & 0x1DDF  # public private protected static final bridge varargs native abstract strict synthetic
    if access & 0x0020 and not access & 0x0100:
        flags |= 0x20000  # ACC_DECLARED_SYNCHRONIZED
    return flags | (ACC_CONSTRUCTOR if name in ("<init>", "<clinit>") else 0)


def _translate_method(cls: _JvmClass, method: _JvmMethod, rename: dict[str, str]) -> DexMethodDef:
    parameters, result = _parameters(method.descriptor)
    lowering = _Method(cls, method, rename, _SCRATCH, False)
    code = None
    if method.code:
        try:
            lowering.translate()
        except _Retry:
            lowering = _Method(cls, method, rename, _SCRATCH, True)
            lowering.translate()
        # Again with only the scratch registers the first pass used: lower registers only need fewer copies.
        code = _Method(cls, method, rename, lowering.scratch_used, lowering.long).translate()
    return DexMethodDef(method.name, lowering.descriptor(result), tuple(lowering.descriptor(p) for p in parameters), _method_access(method.access, method.name), code)


def translate_class(data: bytes, rename: dict[str, str] | None = None) -> DexClassDef:
    """One JVM class file as a DEX class; ``rename`` maps internal class names, everywhere they occur."""
    cls = _parse_classfile(data)
    probe = _Method(cls, _JvmMethod(ACC_STATIC, "<probe>", "()V", 0, 0, b"", {}), dict(rename or {}), 0, False)
    return DexClassDef(
        probe.class_type(cls.name), cls.access & ~ACC_SUPER, probe.class_type(cls.superclass) if cls.superclass else None,
        tuple(probe.class_type(name) for name in cls.interfaces),
        tuple(DexFieldDef(name, probe.descriptor(descriptor), access & 0x50DF) for access, name, descriptor in cls.fields),
        tuple(_translate_method(cls, method, probe.rename) for method in cls.methods),
    )


def merge_classes(primary: DexClassDef, *others: DexClassDef) -> DexClassDef:
    """``primary`` with the fields and methods of ``others`` (translated with their names renamed onto it)."""
    fields, methods = list(primary.fields), list(primary.methods)
    for other in others:
        fields += other.fields
        methods += other.methods
    if len({(f.name, f.type) for f in fields}) != len(fields) or len({(m.name, m.returns, m.parameters) for m in methods}) != len(methods):
        fail("XAX.DEX.CLASS", primary.descriptor, "DEX-MERGE-DUPLICATE", "distinct members", "a duplicate member")
    return DexClassDef(primary.descriptor, primary.access, primary.superclass, primary.interfaces, tuple(fields), tuple(methods))


# ---------------------------------------------------------------- test tooling: ART on a device

# Not part of any artifact.  With ``XAX_JVM_DEX_ADB=1`` the JVM runners (``xax_jvm.run_jvm_calls``/``run_jvm_jar``)
# lower the program's class to DEX here and run it under ``dalvikvm64`` on the connected ``adb`` device, so every
# JVM test also checks this lowering on ART (ADR-259).  The call harness is the JVM one, loading the class from the
# class path instead of a JAR; it is compiled once with ``javac`` and ``d8`` (``ANDROID_BUILD_TOOLS``).
_DEVICE_HARNESS = r"""
import java.lang.reflect.*;
import java.io.*;
public final class XaxDexHarness {
  public static void main(String[] a) throws Exception {
    Class<?> c = Class.forName(a[0]);
    Method m = null;
    for (Method x : c.getDeclaredMethods()) if (x.getName().equals(a[1])) m = x;
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
_device_harness: list[bytes] = []


def device_art_requested() -> bool:
    import os

    return os.environ.get("XAX_JVM_DEX_ADB") == "1"


def _harness_dex() -> bytes:
    import os
    import shutil
    import subprocess
    import tempfile
    from pathlib import Path

    if not _device_harness:
        tools = Path(os.environ.get("ANDROID_BUILD_TOOLS", ""))
        javac = shutil.which("javac")
        if not javac or not (tools / "lib/d8.jar").exists():
            fail("XAX.DEX.HOST", "host", "DEX-HOST-TOOLS", "javac and ANDROID_BUILD_TOOLS/lib/d8.jar for the test harness", "missing")
        with tempfile.TemporaryDirectory(prefix="xax-dex-harness-") as directory:
            source = Path(directory) / "XaxDexHarness.java"
            source.write_text(_DEVICE_HARNESS, encoding="ascii")
            subprocess.run([javac, "--release", "11", "-d", directory, str(source)], check=True, capture_output=True)
            subprocess.run([shutil.which("java") or "java", "-cp", str(tools / "lib/d8.jar"), "com.android.tools.r8.D8", "--min-api", "28",
                            "--output", directory, str(Path(directory) / "XaxDexHarness.class")], check=True, capture_output=True)
            _device_harness.append((Path(directory) / "classes.dex").read_bytes())
    return _device_harness[0]


def run_on_device_art(class_bytes: bytes, main: str, arguments: Sequence[str] = (), stdin: bytes | None = None, *, harness: bool = False, timeout: float = 600.0):
    """Lower one class file to DEX and run ``main`` under ``dalvikvm64`` on the ``adb`` device (byte-exact streams)."""
    import os
    import subprocess
    import tempfile
    from pathlib import Path

    remote = f"/data/local/tmp/xax-dex-{os.getpid()}"
    env = {**os.environ, "MSYS_NO_PATHCONV": "1"}

    def adb(*args: str, capture: bool = True):
        return subprocess.run(["adb", *args], capture_output=capture, timeout=timeout, check=True, env=env).stdout

    with tempfile.TemporaryDirectory(prefix="xax-dex-") as directory:
        work = Path(directory)
        (work / "program.dex").write_bytes(write_dex([translate_class(class_bytes)]))
        (work / "stdin").write_bytes(stdin or b"")
        files = ["program.dex", "stdin"]
        if harness:
            (work / "harness.dex").write_bytes(_harness_dex())
            files.append("harness.dex")
        adb("shell", f"rm -rf {remote} && mkdir -p {remote}")
        for name in files:
            adb("push", str(work / name), f"{remote}/{name}")
    classpath = f"{remote}/program.dex" + (f":{remote}/harness.dex" if harness else "")
    quoted = " ".join(f"'{item}'" for item in arguments)
    adb("shell", f"cd {remote} && dalvikvm64 -cp {classpath} {main} {quoted} < stdin > stdout 2> stderr; echo $? > status")
    stdout, stderr = adb("exec-out", f"cat {remote}/stdout"), adb("exec-out", f"cat {remote}/stderr")
    status = int(adb("exec-out", f"cat {remote}/status").strip() or b"0")
    adb("shell", f"rm -rf {remote}")
    return subprocess.CompletedProcess(["dalvikvm64", main, *arguments], status, stdout, stderr)
