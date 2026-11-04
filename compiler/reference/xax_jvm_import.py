"""Deterministic JVM class-file importer: typed foreign declarations from JDK metadata (ADR-166, OI-32).

The input is class files: a JDK ``.jmod`` (``java.base.jmod``) or a JAR.  The
output is canonical XAX semantic state, the same ``jvm-*`` foreign declarations
that are otherwise written by hand (ADR-112, ADR-161–ADR-164).  The importer
loads no class and runs no Java.

Requests name members exactly:

* ``Owner.name(descriptor)`` — a method, or a constructor when ``name`` is ``<init>``;
* ``Owner.name:descriptor`` — a field read;
* ``Owner.name:descriptor=`` — a field write.

Each request resolves the way the JVM resolves a member reference: the owner
first, then its superclasses, then its superinterfaces.  It imports only if:

* the owner is a public class in an exported package (the module's
  unqualified ``exports``);
* the member is public and not the class initializer.  (Public synthetic
  bridges are real members and import when requested; ``class_requests``
  lists a class's API without them.)

What a class file does not say is imported conservatively (OI-32):

* **Effects.** Every member takes and returns one effect token (default:
  the I/O effect), so the calls stay in program order. Purity or another
  effect is a curated fact that the caller passes explicitly (``pure``,
  ``effects``).
* **Nulls.** References are nullable ``jvm-ref`` pointers. A null receiver
  or a Java exception ends the program, the existing foreign-member rule.
* **Callbacks.** A functional-interface parameter imports as a plain
  reference unless the caller asks for callbacks, in which case it imports as
  the interface's ``jvm_interface_entry_type`` (ADR-161).

A request that cannot be imported is refused with a reason in the report;
nothing is guessed.
"""

from __future__ import annotations

import io
import struct
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Mapping

from xax_android_sdk import JavaClassMetadata, JavaMemberMetadata, parse_classfile
from xax_compiler import (
    JVM_GETFIELD_ABI,
    JVM_GETSTATIC_ABI,
    JVM_INVOKEINTERFACE_ABI,
    JVM_INVOKESTATIC_ABI,
    JVM_INVOKESTATIC_INTERFACE_ABI,
    JVM_INVOKEVIRTUAL_ABI,
    JVM_NEW_ABI,
    JVM_PUTFIELD_ABI,
    JVM_PUTSTATIC_ABI,
    EffectDomain,
    FloatFormat,
    SemanticObject,
    bits_type,
    effect_type,
    float_type,
    foreign_function_symbol,
    jvm_interface_entry_type,
    opaque_identity_type,
)
from xax_jvm import REFERENCE_PREFIX, jvm_reference_type

IMPORTER_IDENTITY = "xax-jvm-classfile-import-v1"
ACC_PUBLIC, ACC_PROTECTED, ACC_STATIC, ACC_FINAL, ACC_INTERFACE, ACC_ABSTRACT, ACC_SYNTHETIC = 0x0001, 0x0004, 0x0008, 0x0010, 0x0200, 0x0400, 0x1000
_OBJECT_METHODS = frozenset({("equals", "(Ljava/lang/Object;)Z"), ("hashCode", "()I"), ("toString", "()Ljava/lang/String;")})
_PRIMITIVE = {"Z": 1, "B": 8, "C": 16, "S": 16, "I": 32, "J": 64}


class _ClassBytes:
    """Class files by internal name, with the packages a module exports unqualified."""

    def __init__(self, entries: Mapping[str, bytes], exported: frozenset[str] | None) -> None:
        self.entries = dict(entries)
        self.exported = exported  # None: every package (a plain JAR on the class path)


def _module_exports(data: bytes) -> frozenset[str]:
    """Unqualified ``exports`` of a ``module-info.class`` (the Module attribute)."""
    count = struct.unpack_from(">H", data, 8)[0]
    position, index, pool = 10, 1, {}
    while index < count:
        tag = data[position]
        if tag == 1:
            length = struct.unpack_from(">H", data, position + 1)[0]
            pool[index] = ("utf8", data[position + 3:position + 3 + length].decode("utf-8"))
            position += 3 + length
        elif tag in (7, 8, 16, 19, 20):
            pool[index] = (tag, struct.unpack_from(">H", data, position + 1)[0])
            position += 3
        elif tag == 15:
            position += 4
        elif tag in (5, 6):
            position, index = position + 9, index + 1
        else:
            position += 5
        index += 1
    utf8 = lambda i: pool[i][1]  # noqa: E731

    def skip_attributes(position: int) -> int:
        count, position = struct.unpack_from(">H", data, position)[0], position + 2
        for _ in range(count):
            position += 6 + struct.unpack_from(">I", data, position + 2)[0]
        return position

    position += 6  # access, this, super
    position += 2 + 2 * struct.unpack_from(">H", data, position)[0]  # interfaces
    for _table in range(2):  # fields, methods: module-info has none, but stay exact
        entries = struct.unpack_from(">H", data, position)[0]
        position += 2
        for _ in range(entries):
            position = skip_attributes(position + 6)
    exported: set[str] = set()
    count, position = struct.unpack_from(">H", data, position)[0], position + 2
    for _ in range(count):
        name = utf8(struct.unpack_from(">H", data, position)[0])
        length = struct.unpack_from(">I", data, position + 2)[0]
        body = position + 6
        if name == "Module":
            cursor = body + 6  # module name, flags, version
            cursor += 2 + 6 * struct.unpack_from(">H", data, cursor)[0]  # requires
            for _export in range(struct.unpack_from(">H", data, cursor)[0]):
                package, _flags, targets = struct.unpack_from(">HHH", data, cursor + 2)
                if targets == 0:
                    exported.add(utf8(pool[package][1]))
                cursor += 6 + 2 * targets
        position = body + length
    return frozenset(exported)


@dataclass
class JvmClassPath:
    """Class files to import from: ``.jmod`` modules and JARs, searched in order."""

    sources: list[_ClassBytes] = field(default_factory=list)
    _parsed: dict[str, JavaClassMetadata | None] = field(default_factory=dict)

    @classmethod
    def of(cls, *paths: str | Path) -> "JvmClassPath":
        classpath = cls()
        for path in paths:
            data = Path(path).read_bytes()
            module = data[:4] == b"JM\x01\x00"
            with zipfile.ZipFile(io.BytesIO(data[4:] if module else data)) as archive:
                prefix = "classes/" if module else ""
                entries = {
                    name[len(prefix):-len(".class")]: archive.read(name)
                    for name in archive.namelist() if name.startswith(prefix) and name.endswith(".class")
                }
            exported = _module_exports(entries.pop("module-info")) if "module-info" in entries else None
            classpath.sources.append(_ClassBytes(entries, exported))
        return classpath

    def metadata(self, name: str) -> JavaClassMetadata | None:
        if name not in self._parsed:
            data = next((source.entries[name] for source in self.sources if name in source.entries), None)
            self._parsed[name] = None if data is None else parse_classfile(data)
        return self._parsed[name]

    def accessible(self, name: str) -> bool:
        """A public class in an exported package."""
        metadata = self.metadata(name)
        if metadata is None or not metadata.access_flags & ACC_PUBLIC:
            return False
        package = name.rsplit("/", 1)[0] if "/" in name else ""
        source = next(source for source in self.sources if name in source.entries)
        return source.exported is None or package in source.exported

    def class_names(self) -> tuple[str, ...]:
        return tuple(sorted({name for source in self.sources for name in source.entries}))


@dataclass(frozen=True)
class JvmImport:
    declarations: dict[str, SemanticObject]  # request -> declaration
    objects: tuple[SemanticObject, ...]  # every type the declarations reference, then the declarations
    refused: dict[str, str]  # request -> reason

    @property
    def report(self) -> dict:
        return {"importer": IMPORTER_IDENTITY, "imported": sorted(self.declarations), "refused": dict(sorted(self.refused.items()))}


class _Refused(Exception):
    pass


def _split_descriptor(descriptor: str) -> tuple[list[str], str]:
    parameters, index = [], 1
    while descriptor[index] != ")":
        start = index
        while descriptor[index] == "[":
            index += 1
        index = descriptor.index(";", index) + 1 if descriptor[index] == "L" else index + 1
        parameters.append(descriptor[start:index])
    return parameters, descriptor[index + 1:]


class _Importer:
    def __init__(self, classpath: JvmClassPath, pure: frozenset[str], effects: Mapping[str, SemanticObject], callbacks: bool) -> None:
        self.classpath, self.pure, self.effects, self.callbacks = classpath, pure, effects, callbacks
        self.types: dict[bytes, SemanticObject] = {}

    def _keep(self, *objects: SemanticObject) -> SemanticObject:
        for item in objects:
            self.types.setdefault(item.cid, item)
        return objects[-1]

    def _abstract_methods(self, name: str, seen: set[str]) -> set[tuple[str, str]]:
        metadata = self.classpath.metadata(name)
        if metadata is None or name in seen:
            return set()
        seen.add(name)
        own = {(m.name, m.descriptor) for m in metadata.methods if m.access_flags & ACC_ABSTRACT}
        defaults = {(m.name, m.descriptor) for m in metadata.methods if not m.access_flags & (ACC_ABSTRACT | ACC_STATIC)}
        inherited = set().union(*(self._abstract_methods(item, seen) for item in metadata.interfaces)) if metadata.interfaces else set()
        return (own | (inherited - defaults)) - _OBJECT_METHODS

    def _value(self, descriptor: str, *, parameter: bool) -> SemanticObject:
        if descriptor in _PRIMITIVE:
            return self._keep(bits_type(_PRIMITIVE[descriptor]))
        if descriptor in ("F", "D"):
            return self._keep(float_type(FloatFormat.BINARY32 if descriptor == "F" else FloatFormat.BINARY64))
        if parameter and self.callbacks and descriptor.startswith("L"):
            interface = descriptor[1:-1]
            metadata = self.classpath.metadata(interface)
            if metadata is not None and metadata.access_flags & ACC_INTERFACE:
                abstract = self._abstract_methods(interface, set())
                if len(abstract) == 1:
                    method, signature = next(iter(abstract))
                    member = f"{method}{signature}".encode()
                    element = opaque_identity_type(b"code-entry:jvm-interface:" + interface.encode() + b"." + member)
                    return self._keep(element, jvm_interface_entry_type(interface.encode(), member))
        element = opaque_identity_type(REFERENCE_PREFIX + descriptor.encode())
        return self._keep(element, jvm_reference_type(descriptor.encode()))

    def _owner(self, owner: str) -> JavaClassMetadata:
        if not self.classpath.accessible(owner):
            raise _Refused("owner not a public class in an exported package" if self.classpath.metadata(owner) else "owner not found")
        return self.classpath.metadata(owner)

    def _find(self, owner: str, kind: str, name: str, descriptor: str) -> tuple[JavaClassMetadata, JavaMemberMetadata]:
        """JVM member resolution: the class, its superclasses, then superinterfaces."""
        pending, seen, interfaces = [owner], set(), []
        while pending:
            current = pending.pop(0)
            metadata = self.classpath.metadata(current)
            if metadata is None or current in seen:
                continue
            seen.add(current)
            for member in (metadata.methods if kind == "method" else metadata.fields):
                if member.name == name and member.descriptor == descriptor:
                    return metadata, member
            if name == "<init>":
                break  # constructors are not inherited
            if metadata.superclass:
                pending.insert(0, metadata.superclass)
            interfaces.extend(metadata.interfaces)
            if not pending:
                pending, interfaces = interfaces, []
        raise _Refused("member not found")

    def declaration(self, request: str) -> SemanticObject:
        owner, _dot, member = request.partition(".")  # internal names have no dots
        if not member:
            raise _Refused("malformed request")
        metadata = self._owner(owner)
        effect = None if request in self.pure else self.effects.get(request, None) or self._keep(effect_type(EffectDomain.IO, 0))
        if effect is not None:
            self._keep(effect)
        tail = (effect,) if effect is not None else ()
        library = owner.encode("ascii")
        interface = bool(metadata.access_flags & ACC_INTERFACE)
        if "(" in member:
            name, descriptor = member[:member.index("(")], member[member.index("("):]
            declaring, found = self._find(owner, "method", name, descriptor)
            if not found.access_flags & ACC_PUBLIC or name == "<clinit>":
                raise _Refused("member not public")
            parameters, result = _split_descriptor(descriptor)
            inputs = [self._value(item, parameter=True) for item in parameters]
            outputs = [] if result == "V" else [self._value(result, parameter=False)]
            if name == "<init>":
                if metadata.access_flags & (ACC_ABSTRACT | ACC_INTERFACE):
                    raise _Refused("constructor of an abstract class or interface")
                outputs = [self._value(f"L{owner};", parameter=False)]
                abi = JVM_NEW_ABI
            elif found.access_flags & ACC_STATIC:
                if declaring.internal_name != owner and declaring.access_flags & ACC_INTERFACE:
                    raise _Refused("static interface methods are not inherited")
                abi = JVM_INVOKESTATIC_INTERFACE_ABI if interface else JVM_INVOKESTATIC_ABI
            else:
                inputs.insert(0, self._value(f"L{owner};", parameter=False))
                abi = JVM_INVOKEINTERFACE_ABI if interface else JVM_INVOKEVIRTUAL_ABI
            return foreign_function_symbol(library, member.encode("ascii"), (*inputs, *tail), (*outputs, *tail), abi=abi)
        write = member.endswith("=")
        field_member = member[:-1] if write else member
        if ":" not in field_member:
            raise _Refused("malformed request")
        name, descriptor = field_member.split(":", 1)
        _declaring, found = self._find(owner, "field", name, descriptor)
        if not found.access_flags & ACC_PUBLIC:
            raise _Refused("member not public")
        value = self._value(descriptor, parameter=False)
        static = bool(found.access_flags & ACC_STATIC)
        if write:
            if found.access_flags & ACC_FINAL:
                raise _Refused("final field")
            if static:
                return foreign_function_symbol(library, field_member.encode("ascii"), (value, *tail), tail, abi=JVM_PUTSTATIC_ABI)
            receiver = self._value(f"L{owner};", parameter=False)
            return foreign_function_symbol(library, field_member.encode("ascii"), (receiver, value, *tail), tail, abi=JVM_PUTFIELD_ABI)
        if static:
            return foreign_function_symbol(library, field_member.encode("ascii"), tail, (value, *tail), abi=JVM_GETSTATIC_ABI)
        receiver = self._value(f"L{owner};", parameter=False)
        return foreign_function_symbol(library, field_member.encode("ascii"), (receiver, *tail), (value, *tail), abi=JVM_GETFIELD_ABI)


def import_jvm_members(
    classpath: JvmClassPath, requests: Iterable[str], *, pure: Iterable[str] = (),
    effects: Mapping[str, SemanticObject] | None = None, callbacks: bool = False,
) -> JvmImport:
    """Import each request (``Owner.name(desc)``, ``Owner.name:desc``, ``Owner.name:desc=``)."""
    importer = _Importer(classpath, frozenset(pure), dict(effects or {}), callbacks)
    declarations, refused = {}, {}
    for request in sorted(set(requests)):
        try:
            declarations[request] = importer.declaration(request)
        except _Refused as reason:
            refused[request] = str(reason)
    return JvmImport(declarations, (*importer.types.values(), *declarations.values()), refused)


def class_requests(classpath: JvmClassPath, owner: str) -> tuple[str, ...]:
    """A class's declared API as requests: public and protected methods, constructors, field reads, and field writes."""
    metadata = classpath.metadata(owner)
    if metadata is None:
        return ()
    api = lambda item: item.access_flags & (ACC_PUBLIC | ACC_PROTECTED) and not item.access_flags & ACC_SYNTHETIC  # noqa: E731
    requests = [f"{owner}.{m.name}{m.descriptor}" for m in metadata.methods if m.name != "<clinit>" and api(m)]
    for item in filter(api, metadata.fields):
        requests.append(f"{owner}.{item.name}:{item.descriptor}")
        if not item.access_flags & ACC_FINAL:
            requests.append(f"{owner}.{item.name}:{item.descriptor}=")
    return tuple(requests)
