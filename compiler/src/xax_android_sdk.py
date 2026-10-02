"""Deterministic Java/Android SDK metadata import for XAX.

This module parses class-file/JAR metadata and Android ``api-versions.xml``
directly.  Imported classes/members become compact content-addressed XAX target
carriers.  It does not generate JNI calls, load classes, or add Java/Android
operations to the XAX kernel.
"""

from __future__ import annotations

from dataclasses import dataclass
import io
import struct
from typing import Iterable
import xml.etree.ElementTree as ET
import zipfile

from xax_compiler import SemanticObject, fail, target, uleb


CLASS_MAGIC = 0xCAFEBABE
ANDROID_SDK_CLASS_PREFIX = b"xax.android.sdk.class.v1\0"
ANDROID_SDK_MEMBER_PREFIX = b"xax.android.sdk.member.v1\0"


@dataclass(frozen=True, order=True)
class JavaMemberMetadata:
    kind: str
    name: str
    descriptor: str
    access_flags: int
    annotations: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.kind not in {"field", "method"}:
            raise ValueError("Java member kind must be field or method")
        if not self.name or "\x00" in self.name:
            raise ValueError("Java member name must be nonempty")
        if self.kind == "field":
            _validate_field_descriptor(self.descriptor)
        else:
            _validate_method_descriptor(self.descriptor)
        if tuple(sorted(set(self.annotations))) != self.annotations:
            raise ValueError("Java annotations must be sorted and unique")


@dataclass(frozen=True, order=True)
class JavaClassMetadata:
    internal_name: str
    superclass: str | None
    interfaces: tuple[str, ...]
    access_flags: int
    major_version: int
    minor_version: int
    annotations: tuple[str, ...]
    fields: tuple[JavaMemberMetadata, ...]
    methods: tuple[JavaMemberMetadata, ...]

    def __post_init__(self) -> None:
        _validate_internal_name(self.internal_name)
        if self.superclass is not None:
            _validate_internal_name(self.superclass)
        for item in self.interfaces:
            _validate_internal_name(item)
        if self.major_version < 45:
            raise ValueError("unsupported pre-Java-1.1 class version")
        if tuple(sorted(set(self.annotations))) != self.annotations:
            raise ValueError("Java annotations must be sorted and unique")
        if tuple(sorted(self.fields, key=lambda item: (item.name, item.descriptor, item.access_flags, item.annotations))) != self.fields:
            raise ValueError("Java fields must be canonical")
        if tuple(sorted(self.methods, key=lambda item: (item.name, item.descriptor, item.access_flags, item.annotations))) != self.methods:
            raise ValueError("Java methods must be canonical")


@dataclass(frozen=True, order=True)
class ApiVersion:
    since: int
    deprecated: int | None = None
    removed: int | None = None

    def __post_init__(self) -> None:
        if self.since < 1:
            raise ValueError("Android API since level must be positive")
        if self.deprecated is not None and self.deprecated < self.since:
            raise ValueError("Android API deprecation precedes introduction")
        if self.removed is not None and self.removed < self.since:
            raise ValueError("Android API removal precedes introduction")


@dataclass(frozen=True)
class AndroidApiProfile:
    min_sdk: int
    target_sdk: int
    compile_sdk: int
    device_api_min: int | None = None
    device_api_max: int | None = None

    def __post_init__(self) -> None:
        if not (1 <= self.min_sdk <= self.target_sdk <= self.compile_sdk):
            raise ValueError("Android API profile requires 1 <= minSdk <= targetSdk <= compileSdk")
        if self.device_api_min is not None and self.device_api_min < self.min_sdk:
            raise ValueError("device API minimum cannot be below minSdk")
        if self.device_api_max is not None:
            lower = self.min_sdk if self.device_api_min is None else self.device_api_min
            if self.device_api_max < lower:
                raise ValueError("device API maximum precedes device API minimum")


@dataclass(frozen=True)
class AndroidApiAvailabilityDecision:
    available: bool
    runtime_min: int
    runtime_max: int | None
    version: ApiVersion


@dataclass(frozen=True)
class AndroidApiVersions:
    classes: tuple[tuple[str, ApiVersion], ...]
    methods: tuple[tuple[str, str, ApiVersion], ...]
    fields: tuple[tuple[str, str, ApiVersion], ...]

    def class_version(self, internal_name: str) -> ApiVersion | None:
        return dict(self.classes).get(internal_name)

    def method_version(self, internal_name: str, name: str, descriptor: str) -> ApiVersion | None:
        return {(owner, signature): version for owner, signature, version in self.methods}.get((internal_name, name + descriptor))

    def field_version(self, internal_name: str, name: str) -> ApiVersion | None:
        return {(owner, field): version for owner, field, version in self.fields}.get((internal_name, name))


@dataclass(frozen=True)
class ImportedAndroidClass:
    metadata: JavaClassMetadata
    class_contract: SemanticObject
    member_contracts: tuple[SemanticObject, ...]


@dataclass(frozen=True)
class AndroidSdkImport:
    classes: tuple[ImportedAndroidClass, ...]

    @property
    def semantic_objects(self) -> tuple[SemanticObject, ...]:
        objects = {
            obj.cid: obj
            for imported in self.classes
            for obj in (imported.class_contract, *imported.member_contracts)
        }
        return tuple(objects[cid] for cid in sorted(objects))

    def query_class(self, internal_name: str) -> ImportedAndroidClass | None:
        for item in self.classes:
            if item.metadata.internal_name == internal_name:
                return item
        return None

    def query_members(self, internal_name: str, text: str = "") -> tuple[JavaMemberMetadata, ...]:
        item = self.query_class(internal_name)
        if item is None:
            return ()
        text = text.lower()
        members = (*item.metadata.fields, *item.metadata.methods)
        return tuple(member for member in members if not text or text in member.name.lower())


class _Cursor:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def take(self, size: int) -> bytes:
        if size < 0 or self.pos + size > len(self.data):
            raise ValueError("truncated Java class file")
        start = self.pos
        self.pos += size
        return self.data[start:self.pos]

    def u1(self) -> int:
        return self.take(1)[0]

    def u2(self) -> int:
        return struct.unpack(">H", self.take(2))[0]

    def u4(self) -> int:
        return struct.unpack(">I", self.take(4))[0]


def _mutf8_decode(raw: bytes) -> str:
    units: list[int] = []
    index = 0
    while index < len(raw):
        first = raw[index]
        if 0x01 <= first <= 0x7F:
            units.append(first)
            index += 1
        elif first & 0xE0 == 0xC0:
            if index + 1 >= len(raw) or raw[index + 1] & 0xC0 != 0x80:
                raise ValueError("malformed class-file modified UTF-8")
            value = ((first & 0x1F) << 6) | (raw[index + 1] & 0x3F)
            if value == 0:
                units.append(0)
            elif value < 0x80:
                raise ValueError("non-canonical class-file modified UTF-8")
            else:
                units.append(value)
            index += 2
        elif first & 0xF0 == 0xE0:
            if index + 2 >= len(raw) or raw[index + 1] & 0xC0 != 0x80 or raw[index + 2] & 0xC0 != 0x80:
                raise ValueError("malformed class-file modified UTF-8")
            value = ((first & 0x0F) << 12) | ((raw[index + 1] & 0x3F) << 6) | (raw[index + 2] & 0x3F)
            if value < 0x800:
                raise ValueError("non-canonical class-file modified UTF-8")
            units.append(value)
            index += 3
        else:
            raise ValueError("unsupported class-file modified UTF-8 byte")
    packed = b"".join(struct.pack("<H", item) for item in units)
    return packed.decode("utf-16-le", "surrogatepass")


def _validate_internal_name(value: str) -> None:
    if not value or value.startswith("/") or value.endswith("/") or "//" in value or "." in value or "\x00" in value:
        raise ValueError(f"invalid JVM internal class name: {value!r}")


def _parse_descriptor_type(value: str, index: int, *, allow_void: bool) -> int:
    if index >= len(value):
        raise ValueError("truncated JVM descriptor")
    code = value[index]
    if code == "V":
        if allow_void:
            return index + 1
        raise ValueError("void is not valid in this JVM descriptor position")
    if code in "ZBCSIJFD":
        return index + 1
    if code == "L":
        end = value.find(";", index + 1)
        if end < 0:
            raise ValueError("unterminated JVM reference descriptor")
        _validate_internal_name(value[index + 1:end])
        return end + 1
    if code == "[":
        cursor = index
        while cursor < len(value) and value[cursor] == "[":
            cursor += 1
        if cursor - index > 255:
            raise ValueError("JVM array descriptor exceeds 255 dimensions")
        return _parse_descriptor_type(value, cursor, allow_void=False)
    raise ValueError(f"invalid JVM descriptor code: {code!r}")


def _validate_field_descriptor(value: str) -> None:
    if _parse_descriptor_type(value, 0, allow_void=False) != len(value):
        raise ValueError("trailing bytes in JVM field descriptor")


def _validate_method_descriptor(value: str) -> None:
    if not value.startswith("("):
        raise ValueError("JVM method descriptor must start with '('")
    cursor = 1
    while cursor < len(value) and value[cursor] != ")":
        cursor = _parse_descriptor_type(value, cursor, allow_void=False)
    if cursor >= len(value) or value[cursor] != ")":
        raise ValueError("unterminated JVM method descriptor")
    cursor = _parse_descriptor_type(value, cursor + 1, allow_void=True)
    if cursor != len(value):
        raise ValueError("trailing bytes in JVM method descriptor")

def parse_jvm_field_descriptor(value: str) -> str:
    """Validate and return one canonical JVM field descriptor."""
    _validate_field_descriptor(value)
    return value


def parse_jvm_method_descriptor(value: str) -> tuple[tuple[str, ...], str]:
    """Return ``(parameter_descriptors, result_descriptor)`` for a JVM method descriptor."""
    _validate_method_descriptor(value)
    parameters: list[str] = []
    cursor = 1
    while value[cursor] != ")":
        end = _parse_descriptor_type(value, cursor, allow_void=False)
        parameters.append(value[cursor:end])
        cursor = end
    result_start = cursor + 1
    result_end = _parse_descriptor_type(value, result_start, allow_void=True)
    if result_end != len(value):
        raise ValueError("trailing bytes in JVM method descriptor")
    return tuple(parameters), value[result_start:result_end]


def _cp_utf8(cp: list[object | None], index: int) -> str:
    if index <= 0 or index >= len(cp) or not isinstance(cp[index], str):
        raise ValueError("class-file constant pool UTF-8 reference is invalid")
    return cp[index]


def _cp_class_name(cp: list[object | None], index: int) -> str:
    if index <= 0 or index >= len(cp):
        raise ValueError("class-file constant pool class reference is invalid")
    item = cp[index]
    if not (isinstance(item, tuple) and item[0] == 7):
        raise ValueError("constant pool entry is not CONSTANT_Class")
    name = _cp_utf8(cp, item[1])
    _validate_internal_name(name)
    return name


def _skip_element_value(cursor: _Cursor) -> None:
    tag = chr(cursor.u1())
    if tag in "BCDFIJSZs":
        cursor.u2()
    elif tag == "e":
        cursor.u2(); cursor.u2()
    elif tag == "c":
        cursor.u2()
    elif tag == "@":
        _skip_annotation(cursor)
    elif tag == "[":
        for _ in range(cursor.u2()):
            _skip_element_value(cursor)
    else:
        raise ValueError(f"unsupported class-file annotation element tag: {tag!r}")


def _skip_annotation(cursor: _Cursor) -> int:
    type_index = cursor.u2()
    for _ in range(cursor.u2()):
        cursor.u2()
        _skip_element_value(cursor)
    return type_index


def _annotation_descriptors(payload: bytes, cp: list[object | None]) -> tuple[str, ...]:
    cursor = _Cursor(payload)
    descriptors = []
    for _ in range(cursor.u2()):
        type_index = _skip_annotation(cursor)
        descriptor = _cp_utf8(cp, type_index)
        _validate_field_descriptor(descriptor)
        descriptors.append(descriptor)
    if cursor.pos != len(payload):
        raise ValueError("trailing bytes in annotation attribute")
    return tuple(sorted(set(descriptors)))


def _read_attributes(cursor: _Cursor, cp: list[object | None]) -> tuple[str, ...]:
    annotations: set[str] = set()
    for _ in range(cursor.u2()):
        name = _cp_utf8(cp, cursor.u2())
        payload = cursor.take(cursor.u4())
        if name in {"RuntimeVisibleAnnotations", "RuntimeInvisibleAnnotations"}:
            annotations.update(_annotation_descriptors(payload, cp))
    return tuple(sorted(annotations))


def parse_classfile(data: bytes) -> JavaClassMetadata:
    cursor = _Cursor(data)
    if cursor.u4() != CLASS_MAGIC:
        raise ValueError("not a Java class file")
    minor = cursor.u2()
    major = cursor.u2()
    count = cursor.u2()
    if count == 0:
        raise ValueError("invalid zero class-file constant-pool count")
    cp: list[object | None] = [None] * count
    index = 1
    while index < count:
        tag = cursor.u1()
        if tag == 1:
            cp[index] = _mutf8_decode(cursor.take(cursor.u2()))
        elif tag in {3, 4}:
            cp[index] = (tag, cursor.take(4))
        elif tag in {5, 6}:
            cp[index] = (tag, cursor.take(8))
            index += 1
            if index < count:
                cp[index] = None
        elif tag in {7, 8, 16, 19, 20}:
            cp[index] = (tag, cursor.u2())
        elif tag in {9, 10, 11, 12, 17, 18}:
            cp[index] = (tag, cursor.u2(), cursor.u2())
        elif tag == 15:
            cp[index] = (tag, cursor.u1(), cursor.u2())
        else:
            raise ValueError(f"unsupported Java class-file constant-pool tag {tag}")
        index += 1

    access = cursor.u2()
    this_name = _cp_class_name(cp, cursor.u2())
    super_index = cursor.u2()
    super_name = None if super_index == 0 else _cp_class_name(cp, super_index)
    interfaces = tuple(_cp_class_name(cp, cursor.u2()) for _ in range(cursor.u2()))

    def read_members(kind: str) -> tuple[JavaMemberMetadata, ...]:
        items = []
        for _ in range(cursor.u2()):
            flags = cursor.u2()
            name = _cp_utf8(cp, cursor.u2())
            descriptor = _cp_utf8(cp, cursor.u2())
            annotations = _read_attributes(cursor, cp)
            items.append(JavaMemberMetadata(kind, name, descriptor, flags, annotations))
        return tuple(sorted(items, key=lambda item: (item.name, item.descriptor, item.access_flags, item.annotations)))

    fields = read_members("field")
    methods = read_members("method")
    annotations = _read_attributes(cursor, cp)
    if cursor.pos != len(data):
        raise ValueError("trailing bytes after Java class file")
    return JavaClassMetadata(
        this_name,
        super_name,
        interfaces,
        access,
        major,
        minor,
        annotations,
        fields,
        methods,
    )


def parse_android_api_versions(xml_data: bytes | str) -> AndroidApiVersions:
    root = ET.fromstring(xml_data)
    if root.tag != "api":
        raise ValueError("Android API versions XML root must be <api>")

    def version_from(element: ET.Element, default_since: int | None = None) -> ApiVersion:
        since_text = element.get("since")
        if since_text is None:
            if default_since is None:
                raise ValueError("Android API version entry has no since level")
            since = default_since
        else:
            since = int(since_text)
        deprecated = int(element.get("deprecated")) if element.get("deprecated") else None
        removed = int(element.get("removed")) if element.get("removed") else None
        return ApiVersion(since, deprecated, removed)

    class_entries: dict[str, ApiVersion] = {}
    method_entries: dict[tuple[str, str], ApiVersion] = {}
    field_entries: dict[tuple[str, str], ApiVersion] = {}
    root_default = int(root.get("version")) if root.get("version") else None
    for class_element in root.findall("class"):
        name = class_element.get("name")
        if not name:
            raise ValueError("Android API class entry has no name")
        _validate_internal_name(name)
        class_version = version_from(class_element, root_default)
        if name in class_entries:
            raise ValueError("duplicate Android API class version entry")
        class_entries[name] = class_version
        for member in class_element:
            if member.tag not in {"method", "field"}:
                continue
            member_name = member.get("name")
            if not member_name:
                raise ValueError("Android API member entry has no name")
            version = version_from(member, class_version.since)
            key = (name, member_name)
            table = method_entries if member.tag == "method" else field_entries
            if key in table:
                raise ValueError("duplicate Android API member version entry")
            table[key] = version
    return AndroidApiVersions(
        tuple(sorted(class_entries.items())),
        tuple((owner, name, version) for (owner, name), version in sorted(method_entries.items())),
        tuple((owner, name, version) for (owner, name), version in sorted(field_entries.items())),
    )


def verify_android_api_available(
    entity: str,
    version: ApiVersion,
    profile: AndroidApiProfile,
    *,
    runtime_api_min: int | None = None,
    runtime_api_max: int | None = None,
) -> AndroidApiAvailabilityDecision:
    """Verify one API is available over the exact reachable runtime interval.

    A runtime branch is explicit by passing a narrowed API interval.  No silent
    version fallback or optimistic future-device assumption is performed.
    """
    lower = profile.device_api_min if profile.device_api_min is not None else profile.min_sdk
    upper = profile.device_api_max
    if runtime_api_min is not None:
        if runtime_api_min < lower:
            fail("XAX.ANDROID.API_GUARD", entity, "ANDROID-API-GUARD-SUBSET", f">= {lower}", runtime_api_min)
        lower = runtime_api_min
    if runtime_api_max is not None:
        if runtime_api_max < lower:
            fail("XAX.ANDROID.API_GUARD", entity, "ANDROID-API-GUARD-RANGE", f">= {lower}", runtime_api_max)
        if upper is not None and runtime_api_max > upper:
            fail("XAX.ANDROID.API_GUARD", entity, "ANDROID-API-GUARD-SUBSET", f"<= {upper}", runtime_api_max)
        upper = runtime_api_max
    if version.since > profile.compile_sdk:
        fail("XAX.ANDROID.API_COMPILE", entity, "ANDROID-API-COMPILE-SDK", f">= {version.since}", profile.compile_sdk)
    if lower < version.since:
        fail(
            "XAX.ANDROID.API_UNAVAILABLE",
            entity,
            "ANDROID-API-SINCE",
            f"runtime API >= {version.since}",
            lower,
            repair_neighborhood=("add explicit runtime API guard", "raise minSdk", "select older API"),
        )
    if version.removed is not None and (upper is None or upper >= version.removed):
        fail(
            "XAX.ANDROID.API_REMOVED",
            entity,
            "ANDROID-API-REMOVED",
            f"runtime API < {version.removed}",
            "unbounded" if upper is None else upper,
            repair_neighborhood=("add explicit upper runtime API guard", "select replacement API"),
        )
    return AndroidApiAvailabilityDecision(True, lower, upper, version)


def verify_android_member_available(
    versions: AndroidApiVersions,
    owner: str,
    kind: str,
    name: str,
    descriptor: str | None,
    profile: AndroidApiProfile,
    *,
    runtime_api_min: int | None = None,
    runtime_api_max: int | None = None,
) -> AndroidApiAvailabilityDecision:
    if kind == "method":
        if descriptor is None:
            raise ValueError("method availability requires JVM descriptor")
        version = versions.method_version(owner, name, descriptor)
        entity = f"{owner}.{name}{descriptor}"
    elif kind == "field":
        version = versions.field_version(owner, name)
        entity = f"{owner}.{name}"
    else:
        raise ValueError("Android API member kind must be method or field")
    if version is None:
        fail("XAX.ANDROID.API_UNKNOWN", entity, "ANDROID-API-METADATA", "member present in selected SDK/API metadata", "missing")
    return verify_android_api_available(
        entity, version, profile, runtime_api_min=runtime_api_min, runtime_api_max=runtime_api_max
    )


def _blob(value: bytes) -> bytes:
    return uleb(len(value)) + value


def _text(value: str) -> bytes:
    return _blob(value.encode("utf-8"))


def _api_version_bytes(version: ApiVersion | None) -> bytes:
    if version is None:
        return b"\x00"
    return b"\x01" + uleb(version.since) + uleb(0 if version.deprecated is None else version.deprecated + 1) + uleb(0 if version.removed is None else version.removed + 1)


def android_member_contract(owner: str, member: JavaMemberMetadata, version: ApiVersion | None = None) -> SemanticObject:
    _validate_internal_name(owner)
    identity = bytearray(ANDROID_SDK_MEMBER_PREFIX)
    identity.extend(b"\x01" if member.kind == "field" else b"\x02")
    identity.extend(_text(owner) + _text(member.name) + _text(member.descriptor))
    identity.extend(uleb(member.access_flags))
    identity.extend(_api_version_bytes(version))
    identity.extend(uleb(len(member.annotations)))
    for annotation in member.annotations:
        identity.extend(_text(annotation))
    return target(bytes(identity))


def android_class_contract(metadata: JavaClassMetadata, member_contracts: Iterable[SemanticObject], version: ApiVersion | None = None) -> SemanticObject:
    members = tuple(sorted((item.cid for item in member_contracts)))
    identity = bytearray(ANDROID_SDK_CLASS_PREFIX)
    identity.extend(_text(metadata.internal_name))
    identity.extend(_text("" if metadata.superclass is None else metadata.superclass))
    identity.extend(uleb(metadata.access_flags) + uleb(metadata.major_version) + uleb(metadata.minor_version))
    identity.extend(_api_version_bytes(version))
    identity.extend(uleb(len(metadata.interfaces)))
    for interface in metadata.interfaces:
        identity.extend(_text(interface))
    identity.extend(uleb(len(metadata.annotations)))
    for annotation in metadata.annotations:
        identity.extend(_text(annotation))
    identity.extend(uleb(len(members)) + b"".join(members))
    return target(bytes(identity))


def import_android_classes(classes: Iterable[JavaClassMetadata], versions: AndroidApiVersions | None = None) -> AndroidSdkImport:
    classes = tuple(sorted(classes, key=lambda item: item.internal_name))
    if len({item.internal_name for item in classes}) != len(classes):
        raise ValueError("duplicate class in Android SDK import")
    imported: list[ImportedAndroidClass] = []
    for metadata in classes:
        member_contracts = []
        for member in (*metadata.fields, *metadata.methods):
            if versions is None:
                version = None
            elif member.kind == "field":
                version = versions.field_version(metadata.internal_name, member.name)
            else:
                version = versions.method_version(metadata.internal_name, member.name, member.descriptor)
            member_contracts.append(android_member_contract(metadata.internal_name, member, version))
        member_contracts_tuple = tuple(sorted(member_contracts, key=lambda item: item.cid))
        class_version = None if versions is None else versions.class_version(metadata.internal_name)
        class_contract = android_class_contract(metadata, member_contracts_tuple, class_version)
        imported.append(ImportedAndroidClass(metadata, class_contract, member_contracts_tuple))
    return AndroidSdkImport(tuple(imported))


def import_android_jar(jar_data: bytes, versions: AndroidApiVersions | None = None) -> AndroidSdkImport:
    classes = []
    with zipfile.ZipFile(io.BytesIO(jar_data), "r") as archive:
        names = sorted(name for name in archive.namelist() if name.endswith(".class") and not name.endswith("module-info.class"))
        if any(name.startswith("META-INF/versions/") for name in names):
            raise ValueError("multi-release JARs require an explicit version-selection policy")
        for name in names:
            classes.append(parse_classfile(archive.read(name)))
    return import_android_classes(classes, versions)


__all__ = [
    "ANDROID_SDK_CLASS_PREFIX",
    "ANDROID_SDK_MEMBER_PREFIX",
    "AndroidApiAvailabilityDecision",
    "AndroidApiProfile",
    "AndroidApiVersions",
    "AndroidSdkImport",
    "ApiVersion",
    "ImportedAndroidClass",
    "JavaClassMetadata",
    "JavaMemberMetadata",
    "android_class_contract",
    "android_member_contract",
    "import_android_classes",
    "import_android_jar",
    "parse_android_api_versions",
    "parse_classfile",
    "parse_jvm_field_descriptor",
    "parse_jvm_method_descriptor",
    "verify_android_api_available",
    "verify_android_member_available",
]
