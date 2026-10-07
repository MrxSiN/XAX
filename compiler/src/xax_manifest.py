"""Deterministic direct binary AndroidManifest.xml emission for the first XAX Activity fixture.

The emitter uses Android's public binary XML structures directly.  It is a
platform package/tooling representation, not a new XAX kernel operation.
"""

from __future__ import annotations

from dataclasses import dataclass
import struct

from xax_compiler import Cursor, Kind, SemanticObject, fail, target, uleb


RES_STRING_POOL_TYPE = 0x0001
RES_XML_TYPE = 0x0003
RES_XML_START_NAMESPACE_TYPE = 0x0100
RES_XML_END_NAMESPACE_TYPE = 0x0101
RES_XML_START_ELEMENT_TYPE = 0x0102
RES_XML_END_ELEMENT_TYPE = 0x0103
RES_XML_RESOURCE_MAP_TYPE = 0x0180
UTF8_FLAG = 1 << 8
NO_INDEX = 0xFFFFFFFF

TYPE_STRING = 0x03
TYPE_INT_DEC = 0x10
TYPE_INT_BOOLEAN = 0x12

ANDROID_NS_PREFIX = "android"
ANDROID_NS_URI = "http://schemas.android.com/apk/res/android"

ANDROID_MANIFEST_PREFIX = b"android-manifest-v1"


def _semantic_bytes(value: str, name: str) -> bytes:
    if not value or "\x00" in value:
        raise ValueError(f"{name} must be nonempty and NUL-free")
    return value.encode("utf-8")


# Public framework attribute IDs, stable since their introduction.  These are
# an explicit target-profile table, not guessed dynamically at runtime.
ANDROID_ATTR_NAME = 0x01010003
ANDROID_ATTR_HAS_CODE = 0x0101000C
ANDROID_ATTR_DEBUGGABLE = 0x0101000F
ANDROID_ATTR_EXPORTED = 0x01010010
ANDROID_ATTR_MIN_SDK_VERSION = 0x0101020C
ANDROID_ATTR_VERSION_CODE = 0x0101021B
ANDROID_ATTR_TARGET_SDK_VERSION = 0x01010270

ANDROID_ATTR_IDS = {
    "name": ANDROID_ATTR_NAME,
    "hasCode": ANDROID_ATTR_HAS_CODE,
    "exported": ANDROID_ATTR_EXPORTED,
    "minSdkVersion": ANDROID_ATTR_MIN_SDK_VERSION,
    "versionCode": ANDROID_ATTR_VERSION_CODE,
    "targetSdkVersion": ANDROID_ATTR_TARGET_SDK_VERSION,
}


@dataclass(frozen=True)
class AndroidManifestSpec:
    package_name: str
    activity_class: str
    min_sdk: int = 28
    target_sdk: int = 35
    version_code: int = 1
    launcher: bool = True
    # Explicit platform semantics: JDWP and run-as on user builds.  Off by default;
    # when off the identity has no trailing byte, so existing manifest CIDs are unchanged.
    debuggable: bool = False

    def __post_init__(self) -> None:
        if not self.package_name or any(part == "" for part in self.package_name.split(".")):
            raise ValueError("Android package name must contain nonempty dot-separated components")
        if not self.activity_class or "/" in self.activity_class or ";" in self.activity_class:
            raise ValueError("Activity class must use Java binary-name notation")
        if not 1 <= self.min_sdk <= self.target_sdk <= 0x7FFFFFFF:
            raise ValueError("invalid Android SDK profile")
        if not 1 <= self.version_code <= 0x7FFFFFFF:
            raise ValueError("versionCode must be a positive signed 32-bit integer")




@dataclass(frozen=True)
class AndroidManifestReceiver:
    class_name: str
    exported: bool = False
    action: str | None = None

    def __post_init__(self) -> None:
        if not self.class_name or "/" in self.class_name or ";" in self.class_name:
            raise ValueError("Receiver class must use Java binary-name notation")
        if self.action is not None and (not self.action or "\x00" in self.action):
            raise ValueError("Receiver action must be nonempty and NUL-free")

@dataclass(frozen=True)
class AndroidManifestService:
    class_name: str
    exported: bool = False

    def __post_init__(self) -> None:
        if not self.class_name or "/" in self.class_name or ";" in self.class_name:
            raise ValueError("Service class must use Java binary-name notation")

@dataclass(frozen=True)
class AndroidManifestApplication:
    class_name: str

    def __post_init__(self) -> None:
        if not self.class_name or "/" in self.class_name or ";" in self.class_name:
            raise ValueError("Application class must use Java binary-name notation")


def android_manifest_semantics(spec: AndroidManifestSpec) -> SemanticObject:
    """Create content-addressed Android manifest semantics as a target carrier."""

    package_name = _semantic_bytes(spec.package_name, "package name")
    activity_class = _semantic_bytes(spec.activity_class, "activity class")
    identity = bytearray(ANDROID_MANIFEST_PREFIX)
    for value in (package_name, activity_class):
        identity.extend(uleb(len(value)) + value)
    identity.extend(uleb(spec.min_sdk) + uleb(spec.target_sdk) + uleb(spec.version_code))
    identity.extend(bytes((1 if spec.launcher else 0,)))
    if spec.debuggable:
        identity.append(1)
    return target(bytes(identity))


def decode_android_manifest_semantics(obj: SemanticObject) -> AndroidManifestSpec:
    if obj.kind != Kind.TARGET or obj.references:
        fail("XAX.ANDROID.MANIFEST", obj.cid.hex(), "ANDROID-MANIFEST-CARRIER", Kind.TARGET.name, obj.kind.name)
    outer = Cursor(obj.body, obj.cid.hex())
    identity = outer.byte_string()
    outer.end("ANDROID-MANIFEST-CARRIER")
    if not identity.startswith(ANDROID_MANIFEST_PREFIX):
        fail("XAX.ANDROID.MANIFEST", obj.cid.hex(), "ANDROID-MANIFEST-IDENTITY", ANDROID_MANIFEST_PREFIX.decode(), identity[:32].hex())
    cursor = Cursor(identity[len(ANDROID_MANIFEST_PREFIX):], obj.cid.hex())
    package_raw = cursor.byte_string()
    activity_raw = cursor.byte_string()
    min_sdk, target_sdk, version_code = cursor.uleb(), cursor.uleb(), cursor.uleb()
    launcher = cursor.boolean()
    debuggable = cursor.boolean() if cursor.remaining else False  # a 0 byte fails the canonical check below
    cursor.end("ANDROID-MANIFEST-IDENTITY")
    try:
        spec = AndroidManifestSpec(
            package_raw.decode("utf-8"),
            activity_raw.decode("utf-8"),
            min_sdk=min_sdk,
            target_sdk=target_sdk,
            version_code=version_code,
            launcher=launcher,
            debuggable=debuggable,
        )
    except (UnicodeDecodeError, ValueError) as error:
        fail("XAX.ANDROID.MANIFEST", obj.cid.hex(), "ANDROID-MANIFEST-FIELDS", "valid canonical manifest fields", str(error))
    canonical = android_manifest_semantics(spec)
    if canonical.cid != obj.cid:
        fail("XAX.ANDROID.MANIFEST", obj.cid.hex(), "ANDROID-MANIFEST-CANONICAL", canonical.cid.hex(), obj.cid.hex())
    return spec


def emit_binary_manifest_from_semantics(obj: SemanticObject) -> bytes:
    return emit_binary_manifest(decode_android_manifest_semantics(obj))


def emit_binary_manifest_with_receivers_from_semantics(
    obj: SemanticObject,
    receivers: tuple[AndroidManifestReceiver, ...] = (),
) -> bytes:
    return emit_binary_manifest(decode_android_manifest_semantics(obj), receivers=receivers)


def emit_binary_manifest_with_components_from_semantics(
    obj: SemanticObject,
    receivers: tuple[AndroidManifestReceiver, ...] = (),
    services: tuple[AndroidManifestService, ...] = (),
    application: AndroidManifestApplication | None = None,
) -> bytes:
    return emit_binary_manifest(
        decode_android_manifest_semantics(obj),
        receivers=receivers,
        services=services,
        application=application,
    )


@dataclass(frozen=True)
class ManifestAttributeView:
    namespace: str | None
    name: str
    value: str | int | bool
    resource_id: int | None


@dataclass(frozen=True)
class ManifestElementView:
    name: str
    attributes: tuple[ManifestAttributeView, ...]
    depth: int


@dataclass(frozen=True)
class BinaryManifestInspection:
    file_size: int
    strings: tuple[str, ...]
    resource_map: tuple[int, ...]
    elements: tuple[ManifestElementView, ...]
    namespace_prefix: str
    namespace_uri: str


@dataclass(frozen=True)
class _Attribute:
    namespace: str | None
    name: str
    type_: int
    value: str | int | bool
    resource_id: int | None = None


@dataclass(frozen=True)
class _Element:
    name: str
    attributes: tuple[_Attribute, ...] = ()
    children: tuple["_Element", ...] = ()


def _utf8_len(value: int) -> bytes:
    if value < 0 or value > 0x7FFF:
        raise ValueError("binary XML UTF-8 string length exceeds supported 15-bit bound")
    if value <= 0x7F:
        return bytes((value,))
    return bytes((0x80 | (value >> 8), value & 0xFF))


def _utf16_units(value: str) -> int:
    return len(value.encode("utf-16-le", "surrogatepass")) // 2


def _string_pool(strings: tuple[str, ...]) -> bytes:
    encoded_items = []
    offsets = []
    blob = bytearray()
    for value in strings:
        raw = value.encode("utf-8")
        item = _utf8_len(_utf16_units(value)) + _utf8_len(len(raw)) + raw + b"\x00"
        offsets.append(len(blob))
        blob.extend(item)
    while len(blob) % 4:
        blob.append(0)
    header_size = 28
    strings_start = header_size + 4 * len(strings)
    size = strings_start + len(blob)
    out = bytearray(struct.pack("<HHI5I", RES_STRING_POOL_TYPE, header_size, size, len(strings), 0, UTF8_FLAG, strings_start, 0))
    out.extend(b"".join(struct.pack("<I", value) for value in offsets))
    out.extend(blob)
    return bytes(out)


def _chunk(type_: int, header_size: int, payload: bytes) -> bytes:
    return struct.pack("<HHI", type_, header_size, 8 + len(payload)) + payload


def _node_prefix(line: int = 0) -> bytes:
    return struct.pack("<II", line, NO_INDEX)


def _namespace_chunk(type_: int, prefix_idx: int, uri_idx: int) -> bytes:
    payload = _node_prefix() + struct.pack("<II", prefix_idx, uri_idx)
    return _chunk(type_, 16, payload)


def _typed_value(type_: int, data: int) -> bytes:
    return struct.pack("<HBBI", 8, 0, type_, data & 0xFFFFFFFF)


def _start_element(name_idx: int, attributes: tuple[_Attribute, ...], indices: dict[str, int], resource_ids: dict[str, int]) -> bytes:
    sorted_attrs = tuple(
        sorted(
            attributes,
            key=lambda item: (
                0 if item.namespace is None else 1,
                item.resource_id if item.resource_id is not None else 0,
                item.name,
            ),
        )
    )
    attr_blob = bytearray()
    for item in sorted_attrs:
        ns_idx = NO_INDEX if item.namespace is None else indices[item.namespace]
        attr_name_idx = indices[item.name]
        if item.type_ == TYPE_STRING:
            value = str(item.value)
            raw_idx = indices[value]
            typed = _typed_value(TYPE_STRING, raw_idx)
        elif item.type_ == TYPE_INT_DEC:
            raw_idx = NO_INDEX
            typed = _typed_value(TYPE_INT_DEC, int(item.value))
        elif item.type_ == TYPE_INT_BOOLEAN:
            raw_idx = NO_INDEX
            typed = _typed_value(TYPE_INT_BOOLEAN, 1 if bool(item.value) else 0)
        else:
            raise ValueError("unsupported manifest attribute type")
        attr_blob.extend(struct.pack("<III", ns_idx, attr_name_idx, raw_idx) + typed)
    # ResXMLTree_attrExt: ns, name, attributeStart=20, attributeSize=20, count, id/class/style indexes.
    ext = struct.pack("<IIHHHHHH", NO_INDEX, name_idx, 20, 20, len(sorted_attrs), 0, 0, 0)
    payload = _node_prefix() + ext + attr_blob
    return _chunk(RES_XML_START_ELEMENT_TYPE, 16, payload)


def _end_element(name_idx: int) -> bytes:
    return _chunk(RES_XML_END_ELEMENT_TYPE, 16, _node_prefix() + struct.pack("<II", NO_INDEX, name_idx))


def _tree_from_spec(
    spec: AndroidManifestSpec,
    receivers: tuple[AndroidManifestReceiver, ...] = (),
    services: tuple[AndroidManifestService, ...] = (),
    application: AndroidManifestApplication | None = None,
) -> _Element:
    android = ANDROID_NS_URI
    children: list[_Element] = [
        _Element(
            "uses-sdk",
            (
                _Attribute(android, "minSdkVersion", TYPE_INT_DEC, spec.min_sdk, ANDROID_ATTR_MIN_SDK_VERSION),
                _Attribute(android, "targetSdkVersion", TYPE_INT_DEC, spec.target_sdk, ANDROID_ATTR_TARGET_SDK_VERSION),
            ),
        )
    ]
    activity_children: tuple[_Element, ...] = ()
    if spec.launcher:
        activity_children = (
            _Element(
                "intent-filter",
                children=(
                    _Element("action", (_Attribute(android, "name", TYPE_STRING, "android.intent.action.MAIN", ANDROID_ATTR_NAME),)),
                    _Element("category", (_Attribute(android, "name", TYPE_STRING, "android.intent.category.LAUNCHER", ANDROID_ATTR_NAME),)),
                ),
            ),
        )
    activity = _Element(
        "activity",
        (
            _Attribute(android, "name", TYPE_STRING, spec.activity_class, ANDROID_ATTR_NAME),
            _Attribute(android, "exported", TYPE_INT_BOOLEAN, bool(spec.launcher), ANDROID_ATTR_EXPORTED),
        ),
        activity_children,
    )
    receiver_elements = []
    for receiver in sorted(receivers, key=lambda item: item.class_name.encode("utf-8")):
        receiver_children: tuple[_Element, ...] = ()
        if receiver.action is not None:
            receiver_children = (
                _Element(
                    "intent-filter",
                    children=(
                        _Element(
                            "action",
                            (_Attribute(android, "name", TYPE_STRING, receiver.action, ANDROID_ATTR_NAME),),
                        ),
                    ),
                ),
            )
        receiver_elements.append(
            _Element(
                "receiver",
                (
                    _Attribute(android, "name", TYPE_STRING, receiver.class_name, ANDROID_ATTR_NAME),
                    _Attribute(android, "exported", TYPE_INT_BOOLEAN, receiver.exported, ANDROID_ATTR_EXPORTED),
                ),
                receiver_children,
            )
        )
    service_elements = [
        _Element(
            "service",
            (
                _Attribute(android, "name", TYPE_STRING, service.class_name, ANDROID_ATTR_NAME),
                _Attribute(android, "exported", TYPE_INT_BOOLEAN, service.exported, ANDROID_ATTR_EXPORTED),
            ),
        )
        for service in sorted(services, key=lambda item: item.class_name.encode("utf-8"))
    ]
    application_attributes = [_Attribute(android, "hasCode", TYPE_INT_BOOLEAN, True, ANDROID_ATTR_HAS_CODE)]
    if spec.debuggable:
        application_attributes.append(_Attribute(android, "debuggable", TYPE_INT_BOOLEAN, True, ANDROID_ATTR_DEBUGGABLE))
    if application is not None:
        application_attributes.append(_Attribute(android, "name", TYPE_STRING, application.class_name, ANDROID_ATTR_NAME))
    application_element = _Element(
        "application",
        tuple(application_attributes),
        (activity, *receiver_elements, *service_elements),
    )
    children.append(application_element)
    return _Element(
        "manifest",
        (
            _Attribute(None, "package", TYPE_STRING, spec.package_name, None),
            _Attribute(android, "versionCode", TYPE_INT_DEC, spec.version_code, ANDROID_ATTR_VERSION_CODE),
        ),
        tuple(children),
    )


def emit_binary_manifest(
    spec: AndroidManifestSpec,
    *,
    receivers: tuple[AndroidManifestReceiver, ...] = (),
    services: tuple[AndroidManifestService, ...] = (),
    application: AndroidManifestApplication | None = None,
) -> bytes:
    tree = _tree_from_spec(spec, receivers, services, application)
    # debuggable joins the resource map only when used, so other manifests keep their bytes.
    attribute_ids = {**ANDROID_ATTR_IDS, "debuggable": ANDROID_ATTR_DEBUGGABLE} if spec.debuggable else ANDROID_ATTR_IDS
    resource_names = tuple(name for name, _id in sorted(attribute_ids.items(), key=lambda item: item[1]))
    strings: set[str] = {ANDROID_NS_PREFIX, ANDROID_NS_URI, *resource_names}

    def collect(element: _Element) -> None:
        strings.add(element.name)
        for item in element.attributes:
            strings.add(item.name)
            if item.namespace is not None:
                strings.add(item.namespace)
            if item.type_ == TYPE_STRING:
                strings.add(str(item.value))
        for child in element.children:
            collect(child)

    collect(tree)
    # Resource-map names must occupy the first string slots in resource-ID order.
    tail = tuple(sorted(strings.difference(resource_names), key=lambda value: value.encode("utf-8")))
    ordered = resource_names + tail
    indices = {value: index for index, value in enumerate(ordered)}
    resource_map = tuple(attribute_ids[name] for name in resource_names)

    chunks = bytearray()
    chunks.extend(_string_pool(ordered))
    chunks.extend(_chunk(RES_XML_RESOURCE_MAP_TYPE, 8, b"".join(struct.pack("<I", item) for item in resource_map)))
    chunks.extend(_namespace_chunk(RES_XML_START_NAMESPACE_TYPE, indices[ANDROID_NS_PREFIX], indices[ANDROID_NS_URI]))

    def emit(element: _Element) -> None:
        chunks.extend(_start_element(indices[element.name], element.attributes, indices, ANDROID_ATTR_IDS))
        for child in element.children:
            emit(child)
        chunks.extend(_end_element(indices[element.name]))

    emit(tree)
    chunks.extend(_namespace_chunk(RES_XML_END_NAMESPACE_TYPE, indices[ANDROID_NS_PREFIX], indices[ANDROID_NS_URI]))
    return struct.pack("<HHI", RES_XML_TYPE, 8, 8 + len(chunks)) + bytes(chunks)


def _read_utf8_len(data: bytes, offset: int) -> tuple[int, int]:
    first = data[offset]
    offset += 1
    if first & 0x80:
        return ((first & 0x7F) << 8) | data[offset], offset + 1
    return first, offset


def _parse_string_pool(data: bytes, offset: int) -> tuple[tuple[str, ...], int]:
    type_, header_size, size = struct.unpack_from("<HHI", data, offset)
    if type_ != RES_STRING_POOL_TYPE or header_size != 28 or offset + size > len(data):
        raise ValueError("invalid binary XML string pool")
    string_count, style_count, flags, strings_start, styles_start = struct.unpack_from("<5I", data, offset + 8)
    if style_count or styles_start or not flags & UTF8_FLAG:
        raise ValueError("unsupported binary XML string-pool profile")
    offsets = struct.unpack_from(f"<{string_count}I", data, offset + header_size) if string_count else ()
    out: list[str] = []
    for relative in offsets:
        cursor = offset + strings_start + relative
        _utf16_len, cursor = _read_utf8_len(data, cursor)
        byte_len, cursor = _read_utf8_len(data, cursor)
        raw = data[cursor:cursor + byte_len]
        if cursor + byte_len >= offset + size or data[cursor + byte_len] != 0:
            raise ValueError("unterminated binary XML UTF-8 string")
        out.append(raw.decode("utf-8"))
    return tuple(out), offset + size


def inspect_binary_manifest(data: bytes) -> BinaryManifestInspection:
    if len(data) < 8:
        raise ValueError("binary manifest too small")
    type_, header_size, size = struct.unpack_from("<HHI", data, 0)
    if (type_, header_size, size) != (RES_XML_TYPE, 8, len(data)):
        raise ValueError("invalid binary XML tree header")
    strings, cursor = _parse_string_pool(data, 8)
    if cursor + 8 > len(data):
        raise ValueError("binary manifest missing resource map")
    type_, header_size, chunk_size = struct.unpack_from("<HHI", data, cursor)
    if type_ != RES_XML_RESOURCE_MAP_TYPE or header_size != 8 or chunk_size < 8 or chunk_size % 4:
        raise ValueError("invalid binary XML resource map")
    resource_map = struct.unpack_from(f"<{(chunk_size - 8) // 4}I", data, cursor + 8) if chunk_size > 8 else ()
    cursor += chunk_size

    prefix = uri = None
    depth = 0
    elements: list[ManifestElementView] = []
    resource_by_index = {index: value for index, value in enumerate(resource_map)}
    while cursor < len(data):
        if cursor + 8 > len(data):
            raise ValueError("truncated binary XML chunk")
        chunk_type, node_header_size, chunk_size = struct.unpack_from("<HHI", data, cursor)
        if chunk_size < node_header_size or cursor + chunk_size > len(data):
            raise ValueError("invalid binary XML chunk bounds")
        if chunk_type in (RES_XML_START_NAMESPACE_TYPE, RES_XML_END_NAMESPACE_TYPE):
            if node_header_size != 16 or chunk_size != 24:
                raise ValueError("invalid namespace chunk")
            prefix_idx, uri_idx = struct.unpack_from("<II", data, cursor + 16)
            if chunk_type == RES_XML_START_NAMESPACE_TYPE:
                prefix, uri = strings[prefix_idx], strings[uri_idx]
        elif chunk_type == RES_XML_START_ELEMENT_TYPE:
            if node_header_size != 16 or chunk_size < 36:
                raise ValueError("invalid start-element chunk")
            ns_idx, name_idx, attr_start, attr_size, attr_count, _id, _class, _style = struct.unpack_from("<IIHHHHHH", data, cursor + 16)
            if ns_idx != NO_INDEX or attr_start != 20 or attr_size != 20:
                raise ValueError("unsupported start-element profile")
            attrs: list[ManifestAttributeView] = []
            base = cursor + 16 + attr_start
            for index in range(attr_count):
                at = base + index * attr_size
                attr_ns, attr_name, raw_idx = struct.unpack_from("<III", data, at)
                value_size, res0, value_type, value_data = struct.unpack_from("<HBBI", data, at + 12)
                if value_size != 8 or res0 != 0:
                    raise ValueError("invalid typed manifest value")
                namespace = None if attr_ns == NO_INDEX else strings[attr_ns]
                if value_type == TYPE_STRING:
                    value: str | int | bool = strings[value_data]
                    if raw_idx != value_data:
                        raise ValueError("manifest string raw/typed index mismatch")
                elif value_type == TYPE_INT_DEC:
                    value = value_data
                elif value_type == TYPE_INT_BOOLEAN:
                    value = bool(value_data)
                else:
                    raise ValueError("unsupported manifest typed value")
                attrs.append(ManifestAttributeView(namespace, strings[attr_name], value, resource_by_index.get(attr_name)))
            elements.append(ManifestElementView(strings[name_idx], tuple(attrs), depth))
            depth += 1
        elif chunk_type == RES_XML_END_ELEMENT_TYPE:
            if node_header_size != 16 or chunk_size != 24:
                raise ValueError("invalid end-element chunk")
            depth -= 1
            if depth < 0:
                raise ValueError("binary XML element underflow")
        else:
            raise ValueError(f"unsupported binary XML chunk type {chunk_type:#x}")
        cursor += chunk_size
    if depth or prefix is None or uri is None:
        raise ValueError("unbalanced binary manifest")
    return BinaryManifestInspection(len(data), strings, tuple(resource_map), tuple(elements), prefix, uri)


__all__ = [
    "ANDROID_ATTR_EXPORTED",
    "ANDROID_ATTR_HAS_CODE",
    "ANDROID_ATTR_MIN_SDK_VERSION",
    "ANDROID_ATTR_NAME",
    "ANDROID_ATTR_TARGET_SDK_VERSION",
    "ANDROID_ATTR_VERSION_CODE",
    "ANDROID_NS_URI",
    "ANDROID_MANIFEST_PREFIX",
    "AndroidManifestSpec",
    "AndroidManifestReceiver",
    "AndroidManifestService",
    "AndroidManifestApplication",
    "android_manifest_semantics",
    "decode_android_manifest_semantics",
    "emit_binary_manifest_from_semantics",
    "emit_binary_manifest_with_receivers_from_semantics",
    "emit_binary_manifest_with_components_from_semantics",
    "BinaryManifestInspection",
    "ManifestAttributeView",
    "ManifestElementView",
    "emit_binary_manifest",
    "inspect_binary_manifest",
]
