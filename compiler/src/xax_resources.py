"""Deterministic bounded Android resource-table emission.

The current prototype supports one application package (ID 0x7f), one ``string``
resource type (type ID 1), and the default configuration.  Resource semantics
are carried by an ordinary identity-only XAX target object; ``resources.arsc``
is a target representation, not a kernel object kind or source language.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
import struct

from xax_compiler import Cursor, Kind, SemanticObject, fail, target, uleb


RES_STRING_POOL_TYPE = 0x0001
RES_TABLE_TYPE = 0x0002
RES_TABLE_PACKAGE_TYPE = 0x0200
RES_TABLE_TYPE_TYPE = 0x0201
RES_TABLE_TYPE_SPEC_TYPE = 0x0202
UTF8_FLAG = 1 << 8
TYPE_STRING = 0x03
NO_ENTRY = 0xFFFFFFFF
APP_PACKAGE_ID = 0x7F
STRING_TYPE_ID = 1
ANDROID_RESOURCES_PREFIX = b"android-resources-v1"
_RESOURCE_NAME = re.compile(r"^[a-z][a-z0-9_]*$")


@dataclass(frozen=True, order=True)
class AndroidStringResource:
    name: str
    value: str

    def __post_init__(self) -> None:
        if not _RESOURCE_NAME.fullmatch(self.name):
            raise ValueError("Android string resource name must match [a-z][a-z0-9_]*")
        if "\x00" in self.value:
            raise ValueError("Android string resource value must be NUL-free")
        self.name.encode("utf-8")
        self.value.encode("utf-8")


@dataclass(frozen=True)
class AndroidResourceSpec:
    package_name: str
    strings: tuple[AndroidStringResource, ...]

    def __post_init__(self) -> None:
        if not self.package_name or any(part == "" for part in self.package_name.split(".")):
            raise ValueError("Android resource package name must contain nonempty dot-separated components")
        if "\x00" in self.package_name:
            raise ValueError("Android resource package name must be NUL-free")
        if len(self.package_name.encode("utf-16-le")) // 2 > 127:
            raise ValueError("Android resource package name exceeds ResTable_package bound")
        ordered = tuple(sorted(self.strings, key=lambda item: item.name.encode("utf-8")))
        if not ordered:
            raise ValueError("bounded Android resource table requires at least one string")
        if len({item.name for item in ordered}) != len(ordered):
            raise ValueError("Android resource names must be unique")
        object.__setattr__(self, "strings", ordered)


@dataclass(frozen=True)
class AndroidResourceEntryView:
    resource_id: int
    name: str
    value: str


@dataclass(frozen=True)
class AndroidResourceTableInspection:
    file_size: int
    package_id: int
    package_name: str
    type_name: str
    entries: tuple[AndroidResourceEntryView, ...]


def _bytes(value: bytes) -> bytes:
    return uleb(len(value)) + value


def android_resources_semantics(spec: AndroidResourceSpec) -> SemanticObject:
    package = spec.package_name.encode("utf-8")
    identity = bytearray(ANDROID_RESOURCES_PREFIX + _bytes(package) + uleb(len(spec.strings)))
    for item in spec.strings:
        identity.extend(_bytes(item.name.encode("utf-8")))
        identity.extend(_bytes(item.value.encode("utf-8")))
    return target(bytes(identity))


def decode_android_resources_semantics(obj: SemanticObject) -> AndroidResourceSpec:
    if obj.kind != Kind.TARGET or obj.references:
        fail("XAX.ANDROID.RESOURCES", obj.cid.hex(), "ANDROID-RESOURCES-CARRIER", Kind.TARGET.name, obj.kind.name)
    outer = Cursor(obj.body, obj.cid.hex())
    identity = outer.byte_string()
    outer.end("ANDROID-RESOURCES-CARRIER")
    if not identity.startswith(ANDROID_RESOURCES_PREFIX):
        fail(
            "XAX.ANDROID.RESOURCES",
            obj.cid.hex(),
            "ANDROID-RESOURCES-IDENTITY",
            ANDROID_RESOURCES_PREFIX.decode(),
            identity[:32].hex(),
        )
    cursor = Cursor(identity[len(ANDROID_RESOURCES_PREFIX):], obj.cid.hex())
    try:
        package_name = cursor.byte_string().decode("utf-8")
        count = cursor.uleb()
        items = []
        for _ in range(count):
            items.append(AndroidStringResource(cursor.byte_string().decode("utf-8"), cursor.byte_string().decode("utf-8")))
        cursor.end("ANDROID-RESOURCES-IDENTITY")
        spec = AndroidResourceSpec(package_name, tuple(items))
    except (UnicodeDecodeError, ValueError) as error:
        fail("XAX.ANDROID.RESOURCES", obj.cid.hex(), "ANDROID-RESOURCES-FIELDS", "valid canonical resource fields", str(error))
    canonical = android_resources_semantics(spec)
    if canonical.cid != obj.cid:
        fail("XAX.ANDROID.RESOURCES", obj.cid.hex(), "ANDROID-RESOURCES-CANONICAL", canonical.cid.hex(), obj.cid.hex())
    return spec


def resource_id(name: str, spec: AndroidResourceSpec) -> int:
    for index, item in enumerate(spec.strings):
        if item.name == name:
            return (APP_PACKAGE_ID << 24) | (STRING_TYPE_ID << 16) | index
    raise KeyError(name)


def _utf8_len(value: int) -> bytes:
    if value < 0 or value > 0x7FFF:
        raise ValueError("resource string length exceeds supported 15-bit bound")
    if value <= 0x7F:
        return bytes((value,))
    return bytes((0x80 | (value >> 8), value & 0xFF))


def _utf16_units(value: str) -> int:
    return len(value.encode("utf-16-le", "surrogatepass")) // 2


def _string_pool(strings: tuple[str, ...]) -> bytes:
    offsets: list[int] = []
    blob = bytearray()
    for value in strings:
        raw = value.encode("utf-8")
        offsets.append(len(blob))
        blob.extend(_utf8_len(_utf16_units(value)))
        blob.extend(_utf8_len(len(raw)))
        blob.extend(raw + b"\x00")
    while len(blob) % 4:
        blob.append(0)
    header_size = 28
    strings_start = header_size + 4 * len(strings)
    size = strings_start + len(blob)
    return (
        struct.pack("<HHI5I", RES_STRING_POOL_TYPE, header_size, size, len(strings), 0, UTF8_FLAG, strings_start, 0)
        + b"".join(struct.pack("<I", offset) for offset in offsets)
        + bytes(blob)
    )


def _package_name(value: str) -> bytes:
    raw = value.encode("utf-16-le") + b"\x00\x00"
    if len(raw) > 256:
        raise ValueError("resource package name exceeds fixed UTF-16 field")
    return raw + b"\x00" * (256 - len(raw))


def emit_resources_arsc(spec: AndroidResourceSpec) -> bytes:
    """Emit one deterministic Android ``resources.arsc`` string table."""

    type_pool = _string_pool(("string",))
    key_pool = _string_pool(tuple(item.name for item in spec.strings))
    value_strings = tuple(sorted({item.value for item in spec.strings}, key=lambda value: value.encode("utf-8")))
    value_pool = _string_pool(value_strings)
    value_index = {value: index for index, value in enumerate(value_strings)}
    entry_count = len(spec.strings)

    type_spec_size = 16 + 4 * entry_count
    type_spec = struct.pack(
        "<HHIBBHI",
        RES_TABLE_TYPE_SPEC_TYPE,
        16,
        type_spec_size,
        STRING_TYPE_ID,
        0,
        0,
        entry_count,
    ) + b"\x00\x00\x00\x00" * entry_count

    # Oldest compact default configuration shape: fields through sdk/minor (28 bytes).
    config = struct.pack("<I", 28) + b"\x00" * 24
    type_header_size = 20 + len(config)
    entries_start = type_header_size + 4 * entry_count
    entry_blob = bytearray()
    offsets = []
    for key_index, item in enumerate(spec.strings):
        offsets.append(len(entry_blob))
        entry_blob.extend(struct.pack("<HHI", 8, 0, key_index))
        entry_blob.extend(struct.pack("<HBBI", 8, 0, TYPE_STRING, value_index[item.value]))
    type_size = entries_start + len(entry_blob)
    type_chunk = (
        struct.pack(
            "<HHIBBHII",
            RES_TABLE_TYPE_TYPE,
            type_header_size,
            type_size,
            STRING_TYPE_ID,
            0,
            0,
            entry_count,
            entries_start,
        )
        + config
        + b"".join(struct.pack("<I", offset) for offset in offsets)
        + bytes(entry_blob)
    )

    package_header_size = 288
    type_strings_offset = package_header_size
    key_strings_offset = type_strings_offset + len(type_pool)
    package_payload = (
        struct.pack("<I", APP_PACKAGE_ID)
        + _package_name(spec.package_name)
        + struct.pack("<IIIII", type_strings_offset, STRING_TYPE_ID, key_strings_offset, entry_count, 0)
    )
    if len(package_payload) != package_header_size - 8:
        raise AssertionError("ResTable_package header size mismatch")
    package_body = type_pool + key_pool + type_spec + type_chunk
    package_size = package_header_size + len(package_body)
    package_chunk = struct.pack("<HHI", RES_TABLE_PACKAGE_TYPE, package_header_size, package_size) + package_payload + package_body

    total_size = 12 + len(value_pool) + len(package_chunk)
    return struct.pack("<HHII", RES_TABLE_TYPE, 12, total_size, 1) + value_pool + package_chunk


def emit_resources_arsc_from_semantics(obj: SemanticObject) -> bytes:
    return emit_resources_arsc(decode_android_resources_semantics(obj))


def _read_utf8_len(data: bytes, cursor: int) -> tuple[int, int]:
    if cursor >= len(data):
        raise ValueError("truncated resource string length")
    first = data[cursor]
    cursor += 1
    if first & 0x80:
        if cursor >= len(data):
            raise ValueError("truncated resource string length")
        return ((first & 0x7F) << 8) | data[cursor], cursor + 1
    return first, cursor


def _parse_string_pool(data: bytes, offset: int) -> tuple[tuple[str, ...], int]:
    if offset + 28 > len(data):
        raise ValueError("truncated resource string pool")
    type_, header_size, size, count, style_count, flags, strings_start, styles_start = struct.unpack_from("<HHI5I", data, offset)
    if type_ != RES_STRING_POOL_TYPE or header_size != 28 or style_count != 0 or styles_start != 0 or not flags & UTF8_FLAG:
        raise ValueError("unsupported resource string pool")
    end = offset + size
    if end > len(data) or strings_start < header_size + 4 * count:
        raise ValueError("invalid resource string pool bounds")
    result = []
    for index in range(count):
        relative = struct.unpack_from("<I", data, offset + header_size + 4 * index)[0]
        cursor = offset + strings_start + relative
        utf16_len, cursor = _read_utf8_len(data, cursor)
        utf8_len, cursor = _read_utf8_len(data, cursor)
        raw = data[cursor:cursor + utf8_len]
        if len(raw) != utf8_len or cursor + utf8_len >= end or data[cursor + utf8_len] != 0:
            raise ValueError("invalid resource string payload")
        value = raw.decode("utf-8")
        if _utf16_units(value) != utf16_len:
            raise ValueError("resource string UTF-16 length mismatch")
        result.append(value)
    return tuple(result), end


def inspect_resources_arsc(data: bytes) -> AndroidResourceTableInspection:
    if len(data) < 12:
        raise ValueError("truncated resources.arsc")
    type_, header_size, size, package_count = struct.unpack_from("<HHII", data, 0)
    if type_ != RES_TABLE_TYPE or header_size != 12 or size != len(data) or package_count != 1:
        raise ValueError("invalid bounded resource table header")
    values, package_offset = _parse_string_pool(data, 12)
    if package_offset + 288 > len(data):
        raise ValueError("truncated resource package")
    p_type, p_header, p_size = struct.unpack_from("<HHI", data, package_offset)
    if p_type != RES_TABLE_PACKAGE_TYPE or p_header != 288 or package_offset + p_size != len(data):
        raise ValueError("invalid resource package chunk")
    package_id = struct.unpack_from("<I", data, package_offset + 8)[0]
    name_raw = data[package_offset + 12:package_offset + 268]
    terminator = next((i for i in range(0, len(name_raw), 2) if name_raw[i:i+2] == b"\x00\x00"), None)
    if terminator is None:
        raise ValueError("unterminated resource package name")
    package_name = name_raw[:terminator].decode("utf-16-le")
    type_strings_off, _last_type, key_strings_off, _last_key, type_id_offset = struct.unpack_from("<IIIII", data, package_offset + 268)
    if type_id_offset != 0:
        raise ValueError("bounded resource table does not use type ID offset")
    types, _ = _parse_string_pool(data, package_offset + type_strings_off)
    keys, after_keys = _parse_string_pool(data, package_offset + key_strings_off)
    if types != ("string",):
        raise ValueError("bounded resource table requires one string type")

    ts_type, ts_header, ts_size, ts_id, ts_res0, ts_res1, entry_count = struct.unpack_from("<HHIBBHI", data, after_keys)
    if (ts_type, ts_header, ts_id, ts_res0, ts_res1) != (RES_TABLE_TYPE_SPEC_TYPE, 16, STRING_TYPE_ID, 0, 0):
        raise ValueError("invalid resource type-spec")
    if entry_count != len(keys) or ts_size != 16 + 4 * entry_count:
        raise ValueError("resource type-spec entry count mismatch")
    type_offset = after_keys + ts_size
    t_type, t_header, t_size, t_id, t_flags, t_reserved, t_count, entries_start = struct.unpack_from("<HHIBBHII", data, type_offset)
    if (t_type, t_id, t_flags, t_reserved, t_count) != (RES_TABLE_TYPE_TYPE, STRING_TYPE_ID, 0, 0, entry_count):
        raise ValueError("invalid resource type chunk")
    config_size = struct.unpack_from("<I", data, type_offset + 20)[0]
    if t_header != 20 + config_size or config_size < 4 or entries_start != t_header + 4 * entry_count:
        raise ValueError("invalid resource type configuration")
    if type_offset + t_size != len(data):
        raise ValueError("resource type chunk must terminate bounded package")

    entries = []
    offsets_base = type_offset + t_header
    data_base = type_offset + entries_start
    for index, key in enumerate(keys):
        relative = struct.unpack_from("<I", data, offsets_base + 4 * index)[0]
        if relative == NO_ENTRY:
            raise ValueError("bounded resource table cannot contain missing entries")
        entry_offset = data_base + relative
        entry_size, flags, key_index = struct.unpack_from("<HHI", data, entry_offset)
        value_size, res0, data_type, value_index = struct.unpack_from("<HBBI", data, entry_offset + entry_size)
        if entry_size != 8 or flags != 0 or key_index != index or value_size != 8 or res0 != 0 or data_type != TYPE_STRING:
            raise ValueError("invalid bounded string resource entry")
        if value_index >= len(values):
            raise ValueError("resource value string index out of range")
        entries.append(AndroidResourceEntryView((package_id << 24) | (STRING_TYPE_ID << 16) | index, key, values[value_index]))
    return AndroidResourceTableInspection(len(data), package_id, package_name, "string", tuple(entries))


__all__ = [
    "ANDROID_RESOURCES_PREFIX",
    "APP_PACKAGE_ID",
    "STRING_TYPE_ID",
    "AndroidResourceEntryView",
    "AndroidResourceSpec",
    "AndroidResourceTableInspection",
    "AndroidStringResource",
    "android_resources_semantics",
    "decode_android_resources_semantics",
    "emit_resources_arsc",
    "emit_resources_arsc_from_semantics",
    "inspect_resources_arsc",
    "resource_id",
]
