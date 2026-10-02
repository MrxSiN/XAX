"""Deterministic direct APK/ZIP container construction.

This is a packaging primitive, not an Android manifest compiler or signer.  It
writes ZIP bytes directly so alignment is explicit and reproducible.  The caller
must provide already-lowered AndroidManifest.xml/DEX/ELF bytes.
"""

from __future__ import annotations

from dataclasses import dataclass
import io
import struct
import zipfile
import zlib
from typing import Iterable, Mapping


LOCAL_FILE_HEADER = 0x04034B50
CENTRAL_DIRECTORY_HEADER = 0x02014B50
END_OF_CENTRAL_DIRECTORY = 0x06054B50
DOS_DATE_1980_01_01 = 0x0021
DOS_TIME_00_00_00 = 0
ZIP_STORED = 0
UTF8_FLAG = 0x0800
PADDING_EXTRA_ID = 0xFFFF
DEFAULT_NATIVE_ALIGNMENT = 16 * 1024
DEFAULT_ENTRY_ALIGNMENT = 4


@dataclass(frozen=True, order=True)
class ApkEntry:
    name: str
    data: bytes
    alignment: int = DEFAULT_ENTRY_ALIGNMENT

    def __post_init__(self) -> None:
        if not self.name or self.name.startswith("/") or ".." in self.name.split("/") or "\\" in self.name or "\x00" in self.name:
            raise ValueError(f"invalid APK entry name: {self.name!r}")
        if self.name.endswith("/"):
            raise ValueError("directory entries are not emitted")
        if self.alignment <= 0 or self.alignment & (self.alignment - 1):
            raise ValueError("APK entry alignment must be a positive power of two")
        if not isinstance(self.data, bytes):
            raise TypeError("APK entry data must be bytes")


@dataclass(frozen=True)
class ApkEntryView:
    name: str
    local_header_offset: int
    data_offset: int
    size: int
    crc32: int
    alignment: int


@dataclass(frozen=True)
class ApkInspection:
    entries: tuple[ApkEntryView, ...]
    central_directory_offset: int
    central_directory_size: int
    file_size: int


def _name_bytes(name: str) -> tuple[bytes, int]:
    try:
        encoded = name.encode("ascii")
        return encoded, 0
    except UnicodeEncodeError:
        return name.encode("utf-8"), UTF8_FLAG


def _padding_extra(current_without_extra: int, alignment: int) -> bytes:
    needed = (-current_without_extra) % alignment
    if needed == 0:
        return b""
    total = needed
    if total < 4:
        total += alignment
    if total > 0xFFFF:
        raise ValueError("APK alignment padding exceeds ZIP extra-field capacity")
    return struct.pack("<HH", PADDING_EXTRA_ID, total - 4) + b"\x00" * (total - 4)


def build_apk(entries: Iterable[ApkEntry]) -> bytes:
    """Build a deterministic, unsigned, stored-entry APK-compatible ZIP."""

    entries = tuple(sorted(entries, key=lambda item: item.name.encode("utf-8")))
    if not entries or len({item.name for item in entries}) != len(entries):
        raise ValueError("APK entries must be nonempty and have unique names")
    out = bytearray()
    central: list[bytes] = []

    for item in entries:
        name, flags = _name_bytes(item.name)
        crc = zlib.crc32(item.data) & 0xFFFFFFFF
        local_offset = len(out)
        base_data_offset = local_offset + 30 + len(name)
        extra = _padding_extra(base_data_offset, item.alignment)
        data_offset = base_data_offset + len(extra)
        if data_offset % item.alignment:
            raise AssertionError("APK entry alignment failure")
        if len(item.data) > 0xFFFFFFFF or local_offset > 0xFFFFFFFF:
            raise ValueError("ZIP64 is intentionally unsupported")
        out.extend(
            struct.pack(
                "<IHHHHHIIIHH",
                LOCAL_FILE_HEADER,
                20,
                flags,
                ZIP_STORED,
                DOS_TIME_00_00_00,
                DOS_DATE_1980_01_01,
                crc,
                len(item.data),
                len(item.data),
                len(name),
                len(extra),
            )
        )
        out.extend(name)
        out.extend(extra)
        out.extend(item.data)
        central.append(
            struct.pack(
                "<IHHHHHHIIIHHHHHII",
                CENTRAL_DIRECTORY_HEADER,
                20,
                20,
                flags,
                ZIP_STORED,
                DOS_TIME_00_00_00,
                DOS_DATE_1980_01_01,
                crc,
                len(item.data),
                len(item.data),
                len(name),
                0,
                0,
                0,
                0,
                0,
                local_offset,
            )
            + name
        )

    central_offset = len(out)
    central_blob = b"".join(central)
    out.extend(central_blob)
    if len(entries) > 0xFFFF or len(central_blob) > 0xFFFFFFFF or central_offset > 0xFFFFFFFF:
        raise ValueError("ZIP64 is intentionally unsupported")
    out.extend(
        struct.pack(
            "<IHHHHIIH",
            END_OF_CENTRAL_DIRECTORY,
            0,
            0,
            len(entries),
            len(entries),
            len(central_blob),
            central_offset,
            0,
        )
    )
    return bytes(out)


def build_unsigned_apk(
    manifest: bytes,
    dex: bytes,
    *,
    native_libraries: Mapping[str, bytes] = {},
    extra_entries: Mapping[str, bytes] = {},
    native_alignment: int = DEFAULT_NATIVE_ALIGNMENT,
) -> bytes:
    """Package already-generated Android representations into an unsigned APK."""

    if not manifest or not dex:
        raise ValueError("unsigned APK requires manifest and classes.dex bytes")
    entries = [
        ApkEntry("AndroidManifest.xml", bytes(manifest), DEFAULT_ENTRY_ALIGNMENT),
        ApkEntry("classes.dex", bytes(dex), DEFAULT_ENTRY_ALIGNMENT),
    ]
    for abi_name, data in native_libraries.items():
        if "/" in abi_name or "\\" in abi_name or not abi_name:
            raise ValueError("native library key must be an ABI-local filename")
        entries.append(ApkEntry(f"lib/arm64-v8a/{abi_name}", bytes(data), native_alignment))
    for name, data in extra_entries.items():
        entries.append(ApkEntry(name, bytes(data), DEFAULT_ENTRY_ALIGNMENT))
    return build_apk(entries)


def inspect_apk(data: bytes) -> ApkInspection:
    """Inspect local ZIP records and cross-check the archive with Python's ZIP parser."""

    # Independent central-directory validation first.
    with zipfile.ZipFile(io.BytesIO(data), "r") as archive:
        infos = tuple(archive.infolist())
        for info in infos:
            if archive.read(info.filename) is None:
                raise AssertionError("unreachable")

    entries: list[ApkEntryView] = []
    cursor = 0
    for info in infos:
        if cursor + 30 > len(data):
            raise ValueError("truncated local ZIP header")
        values = struct.unpack_from("<IHHHHHIIIHH", data, cursor)
        if values[0] != LOCAL_FILE_HEADER:
            raise ValueError("local ZIP header order differs from central directory")
        name_len, extra_len = values[-2], values[-1]
        name_start = cursor + 30
        name_raw = data[name_start:name_start + name_len]
        flags = values[2]
        name = name_raw.decode("utf-8" if flags & UTF8_FLAG else "ascii")
        if name != info.filename:
            raise ValueError("ZIP local/central name mismatch")
        data_offset = name_start + name_len + extra_len
        size = values[8]
        crc = values[6]
        alignment = DEFAULT_NATIVE_ALIGNMENT if name.startswith("lib/") and name.endswith(".so") else DEFAULT_ENTRY_ALIGNMENT
        entries.append(ApkEntryView(name, cursor, data_offset, size, crc, alignment))
        cursor = data_offset + size

    eocd = data.rfind(struct.pack("<I", END_OF_CENTRAL_DIRECTORY))
    if eocd < 0 or eocd + 22 > len(data):
        raise ValueError("missing ZIP end of central directory")
    values = struct.unpack_from("<IHHHHIIH", data, eocd)
    central_size, central_offset = values[5], values[6]
    if central_offset != cursor or central_offset + central_size != eocd:
        raise ValueError("ZIP central directory bounds mismatch")
    return ApkInspection(tuple(entries), central_offset, central_size, len(data))


__all__ = [
    "ApkEntry",
    "ApkEntryView",
    "ApkInspection",
    "DEFAULT_NATIVE_ALIGNMENT",
    "build_apk",
    "build_unsigned_apk",
    "inspect_apk",
]
