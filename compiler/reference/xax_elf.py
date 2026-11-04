"""Shared ELF64 little-endian encoding primitives for XAX artifact emitters.

Pure byte packing only: no layout policy, no target knowledge.  Emitters
(Android shared objects, Linux executables) own their layouts.
"""

from __future__ import annotations

import struct
from typing import Iterable, Sequence


def c_string_table(strings: Iterable[bytes]) -> tuple[bytes, dict[bytes, int]]:
    out = bytearray(b"\x00")
    offsets: dict[bytes, int] = {b"": 0}
    for item in strings:
        item = bytes(item)
        if not item or b"\x00" in item:
            if not item:
                continue
            raise ValueError("ELF strings must be nonempty and NUL-free")
        if item not in offsets:
            offsets[item] = len(out)
            out.extend(item + b"\x00")
    return bytes(out), offsets


def sysv_hash(name: bytes) -> int:
    value = 0
    for byte in name:
        value = (value << 4) + byte
        top = value & 0xF0000000
        if top:
            value ^= top >> 24
        value &= ~top
    return value & 0xFFFFFFFF


def hash_section(symbol_names: Sequence[bytes]) -> bytes:
    # One bucket is enough for the bounded prototype and avoids emitting a
    # tuning table that provides no startup benefit at these symbol counts.
    nchain = len(symbol_names)
    nbucket = 1
    buckets = [0]
    chains = [0] * nchain
    previous = 0
    for index, name in enumerate(symbol_names[1:], 1):
        _ = sysv_hash(name)
        if not buckets[0]:
            buckets[0] = index
        elif previous:
            chains[previous] = index
        previous = index
    return struct.pack("<II", nbucket, nchain) + struct.pack(f"<{nbucket}I", *buckets) + struct.pack(f"<{nchain}I", *chains)


def section_header(name: int, type_: int, flags: int, address: int, offset: int, size: int, link: int, info: int, alignment: int, entsize: int) -> bytes:
    return struct.pack("<IIQQQQIIQQ", name, type_, flags, address, offset, size, link, info, alignment, entsize)


def program_header(type_: int, flags: int, offset: int, vaddr: int, filesz: int, memsz: int, align: int) -> bytes:
    return struct.pack("<IIQQQQQQ", type_, flags, offset, vaddr, vaddr, filesz, memsz, align)


def symbol(name: int, info: int, other: int, shndx: int, value: int, size: int) -> bytes:
    return struct.pack("<IBBHQQ", name, info, other, shndx, value, size)


def dynamic(tag: int, value: int) -> bytes:
    return struct.pack("<QQ", tag, value)


def rela(offset: int, symbol_index: int, relocation_type: int, addend: int = 0) -> bytes:
    return struct.pack("<QQq", offset, (symbol_index << 32) | relocation_type, addend)
