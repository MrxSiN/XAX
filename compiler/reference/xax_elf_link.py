"""Deterministic static linking of ELF64 relocatable objects into XAX images (ADR-129).

Artifact infrastructure, not semantics.  It places the allocatable sections
of ``ET_REL`` objects (text, read-only data, data, zero-initialized data) at
a caller-chosen address, resolves their symbols, and applies an exact
AArch64 relocation subset.  Anything outside it is refused with its reason:
an unknown relocation type, an undefined symbol, an overflowing
displacement, a common symbol, or a non-AArch64 object.  Non-allocatable
sections (comments, notes, debug, unwind tables) are dropped, never
consulted.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence

from xax_compiler import fail

SHF_WRITE, SHF_ALLOC, SHF_EXECINSTR = 1, 2, 4
SHT_PROGBITS, SHT_SYMTAB, SHT_NOBITS, SHT_RELA = 1, 2, 8, 4
SHN_UNDEF, SHN_ABS, SHN_COMMON = 0, 0xFFF1, 0xFFF2
EM_AARCH64 = 183
# Relocation types this linker applies (AArch64 ELF ABI numbering).
R_ABS64, R_PREL32, R_ADR_PREL_LO21, R_ADR_PREL_PG_HI21, R_ADD_ABS_LO12_NC = 257, 261, 274, 275, 277
R_LDST8, R_JUMP26, R_CALL26, R_LDST16, R_LDST32, R_LDST64, R_LDST128 = 278, 282, 283, 284, 285, 286, 299
_LDST_SHIFT = {R_LDST8: 0, R_LDST16: 1, R_LDST32: 2, R_LDST64: 3, R_LDST128: 4}
_SUPPORTED = frozenset({R_ABS64, R_PREL32, R_ADR_PREL_LO21, R_ADR_PREL_PG_HI21, R_ADD_ABS_LO12_NC, R_JUMP26, R_CALL26, *_LDST_SHIFT})
_ORDER = ("text", "rodata", "data", "bss")


@dataclass(frozen=True)
class _Section:
    name: str
    kind: str
    data: bytes
    size: int
    alignment: int


@dataclass(frozen=True)
class _Symbol:
    name: str
    value: int
    section: int
    binding: int


@dataclass(frozen=True)
class LinkedObjects:
    """Placed bytes (zero-initialized data included) and the global symbol addresses."""

    data: bytes
    base: int
    symbols: dict[str, int]
    writable: bool


def _refuse(rule: str, expected, actual) -> None:
    fail("XAX.LINK.OBJECT", "static-link", rule, expected, actual)


def _read_object(path: Path):
    data = Path(path).read_bytes()
    if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        _refuse("LINK-ELF64-LE", "ELF64 little-endian", data[:6].hex())
    e_type, machine = struct.unpack_from("<HH", data, 16)
    if e_type != 1 or machine != EM_AARCH64:
        _refuse("LINK-AARCH64-RELOCATABLE", [1, EM_AARCH64], [e_type, machine])
    shoff, = struct.unpack_from("<Q", data, 40)
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 58)
    headers = [struct.unpack_from("<IIQQQQIIQQ", data, shoff + index * shentsize) for index in range(shnum)]
    names = headers[shstrndx]

    def name(offset: int, table) -> str:
        start = table[4] + offset
        return data[start:data.index(b"\0", start)].decode()

    sections: dict[int, _Section] = {}
    symbols: list[_Symbol] = []
    relocations: dict[int, list[tuple[int, int, int, int]]] = {}
    for index, (sh_name, sh_type, flags, _addr, offset, size, link, info, alignment, entsize) in enumerate(headers):
        section_name = name(sh_name, names)
        if sh_type == SHT_SYMTAB:
            strings = headers[link]
            for position in range(size // entsize):
                st_name, st_info, _other, shndx, value, _size = struct.unpack_from("<IBBHQQ", data, offset + position * entsize)
                symbols.append(_Symbol(name(st_name, strings) if st_name else "", value, shndx, st_info >> 4))
        elif sh_type == SHT_RELA:
            relocations[info] = [
                (r_offset, r_info & 0xFFFFFFFF, r_info >> 32, addend)
                for r_offset, r_info, addend in (struct.unpack_from("<QQq", data, offset + position * entsize) for position in range(size // entsize))
            ]
        elif flags & SHF_ALLOC and sh_type in (SHT_PROGBITS, SHT_NOBITS):
            kind = "text" if flags & SHF_EXECINSTR else "bss" if sh_type == SHT_NOBITS else "data" if flags & SHF_WRITE else "rodata"
            sections[index] = _Section(section_name, kind, data[offset:offset + size] if sh_type == SHT_PROGBITS else bytes(size), size, max(1, alignment))
    if any(symbol.section == SHN_COMMON for symbol in symbols):
        _refuse("LINK-NO-COMMON", "no common symbols (compile with -fno-common)", [symbol.name for symbol in symbols if symbol.section == SHN_COMMON])
    return sections, symbols, relocations


def link_objects(paths: Sequence[str | Path], base: int, externals: Mapping[str, int] | None = None) -> LinkedObjects:
    """Place and relocate ``paths`` at ``base``; ``externals`` resolves symbols the objects use but do not define."""
    externals = dict(externals or {})
    objects = [_read_object(Path(path)) for path in paths]
    placed: dict[tuple[int, int], int] = {}
    cursor = base
    for kind in _ORDER:  # deterministic: kind, then object order, then section index
        for object_index, (sections, _symbols, _relocations) in enumerate(objects):
            for index in sorted(sections):
                section = sections[index]
                if section.kind == kind:
                    cursor = (cursor + section.alignment - 1) & -section.alignment
                    placed[(object_index, index)] = cursor
                    cursor += section.size
    image = bytearray(cursor - base)
    for (object_index, index), address in placed.items():
        section = objects[object_index][0][index]
        image[address - base:address - base + section.size] = section.data
    globals_: dict[str, int] = {}
    for object_index, (_sections, symbols, _relocations) in enumerate(objects):
        for symbol in symbols:
            if symbol.binding in (1, 2) and symbol.section not in (SHN_UNDEF, SHN_ABS) and (object_index, symbol.section) in placed:
                if symbol.name in globals_:
                    _refuse("LINK-SYMBOL-UNIQUE", "one definition", symbol.name)
                globals_[symbol.name] = placed[(object_index, symbol.section)] + symbol.value

    def address_of(object_index: int, symbol: _Symbol) -> int:
        if symbol.section == SHN_ABS:
            return symbol.value
        if symbol.section != SHN_UNDEF:
            if (object_index, symbol.section) not in placed:
                _refuse("LINK-SYMBOL-ALLOCATED", "a symbol in an allocatable section", symbol.name)
            return placed[(object_index, symbol.section)] + symbol.value
        if symbol.name in globals_:
            return globals_[symbol.name]
        if symbol.name in externals:
            return externals[symbol.name]
        _refuse("LINK-SYMBOL-DEFINED", "a definition in a linked object or a declared external", symbol.name)

    unsupported = sorted({kind for sections, _symbols, relocations in objects for index, items in relocations.items() if index in sections for _o, kind, _s, _a in items} - _SUPPORTED)
    if unsupported:  # refuse before resolving anything: GOT/TLS/PLT forms are outside the subset
        _refuse("LINK-RELOCATION-TYPE", sorted(_SUPPORTED), unsupported)
    for object_index, (sections, symbols, relocations) in enumerate(objects):
        for section_index, items in sorted(relocations.items()):
            if section_index not in sections:
                continue  # relocations of dropped (non-allocatable) sections
            section_address = placed[(object_index, section_index)]
            for offset, kind, symbol_index, addend in items:
                place = section_address + offset
                value = address_of(object_index, symbols[symbol_index]) + addend
                at = place - base
                word = int.from_bytes(image[at:at + 4], "little")
                if kind == R_ABS64:
                    image[at:at + 8] = (value & (1 << 64) - 1).to_bytes(8, "little")
                    continue
                if kind == R_PREL32:
                    delta = value - place
                    if not -(1 << 31) <= delta < 1 << 32:
                        _refuse("LINK-RELOCATION-RANGE", "32-bit displacement", delta)
                    word = delta & 0xFFFFFFFF
                elif kind in (R_CALL26, R_JUMP26):
                    delta = value - place
                    if delta % 4 or not -(1 << 27) <= delta < 1 << 27:
                        _refuse("LINK-RELOCATION-RANGE", "aligned 28-bit branch displacement", delta)
                    word = (word & 0xFC000000) | ((delta >> 2) & 0x3FFFFFF)
                elif kind == R_ADR_PREL_PG_HI21:
                    pages = ((value & ~0xFFF) - (place & ~0xFFF)) >> 12
                    if not -(1 << 20) <= pages < 1 << 20:
                        _refuse("LINK-RELOCATION-RANGE", "21-bit page displacement", pages)
                    word = (word & 0x9F00001F) | ((pages & 0x3) << 29) | (((pages >> 2) & 0x7FFFF) << 5)
                elif kind == R_ADR_PREL_LO21:
                    delta = value - place
                    if not -(1 << 20) <= delta < 1 << 20:
                        _refuse("LINK-RELOCATION-RANGE", "21-bit displacement", delta)
                    word = (word & 0x9F00001F) | ((delta & 0x3) << 29) | (((delta >> 2) & 0x7FFFF) << 5)
                elif kind == R_ADD_ABS_LO12_NC:
                    word = (word & 0xFFC003FF) | ((value & 0xFFF) << 10)
                elif kind in _LDST_SHIFT:
                    shift = _LDST_SHIFT[kind]
                    if value & ((1 << shift) - 1):
                        _refuse("LINK-RELOCATION-ALIGNMENT", f"{1 << shift}-byte aligned target", value)
                    word = (word & 0xFFC003FF) | (((value & 0xFFF) >> shift) << 10)
                else:
                    _refuse("LINK-RELOCATION-TYPE", sorted((R_ABS64, R_PREL32, R_ADR_PREL_LO21, R_ADR_PREL_PG_HI21, R_ADD_ABS_LO12_NC, R_JUMP26, R_CALL26, *_LDST_SHIFT)), kind)
                image[at:at + 4] = word.to_bytes(4, "little")
    writable = any(section.kind in ("data", "bss") for sections, _s, _r in objects for section in sections.values())
    return LinkedObjects(bytes(image), base, globals_, writable)
