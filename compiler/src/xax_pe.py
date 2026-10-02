"""Direct PE32+ executable container for x86-64 Windows native images.

The container adds no code: the entry point is the XAX entry function itself
and every foreign call binds to one loader-filled import-address-table slot.
No CRT, startup stub, runtime, or relocation table is emitted; generated code
is position independent (rel32 calls, RIP-relative import slots), so the
image is ASLR-compatible without base relocations.
"""
from __future__ import annotations

import struct

from xax_compiler import fail
from xax_x86_64 import NativeImage

IMAGE_BASE = 0x140000000
SECTION_ALIGNMENT = 0x1000
FILE_ALIGNMENT = 0x200
HEADERS_SIZE = 0x200
# ponytail: fixed 1 MiB reserve/4 KiB commit stack, derive from the bounded
# stack analysis once a hosted profile requests an exact budget.
STACK_RESERVE, STACK_COMMIT = 0x100000, 0x1000


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) & -alignment


def _section(name: bytes, virtual_size: int, rva: int, raw_size: int, raw_offset: int, flags: int) -> bytes:
    return struct.pack("<8sIIIIIIHHI", name, virtual_size, rva, raw_size, raw_offset, 0, 0, 0, 0, flags)


def _import_section(rva: int, imports: tuple[tuple[int, bytes, bytes], ...]) -> tuple[bytes, dict[tuple[bytes, bytes], int], int, int]:
    libraries: dict[bytes, list[bytes]] = {}
    for library, name in sorted({(lib, sym) for _, lib, sym in imports}):
        libraries.setdefault(library, []).append(name)
    order = sorted(libraries)
    descriptors_size = 20 * (len(order) + 1)
    thunk_bytes = sum(8 * (len(libraries[lib]) + 1) for lib in order)
    ilt_rva = rva + descriptors_size
    iat_rva = ilt_rva + thunk_bytes
    strings = bytearray()
    strings_rva = iat_rva + thunk_bytes
    hint_names: dict[tuple[bytes, bytes], int] = {}
    dll_names: dict[bytes, int] = {}
    for library in order:
        for name in libraries[library]:
            hint_names[(library, name)] = strings_rva + len(strings)
            strings += b"\0\0" + name + b"\0"
            if len(strings) % 2:
                strings += b"\0"
        dll_names[library] = strings_rva + len(strings)
        strings += library + b"\0"
        if len(strings) % 2:
            strings += b"\0"
    descriptors = bytearray()
    thunks = bytearray()
    slots: dict[tuple[bytes, bytes], int] = {}
    offset = 0
    for library in order:
        descriptors += struct.pack("<IIIII", ilt_rva + offset, 0, 0, dll_names[library], iat_rva + offset)
        for name in libraries[library]:
            slots[(library, name)] = iat_rva + offset
            thunks += struct.pack("<Q", hint_names[(library, name)])
            offset += 8
        thunks += bytes(8)
        offset += 8
    descriptors += bytes(20)
    body = bytes(descriptors + thunks + thunks + strings)
    return body, slots, iat_rva, thunk_bytes


def emit_pe_executable(image: NativeImage) -> bytes:
    """Wrap a parameterless entry as a console PE32+ executable.

    The program must end the process with an explicit ``ExitProcess`` call:
    returning from a PE entry does not terminate a process whose loader
    worker threads are alive, and the container adds no hidden exit path.
    """
    if image.parameter_widths or image.parameter_kinds:
        fail("XAX.PE.ENTRY", image.target_cid.hex(), "PE-ENTRY-NO-PARAMETERS", 0, len(image.parameter_widths))
    if any(not kind.startswith("u") for kind in image.return_kinds):
        fail("XAX.PE.ENTRY", image.target_cid.hex(), "PE-ENTRY-INTEGER-RESULT", "u<bits>", list(image.return_kinds))
    text_rva = SECTION_ALIGNMENT
    code = bytearray(image.code)
    text_raw = _align(len(code), FILE_ALIGNMENT)
    idata_rva = text_rva + _align(len(code), SECTION_ALIGNMENT)
    sections = [(b".text", len(code), text_rva, text_raw, 0x60000020)]
    idata = b""
    import_dir = iat_dir = (0, 0)
    if image.imports:
        idata, slots, iat_rva, iat_size = _import_section(idata_rva, image.imports)
        for position, library, name in image.imports:
            displacement = slots[(library, name)] - (text_rva + position + 4)
            code[position : position + 4] = displacement.to_bytes(4, "little", signed=True)
        sections.append((b".idata", len(idata), idata_rva, _align(len(idata), FILE_ALIGNMENT), 0xC0000040))
        import_dir = (idata_rva, 20 * (len({lib for _, lib, _ in image.imports}) + 1))
        iat_dir = (iat_rva, iat_size)
    size_of_image = sections[-1][2] + _align(sections[-1][1], SECTION_ALIGNMENT)
    directories = [(0, 0)] * 16
    directories[1] = import_dir
    directories[12] = iat_dir
    optional = struct.pack(
        "<HBBIIIIIQIIHHHHHHIIIIHHQQQQII",
        0x20B, 0, 0, text_raw, sum(s[3] for s in sections[1:]), 0,
        text_rva + image.entry_offset, text_rva, IMAGE_BASE, SECTION_ALIGNMENT, FILE_ALIGNMENT,
        6, 0, 0, 0, 6, 0, 0, size_of_image, HEADERS_SIZE, 0,
        3,  # IMAGE_SUBSYSTEM_WINDOWS_CUI
        0x8160,  # TERMINAL_SERVER_AWARE | NX_COMPAT | DYNAMIC_BASE | HIGH_ENTROPY_VA
        STACK_RESERVE, STACK_COMMIT, 0x100000, 0x1000, 0, 16,
    ) + b"".join(struct.pack("<II", *entry) for entry in directories)
    coff = struct.pack("<HHIIIHH", 0x8664, len(sections), 0, 0, 0, len(optional), 0x0022)
    headers = bytearray(b"MZ" + bytes(0x3A) + struct.pack("<I", 0x40) + b"PE\0\0" + coff + optional)
    raw_offset = HEADERS_SIZE
    for name, virtual_size, rva, raw_size, flags in sections:
        headers += _section(name, virtual_size, rva, raw_size, raw_offset, flags)
        raw_offset += raw_size
    if len(headers) > HEADERS_SIZE:
        fail("XAX.PE.HEADERS", image.target_cid.hex(), "PE-HEADERS-FIT", HEADERS_SIZE, len(headers))
    out = bytes(headers).ljust(HEADERS_SIZE, b"\0") + bytes(code).ljust(text_raw, b"\0")
    if idata:
        out += idata.ljust(_align(len(idata), FILE_ALIGNMENT), b"\0")
    return out
