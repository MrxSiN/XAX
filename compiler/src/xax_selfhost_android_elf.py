"""S15e.6e (ADR-336): the Android AArch64 shared object container (``xax_android.emit_android_elf``) as an XAX program.

The program takes the compiled AArch64 bundle (its code, its function offsets and its foreign calls) and the export list
and writes the whole ET_DYN as the bootstrap does: the exports sorted by name; the referenced imports sorted and checked
for an unambiguous library per name; the text padded with NOPs to 16 bytes, one PIC thunk per imported name, and every
foreign call patched to a BL to its thunk; the dynamic string table (SONAME, exports, imports, needed libraries), the
one-bucket SysV hash, the dynamic symbols (exports with their exact sizes to the next function, imports undefined), the
GLOB_DAT relocations; the layout (the packed format's RW segment placed after RX in the file, its addresses offset onto a
fresh 16 KiB page); the thunks' ADRP/LDR/BR words; the dynamic section, the program and section headers.  A check the
bootstrap fails (an empty export list, a duplicate export, an unreachable export function, an ambiguous import, a BL or
ADRP out of range, a misaligned GOT slot, an invalid SONAME) makes the program decline.

Input (64-bit words; a byte string is its length, then its bytes packed eight to a word, little endian): the packed
flag, the BSS size, the SONAME, the rodata, the data, the code; the function count and each function's offset (in the
bundle's order); the foreign calls (count; each position, library, name); the exports (count; each name and its
function's index in the bundle, the count for an unknown function).
Output: the status (1), the text offset (word 1), the text size (word 2), the import count (word 3) and the needed
library count (word 4); the image record ``[1, 0, length, bytes packed eight to a word]`` at ``IMAGE_AT``.
"""

from __future__ import annotations

from xax_native import bootstrap_dir
from xax_selfhost_facts import E
from xax_selfhost_general_image import IMAGE_AT
from xax_selfhost_views_backend import NativeProgram

STORE_PATH = bootstrap_dir() / "xax_android_elf.xax"
OUT = IMAGE_AT + 3
PAGE = 0x4000


def at(e: E, base, k):
    return e.ld(e.add(base, k))


def align(e: E, value, alignment: int):
    return e.and_(e.add(value, alignment - 1), (1 << 64) - alignment)


_PROGRAM = NativeProgram(STORE_PATH, "android-elf")
load_android_elf_program = _PROGRAM.load
OPT_OUT = "XAX_ANDROID_ELF_PYTHON"


def elf_with_xax(bundle, exports, *, soname: bytes, rodata: bytes, data: bytes, bss_bytes: int, packed: bool,
                 required: bool = False) -> tuple[bytes, int, int, int, int] | None:
    """``(image, text offset, text size, imports, needed libraries)`` the XAX program writes, or None where it cannot run
    or declines (unless ``required``)."""
    import os

    import xax_native

    def blob(value: bytes) -> list[int]:
        value = bytes(value)
        padded = value + bytes(-len(value) % 8)
        return [len(value), *(int.from_bytes(padded[k:k + 8], "little") for k in range(0, len(padded), 8))]

    cids = [cid for cid, _offset in bundle.function_offsets]
    if len(set(cids)) != len(cids) or bss_bytes < 0:
        return None
    index = {cid: k for k, cid in enumerate(cids)}
    words = [int(bool(packed)), bss_bytes, *blob(soname), *blob(rodata), *blob(data), *blob(bundle.code), len(cids),
             *(offset for _cid, offset in bundle.function_offsets), len(bundle.foreign_calls)]
    for position, library, name in bundle.foreign_calls:
        words += [position, *blob(library), *blob(name)]
    words.append(len(exports))
    for item in exports:
        words += [*blob(item.name), index.get(item.function_cid, len(cids))]
    if any(not 0 <= word < 1 << 64 for word in words):
        return None
    native = None if os.environ.get(OPT_OUT) == "1" else _PROGRAM.native(OPT_OUT)
    result = None
    if native is not None:
        def collect(read):
            status = read(0, 5)
            if status[0] != 1:
                return None
            head = read(IMAGE_AT, 3)
            packed_words = read(IMAGE_AT + 3, (head[2] + 7) // 8)
            return (b"".join(word.to_bytes(8, "little") for word in packed_words)[:head[2]], *status[1:5])

        result = native.run(words, collect)
        if result is None:
            xax_native.declined("android-elf", 1)
    if result is None and required:
        raise RuntimeError("the XAX Android ELF program is unavailable or declined")
    return result
