"""S15e.6a (ADR-336): the APK container (``xax_apk.build_apk``) as an XAX program.

The deterministic stored-entry ZIP every Android package is: the entries sorted by their UTF-8 names, each local
header with the padding extra field (``0xFFFF``) that aligns its data, the CRC-32 of the data, the central directory
and its end record.  The Python front door (``xax_apk.build_apk``) keeps its argument checks (they are host errors, not
diagnostics) and asks this program first; ``XAX_GENERAL_FRONTEND_DIFF=1`` compares the two.

Input (64-bit words): the entry count, then per entry the name's byte count, its bytes (one per word), the UTF-8 flag
(``0x0800`` for a name that is not ASCII, else 0), the alignment, the data's byte count and the data packed eight bytes
to a word (little endian).
Output: the status (1), then at ``IMAGE_AT`` the general programs' image record ``[1, 0, length, bytes packed eight to
a word]``; a declined input (padding past ``0xFFFF``, sizes past ZIP32) leaves the status 0.
"""

from __future__ import annotations

from xax_native import bootstrap_dir
from xax_selfhost_facts import E
from xax_selfhost_general_image import IMAGE_AT
from xax_selfhost_views_backend import NativeProgram, _call

STORE_PATH = bootstrap_dir() / "xax_apk_container.xax"
OUT = IMAGE_AT + 3  # the packed bytes


def put(e: E, byte):
    _call(e, "az_put", byte)


def le(e: E, value, n: int):
    """``n`` little-endian bytes of ``value``."""
    e.var("le_v", value)
    for k in range(n):
        put(e, e.and_(e.udiv(e.p["le_v"], 1 << (8 * k)) if k else e.p["le_v"], 255))


_PROGRAM = NativeProgram(STORE_PATH, "apk-container")
load_apk_program = _PROGRAM.load
OPT_OUT = "XAX_APK_PYTHON"


def apk_with_xax(entries, *, required: bool = False) -> bytes | None:
    """The APK bytes the XAX program writes for checked, sorted-or-not ``ApkEntry`` items, or None where it cannot run or
    declines (unless ``required``)."""
    import xax_native

    native = None if __import__("os").environ.get(OPT_OUT) == "1" else _PROGRAM.native(OPT_OUT)
    data = None
    if native is not None:
        words = [len(entries)]
        for item in entries:
            try:
                name, flags = item.name.encode("ascii"), 0
            except UnicodeEncodeError:
                name, flags = item.name.encode("utf-8"), 0x0800
            words += [len(name), *name, flags, item.alignment, len(item.data)]
            padded = item.data + bytes(-len(item.data) % 8)
            words += [int.from_bytes(padded[k:k + 8], "little") for k in range(0, len(padded), 8)]

        def collect(read):
            (status,) = read(0, 1)
            if status != 1:
                return None
            head = read(IMAGE_AT, 3)
            packed = read(IMAGE_AT + 3, (head[2] + 7) // 8)
            return b"".join(word.to_bytes(8, "little") for word in packed)[:head[2]]

        data = native.run(words, collect)
        if data is None:
            xax_native.declined("apk-container", 1)
    if data is None and required:
        raise RuntimeError("the XAX APK container program is unavailable or declined")
    return data
