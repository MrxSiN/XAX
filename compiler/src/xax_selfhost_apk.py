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

from xax_compiler import Operation, x86_64_linux_exec_target
from xax_graph_builder import program_store
from xax_native import bootstrap_dir
from xax_selfhost_facts import E, H_ARENA, H_ARENA_END, NONE, _function
from xax_selfhost_general_image import IMAGE_AT, IMAGE_END
from xax_selfhost_views_backend import _FN, NativeProgram, _call, _ok
from xax_selfhost_x86_64_general import GENERAL_ARENA_AT, GENERAL_ARENA_END

STORE_PATH = bootstrap_dir() / "xax_apk_container.xax"
OUT = IMAGE_AT + 3  # the packed bytes
CRC_POLY = 0xEDB88320
(E_NAME, E_NAMEN, E_FLAGS, E_ALIGN, E_DATA, E_DATAN, E_CRC, E_LOCAL) = range(8)
ENTRY_WORDS = 8


def _bx(e: E, x, y):
    return e.bin(Operation.BIT_XOR, x, y)


def _shift_bytes(e: E, k):
    """``256 ** k`` for ``k`` in 0..7."""
    result = e.c(1)
    for q in range(1, 8):
        result = e.sel(e.eq(k, q), 1 << (8 * q), result)
    return result


def _put_fn(tables):
    """``put(byte)``: the next output byte (the running length is the record's length word)."""
    def build(e: E):
        p = e.p
        e.var("pb_pos", e.ld(IMAGE_AT + 2))
        e.var("pb_at", e.add(OUT, e.udiv(p["pb_pos"], 8)))
        _ok(e, e.lt(p["pb_at"], IMAGE_END))
        e.var("pb_k", e.urem(p["pb_pos"], 8))
        e.if_(e.eq(p["pb_k"], 0), lambda: e.st(p["pb_at"], p["byte"]),
              lambda: e.st(p["pb_at"], e.or_(e.ld(p["pb_at"]), e.mul(p["byte"], _shift_bytes(e, p["pb_k"])))))
        e.st(IMAGE_AT + 2, e.add(p["pb_pos"], 1))
        e.give(1)
    return _function(("byte",), build, tables)


def put(e: E, byte):
    _call(e, "az_put", byte)


def le(e: E, value, n: int):
    """``n`` little-endian bytes of ``value``."""
    e.var("le_v", value)
    for k in range(n):
        put(e, e.and_(e.udiv(e.p["le_v"], 1 << (8 * k)) if k else e.p["le_v"], 255))


def _data_byte(e: E, at, k):
    """Byte ``k`` of the packed input data at word ``at``."""
    return e.and_(e.udiv(e.rd(e.add(at, e.udiv(k, 8))), _shift_bytes(e, e.urem(k, 8))), 255)


def _crc_fn(tables):
    """``crc(at, n)``: the CRC-32 of the ``n`` packed input bytes at word ``at``."""
    def build(e: E):
        p = e.p
        e.var("cr_c", 0xFFFFFFFF)

        def byte():
            e.set("cr_c", _bx(e, p["cr_c"], _data_byte(e, p["at"], p["cr_k"])))
            for _ in range(8):
                e.set("cr_c", _bx(e, e.udiv(p["cr_c"], 2), e.sel(e.ne(e.and_(p["cr_c"], 1), 0), CRC_POLY, 0)))

        e.for_("cr_k", 0, p["n"], byte)
        e.give(_bx(e, p["cr_c"], 0xFFFFFFFF))
    return _function(("at", "n"), build, tables)


def _copy_fn(tables):
    """``copy(at, n)``: the ``n`` packed input bytes at word ``at`` to the output."""
    def build(e: E):
        p = e.p
        e.for_("cp_k", 0, p["n"], lambda: put(e, _data_byte(e, p["at"], p["cp_k"])))
        e.give(1)
    return _function(("at", "n"), build, tables)


def _less_fn(tables):
    """1 when entry record ``a``'s name sorts before ``b``'s (bytes; a prefix first)."""
    def build(e: E):
        p = e.p
        e.var("ls_an", e.ld(e.add(p["a"], E_NAMEN)))
        e.var("ls_bn", e.ld(e.add(p["b"], E_NAMEN)))
        e.var("ls_n", e.sel(e.lt(p["ls_an"], p["ls_bn"]), p["ls_an"], p["ls_bn"]))

        def compare():
            e.var("ls_x", e.rd(e.add(e.ld(e.add(p["a"], E_NAME)), p["ls_k"])))
            e.var("ls_y", e.rd(e.add(e.ld(e.add(p["b"], E_NAME)), p["ls_k"])))
            e.if_(e.lt(p["ls_x"], p["ls_y"]), lambda: e.give(1))
            e.if_(e.lt(p["ls_y"], p["ls_x"]), lambda: e.give(0))

        e.for_("ls_k", 0, p["ls_n"], compare)
        e.give(e.flag(e.lt(p["ls_an"], p["ls_bn"])))
    return _function(("a", "b"), build, tables)


def _frontend(tables):
    def build(e: E):
        p = e.p
        e.st(0, 0)
        e.set_hd(H_ARENA, GENERAL_ARENA_AT)
        e.set_hd(H_ARENA_END, GENERAL_ARENA_END)
        e.var("n", e.rd(0))
        _ok(e, e.both(e.lt(0, p["n"]), e.le(p["n"], 0xFFFF)))
        e.var("records", e.alloc(e.add(e.mul(p["n"], ENTRY_WORDS), 1)))
        e.var("order", e.alloc(e.add(p["n"], 1)))
        _ok(e, e.both(e.ne(p["records"], NONE), e.ne(p["order"], NONE)))
        e.var("at", 1)

        def parse():
            e.var("r", e.add(p["records"], e.mul(p["q"], ENTRY_WORDS)))
            e.var("nn", e.rd(p["at"]))
            e.st(e.add(p["r"], E_NAMEN), p["nn"])
            e.st(e.add(p["r"], E_NAME), e.add(p["at"], 1))
            e.set("at", e.add(e.add(p["at"], 1), p["nn"]))
            e.st(e.add(p["r"], E_FLAGS), e.rd(p["at"]))
            e.st(e.add(p["r"], E_ALIGN), e.rd(e.add(p["at"], 1)))
            e.var("dn", e.rd(e.add(p["at"], 2)))
            _ok(e, e.le(p["dn"], 0xFFFFFFFF))  # ZIP64 is intentionally unsupported
            e.st(e.add(p["r"], E_DATAN), p["dn"])
            e.st(e.add(p["r"], E_DATA), e.add(p["at"], 3))
            e.set("at", e.add(e.add(p["at"], 3), e.udiv(e.add(p["dn"], 7), 8)))
            e.st(e.add(p["order"], p["q"]), p["r"])

        e.for_("q", 0, p["n"], parse)

        # ``sorted(entries, key=name.encode("utf-8"))``: stable insertion by the names' bytes.
        def insert():
            e.var("item", e.ld(e.add(p["order"], p["s"])))
            e.var("j", p["s"])
            before = lambda: e.both(e.lt(0, p["j"]), e.ne(_call(e, "az_less", p["item"], e.ld(e.add(p["order"], e.sub(p["j"], 1)))), 0))  # noqa: E731
            e.while_(before, lambda: (e.st(e.add(p["order"], p["j"]), e.ld(e.add(p["order"], e.sub(p["j"], 1)))), e.set("j", e.sub(p["j"], 1))))
            e.st(e.add(p["order"], p["j"]), p["item"])

        e.for_("s", 1, p["n"], insert)
        e.st(IMAGE_AT + 2, 0)

        def local():
            e.var("r", e.ld(e.add(p["order"], p["q"])))
            r = p["r"]
            f = lambda field: e.ld(e.add(r, field))  # noqa: E731
            e.var("crc", _call(e, "az_crc", f(E_DATA), f(E_DATAN)))
            e.st(e.add(r, E_CRC), p["crc"])
            e.var("offset", e.ld(IMAGE_AT + 2))
            _ok(e, e.le(p["offset"], 0xFFFFFFFF))
            e.st(e.add(r, E_LOCAL), p["offset"])
            e.var("base", e.add(e.add(p["offset"], 30), f(E_NAMEN)))
            e.var("align", f(E_ALIGN))
            e.var("needed", e.urem(e.sub(p["align"], e.urem(p["base"], p["align"])), p["align"]))
            e.var("total", p["needed"])
            e.if_(e.both(e.ne(p["total"], 0), e.lt(p["total"], 4)), lambda: e.set("total", e.add(p["total"], p["align"])))
            # Padding past the extra field's capacity, or shorter than its own header (an alignment of 2): the bootstrap's
            # error.
            _ok(e, e.both(e.le(p["total"], 0xFFFF), e.either(e.eq(p["total"], 0), e.le(4, p["total"]))))
            for value, n in ((0x04034B50, 4), (20, 2), (f(E_FLAGS), 2), (0, 2), (0, 2), (0x0021, 2), (p["crc"], 4), (f(E_DATAN), 4), (f(E_DATAN), 4),
                             (f(E_NAMEN), 2), (p["total"], 2)):
                le(e, value, n)
            e.for_("k", 0, f(E_NAMEN), lambda: put(e, e.rd(e.add(f(E_NAME), p["k"]))))

            def extra():
                le(e, 0xFFFF, 2)
                le(e, e.sub(p["total"], 4), 2)
                e.for_("k", 0, e.sub(p["total"], 4), lambda: put(e, 0))

            e.if_(e.ne(p["total"], 0), extra)
            _call(e, "az_copy", f(E_DATA), f(E_DATAN))

        e.for_("q", 0, p["n"], local)
        e.var("central", e.ld(IMAGE_AT + 2))

        def central():
            e.var("r", e.ld(e.add(p["order"], p["q"])))
            r = p["r"]
            f = lambda field: e.ld(e.add(r, field))  # noqa: E731
            for value, n in ((0x02014B50, 4), (20, 2), (20, 2), (f(E_FLAGS), 2), (0, 2), (0, 2), (0x0021, 2), (f(E_CRC), 4), (f(E_DATAN), 4),
                             (f(E_DATAN), 4), (f(E_NAMEN), 2), (0, 2), (0, 2), (0, 2), (0, 2), (0, 4), (f(E_LOCAL), 4)):
                le(e, value, n)
            e.for_("k", 0, f(E_NAMEN), lambda: put(e, e.rd(e.add(f(E_NAME), p["k"]))))

        e.for_("q", 0, p["n"], central)
        e.var("central_size", e.sub(e.ld(IMAGE_AT + 2), p["central"]))
        _ok(e, e.le(p["central"], 0xFFFFFFFF))
        for value, n in ((0x06054B50, 4), (0, 2), (0, 2), (p["n"], 2), (p["n"], 2), (p["central_size"], 4), (p["central"], 4), (0, 2)):
            le(e, value, n)
        e.st(IMAGE_AT, 1)
        e.st(IMAGE_AT + 1, 0)
        e.st(0, 1)
        e.give(1)
    return _function((), build, tables)


def build_apk_program():
    """``(reader, function)``: the APK container program's store and its entry."""
    tables = None
    objects: list = []
    _FN.clear()

    def add(name, made):
        function, items = made
        objects.extend(items)
        _FN[name] = function
        return function

    for name, builder in (("az_put", _put_fn), ("az_crc", _crc_fn), ("az_copy", _copy_fn), ("az_less", _less_fn)):
        add(name, builder(tables))
    program = add("frontend", _frontend(tables))
    return program_store(program, x86_64_linux_exec_target(), tuple(objects)), program


_PROGRAM = NativeProgram(STORE_PATH, build_apk_program, "apk-container")
load_apk_program = _PROGRAM.load
write_apk_store = _PROGRAM.write
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
