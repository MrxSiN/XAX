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

from xax_compiler import x86_64_linux_exec_target
from xax_graph_builder import program_store
from xax_native import bootstrap_dir
from xax_selfhost_facts import E, H_ARENA, H_ARENA_END, NONE, _function
from xax_selfhost_general_image import IMAGE_AT, IMAGE_END
from xax_selfhost_views_backend import _FN, NativeProgram, _call, _ok
from xax_selfhost_x86_64_general import GENERAL_ARENA_AT, GENERAL_ARENA_END

STORE_PATH = bootstrap_dir() / "xax_android_elf.xax"
OUT = IMAGE_AT + 3
STATE_AT = 110 << 20
(G_CUR, G_OUT, G_CAP, G_TXT, G_TN, G_TCAP, G_STR, G_NSTR, G_SOFF, G_STRN) = (STATE_AT + k for k in range(10))
PAGE = 0x4000
NOP = 0xD503201F
SECTIONS = (b".hash", b".dynsym", b".dynstr", b".rela.dyn", b".text", b".rodata", b".got", b".data", b".bss", b".dynamic", b".shstrtab")


def _shstrtab() -> tuple[bytes, dict[bytes, int]]:
    out, names = bytearray(b"\x00"), {}
    for item in SECTIONS:
        names[item] = len(out)
        out.extend(item + b"\x00")
    return bytes(out), names


SHSTRTAB, SH_NAME = _shstrtab()


def _shift_bytes(e: E, k):
    result = e.c(1)
    for q in range(1, 8):
        result = e.sel(e.eq(k, q), 1 << (8 * q), result)
    return result


def at(e: E, base, k):
    return e.ld(e.add(base, k))


def _down(e: E, j: str, test, body):
    """``while j > 0 and test(): body()``, with ``test`` evaluated only while ``j > 0``."""
    go = f"{j}_go"
    e.var(go, 1)
    e.while_(lambda: e.ne(e.p[go], 0), lambda: e.if_(e.eq(e.p[j], 0), lambda: e.set(go, 0),
                                                       lambda: e.if_(e.ne(test(), 0), body, lambda: e.set(go, 0))))


def _word_fn(tables):
    def build(e: E):
        p = e.p
        e.var("wd_at", e.ld(G_CUR))
        e.st(G_CUR, e.add(p["wd_at"], 1))
        e.give(e.rd(p["wd_at"]))
    return _function((), build, tables)


def _bytes_fn(tables):
    """``bytes()``: the packed input byte string at the cursor, unpacked one byte per word into the arena (its handle
    ``[n, bytes...]``), the cursor moved past it."""
    def build(e: E):
        p = e.p
        e.var("bs_at", e.ld(G_CUR))
        e.var("bs_n", e.rd(p["bs_at"]))
        _ok(e, e.le(p["bs_n"], 1 << 26))
        e.var("bs_h", e.alloc(e.add(p["bs_n"], 1)))
        _ok(e, e.ne(p["bs_h"], NONE))
        e.st(p["bs_h"], p["bs_n"])
        e.for_("bs_k", 0, p["bs_n"], lambda: e.st(e.add(e.add(p["bs_h"], 1), p["bs_k"]), e.and_(
            e.udiv(e.rd(e.add(e.add(p["bs_at"], 1), e.udiv(p["bs_k"], 8))), _shift_bytes(e, e.urem(p["bs_k"], 8))), 255)))
        e.st(G_CUR, e.add(e.add(p["bs_at"], 1), e.udiv(e.add(p["bs_n"], 7), 8)))
        e.give(p["bs_h"])
    return _function((), build, tables)


def _less_fn(tables):
    """1 when byte string ``a`` sorts before ``b`` (a prefix first)."""
    def build(e: E):
        p = e.p
        e.var("ls_an", e.ld(p["a"]))
        e.var("ls_bn", e.ld(p["b"]))
        e.var("ls_n", e.sel(e.lt(p["ls_an"], p["ls_bn"]), p["ls_an"], p["ls_bn"]))

        def compare():
            e.var("ls_x", e.ld(e.add(e.add(p["a"], 1), p["ls_k"])))
            e.var("ls_y", e.ld(e.add(e.add(p["b"], 1), p["ls_k"])))
            e.if_(e.lt(p["ls_x"], p["ls_y"]), lambda: e.give(1))
            e.if_(e.lt(p["ls_y"], p["ls_x"]), lambda: e.give(0))

        e.for_("ls_k", 0, p["ls_n"], compare)
        e.give(e.flag(e.lt(p["ls_an"], p["ls_bn"])))
    return _function(("a", "b"), build, tables)


def _same_fn(tables):
    def build(e: E):
        p = e.p
        e.if_(e.ne(e.ld(p["a"]), e.ld(p["b"])), lambda: e.give(0))
        e.for_("sm_k", 1, e.add(e.ld(p["a"]), 1),
               lambda: e.if_(e.ne(e.ld(e.add(p["a"], p["sm_k"])), e.ld(e.add(p["b"], p["sm_k"]))), lambda: e.give(0)))
        e.give(1)
    return _function(("a", "b"), build, tables)


def _pair_less_fn(tables):
    """1 when record ``a`` sorts before ``b`` by its first string, then its second (``second`` 0: the first only)."""
    def build(e: E):
        p = e.p
        e.if_(e.ne(_call(e, "ae_less", e.ld(p["a"]), e.ld(p["b"])), 0), lambda: e.give(1))
        e.if_(e.ne(_call(e, "ae_less", e.ld(p["b"]), e.ld(p["a"])), 0), lambda: e.give(0))
        e.if_(e.eq(p["second"], 0), lambda: e.give(0))
        e.give(_call(e, "ae_less", at(e, p["a"], 1), at(e, p["b"], 1)))
    return _function(("a", "b", "second"), build, tables)


def _sort_fn(tables):
    """``sort(arr, n, second)``: the ``n`` record pointers at ``arr`` sorted (stable insertion) by ``pairless``."""
    def build(e: E):
        p = e.p

        def insert():
            e.var("so_item", e.ld(e.add(p["arr"], p["so_s"])))
            e.var("so_j", p["so_s"])
            _down(e, "so_j", lambda: _call(e, "ae_pairless", p["so_item"], e.ld(e.add(p["arr"], e.sub(p["so_j"], 1))), p["second"]),
                  lambda: (e.st(e.add(p["arr"], p["so_j"]), e.ld(e.add(p["arr"], e.sub(p["so_j"], 1)))), e.set("so_j", e.sub(p["so_j"], 1))))
            e.st(e.add(p["arr"], p["so_j"]), p["so_item"])

        e.for_("so_s", 1, p["n"], insert)
        e.give(1)
    return _function(("arr", "n", "second"), build, tables)


def _string_offset_fn(tables):
    """``soff(h)``: the dynamic string table offset of ``h`` (appended on first use; the empty string is 0)."""
    def build(e: E):
        p = e.p
        e.if_(e.eq(e.ld(p["h"]), 0), lambda: e.give(0))
        e.for_("so_k", 1, e.add(e.ld(p["h"]), 1), lambda: _ok(e, e.ne(e.ld(e.add(p["h"], p["so_k"])), 0)))  # NUL-free
        e.for_("so_k", 0, e.ld(G_NSTR), lambda: e.if_(e.ne(_call(e, "ae_same", p["h"], e.ld(e.add(e.ld(G_STR), p["so_k"]))), 0),
                                                       lambda: e.give(e.ld(e.add(e.ld(G_SOFF), p["so_k"])))))
        e.var("so_n", e.ld(G_NSTR))
        _ok(e, e.lt(p["so_n"], 1 << 16))
        e.st(e.add(e.ld(G_STR), p["so_n"]), p["h"])
        e.var("so_at", e.ld(G_STRN))
        e.st(e.add(e.ld(G_SOFF), p["so_n"]), p["so_at"])
        e.st(G_NSTR, e.add(p["so_n"], 1))
        e.st(G_STRN, e.add(e.add(p["so_at"], e.ld(p["h"])), 1))
        e.give(p["so_at"])
    return _function(("h",), build, tables)


def _set_fn(tables):
    """``set(pos, value, n)``: ``n`` little-endian bytes of ``value`` into the output at ``pos``."""
    def build(e: E):
        p = e.p
        _ok(e, e.le(e.add(p["pos"], p["n"]), e.ld(G_CAP)))
        e.var("st_v", p["value"])
        e.for_("st_k", 0, p["n"], lambda: (e.st(e.add(e.ld(G_OUT), e.add(p["pos"], p["st_k"])), e.and_(p["st_v"], 255)), e.set("st_v", e.udiv(p["st_v"], 256))))
        e.give(1)
    return _function(("pos", "value", "n"), build, tables)


def _copy_fn(tables):
    """``copy(pos, h)``: the byte string ``h`` into the output at ``pos``."""
    def build(e: E):
        p = e.p
        _ok(e, e.le(e.add(p["pos"], e.ld(p["h"])), e.ld(G_CAP)))
        e.for_("cp_k", 0, e.ld(p["h"]), lambda: e.st(e.add(e.ld(G_OUT), e.add(p["pos"], p["cp_k"])), e.ld(e.add(e.add(p["h"], 1), p["cp_k"]))))
        e.give(1)
    return _function(("pos", "h"), build, tables)


def _text_word_fn(tables):
    """``tword(pos, value)``: four little-endian bytes into the text at ``pos`` (appended at its end)."""
    def build(e: E):
        p = e.p
        _ok(e, e.le(e.add(p["pos"], 4), e.ld(G_TCAP)))
        e.var("tw_v", p["value"])
        e.for_("tw_k", 0, 4, lambda: (e.st(e.add(e.ld(G_TXT), e.add(p["pos"], p["tw_k"])), e.and_(p["tw_v"], 255)), e.set("tw_v", e.udiv(p["tw_v"], 256))))
        e.if_(e.lt(e.ld(G_TN), e.add(p["pos"], 4)), lambda: e.st(G_TN, e.add(p["pos"], 4)))
        e.give(1)
    return _function(("pos", "value"), build, tables)


def align(e: E, value, alignment: int):
    return e.and_(e.add(value, alignment - 1), (1 << 64) - alignment)


def _frontend(tables):
    def build(e: E):
        p = e.p
        word = lambda: _call(e, "ae_word")  # noqa: E731
        data = lambda: _call(e, "ae_bytes")  # noqa: E731
        put = lambda pos, value, n: _call(e, "ae_set", pos, value, n)  # noqa: E731
        e.st(0, 0)
        e.set_hd(H_ARENA, GENERAL_ARENA_AT)
        e.set_hd(H_ARENA_END, GENERAL_ARENA_END)
        e.st(G_CUR, 0)
        e.var("packed", word())
        e.var("bss", word())
        _ok(e, e.lt(p["bss"], 1 << 40))
        e.var("soname", data())
        e.var("rodata", data())
        e.var("data", data())
        e.var("code", data())
        e.var("code_n", e.ld(p["code"]))
        _ok(e, e.eq(e.urem(p["code_n"], 4), 0))
        e.var("nfn", word())
        _ok(e, e.le(p["nfn"], 1 << 20))
        e.var("fn", e.alloc(e.add(p["nfn"], 1)))
        _ok(e, e.ne(p["fn"], NONE))
        e.for_("q", 0, p["nfn"], lambda: e.st(e.add(p["fn"], p["q"]), word()))
        e.var("nfc", word())
        _ok(e, e.le(p["nfc"], 1 << 20))
        e.var("calls", e.alloc(e.add(e.mul(p["nfc"], 3), 1)))
        e.var("pairs", e.alloc(e.add(p["nfc"], 1)))
        _ok(e, e.both(e.ne(p["calls"], NONE), e.ne(p["pairs"], NONE)))

        def call():
            e.var("cr", e.add(p["calls"], e.mul(p["q"], 3)))
            e.st(e.add(p["cr"], 2), word())  # the position; the record's first words are the library and the name (sorting)
            e.st(p["cr"], data())
            e.st(e.add(p["cr"], 1), data())
            e.st(e.add(p["pairs"], p["q"]), p["cr"])

        e.for_("q", 0, p["nfc"], call)
        e.var("nex", word())
        _ok(e, e.both(e.lt(0, p["nex"]), e.le(p["nex"], 1 << 16)))  # at least one explicit export
        e.var("exports", e.alloc(e.add(e.mul(p["nex"], 2), 1)))
        e.var("order", e.alloc(e.add(p["nex"], 1)))
        _ok(e, e.both(e.ne(p["exports"], NONE), e.ne(p["order"], NONE)))

        def export():
            e.var("er", e.add(p["exports"], e.mul(p["q"], 2)))
            e.st(p["er"], data())
            e.var("efn", word())
            _ok(e, e.lt(p["efn"], p["nfn"]))  # a compiled function
            e.st(e.add(p["er"], 1), p["efn"])
            e.st(e.add(p["order"], p["q"]), p["er"])

        e.for_("q", 0, p["nex"], export)
        _ok(e, e.ne(e.ld(p["soname"]), 0))
        _call(e, "ae_sort", p["order"], p["nex"], 0)
        e.for_("q", 1, p["nex"], lambda: _ok(e, e.eq(_call(e, "ae_same", e.ld(e.ld(e.add(p["order"], p["q"]))),
                                                                  e.ld(e.ld(e.add(p["order"], e.sub(p["q"], 1))))), 0)))  # no duplicate
        # The referenced imports: (library, name) sorted, distinct; one library per name.
        _call(e, "ae_sort", p["pairs"], p["nfc"], 1)
        e.var("refs", e.alloc(e.add(p["nfc"], 1)))
        _ok(e, e.ne(p["refs"], NONE))
        e.var("nrefs", 0)

        def distinct():
            e.var("pr", e.ld(e.add(p["pairs"], p["q"])))

            def fresh():
                e.var("pv", e.ld(e.add(p["refs"], e.sub(p["nrefs"], 1))))
                return e.flag(e.either(e.eq(_call(e, "ae_same", e.ld(p["pr"]), e.ld(p["pv"])), 0), e.eq(_call(e, "ae_same", at(e, p["pr"], 1), at(e, p["pv"], 1)), 0)))

            e.var("isnew", 1)
            e.if_(e.ne(p["nrefs"], 0), lambda: e.set("isnew", fresh()))
            e.if_(e.ne(p["isnew"], 0), lambda: (e.st(e.add(p["refs"], p["nrefs"]), p["pr"]), e.set("nrefs", e.add(p["nrefs"], 1))))

        e.for_("q", 0, p["nfc"], distinct)
        e.for_("q", 0, p["nrefs"], lambda: e.for_("j", 0, p["q"], lambda: _ok(e, e.either(
            e.eq(_call(e, "ae_same", at(e, e.ld(e.add(p["refs"], p["q"])), 1), at(e, e.ld(e.add(p["refs"], p["j"])), 1)), 0),
            e.ne(_call(e, "ae_same", e.ld(e.ld(e.add(p["refs"], p["q"]))), e.ld(e.ld(e.add(p["refs"], p["j"])))), 0)))))
        # The import names and the needed libraries, each sorted and distinct.
        e.var("names", e.alloc(e.add(p["nrefs"], 1)))
        e.var("libs", e.alloc(e.add(p["nrefs"], 1)))
        _ok(e, e.both(e.ne(p["names"], NONE), e.ne(p["libs"], NONE)))
        e.var("nimp", 0)
        e.var("nlib", 0)

        def unique(arr, count, word_index):
            def each():
                e.var("uh", at(e, e.ld(e.add(p["refs"], p["q"])), word_index))
                e.var("seen", 0)
                e.for_("j", 0, p[count], lambda: e.if_(e.ne(_call(e, "ae_same", e.ld(e.ld(e.add(p[arr], p["j"]))), p["uh"]), 0), lambda: e.set("seen", 1)))

                def add():
                    e.var("ur", e.alloc(1))
                    _ok(e, e.ne(p["ur"], NONE))
                    e.st(p["ur"], p["uh"])
                    e.st(e.add(p[arr], p[count]), p["ur"])
                    e.set(count, e.add(p[count], 1))

                e.if_(e.eq(p["seen"], 0), add)

            e.for_("q", 0, p["nrefs"], each)
            _call(e, "ae_sort", p[arr], p[count], 0)

        unique("names", "nimp", 1)
        unique("libs", "nlib", 0)

        # The text: the code, NOPs to 16 bytes, one thunk per imported name (in the referenced order).
        e.st(G_TCAP, e.add(e.add(p["code_n"], 16), e.mul(p["nrefs"], 12)))
        e.st(G_TXT, e.alloc(e.add(e.ld(G_TCAP), 1)))
        _ok(e, e.ne(e.ld(G_TXT), NONE))
        e.for_("q", 0, p["code_n"], lambda: e.st(e.add(e.ld(G_TXT), p["q"]), e.ld(e.add(e.add(p["code"], 1), p["q"]))))
        e.st(G_TN, p["code_n"])
        e.while_(lambda: e.ne(e.urem(e.ld(G_TN), 16), 0), lambda: _call(e, "ae_tword", e.ld(G_TN), NOP))
        e.var("thunks", e.alloc(e.add(e.mul(p["nrefs"], 2), 1)))
        _ok(e, e.ne(p["thunks"], NONE))
        e.var("nth", 0)

        def thunk():
            e.var("tn", at(e, e.ld(e.add(p["refs"], p["q"])), 1))
            e.var("seen", 0)
            e.for_("j", 0, p["nth"], lambda: e.if_(e.ne(_call(e, "ae_same", at(e, p["thunks"], e.mul(p["j"], 2)), p["tn"]), 0), lambda: e.set("seen", 1)))

            def add():
                e.st(e.add(p["thunks"], e.mul(p["nth"], 2)), p["tn"])
                e.st(e.add(e.add(p["thunks"], e.mul(p["nth"], 2)), 1), e.ld(G_TN))
                e.for_("j", 0, 3, lambda: _call(e, "ae_tword", e.ld(G_TN), 0))
                e.set("nth", e.add(p["nth"], 1))

            e.if_(e.eq(p["seen"], 0), add)

        e.for_("q", 0, p["nrefs"], thunk)

        def thunk_of(name):
            e.var("to_off", NONE)
            e.for_("j", 0, p["nth"], lambda: e.if_(e.ne(_call(e, "ae_same", at(e, p["thunks"], e.mul(p["j"], 2)), name), 0),
                                                    lambda: e.set("to_off", at(e, p["thunks"], e.add(e.mul(p["j"], 2), 1)))))
            return p["to_off"]

        def patch():
            e.var("cr", e.add(p["calls"], e.mul(p["q"], 3)))
            e.var("pos", at(e, p["cr"], 2))
            e.var("disp", e.sub(thunk_of(at(e, p["cr"], 1)), p["pos"]))
            _ok(e, e.both(e.eq(e.and_(p["disp"], 3), 0), e.lt(e.add(p["disp"], 1 << 27), 1 << 28)))
            e.var("negative", e.flag(e.le(1 << 63, p["disp"])))
            e.var("units", e.sel(e.ne(p["negative"], 0), e.sub(0, e.udiv(e.sub(0, p["disp"]), 4)), e.udiv(p["disp"], 4)))
            _ok(e, e.le(e.add(p["pos"], 4), e.ld(G_TN)))
            _call(e, "ae_tword", p["pos"], e.or_(0x94000000, e.and_(p["units"], 0x3FFFFFF)))

        e.for_("q", 0, p["nfc"], patch)
        e.var("text_n", e.ld(G_TN))

        # The dynamic strings and the layout.
        e.st(G_STR, e.alloc(1 << 16))
        e.st(G_SOFF, e.alloc(1 << 16))
        _ok(e, e.both(e.ne(e.ld(G_STR), NONE), e.ne(e.ld(G_SOFF), NONE)))
        e.st(G_NSTR, 0)
        e.st(G_STRN, 1)
        soff = lambda h: _call(e, "ae_soff", h)  # noqa: E731
        soff(p["soname"])
        e.for_("q", 0, p["nex"], lambda: soff(e.ld(e.ld(e.add(p["order"], p["q"])))))
        e.for_("q", 0, p["nimp"], lambda: soff(e.ld(e.ld(e.add(p["names"], p["q"])))))
        e.for_("q", 0, p["nlib"], lambda: soff(e.ld(e.ld(e.add(p["libs"], p["q"])))))
        e.var("dynstr_n", e.ld(G_STRN))
        e.var("nsym", e.add(e.add(1, p["nex"]), p["nimp"]))
        e.var("hash_n", e.add(12, e.mul(p["nsym"], 4)))
        e.var("hash_off", align(e, 64 + 4 * 56, 8))
        e.var("dynsym_off", align(e, e.add(p["hash_off"], p["hash_n"]), 8))
        e.var("dynstr_off", e.add(p["dynsym_off"], e.mul(p["nsym"], 24)))
        e.var("rela_off", align(e, e.add(p["dynstr_off"], p["dynstr_n"]), 8))
        e.var("rela_n", e.mul(p["nimp"], 24))
        e.var("text_off", align(e, e.add(p["rela_off"], p["rela_n"]), 16))
        e.var("rodata_off", align(e, e.add(p["text_off"], p["text_n"]), 16))
        e.var("rx_end", e.add(p["rodata_off"], e.ld(p["rodata"])))
        e.var("rw_off", e.sel(e.ne(p["packed"], 0), align(e, p["rx_end"], 8), align(e, p["rx_end"], PAGE)))
        e.var("delta", e.sel(e.ne(p["packed"], 0), e.sub(align(e, p["rx_end"], PAGE), e.sub(p["rw_off"], e.urem(p["rw_off"], PAGE))), 0))
        e.var("got_off", p["rw_off"])
        e.var("got_n", e.mul(p["nimp"], 8))
        e.var("data_off", align(e, e.add(p["got_off"], p["got_n"]), 8))
        e.var("dyn_count", e.add(e.add(7, p["nlib"]), e.sel(e.ne(p["nimp"], 0), 3, 0)))
        e.var("dynamic_off", align(e, e.add(p["data_off"], e.ld(p["data"])), 8))
        e.var("dynamic_n", e.mul(p["dyn_count"], 16))
        e.var("rw_file_end", e.add(p["dynamic_off"], p["dynamic_n"]))
        e.var("bss_off", align(e, p["rw_file_end"], 8))
        e.var("rw_mem_end", e.add(p["bss_off"], p["bss"]))
        e.var("got_addr", e.add(p["got_off"], p["delta"]))
        e.var("dynamic_addr", e.add(p["dynamic_off"], p["delta"]))
        e.var("shstr_off", p["rw_file_end"])
        e.var("shoff", align(e, e.add(p["shstr_off"], len(SHSTRTAB)), 8))
        e.var("size", e.add(p["shoff"], 12 * 64))

        # The thunks: ADRP x16, the GOT page; LDR x16, [x16, the slot's page offset]; BR x16.
        def thunk_words():
            e.var("tname", at(e, p["thunks"], e.mul(p["q"], 2)))
            e.var("toff", at(e, p["thunks"], e.add(e.mul(p["q"], 2), 1)))
            e.var("slot", NONE)
            e.for_("j", 0, p["nimp"], lambda: e.if_(e.ne(_call(e, "ae_same", e.ld(e.ld(e.add(p["names"], p["j"]))), p["tname"]), 0), lambda: e.set("slot", p["j"])))
            e.var("target", e.add(p["got_addr"], e.mul(p["slot"], 8)))
            e.var("pc", e.add(p["text_off"], p["toff"]))
            e.var("pages", e.sub(e.udiv(p["target"], 4096), e.udiv(p["pc"], 4096)))  # the signed page delta
            _ok(e, e.lt(e.add(p["pages"], 1 << 20), 1 << 21))
            e.var("imm", e.and_(p["pages"], 0x1FFFFF))
            _call(e, "ae_tword", p["toff"], e.or_(e.or_(0x90000000, e.mul(e.and_(p["imm"], 3), 1 << 29)), e.or_(e.mul(e.and_(e.udiv(p["imm"], 4), 0x7FFFF), 32), 16)))
            e.var("page_off", e.and_(p["target"], 0xFFF))
            _ok(e, e.eq(e.and_(p["page_off"], 7), 0))
            _call(e, "ae_tword", e.add(p["toff"], 4), e.or_(0xF9400000, e.or_(e.mul(e.udiv(p["page_off"], 8), 1024), (16 << 5) | 16)))
            _call(e, "ae_tword", e.add(p["toff"], 8), 0xD61F0000 | (16 << 5))

        e.for_("q", 0, p["nth"], thunk_words)

        # The output, zeroed.
        e.st(G_CAP, p["size"])
        _ok(e, e.le(p["size"], 1 << 26))
        e.st(G_OUT, e.alloc(e.add(p["size"], 1)))
        _ok(e, e.ne(e.ld(G_OUT), NONE))
        e.for_("q", 0, p["size"], lambda: e.st(e.add(e.ld(G_OUT), p["q"]), 0))
        for k, byte in enumerate(b"\x7fELF" + bytes((2, 1, 1))):
            put(k, byte, 1)
        for pos, value, n in ((16, 3, 2), (18, 183, 2), (20, 1, 4), (24, 0, 8), (32, 64, 8), (40, p["shoff"], 8), (48, 0, 4), (52, 64, 2), (54, 56, 2),
                              (56, 4, 2), (58, 64, 2), (60, 12, 2), (62, 11, 2)):
            put(pos, value, n)

        def program_header(k, kind, flags, offset, address, filesz, memsz, alignment):
            base = 64 + 56 * k
            for pos, value, n in ((0, kind, 4), (4, flags, 4), (8, offset, 8), (16, address, 8), (24, address, 8), (32, filesz, 8), (40, memsz, 8), (48, alignment, 8)):
                put(base + pos, value, n)

        program_header(0, 1, 4 | 1, 0, 0, p["rx_end"], p["rx_end"], PAGE)
        program_header(1, 1, 4 | 2, p["rw_off"], e.add(p["rw_off"], p["delta"]), e.sub(p["rw_file_end"], p["rw_off"]), e.sub(p["rw_mem_end"], p["rw_off"]), PAGE)
        program_header(2, 2, 4 | 2, p["dynamic_off"], p["dynamic_addr"], p["dynamic_n"], p["dynamic_n"], 8)
        program_header(3, 0x6474E551, 4 | 2, 0, 0, 0, 0, 16)
        # The hash: one bucket (the first symbol), each symbol chained to the next.
        put(p["hash_off"], 1, 4)
        put(e.add(p["hash_off"], 4), p["nsym"], 4)
        put(e.add(p["hash_off"], 8), e.sel(e.lt(1, p["nsym"]), 1, 0), 4)
        e.for_("q", 1, e.sub(p["nsym"], 1), lambda: put(e.add(e.add(p["hash_off"], 12), e.mul(p["q"], 4)), e.add(p["q"], 1), 4))
        # The dynamic symbols: exports (sized to the next function start), then the undefined imports.
        e.var("sorted_fn", e.alloc(e.add(p["nfn"], 1)))
        e.var("fn_size", e.alloc(e.add(p["nfn"], 1)))
        _ok(e, e.both(e.ne(p["sorted_fn"], NONE), e.ne(p["fn_size"], NONE)))
        e.for_("q", 0, p["nfn"], lambda: e.st(e.add(p["sorted_fn"], p["q"]), p["q"]))

        def by_offset():
            e.var("bi", e.ld(e.add(p["sorted_fn"], p["q"])))
            e.var("bj", p["q"])
            _down(e, "bj", lambda: e.flag(e.lt(e.ld(e.add(p["fn"], p["bi"])), e.ld(e.add(p["fn"], e.ld(e.add(p["sorted_fn"], e.sub(p["bj"], 1))))))),
                  lambda: (e.st(e.add(p["sorted_fn"], p["bj"]), e.ld(e.add(p["sorted_fn"], e.sub(p["bj"], 1)))), e.set("bj", e.sub(p["bj"], 1))))
            e.st(e.add(p["sorted_fn"], p["bj"]), p["bi"])

        e.for_("q", 1, p["nfn"], by_offset)

        def sizes():
            e.var("si", e.ld(e.add(p["sorted_fn"], p["q"])))
            e.var("end", p["code_n"])
            e.if_(e.lt(e.add(p["q"], 1), p["nfn"]), lambda: e.set("end", e.ld(e.add(p["fn"], e.ld(e.add(p["sorted_fn"], e.add(p["q"], 1)))))))
            e.var("start", e.ld(e.add(p["fn"], p["si"])))
            e.st(e.add(p["fn_size"], p["si"]), e.sel(e.lt(p["start"], p["end"]), e.sub(p["end"], p["start"]), 0))

        e.for_("q", 0, p["nfn"], sizes)

        def symbol(k, name, shndx, value, size):
            base = e.add(p["dynsym_off"], e.mul(k, 24))
            for pos, item, n in ((0, soff(name), 4), (4, 0x12, 1), (5, 0, 1), (6, shndx, 2), (8, value, 8), (16, size, 8)):
                put(e.add(base, pos), item, n)

        def export_symbol():
            e.var("xr", e.ld(e.add(p["order"], p["q"])))
            e.var("xf", at(e, p["xr"], 1))
            symbol(e.add(p["q"], 1), e.ld(p["xr"]), 5, e.add(p["text_off"], e.ld(e.add(p["fn"], p["xf"]))), e.ld(e.add(p["fn_size"], p["xf"])))

        e.for_("q", 0, p["nex"], export_symbol)
        e.for_("q", 0, p["nimp"], lambda: symbol(e.add(e.add(p["q"], 1), p["nex"]), e.ld(e.ld(e.add(p["names"], p["q"]))), 0, 0, 0))
        e.for_("q", 0, e.ld(G_NSTR), lambda: _call(e, "ae_copy", e.add(p["dynstr_off"], e.ld(e.add(e.ld(G_SOFF), p["q"]))), e.ld(e.add(e.ld(G_STR), p["q"]))))
        # The GLOB_DAT relocations of the GOT slots.
        e.for_("q", 0, p["nimp"], lambda: (put(e.add(p["rela_off"], e.mul(p["q"], 24)), e.add(p["got_addr"], e.mul(p["q"], 8)), 8),
                                           put(e.add(e.add(p["rela_off"], e.mul(p["q"], 24)), 8), e.add(e.mul(e.add(e.add(p["q"], 1), p["nex"]), 1 << 32), 1025), 8)))
        # The text, the rodata, the data.
        e.for_("q", 0, p["text_n"], lambda: put(e.add(p["text_off"], p["q"]), e.ld(e.add(e.ld(G_TXT), p["q"])), 1))
        _call(e, "ae_copy", p["rodata_off"], p["rodata"])
        _call(e, "ae_copy", p["data_off"], p["data"])
        # The dynamic section.
        e.var("dp", p["dynamic_off"])

        def dynamic(tag, value):
            put(p["dp"], tag, 8)
            put(e.add(p["dp"], 8), value, 8)
            e.set("dp", e.add(p["dp"], 16))

        e.for_("q", 0, p["nlib"], lambda: dynamic(1, soff(e.ld(e.ld(e.add(p["libs"], p["q"]))))))
        for tag, value in ((4, p["hash_off"]), (5, p["dynstr_off"]), (6, p["dynsym_off"]), (10, p["dynstr_n"]), (11, 24), (14, soff(p["soname"]))):
            dynamic(tag, value)
        e.if_(e.ne(p["nimp"], 0), lambda: (dynamic(7, p["rela_off"]), dynamic(8, p["rela_n"]), dynamic(9, 24)))
        dynamic(0, 0)
        # The section names and headers.
        for k, byte in enumerate(SHSTRTAB):
            put(e.add(p["shstr_off"], k), byte, 1)

        def section(k, name, kind, flags, address, offset, size, link, info, alignment, entsize):
            base = e.add(p["shoff"], 64 * k)
            for pos, value, n in ((0, SH_NAME[name], 4), (4, kind, 4), (8, flags, 8), (16, address, 8), (24, offset, 8), (32, size, 8), (40, link, 4),
                                  (44, info, 4), (48, alignment, 8), (56, entsize, 8)):
                put(e.add(base, pos), value, n)

        section(1, b".hash", 5, 2, p["hash_off"], p["hash_off"], p["hash_n"], 2, 0, 4, 4)
        section(2, b".dynsym", 11, 2, p["dynsym_off"], p["dynsym_off"], e.mul(p["nsym"], 24), 3, 1, 8, 24)
        section(3, b".dynstr", 3, 2, p["dynstr_off"], p["dynstr_off"], p["dynstr_n"], 0, 0, 1, 0)
        section(4, b".rela.dyn", 4, 2, p["rela_off"], p["rela_off"], p["rela_n"], 2, 0, 8, 24)
        section(5, b".text", 1, 2 | 4, p["text_off"], p["text_off"], p["text_n"], 0, 0, 16, 0)
        section(6, b".rodata", 1, 2, p["rodata_off"], p["rodata_off"], e.ld(p["rodata"]), 0, 0, 16, 0)
        section(7, b".got", 1, 2 | 1, p["got_addr"], p["got_off"], p["got_n"], 0, 0, 8, 8)
        section(8, b".data", 1, 2 | 1, e.add(p["data_off"], p["delta"]), p["data_off"], e.ld(p["data"]), 0, 0, 8, 0)
        section(9, b".bss", 8, 2 | 1, e.add(p["bss_off"], p["delta"]), p["bss_off"], p["bss"], 0, 0, 8, 0)
        section(10, b".dynamic", 6, 2 | 1, p["dynamic_addr"], p["dynamic_off"], p["dynamic_n"], 3, 0, 8, 16)
        section(11, b".shstrtab", 3, 0, 0, p["shstr_off"], len(SHSTRTAB), 0, 0, 1, 0)

        # The image record.
        e.var("pk", e.ld(G_OUT))
        _ok(e, e.lt(e.add(OUT, e.udiv(p["size"], 8)), IMAGE_END))

        def pack():
            e.var("wv", 0)
            for k in range(7, -1, -1):
                e.set("wv", e.add(e.mul(p["wv"], 256), e.sel(e.lt(e.add(e.mul(p["q"], 8), k), p["size"]), e.ld(e.add(p["pk"], e.add(e.mul(p["q"], 8), k))), 0)))
            e.st(e.add(OUT, p["q"]), p["wv"])

        e.for_("q", 0, e.udiv(e.add(p["size"], 7), 8), pack)
        e.st(IMAGE_AT, 1)
        e.st(IMAGE_AT + 1, 0)
        e.st(IMAGE_AT + 2, p["size"])
        e.st(1, p["text_off"])
        e.st(2, p["text_n"])
        e.st(3, p["nimp"])
        e.st(4, p["nlib"])
        e.st(0, 1)
        e.give(1)
    return _function((), build, tables)


def build_android_elf_program():
    """``(reader, function)``: the Android ELF container program's store and its entry."""
    tables = None
    objects: list = []
    _FN.clear()

    def add(name, made):
        function, items = made
        objects.extend(items)
        _FN[name] = function
        return function

    for name, builder in (("ae_word", _word_fn), ("ae_bytes", _bytes_fn), ("ae_less", _less_fn), ("ae_same", _same_fn), ("ae_pairless", _pair_less_fn),
                          ("ae_sort", _sort_fn), ("ae_soff", _string_offset_fn), ("ae_set", _set_fn), ("ae_copy", _copy_fn), ("ae_tword", _text_word_fn)):
        add(name, builder(tables))
    program = add("frontend", _frontend(tables))
    return program_store(program, x86_64_linux_exec_target(), tuple(objects)), program


_PROGRAM = NativeProgram(STORE_PATH, build_android_elf_program, "android-elf")
load_android_elf_program = _PROGRAM.load
write_android_elf_store = _PROGRAM.write
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
