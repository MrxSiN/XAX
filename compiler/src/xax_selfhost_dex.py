"""S15e.6d.1 (ADR-336): the DEX 039 bridge (``xax_dex.emit_dex039_bridge``) as an XAX program, for the core bridge shapes.

The program takes the bridge specification's core fields (the class, its superclass and interfaces, the native library
and its deferred-load override, the native methods, the forwarding overrides, the null-return overrides, the constant-
and echo-string methods and the assembled methods) and writes the whole file as the bootstrap does: the string set
(ordered by UTF-16 code units), the types (in string order), the prototypes (interned; ordered by return and parameter
types), the method references (ordered by class, name and prototype), the type lists, the code items (the constructor,
the ``<clinit>`` that loads the library, the forwarding overrides in their compact 35c and range forms, the constant and
echo methods, the null returns and the assembled bodies), the class data, the MUTF-8 string data, the map list, the
header, the SHA-1 signature and the Adler-32 checksum.  An index or register past a 16-bit field (the bootstrap's
error) makes the program decline.  The Activity UI, click-text and libxposed shapes are S15e.6d.2-S15e.6d.3: the front
door does not ask the program for them.

Input (64-bit words; a string is its UTF-16 code-unit count, then one unit per word; a prototype is its return type,
its parameter count and its parameters): the class, the superclass, the class access flags, the interface count and
the interfaces; the library flag and the library; the override flag and the override's name; the native methods (count;
each name, prototype, access); the forwarding overrides (count; each name, prototype, native target, access, super
flag); the null-return overrides (count; each name, prototype, access); the constant-string methods (count; each name,
value, access); the echo-string methods (count; each name, access); the assembled methods (count; each name, prototype,
register count, access, instruction count, and per instruction its opcode, register count, registers, reference kind
(0 none, 1 string, 2 type, 3 method), the reference (a string; a type; a method's class, name and prototype) and the
32-bit literal).
Output: the status (1) and the image record ``[1, 0, length, bytes packed eight to a word]`` at ``IMAGE_AT``.
"""

from __future__ import annotations

from xax_compiler import Operation, x86_64_linux_exec_target
from xax_graph_builder import program_store
from xax_native import bootstrap_dir
from xax_selfhost_facts import E, H_ARENA, H_ARENA_END, NONE, _function
from xax_selfhost_general_image import IMAGE_AT, IMAGE_END
from xax_selfhost_views_backend import _FN, NativeProgram, _call, _ok
from xax_selfhost_x86_64_general import GENERAL_ARENA_AT, GENERAL_ARENA_END

STORE_PATH = bootstrap_dir() / "xax_dex_bridge.xax"
OUT = IMAGE_AT + 3
STATE_AT = 110 << 20
(G_CUR, G_OUT, G_ON, G_CAP, G_S, G_NS, G_T, G_NT, G_P, G_NP, G_M, G_NM, G_L, G_NL, G_LO, G_C, G_NC, G_SHA) = (STATE_AT + k for k in range(18))
G_K = STATE_AT + 32  # the constant strings' handles
SHA_AT = STATE_AT + 64  # H (5), W (80)
MASK32 = 0xFFFFFFFF
CAP = 1 << 16  # strings, types, prototypes, methods, type lists, code items each
ACC_PRIVATE, ACC_STATIC, ACC_CONSTRUCTOR = 0x0002, 0x0008, 0x10000
P_RET, P_RANK, P_SHORTY, P_N = range(4)  # a prototype: return, rank, shorty, then its type list [n, parameters...]
INSTR = 12  # an instruction: opcode, register count, five registers, reference kind, three reference words, literal
CONSTANTS = ("<init>", "<clinit>", "V", "Ljava/lang/String;", "Ljava/lang/System;", "loadLibrary", "I", "Ljava/lang/CharSequence;",
             "Landroid/content/Context;", "Landroid/view/View;", "Landroid/view/View$OnClickListener;", "Landroid/widget/Button;",
             "Landroid/widget/TextView;", "Landroid/app/Activity;", "setText", "setOnClickListener", "setContentView", "onCreate", "onClick")
UI_STRINGS = ("Landroid/content/Context;", "Landroid/view/View;", "Landroid/view/View$OnClickListener;", "Landroid/widget/Button;",
              "Landroid/widget/TextView;", "setText", "setOnClickListener", "setContentView")
CONST = {text: k for k, text in enumerate(CONSTANTS)}
SHA1_IV = (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0)


def _bx(e: E, x, y):
    return e.bin(Operation.BIT_XOR, x, y)


def _rotl(e: E, x, n: int):
    return e.or_(e.and_(e.mul(x, 1 << n), MASK32), e.udiv(x, 1 << (32 - n)))


def K(e: E, text: str):
    return e.ld(G_K + CONST[text])


def at(e: E, base, k):
    return e.ld(e.add(base, k))


# -- strings (UTF-16 code units in the arena) ------------------------------------------------------------------------------

def _down(e: E, j: str, test, body):
    """``while j > 0 and test(): body()``, with ``test`` (a call reading element ``j - 1``) evaluated only while
    ``j > 0``: ``both`` evaluates every operand, so a plain condition would compare a word before the array."""
    go = f"{j}_go"
    e.var(go, 1)
    e.while_(lambda: e.ne(e.p[go], 0), lambda: e.if_(e.eq(e.p[j], 0), lambda: e.set(go, 0),
                                                       lambda: e.if_(e.ne(test(), 0), body, lambda: e.set(go, 0))))


def _less_fn(tables):
    """1 when string ``a`` sorts before ``b`` (code units; a prefix first)."""
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


def _string_fn(tables):
    """``string()``: the input string at the cursor, copied to the arena (its handle), the cursor moved past it."""
    def build(e: E):
        p = e.p
        e.var("sr_at", e.ld(G_CUR))
        e.var("sr_n", e.rd(p["sr_at"]))
        _ok(e, e.le(p["sr_n"], 1 << 24))
        e.var("sr_h", e.alloc(e.add(p["sr_n"], 1)))
        _ok(e, e.ne(p["sr_h"], NONE))
        e.st(p["sr_h"], p["sr_n"])
        e.for_("sr_k", 0, p["sr_n"], lambda: e.st(e.add(e.add(p["sr_h"], 1), p["sr_k"]), e.rd(e.add(e.add(p["sr_at"], 1), p["sr_k"]))))
        e.st(G_CUR, e.add(e.add(p["sr_at"], 1), p["sr_n"]))
        e.give(p["sr_h"])
    return _function((), build, tables)


def _word_fn(tables):
    def build(e: E):
        p = e.p
        e.var("wd_at", e.ld(G_CUR))
        e.st(G_CUR, e.add(p["wd_at"], 1))
        e.give(e.rd(p["wd_at"]))
    return _function((), build, tables)


def _push_fn(tables):
    """``push(list, count, value)``: ``value`` appended to the array whose base is word ``list`` and length word
    ``count``."""
    def build(e: E):
        p = e.p
        e.var("pu_n", e.ld(p["count"]))
        _ok(e, e.lt(p["pu_n"], CAP))
        e.st(e.add(e.ld(p["list"]), p["pu_n"]), p["value"])
        e.st(p["count"], e.add(p["pu_n"], 1))
        e.give(1)
    return _function(("list", "count", "value"), build, tables)


def push(e: E, which: tuple[int, int], value):
    _call(e, "dx_push", which[0], which[1], value)


STRINGS, TYPES, PROTOS, METHODS, LISTS, CODES = (G_S, G_NS), (G_T, G_NT), (G_P, G_NP), (G_M, G_NM), (G_L, G_NL), (G_C, G_NC)


def _sort_fn(tables):
    """``sort(arr, n)``: the ``n`` string handles at ``arr`` in code-unit order (stable insertion), duplicates dropped;
    the distinct count."""
    def build(e: E):
        p = e.p

        def insert():
            e.var("so_item", e.ld(e.add(p["arr"], p["so_s"])))
            e.var("so_j", p["so_s"])
            _down(e, "so_j", lambda: _call(e, "dx_less", p["so_item"], e.ld(e.add(p["arr"], e.sub(p["so_j"], 1)))),
                  lambda: (e.st(e.add(p["arr"], p["so_j"]), e.ld(e.add(p["arr"], e.sub(p["so_j"], 1)))), e.set("so_j", e.sub(p["so_j"], 1))))
            e.st(e.add(p["arr"], p["so_j"]), p["so_item"])

        e.for_("so_s", 1, p["n"], insert)
        e.var("so_m", e.sel(e.lt(0, p["n"]), 1, 0))

        def keep():
            e.var("so_h", e.ld(e.add(p["arr"], p["so_k"])))
            e.if_(e.eq(_call(e, "dx_same", p["so_h"], e.ld(e.add(p["arr"], e.sub(p["so_m"], 1)))), 0),
                  lambda: (e.st(e.add(p["arr"], p["so_m"]), p["so_h"]), e.set("so_m", e.add(p["so_m"], 1))))

        e.for_("so_k", 1, p["n"], keep)
        e.give(p["so_m"])
    return _function(("arr", "n"), build, tables)


def _find_fn(tables):
    """``find(list, count, h)``: the index of the string with ``h``'s units in the sorted array (it is there)."""
    def build(e: E):
        p = e.p
        e.for_("fd_k", 0, e.ld(p["count"]),
               lambda: e.if_(e.ne(_call(e, "dx_same", p["h"], e.ld(e.add(e.ld(p["list"]), p["fd_k"]))), 0), lambda: e.give(p["fd_k"])))
        e.give(NONE)
    return _function(("list", "count", "h"), build, tables)


def sidx(e: E, h):
    return _call(e, "dx_find", G_S, G_NS, h)


def tidx(e: E, h):
    return _call(e, "dx_find", G_T, G_NT, h)


# -- prototypes, type lists and methods ----------------------------------------------------------------------------------

def _list_less_fn(tables):
    """1 when type list ``a`` (``[n, types...]``) sorts before ``b``: element-wise in type order, a prefix first."""
    def build(e: E):
        p = e.p
        e.var("ll_an", e.ld(p["a"]))
        e.var("ll_bn", e.ld(p["b"]))
        e.var("ll_n", e.sel(e.lt(p["ll_an"], p["ll_bn"]), p["ll_an"], p["ll_bn"]))

        def compare():
            e.var("ll_x", e.ld(e.add(e.add(p["a"], 1), p["ll_k"])))
            e.var("ll_y", e.ld(e.add(e.add(p["b"], 1), p["ll_k"])))
            e.if_(e.ne(_call(e, "dx_less", p["ll_x"], p["ll_y"]), 0), lambda: e.give(1))
            e.if_(e.ne(_call(e, "dx_less", p["ll_y"], p["ll_x"]), 0), lambda: e.give(0))

        e.for_("ll_k", 0, p["ll_n"], compare)
        e.give(e.flag(e.lt(p["ll_an"], p["ll_bn"])))
    return _function(("a", "b"), build, tables)


def _list_same_fn(tables):
    def build(e: E):
        p = e.p
        e.if_(e.ne(e.ld(p["a"]), e.ld(p["b"])), lambda: e.give(0))
        e.for_("lm_k", 1, e.add(e.ld(p["a"]), 1),
               lambda: e.if_(e.eq(_call(e, "dx_same", e.ld(e.add(p["a"], p["lm_k"])), e.ld(e.add(p["b"], p["lm_k"]))), 0), lambda: e.give(0)))
        e.give(1)
    return _function(("a", "b"), build, tables)


def _proto_less_fn(tables):
    """1 when prototype ``a`` sorts before ``b``: by return type, then by the parameters' type list."""
    def build(e: E):
        p = e.p
        e.if_(e.ne(_call(e, "dx_less", e.ld(p["a"]), e.ld(p["b"])), 0), lambda: e.give(1))
        e.if_(e.ne(_call(e, "dx_less", e.ld(p["b"]), e.ld(p["a"])), 0), lambda: e.give(0))
        e.give(_call(e, "dx_listless", e.add(p["a"], P_N), e.add(p["b"], P_N)))
    return _function(("a", "b"), build, tables)


def _intern_fn(tables):
    """``intern(ret, list)``: the prototype of return ``ret`` and type list ``list`` (an existing one, or a new one whose
    strings and types join the sets)."""
    def build(e: E):
        p = e.p

        def each():
            e.var("in_q", e.ld(e.add(e.ld(G_P), p["in_k"])))
            e.if_(e.both(e.ne(_call(e, "dx_same", e.ld(p["in_q"]), p["ret"]), 0), e.ne(_call(e, "dx_listsame", e.add(p["in_q"], P_N), p["list"]), 0)),
                  lambda: e.give(p["in_q"]))

        e.for_("in_k", 0, e.ld(G_NP), each)
        e.var("in_n", e.ld(p["list"]))
        e.var("in_r", e.alloc(e.add(p["in_n"], P_N + 1)))
        e.var("in_s", e.alloc(e.add(p["in_n"], 2)))
        _ok(e, e.both(e.ne(p["in_r"], NONE), e.ne(p["in_s"], NONE)))
        e.st(e.add(p["in_r"], P_RET), p["ret"])
        e.st(e.add(p["in_r"], P_N), p["in_n"])
        e.st(p["in_s"], e.add(p["in_n"], 1))

        def short(h):
            e.var("in_u", e.ld(e.add(h, 1)))
            return e.sel(e.either(e.eq(p["in_u"], ord("L")), e.eq(p["in_u"], ord("["))), ord("L"), p["in_u"])

        e.st(e.add(p["in_s"], 1), short(p["ret"]))
        push(e, STRINGS, p["ret"])
        push(e, TYPES, p["ret"])

        def parameter():
            e.var("in_h", e.ld(e.add(e.add(p["list"], 1), p["in_k"])))
            e.st(e.add(e.add(p["in_r"], P_N + 1), p["in_k"]), p["in_h"])
            e.st(e.add(e.add(p["in_s"], 2), p["in_k"]), short(p["in_h"]))
            push(e, STRINGS, p["in_h"])
            push(e, TYPES, p["in_h"])

        e.for_("in_k", 0, p["in_n"], parameter)
        e.st(e.add(p["in_r"], P_SHORTY), p["in_s"])
        push(e, STRINGS, p["in_s"])
        push(e, PROTOS, p["in_r"])
        e.give(p["in_r"])
    return _function(("ret", "list"), build, tables)


def _proto_in_fn(tables):
    """``proto()``: the input prototype at the cursor, interned."""
    def build(e: E):
        p = e.p
        e.var("pi_ret", _call(e, "dx_string"))
        e.var("pi_n", _call(e, "dx_word"))
        _ok(e, e.le(p["pi_n"], 256))
        e.var("pi_l", e.alloc(e.add(p["pi_n"], 1)))
        _ok(e, e.ne(p["pi_l"], NONE))
        e.st(p["pi_l"], p["pi_n"])
        e.for_("pi_k", 0, p["pi_n"], lambda: e.st(e.add(e.add(p["pi_l"], 1), p["pi_k"]), _call(e, "dx_string")))
        e.give(_call(e, "dx_intern", p["pi_ret"], p["pi_l"]))
    return _function((), build, tables)


def _method_fn(tables):
    """``method(cls, name, proto)``: one more method reference (duplicates are dropped after sorting)."""
    def build(e: E):
        p = e.p
        e.var("me_r", e.alloc(3))
        _ok(e, e.ne(p["me_r"], NONE))
        e.st(p["me_r"], p["cls"])
        e.st(e.add(p["me_r"], 1), p["name"])
        e.st(e.add(p["me_r"], 2), p["proto"])
        push(e, METHODS, p["me_r"])
        e.give(1)
    return _function(("cls", "name", "proto"), build, tables)


def _method_less_fn(tables):
    """1 when method reference ``a`` sorts before ``b``: class, name, prototype rank."""
    def build(e: E):
        p = e.p
        for k in range(2):
            e.if_(e.ne(_call(e, "dx_less", at(e, p["a"], k), at(e, p["b"], k)), 0), lambda: e.give(1))
            e.if_(e.ne(_call(e, "dx_less", at(e, p["b"], k), at(e, p["a"], k)), 0), lambda: e.give(0))
        e.give(e.flag(e.lt(at(e, at(e, p["a"], 2), P_RANK), at(e, at(e, p["b"], 2), P_RANK))))
    return _function(("a", "b"), build, tables)


def _method_same_fn(tables):
    def build(e: E):
        p = e.p
        e.if_(e.ne(at(e, p["a"], 2), at(e, p["b"], 2)), lambda: e.give(0))
        e.give(e.flag(e.both(e.ne(_call(e, "dx_same", at(e, p["a"], 0), at(e, p["b"], 0)), 0),
                             e.ne(_call(e, "dx_same", at(e, p["a"], 1), at(e, p["b"], 1)), 0))))
    return _function(("a", "b"), build, tables)


def _sort_records_fn(tables):
    """``sort_records(arr, n, kind)``: the ``n`` record pointers at ``arr`` sorted (stable insertion) by ``kind``:
    0 prototypes, 1 methods, 2 type lists; then duplicates dropped (methods, type lists); the count kept."""
    def build(e: E):
        p = e.p

        def less(x, y):  # only the kind's own comparison runs: the others would read the records' words as lengths
            e.var("sr_less", 0)
            e.if_(e.eq(p["kind"], 0), lambda: e.set("sr_less", _call(e, "dx_protoless", x, y)), lambda: e.if_(
                e.eq(p["kind"], 1), lambda: e.set("sr_less", _call(e, "dx_methodless", x, y)), lambda: e.set("sr_less", _call(e, "dx_listless", x, y))))
            return p["sr_less"]

        def insert():
            e.var("sr_item", e.ld(e.add(p["arr"], p["sr_s"])))
            e.var("sr_j", p["sr_s"])
            _down(e, "sr_j", lambda: less(p["sr_item"], e.ld(e.add(p["arr"], e.sub(p["sr_j"], 1)))), lambda: (e.st(e.add(p["arr"], p["sr_j"]), e.ld(e.add(p["arr"], e.sub(p["sr_j"], 1)))), e.set("sr_j", e.sub(p["sr_j"], 1))))
            e.st(e.add(p["arr"], p["sr_j"]), p["sr_item"])

        e.for_("sr_s", 1, p["n"], insert)
        e.if_(e.eq(p["kind"], 0), lambda: e.give(p["n"]))
        e.var("sr_m", e.sel(e.lt(0, p["n"]), 1, 0))

        def keep():
            e.var("sr_h", e.ld(e.add(p["arr"], p["sr_k"])))
            e.var("sr_prev", e.ld(e.add(p["arr"], e.sub(p["sr_m"], 1))))
            e.var("sr_same", 0)
            e.if_(e.eq(p["kind"], 1), lambda: e.set("sr_same", _call(e, "dx_methodsame", p["sr_h"], p["sr_prev"])),
                  lambda: e.set("sr_same", _call(e, "dx_listsame", p["sr_h"], p["sr_prev"])))
            e.if_(e.eq(p["sr_same"], 0), lambda: (e.st(e.add(p["arr"], p["sr_m"]), p["sr_h"]), e.set("sr_m", e.add(p["sr_m"], 1))))

        e.for_("sr_k", 1, p["n"], keep)
        e.give(p["sr_m"])
    return _function(("arr", "n", "kind"), build, tables)


def _midx_fn(tables):
    """``midx(cls, name, proto)``: the method reference's index (it is there)."""
    def build(e: E):
        p = e.p

        def each():
            e.var("mx_r", e.ld(e.add(e.ld(G_M), p["mx_k"])))
            e.if_(e.both(e.eq(at(e, p["mx_r"], 2), p["proto"]),
                         e.both(e.ne(_call(e, "dx_same", at(e, p["mx_r"], 0), p["cls"]), 0), e.ne(_call(e, "dx_same", at(e, p["mx_r"], 1), p["name"]), 0))),
                  lambda: e.give(p["mx_k"]))

        e.for_("mx_k", 0, e.ld(G_NM), each)
        e.give(NONE)
    return _function(("cls", "name", "proto"), build, tables)


def midx(e: E, cls, name, proto):
    return _call(e, "dx_midx", cls, name, proto)


def _list_offset_fn(tables):
    """The data offset of the type list with ``list``'s types (0 for an empty one)."""
    def build(e: E):
        p = e.p
        e.if_(e.eq(e.ld(p["list"]), 0), lambda: e.give(0))
        e.for_("lo_k", 0, e.ld(G_NL),
               lambda: e.if_(e.ne(_call(e, "dx_listsame", p["list"], e.ld(e.add(e.ld(G_L), p["lo_k"]))), 0), lambda: e.give(e.ld(e.add(e.ld(G_LO), p["lo_k"])))))
        e.give(NONE)
    return _function(("list",), build, tables)


# -- the output (bytes one per word in the arena) ----------------------------------------------------------------------------

def _byte_fn(tables):
    def build(e: E):
        p = e.p
        e.var("by_n", e.ld(G_ON))
        _ok(e, e.lt(p["by_n"], e.ld(G_CAP)))
        e.st(e.add(e.ld(G_OUT), p["by_n"]), p["b"])
        e.st(G_ON, e.add(p["by_n"], 1))
        e.give(1)
    return _function(("b",), build, tables)


def b(e: E, value):
    _call(e, "dx_byte", value)


def _le_fn(tables):
    """``le(value, n)``: ``n`` little-endian bytes; declines when ``value`` does not fit (the bootstrap's ``struct``
    error)."""
    def build(e: E):
        p = e.p
        _ok(e, e.either(e.eq(p["n"], 8), e.lt(p["value"], e.sel(e.eq(p["n"], 1), 1 << 8, e.sel(e.eq(p["n"], 2), 1 << 16, 1 << 32)))))
        e.var("le_v", p["value"])
        e.for_("le_k", 0, p["n"], lambda: (b(e, e.and_(p["le_v"], 255)), e.set("le_v", e.udiv(p["le_v"], 256))))
        e.give(1)
    return _function(("value", "n"), build, tables)


def u16(e: E, value):
    _call(e, "dx_le", value, 2)


def u32(e: E, value):
    _call(e, "dx_le", value, 4)


def _set32_fn(tables):
    """``set32(at, value)``: four little-endian bytes over the output at ``at``."""
    def build(e: E):
        p = e.p
        _ok(e, e.lt(p["value"], 1 << 32))
        e.var("s3_v", p["value"])
        e.for_("s3_k", 0, 4, lambda: (e.st(e.add(e.ld(G_OUT), e.add(p["at"], p["s3_k"])), e.and_(p["s3_v"], 255)), e.set("s3_v", e.udiv(p["s3_v"], 256))))
        e.give(1)
    return _function(("at", "value"), build, tables)


def _align_fn(tables):
    def build(e: E):
        e.while_(lambda: e.ne(e.urem(e.ld(G_ON), 4), 0), lambda: b(e, 0))
        e.give(1)
    return _function((), build, tables)


def align(e: E):
    _call(e, "dx_align")


def _uleb_fn(tables):
    def build(e: E):
        p = e.p
        e.var("ul_v", p["value"])
        e.while_(lambda: e.lt(127, p["ul_v"]), lambda: (b(e, e.or_(e.and_(p["ul_v"], 0x7F), 0x80)), e.set("ul_v", e.udiv(p["ul_v"], 128))))
        b(e, p["ul_v"])
        e.give(1)
    return _function(("value",), build, tables)


def uleb(e: E, value):
    _call(e, "dx_uleb", value)


def _mutf8_fn(tables):
    """The string data item of ``h``: its unit count, its MUTF-8 bytes and the terminator."""
    def build(e: E):
        p = e.p
        uleb(e, e.ld(p["h"]))

        def unit():
            e.var("mu_c", e.ld(e.add(e.add(p["h"], 1), p["mu_k"])))
            e.if_(e.eq(p["mu_c"], 0), lambda: (b(e, 0xC0), b(e, 0x80)), lambda: e.if_(
                e.le(p["mu_c"], 0x7F), lambda: b(e, p["mu_c"]), lambda: e.if_(
                    e.le(p["mu_c"], 0x7FF), lambda: (b(e, e.or_(0xC0, e.udiv(p["mu_c"], 64))), b(e, e.or_(0x80, e.and_(p["mu_c"], 0x3F)))),
                    lambda: (b(e, e.or_(0xE0, e.udiv(p["mu_c"], 4096))), b(e, e.or_(0x80, e.and_(e.udiv(p["mu_c"], 64), 0x3F))),
                             b(e, e.or_(0x80, e.and_(p["mu_c"], 0x3F)))))))

        e.for_("mu_k", 0, e.ld(p["h"]), unit)
        b(e, 0)
        e.give(1)
    return _function(("h",), build, tables)


def _code_fn(tables):
    """``code(name, registers, ins, outs, units, n)``: an aligned code item of the ``n`` units at ``units``, recorded as
    the latest code of ``name``."""
    def build(e: E):
        p = e.p
        align(e)
        e.var("cd_r", e.alloc(2))
        _ok(e, e.ne(p["cd_r"], NONE))
        e.st(p["cd_r"], p["name"])
        e.st(e.add(p["cd_r"], 1), e.ld(G_ON))
        push(e, CODES, p["cd_r"])
        for value in ("registers", "ins", "outs"):
            u16(e, p[value])
        u16(e, 0)
        u32(e, 0)
        u32(e, p["n"])
        e.for_("cd_k", 0, p["n"], lambda: u16(e, e.ld(e.add(p["units"], p["cd_k"]))))
        e.give(1)
    return _function(("name", "registers", "ins", "outs", "units", "n"), build, tables)


def _code_at_fn(tables):
    """The offset of the latest code item of ``name``."""
    def build(e: E):
        p = e.p
        e.var("ca_off", NONE)
        e.for_("ca_k", 0, e.ld(G_NC), lambda: (
            e.var("ca_r", e.ld(e.add(e.ld(G_C), p["ca_k"]))),
            e.if_(e.ne(_call(e, "dx_same", e.ld(p["ca_r"]), p["name"]), 0), lambda: e.set("ca_off", at(e, p["ca_r"], 1)))))
        e.give(p["ca_off"])
    return _function(("name",), build, tables)


class Units:
    """A code-unit list in the arena."""

    def __init__(self, e: E, name: str, capacity):
        self.e, self.name = e, name
        e.var(name, e.alloc(capacity))
        _ok(e, e.ne(e.p[name], NONE))
        e.var(f"{name}_n", 0)

    def add(self, *values):
        e = self.e
        for value in values:
            e.st(e.add(e.p[self.name], e.p[f"{self.name}_n"]), value)
            e.set(f"{self.name}_n", e.add(e.p[f"{self.name}_n"], 1))

    def code(self, name, registers, ins, outs):
        _call(self.e, "dx_code", name, registers, ins, outs, self.e.p[self.name], self.e.p[f"{self.name}_n"])


# -- SHA-1 and Adler-32 ---------------------------------------------------------------------------------------------------

def _sha1_block_fn(tables):
    """One 64-byte block at ``at`` (bytes one per word) into the state at ``SHA_AT``."""
    def build(e: E):
        p = e.p
        w = SHA_AT + 5
        e.for_("s1_t", 0, 16, lambda: e.st(e.add(w, p["s1_t"]), e.or_(
            e.or_(e.mul(e.ld(e.add(p["at"], e.mul(p["s1_t"], 4))), 1 << 24), e.mul(e.ld(e.add(e.add(p["at"], 1), e.mul(p["s1_t"], 4))), 1 << 16)),
            e.or_(e.mul(e.ld(e.add(e.add(p["at"], 2), e.mul(p["s1_t"], 4))), 1 << 8), e.ld(e.add(e.add(p["at"], 3), e.mul(p["s1_t"], 4)))))))
        e.for_("s1_t", 16, 80, lambda: e.st(e.add(w, p["s1_t"]), _rotl(e, _bx(e, _bx(e, e.ld(e.add(w, e.sub(p["s1_t"], 3))), e.ld(e.add(w, e.sub(p["s1_t"], 8)))),
                                                                             _bx(e, e.ld(e.add(w, e.sub(p["s1_t"], 14))), e.ld(e.add(w, e.sub(p["s1_t"], 16))))), 1)))
        names = ("s1_a", "s1_b", "s1_c", "s1_d", "s1_e")
        for k, name in enumerate(names):
            e.var(name, e.ld(SHA_AT + k))

        def round_():
            a, bb, c, d, f_e = (p[name] for name in names)
            t = p["s1_r"]
            choose = e.or_(e.and_(bb, c), e.and_(_bx(e, bb, MASK32), d))
            parity = _bx(e, _bx(e, bb, c), d)
            majority = e.or_(e.or_(e.and_(bb, c), e.and_(bb, d)), e.and_(c, d))
            f = e.sel(e.lt(t, 20), choose, e.sel(e.lt(t, 40), parity, e.sel(e.lt(t, 60), majority, parity)))
            k = e.sel(e.lt(t, 20), 0x5A827999, e.sel(e.lt(t, 40), 0x6ED9EBA1, e.sel(e.lt(t, 60), 0x8F1BBCDC, 0xCA62C1D6)))
            e.var("s1_tmp", e.and_(e.add(e.add(_rotl(e, a, 5), f), e.add(e.add(f_e, k), e.ld(e.add(w, t)))), MASK32))
            e.set("s1_e", d)
            e.set("s1_d", c)
            e.set("s1_c", _rotl(e, bb, 30))
            e.set("s1_b", a)
            e.set("s1_a", p["s1_tmp"])

        e.for_("s1_r", 0, 80, round_)
        for k, name in enumerate(names):
            e.st(SHA_AT + k, e.and_(e.add(e.ld(SHA_AT + k), p[name]), MASK32))
        e.give(1)
    return _function(("at",), build, tables)


def _sign_fn(tables):
    """The signature (SHA-1 of the output from byte 32) at 12 and the Adler-32 checksum (from byte 12) at 8."""
    def build(e: E):
        p = e.p
        e.var("sg_n", e.sub(e.ld(G_ON), 32))
        e.var("sg_m", e.alloc(e.add(p["sg_n"], 128)))
        _ok(e, e.ne(p["sg_m"], NONE))
        e.for_("sg_k", 0, p["sg_n"], lambda: e.st(e.add(p["sg_m"], p["sg_k"]), e.ld(e.add(e.add(e.ld(G_OUT), 32), p["sg_k"]))))
        e.var("sg_len", p["sg_n"])
        e.st(e.add(p["sg_m"], p["sg_len"]), 0x80)
        e.set("sg_len", e.add(p["sg_len"], 1))
        e.while_(lambda: e.ne(e.urem(p["sg_len"], 64), 56), lambda: (e.st(e.add(p["sg_m"], p["sg_len"]), 0), e.set("sg_len", e.add(p["sg_len"], 1))))
        e.var("sg_bits", e.mul(p["sg_n"], 8))
        for k in range(8):
            e.st(e.add(p["sg_m"], e.add(p["sg_len"], k)), e.and_(e.udiv(p["sg_bits"], 1 << (8 * (7 - k))) if k < 7 else p["sg_bits"], 255))
        e.set("sg_len", e.add(p["sg_len"], 8))
        for k, word in enumerate(SHA1_IV):
            e.st(SHA_AT + k, word)
        e.var("sg_q", 0)
        e.while_(lambda: e.lt(p["sg_q"], p["sg_len"]), lambda: (_call(e, "dx_sha1", e.add(p["sg_m"], p["sg_q"])), e.set("sg_q", e.add(p["sg_q"], 64))))
        for k in range(20):
            e.st(e.add(e.ld(G_OUT), 12 + k), e.and_(e.udiv(e.ld(SHA_AT + k // 4), 1 << (8 * (3 - k % 4))) if k % 4 < 3 else e.ld(SHA_AT + k // 4), 255))
        e.var("sg_a", 1)
        e.var("sg_b", 0)
        e.for_("sg_k", 12, e.ld(G_ON), lambda: (e.set("sg_a", e.urem(e.add(p["sg_a"], e.ld(e.add(e.ld(G_OUT), p["sg_k"]))), 65521)),
                                                 e.set("sg_b", e.urem(e.add(p["sg_b"], p["sg_a"]), 65521))))
        _call(e, "dx_set32", 8, e.add(e.mul(p["sg_b"], 65536), p["sg_a"]))
        e.give(1)
    return _function((), build, tables)


# -- the bridge ---------------------------------------------------------------------------------------------------------------

def _frontend(tables):
    def build(e: E):
        p = e.p
        word = lambda: _call(e, "dx_word")  # noqa: E731
        string = lambda: _call(e, "dx_string")  # noqa: E731
        proto = lambda: _call(e, "dx_proto")  # noqa: E731
        e.st(0, 0)
        e.set_hd(H_ARENA, GENERAL_ARENA_AT)
        e.set_hd(H_ARENA_END, GENERAL_ARENA_END)
        for base, _count in (STRINGS, TYPES, PROTOS, METHODS, LISTS, CODES):
            e.st(base, e.alloc(CAP))
            _ok(e, e.ne(e.ld(base), NONE))
            e.st(_count, 0)
        for k, text in enumerate(CONSTANTS):
            e.var("cs_h", e.alloc(len(text) + 1))
            _ok(e, e.ne(p["cs_h"], NONE))
            e.st(p["cs_h"], len(text))
            for j, char in enumerate(text):
                e.st(e.add(p["cs_h"], 1 + j), ord(char))
            e.st(G_K + k, p["cs_h"])
        e.st(G_CUR, 0)
        # Constant prototypes: ``()V``, ``(String)V``, ``()String``, ``(String)String``.
        e.var("empty", e.alloc(1))
        e.var("one", e.alloc(2))
        _ok(e, e.both(e.ne(p["empty"], NONE), e.ne(p["one"], NONE)))
        e.st(p["empty"], 0)
        e.st(p["one"], 1)
        e.st(e.add(p["one"], 1), K(e, "Ljava/lang/String;"))
        e.var("ctor", _call(e, "dx_intern", K(e, "V"), p["empty"]))

        e.var("cls", string())
        e.var("super", string())
        e.var("access", word())
        e.var("nif", word())
        _ok(e, e.le(p["nif"], 256))
        e.var("ifs", e.alloc(e.add(p["nif"], 1)))
        _ok(e, e.ne(p["ifs"], NONE))
        e.st(p["ifs"], p["nif"])
        e.for_("q", 0, p["nif"], lambda: (e.st(e.add(e.add(p["ifs"], 1), p["q"]), string()), push(e, STRINGS, e.ld(e.add(e.add(p["ifs"], 1), p["q"]))),
                                          push(e, TYPES, e.ld(e.add(e.add(p["ifs"], 1), p["q"])))))
        for h in (p["cls"], p["super"]):
            push(e, STRINGS, h)
            push(e, TYPES, h)
        push(e, STRINGS, K(e, "<init>"))
        e.var("has_lib", word())
        e.var("lib", 0)
        e.if_(e.ne(p["has_lib"], 0), lambda: e.set("lib", string()))
        e.var("has_override", word())
        e.var("override", 0)
        e.if_(e.ne(p["has_override"], 0), lambda: e.set("override", string()))
        e.var("clinit", e.flag(e.both(e.ne(p["has_lib"], 0), e.eq(p["has_override"], 0))))
        _call(e, "dx_method", p["super"], K(e, "<init>"), p["ctor"])
        _call(e, "dx_method", p["cls"], K(e, "<init>"), p["ctor"])

        def items(name, words, read):
            """``n`` records of ``words`` words read by ``read(record)``."""
            e.var(f"n_{name}", word())
            _ok(e, e.le(p[f"n_{name}"], CAP))
            e.var(name, e.alloc(e.add(e.mul(p[f"n_{name}"], words), 1)))
            _ok(e, e.ne(p[name], NONE))
            e.for_("q", 0, p[f"n_{name}"], lambda: read(e.add(p[name], e.mul(p["q"], words))))

        def own(r, name_word, proto_word):
            push(e, STRINGS, at(e, r, name_word))
            _call(e, "dx_method", p["cls"], at(e, r, name_word), at(e, r, proto_word))

        def native(r):
            e.var("r", r)
            e.st(p["r"], string())
            e.st(e.add(p["r"], 1), proto())
            e.st(e.add(p["r"], 2), word())
            own(p["r"], 0, 1)

        items("natives", 3, native)

        def forwarding(r):
            e.var("r", r)
            e.st(p["r"], string())
            e.st(e.add(p["r"], 1), proto())
            e.st(e.add(p["r"], 2), string())
            e.st(e.add(p["r"], 3), word())
            e.st(e.add(p["r"], 4), word())
            own(p["r"], 0, 1)
            e.if_(e.ne(at(e, p["r"], 4), 0), lambda: _call(e, "dx_method", p["super"], at(e, p["r"], 0), at(e, p["r"], 1)))

        items("forwards", 5, forwarding)

        def null(r):
            e.var("r", r)
            e.st(p["r"], string())
            e.st(e.add(p["r"], 1), proto())
            e.st(e.add(p["r"], 2), word())
            own(p["r"], 0, 1)

        items("nulls", 3, null)
        # The constant and echo prototypes and ``System.loadLibrary``'s join the set only when used, as in the bootstrap.
        e.var("string_proto", 0)
        e.var("echo_proto", 0)
        e.var("load_proto", 0)
        e.var("peek", e.rd(e.ld(G_CUR)))
        e.if_(e.ne(p["peek"], 0), lambda: e.set("string_proto", _call(e, "dx_intern", K(e, "Ljava/lang/String;"), p["empty"])))

        def constant(r):
            e.var("r", r)
            e.st(p["r"], string())
            e.st(e.add(p["r"], 1), string())
            e.st(e.add(p["r"], 2), word())
            push(e, STRINGS, at(e, p["r"], 1))
            push(e, STRINGS, at(e, p["r"], 0))
            _call(e, "dx_method", p["cls"], at(e, p["r"], 0), p["string_proto"])

        items("constants", 3, constant)
        e.set("peek", e.rd(e.ld(G_CUR)))
        e.if_(e.ne(p["peek"], 0), lambda: e.set("echo_proto", _call(e, "dx_intern", K(e, "Ljava/lang/String;"), p["one"])))

        def echo(r):
            e.var("r", r)
            e.st(p["r"], string())
            e.st(e.add(p["r"], 1), word())
            push(e, STRINGS, at(e, p["r"], 0))
            _call(e, "dx_method", p["cls"], at(e, p["r"], 0), p["echo_proto"])

        items("echoes", 2, echo)

        def assembled(r):
            e.var("r", r)
            e.st(p["r"], string())
            e.st(e.add(p["r"], 1), proto())
            e.st(e.add(p["r"], 2), word())
            e.st(e.add(p["r"], 3), word())
            e.var("ni", word())
            _ok(e, e.both(e.lt(0, p["ni"]), e.le(p["ni"], 1 << 16)))
            e.st(e.add(p["r"], 4), p["ni"])
            e.var("ins", e.alloc(e.mul(p["ni"], INSTR)))
            _ok(e, e.ne(p["ins"], NONE))
            e.st(e.add(p["r"], 5), p["ins"])
            own(p["r"], 0, 1)

            def instruction():
                e.var("ir", e.add(p["ins"], e.mul(p["j"], INSTR)))
                e.st(p["ir"], word())
                e.var("nr", word())
                _ok(e, e.le(p["nr"], 5))
                e.st(e.add(p["ir"], 1), p["nr"])
                for k in range(5):
                    e.st(e.add(p["ir"], 2 + k), 0)
                e.for_("k", 0, p["nr"], lambda: e.st(e.add(e.add(p["ir"], 2), p["k"]), word()))
                e.var("rk", word())
                e.st(e.add(p["ir"], 7), p["rk"])

                def text():
                    e.st(e.add(p["ir"], 8), string())
                    push(e, STRINGS, at(e, p["ir"], 8))
                    e.if_(e.eq(p["rk"], 2), lambda: push(e, TYPES, at(e, p["ir"], 8)))

                def method():
                    e.st(e.add(p["ir"], 8), string())
                    e.st(e.add(p["ir"], 9), string())
                    e.st(e.add(p["ir"], 10), proto())
                    for k in (8, 9):
                        push(e, STRINGS, at(e, p["ir"], k))
                    push(e, TYPES, at(e, p["ir"], 8))
                    _call(e, "dx_method", at(e, p["ir"], 8), at(e, p["ir"], 9), at(e, p["ir"], 10))

                e.if_(e.either(e.eq(p["rk"], 1), e.eq(p["rk"], 2)), text)
                e.if_(e.eq(p["rk"], 3), method)
                e.st(e.add(p["ir"], 11), word())

            e.for_("j", 0, p["ni"], instruction)

        items("asms", 6, assembled)

        def single(name, h):
            e.var(name, e.alloc(2))
            _ok(e, e.ne(p[name], NONE))
            e.st(p[name], 1)
            e.st(e.add(p[name], 1), h)
            return p[name]

        # S15e.6d.2: the Activity UI (its button's text inline (0), a resource ID (1) or a managed method (2)) and the
        # click-text listener (inline (0) or a resource ID (1)).
        for name in ("ui", "ui_kind", "ui_text", "ui_arg", "ui_settext", "ui_button", "ui_listen", "ui_content", "listener",
                     "click", "click_kind", "click_text", "click_settext"):
            e.var(name, 0)
        e.set("ui", word())

        def ui():
            e.set("listener", string())
            e.set("ui_kind", word())
            e.if_(e.eq(p["ui_kind"], 1), lambda: e.set("ui_text", word()), lambda: e.set("ui_text", string()))
            e.if_(e.eq(p["ui_kind"], 2), lambda: e.if_(e.ne(word(), 0), lambda: e.set("ui_arg", string())))
            e.set("ui_button", _call(e, "dx_intern", K(e, "V"), single("l_context", K(e, "Landroid/content/Context;"))))
            e.set("ui_settext", _call(e, "dx_intern", K(e, "V"), single("l_text", e.sel(e.eq(p["ui_kind"], 1), K(e, "I"), K(e, "Ljava/lang/CharSequence;")))))
            e.set("ui_listen", _call(e, "dx_intern", K(e, "V"), single("l_listen", K(e, "Landroid/view/View$OnClickListener;"))))
            e.set("ui_content", _call(e, "dx_intern", K(e, "V"), single("l_view", K(e, "Landroid/view/View;"))))
            for text in UI_STRINGS:
                push(e, STRINGS, K(e, text))
                if text.startswith("L"):
                    push(e, TYPES, K(e, text))
            push(e, STRINGS, p["listener"])
            push(e, TYPES, p["listener"])
            e.if_(e.eq(p["ui_kind"], 0), lambda: (push(e, STRINGS, p["ui_text"]), push(e, STRINGS, K(e, "Ljava/lang/CharSequence;")),
                                                  push(e, TYPES, K(e, "Ljava/lang/CharSequence;"))))
            e.if_(e.ne(p["ui_arg"], 0), lambda: push(e, STRINGS, p["ui_arg"]))
            for cls, name, proto in (("Landroid/widget/Button;", "<init>", "ui_button"), ("Landroid/widget/TextView;", "setText", "ui_settext"),
                                     (None, "<init>", "ctor"), ("Landroid/view/View;", "setOnClickListener", "ui_listen"),
                                     ("Landroid/app/Activity;", "setContentView", "ui_content")):
                _call(e, "dx_method", p["listener"] if cls is None else K(e, cls), K(e, name), p[proto])

        e.if_(e.ne(p["ui"], 0), ui)
        e.set("click", word())

        def click():
            e.set("click_kind", word())
            e.if_(e.eq(p["click_kind"], 1), lambda: e.set("click_text", word()), lambda: e.set("click_text", string()))
            e.set("click_settext", _call(e, "dx_intern", K(e, "V"), single("c_text", e.sel(e.eq(p["click_kind"], 1), K(e, "I"), K(e, "Ljava/lang/CharSequence;")))))
            for text in ("Landroid/widget/TextView;", "setText"):
                push(e, STRINGS, K(e, text))
            push(e, TYPES, K(e, "Landroid/widget/TextView;"))
            e.if_(e.eq(p["click_kind"], 0), lambda: (push(e, STRINGS, p["click_text"]), push(e, STRINGS, K(e, "Ljava/lang/CharSequence;")),
                                                     push(e, TYPES, K(e, "Ljava/lang/CharSequence;"))))
            _call(e, "dx_method", K(e, "Landroid/widget/TextView;"), K(e, "setText"), p["click_settext"])

        e.if_(e.ne(p["click"], 0), click)

        def library():
            e.set("load_proto", _call(e, "dx_intern", K(e, "V"), p["one"]))
            for text in ("Ljava/lang/System;", "loadLibrary"):
                push(e, STRINGS, K(e, text))
            push(e, STRINGS, p["lib"])
            push(e, TYPES, K(e, "Ljava/lang/System;"))
            _call(e, "dx_method", K(e, "Ljava/lang/System;"), K(e, "loadLibrary"), p["load_proto"])

        e.if_(e.ne(p["has_lib"], 0), library)

        def clinit():
            push(e, STRINGS, K(e, "<clinit>"))
            _call(e, "dx_method", p["cls"], K(e, "<clinit>"), p["ctor"])

        e.if_(e.ne(p["clinit"], 0), clinit)
        # The sets, their orders and the prototypes' types and strings (taken only from the prototypes kept).
        e.st(G_NS, _call(e, "dx_sort", e.ld(G_S), e.ld(G_NS)))
        e.st(G_NT, _call(e, "dx_sort", e.ld(G_T), e.ld(G_NT)))
        _call(e, "dx_sortrec", e.ld(G_P), e.ld(G_NP), 0)
        e.for_("q", 0, e.ld(G_NP), lambda: e.st(e.add(e.ld(e.add(e.ld(G_P), p["q"])), P_RANK), p["q"]))
        e.st(G_NM, _call(e, "dx_sortrec", e.ld(G_M), e.ld(G_NM), 1))
        # The type lists: the prototypes' parameters and the interfaces.
        e.for_("q", 0, e.ld(G_NP), lambda: (e.var("pr", e.ld(e.add(e.ld(G_P), p["q"]))),
                                             e.if_(e.ne(at(e, p["pr"], P_N), 0), lambda: push(e, LISTS, e.add(p["pr"], P_N)))))
        e.if_(e.ne(p["nif"], 0), lambda: push(e, LISTS, p["ifs"]))
        e.st(G_NL, _call(e, "dx_sortrec", e.ld(G_L), e.ld(G_NL), 2))
        e.st(G_LO, e.alloc(e.add(e.ld(G_NL), 1)))
        _ok(e, e.ne(e.ld(G_LO), NONE))

        # The layout.
        e.var("ns", e.ld(G_NS))
        e.var("nt", e.ld(G_NT))
        e.var("npr", e.ld(G_NP))
        e.var("nm", e.ld(G_NM))
        e.var("type_ids", e.add(0x70, e.mul(p["ns"], 4)))
        e.var("proto_ids", e.add(p["type_ids"], e.mul(p["nt"], 4)))
        e.var("method_ids", e.add(p["proto_ids"], e.mul(p["npr"], 12)))
        e.var("class_defs", e.add(p["method_ids"], e.mul(p["nm"], 8)))
        e.var("data_off", e.add(p["class_defs"], 32))
        e.st(G_CAP, e.add(e.mul(e.ld(G_CUR), 64), 1 << 16))
        e.st(G_OUT, e.alloc(e.ld(G_CAP)))
        _ok(e, e.ne(e.ld(G_OUT), NONE))
        e.st(G_ON, 0)
        e.for_("q", 0, p["data_off"], lambda: b(e, 0))

        def type_list():
            align(e)
            e.var("tl", e.ld(e.add(e.ld(G_L), p["q"])))
            e.st(e.add(e.ld(G_LO), p["q"]), e.ld(G_ON))
            u32(e, e.ld(p["tl"]))
            e.for_("j", 0, e.ld(p["tl"]), lambda: u16(e, tidx(e, e.ld(e.add(e.add(p["tl"], 1), p["j"])))))

        e.for_("q", 0, e.ld(G_NL), type_list)

        # The code items.
        u = Units(e, "u", 64)
        u.add(0x1070, midx(e, p["super"], K(e, "<init>"), p["ctor"]), 0, 0x000E)
        u.code(K(e, "<init>"), 1, 1, 1)

        def clinit_code():
            e.set("u_n", 0)
            u.add(0x001A, sidx(e, p["lib"]), 0x1071, midx(e, K(e, "Ljava/lang/System;"), K(e, "loadLibrary"), p["load_proto"]), 0, 0x000E)
            u.code(K(e, "<clinit>"), 1, 0, 1)

        e.if_(e.ne(p["clinit"], 0), clinit_code)

        def forward():
            e.var("r", e.add(p["forwards"], e.mul(p["q"], 5)))
            e.var("pr", at(e, p["r"], 1))
            e.var("pn", at(e, p["pr"], P_N))
            e.var("ret", at(e, p["pr"], P_RET))
            e.var("ret_u", at(e, p["ret"], 1))
            e.var("wide", 0)
            e.var("ins", 1)

            def parameter():
                e.var("pu", at(e, at(e, p["pr"], e.add(P_N + 1, p["j"])), 1))
                e.var("pw", e.flag(e.both(e.eq(at(e, at(e, p["pr"], e.add(P_N + 1, p["j"])), 0), 1), e.either(e.eq(p["pu"], ord("J")), e.eq(p["pu"], ord("D"))))))
                e.set("wide", e.or_(p["wide"], p["pw"]))
                e.set("ins", e.add(p["ins"], e.add(1, p["pw"])))

            e.for_("j", 0, p["pn"], parameter)
            e.var("void", e.flag(e.both(e.eq(e.ld(p["ret"]), 1), e.eq(p["ret_u"], ord("V")))))
            e.var("native", midx(e, p["cls"], at(e, p["r"], 2), p["pr"]))
            e.var("rc", e.add(1, p["pn"]))
            e.set("u_n", 0)

            def ranged():
                e.var("width", e.sel(e.ne(p["void"], 0), 0,
                                     e.sel(e.both(e.eq(e.ld(p["ret"]), 1), e.either(e.eq(p["ret_u"], ord("J")), e.eq(p["ret_u"], ord("D")))), 2, 1)))
                _ok(e, e.both(e.le(e.add(p["ins"], p["width"]), 0xFFFF), e.le(p["native"], 0xFFFF)))
                e.if_(e.ne(at(e, p["r"], 4), 0), lambda: u.add(e.or_(0x0075, e.mul(p["ins"], 256)), midx(e, p["super"], at(e, p["r"], 0), p["pr"]), p["width"]))
                u.add(e.or_(0x0076, e.mul(p["ins"], 256)), p["native"], p["width"])
                e.if_(e.ne(p["void"], 0), lambda: u.add(0x000E), lambda: e.if_(
                    e.eq(p["width"], 2), lambda: u.add(0x000B, 0x0010), lambda: e.if_(
                        e.either(e.eq(p["ret_u"], ord("L")), e.eq(p["ret_u"], ord("["))), lambda: u.add(0x000C, 0x0011), lambda: u.add(0x000A, 0x000F))))
                u.code(at(e, p["r"], 0), e.add(p["ins"], p["width"]), p["ins"], p["ins"])

            def compact():
                _ok(e, e.le(p["native"], 0xFFFF))
                e.var("first", e.or_(0x0070, e.mul(p["rc"], 4096)))
                e.var("regs", 0)
                e.for_("j", 0, p["rc"], lambda: e.set("regs", e.add(p["regs"], e.mul(p["j"], e.sel(e.eq(p["j"], 0), 1, e.sel(e.eq(p["j"], 1), 16, e.sel(e.eq(p["j"], 2), 256, 4096)))))))

                def deferred():
                    e.var("shifted", 0)
                    e.for_("j", 0, p["rc"], lambda: e.set("shifted", e.add(p["shifted"], e.mul(e.add(p["j"], 1),
                                                                                            e.sel(e.eq(p["j"], 0), 1, e.sel(e.eq(p["j"], 1), 16, e.sel(e.eq(p["j"], 2), 256, 4096)))))))
                    e.var("lib_i", sidx(e, p["lib"]))
                    e.var("load_i", midx(e, K(e, "Ljava/lang/System;"), K(e, "loadLibrary"), p["load_proto"]))
                    _ok(e, e.both(e.le(p["lib_i"], 0xFFFF), e.le(p["load_i"], 0xFFFF)))
                    u.add(0x001A, p["lib_i"], 0x1071, p["load_i"], 0, p["first"], p["native"], p["shifted"], 0x000E)
                    u.code(at(e, p["r"], 0), e.add(p["rc"], 1), p["rc"], e.sel(e.lt(p["rc"], 1), 1, p["rc"]))

                def super_call():
                    e.var("super_i", midx(e, p["super"], at(e, p["r"], 0), p["pr"]))
                    _ok(e, e.le(p["super_i"], 0xFFFF))
                    u.add(e.or_(0x006F, e.mul(p["rc"], 4096)), p["super_i"], p["regs"], p["first"], p["native"], p["regs"], 0x000E)
                    u.code(at(e, p["r"], 0), p["rc"], p["rc"], p["rc"])

                def direct():
                    u.add(p["first"], p["native"], p["regs"], 0x000E)
                    u.code(at(e, p["r"], 0), p["rc"], p["rc"], p["rc"])

                def activity():
                    def invoke(opcode, index, registers):
                        word = sum(reg << (4 * k) for k, reg in enumerate(registers))
                        u.add(opcode | (len(registers) << 12), index, word)

                    invoke(0x6F, midx(e, p["super"], at(e, p["r"], 0), p["pr"]), (3, 4))
                    u.add(0x0022, tidx(e, K(e, "Landroid/widget/Button;")))
                    invoke(0x70, midx(e, K(e, "Landroid/widget/Button;"), K(e, "<init>"), p["ui_button"]), (0, 3))

                    def method_text():
                        e.if_(e.eq(p["ui_arg"], 0), lambda: invoke(0x6E, midx(e, p["cls"], p["ui_text"], p["string_proto"]), (3,)),
                              lambda: (u.add(0x011A, sidx(e, p["ui_arg"])), invoke(0x6E, midx(e, p["cls"], p["ui_text"], p["echo_proto"]), (3, 1))))
                        u.add(0x010C)

                    e.if_(e.eq(p["ui_kind"], 0), lambda: u.add(0x011A, sidx(e, p["ui_text"])), lambda: e.if_(
                        e.eq(p["ui_kind"], 2), method_text, lambda: u.add(0x0114, e.and_(p["ui_text"], 0xFFFF), e.and_(e.udiv(p["ui_text"], 65536), 0xFFFF))))
                    invoke(0x6E, midx(e, K(e, "Landroid/widget/TextView;"), K(e, "setText"), p["ui_settext"]), (0, 1))
                    u.add(0x0222, tidx(e, p["listener"]))
                    invoke(0x70, midx(e, p["listener"], K(e, "<init>"), p["ctor"]), (2,))
                    invoke(0x6E, midx(e, K(e, "Landroid/view/View;"), K(e, "setOnClickListener"), p["ui_listen"]), (0, 2))
                    invoke(0x6E, midx(e, K(e, "Landroid/app/Activity;"), K(e, "setContentView"), p["ui_content"]), (3, 0))
                    invoke(0x70, p["native"], (3, 4))
                    u.add(0x000E)
                    u.code(at(e, p["r"], 0), 5, 2, 2)

                def clicked():
                    u.add(0x021F, tidx(e, K(e, "Landroid/widget/TextView;")))
                    e.if_(e.eq(p["click_kind"], 0), lambda: u.add(0x001A, sidx(e, p["click_text"])),
                          lambda: u.add(0x0014, e.and_(p["click_text"], 0xFFFF), e.and_(e.udiv(p["click_text"], 65536), 0xFFFF)))
                    u.add(0x206E, midx(e, K(e, "Landroid/widget/TextView;"), K(e, "setText"), p["click_settext"]), 0x0002, 0x2070, p["native"], 0x0021, 0x000E)
                    u.code(at(e, p["r"], 0), 3, 2, 2)

                e.var("is_override", e.flag(e.both(e.ne(p["has_override"], 0), e.ne(_call(e, "dx_same", p["override"], at(e, p["r"], 0)), 0))))
                e.var("is_ui", e.flag(e.both(e.both(e.ne(p["ui"], 0), e.ne(at(e, p["r"], 4), 0)), e.ne(_call(e, "dx_same", K(e, "onCreate"), at(e, p["r"], 0)), 0))))
                e.var("is_click", e.flag(e.both(e.ne(p["click"], 0), e.ne(_call(e, "dx_same", K(e, "onClick"), at(e, p["r"], 0)), 0))))
                e.if_(e.ne(p["is_override"], 0), deferred, lambda: e.if_(e.ne(p["is_ui"], 0), activity, lambda: e.if_(
                    e.ne(p["is_click"], 0), clicked, lambda: e.if_(e.ne(at(e, p["r"], 4), 0), super_call, direct))))

            e.if_(e.either(e.eq(p["void"], 0), e.either(e.ne(p["wide"], 0), e.lt(3, p["pn"]))), ranged, compact)

        e.for_("q", 0, p["n_forwards"], forward)

        def constant_code():
            e.var("r", e.add(p["constants"], e.mul(p["q"], 3)))
            e.set("u_n", 0)
            u.add(0x001A, sidx(e, at(e, p["r"], 1)), 0x0011)
            u.code(at(e, p["r"], 0), 2, 1, 0)

        e.for_("q", 0, p["n_constants"], constant_code)

        def echo_code():
            e.var("r", e.add(p["echoes"], e.mul(p["q"], 2)))
            e.set("u_n", 0)
            u.add(0x0111)
            u.code(at(e, p["r"], 0), 2, 2, 0)

        e.for_("q", 0, p["n_echoes"], echo_code)

        def null_code():
            e.var("r", e.add(p["nulls"], e.mul(p["q"], 3)))
            e.var("ins", e.add(1, at(e, at(e, p["r"], 1), P_N)))
            e.set("u_n", 0)
            u.add(0x0012, 0x0011)
            u.code(at(e, p["r"], 0), e.add(p["ins"], 1), p["ins"], 0)

        e.for_("q", 0, p["n_nulls"], null_code)

        def asm_code():
            e.var("r", e.add(p["asms"], e.mul(p["q"], 6)))
            e.var("pr", at(e, p["r"], 1))
            e.var("ins", e.sel(e.eq(e.and_(at(e, p["r"], 3), ACC_STATIC), 0), 1, 0))
            e.for_("j", 0, at(e, p["pr"], P_N), lambda: (
                e.var("ph", at(e, p["pr"], e.add(P_N + 1, p["j"]))),
                e.set("ins", e.add(p["ins"], e.sel(e.both(e.eq(e.ld(p["ph"]), 1), e.either(e.eq(at(e, p["ph"], 1), ord("J")), e.eq(at(e, p["ph"], 1), ord("D")))), 2, 1)))))
            e.var("outs", 0)
            e.var("au", e.alloc(e.add(e.mul(at(e, p["r"], 4), 3), 1)))
            _ok(e, e.ne(p["au"], NONE))
            e.var("au_n", 0)

            def add(value):
                e.st(e.add(p["au"], p["au_n"]), value)
                e.set("au_n", e.add(p["au_n"], 1))

            def instruction():
                e.var("ir", e.add(at(e, p["r"], 5), e.mul(p["j"], INSTR)))
                e.var("opc", e.ld(p["ir"]))
                e.var("r0", at(e, p["ir"], 2))

                def invoke():
                    e.var("nr", at(e, p["ir"], 1))
                    e.set("outs", e.sel(e.lt(p["outs"], p["nr"]), p["nr"], p["outs"]))
                    add(e.or_(e.or_(e.mul(p["nr"], 4096), e.mul(at(e, p["ir"], 6), 256)), p["opc"]))
                    add(midx(e, at(e, p["ir"], 8), at(e, p["ir"], 9), at(e, p["ir"], 10)))
                    add(e.or_(e.or_(p["r0"], e.mul(at(e, p["ir"], 3), 16)), e.or_(e.mul(at(e, p["ir"], 4), 256), e.mul(at(e, p["ir"], 5), 4096))))

                def reference():
                    add(e.or_(e.mul(p["r0"], 256), p["opc"]))
                    e.if_(e.eq(p["opc"], 0x1A), lambda: add(sidx(e, at(e, p["ir"], 8))), lambda: add(tidx(e, at(e, p["ir"], 8))))

                def literal():
                    add(e.or_(e.mul(p["r0"], 256), p["opc"]))
                    add(e.and_(at(e, p["ir"], 11), 0xFFFF))
                    add(e.udiv(e.and_(at(e, p["ir"], 11), MASK32), 65536))

                e.if_(e.both(e.le(0x6E, p["opc"]), e.le(p["opc"], 0x72)), invoke, lambda: e.if_(
                    e.either(e.eq(p["opc"], 0x1A), e.either(e.eq(p["opc"], 0x1F), e.eq(p["opc"], 0x22))), reference, lambda: e.if_(
                        e.eq(p["opc"], 0x14), literal, lambda: e.if_(e.eq(p["opc"], 0x0E), lambda: add(p["opc"]), lambda: add(e.or_(e.mul(p["r0"], 256), p["opc"]))))))

            e.for_("j", 0, at(e, p["r"], 4), instruction)
            _call(e, "dx_code", at(e, p["r"], 0), at(e, p["r"], 2), p["ins"], p["outs"], p["au"], p["au_n"])

        e.for_("q", 0, p["n_asms"], asm_code)

        # The class data: the direct and virtual methods, each sorted by method index.
        e.var("class_data", e.ld(G_ON))
        e.var("total", e.add(e.add(e.add(p["n_natives"], p["n_forwards"]), e.add(p["n_nulls"], p["n_constants"])), e.add(e.add(p["n_echoes"], p["n_asms"]), 2)))
        e.var("direct", e.alloc(e.add(e.mul(p["total"], 3), 1)))
        e.var("virtual", e.alloc(e.add(e.mul(p["total"], 3), 1)))
        _ok(e, e.both(e.ne(p["direct"], NONE), e.ne(p["virtual"], NONE)))
        e.var("nd", 0)
        e.var("nv", 0)

        def entry(is_direct, index, flags, code):
            def put(arr, count):
                e.var("en_at", e.add(p[arr], e.mul(p[count], 3)))
                e.st(p["en_at"], index)
                e.st(e.add(p["en_at"], 1), flags)
                e.st(e.add(p["en_at"], 2), code)
                e.set(count, e.add(p[count], 1))

            e.if_(is_direct, lambda: put("direct", "nd"), lambda: put("virtual", "nv"))

        entry(e.eq(0, 0), midx(e, p["cls"], K(e, "<init>"), p["ctor"]), 0x10001, _call(e, "dx_codeat", K(e, "<init>")))
        e.if_(e.ne(p["clinit"], 0), lambda: entry(e.eq(0, 0), midx(e, p["cls"], K(e, "<clinit>"), p["ctor"]), 0x10008, _call(e, "dx_codeat", K(e, "<clinit>"))))

        def table(name, words, proto_of, flags_word, direct_mask, coded):
            def each():
                e.var("r", e.add(p[name], e.mul(p["q"], words)))
                e.var("fl", at(e, p["r"], flags_word))
                entry(e.ne(e.and_(p["fl"], direct_mask), 0), midx(e, p["cls"], at(e, p["r"], 0), proto_of(p["r"])), p["fl"],
                      _call(e, "dx_codeat", at(e, p["r"], 0)) if coded else 0)

            e.for_("q", 0, p[f"n_{name}"], each)

        table("natives", 3, lambda r: at(e, r, 1), 2, ACC_PRIVATE | ACC_STATIC, False)
        table("forwards", 5, lambda r: at(e, r, 1), 3, 0, True)
        table("nulls", 3, lambda r: at(e, r, 1), 2, 0, True)
        table("constants", 3, lambda r: p["string_proto"], 2, 0, True)
        table("echoes", 2, lambda r: p["echo_proto"], 1, 0, True)
        table("asms", 6, lambda r: at(e, r, 1), 3, ACC_PRIVATE | ACC_STATIC | ACC_CONSTRUCTOR, True)
        uleb(e, 0)
        uleb(e, 0)
        uleb(e, p["nd"])
        uleb(e, p["nv"])
        for arr, count in (("direct", "nd"), ("virtual", "nv")):
            _call(e, "dx_sortentries", p[arr], p[count])
            e.var("prev", 0)
            e.for_("q", 0, p[count], lambda arr=arr: (
                e.var("ea", e.add(p[arr], e.mul(p["q"], 3))),
                uleb(e, e.sub(e.ld(p["ea"]), p["prev"])),
                uleb(e, at(e, p["ea"], 1)),
                uleb(e, at(e, p["ea"], 2)),
                e.set("prev", e.ld(p["ea"]))))

        # The string data, the map list.
        e.var("string_data", e.ld(G_ON))
        e.var("sd", e.alloc(e.add(p["ns"], 1)))
        _ok(e, e.ne(p["sd"], NONE))
        e.for_("q", 0, p["ns"], lambda: (e.st(e.add(p["sd"], p["q"]), e.ld(G_ON)), _call(e, "dx_mutf8", e.ld(e.add(e.ld(G_S), p["q"])))))
        align(e)
        e.var("map", e.ld(G_ON))
        e.var("nlists", e.ld(G_NL))
        u32(e, e.add(10, e.flag(e.ne(p["nlists"], 0))))
        for kind, count, offset in ((0x0000, 1, 0), (0x0001, p["ns"], 0x70), (0x0002, p["nt"], p["type_ids"]), (0x0003, p["npr"], p["proto_ids"]),
                                    (0x0005, p["nm"], p["method_ids"]), (0x0006, 1, p["class_defs"])):
            u16(e, kind)
            u16(e, 0)
            u32(e, count)
            u32(e, offset)
        e.if_(e.ne(p["nlists"], 0), lambda: (u16(e, 0x1001), u16(e, 0), u32(e, p["nlists"]), u32(e, e.ld(e.ld(G_LO)))))
        for kind, count, offset in ((0x2001, e.ld(G_NC), at(e, e.ld(e.ld(G_C)), 1)), (0x2000, 1, p["class_data"]), (0x2002, p["ns"], p["string_data"]),
                                    (0x1000, 1, p["map"])):
            u16(e, kind)
            u16(e, 0)
            u32(e, count)
            u32(e, offset)
        e.var("size", e.ld(G_ON))

        # The header and the index sections.
        for k, byte in enumerate(b"dex\n039\x00"):
            e.st(e.add(e.ld(G_OUT), k), byte)
        for k, value in enumerate((p["size"], 0x70, 0x12345678, 0, 0, p["map"], p["ns"], 0x70, p["nt"], p["type_ids"], p["npr"], p["proto_ids"], 0, 0,
                                   p["nm"], p["method_ids"], 1, p["class_defs"], e.sub(p["size"], p["data_off"]), p["data_off"])):
            _call(e, "dx_set32", 32 + 4 * k, value)
        e.for_("q", 0, p["ns"], lambda: _call(e, "dx_set32", e.add(0x70, e.mul(p["q"], 4)), e.ld(e.add(p["sd"], p["q"]))))
        e.for_("q", 0, p["nt"], lambda: _call(e, "dx_set32", e.add(p["type_ids"], e.mul(p["q"], 4)), sidx(e, e.ld(e.add(e.ld(G_T), p["q"])))))

        def proto_id():
            e.var("pr", e.ld(e.add(e.ld(G_P), p["q"])))
            e.var("pa", e.add(p["proto_ids"], e.mul(p["q"], 12)))
            _call(e, "dx_set32", p["pa"], sidx(e, at(e, p["pr"], P_SHORTY)))
            _call(e, "dx_set32", e.add(p["pa"], 4), tidx(e, at(e, p["pr"], P_RET)))
            _call(e, "dx_set32", e.add(p["pa"], 8), _call(e, "dx_listat", e.add(p["pr"], P_N)))

        e.for_("q", 0, p["npr"], proto_id)

        def method_id():
            e.var("mr", e.ld(e.add(e.ld(G_M), p["q"])))
            e.var("ma", e.add(p["method_ids"], e.mul(p["q"], 8)))
            e.var("mc", tidx(e, at(e, p["mr"], 0)))
            e.var("mp", at(e, at(e, p["mr"], 2), P_RANK))
            _ok(e, e.both(e.le(p["mc"], 0xFFFF), e.le(p["mp"], 0xFFFF)))
            _call(e, "dx_set32", p["ma"], e.add(p["mc"], e.mul(p["mp"], 65536)))
            _call(e, "dx_set32", e.add(p["ma"], 4), sidx(e, at(e, p["mr"], 1)))

        e.for_("q", 0, p["nm"], method_id)
        for k, value in enumerate((tidx(e, p["cls"]), p["access"], tidx(e, p["super"]), e.sel(e.eq(p["nif"], 0), 0, _call(e, "dx_listat", p["ifs"])),
                                   0xFFFFFFFF, 0, p["class_data"], 0)):
            _call(e, "dx_set32", e.add(p["class_defs"], 4 * k), value)
        _call(e, "dx_sign")

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
        e.st(0, 1)
        e.give(1)
    return _function((), build, tables)


def _sort_entries_fn(tables):
    """``sort_entries(arr, n)``: the ``n`` three-word class-data entries at ``arr`` by method index (stable)."""
    def build(e: E):
        p = e.p
        rec = lambda k: e.add(p["arr"], e.mul(k, 3))  # noqa: E731

        def insert():
            e.var("se_j", p["se_s"])

            def swap():
                for field in range(3):
                    e.var("se_t", e.ld(e.add(rec(p["se_j"]), field)))
                    e.st(e.add(rec(p["se_j"]), field), e.ld(e.add(rec(e.sub(p["se_j"], 1)), field)))
                    e.st(e.add(rec(e.sub(p["se_j"], 1)), field), p["se_t"])
                e.set("se_j", e.sub(p["se_j"], 1))

            e.while_(lambda: e.both(e.lt(0, p["se_j"]), e.lt(e.ld(rec(p["se_j"])), e.ld(rec(e.sub(p["se_j"], 1))))), swap)

        e.for_("se_s", 1, p["n"], insert)
        e.give(1)
    return _function(("arr", "n"), build, tables)


def build_dex_program():
    """``(reader, function)``: the DEX bridge program's store and its entry."""
    tables = None
    objects: list = []
    _FN.clear()

    def add(name, made):
        function, items = made
        objects.extend(items)
        _FN[name] = function
        return function

    for name, builder in (("dx_less", _less_fn), ("dx_same", _same_fn), ("dx_string", _string_fn), ("dx_word", _word_fn), ("dx_push", _push_fn),
                          ("dx_sort", _sort_fn), ("dx_find", _find_fn), ("dx_listless", _list_less_fn), ("dx_listsame", _list_same_fn),
                          ("dx_protoless", _proto_less_fn), ("dx_intern", _intern_fn), ("dx_proto", _proto_in_fn), ("dx_method", _method_fn),
                          ("dx_methodless", _method_less_fn), ("dx_methodsame", _method_same_fn), ("dx_sortrec", _sort_records_fn),
                          ("dx_midx", _midx_fn), ("dx_listat", _list_offset_fn), ("dx_byte", _byte_fn), ("dx_le", _le_fn), ("dx_set32", _set32_fn),
                          ("dx_align", _align_fn), ("dx_uleb", _uleb_fn), ("dx_mutf8", _mutf8_fn), ("dx_code", _code_fn), ("dx_codeat", _code_at_fn),
                          ("dx_sha1", _sha1_block_fn), ("dx_sign", _sign_fn),
                          ("dx_sortentries", _sort_entries_fn)):
        add(name, builder(tables))
    program = add("frontend", _frontend(tables))
    return program_store(program, x86_64_linux_exec_target(), tuple(objects)), program


_PROGRAM = NativeProgram(STORE_PATH, build_dex_program, "dex-bridge")
load_dex_program = _PROGRAM.load
write_dex_store = _PROGRAM.write
OPT_OUT = "XAX_DEX_BRIDGE_PYTHON"
_OPCODES = None


def _core(spec) -> bool:
    return (spec.libxposed_hook_intercept is None and spec.libxposed_hook_install is None
            and spec.libxposed_module_services is None and spec.libxposed_remote_preferences is None and spec.libxposed_hot_reload is None
            and spec.libxposed_remote_files is None)


def dex_with_xax(spec, *, required: bool = False) -> bytes | None:
    """The DEX bytes the XAX program writes for a checked core ``DexBridgeSpec``, or None where it cannot run, the shape
    is not a core one, or the program declines (unless ``required``)."""
    import os

    import xax_dex as D
    import xax_native

    if not _core(spec):
        if required:
            raise RuntimeError("the XAX DEX bridge program covers the core shapes only (S15e.6d.1)")
        return None

    def text(value: str) -> list[int]:
        units = D._utf16_units(value)
        return [len(units), *units]

    def proto(value) -> list[int]:
        return [*text(value.return_type), len(value.parameters), *(unit for item in value.parameters for unit in text(item))]

    words = [*text(spec.class_descriptor), *text(spec.superclass_descriptor), spec.class_access_flags, len(spec.interfaces)]
    for item in spec.interfaces:
        words += text(item)
    words += [0] if spec.native_library is None else [1, *text(spec.native_library)]
    words += [0] if spec.native_library_load_override is None else [1, *text(spec.native_library_load_override)]
    words.append(len(spec.native_methods))
    for item in spec.native_methods:
        words += [*text(item.name), *proto(item.proto), item.access_flags]
    words.append(len(spec.forwarding_overrides))
    for item in spec.forwarding_overrides:
        words += [*text(item.name), *proto(item.proto), *text(item.native_target), item.access_flags, int(bool(item.call_super))]
    words.append(len(spec.null_return_overrides))
    for item in spec.null_return_overrides:
        words += [*text(item.name), *proto(item.proto), item.access_flags]
    words.append(len(spec.constant_string_methods))
    for item in spec.constant_string_methods:
        words += [*text(item.name), *text(item.value), item.access_flags]
    words.append(len(spec.echo_string_methods))
    for item in spec.echo_string_methods:
        words += [*text(item.name), item.access_flags]
    words.append(len(spec.assembled_methods))
    for item in spec.assembled_methods:
        words += [*text(item.name), *proto(item.proto), item.registers_size, item.access_flags, len(item.instructions)]
        for instruction in item.instructions:
            words += [D._ASSEMBLED_OPCODES[instruction.mnemonic], len(instruction.registers), *instruction.registers]
            reference = instruction.reference
            if reference is None:
                words.append(0)
            elif isinstance(reference, D.DexMethodRef):
                words += [3, *text(reference.class_descriptor), *text(reference.name), *proto(reference.proto)]
            else:
                words += [1 if instruction.mnemonic == "const-string" else 2, *text(reference)]
            words.append((instruction.literal or 0) & 0xFFFFFFFF)
    ui = spec.activity_ui
    if ui is None:
        words.append(0)
    elif ui.button_text is not None:
        words += [1, *text(ui.listener_class_descriptor), 0, *text(ui.button_text)]
    elif ui.button_text_resource_id is not None:
        words += [1, *text(ui.listener_class_descriptor), 1, ui.button_text_resource_id]
    else:
        words += [1, *text(ui.listener_class_descriptor), 2, *text(ui.button_text_method_name)]
        words += [0] if ui.button_text_method_argument is None else [1, *text(ui.button_text_method_argument)]
    click = spec.click_text
    if click is None:
        words.append(0)
    else:
        words += [1, 0, *text(click.text)] if click.text is not None else [1, 1, click.text_resource_id]
    if any(not 0 <= word < 1 << 63 for word in words):
        return None
    native = None if os.environ.get(OPT_OUT) == "1" else _PROGRAM.native(OPT_OUT)
    data = None
    if native is not None:
        def collect(read):
            (status,) = read(0, 1)
            if status != 1:
                return None
            head = read(IMAGE_AT, 3)
            packed = read(IMAGE_AT + 3, (head[2] + 7) // 8)
            return b"".join(word.to_bytes(8, "little") for word in packed)[:head[2]]

        data = native.run(words, collect)
        if data is None:
            xax_native.declined("dex-bridge", 1)
    if data is None and required:
        raise RuntimeError("the XAX DEX bridge program is unavailable or declined")
    return data
