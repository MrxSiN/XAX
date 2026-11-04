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

from xax_compiler import Operation
from xax_native import bootstrap_dir
from xax_selfhost_facts import E, NONE, _function
from xax_selfhost_general_image import IMAGE_AT
from xax_selfhost_views_backend import NativeProgram, _call, _ok

STORE_PATH = bootstrap_dir() / "xax_dex_bridge.xax"
OUT = IMAGE_AT + 3
STATE_AT = 110 << 20
(G_CUR, G_OUT, G_ON, G_CAP, G_S, G_NS, G_T, G_NT, G_P, G_NP, G_M, G_NM, G_L, G_NL, G_LO, G_C, G_NC, G_SHA, G_F, G_NF) = (STATE_AT + k for k in range(20))
G_K = STATE_AT + 512  # the constant strings' handles
SHA_AT = STATE_AT + 64  # H (5), W (80)
MASK32 = 0xFFFFFFFF
CAP = 1 << 20  # strings, types, prototypes, methods, type lists, code items and fields each (before duplicates are dropped)
ACC_PRIVATE, ACC_STATIC, ACC_CONSTRUCTOR = 0x0002, 0x0008, 0x10000
P_RET, P_RANK, P_SHORTY, P_N = range(4)  # a prototype: return, rank, shorty, then its type list [n, parameters...]
CONSTANTS = ("<init>", "<clinit>", "V", "Ljava/lang/String;", "Ljava/lang/System;", "loadLibrary", "I", "Ljava/lang/CharSequence;",
             "Landroid/content/Context;", "Landroid/view/View;", "Landroid/view/View$OnClickListener;", "Landroid/widget/Button;",
             "Landroid/widget/TextView;", "Landroid/app/Activity;", "setText", "setOnClickListener", "setContentView", "onCreate", "onClick")
# S15e.6d.3: the libxposed adapters' fixed strings.
CHAIN, OBJECT, OBJECT_ARRAY = "Lio/github/libxposed/api/XposedInterface$Chain;", "Ljava/lang/Object;", "[Ljava/lang/Object;"
API = "Lio/github/libxposed/api/"
READY, RELOADING, RELOADED = API + "XposedModuleInterface$PackageReadyParam;", API + "XposedModuleInterface$HotReloadingParam;", API + "XposedModuleInterface$HotReloadedParam;"
WRAPPER, BUILDER, HOOKER, HANDLE, MODE = (API + "XposedInterfaceWrapper;", API + "XposedInterface$HookBuilder;", API + "XposedInterface$Hooker;",
                                          API + "XposedInterface$HookHandle;", API + "XposedInterface$ExceptionMode;")
LOADER, CLASS, CLASS_ARRAY, METHOD, EXECUTABLE = "Ljava/lang/ClassLoader;", "Ljava/lang/Class;", "[Ljava/lang/Class;", "Ljava/lang/reflect/Method;", "Ljava/lang/reflect/Executable;"
PREFS, LIST, PFD, STRING_ARRAY = "Landroid/content/SharedPreferences;", "Ljava/util/List;", "Landroid/os/ParcelFileDescriptor;", "[Ljava/lang/String;"
STRING = "Ljava/lang/String;"
# (generated name, framework name, return, parameters) in the canonical service order.
SERVICES = (("xaxFrameworkName", "getFrameworkName", STRING, ()), ("xaxFrameworkVersion", "getFrameworkVersion", STRING, ()),
            ("xaxRemotePreferences", "getRemotePreferences", PREFS, (STRING,)), ("xaxListRemoteFiles", "listRemoteFiles", STRING_ARRAY, ()),
            ("xaxOpenRemoteFile", "openRemoteFile", PFD, (STRING,)))
# (generated name, interface name, result, code shape) in the canonical read order; ``contains`` has no default.
READS = (("xaxPrefBoolean", "getBoolean", "Z", 0), ("xaxPrefInt", "getInt", "I", 0), ("xaxPrefLong", "getLong", "J", 1),
         ("xaxPrefFloat", "getFloat", "F", 0), ("xaxPrefString", "getString", STRING, 2), ("xaxPrefContains", "contains", "Z", 3))
LIBXPOSED = (CHAIN, OBJECT, OBJECT_ARRAY, READY, RELOADING, RELOADED, WRAPPER, BUILDER, HOOKER, HANDLE, MODE, LOADER, CLASS, CLASS_ARRAY, METHOD,
             EXECUTABLE, PREFS, LIST, PFD, STRING_ARRAY, "Z", "J", "F", "intercept", "proceed", "getArg", "getClassLoader", "loadClass",
             "getDeclaredMethod", "hook", "deoptimize", "setExceptionMode", "setId", "xaxHookHandle", "xaxUnhook", "unhook", "onPackageReady",
             *(name for item in SERVICES for name in item[:2]), "xaxRemotePreferencesIfSupported", "getFrameworkProperties",
             *(name for item in READS for name in item[:2]), "onHotReloading", "onHotReloaded", "setSavedInstanceState", "getSavedInstanceState",
             "getOldHookHandles", "get", "isEmpty", "getId", "equals", "replaceHook", "xaxReloadClassLoader", "xaxListRemoteFilesIfSupported",
             "xaxOpenRemoteFileIfSupported")
CONSTANTS = tuple(dict.fromkeys((*CONSTANTS, *LIBXPOSED)))
CONST = {text: k for k, text in enumerate(CONSTANTS)}
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


STRINGS, TYPES, PROTOS, METHODS, LISTS, CODES, FIELDS = (G_S, G_NS), (G_T, G_NT), (G_P, G_NP), (G_M, G_NM), (G_L, G_NL), (G_C, G_NC), (G_F, G_NF)


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
    0 prototypes, 1 methods, 2 type lists, 3 fields; then duplicates dropped (methods, type lists, fields); the count kept."""
    def build(e: E):
        p = e.p

        def less(x, y):  # only the kind's own comparison runs: the others would read the records' words as lengths
            e.var("sr_less", 0)
            e.if_(e.eq(p["kind"], 0), lambda: e.set("sr_less", _call(e, "dx_protoless", x, y)), lambda: e.if_(
                e.eq(p["kind"], 1), lambda: e.set("sr_less", _call(e, "dx_methodless", x, y)), lambda: e.if_(
                    e.eq(p["kind"], 3), lambda: e.set("sr_less", _call(e, "dx_fieldless", x, y)), lambda: e.set("sr_less", _call(e, "dx_listless", x, y)))))
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
            e.if_(e.eq(p["kind"], 1), lambda: e.set("sr_same", _call(e, "dx_methodsame", p["sr_h"], p["sr_prev"])), lambda: e.if_(
                e.eq(p["kind"], 3), lambda: e.set("sr_same", _call(e, "dx_fieldsame", p["sr_h"], p["sr_prev"])),
                lambda: e.set("sr_same", _call(e, "dx_listsame", p["sr_h"], p["sr_prev"]))))
            e.if_(e.eq(p["sr_same"], 0), lambda: (e.st(e.add(p["arr"], p["sr_m"]), p["sr_h"]), e.set("sr_m", e.add(p["sr_m"], 1))))

        e.for_("sr_k", 1, p["n"], keep)
        e.give(p["sr_m"])
    return _function(("arr", "n", "kind"), build, tables)


def _field_less_fn(tables):
    """1 when field reference ``a`` (class, name, type) sorts before ``b``."""
    def build(e: E):
        p = e.p
        for k in range(3):
            e.if_(e.ne(_call(e, "dx_less", at(e, p["a"], k), at(e, p["b"], k)), 0), lambda: e.give(1))
            e.if_(e.ne(_call(e, "dx_less", at(e, p["b"], k), at(e, p["a"], k)), 0), lambda: e.give(0))
        e.give(0)
    return _function(("a", "b"), build, tables)


def _field_same_fn(tables):
    """1 when field references ``a`` and ``b`` name the same class, name and type."""
    def build(e: E):
        p = e.p
        for k in range(3):
            e.if_(e.eq(_call(e, "dx_same", at(e, p["a"], k), at(e, p["b"], k)), 0), lambda: e.give(0))
        e.give(1)
    return _function(("a", "b"), build, tables)


def _field_fn(tables):
    """``field(cls, name, type)``: one more field reference."""
    def build(e: E):
        p = e.p
        e.var("fl_r", e.alloc(3))
        _ok(e, e.ne(p["fl_r"], NONE))
        for k, name in enumerate(("cls", "name", "type")):
            e.st(e.add(p["fl_r"], k), p[name])
        push(e, FIELDS, p["fl_r"])
        e.give(1)
    return _function(("cls", "name", "type"), build, tables)


def _fidx_fn(tables):
    """``fidx(cls, name, type)``: the field reference's index (it is there)."""
    def build(e: E):
        p = e.p

        def each():
            e.var("fx_r", e.ld(e.add(e.ld(G_F), p["fx_k"])))
            e.var("fx_same", 1)
            for k, name in enumerate(("cls", "name", "type")):
                e.if_(e.eq(_call(e, "dx_same", at(e, p["fx_r"], k), p[name]), 0), lambda: e.set("fx_same", 0))
            e.if_(e.ne(p["fx_same"], 0), lambda: e.give(p["fx_k"]))

        e.for_("fx_k", 0, e.ld(G_NF), each)
        e.give(NONE)
    return _function(("cls", "name", "type"), build, tables)


def fidx(e: E, cls, name, type_):
    return _call(e, "dx_fidx", cls, name, type_)


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


# -- S15e.6d.3: the libxposed adapters -----------------------------------------------------------------------------------


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


# The DEX programs' shared helpers (the bridge program here, the class-file writer in ``xax_selfhost_dex_writer``).
HELPERS = (
    ("dx_less", _less_fn), ("dx_same", _same_fn), ("dx_string", _string_fn), ("dx_word", _word_fn),
    ("dx_push", _push_fn), ("dx_fieldless", _field_less_fn), ("dx_fieldsame", _field_same_fn), ("dx_field", _field_fn),
    ("dx_fidx", _fidx_fn), ("dx_sort", _sort_fn), ("dx_find", _find_fn), ("dx_listless", _list_less_fn),
    ("dx_listsame", _list_same_fn), ("dx_protoless", _proto_less_fn), ("dx_intern", _intern_fn), ("dx_proto", _proto_in_fn),
    ("dx_method", _method_fn), ("dx_methodless", _method_less_fn), ("dx_methodsame", _method_same_fn), ("dx_sortrec", _sort_records_fn),
    ("dx_midx", _midx_fn), ("dx_listat", _list_offset_fn), ("dx_byte", _byte_fn), ("dx_le", _le_fn),
    ("dx_set32", _set32_fn), ("dx_align", _align_fn), ("dx_uleb", _uleb_fn), ("dx_mutf8", _mutf8_fn),
    ("dx_code", _code_fn), ("dx_codeat", _code_at_fn), ("dx_sha1", _sha1_block_fn), ("dx_sign", _sign_fn),
    ("dx_sortentries", _sort_entries_fn),
)


_PROGRAM = NativeProgram(STORE_PATH, "dex-bridge")
load_dex_program = _PROGRAM.load
OPT_OUT = "XAX_DEX_BRIDGE_PYTHON"


SERVICE_NAMES = ("framework-name", "framework-version", "remote-preferences", "list-remote-files", "open-remote-file")
READ_NAMES = ("boolean", "int", "long", "float", "string", "contains")


def dex_with_xax(spec, *, required: bool = False) -> bytes | None:
    """The DEX bytes the XAX program writes for a checked ``DexBridgeSpec``, or None where it cannot run or declines
    (unless ``required``)."""
    import os

    import xax_dex as D
    import xax_native

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
    hook = spec.libxposed_hook_intercept
    if hook is None:
        words.append(0)
    else:
        words += [1, int(hook.inspected_argument_index is not None), hook.inspected_argument_index or 0]
        for value in (hook.replacement_string, hook.argument_replacement_string):
            words += [0] if value is None else [1, *text(value)]
    install = spec.libxposed_hook_install
    if install is None:
        words.append(0)
    else:
        words += [1, *text(install.target_class_binary_name), *text(install.target_method_name), *text(install.hooker_class_descriptor)]
        words += [1, *text(install.parameter_type_binary_names[0])] if install.parameter_type_binary_names else [0]
        words += [*text(install.exception_mode), int(install.lifetime_policy == "retained-manual-unhook"), int(install.deoptimize_before_hook)]
        words += [0] if install.hook_id is None else [1, *text(install.hook_id)]
    services = spec.libxposed_module_services
    words.append(0 if services is None else sum(1 << k for k, name in enumerate(SERVICE_NAMES) if name in services.services))
    preferences = spec.libxposed_remote_preferences
    words.append(0 if preferences is None else sum(1 << k for k, name in enumerate(READ_NAMES) if name in preferences.reads))
    reload = spec.libxposed_hot_reload
    words += [0] if reload is None else [1, *text(reload.hooker_class_descriptor), *text(reload.hook_id)]
    files = spec.libxposed_remote_files
    words.append(0 if files is None else int("list" in files.operations) | (2 * int("open" in files.operations)))
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
