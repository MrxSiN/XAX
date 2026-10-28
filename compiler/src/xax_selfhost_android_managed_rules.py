"""S15e.6f.2 (ADR-336): the managed-class Android profile's decisions (``xax_build._build_android_managed_apk``) as an XAX
program.

The program evaluates the profile's rule sites in the bootstrap's order: distinct class descriptors (``M1``), the DEX 039
SDK floor (``M2``), the manifest Activity among the classes (``M3``), each method's JNI export (``M4``) and its ABI
signature (``M5``: ``JNIEnv*``, the receiver and the arguments at their JNI widths or as borrowed references to their
families, the result likewise), the build entry among the Activity's exports (``M6``), and the platform-usage rules
(``M7``): the platform declarations' own rules (foreground-service permissions and prerequisites, the boot-completed
permission, the Activity, ``maxSdkVersion`` below ``minSdk``), the API level of every reachable platform member, the
permissions of every capability used and of every reachable NDK contract (with ``maxSdkVersion`` coverage), the
acquire/release pairs, the abstract callback methods, the super calls the framework requires, and the declared
components.  The platform tables (``xax_android_platform``, ``xax_manifest``) are the program's constant data.  It writes
the JNI-signature reason and every platform problem as the diagnostic's text.  The host decodes the carriers, extracts
the export functions' interface type facts, and walks the platform members and objects reachable from the exports.

Output: the status (1), the verdict (word 1: 0 accepted, ``k`` for ``Mk``), the class and method positions (words 2, 3)
and at ``TEXT_AT`` the texts ``[count, (length, bytes one per word)...]``.
"""

from __future__ import annotations

from xax_compiler import x86_64_linux_exec_target
from xax_graph_builder import program_store
from xax_native import bootstrap_dir
from xax_selfhost_facts import E, H_ARENA, H_ARENA_END, NONE, _function
from xax_selfhost_views_backend import _FN, NativeProgram, _call, _ok
from xax_selfhost_x86_64_general import GENERAL_ARENA_AT, GENERAL_ARENA_END

STORE_PATH = bootstrap_dir() / "xax_android_managed_rules.xax"
STATE_AT = 110 << 20
(G_CUR, G_TCUR, G_TEXT_N, G_TEXT_AT, G_CUR_TEXT, G_EXPORTS, G_DECLARED, G_METHODS, G_MIN, G_TARGET, G_CLS, G_NC) = (STATE_AT + k for k in range(12))
# A class record: CID, descriptor (UTF-8), descriptor (UTF-16), superclass, interfaces, method count, methods; a method
# record: name, descriptor, super flag, native name (UTF-16).
CLASS_WORDS, METHOD_WORDS = 7, 4
G_K = STATE_AT + 64  # the constant texts' handles
TABLE_AT = STATE_AT + 4096  # the platform tables, packed eight bytes to a word
TEXT_AT = 4096
TEXT_END = 100 << 20
PRIMITIVES = "ZBCSIJFD"
REFERENCE_KINDS = {"LOCAL": 1, "BORROWED": 2}
TEXTS = ["ABI parameters, expected JNIEnv*, this and ", " argument(s)", "first parameter is not JNIEnv*", "parameter ", " is not the JNI width of ",
         " is not a borrowed JNI reference to ", "void method with a non-proof result", " non-proof results for ", "result is not the JNI width of ",
         "result is not a local or borrowed JNI reference to ", ": foreground service needs android.permission.FOREGROUND_SERVICE",
         ": foregroundServiceType ", " needs ", " (targetSdk >= 34)", " needs one of [", "', '", "']", ": android.intent.action.BOOT_COMPLETED needs "
         "android.permission.RECEIVE_BOOT_COMPLETED", ": already the manifest Activity", ": maxSdkVersion ", " is below minSdk ", " (never requested)",
         ": needs ", " maxSdkVersion ", " does not cover the API levels that need it", ": needs API ", ", minSdk is ", ".", " is acquired but ",
         " is never reachable", " requires ", ": the framework override must call super", ": declared ", " is not a managed class in this APK",
         ": a ", " must extend ", "android.permission.FOREGROUND_SERVICE", "android.intent.action.BOOT_COMPLETED",
         "android.permission.RECEIVE_BOOT_COMPLETED", ": ", "'", "service"]
T = {text: k for k, text in enumerate(TEXTS)}


def _constant(text: str) -> int:
    """The constant text's slot (registered while the helpers are built; the frontend, built last, stores them all)."""
    if text not in T:
        T[text] = len(TEXTS)
        TEXTS.append(text)
    return T[text]


def _table_blob() -> bytes:
    """The platform tables as bytes: lengths and numbers two bytes little endian, texts UTF-8, CIDs 32 bytes."""
    from xax_android_platform import CALLBACK_ABSTRACT_METHODS, CAPABILITIES, COMPONENT_SUPERCLASSES, SUPER_REQUIRED, _ndk_permission_index
    from xax_manifest import FOREGROUND_SERVICE_PREREQUISITES, FOREGROUND_SERVICE_TYPES

    out = bytearray()
    n = lambda value: out.extend(value.to_bytes(2, "little"))  # noqa: E731

    def text(value: str) -> None:
        raw = value.encode("utf-8")
        n(len(raw))
        out.extend(raw)

    def member(item) -> None:
        text(item.owner), text(item.name), text(item.descriptor)

    def rules(items) -> None:
        n(len(items))
        for rule in items:
            text(rule.permission), n(rule.from_target), n(rule.device_max)

    n(len(CAPABILITIES))
    for capability in CAPABILITIES:
        text(capability.name), n(capability.min_api)
        n(len(capability.members))
        for item in capability.members:
            member(item)
        rules(capability.permissions)
        n(len(capability.releases))
        for acquire, release in capability.releases:
            member(acquire), member(release)
    for table in (CALLBACK_ABSTRACT_METHODS, {key: tuple(sorted(value)) for key, value in SUPER_REQUIRED.items()}):
        n(len(table))
        for parent, methods in table.items():
            text(parent)
            n(len(methods))
            for name, descriptor in methods:
                text(name), text(descriptor)
    text(COMPONENT_SUPERCLASSES["service"]), text(COMPONENT_SUPERCLASSES["receiver"])
    index = sorted(_ndk_permission_index().items())
    n(len(index))
    for cid, (name, items) in index:
        out.extend(cid)
        text(name)
        rules(items)
    n(len(FOREGROUND_SERVICE_TYPES))
    for name, (_flag, permission) in FOREGROUND_SERVICE_TYPES.items():
        text(name), text(permission or "")
    n(len(FOREGROUND_SERVICE_PREREQUISITES))
    for name, options in FOREGROUND_SERVICE_PREREQUISITES.items():
        text(name)
        n(len(options))
        for item in options:
            text(item)
    return bytes(out)


def at(e: E, base, k):
    return e.ld(e.add(base, k))


def _shift_bytes(e: E, k):
    result = e.c(1)
    for q in range(1, 8):
        result = e.sel(e.eq(k, q), 1 << (8 * q), result)
    return result


# -- reading: the input and the tables ---------------------------------------------------------------------------------------

def _word_fn(tables):
    def build(e: E):
        p = e.p
        e.var("wd_at", e.ld(G_CUR))
        e.st(G_CUR, e.add(p["wd_at"], 1))
        e.give(e.rd(p["wd_at"]))
    return _function((), build, tables)


def _seq_fn(tables):
    """``seq()``: the input sequence at the cursor (count, then one word per item) as an arena handle."""
    def build(e: E):
        p = e.p
        e.var("sq_at", e.ld(G_CUR))
        e.var("sq_n", e.rd(p["sq_at"]))
        _ok(e, e.le(p["sq_n"], 1 << 20))
        e.var("sq_h", e.alloc(e.add(p["sq_n"], 1)))
        _ok(e, e.ne(p["sq_h"], NONE))
        e.st(p["sq_h"], p["sq_n"])
        e.for_("sq_k", 0, p["sq_n"], lambda: e.st(e.add(e.add(p["sq_h"], 1), p["sq_k"]), e.rd(e.add(e.add(p["sq_at"], 1), p["sq_k"]))))
        e.st(G_CUR, e.add(e.add(p["sq_at"], 1), p["sq_n"]))
        e.give(p["sq_h"])
    return _function((), build, tables)


def _list_fn(tables):
    """``list()``: a count, then that many sequences (``[n, handles...]``)."""
    def build(e: E):
        p = e.p
        e.var("li_n", _call(e, "mr_word"))
        _ok(e, e.le(p["li_n"], 1 << 20))
        e.var("li_h", e.alloc(e.add(p["li_n"], 1)))
        _ok(e, e.ne(p["li_h"], NONE))
        e.st(p["li_h"], p["li_n"])
        e.for_("li_k", 0, p["li_n"], lambda: e.st(e.add(e.add(p["li_h"], 1), p["li_k"]), _call(e, "mr_seq")))
        e.give(p["li_h"])
    return _function((), build, tables)


def _tbyte(e: E, k):
    return e.and_(e.udiv(e.ld(e.add(TABLE_AT, e.udiv(k, 8))), _shift_bytes(e, e.urem(k, 8))), 255)


def _tn_fn(tables):
    """``tn()``: the table's next two-byte number."""
    def build(e: E):
        p = e.p
        e.var("tn_at", e.ld(G_TCUR))
        e.st(G_TCUR, e.add(p["tn_at"], 2))
        e.give(e.add(_tbyte(e, p["tn_at"]), e.mul(_tbyte(e, e.add(p["tn_at"], 1)), 256)))
    return _function((), build, tables)


def _ttext_fn(tables):
    """``ttext()``: the table's next text (or, with ``n`` nonzero, the next ``n`` bytes) as an arena handle."""
    def build(e: E):
        p = e.p
        e.var("tt_n", p["n"])
        e.if_(e.eq(p["n"], 0), lambda: e.set("tt_n", _call(e, "mr_tn")))  # (a ``sel`` would read the length either way)
        e.var("tt_at", e.ld(G_TCUR))
        e.var("tt_h", e.alloc(e.add(p["tt_n"], 1)))
        _ok(e, e.ne(p["tt_h"], NONE))
        e.st(p["tt_h"], p["tt_n"])
        e.for_("tt_k", 0, p["tt_n"], lambda: e.st(e.add(e.add(p["tt_h"], 1), p["tt_k"]), _tbyte(e, e.add(p["tt_at"], p["tt_k"]))))
        e.st(G_TCUR, e.add(p["tt_at"], p["tt_n"]))
        e.give(p["tt_h"])
    return _function(("n",), build, tables)


# -- texts ----------------------------------------------------------------------------------------------------------------------

def _same_fn(tables):
    def build(e: E):
        p = e.p
        e.if_(e.either(e.eq(p["a"], 0), e.eq(p["b"], 0)), lambda: e.give(e.flag(e.eq(p["a"], p["b"]))))
        e.if_(e.ne(e.ld(p["a"]), e.ld(p["b"])), lambda: e.give(0))
        e.for_("sm_k", 1, e.add(e.ld(p["a"]), 1),
               lambda: e.if_(e.ne(e.ld(e.add(p["a"], p["sm_k"])), e.ld(e.add(p["b"], p["sm_k"]))), lambda: e.give(0)))
        e.give(1)
    return _function(("a", "b"), build, tables)


def _less_fn(tables):
    """1 when ``a`` sorts before ``b`` (bytes; a prefix first)."""
    def build(e: E):
        p = e.p
        e.var("ls_an", e.ld(p["a"]))
        e.var("ls_bn", e.ld(p["b"]))
        e.var("ls_n", e.sel(e.lt(p["ls_an"], p["ls_bn"]), p["ls_an"], p["ls_bn"]))

        def compare():
            e.var("ls_x", at(e, p["a"], e.add(p["ls_k"], 1)))
            e.var("ls_y", at(e, p["b"], e.add(p["ls_k"], 1)))
            e.if_(e.lt(p["ls_x"], p["ls_y"]), lambda: e.give(1))
            e.if_(e.lt(p["ls_y"], p["ls_x"]), lambda: e.give(0))

        e.for_("ls_k", 0, p["ls_n"], compare)
        e.give(e.flag(e.lt(p["ls_an"], p["ls_bn"])))
    return _function(("a", "b"), build, tables)


def _begin_fn(tables):
    """Starts the next output text."""
    def build(e: E):
        p = e.p
        e.var("bg_at", e.ld(G_TEXT_AT))
        _ok(e, e.lt(e.add(p["bg_at"], 1), TEXT_END))
        e.st(G_CUR_TEXT, p["bg_at"])
        e.st(p["bg_at"], 0)
        e.st(G_TEXT_AT, e.add(p["bg_at"], 1))
        e.st(TEXT_AT, e.add(e.ld(TEXT_AT), 1))
        e.give(1)
    return _function((), build, tables)


def _put_fn(tables):
    """``put(byte)``: one more byte of the current output text."""
    def build(e: E):
        p = e.p
        e.var("pt_at", e.ld(G_TEXT_AT))
        _ok(e, e.lt(p["pt_at"], TEXT_END))
        e.st(p["pt_at"], p["byte"])
        e.st(G_TEXT_AT, e.add(p["pt_at"], 1))
        e.var("pt_len", e.ld(G_CUR_TEXT))
        e.st(p["pt_len"], e.add(e.ld(p["pt_len"]), 1))
        e.give(1)
    return _function(("byte",), build, tables)


def _emit_fn(tables):
    """``emit(h)``: the bytes of handle ``h``."""
    def build(e: E):
        p = e.p
        e.for_("em_k", 1, e.add(e.ld(p["h"]), 1), lambda: _call(e, "mr_put", at(e, p["h"], p["em_k"])))
        e.give(1)
    return _function(("h",), build, tables)


def _number_fn(tables):
    """``number(v)``: ``v`` in decimal."""
    def build(e: E):
        p = e.p
        e.var("nb_d", e.alloc(24))
        _ok(e, e.ne(p["nb_d"], NONE))
        e.var("nb_n", 0)
        e.var("nb_v", p["v"])

        def digit():
            e.st(e.add(p["nb_d"], p["nb_n"]), e.add(ord("0"), e.urem(p["nb_v"], 10)))
            e.set("nb_n", e.add(p["nb_n"], 1))
            e.set("nb_v", e.udiv(p["nb_v"], 10))

        digit()
        e.while_(lambda: e.ne(p["nb_v"], 0), digit)
        e.while_(lambda: e.lt(0, p["nb_n"]), lambda: (e.set("nb_n", e.sub(p["nb_n"], 1)), _call(e, "mr_put", e.ld(e.add(p["nb_d"], p["nb_n"])))))
        e.give(1)
    return _function(("v",), build, tables)


class Text:
    """Builds one output text from handles, constant texts and numbers."""

    def __init__(self, e: E):
        self.e = e
        _call(e, "mr_begin")

    def __call__(self, *parts):
        e = self.e
        for part in parts:
            if isinstance(part, str):
                _call(e, "mr_emit", e.ld(G_K + _constant(part)))
            elif isinstance(part, tuple) and part[0] == "n":
                _call(e, "mr_number", part[1])
            else:
                _call(e, "mr_emit", part)
        return self


def _java_family_fn(tables):
    """``family(d)``: a reference descriptor's JNI family (``L...;`` without its delimiters, ``[...`` whole; ``/`` as
    ``.``)."""
    def build(e: E):
        p = e.p
        e.var("jf_l", e.flag(e.eq(at(e, p["d"], 1), ord("L"))))
        e.var("jf_n", e.sub(e.ld(p["d"]), e.mul(p["jf_l"], 2)))
        e.var("jf_h", e.alloc(e.add(p["jf_n"], 1)))
        _ok(e, e.ne(p["jf_h"], NONE))
        e.st(p["jf_h"], p["jf_n"])
        e.for_("jf_k", 0, p["jf_n"], lambda: (e.var("jf_u", at(e, p["d"], e.add(e.add(p["jf_k"], 1), p["jf_l"]))),
                                              e.st(e.add(e.add(p["jf_h"], 1), p["jf_k"]), e.sel(e.eq(p["jf_u"], ord("/")), ord("."), p["jf_u"]))))
        e.give(p["jf_h"])
    return _function(("d",), build, tables)


def _parse_fn(tables):
    """``parse(d)``: the JVM method descriptor ``d``'s parameters and result as a list ``[n + 1, parameters..., result]``
    (the descriptor was checked when its carrier was decoded)."""
    def build(e: E):
        p = e.p
        e.var("pa_h", e.alloc(e.add(e.ld(p["d"]), 2)))
        _ok(e, e.ne(p["pa_h"], NONE))
        e.var("pa_n", 0)
        e.var("pa_k", 2)  # after "("

        def one():
            e.var("pa_s", p["pa_k"])
            e.while_(lambda: e.eq(at(e, p["d"], p["pa_k"]), ord("[")), lambda: e.set("pa_k", e.add(p["pa_k"], 1)))
            e.if_(e.eq(at(e, p["d"], p["pa_k"]), ord("L")), lambda: e.while_(lambda: e.ne(at(e, p["d"], p["pa_k"]), ord(";")),
                                                                            lambda: e.set("pa_k", e.add(p["pa_k"], 1))))
            e.set("pa_k", e.add(p["pa_k"], 1))
            e.var("pa_t", e.alloc(e.add(e.sub(p["pa_k"], p["pa_s"]), 1)))
            _ok(e, e.ne(p["pa_t"], NONE))
            e.st(p["pa_t"], e.sub(p["pa_k"], p["pa_s"]))
            e.for_("pa_j", 0, e.sub(p["pa_k"], p["pa_s"]), lambda: e.st(e.add(e.add(p["pa_t"], 1), p["pa_j"]), at(e, p["d"], e.add(p["pa_s"], p["pa_j"]))))
            e.set("pa_n", e.add(p["pa_n"], 1))
            e.st(e.add(p["pa_h"], p["pa_n"]), p["pa_t"])

        e.while_(lambda: e.ne(at(e, p["d"], p["pa_k"]), ord(")")), one)
        e.set("pa_k", e.add(p["pa_k"], 1))
        one()
        e.st(p["pa_h"], p["pa_n"])
        e.give(p["pa_h"])
    return _function(("d",), build, tables)


def _primitive(e: E, h):
    """The primitive's position in ``PRIMITIVES`` + 1, or 0 for a reference descriptor."""
    result = e.c(0)
    for k, char in enumerate(PRIMITIVES):
        result = e.sel(e.both(e.eq(e.ld(h), 1), e.eq(at(e, h, 1), ord(char))), k + 1, result)
    return result


def _signature_fn(tables):
    """``signature(method descriptor, class descriptor, parameters, results)``: 1 and the reason as the next text where
    the export's interface facts (each ``[env, width mask, reference kind, family...]``) cannot implement the method;
    0 otherwise."""
    def build(e: E):
        p = e.p
        e.var("sg_parsed", _call(e, "mr_parse", p["method"]))
        e.var("sg_jn", e.sub(e.ld(p["sg_parsed"]), 1))
        e.var("sg_result", at(e, p["sg_parsed"], e.ld(p["sg_parsed"])))
        e.var("sg_pn", e.ld(p["params"]))

        def reason(*parts):
            Text(e)(*parts)
            e.give(1)

        e.if_(e.ne(p["sg_pn"], e.add(2, p["sg_jn"])), lambda: reason(("n", p["sg_pn"]), " ", "ABI parameters, expected JNIEnv*, this and ",
                                                                      ("n", p["sg_jn"]), " argument(s)"))
        e.if_(e.eq(at(e, at(e, p["params"], 1), 1), 0), lambda: reason("first parameter is not JNIEnv*"))

        def parameter():
            e.var("sg_d", e.sel(e.eq(p["sg_i"], 1), p["klass"], at(e, p["sg_parsed"], e.sub(p["sg_i"], 1))))
            e.var("sg_f", at(e, p["params"], e.add(p["sg_i"], 1)))
            e.var("sg_prim", _primitive(e, p["sg_d"]))
            e.if_(e.ne(p["sg_prim"], 0), lambda: e.if_(e.eq(e.and_(at(e, p["sg_f"], 2), e.mul(1, _bit(e, p["sg_prim"]))), 0),
                                                       lambda: reason("parameter ", ("n", p["sg_i"]), " is not the JNI width of ", p["sg_d"])),
                  lambda: e.if_(e.either(e.ne(at(e, p["sg_f"], 3), REFERENCE_KINDS["BORROWED"]),
                                         e.eq(_call(e, "mr_samefamily", p["sg_f"], _call(e, "mr_family", p["sg_d"])), 0)),
                                lambda: reason("parameter ", ("n", p["sg_i"]), " is not a borrowed JNI reference to ", p["sg_d"])))

        e.for_("sg_i", 1, p["sg_pn"], parameter)
        e.var("sg_rn", e.ld(p["results"]))
        e.var("sg_void", e.flag(e.both(e.eq(e.ld(p["sg_result"]), 1), e.eq(at(e, p["sg_result"], 1), ord("V")))))
        e.if_(e.ne(p["sg_void"], 0), lambda: (e.if_(e.ne(p["sg_rn"], 0), lambda: reason("void method with a non-proof result")), e.give(0)))
        e.if_(e.ne(p["sg_rn"], 1), lambda: reason(("n", p["sg_rn"]), " non-proof results for ", p["sg_result"]))
        e.var("sg_rf", at(e, p["results"], 1))
        e.var("sg_rprim", _primitive(e, p["sg_result"]))
        e.if_(e.ne(p["sg_rprim"], 0), lambda: (e.if_(e.eq(e.and_(at(e, p["sg_rf"], 2), _bit(e, p["sg_rprim"])), 0),
                                                     lambda: reason("result is not the JNI width of ", p["sg_result"])), e.give(0)))
        e.if_(e.either(e.eq(at(e, p["sg_rf"], 3), 0), e.either(e.eq(_call(e, "mr_samefamily", p["sg_rf"], _call(e, "mr_family", p["sg_result"])), 0),
                                                              e.lt(REFERENCE_KINDS["BORROWED"], at(e, p["sg_rf"], 3)))),
              lambda: reason("result is not a local or borrowed JNI reference to ", p["sg_result"]))
        e.give(0)
    return _function(("method", "klass", "params", "results"), build, tables)


def _bit(e: E, position):
    """``1 << (position - 1)`` for a primitive position 1..8."""
    result = e.c(1)
    for k in range(2, 9):
        result = e.sel(e.eq(position, k), 1 << (k - 1), result)
    return result


def _same_family_fn(tables):
    """1 when the fact ``f`` (``[env, mask, kind, family bytes...]``) names the family ``h``."""
    def build(e: E):
        p = e.p
        e.if_(e.ne(e.sub(e.ld(p["f"]), 3), e.ld(p["h"])), lambda: e.give(0))
        e.for_("sf_k", 1, e.add(e.ld(p["h"]), 1), lambda: e.if_(e.ne(at(e, p["f"], e.add(p["sf_k"], 3)), at(e, p["h"], p["sf_k"])), lambda: e.give(0)))
        e.give(1)
    return _function(("f", "h"), build, tables)


def _jni_fn(tables):
    """``jni(d, m)``: the JNI short symbol (bytes) of the UTF-16 class descriptor ``d`` and method ``m``."""
    def build(e: E):
        p = e.p
        e.var("jx_dn", e.ld(p["d"]))
        e.var("jx_h", e.alloc(e.add(e.mul(e.add(p["jx_dn"], e.ld(p["m"])), 6), 8)))
        _ok(e, e.ne(p["jx_h"], NONE))
        e.var("jx_n", 0)

        def out(byte):
            e.st(e.add(e.add(p["jx_h"], 1), p["jx_n"]), byte)
            e.set("jx_n", e.add(p["jx_n"], 1))

        for byte in b"Java_":
            out(byte)

        def mangle(u):
            alnum = e.either(e.both(e.le(ord("A"), u), e.le(u, ord("Z"))), e.either(e.both(e.le(ord("a"), u), e.le(u, ord("z"))),
                                                                                  e.both(e.le(ord("0"), u), e.le(u, ord("9")))))

            def hexed():
                out(ord("_"))
                out(ord("0"))
                for shift in (12, 8, 4, 0):
                    e.var("jx_d", e.and_(e.udiv(u, 1 << shift), 15))
                    out(e.sel(e.lt(p["jx_d"], 10), e.add(p["jx_d"], ord("0")), e.add(p["jx_d"], ord("a") - 10)))

            e.if_(alnum, lambda: out(u), lambda: e.if_(
                e.either(e.eq(u, ord("/")), e.eq(u, ord("."))), lambda: out(ord("_")), lambda: e.if_(
                    e.eq(u, ord("_")), lambda: (out(ord("_")), out(ord("1"))), lambda: e.if_(
                        e.eq(u, ord(";")), lambda: (out(ord("_")), out(ord("2"))), lambda: e.if_(
                            e.eq(u, ord("[")), lambda: (out(ord("_")), out(ord("3"))), hexed)))))

        e.for_("jx_k", 2, p["jx_dn"], lambda: (e.var("jx_c", at(e, p["d"], p["jx_k"])), mangle(p["jx_c"])))
        out(ord("_"))
        e.for_("jx_k", 1, e.add(e.ld(p["m"]), 1), lambda: (e.var("jx_c", at(e, p["m"], p["jx_k"])), mangle(p["jx_c"])))
        e.st(p["jx_h"], p["jx_n"])
        e.give(p["jx_h"])
    return _function(("d", "m"), build, tables)


def _export_fn(tables):
    """``export_of(name)``: the record of the last export named ``name`` (0 where none is)."""
    def build(e: E):
        p = e.p
        e.var("ex_f", 0)
        e.var("ex_l", e.ld(G_EXPORTS))
        e.for_("ex_k", 1, e.add(e.ld(p["ex_l"]), 1), lambda: e.if_(e.ne(_call(e, "mr_same", at(e, at(e, p["ex_l"], p["ex_k"]), 0), p["name"]), 0),
                                                                  lambda: e.set("ex_f", at(e, p["ex_l"], p["ex_k"]))))
        e.give(p["ex_f"])
    return _function(("name",), build, tables)


def _declared_fn(tables):
    """``declared(permission)``: the declared permission's record ``[name, max SDK]`` (0 where it is not declared)."""
    def build(e: E):
        p = e.p
        e.var("dc_f", 0)
        e.var("dc_l", e.ld(G_DECLARED))
        e.for_("dc_k", 1, e.add(e.ld(p["dc_l"]), 1), lambda: e.if_(e.ne(_call(e, "mr_same", at(e, at(e, p["dc_l"], p["dc_k"]), 0), p["name"]), 0),
                                                                  lambda: e.set("dc_f", at(e, p["dc_l"], p["dc_k"]))))
        e.give(p["dc_f"])
    return _function(("name",), build, tables)


def _need_fn(tables):
    """``need(rules, why)``: the problems of a permission rule list ``[n, (permission, from target, device max)...]``."""
    def build(e: E):
        p = e.p

        def rule():
            e.var("nd_r", at(e, p["rules"], e.add(1, e.mul(p["nd_k"], 3))))
            e.var("nd_from", at(e, p["rules"], e.add(2, e.mul(p["nd_k"], 3))))
            e.var("nd_max", at(e, p["rules"], e.add(3, e.mul(p["nd_k"], 3))))
            required = e.both(e.le(p["nd_from"], e.ld(G_TARGET)), e.either(e.eq(p["nd_max"], 0), e.le(e.ld(G_MIN), p["nd_max"])))

            def check():
                e.var("nd_item", _call(e, "mr_declared", p["nd_r"]))
                e.if_(e.eq(p["nd_item"], 0), lambda: Text(e)(p["why"], ": needs ", p["nd_r"]), lambda: e.if_(
                    e.both(e.ne(at(e, p["nd_item"], 1), 0), e.either(e.eq(p["nd_max"], 0), e.lt(at(e, p["nd_item"], 1), p["nd_max"]))),
                    lambda: Text(e)(p["why"], ": ", p["nd_r"], " maxSdkVersion ", ("n", at(e, p["nd_item"], 1)), " does not cover the API levels that need it")))

            e.if_(required, check)

        e.for_("nd_k", 0, e.ld(p["rules"]), rule)
        e.give(1)
    return _function(("rules", "why"), build, tables)


def _rules_fn(tables):
    """``rules()``: the table's next permission rule list ``[n, (permission, from target, device max)...]``."""
    def build(e: E):
        p = e.p
        e.var("rl_n", _call(e, "mr_tn"))
        e.var("rl_h", e.alloc(e.add(e.mul(p["rl_n"], 3), 1)))
        _ok(e, e.ne(p["rl_h"], NONE))
        e.st(p["rl_h"], p["rl_n"])
        e.for_("rl_k", 0, p["rl_n"], lambda: (e.st(e.add(p["rl_h"], e.add(1, e.mul(p["rl_k"], 3))), _call(e, "mr_ttext", 0)),
                                              e.st(e.add(p["rl_h"], e.add(2, e.mul(p["rl_k"], 3))), _call(e, "mr_tn")),
                                              e.st(e.add(p["rl_h"], e.add(3, e.mul(p["rl_k"], 3))), _call(e, "mr_tn"))))
        e.give(p["rl_h"])
    return _function((), build, tables)


def _reached_fn(tables):
    """1 when the reachable platform members hold ``(owner, name, descriptor)`` (the member record ``m``)."""
    def build(e: E):
        p = e.p
        e.var("rc_l", e.ld(G_METHODS))
        e.for_("rc_k", 0, e.udiv(e.ld(p["rc_l"]), 3), lambda: e.if_(e.both(
            e.ne(_call(e, "mr_same", at(e, p["rc_l"], e.add(1, e.mul(p["rc_k"], 3))), at(e, p["m"], 0)), 0),
            e.both(e.ne(_call(e, "mr_same", at(e, p["rc_l"], e.add(2, e.mul(p["rc_k"], 3))), at(e, p["m"], 1)), 0),
                   e.ne(_call(e, "mr_same", at(e, p["rc_l"], e.add(3, e.mul(p["rc_k"], 3))), at(e, p["m"], 2)), 0))), lambda: e.give(1)))
        e.give(0)
    return _function(("m",), build, tables)


def _member_fn(tables):
    """``member()``: the table's next member ``[owner, name, descriptor]``."""
    def build(e: E):
        p = e.p
        e.var("mm_h", e.alloc(3))
        _ok(e, e.ne(p["mm_h"], NONE))
        for k in range(3):
            e.st(e.add(p["mm_h"], k), _call(e, "mr_ttext", 0))
        e.give(p["mm_h"])
    return _function((), build, tables)


def _platform_fn(tables):
    """The platform problems (``platform_usage_violations``), each the next text."""
    def build(e: E):
        p = e.p
        word = lambda: _call(e, "mr_word")  # noqa: E731
        seq = lambda: _call(e, "mr_seq")  # noqa: E731
        listed = lambda: _call(e, "mr_list")  # noqa: E731
        tn = lambda: _call(e, "mr_tn")  # noqa: E731
        ttext = lambda: _call(e, "mr_ttext", 0)  # noqa: E731
        same = lambda a, b: e.ne(_call(e, "mr_same", a, b), 0)  # noqa: E731
        K = lambda text: e.ld(G_K + _constant(text))  # noqa: E731
        e.var("activity", e.ld(STATE_AT + 32))
        # The declarations: permission records [name, max SDK]; components [kind, class name, types, actions].
        e.var("np", word())
        _ok(e, e.le(p["np"], 1 << 16))
        e.var("perms", e.alloc(e.add(p["np"], 1)))
        _ok(e, e.ne(p["perms"], NONE))
        e.st(p["perms"], p["np"])

        def permission():
            e.var("pr", e.alloc(2))
            _ok(e, e.ne(p["pr"], NONE))
            e.st(p["pr"], seq())
            e.st(e.add(p["pr"], 1), word())
            e.st(e.add(p["perms"], e.add(p["q"], 1)), p["pr"])

        e.for_("q", 0, p["np"], permission)
        e.st(G_DECLARED, p["perms"])
        e.var("ncomp", word())
        _ok(e, e.le(p["ncomp"], 1 << 16))
        e.var("comps", e.alloc(e.add(e.mul(p["ncomp"], 4), 1)))
        _ok(e, e.ne(p["comps"], NONE))
        e.for_("q", 0, p["ncomp"], lambda: [e.st(e.add(p["comps"], e.add(e.mul(p["q"], 4), k)), seq() if k < 2 else listed()) for k in range(4)])
        e.st(G_METHODS, listed())  # the reachable members, three texts each
        e.var("objects", listed())
        # The tables: capabilities [name, min API, members, rules, releases, used].
        e.st(G_TCUR, 0)
        e.var("ncap", tn())
        e.var("caps", e.alloc(e.add(e.mul(p["ncap"], 6), 1)))
        _ok(e, e.ne(p["caps"], NONE))

        def capability():
            e.var("cb", e.add(p["caps"], e.mul(p["q"], 6)))
            e.st(p["cb"], ttext())
            e.st(e.add(p["cb"], 1), tn())
            e.var("nm", tn())
            e.var("ms", e.alloc(e.add(p["nm"], 1)))
            _ok(e, e.ne(p["ms"], NONE))
            e.st(p["ms"], p["nm"])
            e.for_("j", 0, p["nm"], lambda: e.st(e.add(p["ms"], e.add(p["j"], 1)), _call(e, "mr_member")))
            e.st(e.add(p["cb"], 2), p["ms"])
            e.st(e.add(p["cb"], 3), _call(e, "mr_rules"))
            e.var("nr", tn())
            e.var("rs", e.alloc(e.add(e.mul(p["nr"], 2), 1)))
            _ok(e, e.ne(p["rs"], NONE))
            e.st(p["rs"], p["nr"])
            e.for_("j", 0, p["nr"], lambda: (e.st(e.add(p["rs"], e.add(1, e.mul(p["j"], 2))), _call(e, "mr_member")),
                                             e.st(e.add(p["rs"], e.add(2, e.mul(p["j"], 2))), _call(e, "mr_member"))))
            e.st(e.add(p["cb"], 4), p["rs"])
            e.st(e.add(p["cb"], 5), 0)

        e.for_("q", 0, p["ncap"], capability)

        def pairs_table(name):
            e.var(f"n{name}", tn())
            e.var(name, e.alloc(e.add(e.mul(p[f"n{name}"], 2), 1)))
            _ok(e, e.ne(p[name], NONE))

            def parent():
                e.st(e.add(p[name], e.mul(p["q"], 2)), ttext())
                e.var("nk", tn())
                e.var("ks", e.alloc(e.add(e.mul(p["nk"], 2), 1)))
                _ok(e, e.ne(p["ks"], NONE))
                e.st(p["ks"], p["nk"])
                e.for_("j", 0, p["nk"], lambda: (e.st(e.add(p["ks"], e.add(1, e.mul(p["j"], 2))), ttext()),
                                                 e.st(e.add(p["ks"], e.add(2, e.mul(p["j"], 2))), ttext())))
                e.st(e.add(p[name], e.add(e.mul(p["q"], 2), 1)), p["ks"])

            e.for_("q", 0, p[f"n{name}"], parent)

        pairs_table("callbacks")
        pairs_table("supers")
        e.var("service_super", ttext())
        e.var("receiver_super", ttext())
        e.var("nndk", tn())
        e.var("ndk", e.alloc(e.add(e.mul(p["nndk"], 3), 1)))
        _ok(e, e.ne(p["ndk"], NONE))
        e.for_("q", 0, p["nndk"], lambda: (e.st(e.add(p["ndk"], e.mul(p["q"], 3)), _call(e, "mr_ttext", 32)),
                                           e.st(e.add(p["ndk"], e.add(e.mul(p["q"], 3), 1)), ttext()),
                                           e.st(e.add(p["ndk"], e.add(e.mul(p["q"], 3), 2)), _call(e, "mr_rules"))))
        e.var("nfg", tn())
        e.var("fg", e.alloc(e.add(e.mul(p["nfg"], 2), 1)))
        _ok(e, e.ne(p["fg"], NONE))
        e.for_("q", 0, p["nfg"], lambda: (e.st(e.add(p["fg"], e.mul(p["q"], 2)), ttext()), e.st(e.add(p["fg"], e.add(e.mul(p["q"], 2), 1)), ttext())))
        e.var("npre", tn())
        e.var("pre", e.alloc(e.add(e.mul(p["npre"], 2), 1)))
        _ok(e, e.ne(p["pre"], NONE))

        def prerequisite():
            e.st(e.add(p["pre"], e.mul(p["q"], 2)), ttext())
            e.var("no", tn())
            e.var("os", e.alloc(e.add(p["no"], 1)))
            _ok(e, e.ne(p["os"], NONE))
            e.st(p["os"], p["no"])
            e.for_("j", 0, p["no"], lambda: e.st(e.add(p["os"], e.add(p["j"], 1)), ttext()))
            e.st(e.add(p["pre"], e.add(e.mul(p["q"], 2), 1)), p["os"])

        e.for_("q", 0, p["npre"], prerequisite)
        declared = lambda name: e.ne(_call(e, "mr_declared", name), 0)  # noqa: E731
        target = e.ld(G_TARGET)

        # The platform declarations' own rules (``platform_declaration_violations``), component by component.
        def component():
            e.var("cp", e.add(p["comps"], e.mul(p["q"], 4)))
            e.var("cname", at(e, p["cp"], 1))
            e.var("ctypes", at(e, p["cp"], 2))
            e.var("cactions", at(e, p["cp"], 3))
            e.if_(e.both(e.lt(0, e.ld(p["ctypes"])), e.eq(e.flag(declared(K("android.permission.FOREGROUND_SERVICE"))), 0)),
                  lambda: Text(e)(p["cname"], ": foreground service needs android.permission.FOREGROUND_SERVICE"))

            def kind():
                e.var("tk", at(e, p["ctypes"], p["j"]))
                e.var("needed", 0)
                e.for_("f", 0, p["nfg"], lambda: e.if_(same(at(e, p["fg"], e.mul(p["f"], 2)), p["tk"]), lambda: e.set("needed", at(e, p["fg"], e.add(e.mul(p["f"], 2), 1)))))
                e.if_(e.both(e.le(34, target), e.lt(0, e.ld(p["needed"]))), lambda: e.if_(
                    e.eq(e.flag(declared(p["needed"])), 0), lambda: Text(e)(p["cname"], ": foregroundServiceType ", p["tk"], " needs ", p["needed"], " (targetSdk >= 34)")))
                e.var("options", 0)
                e.for_("f", 0, p["npre"], lambda: e.if_(same(at(e, p["pre"], e.mul(p["f"], 2)), p["tk"]), lambda: e.set("options", at(e, p["pre"], e.add(e.mul(p["f"], 2), 1)))))

                def listing():
                    e.var("met", 0)
                    e.for_("f", 1, e.add(e.ld(p["options"]), 1), lambda: e.if_(declared(at(e, p["options"], p["f"])), lambda: e.set("met", 1)))

                    def problem():
                        text = Text(e)(p["cname"], ": foregroundServiceType ", p["tk"], " needs one of [", "'")
                        e.for_("f", 1, e.add(e.ld(p["options"]), 1), lambda: (e.if_(e.lt(1, p["f"]), lambda: text("', '")), text(at(e, p["options"], p["f"]))))
                        text("']")

                    e.if_(e.eq(p["met"], 0), problem)

                e.if_(e.both(e.le(34, target), e.ne(p["options"], 0)), lambda: e.if_(e.lt(0, e.ld(p["options"])), listing))

            e.for_("j", 1, e.add(e.ld(p["ctypes"]), 1), kind)
            e.if_(e.both(e.ne(_call(e, "mr_lmember", p["cactions"], K("android.intent.action.BOOT_COMPLETED")), 0),
                         e.eq(e.flag(declared(K("android.permission.RECEIVE_BOOT_COMPLETED"))), 0)),
                  lambda: Text(e)(p["cname"], ": android.intent.action.BOOT_COMPLETED needs android.permission.RECEIVE_BOOT_COMPLETED"))
            e.if_(same(p["cname"], p["activity"]), lambda: Text(e)(p["cname"], ": already the manifest Activity"))

        e.for_("q", 0, p["ncomp"], component)
        e.for_("q", 1, e.add(p["np"], 1), lambda: (e.var("pp", at(e, p["perms"], p["q"])), e.if_(
            e.both(e.ne(at(e, p["pp"], 1), 0), e.lt(at(e, p["pp"], 1), e.ld(G_MIN))),
            lambda: Text(e)(e.ld(p["pp"]), ": maxSdkVersion ", ("n", at(e, p["pp"], 1)), " is below minSdk ", ("n", e.ld(G_MIN)), " (never requested)"))))
        # The reachable members in order, their capabilities and API levels.
        e.var("members", e.ld(G_METHODS))
        e.var("nmem", e.udiv(e.ld(p["members"]), 3))
        e.var("order", e.alloc(e.add(p["nmem"], 1)))
        _ok(e, e.ne(p["order"], NONE))
        e.for_("q", 0, p["nmem"], lambda: e.st(e.add(p["order"], p["q"]), e.add(e.add(p["members"], 1), e.mul(p["q"], 3))))
        _call(e, "mr_sortmembers", p["order"], p["nmem"])

        def used():
            e.var("um", e.ld(e.add(p["order"], p["q"])))
            e.var("ucap", NONE)

            def scan():
                e.var("ucb", e.add(p["caps"], e.mul(p["c"], 6)))
                e.var("ums", at(e, p["ucb"], 2))
                e.for_("j", 1, e.add(e.ld(p["ums"]), 1), lambda: (e.var("ume", at(e, p["ums"], p["j"])), e.if_(e.both(e.eq(p["ucap"], NONE), e.both(
                    same(e.ld(p["ume"]), e.ld(p["um"])), e.both(same(at(e, p["ume"], 1), at(e, p["um"], 1)), same(at(e, p["ume"], 2), at(e, p["um"], 2))))),
                    lambda: e.set("ucap", p["ucb"]))))

            e.for_("c", 0, p["ncap"], scan)

            def mark():
                e.st(e.add(p["ucap"], 5), 1)
                e.if_(e.lt(e.ld(G_MIN), at(e, p["ucap"], 1)), lambda: Text(e)(e.ld(p["um"]), ".", at(e, p["um"], 1), at(e, p["um"], 2), ": needs API ",
                                                                             ("n", at(e, p["ucap"], 1)), ", minSdk is ", ("n", e.ld(G_MIN))))

            e.if_(e.ne(p["ucap"], NONE), mark)

        e.for_("q", 0, p["nmem"], used)

        def capability_rules():
            e.var("rcb", e.add(p["caps"], e.mul(p["q"], 6)))

            def releases():
                _call(e, "mr_need", at(e, p["rcb"], 3), at(e, p["rcb"], 0))
                e.var("rr", at(e, p["rcb"], 4))
                e.for_("j", 0, e.ld(p["rr"]), lambda: (
                    e.var("acq", at(e, p["rr"], e.add(1, e.mul(p["j"], 2)))), e.var("rel", at(e, p["rr"], e.add(2, e.mul(p["j"], 2)))),
                    e.if_(e.both(e.ne(_call(e, "mr_reached", p["acq"]), 0), e.eq(_call(e, "mr_reached", p["rel"]), 0)),
                          lambda: Text(e)(at(e, p["rcb"], 0), ": ", e.ld(p["acq"]), ".", at(e, p["acq"], 1), " is acquired but ", e.ld(p["rel"]), ".",
                                          at(e, p["rel"], 1), " is never reachable"))))

            e.if_(e.ne(at(e, p["rcb"], 5), 0), releases)

        e.for_("q", 0, p["ncap"], capability_rules)
        e.for_("q", 0, p["nndk"], lambda: e.if_(e.ne(_call(e, "mr_lmember", p["objects"], at(e, p["ndk"], e.mul(p["q"], 3))), 0),
                                                lambda: _call(e, "mr_need", at(e, p["ndk"], e.add(e.mul(p["q"], 3), 2)), at(e, p["ndk"], e.add(e.mul(p["q"], 3), 1)))))

        # The classes: abstract callback methods, required super calls.
        def klass():
            e.var("kc", e.add(e.ld(G_CLS), e.mul(p["q"], CLASS_WORDS)))
            e.var("knm", at(e, p["kc"], 5))
            e.var("kms", at(e, p["kc"], 6))
            km = lambda f, k: at(e, p["kms"], e.add(e.mul(f, METHOD_WORDS), k))  # noqa: E731

            def implemented(name, descriptor):
                e.var("imp", 0)
                e.for_("f", 0, p["knm"], lambda: e.if_(e.both(same(km(p["f"], 0), name), same(km(p["f"], 1), descriptor)), lambda: e.set("imp", 1)))
                return p["imp"]

            def parent(parent_handle):
                e.var("pt", parent_handle)

                def abstract():
                    e.var("abs", at(e, p["callbacks"], e.add(e.mul(p["f"], 2), 1)))
                    e.for_("g", 0, e.ld(p["abs"]), lambda: (
                        e.var("an", at(e, p["abs"], e.add(1, e.mul(p["g"], 2)))), e.var("ad", at(e, p["abs"], e.add(2, e.mul(p["g"], 2)))),
                        e.if_(e.eq(implemented(p["an"], p["ad"]), 0), lambda: Text(e)(at(e, p["kc"], 1), ": ", p["pt"], " requires ", p["an"], p["ad"]))))

                e.for_("f", 0, p["ncallbacks"], lambda: e.if_(same(at(e, p["callbacks"], e.mul(p["f"], 2)), p["pt"]), abstract))

            parent(at(e, p["kc"], 3))
            e.for_("h", 1, e.add(e.ld(at(e, p["kc"], 4)), 1), lambda: parent(at(e, at(e, p["kc"], 4), p["h"])))

            def supers():
                e.var("required", 0)

                def table():
                    e.var("sr", at(e, p["supers"], e.add(e.mul(p["g"], 2), 1)))
                    e.for_("h", 0, e.ld(p["sr"]), lambda: e.if_(e.both(same(at(e, p["sr"], e.add(1, e.mul(p["h"], 2))), km(p["f"], 0)),
                                                                       same(at(e, p["sr"], e.add(2, e.mul(p["h"], 2))), km(p["f"], 1))), lambda: e.set("required", 1)))

                e.for_("g", 0, p["nsupers"], lambda: e.if_(same(at(e, p["supers"], e.mul(p["g"], 2)), at(e, p["kc"], 3)), table))
                e.if_(e.both(e.ne(p["required"], 0), e.eq(km(p["f"], 2), 0)),
                      lambda: Text(e)(at(e, p["kc"], 1), ".", km(p["f"], 0), ": the framework override must call super"))

            e.for_("f", 0, p["knm"], supers)

        e.for_("q", 0, e.ld(G_NC), klass)

        # The declared components: managed classes of the right superclass.
        def declared_component():
            e.var("dp", e.add(p["comps"], e.mul(p["q"], 4)))
            e.var("dkind", e.ld(p["dp"]))
            e.var("dn", at(e, p["dp"], 1))
            e.var("ddesc", e.alloc(e.add(e.ld(p["dn"]), 3)))
            _ok(e, e.ne(p["ddesc"], NONE))
            e.st(p["ddesc"], e.add(e.ld(p["dn"]), 2))
            e.st(e.add(p["ddesc"], 1), ord("L"))
            e.for_("f", 1, e.add(e.ld(p["dn"]), 1), lambda: (e.var("dc", at(e, p["dn"], p["f"])),
                                                              e.st(e.add(e.add(p["ddesc"], 1), p["f"]), e.sel(e.eq(p["dc"], ord(".")), ord("/"), p["dc"]))))
            e.st(e.add(p["ddesc"], e.add(e.ld(p["dn"]), 2)), ord(";"))
            e.var("found", 0)
            e.for_("f", 0, e.ld(G_NC), lambda: e.if_(same(at(e, e.ld(G_CLS), e.add(e.mul(p["f"], CLASS_WORDS), 1)), p["ddesc"]),
                                                     lambda: e.set("found", e.add(e.ld(G_CLS), e.mul(p["f"], CLASS_WORDS)))))
            e.var("expected", e.sel(same(p["dkind"], K("service")), p["service_super"], p["receiver_super"]))
            e.if_(e.eq(p["found"], 0), lambda: Text(e)(p["dn"], ": declared ", p["dkind"], " is not a managed class in this APK"),
                  lambda: e.if_(e.eq(e.flag(same(at(e, p["found"], 3), p["expected"])), 0),
                                lambda: Text(e)(p["dn"], ": a ", p["dkind"], " must extend ", p["expected"])))

        e.for_("q", 0, p["ncomp"], declared_component)
        e.give(1)
    return _function((), build, tables)


def _sort_members_fn(tables):
    """``sort_members(arr, n)``: the member records at ``arr`` by owner, name and descriptor (stable insertion)."""
    def build(e: E):
        p = e.p

        def less(a, b):
            e.var("sl_r", 0)
            e.var("sl_d", 0)
            for k in range(3):
                e.if_(e.eq(p["sl_d"], 0), lambda k=k: (
                    e.if_(e.ne(_call(e, "mr_less", at(e, a, k), at(e, b, k)), 0), lambda: (e.set("sl_r", 1), e.set("sl_d", 1))),
                    e.if_(e.ne(_call(e, "mr_less", at(e, b, k), at(e, a, k)), 0), lambda: e.set("sl_d", 1))))
            return p["sl_r"]

        def insert():
            e.var("si_item", e.ld(e.add(p["arr"], p["si_s"])))
            e.var("si_j", p["si_s"])
            e.var("si_go", 1)
            e.while_(lambda: e.ne(p["si_go"], 0), lambda: e.if_(e.eq(p["si_j"], 0), lambda: e.set("si_go", 0), lambda: e.if_(
                e.ne(less(p["si_item"], e.ld(e.add(p["arr"], e.sub(p["si_j"], 1)))), 0),
                lambda: (e.st(e.add(p["arr"], p["si_j"]), e.ld(e.add(p["arr"], e.sub(p["si_j"], 1)))), e.set("si_j", e.sub(p["si_j"], 1))),
                lambda: e.set("si_go", 0))))
            e.st(e.add(p["arr"], p["si_j"]), p["si_item"])

        e.for_("si_s", 1, p["n"], insert)
        e.give(1)
    return _function(("arr", "n"), build, tables)


def _list_member_fn(tables):
    """1 when list ``l`` holds a sequence equal to ``h``."""
    def build(e: E):
        p = e.p
        e.for_("lm_k", 1, e.add(e.ld(p["l"]), 1), lambda: e.if_(e.ne(_call(e, "mr_same", at(e, p["l"], p["lm_k"]), p["h"]), 0), lambda: e.give(1)))
        e.give(0)
    return _function(("l", "h"), build, tables)


def _frontend(tables):
    def build(e: E):
        p = e.p
        word = lambda: _call(e, "mr_word")  # noqa: E731
        seq = lambda: _call(e, "mr_seq")  # noqa: E731
        listed = lambda: _call(e, "mr_list")  # noqa: E731
        e.st(0, 0)
        e.set_hd(H_ARENA, GENERAL_ARENA_AT)
        e.set_hd(H_ARENA_END, GENERAL_ARENA_END)
        e.st(G_CUR, 0)
        e.st(TEXT_AT, 0)
        e.st(G_TEXT_AT, TEXT_AT + 1)
        for k, text in enumerate(TEXTS):
            raw = text.encode("utf-8")
            e.var("ck", e.alloc(len(raw) + 1))
            _ok(e, e.ne(p["ck"], NONE))
            e.st(p["ck"], len(raw))
            for j, byte in enumerate(raw):
                e.st(e.add(p["ck"], 1 + j), byte)
            e.st(G_K + k, p["ck"])
        blob = _table_blob()
        blob += bytes(-len(blob) % 8)
        for k in range(0, len(blob), 8):
            e.st(TABLE_AT + k // 8, int.from_bytes(blob[k:k + 8], "little"))

        def verdict(value, klass=0, method=0):
            e.st(1, value)
            e.st(2, klass)
            e.st(3, method)
            e.st(0, 1)
            e.give(1)

        # The classes, one per carrier CID in order.
        e.var("ncls", word())
        _ok(e, e.le(p["ncls"], 1 << 12))
        e.st(G_CLS, e.alloc(e.add(e.mul(p["ncls"], CLASS_WORDS), 1)))
        _ok(e, e.ne(e.ld(G_CLS), NONE))
        e.var("nc", 0)

        def read_class():
            e.var("rc", e.add(e.ld(G_CLS), e.mul(p["nc"], CLASS_WORDS)))
            for k in range(4):  # CID, descriptor (UTF-8), descriptor (UTF-16), superclass
                e.st(e.add(p["rc"], k), seq())
            e.st(e.add(p["rc"], 4), listed())
            e.var("rn", word())
            _ok(e, e.le(p["rn"], 1 << 12))
            e.var("rm", e.alloc(e.add(e.mul(p["rn"], METHOD_WORDS), 1)))
            _ok(e, e.ne(p["rm"], NONE))
            e.st(e.add(p["rc"], 5), p["rn"])
            e.st(e.add(p["rc"], 6), p["rm"])
            e.for_("j", 0, p["rn"], lambda: (e.st(e.add(p["rm"], e.mul(p["j"], METHOD_WORDS)), seq()), e.st(e.add(p["rm"], e.add(e.mul(p["j"], METHOD_WORDS), 1)), seq()),
                                             e.st(e.add(p["rm"], e.add(e.mul(p["j"], METHOD_WORDS), 2)), word()),
                                             e.st(e.add(p["rm"], e.add(e.mul(p["j"], METHOD_WORDS), 3)), seq())))
            e.var("dup", 0)
            e.for_("j", 0, p["nc"], lambda: e.if_(e.ne(_call(e, "mr_same", e.ld(e.add(e.ld(G_CLS), e.mul(p["j"], CLASS_WORDS))), e.ld(p["rc"])), 0),
                                                  lambda: e.set("dup", 1)))
            e.if_(e.eq(p["dup"], 0), lambda: e.set("nc", e.add(p["nc"], 1)))

        e.for_("q", 0, p["ncls"], read_class)
        e.st(G_NC, p["nc"])
        cls = lambda q, k: at(e, e.ld(G_CLS), e.add(e.mul(q, CLASS_WORDS), k))  # noqa: E731
        e.for_("q", 1, p["nc"], lambda: e.for_("j", 0, p["q"], lambda: e.if_(e.ne(_call(e, "mr_same", cls(p["q"], 1), cls(p["j"], 1)), 0), lambda: verdict(1))))
        e.var("activity", seq())
        e.st(STATE_AT + 32, p["activity"])
        e.st(G_MIN, word())
        e.st(G_TARGET, word())
        e.if_(e.lt(e.ld(G_MIN), 28), lambda: verdict(2))
        e.var("activity_class", NONE)
        e.for_("q", 0, p["nc"], lambda: e.if_(e.both(e.eq(p["activity_class"], NONE), e.ne(_call(e, "mr_same", _call(e, "mr_family", cls(p["q"], 1)), p["activity"]), 0)),
                                              lambda: e.set("activity_class", p["q"])))
        e.if_(e.eq(p["activity_class"], NONE), lambda: verdict(3))
        # The exports: [name, function CID, parameter facts, result facts].
        e.var("nex", word())
        _ok(e, e.le(p["nex"], 1 << 16))
        e.var("exports", e.alloc(e.add(p["nex"], 1)))
        _ok(e, e.ne(p["exports"], NONE))
        e.st(p["exports"], p["nex"])

        def export():
            e.var("xr", e.alloc(4))
            _ok(e, e.ne(p["xr"], NONE))
            e.st(p["xr"], seq())
            e.st(e.add(p["xr"], 1), seq())
            e.st(e.add(p["xr"], 2), listed())
            e.st(e.add(p["xr"], 3), listed())
            e.st(e.add(p["exports"], e.add(p["q"], 1)), p["xr"])

        e.for_("q", 0, p["nex"], export)
        e.st(G_EXPORTS, p["exports"])
        e.var("entry", seq())

        def method():
            e.var("mm", e.add(cls(p["q"], 6), e.mul(p["j"], METHOD_WORDS)))
            e.var("export", _call(e, "mr_export", _call(e, "mr_jni", cls(p["q"], 2), at(e, p["mm"], 3))))
            e.if_(e.eq(p["export"], 0), lambda: verdict(4, p["q"], p["j"]))
            e.if_(e.ne(_call(e, "mr_signature", at(e, p["mm"], 1), cls(p["q"], 1), at(e, p["export"], 2), at(e, p["export"], 3)), 0),
                  lambda: verdict(5, p["q"], p["j"]))

        e.for_("q", 0, p["nc"], lambda: e.for_("j", 0, cls(p["q"], 5), method))
        e.var("entry_ok", 0)
        e.for_("j", 0, cls(p["activity_class"], 5), lambda: (
            e.var("am", e.add(cls(p["activity_class"], 6), e.mul(p["j"], METHOD_WORDS))),
            e.var("ax", _call(e, "mr_export", _call(e, "mr_jni", cls(p["activity_class"], 2), at(e, p["am"], 3)))),
            e.if_(e.ne(_call(e, "mr_same", at(e, p["ax"], 1), p["entry"]), 0), lambda: e.set("entry_ok", 1))))
        e.if_(e.eq(p["entry_ok"], 0), lambda: verdict(6))
        _call(e, "mr_platform")
        e.if_(e.lt(0, e.ld(TEXT_AT)), lambda: verdict(7))
        verdict(0)
    return _function((), build, tables)


def build_managed_rules_program():
    """``(reader, function)``: the managed Android rules program's store and its entry."""
    tables = None
    objects: list = []
    _FN.clear()

    def add(name, made):
        function, items = made
        objects.extend(items)
        _FN[name] = function
        return function

    for name, builder in (("mr_word", _word_fn), ("mr_seq", _seq_fn), ("mr_list", _list_fn), ("mr_tn", _tn_fn), ("mr_ttext", _ttext_fn),
                          ("mr_same", _same_fn), ("mr_less", _less_fn), ("mr_begin", _begin_fn), ("mr_put", _put_fn), ("mr_emit", _emit_fn),
                          ("mr_number", _number_fn), ("mr_family", _java_family_fn), ("mr_parse", _parse_fn), ("mr_samefamily", _same_family_fn),
                          ("mr_signature", _signature_fn), ("mr_jni", _jni_fn), ("mr_export", _export_fn), ("mr_declared", _declared_fn),
                          ("mr_need", _need_fn), ("mr_rules", _rules_fn), ("mr_reached", _reached_fn), ("mr_member", _member_fn),
                          ("mr_lmember", _list_member_fn), ("mr_sortmembers", _sort_members_fn), ("mr_platform", _platform_fn)):
        add(name, builder(tables))
    program = add("frontend", _frontend(tables))
    return program_store(program, x86_64_linux_exec_target(), tuple(objects)), program


_PROGRAM = NativeProgram(STORE_PATH, build_managed_rules_program, "android-managed-rules")
load_managed_rules_program = _PROGRAM.load
write_managed_rules_store = _PROGRAM.write
OPT_OUT = "XAX_ANDROID_RULES_PYTHON"


def _facts(reader, manifest_carrier, managed_carriers, export_carriers, build_entry_function, declarations_carrier) -> list[int]:
    from xax_android_managed import _PRIMITIVES, _jni_reference, decode_android_managed_class
    from xax_android_platform import reachable_platform_uses
    from xax_compiler import _decode_function_interface, _is_proof_type, decode_android_export
    from xax_jni import _jni_value_type, jni_env_pointer_type
    from xax_manifest import decode_android_manifest_semantics, decode_android_platform_declarations

    def text(value: str) -> list[int]:
        raw = value.encode("utf-8")
        return [len(raw), *raw]

    def units(value: str) -> list[int]:
        raw = value.encode("utf-16-le", "surrogatepass")
        return [len(raw) // 2, *(int.from_bytes(raw[k:k + 2], "little") for k in range(0, len(raw), 2))]

    def data(value: bytes) -> list[int]:
        return [len(value), *value]

    def texts(values) -> list[int]:
        return [len(values), *(w for value in values for w in text(value))]

    words = [len(managed_carriers)]
    for carrier in managed_carriers:
        item = decode_android_managed_class(carrier)
        words += [*data(carrier.cid), *text(item.class_descriptor), *units(item.class_descriptor), *text(item.superclass_descriptor),
                  *texts(item.interfaces), len(item.methods)]
        for method in item.methods:
            words += [*text(method.name), *text(method.descriptor), int(method.call_super), *units(method.native_name)]
    manifest = decode_android_manifest_semantics(manifest_carrier)
    words += [*text(manifest.activity_class), manifest.min_sdk, manifest.target_sdk]
    env = jni_env_pointer_type().cid
    widths = {primitive: _jni_value_type(primitive).cid for primitive in "ZBCSIJFD"}
    assert set(widths) == set(_PRIMITIVES)

    def fact(cid: bytes) -> list[int]:
        reference = _jni_reference(cid, reader.get)
        kind, family = (0, "") if reference is None else ({"LOCAL": 1, "BORROWED": 2}.get(reference[0], 3), reference[1])
        raw = family.encode("utf-8")
        return [3 + len(raw), int(cid == env), sum(1 << k for k, primitive in enumerate("ZBCSIJFD") if cid == widths[primitive]), kind, *raw]

    exports = [decode_android_export(carrier) for carrier in export_carriers]
    words.append(len(exports))
    for view in exports:
        _graph, parameters, results = _decode_function_interface(reader.get(view.function_cid), reader.get)
        parameters = [cid for cid in parameters if not _is_proof_type(reader.get(cid))]
        results = [cid for cid in results if not _is_proof_type(reader.get(cid))]
        words += [*data(view.name), *data(view.function_cid), len(parameters), *(w for cid in parameters for w in fact(cid)),
                  len(results), *(w for cid in results for w in fact(cid))]
    words += data(build_entry_function)
    declarations = decode_android_platform_declarations(declarations_carrier) if declarations_carrier is not None else None
    permissions = declarations.permissions if declarations is not None else ()
    components = declarations.components if declarations is not None else ()
    words.append(len(permissions))
    for item in permissions:
        words += [*text(item.name), item.max_sdk]
    words.append(len(components))
    for item in components:
        words += [*text(item.kind), *text(item.class_name), *texts(item.foreground_types), *texts(item.actions)]
    methods, objects = reachable_platform_uses(tuple(view.function_cid for view in {view.name: view for view in exports}.values()), reader.get)
    words += [3 * len(methods), *(w for member in methods for part in member for w in text(part))]
    words += [len(objects), *(w for cid in objects for w in data(cid))]
    return words


def managed_rules_with_xax(reader, manifest_carrier, managed_carriers, export_carriers, build_entry_function, declarations_carrier):
    """``(decided, site, position, texts)``: the XAX program's verdict for the managed-class profile (``site`` the ``Mk``
    that fires or None, ``position`` its class and method, ``texts`` the reason or the platform problems), or
    ``(False, None, None, ())`` where it cannot run, declines, or a fact cannot be read."""
    import os

    import xax_native

    native = None if os.environ.get(OPT_OUT) == "1" else _PROGRAM.native(OPT_OUT)
    if native is None:
        return False, None, None, ()
    try:
        words = _facts(reader, manifest_carrier, managed_carriers, export_carriers, build_entry_function, declarations_carrier)
    except Exception:  # noqa: BLE001 - a carrier the host cannot read: the bootstrap's checks report it
        return False, None, None, ()
    if any(not 0 <= word < 1 << 64 for word in words):
        return False, None, None, ()

    def collect(read):
        status = read(0, 4)
        if status[0] != 1:
            return None
        count = read(TEXT_AT, 1)[0]
        texts, at_word = [], TEXT_AT + 1
        for _ in range(count):
            length = read(at_word, 1)[0]
            texts.append(bytes(read(at_word + 1, length)).decode("utf-8"))
            at_word += 1 + length
        return status[1], (status[2], status[3]), tuple(texts)

    result = native.run(words, collect)
    if result is None:
        xax_native.declined("android-managed-rules", 1)
        return False, None, None, ()
    verdict, position, texts = result
    return True, None if verdict == 0 else f"M{verdict}", position, texts
