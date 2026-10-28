"""S15e.6f.1 (ADR-336): the carrier decisions of the unsigned Android profiles (``xax_build._build_android_unsigned_apk``) as
an XAX program.

The program classifies the package's identity-only carriers by their identity prefixes (in the bootstrap's order) and
evaluates the 60 rule sites of the unsigned profiles in the bootstrap's order: the target profile, the managed-class and
platform-declaration profiles, the carrier counts, the declarative surface closure, the Activity identity and SDK floors,
the resource package, the libxposed metadata, hook, mutation-policy, deoptimization, service, preference, file and
hot-reload closures and API levels, the Java and native entries, and the JNI exports (their names mangled here as JNI
short symbols) with the build entry.  Its verdict is the site that fires (``Uk``), 0 for an accepted package, or 100 for
the managed-class profile (S15e.6f.2).  The host decodes the carriers and lowers the bridge specifications (the
carriers' own canonical checks) and raises the decided site's diagnostic with the bootstrap's arguments
(``xax_build._AndroidRules``); where a fact cannot be read, the host keeps the bootstrap's checks.

Input (64-bit words; a text is its UTF-16 unit count and units, a byte string its length and bytes one per word, an
option a flag then its value, a list its count then its items): see ``_facts``.
Output: the status (1) and the verdict (word 1).
"""

from __future__ import annotations

from xax_compiler import x86_64_linux_exec_target
from xax_graph_builder import program_store
from xax_native import bootstrap_dir
from xax_selfhost_facts import E, H_ARENA, H_ARENA_END, NONE, _function
from xax_selfhost_views_backend import _FN, NativeProgram, _call, _ok
from xax_selfhost_x86_64_general import GENERAL_ARENA_AT, GENERAL_ARENA_END

STORE_PATH = bootstrap_dir() / "xax_android_rules.xax"
STATE_AT = 110 << 20
G_CUR = STATE_AT
G_K = STATE_AT + 64  # the constant texts
MANAGED = 100
# The carrier classes in the bootstrap's classification order (``startswith``), each with its prefixes.
CLASSES = (
    ("ui", (b"android-activity-ui-v1", b"android-activity-resource-ui-v1", b"android-activity-method-ui-v1",
            b"android-activity-argument-method-ui-v1", b"android-surface-activity-v1")),
    ("manifest", (b"android-manifest-v1",)), ("resources", (b"android-resources-v1",)), ("application", (b"android-application-v1",)),
    ("receiver", (b"android-broadcast-receiver-v1",)), ("service", (b"android-service-v1",)), ("libxposed", (b"libxposed-module-v1",)),
    ("managed_entry", (b"libxposed-managed-entry-v1",)), ("adapter", (b"libxposed-hook-adapter-v1",)), ("install", (b"libxposed-hook-install-v1",)),
    ("result", (b"libxposed-hook-result-v1",)), ("argument", (b"libxposed-hook-argument-v1",)), ("combined", (b"libxposed-hook-combined-v1",)),
    ("deopt", (b"libxposed-deoptimize-v1",)), ("services", (b"libxposed-module-services-v1",)), ("preferences", (b"libxposed-remote-preferences-v1",)),
    ("files", (b"libxposed-remote-files-v1",)), ("hot", (b"libxposed-hot-reload-v1",)), ("export", (b"android-export-v1",)),
    ("managed", (b"android-managed-class-v1\x00",)), ("declarations", (b"android-platform-declarations-v1\x00",)),
)
C = {name: k for k, (name, _prefixes) in enumerate(CLASSES)}
# The UI kinds in the bootstrap's order: surface, resource, argument method, method, plain.
UI_KINDS = (b"android-surface-activity-v1", b"android-activity-resource-ui-v1", b"android-activity-argument-method-ui-v1",
            b"android-activity-method-ui-v1")
TEXTS = ("java.lang.String", "onPackageReady", "retained-manual-unhook", "libxaxapp.so")
NAMES = (b"native_init",)
PREFIX_BYTES = 64
# The program's site numbers and the bootstrap's rules (``xax_build._build_android_unsigned_apk``).
SITES = (
    "ANDROID-APK-TARGET", "ANDROID-MANAGED-PROFILE", "ANDROID-DECLARATIONS-PROFILE", "ANDROID-APK-TARGET", "ANDROID-APK-SEMANTIC-CARRIERS",
    "SURFACE-DECLARATIVE-CLOSURE", "ANDROID-APK-ACTIVITY-IDENTITY", "SURFACE-DEX039-MINSDK", "ANDROID-RESOURCE-UI-REQUIRES-TABLE",
    "ANDROID-APK-ACTIVITY-IDENTITY", "ANDROID-APK-MULTIDEX-MINSDK", "ANDROID-APK-RESOURCE-PACKAGE", "ANDROID-APK-LIBXPOSED-MANAGED-METADATA",
    "ANDROID-APK-LIBXPOSED-HOOK-MANAGED-ENTRY", "ANDROID-APK-LIBXPOSED-HOOK-CLOSURE", "ANDROID-APK-LIBXPOSED-HOOK-POLICY",
    "ANDROID-APK-LIBXPOSED-RESULT-CLOSURE", "ANDROID-APK-LIBXPOSED-RESULT-HOOKER", "ANDROID-APK-LIBXPOSED-RESULT-TARGET",
    "ANDROID-APK-LIBXPOSED-RESULT-ZERO-ARG", "ANDROID-APK-LIBXPOSED-HOOK-POLICY", "ANDROID-APK-LIBXPOSED-ARGUMENT-CLOSURE",
    "ANDROID-APK-LIBXPOSED-ARGUMENT-HOOKER", "ANDROID-APK-LIBXPOSED-ARGUMENT-TARGET", "ANDROID-APK-LIBXPOSED-ARGUMENT-INDEX",
    "ANDROID-APK-LIBXPOSED-ARGUMENT-SIGNATURE", "ANDROID-APK-LIBXPOSED-COMBINED-CLOSURE", "ANDROID-APK-LIBXPOSED-COMBINED-HOOKER",
    "ANDROID-APK-LIBXPOSED-COMBINED-TARGET", "ANDROID-APK-LIBXPOSED-COMBINED-INDEX", "ANDROID-APK-LIBXPOSED-COMBINED-SIGNATURE",
    "ANDROID-APK-LIBXPOSED-DEOPT-CLOSURE", "ANDROID-APK-LIBXPOSED-DEOPT-TARGET", "ANDROID-APK-LIBXPOSED-HOOK-API",
    "ANDROID-APK-LIBXPOSED-HOOK-ID-API", "ANDROID-APK-LIBXPOSED-HOOKER-IDENTITY", "ANDROID-APK-LIBXPOSED-HOOK-LIFECYCLE",
    "ANDROID-APK-LIBXPOSED-ZERO-ARG-HOOKER", "ANDROID-APK-LIBXPOSED-SERVICES-CLOSURE", "ANDROID-APK-LIBXPOSED-SERVICES-API",
    "ANDROID-APK-LIBXPOSED-REMOTE-PREFS-CLOSURE", "ANDROID-APK-LIBXPOSED-REMOTE-PREFS-API", "ANDROID-APK-LIBXPOSED-REMOTE-FILES-CLOSURE",
    "ANDROID-APK-LIBXPOSED-REMOTE-FILES-API", "ANDROID-APK-LIBXPOSED-HOT-RELOAD-CLOSURE", "ANDROID-APK-LIBXPOSED-HOT-RELOAD-API",
    "ANDROID-APK-LIBXPOSED-HOT-RELOAD-ENTRY", "ANDROID-APK-LIBXPOSED-HOT-RELOAD-LIFETIME", "ANDROID-APK-LIBXPOSED-HOT-RELOAD-ID",
    "ANDROID-APK-LIBXPOSED-JAVA-ENTRY", "ANDROID-APK-LIBXPOSED-JAVA-IDENTITY", "ANDROID-APK-LIBXPOSED-JAVA-ENTRY",
    "ANDROID-APK-LIBXPOSED-NATIVE-ENTRY", "ANDROID-APK-JNI-EXPORTS", "ANDROID-APK-APPLICATION-EXPORT", "ANDROID-APK-RECEIVER-EXPORT",
    "ANDROID-APK-SERVICE-EXPORT", "ANDROID-APK-LIBXPOSED-MANAGED-EXPORT", "ANDROID-APK-LIBXPOSED-NATIVE-INIT", "ANDROID-APK-BUILD-ENTRY",
)


def at(e: E, base, k):
    return e.ld(e.add(base, k))


# -- reading ----------------------------------------------------------------------------------------------------------------

def _word_fn(tables):
    def build(e: E):
        p = e.p
        e.var("wd_at", e.ld(G_CUR))
        e.st(G_CUR, e.add(p["wd_at"], 1))
        e.give(e.rd(p["wd_at"]))
    return _function((), build, tables)


def _seq_fn(tables):
    """``seq()``: the input sequence at the cursor (its count, then one word per item) copied to the arena (its handle
    ``[n, items...]``)."""
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
    """``list()``: a list of sequences (its handle ``[n, handles...]``)."""
    def build(e: E):
        p = e.p
        e.var("li_n", _call(e, "ar_word"))
        _ok(e, e.le(p["li_n"], 1 << 16))
        e.var("li_h", e.alloc(e.add(p["li_n"], 1)))
        _ok(e, e.ne(p["li_h"], NONE))
        e.st(p["li_h"], p["li_n"])
        e.for_("li_k", 0, p["li_n"], lambda: e.st(e.add(e.add(p["li_h"], 1), p["li_k"]), _call(e, "ar_seq")))
        e.give(p["li_h"])
    return _function((), build, tables)


def _option_fn(tables):
    """``option()``: a flag, then (when set) a sequence; its handle or 0."""
    def build(e: E):
        e.if_(e.eq(_call(e, "ar_word"), 0), lambda: e.give(0))
        e.give(_call(e, "ar_seq"))
    return _function((), build, tables)


def _same_fn(tables):
    """1 when sequences ``a`` and ``b`` (handles; 0 is the absent option) are equal."""
    def build(e: E):
        p = e.p
        e.if_(e.either(e.eq(p["a"], 0), e.eq(p["b"], 0)), lambda: e.give(e.flag(e.eq(p["a"], p["b"]))))
        e.if_(e.ne(e.ld(p["a"]), e.ld(p["b"])), lambda: e.give(0))
        e.for_("sm_k", 1, e.add(e.ld(p["a"]), 1),
               lambda: e.if_(e.ne(e.ld(e.add(p["a"], p["sm_k"])), e.ld(e.add(p["b"], p["sm_k"]))), lambda: e.give(0)))
        e.give(1)
    return _function(("a", "b"), build, tables)


def _list_same_fn(tables):
    """1 when lists ``a`` and ``b`` hold equal sequences in order."""
    def build(e: E):
        p = e.p
        e.if_(e.ne(e.ld(p["a"]), e.ld(p["b"])), lambda: e.give(0))
        e.for_("lm_k", 1, e.add(e.ld(p["a"]), 1),
               lambda: e.if_(e.eq(_call(e, "ar_same", at(e, p["a"], p["lm_k"]), at(e, p["b"], p["lm_k"])), 0), lambda: e.give(0)))
        e.give(1)
    return _function(("a", "b"), build, tables)


def _member_fn(tables):
    """1 when list ``l`` holds a sequence equal to ``h``."""
    def build(e: E):
        p = e.p
        e.for_("mb_k", 1, e.add(e.ld(p["l"]), 1), lambda: e.if_(e.ne(_call(e, "ar_same", at(e, p["l"], p["mb_k"]), p["h"]), 0), lambda: e.give(1)))
        e.give(0)
    return _function(("l", "h"), build, tables)


def _prefix_fn(tables):
    """1 when sequence ``h`` starts with the constant byte sequence ``c``."""
    def build(e: E):
        p = e.p
        e.if_(e.lt(e.ld(p["h"]), e.ld(p["c"])), lambda: e.give(0))
        e.for_("pf_k", 1, e.add(e.ld(p["c"]), 1), lambda: e.if_(e.ne(at(e, p["h"], p["pf_k"]), at(e, p["c"], p["pf_k"])), lambda: e.give(0)))
        e.give(1)
    return _function(("h", "c"), build, tables)


def _java_name_fn(tables):
    """``java(d)``: the Java name of class descriptor ``d`` (``d[1:-1]`` with ``/`` as ``.``)."""
    def build(e: E):
        p = e.p
        e.var("jn_n", e.sel(e.lt(e.ld(p["d"]), 2), 0, e.sub(e.ld(p["d"]), 2)))
        e.var("jn_h", e.alloc(e.add(p["jn_n"], 1)))
        _ok(e, e.ne(p["jn_h"], NONE))
        e.st(p["jn_h"], p["jn_n"])
        e.for_("jn_k", 0, p["jn_n"], lambda: (e.var("jn_u", at(e, p["d"], e.add(p["jn_k"], 2))),
                                              e.st(e.add(e.add(p["jn_h"], 1), p["jn_k"]), e.sel(e.eq(p["jn_u"], ord("/")), ord("."), p["jn_u"]))))
        e.give(p["jn_h"])
    return _function(("d",), build, tables)


def _jni_fn(tables):
    """``jni(d, m)``: the JNI short symbol (bytes) of class descriptor ``d`` and method ``m`` (UTF-16 units); declines
    where ``jni_short_native_symbol`` raises."""
    def build(e: E):
        p = e.p
        e.var("jx_dn", e.ld(p["d"]))
        _ok(e, e.both(e.le(2, p["jx_dn"]), e.both(e.eq(at(e, p["d"], 1), ord("L")), e.eq(at(e, p["d"], p["jx_dn"]), ord(";")))))
        _ok(e, e.lt(0, e.ld(p["m"])))
        e.for_("jx_k", 1, e.add(e.ld(p["m"]), 1), lambda: (
            e.var("jx_u", at(e, p["m"], p["jx_k"])),
            _ok(e, e.both(e.both(e.ne(p["jx_u"], ord(".")), e.ne(p["jx_u"], ord("/"))), e.both(e.both(e.ne(p["jx_u"], ord(";")), e.ne(p["jx_u"], ord("["))),
                                                                                             e.ne(p["jx_u"], 0))))))
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
    """``export_of(name)``: the function CID of the last export named ``name`` (0 where none is)."""
    def build(e: E):
        p = e.p
        e.var("ex_f", 0)
        e.var("ex_l", e.ld(STATE_AT + 2))
        e.for_("ex_k", 0, e.udiv(e.ld(p["ex_l"]), 2), lambda: e.if_(e.ne(_call(e, "ar_same", at(e, p["ex_l"], e.add(1, e.mul(p["ex_k"], 2))), p["name"]), 0),
                                                        lambda: e.set("ex_f", at(e, p["ex_l"], e.add(2, e.mul(p["ex_k"], 2))))))
        e.give(p["ex_f"])
    return _function(("name",), build, tables)


# -- the rules --------------------------------------------------------------------------------------------------------------

def _frontend(tables):
    def build(e: E):
        p = e.p
        word = lambda: _call(e, "ar_word")  # noqa: E731
        seq = lambda: _call(e, "ar_seq")  # noqa: E731
        listed = lambda: _call(e, "ar_list")  # noqa: E731
        option = lambda: _call(e, "ar_option")  # noqa: E731
        same = lambda a, b: e.ne(_call(e, "ar_same", a, b), 0)  # noqa: E731
        e.st(0, 0)
        e.set_hd(H_ARENA, GENERAL_ARENA_AT)
        e.set_hd(H_ARENA_END, GENERAL_ARENA_END)
        e.st(G_CUR, 0)
        # The constant texts (UTF-16 units), export names and carrier prefixes (bytes).
        constants = [*((("t", text), [int.from_bytes(text.encode("utf-16-le")[i:i + 2], "little") for i in range(0, 2 * len(text), 2)]) for text in TEXTS),
                     *((("b", name), list(name)) for name in NAMES),
                     *((("b", prefix), list(prefix)) for _name, prefixes in CLASSES for prefix in prefixes)]
        handles = {}
        for k, (key, units) in enumerate(constants):
            e.var("ck", e.alloc(len(units) + 1))
            _ok(e, e.ne(p["ck"], NONE))
            e.st(p["ck"], len(units))
            for j, unit in enumerate(units):
                e.st(e.add(p["ck"], 1 + j), unit)
            e.st(G_K + k, p["ck"])
            handles[key] = G_K + k

        def K(item):
            return e.ld(handles[("t", item) if isinstance(item, str) else ("b", item)])

        def verdict(value):
            e.st(1, value)
            e.st(0, 1)
            e.give(1)

        # The target profile and the carriers' classes.
        e.var("identity", word())  # 0 v3, 1 v4, 2 v5, 3 another
        e.if_(e.eq(p["identity"], 3), lambda: verdict(1))
        e.var("count", e.alloc(len(CLASSES) + 1))
        _ok(e, e.ne(p["count"], NONE))
        for k in range(len(CLASSES)):
            e.st(e.add(p["count"], k), 0)
        e.var("ui_prefix", 0)
        e.var("nchild", word())
        _ok(e, e.le(p["nchild"], 1 << 16))

        def child():
            e.var("ch", seq())
            e.var("cls", NONE)
            for k, (name, prefixes) in enumerate(CLASSES):
                for prefix in prefixes:
                    e.if_(e.both(e.eq(p["cls"], NONE), same_prefix(p["ch"], prefix)), lambda k=k: e.set("cls", k))
            e.if_(e.ne(p["cls"], NONE), lambda: e.st(e.add(p["count"], p["cls"]), e.add(at(e, p["count"], p["cls"]), 1)))
            e.if_(e.both(e.eq(p["cls"], 0), e.eq(p["ui_prefix"], 0)), lambda: e.set("ui_prefix", p["ch"]))

        def same_prefix(h, prefix):
            return e.ne(_call(e, "ar_prefix", h, K(prefix)), 0)

        e.for_("q", 0, p["nchild"], child)
        n = lambda name: at(e, p["count"], C[name])  # noqa: E731

        def managed():
            others = e.c(0)
            for name in ("ui", "application", "receiver", "service", "libxposed", "managed_entry", "adapter", "install"):
                others = e.add(others, n(name))
            e.if_(e.either(e.lt(0, others), e.either(e.ne(n("manifest"), 1), e.either(e.lt(1, n("resources")), e.lt(1, n("declarations"))))),
                  lambda: verdict(2))
            verdict(MANAGED)

        e.if_(e.lt(0, n("managed")), managed)
        e.if_(e.lt(0, n("declarations")), lambda: verdict(3))
        e.if_(e.ne(p["identity"], 0), lambda: verdict(4))
        bad = e.either(e.ne(n("ui"), 1), e.ne(n("manifest"), 1))
        for name, _prefixes in CLASSES[2:18]:
            bad = e.either(bad, e.lt(1, n(name)))
        e.if_(bad, lambda: verdict(5))
        e.var("kind", 4)
        for k, prefix in reversed(tuple(enumerate(UI_KINDS))):
            e.if_(same_prefix(p["ui_prefix"], prefix), lambda k=k: e.set("kind", k))
        # The decoded facts: absent (0) where the host could not read them; the bootstrap's checks then stay.
        e.if_(e.both(e.eq(p["kind"], 1), e.ne(n("resources"), 1)), lambda: verdict(9))  # (the surface profile is not kind 1)
        e.if_(e.eq(word(), 0), lambda: e.give(NONE))
        e.var("selector", seq())
        e.var("surface_entry", seq())
        e.var("children", listed())
        e.var("allowed", listed())
        e.var("descriptor", seq())
        e.var("surface_activity", seq())
        e.var("surface_min_sdk", word())

        def surface():

            def closed():  # the children equal the allowed set (both as sets)
                e.var("cl_ok", 1)
                e.for_("j", 1, e.add(e.ld(p["children"]), 1), lambda: e.if_(e.eq(_call(e, "ar_member", p["allowed"], at(e, p["children"], p["j"])), 0),
                                                                             lambda: e.set("cl_ok", 0)))
                e.for_("j", 1, e.add(e.ld(p["allowed"]), 1), lambda: e.if_(e.eq(_call(e, "ar_member", p["children"], at(e, p["allowed"], p["j"])), 0),
                                                                            lambda: e.set("cl_ok", 0)))
                return p["cl_ok"]

            e.var("closed", closed())
            e.if_(e.either(e.eq(_call(e, "ar_same", p["surface_entry"], p["selector"]), 0), e.eq(p["closed"], 0)), lambda: verdict(6))
            e.if_(e.eq(_call(e, "ar_same", p["surface_activity"], _call(e, "ar_java", p["descriptor"])), 0), lambda: verdict(7))
            e.if_(e.lt(p["surface_min_sdk"], 28), lambda: verdict(8))
            verdict(0)

        e.if_(e.eq(p["kind"], 0), surface)
        # The views: present (a handle) only where the class has a carrier.
        e.var("ui_descriptor", seq())
        e.var("activity", seq())
        e.var("min_sdk", word())
        e.var("package", seq())
        e.var("resource_package", option())
        e.var("adapter", option())  # [java class]
        e.var("inspected", option())  # [index]
        e.var("install", option())  # [present]
        for name in ("in_class", "in_method", "in_hooker", "in_lifetime"):
            e.var(name, seq())
        e.var("in_params", listed())
        e.var("in_hook_id", option())
        for prefix in ("re", "ar", "co"):
            e.var(f"{prefix}", option())
            for name in ("hooker", "class", "method"):
                e.var(f"{prefix}_{name}", seq())
            e.var(f"{prefix}_index", word())
        e.var("deopt", option())
        e.var("de_class", seq())
        e.var("de_method", seq())
        e.var("de_params", listed())
        e.var("libx", option())
        e.var("lx_target", word())
        e.var("lx_min", word())
        e.var("lx_java", listed())
        e.var("lx_native", listed())
        e.var("managed_entry", option())  # [java class]
        e.var("me_callbacks", listed())
        e.var("hot", option())  # [hook id]
        present = lambda name: e.lt(0, n(name))  # noqa: E731
        absent = lambda name: e.eq(n(name), 0)  # noqa: E731

        e.if_(e.eq(_call(e, "ar_same", p["activity"], _call(e, "ar_java", p["ui_descriptor"])), 0), lambda: verdict(10))
        e.if_(e.lt(p["min_sdk"], 21), lambda: verdict(11))
        e.if_(e.both(e.ne(p["resource_package"], 0), e.eq(_call(e, "ar_same", p["resource_package"], p["package"]), 0)), lambda: verdict(12))
        e.if_(e.both(present("managed_entry"), absent("libxposed")), lambda: verdict(13))
        hooks = e.either(e.either(present("adapter"), present("install")), e.either(e.either(present("result"), present("argument")),
                                                                                   e.either(present("combined"), present("hot"))))
        e.if_(e.both(hooks, e.either(absent("libxposed"), absent("managed_entry"))), lambda: verdict(14))
        e.if_(e.ne(e.flag(present("adapter")), e.flag(present("install"))), lambda: verdict(15))
        target_same = lambda prefix: e.both(same(p[f"{prefix}_class"], p["in_class"]), same(p[f"{prefix}_method"], p["in_method"]))  # noqa: E731
        string_params = lambda: e.both(e.eq(e.ld(p["in_params"]), 1), same(at(e, p["in_params"], 1), K("java.lang.String")))  # noqa: E731

        def result():
            e.if_(e.either(present("argument"), present("combined")), lambda: verdict(16))
            e.if_(e.either(absent("adapter"), absent("install")), lambda: verdict(17))
            e.if_(e.eq(_call(e, "ar_same", p["re_hooker"], p["adapter"]), 0), lambda: verdict(18))
            e.if_(e.eq(e.flag(target_same("re")), 0), lambda: verdict(19))
            e.if_(e.ne(p["inspected"], 0), lambda: verdict(20))

        e.if_(present("result"), result)

        def mutation(prefix, first):
            def check():
                if prefix == "ar":
                    e.if_(present("combined"), lambda: verdict(first - 1))
                e.if_(e.either(absent("adapter"), absent("install")), lambda: verdict(first))
                e.if_(e.eq(_call(e, "ar_same", p[f"{prefix}_hooker"], p["adapter"]), 0), lambda: verdict(first + 1))
                e.if_(e.eq(e.flag(target_same(prefix)), 0), lambda: verdict(first + 2))
                e.if_(e.either(e.eq(p["inspected"], 0), e.ne(at(e, p["inspected"], 1), p[f"{prefix}_index"])), lambda: verdict(first + 3))
                e.if_(e.eq(e.flag(string_params()), 0), lambda: verdict(first + 4))
            return check

        e.if_(present("argument"), mutation("ar", 22))
        e.if_(present("combined"), mutation("co", 27))

        def deoptimization():
            e.if_(absent("install"), lambda: verdict(32))
            e.if_(e.eq(e.flag(e.both(e.both(same(p["de_class"], p["in_class"]), same(p["de_method"], p["in_method"])),
                                     e.ne(_call(e, "ar_listsame", p["de_params"], p["in_params"]), 0))), 0), lambda: verdict(33))

        e.if_(present("deopt"), deoptimization)

        def installation():
            e.if_(e.ne(p["lx_target"], 102), lambda: verdict(34))
            e.if_(e.both(e.ne(p["in_hook_id"], 0), e.ne(p["lx_min"], 102)), lambda: verdict(35))
            e.if_(e.eq(_call(e, "ar_same", p["in_hooker"], p["adapter"]), 0), lambda: verdict(36))
            e.if_(e.eq(_call(e, "ar_member", p["me_callbacks"], K("onPackageReady")), 0), lambda: verdict(37))
            e.if_(e.both(e.both(absent("argument"), absent("combined")), e.ne(p["inspected"], 0)), lambda: verdict(38))

        e.if_(present("install"), installation)
        for name, first in (("services", 39), ("preferences", 41), ("files", 43)):
            e.if_(present(name), lambda first=first: (e.if_(e.either(absent("libxposed"), absent("managed_entry")), lambda: verdict(first)),
                                                      e.if_(e.ne(p["lx_target"], 102), lambda: verdict(first + 1))))

        def hot():
            e.if_(e.either(absent("libxposed"), e.either(absent("managed_entry"), absent("install"))), lambda: verdict(45))
            e.if_(e.either(e.ne(p["lx_min"], 102), e.ne(p["lx_target"], 102)), lambda: verdict(46))
            e.if_(e.ne(e.ld(p["lx_java"]), 1), lambda: verdict(47))
            e.if_(e.eq(_call(e, "ar_same", p["in_lifetime"], K("retained-manual-unhook")), 0), lambda: verdict(48))
            e.if_(e.eq(_call(e, "ar_same", p["in_hook_id"], p["hot"]), 0), lambda: verdict(49))

        e.if_(present("hot"), hot)

        def module():
            def java():
                e.if_(absent("managed_entry"), lambda: verdict(50))
                e.if_(e.either(e.ne(e.ld(p["lx_java"]), 1), e.eq(_call(e, "ar_same", at(e, p["lx_java"], 1), p["managed_entry"]), 0)), lambda: verdict(51))

            e.if_(e.lt(0, e.ld(p["lx_java"])), java, lambda: e.if_(present("managed_entry"), lambda: verdict(52)))
            e.for_("j", 1, e.add(e.ld(p["lx_native"]), 1),
                   lambda: e.if_(e.eq(_call(e, "ar_same", at(e, p["lx_native"], p["j"]), K("libxaxapp.so")), 0), lambda: verdict(53)))

        e.if_(present("libxposed"), module)
        # The JNI exports: the lowered bridges' native methods, by their short symbols (absent where the host could not
        # lower the bridges: the bootstrap's lowering reports it).
        e.if_(e.eq(word(), 0), lambda: e.give(NONE))
        e.var("activity_class", seq())
        e.var("activity_native", seq())
        e.var("listener_class", seq())
        e.var("listener_native", seq())
        e.var("application_bridge", listed())  # [] or [class, native]
        e.var("receiver_bridge", listed())
        e.var("service_bridge", listed())  # [] or [class, natives...]
        e.var("managed_bridge", listed())
        e.st(STATE_AT + 2, listed())  # the exports: name, function CID, ...
        e.var("entry", seq())
        jni = lambda d, m: _call(e, "ar_jni", d, m)  # noqa: E731
        has = lambda name: e.ne(_call(e, "ar_export", name), 0)  # noqa: E731
        e.var("activity_symbol", jni(p["activity_class"], p["activity_native"]))
        e.var("listener_symbol", jni(p["listener_class"], p["listener_native"]))
        e.if_(e.either(e.eq(e.flag(has(p["activity_symbol"])), 0), e.eq(e.flag(has(p["listener_symbol"])), 0)), lambda: verdict(54))
        for name, site in (("application_bridge", 55), ("receiver_bridge", 56)):
            e.if_(e.lt(0, e.ld(p[name])), lambda name=name, site=site: e.if_(
                e.eq(e.flag(has(jni(at(e, p[name], 1), at(e, p[name], 2)))), 0), lambda: verdict(site)))
        for name, site in (("service_bridge", 57), ("managed_bridge", 58)):
            e.if_(e.lt(0, e.ld(p[name])), lambda name=name, site=site: e.for_(
                "j", 2, e.add(e.ld(p[name]), 1), lambda: e.if_(e.eq(e.flag(has(jni(at(e, p[name], 1), at(e, p[name], p["j"])))), 0), lambda: verdict(site))))
        e.if_(e.both(present("libxposed"), e.lt(0, e.ld(p["lx_native"]))), lambda: e.if_(e.eq(e.flag(has(K(b"native_init"))), 0), lambda: verdict(59)))
        e.if_(e.eq(_call(e, "ar_same", _call(e, "ar_export", p["activity_symbol"]), p["entry"]), 0), lambda: verdict(60))
        verdict(0)
    return _function((), build, tables)


def build_rules_program():
    """``(reader, function)``: the Android rules program's store and its entry."""
    tables = None
    objects: list = []
    _FN.clear()

    def add(name, made):
        function, items = made
        objects.extend(items)
        _FN[name] = function
        return function

    for name, builder in (("ar_word", _word_fn), ("ar_seq", _seq_fn), ("ar_list", _list_fn), ("ar_option", _option_fn), ("ar_same", _same_fn),
                          ("ar_listsame", _list_same_fn), ("ar_member", _member_fn), ("ar_prefix", _prefix_fn), ("ar_java", _java_name_fn),
                          ("ar_jni", _jni_fn), ("ar_export", _export_fn)):
        add(name, builder(tables))
    program = add("frontend", _frontend(tables))
    return program_store(program, x86_64_linux_exec_target(), tuple(objects)), program


_PROGRAM = NativeProgram(STORE_PATH, build_rules_program, "android-rules")
load_rules_program = _PROGRAM.load
write_rules_store = _PROGRAM.write
OPT_OUT = "XAX_ANDROID_RULES_PYTHON"


def _facts(reader, package_view, target_object, build_entry_function) -> list[int]:
    """The input words: the target profile and the carriers' identity prefixes, then (flag 1) the decoded and lowered
    facts, or flag 0 where the host cannot read them (a carrier or lowering error, which the bootstrap's checks report)."""
    from xax_compiler import Cursor, Kind, decode_native_target
    from xax_android import ANDROID_TARGET_IDENTITY

    def text(value: str) -> list[int]:
        raw = value.encode("utf-16-le", "surrogatepass")
        return [len(raw) // 2, *(int.from_bytes(raw[k:k + 2], "little") for k in range(0, len(raw), 2))]

    def data(value: bytes) -> list[int]:
        return [len(value), *value]

    def texts(values) -> list[int]:
        return [len(values), *(word for value in values for word in text(value))]

    def option(value, encode) -> list[int]:
        return [0] if value is None else [1, *encode(value)]

    identity = decode_native_target(target_object).identity
    words = [{ANDROID_TARGET_IDENTITY: 0, b"android-arm64-v8a-shared-v4": 1, b"android-arm64-v8a-shared-v5": 2}.get(identity, 3)]
    classes: dict[str, list] = {name: [] for name, _prefixes in CLASSES}
    children = []
    for module_cid in package_view.modules:
        for cid in reader.get(module_cid).references:
            child = reader.get(cid)
            if child.kind != Kind.TARGET or child.references:
                continue
            prefix = Cursor(child.body, child.cid.hex()).byte_string()
            children.append(prefix[:PREFIX_BYTES])
            for name, prefixes in CLASSES:
                if prefix.startswith(prefixes):
                    classes[name].append(child)
                    break
    words.append(len(children))
    for prefix in children:
        words += data(prefix)
    try:
        words += [1, *_decoded(reader, package_view, build_entry_function, classes, text, data, texts, option)]
    except Exception:  # noqa: BLE001 - a carrier the host cannot read: the bootstrap's checks report it
        words.append(0)
    return words


def _decoded(reader, package_view, build_entry_function, classes, text, data, texts, option) -> list[int]:
    from xax_android import (ANDROID_ACTIVITY_ARGUMENT_METHOD_UI_PREFIX, ANDROID_ACTIVITY_METHOD_UI_PREFIX, ANDROID_ACTIVITY_RESOURCE_UI_PREFIX,
                             decode_android_activity_argument_method_ui, decode_android_activity_method_ui, decode_android_activity_resource_ui,
                             decode_android_activity_ui, lower_android_activity_argument_method_ui, lower_android_activity_method_ui,
                             lower_android_activity_resource_ui, lower_android_activity_ui)
    from xax_android_components import ANDROID_SURFACE_ACTIVITY_PREFIX, decode_android_surface_activity
    from xax_compiler import Block, Cursor, Terminator, function, graph_fragment
    from xax_libxposed import (decode_libxposed_deoptimization, decode_libxposed_hook_adapter, decode_libxposed_hook_argument,
                               decode_libxposed_hook_combined, decode_libxposed_hook_installation, decode_libxposed_hook_result,
                               decode_libxposed_hot_reload, decode_libxposed_managed_entry, decode_libxposed_module)
    from xax_manifest import decode_android_manifest_semantics
    from xax_resources import decode_android_resources_semantics

    first = lambda name: classes[name][0] if classes[name] else None  # noqa: E731
    ui, manifest_carrier = first("ui"), first("manifest")
    ui_identity = Cursor(ui.body, ui.cid.hex()).byte_string()
    manifest = decode_android_manifest_semantics(manifest_carrier)
    words: list[int] = []
    if ui_identity.startswith(ANDROID_SURFACE_ACTIVITY_PREFIX):
        selector = function(graph_fragment((Block((), (), Terminator.return_(())),)), (), ())
        descriptor, _description = decode_android_surface_activity(ui)
        module_children = sorted({cid for module in package_view.modules for cid in reader.get(module).references})
        words += [*data(selector.cid), *data(build_entry_function), len(module_children), *(w for cid in module_children for w in data(cid)),
                  3, *data(ui.cid), *data(manifest_carrier.cid), *data(build_entry_function), *text(descriptor), *text(manifest.activity_class),
                  manifest.min_sdk]
        return words
    words += [*data(b""), *data(b""), 0, 0, *text(""), *text(""), 0]
    if ui_identity.startswith(ANDROID_ACTIVITY_RESOURCE_UI_PREFIX):
        ui_view = decode_android_activity_resource_ui(ui)
        lower = (lambda: lower_android_activity_resource_ui(ui, classes["resources"][0])) if len(classes["resources"]) == 1 else None
    elif ui_identity.startswith(ANDROID_ACTIVITY_ARGUMENT_METHOD_UI_PREFIX):
        ui_view, lower = decode_android_activity_argument_method_ui(ui), lambda: lower_android_activity_argument_method_ui(ui)
    elif ui_identity.startswith(ANDROID_ACTIVITY_METHOD_UI_PREFIX):
        ui_view, lower = decode_android_activity_method_ui(ui), lambda: lower_android_activity_method_ui(ui)
    else:
        ui_view, lower = decode_android_activity_ui(ui), lambda: lower_android_activity_ui(ui)
    view = lambda name, decode: decode(first(name)) if classes[name] else None  # noqa: E731
    resource = view("resources", decode_android_resources_semantics)
    adapter = view("adapter", decode_libxposed_hook_adapter)
    install = view("install", decode_libxposed_hook_installation)
    mutations = (view("result", decode_libxposed_hook_result), view("argument", decode_libxposed_hook_argument),
                 view("combined", decode_libxposed_hook_combined))
    deopt = view("deopt", decode_libxposed_deoptimization)
    module = view("libxposed", decode_libxposed_module)
    managed_entry = view("managed_entry", decode_libxposed_managed_entry)
    hot = view("hot", decode_libxposed_hot_reload)
    words += [*text(ui_view.activity_class_descriptor), *text(manifest.activity_class), manifest.min_sdk, *text(manifest.package_name),
              *option(resource.package_name if resource else None, text), *option(adapter.java_class_name if adapter else None, text),
              *option(adapter.inspected_argument_index if adapter is not None else None, lambda value: [1, value]),
              *option(1 if install else None, lambda value: [0])]
    words += [*text(install.target_class_name if install else ""), *text(install.target_method_name if install else ""),
              *text(install.hooker_class_name if install else ""), *text(install.lifetime_policy if install else ""),
              *texts(install.parameter_type_names if install else ()), *option(install.hook_id if install else None, text)]
    for item in mutations:
        words += [*option(1 if item else None, lambda value: [0]), *text(item.hooker_class_name if item else ""), *text(item.target_class_name if item else ""),
                  *text(item.target_method_name if item else ""), getattr(item, "argument_index", 0) if item else 0]
    words += [*option(1 if deopt else None, lambda value: [0]), *text(deopt.target_class_name if deopt else ""), *text(deopt.target_method_name if deopt else ""),
              *texts(deopt.parameter_type_names if deopt else ())]
    words += [*option(1 if module else None, lambda value: [0]), module.target_api_version if module else 0, module.min_api_version if module else 0,
              *texts(module.java_entries if module else ()), *texts(module.native_entries if module else ())]
    words += [*option(managed_entry.java_class_name if managed_entry else None, text), *texts(managed_entry.callbacks if managed_entry else ()),
              *option(hot.hook_id if hot else None, text)]
    # The lowered bridges' native methods and the exports.
    try:
        words += [1, *_lowered(classes, first, lower() if lower else None, text, data, build_entry_function)]
    except Exception:  # noqa: BLE001 - the bootstrap's lowering reports it, after the rule sites before it
        words.append(0)
    return words


def _lowered(classes, first, lowered, text, data, build_entry_function) -> list[int]:
    from xax_android_components import lower_android_application, lower_android_broadcast_receiver, lower_android_service
    from xax_compiler import decode_android_export
    from xax_libxposed import lower_libxposed_managed_entry

    if lowered is None:
        raise ValueError("the UI bridges are not lowered")
    activity_spec, listener_spec = lowered

    def bridge(spec, every: bool) -> list[int]:
        if spec is None:
            return [0]
        natives = [item.name for item in spec.native_methods] if every else [spec.native_methods[0].name]
        return [1 + len(natives), *text(spec.class_descriptor), *(w for name in natives for w in text(name))]

    application = lower_android_application(first("application")) if classes["application"] else None
    receiver = lower_android_broadcast_receiver(first("receiver")) if classes["receiver"] else None
    service = lower_android_service(first("service")) if classes["service"] else None
    managed_spec = None
    if classes["managed_entry"]:
        managed_spec = lower_libxposed_managed_entry(first("managed_entry"), first("install"), first("deopt"), first("services"), first("preferences"),
                                                     first("hot"), first("files"))
    words = [*text(activity_spec.class_descriptor), *text(activity_spec.native_methods[0].name), *text(listener_spec.class_descriptor),
             *text(listener_spec.native_methods[0].name), *bridge(application, False), *bridge(receiver, False), *bridge(service, True),
             *bridge(managed_spec, True)]
    exports = [decode_android_export(carrier) for carrier in classes["export"]]
    words += [2 * len(exports), *(w for item in exports for w in (*data(item.name), *data(item.function_cid)))]
    words += data(build_entry_function)
    return words


def rules_with_xax(reader, package_view, target_object, build_entry_function) -> tuple[bool, str | None]:
    """``(decided, site)``: the XAX rules program's verdict for the unsigned profiles (``site`` the ``Uk`` that fires,
    None for an accepted package, ``"MANAGED"`` for the managed-class profile), or ``(False, None)`` where it cannot run
    or declines."""
    import os

    import xax_native

    native = None if os.environ.get(OPT_OUT) == "1" else _PROGRAM.native(OPT_OUT)
    if native is None:
        return False, None
    words = _facts(reader, package_view, target_object, build_entry_function)
    if any(not 0 <= word < 1 << 64 for word in words):
        return False, None
    verdict = native.run(words, lambda read: read(0, 2))
    if verdict is None or verdict[0] != 1:
        xax_native.declined("android-rules", 1)
        return False, None
    if verdict[1] == MANAGED:
        return True, "MANAGED"
    return True, None if verdict[1] == 0 else f"U{verdict[1]}"
