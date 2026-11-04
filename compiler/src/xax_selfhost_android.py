"""S15e.6h.2 (ADR-355): the Android program: an unsigned APK (``xax_build._build_android_unsigned_apk``) built from the
package's semantic objects by one XAX program.

The program reads the general object table (``xax_selfhost_x86_64_general.general_object_table``), the roots and the
Android words, and decodes the package's carriers itself: it classifies the identity-only carriers of the package's
modules by their identity prefixes (in the bootstrap's order), decodes the Activity UI, the manifest and the JNI exports
with their canonical checks (minimal ULEB128 lengths, strict UTF-8, the specifications' field rules), evaluates the
profile's rule sites, lowers the UI carrier to its two DEX bridge specifications, mangles their JNI short symbols, and
derives the shared object's roots (the exports' functions, in export order, without duplicates).  It then chains the
layer programs, each a function of this program: the AArch64 program builds the bundle from the same input (it reads
the roots after the trap heads), and the ELF, binary manifest, DEX bridge and APK container programs, each built with
its input redirected to output memory (``xax_selfhost_facts.INPUT_REDIRECT``), read the words this program writes.
The coordinator's state and arena lie above the image record (``CO_AT``), where no layer writes; it restores its arena
after every layer.

The profile S15e.6h.2a decides is the plain Activity UI (one ``android-activity-ui-v1`` carrier, one manifest and the
exports, on the v3 target).  Another profile, any rule site that fires, and any carrier or lowering error make the
program decline; the bootstrap then decides (and raises the diagnostic).

Input (64-bit words): the general object table (its entry is the first root), the roots (count, CIDs), then the
Android words: the mode (0: the roots only; 1: the APK), the build entry's CID, the module count and the modules' CIDs.
Output: the status (1); mode 0: the roots (count, CIDs) from word 1; mode 1: the APK as the image record
``[1, 0, length, bytes packed eight to a word]`` at ``IMAGE_AT``.
"""

from __future__ import annotations

import xax_selfhost_diagnostics as D
from xax_compiler import Operation
from xax_native import bootstrap_dir
from xax_selfhost_facts import E, H_ARENA, NONE, _function
from xax_selfhost_general_image import IMAGE_AT, IMAGE_BUFFER_AT, IMAGE_END
from xax_selfhost_views_backend import _FN, CID_WORDS, NativeProgram

STORE_PATH = bootstrap_dir() / "xax_android.xax"
CO_AT = 252 << 20  # above ``IMAGE_END``
G_CUR, G_END, G_W, G_SAVE = CO_AT + 1, CO_AT + 2, CO_AT + 3, CO_AT + 4  # the payload cursor and end, the writer, the arena
G_K = CO_AT + 64  # the constants' handles
# S15e.6i.3 (ADR-359): the large region.  The AArch64 program stages its image in the image buffer; once it has run (or
# in a profile that does not run it) the layer inputs are written there from its start (``G_BIG``), and the layers'
# records and lowered classes are kept there from its end down (``an_bigalloc``), each side checked against the other.
BIG_AT, BIG_END = IMAGE_BUFFER_AT, IMAGE_AT
G_WEND, G_RTOP, G_BIG = CO_AT + 10, CO_AT + 11, CO_AT + 12  # the writer's end, the records' lowest word, 1 once the writer is large
ANDROID_V3 = b"android-arm64-v8a-shared-v3"
ANDROID_LATER = (b"android-arm64-v8a-shared-v4", b"android-arm64-v8a-shared-v5")  # the managed-class profile's too
MASK32 = 0x7FFFFFFF
# The carrier classes in the bootstrap's classification order (``startswith``); the UI kinds are its "ui" class.
CLASSES = (
    ("ui_plain", b"android-activity-ui-v1"), ("ui_resource", b"android-activity-resource-ui-v1"), ("ui_method", b"android-activity-method-ui-v1"),
    ("ui_argument", b"android-activity-argument-method-ui-v1"), ("surface", b"android-surface-activity-v1"), ("manifest", b"android-manifest-v1"),
    ("resources", b"android-resources-v1"), ("application", b"android-application-v1"), ("receiver", b"android-broadcast-receiver-v1"),
    ("service", b"android-service-v1"), ("libxposed", b"libxposed-module-v1"), ("managed_entry", b"libxposed-managed-entry-v1"),
    ("adapter", b"libxposed-hook-adapter-v1"), ("install", b"libxposed-hook-install-v1"), ("result", b"libxposed-hook-result-v1"),
    ("argument", b"libxposed-hook-argument-v1"), ("combined", b"libxposed-hook-combined-v1"), ("deopt", b"libxposed-deoptimize-v1"),
    ("services", b"libxposed-module-services-v1"), ("preferences", b"libxposed-remote-preferences-v1"), ("files", b"libxposed-remote-files-v1"),
    ("hot", b"libxposed-hot-reload-v1"), ("export", b"android-export-v1"), ("managed", b"android-managed-class-v1\x00"),
    ("declarations", b"android-platform-declarations-v1\x00"),
)
C = {name: k for k, (name, _prefix) in enumerate(CLASSES)}
PREFIX = dict(CLASSES)


SURFACE_TEXTS = (b"Landroid/view/SurfaceView;", b"<init>", b"setContentDescription", b"Ljava/lang/CharSequence;", b"setContentView")
#                 exported, foreground types, flags, kind code, kind, actions)


FOREGROUND_TYPES = tuple(__import__("xax_manifest").FOREGROUND_SERVICE_TYPES.items())
JNI_REFERENCE_PREFIXES = (b"android.jni.ref/v2/", b"android.jni.ref/v3/", b"android.jni.ref/")
JMETHOD_PREFIXES = (b"android.jni.jmethodID/v1/", b"android.jni.jmethodID/v2/")
MANAGED_TEXTS = (b".", b"public", b"protected", b"service", b"receiver", b"local", b"borrowed", *JNI_REFERENCE_PREFIXES, *JMETHOD_PREFIXES,
                 *(name.encode() for name, _value in FOREGROUND_TYPES), b"an export of the manifest Activity", b"managed-apk")
CALLBACKS = (b"onModuleLoaded", b"onPackageReady")
SERVICES = (b"framework-name", b"framework-version", b"remote-preferences", b"list-remote-files", b"open-remote-file")
READS = (b"boolean", b"int", b"long", b"float", b"string", b"contains")
FILE_OPERATIONS = (b"list", b"open")
HOT_POLICIES = (b"single-retained-hook-id-guarded-atomic-replace", b"propagate", None, b"skip-replacement", b"package-ready-class-loader",
                b"reject-reload")
XPOSED_MODULE = b"Lio/github/libxposed/api/XposedModule;"
HOOKER = b"Lio/github/libxposed/api/XposedInterface$Hooker;"
LIBXPOSED_TEXTS = (
    *CALLBACKS, *SERVICES, *READS, *FILE_OPERATIONS, *(item for item in HOT_POLICIES if item), b"nullable-on-unsupported", b"best-effort",
    b"PROTECTIVE", b"process", b"retained-manual-unhook", b"java.lang.String", b"replace_after_proceed", b"replace_before_proceed",
    b"replace_argument_then_result", XPOSED_MODULE, HOOKER, b"xaxOnModuleLoaded", b"xaxOnPackageReady",
    b"Lio/github/libxposed/api/XposedModuleInterface$ModuleLoadedParam;", b"Lio/github/libxposed/api/XposedModuleInterface$PackageReadyParam;",
    b"META-INF/xposed/module.prop", b"META-INF/xposed/java_init.list", b"META-INF/xposed/native_init.list", b"META-INF/xposed/scope.list",
    b"minApiVersion=", b"\ntargetApiVersion=", b"\nstaticScope=", b"true\n", b"false\n", b"autoHotReload=true\n", b"\n",
)
# S15e.6i.2b (ADR-358): the libxposed JVM module profile's texts.
JVM_PREFIX, JVM_PREFIX_V2 = b"android-libxposed-jvm-module-v1\0", b"android-libxposed-jvm-module-v2\0"
XPOSED_INTERFACE = b"Lio/github/libxposed/api/XposedInterface;"
READY_PARAM = b"Lio/github/libxposed/api/XposedModuleInterface$PackageReadyParam;"
JVM_ENTRY_DESCRIPTOR = b"(" + XPOSED_INTERFACE + READY_PARAM + b")V"
JVM_KEYS = (b"branding", b"dex", b"fields", b"libraries", b"min_sdk", b"module_class", b"natives", b"package", b"scopes", b"target_sdk",
            b"version_code", b"version_name")
JVM_TEXTS = (JVM_PREFIX, JVM_PREFIX_V2, XPOSED_INTERFACE, READY_PARAM, JVM_ENTRY_DESCRIPTOR, *JVM_KEYS, b"lib/", b"res/", b"L", b";", b"/", b"(", b"xax/P",
             b"entry", b"classes", b".dex")
CONSTANTS = (
    ANDROID_V3, *ANDROID_LATER, b"android-aapcs64-c", b"default", b"xaxOnCreate", b"xaxOnClick", b"onCreate", b"onClick", b"Landroid/app/Activity;",
    b"Ljava/lang/Object;", b"Landroid/view/View$OnClickListener;", b"Landroid/os/Bundle;", b"Landroid/view/View;", b"V", b"xaxapp",
    b"libxaxapp.so", b"AndroidManifest.xml", b"classes.dex", b"classes2.dex", b"lib/arm64-v8a/libxaxapp.so",
    b"resources.arsc", b"Ljava/lang/String;", b"Landroid/content/BroadcastReceiver;", b"Landroid/app/Application;", b"Landroid/app/Service;",
    b"xaxOnReceive", b"onReceive", b"xaxOnDestroy", b"onDestroy", b"onBind", b"Landroid/os/IBinder;", b"Landroid/content/Intent;",
    b"Landroid/content/Context;", *(f"classes{k}.dex".encode() for k in range(3, 10)),
    *LIBXPOSED_TEXTS, *SURFACE_TEXTS, *MANAGED_TEXTS,
    *(prefix for _name, prefix in CLASSES), *JVM_TEXTS,
)
K_INDEX = {value: k for k, value in enumerate(dict.fromkeys(CONSTANTS))}
ACC_PUBLIC_FINAL_CLASS, ACC_NATIVE_METHOD, ACC_PROTECTED, ACC_PUBLIC = 33, 258, 4, 1


G_WHY = CO_AT + 8  # the declining check's site (``DECLINE_SITES[code - 1]``), for diagnosis only
DECLINE_SITES: list[str] = []


def _ok(e: E, condition):
    """Decline (NONE) unless ``condition``, recording the site at ``G_WHY``."""
    import sys

    frame = sys._getframe(1)
    DECLINE_SITES.append(f"{frame.f_code.co_name}:{frame.f_lineno}")
    code = len(DECLINE_SITES)
    e.if_(e.not_(condition), lambda: (e.st(G_WHY, code), e.give(NONE)))


def _call(e: E, name, *arguments):
    """A helper's result; its decline propagates (the helper recorded the site)."""
    result = e.call(_FN[name], *arguments)
    e.if_(e.eq(result, NONE), lambda: e.give(NONE))
    return result


def at(e: E, base, k):
    return e.ld(e.add(base, k))


def _shift(e: E, k):
    """``256 ** k`` for ``k`` in 0..7."""
    result = e.c(1)
    for q in range(1, 8):
        result = e.sel(e.eq(k, q), 1 << (8 * q), result)
    return result


# -- reading the payloads (one byte per input word) -------------------------------------------------------------------------

def _byte_fn(tables):
    def build(e: E):
        p = e.p
        e.var("by_at", e.ld(G_CUR))
        _ok(e, e.lt(p["by_at"], e.ld(G_END)))
        e.st(G_CUR, e.add(p["by_at"], 1))
        e.give(e.rd(p["by_at"]))
    return _function((), build, tables)


def _uleb_fn(tables):
    """A minimal ULEB128 (``Cursor.uleb``) below 2**56; declines otherwise."""
    def build(e: E):
        p = e.p
        e.var("ul_v", 0)
        e.var("ul_s", 0)
        e.var("ul_go", 1)

        def step():
            e.var("ul_b", _call(e, "an_byte"))
            _ok(e, e.lt(p["ul_s"], 56))
            e.set("ul_v", e.or_(p["ul_v"], e.mul(e.and_(p["ul_b"], 127), _pow2(e, p["ul_s"]))))
            e.if_(e.eq(e.and_(p["ul_b"], 128), 0), lambda: (_ok(e, e.either(e.ne(p["ul_b"], 0), e.eq(p["ul_s"], 0))), e.set("ul_go", 0)))
            e.set("ul_s", e.add(p["ul_s"], 7))

        e.while_(lambda: e.ne(p["ul_go"], 0), step)
        _ok(e, e.lt(p["ul_v"], 1 << 56))
        e.give(p["ul_v"])
    return _function((), build, tables)


def _pow2(e: E, s):
    """``2 ** s`` for ``s`` in {0, 7, ..., 49} (a ULEB128 group's shift)."""
    result = e.c(1)
    for q in range(7, 56, 7):
        result = e.sel(e.eq(s, q), 1 << q, result)
    return result


def _bstr_fn(tables):
    """``Cursor.byte_string``: a ULEB128 length, then the bytes; their handle ``[n, bytes...]``."""
    def build(e: E):
        p = e.p
        e.var("bs_n", _call(e, "an_uleb"))
        e.var("bs_at", e.ld(G_CUR))
        _ok(e, e.le(e.add(p["bs_at"], p["bs_n"]), e.ld(G_END)))
        e.var("bs_h", e.alloc(e.add(p["bs_n"], 1)))
        _ok(e, e.ne(p["bs_h"], NONE))
        e.st(p["bs_h"], p["bs_n"])
        e.for_("bs_k", 0, p["bs_n"], lambda: e.st(e.add(e.add(p["bs_h"], 1), p["bs_k"]), e.rd(e.add(p["bs_at"], p["bs_k"]))))
        e.st(G_CUR, e.add(p["bs_at"], p["bs_n"]))
        e.give(p["bs_h"])
    return _function((), build, tables)


def _same_fn(tables):
    """1 when handles ``a`` and ``b`` hold equal sequences."""
    def build(e: E):
        p = e.p
        e.if_(e.ne(e.ld(p["a"]), e.ld(p["b"])), lambda: e.give(0))
        e.for_("sm_k", 1, e.add(e.ld(p["a"]), 1), lambda: e.if_(e.ne(at(e, p["a"], p["sm_k"]), at(e, p["b"], p["sm_k"])), lambda: e.give(0)))
        e.give(1)
    return _function(("a", "b"), build, tables)


def _prefix_fn(tables):
    """1 when handle ``h`` starts with handle ``c``'s sequence."""
    def build(e: E):
        p = e.p
        e.if_(e.lt(e.ld(p["h"]), e.ld(p["c"])), lambda: e.give(0))
        e.for_("pf_k", 1, e.add(e.ld(p["c"]), 1), lambda: e.if_(e.ne(at(e, p["h"], p["pf_k"]), at(e, p["c"], p["pf_k"])), lambda: e.give(0)))
        e.give(1)
    return _function(("h", "c"), build, tables)


def _less_fn(tables):
    """1 when handle ``a``'s sequence sorts before ``b``'s (item by item; a prefix first)."""
    def build(e: E):
        p = e.p
        e.var("ls_n", e.sel(e.lt(e.ld(p["a"]), e.ld(p["b"])), e.ld(p["a"]), e.ld(p["b"])))

        def compare():
            e.if_(e.lt(at(e, p["a"], p["ls_k"]), at(e, p["b"], p["ls_k"])), lambda: e.give(1))
            e.if_(e.lt(at(e, p["b"], p["ls_k"]), at(e, p["a"], p["ls_k"])), lambda: e.give(0))

        e.for_("ls_k", 1, e.add(p["ls_n"], 1), compare)
        e.give(e.flag(e.lt(e.ld(p["a"]), e.ld(p["b"]))))
    return _function(("a", "b"), build, tables)


def _desc_fn(tables):
    """1 when handle ``h`` is a DEX class descriptor (``_validate_class_descriptor``): ``L...;``, longer than 2, no ``.``,
    NUL or ``//``."""
    def build(e: E):
        p = e.p
        e.var("dc_n", e.ld(p["h"]))
        e.if_(e.le(p["dc_n"], 2), lambda: e.give(0))
        e.if_(e.either(e.ne(at(e, p["h"], 1), ord("L")), e.ne(at(e, p["h"], p["dc_n"]), ord(";"))), lambda: e.give(0))

        def check():
            e.var("dc_c", at(e, p["h"], p["dc_k"]))
            e.if_(e.either(e.eq(p["dc_c"], ord(".")), e.eq(p["dc_c"], 0)), lambda: e.give(0))
            e.if_(e.both(e.eq(p["dc_c"], ord("/")), e.eq(at(e, p["h"], e.add(p["dc_k"], 1)), ord("/"))), lambda: e.give(0))

        e.for_("dc_k", 1, p["dc_n"], check)
        e.give(1)
    return _function(("h",), build, tables)


def _java_fn(tables):
    """``java(d)``: the Java binary name of class descriptor ``d`` (``d[1:-1]`` with ``/`` as ``.``)."""
    def build(e: E):
        p = e.p
        e.var("jn_n", e.sub(e.ld(p["d"]), 2))
        e.var("jn_h", e.alloc(e.add(p["jn_n"], 1)))
        _ok(e, e.ne(p["jn_h"], NONE))
        e.st(p["jn_h"], p["jn_n"])
        e.for_("jn_k", 0, p["jn_n"], lambda: (e.var("jn_u", at(e, p["d"], e.add(p["jn_k"], 2))),
                                              e.st(e.add(e.add(p["jn_h"], 1), p["jn_k"]), e.sel(e.eq(p["jn_u"], ord("/")), ord("."), p["jn_u"]))))
        e.give(p["jn_h"])
    return _function(("d",), build, tables)


def _jname_fn(tables):
    """1 when handle ``h`` is a Java binary class name (``LibxposedManagedEntryDescription``): dot-separated parts, each
    a letter, ``_`` or ``$`` then letters, digits, ``_`` or ``$``.  A byte past ASCII gives 0 (the bootstrap's Unicode
    classes then decide: the program declines)."""
    def build(e: E):
        p = e.p
        e.var("jm_start", 1)
        e.if_(e.eq(e.ld(p["h"]), 0), lambda: e.give(0))

        def char():
            e.var("jm_c", at(e, p["h"], p["jm_k"]))
            c = p["jm_c"]
            e.if_(e.le(0x80, c), lambda: e.give(0))
            alpha = e.either(e.both(e.le(ord("A"), c), e.le(c, ord("Z"))), e.both(e.le(ord("a"), c), e.le(c, ord("z"))),
                             e.eq(c, ord("_")), e.eq(c, ord("$")))
            digit = e.both(e.le(ord("0"), c), e.le(c, ord("9")))

            def dot():
                e.if_(e.ne(p["jm_start"], 0), lambda: e.give(0))
                e.set("jm_start", 1)

            def other():
                e.if_(e.ne(p["jm_start"], 0), lambda: e.if_(e.not_(alpha), lambda: e.give(0)),
                      lambda: e.if_(e.not_(e.either(alpha, digit)), lambda: e.give(0)))
                e.set("jm_start", 0)

            e.if_(e.eq(c, ord(".")), dot, other)

        e.for_("jm_k", 1, e.add(e.ld(p["h"]), 1), char)
        e.give(e.flag(e.eq(p["jm_start"], 0)))
    return _function(("h",), build, tables)


def _line_fn(tables):
    """1 when handle ``h`` is nonempty single-line text (no NUL, LF or CR)."""
    def build(e: E):
        p = e.p
        e.if_(e.eq(e.ld(p["h"]), 0), lambda: e.give(0))
        e.for_("ln_k", 1, e.add(e.ld(p["h"]), 1), lambda: (e.var("ln_c", at(e, p["h"], p["ln_k"])), e.if_(
            e.either(e.eq(p["ln_c"], 0), e.eq(p["ln_c"], 10), e.eq(p["ln_c"], 13)), lambda: e.give(0))))
        e.give(1)
    return _function(("h",), build, tables)


def _dotted_fn(tables):
    """``"L" + name.replace(".", "/") + ";"``: the class descriptor of Java binary name handle ``d``."""
    def build(e: E):
        p = e.p
        e.var("dt_n", e.add(e.ld(p["d"]), 2))
        e.var("dt_h", e.alloc(e.add(p["dt_n"], 1)))
        _ok(e, e.ne(p["dt_h"], NONE))
        e.st(p["dt_h"], p["dt_n"])
        e.st(e.add(p["dt_h"], 1), ord("L"))
        e.st(e.add(p["dt_h"], p["dt_n"]), ord(";"))
        e.for_("dt_k", 1, e.add(e.ld(p["d"]), 1), lambda: (e.var("dt_u", at(e, p["d"], p["dt_k"])),
                                                         e.st(e.add(e.add(p["dt_h"], 1), p["dt_k"]), e.sel(e.eq(p["dt_u"], ord(".")), ord("/"), p["dt_u"]))))
        e.give(p["dt_h"])
    return _function(("d",), build, tables)


def _cat_fn(tables):
    """Append handle ``h``'s items to buffer ``b`` (a handle with room past its count)."""
    def build(e: E):
        p = e.p
        e.var("ct_n", e.ld(p["b"]))
        e.for_("ct_k", 1, e.add(e.ld(p["h"]), 1), lambda: e.st(e.add(e.add(p["b"], p["ct_n"]), p["ct_k"]), at(e, p["h"], p["ct_k"])))
        e.st(p["b"], e.add(p["ct_n"], e.ld(p["h"])))
        e.give(1)
    return _function(("b", "h"), build, tables)


def _dec_fn(tables):
    """Append the decimal digits of ``v`` to buffer ``b`` (``str(int)``)."""
    def build(e: E):
        p = e.p
        e.var("dg_n", 1)
        e.var("dg_t", 10)
        e.while_(lambda: e.both(e.le(p["dg_t"], p["v"]), e.lt(p["dg_n"], 19)), lambda: (e.set("dg_n", e.add(p["dg_n"], 1)),
                                                                                    e.set("dg_t", e.mul(p["dg_t"], 10))))
        e.var("dg_at", e.add(p["b"], e.ld(p["b"])))
        e.var("dg_v", p["v"])
        e.for_("dg_k", 0, p["dg_n"], lambda: (e.st(e.add(p["dg_at"], e.sub(p["dg_n"], p["dg_k"])), e.add(ord("0"), e.urem(p["dg_v"], 10))),
                                              e.set("dg_v", e.udiv(p["dg_v"], 10))))
        e.st(p["b"], e.add(e.ld(p["b"]), p["dg_n"]))
        e.give(1)
    return _function(("b", "v"), build, tables)


def _dpack(e: E, h, n, stem: str):
    """The diagnostic words of ``n`` bytes (one per item of handle ``h`` from item 1), packed eight to a word."""
    e.for_(f"{stem}_w", 0, e.udiv(e.add(n, 7), 8), lambda: (
        e.var(f"{stem}_v", 0),
        [e.set(f"{stem}_v", e.add(e.p[f"{stem}_v"], e.mul(e.sel(e.lt(e.add(e.mul(e.p[f"{stem}_w"], 8), i), n),
                                                                 at(e, h, e.add(e.add(e.mul(e.p[f"{stem}_w"], 8), i), 1)), 0), 1 << (8 * i))))
         for i in range(8)],
        D.put(e, e.p[f"{stem}_v"])))


def _dtext_fn(tables):
    """``tag`` (STR, HEX or BYTES), then handle ``h``'s bytes; a STR past ASCII declines unless ``raw`` (the bootstrap
    renders that text with ``decode("ascii", "replace")``)."""
    def build(e: E):
        p = e.p
        e.if_(e.both(e.eq(p["tag"], D.T_STR), e.eq(p["raw"], 0)), lambda: e.for_(
            "dx_k", 1, e.add(e.ld(p["h"]), 1), lambda: e.if_(e.le(0x80, at(e, p["h"], p["dx_k"])), lambda: e.give(NONE))))
        D.put(e, p["tag"])
        D.put(e, e.ld(p["h"]))
        _dpack(e, p["h"], e.ld(p["h"]), "dx")
        e.give(1)
    return _function(("h", "tag", "raw"), build, tables)


def _dcid_fn(tables):
    """A CID handle ``[4, words]`` as a CID value."""
    def build(e: E):
        p = e.p
        D.put(e, D.T_CID)
        for w in range(CID_WORDS):
            D.put(e, at(e, p["h"], 1 + w))
        e.give(1)
    return _function(("h",), build, tables)


def _slice_fn(tables):
    """``slice(h, a, b)``: the handle of handle ``h``'s items ``a`` (from 1) to ``b`` (exclusive)."""
    def build(e: E):
        p = e.p
        e.var("sl_n", e.sub(p["b"], p["a"]))
        e.var("sl_h", e.alloc(e.add(p["sl_n"], 1)))
        _ok(e, e.ne(p["sl_h"], NONE))
        e.st(p["sl_h"], p["sl_n"])
        e.for_("sl_k", 0, p["sl_n"], lambda: e.st(e.add(e.add(p["sl_h"], 1), p["sl_k"]), at(e, p["h"], e.add(p["a"], p["sl_k"]))))
        e.give(p["sl_h"])
    return _function(("h", "a", "b"), build, tables)


def _native_fn(tables):
    """``AndroidManagedMethod.native_name``: ``"xax"``, the name's first letter in upper case, the rest (ASCII)."""
    def build(e: E):
        p = e.p
        e.var("nt_h", e.alloc(e.add(e.ld(p["h"]), 4)))
        _ok(e, e.ne(p["nt_h"], NONE))
        e.st(p["nt_h"], e.add(e.ld(p["h"]), 3))
        for k, byte in enumerate(b"xax"):
            e.st(e.add(p["nt_h"], 1 + k), byte)
        e.var("nt_c", at(e, p["h"], 1))
        e.st(e.add(p["nt_h"], 4), e.sel(e.both(e.le(ord("a"), p["nt_c"]), e.le(p["nt_c"], ord("z"))), e.sub(p["nt_c"], 32), p["nt_c"]))
        e.for_("nt_k", 2, e.add(e.ld(p["h"]), 1), lambda: e.st(e.add(e.add(p["nt_h"], 3), p["nt_k"]), at(e, p["h"], p["nt_k"])))
        e.give(p["nt_h"])
    return _function(("h",), build, tables)


def _binary_fn(tables):
    """``_binary_name``: nonempty, no ``/``, ``;`` or NUL, and no empty dot-separated part."""
    def build(e: E):
        p = e.p
        e.var("bn_n", e.ld(p["h"]))
        e.if_(e.eq(p["bn_n"], 0), lambda: e.give(0))
        e.if_(e.either(e.eq(at(e, p["h"], 1), ord(".")), e.eq(at(e, p["h"], p["bn_n"]), ord("."))), lambda: e.give(0))

        def char():
            e.var("bn_c", at(e, p["h"], p["bn_k"]))
            e.if_(e.either(e.eq(p["bn_c"], ord("/")), e.eq(p["bn_c"], ord(";")), e.eq(p["bn_c"], 0)), lambda: e.give(0))
            e.if_(e.both(e.lt(p["bn_k"], p["bn_n"]), e.eq(p["bn_c"], ord(".")), e.eq(at(e, p["h"], e.add(p["bn_k"], 1)), ord("."))), lambda: e.give(0))

        e.for_("bn_k", 1, e.add(p["bn_n"], 1), char)
        e.give(1)
    return _function(("h",), build, tables)


def _tail_fn(tables):
    """``tail(h, n)``: the handle of ``h``'s sequence without its first ``n`` items."""
    def build(e: E):
        p = e.p
        e.var("tl_n", e.sub(e.ld(p["h"]), p["n"]))
        e.var("tl_h", e.alloc(e.add(p["tl_n"], 1)))
        _ok(e, e.ne(p["tl_h"], NONE))
        e.st(p["tl_h"], p["tl_n"])
        e.for_("tl_k", 0, p["tl_n"], lambda: e.st(e.add(e.add(p["tl_h"], 1), p["tl_k"]), at(e, p["h"], e.add(e.add(p["tl_k"], p["n"]), 1))))
        e.give(p["tl_h"])
    return _function(("h", "n"), build, tables)


def _has_fn(tables):
    """1 when handle ``h`` holds ``value``."""
    def build(e: E):
        p = e.p
        e.for_("hs_k", 1, e.add(e.ld(p["h"]), 1), lambda: e.if_(e.eq(at(e, p["h"], p["hs_k"]), p["value"]), lambda: e.give(1)))
        e.give(0)
    return _function(("h", "value"), build, tables)


def _utf16_fn(tables):
    """The UTF-16 code units of handle ``h``'s bytes decoded as strict UTF-8 (``bytes.decode("utf-8")``), or NONE."""
    def build(e: E):
        p = e.p
        e.var("u8_n", e.ld(p["h"]))
        e.var("u8_o", e.alloc(e.add(e.mul(p["u8_n"], 2), 1)))
        _ok(e, e.ne(p["u8_o"], NONE))
        e.var("u8_m", 0)
        e.var("u8_k", 1)

        def unit(value):
            e.st(e.add(e.add(p["u8_o"], 1), p["u8_m"]), value)
            e.set("u8_m", e.add(p["u8_m"], 1))

        def cont(j):
            """Continuation byte ``j`` after the lead (or 0x100 past the end)."""
            index = e.add(p["u8_k"], j)
            return e.sel(e.le(index, p["u8_n"]), at(e, p["h"], e.sel(e.le(index, p["u8_n"]), index, 1)), 0x100)

        def step():
            e.var("u8_b", at(e, p["h"], p["u8_k"]))
            b = p["u8_b"]

            def one():
                unit(b)
                e.set("u8_k", e.add(p["u8_k"], 1))

            def many():
                e.var("u8_len", e.sel(e.lt(b, 0xE0), 2, e.sel(e.lt(b, 0xF0), 3, 4)))
                # Lead bytes C2..F4; the second byte's range depends on the lead (no overlong, surrogate or > U+10FFFF).
                e.if_(e.either(e.lt(b, 0xC2), e.lt(0xF4, b)), lambda: e.give(NONE))
                e.var("u8_lo", e.sel(e.eq(b, 0xE0), 0xA0, e.sel(e.eq(b, 0xF0), 0x90, 0x80)))
                e.var("u8_hi", e.sel(e.eq(b, 0xED), 0x9F, e.sel(e.eq(b, 0xF4), 0x8F, 0xBF)))
                e.var("u8_c1", cont(1))
                e.if_(e.either(e.lt(p["u8_c1"], p["u8_lo"]), e.lt(p["u8_hi"], p["u8_c1"])), lambda: e.give(NONE))
                e.var("u8_cp", e.add(e.mul(e.and_(b, e.sel(e.eq(p["u8_len"], 2), 0x1F, e.sel(e.eq(p["u8_len"], 3), 0x0F, 0x07))), 64),
                                     e.and_(p["u8_c1"], 0x3F)))

                def more(j):
                    e.var("u8_cj", cont(j))
                    e.if_(e.either(e.lt(p["u8_cj"], 0x80), e.lt(0xBF, p["u8_cj"])), lambda: e.give(NONE))
                    e.set("u8_cp", e.add(e.mul(p["u8_cp"], 64), e.and_(p["u8_cj"], 0x3F)))

                e.if_(e.le(3, p["u8_len"]), lambda: more(2))
                e.if_(e.eq(p["u8_len"], 4), lambda: more(3))
                e.if_(e.lt(p["u8_cp"], 0x10000), lambda: unit(p["u8_cp"]), lambda: (
                    e.var("u8_v", e.sub(p["u8_cp"], 0x10000)),
                    unit(e.add(0xD800, e.udiv(p["u8_v"], 1024))),
                    unit(e.add(0xDC00, e.and_(p["u8_v"], 1023)))))
                e.set("u8_k", e.add(p["u8_k"], p["u8_len"]))

            e.if_(e.lt(b, 0x80), one, many)

        e.while_(lambda: e.le(p["u8_k"], p["u8_n"]), step)
        e.st(p["u8_o"], p["u8_m"])
        e.give(p["u8_o"])
    return _function(("h",), build, tables)


def _jni_fn(tables):
    """``jni(d, m)``: the JNI short symbol (bytes) of class descriptor ``d`` and method ``m`` (UTF-16 units)
    (``xax_jni.jni_short_native_symbol``); declines where it raises."""
    def build(e: E):
        p = e.p
        e.var("jx_dn", e.ld(p["d"]))
        _ok(e, e.both(e.le(2, p["jx_dn"]), e.both(e.eq(at(e, p["d"], 1), ord("L")), e.eq(at(e, p["d"], p["jx_dn"]), ord(";")))))
        _ok(e, e.lt(0, e.ld(p["m"])))
        e.for_("jx_k", 1, e.add(e.ld(p["m"]), 1), lambda: (
            e.var("jx_u", at(e, p["m"], p["jx_k"])),
            _ok(e, e.not_(e.either(*(e.eq(p["jx_u"], ord(c)) for c in "./;[\x00"))))))
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


def _cid_fn(tables):
    """The handle ``[4, words]`` of the CID in the 32 bytes at handle ``h`` from item ``k`` (big-endian words)."""
    def build(e: E):
        p = e.p
        e.var("cd_h", e.alloc(CID_WORDS + 1))
        _ok(e, e.ne(p["cd_h"], NONE))
        e.st(p["cd_h"], CID_WORDS)
        for w in range(CID_WORDS):
            e.var("cd_v", 0)
            for i in range(8):
                e.set("cd_v", e.add(e.mul(p["cd_v"], 256), at(e, p["h"], e.add(p["k"], 8 * w + i))))
            e.st(e.add(p["cd_h"], 1 + w), p["cd_v"])
        e.give(p["cd_h"])
    return _function(("h", "k"), build, tables)


def _incid_fn(tables):
    """The handle ``[4, words]`` of the CID at input word ``at``."""
    def build(e: E):
        p = e.p
        e.var("ic_h", e.alloc(CID_WORDS + 1))
        _ok(e, e.ne(p["ic_h"], NONE))
        e.st(p["ic_h"], CID_WORDS)
        for w in range(CID_WORDS):
            e.st(e.add(p["ic_h"], 1 + w), e.rd(e.add(p["at"], w)))
        e.give(p["ic_h"])
    return _function(("at",), build, tables)


# -- writing a layer's input ------------------------------------------------------------------------------------------------

def _put_fn(tables):
    def build(e: E):
        p = e.p
        e.var("pt_at", e.ld(G_W))
        _ok(e, e.lt(p["pt_at"], e.ld(G_WEND)))
        e.st(p["pt_at"], p["value"])
        e.st(G_W, e.add(p["pt_at"], 1))
        e.give(1)
    return _function(("value",), build, tables)


def _seq_put_fn(tables):
    """Handle ``h``'s count and items (a text's units, a string's bytes one per word)."""
    def build(e: E):
        p = e.p
        _call(e, "an_put", e.ld(p["h"]))
        e.for_("sp_k", 1, e.add(e.ld(p["h"]), 1), lambda: _call(e, "an_put", at(e, p["h"], p["sp_k"])))
        e.give(1)
    return _function(("h",), build, tables)


def _pack_put_fn(tables):
    """``n`` bytes (one per word from ``base``): the count, then the bytes packed eight to a word (little endian)."""
    def build(e: E):
        p = e.p
        _call(e, "an_put", p["n"])

        def word():
            e.var("pk_v", 0)
            for i in range(8):
                index = e.add(e.mul(p["pk_w"], 8), i)
                e.set("pk_v", e.add(p["pk_v"], e.mul(e.sel(e.lt(index, p["n"]), at(e, p["base"], e.sel(e.lt(index, p["n"]), index, 0)), 0), 1 << (8 * i))))
            _call(e, "an_put", p["pk_v"])

        e.for_("pk_w", 0, e.udiv(e.add(p["n"], 7), 8), word)
        e.give(1)
    return _function(("base", "n"), build, tables)


def _bigalloc_fn(tables):
    """``n`` words of the large region, below the records kept so far and above what the writer wrote there."""
    def build(e: E):
        p = e.p
        e.var("ba_top", e.ld(G_RTOP))
        _ok(e, e.le(p["n"], e.sub(p["ba_top"], BIG_AT)))
        e.var("ba_at", e.sub(p["ba_top"], p["n"]))
        _ok(e, e.le(e.sel(e.ne(e.ld(G_BIG), 0), e.ld(G_W), BIG_AT), p["ba_at"]))
        e.st(G_RTOP, p["ba_at"])
        e.if_(e.ne(e.ld(G_BIG), 0), lambda: e.st(G_WEND, p["ba_at"]))
        e.give(p["ba_at"])
    return _function(("n",), build, tables)


def _record_fn(tables):
    """The handle ``[length, packed words...]`` of the image record a layer wrote."""
    def build(e: E):
        p = e.p
        _ok(e, e.both(e.eq(e.ld(IMAGE_AT), 1), e.eq(e.ld(IMAGE_AT + 1), 0)))
        e.var("rc_n", e.ld(IMAGE_AT + 2))
        e.var("rc_w", e.udiv(e.add(p["rc_n"], 7), 8))
        _ok(e, e.le(e.add(IMAGE_AT + 3, p["rc_w"]), IMAGE_END))
        e.var("rc_h", _call(e, "an_bigalloc", e.add(p["rc_w"], 1)))
        e.st(p["rc_h"], p["rc_n"])
        e.for_("rc_k", 0, p["rc_w"], lambda: e.st(e.add(e.add(p["rc_h"], 1), p["rc_k"]), e.ld(e.add(IMAGE_AT + 3, p["rc_k"]))))
        e.give(p["rc_h"])
    return _function((), build, tables)


def _blob_put_fn(tables):
    """A record handle's length and packed words, as written."""
    def build(e: E):
        p = e.p
        _call(e, "an_put", e.ld(p["h"]))
        e.for_("bp_k", 1, e.add(e.udiv(e.add(e.ld(p["h"]), 7), 8), 1), lambda: _call(e, "an_put", at(e, p["h"], p["bp_k"])))
        e.give(1)
    return _function(("h",), build, tables)


# -- S15e.6i.3 (ADR-359): the module record as ``json.loads`` reads it -------------------------------------------------------
# ``decode_libxposed_jvm_module`` reads the record with ``json.loads`` on its bytes: ``detect_encoding``, that codec with
# ``surrogatepass``, then CPython's C scanner.  The program decodes the bytes to code points (``an_jdecode``) and parses
# them as that scanner does (``an_jparse``).  A value node is ``[1, n, bytes]`` (a string: each code point, a surrogate
# too, encoded as UTF-8, so byte order is code-point order; ``node + 1`` is its plain handle), ``[2, neg, nd, digits]`` (an
# integer by its decimal digits), ``[3, n, nodes]`` (an array), ``[4, n, key, value, ...]`` (the object's pairs as
# written), ``[5, class, neg, q, e + E_BIAS]`` (a float, ``float()`` of its text: class 0 is ``q * 2 ** e``, 1 an
# infinity, 2 NaN), ``[6, value]`` (a boolean) or ``[7]`` (null).  What the decoder or the scanner refuses declines (its
# error is not a diagnostic), as do integers past CPython's digit limit and nesting past ``J_DEPTH``.
G_JC, G_JH = CO_AT + 16, CO_AT + 17  # the cursor (an index from 0) and the code points it reads
J_END = 0x110000  # the code point past the end
J_DEPTH = 9000  # below the C scanner's RecursionError (about 9998 levels from a fresh stack)
J_DIGITS = 4300  # ``sys.get_int_max_str_digits()``
E_BIAS = 1 << 40  # signed exponents, offset into unsigned words
J_SPACE = (0x20, 0x09, 0x0A, 0x0D)
HEX_SPACE = (0x20, 0x09, 0x0A, 0x0B, 0x0C, 0x0D)  # ``bytes.fromhex`` skips ASCII whitespace between bytes
SIGNIFICANT = 800  # decimal digits kept for rounding; any later nonzero digit is a sticky digit (halfway cases need 767)
MASK32 = (1 << 32) - 1


def _jcp(e: E, ahead: int = 0):
    """The code point ``ahead`` past the cursor (``J_END`` past the end)."""
    k = e.add(e.ld(G_JC), ahead)
    n = e.ld(e.ld(G_JH))
    return e.sel(e.lt(k, n), at(e, e.ld(G_JH), e.add(e.sel(e.lt(k, n), k, 0), 1)), J_END)


def _jskip(e: E, k=1):
    e.st(G_JC, e.add(e.ld(G_JC), k))


def _isdigit(e: E, c):
    return e.both(e.le(ord("0"), c), e.le(c, ord("9")))


def _hexval(e: E, c):
    """The value of hex digit ``c`` (either case), or NONE."""
    return e.sel(_isdigit(e, c), e.sub(c, ord("0")), e.sel(e.both(e.le(ord("a"), c), e.le(c, ord("f"))), e.sub(c, ord("a") - 10),
                                                             e.sel(e.both(e.le(ord("A"), c), e.le(c, ord("F"))), e.sub(c, ord("A") - 10), NONE)))


def _utf8_length(e: E, b):
    """The length of the encoded code point whose lead byte is ``b``."""
    return e.sel(e.lt(b, 0x80), 1, e.sel(e.lt(b, 0xE0), 2, e.sel(e.lt(b, 0xF0), 3, 4)))


def _jdecode_fn(tables):
    """``b.decode(json.detect_encoding(b), "surrogatepass")`` of handle ``h``'s items past the first ``start``: the code
    points' handle; what that codec refuses declines."""
    def build(e: E):
        p = e.p
        e.var("dd_n", e.sub(e.ld(p["h"]), p["start"]))
        e.var("dd_base", e.add(p["h"], p["start"]))  # byte k is item k + 1 of this base

        def byte(k):
            """Byte ``k`` (256 past the end)."""
            return e.sel(e.lt(k, p["dd_n"]), at(e, p["dd_base"], e.add(e.sel(e.lt(k, p["dd_n"]), k, 0), 1)), 256)

        for k in range(4):
            e.var(f"dd_{k}", byte(e.c(k)))
        b0, b1, b2, b3 = (p[f"dd_{k}"] for k in range(4))
        # 0 UTF-8, 1 UTF-16-LE, 2 UTF-16-BE, 3 UTF-32-LE, 4 UTF-32-BE; ``dd_at`` is past the byte order mark.
        e.var("dd_enc", 0)
        e.var("dd_at", 0)
        e.var("dd_done", 0)

        def pick(condition, encoding, skip):
            e.if_(e.both(e.eq(p["dd_done"], 0), condition), lambda: (e.set("dd_enc", encoding), e.set("dd_at", skip), e.set("dd_done", 1)))

        pick(e.both(e.eq(b0, 0), e.eq(b1, 0), e.eq(b2, 0xFE), e.eq(b3, 0xFF)), 4, 4)
        pick(e.both(e.eq(b0, 0xFF), e.eq(b1, 0xFE), e.eq(b2, 0), e.eq(b3, 0)), 3, 4)
        pick(e.both(e.eq(b0, 0xFE), e.eq(b1, 0xFF)), 2, 2)
        pick(e.both(e.eq(b0, 0xFF), e.eq(b1, 0xFE)), 1, 2)
        pick(e.both(e.eq(b0, 0xEF), e.eq(b1, 0xBB), e.eq(b2, 0xBF)), 0, 3)
        four = lambda: e.le(4, p["dd_n"])  # noqa: E731 - a comparison is made where it is used
        pick(e.both(four(), e.eq(b0, 0), e.ne(b1, 0)), 2, 0)
        pick(e.both(four(), e.eq(b0, 0)), 4, 0)
        pick(e.both(four(), e.eq(b1, 0), e.either(e.ne(b2, 0), e.ne(b3, 0))), 1, 0)
        pick(e.both(four(), e.eq(b1, 0)), 3, 0)
        two = lambda: e.eq(p["dd_n"], 2)  # noqa: E731
        pick(e.both(two(), e.eq(b0, 0)), 2, 0)
        pick(e.both(two(), e.eq(b1, 0)), 1, 0)
        e.var("dd_out", e.alloc(e.add(p["dd_n"], 1)))
        _ok(e, e.ne(p["dd_out"], NONE))
        e.var("dd_m", 0)
        e.var("dd_k", p["dd_at"])
        enc = p["dd_enc"]

        def emit(cp):
            e.st(e.add(e.add(p["dd_out"], 1), p["dd_m"]), cp)
            e.set("dd_m", e.add(p["dd_m"], 1))

        def unit16(k):
            return e.sel(e.eq(enc, 1), e.add(byte(k), e.mul(byte(e.add(k, 1)), 256)), e.add(e.mul(byte(k), 256), byte(e.add(k, 1))))

        def utf8():
            e.var("dd_b", byte(p["dd_k"]))
            b = p["dd_b"]

            def many():
                e.var("dd_len", _utf8_length(e, b))
                _ok(e, e.both(e.le(0xC2, b), e.le(b, 0xF4)))
                # The second byte's range follows the lead (no overlong form or past U+10FFFF); ``surrogatepass`` keeps ED A0-BF.
                e.var("dd_lo", e.sel(e.eq(b, 0xE0), 0xA0, e.sel(e.eq(b, 0xF0), 0x90, 0x80)))
                e.var("dd_hi", e.sel(e.eq(b, 0xF4), 0x8F, 0xBF))
                e.var("dd_c1", byte(e.add(p["dd_k"], 1)))
                _ok(e, e.both(e.le(p["dd_lo"], p["dd_c1"]), e.le(p["dd_c1"], p["dd_hi"])))
                e.var("dd_cp", e.add(e.mul(e.and_(b, e.sel(e.eq(p["dd_len"], 2), 0x1F, e.sel(e.eq(p["dd_len"], 3), 0x0F, 0x07))), 64),
                                     e.and_(p["dd_c1"], 0x3F)))
                for j in (2, 3):
                    def more(j=j):
                        e.var("dd_cj", byte(e.add(p["dd_k"], j)))
                        _ok(e, e.both(e.le(0x80, p["dd_cj"]), e.le(p["dd_cj"], 0xBF)))
                        e.set("dd_cp", e.add(e.mul(p["dd_cp"], 64), e.and_(p["dd_cj"], 0x3F)))

                    e.if_(e.le(j + 1, p["dd_len"]), more)
                emit(p["dd_cp"])
                e.set("dd_k", e.add(p["dd_k"], p["dd_len"]))

            e.if_(e.lt(b, 0x80), lambda: (emit(b), e.set("dd_k", e.add(p["dd_k"], 1))), many)

        def utf16():
            _ok(e, e.lt(e.add(p["dd_k"], 1), p["dd_n"]))  # an odd last byte: truncated data
            e.var("dd_u", unit16(p["dd_k"]))
            e.set("dd_k", e.add(p["dd_k"], 2))

            def pair():
                e.var("dd_u2", unit16(p["dd_k"]))
                e.if_(e.both(e.le(0xDC00, p["dd_u2"]), e.le(p["dd_u2"], 0xDFFF)), lambda: (
                    e.set("dd_u", e.add(0x10000, e.add(e.mul(e.sub(p["dd_u"], 0xD800), 1024), e.sub(p["dd_u2"], 0xDC00)))),
                    e.set("dd_k", e.add(p["dd_k"], 2))))

            e.if_(e.both(e.le(0xD800, p["dd_u"]), e.le(p["dd_u"], 0xDBFF), e.lt(e.add(p["dd_k"], 1), p["dd_n"])), pair)
            emit(p["dd_u"])

        def utf32():
            _ok(e, e.lt(e.add(p["dd_k"], 3), p["dd_n"]))
            e.var("dd_v", 0)
            for j in range(4):
                e.set("dd_v", e.add(p["dd_v"], e.mul(byte(e.add(p["dd_k"], e.sel(e.eq(enc, 3), j, 3 - j))), 1 << (8 * j))))
            _ok(e, e.le(p["dd_v"], 0x10FFFF))
            emit(p["dd_v"])
            e.set("dd_k", e.add(p["dd_k"], 4))

        e.while_(lambda: e.lt(p["dd_k"], p["dd_n"]), lambda: e.if_(e.eq(enc, 0), utf8, lambda: e.if_(e.le(enc, 2), utf16, utf32)))
        e.st(p["dd_out"], p["dd_m"])
        e.give(p["dd_out"])
    return _function(("h", "start"), build, tables)


def _jws_fn(tables):
    def build(e: E):
        e.while_(lambda: e.either(*(e.eq(_jcp(e), c) for c in J_SPACE)), lambda: _jskip(e))
        e.give(1)
    return _function((), build, tables)


def _jhex4_fn(tables):
    """The four hex digits at the cursor (``\\uXXXX``'s): their value; another code point declines."""
    def build(e: E):
        p = e.p
        e.var("j4_v", 0)
        for k in range(4):
            e.var("j4_d", _hexval(e, _jcp(e, k)))
            _ok(e, e.ne(p["j4_d"], NONE))
            e.set("j4_v", e.add(e.mul(p["j4_v"], 16), p["j4_d"]))
        _jskip(e, 4)
        e.give(p["j4_v"])
    return _function((), build, tables)


def _jstr_fn(tables):
    """The JSON string whose opening quote is at the cursor (``scanstring``, strict): its node.  Two passes: the first
    measures the encoded bytes, the second writes them."""
    def build(e: E):
        p = e.p
        e.var("js_start", e.add(e.ld(G_JC), 1))
        e.var("js_h", 0)
        e.var("js_len", 0)

        def one_pass():
            e.if_(e.eq(p["js_m"], 1), lambda: (e.set("js_h", e.alloc(e.add(p["js_len"], 2))), _ok(e, e.ne(p["js_h"], NONE))))
            e.st(G_JC, p["js_start"])
            e.set("js_len", 0)
            e.var("js_go", 1)

            def char():
                e.var("js_c", _jcp(e))
                _ok(e, e.lt(p["js_c"], J_END))  # unterminated
                _jskip(e)
                e.var("js_v", p["js_c"])
                e.if_(e.eq(p["js_c"], ord('"')), lambda: e.set("js_go", 0))
                _ok(e, e.le(0x20, p["js_c"]))  # a control character

                def escape():
                    e.var("js_x", _jcp(e))
                    _jskip(e)
                    e.set("js_v", NONE)
                    for code, value in ((ord('"'), ord('"')), (ord("\\"), ord("\\")), (ord("/"), ord("/")), (ord("b"), 8), (ord("f"), 12),
                                        (ord("n"), 10), (ord("r"), 13), (ord("t"), 9)):
                        e.if_(e.eq(p["js_x"], code), lambda value=value: e.set("js_v", value))

                    def unicode():
                        e.set("js_v", _call(e, "an_jhex4"))

                        def low():
                            e.var("js_save", e.ld(G_JC))
                            _jskip(e, 2)
                            e.var("js_lo", _call(e, "an_jhex4"))
                            e.if_(e.both(e.le(0xDC00, p["js_lo"]), e.le(p["js_lo"], 0xDFFF)), lambda: e.set(
                                "js_v", e.add(0x10000, e.add(e.mul(e.sub(p["js_v"], 0xD800), 1024), e.sub(p["js_lo"], 0xDC00)))),
                                lambda: e.st(G_JC, p["js_save"]))  # another escape: read on its own

                        e.if_(e.both(e.le(0xD800, p["js_v"]), e.le(p["js_v"], 0xDBFF), e.eq(_jcp(e), ord("\\")), e.eq(_jcp(e, 1), ord("u"))), low)

                    e.if_(e.eq(p["js_x"], ord("u")), unicode)
                    _ok(e, e.ne(p["js_v"], NONE))

                e.if_(e.eq(p["js_c"], ord("\\")), escape)

                def keep():
                    v = p["js_v"]
                    e.var("js_n", e.sel(e.lt(v, 0x80), 1, e.sel(e.lt(v, 0x800), 2, e.sel(e.lt(v, 0x10000), 3, 4))))

                    def write():
                        out = e.add(e.add(p["js_h"], 2), p["js_len"])
                        n = p["js_n"]
                        lead = e.sel(e.eq(n, 1), v, e.add(e.sel(e.eq(n, 2), 0xC0, e.sel(e.eq(n, 3), 0xE0, 0xF0)),
                                                          e.udiv(v, e.sel(e.eq(n, 2), 1 << 6, e.sel(e.eq(n, 3), 1 << 12, 1 << 18)))))
                        e.st(out, lead)
                        for j in (1, 2, 3):
                            shift = e.sel(e.eq(e.sub(n, j), 3), 1 << 12, e.sel(e.eq(e.sub(n, j), 2), 1 << 6, 1))
                            e.if_(e.lt(j, n), lambda j=j, shift=shift: e.st(e.add(out, j), e.add(0x80, e.and_(e.udiv(v, shift), 0x3F))))

                    e.if_(e.eq(p["js_m"], 1), write)
                    e.set("js_len", e.add(p["js_len"], p["js_n"]))

                e.if_(e.ne(p["js_go"], 0), keep)

            e.while_(lambda: e.ne(p["js_go"], 0), char)

        e.for_("js_m", 0, 2, one_pass)
        e.st(p["js_h"], 1)
        e.st(e.add(p["js_h"], 1), p["js_len"])
        e.give(p["js_h"])
    return _function((), build, tables)


def _jnum_fn(tables):
    """The number at the cursor (``_match_number_unicode``): an integer node, or a float node rounded as ``float()``
    rounds its text."""
    def build(e: E):
        p = e.p
        e.var("jn_neg", 0)
        e.if_(e.eq(_jcp(e), ord("-")), lambda: (e.set("jn_neg", 1), _jskip(e)))
        e.var("jn_c", _jcp(e))
        _ok(e, _isdigit(e, p["jn_c"]))
        e.var("jn_i0", e.ld(G_JC))
        e.if_(e.eq(p["jn_c"], ord("0")), lambda: _jskip(e), lambda: e.while_(lambda: _isdigit(e, _jcp(e)), lambda: _jskip(e)))
        e.var("jn_i1", e.ld(G_JC))
        e.var("jn_float", 0)
        e.var("jn_f0", e.ld(G_JC))
        e.var("jn_f1", e.ld(G_JC))
        e.if_(e.both(e.eq(_jcp(e), ord(".")), _isdigit(e, _jcp(e, 1))), lambda: (
            _jskip(e), e.set("jn_f0", e.ld(G_JC)), e.while_(lambda: _isdigit(e, _jcp(e)), lambda: _jskip(e)), e.set("jn_f1", e.ld(G_JC)),
            e.set("jn_float", 1)))
        e.var("jn_x", 0)  # the exponent's magnitude, saturated past 10 ** 10
        e.var("jn_xneg", 0)

        def exponent():
            e.var("jn_save", e.ld(G_JC))
            _jskip(e)
            e.if_(e.eq(_jcp(e), ord("-")), lambda: (e.set("jn_xneg", 1), _jskip(e)), lambda: e.if_(e.eq(_jcp(e), ord("+")), lambda: _jskip(e)))
            e.var("jn_x0", e.ld(G_JC))
            e.while_(lambda: _isdigit(e, _jcp(e)), lambda: (
                e.if_(e.lt(p["jn_x"], 10 ** 10), lambda: e.set("jn_x", e.add(e.mul(p["jn_x"], 10), e.sub(_jcp(e), ord("0"))))), _jskip(e)))
            e.if_(e.eq(e.ld(G_JC), p["jn_x0"]), lambda: (e.st(G_JC, p["jn_save"]), e.set("jn_xneg", 0)), lambda: e.set("jn_float", 1))

        e.if_(e.either(e.eq(_jcp(e), ord("e")), e.eq(_jcp(e), ord("E"))), exponent)
        h = e.ld(G_JH)

        def integer():
            e.var("jn_nd", e.sub(p["jn_i1"], p["jn_i0"]))
            _ok(e, e.le(p["jn_nd"], J_DIGITS))  # int()'s ValueError
            e.var("jn_node", e.alloc(e.add(p["jn_nd"], 3)))
            _ok(e, e.ne(p["jn_node"], NONE))
            e.st(p["jn_node"], 2)
            e.st(e.add(p["jn_node"], 1), e.sel(e.eq(at(e, h, e.add(p["jn_i0"], 1)), ord("0")), 0, p["jn_neg"]))  # -0 is 0
            e.st(e.add(p["jn_node"], 2), p["jn_nd"])
            e.for_("jn_k", 0, p["jn_nd"], lambda: e.st(e.add(e.add(p["jn_node"], 3), p["jn_k"]), e.sub(at(e, h, e.add(e.add(p["jn_i0"], p["jn_k"]), 1)), ord("0"))))
            e.give(p["jn_node"])

        e.if_(e.eq(p["jn_float"], 0), integer)
        e.var("jn_node", e.alloc(5))
        _ok(e, e.ne(p["jn_node"], NONE))
        e.st(p["jn_node"], 5)
        e.st(e.add(p["jn_node"], 2), p["jn_neg"])
        e.var("jn_mark", e.hd(H_ARENA))  # the digits and the arithmetic's numbers are released
        e.var("jn_ni", e.sub(p["jn_i1"], p["jn_i0"]))
        e.var("jn_nf", e.sub(p["jn_f1"], p["jn_f0"]))
        e.var("jn_dg", e.alloc(e.add(e.add(p["jn_ni"], p["jn_nf"]), 1)))
        _ok(e, e.ne(p["jn_dg"], NONE))
        e.st(p["jn_dg"], e.add(p["jn_ni"], p["jn_nf"]))
        e.for_("jn_q", 0, p["jn_ni"], lambda: e.st(e.add(e.add(p["jn_dg"], 1), p["jn_q"]), e.sub(at(e, h, e.add(e.add(p["jn_i0"], p["jn_q"]), 1)), ord("0"))))
        e.for_("jn_r", 0, p["jn_nf"], lambda: e.st(e.add(e.add(e.add(p["jn_dg"], 1), p["jn_ni"]), p["jn_r"]),
                                                   e.sub(at(e, h, e.add(e.add(p["jn_f0"], p["jn_r"]), 1)), ord("0"))))
        e.var("jn_e", e.sub(e.sel(e.ne(p["jn_xneg"], 0), e.sub(E_BIAS, p["jn_x"]), e.add(E_BIAS, p["jn_x"])), p["jn_nf"]))
        _call(e, "an_jround", p["jn_node"], p["jn_dg"], p["jn_e"])
        e.set_hd(H_ARENA, p["jn_mark"])
        e.give(p["jn_node"])
    return _function((), build, tables)


def _jvalue_fn(tables):
    """The scalar at the cursor (``scan_once`` but for containers): a literal, a constant or a number."""
    def build(e: E):
        p = e.p

        def literal(text: str):
            return e.both(*(e.eq(_jcp(e, k), ord(c)) for k, c in enumerate(text)))

        def node(words):
            e.var("jv_n", e.alloc(len(words)))
            _ok(e, e.ne(p["jv_n"], NONE))
            for k, word in enumerate(words):
                e.st(e.add(p["jv_n"], k), word)
            e.give(p["jv_n"])

        e.if_(e.eq(_jcp(e), ord('"')), lambda: e.give(_call(e, "an_jstr")))
        for text, words in (("null", (7,)), ("true", (6, 1)), ("false", (6, 0)), ("NaN", (5, 2, 0, 0, E_BIAS)), ("Infinity", (5, 1, 0, 0, E_BIAS)),
                            ("-Infinity", (5, 1, 1, 0, E_BIAS))):
            e.if_(literal(text), lambda text=text, words=words: (_jskip(e, len(text)), node(words)))
        e.give(_call(e, "an_jnum"))
    return _function((), build, tables)


def _jparse_fn(tables):
    """``json.loads``' scanner over the code points ``cps``: the root node.  Containers are read with an explicit stack:
    ``jp_items`` holds the values (an object's keys and values in turn) of every open container, ``jp_frames`` each open
    container's kind and first item."""
    def build(e: E):
        p = e.p
        e.st(G_JH, p["cps"])
        e.st(G_JC, 0)
        e.var("jp_items", e.alloc(e.add(e.ld(p["cps"]), 2)))
        e.var("jp_frames", e.alloc(2 * J_DEPTH + 4))
        _ok(e, e.both(e.ne(p["jp_items"], NONE), e.ne(p["jp_frames"], NONE)))
        e.var("jp_ni", 0)
        e.var("jp_nf", 0)
        e.var("jp_mode", 0)  # 0: a value is expected; 1: a value was read
        e.var("jp_done", 0)
        frame = lambda k: e.add(p["jp_frames"], e.mul(e.sub(p["jp_nf"], 1), 2))  # noqa: E731 - the top frame (k unused)

        def push(v):
            e.st(e.add(p["jp_items"], p["jp_ni"]), v)
            e.set("jp_ni", e.add(p["jp_ni"], 1))

        def key():
            """An object's key, then its ``:``."""
            _ok(e, e.eq(_jcp(e), ord('"')))
            push(_call(e, "an_jstr"))
            _call(e, "an_jws")
            _ok(e, e.eq(_jcp(e), ord(":")))
            _jskip(e)
            _call(e, "an_jws")

        def close():
            """The top container's node from its items; it is then the value read."""
            e.var("jp_kind", e.ld(frame(0)))
            e.var("jp_base", e.ld(e.add(frame(0), 1)))
            e.var("jp_count", e.sub(p["jp_ni"], p["jp_base"]))
            e.var("jp_node", e.alloc(e.add(p["jp_count"], 2)))
            _ok(e, e.ne(p["jp_node"], NONE))
            e.st(p["jp_node"], p["jp_kind"])
            e.st(e.add(p["jp_node"], 1), e.sel(e.eq(p["jp_kind"], 4), e.udiv(p["jp_count"], 2), p["jp_count"]))
            e.for_("jp_k", 0, p["jp_count"], lambda: e.st(e.add(e.add(p["jp_node"], 2), p["jp_k"]), e.ld(e.add(e.add(p["jp_items"], p["jp_base"]), p["jp_k"]))))
            e.set("jp_ni", p["jp_base"])
            e.set("jp_nf", e.sub(p["jp_nf"], 1))
            push(p["jp_node"])
            e.set("jp_mode", 1)

        def open_(kind: int, closer: str):
            _ok(e, e.lt(p["jp_nf"], J_DEPTH))
            e.set("jp_nf", e.add(p["jp_nf"], 1))
            e.st(frame(0), kind)
            e.st(e.add(frame(0), 1), p["jp_ni"])
            _jskip(e)
            _call(e, "an_jws")
            e.if_(e.eq(_jcp(e), ord(closer)), lambda: (_jskip(e), close()), (lambda: key()) if kind == 4 else None)

        def value():
            e.var("jp_c", _jcp(e))
            e.if_(e.eq(p["jp_c"], ord("{")), lambda: open_(4, "}"), lambda: e.if_(e.eq(p["jp_c"], ord("[")), lambda: open_(3, "]"), lambda: (
                push(_call(e, "an_jvalue")), e.set("jp_mode", 1))))

        def after():
            def inner():
                _call(e, "an_jws")
                e.var("jp_sep", _jcp(e))
                e.var("jp_top", e.ld(frame(0)))
                e.var("jp_end", e.sel(e.eq(p["jp_top"], 4), ord("}"), ord("]")))
                _ok(e, e.either(e.eq(p["jp_sep"], ord(",")), e.eq(p["jp_sep"], p["jp_end"])))
                _jskip(e)
                e.if_(e.eq(p["jp_sep"], ord(",")), lambda: (_call(e, "an_jws"), e.set("jp_mode", 0), e.if_(e.eq(p["jp_top"], 4), key)), close)

            e.if_(e.eq(p["jp_nf"], 0), lambda: e.set("jp_done", 1), inner)

        _call(e, "an_jws")
        e.while_(lambda: e.eq(p["jp_done"], 0), lambda: e.if_(e.eq(p["jp_mode"], 0), value, after))
        _call(e, "an_jws")
        _ok(e, e.eq(e.ld(G_JC), e.ld(p["cps"])))  # "Extra data"
        e.give(e.ld(p["jp_items"]))
    return _function(("cps",), build, tables)


# -- arbitrary-precision numbers: ``[n, limbs...]``, 32-bit limbs from the least significant, no zero limb on top --------------

def _blimb(e: E, a, i):
    return at(e, a, e.add(i, 1))


def _bset(e: E, a, i, v):
    e.st(e.add(e.add(a, 1), i), v)


def _bnorm(e: E, a, stem: str):
    e.while_(lambda: e.both(e.lt(0, e.ld(a)), e.eq(_blimb(e, a, e.sub(e.ld(a), 1)), 0)), lambda: e.st(a, e.sub(e.ld(a), 1)))


def _bmul_fn(tables):
    """``a = a * m + c`` in place (``m``, ``c`` below 2 ** 32); ``a`` has room for one more limb."""
    def build(e: E):
        p = e.p
        e.var("bm_carry", p["c"])
        e.for_("bm_i", 0, e.ld(p["a"]), lambda: (
            e.var("bm_t", e.add(e.mul(_blimb(e, p["a"], p["bm_i"]), p["m"]), p["bm_carry"])),
            _bset(e, p["a"], p["bm_i"], e.and_(p["bm_t"], MASK32)), e.set("bm_carry", e.udiv(p["bm_t"], 1 << 32))))
        e.if_(e.ne(p["bm_carry"], 0), lambda: (_bset(e, p["a"], e.ld(p["a"]), p["bm_carry"]), e.st(p["a"], e.add(e.ld(p["a"]), 1))))
        e.give(1)
    return _function(("a", "m", "c"), build, tables)


def _bshl_fn(tables):
    """``a << s``: a new number."""
    def build(e: E):
        p = e.p
        e.var("bs_ls", e.udiv(p["s"], 32))
        e.var("bs_pw", 1)
        e.for_("bs_k", 0, e.urem(p["s"], 32), lambda: e.set("bs_pw", e.mul(p["bs_pw"], 2)))
        e.var("bs_n", e.add(e.add(e.ld(p["a"]), p["bs_ls"]), 1))
        e.var("bs_out", e.alloc(e.add(p["bs_n"], 1)))
        _ok(e, e.ne(p["bs_out"], NONE))
        e.for_("bs_z", 0, p["bs_n"], lambda: _bset(e, p["bs_out"], p["bs_z"], 0))
        e.for_("bs_i", 0, e.ld(p["a"]), lambda: (
            e.var("bs_t", e.mul(_blimb(e, p["a"], p["bs_i"]), p["bs_pw"])),
            e.var("bs_at", e.add(p["bs_i"], p["bs_ls"])),
            _bset(e, p["bs_out"], p["bs_at"], e.add(_blimb(e, p["bs_out"], p["bs_at"]), e.and_(p["bs_t"], MASK32))),
            _bset(e, p["bs_out"], e.add(p["bs_at"], 1), e.udiv(p["bs_t"], 1 << 32))))
        e.st(p["bs_out"], e.sel(e.eq(e.ld(p["a"]), 0), 0, p["bs_n"]))
        _bnorm(e, p["bs_out"], "bs")
        e.give(p["bs_out"])
    return _function(("a", "s"), build, tables)


def _bcmp_fn(tables):
    """0, 1 or 2 as ``a`` is below, equal to or above ``b``."""
    def build(e: E):
        p = e.p
        e.if_(e.ne(e.ld(p["a"]), e.ld(p["b"])), lambda: e.give(e.sel(e.lt(e.ld(p["a"]), e.ld(p["b"])), 0, 2)))
        e.for_("bc_j", 0, e.ld(p["a"]), lambda: (
            e.var("bc_i", e.sub(e.sub(e.ld(p["a"]), 1), p["bc_j"])),
            e.if_(e.ne(_blimb(e, p["a"], p["bc_i"]), _blimb(e, p["b"], p["bc_i"])),
                  lambda: e.give(e.sel(e.lt(_blimb(e, p["a"], p["bc_i"]), _blimb(e, p["b"], p["bc_i"])), 0, 2)))))
        e.give(1)
    return _function(("a", "b"), build, tables)


def _bsub_fn(tables):
    """``a -= b`` in place (``a`` at least ``b``)."""
    def build(e: E):
        p = e.p
        e.var("bb_borrow", 0)
        e.for_("bb_i", 0, e.ld(p["a"]), lambda: (
            e.var("bb_d", e.sub(e.sub(e.add(_blimb(e, p["a"], p["bb_i"]), 1 << 32),
                                      e.sel(e.lt(p["bb_i"], e.ld(p["b"])), _blimb(e, p["b"], e.sel(e.lt(p["bb_i"], e.ld(p["b"])), p["bb_i"], 0)), 0)),
                                p["bb_borrow"])),
            _bset(e, p["a"], p["bb_i"], e.and_(p["bb_d"], MASK32)), e.set("bb_borrow", e.sub(1, e.udiv(p["bb_d"], 1 << 32)))))
        _bnorm(e, p["a"], "bb")
        e.give(1)
    return _function(("a", "b"), build, tables)


def _bbits_fn(tables):
    """The bit length of ``a``."""
    def build(e: E):
        p = e.p
        e.if_(e.eq(e.ld(p["a"]), 0), lambda: e.give(0))
        e.var("bt_top", _blimb(e, p["a"], e.sub(e.ld(p["a"]), 1)))
        e.var("bt_n", 0)
        e.while_(lambda: e.ne(p["bt_top"], 0), lambda: (e.set("bt_top", e.udiv(p["bt_top"], 2)), e.set("bt_n", e.add(p["bt_n"], 1))))
        e.give(e.add(e.mul(e.sub(e.ld(p["a"]), 1), 32), p["bt_n"]))
    return _function(("a",), build, tables)


def _bnew(e: E, name: str, limbs, value=0):
    """A new number of ``value`` (below 2 ** 64) with room for ``limbs`` limbs."""
    e.var(name, e.alloc(e.add(limbs, 3)))
    _ok(e, e.ne(e.p[name], NONE))
    h = e.p[name]
    _bset(e, h, 0, e.and_(value, MASK32))
    _bset(e, h, 1, e.udiv(value, 1 << 32))
    e.st(h, e.sel(e.eq(value, 0), 0, e.sel(e.lt(value, 1 << 32), 1, 2)))
    return h


def _bpow10_fn(tables):
    """``10 ** k``: a new number."""
    def build(e: E):
        p = e.p
        h = _bnew(e, "bp_h", e.add(e.udiv(p["k"], 9), 2), 1)
        e.for_("bp_q", 0, e.udiv(p["k"], 9), lambda: _call(e, "an_bmul", h, 10 ** 9, 0))
        e.for_("bp_r", 0, e.urem(p["k"], 9), lambda: _call(e, "an_bmul", h, 10, 0))
        e.give(h)
    return _function(("k",), build, tables)


def _bdigits_fn(tables):
    """The number of the ``n`` decimal digits of handle ``dg`` from item ``first``, with room for ``room`` more limbs."""
    def build(e: E):
        p = e.p
        h = _bnew(e, "bd_h", e.add(e.add(e.udiv(p["n"], 9), 2), p["room"]))
        e.for_("bd_k", 0, p["n"], lambda: _call(e, "an_bmul", h, 10, at(e, p["dg"], e.add(p["first"], p["bd_k"]))))
        e.give(h)
    return _function(("dg", "first", "n", "room"), build, tables)


def _jround_fn(tables):
    """``float()`` of the decimal ``digits * 10 ** (x - E_BIAS)`` (handle ``dg``'s digits): float node ``node``'s class, ``q``
    and exponent, correctly rounded (ties to even), with IEEE 754 binary64's range and subnormals."""
    def build(e: E):
        p = e.p
        node = p["node"]

        def result(cls, q, exponent):
            e.st(e.add(node, 1), cls)
            e.st(e.add(node, 3), q)
            e.st(e.add(node, 4), exponent)
            e.give(1)

        e.var("jr_nd", e.ld(p["dg"]))
        e.var("jr_first", 1)
        e.while_(lambda: e.both(e.le(p["jr_first"], p["jr_nd"]), e.eq(at(e, p["dg"], p["jr_first"]), 0)), lambda: e.set("jr_first", e.add(p["jr_first"], 1)))
        e.if_(e.lt(p["jr_nd"], p["jr_first"]), lambda: result(0, 0, E_BIAS))  # zero
        e.var("jr_k", e.add(e.sub(p["jr_nd"], p["jr_first"]), 1))
        e.var("jr_use", e.sel(e.lt(p["jr_k"], SIGNIFICANT), p["jr_k"], SIGNIFICANT))
        e.var("jr_sticky", 0)
        e.for_("jr_s", e.add(p["jr_first"], p["jr_use"]), e.add(p["jr_nd"], 1), lambda: e.if_(e.ne(at(e, p["dg"], p["jr_s"]), 0), lambda: e.set("jr_sticky", 1)))
        e.var("jr_x", e.sub(e.add(p["x"], e.sub(p["jr_k"], p["jr_use"])), p["jr_sticky"]))
        e.var("jr_cnt", e.add(p["jr_use"], p["jr_sticky"]))
        e.if_(e.lt(E_BIAS + 310, e.add(p["jr_cnt"], p["jr_x"])), lambda: result(1, 0, E_BIAS))  # past 10 ** 310: infinity
        e.if_(e.lt(e.add(p["jr_cnt"], p["jr_x"]), E_BIAS - 330), lambda: result(0, 0, E_BIAS))  # below 10 ** -330: zero
        e.var("jr_xp", e.sel(e.lt(E_BIAS, p["jr_x"]), e.sub(p["jr_x"], E_BIAS), 0))
        e.var("jr_xn", e.sel(e.lt(p["jr_x"], E_BIAS), e.sub(E_BIAS, p["jr_x"]), 0))
        e.var("jr_N", _call(e, "an_bdigits", p["dg"], p["jr_first"], p["jr_use"], e.add(e.udiv(p["jr_xp"], 9), 2)))
        e.if_(e.ne(p["jr_sticky"], 0), lambda: _call(e, "an_bmul", p["jr_N"], 10, 1))
        e.for_("jr_t", 0, p["jr_xp"], lambda: _call(e, "an_bmul", p["jr_N"], 10, 0))
        e.var("jr_D", _call(e, "an_bpow10", p["jr_xn"]))
        e.var("jr_e", e.sub(e.add(E_BIAS, _call(e, "an_bbits", p["jr_N"])), e.add(_call(e, "an_bbits", p["jr_D"]), 53)))
        e.if_(e.lt(p["jr_e"], E_BIAS - 1074), lambda: e.set("jr_e", E_BIAS - 1074))
        e.var("jr_q", 0)
        e.var("jr_R", 0)
        e.var("jr_B", 0)
        e.var("jr_go", 1)

        def divide():
            """``q, R = divmod(N << -e, D << e)``; once more with ``e + 1`` when ``q`` has 54 bits."""
            e.set("jr_A", _call(e, "an_bshl", p["jr_N"], e.sel(e.lt(p["jr_e"], E_BIAS), e.sub(E_BIAS, p["jr_e"]), 0)))
            e.set("jr_B", _call(e, "an_bshl", p["jr_D"], e.sel(e.lt(E_BIAS, p["jr_e"]), e.sub(p["jr_e"], E_BIAS), 0)))
            e.set("jr_R", p["jr_A"])
            e.set("jr_q", 0)
            e.var("jr_ba", _call(e, "an_bbits", p["jr_A"]))
            e.var("jr_bb", _call(e, "an_bbits", p["jr_B"]))

            def bits():
                e.var("jr_s", e.sub(p["jr_ba"], p["jr_bb"]))
                e.var("jr_pw", 1)
                e.for_("jr_w", 0, p["jr_s"], lambda: e.set("jr_pw", e.mul(p["jr_pw"], 2)))

                def step():
                    e.var("jr_i", e.sub(p["jr_s"], p["jr_j"]))
                    e.var("jr_mark", e.hd(H_ARENA))
                    e.var("jr_T", _call(e, "an_bshl", p["jr_B"], p["jr_i"]))
                    e.if_(e.ne(_call(e, "an_bcmp", p["jr_T"], p["jr_R"]), 2), lambda: (
                        _call(e, "an_bsub", p["jr_R"], p["jr_T"]), e.set("jr_q", e.add(p["jr_q"], p["jr_pw"]))))
                    e.set_hd(H_ARENA, p["jr_mark"])
                    e.set("jr_pw", e.udiv(p["jr_pw"], 2))

                e.for_("jr_j", 0, e.add(p["jr_s"], 1), step)

            e.if_(e.le(p["jr_bb"], p["jr_ba"]), bits)
            e.set("jr_go", 0)
            e.if_(e.le(1 << 53, p["jr_q"]), lambda: (e.set("jr_e", e.add(p["jr_e"], 1)), e.set("jr_go", 1)))

        e.var("jr_A", 0)
        e.while_(lambda: e.ne(p["jr_go"], 0), divide)
        e.var("jr_R2", _call(e, "an_bshl", p["jr_R"], 1))
        e.var("jr_c", _call(e, "an_bcmp", p["jr_R2"], p["jr_B"]))
        e.if_(e.either(e.eq(p["jr_c"], 2), e.both(e.eq(p["jr_c"], 1), e.eq(e.and_(p["jr_q"], 1), 1))), lambda: e.set("jr_q", e.add(p["jr_q"], 1)))
        e.if_(e.eq(p["jr_q"], 1 << 53), lambda: (e.set("jr_q", 1 << 52), e.set("jr_e", e.add(p["jr_e"], 1))))
        e.if_(e.eq(p["jr_q"], 0), lambda: result(0, 0, E_BIAS))
        e.if_(e.lt(E_BIAS + 971, p["jr_e"]), lambda: result(1, 0, E_BIAS))
        result(0, p["jr_q"], p["jr_e"])
    return _function(("node", "dg", "x"), build, tables)


# -- Python's rules over the nodes -------------------------------------------------------------------------------------------

def _jmag_fn(tables):
    """The magnitude of number node ``v`` (an integer, a boolean or a finite float) as a new number."""
    def build(e: E):
        p = e.p
        e.var("jm_t", at(e, p["v"], 0))
        e.if_(e.eq(p["jm_t"], 6), lambda: e.give(_bnew(e, "jm_b", 0, at(e, p["v"], 1))))
        e.if_(e.eq(p["jm_t"], 5), lambda: e.give(_bnew(e, "jm_f", 0, at(e, p["v"], 3))))
        e.give(_call(e, "an_bdigits", e.add(p["v"], 2), 1, at(e, p["v"], 2), 0))
    return _function(("v",), build, tables)


def _jcmp_fn(tables):
    """Python's comparison of number nodes ``a`` and ``b``: 0, 1 or 2 as ``a`` is below, equal to or above ``b``, 3 when
    either is NaN; another value declines (a ``TypeError``)."""
    def build(e: E):
        p = e.p
        for name in ("a", "b"):
            e.var(f"jc_{name}t", at(e, p[name], 0))
            _ok(e, e.either(e.eq(p[f"jc_{name}t"], 2), e.eq(p[f"jc_{name}t"], 5), e.eq(p[f"jc_{name}t"], 6)))
        nan = lambda v, t: e.both(e.eq(t, 5), e.eq(at(e, v, 1), 2))  # noqa: E731
        e.if_(e.either(nan(p["a"], p["jc_at"]), nan(p["b"], p["jc_bt"])), lambda: e.give(3))

        def rank(name):
            """0 minus infinity, 1 negative, 2 zero, 3 positive, 4 infinity."""
            v, t = p[name], p[f"jc_{name}t"]
            zero = e.sel(e.eq(t, 6), e.flag(e.eq(at(e, v, 1), 0)), e.sel(e.eq(t, 5), e.flag(e.eq(at(e, v, 3), 0)),
                                                                          e.flag(e.both(e.eq(at(e, v, 2), 1), e.eq(at(e, v, 3), 0)))))
            neg = e.sel(e.eq(t, 6), 0, e.sel(e.eq(t, 5), at(e, v, 2), at(e, v, 1)))
            finite = e.sel(e.ne(zero, 0), 2, e.sel(e.ne(neg, 0), 1, 3))
            e.var(f"jc_{name}r", e.sel(e.both(e.eq(t, 5), e.eq(at(e, v, 1), 1)), e.sel(e.ne(neg, 0), 0, 4), finite))
            e.var(f"jc_{name}e", e.sel(e.eq(t, 5), at(e, v, 4), E_BIAS))

        rank("a")
        rank("b")
        e.if_(e.ne(p["jc_ar"], p["jc_br"]), lambda: e.give(e.sel(e.lt(p["jc_ar"], p["jc_br"]), 0, 2)))
        e.if_(e.both(e.ne(p["jc_ar"], 1), e.ne(p["jc_ar"], 3)), lambda: e.give(1))
        e.var("jc_mark", e.hd(H_ARENA))
        e.var("jc_ma", _call(e, "an_jmag", p["a"]))
        e.var("jc_mb", _call(e, "an_jmag", p["b"]))
        e.if_(e.lt(p["jc_be"], p["jc_ae"]), lambda: e.set("jc_ma", _call(e, "an_bshl", p["jc_ma"], e.sub(p["jc_ae"], p["jc_be"]))),
              lambda: e.set("jc_mb", _call(e, "an_bshl", p["jc_mb"], e.sub(p["jc_be"], p["jc_ae"]))))
        e.var("jc_c", _call(e, "an_bcmp", p["jc_ma"], p["jc_mb"]))
        e.set_hd(H_ARENA, p["jc_mark"])
        e.give(e.sel(e.eq(p["jc_ar"], 1), e.sub(2, p["jc_c"]), p["jc_c"]))
    return _function(("a", "b"), build, tables)


def _jint_fn(tables):
    """``int(v)`` of number node ``v`` when it is in ``[0, 2 ** 62)``; another value declines."""
    def build(e: E):
        p = e.p
        e.var("ji_t", at(e, p["v"], 0))
        e.if_(e.eq(p["ji_t"], 6), lambda: e.give(at(e, p["v"], 1)))

        def integer():
            _ok(e, e.both(e.eq(at(e, p["v"], 1), 0), e.le(at(e, p["v"], 2), 18)))
            e.var("ji_v", 0)
            e.for_("ji_k", 0, at(e, p["v"], 2), lambda: e.set("ji_v", e.add(e.mul(p["ji_v"], 10), at(e, p["v"], e.add(3, p["ji_k"])))))
            e.give(p["ji_v"])

        e.if_(e.eq(p["ji_t"], 2), integer)
        _ok(e, e.both(e.eq(p["ji_t"], 5), e.eq(at(e, p["v"], 1), 0)))
        e.var("ji_q", at(e, p["v"], 3))
        e.var("ji_e", at(e, p["v"], 4))
        _ok(e, e.either(e.eq(at(e, p["v"], 2), 0), e.eq(p["ji_q"], 0)))  # a negative float truncates below zero

        def up():
            e.var("ji_s", e.sub(p["ji_e"], E_BIAS))
            _ok(e, e.le(p["ji_s"], 9))
            e.for_("ji_u", 0, p["ji_s"], lambda: e.set("ji_q", e.mul(p["ji_q"], 2)))
            e.give(p["ji_q"])

        e.if_(e.le(E_BIAS, p["ji_e"]), up)
        e.var("ji_d", e.sub(E_BIAS, p["ji_e"]))
        e.if_(e.le(64, p["ji_d"]), lambda: e.give(0))
        e.for_("ji_w", 0, p["ji_d"], lambda: e.set("ji_q", e.udiv(p["ji_q"], 2)))
        e.give(p["ji_q"])
    return _function(("v",), build, tables)


def _jconst_fn(tables):
    """An integer node of ``v`` (below 10 ** 18)."""
    def build(e: E):
        p = e.p
        e.var("jk_nd", 1)
        e.var("jk_t", p["v"])
        e.while_(lambda: e.le(10, p["jk_t"]), lambda: (e.set("jk_t", e.udiv(p["jk_t"], 10)), e.set("jk_nd", e.add(p["jk_nd"], 1))))
        e.var("jk_h", e.alloc(e.add(p["jk_nd"], 3)))
        _ok(e, e.ne(p["jk_h"], NONE))
        e.st(p["jk_h"], 2)
        e.st(e.add(p["jk_h"], 1), 0)
        e.st(e.add(p["jk_h"], 2), p["jk_nd"])
        e.set("jk_t", p["v"])
        e.for_("jk_q", 0, p["jk_nd"], lambda: (e.st(e.add(p["jk_h"], e.sub(e.add(2, p["jk_nd"]), p["jk_q"])), e.urem(p["jk_t"], 10)),
                                                e.set("jk_t", e.udiv(p["jk_t"], 10))))
        e.give(p["jk_h"])
    return _function(("v",), build, tables)


def _jiter_fn(tables):
    """``iter(v)``'s items as an array node: an array's items, a string's characters (each a string), an object's keys
    (once each, in first-seen order); another value declines (a ``TypeError``)."""
    def build(e: E):
        p = e.p
        e.var("jt_t", at(e, p["v"], 0))
        e.if_(e.eq(p["jt_t"], 3), lambda: e.give(p["v"]))

        def string():
            e.var("jt_n", at(e, p["v"], 1))
            e.var("jt_out", e.alloc(e.add(p["jt_n"], 2)))
            _ok(e, e.ne(p["jt_out"], NONE))
            e.var("jt_m", 0)
            e.var("jt_k", 0)

            def char():
                e.var("jt_len", _utf8_length(e, at(e, p["v"], e.add(2, p["jt_k"]))))
                e.var("jt_c", e.alloc(e.add(p["jt_len"], 2)))
                _ok(e, e.ne(p["jt_c"], NONE))
                e.st(p["jt_c"], 1)
                e.st(e.add(p["jt_c"], 1), p["jt_len"])
                e.for_("jt_b", 0, p["jt_len"], lambda: e.st(e.add(e.add(p["jt_c"], 2), p["jt_b"]), at(e, p["v"], e.add(e.add(2, p["jt_k"]), p["jt_b"]))))
                e.st(e.add(e.add(p["jt_out"], 2), p["jt_m"]), p["jt_c"])
                e.set("jt_m", e.add(p["jt_m"], 1))
                e.set("jt_k", e.add(p["jt_k"], p["jt_len"]))

            e.while_(lambda: e.lt(p["jt_k"], p["jt_n"]), char)
            e.st(p["jt_out"], 3)
            e.st(e.add(p["jt_out"], 1), p["jt_m"])
            e.give(p["jt_out"])

        e.if_(e.eq(p["jt_t"], 1), string)
        _ok(e, e.eq(p["jt_t"], 4))
        e.var("jt_out", e.alloc(e.add(at(e, p["v"], 1), 2)))
        _ok(e, e.ne(p["jt_out"], NONE))
        e.var("jt_m", 0)

        def key():
            e.var("jt_key", at(e, p["v"], e.add(2, e.mul(p["jt_q"], 2))))
            e.var("jt_new", 1)
            e.for_("jt_j", 0, p["jt_m"], lambda: e.if_(
                e.ne(e.call(_FN["an_same"], e.add(at(e, p["jt_out"], e.add(2, p["jt_j"])), 1), e.add(p["jt_key"], 1)), 0), lambda: e.set("jt_new", 0)))
            e.if_(e.ne(p["jt_new"], 0), lambda: (e.st(e.add(e.add(p["jt_out"], 2), p["jt_m"]), p["jt_key"]), e.set("jt_m", e.add(p["jt_m"], 1))))

        e.for_("jt_q", 0, at(e, p["v"], 1), key)
        e.st(p["jt_out"], 3)
        e.st(e.add(p["jt_out"], 1), p["jt_m"])
        e.give(p["jt_out"])
    return _function(("v",), build, tables)


def _jtruth_fn(tables):
    """``bool(v)``."""
    def build(e: E):
        p = e.p
        e.var("jb_t", at(e, p["v"], 0))
        e.if_(e.eq(p["jb_t"], 2), lambda: e.give(e.flag(e.not_(e.both(e.eq(at(e, p["v"], 2), 1), e.eq(at(e, p["v"], 3), 0))))))
        e.if_(e.eq(p["jb_t"], 5), lambda: e.give(e.flag(e.either(e.ne(at(e, p["v"], 1), 0), e.ne(at(e, p["v"], 3), 0)))))
        e.if_(e.eq(p["jb_t"], 7), lambda: e.give(0))
        e.give(e.flag(e.ne(at(e, p["v"], 1), 0)))  # a string's, array's or object's length, a boolean's value
    return _function(("v",), build, tables)


def _jin_fn(tables):
    """``k in v`` for plain handle ``k`` (an ASCII text): a substring of a string, an array's item, an object's key;
    another value declines (a ``TypeError``)."""
    def build(e: E):
        p = e.p
        e.var("jn_t", at(e, p["v"], 0))
        same = lambda node: e.both(e.eq(at(e, node, 0), 1), e.ne(e.call(_FN["an_same"], e.add(node, 1), p["k"]), 0))  # noqa: E731

        def string():
            e.var("ji_n", at(e, p["v"], 1))
            e.var("ji_m", e.ld(p["k"]))
            e.if_(e.lt(p["ji_n"], p["ji_m"]), lambda: e.give(0))

            def at_(s):
                e.var("ji_same", 1)
                e.for_("ji_r", 0, p["ji_m"], lambda: e.if_(e.ne(at(e, p["v"], e.add(e.add(2, s), p["ji_r"])), at(e, p["k"], e.add(p["ji_r"], 1))),
                                                         lambda: e.set("ji_same", 0)))
                e.if_(e.ne(p["ji_same"], 0), lambda: e.give(1))

            e.for_("ji_s", 0, e.add(e.sub(p["ji_n"], p["ji_m"]), 1), lambda: at_(p["ji_s"]))
            e.give(0)

        e.if_(e.eq(p["jn_t"], 1), string)
        e.if_(e.eq(p["jn_t"], 3), lambda: (e.for_("ji_a", 0, at(e, p["v"], 1), lambda: e.if_(same(at(e, p["v"], e.add(2, p["ji_a"]))), lambda: e.give(1))),
                                         e.give(0)))
        _ok(e, e.eq(p["jn_t"], 4))
        e.for_("ji_o", 0, at(e, p["v"], 1), lambda: e.if_(same(at(e, p["v"], e.add(2, e.mul(p["ji_o"], 2)))), lambda: e.give(1)))
        e.give(0)
    return _function(("v", "k"), build, tables)


def _jget_fn(tables):
    """The value of the last pair of object node ``o`` whose key is handle ``k``'s text (``json.loads`` keeps the last
    duplicate), or NONE: not a decline."""
    def build(e: E):
        p = e.p
        e.var("jg_v", NONE)
        e.for_("jg_q", 0, at(e, p["o"], 1), lambda: e.if_(
            e.ne(e.call(_FN["an_same"], e.add(at(e, p["o"], e.add(2, e.mul(p["jg_q"], 2))), 1), p["k"]), 0),
            lambda: e.set("jg_v", at(e, p["o"], e.add(3, e.mul(p["jg_q"], 2))))))
        e.give(p["jg_v"])
    return _function(("o", "k"), build, tables)


def _jhex_fn(tables):
    """``bytes.fromhex`` of node ``s`` (a string; ASCII whitespace between bytes skipped) when it gives 32 bytes: their
    handle; anything else declines (a ``TypeError`` or ``ValueError``)."""
    def build(e: E):
        p = e.p
        _ok(e, e.eq(at(e, p["s"], 0), 1))
        e.var("jx_n", at(e, p["s"], 1))
        e.var("jx_h", e.alloc(e.add(e.udiv(p["jx_n"], 2), 2)))
        _ok(e, e.ne(p["jx_h"], NONE))
        e.var("jx_m", 0)
        e.var("jx_i", 0)
        byte = lambda k: e.sel(e.lt(k, p["jx_n"]), at(e, p["s"], e.add(2, e.sel(e.lt(k, p["jx_n"]), k, 0))), 256)  # noqa: E731

        def step():
            e.var("jx_c", byte(p["jx_i"]))

            def pair():
                e.var("jx_hi", _hexval(e, p["jx_c"]))
                e.var("jx_lo", _hexval(e, byte(e.add(p["jx_i"], 1))))
                _ok(e, e.both(e.ne(p["jx_hi"], NONE), e.ne(p["jx_lo"], NONE)))
                e.st(e.add(e.add(p["jx_h"], 1), p["jx_m"]), e.add(e.mul(p["jx_hi"], 16), p["jx_lo"]))
                e.set("jx_m", e.add(p["jx_m"], 1))
                e.set("jx_i", e.add(p["jx_i"], 2))

            e.if_(e.either(*(e.eq(p["jx_c"], c) for c in HEX_SPACE)), lambda: e.set("jx_i", e.add(p["jx_i"], 1)), pair)

        e.while_(lambda: e.lt(p["jx_i"], p["jx_n"]), step)
        _ok(e, e.eq(p["jx_m"], 32))  # ``LibxposedJvmModule``'s ValueError
        e.st(p["jx_h"], 32)
        e.give(p["jx_h"])
    return _function(("s",), build, tables)


def _jsurrogate_fn(tables):
    """1 when plain handle ``h`` (a string's bytes) holds a surrogate, which ``str.encode("utf-8")`` refuses."""
    def build(e: E):
        p = e.p
        e.for_("jg_k", 1, e.ld(p["h"]), lambda: e.if_(e.both(e.eq(at(e, p["h"], p["jg_k"]), 0xED), e.le(0xA0, at(e, p["h"], e.add(p["jg_k"], 1)))),
                                                      lambda: e.give(1)))
        e.give(0)
    return _function(("h",), build, tables)


def _u16put_fn(tables):
    """Plain handle ``h``'s text (each code point encoded as UTF-8) as a layer's string: its UTF-16 unit count, then the
    units (``surrogatepass``: a surrogate is its own unit)."""
    def build(e: E):
        p = e.p
        e.var("uu_n", e.ld(p["h"]))
        e.var("uu_units", 0)
        e.var("uu_k", 1)
        e.while_(lambda: e.le(p["uu_k"], p["uu_n"]), lambda: (
            e.var("uu_b", at(e, p["h"], p["uu_k"])), e.set("uu_units", e.add(p["uu_units"], e.sel(e.le(0xF0, p["uu_b"]), 2, 1))),
            e.set("uu_k", e.add(p["uu_k"], _utf8_length(e, p["uu_b"])))))
        _call(e, "an_put", p["uu_units"])
        e.set("uu_k", 1)

        def char():
            e.var("uu_b", at(e, p["h"], p["uu_k"]))
            e.var("uu_len", _utf8_length(e, p["uu_b"]))
            e.var("uu_cp", e.and_(p["uu_b"], e.sel(e.eq(p["uu_len"], 1), 0x7F, e.sel(e.eq(p["uu_len"], 2), 0x1F, e.sel(e.eq(p["uu_len"], 3), 0x0F, 0x07)))))
            e.for_("uu_j", 1, p["uu_len"], lambda: e.set("uu_cp", e.add(e.mul(p["uu_cp"], 64), e.and_(at(e, p["h"], e.add(p["uu_k"], p["uu_j"])), 0x3F))))
            e.if_(e.lt(p["uu_cp"], 0x10000), lambda: _call(e, "an_put", p["uu_cp"]), lambda: (
                _call(e, "an_put", e.add(0xD800, e.udiv(e.sub(p["uu_cp"], 0x10000), 1024))),
                _call(e, "an_put", e.add(0xDC00, e.and_(e.sub(p["uu_cp"], 0x10000), 1023)))))
            e.set("uu_k", e.add(p["uu_k"], p["uu_len"]))

        e.while_(lambda: e.le(p["uu_k"], p["uu_n"]), char)
        e.give(1)
    return _function(("h",), build, tables)


# -- stored ZIP archives (the JVM program's JAR, the branding archive), read as ``zipfile`` reads them -----------------------

def _pbyte(e: E, h, k):
    """Byte ``k`` of a packed record handle ``[length, words...]``."""
    return e.and_(e.udiv(at(e, h, e.add(1, e.udiv(k, 8))), _shift8(e, e.urem(k, 8))), 255)


def _shift8(e: E, j):
    """``256 ** j`` for ``j`` in 0..7."""
    result = e.c(1)
    for q in range(1, 8):
        result = e.sel(e.eq(j, q), 1 << (8 * q), result)
    return result


def _pfield(e: E, h, at_, n: int):
    value = e.c(0)
    for k in reversed(range(n)):
        value = e.add(e.mul(value, 256), _pbyte(e, h, e.add(at_, k)))
    return value


def _crc_fn(tables):
    """The CRC-32 of ``n`` bytes of packed handle ``h`` from byte ``start``."""
    def build(e: E):
        p = e.p
        e.var("cr_c", 0xFFFFFFFF)

        def byte():
            e.set("cr_c", e.bin(Operation.BIT_XOR, p["cr_c"], _pbyte(e, p["h"], e.add(p["start"], p["cr_k"]))))
            for _ in range(8):
                e.set("cr_c", e.sel(e.eq(e.and_(p["cr_c"], 1), 1), e.bin(Operation.BIT_XOR, e.udiv(p["cr_c"], 2), 0xEDB88320), e.udiv(p["cr_c"], 2)))

        e.for_("cr_k", 0, p["n"], byte)
        e.give(e.bin(Operation.BIT_XOR, p["cr_c"], 0xFFFFFFFF))
    return _function(("h", "start", "n"), build, tables)


ZIP_WORDS = 6  # an entry: its name handle, its data's first byte, its size, its method (0 stored, 8 deflated), its compressed size, its CRC-32


def _zip_fn(tables):
    """The entries of the ZIP archive in packed handle ``h``, in central-directory order (``infolist``): ``[n, (name,
    start, size, method, compressed size, CRC)...]``.  Anything ``zipfile`` would read differently or refuse (ZIP64, more
    disks, encryption, patched data, a method other than stored, deflated, bzip2 and LZMA (S15e.6i.3), a local header unlike
    the central one, a stored entry's CRC mismatch, a non-ASCII name) declines; a compressed entry's data is checked when it
    is read (``an_entry_bytes``)."""
    def build(e: E):
        p = e.p
        e.var("zp_len", e.ld(p["h"]))
        _ok(e, e.le(22, p["zp_len"]))
        e.var("zp_min", e.sel(e.lt(65557, p["zp_len"]), e.sub(p["zp_len"], 65557), 0))
        e.var("zp_end", NONE)
        e.var("zp_k", e.sub(p["zp_len"], 22))
        e.while_(lambda: e.both(e.eq(p["zp_end"], NONE), e.le(p["zp_min"], p["zp_k"])), lambda: (
            e.if_(e.eq(_pfield(e, p["h"], p["zp_k"], 4), 0x06054B50), lambda: e.set("zp_end", p["zp_k"])),
            e.if_(e.eq(p["zp_k"], 0), lambda: e.set("zp_min", 1), lambda: e.set("zp_k", e.sub(p["zp_k"], 1)))))
        _ok(e, e.ne(p["zp_end"], NONE))
        end = p["zp_end"]
        _ok(e, e.eq(e.add(e.add(end, 22), _pfield(e, p["h"], e.add(end, 20), 2)), p["zp_len"]))  # the comment reaches the end
        _ok(e, e.both(e.eq(_pfield(e, p["h"], e.add(end, 4), 2), 0), e.eq(_pfield(e, p["h"], e.add(end, 6), 2), 0)))
        e.var("zp_n", _pfield(e, p["h"], e.add(end, 10), 2))
        _ok(e, e.eq(_pfield(e, p["h"], e.add(end, 8), 2), p["zp_n"]))
        e.var("zp_cd", _pfield(e, p["h"], e.add(end, 16), 4))
        _ok(e, e.both(e.ne(p["zp_n"], 0xFFFF), e.lt(p["zp_cd"], 0xFFFFFFFF)))
        _ok(e, e.eq(e.add(p["zp_cd"], _pfield(e, p["h"], e.add(end, 12), 4)), end))  # no data before the archive
        e.var("zp_out", e.alloc(e.add(e.mul(p["zp_n"], ZIP_WORDS), 1)))
        _ok(e, e.ne(p["zp_out"], NONE))
        e.st(p["zp_out"], p["zp_n"])
        e.var("zp_at", p["zp_cd"])

        def entry():
            a = p["zp_at"]
            _ok(e, e.le(e.add(a, 46), end))
            _ok(e, e.eq(_pfield(e, p["h"], a, 4), 0x02014B50))
            e.var("ze_flags", _pfield(e, p["h"], e.add(a, 8), 2))
            _ok(e, e.eq(e.and_(p["ze_flags"], 0x61), 0))  # encrypted, patched data, strong encryption
            e.var("ze_method", _pfield(e, p["h"], e.add(a, 10), 2))
            _ok(e, e.either(*(e.eq(p["ze_method"], m) for m in (0, 8, 12, 14))))  # stored, deflated, bzip2 or LZMA
            e.var("ze_crc", _pfield(e, p["h"], e.add(a, 16), 4))
            e.var("ze_csize", _pfield(e, p["h"], e.add(a, 20), 4))
            e.var("ze_size", _pfield(e, p["h"], e.add(a, 24), 4))
            _ok(e, e.both(e.ne(p["ze_size"], 0xFFFFFFFF), e.ne(p["ze_csize"], 0xFFFFFFFF)))
            _ok(e, e.either(e.ne(p["ze_method"], 0), e.eq(p["ze_csize"], p["ze_size"])))
            e.var("ze_nl", _pfield(e, p["h"], e.add(a, 28), 2))
            e.var("ze_el", _pfield(e, p["h"], e.add(a, 30), 2))
            e.var("ze_cl", _pfield(e, p["h"], e.add(a, 32), 2))
            e.var("ze_local", _pfield(e, p["h"], e.add(a, 42), 4))
            e.var("ze_next", e.add(e.add(e.add(a, 46), p["ze_nl"]), e.add(p["ze_el"], p["ze_cl"])))
            _ok(e, e.le(p["ze_next"], end))
            e.var("ze_name", e.alloc(e.add(p["ze_nl"], 1)))
            _ok(e, e.ne(p["ze_name"], NONE))
            e.st(p["ze_name"], p["ze_nl"])
            e.for_("ze_q", 0, p["ze_nl"], lambda: (e.var("ze_c", _pbyte(e, p["h"], e.add(e.add(a, 46), p["ze_q"]))), _ok(e, e.lt(p["ze_c"], 0x80)),
                                                   e.st(e.add(e.add(p["ze_name"], 1), p["ze_q"]), p["ze_c"])))
            # The local header: its signature and name; the data follows its extra field.
            l = p["ze_local"]  # noqa: E741
            _ok(e, e.le(e.add(l, 30), p["zp_cd"]))
            _ok(e, e.eq(_pfield(e, p["h"], l, 4), 0x04034B50))
            _ok(e, e.eq(_pfield(e, p["h"], e.add(l, 26), 2), p["ze_nl"]))
            e.for_("ze_r", 0, p["ze_nl"], lambda: _ok(e, e.eq(_pbyte(e, p["h"], e.add(e.add(l, 30), p["ze_r"])), at(e, p["ze_name"], e.add(p["ze_r"], 1)))))
            e.var("ze_data", e.add(e.add(e.add(l, 30), p["ze_nl"]), _pfield(e, p["h"], e.add(l, 28), 2)))
            _ok(e, e.le(e.add(p["ze_data"], p["ze_csize"]), p["zp_cd"]))
            e.if_(e.eq(p["ze_method"], 0), lambda: _ok(e, e.eq(e.call(_FN["an_crc"], p["h"], p["ze_data"], p["ze_size"]), p["ze_crc"])))
            slot = e.add(e.add(p["zp_out"], 1), e.mul(p["zq"], ZIP_WORDS))
            for j, name in enumerate(("ze_name", "ze_data", "ze_size", "ze_method", "ze_csize", "ze_crc")):
                e.st(e.add(slot, j), p[name])
            e.set("zp_at", p["ze_next"])

        e.for_("zq", 0, p["zp_n"], entry)
        e.give(p["zp_out"])
    return _function(("h",), build, tables)


# -- S15e.6i.3 (ADR-359): deflated entries, read as ``zipfile`` reads them (``zlib.decompressobj(-15)``) ---------------------
# ``ZipExtFile.read`` hands the entry's ``compress_size`` bytes to raw inflate in one call, keeps the first ``file_size``
# bytes of what it gives and checks their CRC-32.  Inflate stops at the end of the final block, ignoring what follows;
# when the input ends first it gives what it decoded so far, as zlib does, so the data is that output.  Each zlib
# error (a bad block type, stored lengths, code lengths, a code, a distance too far back) declines, at the bit zlib
# finds it.  The bit reader's state and the output are globals, so that every stop ends in ``an_zfinish``.
Z_H, Z_POS, Z_END, Z_BUF, Z_CNT, Z_W = CO_AT + 32, CO_AT + 33, CO_AT + 34, CO_AT + 35, CO_AT + 36, CO_AT + 37
Z_OUT, Z_RING, Z_TOTAL, Z_FSIZE, Z_CRC = CO_AT + 38, CO_AT + 39, CO_AT + 40, CO_AT + 41, CO_AT + 42
Z_STOP = 1 << 40  # ``an_zbits``' result when the input ends
Z_WINDOW = 1 << 15
Z_MAX_OUT = (1 << 31) - 1  # ``ZipExtFile.MAX_N``: one decompress call gives at most this much
LENGTH_BASE = (3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258)
LENGTH_EXTRA = (0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0)
DIST_BASE = (1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193,
             12289, 16385, 24577)
DIST_EXTRA = (0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13)
CODE_ORDER = (16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15)
Z_TABLES = (*LENGTH_BASE, *LENGTH_EXTRA, *DIST_BASE, *DIST_EXTRA, *CODE_ORDER)
Z_LB, Z_LE, Z_DB, Z_DE, Z_CO = 0, 29, 58, 88, 118  # their offsets in the constant block


def _zbits_fn(tables):
    """The next ``n`` bits (at most 16) of the input, least significant first, or ``Z_STOP`` when it ends."""
    def build(e: E):
        p = e.p

        def load():
            e.if_(e.le(e.ld(Z_END), e.ld(Z_POS)), lambda: e.give(Z_STOP))
            e.st(Z_BUF, e.add(e.ld(Z_BUF), e.mul(_pbyte(e, e.ld(Z_H), e.ld(Z_POS)), e.ld(Z_W))))
            e.st(Z_W, e.mul(e.ld(Z_W), 256))
            e.st(Z_CNT, e.add(e.ld(Z_CNT), 8))
            e.st(Z_POS, e.add(e.ld(Z_POS), 1))

        e.while_(lambda: e.lt(e.ld(Z_CNT), p["n"]), load)
        e.var("zb_pw", 1)
        e.for_("zb_k", 0, p["n"], lambda: e.set("zb_pw", e.mul(p["zb_pw"], 2)))
        e.var("zb_v", e.urem(e.ld(Z_BUF), p["zb_pw"]))
        e.st(Z_BUF, e.udiv(e.ld(Z_BUF), p["zb_pw"]))
        e.st(Z_W, e.udiv(e.ld(Z_W), p["zb_pw"]))
        e.st(Z_CNT, e.sub(e.ld(Z_CNT), p["n"]))
        e.give(p["zb_v"])
    return _function(("n",), build, tables)


def _zfinish_fn(tables):
    """The output as ``ZipExtFile.read`` returns it: its first ``file_size`` bytes, one per word, when their CRC-32 is the
    entry's (else ``BadZipFile``: declined)."""
    def build(e: E):
        p = e.p
        e.var("zf_out", e.ld(Z_OUT))
        e.var("zf_m", e.sel(e.lt(e.ld(Z_TOTAL), e.ld(Z_FSIZE)), e.ld(Z_TOTAL), e.ld(Z_FSIZE)))
        e.st(p["zf_out"], p["zf_m"])
        e.var("zf_c", 0xFFFFFFFF)

        def byte():
            e.set("zf_c", e.bin(Operation.BIT_XOR, p["zf_c"], at(e, p["zf_out"], e.add(p["zf_k"], 1))))
            for _ in range(8):
                e.set("zf_c", e.sel(e.eq(e.and_(p["zf_c"], 1), 1), e.bin(Operation.BIT_XOR, e.udiv(p["zf_c"], 2), 0xEDB88320), e.udiv(p["zf_c"], 2)))

        e.for_("zf_k", 0, p["zf_m"], byte)
        _ok(e, e.eq(e.bin(Operation.BIT_XOR, p["zf_c"], 0xFFFFFFFF), e.ld(Z_CRC)))
        e.give(p["zf_out"])
    return _function((), build, tables)


def _zemit_fn(tables):
    """One output byte: into the window, and kept while within ``file_size``; 2 once the output reaches ``Z_MAX_OUT``."""
    def build(e: E):
        p = e.p
        e.var("ze_t", e.ld(Z_TOTAL))
        e.st(e.add(e.ld(Z_RING), e.and_(p["ze_t"], Z_WINDOW - 1)), p["b"])
        e.if_(e.lt(p["ze_t"], e.ld(Z_FSIZE)), lambda: e.st(e.add(e.add(e.ld(Z_OUT), 1), p["ze_t"]), p["b"]))
        e.st(Z_TOTAL, e.add(p["ze_t"], 1))
        e.give(e.sel(e.le(Z_MAX_OUT, e.add(p["ze_t"], 1)), 2, 1))
    return _function(("b",), build, tables)


def _zbuild_fn(tables):
    """``inflate_table``'s checks and a canonical code of the ``n`` lengths at word ``base``: ``[max length, count per
    length (16), symbols by code]``.  Over-subscribed lengths decline, and so do incomplete ones unless the code has one
    length-1 symbol and is not the code-length code (``codes``); a code with no symbol is kept (``max`` 0)."""
    def build(e: E):
        p = e.p
        e.var("zt_t", e.alloc(e.add(p["n"], 34)))
        _ok(e, e.ne(p["zt_t"], NONE))
        t = p["zt_t"]
        e.for_("zt_z", 0, 16, lambda: e.st(e.add(e.add(t, 1), p["zt_z"]), 0))
        e.for_("zt_i", 0, p["n"], lambda: (e.var("zt_l", e.ld(e.add(p["base"], p["zt_i"]))),
                                           e.st(e.add(e.add(t, 1), p["zt_l"]), e.add(at(e, t, e.add(1, p["zt_l"])), 1))))
        e.st(e.add(t, 1), 0)
        e.var("zt_max", 0)
        e.for_("zt_m", 1, 16, lambda: e.if_(e.ne(at(e, t, e.add(1, p["zt_m"])), 0), lambda: e.set("zt_max", p["zt_m"])))
        e.st(t, p["zt_max"])
        e.if_(e.eq(p["zt_max"], 0), lambda: e.give(t))
        e.var("zt_left", 1)
        e.for_("zt_len", 1, 16, lambda: (e.var("zt_c", at(e, t, e.add(1, p["zt_len"]))), e.set("zt_left", e.mul(p["zt_left"], 2)),
                                         _ok(e, e.le(p["zt_c"], p["zt_left"])), e.set("zt_left", e.sub(p["zt_left"], p["zt_c"]))))
        _ok(e, e.either(e.eq(p["zt_left"], 0), e.both(e.eq(p["codes"], 0), e.eq(p["zt_max"], 1))))
        # The symbols ordered by length, then by value (``offs``, in the table's tail).
        offs = e.add(e.add(t, 17), p["n"])
        e.st(e.add(offs, 1), 0)
        e.for_("zt_o", 1, 15, lambda: e.st(e.add(offs, e.add(p["zt_o"], 1)), e.add(e.ld(e.add(offs, p["zt_o"])), at(e, t, e.add(1, p["zt_o"])))))
        e.for_("zt_s", 0, p["n"], lambda: (
            e.var("zt_sl", e.ld(e.add(p["base"], p["zt_s"]))),
            e.if_(e.ne(p["zt_sl"], 0), lambda: (e.st(e.add(e.add(t, 17), e.ld(e.add(offs, p["zt_sl"]))), p["zt_s"]),
                                                e.st(e.add(offs, p["zt_sl"]), e.add(e.ld(e.add(offs, p["zt_sl"])), 1))))))
        e.give(t)
    return _function(("base", "n", "codes"), build, tables)


def _zdecode_fn(tables):
    """The next symbol of code ``t`` read bit by bit (``Z_STOP`` when the input ends).  A code no symbol has declines once
    ``max(1, max length)`` bits are read; the code-length code with no symbol (``quirk``) reads one bit as symbol 0, as
    zlib's table does."""
    def build(e: E):
        p = e.p
        t = p["t"]
        e.var("zd_max", e.ld(t))

        def empty():
            e.var("zd_b", e.call(_FN["an_zbits"], 1))
            e.if_(e.eq(p["zd_b"], Z_STOP), lambda: e.give(Z_STOP))
            _ok(e, e.ne(p["quirk"], 0))
            e.give(0)

        e.if_(e.eq(p["zd_max"], 0), empty)
        e.var("zd_code", 0)
        e.var("zd_first", 0)
        e.var("zd_index", 0)

        def step():
            e.var("zd_bit", e.call(_FN["an_zbits"], 1))
            e.if_(e.eq(p["zd_bit"], Z_STOP), lambda: e.give(Z_STOP))
            e.set("zd_code", e.add(p["zd_code"], p["zd_bit"]))
            e.var("zd_count", at(e, t, e.add(1, p["zd_len"])))
            e.if_(e.lt(p["zd_code"], e.add(p["zd_first"], p["zd_count"])),
                  lambda: e.give(at(e, t, e.add(e.add(17, p["zd_index"]), e.sub(p["zd_code"], p["zd_first"])))))
            e.set("zd_index", e.add(p["zd_index"], p["zd_count"]))
            e.set("zd_first", e.mul(e.add(p["zd_first"], p["zd_count"]), 2))
            e.set("zd_code", e.mul(p["zd_code"], 2))

        e.for_("zd_len", 1, e.add(p["zd_max"], 1), step)
        _ok(e, e.eq(1, 0))  # an invalid code
        e.give(NONE)
    return _function(("t", "quirk"), build, tables)


def _inflate_fn(tables):
    """Raw inflate of ``csize`` bytes of packed handle ``h`` from byte ``start``: ``ZipExtFile.read``'s result (see
    above) for an entry of ``fsize`` bytes and CRC-32 ``crc``, one byte per word."""
    def build(e: E):
        p = e.p
        finish = lambda: e.give(_call(e, "an_zfinish"))  # noqa: E731

        def bits(name, n):
            e.var(name, e.call(_FN["an_zbits"], n))
            e.if_(e.eq(p[name], Z_STOP), finish)
            return p[name]

        def decode(name, table, quirk: int = 0):
            e.var(name, _call(e, "an_zdecode", table, quirk))
            e.if_(e.eq(p[name], Z_STOP), finish)
            return p[name]

        def emit(byte):
            e.if_(e.eq(_call(e, "an_zemit", byte), 2), finish)

        for g, value in ((Z_H, p["h"]), (Z_POS, p["start"]), (Z_END, e.add(p["start"], p["csize"])), (Z_BUF, 0), (Z_CNT, 0), (Z_W, 1),
                         (Z_TOTAL, 0), (Z_FSIZE, p["fsize"]), (Z_CRC, p["crc"])):
            e.st(g, value)
        e.var("zi_out", e.alloc(e.add(p["fsize"], 1)))
        e.var("zi_ring", e.alloc(Z_WINDOW))
        e.var("zi_k", e.alloc(len(Z_TABLES)))
        _ok(e, e.both(e.ne(p["zi_out"], NONE), e.ne(p["zi_ring"], NONE), e.ne(p["zi_k"], NONE)))
        e.st(Z_OUT, p["zi_out"])
        e.st(Z_RING, p["zi_ring"])
        for j, value in enumerate(Z_TABLES):
            e.st(e.add(p["zi_k"], j), value)
        k = lambda offset, i: at(e, p["zi_k"], e.add(offset, i))  # noqa: E731
        e.var("zi_final", 0)
        e.var("zi_lit", 0)
        e.var("zi_dist", 0)

        def fixed():
            e.var("zi_fl", e.alloc(288 + 32))
            _ok(e, e.ne(p["zi_fl"], NONE))
            for lo, hi, length in ((0, 144, 8), (144, 256, 9), (256, 280, 7), (280, 288, 8), (288, 320, 5)):
                e.for_("zi_f", lo, hi, lambda length=length: e.st(e.add(p["zi_fl"], p["zi_f"]), length))
            e.set("zi_lit", _call(e, "an_zbuild", p["zi_fl"], 288, 0))
            e.set("zi_dist", _call(e, "an_zbuild", e.add(p["zi_fl"], 288), 32, 0))

        def dynamic():
            e.var("zi_v", bits("zi_hdr", 14))
            e.var("zi_nlen", e.add(e.and_(p["zi_v"], 31), 257))
            e.var("zi_ndist", e.add(e.and_(e.udiv(p["zi_v"], 32), 31), 1))
            e.var("zi_ncode", e.add(e.udiv(p["zi_v"], 1024), 4))
            _ok(e, e.both(e.le(p["zi_nlen"], 286), e.le(p["zi_ndist"], 30)))  # too many length or distance symbols
            e.var("zi_cl", e.alloc(19))
            e.var("zi_lens", e.alloc(320))
            _ok(e, e.both(e.ne(p["zi_cl"], NONE), e.ne(p["zi_lens"], NONE)))
            e.for_("zi_z", 0, 19, lambda: e.st(e.add(p["zi_cl"], p["zi_z"]), 0))
            e.for_("zi_c", 0, p["zi_ncode"], lambda: e.st(e.add(p["zi_cl"], k(Z_CO, p["zi_c"])), bits("zi_cb", 3)))
            e.var("zi_code", _call(e, "an_zbuild", p["zi_cl"], 19, 1))
            e.var("zi_all", e.add(p["zi_nlen"], p["zi_ndist"]))
            e.var("zi_have", 0)

            def length():
                e.var("zi_sym", decode("zi_ls", p["zi_code"], 1))

                def repeat():
                    e.var("zi_len", 0)
                    e.var("zi_copy", 0)

                    def previous():
                        e.var("zi_x16", bits("zi_r16", 2))
                        _ok(e, e.ne(p["zi_have"], 0))  # invalid bit length repeat
                        e.set("zi_len", e.ld(e.add(p["zi_lens"], e.sub(p["zi_have"], 1))))
                        e.set("zi_copy", e.add(3, p["zi_x16"]))

                    e.if_(e.eq(p["zi_sym"], 16), previous, lambda: e.if_(e.eq(p["zi_sym"], 17), lambda: e.set("zi_copy", e.add(3, bits("zi_r17", 3))),
                                                                       lambda: e.set("zi_copy", e.add(11, bits("zi_r18", 7)))))
                    _ok(e, e.le(e.add(p["zi_have"], p["zi_copy"]), p["zi_all"]))
                    e.for_("zi_rep", 0, p["zi_copy"], lambda: (e.st(e.add(p["zi_lens"], p["zi_have"]), p["zi_len"]), e.set("zi_have", e.add(p["zi_have"], 1))))

                e.if_(e.lt(p["zi_sym"], 16), lambda: (e.st(e.add(p["zi_lens"], p["zi_have"]), p["zi_sym"]), e.set("zi_have", e.add(p["zi_have"], 1))), repeat)

            e.while_(lambda: e.lt(p["zi_have"], p["zi_all"]), length)
            _ok(e, e.ne(e.ld(e.add(p["zi_lens"], 256)), 0))  # missing end-of-block
            e.set("zi_lit", _call(e, "an_zbuild", p["zi_lens"], p["zi_nlen"], 0))
            e.set("zi_dist", _call(e, "an_zbuild", e.add(p["zi_lens"], p["zi_nlen"]), p["zi_ndist"], 0))

        def stored():
            e.var("zi_align", bits("zi_a", e.urem(e.ld(Z_CNT), 8)))
            e.var("zi_n", bits("zi_n16", 16))
            e.var("zi_nn", bits("zi_nn16", 16))
            _ok(e, e.eq(p["zi_n"], e.bin(Operation.BIT_XOR, p["zi_nn"], 0xFFFF)))  # invalid stored block lengths
            e.for_("zi_s", 0, p["zi_n"], lambda: emit(bits("zi_byte", 8)))

        def codes():
            e.var("zi_go", 1)

            def symbol():
                e.var("zi_lsym", decode("zi_lx", p["zi_lit"]))

                def match():
                    e.var("zi_s", e.sub(p["zi_lsym"], 257))
                    _ok(e, e.lt(p["zi_s"], 29))  # invalid literal/length code
                    e.var("zi_ml", e.add(k(Z_LB, p["zi_s"]), bits("zi_lb", k(Z_LE, p["zi_s"]))))
                    e.var("zi_ds", decode("zi_dx", p["zi_dist"]))
                    _ok(e, e.lt(p["zi_ds"], 30))  # invalid distance code
                    e.var("zi_d", e.add(k(Z_DB, p["zi_ds"]), bits("zi_db", k(Z_DE, p["zi_ds"]))))
                    _ok(e, e.le(p["zi_d"], e.ld(Z_TOTAL)))  # invalid distance too far back
                    e.for_("zi_m", 0, p["zi_ml"], lambda: emit(e.ld(e.add(p["zi_ring"], e.and_(e.sub(e.ld(Z_TOTAL), p["zi_d"]), Z_WINDOW - 1)))))

                e.if_(e.lt(p["zi_lsym"], 256), lambda: emit(p["zi_lsym"]), lambda: e.if_(e.eq(p["zi_lsym"], 256), lambda: e.set("zi_go", 0), match))

            e.while_(lambda: e.ne(p["zi_go"], 0), symbol)

        def block():
            e.var("zi_head", bits("zi_h3", 3))
            e.set("zi_final", e.and_(p["zi_head"], 1))
            e.var("zi_type", e.udiv(p["zi_head"], 2))
            _ok(e, e.ne(p["zi_type"], 3))  # invalid block type
            e.var("zi_mark", e.hd(H_ARENA))
            e.if_(e.eq(p["zi_type"], 0), stored, lambda: (e.if_(e.eq(p["zi_type"], 1), fixed, dynamic), codes()))
            e.set_hd(H_ARENA, p["zi_mark"])

        e.while_(lambda: e.eq(p["zi_final"], 0), block)
        finish()
    return _function(("h", "start", "csize", "fsize", "crc"), build, tables)


# -- S15e.6i.3 (ADR-359): bzip2 entries (``bz2.BZ2Decompressor``: libbz2 1.0.8's ``BZ2_bzDecompress``) ----------------------
# The stream is read as ``decompress.c`` reads it, with its checks at the same bits: the magics byte by byte, the block
# header, the selectors (at most ``BZ_MAX_SELECTORS`` kept), the delta-coded code lengths, ``hbCreateDecodeTables``' limit,
# base and perm tables, the MTF and RUNA/RUNB symbols, the inverse BWT, the RLE1 output with randomised blocks, and the
# block and stream CRCs.  A block's bytes are output once its symbols are all read, so input that ends inside a block
# gives the blocks before it.  A code that reaches a ``perm`` entry its table did not set reads memory libbz2 never
# initialised: declined.
BZ_RNUMS = (
    619, 720, 127, 481, 931, 816, 813, 233, 566, 247, 985, 724, 205, 454, 863, 491, 741, 242, 949, 214, 733, 859, 335, 708, 621, 574,
    73, 654, 730, 472, 419, 436, 278, 496, 867, 210, 399, 680, 480, 51, 878, 465, 811, 169, 869, 675, 611, 697, 867, 561, 862, 687,
    507, 283, 482, 129, 807, 591, 733, 623, 150, 238, 59, 379, 684, 877, 625, 169, 643, 105, 170, 607, 520, 932, 727, 476, 693, 425,
    174, 647, 73, 122, 335, 530, 442, 853, 695, 249, 445, 515, 909, 545, 703, 919, 874, 474, 882, 500, 594, 612, 641, 801, 220, 162,
    819, 984, 589, 513, 495, 799, 161, 604, 958, 533, 221, 400, 386, 867, 600, 782, 382, 596, 414, 171, 516, 375, 682, 485, 911, 276,
    98, 553, 163, 354, 666, 933, 424, 341, 533, 870, 227, 730, 475, 186, 263, 647, 537, 686, 600, 224, 469, 68, 770, 919, 190, 373,
    294, 822, 808, 206, 184, 943, 795, 384, 383, 461, 404, 758, 839, 887, 715, 67, 618, 276, 204, 918, 873, 777, 604, 560, 951, 160,
    578, 722, 79, 804, 96, 409, 713, 940, 652, 934, 970, 447, 318, 353, 859, 672, 112, 785, 645, 863, 803, 350, 139, 93, 354, 99,
    820, 908, 609, 772, 154, 274, 580, 184, 79, 626, 630, 742, 653, 282, 762, 623, 680, 81, 927, 626, 789, 125, 411, 521, 938, 300,
    821, 78, 343, 175, 128, 250, 170, 774, 972, 275, 999, 639, 495, 78, 352, 126, 857, 956, 358, 619, 580, 124, 737, 594, 701, 612,
    669, 112, 134, 694, 363, 992, 809, 743, 168, 974, 944, 375, 748, 52, 600, 747, 642, 182, 862, 81, 344, 805, 988, 739, 511, 655,
    814, 334, 249, 515, 897, 955, 664, 981, 649, 113, 974, 459, 893, 228, 433, 837, 553, 268, 926, 240, 102, 654, 459, 51, 686, 754,
    806, 760, 493, 403, 415, 394, 687, 700, 946, 670, 656, 610, 738, 392, 760, 799, 887, 653, 978, 321, 576, 617, 626, 502, 894, 679,
    243, 440, 680, 879, 194, 572, 640, 724, 926, 56, 204, 700, 707, 151, 457, 449, 797, 195, 791, 558, 945, 679, 297, 59, 87, 824,
    713, 663, 412, 693, 342, 606, 134, 108, 571, 364, 631, 212, 174, 643, 304, 329, 343, 97, 430, 751, 497, 314, 983, 374, 822, 928,
    140, 206, 73, 263, 980, 736, 876, 478, 430, 305, 170, 514, 364, 692, 829, 82, 855, 953, 676, 246, 369, 970, 294, 750, 807, 827,
    150, 790, 288, 923, 804, 378, 215, 828, 592, 281, 565, 555, 710, 82, 896, 831, 547, 261, 524, 462, 293, 465, 502, 56, 661, 821,
    976, 991, 658, 869, 905, 758, 745, 193, 768, 550, 608, 933, 378, 286, 215, 979, 792, 961, 61, 688, 793, 644, 986, 403, 106, 366,
    905, 644, 372, 567, 466, 434, 645, 210, 389, 550, 919, 135, 780, 773, 635, 389, 707, 100, 626, 958, 165, 504, 920, 176, 193, 713,
    857, 265, 203, 50, 668, 108, 645, 990, 626, 197, 510, 357, 358, 850, 858, 364, 936, 638,
)
BZ_MAX_SELECTORS = 18002
B_GNO, B_GPOS, B_NSEL, B_SEL, B_TAB, B_GROUP, B_RN = CO_AT + 43, CO_AT + 44, CO_AT + 45, CO_AT + 46, CO_AT + 47, CO_AT + 48, CO_AT + 49
BT_LIMIT, BT_BASE, BT_PERM, BT_MIN, BT_PN, BT_WORDS = 0, 6 * 24, 12 * 24, 12 * 24 + 6 * 258, 12 * 24 + 6 * 258 + 6, 12 * 24 + 6 * 258 + 12


def _mbits_fn(tables):
    """The next ``n`` bits (at most 24), most significant first, or ``Z_STOP`` when the input ends."""
    def build(e: E):
        p = e.p

        def load():
            e.if_(e.le(e.ld(Z_END), e.ld(Z_POS)), lambda: e.give(Z_STOP))
            e.st(Z_BUF, e.add(e.mul(e.ld(Z_BUF), 256), _pbyte(e, e.ld(Z_H), e.ld(Z_POS))))
            e.st(Z_CNT, e.add(e.ld(Z_CNT), 8))
            e.st(Z_POS, e.add(e.ld(Z_POS), 1))

        e.while_(lambda: e.lt(e.ld(Z_CNT), p["n"]), load)
        e.var("mb_pw", 1)
        e.for_("mb_k", 0, e.sub(e.ld(Z_CNT), p["n"]), lambda: e.set("mb_pw", e.mul(p["mb_pw"], 2)))
        e.var("mb_v", e.udiv(e.ld(Z_BUF), p["mb_pw"]))
        e.st(Z_BUF, e.urem(e.ld(Z_BUF), p["mb_pw"]))
        e.st(Z_CNT, e.sub(e.ld(Z_CNT), p["n"]))
        e.give(p["mb_v"])
    return _function(("n",), build, tables)


def _bztable_fn(tables):
    """``hbCreateDecodeTables`` for group ``t``'s ``n`` lengths at word ``lens``, into the tables at ``B_TAB`` (signed values
    as 64-bit two's complement); also the group's minimum length and how many ``perm`` entries it set."""
    def build(e: E):
        p = e.p
        tab = e.ld(B_TAB)
        limit = lambda i: e.add(e.add(tab, BT_LIMIT + 0), e.add(e.mul(p["t"], 24), i))  # noqa: E731 - word addresses
        base = lambda i: e.add(e.add(tab, BT_BASE), e.add(e.mul(p["t"], 24), i))  # noqa: E731
        perm = lambda i: e.add(e.add(tab, BT_PERM), e.add(e.mul(p["t"], 258), i))  # noqa: E731
        length = lambda i: e.ld(e.add(p["lens"], i))  # noqa: E731
        e.var("bt_n", p["n"])
        e.var("bt_min", 32)
        e.var("bt_max", 0)
        e.for_("bt_i", 0, p["bt_n"], lambda: (e.if_(e.lt(length(p["bt_i"]), p["bt_min"]), lambda: e.set("bt_min", length(p["bt_i"]))),
                                              e.if_(e.lt(p["bt_max"], length(p["bt_i"])), lambda: e.set("bt_max", length(p["bt_i"])))))
        e.var("bt_pp", 0)
        e.for_("bt_l", p["bt_min"], e.add(p["bt_max"], 1), lambda: e.for_("bt_j", 0, p["bt_n"], lambda: e.if_(
            e.eq(length(p["bt_j"]), p["bt_l"]), lambda: (e.st(perm(p["bt_pp"]), p["bt_j"]), e.set("bt_pp", e.add(p["bt_pp"], 1))))))
        e.for_("bt_z", 0, 23, lambda: e.st(base(p["bt_z"]), 0))
        e.for_("bt_c", 0, p["bt_n"], lambda: e.st(base(e.add(length(p["bt_c"]), 1)), e.add(e.ld(base(e.add(length(p["bt_c"]), 1))), 1)))
        e.for_("bt_s", 1, 23, lambda: e.st(base(p["bt_s"]), e.add(e.ld(base(p["bt_s"])), e.ld(base(e.sub(p["bt_s"], 1))))))
        e.for_("bt_y", 0, 23, lambda: e.st(limit(p["bt_y"]), (1 << 64) - 1))  # -1
        e.var("bt_vec", 0)
        e.for_("bt_v", p["bt_min"], e.add(p["bt_max"], 1), lambda: (
            e.set("bt_vec", e.add(p["bt_vec"], e.sub(e.ld(base(e.add(p["bt_v"], 1))), e.ld(base(p["bt_v"]))))),
            e.st(limit(p["bt_v"]), e.sub(p["bt_vec"], 1)), e.set("bt_vec", e.mul(p["bt_vec"], 2))))
        e.for_("bt_w", e.add(p["bt_min"], 1), e.add(p["bt_max"], 1), lambda: e.st(
            base(p["bt_w"]), e.sub(e.mul(e.add(e.ld(limit(e.sub(p["bt_w"], 1))), 1), 2), e.ld(base(p["bt_w"])))))
        e.st(e.add(e.add(tab, BT_MIN), p["t"]), p["bt_min"])
        e.st(e.add(e.add(tab, BT_PN), p["t"]), p["bt_pp"])
        e.give(1)
    return _function(("t", "lens", "n"), build, tables)


def _bzsym_fn(tables):
    """``GET_MTF_VAL``: the next symbol (``Z_STOP`` when the input ends)."""
    def build(e: E):
        p = e.p
        tab = e.ld(B_TAB)

        def group():
            _ok(e, e.lt(e.ld(B_GNO), e.ld(B_NSEL)))
            e.st(B_GROUP, e.ld(e.add(e.ld(B_SEL), e.ld(B_GNO))))
            e.st(B_GNO, e.add(e.ld(B_GNO), 1))
            e.st(B_GPOS, 50)

        e.if_(e.eq(e.ld(B_GPOS), 0), group)
        e.st(B_GPOS, e.sub(e.ld(B_GPOS), 1))
        e.var("bz_t", e.ld(B_GROUP))
        e.var("bz_zn", e.ld(e.add(e.add(tab, BT_MIN), p["bz_t"])))
        e.var("bz_zvec", e.call(_FN["an_mbits"], p["bz_zn"]))
        e.if_(e.eq(p["bz_zvec"], Z_STOP), lambda: e.give(Z_STOP))
        e.var("bz_go", 1)

        def step():
            _ok(e, e.le(p["bz_zn"], 20))
            e.var("bz_limit", e.ld(e.add(e.add(tab, BT_LIMIT), e.add(e.mul(p["bz_t"], 24), p["bz_zn"]))))

            def more():
                e.set("bz_zn", e.add(p["bz_zn"], 1))
                e.var("bz_bit", e.call(_FN["an_mbits"], 1))
                e.if_(e.eq(p["bz_bit"], Z_STOP), lambda: e.give(Z_STOP))
                e.set("bz_zvec", e.add(e.mul(p["bz_zvec"], 2), p["bz_bit"]))

            e.if_(e.lt(p["bz_zvec"], e.add(p["bz_limit"], 1)), lambda: e.set("bz_go", 0), more)

        e.while_(lambda: e.ne(p["bz_go"], 0), step)
        e.var("bz_d", e.sub(p["bz_zvec"], e.ld(e.add(e.add(tab, BT_BASE), e.add(e.mul(p["bz_t"], 24), p["bz_zn"])))))
        _ok(e, e.lt(p["bz_d"], 258))
        _ok(e, e.lt(p["bz_d"], e.ld(e.add(e.add(tab, BT_PN), p["bz_t"]))))  # a perm entry libbz2 did not set
        e.give(e.ld(e.add(e.add(tab, BT_PERM), e.add(e.mul(p["bz_t"], 258), p["bz_d"]))))
    return _function((), build, tables)


def _bzcrc_fn(tables):
    """The bzip2 CRC (MSB first, 0x04C11DB7) of ``crc`` with byte ``b`` appended."""
    def build(e: E):
        p = e.p
        e.var("bc_c", e.bin(Operation.BIT_XOR, p["crc"], e.mul(p["b"], 1 << 24)))
        for _ in range(8):
            e.set("bc_c", e.sel(e.ne(e.and_(p["bc_c"], 1 << 31), 0), e.bin(Operation.BIT_XOR, e.and_(e.mul(p["bc_c"], 2), MASK32), 0x04C11DB7),
                                e.and_(e.mul(p["bc_c"], 2), MASK32)))
        e.give(p["bc_c"])
    return _function(("crc", "b"), build, tables)


def _bunzip_fn(tables):
    """``bz2.BZ2Decompressor`` over ``csize`` bytes of packed handle ``h`` from byte ``start``: ``ZipExtFile.read``'s
    result for an entry of ``fsize`` bytes and CRC-32 ``crc`` (see ``an_zfinish``), one byte per word."""
    def build(e: E):
        p = e.p
        finish = lambda: e.give(_call(e, "an_zfinish"))  # noqa: E731

        def bits(name, n):
            e.var(name, e.call(_FN["an_mbits"], n))
            e.if_(e.eq(p[name], Z_STOP), finish)
            return p[name]

        def bytes_are(name, values):
            for value in values:
                _ok(e, e.eq(bits(name, 8), value))

        for g, value in ((Z_H, p["h"]), (Z_POS, p["start"]), (Z_END, e.add(p["start"], p["csize"])), (Z_BUF, 0), (Z_CNT, 0), (Z_TOTAL, 0),
                         (Z_FSIZE, p["fsize"]), (Z_CRC, p["crc"])):
            e.st(g, value)
        e.var("bu_out", e.alloc(e.add(p["fsize"], 1)))
        e.var("bu_ring", e.alloc(Z_WINDOW))
        _ok(e, e.both(e.ne(p["bu_out"], NONE), e.ne(p["bu_ring"], NONE)))
        e.st(Z_OUT, p["bu_out"])
        e.st(Z_RING, p["bu_ring"])
        bytes_are("bu_m", b"BZh")
        e.var("bu_level", bits("bu_lv", 8))
        _ok(e, e.both(e.le(ord("1"), p["bu_level"]), e.le(p["bu_level"], ord("9"))))
        e.var("bu_max", e.mul(e.sub(p["bu_level"], ord("0")), 100000))
        e.var("bu_tt", e.alloc(p["bu_max"]))
        e.var("bu_tab", e.alloc(BT_WORDS))
        e.var("bu_a", e.alloc(256 * 5 + 1 + 6 + 6 * 258 + 2 * BZ_MAX_SELECTORS))
        _ok(e, e.both(e.ne(p["bu_tt"], NONE), e.ne(p["bu_tab"], NONE), e.ne(p["bu_a"], NONE)))
        e.st(B_TAB, p["bu_tab"])
        e.var("bu_rn", e.alloc(len(BZ_RNUMS)))
        _ok(e, e.ne(p["bu_rn"], NONE))
        for k, value in enumerate(BZ_RNUMS):
            e.st(e.add(p["bu_rn"], k), value)
        e.st(B_RN, p["bu_rn"])
        a = p["bu_a"]
        inuse, seq, mtf, unzf = (e.add(a, 256 * k) for k in range(4))
        cftab = e.add(a, 1024)  # 257 words
        pos = e.add(a, 1281)  # 6 words
        lens = e.add(a, 1287)  # 6 * 258
        selmtf = e.add(a, 1287 + 6 * 258)
        sel = e.add(selmtf, BZ_MAX_SELECTORS)
        e.st(B_SEL, sel)
        e.var("bu_comb", 0)

        def block():
            e.var("bu_b0", bits("bu_m0", 8))

            def stream_end():
                bytes_are("bu_e", b"\x72\x45\x38\x50\x90")
                e.var("bu_sc", 0)
                for _ in range(4):
                    e.set("bu_sc", e.add(e.mul(p["bu_sc"], 256), bits("bu_scb", 8)))
                _ok(e, e.eq(p["bu_sc"], p["bu_comb"]))
                finish()

            e.if_(e.eq(p["bu_b0"], 0x17), stream_end)
            _ok(e, e.eq(p["bu_b0"], 0x31))
            bytes_are("bu_mb", b"\x41\x59\x26\x53\x59")
            e.var("bu_bcrc", 0)
            for _ in range(4):
                e.set("bu_bcrc", e.add(e.mul(p["bu_bcrc"], 256), bits("bu_cb", 8)))
            e.var("bu_rand", bits("bu_rb", 1))
            e.var("bu_optr", 0)
            for _ in range(3):
                e.set("bu_optr", e.add(e.mul(p["bu_optr"], 256), bits("bu_ob", 8)))
            _ok(e, e.le(p["bu_optr"], e.add(10, p["bu_max"])))
            e.var("bu_in16", bits("bu_i16", 16))
            e.for_("bu_z", 0, 256, lambda: e.st(e.add(inuse, p["bu_z"]), 0))

            def sixteen():
                e.var("bu_hi", e.and_(e.udiv(p["bu_in16"], _bit_weight(e, e.sub(15, p["bu_g"]))), 1))

                def used():
                    e.var("bu_lo", bits("bu_l16", 16))
                    e.for_("bu_j", 0, 16, lambda: e.st(e.add(inuse, e.add(e.mul(p["bu_g"], 16), p["bu_j"])),
                                                       e.and_(e.udiv(p["bu_lo"], _bit_weight(e, e.sub(15, p["bu_j"]))), 1)))

                e.if_(e.ne(p["bu_hi"], 0), used)

            e.for_("bu_g", 0, 16, sixteen)
            e.var("bu_nin", 0)
            e.for_("bu_u", 0, 256, lambda: e.if_(e.ne(e.ld(e.add(inuse, p["bu_u"])), 0), lambda: (
                e.st(e.add(seq, p["bu_nin"]), p["bu_u"]), e.set("bu_nin", e.add(p["bu_nin"], 1)))))
            _ok(e, e.ne(p["bu_nin"], 0))
            e.var("bu_alpha", e.add(p["bu_nin"], 2))
            e.var("bu_ng", bits("bu_g3", 3))
            _ok(e, e.both(e.le(2, p["bu_ng"]), e.le(p["bu_ng"], 6)))
            e.var("bu_ns", bits("bu_s15", 15))
            _ok(e, e.le(1, p["bu_ns"]))

            def selector():
                e.var("bu_sj", 0)
                e.var("bu_sgo", 1)

                def unary():
                    e.if_(e.eq(bits("bu_sb", 1), 0), lambda: e.set("bu_sgo", 0), lambda: (
                        e.set("bu_sj", e.add(p["bu_sj"], 1)), _ok(e, e.lt(p["bu_sj"], p["bu_ng"]))))

                e.while_(lambda: e.ne(p["bu_sgo"], 0), unary)
                e.if_(e.lt(p["bu_si"], BZ_MAX_SELECTORS), lambda: e.st(e.add(selmtf, p["bu_si"]), p["bu_sj"]))

            e.for_("bu_si", 0, p["bu_ns"], selector)
            e.if_(e.lt(BZ_MAX_SELECTORS, p["bu_ns"]), lambda: e.set("bu_ns", BZ_MAX_SELECTORS))
            e.for_("bu_p", 0, p["bu_ng"], lambda: e.st(e.add(pos, p["bu_p"]), p["bu_p"]))

            def unmtf():
                e.var("bu_v", e.ld(e.add(selmtf, p["bu_x"])))
                e.var("bu_tmp", e.ld(e.add(pos, p["bu_v"])))
                e.while_(lambda: e.lt(0, p["bu_v"]), lambda: (e.st(e.add(pos, p["bu_v"]), e.ld(e.add(pos, e.sub(p["bu_v"], 1)))),
                                                              e.set("bu_v", e.sub(p["bu_v"], 1))))
                e.st(pos, p["bu_tmp"])
                e.st(e.add(sel, p["bu_x"]), p["bu_tmp"])

            e.for_("bu_x", 0, p["bu_ns"], unmtf)

            def coding():
                e.var("bu_curr", bits("bu_c5", 5))

                def one():
                    e.var("bu_cgo", 1)

                    def delta():
                        _ok(e, e.both(e.le(1, p["bu_curr"]), e.le(p["bu_curr"], 20)))
                        e.if_(e.eq(bits("bu_d1", 1), 0), lambda: e.set("bu_cgo", 0), lambda: e.if_(
                            e.eq(bits("bu_d2", 1), 0), lambda: e.set("bu_curr", e.add(p["bu_curr"], 1)), lambda: e.set("bu_curr", e.sub(p["bu_curr"], 1))))

                    e.while_(lambda: e.ne(p["bu_cgo"], 0), delta)
                    e.st(e.add(lens, e.add(e.mul(p["bu_t"], 258), p["bu_ci"])), p["bu_curr"])

                e.for_("bu_ci", 0, p["bu_alpha"], one)
                _call(e, "an_bztable", p["bu_t"], e.add(lens, e.mul(p["bu_t"], 258)), p["bu_alpha"])

            e.for_("bu_t", 0, p["bu_ng"], coding)
            # The MTF and RUNA/RUNB symbols.
            e.for_("bu_mi", 0, 256, lambda: (e.st(e.add(mtf, p["bu_mi"]), p["bu_mi"]), e.st(e.add(unzf, p["bu_mi"]), 0)))
            e.st(B_GNO, 0)
            e.st(B_GPOS, 0)
            e.st(B_NSEL, p["bu_ns"])
            e.var("bu_nb", 0)
            e.var("bu_eob", e.add(p["bu_nin"], 1))

            def symbol(name):
                e.var(name, _call(e, "an_bzsym"))
                e.if_(e.eq(p[name], Z_STOP), finish)
                return p[name]

            e.var("bu_sym", symbol("bu_s0"))

            def put(uc):
                _ok(e, e.lt(p["bu_nb"], p["bu_max"]))
                e.st(e.add(p["bu_tt"], p["bu_nb"]), uc)
                e.set("bu_nb", e.add(p["bu_nb"], 1))

            def run():
                e.var("bu_es", 0)
                e.var("bu_N", 1)
                e.while_(lambda: e.le(p["bu_sym"], 1), lambda: (
                    _ok(e, e.lt(p["bu_N"], 2 * 1024 * 1024)), e.set("bu_es", e.add(p["bu_es"], e.mul(e.add(p["bu_sym"], 1), p["bu_N"]))),
                    e.set("bu_N", e.mul(p["bu_N"], 2)), e.set("bu_sym", symbol("bu_s1"))))
                e.var("bu_uc", e.ld(e.add(seq, e.ld(mtf))))
                e.st(e.add(unzf, p["bu_uc"]), e.add(e.ld(e.add(unzf, p["bu_uc"])), p["bu_es"]))
                e.for_("bu_r", 0, p["bu_es"], lambda: put(p["bu_uc"]))

            def literal():
                e.var("bu_nn", e.sub(p["bu_sym"], 1))
                e.var("bu_mv", e.ld(e.add(mtf, p["bu_nn"])))
                e.while_(lambda: e.lt(0, p["bu_nn"]), lambda: (e.st(e.add(mtf, p["bu_nn"]), e.ld(e.add(mtf, e.sub(p["bu_nn"], 1)))),
                                                               e.set("bu_nn", e.sub(p["bu_nn"], 1))))
                e.st(mtf, p["bu_mv"])
                e.var("bu_lc", e.ld(e.add(seq, p["bu_mv"])))
                e.st(e.add(unzf, p["bu_lc"]), e.add(e.ld(e.add(unzf, p["bu_lc"])), 1))
                put(p["bu_lc"])
                e.set("bu_sym", symbol("bu_s2"))

            e.while_(lambda: e.ne(p["bu_sym"], p["bu_eob"]), lambda: e.if_(e.le(p["bu_sym"], 1), run, literal))
            _ok(e, e.lt(p["bu_optr"], p["bu_nb"]))
            # The inverse BWT: ``tt[cftab[uc]] |= i << 8``.
            e.st(cftab, 0)
            e.for_("bu_cf", 1, 257, lambda: e.st(e.add(cftab, p["bu_cf"]), e.add(e.ld(e.add(cftab, e.sub(p["bu_cf"], 1))), e.ld(e.add(unzf, e.sub(p["bu_cf"], 1))))))
            e.for_("bu_bi", 0, p["bu_nb"], lambda: (
                e.var("bu_bc", e.and_(e.ld(e.add(p["bu_tt"], p["bu_bi"])), 255)),
                e.var("bu_at", e.ld(e.add(cftab, p["bu_bc"]))),
                e.st(e.add(p["bu_tt"], p["bu_at"]), e.add(e.ld(e.add(p["bu_tt"], p["bu_at"])), e.mul(p["bu_bi"], 256))),
                e.st(e.add(cftab, p["bu_bc"]), e.add(p["bu_at"], 1))))
            e.var("bu_tpos", e.udiv(e.ld(e.add(p["bu_tt"], p["bu_optr"])), 256))
            e.var("bu_togo", 0)
            e.var("bu_rtpos", 0)
            e.var("bu_used", 0)

            def get(name):
                """``BZ_GET_FAST``, then for a randomised block ``BZ_RAND_UPD_MASK`` and the mask."""
                e.var("bu_word", e.ld(e.add(p["bu_tt"], p["bu_tpos"])))
                e.var(name, e.and_(p["bu_word"], 255))
                e.set("bu_tpos", e.udiv(p["bu_word"], 256))
                e.set("bu_used", e.add(p["bu_used"], 1))

                def randomise():
                    e.if_(e.eq(p["bu_togo"], 0), lambda: (
                        e.set("bu_togo", _rnum(e, p["bu_rtpos"])), e.set("bu_rtpos", e.and_(e.add(p["bu_rtpos"], 1), 511))))
                    e.set("bu_togo", e.sub(p["bu_togo"], 1))
                    e.if_(e.eq(p["bu_togo"], 1), lambda: e.set(name, e.bin(Operation.BIT_XOR, p[name], 1)))

                e.if_(e.ne(p["bu_rand"], 0), randomise)
                return p[name]

            e.var("bu_k0", get("bu_g0"))
            e.var("bu_crc", 0xFFFFFFFF)
            e.var("bu_end", e.add(p["bu_nb"], 1))

            def emit_run(ch, n):
                def one():
                    e.if_(e.eq(_call(e, "an_zemit", ch), 2), finish)
                    e.set("bu_crc", _call(e, "an_bzcrc", p["bu_crc"], ch))

                e.for_("bu_o", 0, n, one)

            def unrle():
                _ok(e, e.lt(p["bu_used"], p["bu_end"]))  # past the block: corrupt
                e.var("bu_ch", p["bu_k0"])
                e.var("bu_n", 1)
                e.var("bu_more", 1)
                for j in range(3):
                    def next_(j=j):
                        e.var("bu_k1", get("bu_g1"))

                        def same():
                            if j < 2:
                                e.set("bu_n", e.add(p["bu_n"], 1))
                            else:
                                e.var("bu_count", get("bu_g2"))
                                e.set("bu_n", e.add(p["bu_count"], 4))
                                e.set("bu_k0", get("bu_g3"))
                                e.set("bu_more", 0)

                        e.if_(e.eq(p["bu_used"], p["bu_end"]), lambda: e.set("bu_more", 0), lambda: e.if_(
                            e.ne(p["bu_k1"], p["bu_k0"]), lambda: (e.set("bu_k0", p["bu_k1"]), e.set("bu_more", 0)), same))

                    e.if_(e.ne(p["bu_more"], 0), next_)
                emit_run(p["bu_ch"], p["bu_n"])

            e.while_(lambda: e.ne(p["bu_used"], p["bu_end"]), unrle)
            _ok(e, e.eq(e.bin(Operation.BIT_XOR, p["bu_crc"], 0xFFFFFFFF), p["bu_bcrc"]))
            e.set("bu_comb", e.bin(Operation.BIT_XOR, e.and_(e.add(e.mul(p["bu_comb"], 2), e.udiv(p["bu_comb"], 1 << 31)), MASK32), p["bu_bcrc"]))

        e.while_(lambda: e.eq(1, 1), block)
        finish()
    return _function(("h", "start", "csize", "fsize", "crc"), build, tables)


def _bit_weight(e: E, k):
    """``2 ** k`` for ``k`` in 0..15."""
    result = e.c(1)
    for q in range(1, 16):
        result = e.sel(e.eq(k, q), 1 << q, result)
    return result


def _rnum(e: E, k):
    """``BZ2_rNums[k]``: read from the constant block at ``B_RN``."""
    return e.ld(e.add(e.ld(B_RN), k))


# -- S15e.6i.3 (ADR-359): LZMA entries (``zipfile.LZMADecompressor``: liblzma 5.4.5's raw LZMA1 decoder) -------------------
# zipfile's wrapper reads a version (2 bytes), a property size (2 bytes) and the properties; with fewer bytes than those
# it gives nothing.  The properties must be LZMA1's five (``lc``/``lp``/``pb`` with ``lc + lp <= 4``, the dictionary
# size, at least 4096 and rounded up to 16).  The range decoder normalises before each bit, as liblzma does, so input
# that ends inside a symbol gives the symbols before it.  An end-of-payload marker ends the stream once its range coder
# is finished (else ``LZMA_DATA_ERROR``); a distance at or past what the dictionary holds, and a rep match before any
# output, are errors.  The history is a 2 MiB window: a distance past it (only possible past 2 MiB of output, where the
# entry's declared size, at most 2 MiB, no longer counts) declines.
L_RANGE, L_CODE, L_HIST = CO_AT + 50, CO_AT + 51, CO_AT + 52
L_WINDOW = 1 << 21  # bytes, packed eight to a word
(LP_IS_MATCH, LP_IS_REP, LP_IS_REP0, LP_IS_REP1, LP_IS_REP2, LP_IS_REP0_LONG, LP_DIST_SLOT, LP_SPECIAL, LP_ALIGN, LP_MATCH_LEN, LP_REP_LEN,
 LP_LITERAL) = (0, 192, 204, 216, 228, 240, 432, 688, 802, 818, 1332, 1846)


def _lnorm(e: E):
    """``rc_normalize``: one more input byte when the range is below 2 ** 24; ``Z_STOP`` returned when the input ends."""
    def more():
        e.if_(e.le(e.ld(Z_END), e.ld(Z_POS)), lambda: e.give(Z_STOP))
        e.st(L_RANGE, e.and_(e.mul(e.ld(L_RANGE), 256), MASK32))
        e.st(L_CODE, e.add(e.and_(e.mul(e.ld(L_CODE), 256), MASK32), _pbyte(e, e.ld(Z_H), e.ld(Z_POS))))
        e.st(Z_POS, e.add(e.ld(Z_POS), 1))

    e.if_(e.lt(e.ld(L_RANGE), 1 << 24), more)


def _lbit_fn(tables):
    """``rc_bit`` on the probability at word ``prob``: the bit, or ``Z_STOP``."""
    def build(e: E):
        p = e.p
        _lnorm(e)
        e.var("lb_p", e.ld(p["prob"]))
        e.var("lb_bound", e.mul(e.udiv(e.ld(L_RANGE), 1 << 11), p["lb_p"]))

        def zero():
            e.st(L_RANGE, p["lb_bound"])
            e.st(p["prob"], e.add(p["lb_p"], e.udiv(e.sub(2048, p["lb_p"]), 32)))
            e.give(0)

        e.if_(e.lt(e.ld(L_CODE), p["lb_bound"]), zero)
        e.st(L_RANGE, e.sub(e.ld(L_RANGE), p["lb_bound"]))
        e.st(L_CODE, e.sub(e.ld(L_CODE), p["lb_bound"]))
        e.st(p["prob"], e.sub(p["lb_p"], e.udiv(p["lb_p"], 32)))
        e.give(1)
    return _function(("prob",), build, tables)


def _ltree_fn(tables):
    """``rc_bittree`` (``reverse`` 0) or ``rc_bittree_reverse`` (1) of ``n`` bits over the probabilities at ``probs``."""
    def build(e: E):
        p = e.p
        e.var("lt_m", 1)
        e.var("lt_v", 0)
        e.var("lt_w", 1)

        def step():
            e.var("lt_b", e.call(_FN["an_lbit"], e.add(p["probs"], p["lt_m"])))
            e.if_(e.eq(p["lt_b"], Z_STOP), lambda: e.give(Z_STOP))
            e.set("lt_m", e.add(e.mul(p["lt_m"], 2), p["lt_b"]))
            e.set("lt_v", e.add(p["lt_v"], e.mul(p["lt_b"], p["lt_w"])))
            e.set("lt_w", e.mul(p["lt_w"], 2))

        e.for_("lt_k", 0, p["n"], step)
        e.give(e.sel(e.ne(p["reverse"], 0), p["lt_v"], e.sub(p["lt_m"], p["lt_w"])))
    return _function(("probs", "n", "reverse"), build, tables)


def _ldirect_fn(tables):
    """``rc_direct`` for ``n`` bits (32-bit arithmetic as liblzma's): their value, or ``Z_STOP``."""
    def build(e: E):
        p = e.p
        e.var("ld_v", 0)

        def step():
            _lnorm(e)
            e.st(L_RANGE, e.udiv(e.ld(L_RANGE), 2))
            e.st(L_CODE, e.and_(e.sub(e.ld(L_CODE), e.ld(L_RANGE)), MASK32))
            e.var("ld_t", e.udiv(e.ld(L_CODE), 1 << 31))
            e.st(L_CODE, e.and_(e.add(e.ld(L_CODE), e.mul(e.ld(L_RANGE), p["ld_t"])), MASK32))
            e.set("ld_v", e.add(e.mul(p["ld_v"], 2), e.sub(1, p["ld_t"])))

        e.for_("ld_k", 0, p["n"], step)
        e.give(p["ld_v"])
    return _function(("n",), build, tables)


def _llen_fn(tables):
    """A match length from the length coder at ``probs`` for position state ``ps``, or ``Z_STOP``."""
    def build(e: E):
        p = e.p
        stop = lambda name: e.if_(e.eq(p[name], Z_STOP), lambda: e.give(Z_STOP))  # noqa: E731
        e.var("ll_c", e.call(_FN["an_lbit"], p["probs"]))
        stop("ll_c")
        e.if_(e.eq(p["ll_c"], 0), lambda: (e.var("ll_low", e.call(_FN["an_ltree"], e.add(e.add(p["probs"], 2), e.mul(p["ps"], 8)), 3, 0)),
                                           stop("ll_low"), e.give(e.add(p["ll_low"], 2))))
        e.var("ll_c2", e.call(_FN["an_lbit"], e.add(p["probs"], 1)))
        stop("ll_c2")
        e.if_(e.eq(p["ll_c2"], 0), lambda: (e.var("ll_mid", e.call(_FN["an_ltree"], e.add(e.add(p["probs"], 130), e.mul(p["ps"], 8)), 3, 0)),
                                            stop("ll_mid"), e.give(e.add(p["ll_mid"], 10))))
        e.var("ll_high", e.call(_FN["an_ltree"], e.add(p["probs"], 258), 8, 0))
        stop("ll_high")
        e.give(e.add(p["ll_high"], 18))
    return _function(("probs", "ps"), build, tables)


def _lhist_fn(tables):
    """The output byte ``d + 1`` back (``dict_get``); a distance past the window declines."""
    def build(e: E):
        p = e.p
        _ok(e, e.lt(p["d"], L_WINDOW))
        e.var("lh_at", e.and_(e.sub(e.sub(e.ld(Z_TOTAL), p["d"]), 1), L_WINDOW - 1))
        e.give(_pbyte(e, e.sub(e.ld(L_HIST), 1), p["lh_at"]))
    return _function(("d",), build, tables)


def _lemit_fn(tables):
    """One output byte: into the window, and through ``an_zemit`` (2 at ``Z_MAX_OUT``)."""
    def build(e: E):
        p = e.p
        e.var("le_at", e.and_(e.ld(Z_TOTAL), L_WINDOW - 1))
        e.var("le_w", e.add(e.ld(L_HIST), e.udiv(p["le_at"], 8)))
        e.var("le_s", _shift8(e, e.urem(p["le_at"], 8)))
        e.var("le_old", e.and_(e.udiv(e.ld(p["le_w"]), p["le_s"]), 255))
        e.st(p["le_w"], e.add(e.sub(e.ld(p["le_w"]), e.mul(p["le_old"], p["le_s"])), e.mul(p["b"], p["le_s"])))
        e.give(_call(e, "an_zemit", p["b"]))
    return _function(("b",), build, tables)


def _unlzma_fn(tables):
    """zipfile's ``LZMADecompressor`` over ``csize`` bytes of packed handle ``h`` from byte ``start``: ``ZipExtFile.read``'s
    result for an entry of ``fsize`` bytes and CRC-32 ``crc`` (see ``an_zfinish``), one byte per word."""
    def build(e: E):
        p = e.p
        finish = lambda: e.give(_call(e, "an_zfinish"))  # noqa: E731
        byte = lambda k: _pbyte(e, p["h"], e.add(p["start"], k))  # noqa: E731

        def call(name, function, *arguments):
            e.var(name, e.call(_FN[function], *arguments))
            e.if_(e.eq(p[name], NONE), lambda: e.give(NONE))
            e.if_(e.eq(p[name], Z_STOP), finish)
            return p[name]

        def emit(b):
            e.if_(e.eq(_call(e, "an_lemit", b), 2), finish)

        for g, value in ((Z_H, p["h"]), (Z_TOTAL, 0), (Z_FSIZE, p["fsize"]), (Z_CRC, p["crc"])):
            e.st(g, value)
        e.var("lz_out", e.alloc(e.add(p["fsize"], 1)))
        e.var("lz_ring", e.alloc(Z_WINDOW))
        e.var("lz_hist", e.alloc(L_WINDOW // 8 + 1))
        _ok(e, e.both(e.ne(p["lz_out"], NONE), e.ne(p["lz_ring"], NONE), e.ne(p["lz_hist"], NONE)))
        e.st(Z_OUT, p["lz_out"])
        e.st(Z_RING, p["lz_ring"])
        e.st(L_HIST, e.add(p["lz_hist"], 1))
        # The wrapper: nothing until the header and the properties are all there.
        e.if_(e.le(p["csize"], 4), finish)
        e.var("lz_psize", e.add(byte(2), e.mul(byte(3), 256)))
        e.if_(e.le(p["csize"], e.add(4, p["lz_psize"])), finish)
        _ok(e, e.eq(p["lz_psize"], 5))  # ``_decode_filter_properties``: LZMA1's five bytes
        e.var("lz_d", byte(4))
        _ok(e, e.le(p["lz_d"], (4 * 5 + 4) * 9 + 8))
        e.var("lz_pb", e.udiv(p["lz_d"], 45))
        e.var("lz_lp", e.udiv(e.urem(p["lz_d"], 45), 9))
        e.var("lz_lc", e.urem(p["lz_d"], 9))
        _ok(e, e.le(e.add(p["lz_lc"], p["lz_lp"]), 4))
        e.var("lz_dict", e.add(e.add(byte(5), e.mul(byte(6), 1 << 8)), e.add(e.mul(byte(7), 1 << 16), e.mul(byte(8), 1 << 24))))
        e.if_(e.lt(p["lz_dict"], 4096), lambda: e.set("lz_dict", 4096))
        e.set("lz_dict", e.and_(e.add(p["lz_dict"], 15), (1 << 64) - 16))
        e.st(Z_POS, e.add(p["start"], 9))
        e.st(Z_END, e.add(p["start"], p["csize"]))
        e.var("lz_nlit", e.mul(0x300, _bit_weight(e, e.add(p["lz_lc"], p["lz_lp"]))))
        e.var("lz_probs", e.alloc(e.add(LP_LITERAL, p["lz_nlit"])))
        _ok(e, e.ne(p["lz_probs"], NONE))
        e.for_("lz_i", 0, e.add(LP_LITERAL, p["lz_nlit"]), lambda: e.st(e.add(p["lz_probs"], p["lz_i"]), 1024))
        probs = lambda offset: e.add(p["lz_probs"], offset)  # noqa: E731
        # ``rc_read_init``: five bytes, the first 0x00.
        e.if_(e.le(e.ld(Z_END), e.ld(Z_POS)), finish)
        _ok(e, e.eq(_pbyte(e, p["h"], e.ld(Z_POS)), 0))
        e.st(L_CODE, 0)
        for _ in range(5):
            e.if_(e.le(e.ld(Z_END), e.ld(Z_POS)), finish)
            e.st(L_CODE, e.and_(e.add(e.mul(e.ld(L_CODE), 256), _pbyte(e, p["h"], e.ld(Z_POS))), MASK32))
            e.st(Z_POS, e.add(e.ld(Z_POS), 1))
        e.st(L_RANGE, MASK32)
        e.var("lz_state", 0)
        for k in range(4):
            e.var(f"lz_rep{k}", 0)
        e.var("lz_pbmask", e.sub(_bit_weight(e, p["lz_pb"]), 1))
        e.var("lz_lpmask", e.sub(_bit_weight(e, p["lz_lp"]), 1))

        def copy(n):
            e.for_("lz_c", 0, n, lambda: (e.var("lz_cb", _call(e, "an_lhist", p["lz_rep0"])), emit(p["lz_cb"])))

        def symbol():
            e.var("lz_pos", e.ld(Z_TOTAL))
            e.var("lz_ps", e.and_(p["lz_pos"], p["lz_pbmask"]))
            e.var("lz_full", e.sel(e.lt(p["lz_pos"], p["lz_dict"]), p["lz_pos"], p["lz_dict"]))
            st = p["lz_state"]

            def literal():
                e.var("lz_prev", e.sel(e.eq(p["lz_pos"], 0), 0, _call(e, "an_lhist", 0)))
                e.var("lz_lit", probs(e.add(LP_LITERAL, e.mul(0x300, e.add(e.mul(e.and_(p["lz_pos"], p["lz_lpmask"]), _bit_weight(e, p["lz_lc"])),
                                                                           e.udiv(p["lz_prev"], _bit_weight(e, e.sub(8, p["lz_lc"]))))))))

                def plain():
                    e.var("lz_sym", call("lz_ps8", "an_ltree", p["lz_lit"], 8, 0))
                    emit(p["lz_sym"])

                def matched():
                    e.var("lz_mb", _call(e, "an_lhist", p["lz_rep0"]))
                    e.var("lz_offs", 0x100)
                    e.var("lz_s", 1)

                    def bit():
                        e.set("lz_mb", e.mul(p["lz_mb"], 2))
                        e.var("lz_mbit", e.and_(p["lz_mb"], p["lz_offs"]))
                        e.var("lz_b", call("lz_bb", "an_lbit", e.add(p["lz_lit"], e.add(e.add(p["lz_offs"], p["lz_mbit"]), p["lz_s"]))))
                        e.set("lz_s", e.add(e.mul(p["lz_s"], 2), p["lz_b"]))
                        e.set("lz_offs", e.sel(e.ne(p["lz_b"], 0), e.and_(p["lz_offs"], p["lz_mbit"]),
                                               e.and_(p["lz_offs"], e.bin(Operation.BIT_XOR, p["lz_mbit"], (1 << 64) - 1))))

                    e.while_(lambda: e.lt(p["lz_s"], 0x100), bit)
                    emit(e.sub(p["lz_s"], 0x100))

                e.if_(e.lt(st, 7), plain, matched)
                e.set("lz_state", e.sel(e.lt(st, 4), 0, e.sel(e.lt(st, 10), e.sub(st, 3), e.sub(st, 6))))

            def match():
                e.set("lz_rep3", p["lz_rep2"])
                e.set("lz_rep2", p["lz_rep1"])
                e.set("lz_rep1", p["lz_rep0"])
                e.var("lz_len", call("lz_ml", "an_llen", probs(LP_MATCH_LEN), p["lz_ps"]))
                e.set("lz_state", e.sel(e.lt(st, 7), 7, 10))
                e.var("lz_dstate", e.sel(e.lt(p["lz_len"], 6), e.sub(p["lz_len"], 2), 3))
                e.var("lz_slot", call("lz_sl", "an_ltree", probs(e.add(LP_DIST_SLOT, e.mul(p["lz_dstate"], 64))), 6, 0))

                def far():
                    e.var("lz_foot", e.sub(e.udiv(p["lz_slot"], 2), 1))
                    e.set("lz_rep0", e.mul(e.add(2, e.and_(p["lz_slot"], 1)), _pow_small(e, p["lz_foot"])))

                    def special():
                        e.var("lz_sp", call("lz_spr", "an_ltree", probs(e.sub(e.sub(e.add(LP_SPECIAL, p["lz_rep0"]), p["lz_slot"]), 1)), p["lz_foot"], 1))
                        e.set("lz_rep0", e.add(p["lz_rep0"], p["lz_sp"]))

                    def direct():
                        e.var("lz_dir", call("lz_dr", "an_ldirect", e.sub(p["lz_foot"], 4)))
                        e.set("lz_rep0", e.and_(e.add(p["lz_rep0"], e.mul(p["lz_dir"], 16)), MASK32))
                        e.var("lz_al", call("lz_alr", "an_ltree", probs(LP_ALIGN), 4, 1))
                        e.set("lz_rep0", e.and_(e.add(p["lz_rep0"], p["lz_al"]), MASK32))

                    e.if_(e.lt(p["lz_slot"], 14), special, direct)

                e.if_(e.lt(p["lz_slot"], 4), lambda: e.set("lz_rep0", p["lz_slot"]), far)

                def marker():
                    """The end-of-payload marker: normalise, then the range coder must be finished."""
                    _lnorm_or_finish(e, finish)
                    _ok(e, e.eq(e.ld(L_CODE), 0))
                    finish()

                e.if_(e.eq(p["lz_rep0"], MASK32), marker)
                _ok(e, e.lt(p["lz_rep0"], p["lz_full"]))  # ``dict_is_distance_valid``
                copy(p["lz_len"])

            def rep():
                _ok(e, e.ne(p["lz_full"], 0))
                e.var("lz_r0", call("lz_r0b", "an_lbit", probs(e.add(LP_IS_REP0, st))))

                def first():
                    e.var("lz_long", call("lz_lgb", "an_lbit", probs(e.add(LP_IS_REP0_LONG, e.add(e.mul(st, 16), p["lz_ps"])))))

                    def short():
                        e.set("lz_state", e.sel(e.lt(st, 7), 9, 11))
                        copy(1)
                        e.set("lz_len", 0)

                    e.if_(e.eq(p["lz_long"], 0), short)

                def other():
                    e.var("lz_r1", call("lz_r1b", "an_lbit", probs(e.add(LP_IS_REP1, st))))
                    e.var("lz_dist", p["lz_rep1"])

                    def further():
                        e.var("lz_r2", call("lz_r2b", "an_lbit", probs(e.add(LP_IS_REP2, st))))
                        e.if_(e.eq(p["lz_r2"], 0), lambda: e.set("lz_dist", p["lz_rep2"]), lambda: (
                            e.set("lz_dist", p["lz_rep3"]), e.set("lz_rep3", p["lz_rep2"])))
                        e.set("lz_rep2", p["lz_rep1"])

                    e.if_(e.ne(p["lz_r1"], 0), further)
                    e.set("lz_rep1", p["lz_rep0"])
                    e.set("lz_rep0", p["lz_dist"])

                e.var("lz_len", 1)  # 0 once a short rep is copied
                e.if_(e.eq(p["lz_r0"], 0), first, other)

                def long_():
                    e.set("lz_len", call("lz_rl", "an_llen", probs(LP_REP_LEN), p["lz_ps"]))
                    e.set("lz_state", e.sel(e.lt(st, 7), 8, 11))
                    copy(p["lz_len"])

                e.if_(e.ne(p["lz_len"], 0), long_)

            e.var("lz_m", call("lz_mb0", "an_lbit", probs(e.add(LP_IS_MATCH, e.add(e.mul(st, 16), p["lz_ps"])))))

            def not_literal():
                e.var("lz_r", call("lz_rb", "an_lbit", probs(e.add(LP_IS_REP, st))))
                e.if_(e.eq(p["lz_r"], 0), match, rep)

            e.if_(e.eq(p["lz_m"], 0), literal, not_literal)

        e.while_(lambda: e.eq(1, 1), symbol)
        finish()
    return _function(("h", "start", "csize", "fsize", "crc"), build, tables)


def _lnorm_or_finish(e: E, finish):
    """``rc_normalize`` where the input ending finishes the entry."""
    def more():
        e.if_(e.le(e.ld(Z_END), e.ld(Z_POS)), finish)
        e.st(L_RANGE, e.and_(e.mul(e.ld(L_RANGE), 256), MASK32))
        e.st(L_CODE, e.add(e.and_(e.mul(e.ld(L_CODE), 256), MASK32), _pbyte(e, e.ld(Z_H), e.ld(Z_POS))))
        e.st(Z_POS, e.add(e.ld(Z_POS), 1))

    e.if_(e.lt(e.ld(L_RANGE), 1 << 24), more)


def _pow_small(e: E, k):
    """``2 ** k`` for ``k`` in 0..31."""
    result = e.c(1)
    for q in range(1, 32):
        result = e.sel(e.eq(k, q), 1 << q, result)
    return result


def _slice_bytes_fn(tables):
    """``n`` bytes of packed handle ``h`` from byte ``start``, one per word: their handle."""
    def build(e: E):
        p = e.p
        e.var("sb_h", e.alloc(e.add(p["n"], 1)))
        _ok(e, e.ne(p["sb_h"], NONE))
        e.st(p["sb_h"], p["n"])
        e.for_("sb_k", 0, p["n"], lambda: e.st(e.add(e.add(p["sb_h"], 1), p["sb_k"]), _pbyte(e, p["h"], e.add(p["start"], p["sb_k"]))))
        e.give(p["sb_h"])
    return _function(("h", "start", "n"), build, tables)


def _entry_bytes_fn(tables):
    """``ZipFile.read`` of the entry whose ``an_zip`` slot is ``slot`` in packed handle ``h``: its bytes, one per word."""
    def build(e: E):
        p = e.p
        e.if_(e.eq(at(e, p["slot"], 3), 0), lambda: e.give(_call(e, "an_slice_bytes", p["h"], at(e, p["slot"], 1), at(e, p["slot"], 2))))
        for method, name in ((8, "an_inflate"), (12, "an_bunzip")):
            e.if_(e.eq(at(e, p["slot"], 3), method), lambda name=name: e.give(_call(e, name, p["h"], at(e, p["slot"], 1), at(e, p["slot"], 4),
                                                                                      at(e, p["slot"], 2), at(e, p["slot"], 5))))
        e.give(_call(e, "an_unlzma", p["h"], at(e, p["slot"], 1), at(e, p["slot"], 4), at(e, p["slot"], 2), at(e, p["slot"], 5)))
    return _function(("h", "slot"), build, tables)


VERSION_CODE_ATTRIBUTE = 0x0101021B


def _version_code_fn(tables):
    """``_set_version_code``: the binary manifest ``m`` (one byte per word) with its one root ``android:versionCode`` set
    to ``v``; anything the bootstrap refuses (a ``ValueError``) declines."""
    def build(e: E):
        p = e.p
        b = lambda k: at(e, p["m"], e.add(k, 1))  # noqa: E731

        def field(o, n: int):
            value = e.c(0)
            for k in reversed(range(n)):
                value = e.add(e.mul(value, 256), b(e.add(o, k)))
            return value

        e.var("vc_len", e.ld(p["m"]))
        _ok(e, e.le(8, p["vc_len"]))
        _ok(e, e.both(e.eq(field(0, 2), 3), e.eq(field(4, 4), p["vc_len"])))
        e.var("vc_ids", 0)
        e.var("vc_nids", 0)
        e.var("vc_sites", 0)
        e.var("vc_site", 0)
        e.var("vc_o", field(2, 2))

        def chunk():
            o = p["vc_o"]
            _ok(e, e.le(e.add(o, 8), p["vc_len"]))
            e.var("vc_kind", field(o, 2))
            e.var("vc_header", field(e.add(o, 2), 2))
            e.var("vc_size", field(e.add(o, 4), 4))
            _ok(e, e.both(e.le(8, p["vc_header"]), e.le(p["vc_header"], p["vc_size"]), e.le(e.add(o, p["vc_size"]), p["vc_len"])))
            e.if_(e.eq(p["vc_kind"], 0x0180), lambda: (e.set("vc_ids", e.add(o, p["vc_header"])),
                                                     e.set("vc_nids", e.udiv(e.sub(p["vc_size"], p["vc_header"]), 4))))

            def element():
                _ok(e, e.both(e.le(16, p["vc_header"]), e.le(e.add(p["vc_header"], 20), p["vc_size"])))
                e.var("vc_start", field(e.add(e.add(o, p["vc_header"]), 8), 2))
                e.var("vc_asize", field(e.add(e.add(o, p["vc_header"]), 10), 2))
                e.var("vc_count", field(e.add(e.add(o, p["vc_header"]), 12), 2))
                e.var("vc_base", e.add(e.add(o, p["vc_header"]), p["vc_start"]))
                _ok(e, e.both(e.eq(p["vc_asize"], 20), e.le(e.add(p["vc_base"], e.mul(p["vc_count"], 20)), e.add(o, p["vc_size"]))))

                def attribute():
                    e.var("vc_at", e.add(p["vc_base"], e.mul(p["vc_q"], 20)))
                    e.var("vc_name", field(e.add(p["vc_at"], 4), 4))
                    e.if_(e.both(e.lt(p["vc_name"], p["vc_nids"]), e.eq(field(e.add(p["vc_ids"], e.mul(e.sel(e.lt(p["vc_name"], p["vc_nids"]), p["vc_name"], 0), 4)), 4),
                                                                      VERSION_CODE_ATTRIBUTE)),
                          lambda: (e.set("vc_sites", e.add(p["vc_sites"], 1)), e.set("vc_site", p["vc_at"])))

                e.for_("vc_q", 0, p["vc_count"], attribute)

            e.if_(e.eq(p["vc_kind"], 0x0102), element)
            e.set("vc_o", e.add(o, p["vc_size"]))

        e.while_(lambda: e.lt(p["vc_o"], p["vc_len"]), chunk)
        _ok(e, e.both(e.eq(p["vc_o"], p["vc_len"]), e.eq(p["vc_sites"], 1)))
        _ok(e, e.eq(b(e.add(p["vc_site"], 15)), 0x10))  # a decimal integer
        e.var("vc_h", e.alloc(e.add(p["vc_len"], 1)))
        _ok(e, e.ne(p["vc_h"], NONE))
        e.for_("vc_k", 0, e.add(p["vc_len"], 1), lambda: e.st(e.add(p["vc_h"], p["vc_k"]), at(e, p["m"], p["vc_k"])))
        for k in range(4):
            e.st(e.add(p["vc_h"], e.add(e.add(p["vc_site"], 17), k)), e.and_(e.udiv(p["v"], 1 << (8 * k)), 255))
        e.give(p["vc_h"])
    return _function(("m", "v"), build, tables)


def _jtype_fn(tables):
    """``_parse_descriptor_type``: the item after the descriptor type at item ``k`` of handle ``d`` (from 1); ``void``
    allows ``V``.  An invalid type declines (the bootstrap's ``ValueError``)."""
    def build(e: E):
        p = e.p
        e.var("jt_n", e.ld(p["d"]))
        _ok(e, e.le(p["k"], p["jt_n"]))
        e.var("jt_c", at(e, p["d"], p["k"]))
        e.if_(e.eq(p["jt_c"], ord("V")), lambda: (_ok(e, e.ne(p["void"], 0)), e.give(e.add(p["k"], 1))))
        e.if_(e.either(*(e.eq(p["jt_c"], ord(c)) for c in "ZBCSIJFD")), lambda: e.give(e.add(p["k"], 1)))
        e.var("jt_s", p["k"])  # an array's element type follows its dimensions
        e.if_(e.eq(p["jt_c"], ord("[")), lambda: (
            e.while_(lambda: e.both(e.le(p["jt_s"], p["jt_n"]), e.eq(at(e, p["d"], p["jt_s"]), ord("["))), lambda: e.set("jt_s", e.add(p["jt_s"], 1))),
            _ok(e, e.le(e.sub(p["jt_s"], p["k"]), 255)), _ok(e, e.le(p["jt_s"], p["jt_n"]))))
        e.var("jt_e", at(e, p["d"], p["jt_s"]))
        e.if_(e.either(*(e.eq(p["jt_e"], ord(c)) for c in "ZBCSIJFD")), lambda: e.give(e.add(p["jt_s"], 1)))
        _ok(e, e.eq(p["jt_e"], ord("L")))
        # ``L<internal name>;``: not empty, no leading or trailing ``/``, no ``//``, ``.`` or NUL.
        e.var("jt_j", e.add(p["jt_s"], 1))
        e.while_(lambda: e.both(e.le(p["jt_j"], p["jt_n"]), e.ne(at(e, p["d"], p["jt_j"]), ord(";"))), lambda: e.set("jt_j", e.add(p["jt_j"], 1)))
        _ok(e, e.le(p["jt_j"], p["jt_n"]))
        e.var("jt_a", e.add(p["jt_s"], 1))
        _ok(e, e.lt(p["jt_a"], p["jt_j"]))
        _ok(e, e.both(e.ne(at(e, p["d"], p["jt_a"]), ord("/")), e.ne(at(e, p["d"], e.sub(p["jt_j"], 1)), ord("/"))))
        e.for_("jt_q", p["jt_a"], p["jt_j"], lambda: (
            _ok(e, e.both(e.ne(at(e, p["d"], p["jt_q"]), ord(".")), e.ne(at(e, p["d"], p["jt_q"]), 0))),
            _ok(e, e.not_(e.both(e.eq(at(e, p["d"], p["jt_q"]), ord("/")), e.eq(at(e, p["d"], e.add(p["jt_q"], 1)), ord("/")))))))
        e.give(e.add(p["jt_j"], 1))
    return _function(("d", "k", "void"), build, tables)


def _jdesc_fn(tables):
    """``parse_jvm_method_descriptor`` of handle ``d``: ``[n + 1, result, params...]``, each a handle; a malformed
    descriptor declines."""
    def build(e: E):
        p = e.p
        e.var("jd_n", e.ld(p["d"]))
        _ok(e, e.both(e.lt(0, p["jd_n"]), e.eq(at(e, p["d"], 1), ord("("))))
        e.var("jd_out", e.alloc(e.add(p["jd_n"], 2)))
        _ok(e, e.ne(p["jd_out"], NONE))
        e.var("jd_count", 0)
        e.var("jd_k", 2)

        def parameter():
            e.var("jd_end", _call(e, "an_jtype", p["d"], p["jd_k"], 0))
            e.st(e.add(p["jd_out"], e.add(2, p["jd_count"])), call_tail(e, p["d"], p["jd_k"], p["jd_end"]))
            e.set("jd_count", e.add(p["jd_count"], 1))
            e.set("jd_k", p["jd_end"])

        e.while_(lambda: e.both(e.le(p["jd_k"], p["jd_n"]), e.ne(at(e, p["d"], e.sel(e.le(p["jd_k"], p["jd_n"]), p["jd_k"], 1)), ord(")"))), parameter)
        _ok(e, e.le(p["jd_k"], p["jd_n"]))
        e.var("jd_rs", e.add(p["jd_k"], 1))
        e.var("jd_re", _call(e, "an_jtype", p["d"], p["jd_rs"], 1))
        _ok(e, e.eq(p["jd_re"], e.add(p["jd_n"], 1)))
        e.st(p["jd_out"], e.add(p["jd_count"], 1))
        e.st(e.add(p["jd_out"], 1), call_tail(e, p["d"], p["jd_rs"], p["jd_re"]))
        e.give(p["jd_out"])
    return _function(("d",), build, tables)


def call_tail(e: E, h, start, stop):
    """Items ``start`` to ``stop`` (exclusive, from 1) of handle ``h``: their handle."""
    return _call(e, "an_slice_items", h, start, stop)


def _slice_items_fn(tables):
    def build(e: E):
        p = e.p
        e.var("si_n", e.sub(p["stop"], p["start"]))
        e.var("si_h", e.alloc(e.add(p["si_n"], 1)))
        _ok(e, e.ne(p["si_h"], NONE))
        e.st(p["si_h"], p["si_n"])
        e.for_("si_k", 0, p["si_n"], lambda: e.st(e.add(e.add(p["si_h"], 1), p["si_k"]), at(e, p["h"], e.add(p["start"], p["si_k"]))))
        e.give(p["si_h"])
    return _function(("h", "start", "stop"), build, tables)


def _entry_desc_fn(tables):
    """The JVM descriptor (``(params)result``) of method ``entry`` of the lowered class whose descriptor is handle
    ``c`` among ``lowered`` (each the class-translation program's ``[count, words]``), or NONE."""
    def build(e: E):
        p = e.p

        def text_at(h, q):
            return e.add(q, e.add(1, at(e, h, q)))  # past the text at item ``q`` (its count, then its units)

        def same_text(h, q, ref, stem):
            """1 when the text at item ``q`` of ``h`` is handle ``ref``'s items."""
            e.var(stem, e.flag(e.eq(at(e, h, q), e.ld(ref))))
            e.for_(f"{stem}_k", 1, e.add(e.sel(e.ne(p[stem], 0), e.ld(ref), 0), 1), lambda: e.if_(
                e.ne(at(e, h, e.add(q, p[f"{stem}_k"])), at(e, ref, p[f"{stem}_k"])), lambda: e.set(stem, 0)))
            return p[stem]

        e.var("ed_result", NONE)
        e.var("k_entry", e.ld(G_K + K_INDEX[b"entry"]))

        def one_class():
            e.var("ec_h", at(e, p["lowered"], e.add(p["ecq"], 1)))
            h = p["ec_h"]

            def walk():
                e.var("ec_q", text_at(h, e.c(1)))
                e.set("ec_q", e.add(p["ec_q"], 1))  # the access
                e.set("ec_q", e.sel(e.ne(at(e, h, p["ec_q"]), 0), text_at(h, e.add(p["ec_q"], 1)), e.add(p["ec_q"], 1)))  # the superclass
                e.var("ec_ni", at(e, h, p["ec_q"]))
                e.set("ec_q", e.add(p["ec_q"], 1))
                e.for_("eci", 0, p["ec_ni"], lambda: e.set("ec_q", text_at(h, p["ec_q"])))
                e.var("ec_nf", at(e, h, p["ec_q"]))
                e.set("ec_q", e.add(p["ec_q"], 1))
                e.for_("ecf", 0, p["ec_nf"], lambda: e.set("ec_q", e.add(text_at(h, text_at(h, p["ec_q"])), 1)))
                e.var("ec_nm", at(e, h, p["ec_q"]))
                e.set("ec_q", e.add(p["ec_q"], 1))

                def method():
                    e.var("em_name", p["ec_q"])
                    e.var("em_ret", text_at(h, p["em_name"]))
                    e.var("em_np", text_at(h, p["em_ret"]))
                    e.set("ec_q", e.add(p["em_np"], 1))
                    e.var("em_params", p["ec_q"])
                    e.for_("emp", 0, at(e, h, p["em_np"]), lambda: e.set("ec_q", text_at(h, p["ec_q"])))
                    e.var("em_end", p["ec_q"])
                    e.set("ec_q", e.add(p["ec_q"], 1))  # the access

                    def found():
                        e.var("ed_h", e.alloc(e.add(e.ld(p["ec_h"]), 3)))
                        _ok(e, e.ne(p["ed_h"], NONE))
                        e.st(p["ed_h"], 0)

                        def push(value):
                            e.st(e.add(e.add(p["ed_h"], 1), e.ld(p["ed_h"])), value)
                            e.st(p["ed_h"], e.add(e.ld(p["ed_h"]), 1))

                        push(ord("("))
                        e.var("ed_q", p["em_params"])
                        e.while_(lambda: e.lt(p["ed_q"], p["em_end"]), lambda: (
                            e.for_("edk", 1, e.add(at(e, h, p["ed_q"]), 1), lambda: push(at(e, h, e.add(p["ed_q"], p["edk"])))),
                            e.set("ed_q", text_at(h, p["ed_q"]))))
                        push(ord(")"))
                        e.for_("edr", 1, e.add(at(e, h, p["em_ret"]), 1), lambda: push(at(e, h, e.add(p["em_ret"], p["edr"]))))
                        e.set("ed_result", p["ed_h"])

                    e.if_(e.ne(same_text(h, p["em_name"], p["k_entry"], "em_same"), 0), found)
                    e.var("em_code", at(e, h, p["ec_q"]))
                    e.set("ec_q", e.add(p["ec_q"], 1))

                    def code():
                        e.var("em_nu", at(e, h, e.add(p["ec_q"], 3)))
                        e.set("ec_q", e.add(p["ec_q"], 4))

                        def unit():
                            e.var("eu_k", at(e, h, p["ec_q"]))
                            e.set("ec_q", e.add(p["ec_q"], 1))
                            e.if_(e.eq(p["eu_k"], 0), lambda: e.set("ec_q", e.add(p["ec_q"], 1)))
                            e.if_(e.either(e.eq(p["eu_k"], 1), e.eq(p["eu_k"], 2)), lambda: e.set("ec_q", text_at(h, p["ec_q"])))
                            e.if_(e.eq(p["eu_k"], 3), lambda: e.set("ec_q", text_at(h, text_at(h, text_at(h, p["ec_q"])))))

                            def method_ref():
                                e.set("ec_q", text_at(h, text_at(h, text_at(h, p["ec_q"]))))
                                e.var("eu_np", at(e, h, p["ec_q"]))
                                e.set("ec_q", e.add(p["ec_q"], 1))
                                e.for_("eup", 0, p["eu_np"], lambda: e.set("ec_q", text_at(h, p["ec_q"])))

                            e.if_(e.eq(p["eu_k"], 4), method_ref)

                        e.for_("emu", 0, p["em_nu"], unit)

                    e.if_(e.ne(p["em_code"], 0), code)

                e.for_("ecm", 0, p["ec_nm"], method)

            e.if_(e.ne(same_text(h, e.c(1), p["c"], "ec_same"), 0), walk)

        e.for_("ecq", 0, e.ld(p["lowered"]), one_class)
        e.give(p["ed_result"])
    return _function(("lowered", "c"), build, tables)


JVM_HELPERS = (("an_jdecode", _jdecode_fn), ("an_jws", _jws_fn), ("an_jhex4", _jhex4_fn), ("an_jstr", _jstr_fn), ("an_bmul", _bmul_fn),
               ("an_bshl", _bshl_fn), ("an_bcmp", _bcmp_fn), ("an_bsub", _bsub_fn), ("an_bbits", _bbits_fn), ("an_bpow10", _bpow10_fn),
               ("an_bdigits", _bdigits_fn), ("an_jround", _jround_fn), ("an_jnum", _jnum_fn), ("an_jvalue", _jvalue_fn), ("an_jparse", _jparse_fn),
               ("an_jmag", _jmag_fn), ("an_jcmp", _jcmp_fn), ("an_jint", _jint_fn), ("an_jconst", _jconst_fn), ("an_jiter", _jiter_fn),
               ("an_jtruth", _jtruth_fn), ("an_jin", _jin_fn), ("an_jget", _jget_fn), ("an_jhex", _jhex_fn), ("an_jsurrogate", _jsurrogate_fn),
               ("an_u16put", _u16put_fn), ("an_crc", _crc_fn), ("an_zip", _zip_fn), ("an_zbits", _zbits_fn), ("an_zfinish", _zfinish_fn),
               ("an_zemit", _zemit_fn), ("an_zbuild", _zbuild_fn), ("an_zdecode", _zdecode_fn), ("an_inflate", _inflate_fn),
               ("an_mbits", _mbits_fn), ("an_bztable", _bztable_fn), ("an_bzsym", _bzsym_fn), ("an_bzcrc", _bzcrc_fn), ("an_bunzip", _bunzip_fn),
               ("an_lbit", _lbit_fn), ("an_ltree", _ltree_fn), ("an_ldirect", _ldirect_fn), ("an_llen", _llen_fn), ("an_lhist", _lhist_fn),
               ("an_lemit", _lemit_fn), ("an_unlzma", _unlzma_fn),
               ("an_slice_bytes", _slice_bytes_fn), ("an_entry_bytes", _entry_bytes_fn), ("an_version_code", _version_code_fn),
               ("an_slice_items", _slice_items_fn), ("an_jtype", _jtype_fn), ("an_jdesc", _jdesc_fn), ("an_entry_desc", _entry_desc_fn))


HELPERS = (("an_byte", _byte_fn), ("an_uleb", _uleb_fn), ("an_bstr", _bstr_fn), ("an_same", _same_fn), ("an_prefix", _prefix_fn),
           ("an_less", _less_fn), ("an_desc", _desc_fn), ("an_java", _java_fn), ("an_jname", _jname_fn), ("an_line", _line_fn),
           ("an_dotted", _dotted_fn), ("an_cat", _cat_fn), ("an_dec", _dec_fn), ("an_dtext", _dtext_fn),
           ("an_dcid", _dcid_fn), ("an_slice", _slice_fn), ("an_native", _native_fn),
           ("an_binary", _binary_fn), ("an_tail", _tail_fn), ("an_has", _has_fn), ("an_utf16", _utf16_fn), ("an_jni", _jni_fn), ("an_cid", _cid_fn),
           ("an_incid", _incid_fn), ("an_put", _put_fn), ("an_seqput", _seq_put_fn), ("an_packput", _pack_put_fn),
           ("an_bigalloc", _bigalloc_fn), ("an_record", _record_fn), ("an_blobput", _blob_put_fn)) + JVM_HELPERS


# -- the frontend -----------------------------------------------------------------------------------------------------------


_PROGRAM = NativeProgram(STORE_PATH, "android")
OPT_OUT = "XAX_ANDROID_PYTHON"


def android_with_xax(reader, package_view, target_object, build_entry_function, *, required: bool = False, external_inputs=None) -> bytes | None:
    """The unsigned APK the XAX Android program builds for the package, or None where it cannot run or declines (the
    bootstrap then decides), unless ``required``.  S15e.6i.2b: ``external_inputs`` (digest to bytes) follow the
    identity, sorted by digest, as the driver gives them."""
    import os

    import xax_native
    from xax_compiler import Diagnostic, XaxError
    from xax_riscv64 import _cid_words
    from xax_selfhost_x86_64_general import general_object_table

    native = None if os.environ.get(OPT_OUT) == "1" else _PROGRAM.native(OPT_OUT)
    apk = None
    if native is not None:
        table = general_object_table(reader, build_entry_function, target_object)
        if table is not None:
            words = table[0]
            identity = package_view.logical_identity
            tail = [*_cid_words(build_entry_function), len(package_view.modules), *(w for cid in package_view.modules for w in _cid_words(cid)),
                    len(identity), *identity, len(external_inputs or {})]
            for digest, data in sorted((external_inputs or {}).items()):
                padded = data + bytes(-len(data) % 8)
                tail += [*digest, len(data), *(int.from_bytes(padded[k:k + 8], "little") for k in range(0, len(padded), 8))]

            def roots(read):
                (status,) = read(0, 1)
                if status == D.REJECT:
                    return D.decode_diagnostic(read)
                if status != 1:
                    return None
                (count,) = read(1, 1)
                return read(2, count * CID_WORDS)

            found = native.run([*words, 0, 0, *tail], roots)
            if isinstance(found, Diagnostic):
                raise XaxError(found)  # the program decided the rejection
            if found is None and os.environ.get("XAX_ANDROID_WHY") == "1":
                import sys

                (code,) = native.run([*words, 0, 0, *tail], lambda read: read(G_WHY, 1))
                print("android program (roots) declined at", DECLINE_SITES[code - 1] if 0 < code <= len(DECLINE_SITES) else code, file=sys.stderr)
            if found is not None:  # the declarative surface has no roots: the table's entry stays the build entry
                words = [words[0], *(found[:CID_WORDS] or words[1:1 + CID_WORDS]), *words[1 + CID_WORDS:], len(found) // CID_WORDS, *found]

                def collect(read):
                    (status,) = read(0, 1)
                    if status == D.REJECT:
                        return D.decode_diagnostic(read)
                    if status != 1:
                        return None
                    head = read(IMAGE_AT, 3)
                    packed = read(IMAGE_AT + 3, (head[2] + 7) // 8)
                    return b"".join(word.to_bytes(8, "little") for word in packed)[:head[2]]

                apk = native.run([*words, 1, *tail], collect)
                if isinstance(apk, Diagnostic):
                    raise XaxError(apk)
                if apk is None and os.environ.get("XAX_ANDROID_WHY") == "1":
                    import sys

                    code, layer = native.run([*words, 1, *tail], lambda read: read(G_WHY, 2))
                    print("android program declined at", DECLINE_SITES[code - 1] if 0 < code <= len(DECLINE_SITES) else code, "layer", layer,
                          file=sys.stderr)
        if apk is None:
            xax_native.declined("android", 1)
    if apk is None and required:
        raise RuntimeError("the XAX Android program is unavailable or declined")
    return apk
