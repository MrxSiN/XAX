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
import xax_selfhost_facts as F
from xax_compiler import Kind, x86_64_linux_exec_target
from xax_graph_builder import program_store
from xax_native import bootstrap_dir
from xax_selfhost_facts import B64, E, H_ARENA, H_ARENA_END, HEADER, NONE, _function
from xax_selfhost_general_image import I_CURSOR, IMAGE_AT, IMAGE_END
from xax_selfhost_general_regalloc import G_RA
from xax_selfhost_views_backend import _FN, CID_WORDS, GLOBALS, NativeProgram
from xax_selfhost_x86_64_general import COUNT_AT, ORDER_AT

STORE_PATH = bootstrap_dir() / "xax_android.xax"
CO_AT = 252 << 20  # above ``IMAGE_END``
G_INBASE = CO_AT  # ``INPUT_REDIRECT``: a chained layer's input base
G_CUR, G_END, G_W, G_SAVE = CO_AT + 1, CO_AT + 2, CO_AT + 3, CO_AT + 4  # the payload cursor and end, the writer, the arena
G_K = CO_AT + 64  # the constants' handles
SPILL_AT, SPILL_WORDS = CO_AT + 1024, 3072  # a phase's variables, for the next (ADR-352's split)
PHASES = 10
SLOT_AT, SLOT_END = CO_AT + 4096, CO_AT + 16384  # the frontend's variables, one word each (``_Slotted``)
CO_ARENA_AT, CO_ARENA_END = SLOT_END, CO_AT + (3 << 19)  # this program's arena
WRITER_AT, WRITER_END = CO_ARENA_END, HEADER - 4096  # the layers' inputs, written in turn (apart from the arena)
ANDROID_V3 = b"android-arm64-v8a-shared-v3"
ANDROID_LATER = (b"android-arm64-v8a-shared-v4", b"android-arm64-v8a-shared-v5")  # the managed-class profile's too
ANDROID_ABI, ANDROID_FORMATS = 4, (4, 5)
PACKED_FORMAT = 5
NATIVE_ALIGNMENT, ENTRY_ALIGNMENT = 16 * 1024, 4
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
UI_KINDS = ("ui_plain", "ui_resource", "ui_method", "ui_argument", "surface")
# The classes S15e.6h.2 decides; a package with another declines.
# The extra DEX files' names, in the order the bootstrap numbers them.
DEX_NAMES = tuple(f"classes{k}.dex".encode() for k in range(3, 10))
DEX_CLASS = {"managed": "managed_entry"}  # an extra DEX file's carrier class
def _selector_words() -> tuple[int, ...]:
    """The CID words of the empty build selector a declarative surface package names (its only function)."""
    from xax_compiler import Block, Terminator, function, graph_fragment

    cid = function(graph_fragment((Block((), (), Terminator.return_(())),)), (), ()).cid
    return tuple(int.from_bytes(cid[8 * k:8 * k + 8], "big") for k in range(CID_WORDS))


SELECTOR_WORDS = _selector_words()
# ``lower_android_surface_activity``'s onCreate: (opcode, registers, reference); a reference is a type, the description,
# or a method (owner, name, return, parameters).
SURFACE_ON_CREATE = (
    (0x6F, (2, 3), (b"Landroid/app/Activity;", b"onCreate", b"V", (b"Landroid/os/Bundle;",))),
    (0x22, (0,), b"Landroid/view/SurfaceView;"),
    (0x70, (0, 2), (b"Landroid/view/SurfaceView;", b"<init>", b"V", (b"Landroid/content/Context;",))),
    (0x1A, (1,), "description"),
    (0x6E, (0, 1), (b"Landroid/view/View;", b"setContentDescription", b"V", (b"Ljava/lang/CharSequence;",))),
    (0x6E, (2, 0), (b"Landroid/app/Activity;", b"setContentView", b"V", (b"Landroid/view/View;",))),
    (0x0E, (), None),
)
SURFACE_TEXTS = (b"Landroid/view/SurfaceView;", b"<init>", b"setContentDescription", b"Ljava/lang/CharSequence;", b"setContentView")
# The managed-class profile (S15e.6h.2c): a class record's fields, a method record's, a declaration record's width.
(MC_REC, MC_DESC, MC_SUPER, MC_LIB, MC_IFACES, MC_METHODS, MC_DESC16, MC_JAVA) = range(8)
MC_WORDS = 8
(MM_NAME, MM_DESC, MM_ACCESS, MM_SUPER, MM_NATIVE, MM_PARAMS, MM_RESULT) = range(7)
MM_WORDS = 7
DECL_WORDS = 7  # a permission (name, max SDK, never-for-location), a feature (name, required), a component (class,
#                 exported, foreground types, flags, kind code, kind, actions)


def _type_words() -> tuple[tuple[int, ...], tuple[tuple[int, ...], ...]]:
    """The CID words of ``JNIEnv*`` and of the JNI width of each of ``ZBCSIJFD`` (``check_export_signature``'s types)."""
    from xax_jni import _jni_value_type, jni_env_pointer_type

    words = lambda cid: tuple(int.from_bytes(cid[8 * k:8 * k + 8], "big") for k in range(CID_WORDS))  # noqa: E731
    return words(jni_env_pointer_type().cid), tuple(words(_jni_value_type(primitive).cid) for primitive in "ZBCSIJFD")


JNI_ENV_WORDS, JNI_WIDTH_WORDS = _type_words()
FOREGROUND_TYPES = tuple(__import__("xax_manifest").FOREGROUND_SERVICE_TYPES.items())
JNI_REFERENCE_PREFIXES = (b"android.jni.ref/v2/", b"android.jni.ref/v3/", b"android.jni.ref/")
JMETHOD_PREFIXES = (b"android.jni.jmethodID/v1/", b"android.jni.jmethodID/v2/")
MANAGED_TEXT_AT = 4096  # ``xax_selfhost_android_managed_rules.TEXT_AT``: the program's texts
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
CONSTANTS = (
    ANDROID_V3, *ANDROID_LATER, b"android-aapcs64-c", b"default", b"xaxOnCreate", b"xaxOnClick", b"onCreate", b"onClick", b"Landroid/app/Activity;",
    b"Ljava/lang/Object;", b"Landroid/view/View$OnClickListener;", b"Landroid/os/Bundle;", b"Landroid/view/View;", b"V", b"xaxapp",
    b"libxaxapp.so", b"AndroidManifest.xml", b"classes.dex", b"classes2.dex", b"lib/arm64-v8a/libxaxapp.so",
    b"resources.arsc", b"Ljava/lang/String;", b"Landroid/content/BroadcastReceiver;", b"Landroid/app/Application;", b"Landroid/app/Service;",
    b"xaxOnReceive", b"onReceive", b"xaxOnDestroy", b"onDestroy", b"onBind", b"Landroid/os/IBinder;", b"Landroid/content/Intent;",
    b"Landroid/content/Context;", *(f"classes{k}.dex".encode() for k in range(3, 10)),
    *LIBXPOSED_TEXTS, *SURFACE_TEXTS, *MANAGED_TEXTS,
    *(prefix for _name, prefix in CLASSES),
)
K_INDEX = {value: k for k, value in enumerate(dict.fromkeys(CONSTANTS))}
ACC_PUBLIC_FINAL_CLASS, ACC_NATIVE_METHOD, ACC_PROTECTED, ACC_PUBLIC = 33, 258, 4, 1


G_WHY = CO_AT + 8  # the declining check's site (``DECLINE_SITES[code - 1]``), for diagnosis only
G_LAYER = CO_AT + 9  # the layers called so far (1 the AArch64 program), for diagnosis only
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
        _ok(e, e.lt(p["pt_at"], WRITER_END))
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


def _record_fn(tables):
    """The handle ``[length, packed words...]`` of the image record a layer wrote."""
    def build(e: E):
        p = e.p
        _ok(e, e.both(e.eq(e.ld(IMAGE_AT), 1), e.eq(e.ld(IMAGE_AT + 1), 0)))
        e.var("rc_n", e.ld(IMAGE_AT + 2))
        e.var("rc_w", e.udiv(e.add(p["rc_n"], 7), 8))
        _ok(e, e.le(e.add(IMAGE_AT + 3, p["rc_w"]), IMAGE_END))
        e.var("rc_h", e.alloc(e.add(p["rc_w"], 1)))
        _ok(e, e.ne(p["rc_h"], NONE))
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


HELPERS = (("an_byte", _byte_fn), ("an_uleb", _uleb_fn), ("an_bstr", _bstr_fn), ("an_same", _same_fn), ("an_prefix", _prefix_fn),
           ("an_less", _less_fn), ("an_desc", _desc_fn), ("an_java", _java_fn), ("an_jname", _jname_fn), ("an_line", _line_fn),
           ("an_dotted", _dotted_fn), ("an_cat", _cat_fn), ("an_dec", _dec_fn), ("an_dtext", _dtext_fn),
           ("an_dcid", _dcid_fn), ("an_slice", _slice_fn), ("an_native", _native_fn),
           ("an_binary", _binary_fn), ("an_tail", _tail_fn), ("an_has", _has_fn), ("an_utf16", _utf16_fn), ("an_jni", _jni_fn), ("an_cid", _cid_fn),
           ("an_incid", _incid_fn), ("an_put", _put_fn), ("an_seqput", _seq_put_fn), ("an_packput", _pack_put_fn),
           ("an_record", _record_fn), ("an_blobput", _blob_put_fn))


# -- the frontend -----------------------------------------------------------------------------------------------------------

class _Slotted:
    """The frontend's builder: its variables live in memory words (``SLOT_AT``) rather than in SSA values, which every
    block of a large graph would otherwise carry as arguments; loop counters stay SSA values."""

    def __init__(self, real: E, slots: dict[str, int]):
        self._real, self._slots, self._loops = real, slots, set()
        self.p = _SlotView(self)

    def __getattr__(self, name):
        return getattr(self._real, name)

    def _slot(self, name: str) -> int:
        if name not in self._slots:
            if name in self._loops:
                raise AssertionError(f"{name} is a loop counter")
            self._slots[name] = SLOT_AT + len(self._slots)
            assert self._slots[name] < SLOT_END
        return self._slots[name]

    def var(self, name: str, value=0):
        self._real.st(self._slot(name), value)

    def set(self, name: str, value):
        if name in self._slots or name not in self._real.p.types:
            self._real.st(self._slot(name), value)
        else:
            self._real.set(name, value)

    def for_(self, name: str, start, stop, body):
        if name in self._slots:
            raise AssertionError(f"{name} is a slotted variable")
        self._loops.add(name)
        self._real.for_(name, start, stop, body)


class _SlotView:
    def __init__(self, slotted: _Slotted):
        self._e = slotted

    def __getitem__(self, name: str):
        slots = self._e._slots
        return self._e._real.ld(slots[name]) if name in slots else self._e._real.p[name]


def _phases(tables, layers):
    """The frontend's phases (ADR-352's split): the decoding, the rules and the roots, the layers' inputs, then the layers
    and the APK; one generator emits them, each phase a separate function resumed on its own builder, its variables in
    scope passed to the next through ``SPILL_AT``."""
    slots: dict[str, int] = {}

    def body(e: E):
        e = _Slotted(e, slots)
        p = e.p
        call = lambda name, *args: _call(e, name, *args)  # noqa: E731
        put = lambda value: call("an_put", value)  # noqa: E731
        same = lambda a, b: e.ne(call("an_same", a, b), 0)  # noqa: E731
        e.st(0, 0)
        e.st(G_WHY, 0)
        e.st(G_LAYER, 0)
        e.set_hd(H_ARENA, CO_ARENA_AT)
        e.set_hd(H_ARENA_END, CO_ARENA_END)
        e.st(G_W, WRITER_AT)
        for value, k in K_INDEX.items():
            e.var("ck", e.alloc(len(value) + 1))
            _ok(e, e.ne(p["ck"], NONE))
            e.st(p["ck"], len(value))
            for j, byte in enumerate(value):
                e.st(e.add(p["ck"], 1 + j), byte)
            e.st(G_K + k, p["ck"])

        def K(value: bytes):
            return e.ld(G_K + K_INDEX[value])

        def layer(function, base):
            """Call a chained layer on the input at ``base``; decline unless it accepted (status 1)."""
            e.st(G_INBASE, base)
            e.st(G_LAYER, e.add(e.ld(G_LAYER), 1))
            e.st(G_SAVE, e.hd(H_ARENA))
            e.st(G_SAVE + 1, e.hd(H_ARENA_END))
            e.st(0, 0)
            e.var("lr", e.call(function))
            _ok(e, e.lt(e.hd(H_ARENA), CO_AT))  # the layer stayed below this program's state
            e.set_hd(H_ARENA, e.ld(G_SAVE))
            e.set_hd(H_ARENA_END, e.ld(G_SAVE + 1))
            _ok(e, e.both(e.ne(p["lr"], NONE), e.eq(e.ld(0), 1)))

        # 1. The object table: each record's input position (the target is the last record).
        e.var("nobj", e.rd(0))
        _ok(e, e.le(p["nobj"], 1 << 24))
        e.var("objs", e.alloc(e.add(p["nobj"], 2)))
        _ok(e, e.ne(p["objs"], NONE))
        e.var("pos", 1 + CID_WORDS)

        def record():
            e.st(e.add(p["objs"], p["q"]), p["pos"])
            e.set("pos", e.add(e.add(p["pos"], 2), e.mul(e.rd(e.add(p["pos"], 1)), CID_WORDS)))
            e.set("pos", e.add(e.add(e.add(p["pos"], CID_WORDS), 1), e.rd(e.add(p["pos"], CID_WORDS))))

        e.for_("q", 0, e.add(p["nobj"], 1), record)
        rec = lambda k: at(e, p["objs"], k)  # noqa: E731
        kind = lambda k: e.rd(rec(k))  # noqa: E731
        nrefs = lambda k: e.rd(e.add(rec(k), 1))  # noqa: E731
        cid_at = lambda k: e.add(e.add(rec(k), 2), e.mul(nrefs(k), CID_WORDS))  # noqa: E731
        payload_at = lambda k: e.add(e.add(cid_at(k), CID_WORDS), 1)  # noqa: E731
        payload_n = lambda k: e.rd(e.add(cid_at(k), CID_WORDS))  # noqa: E731
        # The group members, the graphs' extents, the audit word and the trap heads, then the roots.
        e.var("nx", e.rd(p["pos"]))
        e.set("pos", e.add(p["pos"], 1))

        def extra():
            e.set("pos", e.add(e.add(p["pos"], 2), e.mul(e.rd(e.add(p["pos"], 1)), CID_WORDS)))
            e.set("pos", e.add(e.add(e.add(p["pos"], CID_WORDS), 1), e.rd(e.add(p["pos"], CID_WORDS))))

        e.for_("q", 0, p["nx"], extra)
        e.var("ng", e.rd(p["pos"]))
        e.set("pos", e.add(p["pos"], 1))
        e.for_("q", 0, p["ng"], lambda: e.set("pos", e.add(e.add(e.add(p["pos"], CID_WORDS), 1), e.mul(e.rd(e.add(p["pos"], CID_WORDS)), 5))))
        e.set("pos", e.add(p["pos"], 1))  # the audit word
        e.var("nt", e.rd(p["pos"]))
        e.set("pos", e.add(p["pos"], 1))

        def trap():
            e.set("pos", e.add(p["pos"], CID_WORDS))
            e.var("tb", e.rd(p["pos"]))
            e.set("pos", e.add(p["pos"], 1))
            e.for_("j", 0, p["tb"], lambda: e.set("pos", e.add(e.add(p["pos"], 2), e.rd(e.add(p["pos"], 1)))))

        e.for_("q", 0, p["nt"], trap)
        e.var("roots_at", p["pos"])
        e.set("pos", e.add(e.add(p["pos"], 1), e.mul(e.rd(p["pos"]), CID_WORDS)))
        e.var("mode", e.rd(p["pos"]))
        e.var("entry", call("an_incid", e.add(p["pos"], 1)))
        e.set("pos", e.add(p["pos"], 1 + CID_WORDS))
        e.var("nmod", e.rd(p["pos"]))
        _ok(e, e.le(p["nmod"], 1 << 16))
        e.var("mods_at", e.add(p["pos"], 1))
        # The package's logical identity (its count, then one byte per word), the entity of the package's diagnostics.
        e.var("lid_at", e.add(p["mods_at"], e.mul(p["nmod"], CID_WORDS)))
        e.var("lid", e.alloc(e.add(e.rd(p["lid_at"]), 1)))
        _ok(e, e.both(e.ne(p["lid"], NONE), e.le(e.rd(p["lid_at"]), 1 << 16)))
        e.for_("lq", 0, e.add(e.rd(p["lid_at"]), 1), lambda: e.st(e.add(p["lid"], p["lq"]), e.rd(e.add(p["lid_at"], p["lq"]))))

        # The diagnostics (``xax_selfhost_diagnostics``): a rejection writes the bootstrap's record, sets the status to
        # ``REJECT`` and stops the driver.
        def d_str(h, raw: bool = False):
            call("an_dtext", h, D.T_STR, int(raw))

        def d_cid_rec(k):
            D.put(e, D.T_CID)
            for w in range(CID_WORDS):
                D.put(e, e.rd(e.add(cid_at(k), w)))

        def d_lid():
            call("an_dtext", p["lid"], D.T_HEX, 0)

        def d_list(values):
            D.put(e, D.T_LIST)
            D.put(e, len(values))
            for value in values:
                value()

        def d_dict(pairs):
            D.put(e, D.T_DICT)
            D.put(e, len(pairs))
            for key, value in pairs:
                D.text(e, key)
                value()

        def d_bool(flag):
            D.tagged(e, D.T_BOOL, flag)

        def reject(entity, rule: str, expected, actual, code: str = "XAX.BUILD.ANDROID"):
            D.begin(e)
            D.text(e, code)
            entity()
            D.text(e, rule)
            expected()
            actual()
            e.st(0, D.REJECT)
            e.give(2)  # the driver stops: the diagnostic is the output

        def find(cid):
            """The record index of the object whose CID handle is ``cid`` (NONE when none is)."""
            e.var("fd", NONE)

            def match():
                e.var("fd_at", cid_at(p["fq"]))
                e.if_(e.both(*(e.eq(e.rd(e.add(p["fd_at"], w)), at(e, cid, 1 + w)) for w in range(CID_WORDS))), lambda: e.set("fd", p["fq"]))

            e.for_("fq", 0, p["nobj"], lambda: e.if_(e.eq(p["fd"], NONE), match))
            return p["fd"]

        def identity(k):
            """The identity byte string of carrier ``k`` (its whole payload); the cursor at its end."""
            e.st(G_CUR, payload_at(k))
            e.st(G_END, e.add(payload_at(k), payload_n(k)))
            e.var("idn", call("an_bstr"))
            _ok(e, e.eq(e.ld(G_CUR), e.ld(G_END)))  # ``outer.end``
            return p["idn"]

        # 2. The target profile: v3 (its format names the packed layout).
        e.st(G_CUR, payload_at(p["nobj"]))
        e.st(G_END, e.add(payload_at(p["nobj"]), payload_n(p["nobj"])))
        e.var("t_id", call("an_bstr"))
        for name in ("t_profile", "t_arch", "t_abi", "t_fmt"):
            e.var(name, call("an_uleb"))
        e.var("t_v3", e.flag(same(p["t_id"], K(ANDROID_V3))))
        e.var("t_known", e.flag(e.either(e.ne(p["t_v3"], 0), *(same(p["t_id"], K(identity)) for identity in ANDROID_LATER))))

        def target_rejected():
            """U1 and U4 (``ANDROID-APK-TARGET``): the target's identity, quoted as the bootstrap quotes it."""
            reject(lambda: d_cid_rec(p["nobj"]), "ANDROID-APK-TARGET", lambda: D.text(e, ANDROID_V3.decode()), lambda: d_str(p["t_id"], raw=True))

        e.if_(e.eq(p["t_known"], 0), target_rejected)  # U1

        # 3. The carriers of the package's modules, classified in the bootstrap's order: per class its count and its
        # first carrier's identity (the bootstrap's ``carriers[0]``), and every export.
        e.var("counts", e.alloc(len(CLASSES)))
        e.var("firsts", e.alloc(len(CLASSES)))
        e.var("firstrecs", e.alloc(len(CLASSES)))  # the first carrier's record index
        _ok(e, e.both(e.ne(p["counts"], NONE), e.ne(p["firsts"], NONE), e.ne(p["firstrecs"], NONE)))
        for k in range(len(CLASSES)):
            e.st(e.add(p["counts"], k), 0)
            e.st(e.add(p["firsts"], k), 0)
        count = lambda name: at(e, p["counts"], C[name])  # noqa: E731
        first = lambda name: at(e, p["firsts"], C[name])  # noqa: E731
        e.var("kids", e.alloc(e.add(e.mul(p["nobj"], p["nmod"]), 1)))  # every identity-only carrier, in module order
        _ok(e, e.ne(p["kids"], NONE))
        e.st(p["kids"], 0)
        e.var("exports", e.alloc(e.add(e.mul(p["nobj"], 2), 1)))  # [2n, name, function CID handle, ...]
        _ok(e, e.ne(p["exports"], NONE))
        e.st(p["exports"], 0)
        e.var("mclasses", e.alloc(e.add(e.mul(p["nobj"], 2), 1)))  # the managed classes: [2n, identity, record, ...]
        _ok(e, e.ne(p["mclasses"], NONE))
        e.st(p["mclasses"], 0)

        def module():
            e.var("m_cid", call("an_incid", e.add(p["mods_at"], e.mul(p["mq"], CID_WORDS))))
            e.var("m", find(p["m_cid"]))
            _ok(e, e.ne(p["m"], NONE))
            _ok(e, e.eq(kind(p["m"]), int(Kind.MODULE)))

            def child():
                e.var("c_cid", call("an_incid", e.add(e.add(rec(p["m"]), 2), e.mul(p["cq"], CID_WORDS))))
                e.var("c", find(p["c_cid"]))
                _ok(e, e.ne(p["c"], NONE))

                def carrier():
                    e.var("cid_", identity(p["c"]))
                    e.st(e.add(p["kids"], e.add(e.ld(p["kids"]), 1)), p["cid_"])
                    e.st(p["kids"], e.add(e.ld(p["kids"]), 1))
                    e.var("cls", NONE)
                    for k, (_name, prefix) in enumerate(CLASSES):
                        e.if_(e.both(e.eq(p["cls"], NONE), e.ne(call("an_prefix", p["cid_"], K(prefix)), 0)), lambda k=k: e.set("cls", k))

                    def classified():
                        e.if_(e.eq(at(e, p["counts"], p["cls"]), 0), lambda: (e.st(e.add(p["firsts"], p["cls"]), p["cid_"]),
                                                                              e.st(e.add(p["firstrecs"], p["cls"]), p["c"])))
                        e.st(e.add(p["counts"], p["cls"]), e.add(at(e, p["counts"], p["cls"]), 1))

                    e.if_(e.ne(p["cls"], NONE), classified)

                    def export():
                        # ``decode_android_export``: the ABI, the visibility, the name, the function's CID.
                        e.var("x_body", call("an_tail", p["cid_"], len(PREFIX["export"])))
                        e.st(G_CUR, 0)
                        e.var("x_abi", _bstr_at(e, p["x_body"], "x"))
                        e.var("x_vis", _bstr_at(e, p["x_body"], "x"))
                        e.var("x_name", _bstr_at(e, p["x_body"], "x"))
                        e.var("x_at", e.ld(G_CUR))
                        _ok(e, e.eq(e.add(p["x_at"], 32), e.ld(p["x_body"])))
                        _ok(e, e.both(same(p["x_abi"], K(b"android-aapcs64-c")), same(p["x_vis"], K(b"default"))))
                        _ok(e, e.both(e.lt(0, e.ld(p["x_name"])), e.eq(call("an_has", p["x_name"], 0), 0)))
                        e.var("x_n", e.ld(p["exports"]))
                        e.st(e.add(p["exports"], e.add(p["x_n"], 1)), p["x_name"])
                        e.st(e.add(p["exports"], e.add(p["x_n"], 2)), call("an_cid", p["x_body"], e.add(p["x_at"], 1)))
                        e.st(p["exports"], e.add(p["x_n"], 2))

                    e.if_(e.eq(p["cls"], C["export"]), export)

                    def managed_class():
                        e.var("mc_n", e.ld(p["mclasses"]))
                        e.st(e.add(p["mclasses"], e.add(p["mc_n"], 1)), p["cid_"])
                        e.st(e.add(p["mclasses"], e.add(p["mc_n"], 2)), p["c"])
                        e.st(p["mclasses"], e.add(p["mc_n"], 2))

                    e.if_(e.eq(p["cls"], C["managed"]), managed_class)

                e.if_(e.both(e.eq(kind(p["c"]), int(Kind.TARGET)), e.eq(nrefs(p["c"]), 0)), carrier)

            e.for_("cq", 0, nrefs(p["m"]), child)

        e.for_("mq", 0, p["nmod"], module)
        e.var("n_ui", e.add(e.add(e.add(count("ui_plain"), count("ui_resource")), e.add(count("ui_method"), count("ui_argument"))), count("surface")))
        integer = lambda value: lambda: D.integer(e, value)  # noqa: E731
        text_ = lambda value: lambda: D.text(e, value)  # noqa: E731

        def managed_profile():
            """U2 (``ANDROID-MANAGED-PROFILE``); otherwise the managed-class profile (S15e.6h.2c)."""
            others = ("application", "receiver", "service", "libxposed", "managed_entry", "adapter", "install")
            e.var("n_others", p["n_ui"])
            for name in others:
                e.set("n_others", e.add(p["n_others"], count(name)))
            fires = e.either(e.ne(p["n_others"], 0), e.ne(count("manifest"), 1), e.lt(1, count("resources")), e.lt(1, count("declarations")))
            e.if_(fires, lambda: reject(d_lid, "ANDROID-MANAGED-PROFILE",
                                        text_("managed classes + one manifest + 0..1 resources + 0..1 platform declarations + exports"),
                                        lambda: d_dict((("other_carriers", integer(p["n_others"])), ("manifest", integer(count("manifest"))),
                                                        ("resources", integer(count("resources"))), ("declarations", integer(count("declarations")))))))
            e.set("managed", 1)

        e.var("managed", 0)  # the managed-class profile (``_build_android_managed_apk``)
        e.if_(e.ne(count("managed"), 0), managed_profile)
        e.if_(e.both(e.eq(p["managed"], 0), e.ne(count("declarations"), 0)), lambda: reject(lambda: d_cid_rec(at(e, p["firstrecs"], C["declarations"])), "ANDROID-DECLARATIONS-PROFILE",
                                                           text_("the managed-class profile"), text_("a pre-managed APK profile")))  # U3
        e.if_(e.both(e.eq(p["managed"], 0), e.eq(p["t_v3"], 0)), target_rejected)  # U4
        _ok(e, e.both(e.eq(p["t_abi"], ANDROID_ABI), e.either(*(e.eq(p["t_fmt"], f) for f in ANDROID_FORMATS))))  # else the shared object's
        single = ("resources", "application", "receiver", "service", "libxposed", "managed_entry", "adapter", "install", "result", "argument",
                  "combined", "deopt", "services", "preferences", "files", "hot")
        u5 = e.either(e.ne(p["n_ui"], 1), e.ne(count("manifest"), 1), *(e.lt(1, count(name)) for name in single))
        keys = ("ui", "manifest", "resources", "application", "receiver", "service", "libxposed", "libxposed_managed_entry", "libxposed_hook_adapter",
                "libxposed_hook_install", "libxposed_hook_result", "libxposed_hook_argument", "libxposed_hook_combined", "libxposed_deoptimization",
                "libxposed_module_services", "libxposed_remote_preferences", "libxposed_remote_files", "libxposed_hot_reload")
        e.if_(e.both(e.eq(p["managed"], 0), u5), lambda: reject(d_lid, "ANDROID-APK-SEMANTIC-CARRIERS",
                                 lambda: d_dict(tuple((key, integer(1) if k < 2 else text_("0..1")) for k, key in enumerate(keys))),
                                 lambda: d_dict(tuple((key, integer(p["n_ui"] if k == 0 else count(name)))
                                                      for k, (key, name) in enumerate(zip(keys, ("ui", "manifest", *single)))))))  # U5
        e.if_(e.both(e.eq(p["managed"], 0), e.ne(count("ui_resource"), 0), e.ne(count("resources"), 1)), lambda: reject(
            lambda: d_cid_rec(at(e, p["firstrecs"], C["ui_resource"])), "ANDROID-RESOURCE-UI-REQUIRES-TABLE", integer(1), integer(count("resources"))))  # U9

        e = _Slotted((yield), slots)
        p = e.p
        # 5. The manifest (``decode_android_manifest_semantics`` and ``AndroidManifestSpec``).
        e.var("f_body", call("an_tail", first("manifest"), len(PREFIX["manifest"])))
        e.st(G_CUR, 0)
        e.var("f_package", _bstr_at(e, p["f_body"], "f"))
        e.var("f_activity", _bstr_at(e, p["f_body"], "f"))
        for name in ("f_min", "f_target", "f_version"):
            e.var(name, _uleb_at(e, p["f_body"], "f"))
        e.var("f_launcher", _byte_at(e, p["f_body"], "f"))
        _ok(e, e.le(p["f_launcher"], 1))
        e.var("f_debug", 0)
        e.if_(e.lt(e.ld(G_CUR), e.ld(p["f_body"])), lambda: (e.set("f_debug", _byte_at(e, p["f_body"], "f")), _ok(e, e.eq(p["f_debug"], 1))))
        _ok(e, e.eq(e.ld(G_CUR), e.ld(p["f_body"])))
        for name in ("f_package", "f_activity"):
            _ok(e, e.ne(call("an_utf16", p[name]), NONE))
            _ok(e, e.both(e.lt(0, e.ld(p[name])), e.eq(call("an_has", p[name], 0), 0)))
        pk = p["f_package"]
        _ok(e, e.both(e.ne(at(e, pk, 1), ord(".")), e.ne(at(e, pk, e.ld(pk)), ord("."))))
        e.var("pd", 0)
        e.for_("pq", 1, e.ld(pk), lambda: e.if_(e.both(e.eq(at(e, pk, p["pq"]), ord(".")), e.eq(at(e, pk, e.add(p["pq"], 1)), ord("."))),
                                                lambda: e.set("pd", 1)))
        _ok(e, e.eq(p["pd"], 0))
        _ok(e, e.both(e.eq(call("an_has", p["f_activity"], ord("/")), 0), e.eq(call("an_has", p["f_activity"], ord(";")), 0)))
        _ok(e, e.both(e.both(e.le(1, p["f_min"]), e.le(p["f_min"], p["f_target"])), e.le(p["f_target"], MASK32)))
        _ok(e, e.both(e.le(1, p["f_version"]), e.le(p["f_version"], MASK32)))

        # The declarative surface Activity (``decode_android_surface_activity``): no native library, its build entry
        # the empty selector, the package exactly the surface, the manifest and the entry (U6), the Activity identity
        # (U7) and the DEX 039 floor (U8); its APK is the manifest and one DEX.
        def surface():
            e.var("sf_body", call("an_tail", first("surface"), len(PREFIX["surface"])))
            e.st(G_CUR, 0)
            e.var("sf_desc", _bstr_at(e, p["sf_body"], "sf"))
            e.var("sf_text", _bstr_at(e, p["sf_body"], "sf"))
            _ok(e, e.eq(e.ld(G_CUR), e.ld(p["sf_body"])))
            e.var("sf_desc16", call("an_utf16", p["sf_desc"]))
            e.var("sf_text16", call("an_utf16", p["sf_text"]))
            _ok(e, e.both(e.ne(p["sf_desc16"], NONE), e.ne(p["sf_text16"], NONE)))
            _ok(e, e.ne(call("an_desc", p["sf_desc"]), 0))
            _ok(e, e.both(e.lt(0, e.ld(p["sf_text"])), e.eq(call("an_has", p["sf_text"], 0), 0)))
            _ok(e, e.not_(same(p["sf_desc"], K(b"Landroid/app/Activity;"))))
            e.var("sf_selector", e.flag(e.both(*(e.eq(at(e, p["entry"], 1 + w), word) for w, word in enumerate(SELECTOR_WORDS)))))
            e.var("sf_entry", 0)
            e.var("sf_other", 0)
            e.var("sf_kids", e.alloc(e.add(e.mul(p["nobj"], e.mul(p["nmod"], CID_WORDS)), 1)))  # the children's CIDs, each once
            _ok(e, e.ne(p["sf_kids"], NONE))
            e.st(p["sf_kids"], 0)

            def sf_module():
                e.var("sm", find(call("an_incid", e.add(p["mods_at"], e.mul(p["sq"], CID_WORDS)))))

                def sf_child():
                    e.var("sc_at", e.add(e.add(rec(p["sm"]), 2), e.mul(p["sk"], CID_WORDS)))
                    is_ = lambda cid_at_: e.both(*(e.eq(e.rd(e.add(p["sc_at"], w)), e.rd(e.add(cid_at_, w))) for w in range(CID_WORDS)))  # noqa: E731
                    e.var("sc_entry", e.flag(e.both(*(e.eq(e.rd(e.add(p["sc_at"], w)), at(e, p["entry"], 1 + w)) for w in range(CID_WORDS)))))
                    e.if_(e.ne(p["sc_entry"], 0), lambda: e.set("sf_entry", 1))
                    e.if_(e.either(e.ne(p["sc_entry"], 0), is_(cid_at(at(e, p["firstrecs"], C["surface"]))),
                                   is_(cid_at(at(e, p["firstrecs"], C["manifest"])))), lambda: None, lambda: e.set("sf_other", 1))
                    # Kept once each, in CID order (``sorted(cid.hex() ...)``): an insertion into the sorted CIDs.
                    e.var("sc_n", e.ld(p["sf_kids"]))
                    kid = lambda j, w: at(e, p["sf_kids"], e.add(e.add(e.mul(j, CID_WORDS), w), 1))  # noqa: E731
                    word = lambda w: e.rd(e.add(p["sc_at"], w))  # noqa: E731
                    e.var("sc_j", 0)
                    e.var("sc_dup", 0)

                    def before(j):
                        """1 when the child sorts after kid ``j`` (or equals it: a duplicate)."""
                        e.var("sb_r", 2)  # undecided
                        for w in range(CID_WORDS):
                            e.if_(e.eq(p["sb_r"], 2), lambda w=w: e.if_(e.lt(kid(j, w), word(w)), lambda: e.set("sb_r", 1), lambda: e.if_(
                                e.lt(word(w), kid(j, w)), lambda: e.set("sb_r", 0))))
                        e.if_(e.eq(p["sb_r"], 2), lambda: (e.set("sc_dup", 1), e.set("sb_r", 0)))
                        return p["sb_r"]

                    e.var("sc_go", 1)
                    e.while_(lambda: e.ne(p["sc_go"], 0), lambda: e.if_(e.lt(p["sc_j"], p["sc_n"]), lambda: e.if_(
                        e.ne(before(p["sc_j"]), 0), lambda: e.set("sc_j", e.add(p["sc_j"], 1)), lambda: e.set("sc_go", 0)), lambda: e.set("sc_go", 0)))

                    def insert():
                        e.var("sc_m", p["sc_n"])
                        e.while_(lambda: e.lt(p["sc_j"], p["sc_m"]), lambda: (
                            [e.st(e.add(p["sf_kids"], e.add(e.add(e.mul(p["sc_m"], CID_WORDS), w), 1)), kid(e.sub(p["sc_m"], 1), w)) for w in range(CID_WORDS)],
                            e.set("sc_m", e.sub(p["sc_m"], 1))))
                        for w in range(CID_WORDS):
                            e.st(e.add(p["sf_kids"], e.add(e.add(e.mul(p["sc_j"], CID_WORDS), w), 1)), word(w))
                        e.st(p["sf_kids"], e.add(p["sc_n"], 1))

                    e.if_(e.eq(p["sc_dup"], 0), insert)

                e.for_("sk", 0, nrefs(p["sm"]), sf_child)

            def surface_children():
                D.put(e, D.T_LIST)
                D.put(e, e.ld(p["sf_kids"]))
                e.for_("sz", 0, e.ld(p["sf_kids"]), lambda: (D.put(e, D.T_CID), [D.put(e, at(e, p["sf_kids"], e.add(e.add(e.mul(p["sz"], CID_WORDS), w), 1)))
                                                                                for w in range(CID_WORDS)]))

            e.for_("sq", 0, p["nmod"], sf_module)
            e.if_(e.both(e.ne(p["sf_entry"], 0), e.ne(p["sf_selector"], 0), e.eq(p["sf_other"], 0)), lambda: None, lambda: reject(
                d_lid, "SURFACE-DECLARATIVE-CLOSURE", text_("surface + manifest + empty build selector only"), surface_children))  # U6
            fa = p["f_activity"]
            e.var("sf_same", e.flag(e.eq(e.ld(fa), e.sub(e.ld(p["sf_desc"]), 2))))
            e.for_("sa", 0, e.sel(e.ne(p["sf_same"], 0), e.ld(fa), 0), lambda: (
                e.var("sac", at(e, p["sf_desc"], e.add(p["sa"], 2))),
                e.if_(e.ne(at(e, fa, e.add(p["sa"], 1)), e.sel(e.eq(p["sac"], ord("/")), ord("."), p["sac"])), lambda: e.set("sf_same", 0))))
            e.if_(e.eq(p["sf_same"], 0), lambda: reject(lambda: d_cid_rec(at(e, p["firstrecs"], C["manifest"])), "ANDROID-APK-ACTIVITY-IDENTITY",
                                                       lambda: d_str(p["sf_desc"]), lambda: d_str(fa)))  # U7
            e.if_(e.lt(p["f_min"], 28), lambda: reject(lambda: d_cid_rec(at(e, p["firstrecs"], C["manifest"])), "SURFACE-DEX039-MINSDK",
                                                      text_(">= 28"), integer(p["f_min"])))  # U8

            def no_roots():
                e.st(1, 0)
                e.st(0, 1)
                e.give(2)

            e.if_(e.eq(p["mode"], 0), no_roots)
            _ok(e, e.both(e.eq(p["mode"], 1), e.eq(e.rd(p["roots_at"]), 0)))
            put_ = lambda value: call("an_put", value)  # noqa: E731
            seq_ = lambda h: call("an_seqput", h)  # noqa: E731
            e.var("sf_in_manifest", e.ld(G_W))
            put_(0)
            seq_(p["f_package"])
            seq_(p["f_activity"])
            for name in ("f_version", "f_min", "f_target", "f_launcher", "f_debug"):
                put_(p[name])
            for _ in range(4):
                put_(0)  # no application, receivers, services or declarations
            e.var("sf_in_dex", e.ld(G_W))

            def proto_(ret: bytes, *parameters: bytes):
                seq_(K(ret))
                put_(len(parameters))
                for item in parameters:
                    seq_(K(item))

            seq_(p["sf_desc16"])
            seq_(K(b"Landroid/app/Activity;"))
            put_(ACC_PUBLIC_FINAL_CLASS)
            for _ in range(8):
                put_(0)  # no interfaces, library, deferred load, natives, overrides, null returns, constant or echo methods
            put_(1)  # the assembled onCreate (``lower_android_surface_activity``)
            seq_(K(b"onCreate"))
            proto_(b"V", b"Landroid/os/Bundle;")
            put_(4)
            put_(ACC_PUBLIC)
            put_(len(SURFACE_ON_CREATE))
            for opcode, registers, reference in SURFACE_ON_CREATE:
                put_(opcode)
                put_(len(registers))
                for register in registers:
                    put_(register)
                if reference is None:
                    put_(0)
                elif reference == "description":
                    put_(1)
                    seq_(p["sf_text16"])
                elif isinstance(reference, bytes):
                    put_(2)
                    seq_(K(reference))
                else:
                    owner, name, ret, parameters = reference
                    put_(3)
                    seq_(K(owner))
                    seq_(K(name))
                    proto_(ret, *parameters)
                put_(0)  # no literal
            for _ in range(8):
                put_(0)  # no Activity UI, click text or libxposed shapes
            layer(layers["resources"], p["sf_in_manifest"])
            e.var("sf_axml", call("an_record"))
            layer(layers["dex"], p["sf_in_dex"])
            e.var("sf_dex", call("an_record"))
            e.var("sf_in_apk", e.ld(G_W))
            put_(2)
            for name, data in ((b"AndroidManifest.xml", "sf_axml"), (b"classes.dex", "sf_dex")):
                seq_(K(name))
                put_(0)
                put_(ENTRY_ALIGNMENT)
                call("an_blobput", p[data])
            layer(layers["apk"], p["sf_in_apk"])
            e.give(2)  # the driver stops: the APK is the output

        e.if_(e.ne(count("surface"), 0), surface)

        e = _Slotted((yield), slots)
        p = e.p
        e.if_(e.ne(p["managed"], 0), lambda: e.give(1))  # the managed-class profile's phases follow
        # 4. The Activity UI (``decode_android_activity_*ui``): the activity and listener descriptors, two strings (the
        # plain and resource UIs) or three (the method UIs: the method's name, its result or argument, the click text).
        e.var("ui_kind", NONE)
        e.var("ui", 0)
        for k, name in enumerate(UI_KINDS[:4]):
            e.if_(e.ne(count(name), 0), lambda k=k, name=name: (e.set("ui_kind", k), e.set("ui", call("an_tail", first(name), len(PREFIX[name])))))
        plain, resource, method, argument = range(4)
        e.var("u_three", e.flag(e.le(method, p["ui_kind"])))
        e.st(G_CUR, 0)
        names = ("u_activity", "u_listener", "u_initial", "u_value", "u_click")
        for name in names[:3]:
            e.var(name, _bstr_at(e, p["ui"], "u"))
        e.var("u_value", 0)
        e.if_(e.ne(p["u_three"], 0), lambda: e.set("u_value", _bstr_at(e, p["ui"], "u")))
        e.var("u_click", _bstr_at(e, p["ui"], "u"))
        _ok(e, e.eq(e.ld(G_CUR), e.ld(p["ui"])))
        e.if_(e.eq(p["u_three"], 0), lambda: e.set("u_value", p["u_click"]))  # checked twice below; unused
        for name in names:
            e.var(f"{name}16", call("an_utf16", p[name]))
            _ok(e, e.ne(p[f"{name}16"], NONE))
            _ok(e, e.both(e.lt(0, e.ld(p[name])), e.eq(call("an_has", p[name], 0), 0)))
        for name, superclass in (("u_activity", b"Landroid/app/Activity;"), ("u_listener", b"Ljava/lang/Object;")):
            # The carrier's and ``_validate_class_descriptor``'s rules: ``L...;``, longer than 2, no ``.``, no ``//``; the
            # bridge's: not its superclass, and the listener not its interface.
            h = p[name]
            _ok(e, e.both(e.lt(2, e.ld(h)), e.both(e.eq(at(e, h, 1), ord("L")), e.eq(at(e, h, e.ld(h)), ord(";")))))
            _ok(e, e.eq(call("an_has", h, ord(".")), 0))
            e.var("dd", 0)
            e.for_("dk", 1, e.ld(h), lambda h=h: e.if_(e.both(e.eq(at(e, h, p["dk"]), ord("/")), e.eq(at(e, h, e.add(p["dk"], 1)), ord("/"))),
                                                     lambda: e.set("dd", 1)))
            _ok(e, e.eq(p["dd"], 0))
            _ok(e, e.not_(same(h, K(superclass))))
        _ok(e, e.not_(same(p["u_listener"], K(b"Landroid/view/View$OnClickListener;"))))

        def member_name():
            # The method UIs' DEX member name: no ``/ . ; [`` or NUL, and not one of the Activity bridge's own methods.
            for c in "/.;[":
                _ok(e, e.eq(call("an_has", p["u_initial"], ord(c)), 0))
            _ok(e, e.both(e.not_(same(p["u_initial"], K(b"xaxOnCreate"))), e.not_(same(p["u_initial"], K(b"onCreate")))))

        e.if_(e.ne(p["u_three"], 0), member_name)

        def resource_names():
            # ``AndroidStringResource``'s name rule ``[a-z][a-z0-9_]*`` for both names.
            for name in ("u_initial", "u_click"):
                h = p[name]
                e.for_(f"{name}_rk", 1, e.add(e.ld(h), 1), lambda h=h, name=name: (
                    e.var("rc", at(e, h, p[f"{name}_rk"])),
                    _ok(e, e.either(e.both(e.le(ord("a"), p["rc"]), e.le(p["rc"], ord("z"))),
                                    e.both(e.lt(1, p[f"{name}_rk"]), e.either(e.both(e.le(ord("0"), p["rc"]), e.le(p["rc"], ord("9"))),
                                                                             e.eq(p["rc"], ord("_"))))))))

        e.if_(e.eq(p["ui_kind"], resource), resource_names)

        # The resource table (``decode_android_resources_semantics``, ``AndroidResourceSpec``): the package, then the
        # strings in their canonical order (by name, without duplicates), each name ``[a-z][a-z0-9_]*``.
        e.var("r_package", 0)
        e.var("r_names", 0)
        e.var("r_values", 0)

        def resources():
            e.var("r_body", call("an_tail", first("resources"), len(PREFIX["resources"])))
            e.st(G_CUR, 0)
            e.set("r_package", _bstr_at(e, p["r_body"], "r"))
            e.var("r_n", _uleb_at(e, p["r_body"], "r"))
            _ok(e, e.both(e.lt(0, p["r_n"]), e.le(p["r_n"], e.ld(p["r_body"]))))
            e.set("r_names", e.alloc(e.add(p["r_n"], 1)))
            e.set("r_values", e.alloc(e.add(p["r_n"], 1)))
            _ok(e, e.both(e.ne(p["r_names"], NONE), e.ne(p["r_values"], NONE)))
            e.st(p["r_names"], p["r_n"])
            e.st(p["r_values"], p["r_n"])

            def string():
                e.var("rn", _bstr_at(e, p["r_body"], "r"))
                e.var("rv", _bstr_at(e, p["r_body"], "r"))
                e.st(e.add(p["r_names"], e.add(p["ri"], 1)), p["rn"])
                e.st(e.add(p["r_values"], e.add(p["ri"], 1)), p["rv"])
                _ok(e, e.both(e.ne(call("an_utf16", p["rn"]), NONE), e.ne(call("an_utf16", p["rv"]), NONE)))
                _ok(e, e.both(e.lt(0, e.ld(p["rn"])), e.eq(call("an_has", p["rv"], 0), 0)))
                e.for_("rk", 1, e.add(e.ld(p["rn"]), 1), lambda: (
                    e.var("rc", at(e, p["rn"], p["rk"])),
                    _ok(e, e.either(e.both(e.le(ord("a"), p["rc"]), e.le(p["rc"], ord("z"))),
                                    e.both(e.lt(1, p["rk"]), e.either(e.both(e.le(ord("0"), p["rc"]), e.le(p["rc"], ord("9"))), e.eq(p["rc"], ord("_"))))))))
                e.if_(e.lt(0, p["ri"]), lambda: _ok(e, e.ne(call("an_less", at(e, p["r_names"], p["ri"]), p["rn"]), 0)))

            e.for_("ri", 0, p["r_n"], string)
            _ok(e, e.eq(e.ld(G_CUR), e.ld(p["r_body"])))
            rp = p["r_package"]
            e.var("r_units", call("an_utf16", rp))
            _ok(e, e.ne(p["r_units"], NONE))
            _ok(e, e.le(e.ld(p["r_units"]), 127))
            _ok(e, e.both(e.lt(0, e.ld(rp)), e.eq(call("an_has", rp, 0), 0)))
            _ok(e, e.both(e.ne(at(e, rp, 1), ord(".")), e.ne(at(e, rp, e.ld(rp)), ord("."))))
            e.var("rd", 0)
            e.for_("rq", 1, e.ld(rp), lambda: e.if_(e.both(e.eq(at(e, rp, p["rq"]), ord(".")), e.eq(at(e, rp, e.add(p["rq"], 1)), ord("."))),
                                                    lambda: e.set("rd", 1)))
            _ok(e, e.eq(p["rd"], 0))

        e.if_(e.eq(count("resources"), 1), resources)

        # The components (``decode_android_application``, ``decode_android_broadcast_receiver``, ``decode_android_service``):
        # each a DEX class descriptor (not its bridge's superclass; its Java name a manifest class name), the receiver's
        # exported flag and action (empty: none), the service's exported flag.
        for stem in ("a", "v", "s"):
            e.var(f"{stem}_desc", 0)
            e.var(f"{stem}_desc16", 0)
            e.var(f"{stem}_exported", 0)
            e.var(f"{stem}_java", 0)
        e.var("v_action", 0)

        def component(name: str, stem: str, superclass: bytes, exported: bool, action: bool):
            body = f"{stem}_body"
            e.var(body, call("an_tail", first(name), len(PREFIX[name])))
            e.st(G_CUR, 0)
            e.set(f"{stem}_desc", _bstr_at(e, p[body], stem))
            if exported:
                e.set(f"{stem}_exported", _byte_at(e, p[body], stem))
                _ok(e, e.le(p[f"{stem}_exported"], 1))
            if action:
                e.set("v_action", _bstr_at(e, p[body], stem))
                _ok(e, e.ne(call("an_utf16", p["v_action"]), NONE))
                _ok(e, e.eq(call("an_has", p["v_action"], 0), 0))
            _ok(e, e.eq(e.ld(G_CUR), e.ld(p[body])))
            d = p[f"{stem}_desc"]
            e.set(f"{stem}_desc16", call("an_utf16", d))
            _ok(e, e.ne(p[f"{stem}_desc16"], NONE))
            _ok(e, e.ne(call("an_desc", d), 0))
            _ok(e, e.not_(same(d, K(superclass))))
            e.for_(f"{stem}_sk", 2, e.ld(d), lambda: _ok(e, e.ne(at(e, d, p[f"{stem}_sk"]), ord(";"))))
            e.set(f"{stem}_java", call("an_java", d))  # before any layer input is written (the writer fills the arena's top)

        e.if_(e.ne(count("application"), 0), lambda: component("application", "a", b"Landroid/app/Application;", False, False))
        e.if_(e.ne(count("receiver"), 0), lambda: component("receiver", "v", b"Landroid/content/BroadcastReceiver;", True, True))
        e.if_(e.ne(count("service"), 0), lambda: component("service", "s", b"Landroid/app/Service;", True, False))

        e = _Slotted((yield), slots)
        p = e.p
        e.if_(e.ne(p["managed"], 0), lambda: e.give(1))  # the managed-class profile's phases follow
        # The libxposed carriers (``xax_libxposed``), each decoded with its description's rules; a Java binary name past
        # ASCII declines.
        def body(name: str, stem: str):
            e.var(f"{stem}_body", call("an_tail", first(name), len(PREFIX[name])))
            e.st(G_CUR, 0)
            return p[f"{stem}_body"]

        def done(h):
            _ok(e, e.eq(e.ld(G_CUR), e.ld(h)))

        def utf8(h):
            _ok(e, e.ne(call("an_utf16", h), NONE))

        def texts_at(h, stem: str):
            """``_get_texts``: a count, then the strings; the list handle ``[n, handles...]``."""
            e.var(f"{stem}_tn", _uleb_at(e, h, stem))
            _ok(e, e.le(p[f"{stem}_tn"], e.ld(h)))
            e.var(f"{stem}_tl", e.alloc(e.add(p[f"{stem}_tn"], 1)))
            _ok(e, e.ne(p[f"{stem}_tl"], NONE))
            e.st(p[f"{stem}_tl"], p[f"{stem}_tn"])
            e.for_(f"{stem}_tk", 0, p[f"{stem}_tn"], lambda: (
                e.var(f"{stem}_ti", _bstr_at(e, h, f"{stem}t")), utf8(p[f"{stem}_ti"]),
                e.st(e.add(p[f"{stem}_tl"], e.add(p[f"{stem}_tk"], 1)), p[f"{stem}_ti"])))
            return p[f"{stem}_tl"]

        def canonical_texts(lst, stem: str, rule=None):
            """``_canonical_text``: single-line entries, sorted by their bytes, without duplicates (each ``rule`` too)."""
            e.for_(f"{stem}_ck", 1, e.add(e.ld(lst), 1), lambda: (
                _ok(e, e.ne(call("an_line", at(e, lst, p[f"{stem}_ck"])), 0)),
                rule(at(e, lst, p[f"{stem}_ck"])) if rule else None,
                e.if_(e.lt(1, p[f"{stem}_ck"]), lambda: _ok(e, e.ne(call("an_less", at(e, lst, e.sub(p[f"{stem}_ck"], 1)),
                                                                                    at(e, lst, p[f"{stem}_ck"])), 0)))))

        def selection(lst, allowed: tuple, stem: str):
            """A selection in its canonical order (the allowed order, without duplicates, nonempty); its bit mask."""
            e.var(f"{stem}_mask", 0)
            e.var(f"{stem}_last", NONE)
            _ok(e, e.lt(0, e.ld(lst)))

            def item():
                e.var(f"{stem}_ix", NONE)
                for k, value in enumerate(allowed):
                    e.if_(same(at(e, lst, p[f"{stem}_sk"]), K(value)), lambda k=k: e.set(f"{stem}_ix", k))
                _ok(e, e.ne(p[f"{stem}_ix"], NONE))
                _ok(e, e.either(e.eq(p[f"{stem}_last"], NONE), e.lt(p[f"{stem}_last"], p[f"{stem}_ix"])))
                e.set(f"{stem}_last", p[f"{stem}_ix"])
                e.set(f"{stem}_mask", e.or_(p[f"{stem}_mask"], _pow2_small(e, p[f"{stem}_ix"])))

            e.for_(f"{stem}_sk", 1, e.add(e.ld(lst), 1), item)
            return p[f"{stem}_mask"]

        def string_parameter(lst):
            """``()`` or ``("java.lang.String",)``."""
            _ok(e, e.le(e.ld(lst), 1))
            e.if_(e.eq(e.ld(lst), 1), lambda: _ok(e, same(at(e, lst, 1), K(b"java.lang.String"))))

        def method_name(h, bracket: bool = False):
            _ok(e, e.lt(0, e.ld(h)))
            for c in "\x00/.;" + ("[" if bracket else ""):
                _ok(e, e.eq(call("an_has", h, ord(c)), 0))

        def jname(h):
            _ok(e, e.ne(call("an_jname", h), 0))

        for name in ("l_min", "l_target", "l_static", "l_java", "l_native", "l_scopes", "m_name", "m_callbacks", "m_mask", "m_desc", "sv_mask", "pf_mask",
                     "fl_mask", "h_id", "ad_name", "ad_index", "ad_desc", "in_class", "in_method", "in_hooker", "in_lifetime", "in_retained",
                     "in_params", "in_hook", "in_desc", "dp_class", "dp_method", "dp_params"):
            e.var(name, 0)
        for stem in ("rs", "ag", "cb"):
            for field in ("hooker", "class", "method", "repl", "rrepl", "index"):
                e.var(f"{stem}_{field}", 0)

        def module_carrier():
            h = body("libxposed", "l")
            e.set("l_min", _uleb_at(e, h, "l"))
            e.set("l_target", _uleb_at(e, h, "l"))
            e.set("l_static", _byte_at(e, h, "l"))
            _ok(e, e.le(p["l_static"], 1))
            e.set("l_java", texts_at(h, "lj"))
            e.set("l_native", texts_at(h, "ln"))
            e.set("l_scopes", texts_at(h, "ls"))
            done(h)
            _ok(e, e.both(e.both(e.le(1, p["l_min"]), e.le(p["l_min"], p["l_target"])), e.le(p["l_target"], MASK32)))
            canonical_texts(p["l_java"], "lj")
            canonical_texts(p["l_native"], "ln", lambda item: _ok(e, e.both(e.eq(call("an_has", item, ord("/")), 0),
                                                                            e.eq(call("an_has", item, ord("\\")), 0))))
            canonical_texts(p["l_scopes"], "ls")
            _ok(e, e.lt(0, e.ld(p["l_java"])))

        def managed_entry_carrier():
            h = body("managed_entry", "m")
            e.set("m_name", _bstr_at(e, h, "m"))
            e.set("m_callbacks", texts_at(h, "mc"))
            done(h)
            jname(p["m_name"])
            e.set("m_mask", selection(p["m_callbacks"], CALLBACKS, "mc"))
            _ok(e, e.ne(p["m_mask"], 2))  # onPackageReady requires onModuleLoaded
            e.set("m_desc", call("an_dotted", p["m_name"]))

        def services_carrier():
            h = body("services", "sv")
            e.var("sv_list", texts_at(h, "svl"))
            e.var("sv_policy", _bstr_at(e, h, "sv"))
            done(h)
            e.set("sv_mask", selection(p["sv_list"], SERVICES, "svl"))
            _ok(e, same(p["sv_policy"], K(b"propagate")))

        def policies(h, stem: str, *values: bytes):
            for k, value in enumerate(values):
                e.var(f"{stem}_p{k}", _bstr_at(e, h, stem))
                _ok(e, same(p[f"{stem}_p{k}"], K(value)))

        def preferences_carrier():
            h = body("preferences", "pf")
            e.var("pf_list", texts_at(h, "pfl"))
            policies(h, "pf", b"nullable-on-unsupported", b"propagate")
            done(h)
            e.set("pf_mask", selection(p["pf_list"], READS, "pfl"))

        def files_carrier():
            h = body("files", "fl")
            e.var("fl_list", texts_at(h, "fll"))
            policies(h, "fl", b"nullable-on-unsupported", b"propagate")
            done(h)
            e.set("fl_mask", selection(p["fl_list"], FILE_OPERATIONS, "fll"))

        def hot_carrier():
            h = body("hot", "h")
            for k, value in enumerate(HOT_POLICIES):
                e.var(f"h_v{k}", _bstr_at(e, h, "h"))
                utf8(p[f"h_v{k}"])
                if value is None:
                    e.set("h_id", p[f"h_v{k}"])
                    _ok(e, e.ne(call("an_line", p["h_id"]), 0))
                else:
                    _ok(e, same(p[f"h_v{k}"], K(value)))
            done(h)

        def adapter_carrier():
            h = body("adapter", "ad")
            e.set("ad_name", _bstr_at(e, h, "ad"))
            e.set("ad_index", _uleb_at(e, h, "ad"))
            done(h)
            jname(p["ad_name"])
            _ok(e, e.le(p["ad_index"], 8))  # 8 is "no inspection"
            e.set("ad_desc", call("an_dotted", p["ad_name"]))

        def policy_carrier(name: str, stem: str, count_: int, mode: bytes, parameter: bool):
            h = body(name, stem)
            for k in range(count_):
                e.var(f"{stem}_v{k}", _bstr_at(e, h, stem))
                utf8(p[f"{stem}_v{k}"])
            if parameter:
                e.set(f"{stem}_index", _uleb_at(e, h, stem))
                _ok(e, e.eq(p[f"{stem}_index"], 0))
            done(h)
            v = lambda k: p[f"{stem}_v{k}"]  # noqa: E731
            e.set(f"{stem}_hooker", v(0))
            e.set(f"{stem}_class", v(1))
            e.set(f"{stem}_method", v(2))
            jname(v(0))
            jname(v(1))
            method_name(v(2))
            _ok(e, same(v(3), K(b"Ljava/lang/String;")))
            if parameter:
                _ok(e, same(v(4), K(b"Ljava/lang/String;")))
            replacements = (5, 6) if count_ == 8 else ((5,) if parameter else (4,))
            for k in replacements:
                _ok(e, e.both(e.lt(0, e.ld(v(k))), e.eq(call("an_has", v(k), 0), 0)))
            e.set(f"{stem}_repl", v(replacements[0]))
            e.set(f"{stem}_rrepl", v(replacements[-1]))
            _ok(e, same(v(count_ - 1), K(mode)))

        def deopt_carrier():
            h = body("deopt", "dp")
            e.set("dp_class", _bstr_at(e, h, "dp"))
            e.set("dp_method", _bstr_at(e, h, "dp"))
            e.set("dp_params", texts_at(h, "dpp"))
            e.var("dp_policy", _bstr_at(e, h, "dp"))
            done(h)
            utf8(p["dp_class"])
            utf8(p["dp_method"])
            jname(p["dp_class"])
            method_name(p["dp_method"])
            string_parameter(p["dp_params"])
            _ok(e, same(p["dp_policy"], K(b"best-effort")))

        def install_carrier():
            h = body("install", "in")
            for name in ("in_class", "in_method", "in_hooker", "in_exception", "in_failure", "in_lifetime"):
                e.var(name, _bstr_at(e, h, "in"))
                utf8(p[name])
            e.set("in_params", texts_at(h, "inp"))
            e.if_(e.lt(e.ld(G_CUR), e.ld(h)), lambda: (e.set("in_hook", _bstr_at(e, h, "in")), utf8(p["in_hook"])))
            done(h)
            jname(p["in_class"])
            jname(p["in_hooker"])
            method_name(p["in_method"], bracket=True)  # and ``_validate_member_name`` when it is lowered
            string_parameter(p["in_params"])
            _ok(e, same(p["in_exception"], K(b"PROTECTIVE")))
            _ok(e, same(p["in_failure"], K(b"propagate")))
            e.set("in_retained", e.flag(same(p["in_lifetime"], K(b"retained-manual-unhook"))))
            _ok(e, e.either(e.ne(p["in_retained"], 0), same(p["in_lifetime"], K(b"process"))))
            e.if_(e.ne(p["in_hook"], 0), lambda: (_ok(e, e.ne(p["in_retained"], 0)), _ok(e, e.ne(call("an_line", p["in_hook"]), 0))))
            e.set("in_desc", call("an_dotted", p["in_hooker"]))

        for name, decode in (("libxposed", module_carrier), ("managed_entry", managed_entry_carrier), ("services", services_carrier),
                             ("preferences", preferences_carrier), ("files", files_carrier), ("hot", hot_carrier), ("adapter", adapter_carrier),
                             ("install", install_carrier), ("deopt", deopt_carrier)):
            e.if_(e.ne(count(name), 0), decode)
        e.if_(e.ne(count("result"), 0), lambda: policy_carrier("result", "rs", 6, b"replace_after_proceed", False))
        e.if_(e.ne(count("argument"), 0), lambda: policy_carrier("argument", "ag", 7, b"replace_before_proceed", True))
        e.if_(e.ne(count("combined"), 0), lambda: policy_carrier("combined", "cb", 8, b"replace_argument_then_result", True))

        e = _Slotted((yield), slots)
        p = e.p
        e.if_(e.ne(p["managed"], 0), lambda: e.give(1))  # the managed-class profile's phases follow
        # 6. The resource IDs (``resource_id``: ``0x7F010000`` plus the name's index; NONE for a name the table lacks,
        # rejected after the rule sites, where the bootstrap lowers), the JNI symbols and the exports they name.
        def resource_id(name, out):
            e.var(out, NONE)
            e.for_(f"{out}_k", 0, e.ld(p["r_names"]), lambda: e.if_(same(at(e, p["r_names"], e.add(p[f"{out}_k"], 1)), p[name]),
                                                                   lambda: e.set(out, e.add(0x7F010000, p[f"{out}_k"]))))
            return p[out]

        e.var("id_initial", 0)
        e.var("id_click", 0)
        e.if_(e.eq(p["ui_kind"], resource), lambda: (e.set("id_initial", resource_id("u_initial", "ri_initial")),
                                                     e.set("id_click", resource_id("u_click", "ri_click"))))
        e.var("s_activity", call("an_jni", p["u_activity16"], K(b"xaxOnCreate")))
        e.var("s_listener", call("an_jni", p["u_listener16"], K(b"xaxOnClick")))

        def export_of(symbol, name):
            """The last export named ``symbol`` (the bootstrap's ``by_name``): its function CID handle, or 0."""
            e.var(name, 0)
            e.for_(f"{name}_k", 0, e.udiv(e.ld(p["exports"]), 2), lambda: e.if_(
                same(at(e, p["exports"], e.add(1, e.mul(p[f"{name}_k"], 2))), symbol),
                lambda: e.set(name, at(e, p["exports"], e.add(2, e.mul(p[f"{name}_k"], 2))))))
            return p[name]

        export_of(p["s_activity"], "xa")

        # The lowering's own checks (``lower_libxposed_managed_entry``, ``lower_libxposed_hook_adapter`` and the DEX
        # specifications): the program declines where the bootstrap raises.
        def managed_lowering():
            _ok(e, e.not_(same(p["m_desc"], K(XPOSED_MODULE))))

            def install():
                _ok(e, e.ne(e.and_(p["m_mask"], 2), 0))
                _ok(e, e.not_(same(p["in_desc"], p["m_desc"])))

            e.if_(e.ne(count("install"), 0), install)
            e.if_(e.ne(count("deopt"), 0), lambda: (
                _ok(e, e.ne(count("install"), 0)), _ok(e, same(p["dp_class"], p["in_class"])), _ok(e, same(p["dp_method"], p["in_method"])),
                _ok(e, e.eq(e.ld(p["dp_params"]), e.ld(p["in_params"])))))
            e.if_(e.ne(count("hot"), 0), lambda: (
                _ok(e, e.ne(count("install"), 0)), _ok(e, e.ne(p["in_retained"], 0)), _ok(e, e.ne(p["in_hook"], 0)),
                _ok(e, same(p["in_hook"], p["h_id"]))))


        def adapter_lowering():
            _ok(e, e.le(e.add(count("result"), e.add(count("argument"), count("combined"))), 1))
            _ok(e, e.both(e.not_(same(p["ad_desc"], K(b"Ljava/lang/Object;"))), e.not_(same(p["ad_desc"], K(HOOKER)))))
            e.if_(e.ne(count("result"), 0), lambda: (_ok(e, same(p["rs_hooker"], p["ad_name"])), _ok(e, e.eq(p["ad_index"], 8))))
            for stem, name in (("ag", "argument"), ("cb", "combined")):
                e.if_(e.ne(count(name), 0), lambda stem=stem: (_ok(e, same(p[f"{stem}_hooker"], p["ad_name"])), _ok(e, e.eq(p["ad_index"], 0))))


        # The rule sites' diagnostics (``xax_build._build_android_unsigned_apk``), by the rules program's verdict.
        rec_of = lambda name: lambda: d_cid_rec(at(e, p["firstrecs"], C[name]))  # noqa: E731
        string = lambda name: lambda: d_str(p[name])  # noqa: E731
        present = lambda name: lambda: d_bool(e.flag(e.ne(count(name), 0)))  # noqa: E731

        def strings(*names):
            return lambda: d_list(tuple(string(name) for name in names))

        def listed(lst):
            def write():
                D.put(e, D.T_LIST)
                D.put(e, e.ld(lst))
                e.for_("ls_k", 1, e.add(e.ld(lst), 1), lambda: d_str(at(e, lst, p["ls_k"])))
            return write

        def index_of(name):
            """The adapter's inspected argument index, ``None`` for 8."""
            return lambda: e.if_(e.eq(p[name], 8), lambda: D.none(e), lambda: D.integer(e, p[name]))

        def closure(entity, keys):
            return lambda: d_dict(tuple((key, present(name)) for key, name in keys))

        def names_sorted():
            """``sorted(name.decode("ascii", "replace") for name in by_name)``: the export names, each once, in order."""
            def write():
                e.var("ns", e.alloc(e.add(e.ld(p["exports"]), 1)))
                _ok(e, e.ne(p["ns"], NONE))
                e.st(p["ns"], 0)

                def add():
                    e.var("nn", at(e, p["exports"], e.add(1, e.mul(p["nq"], 2))))
                    e.var("nj", 0)
                    e.var("ndup", 0)
                    e.var("ngo", 1)
                    e.while_(lambda: e.both(e.ne(p["ngo"], 0), e.lt(p["nj"], e.ld(p["ns"]))), lambda: e.if_(
                        same(at(e, p["ns"], e.add(p["nj"], 1)), p["nn"]), lambda: (e.set("ndup", 1), e.set("ngo", 0)), lambda: e.if_(
                            e.ne(call("an_less", at(e, p["ns"], e.add(p["nj"], 1)), p["nn"]), 0), lambda: e.set("nj", e.add(p["nj"], 1)),
                            lambda: e.set("ngo", 0))))

                    def insert():
                        e.var("nm", e.ld(p["ns"]))
                        e.while_(lambda: e.lt(p["nj"], p["nm"]), lambda: (e.st(e.add(p["ns"], e.add(p["nm"], 1)), at(e, p["ns"], p["nm"])),
                                                                         e.set("nm", e.sub(p["nm"], 1))))
                        e.st(e.add(p["ns"], e.add(p["nj"], 1)), p["nn"])
                        e.st(p["ns"], e.add(e.ld(p["ns"]), 1))

                    e.if_(e.eq(p["ndup"], 0), insert)

                e.for_("nq", 0, e.udiv(e.ld(p["exports"]), 2), add)
                listed(p["ns"])()
            return write

        def jni_text(desc, method: bytes):
            """A JNI symbol's text: ``desc`` names UTF-16 units (``*16``) or the descriptor's bytes."""
            units = lambda: p[desc] if desc.endswith("16") else call("an_utf16", p[desc])  # noqa: E731
            return lambda: d_str(call("an_jni", units(), K(method)))

        java_activity = lambda: d_str(call("an_java", p["u_activity"]))  # noqa: E731
        api = lambda: D.integer(e, 102)  # noqa: E731
        both_policy = lambda: d_dict((("adapter", present("adapter")), ("installation", present("install"))))  # noqa: E731
        metadata_entry = (("metadata", "libxposed"), ("managed_entry", "managed_entry"))
        SITES = {
            10: (rec_of("manifest"), java_activity, string("f_activity")),
            11: (rec_of("manifest"), text_(">= 21"), integer(p["f_min"])),
            12: (rec_of("resources"), string("f_package"), string("r_package")),
            13: (rec_of("managed_entry"), text_("matching libxposed module metadata carrier"), text_("missing")),
            14: (d_lid, text_("libxposed metadata plus generated managed entry"), text_("missing")),
            15: (d_lid, text_("one hook adapter plus one hook installation"), lambda: d_dict((("adapter", present("adapter")), ("installation", present("install"))))),
            16: (d_lid, text_("one mutation policy carrier"), lambda: (
                D.put(e, D.T_LIST), D.put(e, e.add(1, e.add(count("argument"), count("combined")))), D.text(e, "result"),
                e.if_(e.ne(count("argument"), 0), lambda: D.text(e, "argument")), e.if_(e.ne(count("combined"), 0), lambda: D.text(e, "combined")))),
            17: (rec_of("result"), text_("hook adapter plus hook installation"), both_policy),
            18: (rec_of("result"), string("ad_name"), string("rs_hooker")),
            19: (rec_of("result"), strings("in_class", "in_method"), strings("rs_class", "rs_method")),
            20: (rec_of("result"), lambda: D.none(e), index_of("ad_index")),
            21: (d_lid, text_("one mutation policy carrier"), lambda: d_list((text_("argument"), text_("combined")))),
            22: (rec_of("argument"), text_("hook adapter plus hook installation"), both_policy),
            23: (rec_of("argument"), string("ad_name"), string("ag_hooker")),
            24: (rec_of("argument"), strings("in_class", "in_method"), strings("ag_class", "ag_method")),
            25: (rec_of("argument"), integer(p["ag_index"]), index_of("ad_index")),
            26: (rec_of("install"), lambda: d_list((text_("java.lang.String"),)), listed(p["in_params"])),
            27: (rec_of("combined"), text_("hook adapter plus hook installation"), both_policy),
            28: (rec_of("combined"), string("ad_name"), string("cb_hooker")),
            29: (rec_of("combined"), strings("in_class", "in_method"), strings("cb_class", "cb_method")),
            30: (rec_of("combined"), integer(p["cb_index"]), index_of("ad_index")),
            31: (rec_of("install"), lambda: d_list((text_("java.lang.String"),)), listed(p["in_params"])),
            32: (rec_of("deopt"), text_("companion hook installation"), lambda: D.none(e)),
            33: (rec_of("deopt"), lambda: d_dict((("class", string("in_class")), ("method", string("in_method")), ("parameters", listed(p["in_params"])))),
                 lambda: d_dict((("class", string("dp_class")), ("method", string("dp_method")), ("parameters", listed(p["dp_params"]))))),
            34: (rec_of("libxposed"), api, integer(p["l_target"])),
            35: (rec_of("libxposed"), api, integer(p["l_min"])),
            36: (rec_of("install"), string("ad_name"), string("in_hooker")),
            37: (rec_of("managed_entry"), text_("onPackageReady"), listed(p["m_callbacks"])),
            38: (rec_of("adapter"), text_("pure Chain.proceed() with no argument inspection"), index_of("ad_index")),
            39: (rec_of("services"), text_("libxposed metadata plus generated managed entry"), closure(None, metadata_entry)),
            40: (rec_of("libxposed"), api, integer(p["l_target"])),
            41: (rec_of("preferences"), text_("libxposed metadata plus generated managed entry"), closure(None, metadata_entry)),
            42: (rec_of("libxposed"), api, integer(p["l_target"])),
            43: (rec_of("files"), text_("libxposed metadata plus generated managed entry"), closure(None, metadata_entry)),
            44: (rec_of("libxposed"), api, integer(p["l_target"])),
            45: (rec_of("hot"), text_("API-102 metadata, one managed entry, and one retained hook installation"),
                 closure(None, (*metadata_entry, ("hook_install", "install")))),
            46: (rec_of("libxposed"), lambda: d_dict((("min", api), ("target", api))),
                 lambda: d_dict((("min", integer(p["l_min"])), ("target", integer(p["l_target"]))))),
            47: (rec_of("libxposed"), integer(1), integer(e.ld(p["l_java"]))),
            48: (rec_of("install"), text_("retained-manual-unhook"), string("in_lifetime")),
            49: (rec_of("install"), string("h_id"), lambda: e.if_(e.eq(p["in_hook"], 0), lambda: D.none(e), lambda: d_str(p["in_hook"]))),
            50: (rec_of("libxposed"), text_("one generated XposedModule managed entry carrier"), listed(p["l_java"])),
            51: (rec_of("libxposed"), lambda: d_list((string("m_name"),)), listed(p["l_java"])),
            52: (rec_of("libxposed"), lambda: d_list((string("m_name"),)), lambda: d_list(())),
            53: (rec_of("libxposed"), lambda: d_list((text_("libxaxapp.so"),)), listed(p["l_native"])),
            54: (d_lid, lambda: d_list((jni_text("u_activity16", b"xaxOnCreate"), jni_text("u_listener16", b"xaxOnClick"))), names_sorted()),
            55: (d_lid, jni_text("a_desc16", b"xaxOnCreate"), names_sorted()),
            56: (d_lid, jni_text("v_desc16", b"xaxOnReceive"), names_sorted()),
            57: (d_lid, lambda: d_list((jni_text("s_desc16", b"xaxOnCreate"), jni_text("s_desc16", b"xaxOnDestroy"))), names_sorted()),
            58: (d_lid, lambda: e.if_(e.ne(e.and_(p["m_mask"], 2), 0), lambda: d_list((jni_text("m_desc", b"xaxOnModuleLoaded"),
                                                                                       jni_text("m_desc", b"xaxOnPackageReady"))),
                                      lambda: d_list((jni_text("m_desc", b"xaxOnModuleLoaded"),))), names_sorted()),
            59: (d_lid, text_("exported native_init in libxaxapp.so"), names_sorted()),
            60: (d_lid, lambda: call("an_dcid", p["entry"]), lambda: call("an_dcid", p["xa"])),
        }

        def rules_rejection(verdict, sites):
            from xax_selfhost_android_rules import SITES as RULES

            for k in sites:
                entity, expected, actual = SITES[k]
                e.if_(e.eq(verdict, k), lambda k=k, entity=entity, expected=expected, actual=actual: reject(entity, RULES[k - 1], expected, actual))

        # The rules program (S15e.6f.1) decides the profile's 60 rule sites on the facts ``_facts`` gives it.
        text = lambda h: call("an_seqput", h)  # noqa: E731 - a constant's bytes are its UTF-16 units
        text8 = lambda h: call("an_seqput", call("an_utf16", h))  # noqa: E731
        flag = lambda name: e.if_(e.ne(count(name), 0), lambda: (put(1), put(0)), lambda: put(0))  # noqa: E731

        def text_or_empty(name, h):
            e.if_(e.ne(count(name), 0), lambda: text8(h), lambda: put(0))

        def texts8(name, lst):
            e.if_(e.ne(count(name), 0), lambda: (put(e.ld(lst)), e.for_("txk", 1, e.add(e.ld(lst), 1), lambda: text8(at(e, lst, p["txk"])))),
                  lambda: put(0))

        def cid_data(h):
            put(32)
            for w in range(CID_WORDS):
                for i in range(8):
                    put(e.and_(e.udiv(at(e, h, 1 + w), 1 << (56 - 8 * i)), 255))

        e.var("in_facts", e.ld(G_W))
        put(0)  # the v3 target
        put(e.ld(p["kids"]))
        e.for_("fk", 1, e.add(e.ld(p["kids"]), 1), lambda: (
            e.var("fkh", at(e, p["kids"], p["fk"])),
            e.var("fkn", e.sel(e.lt(e.ld(p["fkh"]), 64), e.ld(p["fkh"]), 64)),
            put(p["fkn"]), e.for_("fj", 1, e.add(p["fkn"], 1), lambda: put(at(e, p["fkh"], p["fj"])))))
        put(1)
        for _ in range(7):
            put(0)  # not the declarative surface
        text(p["u_activity16"])
        text8(p["f_activity"])
        put(p["f_min"])
        text8(p["f_package"])
        e.if_(e.ne(p["r_package"], 0), lambda: (put(1), text8(p["r_package"])), lambda: put(0))
        e.if_(e.ne(count("adapter"), 0), lambda: (put(1), text8(p["ad_name"])), lambda: put(0))
        e.if_(e.both(e.ne(count("adapter"), 0), e.ne(p["ad_index"], 8)), lambda: (put(1), put(1), put(p["ad_index"])), lambda: put(0))
        flag("install")
        for name in ("in_class", "in_method", "in_hooker", "in_lifetime"):
            text_or_empty("install", p[name])
        texts8("install", p["in_params"])
        e.if_(e.ne(p["in_hook"], 0), lambda: (put(1), text8(p["in_hook"])), lambda: put(0))
        for stem, name in (("rs", "result"), ("ag", "argument"), ("cb", "combined")):
            flag(name)
            for field in ("hooker", "class", "method"):
                text_or_empty(name, p[f"{stem}_{field}"])
            put(p[f"{stem}_index"])
        flag("deopt")
        text_or_empty("deopt", p["dp_class"])
        text_or_empty("deopt", p["dp_method"])
        texts8("deopt", p["dp_params"])
        flag("libxposed")
        put(p["l_target"])
        put(p["l_min"])
        texts8("libxposed", p["l_java"])
        texts8("libxposed", p["l_native"])
        e.if_(e.ne(count("managed_entry"), 0), lambda: (put(1), text8(p["m_name"])), lambda: put(0))
        e.if_(e.ne(count("managed_entry"), 0), lambda: (put(e.ld(p["m_callbacks"])), e.for_("mk", 1, e.add(e.ld(p["m_callbacks"]), 1),
                                                                                           lambda: text8(at(e, p["m_callbacks"], p["mk"])))),
              lambda: put(0))
        e.if_(e.ne(count("hot"), 0), lambda: (put(1), text8(p["h_id"])), lambda: put(0))
        put(1)  # the lowered bridges
        text(p["u_activity16"])
        text(K(b"xaxOnCreate"))
        text(p["u_listener16"])
        text(K(b"xaxOnClick"))
        e.if_(e.ne(count("application"), 0), lambda: (put(2), text(p["a_desc16"]), text(K(b"xaxOnCreate"))), lambda: put(0))
        e.if_(e.ne(count("receiver"), 0), lambda: (put(2), text(p["v_desc16"]), text(K(b"xaxOnReceive"))), lambda: put(0))
        e.if_(e.ne(count("service"), 0), lambda: (put(3), text(p["s_desc16"]), text(K(b"xaxOnCreate")), text(K(b"xaxOnDestroy"))), lambda: put(0))
        e.if_(e.ne(count("managed_entry"), 0), lambda: (
            put(e.add(2, e.flag(e.ne(e.and_(p["m_mask"], 2), 0)))), text8(p["m_desc"]), text(K(b"xaxOnModuleLoaded")),
            e.if_(e.ne(e.and_(p["m_mask"], 2), 0), lambda: text(K(b"xaxOnPackageReady")))), lambda: put(0))
        put(e.ld(p["exports"]))
        e.for_("fe", 0, e.udiv(e.ld(p["exports"]), 2), lambda: (call("an_seqput", at(e, p["exports"], e.add(1, e.mul(p["fe"], 2)))),
                                                               cid_data(at(e, p["exports"], e.add(2, e.mul(p["fe"], 2))))))
        cid_data(p["entry"])
        layer(layers["rules"], p["in_facts"])
        e.var("verdict", e.ld(1))
        rules_rejection(p["verdict"], range(10, 54))
        # The lowering (after U53): its own checks decline where the bootstrap raises, and a resource UI's names must be
        # the table's.
        e.if_(e.ne(count("managed_entry"), 0), managed_lowering)
        e.if_(e.ne(count("adapter"), 0), adapter_lowering)
        e.var("missing", 0)
        e.if_(e.eq(p["id_initial"], NONE), lambda: e.set("missing", p["u_initial"]), lambda: e.if_(
            e.eq(p["id_click"], NONE), lambda: e.set("missing", p["u_click"])))
        e.if_(e.ne(p["missing"], 0), lambda: reject(
            lambda: d_cid_rec(at(e, p["firstrecs"], C["ui_resource"])), "ANDROID-RESOURCE-UI-NAME",
            lambda: (D.put(e, D.T_LIST), D.put(e, e.ld(p["r_names"])), e.for_("rn_k", 1, e.add(e.ld(p["r_names"]), 1), lambda: d_str(at(e, p["r_names"], p["rn_k"])))),
            lambda: d_str(p["missing"]), code="XAX.ANDROID.UI"))
        rules_rejection(p["verdict"], range(54, 61))
        _ok(e, e.eq(p["verdict"], 0))  # the rules accept the package (a site this program did not expect: declined)

        # 7. The roots: the exports' functions in export order, without duplicates.
        def compute_roots():
            """The roots; a roots-only call (mode 0) stops with them, and a build checks the input's."""
            e.var("roots", e.alloc(e.add(e.mul(e.ld(p["exports"]), CID_WORDS), 1)))
            _ok(e, e.ne(p["roots"], NONE))
            e.st(p["roots"], 0)

            def root():
                e.var("rf", at(e, p["exports"], e.add(2, e.mul(p["rq"], 2))))
                e.var("rnew", 1)
                e.for_("rj", 0, e.ld(p["roots"]), lambda: e.if_(
                    e.both(*(e.eq(at(e, p["roots"], e.add(1 + w, e.mul(p["rj"], CID_WORDS))), at(e, p["rf"], 1 + w)) for w in range(CID_WORDS))),
                    lambda: e.set("rnew", 0)))

                def add():
                    for w in range(CID_WORDS):
                        e.st(e.add(p["roots"], e.add(1 + w, e.mul(e.ld(p["roots"]), CID_WORDS))), at(e, p["rf"], 1 + w))
                    e.st(p["roots"], e.add(e.ld(p["roots"]), 1))

                e.if_(e.ne(p["rnew"], 0), add)

            e.for_("rq", 0, e.udiv(e.ld(p["exports"]), 2), root)
            _ok(e, e.lt(0, e.ld(p["roots"])))

            def roots_only():
                e.st(1, e.ld(p["roots"]))
                e.for_("ro", 0, e.mul(e.ld(p["roots"]), CID_WORDS), lambda: e.st(e.add(2, p["ro"]), at(e, p["roots"], e.add(p["ro"], 1))))
                e.st(0, 1)
                e.give(2)  # the driver stops: the roots are the output

            e.if_(e.eq(p["mode"], 0), roots_only)
            _ok(e, e.eq(p["mode"], 1))
            # The input's roots (and the table's entry, the first root) are these.
            _ok(e, e.eq(e.rd(p["roots_at"]), e.ld(p["roots"])))
            e.for_("ri", 0, e.mul(e.ld(p["roots"]), CID_WORDS), lambda: _ok(e, e.eq(e.rd(e.add(e.add(p["roots_at"], 1), p["ri"])), at(e, p["roots"], e.add(p["ri"], 1)))))
            e.for_("ri", 0, CID_WORDS, lambda: _ok(e, e.eq(e.rd(e.add(1, p["ri"])), at(e, p["roots"], e.add(p["ri"], 1)))))

        compute_roots()

        e = _Slotted((yield), slots)
        p = e.p
        e.if_(e.ne(p["managed"], 0), lambda: e.give(1))  # the managed-class profile's phases follow
        # 8. The layers' inputs that need no bundle: the binary manifest (mode 0) and the two DEX bridges.
        e.var("in_manifest", e.ld(G_W))
        put(0)
        call("an_seqput", p["f_package"])
        call("an_seqput", p["f_activity"])
        for name in ("f_version", "f_min", "f_target", "f_launcher", "f_debug"):
            put(p[name])
        e.if_(e.ne(count("application"), 0), lambda: (put(1), call("an_seqput", p["a_java"])), lambda: put(0))
        put(count("receiver"))
        e.if_(e.ne(count("receiver"), 0), lambda: (call("an_seqput", p["v_java"]), put(p["v_exported"]),
                                                   e.if_(e.ne(e.ld(p["v_action"]), 0), lambda: (put(1), call("an_seqput", p["v_action"])), lambda: put(0))))
        put(count("service"))
        e.if_(e.ne(count("service"), 0), lambda: (call("an_seqput", p["s_java"]), put(p["s_exported"])))
        put(0)  # no platform declarations

        def proto(ret: bytes, *parameters: bytes):
            text(K(ret))
            put(len(parameters))
            for item in parameters:
                text(K(item))

        def bridge(cls16, superclass: bytes, interface: bytes | None, library: bool, natives, overrides, nulls=(), methods=lambda: (put(0), put(0)),
                   ui=lambda: put(0), click=lambda: put(0), load_override: bytes | None = None, libxposed=None):
            """A bridge's words (``dex_with_xax``), its methods in the specification's sorted order: ``natives`` are
            (name, return, parameters); ``overrides`` (name, return, parameters, native, access, super); ``nulls`` (name,
            return, parameters)."""
            text(cls16)
            text(K(superclass))
            put(ACC_PUBLIC_FINAL_CLASS)
            if interface is None:
                put(0)
            else:
                put(1)
                text(K(interface))
            if library:
                put(1)
                text(K(b"xaxapp"))
            else:
                put(0)
            if load_override is None:
                put(0)  # no deferred-load override
            else:
                put(1)
                text(K(load_override))
            put(len(natives))
            for name, ret, parameters in natives:
                text(K(name))
                proto(ret, *parameters)
                put(ACC_NATIVE_METHOD)
            put(len(overrides))
            for name, ret, parameters, native, access, call_super in overrides:
                text(K(name))
                proto(ret, *parameters)
                text(K(native))
                put(access)
                put(call_super)
            put(len(nulls))
            for name, ret, parameters in nulls:
                text(K(name))
                proto(ret, *parameters)
                put(ACC_PUBLIC)
            methods()
            put(0)  # no assembled methods
            ui()
            click()
            if libxposed is None:
                for _ in range(6):
                    put(0)  # no libxposed shapes
            else:
                libxposed()

        def activity_methods():
            # The method UIs' managed method: a constant string (zero arguments) or the echo (one argument).
            e.if_(e.eq(p["ui_kind"], method), lambda: (put(1), text(p["u_initial16"]), text(p["u_value16"]), put(ACC_PUBLIC)), lambda: put(0))
            e.if_(e.eq(p["ui_kind"], argument), lambda: (put(1), text(p["u_initial16"]), put(ACC_PUBLIC)), lambda: put(0))

        def activity_ui():
            put(1)
            text(p["u_listener16"])
            e.if_(e.eq(p["ui_kind"], plain), lambda: (put(0), text(p["u_initial16"])))
            e.if_(e.eq(p["ui_kind"], resource), lambda: (put(1), put(p["id_initial"])))
            e.if_(e.eq(p["ui_kind"], method), lambda: (put(2), text(p["u_initial16"]), put(0)))
            e.if_(e.eq(p["ui_kind"], argument), lambda: (put(2), text(p["u_initial16"]), put(1), text(p["u_value16"])))

        def listener_click():
            put(1)
            e.if_(e.eq(p["ui_kind"], resource), lambda: (put(1), put(p["id_click"])), lambda: (put(0), text(p["u_click16"])))

        e.var("in_activity", e.ld(G_W))
        bundle, view = (b"Landroid/os/Bundle;",), (b"Landroid/view/View;",)
        bridge(p["u_activity16"], b"Landroid/app/Activity;", None, True, ((b"xaxOnCreate", b"V", bundle),),
               ((b"onCreate", b"V", bundle, b"xaxOnCreate", ACC_PROTECTED, 1),), methods=activity_methods, ui=activity_ui)
        e.var("in_listener", e.ld(G_W))
        bridge(p["u_listener16"], b"Ljava/lang/Object;", b"Landroid/view/View$OnClickListener;", False, ((b"xaxOnClick", b"V", view),),
               ((b"onClick", b"V", view, b"xaxOnClick", ACC_PUBLIC, 0),), click=listener_click)
        # The components (``lower_android_broadcast_receiver``, ``lower_android_service``, ``lower_android_application``).
        receive, void = (b"Landroid/content/Context;", b"Landroid/content/Intent;"), ()
        e.var("in_receiver", e.ld(G_W))
        e.if_(e.ne(count("receiver"), 0), lambda: bridge(p["v_desc16"], b"Landroid/content/BroadcastReceiver;", None, True,
                                                        ((b"xaxOnReceive", b"V", receive),), ((b"onReceive", b"V", receive, b"xaxOnReceive", ACC_PUBLIC, 0),)))
        e.var("in_service", e.ld(G_W))
        e.if_(e.ne(count("service"), 0), lambda: bridge(p["s_desc16"], b"Landroid/app/Service;", None, True,
                                                       ((b"xaxOnCreate", b"V", void), (b"xaxOnDestroy", b"V", void)),
                                                       ((b"onCreate", b"V", void, b"xaxOnCreate", ACC_PUBLIC, 1),
                                                        (b"onDestroy", b"V", void, b"xaxOnDestroy", ACC_PUBLIC, 1)),
                                                       ((b"onBind", b"Landroid/os/IBinder;", (b"Landroid/content/Intent;",)),)))
        e.var("in_application", e.ld(G_W))
        e.if_(e.ne(count("application"), 0), lambda: bridge(p["a_desc16"], b"Landroid/app/Application;", None, True, ((b"xaxOnCreate", b"V", void),),
                                                           ((b"onCreate", b"V", void, b"xaxOnCreate", ACC_PUBLIC, 1),)))
        # The libxposed module entry (``lower_libxposed_managed_entry``) and hooker (``lower_libxposed_hook_adapter``).
        loaded = (b"Lio/github/libxposed/api/XposedModuleInterface$ModuleLoadedParam;",)
        ready = (b"Lio/github/libxposed/api/XposedModuleInterface$PackageReadyParam;",)

        def managed_shapes():
            put(0)  # no interceptor

            def install():
                put(1)
                text8(p["in_class"])
                text8(p["in_method"])
                text8(p["in_desc"])
                e.if_(e.eq(e.ld(p["in_params"]), 1), lambda: (put(1), text(K(b"java.lang.String"))), lambda: put(0))
                text(K(b"PROTECTIVE"))
                put(p["in_retained"])
                put(count("deopt"))
                e.if_(e.ne(p["in_hook"], 0), lambda: (put(1), text8(p["in_hook"])), lambda: put(0))

            e.if_(e.ne(count("install"), 0), install, lambda: put(0))
            put(p["sv_mask"])
            put(p["pf_mask"])
            e.if_(e.ne(count("hot"), 0), lambda: (put(1), text8(p["in_desc"]), text8(p["h_id"])), lambda: put(0))
            put(p["fl_mask"])

        def managed(both: bool):
            natives = [(b"xaxOnModuleLoaded", b"V", loaded)] + ([(b"xaxOnPackageReady", b"V", ready)] if both else [])
            overrides = [(b"onModuleLoaded", b"V", loaded, b"xaxOnModuleLoaded", ACC_PUBLIC, 0)]
            if both:
                overrides.append((b"onPackageReady", b"V", ready, b"xaxOnPackageReady", ACC_PUBLIC, 0))
            bridge(call("an_utf16", p["m_desc"]), XPOSED_MODULE, None, True, tuple(natives), tuple(overrides), load_override=b"onModuleLoaded",
                   libxposed=managed_shapes)

        e.var("in_managed", e.ld(G_W))
        e.if_(e.ne(count("managed_entry"), 0), lambda: e.if_(e.ne(e.and_(p["m_mask"], 2), 0), lambda: managed(True), lambda: managed(False)))

        def adapter_shapes():
            put(1)
            put(e.flag(e.ne(p["ad_index"], 8)))
            put(e.sel(e.eq(p["ad_index"], 8), 0, p["ad_index"]))
            e.if_(e.ne(count("result"), 0), lambda: (put(1), text8(p["rs_repl"])), lambda: e.if_(
                e.ne(count("combined"), 0), lambda: (put(1), text8(p["cb_rrepl"])), lambda: put(0)))
            e.if_(e.ne(count("argument"), 0), lambda: (put(1), text8(p["ag_repl"])), lambda: e.if_(
                e.ne(count("combined"), 0), lambda: (put(1), text8(p["cb_repl"])), lambda: put(0)))
            for _ in range(5):
                put(0)  # no installation, services, preferences, hot reload or remote files

        e.var("in_adapter", e.ld(G_W))
        e.if_(e.ne(count("adapter"), 0), lambda: bridge(call("an_utf16", p["ad_desc"]), b"Ljava/lang/Object;", HOOKER, False, (), (),
                                                       libxposed=adapter_shapes))

        # The resource table (``resources.arsc``, mode 1): the package, then the strings in the table's order.
        e.var("in_arsc", e.ld(G_W))

        def arsc():
            put(1)
            call("an_seqput", p["r_package"])
            put(e.ld(p["r_names"]))
            e.for_("aq", 1, e.add(e.ld(p["r_names"]), 1), lambda: (call("an_seqput", at(e, p["r_names"], p["aq"])),
                                                                  call("an_seqput", at(e, p["r_values"], p["aq"]))))

        e.if_(e.eq(count("resources"), 1), arsc)

        e = _Slotted((yield), slots)
        p = e.p
        e.if_(e.ne(p["managed"], 0), lambda: e.give(1))  # the managed-class profile's phases follow
        # 9. The bundle (the AArch64 program on this input), then the shared object's input from its record.
        def shared_object():
            """The bundle (the AArch64 program on this input), then the shared object from its record: ``so``."""
            layer(layers["aarch64"], 0)
            e.var("norder", e.ld(COUNT_AT))
            e.var("order", e.alloc(e.add(e.mul(p["norder"], CID_WORDS), 1)))
            _ok(e, e.ne(p["order"], NONE))
            e.st(p["order"], p["norder"])
            e.for_("oq", 0, e.mul(p["norder"], CID_WORDS), lambda: e.st(e.add(e.add(p["order"], 1), p["oq"]), e.ld(e.add(ORDER_AT, p["oq"]))))
            e.var("rtable", e.ld(GLOBALS + G_RA))
            e.var("rend", e.ld(e.add(p["rtable"], I_CURSOR)))
            _ok(e, e.both(e.lt(IMAGE_AT, p["rend"]), e.le(p["rend"], IMAGE_END)))
            _ok(e, e.eq(e.ld(IMAGE_AT), 1))
            e.var("rp", IMAGE_AT + 1)
            e.var("code_at", p["rp"])
            e.set("rp", e.add(e.add(p["rp"], 1), e.udiv(e.add(e.ld(p["rp"]), 7), 8)))  # the code
            e.set("rp", e.add(e.add(p["rp"], 1), e.udiv(e.add(e.ld(p["rp"]), 7), 8)))  # the (empty) executable
            e.var("members", e.ld(e.add(p["rp"], 2)))
            e.set("rp", e.add(p["rp"], 3))
            _ok(e, e.le(p["members"], p["norder"]))
            e.var("bases", e.alloc(e.add(p["members"], 1)))
            _ok(e, e.ne(p["bases"], NONE))

            def member():
                e.st(e.add(p["bases"], p["bq"]), e.ld(p["rp"]))
                e.set("rp", e.add(e.add(p["rp"], 3), e.mul(e.ld(e.add(p["rp"], 2)), 4)))

            e.for_("bq", 0, p["members"], member)
            e.var("in_elf", e.ld(G_W))
            put(e.flag(e.eq(p["t_fmt"], PACKED_FORMAT)))
            put(0)  # no BSS
            call("an_packput", e.add(K(b"libxaxapp.so"), 1), e.ld(K(b"libxaxapp.so")))
            put(0)  # no rodata
            put(0)  # no data
            e.for_("cq", 0, e.add(1, e.udiv(e.add(e.ld(p["code_at"]), 7), 8)), lambda: put(e.ld(e.add(p["code_at"], p["cq"]))))
            put(p["members"])
            e.for_("bq", 0, p["members"], lambda: put(at(e, p["bases"], p["bq"])))
            e.var("nforeign", e.ld(p["rp"]))
            put(p["nforeign"])
            e.set("rp", e.add(p["rp"], 1))

            def foreign():
                put(e.ld(p["rp"]))
                e.set("rp", e.add(p["rp"], 1))
                for _ in range(2):  # the library, the name: bytes one per word, packed for the ELF program
                    call("an_packput", e.add(p["rp"], 1), e.ld(p["rp"]))
                    e.set("rp", e.add(e.add(p["rp"], 1), e.ld(p["rp"])))

            e.for_("fq", 0, p["nforeign"], foreign)
            put(e.udiv(e.ld(p["exports"]), 2))

            def elf_export():
                e.var("en", at(e, p["exports"], e.add(1, e.mul(p["eq"], 2))))
                e.var("ef", at(e, p["exports"], e.add(2, e.mul(p["eq"], 2))))
                call("an_packput", e.add(p["en"], 1), e.ld(p["en"]))
                e.var("ei", p["members"])
                e.for_("ej", 0, p["members"], lambda: e.if_(
                    e.both(*(e.eq(at(e, p["order"], e.add(1 + w, e.mul(p["ej"], CID_WORDS))), at(e, p["ef"], 1 + w)) for w in range(CID_WORDS))),
                    lambda: e.set("ei", p["ej"])))
                put(p["ei"])

            e.for_("eq", 0, e.udiv(e.ld(p["exports"]), 2), elf_export)

            # 10. The shared object, the manifest and the bridges; each record kept.
            layer(layers["elf"], p["in_elf"])
            e.var("so", call("an_record"))

        shared_object()
        layer(layers["resources"], p["in_manifest"])
        e.var("axml", call("an_record"))
        layer(layers["dex"], p["in_activity"])
        e.var("dex1", call("an_record"))
        layer(layers["dex"], p["in_listener"])
        e.var("dex2", call("an_record"))
        for name in ("receiver", "service", "application", "managed", "adapter"):
            e.var(f"dex_{name}", 0)
            e.if_(e.ne(count(DEX_CLASS.get(name, name)), 0), lambda name=name: (layer(layers["dex"], p[f"in_{name}"]),
                                                                              e.set(f"dex_{name}", call("an_record"))))
        e.var("arsc", 0)
        e.if_(e.eq(count("resources"), 1), lambda: (layer(layers["resources"], p["in_arsc"]), e.set("arsc", call("an_record"))))

        # 11. The APK (``build_unsigned_apk``): the container program sorts the entries.
        e.var("in_apk", e.ld(G_W))
        e.var("n_meta", e.mul(count("libxposed"), e.add(2, e.add(e.flag(e.ne(e.ld(p["l_native"]), 0)), e.flag(e.ne(e.ld(p["l_scopes"]), 0))))))
        put(e.add(e.add(e.add(4, count("resources")), e.add(count("receiver"), e.add(count("service"), count("application")))),
                  e.add(e.add(count("managed_entry"), count("adapter")), p["n_meta"])))

        def entry(name, data, alignment: int):
            call("an_seqput", name)
            put(0)
            put(alignment)
            call("an_blobput", data)

        def entry_bytes(name, h):
            call("an_seqput", name)
            put(0)
            put(ENTRY_ALIGNMENT)
            call("an_packput", e.add(h, 1), e.ld(h))

        for name, data, alignment in ((b"AndroidManifest.xml", "axml", ENTRY_ALIGNMENT), (b"classes.dex", "dex1", ENTRY_ALIGNMENT),
                                      (b"lib/arm64-v8a/libxaxapp.so", "so", NATIVE_ALIGNMENT), (b"classes2.dex", "dex2", ENTRY_ALIGNMENT)):
            entry(K(name), p[data], alignment)
        e.if_(e.eq(count("resources"), 1), lambda: entry(K(b"resources.arsc"), p["arsc"], ENTRY_ALIGNMENT))
        # The extra DEX files, numbered from 3 in the bootstrap's order.
        e.var("nd", 0)

        def dex_name():
            name = K(DEX_NAMES[-1])
            for k in range(len(DEX_NAMES) - 2, -1, -1):
                name = e.sel(e.eq(p["nd"], k), K(DEX_NAMES[k]), name)
            return name

        for name in ("receiver", "service", "application", "managed", "adapter"):
            e.if_(e.ne(count(DEX_CLASS.get(name, name)), 0), lambda name=name: (entry(dex_name(), p[f"dex_{name}"], ENTRY_ALIGNMENT),
                                                                              e.set("nd", e.add(p["nd"], 1))))

        # The libxposed metadata (``emit_libxposed_metadata``): module.prop, then the entry and scope lists.
        def listed_metadata(name: bytes, lst):
            e.var("ml", e.alloc(e.add(p["meta_cap"], 1)))
            _ok(e, e.ne(p["ml"], NONE))
            e.st(p["ml"], 0)
            e.for_("mlk", 1, e.add(e.ld(lst), 1), lambda: (call("an_cat", p["ml"], at(e, lst, p["mlk"])), call("an_cat", p["ml"], K(b"\n"))))
            entry_bytes(K(name), p["ml"])

        def metadata():
            e.var("meta_cap", e.add(e.ld(first("libxposed")), 256))
            e.var("mp", e.alloc(e.add(p["meta_cap"], 1)))
            _ok(e, e.ne(p["mp"], NONE))
            e.st(p["mp"], 0)
            call("an_cat", p["mp"], K(b"minApiVersion="))
            call("an_dec", p["mp"], p["l_min"])
            call("an_cat", p["mp"], K(b"\ntargetApiVersion="))
            call("an_dec", p["mp"], p["l_target"])
            call("an_cat", p["mp"], K(b"\nstaticScope="))
            call("an_cat", p["mp"], e.sel(e.ne(p["l_static"], 0), K(b"true\n"), K(b"false\n")))
            e.if_(e.ne(count("hot"), 0), lambda: call("an_cat", p["mp"], K(b"autoHotReload=true\n")))
            entry_bytes(K(b"META-INF/xposed/module.prop"), p["mp"])
            listed_metadata(b"META-INF/xposed/java_init.list", p["l_java"])
            e.if_(e.ne(e.ld(p["l_native"]), 0), lambda: listed_metadata(b"META-INF/xposed/native_init.list", p["l_native"]))
            e.if_(e.ne(e.ld(p["l_scopes"]), 0), lambda: listed_metadata(b"META-INF/xposed/scope.list", p["l_scopes"]))

        e.if_(e.ne(count("libxposed"), 0), metadata)
        layer(layers["apk"], p["in_apk"])

        # -- The managed-class profile (``_build_android_managed_apk``, ADR-199) ---------------------------------------
        e = _Slotted((yield), slots)
        p = e.p
        e.if_(e.eq(p["managed"], 0), lambda: e.give(1))
        # M0. The classes (``decode_android_managed_class``, ``AndroidManagedClass``): per class a record of its CID's
        # record index, descriptor (bytes, units), superclass, library, interfaces and methods (name, descriptor, access,
        # super flag, native name, parameters, result).
        e.var("ncls", e.udiv(e.ld(p["mclasses"]), 2))
        e.var("classes", e.alloc(e.add(e.mul(p["ncls"], MC_WORDS), 1)))
        _ok(e, e.ne(p["classes"], NONE))
        e.st(p["classes"], p["ncls"])
        cls = lambda k, field: at(e, p["classes"], e.add(e.add(e.mul(k, MC_WORDS), field), 1))  # noqa: E731
        set_cls = lambda k, field, value: e.st(e.add(p["classes"], e.add(e.add(e.mul(k, MC_WORDS), field), 1)), value)  # noqa: E731

        def ascii_identifier(h):
            """``str.isidentifier`` for ASCII names (a name past ASCII declines), and not ``<...>``."""
            _ok(e, e.lt(0, e.ld(h)))
            e.for_("ai_k", 1, e.add(e.ld(h), 1), lambda: (
                e.var("ai_c", at(e, h, p["ai_k"])),
                _ok(e, e.either(e.both(e.le(ord("A"), p["ai_c"]), e.le(p["ai_c"], ord("Z"))), e.both(e.le(ord("a"), p["ai_c"]), e.le(p["ai_c"], ord("z"))),
                                e.eq(p["ai_c"], ord("_")), e.both(e.lt(1, p["ai_k"]), e.le(ord("0"), p["ai_c"]), e.le(p["ai_c"], ord("9")))))))

        def jvm_type(h, at_, allow_void: bool):
            """``_parse_descriptor_type``: the index after the type at ``at_`` (an item index from 1); declines on error."""
            e.var("jt_k", at_)
            e.var("jt_d", 0)
            e.while_(lambda: e.both(e.le(p["jt_k"], e.ld(h)), e.eq(at(e, h, e.sel(e.le(p["jt_k"], e.ld(h)), p["jt_k"], 1)), ord("["))),
                     lambda: (e.set("jt_k", e.add(p["jt_k"], 1)), e.set("jt_d", e.add(p["jt_d"], 1))))
            _ok(e, e.both(e.le(p["jt_d"], 255), e.le(p["jt_k"], e.ld(h))))
            e.var("jt_c", at(e, h, p["jt_k"]))
            prim = e.either(*(e.eq(p["jt_c"], ord(c)) for c in "ZBCSIJFD"))
            void = e.both(e.eq(p["jt_c"], ord("V")), e.eq(p["jt_d"], 0)) if allow_void else e.eq(e.c(0), 1)

            def reference():
                e.var("jt_s", e.add(p["jt_k"], 1))
                e.var("jt_e", NONE)
                e.for_("jt_j", p["jt_s"], e.add(e.ld(h), 1), lambda: e.if_(e.both(e.eq(p["jt_e"], NONE), e.eq(at(e, h, p["jt_j"]), ord(";"))),
                                                                          lambda: e.set("jt_e", p["jt_j"])))
                _ok(e, e.both(e.ne(p["jt_e"], NONE), e.lt(p["jt_s"], p["jt_e"])))  # ``_validate_internal_name``: nonempty
                _ok(e, e.both(e.ne(at(e, h, p["jt_s"]), ord("/")), e.ne(at(e, h, e.sub(p["jt_e"], 1)), ord("/"))))
                e.for_("jt_q", p["jt_s"], p["jt_e"], lambda: (
                    e.var("jt_x", at(e, h, p["jt_q"])),
                    _ok(e, e.not_(e.either(e.eq(p["jt_x"], ord(".")), e.eq(p["jt_x"], 0),
                                           e.both(e.eq(p["jt_x"], ord("/")), e.eq(at(e, h, e.add(p["jt_q"], 1)), ord("/"))))))))
                e.set("jt_k", e.add(p["jt_e"], 1))

            e.if_(e.either(prim, void), lambda: e.set("jt_k", e.add(p["jt_k"], 1)), lambda: e.if_(
                e.eq(p["jt_c"], ord("L")), reference, lambda: _ok(e, e.eq(e.c(0), 1))))
            return p["jt_k"]

        def method_descriptor(h, k, m):
            """``parse_jvm_method_descriptor``: the parameters' and the result's spans, kept in method record ``m``."""
            _ok(e, e.both(e.lt(1, e.ld(h)), e.eq(at(e, h, 1), ord("("))))
            e.var("md_k", 2)
            e.var("md_params", e.alloc(e.add(e.ld(h), 1)))
            _ok(e, e.ne(p["md_params"], NONE))
            e.st(p["md_params"], 0)
            e.var("md_go", 1)

            def parameter():
                e.var("md_end", jvm_type(h, p["md_k"], False))
                e.var("md_t", call("an_slice", h, p["md_k"], p["md_end"]))
                e.st(e.add(p["md_params"], e.add(e.ld(p["md_params"]), 1)), p["md_t"])
                e.st(p["md_params"], e.add(e.ld(p["md_params"]), 1))
                e.set("md_k", p["md_end"])

            e.while_(lambda: e.ne(p["md_go"], 0), lambda: e.if_(
                e.both(e.le(p["md_k"], e.ld(h)), e.ne(at(e, h, e.sel(e.le(p["md_k"], e.ld(h)), p["md_k"], 1)), ord(")"))), parameter,
                lambda: e.set("md_go", 0)))
            _ok(e, e.le(p["md_k"], e.ld(h)))
            e.var("md_rs", e.add(p["md_k"], 1))
            e.var("md_re", jvm_type(h, p["md_rs"], True))
            _ok(e, e.eq(p["md_re"], e.add(e.ld(h), 1)))
            e.st(e.add(m, MM_PARAMS), p["md_params"])
            e.st(e.add(m, MM_RESULT), call("an_slice", h, p["md_rs"], p["md_re"]))

        def managed_class():
            e.var("mk_id", at(e, p["mclasses"], e.add(1, e.mul(p["mk"], 2))))
            e.var("mk_rec", at(e, p["mclasses"], e.add(2, e.mul(p["mk"], 2))))
            e.for_("mk_j", 0, p["mk"], lambda: _ok(e, e.ne(at(e, p["mclasses"], e.add(2, e.mul(p["mk_j"], 2))), p["mk_rec"])))  # once each
            set_cls(p["mk"], MC_REC, p["mk_rec"])
            e.var("mk_body", call("an_tail", p["mk_id"], len(PREFIX["managed"])))
            e.st(G_CUR, 0)
            for field, stem in ((MC_DESC, "mcd"), (MC_SUPER, "mcs"), (MC_LIB, "mcl")):
                e.var(f"{stem}_v", _bstr_at(e, p["mk_body"], "mk"))
                _ok(e, e.ne(call("an_utf16", p[f"{stem}_v"]), NONE))
                set_cls(p["mk"], field, p[f"{stem}_v"])
            e.var("mk_ifaces", texts_at(p["mk_body"], "mki"))
            e.var("mk_nm", _uleb_at(e, p["mk_body"], "mk"))
            _ok(e, e.both(e.lt(0, p["mk_nm"]), e.le(p["mk_nm"], e.ld(p["mk_body"]))))
            e.var("mk_methods", e.alloc(e.add(e.mul(p["mk_nm"], MM_WORDS), 1)))
            _ok(e, e.ne(p["mk_methods"], NONE))
            e.st(p["mk_methods"], p["mk_nm"])

            def method():
                e.var("mm", e.add(e.add(p["mk_methods"], 1), e.mul(p["mq"], MM_WORDS)))
                for field in (MM_NAME, MM_DESC, MM_ACCESS):
                    e.var("mm_v", _bstr_at(e, p["mk_body"], "mm"))
                    _ok(e, e.ne(call("an_utf16", p["mm_v"]), NONE))
                    e.st(e.add(p["mm"], field), p["mm_v"])
                e.var("mm_super", _byte_at(e, p["mk_body"], "mm"))
                _ok(e, e.le(p["mm_super"], 1))
                e.st(e.add(p["mm"], MM_SUPER), p["mm_super"])
                name, access = e.ld(e.add(p["mm"], MM_NAME)), e.ld(e.add(p["mm"], MM_ACCESS))
                ascii_identifier(name)
                method_descriptor(e.ld(e.add(p["mm"], MM_DESC)), p["mk"], p["mm"])
                e.var("mm_public", e.flag(same(access, K(b"public"))))
                _ok(e, e.either(e.ne(p["mm_public"], 0), same(access, K(b"protected"))))
                e.st(e.add(p["mm"], MM_ACCESS), e.sel(e.ne(p["mm_public"], 0), ACC_PUBLIC, ACC_PROTECTED))
                e.if_(e.ne(p["mm_super"], 0), lambda: _ok(e, same(e.ld(e.add(p["mm"], MM_RESULT)), K(b"V"))))
                e.st(e.add(p["mm"], MM_NATIVE), call("an_native", name))
                # The canonical order: sorted by name (distinct names), so each name after the previous one.
                e.if_(e.lt(0, p["mq"]), lambda: _ok(e, e.ne(call("an_less", e.ld(e.sub(e.add(p["mm"], MM_NAME), MM_WORDS)), name), 0)))

            e.for_("mq", 0, p["mk_nm"], method)
            _ok(e, e.eq(e.ld(G_CUR), e.ld(p["mk_body"])))
            for field in (MC_DESC, MC_SUPER):
                h = cls(p["mk"], field)
                _ok(e, e.both(e.lt(2, e.ld(h)), e.eq(at(e, h, 1), ord("L")), e.eq(at(e, h, e.ld(h)), ord(";"))))
                _ok(e, e.ne(call("an_desc", h), 0))  # and the DEX bridge's
            e.for_("mi", 1, e.add(e.ld(p["mk_ifaces"]), 1), lambda: (
                _ok(e, e.ne(call("an_desc", at(e, p["mk_ifaces"], p["mi"])), 0)),
                _ok(e, e.not_(e.either(same(at(e, p["mk_ifaces"], p["mi"]), cls(p["mk"], MC_DESC)), same(at(e, p["mk_ifaces"], p["mi"]), cls(p["mk"], MC_SUPER))))),
                e.if_(e.lt(1, p["mi"]), lambda: _ok(e, e.ne(call("an_less", at(e, p["mk_ifaces"], e.sub(p["mi"], 1)), at(e, p["mk_ifaces"], p["mi"])), 0)))))
            _ok(e, e.not_(same(cls(p["mk"], MC_DESC), cls(p["mk"], MC_SUPER))))
            lib = cls(p["mk"], MC_LIB)
            _ok(e, e.both(e.lt(0, e.ld(lib)), e.eq(call("an_has", lib, ord("/")), 0), e.eq(call("an_has", lib, ord("\\")), 0), e.eq(call("an_has", lib, 0), 0)))
            set_cls(p["mk"], MC_IFACES, p["mk_ifaces"])
            set_cls(p["mk"], MC_METHODS, p["mk_methods"])
            set_cls(p["mk"], MC_DESC16, call("an_utf16", cls(p["mk"], MC_DESC)))
            set_cls(p["mk"], MC_JAVA, call("an_java", cls(p["mk"], MC_DESC)))

        e.for_("mk", 0, p["ncls"], managed_class)

        def declarations():
            """``decode_android_platform_declarations``: the permissions, features and components, each in its canonical
            order (by name, without duplicates)."""
            e.var("pd_body", call("an_tail", first("declarations"), len(PREFIX["declarations"])))
            e.st(G_CUR, 0)
            binary = lambda h: (_ok(e, e.ne(call("an_utf16", h), NONE)), _ok(e, e.ne(call("an_binary", h), 0)))  # noqa: E731

            def listed_(stem, read):
                e.var(f"{stem}_n", _uleb_at(e, p["pd_body"], "pd"))
                _ok(e, e.le(p[f"{stem}_n"], e.ld(p["pd_body"])))
                e.var(stem, e.alloc(e.add(e.mul(p[f"{stem}_n"], DECL_WORDS), 1)))
                _ok(e, e.ne(p[stem], NONE))
                e.st(p[stem], p[f"{stem}_n"])
                e.for_(f"{stem}_k", 0, p[f"{stem}_n"], lambda: read(e.add(e.add(p[stem], 1), e.mul(p[f"{stem}_k"], DECL_WORDS)), p[f"{stem}_k"]))

            def ordered(stem, field):
                e.for_(f"{stem}_o", 1, p[f"{stem}_n"], lambda: _ok(e, e.ne(call("an_less", e.ld(e.add(e.add(p[stem], 1), e.add(e.mul(e.sub(p[f"{stem}_o"], 1), DECL_WORDS), field))),
                                                                                  e.ld(e.add(e.add(p[stem], 1), e.add(e.mul(p[f"{stem}_o"], DECL_WORDS), field)))), 0)))

            def permission(r, _k):
                e.var("pp_name", _bstr_at(e, p["pd_body"], "pp"))
                binary(p["pp_name"])
                e.st(r, p["pp_name"])
                e.var("pp_max", _uleb_at(e, p["pd_body"], "pp"))
                _ok(e, e.le(p["pp_max"], MASK32))
                e.st(e.add(r, 1), p["pp_max"])
                e.var("pp_never", _byte_at(e, p["pd_body"], "pp"))
                _ok(e, e.le(p["pp_never"], 1))
                e.st(e.add(r, 2), p["pp_never"])

            def feature(r, _k):
                e.var("pf_name", _bstr_at(e, p["pd_body"], "pfe"))
                binary(p["pf_name"])
                e.st(r, p["pf_name"])
                e.var("pf_req", _byte_at(e, p["pd_body"], "pfe"))
                _ok(e, e.le(p["pf_req"], 1))
                e.st(e.add(r, 1), p["pf_req"])

            def component(r, _k):
                e.var("pc_kind", _bstr_at(e, p["pd_body"], "pc"))
                e.var("pc_service", e.flag(same(p["pc_kind"], K(b"service"))))
                _ok(e, e.either(e.ne(p["pc_service"], 0), same(p["pc_kind"], K(b"receiver"))))
                e.st(e.add(r, 5), p["pc_kind"])
                e.st(e.add(r, 4), e.sub(1, p["pc_service"]))  # 0 a service, 1 a receiver
                e.var("pc_class", _bstr_at(e, p["pd_body"], "pc"))
                binary(p["pc_class"])
                e.st(r, p["pc_class"])
                e.var("pc_exported", _byte_at(e, p["pd_body"], "pc"))
                _ok(e, e.le(p["pc_exported"], 1))
                e.st(e.add(r, 1), p["pc_exported"])
                e.var("pc_types", texts_at(p["pd_body"], "pct"))
                e.var("pc_flags", 0)
                e.for_("pt_k", 1, e.add(e.ld(p["pc_types"]), 1), lambda: (
                    e.var("pt_bit", NONE),
                    [e.if_(same(at(e, p["pc_types"], p["pt_k"]), K(name.encode())), lambda bit=bit: e.set("pt_bit", bit)) for name, (bit, _permission) in
                     FOREGROUND_TYPES],
                    _ok(e, e.ne(p["pt_bit"], NONE)),
                    e.set("pc_flags", e.or_(p["pc_flags"], p["pt_bit"])),
                    e.if_(e.lt(1, p["pt_k"]), lambda: _ok(e, e.ne(call("an_less", at(e, p["pc_types"], e.sub(p["pt_k"], 1)), at(e, p["pc_types"], p["pt_k"])), 0)))))
                _ok(e, e.either(e.ne(p["pc_service"], 0), e.eq(e.ld(p["pc_types"]), 0)))
                e.st(e.add(r, 2), p["pc_types"])
                e.st(e.add(r, 3), p["pc_flags"])
                e.var("pc_actions", texts_at(p["pd_body"], "pca"))
                e.for_("pa_k", 1, e.add(e.ld(p["pc_actions"]), 1), lambda: (
                    _ok(e, e.both(e.lt(0, e.ld(at(e, p["pc_actions"], p["pa_k"]))), e.eq(call("an_has", at(e, p["pc_actions"], p["pa_k"]), 0), 0))),
                    e.if_(e.lt(1, p["pa_k"]), lambda: _ok(e, e.ne(call("an_less", at(e, p["pc_actions"], e.sub(p["pa_k"], 1)), at(e, p["pc_actions"], p["pa_k"])), 0)))))
                e.st(e.add(r, 6), p["pc_actions"])

            listed_("perms", permission)
            ordered("perms", 0)
            listed_("feats", feature)
            ordered("feats", 0)
            listed_("comps", component)
            ordered("comps", 0)
            _ok(e, e.eq(e.ld(G_CUR), e.ld(p["pd_body"])))

        for name in ("perms", "feats", "comps", "perms_n", "feats_n", "comps_n"):
            e.var(name, 0)
        e.if_(e.ne(count("declarations"), 0), declarations)
        e.if_(e.eq(count("resources"), 1), resources)

        # The exports' interface type facts (``_decode_function_interface``, ``_jni_reference``) and the objects and
        # typed JNI methods reachable from them (``reachable_platform_uses``).
        def payload_uleb(start, stem):
            """A minimal ULEB128 of an object's payload (input words) at the cursor ``G_CUR``, bounded by ``G_END``."""
            e.st(G_CUR, start)
            return call("an_uleb")

        def jni_reference(type_rec):
            """``_jni_reference``: the family's bytes of a JNI reference type (``jr_family``, 0 when it is none) and its kind
            (``jr_kind``: 1 local, 2 borrowed, 3 another)."""
            e.var("jr_family", 0)
            e.var("jr_kind", 0)

            def pointer():
                e.st(G_END, e.add(payload_at(type_rec), payload_n(type_rec)))
                e.st(G_CUR, payload_at(type_rec))
                e.var("jr_form", call("an_uleb"))

                def element():
                    call("an_uleb")  # the space
                    e.var("jr_ref", call("an_uleb"))
                    call("an_uleb")  # the permission
                    call("an_uleb")  # the alignment
                    e.var("jr_elem", find(call("an_incid", e.add(e.add(rec(type_rec), 2), e.mul(p["jr_ref"], CID_WORDS)))))

                    def opaque():
                        e.st(G_END, e.add(payload_at(p["jr_elem"]), payload_n(p["jr_elem"])))
                        e.st(G_CUR, payload_at(p["jr_elem"]))
                        e.var("jr_form2", call("an_uleb"))

                        def identity_():
                            e.var("jr_id", call("an_bstr"))
                            v2, v3, v1 = (K(prefix) for prefix in JNI_REFERENCE_PREFIXES)
                            e.var("jr_v", e.sel(e.ne(call("an_prefix", p["jr_id"], v2), 0), 2, e.sel(e.ne(call("an_prefix", p["jr_id"], v3), 0), 3,
                                                                                                   e.sel(e.ne(call("an_prefix", p["jr_id"], v1), 0), 1, 0))))

                            def versioned():
                                e.var("jr_byte", at(e, p["jr_id"], 20))  # the kind byte after the 19-byte prefix
                                e.set("jr_kind", e.sel(e.eq(p["jr_byte"], 2), 1, e.sel(e.eq(p["jr_byte"], 1), 2, 3)))  # LOCAL, BORROWED
                                e.var("jr_tail", call("an_tail", p["jr_id"], e.add(19, e.sel(e.eq(p["jr_v"], 3), 2, 1))))
                                e.st(G_CUR, 0)
                                e.set("jr_family", _bstr_at(e, p["jr_tail"], "jr"))

                            def plain():
                                e.var("jr_rest", call("an_tail", p["jr_id"], len(JNI_REFERENCE_PREFIXES[2])))
                                e.var("jr_slash", NONE)
                                e.for_("jr_s", 1, e.add(e.ld(p["jr_rest"]), 1), lambda: e.if_(e.both(e.eq(p["jr_slash"], NONE), e.eq(at(e, p["jr_rest"], p["jr_s"]), ord("/"))),
                                                                                             lambda: e.set("jr_slash", p["jr_s"])))
                                _ok(e, e.ne(p["jr_slash"], NONE))  # ``partition`` without a slash: the kind ``""``, not a family
                                e.var("jr_kn", call("an_slice", p["jr_rest"], 1, p["jr_slash"]))
                                e.set("jr_kind", e.sel(same(p["jr_kn"], K(b"local")), 1, e.sel(same(p["jr_kn"], K(b"borrowed")), 2, 3)))
                                e.set("jr_family", call("an_slice", p["jr_rest"], e.add(p["jr_slash"], 1), e.add(e.ld(p["jr_rest"]), 1)))

                            e.if_(e.ne(p["jr_v"], 0), lambda: e.if_(e.eq(p["jr_v"], 1), plain, versioned))

                        e.if_(e.both(e.eq(p["jr_form2"], 6), e.eq(nrefs(p["jr_elem"]), 0), e.eq(kind(p["jr_elem"]), int(Kind.TYPE))), identity_)

                    e.if_(e.ne(p["jr_elem"], NONE), opaque)

                e.if_(e.eq(p["jr_form"], 2), element)

            e.if_(e.eq(kind(type_rec), int(Kind.TYPE)), pointer)

        def type_fact(type_rec):
            """``fact(cid)``: ``[3 + n, JNIEnv*, the JNI widths it is, reference kind, family bytes...]``."""
            e.var("tf_cid", cid_at(type_rec))
            e.var("tf_env", e.flag(e.both(*(e.eq(e.rd(e.add(p["tf_cid"], w)), word) for w, word in enumerate(JNI_ENV_WORDS)))))
            e.var("tf_widths", 0)
            for bit, words in enumerate(JNI_WIDTH_WORDS):
                e.if_(e.both(*(e.eq(e.rd(e.add(p["tf_cid"], w)), word) for w, word in enumerate(words))), lambda bit=bit: e.set("tf_widths", e.or_(p["tf_widths"], 1 << bit)))
            jni_reference(type_rec)
            put(e.add(3, e.sel(e.ne(p["jr_family"], 0), e.ld(p["jr_family"]), 0)))
            put(p["tf_env"])
            put(p["tf_widths"])
            put(e.sel(e.ne(p["jr_family"], 0), p["jr_kind"], 0))
            e.if_(e.ne(p["jr_family"], 0), lambda: e.for_("tf_k", 1, e.add(e.ld(p["jr_family"]), 1), lambda: put(at(e, p["jr_family"], p["tf_k"]))))

        def interface_types(function_rec, results: bool):
            """``_decode_function_interface``: the non-proof parameter (or result) types' facts, after their count."""
            e.st(G_END, e.add(payload_at(function_rec), payload_n(function_rec)))
            e.st(G_CUR, payload_at(function_rec))
            e.var("it_graph", call("an_uleb"))
            e.var("it_g", find(call("an_incid", e.add(e.add(rec(function_rec), 2), e.mul(p["it_graph"], CID_WORDS)))))
            _ok(e, e.both(e.ne(p["it_g"], NONE), e.eq(kind(p["it_g"]), int(Kind.GRAPH_FRAGMENT))))  # a group member: declined
            e.var("it_np", call("an_uleb"))
            e.var("it_params", e.alloc(e.add(p["it_np"], 1)))
            _ok(e, e.ne(p["it_params"], NONE))
            e.st(p["it_params"], p["it_np"])
            e.for_("it_k", 0, p["it_np"], lambda: e.st(e.add(p["it_params"], e.add(p["it_k"], 1)), call("an_uleb")))
            e.var("it_nr", call("an_uleb"))
            e.var("it_results", e.alloc(e.add(p["it_nr"], 1)))
            _ok(e, e.ne(p["it_results"], NONE))
            e.st(p["it_results"], p["it_nr"])
            e.for_("it_k", 0, p["it_nr"], lambda: e.st(e.add(p["it_results"], e.add(p["it_k"], 1)), call("an_uleb")))
            _ok(e, e.eq(e.ld(G_CUR), e.ld(G_END)))
            e.var("it_list", p["it_results"] if results else p["it_params"])
            e.var("it_types", e.alloc(e.add(e.ld(p["it_list"]), 1)))
            _ok(e, e.ne(p["it_types"], NONE))
            e.st(p["it_types"], 0)

            def keep():
                e.var("it_t", find(call("an_incid", e.add(e.add(rec(function_rec), 2), e.mul(at(e, p["it_list"], p["it_q"]), CID_WORDS)))))
                _ok(e, e.ne(p["it_t"], NONE))
                e.st(G_END, e.add(payload_at(p["it_t"]), payload_n(p["it_t"])))
                e.st(G_CUR, payload_at(p["it_t"]))
                e.var("it_form", e.sel(e.eq(payload_n(p["it_t"]), 0), NONE, call("an_uleb")))
                e.if_(e.both(e.eq(kind(p["it_t"]), int(Kind.TYPE)), e.either(e.eq(p["it_form"], 3), e.eq(p["it_form"], 4))), lambda: None, lambda: (
                    e.st(e.add(p["it_types"], e.add(e.ld(p["it_types"]), 1)), p["it_t"]), e.st(p["it_types"], e.add(e.ld(p["it_types"]), 1))))

            e.for_("it_q", 1, e.add(e.ld(p["it_list"]), 1), keep)
            return p["it_types"]

        # The closure from the exports' functions (``reachable_platform_uses``): every reachable object once, and the
        # typed JNI methods (owner, name, descriptor) among their opaque identity types, each once.
        e.var("seen", e.alloc(e.add(p["nobj"], 1)))
        e.var("pending", e.alloc(e.add(p["nobj"], 1)))
        e.var("members", e.alloc(e.add(e.mul(p["nobj"], 3), 1)))
        _ok(e, e.both(e.ne(p["seen"], NONE), e.ne(p["pending"], NONE), e.ne(p["members"], NONE)))
        e.for_("sz", 0, p["nobj"], lambda: e.st(e.add(p["seen"], p["sz"]), 0))
        e.st(p["pending"], 0)
        e.st(p["members"], 0)
        e.var("nseen", 0)

        def push(record):
            e.if_(e.eq(at(e, p["seen"], record), 0), lambda: (e.st(e.add(p["seen"], record), 1), e.set("nseen", e.add(p["nseen"], 1)),
                                                             e.st(e.add(p["pending"], e.add(e.ld(p["pending"]), 1)), record),
                                                             e.st(p["pending"], e.add(e.ld(p["pending"]), 1))))

        def closure_root():
            """``{view.name: view for view in exports}.values()``: an export shadowed by a later one of its name is no root."""
            e.var("rx_later", 0)
            e.for_("rx_j", e.add(p["rx"], 1), e.udiv(e.ld(p["exports"]), 2), lambda: e.if_(
                same(at(e, p["exports"], e.add(1, e.mul(p["rx_j"], 2))), at(e, p["exports"], e.add(1, e.mul(p["rx"], 2)))), lambda: e.set("rx_later", 1)))
            e.if_(e.eq(p["rx_later"], 0), lambda: (e.var("rx_f", find(at(e, p["exports"], e.add(2, e.mul(p["rx"], 2))))), _ok(e, e.ne(p["rx_f"], NONE)),
                                                   push(p["rx_f"])))

        e.for_("rx", 0, e.udiv(e.ld(p["exports"]), 2), closure_root)

        def visit():
            e.var("vo", at(e, p["pending"], e.ld(p["pending"])))
            e.st(p["pending"], e.sub(e.ld(p["pending"]), 1))
            e.for_("vr", 0, nrefs(p["vo"]), lambda: (
                e.var("vr_o", find(call("an_incid", e.add(e.add(rec(p["vo"]), 2), e.mul(p["vr"], CID_WORDS))))), _ok(e, e.ne(p["vr_o"], NONE)), push(p["vr_o"])))

            def method_identity():
                e.st(G_END, e.add(payload_at(p["vo"]), payload_n(p["vo"])))
                e.st(G_CUR, payload_at(p["vo"]))
                e.var("vm_form", call("an_uleb"))

                def opaque():
                    e.var("vm_id", call("an_bstr"))
                    e.var("vm_pre", e.sel(e.ne(call("an_prefix", p["vm_id"], K(JMETHOD_PREFIXES[0])), 0), len(JMETHOD_PREFIXES[0]),
                                          e.sel(e.ne(call("an_prefix", p["vm_id"], K(JMETHOD_PREFIXES[1])), 0), len(JMETHOD_PREFIXES[1]), 0)))

                    def member():
                        e.var("vm_tail", call("an_tail", p["vm_id"], e.add(p["vm_pre"], 1)))
                        e.st(G_CUR, 0)
                        e.var("vm_owner", _bstr_at(e, p["vm_tail"], "vm"))
                        e.var("vm_name", _bstr_at(e, p["vm_tail"], "vm"))
                        e.var("vm_desc", _bstr_at(e, p["vm_tail"], "vm"))
                        for name in ("vm_owner", "vm_name", "vm_desc"):
                            _ok(e, e.ne(call("an_utf16", p[name]), NONE))
                        e.var("vm_dup", 0)
                        e.for_("vm_j", 0, e.ld(p["members"]), lambda: e.if_(e.both(
                            same(at(e, p["members"], e.add(1, e.mul(p["vm_j"], 3))), p["vm_owner"]),
                            same(at(e, p["members"], e.add(2, e.mul(p["vm_j"], 3))), p["vm_name"]),
                            same(at(e, p["members"], e.add(3, e.mul(p["vm_j"], 3))), p["vm_desc"])), lambda: e.set("vm_dup", 1)))

                        def add():
                            base = e.add(p["members"], e.mul(e.ld(p["members"]), 3))
                            e.st(e.add(base, 1), p["vm_owner"])
                            e.st(e.add(base, 2), p["vm_name"])
                            e.st(e.add(base, 3), p["vm_desc"])
                            e.st(p["members"], e.add(e.ld(p["members"]), 1))

                        e.if_(e.eq(p["vm_dup"], 0), add)

                    e.if_(e.ne(p["vm_pre"], 0), member)

                e.if_(e.both(e.eq(p["vm_form"], 6), e.eq(nrefs(p["vo"]), 0)), opaque)

            e.if_(e.both(e.eq(kind(p["vo"]), int(Kind.TYPE)), e.lt(0, payload_n(p["vo"]))), method_identity)

        e.while_(lambda: e.ne(e.ld(p["pending"]), 0), visit)

        # M1. The managed rules program (S15e.6f.2) on ``_facts``'s words: the verdict (``Mk``), its class and method, its texts.
        e = _Slotted((yield), slots)
        p = e.p
        e.if_(e.eq(p["managed"], 0), lambda: e.give(1))
        put_utf8 = lambda h: call("an_seqput", h)  # noqa: E731 - a text: its UTF-8 bytes, one per word
        units = lambda h: call("an_seqput", call("an_utf16", h))  # noqa: E731

        def data_cid_rec(record):
            put(32)
            for w in range(CID_WORDS):
                for i in range(8):
                    put(e.and_(e.udiv(e.rd(e.add(cid_at(record), w)), 1 << (56 - 8 * i)), 255))

        def data_cid(h):
            put(32)
            for w in range(CID_WORDS):
                for i in range(8):
                    put(e.and_(e.udiv(at(e, h, 1 + w), 1 << (56 - 8 * i)), 255))

        def texts_put(lst):
            put(e.ld(lst))
            e.for_("tp_k", 1, e.add(e.ld(lst), 1), lambda: put_utf8(at(e, lst, p["tp_k"])))

        e.var("in_mfacts", e.ld(G_W))
        put(p["ncls"])

        def class_facts():
            data_cid_rec(cls(p["fc"], MC_REC))
            put_utf8(cls(p["fc"], MC_DESC))
            call("an_seqput", cls(p["fc"], MC_DESC16))
            put_utf8(cls(p["fc"], MC_SUPER))
            texts_put(cls(p["fc"], MC_IFACES))
            e.var("fc_m", cls(p["fc"], MC_METHODS))
            put(e.ld(p["fc_m"]))
            e.for_("fm", 0, e.ld(p["fc_m"]), lambda: (
                e.var("fm_r", e.add(e.add(p["fc_m"], 1), e.mul(p["fm"], MM_WORDS))),
                put_utf8(e.ld(e.add(p["fm_r"], MM_NAME))), put_utf8(e.ld(e.add(p["fm_r"], MM_DESC))), put(e.ld(e.add(p["fm_r"], MM_SUPER))),
                units(e.ld(e.add(p["fm_r"], MM_NATIVE)))))

        e.for_("fc", 0, p["ncls"], class_facts)
        put_utf8(p["f_activity"])
        put(p["f_min"])
        put(p["f_target"])
        put(e.udiv(e.ld(p["exports"]), 2))

        def export_facts():
            call("an_seqput", at(e, p["exports"], e.add(1, e.mul(p["fx"], 2))))
            e.var("fx_f", at(e, p["exports"], e.add(2, e.mul(p["fx"], 2))))
            data_cid(p["fx_f"])
            e.var("fx_rec", find(p["fx_f"]))
            _ok(e, e.both(e.ne(p["fx_rec"], NONE), e.eq(kind(e.sel(e.eq(p["fx_rec"], NONE), 0, p["fx_rec"])), int(Kind.FUNCTION))))
            for results in (False, True):
                e.var("fx_types", interface_types(p["fx_rec"], results))
                put(e.ld(p["fx_types"]))
                e.for_("fx_t", 1, e.add(e.ld(p["fx_types"]), 1), lambda: type_fact(at(e, p["fx_types"], p["fx_t"])))

        e.for_("fx", 0, e.udiv(e.ld(p["exports"]), 2), export_facts)
        data_cid(p["entry"])
        put(p["perms_n"])
        e.for_("fp", 0, p["perms_n"], lambda: (put_utf8(at(e, p["perms"], e.add(1, e.mul(p["fp"], DECL_WORDS)))),
                                               put(at(e, p["perms"], e.add(2, e.mul(p["fp"], DECL_WORDS))))))
        put(p["comps_n"])
        e.for_("fq", 0, p["comps_n"], lambda: (
            e.var("fq_r", e.add(e.add(p["comps"], 1), e.mul(p["fq"], DECL_WORDS))),
            put_utf8(e.ld(e.add(p["fq_r"], 5))), put_utf8(e.ld(p["fq_r"])), texts_put(e.ld(e.add(p["fq_r"], 2))), texts_put(e.ld(e.add(p["fq_r"], 6)))))
        put(e.mul(e.ld(p["members"]), 3))
        e.for_("fv", 1, e.add(e.mul(e.ld(p["members"]), 3), 1), lambda: put_utf8(at(e, p["members"], p["fv"])))
        put(p["nseen"])
        e.for_("fo", 0, p["nobj"], lambda: e.if_(e.ne(at(e, p["seen"], p["fo"]), 0), lambda: data_cid_rec(p["fo"])))
        layer(layers["managed_rules"], p["in_mfacts"])
        e.var("m_verdict", e.ld(1))
        e.var("m_class", e.ld(2))
        e.var("m_method", e.ld(3))
        e.var("m_texts", e.alloc(e.add(e.ld(MANAGED_TEXT_AT), 1)))  # the texts, kept as handles
        _ok(e, e.ne(p["m_texts"], NONE))
        e.st(p["m_texts"], e.ld(MANAGED_TEXT_AT))
        e.var("mt_at", MANAGED_TEXT_AT + 1)
        e.for_("mt", 0, e.ld(MANAGED_TEXT_AT), lambda: (
            e.var("mt_h", e.alloc(e.add(e.ld(p["mt_at"]), 1))), _ok(e, e.ne(p["mt_h"], NONE)),
            e.for_("mt_j", 0, e.add(e.ld(p["mt_at"]), 1), lambda: e.st(e.add(p["mt_h"], p["mt_j"]), e.ld(e.add(p["mt_at"], p["mt_j"])))),
            e.st(e.add(p["m_texts"], e.add(p["mt"], 1)), p["mt_h"]),
            e.set("mt_at", e.add(e.add(p["mt_at"], 1), e.ld(p["mt_at"])))))

        # The sites' diagnostics (``_build_android_managed_apk``).
        def sorted_texts(handles_fn, stem):
            """A list of texts sorted by their bytes (duplicates kept)."""
            def write():
                e.var(f"{stem}_l", handles_fn())
                n = e.ld(p[f"{stem}_l"])
                e.for_(f"{stem}_i", 2, e.add(n, 1), lambda: (
                    e.var(f"{stem}_x", at(e, p[f"{stem}_l"], p[f"{stem}_i"])), e.var(f"{stem}_j", p[f"{stem}_i"]),
                    e.while_(lambda: e.both(e.lt(1, p[f"{stem}_j"]), e.ne(call("an_less", p[f"{stem}_x"], at(e, p[f"{stem}_l"], e.sel(e.lt(1, p[f"{stem}_j"]), e.sub(p[f"{stem}_j"], 1), 1))), 0)),
                             lambda: (e.st(e.add(p[f"{stem}_l"], p[f"{stem}_j"]), at(e, p[f"{stem}_l"], e.sub(p[f"{stem}_j"], 1))), e.set(f"{stem}_j", e.sub(p[f"{stem}_j"], 1)))),
                    e.st(e.add(p[f"{stem}_l"], p[f"{stem}_j"]), p[f"{stem}_x"])))
                D.put(e, D.T_LIST)
                D.put(e, n)
                e.for_(f"{stem}_w", 1, e.add(n, 1), lambda: d_str(at(e, p[f"{stem}_l"], p[f"{stem}_w"])))
            return write

        def class_field_list(field):
            def make():
                e.var("cf_l", e.alloc(e.add(p["ncls"], 1)))
                _ok(e, e.ne(p["cf_l"], NONE))
                e.st(p["cf_l"], p["ncls"])
                e.for_("cf_k", 0, p["ncls"], lambda: e.st(e.add(p["cf_l"], e.add(p["cf_k"], 1)), cls(p["cf_k"], field)))
                return p["cf_l"]
            return make

        def method_at(k, j):
            return e.add(e.add(cls(k, MC_METHODS), 1), e.mul(j, MM_WORDS))

        e.var("m_symbol", 0)
        e.if_(e.both(e.lt(p["m_class"], p["ncls"]), e.lt(0, p["m_verdict"])), lambda: e.if_(e.lt(p["m_method"], e.ld(cls(p["m_class"], MC_METHODS))), lambda: e.set(
            "m_symbol", call("an_jni", cls(p["m_class"], MC_DESC16), call("an_utf16", e.ld(e.add(method_at(p["m_class"], p["m_method"]), MM_NATIVE)))))))
        names_sorted_ = names_sorted()

        def m5_expected():
            e.var("m5_m", method_at(p["m_class"], p["m_method"]))
            e.var("m5_b", e.alloc(e.add(e.add(e.add(e.ld(cls(p["m_class"], MC_JAVA)), e.ld(e.ld(e.add(p["m5_m"], MM_NAME)))), e.ld(e.ld(e.add(p["m5_m"], MM_DESC)))), 2)))
            _ok(e, e.ne(p["m5_b"], NONE))
            e.st(p["m5_b"], 0)
            call("an_cat", p["m5_b"], cls(p["m_class"], MC_JAVA))
            call("an_cat", p["m5_b"], K(b"."))
            call("an_cat", p["m5_b"], e.ld(e.add(p["m5_m"], MM_NAME)))
            call("an_cat", p["m5_b"], e.ld(e.add(p["m5_m"], MM_DESC)))
            d_str(p["m5_b"])

        MSITES = {
            1: (d_lid, "ANDROID-MANAGED-CLASS-UNIQUE", text_("distinct class descriptors"), sorted_texts(class_field_list(MC_DESC), "m1")),
            2: (rec_of("manifest"), "ANDROID-MANAGED-DEX039-MINSDK", text_(">= 28"), integer(p["f_min"])),
            3: (rec_of("manifest"), "ANDROID-APK-ACTIVITY-IDENTITY", sorted_texts(class_field_list(MC_JAVA), "m3"), string("f_activity")),
            4: (d_lid, "ANDROID-MANAGED-EXPORT", lambda: d_str(p["m_symbol"]), names_sorted_),
            5: (lambda: call("an_dcid", export_of(p["m_symbol"], "m5_f")), "ANDROID-MANAGED-JNI-SIGNATURE", m5_expected,
                lambda: d_str(at(e, p["m_texts"], 1), raw=True)),
            6: (d_lid, "ANDROID-APK-BUILD-ENTRY", text_("an export of the manifest Activity"), lambda: call("an_dcid", p["entry"])),
            7: (lambda: e.if_(e.ne(count("declarations"), 0), rec_of("declarations"), text_("managed-apk")), "ANDROID-PLATFORM-RULES",
                text_("no platform-rule violations"), lambda: (D.put(e, D.T_LIST), D.put(e, e.ld(p["m_texts"])),
                                                              e.for_("m7_k", 1, e.add(e.ld(p["m_texts"]), 1), lambda: d_str(at(e, p["m_texts"], p["m7_k"]), raw=True)))),
        }
        for k, (entity, rule, expected, actual) in MSITES.items():
            e.if_(e.eq(p["m_verdict"], k), lambda entity=entity, rule=rule, expected=expected, actual=actual: reject(entity, rule, expected, actual))
        _ok(e, e.eq(p["m_verdict"], 0))
        # The Activity class (the manifest's), first in the DEX files; the others by descriptor.
        e.var("m_activity", NONE)
        e.for_("ma", 0, p["ncls"], lambda: e.if_(e.both(e.eq(p["m_activity"], NONE), same(cls(p["ma"], MC_JAVA), p["f_activity"])), lambda: e.set("m_activity", p["ma"])))
        _ok(e, e.ne(p["m_activity"], NONE))
        e.var("m_order", e.alloc(e.add(p["ncls"], 1)))
        _ok(e, e.ne(p["m_order"], NONE))
        e.st(p["m_order"], 0)
        e.st(e.add(p["m_order"], 1), p["m_activity"])

        def order_class():
            e.var("oc_j", e.ld(p["m_order"]))
            e.var("oc_go", 1)
            e.while_(lambda: e.both(e.ne(p["oc_go"], 0), e.lt(1, p["oc_j"])), lambda: e.if_(
                e.ne(call("an_less", cls(p["oc"], MC_DESC), cls(at(e, p["m_order"], p["oc_j"]), MC_DESC)), 0),
                lambda: (e.st(e.add(p["m_order"], e.add(p["oc_j"], 1)), at(e, p["m_order"], p["oc_j"])), e.set("oc_j", e.sub(p["oc_j"], 1))),
                lambda: e.set("oc_go", 0)))
            e.st(e.add(p["m_order"], e.add(p["oc_j"], 1)), p["oc"])
            e.st(p["m_order"], e.add(e.ld(p["m_order"]), 1))

        e.st(p["m_order"], 1)
        e.for_("oc", 0, p["ncls"], lambda: e.if_(e.ne(p["oc"], p["m_activity"]), order_class))

        # The roots: a roots-only call stops here.
        compute_roots()

        # M2. The layers' inputs (``lower_android_managed_class``, the manifest with its declarations), the layers, the APK.
        e = _Slotted((yield), slots)
        p = e.p
        e.if_(e.eq(p["managed"], 0), lambda: e.give(1))
        text = lambda h: call("an_seqput", h)  # noqa: E731
        e.var("in_mmanifest", e.ld(G_W))
        put(0)
        call("an_seqput", p["f_package"])
        call("an_seqput", p["f_activity"])
        for name in ("f_version", "f_min", "f_target", "f_launcher", "f_debug"):
            put(p[name])
        put(0)  # no application
        put(0)  # no receivers
        put(0)  # no services

        def declared():
            put(1)
            put(p["perms_n"])
            e.for_("dp", 0, p["perms_n"], lambda: (e.var("dp_r", e.add(e.add(p["perms"], 1), e.mul(p["dp"], DECL_WORDS))), call("an_seqput", e.ld(p["dp_r"])),
                                                   put(e.ld(e.add(p["dp_r"], 1))), put(e.ld(e.add(p["dp_r"], 2)))))
            put(p["feats_n"])
            e.for_("df", 0, p["feats_n"], lambda: (e.var("df_r", e.add(e.add(p["feats"], 1), e.mul(p["df"], DECL_WORDS))), call("an_seqput", e.ld(p["df_r"])),
                                                   put(e.ld(e.add(p["df_r"], 1)))))
            put(p["comps_n"])
            e.for_("dc", 0, p["comps_n"], lambda: (
                e.var("dc_r", e.add(e.add(p["comps"], 1), e.mul(p["dc"], DECL_WORDS))), put(e.ld(e.add(p["dc_r"], 4))), call("an_seqput", e.ld(p["dc_r"])),
                put(e.ld(e.add(p["dc_r"], 1))), put(e.flag(e.ne(e.ld(e.ld(e.add(p["dc_r"], 2))), 0))), put(e.ld(e.add(p["dc_r"], 3))),
                put(e.ld(e.ld(e.add(p["dc_r"], 6)))), e.for_("dc_a", 1, e.add(e.ld(e.ld(e.add(p["dc_r"], 6))), 1),
                                                         lambda: call("an_seqput", at(e, e.ld(e.add(p["dc_r"], 6)), p["dc_a"])))))

        e.if_(e.ne(count("declarations"), 0), declared, lambda: put(0))

        def managed_bridge(k):
            """``lower_android_managed_class``: the natives (sorted by name) forwarded by the methods' overrides."""
            text(cls(k, MC_DESC16))
            units(cls(k, MC_SUPER))
            put(ACC_PUBLIC_FINAL_CLASS)
            e.var("mb_if", cls(k, MC_IFACES))
            put(e.ld(p["mb_if"]))
            e.for_("mb_i", 1, e.add(e.ld(p["mb_if"]), 1), lambda: units(at(e, p["mb_if"], p["mb_i"])))
            put(1)
            units(cls(k, MC_LIB))
            put(0)  # no deferred-load override
            e.var("mb_m", cls(k, MC_METHODS))
            e.var("mb_order", e.alloc(e.add(e.ld(p["mb_m"]), 1)))  # the methods by native name
            _ok(e, e.ne(p["mb_order"], NONE))
            e.st(p["mb_order"], 0)

            def rank():
                e.var("rk_r", e.add(e.add(p["mb_m"], 1), e.mul(p["rk"], MM_WORDS)))
                e.var("rk_j", e.ld(p["mb_order"]))
                e.var("rk_go", 1)
                e.while_(lambda: e.both(e.ne(p["rk_go"], 0), e.lt(0, p["rk_j"])), lambda: e.if_(
                    e.ne(call("an_less", e.ld(e.add(p["rk_r"], MM_NATIVE)), e.ld(e.add(at(e, p["mb_order"], p["rk_j"]), MM_NATIVE))), 0),
                    lambda: (e.st(e.add(p["mb_order"], e.add(p["rk_j"], 1)), at(e, p["mb_order"], p["rk_j"])), e.set("rk_j", e.sub(p["rk_j"], 1))),
                    lambda: e.set("rk_go", 0)))
                e.st(e.add(p["mb_order"], e.add(p["rk_j"], 1)), p["rk_r"])
                e.st(p["mb_order"], e.add(e.ld(p["mb_order"]), 1))

            e.for_("rk", 0, e.ld(p["mb_m"]), rank)

            def proto_(r):
                units(e.ld(e.add(r, MM_RESULT)))
                e.var("pr_l", e.ld(e.add(r, MM_PARAMS)))
                put(e.ld(p["pr_l"]))
                e.for_("pr_k", 1, e.add(e.ld(p["pr_l"]), 1), lambda: units(at(e, p["pr_l"], p["pr_k"])))

            put(e.ld(p["mb_m"]))
            e.for_("mn", 1, e.add(e.ld(p["mb_order"]), 1), lambda: (e.var("mn_r", at(e, p["mb_order"], p["mn"])), units(e.ld(e.add(p["mn_r"], MM_NATIVE))),
                                                                   proto_(p["mn_r"]), put(ACC_NATIVE_METHOD)))
            put(e.ld(p["mb_m"]))
            e.for_("mo", 0, e.ld(p["mb_m"]), lambda: (
                e.var("mo_r", e.add(e.add(p["mb_m"], 1), e.mul(p["mo"], MM_WORDS))), units(e.ld(e.add(p["mo_r"], MM_NAME))), proto_(p["mo_r"]),
                units(e.ld(e.add(p["mo_r"], MM_NATIVE))), put(e.ld(e.add(p["mo_r"], MM_ACCESS))), put(e.ld(e.add(p["mo_r"], MM_SUPER)))))
            for _ in range(12):
                put(0)  # no null returns, constant or echo methods, assembled methods, UI, click text or libxposed shapes

        e.var("in_mdex", e.alloc(e.add(p["ncls"], 1)))
        _ok(e, e.ne(p["in_mdex"], NONE))
        e.for_("md", 1, e.add(p["ncls"], 1), lambda: (e.st(e.add(p["in_mdex"], p["md"]), e.ld(G_W)), managed_bridge(at(e, p["m_order"], p["md"]))))
        e.var("in_marsc", e.ld(G_W))
        e.if_(e.eq(count("resources"), 1), arsc)
        shared_object()
        layer(layers["resources"], p["in_mmanifest"])
        e.var("m_axml", call("an_record"))
        e.var("m_dex", e.alloc(e.add(p["ncls"], 1)))
        _ok(e, e.ne(p["m_dex"], NONE))
        e.for_("mx", 1, e.add(p["ncls"], 1), lambda: (layer(layers["dex"], at(e, p["in_mdex"], p["mx"])), e.st(e.add(p["m_dex"], p["mx"]), call("an_record"))))
        e.var("m_arsc", 0)
        e.if_(e.eq(count("resources"), 1), lambda: (layer(layers["resources"], p["in_marsc"]), e.set("m_arsc", call("an_record"))))
        e.var("in_mapk", e.ld(G_W))
        put(e.add(e.add(p["ncls"], 2), count("resources")))
        entry(K(b"AndroidManifest.xml"), p["m_axml"], ENTRY_ALIGNMENT)
        entry(K(b"lib/arm64-v8a/libxaxapp.so"), p["so"], NATIVE_ALIGNMENT)
        entry(K(b"classes.dex"), at(e, p["m_dex"], 1), ENTRY_ALIGNMENT)
        e.var("nd", 0)
        e.for_("my", 2, e.add(p["ncls"], 1), lambda: (entry(e.sel(e.eq(p["my"], 2), K(b"classes2.dex"), dex_name()), at(e, p["m_dex"], p["my"]), ENTRY_ALIGNMENT),
                                                     e.set("nd", e.add(p["nd"], e.flag(e.lt(2, p["my"]))))))
        e.if_(e.eq(count("resources"), 1), lambda: entry(K(b"resources.arsc"), p["m_arsc"], ENTRY_ALIGNMENT))
        layer(layers["apk"], p["in_mapk"])

    functions, names, generator = [], (), None
    for k in range(PHASES):
        def build(e: E, k=k, names=names):
            nonlocal generator
            for j, name in enumerate(names):
                e.var(name, e.ld(SPILL_AT + j))
            try:
                if generator is None:
                    generator = body(e)
                    next(generator)
                else:
                    generator.send(e)
            except StopIteration:
                pass
            if k + 1 < PHASES:
                spilled = tuple(name for name in e.p.order if e.p.types[name] is B64)
                assert len(spilled) <= SPILL_WORDS
                for j, name in enumerate(spilled):
                    e.st(SPILL_AT + j, e.p[name])
                built.append(spilled)
            e.give(1)

        built: list = []
        functions.append(_function((), build, tables))
        names = built[0] if built else ()
    return functions


def _frontend(tables, phases):
    """The frontend: each phase in turn; a phase's 2 is the roots-only output."""
    def build(e: E):
        p = e.p
        for k, function in enumerate(phases):
            e.var("ph", e.call(function))
            e.if_(e.eq(p["ph"], NONE), lambda: e.give(NONE))  # the phase recorded its site
            e.if_(e.eq(p["ph"], 2), lambda: e.give(1))
        e.give(1)
    return _function((), build, tables)


def _pow2_small(e: E, k):
    """``2 ** k`` for ``k`` in 0..7."""
    result = e.c(1)
    for q in range(1, 8):
        result = e.sel(e.eq(k, q), 1 << q, result)
    return result


def _bstr_at(e: E, h, stem: str):
    """``Cursor.byte_string`` over handle ``h``'s items, at the cursor ``G_CUR`` (an index from 0)."""
    n = _uleb_at(e, h, stem)
    e.var(f"{stem}_bn", n)
    e.var(f"{stem}_ba", e.ld(G_CUR))
    _ok(e, e.le(e.add(e.p[f"{stem}_ba"], e.p[f"{stem}_bn"]), e.ld(h)))
    e.var(f"{stem}_bh", e.alloc(e.add(e.p[f"{stem}_bn"], 1)))
    _ok(e, e.ne(e.p[f"{stem}_bh"], NONE))
    e.st(e.p[f"{stem}_bh"], e.p[f"{stem}_bn"])
    e.for_(f"{stem}_bk", 0, e.p[f"{stem}_bn"], lambda: e.st(e.add(e.add(e.p[f"{stem}_bh"], 1), e.p[f"{stem}_bk"]),
                                                             at(e, h, e.add(e.add(e.p[f"{stem}_ba"], e.p[f"{stem}_bk"]), 1))))
    e.st(G_CUR, e.add(e.p[f"{stem}_ba"], e.p[f"{stem}_bn"]))
    return e.p[f"{stem}_bh"]


def _byte_at(e: E, h, stem: str):
    e.var(f"{stem}_ya", e.ld(G_CUR))
    _ok(e, e.lt(e.p[f"{stem}_ya"], e.ld(h)))
    e.st(G_CUR, e.add(e.p[f"{stem}_ya"], 1))
    return at(e, h, e.add(e.p[f"{stem}_ya"], 1))


def _uleb_at(e: E, h, stem: str):
    """A minimal ULEB128 below 2**56 over handle ``h``'s items at ``G_CUR``."""
    p = e.p
    e.var(f"{stem}_uv", 0)
    e.var(f"{stem}_us", 0)
    e.var(f"{stem}_ug", 1)

    def step():
        e.var(f"{stem}_ub", _byte_at(e, h, stem))
        b = p[f"{stem}_ub"]
        _ok(e, e.lt(p[f"{stem}_us"], 56))
        e.set(f"{stem}_uv", e.or_(p[f"{stem}_uv"], e.mul(e.and_(b, 127), _pow2(e, p[f"{stem}_us"]))))
        e.if_(e.eq(e.and_(b, 128), 0), lambda: (_ok(e, e.either(e.ne(b, 0), e.eq(p[f"{stem}_us"], 0))), e.set(f"{stem}_ug", 0)))
        e.set(f"{stem}_us", e.add(p[f"{stem}_us"], 7))

    e.while_(lambda: e.ne(p[f"{stem}_ug"], 0), step)
    _ok(e, e.lt(p[f"{stem}_uv"], 1 << 56))
    return p[f"{stem}_uv"]


def _layers():
    """The chained layer programs' entries and objects: the AArch64 program as built (it reads this input), the others
    built with their input redirected to output memory."""
    import xax_selfhost_aarch64_general as A64
    import xax_selfhost_android_elf as ELF
    import xax_selfhost_android_resources as RES
    import xax_selfhost_android_managed_rules as MANAGED_RULES
    import xax_selfhost_android_rules as RULES
    import xax_selfhost_apk as APK
    import xax_selfhost_dex as DEX

    layers, objects = {}, []
    reader, layers["aarch64"] = A64.load_aarch64_program()
    objects.extend(reader.objects())
    F.INPUT_REDIRECT = G_INBASE
    try:
        for name, build in (("elf", ELF.build_android_elf_program), ("resources", RES.build_resources_program), ("dex", DEX.build_dex_program),
                            ("apk", APK.build_apk_program), ("rules", RULES.build_rules_program),
                            ("managed_rules", MANAGED_RULES.build_managed_rules_program)):
            reader, layers[name] = build()
            objects.extend(reader.objects())
    finally:
        F.INPUT_REDIRECT = None
    return layers, objects


def build_android_program():
    """``(reader, function)``: the Android program's store and its entry."""
    tables = None
    layers, objects = _layers()
    _FN.clear()
    DECLINE_SITES.clear()  # numbered per build, not per process

    def add(name, made):
        function, items = made
        objects.extend(items)
        _FN[name] = function
        return function

    for name, builder in HELPERS:
        add(name, builder(tables))
    phases = []
    for function, items in _phases(tables, layers):
        objects.extend(items)
        phases.append(function)
    program = add("frontend", _frontend(tables, phases))
    unique = tuple({obj.cid: obj for obj in objects}.values())
    return program_store(program, x86_64_linux_exec_target(), unique), program


_PROGRAM = NativeProgram(STORE_PATH, build_android_program, "android")
load_android_program = _PROGRAM.load
write_android_store = _PROGRAM.write
OPT_OUT = "XAX_ANDROID_PYTHON"


def android_with_xax(reader, package_view, target_object, build_entry_function, *, required: bool = False) -> bytes | None:
    """The unsigned APK the XAX Android program builds for the package, or None where it cannot run or declines (the
    bootstrap then decides), unless ``required``."""
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
                    len(identity), *identity]

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
