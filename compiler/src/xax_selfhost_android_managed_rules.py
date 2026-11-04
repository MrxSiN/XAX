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

from xax_native import bootstrap_dir
from xax_selfhost_facts import E
from xax_selfhost_views_backend import NativeProgram

STORE_PATH = bootstrap_dir() / "xax_android_managed_rules.xax"
TEXT_AT = 4096
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


def at(e: E, base, k):
    return e.ld(e.add(base, k))


# -- reading: the input and the tables ---------------------------------------------------------------------------------------


# -- texts ----------------------------------------------------------------------------------------------------------------------


_PROGRAM = NativeProgram(STORE_PATH, "android-managed-rules")
load_managed_rules_program = _PROGRAM.load
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
