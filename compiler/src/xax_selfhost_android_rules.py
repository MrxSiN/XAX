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

from xax_native import bootstrap_dir
from xax_selfhost_facts import E
from xax_selfhost_views_backend import NativeProgram

STORE_PATH = bootstrap_dir() / "xax_android_rules.xax"
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
NAMES = (b"native_init",)
PREFIX_BYTES = 64


def at(e: E, base, k):
    return e.ld(e.add(base, k))


# -- reading ----------------------------------------------------------------------------------------------------------------


# -- the rules --------------------------------------------------------------------------------------------------------------


_PROGRAM = NativeProgram(STORE_PATH, "android-rules")
load_rules_program = _PROGRAM.load
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
