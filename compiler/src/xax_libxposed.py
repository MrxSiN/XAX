"""Canonical modern libxposed module metadata for Android APK lowering.

libxposed is an external platform package, not XAX kernel semantics.  This module
models only the current module-entry/scope metadata required to package generated
XAX artifacts without Gradle or handwritten resource files.
"""
from __future__ import annotations

from dataclasses import dataclass

from xax_compiler import Cursor, Kind, SemanticObject, fail, target, uleb


LIBXPOSED_MODULE_PREFIX = b"libxposed-module-v1"
LIBXPOSED_MANAGED_ENTRY_PREFIX = b"libxposed-managed-entry-v1"
LIBXPOSED_HOOK_ADAPTER_PREFIX = b"libxposed-hook-adapter-v1"
LIBXPOSED_HOOK_INSTALL_PREFIX = b"libxposed-hook-install-v1"
LIBXPOSED_HOOK_RESULT_PREFIX = b"libxposed-hook-result-v1"
LIBXPOSED_HOOK_ARGUMENT_PREFIX = b"libxposed-hook-argument-v1"
LIBXPOSED_HOOK_COMBINED_PREFIX = b"libxposed-hook-combined-v1"
LIBXPOSED_DEOPTIMIZE_PREFIX = b"libxposed-deoptimize-v1"
LIBXPOSED_MODULE_SERVICES_PREFIX = b"libxposed-module-services-v1"
LIBXPOSED_REMOTE_PREFERENCES_PREFIX = b"libxposed-remote-preferences-v1"
LIBXPOSED_REMOTE_FILES_PREFIX = b"libxposed-remote-files-v1"
LIBXPOSED_HOT_RELOAD_PREFIX = b"libxposed-hot-reload-v1"

LIBXPOSED_XPOSED_MODULE = "Lio/github/libxposed/api/XposedModule;"
LIBXPOSED_MODULE_LOADED_PARAM = "Lio/github/libxposed/api/XposedModuleInterface$ModuleLoadedParam;"
LIBXPOSED_PACKAGE_READY_PARAM = "Lio/github/libxposed/api/XposedModuleInterface$PackageReadyParam;"
LIBXPOSED_MANAGED_CALLBACKS = ("onModuleLoaded", "onPackageReady")
LIBXPOSED_HOOKER = "Lio/github/libxposed/api/XposedInterface$Hooker;"


def _canonical_text(values: tuple[str, ...], label: str) -> tuple[str, ...]:
    for value in values:
        if not value or "\x00" in value or "\n" in value or "\r" in value:
            raise ValueError(f"{label} entries must be nonempty single-line text")
    return tuple(sorted(set(values), key=lambda value: value.encode("utf-8")))


@dataclass(frozen=True)
class LibxposedModuleDescription:
    min_api_version: int = 101
    target_api_version: int = 102
    static_scope: bool = True
    java_entries: tuple[str, ...] = ()
    native_entries: tuple[str, ...] = ()
    scopes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not 1 <= self.min_api_version <= self.target_api_version <= 0x7FFFFFFF:
            raise ValueError("invalid libxposed API version interval")
        java_entries = _canonical_text(self.java_entries, "java entry")
        native_entries = _canonical_text(self.native_entries, "native entry")
        scopes = _canonical_text(self.scopes, "scope")
        if not java_entries and not native_entries:
            raise ValueError("libxposed module requires at least one Java or native entry")
        for value in native_entries:
            if "/" in value or "\\" in value:
                raise ValueError("libxposed native entry must be an APK-local library base name")
        object.__setattr__(self, "java_entries", java_entries)
        object.__setattr__(self, "native_entries", native_entries)
        object.__setattr__(self, "scopes", scopes)


def _put_texts(out: bytearray, values: tuple[str, ...]) -> None:
    out.extend(uleb(len(values)))
    for value in values:
        raw = value.encode("utf-8")
        out.extend(uleb(len(raw)) + raw)


def _get_texts(cursor: Cursor) -> tuple[str, ...]:
    count = cursor.uleb()
    values: list[str] = []
    for _ in range(count):
        values.append(cursor.byte_string().decode("utf-8"))
    return tuple(values)


def libxposed_module_semantics(description: LibxposedModuleDescription) -> SemanticObject:
    identity = bytearray(LIBXPOSED_MODULE_PREFIX)
    identity.extend(uleb(description.min_api_version))
    identity.extend(uleb(description.target_api_version))
    identity.append(1 if description.static_scope else 0)
    _put_texts(identity, description.java_entries)
    _put_texts(identity, description.native_entries)
    _put_texts(identity, description.scopes)
    return target(bytes(identity))


def decode_libxposed_module(obj: SemanticObject) -> LibxposedModuleDescription:
    if obj.kind != Kind.TARGET or obj.references:
        fail("XAX.LIBXPOSED", obj.cid.hex(), "LIBXPOSED-CARRIER", Kind.TARGET.name, obj.kind.name)
    outer = Cursor(obj.body, obj.cid.hex())
    identity = outer.byte_string()
    outer.end("LIBXPOSED-CARRIER")
    if not identity.startswith(LIBXPOSED_MODULE_PREFIX):
        fail("XAX.LIBXPOSED", obj.cid.hex(), "LIBXPOSED-IDENTITY", LIBXPOSED_MODULE_PREFIX.decode(), identity[:40].hex())
    cursor = Cursor(identity[len(LIBXPOSED_MODULE_PREFIX):], obj.cid.hex())
    try:
        description = LibxposedModuleDescription(
            cursor.uleb(),
            cursor.uleb(),
            cursor.boolean(),
            _get_texts(cursor),
            _get_texts(cursor),
            _get_texts(cursor),
        )
        cursor.end("LIBXPOSED-IDENTITY")
    except (UnicodeDecodeError, ValueError) as error:
        fail("XAX.LIBXPOSED", obj.cid.hex(), "LIBXPOSED-FIELDS", "valid canonical libxposed metadata", str(error))
    canonical = libxposed_module_semantics(description)
    if canonical.cid != obj.cid:
        fail("XAX.LIBXPOSED", obj.cid.hex(), "LIBXPOSED-CANONICAL", canonical.cid.hex(), obj.cid.hex())
    return description



@dataclass(frozen=True)
class LibxposedManagedEntryDescription:
    java_class_name: str = "xax.generated.XaxModule"
    callbacks: tuple[str, ...] = LIBXPOSED_MANAGED_CALLBACKS

    def __post_init__(self) -> None:
        name = self.java_class_name
        if (
            not name
            or "\x00" in name
            or "/" in name
            or name.startswith(".")
            or name.endswith(".")
            or ".." in name
            or any(not part or not (part[0].isalpha() or part[0] in "_$") or not all(ch.isalnum() or ch in "_$" for ch in part) for part in name.split("."))
        ):
            raise ValueError("invalid libxposed managed entry Java class name")
        callbacks = tuple(sorted(set(self.callbacks), key=lambda item: LIBXPOSED_MANAGED_CALLBACKS.index(item) if item in LIBXPOSED_MANAGED_CALLBACKS else len(LIBXPOSED_MANAGED_CALLBACKS)))
        if not callbacks or any(item not in LIBXPOSED_MANAGED_CALLBACKS for item in callbacks):
            raise ValueError("unsupported libxposed managed lifecycle callback")
        if "onPackageReady" in callbacks and "onModuleLoaded" not in callbacks:
            raise ValueError("onPackageReady requires onModuleLoaded so native library loading occurs first")
        object.__setattr__(self, "callbacks", callbacks)

    @property
    def class_descriptor(self) -> str:
        return "L" + self.java_class_name.replace(".", "/") + ";"


def libxposed_managed_entry_semantics(description: LibxposedManagedEntryDescription = LibxposedManagedEntryDescription()) -> SemanticObject:
    identity = bytearray(LIBXPOSED_MANAGED_ENTRY_PREFIX)
    name = description.java_class_name.encode("utf-8")
    identity.extend(uleb(len(name)) + name)
    _put_texts(identity, description.callbacks)
    return target(bytes(identity))


def decode_libxposed_managed_entry(obj: SemanticObject) -> LibxposedManagedEntryDescription:
    if obj.kind != Kind.TARGET or obj.references:
        fail("XAX.LIBXPOSED", obj.cid.hex(), "LIBXPOSED-MANAGED-CARRIER", Kind.TARGET.name, obj.kind.name)
    outer = Cursor(obj.body, obj.cid.hex())
    identity = outer.byte_string()
    outer.end("LIBXPOSED-MANAGED-CARRIER")
    if not identity.startswith(LIBXPOSED_MANAGED_ENTRY_PREFIX):
        fail("XAX.LIBXPOSED", obj.cid.hex(), "LIBXPOSED-MANAGED-IDENTITY", LIBXPOSED_MANAGED_ENTRY_PREFIX.decode(), identity[:48].hex())
    cursor = Cursor(identity[len(LIBXPOSED_MANAGED_ENTRY_PREFIX):], obj.cid.hex())
    try:
        description = LibxposedManagedEntryDescription(
            cursor.byte_string().decode("utf-8"),
            _get_texts(cursor),
        )
        cursor.end("LIBXPOSED-MANAGED-IDENTITY")
    except (UnicodeDecodeError, ValueError) as error:
        fail("XAX.LIBXPOSED", obj.cid.hex(), "LIBXPOSED-MANAGED-FIELDS", "valid canonical managed entry", str(error))
    canonical = libxposed_managed_entry_semantics(description)
    if canonical.cid != obj.cid:
        fail("XAX.LIBXPOSED", obj.cid.hex(), "LIBXPOSED-MANAGED-CANONICAL", canonical.cid.hex(), obj.cid.hex())
    return description


@dataclass(frozen=True)
class LibxposedModuleServicesDescription:
    """Selected API-102 framework/module services exposed by generated DEX.

    Nothing is implicitly cached and no exception is swallowed. Remote service
    failures therefore propagate exactly as supplied by the framework.
    """

    services: tuple[str, ...] = (
        "framework-name",
        "framework-version",
        "remote-preferences",
    )
    failure_policy: str = "propagate"

    def __post_init__(self) -> None:
        allowed = (
            "framework-name",
            "framework-version",
            "remote-preferences",
            "list-remote-files",
            "open-remote-file",
        )
        values = tuple(item for item in allowed if item in self.services)
        if not values or len(self.services) != len(set(self.services)) or any(item not in allowed for item in self.services):
            raise ValueError("invalid libxposed module-service selection")
        if self.failure_policy != "propagate":
            raise ValueError("bounded libxposed module services require explicit propagate failure policy")
        object.__setattr__(self, "services", values)


def libxposed_module_services_semantics(
    description: LibxposedModuleServicesDescription = LibxposedModuleServicesDescription(),
) -> SemanticObject:
    identity = bytearray(LIBXPOSED_MODULE_SERVICES_PREFIX)
    _put_texts(identity, description.services)
    policy = description.failure_policy.encode("utf-8")
    identity.extend(uleb(len(policy)) + policy)
    return target(bytes(identity))


def decode_libxposed_module_services(obj: SemanticObject) -> LibxposedModuleServicesDescription:
    if obj.kind != Kind.TARGET or obj.references:
        fail("XAX.LIBXPOSED", obj.cid.hex(), "LIBXPOSED-SERVICES-CARRIER", Kind.TARGET.name, obj.kind.name)
    outer = Cursor(obj.body, obj.cid.hex())
    identity = outer.byte_string()
    outer.end("LIBXPOSED-SERVICES-CARRIER")
    if not identity.startswith(LIBXPOSED_MODULE_SERVICES_PREFIX):
        fail(
            "XAX.LIBXPOSED", obj.cid.hex(), "LIBXPOSED-SERVICES-IDENTITY",
            LIBXPOSED_MODULE_SERVICES_PREFIX.decode(), identity[:48].hex(),
        )
    cursor = Cursor(identity[len(LIBXPOSED_MODULE_SERVICES_PREFIX):], obj.cid.hex())
    try:
        description = LibxposedModuleServicesDescription(
            _get_texts(cursor),
            cursor.byte_string().decode("utf-8"),
        )
        cursor.end("LIBXPOSED-SERVICES-IDENTITY")
    except (UnicodeDecodeError, ValueError) as error:
        fail("XAX.LIBXPOSED", obj.cid.hex(), "LIBXPOSED-SERVICES-FIELDS", "valid canonical module services", str(error))
    canonical = libxposed_module_services_semantics(description)
    if canonical.cid != obj.cid:
        fail("XAX.LIBXPOSED", obj.cid.hex(), "LIBXPOSED-SERVICES-CANONICAL", canonical.cid.hex(), obj.cid.hex())
    return description


@dataclass(frozen=True)
class LibxposedRemotePreferencesDescription:
    """Bounded typed reads from libxposed remote SharedPreferences.

    Remote-resource availability is explicit.  The generated acquisition helper
    checks ``PROP_CAP_REMOTE`` and returns a nullable ``SharedPreferences`` when
    the framework does not advertise remote resources.  Once a preferences
    object exists, selected typed reads are direct Android ``SharedPreferences``
    interface calls: no editor/write path, cache, retry, allocation, or hidden
    exception translation is implied.
    """

    reads: tuple[str, ...] = (
        "boolean",
        "int",
        "long",
        "float",
        "string",
        "contains",
    )
    capability_policy: str = "nullable-on-unsupported"
    failure_policy: str = "propagate"

    def __post_init__(self) -> None:
        allowed = ("boolean", "int", "long", "float", "string", "contains")
        values = tuple(item for item in allowed if item in self.reads)
        if not values or len(self.reads) != len(set(self.reads)) or any(item not in allowed for item in self.reads):
            raise ValueError("invalid libxposed remote-preferences read selection")
        if self.capability_policy != "nullable-on-unsupported":
            raise ValueError("bounded libxposed remote preferences require nullable-on-unsupported capability policy")
        if self.failure_policy != "propagate":
            raise ValueError("bounded libxposed remote preferences require explicit propagate failure policy")
        object.__setattr__(self, "reads", values)


def libxposed_remote_preferences_semantics(
    description: LibxposedRemotePreferencesDescription = LibxposedRemotePreferencesDescription(),
) -> SemanticObject:
    identity = bytearray(LIBXPOSED_REMOTE_PREFERENCES_PREFIX)
    _put_texts(identity, description.reads)
    capability = description.capability_policy.encode("utf-8")
    failure = description.failure_policy.encode("utf-8")
    identity.extend(uleb(len(capability)) + capability)
    identity.extend(uleb(len(failure)) + failure)
    return target(bytes(identity))


def decode_libxposed_remote_preferences(obj: SemanticObject) -> LibxposedRemotePreferencesDescription:
    if obj.kind != Kind.TARGET or obj.references:
        fail("XAX.LIBXPOSED", obj.cid.hex(), "LIBXPOSED-REMOTE-PREFS-CARRIER", Kind.TARGET.name, obj.kind.name)
    outer = Cursor(obj.body, obj.cid.hex())
    identity = outer.byte_string()
    outer.end("LIBXPOSED-REMOTE-PREFS-CARRIER")
    if not identity.startswith(LIBXPOSED_REMOTE_PREFERENCES_PREFIX):
        fail(
            "XAX.LIBXPOSED", obj.cid.hex(), "LIBXPOSED-REMOTE-PREFS-IDENTITY",
            LIBXPOSED_REMOTE_PREFERENCES_PREFIX.decode(), identity[:56].hex(),
        )
    cursor = Cursor(identity[len(LIBXPOSED_REMOTE_PREFERENCES_PREFIX):], obj.cid.hex())
    try:
        description = LibxposedRemotePreferencesDescription(
            _get_texts(cursor),
            cursor.byte_string().decode("utf-8"),
            cursor.byte_string().decode("utf-8"),
        )
        cursor.end("LIBXPOSED-REMOTE-PREFS-IDENTITY")
    except (UnicodeDecodeError, ValueError) as error:
        fail(
            "XAX.LIBXPOSED", obj.cid.hex(), "LIBXPOSED-REMOTE-PREFS-FIELDS",
            "valid canonical remote-preferences policy", str(error),
        )
    canonical = libxposed_remote_preferences_semantics(description)
    if canonical.cid != obj.cid:
        fail(
            "XAX.LIBXPOSED", obj.cid.hex(), "LIBXPOSED-REMOTE-PREFS-CANONICAL",
            canonical.cid.hex(), obj.cid.hex(),
        )
    return description


@dataclass(frozen=True)
class LibxposedRemoteFilesDescription:
    """Capability-gated API-102 remote file access without hidden fallback."""

    operations: tuple[str, ...] = ("list", "open")
    capability_policy: str = "nullable-on-unsupported"
    failure_policy: str = "propagate"

    def __post_init__(self) -> None:
        allowed = ("list", "open")
        ordered = tuple(item for item in allowed if item in self.operations)
        if not ordered or len(self.operations) != len(set(self.operations)) or any(item not in allowed for item in self.operations):
            raise ValueError("invalid libxposed remote-file operation selection")
        if self.capability_policy != "nullable-on-unsupported":
            raise ValueError("bounded libxposed remote files require nullable-on-unsupported capability policy")
        if self.failure_policy != "propagate":
            raise ValueError("bounded libxposed remote files require explicit propagate failure policy")
        object.__setattr__(self, "operations", ordered)


def libxposed_remote_files_semantics(
    description: LibxposedRemoteFilesDescription = LibxposedRemoteFilesDescription(),
) -> SemanticObject:
    identity = bytearray(LIBXPOSED_REMOTE_FILES_PREFIX)
    _put_texts(identity, description.operations)
    for value in (description.capability_policy, description.failure_policy):
        raw = value.encode("utf-8")
        identity.extend(uleb(len(raw)) + raw)
    return target(bytes(identity))


def decode_libxposed_remote_files(obj: SemanticObject) -> LibxposedRemoteFilesDescription:
    if obj.kind != Kind.TARGET or obj.references:
        fail("XAX.LIBXPOSED", obj.cid.hex(), "LIBXPOSED-REMOTE-FILES-CARRIER", Kind.TARGET.name, obj.kind.name)
    outer = Cursor(obj.body, obj.cid.hex())
    identity = outer.byte_string()
    outer.end("LIBXPOSED-REMOTE-FILES-CARRIER")
    if not identity.startswith(LIBXPOSED_REMOTE_FILES_PREFIX):
        fail("XAX.LIBXPOSED", obj.cid.hex(), "LIBXPOSED-REMOTE-FILES-IDENTITY", LIBXPOSED_REMOTE_FILES_PREFIX.decode(), identity[:48].hex())
    cursor = Cursor(identity[len(LIBXPOSED_REMOTE_FILES_PREFIX):], obj.cid.hex())
    try:
        description = LibxposedRemoteFilesDescription(
            _get_texts(cursor),
            cursor.byte_string().decode("utf-8"),
            cursor.byte_string().decode("utf-8"),
        )
        cursor.end("LIBXPOSED-REMOTE-FILES-IDENTITY")
    except (UnicodeDecodeError, ValueError) as error:
        fail("XAX.LIBXPOSED", obj.cid.hex(), "LIBXPOSED-REMOTE-FILES-FIELDS", "valid canonical remote-file policy", str(error))
    canonical = libxposed_remote_files_semantics(description)
    if canonical.cid != obj.cid:
        fail("XAX.LIBXPOSED", obj.cid.hex(), "LIBXPOSED-REMOTE-FILES-CANONICAL", canonical.cid.hex(), obj.cid.hex())
    return description


@dataclass(frozen=True)
class LibxposedHotReloadDescription:
    """Bounded API-102 hot reload for exactly one retained, stable-ID hook.

    The old generation saves only the target/app ClassLoader captured from
    PackageReadyParam and rejects reload if target readiness never occurred. The
    new generation restores that host-owned loader, consumes the framework-supplied
    old HookHandle list, requires the build closure to prove there is exactly one
    generated retained hook, verifies that handle's API-102 hook ID, and atomically
    replaces it with the new generated Hooker. Missing/mismatched new-generation
    transfer state is an explicit no-op; framework failures still propagate. No
    module-defined saved object, arbitrary resource transfer, thread cleanup,
    listener cleanup, or lifecycle replay is inferred.
    """

    policy: str = "single-retained-hook-id-guarded-atomic-replace"
    failure_policy: str = "propagate"
    hook_id: str = "xax.primary"
    mismatch_policy: str = "skip-replacement"
    state_policy: str = "package-ready-class-loader"
    missing_state_policy: str = "reject-reload"

    def __post_init__(self) -> None:
        if self.policy != "single-retained-hook-id-guarded-atomic-replace":
            raise ValueError("unsupported bounded libxposed hot-reload policy")
        if self.failure_policy != "propagate":
            raise ValueError("bounded libxposed hot reload requires explicit propagate failure policy")
        if not self.hook_id or "\x00" in self.hook_id or "\n" in self.hook_id or "\r" in self.hook_id:
            raise ValueError("libxposed hot-reload hook ID must be nonempty single-line text")
        if self.mismatch_policy != "skip-replacement":
            raise ValueError("bounded libxposed hot reload requires explicit skip-replacement mismatch policy")
        if self.state_policy != "package-ready-class-loader":
            raise ValueError("bounded libxposed hot reload requires explicit package-ready-class-loader state policy")
        if self.missing_state_policy != "reject-reload":
            raise ValueError("bounded libxposed hot reload requires explicit reject-reload missing-state policy")


def libxposed_hot_reload_semantics(
    description: LibxposedHotReloadDescription = LibxposedHotReloadDescription(),
) -> SemanticObject:
    identity = bytearray(LIBXPOSED_HOT_RELOAD_PREFIX)
    for value in (
        description.policy, description.failure_policy, description.hook_id, description.mismatch_policy,
        description.state_policy, description.missing_state_policy,
    ):
        raw = value.encode("utf-8")
        identity.extend(uleb(len(raw)) + raw)
    return target(bytes(identity))


def decode_libxposed_hot_reload(obj: SemanticObject) -> LibxposedHotReloadDescription:
    if obj.kind != Kind.TARGET or obj.references:
        fail("XAX.LIBXPOSED", obj.cid.hex(), "LIBXPOSED-HOT-RELOAD-CARRIER", Kind.TARGET.name, obj.kind.name)
    outer = Cursor(obj.body, obj.cid.hex())
    identity = outer.byte_string()
    outer.end("LIBXPOSED-HOT-RELOAD-CARRIER")
    if not identity.startswith(LIBXPOSED_HOT_RELOAD_PREFIX):
        fail("XAX.LIBXPOSED", obj.cid.hex(), "LIBXPOSED-HOT-RELOAD-IDENTITY", LIBXPOSED_HOT_RELOAD_PREFIX.decode(), identity[:48].hex())
    cursor = Cursor(identity[len(LIBXPOSED_HOT_RELOAD_PREFIX):], obj.cid.hex())
    try:
        description = LibxposedHotReloadDescription(
            cursor.byte_string().decode("utf-8"),
            cursor.byte_string().decode("utf-8"),
            cursor.byte_string().decode("utf-8"),
            cursor.byte_string().decode("utf-8"),
            cursor.byte_string().decode("utf-8"),
            cursor.byte_string().decode("utf-8"),
        )
        cursor.end("LIBXPOSED-HOT-RELOAD-IDENTITY")
    except (UnicodeDecodeError, ValueError) as error:
        fail("XAX.LIBXPOSED", obj.cid.hex(), "LIBXPOSED-HOT-RELOAD-FIELDS", "valid canonical hot-reload policy", str(error))
    canonical = libxposed_hot_reload_semantics(description)
    if canonical.cid != obj.cid:
        fail("XAX.LIBXPOSED", obj.cid.hex(), "LIBXPOSED-HOT-RELOAD-CANONICAL", canonical.cid.hex(), obj.cid.hex())
    return description


def lower_libxposed_managed_entry(
    obj: SemanticObject,
    hook_installation: SemanticObject | None = None,
    deoptimization: SemanticObject | None = None,
    module_services: SemanticObject | None = None,
    remote_preferences: SemanticObject | None = None,
    hot_reload: SemanticObject | None = None,
    remote_files: SemanticObject | None = None,
):
    """Lower the bounded API-101/102 managed lifecycle entry directly to DEX.

    Hook installation and deoptimization are distinct semantic carriers.
    Deoptimization is deliberately never inferred from hooking: the current
    bounded profile accepts an explicit best-effort request for the exact hook
    target and reuses the already-resolved ``Method`` before installation.
    """
    from xax_dex import (
        ACC_PRIVATE, ACC_NATIVE, ACC_PUBLIC, DexBridgeSpec, DexForwardingOverride,
        DexLibxposedHookInstallSpec, DexLibxposedModuleServicesSpec,
        DexLibxposedRemotePreferencesSpec, DexLibxposedHotReloadSpec, DexLibxposedRemoteFilesSpec, DexNativeMethod, DexProto,
    )

    description = decode_libxposed_managed_entry(obj)
    callback_types = {
        "onModuleLoaded": LIBXPOSED_MODULE_LOADED_PARAM,
        "onPackageReady": LIBXPOSED_PACKAGE_READY_PARAM,
    }
    native_names = {
        "onModuleLoaded": "xaxOnModuleLoaded",
        "onPackageReady": "xaxOnPackageReady",
    }
    native_methods = []
    overrides = []
    for callback in description.callbacks:
        proto = DexProto("V", (callback_types[callback],))
        native_name = native_names[callback]
        native_methods.append(DexNativeMethod(native_name, proto, ACC_PRIVATE | ACC_NATIVE))
        overrides.append(DexForwardingOverride(callback, proto, native_name, ACC_PUBLIC, False))
    reload_description = decode_libxposed_hot_reload(hot_reload) if hot_reload is not None else None
    hook_install = None
    if hook_installation is not None:
        install = decode_libxposed_hook_installation(hook_installation)
        if "onPackageReady" not in description.callbacks:
            raise ValueError("libxposed hook installation requires onPackageReady callback")
        deoptimize_before_hook = False
        if deoptimization is not None:
            deopt = decode_libxposed_deoptimization(deoptimization)
            if (
                deopt.target_class_name != install.target_class_name
                or deopt.target_method_name != install.target_method_name
                or deopt.parameter_type_names != install.parameter_type_names
            ):
                raise ValueError("bounded libxposed deoptimization target must equal hook installation target")
            deoptimize_before_hook = True
        hook_install = DexLibxposedHookInstallSpec(
            install.target_class_name,
            install.target_method_name,
            "L" + install.hooker_class_name.replace(".", "/") + ";",
            install.parameter_type_names,
            install.exception_mode,
            install.failure_policy,
            install.lifetime_policy,
            deoptimize_before_hook,
            hook_id=install.hook_id,
        )
    elif deoptimization is not None:
        raise ValueError("bounded libxposed deoptimization currently requires a hook installation target")
    service_spec = None
    if module_services is not None:
        services = decode_libxposed_module_services(module_services)
        service_spec = DexLibxposedModuleServicesSpec(services.services, services.failure_policy)
    remote_preferences_spec = None
    if remote_preferences is not None:
        preferences = decode_libxposed_remote_preferences(remote_preferences)
        remote_preferences_spec = DexLibxposedRemotePreferencesSpec(
            preferences.reads,
            preferences.capability_policy,
            preferences.failure_policy,
        )
    remote_files_spec = None
    if remote_files is not None:
        files = decode_libxposed_remote_files(remote_files)
        remote_files_spec = DexLibxposedRemoteFilesSpec(
            files.operations, files.capability_policy, files.failure_policy,
        )
    hot_reload_spec = None
    if reload_description is not None:
        if hook_install is None:
            raise ValueError("bounded libxposed hot reload requires one hook installation")
        if hook_install.lifetime_policy != "retained-manual-unhook":
            raise ValueError("bounded libxposed hot reload requires retained-manual-unhook lifetime")
        if hook_install.hook_id != reload_description.hook_id:
            raise ValueError("bounded libxposed hot reload requires the installation's matching stable hook ID")
        hot_reload_spec = DexLibxposedHotReloadSpec(
            hook_install.hooker_class_descriptor,
            reload_description.policy,
            reload_description.failure_policy,
            reload_description.hook_id,
            reload_description.mismatch_policy,
            reload_description.state_policy,
            reload_description.missing_state_policy,
        )
    return DexBridgeSpec(
        description.class_descriptor,
        LIBXPOSED_XPOSED_MODULE,
        tuple(native_methods),
        tuple(overrides),
        native_library="xaxapp",
        native_library_load_override="onModuleLoaded",
        libxposed_hook_install=hook_install,
        libxposed_module_services=service_spec,
        libxposed_remote_preferences=remote_preferences_spec,
        libxposed_hot_reload=hot_reload_spec,
        libxposed_remote_files=remote_files_spec,
    )


@dataclass(frozen=True)
class LibxposedHookAdapterDescription:
    """One bounded API-102 interceptor-chain adapter.

    This semantic object intentionally does not imply hook installation.  It
    proves the managed hot-path ABI independently: inspect one argument, proceed
    exactly once, and return the original result.  Installation/target identity
    is modeled separately so a packaged adapter cannot be mistaken for an
    installed hook.
    """

    java_class_name: str = "xax.generated.XaxHooker"
    inspected_argument_index: int | None = 0

    def __post_init__(self) -> None:
        LibxposedManagedEntryDescription(self.java_class_name, ("onModuleLoaded",))
        if self.inspected_argument_index is not None and not 0 <= self.inspected_argument_index <= 7:
            raise ValueError("bounded libxposed hook adapter supports argument indices 0..7 or no inspection")

    @property
    def class_descriptor(self) -> str:
        return "L" + self.java_class_name.replace(".", "/") + ";"


def libxposed_hook_adapter_semantics(
    description: LibxposedHookAdapterDescription = LibxposedHookAdapterDescription(),
) -> SemanticObject:
    identity = bytearray(LIBXPOSED_HOOK_ADAPTER_PREFIX)
    name = description.java_class_name.encode("utf-8")
    identity.extend(uleb(len(name)) + name)
    identity.extend(uleb(8 if description.inspected_argument_index is None else description.inspected_argument_index))
    return target(bytes(identity))


def decode_libxposed_hook_adapter(obj: SemanticObject) -> LibxposedHookAdapterDescription:
    if obj.kind != Kind.TARGET or obj.references:
        fail("XAX.LIBXPOSED", obj.cid.hex(), "LIBXPOSED-HOOK-ADAPTER-CARRIER", Kind.TARGET.name, obj.kind.name)
    outer = Cursor(obj.body, obj.cid.hex())
    identity = outer.byte_string()
    outer.end("LIBXPOSED-HOOK-ADAPTER-CARRIER")
    if not identity.startswith(LIBXPOSED_HOOK_ADAPTER_PREFIX):
        fail(
            "XAX.LIBXPOSED", obj.cid.hex(), "LIBXPOSED-HOOK-ADAPTER-IDENTITY",
            LIBXPOSED_HOOK_ADAPTER_PREFIX.decode(), identity[:48].hex(),
        )
    cursor = Cursor(identity[len(LIBXPOSED_HOOK_ADAPTER_PREFIX):], obj.cid.hex())
    try:
        name = cursor.byte_string().decode("utf-8")
        encoded_index = cursor.uleb()
        description = LibxposedHookAdapterDescription(
            name,
            None if encoded_index == 8 else encoded_index,
        )
        cursor.end("LIBXPOSED-HOOK-ADAPTER-IDENTITY")
    except (UnicodeDecodeError, ValueError) as error:
        fail("XAX.LIBXPOSED", obj.cid.hex(), "LIBXPOSED-HOOK-ADAPTER-FIELDS", "valid canonical hook adapter", str(error))
    canonical = libxposed_hook_adapter_semantics(description)
    if canonical.cid != obj.cid:
        fail("XAX.LIBXPOSED", obj.cid.hex(), "LIBXPOSED-HOOK-ADAPTER-CANONICAL", canonical.cid.hex(), obj.cid.hex())
    return description


def lower_libxposed_hook_adapter(
    obj: SemanticObject,
    result_policy: SemanticObject | None = None,
    argument_policy: SemanticObject | None = None,
    combined_policy: SemanticObject | None = None,
):
    from xax_dex import DexBridgeSpec, DexLibxposedHookInterceptSpec

    description = decode_libxposed_hook_adapter(obj)
    if sum(item is not None for item in (result_policy, argument_policy, combined_policy)) > 1:
        raise ValueError("bounded libxposed adapter supports one mutation policy carrier at a time")
    result_replacement = None
    argument_replacement = None
    if result_policy is not None:
        policy = decode_libxposed_hook_result(result_policy)
        if policy.hooker_class_name != description.java_class_name:
            raise ValueError("libxposed hook result policy hooker identity mismatch")
        result_replacement = policy.replacement_string
    if argument_policy is not None:
        policy = decode_libxposed_hook_argument(argument_policy)
        if policy.hooker_class_name != description.java_class_name:
            raise ValueError("libxposed hook argument policy hooker identity mismatch")
        if description.inspected_argument_index != policy.argument_index:
            raise ValueError("libxposed hook argument policy requires matching inspected argument index")
        argument_replacement = policy.replacement_string
    if combined_policy is not None:
        policy = decode_libxposed_hook_combined(combined_policy)
        if policy.hooker_class_name != description.java_class_name:
            raise ValueError("libxposed combined hook policy hooker identity mismatch")
        if description.inspected_argument_index != policy.argument_index:
            raise ValueError("libxposed combined hook policy requires matching inspected argument index")
        argument_replacement = policy.argument_replacement_string
        result_replacement = policy.result_replacement_string
    return DexBridgeSpec(
        description.class_descriptor,
        "Ljava/lang/Object;",
        interfaces=(LIBXPOSED_HOOKER,),
        libxposed_hook_intercept=DexLibxposedHookInterceptSpec(
            description.inspected_argument_index,
            result_replacement,
            argument_replacement,
        ),
    )

@dataclass(frozen=True)
class LibxposedHookResultDescription:
    """Bounded post-proceed result replacement for one exact managed target.

    This is deliberately separate from adapter identity and installation.  The
    first profile proves only a zero-argument target whose declared return type
    is ``java.lang.String``.  The interceptor still calls ``Chain.proceed()``
    exactly once and captures the original result before returning one canonical
    constant replacement String.
    """

    hooker_class_name: str = "xax.generated.XaxHooker"
    target_class_name: str = "com.example.target.XaxActivity"
    target_method_name: str = "hookTarget"
    expected_return_descriptor: str = "Ljava/lang/String;"
    replacement_string: str = "Hooked"
    mode: str = "replace_after_proceed"

    def __post_init__(self) -> None:
        for value in (self.hooker_class_name, self.target_class_name):
            LibxposedManagedEntryDescription(value, ("onModuleLoaded",))
        if not self.target_method_name or any(ch in self.target_method_name for ch in "\x00/.;"):
            raise ValueError("invalid libxposed result-policy target method name")
        if self.expected_return_descriptor != "Ljava/lang/String;":
            raise ValueError("bounded libxposed result replacement currently requires java.lang.String result")
        if not self.replacement_string or "\x00" in self.replacement_string:
            raise ValueError("libxposed replacement String must be nonempty and NUL-free")
        if self.mode != "replace_after_proceed":
            raise ValueError("bounded libxposed result replacement requires replace_after_proceed mode")


def libxposed_hook_result_semantics(
    description: LibxposedHookResultDescription = LibxposedHookResultDescription(),
) -> SemanticObject:
    identity = bytearray(LIBXPOSED_HOOK_RESULT_PREFIX)
    for value in (
        description.hooker_class_name, description.target_class_name, description.target_method_name,
        description.expected_return_descriptor, description.replacement_string, description.mode,
    ):
        raw = value.encode("utf-8")
        identity.extend(uleb(len(raw)) + raw)
    return target(bytes(identity))


def decode_libxposed_hook_result(obj: SemanticObject) -> LibxposedHookResultDescription:
    if obj.kind != Kind.TARGET or obj.references:
        fail("XAX.LIBXPOSED", obj.cid.hex(), "LIBXPOSED-HOOK-RESULT-CARRIER", Kind.TARGET.name, obj.kind.name)
    outer = Cursor(obj.body, obj.cid.hex())
    identity = outer.byte_string()
    outer.end("LIBXPOSED-HOOK-RESULT-CARRIER")
    if not identity.startswith(LIBXPOSED_HOOK_RESULT_PREFIX):
        fail(
            "XAX.LIBXPOSED", obj.cid.hex(), "LIBXPOSED-HOOK-RESULT-IDENTITY",
            LIBXPOSED_HOOK_RESULT_PREFIX.decode(), identity[:48].hex(),
        )
    cursor = Cursor(identity[len(LIBXPOSED_HOOK_RESULT_PREFIX):], obj.cid.hex())
    try:
        description = LibxposedHookResultDescription(*(cursor.byte_string().decode("utf-8") for _ in range(6)))
        cursor.end("LIBXPOSED-HOOK-RESULT-IDENTITY")
    except (UnicodeDecodeError, ValueError) as error:
        fail("XAX.LIBXPOSED", obj.cid.hex(), "LIBXPOSED-HOOK-RESULT-FIELDS", "valid canonical result replacement", str(error))
    canonical = libxposed_hook_result_semantics(description)
    if canonical.cid != obj.cid:
        fail("XAX.LIBXPOSED", obj.cid.hex(), "LIBXPOSED-HOOK-RESULT-CANONICAL", canonical.cid.hex(), obj.cid.hex())
    return description


@dataclass(frozen=True)
class LibxposedHookArgumentDescription:
    """Bounded one-argument replacement policy for one exact managed target.

    API 102 exposes argument replacement through ``Chain.proceed(Object[])``.
    The first exact profile therefore models one ``String`` argument at index 0
    and makes the required one-element Object[] allocation visible in generated
    DEX instead of hiding it behind a helper/runtime abstraction.
    """

    hooker_class_name: str = "xax.generated.XaxHooker"
    target_class_name: str = "com.example.target.XaxActivity"
    target_method_name: str = "hookTarget"
    expected_parameter_descriptor: str = "Ljava/lang/String;"
    expected_return_descriptor: str = "Ljava/lang/String;"
    argument_index: int = 0
    replacement_string: str = "HookedArg"
    mode: str = "replace_before_proceed"

    def __post_init__(self) -> None:
        for value in (self.hooker_class_name, self.target_class_name):
            LibxposedManagedEntryDescription(value, ("onModuleLoaded",))
        if not self.target_method_name or any(ch in self.target_method_name for ch in "\x00/.;"):
            raise ValueError("invalid libxposed argument-policy target method name")
        if self.expected_parameter_descriptor != "Ljava/lang/String;":
            raise ValueError("bounded libxposed argument replacement currently requires one java.lang.String parameter")
        if self.expected_return_descriptor != "Ljava/lang/String;":
            raise ValueError("bounded libxposed argument replacement currently requires java.lang.String result")
        if self.argument_index != 0:
            raise ValueError("bounded libxposed argument replacement currently supports argument index 0 only")
        if not self.replacement_string or "\x00" in self.replacement_string:
            raise ValueError("libxposed replacement argument String must be nonempty and NUL-free")
        if self.mode != "replace_before_proceed":
            raise ValueError("bounded libxposed argument replacement requires replace_before_proceed mode")


def libxposed_hook_argument_semantics(
    description: LibxposedHookArgumentDescription = LibxposedHookArgumentDescription(),
) -> SemanticObject:
    identity = bytearray(LIBXPOSED_HOOK_ARGUMENT_PREFIX)
    for value in (
        description.hooker_class_name,
        description.target_class_name,
        description.target_method_name,
        description.expected_parameter_descriptor,
        description.expected_return_descriptor,
        description.replacement_string,
        description.mode,
    ):
        raw = value.encode("utf-8")
        identity.extend(uleb(len(raw)) + raw)
    identity.extend(uleb(description.argument_index))
    return target(bytes(identity))


def decode_libxposed_hook_argument(obj: SemanticObject) -> LibxposedHookArgumentDescription:
    if obj.kind != Kind.TARGET or obj.references:
        fail("XAX.LIBXPOSED", obj.cid.hex(), "LIBXPOSED-HOOK-ARGUMENT-CARRIER", Kind.TARGET.name, obj.kind.name)
    outer = Cursor(obj.body, obj.cid.hex())
    identity = outer.byte_string()
    outer.end("LIBXPOSED-HOOK-ARGUMENT-CARRIER")
    if not identity.startswith(LIBXPOSED_HOOK_ARGUMENT_PREFIX):
        fail(
            "XAX.LIBXPOSED", obj.cid.hex(), "LIBXPOSED-HOOK-ARGUMENT-IDENTITY",
            LIBXPOSED_HOOK_ARGUMENT_PREFIX.decode(), identity[:48].hex(),
        )
    cursor = Cursor(identity[len(LIBXPOSED_HOOK_ARGUMENT_PREFIX):], obj.cid.hex())
    try:
        values = [cursor.byte_string().decode("utf-8") for _ in range(7)]
        argument_index = cursor.uleb()
        description = LibxposedHookArgumentDescription(
            values[0], values[1], values[2], values[3], values[4], argument_index, values[5], values[6]
        )
        cursor.end("LIBXPOSED-HOOK-ARGUMENT-IDENTITY")
    except (UnicodeDecodeError, ValueError) as error:
        fail("XAX.LIBXPOSED", obj.cid.hex(), "LIBXPOSED-HOOK-ARGUMENT-FIELDS", "valid canonical argument replacement", str(error))
    canonical = libxposed_hook_argument_semantics(description)
    if canonical.cid != obj.cid:
        fail("XAX.LIBXPOSED", obj.cid.hex(), "LIBXPOSED-HOOK-ARGUMENT-CANONICAL", canonical.cid.hex(), obj.cid.hex())
    return description


@dataclass(frozen=True)
class LibxposedHookCombinedDescription:
    """Bounded argument-then-result replacement for one exact String target.

    This carrier exists separately so neither the zero-argument result policy nor
    the one-argument argument-only policy silently changes meaning.  The exact
    profile replaces argument 0, calls ``Chain.proceed(Object[])`` exactly once,
    captures the original result, then returns one constant replacement String.
    The required one-element Object[] allocation remains explicit hot-path cost.
    """

    hooker_class_name: str = "xax.generated.XaxHooker"
    target_class_name: str = "com.example.target.XaxActivity"
    target_method_name: str = "hookTarget"
    expected_parameter_descriptor: str = "Ljava/lang/String;"
    expected_return_descriptor: str = "Ljava/lang/String;"
    argument_index: int = 0
    argument_replacement_string: str = "HookedArg"
    result_replacement_string: str = "HookedResult"
    mode: str = "replace_argument_then_result"

    def __post_init__(self) -> None:
        for value in (self.hooker_class_name, self.target_class_name):
            LibxposedManagedEntryDescription(value, ("onModuleLoaded",))
        if not self.target_method_name or any(ch in self.target_method_name for ch in "\x00/.;"):
            raise ValueError("invalid libxposed combined-policy target method name")
        if self.expected_parameter_descriptor != "Ljava/lang/String;":
            raise ValueError("bounded combined hook policy currently requires one java.lang.String parameter")
        if self.expected_return_descriptor != "Ljava/lang/String;":
            raise ValueError("bounded combined hook policy currently requires java.lang.String result")
        if self.argument_index != 0:
            raise ValueError("bounded combined hook policy currently supports argument index 0 only")
        for label, value in (
            ("argument", self.argument_replacement_string),
            ("result", self.result_replacement_string),
        ):
            if not value or "\x00" in value:
                raise ValueError(f"libxposed combined replacement {label} String must be nonempty and NUL-free")
        if self.mode != "replace_argument_then_result":
            raise ValueError("bounded combined hook policy requires replace_argument_then_result mode")


def libxposed_hook_combined_semantics(
    description: LibxposedHookCombinedDescription = LibxposedHookCombinedDescription(),
) -> SemanticObject:
    identity = bytearray(LIBXPOSED_HOOK_COMBINED_PREFIX)
    for value in (
        description.hooker_class_name,
        description.target_class_name,
        description.target_method_name,
        description.expected_parameter_descriptor,
        description.expected_return_descriptor,
        description.argument_replacement_string,
        description.result_replacement_string,
        description.mode,
    ):
        raw = value.encode("utf-8")
        identity.extend(uleb(len(raw)) + raw)
    identity.extend(uleb(description.argument_index))
    return target(bytes(identity))


def decode_libxposed_hook_combined(obj: SemanticObject) -> LibxposedHookCombinedDescription:
    if obj.kind != Kind.TARGET or obj.references:
        fail("XAX.LIBXPOSED", obj.cid.hex(), "LIBXPOSED-HOOK-COMBINED-CARRIER", Kind.TARGET.name, obj.kind.name)
    outer = Cursor(obj.body, obj.cid.hex())
    identity = outer.byte_string()
    outer.end("LIBXPOSED-HOOK-COMBINED-CARRIER")
    if not identity.startswith(LIBXPOSED_HOOK_COMBINED_PREFIX):
        fail(
            "XAX.LIBXPOSED", obj.cid.hex(), "LIBXPOSED-HOOK-COMBINED-IDENTITY",
            LIBXPOSED_HOOK_COMBINED_PREFIX.decode(), identity[:48].hex(),
        )
    cursor = Cursor(identity[len(LIBXPOSED_HOOK_COMBINED_PREFIX):], obj.cid.hex())
    try:
        values = [cursor.byte_string().decode("utf-8") for _ in range(8)]
        argument_index = cursor.uleb()
        description = LibxposedHookCombinedDescription(
            values[0], values[1], values[2], values[3], values[4], argument_index,
            values[5], values[6], values[7],
        )
        cursor.end("LIBXPOSED-HOOK-COMBINED-IDENTITY")
    except (UnicodeDecodeError, ValueError) as error:
        fail("XAX.LIBXPOSED", obj.cid.hex(), "LIBXPOSED-HOOK-COMBINED-FIELDS", "valid canonical combined replacement", str(error))
    canonical = libxposed_hook_combined_semantics(description)
    if canonical.cid != obj.cid:
        fail("XAX.LIBXPOSED", obj.cid.hex(), "LIBXPOSED-HOOK-COMBINED-CANONICAL", canonical.cid.hex(), obj.cid.hex())
    return description


@dataclass(frozen=True)
class LibxposedDeoptimizationDescription:
    """One explicit API-102 deoptimization request for a managed hook target.

    The current bounded lowering deliberately supports only the exact executable
    already resolved for a companion hook installation.  The request is
    best-effort because libxposed exposes deoptimization success as a boolean;
    ignoring that result is therefore part of the semantic policy rather than a
    hidden compiler choice.  No deoptimization is synthesized when this carrier
    is absent.
    """

    target_class_name: str = "android.app.Activity"
    target_method_name: str = "onResume"
    parameter_type_names: tuple[str, ...] = ()
    result_policy: str = "best-effort"

    def __post_init__(self) -> None:
        LibxposedManagedEntryDescription(self.target_class_name, ("onModuleLoaded",))
        if not self.target_method_name or any(ch in self.target_method_name for ch in "\x00/.;"):
            raise ValueError("invalid libxposed deoptimization target method name")
        if self.parameter_type_names not in ((), ("java.lang.String",)):
            raise ValueError("bounded libxposed deoptimization supports zero args or one java.lang.String parameter")
        if self.result_policy != "best-effort":
            raise ValueError("bounded libxposed deoptimization currently requires explicit best-effort result policy")


def libxposed_deoptimization_semantics(
    description: LibxposedDeoptimizationDescription = LibxposedDeoptimizationDescription(),
) -> SemanticObject:
    identity = bytearray(LIBXPOSED_DEOPTIMIZE_PREFIX)
    for value in (
        description.target_class_name,
        description.target_method_name,
    ):
        raw = value.encode("utf-8")
        identity.extend(uleb(len(raw)) + raw)
    _put_texts(identity, description.parameter_type_names)
    raw = description.result_policy.encode("utf-8")
    identity.extend(uleb(len(raw)) + raw)
    return target(bytes(identity))


def decode_libxposed_deoptimization(obj: SemanticObject) -> LibxposedDeoptimizationDescription:
    if obj.kind != Kind.TARGET or obj.references:
        fail("XAX.LIBXPOSED", obj.cid.hex(), "LIBXPOSED-DEOPT-CARRIER", Kind.TARGET.name, obj.kind.name)
    outer = Cursor(obj.body, obj.cid.hex())
    identity = outer.byte_string()
    outer.end("LIBXPOSED-DEOPT-CARRIER")
    if not identity.startswith(LIBXPOSED_DEOPTIMIZE_PREFIX):
        fail(
            "XAX.LIBXPOSED", obj.cid.hex(), "LIBXPOSED-DEOPT-IDENTITY",
            LIBXPOSED_DEOPTIMIZE_PREFIX.decode(), identity[:48].hex(),
        )
    cursor = Cursor(identity[len(LIBXPOSED_DEOPTIMIZE_PREFIX):], obj.cid.hex())
    try:
        description = LibxposedDeoptimizationDescription(
            cursor.byte_string().decode("utf-8"),
            cursor.byte_string().decode("utf-8"),
            _get_texts(cursor),
            cursor.byte_string().decode("utf-8"),
        )
        cursor.end("LIBXPOSED-DEOPT-IDENTITY")
    except (UnicodeDecodeError, ValueError) as error:
        fail("XAX.LIBXPOSED", obj.cid.hex(), "LIBXPOSED-DEOPT-FIELDS", "valid canonical deoptimization request", str(error))
    canonical = libxposed_deoptimization_semantics(description)
    if canonical.cid != obj.cid:
        fail("XAX.LIBXPOSED", obj.cid.hex(), "LIBXPOSED-DEOPT-CANONICAL", canonical.cid.hex(), obj.cid.hex())
    return description


@dataclass(frozen=True)
class LibxposedHookInstallationDescription:
    """One explicit, bounded managed hook installation.

    The current implementation intentionally supports only a zero-argument target
    method resolved during ``onPackageReady``.  Resolution uses the package-ready
    ClassLoader once; the generated hot interceptor contains no lookup/reflection.
    Installation failure is explicit ``propagate`` behavior. A retained hook's
    optional stable ID is part of this installation's canonical identity.
    """

    target_class_name: str = "android.app.Activity"
    target_method_name: str = "onResume"
    hooker_class_name: str = "xax.generated.XaxHooker"
    parameter_type_names: tuple[str, ...] = ()
    exception_mode: str = "PROTECTIVE"
    failure_policy: str = "propagate"
    lifetime_policy: str = "process"
    hook_id: str | None = None

    def __post_init__(self) -> None:
        for label, value in (("target class", self.target_class_name), ("hooker class", self.hooker_class_name)):
            LibxposedManagedEntryDescription(value, ("onModuleLoaded",))
        if not self.target_method_name or any(ch in self.target_method_name for ch in "\x00/.;"):
            raise ValueError("invalid libxposed hook target method name")
        if self.parameter_type_names not in ((), ("java.lang.String",)):
            raise ValueError("bounded libxposed hook installation supports zero arguments or one java.lang.String parameter")
        if self.exception_mode != "PROTECTIVE":
            raise ValueError("bounded libxposed hook installation requires explicit PROTECTIVE exception mode")
        if self.failure_policy != "propagate":
            raise ValueError("bounded libxposed hook installation currently supports only explicit propagate failure policy")
        if self.lifetime_policy not in ("process", "retained-manual-unhook"):
            raise ValueError("bounded libxposed hook installation supports process or retained-manual-unhook lifetime")
        if self.hook_id is not None and (
            self.lifetime_policy != "retained-manual-unhook"
            or not self.hook_id
            or any(ch in self.hook_id for ch in "\x00\r\n")
        ):
            raise ValueError("libxposed hook ID requires retained lifetime and nonempty single-line text")


def libxposed_hook_installation_semantics(
    description: LibxposedHookInstallationDescription = LibxposedHookInstallationDescription(),
) -> SemanticObject:
    identity = bytearray(LIBXPOSED_HOOK_INSTALL_PREFIX)
    for value in (
        description.target_class_name, description.target_method_name, description.hooker_class_name,
        description.exception_mode, description.failure_policy, description.lifetime_policy,
    ):
        raw = value.encode("utf-8")
        identity.extend(uleb(len(raw)) + raw)
    _put_texts(identity, description.parameter_type_names)
    if description.hook_id is not None:
        raw = description.hook_id.encode("utf-8")
        identity.extend(uleb(len(raw)) + raw)
    return target(bytes(identity))


def decode_libxposed_hook_installation(obj: SemanticObject) -> LibxposedHookInstallationDescription:
    if obj.kind != Kind.TARGET or obj.references:
        fail("XAX.LIBXPOSED", obj.cid.hex(), "LIBXPOSED-HOOK-INSTALL-CARRIER", Kind.TARGET.name, obj.kind.name)
    outer = Cursor(obj.body, obj.cid.hex())
    identity = outer.byte_string()
    outer.end("LIBXPOSED-HOOK-INSTALL-CARRIER")
    if not identity.startswith(LIBXPOSED_HOOK_INSTALL_PREFIX):
        fail(
            "XAX.LIBXPOSED", obj.cid.hex(), "LIBXPOSED-HOOK-INSTALL-IDENTITY",
            LIBXPOSED_HOOK_INSTALL_PREFIX.decode(), identity[:48].hex(),
        )
    cursor = Cursor(identity[len(LIBXPOSED_HOOK_INSTALL_PREFIX):], obj.cid.hex())
    try:
        target_class_name = cursor.byte_string().decode("utf-8")
        target_method_name = cursor.byte_string().decode("utf-8")
        hooker_class_name = cursor.byte_string().decode("utf-8")
        exception_mode = cursor.byte_string().decode("utf-8")
        failure_policy = cursor.byte_string().decode("utf-8")
        lifetime_policy = cursor.byte_string().decode("utf-8")
        parameter_type_names = _get_texts(cursor)
        hook_id = cursor.byte_string().decode("utf-8") if cursor.remaining else None
        description = LibxposedHookInstallationDescription(
            target_class_name,
            target_method_name,
            hooker_class_name,
            parameter_type_names,
            exception_mode,
            failure_policy,
            lifetime_policy,
            hook_id,
        )
        cursor.end("LIBXPOSED-HOOK-INSTALL-IDENTITY")
    except (UnicodeDecodeError, ValueError) as error:
        fail("XAX.LIBXPOSED", obj.cid.hex(), "LIBXPOSED-HOOK-INSTALL-FIELDS", "valid canonical hook installation", str(error))
    canonical = libxposed_hook_installation_semantics(description)
    if canonical.cid != obj.cid:
        fail("XAX.LIBXPOSED", obj.cid.hex(), "LIBXPOSED-HOOK-INSTALL-CANONICAL", canonical.cid.hex(), obj.cid.hex())
    return description


def emit_libxposed_metadata(obj: SemanticObject, hot_reload: SemanticObject | None = None) -> dict[str, bytes]:
    description = decode_libxposed_module(obj)
    hot_reload_line = ""
    if hot_reload is not None:
        decode_libxposed_hot_reload(hot_reload)
        hot_reload_line = "autoHotReload=true\n"
    entries: dict[str, bytes] = {
        "META-INF/xposed/module.prop": (
            f"minApiVersion={description.min_api_version}\n"
            f"targetApiVersion={description.target_api_version}\n"
            f"staticScope={'true' if description.static_scope else 'false'}\n"
            f"{hot_reload_line}"
        ).encode("utf-8"),
    }
    if description.java_entries:
        entries["META-INF/xposed/java_init.list"] = ("\n".join(description.java_entries) + "\n").encode("utf-8")
    if description.native_entries:
        entries["META-INF/xposed/native_init.list"] = ("\n".join(description.native_entries) + "\n").encode("utf-8")
    if description.scopes:
        entries["META-INF/xposed/scope.list"] = ("\n".join(description.scopes) + "\n").encode("utf-8")
    return entries


__all__ = [
    "LIBXPOSED_MODULE_PREFIX",
    "LIBXPOSED_MANAGED_ENTRY_PREFIX",
    "LIBXPOSED_HOOK_ADAPTER_PREFIX",
    "LIBXPOSED_HOOK_INSTALL_PREFIX",
    "LIBXPOSED_HOOK_RESULT_PREFIX",
    "LIBXPOSED_HOOK_ARGUMENT_PREFIX",
    "LIBXPOSED_HOOK_COMBINED_PREFIX",
    "LIBXPOSED_DEOPTIMIZE_PREFIX",
    "LIBXPOSED_MODULE_SERVICES_PREFIX",
    "LIBXPOSED_REMOTE_PREFERENCES_PREFIX",
    "LIBXPOSED_REMOTE_FILES_PREFIX",
    "LIBXPOSED_HOT_RELOAD_PREFIX",
    "LIBXPOSED_XPOSED_MODULE",
    "LIBXPOSED_MODULE_LOADED_PARAM",
    "LIBXPOSED_PACKAGE_READY_PARAM",
    "LIBXPOSED_HOOKER",
    "LibxposedModuleDescription",
    "LibxposedManagedEntryDescription",
    "LibxposedHookAdapterDescription",
    "LibxposedHookInstallationDescription",
    "LibxposedHookResultDescription",
    "LibxposedHookArgumentDescription",
    "LibxposedHookCombinedDescription",
    "LibxposedDeoptimizationDescription",
    "LibxposedModuleServicesDescription",
    "LibxposedRemotePreferencesDescription",
    "LibxposedRemoteFilesDescription",
    "LibxposedHotReloadDescription",
    "libxposed_module_semantics",
    "decode_libxposed_module",
    "libxposed_managed_entry_semantics",
    "decode_libxposed_managed_entry",
    "lower_libxposed_managed_entry",
    "libxposed_hook_adapter_semantics",
    "decode_libxposed_hook_adapter",
    "lower_libxposed_hook_adapter",
    "libxposed_hook_result_semantics",
    "decode_libxposed_hook_result",
    "libxposed_hook_argument_semantics",
    "decode_libxposed_hook_argument",
    "libxposed_hook_combined_semantics",
    "decode_libxposed_hook_combined",
    "libxposed_deoptimization_semantics",
    "decode_libxposed_deoptimization",
    "libxposed_module_services_semantics",
    "decode_libxposed_module_services",
    "libxposed_remote_preferences_semantics",
    "decode_libxposed_remote_preferences",
    "libxposed_remote_files_semantics",
    "decode_libxposed_remote_files",
    "libxposed_hot_reload_semantics",
    "decode_libxposed_hot_reload",
    "libxposed_hook_installation_semantics",
    "decode_libxposed_hook_installation",
    "emit_libxposed_metadata",
]
