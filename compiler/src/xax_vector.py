"""Static Vector/libxposed API-102 acceptance check for generated module APKs (ADR-178).

XAX's Android hooking contract is

    XAX -> modern libxposed API-102 module -> Vector -> ART

Generated modules link only the public ``io.github.libxposed.api`` surface;
Vector (https://github.com/JingMatrix/Vector) is the reference runtime that
supplies it.  This module is validation tooling, not code generation.  It
checks an APK against

* the rules Vector v2.2's daemon and module manager apply when they discover,
  load and instantiate a module (``FileSystem.loadModule``,
  ``ConfigCache.getModuleApkPath``, ``VectorModuleManager.buildGeneration`` and
  ``runHotReload``, ``native_api.cpp``'s ``do_dlopen`` hook), and
* the pinned public API-102 member table (``vector_runtime_pin.json``), so
  every libxposed class, method and field the DEX names must exist with that
  exact descriptor, and an API-102-only member cannot sit behind
  ``minApiVersion=101``.

It never executes anything; runtime behaviour is the Vector harness's job.
"""

from __future__ import annotations

from dataclasses import dataclass
import io
import json
from pathlib import Path
import struct
import zipfile

from xax_dex import DexReferences, inspect_dex_references

PIN_PATH = Path(__file__).resolve().parents[1] / "integration" / "android" / "vector" / "vector_runtime_pin.json"
LIBXPOSED_PREFIX = "Lio/github/libxposed/"
XPOSED_MODULE = "Lio/github/libxposed/api/XposedModule;"
MODULE_INTERFACE = "Lio/github/libxposed/api/XposedModuleInterface;"
HOOKER = "Lio/github/libxposed/api/XposedInterface$Hooker;"
HOOKER_INTERCEPT = ("intercept", "(Lio/github/libxposed/api/XposedInterface$Chain;)Ljava/lang/Object;")
HOT_RELOAD_CALLBACKS = ("onHotReloading", "onHotReloaded")
# Packages a framework-independent module must never name.
IMPLEMENTATION_PREFIXES = ("Lorg/matrix/vector/", "Lorg/lsposed/")
LEGACY_PREFIX = "Lde/robv/android/xposed/"
LEGACY_ENTRIES = ("assets/xposed_init", "assets/native_init")
NATIVE_ABI = "arm64-v8a"
# Vector loads libraries straight from the APK (``apk!/lib/<abi>``), which needs
# stored, page-aligned entries; 16 KiB covers 4 KiB and 16 KiB page kernels.
NATIVE_ALIGNMENT = 16384


def load_vector_pin(path: Path = PIN_PATH) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


class LibxposedApiTable:
    """The pinned public libxposed API, queried by exact JVM descriptor."""

    def __init__(self, pin: dict[str, object]):
        self.lib_api = int(pin["libxposed_api"]["lib_api"])
        self._classes = {row["descriptor"]: row for row in pin["api_classes"]}

    def has_class(self, descriptor: str) -> bool:
        return descriptor in self._classes

    def member(self, kind: str, owner: str, name: str, descriptor: str) -> dict[str, object] | None:
        """Resolve like the JVM: the owner, then its API supertypes."""
        pending, seen = [owner], set()
        while pending:
            current = pending.pop(0)
            if current in seen or current not in self._classes:
                continue
            seen.add(current)
            row = self._classes[current]
            for item in row["members"]:
                if item["kind"] == kind and item["name"] == name and item["descriptor"] == descriptor:
                    return item
            pending.extend(([row["superclass"]] if row["superclass"] else []) + list(row["interfaces"]))
        return None

    def method_names(self, owner: str) -> set[str]:
        return {item["name"] for item in self._classes[owner]["members"] if item["kind"] == "method"}


@dataclass(frozen=True)
class VectorModuleReport:
    module_prop: dict[str, str]
    java_entries: tuple[str, ...]
    native_entries: tuple[str, ...]
    scopes: tuple[str, ...]
    # (kind, owner, name, descriptor, since) for every libxposed member the DEX names.
    api_members: tuple[tuple[str, str, str, str, int], ...]
    required_api: int
    violations: tuple[str, ...]

    @property
    def accepted(self) -> bool:
        return not self.violations

    @property
    def api102_members(self) -> tuple[tuple[str, str, str, str, int], ...]:
        return tuple(item for item in self.api_members if item[4] >= 102)


def _properties(raw: bytes) -> dict[str, str]:
    """The ``java.util.Properties`` subset module.prop uses (no escapes or continuations)."""
    values: dict[str, str] = {}
    for line in raw.decode("utf-8").splitlines():
        line = line.strip()
        if not line or line[0] in "#!":
            continue
        separator = min((index for index in (line.find("="), line.find(":")) if index >= 0), default=-1)
        key, value = (line, "") if separator < 0 else (line[:separator], line[separator + 1:])
        values[key.strip()] = value.strip()
    return values


def _list(archive: zipfile.ZipFile, name: str) -> tuple[str, ...]:
    if name not in archive.namelist():
        return ()
    lines = (line.strip() for line in archive.read(name).decode("utf-8").splitlines())
    return tuple(line for line in lines if line and not line.startswith("#"))


def _leading_int(value: str | None) -> int:
    digits = ""
    for character in (value or "").strip():
        if not character.isdigit():
            break
        digits += character
    return int(digits) if digits else 0


def _dex_files(archive: zipfile.ZipFile) -> list[DexReferences]:
    """``classes.dex``, ``classes2.dex``, ... in Vector's order, stopping at the first gap."""
    names, index = set(archive.namelist()), 1
    out = []
    while (name := "classes.dex" if index == 1 else f"classes{index}.dex") in names:
        out.append(inspect_dex_references(archive.read(name)))
        index += 1
    return out


def _stored_offset(apk: bytes, info: zipfile.ZipInfo) -> int:
    name_length, extra_length = struct.unpack_from("<HH", apk, info.header_offset + 26)
    return info.header_offset + 30 + name_length + extra_length


def check_vector_module_apk(apk: bytes, table: LibxposedApiTable) -> VectorModuleReport:
    from xax_android import inspect_android_elf

    violations: list[str] = []
    archive = zipfile.ZipFile(io.BytesIO(apk))
    names = set(archive.namelist())
    if "META-INF/xposed/module.prop" not in names:
        violations.append("VECTOR-MODULE-PROP: META-INF/xposed/module.prop is missing")
    prop = _properties(archive.read("META-INF/xposed/module.prop")) if "META-INF/xposed/module.prop" in names else {}
    java_entries = _list(archive, "META-INF/xposed/java_init.list")
    native_entries = _list(archive, "META-INF/xposed/native_init.list")
    scopes = _list(archive, "META-INF/xposed/scope.list")
    min_api, target_api = _leading_int(prop.get("minApiVersion")), _leading_int(prop.get("targetApiVersion"))

    # Vector picks the modern loader from targetApiVersion alone (>= 101); XAX
    # generates against exactly the pinned LIB_API.
    if target_api != table.lib_api:
        violations.append(f"VECTOR-TARGET-API: targetApiVersion={target_api}, expected {table.lib_api}")
    if not 1 <= min_api <= target_api:
        violations.append(f"VECTOR-MIN-API: minApiVersion={min_api} is not within 1..targetApiVersion")
    if not java_entries:
        violations.append("VECTOR-JAVA-ENTRY: java_init.list is missing or empty; Vector neither discovers nor loads the APK")
    for legacy in LEGACY_ENTRIES:
        if legacy in names:
            violations.append(f"VECTOR-LEGACY-API: legacy {legacy} present in a modern module")
    mode = prop.get("exceptionMode")
    if mode is not None and mode.lower() not in ("protective", "passthrough"):
        violations.append(f"VECTOR-EXCEPTION-MODE: exceptionMode={mode!r}")
    if prop.get("staticScope", "").lower() == "true" and not scopes:
        violations.append("VECTOR-STATIC-SCOPE: staticScope=true with an empty scope.list (Vector ignores it)")
    auto_hot_reload = prop.get("autoHotReload", "").lower() == "true"

    dexes = _dex_files(archive)
    if not dexes:
        violations.append("VECTOR-DEX: classes.dex is missing")
    defined = {item.descriptor: item for dex in dexes for item in dex.classes}
    required = 101
    used: set[tuple[str, str, str, str, int]] = set()
    for dex in dexes:
        for descriptor in dex.types:
            if descriptor.startswith(LEGACY_PREFIX):
                violations.append(f"VECTOR-LEGACY-API: references legacy Xposed type {descriptor}")
            if descriptor.startswith(IMPLEMENTATION_PREFIXES):
                violations.append(f"VECTOR-IMPLEMENTATION-REF: references framework implementation type {descriptor}")
            if descriptor.startswith(LIBXPOSED_PREFIX) and not descriptor.startswith("[") and not table.has_class(descriptor):
                violations.append(f"VECTOR-UNKNOWN-API-CLASS: {descriptor} is not in the pinned API")
        for kind, references in (("method", dex.method_refs), ("field", dex.field_refs)):
            for owner, name, descriptor in references:
                if not owner.startswith(LIBXPOSED_PREFIX):
                    continue
                member = table.member(kind, owner, name, descriptor)
                if member is None:
                    violations.append(f"VECTOR-UNKNOWN-API-MEMBER: {kind} {owner}->{name}{descriptor}")
                    continue
                if member["internal"]:
                    violations.append(f"VECTOR-INTERNAL-API: {owner}->{name} is framework-internal")
                used.add((kind, owner, name, descriptor, int(member["since"])))
                required = max(required, int(member["since"]))
        for item in dex.classes:
            if item.descriptor.startswith(LIBXPOSED_PREFIX):
                violations.append(f"VECTOR-BUNDLED-API: defines {item.descriptor}; Vector refuses bundled API classes")
            if HOOKER in item.interfaces and HOOKER_INTERCEPT not in {(name, proto) for name, proto, _ in item.methods}:
                violations.append(f"VECTOR-HOOKER: {item.descriptor} implements Hooker without intercept(Chain)")

    callback_names = table.method_names(MODULE_INTERFACE)
    for entry in java_entries:
        descriptor = "L" + entry.replace(".", "/") + ";"
        item = defined.get(descriptor)
        if item is None:
            violations.append(f"VECTOR-ENTRY-CLASS: {entry} is not defined in the module DEX")
            continue
        if item.superclass != XPOSED_MODULE:
            violations.append(f"VECTOR-ENTRY-CLASS: {entry} does not extend XposedModule directly")
        if ("<init>", "()V") not in {(name, proto) for name, proto, _ in item.methods}:
            violations.append(f"VECTOR-ENTRY-CLASS: {entry} has no no-argument constructor")
        for name, proto, _flags in item.methods:
            if name not in callback_names:
                continue
            member = table.member("method", MODULE_INTERFACE, name, proto)
            if member is None:
                violations.append(f"VECTOR-CALLBACK-PROTO: {entry}.{name}{proto} does not override the API callback")
            else:
                required = max(required, int(member["since"]))
                used.add(("method", MODULE_INTERFACE, name, proto, int(member["since"])))
    if auto_hot_reload:
        required = max(required, 102)
        if len(java_entries) != 1:
            violations.append("VECTOR-HOT-RELOAD: autoHotReload needs exactly one Java entry")
        elif (item := defined.get("L" + java_entries[0].replace(".", "/") + ";")) is not None:
            overridden = {name for name, _proto, _flags in item.methods}
            if not set(HOT_RELOAD_CALLBACKS) <= overridden:
                violations.append("VECTOR-HOT-RELOAD: autoHotReload without onHotReloading/onHotReloaded overrides")
    if min_api and min_api < required:
        violations.append(f"VECTOR-MIN-API: minApiVersion={min_api} but the module uses API-{required} members")

    for entry in native_entries:
        path = f"lib/{NATIVE_ABI}/{entry}"
        if path not in names:
            violations.append(f"VECTOR-NATIVE-ENTRY: {path} is missing")
            continue
        info = archive.getinfo(path)
        if info.compress_type != zipfile.ZIP_STORED or _stored_offset(apk, info) % NATIVE_ALIGNMENT:
            violations.append(f"VECTOR-NATIVE-ENTRY: {path} is not stored {NATIVE_ALIGNMENT}-byte aligned")
        if b"native_init" not in inspect_android_elf(archive.read(path)).exports:
            violations.append(f"VECTOR-NATIVE-ENTRY: {path} does not export native_init")

    return VectorModuleReport(
        prop, java_entries, native_entries, scopes, tuple(sorted(used)), required, tuple(dict.fromkeys(violations)),
    )


__all__ = [
    "PIN_PATH",
    "LibxposedApiTable",
    "VectorModuleReport",
    "check_vector_module_apk",
    "load_vector_pin",
]
