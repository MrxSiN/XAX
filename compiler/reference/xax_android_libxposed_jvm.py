"""Libxposed modules whose code is XAX on the JVM general target (ADR-262).

A module of this profile is ordinary verified XAX: its entry function takes
``(XposedInterface, PackageReadyParam)`` and its other functions call Android,
libxposed and library members through typed ``jvm-*`` foreign declarations
(``xax_construct`` platform ``android-libxposed``).  One identity-only target
carrier, ``android-libxposed-jvm-module-v1``, holds what the APK needs beyond
the code: package, version, the libxposed ``Module`` class, scopes, the SDK
profile, prebuilt dependency DEX files and native libraries (by BLAKE3 digest,
supplied to the build as external inputs), and ``static native`` declarations
for JNI libraries among those natives.

Lowering (``android-libxposed-jvm-apk-v1``), all compiler-generated:

* the entry function's JVM class files (``xax_jvm``) become DEX through
  ``xax_dex_jvm`` (no ``d8``);
* the ``Module`` class is a ``DexBridgeSpec`` whose only behaviour is
  ``onPackageReady(param)`` forwarding ``(this, param)`` to the XAX entry;
* each native class is a ``DexBridgeSpec`` with ``static native`` methods;
* the manifest has an application and no components; libxposed metadata comes
  from ``xax_libxposed``; prebuilt DEX and libraries are copied verbatim.

Signing is the build's ordinary ``SIGN`` effect (``xax_apk_signing``).
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from xax_compiler import Cursor, SemanticObject, fail, target

PREFIX = b"android-libxposed-jvm-module-v1\0"
# v2 adds one static branding archive (AndroidManifest.xml, resources.arsc, res/*) named by BLAKE3 digest.
# Unbranded modules keep their v1 identity; a v1-only compiler rejects v2 rather than drop the branding.
PREFIX_V2 = b"android-libxposed-jvm-module-v2\0"
BRANDING_LIMIT = 2 << 20
LOWERING_IDENTITY = b"android-libxposed-jvm-apk-v1"
API = "io/github/libxposed/api/"
ENTRY_DESCRIPTOR = f"(L{API}XposedInterface;L{API}XposedModuleInterface$PackageReadyParam;)V"


@dataclass(frozen=True)
class NativeMethod:
    class_descriptor: str
    name: str
    descriptor: str


@dataclass(frozen=True)
class StaticField:
    """A ``public static volatile`` field of a holder class: process-wide state the module's code shares."""
    class_descriptor: str
    name: str
    descriptor: str


@dataclass(frozen=True)
class LibxposedJvmModule:
    package: str
    module_class: str
    scopes: tuple[str, ...]
    version_code: int
    version_name: str = ""
    min_sdk: int = 28
    target_sdk: int = 35
    dex: tuple[bytes, ...] = ()
    libraries: tuple[tuple[str, bytes], ...] = ()
    natives: tuple[NativeMethod, ...] = ()
    fields: tuple[StaticField, ...] = ()
    branding: bytes | None = None

    def __post_init__(self) -> None:
        if not self.package or any(not part for part in self.package.split(".")):
            raise ValueError("package must be dot-separated nonempty components")
        if not self.module_class or "/" in self.module_class or ";" in self.module_class:
            raise ValueError("module class uses Java binary-name notation")
        if not self.scopes or any(not scope for scope in self.scopes):
            raise ValueError("a libxposed module needs at least one scope")
        if not 1 <= self.version_code <= 0x7FFFFFFF or not 28 <= self.min_sdk <= self.target_sdk:
            raise ValueError("versionCode must be positive and minSdk at least 28 (DEX 039)")
        if any(len(digest) != 32 for digest in (*self.dex, *(item[1] for item in self.libraries), *self._branding)):
            raise ValueError("inputs are named by 32-byte BLAKE3 digests")
        for path, _ in self.libraries:
            if not path.startswith("lib/") or not path.endswith(".so") or ".." in path or "\\" in path:
                raise ValueError(f"native library path must be lib/<abi>/<name>.so: {path!r}")
        for item in self.natives:
            if not (item.class_descriptor.startswith("L") and item.class_descriptor.endswith(";")) or "(" not in item.descriptor:
                raise ValueError(f"bad native declaration {item}")

    def payload(self) -> bytes:
        record = {
            "package": self.package, "module_class": self.module_class, "scopes": sorted(self.scopes),
            "version_code": self.version_code, "version_name": self.version_name,
            "min_sdk": self.min_sdk, "target_sdk": self.target_sdk,
            "dex": [digest.hex() for digest in self.dex],
            "libraries": sorted([path, digest.hex()] for path, digest in self.libraries),
            "natives": sorted([item.class_descriptor, item.name, item.descriptor] for item in self.natives),
            "fields": sorted([item.class_descriptor, item.name, item.descriptor] for item in self.fields),
        }
        if self.branding is not None:
            record["branding"] = self.branding.hex()
        return json.dumps(record, sort_keys=True, separators=(",", ":")).encode()

    @property
    def _branding(self) -> tuple[bytes, ...]:
        return () if self.branding is None else (self.branding,)

    @property
    def prefix(self) -> bytes:
        return PREFIX if self.branding is None else PREFIX_V2

    @property
    def inputs(self) -> tuple[bytes, ...]:
        return tuple(sorted({*self.dex, *(digest for _, digest in self.libraries), *self._branding}))


def libxposed_jvm_module_semantics(module: LibxposedJvmModule) -> SemanticObject:
    return target(module.prefix + module.payload())


def _is_carrier(identity: bytes) -> bool:
    return identity.startswith(PREFIX) or identity.startswith(PREFIX_V2)


def decode_libxposed_jvm_module(obj: SemanticObject) -> LibxposedJvmModule:
    identity = Cursor(obj.body, obj.cid.hex()).byte_string()
    if not _is_carrier(identity):
        fail("XAX.ANDROID.LIBXPOSED_JVM", obj.cid.hex(), "LIBXPOSED-JVM-CARRIER", PREFIX.decode(), identity[:40].hex())
    prefix = PREFIX if identity.startswith(PREFIX) else PREFIX_V2
    record = json.loads(identity[len(prefix):])
    if (prefix == PREFIX_V2) != ("branding" in record):
        fail("XAX.ANDROID.LIBXPOSED_JVM", obj.cid.hex(), "LIBXPOSED-JVM-BRANDING", "branding exactly in v2", sorted(record))
    return LibxposedJvmModule(
        record["package"], record["module_class"], tuple(record["scopes"]), record["version_code"], record["version_name"],
        record["min_sdk"], record["target_sdk"], tuple(bytes.fromhex(item) for item in record["dex"]),
        tuple((path, bytes.fromhex(digest)) for path, digest in record["libraries"]),
        tuple(NativeMethod(*item) for item in record["natives"]),
        tuple(StaticField(*item) for item in record.get("fields", ())),
        bytes.fromhex(record["branding"]) if "branding" in record else None)


def module_objects(module: LibxposedJvmModule) -> tuple[SemanticObject, ...]:
    """The identity-only carriers a module of this profile references: its own carrier and libxposed metadata."""
    from xax_libxposed import LibxposedModuleDescription, libxposed_module_semantics

    metadata = libxposed_module_semantics(LibxposedModuleDescription(
        min_api_version=102, target_api_version=102, static_scope=True,
        java_entries=(module.module_class,), scopes=module.scopes))
    return libxposed_jvm_module_semantics(module), metadata


def find_carriers(reader, package_view) -> tuple[SemanticObject | None, SemanticObject | None]:
    from xax_compiler import Kind
    from xax_libxposed import LIBXPOSED_MODULE_PREFIX

    carrier = metadata = None
    for module_cid in package_view.modules:
        for cid in reader.get(module_cid).references:
            child = reader.get(cid)
            if child.kind != Kind.TARGET or child.references:
                continue
            identity = Cursor(child.body, child.cid.hex()).byte_string()
            if _is_carrier(identity):
                carrier = child
            elif identity.startswith(LIBXPOSED_MODULE_PREFIX):
                metadata = child
    return carrier, metadata


VERSION_CODE_ATTRIBUTE = 0x0101021B


def _set_version_code(manifest: bytes, version_code: int) -> bytes:
    """Replace the binary manifest's one ``android:versionCode`` integer with the module record's value.

    Chunk headers and sizes are bounds-checked; anything other than exactly one decimal-integer
    versionCode attribute on the root element rejects.
    """
    import struct

    def bad(why: str):
        raise ValueError(f"branding manifest: {why}")

    if len(manifest) < 8 or struct.unpack_from("<HHI", manifest)[0] != 0x0003 or struct.unpack_from("<I", manifest, 4)[0] != len(manifest):
        bad("not one binary XML document")
    out = bytearray(manifest)
    resource_ids: list[int] = []
    sites = []
    offset = struct.unpack_from("<H", manifest, 2)[0]
    while offset < len(manifest):
        if offset + 8 > len(manifest):
            bad("truncated chunk header")
        kind, header, size = struct.unpack_from("<HHI", manifest, offset)
        if header < 8 or size < header or offset + size > len(manifest):
            bad("chunk outside the document")
        if kind == 0x0180:
            resource_ids = list(struct.unpack_from(f"<{(size - header) // 4}I", manifest, offset + header))
        elif kind == 0x0102:
            if header < 16 or size < header + 20:
                bad("short start element")
            start, attr_size, count = struct.unpack_from("<HHH", manifest, offset + header + 8)
            base = offset + header + start
            if attr_size != 20 or base + count * 20 > offset + size:
                bad("attributes outside the element")
            for index in range(count):
                at = base + index * 20
                name = struct.unpack_from("<I", manifest, at + 4)[0]
                if name < len(resource_ids) and resource_ids[name] == VERSION_CODE_ATTRIBUTE:
                    sites.append(at)
        offset += size
    if offset != len(manifest) or len(sites) != 1:
        bad(f"expected one versionCode, found {len(sites)}")
    at = sites[0]
    if manifest[at + 15] != 0x10:
        bad("versionCode is not a decimal integer")
    struct.pack_into("<i", out, at + 16, version_code)
    return bytes(out)


def branding_entries(archive: bytes, version_code: int) -> dict[str, bytes]:
    """The static branding archive's entries, validated, with the module's versionCode in its manifest."""
    import zipfile
    from io import BytesIO

    if len(archive) > BRANDING_LIMIT:
        raise ValueError("branding archive exceeds 2 MiB")
    with zipfile.ZipFile(BytesIO(archive)) as source:
        infos = source.infolist()
        names = [info.filename for info in infos]
        if len(set(names)) != len(names):
            raise ValueError("branding archive has duplicate entries")
        if sum(info.file_size for info in infos) > BRANDING_LIMIT:
            raise ValueError("branding archive expands beyond 2 MiB")
        for name in names:
            if name not in ("AndroidManifest.xml", "resources.arsc") and not (
                    name.startswith("res/") and ".." not in name and "\\" not in name and not name.endswith("/")):
                raise ValueError(f"branding archive may hold only the manifest and resources: {name!r}")
        if "AndroidManifest.xml" not in names:
            raise ValueError("branding archive has no manifest")
        entries = {name: source.read(name) for name in names}
    entries["AndroidManifest.xml"] = _set_version_code(entries["AndroidManifest.xml"], version_code)
    return entries


def build_libxposed_jvm_apk(reader, package_view, target_object: SemanticObject, entry_cid: bytes,
                            external_inputs) -> bytes:
    """Lower one module of this profile to an unsigned APK.  S15e.6i.2b (ADR-358): the XAX Android program builds it
    first; ``XAX_GENERAL_FRONTEND_DIFF=1`` compares the two."""
    import os

    from xax_compiler import XaxError
    from xax_selfhost_android import android_with_xax

    def reference():
        try:
            return _build_libxposed_jvm_apk(reader, package_view, target_object, entry_cid, external_inputs)
        except XaxError as error:
            return error.diagnostic

    diff = os.environ.get("XAX_GENERAL_FRONTEND_DIFF") == "1"
    try:
        built = android_with_xax(reader, package_view, target_object, entry_cid, external_inputs=dict(external_inputs))
    except XaxError as error:  # the program decided the rejection
        if diff and reference() != error.diagnostic:
            raise AssertionError("S15e.6i.2b libxposed JVM rejections disagree") from error
        raise
    if built is not None:
        if diff and reference() != built:
            raise AssertionError("S15e.6i.2b libxposed JVM APKs disagree")
        return built
    return _build_libxposed_jvm_apk(reader, package_view, target_object, entry_cid, external_inputs)


def _build_libxposed_jvm_apk(reader, package_view, target_object: SemanticObject, entry_cid: bytes, external_inputs) -> bytes:
    """The bootstrap's lowering of one module of this profile."""
    import zipfile
    from io import BytesIO

    from xax_apk import ApkEntry, build_apk
    from xax_dex import DexAssembledMethod, DexBridgeSpec, DexInstruction, DexMethodRef, DexNativeMethod, DexProto, emit_dex039_bridge
    from xax_dex import ACC_NATIVE, ACC_PUBLIC, ACC_STATIC
    from xax_dex_jvm import translate_class, write_dex
    from xax_jvm import compile_jvm_bound_target
    from xax_libxposed import emit_libxposed_metadata
    from xax_manifest import AndroidManifestSpec, emit_binary_manifest
    from xax_android_sdk import parse_jvm_method_descriptor

    carrier, metadata = find_carriers(reader, package_view)
    where = package_view.logical_identity.hex()
    if carrier is None or metadata is None:
        fail("XAX.BUILD.ANDROID", where, "LIBXPOSED-JVM-CARRIERS", "one module carrier and libxposed metadata", "missing")
    module = decode_libxposed_jvm_module(carrier)
    missing = [digest.hex() for digest in module.inputs if digest not in external_inputs]
    if missing:
        fail("XAX.BUILD.INPUT_CLOSURE", where, "LIBXPOSED-JVM-INPUTS", "every declared DEX and library", missing)

    image = compile_jvm_bound_target(reader, entry_cid, target_object)
    if (entry_cid, image.entry_method, ENTRY_DESCRIPTOR) not in image.methods:
        fail("XAX.BUILD.ANDROID", entry_cid.hex(), "LIBXPOSED-JVM-ENTRY", ENTRY_DESCRIPTOR,
             [descriptor for cid, _, descriptor in image.methods if cid == entry_cid])
    from xax_dex_jvm import DexClassDef, DexFieldDef

    with zipfile.ZipFile(BytesIO(image.jar)) as jar:
        classes = [translate_class(jar.read(name)) for name in sorted(jar.namelist()) if name.endswith(".class")]
    holders: dict[str, list] = {}
    for item in module.fields:
        holders.setdefault(item.class_descriptor, []).append(DexFieldDef(item.name, item.descriptor, 0x0001 | 0x0008 | 0x0040))
    classes += [DexClassDef(descriptor, 0x0001 | 0x0010, "Ljava/lang/Object;", fields=tuple(fields))
                for descriptor, fields in sorted(holders.items())]
    code_dex = write_dex(classes)

    # The Module class: libxposed's lifecycle entry forwards (this, param) to the verified XAX entry.
    ready = f"L{API}XposedModuleInterface$PackageReadyParam;"
    forward = DexAssembledMethod("onPackageReady", DexProto("V", (ready,)), 2, (
        DexInstruction("invoke-static", (0, 1), DexMethodRef(
            "L" + image.class_name + ";", image.entry_method,
            DexProto("V", (f"L{API}XposedInterface;", ready)))),
        DexInstruction("return-void"),
    ))
    module_dex = emit_dex039_bridge(DexBridgeSpec("L" + module.module_class.replace(".", "/") + ";", f"L{API}XposedModule;",
                                                  assembled_methods=(forward,)))
    native_dex = []
    by_class: dict[str, list] = {}
    for item in module.natives:
        parameters, result = parse_jvm_method_descriptor(item.descriptor)
        by_class.setdefault(item.class_descriptor, []).append(
            DexNativeMethod(item.name, DexProto(result, tuple(parameters)), ACC_PUBLIC | ACC_STATIC | ACC_NATIVE))
    for descriptor, methods in sorted(by_class.items()):
        native_dex.append(emit_dex039_bridge(DexBridgeSpec(descriptor, "Ljava/lang/Object;", native_methods=tuple(methods))))

    branding = {} if module.branding is None else branding_entries(external_inputs[module.branding], module.version_code)
    manifest = branding.pop("AndroidManifest.xml", None) or emit_binary_manifest(AndroidManifestSpec(
        module.package, "", module.min_sdk, module.target_sdk, module.version_code, launcher=False))
    dex_files = [module_dex, code_dex, *native_dex, *(external_inputs[digest] for digest in module.dex)]
    entries = [ApkEntry("AndroidManifest.xml", manifest)]
    entries += [ApkEntry(name, data) for name, data in branding.items()]
    entries += [ApkEntry("classes.dex" if index == 0 else f"classes{index + 1}.dex", data) for index, data in enumerate(dex_files)]
    entries += [ApkEntry(name, data) for name, data in emit_libxposed_metadata(metadata).items()]
    # Uncompressed and 16 KiB aligned, so the loader can map libraries straight from the APK.
    entries += [ApkEntry(path, external_inputs[digest], 16384) for path, digest in module.libraries]
    return build_apk(entries)


def build_module(reader, inputs, signing_transport: bytes | None = None, *, producer_identity: bytes = b"", with_snapshot: bool = False):
    """Build the release APK of a verified store of this profile with its external inputs.

    ``inputs`` maps BLAKE3 digest to bytes and may hold more than the module declares; only the
    declared DEX/library digests (and the signing transport, when the request is signed) enter the
    snapshot's external closure, so the build key commits to exactly what the APK contains.
    """
    from blake3 import blake3

    from xax_build import (BuildCapability, BuildCapabilityKind, BuildEffect, build, decode_package, decode_request,
                           decode_snapshot, resolve_packages, snapshot_store)

    resolve = reader.get
    snapshot = decode_snapshot(resolve(reader.root_cid), resolve)
    request = resolve(snapshot.request_root)
    request_view = decode_request(request, resolve)
    package_view = decode_package(resolve(request_view.package_root), resolve)
    carrier, _ = find_carriers(reader, package_view)
    if carrier is None:
        raise ValueError("store is not an android-libxposed module")
    module = decode_libxposed_jvm_module(carrier)
    closure = {}
    for digest in module.inputs:
        if digest not in inputs:
            raise ValueError(f"missing build input {digest.hex()}")
        closure[digest] = inputs[digest]
    effects = []
    signers = [item for item in package_view.capabilities if item.kind == BuildCapabilityKind.SIGN]
    if signers:
        if signing_transport is None:
            raise ValueError("signed module needs the private signing capability")
        closure[blake3(signing_transport).digest()] = signing_transport
        effects.append(BuildEffect(package_view.logical_identity, BuildCapability(BuildCapabilityKind.SIGN, signers[0].scope),
                                   signing_transport))
    objects = tuple(reader.objects())
    resolution = resolve_packages(request, objects, resolve(snapshot.trust_policy_root), snapshot.resolver_identity,
                                  external_inputs=closure)
    snapshot_reader = snapshot_store(resolution, objects)
    result = build(snapshot_reader, request.cid, external_inputs=closure, effects=effects, producer_identity=producer_identity)
    # The provenance refers to the input-closed snapshot, so a caller decoding it needs that store too.
    return (result, snapshot_reader) if with_snapshot else result
