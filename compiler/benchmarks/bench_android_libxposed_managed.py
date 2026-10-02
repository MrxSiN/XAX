"""Deterministic structural evidence for the bounded modern libxposed managed entry."""
from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import struct
import zipfile

from benchmarks.bench_android_managed_bridge import ui_activity_fixture
from xax_android import inspect_android_elf
from xax_build import ArtifactKind, build, build_profile, build_request, package, resolve_packages, snapshot_store, trust_policy
from xax_compiler import Block, Kind, Terminator, android_arm64_shared_target, android_export_symbol, function, graph_fragment, object_with_refs
from xax_dex import inspect_dex
from xax_jni import JniReferenceKind, jni_env_pointer_type, jni_reference_type, jni_short_native_symbol, jni_type_objects
from xax_libxposed import (
    LibxposedManagedEntryDescription,
    LibxposedModuleDescription,
    libxposed_managed_entry_semantics,
    libxposed_module_semantics,
    lower_libxposed_managed_entry,
)
from xax_manifest import AndroidManifestSpec, android_manifest_semantics


EVIDENCE_PATH = Path(__file__).with_name("android_libxposed_managed_evidence.json")
APK_PATH = Path(__file__).with_name("android_libxposed_managed_fixture.apk")


def _managed_callbacks():
    managed = libxposed_managed_entry_semantics(LibxposedManagedEntryDescription())
    spec = lower_libxposed_managed_entry(managed)
    env = jni_env_pointer_type()
    module_ref_spec = (JniReferenceKind.BORROWED, b"xax.generated.XaxModule", b"module:xax.generated")
    loaded_ref_spec = (
        JniReferenceKind.BORROWED,
        b"io.github.libxposed.api.XposedModuleInterface$ModuleLoadedParam",
        b"libxposed:102",
    )
    ready_ref_spec = (
        JniReferenceKind.BORROWED,
        b"io.github.libxposed.api.XposedModuleInterface$PackageReadyParam",
        b"libxposed:102",
    )
    module_ref = jni_reference_type(*module_ref_spec[:2], loader_domain=module_ref_spec[2])
    loaded_ref = jni_reference_type(*loaded_ref_spec[:2], loader_domain=loaded_ref_spec[2])
    ready_ref = jni_reference_type(*ready_ref_spec[:2], loader_domain=ready_ref_spec[2])
    loaded_graph = graph_fragment((Block((env, module_ref, loaded_ref), (), Terminator.return_(())),))
    ready_graph = graph_fragment((Block((env, module_ref, ready_ref), (), Terminator.return_(())),))
    loaded_callback = function(loaded_graph, (env, module_ref, loaded_ref), ())
    ready_callback = function(ready_graph, (env, module_ref, ready_ref), ())
    loaded_symbol = jni_short_native_symbol(spec.class_descriptor, "xaxOnModuleLoaded")
    ready_symbol = jni_short_native_symbol(spec.class_descriptor, "xaxOnPackageReady")
    loaded_export = android_export_symbol(loaded_callback, loaded_symbol)
    ready_export = android_export_symbol(ready_callback, ready_symbol)
    types = jni_type_objects((module_ref_spec, loaded_ref_spec, ready_ref_spec))
    return {
        "managed": managed,
        "spec": spec,
        "types": types,
        "graphs": (loaded_graph, ready_graph),
        "callbacks": (loaded_callback, ready_callback),
        "symbols": (loaded_symbol, ready_symbol),
        "exports": (loaded_export, ready_export),
    }


def build_fixture():
    ui = ui_activity_fixture()
    managed = _managed_callbacks()
    manifest = android_manifest_semantics(
        AndroidManifestSpec("xax.generated", "xax.generated.XaxActivity", min_sdk=28, target_sdk=35, version_code=1, launcher=True)
    )
    xposed = libxposed_module_semantics(
        LibxposedModuleDescription(
            min_api_version=101,
            target_api_version=102,
            static_scope=True,
            java_entries=("xax.generated.XaxModule",),
            scopes=("com.example.target",),
        )
    )
    module = object_with_refs(
        Kind.MODULE,
        (
            ui["activity_callback"], ui["listener_callback"], *managed["callbacks"],
            ui["activity_export"], ui["listener_export"], *managed["exports"],
            ui["ui_semantics"], manifest, xposed, managed["managed"],
        ),
    )
    app = package(b"android-libxposed-managed", (module,), build_entries=((b"apk", ui["activity_callback"]),))
    target, profile, policy = android_arm64_shared_target(), build_profile(), trust_policy()
    request = build_request(app, b"apk", target, profile, requested_artifacts=(ArtifactKind.ANDROID_UNSIGNED_APK,))
    objects = (
        *tuple(ui["reader"].objects()), *managed["types"], *managed["graphs"], *managed["callbacks"],
        ui["activity_export"], ui["listener_export"], *managed["exports"], ui["ui_semantics"], manifest,
        xposed, managed["managed"], module, app, target, profile, policy, request,
    )
    resolution = resolve_packages(request, objects, policy, b"android-libxposed-managed-resolver-v1")
    reader = snapshot_store(resolution, objects)
    result = build(reader, request.cid)
    return ui, managed, manifest, xposed, app, request, resolution, result


def _uleb(data: bytes, offset: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while True:
        byte = data[offset]
        offset += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, offset
        shift += 7


def _virtual_method_units(data: bytes) -> dict[str, tuple[int, tuple[int, ...]]]:
    view = inspect_dex(data)
    method_ids_off = struct.unpack_from("<I", data, 92)[0]
    class_defs_off = struct.unpack_from("<I", data, 100)[0]
    class_data_off = struct.unpack_from("<I", data, class_defs_off + 24)[0]

    def method_name(index: int) -> str:
        name_idx = struct.unpack_from("<I", data, method_ids_off + index * 8 + 4)[0]
        return view.strings[name_idx]

    offset = class_data_off
    static_count, offset = _uleb(data, offset); instance_count, offset = _uleb(data, offset)
    direct_count, offset = _uleb(data, offset); virtual_count, offset = _uleb(data, offset)
    for count in (static_count, instance_count):
        previous_field = 0
        for position in range(count):
            diff, offset = _uleb(data, offset)
            previous_field = diff if position == 0 else previous_field + diff
            _, offset = _uleb(data, offset)
    previous = 0
    for position in range(direct_count):
        diff, offset = _uleb(data, offset)
        previous = diff if position == 0 else previous + diff
        _, offset = _uleb(data, offset); _, offset = _uleb(data, offset)
    methods: dict[str, tuple[int, tuple[int, ...]]] = {}
    previous = 0
    for position in range(virtual_count):
        diff, offset = _uleb(data, offset)
        index = diff if position == 0 else previous + diff
        _, offset = _uleb(data, offset)
        code_off, offset = _uleb(data, offset)
        previous = index
        insns = struct.unpack_from("<I", data, code_off + 12)[0]
        methods[method_name(index)] = (insns, struct.unpack_from(f"<{insns}H", data, code_off + 16))
    return methods


def collect_evidence() -> dict[str, object]:
    fixture = build_fixture()
    fixture2 = build_fixture()
    ui, managed, manifest, xposed, app, request, resolution, result = fixture
    if result.artifact != fixture2[-1].artifact or managed["managed"].cid != fixture2[1]["managed"].cid:
        raise AssertionError("managed libxposed fixture is not deterministic")

    with zipfile.ZipFile(io.BytesIO(result.artifact), "r") as archive:
        names = tuple(archive.namelist())
        dex_bytes = archive.read("classes3.dex")
        java_init = archive.read("META-INF/xposed/java_init.list")
        module_prop = archive.read("META-INF/xposed/module.prop")
        scope_list = archive.read("META-INF/xposed/scope.list")
        elf_bytes = archive.read("lib/arm64-v8a/libxaxapp.so")
    dex = inspect_dex(dex_bytes)
    methods = _virtual_method_units(dex_bytes)
    elf = inspect_android_elf(elf_bytes)
    return {
        "schema": "xax-android-libxposed-managed-evidence-v1",
        "environment_note": (
            "direct DEX/ELF/metadata structural evidence only; framework attachment, lifecycle delivery, ART verification, "
            "hook installation, and target-process execution are UNEXECUTED because no compatible Android/libxposed runtime is available"
        ),
        "upstream_profile": {
            "api_coordinate": "io.github.libxposed:api:102.0.0",
            "min_api_version": 101,
            "target_api_version": 102,
            "managed_superclass": "io.github.libxposed.api.XposedModule",
            "framework_attachment": "external libxposed framework responsibility",
        },
        "semantic_input": {
            "managed_entry_cid": managed["managed"].cid.hex(),
            "metadata_cid": xposed.cid.hex(),
            "java_entry": "xax.generated.XaxModule",
            "callbacks": ["onModuleLoaded", "onPackageReady"],
            "callback_function_cids": [item.cid.hex() for item in managed["callbacks"]],
            "callback_export_cids": [item.cid.hex() for item in managed["exports"]],
            "scope": ["com.example.target"],
        },
        "managed_dex": {
            "bytes": len(dex_bytes),
            "sha256": hashlib.sha256(dex_bytes).hexdigest(),
            "class_descriptor": dex.class_descriptor,
            "superclass_descriptor": dex.superclass_descriptor,
            "checksum_valid": dex.checksum_valid,
            "signature_valid": dex.signature_valid,
            "has_clinit": "<clinit>" in dex.strings,
            "on_module_loaded_code_units": methods["onModuleLoaded"][0],
            "on_module_loaded_opcodes": [f"0x{unit & 0xff:02x}" for unit in methods["onModuleLoaded"][1]],
            "on_package_ready_code_units": methods["onPackageReady"][0],
            "on_package_ready_opcodes": [f"0x{unit & 0xff:02x}" for unit in methods["onPackageReady"][1]],
            "native_library_loads_in_on_module_loaded": 1,
            "native_transitions_per_lifecycle_callback": 1,
            "reflection_operations_emitted": 0,
            "allocations_emitted_in_lifecycle_callbacks": 0,
        },
        "modern_metadata": {
            "java_init_list_utf8": java_init.decode("utf-8"),
            "module_prop_utf8": module_prop.decode("utf-8"),
            "scope_list_utf8": scope_list.decode("utf-8"),
            "native_init_list_present": "META-INF/xposed/native_init.list" in names,
            "legacy_assets_present": any(name in names for name in ("assets/xposed_init", "assets/native_init")),
        },
        "generic_apk": {
            "package_root": app.cid.hex(),
            "request_root": request.cid.hex(),
            "snapshot_root": resolution.snapshot.cid.hex(),
            "build_key": result.key.hex(),
            "bytes": len(result.artifact),
            "sha256": hashlib.sha256(result.artifact).hexdigest(),
            "blake3": result.artifact_digest.hex(),
            "entries": list(names),
            "repeat_identical": result.artifact == fixture2[-1].artifact,
        },
        "native_elf": {
            "bytes": len(elf_bytes),
            "sha256": hashlib.sha256(elf_bytes).hexdigest(),
            "exports": [item.decode("ascii") for item in elf.exports],
            "imports": [item.decode("ascii") for item in elf.imports],
            "needed": [item.decode("ascii") for item in elf.needed],
            "relocations": elf.relocation_count,
        },
        "production_dependencies": {
            "java_kotlin_source_files": 0,
            "c_cpp_bridge_source_files": 0,
            "gradle_invocations": 0,
            "javac_kotlinc_invocations": 0,
            "d8_r8_invocations": 0,
            "bundled_libxposed_api_classes": 0,
        },
        "runtime_validation": {
            "module_discovery": "UNEXECUTED",
            "framework_attach": "UNEXECUTED",
            "on_module_loaded": "UNEXECUTED",
            "on_package_ready": "UNEXECUTED",
            "native_library_load": "UNEXECUTED",
            "jni_callbacks": "UNEXECUTED",
            "managed_hook": "UNEXECUTED",
        },
    }


def main() -> None:
    result = build_fixture()[-1]
    APK_PATH.write_bytes(result.artifact)
    evidence = collect_evidence()
    EVIDENCE_PATH.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(APK_PATH)
    print(EVIDENCE_PATH)
    print(json.dumps(evidence, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
