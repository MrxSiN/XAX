"""Deterministic direct-APK evidence for the bounded modern libxposed native path.

API 102 requires a Java entry, and Vector only calls ``native_init`` when the
Java entry's ``System.loadLibrary`` opens a library named in native_init.list,
so the native entry rides on the generated XposedModule (ADR-178).
"""
from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import zipfile

from benchmarks.bench_android_arm64 import libxposed_native_init_fixture
from benchmarks.bench_android_libxposed_managed import _managed_callbacks
from benchmarks.bench_android_managed_bridge import ui_activity_fixture
from xax_android import inspect_android_elf
from xax_apk import inspect_apk
from xax_build import ArtifactKind, build, build_profile, build_request, package, resolve_packages, snapshot_store, trust_policy
from xax_compiler import Kind, android_arm64_shared_target, android_export_symbol, object_with_refs
from xax_libxposed import LibxposedModuleDescription, libxposed_module_semantics
from xax_manifest import AndroidManifestSpec, android_manifest_semantics


EVIDENCE_PATH = Path(__file__).with_name("android_libxposed_evidence.json")
APK_PATH = Path(__file__).with_name("android_libxposed_native_fixture.apk")


def build_fixture():
    ui = ui_activity_fixture()
    managed = _managed_callbacks()
    native_reader, _native_target, native_init, native_callback, _exports = libxposed_native_init_fixture()
    native_export = android_export_symbol(native_init, b"native_init")
    manifest = android_manifest_semantics(
        AndroidManifestSpec(
            "xax.generated",
            "xax.generated.XaxActivity",
            min_sdk=28,
            target_sdk=35,
            version_code=1,
            launcher=True,
        )
    )
    xposed = libxposed_module_semantics(
        LibxposedModuleDescription(
            min_api_version=101,
            target_api_version=102,
            static_scope=True,
            java_entries=("xax.generated.XaxModule",),
            native_entries=("libxaxapp.so",),
            scopes=("com.example.target",),
        )
    )
    module = object_with_refs(
        Kind.MODULE,
        (
            ui["activity_callback"], ui["listener_callback"], native_init, native_callback, *managed["callbacks"],
            ui["activity_export"], ui["listener_export"], native_export, *managed["exports"],
            ui["ui_semantics"], manifest, xposed, managed["managed"],
        ),
    )
    app = package(b"android-libxposed-native", (module,), build_entries=((b"apk", ui["activity_callback"]),))
    target, profile, policy = android_arm64_shared_target(), build_profile(), trust_policy()
    request = build_request(app, b"apk", target, profile, requested_artifacts=(ArtifactKind.ANDROID_UNSIGNED_APK,))
    objects = (
        *tuple(ui["reader"].objects()), *tuple(native_reader.objects()),
        *managed["types"], *managed["graphs"], *managed["callbacks"], *managed["exports"], managed["managed"],
        ui["activity_export"], ui["listener_export"], native_export, ui["ui_semantics"], manifest, xposed,
        module, app, target, profile, policy, request,
    )
    resolution = resolve_packages(request, objects, policy, b"android-libxposed-native-resolver-v1")
    reader = snapshot_store(resolution, objects)
    result = build(reader, request.cid)
    return ui, native_init, native_callback, native_export, manifest, xposed, app, request, resolution, result


def collect_evidence() -> dict[str, object]:
    fixture = build_fixture()
    fixture2 = build_fixture()
    ui, native_init, native_callback, native_export, manifest, xposed, app, request, resolution, result = fixture
    result2 = fixture2[-1]
    if result.artifact != result2.artifact or xposed.cid != fixture2[5].cid:
        raise AssertionError("libxposed native APK fixture is not deterministic")

    apk_view = inspect_apk(result.artifact)
    with zipfile.ZipFile(io.BytesIO(result.artifact), "r") as archive:
        names = tuple(archive.namelist())
        module_prop = archive.read("META-INF/xposed/module.prop")
        java_init_list = archive.read("META-INF/xposed/java_init.list")
        native_init_list = archive.read("META-INF/xposed/native_init.list")
        scope_list = archive.read("META-INF/xposed/scope.list")
        elf_bytes = archive.read("lib/arm64-v8a/libxaxapp.so")
    elf = inspect_android_elf(elf_bytes)
    return {
        "schema": "xax-android-libxposed-native-evidence-v2",
        "environment_note": (
            "direct modern-libxposed metadata/native ELF structural evidence only; the native entry rides on the "
            "generated Java entry as API 102 and Vector require (ADR-178). Vector loading, native_init invocation, "
            "hooks, and target-process execution are UNEXECUTED here; see android_vector_runtime_evidence.json"
        ),
        "semantic_input": {
            "libxposed_carrier_cid": xposed.cid.hex(),
            "manifest_carrier_cid": manifest.cid.hex(),
            "native_init_function_cid": native_init.cid.hex(),
            "native_init_export_cid": native_export.cid.hex(),
            "min_api_version": 101,
            "target_api_version": 102,
            "static_scope": True,
            "java_entries": ["xax.generated.XaxModule"],
            "native_entries": ["libxaxapp.so"],
            "scopes": ["com.example.target"],
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
            "repeat_identical": result.artifact == result2.artifact,
            "legacy_assets_xposed_init_present": "assets/xposed_init" in names,
            "legacy_assets_native_init_present": "assets/native_init" in names,
        },
        "modern_metadata": {
            "module_prop_utf8": module_prop.decode("utf-8"),
            "java_init_list_utf8": java_init_list.decode("utf-8"),
            "native_init_list_utf8": native_init_list.decode("utf-8"),
            "scope_list_utf8": scope_list.decode("utf-8"),
        },
        "native_elf": {
            "bytes": len(elf_bytes),
            "sha256": hashlib.sha256(elf_bytes).hexdigest(),
            "exports": [item.decode("ascii") for item in elf.exports],
            "imports": [item.decode("ascii") for item in elf.imports],
            "needed": [item.decode("ascii") for item in elf.needed],
            "relocations": elf.relocation_count,
            "native_init_exported": b"native_init" in elf.exports,
        },
        "production_dependencies": {
            "java_kotlin_source_files": 0,
            "c_cpp_bridge_source_files": 0,
            "gradle_invocations": 0,
            "d8_r8_invocations": 0,
            "external_linker_invocations": 0,
        },
        "runtime_validation": {
            "module_discovery": "UNEXECUTED",
            "native_init_invocation": "UNEXECUTED",
            "framework_api_version_read": "UNEXECUTED",
            "native_hook_install": "UNEXECUTED",
            "native_hook_callback": "UNEXECUTED",
            "native_unhook": "UNEXECUTED",
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
