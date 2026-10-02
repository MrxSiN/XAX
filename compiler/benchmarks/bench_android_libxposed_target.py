"""Deterministic structural evidence for the controlled XAX target app used by managed-hook experiments."""
from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import zipfile

from benchmarks.bench_android_arm64 import _reader
from benchmarks.bench_android_libxposed_managed import _virtual_method_units
from xax_android import android_activity_method_ui_semantics, inspect_android_elf
from xax_build import ArtifactKind, build, build_profile, build_request, package, resolve_packages, snapshot_store, trust_policy
from xax_compiler import Block, Kind, Terminator, android_arm64_shared_target, android_export_symbol, function, graph_fragment, object_with_refs
from xax_dex import inspect_dex
from xax_jni import JniReferenceKind, jni_env_pointer_type, jni_reference_type, jni_short_native_symbol, jni_type_objects
from xax_manifest import AndroidManifestSpec, android_manifest_semantics

EVIDENCE_PATH = Path(__file__).with_name("android_libxposed_target_evidence.json")
APK_PATH = Path(__file__).with_name("android_libxposed_target_fixture.apk")

PACKAGE_NAME = "com.example.target"
ACTIVITY_CLASS = "Lcom/example/target/XaxActivity;"
LISTENER_CLASS = "Lcom/example/target/XaxOnClickListener;"
HOOK_METHOD = "hookTarget"
HOOK_DESCRIPTOR = "()Ljava/lang/String;"


def build_fixture():
    target = android_arm64_shared_target()
    ui_semantics = android_activity_method_ui_semantics(
        activity_class_descriptor=ACTIVITY_CLASS,
        listener_class_descriptor=LISTENER_CLASS,
        initial_text_method_name=HOOK_METHOD,
        initial_text_method_result="Original",
        click_button_text="Clicked",
    )
    manifest = android_manifest_semantics(
        AndroidManifestSpec(
            PACKAGE_NAME,
            "com.example.target.XaxActivity",
            min_sdk=28,
            target_sdk=35,
            version_code=1,
            launcher=True,
        )
    )

    env = jni_env_pointer_type()
    activity_spec = (JniReferenceKind.BORROWED, b"com.example.target.XaxActivity", b"app:com.example.target")
    bundle_spec = (JniReferenceKind.BORROWED, b"android.os.Bundle", b"android.boot")
    listener_spec = (JniReferenceKind.BORROWED, b"com.example.target.XaxOnClickListener", b"app:com.example.target")
    view_spec = (JniReferenceKind.BORROWED, b"android.view.View", b"android.boot")
    activity_ref = jni_reference_type(*activity_spec[:2], loader_domain=activity_spec[2])
    bundle_ref = jni_reference_type(*bundle_spec[:2], loader_domain=bundle_spec[2])
    listener_ref = jni_reference_type(*listener_spec[:2], loader_domain=listener_spec[2])
    view_ref = jni_reference_type(*view_spec[:2], loader_domain=view_spec[2])

    activity_graph = graph_fragment((Block((env, activity_ref, bundle_ref), (), Terminator.return_(())),))
    listener_graph = graph_fragment((Block((env, listener_ref, view_ref), (), Terminator.return_(())),))
    activity_callback = function(activity_graph, (env, activity_ref, bundle_ref), ())
    listener_callback = function(listener_graph, (env, listener_ref, view_ref), ())
    activity_export = android_export_symbol(activity_callback, jni_short_native_symbol(ACTIVITY_CLASS, "xaxOnCreate"))
    listener_export = android_export_symbol(listener_callback, jni_short_native_symbol(LISTENER_CLASS, "xaxOnClick"))

    type_specs = (activity_spec, bundle_spec, listener_spec, view_spec)
    local_objects = [*jni_type_objects(type_specs), activity_graph, listener_graph, activity_export, listener_export]
    native_reader = _reader((activity_callback, listener_callback), tuple(local_objects), target)

    module = object_with_refs(
        Kind.MODULE,
        (activity_callback, listener_callback, activity_export, listener_export, ui_semantics, manifest),
    )
    app = package(b"android-libxposed-target", (module,), build_entries=((b"apk", activity_callback),))
    profile, policy = build_profile(), trust_policy()
    request = build_request(app, b"apk", target, profile, requested_artifacts=(ArtifactKind.ANDROID_UNSIGNED_APK,))
    objects = (
        *tuple(native_reader.objects()), activity_export, listener_export, ui_semantics, manifest,
        module, app, target, profile, policy, request,
    )
    resolution = resolve_packages(request, objects, policy, b"android-libxposed-target-resolver-v1")
    reader = snapshot_store(resolution, objects)
    result = build(reader, request.cid)
    return ui_semantics, manifest, activity_callback, listener_callback, activity_export, listener_export, app, request, resolution, result


def collect_evidence() -> dict[str, object]:
    fixture = build_fixture()
    repeat = build_fixture()
    ui, manifest, activity_callback, listener_callback, activity_export, listener_export, app, request, resolution, result = fixture
    if result.artifact != repeat[-1].artifact or ui.cid != repeat[0].cid:
        raise AssertionError("controlled target fixture is not deterministic")

    with zipfile.ZipFile(io.BytesIO(result.artifact), "r") as archive:
        names = tuple(archive.namelist())
        activity_bytes = archive.read("classes.dex")
        listener_bytes = archive.read("classes2.dex")
        elf_bytes = archive.read("lib/arm64-v8a/libxaxapp.so")
    activity = inspect_dex(activity_bytes)
    listener = inspect_dex(listener_bytes)
    methods = _virtual_method_units(activity_bytes)
    hook_units = methods[HOOK_METHOD][1]
    create_units = methods["onCreate"][1]
    elf = inspect_android_elf(elf_bytes)
    return {
        "schema": "xax-android-libxposed-target-evidence-v1",
        "environment_note": (
            "direct semantic/DEX/ELF/APK structural evidence only; install, Activity launch, UI rendering, "
            "and any libxposed hook execution are UNEXECUTED because no Android/libxposed runtime is available"
        ),
        "semantic_input": {
            "ui_cid": ui.cid.hex(),
            "manifest_cid": manifest.cid.hex(),
            "package_name": PACKAGE_NAME,
            "activity_class": "com.example.target.XaxActivity",
            "listener_class": "com.example.target.XaxOnClickListener",
            "target_method": HOOK_METHOD,
            "target_method_descriptor": HOOK_DESCRIPTOR,
            "unhooked_result": "Original",
            "click_text": "Clicked",
            "activity_callback_cid": activity_callback.cid.hex(),
            "listener_callback_cid": listener_callback.cid.hex(),
            "activity_export_cid": activity_export.cid.hex(),
            "listener_export_cid": listener_export.cid.hex(),
        },
        "activity_dex": {
            "bytes": len(activity_bytes),
            "sha256": hashlib.sha256(activity_bytes).hexdigest(),
            "class_descriptor": activity.class_descriptor,
            "checksum_valid": activity.checksum_valid,
            "signature_valid": activity.signature_valid,
            "hook_target_code_units": methods[HOOK_METHOD][0],
            "hook_target_code_units_raw": [f"0x{unit:04x}" for unit in hook_units],
            "hook_target_opcodes": [f"0x{hook_units[0] & 0xff:02x}", f"0x{hook_units[2] & 0xff:02x}"],
            "hook_target_result_literal_present": "Original" in activity.strings,
            "on_create_code_units": methods["onCreate"][0],
            "on_create_code_units_raw": [f"0x{unit:04x}" for unit in create_units],
            "on_create_uses_hook_target": "hookTarget" in activity.strings,
            "placeholder_present": "placeholder" in activity.strings,
        },
        "listener_dex": {
            "bytes": len(listener_bytes),
            "sha256": hashlib.sha256(listener_bytes).hexdigest(),
            "class_descriptor": listener.class_descriptor,
            "interfaces": list(listener.interfaces),
            "checksum_valid": listener.checksum_valid,
            "signature_valid": listener.signature_valid,
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
            "repeat_identical": result.artifact == repeat[-1].artifact,
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
        },
        "runtime_validation": {
            "apk_install": "UNEXECUTED",
            "activity_launch": "UNEXECUTED",
            "unhooked_result_visible": "UNEXECUTED",
            "hooked_result_visible": "UNEXECUTED",
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
