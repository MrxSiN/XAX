"""Deterministic evidence for capability-gated typed libxposed remote preferences."""
from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import zipfile

from benchmarks.bench_android_libxposed_managed import _managed_callbacks, _virtual_method_units
from benchmarks.bench_android_managed_bridge import ui_activity_fixture
from xax_build import ArtifactKind, build, build_profile, build_request, package, resolve_packages, snapshot_store, trust_policy
from xax_compiler import Kind, android_arm64_shared_target, object_with_refs
from xax_dex import inspect_dex
from xax_libxposed import (
    LibxposedModuleDescription,
    LibxposedRemotePreferencesDescription,
    libxposed_module_semantics,
    libxposed_remote_preferences_semantics,
)
from xax_manifest import AndroidManifestSpec, android_manifest_semantics


EVIDENCE_PATH = Path(__file__).with_name("android_libxposed_remote_preferences_evidence.json")
APK_PATH = Path(__file__).with_name("android_libxposed_remote_preferences_fixture.apk")

READS = ("boolean", "int", "long", "float", "string", "contains")


def build_fixture():
    ui = ui_activity_fixture()
    managed = _managed_callbacks()
    remote_preferences = libxposed_remote_preferences_semantics(
        LibxposedRemotePreferencesDescription(
            READS,
            "nullable-on-unsupported",
            "propagate",
        )
    )
    manifest = android_manifest_semantics(
        AndroidManifestSpec(
            "xax.generated", "xax.generated.XaxActivity", min_sdk=28, target_sdk=35,
            version_code=1, launcher=True,
        )
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
            ui["ui_semantics"], manifest, xposed, managed["managed"], remote_preferences,
        ),
    )
    app = package(b"android-libxposed-remote-preferences", (module,), build_entries=((b"apk", ui["activity_callback"]),))
    target, profile, policy = android_arm64_shared_target(), build_profile(), trust_policy()
    request = build_request(app, b"apk", target, profile, requested_artifacts=(ArtifactKind.ANDROID_UNSIGNED_APK,))
    objects = (
        *tuple(ui["reader"].objects()), *managed["types"], *managed["graphs"], *managed["callbacks"],
        ui["activity_export"], ui["listener_export"], *managed["exports"], ui["ui_semantics"], manifest,
        xposed, managed["managed"], remote_preferences, module, app, target, profile, policy, request,
    )
    resolution = resolve_packages(request, objects, policy, b"android-libxposed-remote-preferences-resolver-v1")
    reader = snapshot_store(resolution, objects)
    result = build(reader, request.cid)
    return managed, remote_preferences, xposed, app, request, resolution, result


def collect_evidence() -> dict[str, object]:
    fixture = build_fixture()
    repeat = build_fixture()
    managed, remote_preferences, xposed, app, request, resolution, result = fixture
    if result.artifact != repeat[-1].artifact or remote_preferences.cid != repeat[1].cid:
        raise AssertionError("libxposed remote-preferences fixture is not deterministic")
    with zipfile.ZipFile(io.BytesIO(result.artifact), "r") as archive:
        names = tuple(archive.namelist())
        managed_bytes = archive.read("classes3.dex")
    dex = inspect_dex(managed_bytes)
    methods = _virtual_method_units(managed_bytes)
    acquire_units = methods["xaxRemotePreferencesIfSupported"][1]
    generated = {
        "boolean": "xaxPrefBoolean",
        "int": "xaxPrefInt",
        "long": "xaxPrefLong",
        "float": "xaxPrefFloat",
        "string": "xaxPrefString",
        "contains": "xaxPrefContains",
    }
    typed_reads = {}
    for read, name in generated.items():
        units = methods[name][1]
        typed_reads[read] = {
            "generated_method": name,
            "code_units": methods[name][0],
            "invoke_interface_count": sum(1 for unit in units if unit & 0xFF == 0x72),
            "allocation_opcodes": sum(1 for unit in units if unit & 0xFF in (0x22, 0x23)),
            "terminal_opcodes": [units[-2] & 0xFF, units[-1] & 0xFF],
        }
    return {
        "schema": "xax-android-libxposed-remote-preferences-evidence-v1",
        "environment_note": (
            "direct semantic/DEX/APK structural evidence only; PROP_CAP_REMOTE behavior, returned SharedPreferences values, "
            "cross-process change visibility, and framework failures are UNEXECUTED because no compatible Android/libxposed "
            "API-102 runtime is available"
        ),
        "upstream_contract": {
            "api_coordinate": "io.github.libxposed:api:102.0.0",
            "capability": "PROP_CAP_REMOTE = 1L << 1",
            "framework_properties_method": "getFrameworkProperties()->long",
            "acquire_method": "getRemotePreferences(String)->SharedPreferences",
            "hooked_process_access": "read-only",
            "typed_reads": [
                "getBoolean(String,boolean)->boolean",
                "getInt(String,int)->int",
                "getLong(String,long)->long",
                "getFloat(String,float)->float",
                "getString(String,String)->String",
                "contains(String)->boolean",
            ],
        },
        "semantic_input": {
            "metadata_cid": xposed.cid.hex(),
            "managed_entry_cid": managed["managed"].cid.hex(),
            "remote_preferences_cid": remote_preferences.cid.hex(),
            "reads": list(READS),
            "capability_policy": "nullable-on-unsupported",
            "failure_policy": "propagate",
        },
        "managed_dex": {
            "bytes": len(managed_bytes),
            "sha256": hashlib.sha256(managed_bytes).hexdigest(),
            "checksum_valid": dex.checksum_valid,
            "signature_valid": dex.signature_valid,
            "class_descriptor": dex.class_descriptor,
            "acquire": {
                "generated_method": "xaxRemotePreferencesIfSupported",
                "code_units": methods["xaxRemotePreferencesIfSupported"][0],
                "invoke_virtual_count": sum(1 for unit in acquire_units if unit & 0xFF == 0x6E),
                "if_eqz_count": sum(1 for unit in acquire_units if unit & 0xFF == 0x38),
                "and_int_lit8_count": sum(1 for unit in acquire_units if unit & 0xFF == 0xDD),
                "null_fallback_count": sum(1 for unit in acquire_units if unit & 0xFF == 0x12),
                "allocation_opcodes": sum(1 for unit in acquire_units if unit & 0xFF in (0x22, 0x23)),
            },
            "typed_reads": typed_reads,
            "write_surface_absent": {
                "Editor": "Landroid/content/SharedPreferences$Editor;" not in dex.strings,
                "edit": "edit" not in dex.strings,
                "putBoolean": "putBoolean" not in dex.strings,
                "apply": "apply" not in dex.strings,
            },
        },
        "apk": {
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
        "runtime_validation": {
            "capability_bit": "UNEXECUTED",
            "unsupported_returns_null": "UNEXECUTED",
            "remote_preferences_read": "UNEXECUTED",
            "change_listener_visibility": "UNEXECUTED",
            "failure_propagation": "UNEXECUTED",
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
