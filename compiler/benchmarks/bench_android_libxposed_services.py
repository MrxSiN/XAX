"""Deterministic evidence for explicit libxposed API-102 module-service wrappers."""
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
    LibxposedModuleServicesDescription,
    libxposed_module_semantics,
    libxposed_module_services_semantics,
)
from xax_manifest import AndroidManifestSpec, android_manifest_semantics


EVIDENCE_PATH = Path(__file__).with_name("android_libxposed_services_evidence.json")
APK_PATH = Path(__file__).with_name("android_libxposed_services_fixture.apk")

SERVICES = (
    "framework-name",
    "framework-version",
    "remote-preferences",
    "list-remote-files",
    "open-remote-file",
)


def build_fixture():
    ui = ui_activity_fixture()
    managed = _managed_callbacks()
    services = libxposed_module_services_semantics(
        LibxposedModuleServicesDescription(SERVICES, "propagate")
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
            ui["ui_semantics"], manifest, xposed, managed["managed"], services,
        ),
    )
    app = package(b"android-libxposed-services", (module,), build_entries=((b"apk", ui["activity_callback"]),))
    target, profile, policy = android_arm64_shared_target(), build_profile(), trust_policy()
    request = build_request(app, b"apk", target, profile, requested_artifacts=(ArtifactKind.ANDROID_UNSIGNED_APK,))
    objects = (
        *tuple(ui["reader"].objects()), *managed["types"], *managed["graphs"], *managed["callbacks"],
        ui["activity_export"], ui["listener_export"], *managed["exports"], ui["ui_semantics"], manifest,
        xposed, managed["managed"], services, module, app, target, profile, policy, request,
    )
    resolution = resolve_packages(request, objects, policy, b"android-libxposed-services-resolver-v1")
    reader = snapshot_store(resolution, objects)
    result = build(reader, request.cid)
    return managed, services, xposed, app, request, resolution, result


def collect_evidence() -> dict[str, object]:
    fixture = build_fixture()
    repeat = build_fixture()
    managed, services, xposed, app, request, resolution, result = fixture
    if result.artifact != repeat[-1].artifact or services.cid != repeat[1].cid:
        raise AssertionError("libxposed module-service fixture is not deterministic")
    with zipfile.ZipFile(io.BytesIO(result.artifact), "r") as archive:
        names = tuple(archive.namelist())
        managed_bytes = archive.read("classes3.dex")
    dex = inspect_dex(managed_bytes)
    methods = _virtual_method_units(managed_bytes)
    generated = {
        "framework-name": "xaxFrameworkName",
        "framework-version": "xaxFrameworkVersion",
        "remote-preferences": "xaxRemotePreferences",
        "list-remote-files": "xaxListRemoteFiles",
        "open-remote-file": "xaxOpenRemoteFile",
    }
    wrappers = {}
    for service, name in generated.items():
        units = methods[name][1]
        wrappers[service] = {
            "generated_method": name,
            "code_units": methods[name][0],
            "invoke_virtual_count": sum(1 for unit in units if unit & 0xFF == 0x6E),
            "move_result_object_count": sum(1 for unit in units if unit & 0xFF == 0x0C),
            "return_object_count": sum(1 for unit in units if unit & 0xFF == 0x11),
            "allocation_opcodes": sum(1 for unit in units if unit & 0xFF in (0x22, 0x23)),
        }
    return {
        "schema": "xax-android-libxposed-services-evidence-v1",
        "environment_note": (
            "direct semantic/DEX/APK structural evidence only; actual framework values, remote capability support, remote preferences, "
            "and remote file access are UNEXECUTED because no compatible Android/libxposed API-102 runtime is available"
        ),
        "upstream_contract": {
            "api_coordinate": "io.github.libxposed:api:102.0.0",
            "methods": [
                "getFrameworkName()->String",
                "getFrameworkVersion()->String",
                "getRemotePreferences(String)->SharedPreferences",
                "listRemoteFiles()->String[]",
                "openRemoteFile(String)->ParcelFileDescriptor",
            ],
            "remote_failure_policy": "propagate",
            "hidden_caching": False,
        },
        "semantic_input": {
            "metadata_cid": xposed.cid.hex(),
            "managed_entry_cid": managed["managed"].cid.hex(),
            "module_services_cid": services.cid.hex(),
            "services": list(SERVICES),
            "failure_policy": "propagate",
        },
        "managed_dex": {
            "bytes": len(managed_bytes),
            "sha256": hashlib.sha256(managed_bytes).hexdigest(),
            "checksum_valid": dex.checksum_valid,
            "signature_valid": dex.signature_valid,
            "class_descriptor": dex.class_descriptor,
            "wrappers": wrappers,
            "remote_types_present": {
                "SharedPreferences": "Landroid/content/SharedPreferences;" in dex.strings,
                "ParcelFileDescriptor": "Landroid/os/ParcelFileDescriptor;" in dex.strings,
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
            "framework_name": "UNEXECUTED",
            "framework_version": "UNEXECUTED",
            "remote_preferences": "UNEXECUTED",
            "list_remote_files": "UNEXECUTED",
            "open_remote_file": "UNEXECUTED",
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
