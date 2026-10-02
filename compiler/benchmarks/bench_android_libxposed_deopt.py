"""Deterministic evidence for explicit libxposed API-102 deoptimization-before-hook."""
from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import struct
import zipfile

from benchmarks.bench_android_libxposed_hook import _instruction_opcodes, _opcode_counts
from benchmarks.bench_android_libxposed_managed import _managed_callbacks, _virtual_method_units
from benchmarks.bench_android_managed_bridge import ui_activity_fixture
from xax_build import ArtifactKind, build, build_profile, build_request, package, resolve_packages, snapshot_store, trust_policy
from xax_compiler import Kind, android_arm64_shared_target, object_with_refs
from xax_dex import inspect_dex
from xax_libxposed import (
    LibxposedDeoptimizationDescription,
    LibxposedHookAdapterDescription,
    LibxposedHookInstallationDescription,
    LibxposedModuleDescription,
    libxposed_deoptimization_semantics,
    libxposed_hook_adapter_semantics,
    libxposed_hook_installation_semantics,
    libxposed_module_semantics,
)
from xax_manifest import AndroidManifestSpec, android_manifest_semantics


EVIDENCE_PATH = Path(__file__).with_name("android_libxposed_deopt_evidence.json")
APK_PATH = Path(__file__).with_name("android_libxposed_deopt_fixture.apk")


def build_fixture():
    ui = ui_activity_fixture()
    managed = _managed_callbacks()
    hooker = libxposed_hook_adapter_semantics(
        LibxposedHookAdapterDescription(java_class_name="xax.generated.XaxHooker", inspected_argument_index=None)
    )
    installation = libxposed_hook_installation_semantics(
        LibxposedHookInstallationDescription(
            target_class_name="android.app.Activity",
            target_method_name="onResume",
            hooker_class_name="xax.generated.XaxHooker",
            parameter_type_names=(),
            exception_mode="PROTECTIVE",
            failure_policy="propagate",
            lifetime_policy="process",
        )
    )
    deoptimization = libxposed_deoptimization_semantics(
        LibxposedDeoptimizationDescription(
            target_class_name="android.app.Activity",
            target_method_name="onResume",
            parameter_type_names=(),
            result_policy="best-effort",
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
            ui["ui_semantics"], manifest, xposed, managed["managed"], hooker, installation, deoptimization,
        ),
    )
    app = package(b"android-libxposed-deopt", (module,), build_entries=((b"apk", ui["activity_callback"]),))
    target, profile, policy = android_arm64_shared_target(), build_profile(), trust_policy()
    request = build_request(app, b"apk", target, profile, requested_artifacts=(ArtifactKind.ANDROID_UNSIGNED_APK,))
    objects = (
        *tuple(ui["reader"].objects()), *managed["types"], *managed["graphs"], *managed["callbacks"],
        ui["activity_export"], ui["listener_export"], *managed["exports"], ui["ui_semantics"], manifest,
        xposed, managed["managed"], hooker, installation, deoptimization, module, app, target, profile, policy, request,
    )
    resolution = resolve_packages(request, objects, policy, b"android-libxposed-deopt-resolver-v1")
    reader = snapshot_store(resolution, objects)
    result = build(reader, request.cid)
    return ui, managed, hooker, installation, deoptimization, xposed, app, request, resolution, result


def _invoke_virtual_names(data: bytes, units: tuple[int, ...]) -> tuple[str, ...]:
    view = inspect_dex(data)
    method_ids_off = struct.unpack_from("<I", data, 92)[0]
    names: list[str] = []
    offset = 0
    widths = {0x0C: 1, 0x0E: 1, 0x11: 1, 0x12: 1, 0x1A: 2, 0x22: 2, 0x38: 2,
              0x54: 2, 0x5B: 2, 0x62: 2, 0x6E: 3, 0x70: 3, 0x72: 3}
    while offset < len(units):
        opcode = units[offset] & 0xFF
        width = widths[opcode]
        if opcode == 0x6E:
            method_index = units[offset + 1]
            name_index = struct.unpack_from("<I", data, method_ids_off + method_index * 8 + 4)[0]
            names.append(view.strings[name_index])
        offset += width
    return tuple(names)


def collect_evidence() -> dict[str, object]:
    fixture = build_fixture()
    repeat = build_fixture()
    ui, managed, hooker, installation, deoptimization, xposed, app, request, resolution, result = fixture
    if result.artifact != repeat[-1].artifact:
        raise AssertionError("libxposed deoptimization fixture APK is not deterministic")
    if deoptimization.cid != repeat[4].cid:
        raise AssertionError("libxposed deoptimization semantic carrier is not deterministic")

    with zipfile.ZipFile(io.BytesIO(result.artifact), "r") as archive:
        names = tuple(archive.namelist())
        managed_bytes = archive.read("classes3.dex")
        hooker_bytes = archive.read("classes4.dex")
    managed_dex = inspect_dex(managed_bytes)
    managed_methods = _virtual_method_units(managed_bytes)
    hooker_methods = _virtual_method_units(hooker_bytes)
    package_ready_units = managed_methods["onPackageReady"][1]
    intercept_units = hooker_methods["intercept"][1]
    invoke_names = _invoke_virtual_names(managed_bytes, package_ready_units)
    if "deoptimize" not in invoke_names or "hook" not in invoke_names:
        raise AssertionError("expected deoptimize and hook calls in package-ready lowering")
    if invoke_names.index("deoptimize") >= invoke_names.index("hook"):
        raise AssertionError("deoptimization must occur before hook installation")

    return {
        "schema": "xax-android-libxposed-deopt-evidence-v1",
        "environment_note": (
            "direct semantic/DEX/APK structural evidence only; actual ART deoptimization success and hook behavior are "
            "UNEXECUTED because no compatible Android/libxposed API-102 runtime is available"
        ),
        "upstream_contract": {
            "api_coordinate": "io.github.libxposed:api:102.0.0",
            "method": "XposedInterface.deoptimize(Executable)->boolean",
            "semantic_result_policy": "best-effort",
            "boolean_result_use": "explicitly ignored",
        },
        "semantic_input": {
            "metadata_cid": xposed.cid.hex(),
            "managed_entry_cid": managed["managed"].cid.hex(),
            "hook_adapter_cid": hooker.cid.hex(),
            "hook_installation_cid": installation.cid.hex(),
            "deoptimization_cid": deoptimization.cid.hex(),
            "target_class": "android.app.Activity",
            "target_method": "onResume",
            "target_parameters": [],
            "result_policy": "best-effort",
        },
        "install_dex": {
            "bytes": len(managed_bytes),
            "sha256": hashlib.sha256(managed_bytes).hexdigest(),
            "class_descriptor": managed_dex.class_descriptor,
            "checksum_valid": managed_dex.checksum_valid,
            "signature_valid": managed_dex.signature_valid,
            "on_package_ready_code_units": managed_methods["onPackageReady"][0],
            "instruction_opcodes": [f"0x{opcode:02x}" for opcode in _instruction_opcodes(package_ready_units)],
            "opcode_counts": _opcode_counts(package_ready_units),
            "invoke_virtual_names": list(invoke_names),
            "deoptimize_call_count": invoke_names.count("deoptimize"),
            "hook_call_count": invoke_names.count("hook"),
            "deoptimize_precedes_hook": invoke_names.index("deoptimize") < invoke_names.index("hook"),
            "extra_allocations_for_deoptimization": 0,
        },
        "hot_hooker": {
            "intercept_code_units": hooker_methods["intercept"][0],
            "opcode_counts": _opcode_counts(intercept_units),
            "deoptimize_string_present": "deoptimize" in inspect_dex(hooker_bytes).strings,
            "note": "deoptimization is install-time only and does not enter the interceptor hot path",
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
            "module_discovery": "UNEXECUTED",
            "package_ready": "UNEXECUTED",
            "deoptimization_return": "UNEXECUTED",
            "hook_installation": "UNEXECUTED",
            "interception": "UNEXECUTED",
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
