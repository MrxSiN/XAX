"""Deterministic structural evidence for bounded API-102 argument replacement."""
from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import zipfile

from benchmarks.bench_android_libxposed_argument_target import (
    ACTIVITY_CLASS as TARGET_ACTIVITY_DESCRIPTOR,
    HOOK_DESCRIPTOR,
    HOOK_METHOD,
    ORIGINAL_ARGUMENT,
    PACKAGE_NAME as TARGET_PACKAGE,
    collect_evidence as collect_target_evidence,
)
from benchmarks.bench_android_libxposed_managed import _managed_callbacks, _virtual_method_units
from benchmarks.bench_android_managed_bridge import ui_activity_fixture
from xax_android import inspect_android_elf
from xax_build import ArtifactKind, build, build_profile, build_request, package, resolve_packages, snapshot_store, trust_policy
from xax_compiler import Kind, android_arm64_shared_target, object_with_refs
from xax_dex import inspect_dex
from xax_libxposed import (
    LibxposedHookAdapterDescription,
    LibxposedHookArgumentDescription,
    LibxposedHookInstallationDescription,
    LibxposedModuleDescription,
    libxposed_hook_adapter_semantics,
    libxposed_hook_argument_semantics,
    libxposed_hook_installation_semantics,
    libxposed_module_semantics,
)
from xax_manifest import AndroidManifestSpec, android_manifest_semantics

EVIDENCE_PATH = Path(__file__).with_name("android_libxposed_argument_evidence.json")
APK_PATH = Path(__file__).with_name("android_libxposed_argument_fixture.apk")
TARGET_CLASS_BINARY = TARGET_ACTIVITY_DESCRIPTOR[1:-1].replace("/", ".")
REPLACEMENT_ARGUMENT = "HookedArg"

_WIDTHS = {
    0x0C: 1, 0x0E: 1, 0x11: 1, 0x12: 1,
    0x1A: 2, 0x22: 2, 0x23: 2, 0x4D: 2, 0x62: 2,
    0x6E: 3, 0x70: 3, 0x72: 3,
}


def _opcodes(units: tuple[int, ...]) -> tuple[int, ...]:
    result: list[int] = []
    offset = 0
    while offset < len(units):
        opcode = units[offset] & 0xFF
        width = _WIDTHS.get(opcode)
        if width is None or offset + width > len(units):
            raise AssertionError(f"unexpected argument-hook DEX opcode 0x{opcode:02x} at unit {offset}")
        result.append(opcode)
        offset += width
    return tuple(result)


def build_fixture():
    ui = ui_activity_fixture()
    managed = _managed_callbacks()
    hooker = libxposed_hook_adapter_semantics(
        LibxposedHookAdapterDescription(java_class_name="xax.generated.XaxHooker", inspected_argument_index=0)
    )
    installation = libxposed_hook_installation_semantics(
        LibxposedHookInstallationDescription(
            target_class_name=TARGET_CLASS_BINARY,
            target_method_name=HOOK_METHOD,
            hooker_class_name="xax.generated.XaxHooker",
            parameter_type_names=("java.lang.String",),
            exception_mode="PROTECTIVE",
            failure_policy="propagate",
            lifetime_policy="process",
        )
    )
    argument_policy = libxposed_hook_argument_semantics(
        LibxposedHookArgumentDescription(
            hooker_class_name="xax.generated.XaxHooker",
            target_class_name=TARGET_CLASS_BINARY,
            target_method_name=HOOK_METHOD,
            expected_parameter_descriptor="Ljava/lang/String;",
            expected_return_descriptor="Ljava/lang/String;",
            argument_index=0,
            replacement_string=REPLACEMENT_ARGUMENT,
            mode="replace_before_proceed",
        )
    )
    manifest = android_manifest_semantics(
        AndroidManifestSpec("com.example.module", "xax.generated.XaxActivity", min_sdk=28, target_sdk=35, version_code=1, launcher=True)
    )
    xposed = libxposed_module_semantics(
        LibxposedModuleDescription(
            min_api_version=101,
            target_api_version=102,
            static_scope=True,
            java_entries=("xax.generated.XaxModule",),
            scopes=(TARGET_PACKAGE,),
        )
    )
    module = object_with_refs(
        Kind.MODULE,
        (
            ui["activity_callback"], ui["listener_callback"], *managed["callbacks"],
            ui["activity_export"], ui["listener_export"], *managed["exports"],
            ui["ui_semantics"], manifest, xposed, managed["managed"], hooker, installation, argument_policy,
        ),
    )
    app = package(b"android-libxposed-argument", (module,), build_entries=((b"apk", ui["activity_callback"]),))
    target, profile, policy = android_arm64_shared_target(), build_profile(), trust_policy()
    request = build_request(app, b"apk", target, profile, requested_artifacts=(ArtifactKind.ANDROID_UNSIGNED_APK,))
    objects = (
        *tuple(ui["reader"].objects()), *managed["types"], *managed["graphs"], *managed["callbacks"],
        ui["activity_export"], ui["listener_export"], *managed["exports"], ui["ui_semantics"], manifest,
        xposed, managed["managed"], hooker, installation, argument_policy, module, app, target, profile, policy, request,
    )
    resolution = resolve_packages(request, objects, policy, b"android-libxposed-argument-resolver-v1")
    reader = snapshot_store(resolution, objects)
    result = build(reader, request.cid)
    return ui, managed, hooker, installation, argument_policy, manifest, xposed, app, request, resolution, result


def collect_evidence() -> dict[str, object]:
    fixture = build_fixture()
    repeat = build_fixture()
    ui, managed, hooker, installation, argument_policy, manifest, xposed, app, request, resolution, result = fixture
    if result.artifact != repeat[-1].artifact:
        raise AssertionError("libxposed argument fixture APK is not deterministic")
    if argument_policy.cid != repeat[4].cid:
        raise AssertionError("libxposed argument policy identity is not deterministic")

    target = collect_target_evidence()
    contract = target["semantic_input"]
    if (
        contract["package_name"] != TARGET_PACKAGE
        or contract["activity_class"] != TARGET_CLASS_BINARY
        or contract["target_method"] != HOOK_METHOD
        or contract["target_method_descriptor"] != HOOK_DESCRIPTOR
    ):
        raise AssertionError("controlled argument target evidence does not match module policy")

    with zipfile.ZipFile(io.BytesIO(result.artifact), "r") as archive:
        names = tuple(archive.namelist())
        managed_bytes = archive.read("classes3.dex")
        hooker_bytes = archive.read("classes4.dex")
        elf_bytes = archive.read("lib/arm64-v8a/libxaxapp.so")
        scope_list = archive.read("META-INF/xposed/scope.list")
    managed_dex = inspect_dex(managed_bytes)
    hooker_dex = inspect_dex(hooker_bytes)
    managed_methods = _virtual_method_units(managed_bytes)
    hooker_methods = _virtual_method_units(hooker_bytes)
    package_ready_units = managed_methods["onPackageReady"][1]
    intercept_units = hooker_methods["intercept"][1]
    install_ops = _opcodes(package_ready_units)
    hot_ops = _opcodes(intercept_units)
    elf = inspect_android_elf(elf_bytes)

    if hot_ops.count(0x23) != 1 or hot_ops.count(0x4D) != 1 or hot_ops.count(0x72) != 2:
        raise AssertionError(f"unexpected argument replacement hot path: {hot_ops!r}")

    return {
        "schema": "xax-android-libxposed-argument-evidence-v1",
        "environment_note": (
            "paired target/module direct structural evidence only; installation, interception, argument replacement, original invocation, "
            "UI observation, allocation measurement under ART, and process survival are UNEXECUTED because no compatible Android/libxposed runtime is available"
        ),
        "upstream_contract": {
            "api_coordinate": "io.github.libxposed:api:102.0.0",
            "argument_read": "Chain.getArg(int)->Object",
            "argument_replacement": "Chain.proceed(Object[])->Object",
            "mutable_in_place_argument_api": False,
        },
        "target_contract": {
            "target_apk_sha256": target["generic_apk"]["sha256"],
            "package_name": TARGET_PACKAGE,
            "class_name": TARGET_CLASS_BINARY,
            "method_name": HOOK_METHOD,
            "method_descriptor": HOOK_DESCRIPTOR,
            "original_argument": ORIGINAL_ARGUMENT,
            "unhooked_result": ORIGINAL_ARGUMENT,
            "target_method_code_units": target["activity_dex"]["hook_target_code_units"],
        },
        "semantic_input": {
            "metadata_cid": xposed.cid.hex(),
            "managed_entry_cid": managed["managed"].cid.hex(),
            "hook_adapter_cid": hooker.cid.hex(),
            "hook_installation_cid": installation.cid.hex(),
            "argument_policy_cid": argument_policy.cid.hex(),
            "target_class": TARGET_CLASS_BINARY,
            "target_method": HOOK_METHOD,
            "target_parameter_descriptor": "Ljava/lang/String;",
            "target_return_descriptor": "Ljava/lang/String;",
            "argument_index": 0,
            "replacement_argument": REPLACEMENT_ARGUMENT,
            "mode": "replace_before_proceed",
        },
        "install_dex": {
            "bytes": len(managed_bytes),
            "sha256": hashlib.sha256(managed_bytes).hexdigest(),
            "class_descriptor": managed_dex.class_descriptor,
            "on_package_ready_code_units": managed_methods["onPackageReady"][0],
            "instruction_opcodes": [f"0x{opcode:02x}" for opcode in install_ops],
            "class_array_allocations": install_ops.count(0x23),
            "hooker_object_allocations": install_ops.count(0x22),
            "parameter_class_name_present": "java.lang.String" in managed_dex.strings,
        },
        "hot_hooker_dex": {
            "bytes": len(hooker_bytes),
            "sha256": hashlib.sha256(hooker_bytes).hexdigest(),
            "class_descriptor": hooker_dex.class_descriptor,
            "intercept_code_units": hooker_methods["intercept"][0],
            "intercept_code_units_raw": [f"0x{unit:04x}" for unit in intercept_units],
            "instruction_opcodes": [f"0x{opcode:02x}" for opcode in hot_ops],
            "argument_reads": 1,
            "chain_proceed_calls": 1,
            "object_array_allocations_per_intercept_emitted": hot_ops.count(0x23),
            "object_allocations_per_intercept_emitted": hot_ops.count(0x22),
            "argument_array_stores": hot_ops.count(0x4D),
            "replacement_literal_present": REPLACEMENT_ARGUMENT in hooker_dex.strings,
            "lookup_strings_present": [item for item in ("loadClass", "getDeclaredMethod", "hook") if item in hooker_dex.strings],
        },
        "module_apk": {
            "package_root": app.cid.hex(),
            "request_root": request.cid.hex(),
            "snapshot_root": resolution.snapshot.cid.hex(),
            "build_key": result.key.hex(),
            "bytes": len(result.artifact),
            "sha256": hashlib.sha256(result.artifact).hexdigest(),
            "blake3": result.artifact_digest.hex(),
            "entries": list(names),
            "scope_list_utf8": scope_list.decode("utf-8"),
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
        "allocation_policy": {
            "xax_attributable_steady_state_array_allocations_per_intercept_emitted": 1,
            "reason": "API 102 argument replacement requires Chain.proceed(Object[]); no in-place Chain.setArg API exists",
            "zero_allocation_claim": False,
        },
        "runtime_validation": {
            "module_discovery": "UNEXECUTED",
            "package_ready": "UNEXECUTED",
            "hook_installation": "UNEXECUTED",
            "interception": "UNEXECUTED",
            "argument_replacement": "UNEXECUTED",
            "chain_proceed_with_replacement": "UNEXECUTED",
            "target_ui_changed_from_originalarg_to_hookedarg": "UNEXECUTED",
            "art_allocation_count": "UNEXECUTED",
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
