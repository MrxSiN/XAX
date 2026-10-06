"""Deterministic structural evidence for one installed modern libxposed API-102 managed hook."""
from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import zipfile

from benchmarks.bench_android_libxposed_managed import _managed_callbacks, _virtual_method_units
from benchmarks.bench_android_managed_bridge import ui_activity_fixture
from xax_android import inspect_android_elf
from xax_build import ArtifactKind, build, build_profile, build_request, package, resolve_packages, snapshot_store, trust_policy
from xax_compiler import Kind, android_arm64_shared_target, object_with_refs
from xax_dex import inspect_dex
from xax_libxposed import (
    LibxposedHookAdapterDescription,
    LibxposedHookInstallationDescription,
    LibxposedModuleDescription,
    LibxposedHotReloadDescription,
    libxposed_hook_adapter_semantics,
    libxposed_hook_installation_semantics,
    libxposed_module_semantics,
    libxposed_hot_reload_semantics,
)
from xax_manifest import AndroidManifestSpec, android_manifest_semantics


EVIDENCE_PATH = Path(__file__).with_name("android_libxposed_hook_evidence.json")
APK_PATH = Path(__file__).with_name("android_libxposed_hook_fixture.apk")


def build_fixture(
    *,
    lifetime_policy: str = "process",
    hot_reload: bool = False,
    hook_id: str | None = None,
    min_api_version: int | None = None,
):
    """Build the hook fixture; ``hook_id``/``min_api_version`` override the defaults.

    A stable hook ID (``HookBuilder.setId``) is API-102-only, so the default
    minimum is 102 whenever an ID is present.
    """
    if hook_id is None and hot_reload:
        hook_id = "xax.primary"
    if min_api_version is None:
        min_api_version = 102 if hook_id is not None else 101
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
            lifetime_policy=lifetime_policy,
            hook_id=hook_id,
        )
    )
    hot_reload_semantics = libxposed_hot_reload_semantics(LibxposedHotReloadDescription(hook_id=hook_id)) if hot_reload else None
    manifest = android_manifest_semantics(
        AndroidManifestSpec(
            "xax.generated", "xax.generated.XaxActivity", min_sdk=28, target_sdk=35,
            version_code=1, launcher=True,
        )
    )
    xposed = libxposed_module_semantics(
        LibxposedModuleDescription(
            min_api_version=min_api_version,
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
            ui["ui_semantics"], manifest, xposed, managed["managed"], hooker, installation,
            *((hot_reload_semantics,) if hot_reload_semantics is not None else ()),
        ),
    )
    app = package(b"android-libxposed-hook", (module,), build_entries=((b"apk", ui["activity_callback"]),))
    target, profile, policy = android_arm64_shared_target(), build_profile(), trust_policy()
    request = build_request(app, b"apk", target, profile, requested_artifacts=(ArtifactKind.ANDROID_UNSIGNED_APK,))
    objects = (
        *tuple(ui["reader"].objects()), *managed["types"], *managed["graphs"], *managed["callbacks"],
        ui["activity_export"], ui["listener_export"], *managed["exports"], ui["ui_semantics"], manifest,
        xposed, managed["managed"], hooker, installation,
        *((hot_reload_semantics,) if hot_reload_semantics is not None else ()),
        module, app, target, profile, policy, request,
    )
    resolution = resolve_packages(request, objects, policy, b"android-libxposed-hook-resolver-v1")
    reader = snapshot_store(resolution, objects)
    result = build(reader, request.cid)
    return ui, managed, hooker, installation, manifest, xposed, app, request, resolution, result


_DEX_WIDTHS = {
    0x0A: 1,  # move-result
    0x0C: 1,  # move-result-object
    0x0E: 1,  # return-void
    0x0F: 1,  # return
    0x11: 1,  # return-object
    0x12: 1,  # const/4
    0x1A: 2,  # const-string
    0x1F: 2,  # check-cast
    0x22: 2,  # new-instance
    0x38: 2,  # if-eqz
    0x39: 2,  # if-nez
    0x54: 2,  # iget-object
    0x5B: 2,  # iput-object
    0x62: 2,  # sget-object
    0x6E: 3,  # invoke-virtual
    0x70: 3,  # invoke-direct
    0x72: 3,  # invoke-interface
}


def _instruction_opcodes(units: tuple[int, ...]) -> tuple[int, ...]:
    result: list[int] = []
    offset = 0
    while offset < len(units):
        opcode = units[offset] & 0xFF
        width = _DEX_WIDTHS.get(opcode)
        if width is None or offset + width > len(units):
            raise AssertionError(f"unexpected bounded hook DEX opcode 0x{opcode:02x} at unit {offset}")
        result.append(opcode)
        offset += width
    return tuple(result)


def _opcode_counts(units: tuple[int, ...]) -> dict[str, int]:
    opcodes = _instruction_opcodes(units)
    return {
        "invoke_interface": opcodes.count(0x72),
        "invoke_virtual": opcodes.count(0x6E),
        "invoke_direct": opcodes.count(0x70),
        "sget_object": opcodes.count(0x62),
        "new_instance": opcodes.count(0x22),
        "move_result_object": opcodes.count(0x0C),
        "return_object": opcodes.count(0x11),
        "return_void": opcodes.count(0x0E),
    }


def collect_evidence() -> dict[str, object]:
    fixture = build_fixture()
    repeat = build_fixture()
    ui, managed, hooker, installation, manifest, xposed, app, request, resolution, result = fixture
    if result.artifact != repeat[-1].artifact:
        raise AssertionError("libxposed hook fixture APK is not deterministic")
    if hooker.cid != repeat[2].cid or installation.cid != repeat[3].cid:
        raise AssertionError("libxposed hook semantic carriers are not deterministic")

    with zipfile.ZipFile(io.BytesIO(result.artifact), "r") as archive:
        names = tuple(archive.namelist())
        managed_bytes = archive.read("classes3.dex")
        hooker_bytes = archive.read("classes4.dex")
        elf_bytes = archive.read("lib/arm64-v8a/libxaxapp.so")
        java_init = archive.read("META-INF/xposed/java_init.list")
        scope_list = archive.read("META-INF/xposed/scope.list")
        module_prop = archive.read("META-INF/xposed/module.prop")

    managed_dex = inspect_dex(managed_bytes)
    hooker_dex = inspect_dex(hooker_bytes)
    managed_methods = _virtual_method_units(managed_bytes)
    hooker_methods = _virtual_method_units(hooker_bytes)
    package_ready_units = managed_methods["onPackageReady"][1]
    intercept_units = hooker_methods["intercept"][1]
    elf = inspect_android_elf(elf_bytes)

    return {
        "schema": "xax-android-libxposed-hook-evidence-v1",
        "environment_note": (
            "direct semantic/DEX/ELF/APK structural evidence only; module discovery, package-ready delivery, reflection resolution, "
            "hook installation, interception, original invocation, and target-process execution are UNEXECUTED because no compatible "
            "Android/libxposed runtime is available"
        ),
        "upstream_profile": {
            "api_coordinate": "io.github.libxposed:api:102.0.0",
            "target_api_version": 102,
            "managed_entry_superclass": "io.github.libxposed.api.XposedModule",
            "hook_api": "XposedInterface.hook(Executable)->HookBuilder; HookBuilder.setExceptionMode(PROTECTIVE).intercept(Hooker)",
            "hot_chain_api": "Hooker.intercept(Chain)->Object; Chain.proceed()->Object",
        },
        "semantic_input": {
            "metadata_cid": xposed.cid.hex(),
            "managed_entry_cid": managed["managed"].cid.hex(),
            "hook_adapter_cid": hooker.cid.hex(),
            "hook_installation_cid": installation.cid.hex(),
            "target_class": "android.app.Activity",
            "target_method": "onResume",
            "target_parameters": [],
            "hooker_class": "xax.generated.XaxHooker",
            "exception_mode": "PROTECTIVE",
            "failure_policy": "propagate",
            "lifetime_policy": "process",
            "scope": ["com.example.target"],
        },
        "install_dex": {
            "bytes": len(managed_bytes),
            "sha256": hashlib.sha256(managed_bytes).hexdigest(),
            "class_descriptor": managed_dex.class_descriptor,
            "checksum_valid": managed_dex.checksum_valid,
            "signature_valid": managed_dex.signature_valid,
            "on_package_ready_code_units": managed_methods["onPackageReady"][0],
            "on_package_ready_code_units_raw": [f"0x{unit:04x}" for unit in package_ready_units],
            "on_package_ready_instruction_opcodes": [f"0x{opcode:02x}" for opcode in _instruction_opcodes(package_ready_units)],
            "opcode_counts": _opcode_counts(package_ready_units),
            "target_lookup_strings": [
                item for item in ("getClassLoader", "loadClass", "getDeclaredMethod", "hook", "setExceptionMode", "intercept", "PROTECTIVE")
                if item in managed_dex.strings
            ],
            "hooker_allocations_during_install": _opcode_counts(package_ready_units)["new_instance"],
            "native_package_ready_transitions": 1,
            "try_catch_handlers": 0,
        },
        "hot_hooker_dex": {
            "bytes": len(hooker_bytes),
            "sha256": hashlib.sha256(hooker_bytes).hexdigest(),
            "class_descriptor": hooker_dex.class_descriptor,
            "interfaces": list(hooker_dex.interfaces),
            "checksum_valid": hooker_dex.checksum_valid,
            "signature_valid": hooker_dex.signature_valid,
            "intercept_code_units": hooker_methods["intercept"][0],
            "intercept_code_units_raw": [f"0x{unit:04x}" for unit in intercept_units],
            "intercept_instruction_opcodes": [f"0x{opcode:02x}" for opcode in _instruction_opcodes(intercept_units)],
            "opcode_counts": _opcode_counts(intercept_units),
            "chain_proceed_calls": _opcode_counts(intercept_units)["invoke_interface"],
            "argument_reads": 0,
            "allocations_per_intercept_emitted": _opcode_counts(intercept_units)["new_instance"],
            "reflection_strings_present": [
                item for item in ("loadClass", "getDeclaredMethod", "hook", "setExceptionMode") if item in hooker_dex.strings
            ],
        },
        "handle_lifetime": {
            "policy": "process",
            "returned_hook_handle_stored_for_unhook": False,
            "unhook_supported_by_this_profile": False,
            "note": "the HookHandle is intentionally not retained by the bounded process-lifetime profile; explicit unhook is not claimed",
        },
        "modern_metadata": {
            "java_init_list_utf8": java_init.decode("utf-8"),
            "scope_list_utf8": scope_list.decode("utf-8"),
            "module_prop_utf8": module_prop.decode("utf-8"),
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
            "bundled_libxposed_api_classes": 0,
        },
        "runtime_validation": {
            "module_discovery": "UNEXECUTED",
            "package_ready": "UNEXECUTED",
            "classloader_resolution": "UNEXECUTED",
            "hook_installation": "UNEXECUTED",
            "interception": "UNEXECUTED",
            "chain_proceed": "UNEXECUTED",
            "target_process_survival": "UNEXECUTED",
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
