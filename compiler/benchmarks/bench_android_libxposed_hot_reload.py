"""Deterministic structural evidence for API-102 stable-ID guarded atomic hook replacement."""
from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import zipfile

from benchmarks.bench_android_libxposed_hook import _instruction_opcodes, build_fixture
from benchmarks.bench_android_libxposed_managed import _virtual_method_units
from xax_dex import inspect_dex
from xax_libxposed import libxposed_hot_reload_semantics

EVIDENCE_PATH = Path(__file__).with_name("android_libxposed_hot_reload_evidence.json")
APK_PATH = Path(__file__).with_name("android_libxposed_hot_reload_fixture.apk")


def collect_evidence() -> dict[str, object]:
    fixture = build_fixture(lifetime_policy="retained-manual-unhook", hot_reload=True)
    repeat = build_fixture(lifetime_policy="retained-manual-unhook", hot_reload=True)
    baseline = build_fixture(lifetime_policy="retained-manual-unhook", hot_reload=False)
    ui, managed, hooker, installation, manifest, xposed, app, request, resolution, result = fixture
    hot_reload = libxposed_hot_reload_semantics()
    if result.artifact != repeat[-1].artifact:
        raise AssertionError("libxposed hot-reload fixture is not deterministic")

    with zipfile.ZipFile(io.BytesIO(result.artifact), "r") as archive:
        names = tuple(archive.namelist())
        managed_bytes = archive.read("classes3.dex")
        hooker_bytes = archive.read("classes4.dex")
        module_prop = archive.read("META-INF/xposed/module.prop")
    with zipfile.ZipFile(io.BytesIO(baseline[-1].artifact), "r") as archive:
        baseline_hooker_bytes = archive.read("classes4.dex")

    dex = inspect_dex(managed_bytes)
    methods = _virtual_method_units(managed_bytes)
    pre_units = methods["onHotReloading"][1]
    post_units = methods["onHotReloaded"][1]
    pre_opcodes = _instruction_opcodes(pre_units)
    post_opcodes = _instruction_opcodes(post_units)
    return {
        "schema": "xax-android-libxposed-hot-reload-evidence-v1",
        "environment_note": (
            "direct semantic/DEX/APK structural evidence only; framework hot-reload callback delivery, old HookHandle transfer, "
            "atomic replacement behavior, and target-process continuity are UNEXECUTED because no compatible Android/libxposed "
            "API-102 runtime is available"
        ),
        "upstream_profile": {
            "api_coordinate": "io.github.libxposed:api:102.0.0",
            "min_api_version": 102,
            "target_api_version": 102,
            "auto_hot_reload": True,
            "java_entry_count": 1,
            "replacement_contract": "capture PackageReadyParam ClassLoader; save/restore it across generations; setId(stable ID) at install; HotReloadedParam old handle must be nonempty and getId()==stable ID before replaceHook(new generated Hooker)",
        },
        "semantic_input": {
            "hot_reload_cid": hot_reload.cid.hex(),
            "hook_installation_cid": installation.cid.hex(),
            "managed_entry_cid": managed["managed"].cid.hex(),
            "hook_adapter_cid": hooker.cid.hex(),
            "policy": "single-retained-hook-id-guarded-atomic-replace",
            "failure_policy": "propagate",
            "hook_id": "xax.primary",
            "mismatch_policy": "skip-replacement",
            "state_policy": "package-ready-class-loader",
            "missing_state_policy": "reject-reload",
        },
        "managed_dex": {
            "bytes": len(managed_bytes),
            "sha256": hashlib.sha256(managed_bytes).hexdigest(),
            "checksum_valid": dex.checksum_valid,
            "signature_valid": dex.signature_valid,
            "class_descriptor": dex.class_descriptor,
            "on_hot_reloading": {
                "code_units": methods["onHotReloading"][0],
                "raw_units": [f"0x{unit:04x}" for unit in pre_units],
                "instruction_opcodes": [f"0x{opcode:02x}" for opcode in pre_opcodes],
                "invoke_interface_count": pre_opcodes.count(0x72),
                "missing_loader_reject_guard_count": pre_opcodes.count(0x38),
                "policy": "save host-owned PackageReadyParam ClassLoader; reject reload if it was never captured",
            },
            "on_hot_reloaded": {
                "code_units": methods["onHotReloaded"][0],
                "instruction_opcodes": [f"0x{opcode:02x}" for opcode in post_opcodes],
                "invoke_interface_count": post_opcodes.count(0x72),
                "invoke_virtual_count": post_opcodes.count(0x6E),
                "saved_state_null_guard_count": max(0, post_opcodes.count(0x38) - 1),
                "empty_guard_count": post_opcodes.count(0x39),
                "id_mismatch_guard_count": 1 if post_opcodes.count(0x38) >= 1 else 0,
                "new_instance_count": post_opcodes.count(0x22),
                "check_cast_count": post_opcodes.count(0x1F),
                "iput_object_count": post_opcodes.count(0x5B),
                "new_array_count": post_opcodes.count(0x23),
            },
            "required_symbols_present": all(
                value in dex.strings for value in (
                    "onHotReloading", "onHotReloaded", "setSavedInstanceState", "getSavedInstanceState",
                    "xaxReloadClassLoader", "getOldHookHandles", "setId", "getId", "isEmpty",
                    "equals", "xax.primary", "replaceHook", "xaxHookHandle",
                )
            ),
        },
        "metadata": {
            "module_prop_utf8": module_prop.decode("utf-8"),
            "auto_hot_reload_line_present": b"autoHotReload=true\n" in module_prop,
        },
        "hooker_hot_path_regression": {
            "hot_reload_hooker_sha256": hashlib.sha256(hooker_bytes).hexdigest(),
            "baseline_retained_hooker_sha256": hashlib.sha256(baseline_hooker_bytes).hexdigest(),
            "byte_identical": hooker_bytes == baseline_hooker_bytes,
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
            "delta_bytes_vs_retained_non_hot_reload": len(result.artifact) - len(baseline[-1].artifact),
        },
        "runtime_validation": {
            "on_hot_reloading_delivery": "UNEXECUTED",
            "old_handle_transfer": "UNEXECUTED",
            "saved_target_class_loader_transfer": "UNEXECUTED",
            "missing_target_state_rejects_reload": "UNEXECUTED",
            "stable_hook_id_round_trip": "UNEXECUTED",
            "id_mismatch_skip": "UNEXECUTED",
            "replace_hook_atomicity": "UNEXECUTED",
            "no_hook_gap": "UNEXECUTED",
            "target_process_continuity": "UNEXECUTED",
        },
    }


def main() -> None:
    result = build_fixture(lifetime_policy="retained-manual-unhook", hot_reload=True)[-1]
    APK_PATH.write_bytes(result.artifact)
    evidence = collect_evidence()
    EVIDENCE_PATH.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(APK_PATH)
    print(EVIDENCE_PATH)
    print(json.dumps(evidence, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
