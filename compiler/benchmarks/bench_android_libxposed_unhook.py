"""Deterministic structural evidence for retained libxposed HookHandle/manual unhook."""
from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import struct
import zipfile

from benchmarks.bench_android_libxposed_hook import (
    _instruction_opcodes,
    _opcode_counts,
    build_fixture,
)
from benchmarks.bench_android_libxposed_managed import _virtual_method_units
from xax_dex import inspect_dex


EVIDENCE_PATH = Path(__file__).with_name("android_libxposed_unhook_evidence.json")
APK_PATH = Path(__file__).with_name("android_libxposed_unhook_fixture.apk")


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


def _class_field_counts(data: bytes) -> tuple[int, int]:
    class_defs_off = struct.unpack_from("<I", data, 100)[0]
    class_data_off = struct.unpack_from("<I", data, class_defs_off + 24)[0]
    static_fields, offset = _uleb(data, class_data_off)
    instance_fields, _ = _uleb(data, offset)
    return static_fields, instance_fields


def collect_evidence() -> dict[str, object]:
    retained = build_fixture(lifetime_policy="retained-manual-unhook")
    repeat = build_fixture(lifetime_policy="retained-manual-unhook")
    process = build_fixture(lifetime_policy="process")
    ui, managed, hooker, installation, manifest, xposed, app, request, resolution, result = retained
    if result.artifact != repeat[-1].artifact:
        raise AssertionError("retained libxposed hook APK is not deterministic")
    if installation.cid != repeat[3].cid:
        raise AssertionError("retained hook installation semantic identity is not deterministic")

    with zipfile.ZipFile(io.BytesIO(result.artifact), "r") as archive:
        names = tuple(archive.namelist())
        managed_bytes = archive.read("classes3.dex")
        hooker_bytes = archive.read("classes4.dex")
    with zipfile.ZipFile(io.BytesIO(process[-1].artifact), "r") as archive:
        process_managed_bytes = archive.read("classes3.dex")

    managed_view = inspect_dex(managed_bytes)
    process_view = inspect_dex(process_managed_bytes)
    methods = _virtual_method_units(managed_bytes)
    process_methods = _virtual_method_units(process_managed_bytes)
    install_units = methods["onPackageReady"][1]
    unhook_units = methods["xaxUnhook"][1]
    static_fields, instance_fields = _class_field_counts(managed_bytes)
    process_static_fields, process_instance_fields = _class_field_counts(process_managed_bytes)

    unhook_opcodes = _instruction_opcodes(unhook_units)
    install_opcodes = _instruction_opcodes(install_units)
    return {
        "schema": "xax-android-libxposed-unhook-evidence-v1",
        "environment_note": (
            "direct semantic/DEX/APK structural evidence only; HookHandle retention, xaxUnhook invocation, framework unhook behavior, "
            "and target-process execution are UNEXECUTED because no compatible Android/libxposed runtime is available"
        ),
        "upstream_profile": {
            "api_coordinate": "io.github.libxposed:api:102.0.0",
            "hook_handle_contract": "XposedInterface.HookHandle.unhook()",
            "lifetime_policy": "retained-manual-unhook",
        },
        "semantic_input": {
            "hook_installation_cid": installation.cid.hex(),
            "process_hook_installation_cid": process[3].cid.hex(),
            "lifetime_policy_changes_canonical_identity": installation.cid != process[3].cid,
            "managed_entry_cid": managed["managed"].cid.hex(),
            "hook_adapter_cid": hooker.cid.hex(),
        },
        "managed_dex": {
            "bytes": len(managed_bytes),
            "sha256": hashlib.sha256(managed_bytes).hexdigest(),
            "class_descriptor": managed_view.class_descriptor,
            "checksum_valid": managed_view.checksum_valid,
            "signature_valid": managed_view.signature_valid,
            "static_fields": static_fields,
            "instance_fields": instance_fields,
            "retained_field_name_present": "xaxHookHandle" in managed_view.strings,
            "manual_unhook_method_present": "xaxUnhook" in managed_view.strings,
            "install_code_units": methods["onPackageReady"][0],
            "install_instruction_opcodes": [f"0x{opcode:02x}" for opcode in install_opcodes],
            "install_iput_object_count": install_opcodes.count(0x5B),
            "unhook_code_units": methods["xaxUnhook"][0],
            "unhook_code_units_raw": [f"0x{unit:04x}" for unit in unhook_units],
            "unhook_instruction_opcodes": [f"0x{opcode:02x}" for opcode in unhook_opcodes],
            "unhook_iget_object_count": unhook_opcodes.count(0x54),
            "unhook_null_branch_count": unhook_opcodes.count(0x38),
            "unhook_invoke_interface_count": unhook_opcodes.count(0x72),
            "unhook_iput_object_count": unhook_opcodes.count(0x5B),
            "unhook_return_count": unhook_opcodes.count(0x0E),
        },
        "process_profile_regression": {
            "apk_bytes": len(process[-1].artifact),
            "apk_sha256": hashlib.sha256(process[-1].artifact).hexdigest(),
            "managed_dex_bytes": len(process_managed_bytes),
            "managed_dex_sha256": hashlib.sha256(process_managed_bytes).hexdigest(),
            "static_fields": process_static_fields,
            "instance_fields": process_instance_fields,
            "xax_hook_handle_present": "xaxHookHandle" in process_view.strings,
            "xax_unhook_present": "xaxUnhook" in process_view.strings,
            "on_package_ready_code_units": process_methods["onPackageReady"][0],
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
            "delta_bytes_vs_process_profile": len(result.artifact) - len(process[-1].artifact),
        },
        "hot_hooker_regression": {
            "retained_hooker_dex_sha256": hashlib.sha256(hooker_bytes).hexdigest(),
            "process_hooker_dex_sha256": hashlib.sha256(
                zipfile.ZipFile(io.BytesIO(process[-1].artifact), "r").read("classes4.dex")
            ).hexdigest(),
            "hooker_bytes_identical": hooker_bytes == zipfile.ZipFile(io.BytesIO(process[-1].artifact), "r").read("classes4.dex"),
            "note": "lifetime policy changes generated module/install DEX only; interceptor hot path is byte-identical",
        },
        "runtime_validation": {
            "handle_retention": "UNEXECUTED",
            "manual_unhook_call": "UNEXECUTED",
            "idempotent_second_unhook": "UNEXECUTED",
            "target_process_survival": "UNEXECUTED",
        },
    }


def main() -> None:
    result = build_fixture(lifetime_policy="retained-manual-unhook")[-1]
    APK_PATH.write_bytes(result.artifact)
    evidence = collect_evidence()
    EVIDENCE_PATH.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(APK_PATH)
    print(EVIDENCE_PATH)
    print(json.dumps(evidence, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
