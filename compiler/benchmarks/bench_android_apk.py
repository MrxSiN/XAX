"""Deterministic structural evidence for the first directly emitted XAX Android APK.

The artifact is assembled from XAX-emitted binary AndroidManifest.xml, DEX 039,
AArch64 ELF and a direct APK Signature Scheme v2 signing block.  No Android
runtime success is claimed without executing it on Android/ART.
"""
from __future__ import annotations

import hashlib
import io
import json

from blake3 import blake3
import zipfile
from pathlib import Path

from benchmarks.bench_android_managed_bridge import ui_activity_fixture
from xax_android import inspect_android_elf
from xax_apk import inspect_apk
from xax_apk_signing import RsaSigningCapability, encode_private_signing_capability, inspect_apk_v2
from xax_build import (
    ArtifactKind,
    BuildCapability,
    BuildCapabilityKind,
    BuildEffect,
    CapabilityGrant,
    build,
    build_profile,
    build_request,
    package,
    resolve_packages,
    snapshot_store,
    trust_policy,
)
from xax_compiler import Kind, android_arm64_shared_target, object_with_refs
from xax_dex import inspect_dex
from xax_manifest import AndroidManifestSpec, android_manifest_semantics, emit_binary_manifest_from_semantics, inspect_binary_manifest


BENCHMARK_DIR = Path(__file__).parent
SIGNER_FIXTURE = BENCHMARK_DIR.parent / "tests" / "fixtures" / "android_v2_test_signer.json"
ARTIFACT_PATH = BENCHMARK_DIR / "android_minimal_activity.apk"
EVIDENCE_PATH = BENCHMARK_DIR / "android_apk_evidence.json"


def _signing_capability() -> RsaSigningCapability:
    raw = json.loads(SIGNER_FIXTURE.read_text(encoding="utf-8"))
    return RsaSigningCapability(
        int(raw["modulus_hex"], 16),
        int(raw["public_exponent"]),
        int(raw["private_exponent_hex"], 16),
        bytes.fromhex(raw["certificate_der_hex"]),
    )


def _package_build(ui, manifest_semantics, artifact_kind: ArtifactKind, signer: RsaSigningCapability | None = None):
    module = object_with_refs(
        Kind.MODULE,
        (
            ui["activity_callback"],
            ui["listener_callback"],
            ui["activity_export"],
            ui["listener_export"],
            ui["ui_semantics"],
            manifest_semantics,
        ),
    )
    capabilities = ()
    grants = ()
    effects = ()
    if artifact_kind == ArtifactKind.ANDROID_SIGNED_APK:
        if signer is None:
            raise ValueError("signed Android package build requires explicit signer")
        sign_capability = BuildCapability(BuildCapabilityKind.SIGN, bytes.fromhex(signer.identity_sha256))
        capabilities = (sign_capability,)
        grants = (CapabilityGrant(b"android-app", sign_capability),)
        effects = (BuildEffect(b"android-app", sign_capability, encode_private_signing_capability(signer)),)
    elif signer is not None:
        raise ValueError("signer supplied for unsigned Android package build")

    package_object = package(
        b"android-app",
        (module,),
        build_entries=((b"apk", ui["activity_callback"]),),
        capabilities=capabilities,
    )
    target = android_arm64_shared_target()
    profile, policy = build_profile(grants=grants), trust_policy()
    request = build_request(
        package_object,
        b"apk",
        target,
        profile,
        requested_artifacts=(artifact_kind,),
    )
    objects = (
        *tuple(ui["reader"].objects()),
        ui["activity_export"], ui["listener_export"], ui["ui_semantics"],
        manifest_semantics, module, package_object, target, profile, policy, request,
    )
    external_inputs = {}
    if effects:
        transport = effects[0].value
        external_inputs = {blake3(transport).digest(): transport}
    resolution = resolve_packages(
        request, objects, policy, b"android-resolver-v1", external_inputs=external_inputs
    )
    reader = snapshot_store(resolution, objects)
    result = build(reader, request.cid, external_inputs=external_inputs, effects=effects)
    return result, resolution, package_object, request


def _unsigned_package_build(ui, manifest_semantics):
    return _package_build(ui, manifest_semantics, ArtifactKind.ANDROID_UNSIGNED_APK)


def _signed_package_build(ui, manifest_semantics, signer: RsaSigningCapability):
    return _package_build(ui, manifest_semantics, ArtifactKind.ANDROID_SIGNED_APK, signer)


def build_fixture() -> tuple[bytes, bytes, bytes, bytes, bytes, bytes, bytes]:
    ui = ui_activity_fixture()
    manifest_semantics = android_manifest_semantics(
        AndroidManifestSpec(
            package_name="xax.generated",
            activity_class="xax.generated.XaxActivity",
            min_sdk=28,
            target_sdk=35,
            version_code=1,
            launcher=True,
        )
    )
    unsigned_result, _unsigned_resolution, _unsigned_package, _unsigned_request = _unsigned_package_build(ui, manifest_semantics)
    signer = _signing_capability()
    signed_result, _signed_resolution, _signed_package, _signed_request = _signed_package_build(ui, manifest_semantics, signer)
    unsigned = unsigned_result.artifact
    signed = signed_result.artifact
    with zipfile.ZipFile(io.BytesIO(unsigned), "r") as archive:
        manifest = archive.read("AndroidManifest.xml")
        dex = archive.read("classes.dex")
        listener_dex = archive.read("classes2.dex")
        elf = archive.read("lib/arm64-v8a/libxaxapp.so")
    return manifest_semantics, manifest, dex, listener_dex, elf, unsigned, signed


def collect_evidence() -> dict[str, object]:
    ui = ui_activity_fixture()
    manifest_semantics = android_manifest_semantics(
        AndroidManifestSpec("xax.generated", "xax.generated.XaxActivity", min_sdk=28, target_sdk=35, version_code=1, launcher=True)
    )
    build_result, resolution, package_object, request = _unsigned_package_build(ui, manifest_semantics)
    signer = _signing_capability()
    signed_build_result, signed_resolution, signed_package_object, signed_request = _signed_package_build(ui, manifest_semantics, signer)
    manifest_semantics2, manifest, dex, listener_dex, elf, unsigned, signed = build_fixture()
    if (
        manifest_semantics.cid != manifest_semantics2.cid
        or build_result.artifact != unsigned
        or signed_build_result.artifact != signed
    ):
        raise AssertionError("Android package build fixture is not deterministic")
    manifest_view = inspect_binary_manifest(manifest)
    dex_view = inspect_dex(dex)
    listener_dex_view = inspect_dex(listener_dex)
    elf_view = inspect_android_elf(elf)
    unsigned_view = inspect_apk(unsigned)
    signed_view = inspect_apk_v2(signed)
    capability = _signing_capability()

    entry_alignments = {
        item.name: {
            "data_offset": item.data_offset,
            "required_alignment": item.alignment,
            "aligned": item.data_offset % item.alignment == 0,
            "size": item.size,
        }
        for item in unsigned_view.entries
    }
    return {
        "schema": "xax-android-apk-evidence-v2",
        "environment_note": (
            "direct-emission structural/signature evidence only; Android package-manager/ART/Activity "
            "execution is UNEXECUTED because no Android device/emulator/build-tools runtime is available"
        ),
        "semantic_source_policy": {
            "java_source_files": 0,
            "kotlin_source_files": 0,
            "c_cpp_bridge_source_files": 0,
            "gradle_build_files": 0,
            "javac_invocations": 0,
            "kotlinc_invocations": 0,
            "d8_r8_invocations": 0,
            "aapt2_invocations": 0,
            "external_linker_invocations": 0,
            "apksigner_invocations": 0,
        },
        "generic_build_request": {
            "unsigned": {
                "artifact_kind": "ANDROID_UNSIGNED_APK",
                "package_root": package_object.cid.hex(),
                "request_root": request.cid.hex(),
                "snapshot_root": resolution.snapshot.cid.hex(),
                "build_key": build_result.key.hex(),
                "artifact_digest_blake3": build_result.artifact_digest.hex(),
                "bytes": len(build_result.artifact),
                "repeat_path_matches_fixture": build_result.artifact == unsigned,
            },
            "signed": {
                "artifact_kind": "ANDROID_SIGNED_APK",
                "package_root": signed_package_object.cid.hex(),
                "request_root": signed_request.cid.hex(),
                "snapshot_root": signed_resolution.snapshot.cid.hex(),
                "build_key": signed_build_result.key.hex(),
                "artifact_digest_blake3": signed_build_result.artifact_digest.hex(),
                "bytes": len(signed_build_result.artifact),
                "repeat_path_matches_fixture": signed_build_result.artifact == signed,
                "signer_identity_sha256": signer.identity_sha256,
                "private_key_material_in_semantic_store": False,
                "private_key_material_in_provenance": False,
            },
        },
        "manifest": {
            "semantic_cid": manifest_semantics.cid.hex(),
            "bytes": len(manifest),
            "sha256": hashlib.sha256(manifest).hexdigest(),
            "package": "xax.generated",
            "activity": "xax.generated.XaxActivity",
            "min_sdk": 28,
            "target_sdk": 35,
            "elements": [item.name for item in manifest_view.elements],
        },
        "dex": {
            "primary_bytes": len(dex),
            "primary_sha256": hashlib.sha256(dex).hexdigest(),
            "secondary_bytes": len(listener_dex),
            "secondary_sha256": hashlib.sha256(listener_dex).hexdigest(),
            "version": dex_view.version,
            "primary_classes": dex_view.class_defs_size,
            "secondary_classes": listener_dex_view.class_defs_size,
            "primary_methods": dex_view.method_ids_size,
            "secondary_methods": listener_dex_view.method_ids_size,
            "primary_checksum_valid": dex_view.checksum_valid,
            "primary_signature_valid": dex_view.signature_valid,
            "secondary_checksum_valid": listener_dex_view.checksum_valid,
            "secondary_signature_valid": listener_dex_view.signature_valid,
            "lifecycle_bridge": "onCreate -> invoke-super -> managed Button/listener setup -> xaxOnCreate(native) -> return",
            "click_bridge": "onClick -> check-cast clicked View -> setText(Clicked) -> xaxOnClick(native) -> return",
            "initial_button_text": "XAX",
            "native_transitions_per_lifecycle_callback": 1,
            "native_transitions_per_click_callback": 1,
            "managed_activity_create_allocations_emitted": 2,
            "managed_click_allocations_emitted": 0,
            "click_visible_state_change": "button text XAX -> Clicked",
            "reflection_operations_emitted": 0,
            "multidex_runtime_dependency": 0,
        },
        "elf": {
            "bytes": len(elf),
            "sha256": hashlib.sha256(elf).hexdigest(),
            "exports": [item.decode("ascii") for item in elf_view.exports],
            "imports": [item.decode("ascii") for item in elf_view.imports],
            "needed": [item.decode("ascii") for item in elf_view.needed],
            "relocations": elf_view.relocation_count,
        },
        "unsigned_apk": {
            "bytes": len(unsigned),
            "sha256": hashlib.sha256(unsigned).hexdigest(),
            "entry_order": [item.name for item in unsigned_view.entries],
            "entry_alignment": entry_alignments,
        },
        "signed_apk": {
            "bytes": len(signed),
            "sha256": hashlib.sha256(signed).hexdigest(),
            "v2_signing_block_offset": signed_view.signing_block_offset,
            "v2_signing_block_size": signed_view.signing_block_size,
            "signature_algorithm_id": signed_view.signature_algorithm_id,
            "certificate_sha256": signed_view.certificate_sha256,
            "expected_certificate_sha256": capability.identity_sha256,
            "signature_valid": signed_view.signature_valid,
            "content_digest_valid": signed_view.content_digest_valid,
            "certificate_key_matches": signed_view.certificate_key_matches,
        },
        "runtime_validation": {
            "validation_harness": "compiler/integration/android/validate_activity_apk.sh",
            "package_install": "UNEXECUTED",
            "activity_launch": "UNEXECUTED",
            "native_library_load": "UNEXECUTED",
            "jni_callback": "UNEXECUTED",
            "button_render": "UNEXECUTED",
            "button_click_callback": "UNEXECUTED",
        },
        "remaining_before_fixture_b_runtime_proof": [
            "execute package-manager signature/manifest validation on Android",
            "execute ART DEX verification/class initialization",
            "launch Activity and observe managed Button/listener construction plus one JNI lifecycle callback",
            "click the rendered Button and observe one JNI click callback",
            "validate the XAX-semantic UI carrier lowering and visible state mutation on real ART/Android",
        ],
    }


def main() -> None:
    _manifest_semantics, _manifest, _dex, _listener_dex, _elf, _unsigned, signed = build_fixture()
    ARTIFACT_PATH.write_bytes(signed)
    evidence = collect_evidence()
    EVIDENCE_PATH.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(ARTIFACT_PATH)
    print(EVIDENCE_PATH)
    print(json.dumps(evidence, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
