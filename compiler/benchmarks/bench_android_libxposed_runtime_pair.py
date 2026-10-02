"""Validation-only signed APK pair for the controlled API-102 libxposed fixture.

The semantic/build evidence remains in the target/combined benchmarks.  This file
only gives the unavailable real-device/runtime proof a deterministic installable
pair using the repository test signing capability.  It does not claim execution.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from benchmarks.bench_android_apk import _signing_capability
from benchmarks.bench_android_libxposed_argument_target import build_fixture as build_target_fixture
from benchmarks.bench_android_libxposed_combined import build_fixture as build_module_fixture
from xax_apk_signing import inspect_apk_v2, sign_apk_v2

DIR = Path(__file__).parent
TARGET_APK = DIR / "android_libxposed_runtime_target_signed.apk"
MODULE_APK = DIR / "android_libxposed_runtime_module_signed.apk"
EVIDENCE = DIR / "android_libxposed_runtime_pair_evidence.json"


def collect_evidence() -> dict[str, object]:
    signer = _signing_capability()
    target_unsigned = build_target_fixture()[-1].artifact
    module_unsigned = build_module_fixture()[-1].artifact
    target_signed = sign_apk_v2(target_unsigned, signer)
    module_signed = sign_apk_v2(module_unsigned, signer)
    target_view = inspect_apk_v2(target_signed)
    module_view = inspect_apk_v2(module_signed)
    if not (target_view.signature_valid and target_view.content_digest_valid and target_view.certificate_key_matches):
        raise AssertionError("signed libxposed target validation APK failed internal v2 verification")
    if not (module_view.signature_valid and module_view.content_digest_valid and module_view.certificate_key_matches):
        raise AssertionError("signed libxposed module validation APK failed internal v2 verification")
    return {
        "schema": "xax-android-libxposed-runtime-pair-evidence-v1",
        "purpose": "validation-only installable pair; no runtime result is claimed",
        "signer_identity_sha256": signer.identity_sha256,
        "target": {
            "package": "com.example.target",
            "activity": "com.example.target.XaxActivity",
            "expected_unhooked_text": "OriginalArg",
            "bytes": len(target_signed),
            "sha256": hashlib.sha256(target_signed).hexdigest(),
            "v2_signature_valid": target_view.signature_valid,
            "v2_content_digest_valid": target_view.content_digest_valid,
            "v2_certificate_key_matches": target_view.certificate_key_matches,
        },
        "module": {
            "package": "com.example.module",
            "scope": "com.example.target",
            "expected_hooked_text": "HookedResult",
            "bytes": len(module_signed),
            "sha256": hashlib.sha256(module_signed).hexdigest(),
            "v2_signature_valid": module_view.signature_valid,
            "v2_content_digest_valid": module_view.content_digest_valid,
            "v2_certificate_key_matches": module_view.certificate_key_matches,
        },
        "runtime_validation": {
            "module_enabled_and_scoped": "EXTERNAL_PRECONDITION",
            "install": "UNEXECUTED",
            "package_ready": "UNEXECUTED",
            "interception": "UNEXECUTED",
            "visible_hooked_result": "UNEXECUTED",
        },
    }


def main() -> None:
    signer = _signing_capability()
    target_signed = sign_apk_v2(build_target_fixture()[-1].artifact, signer)
    module_signed = sign_apk_v2(build_module_fixture()[-1].artifact, signer)
    TARGET_APK.write_bytes(target_signed)
    MODULE_APK.write_bytes(module_signed)
    evidence = collect_evidence()
    EVIDENCE.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(TARGET_APK)
    print(MODULE_APK)
    print(EVIDENCE)
    print(json.dumps(evidence, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
