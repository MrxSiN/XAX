"""Signed, installable module/target profiles for the Vector runtime harness (ADR-178).

Every profile reuses an existing libxposed fixture builder; nothing here adds
semantics.  Each APK is v2-signed with the repository test signer so it can be
installed on a device, and each module is checked against Vector v2.2's loader
rules with ``xax_vector``.  This file records hashes and acceptance only: the
runtime results belong to ``integration/android/vector/vector_harness.py``.

    python -m benchmarks.bench_android_vector_profiles [--out DIR]
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
from typing import Callable

from benchmarks import (
    bench_android_libxposed,
    bench_android_libxposed_argument,
    bench_android_libxposed_argument_target,
    bench_android_libxposed_combined,
    bench_android_libxposed_deopt,
    bench_android_libxposed_hook,
    bench_android_libxposed_managed,
    bench_android_libxposed_remote_files,
    bench_android_libxposed_remote_preferences,
    bench_android_libxposed_result,
    bench_android_libxposed_services,
    bench_android_libxposed_target,
)
from benchmarks.bench_android_apk import _signing_capability
from xax_apk_signing import inspect_apk_v2, sign_apk_v2
from xax_vector import LibxposedApiTable, check_vector_module_apk, load_vector_pin

EVIDENCE = Path(__file__).with_name("android_vector_profiles_evidence.json")
TARGET_PACKAGE = "com.example.target"
TARGET_ACTIVITY = "com.example.target.XaxActivity"


def _hook(**options) -> Callable[[], bytes]:
    return lambda: bench_android_libxposed_hook.build_fixture(**options)[-1].artifact


def _artifact(module) -> Callable[[], bytes]:
    return lambda: module.build_fixture()[-1].artifact


# The controlled targets: hookTarget(String) echoes "OriginalArg"; hookTarget()
# returns "Original".  Both are the package com.example.target.
TARGETS: dict[str, Callable[[], bytes]] = {
    "string": _artifact(bench_android_libxposed_argument_target),
    "zero": _artifact(bench_android_libxposed_target),
}
TARGET_TEXT = {"string": "OriginalArg", "zero": "Original"}
RETAINED_RELOAD = {"lifetime_policy": "retained-manual-unhook", "hot_reload": True}


@dataclass(frozen=True)
class Profile:
    name: str
    package: str
    target: str
    module: Callable[[], bytes]
    expected_text: str
    # A second generation installed over the first to drive Vector's auto hot reload.
    reload: Callable[[], bytes] | None = None


PROFILES: tuple[Profile, ...] = (
    Profile("managed", "xax.generated", "string", _artifact(bench_android_libxposed_managed), "OriginalArg"),
    Profile("native", "xax.generated", "string", _artifact(bench_android_libxposed), "OriginalArg"),
    Profile("hook", "xax.generated", "string", _hook(), "OriginalArg"),
    Profile("deopt", "xax.generated", "string", _artifact(bench_android_libxposed_deopt), "OriginalArg"),
    Profile("unhook", "xax.generated", "string", _hook(lifetime_policy="retained-manual-unhook"), "OriginalArg"),
    Profile("result", "com.example.module", "zero", _artifact(bench_android_libxposed_result), "Hooked"),
    Profile("argument", "com.example.module", "string", _artifact(bench_android_libxposed_argument), "HookedArg"),
    Profile("combined", "com.example.module", "string", _artifact(bench_android_libxposed_combined), "HookedResult"),
    Profile("protective", "com.example.module", "string", _artifact(bench_android_libxposed_combined), "HookedResult"),
    Profile("services", "xax.generated", "string", _artifact(bench_android_libxposed_services), "OriginalArg"),
    Profile("remote_preferences", "xax.generated", "string", _artifact(bench_android_libxposed_remote_preferences), "OriginalArg"),
    Profile("remote_files", "xax.generated", "string", _artifact(bench_android_libxposed_remote_files), "OriginalArg"),
    Profile(
        "hot_reload", "xax.generated", "string", _hook(**RETAINED_RELOAD), "OriginalArg",
        reload=_hook(**RETAINED_RELOAD, version_code=2),
    ),
    Profile(
        "hot_reload_id_mismatch", "xax.generated", "string", _hook(**RETAINED_RELOAD), "OriginalArg",
        reload=_hook(**RETAINED_RELOAD, hook_id="xax.other", version_code=2),
    ),
)


def signed_apks() -> dict[str, bytes]:
    """``<profile>.apk``, ``<profile>.reload.apk`` and ``target-<kind>.apk``, all v2-signed."""
    signer = _signing_capability()
    out: dict[str, bytes] = {}
    for kind, build in TARGETS.items():
        out[f"target-{kind}.apk"] = sign_apk_v2(build(), signer)
    built: dict[int, bytes] = {}
    for profile in PROFILES:
        for suffix, build in ((".apk", profile.module), (".reload.apk", profile.reload)):
            if build is None:
                continue
            key = id(build)
            if key not in built:
                built[key] = sign_apk_v2(build(), signer)
            out[profile.name + suffix] = built[key]
    for name, apk in out.items():
        view = inspect_apk_v2(apk)
        if not (view.signature_valid and view.content_digest_valid and view.certificate_key_matches):
            raise AssertionError(f"{name} failed internal v2 verification")
    return out


def collect_evidence(apks: dict[str, bytes] | None = None) -> dict[str, object]:
    apks = signed_apks() if apks is None else apks
    table = LibxposedApiTable(load_vector_pin())

    def module_row(name: str) -> dict[str, object]:
        report = check_vector_module_apk(apks[name], table)
        return {
            "file": name,
            "sha256": hashlib.sha256(apks[name]).hexdigest(),
            "version_code_bumped": name.endswith(".reload.apk"),
            "vector_accepted": report.accepted,
            "vector_violations": list(report.violations),
            "required_api": report.required_api,
            "module_prop": report.module_prop,
        }

    return {
        "schema": "xax-android-vector-profiles-v1",
        "purpose": "validation-only signed inputs for the Vector runtime harness; no runtime result is claimed",
        "signer_identity_sha256": _signing_capability().identity_sha256,
        "targets": {
            kind: {
                "file": f"target-{kind}.apk",
                "package": TARGET_PACKAGE,
                "activity": TARGET_ACTIVITY,
                "unhooked_text": TARGET_TEXT[kind],
                "sha256": hashlib.sha256(apks[f"target-{kind}.apk"]).hexdigest(),
            }
            for kind in TARGETS
        },
        "profiles": {
            profile.name: {
                "package": profile.package,
                "target": profile.target,
                "expected_text": profile.expected_text,
                "module": module_row(profile.name + ".apk"),
                **({"reload": module_row(profile.name + ".reload.apk")} if profile.reload is not None else {}),
            }
            for profile in PROFILES
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, help="also write the signed APKs here")
    arguments = parser.parse_args()
    apks = signed_apks()
    if arguments.out is not None:
        arguments.out.mkdir(parents=True, exist_ok=True)
        for name, apk in apks.items():
            (arguments.out / name).write_bytes(apk)
    evidence = collect_evidence(apks)
    EVIDENCE.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(EVIDENCE)


if __name__ == "__main__":
    main()
