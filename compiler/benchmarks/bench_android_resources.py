"""Deterministic evidence for the bounded direct Android string-resource table."""
from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import zipfile

from benchmarks.bench_android_managed_bridge import ui_activity_fixture
from xax_android import android_activity_resource_ui_semantics
from xax_build import ArtifactKind, build, build_profile, build_request, package, resolve_packages, snapshot_store, trust_policy
from xax_compiler import Kind, android_arm64_shared_target, object_with_refs
from xax_dex import inspect_dex
from xax_manifest import AndroidManifestSpec, android_manifest_semantics
from xax_resources import (
    AndroidResourceSpec,
    AndroidStringResource,
    android_resources_semantics,
    emit_resources_arsc_from_semantics,
    inspect_resources_arsc,
)


EVIDENCE_PATH = Path(__file__).with_name("android_resources_evidence.json")
TABLE_PATH = Path(__file__).with_name("android_strings.arsc")


def fixture():
    spec = AndroidResourceSpec(
        "xax.generated",
        (
            AndroidStringResource("app_name", "XAX"),
            AndroidStringResource("clicked", "Clicked"),
            AndroidStringResource("greeting", "Hello from XAX"),
        ),
    )
    carrier = android_resources_semantics(spec)
    table = emit_resources_arsc_from_semantics(carrier)
    return spec, carrier, table


def resource_backed_apk_fixture():
    ui_native = ui_activity_fixture()
    resource_ui = android_activity_resource_ui_semantics()
    spec, resources, table = fixture()
    manifest = android_manifest_semantics(
        AndroidManifestSpec("xax.generated", "xax.generated.XaxActivity", min_sdk=28, target_sdk=35)
    )
    module = object_with_refs(
        Kind.MODULE,
        (
            ui_native["activity_callback"], ui_native["listener_callback"],
            ui_native["activity_export"], ui_native["listener_export"],
            resource_ui, resources, manifest,
        ),
    )
    app = package(b"android-resource-ui", (module,), build_entries=((b"apk", ui_native["activity_callback"]),))
    target, profile, policy = android_arm64_shared_target(), build_profile(), trust_policy()
    request = build_request(app, b"apk", target, profile, requested_artifacts=(ArtifactKind.ANDROID_UNSIGNED_APK,))
    objects = (
        *tuple(ui_native["reader"].objects()), ui_native["activity_export"], ui_native["listener_export"],
        resource_ui, resources, manifest, module, app, target, profile, policy, request,
    )
    resolution = resolve_packages(request, objects, policy, b"android-resource-ui-resolver-v1")
    reader = snapshot_store(resolution, objects)
    result = build(reader, request.cid)
    return spec, resources, table, resource_ui, result, resolution, app, request


def collect_evidence() -> dict[str, object]:
    spec, carrier, table = fixture()
    spec2, carrier2, table2 = fixture()
    if spec != spec2 or carrier.cid != carrier2.cid or table != table2:
        raise AssertionError("Android resource fixture is not deterministic")
    view = inspect_resources_arsc(table)
    _spec3, _resources3, _table3, resource_ui, apk_result, resolution, app, request = resource_backed_apk_fixture()
    with zipfile.ZipFile(io.BytesIO(apk_result.artifact), "r") as archive:
        activity_dex = archive.read("classes.dex")
        listener_dex = archive.read("classes2.dex")
        packaged_table = archive.read("resources.arsc")
    activity_view, listener_view = inspect_dex(activity_dex), inspect_dex(listener_dex)
    if packaged_table != table:
        raise AssertionError("generic Android build changed resource table bytes")
    return {
        "schema": "xax-android-resources-evidence-v1",
        "environment_note": (
            "direct structural resource-table evidence only; Android AssetManager/package-manager "
            "loading is UNEXECUTED because no Android device/emulator/build-tools runtime is available"
        ),
        "semantic_input": {
            "package": spec.package_name,
            "carrier_cid": carrier.cid.hex(),
            "strings": [{"name": item.name, "value": item.value} for item in spec.strings],
        },
        "output": {
            "bytes": len(table),
            "sha256": hashlib.sha256(table).hexdigest(),
            "package_id": view.package_id,
            "type": view.type_name,
            "entries": [
                {"resource_id": f"0x{item.resource_id:08x}", "name": item.name, "value": item.value}
                for item in view.entries
            ],
            "repeat_identical": table == table2,
        },
        "resource_backed_ui_apk": {
            "ui_semantic_cid": resource_ui.cid.hex(),
            "package_root": app.cid.hex(),
            "request_root": request.cid.hex(),
            "snapshot_root": resolution.snapshot.cid.hex(),
            "build_key": apk_result.key.hex(),
            "apk_bytes": len(apk_result.artifact),
            "apk_blake3": apk_result.artifact_digest.hex(),
            "activity_dex_bytes": len(activity_dex),
            "listener_dex_bytes": len(listener_dex),
            "activity_contains_inline_XAX": "XAX" in activity_view.strings,
            "listener_contains_inline_Clicked": "Clicked" in listener_view.strings,
            "initial_resource_id": "0x7f010000",
            "click_resource_id": "0x7f010001",
            "resources_entry_present": True,
        },
        "production_dependencies": {
            "aapt2_invocations": 0,
            "external_resource_linker_invocations": 0,
            "runtime_xax_resource_parser_added": 0,
        },
        "runtime_validation": {
            "asset_manager_table_load": "UNEXECUTED",
            "resources_get_string": "UNEXECUTED",
        },
    }


def main() -> None:
    _spec, _carrier, table = fixture()
    TABLE_PATH.write_bytes(table)
    evidence = collect_evidence()
    EVIDENCE_PATH.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(TABLE_PATH)
    print(EVIDENCE_PATH)
    print(json.dumps(evidence, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
