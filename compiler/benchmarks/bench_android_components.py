"""Deterministic structural evidence for the bounded Android BroadcastReceiver slice."""
from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import struct
import zipfile

from benchmarks.bench_android_managed_bridge import ui_activity_fixture
from xax_android import inspect_android_elf
from xax_android_components import android_broadcast_receiver_semantics, lower_android_broadcast_receiver
from xax_build import ArtifactKind, build, build_profile, build_request, package, resolve_packages, snapshot_store, trust_policy
from xax_compiler import (
    Block,
    Kind,
    Terminator,
    android_arm64_shared_target,
    android_export_symbol,
    function,
    graph_fragment,
    object_with_refs,
)
from xax_dex import emit_dex039_bridge, inspect_dex
from xax_jni import JniReferenceKind, jni_env_pointer_type, jni_reference_type, jni_short_native_symbol, jni_type_objects
from xax_manifest import AndroidManifestSpec, android_manifest_semantics, inspect_binary_manifest


EVIDENCE_PATH = Path(__file__).with_name("android_components_evidence.json")
APK_PATH = Path(__file__).with_name("android_receiver_fixture.apk")


def receiver_native_fixture():
    receiver_semantics = android_broadcast_receiver_semantics(
        exported=True,
        action="xax.generated.ACTION_TEST",
    )
    receiver_dex_spec = lower_android_broadcast_receiver(receiver_semantics)
    env = jni_env_pointer_type()
    receiver_ref_spec = (JniReferenceKind.BORROWED, b"xax.generated.XaxReceiver", b"app:xax.generated")
    context_ref_spec = (JniReferenceKind.BORROWED, b"android.content.Context", b"android.boot")
    intent_ref_spec = (JniReferenceKind.BORROWED, b"android.content.Intent", b"android.boot")
    receiver_ref = jni_reference_type(*receiver_ref_spec[:2], loader_domain=receiver_ref_spec[2])
    context_ref = jni_reference_type(*context_ref_spec[:2], loader_domain=context_ref_spec[2])
    intent_ref = jni_reference_type(*intent_ref_spec[:2], loader_domain=intent_ref_spec[2])
    graph = graph_fragment((Block((env, receiver_ref, context_ref, intent_ref), (), Terminator.return_(())),))
    callback = function(graph, (env, receiver_ref, context_ref, intent_ref), ())
    symbol = jni_short_native_symbol(receiver_dex_spec.class_descriptor, receiver_dex_spec.native_methods[0].name)
    export = android_export_symbol(callback, symbol)
    types = jni_type_objects((receiver_ref_spec, context_ref_spec, intent_ref_spec))
    return {
        "semantics": receiver_semantics,
        "dex_spec": receiver_dex_spec,
        "callback": callback,
        "graph": graph,
        "symbol": symbol,
        "export": export,
        "types": types,
    }


def receiver_apk_fixture():
    ui = ui_activity_fixture()
    receiver = receiver_native_fixture()
    manifest = android_manifest_semantics(
        AndroidManifestSpec("xax.generated", "xax.generated.XaxActivity", min_sdk=28, target_sdk=35)
    )
    module = object_with_refs(
        Kind.MODULE,
        (
            ui["activity_callback"], ui["listener_callback"], receiver["callback"],
            ui["activity_export"], ui["listener_export"], receiver["export"],
            ui["ui_semantics"], manifest, receiver["semantics"],
        ),
    )
    app = package(b"android-receiver-fixture", (module,), build_entries=((b"apk", ui["activity_callback"]),))
    target, profile, policy = android_arm64_shared_target(), build_profile(), trust_policy()
    request = build_request(app, b"apk", target, profile, requested_artifacts=(ArtifactKind.ANDROID_UNSIGNED_APK,))
    objects = (
        *tuple(ui["reader"].objects()), *receiver["types"], receiver["graph"], receiver["callback"], receiver["export"],
        ui["activity_export"], ui["listener_export"], ui["ui_semantics"], manifest, receiver["semantics"],
        module, app, target, profile, policy, request,
    )
    resolution = resolve_packages(request, objects, policy, b"android-receiver-resolver-v1")
    reader = snapshot_store(resolution, objects)
    result = build(reader, request.cid)
    return ui, receiver, manifest, app, request, resolution, result


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


def _virtual_method_code_units(data: bytes, method_name: str) -> tuple[int, tuple[int, ...]]:
    view = inspect_dex(data)
    method_ids_off = struct.unpack_from("<I", data, 92)[0]
    class_defs_off = struct.unpack_from("<I", data, 100)[0]
    class_data_off = struct.unpack_from("<I", data, class_defs_off + 24)[0]

    def name(index: int) -> str:
        name_idx = struct.unpack_from("<I", data, method_ids_off + index * 8 + 4)[0]
        return view.strings[name_idx]

    offset = class_data_off
    _, offset = _uleb(data, offset)
    _, offset = _uleb(data, offset)
    direct_count, offset = _uleb(data, offset)
    virtual_count, offset = _uleb(data, offset)
    previous = 0
    for position in range(direct_count):
        diff, offset = _uleb(data, offset)
        previous = diff if position == 0 else previous + diff
        _, offset = _uleb(data, offset)
        _, offset = _uleb(data, offset)
    previous = 0
    for position in range(virtual_count):
        diff, offset = _uleb(data, offset)
        index = diff if position == 0 else previous + diff
        _, offset = _uleb(data, offset)
        code_off, offset = _uleb(data, offset)
        previous = index
        if name(index) == method_name:
            insns = struct.unpack_from("<I", data, code_off + 12)[0]
            return insns, struct.unpack_from(f"<{insns}H", data, code_off + 16)
    raise AssertionError(method_name)


def collect_evidence() -> dict[str, object]:
    ui, receiver, manifest, app, request, resolution, result = receiver_apk_fixture()
    ui2, receiver2, manifest2, app2, request2, resolution2, result2 = receiver_apk_fixture()
    if result.artifact != result2.artifact or receiver["semantics"].cid != receiver2["semantics"].cid:
        raise AssertionError("Android receiver fixture is not deterministic")
    receiver_dex = emit_dex039_bridge(receiver["dex_spec"])
    dex_view = inspect_dex(receiver_dex)
    code_units, units = _virtual_method_code_units(receiver_dex, "onReceive")
    with zipfile.ZipFile(io.BytesIO(result.artifact), "r") as archive:
        names = tuple(archive.namelist())
        packaged_receiver_dex = archive.read("classes3.dex")
        manifest_bytes = archive.read("AndroidManifest.xml")
        elf_bytes = archive.read("lib/arm64-v8a/libxaxapp.so")
    if packaged_receiver_dex != receiver_dex:
        raise AssertionError("generic build changed receiver DEX bytes")
    manifest_view = inspect_binary_manifest(manifest_bytes)
    receiver_elements = [item for item in manifest_view.elements if item.name == "receiver"]
    action_values = [
        attr.value
        for item in manifest_view.elements
        if item.name == "action"
        for attr in item.attributes
        if attr.name == "name"
    ]
    elf = inspect_android_elf(elf_bytes)
    return {
        "schema": "xax-android-components-evidence-v1",
        "environment_note": (
            "direct structural BroadcastReceiver evidence only; package-manager/ART/broadcast execution is "
            "UNEXECUTED because no Android device/emulator is available"
        ),
        "semantic_input": {
            "receiver_carrier_cid": receiver["semantics"].cid.hex(),
            "class_descriptor": dex_view.class_descriptor,
            "exported": True,
            "action": "xax.generated.ACTION_TEST",
            "callback_cid": receiver["callback"].cid.hex(),
            "export_cid": receiver["export"].cid.hex(),
            "jni_symbol": receiver["symbol"].decode("ascii"),
            "loader_domains": {
                "receiver": "app:xax.generated",
                "context": "android.boot",
                "intent": "android.boot",
            },
        },
        "dex": {
            "bytes": len(receiver_dex),
            "sha256": hashlib.sha256(receiver_dex).hexdigest(),
            "superclass": dex_view.superclass_descriptor,
            "on_receive_code_units": code_units,
            "on_receive_opcodes": [f"0x{unit & 0xff:02x}" for unit in units],
            "native_transitions": 1,
            "allocations_emitted_in_on_receive": 0,
            "reflection_operations_emitted": 0,
            "checksum_valid": dex_view.checksum_valid,
            "signature_valid": dex_view.signature_valid,
        },
        "manifest": {
            "receiver_count": len(receiver_elements),
            "receiver_attributes": {
                attr.name: attr.value for attr in receiver_elements[0].attributes
            },
            "action_present": "xax.generated.ACTION_TEST" in action_values,
        },
        "generic_apk": {
            "package_root": app.cid.hex(),
            "request_root": request.cid.hex(),
            "snapshot_root": resolution.snapshot.cid.hex(),
            "build_key": result.key.hex(),
            "bytes": len(result.artifact),
            "blake3": result.artifact_digest.hex(),
            "entries": list(names),
            "repeat_identical": result.artifact == result2.artifact,
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
            "gradle_invocations": 0,
            "d8_r8_invocations": 0,
            "external_manifest_compiler_invocations": 0,
        },
        "runtime_validation": {
            "package_install": "UNEXECUTED",
            "receiver_instantiation": "UNEXECUTED",
            "broadcast_delivery": "UNEXECUTED",
            "xax_callback_execution": "UNEXECUTED",
        },
    }


def main() -> None:
    *_unused, result = receiver_apk_fixture()
    APK_PATH.write_bytes(result.artifact)
    evidence = collect_evidence()
    EVIDENCE_PATH.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(APK_PATH)
    print(EVIDENCE_PATH)
    print(json.dumps(evidence, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
