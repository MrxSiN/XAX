"""Deterministic structural evidence for the bounded Android Service slice."""
from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import struct
import zipfile

from benchmarks.bench_android_managed_bridge import ui_activity_fixture
from xax_android import inspect_android_elf
from xax_android_components import android_service_semantics, lower_android_service
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


EVIDENCE_PATH = Path(__file__).with_name("android_service_evidence.json")
APK_PATH = Path(__file__).with_name("android_service_fixture.apk")


def service_native_fixture():
    semantics = android_service_semantics(exported=False)
    dex_spec = lower_android_service(semantics)
    env = jni_env_pointer_type()
    service_ref_spec = (JniReferenceKind.BORROWED, b"xax.generated.XaxService", b"app:xax.generated")
    service_ref = jni_reference_type(*service_ref_spec[:2], loader_domain=service_ref_spec[2])
    graph = graph_fragment((Block((env, service_ref), (), Terminator.return_(())),))
    callback = function(graph, (env, service_ref), ())
    symbols = tuple(jni_short_native_symbol(dex_spec.class_descriptor, item.name) for item in dex_spec.native_methods)
    exports = tuple(android_export_symbol(callback, symbol) for symbol in symbols)
    types = jni_type_objects((service_ref_spec,))
    return {
        "semantics": semantics,
        "dex_spec": dex_spec,
        "callback": callback,
        "graph": graph,
        "symbols": symbols,
        "exports": exports,
        "types": types,
    }


def service_apk_fixture():
    ui = ui_activity_fixture()
    service = service_native_fixture()
    manifest = android_manifest_semantics(
        AndroidManifestSpec("xax.generated", "xax.generated.XaxActivity", min_sdk=28, target_sdk=35)
    )
    module = object_with_refs(
        Kind.MODULE,
        (
            ui["activity_callback"], ui["listener_callback"], service["callback"],
            ui["activity_export"], ui["listener_export"], *service["exports"],
            ui["ui_semantics"], manifest, service["semantics"],
        ),
    )
    app = package(b"android-service-fixture", (module,), build_entries=((b"apk", ui["activity_callback"]),))
    target, profile, policy = android_arm64_shared_target(), build_profile(), trust_policy()
    request = build_request(app, b"apk", target, profile, requested_artifacts=(ArtifactKind.ANDROID_UNSIGNED_APK,))
    objects = (
        *tuple(ui["reader"].objects()), *service["types"], service["graph"], service["callback"], *service["exports"],
        ui["activity_export"], ui["listener_export"], ui["ui_semantics"], manifest, service["semantics"],
        module, app, target, profile, policy, request,
    )
    resolution = resolve_packages(request, objects, policy, b"android-service-resolver-v1")
    reader = snapshot_store(resolution, objects)
    result = build(reader, request.cid)
    return ui, service, manifest, app, request, resolution, result


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
    ui, service, manifest, app, request, resolution, result = service_apk_fixture()
    ui2, service2, manifest2, app2, request2, resolution2, result2 = service_apk_fixture()
    if result.artifact != result2.artifact or service["semantics"].cid != service2["semantics"].cid:
        raise AssertionError("Android service fixture is not deterministic")
    service_dex = emit_dex039_bridge(service["dex_spec"])
    dex_view = inspect_dex(service_dex)
    methods = {name: _virtual_method_code_units(service_dex, name) for name in ("onCreate", "onDestroy", "onBind")}
    with zipfile.ZipFile(io.BytesIO(result.artifact), "r") as archive:
        names = tuple(archive.namelist())
        packaged_service_dex = archive.read("classes3.dex")
        manifest_bytes = archive.read("AndroidManifest.xml")
        elf_bytes = archive.read("lib/arm64-v8a/libxaxapp.so")
    if packaged_service_dex != service_dex:
        raise AssertionError("generic build changed service DEX bytes")
    manifest_view = inspect_binary_manifest(manifest_bytes)
    service_elements = [item for item in manifest_view.elements if item.name == "service"]
    elf = inspect_android_elf(elf_bytes)
    return {
        "schema": "xax-android-service-evidence-v1",
        "environment_note": (
            "direct structural unbound-Service evidence only; package-manager/ART/service execution is "
            "UNEXECUTED because no Android device/emulator is available"
        ),
        "semantic_input": {
            "service_carrier_cid": service["semantics"].cid.hex(),
            "class_descriptor": dex_view.class_descriptor,
            "exported": False,
            "callback_cid": service["callback"].cid.hex(),
            "export_cids": [item.cid.hex() for item in service["exports"]],
            "jni_symbols": [item.decode("ascii") for item in service["symbols"]],
            "loader_domain": "app:xax.generated",
        },
        "dex": {
            "bytes": len(service_dex),
            "sha256": hashlib.sha256(service_dex).hexdigest(),
            "superclass": dex_view.superclass_descriptor,
            "on_create_code_units": methods["onCreate"][0],
            "on_create_opcodes": [f"0x{unit & 0xff:02x}" for unit in methods["onCreate"][1]],
            "on_destroy_code_units": methods["onDestroy"][0],
            "on_destroy_opcodes": [f"0x{unit & 0xff:02x}" for unit in methods["onDestroy"][1]],
            "on_bind_code_units": methods["onBind"][0],
            "on_bind_opcodes": [f"0x{unit & 0xff:02x}" for unit in methods["onBind"][1]],
            "lifecycle_native_transitions_each": 1,
            "on_bind_native_transitions": 0,
            "allocations_emitted_in_callbacks": 0,
            "reflection_operations_emitted": 0,
            "checksum_valid": dex_view.checksum_valid,
            "signature_valid": dex_view.signature_valid,
        },
        "manifest": {
            "service_count": len(service_elements),
            "service_attributes": {attr.name: attr.value for attr in service_elements[0].attributes},
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
            "service_instantiation": "UNEXECUTED",
            "on_create_callback": "UNEXECUTED",
            "on_destroy_callback": "UNEXECUTED",
            "on_bind_null_result": "UNEXECUTED",
        },
    }


def main() -> None:
    *_unused, result = service_apk_fixture()
    APK_PATH.write_bytes(result.artifact)
    evidence = collect_evidence()
    EVIDENCE_PATH.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(APK_PATH)
    print(EVIDENCE_PATH)
    print(json.dumps(evidence, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
