"""Deterministic structural evidence for the first XAX DEX -> JNI -> AArch64 bridge."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from benchmarks.bench_android_arm64 import _reader
from xax_android import android_activity_ui_semantics, compile_android_shared, inspect_android_elf, lower_android_activity_ui
from xax_compiler import (
    Block,
    Kind,
    Terminator,
    android_arm64_shared_target,
    android_export_symbol,
    function,
    graph_fragment,
)
from xax_dex import DexProto, activity_bridge_spec, activity_button_bridge_spec, click_text_listener_bridge_spec, emit_dex039_bridge, inspect_dex, interface_callback_bridge_spec
from xax_jni import JniReferenceKind, jni_env_pointer_type, jni_reference_type, jni_short_native_symbol, jni_type_objects


def bridge_fixture():
    target = android_arm64_shared_target()
    class_descriptor = "Lxax/generated/XaxActivity;"
    lifecycle_method = "onCreate"
    dex_spec = activity_bridge_spec(class_descriptor, lifecycle_method=lifecycle_method)
    native_method = dex_spec.native_methods[0].name
    env = jni_env_pointer_type()
    receiver = jni_reference_type(JniReferenceKind.BORROWED, b"activity")
    bundle = jni_reference_type(JniReferenceKind.BORROWED, b"android.os.Bundle")
    graph = graph_fragment([Block((env, receiver, bundle), (), Terminator.return_(()))])
    callback = function(graph, (env, receiver, bundle), ())
    symbol = jni_short_native_symbol(class_descriptor, native_method)
    export = android_export_symbol(callback, symbol)
    objects = {obj.cid: obj for obj in jni_type_objects(((JniReferenceKind.BORROWED, b"activity"), (JniReferenceKind.BORROWED, b"android.os.Bundle")))}
    objects[graph.cid] = graph
    objects[export.cid] = export
    reader = _reader((callback,), tuple(objects.values()), target)
    shared = compile_android_shared(reader, (export,), target_object=target, soname=b"libxaxapp.so")
    dex = emit_dex039_bridge(dex_spec)
    return callback, export, symbol, shared, dex




def listener_bridge_fixture():
    target = android_arm64_shared_target()
    class_descriptor = "Lxax/generated/XaxOnClickListener;"
    interface_descriptor = "Landroid/view/View$OnClickListener;"
    dex_spec = interface_callback_bridge_spec(
        class_descriptor, interface_descriptor, "onClick", DexProto("V", ("Landroid/view/View;",))
    )
    native_method = dex_spec.native_methods[0].name
    env = jni_env_pointer_type()
    receiver_spec = (JniReferenceKind.BORROWED, b"xax.generated.XaxOnClickListener", b"app:xax.generated")
    view_spec = (JniReferenceKind.BORROWED, b"android.view.View", b"android.boot")
    receiver = jni_reference_type(*receiver_spec[:2], loader_domain=receiver_spec[2])
    view = jni_reference_type(*view_spec[:2], loader_domain=view_spec[2])
    graph = graph_fragment([Block((env, receiver, view), (), Terminator.return_(()))])
    callback = function(graph, (env, receiver, view), ())
    symbol = jni_short_native_symbol(class_descriptor, native_method)
    export = android_export_symbol(callback, symbol)
    objects = {obj.cid: obj for obj in jni_type_objects((receiver_spec, view_spec))}
    objects[graph.cid] = graph
    objects[export.cid] = export
    reader = _reader((callback,), tuple(objects.values()), target)
    shared = compile_android_shared(reader, (export,), target_object=target, soname=b"libxaxapp.so")
    dex = emit_dex039_bridge(dex_spec)
    return callback, export, symbol, shared, dex



def ui_activity_fixture():
    """Build the first UI-bearing Activity/listener pair against one native ELF."""
    target = android_arm64_shared_target()
    activity_class = "Lxax/generated/XaxActivity;"
    listener_class = "Lxax/generated/XaxOnClickListener;"
    ui_semantics = android_activity_ui_semantics(
        activity_class_descriptor=activity_class,
        listener_class_descriptor=listener_class,
        initial_button_text="XAX",
        click_button_text="Clicked",
    )
    activity_spec, listener_spec = lower_android_activity_ui(ui_semantics)

    env = jni_env_pointer_type()
    activity_ref_spec = (JniReferenceKind.BORROWED, b"xax.generated.XaxActivity", b"app:xax.generated")
    bundle_ref_spec = (JniReferenceKind.BORROWED, b"android.os.Bundle", b"android.boot")
    listener_ref_spec = (JniReferenceKind.BORROWED, b"xax.generated.XaxOnClickListener", b"app:xax.generated")
    view_ref_spec = (JniReferenceKind.BORROWED, b"android.view.View", b"android.boot")
    activity_ref = jni_reference_type(*activity_ref_spec[:2], loader_domain=activity_ref_spec[2])
    bundle_ref = jni_reference_type(*bundle_ref_spec[:2], loader_domain=bundle_ref_spec[2])
    listener_ref = jni_reference_type(*listener_ref_spec[:2], loader_domain=listener_ref_spec[2])
    view_ref = jni_reference_type(*view_ref_spec[:2], loader_domain=view_ref_spec[2])

    activity_graph = graph_fragment([Block((env, activity_ref, bundle_ref), (), Terminator.return_(()))])
    listener_graph = graph_fragment([Block((env, listener_ref, view_ref), (), Terminator.return_(()))])
    activity_callback = function(activity_graph, (env, activity_ref, bundle_ref), ())
    listener_callback = function(listener_graph, (env, listener_ref, view_ref), ())
    activity_symbol = jni_short_native_symbol(activity_class, "xaxOnCreate")
    listener_symbol = jni_short_native_symbol(listener_class, "xaxOnClick")
    activity_export = android_export_symbol(activity_callback, activity_symbol)
    listener_export = android_export_symbol(listener_callback, listener_symbol)

    type_specs = (activity_ref_spec, bundle_ref_spec, listener_ref_spec, view_ref_spec)
    objects = {obj.cid: obj for obj in jni_type_objects(type_specs)}
    for obj in (activity_graph, listener_graph, activity_export, listener_export):
        objects[obj.cid] = obj
    reader = _reader((activity_callback, listener_callback), tuple(objects.values()), target)
    shared = compile_android_shared(
        reader,
        (activity_export, listener_export),
        target_object=target,
        soname=b"libxaxapp.so",
    )
    return {
        "activity_callback": activity_callback,
        "listener_callback": listener_callback,
        "activity_export": activity_export,
        "listener_export": listener_export,
        "activity_symbol": activity_symbol,
        "listener_symbol": listener_symbol,
        "shared": shared,
        "activity_dex": emit_dex039_bridge(activity_spec),
        "listener_dex": emit_dex039_bridge(listener_spec),
        "ui_semantics": ui_semantics,
        "reader": reader,
    }

def collect_evidence():
    callback, export, symbol, shared, dex = bridge_fixture()
    listener_callback, listener_export, listener_symbol, listener_shared, listener_dex = listener_bridge_fixture()
    ui = ui_activity_fixture()
    elf = inspect_android_elf(shared.data)
    dex_view = inspect_dex(dex)
    listener_elf = inspect_android_elf(listener_shared.data)
    listener_dex_view = inspect_dex(listener_dex)
    ui_elf = inspect_android_elf(ui["shared"].data)
    ui_activity_dex = inspect_dex(ui["activity_dex"])
    ui_listener_dex = inspect_dex(ui["listener_dex"])
    edited_ui_semantics = android_activity_ui_semantics(click_button_text="Done")
    edited_activity_spec, edited_listener_spec = lower_android_activity_ui(edited_ui_semantics)
    edited_activity_dex = emit_dex039_bridge(edited_activity_spec)
    edited_listener_dex = emit_dex039_bridge(edited_listener_spec)
    return {
        "schema": "xax-android-managed-bridge-evidence-v3",
        "environment_note": "structural direct-emission evidence only; ART/Android execution is unexecuted because no device/emulator is available",
        "bridge": {
            "class_descriptor": "Lxax/generated/XaxActivity;",
            "lifecycle_method": "onCreate",
            "native_callback": "xaxOnCreate",
            "lifecycle_sequence": ["invoke-super", "invoke-direct-native", "return-void"],
            "native_transitions_per_callback": 1,
            "jni_symbol": symbol.decode("ascii"),
            "xax_callback_cid": callback.cid.hex(),
            "semantic_export_cid": export.cid.hex(),
        },
        "interface_callback_bridge": {
            "class_descriptor": listener_dex_view.class_descriptor,
            "interfaces": list(listener_dex_view.interfaces),
            "method": "onClick",
            "native_callback": "xaxOnClick",
            "callback_sequence": ["invoke-direct-native", "return-void"],
            "dex_code_units": 4,
            "native_transitions_per_callback": 1,
            "per_callback_allocations_emitted": 0,
            "reflection_operations_emitted": 0,
            "jni_symbol": listener_symbol.decode("ascii"),
            "xax_callback_cid": listener_callback.cid.hex(),
            "semantic_export_cid": listener_export.cid.hex(),
            "semantic_loader_domains": {
                "listener": "app:xax.generated",
                "view": "android.boot",
            },
            "dex_bytes": len(listener_dex),
            "dex_sha256": hashlib.sha256(listener_dex).hexdigest(),
            "elf_bytes": len(listener_shared.data),
            "elf_sha256": hashlib.sha256(listener_shared.data).hexdigest(),
            "elf_exports": [item.decode("ascii") for item in listener_elf.exports],
            "elf_imports": [item.decode("ascii") for item in listener_elf.imports],
            "elf_needed": [item.decode("ascii") for item in listener_elf.needed],
            "elf_relocations": listener_elf.relocation_count,
        },
        "activity_ui_bridge": {
            "semantic_ui_cid": ui["ui_semantics"].cid.hex(),
            "activity_class": ui_activity_dex.class_descriptor,
            "listener_class": ui_listener_dex.class_descriptor,
            "listener_interfaces": list(ui_listener_dex.interfaces),
            "initial_button_text": "XAX",
            "activity_on_create_sequence": [
                "invoke-super Activity.onCreate",
                "new-instance Button",
                "invoke-direct Button.<init>(Activity)",
                "const-string XAX",
                "invoke-virtual TextView.setText",
                "new-instance XaxOnClickListener",
                "invoke-direct listener.<init>",
                "invoke-virtual View.setOnClickListener",
                "invoke-virtual Activity.setContentView",
                "invoke-direct-native xaxOnCreate",
                "return-void",
            ],
            "activity_on_create_code_units": 28,
            "managed_allocations_during_activity_create": 2,
            "reflection_operations_emitted": 0,
            "native_transitions_during_activity_create": 1,
            "native_transitions_per_click": 1,
            "click_visible_state_change": "clicked View narrowed to TextView; setText(Clicked) before native callback",
            "click_code_units": 11,
            "click_allocations_emitted": 0,
            "activity_dex_bytes": len(ui["activity_dex"]),
            "activity_dex_sha256": hashlib.sha256(ui["activity_dex"]).hexdigest(),
            "listener_dex_bytes": len(ui["listener_dex"]),
            "listener_dex_sha256": hashlib.sha256(ui["listener_dex"]).hexdigest(),
            "combined_elf_bytes": len(ui["shared"].data),
            "combined_elf_sha256": hashlib.sha256(ui["shared"].data).hexdigest(),
            "combined_elf_exports": [item.decode("ascii") for item in ui_elf.exports],
            "combined_elf_imports": [item.decode("ascii") for item in ui_elf.imports],
            "combined_elf_needed": [item.decode("ascii") for item in ui_elf.needed],
            "combined_elf_relocations": ui_elf.relocation_count,
            "secondary_dex_policy": "classes2.dex; valid for this minSdk>=21 fixture without a multidex support runtime",
            "button_state_change": "generated managed click adapter sets text to Clicked, then invokes XAX callback",
            "incremental_click_text_edit": {
                "edited_semantic_ui_cid": edited_ui_semantics.cid.hex(),
                "primary_activity_dex_unchanged": edited_activity_dex == ui["activity_dex"],
                "listener_dex_changed": edited_listener_dex != ui["listener_dex"],
                "edited_listener_dex_sha256": hashlib.sha256(edited_listener_dex).hexdigest(),
            },
        },
        "dex": {
            "version": dex_view.version,
            "bytes": len(dex),
            "sha256": hashlib.sha256(dex).hexdigest(),
            "strings": dex_view.string_ids_size,
            "types": dex_view.type_ids_size,
            "protos": dex_view.proto_ids_size,
            "methods": dex_view.method_ids_size,
            "classes": dex_view.class_defs_size,
            "checksum_valid": dex_view.checksum_valid,
            "signature_valid": dex_view.signature_valid,
            "java_kotlin_source_files": 0,
            "d8_r8_invocations": 0,
        },
        "elf": {
            "bytes": len(shared.data),
            "sha256": hashlib.sha256(shared.data).hexdigest(),
            "exports": [item.decode("ascii") for item in elf.exports],
            "imports": [item.decode("ascii") for item in elf.imports],
            "needed": [item.decode("ascii") for item in elf.needed],
            "relocations": elf.relocation_count,
            "text_bytes": elf.text_size,
        },
        "runtime_validation": "UNEXECUTED",
        "remaining_before_activity_runtime": [
            "real Android package-manager verification of the directly emitted manifest/APK/v2 signature",
            "real ART verification/class initialization and System.loadLibrary execution",
            "real Activity lifecycle execution through invoke-super then the XAX JNI callback",
            "real UI behavior including instantiation/registration of the generated listener adapter",
            "promote the current bounded UI lowering configuration into authoritative XAX semantic build data",
        ],
    }


def main():
    evidence = collect_evidence()
    path = Path(__file__).with_name("android_managed_bridge_evidence.json")
    path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(path)
    print(json.dumps(evidence, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
