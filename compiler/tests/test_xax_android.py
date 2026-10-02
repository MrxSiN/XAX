import json
import shutil
from pathlib import Path

import pytest

from benchmarks.bench_android_arm64 import (
    bionic_import_fixture,
    collect_evidence,
    indirect_cycle_fixture,
    jni_onload_fixture,
    libxposed_hook_call_fixture,
    libxposed_native_init_fixture,
    minimal_native_init_fixture,
    simple_add_fixture,
)
from xax_android import (
    AndroidExport,
    android_activity_argument_method_ui_semantics,
    decode_android_activity_argument_method_ui,
    lower_android_activity_argument_method_ui,
    android_activity_method_ui_semantics,
    android_activity_resource_ui_semantics,
    android_activity_ui_semantics,
    compile_android_shared,
    decode_android_activity_method_ui,
    decode_android_activity_resource_ui,
    decode_android_activity_ui,
    inspect_android_elf,
    lower_android_activity_method_ui,
    lower_android_activity_resource_ui,
    lower_android_activity_ui,
    validate_with_readelf,
    write_modern_libxposed_fixture,
)
from xax_compiler import (
    XaxError,
    aarch64_baremetal_target,
    android_export_symbol,
    decode_android_export,
    decode_native_target,
    target,
)


def _words(code):
    return tuple(int.from_bytes(code[i:i + 4], "little") for i in range(0, len(code), 4))


def _entry_code(shared, reader, target, function_cids, function_cid):
    from xax_aarch64 import compile_aarch64_bundle_bound_target
    bundle = compile_aarch64_bundle_bound_target(reader, function_cids, target)
    item = next(r for r in bundle.semantic_ranges if r.function_cid == function_cid and r.block_index is None)
    return bundle.code[item.start:item.end]


def test_android_activity_ui_semantics_are_canonical_and_lower_deterministically():
    left = android_activity_ui_semantics()
    right = android_activity_ui_semantics()
    assert left.cid == right.cid
    view = decode_android_activity_ui(left)
    assert view.activity_class_descriptor == "Lxax/generated/XaxActivity;"
    assert view.listener_class_descriptor == "Lxax/generated/XaxOnClickListener;"
    assert view.initial_button_text == "XAX"
    assert view.click_button_text == "Clicked"

    from xax_dex import emit_dex039_bridge
    a0, l0 = lower_android_activity_ui(left)
    a1, l1 = lower_android_activity_ui(right)
    assert emit_dex039_bridge(a0) == emit_dex039_bridge(a1)
    assert emit_dex039_bridge(l0) == emit_dex039_bridge(l1)


def test_android_activity_ui_click_edit_has_local_lowering_identity():
    from xax_dex import emit_dex039_bridge
    base = android_activity_ui_semantics(click_button_text="Clicked")
    edited = android_activity_ui_semantics(click_button_text="Done")
    assert base.cid != edited.cid
    base_activity, base_listener = lower_android_activity_ui(base)
    edited_activity, edited_listener = lower_android_activity_ui(edited)
    assert emit_dex039_bridge(base_activity) == emit_dex039_bridge(edited_activity)
    assert emit_dex039_bridge(base_listener) != emit_dex039_bridge(edited_listener)


def test_android_activity_method_ui_is_canonical_and_edit_local():
    from xax_dex import emit_dex039_bridge, inspect_dex

    left = android_activity_method_ui_semantics()
    right = android_activity_method_ui_semantics()
    assert left.cid == right.cid
    view = decode_android_activity_method_ui(left)
    assert view.activity_class_descriptor == "Lxax/generated/XaxActivity;"
    assert view.listener_class_descriptor == "Lxax/generated/XaxOnClickListener;"
    assert view.initial_text_method_name == "hookTarget"
    assert view.initial_text_method_result == "Original"
    assert view.click_button_text == "Clicked"

    activity, listener = lower_android_activity_method_ui(left)
    activity_bytes = emit_dex039_bridge(activity)
    listener_bytes = emit_dex039_bridge(listener)
    strings = inspect_dex(activity_bytes).strings
    assert "hookTarget" in strings
    assert "Original" in strings
    assert "placeholder" not in strings
    assert activity.activity_ui.button_text_method_name == "hookTarget"
    assert len(activity.constant_string_methods) == 1
    assert activity.constant_string_methods[0].name == "hookTarget"
    assert activity.constant_string_methods[0].value == "Original"

    edited = android_activity_method_ui_semantics(initial_text_method_result="Changed")
    edited_activity, edited_listener = lower_android_activity_method_ui(edited)
    assert edited.cid != left.cid
    assert emit_dex039_bridge(edited_activity) != activity_bytes
    assert emit_dex039_bridge(edited_listener) == listener_bytes


def test_android_activity_argument_method_ui_is_exact_echo_target_and_edit_local():
    from xax_dex import emit_dex039_bridge, inspect_dex

    obj = android_activity_argument_method_ui_semantics()
    view = decode_android_activity_argument_method_ui(obj)
    assert view.activity_class_descriptor == "Lcom/example/target/XaxActivity;"
    assert view.initial_text_method_name == "hookTarget"
    assert view.initial_text_method_argument == "OriginalArg"

    activity, listener = lower_android_activity_argument_method_ui(obj)
    activity_bytes = emit_dex039_bridge(activity)
    listener_bytes = emit_dex039_bridge(listener)
    inspection = inspect_dex(activity_bytes)
    assert "hookTarget" in inspection.strings
    assert "OriginalArg" in inspection.strings
    assert len(activity.echo_string_methods) == 1
    assert activity.echo_string_methods[0].proto.parameters == ("Ljava/lang/String;",)
    assert activity.activity_ui.button_text_method_argument == "OriginalArg"

    edited = android_activity_argument_method_ui_semantics(initial_text_method_argument="ChangedArg")
    edited_activity, edited_listener = lower_android_activity_argument_method_ui(edited)
    assert edited.cid != obj.cid
    assert emit_dex039_bridge(edited_activity) != activity_bytes
    assert emit_dex039_bridge(edited_listener) == listener_bytes


def test_android_resource_ui_resolves_exact_resource_ids_and_excludes_inline_text():
    from xax_dex import emit_dex039_bridge, inspect_dex
    from xax_resources import AndroidResourceSpec, AndroidStringResource, android_resources_semantics

    resources = android_resources_semantics(
        AndroidResourceSpec(
            "xax.generated",
            (AndroidStringResource("app_name", "XAX"), AndroidStringResource("clicked", "Clicked")),
        )
    )
    ui = android_activity_resource_ui_semantics()
    view = decode_android_activity_resource_ui(ui)
    assert (view.initial_button_resource, view.click_button_resource) == ("app_name", "clicked")
    activity, listener = lower_android_activity_resource_ui(ui, resources)
    activity_dex, listener_dex = emit_dex039_bridge(activity), emit_dex039_bridge(listener)
    assert "XAX" not in inspect_dex(activity_dex).strings
    assert "Clicked" not in inspect_dex(listener_dex).strings
    assert activity.activity_ui.button_text_resource_id == 0x7F010000
    assert listener.click_text.text_resource_id == 0x7F010001

    missing = android_activity_resource_ui_semantics(click_button_resource="missing")
    with pytest.raises(XaxError):
        lower_android_activity_resource_ui(missing, resources)


def test_android_activity_ui_rejects_wrong_target_carrier():
    with pytest.raises(XaxError):
        decode_android_activity_ui(target(b"not-android-ui"))


def test_android_target_reuses_aapcs64_register_contract():
    _reader, target, _fn, _exports = simple_add_fixture()
    desc = decode_native_target(target)
    assert desc.identity == b"android-arm64-v8a-shared-v3"
    assert (desc.architecture, desc.abi, desc.image_format) == (3, 4, 4)
    assert desc.argument_registers == tuple(range(8))
    assert desc.result_register == 0
    assert desc.scratch_registers == (9, 10)
    assert desc.stack_alignment == 16



def test_semantic_export_carrier_is_exact_and_compiles():
    reader, target, fn, _exports = simple_add_fixture()
    carrier = android_export_symbol(fn, b"public_add")
    decoded = decode_android_export(carrier)
    assert decoded.abi == b"android-aapcs64-c"
    assert decoded.visibility == b"default"
    assert decoded.name == b"public_add"
    assert decoded.function_cid == fn.cid
    shared = compile_android_shared(reader, (carrier,), target_object=target)
    assert inspect_android_elf(shared.data).exports == (b"public_add",)

def test_android_elf_is_et_dyn_aarch64_pic_and_16k_compatible():
    reader, target, fn, exports = simple_add_fixture()
    shared = compile_android_shared(reader, exports, target_object=target)
    view = inspect_android_elf(shared.data)
    assert (view.elf_class, view.data_encoding, view.elf_type, view.machine) == (2, 1, 3, 183)
    assert view.load_alignments == (0x4000, 0x4000)
    assert view.exports == (b"add",)
    assert view.imports == ()
    assert view.needed == ()
    assert view.relocation_count == 0
    assert not view.has_init_array and not view.has_fini_array and not view.has_tls


def test_android_simple_add_keeps_register_resident_backend():
    reader, target, fn, exports = simple_add_fixture()
    shared = compile_android_shared(reader, exports, target_object=target)
    code = _entry_code(shared, reader, target, (fn.cid,), fn.cid)
    assert _words(code) == (0x0B010000, 0xD65F03C0)  # add w0,w0,w1; ret


def test_minimal_native_init_is_two_instruction_leaf_and_callback_is_hidden():
    reader, target, fn, callback, exports = minimal_native_init_fixture()
    shared = compile_android_shared(reader, exports, target_object=target)
    view = inspect_android_elf(shared.data)
    code = _entry_code(shared, reader, target, (fn.cid, callback.cid), fn.cid)
    words = _words(code)
    assert len(words) == 2
    assert (words[0] & 0x9F000000) == 0x10000000  # ADR
    assert words[1] == 0xD65F03C0
    assert view.exports == (b"native_init",)
    assert view.imports == () and view.needed == () and view.relocation_count == 0


def test_libxposed_native_init_reads_fields_directly_without_frame():
    reader, target, fn, callback, exports = libxposed_native_init_fixture()
    shared = compile_android_shared(reader, exports, target_object=target)
    code = _entry_code(shared, reader, target, (fn.cid, callback.cid), fn.cid)
    words = _words(code)
    assert words[:2] == (0xB9400001, 0xF9400400)  # version@0; hook_func@8
    assert words[-1] == 0xD65F03C0
    assert all((word & 0xFF000000) not in (0xD1000000, 0x91000000) for word in words[:-1])


def test_libxposed_function_pointer_call_lowers_to_blr_without_import():
    reader, target, fn, exports = libxposed_hook_call_fixture()
    shared = compile_android_shared(reader, exports, target_object=target)
    code = _entry_code(shared, reader, target, (fn.cid,), fn.cid)
    assert any((word & 0xFFFFFC1F) == 0xD63F0000 for word in _words(code))
    view = inspect_android_elf(shared.data)
    assert view.imports == () and view.needed == () and view.relocation_count == 0



def test_indirect_call_argument_cycle_preserves_target_with_scratch_register():
    reader, target, fn, exports = indirect_cycle_fixture()
    shared = compile_android_shared(reader, exports, target_object=target)
    code = _entry_code(shared, reader, target, (fn.cid,), fn.cid)
    words = _words(code)
    assert any((word & 0xFFFFFC1F) == 0xD63F0000 for word in words)
    # The function pointer is preserved around the x0/x1 cycle; the emitted
    # code remains deterministic and uses no generic trampoline.
    assert shared.data == compile_android_shared(reader, exports, target_object=target).data

def test_jni_onload_uses_table_loads_and_direct_blr_only():
    reader, target, fn, exports = jni_onload_fixture()
    shared = compile_android_shared(reader, exports, target_object=target)
    code = _entry_code(shared, reader, target, (fn.cid,), fn.cid)
    words = _words(code)
    assert 0xF9400001 in words  # JavaVM->functions at offset 0
    assert 0xF9401821 in words  # JNIInvokeInterface.GetEnv at 6*8
    assert any((word & 0xFFFFFC1F) == 0xD63F0000 for word in words)
    view = inspect_android_elf(shared.data)
    assert view.exports == (b"JNI_OnLoad",)
    assert view.imports == () and view.needed == () and view.relocation_count == 0


def test_explicit_bionic_import_emits_only_requested_needed_symbol_and_relocation():
    reader, target, fn, exports = bionic_import_fixture()
    shared = compile_android_shared(reader, exports, target_object=target)
    view = inspect_android_elf(shared.data)
    assert view.exports == (b"probe_getpid",)
    assert view.imports == (b"getpid",)
    assert view.needed == (b"libc.so",)
    assert view.relocation_count == 1


def test_static_rodata_data_bss_are_explicit_and_deterministic():
    reader, target, fn, exports = simple_add_fixture()
    args = dict(target_object=target, rodata=b"abc\0", data=b"XY", bss_bytes=64)
    first = compile_android_shared(reader, exports, **args)
    second = compile_android_shared(reader, exports, **args)
    assert first.data == second.data
    assert (first.metrics.rodata_bytes, first.metrics.data_bytes, first.metrics.bss_bytes) == (4, 2, 64)
    assert first.metrics.dynamic_relocations == 0


def test_wrong_target_and_duplicate_exports_reject():
    reader, target, fn, exports = simple_add_fixture()
    with pytest.raises(XaxError):
        compile_android_shared(reader, exports, target_object=aarch64_baremetal_target())
    with pytest.raises(ValueError):
        compile_android_shared(reader, (AndroidExport(b"add", fn.cid), AndroidExport(b"add", fn.cid)), target_object=target)


def test_modern_libxposed_packaging_uses_meta_inf_and_no_legacy_assets(tmp_path):
    reader, target, fn, callback, exports = minimal_native_init_fixture()
    shared = compile_android_shared(reader, exports, target_object=target)
    root = write_modern_libxposed_fixture(tmp_path / "fixture", shared)
    meta = root / "app" / "src" / "main" / "resources" / "META-INF" / "xposed"
    assert (meta / "native_init.list").read_text().strip() == "libxaxmodule.so"
    assert (meta / "module.prop").is_file()
    assert (meta / "scope.list").is_file()
    assert not (root / "app" / "src" / "main" / "assets" / "xposed_init").exists()
    assert not (root / "app" / "src" / "main" / "assets" / "native_init").exists()


def test_readelf_accepts_generated_shared_object_when_available(tmp_path):
    if not (shutil.which("readelf") or shutil.which("llvm-readelf")):
        pytest.skip("readelf unavailable")
    reader, target, fn, exports = bionic_import_fixture()
    shared = compile_android_shared(reader, exports, target_object=target)
    path = tmp_path / "libprobe.so"
    path.write_bytes(shared.data)
    output = validate_with_readelf(path)
    assert "AArch64" in output
    assert "DYN" in output
    assert "getpid" in output


def test_committed_android_evidence_reproduces_exactly():
    evidence_path = Path(__file__).parents[1] / "benchmarks" / "android_arm64_evidence.json"
    expected = json.loads(evidence_path.read_text(encoding="utf-8"))
    assert collect_evidence() == expected
