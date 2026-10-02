from __future__ import annotations

import hashlib
import struct
import unittest
import zlib
from pathlib import Path

from benchmarks.bench_android_managed_bridge import collect_evidence

from xax_dex import (
    ACC_NATIVE,
    ACC_PRIVATE,
    ACC_PROTECTED,
    ACC_PUBLIC,
    DEX039_MAGIC,
    DexBridgeSpec,
    DexActivityUiSpec,
    DexConstantStringMethod,
    DexForwardingOverride,
    DexNativeMethod,
    DexProto,
    activity_bridge_spec,
    activity_button_bridge_spec,
    activity_button_resource_bridge_spec,
    click_resource_listener_bridge_spec,
    click_text_listener_bridge_spec,
    emit_dex039_bridge,
    inspect_dex,
    interface_callback_bridge_spec,
)


class DexTests(unittest.TestCase):
    def test_minimal_activity_bridge_is_deterministic_valid_dex039(self) -> None:
        spec = activity_bridge_spec()
        first = emit_dex039_bridge(spec)
        second = emit_dex039_bridge(spec)
        self.assertEqual(first, second)
        self.assertEqual(first[:8], DEX039_MAGIC)
        view = inspect_dex(first)
        self.assertEqual(view.version, "039")
        self.assertTrue(view.checksum_valid)
        self.assertTrue(view.signature_valid)
        self.assertEqual(view.file_size, len(first))
        self.assertEqual(view.class_defs_size, 1)
        self.assertEqual(view.method_ids_size, 7)  # super/own lifecycle + native callback + loadLibrary/bootstrap methods
        self.assertIn("xaxOnCreate", view.strings)
        self.assertIn("Lxax/generated/XaxActivity;", view.strings)
        self.assertIn("Landroid/app/Activity;", view.strings)
        self.assertIn("Landroid/os/Bundle;", view.strings)
        self.assertIn("onCreate", view.strings)

    def test_deferred_native_library_load_occurs_in_selected_callback_not_clinit(self) -> None:
        from xax_libxposed import libxposed_managed_entry_semantics, lower_libxposed_managed_entry

        data = emit_dex039_bridge(lower_libxposed_managed_entry(libxposed_managed_entry_semantics()))
        view = inspect_dex(data)
        self.assertNotIn("<clinit>", view.strings)
        self.assertIn("loadLibrary", view.strings)
        method_ids_size = struct.unpack_from("<I", data, 88)[0]
        method_ids_off = struct.unpack_from("<I", data, 92)[0]

        def method_name(index: int) -> str:
            self.assertLess(index, method_ids_size)
            name_idx = struct.unpack_from("<I", data, method_ids_off + index * 8 + 4)[0]
            return view.strings[name_idx]

        def uleb(offset: int) -> tuple[int, int]:
            result = 0
            shift = 0
            while True:
                byte = data[offset]
                offset += 1
                result |= (byte & 0x7F) << shift
                if not byte & 0x80:
                    return result, offset
                shift += 7

        class_defs_off = struct.unpack_from("<I", data, 100)[0]
        class_data_off = struct.unpack_from("<I", data, class_defs_off + 24)[0]
        offset = class_data_off
        _, offset = uleb(offset); _, offset = uleb(offset)
        direct_count, offset = uleb(offset); virtual_count, offset = uleb(offset)
        direct = {}
        previous = 0
        for position in range(direct_count):
            diff, offset = uleb(offset)
            index = diff if position == 0 else previous + diff
            flags, offset = uleb(offset); code_off, offset = uleb(offset)
            direct[method_name(index)] = (flags, code_off)
            previous = index
        virtual = {}
        previous = 0
        for position in range(virtual_count):
            diff, offset = uleb(offset)
            index = diff if position == 0 else previous + diff
            flags, offset = uleb(offset); code_off, offset = uleb(offset)
            virtual[method_name(index)] = (flags, code_off)
            previous = index
        self.assertEqual(set(direct), {"<init>", "xaxOnModuleLoaded", "xaxOnPackageReady"})
        loaded_off = virtual["onModuleLoaded"][1]
        registers, ins, outs, tries, debug, insns = struct.unpack_from("<HHHHII", data, loaded_off)
        self.assertEqual((registers, ins, outs, tries, debug, insns), (3, 2, 2, 0, 0, 9))
        loaded = struct.unpack_from("<9H", data, loaded_off + 16)
        self.assertEqual((loaded[0], loaded[2], loaded[4], loaded[5], loaded[7], loaded[8]), (0x001A, 0x1071, 0x0000, 0x2070, 0x0021, 0x000E))
        self.assertEqual(view.strings[loaded[1]], "xaxapp")
        self.assertEqual(method_name(loaded[3]), "loadLibrary")
        self.assertEqual(method_name(loaded[6]), "xaxOnModuleLoaded")

        ready_off = virtual["onPackageReady"][1]
        registers, ins, outs, tries, debug, insns = struct.unpack_from("<HHHHII", data, ready_off)
        self.assertEqual((registers, ins, outs, tries, debug, insns), (2, 2, 2, 0, 0, 4))
        ready = struct.unpack_from("<4H", data, ready_off + 16)
        self.assertEqual((ready[0], ready[2], ready[3]), (0x2070, 0x0010, 0x000E))
        self.assertEqual(method_name(ready[1]), "xaxOnPackageReady")

    def test_checksum_and_signature_cover_normative_ranges(self) -> None:
        data = emit_dex039_bridge(activity_bridge_spec())
        self.assertEqual(struct.unpack_from("<I", data, 8)[0], zlib.adler32(data[12:]) & 0xFFFFFFFF)
        self.assertEqual(data[12:32], hashlib.sha1(data[32:]).digest())

    def test_activity_lifecycle_override_calls_super_then_one_private_native_callback(self) -> None:
        data = emit_dex039_bridge(activity_bridge_spec())
        view = inspect_dex(data)
        method_ids_size = struct.unpack_from("<I", data, 88)[0]
        method_ids_off = struct.unpack_from("<I", data, 92)[0]

        def method_name(index: int) -> str:
            self.assertLess(index, method_ids_size)
            name_idx = struct.unpack_from("<I", data, method_ids_off + index * 8 + 4)[0]
            return view.strings[name_idx]

        def uleb(offset: int) -> tuple[int, int]:
            result = 0
            shift = 0
            while True:
                byte = data[offset]
                offset += 1
                result |= (byte & 0x7F) << shift
                if not byte & 0x80:
                    return result, offset
                shift += 7

        class_defs_off = struct.unpack_from("<I", data, 100)[0]
        class_data_off = struct.unpack_from("<I", data, class_defs_off + 24)[0]
        offset = class_data_off
        static_fields, offset = uleb(offset)
        instance_fields, offset = uleb(offset)
        direct_count, offset = uleb(offset)
        virtual_count, offset = uleb(offset)
        self.assertEqual((static_fields, instance_fields, direct_count, virtual_count), (0, 0, 3, 1))

        direct = {}
        previous = 0
        for position in range(direct_count):
            diff, offset = uleb(offset)
            index = diff if position == 0 else previous + diff
            flags, offset = uleb(offset)
            code_off, offset = uleb(offset)
            direct[method_name(index)] = (flags, code_off)
            previous = index
        virtual = {}
        previous = 0
        for position in range(virtual_count):
            diff, offset = uleb(offset)
            index = diff if position == 0 else previous + diff
            flags, offset = uleb(offset)
            code_off, offset = uleb(offset)
            virtual[method_name(index)] = (flags, code_off)
            previous = index

        self.assertEqual(direct["xaxOnCreate"][0], ACC_PRIVATE | ACC_NATIVE)
        self.assertEqual(direct["xaxOnCreate"][1], 0)
        self.assertEqual(virtual["onCreate"][0], ACC_PROTECTED)
        lifecycle_code_off = virtual["onCreate"][1]
        self.assertNotEqual(lifecycle_code_off, 0)

        registers, ins, outs, tries, debug, insns = struct.unpack_from("<HHHHII", data, lifecycle_code_off)
        self.assertEqual((registers, ins, outs, tries, debug, insns), (2, 2, 2, 0, 0, 7))
        units = struct.unpack_from("<7H", data, lifecycle_code_off + 16)
        self.assertEqual((units[0], units[2], units[3], units[5], units[6]), (0x206F, 0x0010, 0x2070, 0x0010, 0x000E))
        self.assertEqual(method_name(units[1]), "onCreate")
        self.assertEqual(method_name(units[4]), "xaxOnCreate")

        # Static initialization remains one loadLibrary call and no reflection/allocation.
        clinit_code_off = direct["<clinit>"][1]
        registers, ins, outs, tries, debug, insns = struct.unpack_from("<HHHHII", data, clinit_code_off)
        self.assertEqual((registers, ins, outs, tries, debug, insns), (1, 0, 1, 0, 0, 6))
        clinit = struct.unpack_from("<6H", data, clinit_code_off + 16)
        self.assertEqual((clinit[0], clinit[2], clinit[4], clinit[5]), (0x001A, 0x1071, 0x0000, 0x000E))


    def test_activity_button_ui_setup_is_exact_and_single_transition(self) -> None:
        data = emit_dex039_bridge(activity_button_bridge_spec(button_text="XAX"))
        view = inspect_dex(data)
        method_ids_size = struct.unpack_from("<I", data, 88)[0]
        method_ids_off = struct.unpack_from("<I", data, 92)[0]

        def method_name(index: int) -> str:
            self.assertLess(index, method_ids_size)
            name_idx = struct.unpack_from("<I", data, method_ids_off + index * 8 + 4)[0]
            return view.strings[name_idx]

        def uleb(offset: int) -> tuple[int, int]:
            result = 0
            shift = 0
            while True:
                byte = data[offset]
                offset += 1
                result |= (byte & 0x7F) << shift
                if not byte & 0x80:
                    return result, offset
                shift += 7

        class_defs_off = struct.unpack_from("<I", data, 100)[0]
        class_data_off = struct.unpack_from("<I", data, class_defs_off + 24)[0]
        offset = class_data_off
        _, offset = uleb(offset)
        _, offset = uleb(offset)
        direct_count, offset = uleb(offset)
        virtual_count, offset = uleb(offset)
        previous = 0
        for position in range(direct_count):
            diff, offset = uleb(offset)
            previous = diff if position == 0 else previous + diff
            _, offset = uleb(offset)
            _, offset = uleb(offset)
        virtual = {}
        previous = 0
        for position in range(virtual_count):
            diff, offset = uleb(offset)
            index = diff if position == 0 else previous + diff
            flags, offset = uleb(offset)
            code_off, offset = uleb(offset)
            virtual[method_name(index)] = (flags, code_off)
            previous = index

        code_off = virtual["onCreate"][1]
        registers, ins, outs, tries, debug, insns = struct.unpack_from("<HHHHII", data, code_off)
        self.assertEqual((registers, ins, outs, tries, debug, insns), (5, 2, 2, 0, 0, 28))
        units = struct.unpack_from("<28H", data, code_off + 16)

        # Exact bounded managed setup:
        # super.onCreate -> new Button -> Button.<init>(Activity) -> const String ->
        # setText -> new listener -> listener.<init> -> setOnClickListener ->
        # setContentView -> one private native lifecycle callback -> return.
        cursor = 0
        self.assertEqual(units[cursor] & 0xFF, 0x6F); self.assertEqual(method_name(units[cursor + 1]), "onCreate"); cursor += 3
        self.assertEqual(units[cursor] & 0xFF, 0x22); cursor += 2
        self.assertEqual(units[cursor] & 0xFF, 0x70); self.assertEqual(method_name(units[cursor + 1]), "<init>"); cursor += 3
        self.assertEqual(units[cursor] & 0xFF, 0x1A); self.assertEqual(view.strings[units[cursor + 1]], "XAX"); cursor += 2
        self.assertEqual(units[cursor] & 0xFF, 0x6E); self.assertEqual(method_name(units[cursor + 1]), "setText"); cursor += 3
        self.assertEqual(units[cursor] & 0xFF, 0x22); cursor += 2
        self.assertEqual(units[cursor] & 0xFF, 0x70); self.assertEqual(method_name(units[cursor + 1]), "<init>"); cursor += 3
        self.assertEqual(units[cursor] & 0xFF, 0x6E); self.assertEqual(method_name(units[cursor + 1]), "setOnClickListener"); cursor += 3
        self.assertEqual(units[cursor] & 0xFF, 0x6E); self.assertEqual(method_name(units[cursor + 1]), "setContentView"); cursor += 3
        self.assertEqual(units[cursor] & 0xFF, 0x70); self.assertEqual(method_name(units[cursor + 1]), "xaxOnCreate"); cursor += 3
        self.assertEqual(units[cursor], 0x000E); cursor += 1
        self.assertEqual(cursor, len(units))
        self.assertEqual(sum(1 for i, unit in enumerate(units) if unit & 0xFF == 0x22), 2)
        self.assertNotIn("Ljava/lang/reflect/Method;", view.strings)
        self.assertNotIn("java/lang/reflect", "\n".join(view.strings))

    def test_activity_method_backed_text_has_exact_string_method_and_call(self) -> None:
        from dataclasses import replace

        base = activity_button_bridge_spec(button_text="placeholder")
        spec = replace(
            base,
            activity_ui=DexActivityUiSpec(
                "Lxax/generated/XaxOnClickListener;",
                button_text_method_name="hookTarget",
            ),
            constant_string_methods=(DexConstantStringMethod("hookTarget", "Original"),),
        )
        data = emit_dex039_bridge(spec)
        view = inspect_dex(data)
        self.assertIn("hookTarget", view.strings)
        self.assertIn("Original", view.strings)
        self.assertNotIn("placeholder", view.strings)

        method_ids_size = struct.unpack_from("<I", data, 88)[0]
        method_ids_off = struct.unpack_from("<I", data, 92)[0]
        def method_name(index: int) -> str:
            self.assertLess(index, method_ids_size)
            name_idx = struct.unpack_from("<I", data, method_ids_off + index * 8 + 4)[0]
            return view.strings[name_idx]
        def uleb(offset: int) -> tuple[int, int]:
            result = 0
            shift = 0
            while True:
                byte = data[offset]
                offset += 1
                result |= (byte & 0x7F) << shift
                if not byte & 0x80:
                    return result, offset
                shift += 7

        class_defs_off = struct.unpack_from("<I", data, 100)[0]
        class_data_off = struct.unpack_from("<I", data, class_defs_off + 24)[0]
        offset = class_data_off
        _, offset = uleb(offset); _, offset = uleb(offset)
        direct_count, offset = uleb(offset); virtual_count, offset = uleb(offset)
        previous = 0
        for position in range(direct_count):
            diff, offset = uleb(offset)
            previous = diff if position == 0 else previous + diff
            _, offset = uleb(offset); _, offset = uleb(offset)
        virtual = {}
        previous = 0
        for position in range(virtual_count):
            diff, offset = uleb(offset)
            index = diff if position == 0 else previous + diff
            flags, offset = uleb(offset)
            code_off, offset = uleb(offset)
            virtual[method_name(index)] = (flags, code_off)
            previous = index

        self.assertEqual(virtual["hookTarget"][0], ACC_PUBLIC)
        hook_off = virtual["hookTarget"][1]
        registers, ins, outs, tries, debug, insns = struct.unpack_from("<HHHHII", data, hook_off)
        self.assertEqual((registers, ins, outs, tries, debug, insns), (2, 1, 0, 0, 0, 3))
        hook_units = struct.unpack_from("<3H", data, hook_off + 16)
        self.assertEqual(hook_units[0] & 0xFF, 0x1A)
        self.assertEqual(view.strings[hook_units[1]], "Original")
        self.assertEqual(hook_units[2] & 0xFF, 0x11)

        create_off = virtual["onCreate"][1]
        registers, ins, outs, tries, debug, insns = struct.unpack_from("<HHHHII", data, create_off)
        self.assertEqual((registers, ins, outs, tries, debug, insns), (5, 2, 2, 0, 0, 30))
        units = struct.unpack_from("<30H", data, create_off + 16)
        cursor = 0
        self.assertEqual(units[cursor] & 0xFF, 0x6F); cursor += 3  # super.onCreate
        self.assertEqual(units[cursor] & 0xFF, 0x22); cursor += 2  # new Button
        self.assertEqual(units[cursor] & 0xFF, 0x70); cursor += 3  # Button.<init>
        self.assertEqual(units[cursor] & 0xFF, 0x6E)
        self.assertEqual(method_name(units[cursor + 1]), "hookTarget")
        cursor += 3
        self.assertEqual(units[cursor] & 0xFF, 0x0C); cursor += 1  # move-result-object
        self.assertEqual(units[cursor] & 0xFF, 0x6E)
        self.assertEqual(method_name(units[cursor + 1]), "setText")
        cursor += 3
        self.assertEqual(units[cursor] & 0xFF, 0x22); cursor += 2
        self.assertEqual(units[cursor] & 0xFF, 0x70); cursor += 3
        self.assertEqual(units[cursor] & 0xFF, 0x6E); cursor += 3
        self.assertEqual(units[cursor] & 0xFF, 0x6E); cursor += 3
        self.assertEqual(units[cursor] & 0xFF, 0x70); cursor += 3
        self.assertEqual(units[cursor], 0x000E); cursor += 1
        self.assertEqual(cursor, len(units))

    def test_interface_callback_bridge_implements_interface_and_invokes_native_once(self) -> None:
        proto = DexProto("V", ("Landroid/view/View;",))
        spec = interface_callback_bridge_spec(
            "Lxax/generated/XaxOnClickListener;",
            "Landroid/view/View$OnClickListener;",
            "onClick",
            proto,
        )
        data = emit_dex039_bridge(spec)
        view = inspect_dex(data)
        self.assertEqual(view.class_descriptor, "Lxax/generated/XaxOnClickListener;")
        self.assertEqual(view.superclass_descriptor, "Ljava/lang/Object;")
        self.assertEqual(view.interfaces, ("Landroid/view/View$OnClickListener;",))

        method_ids_size = struct.unpack_from("<I", data, 88)[0]
        method_ids_off = struct.unpack_from("<I", data, 92)[0]
        def method_name(index: int) -> str:
            self.assertLess(index, method_ids_size)
            name_idx = struct.unpack_from("<I", data, method_ids_off + index * 8 + 4)[0]
            return view.strings[name_idx]
        def uleb(offset: int) -> tuple[int, int]:
            result = 0
            shift = 0
            while True:
                byte = data[offset]
                offset += 1
                result |= (byte & 0x7F) << shift
                if not byte & 0x80:
                    return result, offset
                shift += 7

        class_defs_off = struct.unpack_from("<I", data, 100)[0]
        class_data_off = struct.unpack_from("<I", data, class_defs_off + 24)[0]
        offset = class_data_off
        static_fields, offset = uleb(offset)
        instance_fields, offset = uleb(offset)
        direct_count, offset = uleb(offset)
        virtual_count, offset = uleb(offset)
        self.assertEqual((static_fields, instance_fields, direct_count, virtual_count), (0, 0, 3, 1))
        previous = 0
        direct = {}
        for position in range(direct_count):
            diff, offset = uleb(offset)
            index = diff if position == 0 else previous + diff
            flags, offset = uleb(offset)
            code_off, offset = uleb(offset)
            direct[method_name(index)] = (flags, code_off)
            previous = index
        previous = 0
        virtual = {}
        for position in range(virtual_count):
            diff, offset = uleb(offset)
            index = diff if position == 0 else previous + diff
            flags, offset = uleb(offset)
            code_off, offset = uleb(offset)
            virtual[method_name(index)] = (flags, code_off)
            previous = index

        self.assertEqual(direct["xaxOnClick"][0], ACC_PRIVATE | ACC_NATIVE)
        self.assertEqual(direct["xaxOnClick"][1], 0)
        self.assertEqual(virtual["onClick"][0], ACC_PUBLIC)
        code_off = virtual["onClick"][1]
        registers, ins, outs, tries, debug, insns = struct.unpack_from("<HHHHII", data, code_off)
        self.assertEqual((registers, ins, outs, tries, debug, insns), (2, 2, 2, 0, 0, 4))
        units = struct.unpack_from("<4H", data, code_off + 16)
        self.assertEqual((units[0], units[2], units[3]), (0x2070, 0x0010, 0x000E))
        self.assertEqual(method_name(units[1]), "xaxOnClick")
        # No invoke-super/new-instance/new-array/reflection instructions exist in this callback body.
        self.assertEqual(sum(1 for unit in units if unit & 0xFF in {0x6F, 0x22, 0x23}), 0)

    def test_click_text_listener_updates_view_without_allocation_then_calls_native_once(self) -> None:
        data = emit_dex039_bridge(click_text_listener_bridge_spec(text="Clicked"))
        view = inspect_dex(data)
        self.assertEqual(view.interfaces, ("Landroid/view/View$OnClickListener;",))
        self.assertIn("Clicked", view.strings)

        method_ids_size = struct.unpack_from("<I", data, 88)[0]
        method_ids_off = struct.unpack_from("<I", data, 92)[0]
        def method_name(index: int) -> str:
            self.assertLess(index, method_ids_size)
            name_idx = struct.unpack_from("<I", data, method_ids_off + index * 8 + 4)[0]
            return view.strings[name_idx]
        def uleb(offset: int) -> tuple[int, int]:
            result = 0
            shift = 0
            while True:
                byte = data[offset]
                offset += 1
                result |= (byte & 0x7F) << shift
                if not byte & 0x80:
                    return result, offset
                shift += 7

        class_defs_off = struct.unpack_from("<I", data, 100)[0]
        class_data_off = struct.unpack_from("<I", data, class_defs_off + 24)[0]
        offset = class_data_off
        _, offset = uleb(offset); _, offset = uleb(offset)
        direct_count, offset = uleb(offset); virtual_count, offset = uleb(offset)
        previous = 0
        for position in range(direct_count):
            diff, offset = uleb(offset)
            previous = diff if position == 0 else previous + diff
            _, offset = uleb(offset); _, offset = uleb(offset)
        previous = 0
        code_off = None
        for position in range(virtual_count):
            diff, offset = uleb(offset)
            index = diff if position == 0 else previous + diff
            _, offset = uleb(offset)
            candidate, offset = uleb(offset)
            if method_name(index) == "onClick":
                code_off = candidate
            previous = index
        self.assertIsNotNone(code_off)
        registers, ins, outs, tries, debug, insns = struct.unpack_from("<HHHHII", data, code_off)
        self.assertEqual((registers, ins, outs, tries, debug, insns), (3, 2, 2, 0, 0, 11))
        units = struct.unpack_from("<11H", data, code_off + 16)
        self.assertEqual(units[0] & 0xFF, 0x1F)  # check-cast
        self.assertEqual(units[2] & 0xFF, 0x1A)  # const-string
        self.assertEqual(view.strings[units[3]], "Clicked")
        self.assertEqual(units[4] & 0xFF, 0x6E)  # invoke-virtual setText
        self.assertEqual(method_name(units[5]), "setText")
        self.assertEqual(units[7] & 0xFF, 0x70)  # invoke-direct native
        self.assertEqual(method_name(units[8]), "xaxOnClick")
        self.assertEqual(units[10], 0x000E)
        self.assertEqual(sum(1 for unit in units if unit & 0xFF in {0x22, 0x23}), 0)

    def test_resource_backed_ui_uses_const_resource_ids_not_inline_strings(self) -> None:
        activity = emit_dex039_bridge(activity_button_resource_bridge_spec(button_text_resource_id=0x7F010000))
        listener = emit_dex039_bridge(click_resource_listener_bridge_spec(text_resource_id=0x7F010001))
        self.assertNotIn("XAX", inspect_dex(activity).strings)
        self.assertNotIn("Clicked", inspect_dex(listener).strings)
        self.assertIn("I", inspect_dex(activity).strings)
        self.assertIn("I", inspect_dex(listener).strings)

        # The exact resource IDs occur as DEX const/31i immediates. There is no
        # const-string for the resource value and no allocation in the click body.
        self.assertIn(struct.pack("<HHH", 0x0114, 0x0000, 0x7F01), activity)
        self.assertIn(struct.pack("<HHH", 0x0014, 0x0001, 0x7F01), listener)

    def test_interface_order_and_duplicates_canonicalize(self) -> None:
        proto = DexProto("V", ())
        native = DexNativeMethod("xaxRun", proto, ACC_PRIVATE | ACC_NATIVE)
        forward = DexForwardingOverride("run", proto, "xaxRun", ACC_PUBLIC, False)
        left = DexBridgeSpec(
            "Lxax/generated/Callbacks;",
            "Ljava/lang/Object;",
            (native,),
            (forward,),
            ("Ljava/lang/Runnable;", "Lxax/api/Marker;", "Ljava/lang/Runnable;"),
        )
        right = DexBridgeSpec(
            "Lxax/generated/Callbacks;",
            "Ljava/lang/Object;",
            (native,),
            (forward,),
            ("Lxax/api/Marker;", "Ljava/lang/Runnable;"),
        )
        self.assertEqual(left.interfaces, ("Ljava/lang/Runnable;", "Lxax/api/Marker;"))
        self.assertEqual(emit_dex039_bridge(left), emit_dex039_bridge(right))

    def test_method_order_is_canonical_regardless_of_input_order(self) -> None:
        a = DexNativeMethod("beta", DexProto("I", ("I",)))
        b = DexNativeMethod("alpha", DexProto("V", ()))
        left = DexBridgeSpec("Lxax/generated/B;", "Ljava/lang/Object;", (a, b))
        right = DexBridgeSpec("Lxax/generated/B;", "Ljava/lang/Object;", (b, a))
        self.assertEqual(emit_dex039_bridge(left), emit_dex039_bridge(right))

    def test_invalid_descriptors_and_duplicate_methods_are_rejected(self) -> None:
        with self.assertRaises(ValueError):
            DexBridgeSpec("xax.Bad", "Ljava/lang/Object;")
        with self.assertRaises(ValueError):
            DexProto("V", ("V",))
        method = DexNativeMethod("f")
        with self.assertRaises(ValueError):
            DexBridgeSpec("Lxax/generated/B;", "Ljava/lang/Object;", (method, method))

    def test_managed_bridge_evidence_reproduces(self) -> None:
        committed = Path(__file__).parents[1] / "benchmarks" / "android_managed_bridge_evidence.json"
        import json
        self.assertEqual(json.loads(committed.read_text(encoding="utf-8")), collect_evidence())
        evidence = collect_evidence()
        self.assertEqual(evidence["bridge"]["jni_symbol"], evidence["elf"]["exports"][0])
        self.assertEqual(evidence["interface_callback_bridge"]["jni_symbol"], evidence["interface_callback_bridge"]["elf_exports"][0])
        self.assertEqual(evidence["interface_callback_bridge"]["interfaces"], ["Landroid/view/View$OnClickListener;"])
        self.assertEqual(evidence["interface_callback_bridge"]["dex_code_units"], 4)
        self.assertEqual(evidence["interface_callback_bridge"]["per_callback_allocations_emitted"], 0)
        self.assertEqual(evidence["dex"]["java_kotlin_source_files"], 0)
        self.assertEqual(evidence["dex"]["d8_r8_invocations"], 0)
        self.assertEqual(evidence["runtime_validation"], "UNEXECUTED")


    def test_inspector_rejects_corruption(self) -> None:
        data = bytearray(emit_dex039_bridge(activity_bridge_spec()))
        data[40:44] = b"\x00\x00\x00\x00"
        with self.assertRaisesRegex(ValueError, "endian"):
            inspect_dex(bytes(data))


if __name__ == "__main__":
    unittest.main()
