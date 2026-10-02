from __future__ import annotations

import unittest
import struct

from xax_dex import emit_dex039_bridge, inspect_dex
from xax_libxposed import (
    LIBXPOSED_HOOKER,
    LIBXPOSED_MODULE_LOADED_PARAM,
    LIBXPOSED_PACKAGE_READY_PARAM,
    LIBXPOSED_XPOSED_MODULE,
    LibxposedManagedEntryDescription,
    LibxposedHookAdapterDescription,
    LibxposedHookArgumentDescription,
    LibxposedHookCombinedDescription,
    LibxposedDeoptimizationDescription,
    LibxposedModuleServicesDescription,
    LibxposedRemotePreferencesDescription,
    LibxposedRemoteFilesDescription,
    LibxposedHotReloadDescription,
    LibxposedHookInstallationDescription,
    LibxposedHookResultDescription,
    LibxposedModuleDescription,
    decode_libxposed_managed_entry,
    decode_libxposed_hook_adapter,
    decode_libxposed_hook_argument,
    decode_libxposed_hook_combined,
    decode_libxposed_deoptimization,
    decode_libxposed_module_services,
    decode_libxposed_remote_preferences,
    decode_libxposed_remote_files,
    decode_libxposed_hot_reload,
    decode_libxposed_hook_installation,
    decode_libxposed_hook_result,
    decode_libxposed_module,
    emit_libxposed_metadata,
    libxposed_managed_entry_semantics,
    libxposed_hook_adapter_semantics,
    libxposed_hook_argument_semantics,
    libxposed_hook_combined_semantics,
    libxposed_deoptimization_semantics,
    libxposed_module_services_semantics,
    libxposed_remote_preferences_semantics,
    libxposed_remote_files_semantics,
    libxposed_hot_reload_semantics,
    libxposed_hook_installation_semantics,
    libxposed_hook_result_semantics,
    libxposed_module_semantics,
    lower_libxposed_managed_entry,
    lower_libxposed_hook_adapter,
)


class LibxposedMetadataTests(unittest.TestCase):
    def test_canonical_identity_and_metadata_emission(self):
        first = libxposed_module_semantics(
            LibxposedModuleDescription(
                min_api_version=101,
                target_api_version=102,
                static_scope=True,
                native_entries=("libxaxapp.so", "libxaxapp.so"),
                scopes=("com.example.z", "com.example.a", "com.example.z"),
            )
        )
        second = libxposed_module_semantics(
            LibxposedModuleDescription(
                min_api_version=101,
                target_api_version=102,
                static_scope=True,
                native_entries=("libxaxapp.so",),
                scopes=("com.example.a", "com.example.z"),
            )
        )
        self.assertEqual(first.cid, second.cid)
        view = decode_libxposed_module(first)
        self.assertEqual(view.native_entries, ("libxaxapp.so",))
        self.assertEqual(view.scopes, ("com.example.a", "com.example.z"))
        self.assertEqual(
            emit_libxposed_metadata(first),
            {
                "META-INF/xposed/module.prop": b"minApiVersion=101\ntargetApiVersion=102\nstaticScope=true\n",
                "META-INF/xposed/native_init.list": b"libxaxapp.so\n",
                "META-INF/xposed/scope.list": b"com.example.a\ncom.example.z\n",
            },
        )

        changed = libxposed_module_semantics(
            LibxposedModuleDescription(
                min_api_version=101,
                target_api_version=103,
                static_scope=True,
                native_entries=("libxaxapp.so",),
                scopes=("com.example.a", "com.example.z"),
            )
        )
        self.assertNotEqual(first.cid, changed.cid)

    def test_java_entry_is_canonical_data_even_before_build_support(self):
        obj = libxposed_module_semantics(
            LibxposedModuleDescription(
                java_entries=("xax.generated.XaxModule",),
                scopes=("com.example.target",),
            )
        )
        self.assertEqual(
            emit_libxposed_metadata(obj)["META-INF/xposed/java_init.list"],
            b"xax.generated.XaxModule\n",
        )

    def test_managed_entry_identity_and_bounded_api102_lifecycle_lowering(self):
        first = libxposed_managed_entry_semantics(
            LibxposedManagedEntryDescription(callbacks=("onPackageReady", "onModuleLoaded", "onPackageReady"))
        )
        second = libxposed_managed_entry_semantics(
            LibxposedManagedEntryDescription(callbacks=("onModuleLoaded", "onPackageReady"))
        )
        self.assertEqual(first.cid, second.cid)
        view = decode_libxposed_managed_entry(first)
        self.assertEqual(view.java_class_name, "xax.generated.XaxModule")
        spec = lower_libxposed_managed_entry(first)
        self.assertEqual(spec.superclass_descriptor, LIBXPOSED_XPOSED_MODULE)
        self.assertEqual(spec.native_library, "xaxapp")
        self.assertEqual(spec.native_library_load_override, "onModuleLoaded")
        self.assertEqual(
            tuple((item.name, item.proto.parameters) for item in spec.forwarding_overrides),
            (
                ("onModuleLoaded", (LIBXPOSED_MODULE_LOADED_PARAM,)),
                ("onPackageReady", (LIBXPOSED_PACKAGE_READY_PARAM,)),
            ),
        )
        # The lifecycle callbacks are direct generated adapters, not superclass calls.
        self.assertTrue(all(not item.call_super for item in spec.forwarding_overrides))

        with self.assertRaises(ValueError):
            LibxposedManagedEntryDescription(callbacks=("onPackageReady",))
        with self.assertRaises(ValueError):
            LibxposedManagedEntryDescription(java_class_name="bad/name")

    def test_invalid_metadata_rejects(self):
        for kwargs in (
            {"min_api_version": 103, "target_api_version": 102, "native_entries": ("libxaxapp.so",)},
            {"native_entries": ("lib/arm64-v8a/libxaxapp.so",)},
            {"native_entries": ()},
            {"native_entries": ("libxaxapp.so\nother",)},
        ):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(ValueError):
                    LibxposedModuleDescription(**kwargs)

    def test_hook_adapter_identity_and_exact_pass_through_chain_shape(self):
        first = libxposed_hook_adapter_semantics(LibxposedHookAdapterDescription(inspected_argument_index=0))
        second = libxposed_hook_adapter_semantics(LibxposedHookAdapterDescription(inspected_argument_index=0))
        changed = libxposed_hook_adapter_semantics(LibxposedHookAdapterDescription(inspected_argument_index=1))
        self.assertEqual(first.cid, second.cid)
        self.assertNotEqual(first.cid, changed.cid)
        self.assertEqual(decode_libxposed_hook_adapter(first).inspected_argument_index, 0)

        spec = lower_libxposed_hook_adapter(first)
        self.assertEqual(spec.superclass_descriptor, "Ljava/lang/Object;")
        self.assertEqual(spec.interfaces, (LIBXPOSED_HOOKER,))
        self.assertIsNotNone(spec.libxposed_hook_intercept)
        data = emit_dex039_bridge(spec)
        view = inspect_dex(data)
        self.assertEqual(view.interfaces, (LIBXPOSED_HOOKER,))
        self.assertEqual(len(data), 744)

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

        method_ids_off = struct.unpack_from("<I", data, 92)[0]
        class_defs_off = struct.unpack_from("<I", data, 100)[0]
        class_data_off = struct.unpack_from("<I", data, class_defs_off + 24)[0]

        def method_name(index: int) -> str:
            name_idx = struct.unpack_from("<I", data, method_ids_off + index * 8 + 4)[0]
            return view.strings[name_idx]

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
            _, offset = uleb(offset)
            code_off, offset = uleb(offset)
            virtual[method_name(index)] = code_off
            previous = index
        self.assertEqual(tuple(virtual), ("intercept",))
        code_off = virtual["intercept"]
        registers, ins, outs, tries, debug, insns = struct.unpack_from("<HHHHII", data, code_off)
        self.assertEqual((registers, ins, outs, tries, debug, insns), (4, 2, 2, 0, 0, 10))
        units = struct.unpack_from("<10H", data, code_off + 16)
        self.assertEqual(tuple(unit & 0xFF for unit in units), (0x12, 0x72, units[2] & 0xFF, 0x03, 0x0C, 0x72, units[6] & 0xFF, 0x03, 0x0C, 0x11))
        # More direct opcode positions: getArg once, proceed once, no new-instance.
        self.assertEqual(sum(1 for unit in units if (unit & 0xFF) == 0x72), 2)
        self.assertNotIn(0x22, tuple(unit & 0xFF for unit in units))

        with self.assertRaises(ValueError):
            LibxposedHookAdapterDescription(inspected_argument_index=8)

    def test_hook_adapter_can_be_pure_proceed_for_zero_argument_target(self):
        obj = libxposed_hook_adapter_semantics(
            LibxposedHookAdapterDescription(inspected_argument_index=None)
        )
        self.assertIsNone(decode_libxposed_hook_adapter(obj).inspected_argument_index)
        data = emit_dex039_bridge(lower_libxposed_hook_adapter(obj))
        view = inspect_dex(data)
        self.assertIn("proceed", view.strings)
        self.assertNotIn("getArg", view.strings)
        self.assertEqual(len(data), 672)

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

        method_ids_off = struct.unpack_from("<I", data, 92)[0]
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
            _, offset = uleb(offset)
            code_off, offset = uleb(offset)
            name_idx = struct.unpack_from("<I", data, method_ids_off + index * 8 + 4)[0]
            virtual[view.strings[name_idx]] = code_off
            previous = index
        self.assertEqual(tuple(virtual), ("intercept",))
        code_off = virtual["intercept"]
        registers, ins, outs, tries, debug, insns = struct.unpack_from("<HHHHII", data, code_off)
        self.assertEqual((registers, ins, outs, tries, debug, insns), (3, 2, 1, 0, 0, 5))
        units = struct.unpack_from("<5H", data, code_off + 16)
        self.assertEqual(tuple(unit & 0xFF for unit in units), (0x72, units[1] & 0xFF, 0x02, 0x0C, 0x11))
        self.assertEqual(sum(1 for unit in units if (unit & 0xFF) == 0x72), 1)
        self.assertNotIn(0x22, tuple(unit & 0xFF for unit in units))

    def test_hook_result_replacement_is_separate_canonical_policy_and_exact_hot_shape(self):
        adapter = libxposed_hook_adapter_semantics(
            LibxposedHookAdapterDescription(inspected_argument_index=None)
        )
        first = libxposed_hook_result_semantics(
            LibxposedHookResultDescription(replacement_string="Hooked")
        )
        second = libxposed_hook_result_semantics(
            LibxposedHookResultDescription(replacement_string="Hooked")
        )
        changed = libxposed_hook_result_semantics(
            LibxposedHookResultDescription(replacement_string="Changed")
        )
        self.assertEqual(first.cid, second.cid)
        self.assertNotEqual(first.cid, changed.cid)
        policy = decode_libxposed_hook_result(first)
        self.assertEqual(policy.expected_return_descriptor, "Ljava/lang/String;")
        self.assertEqual(policy.mode, "replace_after_proceed")
        self.assertEqual(policy.replacement_string, "Hooked")

        # Existing adapter identity is unchanged; only lowering is extended by
        # the separate result-policy carrier.
        pass_through = emit_dex039_bridge(lower_libxposed_hook_adapter(adapter))
        data = emit_dex039_bridge(lower_libxposed_hook_adapter(adapter, first))
        self.assertNotEqual(data, pass_through)
        view = inspect_dex(data)
        self.assertIn("Hooked", view.strings)
        self.assertNotIn("getArg", view.strings)

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

        method_ids_off = struct.unpack_from("<I", data, 92)[0]
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
        code_off = None
        previous = 0
        for position in range(virtual_count):
            diff, offset = uleb(offset)
            index = diff if position == 0 else previous + diff
            _, offset = uleb(offset)
            candidate, offset = uleb(offset)
            name_idx = struct.unpack_from("<I", data, method_ids_off + index * 8 + 4)[0]
            if view.strings[name_idx] == "intercept":
                code_off = candidate
            previous = index
        self.assertIsNotNone(code_off)
        registers, ins, outs, tries, debug, insns = struct.unpack_from("<HHHHII", data, code_off)
        self.assertEqual((registers, ins, outs, tries, debug, insns), (4, 2, 1, 0, 0, 7))
        units = struct.unpack_from("<7H", data, code_off + 16)
        self.assertEqual(units[0] & 0xFF, 0x72)       # Chain.proceed
        self.assertEqual(units[3] & 0xFF, 0x0C)       # capture original Object
        self.assertEqual(units[4] & 0xFF, 0x1A)       # const-string replacement
        self.assertEqual(view.strings[units[5]], "Hooked")
        self.assertEqual(units[6] & 0xFF, 0x11)       # return-object replacement
        self.assertEqual(sum(1 for unit in units if (unit & 0xFF) == 0x72), 1)
        self.assertNotIn(0x22, tuple(unit & 0xFF for unit in units))

        with self.assertRaises(ValueError):
            LibxposedHookResultDescription(expected_return_descriptor="Ljava/lang/Object;")
        with self.assertRaises(ValueError):
            lower_libxposed_hook_adapter(
                libxposed_hook_adapter_semantics(LibxposedHookAdapterDescription(inspected_argument_index=0)), first
            )

    def test_hook_argument_replacement_is_explicit_one_array_allocation(self):
        adapter = libxposed_hook_adapter_semantics(
            LibxposedHookAdapterDescription(inspected_argument_index=0)
        )
        first = libxposed_hook_argument_semantics(
            LibxposedHookArgumentDescription(replacement_string="HookedArg")
        )
        second = libxposed_hook_argument_semantics(
            LibxposedHookArgumentDescription(replacement_string="HookedArg")
        )
        changed = libxposed_hook_argument_semantics(
            LibxposedHookArgumentDescription(replacement_string="ChangedArg")
        )
        self.assertEqual(first.cid, second.cid)
        self.assertNotEqual(first.cid, changed.cid)
        policy = decode_libxposed_hook_argument(first)
        self.assertEqual(policy.argument_index, 0)
        self.assertEqual(policy.expected_parameter_descriptor, "Ljava/lang/String;")
        self.assertEqual(policy.expected_return_descriptor, "Ljava/lang/String;")

        data = emit_dex039_bridge(lower_libxposed_hook_adapter(adapter, argument_policy=first))
        view = inspect_dex(data)
        self.assertIn("HookedArg", view.strings)
        self.assertIn("[Ljava/lang/Object;", view.strings)
        self.assertIn("getArg", view.strings)

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

        method_ids_off = struct.unpack_from("<I", data, 92)[0]
        class_defs_off = struct.unpack_from("<I", data, 100)[0]
        class_data_off = struct.unpack_from("<I", data, class_defs_off + 24)[0]
        offset = class_data_off
        _, offset = uleb(offset); _, offset = uleb(offset)
        direct_count, offset = uleb(offset); virtual_count, offset = uleb(offset)
        for _ in range(direct_count):
            _, offset = uleb(offset); _, offset = uleb(offset); _, offset = uleb(offset)
        previous = 0
        code_off = None
        for position in range(virtual_count):
            diff, offset = uleb(offset)
            index = diff if position == 0 else previous + diff
            _, offset = uleb(offset)
            candidate, offset = uleb(offset)
            name_idx = struct.unpack_from("<I", data, method_ids_off + index * 8 + 4)[0]
            if view.strings[name_idx] == "intercept":
                code_off = candidate
            previous = index
        self.assertIsNotNone(code_off)
        registers, ins, outs, tries, debug, insns = struct.unpack_from("<HHHHII", data, code_off)
        self.assertEqual((registers, ins, outs, tries, debug), (7, 2, 2, 0, 0))
        units = struct.unpack_from(f"<{insns}H", data, code_off + 16)
        opcodes = tuple(unit & 0xFF for unit in units)
        self.assertEqual(opcodes.count(0x23), 1)  # explicit Object[1] allocation
        self.assertEqual(opcodes.count(0x4D), 1)  # replacement stored into array
        self.assertEqual(opcodes.count(0x72), 2)  # getArg + proceed(Object[])
        self.assertEqual(opcodes.count(0x22), 0)  # no object construction besides array
        self.assertEqual(opcodes[-1], 0x11)

        with self.assertRaises(ValueError):
            LibxposedHookArgumentDescription(argument_index=1)
        with self.assertRaises(ValueError):
            lower_libxposed_hook_adapter(
                libxposed_hook_adapter_semantics(LibxposedHookAdapterDescription(inspected_argument_index=None)),
                argument_policy=first,
            )

    def test_hook_combined_argument_then_result_is_one_proceed_and_one_array_allocation(self):
        adapter = libxposed_hook_adapter_semantics(
            LibxposedHookAdapterDescription(inspected_argument_index=0)
        )
        first = libxposed_hook_combined_semantics(
            LibxposedHookCombinedDescription(
                argument_replacement_string="HookedArg",
                result_replacement_string="HookedResult",
            )
        )
        second = libxposed_hook_combined_semantics(
            LibxposedHookCombinedDescription(
                argument_replacement_string="HookedArg",
                result_replacement_string="HookedResult",
            )
        )
        changed = libxposed_hook_combined_semantics(
            LibxposedHookCombinedDescription(
                argument_replacement_string="HookedArg",
                result_replacement_string="ChangedResult",
            )
        )
        self.assertEqual(first.cid, second.cid)
        self.assertNotEqual(first.cid, changed.cid)
        policy = decode_libxposed_hook_combined(first)
        self.assertEqual(policy.argument_index, 0)
        self.assertEqual(policy.expected_parameter_descriptor, "Ljava/lang/String;")
        self.assertEqual(policy.expected_return_descriptor, "Ljava/lang/String;")

        data = emit_dex039_bridge(lower_libxposed_hook_adapter(adapter, combined_policy=first))
        view = inspect_dex(data)
        self.assertIn("HookedArg", view.strings)
        self.assertIn("HookedResult", view.strings)
        self.assertIn("[Ljava/lang/Object;", view.strings)

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

        method_ids_off = struct.unpack_from("<I", data, 92)[0]
        class_defs_off = struct.unpack_from("<I", data, 100)[0]
        class_data_off = struct.unpack_from("<I", data, class_defs_off + 24)[0]
        offset = class_data_off
        _, offset = uleb(offset); _, offset = uleb(offset)
        direct_count, offset = uleb(offset); virtual_count, offset = uleb(offset)
        for _ in range(direct_count):
            _, offset = uleb(offset); _, offset = uleb(offset); _, offset = uleb(offset)
        previous = 0
        code_off = None
        for position in range(virtual_count):
            diff, offset = uleb(offset)
            index = diff if position == 0 else previous + diff
            _, offset = uleb(offset)
            candidate, offset = uleb(offset)
            name_idx = struct.unpack_from("<I", data, method_ids_off + index * 8 + 4)[0]
            if view.strings[name_idx] == "intercept":
                code_off = candidate
            previous = index
        self.assertIsNotNone(code_off)
        registers, ins, outs, tries, debug, insns = struct.unpack_from("<HHHHII", data, code_off)
        self.assertEqual((registers, ins, outs, tries, debug), (7, 2, 2, 0, 0))
        units = struct.unpack_from(f"<{insns}H", data, code_off + 16)
        opcodes = tuple(unit & 0xFF for unit in units)
        self.assertEqual(opcodes.count(0x23), 1)  # Object[1]
        self.assertEqual(opcodes.count(0x4D), 1)  # replacement argument store
        self.assertEqual(opcodes.count(0x72), 2)  # getArg + one proceed(Object[])
        self.assertEqual(opcodes.count(0x22), 0)
        self.assertEqual(opcodes[-3], 0x1A)       # post-proceed result replacement
        self.assertEqual(view.strings[units[-2]], "HookedResult")
        self.assertEqual(opcodes[-1], 0x11)

        with self.assertRaises(ValueError):
            LibxposedHookCombinedDescription(argument_index=1)

    def test_hook_installation_identity_and_exact_package_ready_shape(self):
        first = libxposed_hook_installation_semantics()
        second = libxposed_hook_installation_semantics(
            LibxposedHookInstallationDescription(
                target_class_name="android.app.Activity",
                target_method_name="onResume",
                hooker_class_name="xax.generated.XaxHooker",
            )
        )
        changed = libxposed_hook_installation_semantics(
            LibxposedHookInstallationDescription(target_method_name="onStart")
        )
        self.assertEqual(first.cid, second.cid)
        self.assertNotEqual(first.cid, changed.cid)
        self.assertEqual(decode_libxposed_hook_installation(first).exception_mode, "PROTECTIVE")

        managed = libxposed_managed_entry_semantics(LibxposedManagedEntryDescription())
        spec = lower_libxposed_managed_entry(managed, first)
        self.assertIsNotNone(spec.libxposed_hook_install)
        data = emit_dex039_bridge(spec)
        view = inspect_dex(data)
        for expected in (
            "android.app.Activity", "onResume", "getClassLoader", "loadClass",
            "getDeclaredMethod", "hook", "setExceptionMode", "intercept", "PROTECTIVE",
            "Lxax/generated/XaxHooker;",
        ):
            self.assertIn(expected, view.strings)
        self.assertEqual(struct.unpack_from("<I", data, 80)[0], 1)  # field_ids_size

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

        method_ids_off = struct.unpack_from("<I", data, 92)[0]
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
            _, offset = uleb(offset)
            code_off, offset = uleb(offset)
            name_idx = struct.unpack_from("<I", data, method_ids_off + index * 8 + 4)[0]
            virtual[view.strings[name_idx]] = code_off
            previous = index
        code_off = virtual["onPackageReady"]
        registers, ins, outs, tries, debug, insns = struct.unpack_from("<HHHHII", data, code_off)
        self.assertEqual((registers, ins, outs, tries, debug), (9, 2, 3, 0, 0))
        units = struct.unpack_from(f"<{insns}H", data, code_off + 16)
        opcodes = tuple(unit & 0xFF for unit in units)
        self.assertEqual(opcodes.count(0x72), 3)  # getClassLoader, setExceptionMode, intercept
        self.assertEqual(opcodes.count(0x6E), 3)  # loadClass, getDeclaredMethod, hook
        self.assertEqual(opcodes.count(0x62), 1)  # ExceptionMode.PROTECTIVE
        self.assertEqual(opcodes.count(0x22), 1)  # one Hooker allocation at install time
        self.assertEqual(opcodes.count(0x70), 2)  # Hooker.<init> + native lifecycle callback

        one_arg = libxposed_hook_installation_semantics(
            LibxposedHookInstallationDescription(parameter_type_names=("java.lang.String",))
        )
        one_arg_data = emit_dex039_bridge(lower_libxposed_managed_entry(managed, one_arg))
        one_arg_view = inspect_dex(one_arg_data)
        self.assertIn("java.lang.String", one_arg_view.strings)
        def one_arg_uleb(offset: int) -> tuple[int, int]:
            result = 0
            shift = 0
            while True:
                byte = one_arg_data[offset]
                offset += 1
                result |= (byte & 0x7F) << shift
                if not byte & 0x80:
                    return result, offset
                shift += 7
        one_arg_class_defs_off = struct.unpack_from("<I", one_arg_data, 100)[0]
        one_arg_class_data_off = struct.unpack_from("<I", one_arg_data, one_arg_class_defs_off + 24)[0]
        offset = one_arg_class_data_off
        _, offset = one_arg_uleb(offset); _, offset = one_arg_uleb(offset)
        direct_count, offset = one_arg_uleb(offset); virtual_count, offset = one_arg_uleb(offset)
        for _ in range(direct_count):
            _, offset = one_arg_uleb(offset); _, offset = one_arg_uleb(offset); _, offset = one_arg_uleb(offset)
        previous = 0
        one_arg_code_off = None
        one_arg_method_ids_off = struct.unpack_from("<I", one_arg_data, 92)[0]
        for position in range(virtual_count):
            diff, offset = one_arg_uleb(offset)
            index = diff if position == 0 else previous + diff
            _, offset = one_arg_uleb(offset)
            candidate, offset = one_arg_uleb(offset)
            name_idx = struct.unpack_from("<I", one_arg_data, one_arg_method_ids_off + index * 8 + 4)[0]
            if one_arg_view.strings[name_idx] == "onPackageReady":
                one_arg_code_off = candidate
            previous = index
        self.assertIsNotNone(one_arg_code_off)
        _, _, _, _, _, one_arg_insns = struct.unpack_from("<HHHHII", one_arg_data, one_arg_code_off)
        one_arg_units = struct.unpack_from(f"<{one_arg_insns}H", one_arg_data, one_arg_code_off + 16)
        self.assertEqual(one_arg_units[17] & 0xFF, 0x23)  # install-time Class[1]
        self.assertEqual(one_arg_units[20] & 0xFF, 0x4D)  # parameter Class into Class[1]
        self.assertEqual(one_arg_units[38] & 0xFF, 0x22)  # one Hooker allocation

        with self.assertRaises(ValueError):
            LibxposedHookInstallationDescription(parameter_type_names=("java.lang.Integer",))
        with self.assertRaises(ValueError):
            LibxposedHookInstallationDescription(exception_mode="RETHROW")
        with self.assertRaises(ValueError):
            LibxposedHookInstallationDescription(failure_policy="ignore")
        with self.assertRaises(ValueError):
            LibxposedHookInstallationDescription(lifetime_policy="manual-unhook")

    def test_deoptimization_is_explicit_best_effort_and_precedes_hook(self):
        managed = libxposed_managed_entry_semantics(LibxposedManagedEntryDescription())
        installation = libxposed_hook_installation_semantics(
            LibxposedHookInstallationDescription(
                target_class_name="android.app.Activity",
                target_method_name="onResume",
            )
        )
        deopt = libxposed_deoptimization_semantics(
            LibxposedDeoptimizationDescription(
                target_class_name="android.app.Activity",
                target_method_name="onResume",
                result_policy="best-effort",
            )
        )
        same = libxposed_deoptimization_semantics(LibxposedDeoptimizationDescription())
        changed = libxposed_deoptimization_semantics(
            LibxposedDeoptimizationDescription(target_method_name="onStart")
        )
        self.assertEqual(deopt.cid, same.cid)
        self.assertNotEqual(deopt.cid, changed.cid)
        self.assertEqual(decode_libxposed_deoptimization(deopt).result_policy, "best-effort")

        baseline = emit_dex039_bridge(lower_libxposed_managed_entry(managed, installation))
        data = emit_dex039_bridge(lower_libxposed_managed_entry(managed, installation, deopt))
        baseline_view = inspect_dex(baseline)
        view = inspect_dex(data)
        self.assertNotIn("deoptimize", baseline_view.strings)
        self.assertIn("deoptimize", view.strings)

        from benchmarks.bench_android_libxposed_managed import _virtual_method_units
        baseline_units = _virtual_method_units(baseline)["onPackageReady"][1]
        units = _virtual_method_units(data)["onPackageReady"][1]
        self.assertEqual(len(units), len(baseline_units) + 3)  # one invoke-virtual 35c
        self.assertEqual(sum(1 for unit in units if unit & 0xFF == 0x6E),
                         sum(1 for unit in baseline_units if unit & 0xFF == 0x6E) + 1)

        method_ids_off = struct.unpack_from("<I", data, 92)[0]
        invoke_names = []
        for index, unit in enumerate(units[:-1]):
            if unit & 0xFF != 0x6E:
                continue
            method_index = units[index + 1]
            name_index = struct.unpack_from("<I", data, method_ids_off + method_index * 8 + 4)[0]
            invoke_names.append(view.strings[name_index])
        self.assertIn("deoptimize", invoke_names)
        self.assertLess(invoke_names.index("deoptimize"), invoke_names.index("hook"))

        with self.assertRaises(ValueError):
            LibxposedDeoptimizationDescription(result_policy="require-success")
        mismatched = libxposed_deoptimization_semantics(
            LibxposedDeoptimizationDescription(target_method_name="onStart")
        )
        with self.assertRaisesRegex(ValueError, "must equal hook installation target"):
            lower_libxposed_managed_entry(managed, installation, mismatched)
        with self.assertRaisesRegex(ValueError, "requires a hook installation"):
            lower_libxposed_managed_entry(managed, None, deopt)

    def test_module_services_are_explicit_wrappers_with_propagating_failures(self):
        managed = libxposed_managed_entry_semantics(LibxposedManagedEntryDescription())
        services = libxposed_module_services_semantics(
            LibxposedModuleServicesDescription(
                services=(
                    "open-remote-file",
                    "framework-name",
                    "remote-preferences",
                    "list-remote-files",
                    "framework-version",
                ),
                failure_policy="propagate",
            )
        )
        view = decode_libxposed_module_services(services)
        self.assertEqual(
            view.services,
            (
                "framework-name",
                "framework-version",
                "remote-preferences",
                "list-remote-files",
                "open-remote-file",
            ),
        )
        self.assertEqual(view.failure_policy, "propagate")
        data = emit_dex039_bridge(lower_libxposed_managed_entry(managed, None, None, services))
        dex = inspect_dex(data)
        for expected in (
            "xaxFrameworkName", "xaxFrameworkVersion", "xaxRemotePreferences",
            "xaxListRemoteFiles", "xaxOpenRemoteFile", "getFrameworkName",
            "getFrameworkVersion", "getRemotePreferences", "listRemoteFiles", "openRemoteFile",
            "Landroid/content/SharedPreferences;", "Landroid/os/ParcelFileDescriptor;",
        ):
            self.assertIn(expected, dex.strings)

        from benchmarks.bench_android_libxposed_managed import _virtual_method_units
        methods = _virtual_method_units(data)
        for name in (
            "xaxFrameworkName", "xaxFrameworkVersion", "xaxRemotePreferences",
            "xaxListRemoteFiles", "xaxOpenRemoteFile",
        ):
            self.assertIn(name, methods)
            self.assertEqual(methods[name][0], 5)
            units = methods[name][1]
            self.assertEqual(tuple(unit & 0xFF for unit in (units[0], units[3], units[4])), (0x6E, 0x0C, 0x11))

        with self.assertRaises(ValueError):
            LibxposedModuleServicesDescription(services=("remote-preferences", "remote-preferences"))
        with self.assertRaises(ValueError):
            LibxposedModuleServicesDescription(services=("unknown",))
        with self.assertRaises(ValueError):
            LibxposedModuleServicesDescription(failure_policy="ignore")

    def test_remote_preferences_are_capability_gated_and_typed_reads_are_direct(self):
        managed = libxposed_managed_entry_semantics(LibxposedManagedEntryDescription())
        policy = libxposed_remote_preferences_semantics(
            LibxposedRemotePreferencesDescription(
                reads=("string", "boolean", "long", "contains", "float", "int"),
                capability_policy="nullable-on-unsupported",
                failure_policy="propagate",
            )
        )
        decoded = decode_libxposed_remote_preferences(policy)
        self.assertEqual(decoded.reads, ("boolean", "int", "long", "float", "string", "contains"))
        self.assertEqual(decoded.capability_policy, "nullable-on-unsupported")
        self.assertEqual(decoded.failure_policy, "propagate")

        data = emit_dex039_bridge(lower_libxposed_managed_entry(managed, remote_preferences=policy))
        dex = inspect_dex(data)
        for expected in (
            "xaxRemotePreferencesIfSupported", "getFrameworkProperties", "getRemotePreferences",
            "xaxPrefBoolean", "xaxPrefInt", "xaxPrefLong", "xaxPrefFloat", "xaxPrefString", "xaxPrefContains",
            "getBoolean", "getInt", "getLong", "getFloat", "getString", "contains",
            "Landroid/content/SharedPreferences;",
        ):
            self.assertIn(expected, dex.strings)

        from benchmarks.bench_android_libxposed_managed import _virtual_method_units
        methods = _virtual_method_units(data)
        acquire_units = methods["xaxRemotePreferencesIfSupported"][1]
        self.assertEqual(methods["xaxRemotePreferencesIfSupported"][0], 16)
        self.assertEqual(tuple(unit & 0xFF for unit in acquire_units), (
            0x6E, acquire_units[1] & 0xFF, 0x02, 0x0B, 0x84, 0xDD, 0x00, 0x38,
            0x07, 0x6E, acquire_units[10] & 0xFF, 0x32, 0x0C, 0x11, 0x12, 0x11,
        ))
        self.assertEqual(sum(1 for unit in acquire_units if unit & 0xFF == 0x6E), 2)
        self.assertNotIn(0x22, tuple(unit & 0xFF for unit in acquire_units))
        self.assertNotIn(0x23, tuple(unit & 0xFF for unit in acquire_units))

        expected_tail = {
            "xaxPrefBoolean": (0x0A, 0x0F),
            "xaxPrefInt": (0x0A, 0x0F),
            "xaxPrefLong": (0x0B, 0x10),
            "xaxPrefFloat": (0x0A, 0x0F),
            "xaxPrefString": (0x0C, 0x11),
            "xaxPrefContains": (0x0A, 0x0F),
        }
        for name, tail in expected_tail.items():
            self.assertEqual(methods[name][0], 5)
            units = methods[name][1]
            self.assertEqual(units[0] & 0xFF, 0x72)
            self.assertEqual((units[3] & 0xFF, units[4] & 0xFF), tail)
            self.assertNotIn(0x22, tuple(unit & 0xFF for unit in units))
            self.assertNotIn(0x23, tuple(unit & 0xFF for unit in units))

        with self.assertRaises(ValueError):
            LibxposedRemotePreferencesDescription(reads=("boolean", "boolean"))
        with self.assertRaises(ValueError):
            LibxposedRemotePreferencesDescription(reads=("editor",))
        with self.assertRaises(ValueError):
            LibxposedRemotePreferencesDescription(capability_policy="assume-supported")
        with self.assertRaises(ValueError):
            LibxposedRemotePreferencesDescription(failure_policy="ignore")

    def test_retained_manual_unhook_is_explicit_and_process_profile_stays_field_free(self):
        from benchmarks.bench_android_libxposed_managed import _virtual_method_units

        managed = libxposed_managed_entry_semantics(LibxposedManagedEntryDescription())
        implicit_process = libxposed_hook_installation_semantics(LibxposedHookInstallationDescription())
        explicit_process = libxposed_hook_installation_semantics(
            LibxposedHookInstallationDescription(lifetime_policy="process")
        )
        retained = libxposed_hook_installation_semantics(
            LibxposedHookInstallationDescription(lifetime_policy="retained-manual-unhook")
        )
        self.assertEqual(implicit_process.cid, explicit_process.cid)
        self.assertNotEqual(implicit_process.cid, retained.cid)
        self.assertEqual(decode_libxposed_hook_installation(retained).lifetime_policy, "retained-manual-unhook")

        process_dex = emit_dex039_bridge(lower_libxposed_managed_entry(managed, implicit_process))
        retained_dex = emit_dex039_bridge(lower_libxposed_managed_entry(managed, retained))
        process_view = inspect_dex(process_dex)
        retained_view = inspect_dex(retained_dex)
        self.assertNotIn("xaxHookHandle", process_view.strings)
        self.assertNotIn("xaxUnhook", process_view.strings)
        self.assertIn("xaxHookHandle", retained_view.strings)
        self.assertIn("xaxUnhook", retained_view.strings)
        self.assertIn("unhook", retained_view.strings)

        methods = _virtual_method_units(retained_dex)
        self.assertIn("xaxUnhook", methods)
        self.assertEqual(methods["xaxUnhook"][0], 11)
        units = methods["xaxUnhook"][1]
        # iget-object handle; if-eqz return; invoke-interface unhook; clear field; return.
        self.assertEqual(
            tuple(units[index] & 0xFF for index in (0, 2, 4, 7, 8, 10)),
            (0x54, 0x38, 0x72, 0x12, 0x5B, 0x0E),
        )
        package_ready = methods["onPackageReady"][1]
        self.assertIn(0x765B, package_ready)  # store returned HookHandle into this.xaxHookHandle

        class_defs_off = struct.unpack_from("<I", retained_dex, 100)[0]
        class_data_off = struct.unpack_from("<I", retained_dex, class_defs_off + 24)[0]
        def uleb(offset: int) -> tuple[int, int]:
            result = 0
            shift = 0
            while True:
                byte = retained_dex[offset]
                offset += 1
                result |= (byte & 0x7F) << shift
                if not byte & 0x80:
                    return result, offset
                shift += 7
        static_fields, offset = uleb(class_data_off)
        instance_fields, _ = uleb(offset)
        self.assertEqual(static_fields, 0)
        self.assertEqual(instance_fields, 1)


    def test_remote_files_are_capability_gated_without_hidden_fallback(self):
        from benchmarks.bench_android_libxposed_managed import _virtual_method_units

        managed = libxposed_managed_entry_semantics(LibxposedManagedEntryDescription())
        policy = libxposed_remote_files_semantics(LibxposedRemoteFilesDescription(("open", "list")))
        self.assertEqual(decode_libxposed_remote_files(policy).operations, ("list", "open"))
        data = emit_dex039_bridge(lower_libxposed_managed_entry(managed, remote_files=policy))
        view = inspect_dex(data)
        self.assertTrue(view.checksum_valid and view.signature_valid)
        methods = _virtual_method_units(data)
        for name in ("xaxListRemoteFilesIfSupported", "xaxOpenRemoteFileIfSupported"):
            self.assertEqual(methods[name][0], 16)
            units = methods[name][1]
            opcodes = tuple(unit & 0xFF for unit in units)
            self.assertEqual(opcodes.count(0x6E), 2)
            self.assertEqual(opcodes.count(0x38), 1)
            self.assertEqual(opcodes.count(0xDD), 1)
            self.assertNotIn(0x22, opcodes)
            self.assertNotIn(0x23, opcodes)
        with self.assertRaises(ValueError):
            LibxposedRemoteFilesDescription(("open", "open"))
        with self.assertRaises(ValueError):
            LibxposedRemoteFilesDescription(("write",))
        with self.assertRaises(ValueError):
            LibxposedRemoteFilesDescription(capability_policy="assume-supported")
        with self.assertRaises(ValueError):
            LibxposedRemoteFilesDescription(failure_policy="ignore")

    def test_hot_reload_is_explicit_single_retained_hook_atomic_replacement(self):
        from benchmarks.bench_android_libxposed_managed import _virtual_method_units

        managed = libxposed_managed_entry_semantics(LibxposedManagedEntryDescription())
        installation = libxposed_hook_installation_semantics(
            LibxposedHookInstallationDescription(lifetime_policy="retained-manual-unhook")
        )
        hot_reload = libxposed_hot_reload_semantics(LibxposedHotReloadDescription())
        self.assertEqual(
            decode_libxposed_hot_reload(hot_reload).policy,
            "single-retained-hook-id-guarded-atomic-replace",
        )

        spec = lower_libxposed_managed_entry(managed, installation, hot_reload=hot_reload)
        data = emit_dex039_bridge(spec)
        view = inspect_dex(data)
        self.assertTrue(view.checksum_valid)
        self.assertTrue(view.signature_valid)
        for value in (
            "onHotReloading", "onHotReloaded", "setSavedInstanceState", "getSavedInstanceState",
            "xaxReloadClassLoader", "getOldHookHandles", "setId", "getId", "isEmpty", "equals",
            "replaceHook", "xax.primary",
        ):
            self.assertIn(value, view.strings)

        methods = _virtual_method_units(data)
        from benchmarks.bench_android_libxposed_hook import _instruction_opcodes
        self.assertEqual(methods["onHotReloading"][0], 11)
        pre_opcodes = _instruction_opcodes(methods["onHotReloading"][1])
        self.assertEqual(pre_opcodes, (0x54, 0x38, 0x72, 0x12, 0x0F, 0x12, 0x0F))
        self.assertEqual(methods["onHotReloaded"][0], 51)
        opcodes = _instruction_opcodes(methods["onHotReloaded"][1])
        self.assertEqual(
            opcodes,
            (0x72, 0x0C, 0x38, 0x1F, 0x5B, 0x72, 0x0C, 0x72, 0x0A, 0x39, 0x12, 0x72, 0x0C, 0x1F, 0x72, 0x0C, 0x1A, 0x6E, 0x0A, 0x38, 0x22, 0x70, 0x72, 0x0C, 0x5B, 0x0E),
        )
        # One Hooker instance is intentionally created only after the old-handle
        # list is nonempty and its stable API-102 hook ID matches. There is no
        # unhook/install gap, reflection, target lookup, or array allocation.
        self.assertEqual(opcodes.count(0x22), 1)
        self.assertNotIn(0x23, opcodes)
        self.assertEqual(pre_opcodes.count(0x38), 1)
        self.assertEqual(opcodes.count(0x39), 1)
        self.assertEqual(opcodes.count(0x38), 2)

        module = libxposed_module_semantics(
            LibxposedModuleDescription(
                min_api_version=102,
                target_api_version=102,
                java_entries=("xax.generated.XaxModule",),
            )
        )
        self.assertIn(b"autoHotReload=true\n", emit_libxposed_metadata(module, hot_reload)["META-INF/xposed/module.prop"])

        process_install = libxposed_hook_installation_semantics(LibxposedHookInstallationDescription())
        with self.assertRaises(ValueError):
            lower_libxposed_managed_entry(managed, process_install, hot_reload=hot_reload)
        with self.assertRaises(ValueError):
            lower_libxposed_managed_entry(managed, None, hot_reload=hot_reload)
        with self.assertRaises(ValueError):
            LibxposedHotReloadDescription(policy="multi-hook")
        with self.assertRaises(ValueError):
            LibxposedHotReloadDescription(failure_policy="ignore")
        with self.assertRaises(ValueError):
            LibxposedHotReloadDescription(hook_id="")
        with self.assertRaises(ValueError):
            LibxposedHotReloadDescription(mismatch_policy="replace-anyway")
        with self.assertRaises(ValueError):
            LibxposedHotReloadDescription(state_policy="module-object")
        with self.assertRaises(ValueError):
            LibxposedHotReloadDescription(missing_state_policy="continue")


if __name__ == "__main__":
    unittest.main()
