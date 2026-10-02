from __future__ import annotations

import struct
import unittest

from xax_android_components import (
    android_application_semantics,
    android_broadcast_receiver_semantics,
    android_service_semantics,
    decode_android_application,
    decode_android_broadcast_receiver,
    decode_android_service,
    lower_android_application,
    lower_android_broadcast_receiver,
    lower_android_service,
)
from xax_dex import ACC_PRIVATE, ACC_PUBLIC, ACC_NATIVE, emit_dex039_bridge, inspect_dex


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


def _method_code(data: bytes, method_name: str) -> tuple[tuple[int, int, int, int, int, int], tuple[int, ...], int]:
    view = inspect_dex(data)
    method_ids_size = struct.unpack_from("<I", data, 88)[0]
    method_ids_off = struct.unpack_from("<I", data, 92)[0]

    def name(index: int) -> str:
        if index >= method_ids_size:
            raise AssertionError(index)
        name_idx = struct.unpack_from("<I", data, method_ids_off + index * 8 + 4)[0]
        return view.strings[name_idx]

    class_defs_off = struct.unpack_from("<I", data, 100)[0]
    class_data_off = struct.unpack_from("<I", data, class_defs_off + 24)[0]
    offset = class_data_off
    _static, offset = _uleb(data, offset)
    _instance, offset = _uleb(data, offset)
    direct_count, offset = _uleb(data, offset)
    virtual_count, offset = _uleb(data, offset)
    previous = 0
    for position in range(direct_count):
        diff, offset = _uleb(data, offset)
        index = diff if position == 0 else previous + diff
        _flags, offset = _uleb(data, offset)
        _code_off, offset = _uleb(data, offset)
        previous = index
    previous = 0
    for position in range(virtual_count):
        diff, offset = _uleb(data, offset)
        index = diff if position == 0 else previous + diff
        flags, offset = _uleb(data, offset)
        code_off, offset = _uleb(data, offset)
        previous = index
        if name(index) == method_name:
            header = struct.unpack_from("<HHHHII", data, code_off)
            insns = header[-1]
            units = struct.unpack_from(f"<{insns}H", data, code_off + 16)
            return header, units, flags
    raise AssertionError(method_name)


class AndroidComponentTests(unittest.TestCase):
    def test_receiver_semantics_are_canonical_and_edit_local(self) -> None:
        first = android_broadcast_receiver_semantics(
            exported=True, action="xax.generated.ACTION_TEST"
        )
        second = android_broadcast_receiver_semantics(
            exported=True, action="xax.generated.ACTION_TEST"
        )
        edited = android_broadcast_receiver_semantics(
            exported=False, action="xax.generated.ACTION_TEST"
        )
        self.assertEqual(first.cid, second.cid)
        self.assertNotEqual(first.cid, edited.cid)
        view = decode_android_broadcast_receiver(first)
        self.assertEqual(view.class_descriptor, "Lxax/generated/XaxReceiver;")
        self.assertEqual(view.java_class_name, "xax.generated.XaxReceiver")
        self.assertTrue(view.exported)
        self.assertEqual(view.action, "xax.generated.ACTION_TEST")

    def test_receiver_lowers_to_one_direct_native_transition(self) -> None:
        carrier = android_broadcast_receiver_semantics()
        spec = lower_android_broadcast_receiver(carrier)
        self.assertEqual(spec.superclass_descriptor, "Landroid/content/BroadcastReceiver;")
        self.assertEqual(len(spec.native_methods), 1)
        self.assertEqual(spec.native_methods[0].name, "xaxOnReceive")
        self.assertEqual(spec.native_methods[0].access_flags, ACC_PRIVATE | ACC_NATIVE)
        self.assertEqual(spec.forwarding_overrides[0].name, "onReceive")
        self.assertEqual(spec.forwarding_overrides[0].access_flags, ACC_PUBLIC)
        self.assertFalse(spec.forwarding_overrides[0].call_super)

        data = emit_dex039_bridge(spec)
        view = inspect_dex(data)
        self.assertEqual(view.class_descriptor, "Lxax/generated/XaxReceiver;")
        self.assertEqual(view.superclass_descriptor, "Landroid/content/BroadcastReceiver;")
        header, units, flags = _method_code(data, "onReceive")
        self.assertEqual(flags, ACC_PUBLIC)
        self.assertEqual(header[:6], (3, 3, 3, 0, 0, 4))
        self.assertEqual(len(units), 4)
        self.assertEqual(units[0] & 0xFF, 0x70)  # invoke-direct private native callback
        self.assertEqual(units[-1], 0x000E)       # return-void
        self.assertEqual(sum(1 for unit in units if unit & 0xFF in {0x6F, 0x22, 0x23}), 0)
        self.assertNotIn("java/lang/reflect", "\n".join(view.strings))

    def test_application_semantics_and_lifecycle_lowering(self) -> None:
        first = android_application_semantics()
        second = android_application_semantics()
        edited = android_application_semantics(class_descriptor="Lxax/generated/OtherApplication;")
        self.assertEqual(first.cid, second.cid)
        self.assertNotEqual(first.cid, edited.cid)
        view = decode_android_application(first)
        self.assertEqual(view.java_class_name, "xax.generated.XaxApplication")
        spec = lower_android_application(first)
        self.assertEqual(spec.superclass_descriptor, "Landroid/app/Application;")
        self.assertEqual([item.name for item in spec.native_methods], ["xaxOnCreate"])
        data = emit_dex039_bridge(spec)
        header, units, flags = _method_code(data, "onCreate")
        self.assertEqual(flags, ACC_PUBLIC)
        self.assertEqual(header[:6], (1, 1, 1, 0, 0, 7))
        self.assertEqual(units[0] & 0xFF, 0x6F)
        self.assertEqual(units[3] & 0xFF, 0x70)
        self.assertEqual(units[-1], 0x000E)

    def test_service_semantics_are_canonical_and_edit_local(self) -> None:
        first = android_service_semantics(exported=False)
        second = android_service_semantics(exported=False)
        edited = android_service_semantics(exported=True)
        self.assertEqual(first.cid, second.cid)
        self.assertNotEqual(first.cid, edited.cid)
        view = decode_android_service(first)
        self.assertEqual(view.class_descriptor, "Lxax/generated/XaxService;")
        self.assertEqual(view.java_class_name, "xax.generated.XaxService")
        self.assertFalse(view.exported)

    def test_service_lowers_lifecycle_and_null_on_bind_exactly(self) -> None:
        carrier = android_service_semantics()
        spec = lower_android_service(carrier)
        self.assertEqual(spec.superclass_descriptor, "Landroid/app/Service;")
        self.assertEqual([item.name for item in spec.native_methods], ["xaxOnCreate", "xaxOnDestroy"])
        self.assertEqual([item.name for item in spec.forwarding_overrides], ["onCreate", "onDestroy"])
        self.assertTrue(all(item.call_super for item in spec.forwarding_overrides))
        self.assertEqual(len(spec.null_return_overrides), 1)
        self.assertEqual(spec.null_return_overrides[0].name, "onBind")
        self.assertEqual(spec.null_return_overrides[0].proto.return_type, "Landroid/os/IBinder;")

        data = emit_dex039_bridge(spec)
        view = inspect_dex(data)
        self.assertEqual(view.class_descriptor, "Lxax/generated/XaxService;")
        self.assertEqual(view.superclass_descriptor, "Landroid/app/Service;")
        for name in ("onCreate", "onDestroy"):
            header, units, flags = _method_code(data, name)
            self.assertEqual(flags, ACC_PUBLIC)
            self.assertEqual(header[:6], (1, 1, 1, 0, 0, 7))
            self.assertEqual(units[0] & 0xFF, 0x6F)  # invoke-super
            self.assertEqual(units[3] & 0xFF, 0x70)  # invoke-direct native callback
            self.assertEqual(units[-1], 0x000E)
        bind_header, bind_units, bind_flags = _method_code(data, "onBind")
        self.assertEqual(bind_flags, ACC_PUBLIC)
        self.assertEqual(bind_header[:6], (3, 2, 0, 0, 0, 2))
        self.assertEqual(bind_units, (0x0012, 0x0011))  # const/4 v0,#0; return-object v0
        self.assertNotIn("java/lang/reflect", "\n".join(view.strings))

    def test_invalid_service_identity_rejects(self) -> None:
        with self.assertRaises(ValueError):
            android_service_semantics(class_descriptor="xax.generated.Bad")

    def test_invalid_receiver_identity_rejects(self) -> None:
        with self.assertRaises(ValueError):
            android_broadcast_receiver_semantics(class_descriptor="xax.generated.Bad")
        with self.assertRaises(ValueError):
            android_broadcast_receiver_semantics(action="")


if __name__ == "__main__":
    unittest.main()
