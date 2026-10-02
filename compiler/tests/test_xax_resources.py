from __future__ import annotations

import unittest

from xax_compiler import Kind, StoreReader, object_with_refs, write_store
from xax_resources import (
    APP_PACKAGE_ID,
    AndroidResourceSpec,
    AndroidStringResource,
    android_resources_semantics,
    decode_android_resources_semantics,
    emit_resources_arsc,
    emit_resources_arsc_from_semantics,
    inspect_resources_arsc,
    resource_id,
)


class AndroidResourcesTests(unittest.TestCase):
    def test_string_resource_semantics_are_canonical_and_order_independent(self) -> None:
        first = AndroidResourceSpec(
            "xax.generated",
            (
                AndroidStringResource("clicked", "Clicked"),
                AndroidStringResource("app_name", "XAX"),
            ),
        )
        second = AndroidResourceSpec(
            "xax.generated",
            (
                AndroidStringResource("app_name", "XAX"),
                AndroidStringResource("clicked", "Clicked"),
            ),
        )
        one, two = android_resources_semantics(first), android_resources_semantics(second)
        self.assertEqual(one.cid, two.cid)
        self.assertEqual(decode_android_resources_semantics(one), second)
        module = object_with_refs(Kind.MODULE, (one,))
        StoreReader(write_store(module.cid, (one, module)))

    def test_direct_string_table_has_stable_ids_and_values(self) -> None:
        spec = AndroidResourceSpec(
            "xax.generated",
            (
                AndroidStringResource("app_name", "XAX"),
                AndroidStringResource("clicked", "Clicked"),
                AndroidStringResource("same", "XAX"),
            ),
        )
        first = emit_resources_arsc(spec)
        second = emit_resources_arsc(spec)
        self.assertEqual(first, second)
        view = inspect_resources_arsc(first)
        self.assertEqual(view.package_id, APP_PACKAGE_ID)
        self.assertEqual(view.package_name, "xax.generated")
        self.assertEqual(view.type_name, "string")
        self.assertEqual(
            tuple((item.resource_id, item.name, item.value) for item in view.entries),
            (
                (0x7F010000, "app_name", "XAX"),
                (0x7F010001, "clicked", "Clicked"),
                (0x7F010002, "same", "XAX"),
            ),
        )
        self.assertEqual(resource_id("clicked", spec), 0x7F010001)
        carrier = android_resources_semantics(spec)
        self.assertEqual(emit_resources_arsc_from_semantics(carrier), first)

    def test_invalid_names_duplicates_and_corruption_reject(self) -> None:
        with self.assertRaises(ValueError):
            AndroidStringResource("Bad-Name", "x")
        with self.assertRaises(ValueError):
            AndroidResourceSpec(
                "xax.generated",
                (AndroidStringResource("same", "a"), AndroidStringResource("same", "b")),
            )
        data = bytearray(
            emit_resources_arsc(AndroidResourceSpec("xax.generated", (AndroidStringResource("app_name", "XAX"),)))
        )
        data[0] ^= 1
        with self.assertRaises(ValueError):
            inspect_resources_arsc(bytes(data))


if __name__ == "__main__":
    unittest.main()
