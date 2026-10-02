from __future__ import annotations

import unittest

from xax_manifest import (
    ANDROID_ATTR_EXPORTED,
    ANDROID_ATTR_HAS_CODE,
    ANDROID_ATTR_MIN_SDK_VERSION,
    ANDROID_ATTR_NAME,
    ANDROID_ATTR_TARGET_SDK_VERSION,
    ANDROID_ATTR_VERSION_CODE,
    ANDROID_NS_URI,
    AndroidManifestApplication,
    AndroidManifestReceiver,
    AndroidManifestService,
    AndroidManifestSpec,
    android_manifest_semantics,
    decode_android_manifest_semantics,
    emit_binary_manifest_from_semantics,
    emit_binary_manifest,
    inspect_binary_manifest,
)


class ManifestTests(unittest.TestCase):
    def test_activity_manifest_is_deterministic_and_structurally_roundtrips(self) -> None:
        spec = AndroidManifestSpec("xax.generated", "xax.generated.XaxActivity", min_sdk=28, target_sdk=35)
        first = emit_binary_manifest(spec)
        second = emit_binary_manifest(spec)
        self.assertEqual(first, second)
        view = inspect_binary_manifest(first)
        self.assertEqual(view.file_size, len(first))
        self.assertEqual((view.namespace_prefix, view.namespace_uri), ("android", ANDROID_NS_URI))
        self.assertEqual([item.name for item in view.elements], ["manifest", "uses-sdk", "application", "activity", "intent-filter", "action", "category"])
        self.assertEqual([item.depth for item in view.elements], [0, 1, 1, 2, 3, 4, 4])

        attrs = {(element.name, attr.name): attr for element in view.elements for attr in element.attributes}
        self.assertEqual(attrs[("manifest", "package")].value, "xax.generated")
        self.assertEqual(attrs[("manifest", "versionCode")].value, 1)
        self.assertEqual(attrs[("uses-sdk", "minSdkVersion")].value, 28)
        self.assertEqual(attrs[("uses-sdk", "targetSdkVersion")].value, 35)
        self.assertEqual(attrs[("application", "hasCode")].value, True)
        self.assertEqual(attrs[("activity", "name")].value, "xax.generated.XaxActivity")
        self.assertEqual(attrs[("activity", "exported")].value, True)


    def test_manifest_can_synthesize_broadcast_receiver_and_action(self) -> None:
        spec = AndroidManifestSpec("xax.generated", "xax.generated.XaxActivity", min_sdk=28, target_sdk=35)
        receiver = AndroidManifestReceiver(
            "xax.generated.XaxReceiver",
            exported=True,
            action="xax.generated.ACTION_TEST",
        )
        data = emit_binary_manifest(spec, receivers=(receiver,))
        view = inspect_binary_manifest(data)
        self.assertEqual(
            [item.name for item in view.elements],
            [
                "manifest", "uses-sdk", "application", "activity", "intent-filter", "action", "category",
                "receiver", "intent-filter", "action",
            ],
        )
        receivers = [item for item in view.elements if item.name == "receiver"]
        self.assertEqual(len(receivers), 1)
        attrs = {item.name: item.value for item in receivers[0].attributes}
        self.assertEqual(attrs, {"name": "xax.generated.XaxReceiver", "exported": True})
        actions = [
            next(attr.value for attr in element.attributes if attr.name == "name")
            for element in view.elements
            if element.name == "action"
        ]
        self.assertIn("xax.generated.ACTION_TEST", actions)
        self.assertEqual(data, emit_binary_manifest(spec, receivers=(receiver,)))

    def test_manifest_can_name_custom_application(self) -> None:
        spec = AndroidManifestSpec("xax.generated", "xax.generated.XaxActivity", min_sdk=28, target_sdk=35)
        application = AndroidManifestApplication("xax.generated.XaxApplication")
        data = emit_binary_manifest(spec, application=application)
        view = inspect_binary_manifest(data)
        app = next(item for item in view.elements if item.name == "application")
        attrs = {item.name: item.value for item in app.attributes}
        self.assertEqual(attrs, {"hasCode": True, "name": "xax.generated.XaxApplication"})
        self.assertEqual(data, emit_binary_manifest(spec, application=application))

    def test_manifest_can_synthesize_service(self) -> None:
        spec = AndroidManifestSpec("xax.generated", "xax.generated.XaxActivity", min_sdk=28, target_sdk=35)
        service = AndroidManifestService("xax.generated.XaxService", exported=False)
        data = emit_binary_manifest(spec, services=(service,))
        view = inspect_binary_manifest(data)
        services = [item for item in view.elements if item.name == "service"]
        self.assertEqual(len(services), 1)
        attrs = {item.name: item.value for item in services[0].attributes}
        self.assertEqual(attrs, {"name": "xax.generated.XaxService", "exported": False})
        self.assertEqual(data, emit_binary_manifest(spec, services=(service,)))

    def test_manifest_semantic_carrier_is_canonical_and_lowers_exactly(self) -> None:
        spec = AndroidManifestSpec("xax.generated", "xax.generated.XaxActivity", min_sdk=28, target_sdk=35)
        first = android_manifest_semantics(spec)
        second = android_manifest_semantics(spec)
        self.assertEqual(first.cid, second.cid)
        self.assertEqual(decode_android_manifest_semantics(first), spec)
        self.assertEqual(emit_binary_manifest_from_semantics(first), emit_binary_manifest(spec))

    def test_manifest_semantic_edit_changes_identity(self) -> None:
        first = android_manifest_semantics(AndroidManifestSpec("xax.generated", "xax.generated.XaxActivity", version_code=1))
        second = android_manifest_semantics(AndroidManifestSpec("xax.generated", "xax.generated.XaxActivity", version_code=2))
        self.assertNotEqual(first.cid, second.cid)
        self.assertNotEqual(emit_binary_manifest_from_semantics(first), emit_binary_manifest_from_semantics(second))

    def test_resource_map_uses_public_framework_attribute_ids(self) -> None:
        view = inspect_binary_manifest(emit_binary_manifest(AndroidManifestSpec("xax.generated", "xax.generated.XaxActivity")))
        self.assertEqual(
            view.resource_map,
            tuple(sorted((ANDROID_ATTR_NAME, ANDROID_ATTR_HAS_CODE, ANDROID_ATTR_EXPORTED, ANDROID_ATTR_MIN_SDK_VERSION, ANDROID_ATTR_VERSION_CODE, ANDROID_ATTR_TARGET_SDK_VERSION))),
        )
        attrs = [attr for element in view.elements for attr in element.attributes if attr.namespace == ANDROID_NS_URI]
        self.assertTrue(all(attr.resource_id is not None for attr in attrs))

    def test_launcher_can_be_disabled_without_hidden_intent_filter(self) -> None:
        view = inspect_binary_manifest(emit_binary_manifest(AndroidManifestSpec("xax.generated", "xax.generated.XaxActivity", launcher=False)))
        self.assertEqual([item.name for item in view.elements], ["manifest", "uses-sdk", "application", "activity"])
        activity = next(item for item in view.elements if item.name == "activity")
        exported = next(item for item in activity.attributes if item.name == "exported")
        self.assertFalse(exported.value)

    def test_invalid_profiles_reject(self) -> None:
        with self.assertRaises(ValueError):
            AndroidManifestSpec("xax.generated", "xax.generated.XaxActivity", min_sdk=36, target_sdk=35)
        with self.assertRaises(ValueError):
            AndroidManifestSpec("", "xax.generated.XaxActivity")

    def test_corrupt_tree_size_rejects(self) -> None:
        data = bytearray(emit_binary_manifest(AndroidManifestSpec("xax.generated", "xax.generated.XaxActivity")))
        data[4:8] = (len(data) + 4).to_bytes(4, "little")
        with self.assertRaisesRegex(ValueError, "tree header"):
            inspect_binary_manifest(bytes(data))


if __name__ == "__main__":
    unittest.main()
