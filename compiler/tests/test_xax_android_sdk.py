from __future__ import annotations

import io
from pathlib import Path
import unittest
import zipfile

from xax_android_sdk import (
    import_android_classes,
    import_android_jar,
    parse_android_api_versions,
    parse_classfile,
)
from xax_compiler import Kind, StoreReader, object_with_refs, verify_store, write_store


FIXTURES = Path(__file__).parent / "fixtures"
EXAMPLE = FIXTURES / "android_sdk_example.class"
OTHER = FIXTURES / "android_sdk_other.class"

API_XML = b'''<?xml version="1.0" encoding="utf-8"?>
<api version="1">
  <class name="fixture/api/Example" since="1">
    <method name="&lt;init>()V" />
    <method name="add(IJ)I" since="3" deprecated="5" />
    <method name="hello(Ljava/lang/String;)Ljava/lang/String;" since="2" />
    <field name="FLAG" since="4" />
    <field name="name" />
  </class>
  <class name="fixture/api/Other" since="2">
    <method name="ping()V" />
  </class>
</api>
'''


def jar_bytes(order: tuple[str, ...]) -> bytes:
    payloads = {
        "fixture/api/Example.class": EXAMPLE.read_bytes(),
        "fixture/api/Other.class": OTHER.read_bytes(),
    }
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_STORED) as archive:
        for name in order:
            archive.writestr(name, payloads[name])
    return out.getvalue()


class AndroidSdkImporterTests(unittest.TestCase):
    def test_classfile_parser_extracts_exact_public_metadata(self) -> None:
        metadata = parse_classfile(EXAMPLE.read_bytes())
        self.assertEqual(metadata.internal_name, "fixture/api/Example")
        self.assertEqual(metadata.superclass, "java/lang/Object")
        self.assertEqual(metadata.interfaces, ("java/io/Serializable",))
        self.assertEqual((metadata.major_version, metadata.minor_version), (61, 0))
        self.assertEqual(metadata.annotations, ("Ljava/lang/Deprecated;",))
        fields = {(item.name, item.descriptor): item for item in metadata.fields}
        self.assertIn(("FLAG", "I"), fields)
        self.assertIn(("name", "Ljava/lang/String;"), fields)
        methods = {(item.name, item.descriptor): item for item in metadata.methods}
        self.assertIn(("<init>", "()V"), methods)
        self.assertIn(("add", "(IJ)I"), methods)
        self.assertIn(("hello", "(Ljava/lang/String;)Ljava/lang/String;"), methods)
        self.assertEqual(methods[("hello", "(Ljava/lang/String;)Ljava/lang/String;")].annotations, ("Ljava/lang/Deprecated;",))

    def test_api_versions_are_attached_without_rewriting_class_metadata(self) -> None:
        versions = parse_android_api_versions(API_XML)
        self.assertEqual(versions.class_version("fixture/api/Example").since, 1)
        add = versions.method_version("fixture/api/Example", "add", "(IJ)I")
        self.assertEqual((add.since, add.deprecated, add.removed), (3, 5, None))
        self.assertEqual(versions.field_version("fixture/api/Example", "FLAG").since, 4)

        metadata = parse_classfile(EXAMPLE.read_bytes())
        plain = import_android_classes((metadata,))
        versioned = import_android_classes((metadata,), versions)
        self.assertNotEqual(plain.classes[0].class_contract.cid, versioned.classes[0].class_contract.cid)
        self.assertEqual(plain.classes[0].metadata, versioned.classes[0].metadata)

    def test_jar_import_is_canonical_under_zip_entry_order(self) -> None:
        names = ("fixture/api/Example.class", "fixture/api/Other.class")
        versions = parse_android_api_versions(API_XML)
        left = import_android_jar(jar_bytes(names), versions)
        right = import_android_jar(jar_bytes(tuple(reversed(names))), versions)
        self.assertEqual(
            [(item.metadata.internal_name, item.class_contract.cid) for item in left.classes],
            [(item.metadata.internal_name, item.class_contract.cid) for item in right.classes],
        )
        self.assertEqual([obj.cid for obj in left.semantic_objects], [obj.cid for obj in right.semantic_objects])
        self.assertEqual([item.name for item in left.query_members("fixture/api/Example", "he")], ["hello"])

    def test_imported_contracts_are_valid_content_addressed_target_carriers(self) -> None:
        imported = import_android_jar(
            jar_bytes(("fixture/api/Example.class", "fixture/api/Other.class")),
            parse_android_api_versions(API_XML),
        )
        module = object_with_refs(Kind.MODULE, imported.semantic_objects)
        root = object_with_refs(Kind.PROGRAM_ROOT, (module,))
        objects = (*imported.semantic_objects, module, root)
        reader = StoreReader(write_store(root.cid, objects))
        stats = verify_store(reader)
        self.assertEqual(stats.objects, len(objects))

    def test_multi_release_jar_requires_explicit_profile(self) -> None:
        out = io.BytesIO()
        with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_STORED) as archive:
            archive.writestr("META-INF/versions/17/fixture/api/Example.class", EXAMPLE.read_bytes())
        with self.assertRaisesRegex(ValueError, "multi-release"):
            import_android_jar(out.getvalue())

    def test_corrupt_classfile_and_duplicate_api_entries_reject(self) -> None:
        data = bytearray(EXAMPLE.read_bytes())
        data[0] ^= 1
        with self.assertRaisesRegex(ValueError, "not a Java class"):
            parse_classfile(bytes(data))
        with self.assertRaisesRegex(ValueError, "duplicate"):
            parse_android_api_versions(
                b'<api version="1"><class name="a/A" since="1"><field name="X"/><field name="X"/></class></api>'
            )


if __name__ == "__main__":
    unittest.main()


def test_api_profile_requires_explicit_runtime_guard_for_newer_member():
    from xax_android_sdk import AndroidApiProfile, verify_android_member_available
    from xax_compiler import XaxError

    versions = parse_android_api_versions(API_XML)
    profile = AndroidApiProfile(min_sdk=1, target_sdk=5, compile_sdk=5)
    with unittest.TestCase().assertRaises(XaxError) as caught:
        verify_android_member_available(
            versions, "fixture/api/Example", "method", "add", "(IJ)I", profile
        )
    assert caught.exception.diagnostic.code == "XAX.ANDROID.API_UNAVAILABLE"

    decision = verify_android_member_available(
        versions,
        "fixture/api/Example",
        "method",
        "add",
        "(IJ)I",
        profile,
        runtime_api_min=3,
    )
    assert decision.available and decision.runtime_min == 3


def test_api_profile_rejects_compile_sdk_too_old_and_removed_unbounded_api():
    from xax_android_sdk import AndroidApiProfile, ApiVersion, verify_android_api_available
    from xax_compiler import XaxError

    decision = verify_android_api_available(
        "fixture/api/NewApi.m()V",
        ApiVersion(6),
        AndroidApiProfile(min_sdk=6, target_sdk=6, compile_sdk=6),
    )
    assert decision.runtime_min == 6

    with unittest.TestCase().assertRaises(XaxError) as compile_old:
        verify_android_api_available(
            "fixture/api/NewerApi.m()V",
            ApiVersion(7),
            AndroidApiProfile(min_sdk=6, target_sdk=6, compile_sdk=6),
            runtime_api_min=7,
        )
    assert compile_old.exception.diagnostic.code in {"XAX.ANDROID.API_GUARD", "XAX.ANDROID.API_COMPILE"}

    profile = AndroidApiProfile(min_sdk=1, target_sdk=6, compile_sdk=6)
    with unittest.TestCase().assertRaises(XaxError) as removed:
        verify_android_api_available("fixture/api/OldApi.m()V", ApiVersion(1, removed=5), profile)
    assert removed.exception.diagnostic.code == "XAX.ANDROID.API_REMOVED"
    decision = verify_android_api_available(
        "fixture/api/OldApi.m()V",
        ApiVersion(1, removed=5),
        AndroidApiProfile(min_sdk=1, target_sdk=6, compile_sdk=6, device_api_max=4),
    )
    assert decision.runtime_max == 4
