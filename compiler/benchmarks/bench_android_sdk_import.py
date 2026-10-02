"""Deterministic evidence for direct Android SDK class/API metadata import."""
from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import zipfile

from xax_android_sdk import (
    AndroidApiProfile,
    import_android_jar,
    parse_android_api_versions,
    verify_android_member_available,
)

_ROOT = Path(__file__).parents[1]
_FIXTURES = _ROOT / "tests" / "fixtures"
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


def _jar(order: tuple[str, ...]) -> bytes:
    payloads = {
        "fixture/api/Example.class": (_FIXTURES / "android_sdk_example.class").read_bytes(),
        "fixture/api/Other.class": (_FIXTURES / "android_sdk_other.class").read_bytes(),
    }
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_STORED) as archive:
        for name in order:
            info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_STORED
            archive.writestr(info, payloads[name])
    return out.getvalue()


def collect_evidence() -> dict[str, object]:
    versions = parse_android_api_versions(API_XML)
    names = ("fixture/api/Example.class", "fixture/api/Other.class")
    forward = import_android_jar(_jar(names), versions)
    reverse = import_android_jar(_jar(tuple(reversed(names))), versions)
    canonical = [obj.cid.hex() for obj in forward.semantic_objects]
    add = verify_android_member_available(
        versions,
        "fixture/api/Example",
        "method",
        "add",
        "(IJ)I",
        AndroidApiProfile(min_sdk=1, target_sdk=5, compile_sdk=5),
        runtime_api_min=3,
    )
    classes = []
    for imported in forward.classes:
        classes.append({
            "internal_name": imported.metadata.internal_name,
            "superclass": imported.metadata.superclass,
            "interfaces": list(imported.metadata.interfaces),
            "class_contract_cid": imported.class_contract.cid.hex(),
            "member_contract_cids": [item.cid.hex() for item in imported.member_contracts],
            "fields": [[item.name, item.descriptor] for item in imported.metadata.fields],
            "methods": [[item.name, item.descriptor] for item in imported.metadata.methods],
        })
    return {
        "schema": "xax-android-sdk-import-evidence-v1",
        "inputs": {
            "class_sha256": {
                name: hashlib.sha256((_FIXTURES / Path(name).name.replace("Example.class", "android_sdk_example.class").replace("Other.class", "android_sdk_other.class")).read_bytes()).hexdigest()
                for name in names
            },
            "api_versions_xml_sha256": hashlib.sha256(API_XML).hexdigest(),
        },
        "direct_parser": {"classfile": True, "jar_zip": True, "api_versions_xml": True},
        "external_compiler_invocations": 0,
        "semantic_object_count": len(forward.semantic_objects),
        "semantic_object_cids": canonical,
        "zip_entry_order_independent": canonical == [obj.cid.hex() for obj in reverse.semantic_objects],
        "classes": classes,
        "query_example": {
            "needle": "he",
            "matches": [[item.name, item.descriptor] for item in forward.query_members("fixture/api/Example", "he")],
        },
        "api_guard_example": {
            "entity": "fixture/api/Example.add(IJ)I",
            "declared_since": add.version.since,
            "declared_deprecated": add.version.deprecated,
            "reachable_runtime_min": add.runtime_min,
            "reachable_runtime_max": add.runtime_max,
            "available": add.available,
        },
        "limitations": {
            "official_platform_jar_runtime_validation": "not run on this host because no Android SDK platform JAR is installed",
            "multi_release_jar": "hard rejected until an explicit version-selection profile exists",
            "generic_signature_semantics": "descriptor/access/annotation identity is imported; generic Signature attributes are not yet semanticized",
        },
    }


def main() -> None:
    evidence = collect_evidence()
    path = Path(__file__).with_name("android_sdk_import_evidence.json")
    path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(path)
    print(json.dumps(evidence, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
