"""Regenerate ``vector_runtime_pin.json`` from the pinned libxposed API artifact (ADR-178).

Validation tooling only; nothing here is part of XAX code generation.

Vector is the runtime XAX's Android/libxposed target is tested against; the
module ABI is the public libxposed API it implements.  This script records both:

* the Vector release (tag object and commit) and the libxposed-api /
  libxposed-service submodule commits that release builds against;
* the public API-102 member table, parsed with ``xax_android_sdk.parse_classfile``
  from ``classes.jar`` inside ``io.github.libxposed:api:102.0.0`` (SHA-256 pinned,
  the same artifact ``make_android_root.py`` dexes for ART verification).

``@SinceApi`` marks exactly the API-102 additions over API 101 at this revision;
``@InternalApi`` marks framework-only members a module must never call.

    python integration/android/vector/pin_libxposed_api.py --aar api-102.0.0.aar [--write]

With ``--api-checkout DIR`` (a libxposed-api checkout at the pinned commit) it
also checks that the Java sources the AAR was built from are byte-identical to
the revision Vector pins.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import sys
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[2] / "src"))

from xax_android_sdk import parse_classfile  # noqa: E402

PIN_PATH = HERE / "vector_runtime_pin.json"
ACC_PUBLIC, ACC_PROTECTED, ACC_SYNTHETIC = 0x0001, 0x0004, 0x1000
SINCE_API = "Lio/github/libxposed/annotation/SinceApi;"
INTERNAL_API = "Lio/github/libxposed/annotation/InternalApi;"

VECTOR = {
    "repository": "https://github.com/JingMatrix/Vector",
    "release": "v2.2",
    "tag_object": "8b8fa04dbd58f73bd5187fc6af02b65459b890cc",
    "commit": "88f8e1faa8b4e7ce20aefabe9c295cd746ea038e",
    "framework_name": "Vector",
    "magisk_module_id": "zygisk_vector",
    "minimum_release": "v2.2",
}
LIBXPOSED_API = {
    "repository": "https://github.com/JingMatrix/libxposed-api",
    "submodule_path": "xposed/libxposed",
    "commit": "39cac0845771547c9c67a3e3ce255af110a54a0e",
    "nearest_tag": "102.0.0",
    "tag_commit": "45e7c5cfe54725b6d828d8b7be65e22ce60c67e4",
    "commits_after_tag": ["39cac0845771547c9c67a3e3ce255af110a54a0e Specify requirement for at least one Java entry (#65)"],
    "lib_api": 102,
    "maven": "io.github.libxposed:api:102.0.0",
    "aar_url": "https://repo1.maven.org/maven2/io/github/libxposed/api/102.0.0/api-102.0.0.aar",
    "aar_sha256": "423484a6e1807e7a423c4b88fcd8176d104318259d91791877fed88fe91479d0",
    # Identical at 102.0.0 and at the commit Vector pins; only package-info.java
    # (documentation) differs between the two.
    "source_sha256": {
        "api/src/main/java/io/github/libxposed/api/XposedInterface.java": "e9e79d6c6dd22c9ea4dc6ab24f01bdbc3c7b5a8f05ff47e63a1f7a7d5f6080a4",
        "api/src/main/java/io/github/libxposed/api/XposedInterfaceWrapper.java": "59956c1a629cdd3d695adb776bd3260cc23f8bc7aea62640264bb47381507723",
        "api/src/main/java/io/github/libxposed/api/XposedModule.java": "c843e75ee90e994aee48135ae0a0ef0107a52a0212834762a2e43f2272587d71",
        "api/src/main/java/io/github/libxposed/api/XposedModuleInterface.java": "ce800c651ba8c0b7b847569b0de8225fcf261078c6e6ef6a478a6fba6150b530",
    },
}
LIBXPOSED_SERVICE = {
    "repository": "https://github.com/JingMatrix/libxposed-service",
    "submodule_path": "services/libxposed",
    "commit": "3318940876192e29cf6ab07637e899e22a87ebf0",
    "tag": "102.0.0",
    "maven": "io.github.libxposed:service:102.0.0",
    "aar_sha256": "a665e4af4638924047f5d5cb610553e15bc2c0ea2ce64a27afb6dee257ff014c",
    "aidl_sha256": {
        "interface/src/main/aidl/io/github/libxposed/service/IXposedService.aidl": "41d543a403ce8c843291efab72384e832e15b24e8ca164900a2a0ac270c8b8d0",
    },
    # Generated modules do not link the service library; Vector serves these
    # capability bits through XposedInterface.getFrameworkProperties().
    "framework_properties": {"PROP_CAP_SYSTEM": 1, "PROP_CAP_REMOTE": 2, "PROP_RT_API_PROTECTION": 4},
}


def _since(annotations: tuple[str, ...], class_since: int) -> int:
    return 102 if SINCE_API in annotations else class_since


def api_classes(classes_jar: bytes) -> list[dict[str, object]]:
    """The public API surface of ``classes.jar`` in canonical order."""
    rows = []
    with zipfile.ZipFile(io.BytesIO(classes_jar)) as archive:
        for name in sorted(archive.namelist()):
            if not name.endswith(".class"):
                continue
            view = parse_classfile(archive.read(name))
            class_since = _since(view.annotations, 101)
            members = []
            for item in (*view.fields, *view.methods):
                if not item.access_flags & (ACC_PUBLIC | ACC_PROTECTED) or item.access_flags & ACC_SYNTHETIC:
                    continue
                members.append({
                    "kind": item.kind,
                    "name": item.name,
                    "descriptor": item.descriptor,
                    "since": _since(item.annotations, class_since),
                    "internal": INTERNAL_API in item.annotations,
                    "static": bool(item.access_flags & 0x0008),
                })
            rows.append({
                "descriptor": "L" + view.internal_name + ";",
                "superclass": None if view.superclass is None else "L" + view.superclass + ";",
                "interfaces": ["L" + item + ";" for item in view.interfaces],
                "since": class_since,
                "members": members,
            })
    return rows


def table_digest(classes: list[dict[str, object]]) -> str:
    canonical = json.dumps(classes, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def build_pin(aar: bytes) -> dict[str, object]:
    digest = hashlib.sha256(aar).hexdigest()
    if digest != LIBXPOSED_API["aar_sha256"]:
        raise SystemExit(f"api AAR SHA-256 {digest} != pinned {LIBXPOSED_API['aar_sha256']}")
    with zipfile.ZipFile(io.BytesIO(aar)) as archive:
        classes_jar = archive.read("classes.jar")
    classes = api_classes(classes_jar)
    return {
        "schema": "xax-vector-runtime-pin-v1",
        "vector": VECTOR,
        "libxposed_api": {**LIBXPOSED_API, "classes_jar_sha256": hashlib.sha256(classes_jar).hexdigest()},
        "libxposed_service": LIBXPOSED_SERVICE,
        "api_table_sha256": table_digest(classes),
        "api_classes": classes,
    }


def check_sources(checkout: Path) -> None:
    for relative, expected in LIBXPOSED_API["source_sha256"].items():
        actual = hashlib.sha256((checkout / relative).read_bytes()).hexdigest()
        if actual != expected:
            raise SystemExit(f"{relative}: SHA-256 {actual} != pinned {expected}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--aar", type=Path, required=True)
    parser.add_argument("--api-checkout", type=Path)
    parser.add_argument("--write", action="store_true")
    arguments = parser.parse_args()
    if arguments.api_checkout is not None:
        check_sources(arguments.api_checkout)
    pin = build_pin(arguments.aar.read_bytes())
    text = json.dumps(pin, indent=2, sort_keys=True) + "\n"
    if arguments.write:
        PIN_PATH.write_text(text, encoding="utf-8")
        print(PIN_PATH)
        return 0
    committed = PIN_PATH.read_text(encoding="utf-8") if PIN_PATH.exists() else ""
    if committed != text:
        print("vector_runtime_pin.json is stale; rerun with --write", file=sys.stderr)
        return 1
    print("vector_runtime_pin.json matches the pinned artifact")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
