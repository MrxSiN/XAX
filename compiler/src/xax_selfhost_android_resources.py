"""S15e.6c (ADR-336): the binary Android resources (``xax_manifest.emit_binary_manifest``, ``xax_resources.emit_resources_arsc``)
as an XAX program.

One program, two modes.  Mode 0 is the binary ``AndroidManifest.xml``: the element tree of the manifest specification
(``uses-sdk``, the platform declarations' permissions and features, the application with its activity and launcher
filter, the receivers and services sorted by their class names, the declared components), the resource map (the base
attributes, ``debuggable`` when the manifest is, the declaration attributes the tree uses) in resource-ID order, the
UTF-8 string pool (the resource names first, then every other string sorted by its bytes), the namespace, the elements
with their attributes sorted (no namespace first, then by resource ID, then by name) and their typed values.  Mode 1 is
the bounded ``resources.arsc``: the value pool (the distinct values sorted by their bytes), the package with its
UTF-16 name, the type and key pools, the type spec and the default-configuration type chunk.

The Python front doors keep the specifications' own checks (they are host errors) and the carriers' decoding, and ask
this program first; ``XAX_GENERAL_FRONTEND_DIFF=1`` compares the two.  A string past the pools' 15-bit length bound (the
bootstrap's error) makes the program decline.

Input (64-bit words; a string is its UTF-8 byte count, then one byte per word):
mode 0: package, activity class, version code, min SDK, target SDK, launcher, debuggable; the application class
(present flag, then the string); the receivers (count; each class, exported, action present flag, then the action); the
services (count; each class, exported); the declarations present flag, then the permissions (count; each name, max SDK,
never-for-location), the features (count; each name, required) and the components (count; each kind (0 service,
1 receiver), class, exported, foreground present flag, foreground flags, the action count and the actions).
mode 1: package, the entry count, each entry's name and value (the specification's order).
Output: the status (1) and the image record ``[1, 0, length, bytes packed eight to a word]`` at ``IMAGE_AT``.
"""

from __future__ import annotations

from xax_native import bootstrap_dir
from xax_selfhost_facts import E
from xax_selfhost_general_image import IMAGE_AT
from xax_selfhost_views_backend import NativeProgram, _call

STORE_PATH = bootstrap_dir() / "xax_android_resources.xax"
OUT = IMAGE_AT + 3  # the packed bytes
STATE_AT = 110 << 20
G_STR = STATE_AT + 16  # the constant strings' handles

ANDROID_URI = "http://schemas.android.com/apk/res/android"
# The resource map's candidates in resource-ID order: (name, ID, when: 0 always, 1 a debuggable manifest, 2 used).
RESOURCE_ATTRIBUTES = (
    ("name", 0x01010003, 0), ("hasCode", 0x0101000C, 0), ("debuggable", 0x0101000F, 1), ("exported", 0x01010010, 0),
    ("minSdkVersion", 0x0101020C, 0), ("versionCode", 0x0101021B, 0), ("targetSdkVersion", 0x01010270, 0),
    ("maxSdkVersion", 0x01010271, 2), ("required", 0x0101028E, 2), ("foregroundServiceType", 0x01010599, 2),
    ("usesPermissionFlags", 0x01010644, 2),
)
CONSTANTS = (
    "android", ANDROID_URI, "manifest", "package", "uses-sdk", "uses-permission", "uses-feature", "application",
    "activity", "intent-filter", "action", "category", "receiver", "service", "android.intent.action.MAIN",
    "android.intent.category.LAUNCHER", "string", *(name for name, _id, _when in RESOURCE_ATTRIBUTES),
)
CONST = {text: k for k, text in enumerate(CONSTANTS)}


def put(e: E, byte):
    _call(e, "ar_put", byte)


def le(e: E, value, n: int):
    """``n`` little-endian bytes of ``value``."""
    e.var("le_v", value)
    for k in range(n):
        put(e, e.and_(e.udiv(e.p["le_v"], 1 << (8 * k)) if k else e.p["le_v"], 255))


def pos(e: E):
    return e.ld(IMAGE_AT + 2)


def S(e: E, text: str):
    return e.ld(G_STR + CONST[text])


_PROGRAM = NativeProgram(STORE_PATH, "android-resources")
load_resources_program = _PROGRAM.load
OPT_OUT = "XAX_ANDROID_RESOURCES_PYTHON"


def _run(words: list[int], required: bool) -> bytes | None:
    import os

    import xax_native

    native = None if os.environ.get(OPT_OUT) == "1" else _PROGRAM.native(OPT_OUT)
    data = None
    if native is not None:
        def collect(read):
            (status,) = read(0, 1)
            if status != 1:
                return None
            head = read(IMAGE_AT, 3)
            packed = read(IMAGE_AT + 3, (head[2] + 7) // 8)
            return b"".join(word.to_bytes(8, "little") for word in packed)[:head[2]]

        data = native.run(words, collect)
        if data is None:
            xax_native.declined("android-resources", 1)
    if data is None and required:
        raise RuntimeError("the XAX Android resources program is unavailable or declined")
    return data


def _text(value: str) -> list[int]:
    raw = value.encode("utf-8")
    return [len(raw), *raw]


def manifest_with_xax(spec, *, receivers=(), services=(), application=None, declarations=None, required: bool = False) -> bytes | None:
    """The binary manifest the XAX program writes for checked specifications, or None where it cannot run or declines
    (unless ``required``)."""
    try:
        # S15e.6i.3 (ADR-359): the attributes are ``int()`` of the values, as ``_start_element`` writes them (a libxposed
        # JVM record may give floats or booleans).
        words = [0, *_text(spec.package_name), *_text(spec.activity_class), int(spec.version_code), int(spec.min_sdk), int(spec.target_sdk),
                 int(bool(spec.launcher)), int(bool(spec.debuggable))]
        words += [0] if application is None else [1, *_text(application.class_name)]
        words.append(len(receivers))
        for item in receivers:
            words += [*_text(item.class_name), int(bool(item.exported))]
            words += [0] if item.action is None else [1, *_text(item.action)]
        words.append(len(services))
        for item in services:
            words += [*_text(item.class_name), int(bool(item.exported))]
        if declarations is None:
            words.append(0)
        else:
            words += [1, len(declarations.permissions)]
            for item in declarations.permissions:
                words += [*_text(item.name), item.max_sdk, int(bool(item.never_for_location))]
            words.append(len(declarations.features))
            for item in declarations.features:
                words += [*_text(item.name), int(bool(item.required))]
            words.append(len(declarations.components))
            for item in declarations.components:
                if item.kind not in ("service", "receiver"):
                    return None
                words += [0 if item.kind == "service" else 1, *_text(item.class_name), int(bool(item.exported)),
                          int(bool(item.foreground_types)), item.foreground_flags, len(item.actions)]
                for action in item.actions:
                    words += _text(action)
    except UnicodeEncodeError:
        return None  # the bootstrap's own error
    if any(not 0 <= word < 1 << 63 for word in words):
        return None
    return _run(words, required)


def arsc_with_xax(spec, *, required: bool = False) -> bytes | None:
    """The ``resources.arsc`` the XAX program writes for a checked specification, or None where it cannot run or
    declines (unless ``required``)."""
    try:
        words = [1, *_text(spec.package_name), len(spec.strings)]
        for item in spec.strings:
            words += [*_text(item.name), *_text(item.value)]
    except UnicodeEncodeError:
        return None
    return _run(words, required)
