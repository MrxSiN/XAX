"""General managed classes (ADR-199): structural evidence and an optional device oracle.

The fixture APK is built only from ``android-managed-class-v1`` carriers, one
manifest, and XAX JNI exports:

* ``xax.managed.MainActivity`` (extends Activity): ``onCreate``/``onResume``/``onPause``
  call super and then XAX; ``onKeyDown(int, KeyEvent)`` returns XAX's
  ``keyCode == KEYCODE_VOLUME_UP`` (a ``jboolean`` result through the platform);
* ``xax.managed.SurfaceCallback`` (implements ``SurfaceHolder.Callback``): three
  void callbacks, including ``surfaceChanged(SurfaceHolder, int, int, int)``;
* ``xax.managed.WideProbe``: ``stamp(long) -> long``, the wide range form.

``--device`` (``ANDROID_SERIAL`` must name the device) installs the signed APK and
checks: the Activity resumes; VOLUME_UP is consumed by the XAX result, so media
volume does not move, while in a control build whose XAX result is false the
platform's PhoneWindow fallback changes it (the volume is restored after each
check); three HOME/relaunch cycles keep one process
alive (a missing super call would throw ``SuperNotCalledException``).  The package is uninstalled
afterwards.

    python -m benchmarks.bench_android_managed [--device]
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from xax_android_managed import AndroidManagedClass, AndroidManagedMethod, android_managed_class_semantics
from xax_build import ArtifactKind, build, build_profile, build_request, package, resolve_packages, snapshot_store, trust_policy
from xax_compiler import IntCompare, Kind, Operation, android_arm64_shared_general_target, android_export_symbol, bits_type, object_with_refs
from xax_dex import inspect_dex
from xax_graph_builder import GraphBuilder
from xax_jni import JniReferenceKind, jni_env_pointer_type, jni_reference_type, jni_short_native_symbol, jni_type_objects
from xax_manifest import AndroidManifestSpec, android_manifest_semantics

EVIDENCE = Path(__file__).with_name("android_managed_evidence.json")
PACKAGE = "xax.managed"
APP = f"app:{PACKAGE}".encode()
BOOT = b"android.boot"
KEYCODE_VOLUME_UP = 24

ACTIVITY = AndroidManagedClass("Lxax/managed/MainActivity;", "Landroid/app/Activity;", (), (
    AndroidManagedMethod("onCreate", "(Landroid/os/Bundle;)V", "protected", True),
    AndroidManagedMethod("onResume", "()V", "protected", True),
    AndroidManagedMethod("onPause", "()V", "protected", True),
    AndroidManagedMethod("onKeyDown", "(ILandroid/view/KeyEvent;)Z"),
))
SURFACE = AndroidManagedClass("Lxax/managed/SurfaceCallback;", "Ljava/lang/Object;", ("Landroid/view/SurfaceHolder$Callback;",), (
    AndroidManagedMethod("surfaceCreated", "(Landroid/view/SurfaceHolder;)V"),
    AndroidManagedMethod("surfaceChanged", "(Landroid/view/SurfaceHolder;III)V"),
    AndroidManagedMethod("surfaceDestroyed", "(Landroid/view/SurfaceHolder;)V"),
))
WIDE = AndroidManagedClass("Lxax/managed/WideProbe;", "Ljava/lang/Object;", (), (AndroidManagedMethod("stamp", "(J)J"),))
CLASSES = (ACTIVITY, SURFACE, WIDE)


def _reference(descriptor: str):
    name = descriptor[1:-1].replace("/", ".").encode()
    return jni_reference_type(JniReferenceKind.BORROWED, name, loader_domain=APP if name.startswith(b"xax.") else BOOT)


def _export(owner: AndroidManagedClass, method: AndroidManagedMethod, consumed_key: int = KEYCODE_VOLUME_UP):
    """The XAX function for one forwarded method: empty for void, the key test for onKeyDown, identity for stamp."""
    from xax_android_sdk import parse_jvm_method_descriptor

    parameters, result = parse_jvm_method_descriptor(method.descriptor)
    widths = {"Z": 8, "I": 32, "J": 64}
    types = [jni_env_pointer_type(), _reference(owner.class_descriptor),
             *(bits_type(widths[item]) if item in widths else _reference(item) for item in parameters)]
    graph = GraphBuilder()
    block = graph.block(*types)
    if method.name == "onKeyDown":
        back = block.op1(Operation.INT_COMPARE, (block.params[2], block.const(bits_type(32), consumed_key)), bits_type(1), attributes=(IntCompare.EQ,))
        consumed, ignored = graph.block(), graph.block()
        block.cbr(back, consumed, (), ignored, ())
        consumed.ret(consumed.const(bits_type(8), 1))
        ignored.ret(ignored.const(bits_type(8), 0))
        returns = (bits_type(8),)
    elif method.name == "stamp":
        block.ret(block.params[2])
        returns = (bits_type(64),)
    else:
        block.ret()
        returns = ()
    function = graph.function(types, returns)
    symbol = jni_short_native_symbol(owner.class_descriptor, method.native_name)
    return function, android_export_symbol(function, symbol), graph


def build_fixture(consumed_key: int = KEYCODE_VOLUME_UP):
    """``consumed_key`` other than VOLUME_UP builds the negative control, whose onKeyDown returns false for it."""
    target = android_arm64_shared_general_target()
    manifest = android_manifest_semantics(AndroidManifestSpec(PACKAGE, "xax.managed.MainActivity", min_sdk=28, target_sdk=35))
    carriers = tuple(android_managed_class_semantics(item) for item in CLASSES)
    functions, exports, objects = [], [], []
    for owner in CLASSES:
        for method in owner.methods:
            function, export, graph = _export(owner, method, consumed_key)
            functions.append(function)
            exports.append(export)
            objects.extend(graph.objects.values())
    entry = functions[0]  # MainActivity.onCreate's export (methods are sorted: onCreate first)
    module = object_with_refs(Kind.MODULE, (*functions, *carriers, manifest, *exports))
    app = package(b"android-managed-fixture", (module,), build_entries=((b"apk", entry),))
    profile, policy = build_profile(), trust_policy()
    request = build_request(app, b"apk", target, profile, requested_artifacts=(ArtifactKind.ANDROID_UNSIGNED_APK,))
    references = jni_type_objects(tuple(
        (JniReferenceKind.BORROWED, name.encode(), APP if name.startswith("xax.") else BOOT)
        for name in ("xax.managed.MainActivity", "xax.managed.SurfaceCallback", "xax.managed.WideProbe",
                     "android.os.Bundle", "android.view.KeyEvent", "android.view.SurfaceHolder")
    ))
    everything = (*references, *objects, *functions, *exports, *carriers, manifest, module, app, target, profile, policy, request)
    resolution = resolve_packages(request, everything, policy, b"android-managed-resolver-v1")
    return build(snapshot_store(resolution, everything), request.cid), carriers


def _adb(*arguments: str, check: bool = True) -> str:
    completed = subprocess.run(["adb", *arguments], capture_output=True, text=True, timeout=300)
    if check and completed.returncode:
        raise RuntimeError(f"adb {' '.join(arguments)}: {completed.stderr.strip() or completed.stdout.strip()}")
    return completed.stdout.replace("\r", "")


def _resumed() -> bool:
    return f"{PACKAGE}/.MainActivity" in _adb("shell", "dumpsys activity activities | grep -E 'topResumedActivity|mResumedActivity'", check=False)


def _install(apk: bytes) -> None:
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "managed.apk"
        path.write_bytes(apk)
        _adb("uninstall", PACKAGE, check=False)
        _adb("install", "-t", str(path))


def _media_volume() -> int:
    return int(re.search(r"volume is (\d+)", _adb("shell", "cmd", "media_session", "volume", "--stream", "3", "--get"))[1])


def _volume_key_changes_volume() -> bool:
    """Two VOLUME_UP presses (the first only opens the panel) move media volume unless the Activity consumes them."""
    before = _media_volume()
    for _ in range(2):
        _adb("shell", "input", "keyevent", str(KEYCODE_VOLUME_UP))
        time.sleep(1)
    changed = _media_volume() != before
    for _ in range(4):  # leave the device as found; `volume --set` is ignored on some builds, VOLUME_DOWN is never consumed here
        if _media_volume() <= before:
            break
        _adb("shell", "input", "keyevent", "25")
        time.sleep(1)
    if _media_volume() != before:
        raise RuntimeError(f"could not restore media volume to {before}")
    return changed


def measure_device(apk: bytes, control: bytes) -> dict:
    if not os.environ.get("ANDROID_SERIAL"):
        raise SystemExit("set ANDROID_SERIAL to the device to use")
    checks = {}
    # Negative control: onKeyDown returns false for VOLUME_UP, so PhoneWindow adjusts the volume.
    _install(control)
    _adb("shell", "am", "start", "-W", "-n", f"{PACKAGE}/.MainActivity")
    time.sleep(1)
    checks["control_volume_key_reaches_platform"] = _resumed() and _volume_key_changes_volume()
    _install(apk)
    _adb("logcat", "-c", check=False)
    _adb("shell", "am", "start", "-W", "-n", f"{PACKAGE}/.MainActivity")
    time.sleep(1)
    pid = _adb("shell", "pidof", PACKAGE).strip()
    checks["resumed"] = _resumed()
    checks["volume_key_consumed_by_xax_result"] = checks["resumed"] and not _volume_key_changes_volume()
    cycles = 0
    for _ in range(3):
        _adb("shell", "input", "keyevent", "3")  # HOME: onPause
        time.sleep(1)
        _adb("shell", "am", "start", "-W", "-n", f"{PACKAGE}/.MainActivity")  # onResume
        time.sleep(1)
        cycles += _resumed() and _adb("shell", "pidof", PACKAGE).strip() == pid
    checks["pause_resume_cycles_same_process"] = cycles
    log = _adb("logcat", "-d", "-v", "brief", check=False)
    checks["no_fatal_exception"] = not re.search(rf"FATAL EXCEPTION|SuperNotCalledException|UnsatisfiedLinkError.*{PACKAGE}", log)
    _adb("uninstall", PACKAGE, check=False)
    passed = all(checks[key] for key in ("control_volume_key_reaches_platform", "resumed", "volume_key_consumed_by_xax_result", "no_fatal_exception")) and cycles == 3
    return {
        "label": "EXECUTED",
        "hardware": _adb("shell", "getprop", "ro.kernel.qemu").strip() != "1",
        "device": {name: _adb("shell", "getprop", name).strip() for name in ("ro.product.model", "ro.build.fingerprint", "ro.build.version.sdk")},
        "checks": checks,
        "passed": passed,
    }


def evidence(device: dict | None = None) -> dict:
    result, carriers = build_fixture()
    if result.artifact != build_fixture()[0].artifact:
        raise AssertionError("managed fixture is not deterministic")
    import io
    import zipfile

    with zipfile.ZipFile(io.BytesIO(result.artifact)) as archive:
        dex = {name: inspect_dex(archive.read(name)) for name in sorted(archive.namelist()) if name.endswith(".dex")}
        names = sorted(archive.namelist())
    apk_sha = hashlib.sha256(result.artifact).hexdigest()
    if device is None and EVIDENCE.exists():
        committed = json.loads(EVIDENCE.read_text(encoding="utf-8"))
        if committed.get("apk_sha256") == apk_sha:
            device = committed.get("device")
    return {
        "schema": "xax-android-managed-evidence-v1",
        "decision": "ADR-199",
        "label": "STRUCTURAL",
        "apk_sha256": apk_sha,
        "apk_bytes": len(result.artifact),
        "entries": names,
        "carrier_cids": [carrier.cid.hex() for carrier in carriers],
        "dex": {name: {"classes": [item.class_descriptor for item in view.classes] if hasattr(view, "classes") else None, "bytes": view.file_size}
                for name, view in dex.items()},
        "jni_exports": sorted(symbol.decode() for owner in CLASSES for symbol in owner.symbols()),
        "device": device or {"label": "UNEXECUTED", "note": "python -m benchmarks.bench_android_managed --device with ANDROID_SERIAL"},
    }


def main() -> int:
    from benchmarks.bench_android_apk import _signing_capability
    from xax_apk_signing import sign_apk_v2

    device = None
    if "--device" in sys.argv[1:]:
        signer = _signing_capability()
        device = measure_device(sign_apk_v2(build_fixture()[0].artifact, signer), sign_apk_v2(build_fixture(0x7FFF)[0].artifact, signer))
    result = evidence(device)
    EVIDENCE.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({key: result[key] for key in ("apk_sha256", "apk_bytes", "entries")}, indent=2))
    print("device:", json.dumps(result["device"], indent=1))
    return 0 if result["device"].get("passed", True) else 1


if __name__ == "__main__":
    sys.exit(main())
