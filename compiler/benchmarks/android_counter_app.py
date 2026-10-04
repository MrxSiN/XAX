"""U1 workload 4: an Android app with state, file I/O, and lifecycle (ADR-111).

``xax.counter`` shows a button whose text is a count.  ``onCreate`` restores
the count from ``<files dir>/xax.counter``; each tap increments it and writes it
back; the count survives the process being killed.  Every read, write,
increment, and descriptor close is XAX native code (``xax_android_counter``);
the generated DEX only obtains the descriptor and displays the returned number.

Run ``python -m benchmarks.android_counter_app`` from ``compiler/`` to rebuild
``android_counter_activity.apk``.  Device check: ``integration/android/validate_counter_apk.sh``;
``--device`` also runs it against the connected ``adb`` target and records the
result, with the target's identity, under ``device`` in the evidence.  An emulator
run is recorded as such (``hardware: false``): it is correctness evidence only.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

from xax_android_counter import counter_activity_semantics, counter_dex_specs, counter_library, decode_counter_activity, jni_symbols
from xax_apk import build_unsigned_apk
from xax_apk_signing import sign_apk_v2
from xax_dex import emit_dex039_bridge
from xax_manifest import AndroidManifestSpec, android_manifest_semantics, emit_binary_manifest_from_semantics

HERE = Path(__file__).resolve().parent
APK = HERE / "android_counter_activity.apk"
EVIDENCE = HERE / "android_counter_evidence.json"
LOADER = HERE.parent / "integration/android/counter_native_loader.c"
EXPECTED_NATIVE = "XAX_COUNTER seen=0,1,2,3,3,4 file_bytes=8 stored=4 fds_closed=1"
NATIVE_LIBRARY = "xaxcounter"
SEMANTICS = dict(package_name="xax.counter", activity_class="xax.counter.CounterActivity",
                 listener_class="xax.counter.CounterClickListener", state_file="xax.counter")


def build() -> dict[str, bytes]:
    from benchmarks.bench_android_apk import _signing_capability

    description = decode_counter_activity(counter_activity_semantics(**SEMANTICS))
    activity_spec, listener_spec = counter_dex_specs(description, NATIVE_LIBRARY)
    activity_dex, listener_dex = emit_dex039_bridge(activity_spec), emit_dex039_bridge(listener_spec)
    library = counter_library(description, soname=f"lib{NATIVE_LIBRARY}.so".encode())
    manifest = emit_binary_manifest_from_semantics(android_manifest_semantics(AndroidManifestSpec(
        package_name=description.package_name, activity_class=description.activity_class,
        min_sdk=28, target_sdk=35, version_code=1, launcher=True,
    )))
    unsigned = build_unsigned_apk(manifest, activity_dex, native_libraries={f"lib{NATIVE_LIBRARY}.so": library}, extra_entries={"classes2.dex": listener_dex})
    return {
        "manifest": manifest, "activity_dex": activity_dex, "listener_dex": listener_dex, "library": library,
        "unsigned": unsigned, "signed": sign_apk_v2(unsigned, _signing_capability()),
        "symbols": b",".join(jni_symbols(description)),
    }


def run_native(apk: Path) -> str:
    """The APK's own library under Android's linker and bionic: restore, three clicks, restart, click."""
    from benchmarks import bench_android_bionic as bionic

    symbols = [item.decode() for item in build()["symbols"].split(b",")]
    with tempfile.TemporaryDirectory() as directory:
        work = Path(directory)
        with zipfile.ZipFile(apk) as archive:
            (work / "lib.so").write_bytes(archive.read(f"lib/arm64-v8a/lib{NATIVE_LIBRARY}.so"))
        subprocess.run([bionic._clang(28), "-O2", "-fPIE", "-pie", str(LOADER), "-ldl", "-o", str(work / "loader")], check=True, capture_output=True)
        Path("/data/local/tmp").mkdir(parents=True, exist_ok=True)
        completed = bionic._run(work / "loader", "./lib.so", "/data/local/tmp/xax.counter.state", *symbols, cwd=work)
    return completed.stdout.strip()


ORACLE = HERE.parent / "integration/android/validate_counter_apk.sh"
ORACLE_PASSED = "XAX counter Activity validation passed"
_DEVICE_PROPERTIES = ("ro.build.fingerprint", "ro.build.version.sdk", "ro.product.cpu.abilist", "ro.dalvik.vm.native.bridge", "ro.kernel.qemu", "ro.boot.qemu", "ro.hw_timeout_multiplier")


def run_device() -> dict:
    """Run the device oracle on the connected ``adb`` target and describe the target."""
    def prop(name: str) -> str:
        return subprocess.run(["adb", "shell", "getprop", name], capture_output=True, text=True, timeout=120).stdout.strip()

    properties = {name: prop(name) for name in _DEVICE_PROPERTIES}
    completed = subprocess.run(["bash", str(ORACLE)], capture_output=True, text=True, timeout=3600)
    output = [line for line in completed.stdout.splitlines() if line.startswith(("ok:", "note:", ORACLE_PASSED))]
    output += [f"stderr: {line}" for line in completed.stderr.splitlines()[-5:]] if completed.returncode else []
    emulated = "1" in (properties["ro.kernel.qemu"], properties["ro.boot.qemu"])
    native_abi = properties["ro.product.cpu.abilist"].split(",")[0]
    return {
        "label": "EXECUTED" if completed.returncode == 0 and ORACLE_PASSED in completed.stdout else "FAILED",
        "oracle": "integration/android/validate_counter_apk.sh",
        "apk_sha256": hashlib.sha256(APK.read_bytes()).hexdigest(),
        "target": properties,
        "hardware": not emulated,
        "arm64_native": native_abi == "arm64-v8a",
        "output": output,
        "passed": completed.returncode == 0,
    }


def evidence(device: dict | None = None) -> dict:
    from benchmarks import bench_android_art_verify as art, bench_android_official_tools as official

    official_row = official.validate_apk(APK)
    art.WORK.mkdir(parents=True, exist_ok=True)
    copy = art.WORK / APK.name
    shutil.copy(APK, copy)
    classes = art.verify(copy)
    native = run_native(APK)
    artifacts = build()
    return {
        "format": "xax-android-counter-evidence-v1",
        "decision": "ADR-111",
        "apk_sha256": hashlib.sha256(APK.read_bytes()).hexdigest(),
        "sizes": {name: len(artifacts[name]) for name in ("activity_dex", "listener_dex", "library", "signed")},
        "official_tools": {"label": "STRUCTURAL", "checks": official_row["checks"], "passed": official_row["passed"]},
        "art_verify": {"label": "EXECUTED", "classes": classes, "passed": set(classes.values()) == {"Verified"}},
        "native_under_bionic": {"label": "EXECUTED", "expected": EXPECTED_NATIVE, "observed": native, "passed": native == EXPECTED_NATIVE},
        "device": device or _committed_device() or {"label": "UNEXECUTED", "oracle": "integration/android/validate_counter_apk.sh"},
    }


def _committed_device() -> dict | None:
    """Keep a recorded device run while it is still a run of the committed APK."""
    if not EVIDENCE.exists():
        return None
    device = json.loads(EVIDENCE.read_text(encoding="utf-8")).get("device", {})
    current = device.get("apk_sha256") == hashlib.sha256(APK.read_bytes()).hexdigest()
    return device if current and device.get("label") == "EXECUTED" else None


def main() -> int:
    artifacts = build()
    APK.write_bytes(artifacts["signed"])
    result = evidence(run_device() if "--device" in sys.argv[1:] else None)
    EVIDENCE.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({key: result[key]["passed"] for key in ("official_tools", "art_verify", "native_under_bionic")}))
    for name in ("activity_dex", "listener_dex", "library", "signed"):
        print(f"{name}: {len(artifacts[name])} bytes {hashlib.sha256(artifacts[name]).hexdigest()[:16]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
