"""ART's own verifier over every committed XAX APK (ADR-108).

Runs Android 14's ``dex2oat64 --compiler-filter=verify`` against the device's
framework boot classpath and precompiled arm64 boot image, then reads each
class's verification status back with ``oatdump``.  Both tools come from the
official system image and run under ``qemu-aarch64`` user mode
(``integration/android/make_android_root.py`` builds the root).  libxposed
modules are verified with the libxposed API 102.0.0 (Maven Central) as their
parent class loader, which is how the framework supplies it.

A negative control patches the generated click listener so ``TextView.setText``
is invoked on a plain ``View`` (the ``check-cast`` becomes two ``nop``s, and the DEX
checksum is fixed).  ART must not report that class as ``Verified``.

This is ART verification, not execution: no class is initialized or run.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import zipfile
import zlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
EVIDENCE = HERE / "android_art_verify_evidence.json"
PREFIX = Path(os.environ.get("XAX_ANDROID_PREFIX", "/opt/android"))
ROOT = PREFIX / "root"
LIBXPOSED_API = PREFIX / "libxposed/libxposed-api-102-dex.jar"
QEMU = shutil.which("qemu-aarch64-static") or shutil.which("qemu-aarch64")
# The bootclasspath recorded in the system image's own boot.oat header.
BOOT_CLASSPATH = ":".join((
    "/apex/com.android.art/javalib/core-oj.jar", "/apex/com.android.art/javalib/core-libart.jar",
    "/apex/com.android.art/javalib/okhttp.jar", "/apex/com.android.art/javalib/bouncycastle.jar",
    "/apex/com.android.art/javalib/apache-xml.jar", "/system/framework/framework.jar",
    "/system/framework/framework-graphics.jar", "/system/framework/ext.jar", "/system/framework/telephony-common.jar",
    "/system/framework/voip-common.jar", "/system/framework/ims-common.jar", "/apex/com.android.i18n/javalib/core-icu4j.jar",
))
# The guest sees host paths that do not exist under the root; qemu -L falls back to the host.
WORK = Path("/data/local/tmp/xax-art-verify")
_ENVIRONMENT = {
    **os.environ,
    "ANDROID_ROOT": "/system", "ANDROID_ART_ROOT": "/apex/com.android.art", "ANDROID_I18N_ROOT": "/apex/com.android.i18n",
    "ANDROID_TZDATA_ROOT": "/apex/com.android.tzdata", "ANDROID_DATA": "/data",
    "LD_LIBRARY_PATH": ":".join(f"/apex/{name}/lib64" for name in ("com.android.art", "com.android.runtime", "com.android.os.statsd", "com.android.i18n")) + ":/system/lib64",
}


def available() -> bool:
    return QEMU is not None and (ROOT / "apex/com.android.art/bin/dex2oat64").exists()


def _art(tool: str, *arguments: str) -> subprocess.CompletedProcess:
    command = [QEMU, "-L", str(ROOT), str(ROOT / "apex/com.android.art/bin" / tool), *arguments]
    return subprocess.run(command, capture_output=True, text=True, env=_ENVIRONMENT, timeout=600, check=False)


def verify(path: Path, class_loader_context: str | None = None) -> dict[str, str]:
    """``{class descriptor: ART class status}`` for a DEX or APK at ``path`` (under ``WORK``)."""
    odex = path.with_suffix(".odex")
    arguments = [
        f"--runtime-arg", f"-Xbootclasspath:{BOOT_CLASSPATH}", "--runtime-arg", f"-Xbootclasspath-locations:{BOOT_CLASSPATH}",
        "--boot-image=/system/framework/boot.art", f"--dex-file={path}", f"--dex-location={path}", f"--oat-file={odex}",
        "--compiler-filter=verify", "--instruction-set=arm64",
    ]
    if class_loader_context:
        arguments.append(f"--class-loader-context={class_loader_context}")
    compiled = _art("dex2oat64", *arguments)
    if compiled.returncode:
        raise RuntimeError(f"dex2oat64 failed for {path.name}: {compiled.stderr.strip()[-400:]}")
    statuses = {}
    for line in _art("oatdump", f"--oat-file={odex}", "--no-disassemble").stdout.splitlines():
        if "(type_idx=" in line:
            descriptor = line.split(": ", 1)[1].split(" ", 1)[0]
            statuses[descriptor] = line.rsplit("(", 2)[-2].rstrip(") ")
    return statuses


def _ill_typed_listener() -> bytes:
    """The minimal Activity's listener DEX with its ``check-cast`` replaced by two ``nop``s."""
    with zipfile.ZipFile(HERE / "android_minimal_activity.apk") as apk:
        dex = bytearray(apk.read("classes2.dex"))
    position = dex.index(bytes.fromhex("1f020200"))  # check-cast v2, Landroid/widget/TextView;
    dex[position:position + 4] = bytes(4)
    dex[8:12] = zlib.adler32(bytes(dex[12:])).to_bytes(4, "little")
    return bytes(dex)


def evidence() -> dict:
    shutil.rmtree(WORK, ignore_errors=True)
    WORK.mkdir(parents=True)
    shutil.copy(LIBXPOSED_API, WORK / "libxposed-api.jar")
    context = f"PCL[{WORK / 'libxposed-api.jar'}]"
    apks = {}
    for apk in sorted(HERE.glob("*.apk")):
        copy = WORK / apk.name
        shutil.copy(apk, copy)
        libxposed = any(name.startswith("META-INF/xposed/") for name in zipfile.ZipFile(apk).namelist())
        statuses = verify(copy, context if libxposed else None)
        apks[apk.name] = {
            "sha256": hashlib.sha256(apk.read_bytes()).hexdigest(),
            "class_loader_context": "libxposed-api-102.0.0" if libxposed else None,
            "classes": statuses,
            "passed": bool(statuses) and all(status == "Verified" for status in statuses.values()),
        }
    control = WORK / "ill_typed_listener.dex"
    control.write_bytes(_ill_typed_listener())
    control_status = verify(control)
    return {
        "format": "xax-android-art-verify-evidence-v1",
        "label": "EXECUTED",
        "note": "ART dex2oat verify-only compilation and oatdump class status; no class is initialized or run",
        "environment": {
            "art": "dex2oat64/oatdump from the Android 14 arm64 system image (arm64-v8a-34_r04), under qemu-aarch64 user mode",
            "boot_classpath": BOOT_CLASSPATH,
            "boot_image": "/system/framework/boot.art (precompiled arm64, from the system image)",
            "libxposed_api": "io.github.libxposed:api:102.0.0 (Maven Central, SHA-256 423484a6e1807e7a423c4b88fcd8176d104318259d91791877fed88fe91479d0)",
        },
        "apks": apks,
        "negative_control": {"patch": "listener check-cast -> nop nop", "classes": control_status,
                             "rejected": bool(control_status) and all(status != "Verified" for status in control_status.values())},
        "passed": sum(row["passed"] for row in apks.values()),
        "total": len(apks),
    }


def main() -> int:
    result = evidence()
    EVIDENCE.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    for name, row in result["apks"].items():
        print(f"{'PASS' if row['passed'] else 'FAIL'} {name} {row['classes']}")
    print("negative control", result["negative_control"])
    print(f"{result['passed']}/{result['total']}")
    return 0 if result["passed"] == result["total"] and result["negative_control"]["rejected"] else 1


if __name__ == "__main__":
    sys.exit(main())
