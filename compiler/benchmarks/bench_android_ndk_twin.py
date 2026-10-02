"""Size baseline for the Android row: XAX's minimal Activity APK against a conventional Java + NDK twin.

The twin (``android_ndk_twin/``) has the same classes, methods, strings, manifest,
and native callbacks as ``android_minimal_activity.apk``.  It is built the way a
release build is normally made, with Google's own tools:

* ``javac --release 11`` against ``android.jar``, then ``d8 --release --min-api 28``;
* NDK ``clang -O2 -fPIC -shared`` with 16 KiB page alignment, then ``llvm-strip --strip-unneeded``;
* ``aapt2 link`` for the binary manifest;
* every entry stored uncompressed (as in the XAX APK), ``zipalign -P 16`` (16 KiB
  ``.so`` alignment inside the APK, as the XAX packager does for 16 KiB-page devices),
  and ``apksigner`` with a v2-only RSA-2048 signature (as in the XAX APK).

Only sizes are compared.  Start-up time and memory need a device.  Set
``ANDROID_NDK_HOME``, ``ANDROID_BUILD_TOOLS``, and ``ANDROID_JAR``; run from ``compiler/``.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
TWIN = HERE / "android_ndk_twin"
XAX_APK = HERE / "android_minimal_activity.apk"
XAX_PACKED_APK = HERE / "android_minimal_activity_packed.apk"  # same program, packed ELF container (ADR-105)
EVIDENCE = HERE / "android_ndk_twin_evidence.json"
NDK = Path(os.environ.get("ANDROID_NDK_HOME", "/opt/android/android-ndk-r28c"))
BUILD_TOOLS = Path(os.environ.get("ANDROID_BUILD_TOOLS", "/opt/android/bt36/android-16"))
ANDROID_JAR = Path(os.environ.get("ANDROID_JAR", "/opt/android/platform/android-35/android.jar"))
LLVM = NDK / "toolchains/llvm/prebuilt/linux-x86_64/bin"
_ENV = {**os.environ, "JAVA_TOOL_OPTIONS": ""}


def _run(*command) -> str:
    return subprocess.run([str(item) for item in command], check=True, capture_output=True, text=True, env=_ENV).stdout


def _native_functions(library: bytes) -> dict[str, int]:
    """Size of every defined dynamic function symbol, as ``llvm-readelf`` reports it."""
    with tempfile.NamedTemporaryFile(suffix=".so") as handle:
        handle.write(library)
        handle.flush()
        lines = _run(LLVM / "llvm-readelf", "--dyn-syms", "-W", handle.name).splitlines()
    functions = {}
    for line in lines:
        fields = line.split()
        if len(fields) == 8 and fields[3] == "FUNC" and fields[6] != "UND":
            functions[fields[7]] = int(fields[2], 0)
    return functions


def _measure(apk: Path) -> dict:
    with zipfile.ZipFile(apk) as archive:
        entries = {item.filename: archive.read(item.filename) for item in archive.infolist()}
    library = next(data for name, data in entries.items() if name.startswith("lib/arm64-v8a/"))
    functions = _native_functions(library)
    return {
        "apk_bytes": apk.stat().st_size,
        "apk_sha256": hashlib.sha256(apk.read_bytes()).hexdigest(),
        "dex_bytes": sum(len(data) for name, data in entries.items() if name.endswith(".dex")),
        "dex_files": sorted(name for name in entries if name.endswith(".dex")),
        "manifest_bytes": len(entries["AndroidManifest.xml"]),
        "native_library_bytes": len(library),
        "native_function_bytes": functions,
        "native_needed": sorted(line.split("[")[1].rstrip("]") for line in _readelf_dynamic(library) if "(NEEDED)" in line),
        "badging": _badging(apk),
    }


def _badging(apk: Path) -> list[str]:
    """Package, SDK, and launchable activity; ``aapt2 link`` build-provenance attributes are dropped."""
    lines = [line for line in _run(BUILD_TOOLS / "aapt2", "dump", "badging", apk).splitlines() if line.startswith(("package:", "launchable-activity:", "sdkVersion:"))]
    return [re.sub(r" (platformBuildVersion\w*|compileSdkVersion\w*)='[^']*'", "", line) for line in lines]


def _readelf_dynamic(library: bytes) -> list[str]:
    with tempfile.NamedTemporaryFile(suffix=".so") as handle:
        handle.write(library)
        handle.flush()
        return _run(LLVM / "llvm-readelf", "-d", handle.name).splitlines()


def build_twin(work: Path) -> Path:
    classes = work / "classes"
    sources = sorted(str(path) for path in (TWIN / "java").rglob("*.java"))
    _run("javac", "--release", "11", "-cp", ANDROID_JAR, "-d", classes, *sources)
    dex = work / "dex"
    dex.mkdir()
    _run(BUILD_TOOLS / "d8", "--release", "--min-api", "28", "--lib", ANDROID_JAR, "--output", dex, *sorted(classes.rglob("*.class")))
    library = work / "libxaxapp.so"
    _run(LLVM / "aarch64-linux-android28-clang", "-O2", "-fPIC", "-shared", "-Wl,-z,max-page-size=16384", "-Wl,--gc-sections", "-o", library, TWIN / "xaxapp.c")
    _run(LLVM / "llvm-strip", "--strip-unneeded", library)
    linked = work / "linked.apk"
    _run(BUILD_TOOLS / "aapt2", "link", "--manifest", TWIN / "AndroidManifest.xml", "-I", ANDROID_JAR, "-o", linked)
    stored = work / "stored.apk"
    with zipfile.ZipFile(linked) as source, zipfile.ZipFile(stored, "w", zipfile.ZIP_STORED) as out:
        out.writestr("AndroidManifest.xml", source.read("AndroidManifest.xml"))
        out.write(dex / "classes.dex", "classes.dex")
        out.write(library, "lib/arm64-v8a/libxaxapp.so")
    aligned = work / "aligned.apk"
    _run(BUILD_TOOLS / "zipalign", "-P", "16", "-f", "4", stored, aligned)
    keystore = work / "twin.jks"
    _run("keytool", "-genkeypair", "-keystore", keystore, "-storepass", "twin-pass", "-alias", "twin", "-keyalg", "RSA", "-keysize", "2048",
         "-validity", "10000", "-dname", "CN=XAX twin", "-noprompt")
    signed = work / "twin.apk"
    _run(BUILD_TOOLS / "apksigner", "sign", "--ks", keystore, "--ks-pass", "pass:twin-pass", "--v1-signing-enabled", "false",
         "--v2-signing-enabled", "true", "--v3-signing-enabled", "false", "--out", signed, aligned)
    _run(BUILD_TOOLS / "apksigner", "verify", signed)
    return signed


def evidence() -> dict:
    with tempfile.TemporaryDirectory() as directory:
        twin = _measure(build_twin(Path(directory)))
    xax = _measure(XAX_APK)
    packed = _measure(XAX_PACKED_APK)
    keys = ("apk_bytes", "dex_bytes", "manifest_bytes", "native_library_bytes")
    return {
        "format": "xax-android-ndk-twin-evidence-v1",
        "label": "MEASURED",
        "note": "sizes only; start-up latency and memory need a device",
        "toolchain": {
            "ndk": (NDK / "source.properties").read_text(encoding="utf-8").split("Pkg.Revision = ")[1].split()[0],
            "build_tools": (BUILD_TOOLS / "source.properties").read_text(encoding="utf-8").split("Pkg.Revision=")[1].split()[0],
            "javac": subprocess.run(["javac", "-version"], capture_output=True, text=True, env=_ENV).stdout.strip(),
            "android_jar": ANDROID_JAR.parent.name,
        },
        "behavior_match": all(side["badging"] == twin["badging"] and set(side["native_function_bytes"]) == set(twin["native_function_bytes"]) for side in (xax, packed)),
        "xax": xax,
        "xax_packed": packed,
        "java_ndk": twin,
        "xax_over_java_ndk": {key: round(xax[key] / twin[key], 3) for key in keys},
        "xax_packed_over_java_ndk": {key: round(packed[key] / twin[key], 3) for key in keys},
    }


def main() -> int:
    result = evidence()
    EVIDENCE.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({key: result[key] for key in ("behavior_match", "xax_over_java_ndk", "xax_packed_over_java_ndk")}, indent=2))
    for side in ("xax", "xax_packed", "java_ndk"):
        row = result[side]
        print(side, {key: row[key] for key in ("apk_bytes", "dex_bytes", "manifest_bytes", "native_library_bytes", "native_function_bytes", "native_needed")})
    return 0 if result["behavior_match"] else 1


if __name__ == "__main__":
    sys.exit(main())
