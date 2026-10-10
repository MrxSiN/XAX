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
KOTLIN_HOME = Path(os.environ.get("KOTLIN_HOME", "/opt/kotlinc"))  # the kotlinc distribution: lib/kotlin-compiler.jar, lib/kotlin-stdlib.jar
LLVM = NDK / "toolchains/llvm/prebuilt" / ("windows-x86_64" if os.name == "nt" else "linux-x86_64") / "bin"
_ENV = {**os.environ, "JAVA_TOOL_OPTIONS": ""}


def _llvm(name: str) -> Path:
    """Resolve an NDK tool on Linux or Windows without involving a shell."""
    for suffix in ((".cmd", ".exe", "") if os.name == "nt" else ("",)):
        path = LLVM / f"{name}{suffix}"
        if path.exists():
            return path
    return LLVM / name


def _sdk(name: str) -> Path:
    for suffix in ((".bat", ".exe", "") if os.name == "nt" else ("",)):
        path = BUILD_TOOLS / f"{name}{suffix}"
        if path.exists():
            return path
    return BUILD_TOOLS / name


def _run(*command) -> str:
    return subprocess.run([str(item) for item in command], check=True, capture_output=True, text=True, env=_ENV).stdout


def _native_functions(library: bytes) -> dict[str, int]:
    """Size of every defined dynamic function symbol, as ``llvm-readelf`` reports it."""
    with tempfile.NamedTemporaryFile(suffix=".so") as handle:
        handle.write(library)
        handle.flush()
        lines = _run(_llvm("llvm-readelf"), "--dyn-syms", "-W", handle.name).splitlines()
    functions = {}
    for line in lines:
        fields = line.split()
        if len(fields) == 8 and fields[3] == "FUNC" and fields[6] != "UND":
            functions[fields[7]] = int(fields[2], 0)
    return functions


def _measure(apk: Path) -> dict:
    with zipfile.ZipFile(apk) as archive:
        entries = {item.filename: archive.read(item.filename) for item in archive.infolist()}
    library = next((data for name, data in entries.items() if name.startswith("lib/arm64-v8a/")), None)
    measured = {
        "apk_bytes": apk.stat().st_size,
        "apk_sha256": hashlib.sha256(apk.read_bytes()).hexdigest(),
        "dex_bytes": sum(len(data) for name, data in entries.items() if name.endswith(".dex")),
        "dex_files": sorted(name for name in entries if name.endswith(".dex")),
        "manifest_bytes": len(entries["AndroidManifest.xml"]),
        "native_library_bytes": len(library or b""),
        "badging": _badging(apk),
    }
    if library is not None:  # a pure Java twin has none
        measured["native_function_bytes"] = _native_functions(library)
        measured["native_needed"] = sorted(line.split("[")[1].rstrip("]") for line in _readelf_dynamic(library) if "(NEEDED)" in line)
    return measured


def _badging(apk: Path) -> list[str]:
    """Package, SDK, and launchable activity; ``aapt2 link`` build-provenance attributes are dropped."""
    lines = [line for line in _run(_sdk("aapt2"), "dump", "badging", apk).splitlines() if line.startswith(("package:", "launchable-activity:", "sdkVersion:"))]
    return [re.sub(r" (platformBuildVersion\w*|compileSdkVersion\w*)='[^']*'", "", line) for line in lines]


def _readelf_dynamic(library: bytes) -> list[str]:
    with tempfile.NamedTemporaryFile(suffix=".so") as handle:
        handle.write(library)
        handle.flush()
        return _run(_llvm("llvm-readelf"), "-d", handle.name).splitlines()


def build_twin(work: Path, twin: Path = TWIN, library_name: str = "xaxapp", package: str | None = None) -> Path:
    """Build a twin directory (``java/`` or ``kotlin/``, optional ``<library_name>.c``, ``AndroidManifest.xml``) into a signed APK.

    ``package`` renames the application package (classes keep their names), so several twins can be installed side by side."""
    classes = work / "classes"
    dex = work / "dex"
    dex.mkdir()
    if (twin / "kotlin").exists():  # Kotlin: kotlinc, then R8 over the program and kotlin-stdlib, as a release build does
        sources = sorted(str(path) for path in (twin / "kotlin").rglob("*.kt"))
        _run("java", "-cp", KOTLIN_HOME / "lib/kotlin-compiler.jar", "org.jetbrains.kotlin.cli.jvm.K2JVMCompiler", "-no-stdlib", "-no-reflect",
             "-jvm-target", "11", "-cp", os.pathsep.join(map(str, (ANDROID_JAR, KOTLIN_HOME / "lib/kotlin-stdlib.jar"))), "-d", classes, *sources)
        _run("java", "-cp", BUILD_TOOLS / "lib/d8.jar", "com.android.tools.r8.R8", "--release", "--min-api", "28", "--lib", ANDROID_JAR,
             "--pg-conf", twin / "proguard-rules.pro", "--output", dex, *sorted(classes.rglob("*.class")), KOTLIN_HOME / "lib/kotlin-stdlib.jar")
    else:
        sources = sorted(str(path) for path in (twin / "java").rglob("*.java"))
        _run("javac", "--release", "11", "-cp", ANDROID_JAR, "-d", classes, *sources)
        _run(_sdk("d8"), "--release", "--min-api", "28", "--lib", ANDROID_JAR, "--output", dex, *sorted(classes.rglob("*.class")))
    library = work / f"lib{library_name}.so"
    native = (twin / f"{library_name}.c").exists()  # a pure Java twin has no native library
    if native:
        _run(_llvm("aarch64-linux-android28-clang"), "-O2", "-fPIC", "-shared", "-Wl,-z,max-page-size=16384", "-Wl,--gc-sections", "-o", library, twin / f"{library_name}.c")
        _run(_llvm("llvm-strip"), "--strip-unneeded", library)
    linked = work / "linked.apk"
    _run(_sdk("aapt2"), "link", "--manifest", twin / "AndroidManifest.xml", "-I", ANDROID_JAR, "-o", linked, *(("--rename-manifest-package", package) if package else ()))
    stored = work / "stored.apk"
    with zipfile.ZipFile(linked) as source, zipfile.ZipFile(stored, "w", zipfile.ZIP_STORED) as out:
        out.writestr("AndroidManifest.xml", source.read("AndroidManifest.xml"))
        out.write(dex / "classes.dex", "classes.dex")
        if native:
            out.write(library, f"lib/arm64-v8a/lib{library_name}.so")
    aligned = work / "aligned.apk"
    _run(_sdk("zipalign"), "-P", "16", "-f", "4", stored, aligned)
    keystore = work / "twin.jks"
    _run("keytool", "-genkeypair", "-keystore", keystore, "-storepass", "twin-pass", "-alias", "twin", "-keyalg", "RSA", "-keysize", "2048",
         "-validity", "10000", "-dname", "CN=XAX twin", "-noprompt")
    signed = work / "twin.apk"
    _run(_sdk("apksigner"), "sign", "--ks", keystore, "--ks-pass", "pass:twin-pass", "--v1-signing-enabled", "false",
         "--v2-signing-enabled", "true", "--v3-signing-enabled", "false", "--out", signed, aligned)
    _run(_sdk("apksigner"), "verify", signed)
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
