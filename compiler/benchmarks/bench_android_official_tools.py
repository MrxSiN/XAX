"""Independent validation of every committed XAX Android APK with Google's own tools.

The XAX emitters write APK, DEX, manifest, resources, signatures, and ELF bytes
directly.  The repository's own tests check those bytes with the repository's
own parsers; this benchmark asks the official Android build tools instead:

* ``apksigner verify`` (signature schemes, for signed APKs);
* ``zipalign -c -P 16 4`` (4-byte entries; uncompressed ``.so`` on 16 KiB boundaries);
* ``aapt2 dump badging`` (binary manifest and resource table);
* ``dexdump -c`` and ``dexdump -d`` (DEX checksum and a full code walk);
* ``d8 --release`` re-dexing each DEX (a full independent parse into D8's IR);
* ``llvm-readelf -h -l -d --dyn-syms`` on each native library.

This is format validation, not execution: ART's verifier and the runtime are
not involved.  Set ``ANDROID_BUILD_TOOLS`` (default ``/opt/android/bt/android-14``)
and run from ``compiler/``.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

from benchmarks.bench_android_ndk_twin import _sdk  # BUILD_TOOLS tool on Linux or Windows

HERE = Path(__file__).resolve().parent
EVIDENCE = HERE / "android_official_tools_evidence.json"
BUILD_TOOLS = Path(os.environ.get("ANDROID_BUILD_TOOLS", "/opt/android/bt36/android-16"))
_QUIET_JAVA = {**os.environ, "JAVA_TOOL_OPTIONS": ""}


def _run(*command: str | Path) -> subprocess.CompletedProcess:
    return subprocess.run([str(item) for item in command], capture_output=True, text=True, env=_QUIET_JAVA, check=False)


def _tool_version() -> str:
    properties = (BUILD_TOOLS / "source.properties").read_text(encoding="utf-8")
    return next(line.split("=", 1)[1].strip() for line in properties.splitlines() if line.startswith("Pkg.Revision"))


def validate_apk(path: Path) -> dict:
    checks: dict[str, bool] = {}
    names = zipfile.ZipFile(path).namelist()
    # An APK Signing Block (v2+) or JAR signature files (v1); META-INF/ alone is not a signature.
    signed = b"APK Sig Block 42" in path.read_bytes() or any(name.startswith("META-INF/") and name.endswith((".RSA", ".EC", ".DSA")) for name in names)
    if signed:
        checks["apksigner"] = _run(_sdk("apksigner"), "verify", path).returncode == 0
    checks["zipalign_16k"] = _run(_sdk("zipalign"), "-c", "-P", "16", "4", path).returncode == 0
    if "AndroidManifest.xml" in names:
        checks["aapt2_badging"] = _run(_sdk("aapt2"), "dump", "badging", path).returncode == 0
    with tempfile.TemporaryDirectory() as directory:
        zipfile.ZipFile(path).extractall(directory)
        for name in sorted(item for item in names if item.endswith(".dex")):
            dex = Path(directory) / name
            checks[f"{name}:dexdump_checksum"] = _run(_sdk("dexdump"), "-c", dex).returncode == 0
            walk = _run(_sdk("dexdump"), "-d", dex)
            checks[f"{name}:dexdump_code"] = walk.returncode == 0 and "Failure" not in walk.stderr
            output = Path(directory) / f"d8-{name}"
            output.mkdir()
            checks[f"{name}:d8_redex"] = _run(_sdk("d8"), "--release", "--min-api", "28", "--output", output, dex).returncode == 0
        for name in sorted(item for item in names if item.endswith(".so")):
            readelf = _run(shutil.which("llvm-readelf") or "llvm-readelf", "-h", "-l", "-d", "--dyn-syms", Path(directory) / name)
            checks[f"{name}:llvm_readelf"] = readelf.returncode == 0 and not readelf.stderr.strip()
    return {
        "bytes": path.stat().st_size,
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "signed": signed,
        "checks": checks,
        "passed": all(checks.values()),
    }


def evidence() -> dict:
    apks = {path.name: validate_apk(path) for path in sorted(HERE.glob("*.apk"))}
    return {
        "format": "xax-android-official-tools-evidence-v1",
        "label": "STRUCTURAL",
        "note": "format validation by Google's build tools; not ART verification or execution",
        "build_tools": _tool_version(),
        "llvm_readelf": _run(shutil.which("llvm-readelf") or "llvm-readelf", "--version").stdout.split("\n")[1].strip(),
        "apks": apks,
        "passed": sum(item["passed"] for item in apks.values()),
        "total": len(apks),
    }


def main() -> int:
    result = evidence()
    EVIDENCE.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    for name, item in result["apks"].items():
        failed = [check for check, ok in item["checks"].items() if not ok]
        print(f"{'PASS' if item['passed'] else 'FAIL'} {name} {len(item['checks'])} checks {failed or ''}")
    print(f"{result['passed']}/{result['total']}")
    return 0 if result["passed"] == result["total"] else 1


if __name__ == "__main__":
    sys.exit(main())
