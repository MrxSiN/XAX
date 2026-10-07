"""ART's own tools on a connected rooted arm64 device, for the ART verify/execute benches.

The qemu route runs Android 14's tools from a system image on a Linux host.  This
route runs the device's own ``dex2oat64``/``oatdump``/``dalvikvm64`` against its own
boot image, over ``adb`` as root (``dex2oat64`` from the shell domain cannot write
its output).  ``ANDROID_SERIAL`` selects the device.

The libxposed API comes from the pinned Maven AAR (``XAX_LIBXPOSED_AAR``; its
SHA-256 must equal the Vector pin), dexed with the SDK's ``d8``.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import tempfile
import zipfile
from pathlib import Path

from benchmarks.bench_android_ndk_twin import _sdk

ART_BIN = "/apex/com.android.art/bin"
PIN = Path(__file__).resolve().parents[1] / "integration/android/vector/vector_runtime_pin.json"
_QUIET = {**os.environ, "JAVA_TOOL_OPTIONS": "", "MSYS_NO_PATHCONV": "1"}


def requested() -> bool:
    return os.environ.get("XAX_ART_DEVICE") == "1"


def adb(*arguments: str, timeout: int = 600) -> str:
    completed = subprocess.run(["adb", *arguments], capture_output=True, text=True, env=_QUIET, timeout=timeout)
    if completed.returncode:
        raise RuntimeError(f"adb {' '.join(arguments)}: {completed.stderr.strip() or completed.stdout.strip()}")
    return completed.stdout.replace("\r", "")


def push(local: Path, remote: str) -> None:
    adb("push", str(local), remote)


def root_sh(script: str, timeout: int = 600) -> subprocess.CompletedProcess:
    """Run ``script`` with ``sh`` as root; stdout/stderr/returncode are the script's."""
    with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False, newline="\n") as handle:
        handle.write(script)
    try:
        push(Path(handle.name), "/data/local/tmp/xax_art.sh")
    finally:
        os.unlink(handle.name)
    return subprocess.run(["adb", "shell", "su", "-c", "sh /data/local/tmp/xax_art.sh"],
                          capture_output=True, text=True, env=_QUIET, timeout=timeout, check=False)


def environment(tools: str) -> dict[str, str]:
    properties = {name: adb("shell", "getprop", name).strip() for name in (
        "ro.build.fingerprint", "ro.product.model", "ro.build.version.sdk", "ro.kernel.qemu")}
    if properties.pop("ro.kernel.qemu") == "1":
        raise RuntimeError("the device route needs arm64 hardware, not an emulator")
    apexes = adb("shell", "pm", "list", "packages", "--apex-only", "--show-versioncode")
    art = re.search(r"package:(\S+\.art) versionCode:(\d+)", apexes)
    return {
        "art": f"{tools} on the device (its own boot image), as root over adb",
        "device": properties["ro.product.model"],
        "fingerprint": properties["ro.build.fingerprint"],
        "sdk": properties["ro.build.version.sdk"],
        "art_apex": f"{art.group(1)} {art.group(2)}" if art else None,
    }


def libxposed_api(work: Path) -> tuple[Path, Path]:
    """The pinned API's ``classes.jar`` and its dexed jar, under ``work``."""
    aar = Path(os.environ["XAX_LIBXPOSED_AAR"])
    pin = json.loads(PIN.read_text(encoding="utf-8"))["libxposed_api"]
    if hashlib.sha256(aar.read_bytes()).hexdigest() != pin["aar_sha256"]:
        raise RuntimeError(f"{aar} is not the pinned libxposed API AAR")
    classes = work / "libxposed-classes.jar"
    classes.write_bytes(zipfile.ZipFile(aar).read("classes.jar"))
    dexed = work / "libxposed-api-102-dex.jar"
    subprocess.run([str(_sdk("d8")), "--release", "--min-api", "28", "--output", str(dexed), str(classes)],
                   check=True, capture_output=True, env=_QUIET)
    return classes, dexed
