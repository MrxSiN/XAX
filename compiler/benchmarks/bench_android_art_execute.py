"""Execute XAX-generated libxposed modules on ART (ADR-109).

Android 14's own ``dalvikvm64`` (from the official system image, under
``qemu-aarch64``) runs the unmodified module APKs.  The harness in
``integration/android/art_libxposed_harness`` plays the libxposed API-102
framework.  It attaches itself to the generated ``XaxModule``, calls
``onModuleLoaded``, which loads the module's XAX native library through ART's
nativeloader and calls into it over JNI, and then ``onPackageReady``, which
installs the hook.  It then runs the installed ``Hooker`` around the real
target method.  Each module's observed behaviour is compared with the
behaviour its profile declares.

The harness is a stand-in for the framework, not LSPosed: no method is really
hooked in another app's process.  ART, its interpreter, JNI, nativeloader, and
the XAX code are real.
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

HERE = Path(__file__).resolve().parent
EVIDENCE = HERE / "android_art_execute_evidence.json"
HARNESS = HERE.parent / "integration/android/art_libxposed_harness/java"
PREFIX = Path(os.environ.get("XAX_ANDROID_PREFIX", "/opt/android"))
ROOT = PREFIX / "root"
BUILD_TOOLS = PREFIX / "bt36/android-16"
ANDROID_JAR = PREFIX / "platform/android-35/android.jar"
API_CLASSES = PREFIX / "libxposed/classes.jar"
API_DEX = PREFIX / "libxposed/libxposed-api-102-dex.jar"
QEMU = shutil.which("qemu-aarch64-static") or shutil.which("qemu-aarch64")
WORK = Path("/data/local/tmp/xax-art-execute")  # qemu -L falls back to host paths absent from the root
BOOT_CLASSPATH = ":".join((
    "/apex/com.android.art/javalib/core-oj.jar", "/apex/com.android.art/javalib/core-libart.jar",
    "/apex/com.android.art/javalib/okhttp.jar", "/apex/com.android.art/javalib/bouncycastle.jar",
    "/apex/com.android.art/javalib/apache-xml.jar", "/system/framework/framework.jar",
    "/system/framework/framework-graphics.jar", "/system/framework/ext.jar", "/system/framework/telephony-common.jar",
    "/system/framework/voip-common.jar", "/system/framework/ims-common.jar", "/apex/com.android.i18n/javalib/core-icu4j.jar",
))
# Declared behaviour of each module profile (see the matching android_libxposed_*_evidence.json).
# "receiver=simulated": the hooked method is declared on a framework class that a bare dalvikvm
# cannot construct, so the original call returns no value; everything XAX generated still runs.
EXPECTED = {
    "android_libxposed_argument_fixture.apk":
        "hooked=com.example.target.XaxActivity.hookTarget/1 mode=PROTECTIVE hooker=xax.generated.XaxHooker calls=[framework.hook, builder.setExceptionMode, builder.intercept] proceeds=1 proceed_args=[HookedArg] original=HookedArg result=HookedArg",
    "android_libxposed_combined_fixture.apk":
        "hooked=com.example.target.XaxActivity.hookTarget/1 mode=PROTECTIVE hooker=xax.generated.XaxHooker calls=[framework.hook, builder.setExceptionMode, builder.intercept] proceeds=1 proceed_args=[HookedArg] original=HookedArg result=HookedResult",
    "android_libxposed_deopt_fixture.apk":
        "hooked=android.app.Activity.onResume/0 mode=PROTECTIVE hooker=xax.generated.XaxHooker calls=[framework.deoptimize, framework.hook, builder.setExceptionMode, builder.intercept] proceeds=1 proceed_args=[] original=null result=null receiver=simulated",
    "android_libxposed_hook_fixture.apk":
        "hooked=android.app.Activity.onResume/0 mode=PROTECTIVE hooker=xax.generated.XaxHooker calls=[framework.hook, builder.setExceptionMode, builder.intercept] proceeds=1 proceed_args=[] original=null result=null receiver=simulated",
    "android_libxposed_hot_reload_fixture.apk":
        "hooked=android.app.Activity.onResume/0 mode=PROTECTIVE hooker=xax.generated.XaxHooker calls=[framework.hook, builder.setExceptionMode, builder.setId, builder.intercept, handle.unhook, module.xaxUnhook] proceeds=1 proceed_args=[] original=null result=null receiver=simulated",
    "android_libxposed_managed_fixture.apk":
        "hooked=none services=[] calls=[]",
    "android_libxposed_remote_files_fixture.apk":
        "hooked=none services=[nocap.files=null,nocap.open=null,cap.files=[config.json],cap.open=threw:FileNotFoundException] calls=[framework.getFrameworkProperties, framework.getFrameworkProperties, framework.getFrameworkProperties, framework.listRemoteFiles, framework.getFrameworkProperties, framework.openRemoteFile]",
    "android_libxposed_remote_preferences_fixture.apk":
        "hooked=none services=[nocap.prefs=false,cap.prefs=true,bool=true,int=7,long=70000000000,float=1.5,string=remote,contains=true] calls=[framework.getFrameworkProperties, framework.getFrameworkProperties, framework.getRemotePreferences, prefs.getBoolean, prefs.getInt, prefs.getLong, prefs.getFloat, prefs.getString, prefs.contains]",
    "android_libxposed_result_fixture.apk":
        "hooked=com.example.target.XaxActivity.hookTarget/0 mode=PROTECTIVE hooker=xax.generated.XaxHooker calls=[framework.hook, builder.setExceptionMode, builder.intercept] proceeds=1 proceed_args=[] original=OriginalResult result=Hooked",
    "android_libxposed_runtime_module_signed.apk":
        "hooked=com.example.target.XaxActivity.hookTarget/1 mode=PROTECTIVE hooker=xax.generated.XaxHooker calls=[framework.hook, builder.setExceptionMode, builder.intercept] proceeds=1 proceed_args=[HookedArg] original=HookedArg result=HookedResult",
    "android_libxposed_services_fixture.apk":
        "hooked=none services=[name=XaxArtHarness,version=1.0,files=[config.json],open=threw:FileNotFoundException,prefs=true] calls=[framework.getFrameworkName, framework.getFrameworkVersion, framework.listRemoteFiles, framework.openRemoteFile, framework.getRemotePreferences]",
    "android_libxposed_unhook_fixture.apk":
        "hooked=android.app.Activity.onResume/0 mode=PROTECTIVE hooker=xax.generated.XaxHooker calls=[framework.hook, builder.setExceptionMode, builder.intercept, handle.unhook, module.xaxUnhook] proceeds=1 proceed_args=[] original=null result=null receiver=simulated",
}


_ENVIRONMENT = {
    **os.environ,
    "ANDROID_ROOT": "/system", "ANDROID_ART_ROOT": "/apex/com.android.art", "ANDROID_I18N_ROOT": "/apex/com.android.i18n",
    "ANDROID_TZDATA_ROOT": "/apex/com.android.tzdata", "ANDROID_DATA": "/data",
}


def available() -> bool:
    return QEMU is not None and (ROOT / "apex/com.android.art/bin/dalvikvm64").exists() and (ROOT / "linkerconfig/ld.config.txt").exists()


def build_harness(work: Path) -> Path:
    """Compile the harness against android.jar and the libxposed API, then dex it."""
    quiet = {**os.environ, "JAVA_TOOL_OPTIONS": ""}
    classes, dex = work / "classes", work / "dex"
    dex.mkdir(parents=True)
    sources = sorted(str(path) for path in HARNESS.rglob("*.java"))
    subprocess.run(["javac", "--release", "11", "-cp", f"{ANDROID_JAR}:{API_CLASSES}", "-d", str(classes), *sources], check=True, capture_output=True, env=quiet)
    subprocess.run([str(BUILD_TOOLS / "d8"), "--release", "--min-api", "28", "--lib", str(ANDROID_JAR), "--classpath", str(API_CLASSES),
                    "--output", str(dex), *sorted(str(path) for path in classes.rglob("*.class"))], check=True, capture_output=True, env=quiet)
    return dex / "classes.dex"


def run_module(apk: Path, harness: Path) -> subprocess.CompletedProcess:
    shutil.rmtree(WORK, ignore_errors=True)
    (WORK / "lib").mkdir(parents=True)
    shutil.copy(harness, WORK / "harness.dex")
    shutil.copy(API_DEX, WORK / "api.jar")
    shutil.copy(apk, WORK / "module.apk")
    with zipfile.ZipFile(apk) as archive:
        for name in archive.namelist():
            if name.startswith("lib/arm64-v8a/"):
                (WORK / "lib" / Path(name).name).write_bytes(archive.read(name))
    command = [
        QEMU, "-L", str(ROOT), str(ROOT / "apex/com.android.art/bin/dalvikvm64"),
        f"-Xbootclasspath:{BOOT_CLASSPATH}", f"-Xbootclasspath-locations:{BOOT_CLASSPATH}", "-Ximage:/system/framework/boot.art",
        f"-Djava.library.path={WORK / 'lib'}", "-cp", f"{WORK / 'harness.dex'}:{WORK / 'api.jar'}:{WORK / 'module.apk'}", "xax.harness.Main",
    ]
    return subprocess.run(command, capture_output=True, text=True, env=_ENVIRONMENT, timeout=600, check=False)


def evidence() -> dict:
    with tempfile.TemporaryDirectory() as directory:
        harness = build_harness(Path(directory))
        runs = {}
        for name, expected in EXPECTED.items():
            completed = run_module(HERE / name, harness)
            observed = next((line.removeprefix("XAX_LIBXPOSED_ART ") for line in completed.stdout.splitlines() if line.startswith("XAX_LIBXPOSED_ART ")), None)
            runs[name] = {
                "sha256": hashlib.sha256((HERE / name).read_bytes()).hexdigest(),
                "expected": expected, "observed": observed, "exit": completed.returncode,
                "passed": completed.returncode == 0 and observed == expected,
            }
    return {
        "format": "xax-android-art-execute-evidence-v1",
        "label": "EXECUTED",
        "note": "ART dalvikvm64 runs the unmodified module APK with its XAX native library; the libxposed framework is a recording stand-in",
        "environment": {
            "art": "dalvikvm64 from the Android 14 arm64 system image (arm64-v8a-34_r04), under qemu-aarch64 user mode",
            "boot_image": "/system/framework/boot.art (precompiled arm64)",
            "libxposed_api": "io.github.libxposed:api:102.0.0",
        },
        "runs": runs,
        "passed": sum(run["passed"] for run in runs.values()),
        "total": len(runs),
    }


def main() -> int:
    result = evidence()
    EVIDENCE.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    for name, run in result["runs"].items():
        print(f"{'PASS' if run['passed'] else 'FAIL'} {name}: {run['observed']}")
    print(f"{result['passed']}/{result['total']}")
    return 0 if result["passed"] == result["total"] else 1


if __name__ == "__main__":
    sys.exit(main())
