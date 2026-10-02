#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PROBE="$ROOT/benchmarks/android_platform_runtime_probe.so"
LOADER_SRC="$ROOT/integration/android/platform_contract_runtime_loader.c"
EVIDENCE="$ROOT/benchmarks/android_platform_runtime_probe_evidence.json"
: "${ANDROID_NDK_HOME:?ANDROID_NDK_HOME must point to an Android NDK}"
command -v adb >/dev/null || { echo "adb is required" >&2; exit 2; }
ABI="$(adb shell getprop ro.product.cpu.abi | tr -d '\r')"
case "$ABI" in arm64-v8a*) ;; *) echo "requires arm64-v8a device/emulator, got $ABI" >&2; exit 2;; esac
python "$ROOT/benchmarks/bench_android_platform_runtime.py"
CLANG="$(find "$ANDROID_NDK_HOME/toolchains/llvm/prebuilt" -type f -name 'aarch64-linux-android24-clang' -print -quit)"
[ -n "$CLANG" ] || { echo "aarch64-linux-android24-clang not found in NDK" >&2; exit 2; }
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
"$CLANG" -O2 -fPIE -pie -pthread "$LOADER_SRC" -ldl -o "$TMP/xax_platform_runtime_loader"
REMOTE="/data/local/tmp/xax-platform-runtime-$$"
adb shell "mkdir -p $REMOTE"
trap 'adb shell "rm -rf '$REMOTE'" >/dev/null 2>&1 || true; rm -rf "$TMP"' EXIT
adb push "$PROBE" "$REMOTE/libxax_platform_probe.so" >/dev/null
adb push "$TMP/xax_platform_runtime_loader" "$REMOTE/xax_platform_runtime_loader" >/dev/null
adb shell "chmod 755 $REMOTE/xax_platform_runtime_loader"
OUTPUT="$(adb shell "cd $REMOTE && ./xax_platform_runtime_loader ./libxax_platform_probe.so" | tr -d '\r')"
echo "$OUTPUT"
grep -q '^XAX_PLATFORM_RUNTIME_OK file=1 thread=1 socket=1$' <<<"$OUTPUT"
DEVICE="$(adb shell getprop ro.product.model | tr -d '\r')"
ANDROID_RELEASE="$(adb shell getprop ro.build.version.release | tr -d '\r')"
ANDROID_API="$(adb shell getprop ro.build.version.sdk | tr -d '\r')"
OUTPUT="$OUTPUT" DEVICE="$DEVICE" ABI="$ABI" ANDROID_RELEASE="$ANDROID_RELEASE" ANDROID_API="$ANDROID_API" EVIDENCE="$EVIDENCE" python - <<'PY'
import json, os
from pathlib import Path
path=Path(os.environ['EVIDENCE'])
data=json.loads(path.read_text())
data['runtime']={
  'executed': True,
  'result': os.environ['OUTPUT'],
  'device': os.environ['DEVICE'],
  'abi': os.environ['ABI'],
  'android_release': os.environ['ANDROID_RELEASE'],
  'android_api': int(os.environ['ANDROID_API']),
  'file': True, 'thread': True, 'socket': True,
}
path.write_text(json.dumps(data, indent=2, sort_keys=True)+'\n')
PY
echo "$EVIDENCE"
