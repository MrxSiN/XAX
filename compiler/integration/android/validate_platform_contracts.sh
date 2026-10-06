#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PROBE="$ROOT/benchmarks/android_platform_runtime_probe.so"
LOADER_SRC="$ROOT/integration/android/platform_contract_runtime_loader.c"
EVIDENCE="$ROOT/benchmarks/android_platform_runtime_probe_evidence.json"
: "${ANDROID_NDK_HOME:?ANDROID_NDK_HOME must point to an Android NDK}"
command -v adb >/dev/null || { echo "adb is required" >&2; exit 2; }
ABI="$(adb shell getprop ro.product.cpu.abi | tr -d '\r')"
ABILIST="$(adb shell getprop ro.product.cpu.abilist | tr -d '\r')"
# An x86_64 emulator image with ARM translation lists arm64-v8a after its native ABI;
# the run is then recorded as translated, not hardware (XAX_SPEC.md section 21.2).
case ",$ABILIST," in *,arm64-v8a,*) ;; *) echo "requires an arm64-v8a device/emulator, got $ABILIST" >&2; exit 2;; esac
python "$ROOT/benchmarks/bench_android_platform_runtime.py"
CLANG_ARGS=()
LOADER_OUT=""
PROBE_PUSH="$PROBE"
EVIDENCE_OUT="$EVIDENCE"
case "$(uname -s)" in
  MINGW*|MSYS*)
    export MSYS_NO_PATHCONV=1
    CLANG="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/windows-x86_64/bin/clang.exe"
    CLANG_ARGS+=(--target=aarch64-linux-android24)
    LOADER_SRC="$(cygpath -w "$LOADER_SRC")"
    PROBE_PUSH="$(cygpath -w "$PROBE")"
    EVIDENCE_OUT="$(cygpath -w "$EVIDENCE")"
    ;;
  *) CLANG="$(find "$ANDROID_NDK_HOME/toolchains/llvm/prebuilt" -type f -name 'aarch64-linux-android24-clang' -print -quit)" ;;
esac
[ -n "$CLANG" ] || { echo "aarch64-linux-android24-clang not found in NDK" >&2; exit 2; }
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
LOADER_OUT="$TMP/xax_platform_runtime_loader"
[[ "$(uname -s)" == MINGW* || "$(uname -s)" == MSYS* ]] && LOADER_OUT="$(cygpath -w "$LOADER_OUT")"
"$CLANG" "${CLANG_ARGS[@]}" -O2 -fPIE -pie -pthread "$LOADER_SRC" -ldl -o "$LOADER_OUT"
REMOTE="/data/local/tmp/xax-platform-runtime-$$"
adb shell "mkdir -p $REMOTE"
trap 'adb shell "rm -rf '$REMOTE'" >/dev/null 2>&1 || true; rm -rf "$TMP"' EXIT
adb push "$PROBE_PUSH" "$REMOTE/libxax_platform_probe.so" >/dev/null
adb push "$LOADER_OUT" "$REMOTE/xax_platform_runtime_loader" >/dev/null
adb shell "chmod 755 $REMOTE/xax_platform_runtime_loader"
OUTPUT="$(adb shell "cd $REMOTE && ./xax_platform_runtime_loader ./libxax_platform_probe.so" | tr -d '\r')"
echo "$OUTPUT"
grep -q '^XAX_PLATFORM_RUNTIME_OK file=1 thread=1 socket=1$' <<<"$OUTPUT"
DEVICE="$(adb shell getprop ro.product.model | tr -d '\r')"
ANDROID_RELEASE="$(adb shell getprop ro.build.version.release | tr -d '\r')"
ANDROID_API="$(adb shell getprop ro.build.version.sdk | tr -d '\r')"
BRIDGE="$(adb shell getprop ro.dalvik.vm.native.bridge | tr -d '\r')"
QEMU="$(adb shell getprop ro.kernel.qemu | tr -d '\r')"
OUTPUT="$OUTPUT" DEVICE="$DEVICE" ABI="$ABI" ABILIST="$ABILIST" BRIDGE="$BRIDGE" QEMU="$QEMU" ANDROID_RELEASE="$ANDROID_RELEASE" ANDROID_API="$ANDROID_API" EVIDENCE="$EVIDENCE_OUT" python - <<'PY'
import json, os
from pathlib import Path
path=Path(os.environ['EVIDENCE'])
data=json.loads(path.read_text())
data['runtime']={
  'executed': True,
  'result': os.environ['OUTPUT'],
  'device': os.environ['DEVICE'],
  'abi': os.environ['ABI'],
  'abilist': os.environ['ABILIST'],
  'native_bridge': os.environ['BRIDGE'] or None,
  'hardware': os.environ['QEMU'] != '1',
  'arm64_native': os.environ['ABI'].startswith('arm64-v8a'),
  'android_release': os.environ['ANDROID_RELEASE'],
  'android_api': int(os.environ['ANDROID_API']),
  'file': True, 'thread': True, 'socket': True,
}
path.write_text(json.dumps(data, indent=2, sort_keys=True)+'\n')
PY
echo "$EVIDENCE"
