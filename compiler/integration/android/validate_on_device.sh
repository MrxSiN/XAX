#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
SO="$ROOT/libxposed_fixture/app/src/main/jniLibs/arm64-v8a/libxaxmodule.so"
: "${ANDROID_NDK_HOME:?set ANDROID_NDK_HOME to a modern Android NDK}"
command -v adb >/dev/null || { echo "adb not found" >&2; exit 2; }
HOST_TAG=linux-x86_64
case "$(uname -s)-$(uname -m)" in
  Darwin-arm64) HOST_TAG=darwin-x86_64 ;;
  Darwin-x86_64) HOST_TAG=darwin-x86_64 ;;
esac
CLANG="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/$HOST_TAG/bin/aarch64-linux-android26-clang"
[ -x "$CLANG" ] || { echo "Android NDK arm64 clang not found: $CLANG" >&2; exit 2; }
TMP="${TMPDIR:-/tmp}/xax-android-loader-$$"
trap 'rm -f "$TMP"' EXIT
"$CLANG" -O2 -fPIE -pie "$ROOT/device_loader.c" -ldl -o "$TMP"
adb push "$SO" /data/local/tmp/libxaxmodule.so >/dev/null
adb push "$TMP" /data/local/tmp/xax_android_loader >/dev/null
adb shell chmod 755 /data/local/tmp/xax_android_loader
adb shell /data/local/tmp/xax_android_loader /data/local/tmp/libxaxmodule.so
