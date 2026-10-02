#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TARGET_APK="${XAX_LIBXPOSED_TARGET_APK:-$ROOT/benchmarks/android_libxposed_runtime_target_signed.apk}"
MODULE_APK="${XAX_LIBXPOSED_MODULE_APK:-$ROOT/benchmarks/android_libxposed_runtime_module_signed.apk}"
TARGET_PACKAGE="com.example.target"
MODULE_PACKAGE="com.example.module"
COMPONENT="$TARGET_PACKAGE/.XaxActivity"
REMOTE_XML="/data/local/tmp/xax_libxposed_ui.xml"

command -v adb >/dev/null || { echo "adb not found" >&2; exit 2; }
[ -f "$TARGET_APK" ] || { echo "target APK not found: $TARGET_APK" >&2; exit 2; }
[ -f "$MODULE_APK" ] || { echo "module APK not found: $MODULE_APK" >&2; exit 2; }
[ "${XAX_LIBXPOSED_PREPARED:-0}" = "1" ] || {
  echo "set XAX_LIBXPOSED_PREPARED=1 only after enabling $MODULE_PACKAGE and scoping it to $TARGET_PACKAGE in the installed compatible libxposed framework" >&2
  exit 2
}

ABIS="$(adb shell getprop ro.product.cpu.abilist | tr -d '\r')"
case ",$ABIS," in *,arm64-v8a,*) ;; *) echo "target does not advertise arm64-v8a: $ABIS" >&2; exit 2 ;; esac

cleanup() {
  adb shell rm -f "$REMOTE_XML" >/dev/null 2>&1 || true
  if [ "${XAX_KEEP_INSTALLED:-0}" != "1" ]; then
    adb uninstall "$TARGET_PACKAGE" >/dev/null 2>&1 || true
    adb uninstall "$MODULE_PACKAGE" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

adb install -r -t "$MODULE_APK" >/dev/null
adb install -r -t "$TARGET_APK" >/dev/null
adb shell am force-stop "$TARGET_PACKAGE"
START="$(adb shell am start -W -n "$COMPONENT" 2>&1 | tr -d '\r')"
printf '%s\n' "$START"
printf '%s\n' "$START" | grep -q '^Status: ok$' || { echo "target Activity launch failed" >&2; exit 3; }

PID="$(adb shell pidof "$TARGET_PACKAGE" | tr -d '\r')"
[ -n "$PID" ] || { echo "target process is not alive after libxposed package-ready/interception path" >&2; exit 4; }
sleep 1
adb shell uiautomator dump "$REMOTE_XML" >/dev/null
XML="$(adb exec-out cat "$REMOTE_XML" | tr -d '\r')"
if printf '%s' "$XML" | grep -Fq 'text="HookedResult"'; then
  echo "XAX libxposed combined validation passed: module discovery/scope precondition, package-ready hook path, interception, original proceed, and visible result replacement"
  exit 0
fi
if printf '%s' "$XML" | grep -Fq 'text="OriginalArg"'; then
  echo "target remained unhooked (OriginalArg visible); verify the module is enabled, scoped to com.example.target, and the framework is API-102 compatible" >&2
  exit 5
fi
echo "neither expected HookedResult nor unhooked OriginalArg is visible" >&2
exit 6
