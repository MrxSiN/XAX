#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
APK="${XAX_ANDROID_APK:-$ROOT/benchmarks/android_minimal_activity.apk}"
PACKAGE="xax.generated"
COMPONENT="$PACKAGE/.XaxActivity"
REMOTE_XML="/data/local/tmp/xax_activity_ui.xml"

command -v adb >/dev/null || { echo "adb not found" >&2; exit 2; }
[ -f "$APK" ] || { echo "APK not found: $APK" >&2; exit 2; }
# Git Bash on Windows rewrites device paths like /data/local/tmp; stop that and give adb.exe a native host path.
if command -v cygpath >/dev/null; then export MSYS_NO_PATHCONV=1; APK="$(cygpath -m "$APK")"; fi

ABIS="$(adb shell getprop ro.product.cpu.abilist | tr -d '\r')"
case ",$ABIS," in
  *,arm64-v8a,*) ;;
  *) echo "connected Android target does not advertise arm64-v8a: $ABIS" >&2; exit 2 ;;
esac

cleanup() {
  adb shell rm -f "$REMOTE_XML" >/dev/null 2>&1 || true
  if [ "${XAX_KEEP_INSTALLED:-0}" != "1" ]; then
    adb uninstall "$PACKAGE" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

adb install -r -t "$APK" >/dev/null
adb shell am force-stop "$PACKAGE"
START_OUTPUT="$(adb shell am start -W -n "$COMPONENT" 2>&1 | tr -d '\r')"
printf '%s\n' "$START_OUTPUT"
printf '%s\n' "$START_OUTPUT" | grep -q '^Status: ok$' || {
  echo "Activity launch did not report Status: ok" >&2
  exit 3
}

PID="$(adb shell pidof "$PACKAGE" | tr -d '\r')"
[ -n "$PID" ] || { echo "Activity process is not alive after lifecycle callback" >&2; exit 4; }

adb shell uiautomator dump "$REMOTE_XML" >/dev/null
INITIAL_XML="$(adb exec-out cat "$REMOTE_XML" | tr -d '\r')"
printf '%s' "$INITIAL_XML" | grep -Fq 'text="XAX"' || {
  echo "initial XAX button text not found" >&2
  exit 5
}

SIZE="$(adb shell wm size | tr -d '\r' | tail -n1)"
WIDTH="${SIZE##* }"; WIDTH="${WIDTH%x*}"
HEIGHT="${SIZE##*x}"
case "$WIDTH:$HEIGHT" in
  *[!0-9:]*|:|*:) echo "unable to parse device size: $SIZE" >&2; exit 6 ;;
esac
adb shell input tap "$((WIDTH / 2))" "$((HEIGHT / 2))"
sleep 1

PID_AFTER="$(adb shell pidof "$PACKAGE" | tr -d '\r')"
[ -n "$PID_AFTER" ] || { echo "Activity process died during click/native callback" >&2; exit 7; }

adb shell uiautomator dump "$REMOTE_XML" >/dev/null
CLICK_XML="$(adb exec-out cat "$REMOTE_XML" | tr -d '\r')"
printf '%s' "$CLICK_XML" | grep -Fq 'text="Clicked"' || {
  echo "Clicked button state not found after tap" >&2
  exit 8
}

echo "XAX Android Activity validation passed: install, launch, initial UI, click state mutation, and callback survival"
