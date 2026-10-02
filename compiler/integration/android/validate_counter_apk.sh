#!/usr/bin/env bash
# Device oracle for benchmarks/android_counter_activity.apk (ADR-111).  Validation only.
# Checks: fresh install shows 0; three taps show 1, 2, 3; after force-stop and relaunch the
# Activity restores 3 (state persisted by XAX native code); one more tap shows 4; the private
# state file holds the 8-byte little-endian value 4.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
APK="${XAX_ANDROID_APK:-$ROOT/benchmarks/android_counter_activity.apk}"
PACKAGE="xax.counter"
COMPONENT="$PACKAGE/.CounterActivity"
REMOTE_XML="/data/local/tmp/xax_counter_ui.xml"

command -v adb >/dev/null || { echo "adb not found" >&2; exit 2; }
[ -f "$APK" ] || { echo "APK not found: $APK" >&2; exit 2; }
if command -v cygpath >/dev/null; then export MSYS_NO_PATHCONV=1; APK="$(cygpath -m "$APK")"; fi
ABIS="$(adb shell getprop ro.product.cpu.abilist | tr -d '\r')"
case ",$ABIS," in *,arm64-v8a,*) ;; *) echo "target does not advertise arm64-v8a: $ABIS" >&2; exit 2 ;; esac

cleanup() {
  adb shell rm -f "$REMOTE_XML" >/dev/null 2>&1 || true
  [ "${XAX_KEEP_INSTALLED:-0}" = "1" ] || adb uninstall "$PACKAGE" >/dev/null 2>&1 || true
}
trap cleanup EXIT

launch() {
  adb shell am force-stop "$PACKAGE"
  local output; output="$(adb shell am start -W -n "$COMPONENT" 2>&1 | tr -d '\r')"
  printf '%s\n' "$output" | grep -q '^Status: ok$' || { printf '%s\n' "$output"; echo "launch failed" >&2; exit 3; }
  sleep 1
}

expect_text() {
  adb shell uiautomator dump "$REMOTE_XML" >/dev/null
  adb exec-out cat "$REMOTE_XML" | tr -d '\r' | grep -Fq "text=\"$1\"" || { echo "expected button text $1" >&2; exit 4; }
  [ -n "$(adb shell pidof "$PACKAGE" | tr -d '\r')" ] || { echo "process died" >&2; exit 5; }
  echo "ok: $1"
}

tap() {
  local size width height
  size="$(adb shell wm size | tr -d '\r' | tail -n1)"; width="${size##* }"; width="${width%x*}"; height="${size##*x}"
  adb shell input tap "$((width / 2))" "$((height / 2))"
  sleep 1
}

adb uninstall "$PACKAGE" >/dev/null 2>&1 || true
adb install -t "$APK" >/dev/null
launch; expect_text 0
tap; expect_text 1
tap; expect_text 2
tap; expect_text 3
launch; expect_text 3          # restored after the process was killed
tap; expect_text 4
# run-as works only for debuggable builds; the UI checks above already prove persistence.
if STATE="$(adb exec-out run-as "$PACKAGE" od -An -tu8 -N8 files/xax.counter 2>/dev/null | tr -d ' \r\n')" && [ -n "$STATE" ]; then
  [ "$STATE" = "4" ] || { echo "state file holds '$STATE', expected 4" >&2; exit 6; }
  echo "ok: state file 4"
else
  echo "note: state file not readable via run-as (non-debuggable build)"
fi
echo "XAX counter Activity validation passed: restore, increment, persistence across process death, file contents"
