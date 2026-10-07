#!/usr/bin/env bash
# Run the Vector runtime harness against the adb device in ANDROID_SERIAL (or the only one).
# Validation-only: nothing here builds XAX output beyond the deterministic signed profiles.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
COMPILER="$(cd "$HERE/../../.." && pwd)"
command -v adb >/dev/null || { echo "adb not found" >&2; exit 2; }
adb get-state >/dev/null 2>&1 || { echo "no adb device; set ANDROID_SERIAL" >&2; exit 2; }
cd "$COMPILER"
PYTHONPATH="src:.:..${PYTHONPATH:+:$PYTHONPATH}" exec python "$HERE/vector_harness.py" "$@"
