#!/usr/bin/env bash
set -euo pipefail

: "${ANDROID_NDK_HOME:?set ANDROID_NDK_HOME to an Android NDK root}"
API="${ANDROID_API:-26}"
HOST_TAG="${ANDROID_NDK_HOST_TAG:-linux-x86_64}"
TOOLCHAIN="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/$HOST_TAG/bin"
CLANG="$TOOLCHAIN/aarch64-linux-android${API}-clang"
READELF="${LLVM_READELF:-$TOOLCHAIN/llvm-readelf}"
OBJDUMP="${LLVM_OBJDUMP:-$TOOLCHAIN/llvm-objdump}"

for tool in "$CLANG" "$READELF" "$OBJDUMP"; do
  [[ -x "$tool" ]] || { echo "missing tool: $tool" >&2; exit 2; }
done

HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="${1:-$HERE/out}"
mkdir -p "$OUT"

build_one() {
  local src="$1" name="$2"
  "$CLANG" -O2 -fPIC -shared -nostdlib -Wl,--build-id=none \
    -Wl,-z,max-page-size=16384 -Wl,-z,common-page-size=16384 \
    "$HERE/$src" -o "$OUT/$name.so"
  "$READELF" -h -l -d -s -r "$OUT/$name.so" > "$OUT/$name.readelf.txt"
  "$OBJDUMP" -d "$OUT/$name.so" > "$OUT/$name.objdump.txt"
}

build_one native_init.c native_init
build_one jni_onload.c jni_onload
# This reference intentionally uses a real Bionic import and therefore is not -nostdlib.
"$CLANG" -O2 -fPIC -shared -Wl,--build-id=none \
  -Wl,-z,max-page-size=16384 -Wl,-z,common-page-size=16384 \
  "$HERE/import_getpid.c" -o "$OUT/import_getpid.so"
"$READELF" -h -l -d -s -r "$OUT/import_getpid.so" > "$OUT/import_getpid.readelf.txt"
"$OBJDUMP" -d "$OUT/import_getpid.so" > "$OUT/import_getpid.objdump.txt"

printf 'NDK reference artifacts written to %s\n' "$OUT"
