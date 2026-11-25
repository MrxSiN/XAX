#!/bin/sh
# sh request.sh <driver> <target> <out>: the build request store for a driver store and a target object (README.md).
# The logic is the XAX program xax_request.xax; this script only builds it with the compiler and runs it. On Windows
# (Git for Windows' sh) the pinned Windows seed builds xax_request_windows.xax instead.
set -eu
[ $# -eq 3 ] || { echo "usage: request.sh <driver> <target> <out>" >&2; exit 3; }
here=$(cd "$(dirname "$0")" && pwd)
bootstrap=$(dirname "$(dirname "$here")")
case $(uname -s) in
    MINGW*|MSYS*|CYGWIN*) seed=$bootstrap/windows/xaxc-windows-x86_64.exe; program=$here/xax_request_windows.xax; exe=.exe ;;
    *) seed=$bootstrap/seed/xaxc-linux-x86_64; program=$here/xax_request.xax; exe= ;;
esac
xaxc=${XAXC:-$seed}
work=$(mktemp -d "${TMPDIR:-/tmp}/xax-request.XXXXXX")
trap 'rm -rf "$work"' EXIT
"$xaxc" resolve "$program" "$work/request.xax"
"$xaxc" build "$work/request.xax" "$work/xax_request$exe" "$work/provenance"
chmod 755 "$work/xax_request$exe"
"$work/xax_request$exe" "$1" "$2" "$3"
