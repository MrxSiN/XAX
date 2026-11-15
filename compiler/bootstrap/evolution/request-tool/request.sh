#!/bin/sh
# sh request.sh <driver> <target> <out>: the build request store for a driver store and a target object (README.md).
# The logic is the XAX program xax_request.xax; this script only builds it with the compiler and runs it.
set -eu
[ $# -eq 3 ] || { echo "usage: request.sh <driver> <target> <out>" >&2; exit 3; }
here=$(cd "$(dirname "$0")" && pwd)
bootstrap=$(dirname "$(dirname "$here")")
xaxc=${XAXC:-"$bootstrap/seed/xaxc-linux-x86_64"}
work=$(mktemp -d "${TMPDIR:-/tmp}/xax-request.XXXXXX")
trap 'rm -rf "$work"' EXIT
"$xaxc" resolve "$here/xax_request.xax" "$work/request.xax"
"$xaxc" build "$work/request.xax" "$work/xax_request" "$work/provenance"
chmod 755 "$work/xax_request"
"$work/xax_request" "$1" "$2" "$3"
