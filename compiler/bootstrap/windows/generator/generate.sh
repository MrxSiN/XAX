#!/bin/sh
# sh generate.sh <request> <out>: the Windows seed's build request from the shared compiler request (README.md).
# The logic is the XAX program xax_hosting.xax; this script only runs xaxc and that program.
set -eu
[ $# -eq 2 ] || { echo "usage: generate.sh <request> <out>" >&2; exit 3; }
here=$(cd "$(dirname "$0")" && pwd)
windows=$(dirname "$here")
bootstrap=$(dirname "$windows")
xaxc=${XAXC:-"$bootstrap/seed/xaxc-linux-x86_64"}
work=$(mktemp -d "${TMPDIR:-/tmp}/xax-windows.XXXXXX")
trap 'rm -rf "$work"' EXIT
"$xaxc" resolve "$here/xax_hosting.xax" "$work/tool.xax"
"$xaxc" build "$work/tool.xax" "$work/xax_hosting" "$work/provenance"
chmod 755 "$work/xax_hosting"
tool="$work/xax_hosting"
: > "$work/empty"
"$xaxc" edit "$1" "$work/empty" "$work/listing"
"$tool" e "$1" "$work/listing" /dev/null "$work/main"
"$xaxc" edit "$1" "$work/main" "$work/main.view"
"$tool" b "$work/main.view" "$work/listing" "$windows/host_layer.txt" "$work/hosting.batch"
"$xaxc" edit "$1" "$work/hosting.batch" "$work/hosted.xax"
"$xaxc" verify "$work/hosted.xax" "$work/hosted.diag"
"$tool" r "$work/hosted.xax" "$here/pe_target.template" /dev/null "$work/pe_target.edit"
"$xaxc" edit "$work/hosted.xax" "$work/pe_target.edit" "$2"
"$xaxc" verify "$2" "$work/request.diag"
