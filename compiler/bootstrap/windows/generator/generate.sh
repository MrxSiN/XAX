#!/bin/sh
# sh generate.sh <request> <out>: the Windows seed's build request from the shared compiler request (README.md).
# The logic is the XAX program xax_hosting.xax; this script only runs xaxc and that program, and puts the hosted
# store's root line before pe_target.batch.
set -eu
[ $# -eq 2 ] || { echo "usage: generate.sh <request> <out>" >&2; exit 3; }
here=$(cd "$(dirname "$0")" && pwd)
windows=$(dirname "$here")
bootstrap=$(dirname "$windows")
case $(uname -s) in  # on Windows (Git for Windows' sh) the Windows seed builds the hosted copy of the tool
    MINGW*|MSYS*|CYGWIN*) seed=$windows/xaxc-windows-x86_64.exe; program=$here/xax_hosting_windows.xax; exe=.exe ;;
    *) seed=$bootstrap/seed/xaxc-linux-x86_64; program=$here/xax_hosting.xax; exe= ;;
esac
xaxc=${XAXC:-$seed}
work=$(mktemp -d "${TMPDIR:-/tmp}/xax-windows.XXXXXX")
trap 'rm -rf "$work"' EXIT
"$xaxc" resolve "$program" "$work/tool.xax"
"$xaxc" build "$work/tool.xax" "$work/xax_hosting$exe" "$work/provenance"
chmod 755 "$work/xax_hosting$exe"
tool="$work/xax_hosting$exe"
: > "$work/empty"
"$xaxc" edit "$1" "$work/empty" "$work/listing"
"$tool" e "$1" "$work/listing" "$work/empty" "$work/main"
"$xaxc" edit "$1" "$work/main" "$work/main.view"
"$tool" b "$work/main.view" "$work/listing" "$windows/host_layer.txt" "$work/hosting.batch"
"$xaxc" edit "$1" "$work/hosting.batch" "$work/hosted.xax"
"$xaxc" verify "$work/hosted.xax" "$work/hosted.diag"
"$xaxc" edit "$work/hosted.xax" "$work/empty" "$work/hosted.listing"
{ head -n 1 "$work/hosted.listing"; echo F0; cat "$here/pe_target.batch"; } > "$work/pe_target.batch"
"$xaxc" edit "$work/hosted.xax" "$work/pe_target.batch" "$2"
"$xaxc" verify "$2" "$work/request.diag"
