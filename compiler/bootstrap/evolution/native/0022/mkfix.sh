#!/bin/sh
# mkfix.sh <store> <batch>: the emit function (CID 738e715c...) with the hoisted-register loop spliced before its frame
set -eu
here=$(cd "$(dirname "$0")" && pwd); native=$(cd "$here/.." && pwd)
xaxc=${XAXC:-$native/../../seed/xaxc-linux-x86_64}
work=$(mktemp -d); trap 'rm -r "$work"' EXIT
: > "$work/empty"; "$xaxc" edit "$1" "$work/empty" "$work/list"
handle=$(grep " 738e715c9203cca8b22583199a34d5c682c3cb38ce2a9e320cdd0500026bdf13" "$work/list" | cut -d' ' -f1)
echo "$handle" > "$work/sel"; "$xaxc" edit "$1" "$work/sel" "$work/f.view"
sed 's/W = "T5"; M = "T2"/W = "T0"; M = "T3"/' "$native/0020/ws64.awk" > "$work/ws.awk"
awk -f "$work/ws.awk" "$here/hoisted.src" > "$work/loop"
tail -n +3 "$work/f.view" | awk -v LOOP="$work/loop" -f "$here/hoisted_splice.awk" > "$work/e1"
awk -f "$native/0020/blockrenum.awk" "$work/e1" "$work/e1" > "$work/e2"
awk -f "$native/0015/renumber.awk" "$work/e2" "$work/e2" > "$work/e3"
{ head -1 "$work/f.view"; echo "$handle"; echo "define @emitf"; cat "$work/e3"; echo end; echo "replace $handle @emitf"; } > "$2"
