#!/bin/sh
# mka64.sh <store> <batch> [<CID>]: the AArch64 view builder (value_facts' AArch64 caller) with the fold loop spliced in
set -eu
here=$(cd "$(dirname "$0")" && pwd); native=${NATIVE:-/home/user/XAX/compiler/bootstrap/evolution/native}
xaxc=${XAXC:-$native/../../seed/xaxc-linux-x86_64}; cid=${3:-df9251f8b744c4244398e5d96a60cb3fb337032482c98abd5de678e81c37fb79}
work=$(mktemp -d); trap 'rm -r "$work"' EXIT
: > "$work/empty"; "$xaxc" edit "$1" "$work/empty" "$work/list"
handle=$(grep " $cid" "$work/list" | cut -d' ' -f1)
echo "$handle" > "$work/sel"; "$xaxc" edit "$1" "$work/sel" "$work/f.view"
sed 's/W = "T5"; M = "T2"/W = "T0"; M = "T3"/' "$native/0020/ws64.awk" > "$work/ws.awk"
awk -f "$work/ws.awk" "$here/a64fold.src" > "$work/loop"
tail -n +3 "$work/f.view" | awk -v LOOP="$work/loop" -f "$here/splice.awk" > "$work/e1"
awk -f "$native/0020/blockrenum.awk" "$work/e1" "$work/e1" > "$work/e2"
awk -f "$native/0015/renumber.awk" "$work/e2" "$work/e2" > "$work/e3"
{ head -1 "$work/f.view"; echo "$handle"; echo "define @a64view"; cat "$work/e3"; echo end; echo "replace $handle @a64view"; } > "$2"
