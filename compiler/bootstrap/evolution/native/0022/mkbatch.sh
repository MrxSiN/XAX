#!/bin/sh
# mkbatch.sh <store> <batch>: list <store>, view its `basics`, splice in the fold loop, number the result, write the batch.
set -eu
here=$(cd "$(dirname "$0")" && pwd); native=$(cd "$here/.." && pwd)
xaxc=${XAXC:-$native/../../seed/xaxc-linux-x86_64}
work=$(mktemp -d); trap 'rm -r "$work"' EXIT
: > "$work/empty"; "$xaxc" edit "$1" "$work/empty" "$work/list"
handle=$(grep " $BASICS_CID" "$work/list" | cut -d' ' -f1)
echo "$handle" > "$work/sel"; "$xaxc" edit "$1" "$work/sel" "$work/basics.view"
awk -f "$native/0020/ws64.awk" "$here/fold.src" > "$work/fold.x"
tail -n +3 "$work/basics.view" | awk -v FOLD="$work/fold.x" -f "$here/splice.awk" > "$work/b1"
awk -f "$native/0020/blockrenum.awk" "$work/b1" "$work/b1" > "$work/b2"
awk -f "$native/0015/renumber.awk" "$work/b2" "$work/b2" > "$work/b3"
{ head -1 "$work/basics.view"; echo "$handle"; echo "define @basics"; cat "$work/b3"; echo end; echo "replace $handle @basics"; } > "$2"
