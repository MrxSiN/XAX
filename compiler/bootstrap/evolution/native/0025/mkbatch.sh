#!/bin/sh
# mkbatch.sh <store> <batch out>: ledger 0025's batch for one store.
# `_conditional` (CID 8037b966...) of the AArch64 register lowering: exit_copies.awk on the function's own view, then
# ../0015/renumber.awk numbers the nodes.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
xaxc=${XAXC:-$here/../../../seed/xaxc-linux-x86_64}
store=$1; out=$2; tmp=${TMPDIR:-/tmp}/xax0025.$$; mkdir -p "$tmp"
: > "$tmp/empty"
"$xaxc" edit "$store" "$tmp/empty" "$tmp/list"
f=$(grep " 8037b966825402a06902e04e205d95f3d409ce55fea4754992459034a71482b2\$" "$tmp/list" | cut -d' ' -f1)
echo "$f" > "$tmp/sel"; "$xaxc" edit "$store" "$tmp/sel" "$tmp/view"
tail -n +3 "$tmp/view" | awk -f "$here/exit_copies.awk" > "$tmp/edited"
{ head -1 "$tmp/view"; echo "$f"
  echo "define @conditional"; awk -f "$here/../0015/renumber.awk" "$tmp/edited" "$tmp/edited"; echo end
  echo "replace $f @conditional"; } > "$out"
rm -rf "$tmp"
