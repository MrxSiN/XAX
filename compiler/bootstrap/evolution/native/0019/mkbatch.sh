#!/bin/sh
# mkbatch.sh <store> <batch out>: ledger 0019's batch for one store.  candidate (CID ac26e229...) is listed, viewed,
# given the budget guard (budget.awk, BUDGET 2^17 values) and renumbered (../0015/renumber.awk), then replaced.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
xaxc=${XAXC:-$here/../../../seed/xaxc-linux-x86_64}
store=$1; out=$2; tmp=${TMPDIR:-/tmp}/xax0019.$$; mkdir -p "$tmp"
: > "$tmp/empty"
"$xaxc" edit "$store" "$tmp/empty" "$tmp/list"
h=$(grep ' ac26e229eb80aeb9b4a5da13bcf6487de29ff5e4d85383bdfd12299a6fc7ff56$' "$tmp/list" | cut -d' ' -f1)
echo "$h" > "$tmp/sel"
"$xaxc" edit "$store" "$tmp/sel" "$tmp/view"
awk -v BUDGET=131072 -f "$here/budget.awk" "$tmp/view" > "$tmp/guarded"
{ head -1 "$tmp/view"; echo "$h"; echo "define @candidate"; awk -f "$here/../0015/renumber.awk" "$tmp/guarded" "$tmp/guarded"
  echo end; echo "replace $h @candidate"; } > "$out"
rm -rf "$tmp"
