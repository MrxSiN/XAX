#!/bin/sh
# mkbatch.sh <store> <batch out>: ledger 0020's batch for one store.
#  - `_intervals` (CID 0952bb79...): the range pool sized by @pool_bound (pool_bound.src; intervals.awk).
#  - `_aliases` (CID adc7c672...): each parameter's incoming arguments listed once (lists.src through blocks.awk;
#    aliases.awk) instead of a scan of every edge per parameter and round.
# ws64.awk expands the workspace words, blockrenum.awk numbers blocks and ../0015/renumber.awk nodes and parameters.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
xaxc=${XAXC:-$here/../../../seed/xaxc-linux-x86_64}
store=$1; out=$2; tmp=${TMPDIR:-/tmp}/xax0020.$$; mkdir -p "$tmp"
: > "$tmp/empty"
"$xaxc" edit "$store" "$tmp/empty" "$tmp/list"
handle() { grep " $1\$" "$tmp/list" | cut -d' ' -f1; }
fa=$(handle adc7c67261ca7d64848a4f1a80128d405216355ec3f225ff1cd6f61a034fe367)
fi=$(handle 0952bb790a56f62d7542d071d1f269020d35b076d20e3b6d05218e34fccfc28a)
view() { echo "$1" > "$tmp/sel"; "$xaxc" edit "$store" "$tmp/sel" "$2"; }
view "$fa" "$tmp/aliases"; view "$fi" "$tmp/intervals"
number() { awk -f "$here/ws64.awk" "$1" > "$1.ws"; awk -f "$here/blockrenum.awk" "$1.ws" "$1.ws" > "$1.b"; awk -f "$here/../0015/renumber.awk" "$1.b" "$1.b"; }
awk -f "$here/blocks.awk" "$here/lists.src" > "$tmp/lists"
tail -n +3 "$tmp/aliases" | awk -v LISTS="$tmp/lists" -f "$here/aliases.awk" > "$tmp/a.edited"
tail -n +3 "$tmp/intervals" | awk -f "$here/intervals.awk" > "$tmp/i.edited"
cp "$here/pool_bound.src" "$tmp/p.edited"
{ head -1 "$tmp/aliases"; echo "$fa"
  echo "define @pool_bound"; number "$tmp/p.edited"; echo end
  echo "define @intervals"; number "$tmp/i.edited"; echo end
  echo "define @aliases"; number "$tmp/a.edited"; echo end
  echo "replace $fi @intervals"; echo "replace $fa @aliases"; } > "$out"
rm -rf "$tmp"
