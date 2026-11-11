#!/bin/sh
# rebuild.sh <production driver store before> <batch> <BBC driver store> <BBC driver store out>
# BBC's driver after one production ledger transaction: the transaction's own batch, applied to BBC's store by
# `xaxc edit` and accepted by `xaxc verify`.  Only the batch's store handles change: its root line becomes BBC's
# root and each function handle F<n> of the production store becomes that function's CID (an entity) or its handle
# in BBC's store (the function line and `replace`).  The engine rebuilds every caller, BBC's entry and its four
# driver entries among them.  Run it once per transaction, in ledger order.  sh, grep, cut, sed, sort and xaxc only.
#
# Ceiling: a batch that names the production entry itself declines here (BBC's entry is its Windows form, another
# function); write that transaction for BBC's entry as its own native batch.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
xaxc=${XAXC:-$here/../../../../../bootstrap/seed/xaxc-linux-x86_64}
[ $# -eq 4 ] || { echo "usage: rebuild.sh <driver store before> <batch> <BBC store> <BBC store out>" >&2; exit 3; }
before=$1; batch=$2; bbc=$3; out=$4
work=$(mktemp -d "${TMPDIR:-/tmp}/bbc-rebuild.XXXXXX")
trap 'rm -rf "$work"' EXIT
: > "$work/empty"
"$xaxc" edit "$before" "$work/empty" "$work/d.list"
"$xaxc" edit "$bbc" "$work/empty" "$work/b.list"
[ "$(head -1 "$batch")" = "$(head -1 "$work/d.list")" ] || { echo "rebuild.sh: $batch is not a batch for $before" >&2; exit 1; }
# pass 1 names each handle by its CID, pass 2 gives the function line and `replace` BBC's handle: no handle is
# rewritten twice
echo "1s/.*/$(head -1 "$work/b.list")/" > "$work/pass1"; : > "$work/pass2"
for f in $(grep -oE '(^|entity=|^replace )F[0-9]+' "$batch" | grep -oE 'F[0-9]+$' | sort -u); do
    cid=$(grep "^$f " "$work/d.list" | cut -d' ' -f2)
    h=$(grep " $cid" "$work/b.list" | cut -d' ' -f1)
    [ -n "$cid" ] && [ -n "$h" ] || { echo "rebuild.sh: $f ($cid) of the production store is not in $bbc" >&2; exit 2; }
    { echo "s/^$f\$/C:$cid/"; echo "s/^replace $f /replace C:$cid /"; echo "s/entity=$f /entity=$cid /g"; } >> "$work/pass1"
    { echo "s/^C:$cid\$/$h/"; echo "s/^replace C:$cid /replace $h /"; } >> "$work/pass2"
done
sed -f "$work/pass1" "$batch" | sed -f "$work/pass2" > "$work/batch"
"$xaxc" edit "$bbc" "$work/batch" "$out"
"$xaxc" verify "$out" "$work/verify"
