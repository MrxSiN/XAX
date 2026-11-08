#!/bin/sh
# mkcap.sh <store> <CID> <values: all|v,v> <init: init|-> <batch>: the function's VCAP-derived constants become loads of the
# capacity word (GLOBALS + 170); with init, its entry block first stores the initial capacity there.
set -eu
here=$(cd "$(dirname "$0")" && pwd); native=/home/user/XAX/compiler/bootstrap/evolution/native
xaxc=${XAXC:-/home/user/XAX/compiler/bootstrap/seed/xaxc-linux-x86_64}
work=$(mktemp -d); trap 'rm -r "$work"' EXIT
LIST=${LIST:-$work/list}; [ -s "$LIST" ] || { : > "$work/empty"; "$xaxc" edit "$1" "$work/empty" "$LIST"; }
handle=$(grep " $2" "$LIST" | cut -d' ' -f1); echo "$handle" > "$work/sel"; "$xaxc" edit "$1" "$work/sel" "$work/f.view"
tail -n +3 "$work/f.view" > "$work/body"
vals=$3; [ "$vals" = all ] && vals="262144,262145,262146,524288,524289,786432"
sites=$(awk -v V="$vals" 'BEGIN { n = split(V, a, ","); for (i = 1; i <= n; i++) ok[a[i]] = 1 }
  $2 == "constant" && ($3 in ok) { m = int($3 / 262144); printf "%s%s:%d:%d", (c++ ? "," : ""), $1, m, $3 - m * 262144 }' "$work/body")
W=$(awk -v V="$vals" 'BEGIN { n = split(V, a, ","); for (i = 1; i <= n; i++) ok[a[i]] = 1 } $2 == "constant" && ($3 in ok) { split($5, t, ","); print t[1]; exit }' "$work/body")
B=$(awk '/^T[0-9]+ bits1$/ { print $1; exit }' "$work/body"); I=$(awk '/^T[0-9]+ bits32$/ { print $1; exit }' "$work/body")
[ -n "$B" ] && [ -n "$I" ] && [ -n "$W" ] || { echo "types missing: W=$W B=$B I=$I" >&2; exit 1; }
if [ "$4" = init ]; then awk 'done == 0 && /^B[0-9]+\(/ { print; print "@INITCAP"; done = 1; next } { print }' "$work/body" > "$work/b0"; else cp "$work/body" "$work/b0"; fi
awk -v SITES="$sites" -v W="$W" -v INIT=262144 -v DOINIT=$([ "$4" = init ] && echo 1 || echo 0) -f "$here/cap.awk" "$work/body" "$work/body" > "$work/b1"
M=$(awk '/checked.load.bits.le/ { for (i = 1; i <= NF; i++) if ($i == "->") { split($(i+1), t, ","); print t[2]; exit } }' "$work/b1")
awk -v W="$W" -v M="$M" -v B="$B" -v I="$I" -f "$here/ws.awk" "$work/b1" > "$work/b2"
awk -f "$native/0015/renumber.awk" "$work/b2" "$work/b2" > "$work/b3"
{ head -1 "$work/f.view"; echo "$handle"; echo "define @capf"; cat "$work/b3"; echo end; echo "replace $handle @capf"; } > "$5"
echo "$handle $(echo "$sites" | tr ',' '\n' | grep -c .) sites W=$W M=$M B=$B I=$I" >&2
