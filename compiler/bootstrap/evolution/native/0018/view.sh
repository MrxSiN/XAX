#!/bin/sh
# view.sh <view> <cid-prefix> > <new view>: ledger 0018's rewrite of one function view (sites.txt): pack.awk on its
# image-buffer accesses, the image cap 2^25 -> 48 MiB and the container cap and buffer 2^25 + 64 KiB -> 48 MiB + 64 KiB
# where sites.txt lists them, then ../0015/renumber.awk.
here=$(dirname "$0"); view=$1; cid=$2
line=$(grep "^$cid " "$here/sites.txt") || { echo "view.sh: $cid not in sites.txt" >&2; exit 1; }
sites=$(echo "$line" | awk '{ for (i = 3; i <= NF; i++) if ($i ~ /^N[0-9]+:/) s = s " " $i; print s }')
tmp=${TMPDIR:-/tmp}/xax0018.$$
if [ -n "$sites" ]; then awk -v SITES="$sites" -f "$here/pack.awk" "$view" "$view" > "$tmp" || exit 1; else cp "$view" "$tmp"; fi
case " $line " in *" image "*) sed -i 's/ constant 33554432 -> / constant 50331648 -> /' "$tmp" ;; esac
case " $line " in *" container "*) sed -i 's/ constant 33619968 -> / constant 50397184 -> /' "$tmp" ;; esac
awk -f "$here/../0015/renumber.awk" "$tmp" "$tmp"
rm -f "$tmp"
