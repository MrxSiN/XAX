#!/bin/sh
# mkbatch.sh <store> <batch out>: ledger 0021's batch for the driver or the request store.  It supplies the type
# heap_view<8 MiB>, defines @decode (`decode`, CID cb5dc08f...) and @main (the driver's main, CID 2713dde0...) from the
# store's own views through body8.awk, then replaces main (its @decode call leaves the old decode unreachable; replacing decode as well would rebuild the old main beside the new one).
set -eu
here=$(cd "$(dirname "$0")" && pwd)
xaxc=${XAXC:-$here/../../../seed/xaxc-linux-x86_64}
store=$1; out=$2; tmp=${TMPDIR:-/tmp}/xax0021.$$; mkdir -p "$tmp"
: > "$tmp/empty"
"$xaxc" edit "$store" "$tmp/empty" "$tmp/list"
handle() { grep " $1\$" "$tmp/list" | cut -d' ' -f1; }
fd=$(handle cb5dc08f67b2bbd455f148b6d4bba2014b8b9575f38ddc30858ef080001551ba)
fm=$(handle 2713dde074a31c667a259f0efb5936c12e5d82842a41d1cf5217910a55fd7646)
view() { echo "$1" > "$tmp/sel"; "$xaxc" edit "$store" "$tmp/sel" "$2"; }
view "$fd" "$tmp/decode"; view "$fm" "$tmp/main"
{ head -1 "$tmp/main"; echo "$fm"
  echo "define @view8"; echo "object 4 0x04810201048080800400"; echo end
  sed -e 's/3431393433303403/3833383836303803/' -e 's/6dff1135b04230868f3f844c607746a224f5f1236a5af8e229839df0ea129f63/e9ce063c1048ad3a35e03fee6e80d0d2a085a839645965750acdd60792bd4520/' "$here/munmap4.hex" |
    awk '{ printf "define @unmap_%s\nobject 6 0x%s\nend\n", (NR == 1 ? "a" : "b"), $2 }'
  echo "define @decode"; tail -n +3 "$tmp/decode" | awk -f "$here/body8.awk"; echo end
  echo "define @main"; tail -n +3 "$tmp/main" | awk -v DECODE="$fd" -f "$here/body8.awk"; echo end
  echo "replace $fm @main"; } > "$out"
rm -rf "$tmp"
