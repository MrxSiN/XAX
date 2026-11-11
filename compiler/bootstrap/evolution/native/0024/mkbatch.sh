#!/bin/sh
# mkbatch.sh compare|frame <store> <batch>: list <store>, view the function, splice in the source, number the
# result, write the batch.  The function is found by its CID, so the handles the sources name are the ones they
# were written against.
set -eu
here=$(cd "$(dirname "$0")" && pwd); native=$(cd "$here/.." && pwd)
xaxc=${XAXC:-$native/../../seed/xaxc-linux-x86_64}
work=$(mktemp -d); trap 'rm -r "$work"' EXIT
case $1 in
    compare)
        cid=fa9cbfb3e5eff59eec6e8b5bb06f3f8ebb305effa3697cd5db2648e84dbcf52f
        # Two instances of compare.src: `I:` lines and B22 for an immediate right operand, `R:` lines and B41 for a
        # register one (its handles moved out of the first instance's way).
        { sed -e '/^R:/d' -e 's/^I://' -e 's/@NEXT/B22/g' "$here/compare.src"; echo '@@'
          sed -e '/^I:/d' -e 's/^R://' -e 's/@NEXT/B41/g' -e 's/\([PN]\)8000/\18100/g' -e 's/B9000/B9100/g' "$here/compare.src"; } > "$work/in" ;;
    frame) cid=a4e4e43ca24e99532afa7e6e1ab974c925b3ef07fe451a264d60eaa69249ec18; cp "$here/frame.src" "$work/in" ;;
    *) echo "usage: mkbatch.sh compare|frame <store> <batch>" >&2; exit 3 ;;
esac
: > "$work/empty"; "$xaxc" edit "$2" "$work/empty" "$work/list"
handle=$(grep " $cid" "$work/list" | cut -d' ' -f1)
[ -n "$handle" ] || { echo "mkbatch.sh: $2 does not hold the $1 function" >&2; exit 1; }
echo "$handle" > "$work/sel"; "$xaxc" edit "$2" "$work/sel" "$work/f.view"
sed 's/W = "T5"; M = "T2"/W = "T0"; M = "T3"/' "$native/0020/ws64.awk" > "$work/ws.awk"
awk -f "$work/ws.awk" "$work/in" > "$work/src"
tail -n +3 "$work/f.view" > "$work/body"
awk -v SRC="$work/src" -f "$here/$1_splice.awk" "$work/body" "$work/body" > "$work/b1"
awk -f "$native/0020/blockrenum.awk" "$work/b1" "$work/b1" > "$work/b2"
awk -f "$native/0015/renumber.awk" "$work/b2" "$work/b2" > "$work/b3"
{ head -1 "$work/f.view"; echo "$handle"; echo "define @$1"; cat "$work/b3"; echo end; echo "replace $handle @$1"; } > "$3"
