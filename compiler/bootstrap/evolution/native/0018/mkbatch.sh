#!/bin/sh
# mkbatch.sh A|B <function list> <views dir> <batch>: ledger 0018's batches for one store.
#   <function list>  the store's `xaxc edit <store> <empty file> <list>` output (R <root>, then F<n> <CID>)
#   <views dir>      that store's view of each function below, as <dir>/F<n>.view (`xaxc edit <store> <F<n>> <view>`)
# A (on the store): every function of sites.txt but image_add is redefined from its rewritten view (view.sh),
#   callees first, and a call to another redefined function names it as @name; only general_main (the program's
#   main, called from outside the set) is replaced, and the others are reached through the @ references.
#   Replacing a function whose every caller is redefined here, or a second function whose replacement cascades
#   into the first (image_add -> the view function -> main), leaves an old object unreachable or missing
#   (XAX.IDENTITY.UNREACHABLE_OBJECT, XAX.IDENTITY.OBJECT_MISSING), hence two batches.
# B (on A's result, from that store's list and view): image_add, replaced.
here=$(dirname "$0"); part=$1; list=$2; views=$3; out=$4
case "$part" in
    A) order="image_snapshot dll_edata elf_static image_adapter image_record pe elf_dynamic image_finish general_main"; replaced=general_main ;;
    B) order="image_add"; replaced=image_add ;;
    *) echo "usage: mkbatch.sh A|B <list> <views> <batch>" >&2; exit 2 ;;
esac
cid() { awk -v n="$1" '$2 == n { print $1 }' "$here/sites.txt"; }
handle() { grep " $(cid "$1")" "$list" | cut -d' ' -f1; }
subst=""
for name in $order; do h=$(handle $name); [ -n "$h" ] || { echo "mkbatch.sh: $name not in $list" >&2; exit 1; }; subst="$subst s/entity=$h /entity=@$name /g;"; done
{
    head -1 "$list"
    handle $replaced
    for name in $order; do
        echo "define @$name"
        sh "$here/view.sh" "$views/$(handle $name).view" "$(cid $name)" | tail -n +3 | sed "$subst"
        echo "end"
    done
    echo "replace $(handle $replaced) @$replaced"
} > "$out"
