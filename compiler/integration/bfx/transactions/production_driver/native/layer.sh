#!/bin/sh
# layer.sh <BBC driver store> <W2 store of rebuild.sh> <work directory>
# Writes <work>/layer_functions.batch, BBC's layer as rebuild.sh takes it (README.md), from a BBC driver store
# (integration/bfx/bbc.xax).  layer.py finds the layer and its call graph; each function's view (kept in
# <work>/views) is made portable by portable.awk, callees before callers (tsort).  Then the four variant stubs, the
# compile steps' argument helpers (helpers.batch) and BBC's entry (entry.view: the store's entry without the graph
# proof cache).
set -eu
here=$(cd "$(dirname "$0")" && pwd)
compiler=$(cd "$here/../../../../.." && pwd)
xaxc=${XAXC:-$compiler/bootstrap/seed/xaxc-linux-x86_64}
store=$1; base=$2; work=$3; mkdir -p "$work/views"; : > "$work/empty"
"$xaxc" edit "$store" "$work/empty" "$work/store.list"
PYTHONPATH="$compiler/src:$compiler/reference" python3 "$here/layer.py" "$store" "$base" > "$work/layer.txt"
entry=$(head -1 "$work/layer.txt" | cut -c1-8)
cut -d' ' -f1 "$work/layer.txt" > "$work/new.txt"
awk '{print substr($1, 1, 8), substr($1, 1, 8); for (i = 2; i <= NF; i++) if ($i !~ /\*$/) print $i, substr($1, 1, 8)}' \
    "$work/layer.txt" | tsort | grep -v -x "$entry" > "$work/order.txt"
{
    while read -r c; do
        if [ ! -s "$work/views/$c.view" ]; then
            grep " $(grep "^$c" "$work/new.txt")" "$work/store.list" | cut -d' ' -f1 > "$work/sel"
            "$xaxc" edit "$store" "$work/sel" "$work/views/$c.view"
        fi
        echo "define @L_$c"
        awk -v BBC="$work/store.list" -v NEW="$work/new.txt" -v VARIANTS="" -v OLDMAIN="" -f "$here/portable.awk" "$work/views/$c.view"
        echo end
    done < "$work/order.txt"
    for v in dae4d02b 3d257046 2d5b5ccd cb6e44b2; do printf 'define @V_%s\n@STUB\nend\n' "$v"; done
    cat "$here/helpers.batch"
    echo "define @L_$entry"; cat "$here/entry.view"; echo end
} > "$work/layer_functions.batch"
echo "$work/layer_functions.batch: $(grep -c '^define' "$work/layer_functions.batch") definitions, entry @L_$entry"
