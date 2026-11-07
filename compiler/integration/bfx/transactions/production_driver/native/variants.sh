#!/bin/sh
# variants.sh <store after 3a> <work directory> <eager entry CID> <layer objects batch> <layer functions batch> <stubs>
# BBC's four driver entries, one native batch each.  Each takes the store's own view of the eager entry, rewritten
# by variant.awk:
#   - 17 allocation sites are reserved;
#   - for the three compile steps, arg_copy calls the step's argument helper, the argument count is the step's own
#     (a constant function), and ExitProcess becomes SetLastError.
# The variant then replaces, in its place, the stub that BBC's entry calls.  <stubs> lists "k CID" for the stubs of
# batch 3a, numbered in order.  A step batch also carries the layer's objects (SetLastError among them) and its
# argument helper's definition (layer_functions.batch).  Only the variant reaches them, so 3a's store dropped them.
# The last store is <work>/B3v4.xax.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
store=$1; work=$2; main=$3; objects=$4; layer=$5; stubs=$6
xaxc=${XAXC:-$here/../../../../../bootstrap/seed/xaxc-linux-x86_64}
valloc=e8cf5a7cb5283490c972afd87b89985a4a1f8e616e6d47b2326aa6c3061e6a58
exitprocess=8718568ef087172920355a78db42489d2d7c3391463aebb73164f523cb03e5e4
argcopy=8e86608556a77e3dbb6e371fa96acf9e96bfe4afac5ec1baee7d77a373c6a353
argc=e1d73163fb70f4f10dedfe731c98c67c027e69e82efb6074a40aed36bed85c6c
reserve="1 2 3 4 6 7 8 9 12 13 14 15 18 19 20 21 22"
: > "$work/empty"
i=0
# variant name : step argument helper : step argument count (resolve 4; build and edit 5), as CID prefixes, in stub
# order; the lazy command-line entry has neither
for spec in dae4d02b:: 3d257046:5e2a3f84:a07e002e 2d5b5ccd:8fcd655d:822b1e3d cb6e44b2:e726006e:822b1e3d; do
    i=$((i + 1))
    variant=${spec%%:*}; rest=${spec#*:}; helper=${rest%%:*}; count=${rest#*:}
    stub=$(awk -v k=$i '$1 == k {print $2}' "$stubs")
    "$xaxc" edit "$store" "$work/empty" "$work/s$i.list"
    sh_=$(grep " $stub" "$work/s$i.list" | cut -d' ' -f1)
    mh=$(grep " $main" "$work/s$i.list" | cut -d' ' -f1)
    ah=$(grep " $argcopy" "$work/s$i.list" | cut -d' ' -f1)
    ch=$(grep " $argc" "$work/s$i.list" | cut -d' ' -f1)
    echo "$mh" > "$work/s$i.sel"
    "$xaxc" edit "$store" "$work/s$i.sel" "$work/s$i.main"
    root=$(head -1 "$work/s$i.main")
    batch="$work/3v$i.batch"
    if [ -n "$helper" ]; then
        awk -v VALLOC=$valloc -v RESERVE="$reserve" -v ARGFROM="$ah" -v ARGTO="@L_$helper" -v ARGCFROM="$ch" -v ARGCTO="@L_$count" -v EXITFROM=$exitprocess -v EXITTO=@o_7c0d581e \
            -f "$here/variant.awk" "$work/s$i.main" "$work/s$i.main" > "$work/s$i.view"
        { echo "$root"; echo "$sh_"; cat "$objects"
          for f in "$helper" "$count"; do
              awk -v name="define @L_$f" '$0 == name {p = 1} p {print} p && $0 == "end" {exit}' "$layer" | sed "s/entity=@MAIN /entity=$main /"
          done
          echo "define @V_$variant"; cat "$work/s$i.view"; echo end; echo "replace $sh_ @V_$variant"; } > "$batch"
    else
        awk -v VALLOC=$valloc -v RESERVE="$reserve" -f "$here/variant.awk" "$work/s$i.main" "$work/s$i.main" > "$work/s$i.view"
        { echo "$root"; echo "$sh_"; echo "define @V_$variant"; cat "$work/s$i.view"; echo end; echo "replace $sh_ @V_$variant"; } > "$batch"
    fi
    echo "$batch: stub $sh_, eager entry $mh, arg_copy $ah${helper:+, helper @L_$helper}"
    "$xaxc" edit "$store" "$batch" "$work/B3v$i.xax"
    store="$work/B3v$i.xax"
done
