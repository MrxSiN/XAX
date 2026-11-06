#!/bin/sh
# variants.sh <store after 3a> <work directory> <W2 main CID> <layer objects batch> <BBC 0003 listing> <BBC views>
#             <layer function CIDs> <variant CIDs file> [<first step>]
# BBC's four driver entries, one native batch each: the store's own main view, rewritten by variant.awk (17 allocation
# sites reserved; for the three compile steps, arg_copy calls the step's argument helper and ExitProcess becomes
# SetLastError), replaces the stub BBC's entry calls in its place.  A step batch also carries the layer's objects
# (SetLastError among them) and its argument helper's definition, from its 0003 view with its callees remapped to
# that store's handles (remap.awk): only the variant reaches them, so 3a's store dropped them.  Prints each batch's path; the last store is <work>/B3v4.xax.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
store=$1; work=$2; main=$3; objects=$4; bbclist=$5; views=$6; layernew=$7; variants=$8; first=${9:-1}
xaxc=${XAXC:-$here/../../../../../bootstrap/seed/xaxc-linux-x86_64}
valloc=e8cf5a7cb5283490c972afd87b89985a4a1f8e616e6d47b2326aa6c3061e6a58
exitprocess=8718568ef087172920355a78db42489d2d7c3391463aebb73164f523cb03e5e4
argcopy=8e86608556a77e3dbb6e371fa96acf9e96bfe4afac5ec1baee7d77a373c6a353
reserve="1 2 3 4 6 7 8 9 12 13 14 15 18 19 20 21 22"
: > "$work/empty"
i=0
# stub CID prefix : variant name : step argument helper CID prefix (none for the lazy command-line entry)
for spec in 667d57c40c16:dae4d02b: 774f6276203e:3d257046:5e2a3f84 775285ded299:2d5b5ccd:8fcd655d ef4f9c6021fd:cb6e44b2:e726006e; do
    i=$((i + 1))
    [ "$i" -ge "$first" ] || continue
    stub=${spec%%:*}; rest=${spec#*:}; variant=${rest%%:*}; helper=${rest#*:}
    "$xaxc" edit "$store" "$work/empty" "$work/s$i.list"
    sh_=$(grep " $stub" "$work/s$i.list" | cut -d' ' -f1)
    mh=$(grep " $main" "$work/s$i.list" | cut -d' ' -f1)
    ah=$(grep " $argcopy" "$work/s$i.list" | cut -d' ' -f1)
    echo "$mh" > "$work/s$i.sel"
    "$xaxc" edit "$store" "$work/s$i.sel" "$work/s$i.main"
    root=$(head -1 "$work/s$i.main")
    batch="$work/3v$i.batch"
    if [ -n "$helper" ]; then
        hh=@L_$helper
        awk -v VALLOC=$valloc -v RESERVE="$reserve" -v ARGFROM="$ah" -v ARGTO="$hh" -v EXITFROM=$exitprocess -v EXITTO=@o_7c0d581e \
            -f "$here/variant.awk" "$work/s$i.main" "$work/s$i.main" > "$work/s$i.view"
        { echo "$root"; echo "$sh_"; cat "$objects"; hv=$(grep " $helper" "$views/handles.txt" | cut -d' ' -f1)
          echo "define @L_$helper"; awk -v BBC="$bbclist" -v W2="$work/s$i.list" -v NEW="$layernew" -v VARIANTS="$(cat "$variants")" \
              -v OLDMAIN=a15d38e4ff1188bccd893a109436e65ca6bb2a693ded67bc71a4b1f11481b092 -v MAIN="$main" -f "$here/remap.awk" "$views/$hv.txt"; echo end
          echo "define @V_$variant"; cat "$work/s$i.view"; echo end; echo "replace $sh_ @V_$variant"; } > "$batch"
    else
        awk -v VALLOC=$valloc -v RESERVE="$reserve" -f "$here/variant.awk" "$work/s$i.main" "$work/s$i.main" > "$work/s$i.view"
        { echo "$root"; echo "$sh_"; echo "define @V_$variant"; cat "$work/s$i.view"; echo end; echo "replace $sh_ @V_$variant"; } > "$batch"
    fi
    echo "$batch: stub $sh_, main $mh, arg_copy $ah${helper:+, helper $hh}"
    "$xaxc" edit "$store" "$batch" "$work/B3v$i.xax"
    store="$work/B3v$i.xax"
done
