#!/bin/sh
# rebuild.sh <production driver store> <work directory>
# BBC's driver from XAX's production driver, by native transactions only (README.md): the Windows host batch, the PE
# target record, BBC's layer (batch 3a with stubs), the four driver entry variants; then xaxc verify.  The result is
# <work>/bbc.xax.  cids.py only reads CIDs that listings do not show.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
compiler=$(cd "$here/../../../../.." && pwd)
xaxc=${XAXC:-$compiler/bootstrap/seed/xaxc-linux-x86_64}
cids() { PYTHONPATH="$compiler/src:$compiler/reference" python3 "$here/cids.py" "$@"; }
work=$2; mkdir -p "$work"; : > "$work/empty"
handle() { grep " $2" "$1" | cut -d' ' -f1; }
view() { echo "$2" > "$work/sel"; "$xaxc" edit "$1" "$work/sel" "$3"; }
# 1. the Windows host
cp "$1" "$work/D.xax"
"$xaxc" edit "$work/D.xax" "$work/empty" "$work/D.list"
main=$(cids "$work/D.xax" entry); mh=$(handle "$work/D.list" "$main")
view "$work/D.xax" "$mh" "$work/D.main"
awk -v MAP="$here/main_map.txt" -f "$here/port_main.awk" "$work/D.main" "$work/D.main" > "$work/winmain.view"
{ head -1 "$work/D.main"; echo "$mh"; cat "$here/windows_objects.batch" "$here/adapters.batch"
  echo "define @main"; cat "$work/winmain.view"; echo end; echo "replace $mh @main"; } > "$work/1_windows_host.batch"
"$xaxc" edit "$work/D.xax" "$work/1_windows_host.batch" "$work/W1.xax"
# 2. the PE target, with operations 77 and 78
sh "$here/replace_reference.sh" "$(cids "$work/W1.xax" root)" "$(cids "$work/W1.xax" module)" "$(cids "$work/W1.xax" target)" 6 \
    "$(cat "$here/pe_target_growable.hex")" > "$work/2_pe_target.edit"
"$xaxc" edit "$work/W1.xax" "$work/2_pe_target.edit" "$work/W2.xax"
# 3a. BBC's layer, with a stub for each driver entry variant
"$xaxc" edit "$work/W2.xax" "$work/empty" "$work/W2.list"
main=$(cids "$work/W2.xax" entry); mh=$(handle "$work/W2.list" "$main")
view "$work/W2.xax" "$mh" "$work/W2.main"
sig=$(sed -n 3p "$work/W2.main")
stub() {  # stub k: calls the eager entry; the constant k keeps the four apart
    echo "$sig"
    echo "B0($(seq 0 23 | awk '{printf "%sP%d:%s", (NR > 1 ? "," : ""), $1, ($1 == 0 ? "T0" : ($1 == 1 ? "T1" : "T2"))}'))"
    echo "N0 constant $1 -> T3"
    echo "N1 call.direct entity=$main$(seq 0 23 | awk '{printf " P%d", $1}') -> T0,T1$(printf ',T2%.0s' $(seq 1 22))"
    echo "ret N1$(seq 1 23 | awk '{printf " N1.R%d", $1}')"
    grep "^T[0-2] " "$work/W2.main"; echo "T3 bits64"
}
{ head -1 "$work/W2.main"; echo "$mh"; cat "$here/layer_objects.batch"
  k=0; while IFS= read -r line; do
      if [ "$line" = "@STUB" ]; then k=$((k + 1)); stub $k; else printf '%s\n' "$line" | sed "s/entity=@MAIN /entity=$main /"; fi
  done < "$here/layer_functions.batch"
  echo "replace $mh $(grep "^define" "$here/layer_functions.batch" | tail -1 | cut -d" " -f2)"; } > "$work/3a_bbc_layer.batch"  # BBC entry: the last definition
"$xaxc" edit "$work/W2.xax" "$work/3a_bbc_layer.batch" "$work/B3a.xax"
# 3b-3e. the variants
cids "$work/B3a.xax" stubs "$main" | sort -n > "$work/stubs.txt"
sh "$here/variants.sh" "$work/B3a.xax" "$work" "$main" "$here/layer_objects.batch" "$here/layer_functions.batch" "$work/stubs.txt"
cp "$work/B3v4.xax" "$work/bbc.xax"
"$xaxc" verify "$work/bbc.xax" "$work/bbc.verify"
echo "bbc.xax: $(cids "$work/bbc.xax" root)"
