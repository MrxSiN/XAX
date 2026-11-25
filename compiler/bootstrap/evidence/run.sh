#!/bin/sh
# sh run.sh <out> [quick]: the full self-hosting evidence, V2 (README.md; RFC docs/proposals/build-bootstrap-rotation-rfc.md
# section 4). It writes <out>/record and keeps every output it hashed under <out>. `quick` skips the ledger replay
# (its line then reads `replay not-run`). The logic is the XAX program xax_evidence.xax; this script only runs xaxc,
# that program and the ledger script, and writes their results as lines. XAXC names the seed (default: the pinned one).
set -u
[ $# -ge 1 ] || { echo "usage: run.sh <out> [quick]" >&2; exit 3; }
here=$(cd "$(dirname "$0")" && pwd)
bootstrap=$(dirname "$here")
seed=${XAXC:-"$bootstrap/seed/xaxc-linux-x86_64"}
mkdir -p "$1" || exit 3
out=$(cd "$1" && pwd)
rec=$out/record
"$seed" resolve "$here/xax_evidence.xax" "$out/tool.xax" && "$seed" build "$out/tool.xax" "$out/xax_evidence" "$out/tool.provenance" || {
    echo "run.sh: building xax_evidence failed" >&2; exit 3; }
chmod 755 "$out/xax_evidence"
ev() {  # ev <command> <argument>...: the evidence program writes its text to a file, its last argument; print it
    "$out/xax_evidence" "$@" "$out/ev.out"; status=$?
    [ ! -f "$out/ev.out" ] || cat "$out/ev.out"; rm -f "$out/ev.out"
    return $status
}
t=ev
request=$bootstrap/seed/xax_compiler_request.xax
tiny=$bootstrap/evolution/ledger-tool/seed.xax
cd "$bootstrap" || exit 3

cases() {  # cases <tag> <context> <compiler> <plan>: one line per case
    while read -r i args; do
        # shellcheck disable=SC2086 # the plan's paths have no spaces
        "$3" $args >/dev/null 2>&1
        s=$?
        [ $s -ne 1 ] || "$seed" edit "$tiny" "$out/$2/$i.0" "$out/$2/$i.d" >/dev/null 2>&1
        echo "$1 $2 $i $s $("$t" sha "$out/$2/$i.0") $("$t" sha "$out/$2/$i.1") $("$t" diag "$out/$2/$i.d")" >> "$rec"
    done < "$4"
}

{
    echo "xax-full-selfhost-evidence-v2"
    echo "ledger $(sh evolution/evolve.sh ledger blob evolution/LEDGER)"
    echo "corpus $("$t" sha "$here/CORPUS")"
    echo "seed $("$t" sha "$seed") $("$t" elf "$seed")"
    echo "request $("$t" sha "$request")"
} > "$rec"

prev=$seed n=1 fixed=none contexts="C0:$seed"
while :; do
    "$prev" resolve "$request" "$out/S$n" >/dev/null 2>&1; rs=$?
    "$prev" build "$out/S$n" "$out/C$n" "$out/P$n" >/dev/null 2>&1; bs=$?
    interp=-; [ $bs -ne 0 ] || interp=$("$t" elf "$out/C$n")
    echo "generation $n $("$t" sha "$prev") $rs $("$t" sha "$out/S$n") $bs $("$t" sha "$out/C$n") $("$t" sha "$out/P$n") $interp" >> "$rec"
    [ $bs -eq 0 ] || break
    if cmp -s "$prev" "$out/C$n"; then fixed=$n; break; fi
    chmod 755 "$out/C$n"
    contexts="$contexts C$n:$out/C$n"
    [ $n -lt 3 ] || break
    prev=$out/C$n n=$((n + 1))
done
echo "fixedpoint $fixed" >> "$rec"

for k in 1 2; do  # the seed with an empty environment: nothing, Python included, can be found on a PATH
    env -i "$seed" resolve "$request" "$out/E$k.snapshot" >/dev/null 2>&1; rs=$?
    env -i "$seed" build "$out/E$k.snapshot" "$out/E$k" "$out/E$k.provenance" >/dev/null 2>&1; bs=$?
    echo "empty $k $rs $bs $("$t" sha "$out/E$k")" >> "$rec"
done

for context in $contexts; do
    name=${context%%:*} compiler=${context#*:}
    mkdir -p "$out/$name" "$out/$name-r"
    echo "context $name $("$t" sha "$compiler")" >> "$rec"
    "$t" plan "$here/CORPUS" "$out/$name" > "$out/$name/plan" || exit 3
    cases outcome "$name" "$compiler" "$out/$name/plan"
    "$t" plan "$here/CORPUS" "$out/$name-r" | head -n 10 > "$out/$name-r/plan"  # the flakiness probe: ten cases again
    cases repeat "$name-r" "$compiler" "$out/$name-r/plan"
done

if [ "${2:-}" = quick ] || [ ! -f "$out/C1" ]; then
    echo "replay not-run" >> "$rec"
else
    chmod 755 "$out/C1"
    XAXC=$out/C1 sh evolution/evolve.sh replay > "$out/replay.log" 2>&1
    echo "replay $? $(tail -n 1 "$out/replay.log")" >> "$rec"
fi
echo "end" >> "$rec"
