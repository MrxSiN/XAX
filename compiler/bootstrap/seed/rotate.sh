#!/bin/sh
# Seed rotation by release (RFC docs/proposals/build-bootstrap-rotation-rfc.md sections 3, 8 and 9; rotate-tool/README.md).
#
#   sh rotate.sh state                       the release state, from bootstrap/RELEASES and the ledger
#   sh rotate.sh gate                        exit 0 when the computed profile's requirements hold: no unmet item,
#                                            evolve.sh check, then the tests POLICY selects (all for a candidate)
#   sh rotate.sh build <n> [<out>]           rebuild the compiler to its fixed point, cross-build every other host's
#                                            seed with it, install the seeds and append `candidate <n> ...`
#   sh rotate.sh build --dry [<out>]         the same build, compared with the pinned seeds; nothing is written
#   sh rotate.sh confirm <target> [<out>]    the candidate seed rebuilds itself twice on that host; write its evidence
#                                            and append `confirmed ...`
#   sh rotate.sh validate <record>           the V2 record's levels all hold: append `validated <n> evidence=...`
#
# The logic is the XAX programs rotate-tool/xax_rotate.xax and evidence/xax_evidence.xax; this script only runs xaxc,
# those programs and the repository's other scripts, and writes their results as lines. XAXC names the compiler that
# builds the tools (default: the pinned seed). Run it on Linux x86-64 (WSL works; the Windows seed runs through
# interop there).
set -u
here=$(cd "$(dirname "$0")" && pwd)
bootstrap=$(dirname "$here")
seed=$here/xaxc-linux-x86_64
store=$here/rotate-tool/xax_rotate.xax exe= hosted=
case $(uname -s) in  # on Windows (Git for Windows' sh) `state`, `pin`, `tests` and `validate`'s checks use the Windows seed
    MINGW*|MSYS*|CYGWIN*) seed=$bootstrap/windows/xaxc-windows-x86_64.exe; store=$here/rotate-tool/xax_rotate_windows.xax; exe=.exe hosted=_windows ;;
esac
xaxc=${XAXC:-$seed}
die() { echo "rotate.sh: $*" >&2; exit 1; }
work=$(mktemp -d "${TMPDIR:-/tmp}/xax-rotate.XXXXXX")
trap 'rm -rf "$work"' EXIT

tool() {  # tool <store> <name>: build an XAX tool program with xaxc
    "$xaxc" resolve "$1" "$work/$2.xax" && "$xaxc" build "$work/$2.xax" "$work/$2$exe" "$work/$2.provenance" || die "building $2 failed"
    chmod 755 "$work/$2$exe"
}
tool "$store" rotate
rot() {  # rot <command> <argument>...: the release tool writes its text to a file (its last argument); print it
    rm -f "$work/rotate.out"
    status=0; "$work/rotate$exe" "$@" "$work/rotate.out" || status=$?
    [ ! -f "$work/rotate.out" ] || cat "$work/rotate.out"
    return $status
}
r=rot
winpath() { if command -v wslpath >/dev/null 2>&1; then wslpath -w "$1"; else printf %s "$1"; fi; }
candidate() { "$r" state "$bootstrap" | sed -n 's/^candidate //p'; }

selfbuild() {  # selfbuild <compiler> <request> <out> <win>: generations to the first fixed point (at most 3); prints its path
    prev=$1 n=1
    while :; do
        if [ "$4" = win ]; then
            "$prev" resolve "$(winpath "$2")" "$(winpath "$3/S$n")" && "$prev" build "$(winpath "$3/S$n")" "$(winpath "$3/C$n")" "$(winpath "$3/P$n")"
        else
            "$prev" resolve "$2" "$3/S$n" && "$prev" build "$3/S$n" "$3/C$n" "$3/P$n"
        fi >&2 || return 1
        chmod 755 "$3/C$n"
        echo "generation $n $("$r" id "$prev") $("$r" id "$3/C$n")" >> "$3/generations"
        if cmp -s "$prev" "$3/C$n"; then echo "$prev"; return 0; fi
        [ $n -lt 3 ] || return 1
        prev=$3/C$n n=$((n + 1))
    done
}

case ${1:-} in
state)
    "$r" state "$bootstrap" ;;
gate)
    "$r" state "$bootstrap" || exit 1
    sh "$bootstrap/evolution/evolve.sh" check || die "gate: evolve.sh check failed"
    tests=$("$r" tests "$bootstrap")
    [ -n "$tests" ] || exit 0
    [ "$tests" != all ] || tests=tests
    # shellcheck disable=SC2086 # POLICY's test paths have no spaces
    (cd "$bootstrap/.." && ${PYTHON:-python3} -m pytest -q $tests) || die "gate: tests failed: $tests" ;;
build)
    name=${2:?usage: rotate.sh build <n>|--dry [<out>]}
    out=${3:-$work/build}
    mkdir -p "$out/linux" "$out/windows" || exit 3
    sh "$bootstrap/evolution/request-tool/request.sh" "$bootstrap/xax_compiler_driver_general.xax" \
        "$bootstrap/evolution/request-tool/x86_64-linux-elf-exec-v1.target" "$out/request.xax" || die "deriving the request failed"
    cmp -s "$out/request.xax" "$here/xax_compiler_request.xax" || die "the committed request is not the driver's derivation"
    fixed=$(selfbuild "$seed" "$out/request.xax" "$out/linux" linux) || die "no fixed point within three generations"
    sh "$bootstrap/windows/generator/generate.sh" "$out/request.xax" "$out/windows/request.xax" || die "generating the Windows request failed"
    "$fixed" resolve "$out/windows/request.xax" "$out/windows/snapshot.xax" \
        && "$fixed" build "$out/windows/snapshot.xax" "$out/windows/xaxc-windows-x86_64.exe" "$out/windows/provenance" || die "cross-building Windows failed"
    linux=$("$r" id "$fixed") windows=$("$r" id "$out/windows/xaxc-windows-x86_64.exe")
    echo "x86_64-linux-elf-exec-v1 $linux"
    echo "x86_64-windows-pe-v1 $windows"
    if [ "$name" = --dry ]; then
        [ "$linux" = "$("$r" pin "$bootstrap" x86_64-linux-elf-exec-v1)" ] || die "dry: the Linux seed differs from the pin"
        [ "$windows" = "$("$r" pin "$bootstrap" x86_64-windows-pe-v1)" ] || die "dry: the Windows seed differs from the pin"
        echo "dry: both rebuilt seeds equal the pins"
        exit 0
    fi
    ledger=$("$r" state "$bootstrap" | sed -n 's/^ledger //p')
    driver=$(sh "$bootstrap/evolution/evolve.sh" ledger blob "$bootstrap/xax_compiler_driver_general.xax")
    policy=$("$r" id "$bootstrap/POLICY")
    cp "$fixed" "$seed" && cp "$out/windows/xaxc-windows-x86_64.exe" "$bootstrap/windows/xaxc-windows-x86_64.exe" || exit 3
    echo "candidate $name ledger=$ledger driver=$driver policy=${policy%%:*} x86_64-linux-elf-exec-v1=$linux x86_64-windows-pe-v1=$windows" \
        >> "$bootstrap/RELEASES" ;;
confirm)
    target=${2:?usage: rotate.sh confirm <target> [<out>]}
    out=${3:-$work/confirm}
    n=$(candidate)
    [ -n "$n" ] && [ "$n" != none ] || die "no candidate to confirm"
    mkdir -p "$out" || exit 3
    case $target in
    x86_64-linux-elf-exec-v1) binary=$seed request=$here/xax_compiler_request.xax mode=linux ;;
    x86_64-windows-pe-v1)
        # a copy: interop needs the execute bit, which a Linux checkout does not give the .exe
        cp "$bootstrap/windows/xaxc-windows-x86_64.exe" "$out/seed.exe" && chmod 755 "$out/seed.exe" || exit 3
        binary=$out/seed.exe mode=win request=$out/request.xax
        sh "$bootstrap/windows/generator/generate.sh" "$here/xax_compiler_request.xax" "$request" || die "generating the Windows request failed"
        "$binary" verify "$(winpath "$bootstrap/evolution/ledger-tool/seed.xax")" "$(winpath "$out/probe")" \
            || { echo "confirm $n $target NOT RUN: the Windows seed does not run here" >&2; exit 1; } ;;
    *) die "unknown target $target" ;;
    esac
    fixed=$(selfbuild "$binary" "$request" "$out" "$mode") || die "confirm: the candidate seed did not rebuild itself"
    [ "$fixed" = "$binary" ] || die "confirm: the candidate seed is not its own fixed point"
    # the rebuild's output rebuilds it once more
    if [ "$mode" = win ]; then
        "$out/C1" resolve "$(winpath "$request")" "$(winpath "$out/S2")" && "$out/C1" build "$(winpath "$out/S2")" "$(winpath "$out/C2")" "$(winpath "$out/P2")"
    else
        "$out/C1" resolve "$request" "$out/S2" && "$out/C1" build "$out/S2" "$out/C2" "$out/P2"
    fi || die "confirm: the second rebuild failed"
    cmp -s "$binary" "$out/C2" || die "confirm: the second rebuild differs"
    mkdir -p "$bootstrap/evidence/confirm" || exit 3
    evidence=$bootstrap/evidence/confirm/$n-$target.txt
    {
        echo "xax-confirm-v1"
        echo "release $n"
        echo "target $target"
        echo "seed $("$r" id "$binary")"
        echo "request $("$r" id "$request")"
        cat "$out/generations"
        echo "generation 2 $("$r" id "$out/C1") $("$r" id "$out/C2")"
        if [ "$mode" = win ] && command -v wslpath >/dev/null 2>&1; then
            echo "host $(uname -srm); the seed ran as a Windows process through WSL interop"
        else
            echo "host $(uname -srm)"
        fi
        echo "label EXECUTED"
    } > "$evidence"
    sha=$("$r" id "$binary") record=$("$r" id "$evidence")
    echo "confirmed $n $target ${sha%%:*} ${record%%:*}" >> "$bootstrap/RELEASES" ;;
validate)
    record=${2:?usage: rotate.sh validate <record>}
    "$r" state "$bootstrap" | grep -qx "profile candidate" || die "validate: no fully confirmed candidate"
    tool "$bootstrap/evidence/xax_evidence$hosted.xax" evidence
    "$work/evidence$exe" levels "$record" "$bootstrap/evidence/CORPUS" "$bootstrap/evidence/SNAPSHOTS" "$here/xaxc-linux-x86_64" "$work/levels" || exit 3
    "$r" valid "$work/levels" || { cat "$work/levels" >&2; die "validate: not every level holds"; }
    sha=$("$r" id "$record")
    echo "validated $(candidate) evidence=${sha%%:*}" >> "$bootstrap/RELEASES" ;;
*)
    sed -n '2,13s/^# \{0,1\}//p' "$0" >&2; exit 3 ;;
esac
