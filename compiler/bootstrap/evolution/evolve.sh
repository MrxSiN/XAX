#!/bin/sh
# N0.4 (ADR-367, ADR-372): the evolution ledger kept with the production compiler alone, no Python.
#
#   sh evolve.sh apply <record> <store> [<store> ...]   add one transaction to the ledger
#   sh evolve.sh replay [<store>]                          replay the ledger's transactions with xaxc edit
#   sh evolve.sh check [<bootstrap>]                       every store's chain ends at the committed store
#   sh evolve.sh ledger <command> <argument>...            run the ledger program (ledger-tool/README.md) itself
#
# A record is an XAXEDIT1 edit record or a batch (text whose first word is R: the root, a function, then edits,
# `define` and `replace`, docs/09_AI_PROTOCOL.md section 16), the form native authoring writes. <store> is a path
# under bootstrap/ as the ledger names it. `apply` runs `xaxc edit <store> <record> <candidate>` and then
# `xaxc verify <candidate>` on every store, and only when all succeed copies the record into evolution/, replaces the
# stores and appends one line per store: <record> <store> <before blob> <after blob>.  A blob is the git object id of
# a store's bytes, so earlier stores are read back from the repository. `replay` takes each transaction's earlier
# store from the committed file while it still is that store, else from git, else from the store's previous replayed
# result (transactions chained in one commit), applies the record with xaxc edit, and compares the result with the
# recorded blob. The replay is strict: a shallow clone, or a transaction whose earlier store it cannot find or whose
# result differs, fails it; it ends with `replayed <n> of <total> LEDGER=<blob> xaxc=<blob>` (git object ids) for the
# evidence and tests to read. XAXC names the compiler (default: the pinned seed).
#
# A derived store (a `derived <store> <final blob> <tool root>` line, RFC step 6) is no longer changed by transactions:
# seed/xax_compiler_request.xax is request-tool/request.sh of the driver, so `apply` rewrites it after a driver
# transaction and `check` requires the committed request to be that derivation. Its historical transactions replay.
#
# The ledger's logic (blob ids, chain ends, the transaction list, the check) is the XAX program ledger-tool/xax_ledger.xax
# (ledger-tool/README.md), built here with the compiler; this script only runs xaxc, git and that program. On Windows
# (Git for Windows' sh) the pinned Windows seed builds ledger-tool/xax_ledger_windows.xax instead.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
bootstrap=$(dirname "$here")
case $(uname -s) in
    MINGW*|MSYS*|CYGWIN*) windows=1; seed=$bootstrap/windows/xaxc-windows-x86_64.exe; program=$here/ledger-tool/xax_ledger_windows.xax; exe=.exe ;;
    *) windows=0; seed=$bootstrap/seed/xaxc-linux-x86_64; program=$here/ledger-tool/xax_ledger.xax; exe= ;;
esac
xaxc=${XAXC:-$seed}

die() { echo "evolve.sh: $*" >&2; exit 1; }

work=$(mktemp -d "${TMPDIR:-/tmp}/xax-evolve.XXXXXX")
trap 'rm -rf "$work"' EXIT
"$xaxc" resolve "$program" "$work/ledger.xax" || die "xaxc resolve of the ledger program failed"
"$xaxc" build "$work/ledger.xax" "$work/xax_ledger$exe" "$work/ledger.provenance" || die "xaxc build of the ledger program failed"
chmod 755 "$work/xax_ledger$exe"
tool="$work/xax_ledger$exe"

ledger() {  # ledger <command> <argument>...: the program writes its text to a file (the last argument); print it,
            # to standard error for `check` (the stores it reports), and keep the program's exit status
    rm -f "$work/ledger.out"
    status=0; "$tool" "$@" "$work/ledger.out" || status=$?
    if [ -f "$work/ledger.out" ]; then
        if [ "$1" = check ]; then cat "$work/ledger.out" >&2; else cat "$work/ledger.out"; fi
    fi
    return $status
}

apply() {
    record=$1; shift
    [ $# -gt 0 ] || die "usage: evolve.sh apply <record> <store> [<store> ...]"
    [ -f "$record" ] || die "$record: no such record"
    for store in "$@"; do  # the request derivation (request-tool) runs on Linux x86-64 only
        [ $windows = 0 ] || [ "$store" != xax_compiler_driver_general.xax ] || die "a driver transaction derives the request: run it on Linux x86-64"
    done
    name=$(basename "$record")
    if [ -e "$here/$name" ] && ! cmp -s "$record" "$here/$name"; then die "$name already names another record"; fi
    n=0
    for store in "$@"; do
        path="$bootstrap/$store"
        [ -f "$path" ] || die "$store is not a store under bootstrap/"
        before=$(ledger head "$bootstrap" "$store") || die "$store is not a frozen store (no ledger chain, a broken one, or derived)"
        [ "$(ledger blob "$path")" = "$before" ] || die "$store is not its ledger chain's end"
        n=$((n + 1))
        if ! "$xaxc" edit "$path" "$record" "$work/$n.xax"; then
            die "xaxc edit $store: rejected (the diagnostic record is $work/$n.xax; xaxc edit <store> <it> <out> renders it)"
        fi
        "$xaxc" verify "$work/$n.xax" "$work/$n.verify" || die "xaxc verify of the edited $store: rejected"
        echo "$name $store $before $(ledger blob "$work/$n.xax")" >> "$work/lines"
    done
    [ -e "$here/$name" ] || cp -- "$record" "$here/$name"
    n=0
    for store in "$@"; do
        n=$((n + 1))
        cp -- "$work/$n.xax" "$bootstrap/$store"
    done
    cat "$work/lines" >> "$here/LEDGER"
    cat "$work/lines"
    for store in "$@"; do
        [ "$store" != xax_compiler_driver_general.xax ] || [ ! -f "$bootstrap/seed/xax_compiler_request.xax" ] || derive "$bootstrap" "$bootstrap/seed/xax_compiler_request.xax"
    done
}

derive() {  # derive <bootstrap> <out>: the build request of that bootstrap's driver (RFC step 6)
    sh "$here/request-tool/request.sh" "$1/xax_compiler_driver_general.xax" "$here/request-tool/x86_64-linux-elf-exec-v1.target" "$2"
}

replay() {
    only=${1:-}
    status=0 total=0 replayed=0
    # Strict (docs/proposals/build-bootstrap-rotation-rfc.md section 5): every transaction is replayed or the replay fails.
    [ "$(git -C "$bootstrap" rev-parse --is-shallow-repository)" = false ] || die "shallow clone: replay needs the full history"
    ledger transactions "$bootstrap" > "$work/transactions"
    while read -r name store before after; do
        [ -z "$only" ] || [ "$store" = "$only" ] || continue
        total=$((total + 1))
        made="$work/made-$(echo "$store" | tr / _)"  # this store's last replayed result
        if [ "$(ledger blob "$bootstrap/$store")" = "$before" ]; then
            cp -- "$bootstrap/$store" "$work/before.xax"
        elif git -C "$bootstrap" cat-file blob "$before" > "$work/before.xax" 2>/dev/null; then
            :
        elif [ -f "$made" ] && [ "$(ledger blob "$made")" = "$before" ]; then
            cp -- "$made" "$work/before.xax"  # a transaction chained in one commit: git holds only the chain's end
        else
            echo "FAIL $name $store: the repository does not hold $before" >&2
            status=1
            continue
        fi
        if "$xaxc" edit "$work/before.xax" "$here/$name" "$work/after.xax" && [ "$(ledger blob "$work/after.xax")" = "$after" ]; then
            cp -- "$work/after.xax" "$made"
            replayed=$((replayed + 1))
            echo "ok   $name $store"
        else
            echo "FAIL $name $store" >&2
            status=1
        fi
    done < "$work/transactions"
    [ "$total" -gt 0 ] || { echo "FAIL no transaction${only:+ for $only}" >&2; status=1; }
    echo "replayed $replayed of $total LEDGER=$(ledger blob "$here/LEDGER") xaxc=$(ledger blob "$xaxc")"
    return $status
}

command=${1:-}
[ $# -eq 0 ] || shift
case "$command" in
    apply) apply "$@" ;;
    replay) replay "$@" ;;
    ledger) ledger "$@" ;;
    check)
        root=${1:-$bootstrap}
        ledger check "$root"
        if [ $windows = 1 ]; then
            echo "every chain ends at its committed store; the request derivation was not checked (request-tool runs on Linux x86-64)"
        else
            if [ -f "$root/seed/xax_compiler_request.xax" ]; then
                derive "$root" "$work/request.xax"
                cmp -s "$work/request.xax" "$root/seed/xax_compiler_request.xax" || die "seed/xax_compiler_request.xax is not the request of the committed driver (request-tool/request.sh)"
            fi
            echo "every chain ends at its committed store; the request is derived from the driver"
        fi ;;
    *) die "usage: evolve.sh apply <record> <store>... | replay [<store>] | check [<bootstrap>] | ledger <command> <argument>..." ;;
esac
