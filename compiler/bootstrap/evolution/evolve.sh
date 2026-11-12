#!/bin/sh
# N0.4 (ADR-367, ADR-372): the evolution ledger kept with the production compiler alone, no Python.
#
#   sh evolve.sh apply <record> <store> [<store> ...]   add one transaction to the ledger
#   sh evolve.sh replay [<store>]                          replay the ledger's transactions with xaxc edit
#   sh evolve.sh check [<bootstrap>]                       every store's chain ends at the committed store
#   sh evolve.sh ledger <command> <argument>...            run the ledger program (ledger/README.md) itself
#
# A record is an XAXEDIT1 edit record or a batch (text whose first word is R: the root, a function, then edits,
# `define` and `replace`, docs/09_AI_PROTOCOL.md section 16), the form native authoring writes. <store> is a path
# under bootstrap/ as the ledger names it. `apply` runs `xaxc edit <store> <record> <candidate>` and then
# `xaxc verify <candidate>` on every store, and only when all succeed copies the record into evolution/, replaces the
# stores and appends one line per store: <record> <store> <before blob> <after blob>.  A blob is the git object id of
# a store's bytes, so earlier stores are read back from the repository. `replay` takes each transaction's earlier
# store from the committed file while it still is that store, else from git, else from the store's previous replayed
# result (transactions chained in one commit), applies the record with xaxc edit, and compares the result with the
# recorded blob. XAXC names the compiler (default: the pinned seed).
#
# The ledger's logic (blob ids, chain ends, the transaction list, the check) is the XAX program ledger/xax_ledger.xax
# (ledger/README.md), built here with the compiler; this script only runs xaxc, git and that program.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
bootstrap=$(dirname "$here")
xaxc=${XAXC:-"$bootstrap/seed/xaxc-linux-x86_64"}

die() { echo "evolve.sh: $*" >&2; exit 1; }

work=$(mktemp -d "${TMPDIR:-/tmp}/xax-evolve.XXXXXX")
trap 'rm -rf "$work"' EXIT
"$xaxc" resolve "$here/ledger/xax_ledger.xax" "$work/ledger.xax" || die "xaxc resolve of the ledger program failed"
"$xaxc" build "$work/ledger.xax" "$work/xax_ledger" "$work/ledger.provenance" || die "xaxc build of the ledger program failed"
chmod 755 "$work/xax_ledger"
tool="$work/xax_ledger"

apply() {
    record=$1; shift
    [ $# -gt 0 ] || die "usage: evolve.sh apply <record> <store> [<store> ...]"
    [ -f "$record" ] || die "$record: no such record"
    name=$(basename "$record")
    if [ -e "$here/$name" ] && ! cmp -s "$record" "$here/$name"; then die "$name already names another record"; fi
    n=0
    for store in "$@"; do
        path="$bootstrap/$store"
        [ -f "$path" ] || die "$store is not a store under bootstrap/"
        before=$("$tool" head "$bootstrap" "$store") || die "$store is not a frozen store (no ledger chain, or a broken one)"
        [ "$("$tool" blob "$path")" = "$before" ] || die "$store is not its ledger chain's end"
        n=$((n + 1))
        if ! "$xaxc" edit "$path" "$record" "$work/$n.xax"; then
            die "xaxc edit $store: rejected (the diagnostic record is $work/$n.xax; xaxc edit <store> <it> <out> renders it)"
        fi
        "$xaxc" verify "$work/$n.xax" "$work/$n.verify" || die "xaxc verify of the edited $store: rejected"
        echo "$name $store $before $("$tool" blob "$work/$n.xax")" >> "$work/lines"
    done
    [ -e "$here/$name" ] || cp -- "$record" "$here/$name"
    n=0
    for store in "$@"; do
        n=$((n + 1))
        cp -- "$work/$n.xax" "$bootstrap/$store"
    done
    cat "$work/lines" >> "$here/LEDGER"
    cat "$work/lines"
}

replay() {
    only=${1:-}
    status=0
    "$tool" transactions "$bootstrap" > "$work/transactions"
    while read -r name store before after; do
        [ -z "$only" ] || [ "$store" = "$only" ] || continue
        made="$work/made-$(echo "$store" | tr / _)"  # this store's last replayed result
        if [ "$("$tool" blob "$bootstrap/$store")" = "$before" ]; then
            cp -- "$bootstrap/$store" "$work/before.xax"
        elif git -C "$bootstrap" cat-file blob "$before" > "$work/before.xax" 2>/dev/null; then
            :
        elif [ -f "$made" ] && [ "$("$tool" blob "$made")" = "$before" ]; then
            cp -- "$made" "$work/before.xax"  # a transaction chained in one commit: git holds only the chain's end
        else
            echo "skip $name $store: the repository does not hold $before"
            continue
        fi
        if "$xaxc" edit "$work/before.xax" "$here/$name" "$work/after.xax" && [ "$("$tool" blob "$work/after.xax")" = "$after" ]; then
            cp -- "$work/after.xax" "$made"
            echo "ok   $name $store"
        else
            echo "FAIL $name $store" >&2
            status=1
        fi
    done < "$work/transactions"
    return $status
}

command=${1:-}
[ $# -eq 0 ] || shift
case "$command" in
    apply) apply "$@" ;;
    replay) replay "$@" ;;
    ledger) "$tool" "$@" ;;
    check) "$tool" check "${1:-$bootstrap}" && echo "every chain ends at its committed store" ;;
    *) die "usage: evolve.sh apply <record> <store>... | replay [<store>] | check [<bootstrap>] | ledger <command> <argument>..." ;;
esac
