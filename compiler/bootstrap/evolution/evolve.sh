#!/bin/sh
# N0.4 (ADR-367, ADR-372): the evolution ledger kept with the production compiler alone, no Python.
#
#   sh evolve.sh apply <record> <store> [<store> ...]   add one transaction to the ledger
#   sh evolve.sh replay [<store>]                          replay the ledger's transactions with xaxc edit
#   sh evolve.sh check                                     every store's chain ends at the committed store
#
# A record is an XAXEDIT1 edit record or a batch (text whose first word is R: the root, a function, then edits,
# `define` and `replace`, docs/09_AI_PROTOCOL.md section 16), the form native authoring writes. <store> is a path
# under bootstrap/ as the ledger names it. `apply` runs `xaxc edit <store> <record> <candidate>` and then
# `xaxc verify <candidate>` on every store, and only when all succeed copies the record into evolution/, replaces the
# stores and appends one line per store: <record> <store> <before blob> <after blob>.  A blob is the git object id of
# a store's bytes (git hash-object, or sha1sum of "blob <size>\0" and the bytes where git is absent), so earlier
# stores are read back from the repository. `replay` takes each transaction's earlier store from git (or the committed
# file while it still is that store, or the store's previous replayed result when git lacks it: transactions chained in
# one commit), applies the record with xaxc edit, and compares the result with the recorded
# blob. XAXC names the compiler (default: the pinned seed).
set -eu
here=$(cd "$(dirname "$0")" && pwd)
bootstrap=$(dirname "$here")
ledger="$here/LEDGER"
xaxc=${XAXC:-"$bootstrap/seed/xaxc-linux-x86_64"}

die() { echo "evolve.sh: $*" >&2; exit 1; }

blob() {  # the git object id of file $1
    if command -v git >/dev/null 2>&1; then
        git hash-object --no-filters -- "$1"
    else
        { printf 'blob %s\0' "$(wc -c < "$1" | tr -d ' ')"; cat -- "$1"; } | sha1sum | cut -d' ' -f1
    fi
}

head_of() {  # the ledger chain end of store $1
    awk -v s="$1" '$1 == "baseline" && $2 == s { h = $3 } $1 !~ /^#/ && $1 != "baseline" && NF == 4 && $2 == s {
        if ($3 != h) { print "BROKEN"; exit } h = $4 } END { print h }' "$ledger"
}

stores() { awk '$1 == "baseline" { print $2 }' "$ledger"; }

check() {
    status=0
    for store in $(stores); do
        want=$(head_of "$store")
        [ "$want" != BROKEN ] || { echo "$store: the chain is broken" >&2; status=1; continue; }
        have=$(blob "$bootstrap/$store")
        [ "$have" = "$want" ] || { echo "$store: committed $have, the chain ends at $want" >&2; status=1; }
    done
    return $status
}

apply() {
    record=$1; shift
    [ $# -gt 0 ] || die "usage: evolve.sh apply <record> <store> [<store> ...]"
    [ -f "$record" ] || die "$record: no such record"
    name=$(basename "$record")
    if [ -e "$here/$name" ] && ! cmp -s "$record" "$here/$name"; then die "$name already names another record"; fi
    work=$(mktemp -d "${TMPDIR:-/tmp}/xax-evolve.XXXXXX")
    trap 'rm -rf "$work"' EXIT
    n=0
    for store in "$@"; do
        path="$bootstrap/$store"
        [ -f "$path" ] || die "$store is not a store under bootstrap/"
        before=$(head_of "$store")
        [ -n "$before" ] && [ "$before" != BROKEN ] || die "$store is not a frozen store (no ledger chain)"
        [ "$(blob "$path")" = "$before" ] || die "$store is not its ledger chain's end"
        n=$((n + 1))
        if ! "$xaxc" edit "$path" "$record" "$work/$n.xax"; then
            die "xaxc edit $store: rejected (the diagnostic record is $work/$n.xax; xaxc edit <store> <it> <out> renders it)"
        fi
        "$xaxc" verify "$work/$n.xax" "$work/$n.verify" || die "xaxc verify of the edited $store: rejected"
        echo "$name $store $before $(blob "$work/$n.xax")" >> "$work/lines"
    done
    [ -e "$here/$name" ] || cp -- "$record" "$here/$name"
    n=0
    for store in "$@"; do
        n=$((n + 1))
        cp -- "$work/$n.xax" "$bootstrap/$store"
    done
    cat "$work/lines" >> "$ledger"
    cat "$work/lines"
}

replay() {
    only=${1:-}
    work=$(mktemp -d "${TMPDIR:-/tmp}/xax-replay.XXXXXX")
    trap 'rm -rf "$work"' EXIT
    status=0
    awk '$1 !~ /^#/ && $1 != "baseline" && NF == 4' "$ledger" > "$work/transactions"
    while read -r name store before after; do
        [ -z "$only" ] || [ "$store" = "$only" ] || continue
        made="$work/made-$(echo "$store" | tr / _)"  # this store's last replayed result
        if [ "$(blob "$bootstrap/$store")" = "$before" ]; then
            cp -- "$bootstrap/$store" "$work/before.xax"
        elif git -C "$bootstrap" cat-file blob "$before" > "$work/before.xax" 2>/dev/null; then
            :
        elif [ -f "$made" ] && [ "$(blob "$made")" = "$before" ]; then
            cp -- "$made" "$work/before.xax"  # a transaction chained in one commit: git holds only the chain's end
        else
            echo "skip $name $store: the repository does not hold $before"
            continue
        fi
        if "$xaxc" edit "$work/before.xax" "$here/$name" "$work/after.xax" && [ "$(blob "$work/after.xax")" = "$after" ]; then
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
    check) check && echo "every chain ends at its committed store" ;;
    *) die "usage: evolve.sh apply <record> <store>... | replay [<store>] | check" ;;
esac
