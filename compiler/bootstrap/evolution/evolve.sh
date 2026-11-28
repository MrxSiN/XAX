#!/bin/sh
# N0.4 (ADR-367, ADR-372): the evolution ledger kept with the production compiler alone, no Python.
#
#   sh evolve.sh apply <record> <store> [<store> ...]   add one transaction to the ledger
#   sh evolve.sh replay [--from <blob>] [--jobs <n>] [<store>]   replay the ledger's transactions with xaxc edit
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
# ADR-433 (2): `--from <blob>` replays only the transactions after an earlier LEDGER (the git blob a validated
# release's record names; `xax_ledger after`, so it must be a byte prefix of the committed LEDGER ending at a line
# end). The prefix's transactions count as replayed, since that record proves them: the last line is the one a full
# replay prints, after a line `checkpoint <blob> <k> earlier transactions not replayed`. `--jobs <n>` (default 1)
# replays on n workers: a transaction whose earlier store only an earlier replayed result holds stays on its
# predecessor's worker; results print in ledger order once all are done (with one worker, as each is done).
#
# One driver blob per pull request: each driver store committed to git is about 64 MB of history, so a pull request
# commits the driver (and its derived request) once, after all of its transactions are applied. Several transactions
# on the driver in one pull request are applied one after the other and committed together; git then holds only the
# chain's end, and `replay` takes the intermediate stores from its own earlier results.
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
    MINGW*|MSYS*|CYGWIN*) seed=$bootstrap/windows/xaxc-windows-x86_64.exe; program=$here/ledger-tool/xax_ledger_windows.xax; exe=.exe ;;
    *) seed=$bootstrap/seed/xaxc-linux-x86_64; program=$here/ledger-tool/xax_ledger.xax; exe= ;;
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
    out=${ledger_out:-$work/ledger.out}  # a replay worker has its own
    rm -f "$out"
    status=0; "$tool" "$@" "$out" || status=$?
    if [ -f "$out" ]; then
        if [ "$1" = check ]; then cat "$out" >&2; else cat "$out"; fi
    fi
    return $status
}

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

replay_worker() {  # replay_worker <list> <dir>: replay the list's lines (<index> <source> <name> <store> <before>
                   # <after>) in order; one result line per transaction (<index> ok|FAIL ...) on standard output
    mkdir -p "$2"
    ledger_out=$2/ledger.out
    while read -r index source name store before after; do
        made="$2/made-$(echo "$store" | tr / _)"  # this store's last replayed result on this worker
        case $source in
            committed) cp -- "$bootstrap/$store" "$2/before.xax" ;;
            git) git -C "$bootstrap" cat-file blob "$before" > "$2/before.xax" ;;
            *) if [ -f "$made" ] && [ "$(ledger blob "$made")" = "$before" ]; then
                   cp -- "$made" "$2/before.xax"  # a transaction chained in one commit: git holds only the chain's end
               else
                   echo "$index FAIL $name $store: the repository does not hold $before"; continue
               fi ;;
        esac
        if "$xaxc" edit "$2/before.xax" "$here/$name" "$2/after.xax" >&2 && [ "$(ledger blob "$2/after.xax")" = "$after" ]; then
            cp -- "$2/after.xax" "$made"
            echo "$index ok   $name $store"
        else
            echo "$index FAIL $name $store"
        fi
    done < "$1"
}

replay() {
    from= jobs=1 only=
    while [ $# -gt 0 ]; do
        case $1 in
            --from) [ $# -ge 2 ] || die "--from needs a LEDGER blob"; from=$2; shift 2 ;;
            --jobs) [ $# -ge 2 ] && [ "$2" -ge 1 ] 2>/dev/null || die "--jobs needs a worker count of 1 or more"; jobs=$2; shift 2 ;;
            *) only=$1; shift ;;
        esac
    done
    # Strict (docs/proposals/build-bootstrap-rotation-rfc.md section 5): every transaction is replayed or the replay fails.
    [ "$(git -C "$bootstrap" rev-parse --is-shallow-repository)" = false ] || die "shallow clone: replay needs the full history"
    ledger transactions "$bootstrap" | awk -v s="$only" 's == "" || $2 == s' > "$work/all"
    if [ -n "$from" ]; then
        git -C "$bootstrap" cat-file blob "$from" > "$work/prefix" 2>/dev/null || die "the repository does not hold LEDGER $from"
        ledger after "$bootstrap" "$work/prefix" > "$work/after" || die "$from is not an earlier LEDGER (a byte prefix of the committed one, ending at a line end)"
        awk -v s="$only" 's == "" || $2 == s' "$work/after" > "$work/transactions"
    else
        cp -- "$work/all" "$work/transactions"
    fi
    total=$(wc -l < "$work/all") proven=$(($(wc -l < "$work/all") - $(wc -l < "$work/transactions")))
    # Each transaction's source and worker: a chained one (its earlier store neither committed nor in git) goes to the
    # worker of the store's previous transaction, any other to the next worker in turn.
    index=0 next=0
    while read -r name store before after; do
        index=$((index + 1))
        key=$(echo "$store" | tr / _)
        [ -f "$work/blob-$key" ] || ledger blob "$bootstrap/$store" > "$work/blob-$key"
        if [ "$(cat "$work/blob-$key")" = "$before" ]; then source=committed
        elif git -C "$bootstrap" cat-file -e "$before" 2>/dev/null; then source=git
        else source=chained
        fi
        if [ $source = chained ] && [ -f "$work/worker-$key" ]; then worker=$(cat "$work/worker-$key")
        else worker=$next; next=$(((next + 1) % jobs))
        fi
        echo "$worker" > "$work/worker-$key"
        echo "$index $source $name $store $before $after" >> "$work/list-$worker"
    done < "$work/transactions"
    : > "$work/results"
    if [ "$jobs" -eq 1 ]; then
        [ ! -f "$work/list-0" ] || replay_worker "$work/list-0" "$work/w0" | tee "$work/results" | cut -d' ' -f2-
    else
        k=0
        while [ $k -lt "$jobs" ]; do
            [ ! -f "$work/list-$k" ] || replay_worker "$work/list-$k" "$work/w$k" > "$work/results-$k" &
            k=$((k + 1))
        done
        wait
        cat "$work"/results-* 2>/dev/null | sort -n > "$work/results"
        cut -d' ' -f2- "$work/results"
    fi
    replayed=$((proven + $(grep -c '^[0-9]* ok ' "$work/results" || true)))
    status=0
    if grep -q '^[0-9]* FAIL ' "$work/results"; then status=1; fi
    [ "$total" -gt 0 ] || { echo "FAIL no transaction${only:+ for $only}" >&2; status=1; }
    [ -z "$from" ] || echo "checkpoint $from $proven earlier transactions not replayed"
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
        if [ -f "$root/seed/xax_compiler_request.xax" ]; then
            derive "$root" "$work/request.xax"
            cmp -s "$work/request.xax" "$root/seed/xax_compiler_request.xax" || die "seed/xax_compiler_request.xax is not the request of the committed driver (request-tool/request.sh)"
        fi
        echo "every chain ends at its committed store; the request is derived from the driver" ;;
    *) die "usage: evolve.sh apply <record> <store>... | replay [<store>] | check [<bootstrap>] | ledger <command> <argument>..." ;;
esac
