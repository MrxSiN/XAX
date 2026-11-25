#!/bin/sh
# The generated status blocks (AGENTS.md, "Documents and status"); the logic is xax_status.xax (README.md).
#
#   sh status.sh check [<repo>]   print `stale: <path>` for each Markdown file whose blocks differ; exit 1 if any
#   sh status.sh write [<repo>]   rewrite those files and print `updated: <path>`
#
# <repo> (default: this checkout) supplies XAX_REPLACEMENT_MATRIX.json and the Markdown files; the bootstrap levels
# always come from this checkout's latest validated release. On Linux x86-64 the pinned Linux seed builds the tools.
# On Windows (Git for Windows' sh) the pinned Windows seed builds xax_status_windows.xax; the bootstrap line needs the
# Linux-only evidence and release tools, so there a document with a bootstrap block is refused.
# This script only builds the XAX tools, lists the files and compares bytes.
set -u
here=$(cd "$(dirname "$0")" && pwd)
bootstrap=$(dirname "$here")
mode=${1:-check}
repo=${2:-$(dirname "$(dirname "$bootstrap")")}
case $(uname -s) in
    MINGW*|MSYS*|CYGWIN*) windows=1; seed=$bootstrap/windows/xaxc-windows-x86_64.exe; store=$here/xax_status_windows.xax; exe=.exe ;;
    *) windows=0; seed=$bootstrap/seed/xaxc-linux-x86_64; store=$here/xax_status.xax; exe= ;;
esac
xaxc=${XAXC:-$seed}
die() { echo "status.sh: $*" >&2; exit 3; }
case $mode in check|write) ;; *) die "usage: status.sh check|write [<repo>]" ;; esac
work=$(mktemp -d "${TMPDIR:-/tmp}/xax-status.XXXXXX")
trap 'rm -rf "$work"' EXIT

tool() {  # tool <store> <name>
    "$xaxc" resolve "$1" "$work/$2.xax" && "$xaxc" build "$work/$2.xax" "$work/$2$exe" "$work/$2.provenance" || die "building $2 failed"
    chmod 755 "$work/$2$exe"
}
tool "$store" status
s=$work/status$exe

"$s" l "$repo/XAX_REPLACEMENT_MATRIX.json" "$work/levels" || die "reading the matrix failed"
"$s" t "$repo/XAX_REPLACEMENT_MATRIX.json" "$work/targets" || die "reading the matrix failed"
if [ $windows = 0 ]; then
    tool "$bootstrap/evidence/xax_evidence.xax" evidence
    tool "$bootstrap/seed/rotate-tool/xax_rotate.xax" rotate
    release=$("$work/rotate" state "$bootstrap" | sed -n 's/^validated //p')
    [ -n "$release" ] || die "no validated release"
    record=$bootstrap/evidence/records/$release.record
    "$work/evidence" levels "$record" "$bootstrap/evidence/CORPUS" "$bootstrap/evidence/SNAPSHOTS" "$seed" > "$work/b-levels" \
        || die "xax_evidence levels failed"
    "$s" b "$release" "$work/b-levels" "$record" "$seed" "$work/bootstrap" || die "deriving the bootstrap block failed"
else
    : > "$work/bootstrap"
fi

stale=0
find "$repo" -name '*.md' -not -path '*/.git/*' | LC_ALL=C sort > "$work/documents"
while IFS= read -r file; do
    grep -q '<!-- /xax-status:' "$file" || continue
    [ $windows = 0 ] || ! grep -q '<!-- xax-status:bootstrap -->' "$file" || die "$file has a bootstrap block: run on Linux x86-64"
    "$s" s "$file" "$work/levels" "$work/targets" "$work/bootstrap" "$work/new" || die "rewriting $file failed"
    cmp -s "$work/new" "$file" && continue
    if [ "$mode" = write ]; then
        cp "$work/new" "$file" || die "writing $file failed"
        echo "updated: ${file#"$repo"/}"
    else
        echo "stale: ${file#"$repo"/}"
        stale=1
    fi
done < "$work/documents"
exit $stale
