#!/bin/sh
# sh oracle.sh run <store> <function CID> <argument>...: the native reference executor (README.md; ADR-405).
# The logic is the XAX program xax_oracle.xax; this script only builds it with the compiler and runs it.
# On Windows (Git for Windows' sh) the pinned Windows seed builds the hosted store xax_oracle_windows.xax.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
bootstrap=$(dirname "$here")
case $(uname -s) in
    MINGW*|MSYS*|CYGWIN*) seed=$bootstrap/windows/xaxc-windows-x86_64.exe; store=xax_oracle_windows.xax; exe=.exe ;;
    *) seed=$bootstrap/seed/xaxc-linux-x86_64; store=xax_oracle.xax; exe= ;;
esac
xaxc=${XAXC:-$seed}
work=$(mktemp -d "${TMPDIR:-/tmp}/xax-oracle.XXXXXX")
trap 'rm -rf "$work"' EXIT
"$xaxc" resolve "$here/$store" "$work/oracle.xax"
"$xaxc" build "$work/oracle.xax" "$work/xax_oracle$exe" "$work/provenance"
chmod 755 "$work/xax_oracle$exe"
set +e
"$work/xax_oracle$exe" "$@"
