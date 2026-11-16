#!/bin/sh
# sh oracle.sh run <store> <function CID> <argument>...: the native reference executor (README.md; ADR-405).
# The logic is the XAX program xax_oracle.xax; this script only builds it with the compiler and runs it.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
xaxc=${XAXC:-"$(dirname "$here")/seed/xaxc-linux-x86_64"}
work=$(mktemp -d "${TMPDIR:-/tmp}/xax-oracle.XXXXXX")
trap 'rm -rf "$work"' EXIT
"$xaxc" resolve "$here/xax_oracle.xax" "$work/oracle.xax"
"$xaxc" build "$work/oracle.xax" "$work/xax_oracle" "$work/provenance"
chmod 755 "$work/xax_oracle"
set +e
"$work/xax_oracle" "$@"
