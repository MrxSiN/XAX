#!/bin/sh
# S15a (ADR-286): the Linux x86-64 production compiler rebuilds itself from the pinned seed, with no Python.
#
#   sh selfbuild.sh <output directory>
#
# The seed (xaxc-linux-x86_64, a static ELF64 executable with no interpreter) resolves the compiler's canonical build
# request (xax_compiler_request.xax) to its snapshot store and builds the snapshot into the next compiler and its
# provenance; that compiler does the same.  The two compilers must be byte for byte the same.  Only sh, dirname,
# mkdir, chmod, and cmp are used besides the compilers.
set -eu
here=$(dirname "$0")
out=${1:?usage: selfbuild.sh <output directory>}
mkdir -p "$out"
compiler="$here/xaxc-linux-x86_64"
for n in 1 2; do
    "$compiler" resolve "$here/xax_compiler_request.xax" "$out/snapshot$n.xax"
    "$compiler" build "$out/snapshot$n.xax" "$out/xaxc$n" "$out/provenance$n"
    chmod 755 "$out/xaxc$n"
    compiler="$out/xaxc$n"
done
cmp "$out/xaxc1" "$out/xaxc2"
