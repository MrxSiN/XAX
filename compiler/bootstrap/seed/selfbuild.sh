#!/bin/sh
# S15a (ADR-286): the Linux x86-64 production compiler rebuilds itself from the pinned seed, with no Python.
#
#   sh selfbuild.sh <output directory>
#
# The seed (xaxc-linux-x86_64, a static ELF64 executable with no interpreter) resolves the compiler's canonical build
# request (xax_compiler_request.xax) to its snapshot store and builds the snapshot into the next compiler and its
# provenance; that compiler does the same.  The two compilers must be byte for byte the same.  Only sh, dirname,
# mkdir, chmod, and cmp are used besides the compilers.
#
# On Windows (Git for Windows' sh) the Windows seed does the same from the Windows request, which
# ../windows/generator/generate.sh makes from the shared request with that seed.
set -eu
here=$(dirname "$0")
out=${1:?usage: selfbuild.sh <output directory>}
mkdir -p "$out"
request="$here/xax_compiler_request.xax"
compiler="$here/xaxc-linux-x86_64"
exe=
case ${OS:-} in  # Windows sets OS=Windows_NT; no command beyond the ones above is needed to tell
    Windows_NT)
        compiler="$here/../windows/xaxc-windows-x86_64.exe"; exe=.exe
        XAXC=$compiler sh "$here/../windows/generator/generate.sh" "$request" "$out/request.xax"
        request="$out/request.xax" ;;
esac
for n in 1 2; do
    "$compiler" resolve "$request" "$out/snapshot$n.xax"
    "$compiler" build "$out/snapshot$n.xax" "$out/xaxc$n$exe" "$out/provenance$n"
    chmod 755 "$out/xaxc$n$exe"
    compiler="$out/xaxc$n$exe"
done
cmp "$out/xaxc1$exe" "$out/xaxc2$exe"
