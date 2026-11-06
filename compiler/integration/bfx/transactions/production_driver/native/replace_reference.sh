#!/bin/sh
# replace_reference.sh <root> <owner> <old> <kind> <body hex> > <record>
# An XAXEDIT1 record (xaxc edit's edit-record input) with one REPLACE_REFERENCE: in <owner>, the reference <old>
# becomes the record's supplied object 0, of kind <kind> with no references and body <body hex>; <root> is the
# store root the record expects.  Written with printf alone.
set -eu
uleb() { v=$1; out=""; while :; do b=$((v & 127)); v=$((v >> 7)); if [ "$v" -gt 0 ]; then out="$out$(printf '%02x' $((b | 128)))"; else out="$out$(printf '%02x' "$b")"; break; fi; done; printf '%s' "$out"; }
magic=$(printf 'XAXEDIT1' | od -An -tx1 | tr -d ' \n')
mark=$(printf 'XAX-SUPPLIED-OBJECT-REF' | od -An -tx1 | tr -d ' \n')00
n=$(( ${#5} / 2 ))
hex="$magic$1$(uleb 1)$(uleb 3)$2$3${mark}0000000000000000$(uleb 1)$(uleb "$4")$(uleb 0)$(uleb "$n")$5"
printf '%s' "$hex" | sed 's/../\\x&/g' | xargs -0 printf '%b'
