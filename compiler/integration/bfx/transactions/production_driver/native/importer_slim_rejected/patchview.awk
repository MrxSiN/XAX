# patchview.awk patches.txt <view>: apply "B<n> <k> drop|set <v>" to the k-th @L_fb0c995c call of block B<n>.
# set: a fresh constant node replaces the call's value operand; drop: the call goes, and every later use of its
# results (.R1 .R2 .R3, and the bare handle) takes its inputs (view, state, memory, position).
NR == FNR { key = $1 " " $2; if ($3 == "drop") D[key] = 1; else S[key] = $4; next }
function sub_aliases(line,   out, tok) {
    out = ""
    while (match(line, /N[0-9]+(\.R[0-9])?/)) {
        tok = substr(line, RSTART, RLENGTH)
        out = out substr(line, 1, RSTART - 1) ((tok in A) ? A[tok] : tok); line = substr(line, RSTART + RLENGTH)
    }
    return out line
}
/^B[0-9]+\(/ { b = $1; sub(/\(.*/, "", b); k = 0; print; next }
/^N[0-9]+ call\.direct entity=@L_fb0c995c / {
    $0 = sub_aliases($0); k++; key = b " " k
    if (key in D) { A[$1] = $7; A[$1 ".R1"] = $4; A[$1 ".R2"] = $5; A[$1 ".R3"] = $6; nd++; next }
    if (key in S) { c = "N" (++fresh + 9800000); print c " constant " S[key] " -> T9"; $8 = c; ns++ }
    print; next
}
/^N[0-9]+ / || /^(br|cbr|ret) / { print sub_aliases($0); next }
{ print }
END { print "dropped " nd ", set " ns > "/dev/stderr" }
