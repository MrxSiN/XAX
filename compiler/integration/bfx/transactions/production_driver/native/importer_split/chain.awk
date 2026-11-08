# chain.awk -v IN="<view> <state> <mem> <pos>" -v LAST=<handle> -v BASE=<n>: the varint writes (fb0c995c) of the
# tokens on stdin, one call per token; a number becomes a constant node first. The last call is named LAST.
{ for (i = 1; i <= NF; i++) t[++n] = $i }
END {
    split(IN, a, " "); v = a[1]; s = a[2]; m = a[3]; p = a[4]; k = BASE
    for (i = 1; i <= n; i++) {
        x = t[i]
        if (x ~ /^[0-9]+$/) { c = "N" k++; print c " constant " x " -> T9"; x = c }
        call = (i == n) ? LAST : "N" k++
        print call " call.direct entity=@L_fb0c995c " v " " s " " m " " p " " x " -> T9,T3,T5,T2"
        v = call ".R1"; s = call ".R2"; m = call ".R3"; p = call
    }
}
