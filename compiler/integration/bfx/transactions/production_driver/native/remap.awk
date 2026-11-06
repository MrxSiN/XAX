# awk -v BBC=<bbc listing> -v W2=<W2 listing> -v NEW=<new cids> -v VARIANTS=<variant cids> -v OLDMAIN=<cid> -v MAIN=<cid> -f remap.awk <view>
# A BBC-layer view's body with every callee handle rewritten for the W2 store: a new function is @L_<cid8>, a variant
# @V_<cid8>, the old ported main the new one (by CID), any other function its W2 handle.
BEGIN {
    while ((getline l < BBC) > 0) { split(l, a, " "); if (a[1] ~ /^F/) bcid[a[1]] = a[2] }
    while ((getline l < W2) > 0) { split(l, a, " "); if (a[1] ~ /^F/) whandle[a[2]] = a[1] }
    while ((getline l < NEW) > 0) isnew[l] = 1
    n = split(VARIANTS, v, " "); for (i = 1; i <= n; i++) isvar[v[i]] = 1
}
FNR >= 3 {
    line = $0; out = ""
    while (match(line, /entity=F[0-9]+/)) {
        h = substr(line, RSTART + 7, RLENGTH - 7); c = bcid[h]
        if (c in isvar) r = "@V_" substr(c, 1, 8)
        else if (c in isnew) r = "@L_" substr(c, 1, 8)
        else if (c == OLDMAIN) r = MAIN
        else if (c in whandle) r = whandle[c]
        else { print "remap.awk: " h " (" c ") is not in W2" > "/dev/stderr"; exit 1 }
        out = out substr(line, 1, RSTART - 1) "entity=" r; line = substr(line, RSTART + RLENGTH)
    }
    print out line
}
