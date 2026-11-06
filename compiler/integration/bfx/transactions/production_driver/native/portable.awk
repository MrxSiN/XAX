# awk -v BBC=<0003 BBC store listing> -v NEW=<layer function CIDs> -v VARIANTS=<variant CIDs> -v OLDMAIN=<CID> -f portable.awk <view>
# A BBC-layer function's 0003 view with callees named so the text fits any store that holds the driver helpers it calls:
# a layer function is @L_<cid8>, a driver entry variant @V_<cid8>, the old ported main @MAIN (the rebuild names the
# new main's CID), any other callee by its 64-digit CID.
BEGIN {
    while ((getline l < BBC) > 0) { split(l, a, " "); if (a[1] ~ /^F/) bcid[a[1]] = a[2] }
    while ((getline l < NEW) > 0) isnew[l] = 1
    n = split(VARIANTS, v, " "); for (i = 1; i <= n; i++) isvar[v[i]] = 1
}
FNR >= 3 {
    line = $0; out = ""
    while (match(line, /entity=F[0-9]+/)) {
        h = substr(line, RSTART + 7, RLENGTH - 7); c = bcid[h]
        if (c in isvar) r = "@V_" substr(c, 1, 8); else if (c in isnew) r = "@L_" substr(c, 1, 8); else if (c == OLDMAIN) r = "@MAIN"; else r = c
        out = out substr(line, 1, RSTART - 1) "entity=" r; line = substr(line, RSTART + RLENGTH)
    }
    print out line
}
