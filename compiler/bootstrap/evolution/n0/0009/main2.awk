# The driver's main -> @main2: before each decoder call, N = 32 and N' = length + N; the call becomes @decode2 with
# N' (the read limit) for the length and its mode constant typed bits<32> (T21).  Node handles move up past each
# insertion (two nodes per call; no call is added, so nothing is inlined into main).
function shiftn(line,    out, pre, n, k, add) {
    out = ""
    while (match(line, /N[0-9]+/)) {
        pre = substr(line, 1, RSTART - 1); n = substr(line, RSTART + 1, RLENGTH - 1) + 0
        add = 0
        if (RSTART == 1 || substr(line, RSTART - 1, 1) !~ /[A-Za-z0-9]/) for (k = 1; k <= nsites; k++) if (site[k] <= n) add += 2
        out = out pre "N" (n + add); line = substr(line, RSTART + RLENGTH)
    }
    return out line
}
FNR == NR { if ($0 ~ /call\.direct entity=F77 /) { site[++nsites] = substr($1, 2) + 0; mode[$11] = 1 } next }
FNR <= 2 { next }
{
    if ($1 in mode) { sub(/ -> T3$/, " -> T21") }
    if ($0 ~ /call\.direct entity=F77 /) {
        line = shiftn($0); split(line, f, " ")
        n = substr(f[1], 2) + 0
        printf "N%d constant 32 -> T3\n", n - 2
        printf "N%d add.wrap %s N%d -> T3\n", n - 1, f[10], n - 2
        sub(/entity=F77/, "entity=@decode2", line)
        out = f[1] " " f[2] " entity=@decode2"
        for (k = 4; k <= length(f); k++) out = out " " (k == 10 ? "N" (n - 1) : f[k])
        print out
        next
    }
    print shiftn($0)
}
