# The driver's main F441 -> @main2: before each call of the decoder, a call of @read_limit on its length argument; the
# decoder call becomes @decode2 with that limit as its ninth argument.  Node handles move up past each insertion.
function shiftn(line,    out, pre, n, k, add) {
    out = ""
    while (match(line, /N[0-9]+/)) {
        pre = substr(line, 1, RSTART - 1); n = substr(line, RSTART + 1, RLENGTH - 1) + 0
        add = 0
        if (RSTART == 1 || substr(line, RSTART - 1, 1) !~ /[A-Za-z0-9]/) for (k = 1; k <= nsites; k++) if (site[k] <= n) add++
        out = out pre "N" (n + add); line = substr(line, RSTART + RLENGTH)
    }
    return out line
}
FNR == NR { if ($0 ~ /call\.direct entity=F77 /) site[++nsites] = substr($1, 2) + 0; next }
FNR <= 2 { next }
{
    if ($0 ~ /call\.direct entity=F77 /) {
        n = substr($1, 2) + 0; j = 0
        for (k = 1; k <= nsites; k++) if (site[k] <= n) j++
        line = shiftn($0); split(line, f, " ")
        printf "N%d call.direct entity=@read_limit %s -> T3\n", n + j - 1, f[10]
        sub(/entity=F77/, "entity=@decode2", line)
        sub(/ -> /, " N" (n + j - 1) " -> ", line)
        print line
        next
    }
    print shiftn($0)
}
