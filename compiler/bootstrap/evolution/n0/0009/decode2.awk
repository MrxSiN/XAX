# The decoder F80's view -> @decode2: a ninth parameter (P8, bits64: the read limit) and every data byte read a growable
# load bounded by it.  Parameters from P8 on move up by one.
function shiftp(line,    out, pre, n) {
    out = ""
    while (match(line, /P[0-9]+/)) {
        pre = substr(line, 1, RSTART - 1); n = substr(line, RSTART + 1, RLENGTH - 1) + 0
        if (n >= 8 && (RSTART == 1 || substr(line, RSTART - 1, 1) !~ /[A-Za-z0-9]/)) n = n + 1
        out = out pre "P" n; line = substr(line, RSTART + RLENGTH)
    }
    return out line
}
NR <= 2 { next }                                   # the R and F header lines
NR == 3 { sub(/T5,T5\)->/, "T5,T5,T5)->"); print; next }
{
    line = shiftp($0)
    if (line ~ /^B0\(/) sub(/P7:T5\)/, "P7:T5,P8:T5)", line)
    if (line ~ /checked\.load\.bits\.le P0 / && line ~ /-> T8,T2 \[1,1\]$/) {
        sub(/checked\.load\.bits\.le P0 /, "growable.load.bits.le P0 ", line)
        # operands: P0 <offset> <memory>  ->  P0 <offset> P8 <memory>
        split(line, f, " "); line = f[1] " " f[2] " " f[3] " " f[4] " P8"
        for (k = 5; k <= length(f); k++) line = line " " f[k]
    }
    print line
}
