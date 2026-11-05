# The decoder's view -> @decode2.  Its signature changes: P6 is now the limit of the bytes it may read (the store's
# length and the 32-byte digest the driver passes after it) and P7, the mode (1 to 4), is bits<32> (T7).  Three nodes
# open B0: N0 = @read_limit(P6), N1 = 32, N2 = P6 - N1 (the length, where P6 was used); later nodes move up by three.
# Every data byte read is a growable load bounded by N0.
function renum(line,    out, pre, n) {
    out = ""
    while (match(line, /N[0-9]+/)) {
        pre = substr(line, 1, RSTART - 1); n = substr(line, RSTART + 1, RLENGTH - 1) + 0
        if (RSTART == 1 || substr(line, RSTART - 1, 1) !~ /[A-Za-z0-9]/) n = n + 3
        out = out pre "N" n; line = substr(line, RSTART + RLENGTH)
    }
    return out line
}
function p6(line) { gsub(/ P6 /, " N2 ", line); gsub(/ P6$/, " N2", line); gsub(/\(P6,/, "(N2,", line); gsub(/,P6,/, ",N2,", line); gsub(/,P6\)/, ",N2)", line); return line }
NR <= 2 { next }
NR == 3 { sub(/T5,T5\)->/, "T5,T7)->"); print; next }
{
    line = $0
    # the constants compared with the mode become bits<32>
    if (line ~ /^N(0|780|3039|3049) constant [0-9]+ -> T5$/) sub(/-> T5$/, "-> T7", line)
    if (line ~ /^B0\(/) {
        sub(/P7:T5\)/, "P7:T7)", line); print line
        print "N0 call.direct entity=@read_limit P6 -> T5"; print "N1 constant 32 -> T5"; print "N2 sub.wrap P6 N1 -> T5"
        next
    }
    line = p6(renum(line))
    if (line ~ /checked\.load\.bits\.le P0 / && line ~ /-> T8,T2 \[1,1\]$/) {
        sub(/checked\.load\.bits\.le P0 /, "growable.load.bits.le P0 ", line)
        split(line, f, " "); line = f[1] " " f[2] " " f[3] " " f[4] " N0"     # P0 <offset> N0 <memory>
        for (k = 5; k <= length(f); k++) line = line " " f[k]
    }
    print line
}
