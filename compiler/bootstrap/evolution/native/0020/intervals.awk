# Ledger 0020: `_intervals` (CID 0952bb79...) sizes its range pool by @pool_bound (pool_bound.src) instead of by
# blocks x values.  B0 first calls @pool_bound; the call's views and memory replace B0's parameters P0-P5 in B0, and
# the blocks x values product (N37) becomes the bound.
function block(line) { return match(line, /^B[0-9]+\(/) ? substr(line, 2, RLENGTH - 2) + 0 : -1 }
function views(line,    out, tok) {
    out = ""
    while (match(line, /P[0-5]([^0-9]|$)/)) {
        tok = substr(line, RSTART + 1, 1)
        out = out substr(line, 1, RSTART - 1) "N8100000.R" (tok + 1)
        line = substr(line, RSTART + 2)
    }
    return out line
}
{ b = block($0); if (b >= 0) cur = b }
cur == 0 && b == 0 { print; print "N8100000 call.direct entity=@pool_bound P0 P1 P2 P3 P4 P5 -> T5,T0,T1,T2,T3,T4,T2"; next }
cur == 0 && $1 == "N37" { print "N8100001 constant 0 -> T5"; print "N37 add.wrap N8100000 N8100001 -> T5"; next }
cur == 0 && /^(N|br |cbr |ret )/ { print views($0); next }
{ print }
