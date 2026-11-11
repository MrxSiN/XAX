# Ledger 0024: splice the sign correction into the register lowering's `em_compare` (-v SRC=<expanded source: the
# immediate instance, a line `@@`, the register instance>).  The immediate instance goes in front of B22 (the left
# operand is in a register and the right one is an immediate) and takes the one edge into it; the register instance
# goes in front of B41 (both operands are in registers) and takes the one edge into it.  @EB becomes this store's
# handle of the byte emitter, read from the first call of B26 (the REX prefix of `test`).  The view is given twice.
FNR == NR { if (/^B26\(/) seen = 1; else if (seen && !eb && match($0, /call\.direct entity=F[0-9]+/)) eb = substr($0, RSTART + 19, RLENGTH - 19); next }
function put(part,    l, at) {
    if (eb == "") { print "no emitter" > "/dev/stderr"; exit 1 }
    at = 0
    while ((getline l < SRC) > 0) { if (l == "@@") { at++; continue } if (at == part) { gsub(/@EB/, eb, l); print l } }
    close(SRC)
}
/^cbr / && / B22\(/ { if (imm++) { print "edge twice" > "/dev/stderr"; exit 1 } sub(/ B22\(/, " B9000000("); print; next }
/^br B41\(/ { if (reg++) { print "edge twice" > "/dev/stderr"; exit 1 } sub(/^br B41\(/, "br B9100000("); print; next }
/^B22\(/ { put(0); done++ }
/^B41\(/ { put(1); done++ }
{ print }
END { if (done != 2 || imm != 1 || reg != 1) { print "anchors " done " " imm " " reg > "/dev/stderr"; exit 1 } }
