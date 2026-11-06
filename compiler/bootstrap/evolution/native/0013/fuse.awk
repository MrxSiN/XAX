# The x86-64 general backend's register path fused a compare into its block's conditional branch when no node of that
# block used it, though a later block could still read it (ADR-304's bits<1> hazard; OI-53).  `basics` now also
# requires the compare's early use count (every block, terminators included; T_EARLY) to be 1: the branch is its only
# use.  Sixteen nodes are inserted after N3190 in B196 and node handles from N3191 on move up by 16.
function shiftn(line,    out, pre, n) {
    out = ""
    while (match(line, /N[0-9]+/)) {
        pre = substr(line, 1, RSTART - 1); n = substr(line, RSTART + 1, RLENGTH - 1) + 0
        if ((RSTART == 1 || substr(line, RSTART - 1, 1) !~ /[A-Za-z0-9]/) && n >= 3191) n += 16
        out = out pre "N" n; line = substr(line, RSTART + RLENGTH)
    }
    return out line
}
NR <= 2 { next }
$0 == "N3190 int.zero.extend N3188 -> T5" {
    if (state != 0) { print "anchor twice" > "/dev/stderr"; exit 1 }
    print
    print "N3191 constant 234881504 -> T7"
    print "N3192 checked.load.bits.le P3307 N3191 N3177.R1 -> T5,T2 [8,1]"
    print "N3193 constant 2 -> T5"
    print "N3194 add.wrap N3192 N3193 -> T5"
    print "N3195 constant 8 -> T5"
    print "N3196 mul.wrap N3194 N3195 -> T5"
    print "N3197 int.truncate N3196 -> T7"
    print "N3198 checked.load.bits.le P3307 N3197 N3192.R1 -> T5,T2 [8,1]"
    print "N3199 add.wrap N3198 P3326 -> T5"
    print "N3200 mul.wrap N3199 N3195 -> T5"
    print "N3201 int.truncate N3200 -> T7"
    print "N3202 checked.load.bits.le P3307 N3201 N3198.R1 -> T5,T2 [8,1]"
    print "N3203 constant 1 -> T5"
    print "N3204 int.compare N3202 N3203 -> T6 [1]"
    print "N3205 int.zero.extend N3204 -> T5"
    print "N3206 bit.and N3190 N3205 -> T5"
    state = 1; next
}
state == 1 && $0 == "N3191 bit.and N3189 N3190 -> T5" { print "N3207 bit.and N3189 N3206 -> T5"; state = 2; next }
state == 2 && /^cbr N3193 B203\(/ { l = shiftn($0); n = gsub(/N3177\.R1/, "N3202.R1", l); if (n != 2) { print "mem args " n > "/dev/stderr"; exit 1 } print l; state = 3; next }
{ print shiftn($0) }
END { if (state != 3) { print "state " state > "/dev/stderr"; exit 1 } }
