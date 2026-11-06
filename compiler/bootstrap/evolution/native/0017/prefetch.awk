# prefetch's view with a guard in front: when the view has more than LIMIT blocks (GLOBALS + G_BCOUNT, word
# 29360176), it gives 1 at once and selects no prefetch.  The old entry block becomes B2; the output needs
# renumber.awk (ledger 0015).
FNR <= 2 { next }
FNR == 3 {
    print
    print "B0(P900:T0,P901:T1,P902:T2,P903:T3,P904:T4,P905:T2)"
    print "N9000 constant 29360176 -> T5"
    print "N9001 constant 268435456 -> T5"; print "N9002 int.compare N9000 N9001 -> T6 [3]"; print "N9003 constant 268435455 -> T5"
    print "N9004 int.zero.extend N9002 -> T5"; print "N9005 sub.wrap N9000 N9003 -> T5"; print "N9006 mul.wrap N9004 N9005 -> T5"
    print "N9007 add.wrap N9003 N9006 -> T5"; print "N9008 constant 8 -> T5"; print "N9009 mul.wrap N9007 N9008 -> T5"
    print "N9010 int.truncate N9009 -> T7"
    print "N9011 checked.load.bits.le P903 N9010 P905 -> T5,T2 [8,1]"
    print "N9012 constant " LIMIT " -> T5"
    print "N9013 int.compare N9012 N9011 -> T6 [3]"
    print "cbr N9013 B1(P900,P901,P902,P903,P904,N9011.R1) B2(P900,P901,P902,P903,P904,N9011.R1)"
    print "B1(P910:T0,P911:T1,P912:T2,P913:T3,P914:T4,P915:T2)"
    print "N9020 constant 1 -> T5"
    print "ret N9020 P910 P911 P912 P913 P914 P915"
    next
}
/^T[0-9]+ / { print; next }
{
    line = $0; out = ""
    while (match(line, /B[0-9]+\(/)) { out = out substr(line, 1, RSTART - 1) "B" (substr(line, RSTART + 1, RLENGTH - 2) + 2) "("; line = substr(line, RSTART + RLENGTH) }
    print out line
}
