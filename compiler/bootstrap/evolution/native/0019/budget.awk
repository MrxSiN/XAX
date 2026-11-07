# candidate's view with a guard in front: when the lowering view already has more than BUDGET values
# (GLOBALS + G_VCOUNT, word 29360173), it gives 0 at once: the call is not inlined and stays a call.  The old entry
# block becomes B2; the output needs renumber.awk (ledger 0015).  Parameters: P0 the callee, P1 its result count,
# P2-P4 and P5-P7 two (view, ..., memory) groups; GLOBALS is read through P5 with memory P7, as candidate does.
FNR <= 2 { next }
FNR == 3 {
    print
    print "B0(P900:T0,P901:T0,P902:T1,P903:T2,P904:T3,P905:T4,P906:T5,P907:T3)"
    print "N9000 constant 29360173 -> T0"
    print "N9001 constant 268435456 -> T0"; print "N9002 int.compare N9000 N9001 -> T6 [3]"; print "N9003 constant 268435455 -> T0"
    print "N9004 int.zero.extend N9002 -> T0"; print "N9005 sub.wrap N9000 N9003 -> T0"; print "N9006 mul.wrap N9004 N9005 -> T0"
    print "N9007 add.wrap N9003 N9006 -> T0"; print "N9008 constant 8 -> T0"; print "N9009 mul.wrap N9007 N9008 -> T0"
    print "N9010 int.truncate N9009 -> T7"
    print "N9011 checked.load.bits.le P905 N9010 P907 -> T0,T3 [8,1]"
    print "N9012 constant " BUDGET " -> T0"
    print "N9013 int.compare N9012 N9011 -> T6 [3]"
    print "cbr N9013 B1(P900,P901,P902,P903,P904,P905,P906,N9011.R1) B2(P900,P901,P902,P903,P904,P905,P906,N9011.R1)"
    print "B1(P910:T0,P911:T0,P912:T1,P913:T2,P914:T3,P915:T4,P916:T5,P917:T3)"
    print "N9020 constant 0 -> T0"
    print "ret N9020 P912 P913 P914 P915 P916 P917"
    next
}
/^T[0-9]+ / { print; next }
{
    line = $0; out = ""
    while (match(line, /B[0-9]+\(/)) { out = out substr(line, 1, RSTART - 1) "B" (substr(line, RSTART + 1, RLENGTH - 2) + 2) "("; line = substr(line, RSTART + RLENGTH) }
    print out line
}
