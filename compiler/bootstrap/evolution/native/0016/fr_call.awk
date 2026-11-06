# fr_call's arity guard (B306 of its view, the same in every store): `1 < cl_r` becomes `0 < @cl_borrow(node,
# cl_r + cl_r_first * 2^32)`, the call threading the state the branch passes on.  The two counts share one word so
# that @cl_borrow has four machine parameters and the register path (which the pre-0016 seed must use to build it)
# lowers it.  The output has one more node; renumber.awk
# (ledger 0015) then numbers the view in order.
$1 == "N3327" && $2 == "constant" && $3 == "1" { print "N99996 constant 4294967296 -> T0"; print "N99997 mul.wrap P6926 N99996 -> T0"; print "N99998 add.wrap P6925 N99997 -> T0"
    print "N3327 call.direct entity=@cl_borrow N48 N99998 P6911 P6912 P6913 P6914 P6915 P6916 -> T0,T1,T2,T3,T4,T5,T3"; print "N99999 constant 0 -> T0"; seen++; next }
$1 == "N3328" && $2 == "int.compare" && $3 == "N3327" && $4 == "P6925" { print "N3328 int.compare N99999 N3327 -> T6 [3]"; seen++; next }
$1 == "cbr" && $2 == "N3328" { gsub(/\(P6909,P6910,P6911,P6912,P6913,P6914,P6915,P6916,/, "(P6909,P6910,N3327.R1,N3327.R2,N3327.R3,N3327.R4,N3327.R5,N3327.R6,"); seen++; print; next }
{ print }
END { if (seen != 3) { print "fr_call.awk: the guard was not found" > "/dev/stderr"; exit 1 } }
