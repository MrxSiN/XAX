# Ledger 0024: splice the sign correction (-v SRC=<expanded frame.src>) in front of B458 of the frame path's integer
# node function, the block that emits the compare's `cmp` after both operands are loaded.  The one edge into B458
# (from B457) goes to the new block instead.  @EB in the source becomes this store's handle of the byte emitter,
# read from the call that emits the compare's REX prefix (the first call of B459).  The view is given twice.
FNR == NR { if (/^B459\(/) seen = 1; else if (seen && !eb && match($0, /call\.direct entity=F[0-9]+/)) eb = substr($0, RSTART + 19, RLENGTH - 19); next }
/^br B458\(/ { if (edges++) { print "edge twice" > "/dev/stderr"; exit 1 } sub(/^br B458\(/, "br B9000000("); print; next }
/^B458\(/ {
    if (eb == "" || edges != 1) { print "no anchor" > "/dev/stderr"; exit 1 }
    while ((getline l < SRC) > 0) { gsub(/@EB/, eb, l); print l }
    done = 1
}
{ print }
END { if (!done) { print "B458 not found" > "/dev/stderr"; exit 1 } }
