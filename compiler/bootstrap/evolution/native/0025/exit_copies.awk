# Ledger 0025: `_conditional` (CID 8037b966...) of the AArch64 register lowering.  Input: the function's view from its
# signature line.  In B33 (the test "the taken edge has copies and its target is not the following block", N504) the
# early copies get a third condition: the target's loop depth (A_DEPTH, word 36 of the lowering's globals) is not
# below this block's.  The four word loads thread the memory, so the block's edges pass the last load's memory
# instead of P587.
#   @LD <node> <address> <workspace pointer> <memory>   <node> = word <address>; its memory is <node>.R1
# A word address is clamped below 2^28 and scaled by 8, as every load of this function is.
BEGIN { n = 8300000 }
function ld(node, a, ws, mem,    c1, c2, c3, c4, c5, c6, c7, c8, c9, c10) {
    c1 = "N" n++; c2 = "N" n++; c3 = "N" n++; c4 = "N" n++; c5 = "N" n++; c6 = "N" n++; c7 = "N" n++; c8 = "N" n++; c9 = "N" n++; c10 = "N" n++
    print c1 " constant 268435456 -> T0"; print c2 " int.compare " a " " c1 " -> T6 [3]"; print c3 " constant 268435455 -> T0"
    print c4 " int.zero.extend " c2 " -> T0"; print c5 " sub.wrap " a " " c3 " -> T0"; print c6 " mul.wrap " c4 " " c5 " -> T0"
    print c7 " add.wrap " c3 " " c6 " -> T0"; print c8 " constant 8 -> T0"; print c9 " mul.wrap " c7 " " c8 " -> T0"
    print c10 " int.truncate " c9 " -> T7"
    print node " checked.load.bits.le " ws " " c10 " " mem " -> T0,T3 [8,1]"
}
match($0, /^B[0-9]+\(/) { cur = substr($0, 2, RLENGTH - 2) + 0 }
cur == 33 && $1 == "N506" {
    if ($0 != "N506 int.compare N504 N505 -> T6 [2]") { print "exit_copies.awk: unexpected N506: " $0 > "/dev/stderr"; exit 1 }
    print "N8200000 constant 29360189 -> T0"
    ld("N8200001", "N8200000", "P585", "P587")            # the lowering's globals
    print "N8200002 constant 36 -> T0"
    print "N8200003 add.wrap N8200001 N8200002 -> T0"
    ld("N8200004", "N8200003", "P585", "N8200001.R1")     # A_DEPTH: loop depth per block
    print "N8200005 add.wrap N8200004 P0 -> T0"
    ld("N8200006", "N8200005", "P585", "N8200004.R1")     # this block's depth
    print "N8200007 add.wrap N8200004 P589 -> T0"
    ld("N8200008", "N8200007", "P585", "N8200006.R1")     # the taken target's depth
    print "N8200009 int.compare N8200008 N8200006 -> T6 [3]"  # the edge leaves a loop
    print "N8200010 int.zero.extend N8200009 -> T0"
    print "N8200011 constant 1 -> T0"
    print "N8200012 sub.wrap N8200011 N8200010 -> T0"
    print "N8200013 bit.and N504 N8200012 -> T0"
    print "N506 int.compare N8200013 N505 -> T6 [2]"
    done++; next
}
cur == 33 && $1 == "cbr" {
    if (gsub(/,P587,/, ",N8200008.R1,") != 2) { print "exit_copies.awk: unexpected B33 terminator" > "/dev/stderr"; exit 1 }
    done++
}
{ print }
END { if (done != 2) { print "exit_copies.awk: B33 not found" > "/dev/stderr"; exit 1 } }
