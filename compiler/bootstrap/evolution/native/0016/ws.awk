# Expands workspace-word macros in a hand-written view (the forms the general program's views use):
#   @LD <node> <address> <workspace pointer> <memory>          <node> = word <address>; its memory is <node>.R1
#   @ST <node> <address> <workspace pointer> <value> <memory>  word <address> = <value>; <node> is the memory
# A word address is clamped below 2^28 and scaled by 8, as e.ld/e.st do.  Fresh nodes are numbered from 90000 up;
# renumber.awk (ledger 0015) then numbers everything in order.
BEGIN { n = 90000 }
function addr(a,    c1, c2, c3, c4, c5, c6, c7, c8, c9, c10) {
    c1 = "N" n++; c2 = "N" n++; c3 = "N" n++; c4 = "N" n++; c5 = "N" n++; c6 = "N" n++; c7 = "N" n++; c8 = "N" n++; c9 = "N" n++; c10 = "N" n++
    print c1 " constant 268435456 -> T0"; print c2 " int.compare " a " " c1 " -> T6 [3]"; print c3 " constant 268435455 -> T0"
    print c4 " int.zero.extend " c2 " -> T0"; print c5 " sub.wrap " a " " c3 " -> T0"; print c6 " mul.wrap " c4 " " c5 " -> T0"
    print c7 " add.wrap " c3 " " c6 " -> T0"; print c8 " constant 8 -> T0"; print c9 " mul.wrap " c7 " " c8 " -> T0"
    print c10 " int.truncate " c9 " -> T7"
    return c10
}
$1 == "@LD" { o = addr($3); print $2 " checked.load.bits.le " $4 " " o " " $5 " -> T0,T3 [8,1]"; next }
$1 == "@ST" { o = addr($3); print $2 " checked.store.bits.le " $4 " " o " " $5 " " $6 " -> T3 [8,1]"; next }
{ print }
