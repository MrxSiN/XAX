# ws.awk -v W= -v M= -v B= -v I=: @LD/@ST (as native/0020/ws64.awk) with this function's word, memory, bits1, bits32 types.
BEGIN { n = 90000 }
function addr(a,    c1, c2, c3, c4, c5, c6, c7, c8, c9, c10) {
    c1 = "N" n++; c2 = "N" n++; c3 = "N" n++; c4 = "N" n++; c5 = "N" n++; c6 = "N" n++; c7 = "N" n++; c8 = "N" n++; c9 = "N" n++; c10 = "N" n++
    print c1 " constant 268435456 -> " W; print c2 " int.compare " a " " c1 " -> " B " [3]"; print c3 " constant 268435455 -> " W
    print c4 " int.zero.extend " c2 " -> " W; print c5 " sub.wrap " a " " c3 " -> " W; print c6 " mul.wrap " c4 " " c5 " -> " W
    print c7 " add.wrap " c3 " " c6 " -> " W; print c8 " constant 8 -> " W; print c9 " mul.wrap " c7 " " c8 " -> " W
    print c10 " int.truncate " c9 " -> " I
    return c10
}
$1 == "@LD" { o = addr($3); print $2 " checked.load.bits.le " $4 " " o " " $5 " -> " W "," M " [8,1]"; next }
$1 == "@ST" { o = addr($3); print $2 " checked.store.bits.le " $4 " " o " " $5 " " $6 " -> " M " [8,1]"; next }
{ print }
