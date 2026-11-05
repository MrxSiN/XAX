# OI-52 R1 in the register path's checked access (em_memory): a bound extent - size of 2^31 or more is no longer
# rejected (NATIVE-CHECKED-BOUND-ENCODABLE); it is materialized, `movabs r11, bound; cmp index, r11` (64-bit), and the
# check's `ja` trap (B94) follows as before.  The reject's threshold becomes 2^64 - 1 (unreachable); B87 continues in
# the new B298, which takes small bounds to the imm32 compare (B91) and large ones through three `eb` calls to B94.
# Heap views and memory travel as block parameters; only appended handles are new, nothing is renumbered.
# Usage: awk -v EB=F<eb> -v LASTB=<last block> -v LASTP=<last parameter> -v LASTN=<last node> -f em_memory.awk <view>
function st(i, k,   s) { s = "P" i; for (k = 1; k < 6; k++) s = s ",P" (i + k); return s }       # six state parameters
function sp(i,   s, k) { s = "P" i; for (k = 1; k < 6; k++) s = s " P" (i + k); return s }     # the same, as operands
function hdr(i, k,   s) { s = "P" i ":T1,P" (i+1) ":T2,P" (i+2) ":T3,P" (i+3) ":T4,P" (i+4) ":T5,P" (i+5) ":T3"; return s }
function res(n,   s, k) { s = n ".R1"; for (k = 2; k <= 6; k++) s = s "," n ".R" k; return s }
function node(text) { print "N" (++N) " " text; return "N" N }
function block(h) { print "B" (++B) "(" h ")"; return B }
NR <= 2 { next }
$0 == "N1812 constant 2147483648 -> T0" { print "N1812 constant 18446744073709551615 -> T0"; hit1 = 1; next }
inB87 { if ($0 !~ /^br B91\(/) { print "unexpected B87 body" > "/dev/stderr"; exit 1 }
        args = substr($0, 7); print "br B" (LASTB + 1) args; inB87 = 0; hit2 = 1; next }
/^B87\(/ { inB87 = 1; print; next }
/^B91\(/ { types = $0; sub(/^B91\(/, "", types); sub(/\)$/, "", types); n = split(types, t, ","); for (k = 1; k <= n; k++) { sub(/^P[0-9]+:/, "", t[k]); ty[k] = t[k] } }
/^T0 / && !done {
    if (!hit1 || !hit2) { print "anchor missing" > "/dev/stderr"; exit 1 }
    B = LASTB; P = LASTP; N = LASTN
    # B298: the 31 values B91 takes
    h = ""; for (k = 1; k <= 31; k++) h = h (k > 1 ? "," : "") "P" (P + k) ":" ty[k]
    b0 = block(h); p0 = P + 1; P += 31
    all = "P" p0; for (k = 1; k < 31; k++) all = all ",P" (p0 + k)
    tail = "P" (p0 + 8); for (k = 9; k < 31; k++) tail = tail ",P" (p0 + k)
    big = node("constant 2147483648 -> T0"); cond = node("int.compare " big " P1928 -> T6 [4]")
    print "cbr " cond " B" (B + 1) "(" st(p0 + 2) ") B91(" all ")"
    # three bytes groups: movabs r11 (49 BB), the bound (8 bytes), cmp index, r11 (4C+hi 39 D8+low3)
    for (step = 1; step <= 3; step++) {
        block(hdr(P + 1)); s = P + 1; P += 6
        if (step == 1) { w = node("constant 47945 -> T0"); c = node("constant 2 -> T0") }
        if (step == 2) { w = "P1928"; c = node("constant 8 -> T0") }
        if (step == 3) {
            eight = node("constant 8 -> T0"); hi1 = node("int.compare " eight " P1929 -> T6 [4]"); hi = node("int.zero.extend " hi1 " -> T0")
            seven = node("constant 7 -> T0"); lo = node("bit.and P1929 " seven " -> T0")
            c76 = node("constant 76 -> T0"); rex = node("add.wrap " c76 " " hi " -> T0")
            c216 = node("constant 216 -> T0"); mrm = node("add.wrap " c216 " " lo " -> T0")
            c64k = node("constant 65536 -> T0"); hiw = node("mul.wrap " mrm " " c64k " -> T0")
            c14592 = node("constant 14592 -> T0"); w1 = node("add.wrap " rex " " c14592 " -> T0"); w = node("add.wrap " w1 " " hiw " -> T0")
            c = node("constant 3 -> T0")
        }
        call = node("call.direct entity=" EB " " w " " c " " sp(s) " -> T0,T1,T2,T3,T4,T5,T3")
        none = node("constant 4294967295 -> T0"); stop = node("int.compare " call " " none " -> T6 [1]")
        next_ok = (step < 3) ? "B" (B + 2) "(" res(call) ")" : "B94(P" p0 ",P" (p0 + 1) "," res(call) "," tail ")"
        print "cbr " stop " B" (B + 1) "(" res(call) ") " next_ok
        block(hdr(P + 1)); r = P + 1; P += 6
        none2 = node("constant 4294967295 -> T0")
        print "ret " none2 " " sp(r)
    }
    done = 1
}
{ print }
