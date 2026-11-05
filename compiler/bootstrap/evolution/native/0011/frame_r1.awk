# OI-52 R1 on the frame path: every `cmp reg, imm32` of a checked bound (frame_access, fr_memory, fr_tail) whose bound
# is 2^31 or more is materialized instead of rejected: `movabs r11, bound; cmp reg, r11` (64-bit), then the code
# after the imm32 compare (the rejoin block).  Per site: the reject's threshold becomes 2^64 - 1, the continue block
# jumps to new blocks appended after the last block, which take a small bound to the old compare and a large one
# through three `eb` calls to the rejoin block.  Nothing is renumbered.
# Usage: awk -v EB=F<eb> -f frame_r1.awk <view>   (the view's R and F lines first)
function fail(m) { print "frame_r1: " m > "/dev/stderr"; bad = 1; exit 1 }
function hname(l) { return substr(l, 1, index(l, "(") - 1) }
function targets(l, out,   rest, n, i, depth, c, start) {   # the edge targets of a br/cbr line: out[k] = "Bn(args)"
    n = 0; start = 0; depth = 0
    for (i = 1; i <= length(l); i++) {
        c = substr(l, i, 1)
        if (c == "B" && depth == 0 && (i == 1 || substr(l, i - 1, 1) == " ")) start = i
        if (c == "(") depth++
        if (c == ")") { depth--; if (depth == 0 && start) { out[++n] = substr(l, start, i - start + 1); start = 0 } }
    }
    return n
}
function args(t) { return substr(t, index(t, "(")) }
function argv_(t, a) { return split(substr(t, index(t, "(") + 1, length(t) - index(t, "(") - 1), a, ",") }
function sp(i,   s, k) { s = "P" i; for (k = 1; k < 6; k++) s = s " P" (i + k); return s }
function hdr6(i) { return "P" i ":T1,P" (i+1) ":T2,P" (i+2) ":T3,P" (i+3) ":T4,P" (i+4) ":T5,P" (i+5) ":T3" }
function res(n,   s, k) { s = n ".R1"; for (k = 2; k <= 6; k++) s = s "," n ".R" k; return s }
function node(text) { out[++no] = "N" (++N) " " text; return "N" N }
{ line[NR] = $0 }
END {
    if (bad) exit 1
    first = 3; last = NR
    for (i = first; i <= NR; i++) { if (line[i] ~ /^T[0-9]+ /) { last = i - 1; break } }
    for (i = first; i <= last; i++) {
        if (line[i] ~ /^B[0-9]+\(/) { b = hname(line[i]); head[b] = i; nb = b }
        else { blk_of[i] = b; endl[b] = i }
        if (line[i] ~ /^B[0-9]+\(/ ) { B = substr(b, 2) + 0 }
        if (match(line[i], /^N[0-9]+ /)) N = substr(line[i], 2, RLENGTH - 2) + 0
    }
    P = 0; for (i = first; i <= last; i++) { s = line[i]; while (match(s, /P[0-9]+:/)) { v = substr(s, RSTART + 1, RLENGTH - 2) + 0; if (v > P) P = v; s = substr(s, RSTART + RLENGTH) } }
    no = 0; sites = 0
    for (i = first; i <= last; i++) {
        if (line[i] !~ /^N[0-9]+ constant 2147483648 -> T0$/) continue
        split(line[i], f, " "); nt = f[1]
        split(line[i + 1], g, " "); if (g[2] != "int.compare" || g[3] != nt || line[i + 1] !~ /-> T6 \[4\]$/) continue  # another use of 2^31
        value = g[4]; nc = g[1]
        if (line[i + 2] !~ ("^cbr " nc " ")) fail("cbr after " nt)
        if (targets(line[i + 2], tg) != 2) fail("cbr targets"); bcont = hname(tg[2])
        cl = endl[bcont]; if (cl != head[bcont] + 1 || line[cl] !~ /^br B/) fail(bcont " is not a single br")
        targets(line[cl], tb); bx = hname(tb[1])
        # Bx: constant W; constant 3; eb call; ... cbr -> By; By: br Bw; Bw: constant 4; eb value 4; cbr -> Bs; Bs: br Brejoin
        if (line[head[bx] + 1] !~ /^N[0-9]+ constant [0-9]+ -> T0$/ || line[head[bx] + 2] !~ / constant 3 -> T0$/ || line[head[bx] + 3] !~ ("call.direct entity=" EB " ")) fail(bx " is not the imm32 compare")
        split(line[head[bx] + 1], w, " "); W = w[3] + 0
        targets(line[endl[bx]], t1); by = hname(t1[2]); if (line[endl[by]] !~ /^br B/) fail(by)
        targets(line[endl[by]], t2); bw = hname(t2[1])
        if (line[head[bw] + 1] !~ / constant 4 -> T0$/ || line[head[bw] + 2] !~ ("call.direct entity=" EB " ")) fail(bw " is not the imm32 bytes")
        targets(line[endl[bw]], t3); bs = hname(t3[2]); if (line[endl[bs]] !~ /^br B/) fail(bs)
        targets(line[endl[bs]], t4); brejoin = hname(t4[1])
        # the parameters Bx takes: two words, the six state values, then the rest
        hx = line[head[bx]]; hx = substr(hx, index(hx, "(") + 1); hx = substr(hx, 1, length(hx) - 1); n = split(hx, ht, ",")
        for (k = 1; k <= n; k++) { tt = ht[k]; sub(/^P[0-9]+:/, "", tt); ty[k] = tt }
        if (ty[3] != "T1" || ty[4] != "T2" || ty[5] != "T3" || ty[6] != "T4" || ty[7] != "T5" || ty[8] != "T3") fail(bx " state layout")
        hr = line[head[brejoin]]; if (gsub(/,/, ",", hr) + 1 != n) fail(brejoin " takes " n " values?")
        rex = W % 256; modrm = int(W / 65536) % 256; if (int(W / 256) % 256 != 129 || rex < 72 || rex > 73 || modrm < 248) fail("word " W)
        cmpw = (76 + rex - 72) + 57 * 256 + (216 + modrm - 248) * 65536
        # edits: the threshold, the continue block's jump
        line[i] = nt " constant 18446744073709551615 -> T0"
        bnew = "B" (++B); line[cl] = "br " bnew args(tb[1])
        h = ""; for (k = 1; k <= n; k++) h = h (k > 1 ? "," : "") "P" (P + k) ":" ty[k]
        out[++no] = bnew "(" h ")"; p0 = P + 1; P += n
        all = "P" p0; for (k = 1; k < n; k++) all = all ",P" (p0 + k)
        tail = ""; for (k = 8; k < n; k++) tail = tail ",P" (p0 + k)
        big = node("constant 2147483648 -> T0"); cond = node("int.compare " big " " value " -> T6 [4]")
        st = "P" (p0 + 2); for (k = 3; k < 8; k++) st = st ",P" (p0 + k)
        out[++no] = "cbr " cond " B" (B + 1) "(" st ") " bx "(" all ")"
        for (step = 1; step <= 3; step++) {
            out[++no] = "B" (++B) "(" hdr6(P + 1) ")"; s0 = P + 1; P += 6
            if (step == 1) { wv = node("constant 47945 -> T0"); cv = node("constant 2 -> T0") }
            if (step == 2) { wv = value; cv = node("constant 8 -> T0") }
            if (step == 3) { wv = node("constant " cmpw " -> T0"); cv = node("constant 3 -> T0") }
            call = node("call.direct entity=" EB " " wv " " cv " " sp(s0) " -> T0,T1,T2,T3,T4,T5,T3")
            none = node("constant 4294967295 -> T0"); stop = node("int.compare " call " " none " -> T6 [1]")
            nx = (step < 3) ? "B" (B + 2) "(" res(call) ")" : brejoin "(P" p0 ",P" (p0 + 1) "," res(call) tail ")"
            out[++no] = "cbr " stop " B" (B + 1) "(" res(call) ") " nx
            out[++no] = "B" (++B) "(" hdr6(P + 1) ")"; r0 = P + 1; P += 6
            none2 = node("constant 4294967295 -> T0"); out[++no] = "ret " none2 " " sp(r0)
        }
        sites++
    }
    for (i = first; i <= last; i++) print line[i]
    for (k = 1; k <= no; k++) print out[k]
    for (i = last + 1; i <= NR; i++) print line[i]
    print "frame_r1: " sites " sites" > "/dev/stderr"
}
