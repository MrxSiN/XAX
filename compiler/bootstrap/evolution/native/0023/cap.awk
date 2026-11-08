# cap2.awk -v SITES="Nk:m:a,..." -v INIT=<v> -v DOINIT=0|1 view view
# Each listed constant Nk becomes  m * cap + a  where cap is loaded from the capacity word (GLOBALS + 170, word
# 29360298); with DOINIT the entry block first stores INIT there.  The load is threaded on the workspace memory:
# the (view, token) pair is followed through each block (loads, stores, and calls that take and give back both).
function rtype(x,   b, k) { if (x in PT) return PT[x]; if (x ~ /\.R[0-9]+$/) { b = x; sub(/\.R[0-9]+$/, "", b); k = substr(x, length(b) + 3) + 0; return RT[b, k] } return RT[x, 0] }
function ref(b, k) { return k == 0 ? b : b ".R" k }
FNR == NR {
    if ($1 ~ /^B[0-9]+\(/) { s = $0; while (match(s, /P[0-9]+:T[0-9]+/)) { split(substr(s, RSTART, RLENGTH), qa, ":"); PT[qa[1]] = qa[2]; s = substr(s, RSTART + RLENGTH) } }
    if ($1 ~ /^N[0-9]+$/) { for (i = 1; i <= NF; i++) if ($i == "->") { nr = split($(i + 1), ty, ","); for (k = 1; k <= nr; k++) RT[$1, k - 1] = ty[k] } }
    if ($1 ~ /^N[0-9]+$/) DEF[$1] = $0
    if ($2 == "checked.load.bits.le" || $2 == "checked.store.bits.le") {
        # a workspace access: its address is the word clamp  trunc((268435455 + ...) * 8)
        split(DEF[$4], d1, " "); split(DEF[d1[3]], d2, " "); split(DEF[d2[3]], d3, " ")
        if (d1[2] == "int.truncate" && d2[2] == "mul.wrap" && d3[2] == "add.wrap" && DEF[d3[3]] ~ / constant 268435455 /) LOADS[++nlo] = $0
    }
    next
}
FNR == 1 {
    for (i = 1; i <= nlo; i++) { split(LOADS[i], a, " "); WT = rtype(a[3]); MT = rtype(a[2] == "checked.load.bits.le" ? a[5] : a[6]); break }
    n = split(SITES, S, ","); for (i = 1; i <= n; i++) { split(S[i], f, ":"); SITE[f[1]] = 1; MUL[f[1]] = f[2]; ADD[f[1]] = f[3] }
}
{ L[++nl] = $0 }
END {
    fresh = 0; seen = 0
    for (i = 1; i <= nl; i++) {
        if (L[i] ~ /^B[0-9]+\(/) { if (pold != "") { print "UNCONSUMED " pold > "/dev/stderr"; bad = 1 }; V = ""; T = ""; pold = ""
            if (DOINIT && !seen) needinit = 1; seen = 1
            # the pair at entry: the operands of the block's first workspace consumer
            for (j = i + 1; j <= nl && L[j] !~ /^B[0-9]+\(/; j++) { ln2 = L[j]; sub(/ -> .*/, "", ln2); nc = split(ln2, c, /[ (),]+/)
                if ((c[2] == "checked.load.bits.le" || c[2] == "checked.store.bits.le") && rtype(c[3]) == WT) { V = c[3]; T = (c[2] == "checked.load.bits.le") ? c[5] : c[6]; break }
                pv = 0; for (q = 2; q <= nc; q++) { if (!pv && rtype(c[q]) == WT) pv = q; else if (pv && rtype(c[q]) == MT) { V = c[pv]; T = c[q]; break } }
                if (V != "") break }
            continue }
        if (L[i] ~ /^T[0-9]+ / || L[i] ~ /^\(/) continue
        if (pold != "") { line = L[i]; o2 = ""; hit = 0
            while (match(line, /[NP][0-9]+(\.R[0-9]+)?/)) { tk = substr(line, RSTART, RLENGTH); if (tk == pold) { tk = pnew; hit = 1 }; o2 = o2 substr(line, 1, RSTART - 1) tk; line = substr(line, RSTART + RLENGTH) }
            L[i] = o2 line; if (hit) pold = "" }
        split(L[i], a, " ")
        site = (a[1] in SITE)
        if (needinit || site) {
            if (V == "") {  # the pair the block holds at entry: the operands of its first workspace consumer
                for (j = i; j <= nl && L[j] !~ /^B[0-9]+\(/; j++) { ln2 = L[j]; sub(/ -> .*/, "", ln2); nc = split(ln2, c, /[ (),]+/); cv = ""; ct = ""
                    for (q = 2; q <= nc; q++) { if (rtype(c[q]) == WT && cv == "") cv = c[q]; if (rtype(c[q]) == MT && ct == "") ct = c[q] }
                    if (cv != "" && ct != "") { V = cv; T = ct; break } }
                if (V == "") { hb = i; while (hb > 1 && L[hb] !~ /^B[0-9]+\(/) hb--; s3 = L[hb]; nv = 0; nm = 0
                    while (match(s3, /P[0-9]+:T[0-9]+/)) { split(substr(s3, RSTART, RLENGTH), qb, ":"); if (qb[2] == WT) { nv++; V = qb[1] } if (qb[2] == MT) { nm++; T = qb[1] } s3 = substr(s3, RSTART + RLENGTH) }
                    if (nv != 1 || nm != 1) { V = ""; T = "" } }
                if (V == "") { print "NO-PAIR at line " i " " L[i] > "/dev/stderr"; bad = 1; continue }
            }
            k = ++fresh; base = 9100000 + 20 * k; pre = ""
            if (needinit) {
                pre = "N" (base + 10) " constant 29360298 -> " W "\nN" (base + 11) " constant " INIT " -> " W "\n@ST N" (base + 12) " N" (base + 10) " " V " N" (base + 11) " " T "\n"
                # the current line may consume T: rename it now
                line = L[i]; o2 = ""; hit = 0
                while (match(line, /[NP][0-9]+(\.R[0-9]+)?/)) { tk = substr(line, RSTART, RLENGTH); if (tk == T) { tk = "N" (base + 12); hit = 1 }; o2 = o2 substr(line, 1, RSTART - 1) tk; line = substr(line, RSTART + RLENGTH) }
                if (!site && hit) { L[i] = o2 line; split(L[i], a, " ") } else if (!hit) { pold = T; pnew = "N" (base + 12) }
                T = "N" (base + 12); needinit = 0
                if (!site) { R[i] = pre; }
            }
            if (site) {
                ld = "N" base; tyy = RT[a[1], 0]
                pre = pre "N" (base + 1) " constant 29360298 -> " tyy "\n@LD " ld " N" (base + 1) " " V " " T "\n"
                val = ld
                if (MUL[a[1]] != 1) { pre = pre "N" (base + 2) " constant " MUL[a[1]] " -> " tyy "\nN" (base + 3) " mul.wrap " ld " N" (base + 2) " -> " tyy "\n"; val = "N" (base + 3) }
                if (ADD[a[1]] != 0) { pre = pre "N" (base + 4) " constant " ADD[a[1]] " -> " tyy "\nN" (base + 5) " add.wrap " val " N" (base + 4) " -> " tyy "\n"; val = "N" (base + 5) }
                pre = pre "N" (base + 6) " constant 0 -> " tyy "\n" a[1] " add.wrap " val " N" (base + 6) " -> " tyy
                R[i] = pre; L[i] = ""; pold = T; pnew = ld ".R1"; T = ld ".R1"
                continue
            }
        }
        # follow the pair: a consumer of T gives back a new token (and view)
        hasT = 0; for (q = 2; q <= length(a); q++) { if (a[q] == "->") break; if (a[q] == T) hasT = q }
        if (a[1] ~ /^(br|cbr|ret)$/) continue
        if (hasT && T != "") {
            if (a[2] == "checked.load.bits.le") { T = a[1] ".R1" }
            else if (a[2] == "checked.store.bits.le") { T = a[1] }
            else if (a[2] == "call.direct" || a[2] == "call.foreign") {
                nop = 0; delete OP; for (q = 4; q <= length(a) && a[q] != "->"; q++) { nop++; OP[nop] = a[q] }
                tv = 0; tt = 0; for (q = 1; q <= nop; q++) { if (OP[q] == V) tv = q; if (OP[q] == T) tt = q }
                # the m-th operand of a type comes back as the m-th result of that type (results after the first)
                mt = 0; for (q = 1; q <= tt; q++) if (rtype(OP[q]) == MT) mt++
                mv = 0; if (tv) for (q = 1; q <= tv; q++) if (rtype(OP[q]) == WT) mv++
                nt = 0; nv = 0; T2 = ""; V2 = ""
                for (q = 1; RT[a[1], q] != ""; q++) { if (RT[a[1], q] == MT && ++nt == mt) T2 = ref(a[1], q); if (RT[a[1], q] == WT && ++nv == mv) V2 = ref(a[1], q) }
                if (T2 == "") { print "CALL-TOKEN? line " i > "/dev/stderr"; bad = 1 }
                T = T2; if (tv && V2 != "") V = V2
            } else { print "UNKNOWN-CONSUMER line " i ": " a[2] > "/dev/stderr"; bad = 1 }
        }
    }
    for (i = 1; i <= nl; i++) { if (i in R) { print R[i]; if (L[i] != "") print L[i] } else print L[i] }
    exit bad
}
