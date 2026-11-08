# parse.awk -v PROG="<items>" -v CUR="<block symbols>" on one chain's tokens (stdin, space separated): patch actions
# "<k> drop" / "<k> set <v>" (k = 1-based write index) slimming every non-entry block from 9 to 6 parameters.
# Items: block header node nodes:<n> term count cur:<syms> b0term stop
function ref(ctx,   tag, b, k) {
    tag = T[i]
    if (tag == "0") {
        b = T[i + 1]; k = T[i + 2]
        if (B0 && ctx == "edge" && b == "0" && (k == 1 || k == 4 || k == 7)) { drop(i); drop(i + 1); drop(i + 2); d++ }
        else if (!B0 && (b in C)) {
            if (k == 3 || k == 5 || k == 7) {
                if (ctx == "edge") { drop(i); drop(i + 1); drop(i + 2); d++ }
                else if (ctx == "ret") { set(i + 1, 0); set(i + 2, (k == 3) ? 1 : (k == 5 ? 4 : 7)) }
                else { print "ERROR T1 param in node at " i > "/dev/stderr"; err = 1 }
            } else if (k == 4) set(i + 2, 3); else if (k == 6) set(i + 2, 4); else if (k == 8) set(i + 2, 5); else if (k == 9 && ACC) set(i + 2, 6)
        }
        i += 3
    } else i += 4
}
function drop(j) { print j " drop" }
function set(j, v) { if (T[j] != v) print j " set " v }
function node(   op, n, j, na) { op = T[i++]; n = T[i++]; for (j = 0; j < n; j++) ref("node"); n = T[i++]; i += n
    if (op == 57 || op == 38 || op == 39 || op == 63) { na = T[i++]; i += na } }
function header(   n) { n = T[i]; ACC = (n == 10)
    if ((n == 9 || n == 10) && T[i+1] == 6 && T[i+2] == 6 && T[i+3] == 6 && T[i+4] == 5 && T[i+5] == 3 && T[i+6] == 5 && T[i+7] == 3 && T[i+8] == 5 && T[i+9] == 3) {
        set(i, n - 3); drop(i + 4); drop(i + 6); drop(i + 8) } else { print "ERROR header at " i ": " n > "/dev/stderr"; err = 1 }
    i += 1 + n }
function edge(   cp, n, j) { i++; cp = i; n = T[i++]; d = 0; for (j = 0; j < n; j++) ref("edge"); if (d) set(cp, n - d) }
function term(   k, n, j) { k = T[i++]
    if (k == 1) edge(); else if (k == 2) { ref("node"); edge(); edge() } else if (k == 3) { n = T[i++]; for (j = 0; j < n; j++) ref("ret") }
    else { print "ERROR term kind " k " at " i > "/dev/stderr"; err = 1 } }
{ for (f = 1; f <= NF; f++) T[++nt] = $f }
END {
    i = 1; np = split(PROG, P, " "); B0 = 0
    nc = split(CUR, cs, ","); for (j = 1; j <= nc; j++) C[cs[j]] = 1
    for (q = 1; q <= np; q++) {
        it = P[q]
        if (it ~ /^cur:/) { delete C; nc = split(substr(it, 5), cs, ","); for (j = 1; j <= nc; j++) C[cs[j]] = 1; B0 = 0 }
        else if (it == "b0term") { B0 = 1; term(); B0 = 0 }
        else if (it == "header") header(); else if (it == "count") i++
        else if (it == "node") node(); else if (it == "term") term()
        else if (it == "block") { header(); n = T[i++]; for (j = 0; j < n; j++) node(); term() }
        else if (it == "stop") break
    }
    if (!err && it != "stop" && i != nt + 1) print "WARN consumed " i - 1 " of " nt > "/dev/stderr"
}
