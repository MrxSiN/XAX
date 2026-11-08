# Per emitter block: its write chain(s) of @L_fb0c995c calls: first call's inputs, last call, the token stream, and
# the non-constant nodes found between the first and last call (they block a mechanical rewrite).
/^B[0-9]+\(/ { flush(); b = $1; sub(/\(.*/, "", b); next }
/^N[0-9]+ constant / { c[$1] = $3; if (inch) pend = pend " " $1; next }
/fb0c995c/ {
    v = ""; for (i = 1; i <= NF; i++) if ($i == "->") v = $(i - 1)
    if (!inch) { inch = 1; first = $4 " " $5 " " $6 " " $7; nchain++ } else if ($4 != last ".R1") { inter = inter " BREAK" }
    toks = toks " " ((v in c) ? c[v] : v); last = $1; n++; next
}
/^N/ && inch { inter = inter " " $2 }
/^(br|cbr|ret) / { flush() }
function flush() { if (n) printf "%s|%s|%s|%d|%s|%s\n", b, first, last, n, inter, toks; inch = 0; n = 0; toks = ""; inter = ""; pend = "" }
