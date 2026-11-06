# Renumber a view's node (N) and parameter (P) handles sequentially in order of definition (node lines, then block
# headers' parameters), keeping every use consistent.  Blocks must already be in order.
function sub_all(line, letter, map,    out, tok, id) {
    out = ""
    while (match(line, letter "[0-9]+")) {
        tok = substr(line, RSTART, RLENGTH); id = substr(tok, 2)
        # a handle only: not inside a longer word (the character before is not a letter or digit)
        pre = substr(line, RSTART - 1, 1)
        if (RSTART > 1 && pre ~ /[A-Za-z0-9_]/) { out = out substr(line, 1, RSTART + RLENGTH - 1) }
        else { out = out substr(line, 1, RSTART - 1) letter ((id in map) ? map[id] : id) }
        line = substr(line, RSTART + RLENGTH)
    }
    return out line
}
FNR == NR {
    if ($1 ~ /^N[0-9]+$/) nmap[substr($1, 2)] = nn++
    if ($1 ~ /^B[0-9]+\(/) { s = $0; while (match(s, /P[0-9]+:/)) { pmap[substr(s, RSTART + 1, RLENGTH - 2)] = np++; s = substr(s, RSTART + RLENGTH) } }
    next
}
/^T[0-9]+ / || /^\(/ { print; next }
{ print sub_all(sub_all($0, "N", nmap), "P", pmap) }
