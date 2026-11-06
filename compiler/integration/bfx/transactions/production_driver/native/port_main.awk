# Rewrites the production driver's entry view (Linux host calls) into BBC's Windows-hosted entry view.
#   awk -v MAP=<map file> -f port_main.awk <view> <view>  >  the function's view from its signature line
# MAP lines: <old foreign entity CID> <new entity> <kind>; kinds: mmap, munmap, open, read, write, argcopy, swap, call.
# mmap(len, mem) becomes VirtualAlloc(0, len, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE, mem). munmap(ptr, view, mem)
# becomes VirtualFree(ptr, 0, MEM_RELEASE, view, mem), its bits32 result widened. open, read, write and argcopy become
# calls of BBC's adapters, which also take and give back the view token of the memory they touch; later uses of that
# token in the block take the returned one. swap keeps the operands and results; call does too, calling a function.
function form(t) { return (t in tform) ? tform[t] : 0 }
function remap(v,    base, r, k) {
    if (v in tokmap) return tokmap[v]
    if (v !~ /^N[0-9]+/) return v
    base = v; r = 0
    if (index(v, ".R")) { split(v, q, ".R"); base = q[1]; r = q[2] + 0 }
    k = substr(base, 2)
    if (!(k in nid)) return v
    if (kind[k] == "open" || kind[k] == "read" || kind[k] == "write") return "N" nid[k] (r == 0 ? ".R4" : (r == 1 ? ".R3" : ".R2"))
    if (kind[k] == "argcopy") return "N" nid[k] (r == 0 ? ".R3" : ".R2")
    if (kind[k] == "munmap") return (r == 0 ? "N" zx[k] : "N" nid[k] ".R1")
    return "N" nid[k] (r > 0 ? ".R" r : "")
}
function rewrite_list(s,    out, tok) {   # values separated by commas or spaces, inside a terminator
    out = ""
    while (match(s, /[NP][0-9]+(\.R[0-9]+)?/)) {
        tok = substr(s, RSTART, RLENGTH)
        out = out substr(s, 1, RSTART - 1) remap(tok)
        s = substr(s, RSTART + RLENGTH)
    }
    return out s
}
BEGIN { while ((getline line < MAP) > 0) { split(line, m, " "); newent[m[1]] = m[2]; mkind[m[1]] = m[3] } }
# pass 1: types, kinds and the new node numbers
FNR == NR {
    if ($1 ~ /^T[0-9]+$/) { tform[$1] = ($2 ~ /^bits/ ? 1 : substr($2, 5) + 0); if ($3 ~ /^2b2704e5/) MEM = $1; if ($2 == "bits64") B64 = $1; if ($2 == "bits32") B32 = $1 }
    if ($1 ~ /^N[0-9]+$/) {
        k = substr($1, 2); kk = ""
        if ($2 == "call.foreign") { e = substr($3, 8); if (e in mkind) kk = mkind[e] }
        kind[k] = kk
        if (kk == "mmap") { next_id += 3 }
        if (kk == "munmap") { next_id += 2 }
        nid[k] = next_id++
        if (kk == "munmap") zx[k] = next_id++
    }
    next
}
FNR <= 2 { next }
FNR == 3 { print; next }
/^T[0-9]+ / { print; next }
$1 ~ /^B[0-9]+\(/ {
    print
    # values are named once per function: the tables hold across blocks
    s = $0; n = 0
    while (match(s, /P[0-9]+:T[0-9]+/)) { split(substr(s, RSTART, RLENGTH), kv, ":"); n++; pv[n] = kv[1]; pt[n] = kv[2]; ty[kv[1]] = kv[2]; s = substr(s, RSTART + RLENGTH) }
    for (i = 3; i <= n; i++) if (pt[i] == MEM && form(pt[i - 1]) == 4 && form(pt[i - 2]) == 2) assoc[pv[i]] = pv[i - 1]
    next
}
$1 ~ /^N[0-9]+$/ {
    k = substr($1, 2)
    split($0, halves, " -> "); head = halves[1]; tail = halves[2]
    nf = split(head, f, " "); split(tail, tl, " "); nr = split(tl[1], rt, ",")
    first = 3; if (f[2] == "constant" || index(f[3], "entity=")) first = 4
    no = 0; for (i = first; i <= nf; i++) { no++; op[no] = f[i] }
    # memory results: a ptr/view/memory triple names its view; otherwise the j-th memory result keeps the j-th memory operand's view
    nm = 0; for (i = 1; i <= no; i++) if (ty[op[i]] == MEM) { nm++; mo[nm] = op[i] }
    j = 0
    for (i = 1; i <= nr; i++) {
        name = (i == 1 ? $1 : $1 ".R" (i - 1)); ty[name] = rt[i]
        if (rt[i] == MEM) {
            j++
            if (i >= 3 && form(rt[i - 1]) == 4 && form(rt[i - 2]) == 2) assoc[name] = $1 ".R" (i - 2)
            else if (j <= nm && (mo[j] in assoc)) assoc[name] = assoc[mo[j]]
        }
    }
    kk = kind[k]; id = "N" nid[k]
    for (i = 1; i <= no; i++) nop[i] = remap(op[i])
    if (kk == "") {
        line = id " " f[2]; if (first == 4) line = line " " f[3]
        for (i = 1; i <= no; i++) line = line " " nop[i]
        print line " -> " tail
        next
    }
    e = substr(f[3], 8); ent = "entity=" newent[e]
    if (kk == "mmap") {
        c = nid[k] - 3
        print "N" c " constant 0 -> " B64; print "N" (c + 1) " constant 12288 -> " B32; print "N" (c + 2) " constant 4 -> " B32
        print id " call.foreign " ent " N" c " " nop[1] " N" (c + 1) " N" (c + 2) " " nop[2] " -> " tail
    } else if (kk == "munmap") {
        c = nid[k] - 2
        print "N" c " constant 0 -> " B64; print "N" (c + 1) " constant 32768 -> " B32
        print id " call.foreign " ent " " nop[1] " N" c " N" (c + 1) " " nop[2] " " nop[3] " -> " B32 "," MEM
        print "N" zx[k] " int.zero.extend " id " -> " B64
    } else if (kk == "swap" || kk == "call") {
        line = id " " (kk == "call" ? "call.direct" : f[2]) " " ent; for (i = 1; i <= no; i++) line = line " " nop[i]
        print line " -> " tail
    } else {
        memop = (kk == "open" ? op[6] : (kk == "argcopy" ? op[3] : op[5]))
        if (!(memop in assoc)) { print "port_main.awk: no view for " memop " at " $1 > "/dev/stderr"; exit 1 }
        told = assoc[memop]; tnew = remap(told)
        ptrt = ty[op[2]]; viewt = ty[told]
        if (kk == "open") line = id " call.direct " ent " " nop[1] " " nop[2] " " tnew " " nop[6] " " nop[3] " " nop[4] " " nop[5] " -> " ptrt "," viewt "," MEM "," rt[2] "," rt[1]
        else if (kk == "argcopy") line = id " call.direct " ent " " nop[1] " " nop[2] " " tnew " " nop[3] " -> " ptrt "," viewt "," MEM "," rt[1]
        else line = id " call.direct " ent " " nop[1] " " nop[2] " " tnew " " nop[5] " " nop[3] " " nop[4] " -> " ptrt "," viewt "," MEM "," rt[2] "," rt[1]
        print line
        tokmap[told] = id ".R1"
    }
    next
}
{ print rewrite_list($0) }
