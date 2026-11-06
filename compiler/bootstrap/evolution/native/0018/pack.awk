# Ledger 0018: rewrite byte accesses of the x86-64 image buffer into accesses of the packed buffer.
#
#   awk -v SITES="N12:210 N40:=P7 ..." -f pack.awk <view> <view>   (SITE:SLOT reloads the base; SITE:=VALUE uses a value of the block)
#
# Each site is a workspace word load or store (`checked.load.bits.le` / `checked.store.bits.le`, the e.ld/e.st form:
# the word address clamped below 2^28 and scaled by 8) that reads or writes one byte, one per word, of a byte buffer
# whose base the program keeps in register-allocation slot SLOT (`_ra(SLOT)`: the word at
# `ld(GLOBALS + G_RA) + SLOT`, with GLOBALS + G_RA = 29360188).  The old byte address A is recovered from the
# access's clamp chain.  Before the access the site reloads the base R from the slot, then works on word
# R + (A - R) / 8, byte lane (A - R) mod 8, as multiplier M = 256^lane:
#   a store of V  becomes  old = word; word = old - ((old / M) & 255) * M + V * M   (the access node keeps its handle,
#                          so its memory result stays the one later nodes use);
#   a load        becomes  the word load (same handle, so `.R1` stays the memory) and a byte (word / M) & 255 that
#                          every later bare use of the load's value takes instead.
# Fresh nodes are numbered from 80000 up; ../0015/renumber.awk then numbers everything in order of definition.
function opnd(line, k,    a, n) { n = split(line, a, " "); return a[k + 2] }  # k-th operand of a node line
function op(line,    a) { split(line, a, " "); return a[2] }
function fresh() { return "N" n++ }
function emit(s) { print s }
function addr(a,    c1, c2, c3, c4, c5, c6, c7, c8, c9, c10) {
    c1 = fresh(); c2 = fresh(); c3 = fresh(); c4 = fresh(); c5 = fresh(); c6 = fresh(); c7 = fresh(); c8 = fresh(); c9 = fresh(); c10 = fresh()
    emit(c1 " constant 268435456 -> " B64); emit(c2 " int.compare " a " " c1 " -> " B1 " [3]"); emit(c3 " constant 268435455 -> " B64)
    emit(c4 " int.zero.extend " c2 " -> " B64); emit(c5 " sub.wrap " a " " c3 " -> " B64); emit(c6 " mul.wrap " c4 " " c5 " -> " B64)
    emit(c7 " add.wrap " c3 " " c6 " -> " B64); emit(c8 " constant 8 -> " B64); emit(c9 " mul.wrap " c7 " " c8 " -> " B64)
    emit(c10 " int.truncate " c9 " -> " B32)
    return c10
}
function ld(node, a, ptr, mem) { emit(node " checked.load.bits.le " ptr " " addr(a) " " mem " -> " B64 "," MEM " [8,1]") }
function st(node, a, ptr, value, mem) { emit(node " checked.store.bits.le " ptr " " addr(a) " " value " " mem " -> " MEM " [8,1]") }
function konst(v,    c) { c = fresh(); emit(c " constant " v " -> " B64); return c }
function bin(o, x, y,    c) { c = fresh(); emit(c " " o " " x " " y " -> " B64); return c }
# The byte address A of an access: its offset is int.truncate(mul.wrap(add.wrap(c, mul.wrap(zext(cmp), sub.wrap(A, c))), 8)).
function byte_address(site,    t, m, a, m2, s) {
    t = def[opnd(def[site], 2)]; if (op(t) != "int.truncate") fail(site, "offset is not int.truncate")
    m = def[opnd(t, 1)]; if (op(m) != "mul.wrap") fail(site, "no scale")
    a = def[opnd(m, 1)]; if (op(a) != "add.wrap") fail(site, "no clamp add")
    m2 = def[opnd(a, 2)]; if (op(m2) != "mul.wrap") fail(site, "no clamp mul")
    s = def[opnd(m2, 2)]; if (op(s) != "sub.wrap") fail(site, "no clamp sub")
    return opnd(s, 1)
}
function fail(site, why) { printf "pack.awk: %s: %s\n", site, why > "/dev/stderr"; bad = 1; exit 1 }
function rename(line,    out, tok, rest, c) {  # bare uses of a renamed load value (not N<k>.R<j>, not the defining handle)
    out = ""
    while (match(line, /N[0-9]+/)) {
        tok = substr(line, RSTART, RLENGTH); c = substr(line, RSTART + RLENGTH, 1)
        if ((RSTART == 1 || substr(line, RSTART - 1, 1) !~ /[A-Za-z0-9_]/) && c != "." && c !~ /[0-9]/ && (tok in renamed))
            out = out substr(line, 1, RSTART - 1) renamed[tok]
        else out = out substr(line, 1, RSTART + RLENGTH - 1)
        line = substr(line, RSTART + RLENGTH)
    }
    return out line
}
BEGIN {
    n = 80000
    ns = split(SITES, list, " ")
    for (i = 1; i <= ns; i++) { split(list[i], kv, ":"); slot[kv[1]] = kv[2] }
}
FNR == NR {
    if ($1 ~ /^N[0-9]+$/) def[$1] = $0
    if ($1 ~ /^T[0-9]+$/ && $2 == "bits64") B64 = $1
    if ($1 ~ /^T[0-9]+$/ && $2 == "bits1") B1 = $1
    if ($1 ~ /^T[0-9]+$/ && $2 == "bits32") B32 = $1
    if ($2 == "checked.store.bits.le") { MEM = $NF; if (MEM ~ /^\[/) MEM = $(NF - 1) }
    next
}
FNR == 1 { for (s in slot) if (!(s in def)) fail(s, "no such node"); if (B64 == "" || B1 == "" || B32 == "" || MEM == "") fail("types", "missing") }
{
    line = rename($0)
    split(line, f, " ")
    s = f[1]
    if (!(s in slot)) { print line; next }
    kind = op(def[s]); A = byte_address(s); ptr = f[3]
    if (kind == "checked.store.bits.le") { value = f[5]; mem = f[6] }
    else if (kind == "checked.load.bits.le") mem = f[5]
    else fail(s, "not a workspace access")
    # The base: _ra(SLOT), or (SITE:=VALUE) a value of this block that holds it.
    if (slot[s] ~ /^=/) { r = substr(slot[s], 2); rmem = mem }
    else {
        g = fresh(); emit(g " constant 29360188 -> " B64); t = fresh(); ld(t, g, ptr, mem)
        r = fresh(); ld(r, bin("add.wrap", t, konst(slot[s])), ptr, t ".R1"); rmem = r ".R1"
    }
    off = bin("sub.wrap", A, r)
    w = bin("add.wrap", r, bin("udiv", off, konst(8)))
    lane = bin("bit.and", off, konst(7))
    f0 = bin("add.wrap", konst(1), bin("mul.wrap", bin("bit.and", lane, konst(1)), konst(255)))
    f1 = bin("add.wrap", konst(1), bin("mul.wrap", bin("bit.and", bin("udiv", lane, konst(2)), konst(1)), konst(65535)))
    f2 = bin("add.wrap", konst(1), bin("mul.wrap", bin("udiv", lane, konst(4)), konst(4294967295)))
    M = bin("mul.wrap", bin("mul.wrap", f0, f1), f2)
    if (kind == "checked.store.bits.le") {
        o = fresh(); ld(o, w, ptr, rmem)
        cleared = bin("sub.wrap", o, bin("mul.wrap", bin("bit.and", bin("udiv", o, M), konst(255)), M))
        st(s, w, ptr, bin("add.wrap", cleared, bin("mul.wrap", value, M)), o ".R1")
    } else {
        ld(s, w, ptr, rmem)
        renamed[s] = bin("bit.and", bin("udiv", s, M), konst(255))
    }
}
