# Expands the block macros of lists.src into view text (hand-written blocks spliced into `_aliases`):
#   @H k e      header of block b<k>: the 17 values `_aliases` carries at B52 (five views, memory, eleven words) and e
#               more words; parameter j of block k is p<k>.<j>
#   @X k        a header with only the five views and memory (the decline block)
#   {V k}       p<k>.0-p<k>.4 (the views); {S k} p<k>.6-p<k>.16 (the carried words)
#   p<k>.<a>-<b> the parameters a..b of block k, comma separated
#   p<k>.<j> -> P(9000000 + 1000k + j), n<k>.<j> -> N(9000000 + 1000k + j), b<k> -> B(5000 + k)
# ../0015/renumber.awk numbers nodes and parameters afterwards; blockrenum.awk numbers blocks.
function P(k, j) { return "P" (9000000 + 1000 * k + j) }
function range(k, a, b,    s, j) { s = P(k, a); for (j = a + 1; j <= b; j++) s = s "," P(k, j); return s }
$1 == "@H" { k = $2; e = $3; s = "B" (5000 + k) "(" P(k, 0) ":T0," P(k, 1) ":T1," P(k, 2) ":T2," P(k, 3) ":T3," P(k, 4) ":T4," P(k, 5) ":T2"
             for (j = 6; j < 17 + e; j++) s = s "," P(k, j) ":T5"; print s ")"; next }
$1 == "@X" { k = $2; print "B" (5000 + k) "(" P(k, 0) ":T0," P(k, 1) ":T1," P(k, 2) ":T2," P(k, 3) ":T3," P(k, 4) ":T4," P(k, 5) ":T2)"; next }
/^#/ || /^$/ { next }
{
    line = $0
    while (match(line, /\{V [0-9]+\}/)) { k = substr(line, RSTART + 3, RLENGTH - 4); line = substr(line, 1, RSTART - 1) range(k, 0, 4) substr(line, RSTART + RLENGTH) }
    while (match(line, /\{S [0-9]+\}/)) { k = substr(line, RSTART + 3, RLENGTH - 4); line = substr(line, 1, RSTART - 1) range(k, 6, 16) substr(line, RSTART + RLENGTH) }
    while (match(line, /p[0-9]+\.[0-9]+-[0-9]+/)) { t = substr(line, RSTART + 1, RLENGTH - 1); split(t, a, /[.-]/); line = substr(line, 1, RSTART - 1) range(a[1], a[2], a[3]) substr(line, RSTART + RLENGTH) }
    while (match(line, /[pn][0-9]+\.[0-9]+/)) { t = substr(line, RSTART, RLENGTH); split(substr(t, 2), a, "."); line = substr(line, 1, RSTART - 1) (substr(t, 1, 1) == "p" ? "P" : "N") (9000000 + 1000 * a[1] + a[2]) substr(line, RSTART + RLENGTH) }
    while (match(line, /b[0-9]+\(/)) { line = substr(line, 1, RSTART - 1) "B" (5000 + substr(line, RSTART + 1, RLENGTH - 2)) "(" substr(line, RSTART + RLENGTH) }
    print line
}
