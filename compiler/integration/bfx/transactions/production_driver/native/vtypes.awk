# For each call.foreign of the given entities (prefixes in ENT, comma-separated), print the entity prefix and the
# types (full CIDs) of its operands.
BEGIN { n = split(ENT, e, ","); for (i = 1; i <= n; i++) want[e[i]] = 1 }
FNR == NR { if ($1 ~ /^T[0-9]+$/) T[$1] = ($2 ~ /^bits/ ? $2 : $3); next }
$1 ~ /^B[0-9]+\(/ { s = $0; while (match(s, /P[0-9]+:T[0-9]+/)) { split(substr(s, RSTART, RLENGTH), kv, ":"); ty[kv[1]] = kv[2]; s = substr(s, RSTART + RLENGTH) } next }
$1 ~ /^N[0-9]+$/ {
    split($0, parts, " -> "); split(parts[2], rt, /[ ,]/); k = 0
    for (i = 1; i in rt; i++) if (rt[i] ~ /^T[0-9]+$/) { ty[(k == 0 ? $1 : $1 ".R" k)] = rt[i]; k++ }
    if ($2 == "call.foreign") { ent = substr($3, 8, 8); if (ent in want) { line = ent; for (i = 4; $i != "->"; i++) line = line " " T[ty[$i]]; print line } }
}
