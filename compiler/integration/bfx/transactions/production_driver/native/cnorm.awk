# awk -v LIST=<store listing> -f cnorm.awk <view> <view>: the body with type handles and callee handles named by CID
BEGIN { while ((getline l < LIST) > 0) { split(l, a, " "); if (a[1] ~ /^F[0-9]+$/) cid[a[1]] = substr(a[2], 1, 12) } }
FNR == NR { if ($1 ~ /^T[0-9]+$/) name[$1] = ($2 ~ /^bits/ ? $2 : substr($3, 1, 8)); next }
FNR >= 3 && $1 !~ /^T[0-9]+$/ {
    line = $0; out = ""
    while (match(line, /entity=F[0-9]+/)) { h = substr(line, RSTART + 7, RLENGTH - 7); out = out substr(line, 1, RSTART - 1) "entity=" ((h in cid) ? cid[h] : h); line = substr(line, RSTART + RLENGTH) }
    line = out line; out = ""
    while (match(line, /T[0-9]+/)) { tok = substr(line, RSTART, RLENGTH); out = out substr(line, 1, RSTART - 1) ((tok in name) ? name[tok] : tok); line = substr(line, RSTART + RLENGTH) }
    print out line
}
