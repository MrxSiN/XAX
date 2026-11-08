# Number a view's blocks B0, B1, ... in the order their headers appear, keeping every branch target consistent.
FNR == NR { if (match($0, /^B[0-9]+\(/)) map[substr($0, 2, RLENGTH - 2)] = nb++; next }
{
    out = ""; line = $0
    while (match(line, /B[0-9]+\(/)) { id = substr(line, RSTART + 1, RLENGTH - 2); out = out substr(line, 1, RSTART - 1) "B" ((id in map) ? map[id] : id) "("; line = substr(line, RSTART + RLENGTH) }
    print out line
}
