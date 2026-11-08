# Rewrites BBC's importer emitter (@L_51b36b76): -v ADD=<add chain> -v MUL=<mul chain>
#  B12 (the pre-pass step): an ADD (01) or MUL (02) takes two block ids, its handler block and its access block;
#  B161 (ADD) and B162 (MUL): the write chains N13763..N14111 and N14159..N14563 are replaced.
function blk(line) { return match(line, /^B[0-9]+\(/) ? substr(line, 2, RLENGTH - 2) + 0 : -1 }
{ b = blk($0); if (b >= 0) cur = b }
cur == 12 && /^br B4\(/ {
    print "N9500010 constant 1 -> T9"; print "N9500011 int.compare P303 N9500010 -> T10 [1]"
    print "N9500012 constant 2 -> T9"; print "N9500013 int.compare P303 N9500012 -> T10 [1]"
    print "N9500014 bit.or N9500011 N9500013 -> T10"; print "N9500015 int.zero.extend N9500014 -> T9"
    print "N9500016 add.wrap P302 N9500015 -> T9"
    sub(/,P302\)$/, ",N9500016)"); print; next
}
cur == 161 && $1 == "N13763" { print "N9500000 constant 1 -> T9"; print "N9500001 add.wrap P5155 N9500000 -> T9"
    while ((getline l < ADD) > 0) print l; skip = 1; next }
cur == 161 && skip && $1 == "N14111" { skip = 0; next }
cur == 162 && $1 == "N14159" { print "N9500003 constant 1 -> T9"; print "N9500002 add.wrap P5184 N9500003 -> T9"; while ((getline l < MUL) > 0) print l; skip = 1; next }
cur == 162 && skip && $1 == "N14563" { skip = 0; next }
skip { next }
{ print }
