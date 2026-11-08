# Ledger 0020: `_aliases` (CID adc7c672...) reads each block parameter's incoming arguments from the lists `lists.src`
# builds (-v LISTS=<expanded lists.src>) instead of scanning every edge of the function for every parameter.
# The view's handles are the function's own (the same in every store but for callee handles), so the edit names them.
#   B42  (the first-appearance pass is done)  branches to the lists, which go on to B52 with word 9 = S, word 10 = A.
#   B58  (a parameter's scan starts)          j runs from S[v] to S[v + 1] in B60's block index and block count words.
#   B61  (one more argument)                   the argument is A[j]; on to B71, which canonicalizes it as before.
#   B77  (after the argument)                  j + 1, back to B60.
#   B63-B70 (the edge and argument loops)     removed: nothing reaches them.
# The lists are spliced in after B81 (block numbers are renumbered afterwards).
function block(line) { return match(line, /^B[0-9]+\(/) ? substr(line, 2, RLENGTH - 2) + 0 : -1 }
{ b = block($0); if (b >= 0) cur = b }
cur >= 63 && cur <= 70 { next }
cur == 42 && /^br B52\(/ { sub(/^br B52\(/, "br B5000("); print; next }
cur == 58 && $1 == "N2706" { skip = 1 }
cur == 58 && skip { if ($1 == "N2718") skip = 0; next }
cur == 58 && /^br B60\(/ {
    print "N8000001 add.wrap P900 N2484 -> T5"
    print "@LD N8000002 N8000001 P894 N2703.R1"
    print "N8000003 constant 1 -> T5"
    print "N8000004 add.wrap N8000001 N8000003 -> T5"
    print "@LD N8000005 N8000004 P894 N8000002.R1"
    print "br B60(P891,P892,P893,P894,P895,N8000005.R1,P897,P898,P899,P900,P901,P902,P903,P904,N8000002,N8000005,P907,P908,P909,P910,N2703,N2704,N2705)"
    next
}
cur == 61 && b < 0 { next }
cur == 61 {
    print
    print "N8000011 add.wrap P964 P968 -> T5"
    print "@LD N8000012 N8000011 P957 P959"
    print "N8000013 constant 0 -> T5"
    s = "br B71(P954,P955,P956,P957,P958,N8000012.R1"
    for (j = 960; j <= 976; j++) s = s ",P" j
    print s ",N8000013,N8000013,N8000013,N8000013,N8000013,N8000013,N8000012)"
    next
}
cur == 77 && b < 0 { next }
cur == 77 {
    print
    print "N8000021 constant 1 -> T5"
    print "N8000022 add.wrap P1417 N8000021 -> T5"
    s = "br B60(P1403,P1404,P1405,P1406,P1407,P1408"
    for (j = 1409; j <= 1416; j++) s = s ",P" j
    s = s ",N8000022"
    for (j = 1418; j <= 1425; j++) s = s ",P" j
    print s ")"
    next
}
cur == 81 && /^br B55\(/ { print; while ((getline l < LISTS) > 0) print l; cur = 82; next }
{ print }
