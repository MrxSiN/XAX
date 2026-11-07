# Derives one of BBC's driver entries from the Windows-hosted entry's view (lazily committed views, ADR of
# integration/bfx/COMPILE.md "Lazily committed driver views"; the single-process compile steps).
#   awk -v VALLOC=<VirtualAlloc CID> -v RESERVE="<site numbers>" [-v ARGFROM=<entity> -v ARGTO=<entity>]
#       [-v ARGCFROM=<entity> -v ARGCTO=<entity>] [-v EXITFROM=<entity> -v EXITTO=<entity>] -f variant.awk <view> <view>
# The VirtualAlloc sites numbered in RESERVE (in order of appearance) reserve with MEM_RESERVE and PAGE_NOACCESS
# (8192, 1) instead of committing (12288, 4): their own type and protection constants change. Calls of ARGFROM call
# ARGTO, and calls of the argument count ARGCFROM call ARGCTO (the step's own count); ExitProcess (EXITFROM)
# becomes EXITTO (SetLastError).  The output is the body from the signature line.
BEGIN { n = split(RESERVE, r, " "); for (i = 1; i <= n; i++) reserve[r[i]] = 1 }
FNR == NR {
    if ($2 == "call.foreign" && $3 == "entity=" VALLOC) { site++; if (site in reserve) { kind[$6] = "type"; kind[$7] = "protect" } }
    next
}
FNR <= 2 { next }
$1 in kind {
    if (kind[$1] == "type" && $3 == "12288") $3 = "8192"; else if (kind[$1] == "protect" && $3 == "4") $3 = "1"
    else { print "variant.awk: unexpected constant at " $1 > "/dev/stderr"; exit 1 }
}
ARGFROM != "" { gsub("entity=" ARGFROM " ", "entity=" ARGTO " ") }
ARGCFROM != "" { gsub("entity=" ARGCFROM " ", "entity=" ARGCTO " ") }
EXITFROM != "" { gsub("entity=" EXITFROM " ", "entity=" EXITTO " ") }
{ print }
