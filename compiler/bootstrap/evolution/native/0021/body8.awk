# Ledger 0021: graph bodies up to 8 MiB.  Rewrites the driver main's view (-v DECODE=F<n> of `decode`, CID cb5dc08f...)
# or `decode`'s own view: the body view type heap_view<4 MiB> (6dff1135...) becomes heap_view<8 MiB> (e9ce063c...,
# supplied by the batch); in main also the three body buffers' sizes and `heap.view` extents (4194304), the body-length
# bounds (4194304) and the body capacity (4194272: 4 MiB less the 32-byte CID after the body), and the calls of
# `decode` name the batch's @decode and its two munmap(ptr, 4194304) declarations (munmap4.hex) name @unmap_a and
# @unmap_b: the same declarations with the length 8388608 and the 8 MiB view type.
/^T[0-9]+ form4 6dff1135b04230868f3f844c607746a224f5f1236a5af8e229839df0ea129f63$/ {
    sub(/6dff1135b04230868f3f844c607746a224f5f1236a5af8e229839df0ea129f63/, "e9ce063c1048ad3a35e03fee6e80d0d2a085a839645965750acdd60792bd4520"); print; next }
/^T[0-9]+ / { print; next }
$2 == "constant" && $3 == "4194304" { $3 = "8388608"; print; next }
$2 == "constant" && $3 == "4194272" { $3 = "8388576"; print; next }
$2 == "heap.view" && /\[4194304,4096\]$/ { sub(/\[4194304,4096\]$/, "[8388608,4096]"); print; next }
$2 == "call.foreign" && $3 == "entity=0253366de8c5496c82392f5a4410764cfe220043577c84f14d171ea691db5ff4" { $3 = "entity=@unmap_a"; print; next }
$2 == "call.foreign" && $3 == "entity=eaf3a7be935628a2ed5c436e846c06dce62ceeae5e8311dfe632d6dd1dc5338d" { $3 = "entity=@unmap_b"; print; next }
DECODE != "" && $2 == "call.direct" && $3 == "entity=" DECODE { $3 = "entity=@decode"; print; next }
{ print }
