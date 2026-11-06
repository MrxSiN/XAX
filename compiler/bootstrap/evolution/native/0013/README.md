# Ledger 0013: compares fused into a branch only when the branch is their only use (ADR-376)

`fuse.awk` rewrites the native view of the x86-64 general backend's `basics` (F893 in the driver and the request,
F205 in the x86-64 general program). It inserts sixteen nodes in B196 (the fusion check): they load the
condition's early use count (`T_EARLY`, every block, terminators included) and AND `count == 1` into the fusion
flag. Node handles from N3191 on move up by 16.
