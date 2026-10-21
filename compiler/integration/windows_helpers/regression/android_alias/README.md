# ARM64 alias-index regression fixtures

dispatch.xax is a private test entry exposing exact production dispatch blocks
and the original parameter fixed point. It takes list/count plus the compiler's
two declared borrowed views. It does not accept an untrusted graph or replace
the public compiler. cases.json freezes 1,091 finite normalized metadata cases.
The independent reference visits the entire CFG in source-block/edge order.

Initialize the documented compiler tables from each fixture and call the entry
in complete, initialized, distinct declared buffers. Require exact returned
status, aliases, per-value stamps, stamp counter and unchanged arena head/end.
The short/reversed/bad-limit modes force scratch failure: production dispatch
must still complete through the original scan. The helper alone must decline
before changing those tables. Random cases use seed 2026102101; a 200-block
reverse dependency chain with two incoming edges forces 200 immediate-update rounds.

Compiler table fields are defined by the canonical general-view/regalloc/ARM64
helpers. G_BCOUNT is blocks; G_BLIST lists block records with dense B_POS,
B_NEDGES and B_EDGES. Each three-word edge is destination block, argument count,
argument-list pointer. G_VPOS encodes block/index for parameters. G_RA supplies
T_ALIAS, T_RW and T_S2 arrays plus R_STAMP initially 100; G_A64 supplies A_ENTRY=0.
Populate the given parameter list and initial aliases/widths; clear T_S2.
The two scalar entry arguments are list pointer and list length. All addresses
above are output-view word indices, not raw external pointers.

Use arena mark 100000 and end mark+2*(blocks+edges). For short reduce end by 1;
for reversed set mark=end+1; for bad_limit set end=HEADER. A successful dispatch
returns 1 and must match expected_aliases, expected_stamps and expected_counter.
The helper's capacity modes instead return NONE without table/counter/head
mutation. Check the arena-end value and an adjacent guard as well.

See ../../alias_index_evidence.json for canonical identities, native authority,
full-driver diagnostics, Android execution and latency measurement scope.
The independent orchestration and DLL bootstrap remain outside the repository.
