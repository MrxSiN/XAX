# Ledger 0023: the per-view value capacity is a word, not a constant (ADR-391)

Every use of `VCAP` (2^18, the values one function view holds) in the production driver becomes a load of one
workspace word, the capacity word (globals slot 170, word 29360298), and the three backend prologues (x86-64,
AArch64, JVM) store its value, 262,144, before any view work. Nothing else changes: with the word at 262,144 the
compiler behaves as before. This is the first step towards capacities that follow the program (ADR-390).

The sites (`ordered.txt`, 18 functions by CID, callers first so that a later replacement only re-references an earlier
one) come from the generator sources' symbolic `VCAP` uses (`git show 4a5d4b8^:compiler/src/...`):
- the prologues' table allocations (`VCAP + 1`, `VCAP + 2`, `2·VCAP + 1`, `3·VCAP`, ...) and the AArch64 lowering's
  per-function table (`VCAP + 1`);
- the capacity checks (`_new_value`: `G_VCOUNT < VCAP`; `_map`: `G_FKEYN < VCAP`) and `G_FKEYS + VCAP`;
- the range tables' second halves (`G2_CACHE`, `G2_RECOMP`, `G2_COPY` at `v + VCAP`).
Other constants of the same value are other capacities and stay: base64's and UTF-8's 2^18, the `1 << n` select
chains, the semantic index's `MAX_NODES` (2^19), growable buffers with their own 2^18 header.

Tools: `mkcap.sh <store> <CID> <values> <init|-> <batch>` views the function and writes its batch; `cap.awk` replaces
each site constant `k·2^18 + a` with `k·cap + a`, the cap loaded from the capacity word on the workspace memory: it
follows the workspace (view, token) pair through each block (loads, stores, and calls that take both and give them
back), inserts the load where the constant was, and renames the next consumer of the token (every use on that line,
for a conditional branch's two edges); with `init` the entry block first stores the capacity. `ws.awk` expands the
loads and stores with the function's own types. `all.sh` runs the 18 functions in order.

Checks: the result verifies; the compiler built by the previous seed from the new request (A) and the one built by A
(B) are byte-identical, so the new compiler behaves as the old one; B and the previous seed build the same Windows and
Android executables (BBC's mandelbrot, life, factor). The request store equals `compiler_request` of the new driver.
