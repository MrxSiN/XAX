# Native `construct` (work in progress)

`xax-construct-v1` has no native decoder. `xax_construct.construct` exists only as Python
(`compiler/src/xax_construct.py`), so a native host cannot construct a program from a carrier, and a
consumer that needs one either runs Python or ships a second decoder. This directory is the start of a
native decoder that keeps XAX as the only semantic authority.

**Status: steps 1-5c, and the `construct` command (step 6) as its own native program.** What is
established is that the authoring
primitives the self-hosting components use (`Proc` over `GraphBuilder`) reach the *same canonical objects*
as the Python reference, that a program authored that way runs as a native windows-x86_64 host with the
file transport a `construct` command needs, that the host can read a carrier into a tree and write the tree
back out byte for byte, that every named type and derived declaration in both carriers resolves to the
reference object, that the graph, function, module, package, target, profile, trust-policy, build-request
and snapshot objects of both carriers come out byte-identical -- the snapshot's CID *is* the reference
store's root -- and that the program refuses what it does not implement (a platform other than
windows-x86_64, more than one build entry) rather than emit a plausible wrong object. The container is
written by the linked S9 writer, so both stores come out byte-identical to the committed ones, and the
command form writes that store with no Python and no listing path. The general `xaxc` driver does not
dispatch the command yet, and the MCP tool is not wired (M3).

## Why canonical identity is the oracle

A carrier names things; a canonical store has no names, only content addresses. A native decoder is
therefore correct exactly when it builds the same objects. `construct` is deterministic, so the check
is a byte comparison, not an equivalence argument:

| carrier (in XAX-MCP, which produced them with the Python reference) | expected store root | store bytes |
|---|---|---|
| `native/construction_request.json` (957 KB) | `baec162e4bfb177fff18c3d36efdbd6e2ad0a0dec6cb412874fcbd18c12dd442` | 1 020 614 |
| `native/sandbox_request.json` (66 KB) | `7ef7099d5358bf022715faff1ef26387c1486c554ed2f7d9145bd9d8953ef8b6` | 74 434 |

If a native decoder reproduces those two stores byte for byte, it is right about types, operations,
entities, blocks, operands, packages, build requests and resolution. Nothing else has to be trusted.

## Step 1: authoring primitives (done)

`probe_seed.py` authors one function with `Proc` from the semantics a small carrier states, and compares
its CID with the function the reference builds from that carrier:

```powershell
$env:PYTHONPATH = (Resolve-Path compiler/src).Path
python -B compiler/integration/construct/probe_seed.py                          # in-process reference
python -B compiler/integration/construct/probe_seed.py ..\XAX-MCP\native\xax-mcp-seed.xax
```

Both print `f70ba76887b02a4d27e583f490c654035490e4e9ab1c37bb2af49475a052f1d8` and `MATCH`: effects,
`call.foreign` with an entity, constants, terminators, parameter types and the function itself all
land on the reference objects. That covers the per-node half of graph assembly.

## Step 2: the host (done)

`host.py` authors the transport program the decoder will live in and builds it end to end:

```powershell
$env:PYTHONPATH = (Resolve-Path compiler/src).Path
python -B compiler/integration/construct/host.py build/construct_host --check
```

```
entry     ca66c72ad84a126a35b3d922c29b4b61c585260064a163d286409209ffc76c4f
root      205acbdf03070039ea8e42dbaf5c691e6cf457d9cbb8f142b0bf60acd52ed4d3
store     13086 bytes
artifact  3584 bytes
check     PASS exit=0 bytes=1024
```

The contract is `host.exe <carrier path> <store path>`, read the way every Windows host here reads
its command line (`GetCommandLineA` + `lstrcpynA`), one `virtual_alloc` view holding the command-line
copy, both path buffers and the data buffer. Measured on this host: a 255-byte file round-trips
byte-identically, and the two committed carriers pass through at full length (957 089 and 66 KB)
with exit 0.

It fails closed, which is the property the decoder depends on:

| situation | exit |
|---|---|
| input does not open | 2 |
| output does not open | 3 |
| input empty or unreadable | 4 |
| input fills the 4 MiB data region | 5 |
| short write | 6 |
| anything after the store path (quoting included) | 7 |

The view is one linear token: every path hands it back through `win32.virtual_free_view` before
`win32.exit_process`, and a failed step records a code that the single exit returns. Quoted paths
are deliberately not interpreted -- the quoting characters would reach `_open`, which fails, and the
process exits non-zero instead of guessing.

## Step 3: the carrier reader (done, bounded)

`reader.py` replaces the copy with a parse. It builds a tree in the same view -- kind, byte span,
first child, next sibling, one node per value and one per object member -- and then walks the tree
back out in canonical form. The command contract is unchanged (`reader.exe <carrier> <output>`), so
step 4 can consume the tree without a second transport.

```powershell
$env:PYTHONPATH = (Resolve-Path compiler/src).Path
python -B compiler/integration/construct/reader.py build/construct_reader --check `
    ..\XAX-MCP\native\sandbox_request.json ..\XAX-MCP\native\construction_request.json
```

```
entry     6539e017fad3bd82a0582a4143fbcfd1e1985fd2237ed18e95f785ece34680f0
root      a87c6b33e690e7fdada5e67deb338b2c655bd37cb3185fdf99ea61db86a75d17
store     280467 bytes
artifact  80384 bytes
corpus    15 round-trips, 22 refusals, empty PASS
carrier   sandbox_request.json          66322 bytes exit=0 MATCH
carrier   construction_request.json    957089 bytes exit=0 MATCH
```

The output is `json.dumps(json.loads(carrier), separators=(",", ":"))` byte for byte. Both committed
carriers are already in that canonical form (member order is the sorted order), so the comparison also
proves that no input byte was dropped, reordered or invented. Measured on this host: 32 ms for the
957 KB carrier, 19 ms for the 66 KB one, and two consecutive builds produce the same root, store and
artifact.

The reader refuses rather than approximates, and every refusal is a code:

| input | exit |
|---|---|
| fraction or exponent (`1.5`, `1e3`) | 8 |
| bare sign, leading zero (`-`, `01`) | 8 |
| a backslash escape, a raw byte >= 0x80, a control byte | 8 |
| a malformed document (trailing comma, missing colon, truncated, trailing data) | 8 |
| deeper than 32 frames or more than 262 144 nodes | 9 |

Inputs the carriers do not contain today -- `\uXXXX` escapes, UTF-8, floats, and *unsorted* member
order -- are exactly the step 3b list. They are rejected here, not silently approximated: a carrier
this reader accepts is one it understood completely. The tree it builds is the whole carrier; nothing
is skipped on the way to emission.

## Step 4: type and entity resolution (done)

`resolve.py` walks the tree step 3 built and turns every type and entity *name* into the canonical
object the reference builds, emitting one line per occurrence in the native writer's batch shape:

```
<kind> <schema> <refs|-> <body hex>
```

`-` means no references; otherwise the space-separated reference CIDs. That is exactly the input
`xax_selfhost_writer` expects, so step 5 hands the listing over instead of re-encoding objects.

Names resolve the way `xax_construct._Builder.type` does: a carrier alias first, then `b<N>`, then a
`win32.` platform name. The platform namespace is embedded as authoring data -- the 21 declarations of
`xax_platform.win32_kernel32_api()` and `win32_stdio_api()` are captured at build time as framed entries
(2 880 bytes) and stored in the same view at `NS = 0xE00000`, so a `win32.<name>` spec is a table
lookup, not a table in Python at run time. Aliases resolve in a bounded loop (8 hops) so a cycle is a
refusal, not a build-time recursion.

```powershell
$env:PYTHONPATH = (Resolve-Path compiler/src).Path
python -B compiler/integration/construct/resolve.py build/construct_resolve --check `
    ..\XAX-MCP\native\sandbox_request.json ..\XAX-MCP\native\construction_request.json
```

```
entry     31f6fd4645420de285650b312446b8bba30a9a5b229e7fcbb32fedad61f40603
entry fn  268d040bcef7a3e5d0df98c4fd4ebff23fb2809a3e2a4058116d04137e5d6a3c
store     2121837 bytes
artifact  313344 bytes
namespace 2880 bytes, 21 entries
carrier   sandbox_request.json       exit=0 lines=2473 resolved=2460 deferred=13 MATCH
carrier   construction_request.json  exit=0 lines=31325 resolved=30925 deferred=400 MATCH
```

The check decodes each produced line back into a `SemanticObject` and compares its CID with the
reference object for that occurrence, so the claim is object identity, not textual similarity. Both
carriers run inside the one program, and the reader's identity is unchanged by the seam that exposes
the tree (`6539e017…`, root `a87c6b33…`, 280 467 B, 80 384 B). Measured on this host: 17 ms for the
66 KB carrier, 29 ms for the 957 KB one; two consecutive builds produce the same store
(`8fd859243bc9a747`, 2 121 837 B).

```powershell
resolve.exe <carrier> <listing>
```

| situation | exit |
|---|---|
| unknown alias, unknown `win32.` name, alias chain longer than 8, `b` width 0 or above 64, view extent above 2^28 | 11 |
| unknown entity name, a type name used as an entity, malformed `win32.import` / `win32.virtual_free_view` | 12 |
| a graph beyond the staging caps above, an unknown operation or type name inside a graph, a declaration body past its region | 13 |

## Step 4b: derived declarations (done)

A declaration is the one object whose body contains *other objects' identities*: the imported
signature's type CIDs and the deallocator contract. The program therefore hashes inside itself.

`hash_span_function` in `xax_selfhost_blake3.py` is the single-view span hash. `hash_function` lends the
caller's memory as two views, and a program that owns its memory cannot do that: one allocation yields
one live effect token and a second `heap_view` consumes the first view's token
(`XAX.MEMORY.EFFECT_LINEAR`). The span variant takes one view triple, hashes
`input[base : base + length]`, and addresses the chaining-value stack and digest at a fixed distance
past the view base, sharing that one token. `probe_hash.py` builds a program that hashes six inputs
(empty, 3 B, one block, two blocks, two chunks, ten chunks) and compares every digest word with the
Python reference: exit 0, 6 of 6 match.

The resolver stages each object's canonical content -- `blake3("XAX-SEM-1", uleb(kind), uleb(schema),
uleb(refcount), refs, uleb(bodylen), body)` -- at `CANON = 0xEB0000`, points the hash at
`0xEE2000` (2 048 bytes, digest at `+1 728`) and assembles declaration bodies at `DBODY = 0xEE4000`.
The canonical region is `0x31000` bytes because the hash reads the span it hashes: the scratch must sit
past the widest object (a reference table plus a body), never inside it -- a lesson step 5a paid for.
Each type spec in a signature is resolved by the same code as a top-level type, hashed, and its digest
appended, so the declaration cannot disagree with the type lines in the same listing.
`win32.virtual_free_view` also embeds the view type built from the carrier's extent, which is why the
view object's body is assembled here rather than looked up.

A declaration body is ``uleb(len(identity)) + identity`` (the TARGET encoding), and the identity starts
with the 19 raw bytes `foreign-function-v1` -- not a length-prefixed string -- followed by length-prefixed
ABI, library, symbol, input CIDs, output CIDs, then the optional deallocator clause
`02 00 03` (`uleb(tag) uleb(pointer_input) uleb(token_input)`).

Only the function placeholders remain deferred, and they are counted, never guessed:

| deferred name | sandbox | construction | needs |
|---|---|---|---|
| `{"fn": …}` | 13 | 400 | graph assembly (step 5) |

The declaration lines that used to be deferred now match: 61 sandbox and 48 construction
`win32.import` declarations, plus 4 and 6 `win32.virtual_free_view` declarations.

## Step 5a: graph and function objects (done)

Step 4 resolved names; step 5a encodes the objects that hold them. One carrier function becomes its
constants, its graph and its function object:

- a constant is `5 1 <type CID> 00 <uleb width> <value>`: the type is resolved like any other type spec,
  hashed, and the body is the width and the little-endian value the carrier spelled;
- a graph is `7 1 <refs> <body>`: `uleb(block count), uleb(entry)`, then per block
  `uleb(parameter count) + positions, uleb(node count)`, then per node `uleb(op), [uleb(entity)],
  uleb(operand count) + operand references, uleb(result count) + result positions,
  [uleb(attribute count) + values]`, and finally the terminator `uleb(kind)` -- BRANCH 1, CBRANCH 2,
  RETURN 3;
- a function is `3 1 <graph CID, parameter CIDs, return CIDs> <graph rank, parameter ranks, return ranks>`.

An operand reference is `uleb(tag), uleb(block), uleb(index)` plus `uleb(result)` when the tag selects a
node result: operands point at positions, never at CIDs, which is why an object's reference table has to
be complete before its body is written.

One view holds everything, so a function is encoded without a second allocation: pass one resolves every
operand, constant and type and logs each reference *occurrence* in body order (`OCC`); the distinct
references are deduplicated in first-occurrence order, selection-sorted by a 32-byte compare, and every
position is read back through `REF_POS[slot]`. Pass two replays the same walk to write the body, so the
two passes have to agree on every numbering decision -- including where an inline constant is inserted.

```powershell
$env:PYTHONPATH = (Resolve-Path compiler/src).Path
python -B compiler/integration/construct/resolve.py build/construct_resolve --check `
    ..\XAX-MCP\native\sandbox_request.json ..\XAX-MCP\native\construction_request.json
```

```
entry     4426818db95e2ad3997f4ec32b5f06d8b7998ba21eee698277f5228d1dc295b2
entry fn  3d3a391c22e1baf03a0a037e33ce7689df0aaceea0f5e65e1bbdf0677a2bf564
store     19085525 bytes
artifact  2870784 bytes
namespace 2880 bytes, 21 entries
carrier   sandbox_request.json       exit=0 lines=3066 resolved=3053 deferred=13 MATCH
store     sandbox_request.json          74434 bytes /    74434 root 7ef7099d5358bf02 MATCH
carrier   construction_request.json  exit=0 lines=41325 resolved=40925 deferred=400 MATCH
store     construction_request.json   1020614 bytes /  1020614 root baec162e4bfb177f MATCH
```

Every produced line is decoded back into a `SemanticObject` and compared with the reference object for
that occurrence, so both listings are byte-identical object by object: 3 066 and 41 325 lines,
`sha256 35e23efa…` and `fef6f4ea…`. The 13 and 400 `?` lines are the `{"fn": …}` occurrences the
reference also defers at that point in its own walk; the graph pass resolves them from the name table
filled as each function is registered, which is why the walk visits functions in carrier order. The
program now also emits the step-5b objects and the step-5c snapshot, so these are its identities; the 5a
claim is the first 3 059 and 41 318 lines, which are unchanged. The store lines are the container half:
the bytes the S9 writer returns are compared with `xax_construct.construct(...).reader.canonical_bytes()`,
so the two committed stores are reproduced byte for byte, not just their roots.

Measured on this host, one program for both carriers (the machine is shared, so the timing rows varied by
nearly a factor of two between runs; the byte rows did not):

| measurement | value |
|---|---|
| `resolve_packages` / `snapshot_store` / `build` (unverified harness, 5a/5b program) | 185.1 s / 22.8 s / 876.3 s |
| verifier pass (separate gate, 5a/5b program) | 160.1 s, 1 305 objects |
| `build_main` / verifier pass (5c program, separate gate) | 41.8 s / 392.0 s |
| store / artifact (5c program) | 19 085 525 B / 2 870 784 B |
| widest graph body (sandbox, construction) | 16 141 B / 56 123 B (cap 131 072) |
| widest reference table | 231 / 1 391 entries (cap 2 048) |
| widest canonical object | 23 549 B / 100 651 B (region 200 704) |

The caps are enforced, not assumed: a body above `0x20000`, a reference table above 2 048 entries, a
canonical object above `0x31000`, more than 16 parameters or returns, more than 8 192 nodes or 512 blocks
in one function, or a name table past the end of the view is a refusal (`BAD_GRAPH`, exit 13) rather than
a silent overwrite of the next region.

Six defects the byte oracle caught, each of which produced a *plausible* listing:

| symptom | cause |
|---|---|
| every operand name lookup missed | the operation table steps by `3 + the entry's length byte`, not by the lookup name's length |
| constants had the wrong type | an inline constant hashes its resolved type *before* its value, and the value widens into the shift register the writer reads |
| one function stalled the walk forever | a body called by an outer `each` reused that loop's cursor register |
| every function name was zero bytes | `register_function` read the name with a base-relative load although `start()` is input-relative |
| declarations were correct lines with wrong CIDs | the hash covered only the length prefix left at `CANON`; the identity was at `DBODY` and had to be staged canonically first |
| one graph had a wrong CID while its line was right | that 16 141-byte body overran the 8 KiB gap into the hash's own scratch; the region now lies past the widest object and `hash_canonical` refuses a wider span |

The staging layout is asserted at authoring time (`CANON_CAP >= REF_CAP * 32 + BODY_CAP + 16`, no region
overlap, the hash scratch past the canonical span), so a future cap change cannot silently reintroduce
the last defect.

Two narrowly scoped, semantics-preserving changes in `compiler/src` were needed to build a program this
size at all: `xax_prefetch` computes a block's cycle set lazily instead of for every block on every
visit, and `pointer_extent_from_graph` binary-searches a sorted pointer table instead of copying it on
every call. Neither changes an emitted object; together they take the build from not finishing to about ten
minutes on this host.

A per-function split (`walk` / `graph_collect` / `graph_write`, with the type table shared through the
environment) was designed and then deprioritised: with those two changes the monolithic program builds
and verifies, so the split would buy build time at the cost of a second parameter-passing convention. It
remains the first move if the build cost becomes a problem again.

`TRAP` terminators and `CALL_GROUP_MEMBER` are not encoded yet; neither carrier uses them, and the walk
refuses what it does not recognise.

## Step 5b: module, package and build request (done, two limits)

`xax_construct.construct` appends six objects after the functions, in this order: the platform target, the
module, the package, the hermetic profile, the trust policy and the build request. None is a graph, so
they reuse the function pass's staging: references are collected into `REFS` through `ref_slot`, sorted
once by `sort_refs`, and every rank in a body is read back with `rank_of` -- the same table the graph
encoder uses, so a body's ranks cannot disagree with its own reference table. `emit_staged(kind, schema)`
then canonicalises, hashes and prints the line, and every object that is referenced copies its CID from
`CUR` into a slot of its own (`TARGET_CID`, `MODULE_CID`, `PACKAGE_CID`, `PROFILE_CID`, `POLICY_CID`):
`select_function` became `lookup_function` (find the name, leave its CID in `CUR`) plus a `ref_collect`
call, so the same lookup serves `{"fn": ...}` operands and the package's entry.

| object | encoding |
|---|---|
| `Kind.TARGET` (6) | the fixed platform target, a 129-byte literal with no references: not carrier data, and the same bytes for every carrier this program accepts |
| `Kind.MODULE` (2) | references = every built function CID (sorted, deduplicated); body = `uleb(count)` followed by the ranks `0..n-1` |
| `Kind.PACKAGE` (9) | `uleb(len(name)) + name`, `uleb(1)` module and its rank, `uleb(0)` dependencies, `uleb(1)` entry with `uleb(len(entry)) + entry + uleb(rank)`, then `0` features, `0` configuration and `0` capabilities |
| `Kind.BUILD` profile (10) | `01 01 00 01 00` -- `PROFILE`, `HERMETIC_REPRODUCIBLE`, no optimisation, verification, no grants |
| `Kind.BUILD` trust policy (10) | `04 00 00 00 00` -- `TRUST_POLICY`, no algorithms, no signers |
| `Kind.BUILD` request (10) | `uleb(2)`, package rank, `uleb(len(release)) + release`, target rank, profile rank, `0` features, `0` configuration, then `uleb(1) uleb(1)` for one `NATIVE_IMAGE` artifact |

Measured on the sandbox carrier, those bodies are `08 00 01 02 03 04 05 06 07` (eight functions, ranks in
order), `0f "xax_mcp_sandbox" 01 00 00 01 03 "app" 01 00 00 00`, `01 01 00 01 00`, `04 00 00 00 00` and
`02 00 03 "app" 01 02 00 00 01 01` (package rank 0, target rank 1, profile rank 2). The construction
carrier's module body is 216 bytes -- `uleb(171)`, then 128 one-byte ranks and 43 two-byte ranks -- and its
package and request are 27 and 12 bytes; the six lines are the same six encodings, not carrier-specific
arithmetic. Six lines were appended to the oracle in the program's order, and all six CIDs were checked
against `xax_construct.construct` before the program was written: target `99480deb...`, module
`b363e174...`, package `396e6697...`, profile `9e3dd6a9...`, policy `15264515...`, request `6fbb92a5...`.
Both carriers now match end to end: 3 066 lines (13 deferred) and 41 325 lines (400 deferred).

Three defects the gate caught, each of which produced a plausible listing:

| symptom | cause |
|---|---|
| the module was never reached | `span_eq` returns `bits<1>`; comparing it with a `b32` zero breaks `INT-COMPARE-CONTRACT`, so the platform check has to widen the flag first |
| every body byte was refused | `INT_TRUNCATE` must *narrow*: a `b8` literal truncated to `b8` is rejected, so `gb_put` takes a `b32` and the literal bytes are authored as `b32` |
| exactly three lines had kind `1` (profile, policy, request) | `emit_sorted_object` printed `48 + kind`, which is only right for single-digit kinds; `BUILD` is 10, so the digit was written as `:`-minus-one. Target, module and package were already byte-correct, which located the defect in the printer, not the encoders |

Two limits are refusals, not approximations:

- **`windows-x86_64` only.** The target is authoring data embedded like the namespace blob, so a carrier
  whose `platform` is anything else is refused (`BAD_GRAPH`, exit 13) instead of being labelled with the
  wrong target. Both carriers are windows-x86_64.
- **Exactly one build entry.** The reference sorts entry names and accepts any number; sorting
  variable-length name spans is not implemented, so a second entry is refused rather than emitted with
  the wrong rank order. Both carriers have one (`app` -> `main`).

`TRAP` terminators and `CALL_GROUP_MEMBER` remain unencoded for the same reason as before: no carrier
uses them, and the walk refuses what it does not recognise.

## Step 5c: the root and the store container (done)

A canonical store's root is the snapshot object: `resolve_packages` selects the request's package and its
dependency closure and returns the `Kind.BUILD` object with form `SNAPSHOT`. The program now emits it as
the seventh appended object:

```
uleb(SNAPSHOT=3), uleb(rank(request)), uleb(len) + resolver identity, uleb(rank(policy)),
uleb(packages) + their ranks, uleb(signatures) + their ranks, uleb(digests) + the 32-byte digests
```

The references are the sorted, deduplicated CIDs of the request, the policy and the selected packages; the
identity is `xax-construct-v1`; neither carrier has dependencies, signatures or external digests. The last
produced line's CID is then the store root itself -- `7ef7099d…f8b6` for the sandbox carrier and
`baec162e…d442` for the construction carrier, the two roots the reference stores have. That is checked
twice: the line is decoded and compared with `resolve_packages`'s own object, and that object is the root
`xax_construct.construct` returns (`store.root_cid`), confirmed separately on both carriers.

The container is written by the S9 writer, linked into the resolver as a component and called directly,
so there is one container implementation rather than two. The walk stages every object it emits as a
writer batch record (`kind`, `schema`, reference count, body length, CID, references, body) in append
order, deduplicated by CID through an open-addressing index; the record area starts after the three header
words and the root CID, at 56 bytes. The snapshot's references then close the reachable set -- the store is
that closure, not the listing: 2 of the sandbox carrier's 272 distinct line CIDs and 1 of the construction
carrier's 3 413 are unreachable aliases, while the sandbox store holds one object with no line at all, the
inline `b16` type. The marked records are compacted forward in append order behind the header (`count`,
`0` non-semantic records, `total` length, root CID), and the buffer the writer returns is written to the
third argv path. The resolver borrows one 32 MiB batch view, one 64 MiB output view and the hash's 2 KiB
scratch view; all three are released before the program returns.

Both stores are byte-identical to the committed ones:

| carrier | store bytes | SHA-256 | root |
|---|---|---|---|
| `sandbox_request.json` | 74 434 | `588f57c0fa69eb175b6e06e88c73977292d42c06dfc5b814ec48cc5710bab2b8` | `7ef7099d5358bf022715faff1ef26387c1486c554ed2f7d9145bd9d8953ef8b6` |
| `construction_request.json` | 1 020 614 | `bbe28c1e5568abf40cb2d38a354f4dcbaae09b231abeb04f87674d5f1a70e25f` | `baec162e4bfb177fff18c3d36efdbd6e2ad0a0dec6cb412874fcbd18c12dd442` |

The comparison is against `xax_construct.construct(carrier).reader.canonical_bytes()`, which was checked
separately to equal the committed `native/xax-mcp-*.xax` files byte for byte, so the oracle is the
committed store itself and not a looser re-encoding of it.

Four defects on the way to that run are worth recording, because each one produced a store that looked
plausible:

- the batch's first record was written at offset 0 and overwrote the header the writer reads first, so the
  sandbox listing matched while the store was refused;
- `find_record` returns a position in the sorted CID index, and that position was used as the object's own
  index: the "closure" then marked and expanded whichever objects happened to sit at those positions. The
  sandbox store had 54 objects at depths 0 and 2..5 with none at depth 1, which no walk from the root can
  produce;
- the store registers were first placed at `0x960000`, inside the parser's `START` array, which corrupted
  the walk on the construction carrier (it crashed rather than refused);
- three verifier-level defects in the linked call: a lent view rebound to the caller's pointer type, the
  lent views never released at return, and `virtual_free_view` needing one declaration per (pointer, view)
  pair rather than one per call.

Store refusals are exit codes that name the stage: 20 (more distinct objects than the 8 192-entry index),
21 (batch capacity), 23 (a reference with no staged object), and `0x100 + status * 0x40 + reason` for a
writer that rejects or declines the batch.

## Step 6: the `construct` command (done as a command; driver dispatch left)

`construct <carrier> <store>` is the same walk with a different transport, not a second decoder: the
listing writer is compiled out (`walk(listing=False)`), argv[2] is the store, and the bytes the S9 writer
returns are written there. The command is the program's own name rather than a word in argv[1]; the store
is the only output, so no listing path is asked for. The check runs it on both carriers and compares the
store bytes with `xax_construct.construct(...).reader.canonical_bytes()` -- the committed stores again:

```
entry     096ef1b4a7b1233eed01679efce9e907cb42f6f7b2b41e3532eebf7a571d3cfa
entry fn  3d3a391c22e1baf03a0a037e33ce7689df0aaceea0f5e65e1bbdf0677a2bf564
store     19045135 bytes
artifact  2852352 bytes
command   sandbox_request.json       exit=0 store=   74434/   74434 sha256=588f57c0fa69eb17 root 7ef7099d5358bf02 MATCH
command   construction_request.json  exit=0 store= 1020614/ 1020614 sha256=bbe28c1e5568abf4 root baec162e4bfb177f MATCH
```

The command build is smaller than the check build (19 045 135 vs 19 085 525 store bytes, 2 852 352 vs
2 870 784 artifact bytes) because the listing writer's blocks are never emitted when no line is written.

What is not done: the general driver (`compiler/src/xax_selfhost_driver.py`, `COMMANDS`) does not dispatch
`construct`, so the command is a separate native program for now; the driver has not been re-derived for
Windows and there is no `DRIVER.md` for it. Those are the remaining parts of the plan's step 6. The command
itself is what a host -- and the MCP adapter -- needs.


## The plan

| Step | Content | Oracle |
|---|---|---|
| 1 | authoring primitives (this check) | canonical CID match |
| 2 | native host: argv, file read/write, exit (the pattern of `hash_host.xax`) | copies bytes byte-exactly, exits 0; refuses with 2-7 |
| 3 | carrier JSON reader: objects, arrays, strings, integers; unmeasured cases refused | `json.dumps(json.loads(x), sort_keys=True, separators=(",",":"))` byte-identical on both carriers |
| 3b | `\uXXXX` escapes, UTF-8, floats, member-order sort for unsorted carriers | a corpus that exercises each, against `json.dumps` |
| 4 | types, aliases, view specs and `win32.` platform lookups against the embedded namespace | every produced object's CID equals the reference object's |
| 4b | derived declarations (`win32.import`, `win32.virtual_free_view`) with type CIDs hashed in-program | the 109 import and 10 view-free declarations the carriers use, byte-exact (done) |
| 5a | constant, graph and function objects: two passes per function, a reference table and positions, terminators | both carriers' listings byte-exact (done) |
| 5b | module, package, profile, policy, target and build-request objects | both carriers' six appended lines byte-exact (done; the snapshot moves to 5c) |
| 5c | snapshot object, which is the store's root, and the store container from the listing (`xax_selfhost_writer` reuse) | the root CIDs match and the two stores are byte-exact (done) |
| 6 | `construct <carrier> <store>` (done as a separate native program); driver dispatch, re-derived Windows driver and `DRIVER.md` (left) | the command reproduces both committed stores byte-exactly (done); command table and native checks (left) |

Steps 5b and 5c are where the existing `xax_selfhost_resolve` and `xax_selfhost_writer` components are
reused rather than reimplemented.

## Boundaries

- No Python at run time. Python remains build tooling here (it authors the component), exactly as
  every `compiler/src/xax_selfhost_*.py` module already does.
- No second canonical graph store and no second semantics: a native decoder that disagrees with the
  reference is a bug, decided by the byte comparison above.
- Floats, non-ASCII input and carrier features not yet implemented are **rejected with a diagnostic**,
  never silently approximated.
- The Windows driver store stays untouched until step 5 passes; a wrong decoder must not be able to
  reach the program that builds every artifact.
