# Native `construct` (work in progress)

`xax-construct-v1` has no native decoder. `xax_construct.construct` exists only as Python
(`compiler/src/xax_construct.py`), so a native host cannot construct a program from a carrier, and a
consumer that needs one either runs Python or ships a second decoder. This directory is the start of a
native decoder that keeps XAX as the only semantic authority.

**Status: steps 1-4 of the plan below.** What is established is that the authoring primitives the
self-hosting components use (`Proc` over `GraphBuilder`) reach the *same canonical objects* as the
Python reference, that a program authored that way runs as a native windows-x86_64 host with the file
transport a `construct` command needs, that the host can read a carrier into a tree and write the tree
back out byte for byte, and that every named type in both carriers resolves to the reference object.
Derived declarations, assembly and the driver command are the remaining steps.

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

## Step 4: type and entity resolution (done for named types)

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
entry     a7c0def59d84edb439c94381616f3c29fbb68e23b24b505016d0ee54cd3973d4
entry fn  7372266ec2e28a5862849f7836030ae2d4224573498d8e8e103b8cf880c94b1a
store     1531340 bytes
artifact  194560 bytes
namespace 2880 bytes, 21 entries
carrier   sandbox_request.json       exit=0 lines=2473 resolved=2395 deferred=78 MATCH
carrier   construction_request.json  exit=0 lines=31325 resolved=30871 deferred=454 MATCH
```

The check decodes each produced line back into a `SemanticObject` and compares its CID with the
reference object for that occurrence, so the claim is object identity, not textual similarity. Both
carriers run inside the one program, and the reader's identity is unchanged by the seam that exposes
the tree (`6539e017…`, root `a87c6b33…`, 280 467 B, 80 384 B). Measured on this host: 16 ms for the
66 KB carrier, 27 ms for the 957 KB one; two consecutive builds produce the same store
(`24d3be84519b0103`, 1 531 340 B).

```powershell
resolve.exe <carrier> <listing>
```

| situation | exit |
|---|---|
| unknown alias, unknown `win32.` name, alias chain longer than 8 | 11 |
| unknown entity name | 12 |

`?` lines are counted, not emitted as guesses. They are the derived declarations whose bodies need
type CIDs hashed in the program:

| deferred name | sandbox | construction | needs |
|---|---|---|---|
| `win32.import` | 61 | 48 | type CIDs for the imported signature (step 4b) |
| `win32.virtual_free_view` | 4 | 6 | the view type's CID (step 4b) |
| `{"fn": …}` | 13 | 400 | graph assembly (step 5) |

## The plan

| Step | Content | Oracle |
|---|---|---|
| 1 | authoring primitives (this check) | canonical CID match |
| 2 | native host: argv, file read/write, exit (the pattern of `hash_host.xax`) | copies bytes byte-exactly, exits 0; refuses with 2-7 |
| 3 | carrier JSON reader: objects, arrays, strings, integers; unmeasured cases refused | `json.dumps(json.loads(x), sort_keys=True, separators=(",",":"))` byte-identical on both carriers |
| 3b | `\uXXXX` escapes, UTF-8, floats, member-order sort for unsorted carriers | a corpus that exercises each, against `json.dumps` |
| 4 | types, aliases, view specs and `win32.` platform lookups against the embedded namespace | every produced object's CID equals the reference object's |
| 4b | derived declarations (`win32.import`, `win32.virtual_free_view`) with type CIDs hashed in-program | the 109 import and 10 view-free declarations the carriers use |
| 5 | graph, package and build request assembly; `resolve` + `snapshot_store` reuse | the two store roots above, byte-exact |
| 6 | driver command `construct <carrier> <store>`, re-derived Windows driver, `DRIVER.md` | command table and native checks |

Step 5 is where the existing `xax_selfhost_resolve` and `xax_selfhost_writer` components are reused
rather than reimplemented.

## Boundaries

- No Python at run time. Python remains build tooling here (it authors the component), exactly as
  every `compiler/src/xax_selfhost_*.py` module already does.
- No second canonical graph store and no second semantics: a native decoder that disagrees with the
  reference is a bug, decided by the byte comparison above.
- Floats, non-ASCII input and carrier features not yet implemented are **rejected with a diagnostic**,
  never silently approximated.
- The Windows driver store stays untouched until step 5 passes; a wrong decoder must not be able to
  reach the program that builds every artifact.
