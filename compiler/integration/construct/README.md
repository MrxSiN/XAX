# Native `construct` (work in progress)

`xax-construct-v1` has no native decoder. `xax_construct.construct` exists only as Python
(`compiler/src/xax_construct.py`), so a native host cannot construct a program from a carrier, and a
consumer that needs one either runs Python or ships a second decoder. This directory is the start of a
native decoder that keeps XAX as the only semantic authority.

**Status: step 1 of the plan below. Nothing here decodes a carrier yet.** What is established is that
the authoring primitives the self-hosting components use (`Proc` over `GraphBuilder`) reach the *same
canonical objects* as the Python reference, which is the precondition for the rest.

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

## The plan

| Step | Content | Oracle |
|---|---|---|
| 1 | authoring primitives (this check) | canonical CID match |
| 2 | native host: argv, file read/write, exit (the pattern of `hash_host.xax`) | copies bytes, exits 0 |
| 3 | carrier JSON reader: objects, arrays, strings (incl. `\u` escapes), integers; floats rejected | `json.dumps(json.loads(x), sort_keys=True, separators=(",",":"))` byte-identical on both carriers |
| 4 | type and entity resolution, embedded platform namespaces (as `xax_platform.py` declares them) | object CIDs for every type/entity name |
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
