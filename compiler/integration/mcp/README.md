# Native MCP server authoring (XAX-MCP)

The deployed MCP server `MrxSiN/XAX-MCP` is not a Python server. It is one XAX program, `xax-mcp-native`, built
from one `xax-construct-v1` carrier into a verified canonical store and a PE32+ executable. `xax-mcp-sandbox` is a
second XAX program with the same shape. Neither runs Python on its request path.

This directory is the authoring tooling for those two programs, and it lives here rather than in the artifact
repository so that `MrxSiN/XAX-MCP` contains no source code: carriers, canonical stores, executables, evidence and
docs only. The program semantics are XAX either way; what remains in Python is the carrier emitter, which the native
`construct` decoder (`compiler/integration/construct/`) replaces when it is finished.

| file | role |
|---|---|
| `server.py` | writes the `xax-construct-v1` carrier for `xax-mcp-native` (STDIO framing, JSON validation, JSON-RPC, MCP lifecycle, tool dispatch, host rights) |
| `sandbox.py` | writes the carrier for `xax-mcp-sandbox`, the fixed executor boundary (job object, AppContainer, pipes, supervision) |
| `dsl.py` | the block/edge emitter both carriers are written with |
| `schemas.py` | the tool argument schemas the server carrier embeds (transport values) |
| `seed.py` | the editable form-2 build-request seed `xax-mcp-seed.xax` |
| `chain.py` | drives the native compiler over that seed: `edit` -> `resolve` -> `build` |
| `bench.py` | protocol measurements (cold start, round-trip latency, peak working set) |
| `fingerprint.py` | recomputes the toolchain fingerprint recorded in the XAX-MCP compatibility matrix |
| `tests/test_native_stdio.py` | the Windows STDIO suite over the real PE32+ |
| `tests/generic_client.py` | a minimal MCP client over the same transport |

## Regenerate the artifacts

```powershell
$src = (Resolve-Path compiler/src).Path
python -B compiler/integration/mcp/server.py  $src D:\GitHub\XAX-MCP\native
python -B compiler/integration/mcp/sandbox.py $src D:\GitHub\XAX-MCP\native
python -B compiler/integration/mcp/seed.py    $src D:\GitHub\XAX-MCP\native
```

Each command prints the store root, the store size and the artifact size. These are the numbers the committed
artifacts have, so a regeneration is byte for byte reproducible:

| program | store root | store bytes | artifact bytes |
|---|---|---|---|
| `xax-mcp-native` | `baec162e4bfb177fff18c3d36efdbd6e2ad0a0dec6cb412874fcbd18c12dd442` | 1 020 614 | 318 464 |
| `xax-mcp-sandbox` | `7ef7099d5358bf022715faff1ef26387c1486c554ed2f7d9145bd9d8953ef8b6` | 74 434 | 25 600 |
| `xax-mcp-seed` | `572f683e22d94efe404b5b73f59b85edfd3e6ccbd2614342fdf58fe66cb61587` | 1 852 | 1 536 |

## Run the tests

The suite is a Windows test client; the server under test is the committed executable.

```powershell
$env:XAX_MCP_HOME = "D:\GitHub\XAX-MCP"        # committed carriers, stores and executables
$env:XAX_NATIVE_SRC = "D:\GitHub\XAX\compiler\src"
python -m pytest -q compiler/integration/mcp/tests
```

`XAX_MCP_HOME` supplies the artifacts to compare against; `XAX_NATIVE_SRC` enables the tests that rebuild the
store and check it byte for byte. Without either, the tests that need them skip rather than pass silently.

The pin's compiler tree is checked with `fingerprint.py`:

```powershell
python -B compiler/integration/mcp/fingerprint.py D:\GitHub\XAX
# 0ab800baf79464895bceeb0ccdaa13f4b8d1969fc627644f01e447575731f5d9
```

## What is still Python

The carrier emitters. `xax_construct.construct` is Python-only upstream, so a carrier today cannot be turned into
a store without it. `compiler/integration/construct/` is the native decoder that removes that dependency: when it
reproduces both stores above byte for byte, the emitters are only needed to *edit* a carrier, and the artifact
repository's build becomes `construct <carrier> <store>` plus `build <store> <exe>`.
