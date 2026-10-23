# Native MCP programs (XAX-MCP)

The deployed MCP server `MrxSiN/XAX-MCP` is not a Python server. It is one XAX program, `xax-mcp-native`, built
from a verified canonical store into a PE32+ executable. `xax-mcp-sandbox` and `xax-mcp-seed` have the same shape.
None of them runs Python on its request path.

This directory holds the authoritative XAX programs and the tooling that builds and checks them. It lives in the
XAX repository so that `MrxSiN/XAX-MCP` contains no source code: carriers, canonical stores, executables, evidence
and docs only.

## The programs are the stores

`programs/*.xax` are the authoritative programs. A `xax-construct-v1` carrier is transport, never source; the
carrier files are kept because the native `construct` decoder reads them and because they are the readable form of
the same graph.

| file | role |
|---|---|
| `programs/xax-mcp-native.xax` | the server program: STDIO framing, JSON validation, JSON-RPC, MCP lifecycle, tool dispatch, host rights |
| `programs/xax-mcp-sandbox.xax` | the executor boundary: job object, AppContainer, pipes, supervision |
| `programs/xax-mcp-seed.xax` | the editable form-2 build-request seed (entry returns 40 through `ExitProcess`) |
| `programs/xax-mcp-seed-snapshot.xax` | the resolved snapshot of the seed, as committed by the authors |
| `programs/construction_request.json` | the `xax-construct-v1` carrier of the server (transport) |
| `programs/sandbox_request.json` | the carrier of the executor (transport) |
| `programs/tool-schemas.json` | the tool argument schemas the server carrier embeds (transport data) |
| `chain.py` | drives the native compiler over the seed: `edit` -> `resolve` -> `build` (port pending) |
| `bench.py` | protocol measurements (port pending) |
| `fingerprint.py` | recomputes the toolchain fingerprint (port pending) |
| `tests/test_native_stdio.py` | the Windows STDIO suite over the real PE32+ (port pending) |

The five Python carrier emitters (`server.py`, `sandbox.py`, `seed.py`, `dsl.py`, `schemas.py`) were retired in
this change. They are preserved in git history at `6b6c359`; the programs they emitted are the stores above. The
store is the source: an edit is a typed `xaxc edit` record, not a regeneration from a DSL.

## Build and verify

No author runs. The committed stores are the inputs:

```powershell
$programs = "compiler/integration/mcp/programs"
# server and executor are snapshots
build/windows_helpers/xaxc-windows.exe verify $programs/xax-mcp-native.xax   server.verify
build/windows_helpers/xaxc-windows.exe build  $programs/xax-mcp-native.xax   server.exe server.prov
build/windows_helpers/xaxc-windows.exe build  $programs/xax-mcp-sandbox.xax  sandbox.exe sandbox.prov
# the seed is a form-2 build request: resolve it first
build/windows_helpers/xaxc-windows.exe resolve $programs/xax-mcp-seed.xax seed-snapshot.xax
build/windows_helpers/xaxc-windows.exe build   seed-snapshot.xax seed.exe seed.prov
```

The committed artifacts are:

| program | store root | store bytes | executable | executable bytes |
|---|---|---|---|---|
| `xax-mcp-native` | `18ceecd9fe284e16919bb5f0f40bdf52cf5a90407ad007d218f30d3235024b07` | 1 103 602 | `9f6e272bbbc938d3493a98b7c68409de31a09ffc4cc958bb41be7447b65c076a` | 359 424 |
| `xax-mcp-sandbox` | `7ef7099d5358bf022715faff1ef26387c1486c554ed2f7d9145bd9d8953ef8b6` | 74 434 | `6d563e0f23e4f402d55c82b200d42bce91c41c98aab101267e67d3645a1d37e2` | 25 600 |
| `xax-mcp-seed` | `572f683e22d94efe404b5b73f59b85edfd3e6ccbd2614342fdf58fe66cb61587` | 1 852 | `8faaeb7e63e5d1a07bcd9c46e3ae3381af267b67e213cec6b992c628fb1843ca` | 1 536 |

The executor build is byte-identical to the committed PE. The server build is not yet byte-identical: the native
backend omits the reference Windows guard-page probe, which shifts the image by 16 bytes (B1). The committed
server PE remains the author-built one; the store and the carrier are byte-identical to the committed artifacts.

The native `xaxc` is a local prototype and is not committed to the pinned tree. The pinned compiler commit is
`3e9b0c2b3f88d2193caae72a5fe8eefa83d1995b`; the tools here are integration tooling for that pin.

## Run the tests

The suite is an external Windows test client; the server under test is the committed executable. The client also
checks that `programs/*` are byte-identical to the deployed artifacts in `XAX_MCP_HOME`.

```powershell
$env:XAX_MCP_HOME = "D:\GitHub\XAX-MCP"        # committed carriers, stores and executables
python -m pytest -q compiler/integration/mcp/tests
```

Optional gates, each of which skips rather than passing silently when unset:

| variable | enables |
|---|---|
| `XAX_MCP_TEST_COMPILER` | native `xaxc`: deterministic rebuild of the committed server store |
| `XAX_MCP_TEST_CONSTRUCT` | native `construct`: decode `sandbox_request.json` and compare the store |
| `XAX_NATIVE_SRC` | the pinned `compiler/src`, for the `xaxc edit` record in the chain test |
| `XAX_MCP_NATIVE_EXE` | a server executable other than `XAX_MCP_HOME/native/xax-mcp-native.exe` |

The pin's compiler tree is checked with `fingerprint.py`:

```powershell
python -B compiler/integration/mcp/fingerprint.py D:\GitHub\XAX
# 0ab800baf79464895bceeb0ccdaa13f4b8d1969fc627644f01e447575731f5d9
```

## What is still Python

The carrier emitters are gone. `chain.py`, `bench.py`, `fingerprint.py` and the test client remain Python while
they are ported to XAX programs; they are build/test tooling, never part of a deployed artifact. The retirements
and the remaining port are recorded as B5 in the XAX-MCP evidence.
