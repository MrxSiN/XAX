# Windows native helper hosts

`hash_host.xax` is a canonical XAX program that reads raw bytes from standard
input and writes their 32-byte BLAKE3-256 digest to standard output. It runs
as a Windows x86-64 PE executable, using only kernel32 imports. The host owns
its input, scratch, read buffer and byte-count storage. Its hashing functions
come from the existing generic BLAKE3 graph constructor; no new hash algorithm
or foreign hash library is part of the program.

The hashing host does **not** change the Linux-only in-process helper loader
or activate native hashing in the Python compiler. The separate
[Windows driver prototype](DRIVER.md) executes the existing store/graph, CFG,
typing and verifier call chain as a native process on tested inputs. Its
diagnostic and large-store coverage limits remain explicit.

## Stream contract

| Item | Behavior |
|---|---|
| Input | Raw bytes until EOF, from a file or byte-mode pipe |
| Maximum input | 16,777,216 bytes, inclusive; inherited from the existing hash view |
| Success | Exit 0 and exactly 32 raw digest bytes; no text encoding or newline |
| I/O failure | Exit 1; discard any output, including a partial failed write |
| Input beyond capacity | Exit 2 with no digest |
| Allocation failure | Checked heap-view trap ends the process before publishing a digest |

Reads handle partial input and zero-length EOF. A broken input pipe is EOF;
other read errors fail. Capacity is checked before copying a chunk. All local
buffer accesses are checked, and the digest is published only after the whole
input is accepted. `ReadFile` and `GetLastError` thread an explicit process
effect as well as the separate filesystem and memory effects. Every ordinary
completion path releases all four allocations before `ExitProcess`.

The current general compiler-driver store exceeds this single-input limit
and is correctly rejected. No incremental hash interface is claimed.

## Rebuild from the canonical source

Run from the XAX repository root in PowerShell. The commands invoke unchanged
generic Python bootstrap verification, x86-64 lowering and PE emission.
They do not require a C compiler, .NET SDK or new Python package. Windows PE
entry points use the normal Win64 call convention; do not request the
Linux-style `process_entry=True` lowering option.

```powershell
$env:PYTHONPATH = (Resolve-Path compiler/src).Path
@'
from pathlib import Path
from xax_compiler import Kind, StoreReader, verify_store
from xax_pe import compile_pe_executable

reader = StoreReader(Path('compiler/integration/windows_helpers/hash_host.xax').read_bytes())
verify_store(reader)
module = next(obj for obj in reader.objects() if obj.kind == Kind.MODULE)
entry = next(reader.get(cid) for cid in module.references if reader.get(cid).kind == Kind.FUNCTION)
target = next(reader.get(cid) for cid in module.references if reader.get(cid).kind == Kind.TARGET)
output = Path('build/windows_helpers/xax-hash.exe')
output.parent.mkdir(parents=True, exist_ok=True)
output.write_bytes(compile_pe_executable(reader, entry.cid, target, frontend='python'))
'@ | python -B -
```

Keep generated artifacts outside version control. The bootstrap may use its
recorded Python fallback; this build step is not claimed to run natively in
XAX. The resulting executable contains XAX machine code and kernel32 imports.

## Small regression check

This external process check supplies the two existing official test vectors
and an oversized stream. Python only supplies bytes and checks the result.

```powershell
@'
import os, subprocess
exe = 'build/windows_helpers/xax-hash.exe'
env = {**os.environ, 'XAX_REQUIRE_NATIVE': '1'}
for data, expected in [
    (b'', 'af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262'),
    (b'abc', '6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85'),
]:
    result = subprocess.run([exe], input=data, capture_output=True, env=env, timeout=30)
    assert result.returncode == 0 and result.stdout.hex() == expected
result = subprocess.run([exe], input=b'X' * (16_777_216 + 1), capture_output=True, env=env, timeout=30)
assert result.returncode == 2 and result.stdout == b''
'@ | python -B -
```

## Executed checks and provenance

[execution.json](execution.json) records 139 successful native process cases
and five failure cases on Windows. Successful outputs match an independently
installed BLAKE3 package used only by the external test driver. Cases include
block/tree/chunk boundaries, 100 seeded random inputs, fragmented binary
pipes, redirected files, three eligible canonical stores and the exact input
limit. Failures include two oversized streams, the oversized compiler-driver
store, invalid standard handles and a closed output pipe. The emitted PE is
45,568 bytes and rebuilds byte for byte from the saved graph.

[error_state.edit](error_state.edit) is the exact-root transaction that makes
the read/error-state ordering explicit. The unchanged reference transaction
applier was followed by canonical verification and workspace save; applying
the record to the resulting root is rejected as stale. The current `.xax`
store is authoritative; apply subsequent changes through verified transactions.

The report separates runtime native authority from bootstrap fallback
authority. It records source, artifact, transaction and external test-driver
hashes. The external full test driver remains local; the small check above
is directly reproducible. No cold full-pipeline timing, competitor result,
RAM result or Android execution is established here.
