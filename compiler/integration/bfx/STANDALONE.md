# Standalone Android decision process

[standalone_arm64.xax](standalone_arm64.xax) calls a verified decision directly
from a static executable. It uses the existing AArch64 syscall target and runs
on Android ARM64. There is no shared-library test host, dynamic loader, libc,
Brainfuck interpreter or foreign implementation of language algorithms.

The source is a canonical host with an empty decision as its initial callee.
Bind an imported component through an exact-root transaction. The supplied
[standalone_hello.edit](standalone_hello.edit) is a complete example binding
the current importer's hello component. Arbitrary later source changes must
also use verified workspace transactions.

Initial root: `ffc802672a132e2bd40bc89c92d9d89b0ff9b7d21b1157cd0ba9caa2ab7c8dbd`.
Initial source SHA-256:
`43a227c14726eb76a227c8ab63d8ba18dd5b52cdf4c9099985301183c80a85d6`.
The source has 12,828 bytes; its empty executable has 1,436 bytes.

## Process contract

The host reads raw stdin to EOF, accepting at most 65,536 bytes. It then calls
the existing decision with three distinct initialized 65,536-byte input,
output and tape views, the input length and output capacity 65,536. The core
still performs its full tape reset and every original bounds/I/O check.
Input above the transport limit rejects before the decision executes.
This is a buffered process interface; interactive input requires EOF.

After the call, the host checks status and output length before writing any
successful output. Language failures discard the core's entire output prefix.
Reads retry EINTR and accumulate fragments. Writes retry EINTR and partial
transfers. Zero progress or another I/O error fails. Each transfer remains
within the checked owned view; dynamic pointer rebasing preserves provenance.

| Exit | Meaning |
|---|---|
| 0 | Success |
| 1 | Executed tape movement exceeded bounds |
| 2 | Output capacity exhausted |
| 3 | Input above the 65,536-byte process limit |
| 5 | Read/write failure or invalid returned output length |

Three owned mmap views are released with munmap before explicit exit_group.
Their 196,608-byte declared allocation is **not measured resident RAM**.
Allocation failure takes the existing checked-null trap. A failed OS write
can have emitted a prefix; callers must discard output on nonzero termination.
There is no instruction budget or changed nontermination semantics.

## Executed evidence

[standalone_arm64_evidence.json](standalone_arm64_evidence.json) retains exact
sources, bindings, artifacts, raw timings, tools and bootstrap authority.
[standalone_native_replay.json](standalone_native_replay.json) separately
records native-only replay through `xax_native.AUTHORITY`.

- Twenty decision components run with their independently checked outputs
  and statuses. Additional checks cover binary/fragmented input, EOF,
  exactly 65,536 input bytes, excess input and actual closed descriptors.
- A component that writes a prefix then crosses the tape boundary exits 1
  with no stdout. A looping output component exits 2 with no stdout when the
  core reaches its output limit. A 65,025-byte output matches exactly through
  a regular file and the native process timer's pipe.
- Native-only replay covers 23 Android programs with complete ELF hashes
  and exact roots. The Windows native driver replays the public hello binding
  exactly, verifies its result and rejects its stale root. Children use
  `XAX_REQUIRE_NATIVE=1`; external transports implement only file/pipe I/O,
  process launch, clocks and descriptor-failure injection.
- A second bootstrap build of the empty and hello programs reproduces their
  executable bytes. Verification, lowering and ELF packaging use unchanged
  generic Python utilities. The common Python helper loader is unchanged.

Direct ADB shell display translated newlines on the tested host, so binary
checks use redirected device files and pull, or native pipes. Allocation
failure, EINTR and forced short-write injection were not performed. A first
timing probe overlapped validation; its complete raw data and exclusion reason
are retained separately from the primary run.

## Primary process comparison

The original twelve pilot sources, inputs, holdouts and expected outputs stay
fixed. Awib and brainfry executable hashes match the pinned pilot artifacts.
Each comparator has three separate runs of ten randomized pairs per source,
with two warmups per arm/run/source. All 1,440 timed process invocations check
output and exit status. The timer runs on the Pixel 8 Pro around fork, exec,
pipe consumption and wait; ADB, input-file opening and pipe creation precede
the timer equally. Startup and all program work remain included.

| Android comparison | Standalone BBC (ms) | Other program (ms) | BBC difference |
|---|---:|---:|---|
| Awib | 13.441 | 31.076 | 17.635 ms less |
| brainfry | 12.501 | 7.473 | 5.028 ms more |

Each value averages the twelve per-program medians of thirty trials. BBC's
two paired populations are retained separately. Exploratory, two-comparator
family-adjusted bootstrap intervals put BBC's advantage over Awib at 16.661
to 20.206 ms and its disadvantage to brainfry at 4.738 to 6.341 ms. Only three
process clusters exist; clocks, affinity and thermals were uncontrolled.

This is a measured advantage over **the pinned Awib configuration on the
common safe no-EOF subset on this Android process boundary**. Brainfry remains
faster. It is not an unrestricted compiler or application sweep. The installed
Android UI application retains its previously tested module. End-to-end build
time, peak RAM, steady-state comparator execution, Windows standalone execution
and best-mode coverage are not measured here.

| Native file bytes over the same twelve programs | BBC | Awib | brainfry |
|---|---:|---:|---:|
| Range | 1,876–13,552 | 4,480–4,904 | 896–3,184 |
| Arithmetic mean | 5,422.7 | 4,644.0 | 1,306.7 |

BBC counts its complete executable; it needs no fixed test-host file. Code
size remains larger on average than both competitors. File size is not RAM.
No unrestricted comparator is marked SURPASSED; the general goal remains unmet.

## Reproduce the hello binding

From the repository root, with 64-bit Python and `XAX_REQUIRE_NATIVE` unset,
invoke the existing bootstrap utilities unchanged:

```powershell
$env:PYTHONPATH = (Resolve-Path compiler/src).Path
@'
from pathlib import Path
import xax_compiler as X
from xax_selfhost_edit import apply_reference
from xax_workspace import Workspace
from xax_linux_aarch64 import compile_linux_aarch64_executable

folder = Path('compiler/integration/bfx')
reader = X.StoreReader((folder/'standalone_arm64.xax').read_bytes(), proof_cache=X.ProofCache())
reader = apply_reference(reader, (folder/'standalone_hello.edit').read_bytes())
X.verify_store(reader)
module = next(reader.get(c) for c in reader.get(reader.root_cid).references if reader.get(c).kind == X.Kind.MODULE)
entry = next(reader.get(c) for c in module.references if reader.get(c).kind == X.Kind.FUNCTION)
target = next(reader.get(c) for c in module.references if reader.get(c).kind == X.Kind.TARGET)
output = Path('build/bfx/standalone-hello')
output.parent.mkdir(parents=True, exist_ok=True)
Workspace(reader).save(output.with_suffix('.xax'))
output.write_bytes(compile_linux_aarch64_executable(reader, entry.cid, target.cid, frontend='python').data)
'@ | python -B -
```

The native driver's `edit <source> <record> <output>` can perform the same
binding where that driver is installed. Deploy the resulting ELF with ADB,
make it executable and run it on Android with stdin at EOF. It emits
`Hello World!` followed by LF. No desktop Linux host is needed or claimed.
