# Eight-byte decision tape reset

The importer clears the complete 65,536-byte decision tape using checked
eight-byte stores at alignment one. It performs 8,192 reset iterations.
The previous importer used 65,536 checked one-byte stores. Brainfuck source,
BFX v1, decision ABI, logical length guards and source instruction lowering
are unchanged. This is a generic memory-initialization improvement.

## Canonical change

[wide_reset.edit](wide_reset.edit) replaces one graph reference in the importer.
Its parent is `import_bfx.xax` at revision
`3ddafd26752511d7efbc6ff715e2f4899be93ff2`.

- Expected root: `108fe27f40ea8b1fffa14426c6ee85bcecb7caef91e2f8313292ec22770badb8`.
- Result root: `6af38cf7dce17eaeb4929a5e3cde770f04996db84026d5c9acb6743a07f4e63e`.
- Result SHA-256: `b4069061eec825d34f1c6a4172ecae4aff3e588c67054e27810d4ed3ced41c03`.

The record changes only the reset block emitted by the canonical importer.
The reference transaction applier, full verifier and `Workspace.save` establish
the maintained source. The native Windows driver also replays it exactly,
rejects reapplication to the changed root and verifies the resulting importer.
No production Python implementation changes.

## Equivalence argument

The unchanged entry guards reject logical input/output lengths above 65,536
before touching the tape. A valid call enters the reset with offset zero.
The existing 32-bit constant one, rotated right by 29, gives stride eight;
no constant-table or public-interface extension is needed.

At reset iteration `k`, the offset is `8k`, for `0 <= k < 8192`. The checked
store writes eight zero bytes, covering exactly `8k` through `8k + 7`.
The last offset is 65,528; the last byte is 65,535. The counter then reaches
65,536 and the unchanged condition exits. No counter wraps, ranges overlap
or byte remains uncleared. A 64-bit zero has the same byte representation
on every supported target. Alignment one preserves the borrowed-view contract.

Memory frontiers remain threaded through the checked store. Every other
generated block is identical: pointer moves, skipped loops, wrapping, input
consumption, output prefixes and defined failure ordering retain their checks.
The generated graph has one additional pure node in its reset block.

## Executed checks

[wide_reset_evidence.json](wide_reset_evidence.json) is an immutable snapshot.
It records source/artifact/tool hashes and separate bootstrap/native authority.

- Both importer versions pass the same 393 record cases on Windows and Android.
  Rejection statuses match. Every accepted store passes full canonical
  verification; its only semantic difference is the reset block. Android
  output matches its corresponding Windows output byte for byte.
- Twenty decision programs have 19 checks per version/target: 1,520 calls
  agree with an independent interpreter on status, the whole output buffer
  and the whole tape. Checks include dirty tapes, five pointer alignments,
  wrapping, EOF, nested/skipped loops, both tape bounds, zero output capacity
  and invalid logical lengths. Input bytes and allocation guards stay intact.
- Three frontend generations on each target reproduce BFX, stores and native
  libraries. Each generation checks twelve exact fixtures, own source and
  seven resource/framing boundaries. BBC's source and BFX seed are unchanged.
- A separate Windows process replays 1,606 native calls with
  `XAX_REQUIRE_NATIVE=1`, including all importer cases, decision cases and
  three frontend generations. Direct Android children also require native
  execution. External transports supply buffers, files and clocks only.

Unchanged Python utilities perform bootstrap verification and lowering.
Native process authority is recorded by external transports with complete
DLL/ELF/PE digests; it does not activate the common Python helper loader.
The installed Android application retains its previously measured module.

## Measurements

The fixed twelve-program pilot corpus and inputs are unchanged. Three
independent runs have ten randomized pairs per case/run. Each observation is
the mean of sixteen timed native calls; each call includes the full reset.
Output/status checks follow every call outside the timer. Three warmups per
arm/case/run are unmeasured. Each target has 11,520 timed calls.

| Native-call boundary | Previous importer (ms) | Current importer (ms) | Less time (ms) |
|---|---:|---:|---:|
| Windows x86-64 | 6.168 | 5.624 | 0.544 |
| Android ARM64 | 1.360 | 1.302 | 0.058 |

These are arithmetic averages of the twelve workload medians of batch means.
Exploratory paired bootstrap intervals for less time are 0.140–0.796 ms on
Windows and 0.055–0.081 ms on Android. Only three process clusters exist;
clocks, affinity and thermals were uncontrolled. Windows includes ctypes
call overhead; Android times the direct native call. Cross-device times do
not compare processor speed. These intervals establish no competitor result.

A fresh Android process experiment reuses the pinned Awib/brainfry executables
and exact 5,608-byte pilot host, verifying every artifact hash, input, output
and exit status. Three runs of ten randomized pairs use the same corpus:

| Android process comparison | BBC including startup (ms) | Other program including startup (ms) | Extra time BBC takes (ms) |
|---|---:|---:|---:|
| Awib | 39.347 | 32.055 | 7.292 |
| brainfry | 38.435 | 8.483 | 29.952 |

The rows average per-program medians; BBC has separate paired populations.
Both process aggregates still favor the competitors. No comparator is
SURPASSED. This experiment measures no end-to-end compiler latency, peak RAM,
application benefit, Windows competitor result or alternate competitor mode.
Raw samples and limitations remain in the evidence; earlier reports are unchanged.

The twelve measured programs keep identical native file sizes. The separate
empty-program Windows regression DLL grows from 2,560 to 3,072 bytes at a PE
section-padding boundary. The Windows importer grows by 512 bytes; its Android
library stays 132,040 bytes. No smaller-file or resident-RAM claim is made.
