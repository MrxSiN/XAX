# Native BFX importer

`import_bfx.xax` is the canonical XAX source for the BFX-to-decision-store
adapter. It calls the canonical decoder and graph-native BLAKE3
helper, emits checked native decision operations and loop edges, computes
semantic CIDs, sorts records, and writes the complete canonical store/index/
digest. No Python BFX parsing, opcode translation or graph construction runs
in this path.

The initial graph was authored through XAX's existing GraphBuilder/Proc
construction interface, verified, tested privately, then saved with
`Workspace.save`. The construction carrier is external, not maintained
source. Subsequent source changes require expected-root workspace transactions.

The importer accepts strict v1, the explicitly versioned
[v2 CLEAR extension](CLEAR.md), [v3 arithmetic powers](POWERS.md), and
[v4 monotone movement powers](MOVEMENT.md). Versions two through four permit
payload byte zero; versions three/four permit arithmetic bytes one through
fourteen, and only v4 permits movement bytes fifteen through twenty-eight.
V1/v2/v3 accepted output stores stay exact. The standalone `bfx.xax` validator remains v1-only.

The current [eight-byte tape reset](WIDE_RESET.md) retains the complete
65,536-byte reset and all checked accesses. Its canonical transaction,
correctness runs and absolute timings have separate evidence.
The [standalone Android host](STANDALONE.md) can call an imported decision
directly from a static executable, removing the shared-library test host.
The [standalone Windows host](WINDOWS_STANDALONE.md) supplies a kernel32-only
PE process with the same buffered-input, checked-decision and exit contract.

## Import call

The function borrows four distinct live initialized views:

| View | Pointer | Extent |
|---|---|---|
| BFX record | read-only byte pointer | 3847 bytes |
| Decoder workspace | read/write byte pointer | 16380 bytes |
| Output and serialization workspace | read/write byte pointer | 67108864 bytes |
| BLAKE3 scratch | read/write u32 pointer, alignment 4 | 2048 bytes |

Each view is supplied as pointer, extent-bearing ownership proof and memory
frontier. All four triples return with updated frontiers. The caller
establishes validity, initialization, non-aliasing and lifetimes; this is an
internal typed ABI, not an untrusted pointer API.

Before each call, write the logical BFX record length as a little-endian u32
into workspace bytes 0..3. The importer reads it before the decoder reuses
that workspace. The native export is:

`import_bfx(record_pointer, workspace_pointer, output_pointer, hash_pointer) -> u64`

Success returns `store_length << 32`; publish only `output[0:store_length]`.
Failure returns the decoder error in the low 32 bits, with no successful
store. Error meanings are in [the decoder contract](README.md). Other output
bytes are internal scratch and unspecified. Reset the workspace request length
before every invocation. Keeping the request at four native arguments avoids
the legacy Win64 fallback path's unsupported nested borrowed-view returns.

The generated decision function borrows distinct input, output and tape byte
views, each **65536 bytes**, followed by u32 input length and output capacity.
Its result is `(output_length << 32) | status`: 0 success, 1 pointer bounds,
2 output exhausted, 3 invalid logical lengths. Every valid call zeroes the
whole tape. Byte arithmetic wraps, EOF reads zero and every executed pointer
move checks its boundary. Error output prefixes must be discarded.
Callers with smaller allocations must supply a separately verified wrapper
rather than falsely claim a full view.

The emitted store binds the existing Android integer shared-library target.
The same verified decision function can be explicitly bound to the existing
Windows target by generic XAX lowering. There is no runtime BF interpreter,
new instruction, BF optimization pass, ABI implementation or APK packager here.

## Storage bounds

BFX still accepts at most 3840 instructions and nesting 255. A first pass
assigns one main graph block per instruction plus two blocks per input and
one per output; two entry guards retain structurally reachable failure paths.
There are at most 11529 blocks, so block references occupy at most two ULEB
bytes. At most 512 serialized bytes per instruction plus 4096 fixed bytes
bound the graph below 2 MiB. Eight-MiB-separated staging regions hold graph
body, semantic preimages, records and final output. Metadata starts at 48 MiB
and the 3841-entry block map at 49 MiB, within the 64 MiB output/work view.
The large view is compiler workspace, not a generated decision allocation.
All native memory accesses remain checked.

## Android hash implementation

Hashing uses a pure byte-mask helper and a 16-byte-result mixing helper.
Compression writes the eight chaining words to bytes 1760..1791 of the existing
2048-byte hash scratch view. The hash caller reads those words with checked
accesses and threads the same scratch ownership and memory frontier through
each call. The digest remains at bytes 1728..1759. No allocation or extra
caller buffer is introduced; the import ABI and BFX v1 are unchanged.

This keeps frames within the Android target's supported limit and avoids its
large-composite return path. That general backend defect is tracked in
[OI-49](../../../XAX_OPEN_ISSUES.md#oi-49--android-arm64-large-composite-return-copy).
The importer uses results of at most 16 machine bytes. No backend source was
changed.

`android_importer.edit` records the exact-root reference transaction that
installed this graph change. The saved `import_bfx.xax` store is authoritative;
apply subsequent edits through verified transactions. The unchanged Python
reference transaction applier and canonical verifier were used by the host.

## 2026-10-19 execution snapshot

- 393 complete-importer record cases passed on each of Windows x86-64 and
  Android ARM64. Android also imported compiler, framer and decision outputs.
  Every emitted store matched the established Windows result byte for byte;
  input bytes and guards on all four buffers remained unchanged.
- 89 calls across 13 emitted native Windows decisions agreed with an
  independent interpreter, covering wrapping, EOF, loops, skipped bounds,
  tape bounds, invalid lengths and output exhaustion. Deliberately
  nonterminating nonzero empty-loop inputs were excluded from execution.
- Three Windows frontend generations produced identical BFX, stores and DLLs.
- Three Android generations executed both BFX import and the native Brainfuck
  frontend on Pixel 8 Pro. BFX, stores and ELF libraries matched across all
  generations; eight exact frontend fixtures passed in each generation.
- Rebuilding Android and Windows importer artifacts from that snapshot's store
  reproduced the tested bytes.

For that snapshot, verification/lowering runs on Windows through unchanged generic
Python bootstrap utilities. Importer lowering uses the verified parsed graph
views and empty prefetch marks through the existing generic lowering interface
on Windows, avoiding expansion of thousands of serialization calls. These are
derived lowering views, not source mutations or import logic.
`XAX_REQUIRE_NATIVE` is unset. These results establish native importer and
frontend execution; they do not claim an Android-hosted XAX compiler.

Exact identities, artifacts, transaction, device results and external tool
hashes: [android_import_evidence.json](android_import_evidence.json). The
[Android app and regression source](ANDROID.md) are canonical stores.

The [2026-10-20 reset evidence](wide_reset_evidence.json) covers the current
importer: 393 cases per arm/target, 380 decision checks per arm/target, and
three frontend generations with 20 checks each on both targets. Native-only
Windows replay and Android child execution use `XAX_REQUIRE_NATIVE=1` with
separate authority records. The standalone native Windows driver applies the
transaction byte for byte, rejects its stale root and verifies the result.
Bootstrap graph verification and native lowering still use unchanged Python
tools; no complete native BBC compiler-host or Android-hosted compiler is claimed.
