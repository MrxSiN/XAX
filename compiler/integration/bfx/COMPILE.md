# Unified BBC compilation

`compile.xax` is the single supported public BBC source compilation entry.
Its `compile_bfx` function calls the existing BBC Brainfuck filtering, validation,
run-packing and clear algorithms. `source.xax` and `pack.xax` are private
components. The bounded BF compiler is a private seed/reference, not a second
public source workflow. The BFX wire format and shared strict decoder are unchanged.

## Typed interface

Four distinct initialized writable borrowed views, in order:
source/work 1,114,112; record 65,546; output/work 1,114,112;
tape/work 1,114,112 bytes. Pointer/view/memory tokens accompany each pointer.
Raw pointers alone establish none of the ownership or lifetime preconditions.

Set source/work u32 actual frame length at offset 0 and u32 optimization level
at offset 4. At offset 65,531 place `source_length:u32le || source || 01`.
The declared length counts binary bytes, including NUL and FF. Actual length
must equal declared length plus five. The maximum source is 1,048,576 bytes.
The coordinator validates the complete frame before moving its source bytes
one byte right, in reverse order, for the private chunk ABI.

Return `(record_bytes << 32) | status`: 0 success, 1 framing, 2 brackets,
3 capacity, 4 unsupported level/internal component failure. Failure length is
zero; discard provisional buffers. Framing/configuration failures tested by
this interface leave every buffer untouched. Check order: physical frame
range, declared source capacity, exact frame length, terminator, supported
level, pre-optimization instruction capacity, bracket validity. Only sticky
bracket status is deferred across chunks; component/framing failures are immediate.

O0 preserves primitive instructions. O1 packs arithmetic and monotone moves
through `stream_runs.bf`, then applies `optimize.bf` when packed count is at
most 3,840. Larger modules conservatively retain clear loops. O2/O3 are rejected.
Source validation remains `stream_chunks.bf`; no native parser or optimizer
substitutes for it. Record output is provisional until success. The CLI and
importer use the same strict decoder before publication/import.

## Native Windows command

`compile_windows.xax` contains one native Windows process host. Commands:

```
bbc emit-bfx [-O0|-O1]     raw binary source stdin, BFX stdout; default O1
bbc check                 raw binary source stdin, no success output
bbc info                  BFX stdin, instruction count stdout
```

Exits: 0 success; 1 invalid source/BFX; 2 resource capacity; 3 I/O failure;
4 usage/unsupported level. Errors write stderr and publish no BFX. An OS write
may fail after a prefix; callers must discard output on nonzero exit. Every
ordinary completion explicitly frees all seven allocations (4,001,802 declared
bytes). Allocation-failure and forced-short-write injection are not claimed.

These commands execute without Python. Executable compilation is the later
[`bbc compile`](#native-source-to-executable-compilation--2026-10-21) command;
library packaging is not implemented. Bootstrapping `bbc.exe` itself still uses
the unchanged generic SDK.
The Android shared component executes on-device; the CLI host is Windows-only.

## Bootstrap the Windows command with the generic SDK

Run the following generic API recipe from XAX `compiler/src`, with Python 3.13
on Windows x86-64. It builds into ignored BBC `build/` when that output is selected.
This is initial toolchain bootstrap, not the runtime of the commands above.
Existing five-machine-argument BF calls need the disclosed generic inlining
configuration. All original canonical graphs are fully verified first.

```python
from pathlib import Path
import xax_compiler as c
import xax_inline as I
from xax_x86_64 import _compile_native_with_target
from xax_pe import emit_pe_executable
p = Path('../integration/bfx/compile_windows.xax')
r = c.StoreReader(p.read_bytes(), proof_cache=c.ProofCache())
c.verify_store(r)
entry = bytes.fromhex('6b9b179df6db4b53aa04c9ece994e3a381548f69bcc31b1464c2bb540e02fe03')
views = {o.cid: c.parse_function_graph(o, r.get)
         for o in r.objects() if o.kind == c.Kind.FUNCTION}
for cid, view in tuple(views.items()):
    blocks, first = I._lift(view)
    sites = [(b, i) for b in blocks for i, n in enumerate(b.nodes)
             if n.node.operation == c.Operation.CALL_DIRECT
             and len(c._decode_function_interface(n.node.entity, r.get)[1]) == 11]
    if not sites:
        continue
    for b, i in reversed(sites):
        I._splice(blocks, b, i, views[b.nodes[i].node.entity.cid])
    while (I._merge_blocks(blocks, first) or I._thread_jumps(blocks, first)
           or I._store_truncations(blocks, r.get) or I._local_parameters(blocks, first)
           or I._dead_code(blocks)):
        pass
    views[cid] = I._lower(view, I._layout(blocks, first), first)
image = _compile_native_with_target(
    r, entry, c.x86_64_windows_pe_target(), verified=True, views=views,
    prefetches={cid: {} for cid in views})
Path('bbc.exe').write_bytes(emit_pe_executable(image))
```

`unified_compilation_evidence.json` records graph roots, exact transactions,
final image hashes, native regression cases, self-compilation and limitations.
The expected SHA-256 of this recipe's executable is recorded there.

## Transaction provenance

The baseline is XAX 42de0fc3ce31d4447f697e35a565cb4fdc489eda.
Initial facade construction uses existing generic canonical graph construction;
all subsequent changes use expected-root transactions and Workspace.save.
`transactions/unified/` retains:

- Clear view widening from the BF-native compiled optimize store.
- Fresh stream_chunks native import view widening and source binding.
- Facade binding to the reproducible native BF core.
- Host main binding against windows_helpers/hash_host.xax, then the small
  diagnostics insertion and reproducible frontend binding.
- The local source error-precedence correction and its facade/host bindings.

Every accepted edit received full verification and stale-root replay rejection.
All three frontend generations reproduce the embedded BF core. The final
wrapper's unchanged graph is reused by content identity after that check;
no no-op transaction is used as evidence of a rebuild. The final three
Windows DLL and Android shared images are also rebuilt identically.
Initial authoring transport and intermediate parents are archived outside BBC;
current runtime stores are closed and do not load historical parents or seeds.
Generic SDK Python files and all BBC BF instruction streams remain unchanged.

## Native source-to-executable compilation — 2026-10-21

`compile_windows.xax` now also implements `bbc compile` and `bbc bind`. The
change is one expected-root transaction,
[transactions/native_compile.edit](transactions/native_compile.edit): its
expected root is the previous host root
`fcbea87b30cbf359ec073c1c54cde985d4ca3b9350e12f0075647815ac9c98a4`, and it
replaces the module's process entry with a new entry that handles the two new
commands and calls the unchanged previous entry for `emit-bfx`, `check` and
`info`. The result root is
`db853d409115d4b87bf032613c8f5379b0d4220050b07530c61c0e903645c789`.
Full canonical verification and `Workspace.save` produced the store; replaying
the record against the result rejects its stale root.

```
bbc compile <android-arm64|windows-x86_64> [-O0|-O1] <output> < program.bf
bbc bind    <android-arm64|windows-x86_64> [-O0|-O1] < program.bf > program.edit
```

`bind` runs, in one process, the unchanged BF frontend (`compile_bfx`), the
unchanged strict decoder/importer (`import_bfx`) and a new canonical framing
function. Framing reads the importer's canonical decision store and writes one
`XAXEDIT1` record: the host request's expected root, a `REPLACE_REFERENCE` of
the host graph's empty decision with the imported decision, and every store
object as a supplied object. It accepts only a store with magic, version 1,
BLAKE3 suite, no non-semantic records, 1 to 256 objects (the native driver's
supplied-object limit; more is a capacity failure), schema 1 records whose
lengths stay inside the store, and exactly one FUNCTION object. Nothing is
trusted from this record: the driver checks the expected root, recomputes every
supplied object's CID and verifies the result.

`compile` writes that record beside the output and runs the native XAX driver
(`xaxc.exe`) three times with `CreateProcessW`, waiting for each: `edit` binds
the decision into the target's host request, `resolve` makes the build snapshot
and `build` verifies, lowers and packages it. `<output>.xax` (the verified
snapshot) and `<output>.provenance` remain; the record and request are deleted.
On failure every output, snapshot and provenance file is deleted. No Python,
interpreter or foreign compiler logic runs at any stage.

The host requests are canonical build requests, `bbc-android-arm64.xax` and
`bbc-windows-x86_64.xax`, with package identity `bbc`, entry `main`, the
default hermetic profile and a native-image artifact. They wrap the unchanged
`standalone_arm64.xax` and `standalone_windows.xax` programs; their roots are
`4b2c3e190b548d96b5c504e8fd95c09edb204685340290e9741918f1ccd95d7f` and
`e2c3f5574a423cb17d54c5bb440508ca0c42faafbd848e6a5a9270ca62ad4560`. They were
created once with the generic `xax_build` constructors and verified; later
changes use expected-root transactions.

Install layout: put `bbc.exe`, the driver as `xaxc.exe` and both request stores
in one directory. `bbc compile` finds them with `GetModuleFileNameW`; output
paths are relative to the working directory. Combined command lines are limited
to 3,900 UTF-8 bytes (`2 * directory + 3 * output + 120`), larger paths exit 4.

| Exit | Meaning |
|---|---|
| 0 | Success |
| 1 | Invalid Brainfuck source |
| 2 | A source or importer resource limit |
| 3 | I/O failure, the driver could not start, or the driver reported I/O failure |
| 4 | Usage, or an internal component or edit/resolve rejection |
| 5 | The native backend rejects or declines the program for the target |

### Bootstrap

Build `bbc.exe` from the new store with the generic recipe above (the same
11-parameter callee inlining configuration). Build the driver with the recipe in
[DRIVER.md](../windows_helpers/DRIVER.md); its PE must be SHA-256
`aa72234d6dd8a111efde62b47ced8449a482c4c5506d876714ff7fbe0968ab79`.

### Bootstrap backend finding

The generic bootstrap's Windows PE lowering of the new entry lost scalar values
carried from early blocks across later loops and calls: a standard handle
reached `WriteFile` as 2, and the selected target reached framing as an invalid
value, although each value has a single definition in the verified graph. The
entry therefore keeps process scalars in words of its own initialized chunk view
and fetches standard handles where it uses them. This is a defect in the
disclosed generic bootstrap backend, not a graph rule; it is recorded here
because any other long-lived bootstrap-lowered entry can meet it.

### Execution evidence

See [native_compile_evidence.json](native_compile_evidence.json). It was run on
Linux x86-64 with Wine 9.0 hosting the Windows PEs and `qemu-aarch64` user
emulation running Android ARM64 artifacts. These are emulated environments, not
Windows or Android device executions. The artifacts are nonetheless compared
byte for byte with earlier native-driver artifacts that ran on Windows 11 and
a Pixel 8 Pro.

The first campaign run with the previous driver rejected nine Windows builds of
decisions the lowering view does not inline (over 256 nodes, such as O0 hello
and both depth-512 programs) with `NATIVE-CALL-ARITY` `[5,4]`: the x86-64 frame
path counted the three borrowed views the decision gives back as machine
results. The [call elision](../windows_helpers/DRIVER.md#x86-64-borrowed-view-call-elision--2026-10-21)
driver change removes that gap; with it all 332 campaign builds (83 programs,
O0/O1, both targets) succeed and 588 executions match the reference
interpreter. `bbc compile` requires that driver (PE SHA-256
`110a76a2578f5f55777e6b0438b05642013e9587cae902ef3729229af8e5420e`); exit 5
remains for any other native backend rejection or decline.

| Fresh-process complete build, Linux host, median of 10 (s) | `bbc compile` under Wine | Previous Python SDK path |
|---|---:|---:|
| hello | 0.245 | 1.271 |
| nested_math | 0.247 | 1.238 |
| checksum_four | 0.237 | 1.236 |
| deep_nesting_512 | 0.853 | 11.218 |

Both arms produce identical artifacts. The Python arm starts from the native
record, so it excludes frontend and import. Each Wine process launch costs about
0.044 s here and `bbc compile` launches four, so these are not Windows-native
times and carry no competitor verdict. Stage medians under Wine are bind 0.050,
edit 0.065, resolve 0.069 and build 0.075 s, each including that launch cost.

## Single-process compilation — 2026-10-21

[bbc.xax](bbc.xax) is one program that holds BBC's commands and the whole native
XAX driver, so `bbc compile` runs in one process. It is the driver store
(`../windows_helpers/driver.xax`, root
`9bf3f203349cf8712ca93f968db2bd63f1c20b6277181891724ee4fbdd60aafc`) with one
expected-root transaction,
[transactions/bbc_single_process.edit](transactions/bbc_single_process.edit),
that replaces the module's entry. Result root:
`84478ecaeb21337d68707db175d6c85fc6628466fc4e6b119e50d19e46933f78`. Full
verification, `Workspace.save` and stale-root rejection pass.

The new entry dispatches on the first argument:

- `verify`, `inspect`, `resolve`, `build`, `edit`, `lower`, `resolve-trusted`:
  the unchanged driver entry.
- `compile`: an in-process front (argument checks, source read, the unchanged
  `compile_bfx` and importer, framing, `<output>.edit`), then the driver entry
  three more times as ordinary calls, then cleanup and one exit.
- anything else: the BBC command entry (`emit-bfx`, `check`, `info`, `bind`,
  usage).

Each of the three driver calls uses a variant of the driver entry whose graph
differs in three references only: its argument count and argument helpers
synthesize that step's command line from this process's own arguments (`edit
<dir>bbc-<target>.xax <output>.edit <output>.request.xax`, `resolve
<output>.request.xax <output>.xax`, `build <output>.xax <output>
<output>.provenance`), and its final `ExitProcess` is `SetLastError`, so the
step's exit status is read with `GetLastError` immediately after the call.
Every step still verifies its inputs; the intermediate request and snapshot
remain files. No other state passes between steps. Each step allocates and
releases the driver's views as before.

Install `bbc.exe` with the two host requests only; `xaxc.exe` is no longer
needed. Exits and outputs are those of the native compilation section above.
`bbc.exe` also answers the driver's own commands.

### Bootstrap

Build `bbc.exe` from `bbc.xax` with the generic SDK, choosing a lowering view
per function: functions of the driver entry's closure and the three step
variants use the driver recipe in [DRIVER.md](../windows_helpers/DRIVER.md);
every other function uses the recipe above (inline 11-parameter callee sites,
otherwise the parsed graph). The tested PE is 14,747,648 bytes, SHA-256
`4e5b03d49ce0759156e7f229c564c0816e214523423d455edc37d87b4d5afa01`.

The compile front is deliberately loop-free: its two loops (reading source and
writing the record) are small helper functions with at most four machine
arguments. An earlier front with its loops inline failed under the generic
bootstrap's register-resident x86-64 lowering: a loop-carried view pointer's
spill slot was shared with another value, so the record copy read a wrong
pointer. The graph was valid; this is the same bootstrap defect class recorded
above and remains open in the generic SDK.

### Evidence

[single_process_evidence.json](single_process_evidence.json), Wine and qemu
user emulation on Linux x86-64:

- 83 programs, O0/O1, both targets: 332 builds, 588 executions matching the
  reference interpreter; all 332 artifacts equal the multi-process pipeline's.
- Driver commands through `bbc.exe` give byte-identical exits, diagnostics,
  artifacts and provenance to the driver PE on 141 regression and
  declared-rejection stores.
- Error paths (invalid source, target, level, missing host request, missing
  output directory) give exits 1, 4, 4, 3, 3 and leave no files.

| Complete Android build, median of 10 (s) | Single process | Previous four processes | Python SDK path |
|---|---:|---:|---:|
| hello | 0.110 | 0.271 | 1.409 |
| nested_math | 0.113 | 0.272 | 1.347 |
| checksum_four | 0.111 | 0.275 | 1.444 |
| deep_nesting_512 | 0.883 | 0.993 | 13.094 |

All arms produce identical artifacts. One Wine launch (about 0.044 s) remains
in the single-process time; these are not Windows-native times and give no
competitor verdict. The remaining work in a small build is three driver entry
runs, each committing the driver's fixed views and re-reading and re-verifying
its inputs; handing verified stores between steps in memory is the next step.
