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

These commands execute without Python. Full native executable/library compilation
is not implemented by this host. Bootstrap and native-code generation still use
the unchanged Windows-hosted generic SDK. No `bbc compile` command is claimed.
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
