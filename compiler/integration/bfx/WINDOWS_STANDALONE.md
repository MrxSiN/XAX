# Standalone Windows decision process

`standalone_windows.xax` is a canonical XAX host for a complete Windows
x86-64 PE executable. It calls the verified decision directly and imports
only kernel32 functions. It needs no separate test host, decision DLL,
Brainfuck interpreter or C runtime.

Bind an imported decision with an expected-root transaction. The supplied
`standalone_windows_hello.edit` binds the hello example. Source mutations
must continue through verified workspace transactions; construction tools
are external and are not maintained implementation source.

## Process contract

The process buffers binary stdin until EOF, accepting at most 65,536 bytes.
It owns three distinct zero-initialized 65,536-byte views and a four-byte
transfer counter. Each successful call still clears the entire decision tape.
The host checks the decision status and output length before publishing output.
Language failures discard any output prefix.

| Exit | Meaning |
|---|---|
| 0 | Success |
| 1 | Executed tape movement exceeded bounds |
| 2 | Decision output capacity exhausted |
| 3 | Input exceeds 65,536 bytes |
| 5 | Read/write failure or invalid returned output length |

ReadFile accumulates fragments; an empty read or broken input pipe ends input.
Checked eight-byte and tail-byte copies assemble input. After the decision,
the input allocation becomes a write-staging buffer. WriteFile loops over
partial transfers and rejects zero progress. All ordinary completion paths
release all four allocations before ExitProcess. Allocation failure takes
the existing checked heap-view trap. An OS write failure can publish a prefix;
the caller must discard output on nonzero exit.

The 196,612 declared buffer bytes are allocation sizes, not resident RAM.
The separately measured process resource results include loader and startup
costs. No instruction budget or altered nontermination behavior is introduced.

## Build configuration

The recorded Windows bootstrap uses unchanged generic XAX verification,
graph inlining, x86-64 lowering and PE emission. It does not modify a Python
compiler module or implement a Brainfuck/BFX algorithm externally.

The plain default PE lowering path declines larger bound programs: its
register path accepts at most four machine arguments, while the decision
has five, and the fallback cannot handle the returned borrowed views at
that call. The recorded configuration uses the existing generic graph
splicing operations to inline the decision into a **derived lowering view**.
That view is supplied through the existing `views`/`prefetches` lowering
interface after canonical verification. It is not serialized as authoritative
source and does not supply a new proof. Its construction, verification and
lowering costs are included in the fresh-process build measurements.

From the repository root, apply the binding with the unchanged transaction
API (`xax_selfhost_edit.apply_reference`) and save through `Workspace.save`.
For the resulting verified reader `r`, entry function `main` and bound
decision `core`, the recorded generic lowering configuration is:

```python
import xax_inline as I
from xax_compiler import Kind, Operation, parse_function_graph, x86_64_windows_pe_target
from xax_x86_64 import _compile_native_with_target
from xax_pe import emit_pe_executable

graph = parse_function_graph(main, r.get)
blocks, entry = I._lift(graph)
sites = [(block, n) for block in blocks for n, item in enumerate(block.nodes)
         if item.node.operation == Operation.CALL_DIRECT
         and item.node.entity.cid == core.cid]
assert len(sites) == 1
block, position = sites[0]
I._splice(blocks, block, position, parse_function_graph(core, r.get))
while (I._merge_blocks(blocks, entry) or I._thread_jumps(blocks, entry)
       or I._store_truncations(blocks, r.get)
       or I._local_parameters(blocks, entry) or I._dead_code(blocks)):
    pass
view = I._lower(graph, I._layout(blocks, entry), entry)
views = {o.cid: parse_function_graph(o, r.get)
         for o in r.objects() if o.kind == Kind.FUNCTION}
views[main.cid] = view
image = _compile_native_with_target(
    r, main.cid, x86_64_windows_pe_target(), verified=True,
    views=views, prefetches={cid: {} for cid in views})
executable_bytes = emit_pe_executable(image)
```

`verified=True` is valid only after the ordinary verifier has accepted the
complete canonical store. The private generic bootstrap APIs above are
revision-dependent. This is not a completed native XAX compiler-host path;
the separate Windows native driver remains bounded.

## Validation

The [execution report](standalone_windows_evidence.json) records 23 native
decision programs and 28 host checks:
the existing interpreter-equivalence corpus, prefix failure, output overflow,
65,025-byte output, maximum/excess input, fragmented binary pipes and invalid
standard handles. Empty and hello executables rebuild byte for byte. The native
Windows driver replays the public binding, verifies its result and rejects
the stale root. Runtime replay records native authority separately from the
bootstrap verifier/lowerer's fallback authority.

Forced short OS writes and allocation failures were not injected. The code
contains partial-write handling. Performance scope and raw samples belong
to the separate build/resource comparison report; earlier Android snapshots
remain unchanged.
