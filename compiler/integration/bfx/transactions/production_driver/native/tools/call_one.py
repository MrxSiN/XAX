# A PE (or Linux) entry calling one BBC function: bits parameters are constants, each ptr/view/mem triple a fresh
# VirtualAlloc'd view; results' triples are freed and the first bits result is the exit status.
import os, sys
from pathlib import Path
import xax_compiler as X
from xax_compiler import Kind, Operation, bits_type, object_with_refs, x86_64_windows_pe_target, StoreReader, write_store
from xax_graph_builder import GraphBuilder
from xax_platform import win32_kernel32_api
from xax_selfhost_x86_64_general import general_with_xax

bbc = StoreReader(Path(sys.argv[3] if len(sys.argv) > 3 else "integration/bfx/bbc.xax").read_bytes())
api = win32_kernel32_api()
B32, B64 = bits_type(32), bits_type(64)
mem = api.memory_effect
fn = next(o for o in bbc.objects() if o.kind == Kind.FUNCTION and o.cid.hex().startswith(sys.argv[1]))
objs, todo = {}, [fn.cid]
while todo:
    c = todo.pop()
    if c in objs: continue
    objs[c] = bbc.get(c); todo.extend(objs[c].references)
b_ = fn.body; n = b_[1]
P = [bbc.get(fn.references[i]) for i in b_[2:2 + n]]; m = b_[2 + n]
R = [bbc.get(fn.references[i]) for i in b_[3 + n:3 + n + m]]
nmem = sum(1 for t in P if t.cid == mem.cid)
g = GraphBuilder(); g.track(*api.types, B32, B64, *P, *R)
b = g.block(api.process_effect, api.filesystem_effect, *(mem,) * nmem)
process, fs, *mems = b.params
args, k, i = [], 0, 0
while i < len(P):
    t = P[i]
    if X._heap_view_info(P[i + 1]) is not None if i + 1 < len(P) else False:
        ext = X._heap_view_info(P[i + 1])[0]
        raw, owner, mm = b.op(Operation.CALL_FOREIGN, (b.const(B64, 0), b.const(B64, ext), b.const(B32, 0x3000), b.const(B32, 4), mems[k]),
                              (api.heap_ptr_rw, api.heap_resource, mem), entity=api.virtual_alloc)
        v, tok, mm = b.op(Operation.HEAP_VIEW, (raw, owner, mm), (t, P[i + 1], mem), attributes=(ext, 8))
        args += [v, tok, mm]; k += 1; i += 3
    else:
        args.append(b.const(t, 1)); i += 1
outs = list(b.op(Operation.CALL_DIRECT, tuple(args), tuple(R), entity=fn))
status, done, frees, i = None, [], [], 0
while i < len(R):
    if i + 1 < len(R) and X._heap_view_info(R[i + 1]) is not None:
        free = api.virtual_free_view(R[i + 1], R[i]); frees.append(free)
        done.append(b.op(Operation.CALL_FOREIGN, (outs[i], b.const(B64, 0), b.const(B32, 0x8000), outs[i + 1], outs[i + 2]), (B32, mem), entity=free)[1])
        i += 3
    else:
        if status is None and R[i].cid in (B64.cid, B32.cid):
            status = outs[i] if R[i].cid == B32.cid else b.op1(Operation.INT_TRUNCATE, (outs[i],), B32)
        i += 1
status = status or b.const(B32, 0)
process = b.op1(Operation.CALL_FOREIGN, (status, process), api.process_effect, entity=api.exit_process)
b.ret(status, process, fs, *done)
entry = g.function((api.process_effect, api.filesystem_effect, *(mem,) * nmem), (B32, api.process_effect, api.filesystem_effect, *(mem,) * len(done)))
target = x86_64_windows_pe_target()
module = object_with_refs(Kind.MODULE, [entry, target])
root = object_with_refs(Kind.PROGRAM_ROOT, [module])
by = {o.cid: o for o in (*api.types, *api.symbols, *frees, *g.objects.values(), entry, target, module, root, *objs.values())}
keep, todo = {}, [root.cid]
while todo:
    c = todo.pop()
    if c in keep: continue
    keep[c] = by[c]; todo.extend(by[c].references)
r = StoreReader(write_store(root.cid, list(keep.values())))
Path(sys.argv[2]).write_bytes(r.data)
X.verify_store(r)
print("verified", len(keep), "objects", flush=True)
