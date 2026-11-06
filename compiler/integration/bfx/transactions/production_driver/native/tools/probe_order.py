# The closure order around the stop (indices 541-543 here: edit for the case) and the view globals G_VCOUNT, G_BCOUNT.
# Usage: probe_order.py <store with a module>
import sys
from pathlib import Path
import xax_compiler as X
import xax_selfhost_x86_64_general as XG
import xax_selfhost_general_view as GV
from xax_selfhost_views_backend import GLOBALS
r = X.StoreReader(Path(sys.argv[1]).read_bytes())
module = next(o for o in r.objects() if o.kind == X.Kind.MODULE)
entry = next(r.get(c) for c in module.references if r.get(c).kind == X.Kind.FUNCTION)
target = next(r.get(c) for c in module.references if r.get(c).kind == X.Kind.TARGET)
words, members = XG.general_object_table(r, entry.cid, target, False, False)
def collect(read):
    (count,) = read(1, 1)
    order = read(16, count * 4)
    cids = [b"".join(w.to_bytes(8, "big") for w in order[k:k + 4]) for k in range(0, len(order), 4)]
    print("status", read(0, 2), "count", count)
    for k in (541, 542, 543):
        if k < len(cids): print(k, cids[k].hex())
    g = read(GLOBALS, 64)
    print("VCOUNT", g[GV.G_VCOUNT], "BCOUNT", g[GV.G_BCOUNT])
XG.native_general().run(words, collect)
