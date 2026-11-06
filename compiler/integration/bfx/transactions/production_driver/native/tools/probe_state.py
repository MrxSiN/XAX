# Probe of the general program's state where a native build stops: status words, the analysis area (E_F, R_*),
# the image slots (I_LEN = slot 211 of G_RA), and the closure order.  Usage: probe_state.py <store with a module>
import sys
from pathlib import Path
import xax_compiler as X
import xax_selfhost_x86_64_general as XG
import xax_selfhost_views_backend as V
import xax_selfhost_general_emit as EM
import xax_selfhost_general_regalloc as RA
r = X.StoreReader(Path(sys.argv[1]).read_bytes())
module = next(o for o in r.objects() if o.kind == X.Kind.MODULE)
entry = next(r.get(c) for c in module.references if r.get(c).kind == X.Kind.FUNCTION)
target = next(r.get(c) for c in module.references if r.get(c).kind == X.Kind.TARGET)
native = XG.native_general()
words, members = XG.general_object_table(r, entry.cid, target, False, False)
listed = list(r.objects())


def collect(read):
    (count,) = read(1, 1)
    order = read(16, count * 4)
    cids = [b"".join(w.to_bytes(8, "big") for w in order[k:k + 4]) for k in range(0, len(order), 4)]
    (ra,) = read(V.GLOBALS + 60, 1)
    f = read(ra + EM.E_F, 1)[0]
    fail = read(ra + EM.E_FAIL, 1)[0]
    print("count", count, "ra", ra, "E_F", f, "E_FAIL", fail)
    for name in ("R_NPARAMS", "R_NRETURNS", "R_ELIGIBLE"):
        if hasattr(RA, name): print(name, read(ra + getattr(RA, name), 1)[0])
    if f < len(listed): print("E_F object", listed[f].kind, listed[f].cid.hex()[:16])
    print("status", read(0, 4)); print("image slots", read(ra + 210, 22)); print("F162 at", [k for k, c in enumerate(cids) if c.hex().startswith("51514b76")], "first", cids[0].hex()[:16])
    print("last in order", cids[-1].hex()[:16] if cids else None)
    return None


native.run(words, collect)
