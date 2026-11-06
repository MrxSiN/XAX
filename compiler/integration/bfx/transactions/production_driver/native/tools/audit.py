# Per-function analysis and emission statuses the general program wrote, read even when it declines.
import sys
from pathlib import Path
import xax_compiler as X
import xax_selfhost_x86_64_general as XG
r = X.StoreReader(Path(sys.argv[1]).read_bytes())
module = next(o for o in r.objects() if o.kind == X.Kind.MODULE)
entry = next(r.get(c) for c in module.references if r.get(c).kind == X.Kind.FUNCTION)
target = next(r.get(c) for c in module.references if r.get(c).kind == X.Kind.TARGET)
native = XG.native_general()
words, members = XG.general_object_table(r, entry.cid, target, True, False)
resolve = X.store_resolver(r)
log = []
ra, re_ = XG._read_analysis, XG._read_emission
def ra2(take, value, n):
    a = ra(take, value, n); log.append(["analysis", a if isinstance(a, str) or a is None else "analysed"]); return a
def re2(take, f):
    m = re_(take, f); log.append(["emit", f.cid.hex()[:12], m if m is None or isinstance(m, str) else "code"]); return m
XG._read_analysis, XG._read_emission = ra2, re2

def collect(read):
    (count,) = read(1, 1)
    order = read(16, count * 4)
    cids = [b"".join(w.to_bytes(8, "big") for w in order[k:k + 4]) for k in range(0, len(order), 4)]
    closure = tuple(members[c] if c in members else resolve(c) for c in cids)
    try:
        XG.rebuild_views(XG._view_words(read), closure, resolve, True)
    except Exception as error:
        print("rebuild stopped:", repr(error)[:200])
    return None

native.run(words, collect)
for k in range(0, len(log) - 1, 2):
    print(k // 2, log[k][1], log[k + 1][1], log[k + 1][2])
