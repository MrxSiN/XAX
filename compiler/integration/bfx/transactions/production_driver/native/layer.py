"""Read-only: BBC's layer in a BBC driver store, for layer.sh.  `layer.py <BBC driver store> <W2 store>`

The layer is what BBC's entry (the module's entry) reaches without entering the driver: the walk stops at functions the
W2 store holds (driver helpers, by CID) and at the entry's callees with 24 or more parameters (the driver entry and its
variants).  Prints one line per layer function, breadth first: its CID, then its callees' CID prefixes (`*` = in W2).
"""
import sys
from pathlib import Path

import xax_compiler as X

store = X.StoreReader(Path(sys.argv[1]).read_bytes())
base = {o.cid for o in X.StoreReader(Path(sys.argv[2]).read_bytes()).objects() if o.kind == X.Kind.FUNCTION}
resolve = X.store_resolver(store)
module = next(o for o in store.objects() if o.kind == X.Kind.MODULE)
entry = next(c for c in module.references if store.get(c).kind == X.Kind.FUNCTION)


def callees(cid):
    found = []
    for block in X.parse_function_graph(store.get(cid), resolve).blocks:
        for node in block.nodes:
            if node.entity is not None and node.entity.kind == X.Kind.FUNCTION and node.entity.cid not in found:
                found.append(node.entity.cid)
    return found


stops = {c for c in callees(entry) if c not in base and store.get(c).body[1] >= 24}
seen, pending = set(), [entry]
while pending:
    cid = pending.pop(0)
    if cid in seen or cid in base or cid in stops:
        continue
    seen.add(cid)
    called = [c for c in callees(cid) if c not in stops]
    pending.extend(called)
    print(cid.hex(), " ".join(c.hex()[:8] + ("*" if c in base else "") for c in called), flush=True)
