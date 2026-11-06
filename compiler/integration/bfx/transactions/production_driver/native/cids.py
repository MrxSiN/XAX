"""Read-only CIDs of a store that native listings do not show: `cids.py <store> root|module|target|entry|stubs <main>`."""
import sys
from pathlib import Path

import xax_compiler as X

reader = X.StoreReader(Path(sys.argv[1]).read_bytes())
module = next(o for o in reader.objects() if o.kind == X.Kind.MODULE)
what = sys.argv[2]
if what == "root":
    print(reader.root_cid.hex())
elif what == "module":
    print(module.cid.hex())
elif what in ("target", "entry"):
    kind = X.Kind.TARGET if what == "target" else X.Kind.FUNCTION
    print(next(c.hex() for c in module.references if reader.get(c).kind == kind))
elif what == "stubs":  # the two-node functions that call <main>, by the constant they carry
    resolve = X.store_resolver(reader)
    main = bytes.fromhex(sys.argv[3])
    for f in reader.objects():
        if f.kind != X.Kind.FUNCTION:
            continue
        graph = X.parse_function_graph(f, resolve)
        nodes = [n for b in graph.blocks for n in b.nodes]
        if len(nodes) == 2 and nodes[1].entity is not None and nodes[1].entity.cid == main:
            print(X._decode_constant(nodes[0].entity, resolve)[1], f.cid.hex())
