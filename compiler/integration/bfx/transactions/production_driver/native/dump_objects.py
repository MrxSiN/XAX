# Prints `define @name` / `object <kind> 0x<body> <refs>` / `end` for the named objects of a store (data, copied).
# Usage: dump_objects.py <store> <name>=<cid prefix> ...
import sys
from pathlib import Path
import xax_compiler as X
r = X.StoreReader(Path(sys.argv[1]).read_bytes())
index = {o.cid.hex(): o for o in r.objects()}
for item in sys.argv[2:]:
    name, prefix = item.split("=")
    (cid,) = [c for c in index if c.startswith(prefix)]
    o = index[cid]
    refs = "".join(" " + ref.hex() for ref in o.references)
    print(f"define @{name}\nobject {int(o.kind)} 0x{o.body.hex()}{refs}\nend")
