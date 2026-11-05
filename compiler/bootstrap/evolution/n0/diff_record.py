# N0 (ADR-367, ADR-370): a ledger record turning store OLD into store NEW, both made by the authoring worktree.  Walk both
# roots in parallel; where an object keeps its kind and reference count, descend into the reference that changed (by
# position, or the one reference only each side has when sorted references moved); at a graph, or where the shapes
# differ, replace the reference at its owner (REPLACE_REFERENCE) and carry the new object's closure.
# Usage (from compiler/, PYTHONPATH=src:reference:.): diff_record.py <old store> <new store> <out record>
import sys
from pathlib import Path
import xax_compiler as X
from xax_selfhost_edit import REPLACE_REFERENCE, edit_record

old, new = (X.StoreReader(Path(p).read_bytes()) for p in sys.argv[1:3])
present = {o.cid for o in old.objects()}
muts, seen = [], set()


def walk(a, b):
    """Objects a (old) and b (new) stand at the same place; a != b."""
    if (a, b) in seen:
        return
    seen.add((a, b))
    oa, ob = old.get(a), new.get(b)
    assert oa.kind == ob.kind and len(oa.references) == len(ob.references), "roots differ in shape"
    if oa.body == ob.body:
        pairs = [(ra, rb) for ra, rb in zip(oa.references, ob.references) if ra != rb]
    else:  # sorted references moved: pair the one reference only the old has with the one only the new has
        only_a = [r for r in oa.references if r not in set(ob.references)]
        only_b = [r for r in ob.references if r not in set(oa.references)]
        assert len(only_a) == len(only_b) == 1, "roots differ in shape"
        pairs = [(only_a[0], only_b[0])]
    for ra, rb in pairs:
        if ob.kind == X.Kind.GRAPH_FRAGMENT or not shape(ra, rb):
            muts.append((REPLACE_REFERENCE, a, ra, rb))
        else:
            walk(ra, rb)


def shape(a, b):
    oa, ob = old.get(a), new.get(b)
    if oa.kind != ob.kind or len(oa.references) != len(ob.references) or oa.kind == X.Kind.GRAPH_FRAGMENT:
        return False
    return oa.body == ob.body or len(set(oa.references) - set(ob.references)) == 1


assert old.root_cid != new.root_cid
walk(old.root_cid, new.root_cid)
carried, pending = {}, [m[3] for m in muts]
while pending:
    c = pending.pop()
    if c in present or c in carried:
        continue
    o = new.get(c)
    carried[c] = o
    pending.extend(o.references)
Path(sys.argv[3]).write_bytes(edit_record(muts, objects=list(carried.values())))
print([(m[1].hex()[:12], m[2].hex()[:12], m[3].hex()[:12]) for m in muts])
print(Path(sys.argv[1]).name, "mutations", len(muts), "owners", len({m[1] for m in muts}), "carried", len(carried),
      "bytes", Path(sys.argv[3]).stat().st_size)
