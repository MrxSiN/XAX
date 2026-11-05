# N0 (ADR-367, ADR-370): a ledger record turning store OLD into store NEW, both made by the authoring worktree.  Walk both
# roots in parallel; where an object keeps its kind and reference count, descend into the references that changed (the
# references only each side has, paired by kind where several changed; by position where references repeat); at a
# graph, or where the shapes differ, replace the reference at its owner (REPLACE_REFERENCE) and carry the new object's
# closure.
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
    # the references only the old has and only the new has (sorted references may have moved)
    only_a = [r for r in oa.references if r not in set(ob.references)]
    only_b = [r for r in ob.references if r not in set(oa.references)]
    if len(only_a) != len(only_b):  # duplicates: pair by position
        assert oa.body == ob.body, "roots differ in shape"
        pairs = [(ra, rb) for ra, rb in zip(oa.references, ob.references) if ra != rb]
    else:
        if len(only_a) == 1:
            pairs = [(only_a[0], only_b[0])]
        else:  # several: pair them by kind, which must then be distinct
            kinds_a, kinds_b = {old.get(r).kind: r for r in only_a}, {new.get(r).kind: r for r in only_b}
            assert len(kinds_a) == len(only_a) and kinds_a.keys() == kinds_b.keys(), "roots differ in shape"
            pairs = [(kinds_a[k], kinds_b[k]) for k in kinds_a]
    for ra, rb in pairs:
        if ob.kind == X.Kind.GRAPH_FRAGMENT or not shape(ra, rb):
            muts.append((REPLACE_REFERENCE, a, ra, rb))
        else:
            walk(ra, rb)


def shape(a, b):
    oa, ob = old.get(a), new.get(b)
    if oa.kind != ob.kind or len(oa.references) != len(ob.references) or oa.kind == X.Kind.GRAPH_FRAGMENT:
        return False
    return oa.body == ob.body or len(set(oa.references) - set(ob.references)) >= 1


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
