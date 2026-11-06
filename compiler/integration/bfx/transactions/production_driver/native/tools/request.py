# Experiment: a build request for a BBC driver store (its module's entry, its PE target), as compiler_request makes one.
import sys
from pathlib import Path
import xax_compiler as X
from xax_build import build_profile, build_request, package
X._WRITER_ATTEMPTED, X._NATIVE_WRITER = True, None
r = X.StoreReader(Path(sys.argv[1]).read_bytes())
module = next(o for o in r.objects() if o.kind == X.Kind.MODULE)
entry = next(r.get(c) for c in module.references if r.get(c).kind == X.Kind.FUNCTION)
target = next(r.get(c) for c in module.references if r.get(c).kind == X.Kind.TARGET)
app = package(b"bbc", (module,), build_entries=((b"bbc", entry),))
profile = build_profile()
request = build_request(app, b"bbc", target, profile)
by = {o.cid: o for o in (*r.objects(), app, target, profile, request)}
reached, pending = {}, [request.cid]
while pending:
    c = pending.pop()
    if c not in reached:
        reached[c] = by[c]; pending.extend(by[c].references)
Path(sys.argv[2]).write_bytes(X.StoreReader.from_objects(request.cid, reached.values()).data)
print("request objects", len(reached))
