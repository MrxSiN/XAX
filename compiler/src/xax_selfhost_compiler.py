"""Self-hosting step S14b (ADR-285): the production compiler as a canonical build request.

The production compiler on Linux x86-64 is the general driver (``xax_compiler_driver_general.xax``).  Its canonical
package names the driver store's module and one build entry, ``xaxc``: the driver function, the Linux process entry.
Its request builds that entry for ``x86_64-linux-elf-exec-v1`` with the default profile, one native image.  The request
store holds the request and everything it reaches; the compiler resolves it (``resolve``, S13c) to its snapshot store
and builds the snapshot (``build``, S13a) into the next compiler and its provenance.

Everything here is derived from the committed driver store, deterministically; nothing is a second copy of the
compiler.
"""

from __future__ import annotations

from xax_build import build_profile, build_request, package
from xax_compiler import Kind, StoreReader, x86_64_linux_exec_target

COMPILER_PACKAGE = b"xax-compiler"
COMPILER_ENTRY = b"xaxc"


def compiler_request(reader: StoreReader | None = None):
    """``(request store, request object)`` for the driver store ``reader`` (default: the committed one)."""
    if reader is None:
        from xax_selfhost_driver import GENERAL_STORE_PATH

        reader = StoreReader(GENERAL_STORE_PATH.read_bytes())
    module = next(item for item in reader.objects() if item.kind == Kind.MODULE)
    entry = next(reader.get(cid) for cid in module.references if reader.get(cid).kind == Kind.FUNCTION)
    target = x86_64_linux_exec_target()
    app = package(COMPILER_PACKAGE, (module,), build_entries=((COMPILER_ENTRY, entry),))
    profile = build_profile()
    request = build_request(app, COMPILER_ENTRY, target, profile)
    by_cid = {item.cid: item for item in (*reader.objects(), app, target, profile, request)}
    reached, pending = {}, [request.cid]
    while pending:
        cid = pending.pop()
        if cid not in reached:
            reached[cid] = by_cid[cid]
            pending.extend(by_cid[cid].references)
    return StoreReader.from_objects(request.cid, reached.values()), request
