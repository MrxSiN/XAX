"""BBC Brainfuck decisions as Android ``bfc_call_v1`` shared libraries.

``integration/bfx/shared_arm64.xax`` is a canonical host whose one export, ``bfc_call_v1``, calls an empty
decision: the standalone ARM64 host's own empty decision object, so ``bbc bind android-arm64`` records bind it.
``bind`` retargets such a record (its expected root and the graph owning the decision reference) and applies it
with the reference transaction applier; ``build`` lowers the bound host to an ET_DYN for the Android integer
target.  Nothing here parses BFX or Brainfuck: the decision and every supplied object come from BBC's record.

C ABI (AAPCS64), as the libbrainfuckc bridge calls it::

    uint64_t bfc_call_v1(const uint8_t *in, uint64_t in_len, uint8_t *out, uint64_t out_cap,
                         uint8_t *tape, uint64_t tape_len, uint64_t budget, uint64_t *out_len);

Status 0 success, 2 output capacity, 3 tape movement out of bounds or a rejected call.  A call rejects without
touching any buffer unless ``tape_len >= 65536``, ``in_len <= 65536`` and ``out_cap <= 65536``.  The decision reads
only ``in[0, in_len)``, writes only ``out[0, out_cap)``, zeroes and uses all of ``tape[0, 65536)`` and stores
``*out_len`` after it returns; BBC has no instruction budget, so ``budget`` is ignored.
"""

from __future__ import annotations

import sys
import sysconfig
from pathlib import Path

from xax_compiler import Kind, StoreReader, android_arm64_shared_integer_target, verify_store
from xax_selfhost_edit import REPLACE_REFERENCE, apply_reference, edit_record, parse_record

HOST = Path(__file__).resolve().parents[1] / "integration/bfx/shared_arm64.xax"
if not HOST.is_file():
    HOST = Path(sysconfig.get_path("data")) / "share/xax/bfx/shared_arm64.xax"
EXPORT = b"bfc_call_v1"


def _owner(reader: StoreReader, child: bytes) -> bytes:
    owners = [item.cid for item in reader.objects() if item.kind == Kind.GRAPH_FRAGMENT and child in item.references]
    if len(owners) != 1:
        raise ValueError(f"expected one graph referencing the decision, found {len(owners)}")
    return owners[0]


def bind(record: bytes, host: StoreReader | None = None) -> StoreReader:
    """The host with the decision of one ``bbc bind`` record (any host target) bound, verified."""
    host = host or StoreReader(HOST.read_bytes())
    _root, mutations, objects = parse_record(record, with_objects=True)
    if len(mutations) != 1 or mutations[0][0] != REPLACE_REFERENCE:
        raise ValueError("a BBC bind record replaces exactly one reference")
    _kind, _owner_cid, old, new = mutations[0]
    retargeted = edit_record(((REPLACE_REFERENCE, _owner(host, old), old, new),), host.root_cid, objects)
    bound = apply_reference(host, retargeted)
    verify_store(bound)
    return bound


def build(bound: StoreReader, soname: bytes = b"libbbc.so") -> bytes:
    from xax_android import AndroidExport, compile_android_shared

    root = bound.get(bound.root_cid)
    module = bound.get(root.references[0])
    entry = next(cid for cid in module.references if bound.get(cid).kind == Kind.FUNCTION)
    return compile_android_shared(bound, [AndroidExport(EXPORT, entry)], target_object=android_arm64_shared_integer_target(),
                                  soname=soname).data


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit("usage: python -m xax_android_bfc <bbc bind record> <output.so>")
    output = Path(sys.argv[2])
    output.write_bytes(build(bind(Path(sys.argv[1]).read_bytes()), output.name.encode()))
