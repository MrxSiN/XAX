"""Drives the native XAX compiler over the seed store: ``edit`` -> ``resolve`` -> ``build``.

Development/verification tooling, never part of the deployed server's request path.  ``make_record`` needs the pinned
XAX Python tooling (it names a constant node by its function CID, block and position, as the ``XAXEDIT1`` carrier
requires); ``run_chain`` and the server invoke only the native compiler executable.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def _xax(xax_src: Path):
    sys.path.insert(0, str(xax_src))
    from xax_compiler import (Kind, Operation, _decode_constant, _decode_function_interface, _parse_graph,
                              store_resolver)
    from xax_selfhost_edit import SET_CONSTANT, edit_record
    from xax_workspace import Workspace

    return Kind, Operation, _decode_constant, _decode_function_interface, _parse_graph, store_resolver, Workspace, edit_record, SET_CONSTANT


def make_record(xax_src: Path, store_path: Path, value: int) -> tuple[bytes, int]:
    """An ``XAXEDIT1`` record that sets the first constant in the store to ``value``.  Returns (record, old value)."""
    Kind, Operation, _decode_constant, _decode_function_interface, _parse_graph, store_resolver, Workspace, edit_record, SET_CONSTANT = _xax(xax_src)
    workspace = Workspace.load(store_path)
    resolve = store_resolver(workspace.reader)
    for obj in tuple(workspace.reader.objects()):
        if obj.kind != Kind.FUNCTION:
            continue
        graph_object, _, _ = _decode_function_interface(resolve(obj.cid), resolve)
        graph = _parse_graph(graph_object, resolve)
        for block_index, block in enumerate(graph.blocks):
            for node_index, node in enumerate(block.nodes):
                if node.operation == Operation.CONSTANT:
                    _type, old = _decode_constant(node.entity, resolve)
                    record = edit_record([(SET_CONSTANT, obj.cid, block_index, node_index, old, value)],
                                         expected_root=workspace.root)
                    return record, old
    raise SystemExit(f"no constant node in {store_path}")


def run_chain(compiler: Path, seed: Path, work: Path, record: bytes) -> dict:
    """Run the native ``edit``/``resolve``/``build`` chain; returns a summary or raises on rejection."""
    work.mkdir(parents=True, exist_ok=True)
    record_path, next_path = work / "edit.rec", work / "next.xax"
    snapshot_path, artifact_path, provenance_path = work / "snapshot.xax", work / "artifact.exe", work / "artifact.prov"
    record_path.write_bytes(record)
    for stale in (next_path, snapshot_path, artifact_path, provenance_path):
        stale.unlink(missing_ok=True)

    def run(*args):
        return subprocess.run([str(compiler), *map(str, args)], capture_output=True)

    edit = run("edit", seed, record_path, next_path)
    if edit.returncode != 0:
        raise SystemExit(f"edit rejected ({edit.returncode}): {next_path.read_bytes()[:120]!r}")
    resolve = run("resolve", next_path, snapshot_path)
    if resolve.returncode != 0:
        raise SystemExit(f"resolve rejected ({resolve.returncode}): {snapshot_path.read_bytes()[:120]!r}")
    build = run("build", snapshot_path, artifact_path, provenance_path)
    if build.returncode != 0:
        raise SystemExit(f"build rejected ({build.returncode}): {artifact_path.read_bytes()[:120]!r}")
    return {"root": next_path.read_bytes()[7:39].hex(),
            "artifact_bytes": artifact_path.stat().st_size,
            "provenance_bytes": provenance_path.stat().st_size,
            "provenance_hex": provenance_path.read_bytes().hex()}


if __name__ == "__main__":
    import json

    xax_src, compiler, seed, work = (Path(sys.argv[i]) for i in range(1, 5))
    record, old = make_record(xax_src, seed, int(sys.argv[5]) if len(sys.argv) > 5 else 41)
    print(json.dumps({"old": old, "record_bytes": len(record), **run_chain(compiler, seed, work, record)}, indent=1))
