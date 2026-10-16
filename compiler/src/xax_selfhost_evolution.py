"""Self-hosting step S15d.2 (ADR-305): the committed compiler stores are authoritative; the evolution ledger.

Until S15d the general driver's store was exactly what its Python builder made (``build_general_driver_program``).
From S15d.2 the builders are a *baseline*: the committed store is the baseline with the transactions of the evolution
ledger applied in order, each by the production compiler's ``edit`` command (S15d.1).  The compiler is changed by
adding a transaction to the ledger, not by editing a builder.

``bootstrap/evolution/`` holds one edit record per transaction (``NNNN-name.edit``, ``xax_selfhost_edit``'s format)
and ``LEDGER``, a text list of them in order, each with the query that located its nodes::

    <record file> <query name>

A record names nodes by their function's CID, so it applies to one baseline.  When the baseline changes, ``rebase``
derives each record again from its query (``QUERIES``: read-only tooling over the baseline store) and the ledger is
reviewed; a record is never edited by hand.

``evolve`` applies the ledger with ``xax_selfhost_edit.apply_reference`` (the Python reference, equal to the XAX
engine and to ``Workspace.commit``), so ``test_store_regeneration`` checks the committed store on every host; on Linux
x86-64 ``tests/test_xax_selfhost_evolution.py`` checks that the production compiler's ``edit`` makes the same stores.
"""

from __future__ import annotations

from pathlib import Path

from xax_native import bootstrap_dir

EVOLUTION_DIRECTORY = bootstrap_dir() / "evolution"
GENERAL_STORE_PATH = bootstrap_dir() / "xax_compiler_driver_general.xax"  # the store the ledger evolves
LEDGER_PATH = EVOLUTION_DIRECTORY / "LEDGER"


def entries() -> list[tuple[Path, str]]:
    """``(record path, query name)`` per ledger line, in order."""
    if not LEDGER_PATH.exists():
        return []
    found = []
    for line in LEDGER_PATH.read_text(encoding="ascii").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            record, query = line.split()
            found.append((EVOLUTION_DIRECTORY / record, query))
    return found


def evolve(reader):
    """``reader`` with every ledger transaction applied in order."""
    from xax_selfhost_edit import apply_reference

    for record, _query in entries():
        reader = apply_reference(reader, record.read_bytes())
    return reader


def build_evolved_general():
    """``(reader, entry)``: the general driver's baseline with the ledger applied; the committed store is this."""
    from xax_compiler import Kind
    from xax_selfhost_driver import build_general_driver_program

    reader, _entry = build_general_driver_program()
    reader = evolve(reader)
    module = next(item for item in reader.objects() if item.kind == Kind.MODULE)
    return reader, next(reader.get(cid) for cid in module.references if reader.get(cid).kind == Kind.FUNCTION)


# -- queries (read-only tooling: which nodes a transaction changes) -------------------------------------------------

def _main_graph(reader):
    import xax_compiler as X

    module = next(item for item in reader.objects() if item.kind == X.Kind.MODULE)
    main = next(reader.get(cid) for cid in module.references if reader.get(cid).kind == X.Kind.FUNCTION)
    graph = X._parse_graph(reader.get(main.references[X.Cursor(main.body, "").uleb()]), reader.get)
    return main, graph


def _constant_value(node):
    import xax_compiler as X

    return int.from_bytes(node.entity.body[2:], "little") if node.operation == X.Operation.CONSTANT else None


def query_inputs_limit(reader, limit: int = 100) -> list[tuple]:
    """S15d.3 (ADR-306): raise the external input files a command takes from 64 to ``limit``.  Two facts change in the
    driver's function: the argument check's bound (the constant 64 compared, unsigned, below the count of extra
    arguments) and the staged digest's place in the workspace (``INPUTS_AT`` + 64 * 32 + k, which must stay above the
    sorted list of ``limit`` digests: it moves to ``INPUTS_AT`` + 4096 + k)."""
    import xax_compiler as X
    from xax_selfhost_edit import SET_CONSTANT
    from xax_selfhost_request import INPUTS_AT

    old_limit, old_staged, new_staged = 64, INPUTS_AT + 64 * 32, INPUTS_AT + 4096
    if limit * 32 > new_staged - INPUTS_AT:
        raise ValueError("the sorted digests would reach the staged one")
    main, graph = _main_graph(reader)
    mutations = []
    for b, block in enumerate(graph.blocks):
        for n, node in enumerate(block.nodes):
            if node.operation == X.Operation.INT_COMPARE and node.attributes == (int(X.IntCompare.ULT),) and node.operands[0].tag == 1:
                source = node.operands[0]
                if _constant_value(graph.blocks[source.block].nodes[source.index]) == old_limit:
                    mutations.append((SET_CONSTANT, main.cid, source.block, source.index, old_limit, limit))
    if len(mutations) != 1:
        raise ValueError(f"the argument check's bound: {len(mutations)} candidates")
    for b, block in enumerate(graph.blocks):
        for n, node in enumerate(block.nodes):
            value = _constant_value(node)
            if value is not None and old_staged <= value < old_staged + 32:
                mutations.append((SET_CONSTANT, main.cid, b, n, value, value - old_staged + new_staged))
    if len(mutations) < 1 + 32:
        raise ValueError("the staged digest's places")
    return mutations


def query_dead_constants(reader) -> list[tuple]:
    """S15d.4b (ADR-314): the driver's function holds constants nothing uses (each builder idiom that materialized a
    constant on a path that then did not need it); delete them.  A constant is pure, so ``DeleteNode`` takes it when it
    has no use: no node operand, terminator value or edge argument names it."""
    import xax_compiler as X
    from xax_selfhost_edit import DELETE_NODE

    main, graph = _main_graph(reader)
    used = set()
    for block in graph.blocks:
        values = [value for node in block.nodes for value in node.operands]
        values += list(block.terminator.values) + [value for _target, arguments in block.terminator.edges for value in arguments]
        used.update((value.block, value.index) for value in values if value.tag == 1)
    mutations = [(DELETE_NODE, main.cid, b, n) for b, block in enumerate(graph.blocks) for n, node in enumerate(block.nodes)
                 if node.operation == X.Operation.CONSTANT and (b, n) not in used]
    if not mutations:
        raise ValueError("no unused constant")
    return mutations


QUERIES = {"inputs_limit": query_inputs_limit, "dead_constants": query_dead_constants}
INPUTS_LIMIT = 100  # the committed compiler's external-input bound since ledger entry 0001 (the baseline's is 64)


def rebase(reader=None) -> list[Path]:
    """Derive every record again from its query over the baseline (``reader``: default, the builder's), applying the
    earlier ones first; the records are rewritten for review."""
    from xax_selfhost_driver import build_general_driver_program
    from xax_selfhost_edit import apply_reference, edit_record

    if reader is None:
        reader = build_general_driver_program()[0]
    written = []
    for record, query in entries():
        data = edit_record(QUERIES[query](reader))
        record.write_bytes(data)
        written.append(record)
        reader = apply_reference(reader, data)
    return written


if __name__ == "__main__":
    import sys

    if sys.argv[1:] == ["rebase"]:
        for path in rebase():
            print(path)
    else:
        raise SystemExit("usage: python -m xax_selfhost_evolution rebase")
