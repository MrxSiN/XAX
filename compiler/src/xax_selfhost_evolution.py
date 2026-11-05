"""Self-hosting step W2 (ADR-361): the committed self-hosting stores are frozen; the evolution ledger.

S15d.2 (ADR-305) made the general driver's store its Python builder's baseline with the transactions of an evolution
ledger applied.  From W2 there is no builder baseline: every self-hosting store under ``bootstrap/`` is *frozen*, the
committed file is its source, and it changes only by transactions of the production compiler's ``edit`` command
(``xaxc edit <store> <record> <out>``, then ``xaxc verify``), each recorded in the ledger.  The Python builders that made
these stores were deleted; nothing regenerates a frozen store from Python.

``bootstrap/evolution/LEDGER`` (``xax-evolution-ledger-v2``) is a text file of two kinds of lines::

    baseline <store> <blob>
    <record> <store> <before blob> <after blob>

``<store>`` is a path under ``bootstrap/``; ``<blob>`` is the git object id of a store's bytes (``git hash-object``), so a
store a later transaction replaced is read back from the repository (``git cat-file blob``).  The ``baseline`` lines
are the stores as frozen at W2.  Each transaction line applies ``evolution/<record>`` (an ``XAXEDIT1`` edit record,
``xax_selfhost_edit``'s format) to the store whose blob is ``before`` and makes the store whose blob is ``after``.  Per
store the lines form a chain from its baseline; the committed store is the chain's end.

``tests/test_store_regeneration.py`` checks every chain on every host and replays each transaction with the Python
reference (``xax_selfhost_edit.apply_reference``, equal to the XAX engine) where git holds the earlier store; on Linux
x86-64 ``tests/test_xax_selfhost_evolution.py`` replays them with the production compiler's ``edit``.

Adding a transaction (Linux x86-64; no Python runs inside the compiler)::

    python -m xax_selfhost_evolution apply <record> <store> [<store> ...] [--compiler <xaxc>]

copies the record into ``evolution/``, runs ``xaxc edit`` and then ``xaxc verify`` on each named store, replaces the
store and appends its line.  A change to the production compiler names ``xax_compiler_driver_general.xax`` and
``seed/xax_compiler_request.xax`` (the request store must stay ``xax_selfhost_compiler.compiler_request`` of the driver
store); rebuild with ``bootstrap/seed/selfbuild.sh``.  ``python -m xax_selfhost_evolution check`` checks the chains.
"""

from __future__ import annotations

import hashlib
import shutil
import subprocess
import tempfile
from pathlib import Path

from xax_native import bootstrap_dir

BOOTSTRAP = bootstrap_dir()
EVOLUTION_DIRECTORY = BOOTSTRAP / "evolution"
LEDGER_PATH = EVOLUTION_DIRECTORY / "LEDGER"
GENERAL_STORE_PATH = BOOTSTRAP / "xax_compiler_driver_general.xax"  # the production compiler's store
DRIVER_STORE, REQUEST_STORE = "xax_compiler_driver_general.xax", "seed/xax_compiler_request.xax"
SEED_COMPILER = BOOTSTRAP / "seed" / "xaxc-linux-x86_64"
INPUTS_LIMIT = 100  # the committed compiler's external-input bound (ADR-306; the frozen driver holds it)
HEADER = ("# xax-evolution-ledger-v2 (ADR-361): the frozen self-hosting stores and the transactions applied to them, in order.\n"
          "# baseline <store> <blob>  |  <record> <store> <before blob> <after blob>   (blob: the git object id of the store's bytes)\n")


def blob_id(data: bytes) -> str:
    """The git object id of ``data`` as a blob (``git hash-object``)."""
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


class Ledger:
    """The parsed ledger: ``baselines`` (store -> blob) and ``transactions`` ((record path, store, before, after), in
    order)."""

    def __init__(self, text: str) -> None:
        self.baselines: dict[str, str] = {}
        self.transactions: list[tuple[Path, str, str, str]] = []
        for number, line in enumerate(text.splitlines(), 1):
            fields = line.split()
            if not fields or fields[0].startswith("#"):
                continue
            if fields[0] == "baseline" and len(fields) == 3:
                if fields[1] in self.baselines:
                    raise ValueError(f"LEDGER:{number}: a second baseline for {fields[1]}")
                self.baselines[fields[1]] = fields[2]
            elif len(fields) == 4 and fields[0] != "baseline":
                self.transactions.append((EVOLUTION_DIRECTORY / fields[0], fields[1], fields[2], fields[3]))
            else:
                raise ValueError(f"LEDGER:{number}: not a ledger line: {line!r}")

    def heads(self) -> dict[str, str]:
        """Each store's chain end; a transaction must start at its store's current end."""
        heads = dict(self.baselines)
        for record, store, before, after in self.transactions:
            if store not in heads:
                raise ValueError(f"{record.name}: {store} has no baseline")
            if heads[store] != before:
                raise ValueError(f"{record.name}: {store}'s chain is at {heads[store]}, the transaction starts at {before}")
            heads[store] = after
        return heads


def ledger() -> Ledger:
    return Ledger(LEDGER_PATH.read_text(encoding="ascii"))


def store_path(store: str) -> Path:
    return BOOTSTRAP / store


def frozen_stores() -> list[str]:
    return sorted(ledger().baselines)


def check() -> dict[str, str]:
    """``store -> blob`` after checking that every chain is well formed and ends at the committed store."""
    heads = ledger().heads()
    for store, head in heads.items():
        actual = blob_id(store_path(store).read_bytes())
        if actual != head:
            raise ValueError(f"{store}: the committed store is {actual}; its ledger chain ends at {head}")
    return heads


def stored_blob(blob: str) -> bytes | None:
    """A store's bytes from the repository's object database, or None where git or the object is unavailable."""
    git = shutil.which("git")
    if git is None:
        return None
    result = subprocess.run([git, "cat-file", "blob", blob], cwd=BOOTSTRAP, capture_output=True, check=False)
    return result.stdout if result.returncode == 0 and blob_id(result.stdout) == blob else None


def before_store(store: str, before: str) -> bytes | None:
    """The store a transaction starts from: the committed file when it still is that store, else git's copy."""
    data = store_path(store).read_bytes()
    return data if blob_id(data) == before else stored_blob(before)


def is_batch(record: Path) -> bool:
    """N0.4 (ADR-372): a record written as native batch text (``R <root>`` first), not an ``XAXEDIT1`` edit record."""
    return record.read_bytes()[:2] == b"R "


def replay_reference(record: Path, data: bytes) -> bytes:
    """One transaction with the Python reference engine (``apply_reference``, equal to ``xaxc edit``)."""
    from xax_compiler import StoreReader
    from xax_selfhost_edit import apply_reference

    return apply_reference(StoreReader(data), record.read_bytes()).data


def probe_record(reader) -> bytes:
    """A structural transaction on a driver store that the ledger does not record: one constant (the type and value of
    the function's first constant) inserted before the first node of the driver function's first block that has
    nodes.  The evidence run has C1 apply it to the committed store, so ordinary evolution (B6) is shown on the frozen
    store even while the ledger holds no structural transaction."""
    import xax_compiler as X
    from xax_selfhost_edit import INSERT_NODE, edit_record

    module = next(item for item in reader.objects() if item.kind == X.Kind.MODULE)
    main = next(reader.get(cid) for cid in module.references if reader.get(cid).kind == X.Kind.FUNCTION)
    graph = X._parse_graph(reader.get(main.references[X.Cursor(main.body, "").uleb()]), reader.get)
    constant = next(node for block in graph.blocks for node in block.nodes if node.operation == X.Operation.CONSTANT)
    block = next(index for index, item in enumerate(graph.blocks) if item.nodes)
    value = int.from_bytes(constant.entity.body[2:], "little")
    return edit_record([(INSERT_NODE, main.cid, block, 0, 0, X.Operation.CONSTANT, (), constant.results[0], value, ())])


def run_compiler(compiler: Path, *arguments) -> int:
    return subprocess.run([str(compiler), *(str(item) for item in arguments)], check=False).returncode


def apply(record: Path, stores: list[str], compiler: Path = SEED_COMPILER) -> list[str]:
    """Add one transaction: ``xaxc edit`` then ``xaxc verify`` on each store, which is replaced; the ledger lines it
    appended.  Nothing is changed unless every store's edit and verification succeed."""
    from xax_selfhost_edit import parse_record

    data = Path(record).read_bytes()
    if data[:2] != b"R ":  # a batch (native text) is checked by xaxc edit itself
        parse_record(data)
    heads = check()
    target = EVOLUTION_DIRECTORY / Path(record).name
    if target.exists() and target.read_bytes() != data:
        raise ValueError(f"{target.name} already names another record")
    made = {}
    with tempfile.TemporaryDirectory(prefix="xax-evolve-") as directory:
        for store in stores:
            if store not in heads:
                raise ValueError(f"{store} is not a frozen store")
            output, verified = Path(directory) / f"{len(made)}.xax", Path(directory) / f"{len(made)}.verify"
            status = run_compiler(compiler, "edit", store_path(store), record, output)
            if status != 0:
                raise RuntimeError(f"xaxc edit {store}: exit status {status} (the diagnostic record is in {output})")
            status = run_compiler(compiler, "verify", output, verified)
            if status != 0:
                raise RuntimeError(f"xaxc verify of the edited {store}: exit status {status}")
            made[store] = output.read_bytes()
        target.write_bytes(data)
        lines = []
        for store, after in made.items():
            store_path(store).write_bytes(after)
            lines.append(f"{target.name} {store} {heads[store]} {blob_id(after)}")
    with LEDGER_PATH.open("a", encoding="ascii") as handle:
        handle.writelines(line + "\n" for line in lines)
    return lines


def main(arguments: list[str]) -> int:
    if arguments == ["check"]:
        for store, head in sorted(check().items()):
            print(head, store)
        return 0
    if len(arguments) >= 3 and arguments[0] == "apply":
        compiler = SEED_COMPILER
        if "--compiler" in arguments:
            at = arguments.index("--compiler")
            compiler = Path(arguments[at + 1])
            arguments = arguments[:at] + arguments[at + 2:]
        for line in apply(Path(arguments[1]), arguments[2:], compiler):
            print(line)
        return 0
    raise SystemExit("usage: python -m xax_selfhost_evolution check | apply <record> <store>... [--compiler <xaxc>]")


if __name__ == "__main__":
    import sys

    raise SystemExit(main(sys.argv[1:]))
