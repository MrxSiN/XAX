"""W2 (ADR-361): the frozen compiler evolves by its own transactions; the evolution ledger on the committed stores.

``test_store_regeneration`` checks the ledger's chains and replays its transactions with the Python reference.  Here,
on Linux x86-64, with the pinned seed compiler (no Python runs inside it):

* every ledger transaction is replayed with ``xaxc edit`` from the store it started at and makes the store it recorded,
  which ``xaxc verify`` accepts;
* ``python -m xax_selfhost_evolution apply`` adds a transaction to the committed general driver store directly: the
  store ``xaxc edit`` makes equals the Python reference's, verifies, and the appended ledger line chains from the
  frozen baseline to it (on a copy of ``bootstrap/``);
* the raised external-input bound the frozen driver holds (ADR-306): it resolves 100 inputs to the bootstrap's
  snapshot and refuses 101.
"""

from __future__ import annotations

import platform
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import xax_compiler as X

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

LINUX_X86_64 = sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")


def bound_record(reader, old: int, new: int) -> bytes:
    """An edit record that changes the driver's external-input bound (the constant compared, unsigned, below the
    count of extra arguments) from ``old`` to ``new``."""
    from xax_selfhost_edit import SET_CONSTANT, edit_record

    module = next(item for item in reader.objects() if item.kind == X.Kind.MODULE)
    main = next(reader.get(cid) for cid in module.references if reader.get(cid).kind == X.Kind.FUNCTION)
    graph = X._parse_graph(reader.get(main.references[X.Cursor(main.body, "").uleb()]), reader.get)
    found = []
    for block in graph.blocks:
        for node in block.nodes:
            if node.operation == X.Operation.INT_COMPARE and node.attributes == (int(X.IntCompare.ULT),) and node.operands[0].tag == 1:
                source = node.operands[0]
                constant = graph.blocks[source.block].nodes[source.index]
                if constant.operation == X.Operation.CONSTANT and int.from_bytes(constant.entity.body[2:], "little") == old:
                    found.append((SET_CONSTANT, main.cid, source.block, source.index, old, new))
    assert len(found) == 1, found
    return edit_record(found)


@unittest.skipUnless(LINUX_X86_64, "UNAVAILABLE: the compiler runs on Linux x86-64 only")
class EvolutionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = Path(tempfile.mkdtemp())

    def test_the_compiler_replays_the_ledger(self):
        import xax_selfhost_evolution as EV

        for record, store, before, after in EV.ledger().transactions:
            data = EV.before_store(store, before)
            if data is None:
                continue  # test_store_regeneration reports the unavailable store
            with self.subTest(record=record.name, store=store):
                path, output = self.directory / "before.xax", self.directory / "after.xax"
                path.write_bytes(data)
                self.assertEqual(EV.run_compiler(EV.SEED_COMPILER, "edit", path, record, output), 0)
                self.assertEqual(EV.blob_id(output.read_bytes()), after)
                self.assertEqual(EV.run_compiler(EV.SEED_COMPILER, "verify", output, self.directory / "verified.bin"), 0)

    def test_apply_adds_a_transaction_to_the_committed_driver_store(self):
        import xax_selfhost_evolution as EV

        bootstrap = self.directory / "bootstrap"
        (bootstrap / "evolution").mkdir(parents=True)
        shutil.copyfile(EV.GENERAL_STORE_PATH, bootstrap / EV.DRIVER_STORE)
        baseline = EV.ledger().heads()[EV.DRIVER_STORE]
        (bootstrap / "evolution" / "LEDGER").write_text(EV.HEADER + f"baseline {EV.DRIVER_STORE} {baseline}\n", encoding="ascii")
        reader = X.StoreReader(EV.GENERAL_STORE_PATH.read_bytes())
        record = self.directory / "0001-inputs-99.edit"
        record.write_bytes(bound_record(reader, EV.INPUTS_LIMIT, EV.INPUTS_LIMIT - 1))
        saved = EV.BOOTSTRAP, EV.EVOLUTION_DIRECTORY, EV.LEDGER_PATH
        EV.BOOTSTRAP, EV.EVOLUTION_DIRECTORY, EV.LEDGER_PATH = bootstrap, bootstrap / "evolution", bootstrap / "evolution" / "LEDGER"
        try:
            lines = EV.apply(record, [EV.DRIVER_STORE])
            ledger = EV.ledger()
        finally:
            EV.BOOTSTRAP, EV.EVOLUTION_DIRECTORY, EV.LEDGER_PATH = saved
        made = (bootstrap / EV.DRIVER_STORE).read_bytes()
        self.assertEqual(made, EV.replay_reference(record, reader.data))
        self.assertEqual(lines, [f"{record.name} {EV.DRIVER_STORE} {baseline} {EV.blob_id(made)}"])
        self.assertEqual(len(ledger.transactions), 1)
        check = subprocess.run(["sh", str(EV.EVOLUTION_DIRECTORY / "evolve.sh"), "check", str(bootstrap)], capture_output=True, text=True)
        self.assertEqual(check.returncode, 0, check.stderr)
        self.assertEqual((bootstrap / "evolution" / record.name).read_bytes(), record.read_bytes())

    def test_the_raised_input_bound(self):
        from test_xax_selfhost_s15c import _Fixture, resolve_expected
        from xax_selfhost_driver import NativeGeneralDriver
        from xax_selfhost_evolution import INPUTS_LIMIT

        driver = NativeGeneralDriver()
        driver.timeout = 1800
        fixture = _Fixture()
        request = self.directory / "request.xax"
        request.write_bytes(fixture.request_store().data)
        values = [bytes([k]) * (k + 1) for k in range(INPUTS_LIMIT + 1)]
        paths = []
        for k, value in enumerate(values):
            paths.append(self.directory / f"input{k}.bin")
            paths[-1].write_bytes(value)
        output = self.directory / "snapshot.xax"
        output.unlink(missing_ok=True)
        self.assertEqual(driver.resolve(request, output, *paths[:INPUTS_LIMIT]), 0)
        self.assertEqual(("store", output.read_bytes()), resolve_expected(fixture.request_store(), values[:INPUTS_LIMIT]))
        self.assertEqual(driver.resolve(request, output, *paths), 3)


if __name__ == "__main__":
    unittest.main()
