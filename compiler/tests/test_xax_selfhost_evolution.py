"""W2 (ADR-361): the frozen compiler evolves by its own transactions; the evolution ledger on the committed stores.

``test_store_regeneration`` checks the ledger's chains and replays its transactions with the Python reference.  Here,
on Linux x86-64, with the pinned seed compiler (no Python runs inside it):

* ``evolve.sh replay`` replays every ledger transaction with ``xaxc edit`` from the store it started at and makes the
  store it recorded;
* ``evolve.sh apply`` adds a transaction to the general driver store (on a copy of ``bootstrap/``): the store
  ``xaxc edit`` makes equals the Python reference's, and the appended ledger line chains from the baseline to it;
* the raised external-input bound the frozen driver holds (ADR-306): it resolves 100 inputs to the bootstrap's
  snapshot and refuses 101.
"""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import xax_compiler as X
from xax_selfhost_driver import INPUTS_LIMIT

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

BOOTSTRAP = Path(__file__).resolve().parents[1] / "bootstrap"
EVOLVE = BOOTSTRAP / "evolution" / "evolve.sh"
LINUX_X86_64 = sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")



def ledger(*arguments) -> str:
    """The native ledger program's output for one command (``evolve.sh ledger``), without the final newline."""
    run = subprocess.run(["sh", str(EVOLVE), "ledger", *(str(item) for item in arguments)], capture_output=True, text=True, check=True)
    return run.stdout.rstrip("\n")


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
        replay = subprocess.run(["sh", str(EVOLVE), "replay"], capture_output=True, text=True)
        self.assertEqual(replay.returncode, 0, replay.stderr)
        self.assertNotIn("FAIL", replay.stdout + replay.stderr)

    def test_apply_adds_a_transaction_to_the_committed_driver_store(self):
        from xax_selfhost_edit import apply_reference
        from xax_selfhost_seed import SEED_PATH

        driver = "xax_compiler_driver_general.xax"
        bootstrap = self.directory / "bootstrap"
        shutil.copytree(BOOTSTRAP / "evolution" / "ledger-tool", bootstrap / "evolution" / "ledger-tool")
        shutil.copyfile(EVOLVE, bootstrap / "evolution" / "evolve.sh")
        shutil.copyfile(BOOTSTRAP / driver, bootstrap / driver)
        baseline = ledger("head", BOOTSTRAP, driver)
        (bootstrap / "evolution" / "LEDGER").write_text(f"# a copy\nbaseline {driver} {baseline}\n", encoding="ascii")
        reader = X.StoreReader((BOOTSTRAP / driver).read_bytes())
        record = self.directory / "0001-inputs-99.edit"
        record.write_bytes(bound_record(reader, INPUTS_LIMIT, INPUTS_LIMIT - 1))
        applied = subprocess.run(["sh", str(bootstrap / "evolution" / "evolve.sh"), "apply", str(record), driver],
                                 capture_output=True, text=True, env={**os.environ, "XAXC": str(SEED_PATH)})
        self.assertEqual(applied.returncode, 0, applied.stderr)
        made = (bootstrap / driver).read_bytes()
        self.assertEqual(made, apply_reference(reader, record.read_bytes()).data)
        line = f"{record.name} {driver} {baseline} {ledger('blob', bootstrap / driver)}"
        self.assertEqual(applied.stdout.splitlines(), [line])
        self.assertEqual(ledger("transactions", bootstrap), line)
        check = subprocess.run(["sh", str(EVOLVE), "check", str(bootstrap)], capture_output=True, text=True)
        self.assertEqual(check.returncode, 0, check.stderr)
        self.assertEqual((bootstrap / "evolution" / record.name).read_bytes(), record.read_bytes())

    def test_the_raised_input_bound(self):
        from test_xax_selfhost_s15c import _Fixture, resolve_expected
        from xax_selfhost_driver import NativeGeneralDriver

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
