"""S15d.2-S15d.3 (ADR-305, ADR-306): the compiler evolves by its own transactions; the evolution ledger.

The general driver's committed store is its builder's baseline with the ledger's transactions applied in order
(``test_store_regeneration`` checks that with the Python reference).  Here:

* every ledger record is well formed and is what its query derives from the baseline (``rebase`` is a no-op);
* on Linux x86-64 the production compiler's own ``edit`` applies the ledger to the baseline driver store and to the
  baseline request store and makes exactly the committed stores, which its ``verify`` accepts; the request store is
  the one derived from the committed driver store;
* the first transaction raised the external input bound from 64 to 100: the committed compiler resolves 100 inputs to
  the bootstrap's snapshot and refuses 101.
"""

from __future__ import annotations

import platform
import sys
import tempfile
import unittest
from pathlib import Path

import xax_compiler as X

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

LINUX_X86_64 = sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")


def _baseline():
    from xax_selfhost_driver import build_general_driver_program

    building = X._TYPING_BUILDING
    X._TYPING_BUILDING = True
    try:
        return build_general_driver_program()[0]
    finally:
        X._TYPING_BUILDING = building


class LedgerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.baseline = _baseline()

    def test_records_are_their_queries(self):
        from xax_selfhost_edit import apply_reference, edit_record, parse_record
        from xax_selfhost_evolution import QUERIES, entries

        reader = self.baseline
        self.assertTrue(entries())
        for record, query in entries():
            data = record.read_bytes()
            parse_record(data)
            self.assertEqual(data, edit_record(QUERIES[query](reader)), record.name)
            reader = apply_reference(reader, data)

    def test_the_request_store_is_derived_from_the_driver_store(self):
        from xax_selfhost_compiler import compiler_request
        from xax_selfhost_seed import REQUEST_PATH

        self.assertEqual(compiler_request()[0].data, REQUEST_PATH.read_bytes())


@unittest.skipUnless(LINUX_X86_64, "UNAVAILABLE: the driver image runs on Linux x86-64 only")
class EvolutionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from xax_selfhost_driver import NativeGeneralDriver

        cls.driver = NativeGeneralDriver()
        cls.driver.timeout = 1800
        cls.directory = Path(tempfile.mkdtemp())

    def test_the_compiler_makes_the_committed_stores(self):
        from xax_selfhost_compiler import compiler_request
        from xax_selfhost_evolution import GENERAL_STORE_PATH, entries
        from xax_selfhost_seed import REQUEST_PATH

        baseline = _baseline()
        stores = {"driver": baseline.data, "request": compiler_request(baseline)[0].data}
        committed = {"driver": GENERAL_STORE_PATH.read_bytes(), "request": REQUEST_PATH.read_bytes()}
        for name, data in stores.items():
            path = self.directory / f"{name}.xax"
            path.write_bytes(data)
            for record, _query in entries():
                output = self.directory / f"{name}-next.xax"
                self.assertEqual(self.driver._process("edit", path, record, output), 0, (name, record.name))
                output.replace(path)
            with self.subTest(name):
                self.assertEqual(path.read_bytes(), committed[name])
                self.assertEqual(self.driver.verify(path, self.directory / "verified.bin"), 0)

    def test_the_raised_input_bound(self):
        from test_xax_selfhost_s15c import _Fixture, resolve_expected
        from xax_selfhost_evolution import INPUTS_LIMIT

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
        self.assertEqual(self.driver.resolve(request, output, *paths[:INPUTS_LIMIT]), 0)
        self.assertEqual(("store", output.read_bytes()), resolve_expected(fixture.request_store(), values[:INPUTS_LIMIT]))
        self.assertEqual(self.driver.resolve(request, output, *paths), 3)


if __name__ == "__main__":
    unittest.main()
