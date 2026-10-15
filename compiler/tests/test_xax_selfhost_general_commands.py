"""S13b (ADR-282): ``verify`` and ``inspect`` in the general driver process, against ``xaxc``.

``verify <store> <output>`` and ``inspect <store> <output>`` run the driver's own verification (S10e) and stop there:
``verify`` writes an empty file when the store verifies, ``inspect`` the store's root and, per object in store order,
its kind, CID, and references.  A store that does not verify gives the rejection record, as ``lower`` and ``build``
do.  Differential: ``xaxc verify`` accepts exactly the stores the driver accepts, each rejection record is the
bootstrap's exact diagnostic or the driver's own ``XAX.DRIVER.VERIFY`` (ADR-266), and ``decode_inspection`` of the
driver's record equals ``xaxc inspect``'s JSON object.  Every run is a process with no Python inside.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import platform
import sys
import tempfile
import unittest
from pathlib import Path

import xax_compiler as X
from xax_selfhost_diagnostics import decode_record

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

LINUX_X86_64 = sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")
BOOTSTRAP = Path(__file__).resolve().parents[1] / "bootstrap"


def _xaxc(*arguments) -> tuple[int, str]:
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        status = X.main([str(item) for item in arguments])
    return status, output.getvalue()


def _record(data: bytes):
    return decode_record([int.from_bytes(data[k:k + 8], "little") for k in range(0, len(data), 8)])


@unittest.skipUnless(LINUX_X86_64, "UNAVAILABLE: the driver image runs on Linux x86-64 only")
class GeneralCommandTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from xax_selfhost_driver import NativeGeneralDriver

        cls.driver = NativeGeneralDriver()
        cls.driver.timeout = 600
        cls.directory = tempfile.mkdtemp()

    def run_command(self, command: str, data: bytes):
        store, output = (os.path.join(self.directory, name) for name in ("store.xax", "out.bin"))
        Path(store).write_bytes(data)
        if os.path.exists(output):
            os.unlink(output)
        status = getattr(self.driver, command)(store, output)
        produced = Path(output).read_bytes() if os.path.exists(output) else None
        return status, produced, store

    def assertVerify(self, data: bytes):
        """The driver accepts exactly what ``xaxc verify`` accepts; a rejection is exact or the driver's own."""
        status, produced, store = self.run_command("verify", data)
        expected, printed = _xaxc("verify", store)
        if expected == 0:
            self.assertEqual((status, produced), (0, b""))
            return "accepted"
        self.assertIn(status, (1, 2))  # rejected, or declined: never accepted
        if status == 1:
            diagnostic = _record(produced)
            if diagnostic.code != "XAX.DRIVER.VERIFY":
                self.assertEqual(json.loads(X.diagnostic_json(X.XaxError(diagnostic))), json.loads(printed))
            return "rejected"
        return "declined"

    def assertInspect(self, data: bytes):
        from xax_selfhost_driver import decode_inspection

        status, produced, store = self.run_command("inspect", data)
        expected, printed = _xaxc("inspect", store)
        self.assertEqual(expected, 0)
        self.assertEqual(status, 0)
        self.assertEqual(decode_inspection(produced), json.loads(printed))

    def programs(self):
        """Committed component stores up to 4 MB, Linux test programs, and a build snapshot."""
        from test_xax_linux import _crc_program, _status_program
        from test_xax_selfhost_general_build import _parts, _program

        stores = {path.name: path.read_bytes() for path in sorted(BOOTSTRAP.glob("*.xax")) if path.stat().st_size <= 4 << 20}
        status, _entry, target, _ = _status_program(lambda b: b.const(X.bits_type(32), 7))
        stores["status"] = status.data
        stores["crc"] = _crc_program(X.x86_64_linux_dynamic_exec_target())[0].data
        objects, entry = _parts(status)
        stores["snapshot"] = _program(objects, {b"image": entry}, target).data
        return stores

    def test_verify_and_inspect(self):
        for name, data in self.programs().items():
            with self.subTest(name):
                self.assertEqual(self.assertVerify(data), "accepted")
                self.assertInspect(data)

    def test_rejections(self):
        """Mutated stores: every one ``xaxc verify`` rejects is rejected or declined, never accepted, and the reverse."""
        from test_xax_linux import _status_program

        program, _entry, _target, _ = _status_program(lambda b: b.const(X.bits_type(32), 7))
        data = program.data
        outcomes = {}
        for offset in range(0, len(data), max(1, len(data) // 60)):
            mutated = data[:offset] + bytes(((data[offset] + 1) & 0xFF,)) + data[offset + 1:]
            outcome = self.assertVerify(mutated)
            outcomes[outcome] = outcomes.get(outcome, 0) + 1
        self.assertIn("rejected", outcomes)
        status, produced, _store = self.run_command("inspect", data[:-1])
        self.assertEqual(status, 1)  # inspect verifies first
        self.assertEqual(_record(produced).code[:4], "XAX.")

    def test_argument_counts(self):
        store, output = (os.path.join(self.directory, name) for name in ("store.xax", "out.bin"))
        Path(store).write_bytes((BOOTSTRAP / "xax_cfg_analysis.xax").read_bytes())
        for arguments in (("verify", store), ("verify", store, output, output), ("inspect", store, output, output),
                          ("lower", store, output), ("build", store, output), ("check", store, output)):
            with self.subTest(arguments):
                self.assertEqual(self.driver._process(*arguments), 3)


if __name__ == "__main__":
    unittest.main()
