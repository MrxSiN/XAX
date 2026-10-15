"""S15b.1-S15b.2 (ADR-288, ADR-289): the general driver's ``verify`` rejects exactly as ``verify_store`` does.

The production compiler's ``verify`` command runs as a process with no Python inside.  On mutated stores it must
accept exactly what ``verify_store`` accepts and, when it rejects, write the bootstrap's own diagnostic (code, entity,
rule, expected, actual, dependencies, repair neighborhood), in ``verify_store``'s order: missing references, object
rejections after the graphs they parse first, types and constants, the store's rootedness last.  Graph checks not yet
rendered keep the driver's own record (``XAX.DRIVER.VERIFY``); a decline makes no claim.

* Object sites: the stores of ``test_xax_selfhost_render`` (functions, groups, contracts, lists, targets, packages and
  build objects), with one object's body or references mutated.
* Types and constants: ``test_xax_selfhost_objects``'s random types of every form and constants, mutated, in a module.
"""

from __future__ import annotations

import os
import platform
import random
import sys
import tempfile
import unittest
from pathlib import Path

import xax_compiler as X
from xax_compiler import Kind, StoreReader, XaxError, object_with_refs, write_store
from xax_selfhost_diagnostics import decode_record

LINUX_X86_64 = sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")


@unittest.skipUnless(LINUX_X86_64, "UNAVAILABLE: the driver runs on Linux x86-64 only")
class VerifyExactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from xax_selfhost_driver import NativeGeneralDriver

        cls.driver = NativeGeneralDriver()
        cls.driver.timeout = 600
        cls.directory = tempfile.mkdtemp()

    def driver_outcome(self, data: bytes):
        store, output = (os.path.join(self.directory, name) for name in ("store.xax", "out.bin"))
        Path(store).write_bytes(data)
        if os.path.exists(output):
            os.unlink(output)
        status = self.driver.verify(store, output)
        if status == 1:
            produced = Path(output).read_bytes()
            return "rejected", decode_record([int.from_bytes(produced[k:k + 8], "little") for k in range(0, len(produced), 8)])
        return {0: "accepted", 2: "declined", 3: "failed"}[status], None

    def check(self, reader, tally):
        X._PARSED_GRAPHS.clear()
        try:
            X.verify_store(reader)
            expected = None
        except XaxError as error:
            expected = error.diagnostic
        except (IndexError, KeyError, TypeError, ValueError):
            tally["host_error"] += 1  # the host fails without a diagnostic: no reference to compare with
            return
        kind, diagnostic = self.driver_outcome(reader.data)
        if expected is None:
            self.assertIn(kind, ("accepted", "declined"))
            tally["accepted" if kind == "accepted" else "declined"] += 1
            return
        self.assertIn(kind, ("rejected", "declined"))  # never accepted
        if kind == "declined":
            tally["declined"] += 1
        elif diagnostic.code == "XAX.DRIVER.VERIFY":
            tally["driver_record"] += 1
        else:
            self.assertEqual(diagnostic, expected)
            tally["exact"] += 1

    def test_object_sites(self):
        from test_xax_selfhost_render import _bases, _mutated

        rng = random.Random(288)
        bases = _bases(rng)
        tally = dict.fromkeys(("accepted", "exact", "driver_record", "declined", "host_error"), 0)
        for trial in range(int(os.environ.get("XAX_VERIFY_EXACT_TRIALS", "240"))):
            objects, root = bases[trial % len(bases)]
            for _round in range(1 + rng.randrange(2)):
                objects, root = _mutated(rng, objects, root)
            try:
                reader = StoreReader(write_store(root, list(objects.values())))
            except (XaxError, ValueError, KeyError):
                continue
            with self.subTest(trial=trial):
                self.check(reader, tally)
        self.assertGreater(tally["exact"], 100, tally)

    def test_types_and_constants(self):
        from test_xax_selfhost_objects import _sample

        rng = random.Random(289)
        tally = dict.fromkeys(("accepted", "exact", "driver_record", "declined", "host_error"), 0)
        for trial in range(int(os.environ.get("XAX_VERIFY_EXACT_TRIALS", "240"))):
            made, objects = _sample(rng)
            module = object_with_refs(Kind.MODULE, [made])
            root = object_with_refs(Kind.PROGRAM_ROOT, [module])
            stored = {item.cid: item for item in (*objects, module, root)}
            try:
                reader = StoreReader(write_store(root.cid, list(stored.values())))
            except (XaxError, ValueError, KeyError):
                continue
            with self.subTest(trial=trial):
                self.check(reader, tally)
        self.assertGreater(tally["exact"], 40, tally)


if __name__ == "__main__":
    unittest.main()
