"""S6c (ADR-150): every committed store, the verifier's own included, is decided by XAX.

The XAX store verifier must prove the store (rootedness, acyclicity) and every
object in it, and the graph decoder must stream every graph body, so the
bootstrap verifier runs no object check for the compiler's own helper programs.
"""

from __future__ import annotations

import platform
import sys
import unittest
from pathlib import Path

import xax_compiler as X

LINUX_X86_64 = sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")
STORES = sorted((Path(__file__).resolve().parents[1] / "bootstrap").glob("*.xax"))


@unittest.skipUnless(LINUX_X86_64, "requires a Linux x86-64 host")
class CommittedStoreTests(unittest.TestCase):
    def test_every_object_of_every_store_is_decided_by_xax(self):
        self.assertTrue(any(path.name == "xax_store_verifier.xax" for path in STORES))
        for path in STORES:
            with self.subTest(store=path.name):
                reader = X.StoreReader(path.read_bytes())
                objects = {obj.cid: obj for obj in reader.objects()}
                X._xax_prove_objects(objects, objects.__getitem__)
                store_ok, proven = X._xax_verify_store(reader, objects)
                self.assertTrue(store_ok)
                undecided = [obj.kind.name for obj in objects.values()
                             if obj.cid not in proven and obj.cid not in X._XAX_VALID_OBJECTS and obj.cid not in X._XAX_GLUE_GRAPHS]
                self.assertEqual(undecided, [])
                X.verify_store(reader)


if __name__ == "__main__":
    unittest.main()
