"""BBC decisions bound into the bfc_call_v1 shared-library host (integration/bfx/SHARED.md)."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from xax_android import inspect_android_elf  # noqa: E402
from xax_android_bfc import HOST, bind, build  # noqa: E402
from xax_compiler import StoreReader  # noqa: E402

BFX = Path(__file__).resolve().parents[1] / "integration/bfx"


class SharedHost(unittest.TestCase):
    def test_bbc_bind_record_binds_and_builds(self) -> None:
        host = StoreReader(HOST.read_bytes())
        bound = bind((BFX / "standalone_hello.edit").read_bytes(), host)
        self.assertNotEqual(bound.root_cid, host.root_cid)
        elf = inspect_android_elf(build(bound))
        self.assertEqual((elf.exports, elf.imports), ((b"bfc_call_v1",), ()))

    def test_stale_or_foreign_records_reject(self) -> None:
        record = bytearray((BFX / "standalone_hello.edit").read_bytes())
        record[8 + 32] = 2  # two mutations claimed
        with self.assertRaises(Exception):
            bind(bytes(record))


if __name__ == "__main__":
    unittest.main()
