"""ADR-222: component-store verification is memoized in the native image cache, keyed by exact store bytes and the
exact verifier, and never trusted outside it."""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import xax_compiler
import xax_native
from xax_compiler import StoreReader
from xax_selfhost_cfg import STORE_PATH


class VerifiedComponentStoreTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        os.chmod(self.directory.name, 0o700)
        self.env = mock.patch.dict(os.environ, {"XAX_NATIVE_CACHE": self.directory.name})
        self.env.start()
        os.environ.pop("XAX_NATIVE_REVERIFY", None)
        self.reader = StoreReader(STORE_PATH.read_bytes())

    def tearDown(self):
        self.env.stop()
        self.directory.cleanup()

    def _verify(self, reader, name="cfg"):
        calls = []
        real = xax_compiler.verify_store

        def counting(item):
            if item.root_cid == reader.root_cid:  # nested loads of other components verify their own stores
                calls.append(item.root_cid)
            return real(item)

        with mock.patch.object(xax_compiler, "verify_store", counting):
            xax_native.verify_component_store(reader, name)
        return len(calls)

    def records(self):
        # Verifying a store loads other components, which record their own stores in the same cache.
        return sorted(Path(self.directory.name).glob("verified-cfg-*.bin"))

    def test_first_load_verifies_and_later_loads_reuse_the_record(self):
        # >= 1: in a cold process, verifying the CFG store loads the native CFG component, whose loader verifies it too.
        self.assertGreaterEqual(self._verify(self.reader), 1)
        self.assertEqual(len(self.records()), 1)
        self.assertEqual(self._verify(self.reader), 0)

    def test_record_is_bound_to_exact_store_bytes_and_name(self):
        self._verify(self.reader)
        self.assertGreaterEqual(self._verify(self.reader, "other-name"), 1)
        other = StoreReader(Path(STORE_PATH.parent, "xax_store_decoder.xax").read_bytes())
        self.assertGreaterEqual(self._verify(other), 1)

    def test_record_is_bound_to_the_verifier_identity(self):
        self._verify(self.reader)
        with mock.patch.object(xax_native, "_VERIFIER_IDENTITY", b"\x01" * 32):
            self.assertEqual(self._verify(self.reader), 1)

    def test_corrupt_record_is_ignored_and_rewritten(self):
        self._verify(self.reader)
        (record,) = self.records()
        record.write_bytes(b"XAXVS1\0\0" + bytes(32))
        self.assertEqual(self._verify(self.reader), 1)
        self.assertEqual(self._verify(self.reader), 0)

    def test_reverify_switch_and_unusable_cache_always_verify(self):
        self._verify(self.reader)
        with mock.patch.dict(os.environ, {"XAX_NATIVE_REVERIFY": "1"}):
            self.assertEqual(self._verify(self.reader), 1)
        os.chmod(self.directory.name, 0o777)  # group/world-writable: cache_dir() refuses it
        try:
            self.assertEqual(self._verify(self.reader), 1)
        finally:
            os.chmod(self.directory.name, 0o700)

    def test_failed_verification_writes_no_record(self):
        with mock.patch.object(xax_compiler, "verify_store", side_effect=xax_compiler.XaxError(
                xax_compiler.Diagnostic("XAX.TEST", "e", "R", 1, 2))):
            with self.assertRaises(xax_compiler.XaxError):
                xax_native.verify_component_store(self.reader, "cfg")
        self.assertEqual(self.records(), [])


if __name__ == "__main__":
    unittest.main()
