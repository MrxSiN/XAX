"""Issue #96: sign extension is the exact composition of docs/03 §4.2, on both executors (ADR-405)."""

from __future__ import annotations

import unittest

from test_native_oracle import oracle_execute
from xax_compiler import execute
from xax_construct import construct

SIGN = 1 << 31
REQUEST = {
    "format": "xax-construct-v1", "platform": "jvm",
    "functions": [{"name": "sext", "params": ["b32"], "returns": ["b64"], "blocks": [{"params": ["b32"], "nodes": [
        ["int.zero.extend", ["p0"], ["b64"]],
        ["bit.xor", ["n0", ["b64", SIGN]], ["b64"]],
        ["sub.wrap", ["n1", ["b64", SIGN]], ["b64"]]], "end": ["ret", ["n2"]]}]}],
    "package": {"name": "sext", "entries": {"app": "sext"}, "release": "app"}}


class SignExtendCompositionTests(unittest.TestCase):
    def test_vectors(self):
        constructed = construct(REQUEST)
        cid = constructed.functions["sext"].cid
        for value in (0, 1, 0xFFFFFFFF, 0x80000000, 0x7FFFFFFF):
            expected = value - (1 << 32) if value & SIGN else value
            with self.subTest(value=hex(value)):
                for run in (execute, oracle_execute):
                    self.assertEqual(run(constructed.reader, cid, [value]), (expected % (1 << 64),))


if __name__ == "__main__":
    unittest.main()
