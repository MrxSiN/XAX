"""S15e.3b (ADR-326): Windows PE32+ functions on the hosted legacy register path, lowered by the XAX general program.

``xax_pe.compile_pe_executable(..., frontend="xax")`` runs the XAX general program and fails where it declines;
``frontend="python"`` is the bootstrap.  Differential, by bytes, over ``pe_legacy_corpus`` (every case checked to reach
the bootstrap's ``_compile_register_resident_function``), and the rejections it decides on that path
(``NATIVE-FOREIGN-ABI``, ``WIN64-COM-METHOD``, ``NATIVE-CHECKED-BOUND-ENCODABLE``).
"""

from __future__ import annotations

import os
import platform
import random
import sys
import unittest
from pathlib import Path

from xax_compiler import XaxError, verify_store
from xax_pe import compile_pe_executable

sys.path.insert(0, str(Path(__file__).resolve().parent))

LINUX_X86_64 = sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")


def _outcome(reader, entry, target, frontend):
    try:
        return "image", compile_pe_executable(reader, entry.cid, target, frontend=frontend)
    except XaxError as error:
        return "rejected", error.diagnostic


@unittest.skipUnless(LINUX_X86_64, "UNAVAILABLE: the XAX general program runs on Linux x86-64 only")
class XaxPeLegacyTests(unittest.TestCase):
    def test_corpus_and_rejections(self):
        import xax_x86_64
        from pe_legacy_corpus import pe_legacy_case

        taken = []
        original = xax_x86_64._compile_register_resident_function

        def recording(*arguments, **keywords):
            result = original(*arguments, **keywords)
            taken.append(result is not None)
            return result

        rng = random.Random(326)
        seen = set()
        xax_x86_64._compile_register_resident_function = recording
        try:
            for fault in (None, "com", "abi", "malformed", "bound"):
                for trial in range(int(os.environ.get("XAX_PE_LEGACY_TRIALS", "8")) if fault is None else 2):
                    reader, entry, target, name = pe_legacy_case(rng, fault)
                    with self.subTest(fault=fault, trial=trial, case=name):
                        verify_store(reader)
                        taken.clear()
                        expected = _outcome(reader, entry, target, "python")
                        if expected[0] == "image":
                            self.assertIn(True, taken)  # the bootstrap took the legacy path (a rejection raises inside it)
                        self.assertEqual(_outcome(reader, entry, target, "xax"), expected)
                        seen.add(expected[0] if expected[0] == "image" else expected[1].rule)
        finally:
            xax_x86_64._compile_register_resident_function = original
        self.assertTrue({"image", "NATIVE-FOREIGN-ABI", "NATIVE-CHECKED-BOUND-ENCODABLE"} <= seen, seen)


if __name__ == "__main__":
    unittest.main()
