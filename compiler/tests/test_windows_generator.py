"""RFC step 5: the Windows seed's build request generated natively (``bootstrap/windows/generator``).

On Linux x86-64 with the pinned seed: the committed generator store is its batch, and ``generate.sh`` makes, from the
committed shared request, the Windows request ``windows/seed.json`` records (``source.result_sha256``), the one the
pinned Windows seed is built from.
"""

from __future__ import annotations

import hashlib
import json
import platform
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

BOOTSTRAP = Path(__file__).resolve().parents[1] / "bootstrap"
GENERATOR = BOOTSTRAP / "windows" / "generator"
SEED = BOOTSTRAP / "seed" / "xaxc-linux-x86_64"
LINUX_X86_64 = sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")


@unittest.skipUnless(LINUX_X86_64, "the pinned seed runs on Linux x86-64")
class WindowsGeneratorTests(unittest.TestCase):
    def test_the_store_is_its_batch(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / "tool.xax"
            subprocess.run([str(SEED), "edit", str(BOOTSTRAP / "evolution" / "ledger-tool" / "seed.xax"), str(GENERATOR / "generator.batch"), str(out)], check=True)
            self.assertEqual(out.read_bytes(), (GENERATOR / "xax_hosting.xax").read_bytes())

    def test_the_request_is_the_recorded_one(self):
        recorded = json.loads((BOOTSTRAP / "windows" / "seed.json").read_text())["source"]["result_sha256"]
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / "request.xax"
            subprocess.run(["sh", str(GENERATOR / "generate.sh"), str(BOOTSTRAP / "seed" / "xax_compiler_request.xax"), str(out)], check=True, timeout=3600)
            self.assertEqual(hashlib.sha256(out.read_bytes()).hexdigest(), recorded)


if __name__ == "__main__":
    unittest.main()
