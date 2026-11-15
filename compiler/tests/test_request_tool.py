"""RFC step 5: the native request tool (``bootstrap/evolution/request-tool``) against its oracles at ledger 0032.

On Linux x86-64 with the pinned seed: the committed tool store is the seed's ``xaxc edit`` of its batch, and the
request the tool writes for the committed driver equals the committed request and the reference ``compiler_request``.
"""

from __future__ import annotations

import platform
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

BOOTSTRAP = Path(__file__).resolve().parents[1] / "bootstrap"
TOOL = BOOTSTRAP / "evolution" / "request-tool"
SEED = BOOTSTRAP / "seed" / "xaxc-linux-x86_64"
LINUX_X86_64 = sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")


@unittest.skipUnless(LINUX_X86_64, "the pinned seed runs on Linux x86-64")
class RequestToolTests(unittest.TestCase):
    def test_the_store_is_its_batch(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / "tool.xax"
            subprocess.run([str(SEED), "edit", str(BOOTSTRAP / "evolution" / "ledger-tool" / "seed.xax"), str(TOOL / "request.batch"), str(out)], check=True)
            self.assertEqual(out.read_bytes(), (TOOL / "xax_request.xax").read_bytes())

    def test_the_request_equals_the_committed_one_and_the_reference(self):
        from xax_selfhost_compiler import compiler_request

        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / "request.xax"
            subprocess.run(["sh", str(TOOL / "request.sh"), str(BOOTSTRAP / "xax_compiler_driver_general.xax"), str(TOOL / "x86_64-linux-elf-exec-v1.target"), str(out)], check=True)
            made = out.read_bytes()
        self.assertEqual(made, (BOOTSTRAP / "seed" / "xax_compiler_request.xax").read_bytes())
        self.assertEqual(made, compiler_request()[0].data)

    def test_a_missing_driver_writes_nothing(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / "request.xax"
            run = subprocess.run(["sh", str(TOOL / "request.sh"), str(Path(directory) / "missing.xax"), str(TOOL / "x86_64-linux-elf-exec-v1.target"), str(out)], check=False)
            self.assertEqual(run.returncode, 1)
            self.assertFalse(out.exists())


if __name__ == "__main__":
    unittest.main()
