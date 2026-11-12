"""BBC's Windows-hosted production driver, natively (integration/bfx/transactions/production_driver/native).

Replays the port with the pinned seed. The production driver after ledger 0015 (its git blob) takes the
Windows-host batch, then the PE-target record. The roots must be the recorded ones and ``xaxc verify`` must accept
the result.
"""

from __future__ import annotations

import platform
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import xax_compiler as X
from xax_selfhost_seed import SEED_PATH

HERE = Path(__file__).resolve().parents[1]
PORT = HERE / "integration" / "bfx" / "transactions" / "production_driver" / "native"
DRIVER_BLOB = "fc32dfd83bb8130cc0fdf92724197dbd56a4585c"
ROOTS = ("ad201ea4415c6b90d1daf62cd2b606f5d76f30a621f0398ac3b5cdc78ad063f3",
         "b42738751c5ce443d5da5e3a8a0d5ecae0f8fe4e300e7c06d3bbb80aecaf2827")


@unittest.skipUnless(platform.system() == "Linux" and platform.machine() in ("x86_64", "AMD64"), "the seed runs on Linux x86-64")
class WindowsHostPortTests(unittest.TestCase):
    def test_port_replays(self):
        if shutil.which("git") is None:
            self.skipTest("requires git")
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            store = work / "driver.xax"
            data = subprocess.run(["git", "-C", str(HERE), "cat-file", "blob", DRIVER_BLOB], capture_output=True).stdout
            if not data:
                self.skipTest("the repository does not hold the production driver blob")
            store.write_bytes(data)
            for step, (name, root) in enumerate(zip(("1_windows_host.batch", "2_pe_target.edit"), ROOTS)):
                out = work / f"step{step}.xax"
                self.assertEqual(subprocess.run([SEED_PATH, "edit", store, PORT / name, out]).returncode, 0, name)
                self.assertEqual(X.StoreReader(out.read_bytes()).root_cid.hex(), root, name)
                store = out
            self.assertEqual(subprocess.run([SEED_PATH, "verify", store, work / "verify"]).returncode, 0)


if __name__ == "__main__":
    unittest.main()
