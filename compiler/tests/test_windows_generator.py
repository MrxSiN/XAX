"""RFC step 5: the Windows seed's build request generated natively (``bootstrap/windows/generator``).

On Linux x86-64 with the pinned seed: the committed generator store is its batch, and ``generate.sh`` makes, from the
committed shared request, the Windows request the released Windows seed was confirmed with (the ``request`` line of
``evidence/confirm/<release>-x86_64-windows-pe-v1.txt``, ADR-410).
"""

from __future__ import annotations

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
    def test_the_store_is_its_batches(self):
        """generator.batch on the ledger seed, then entry.batch (2026-11-25: the package entry is read after the package
        identity and the entry name, not at a fixed byte)."""
        with tempfile.TemporaryDirectory() as directory:
            first, out = Path(directory) / "first.xax", Path(directory) / "tool.xax"
            subprocess.run([str(SEED), "edit", str(BOOTSTRAP / "evolution" / "ledger-tool" / "seed.xax"), str(GENERATOR / "generator.batch"), str(first)], check=True)
            subprocess.run([str(SEED), "edit", str(first), str(GENERATOR / "entry.batch"), str(out)], check=True)
            self.assertEqual(out.read_bytes(), (GENERATOR / "xax_hosting.xax").read_bytes())

    def test_the_ledger_tool_is_hosted(self):
        """The ledger program's Windows store is generate.sh's output for its Linux store (OI-60)."""
        tool = BOOTSTRAP / "evolution" / "ledger-tool"
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / "xax_ledger_windows.xax"
            subprocess.run(["sh", str(GENERATOR / "generate.sh"), str(tool / "xax_ledger.xax"), str(out)], check=True, capture_output=True, timeout=1800)
            self.assertEqual(out.read_bytes(), (tool / "xax_ledger_windows.xax").read_bytes())

    def test_the_ledger_tool_is_its_batches(self):
        """xax_ledger.xax is check.batch, commands.batch, derived.batch and driver.batch on the ledger seed."""
        tool = BOOTSTRAP / "evolution" / "ledger-tool"
        with tempfile.TemporaryDirectory() as directory:
            store = tool / "seed.xax"
            for k, batch in enumerate(("check", "commands", "derived", "driver")):
                out = Path(directory) / f"{k}.xax"
                subprocess.run([str(SEED), "edit", str(store), str(tool / f"{batch}.batch"), str(out)], check=True, capture_output=True)
                store = out
            self.assertEqual(store.read_bytes(), (tool / "xax_ledger.xax").read_bytes())

    def test_the_request_is_the_recorded_one(self):
        from xax_selfhost_seed import WINDOWS_TARGET, identity, released

        confirmation = (BOOTSTRAP / "evidence" / "confirm" / f"{released()}-{WINDOWS_TARGET}.txt").read_text(encoding="ascii")
        recorded = next(line.split()[1] for line in confirmation.splitlines() if line.startswith("request "))
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / "request.xax"
            subprocess.run(["sh", str(GENERATOR / "generate.sh"), str(BOOTSTRAP / "seed" / "xax_compiler_request.xax"), str(out)], check=True, timeout=3600)
            self.assertEqual("%s:%d" % identity(out), recorded)


if __name__ == "__main__":
    unittest.main()
