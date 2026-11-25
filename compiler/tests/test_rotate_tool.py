"""RFC phase 6: the native release-state program (``bootstrap/seed/rotate-tool``).

On Linux x86-64 with the pinned seed: the committed program is the seed's ``xaxc edit`` of its batch; the committed
state is release 0038, released, with pins equal to the committed seeds (ADR-410); and on copies of
RELEASES and LEDGER the lifecycle reads as RFC section 3 says: development and its POLICY tests, a candidate with
pending hosts, a confirmation with the wrong hash, a confirmed candidate, a stale one, and a blocked one.
"""

from __future__ import annotations

import hashlib
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

BOOTSTRAP = Path(__file__).resolve().parents[1] / "bootstrap"
TOOL = BOOTSTRAP / "seed" / "rotate-tool"
SEED = BOOTSTRAP / "seed" / "xaxc-linux-x86_64"
LINUX_X86_64 = sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")
WINDOWS_X86_64 = sys.platform == "win32" and platform.machine().lower() in ("x86_64", "amd64") and shutil.which("sh") is not None
H1, H2 = "1" * 64, "2" * 64


@unittest.skipUnless(LINUX_X86_64, "the pinned seed runs on Linux x86-64")
class RotateToolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        work = Path(cls.directory.name)
        subprocess.run([str(SEED), "resolve", str(TOOL / "xax_rotate.xax"), str(work / "tool.xax")], check=True)
        subprocess.run([str(SEED), "build", str(work / "tool.xax"), str(work / "xax_rotate"), str(work / "provenance")], check=True)
        (work / "xax_rotate").chmod(0o755)
        cls.tool = work / "xax_rotate"

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def run_tool(self, *arguments):
        """(exit status, text): the tool writes its text to a file, its last argument (rotate-tool/README.md)."""
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / "out"
            done = subprocess.run([str(self.tool), *map(str, arguments), str(out)], capture_output=True, check=False)
            return done.returncode, out.read_bytes().decode() if out.exists() else ""

    def test_the_store_is_its_batch(self):
        """rotate.batch, then driver.batch (2026-11-25: the general driver's entry and host functions)."""
        with tempfile.TemporaryDirectory() as directory:
            first, out = Path(directory) / "first.xax", Path(directory) / "tool.xax"
            subprocess.run([str(SEED), "edit", str(BOOTSTRAP / "evolution" / "ledger-tool" / "seed.xax"), str(TOOL / "rotate.batch"), str(first)], check=True)
            subprocess.run([str(SEED), "edit", str(first), str(TOOL / "driver.batch"), str(out)], check=True)
            self.assertEqual(out.read_bytes(), (TOOL / "xax_rotate.xax").read_bytes())

    def test_the_committed_state_and_pins(self):
        status, text = self.run_tool("state", BOOTSTRAP)
        self.assertEqual(status, 0)
        self.assertIn("validated 0043\ncandidate none\nprofile released\n", text)
        for target, seed in (("x86_64-linux-elf-exec-v1", SEED), ("x86_64-windows-pe-v1", BOOTSTRAP / "windows" / "xaxc-windows-x86_64.exe")):
            data = seed.read_bytes()
            self.assertEqual(self.run_tool("pin", BOOTSTRAP, target), (0, f"{hashlib.sha256(data).hexdigest()}:{len(data)}\n"), target)
            self.assertEqual(self.run_tool("id", seed), self.run_tool("pin", BOOTSTRAP, target), target)
        self.assertEqual(self.run_tool("pin", BOOTSTRAP, "no-such-target")[0], 1)

    def test_the_lifecycle(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "evolution").mkdir()
            for name in ("RELEASES", "POLICY"):
                shutil.copy(BOOTSTRAP / name, root / name)
            shutil.copy(BOOTSTRAP / "evolution" / "LEDGER", root / "evolution" / "LEDGER")

            def append(path, line):
                with open(root / path, "a", encoding="ascii") as file:
                    file.write(line + "\n")

            def check(profile_line, pending=(), tests=None, status=0):
                code, text = self.run_tool("state", root)
                self.assertEqual(code, status, text)
                self.assertEqual(text.splitlines()[-1], profile_line)
                self.assertEqual([line[8:] for line in text.splitlines() if line.startswith("pending ")], list(pending))
                if tests is not None:
                    self.assertEqual(self.run_tool("tests", root), (0, tests))

            policy = {line.split()[1]: " ".join(line.split()[2:]) for line in (BOOTSTRAP / "POLICY").read_text().splitlines() if line.startswith("test ")}
            append("evolution/LEDGER", "0044-x.batch xax_x86_64_general.xax aaaa bbbb")
            append("evolution/LEDGER", "derived seed/xax_compiler_request.xax cccc dddd")
            check("profile development", tests=f"{policy['*']}\n{policy['xax_x86_64_general.xax']}\n")
            append("RELEASES", f"candidate 0044 ledger=0044-x.batch driver=ff policy=00 x86_64-linux-elf-exec-v1={H1}:10 x86_64-windows-pe-v1={H2}:20")
            check("unmet confirm", ("x86_64-linux-elf-exec-v1", "x86_64-windows-pe-v1"), "all\n", 1)
            append("RELEASES", f"confirmed 0044 x86_64-linux-elf-exec-v1 {H1} ee")
            append("RELEASES", f"confirmed 0044 x86_64-windows-pe-v1 {H1} ee")
            check("unmet confirm", ("x86_64-windows-pe-v1",), status=1)
            append("RELEASES", f"confirmed 0044 x86_64-windows-pe-v1 {H2} ee")
            check("profile candidate", tests="all\n")
            append("evolution/LEDGER", "0045-y.batch xax_android.xax aaaa bbbb")
            check("profile development", tests=f"{policy['*']}\n{policy['xax_x86_64_general.xax']}\n{policy['xax_android.xax']}\n")
            append("RELEASES", "blocked 0044 c1 three repairs failed")
            check("unmet blocked", tests="", status=1)

    def test_valid_levels(self):
        with tempfile.TemporaryDirectory() as directory:
            levels = Path(directory) / "levels"
            good = "".join(f"B{n} 1\n" for n in range(7)) + "rotated 1\npython 0\n"
            for text, status in ((good, 0), (good.replace("B6 1", "B6 0"), 1), (good.replace("python 0", "python 1"), 1), (good + "\n", 1)):
                levels.write_text(text, encoding="ascii")
                self.assertEqual(self.run_tool("valid", levels)[0], status)


@unittest.skipUnless(WINDOWS_X86_64, "the Windows release tool runs where the Windows seed runs")
class WindowsRotateToolTests(unittest.TestCase):
    """OI-60: rotate.sh's release tool on the Windows seed (rotate-tool/xax_rotate_windows.xax)."""

    def test_state_names_the_released_profile(self):
        run = subprocess.run(["sh", str(BOOTSTRAP / "seed" / "rotate.sh"), "state"], capture_output=True, text=True, timeout=1800)
        self.assertEqual(run.returncode, 0, run.stderr)
        lines = run.stdout.splitlines()
        self.assertTrue(lines[0].startswith("ledger ") and any(line.startswith("validated ") for line in lines), run.stdout)
        self.assertIn(lines[-1], ("profile released", "profile candidate", "profile development"))


if __name__ == "__main__":
    unittest.main()
