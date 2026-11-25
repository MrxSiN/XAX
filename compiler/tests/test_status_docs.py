"""Documents that repeat current levels must match their sources; the XAX program `status-tool/xax_status.xax` writes
the blocks (`sh status.sh check|write [<repo>]`, its README). This file only runs it.

On Linux x86-64 every case runs with the pinned Linux seed. On Windows (with Git for Windows' `sh` on PATH) they run the
tools' Windows stores (`*_windows.xax`) built by the pinned Windows seed (OI-60); only the batch and generator checks
are Linux-only."""
import hashlib
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
MATRIX = REPO / "XAX_REPLACEMENT_MATRIX.json"
TOOL = REPO / "compiler" / "bootstrap" / "status-tool" / "status.sh"
LINUX_X86_64 = sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")
WINDOWS_X86_64 = sys.platform == "win32" and platform.machine().lower() in ("x86_64", "amd64") and shutil.which("sh") is not None
BOOTSTRAP = TOOL.parents[1]
BLOCK = re.compile(r"<!-- xax-status:(levels|targets|bootstrap) -->.*?<!-- /xax-status:\1 -->", re.S)


def status(mode: str, repo: Path | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(["sh", str(TOOL), mode, *([str(repo)] if repo else [])], capture_output=True, text=True, timeout=600)


def page_repo(directory: str, text: str) -> tuple[Path, Path]:
    root = Path(directory)
    shutil.copy(MATRIX, root / MATRIX.name)
    page = root / "page.md"
    page.write_text(text, encoding="utf-8")
    return root, page


@unittest.skipUnless(LINUX_X86_64 or WINDOWS_X86_64, "the status tool runs on the pinned Linux or Windows x86-64 seed")
class StatusDocsTests(unittest.TestCase):
    @unittest.skipUnless(LINUX_X86_64, "the ledger seed's xaxc edit runs on the Linux seed")
    def test_the_program_is_its_batch_on_the_ledger_seed(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / "xax_status.xax"
            subprocess.run([str(BOOTSTRAP / "seed" / "xaxc-linux-x86_64"), "edit", str(BOOTSTRAP / "evolution" / "ledger-tool" / "seed.xax"),
                            str(TOOL.parent / "status.batch"), str(out)], check=True, capture_output=True)
            self.assertEqual(out.read_bytes(), (TOOL.parent / "xax_status.xax").read_bytes())

    @unittest.skipUnless(LINUX_X86_64, "the Windows generator runs on the Linux seed")
    def test_the_windows_program_is_the_generated_one(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / "xax_status_windows.xax"
            subprocess.run(["sh", str(BOOTSTRAP / "windows" / "generator" / "generate.sh"), str(TOOL.parent / "xax_status.xax"), str(out)],
                           check=True, capture_output=True, timeout=1800)
            self.assertEqual(out.read_bytes(), (TOOL.parent / "xax_status_windows.xax").read_bytes())

    @unittest.skipUnless(WINDOWS_X86_64, "the Windows seed is checked where it runs")
    def test_the_windows_seed_is_its_pin(self):
        """OI-60: the seed these cases run is the released Windows seed (the candidate line of the latest validated
        release in RELEASES)."""
        lines = (BOOTSTRAP / "RELEASES").read_text(encoding="ascii").splitlines()
        release = [line.split()[1] for line in lines if line.startswith("validated ")][-1]
        candidate = next(line for line in lines if line.startswith(f"candidate {release} "))
        pinned = next(word.split("=", 1)[1] for word in candidate.split() if word.startswith("x86_64-windows-pe-v1="))
        seed = (BOOTSTRAP / "windows" / "xaxc-windows-x86_64.exe").read_bytes()
        self.assertEqual(f"{hashlib.sha256(seed).hexdigest()}:{len(seed)}", pinned)

    def test_every_block_matches_its_source(self):
        documents = [p for p in REPO.rglob("*.md") if ".git" not in p.parts and BLOCK.search(p.read_text(encoding="utf-8"))]
        self.assertGreaterEqual(len(documents), 5)
        run = status("check")
        self.assertEqual((run.returncode, run.stdout), (0, ""), "run: sh compiler/bootstrap/status-tool/status.sh write\n" + run.stderr)

    def test_a_stale_block_is_detected_and_rewritten(self):
        with tempfile.TemporaryDirectory() as directory:
            root, page = page_repo(directory, "# Page\n\n<!-- xax-status:levels -->R6: everything<!-- /xax-status:levels -->\n")
            run = status("check", root)
            self.assertEqual((run.returncode, run.stdout), (1, "stale: page.md\n"))
            self.assertEqual(status("write", root).stdout, "updated: page.md\n")
            self.assertRegex(page.read_text(encoding="utf-8"), r"R6: [^;]*linux-x86_64")
            run = status("check", root)
            self.assertEqual((run.returncode, run.stdout), (0, ""))

    def test_targets_table_lists_every_platform_with_its_level(self):
        with tempfile.TemporaryDirectory() as directory:
            root, page = page_repo(directory, "# Page\n\n<!-- xax-status:targets --><!-- /xax-status:targets -->\n")
            self.assertEqual(status("write", root).stdout, "updated: page.md\n")
            text = page.read_text(encoding="utf-8")
            self.assertIn("| x86-64 Linux | `linux-x86_64` | R6 |", text)
            self.assertIn("| .NET CLI/CLR | `dotnet-clr` | \N{EM DASH} |", text)
            self.assertLess(text.index("`linux-x86_64`"), text.index("`dotnet-clr`"))

    def test_an_opening_tag_without_its_closing_tag_stays(self):
        with tempfile.TemporaryDirectory() as directory:
            text = "a <!-- xax-status:levels --> b <!-- /xax-status:targets -->\n"
            root, page = page_repo(directory, text)
            self.assertEqual((status("check", root).returncode, page.read_text(encoding="utf-8")), (0, text))

    def test_bootstrap_block_is_the_derived_status(self):
        """STATUS_DOCS_SYNCHRONIZED for B levels: the block comes from the executed records, never prose. The oracle is
        ``bootstrap_status`` (W3, ADR-362: no M14 evidence, and the bootstrap seed is the native compiler)."""
        from xax_selfhost_seed import bootstrap_status

        status_ = bootstrap_status()
        with tempfile.TemporaryDirectory() as directory:
            root, page = page_repo(directory, "<!-- xax-status:bootstrap -->B6 everywhere<!-- /xax-status:bootstrap -->")
            self.assertEqual(status("write", root).stdout, "updated: page.md\n")
            text = page.read_text(encoding="utf-8")
            full = status_["full_production_compiler"]
            established = [f"B{n}" for n in range(7) if full[f"B{n}"]]
            self.assertIn("whole production compiler: " + (f"{', '.join(established)} established" if established else "none of B0-B6 is established"),
                          text)
            self.assertNotIn("B6 everywhere", text)
            self.assertNotIn("M14", text)
            self.assertIn(f"Bootstrap seed: native-elf `compiler/bootstrap/seed/xaxc-linux-x86_64`, {status_['bootstrap_seed']['bytes']:,} bytes", text)
            self.assertIn("requires Python: " + ("yes" if status_["bootstrap_seed"]["requires_python"] else "no") + ".", text)


if __name__ == "__main__":
    unittest.main()
