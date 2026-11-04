"""Documents that repeat replacement levels must match the matrix they are generated from."""
import shutil
import tempfile
import unittest
from pathlib import Path

from xax_status_docs import MATRIX, REPO, documents, sync


class StatusDocsTests(unittest.TestCase):
    def test_every_levels_block_matches_the_matrix(self):
        self.assertGreaterEqual(len(documents()), 5)
        self.assertEqual(sync(write=False), [], "run: python -m xax_status_docs --write")

    def test_a_stale_block_is_detected_and_rewritten(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            shutil.copy(MATRIX, root / MATRIX.name)
            page = root / "page.md"
            page.write_text("# Page\n\n<!-- xax-status:levels -->R6: everything<!-- /xax-status:levels -->\n")
            self.assertEqual(sync(write=False, repo=root), [page])
            self.assertEqual(sync(write=True, repo=root), [page])
            self.assertRegex(page.read_text(), r"R6: [^;]*linux-x86_64")
            self.assertEqual(sync(write=False, repo=root), [])

    def test_targets_table_lists_every_platform_with_its_level(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            shutil.copy(MATRIX, root / MATRIX.name)
            page = root / "page.md"
            page.write_text("# Page\n\n<!-- xax-status:targets --><!-- /xax-status:targets -->\n")
            self.assertEqual(sync(write=True, repo=root), [page])
            text = page.read_text(encoding="utf-8")
            self.assertIn("| x86-64 Linux | `linux-x86_64` | R6 |", text)
            self.assertIn("| .NET CLI/CLR | `dotnet-clr` | \N{EM DASH} |", text)
            self.assertLess(text.index("`linux-x86_64`"), text.index("`dotnet-clr`"))

    def test_bootstrap_block_is_the_derived_status(self):
        """STATUS_DOCS_SYNCHRONIZED for B levels: the block comes from ``bootstrap_status`` over the executed records,
        never prose (W3, ADR-362: no M14 evidence, and the bootstrap seed is the native compiler)."""
        from xax_selfhost import bootstrap_status

        status = bootstrap_status()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            page = root / "page.md"
            page.write_text("<!-- xax-status:bootstrap -->B6 everywhere<!-- /xax-status:bootstrap -->", encoding="utf-8")
            self.assertEqual(sync(write=True, repo=root), [page])
            text = page.read_text(encoding="utf-8")
            full = status["full_production_compiler"]
            established = [f"B{n}" for n in range(7) if full[f"B{n}"]]
            self.assertIn("whole production compiler: " + (f"{', '.join(established)} established" if established else "none of B0-B6 is established"),
                          text)  # S15g (ADR-358): the derived levels, whatever they are
            self.assertNotIn("B6 everywhere", text)
            self.assertNotIn("M14", text)
            self.assertIn("Bootstrap seed: native-elf `compiler/bootstrap/seed/xaxc-linux-x86_64`", text)
            self.assertIn("requires Python: " + ("yes" if status["bootstrap_seed"]["requires_python"] else "no") + ".", text)
        self.assertTrue(any("xax-status:bootstrap" in path.read_text(encoding="utf-8") for path in documents()))


if __name__ == "__main__":
    unittest.main()
