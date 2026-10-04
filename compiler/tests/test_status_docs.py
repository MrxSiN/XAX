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
            self.assertRegex(page.read_text(), r"R4: [^;]*linux-x86_64")
            self.assertEqual(sync(write=False, repo=root), [])

    def test_targets_table_lists_every_platform_with_its_level(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            shutil.copy(MATRIX, root / MATRIX.name)
            page = root / "page.md"
            page.write_text("# Page\n\n<!-- xax-status:targets --><!-- /xax-status:targets -->\n")
            self.assertEqual(sync(write=True, repo=root), [page])
            text = page.read_text()
            self.assertIn("| x86-64 Linux | `linux-x86_64` | R4 |", text)
            self.assertIn("| .NET CLI/CLR | `dotnet-clr` | — |", text)
            self.assertLess(text.index("`linux-x86_64`"), text.index("`dotnet-clr`"))


if __name__ == "__main__":
    unittest.main()
