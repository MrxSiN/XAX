"""ADR-129: static linking of freestanding C objects into bare-metal XAX images."""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from xax_compiler import XaxError

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from benchmarks.board_linked_c import CFLAGS, EXPECTED, OBJECT_NAME, build, compile_object  # noqa: E402

CROSS = shutil.which("aarch64-linux-gnu-gcc")
QEMU = shutil.which("qemu-system-aarch64")


def _object(directory: Path, source: str, *flags: str, name: str = "unit.o") -> Path:
    path = directory / "unit.c"
    path.write_text(source)
    output = directory / name
    subprocess.run([CROSS, *CFLAGS, *flags, "-c", str(path), "-o", str(output)], check=True)
    return output


@unittest.skipUnless(CROSS, "requires aarch64-linux-gnu-gcc")
class StaticLinkTests(unittest.TestCase):
    def test_layout_is_deterministic_and_symbols_resolve(self):
        from xax_elf_link import link_objects

        with tempfile.TemporaryDirectory() as directory:
            path = compile_object(Path(directory))
            first, second = link_objects([path], 0x40090000), link_objects([path], 0x40090000)
            self.assertEqual(first, second)
            self.assertEqual(sorted(first.symbols), ["board_alloc", "board_crc32", "board_release"])
            self.assertTrue(first.writable)

    def _refusal(self, source: str, *flags: str, externals=None) -> str:
        from xax_elf_link import link_objects

        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(XaxError) as caught:
                link_objects([_object(Path(directory), source, *flags)], 0x40090000, externals)
            return caught.exception.diagnostic.rule

    def test_refusals(self):
        self.assertEqual(self._refusal("int missing(void); int f(void) { return missing(); }"), "LINK-SYMBOL-DEFINED")
        self.assertEqual(self._refusal("extern int shared; int f(void) { return shared; }", "-fpic", externals={"shared": 0x40100000}), "LINK-RELOCATION-TYPE")
        self.assertEqual(self._refusal("int common_value; int f(void) { return common_value; }", "-fcommon"), "LINK-NO-COMMON")

    def test_declaration_must_name_the_defining_object(self):
        from xax_board import compile_board_image

        reader, reset, handler, board = build()
        with tempfile.TemporaryDirectory() as directory:
            renamed = Path(directory) / "other.o"
            renamed.write_bytes(compile_object(Path(directory)).read_bytes())
            with self.assertRaises(XaxError) as caught:
                compile_board_image(reader, reset.cid, handler.cid, board.cid, objects=[renamed])
            self.assertEqual(caught.exception.diagnostic.rule, "BOARD-STATIC-SYMBOL")
            with self.assertRaises(XaxError) as caught:
                compile_board_image(reader, reset.cid, handler.cid, board.cid)
            self.assertEqual(caught.exception.diagnostic.rule, "BOARD-STATIC-SYMBOL")

    @unittest.skipUnless(QEMU, "requires qemu-system-aarch64")
    def test_xax_calls_linked_c_on_the_board(self):
        from xax_board import compile_board_image, run_board_image

        reader, reset, handler, board = build()
        with tempfile.TemporaryDirectory() as directory:
            image = compile_board_image(reader, reset.cid, handler.cid, board.cid, objects=[compile_object(Path(directory))])
        completed = run_board_image(image)
        self.assertEqual((completed.returncode, completed.stdout), (0, EXPECTED))


if __name__ == "__main__":
    unittest.main()
