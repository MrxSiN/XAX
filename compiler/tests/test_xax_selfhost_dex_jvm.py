"""S15e.6g.2 (ADR-350): the DEX class the XAX JVM-to-DEX lowering program gives equals ``xax_dex_jvm.translate_class``'s.

javac-compiled fixtures (``tests/fixtures/dex_jvm``, plus a method long enough for ``goto/32`` and inverted tests and one
with more than 256 registers) cover the instruction table: constants and ``ldc`` of every kind, loads and stores (and
``wide``), arrays of every element type, the dup/swap forms, integer, long, float and double arithmetic and conversions,
``iinc``, every branch, table and lookup switches, returns, field access, the four invoke forms, object and array
creation, casts, and ``StackMapTable`` frames.  Each class is lowered with and without renames.  A class the bootstrap
rejects (a ternary's frame with a non-empty stack, an exception handler, modified UTF-8) makes the program decline.
"""

from __future__ import annotations

import functools
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

LINUX_X86_64 = sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")
FIXTURES = Path(__file__).resolve().parent / "fixtures" / "dex_jvm"
RENAMES = (None, {"xax/Ops": "xax/Renamed", "xax/Base": "q/Root", "java/lang/Object": "java/lang/Object"})


def _generated() -> dict[str, str]:
    big = ["package xax;", "public class Big {", "  static int big(int a, int b) {", "    int r = 0;", "    while (a < b) {"]
    big += [f"      r += a * {k + 3} ^ (r >>> 3);" for k in range(4000)]
    big += ["      a++;", "    }", "    if (r == 0) { r = 1; }", "    return r;", "  }", "}"]
    names = [f"q{k}" for k in range(150)]
    more = ["package xax;", "public class More {", "  static long lv() { return 3L; }",
            "  static float f(float x, float y) { float z = 2.0f; x = -x % y + z; return x; }",
            "  static double d(double a, double b) { a = b; double c = a; return -c; }",
            "  static int cmp(int a, int b) { int r = 0; if (a <= b) r++; if (a > b) r += 2; if (a >= b) r += 4; return r; }",
            "  static void p() { lv(); lv(); }", "  static long many(long a) {"]
    more += [f"    long {name} = a + {len(name)};" for name in names] + ["    long s = 0;"] + [f"    s += {name} * {name};" for name in names]
    more += ["    int i = (int) s; i += 40000; double dd = s; float ff = i; dd += ff;", "    return s + i + (long) dd;", "  }", "}"]
    return {"Big.java": "\n".join(big), "More.java": "\n".join(more)}


@functools.lru_cache(maxsize=1)
def _classes() -> dict[str, bytes]:
    with tempfile.TemporaryDirectory() as work:
        sources = Path(work) / "src"
        sources.mkdir()
        for path in FIXTURES.glob("*.java"):
            shutil.copy(path, sources / path.name)
        for name, text in _generated().items():
            (sources / name).write_text(text)
        subprocess.run(["javac", "--release", "8", "-encoding", "UTF-8", "-nowarn", "-d", str(Path(work) / "out"), *sorted(map(str, sources.glob("*.java")))],
                       check=True, capture_output=True)
        return {path.name: path.read_bytes() for path in sorted((Path(work) / "out").rglob("*.class"))}


@unittest.skipUnless(LINUX_X86_64 and shutil.which("javac"), "the XAX lowering program runs natively on Linux x86-64; the fixtures need javac")
class SelfhostDexJvmTests(unittest.TestCase):
    def test_javac_classes(self):
        import xax_dex_jvm as D
        from xax_compiler import XaxError
        from xax_selfhost_dex_jvm import translate_class_with_xax

        rejected = set()
        for name, data in _classes().items():
            for rename in RENAMES:
                with self.subTest(cls=name, rename=bool(rename)):
                    try:
                        reference = D._translate_class_python(data, rename)
                    except (XaxError, UnicodeDecodeError):
                        reference = None
                        rejected.add(name)
                    lowered = translate_class_with_xax(data, rename)
                    self.assertEqual(lowered, reference)
        self.assertEqual(rejected, {"Tern.class", "Exc.class", "Mutf.class"})

    def test_long_branches_and_registers(self):
        import xax_dex_jvm as D

        classes = _classes()
        big = D.translate_class(classes["Big.class"])
        self.assertIn(0x2A, [unit for method in big.methods if method.code for unit in method.code.units if isinstance(unit, int)])
        more = D.translate_class(classes["More.class"])
        self.assertGreater(max(method.code.registers for method in more.methods if method.code), 256)


if __name__ == "__main__":
    unittest.main()
