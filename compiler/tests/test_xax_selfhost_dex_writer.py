"""S15e.6g.1 (ADR-349): the DEX file written by the XAX writer program equals ``xax_dex_jvm.write_dex``'s.

Seeded class sets: descriptors with and without a superclass, interfaces (shared and not), static and instance fields,
direct and virtual methods with and without code, and code units of every kind (values, strings with non-BMP text,
types, field and method references); a duplicate class makes the program decline.
"""

from __future__ import annotations

import platform
import random
import sys
import unittest

import xax_dex_jvm as D
from xax_selfhost_dex_writer import write_dex_with_xax

LINUX_X86_64 = sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")
TYPES = ("I", "J", "Z", "Ljava/lang/String;", "Lx/A;", "Lx/B;", "[I", "Lé/𝄞;")


def _classes(rng):
    names = rng.sample(("Lx/A;", "Lx/B;", "Lx/C;", "Lé/𝄞;", "Lq/Main;"), rng.randint(1, 4))
    classes = []
    for name in names:
        fields = tuple(D.DexFieldDef(f"f{k}", rng.choice(TYPES), rng.choice((0x1, 0x2, 0x8, 0x9, 0x12))) for k in range(rng.randint(0, 3)))
        methods = []
        for k in range(rng.randint(0, 4)):
            parameters = tuple(rng.choice(TYPES) for _ in range(rng.randint(0, 3)))
            access = rng.choice((0x1, 0x2, 0x8, 0x9, 0x10001, 0x401))
            code = None
            if not access & 0x400:
                units = []
                for _ in range(rng.randint(1, 8)):
                    kind = rng.randrange(5)
                    if kind == 0:
                        units.append(rng.randrange(0x10000))
                    elif kind == 1:
                        units.append(("string", rng.choice(("hello", "x𝄞", "", "Lx/A;"))))
                    elif kind == 2:
                        units.append(("type", rng.choice(TYPES)))
                    elif kind == 3:
                        units.append(("field", (rng.choice(names), f"g{rng.randrange(3)}", rng.choice(TYPES))))
                    else:
                        units.append(("method", (rng.choice((*names, "Ljava/lang/Object;")), rng.choice(("run", "<init>", "m")), rng.choice(("V", *TYPES)),
                                                 tuple(rng.choice(TYPES) for _ in range(rng.randint(0, 2))))))
                code = D.DexCode(rng.randint(4, 12), rng.randint(0, 3), rng.randint(0, 3), tuple(units))
            methods.append(D.DexMethodDef(f"m{k}", rng.choice(("V", *TYPES)), parameters, access, code))
        classes.append(D.DexClassDef(name, rng.choice((0x1, 0x11, 0x601)), rng.choice((None, "Ljava/lang/Object;", "Lx/Base;")),
                                     tuple(sorted(rng.sample(("Ljava/lang/Runnable;", "Lx/I;", "Lx/J;"), rng.randint(0, 2)))), fields, tuple(methods)))
    return classes


@unittest.skipUnless(LINUX_X86_64, "the XAX DEX writer program runs natively on Linux x86-64")
class SelfhostDexWriterTests(unittest.TestCase):
    def test_random_class_sets(self):
        rng = random.Random(349)
        for trial in range(60):
            classes = _classes(rng)
            with self.subTest(trial=trial):
                self.assertEqual(write_dex_with_xax(tuple(classes), required=True), D._write_dex_python(classes))

    def test_duplicate_class_declines(self):
        item = D.DexClassDef("Lx/A;", 1, "Ljava/lang/Object;")
        self.assertIsNone(write_dex_with_xax((item, item)))
        with self.assertRaises(Exception):
            D.write_dex([item, item])


if __name__ == "__main__":
    unittest.main()
