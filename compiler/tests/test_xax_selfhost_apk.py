"""S15e.6a (ADR-340): the APK container built by the XAX program equals ``xax_apk``'s.

Seeded entry sets (names ASCII and not, empty to 5000-byte data, every alignment ``build_unsigned_apk`` uses and
others); where the bootstrap itself fails (an alignment of 2 needing one to three padding bytes) the program declines.
"""

from __future__ import annotations

import platform
import random
import sys
import unittest

import xax_apk as P
from xax_selfhost_apk import apk_with_xax

LINUX_X86_64 = sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")
NAMES = ("classes.dex", "AndroidManifest.xml", "resources.arsc", "lib/arm64-v8a/libxax.so", "résumé.txt", "classes2.dex")


@unittest.skipUnless(LINUX_X86_64, "the XAX APK container program runs natively on Linux x86-64")
class SelfhostApkTests(unittest.TestCase):
    def test_random_containers(self):
        rng = random.Random(340)
        outcomes = set()
        for trial in range(60):
            names = set()
            entries = []
            while len(entries) < rng.randint(1, 6):
                name = rng.choice((*NAMES, f"assets/{rng.randrange(100)}", "z" * rng.randint(1, 40)))
                if name in names:
                    continue
                names.add(name)
                size = rng.choice((0, 1, 7, 8, 9, 100, 5000))
                entries.append(P.ApkEntry(name, bytes(rng.getrandbits(8) for _ in range(size)), rng.choice((1, 2, 4, 8, 16384))))
            built = apk_with_xax(tuple(sorted(entries, key=lambda item: item.name.encode("utf-8"))))
            try:
                expected = P._build_apk_python(tuple(sorted(entries, key=lambda item: item.name.encode("utf-8"))))
            except Exception:  # noqa: BLE001 - the bootstrap's own failure: the program declines
                expected = None
            with self.subTest(trial=trial):
                self.assertEqual(built, expected)
            outcomes.add("built" if built is not None else "declined")
        self.assertEqual(outcomes, {"built", "declined"})

    def test_unsigned_apk(self):
        """``build_unsigned_apk``'s layout (the 16 KiB native alignment) through ``build_apk``, which asks XAX first."""
        manifest, dex, library = b"\x03\x00\x08\x00" + bytes(60), b"dex\n039\x00" + bytes(100), b"\x7fELF" + bytes(3000)
        entries = (P.ApkEntry("AndroidManifest.xml", manifest), P.ApkEntry("classes.dex", dex),
                   P.ApkEntry("lib/arm64-v8a/libxaxapp.so", library, P.DEFAULT_NATIVE_ALIGNMENT), P.ApkEntry("resources.arsc", bytes(77)))
        self.assertEqual(apk_with_xax(entries), P._build_apk_python(entries))
        self.assertEqual(P.build_unsigned_apk(manifest, dex, native_libraries={"libxaxapp.so": library}, extra_entries={"resources.arsc": bytes(77)}),
                         P._build_apk_python(entries))


if __name__ == "__main__":
    unittest.main()
