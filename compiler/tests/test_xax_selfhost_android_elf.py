"""S15e.6e (ADR-346): the Android AArch64 shared object written by the XAX program equals ``xax_android``'s.

Seeded bundles (one to five functions in any offset order, foreign calls to several libraries with non-ASCII names),
exports, SONAMEs, rodata, data and BSS sizes, in both the classic and the packed (format 5) layouts; inputs the bootstrap
rejects (a duplicate export, an ambiguous import, an unknown export function) make the program decline.
"""

from __future__ import annotations

import platform
import random
import sys
import unittest

import xax_android as A
from xax_aarch64 import Aarch64Bundle
from xax_selfhost_android_elf import elf_with_xax

LINUX_X86_64 = sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")


def _bundle(rng):
    nfn=rng.randint(1,5)
    code=bytes(rng.getrandbits(8) for _ in range(4*rng.randint(nfn, 200)))
    offs=sorted(rng.sample(range(0,len(code),4), nfn))
    if rng.random()<0.3: offs=offs[::-1]
    fns=tuple((bytes([k])*32, o) for k,o in enumerate(offs))
    libs=(b"libc.so",b"liblog.so",b"libandroid.so")
    names=[b"malloc",b"free",b"__android_log_print",b"ANativeActivity_finish",b"x\xc3\xa9"]
    calls=[]
    lib_of={}
    for _ in range(rng.randint(0,6)):
        n=rng.choice(names); l=lib_of.setdefault(n, rng.choice(libs))
        calls.append((rng.randrange(0,len(code),4), l, n))
    return Aarch64Bundle(code, b"t"*32, fns, tuple(calls))


def _case(rng):
    bundle = _bundle(rng)
    exports = [A.AndroidExport(rng.choice((b"Java_x_A_f", b"JNI_OnLoad", b"xax_main", b"z")) + bytes([97 + k]),
                               bundle.function_offsets[rng.randrange(len(bundle.function_offsets))][0]) for k in range(rng.randint(1, 3))]
    options = dict(soname=rng.choice((b"libxaxmodule.so", b"libapp.so")), rodata=bytes(rng.getrandbits(8) for _ in range(rng.choice((0, 5, 100)))),
                   data=bytes(rng.getrandbits(8) for _ in range(rng.choice((0, 8, 33)))), bss_bytes=rng.choice((0, 16, 5000)), packed=rng.random() < 0.5)
    return bundle, exports, options


@unittest.skipUnless(LINUX_X86_64, "the XAX Android ELF program runs natively on Linux x86-64")
class SelfhostAndroidElfTests(unittest.TestCase):
    def test_random_shared_objects(self):
        rng = random.Random(346)
        for trial in range(40):
            bundle, exports, options = _case(rng)
            with self.subTest(trial=trial):
                built = elf_with_xax(bundle, tuple(exports), required=True, **options)
                expected = A._emit_android_elf_python(bundle, exports, **options)
                self.assertEqual(built, (expected.data, expected.text_offset, expected.metrics.text_bytes, expected.metrics.imported_symbols,
                                         expected.metrics.needed_libraries))
                self.assertEqual(A.emit_android_elf(bundle, exports, **options), expected)

    def test_rejections_decline(self):
        bundle, exports, options = _case(random.Random(3460))
        cid = bundle.function_offsets[0][0]
        ambiguous = Aarch64Bundle(bundle.code, bundle.target_cid, bundle.function_offsets, ((0, b"liba.so", b"f"), (4, b"libb.so", b"f")))
        for case in ((bundle, [A.AndroidExport(b"x", cid), A.AndroidExport(b"x", cid)]), (ambiguous, [A.AndroidExport(b"x", cid)]),
                     (bundle, [A.AndroidExport(b"x", b"?" * 32)])):
            with self.subTest(case=case[1]):
                self.assertIsNone(elf_with_xax(case[0], tuple(case[1]), **options))
                with self.assertRaises(Exception):
                    A.emit_android_elf(case[0], case[1], **options)


if __name__ == "__main__":
    unittest.main()
