"""S15e.6b (ADR-341): the APK Signature Scheme v2 signature written by the XAX program equals ``xax_apk_signing``'s.

The test signer over APKs of several sizes (one chunk and several 1 MiB chunks); inputs the bootstrap rejects (no end
record, a truncated one) make the program decline, and ``sign_apk_v2`` (which asks XAX first) still raises.
"""

from __future__ import annotations

import platform
import random
import sys
import unittest

import xax_apk as P
import xax_apk_signing as R
from xax_selfhost_apk_signing import sign_with_xax
from test_xax_apk_signing import signing_capability, unsigned_fixture

LINUX_X86_64 = sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")


@unittest.skipUnless(LINUX_X86_64, "the XAX APK signer program runs natively on Linux x86-64")
class SelfhostApkSigningTests(unittest.TestCase):
    def test_signed_apks(self):
        capability = signing_capability()
        rng = random.Random(341)
        apks = [unsigned_fixture()]
        for size in (0, 1, 4095, (1 << 20) + 17):
            library = bytes(rng.getrandbits(8) for _ in range(size))
            apks.append(P.build_unsigned_apk(b"\x03\x00\x08\x00" + bytes(60), b"dex\n039\x00" + bytes(100),
                                             native_libraries={"libxaxapp.so": library}))
        for index, apk in enumerate(apks):
            with self.subTest(apk=index):
                signed = sign_with_xax(apk, capability, required=True)
                self.assertEqual(signed, R._sign_apk_v2_python(apk, capability))
                self.assertTrue(R.inspect_apk_v2(signed).signature_valid)
        self.assertEqual(R.sign_apk_v2(apks[0], capability), R._sign_apk_v2_python(apks[0], capability))

    def test_rejected_inputs_decline(self):
        capability = signing_capability()
        for apk in (b"junk" * 10, unsigned_fixture()[:-3]):
            with self.subTest(size=len(apk)):
                self.assertIsNone(sign_with_xax(apk, capability))
                with self.assertRaises(ValueError):
                    R.sign_apk_v2(apk, capability)


if __name__ == "__main__":
    unittest.main()
