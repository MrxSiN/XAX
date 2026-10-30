"""S15e.6b (ADR-341): the APK Signature Scheme v2 signature written by the XAX program equals ``xax_apk_signing``'s.

The test signer over APKs of several sizes (one chunk and several 1 MiB chunks); inputs the bootstrap rejects (no end
record, a truncated one) make the program decline, and ``sign_apk_v2`` (which asks XAX first) still raises.

S15e.6i.1 (ADR-357): the transport mode decides ``decode_private_signing_capability`` and the signer's identity as
``build`` does, over the test signer's transport, hand-made faults and random byte faults.
"""

from __future__ import annotations

import platform
import random
import sys
import unittest

import xax_apk as P
import xax_apk_signing as R
import hashlib
import struct

from xax_selfhost_apk_signing import sign_transport_with_xax, sign_with_xax
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

    def test_transports(self):
        from xax_compiler import Diagnostic

        capability = signing_capability()
        apk = unsigned_fixture()
        transport = R.encode_private_signing_capability(capability)
        scope = bytes.fromhex(capability.identity_sha256)
        identity = b"android-app"

        def rejected(rule, expected, actual):
            return ("rejected", Diagnostic("XAX.BUILD.ANDROID", identity.hex(), rule, expected, actual, (), ()))

        def expected(data, scope=scope, effect=True):
            """``build``'s signing, in its order."""
            if not effect:
                return rejected("ANDROID-APK-SIGNING-CAPABILITY", "exactly one explicit package SIGN effect", 0)
            if len(scope) != 32:
                return rejected("ANDROID-APK-SIGNER-IDENTITY", "32-byte certificate SHA-256", scope.hex())
            try:
                decoded = R.decode_private_signing_capability(data)
            except (TypeError, ValueError):
                return rejected("ANDROID-APK-SIGNING-CAPABILITY", "valid private signing capability transport", "invalid")
            actual = hashlib.sha256(decoded.certificate_der).digest()
            if actual != scope:
                return rejected("ANDROID-APK-SIGNER-IDENTITY", scope.hex(), actual.hex())
            return ("signed", R._sign_apk_v2_python(apk, decoded))

        def fields(data):
            out, cursor = [], len(R.PRIVATE_SIGNING_CAPABILITY_MAGIC)
            while cursor < len(data):
                (size,) = struct.unpack_from("<I", data, cursor)
                out.append(data[cursor + 4:cursor + 4 + size])
                cursor += 4 + size
            return out

        def encode(items):
            return R.PRIVATE_SIGNING_CAPABILITY_MAGIC + b"".join(struct.pack("<I", len(item)) + item for item in items)

        n, e, d, certificate = fields(transport)
        modulus = int.from_bytes(n, "big")
        cases = {
            "valid": transport,
            "leading zeros": encode([b"\0\0" + n, b"\0" + e, b"\0" + d, certificate]),
            "magic": b"Y" + transport[1:],
            "truncated": transport[:-1],
            "trailing": transport + b"\0",
            "three fields": encode([n, e, d]),
            "empty field": encode([n, b"", d, certificate]),
            "small modulus": encode([n[:64], e, d, certificate]),
            "even exponent": encode([n, (2).to_bytes(1, "big"), d, certificate]),
            "exponent one": encode([n, b"\1", d, certificate]),
            "private exponent one": encode([n, e, b"\1", certificate]),
            "private exponent above": encode([n, e, (modulus + 1).to_bytes(len(n), "big"), certificate]),
            "private exponent equal": encode([n, e, n, certificate]),
            "other certificate": encode([n, e, d, certificate[:-1] + bytes([certificate[-1] ^ 1])]),
            "garbage certificate": encode([n, e, d, b"\x30\x03\x02\x01\x01"]),
        }
        for name, data in cases.items():
            with self.subTest(case=name):
                self.assertEqual(sign_transport_with_xax(apk, data, scope, identity), expected(data))
        rng = random.Random(357)
        for trial in range(160):
            data = bytearray(transport)
            for _ in range(rng.choice((1, 1, 2, 3))):
                data[rng.randrange(len(data))] = rng.getrandbits(8)
            with self.subTest(trial=trial):
                self.assertEqual(sign_transport_with_xax(apk, bytes(data), scope, identity), expected(bytes(data)))
        for name, other, effect in (("other signer", bytes(32), True), ("short scope", b"\1\2", True), ("no effect", scope, False)):
            with self.subTest(case=name):
                self.assertEqual(sign_transport_with_xax(apk, transport, other, identity, effect=effect), expected(transport, other, effect))

if __name__ == "__main__":
    unittest.main()
