"""S15c.3 (ADR-301): SHA-512 and Ed25519 verification as XAX functions, against the Python reference.

``xax_selfhost_ed25519``'s ``hash`` (a test entry) and ``verify`` are lowered alone and run natively over a workspace.
Differential: SHA-512 digests equal ``hashlib``'s across block boundaries; every verdict equals
``xax_ed25519.verify_bytes`` on valid signatures, single-bit mutations of keys, signatures and messages, and the
encodings RFC 8032 rejects (S at or above L, y at or above p, x = 0 with the sign bit set, small-order points).  The
reference itself is checked against ``cryptography`` when that package is installed.
"""

from __future__ import annotations

import ctypes
import hashlib
import platform
import random
import sys
import unittest

import xax_compiler as X
import xax_ed25519 as R

LINUX_X86_64 = sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")
SMALL_ORDER = (
    "0100000000000000000000000000000000000000000000000000000000000000",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "0000000000000000000000000000000000000000000000000000000000000080",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
)


class ReferenceTests(unittest.TestCase):
    def test_reference_against_cryptography(self):
        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        except ImportError:
            self.skipTest("UNAVAILABLE: the cryptography package is not installed")
        rng = random.Random(301)
        for trial in range(24):
            secret, message = rng.randbytes(32), rng.randbytes(3 * trial)
            key = Ed25519PrivateKey.from_private_bytes(secret)
            public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            self.assertEqual(R.public_key(secret), public)
            self.assertEqual(R.sign_bytes(secret, message), key.sign(message))
            self.assertTrue(R.verify_bytes(public, message, key.sign(message)))

    def test_signature_verifier(self):
        secret, root = bytes(range(32)), bytes(32)
        value = R.sign(secret, root)
        self.assertTrue(R.signature_verifier(R.ALGORITHM, R.public_key(secret), root, value))
        self.assertFalse(R.signature_verifier(b"ed448", R.public_key(secret), root, value))
        self.assertFalse(R.signature_verifier(R.ALGORITHM, R.public_key(secret), b"\x01" + root[1:], value))


@unittest.skipUnless(LINUX_X86_64, "UNAVAILABLE: the helper images run on Linux x86-64 only")
class XaxEd25519Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import xax_selfhost_ed25519 as ED
        from xax_graph_builder import program_store
        from xax_native import zeroed_array
        from xax_selfhost_typing import OUT_WORDS
        from xax_x86_64_views import NativeViewsImage, compile_x86_64_views

        building = X._TYPING_BUILDING
        X._TYPING_BUILDING = True
        try:
            functions, objects = ED.build_functions(test_entries=True)
        finally:
            X._TYPING_BUILDING = building
        cls.ED = ED
        cls.images = {}
        for name in ("hash", "verify"):
            reader = program_store(functions[name], X.x86_64_linux_exec_target(), objects)
            cls.images[name] = NativeViewsImage(compile_x86_64_views(reader, functions[name].cid, X.x86_64_views_target(), backend="python"))
        cls.input = zeroed_array(ctypes.c_uint64, 16)
        cls.output = zeroed_array(ctypes.c_uint64, OUT_WORDS)

    def _message(self, data: bytes):
        self.output[self.ED.MSG_LENGTH] = len(data)
        for k, byte in enumerate(data):
            self.output[self.ED.MSG_AT + k] = byte

    def verify(self, key: bytes, message: bytes, value: bytes) -> int:
        for k, byte in enumerate(key):
            self.output[self.ED.PK_AT + k] = byte
        for k, byte in enumerate(value):
            self.output[self.ED.SIG_AT + k] = byte
        self._message(message)
        return self.images["verify"](ctypes.addressof(self.input), ctypes.addressof(self.output))

    def assertVerdict(self, key: bytes, message: bytes, value: bytes):
        self.assertEqual(self.verify(key, message, value), int(R.verify_bytes(key, message, value)), (key.hex(), message.hex(), value.hex()))

    def test_sha512(self):
        rng = random.Random(512)
        for length in (0, 1, 3, 111, 112, 113, 127, 128, 129, 239, 240, 256, 600, 1024):
            data = rng.randbytes(length)
            self._message(data)
            self.images["hash"](ctypes.addressof(self.input), ctypes.addressof(self.output))
            self.assertEqual(bytes(self.output[self.ED.HASH_AT + k] for k in range(64)), hashlib.sha512(data).digest(), length)

    def test_random_signatures(self):
        rng = random.Random(25519)
        verdicts = set()
        for _trial in range(30):
            secret, message = rng.randbytes(32), rng.randbytes(rng.randrange(0, 120))
            key, value = R.public_key(secret), R.sign_bytes(secret, message)
            cases = [(key, message, value), (key, message + b"x", value)]
            for _mutation in range(2):
                bad = bytearray(value)
                bad[rng.randrange(64)] ^= 1 << rng.randrange(8)
                cases.append((key, message, bytes(bad)))
                other = bytearray(key)
                other[rng.randrange(32)] ^= 1 << rng.randrange(8)
                cases.append((bytes(other), message, value))
            for case in cases:
                self.assertVerdict(*case)
                verdicts.add(R.verify_bytes(*case))
        self.assertEqual(verdicts, {True, False})

    def test_rfc8032_encodings(self):
        secret, message = b"\x07" * 32, b"edge"
        key, value = R.public_key(secret), R.sign_bytes(secret, message)
        s = int.from_bytes(value[32:], "little")
        cases = [(key, message, value[:32] + scalar.to_bytes(32, "little")) for scalar in (s + R.L, R.L, R.L - 1, 0)]
        for y in (R.P, R.P + 1, 2**255 - 1, 1, 0, R.P - 1):
            for sign in (0, 1):
                encoded = (y | sign << 255).to_bytes(32, "little")
                cases += [(encoded, message, value), (encoded, message, (1).to_bytes(32, "little") + bytes(32))]
        for text in SMALL_ORDER:
            point = bytes.fromhex(text)
            cases += [(point, message, (1).to_bytes(32, "little") + bytes(32)), (point, message, point + bytes(32)),
                      (key, message, point + value[32:])]
        for case in cases:
            self.assertVerdict(*case)


if __name__ == "__main__":
    unittest.main()
