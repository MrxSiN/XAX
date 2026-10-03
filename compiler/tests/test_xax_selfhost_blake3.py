"""Self-hosting step S2 (ADR-117): the whole BLAKE3 hash is XAX semantics on the production path."""

from __future__ import annotations

import os
import platform
import random
import sys
import unittest

import blake3
from xax_selfhost_blake3 import INPUT_EXTENT, STORE_PATH, NativeHasher, build_hash_program, load_hash_program

NATIVE = sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")
# Official BLAKE3 test vectors (unkeyed, 32-byte output).
VECTORS = {
    b"": "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
    b"abc": "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85",
}
BOUNDARIES = (0, 1, 3, 4, 5, 63, 64, 65, 127, 128, 1023, 1024, 1025, 2047, 2048, 2049, 3072, 4096, 5121, 8192, 8193, 16385, 31744, 65536, 100003)


class HashStoreTests(unittest.TestCase):
    def test_committed_store_regenerates_and_verifies(self):
        reader, function = build_hash_program()
        self.assertEqual(reader.data, STORE_PATH.read_bytes())
        self.assertEqual(load_hash_program()[1].cid, function.cid)


@unittest.skipUnless(NATIVE, "the native leaf runs on Linux x86-64")
class NativeHashTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.hasher = NativeHasher()

    def test_official_vectors(self):
        for data, expected in VECTORS.items():
            self.assertEqual(self.hasher.digest(data).hex(), expected)

    def test_agrees_with_the_python_driver(self):
        rng = random.Random(11)
        sizes = [*BOUNDARIES, *(rng.randrange(0, 200_000) for _ in range(20)), INPUT_EXTENT]
        for size in sizes:
            data = rng.randbytes(size)
            with self.subTest(size=size):
                self.assertEqual(self.hasher.digest(data), blake3._Blake3(data).digest())

    def test_stale_buffer_bytes_never_leak_into_the_digest(self):
        self.hasher.digest(b"\xff" * 5000)
        self.assertEqual(self.hasher.digest(b"abc").hex(), VECTORS[b"abc"])

    def test_production_hash_is_the_xax_function(self):
        hashed = blake3.blake3(b"abc")
        self.assertEqual(type(hashed).__name__, "_OneShot")
        self.assertEqual(hashed.update(b"def").hexdigest(), blake3._Blake3(b"abcdef").hexdigest())
        self.assertEqual(blake3.blake3(b"x").digest(64), blake3._Blake3(b"x").digest(64))  # other lengths use the driver
        big = os.urandom(INPUT_EXTENT + 5)
        self.assertEqual(blake3.blake3(big).digest(), blake3._Blake3(big).digest())  # over the lent view


if __name__ == "__main__":
    unittest.main()
